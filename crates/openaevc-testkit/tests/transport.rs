//! Daemon transport: HTTP JSON/CBOR, objects, SSE, Unix sockets, TLS, limits, OpenAPI.

use std::sync::Arc;
use std::time::Duration;

use openaevc::protocol::*;
use openaevc::transport::client::{Endpoint, HttpClient};
use openaevc::transport::server::{self, Health, Listener, ServerConfig};
use openaevc_testkit::*;
use tokio::sync::watch;

struct Running {
    client: HttpClient,
    _stop: watch::Sender<bool>,
}

async fn start(h: &Harness, cfg: ServerConfig) -> Running {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let app = server::router(h.rt.clone(), cfg, Arc::new(Health::ready()));
    tokio::spawn(server::serve(Listener::Tcp(l), app, rx));
    Running {
        client: HttpClient::new(Endpoint::Tcp(addr.to_string())),
        _stop: stop,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn info_commands_and_queries_over_http() {
    let h = Harness::new();
    let r = start(&h, ServerConfig::default()).await;
    let info = r.client.info().await.unwrap();
    assert_eq!(info, h.rt.info());
    let root = Identity::generate();
    let env = h.admin_client().command_envelope(Command::CreateNamespace {
        root_principals: vec![root.new_principal()],
        metadata: Default::default(),
    });
    let receipt = r.client.command(&env).await.unwrap();
    root.set_id(receipt.result.ids[0].parse().unwrap());
    let ns: NamespaceId = receipt.result.id.unwrap().parse().unwrap();
    // Retrying the identical envelope over HTTP is idempotent too.
    assert_eq!(
        r.client.command(&env).await.unwrap().receipt,
        receipt.receipt
    );
    let v = r
        .client
        .query(&h.client(&root, ns).query_envelope(Query::GetNamespace {}))
        .await
        .unwrap();
    assert_eq!(v["id"], ns.to_string());
    // CBOR request/response.
    let v = r
        .client
        .cbor()
        .query(&h.client(&root, ns).query_envelope(Query::GetNamespace {}))
        .await
        .unwrap();
    assert_eq!(v["id"], ns.to_string());
    let rc = r
        .client
        .cbor()
        .command(
            &h.client(&root, ns)
                .command_envelope(Command::CreateChangePack {
                    spec: PackSpec::default(),
                }),
        )
        .await
        .unwrap();
    assert_eq!(rc.result.state.as_deref(), Some("OPEN"));
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_are_structured_and_authorization_cannot_be_bypassed() {
    let h = Harness::new();
    let r = start(&h, ServerConfig::default()).await;
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let alice = h.register_key_principal(&root, ns);
    let e = r
        .client
        .command(
            &h.client(&alice, ns)
                .command_envelope(Command::CreateChangePack {
                    spec: PackSpec::default(),
                }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, e.missing_action.as_deref()),
        (ErrorCode::Forbidden, Some("changepack.create"))
    );
    let mut unsigned = h.client(&root, ns).query_envelope(Query::GetNamespace {});
    unsigned.signature = None;
    assert_eq!(
        r.client.query(&unsigned).await.unwrap_err().code,
        ErrorCode::Unauthorized
    );
    let raw = r
        .client
        .post_raw(
            "/v1/commands",
            "application/json",
            b"{\"not\": \"an envelope\"}".to_vec(),
        )
        .await
        .unwrap_err();
    assert_eq!(raw.code, ErrorCode::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread")]
async fn object_endpoints_verify_digests() {
    let h = Harness::new();
    let r = start(&h, ServerConfig::default()).await;
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let pack = h.create_pack(&root, ns);
    let cand = h.seal(&root, ns, pack);
    let c = h.client(&root, ns);
    let bytes = r
        .client
        .get_object(&c.query_envelope(Query::GetObject { digest: cand }), cand)
        .await
        .unwrap();
    assert_eq!(
        openaevc::core::ImmutableObject::from_bytes(&bytes, Some(cand))
            .unwrap()
            .kind(),
        ObjectKind::Candidate
    );
    // Import into another runtime over its daemon.
    let other = Harness::new();
    let ro = start(&other, ServerConfig::default()).await;
    let r2 = Identity::generate();
    let ns2 = other.create_namespace(&r2);
    let c2 = other.client(&r2, ns2);
    ro.client
        .put_object(
            &c2.command_envelope(Command::PutImmutableObject {
                digest: cand,
                bytes: vec![],
            }),
            bytes.clone(),
        )
        .await
        .unwrap();
    assert!(other
        .client(&r2, ns2)
        .query(Query::GetObject { digest: cand })
        .is_ok());
    let wrong = openaevc::crypto::sha256(b"wrong");
    let e = ro
        .client
        .put_object(
            &c2.command_envelope(Command::PutImmutableObject {
                digest: wrong,
                bytes: vec![],
            }),
            bytes,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::DigestMismatch);
    let e = r
        .client
        .get_object(&c.query_envelope(Query::GetObject { digest: wrong }), wrong)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn server_sent_events_stream_and_resume() {
    let h = Harness::new();
    let r = start(&h, ServerConfig::default()).await;
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let env = h.client(&root, ns).query_envelope(Query::ListEvents {
        after: 0,
        limit: None,
        kinds: vec![],
    });
    let mut stream = r.client.events(&env, &[], None).await.unwrap();
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(
        (first.sequence, first.kind.as_str()),
        (1, "namespace.created")
    );
    let second = stream.next().await.unwrap().unwrap();
    assert_eq!(second.sequence, 2);
    // Live delivery after a new commit.
    let hc = h.rt.clone();
    let cmd = h
        .client(&root, ns)
        .command_envelope(Command::CreateChangePack {
            spec: PackSpec::default(),
        });
    tokio::task::spawn_blocking(move || hc.execute(cmd))
        .await
        .unwrap()
        .unwrap();
    let live = tokio::time::timeout(Duration::from_secs(10), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(live.kind, "changepack.created");
    drop(stream);
    // Resume with Last-Event-ID skips what was already processed.
    let env = h.client(&root, ns).query_envelope(Query::ListEvents {
        after: 0,
        limit: None,
        kinds: vec![],
    });
    let mut resumed = r.client.events(&env, &[], Some(2)).await.unwrap();
    assert_eq!(resumed.next().await.unwrap().unwrap().sequence, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn request_size_limit_is_enforced() {
    let h = Harness::new();
    let r = start(
        &h,
        ServerConfig {
            max_request_bytes: 1024,
            ..ServerConfig::default()
        },
    )
    .await;
    let e = r
        .client
        .post_raw("/v1/queries", "application/json", vec![b' '; 4096])
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert!(r.client.info().await.is_ok(), "server remains available");
}

#[tokio::test(flavor = "multi_thread")]
async fn health_and_openapi() {
    let h = Harness::new();
    let r = start(&h, ServerConfig::default()).await;
    assert_eq!(r.client.get_raw("/v1/health/live").await.unwrap().0, 200);
    assert_eq!(r.client.get_raw("/v1/health/ready").await.unwrap().0, 200);
    let (status, body) = r.client.get_raw("/v1/openapi.json").await.unwrap();
    assert_eq!(status, 200);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    for p in [
        "/v1/info",
        "/v1/commands",
        "/v1/queries",
        "/v1/events",
        "/v1/objects/{digest}",
        "/v1/openapi.json",
    ] {
        assert!(doc["paths"].get(p).is_some(), "{p}");
    }
    assert_eq!(doc["openapi"], "3.1.0");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn unix_socket_listener() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("openaevcd.sock");
    let l = tokio::net::UnixListener::bind(&path).unwrap();
    let (_stop, rx) = watch::channel(false);
    tokio::spawn(server::serve(
        Listener::Unix(l),
        server::router(
            h.rt.clone(),
            ServerConfig::default(),
            Arc::new(Health::ready()),
        ),
        rx,
    ));
    let c = HttpClient::new(Endpoint::Unix(path));
    assert_eq!(c.info().await.unwrap(), h.rt.info());
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_listener_requires_tls_clients() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let h = Harness::new();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let acceptor = server::tls_acceptor(vec![cert_der.clone()], key_der).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (_stop, rx) = watch::channel(false);
    tokio::spawn(server::serve(
        Listener::Tls(l, acceptor),
        server::router(
            h.rt.clone(),
            ServerConfig::default(),
            Arc::new(Health::ready()),
        ),
        rx,
    ));
    let tls = HttpClient::new(Endpoint::Tls {
        addr: addr.to_string(),
        server_name: "localhost".into(),
        roots: vec![cert_der],
    });
    assert_eq!(tls.info().await.unwrap(), h.rt.info());
    let plain = HttpClient::new(Endpoint::Tcp(addr.to_string()));
    assert!(plain.info().await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn graceful_shutdown_stops_accepting() {
    let h = Harness::new();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server::serve(
        Listener::Tcp(l),
        server::router(
            h.rt.clone(),
            ServerConfig::default(),
            Arc::new(Health::ready()),
        ),
        rx,
    ));
    let c = HttpClient::new(Endpoint::Tcp(addr.to_string()));
    assert!(c.info().await.is_ok());
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(c.info().await.is_err());
}
