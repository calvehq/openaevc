//! AEVC-INV-029: embedded and daemon clients exercise identical runtime semantics.

use std::sync::Arc;
use std::time::Duration;

use openaevc::core::FixedClock;
use openaevc::protocol::*;
use openaevc::transport::client::Endpoint;
use openaevc::transport::server::{self, Health, Listener, ServerConfig};
use openaevc_sdk::{EmbeddedClient, OpenAevcClient, RemoteClient, Session, TypedClient};
use openaevc_testkit::{admin_identity, Harness, Identity};

#[derive(Debug, PartialEq)]
struct Outcome {
    states: Vec<String>,
    denied: ErrorCode,
    stale: ErrorCode,
    event_kinds: Vec<String>,
    object_kind: ObjectKind,
    baseline_valid: bool,
}

fn session(who: &Identity, ns: Option<NamespaceId>, clock: &FixedClock) -> Session {
    Session::new(who.signer(), who.id(), ns).with_clock(Arc::new(clock.clone()))
}

/// The same observable scenario through any client implementation.
async fn scenario<C: OpenAevcClient>(
    clock: &FixedClock,
    connect: impl Fn(Session) -> C,
) -> Outcome {
    let admin = connect(session(&admin_identity(), None, clock));
    let root = Identity::generate();
    let (ns, roots) = admin
        .create_namespace(vec![root.new_principal()])
        .await
        .unwrap();
    root.set_id(roots[0]);
    let c = connect(session(&root, Some(ns), clock));
    let mut states = Vec::new();
    let pack = c.create_change_pack(PackSpec::default()).await.unwrap();
    states.push(
        c.get_change_pack(pack)
            .await
            .unwrap()
            .state
            .as_str()
            .to_owned(),
    );
    let stale = c
        .command(Command::SealChangePack {
            pack,
            expected_generation: 9,
        })
        .await
        .unwrap_err()
        .code;
    let candidate = c.seal(pack, 1).await.unwrap();
    states.push(
        c.get_change_pack(pack)
            .await
            .unwrap()
            .state
            .as_str()
            .to_owned(),
    );
    states.push(
        c.refresh_qualification(pack, 1)
            .await
            .unwrap()
            .result
            .state
            .unwrap(),
    );
    let promoted = c.promote(pack, 1).await.unwrap();
    states.push(
        c.get_change_pack(pack)
            .await
            .unwrap()
            .state
            .as_str()
            .to_owned(),
    );
    let obj = c.get_object(candidate).await.unwrap();
    let (_, baseline) = c.create_baseline(vec![promoted], vec![]).await.unwrap();
    let baseline_valid = c
        .query(Query::ValidateBaseline { digest: baseline })
        .await
        .unwrap()["valid"]
        == true;
    let mallory = Identity::generate();
    mallory.set_id(c.register_principal(mallory.new_principal()).await.unwrap());
    let denied = connect(session(&mallory, Some(ns), clock))
        .command(Command::CreateChangePack {
            spec: PackSpec::default(),
        })
        .await
        .unwrap_err()
        .code;
    let filter = EventFilter {
        namespace: ns,
        after: 0,
        kinds: vec!["changepack.sealed".into(), "changepack.promoted".into()],
        subjects: vec![],
    };
    let mut stream = c.subscribe(filter).await.unwrap();
    let mut event_kinds = Vec::new();
    for _ in 0..2 {
        let e = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        event_kinds.push(e.kind);
    }
    Outcome {
        states,
        denied,
        stale,
        event_kinds,
        object_kind: obj.kind(),
        baseline_valid,
    }
}

async fn daemon(h: &Harness) -> Endpoint {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (stop, rx) = tokio::sync::watch::channel(false);
    std::mem::forget(stop);
    tokio::spawn(server::serve(
        Listener::Tcp(l),
        server::router(
            h.rt.clone(),
            ServerConfig::default(),
            Arc::new(Health::ready()),
        ),
        rx,
    ));
    Endpoint::Tcp(addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_and_remote_clients_behave_identically() {
    let h1 = Harness::new();
    let rt = h1.rt.clone();
    let embedded = scenario(&h1.clock, |s| EmbeddedClient::new(rt.clone(), s)).await;

    let h2 = Harness::new();
    let ep = daemon(&h2).await;
    let remote = scenario(&h2.clock, |s| RemoteClient::new(ep.clone(), s)).await;

    assert_eq!(embedded, remote);
    assert_eq!(embedded.states, ["OPEN", "SEALED", "QUALIFIED", "PROMOTED"]);
    assert_eq!(embedded.stale, ErrorCode::StaleGeneration);
    assert_eq!(embedded.denied, ErrorCode::Forbidden);
    assert_eq!(
        embedded.event_kinds,
        ["changepack.sealed", "changepack.promoted"]
    );
    assert_eq!(embedded.object_kind, ObjectKind::Candidate);
    assert!(embedded.baseline_valid);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_connect_negotiates_the_protocol_version() {
    let h = Harness::new();
    let ep = daemon(&h).await;
    let admin = admin_identity();
    let c = RemoteClient::connect(ep, session(&admin, None, &h.clock))
        .await
        .unwrap();
    assert_eq!(c.protocol_version(), PROTOCOL_VERSION);
    let e = RemoteClient::connect(
        Endpoint::Tcp("127.0.0.1:1".into()),
        session(&admin, None, &h.clock),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Internal);
    assert!(e.retryable);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_objects_are_verified_client_side() {
    let h = Harness::new();
    let ep = daemon(&h).await;
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let c = RemoteClient::new(ep, session(&root, Some(ns), &h.clock));
    let pack = c.create_change_pack(PackSpec::default()).await.unwrap();
    let cand = c.seal(pack, 1).await.unwrap();
    let obj = c.get_object(cand).await.unwrap();
    assert_eq!(obj.digest(), cand);
}
