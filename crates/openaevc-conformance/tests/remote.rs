//! Remote-mode runs over the v1 HTTP transport, and a deliberately broken server that the suite
//! must reject (proving the cases are sensitive to the violations they claim to test).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::Response;
use openaevc_conformance::target::Identity;
use openaevc_conformance::{run, Profile, Report, Status, Target};
use openaevc_core::Clock;
use openaevc_store::MemoryStore;
use openaevc_transport::client::Endpoint;
use openaevc_transport::server::{self, Health, Listener, ServerConfig};

/// Lies about authorization (denials become empty successes) and flips a byte of every raw object.
async fn corrupt(resp: Response) -> Response {
    let (mut parts, body) = resp.into_parts();
    let mut bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default()
        .to_vec();
    if parts.status == StatusCode::FORBIDDEN {
        parts.status = StatusCode::OK;
        bytes = b"{}".to_vec();
        parts
            .headers
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    } else if parts
        .headers
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v == "application/cbor")
    {
        if let Some(b) = bytes.last_mut() {
            *b ^= 1;
        }
    }
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(bytes))
}

async fn remote(broken: bool) -> Target {
    let id = Identity::generate();
    // The served runtime follows wall-clock time, as a deployed daemon would.
    let clock = id.clock.clone();
    tokio::spawn(async move {
        loop {
            clock.set(openaevc_core::SystemClock.now().unix_nanos() as i64);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    });
    let Target::InProcess(t) = Target::with_store(Arc::new(MemoryStore::new()), &id, None).unwrap()
    else {
        unreachable!()
    };
    let mut app = server::router(
        t.rt.clone(),
        ServerConfig::default(),
        Arc::new(Health::ready()),
    );
    if broken {
        app = app.layer(axum::middleware::map_response(corrupt));
    }
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (stop, rx) = tokio::sync::watch::channel(false);
    std::mem::forget(stop);
    tokio::spawn(server::serve(Listener::Tcp(l), app, rx));
    Target::remote(Endpoint::Tcp(addr), id.admin.clone(), id.admin_id, None, 10)
}

fn failed(report: &Report, id: &str) -> bool {
    report
        .cases
        .iter()
        .any(|c| c.id == id && matches!(c.status, Status::Failed(_)))
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_target_passes_core_and_authority_profiles() {
    for profile in [Profile::Core, Profile::Authority] {
        let report = run(remote(false).await, profile, None).await;
        println!("{}", report.summary());
        assert!(report.conformant(), "{}", report.summary());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn broken_implementation_is_not_conformant() {
    let core = run(remote(true).await, Profile::Core, None).await;
    let authority = run(remote(true).await, Profile::Authority, None).await;
    println!("{}\n{}", core.summary(), authority.summary());
    assert!(!core.conformant() && !authority.conformant());
    assert!(
        failed(&core, "core.objects.round_trip"),
        "{}",
        core.summary()
    );
    let report = authority;
    for id in [
        "authority.default_deny",
        "authority.every_entry_point",
        "authority.denial_audit",
        "capability.revocation",
    ] {
        assert!(
            failed(&report, id),
            "{id} must detect the broken server:\n{}",
            report.summary()
        );
    }
}
