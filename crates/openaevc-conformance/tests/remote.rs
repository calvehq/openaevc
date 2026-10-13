//! Remote-mode runs over the v1 HTTP transport, and a deliberately broken server that the suite
//! must reject (proving the cases are sensitive to the violations they claim to test).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::Response;
use openaevc::core::Clock;
use openaevc::store::MemoryStore;
use openaevc::transport::client::Endpoint;
use openaevc::transport::server::{self, Health, Listener, ServerConfig};
use openaevc_conformance::target::Identity;
use openaevc_conformance::{run, Profile, Report, Status, Target};

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

/// A semantic violation injected into an otherwise correct server's responses.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    /// Denials become successes and raw object bytes are flipped.
    Legacy,
    /// Every error with this code becomes a well-formed fake success.
    Accept(&'static str),
    /// `ValidateBaseline` always answers `valid: true`.
    BaselineAlwaysValid,
    /// The hash of the last event in every event list is altered.
    EventHashes,
}

const FAKE_RECEIPT: &str = r#"{"receipt":"sha256:0000000000000000000000000000000000000000000000000000000000000000","request_id":"req_agjdus24nvyadaareizuivlgo4","result":{},"first_seq":1,"last_seq":1}"#;

async fn mutate(m: Mutation, resp: Response) -> Response {
    let (mut parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default()
        .to_vec();
    let json: Option<serde_json::Value> = serde_json::from_slice(&bytes).ok();
    let out = match m {
        Mutation::Legacy => return corrupt(Response::from_parts(parts, Body::from(bytes))).await,
        Mutation::Accept(code) => match &json {
            Some(v) if !parts.status.is_success() && v["code"] == code => {
                parts.status = StatusCode::OK;
                FAKE_RECEIPT.as_bytes().to_vec()
            }
            _ => bytes,
        },
        Mutation::BaselineAlwaysValid => match json {
            Some(mut v) if v.get("valid") == Some(&serde_json::Value::Bool(false)) => {
                v["valid"] = true.into();
                v["problems"] = serde_json::json!([]);
                serde_json::to_vec(&v).unwrap()
            }
            _ => bytes,
        },
        Mutation::EventHashes => match json {
            Some(serde_json::Value::Array(mut events))
                if events.last().is_some_and(|e| e.get("hash").is_some()) =>
            {
                let last = events.last_mut().unwrap();
                let h = last["hash"].as_str().unwrap().to_owned();
                let flipped = if h.ends_with('0') { "1" } else { "0" };
                last["hash"] = format!("{}{flipped}", &h[..h.len() - 1]).into();
                serde_json::to_vec(&events).unwrap()
            }
            _ => bytes,
        },
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(out))
}

async fn remote(mutation: Option<Mutation>, ext: Option<std::path::PathBuf>) -> Target {
    let id = Identity::generate();
    // The served runtime follows wall-clock time, as a deployed daemon would.
    let clock = id.clock.clone();
    tokio::spawn(async move {
        loop {
            clock.set(openaevc::core::SystemClock.now().unix_nanos() as i64);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    });
    let Target::InProcess(t) =
        Target::with_store(Arc::new(MemoryStore::new()), &id, ext.clone()).unwrap()
    else {
        unreachable!()
    };
    let mut app = server::router(
        t.rt.clone(),
        ServerConfig::default(),
        Arc::new(Health::ready()),
    );
    if let Some(m) = mutation {
        app = app.layer(axum::middleware::map_response(move |r| mutate(m, r)));
    }
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (stop, rx) = tokio::sync::watch::channel(false);
    std::mem::forget(stop);
    tokio::spawn(server::serve(Listener::Tcp(l), app, rx));
    Target::remote(Endpoint::Tcp(addr), id.admin.clone(), id.admin_id, ext, 10)
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
        let report = run(remote(None, None).await, profile, None).await;
        println!("{}", report.summary());
        assert!(report.conformant(), "{}", report.summary());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn broken_implementation_is_not_conformant() {
    let core = run(
        remote(Some(Mutation::Legacy), None).await,
        Profile::Core,
        None,
    )
    .await;
    let authority = run(
        remote(Some(Mutation::Legacy), None).await,
        Profile::Authority,
        None,
    )
    .await;
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

/// Every injected semantic violation is caught by a case covering the violated requirement:
/// the suite is sensitive to what it claims to test, not only to crashes.
#[tokio::test(flavor = "multi_thread")]
async fn each_injected_violation_fails_its_requirement() {
    let ext = openaevc_testkit::Extensions::install();
    let dir = || Some(ext.dir.path().to_path_buf());
    let cases: &[(Mutation, Profile, &str, &str)] = &[
        (
            Mutation::Accept("FORBIDDEN"),
            Profile::Authority,
            "authority.default_deny",
            "AEVC-AUTH-0003",
        ),
        (
            Mutation::Accept("UNAUTHORIZED"),
            Profile::Core,
            "core.signatures",
            "AEVC-ID-0005",
        ),
        (
            Mutation::Accept("REPLAY_DETECTED"),
            Profile::Authority,
            "authority.replay",
            "AEVC-AUTH-0005",
        ),
        (
            Mutation::Accept("STALE_GENERATION"),
            Profile::Runtime,
            "lifecycle.generations",
            "AEVC-LIFE-0001",
        ),
        (
            Mutation::Accept("IMMUTABLE_OBJECT"),
            Profile::Runtime,
            "lifecycle.terminal",
            "AEVC-PRO-0003",
        ),
        (
            Mutation::Accept("EVIDENCE_INVALID"),
            Profile::Runtime,
            "evidence.binding",
            "AEVC-EVD-0001",
        ),
        (
            Mutation::Accept("DIGEST_MISMATCH"),
            Profile::Core,
            "core.objects.invalid_rejected",
            "AEVC-XCH-0002",
        ),
        (
            Mutation::Accept("CANONICAL_ENCODING_ERROR"),
            Profile::Core,
            "core.objects.signature_identity",
            "AEVC-OBJ-0006",
        ),
        (
            Mutation::Accept("CONFLICT"),
            Profile::ExtensionHost,
            "extension.kind_conflicts",
            "AEVC-EXT-0003",
        ),
        (
            Mutation::BaselineAlwaysValid,
            Profile::Full,
            "full.exchange",
            "AEVC-BSL-0003",
        ),
        (
            Mutation::EventHashes,
            Profile::Runtime,
            "events.journal",
            "AEVC-EVT-0003",
        ),
    ];
    let mut missed = Vec::new();
    for (m, profile, case, req) in cases {
        let report = run(remote(Some(*m), dir()).await, *profile, Some(case)).await;
        let caught = failed(&report, case) && report.requirements_failed.contains(*req);
        println!(
            "{m:?} -> {case} [{req}]: {}",
            if caught { "CAUGHT" } else { "MISSED" }
        );
        if !caught {
            missed.push(format!(
                "{m:?} not caught by {case}/{req}:\n{}",
                report.summary()
            ));
        }
    }
    // Control: without a mutation the same cases pass.
    for (_, profile, case, _) in cases {
        let report = run(remote(None, dir()).await, *profile, Some(case)).await;
        assert!(report.conformant(), "control {case}:\n{}", report.summary());
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}
