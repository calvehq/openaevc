//! Phase 7: extension registration, handshake, digest pinning, and host containment.

use std::time::{Duration, Instant};

use openaevc_extension_contract::host::{
    self, CallError, Entrypoint, HostCallHandler, HostError, HostLimits,
};
use openaevc_extension_contract::wire::{HostCall, Operation, WireError};
use openaevc_protocol::*;
use openaevc_testkit::{Extensions, Harness, Identity};
use serde_json::Value;

fn setup(ext: &Extensions) -> (Harness, Identity, NamespaceId) {
    let h = Harness::with_extensions(ext);
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    (h, root, ns)
}

fn register(
    h: &Harness,
    who: &Identity,
    ns: NamespaceId,
    entry: &str,
    digest: Digest,
) -> Result<CommandReceipt, ProtocolError> {
    h.client(who, ns).cmd(Command::RegisterExtension {
        entrypoint: entry.into(),
        artifact_digest: digest,
        approved_host_capabilities: vec![HostCapability::ResourceRead],
    })
}

#[test]
fn registers_compatible_extension_and_records_manifest() {
    let ext = Extensions::install();
    let (h, root, ns) = setup(&ext);
    let r = h.register_extension(&root, ns, &ext, "openaevc-ext-reference-kv");
    let manifest = h
        .client(&root, ns)
        .query(Query::GetObject {
            digest: r.result.digest.unwrap(),
        })
        .unwrap();
    assert_eq!(manifest["envelope"]["kind"], "extension_manifest");
    assert_eq!(
        manifest["envelope"]["body"]["artifact_digest"],
        ext.digest("openaevc-ext-reference-kv").to_string()
    );
    let list = h.client(&root, ns).query(Query::ListExtensions {}).unwrap();
    assert_eq!(list[0]["id"], "org.openaevc.reference.kv");
    assert_eq!(list[0]["active"], true);
    let kinds: Vec<String> = h
        .events(&root, ns)
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    assert!(kinds.contains(&"extension.registered".to_string()));
}

#[test]
fn pinned_digest_must_match_the_artifact() {
    let ext = Extensions::install();
    let (h, root, ns) = setup(&ext);
    let e = register(
        &h,
        &root,
        ns,
        &Extensions::entrypoint("openaevc-ext-reference-kv"),
        openaevc_crypto::sha256(b"other"),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::ExtensionIncompatible);
}

#[test]
fn manifest_digest_and_version_mismatches_fail_before_registration() {
    let ext = Extensions::install();
    let (h, root, ns) = setup(&ext);
    for mode in ["wrong-digest", "incompatible"] {
        let name = format!("conformance-fixture-{mode}");
        let e = register(
            &h,
            &root,
            ns,
            &Extensions::entrypoint(&name),
            ext.digest(&name),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::ExtensionIncompatible, "{mode}");
    }
    assert_eq!(
        h.client(&root, ns).query(Query::ListExtensions {}).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn entrypoints_are_confined_to_extension_directories() {
    let ext = Extensions::install();
    let (h, root, ns) = setup(&ext);
    let d = ext.digest("openaevc-ext-reference-kv");
    for bad in ["../openaevc-ext-reference-kv", "/bin/sh", ""] {
        let e = register(&h, &root, ns, bad, d).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{bad}");
    }
    assert_eq!(
        register(&h, &root, ns, "missing-binary", d)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
}

#[test]
fn registration_requires_authority() {
    let ext = Extensions::install();
    let (h, root, ns) = setup(&ext);
    let alice = h.register_key_principal(&root, ns);
    let name = "openaevc-ext-reference-kv";
    let e = register(
        &h,
        &alice,
        ns,
        &Extensions::entrypoint(name),
        ext.digest(name),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    assert_eq!(e.missing_action.as_deref(), Some("extension.register"));
}

#[test]
fn kinds_cannot_be_claimed_twice_and_unregister_deactivates() {
    let ext = Extensions::install();
    let (h, root, ns) = setup(&ext);
    h.register_extension(&root, ns, &ext, "openaevc-ext-reference-null");
    // Re-registering the same extension ID is an in-place upgrade, not a conflict.
    h.register_extension(&root, ns, &ext, "openaevc-ext-reference-null");
    h.client(&root, ns)
        .cmd(Command::UnregisterExtension {
            extension: "org.openaevc.reference.null".into(),
        })
        .unwrap();
    let list = h.client(&root, ns).query(Query::ListExtensions {}).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["active"], false);
    let e = h
        .client(&root, ns)
        .cmd(Command::UnregisterExtension {
            extension: "org.example.none".into(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
}

// ---------------------------------------------------------------------------------------------
// Host containment (reference process host), independent of the runtime.

struct NoScope;

impl HostCallHandler for NoScope {
    fn handle(&mut self, call: &HostCall) -> Result<Value, CallError> {
        match call {
            HostCall::ResourceRead { resource } => Err(CallError::Denied(format!(
                "resource {} is outside the invocation scope",
                resource.locator
            ))),
            HostCall::EvidenceAttach { .. } => Ok(Value::Bool(true)),
            _ => Err(CallError::Failed(WireError::new(
                "unsupported",
                "not available",
            ))),
        }
    }
}

fn fixture(ext: &Extensions, mode: &str) -> (Entrypoint, ExtensionManifest) {
    let ep = Entrypoint {
        program: ext.path(&format!("conformance-fixture-{mode}")),
        args: vec![],
    };
    let (manifest, _) = host::handshake(&ep, &HostLimits::default()).unwrap();
    (ep, manifest)
}

fn verify_op(mode: &str) -> Operation {
    Operation::Verify {
        kind: format!("fixture.{mode}.check"),
        config: None,
        pack: "cpk_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
        generation: 1,
        candidate: Digest::ZERO,
        effects: vec![],
        evidence: vec![],
    }
}

fn run(
    ext: &Extensions,
    mode: &str,
    limits: HostLimits,
    granted: Vec<HostCapability>,
) -> Result<Value, HostError> {
    let (ep, manifest) = fixture(ext, mode);
    host::invoke(
        &ep,
        &limits,
        &manifest,
        verify_op(mode),
        granted,
        &mut NoScope,
    )
    .map(|r| r.output)
}

#[test]
fn well_behaved_fixture_passes() {
    let ext = Extensions::install();
    let out = run(&ext, "well-behaved", HostLimits::default(), vec![]).unwrap();
    assert_eq!(out["status"], "PASS");
}

#[test]
fn out_of_scope_resource_access_fails_closed() {
    let ext = Extensions::install();
    let e = run(
        &ext,
        "undeclared-resource",
        HostLimits::default(),
        vec![HostCapability::ResourceRead],
    )
    .unwrap_err();
    assert!(matches!(e, HostError::Denied(_)), "{e:?}");
}

#[test]
fn ungranted_process_execution_fails_closed() {
    let ext = Extensions::install();
    let e = run(
        &ext,
        "undeclared-process",
        HostLimits::default(),
        vec![HostCapability::ResourceRead],
    )
    .unwrap_err();
    assert!(matches!(e, HostError::Denied(_)), "{e:?}");
}

#[test]
fn oversized_and_invalid_frames_fail_closed() {
    let ext = Extensions::install();
    let limits = HostLimits {
        max_frame: 1024 * 1024,
        ..Default::default()
    };
    assert!(matches!(
        run(&ext, "oversized", limits.clone(), vec![]).unwrap_err(),
        HostError::Protocol(_)
    ));
    assert!(matches!(
        run(&ext, "invalid-frame", limits.clone(), vec![]).unwrap_err(),
        HostError::Protocol(_)
    ));
    assert!(matches!(
        run(&ext, "crash", limits, vec![]).unwrap_err(),
        HostError::Protocol(_)
    ));
}

#[test]
fn deadline_is_enforced() {
    let ext = Extensions::install();
    // Handshake first so only the invocation is timed (machine load must not flake the bound).
    let (ep, manifest) = fixture(&ext, "slow");
    let limits = HostLimits {
        deadline: Duration::from_millis(400),
        ..Default::default()
    };
    let start = Instant::now();
    let e = host::invoke(
        &ep,
        &limits,
        &manifest,
        verify_op("slow"),
        vec![],
        &mut NoScope,
    )
    .unwrap_err();
    assert_eq!(e, HostError::Deadline);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "slow extension must be killed at the deadline"
    );
}

#[test]
fn extension_processes_get_no_runtime_environment() {
    let ext = Extensions::install();
    std::env::set_var("OPENAEVC_DATA_ROOT_FOR_TEST", "/should/not/leak");
    let out = run(&ext, "probe", HostLimits::default(), vec![]).unwrap();
    let env: Vec<String> =
        serde_json::from_value(out["facts"]["fixture.probe.env"].clone()).unwrap();
    assert!(env.iter().all(|k| k == "PATH"), "{env:?}");
    let cwd = out["facts"]["fixture.probe.cwd"].as_str().unwrap();
    assert_eq!(
        std::fs::canonicalize(cwd).unwrap(),
        std::fs::canonicalize(ext.dir.path()).unwrap()
    );
}
