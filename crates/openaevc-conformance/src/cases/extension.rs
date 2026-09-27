//! EXTENSION_HOST profile, exercised through the runtime with the `conformance-fixture-<mode>`
//! executables (installed in the extension directory the target is configured with).

use openaevc_protocol::*;
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::json;

use crate::ctx::{ensure, exe_name, expect_code, fresh, Check, Ctx, Ns};
use crate::CaseResult;

fn fixture(mode: &str) -> String {
    exe_name(&format!("conformance-fixture-{mode}"))
}

/// Registers a fixture (resource.read approved); returns the manifest digest.
async fn register(cx: &Ctx, ns: &Ns, name: &str) -> Result<Digest, String> {
    let bytes = std::fs::read(cx.extensions()?.join(name))
        .map_err(|e| format!("SKIP: fixture {name} not installed: {e}"))?;
    ns.root
        .register_extension(
            name,
            openaevc_crypto::sha256(&bytes),
            vec![HostCapability::ResourceRead],
        )
        .await
        .c()
}

async fn sealed(ns: &Ns) -> Result<PackId, String> {
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    ns.root.seal(pack, 1).await.c()?;
    Ok(pack)
}

async fn verify(ns: &Ns, pack: PackId, mode: &str) -> Result<CommandReceipt, ProtocolError> {
    ns.root
        .run_verification(pack, 1, &format!("fixture.{mode}.check"), json!({}))
        .await
}

/// A private copy of the well-behaved fixture under a unique name, removed on drop.
struct Copy(std::path::PathBuf, String);

impl Copy {
    fn new(cx: &Ctx) -> Result<Self, String> {
        let dir = cx.extensions()?;
        let mode = format!("copy{}", fresh::<RequestId>().to_string().replace('_', ""));
        let name = fixture(&mode);
        std::fs::copy(dir.join(fixture("well-behaved")), dir.join(&name))
            .map_err(|e| format!("SKIP: cannot write to the extension directory: {e}"))?;
        Ok(Copy(dir.join(&name), mode))
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub async fn confinement(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let name = fixture("well-behaved");
    let bytes = std::fs::read(cx.extensions()?.join(&name)).map_err(|e| format!("SKIP: {e}"))?;
    let d = openaevc_crypto::sha256(&bytes);
    for bad in [
        format!("../{name}"),
        "/bin/sh".into(),
        String::new(),
        format!("./../{name}"),
    ] {
        expect_code(
            ns.root.register_extension(&bad, d, vec![]).await,
            ErrorCode::InvalidArgument,
        )
        .map_err(|e| format!("{bad:?}: {e}"))?;
    }
    expect_code(
        ns.root
            .register_extension("no-such-extension", d, vec![])
            .await,
        ErrorCode::NotFound,
    )?;
    let m = cx.member(&ns).await?;
    let e = expect_code(
        m.client.register_extension(&name, d, vec![]).await,
        ErrorCode::Forbidden,
    )?;
    ensure(
        e.missing_action.as_deref() == Some("extension.register"),
        "registration requires extension.register",
    )
}

pub async fn pinning(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let name = fixture("well-behaved");
    expect_code(
        ns.root
            .register_extension(&name, openaevc_crypto::sha256(b"other"), vec![])
            .await,
        ErrorCode::ExtensionIncompatible,
    )?;
    for mode in ["wrong-digest", "incompatible"] {
        let name = fixture(mode);
        let bytes =
            std::fs::read(cx.extensions()?.join(&name)).map_err(|e| format!("SKIP: {e}"))?;
        expect_code(
            ns.root
                .register_extension(&name, openaevc_crypto::sha256(&bytes), vec![])
                .await,
            ErrorCode::ExtensionIncompatible,
        )
        .map_err(|e| format!("{mode}: {e}"))?;
    }
    let list = ns.root.query(Query::ListExtensions {}).await.c()?;
    ensure(list == json!([]), "failed registrations record nothing")
}

pub async fn kinds(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let name = exe_name("openaevc-ext-reference-null");
    let bytes = std::fs::read(cx.extensions()?.join(&name)).map_err(|e| format!("SKIP: {e}"))?;
    let d = openaevc_crypto::sha256(&bytes);
    let first = ns
        .root
        .register_extension(
            &name,
            d,
            vec![HostCapability::ResourceRead, HostCapability::ProcessExecute],
        )
        .await
        .c()?;
    let obj = ns.root.get_object(first).await.c()?;
    ensure(
        obj.kind() == ObjectKind::ExtensionManifest,
        "the manifest is stored as an immutable object",
    )?;
    let body: ExtensionManifest = obj.body().c()?;
    ensure(
        body.artifact_digest == d,
        "stored manifest pins the artifact",
    )?;
    // Re-registration is an upgrade; the earlier manifest stays resolvable.
    ns.root.register_extension(&name, d, vec![]).await.c()?;
    ensure(
        ns.root.get_object(first).await.c()? == obj,
        "earlier manifests remain",
    )?;
    let list = ns.root.query(Query::ListExtensions {}).await.c()?;
    ensure(
        list.as_array()
            .is_some_and(|l| l.len() == 1 && l[0]["active"] == true),
        format!("one active registration per extension: {list}"),
    )?;
    let events = cx.events(&ns.root).await?;
    let reg: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "extension.registered")
        .collect();
    ensure(
        reg.len() == 2,
        "each registration appends extension.registered",
    )?;
    // Granted = requested ∩ approved: the extension requests nothing it was approved beyond.
    let granted = |i: usize| {
        reg[i].body["granted_host_capabilities"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    };
    let requested: Vec<String> = body
        .host_capabilities
        .iter()
        .map(|c| {
            serde_json::to_value(c)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default()
        })
        .collect();
    ensure(
        granted(0)
            .iter()
            .all(|g| g.as_str().is_some_and(|g| requested.iter().any(|r| r == g))),
        "grants never exceed the manifest's requests",
    )?;
    ensure(
        granted(1).is_empty(),
        "grants never exceed the caller's approvals",
    )
}

pub async fn capabilities(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = sealed(&ns).await?;
    for mode in ["undeclared-resource", "undeclared-process"] {
        register(cx, &ns, &fixture(mode)).await?;
        expect_code(verify(&ns, pack, mode).await, ErrorCode::ExtensionFailed)
            .map_err(|e| format!("{mode}: {e}"))?;
    }
    ensure(
        !cx.events(&ns.root)
            .await?
            .iter()
            .any(|e| e.kind == "verification.completed"),
        "failed invocations record no results",
    )
}

pub async fn limits(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = sealed(&ns).await?;
    // Deadline and frame size depend on runtime configuration; the in-process target sets them
    // below the fixtures' 5 s sleep and 8 MiB output.
    let modes: &[&str] = if cx.target.is_remote() {
        &["invalid-frame", "crash"]
    } else {
        &["invalid-frame", "crash", "oversized", "slow"]
    };
    for mode in modes {
        register(cx, &ns, &fixture(mode)).await?;
        expect_code(verify(&ns, pack, mode).await, ErrorCode::ExtensionFailed)
            .map_err(|e| format!("{mode}: {e}"))?;
    }
    let p = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    ensure(
        ns.root.get_change_pack(p).await.c()?.state == PackState::Open,
        "the runtime remains available",
    )
}

pub async fn environment(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = sealed(&ns).await?;
    register(cx, &ns, &fixture("probe")).await?;
    let r = verify(&ns, pack, "probe").await.c()?;
    let v: VerificationResult = ns
        .root
        .get_object(r.result.digest.ok_or("digest")?)
        .await
        .c()?
        .body()
        .c()?;
    let env = match v.facts.get("fixture.probe.env") {
        Some(FactValue::Set(s)) => s.clone(),
        other => return Err(format!("probe reported no environment: {other:?}")),
    };
    ensure(
        env.iter().all(|k| k == "PATH"),
        format!("extension saw environment variables {env:?}"),
    )?;
    let cwd = match v.facts.get("fixture.probe.cwd") {
        Some(FactValue::Text(s)) => s.clone(),
        _ => return Err("probe reported no cwd".into()),
    };
    let dir = cx.extensions()?;
    let same = std::fs::canonicalize(&cwd).ok() == std::fs::canonicalize(&dir).ok();
    ensure(
        same,
        format!("working directory {cwd} is not the extension directory"),
    )
}

pub async fn reverification(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = sealed(&ns).await?;
    let copy = Copy::new(cx)?;
    register(cx, &ns, &fixture(&copy.1)).await?;
    verify(&ns, pack, &copy.1).await.c()?;
    let mut bytes = std::fs::read(&copy.0).map_err(|e| e.to_string())?;
    bytes.push(0);
    std::fs::write(&copy.0, bytes).map_err(|e| e.to_string())?;
    expect_code(
        verify(&ns, pack, &copy.1).await,
        ErrorCode::ExtensionIncompatible,
    )
    .map(drop)
}
