//! Extension and provider registry commands (spec/extensions.md, spec/execution.md).

use std::collections::BTreeSet;

use crate::core::names;
use crate::extension::host;
use crate::protocol::{
    err, CommandResult, Digest, ErrorCode, HostCapability, ObjectKind, ProtocolError,
    ProviderDescriptor,
};
use serde_json::json;

use crate::runtime::ext;
use crate::runtime::records::{self, ExtensionRecord};
use crate::runtime::tx::Tx;
use crate::runtime::{authz, Ctx, Result};

fn incompatible(m: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorCode::ExtensionIncompatible, m)
}

fn validate_manifest(m: &crate::protocol::ExtensionManifest) -> Result<()> {
    names::validate_extension_id(&m.id)?;
    names::validate_semver(&m.version)?;
    let resources: BTreeSet<&str> = m.resource_kinds.iter().map(|r| r.kind.as_str()).collect();
    for r in &resources {
        names::validate_namespaced(r)?;
    }
    for e in &m.effect_kinds {
        names::validate_namespaced(&e.kind)?;
        if !resources.contains(e.resource_kind.as_str()) {
            return Err(incompatible(format!(
                "effect {} targets undeclared resource kind {}",
                e.kind, e.resource_kind
            )));
        }
        if e.required_actions.is_empty() {
            return Err(incompatible(format!(
                "effect {} declares no required actions",
                e.kind
            )));
        }
        e.required_actions
            .iter()
            .try_for_each(|a| names::validate_namespaced(a))?;
    }
    for k in m
        .verifier_kinds
        .iter()
        .chain(&m.evaluator_kinds)
        .chain(&m.composition_validators)
    {
        names::validate_namespaced(k)?;
    }
    if !m.execution_modes.iter().any(|x| x == "subprocess") {
        return Err(incompatible(
            "extension does not support the subprocess execution mode",
        ));
    }
    Ok(())
}

fn claimed_kinds(m: &crate::protocol::ExtensionManifest) -> Vec<String> {
    m.resource_kinds
        .iter()
        .map(|r| r.kind.clone())
        .chain(m.effect_kinds.iter().map(|e| e.kind.clone()))
        .chain(m.verifier_kinds.iter().cloned())
        .chain(m.evaluator_kinds.iter().cloned())
        .chain(m.composition_validators.iter().cloned())
        .collect()
}

/// Requested host capabilities this host cannot provide: reported, never granted.
pub(crate) fn unsupported_capabilities(
    m: &crate::protocol::ExtensionManifest,
) -> Vec<HostCapability> {
    let mut v: Vec<HostCapability> = m
        .host_capabilities
        .iter()
        .copied()
        .filter(|c| !host::SUPPORTED_HOST_CAPABILITIES.contains(c))
        .collect();
    v.sort();
    v.dedup();
    v
}

pub(crate) fn register(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    entrypoint: String,
    pinned: Digest,
    approved: Vec<HostCapability>,
) -> Result<CommandResult> {
    authz(tx, ctx, "extension.register", None)?;
    let program = ext::resolve_entrypoint(&tx.rt.config.extension_dirs, &entrypoint)?;
    let actual = host::artifact_digest(&program)?;
    if actual != pinned {
        return Err(incompatible(format!(
            "artifact digest {actual} does not match the pinned digest {pinned}"
        )));
    }
    let ep = host::Entrypoint {
        program: program.clone(),
        args: vec![],
    };
    let (manifest, _) =
        host::handshake(&ep, &ext::limits(tx)).map_err(|e| e.into_protocol(&entrypoint))?;
    if manifest.artifact_digest != actual {
        return Err(incompatible(format!(
            "manifest artifact digest {} does not match the executable ({actual})",
            manifest.artifact_digest
        )));
    }
    validate_manifest(&manifest)?;
    let mine: BTreeSet<String> = claimed_kinds(&manifest).into_iter().collect();
    for other in ext::active_extensions(tx)?
        .iter()
        .filter(|r| r.manifest.id != manifest.id)
    {
        if let Some(k) = claimed_kinds(&other.manifest)
            .into_iter()
            .find(|k| mine.contains(k))
        {
            return Err(err::conflict(format!(
                "kind {k} is already provided by extension {}",
                other.manifest.id
            )));
        }
    }
    let mut approved: Vec<HostCapability> = approved
        .into_iter()
        .filter(|c| {
            manifest.host_capabilities.contains(c) && host::SUPPORTED_HOST_CAPABILITIES.contains(c)
        })
        .collect();
    approved.sort();
    approved.dedup();
    let unsupported = unsupported_capabilities(&manifest);
    let obj = tx.object(
        ObjectKind::ExtensionManifest,
        Some(manifest.id.clone()),
        &manifest,
        false,
    )?;
    let id = manifest.id.clone();
    let rec = ExtensionRecord {
        manifest,
        manifest_digest: obj.digest(),
        program: program.to_string_lossy().into_owned(),
        approved: approved.clone(),
        active: true,
        registered_at: tx.now,
    };
    tx.put(records::EXTENSION, &records::key(&tx.ns, &id), &rec)?;
    tx.emit(
        "extension.registered",
        json!({"extension": id, "version": rec.manifest.version, "manifest": obj.digest(), "artifact": actual, "granted_host_capabilities": approved, "unsupported_host_capabilities": unsupported}),
        vec![id.clone(), obj.digest().to_string()],
    );
    Ok(CommandResult {
        id: Some(id),
        digest: Some(obj.digest()),
        ..Default::default()
    })
}

pub(crate) fn unregister(tx: &mut Tx<'_>, ctx: &Ctx, id: String) -> Result<CommandResult> {
    authz(tx, ctx, "extension.register", None)?;
    let key = records::key(&tx.ns, &id);
    let mut rec: ExtensionRecord = tx.require(records::EXTENSION, &key, "extension")?;
    if !rec.active {
        return Err(ProtocolError::new(
            ErrorCode::InvalidTransition,
            format!("extension {id} is not registered"),
        ));
    }
    rec.active = false;
    tx.put(records::EXTENSION, &key, &rec)?;
    tx.emit(
        "extension.unregistered",
        json!({"extension": id}),
        vec![id.clone()],
    );
    Ok(CommandResult {
        id: Some(id),
        ..Default::default()
    })
}

pub(crate) fn register_provider(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    p: ProviderDescriptor,
) -> Result<CommandResult> {
    authz(tx, ctx, "provider.register", None)?;
    names::validate_extension_id(&p.id)?;
    names::validate_semver(&p.version)?;
    for n in p
        .worker_kinds
        .iter()
        .chain(&p.harnesses)
        .chain(&p.required_actions)
        .chain(&p.provenance_fields)
    {
        names::validate_namespaced(n)?;
    }
    names::validate_keys(&p.limits)?;
    if p.harnesses.is_empty() || p.worker_kinds.is_empty() {
        return Err(err::invalid(
            "a provider needs at least one worker kind and harness",
        ));
    }
    if tx
        .peek::<crate::protocol::Principal>(records::PRINCIPAL, &records::key(&tx.ns, p.principal))?
        .is_none()
    {
        return Err(err::not_found(format!(
            "provider principal {} not found",
            p.principal
        )));
    }
    let id = p.id.clone();
    // The provider principal drives executions: only it or a root may replace a registration.
    if let Some(old) =
        tx.peek::<ProviderDescriptor>(records::PROVIDER, &records::key(&tx.ns, &id))?
    {
        if old.principal != ctx.principal && !ctx.roots.contains(&ctx.principal) {
            return Err(err::forbidden(format!(
                "provider {id} is registered to another principal"
            ))
            .with_missing_action("provider.register"));
        }
    }
    tx.put(records::PROVIDER, &records::key(&tx.ns, &id), &p)?;
    tx.emit(
        "provider.registered",
        json!({"provider": id, "version": p.version}),
        vec![id.clone()],
    );
    Ok(CommandResult {
        id: Some(id),
        ..Default::default()
    })
}
