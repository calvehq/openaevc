//! Shared setup: an embedded runtime over SQLite and SDK clients.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openaevc::core::{IdGeneratorExt, SystemClock, UuidV7Ids};
use openaevc::crypto::{Signer, SigningKey};
use openaevc::protocol::*;
use openaevc::runtime::{Admin, Runtime, RuntimeConfig, RuntimeDeps};
use openaevc::store::{SqliteOptions, SqliteStore};
use openaevc_sdk::{EmbeddedClient, OpenAevcClient, Session, TypedClient};

use crate::Result;

#[derive(Debug)]
pub struct Embedded {
    pub rt: Arc<Runtime>,
    pub admin: Arc<SigningKey>,
    pub admin_id: PrincipalId,
}

/// Opens an embedded runtime over a fresh SQLite data root.
pub fn open_embedded(data_root: &Path, extension_dirs: Vec<PathBuf>) -> Result<Embedded> {
    let store = SqliteStore::open(data_root, SqliteOptions::create())?;
    let clock = Arc::new(SystemClock);
    let ids = Arc::new(UuidV7Ids::new(clock.clone()));
    let admin = Arc::new(SigningKey::generate());
    let admin_id: PrincipalId = ids.next();
    let config = RuntimeConfig {
        admins: vec![Admin {
            id: admin_id,
            public_key: admin.public_key(),
        }],
        extension_dirs,
        // A lease must outlast the slowest step between heartbeats; each effect spawns the
        // extension twice, which can take tens of seconds on a loaded machine.
        lease_ms: 120_000,
        ..Default::default()
    };
    let deps = RuntimeDeps {
        store: Arc::new(store),
        clock,
        ids: ids.clone(),
        signer: Arc::new(SigningKey::generate()),
        runtime_principal: ids.next(),
    };
    Ok(Embedded {
        rt: Arc::new(Runtime::open(deps, config)?),
        admin,
        admin_id,
    })
}

/// Creates a Namespace and returns a client for its root principal.
pub async fn new_namespace(e: &Embedded) -> Result<(EmbeddedClient, Arc<SigningKey>)> {
    let admin = EmbeddedClient::new(
        e.rt.clone(),
        Session::new(e.admin.clone(), e.admin_id, None),
    );
    let key = Arc::new(SigningKey::generate());
    let (ns, roots) = admin.create_namespace(vec![key_principal(&key)]).await?;
    Ok((
        EmbeddedClient::new(e.rt.clone(), Session::new(key.clone(), roots[0], Some(ns))),
        key,
    ))
}

pub fn key_principal(key: &SigningKey) -> NewPrincipal {
    NewPrincipal {
        kind: PrincipalKind::Key,
        public_key: Some(key.public_key()),
        linked_to: None,
        attributes: BTreeMap::new(),
    }
}

pub const PROVIDER: &str = "org.example.provider";
pub const HARNESS: &str = "org.example.harness";
pub const WORKER: &str = "org.example.worker";

pub fn provider(principal: PrincipalId) -> ProviderDescriptor {
    ProviderDescriptor {
        id: PROVIDER.into(),
        version: "1.0.0".into(),
        worker_kinds: vec![WORKER.into()],
        harnesses: vec![HARNESS.into()],
        required_actions: vec![],
        cancellation: true,
        resumable: false,
        heartbeat: true,
        limits: BTreeMap::new(),
        provenance_fields: vec![],
        principal,
    }
}

/// Registers the extension executable `name` from `dir` (pinning its digest).
pub async fn register_extension<C: OpenAevcClient>(
    c: &C,
    dir: &Path,
    name: &str,
) -> Result<Digest> {
    let digest = openaevc::crypto::sha256(&std::fs::read(dir.join(name))?);
    Ok(
        c.register_extension(name, digest, vec![HostCapability::ResourceRead])
            .await?,
    )
}

/// Adds a work unit and drives one execution that submits `effects`; returns the new generation.
pub async fn run_effects<C: OpenAevcClient>(
    c: &C,
    pack: PackId,
    effects: Vec<EffectProposal>,
    resource_kind: &str,
) -> Result<u64> {
    let generation = c.get_change_pack(pack).await?.generation;
    let wu = c
        .add_work_unit(pack, generation, "org.example.task")
        .await?;
    let kinds: Vec<String> = effects
        .iter()
        .map(|e| e.kind.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let request = ExecutionRequest {
        pack,
        expected_generation: generation + 1,
        work_unit: wu,
        provider: PROVIDER.into(),
        harness: HARNESS.into(),
        worker: Some(WorkerInfo {
            id: "example-worker".into(),
            kind: WORKER.into(),
            attributes: BTreeMap::new(),
        }),
        allowed_resources: vec![ResourceSelector {
            kind: resource_kind.into(),
            locator_prefix: None,
        }],
        allowed_effects: kinds,
        context: vec![],
        timeout_ms: 60_000,
        budget: BTreeMap::new(),
        max_attempts: 1,
        idempotency_key: format!("example-{wu}"),
        retry_of: None,
    };
    let (_, lease) = c.start_execution(request).await?;
    for e in effects {
        // Keep the lease alive: effects can take a while (each spawns the extension).
        c.heartbeat(&lease).await?;
        if !c.submit_effect(&lease, e).await? {
            return Err("effect rejected by the extension".into());
        }
    }
    c.complete_execution(&lease).await?;
    Ok(generation + 1)
}

pub fn kv_set(key: &str, value: &str) -> EffectProposal {
    EffectProposal {
        kind: "kv.set".into(),
        target: ResourceRef {
            kind: "kv.entry".into(),
            locator: key.into(),
            version: None,
            extension: "org.openaevc.reference.kv".into(),
        },
        payload: serde_json::json!({"value": value}),
        preconditions: vec![],
        outputs: vec![],
    }
}
