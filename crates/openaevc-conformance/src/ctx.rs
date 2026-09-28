//! Helpers shared by conformance cases.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use openaevc_core::request::sign_request;
use openaevc_crypto::{Signer, SigningKey};
use openaevc_protocol::*;
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::{json, Value};

use crate::target::{Client, Target};
use crate::{Case, CaseResult};

/// Converts protocol errors into case failures.
pub trait Check<T> {
    fn c(self) -> Result<T, String>;
}

impl<T> Check<T> for Result<T, ProtocolError> {
    fn c(self) -> Result<T, String> {
        self.map_err(|e| format!("unexpected error {}: {}", e.code, e.message))
    }
}

/// Asserts that `r` failed with `code`.
pub fn expect_code<T: std::fmt::Debug>(
    r: Result<T, ProtocolError>,
    code: ErrorCode,
) -> Result<ProtocolError, String> {
    match r {
        Err(e) if e.code == code => Ok(e),
        Err(e) => Err(format!("expected {code}, got {}: {}", e.code, e.message)),
        Ok(v) => Err(format!("expected {code}, got success: {v:?}")),
    }
}

pub fn ensure(cond: bool, msg: impl Into<String>) -> CaseResult {
    if cond {
        Ok(())
    } else {
        Err(msg.into())
    }
}

pub const PROVIDER: &str = "org.openaevc.conformance.provider";
pub const HARNESS: &str = "org.openaevc.conformance.harness";
pub const WORKER: &str = "org.openaevc.conformance.worker";
pub const KV: &str = "org.openaevc.reference.kv";

/// A fresh Namespace and its root principal.
#[derive(Clone, Debug)]
pub struct Ns {
    pub id: NamespaceId,
    pub root: Client,
    pub root_id: PrincipalId,
    pub root_key: Arc<SigningKey>,
}

/// Another principal registered in a Namespace.
#[derive(Clone, Debug)]
pub struct Member {
    pub id: PrincipalId,
    pub key: Arc<SigningKey>,
    pub client: Client,
}

#[derive(Debug)]
pub struct Ctx {
    pub target: Target,
}

pub fn key_principal(key: &SigningKey) -> NewPrincipal {
    NewPrincipal {
        kind: PrincipalKind::Key,
        public_key: Some(key.public_key()),
        linked_to: None,
        attributes: BTreeMap::new(),
    }
}

pub fn kv_resource(key: &str) -> ResourceRef {
    ResourceRef {
        kind: "kv.entry".into(),
        locator: key.into(),
        version: None,
        extension: KV.into(),
    }
}

pub fn kv_set(key: &str, value: &str) -> EffectProposal {
    EffectProposal {
        kind: "kv.set".into(),
        target: kv_resource(key),
        payload: json!({"value": value}),
        preconditions: vec![],
        outputs: vec![],
    }
}

pub fn exe_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

impl Ctx {
    pub fn new(target: Target) -> Self {
        Ctx { target }
    }

    pub fn skip_reason(&self, _case: &Case) -> Option<String> {
        None
    }

    /// Local extension directory, or a skip.
    pub fn extensions(&self) -> Result<PathBuf, String> {
        self.target
            .extensions()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| "SKIP: no extension directory configured (--extensions)".to_string())
    }

    pub async fn namespace(&self) -> Result<Ns, String> {
        let key = Arc::new(SigningKey::generate());
        let (ns, roots) = self
            .target
            .admin()
            .create_namespace(vec![key_principal(&key)])
            .await
            .c()?;
        let root = self
            .target
            .client(self.target.session(key.clone(), roots[0], Some(ns)));
        Ok(Ns {
            id: ns,
            root,
            root_id: roots[0],
            root_key: key,
        })
    }

    pub fn client_for(&self, ns: NamespaceId, key: Arc<SigningKey>, id: PrincipalId) -> Client {
        self.target.client(self.target.session(key, id, Some(ns)))
    }

    /// Registers a key principal (by the root) and returns its client.
    pub async fn member(&self, ns: &Ns) -> Result<Member, String> {
        let key = Arc::new(SigningKey::generate());
        let id = ns.root.register_principal(key_principal(&key)).await.c()?;
        Ok(Member {
            id,
            key: key.clone(),
            client: self.client_for(ns.id, key, id),
        })
    }

    pub fn grant_body(
        &self,
        ns: NamespaceId,
        issuer: PrincipalId,
        subject: PrincipalId,
        actions: &[&str],
        parent: Option<Digest>,
        depth: u32,
    ) -> GrantBody {
        let now = self.target.now();
        GrantBody {
            id: fresh(),
            namespace: ns,
            issuer,
            subject,
            actions: actions
                .iter()
                .map(|a| a.to_string())
                .collect::<BTreeSet<_>>(),
            resources: vec![],
            constraints: BTreeMap::new(),
            // Backdated so modest clock skew between client and runtime cannot make it not-yet-valid.
            not_before: Timestamp::from_unix_nanos(now.unix_nanos() - 60_000_000_000),
            expires_at: now.plus_millis(24 * 3600 * 1000),
            delegation_depth: depth,
            parent,
            nonce: b64::encode(fresh::<RequestId>().as_bytes()),
        }
    }

    /// Root issues `actions` to `subject`; returns (grant id, grant digest).
    pub async fn grant(
        &self,
        ns: &Ns,
        subject: PrincipalId,
        actions: &[&str],
    ) -> Result<(GrantId, Digest), String> {
        let body = self.grant_body(ns.id, ns.root_id, subject, actions, None, 2);
        let id = body.id;
        Ok((id, ns.root.issue_grant(body).await.c()?))
    }

    /// Builds a signed envelope value, applying `edit` to the unsigned value first.
    pub fn signed_value(
        &self,
        key: &SigningKey,
        caller: PrincipalId,
        ns: Option<NamespaceId>,
        body: Value,
        edit: impl FnOnce(&mut Value),
    ) -> Value {
        let mut v = json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": fresh::<RequestId>(),
            "caller": caller,
            "nonce": b64::encode(fresh::<RequestId>().as_bytes()),
            "issued_at": self.target.now(),
            "body": body,
        });
        if let Some(ns) = ns {
            v["namespace"] = json!(ns);
        }
        edit(&mut v);
        if let Ok(bytes) = openaevc_canonical::encode(&v) {
            v["signature"] = json!(key
                .sign(openaevc_crypto::Domain::Request, &bytes)
                .to_string());
        }
        v
    }

    /// Signs a typed envelope for raw submission.
    pub fn envelope_value<T: serde::Serialize>(
        &self,
        key: &SigningKey,
        caller: PrincipalId,
        ns: Option<NamespaceId>,
        body: T,
    ) -> Result<Value, String> {
        let env = Envelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: fresh(),
            namespace: ns,
            caller,
            act_as: None,
            nonce: b64::encode(fresh::<RequestId>().as_bytes()),
            issued_at: self.target.now(),
            expires_at: None,
            body,
            signature: None,
        };
        let env = sign_request(env, key).c()?;
        serde_json::to_value(env).map_err(|e| e.to_string())
    }

    /// Registers reference-kv and the conformance provider in `ns`.
    pub async fn setup_kv(&self, ns: &Ns) -> CaseResult {
        let dir = self.extensions()?;
        let name = exe_name("openaevc-ext-reference-kv");
        let bytes = std::fs::read(dir.join(&name))
            .map_err(|e| format!("SKIP: reference-kv not found in extension directory: {e}"))?;
        ns.root
            .register_extension(
                &name,
                openaevc_crypto::sha256(&bytes),
                vec![HostCapability::ResourceRead],
            )
            .await
            .c()?;
        ns.root
            .command(Command::RegisterProvider {
                provider: provider(ns.root_id, false),
            })
            .await
            .c()?;
        Ok(())
    }

    pub fn execution_request(
        &self,
        pack: PackId,
        generation: u64,
        work_unit: WorkUnitId,
        effects: &[&str],
    ) -> ExecutionRequest {
        ExecutionRequest {
            pack,
            expected_generation: generation,
            work_unit,
            provider: PROVIDER.into(),
            harness: HARNESS.into(),
            worker: Some(WorkerInfo {
                id: "conformance-worker".into(),
                kind: WORKER.into(),
                attributes: BTreeMap::new(),
            }),
            allowed_resources: if effects.is_empty() {
                vec![]
            } else {
                vec![ResourceSelector {
                    kind: "kv.entry".into(),
                    locator_prefix: None,
                }]
            },
            allowed_effects: effects.iter().map(|s| s.to_string()).collect(),
            context: vec![],
            timeout_ms: 60_000,
            budget: BTreeMap::new(),
            max_attempts: 3,
            idempotency_key: fresh::<RequestId>().to_string(),
            retry_of: None,
        }
    }

    /// Adds a work unit and runs an execution applying `effects`; returns the pack generation.
    pub async fn run_effects(
        &self,
        c: &Client,
        pack: PackId,
        effects: Vec<EffectProposal>,
    ) -> Result<u64, String> {
        let generation = c.get_change_pack(pack).await.c()?.generation;
        let wu = c
            .add_work_unit(pack, generation, "org.openaevc.conformance.task")
            .await
            .c()?;
        let (_, lease) = c
            .start_execution(self.execution_request(
                pack,
                generation + 1,
                wu,
                &["kv.set", "kv.delete"],
            ))
            .await
            .c()?;
        for e in effects {
            c.heartbeat(&lease).await.c()?;
            ensure(c.submit_effect(&lease, e).await.c()?, "effect was rejected")?;
        }
        c.heartbeat(&lease).await.c()?;
        c.complete_execution(&lease).await.c()?;
        Ok(generation + 1)
    }

    /// Seals and qualifies (no gates) a pack at `generation`, then promotes it.
    pub async fn finish(
        &self,
        c: &Client,
        pack: PackId,
        generation: u64,
    ) -> Result<Digest, String> {
        c.seal(pack, generation).await.c()?;
        let q = c.refresh_qualification(pack, generation).await.c()?;
        ensure(
            q.result.state.as_deref() == Some("QUALIFIED"),
            format!("pack did not qualify: {:?}", q.result.state),
        )?;
        c.promote(pack, generation).await.c()
    }

    pub async fn promote_empty(&self, c: &Client) -> Result<(PackId, Digest), String> {
        let pack = c.create_change_pack(PackSpec::default()).await.c()?;
        Ok((pack, self.finish(c, pack, 1).await?))
    }

    pub async fn promote_kv(
        &self,
        c: &Client,
        key: &str,
        value: &str,
    ) -> Result<(PackId, Digest), String> {
        let pack = c.create_change_pack(PackSpec::default()).await.c()?;
        let generation = self.run_effects(c, pack, vec![kv_set(key, value)]).await?;
        Ok((pack, self.finish(c, pack, generation).await?))
    }

    pub async fn events(&self, c: &Client) -> Result<Vec<Event>, String> {
        let v = c
            .query(Query::ListEvents {
                after: 0,
                limit: None,
                kinds: vec![],
            })
            .await
            .c()?;
        serde_json::from_value(v).map_err(|e| e.to_string())
    }
}

pub fn provider(principal: PrincipalId, resumable: bool) -> ProviderDescriptor {
    ProviderDescriptor {
        id: PROVIDER.into(),
        version: "1.0.0".into(),
        worker_kinds: vec![WORKER.into()],
        harnesses: vec![HARNESS.into()],
        required_actions: vec![],
        cancellation: true,
        resumable,
        heartbeat: true,
        limits: BTreeMap::new(),
        provenance_fields: vec![],
        principal,
    }
}

/// A fresh typed identifier.
pub fn fresh<T: openaevc_core::FromUuid>() -> T {
    use openaevc_core::IdGeneratorExt;
    openaevc_core::UuidV7Ids::new(Arc::new(openaevc_core::SystemClock)).next()
}

pub fn fixtures(name: &str) -> Result<Value, String> {
    let text = match name {
        "values" => include_str!("../fixtures/values.json"),
        "objects" => include_str!("../fixtures/objects.json"),
        "signatures" => include_str!("../fixtures/signatures.json"),
        _ => return Err(format!("unknown fixture {name}")),
    };
    serde_json::from_str(text).map_err(|e| e.to_string())
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
