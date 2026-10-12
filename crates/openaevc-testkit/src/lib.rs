//! Test support for OpenAEVC: deterministic clocks and keys, a signing client over an
//! embedded runtime, and helpers for common setup. Never a production dependency.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use openaevc_core::request::sign_request;
use openaevc_core::{Clock, FixedClock, IdGenerator, IdGeneratorExt, UuidV7Ids};
use openaevc_crypto::{Signer, SigningKey};
use openaevc_protocol::*;
use openaevc_runtime::{Admin, Runtime, RuntimeConfig, RuntimeDeps};
use openaevc_store::{MemoryStore, SqliteOptions, SqliteStore, Store};
use serde_json::Value;

/// 2025-01-01T00:00:00Z.
pub const EPOCH_2025: i64 = 1_735_689_600_000_000_000;

/// A principal's key plus its registered ID (assigned after registration).
#[derive(Clone)]
pub struct Identity {
    key: Arc<SigningKey>,
    id: std::sync::Arc<std::sync::OnceLock<PrincipalId>>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({:?})", self.id.get())
    }
}

impl Identity {
    pub fn generate() -> Self {
        Identity {
            key: Arc::new(SigningKey::generate()),
            id: Default::default(),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Identity {
            key: Arc::new(SigningKey::from_seed(seed)),
            id: Default::default(),
        }
    }

    pub fn with_id(self, id: PrincipalId) -> Self {
        let _ = self.id.set(id);
        self
    }

    /// Registered principal ID. Panics if the identity was never registered.
    pub fn id(&self) -> PrincipalId {
        *self.id.get().expect("identity has not been registered")
    }

    pub fn set_id(&self, id: PrincipalId) {
        let _ = self.id.set(id);
    }

    pub fn key(&self) -> &SigningKey {
        &self.key
    }

    /// Shared signer handle (for SDK sessions).
    pub fn signer(&self) -> Arc<SigningKey> {
        self.key.clone()
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    pub fn new_principal(&self) -> NewPrincipal {
        NewPrincipal {
            kind: PrincipalKind::Key,
            public_key: Some(self.public_key()),
            linked_to: None,
            attributes: BTreeMap::new(),
        }
    }
}

/// An embedded runtime plus deterministic clock and a fixed administrator.
pub struct Harness {
    pub rt: Arc<Runtime>,
    pub clock: FixedClock,
    pub admin: Identity,
    pub ids: Arc<dyn IdGenerator>,
}

impl std::fmt::Debug for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Harness").finish_non_exhaustive()
    }
}

pub fn admin_identity() -> Identity {
    Identity::from_seed([0xad; 32])
        .with_id("pri_agjdus24nvyadaareizuivlgo4".parse().expect("valid id"))
}

pub fn runtime_key() -> SigningKey {
    SigningKey::from_seed([0x7e; 32])
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    pub fn new() -> Self {
        Self::with_config(|_| {})
    }

    pub fn with_config(f: impl FnOnce(&mut RuntimeConfig)) -> Self {
        Self::build(Arc::new(MemoryStore::new()), FixedClock::new(EPOCH_2025), f)
    }

    /// Runtime over a SQLite data root (reopenable: same admin and runtime key).
    pub fn sqlite(root: &Path) -> Self {
        let store = SqliteStore::open(root, SqliteOptions::create()).expect("open sqlite store");
        Self::build(Arc::new(store), FixedClock::new(EPOCH_2025), |_| {})
    }

    pub fn build(
        store: Arc<dyn Store>,
        clock: FixedClock,
        f: impl FnOnce(&mut RuntimeConfig),
    ) -> Self {
        let admin = admin_identity();
        let mut config = RuntimeConfig {
            admins: vec![Admin {
                id: admin.id(),
                public_key: admin.public_key(),
            }],
            ..Default::default()
        };
        f(&mut config);
        let ids: Arc<dyn IdGenerator> = Arc::new(UuidV7Ids::new(Arc::new(clock.clone())));
        let deps = RuntimeDeps {
            store,
            clock: Arc::new(clock.clone()),
            ids: ids.clone(),
            signer: Arc::new(runtime_key()),
            runtime_principal: "pri_agjdus24nvyadaareizuivlgp4".parse().expect("valid id"),
        };
        let rt = Arc::new(Runtime::open(deps, config).expect("runtime opens"));
        Harness {
            rt,
            clock,
            admin,
            ids,
        }
    }

    pub fn client(&self, who: &Identity, ns: NamespaceId) -> Client<'_> {
        Client {
            h: self,
            who: who.clone(),
            ns: Some(ns),
            act_as: None,
        }
    }

    pub fn admin_client(&self) -> Client<'_> {
        Client {
            h: self,
            who: self.admin.clone(),
            ns: None,
            act_as: None,
        }
    }

    /// Admin-style client signing with an arbitrary key (for negative tests).
    pub fn admin_client_as(&self, who: &Identity) -> Client<'_> {
        let who = if who.id.get().is_some() {
            who.clone()
        } else {
            who.clone().with_id(self.ids.next())
        };
        Client {
            h: self,
            who,
            ns: None,
            act_as: None,
        }
    }

    /// Creates a Namespace whose single root is `root` (assigning its ID).
    pub fn create_namespace(&self, root: &Identity) -> NamespaceId {
        let r = self
            .admin_client()
            .cmd(Command::CreateNamespace {
                root_principals: vec![root.new_principal()],
                metadata: BTreeMap::new(),
            })
            .expect("create namespace");
        root.set_id(r.result.ids[0].parse().expect("principal id"));
        r.result
            .id
            .expect("namespace id")
            .parse()
            .expect("namespace id")
    }

    pub fn register_key_principal(&self, root: &Identity, ns: NamespaceId) -> Identity {
        let who = Identity::generate();
        let r = self
            .client(root, ns)
            .cmd(Command::RegisterPrincipal {
                principal: who.new_principal(),
            })
            .expect("register principal");
        who.set_id(r.result.id.expect("id").parse().expect("id"));
        who
    }

    pub fn register_actor(&self, root: &Identity, ns: NamespaceId, linked: &Identity) -> Identity {
        let actor = Identity::generate();
        let p = NewPrincipal {
            kind: PrincipalKind::Actor,
            public_key: None,
            linked_to: Some(linked.id()),
            attributes: BTreeMap::from([(
                "org.openaevc.testkit.kind".to_string(),
                "agent".to_string(),
            )]),
        };
        let r = self
            .client(root, ns)
            .cmd(Command::RegisterPrincipal { principal: p })
            .expect("register actor");
        actor.set_id(r.result.id.expect("id").parse().expect("id"));
        actor
    }

    /// Signs a grant body issued by `issuer`.
    pub fn sign_grant(
        &self,
        issuer: &Identity,
        ns: NamespaceId,
        subject: PrincipalId,
        actions: &[&str],
        parent: Option<Digest>,
    ) -> SignedGrant {
        let now = self.clock.now();
        let body = GrantBody {
            id: self.ids.next(),
            namespace: ns,
            issuer: issuer.id(),
            subject,
            actions: actions
                .iter()
                .map(|a| a.to_string())
                .collect::<BTreeSet<_>>(),
            resources: vec![],
            constraints: BTreeMap::new(),
            not_before: now.plus_millis(0),
            expires_at: now.plus_millis(365 * 24 * 3600 * 1000),
            delegation_depth: 2,
            parent,
            nonce: b64::encode(&self.ids.next_bytes()),
        };
        openaevc_authority::sign_grant(body, issuer.key()).expect("sign grant")
    }

    /// Root issues `actions` to `subject`; returns the grant ID.
    pub fn grant(
        &self,
        root: &Identity,
        ns: NamespaceId,
        subject: &Identity,
        actions: &[&str],
    ) -> GrantId {
        let g = self.sign_grant(root, ns, subject.id(), actions, None);
        let id = g.body.id;
        self.client(root, ns)
            .cmd(Command::IssueCapabilityGrant { grant: g })
            .expect("issue grant");
        id
    }

    /// A fresh typed ID from the harness generator.
    pub fn ids_next<T: openaevc_core::FromUuid>(&self) -> T {
        self.ids.next()
    }

    /// All journal events of `ns` as JSON (read as `who`).
    pub fn events(&self, who: &Identity, ns: NamespaceId) -> Vec<Value> {
        let v = self
            .client(who, ns)
            .query(Query::ListEvents {
                after: 0,
                limit: None,
                kinds: vec![],
            })
            .expect("list events");
        serde_json::from_value(v).expect("event list")
    }
}

/// Signs and submits envelopes as one identity.
pub struct Client<'h> {
    h: &'h Harness,
    who: Identity,
    ns: Option<NamespaceId>,
    act_as: Option<PrincipalId>,
}

impl std::fmt::Debug for Client<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("who", &self.who).finish()
    }
}

impl Client<'_> {
    pub fn act_as(mut self, actor: PrincipalId) -> Self {
        self.act_as = Some(actor);
        self
    }

    fn envelope<T: serde::Serialize>(&self, body: T) -> Envelope<T> {
        let env = Envelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: self.h.ids.next(),
            namespace: self.ns,
            caller: self.who.id(),
            act_as: self.act_as,
            nonce: b64::encode(&self.h.ids.next_bytes()),
            issued_at: self.h.clock.now(),
            expires_at: None,
            body,
            signature: None,
        };
        sign_request(env, self.who.key()).expect("sign request")
    }

    pub fn command_envelope(&self, c: Command) -> CommandEnvelope {
        self.envelope(c)
    }

    pub fn query_envelope(&self, q: Query) -> QueryEnvelope {
        self.envelope(q)
    }

    /// Re-signs a modified envelope with this client's key.
    pub fn resign<T: serde::Serialize>(&self, env: Envelope<T>) -> Envelope<T> {
        sign_request(env, self.who.key()).expect("sign request")
    }

    pub fn cmd(&self, c: Command) -> Result<CommandReceipt, ProtocolError> {
        self.h.rt.execute(self.command_envelope(c))
    }

    pub fn query(&self, q: Query) -> Result<Value, ProtocolError> {
        self.h.rt.query(self.query_envelope(q))
    }
}

/// Extension binaries installed into a private directory for one test.
pub struct Extensions {
    pub dir: tempfile::TempDir,
}

impl std::fmt::Debug for Extensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extensions")
            .field("dir", &self.dir.path())
            .finish()
    }
}

pub const FIXTURE_MODES: &[&str] = &[
    "well-behaved",
    "undeclared-resource",
    "undeclared-process",
    "oversized",
    "invalid-frame",
    "wrong-digest",
    "slow",
    "incompatible",
    "crash",
    "probe",
    "detached-child",
    "no-read",
    "wants-unsupported",
    "kind-thief",
    "upgrade",
];

/// Builds the extension packages once per test process and returns the target directory.
fn built_extensions() -> &'static Path {
    static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut cmd = std::process::Command::new(cargo);
        cmd.arg("build");
        // Build in the test binary's profile so the binaries land in its target dir.
        if !cfg!(debug_assertions) {
            cmd.arg("--release");
        }
        let status = cmd
            .args([
                "-q",
                "-p",
                "openaevc-ext-reference-kv",
                "-p",
                "openaevc-ext-reference-null",
                "-p",
                "openaevc-ext-conformance-fixtures",
            ])
            .status()
            .expect("run cargo build for extensions");
        assert!(status.success(), "building extensions failed");
        // <target>/<profile>/deps/<test-binary> -> <target>/<profile>
        let exe = std::env::current_exe().expect("current exe");
        exe.parent()
            .and_then(|p| p.parent())
            .expect("target dir")
            .to_path_buf()
    })
}

impl Extensions {
    /// Copies `openaevc-ext-reference-kv`, `openaevc-ext-reference-null` and every
    /// `conformance-fixture-<mode>` into a fresh directory.
    pub fn install() -> Self {
        let target = built_extensions();
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = std::env::consts::EXE_SUFFIX;
        for name in ["openaevc-ext-reference-kv", "openaevc-ext-reference-null"] {
            std::fs::copy(
                target.join(format!("{name}{exe}")),
                dir.path().join(format!("{name}{exe}")),
            )
            .expect("copy extension");
        }
        for mode in FIXTURE_MODES {
            std::fs::copy(
                target.join(format!("openaevc-ext-conformance-fixtures{exe}")),
                dir.path().join(format!("conformance-fixture-{mode}{exe}")),
            )
            .expect("copy fixture");
        }
        Extensions { dir }
    }

    /// Entrypoint name (relative to the extension directory) of an installed binary.
    pub fn entrypoint(name: &str) -> String {
        format!("{name}{}", std::env::consts::EXE_SUFFIX)
    }

    pub fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(Self::entrypoint(name))
    }

    pub fn digest(&self, name: &str) -> Digest {
        openaevc_crypto::sha256(&std::fs::read(self.path(name)).expect("read extension"))
    }
}

impl Harness {
    /// Harness whose runtime may register extensions from `ext.dir`.
    pub fn with_extensions(ext: &Extensions) -> Self {
        let dir = ext.dir.path().to_path_buf();
        Self::with_config(move |c| c.extension_dirs = vec![dir])
    }

    /// Registers an installed extension (all requested host capabilities approved).
    pub fn register_extension(
        &self,
        root: &Identity,
        ns: NamespaceId,
        ext: &Extensions,
        name: &str,
    ) -> CommandReceipt {
        self.client(root, ns)
            .cmd(Command::RegisterExtension {
                entrypoint: Extensions::entrypoint(name),
                artifact_digest: ext.digest(name),
                approved_host_capabilities: HostCapability::ALL.to_vec(),
            })
            .expect("register extension")
    }
}

pub const PROVIDER: &str = "org.openaevc.testkit.provider";
pub const HARNESS: &str = "org.openaevc.testkit.harness";
pub const WORKER_KIND: &str = "org.openaevc.testkit.worker";
pub const KV: &str = "org.openaevc.reference.kv";

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
        payload: serde_json::json!({"value": value}),
        preconditions: vec![],
        outputs: vec![],
    }
}

pub fn kv_delete(key: &str) -> EffectProposal {
    EffectProposal {
        kind: "kv.delete".into(),
        target: kv_resource(key),
        payload: serde_json::json!({}),
        preconditions: vec![],
        outputs: vec![],
    }
}

pub fn provider_descriptor(principal: PrincipalId, resumable: bool) -> ProviderDescriptor {
    ProviderDescriptor {
        id: PROVIDER.into(),
        version: "0.1.0".into(),
        worker_kinds: vec![WORKER_KIND.into()],
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

/// Parsed typed ID from a receipt's `id`.
pub fn receipt_id<T: std::str::FromStr>(r: &CommandReceipt) -> T
where
    T::Err: std::fmt::Debug,
{
    r.result
        .id
        .as_deref()
        .expect("receipt id")
        .parse()
        .expect("typed id")
}

impl Harness {
    /// Registers reference-kv and the testkit provider (principal = root).
    pub fn setup_kv(&self, root: &Identity, ns: NamespaceId, ext: &Extensions) {
        self.register_extension(root, ns, ext, "openaevc-ext-reference-kv");
        self.client(root, ns)
            .cmd(Command::RegisterProvider {
                provider: provider_descriptor(root.id(), false),
            })
            .expect("register provider");
    }

    pub fn create_pack(&self, who: &Identity, ns: NamespaceId) -> PackId {
        receipt_id(
            &self
                .client(who, ns)
                .cmd(Command::CreateChangePack {
                    spec: PackSpec::default(),
                })
                .expect("create pack"),
        )
    }

    pub fn pack(&self, who: &Identity, ns: NamespaceId, pack: PackId) -> ChangePack {
        serde_json::from_value(
            self.client(who, ns)
                .query(Query::GetChangePack {
                    pack,
                    generation: None,
                })
                .expect("get pack"),
        )
        .expect("pack")
    }

    pub fn add_work(&self, who: &Identity, ns: NamespaceId, pack: PackId) -> WorkUnitId {
        let g = self.pack(who, ns, pack).generation;
        receipt_id(
            &self
                .client(who, ns)
                .cmd(Command::AddWorkUnit {
                    pack,
                    expected_generation: g,
                    kind: "org.example.task".into(),
                    spec: None,
                    depends_on: vec![],
                })
                .expect("add work unit"),
        )
    }

    pub fn execution_request(
        &self,
        pack: PackId,
        generation: u64,
        work_unit: WorkUnitId,
    ) -> ExecutionRequest {
        ExecutionRequest {
            pack,
            expected_generation: generation,
            work_unit,
            provider: PROVIDER.into(),
            harness: HARNESS.into(),
            worker: Some(WorkerInfo {
                id: "worker-1".into(),
                kind: WORKER_KIND.into(),
                attributes: BTreeMap::new(),
            }),
            allowed_resources: vec![ResourceSelector {
                kind: "kv.entry".into(),
                locator_prefix: None,
            }],
            allowed_effects: vec!["kv.set".into(), "kv.delete".into()],
            context: vec![],
            timeout_ms: 60_000,
            budget: BTreeMap::new(),
            max_attempts: 3,
            idempotency_key: b64::encode(&self.ids.next_bytes()),
            retry_of: None,
        }
    }

    /// Starts an execution for `work_unit` at the pack's current generation.
    pub fn start(
        &self,
        who: &Identity,
        ns: NamespaceId,
        pack: PackId,
        work_unit: WorkUnitId,
    ) -> (ExecutionId, Lease) {
        let g = self.pack(who, ns, pack).generation;
        let r = self
            .client(who, ns)
            .cmd(Command::StartExecution {
                request: self.execution_request(pack, g, work_unit),
            })
            .expect("start execution");
        (receipt_id(&r), r.result.lease.expect("lease"))
    }

    /// Runs `harness` for a new work unit of `pack` to completion; returns the execution.
    pub fn run(
        &self,
        who: &Identity,
        ns: NamespaceId,
        pack: PackId,
        harness: &mut dyn openaevc_execution::Harness,
    ) -> ExecutionId {
        let wu = self.add_work(who, ns, pack);
        let (exe, lease) = self.start(who, ns, pack, wu);
        let mut session = ClientSession {
            client: self.client(who, ns),
            execution: exe,
            lease: lease.id,
            generation: lease.generation,
        };
        session.heartbeat().expect("heartbeat");
        harness
            .run("org.example.task", None, &mut session)
            .expect("harness run");
        self.client(who, ns)
            .cmd(Command::CompleteExecution {
                execution: exe,
                lease: lease.id,
            })
            .expect("complete");
        exe
    }
}

/// [`openaevc_execution::ExecutionSession`] backed by signed runtime commands.
pub struct ClientSession<'h> {
    pub client: Client<'h>,
    pub execution: ExecutionId,
    pub lease: LeaseId,
    pub generation: u64,
}

impl std::fmt::Debug for ClientSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSession")
            .field("execution", &self.execution)
            .finish()
    }
}

use openaevc_execution::ExecutionSession as _;

impl openaevc_execution::ExecutionSession for ClientSession<'_> {
    fn heartbeat(&mut self) -> Result<(), ProtocolError> {
        self.client
            .cmd(Command::HeartbeatExecution {
                execution: self.execution,
                lease: self.lease,
                generation: self.generation,
            })
            .map(drop)
    }

    fn submit_effect(&mut self, effect: EffectProposal) -> Result<bool, ProtocolError> {
        let r = self.client.cmd(Command::SubmitEffectProposal {
            execution: self.execution,
            lease: self.lease,
            effect,
        })?;
        Ok(r.result.state.as_deref() == Some("APPLIED"))
    }

    fn observe(&mut self, kind: &str, payload: Value) -> Result<ObservationId, ProtocolError> {
        let r = self.client.cmd(Command::AppendObservation {
            execution: self.execution,
            lease: self.lease,
            kind: kind.into(),
            payload: Some(payload),
            blob: None,
            related_resources: vec![],
            related_effects: vec![],
        })?;
        Ok(receipt_id(&r))
    }
}

/// Deterministic reference harness: submits a fixed list of effects, recording one
/// observation per effect.
#[derive(Debug, Clone)]
pub struct ScriptedHarness {
    pub effects: Vec<EffectProposal>,
}

impl openaevc_execution::Harness for ScriptedHarness {
    fn id(&self) -> &str {
        HARNESS
    }

    fn run(
        &mut self,
        _kind: &str,
        _spec: Option<&Value>,
        session: &mut dyn openaevc_execution::ExecutionSession,
    ) -> Result<(), String> {
        for e in self.effects.clone() {
            let key = e.target.locator.clone();
            let applied = session.submit_effect(e).map_err(|e| e.to_string())?;
            session
                .observe(
                    "org.openaevc.testkit.effect",
                    serde_json::json!({"key": key, "applied": applied}),
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

impl Harness {
    /// Seals the pack at its current generation; returns the candidate digest.
    pub fn seal(&self, who: &Identity, ns: NamespaceId, pack: PackId) -> Digest {
        let g = self.pack(who, ns, pack).generation;
        self.client(who, ns)
            .cmd(Command::SealChangePack {
                pack,
                expected_generation: g,
            })
            .expect("seal")
            .result
            .digest
            .expect("candidate")
    }

    pub fn verify(
        &self,
        who: &Identity,
        ns: NamespaceId,
        pack: PackId,
        verifier: &str,
        config: Value,
    ) -> Result<CommandReceipt, ProtocolError> {
        let g = self.pack(who, ns, pack).generation;
        self.client(who, ns).cmd(Command::RunVerification {
            pack,
            generation: g,
            verifier: verifier.into(),
            config: Some(config),
            evidence: vec![],
        })
    }

    pub fn evaluate(
        &self,
        who: &Identity,
        ns: NamespaceId,
        pack: PackId,
        evaluator: &str,
        config: Value,
    ) -> Result<CommandReceipt, ProtocolError> {
        let g = self.pack(who, ns, pack).generation;
        self.client(who, ns).cmd(Command::RunEvaluation {
            pack,
            generation: g,
            evaluator: evaluator.into(),
            config: Some(config),
            inputs: vec![],
        })
    }

    pub fn qualify(&self, who: &Identity, ns: NamespaceId, pack: PackId) -> CommandReceipt {
        let g = self.pack(who, ns, pack).generation;
        self.client(who, ns)
            .cmd(Command::RefreshQualification {
                pack,
                generation: g,
            })
            .expect("refresh qualification")
    }

    /// Registers a mandatory Namespace policy: every `kv.expect` verification must pass and
    /// `kv.size` must not deny.
    pub fn kv_gate(&self, root: &Identity, ns: NamespaceId) -> Digest {
        let doc: PolicyDocument = serde_json::from_value(serde_json::json!({
            "name": "org.openaevc.testkit.kv-gate",
            "rules": [
                {"id": "expect-pass", "expr": {"verifier": {"kind": "kv.expect", "status": "PASS"}}},
                {"id": "size-not-denied", "expr": {"not": {"evaluator": {"kind": "kv.size", "verdict": "DENY"}}}}
            ]
        }))
        .expect("policy");
        self.client(root, ns)
            .cmd(Command::RegisterPolicy {
                document: doc,
                mandatory: true,
            })
            .expect("register policy")
            .result
            .digest
            .expect("digest")
    }
}

impl Harness {
    /// SQLite-backed harness that also returns the store (for fault injection) — the caller
    /// keeps the runtime's clock at 2025-01-01.
    pub fn sqlite_with_store(root: &Path, ext: Option<&Extensions>) -> (Self, Arc<SqliteStore>) {
        let store =
            Arc::new(SqliteStore::open(root, SqliteOptions::create()).expect("open sqlite store"));
        let dirs = ext
            .map(|e| vec![e.dir.path().to_path_buf()])
            .unwrap_or_default();
        let h = Self::build(store.clone(), FixedClock::new(EPOCH_2025), move |c| {
            c.extension_dirs = dirs
        });
        (h, store)
    }

    /// Promotes a qualified pack; returns the PromotedPack digest.
    pub fn promote(
        &self,
        who: &Identity,
        ns: NamespaceId,
        pack: PackId,
    ) -> Result<Digest, ProtocolError> {
        let g = self.pack(who, ns, pack).generation;
        self.client(who, ns)
            .cmd(Command::PromoteChangePack {
                pack,
                generation: g,
            })
            .map(|r| r.result.digest.expect("promoted digest"))
    }

    /// Runs effects, seals, qualifies (no gates beyond Namespace policy) and promotes a new
    /// ChangePack; returns `(pack, promoted digest)`.
    pub fn promote_new(
        &self,
        who: &Identity,
        ns: NamespaceId,
        effects: Vec<EffectProposal>,
    ) -> (PackId, Digest) {
        self.promote_spec(who, ns, PackSpec::default(), effects)
    }

    pub fn promote_spec(
        &self,
        who: &Identity,
        ns: NamespaceId,
        spec: PackSpec,
        effects: Vec<EffectProposal>,
    ) -> (PackId, Digest) {
        let pack: PackId = receipt_id(
            &self
                .client(who, ns)
                .cmd(Command::CreateChangePack { spec })
                .expect("create pack"),
        );
        self.finish_pack(who, ns, pack, effects)
    }

    /// Executes `effects` in `pack` (if any), seals, qualifies and promotes it.
    pub fn finish_pack(
        &self,
        who: &Identity,
        ns: NamespaceId,
        pack: PackId,
        effects: Vec<EffectProposal>,
    ) -> (PackId, Digest) {
        if !effects.is_empty() {
            self.run(who, ns, pack, &mut ScriptedHarness { effects });
        }
        self.seal(who, ns, pack);
        let q = self.qualify(who, ns, pack);
        assert_eq!(
            q.result.state.as_deref(),
            Some("QUALIFIED"),
            "pack did not qualify"
        );
        (pack, self.promote(who, ns, pack).expect("promote"))
    }
}

impl Harness {
    pub fn create_baseline(
        &self,
        who: &Identity,
        ns: NamespaceId,
        members: Vec<Digest>,
        edges: Vec<CompositionEdge>,
    ) -> Result<CommandReceipt, ProtocolError> {
        self.client(who, ns).cmd(Command::CreateBaseline {
            members,
            edges,
            policies: vec![],
            metadata: BTreeMap::new(),
        })
    }
}
