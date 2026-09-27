//! OpenAEVC reference runtime: the sole authoritative mutation boundary.
//!
//! Every command and query — embedded or via the daemon — enters through [`Runtime::execute`]
//! or [`Runtime::query`], which run one admission path: protocol version, envelope signature
//! against the caller's registered key, freshness window, replay/idempotency, then per-command
//! authorization. A command's state changes, immutable objects, journal events, receipt and
//! replay record are committed as one atomic store batch.
//!
//! ponytail: one global lock serializes commands and queries; per-namespace locks if throughput
//! matters.
#![forbid(unsafe_code)]

mod ext;
mod handlers;
mod queries;
mod records;
mod recovery;
mod tx;
mod view;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use openaevc_authority::{authorize, resolve_caller, Authorization, Request};
use openaevc_core::request::{envelope_digest, verify_request};
use openaevc_core::{Clock, IdGenerator, IdGeneratorExt, ImmutableObject};
use openaevc_crypto::Signer;
use openaevc_protocol::{
    err, Command, CommandEnvelope, CommandReceipt, CommandResult, Digest, Envelope, ErrorCode,
    ImplementationInfo, JournalCheckpoint, Namespace, NamespaceId, ObjectKind, Principal,
    PrincipalId, PrincipalKind, ProtocolError, PublicKey, QueryEnvelope, Receipt, RequestId,
    ResourceRef, RuntimeInfo, RuntimeInstanceId, SUPPORTED_CONTRACT, SUPPORTED_PROTOCOL,
};
use openaevc_store::{RequestRecord, Store};
use serde::Serialize;
use serde_json::Value;

use crate::tx::Tx;
use crate::view::NsView;

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// A runtime administrator: may create Namespaces. Configured out of band.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admin {
    pub id: PrincipalId,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub admins: Vec<Admin>,
    /// Accepted clock skew / replay window for request envelopes.
    pub replay_window_ms: u64,
    /// A signed journal checkpoint is written every this many events per Namespace.
    pub checkpoint_interval: u64,
    /// Record `authorization.denied` events for authenticated denials.
    pub audit_denials: bool,
    /// Execution lease duration.
    pub lease_ms: u64,
    pub heartbeat_interval_ms: u64,
    /// Directories extension entrypoints may be registered from.
    pub extension_dirs: Vec<PathBuf>,
    pub extension_deadline_ms: u64,
    pub max_extension_frame: usize,
    /// Upper bound for paginated query results.
    pub max_page: u32,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            admins: vec![],
            replay_window_ms: 300_000,
            checkpoint_interval: 1000,
            audit_denials: true,
            lease_ms: 30_000,
            heartbeat_interval_ms: 10_000,
            extension_dirs: vec![],
            extension_deadline_ms: 10_000,
            max_extension_frame: 4 * 1024 * 1024,
            max_page: 1000,
        }
    }
}

/// External dependencies. Deterministic implementations make the runtime reproducible in tests.
pub struct RuntimeDeps {
    pub store: Arc<dyn Store>,
    pub clock: Arc<dyn Clock>,
    pub ids: Arc<dyn IdGenerator>,
    /// Runtime key: signs receipts and journal checkpoints.
    pub signer: Arc<dyn Signer>,
    /// Stable principal ID recorded as creator of runtime-signed objects.
    pub runtime_principal: PrincipalId,
}

impl std::fmt::Debug for RuntimeDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeDeps")
            .field("runtime_principal", &self.runtime_principal)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Shared {
    pub store: Arc<dyn Store>,
    pub clock: Arc<dyn Clock>,
    pub ids: Arc<dyn IdGenerator>,
    pub signer: Arc<dyn Signer>,
    pub runtime_principal: PrincipalId,
    pub instance: RuntimeInstanceId,
    pub config: RuntimeConfig,
}

/// Authenticated request context handed to handlers.
#[derive(Debug, Clone)]
pub(crate) struct Ctx {
    /// Effective principal (the ACTOR when `act_as` was used).
    pub principal: PrincipalId,
    /// Authenticated key principal that signed the request.
    pub caller: PrincipalId,
    pub roots: Vec<PrincipalId>,
    pub request_id: RequestId,
}

pub struct Runtime {
    shared: Shared,
    lock: Mutex<()>,
    notify: tokio::sync::watch::Sender<u64>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("instance", &self.shared.instance)
            .finish_non_exhaustive()
    }
}

fn is_authority_error(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Forbidden | ErrorCode::CapabilityExpired | ErrorCode::CapabilityRevoked
    )
}

impl Runtime {
    /// Opens the runtime over a store and runs startup recovery (spec/recovery.md). Fails closed
    /// if authoritative state integrity cannot be established.
    pub fn open(deps: RuntimeDeps, config: RuntimeConfig) -> Result<Self> {
        let shared = Shared {
            instance: deps.ids.next(),
            store: deps.store,
            clock: deps.clock,
            ids: deps.ids,
            signer: deps.signer,
            runtime_principal: deps.runtime_principal,
            config,
        };
        let (notify, _) = tokio::sync::watch::channel(0);
        let rt = Runtime {
            shared,
            lock: Mutex::new(()),
            notify,
        };
        {
            let _g = rt.guard()?;
            recovery::startup(&rt.shared)?;
        }
        Ok(rt)
    }

    fn guard(&self) -> Result<MutexGuard<'_, ()>> {
        self.lock
            .lock()
            .map_err(|_| err::internal("runtime lock poisoned"))
    }

    pub fn info(&self) -> RuntimeInfo {
        RuntimeInfo {
            protocol: SUPPORTED_PROTOCOL,
            contract: SUPPORTED_CONTRACT,
            implementation: ImplementationInfo {
                name: "openaevc-runtime".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            runtime_instance: self.shared.instance,
            runtime_key: self.shared.signer.public_key(),
            replay_window_ms: self.shared.config.replay_window_ms,
        }
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.shared.config
    }

    /// Receives a new value after every commit (event-stream wake-ups).
    pub fn subscribe_notifications(&self) -> tokio::sync::watch::Receiver<u64> {
        self.notify.subscribe()
    }

    fn check_version<T>(env: &Envelope<T>) -> Result<()> {
        if !SUPPORTED_PROTOCOL.contains(env.protocol_version) {
            return Err(ProtocolError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!(
                    "protocol {} is not supported (supported {}..={})",
                    env.protocol_version, SUPPORTED_PROTOCOL.min, SUPPORTED_PROTOCOL.max
                ),
            ));
        }
        Ok(())
    }

    /// Authenticates a namespaced envelope: namespace exists, caller key signature, actor link,
    /// freshness window.
    fn authenticate<T: Serialize>(&self, env: &Envelope<T>) -> Result<(NamespaceId, Ctx)> {
        let ns = env
            .namespace
            .ok_or_else(|| err::invalid("request envelope has no namespace"))?;
        let probe = Tx::new(&self.shared, ns, self.shared.runtime_principal)?;
        let namespace: Namespace = probe
            .peek(records::NAMESPACE, &ns.to_string())?
            .ok_or_else(|| err::not_found(format!("namespace {ns} not found")))?;
        let view = NsView {
            tx: &probe,
            roots: namespace.root_principals.clone(),
        };
        let caller = view_principal(&view, env.caller)?;
        let key = caller
            .public_key
            .ok_or_else(|| err::unauthorized("caller has no key"))?;
        verify_request(env, &key)?;
        let effective = resolve_caller(&view, env.caller, env.act_as)?;
        openaevc_authority::check_freshness(
            self.shared.clock.now(),
            env.issued_at,
            env.expires_at,
            self.shared.config.replay_window_ms,
        )?;
        Ok((
            ns,
            Ctx {
                principal: effective.id,
                caller: env.caller,
                roots: namespace.root_principals,
                request_id: env.request_id,
            },
        ))
    }

    /// Replay protection and idempotency. Returns the original receipt for an identical retry.
    fn check_replay(
        &self,
        env: &CommandEnvelope,
        digest: Digest,
    ) -> Result<Option<CommandReceipt>> {
        let store = &self.shared.store;
        if let Some(rec) = store.get_request(&env.caller, &env.request_id)? {
            if rec.envelope_digest != digest {
                return Err(ProtocolError::new(
                    ErrorCode::ReplayDetected,
                    "request_id reused with a different request",
                ));
            }
            let receipt_digest = rec
                .receipt
                .ok_or_else(|| err::internal("request record without receipt"))?;
            let obj = store
                .get_object(&receipt_digest)?
                .ok_or_else(|| err::integrity("receipt object missing"))?;
            let r: Receipt = obj.body()?;
            return Ok(Some(CommandReceipt {
                receipt: receipt_digest,
                request_id: r.request_id,
                result: r.result,
                first_seq: r.first_seq,
                last_seq: r.last_seq,
            }));
        }
        if store.nonce_used(&env.caller, &env.nonce)? {
            return Err(ProtocolError::new(
                ErrorCode::ReplayDetected,
                "nonce already used",
            ));
        }
        Ok(None)
    }

    /// Executes a signed command envelope.
    pub fn execute(&self, env: CommandEnvelope) -> Result<CommandReceipt> {
        let _g = self.guard()?;
        Self::check_version(&env)?;
        let digest = envelope_digest(&env)?;
        if let Command::CreateNamespace { .. } = env.body {
            return self.execute_admin(env, digest);
        }
        let (ns, ctx) = self.authenticate(&env)?;
        if let Some(r) = self.check_replay(&env, digest)? {
            return Ok(r);
        }
        recovery::expire_leases(&self.shared, ns)?;
        let mut tx = Tx::new(&self.shared, ns, ctx.principal)?;
        tx.request_id = Some(env.request_id);
        tx.actor = Some(ctx.principal);
        let name = env.body.name();
        match handlers::dispatch(&mut tx, &ctx, env.body.clone()) {
            Ok(result) => self.commit(tx, &env, name, digest, result),
            Err(e) => {
                if is_authority_error(e.code) && self.shared.config.audit_denials {
                    self.record_denial(ns, &ctx, name, &e)?;
                }
                Err(e)
            }
        }
    }

    fn execute_admin(&self, env: CommandEnvelope, digest: Digest) -> Result<CommandReceipt> {
        let admin = self
            .shared
            .config
            .admins
            .iter()
            .find(|a| a.id == env.caller)
            .ok_or_else(|| {
                err::unauthorized("only runtime administrators may create namespaces")
            })?;
        verify_request(&env, &admin.public_key)?;
        if env.act_as.is_some() {
            return Err(err::invalid("CreateNamespace cannot use act_as"));
        }
        openaevc_authority::check_freshness(
            self.shared.clock.now(),
            env.issued_at,
            env.expires_at,
            self.shared.config.replay_window_ms,
        )?;
        if let Some(r) = self.check_replay(&env, digest)? {
            return Ok(r);
        }
        let ns: NamespaceId = self.shared.ids.next();
        let mut tx = Tx::new(&self.shared, ns, admin.id)?;
        tx.request_id = Some(env.request_id);
        tx.actor = Some(admin.id);
        let ctx = Ctx {
            principal: admin.id,
            caller: admin.id,
            roots: vec![],
            request_id: env.request_id,
        };
        let result = handlers::dispatch(&mut tx, &ctx, env.body.clone())?;
        self.commit(tx, &env, "CreateNamespace", digest, result)
    }

    fn commit(
        &self,
        mut tx: Tx<'_>,
        env: &CommandEnvelope,
        name: &str,
        digest: Digest,
        result: CommandResult,
    ) -> Result<CommandReceipt> {
        if tx.event_count() == 0 {
            return Err(err::internal(format!("{name} produced no audit event")));
        }
        let (first_seq, last_seq) = (tx.first_seq, tx.last_seq());
        let receipt = Receipt {
            request_id: env.request_id,
            command: name.to_owned(),
            caller: env.caller,
            envelope_digest: digest,
            result: result.clone(),
            first_seq,
            last_seq,
            runtime_instance: self.shared.instance,
            completed_at: tx.now,
        };
        let receipt_obj = tx.object(
            ObjectKind::Receipt,
            Some(env.request_id.to_string()),
            &receipt,
            true,
        )?;
        let events = tx.finish_events()?;
        let interval = self.shared.config.checkpoint_interval.max(1);
        let checkpoint_at = (first_seq..=last_seq).rev().find(|s| s % interval == 0);
        if let Some(seq) = checkpoint_at {
            let hash = events
                .iter()
                .find(|e| e.sequence == seq)
                .map(|e| e.hash)
                .ok_or_else(|| err::internal("checkpoint event"))?;
            let cp = JournalCheckpoint {
                sequence: seq,
                event_hash: hash,
                runtime_key: self.shared.signer.public_key(),
                runtime_instance: self.shared.instance,
                created_at: tx.now,
            };
            let obj = tx.object(ObjectKind::JournalCheckpoint, None, &cp, true)?;
            tx.put(
                records::CHECKPOINT,
                &tx.ns.to_string(),
                &records::CheckpointRecord {
                    digest: obj.digest(),
                    sequence: seq,
                },
            )?;
        }
        let mut batch = tx.into_batch(events)?;
        batch.requests.push(RequestRecord {
            principal: env.caller,
            request_id: env.request_id,
            nonce: env.nonce.clone(),
            envelope_digest: digest,
            receipt: Some(receipt_obj.digest()),
            issued_at: env.issued_at,
        });
        self.shared.store.commit(batch)?;
        self.notify.send_modify(|v| *v += 1);
        Ok(CommandReceipt {
            receipt: receipt_obj.digest(),
            request_id: env.request_id,
            result,
            first_seq,
            last_seq,
        })
    }

    fn record_denial(
        &self,
        ns: NamespaceId,
        ctx: &Ctx,
        command: &str,
        e: &ProtocolError,
    ) -> Result<()> {
        let mut tx = Tx::new(&self.shared, ns, ctx.principal)?;
        tx.request_id = Some(ctx.request_id);
        tx.actor = Some(ctx.principal);
        tx.emit(
            "authorization.denied",
            serde_json::json!({"command": command, "action": e.missing_action, "code": e.code, "caller": ctx.caller}),
            vec![ctx.principal.to_string()],
        );
        let events = tx.finish_events()?;
        let batch = tx.into_batch(events)?;
        self.shared.store.commit(batch)?;
        self.notify.send_modify(|v| *v += 1);
        Ok(())
    }

    /// Executes a signed query envelope. Queries never mutate state.
    pub fn query(&self, env: QueryEnvelope) -> Result<Value> {
        let _g = self.guard()?;
        Self::check_version(&env)?;
        let (ns, ctx) = self.authenticate(&env)?;
        let tx = Tx::new(&self.shared, ns, ctx.principal)?;
        let r = queries::dispatch(&tx, &ctx, env.body);
        if let Err(e) = &r {
            if is_authority_error(e.code) && self.shared.config.audit_denials {
                drop(tx);
                self.record_denial(ns, &ctx, "query", e)?;
            }
        }
        r
    }

    /// Recovery/maintenance tick: expires execution leases in every Namespace. The daemon calls
    /// this periodically; commands also expire leases of their Namespace lazily.
    pub fn tick(&self) -> Result<()> {
        let _g = self.guard()?;
        for ns in self.shared.store.namespaces()? {
            recovery::expire_leases(&self.shared, ns)?;
        }
        self.notify.send_modify(|v| *v += 1);
        Ok(())
    }

    /// Loads a Namespace-visible object after authorizing `object.read` for the envelope's
    /// caller (used by transport object endpoints).
    pub fn read_object(&self, env: QueryEnvelope, digest: &Digest) -> Result<ImmutableObject> {
        let _g = self.guard()?;
        Self::check_version(&env)?;
        let (ns, ctx) = self.authenticate(&env)?;
        let tx = Tx::new(&self.shared, ns, ctx.principal)?;
        authz(&tx, &ctx, "object.read", None)?;
        tx.load_object(digest)?
            .ok_or_else(|| err::not_found(format!("object {digest} not found")).with_object(digest))
    }
}

fn view_principal(view: &NsView<'_, '_>, id: PrincipalId) -> Result<Principal> {
    use openaevc_authority::AuthorityView;
    let p = view
        .principal(&id)
        .ok_or_else(|| err::unauthorized(format!("unknown principal {id}")))?;
    if p.kind == PrincipalKind::Actor {
        return Err(err::unauthorized("actors cannot authenticate directly"));
    }
    Ok(p)
}

/// Authorizes the request's effective principal for `action` (default deny).
pub(crate) fn authz(
    tx: &Tx<'_>,
    ctx: &Ctx,
    action: &str,
    resource: Option<&ResourceRef>,
) -> Result<Authorization> {
    let view = NsView {
        tx,
        roots: ctx.roots.clone(),
    };
    authorize(
        &view,
        tx.now,
        &Request {
            principal: ctx.principal,
            action,
            resource,
        },
    )
}
