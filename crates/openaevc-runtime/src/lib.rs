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
mod metrics;
mod queries;
mod records;
mod recovery;
mod tx;
mod view;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use openaevc_authority::{authorize, resolve_caller, Authorization, Request};
use openaevc_core::request::SignedRequest;
use openaevc_core::{Clock, IdGenerator, IdGeneratorExt, ImmutableObject};
use openaevc_crypto::Signer;
use openaevc_protocol::{
    err, Command, CommandEnvelope, CommandReceipt, CommandResult, Digest, Envelope, ErrorCode,
    Event, EventFilter, ImplementationInfo, Namespace, NamespaceId, ObjectKind, Principal,
    PrincipalId, PrincipalKind, ProtocolError, PublicKey, Query, QueryEnvelope, Receipt, RequestId,
    ResourceRef, RuntimeInfo, RuntimeInstanceId, SUPPORTED_CONTRACT, SUPPORTED_PROTOCOL,
};
use openaevc_store::{RequestRecord, Store};
use serde::Serialize;
use serde_json::Value;

use crate::tx::Tx;
use crate::view::NsView;

pub use metrics::Metrics;

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
    pub notify: tokio::sync::watch::Sender<u64>,
    pub metrics: Metrics,
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

/// Authenticated event subscription (see [`Runtime::subscribe`]).
#[derive(Debug, Clone)]
pub struct Subscription {
    filter: EventFilter,
    ctx: Ctx,
}

impl Subscription {
    /// Sequence of the last event examined.
    pub fn cursor(&self) -> openaevc_protocol::Sequence {
        self.filter.after
    }

    pub fn namespace(&self) -> NamespaceId {
        self.filter.namespace
    }

    /// Resume point, e.g. from an SSE `Last-Event-ID`.
    pub fn set_cursor(&mut self, after: openaevc_protocol::Sequence) {
        self.filter.after = after;
    }
}

pub struct Runtime {
    shared: Shared,
    lock: Mutex<()>,
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
            notify: tokio::sync::watch::channel(0).0,
            metrics: Metrics::default(),
        };
        let rt = Runtime {
            shared,
            lock: Mutex::new(()),
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
        self.shared.notify.subscribe()
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
    fn authenticate<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        req: &SignedRequest<T>,
    ) -> Result<(NamespaceId, Ctx)> {
        let env = &req.envelope;
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
        req.verify(&key)?;
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
        self.execute_inner(SignedRequest::from_envelope(env)?, None)
    }

    /// Executes a signed command envelope received as a JSON-model value (transports). The
    /// signature is verified over the canonical encoding of exactly this value.
    pub fn execute_value(&self, v: Value) -> Result<CommandReceipt> {
        self.execute_inner(SignedRequest::from_value(v)?, None)
    }

    /// Executes a `PutImmutableObject` whose signed envelope carries an empty `bytes` field and
    /// whose object bytes travel separately (e.g. an HTTP `PUT /v1/objects/{digest}` body). The
    /// signature covers the digest; the bytes are verified against it.
    pub fn execute_with_payload(
        &self,
        env: CommandEnvelope,
        payload: Vec<u8>,
    ) -> Result<CommandReceipt> {
        self.execute_with_payload_value(openaevc_canonical::to_value(&env)?, payload)
    }

    /// [`Runtime::execute_with_payload`] for an envelope received as a value.
    pub fn execute_with_payload_value(&self, v: Value, payload: Vec<u8>) -> Result<CommandReceipt> {
        let req = SignedRequest::<Command>::from_value(v)?;
        match &req.envelope.body {
            Command::PutImmutableObject { bytes, .. } if bytes.is_empty() => self.execute_inner(req, Some(payload)),
            _ => Err(err::invalid("a separate payload is only accepted for PutImmutableObject with empty inline bytes")),
        }
    }

    /// Runtime counters.
    pub fn metrics(&self) -> &Metrics {
        &self.shared.metrics
    }

    fn execute_inner(
        &self,
        req: SignedRequest<Command>,
        payload: Option<Vec<u8>>,
    ) -> Result<CommandReceipt> {
        let name = req.envelope.body.name();
        let r = self.execute_locked(req, payload);
        self.shared
            .metrics
            .command(name, r.as_ref().map_or_else(|e| e.code.as_str(), |_| "ok"));
        r
    }

    fn execute_locked(
        &self,
        req: SignedRequest<Command>,
        payload: Option<Vec<u8>>,
    ) -> Result<CommandReceipt> {
        let _g = self.guard()?;
        Self::check_version(&req.envelope)?;
        let digest = req.digest();
        if let Command::CreateNamespace { .. } = req.envelope.body {
            return self.execute_admin(req, digest);
        }
        let (ns, ctx) = self.authenticate(&req)?;
        let env = &req.envelope;
        if let Some(r) = self.check_replay(env, digest)? {
            return Ok(r);
        }
        let now = recovery::expire_leases(&self.shared, ns)?;
        let mut tx = Tx::new(&self.shared, ns, ctx.principal)?;
        tx.now = now;
        tx.request_id = Some(env.request_id);
        tx.actor = Some(ctx.principal);
        let name = env.body.name();
        let body = match (env.body.clone(), payload) {
            (Command::PutImmutableObject { digest, .. }, Some(bytes)) => {
                Command::PutImmutableObject { digest, bytes }
            }
            (body, _) => body,
        };
        match handlers::dispatch(&mut tx, &ctx, body) {
            Ok(result) => self.commit(tx, env, name, digest, result),
            Err(e) => {
                if is_authority_error(e.code) && self.shared.config.audit_denials {
                    self.record_denial(ns, &ctx, name, &e)?;
                }
                Err(e)
            }
        }
    }

    fn execute_admin(&self, req: SignedRequest<Command>, digest: Digest) -> Result<CommandReceipt> {
        let env = &req.envelope;
        let admin = self
            .shared
            .config
            .admins
            .iter()
            .find(|a| a.id == env.caller)
            .ok_or_else(|| {
                err::unauthorized("only runtime administrators may create namespaces")
            })?;
        req.verify(&admin.public_key)?;
        if env.act_as.is_some() {
            return Err(err::invalid("CreateNamespace cannot use act_as"));
        }
        openaevc_authority::check_freshness(
            self.shared.clock.now(),
            env.issued_at,
            env.expires_at,
            self.shared.config.replay_window_ms,
        )?;
        if let Some(r) = self.check_replay(env, digest)? {
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
        self.commit(tx, env, "CreateNamespace", digest, result)
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
        self.shared.notify.send_modify(|v| *v += 1);
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
        self.shared.metrics.denial();
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
        self.shared.notify.send_modify(|v| *v += 1);
        Ok(())
    }

    /// Executes a signed query envelope. Queries never mutate state.
    pub fn query(&self, env: QueryEnvelope) -> Result<Value> {
        self.query_signed(SignedRequest::from_envelope(env)?)
    }

    /// Executes a signed query envelope received as a JSON-model value (transports).
    pub fn query_value(&self, v: Value) -> Result<Value> {
        self.query_signed(SignedRequest::from_value(v)?)
    }

    fn query_signed(&self, req: SignedRequest<Query>) -> Result<Value> {
        let _g = self.guard()?;
        self.shared.metrics.query();
        Self::check_version(&req.envelope)?;
        let (ns, ctx) = self.authenticate(&req)?;
        let tx = Tx::new(&self.shared, ns, ctx.principal)?;
        let r = queries::dispatch(&tx, &ctx, req.envelope.body);
        if let Err(e) = &r {
            if is_authority_error(e.code) && self.shared.config.audit_denials {
                drop(tx);
                self.record_denial(ns, &ctx, "query", e)?;
            }
        }
        r
    }

    /// Opens a long-lived event subscription. The envelope must be a signed `ListEvents` query;
    /// it is authenticated once, and `namespace.read` is re-authorized on every poll so
    /// revocation ends the subscription.
    pub fn subscribe(&self, env: QueryEnvelope, subjects: Vec<String>) -> Result<Subscription> {
        self.subscribe_value(openaevc_canonical::to_value(&env)?, subjects)
    }

    /// [`Runtime::subscribe`] for an envelope received as a value.
    pub fn subscribe_value(&self, v: Value, subjects: Vec<String>) -> Result<Subscription> {
        let req = SignedRequest::<Query>::from_value(v)?;
        let _g = self.guard()?;
        Self::check_version(&req.envelope)?;
        let Query::ListEvents { after, kinds, .. } = req.envelope.body.clone() else {
            return Err(err::invalid(
                "subscriptions are opened with a ListEvents query envelope",
            ));
        };
        let (ns, ctx) = self.authenticate(&req)?;
        let tx = Tx::new(&self.shared, ns, ctx.principal)?;
        authz(&tx, &ctx, "namespace.read", None)?;
        Ok(Subscription {
            filter: EventFilter {
                namespace: ns,
                after,
                kinds,
                subjects,
            },
            ctx,
        })
    }

    /// Returns up to `limit` new matching events and advances the subscription cursor.
    pub fn poll(&self, sub: &mut Subscription, limit: usize) -> Result<Vec<Event>> {
        let _g = self.guard()?;
        let ns = sub.filter.namespace;
        let tx = Tx::new(&self.shared, ns, sub.ctx.principal)?;
        authz(&tx, &sub.ctx, "namespace.read", None)?;
        let mut out = Vec::new();
        loop {
            let page = self
                .shared
                .store
                .read_events(&ns, sub.filter.after, limit.max(1))?;
            let Some(last) = page.last().map(|e| e.sequence) else {
                break;
            };
            for e in page {
                if out.len() == limit {
                    return Ok(out);
                }
                let seq = e.sequence;
                if sub.filter.matches(&e) {
                    out.push(e);
                }
                sub.filter.after = seq;
            }
            if sub.filter.after < last {
                break;
            }
        }
        Ok(out)
    }

    /// Recovery/maintenance tick: expires execution leases in every Namespace. The daemon calls
    /// this periodically; commands also expire leases of their Namespace lazily.
    pub fn tick(&self) -> Result<()> {
        let _g = self.guard()?;
        for ns in self.shared.store.namespaces()? {
            recovery::expire_leases(&self.shared, ns)?;
        }
        self.shared.notify.send_modify(|v| *v += 1);
        Ok(())
    }

    /// Loads a Namespace-visible object after authorizing `object.read` for the envelope's
    /// caller (used by transport object endpoints).
    pub fn read_object(&self, env: QueryEnvelope, digest: &Digest) -> Result<ImmutableObject> {
        self.read_object_value(openaevc_canonical::to_value(&env)?, digest)
    }

    /// [`Runtime::read_object`] for an envelope received as a value.
    pub fn read_object_value(&self, v: Value, digest: &Digest) -> Result<ImmutableObject> {
        let req = SignedRequest::<Query>::from_value(v)?;
        let _g = self.guard()?;
        Self::check_version(&req.envelope)?;
        let (ns, ctx) = self.authenticate(&req)?;
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
