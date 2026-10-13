//! OpenAEVC Rust SDK: one client API over the embedded runtime ([`EmbeddedClient`]) and the
//! `openaevcd` daemon ([`RemoteClient`]).
//!
//! Both clients sign every request with the session's key and submit the identical envelope; the
//! embedded client has no privileged path into the runtime (AEVC-INV-029). This crate is the
//! supported consumer boundary; lower crates are implementation crates.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use openaevc::core::request::sign_request;
use openaevc::core::{Clock, IdGenerator, IdGeneratorExt, ImmutableObject, SystemClock, UuidV7Ids};
use openaevc::crypto::Signer;
use openaevc::protocol::*;
use openaevc::runtime::{Runtime, Subscription};
use openaevc::transport::client::{Endpoint, HttpClient};
use serde::Serialize;
use serde_json::Value;

pub use openaevc::transport::client::Endpoint as RemoteEndpoint;

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Identity and signing context for requests.
#[derive(Clone)]
pub struct Session {
    signer: Arc<dyn Signer>,
    principal: PrincipalId,
    namespace: Option<NamespaceId>,
    act_as: Option<PrincipalId>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("principal", &self.principal)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn new<S: Signer + 'static>(
        signer: Arc<S>,
        principal: PrincipalId,
        namespace: Option<NamespaceId>,
    ) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        Session {
            signer,
            principal,
            namespace,
            act_as: None,
            ids: Arc::new(UuidV7Ids::new(clock.clone())),
            clock,
        }
    }

    /// Act as an ACTOR principal linked to this session's key principal.
    pub fn act_as(mut self, actor: PrincipalId) -> Self {
        self.act_as = Some(actor);
        self
    }

    pub fn with_namespace(mut self, ns: NamespaceId) -> Self {
        self.namespace = Some(ns);
        self
    }

    /// Use a specific clock for `issued_at` (tests, simulations).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.ids = Arc::new(UuidV7Ids::new(clock.clone()));
        self.clock = clock;
        self
    }

    pub fn principal(&self) -> PrincipalId {
        self.principal
    }

    pub fn namespace(&self) -> Option<NamespaceId> {
        self.namespace
    }

    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }

    /// Builds and signs an envelope for `body`.
    pub fn envelope<T: Serialize>(&self, body: T) -> Result<Envelope<T>> {
        let env = Envelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: self.ids.next(),
            namespace: self.namespace,
            caller: self.principal,
            act_as: self.act_as,
            nonce: b64::encode(&self.ids.next_bytes()),
            issued_at: self.clock.now(),
            expires_at: None,
            body,
            signature: None,
        };
        sign_request(env, self.signer.as_ref())
    }

    /// Signs a capability grant issued by this session's principal.
    pub fn sign_grant(&self, body: GrantBody) -> Result<SignedGrant> {
        openaevc::authority::sign_grant(body, self.signer.as_ref())
    }
}

/// Journal events delivered at least once, in sequence order.
pub struct EventStream {
    inner: StreamInner,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EventStream")
    }
}

enum StreamInner {
    Embedded {
        rt: Arc<Runtime>,
        sub: Option<Subscription>,
        notify: tokio::sync::watch::Receiver<u64>,
        buffer: VecDeque<Event>,
    },
    Remote(openaevc::transport::client::EventStream),
}

impl EventStream {
    /// Next event; `None` if the stream ended.
    pub async fn next(&mut self) -> Option<Result<Event>> {
        match &mut self.inner {
            StreamInner::Remote(s) => s.next().await,
            StreamInner::Embedded {
                rt,
                sub,
                notify,
                buffer,
            } => loop {
                if let Some(e) = buffer.pop_front() {
                    return Some(Ok(e));
                }
                let mut s = sub.take()?;
                let r2 = rt.clone();
                let (s, r) = match tokio::task::spawn_blocking(move || {
                    let r = r2.poll(&mut s, 100);
                    (s, r)
                })
                .await
                {
                    Ok(x) => x,
                    Err(_) => return None,
                };
                *sub = Some(s);
                match r {
                    Err(e) => {
                        *sub = None;
                        return Some(Err(e));
                    }
                    Ok(batch) if !batch.is_empty() => buffer.extend(batch),
                    Ok(_) => {
                        let _ =
                            tokio::time::timeout(Duration::from_secs(5), notify.changed()).await;
                    }
                }
            },
        }
    }
}

/// The generic client surface (spec/transport.md). Typed helpers are in [`TypedClient`].
pub trait OpenAevcClient: Send + Sync {
    fn session(&self) -> &Session;
    fn command(&self, command: Command) -> impl Future<Output = Result<CommandReceipt>> + Send;
    fn query(&self, query: Query) -> impl Future<Output = Result<Value>> + Send;
    fn subscribe(&self, filter: EventFilter) -> impl Future<Output = Result<EventStream>> + Send;
    /// Fetches and digest-verifies an immutable object.
    fn get_object(&self, digest: Digest) -> impl Future<Output = Result<ImmutableObject>> + Send;
}

/// In-process client over an embedded [`Runtime`].
#[derive(Clone, Debug)]
pub struct EmbeddedClient {
    rt: Arc<Runtime>,
    session: Session,
}

impl EmbeddedClient {
    pub fn new(rt: Arc<Runtime>, session: Session) -> Self {
        EmbeddedClient { rt, session }
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| err::internal(format!("runtime task failed: {e}")))?
}

fn events_query(filter: &EventFilter) -> Query {
    Query::ListEvents {
        after: filter.after,
        limit: None,
        kinds: filter.kinds.clone(),
    }
}

impl OpenAevcClient for EmbeddedClient {
    fn session(&self) -> &Session {
        &self.session
    }

    async fn command(&self, command: Command) -> Result<CommandReceipt> {
        let env = self.session.envelope(command)?;
        let rt = self.rt.clone();
        blocking(move || rt.execute(env)).await
    }

    async fn query(&self, query: Query) -> Result<Value> {
        let env = self.session.envelope(query)?;
        let rt = self.rt.clone();
        blocking(move || rt.query(env)).await
    }

    async fn subscribe(&self, filter: EventFilter) -> Result<EventStream> {
        let env = self.session.envelope(events_query(&filter))?;
        let rt = self.rt.clone();
        let subjects = filter.subjects.clone();
        let sub = blocking(move || rt.subscribe(env, subjects)).await?;
        Ok(EventStream {
            inner: StreamInner::Embedded {
                rt: self.rt.clone(),
                sub: Some(sub),
                notify: self.rt.subscribe_notifications(),
                buffer: VecDeque::new(),
            },
        })
    }

    async fn get_object(&self, digest: Digest) -> Result<ImmutableObject> {
        let env = self.session.envelope(Query::GetObject { digest })?;
        let rt = self.rt.clone();
        blocking(move || rt.read_object(env, &digest)).await
    }
}

/// Client for `openaevcd` over HTTP (TCP, TLS or Unix socket).
#[derive(Clone, Debug)]
pub struct RemoteClient {
    http: HttpClient,
    session: Session,
    version: ProtocolVersion,
}

impl RemoteClient {
    /// Client without a negotiation round trip (assumes this SDK's protocol version).
    pub fn new(endpoint: Endpoint, session: Session) -> Self {
        RemoteClient {
            http: HttpClient::new(endpoint),
            session,
            version: PROTOCOL_VERSION,
        }
    }

    /// Connects and negotiates the highest protocol version both sides support.
    pub async fn connect(endpoint: Endpoint, session: Session) -> Result<Self> {
        let http = HttpClient::new(endpoint);
        let info = http.info().await?;
        let version = SUPPORTED_PROTOCOL
            .negotiate(&info.protocol)
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::ProtocolVersionUnsupported,
                    format!(
                        "daemon supports {}..={}, SDK supports {}..={}",
                        info.protocol.min,
                        info.protocol.max,
                        SUPPORTED_PROTOCOL.min,
                        SUPPORTED_PROTOCOL.max
                    ),
                )
            })?;
        Ok(RemoteClient {
            http,
            session,
            version,
        })
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    /// Uses canonical CBOR bodies instead of JSON.
    pub fn cbor(mut self) -> Self {
        self.http = self.http.cbor();
        self
    }

    pub async fn info(&self) -> Result<RuntimeInfo> {
        self.http.info().await
    }

    /// Uploads object bytes (object exchange) outside the signed envelope.
    pub async fn put_object(&self, digest: Digest, bytes: Vec<u8>) -> Result<CommandReceipt> {
        let env = self.session.envelope(Command::PutImmutableObject {
            digest,
            bytes: vec![],
        })?;
        self.http.put_object(&env, bytes).await
    }
}

impl OpenAevcClient for RemoteClient {
    fn session(&self) -> &Session {
        &self.session
    }

    async fn command(&self, command: Command) -> Result<CommandReceipt> {
        self.http.command(&self.session.envelope(command)?).await
    }

    async fn query(&self, query: Query) -> Result<Value> {
        self.http.query(&self.session.envelope(query)?).await
    }

    async fn subscribe(&self, filter: EventFilter) -> Result<EventStream> {
        let env = self.session.envelope(events_query(&filter))?;
        let s = self.http.events(&env, &filter.subjects, None).await?;
        Ok(EventStream {
            inner: StreamInner::Remote(s),
        })
    }

    async fn get_object(&self, digest: Digest) -> Result<ImmutableObject> {
        let env = self.session.envelope(Query::GetObject { digest })?;
        let bytes = self.http.get_object(&env, digest).await?;
        ImmutableObject::from_bytes(&bytes, Some(digest))
    }
}

fn id_of<T: std::str::FromStr>(r: &CommandReceipt) -> Result<T> {
    r.result
        .id
        .as_deref()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| err::internal("receipt has no id"))
}

fn digest_of(r: &CommandReceipt) -> Result<Digest> {
    r.result
        .digest
        .ok_or_else(|| err::internal("receipt has no digest"))
}

fn decode<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|e| err::internal(format!("unexpected query result: {e}")))
}

/// Typed convenience methods over the generic command/query primitives.
pub trait TypedClient: OpenAevcClient {
    /// Administrator only: returns the Namespace and its root principal IDs.
    fn create_namespace(
        &self,
        roots: Vec<NewPrincipal>,
    ) -> impl Future<Output = Result<(NamespaceId, Vec<PrincipalId>)>> + Send {
        async move {
            let r = self
                .command(Command::CreateNamespace {
                    root_principals: roots,
                    metadata: Metadata::new(),
                })
                .await?;
            let ids = r
                .result
                .ids
                .iter()
                .map(|s| s.parse().map_err(|_| err::internal("bad principal id")))
                .collect::<Result<_>>()?;
            Ok((id_of(&r)?, ids))
        }
    }

    fn register_principal(
        &self,
        principal: NewPrincipal,
    ) -> impl Future<Output = Result<PrincipalId>> + Send {
        async move {
            id_of(
                &self
                    .command(Command::RegisterPrincipal { principal })
                    .await?,
            )
        }
    }

    /// Signs `body` with the session key and issues it.
    fn issue_grant(&self, body: GrantBody) -> impl Future<Output = Result<Digest>> + Send {
        async move {
            let grant = self.session().sign_grant(body)?;
            digest_of(
                &self
                    .command(Command::IssueCapabilityGrant { grant })
                    .await?,
            )
        }
    }

    fn create_change_pack(&self, spec: PackSpec) -> impl Future<Output = Result<PackId>> + Send {
        async move { id_of(&self.command(Command::CreateChangePack { spec }).await?) }
    }

    fn get_change_pack(&self, pack: PackId) -> impl Future<Output = Result<ChangePack>> + Send {
        async move {
            decode(
                self.query(Query::GetChangePack {
                    pack,
                    generation: None,
                })
                .await?,
            )
        }
    }

    fn add_work_unit(
        &self,
        pack: PackId,
        expected_generation: u64,
        kind: &str,
    ) -> impl Future<Output = Result<WorkUnitId>> + Send {
        let kind = kind.to_owned();
        async move {
            id_of(
                &self
                    .command(Command::AddWorkUnit {
                        pack,
                        expected_generation,
                        kind,
                        spec: None,
                        depends_on: vec![],
                    })
                    .await?,
            )
        }
    }

    fn start_execution(
        &self,
        request: ExecutionRequest,
    ) -> impl Future<Output = Result<(ExecutionId, Lease)>> + Send {
        async move {
            let r = self.command(Command::StartExecution { request }).await?;
            Ok((
                id_of(&r)?,
                r.result
                    .lease
                    .clone()
                    .ok_or_else(|| err::internal("no lease"))?,
            ))
        }
    }

    fn heartbeat(&self, lease: &Lease) -> impl Future<Output = Result<CommandReceipt>> + Send {
        let (execution, id, generation) = (lease.execution, lease.id, lease.generation);
        async move {
            self.command(Command::HeartbeatExecution {
                execution,
                lease: id,
                generation,
            })
            .await
        }
    }

    /// `Ok(true)` if applied, `Ok(false)` if the extension rejected the proposal.
    fn submit_effect(
        &self,
        lease: &Lease,
        effect: EffectProposal,
    ) -> impl Future<Output = Result<bool>> + Send {
        let (execution, id) = (lease.execution, lease.id);
        async move {
            Ok(self
                .command(Command::SubmitEffectProposal {
                    execution,
                    lease: id,
                    effect,
                })
                .await?
                .result
                .state
                .as_deref()
                == Some("APPLIED"))
        }
    }

    fn complete_execution(
        &self,
        lease: &Lease,
    ) -> impl Future<Output = Result<CommandReceipt>> + Send {
        let (execution, id) = (lease.execution, lease.id);
        async move {
            self.command(Command::CompleteExecution {
                execution,
                lease: id,
            })
            .await
        }
    }

    /// Returns the frozen candidate digest.
    fn seal(
        &self,
        pack: PackId,
        expected_generation: u64,
    ) -> impl Future<Output = Result<Digest>> + Send {
        async move {
            digest_of(
                &self
                    .command(Command::SealChangePack {
                        pack,
                        expected_generation,
                    })
                    .await?,
            )
        }
    }

    fn run_verification(
        &self,
        pack: PackId,
        generation: u64,
        verifier: &str,
        config: Value,
    ) -> impl Future<Output = Result<CommandReceipt>> + Send {
        let verifier = verifier.to_owned();
        async move {
            self.command(Command::RunVerification {
                pack,
                generation,
                verifier,
                config: Some(config),
                evidence: vec![],
            })
            .await
        }
    }

    fn run_evaluation(
        &self,
        pack: PackId,
        generation: u64,
        evaluator: &str,
        config: Value,
    ) -> impl Future<Output = Result<CommandReceipt>> + Send {
        let evaluator = evaluator.to_owned();
        async move {
            self.command(Command::RunEvaluation {
                pack,
                generation,
                evaluator,
                config: Some(config),
                inputs: vec![],
            })
            .await
        }
    }

    fn refresh_qualification(
        &self,
        pack: PackId,
        generation: u64,
    ) -> impl Future<Output = Result<CommandReceipt>> + Send {
        async move {
            self.command(Command::RefreshQualification { pack, generation })
                .await
        }
    }

    /// Returns the PromotedPack digest.
    fn promote(
        &self,
        pack: PackId,
        generation: u64,
    ) -> impl Future<Output = Result<Digest>> + Send {
        async move {
            digest_of(
                &self
                    .command(Command::PromoteChangePack { pack, generation })
                    .await?,
            )
        }
    }

    fn create_baseline(
        &self,
        members: Vec<Digest>,
        edges: Vec<CompositionEdge>,
    ) -> impl Future<Output = Result<(BaselineId, Digest)>> + Send {
        async move {
            let r = self
                .command(Command::CreateBaseline {
                    members,
                    edges,
                    policies: vec![],
                    metadata: Metadata::new(),
                })
                .await?;
            Ok((id_of(&r)?, digest_of(&r)?))
        }
    }

    fn register_extension(
        &self,
        entrypoint: &str,
        artifact_digest: Digest,
        approved: Vec<HostCapability>,
    ) -> impl Future<Output = Result<Digest>> + Send {
        let entrypoint = entrypoint.to_owned();
        async move {
            digest_of(
                &self
                    .command(Command::RegisterExtension {
                        entrypoint,
                        artifact_digest,
                        approved_host_capabilities: approved,
                    })
                    .await?,
            )
        }
    }
}

impl<T: OpenAevcClient> TypedClient for T {}
