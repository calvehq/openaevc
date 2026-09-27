//! Conformance targets: the in-process reference runtime, or any implementation exposing the v1
//! transport. Cases only use the public client surface plus a few target capabilities (time
//! control, raw envelope submission, local extension directory).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use openaevc_core::ImmutableObject;
use openaevc_core::{Clock, FixedClock, IdGeneratorExt, UuidV7Ids};
use openaevc_crypto::{Signer, SigningKey};
use openaevc_protocol::*;
use openaevc_runtime::{Admin, Runtime, RuntimeConfig, RuntimeDeps};
use openaevc_sdk::{EmbeddedClient, EventStream, OpenAevcClient, RemoteClient, Session};
use openaevc_store::{MemoryStore, SqliteOptions, SqliteStore, Store};
use openaevc_transport::client::{Endpoint, HttpClient};
use serde_json::Value;

/// Client over either target kind (the SDK traits are statically dispatched).
#[derive(Clone, Debug)]
pub enum Client {
    Embedded(EmbeddedClient),
    Remote(RemoteClient),
}

impl OpenAevcClient for Client {
    fn session(&self) -> &Session {
        match self {
            Client::Embedded(c) => c.session(),
            Client::Remote(c) => c.session(),
        }
    }

    async fn command(&self, command: Command) -> Result<CommandReceipt, ProtocolError> {
        match self {
            Client::Embedded(c) => c.command(command).await,
            Client::Remote(c) => c.command(command).await,
        }
    }

    async fn query(&self, query: Query) -> Result<Value, ProtocolError> {
        match self {
            Client::Embedded(c) => c.query(query).await,
            Client::Remote(c) => c.query(query).await,
        }
    }

    async fn subscribe(&self, filter: EventFilter) -> Result<EventStream, ProtocolError> {
        match self {
            Client::Embedded(c) => c.subscribe(filter).await,
            Client::Remote(c) => c.subscribe(filter).await,
        }
    }

    async fn get_object(&self, digest: Digest) -> Result<ImmutableObject, ProtocolError> {
        match self {
            Client::Embedded(c) => c.get_object(digest).await,
            Client::Remote(c) => c.get_object(digest).await,
        }
    }
}

/// Everything that must stay the same across restarts of an in-process runtime.
#[derive(Clone, Debug)]
pub struct Identity {
    pub clock: FixedClock,
    pub admin: Arc<SigningKey>,
    pub admin_id: PrincipalId,
    pub signer: Arc<SigningKey>,
    pub runtime_principal: PrincipalId,
}

impl Identity {
    pub fn generate() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;
        let clock = FixedClock::new(now);
        let ids = UuidV7Ids::new(Arc::new(clock.clone()));
        Identity {
            admin: Arc::new(SigningKey::generate()),
            admin_id: ids.next(),
            signer: Arc::new(SigningKey::generate()),
            runtime_principal: ids.next(),
            clock,
        }
    }
}

/// The reference runtime running inside the conformance process.
pub struct InProcess {
    pub rt: Arc<Runtime>,
    pub clock: FixedClock,
    pub admin: Arc<SigningKey>,
    pub admin_id: PrincipalId,
    pub extensions: Option<PathBuf>,
    _data_root: Option<tempfile::TempDir>,
}

/// An implementation reached over the v1 HTTP transport.
pub struct Remote {
    pub endpoint: Endpoint,
    pub http: HttpClient,
    pub admin: Arc<SigningKey>,
    pub admin_id: PrincipalId,
    /// Local path of the same extension directory the remote runtime is configured with.
    pub extensions: Option<PathBuf>,
    pub checkpoint_interval: u64,
}

pub enum Target {
    InProcess(InProcess),
    Remote(Remote),
}

impl std::fmt::Debug for InProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InProcess")
    }
}

impl std::fmt::Debug for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Remote({:?})", self.endpoint)
    }
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

/// Runtime configuration used for in-process targets (short checkpoint interval so checkpoint
/// requirements are exercised quickly).
pub fn in_process_config(
    admin_id: PrincipalId,
    admin: &SigningKey,
    extensions: Option<&Path>,
) -> RuntimeConfig {
    RuntimeConfig {
        admins: vec![Admin {
            id: admin_id,
            public_key: admin.public_key(),
        }],
        checkpoint_interval: 10,
        extension_dirs: extensions
            .map(|p| vec![p.to_path_buf()])
            .unwrap_or_default(),
        extension_deadline_ms: 3_000,
        max_extension_frame: 1024 * 1024,
        ..RuntimeConfig::default()
    }
}

impl Target {
    /// In-process reference runtime; `sqlite` selects the SQLite+CAS store in a temp dir.
    pub fn in_process(extensions: Option<PathBuf>, sqlite: bool) -> Result<Self, ProtocolError> {
        let (store, dir): (Arc<dyn Store>, _) = if sqlite {
            let dir = tempfile::tempdir().map_err(|e| err::internal(e.to_string()))?;
            (
                Arc::new(SqliteStore::open(dir.path(), SqliteOptions::create())?),
                Some(dir),
            )
        } else {
            (Arc::new(MemoryStore::new()), None)
        };
        let t = Self::with_store(store, &Identity::generate(), extensions)?;
        Ok(match t {
            Target::InProcess(p) => Target::InProcess(InProcess {
                _data_root: dir,
                ..p
            }),
            remote => remote,
        })
    }

    /// In-process reference runtime over `store` with a fixed identity (restartable).
    pub fn with_store(
        store: Arc<dyn Store>,
        id: &Identity,
        extensions: Option<PathBuf>,
    ) -> Result<Self, ProtocolError> {
        let deps = RuntimeDeps {
            store,
            clock: Arc::new(id.clock.clone()),
            ids: Arc::new(UuidV7Ids::new(Arc::new(id.clock.clone()))),
            signer: id.signer.clone(),
            runtime_principal: id.runtime_principal,
        };
        let rt = Runtime::open(
            deps,
            in_process_config(id.admin_id, &id.admin, extensions.as_deref()),
        )?;
        Ok(Target::InProcess(InProcess {
            rt: Arc::new(rt),
            clock: id.clock.clone(),
            admin: id.admin.clone(),
            admin_id: id.admin_id,
            extensions,
            _data_root: None,
        }))
    }

    pub fn remote(
        endpoint: Endpoint,
        admin: Arc<SigningKey>,
        admin_id: PrincipalId,
        extensions: Option<PathBuf>,
        checkpoint_interval: u64,
    ) -> Self {
        Target::Remote(Remote {
            http: HttpClient::new(endpoint.clone()),
            endpoint,
            admin,
            admin_id,
            extensions,
            checkpoint_interval,
        })
    }

    pub fn describe(&self) -> String {
        match self {
            Target::InProcess(_) => "in-process reference runtime".into(),
            Target::Remote(r) => format!("remote {:?}", r.endpoint),
        }
    }

    pub fn is_remote(&self) -> bool {
        matches!(self, Target::Remote(_))
    }

    pub fn extensions(&self) -> Option<&Path> {
        match self {
            Target::InProcess(t) => t.extensions.as_deref(),
            Target::Remote(t) => t.extensions.as_deref(),
        }
    }

    pub fn checkpoint_interval(&self) -> u64 {
        match self {
            Target::InProcess(_) => 10,
            Target::Remote(r) => r.checkpoint_interval,
        }
    }

    pub async fn info(&self) -> Result<RuntimeInfo, ProtocolError> {
        match self {
            Target::InProcess(t) => Ok(t.rt.info()),
            Target::Remote(t) => t.http.info().await,
        }
    }

    pub fn now(&self) -> Timestamp {
        match self {
            Target::InProcess(t) => t.clock.now(),
            Target::Remote(_) => openaevc_core::SystemClock.now(),
        }
    }

    /// Moves time past `t` (in-process: clock jump; remote: wait, plus a maintenance tick).
    pub async fn advance_past(&self, t: Timestamp) {
        match self {
            Target::InProcess(p) => {
                let target = t.unix_nanos() + 1_000_000;
                if p.clock.now().unix_nanos() < target {
                    p.clock.set(target as i64);
                }
                let rt = p.rt.clone();
                let _ = tokio::task::spawn_blocking(move || rt.tick()).await;
            }
            Target::Remote(_) => {
                let now = openaevc_core::SystemClock.now();
                let wait = now.millis_until(t).max(0) as u64 + 2_500;
                tokio::time::sleep(Duration::from_millis(wait)).await;
            }
        }
    }

    pub fn session(
        &self,
        key: Arc<SigningKey>,
        principal: PrincipalId,
        ns: Option<NamespaceId>,
    ) -> Session {
        let s = Session::new(key, principal, ns);
        match self {
            Target::InProcess(t) => s.with_clock(Arc::new(t.clock.clone())),
            Target::Remote(_) => s,
        }
    }

    pub fn client(&self, session: Session) -> Client {
        match self {
            Target::InProcess(t) => Client::Embedded(EmbeddedClient::new(t.rt.clone(), session)),
            Target::Remote(t) => Client::Remote(RemoteClient::new(t.endpoint.clone(), session)),
        }
    }

    pub fn admin(&self) -> Client {
        let (key, id) = match self {
            Target::InProcess(t) => (t.admin.clone(), t.admin_id),
            Target::Remote(t) => (t.admin.clone(), t.admin_id),
        };
        self.client(self.session(key, id, None))
    }

    /// Submits an already-signed command envelope value exactly as given.
    pub async fn command_value(&self, v: Value) -> Result<CommandReceipt, ProtocolError> {
        match self {
            Target::InProcess(t) => {
                let rt = t.rt.clone();
                tokio::task::spawn_blocking(move || rt.execute_value(v))
                    .await
                    .map_err(|e| err::internal(e.to_string()))?
            }
            Target::Remote(t) => t.http.command_value(&v).await,
        }
    }

    pub async fn query_value(&self, v: Value) -> Result<Value, ProtocolError> {
        match self {
            Target::InProcess(t) => {
                let rt = t.rt.clone();
                tokio::task::spawn_blocking(move || rt.query_value(v))
                    .await
                    .map_err(|e| err::internal(e.to_string()))?
            }
            Target::Remote(t) => t.http.query_value(&v).await,
        }
    }

    /// Object upload with the bytes outside the signed envelope (HTTP `PUT /v1/objects`).
    pub async fn put_object_payload(
        &self,
        env: Value,
        digest: Digest,
        bytes: Vec<u8>,
    ) -> Result<CommandReceipt, ProtocolError> {
        match self {
            Target::InProcess(t) => {
                let rt = t.rt.clone();
                tokio::task::spawn_blocking(move || rt.execute_with_payload_value(env, bytes))
                    .await
                    .map_err(|e| err::internal(e.to_string()))?
            }
            Target::Remote(t) => t.http.put_object_value(&env, digest, bytes).await,
        }
    }
}
