//! HTTP server over TCP, TLS or a Unix-domain socket.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use openaevc_protocol::{
    b64, err, Command, CommandEnvelope, Digest, Envelope, ErrorCode, ProtocolError, Query,
    QueryEnvelope,
};
use openaevc_runtime::Runtime;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;

use crate::{status_for, CBOR, ENVELOPE_HEADER, JSON};

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub max_request_bytes: usize,
    pub request_timeout: Duration,
    /// Per-subscriber event buffer.
    pub event_buffer: usize,
    /// A subscriber whose buffer stays full this long is disconnected.
    pub slow_consumer_timeout: Duration,
    /// Graceful shutdown waits this long for open connections.
    pub shutdown_grace: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            max_request_bytes: 16 * 1024 * 1024,
            request_timeout: Duration::from_secs(60),
            event_buffer: 256,
            slow_consumer_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

/// Liveness/readiness state shared with the daemon.
#[derive(Debug)]
pub struct Health {
    ready: AtomicBool,
    stopping: watch::Receiver<bool>,
    requests: AtomicU64,
    errors: AtomicU64,
    subscribers: AtomicU64,
}

impl Health {
    pub fn new(stopping: watch::Receiver<bool>) -> Self {
        Health {
            ready: AtomicBool::new(false),
            stopping,
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            subscribers: AtomicU64::new(0),
        }
    }

    /// Ready immediately and never stopping (tests, embedded servers).
    pub fn ready() -> Self {
        let (tx, rx) = watch::channel(false);
        std::mem::forget(tx);
        let h = Self::new(rx);
        h.set_ready(true);
        h
    }

    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst) && !*self.stopping.borrow()
    }
}

#[derive(Clone)]
struct AppState {
    rt: Arc<Runtime>,
    cfg: ServerConfig,
    health: Arc<Health>,
}

enum Reply {
    Value(Value, bool),
    Raw(Vec<u8>),
    Error(ProtocolError, bool),
}

fn wants_cbor(h: &HeaderMap) -> bool {
    h.get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains(CBOR))
}

fn is_cbor(h: &HeaderMap) -> bool {
    h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with(CBOR))
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let encode = |v: &Value, cbor: bool| -> (HeaderValue, Vec<u8>) {
            if cbor {
                if let Ok(b) = openaevc_canonical::encode(v) {
                    return (HeaderValue::from_static(CBOR), b);
                }
            }
            (
                HeaderValue::from_static(JSON),
                serde_json::to_vec(v).unwrap_or_default(),
            )
        };
        match self {
            Reply::Value(v, cbor) => {
                let (ct, body) = encode(&v, cbor);
                ([(header::CONTENT_TYPE, ct)], body).into_response()
            }
            Reply::Raw(b) => {
                ([(header::CONTENT_TYPE, HeaderValue::from_static(CBOR))], b).into_response()
            }
            Reply::Error(e, cbor) => {
                let status = StatusCode::from_u16(status_for(e.code))
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let v = serde_json::to_value(&e).unwrap_or(Value::Null);
                let (ct, body) = encode(&v, cbor);
                (status, [(header::CONTENT_TYPE, ct)], body).into_response()
            }
        }
    }
}

fn to_value<T: Serialize>(v: &T) -> Result<Value, ProtocolError> {
    serde_json::to_value(v).map_err(|e| err::internal(format!("encode: {e}")))
}

/// Decodes a request body (JSON or canonical CBOR) into the JSON-model value that was signed.
/// The runtime verifies the signature over exactly this value and parses it strictly.
fn decode_body(headers: &HeaderMap, body: &[u8]) -> Result<Value, ProtocolError> {
    if is_cbor(headers) {
        Ok(openaevc_canonical::decode(body)?)
    } else {
        serde_json::from_slice(body)
            .map_err(|e| err::invalid(format!("request body is not JSON: {e}")))
    }
}

/// Percent-decoded values of every `name=value` pair in a query string. Undecodable values are
/// kept verbatim (they then fail later validation).
fn query_params(query: Option<&str>, name: &str) -> Vec<String> {
    let decode = |v: &str| -> Option<String> {
        let b = v.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'%' => {
                    let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                    out.push(u8::from_str_radix(h, 16).ok()?);
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        String::from_utf8(out).ok()
    };
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .filter(|(k, _)| *k == name)
        .map(|(_, v)| decode(v).unwrap_or_else(|| v.to_owned()))
        .collect()
}

/// Decodes the envelope carried in the `openaevc-envelope` header (or `envelope` query
/// parameter): the value that was signed plus its parsed form for endpoint shape checks.
fn decode_header<T: Serialize + DeserializeOwned>(
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<(Value, Envelope<T>), ProtocolError> {
    let from_query = query_params(query, "envelope").into_iter().next();
    let raw = headers
        .get(ENVELOPE_HEADER)
        .and_then(|v| v.to_str().ok().map(str::to_owned))
        .or(from_query)
        .ok_or_else(|| ProtocolError::new(ErrorCode::Unauthorized, "missing signed envelope"))?;
    let bytes = b64::decode(&raw).map_err(|_| err::invalid("envelope header is not base64url"))?;
    let value = openaevc_canonical::decode(&bytes)?;
    let env = serde_json::from_value(value.clone())
        .map_err(|e| err::invalid(format!("invalid request envelope: {e}")))?;
    Ok((value, env))
}

fn body_or_error(body: Result<Bytes, BytesRejection>) -> Result<Bytes, ProtocolError> {
    body.map_err(|r| err::invalid(format!("request body rejected: {}", r.body_text())))
}

async fn blocking<T: Send + 'static>(
    s: &AppState,
    f: impl FnOnce(Arc<Runtime>) -> Result<T, ProtocolError> + Send + 'static,
) -> Result<T, ProtocolError> {
    s.health.requests.fetch_add(1, Ordering::Relaxed);
    let rt = s.rt.clone();
    let task = tokio::task::spawn_blocking(move || f(rt));
    let r = match tokio::time::timeout(s.cfg.request_timeout, task).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => Err(err::internal("request handler failed")),
        Err(_) => {
            // The runtime may still commit the request: its outcome is unknown. Retrying is
            // safe only with the *same* envelope (idempotent by request_id, AEVC-AUTH-0006); a
            // freshly signed envelope could apply the command twice.
            let mut e = err::internal(
                "request timed out; outcome unknown: resend the same signed envelope to learn it",
            );
            e.retryable = false;
            Err(e)
        }
    };
    if r.is_err() {
        s.health.errors.fetch_add(1, Ordering::Relaxed);
    }
    r
}

async fn info(State(s): State<AppState>) -> Reply {
    match to_value(&s.rt.info()) {
        Ok(v) => Reply::Value(v, false),
        Err(e) => Reply::Error(e, false),
    }
}

async fn commands(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Reply {
    let cbor = wants_cbor(&headers);
    let r = async {
        let env = decode_body(&headers, &body_or_error(body)?)?;
        let receipt = blocking(&s, move |rt| rt.execute_value(env)).await?;
        to_value(&receipt)
    }
    .await;
    match r {
        Ok(v) => Reply::Value(v, cbor),
        Err(e) => Reply::Error(e, cbor),
    }
}

async fn queries(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Reply {
    let cbor = wants_cbor(&headers);
    let r = async {
        let env = decode_body(&headers, &body_or_error(body)?)?;
        blocking(&s, move |rt| rt.query_value(env)).await
    }
    .await;
    match r {
        Ok(v) => Reply::Value(v, cbor),
        Err(e) => Reply::Error(e, cbor),
    }
}

fn path_digest(d: &str) -> Result<Digest, ProtocolError> {
    d.parse().map_err(|_| err::invalid("path is not a digest"))
}

async fn get_object(
    State(s): State<AppState>,
    Path(d): Path<String>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> Reply {
    let r = async {
        let digest = path_digest(&d)?;
        let (value, env): (Value, QueryEnvelope) = decode_header(&headers, q.as_deref())?;
        if !matches!(env.body, Query::GetObject { digest: x } if x == digest) {
            return Err(err::invalid(
                "the signed envelope must be GetObject for this digest",
            ));
        }
        let obj = blocking(&s, move |rt| rt.read_object_value(value, &digest)).await?;
        Ok(obj.bytes().to_vec())
    }
    .await;
    match r {
        Ok(b) => Reply::Raw(b),
        Err(e) => Reply::Error(e, false),
    }
}

async fn put_object(
    State(s): State<AppState>,
    Path(d): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Reply {
    let r = async {
        let digest = path_digest(&d)?;
        let (value, env): (Value, CommandEnvelope) = decode_header(&headers, None)?;
        if !matches!(&env.body, Command::PutImmutableObject { digest: x, bytes } if *x == digest && bytes.is_empty()) {
            return Err(err::invalid("the signed envelope must be PutImmutableObject for this digest with empty inline bytes"));
        }
        let payload = body_or_error(body)?.to_vec();
        let receipt = blocking(&s, move |rt| rt.execute_with_payload_value(value, payload)).await?;
        to_value(&receipt)
    }
    .await;
    match r {
        Ok(v) => Reply::Value(v, false),
        Err(e) => Reply::Error(e, false),
    }
}

fn sse_event(e: &openaevc_protocol::Event) -> SseEvent {
    SseEvent::default()
        .id(e.sequence.to_string())
        .event(e.kind.clone())
        .data(serde_json::to_string(e).unwrap_or_default())
}

async fn events(State(s): State<AppState>, RawQuery(q): RawQuery, headers: HeaderMap) -> Response {
    let setup = async {
        let (env, _): (Value, QueryEnvelope) = decode_header(&headers, q.as_deref())?;
        let subjects = query_params(q.as_deref(), "subject");
        let resume: Option<u64> = headers
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        blocking(&s, move |rt| {
            let mut sub = rt.subscribe_value(env, subjects)?;
            if let Some(r) = resume {
                sub.set_cursor(r.max(sub.cursor()));
            }
            Ok(sub)
        })
        .await
    }
    .await;
    let mut sub = match setup {
        Ok(sub) => sub,
        Err(e) => return Reply::Error(e, false).into_response(),
    };
    let (tx, rx) = mpsc::channel::<Result<SseEvent, Infallible>>(s.cfg.event_buffer.max(1));
    let state = s.clone();
    tokio::spawn(async move {
        state.health.subscribers.fetch_add(1, Ordering::Relaxed);
        let mut notify = state.rt.subscribe_notifications();
        let mut stopping = state.health.stopping.clone();
        'outer: loop {
            let rt = state.rt.clone();
            let polled = tokio::task::spawn_blocking(move || {
                let r = rt.poll(&mut sub, 100);
                (sub, r)
            })
            .await;
            let Ok((s2, r)) = polled else { break };
            sub = s2;
            match r {
                Err(e) => {
                    let data = serde_json::to_string(&e).unwrap_or_default();
                    let _ = tx
                        .send(Ok(SseEvent::default().event("error").data(data)))
                        .await;
                    break;
                }
                Ok(batch) if !batch.is_empty() => {
                    for e in &batch {
                        // Persistent slow consumers are disconnected (bounded memory).
                        if tx
                            .send_timeout(Ok(sse_event(e)), state.cfg.slow_consumer_timeout)
                            .await
                            .is_err()
                        {
                            break 'outer;
                        }
                    }
                    continue;
                }
                Ok(_) => {}
            }
            tokio::select! {
                changed = notify.changed() => if changed.is_err() { break },
                _ = stopping.changed() => break,
                _ = tx.closed() => break,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }
        state.health.subscribers.fetch_sub(1, Ordering::Relaxed);
    });
    Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn live() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(s): State<AppState>) -> StatusCode {
    if s.health.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn metrics(State(s): State<AppState>) -> impl IntoResponse {
    let h = &s.health;
    let body = format!(
        "# TYPE openaevc_http_requests_total counter\nopenaevc_http_requests_total {}\n\
         # TYPE openaevc_http_errors_total counter\nopenaevc_http_errors_total {}\n\
         # TYPE openaevc_event_subscribers gauge\nopenaevc_event_subscribers {}\n{}",
        h.requests.load(Ordering::Relaxed),
        h.errors.load(Ordering::Relaxed),
        h.subscribers.load(Ordering::Relaxed),
        s.rt.metrics().prometheus(),
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

async fn openapi_doc() -> Reply {
    Reply::Value(crate::openapi::document(), false)
}

/// The v1 HTTP surface.
pub fn router(rt: Arc<Runtime>, cfg: ServerConfig, health: Arc<Health>) -> Router {
    let limit = cfg.max_request_bytes;
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/commands", post(commands))
        .route("/v1/queries", post(queries))
        .route("/v1/events", get(events))
        .route("/v1/objects/{digest}", get(get_object).put(put_object))
        .route("/v1/openapi.json", get(openapi_doc))
        .route("/v1/health/live", get(live))
        .route("/v1/health/ready", get(ready))
        .route("/v1/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(AppState { rt, cfg, health })
}

/// A bound listener. Remote (non-loopback) TCP must use `Tls`.
pub enum Listener {
    Tcp(tokio::net::TcpListener),
    Tls(tokio::net::TcpListener, tokio_rustls::TlsAcceptor),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Listener::Tcp(_) => "Listener::Tcp",
            Listener::Tls(..) => "Listener::Tls",
            #[cfg(unix)]
            Listener::Unix(_) => "Listener::Unix",
        })
    }
}

/// Builds a TLS acceptor from a certificate chain and private key.
pub fn tls_acceptor(
    chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    key: rustls_pki_types::PrivateKeyDer<'static>,
) -> Result<tokio_rustls::TlsAcceptor, ProtocolError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| err::invalid(format!("TLS configuration: {e}")))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| err::invalid(format!("TLS certificate: {e}")))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}

/// Concurrent connections served per listener; further clients wait in the accept backlog.
const MAX_CONNECTIONS: usize = 1024;
/// A client must finish sending request headers within this time (slow-header defence; hyper
/// silently disables its default unless a timer is set).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

fn conn_builder() -> Builder<TokioExecutor> {
    let mut b = Builder::new(TokioExecutor::new());
    b.http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    b.http2().timer(hyper_util::rt::TokioTimer::new());
    b
}

fn spawn_conn<IO>(
    io: IO,
    app: Router,
    graceful: &GracefulShutdown,
    permit: tokio::sync::OwnedSemaphorePermit,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper_util::service::TowerToHyperService::new(app);
    let conn = conn_builder()
        .serve_connection_with_upgrades(TokioIo::new(io), svc)
        .into_owned();
    let fut = graceful.watch(conn);
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = fut.await {
            tracing::debug!(event = "transport.connection_error", error = %e);
        }
    });
}

/// Serves until `shutdown` becomes true, then drains connections gracefully.
pub async fn serve(
    listener: Listener,
    app: Router,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let graceful = GracefulShutdown::new();
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok(permit) = slots.clone().acquire_owned().await else {
            break;
        };
        tokio::select! {
            r = shutdown.changed() => {
                if r.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = accept(&listener) => match accepted {
                Ok(Conn::Plain(s)) => spawn_conn(s, app.clone(), &graceful, permit),
                Ok(Conn::Tls(s, acceptor)) => {
                    let app = app.clone();
                    let watcher = graceful.watcher();
                    tokio::spawn(async move {
                        let _permit = permit;
                        match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(s)).await {
                            Ok(Ok(tls)) => {
                                let svc = hyper_util::service::TowerToHyperService::new(app);
                                let conn = conn_builder().serve_connection_with_upgrades(TokioIo::new(tls), svc).into_owned();
                                let _ = watcher.watch(conn).await;
                            }
                            _ => tracing::debug!(event = "transport.tls_handshake_failed"),
                        }
                    });
                }
                #[cfg(unix)]
                Ok(Conn::Unix(s)) => spawn_conn(s, app.clone(), &graceful, permit),
                Err(e) => {
                    tracing::warn!(event = "transport.accept_failed", error = %e);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
    drop(listener);
    let _ = tokio::time::timeout(Duration::from_secs(10), graceful.shutdown()).await;
    Ok(())
}

enum Conn {
    Plain(tokio::net::TcpStream),
    Tls(tokio::net::TcpStream, tokio_rustls::TlsAcceptor),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

async fn accept(l: &Listener) -> std::io::Result<Conn> {
    match l {
        Listener::Tcp(t) => t.accept().await.map(|(s, _)| Conn::Plain(s)),
        Listener::Tls(t, a) => t.accept().await.map(|(s, _)| Conn::Tls(s, a.clone())),
        #[cfg(unix)]
        Listener::Unix(u) => u.accept().await.map(|(s, _)| Conn::Unix(s)),
    }
}

#[cfg(test)]
mod tests {
    use super::query_params;

    #[test]
    fn query_values_are_percent_decoded() {
        let q = Some("subject=sha256%3Aab&x=1&subject=cpk_a&envelope=QUJD");
        assert_eq!(query_params(q, "subject"), ["sha256:ab", "cpk_a"]);
        assert_eq!(query_params(q, "envelope"), ["QUJD"]);
        assert!(query_params(None, "subject").is_empty());
        assert_eq!(query_params(Some("subject=%zz"), "subject"), ["%zz"]);
    }
}
