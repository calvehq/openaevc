//! HTTP client for `openaevcd` over TCP, TLS or a Unix-domain socket. Transport failures are
//! reported as retryable `INTERNAL` protocol errors; runtime errors are decoded unchanged.

use std::sync::Arc;
use std::time::Duration;

use crate::protocol::{
    b64, err, CommandEnvelope, CommandReceipt, Digest, ErrorCode, Event, ProtocolError,
    QueryEnvelope, RuntimeInfo,
};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::transport::{transport_error, CBOR, ENVELOPE_HEADER, JSON};

#[derive(Debug, Clone)]
pub enum Endpoint {
    /// `host:port` over plain TCP (loopback deployments).
    Tcp(String),
    /// `host:port` over TLS, trusting `roots`.
    Tls {
        addr: String,
        server_name: String,
        roots: Vec<rustls_pki_types::CertificateDer<'static>>,
    },
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

#[derive(Debug, Clone)]
pub struct HttpClient {
    endpoint: Endpoint,
    cbor: bool,
    timeout: Duration,
}

async fn exchange<S>(io: S, req: Request<Full<Bytes>>) -> Result<Response<Incoming>, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| transport_error(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
        .send_request(req)
        .await
        .map_err(|e| transport_error(e.to_string()))
}

fn envelope_header<T: Serialize>(env: &T) -> Result<String, ProtocolError> {
    Ok(b64::encode(&crate::canonical::to_canonical(env)?))
}

impl HttpClient {
    pub fn new(endpoint: Endpoint) -> Self {
        HttpClient {
            endpoint,
            cbor: false,
            timeout: Duration::from_secs(60),
        }
    }

    /// Same client, using canonical CBOR request and response bodies.
    pub fn cbor(&self) -> Self {
        HttpClient {
            cbor: true,
            ..self.clone()
        }
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    async fn send(&self, req: Request<Full<Bytes>>) -> Result<Response<Incoming>, ProtocolError> {
        let fut = async {
            match &self.endpoint {
                Endpoint::Tcp(addr) => {
                    let s = tokio::net::TcpStream::connect(addr)
                        .await
                        .map_err(|e| transport_error(e.to_string()))?;
                    exchange(s, req).await
                }
                Endpoint::Tls {
                    addr,
                    server_name,
                    roots,
                } => {
                    let mut store = rustls::RootCertStore::empty();
                    for r in roots {
                        store
                            .add(r.clone())
                            .map_err(|e| transport_error(e.to_string()))?;
                    }
                    let provider = Arc::new(rustls::crypto::ring::default_provider());
                    let cfg = rustls::ClientConfig::builder_with_provider(provider)
                        .with_safe_default_protocol_versions()
                        .map_err(|e| transport_error(e.to_string()))?
                        .with_root_certificates(store)
                        .with_no_client_auth();
                    let name = rustls_pki_types::ServerName::try_from(server_name.clone())
                        .map_err(|e| transport_error(e.to_string()))?;
                    let tcp = tokio::net::TcpStream::connect(addr)
                        .await
                        .map_err(|e| transport_error(e.to_string()))?;
                    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
                        .connect(name, tcp)
                        .await
                        .map_err(|e| transport_error(e.to_string()))?;
                    exchange(tls, req).await
                }
                #[cfg(unix)]
                Endpoint::Unix(path) => {
                    let s = tokio::net::UnixStream::connect(path)
                        .await
                        .map_err(|e| transport_error(e.to_string()))?;
                    exchange(s, req).await
                }
            }
        };
        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| transport_error("request timed out"))?
    }

    fn request(&self, method: &str, path: &str) -> hyper::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost")
    }

    /// Reads the body; non-2xx responses become the decoded protocol error.
    async fn read(resp: Response<Incoming>) -> Result<(u16, Vec<u8>, bool), ProtocolError> {
        let status = resp.status().as_u16();
        let cbor = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with(CBOR));
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| transport_error(e.to_string()))?
            .to_bytes()
            .to_vec();
        if (200..300).contains(&status) {
            return Ok((status, body, cbor));
        }
        let value: Option<Value> = if cbor {
            crate::canonical::decode(&body).ok()
        } else {
            serde_json::from_slice(&body).ok()
        };
        let fallback = match status {
            400 | 413 | 415 | 422 => ErrorCode::InvalidArgument,
            401 => ErrorCode::Unauthorized,
            403 => ErrorCode::Forbidden,
            404 | 405 => ErrorCode::NotFound,
            409 => ErrorCode::Conflict,
            _ => ErrorCode::Internal,
        };
        Err(value
            .and_then(|v| serde_json::from_value::<ProtocolError>(v).ok())
            .unwrap_or_else(|| {
                ProtocolError::new(
                    fallback,
                    format!("HTTP {status}: {}", String::from_utf8_lossy(&body)),
                )
            }))
    }

    fn decode<T: DeserializeOwned>(body: &[u8], cbor: bool) -> Result<T, ProtocolError> {
        let v: Value = if cbor {
            crate::canonical::decode(body)?
        } else {
            serde_json::from_slice(body)
                .map_err(|e| transport_error(format!("malformed response: {e}")))?
        };
        serde_json::from_value(v).map_err(|e| transport_error(format!("unexpected response: {e}")))
    }

    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ProtocolError> {
        let (ct, bytes) = if self.cbor {
            (CBOR, crate::canonical::to_canonical(body)?)
        } else {
            (
                JSON,
                serde_json::to_vec(body).map_err(|e| err::internal(e.to_string()))?,
            )
        };
        let req = self
            .request("POST", path)
            .header("content-type", ct)
            .header("accept", ct)
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|e| transport_error(e.to_string()))?;
        let (_, body, cbor) = Self::read(self.send(req).await?).await?;
        Self::decode(&body, cbor)
    }

    /// `GET /v1/info` (unauthenticated; version negotiation).
    pub async fn info(&self) -> Result<RuntimeInfo, ProtocolError> {
        let req = self
            .request("GET", "/v1/info")
            .body(Full::new(Bytes::new()))
            .map_err(|e| transport_error(e.to_string()))?;
        let (_, body, cbor) = Self::read(self.send(req).await?).await?;
        Self::decode(&body, cbor)
    }

    pub async fn command(&self, env: &CommandEnvelope) -> Result<CommandReceipt, ProtocolError> {
        self.post("/v1/commands", env).await
    }

    pub async fn query(&self, env: &QueryEnvelope) -> Result<Value, ProtocolError> {
        self.post("/v1/queries", env).await
    }

    /// Posts an already-signed command envelope value as-is (conformance and diagnostics).
    pub async fn command_value(&self, env: &Value) -> Result<CommandReceipt, ProtocolError> {
        self.post("/v1/commands", env).await
    }

    /// Posts an already-signed query envelope value as-is.
    pub async fn query_value(&self, env: &Value) -> Result<Value, ProtocolError> {
        self.post("/v1/queries", env).await
    }

    /// `PUT /v1/objects/{digest}` with an already-signed envelope value.
    pub async fn put_object_value(
        &self,
        env: &Value,
        digest: Digest,
        bytes: Vec<u8>,
    ) -> Result<CommandReceipt, ProtocolError> {
        let req = self
            .request("PUT", &format!("/v1/objects/{digest}"))
            .header(
                ENVELOPE_HEADER,
                b64::encode(&crate::canonical::encode(env)?),
            )
            .header("content-type", CBOR)
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|e| transport_error(e.to_string()))?;
        let (_, body, cbor) = Self::read(self.send(req).await?).await?;
        Self::decode(&body, cbor)
    }

    /// `GET /v1/objects/{digest}` with a signed `GetObject` envelope; returns canonical bytes.
    pub async fn get_object(
        &self,
        env: &QueryEnvelope,
        digest: Digest,
    ) -> Result<Vec<u8>, ProtocolError> {
        let req = self
            .request("GET", &format!("/v1/objects/{digest}"))
            .header(ENVELOPE_HEADER, envelope_header(env)?)
            .body(Full::new(Bytes::new()))
            .map_err(|e| transport_error(e.to_string()))?;
        let (_, body, _) = Self::read(self.send(req).await?).await?;
        Ok(body)
    }

    /// `PUT /v1/objects/{digest}` with a signed `PutImmutableObject` envelope (empty inline bytes).
    pub async fn put_object(
        &self,
        env: &CommandEnvelope,
        bytes: Vec<u8>,
    ) -> Result<CommandReceipt, ProtocolError> {
        let digest = match &env.body {
            crate::protocol::Command::PutImmutableObject { digest, .. } => *digest,
            _ => {
                return Err(err::invalid(
                    "put_object needs a PutImmutableObject envelope",
                ))
            }
        };
        let req = self
            .request("PUT", &format!("/v1/objects/{digest}"))
            .header(ENVELOPE_HEADER, envelope_header(env)?)
            .header("content-type", CBOR)
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|e| transport_error(e.to_string()))?;
        let (_, body, cbor) = Self::read(self.send(req).await?).await?;
        Self::decode(&body, cbor)
    }

    /// Opens `GET /v1/events` (SSE) with a signed `ListEvents` envelope.
    pub async fn events(
        &self,
        env: &QueryEnvelope,
        subjects: &[String],
        last_event_id: Option<u64>,
    ) -> Result<EventStream, ProtocolError> {
        let mut path = String::from("/v1/events");
        for (i, s) in subjects.iter().enumerate() {
            path.push(if i == 0 { '?' } else { '&' });
            path.push_str("subject=");
            path.push_str(s);
        }
        let mut b = self
            .request("GET", &path)
            .header(ENVELOPE_HEADER, envelope_header(env)?)
            .header("accept", "text/event-stream");
        if let Some(id) = last_event_id {
            b = b.header("last-event-id", id.to_string());
        }
        let req = b
            .body(Full::new(Bytes::new()))
            .map_err(|e| transport_error(e.to_string()))?;
        let fut = async {
            match &self.endpoint {
                Endpoint::Tcp(addr) => {
                    exchange(
                        tokio::net::TcpStream::connect(addr)
                            .await
                            .map_err(|e| transport_error(e.to_string()))?,
                        req,
                    )
                    .await
                }
                #[cfg(unix)]
                Endpoint::Unix(p) => {
                    exchange(
                        tokio::net::UnixStream::connect(p)
                            .await
                            .map_err(|e| transport_error(e.to_string()))?,
                        req,
                    )
                    .await
                }
                Endpoint::Tls { .. } => self.send(req).await,
            }
        };
        let resp = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| transport_error("request timed out"))??;
        if !resp.status().is_success() {
            return Err(Self::read(resp)
                .await
                .err()
                .unwrap_or_else(|| transport_error("event stream rejected")));
        }
        Ok(EventStream {
            body: resp.into_body(),
            buf: Vec::new(),
        })
    }

    /// `POST` arbitrary bytes (diagnostics and negative tests).
    pub async fn post_raw(
        &self,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ProtocolError> {
        let req = self
            .request("POST", path)
            .header("content-type", content_type)
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| transport_error(e.to_string()))?;
        Ok(Self::read(self.send(req).await?).await?.1)
    }

    /// `GET` returning `(status, body)` without error decoding.
    pub async fn get_raw(&self, path: &str) -> Result<(u16, Vec<u8>), ProtocolError> {
        let req = self
            .request("GET", path)
            .body(Full::new(Bytes::new()))
            .map_err(|e| transport_error(e.to_string()))?;
        let resp = self.send(req).await?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| transport_error(e.to_string()))?
            .to_bytes()
            .to_vec();
        Ok((status, body))
    }
}

/// Server-sent event stream of journal events (at-least-once, in sequence order).
#[derive(Debug)]
pub struct EventStream {
    body: Incoming,
    buf: Vec<u8>,
}

impl EventStream {
    /// Next event; `None` when the server closes the stream.
    pub async fn next(&mut self) -> Option<Result<Event, ProtocolError>> {
        loop {
            if let Some(end) = self.buf.windows(2).position(|w| w == b"\n\n") {
                let block: Vec<u8> = self.buf.drain(..end + 2).collect();
                let text = String::from_utf8_lossy(&block);
                let mut kind = "";
                let mut data = String::new();
                for line in text.lines() {
                    if let Some(v) = line.strip_prefix("event:") {
                        kind = v.trim();
                    } else if let Some(v) = line.strip_prefix("data:") {
                        data.push_str(v.trim_start());
                    }
                }
                if data.is_empty() {
                    continue; // keep-alive comment
                }
                if kind == "error" {
                    let e = serde_json::from_str::<ProtocolError>(&data)
                        .unwrap_or_else(|_| transport_error(data));
                    return Some(Err(e));
                }
                return Some(
                    serde_json::from_str(&data)
                        .map_err(|e| transport_error(format!("malformed event: {e}"))),
                );
            }
            match self.body.frame().await {
                Some(Ok(f)) => {
                    if let Ok(d) = f.into_data() {
                        self.buf.extend_from_slice(&d);
                    }
                }
                Some(Err(e)) => return Some(Err(transport_error(e.to_string()))),
                None => return None,
            }
        }
    }
}
