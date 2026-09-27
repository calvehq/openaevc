//! Versioned TOML configuration with environment-variable overrides for operational values.
//! Configuration never defines product policy; Namespace policy lives in PolicyDocuments.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use openaevc_protocol::{PrincipalId, PublicKey};
use serde::{Deserialize, Serialize};

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub data_root: PathBuf,
    #[serde(default)]
    pub listen: Listen,
    #[serde(default)]
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub extensions: Extensions,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub telemetry: Telemetry,
    #[serde(default)]
    pub admins: Vec<AdminEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// Unix-domain socket path (Unix only). Defaults to `<data_root>/openaevcd.sock`.
    pub unix_socket: Option<PathBuf>,
    /// Plain TCP listener; must be a loopback address.
    pub tcp: Option<String>,
    /// TLS listener (required for non-loopback addresses).
    pub tls: Option<Tls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub address: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeSection {
    pub replay_window_ms: u64,
    pub checkpoint_interval: u64,
    pub lease_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub audit_denials: bool,
    pub max_page: u32,
}

impl Default for RuntimeSection {
    fn default() -> Self {
        let d = openaevc_runtime::RuntimeConfig::default();
        RuntimeSection {
            replay_window_ms: d.replay_window_ms,
            checkpoint_interval: d.checkpoint_interval,
            lease_ms: d.lease_ms,
            heartbeat_interval_ms: d.heartbeat_interval_ms,
            audit_denials: d.audit_denials,
            max_page: d.max_page,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Storage {
    /// `full` (fsync files and directories) or `normal`.
    pub durability: String,
    pub inline_threshold: usize,
    /// Apply pending schema migrations at startup without `--migrate`.
    pub auto_migrate: bool,
}

impl Default for Storage {
    fn default() -> Self {
        Storage {
            durability: "full".into(),
            inline_threshold: 16 * 1024,
            auto_migrate: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Extensions {
    pub directories: Vec<PathBuf>,
    pub deadline_ms: u64,
    pub max_frame_bytes: usize,
}

impl Default for Extensions {
    fn default() -> Self {
        let d = openaevc_runtime::RuntimeConfig::default();
        Extensions {
            directories: vec![],
            deadline_ms: d.extension_deadline_ms,
            max_frame_bytes: d.max_extension_frame,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_request_bytes: usize,
    pub request_timeout_ms: u64,
    pub event_buffer: usize,
    pub slow_consumer_timeout_ms: u64,
    pub tick_interval_ms: u64,
    pub shutdown_grace_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_request_bytes: 16 * 1024 * 1024,
            request_timeout_ms: 60_000,
            event_buffer: 256,
            slow_consumer_timeout_ms: 10_000,
            tick_interval_ms: 1_000,
            shutdown_grace_ms: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Telemetry {
    /// `text` or `json`.
    pub log_format: String,
    pub log_level: String,
    /// Serve Prometheus text at `/v1/metrics`.
    pub metrics: bool,
}

impl Default for Telemetry {
    fn default() -> Self {
        Telemetry {
            log_format: "text".into(),
            log_level: "info".into(),
            metrics: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminEntry {
    pub id: PrincipalId,
    pub public_key: PublicKey,
}

impl Config {
    pub fn new(data_root: PathBuf) -> Self {
        Config {
            version: CONFIG_VERSION,
            data_root,
            listen: Listen::default(),
            runtime: RuntimeSection::default(),
            storage: Storage::default(),
            extensions: Extensions::default(),
            limits: Limits::default(),
            telemetry: Telemetry::default(),
            admins: vec![],
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut c: Config =
            toml::from_str(&text).map_err(|e| format!("invalid configuration: {e}"))?;
        c.apply_env();
        Ok(c)
    }

    /// Operational overrides: `OPENAEVCD_DATA_ROOT`, `OPENAEVCD_UNIX_SOCKET`, `OPENAEVCD_TCP`,
    /// `OPENAEVCD_LOG_LEVEL`, `OPENAEVCD_LOG_FORMAT`.
    pub fn apply_env(&mut self) {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        if let Some(v) = var("OPENAEVCD_DATA_ROOT") {
            self.data_root = v.into();
        }
        if let Some(v) = var("OPENAEVCD_UNIX_SOCKET") {
            self.listen.unix_socket = Some(v.into());
        }
        if let Some(v) = var("OPENAEVCD_TCP") {
            self.listen.tcp = Some(v);
        }
        if let Some(v) = var("OPENAEVCD_LOG_LEVEL") {
            self.telemetry.log_level = v;
        }
        if let Some(v) = var("OPENAEVCD_LOG_FORMAT") {
            self.telemetry.log_format = v;
        }
    }

    pub fn unix_socket(&self) -> PathBuf {
        self.listen
            .unix_socket
            .clone()
            .unwrap_or_else(|| self.data_root.join("openaevcd.sock"))
    }

    /// Structural validation (`openaevcd check-config`).
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CONFIG_VERSION {
            return Err(format!(
                "unsupported configuration version {} (expected {CONFIG_VERSION})",
                self.version
            ));
        }
        if let Some(tcp) = &self.listen.tcp {
            let addr: SocketAddr = tcp
                .parse()
                .map_err(|_| format!("listen.tcp {tcp:?} is not host:port"))?;
            if !addr.ip().is_loopback() {
                return Err(format!("listen.tcp {tcp} is not a loopback address; remote listeners require [listen.tls] (TLS)"));
            }
        }
        if let Some(tls) = &self.listen.tls {
            tls.address
                .parse::<SocketAddr>()
                .map_err(|_| format!("listen.tls.address {:?} is not host:port", tls.address))?;
            for f in [&tls.certificate, &tls.private_key] {
                if !f.is_file() {
                    return Err(format!("TLS file {} does not exist", f.display()));
                }
            }
        }
        if !matches!(self.storage.durability.as_str(), "full" | "normal") {
            return Err("storage.durability must be \"full\" or \"normal\"".into());
        }
        if !matches!(self.telemetry.log_format.as_str(), "text" | "json") {
            return Err("telemetry.log_format must be \"text\" or \"json\"".into());
        }
        for d in &self.extensions.directories {
            if !d.is_dir() {
                return Err(format!(
                    "extension directory {} does not exist",
                    d.display()
                ));
            }
        }
        if self.admins.is_empty() {
            return Err("at least one [[admins]] entry is required to create namespaces".into());
        }
        Ok(())
    }

    /// Effective configuration with secrets redacted. The configuration holds only paths to key
    /// material, never key material; key paths are shown as-is.
    pub fn redacted_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|e| e.to_string())
    }
}
