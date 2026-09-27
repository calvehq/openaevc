//! `openaevcd`: the OpenAEVC reference runtime daemon.
//!
//! Operational infrastructure exposing the runtime's command/query/event surface over a local
//! Unix socket, optional loopback TCP, and TLS for remote access. It is not a product daemon.
#![forbid(unsafe_code)]

mod config;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use openaevc_core::{IdGeneratorExt, SystemClock, UuidV7Ids};
use openaevc_crypto::{Signer, SigningKey};
use openaevc_protocol::PrincipalId;
use openaevc_runtime::{Admin, Runtime, RuntimeConfig, RuntimeDeps};
use openaevc_store::{Durability, SqliteOptions, SqliteStore};
use openaevc_transport::server::{self, Health, Listener, ServerConfig};
use tokio::sync::watch;

use crate::config::{AdminEntry, Config};

#[derive(Parser, Debug)]
#[command(
    name = "openaevcd",
    version,
    about = "OpenAEVC reference runtime daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Initialize a data root: schema, runtime signing key, and optionally a config file and an
    /// administrator key. Never overwrites an existing runtime key.
    Init {
        #[arg(long)]
        data_root: PathBuf,
        #[arg(long)]
        config_out: Option<PathBuf>,
        /// Generate an administrator key (JSON {id, seed}) and list it in the written config.
        #[arg(long)]
        admin_key_out: Option<PathBuf>,
    },
    /// Run the daemon.
    Run {
        #[arg(long, env = "OPENAEVCD_CONFIG")]
        config: PathBuf,
        /// Apply pending data-root schema migrations before starting.
        #[arg(long)]
        migrate: bool,
    },
    /// Validate a configuration file and exit.
    CheckConfig {
        #[arg(long, env = "OPENAEVCD_CONFIG")]
        config: PathBuf,
    },
    /// Print the effective configuration (file + environment overrides), secrets redacted.
    PrintEffectiveConfig {
        #[arg(long, env = "OPENAEVCD_CONFIG")]
        config: PathBuf,
    },
    /// Remove bytes no Namespace indexes (crash leftovers, abandoned uploads) older than the
    /// grace period. Accepted history is never removed. Run with the daemon stopped.
    Gc {
        #[arg(long, env = "OPENAEVCD_CONFIG")]
        config: PathBuf,
        #[arg(long, default_value_t = 3600)]
        grace_seconds: u64,
    },
}

fn key_dir(root: &Path) -> PathBuf {
    root.join("runtime-key")
}

fn write_private(path: &Path, contents: &str) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err("key file must contain 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| "key file is not hex".to_string())?;
    }
    Ok(out)
}

fn init(
    data_root: &Path,
    config_out: Option<&Path>,
    admin_out: Option<&Path>,
) -> Result<(), String> {
    let kd = key_dir(data_root);
    if kd.join("ed25519.seed").exists() {
        return Err(format!(
            "data root {} is already initialized",
            data_root.display()
        ));
    }
    std::fs::create_dir_all(&kd).map_err(|e| e.to_string())?;
    drop(SqliteStore::open(data_root, SqliteOptions::create()).map_err(|e| e.message)?);
    let ids = UuidV7Ids::new(Arc::new(SystemClock));
    let key = SigningKey::generate();
    write_private(&kd.join("ed25519.seed"), &hex(&key.seed()))?;
    let principal: PrincipalId = ids.next();
    std::fs::write(kd.join("principal"), principal.to_string()).map_err(|e| e.to_string())?;
    println!(
        "initialized {} (runtime key {})",
        data_root.display(),
        key.public_key()
    );
    let mut config = Config::new(data_root.to_path_buf());
    if let Some(path) = admin_out {
        let admin = SigningKey::generate();
        let id: PrincipalId = ids.next();
        let doc = serde_json::json!({"id": id, "seed": hex(&admin.seed()), "public_key": admin.public_key()});
        write_private(
            path,
            &serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
        )?;
        config.admins.push(AdminEntry {
            id,
            public_key: admin.public_key(),
        });
        println!("administrator {id} written to {}", path.display());
    }
    if let Some(path) = config_out {
        let text = config.redacted_toml()?;
        std::fs::write(
            path,
            format!(
                "# openaevcd configuration (version {})\n{text}",
                config::CONFIG_VERSION
            ),
        )
        .map_err(|e| e.to_string())?;
        println!("configuration written to {}", path.display());
    }
    Ok(())
}

fn init_logging(c: &Config) {
    let filter = tracing_subscriber::EnvFilter::try_new(&c.telemetry.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if c.telemetry.log_format == "json" {
        let _ = builder.json().try_init();
    } else {
        let _ = builder.try_init();
    }
}

fn load_tls(t: &config::Tls) -> Result<tokio_rustls::TlsAcceptor, String> {
    use rustls_pki_types::pem::PemObject;
    let chain = rustls_pki_types::CertificateDer::pem_file_iter(&t.certificate)
        .map_err(|e| format!("cannot read {}: {e}", t.certificate.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid certificate: {e}"))?;
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(&t.private_key)
        .map_err(|e| format!("invalid private key: {e}"))?;
    server::tls_acceptor(chain, key).map_err(|e| e.message)
}

async fn run(config: Config, migrate: bool) -> Result<(), String> {
    config.validate()?;
    let kd = key_dir(&config.data_root);
    let seed = std::fs::read_to_string(kd.join("ed25519.seed")).map_err(|_| {
        format!(
            "data root {} has no runtime key; run `openaevcd init --data-root {}` first",
            config.data_root.display(),
            config.data_root.display()
        )
    })?;
    let key = SigningKey::from_seed(unhex32(&seed)?);
    let runtime_principal: PrincipalId = std::fs::read_to_string(kd.join("principal"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "runtime principal file is corrupt".to_string())?;
    let opts = SqliteOptions {
        create: false,
        migrate: migrate || config.storage.auto_migrate,
        inline_threshold: config.storage.inline_threshold,
        durability: if config.storage.durability == "normal" {
            Durability::Normal
        } else {
            Durability::Full
        },
    };
    let store = SqliteStore::open(&config.data_root, opts).map_err(|e| e.message)?;
    let clock = Arc::new(SystemClock);
    let rt_config = RuntimeConfig {
        admins: config
            .admins
            .iter()
            .map(|a| Admin {
                id: a.id,
                public_key: a.public_key,
            })
            .collect(),
        replay_window_ms: config.runtime.replay_window_ms,
        checkpoint_interval: config.runtime.checkpoint_interval,
        audit_denials: config.runtime.audit_denials,
        lease_ms: config.runtime.lease_ms,
        heartbeat_interval_ms: config.runtime.heartbeat_interval_ms,
        extension_dirs: config.extensions.directories.clone(),
        extension_deadline_ms: config.extensions.deadline_ms,
        max_extension_frame: config.extensions.max_frame_bytes,
        max_page: config.runtime.max_page,
    };
    let public_key = key.public_key();
    let rt = tokio::task::spawn_blocking(move || {
        Runtime::open(
            RuntimeDeps {
                store: Arc::new(store),
                clock: clock.clone(),
                ids: Arc::new(UuidV7Ids::new(clock)),
                signer: Arc::new(key),
                runtime_principal,
            },
            rt_config,
        )
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.message)?;
    let rt = Arc::new(rt);
    tracing::info!(event = "daemon.started", runtime_key = %public_key, instance = %rt.info().runtime_instance);

    let (stop_tx, stop_rx) = watch::channel(false);
    let health = Arc::new(Health::new(stop_rx.clone()));
    let scfg = ServerConfig {
        max_request_bytes: config.limits.max_request_bytes,
        request_timeout: Duration::from_millis(config.limits.request_timeout_ms),
        event_buffer: config.limits.event_buffer,
        slow_consumer_timeout: Duration::from_millis(config.limits.slow_consumer_timeout_ms),
        shutdown_grace: Duration::from_millis(config.limits.shutdown_grace_ms),
    };
    let app = server::router(rt.clone(), scfg, health.clone());
    let mut servers = Vec::new();
    #[cfg(unix)]
    {
        let path = config.unix_socket();
        if path.exists() {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Err(format!(
                    "socket {} is in use by another daemon",
                    path.display()
                ));
            }
            let _ = std::fs::remove_file(&path);
        }
        let l = tokio::net::UnixListener::bind(&path)
            .map_err(|e| format!("cannot bind {}: {e}", path.display()))?;
        println!("listening unix {}", path.display());
        servers.push(tokio::spawn(server::serve(
            Listener::Unix(l),
            app.clone(),
            stop_rx.clone(),
        )));
    }
    if let Some(tcp) = &config.listen.tcp {
        let l = tokio::net::TcpListener::bind(tcp)
            .await
            .map_err(|e| format!("cannot bind {tcp}: {e}"))?;
        let addr = l.local_addr().map_err(|e| e.to_string())?;
        println!("listening tcp {addr}");
        tracing::info!(event = "daemon.listening", transport = "tcp", address = %addr);
        servers.push(tokio::spawn(server::serve(
            Listener::Tcp(l),
            app.clone(),
            stop_rx.clone(),
        )));
    }
    if let Some(tls) = &config.listen.tls {
        let acceptor = load_tls(tls)?;
        let l = tokio::net::TcpListener::bind(&tls.address)
            .await
            .map_err(|e| format!("cannot bind {}: {e}", tls.address))?;
        let addr = l.local_addr().map_err(|e| e.to_string())?;
        println!("listening tls {addr}");
        tracing::info!(event = "daemon.listening", transport = "tls", address = %addr);
        servers.push(tokio::spawn(server::serve(
            Listener::Tls(l, acceptor),
            app.clone(),
            stop_rx.clone(),
        )));
    }
    health.set_ready(true);

    // Lease expiry and other maintenance.
    let ticker_rt = rt.clone();
    let mut ticker_stop = stop_rx.clone();
    let tick = Duration::from_millis(config.limits.tick_interval_ms.max(100));
    let ticker = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tick) => {
                    let r = ticker_rt.clone();
                    if let Ok(Err(e)) = tokio::task::spawn_blocking(move || r.tick()).await {
                        tracing::warn!(event = "daemon.tick_failed", error = %e);
                    }
                }
                _ = ticker_stop.changed() => break,
            }
        }
    });

    wait_for_signal().await;
    tracing::info!(event = "daemon.stopping");
    health.set_ready(false);
    let _ = stop_tx.send(true);
    for s in servers {
        let _ = s.await;
    }
    let _ = ticker.await;
    #[cfg(unix)]
    let _ = std::fs::remove_file(config.unix_socket());
    tracing::info!(event = "daemon.stopped");
    Ok(())
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Init {
            data_root,
            config_out,
            admin_key_out,
        } => init(&data_root, config_out.as_deref(), admin_key_out.as_deref()),
        Cmd::CheckConfig { config } => Config::load(&config)
            .and_then(|c| c.validate())
            .map(|_| println!("configuration is valid")),
        Cmd::PrintEffectiveConfig { config } => Config::load(&config)
            .and_then(|c| c.redacted_toml())
            .map(|t| print!("{t}")),
        Cmd::Gc {
            config,
            grace_seconds,
        } => Config::load(&config).and_then(|c| {
            let store =
                SqliteStore::open(&c.data_root, SqliteOptions::default()).map_err(|e| e.message)?;
            let r = store
                .collect_garbage(Duration::from_secs(grace_seconds))
                .map_err(|e| e.message)?;
            println!("gc: scanned {}, removed {}", r.scanned, r.removed);
            Ok(())
        }),
        Cmd::Run { config, migrate } => Config::load(&config).and_then(|c| {
            init_logging(&c);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(run(c, migrate))
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("openaevcd: {e}");
            ExitCode::FAILURE
        }
    }
}
