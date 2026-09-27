//! `openaevc-conformance`: runs the conformance suite and writes JSON / JUnit reports.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use openaevc_conformance::{extension_target, Profile, Report, Target};
use openaevc_crypto::SigningKey;
use openaevc_protocol::PrincipalId;
use openaevc_transport::client::Endpoint;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TargetKind {
    /// The reference runtime inside this process (SQLite store in a temporary directory).
    InProcess,
    /// A runtime serving the v1 HTTP transport (`--endpoint`, `--admin-key`).
    Remote,
    /// An extension executable (`--extension`).
    Extension,
}

#[derive(Parser, Debug)]
#[command(
    name = "openaevc-conformance",
    version,
    about = "OpenAEVC conformance suite"
)]
struct Cli {
    /// CORE, AUTHORITY, RUNTIME, EXTENSION_HOST or FULL.
    #[arg(long, default_value = "FULL", value_parser = |s: &str| Profile::parse(s).ok_or(format!("unknown profile {s}")))]
    profile: Profile,
    #[arg(long, value_enum, default_value = "in-process")]
    target: TargetKind,
    /// `host:port`, or `unix:/path/to/socket`.
    #[arg(long)]
    endpoint: Option<String>,
    /// Admin key file written by `openaevcd init --admin-key-out` (JSON: id, seed).
    #[arg(long)]
    admin_key: Option<PathBuf>,
    /// Local extension directory (the same one the target runtime is configured with).
    #[arg(long)]
    extensions: Option<PathBuf>,
    /// Extension executable for `--target extension`.
    #[arg(long)]
    extension: Option<PathBuf>,
    /// The remote runtime's journal checkpoint interval.
    #[arg(long, default_value_t = 1000)]
    checkpoint_interval: u64,
    /// Run only cases whose ID contains this text.
    #[arg(long)]
    filter: Option<String>,
    #[arg(long)]
    report_json: Option<PathBuf>,
    #[arg(long)]
    junit: Option<PathBuf>,
}

fn admin(path: &PathBuf) -> Result<(Arc<SigningKey>, PrincipalId), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("admin key file is not JSON: {e}"))?;
    let id: PrincipalId = v["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or("admin key file has no valid id")?;
    let seed = v["seed"].as_str().ok_or("admin key file has no seed")?;
    let bytes: Vec<u8> = (0..seed.len())
        .step_by(2)
        .filter_map(|i| {
            seed.get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect();
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "admin seed must be 32 hex-encoded bytes")?;
    Ok((Arc::new(SigningKey::from_seed(seed)), id))
}

async fn report(cli: Cli) -> Result<Report, String> {
    let filter = cli.filter.as_deref();
    Ok(match cli.target {
        TargetKind::Extension => {
            let path = cli
                .extension
                .ok_or("--target extension requires --extension <executable>")?;
            tokio::task::spawn_blocking(move || extension_target::check(&path))
                .await
                .map_err(|e| e.to_string())?
        }
        TargetKind::InProcess => {
            let t = Target::in_process(cli.extensions, true).map_err(|e| e.to_string())?;
            openaevc_conformance::run(t, cli.profile, filter).await
        }
        TargetKind::Remote => {
            let ep = cli.endpoint.ok_or("--target remote requires --endpoint")?;
            let ep = match ep.strip_prefix("unix:") {
                #[cfg(unix)]
                Some(p) => Endpoint::Unix(p.into()),
                #[cfg(not(unix))]
                Some(_) => return Err("Unix sockets are not supported on this platform".into()),
                None => Endpoint::Tcp(ep),
            };
            let (key, id) = admin(
                cli.admin_key
                    .as_ref()
                    .ok_or("--target remote requires --admin-key")?,
            )?;
            let t = Target::remote(ep, key, id, cli.extensions, cli.checkpoint_interval);
            openaevc_conformance::run(t, cli.profile, filter).await
        }
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let (json, junit) = (cli.report_json.clone(), cli.junit.clone());
    let r = match report(cli).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("openaevc-conformance: {e}");
            return ExitCode::from(2);
        }
    };
    println!("{}", r.summary());
    for (path, body) in [(json, r.json()), (junit, r.junit())] {
        if let Some(p) = path {
            if let Err(e) = std::fs::write(&p, body) {
                eprintln!("openaevc-conformance: cannot write {}: {e}", p.display());
                return ExitCode::from(2);
            }
        }
    }
    if r.conformant() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
