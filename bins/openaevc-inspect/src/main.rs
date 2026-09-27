//! `openaevc-inspect`: a deliberately narrow developer tool for protocol inspection. It never
//! manages workflows; it decodes, canonicalizes, hashes and verifies protocol data.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use openaevc_core::ImmutableObject;
use openaevc_protocol::{ObjectEnvelope, SUPPORTED_PROTOCOL};
use openaevc_store::{SqliteOptions, SqliteStore, Store};
use serde_json::Value;

const SCHEMA: &str = include_str!("../../../schemas/json/openaevc.schema.json");

#[derive(Parser, Debug)]
#[command(
    name = "openaevc-inspect",
    version,
    about = "Inspect OpenAEVC protocol data"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Decode canonical CBOR (strictly) and print it as JSON.
    Decode { file: PathBuf },
    /// Print canonical JSON, canonical CBOR hex and digest of a JSON document (`-` for stdin).
    Canonicalize { file: PathBuf },
    /// Digest of a canonical CBOR file, or of the canonical encoding of a JSON file.
    Digest { file: PathBuf },
    /// Verify an immutable object (canonical CBOR or JSON envelope): schema, digest, signatures.
    VerifyObject { file: PathBuf },
    /// Verify a data root's journals, objects and indexes (the daemon must be stopped).
    VerifyJournal { data_root: PathBuf },
    /// Print the JSON Schema of a protocol type (`list` for all names).
    Schema { name: String },
    /// Query a daemon's supported versions: `host:port` or `unix:/path`.
    Compatibility { endpoint: String },
}

fn read(file: &Path) -> Result<Vec<u8>, String> {
    if file.as_os_str() == "-" {
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut b).map_err(|e| e.to_string())?;
        return Ok(b);
    }
    std::fs::read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn json_value(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))
}

fn object_from(bytes: &[u8]) -> Result<ImmutableObject, String> {
    if bytes.first() == Some(&b'{') {
        let env: ObjectEnvelope = serde_json::from_value(json_value(bytes)?)
            .map_err(|e| format!("not an object envelope: {e}"))?;
        return ImmutableObject::build(env).map_err(|e| e.to_string());
    }
    ImmutableObject::from_bytes(bytes, None).map_err(|e| e.to_string())
}

fn run(cmd: Cmd) -> Result<(), String> {
    match cmd {
        Cmd::Decode { file } => {
            let v = openaevc_canonical::decode(&read(&file)?)
                .map_err(|e| format!("not canonical CBOR: {e}"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
            );
        }
        Cmd::Canonicalize { file } => {
            let v = json_value(&read(&file)?)?;
            let bytes = openaevc_canonical::encode(&v).map_err(|e| e.to_string())?;
            println!(
                "{}",
                openaevc_canonical::canonical_json(&v).map_err(|e| e.to_string())?
            );
            println!("cbor {}", hex(&bytes));
            println!("digest {}", openaevc_crypto::sha256(&bytes));
        }
        Cmd::Digest { file } => {
            let bytes = read(&file)?;
            let d = if openaevc_canonical::decode(&bytes).is_ok() {
                openaevc_crypto::sha256(&bytes)
            } else {
                let v = json_value(&bytes)
                    .map_err(|_| "file is neither canonical CBOR nor JSON".to_string())?;
                openaevc_crypto::sha256(&openaevc_canonical::encode(&v).map_err(|e| e.to_string())?)
            };
            println!("{d}");
        }
        Cmd::VerifyObject { file } => {
            let o = object_from(&read(&file)?)?;
            println!("valid {} {}", o.kind().as_str(), o.digest());
            println!(
                "namespace {} created_seq {} creator {}",
                o.envelope().namespace,
                o.envelope().created_seq,
                o.envelope().creator
            );
            println!(
                "signatures {} (all verified)",
                o.envelope().signatures.len()
            );
            for r in o.references().map_err(|e| e.to_string())? {
                println!("references {r}");
            }
        }
        Cmd::VerifyJournal { data_root } => {
            let store =
                SqliteStore::open(&data_root, SqliteOptions::default()).map_err(|e| e.message)?;
            let report = store.verify_integrity().map_err(|e| e.message)?;
            for p in &report.problems {
                println!("problem {p}");
            }
            if !report.ok() {
                return Err(format!("{} integrity problem(s)", report.problems.len()));
            }
            println!(
                "ok: {} namespace(s), {} event(s), {} object(s)",
                report.namespaces, report.events, report.objects
            );
        }
        Cmd::Schema { name } => {
            let schema: Value = serde_json::from_str(SCHEMA).map_err(|e| e.to_string())?;
            let defs = schema["$defs"]
                .as_object()
                .ok_or("schema has no definitions")?;
            if name == "list" {
                for k in defs.keys() {
                    println!("{k}");
                }
            } else {
                let def = defs
                    .get(&name)
                    .ok_or_else(|| format!("unknown type {name}; try `schema list`"))?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(def).map_err(|e| e.to_string())?
                );
            }
        }
        Cmd::Compatibility { endpoint } => {
            use openaevc_transport::client::{Endpoint, HttpClient};
            let ep = match endpoint.strip_prefix("unix:") {
                #[cfg(unix)]
                Some(path) => Endpoint::Unix(path.into()),
                #[cfg(not(unix))]
                Some(_) => return Err("Unix sockets are not supported on this platform".into()),
                None => Endpoint::Tcp(endpoint.clone()),
            };
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let info = rt
                .block_on(HttpClient::new(ep).info())
                .map_err(|e| e.to_string())?;
            println!(
                "daemon protocol {}..={}, contract {}..={}",
                info.protocol.min, info.protocol.max, info.contract.min, info.contract.max
            );
            println!(
                "implementation {} {}",
                info.implementation.name, info.implementation.version
            );
            match SUPPORTED_PROTOCOL.negotiate(&info.protocol) {
                Some(v) => println!("negotiated protocol {v}"),
                None => {
                    return Err(format!(
                        "incompatible: this tool supports {}..={}",
                        SUPPORTED_PROTOCOL.min, SUPPORTED_PROTOCOL.max
                    ))
                }
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("openaevc-inspect: {e}");
            ExitCode::FAILURE
        }
    }
}
