//! `OPENAEVC_ENDPOINT=127.0.0.1:7878 OPENAEVC_ADMIN_KEY=admin.json cargo run -p openaevc-examples --example daemon-client`
//!
//! Connects to a running `openaevcd` (see `openaevcd init --admin-key-out`), negotiates the
//! protocol version and creates a Namespace.

use std::sync::Arc;

use openaevc::crypto::{Signer, SigningKey};
use openaevc::protocol::*;
use openaevc::transport::client::Endpoint;
use openaevc_sdk::{RemoteClient, Session, TypedClient};

#[tokio::main]
async fn main() -> openaevc_examples::Result<()> {
    let endpoint = std::env::var("OPENAEVC_ENDPOINT")
        .map_err(|_| "set OPENAEVC_ENDPOINT (host:port or unix:/path)")?;
    let admin: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(std::env::var(
        "OPENAEVC_ADMIN_KEY",
    )?)?)?;
    let seed = admin["seed"].as_str().ok_or("admin seed")?;
    let seed: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&seed[2 * i..2 * i + 2], 16))
        .collect::<Result<_, _>>()?;
    let key = Arc::new(SigningKey::from_seed(
        seed.try_into().map_err(|_| "seed length")?,
    ));
    let ep = match endpoint.strip_prefix("unix:") {
        #[cfg(unix)]
        Some(p) => Endpoint::Unix(p.into()),
        _ => Endpoint::Tcp(endpoint.clone()),
    };
    let client = RemoteClient::connect(
        ep,
        Session::new(key, admin["id"].as_str().ok_or("admin id")?.parse()?, None),
    )
    .await?;
    println!("daemon speaks protocol {}", client.protocol_version());
    let root = SigningKey::generate();
    let (ns, roots) = client
        .create_namespace(vec![NewPrincipal {
            kind: PrincipalKind::Key,
            public_key: Some(root.public_key()),
            linked_to: None,
            attributes: Default::default(),
        }])
        .await?;
    println!("created namespace {ns} with root {}", roots[0]);
    Ok(())
}
