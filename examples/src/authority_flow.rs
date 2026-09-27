//! Capabilities: root → alice (delegable) → bob, then revoking alice's grant cuts bob off.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use openaevc_crypto::SigningKey;
use openaevc_protocol::*;
use openaevc_sdk::{EmbeddedClient, OpenAevcClient, Session, TypedClient};

use crate::common::{key_principal, new_namespace, open_embedded};
use crate::Result;

#[derive(Debug)]
pub struct Outcome {
    pub bob_before: bool,
    pub bob_after: ErrorCode,
    pub bob_other_action: ErrorCode,
}

/// Grant valid for `[now, now + 1 day)`; a delegated grant must not outlive its parent, so both
/// use the same window.
fn body(
    ns: NamespaceId,
    issuer: PrincipalId,
    subject: PrincipalId,
    actions: &[&str],
    parent: Option<Digest>,
    depth: u32,
    now: Timestamp,
) -> GrantBody {
    GrantBody {
        id: fresh_grant_id(),
        namespace: ns,
        issuer,
        subject,
        actions: actions
            .iter()
            .map(|a| a.to_string())
            .collect::<BTreeSet<_>>(),
        resources: vec![],
        constraints: BTreeMap::new(),
        not_before: now.plus_millis(0),
        expires_at: now.plus_millis(24 * 3600 * 1000),
        delegation_depth: depth,
        parent,
        nonce: b64::encode(fresh_grant_id().as_bytes()),
    }
}

fn fresh_grant_id() -> GrantId {
    use openaevc_core::IdGeneratorExt;
    openaevc_core::UuidV7Ids::new(Arc::new(openaevc_core::SystemClock)).next()
}

pub async fn run(data_root: &Path) -> Result<Outcome> {
    let e = open_embedded(data_root, vec![])?;
    let (root, _) = new_namespace(&e).await?;
    let ns = root.session().namespace().ok_or("namespace")?;
    let (alice_key, bob_key) = (
        Arc::new(SigningKey::generate()),
        Arc::new(SigningKey::generate()),
    );
    let alice_id = root.register_principal(key_principal(&alice_key)).await?;
    let bob_id = root.register_principal(key_principal(&bob_key)).await?;
    let alice = EmbeddedClient::new(e.rt.clone(), Session::new(alice_key, alice_id, Some(ns)));
    let bob = EmbeddedClient::new(e.rt.clone(), Session::new(bob_key, bob_id, Some(ns)));
    // Root grants alice changepack actions and grant issuance, delegable one level.
    let now = Timestamp::from_unix_nanos(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i128,
    );
    let alice_grant = body(
        ns,
        root.session().principal(),
        alice_id,
        &["changepack.*", "grant.issue"],
        None,
        1,
        now,
    );
    let alice_grant_id = alice_grant.id;
    let alice_digest = root.issue_grant(alice_grant).await?;
    // Alice delegates only changepack.create to bob.
    alice
        .issue_grant(body(
            ns,
            alice_id,
            bob_id,
            &["changepack.create"],
            Some(alice_digest),
            0,
            now,
        ))
        .await?;
    let bob_before = bob.create_change_pack(PackSpec::default()).await.is_ok();
    let bob_other_action = bob
        .command(Command::RegisterPrincipal {
            principal: key_principal(&SigningKey::generate()),
        })
        .await
        .map(|_| ErrorCode::Internal)
        .unwrap_or_else(|e| e.code);
    root.command(Command::RevokeCapabilityGrant {
        grant: alice_grant_id,
        reason: Some("example".into()),
    })
    .await?;
    let bob_after = bob
        .create_change_pack(PackSpec::default())
        .await
        .map(|_| ErrorCode::Internal)
        .unwrap_or_else(|e| e.code);
    Ok(Outcome {
        bob_before,
        bob_after,
        bob_other_action,
    })
}
