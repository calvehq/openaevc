//! Namespace, principal, capability-grant and policy commands.

use openaevc_core::names;
use openaevc_core::IdGeneratorExt;
use openaevc_protocol::{
    err, CommandResult, GrantId, Metadata, Namespace, NewPrincipal, ObjectKind, PolicyDocument,
    Principal, PrincipalId, PrincipalKind, Revocation, SignedGrant,
};
use serde_json::json;

use crate::records::{self, GrantRecord};
use crate::tx::Tx;
use crate::view::NsView;
use crate::{authz, Ctx, Result};

fn validate_new_principal(tx: &Tx<'_>, p: &NewPrincipal) -> Result<()> {
    names::validate_keys(&p.attributes)?;
    match p.kind {
        PrincipalKind::Actor => {
            if p.public_key.is_some() {
                return Err(err::invalid("ACTOR principals do not have keys"));
            }
            let linked = p.linked_to.ok_or_else(|| {
                err::invalid("ACTOR principals must be linked to a key principal")
            })?;
            let target: Principal = tx
                .peek(records::PRINCIPAL, &records::key(&tx.ns, linked))?
                .ok_or_else(|| err::not_found(format!("linked principal {linked} not found")))?;
            if target.public_key.is_none() {
                return Err(err::invalid("ACTOR must link to a key-bearing principal"));
            }
        }
        _ => {
            if p.public_key.is_none() || p.linked_to.is_some() {
                return Err(err::invalid(
                    "KEY/RUNTIME/SERVICE principals need a public key and no link",
                ));
            }
        }
    }
    Ok(())
}

fn store_principal(tx: &mut Tx<'_>, p: NewPrincipal) -> Result<PrincipalId> {
    let id: PrincipalId = tx.rt.ids.next();
    let principal = Principal {
        id,
        namespace: tx.ns,
        kind: p.kind,
        public_key: p.public_key,
        linked_to: p.linked_to,
        attributes: p.attributes,
        registered_at: tx.now,
    };
    tx.put(records::PRINCIPAL, &records::key(&tx.ns, id), &principal)?;
    tx.emit(
        "principal.registered",
        json!({"principal": principal}),
        vec![id.to_string()],
    );
    Ok(id)
}

pub(crate) fn create(
    tx: &mut Tx<'_>,
    _ctx: &Ctx,
    roots: Vec<NewPrincipal>,
    metadata: Metadata,
) -> Result<CommandResult> {
    names::validate_keys(&metadata)?;
    if roots.is_empty() {
        return Err(err::invalid(
            "a namespace needs at least one root principal",
        ));
    }
    if roots.iter().any(|p| p.kind == PrincipalKind::Actor) {
        return Err(err::invalid("root principals must be key-bearing"));
    }
    let ns = tx.ns;
    let mut ids = Vec::new();
    // Emit namespace.created first so it is sequence 1.
    tx.emit("namespace.created", json!({}), vec![ns.to_string()]);
    for p in roots {
        validate_new_principal(tx, &p)?;
        ids.push(store_principal(tx, p)?);
    }
    let namespace = Namespace {
        id: ns,
        created_at: tx.now,
        created_by: tx.creator,
        root_principals: ids.clone(),
        mandatory_policies: vec![],
        metadata,
    };
    tx.put(records::NAMESPACE, &ns.to_string(), &namespace)?;
    Ok(CommandResult {
        id: Some(ns.to_string()),
        ids: ids.iter().map(ToString::to_string).collect(),
        ..Default::default()
    })
}

pub(crate) fn register_principal(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    p: NewPrincipal,
) -> Result<CommandResult> {
    authz(tx, ctx, "principal.register", None)?;
    validate_new_principal(tx, &p)?;
    let id = store_principal(tx, p)?;
    Ok(CommandResult {
        id: Some(id.to_string()),
        ..Default::default()
    })
}

pub(crate) fn issue_grant(tx: &mut Tx<'_>, ctx: &Ctx, grant: SignedGrant) -> Result<CommandResult> {
    authz(tx, ctx, "grant.issue", None)?;
    let g = &grant.body;
    if g.issuer != ctx.principal {
        return Err(err::forbidden("a grant must be submitted by its issuer"));
    }
    if g.namespace != tx.ns {
        return Err(err::invalid(
            "grant namespace does not match the request namespace",
        ));
    }
    if g.actions.is_empty() || g.expires_at <= g.not_before {
        return Err(err::invalid(
            "grant needs at least one action and a non-empty validity window",
        ));
    }
    names::validate_keys(&g.constraints)?;
    if tx
        .peek::<GrantRecord>(records::GRANT, &records::key(&tx.ns, g.id))?
        .is_some()
    {
        return Err(err::exists(format!("grant {} already exists", g.id)));
    }
    if tx
        .peek::<Principal>(records::PRINCIPAL, &records::key(&tx.ns, g.subject))?
        .is_none()
    {
        return Err(err::not_found(format!(
            "grant subject {} not found",
            g.subject
        )));
    }
    let view = NsView {
        tx,
        roots: ctx.roots.clone(),
    };
    openaevc_authority::validate_grant(&view, tx.now, &grant)?;
    let obj = tx.object(
        ObjectKind::CapabilityGrant,
        Some(g.id.to_string()),
        &grant,
        false,
    )?;
    let (id, subject) = (g.id, g.subject);
    tx.put(
        records::GRANT,
        &records::key(&tx.ns, id),
        &GrantRecord {
            digest: obj.digest(),
            grant,
            revoked: false,
        },
    )?;
    tx.emit(
        "grant.issued",
        json!({"grant": id, "digest": obj.digest(), "subject": subject}),
        vec![
            id.to_string(),
            subject.to_string(),
            obj.digest().to_string(),
        ],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        digest: Some(obj.digest()),
        ..Default::default()
    })
}

pub(crate) fn revoke_grant(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    grant: GrantId,
    reason: Option<String>,
) -> Result<CommandResult> {
    authz(tx, ctx, "grant.revoke", None)?;
    let key = records::key(&tx.ns, grant);
    let mut rec: GrantRecord = tx.require(records::GRANT, &key, "grant")?;
    if rec.grant.body.issuer != ctx.principal && !ctx.roots.contains(&ctx.principal) {
        return Err(
            err::forbidden("only the issuer or a namespace root may revoke a grant")
                .with_missing_action("grant.revoke"),
        );
    }
    if rec.revoked {
        return Err(err::exists(format!("grant {grant} is already revoked")));
    }
    let revocation = Revocation {
        grant,
        grant_digest: rec.digest,
        revoked_by: ctx.principal,
        revoked_at: tx.now,
        reason,
    };
    let obj = tx.object(ObjectKind::Revocation, None, &revocation, false)?;
    rec.revoked = true;
    tx.put(records::GRANT, &key, &rec)?;
    tx.emit(
        "grant.revoked",
        json!({"grant": grant, "revocation": obj.digest()}),
        vec![grant.to_string(), rec.digest.to_string()],
    );
    Ok(CommandResult {
        id: Some(grant.to_string()),
        digest: Some(obj.digest()),
        ..Default::default()
    })
}

pub(crate) fn register_policy(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    doc: PolicyDocument,
    mandatory: bool,
) -> Result<CommandResult> {
    authz(tx, ctx, "policy.register", None)?;
    openaevc_policy::validate(&doc)?;
    let content = openaevc_crypto::digest_of(&doc)?;
    let pkey = records::key(&tx.ns, content);
    let digest = match tx.get::<openaevc_protocol::Digest>(records::POLICY, &pkey)? {
        Some(d) => d,
        None => {
            let obj = tx.object(ObjectKind::PolicyDocument, None, &doc, false)?;
            tx.put(records::POLICY, &pkey, &obj.digest())?;
            obj.digest()
        }
    };
    if mandatory {
        let nkey = tx.ns.to_string();
        let mut namespace: Namespace = tx.require(records::NAMESPACE, &nkey, "namespace")?;
        if !namespace.mandatory_policies.contains(&digest) {
            namespace.mandatory_policies.push(digest);
            tx.put(records::NAMESPACE, &nkey, &namespace)?;
        }
    }
    tx.emit(
        "policy.registered",
        json!({"policy": digest, "name": doc.name, "mandatory": mandatory}),
        vec![digest.to_string()],
    );
    Ok(CommandResult {
        digest: Some(digest),
        ..Default::default()
    })
}
