//! Capability authority (spec/authority.md, spec/capabilities.md).
//!
//! Authority answers "may this principal attempt this action on this resource?". Anything not
//! allowed by a valid capability chain rooted at a Namespace root principal is denied.
//!
//! A grant is valid at time `now` when:
//! * its namespace is the view's namespace;
//! * the issuer is a registered key-bearing principal and the signature verifies in the `grant`
//!   domain with the issuer's key;
//! * `not_before <= now < expires_at`;
//! * it is not revoked;
//! * without a parent, the issuer is a Namespace root; with a parent, the parent is valid, the
//!   parent's subject is this grant's issuer, the parent has delegation depth > 0, this grant's
//!   depth is lower, it does not outlive or predate the parent, and its actions, resources and
//!   constraints are no broader than the parent's.
#![forbid(unsafe_code)]

use openaevc_crypto::{Domain, Signer};
use openaevc_protocol::{
    err, Digest, ErrorCode, GrantBody, GrantId, NamespaceId, Principal, PrincipalId, PrincipalKind,
    ProtocolError, ResourceRef, ResourceSelector, SignedGrant, Timestamp,
};

/// Maximum delegation chain length evaluated (defense against pathological chains).
pub const MAX_CHAIN: usize = 32;

/// Read access to one Namespace's authority state.
pub trait AuthorityView {
    fn namespace(&self) -> NamespaceId;
    fn roots(&self) -> &[PrincipalId];
    fn principal(&self, id: &PrincipalId) -> Option<Principal>;
    fn grant(&self, digest: &Digest) -> Option<SignedGrant>;
    fn grants_for_subject(&self, subject: &PrincipalId) -> Vec<(Digest, SignedGrant)>;
    fn is_revoked(&self, id: &GrantId) -> bool;
}

/// One authorization question.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub principal: PrincipalId,
    pub action: &'a str,
    pub resource: Option<&'a ResourceRef>,
}

/// A positive authorization decision and the facts it rests on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// Principal was a Namespace root.
    pub root: bool,
    /// Grant chain used, leaf first (empty for roots).
    pub grants: Vec<Digest>,
}

/// Signs a grant body with the issuer's key.
pub fn sign_grant(body: GrantBody, issuer: &dyn Signer) -> Result<SignedGrant, ProtocolError> {
    let msg = openaevc_canonical::to_canonical(&body)?;
    Ok(SignedGrant {
        signature: issuer.sign(Domain::Grant, &msg),
        body,
    })
}

fn verify_signature(view: &dyn AuthorityView, g: &SignedGrant) -> Result<(), ProtocolError> {
    let issuer = view.principal(&g.body.issuer).ok_or_else(|| {
        err::unauthorized(format!(
            "grant issuer {} is not a registered principal",
            g.body.issuer
        ))
    })?;
    let key = issuer.public_key.ok_or_else(|| {
        err::unauthorized(format!("grant issuer {} has no signing key", g.body.issuer))
    })?;
    let msg = openaevc_canonical::to_canonical(&g.body)?;
    openaevc_crypto::verify(&key, Domain::Grant, &msg, &g.signature)
}

/// `pattern` matches `action`: `*`, `prefix.*`, or exact.
pub fn action_matches(pattern: &str, action: &str) -> bool {
    pattern == "*"
        || pattern == action
        || pattern.strip_suffix(".*").is_some_and(|p| {
            action.len() > p.len() + 1
                && action.starts_with(p)
                && action.as_bytes()[p.len()] == b'.'
        })
}

/// Parent action pattern covers everything the child pattern allows.
pub fn action_covers(parent: &str, child: &str) -> bool {
    if parent == "*" {
        return true;
    }
    if child == "*" {
        return false;
    }
    match child.strip_suffix(".*") {
        Some(prefix) => {
            parent == child
                || parent
                    .strip_suffix(".*")
                    .is_some_and(|p| action_matches(parent, prefix) || p == prefix)
        }
        None => action_matches(parent, child),
    }
}

fn kind_matches(pattern: &str, kind: &str) -> bool {
    action_matches(pattern, kind)
}

pub fn selector_matches(s: &ResourceSelector, r: &ResourceRef) -> bool {
    kind_matches(&s.kind, &r.kind)
        && s.locator_prefix
            .as_deref()
            .is_none_or(|p| r.locator.starts_with(p))
}

/// Parent selector covers everything the child selector selects.
pub fn selector_covers(parent: &ResourceSelector, child: &ResourceSelector) -> bool {
    action_covers(&parent.kind, &child.kind)
        && match (&parent.locator_prefix, &child.locator_prefix) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(p), Some(c)) => c.starts_with(p.as_str()),
        }
}

/// Resources a grant applies to: empty selector list means every resource.
fn resources_cover(parent: &[ResourceSelector], child: &[ResourceSelector]) -> bool {
    if parent.is_empty() {
        return true;
    }
    !child.is_empty()
        && child
            .iter()
            .all(|c| parent.iter().any(|p| selector_covers(p, c)))
}

fn grant_allows(g: &GrantBody, action: &str, resource: Option<&ResourceRef>) -> bool {
    g.actions.iter().any(|a| action_matches(a, action))
        && match resource {
            // A resource-scoped grant never confers actions that are not about a resource.
            None => g.resources.is_empty(),
            Some(r) => g.resources.is_empty() || g.resources.iter().any(|s| selector_matches(s, r)),
        }
}

fn subset_violation(parent: &GrantBody, child: &GrantBody) -> Option<&'static str> {
    if parent.delegation_depth == 0 {
        return Some("parent grant does not allow delegation");
    }
    if child.delegation_depth >= parent.delegation_depth {
        return Some("delegation depth must decrease");
    }
    if child.expires_at > parent.expires_at {
        return Some("delegated grant outlives its parent");
    }
    if child.not_before < parent.not_before {
        return Some("delegated grant predates its parent");
    }
    if !child
        .actions
        .iter()
        .all(|c| parent.actions.iter().any(|p| action_covers(p, c)))
    {
        return Some("delegated actions exceed the parent grant");
    }
    if !resources_cover(&parent.resources, &child.resources) {
        return Some("delegated resources exceed the parent grant");
    }
    if !parent
        .constraints
        .iter()
        .all(|(k, v)| child.constraints.get(k) == Some(v))
    {
        return Some("delegated grant drops a parent constraint");
    }
    None
}

/// Validates a grant and its whole chain at `now`. Returns the chain digests, leaf's parent
/// first. Errors: `UNAUTHORIZED` (bad signature / unknown issuer), `CAPABILITY_EXPIRED`,
/// `CAPABILITY_REVOKED`, `FORBIDDEN` (not rooted, scope or delegation violation).
pub fn validate_grant(
    view: &dyn AuthorityView,
    now: Timestamp,
    grant: &SignedGrant,
) -> Result<Vec<Digest>, ProtocolError> {
    let mut chain = Vec::new();
    let mut current = grant.clone();
    for _ in 0..MAX_CHAIN {
        let g = &current.body;
        if g.namespace != view.namespace() {
            return Err(err::forbidden(format!(
                "grant {} belongs to another namespace",
                g.id
            )));
        }
        verify_signature(view, &current)?;
        if !g.constraints.is_empty() {
            // Protocol 0.1 enforces no constraints; honouring one would fail open.
            return Err(err::invalid(format!(
                "grant {} carries constraints, which protocol 0.1 does not enforce",
                g.id
            ))
            .with_object(g.id));
        }
        if view.is_revoked(&g.id) {
            return Err(ProtocolError::new(
                ErrorCode::CapabilityRevoked,
                format!("grant {} is revoked", g.id),
            )
            .with_object(g.id));
        }
        if now >= g.expires_at {
            return Err(ProtocolError::new(
                ErrorCode::CapabilityExpired,
                format!("grant {} expired", g.id),
            )
            .with_object(g.id));
        }
        if now < g.not_before {
            return Err(
                err::forbidden(format!("grant {} is not yet valid", g.id)).with_object(g.id)
            );
        }
        let Some(parent_digest) = g.parent else {
            if view.roots().contains(&g.issuer) {
                return Ok(chain);
            }
            return Err(err::forbidden(format!(
                "grant {} is not rooted: issuer is not a namespace root",
                g.id
            ))
            .with_object(g.id));
        };
        let parent = view
            .grant(&parent_digest)
            .ok_or_else(|| err::forbidden(format!("parent grant {parent_digest} is unknown")))?;
        if parent.body.subject != g.issuer {
            return Err(err::forbidden(format!(
                "grant {} issuer is not the subject of its parent",
                g.id
            )));
        }
        if let Some(why) = subset_violation(&parent.body, g) {
            return Err(err::forbidden(format!("grant {}: {why}", g.id)).with_object(g.id));
        }
        chain.push(parent_digest);
        current = parent;
    }
    Err(err::forbidden("delegation chain too long"))
}

/// Default-deny authorization.
pub fn authorize(
    view: &dyn AuthorityView,
    now: Timestamp,
    req: &Request<'_>,
) -> Result<Authorization, ProtocolError> {
    if view.roots().contains(&req.principal) {
        return Ok(Authorization {
            root: true,
            grants: vec![],
        });
    }
    let mut blocked: Option<ProtocolError> = None;
    for (digest, g) in view.grants_for_subject(&req.principal) {
        if !grant_allows(&g.body, req.action, req.resource) {
            continue;
        }
        match validate_grant(view, now, &g) {
            Ok(parents) => {
                let mut grants = vec![digest];
                grants.extend(parents);
                return Ok(Authorization {
                    root: false,
                    grants,
                });
            }
            Err(e) => {
                // Prefer reporting revocation/expiry over generic denial.
                let rank = |c: ErrorCode| match c {
                    ErrorCode::CapabilityRevoked => 2,
                    ErrorCode::CapabilityExpired => 1,
                    _ => 0,
                };
                if blocked.as_ref().is_none_or(|b| rank(e.code) > rank(b.code)) {
                    blocked = Some(e);
                }
            }
        }
    }
    let base = match blocked {
        Some(e)
            if matches!(
                e.code,
                ErrorCode::CapabilityRevoked | ErrorCode::CapabilityExpired
            ) =>
        {
            e
        }
        _ => err::forbidden(format!(
            "no valid capability allows {} for {}",
            req.action, req.principal
        )),
    };
    Err(base.with_missing_action(req.action))
}

/// Authorizes `action` over every resource a selector can match: some valid grant must allow
/// the action with selectors covering `scope` (a grant without selectors covers everything).
pub fn authorize_scope(
    view: &dyn AuthorityView,
    now: Timestamp,
    principal: PrincipalId,
    action: &str,
    scope: &ResourceSelector,
) -> Result<Authorization, ProtocolError> {
    if view.roots().contains(&principal) {
        return Ok(Authorization {
            root: true,
            grants: vec![],
        });
    }
    let mut blocked: Option<ProtocolError> = None;
    for (digest, g) in view.grants_for_subject(&principal) {
        let covers = g.body.actions.iter().any(|a| action_matches(a, action))
            && (g.body.resources.is_empty()
                || g.body.resources.iter().any(|s| selector_covers(s, scope)));
        if !covers {
            continue;
        }
        match validate_grant(view, now, &g) {
            Ok(parents) => {
                let mut grants = vec![digest];
                grants.extend(parents);
                return Ok(Authorization {
                    root: false,
                    grants,
                });
            }
            Err(e) => blocked = Some(e),
        }
    }
    let base = match blocked {
        Some(e)
            if matches!(
                e.code,
                ErrorCode::CapabilityRevoked | ErrorCode::CapabilityExpired
            ) =>
        {
            e
        }
        _ => err::forbidden(format!(
            "no valid capability allows {action} over {}{}",
            scope.kind,
            scope
                .locator_prefix
                .as_deref()
                .map(|p| format!(":{p}*"))
                .unwrap_or_default()
        )),
    };
    Err(base.with_missing_action(action))
}

/// Resolves the effective principal of a request: the authenticated `caller`, or the ACTOR it
/// acts as. Only key-bearing principals authenticate; an ACTOR must be linked to the caller.
pub fn resolve_caller(
    view: &dyn AuthorityView,
    caller: PrincipalId,
    act_as: Option<PrincipalId>,
) -> Result<Principal, ProtocolError> {
    let p = view
        .principal(&caller)
        .ok_or_else(|| err::unauthorized(format!("unknown principal {caller}")))?;
    if p.kind == PrincipalKind::Actor || p.public_key.is_none() {
        return Err(err::unauthorized(
            "actors cannot authenticate directly; act through the linked key principal",
        ));
    }
    let Some(actor_id) = act_as else { return Ok(p) };
    let actor = view
        .principal(&actor_id)
        .ok_or_else(|| err::forbidden(format!("unknown actor {actor_id}")))?;
    if actor.kind != PrincipalKind::Actor || actor.linked_to != Some(caller) {
        return Err(err::forbidden(format!(
            "{caller} may not act as {actor_id}"
        )));
    }
    Ok(actor)
}

/// Replay/freshness window check for request envelopes (nonce uniqueness is enforced by the
/// runtime store).
pub fn check_freshness(
    now: Timestamp,
    issued_at: Timestamp,
    expires_at: Option<Timestamp>,
    window_ms: u64,
) -> Result<(), ProtocolError> {
    let skew = issued_at.millis_until(now).unsigned_abs();
    if skew > u128::from(window_ms) {
        return Err(ProtocolError::new(
            ErrorCode::ReplayDetected,
            "request issued_at is outside the replay window",
        ));
    }
    if expires_at.is_some_and(|e| e <= now) {
        return Err(ProtocolError::new(
            ErrorCode::ReplayDetected,
            "request has expired",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
