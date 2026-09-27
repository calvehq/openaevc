//! Command handlers. Each handler authorizes, validates, stages state changes and emits at
//! least one journal event through the transaction; the caller commits atomically.

mod namespace;

use openaevc_protocol::{Command, CommandResult};

use crate::tx::Tx;
use crate::{Ctx, Result};

pub(crate) fn dispatch(tx: &mut Tx<'_>, ctx: &Ctx, cmd: Command) -> Result<CommandResult> {
    use Command::*;
    match cmd {
        CreateNamespace {
            root_principals,
            metadata,
        } => namespace::create(tx, ctx, root_principals, metadata),
        RegisterPrincipal { principal } => namespace::register_principal(tx, ctx, principal),
        IssueCapabilityGrant { grant } => namespace::issue_grant(tx, ctx, grant),
        RevokeCapabilityGrant { grant, reason } => namespace::revoke_grant(tx, ctx, grant, reason),
        RegisterPolicy {
            document,
            mandatory,
        } => namespace::register_policy(tx, ctx, document, mandatory),
        other => Err(openaevc_protocol::err::invalid(format!(
            "{} is not supported by this runtime build",
            other.name()
        ))),
    }
}

/// Lease sweep (implemented with the execution subsystem).
pub(crate) fn expire_leases(
    _rt: &crate::Shared,
    _ns: openaevc_protocol::NamespaceId,
) -> Result<()> {
    Ok(())
}
