//! Command handlers. Each handler authorizes, validates, stages state changes and emits at
//! least one journal event through the transaction; the caller commits atomically.

mod extensions;
mod graph;
mod namespace;
pub(crate) mod packs;
mod promotion;
pub(crate) use graph::{all_packs, edges, owner, wait_edges, work_status};

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
        CreateChangePack { spec } => packs::create(tx, ctx, spec),
        CreateRevisionPack {
            relation,
            targets,
            spec,
        } => packs::create_revision(tx, ctx, relation, targets, spec),
        UpdateChangePack {
            pack,
            expected_generation,
            intent,
            resource_refs,
            required_policies,
            extension_bindings,
            conflicts_with,
            metadata,
        } => packs::update(
            tx,
            ctx,
            pack,
            expected_generation,
            intent,
            resource_refs,
            required_policies,
            extension_bindings,
            conflicts_with,
            metadata,
        ),
        AddWorkUnit {
            pack,
            expected_generation,
            kind,
            spec,
            depends_on,
        } => graph::add_work_unit(tx, ctx, pack, expected_generation, kind, spec, depends_on),
        UpdateWorkUnit {
            pack,
            expected_generation,
            work_unit,
            spec,
            state,
        } => graph::update_work_unit(tx, ctx, pack, expected_generation, work_unit, spec, state),
        AddActiveDependency {
            pack,
            expected_generation,
            from,
            to,
            kind,
            annotations,
        } => graph::add_dependency(
            tx,
            ctx,
            pack,
            expected_generation,
            from,
            to,
            kind,
            annotations,
        ),
        RemoveActiveDependency {
            pack,
            expected_generation,
            from,
            to,
            kind,
        } => graph::remove_dependency(tx, ctx, pack, expected_generation, from, to, kind),
        SealChangePack {
            pack,
            expected_generation,
        } => packs::seal(tx, ctx, pack, expected_generation),
        ReopenChangePack {
            pack,
            expected_generation,
        } => packs::reopen(tx, ctx, pack, expected_generation),
        AbandonChangePack {
            pack,
            expected_generation,
        } => packs::abandon(tx, ctx, pack, expected_generation),
        QuarantineChangePack { pack, reason } => packs::quarantine(tx, ctx, pack, reason),
        ReleaseQuarantine { pack } => packs::release(tx, ctx, pack),
        PromoteChangePack { pack, generation } => promotion::promote(tx, ctx, pack, generation),
        RegisterExtension {
            entrypoint,
            artifact_digest,
            approved_host_capabilities,
        } => extensions::register(
            tx,
            ctx,
            entrypoint,
            artifact_digest,
            approved_host_capabilities,
        ),
        UnregisterExtension { extension } => extensions::unregister(tx, ctx, extension),
        RegisterProvider { provider } => extensions::register_provider(tx, ctx, provider),
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
