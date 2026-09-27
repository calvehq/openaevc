//! Promotion (spec/promotion.md).

use openaevc_protocol::{err, CommandResult, ErrorCode, PackId, PackState, ProtocolError};

use super::packs;
use crate::tx::Tx;
use crate::{authz, Ctx, Result};

pub(crate) fn promote(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: PackId,
    generation: u64,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.promote", None)?;
    let p = packs::load(tx, id)?;
    match p.state {
        PackState::Qualified => {}
        PackState::Open | PackState::Sealed => {
            return Err(ProtocolError::new(
                ErrorCode::NotQualified,
                format!("pack {id} is {} and not qualified", p.state.as_str()),
            )
            .with_object(id));
        }
        _ => return Err(packs::state_error(&p, "promote")),
    }
    packs::check_generation(&p, generation)?;
    Err(err::internal(
        "promotion transaction lands with the promotion subsystem",
    ))
}
