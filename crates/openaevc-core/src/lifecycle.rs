//! Protocol state machines (spec/changepack.md, spec/execution.md).

use openaevc_protocol::{ExecutionState, PackState, ProtocolError};

/// Canonical v1 ChangePack/RevisionPack transitions.
pub fn pack_transition_allowed(from: PackState, to: PackState) -> bool {
    use PackState::*;
    matches!(
        (from, to),
        (Open, Sealed)
            | (Sealed, Qualified)
            | (Qualified, Promoted)
            // Reopen: new generation, qualification cleared.
            | (Sealed, Open)
            | (Qualified, Open)
            // Qualification lost on refresh.
            | (Qualified, Sealed)
            | (Open | Sealed | Qualified, Abandoned)
            | (Open | Sealed | Qualified, Quarantined)
            // Release restores the previous state; abandoning a quarantined pack is allowed.
            | (Quarantined, Open | Sealed | Qualified | Abandoned)
    )
}

pub fn check_pack_transition(from: PackState, to: PackState) -> Result<(), ProtocolError> {
    if pack_transition_allowed(from, to) {
        Ok(())
    } else {
        let code = if from == PackState::Promoted {
            openaevc_protocol::ErrorCode::ImmutableObject
        } else if from == PackState::Quarantined {
            openaevc_protocol::ErrorCode::Quarantined
        } else {
            openaevc_protocol::ErrorCode::InvalidTransition
        };
        Err(ProtocolError::new(code, format!("pack cannot move from {} to {}", from.as_str(), to.as_str()))
            .with_transition(from.as_str(), to.as_str()))
    }
}

pub fn execution_transition_allowed(from: ExecutionState, to: ExecutionState) -> bool {
    use ExecutionState::*;
    matches!(
        (from, to),
        (Pending, Admitted)
            | (Admitted, Starting)
            | (Starting, Running)
            | (Running, Succeeded)
            | (Admitted | Starting | Running, Cancelled | Failed | Lost)
    )
}

pub fn check_execution_transition(from: ExecutionState, to: ExecutionState) -> Result<(), ProtocolError> {
    if execution_transition_allowed(from, to) {
        Ok(())
    } else {
        let code = if from == ExecutionState::Lost {
            openaevc_protocol::ErrorCode::ExecutionLost
        } else {
            openaevc_protocol::ErrorCode::InvalidTransition
        };
        Err(ProtocolError::new(code, format!("execution cannot move from {} to {}", from.as_str(), to.as_str()))
            .with_transition(from.as_str(), to.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaevc_protocol::{ExecutionState as E, PackState as P};

    #[test]
    fn pack_forward_path() {
        assert!(pack_transition_allowed(P::Open, P::Sealed));
        assert!(pack_transition_allowed(P::Sealed, P::Qualified));
        assert!(pack_transition_allowed(P::Qualified, P::Promoted));
        assert!(pack_transition_allowed(P::Sealed, P::Open), "reopen");
        assert!(pack_transition_allowed(P::Qualified, P::Open), "reopen");
    }

    #[test]
    fn pack_forbidden_transitions() {
        assert!(!pack_transition_allowed(P::Open, P::Promoted));
        assert!(!pack_transition_allowed(P::Open, P::Qualified));
        assert!(!pack_transition_allowed(P::Sealed, P::Promoted));
        for to in [P::Open, P::Sealed, P::Qualified, P::Abandoned, P::Quarantined] {
            assert!(!pack_transition_allowed(P::Promoted, to));
            assert!(!pack_transition_allowed(P::Abandoned, to));
        }
        assert!(!pack_transition_allowed(P::Quarantined, P::Promoted));
    }

    #[test]
    fn abandon_and_quarantine_from_active_states() {
        for from in [P::Open, P::Sealed, P::Qualified] {
            assert!(pack_transition_allowed(from, P::Abandoned));
            assert!(pack_transition_allowed(from, P::Quarantined));
        }
    }

    #[test]
    fn execution_transitions() {
        assert!(execution_transition_allowed(E::Pending, E::Admitted));
        assert!(execution_transition_allowed(E::Admitted, E::Starting));
        assert!(execution_transition_allowed(E::Starting, E::Running));
        assert!(execution_transition_allowed(E::Running, E::Succeeded));
        for from in [E::Starting, E::Running] {
            for to in [E::Cancelled, E::Failed, E::Lost] {
                assert!(execution_transition_allowed(from, to));
            }
        }
        assert!(!execution_transition_allowed(E::Lost, E::Succeeded));
        assert!(!execution_transition_allowed(E::Lost, E::Running));
        assert!(!execution_transition_allowed(E::Pending, E::Running));
        assert!(!execution_transition_allowed(E::Starting, E::Succeeded));
    }
}
