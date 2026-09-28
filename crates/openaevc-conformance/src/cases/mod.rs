//! Case registry. Each case lists the requirement IDs it verifies.

mod authority;
mod core;
mod extension;
mod full;
mod runtime;

use crate::{Case, CaseFuture, Ctx, Profile};

macro_rules! registry {
    ($( $id:literal, $profile:ident, [$($req:literal),* $(,)?], $f:path; )*) => {
        /// All registered cases, in execution order.
        pub fn all() -> Vec<Case> {
            vec![$({
                fn run<'a>(cx: &'a Ctx) -> CaseFuture<'a> {
                    Box::pin($f(cx))
                }
                Case { id: $id, profile: Profile::$profile, requirements: &[$($req),*], run }
            }),*]
        }
    };
}

registry! {
    "core.objects.round_trip", Core, ["AEVC-OBJ-0001", "AEVC-ID-0003", "AEVC-ID-0004", "AEVC-ENC-0004", "AEVC-XCH-0004"], core::objects_round_trip;
    "core.objects.invalid_rejected", Core, ["AEVC-OBJ-0002", "AEVC-OBJ-0003", "AEVC-OBJ-0006", "AEVC-ENC-0005", "AEVC-ENC-0007", "AEVC-XCH-0002", "AEVC-VER-0004", "AEVC-ID-0008"], core::objects_invalid_rejected;
    "core.objects.signature_identity", Core, ["AEVC-OBJ-0001", "AEVC-OBJ-0002", "AEVC-OBJ-0006"], core::signature_identity;
    "core.envelope.data_model", Core, ["AEVC-ENC-0001", "AEVC-ENC-0002", "AEVC-ENC-0003"], core::envelope_data_model;
    "core.envelope.key_order", Core, ["AEVC-ENC-0008"], core::key_order;
    "core.text.byte_exact", Core, ["AEVC-ENC-0006"], core::text_byte_exact;
    "core.identifiers", Core, ["AEVC-ID-0001", "AEVC-ID-0002"], core::identifiers;
    "core.signatures", Core, ["AEVC-ID-0005", "AEVC-ID-0006"], core::signatures;
    "core.errors", Core, ["AEVC-ERR-0001", "AEVC-ERR-0002", "AEVC-ERR-0003"], core::errors;
    "core.versioning", Core, ["AEVC-VER-0001", "AEVC-VER-0002", "AEVC-VER-0003"], core::versioning;
    "core.ordering_and_timestamps", Core, ["AEVC-ID-0007"], core::ordering;

    "authority.unauthenticated", Authority, ["AEVC-AUTH-0001"], authority::unauthenticated;
    "authority.act_as", Authority, ["AEVC-AUTH-0002"], authority::act_as;
    "authority.default_deny", Authority, ["AEVC-AUTH-0003"], authority::default_deny;
    "authority.every_entry_point", Authority, ["AEVC-AUTH-0004", "AEVC-TRN-0001"], authority::every_entry_point;
    "authority.replay", Authority, ["AEVC-AUTH-0005"], authority::replay;
    "authority.idempotency", Authority, ["AEVC-AUTH-0006"], authority::idempotency;
    "authority.denial_audit", Authority, ["AEVC-AUTH-0007"], authority::denial_audit;
    "capability.validity", Authority, ["AEVC-CAP-0001"], authority::grant_validity;
    "capability.rooted", Authority, ["AEVC-CAP-0002"], authority::rooted;
    "capability.delegation", Authority, ["AEVC-CAP-0003"], authority::delegation;
    "capability.issuer_submits", Authority, ["AEVC-CAP-0004"], authority::issuer_submits;
    "capability.revocation", Authority, ["AEVC-CAP-0005"], authority::revocation;
    "capability.constraints", Authority, ["AEVC-CAP-0006"], authority::constraints;
    "capability.resource_scoped", Authority, ["AEVC-CAP-0007"], authority::resource_scoped;
    "namespace.isolation", Authority, ["AEVC-NS-0001", "AEVC-NS-0002", "AEVC-NS-0003", "AEVC-NS-0004"], authority::namespaces;

    "lifecycle.generations", Runtime, ["AEVC-LIFE-0001"], runtime::generations;
    "lifecycle.sealing", Runtime, ["AEVC-LIFE-0002", "AEVC-LIFE-0003"], runtime::sealing;
    "lifecycle.reopen_invalidates", Runtime, ["AEVC-LIFE-0004", "AEVC-EVD-0002", "AEVC-VRF-0003"], runtime::reopen_invalidates;
    "lifecycle.terminal", Runtime, ["AEVC-LIFE-0005", "AEVC-PRO-0003"], runtime::terminal;
    "lifecycle.quarantine", Runtime, ["AEVC-LIFE-0006"], runtime::quarantine;
    "lifecycle.promotion_requires_qualification", Runtime, ["AEVC-LIFE-0007"], runtime::requires_qualification;
    "graph.dependencies", Runtime, ["AEVC-ACG-0001", "AEVC-ACG-0002", "AEVC-ACG-0003"], runtime::graph;
    "execution.admission", Runtime, ["AEVC-EXE-0001", "AEVC-EXE-0003"], runtime::admission;
    "execution.scope_authority", Runtime, ["AEVC-EXE-0002", "AEVC-EXE-0007"], runtime::scope_authority;
    "execution.worker_rules", Runtime, ["AEVC-EXE-0004"], runtime::worker_rules;
    "execution.provider_ownership", Runtime, ["AEVC-EXE-0009"], runtime::provider_ownership;
    "execution.lost", Runtime, ["AEVC-EXE-0005", "AEVC-EXE-0006"], runtime::lost;
    "execution.effects_and_provenance", Runtime, ["AEVC-EXE-0008", "AEVC-OBS-0001", "AEVC-OBS-0002"], runtime::effects;
    "evidence.binding", Runtime, ["AEVC-EVD-0001"], runtime::evidence;
    "verification.results", Runtime, ["AEVC-VRF-0001", "AEVC-VRF-0002", "AEVC-VRF-0004", "AEVC-VRF-0005"], runtime::verification;
    "evaluation.results", Runtime, ["AEVC-EVL-0001", "AEVC-EVL-0002"], runtime::evaluation;
    "policy.gates", Runtime, ["AEVC-POL-0001", "AEVC-POL-0002", "AEVC-POL-0003", "AEVC-POL-0004", "AEVC-POL-0005", "AEVC-POL-0006"], runtime::policy;
    "promotion.transaction", Runtime, ["AEVC-PRO-0001", "AEVC-PRO-0002", "AEVC-PRO-0004"], runtime::promotion;
    "revision.history", Runtime, ["AEVC-REV-0001", "AEVC-REV-0002", "AEVC-REV-0003"], runtime::revisions;
    "baseline.immutability", Runtime, ["AEVC-BSL-0001", "AEVC-BSL-0002", "AEVC-BSL-0003"], runtime::baselines;
    "composition.rules", Runtime, ["AEVC-CMP-0001", "AEVC-CMP-0002", "AEVC-CMP-0003", "AEVC-CMP-0004", "AEVC-CMP-0005"], runtime::composition;
    "events.journal", Runtime, ["AEVC-EVT-0001", "AEVC-EVT-0002", "AEVC-EVT-0003", "AEVC-EVT-0004", "AEVC-EVT-0005"], runtime::events;
    "transport.semantics", Runtime, ["AEVC-TRN-0002", "AEVC-TRN-0003", "AEVC-TRN-0004", "AEVC-TRN-0005"], runtime::transport;

    "extension.confinement", ExtensionHost, ["AEVC-EXT-0001"], extension::confinement;
    "extension.pinning", ExtensionHost, ["AEVC-EXT-0002"], extension::pinning;
    "extension.kinds", ExtensionHost, ["AEVC-EXT-0004", "AEVC-EXT-0010"], extension::kinds;
    "extension.kind_conflicts", ExtensionHost, ["AEVC-EXT-0003"], extension::kind_conflicts;
    "extension.upgrades", ExtensionHost, ["AEVC-EXT-0010"], extension::upgrades;
    "extension.unsupported_capabilities", ExtensionHost, ["AEVC-EXT-0004", "AEVC-EXT-0009"], extension::unsupported_capabilities;
    "extension.capabilities", ExtensionHost, ["AEVC-EXT-0005"], extension::capabilities;
    "extension.limits", ExtensionHost, ["AEVC-EXT-0006"], extension::limits;
    "extension.environment", ExtensionHost, ["AEVC-EXT-0007"], extension::environment;
    "extension.reverification", ExtensionHost, ["AEVC-EXT-0008"], extension::reverification;

    "full.recovery", Full, ["AEVC-REC-0001", "AEVC-REC-0002", "AEVC-REC-0003", "AEVC-REC-0004"], full::recovery;
    "full.exchange", Full, ["AEVC-XCH-0001", "AEVC-OBJ-0004", "AEVC-OBJ-0005", "AEVC-BSL-0003"], full::exchange;
    "full.inert_imports", Full, ["AEVC-XCH-0003", "AEVC-BSL-0002"], full::inert_imports;
}
