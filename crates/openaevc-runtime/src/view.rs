//! Namespace authority view over a transaction (current state including staged writes).

use openaevc_authority::AuthorityView;
use openaevc_protocol::{Digest, GrantId, NamespaceId, Principal, PrincipalId, SignedGrant};

use crate::records::{self, GrantRecord};
use crate::tx::Tx;

pub(crate) struct NsView<'t, 'a> {
    pub tx: &'t Tx<'a>,
    pub roots: Vec<PrincipalId>,
}

impl AuthorityView for NsView<'_, '_> {
    fn namespace(&self) -> NamespaceId {
        self.tx.ns
    }

    fn roots(&self) -> &[PrincipalId] {
        &self.roots
    }

    fn principal(&self, id: &PrincipalId) -> Option<Principal> {
        self.tx
            .peek(records::PRINCIPAL, &records::key(&self.tx.ns, id))
            .ok()
            .flatten()
    }

    fn grant(&self, digest: &Digest) -> Option<SignedGrant> {
        self.tx
            .load_object(digest)
            .ok()
            .flatten()
            .and_then(|o| o.body().ok())
    }

    fn grants_for_subject(&self, subject: &PrincipalId) -> Vec<(Digest, SignedGrant)> {
        // ponytail: linear scan over the Namespace's grants; add a subject index if grant counts grow large.
        self.tx
            .peek_list::<GrantRecord>(records::GRANT, &records::prefix(&self.tx.ns))
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, g)| &g.grant.body.subject == subject)
            .map(|(_, g)| (g.digest, g.grant))
            .collect()
    }

    fn is_revoked(&self, id: &GrantId) -> bool {
        self.tx
            .peek::<GrantRecord>(records::GRANT, &records::key(&self.tx.ns, id))
            .ok()
            .flatten()
            .is_some_and(|g| g.revoked)
    }
}
