//! Namespace authority view over a transaction (current state including staged writes).

use crate::authority::AuthorityView;
use crate::protocol::{Digest, GrantId, NamespaceId, Principal, PrincipalId, SignedGrant};

use crate::runtime::records::{self, GrantRecord};
use crate::runtime::tx::Tx;

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

    /// Only grants issued in this Namespace (`IssueCapabilityGrant`) resolve: an imported
    /// `capability_grant` object is inert data and never acts as a parent (AEVC-XCH-0003).
    fn grant(&self, digest: &Digest) -> Option<SignedGrant> {
        let g: SignedGrant = self.tx.load_object(digest).ok().flatten()?.body().ok()?;
        let rec: GrantRecord = self
            .tx
            .peek(records::GRANT, &records::key(&self.tx.ns, g.body.id))
            .ok()
            .flatten()?;
        (rec.digest == *digest).then_some(rec.grant)
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
