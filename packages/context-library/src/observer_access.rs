//! Observer verification for shared surfaces that consume the context
//! library.
//!
//! When a shared surface (a shared chat, a published artifact) has read from
//! the library, sharing that surface must never grant access to collections
//! the recipient could not already read. The library is therefore itself a
//! connector-shaped resource: kind [`CONTEXT_COLLECTION_KIND`]
//! (`context.collection`), verified with strategy B
//! ([`VerificationStrategy::SingleUnitAcl`]) — one ACL check per observed
//! collection, exactly the GitHub-repo/Google-Doc shape from the Cloudflare
//! OS observer model.
//!
//! Two layers cooperate, and the split matters:
//!
//! 1. [`record_collection_read`] runs at read time. It describes the read
//!    (kind/unit/sub-resource) to the surface's
//!    [`ObservationAuthorizer`], which audits it and applies sharing
//!    policy (exclusions, lockdown). A private collection read is normally
//!    `Allowed` here — the observation layer tracks and audits; it does not
//!    re-implement the library ACL.
//! 2. [`LibraryAccessVerifier`] runs at share/open time. The
//!    [`crate::gatekeeper::ObserverRegistry`] replays the surface's
//!    observation history and asks, per observed collection, whether the
//!    would-be observer can read it with their OWN account — via the
//!    library's existing visibility rules. A surface that observed a
//!    private collection refuses every observer but the owner.

use crate::gatekeeper::observers::AccessVerifier;
use crate::gatekeeper::{
    ObservationAuthorizer, ObservationDecision, ObservationDescription, ObserverRegistry,
    SharingPolicy, TimestampMs, VerificationStrategy,
};

use crate::context_library::collection::ContextLibrary;

/// The resource kind the context library exposes to the observer model.
/// Units of this kind are collection ids; sub-resources are document ids or
/// skill names within the collection.
pub const CONTEXT_COLLECTION_KIND: &str = "context.collection";

/// An [`ObserverRegistry`] preconfigured for the context library:
/// [`CONTEXT_COLLECTION_KIND`] is verified with strategy B
/// ([`VerificationStrategy::SingleUnitAcl`]) — one ACL check per observed
/// collection, re-run on every open.
pub fn library_observer_registry() -> ObserverRegistry {
    let mut registry = ObserverRegistry::new();
    registry.set_strategy(CONTEXT_COLLECTION_KIND, VerificationStrategy::SingleUnitAcl);
    registry
}

/// The connector-side access check for `context.collection` units: "can
/// `observer` read this collection with their own account?"
///
/// Answers via the library's existing visibility rules
/// ([`crate::context_library::collection::Collection::readable_by`], applied
/// through [`ContextLibrary::visible_to`]): public collections verify for
/// anyone, private collections only for their owner. Fails closed — an
/// unknown kind or a collection id not visible to the observer is a refusal.
pub struct LibraryAccessVerifier<'a> {
    pub library: &'a ContextLibrary,
}

impl AccessVerifier for LibraryAccessVerifier<'_> {
    fn can_read(&self, observer: &str, kind: &str, unit: &str) -> bool {
        kind == CONTEXT_COLLECTION_KIND && self.library.visible_to(observer).any(|c| c.id == unit)
    }
}

/// Describe and authorize one library read on a consuming surface, before
/// the content moves: kind [`CONTEXT_COLLECTION_KIND`], unit = the
/// collection id, sub-resource = the document id or skill name read.
///
/// Every call writes one audit record on `auth` either way. The decision
/// applies the surface's sharing posture (registered observers, exclusions,
/// lockdown) — NOT the library ACL, which is enforced at read time by
/// [`ContextLibrary::read_document`]/[`read_skill`][ContextLibrary::read_skill]
/// and re-checked per observer at share time by [`LibraryAccessVerifier`].
pub fn record_collection_read(
    auth: &mut ObservationAuthorizer,
    collection_id: &str,
    doc_or_skill: &str,
    now: TimestampMs,
) -> ObservationDecision {
    let description = ObservationDescription {
        kind: CONTEXT_COLLECTION_KIND.into(),
        unit: collection_id.into(),
        sub_resource: doc_or_skill.into(),
        summary: format!("read {doc_or_skill} from context collection {collection_id}"),
        policy: SharingPolicy::default(),
    };
    // This surface does not support per-recipient redaction of an already
    // rendered artifact, so exclusions cannot be honored here (they would
    // surface as Blocked rather than AllowedExcluding).
    auth.authorize_observation(description, false, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_library::collection::{Collection, Document, Visibility};
    use crate::gatekeeper::GatekeeperError;

    fn library() -> ContextLibrary {
        let mut lib = ContextLibrary::new();
        let mut public = Collection::new("codex", Visibility::Public, "org");
        public.put_document(Document {
            id: "reviews.md".into(),
            title: "Code review standards".into(),
            body: "Review with care.".into(),
        });
        lib.add_collection(public).unwrap();
        let mut private = Collection::new("alice-notes", Visibility::Private, "alice");
        private.put_document(Document {
            id: "draft.md".into(),
            title: "Draft".into(),
            body: "secret draft".into(),
        });
        lib.add_collection(private).unwrap();
        lib
    }

    #[test]
    fn public_collection_history_verifies_any_observer() {
        let lib = library();
        // A surface reads from the PUBLIC collection…
        let mut auth = ObservationAuthorizer::new();
        assert_eq!(
            record_collection_read(&mut auth, "codex", "reviews.md", 1),
            ObservationDecision::Allowed
        );
        // …then anyone at all verifies as an observer: public means
        // tenant-wide readable, so sharing widens nothing.
        let mut registry = library_observer_registry();
        let verifier = LibraryAccessVerifier { library: &lib };
        for observer in ["bob", "alice", "mallory"] {
            let v = registry
                .add_observer(observer, auth.observed(), &verifier, 2)
                .unwrap();
            assert_eq!(
                v.checked,
                vec![(CONTEXT_COLLECTION_KIND.to_string(), "codex".to_string())]
            );
        }
        assert_eq!(registry.verified_observers().count(), 3);
    }

    #[test]
    fn private_collection_history_refuses_non_owner() {
        let lib = library();
        // Alice's own surface reads her PRIVATE collection…
        let mut auth = ObservationAuthorizer::new();
        assert_eq!(
            record_collection_read(&mut auth, "alice-notes", "draft.md", 1),
            ObservationDecision::Allowed
        );
        // …so when the surface is shared, bob (who cannot read the
        // collection himself) fails verification and is not registered.
        let mut registry = library_observer_registry();
        let verifier = LibraryAccessVerifier { library: &lib };
        let err = registry
            .add_observer("bob", auth.observed(), &verifier, 2)
            .unwrap_err();
        assert!(matches!(
            err,
            GatekeeperError::ObserverVerificationFailed { ref observer, .. } if observer == "bob"
        ));
        assert_eq!(registry.verified_observers().count(), 0);
        // The owner still verifies fine.
        assert!(registry
            .add_observer("alice", auth.observed(), &verifier, 3)
            .is_ok());
    }

    #[test]
    fn record_collection_read_audits_without_enforcing_the_library_acl() {
        let mut auth = ObservationAuthorizer::new();
        // A registered observer plus the default sharing policy: reads are
        // Allowed — nothing excludes bob at the observation layer.
        auth.register_observer("bob").unwrap();
        assert_eq!(
            record_collection_read(&mut auth, "codex", "reviews.md", 10),
            ObservationDecision::Allowed
        );
        // Reading a PRIVATE collection unit is STILL Allowed at this layer
        // (the observation authorizer tracks and audits; it does not
        // re-implement the library ACL)…
        assert_eq!(
            record_collection_read(&mut auth, "alice-notes", "draft.md", 11),
            ObservationDecision::Allowed
        );
        // …and every read is audited with its full locator.
        assert_eq!(auth.audit_trail().len(), 2);
        let record = &auth.audit_trail()[1];
        assert_eq!(record.at, 11);
        assert_eq!(record.description.kind, CONTEXT_COLLECTION_KIND);
        assert_eq!(record.description.unit, "alice-notes");
        assert_eq!(record.description.sub_resource, "draft.md");
        assert_eq!(record.decision, ObservationDecision::Allowed);
        assert_eq!(auth.observed().len(), 2);
    }

    #[test]
    fn verifier_fails_closed_on_unknown_kind_or_collection() {
        let lib = library();
        let verifier = LibraryAccessVerifier { library: &lib };
        assert!(verifier.can_read("alice", CONTEXT_COLLECTION_KIND, "alice-notes"));
        assert!(!verifier.can_read("bob", CONTEXT_COLLECTION_KIND, "alice-notes"));
        assert!(!verifier.can_read("alice", CONTEXT_COLLECTION_KIND, "no-such-collection"));
        assert!(!verifier.can_read("alice", "github.repo", "alice-notes"));
    }
}
