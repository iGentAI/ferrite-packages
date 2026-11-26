//! **Authority as a type.**
//!
//! An audit trail whose actor comes from a caller-supplied cookie is forgeable:
//! `Cookie: tracker_user=ceo` is one line of `curl`. A convention that every
//! action goes through one authenticating helper does not prevent that, because
//! a new action added anywhere else would compile.
//!
//! This module makes that impossible. [`Authenticated<R>`] carries a private
//! [`Seal`](seal::Seal), so a value of it can only be produced by
//! [`authenticate`] — which performs all three checks. A handler that takes
//! `Authenticated<Writer>` is therefore holding PROOF the checks ran, and a
//! handler that forgets them has no way to obtain the argument it needs.
//!
//! # Why module privacy is enough here
//!
//! `ferrite-pkg` composes this package INTO the consuming application's own
//! crate, so Alloy and application code share one crate and Rust's `pub(crate)`
//! would not help. Ordinary module privacy does: `seal::Seal` is private to
//! `crate::alloy_auth::authority`, and carries a private field so the type
//! cannot be constructed even where it can be named.
//!
//! # The precise guarantee, and its edge
//!
//! Rust grants a module access to its ANCESTORS' private items, so a module
//! written *inside* `crate::alloy_auth::authority` could reach the seal. No
//! application module is: an app's own code lives at `crate::serve`,
//! `crate::actions`, `crate::model` — all siblings of `alloy_auth`, none of
//! them descendants of this module. So the guarantee this type provides is
//! that **no application module can forge an authority**, which is exactly
//! the failure it exists to prevent. Forging one would mean editing the
//! framework package's own module tree, which is a visible change to the
//! vendored source that `ferrite-pkg check` compares against its package.

use core::marker::PhantomData;

use crate::alloy::error::{AlloyError, Result};
use crate::alloy_auth::session::{check_csrf, SessionStore};
use crate::alloy_auth::user::{Actor, UserStore};

/// The seal. Private to this module, and unconstructable even when named.
mod seal {
    /// A zero-sized witness that the authority checks ran.
    ///
    /// The field is private to THIS module, so naming the type is not
    /// enough to build one: a struct literal needs the field, and only
    /// `seal` can write it. That is what makes the witness meaningful
    /// rather than decorative.
    #[derive(Debug)]
    pub struct Seal(());

    impl Seal {
        /// Mint a seal. Reachable only from this module's parent, which is
        /// where the session, CSRF and role checks actually run.
        pub(super) fn new() -> Self {
            Seal(())
        }
    }
}

/// What a role demands of an actor.
///
/// Implemented only for the marker types below, so the set of authorities an
/// application can require is closed and reviewable.
pub trait Role {
    /// How this role is spelled in an error or a log line.
    const NAME: &'static str;

    /// Refuse an actor that does not hold it.
    fn check(actor: &Actor) -> Result<()>;
}

/// An actor permitted to change state.
///
/// Uninhabited deliberately: it is a type-level tag, never a value, so it
/// cannot be constructed and passed around as though it were authority.
pub enum Writer {}

/// An actor permitted to perform administrative control.
pub enum Admin {}

impl Role for Writer {
    /// The name of the AUTHORITY LEVEL, which is deliberately not one of the
    /// stored roles.
    ///
    /// `"writer"` is not a value [`crate::alloy_auth::user::ROLES`] accepts —
    /// those are `admin`, `member` and `viewer`. `Writer` means "any actor
    /// that is not a viewer", so both `admin` and `member` satisfy it.
    ///
    /// Passing `"writer"` to `create_if_absent` is refused, and because that
    /// refusal usually happens inside `seed()`, the app boots half-seeded
    /// with only a warning in the log. If a sign-in fails for a user you
    /// believe you created, check the role you stored first.
    const NAME: &'static str = "writer";

    fn check(actor: &Actor) -> Result<()> {
        actor.require_writer()
    }
}

impl Role for Admin {
    const NAME: &'static str = "admin";

    fn check(actor: &Actor) -> Result<()> {
        actor.require_role("admin")
    }
}

/// Proof that a request carried a verified session, a matching CSRF token,
/// and an actor holding `R`.
///
/// The only way to obtain one is [`authenticate`]. An application handler
/// that names this type in its signature cannot be reached without the
/// checks having run, which is what turns "we always remember to call
/// `require_writer`" into something the compiler enforces.
#[derive(Debug)]
pub struct Authenticated<R> {
    actor: Actor,
    _role: PhantomData<R>,
    _seal: seal::Seal,
}

impl<R> Authenticated<R> {
    /// The only constructor; private, so the checks in [`authenticate`] and
    /// [`authenticate_form`] cannot be skipped.
    fn sealed(actor: Actor) -> Self {
        Self {
            actor,
            _role: PhantomData,
            _seal: seal::Seal::new(),
        }
    }

    /// The verified actor.
    ///
    /// This identity came from a session the server opened after checking a
    /// password, so an audit entry recording it means what it says.
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The verified actor's id, which is what an audit trail records.
    pub fn id(&self) -> &str {
        &self.actor.id
    }
}

impl Authenticated<Admin> {
    /// Spend admin authority where writer authority is required.
    ///
    /// Roles nest rather than partition: an administrator doing ordinary
    /// work must not need a second account. This is explicit rather than a
    /// blanket `From`, so the widening is visible at the call site.
    pub fn relax(self) -> Authenticated<Writer> {
        Authenticated::sealed(self.actor)
    }
}

/// Resolve a request's session, verify its CSRF token, and check its role.
///
/// This is the ONE constructor. The order is deliberate:
///
/// 1. **Authenticate.** An absent or expired session is `401`, never an
///    anonymous write.
/// 2. **Verify CSRF.** A cross-site POST can make a browser send the session
///    cookie; it cannot make the browser READ that cookie to construct the
///    matching header.
/// 3. **Check the role.** A viewer that can mutate is not a viewer.
///
/// Doing them here rather than in each handler is what makes it impossible
/// for a new action to forget one.
pub async fn authenticate<R: Role>(
    sessions: &mut SessionStore,
    users: &mut UserStore,
    headers: &[(String, String)],
    now_ms: u64,
) -> Result<Authenticated<R>> {
    let session = sessions
        .resolve(users, headers, now_ms)
        .await?
        .ok_or(AlloyError::Unauthorized)?;
    check_csrf(&session, headers)?;
    R::check(&session.actor)?;
    Ok(Authenticated::sealed(session.actor))
}

/// [`authenticate`], accepting the CSRF token from a form body as well as
/// from the header.
///
/// Use this when the app's UI is a server-rendered `<form>`: a form cannot
/// set a header, so [`authenticate`] refuses every signed-in visitor with
/// `Forbidden`. See [`crate::alloy_auth::session::check_csrf_with_body`] for
/// why a body field is as safe as a header here.
pub async fn authenticate_form<R: Role>(
    sessions: &mut SessionStore,
    users: &mut UserStore,
    headers: &[(String, String)],
    body: &[u8],
    now_ms: u64,
) -> Result<Authenticated<R>> {
    let session = sessions
        .resolve(users, headers, now_ms)
        .await?
        .ok_or(AlloyError::Unauthorized)?;
    crate::alloy_auth::session::check_csrf_with_body(&session, headers, body)?;
    R::check(&session.actor)?;
    Ok(Authenticated::sealed(session.actor))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor(role: &str) -> Actor {
        Actor {
            id: "u".into(),
            name: "U".into(),
            role: role.to_string(),
        }
    }

    #[test]
    fn a_viewer_holds_neither_authority() {
        let viewer = actor("viewer");
        assert!(Writer::check(&viewer).is_err());
        assert!(Admin::check(&viewer).is_err());
    }

    #[test]
    fn a_member_writes_but_does_not_administer() {
        let member = actor("member");
        assert!(Writer::check(&member).is_ok());
        assert!(Admin::check(&member).is_err());
    }

    #[test]
    fn an_admin_holds_both_because_roles_nest() {
        // An administrator needing a second account to do ordinary work is a
        // system people work around, and the workaround is a shared login.
        let admin = actor("admin");
        assert!(Writer::check(&admin).is_ok());
        assert!(Admin::check(&admin).is_ok());
    }

    #[test]
    fn admin_authority_relaxes_to_writer_carrying_the_same_actor() {
        // Constructed HERE, inside the module that owns the seal — which is
        // exactly the point: no application module can write this literal.
        let admin: Authenticated<Admin> = Authenticated {
            actor: actor("admin"),
            _role: PhantomData,
            _seal: seal::Seal::new(),
        };
        assert_eq!(admin.id(), "u");
        let writer = admin.relax();
        assert_eq!(writer.actor().role, "admin");
        assert_eq!(writer.id(), "u");
    }
}
