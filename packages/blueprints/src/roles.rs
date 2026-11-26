//! Capability-shaped authorization: `open()` returns a different interface
//! object per role, and the restricted role fails closed.
//!
//! `Role::Build > Role::Use`. A `use` session implements the FULL surface
//! interface with a default-deny posture: every mutating method returns
//! `SessionError::Denied` until someone deliberately decides otherwise. In
//! Rust terms the roles are separate capability structs behind one trait —
//! a new trait method fails closed on the restricted implementation because
//! the compiler forces BOTH types to answer for it.

use ferrite_app::serde::{Deserialize, Serialize};

/// Collaborator roles, ordered: `Use < Build`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum Role {
    /// May use the surface: read state, run its interactions.
    Use,
    /// May modify the surface: edit code, change bindings, share further.
    Build,
}

/// Session failures.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    Denied { action: &'static str },
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { action } => write!(f, "denied: {action} requires the build role"),
        }
    }
}

impl std::error::Error for SessionError {}

/// The full session surface. Every role implements every method; the
/// restricted role denies rather than omits, so callers never learn the
/// interface shape from an authorization failure.
pub trait SurfaceSession {
    fn role(&self) -> Role;
    /// Read the surface (both roles).
    fn read(&self) -> Result<String, SessionError>;
    /// Edit the surface's code (build only).
    fn edit_code(&mut self, new_code: &str) -> Result<(), SessionError>;
    /// Change a binding (build only).
    fn rebind(&mut self, binding: &str, grant: &str) -> Result<(), SessionError>;
    /// Share further (build only).
    fn share(&mut self, with: &str) -> Result<(), SessionError>;
}

/// The unrestricted session.
#[derive(Debug, Default)]
pub struct BuildSession {
    pub code: String,
    pub bindings: Vec<(String, String)>,
    pub shares: Vec<String>,
}

impl SurfaceSession for BuildSession {
    fn role(&self) -> Role {
        Role::Build
    }

    fn read(&self) -> Result<String, SessionError> {
        Ok(self.code.clone())
    }

    fn edit_code(&mut self, new_code: &str) -> Result<(), SessionError> {
        self.code = new_code.to_string();
        Ok(())
    }

    fn rebind(&mut self, binding: &str, grant: &str) -> Result<(), SessionError> {
        self.bindings.push((binding.to_string(), grant.to_string()));
        Ok(())
    }

    fn share(&mut self, with: &str) -> Result<(), SessionError> {
        self.shares.push(with.to_string());
        Ok(())
    }
}

/// The default-deny session: the full interface, refusing every mutation.
#[derive(Debug, Default)]
pub struct UseSession {
    pub code: String,
}

impl SurfaceSession for UseSession {
    fn role(&self) -> Role {
        Role::Use
    }

    fn read(&self) -> Result<String, SessionError> {
        Ok(self.code.clone())
    }

    fn edit_code(&mut self, _new_code: &str) -> Result<(), SessionError> {
        Err(SessionError::Denied {
            action: "edit_code",
        })
    }

    fn rebind(&mut self, _binding: &str, _grant: &str) -> Result<(), SessionError> {
        Err(SessionError::Denied { action: "rebind" })
    }

    fn share(&mut self, _with: &str) -> Result<(), SessionError> {
        Err(SessionError::Denied { action: "share" })
    }
}

/// Open a session at `role`: the returned INTERFACE is the authorization.
pub fn open(role: Role, code: &str) -> Box<dyn SurfaceSession> {
    match role {
        Role::Build => Box::new(BuildSession {
            code: code.to_string(),
            ..Default::default()
        }),
        Role::Use => Box::new(UseSession {
            code: code.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sessions_hold_full_authority() {
        let mut s = open(Role::Build, "code v1");
        assert_eq!(s.read().unwrap(), "code v1");
        s.edit_code("code v2").unwrap();
        s.rebind("github", "grant-1").unwrap();
        s.share("bob").unwrap();
        assert_eq!(s.read().unwrap(), "code v2");
    }

    #[test]
    fn use_sessions_fail_closed_on_every_mutation() {
        let mut s = open(Role::Use, "code v1");
        assert_eq!(s.read().unwrap(), "code v1"); // reading is fine
        assert_eq!(
            s.edit_code("x").unwrap_err(),
            SessionError::Denied {
                action: "edit_code"
            }
        );
        assert_eq!(
            s.rebind("b", "g").unwrap_err(),
            SessionError::Denied { action: "rebind" }
        );
        assert_eq!(
            s.share("eve").unwrap_err(),
            SessionError::Denied { action: "share" }
        );
    }
}
