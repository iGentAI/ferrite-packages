//! **Alloy Auth** — credential-verified sessions for an Alloy application.
//!
//! Use this package when the application owns its users' password credentials.
//! Upstream has no managed Auth Cell or `ferrite auth init`; the application
//! owns its sign-in routes, tenant policy and authorization checks. This
//! package has no password-change backend; advertise only a verified custom
//! flow. See README.md and
//! packages/http-change-password/README.md for integration and checks.
//!
//! An audited mutation is only as trustworthy as the identity it records.
//! An application that reads its actor from a caller-supplied cookie has an
//! audit trail anyone can forge: `Cookie: user=ceo` is one line of `curl`.
//! This package exists so that the actor an application records is one the
//! server actually authenticated.
//!
//! # The shape
//!
//! ```text
//! store  user/{id}      -> UserRecord   the PBKDF2 credential and profile
//! store  sess/{hash}    -> SessionRecord the live session, TTL-expiring
//! ```
//!
//! - A password is verified with [`crate::crypto::password_verify`],
//!   which is PBKDF2-SHA256 with a per-record salt and a stored iteration
//!   count.
//! - A session token is 32 bytes of host entropy. What is STORED is its
//!   SHA-256, never the token itself, so a leaked store yields no usable
//!   session ([`SESSION_BYTES`]).
//! - The session key carries the store's own TTL, so expiry is enforced by
//!   storage rather than by a sweeper that might not run.
//! - The browser receives one `__Host-` prefixed, `HttpOnly`, `Secure`,
//!   `SameSite=Strict` session cookie. The CSRF token bound to that session
//!   travels in the login and identity reply BODIES, because the gateway
//!   relays one `set-cookie` per reply ([`session::login_cookies`]).
//!
//! # What this package does not do
//!
//! It provides no federation, passkeys, email delivery or account recovery.
//! It is the smallest thing that
//! makes an application's audit trail mean what it says.

#![allow(unused_imports, dead_code)]

pub mod authority;
pub mod demo;
pub mod faces;
pub mod session;
pub mod user;

/// Discovery of an app-owned password-change page; does not change credentials.
pub use crate::http_change_password as change_password;

pub use authority::{authenticate, authenticate_form, Admin, Authenticated, Role, Writer};
pub use session::{
    check_csrf, clear_cookies, csrf_cookie, csrf_cookie_name, login_cookies, session_cookie_name,
    session_key, with_csrf, Session, SessionRecord, SessionStore, CSRF_BODY_FIELD, CSRF_COOKIE,
    SESSION_BYTES, SESSION_COOKIE, SESSION_TTL_MS,
};
pub use user::{
    sign_in_attempts_key, user_key, Actor, UserRecord, UserStore, MAX_PASSWORD,
    MAX_SIGN_IN_ATTEMPTS, MIN_PASSWORD, ROLES, SIGN_IN_WINDOW_MS,
};
