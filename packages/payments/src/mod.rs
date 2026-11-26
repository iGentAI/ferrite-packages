//! payments — charging an application's own customers, inside the app model.
//!
//! A deployable Ferrite app names exactly one dependency, so this subsystem
//! travels as SOURCE. It carries the three pieces two commerce applications
//! were otherwise re-deriving: the Stripe request builders, the webhook
//! signature verifier, and the idempotent event-admission ledger a guarded
//! commit carries. It also carries the x402 header path — the machine-payment
//! gate a priced operation runs before it serves.
//!
//! # What this kit does not own
//!
//! It issues no I/O. Every builder returns an [`HttpRequest`] the host
//! delivers through ITS OWN declared egress handle, so the audited
//! destination, the scope pin and the egress audit record stay the host
//! application's. It holds no secret: keys arrive as `&str` from the caller's
//! `ctx.secret(...)`, never from a URL and never from a store row. It computes
//! no digest and no MAC of its own: [`webhook`] calls `ferrite_app::crypto`,
//! which is the platform kernel every consumer already links.
//!
//! # The correctness rules this source encodes
//!
//! These are the payments contract's discipline, restated where the code that enforces them
//! lives:
//!
//! 1. Money rows are state machines guarded by compare-and-swap. The kit
//!    supplies the bounded loop's ceiling ([`ledger::GUARD_RETRIES`]) and the
//!    admission marker ([`ledger::EventLog`]); the row image and its
//!    transitions stay application state.
//! 2. Webhook admission is idempotent by processor event id, and the marker
//!    rides the SAME committed envelope as the state it admits — see
//!    [`ledger::EventLog`], whose documentation states the networked-CAS seam
//!    a retrying committer must self-recognize through.
//! 3. Amounts are verified server-side against the app's own row:
//!    [`money::verify_amount`].
//! 4. Secrets ride `ctx.secret`. No builder here accepts a URL-embedded
//!    credential, and [`stripe::create_checkout_session`] puts the key in an
//!    `authorization` header whose VALUE the egress audit record excludes.
//! 5. No card data, ever. The only checkout shape this kit builds is hosted
//!    Stripe Checkout: the PAN never transits the application.
//! 6. Verification hygiene: a timestamp tolerance against the host's clock, a
//!    constant-time compare, and the RAW request bytes as the MAC input.
//!    [`webhook::verified_event`] is the ordering that makes the last one
//!    structural — it verifies bytes, then parses them, and the kit offers no
//!    entry point that verifies a parsed value.
//! 7. An absent signature is a refusal. [`webhook::verify`] returns
//!    `signature_missing` for an envelope carrying no `stripe-signature`,
//!    which is what a route that forgot to declare the forwarded header
//!    observes on every request.
//!
//! # Evidence class
//!
//! Everything here is proven by unit tests that travel with the source and run
//! inside every consumer. No live payment is recorded in this repository:
//! see this package's README for the per-module evidence class.

pub mod dunning;
pub mod ledger;
pub mod money;
pub mod stripe;
pub mod webhook;
pub mod x402_gate;

/// One outbound request, built but not sent.
///
/// The kit never opens a socket. A builder returns this, and the host
/// application delivers it through the egress handle its own manifest
/// declares: `ctx.egress("stripe")?.deliver_http(EgressHttpMethod::Post,
/// &r.destination, &headers, r.body.as_bytes())`, with `r.headers` mapped to
/// `EgressHeader { name, value }`. Keeping the send on the host side is
/// what preserves the properties the payments contract argues for: the destination is
/// scope-pinned by the manifest, the attempt is recorded in the egress audit
/// plane, and the header VALUES (the bearer credential among them) stay out of
/// that record.
///
/// Header names are lowercase, because that is the form the egress validator
/// admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The absolute destination URL. Never carries a credential.
    pub destination: String,
    /// The request body, already encoded for the declared content type.
    pub body: String,
    /// Lowercase request header names and their values.
    pub headers: Vec<(String, String)>,
}
