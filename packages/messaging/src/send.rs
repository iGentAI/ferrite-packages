//! The one seam where a built request becomes a network call.
//!
//! Everything else in this kit is pure. This module is the exception, and it
//! is one call of `ferrite_app::EgressHandle::deliver_http`: the handle
//! arrives from the CALLER, which opened it from the egress binding its own
//! manifest declares. That is what keeps the destination scope-pinned, the
//! attempt recorded in the application's egress audit plane, and the
//! credential — which rides a header — out of that record.
//!
//! The platform's egress reply carries a status and a body and no headers, so
//! a provider's `retry-after` is not visible here and the local retry ladder
//! (`retry::retry_due_ms` with no provider minimum) stands alone. A
//! rate-limited provider may therefore be retried earlier than it asked; the
//! ladder's floor is what bounds that.
//!
//! # Why the two failure kinds are distinguishable
//!
//! A send ledger has to tell a POLICY refusal from a transport failure: the
//! first is a deployment misconfiguration an operator fixes, and the second is
//! an ambiguous outcome that cannot establish whether the provider accepted. `EgressOutcome::Denied`
//! therefore becomes an [`std::io::ErrorKind::PermissionDenied`] error, and a
//! transport failure keeps whatever kind the SDK reported. A consumer that
//! does not care matches neither and treats both as "not delivered".
//!
//! Retries use only the provider response, never a guessed result after a
//! transport failure.

use ferrite_app::{EgressHandle, EgressHeader, EgressHttpMethod, EgressOutcome};
use std::io;

use super::ProviderRequest;

/// The provider status and body: everything the platform's egress reply
/// carries. There is no header field because there are no headers to put in
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderResponse {
    /// The provider's HTTP status.
    pub status: u16,
    /// The provider's response body, verbatim.
    pub body: Vec<u8>,
}

impl ProviderResponse {
    /// Whether the provider accepted the send (a `2xx`).
    ///
    /// Acceptance is not delivery: a provider that answers `202` has taken
    /// custody of the message, and a bounce is a later, separate event.
    #[must_use]
    pub fn accepted(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Deliver one built request through the caller's egress handle.
///
/// A policy denial is reported as [`std::io::ErrorKind::PermissionDenied`]; a
/// transport failure propagates unchanged. Nothing here retries: a retry that
/// re-issues the provider call can send a second message, so the decision
/// belongs to the consumer's ledger, which knows whether the first attempt was
/// observed.
pub async fn deliver(
    egress: &mut EgressHandle,
    request: &ProviderRequest,
) -> io::Result<ProviderResponse> {
    let headers: Vec<EgressHeader> = request
        .headers
        .iter()
        .map(|(name, value)| EgressHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect();
    let outcome = egress
        .deliver_http(
            EgressHttpMethod::Post,
            &request.destination,
            &headers,
            &request.body,
        )
        .await?;
    match outcome {
        EgressOutcome::Delivered { status, body } => Ok(ProviderResponse { status, body }),
        EgressOutcome::Denied { reason } => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("egress denied: {reason}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderResponse;

    #[test]
    fn acceptance_is_the_two_hundred_class_and_nothing_else() {
        for status in [200u16, 201, 202, 299] {
            assert!(ProviderResponse {
                status,
                body: Vec::new(),
            }
            .accepted());
        }
        for status in [199u16, 300, 400, 429, 500] {
            assert!(!ProviderResponse {
                status,
                body: Vec::new(),
            }
            .accepted());
        }
    }
}
