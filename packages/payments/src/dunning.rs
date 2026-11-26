//! Dunning: the retry schedule for a failed or unpaid charge.
//!
//! # The backoff is FIXED, and that is a platform residue, not a preference
//!
//! A processor that answers `429` states when to come back, in `Retry-After`.
//! A constrained Ferrite application cannot read it. The wire carries the
//! capability — `EgressRequest::DeliverWithResponseHeaders` exists, and the
//! gateway client's `validate_response_header_allowlist` admits exactly
//! `content-type`, `retry-after` and `location` — but no `EgressHandle` method
//! issues that variant, and `EgressOutcome::Delivered.headers` documents itself
//! as "empty for legacy delivery". So an application receives a status and a
//! body, and nothing else.
//!
//! That is the payments contract's acceptance criterion 7, unmet, and its residue
//! is the recorded egress-response-visibility gap. Until an SDK method
//! issues the header-bearing variant, a schedule here would have to GUESS a
//! processor's own answer. This module does not guess: it advances a fixed
//! ladder, and every consumer of it is honest about doing so.
//!
//! When egress response visibility lands, the change is local — read `retry-after` off the outcome
//! and prefer it over [`delay_for_attempt`] when it is present and shorter than
//! the ladder's own ceiling. Nothing else here moves.
//!
//! # Evidence class
//!
//! Unit-proven. No Ferrite application runs a dunning schedule today, so
//! nothing here is exercised against a live processor, and the kit's README
//! records that.

/// The fixed ladder, in milliseconds after the failed attempt: one minute,
/// five minutes, half an hour, two hours, then a day.
///
/// Five rungs spanning just over a day, because the failures worth retrying at
/// all are a rate limit, a transient network fault and a temporarily declined
/// card, and none of them is helped by a sixth attempt. The ladder is a
/// constant rather than a computed exponential so that an operator reading a
/// row's `attempts` can say when the next attempt is due without running the
/// code.
pub const ATTEMPT_DELAYS_MS: [u64; 5] = [
    60_000,     // 1 minute
    300_000,    // 5 minutes
    1_800_000,  // 30 minutes
    7_200_000,  // 2 hours
    86_400_000, // 24 hours
];

/// How many failed attempts the ladder schedules a retry after. A charge is
/// exhausted once a failed attempt has no rung left: past this number.
pub const MAX_ATTEMPTS: u32 = ATTEMPT_DELAYS_MS.len() as u32;

/// The delay after failed attempt number `attempt` (1-based).
///
/// `None` once the ladder is exhausted, which is the signal to stop retrying
/// and surface the failure to a person. `attempt = 0` also answers `None`: a
/// charge that has not been attempted is not being retried.
#[must_use]
pub fn delay_for_attempt(attempt: u32) -> Option<u64> {
    if attempt == 0 {
        return None;
    }
    ATTEMPT_DELAYS_MS.get((attempt - 1) as usize).copied()
}

/// The absolute epoch-ms deadline the next attempt is due at, given the host's
/// clock. `None` when the ladder is exhausted.
#[must_use]
pub fn next_attempt_at_ms(attempt: u32, now_ms: u64) -> Option<u64> {
    delay_for_attempt(attempt).map(|delay| now_ms.saturating_add(delay))
}

/// Has this charge run out of attempts?
#[must_use]
pub fn is_exhausted(attempt: u32) -> bool {
    // Exactly when `delay_for_attempt` has no rung: attempt 5 still has its 24-hour
    // retry, and reporting it exhausted while scheduling that retry contradicted itself.
    attempt > MAX_ATTEMPTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_is_fixed_and_strictly_increasing() {
        // Fixed, because no `EgressHandle` method reads `Retry-After` yet.
        assert_eq!(delay_for_attempt(1), Some(60_000));
        assert_eq!(delay_for_attempt(5), Some(86_400_000));
        for pair in ATTEMPT_DELAYS_MS.windows(2) {
            assert!(pair[1] > pair[0], "the ladder must not go backwards");
        }
    }

    #[test]
    fn the_ladder_ends_rather_than_retrying_forever() {
        assert_eq!(delay_for_attempt(0), None);
        assert_eq!(delay_for_attempt(MAX_ATTEMPTS + 1), None);
        assert_eq!(next_attempt_at_ms(MAX_ATTEMPTS + 1, 1_000), None);
        // finding_8aecc21edfae12ee: exhausted exactly when no rung is left.
        for attempt in 1..=MAX_ATTEMPTS + 2 {
            assert_eq!(is_exhausted(attempt), delay_for_attempt(attempt).is_none(), "{attempt}");
        }
    }

    #[test]
    fn a_due_time_is_absolute_and_saturates_rather_than_wrapping() {
        assert_eq!(next_attempt_at_ms(2, 1_000_000), Some(1_300_000));
        assert_eq!(next_attempt_at_ms(1, u64::MAX), Some(u64::MAX));
    }
}
