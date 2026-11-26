//! When a refused send is worth trying again, and how long to wait.
//!
//! Retry-After is a minimum wait, so a provider hint can extend the local
//! ladder but never shorten it. Only observed retryable statuses enter this
//! policy. Transport failures and unsettled claims remain ambiguous and must
//! not be automatically resent.

/// The duration multiplied by the next attempt number.
pub const RETRY_STEP_MS: u64 = 60_000;

/// Whether a provider status is worth another attempt.
///
/// A `429` is a rate limit and a `5xx` is the provider's own failure; both
/// pass. Every other `4xx` is a rejection of THIS request — a malformed body,
/// a bad credential, a suppressed recipient — and repeating it produces the
/// same answer while consuming the sender's reputation.
#[must_use]
pub fn is_retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

/// The wait before `next_attempt`, as a linear ladder.
///
/// The result is an OFFSET from the settling instant, which is what a
/// message-carried clock can add: a consumer schedules the retry with
/// `publish_at(now + retry_delay_ms(next_attempt))` rather than sleeping.
#[must_use]
pub fn retry_delay_ms(next_attempt: u32) -> u64 {
    RETRY_STEP_MS.saturating_mul(u64::from(next_attempt))
}

/// The provider's earliest retry instant. A missing hint leaves the local
/// ladder in force. An unreadable or conflicting hint holds retries at the
/// maximum deadline: guessing could violate an unsupported HTTP-date minimum.
/// Decimal overflow saturates instead of wrapping into an immediate retry.
#[must_use]
pub fn retry_not_before_ms(headers: &[(String, String)], observed_ms: u64) -> Option<u64> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"));
    let (_, value) = values.next()?;
    if values.next().is_some() {
        return Some(u64::MAX);
    }
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        let seconds = value.bytes().fold(0u64, |n, b| {
            n.saturating_mul(10).saturating_add(u64::from(b - b'0'))
        });
        return Some(observed_ms.saturating_add(seconds.saturating_mul(1000)));
    }
    Some(parse_http_date(value).unwrap_or(u64::MAX))
}

/// Combine the local backoff with the provider minimum.
#[must_use]
pub fn retry_due_ms(next_attempt: u32, observed_ms: u64, provider_minimum: Option<u64>) -> u64 {
    observed_ms
        .saturating_add(retry_delay_ms(next_attempt))
        .max(provider_minimum.unwrap_or(0))
}

// IMF-fixdate, the HTTP date format emitted by current providers. Reject
// malformed dates rather than normalizing an impossible day into another month.
fn parse_http_date(value: &str) -> Option<u64> {
    let parts: Vec<_> = value.split_ascii_whitespace().collect();
    let [weekday, day, month, year, time, "GMT"] = parts.as_slice() else {
        return None;
    };
    if !["Mon,", "Tue,", "Wed,", "Thu,", "Fri,", "Sat,", "Sun,"].contains(weekday) {
        return None;
    }
    let day: u64 = day.parse().ok()?;
    let year: u64 = year.parse().ok()?;
    if !(1970..=9999).contains(&year) {
        return None;
    }
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| m == month)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let lengths = [
        31u64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > *lengths.get(month)? {
        return None;
    }
    let times: Vec<_> = time.split(':').collect();
    let [hour, minute, second] = times.as_slice() else {
        return None;
    };
    let hour: u64 = hour.parse().ok()?;
    let minute: u64 = minute.parse().ok()?;
    let second: u64 = second.parse().ok()?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap_before = |y: u64| (y - 1) / 4 - (y - 1) / 100 + (y - 1) / 400;
    let days = (year - 1970) * 365 + leap_before(year) - leap_before(1970)
        + lengths.iter().take(month).sum::<u64>()
        + day
        - 1;
    Some((days * 86400 + hour * 3600 + minute * 60 + second) * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limits_and_server_faults_are_retried_and_other_rejections_are_not() {
        for status in [429u16, 500, 502, 503, 599] {
            assert!(is_retryable_status(status), "{status} should be retried");
        }
        for status in [200u16, 202, 301, 400, 401, 403, 404, 422, 600] {
            assert!(
                !is_retryable_status(status),
                "{status} should not be retried"
            );
        }
    }

    #[test]
    fn the_ladder_grows_and_never_overflows() {
        assert_eq!(retry_delay_ms(1), RETRY_STEP_MS);
        assert_eq!(retry_delay_ms(2), 2 * RETRY_STEP_MS);
        assert!(retry_delay_ms(3) > retry_delay_ms(2));
        assert_eq!(retry_delay_ms(0), 0);
        // A caller that lost its attempt counter cannot produce a panic here.
        assert!(retry_delay_ms(u32::MAX) >= retry_delay_ms(4));
    }
    #[test]
    fn provider_minimum_never_shortens_the_ladder() {
        let hint = |value: &str| retry_not_before_ms(&[("Retry-After".into(), value.into())], 1000);
        assert_eq!(retry_due_ms(2, 1000, hint("1")), 121000);
        assert_eq!(retry_due_ms(2, 1000, hint("600")), 601000);
        assert_eq!(hint("9999999999999999999999999"), Some(u64::MAX));
        assert_eq!(hint("-1"), Some(u64::MAX));
        assert_eq!(hint("1.5"), Some(u64::MAX));
        assert_eq!(hint(""), Some(u64::MAX));
        assert_eq!(hint("Wed, 21 Oct 2015 07:28:00 GMT"), Some(1445412480000));
        assert_eq!(hint("Thu, 29 Feb 2024 00:00:00 GMT"), Some(1709164800000));
        assert_eq!(hint("Wed, 29 Feb 2023 00:00:00 GMT"), Some(u64::MAX));
        assert_eq!(
            retry_not_before_ms(
                &[
                    ("retry-after".into(), "1".into()),
                    ("retry-after".into(), "600".into())
                ],
                1000
            ),
            Some(u64::MAX)
        );
        assert_eq!(retry_due_ms(2, u64::MAX - 1, None), u64::MAX);
    }
}
