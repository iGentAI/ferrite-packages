//! Money quantities, on the platform's own anchor.
//!
//! Two units appear in a payments integration and confusing them is a real
//! defect class, so both are named here:
//!
//! * **minor units** — what a processor's wire format carries. Stripe's
//!   `unit_amount` and `amount_total` are integer minor units (pence, cents),
//!   and every builder in [`super::stripe`] speaks them.
//! * **micros** — 1,000,000 per major unit, the anchor the platform's own
//!   billing core uses (`usd_minor_to_micros` in `ferrite-billing`). x402
//!   prices are quoted in micros, and USDC's six decimals make one micro one
//!   atomic unit.
//!
//! Nothing here is currency-aware beyond checking the shape of a code: a kit
//! that guessed at exponents would be wrong for the three-decimal currencies
//! and silently wrong for the zero-decimal ones. Callers that need a
//! non-two-decimal currency convert on their own side, and
//! [`verify_amount`] compares like with like because both sides are the
//! processor's own minor units.

/// Micros per major currency unit. 1,000,000 micros is 1.00.
pub const MICROS_PER_UNIT: u64 = 1_000_000;

/// Minor units per major unit for a two-decimal currency (GBP, USD, EUR).
pub const MINOR_UNITS_PER_UNIT: u64 = 100;

/// Micros per minor unit of a two-decimal currency.
pub const MICROS_PER_MINOR_UNIT: u64 = MICROS_PER_UNIT / MINOR_UNITS_PER_UNIT;

/// Convert two-decimal minor units to micros. Exact and total: saturating
/// rather than wrapping, because a wrapped price is a charge.
#[must_use]
pub fn minor_to_micros(minor: u64) -> u64 {
    minor.saturating_mul(MICROS_PER_MINOR_UNIT)
}

/// Convert micros to two-decimal minor units, truncating toward zero.
///
/// Truncation is deliberate and is the safe direction for a payee-side
/// conversion: a price quoted in micros that does not land on a whole minor
/// unit rounds DOWN, so the customer is never charged a fraction the quote did
/// not name. Use [`micros_are_whole_minor_units`] when the loss must be a
/// refusal instead of a rounding.
#[must_use]
pub fn micros_to_minor(micros: u64) -> u64 {
    micros / MICROS_PER_MINOR_UNIT
}

/// Does this micro amount land exactly on a two-decimal minor unit?
#[must_use]
pub fn micros_are_whole_minor_units(micros: u64) -> bool {
    micros.is_multiple_of(MICROS_PER_MINOR_UNIT)
}

/// Is this the shape of an ISO 4217 code? Three ASCII letters, any case.
///
/// A shape check, not a registry: the kit does not carry a currency table, and
/// pretending to validate against one would be a claim it cannot keep.
#[must_use]
pub fn is_currency_code(code: &str) -> bool {
    code.len() == 3 && code.bytes().all(|b| b.is_ascii_alphabetic())
}

/// The verdict of a server-side amount check.
///
/// Contract rule 3: amounts are verified against the application's OWN row, never
/// trusted from the payload. The third arm exists because that rule meets a
/// wire fact — a processor event need not carry the totals, and a kit that
/// collapsed "absent" into "matched" would report a check it never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountCheck {
    /// The presented amount and currency both match the application's row.
    Verified,
    /// The event carried no amount, or no currency, so nothing was compared.
    /// A caller that requires certainty re-reads the payment object through an
    /// outbound GET rather than treating this as acceptance.
    Unverifiable,
    /// The presented amount or currency contradicts the application's row.
    /// Always a refusal.
    Mismatch,
}

/// Compare a processor-presented total against the amount the application
/// itself committed.
///
/// Both sides are the processor's minor units. The currency comparison is
/// ASCII case-insensitive because Stripe answers lowercase codes and most
/// application rows hold them uppercase.
#[must_use]
pub fn verify_amount(
    expected_minor: u64,
    expected_currency: &str,
    presented_minor: Option<u64>,
    presented_currency: Option<&str>,
) -> AmountCheck {
    // Any field that IS present and contradicts the row is a mismatch, even
    // when its partner is absent: absence only ever downgrades agreement.
    if presented_minor.is_some_and(|minor| minor != expected_minor)
        || presented_currency.is_some_and(|currency| !currency.eq_ignore_ascii_case(expected_currency))
    {
        return AmountCheck::Mismatch;
    }
    match (presented_minor, presented_currency) {
        (Some(_), Some(_)) => AmountCheck::Verified,
        _ => AmountCheck::Unverifiable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_micros_anchor_matches_the_platform_billing_convention() {
        // ferrite-billing's `usd_minor_to_micros`: 1.00 is 1,000,000 micros.
        assert_eq!(minor_to_micros(100), MICROS_PER_UNIT);
        assert_eq!(minor_to_micros(1), 10_000);
        assert_eq!(micros_to_minor(MICROS_PER_UNIT), 100);
        assert!(micros_are_whole_minor_units(10_000));
        assert!(!micros_are_whole_minor_units(9_999));
    }

    #[test]
    fn minor_conversion_saturates_rather_than_wrapping() {
        // A wrapped price is a charge, so the overflow direction is pinned.
        assert_eq!(minor_to_micros(u64::MAX), u64::MAX);
    }

    #[test]
    fn micros_truncate_toward_zero_so_a_customer_is_never_over_charged() {
        assert_eq!(micros_to_minor(19_999), 1);
        assert_eq!(micros_to_minor(0), 0);
    }

    #[test]
    fn currency_codes_are_checked_for_shape_only() {
        assert!(is_currency_code("gbp"));
        assert!(is_currency_code("USD"));
        assert!(!is_currency_code("gb"));
        assert!(!is_currency_code("gbpx"));
        assert!(!is_currency_code("g8p"));
    }

    #[test]
    fn an_amount_check_separates_absence_from_agreement() {
        assert_eq!(
            verify_amount(11_990, "gbp", Some(11_990), Some("GBP")),
            AmountCheck::Verified
        );
        assert_eq!(
            verify_amount(11_990, "gbp", Some(1), Some("gbp")),
            AmountCheck::Mismatch
        );
        assert_eq!(
            verify_amount(11_990, "gbp", Some(11_990), Some("usd")),
            AmountCheck::Mismatch
        );
        // Absence is NOT agreement: a kit that returned `Verified` here would
        // report a comparison it never made.
        assert_eq!(
            verify_amount(11_990, "gbp", None, Some("gbp")),
            AmountCheck::Unverifiable
        );
        assert_eq!(
            verify_amount(11_990, "gbp", Some(11_990), None),
            AmountCheck::Unverifiable
        );
    }

    #[test]
    fn a_present_field_that_contradicts_is_a_mismatch_even_alone() {
        assert_eq!(verify_amount(11_990, "gbp", Some(0), None), AmountCheck::Mismatch);
        assert_eq!(verify_amount(11_990, "gbp", None, Some("usd")), AmountCheck::Mismatch);
        assert_eq!(verify_amount(11_990, "gbp", Some(11_990), None), AmountCheck::Unverifiable);
        assert_eq!(verify_amount(11_990, "gbp", None, Some("GBP")), AmountCheck::Unverifiable);
        assert_eq!(verify_amount(11_990, "gbp", None, None), AmountCheck::Unverifiable);
        assert_eq!(verify_amount(11_990, "gbp", Some(11_990), Some("GBP")), AmountCheck::Verified);
    }
}
