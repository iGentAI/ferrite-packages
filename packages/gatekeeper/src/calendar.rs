//! Calendar-expression validation and next-fire evaluation over UTC and
//! fixed-offset timezones.
//!
//! `CalendarAt` schedules carry a 5-field cron expression and a MANDATORY
//! timezone. This module validates both at registration and computes the
//! next fire instant with hand-rolled proleptic-Gregorian civil math —
//! no clock is read; every instant is a parameter.
//!
//! # Recorded delta: no IANA zones, no DST evaluation
//!
//! A constrained Ferrite app has no tzdata and may link exactly one crate, so
//! THIS module accepts only:
//!
//! * `"UTC"`, and
//! * fixed offsets `"+HH:MM"` / `"-HH:MM"` (e.g. `"+02:00"`, `"-05:30"`),
//!   within `-14:00..=+14:00`.
//!
//! IANA zone names are refused at registration, loudly. A deployment that
//! needs DST-correct wall-clock schedules supplies the offset per-schedule
//! and re-registers (or updates) the schedule when its civil zone changes
//! offset; under a fixed offset every local time exists exactly once, so
//! there are no DST gaps or ambiguities to resolve here.
//!
//! # Day fields follow standard cron
//!
//! As in Vixie/POSIX cron, when BOTH day-of-month and day-of-week are
//! restricted a day matches if EITHER does (`0 9 1 * 1` is 09:00 on the 1st
//! and on every Monday); when either is `*` the other alone decides.
//!
//! # Bounded evaluation
//!
//! Expressions are length-capped and step values must fit their field, and
//! `next_fire_after` walks an eight-year window (one full leap cycle,
//! including a skipped century leap year, so `0 0 29 2 *` always finds its
//! next instant) a day at a time, examining hours and minutes only on days
//! whose date fields match — a spec that never matches costs a few thousand
//! day checks, not millions of minute probes. A deserialized spec is
//! re-validated against the same bounds `parse` enforces.

use ferrite_app::serde::{Deserialize, Serialize};

use crate::gatekeeper::{GatekeeperError, TimestampMs};

/// Longest cron expression accepted.
pub const MAX_EXPRESSION_LEN: usize = 256;

/// How far ahead `next_fire_after` searches: eight years, which covers the
/// longest gap between two February 29ths (2096 to 2104, because 2100 is not
/// a leap year).
pub const SEARCH_HORIZON_DAYS: i64 = 8 * 366;

/// One parsed cron field: `*` or a set of allowed values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub enum CronField {
    Any,
    Values(Vec<u32>),
}

impl CronField {
    fn matches(&self, v: u32) -> bool {
        match self {
            CronField::Any => true,
            CronField::Values(vals) => vals.contains(&v),
        }
    }
}

/// A validated 5-field cron expression (minute hour day-of-month month
/// day-of-week) with its timezone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", try_from = "CalendarSpecWire")]
pub struct CalendarSpec {
    pub minute: CronField,
    pub hour: CronField,
    pub day_of_month: CronField,
    pub month: CronField,
    pub day_of_week: CronField,
    /// `"UTC"` or a fixed offset `"±HH:MM"`. IANA zone names are refused —
    /// see the module doc's recorded delta.
    pub timezone: String,
}

/// The untrusted wire shape of a [`CalendarSpec`]; deserialization goes
/// through [`CalendarSpec::validate`] so a stored or submitted spec holds the
/// same invariants `parse` guarantees.
#[derive(Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct CalendarSpecWire {
    minute: CronField,
    hour: CronField,
    day_of_month: CronField,
    month: CronField,
    day_of_week: CronField,
    timezone: String,
}

impl TryFrom<CalendarSpecWire> for CalendarSpec {
    type Error = GatekeeperError;

    fn try_from(w: CalendarSpecWire) -> Result<Self, Self::Error> {
        let spec = CalendarSpec {
            minute: w.minute,
            hour: w.hour,
            day_of_month: w.day_of_month,
            month: w.month,
            day_of_week: w.day_of_week,
            timezone: w.timezone,
        };
        spec.validate()?;
        Ok(spec)
    }
}

fn check_field(field: &CronField, min: u32, max: u32, name: &str) -> Result<(), GatekeeperError> {
    match field {
        CronField::Any => Ok(()),
        CronField::Values(vals) => {
            if vals.is_empty() {
                return Err(GatekeeperError::Invalid(format!("cron {name}: no values")));
            }
            if vals.windows(2).any(|w| w[0] >= w[1]) {
                return Err(GatekeeperError::Invalid(format!(
                    "cron {name}: values must be sorted and unique"
                )));
            }
            if vals.iter().any(|v| *v < min || *v > max) {
                return Err(GatekeeperError::Invalid(format!(
                    "cron {name}: value outside {min}..={max}"
                )));
            }
            Ok(())
        }
    }
}

fn unknown_tz(tz: &str) -> GatekeeperError {
    GatekeeperError::Invalid(format!(
        "unknown timezone {tz:?}: this package evaluates \"UTC\" and fixed offsets \
         (\"+HH:MM\"/\"-HH:MM\") only; IANA zone names need tzdata the constrained \
         tier does not have (recorded delta — supply the offset per-schedule)"
    ))
}

/// Parse `"UTC"` or `"±HH:MM"` into an offset in seconds east of UTC.
fn parse_offset(tz: &str) -> Result<i64, GatekeeperError> {
    if tz == "UTC" {
        return Ok(0);
    }
    let sign = match tz.chars().next() {
        Some('+') => 1i64,
        Some('-') => -1i64,
        _ => return Err(unknown_tz(tz)),
    };
    let rest = tz.get(1..).unwrap_or("");
    let (hh, mm) = rest.split_once(':').ok_or_else(|| unknown_tz(tz))?;
    let all_digits = |s: &str| s.len() == 2 && s.chars().all(|c| c.is_ascii_digit());
    if !all_digits(hh) || !all_digits(mm) {
        return Err(unknown_tz(tz));
    }
    let h: i64 = hh.parse().map_err(|_| unknown_tz(tz))?;
    let m: i64 = mm.parse().map_err(|_| unknown_tz(tz))?;
    // Real-world offsets span -12:00..+14:00; accept the symmetric envelope.
    if h > 14 || m > 59 || (h == 14 && m != 0) {
        return Err(unknown_tz(tz));
    }
    Ok(sign * (h * 3600 + m * 60))
}

// Proleptic-Gregorian day/date conversions, after Howard Hinnant's
// `chrono`-compatible civil-calendar algorithms (public domain arithmetic,
// restated here because the constrained tier cannot link chrono).

/// Days since 1970-01-01 for a civil date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (i64::from(m) + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Civil date for days since 1970-01-01. Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// A broken-down local civil time, minute precision.
#[cfg(test)]
struct Civil {
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    /// 0 = Sunday, matching cron's day-of-week field.
    weekday_from_sunday: u32,
}

/// 0 = Sunday for days since 1970-01-01 (a Thursday, four days after Sunday).
fn weekday_of_days(days: i64) -> u32 {
    (days + 4).rem_euclid(7) as u32
}

/// Break local seconds (UTC seconds + offset) into civil fields.
#[cfg(test)]
fn civil_of_local_secs(local: i64) -> Civil {
    let days = local.div_euclid(86_400);
    let secs = local.rem_euclid(86_400);
    let (_, month, day) = civil_from_days(days);
    Civil {
        month,
        day,
        hour: (secs / 3600) as u32,
        minute: (secs % 3600 / 60) as u32,
        weekday_from_sunday: weekday_of_days(days),
    }
}

fn parse_field(text: &str, min: u32, max: u32, name: &str) -> Result<CronField, GatekeeperError> {
    if text == "*" {
        return Ok(CronField::Any);
    }
    let mut values = Vec::new();
    for part in text.split(',') {
        if let Some(step) = part.strip_prefix("*/") {
            let n: u32 = step
                .parse()
                .map_err(|_| GatekeeperError::Invalid(format!("cron {name}: bad step {part:?}")))?;
            if n == 0 {
                return Err(GatekeeperError::Invalid(format!("cron {name}: step 0")));
            }
            if n > max {
                return Err(GatekeeperError::Invalid(format!(
                    "cron {name}: step {n} exceeds the field maximum {max}"
                )));
            }
            values.extend((min..=max).step_by(n as usize));
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let bad_range =
                |_| GatekeeperError::Invalid(format!("cron {name}: bad range {part:?}"));
            let a: u32 = a.parse().map_err(bad_range)?;
            let b: u32 = b.parse().map_err(bad_range)?;
            if a > b || a < min || b > max {
                return Err(GatekeeperError::Invalid(format!(
                    "cron {name}: range {part:?} outside {min}..={max}"
                )));
            }
            values.extend(a..=b);
            continue;
        }
        let v: u32 = part.parse().map_err(|_| {
            GatekeeperError::Invalid(format!("cron {name}: {part:?} is not a number"))
        })?;
        if v < min || v > max {
            return Err(GatekeeperError::Invalid(format!(
                "cron {name}: {v} outside {min}..={max}"
            )));
        }
        values.push(v);
    }
    values.sort_unstable();
    values.dedup();
    Ok(CronField::Values(values))
}

impl CalendarSpec {
    /// Check the invariants `parse` guarantees: a known timezone and, for
    /// every restricted field, a non-empty, sorted, duplicate-free set of
    /// in-range values. Run on deserialization and before every evaluation,
    /// because the fields are public.
    pub fn validate(&self) -> Result<(), GatekeeperError> {
        parse_offset(&self.timezone)?;
        check_field(&self.minute, 0, 59, "minute")?;
        check_field(&self.hour, 0, 23, "hour")?;
        check_field(&self.day_of_month, 1, 31, "day-of-month")?;
        check_field(&self.month, 1, 12, "month")?;
        check_field(&self.day_of_week, 0, 6, "day-of-week (0=Sun)")?;
        Ok(())
    }

    /// Parse and validate an expression + timezone. Refuses malformed
    /// expressions and unknown timezones by name, at registration time.
    pub fn parse(expression: &str, timezone: &str) -> Result<Self, GatekeeperError> {
        parse_offset(timezone)?;
        if expression.len() > MAX_EXPRESSION_LEN {
            return Err(GatekeeperError::Invalid(format!(
                "cron expression is longer than {MAX_EXPRESSION_LEN} bytes"
            )));
        }
        let fields: Vec<&str> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(GatekeeperError::Invalid(format!(
                "cron expression must have 5 fields, got {}",
                fields.len()
            )));
        }
        Ok(Self {
            minute: parse_field(fields[0], 0, 59, "minute")?,
            hour: parse_field(fields[1], 0, 23, "hour")?,
            day_of_month: parse_field(fields[2], 1, 31, "day-of-month")?,
            month: parse_field(fields[3], 1, 12, "month")?,
            day_of_week: parse_field(fields[4], 0, 6, "day-of-week (0=Sun)")?,
            timezone: timezone.to_string(),
        })
    }

    /// Do the date fields admit this local day? Standard cron: when both
    /// day-of-month and day-of-week are restricted, either one matching is
    /// enough; otherwise the restricted one (if any) decides.
    fn matches_day(&self, month: u32, day: u32, weekday_from_sunday: u32) -> bool {
        if !self.month.matches(month) {
            return false;
        }
        match (&self.day_of_month, &self.day_of_week) {
            (CronField::Values(_), CronField::Values(_)) => {
                self.day_of_month.matches(day) || self.day_of_week.matches(weekday_from_sunday)
            }
            _ => self.day_of_month.matches(day) && self.day_of_week.matches(weekday_from_sunday),
        }
    }

    #[cfg(test)]
    fn matches_civil(&self, c: &Civil) -> bool {
        self.minute.matches(c.minute)
            && self.hour.matches(c.hour)
            && self.matches_day(c.month, c.day, c.weekday_from_sunday)
    }

    /// The next fire instant strictly after `after` (ms since epoch, UTC),
    /// evaluated in the schedule's OWN (fixed-offset) timezone. Searches up
    /// to [`SEARCH_HORIZON_DAYS`], one day at a time; a spec that never
    /// matches within that window is refused.
    pub fn next_fire_after(&self, after: TimestampMs) -> Result<TimestampMs, GatekeeperError> {
        self.validate()?;
        let offset = parse_offset(&self.timezone)?;
        let after_secs = (after / 1000) as i64;
        // The first candidate is the next whole minute strictly after
        // `after`; the last is the search horizon on. Offsets are whole
        // minutes, so minute boundaries coincide in UTC and local time.
        let first_local = after_secs - after_secs.rem_euclid(60) + 60 + offset;
        let limit_local = after_secs + SEARCH_HORIZON_DAYS * 86_400 + offset;
        let no_match = || {
            GatekeeperError::Invalid("cron expression matches no instant within eight years".into())
        };
        for day in first_local.div_euclid(86_400)..=limit_local.div_euclid(86_400) {
            let (_, month, dom) = civil_from_days(day);
            if !self.matches_day(month, dom, weekday_of_days(day)) {
                continue;
            }
            for hour in (0..24u32).filter(|h| self.hour.matches(*h)) {
                for minute in (0..60u32).filter(|m| self.minute.matches(*m)) {
                    let local = day * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60;
                    if local < first_local {
                        continue;
                    }
                    if local > limit_local {
                        return Err(no_match());
                    }
                    // Checked: a horizon near u64::MAX would wrap to a 1970 instant before `after`.
                    return u64::try_from(local - offset)
                        .ok()
                        .and_then(|secs| secs.checked_mul(1000))
                        .ok_or_else(|| GatekeeperError::Invalid("the next fire time is past the timestamp range".into()));
                }
            }
        }
        Err(no_match())
    }

    /// Convenience: the UTC instant of a given local civil date/time in this
    /// spec's zone (used by tests around offset edges). Under a fixed offset
    /// every local time exists exactly once, so there are no ambiguous or
    /// nonexistent local times to resolve.
    pub fn local_instant(
        &self,
        y: i32,
        m: u32,
        d: u32,
        hh: u32,
        mm: u32,
    ) -> Result<TimestampMs, GatekeeperError> {
        let offset = parse_offset(&self.timezone)?;
        if !(1..=12).contains(&m)
            || d < 1
            || d > days_in_month(i64::from(y), m)
            || hh > 23
            || mm > 59
        {
            return Err(GatekeeperError::Invalid("invalid civil time".into()));
        }
        let local = days_from_civil(i64::from(y), m, d) * 86_400
            + i64::from(hh) * 3600
            + i64::from(mm) * 60;
        let utc = local - offset;
        if utc < 0 {
            return Err(GatekeeperError::Invalid(
                "civil time is before the Unix epoch".into(),
            ));
        }
        u64::try_from(utc)
            .ok()
            .and_then(|secs| secs.checked_mul(1000))
            .ok_or_else(|| GatekeeperError::Invalid("civil time is past the timestamp range".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leap_day_schedules_resolve_across_four_and_eight_year_gaps() {
        let s = CalendarSpec::parse("0 0 29 2 *", "UTC").unwrap();
        let jan_2026 = s.local_instant(2026, 1, 1, 0, 0).unwrap();
        let feb_2028 = s.local_instant(2028, 2, 29, 0, 0).unwrap();
        let feb_2032 = s.local_instant(2032, 2, 29, 0, 0).unwrap();
        assert_eq!(s.next_fire_after(jan_2026).unwrap(), feb_2028);
        assert_eq!(s.next_fire_after(feb_2028).unwrap(), feb_2032);
        // 2100 is not a leap year, so 2096-02-29 -> 2104-02-29 is an 8-year gap.
        let feb_2096 = s.local_instant(2096, 2, 29, 0, 0).unwrap();
        let feb_2104 = s.local_instant(2104, 2, 29, 0, 0).unwrap();
        assert_eq!(s.next_fire_after(feb_2096).unwrap(), feb_2104);
        // A spec that can never match is still refused, quickly.
        let never = CalendarSpec::parse("0 0 31 2 *", "UTC").unwrap();
        assert!(never.next_fire_after(jan_2026).is_err());
    }

    #[test]
    fn deserialized_specs_are_validated() {
        let ok = CalendarSpec::parse("*/15 9-17 * * 1-5", "+02:00").unwrap();
        let round = ferrite_app::serde_json::to_value(&ok).unwrap();
        assert_eq!(ferrite_app::serde_json::from_value::<CalendarSpec>(round).unwrap(), ok);
        let any = ferrite_app::serde_json::json!("Any");
        let base = |minute: ferrite_app::serde_json::Value, tz: &str| {
            ferrite_app::serde_json::json!({
                "minute": minute, "hour": any, "day_of_month": any,
                "month": any, "day_of_week": any, "timezone": tz
            })
        };
        let huge: Vec<u32> = vec![60; 10_000];
        for bad in [
            base(ferrite_app::serde_json::json!({"Values": huge}), "UTC"),
            base(ferrite_app::serde_json::json!({"Values": []}), "UTC"),
            base(ferrite_app::serde_json::json!({"Values": [5, 1]}), "UTC"),
            base(ferrite_app::serde_json::json!({"Values": [1, 1]}), "UTC"),
            base(any.clone(), "Europe/Paris"),
        ] {
            assert!(ferrite_app::serde_json::from_value::<CalendarSpec>(bad).is_err());
        }
        // A spec mutated through its public fields is refused at evaluation.
        let mut mutated = ok;
        mutated.minute = CronField::Values(vec![]);
        assert!(mutated.next_fire_after(0).is_err());
    }

    #[test]
    fn parses_and_validates() {
        let s = CalendarSpec::parse("0 3 * * *", "+02:00").unwrap();
        assert_eq!(s.timezone, "+02:00");
        assert!(CalendarSpec::parse("0 3 * *", "UTC").is_err()); // 4 fields
        assert!(CalendarSpec::parse("0 25 * * *", "UTC").is_err()); // hour 25
        assert!(CalendarSpec::parse("0 3 * * *", "Mars/Olympus").is_err()); // bad tz
        assert!(CalendarSpec::parse("*/15 9-17 * * 1-5", "-05:30").is_ok());
        // Recorded delta: IANA zone names are refused, loudly, at registration.
        assert!(CalendarSpec::parse("0 3 * * *", "Europe/Amsterdam").is_err());
        assert!(CalendarSpec::parse("0 3 * * *", "America/New_York").is_err());
        // Offset envelope and shape are enforced.
        assert!(CalendarSpec::parse("0 0 * * *", "+14:00").is_ok());
        assert!(CalendarSpec::parse("0 0 * * *", "+14:01").is_err());
        assert!(CalendarSpec::parse("0 0 * * *", "+15:00").is_err());
        assert!(CalendarSpec::parse("0 0 * * *", "+2:00").is_err()); // not zero-padded
        assert!(CalendarSpec::parse("0 0 * * *", "+02:0a").is_err());
        assert!(CalendarSpec::parse("0 0 * * *", "utc").is_err());
    }

    #[test]
    fn civil_math_agrees_with_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-08-07 is a Friday (5 days from Sunday).
        let d = days_from_civil(2026, 8, 7);
        assert_eq!(civil_from_days(d), (2026, 8, 7));
        assert_eq!((d + 4).rem_euclid(7), 5);
        // Leap rules: 2024 and 2000 are leap years; 2100 is not.
        assert!(is_leap(2024) && is_leap(2000) && !is_leap(2100));
        assert_eq!(civil_from_days(days_from_civil(2024, 2, 29)), (2024, 2, 29));
        // Round-trip every day across a leap-February boundary.
        for z in days_from_civil(2023, 12, 1)..=days_from_civil(2024, 3, 15) {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
    }

    #[test]
    fn fixed_offsets_convert_local_to_utc() {
        let utc = CalendarSpec::parse("0 0 * * *", "UTC").unwrap();
        let east = CalendarSpec::parse("0 0 * * *", "+05:30").unwrap();
        let west = CalendarSpec::parse("0 0 * * *", "-05:30").unwrap();
        // 2026-01-01 05:30 at +05:30 == 2026-01-01 00:00Z.
        assert_eq!(
            east.local_instant(2026, 1, 1, 5, 30).unwrap(),
            utc.local_instant(2026, 1, 1, 0, 0).unwrap()
        );
        // 2026-01-01 00:00 at -05:30 == 2026-01-01 05:30Z.
        assert_eq!(
            west.local_instant(2026, 1, 1, 0, 0).unwrap(),
            utc.local_instant(2026, 1, 1, 5, 30).unwrap()
        );
        // Feb 30 never exists; neither does 24:00.
        assert!(utc.local_instant(2026, 2, 30, 0, 0).is_err());
        assert!(utc.local_instant(2026, 1, 1, 24, 0).is_err());
    }

    #[test]
    fn offset_shift_changes_utc_fire_time() {
        // The node-tier crate's DST test, expressed with per-schedule
        // offsets: 03:00 daily under Amsterdam's winter offset (+01:00)
        // fires at 02:00Z; under its summer offset (+02:00), at 01:00Z.
        // The deployment supplies the offset; the arithmetic is identical.
        let winter = CalendarSpec::parse("0 3 * * *", "+01:00").unwrap();
        let winter_start = winter.local_instant(2026, 1, 10, 0, 0).unwrap();
        let winter_fire = winter.next_fire_after(winter_start).unwrap();
        let winter_utc = civil_of_local_secs((winter_fire / 1000) as i64);
        assert_eq!(winter_utc.hour, 2, "winter 03:00 at +01:00 == 02:00Z");

        let summer = CalendarSpec::parse("0 3 * * *", "+02:00").unwrap();
        let summer_start = summer.local_instant(2026, 7, 10, 0, 0).unwrap();
        let summer_fire = summer.next_fire_after(summer_start).unwrap();
        let summer_utc = civil_of_local_secs((summer_fire / 1000) as i64);
        assert_eq!(summer_utc.hour, 1, "summer 03:00 at +02:00 == 01:00Z");
    }

    #[test]
    fn offset_change_reregistration_models_dst_transition() {
        // Recorded delta: with fixed offsets every local time exists, so the
        // node-tier spring-forward-gap assertion (a 02:30 Europe/Amsterdam
        // schedule skipping the nonexistent 2026-03-29 02:30) fundamentally
        // needs tzdata and is deleted. What stays expressible is the
        // documented recourse — the deployment re-registers the schedule
        // with the summer offset at the transition — and the invariant the
        // gap test defended: exactly one fire per local day, never a wedge
        // or a double fire.
        let winter = CalendarSpec::parse("30 2 * * *", "+01:00").unwrap();
        let last_winter_fire = winter.local_instant(2026, 3, 28, 2, 30).unwrap();
        let summer = CalendarSpec::parse("30 2 * * *", "+02:00").unwrap();
        let fire = summer.next_fire_after(last_winter_fire).unwrap();
        assert_eq!(fire, summer.local_instant(2026, 3, 29, 2, 30).unwrap());
        // Strictly one fire per local day.
        let next = summer.next_fire_after(fire).unwrap();
        assert_eq!(next, summer.local_instant(2026, 3, 30, 2, 30).unwrap());
    }

    #[test]
    fn weekday_and_step_fields_evaluate() {
        // 09:00 on weekdays.
        let s = CalendarSpec::parse("0 9 * * 1-5", "UTC").unwrap();
        // 2026-08-07 is a Friday; next fire after Friday 10:00 is Monday 09:00.
        let fri = s.local_instant(2026, 8, 7, 10, 0).unwrap();
        let fire = s.next_fire_after(fri).unwrap();
        let c = civil_of_local_secs((fire / 1000) as i64);
        assert_eq!((c.month, c.day, c.hour), (8, 10, 9)); // Monday
        assert_eq!(c.weekday_from_sunday, 1);
    }

    /// The day-wise search agrees with a brute-force minute scan.
    #[test]
    fn day_wise_search_matches_a_minute_scan() {
        let start = CalendarSpec::parse("* * * * *", "UTC")
            .unwrap()
            .local_instant(2026, 2, 27, 23, 58)
            .unwrap()
            + 30_000;
        for (expr, tz) in [
            ("*/15 9-17 * * 1-5", "-05:30"),
            ("0 3 * * *", "+02:00"),
            ("30 2 28 2 *", "UTC"),
            ("0 9 1 * 1", "+14:00"),
            ("59 23 31 * *", "-12:00"),
        ] {
            let s = CalendarSpec::parse(expr, tz).unwrap();
            let offset = parse_offset(tz).unwrap();
            let after_secs = (start / 1000) as i64;
            let mut probe = after_secs - after_secs.rem_euclid(60) + 60;
            let expected = loop {
                if s.matches_civil(&civil_of_local_secs(probe + offset)) {
                    break probe as TimestampMs * 1000;
                }
                probe += 60;
            };
            assert_eq!(s.next_fire_after(start).unwrap(), expected, "{expr} @ {tz}");
        }
    }

    /// F478: with both day fields restricted, either one matching fires.
    #[test]
    fn restricted_day_fields_are_a_union() {
        let s = CalendarSpec::parse("0 9 1 * 1", "UTC").unwrap();
        // Friday 2026-08-07 10:00: the next fire is Monday 2026-08-10 09:00
        // (a Monday), not the next Monday that is also the 1st.
        let fri = s.local_instant(2026, 8, 7, 10, 0).unwrap();
        let fire = s.next_fire_after(fri).unwrap();
        assert_eq!(fire, s.local_instant(2026, 8, 10, 9, 0).unwrap());
        // From Monday 2026-08-31 10:00 the next fire is Tuesday the 1st.
        let mon = s.local_instant(2026, 8, 31, 10, 0).unwrap();
        assert_eq!(
            s.next_fire_after(mon).unwrap(),
            s.local_instant(2026, 9, 1, 9, 0).unwrap()
        );
        // With day-of-week unrestricted, day-of-month alone decides.
        let s = CalendarSpec::parse("0 9 1 * *", "UTC").unwrap();
        assert_eq!(
            s.next_fire_after(fri).unwrap(),
            s.local_instant(2026, 9, 1, 9, 0).unwrap()
        );
    }

    /// F479: an oversized step is refused instead of overflowing.
    #[test]
    fn oversized_steps_and_expressions_are_refused() {
        assert!(CalendarSpec::parse("0 0 */4294967295 * *", "UTC").is_err());
        assert!(CalendarSpec::parse("0 0 * */4294967295 *", "UTC").is_err());
        assert!(CalendarSpec::parse("*/60 * * * *", "UTC").is_err());
        assert!(CalendarSpec::parse("*/59 * * * *", "UTC").is_ok());
        let long = format!("0 {} * * *", vec!["1"; 200].join(","));
        assert!(CalendarSpec::parse(&long, "UTC").is_err());
    }

    /// F479: a spec that never matches is refused cheaply. The old
    /// minute-by-minute scan probed 527,040 minutes per call; 200 calls
    /// took tens of seconds in a debug build.
    #[test]
    fn never_matching_specs_are_refused_cheaply() {
        // Feb 30 and Feb 31 never exist.
        let feb30 = CalendarSpec::parse("0 0 30 2 *", "UTC").unwrap();
        let s = CalendarSpec::parse("0 0 31 2 *", "UTC").unwrap();
        let start = s.local_instant(2026, 1, 1, 0, 0).unwrap();
        assert!(feb30.next_fire_after(start).is_err());
        let began = std::time::Instant::now();
        for i in 0..200u64 {
            assert!(s.next_fire_after(start + i * 60_000).is_err());
        }
        assert!(
            began.elapsed() < std::time::Duration::from_secs(2),
            "200 never-matching evaluations took {:?}",
            began.elapsed()
        );
    }
}
