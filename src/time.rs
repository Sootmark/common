//! Timestamps.
//!
//! Every source format converts to one canonical [`Ts`]: signed 100-nanosecond
//! ticks since 1970-01-01T00:00:00 UTC. That is lossless for Windows FILETIME
//! (the finest common forensic resolution) and covers roughly ±29,000 years,
//! so 1601 (FILETIME zero) and 30828 (FILETIME max) both fit.
//!
//! A timestamp also carries:
//! - its [`Precision`] at the source (a FAT time is only good to 2 seconds),
//! - its [`Semantic`]: whether the value is a real UTC time, a local time with
//!   an unknown zone, or not a time at all (zero, sentinel, garbage).
//!
//! Zero and sentinel values are never silently turned into 1601-01-01 or
//! 1970-01-01. Parsers keep the raw source value next to the converted one.

use core::fmt;

/// 100 ns ticks in one second.
pub const TICKS_PER_SECOND: i64 = 10_000_000;
/// 100 ns ticks in one day.
pub const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;
/// 100 ns ticks in one millisecond.
const TICKS_PER_MILLI: i64 = 10_000;
/// 100 ns ticks in one microsecond.
const TICKS_PER_MICRO: i64 = 10;
/// Nanoseconds in one 100 ns tick.
const NANOS_PER_TICK: i64 = 100;
const MILLIS_PER_DAY: f64 = 86_400_000.0;
const MICROS_PER_SECOND: f64 = 1_000_000.0;

/// Ticks between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_UNIX_OFFSET: i64 = 116_444_736_000_000_000;
/// Seconds from 1970-01-01 back to 1899-12-30 (OLE Automation epoch).
const OLE_EPOCH_UNIX_SECONDS: i64 = -2_209_161_600;
/// Seconds from 1970-01-01 back to 1904-01-01 (HFS/HFS+ epoch).
const HFS_EPOCH_UNIX_SECONDS: i64 = -2_082_844_800;
/// Seconds from 1970-01-01 to 2001-01-01 (Cocoa / Mac absolute time epoch).
const COCOA_EPOCH_UNIX_SECONDS: i64 = 978_307_200;

/// Resolution of the timestamp in its source format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Precision {
    /// 100 nanoseconds (FILETIME).
    Tick,
    /// 1 microsecond (WebKit/Chrome, most Unix µs).
    Microsecond,
    /// 1 millisecond.
    Millisecond,
    /// 1 second.
    Second,
    /// 2 seconds (FAT/DOS).
    TwoSeconds,
    /// 1 day.
    Day,
}

/// What a converted value means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Semantic {
    /// A real point in time, in UTC.
    Utc,
    /// A wall-clock time in an unknown time zone (FAT/DOS, some logs).
    /// Convert with [`Ts::assume_offset`] once the host zone is known.
    LocalUnknownZone,
    /// The field was zero: "never set", not 1601 or 1970.
    NotSet,
    /// A reserved "maximum" value (e.g. FILETIME `0x7FFF_FFFF_FFFF_FFFF`).
    Sentinel,
    /// Not representable: overflow, NaN, or impossible calendar fields.
    Invalid,
}

/// A converted timestamp. See the [module docs](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ts {
    ticks: i64,
    precision: Precision,
    semantic: Semantic,
}

impl Ts {
    /// A UTC timestamp from canonical ticks.
    #[must_use]
    pub const fn from_ticks(ticks: i64, precision: Precision) -> Self {
        Self {
            ticks,
            precision,
            semantic: Semantic::Utc,
        }
    }

    /// A wall-clock time in an unknown time zone, from canonical ticks
    /// counted as if the wall clock were UTC (e.g. a log line's local time).
    /// Convert with [`Ts::assume_offset`] once the zone is known.
    #[must_use]
    pub const fn from_local_ticks(ticks: i64, precision: Precision) -> Self {
        Self {
            ticks,
            precision,
            semantic: Semantic::LocalUnknownZone,
        }
    }

    const fn special(semantic: Semantic, precision: Precision) -> Self {
        Self {
            ticks: 0,
            precision,
            semantic,
        }
    }

    const fn checked(ticks: Option<i64>, precision: Precision) -> Self {
        match ticks {
            Some(t) => Self::from_ticks(t, precision),
            None => Self::special(Semantic::Invalid, precision),
        }
    }

    /// Canonical ticks, when the value is a time (UTC or local-unknown-zone).
    #[must_use]
    pub const fn ticks(&self) -> Option<i64> {
        match self.semantic {
            Semantic::Utc | Semantic::LocalUnknownZone => Some(self.ticks),
            _ => None,
        }
    }

    /// Source precision.
    #[must_use]
    pub const fn precision(&self) -> Precision {
        self.precision
    }

    /// What the value means.
    #[must_use]
    pub const fn semantic(&self) -> Semantic {
        self.semantic
    }

    /// Windows FILETIME: 100 ns intervals since 1601-01-01 UTC.
    ///
    /// `0` is [`Semantic::NotSet`]; `0x7FFF_FFFF_FFFF_FFFF` and `u64::MAX` are
    /// [`Semantic::Sentinel`]; other values above `i64::MAX` are invalid.
    ///
    /// ```
    /// use sootmark_common::time::{Semantic, Ts};
    ///
    /// let ts = Ts::from_filetime(125_911_584_000_000_000);
    /// assert_eq!(ts.to_string(), "2000-01-01T00:00:00.0000000Z");
    /// assert_eq!(Ts::from_filetime(0).semantic(), Semantic::NotSet);
    /// ```
    #[must_use]
    pub fn from_filetime(value: u64) -> Self {
        match value {
            0 => Self::special(Semantic::NotSet, Precision::Tick),
            0x7FFF_FFFF_FFFF_FFFF | u64::MAX => Self::special(Semantic::Sentinel, Precision::Tick),
            v => match i64::try_from(v) {
                Ok(v) => Self::from_ticks(v - FILETIME_UNIX_OFFSET, Precision::Tick),
                Err(_) => Self::special(Semantic::Invalid, Precision::Tick),
            },
        }
    }

    /// Unix time in seconds. `0` is treated as [`Semantic::NotSet`], which is
    /// what it means in almost every forensic artifact.
    #[must_use]
    pub fn from_unix_seconds(value: i64) -> Self {
        Self::scaled(value, TICKS_PER_SECOND, Precision::Second)
    }

    /// Unix time in milliseconds. `0` is [`Semantic::NotSet`].
    #[must_use]
    pub fn from_unix_millis(value: i64) -> Self {
        Self::scaled(value, TICKS_PER_MILLI, Precision::Millisecond)
    }

    /// Unix time in microseconds. `0` is [`Semantic::NotSet`].
    #[must_use]
    pub fn from_unix_micros(value: i64) -> Self {
        Self::scaled(value, TICKS_PER_MICRO, Precision::Microsecond)
    }

    /// Unix time in nanoseconds. `0` is [`Semantic::NotSet`].
    /// Sub-100 ns digits are truncated toward negative infinity.
    #[must_use]
    pub fn from_unix_nanos(value: i64) -> Self {
        if value == 0 {
            return Self::special(Semantic::NotSet, Precision::Tick);
        }
        Self::from_ticks(value.div_euclid(NANOS_PER_TICK), Precision::Tick)
    }

    fn scaled(value: i64, ticks_per_unit: i64, precision: Precision) -> Self {
        if value == 0 {
            return Self::special(Semantic::NotSet, precision);
        }
        Self::checked(value.checked_mul(ticks_per_unit), precision)
    }

    /// `WebKit` / Chrome time: microseconds since 1601-01-01 UTC.
    /// `0` is [`Semantic::NotSet`].
    #[must_use]
    pub fn from_webkit_micros(value: i64) -> Self {
        if value == 0 {
            return Self::special(Semantic::NotSet, Precision::Microsecond);
        }
        let ticks = value
            .checked_mul(TICKS_PER_MICRO)
            .and_then(|t| t.checked_sub(FILETIME_UNIX_OFFSET));
        Self::checked(ticks, Precision::Microsecond)
    }

    /// OLE Automation date (`VT_DATE`): days since 1899-12-30, the fraction
    /// being the time of day. For negative values the fraction still counts
    /// forward from midnight (-1.25 is 1899-12-29 06:00). `0.0` is
    /// [`Semantic::NotSet`]. Precision is milliseconds.
    #[must_use]
    pub fn from_ole_date(days: f64) -> Self {
        const MAX_DAYS: f64 = 10_000_000.0; // ±27,000 years
        if days == 0.0 {
            return Self::special(Semantic::NotSet, Precision::Millisecond);
        }
        if !days.is_finite() || days.abs() > MAX_DAYS {
            return Self::special(Semantic::Invalid, Precision::Millisecond);
        }
        let whole = days.trunc();
        let fraction = (days - whole).abs();
        let millis_of_day = (fraction * MILLIS_PER_DAY).round() as i64;
        let ticks = (whole as i64) * TICKS_PER_DAY
            + millis_of_day * TICKS_PER_MILLI
            + OLE_EPOCH_UNIX_SECONDS * TICKS_PER_SECOND;
        Self::from_ticks(ticks, Precision::Millisecond)
    }

    /// HFS / HFS+ time: seconds since 1904-01-01, in UTC (catalog records).
    /// `0` is [`Semantic::NotSet`]. The HFS+ volume header stores *local*
    /// time; use [`Ts::from_hfs_local_seconds`] for that field.
    #[must_use]
    pub fn from_hfs_seconds(value: u32) -> Self {
        if value == 0 {
            return Self::special(Semantic::NotSet, Precision::Second);
        }
        let ticks = (i64::from(value) + HFS_EPOCH_UNIX_SECONDS) * TICKS_PER_SECOND;
        Self::from_ticks(ticks, Precision::Second)
    }

    /// HFS+ volume-header time: seconds since 1904-01-01 local time.
    #[must_use]
    pub fn from_hfs_local_seconds(value: u32) -> Self {
        let mut ts = Self::from_hfs_seconds(value);
        if ts.semantic == Semantic::Utc {
            ts.semantic = Semantic::LocalUnknownZone;
        }
        ts
    }

    /// Cocoa / Mac absolute time: seconds (as `f64`) since 2001-01-01 UTC.
    /// `0.0` is [`Semantic::NotSet`].
    #[must_use]
    pub fn from_cocoa_seconds(seconds: f64) -> Self {
        const MAX_SECONDS: f64 = 900_000_000_000.0; // ±28,000 years
        if seconds == 0.0 {
            return Self::special(Semantic::NotSet, Precision::Microsecond);
        }
        if !seconds.is_finite() || seconds.abs() > MAX_SECONDS {
            return Self::special(Semantic::Invalid, Precision::Microsecond);
        }
        let micros = (seconds * MICROS_PER_SECOND).round() as i64;
        let ticks = micros * TICKS_PER_MICRO + COCOA_EPOCH_UNIX_SECONDS * TICKS_PER_SECOND;
        Self::from_ticks(ticks, Precision::Microsecond)
    }

    /// FAT / MS-DOS date and time words. These are local wall-clock times with
    /// 2-second resolution and no zone, so the result is
    /// [`Semantic::LocalUnknownZone`]. Both words zero is [`Semantic::NotSet`].
    #[must_use]
    pub fn from_dos(date: u16, time: u16) -> Self {
        if date == 0 && time == 0 {
            return Self::special(Semantic::NotSet, Precision::TwoSeconds);
        }
        let year = 1980 + i64::from(date >> 9);
        let month = u32::from((date >> 5) & 0x0F);
        let day = u32::from(date & 0x1F);
        let hour = i64::from(time >> 11);
        let minute = i64::from((time >> 5) & 0x3F);
        let second = i64::from(time & 0x1F) * 2;
        if !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Self::special(Semantic::Invalid, Precision::TwoSeconds);
        }
        let days = days_from_civil(year, month, day);
        let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
        Self {
            ticks: seconds * TICKS_PER_SECOND,
            precision: Precision::TwoSeconds,
            semantic: Semantic::LocalUnknownZone,
        }
    }

    /// Convert a [`Semantic::LocalUnknownZone`] value to UTC, given the
    /// source's offset from UTC in minutes (e.g. `+120` for UTC+2). Other
    /// values are returned unchanged. This applies a fixed offset: resolving
    /// DST from a named zone is the caller's job.
    #[must_use]
    pub fn assume_offset(self, offset_minutes: i32) -> Self {
        if self.semantic != Semantic::LocalUnknownZone {
            return self;
        }
        let ticks = self
            .ticks
            .checked_sub(i64::from(offset_minutes) * 60 * TICKS_PER_SECOND);
        Self::checked(ticks, self.precision)
    }

    /// Whether the value is a time whose calendar year is within
    /// `min_year..=max_year`. Parsers use this to flag implausible values.
    #[must_use]
    pub fn year_within(&self, min_year: i64, max_year: i64) -> bool {
        self.ticks().is_some_and(|t| {
            let (year, _, _) = civil_from_days(t.div_euclid(TICKS_PER_DAY));
            (min_year..=max_year).contains(&year)
        })
    }

    /// ISO 8601 with full 100 ns precision: `2019-04-17T18:40:00.0000000Z`.
    /// Local-unknown-zone values have no `Z`. Years outside 0000–9999 use the
    /// expanded `±YYYYYY` form. Returns `None` for non-time values.
    #[must_use]
    pub fn to_iso8601(&self) -> Option<String> {
        let ticks = self.ticks()?;
        let days = ticks.div_euclid(TICKS_PER_DAY);
        let rem = ticks.rem_euclid(TICKS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let secs = rem / TICKS_PER_SECOND;
        let frac = rem % TICKS_PER_SECOND;
        let zone = if self.semantic == Semantic::Utc {
            "Z"
        } else {
            ""
        };
        let year = if (0..=9999).contains(&year) {
            format!("{year:04}")
        } else {
            format!("{year:+07}")
        };
        Some(format!(
            "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{frac:07}{zone}",
            secs / 3600,
            secs / 60 % 60,
            secs % 60,
        ))
    }
}

impl fmt::Display for Ts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_iso8601() {
            Some(s) => f.write_str(&s),
            None => f.write_str(match self.semantic {
                Semantic::NotSet => "<not set>",
                Semantic::Sentinel => "<sentinel>",
                _ => "<invalid>",
            }),
        }
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
/// Howard Hinnant's `days_from_civil`, valid for any `i64` year in range.
#[must_use]
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(month) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Proleptic Gregorian `(year, month, day)` for days since 1970-01-01.
/// Inverse of [`days_from_civil`].
#[must_use]
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn local_ticks_stay_local_until_an_offset_is_known() {
        let local = Ts::from_local_ticks(TICKS_PER_DAY, Precision::Tick);
        assert_eq!(local.semantic(), Semantic::LocalUnknownZone);
        assert_eq!(
            local.to_iso8601().as_deref(),
            Some("1970-01-02T00:00:00.0000000")
        );
        let utc = local.assume_offset(60);
        assert_eq!(utc.semantic(), Semantic::Utc);
        assert_eq!(
            utc.to_iso8601().as_deref(),
            Some("1970-01-01T23:00:00.0000000Z")
        );
    }
    use super::*;
    use proptest::prelude::*;

    fn iso(ts: Ts) -> String {
        ts.to_iso8601().expect("a time value")
    }

    /// Pack a FAT date word: bits 15–9 year since 1980, 8–5 month, 4–0 day.
    fn dos_date(year: u16, month: u16, day: u16) -> u16 {
        ((year - 1980) << 9) | (month << 5) | day
    }

    /// Pack a FAT time word: bits 15–11 hours, 10–5 minutes, 4–0 seconds / 2.
    fn dos_time(hour: u16, minute: u16, second: u16) -> u16 {
        (hour << 11) | (minute << 5) | (second / 2)
    }

    #[test]
    fn filetime_known_values() {
        assert_eq!(
            iso(Ts::from_filetime(116_444_736_000_000_000)),
            "1970-01-01T00:00:00.0000000Z"
        );
        assert_eq!(
            iso(Ts::from_filetime(125_911_584_000_000_000)),
            "2000-01-01T00:00:00.0000000Z"
        );
        assert_eq!(iso(Ts::from_filetime(1)), "1601-01-01T00:00:00.0000001Z");
        assert_eq!(
            iso(Ts::from_filetime(0x7FFF_FFFF_FFFF_FFFE)),
            "+030828-09-14T02:48:05.4775806Z"
        );
    }

    #[test]
    fn filetime_special_values() {
        assert_eq!(Ts::from_filetime(0).semantic(), Semantic::NotSet);
        assert_eq!(
            Ts::from_filetime(0x7FFF_FFFF_FFFF_FFFF).semantic(),
            Semantic::Sentinel
        );
        assert_eq!(Ts::from_filetime(u64::MAX).semantic(), Semantic::Sentinel);
        assert_eq!(
            Ts::from_filetime(0x8000_0000_0000_0000).semantic(),
            Semantic::Invalid
        );
        assert_eq!(Ts::from_filetime(0).ticks(), None);
        assert_eq!(Ts::from_filetime(0).to_string(), "<not set>");
    }

    #[test]
    fn unix_variants() {
        assert_eq!(
            iso(Ts::from_unix_seconds(946_684_800)),
            "2000-01-01T00:00:00.0000000Z"
        );
        assert_eq!(
            iso(Ts::from_unix_millis(-1)),
            "1969-12-31T23:59:59.9990000Z"
        );
        assert_eq!(iso(Ts::from_unix_micros(1)), "1970-01-01T00:00:00.0000010Z");
        assert_eq!(
            iso(Ts::from_unix_nanos(1_999)),
            "1970-01-01T00:00:00.0000019Z"
        );
        assert_eq!(Ts::from_unix_seconds(0).semantic(), Semantic::NotSet);
        assert_eq!(
            Ts::from_unix_seconds(i64::MAX).semantic(),
            Semantic::Invalid
        );
        assert_eq!(Ts::from_unix_millis(5).precision(), Precision::Millisecond);
    }

    #[test]
    fn webkit() {
        let micros = (946_684_800 + 11_644_473_600) * 1_000_000;
        assert_eq!(
            iso(Ts::from_webkit_micros(micros)),
            "2000-01-01T00:00:00.0000000Z"
        );
        assert_eq!(Ts::from_webkit_micros(0).semantic(), Semantic::NotSet);
        assert_eq!(
            Ts::from_webkit_micros(i64::MAX).semantic(),
            Semantic::Invalid
        );
    }

    #[test]
    fn ole_dates() {
        assert_eq!(iso(Ts::from_ole_date(2.5)), "1900-01-01T12:00:00.0000000Z");
        assert_eq!(
            iso(Ts::from_ole_date(-1.25)),
            "1899-12-29T06:00:00.0000000Z"
        );
        assert_eq!(
            iso(Ts::from_ole_date(36_526.0)),
            "2000-01-01T00:00:00.0000000Z"
        );
        assert_eq!(Ts::from_ole_date(0.0).semantic(), Semantic::NotSet);
        assert_eq!(Ts::from_ole_date(f64::NAN).semantic(), Semantic::Invalid);
        assert_eq!(Ts::from_ole_date(1e12).semantic(), Semantic::Invalid);
    }

    #[test]
    fn hfs_and_cocoa() {
        assert_eq!(iso(Ts::from_hfs_seconds(1)), "1904-01-01T00:00:01.0000000Z");
        assert_eq!(
            Ts::from_hfs_local_seconds(1).semantic(),
            Semantic::LocalUnknownZone
        );
        assert_eq!(
            iso(Ts::from_cocoa_seconds(1.0)),
            "2001-01-01T00:00:01.0000000Z"
        );
        assert_eq!(
            iso(Ts::from_cocoa_seconds(-0.5)),
            "2000-12-31T23:59:59.5000000Z"
        );
        assert_eq!(
            Ts::from_cocoa_seconds(f64::INFINITY).semantic(),
            Semantic::Invalid
        );
    }

    #[test]
    fn dos_is_local_until_an_offset_is_applied() {
        let ts = Ts::from_dos(dos_date(2020, 1, 1), dos_time(12, 30, 58));
        assert_eq!(ts.semantic(), Semantic::LocalUnknownZone);
        assert_eq!(ts.precision(), Precision::TwoSeconds);
        assert_eq!(iso(ts), "2020-01-01T12:30:58.0000000");

        let utc = ts.assume_offset(120); // host was UTC+2
        assert_eq!(utc.semantic(), Semantic::Utc);
        assert_eq!(iso(utc), "2020-01-01T10:30:58.0000000Z");
    }

    #[test]
    fn dos_rejects_impossible_dates() {
        assert_eq!(Ts::from_dos(0, 0).semantic(), Semantic::NotSet);
        assert_eq!(
            Ts::from_dos(dos_date(2020, 2, 30), 0).semantic(),
            Semantic::Invalid
        );
        assert_eq!(
            Ts::from_dos(dos_date(2020, 13, 1), 0).semantic(),
            Semantic::Invalid
        );
        let leap_day = Ts::from_dos(dos_date(2020, 2, 29), 0);
        assert_eq!(leap_day.semantic(), Semantic::LocalUnknownZone);
    }

    #[test]
    fn assume_offset_leaves_utc_values_alone() {
        let ts = Ts::from_unix_seconds(100);
        assert_eq!(ts.assume_offset(60), ts);
    }

    #[test]
    fn year_window() {
        let ts = Ts::from_unix_seconds(946_684_800);
        assert!(ts.year_within(1990, 2030));
        assert!(!ts.year_within(2001, 2030));
        assert!(!Ts::from_filetime(0).year_within(1600, 40_000));
    }

    proptest! {
        #[test]
        fn civil_round_trip(days in -200_000_000i64..200_000_000) {
            let (y, m, d) = civil_from_days(days);
            prop_assert!((1..=12).contains(&m));
            prop_assert!(d >= 1 && d <= days_in_month(y, m));
            prop_assert_eq!(days_from_civil(y, m, d), days);
        }

        #[test]
        fn filetime_is_lossless(ft in 1u64..0x7FFF_FFFF_FFFF_FFFF) {
            let ticks = Ts::from_filetime(ft).ticks().unwrap();
            prop_assert_eq!(ticks + FILETIME_UNIX_OFFSET, ft as i64);
        }

        #[test]
        fn iso_is_ordered_like_ticks(a in 0i64..2_000_000_000_000_000_000, b in 0i64..2_000_000_000_000_000_000) {
            // Within years 1970..=8307 the ISO string sorts like the ticks.
            let (sa, sb) = (iso(Ts::from_ticks(a, Precision::Tick)), iso(Ts::from_ticks(b, Precision::Tick)));
            prop_assert_eq!(a.cmp(&b), sa.cmp(&sb));
        }

        #[test]
        fn converters_never_panic(v in any::<i64>(), f in any::<f64>(), d in any::<u16>(), t in any::<u16>()) {
            let _ = Ts::from_unix_seconds(v).to_iso8601();
            let _ = Ts::from_unix_millis(v).to_iso8601();
            let _ = Ts::from_unix_micros(v).to_iso8601();
            let _ = Ts::from_unix_nanos(v).to_iso8601();
            let _ = Ts::from_webkit_micros(v).to_iso8601();
            let _ = Ts::from_filetime(v as u64).to_iso8601();
            let _ = Ts::from_ole_date(f).to_iso8601();
            let _ = Ts::from_cocoa_seconds(f).to_iso8601();
            let _ = Ts::from_dos(d, t).assume_offset(i32::MAX).to_iso8601();
        }
    }
}
