//! Release-freshness signal: publish-time tracking and cooldown-window checks.
//!
//! Mirrors GitHub Dependabot's default 3-day package cooldown: a version
//! published very recently is a distinct signal from one that has been live
//! for a while, independent of whether it is otherwise "the latest". This
//! module is deliberately minimal (a Unix-seconds newtype plus two free
//! functions) and stays confined to `deps-core` — ecosystem crates only ever
//! produce a [`PublishTime`], never touch the `time` crate directly.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Dependabot's default cooldown window (3 days), in seconds.
pub const DEFAULT_COOLDOWN_SECS: u64 = 3 * 24 * 60 * 60;

/// A release publish instant, normalized to Unix epoch seconds (UTC).
///
/// `Copy` and cheap to pass around, so it fits into `Box<dyn Version>`
/// trait objects without lifetime or allocation concerns.
///
/// # Examples
///
/// ```
/// use deps_core::PublishTime;
///
/// let published = PublishTime::parse_rfc3339("2026-07-18T23:05:13Z").unwrap();
/// let now = PublishTime::from_unix_secs(published.as_unix_secs() + 3600);
///
/// assert_eq!(published.age_secs_from(now), 3600);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublishTime(i64);

impl PublishTime {
    /// Returns the current time as a [`PublishTime`].
    ///
    /// Uses [`std::time::SystemTime`] rather than the `time` crate's own
    /// "now" APIs, so this module never needs the `local-offset`/
    /// `wasm-bindgen` features. A clock before the Unix epoch saturates to 0.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PublishTime;
    ///
    /// let now = PublishTime::now();
    /// assert!(now.as_unix_secs() > 0);
    /// ```
    #[must_use]
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs().cast_signed());
        Self(secs)
    }

    /// Builds a [`PublishTime`] directly from Unix epoch seconds.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PublishTime;
    ///
    /// let t = PublishTime::from_unix_secs(1_753_052_713);
    /// assert_eq!(t.as_unix_secs(), 1_753_052_713);
    /// ```
    #[must_use]
    pub const fn from_unix_secs(secs: i64) -> Self {
        Self(secs)
    }

    /// Builds a [`PublishTime`] from Unix epoch milliseconds, truncating to
    /// whole seconds.
    ///
    /// Kept for a future ecosystem whose registry reports millisecond
    /// timestamps (e.g. Maven's solrsearch `core=gav` API); unused by any
    /// v1 ecosystem, which all report second- or sub-second-precision
    /// RFC 3339 strings via [`PublishTime::parse_rfc3339`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PublishTime;
    ///
    /// let t = PublishTime::from_unix_millis(1_753_052_713_000);
    /// assert_eq!(t.as_unix_secs(), 1_753_052_713);
    /// ```
    #[must_use]
    pub const fn from_unix_millis(ms: i64) -> Self {
        Self(ms / 1000)
    }

    /// Parses an RFC 3339 timestamp string into a [`PublishTime`].
    ///
    /// Accepts every shape seen across v1 registries: a bare `Z` suffix,
    /// arbitrary fractional-second digits, and a numeric UTC offset
    /// (`+00:00`). Returns `None` on any parse failure — per [US-003], a
    /// missing or malformed timestamp degrades to pre-feature behavior
    /// rather than surfacing an error.
    ///
    /// [US-003]: https://github.com/bug-ops/deps-lsp/issues/145
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PublishTime;
    ///
    /// assert!(PublishTime::parse_rfc3339("2026-07-18T23:05:13Z").is_some());
    /// assert!(PublishTime::parse_rfc3339("2026-05-14T19:25:27.735762Z").is_some());
    /// assert!(PublishTime::parse_rfc3339("2026-01-02T08:56:05+00:00").is_some());
    /// assert!(PublishTime::parse_rfc3339("not a timestamp").is_none());
    /// assert!(PublishTime::parse_rfc3339("").is_none());
    /// ```
    #[must_use]
    pub fn parse_rfc3339(s: &str) -> Option<Self> {
        OffsetDateTime::parse(s, &Rfc3339)
            .ok()
            .map(|dt| Self(dt.unix_timestamp()))
    }

    /// Returns this instant as Unix epoch seconds.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PublishTime;
    ///
    /// let t = PublishTime::from_unix_secs(42);
    /// assert_eq!(t.as_unix_secs(), 42);
    /// ```
    #[must_use]
    pub const fn as_unix_secs(self) -> i64 {
        self.0
    }

    /// Age of this publish instant relative to `now`, in seconds.
    ///
    /// A `self` in the future relative to `now` (clock skew, or a registry
    /// timestamp bug) saturates to age `0` rather than underflowing or
    /// returning a negative duration — chosen because a slightly-ahead
    /// registry clock is exactly the "just published" case the freshness
    /// signal exists to surface, so clamping preserves the signal instead of
    /// silently losing it.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PublishTime;
    ///
    /// let published = PublishTime::from_unix_secs(1_000);
    /// let now = PublishTime::from_unix_secs(1_100);
    /// assert_eq!(published.age_secs_from(now), 100);
    ///
    /// // Clock skew: published "after" now clamps to 0, not a negative age.
    /// let future = PublishTime::from_unix_secs(2_000);
    /// assert_eq!(future.age_secs_from(now), 0);
    /// ```
    #[must_use]
    pub const fn age_secs_from(self, now: Self) -> u64 {
        // `saturating_sub` only guards against i64 overflow at the extremes;
        // the diff can still be negative (a future `self`), so clamp that
        // case to 0 explicitly before the `as u64` cast.
        let diff = now.0.saturating_sub(self.0);
        if diff < 0 { 0 } else { diff as u64 }
    }
}

/// Whether an age (in seconds) falls within a cooldown window (in seconds).
///
/// The bound is exclusive: `age_secs < cooldown_secs`. A version published
/// exactly `cooldown_secs` ago is **not** within cooldown; one published a
/// second earlier is. This is the single rule applied uniformly across
/// hover, diagnostics, and completion — no ecosystem overrides it.
///
/// Note the parameter order: **age first, cooldown second** — both are
/// plain `u64`, so a swapped call site would compile silently.
///
/// # Examples
///
/// ```
/// use deps_core::is_within_cooldown;
///
/// assert!(is_within_cooldown(100, 200));
/// assert!(!is_within_cooldown(200, 200));
/// assert!(is_within_cooldown(199, 200));
/// ```
#[must_use]
pub const fn is_within_cooldown(age_secs: u64, cooldown_secs: u64) -> bool {
    age_secs < cooldown_secs
}

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;
const MONTH: u64 = 30 * DAY;
const YEAR: u64 = 365 * DAY;

/// Pluralizes a unit label: `"1 minute ago"` vs `"5 minutes ago"`.
fn format_unit_ago(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{count} {unit}s ago")
    }
}

/// Formats an age in seconds as a coarse, human-readable relative duration.
///
/// Buckets by the largest whole unit that fits: minutes, hours, days, weeks,
/// months, years — pure duration bucketing on a `u64`, not calendar-aware
/// date arithmetic (no month/year length variation), so it needs no
/// timezone or leap-year handling.
///
/// # Examples
///
/// ```
/// use deps_core::format_relative_age;
///
/// assert_eq!(format_relative_age(0), "just now");
/// assert_eq!(format_relative_age(59), "just now");
/// assert_eq!(format_relative_age(60), "1 minute ago");
/// assert_eq!(format_relative_age(300), "5 minutes ago");
/// assert_eq!(format_relative_age(3600), "1 hour ago");
/// assert_eq!(format_relative_age(86_400), "1 day ago");
/// assert_eq!(format_relative_age(604_800), "1 week ago");
/// assert_eq!(format_relative_age(2_592_000), "1 month ago");
/// assert_eq!(format_relative_age(31_536_000), "1 year ago");
/// ```
#[must_use]
pub fn format_relative_age(age_secs: u64) -> String {
    if age_secs < MINUTE {
        "just now".to_string()
    } else if age_secs < HOUR {
        format_unit_ago(age_secs / MINUTE, "minute")
    } else if age_secs < DAY {
        format_unit_ago(age_secs / HOUR, "hour")
    } else if age_secs < WEEK {
        format_unit_ago(age_secs / DAY, "day")
    } else if age_secs < MONTH {
        format_unit_ago(age_secs / WEEK, "week")
    } else if age_secs < YEAR {
        format_unit_ago(age_secs / MONTH, "month")
    } else {
        format_unit_ago(age_secs / YEAR, "year")
    }
}

/// LSP-facing freshness settings, threaded into hover/diagnostics/completion.
///
/// A `Copy` DTO so it can be snapshotted from `deps-lsp`'s
/// `Arc<RwLock<DepsConfig>>` before an `.await` point (matching the existing
/// `CacheConfig` snapshot-before-await pattern) and passed by value into
/// `Ecosystem::generate_hover`/`generate_diagnostics`, without holding the
/// config lock across the call.
///
/// # Examples
///
/// ```
/// use deps_core::FreshnessSettings;
///
/// let settings = FreshnessSettings::default();
/// assert!(settings.enabled);
/// assert_eq!(settings.cooldown_secs, deps_core::DEFAULT_COOLDOWN_SECS);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessSettings {
    /// Whether the freshness signal is rendered at all.
    pub enabled: bool,
    /// Cooldown window, in seconds, below which a publish age is "recent".
    pub cooldown_secs: u64,
}

impl Default for FreshnessSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_secs: DEFAULT_COOLDOWN_SECS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- PublishTime::parse_rfc3339: one fixture per v1 ecosystem's wire format ---

    #[test]
    fn test_parse_rfc3339_cargo_bare_z() {
        let t = PublishTime::parse_rfc3339("2026-07-18T23:05:13Z").unwrap();
        assert_eq!(t.as_unix_secs(), 1_784_415_913);
    }

    #[test]
    fn test_parse_rfc3339_pypi_six_digit_fraction() {
        assert!(PublishTime::parse_rfc3339("2026-05-14T19:25:27.735762Z").is_some());
    }

    #[test]
    fn test_parse_rfc3339_composer_numeric_offset() {
        let a = PublishTime::parse_rfc3339("2026-01-02T08:56:05+00:00").unwrap();
        let b = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_parse_rfc3339_bundler_millisecond_fraction() {
        assert!(PublishTime::parse_rfc3339("2024-01-15T10:30:00.000Z").is_some());
    }

    #[test]
    fn test_parse_rfc3339_dart_fractional_form() {
        assert!(PublishTime::parse_rfc3339("2025-03-10T14:22:05.123Z").is_some());
    }

    #[test]
    fn test_parse_rfc3339_go_bare_z() {
        assert!(PublishTime::parse_rfc3339("2026-02-01T00:00:00Z").is_some());
    }

    #[test]
    fn test_parse_rfc3339_garbage_is_none() {
        assert!(PublishTime::parse_rfc3339("not-a-timestamp").is_none());
    }

    #[test]
    fn test_parse_rfc3339_empty_is_none() {
        assert!(PublishTime::parse_rfc3339("").is_none());
    }

    // --- age_secs_from / clock skew ---

    #[test]
    fn test_age_secs_from_future_timestamp_clamps_to_zero() {
        let now = PublishTime::from_unix_secs(1_000);
        let published_in_future = PublishTime::from_unix_secs(1_500);
        assert_eq!(published_in_future.age_secs_from(now), 0);
    }

    #[test]
    fn test_age_secs_from_normal_case() {
        let published = PublishTime::from_unix_secs(1_000);
        let now = PublishTime::from_unix_secs(1_360);
        assert_eq!(published.age_secs_from(now), 360);
    }

    #[test]
    fn test_age_secs_from_extreme_values_do_not_panic() {
        let published = PublishTime::from_unix_secs(i64::MIN);
        let now = PublishTime::from_unix_secs(i64::MAX);
        // Just must not overflow-panic; the exact saturated value is not load-bearing.
        let _ = published.age_secs_from(now);

        let published = PublishTime::from_unix_secs(i64::MAX);
        let now = PublishTime::from_unix_secs(i64::MIN);
        assert_eq!(published.age_secs_from(now), 0);
    }

    // --- is_within_cooldown boundary ---

    #[test]
    fn test_is_within_cooldown_future_timestamp_counts_as_within() {
        let now = PublishTime::from_unix_secs(1_000);
        let published_in_future = PublishTime::from_unix_secs(1_500);
        let age = published_in_future.age_secs_from(now);
        assert!(is_within_cooldown(age, DEFAULT_COOLDOWN_SECS));
    }

    #[test]
    fn test_is_within_cooldown_at_boundary_is_false() {
        assert!(!is_within_cooldown(200, 200));
    }

    #[test]
    fn test_is_within_cooldown_one_below_boundary_is_true() {
        assert!(is_within_cooldown(199, 200));
    }

    // --- format_relative_age bucket boundaries ---

    #[test]
    fn test_format_relative_age_just_now() {
        assert_eq!(format_relative_age(0), "just now");
        assert_eq!(format_relative_age(59), "just now");
    }

    #[test]
    fn test_format_relative_age_minutes() {
        assert_eq!(format_relative_age(60), "1 minute ago");
        assert_eq!(format_relative_age(119), "1 minute ago");
        assert_eq!(format_relative_age(300), "5 minutes ago");
        assert_eq!(format_relative_age(HOUR - 1), "59 minutes ago");
    }

    #[test]
    fn test_format_relative_age_hours() {
        assert_eq!(format_relative_age(HOUR), "1 hour ago");
        assert_eq!(format_relative_age(2 * HOUR), "2 hours ago");
        assert_eq!(format_relative_age(DAY - 1), "23 hours ago");
    }

    #[test]
    fn test_format_relative_age_days() {
        assert_eq!(format_relative_age(DAY), "1 day ago");
        assert_eq!(format_relative_age(3 * DAY), "3 days ago");
        assert_eq!(format_relative_age(WEEK - 1), "6 days ago");
    }

    #[test]
    fn test_format_relative_age_weeks() {
        assert_eq!(format_relative_age(WEEK), "1 week ago");
        assert_eq!(format_relative_age(2 * WEEK), "2 weeks ago");
        assert_eq!(format_relative_age(MONTH - 1), "4 weeks ago");
    }

    #[test]
    fn test_format_relative_age_months() {
        assert_eq!(format_relative_age(MONTH), "1 month ago");
        assert_eq!(format_relative_age(5 * MONTH), "5 months ago");
        assert_eq!(format_relative_age(YEAR - 1), "12 months ago");
    }

    #[test]
    fn test_format_relative_age_years() {
        assert_eq!(format_relative_age(YEAR), "1 year ago");
        assert_eq!(format_relative_age(2 * YEAR), "2 years ago");
    }

    // --- FreshnessSettings ---

    #[test]
    fn test_freshness_settings_default() {
        let settings = FreshnessSettings::default();
        assert!(settings.enabled);
        assert_eq!(settings.cooldown_secs, DEFAULT_COOLDOWN_SECS);
    }
}
