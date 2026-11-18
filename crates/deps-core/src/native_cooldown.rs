//! Native package-manager publish-age windows (spec 099 Phase 1, #1982).
//!
//! Cargo can hold back releases younger than a configured age
//! (`registry.global-min-publish-age`, `registries.<name>.min-publish-age`). This module owns
//! the typed value for such a window ([`NativeCooldown`]), the shared duration grammar
//! ([`parse_time_span`]) and the read-time predicate ([`NativeGate`]) every surface applies to
//! the publish time of whatever version list it renders.
//!
//! The window is **explain-only**: surfaces name the hold and never propose a held version, but
//! no surface writes an older version in its place.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

mod exemption;
mod scope;

pub use exemption::{Exemption, ExemptionError, ExemptionList, ExemptionSyntax, parse_exemptions};
pub use scope::RepositoryScope;

use crate::lsp_helpers::{ResolvedCandidatesMap, ResolvedVersionsMap, VersionData};
use crate::{ConcreteVersion, CooldownWindow, Dependency, NormalizedName, PackageKey, PublishTime};

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;
/// Cargo's documented month length: 365.2425 days / 12.
const MONTH: u64 = 2_629_746;
const MAX_WINDOW_SECS: u64 = 10 * 365 * DAY;

/// Unit of a configured native time span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeUnit {
    /// Seconds.
    Second,
    /// Minutes.
    Minute,
    /// Hours.
    Hour,
    /// Days.
    Day,
    /// Weeks.
    Week,
    /// Months (2 629 746 seconds, as Cargo defines them).
    Month,
}

impl TimeUnit {
    const fn secs(self) -> u64 {
        match self {
            Self::Second => 1,
            Self::Minute => MINUTE,
            Self::Hour => HOUR,
            Self::Day => DAY,
            Self::Week => WEEK,
            Self::Month => MONTH,
        }
    }

    const fn singular(self) -> &'static str {
        match self {
            Self::Second => "second",
            Self::Minute => "minute",
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        let singular = word.strip_suffix('s').unwrap_or(word);
        [
            Self::Second,
            Self::Minute,
            Self::Hour,
            Self::Day,
            Self::Week,
            Self::Month,
        ]
        .into_iter()
        .find(|unit| unit.singular() == singular)
    }
}

/// A parsed, non-zero `<count> <unit>` span as the user configured it.
///
/// Keeps the configured count and unit (not just seconds) so [`NativeCooldown`]'s `Display`
/// can quote the setting back verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeTimeSpan {
    count: u64,
    unit: TimeUnit,
    secs: u64,
}

impl NativeTimeSpan {
    /// Builds a span from a configured count and unit.
    ///
    /// # Errors
    ///
    /// [`TimeSpanError::Overflow`] when the span does not fit in `u64` seconds.
    pub fn from_count(count: u64, unit: TimeUnit) -> Result<TimeSpanValue, TimeSpanError> {
        if count == 0 {
            return Ok(TimeSpanValue::Disabled);
        }
        let secs = count
            .checked_mul(unit.secs())
            .ok_or(TimeSpanError::Overflow)?;
        Ok(TimeSpanValue::Span(Self { count, unit, secs }))
    }

    /// The span length in seconds (unclamped).
    const fn as_secs(self) -> u64 {
        self.secs
    }
}

impl fmt::Display for NativeTimeSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plural = if self.count == 1 { "" } else { "s" };
        write!(f, "{} {}{plural}", self.count, self.unit.singular())
    }
}

/// Result of parsing a configured time span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSpanValue {
    /// Zero in any spelling: the window is turned off.
    Disabled,
    /// A non-zero span.
    Span(NativeTimeSpan),
}

/// Why a configured time span could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimeSpanError {
    /// The text is outside the supported `<integer> <unit>` grammar.
    #[error("not a valid time span")]
    Malformed,
    /// The span does not fit in `u64` seconds.
    #[error("time span overflows")]
    Overflow,
}

/// Parses Cargo's time-span grammar: `<integer>[ ]<unit>` or the bare `0`.
///
/// Units are `second`, `minute`, `hour`, `day`, `week` and `month` (singular or plural). Zero
/// in any spelling is [`TimeSpanValue::Disabled`]. Whitespace other than the single optional
/// separator, signs and fractions are rejected.
///
/// # Errors
///
/// [`TimeSpanError::Malformed`] when `raw` is outside the grammar;
/// [`TimeSpanError::Overflow`] when the count or the span in seconds exceeds `u64`.
///
/// # Examples
///
/// ```
/// use deps_core::native_cooldown::{TimeSpanError, TimeSpanValue, parse_time_span};
///
/// assert!(matches!(parse_time_span("7 days"), Ok(TimeSpanValue::Span(_))));
/// assert_eq!(parse_time_span("0"), Ok(TimeSpanValue::Disabled));
/// assert_eq!(parse_time_span("1.5 days"), Err(TimeSpanError::Malformed));
/// ```
pub fn parse_time_span(raw: &str) -> Result<TimeSpanValue, TimeSpanError> {
    if raw == "0" {
        return Ok(TimeSpanValue::Disabled);
    }
    let digits_len = raw.bytes().take_while(u8::is_ascii_digit).count();
    let (digits, rest) = raw.split_at(digits_len);
    if digits.is_empty() {
        return Err(TimeSpanError::Malformed);
    }
    let word = rest.strip_prefix(' ').unwrap_or(rest);
    let unit = TimeUnit::from_word(word).ok_or(TimeSpanError::Malformed)?;
    let count: u64 = digits.parse().map_err(|_| TimeSpanError::Overflow)?;
    NativeTimeSpan::from_count(count, unit)
}

/// Parses uv's `exclude-newer` span grammar (friendly units and ISO 8601 durations).
///
/// # Errors
///
/// [`TimeSpanError::Malformed`] outside the grammar; [`TimeSpanError::Overflow`] when the span
/// exceeds `u64` seconds.
///
/// # Examples
///
/// ```
/// use deps_core::native_cooldown::{TimeSpanError, TimeSpanValue, parse_uv_span};
///
/// assert!(matches!(parse_uv_span("7 days"), Ok(TimeSpanValue::Span(_))));
/// assert!(matches!(parse_uv_span("PT36H"), Ok(TimeSpanValue::Span(_))));
/// assert_eq!(parse_uv_span("0 days"), Ok(TimeSpanValue::Disabled));
/// assert_eq!(parse_uv_span("1 month"), Err(TimeSpanError::Malformed));
/// ```
pub fn parse_uv_span(raw: &str) -> Result<TimeSpanValue, TimeSpanError> {
    let parsed = match raw.strip_prefix(['P', 'p']) {
        Some(iso) => parse_iso_term(iso),
        None => split_count(raw).and_then(|(count, rest)| Some((count, friendly_unit(rest)?))),
    };
    let (count, unit) = parsed.ok_or(TimeSpanError::Malformed)?;
    NativeTimeSpan::from_count(count?, unit)
}

/// Parses Yarn's `npmMinimalAgeGate` duration (`ms` package grammar, unitless = minutes).
///
/// The grammar is `<number>[ms|s|m|h|d|w]` with `<number>` an integer or a decimal (`.5`,
/// `1.5`); no sign, no whitespace, no exponent. A bare number is minutes. An integer with a
/// unit keeps that unit; a fraction or `ms` is converted to seconds (rounded up) and shown in
/// the largest unit that divides it evenly. Zero in any spelling is
/// [`TimeSpanValue::Disabled`].
///
/// # Errors
///
/// [`TimeSpanError::Malformed`] outside the grammar; [`TimeSpanError::Overflow`] when the span
/// exceeds `u64` seconds.
///
/// # Examples
///
/// ```
/// use deps_core::native_cooldown::{TimeSpanError, TimeSpanValue, parse_yarn_duration};
///
/// assert!(matches!(parse_yarn_duration("7d"), Ok(TimeSpanValue::Span(_))));
/// assert!(matches!(parse_yarn_duration("1.5h"), Ok(TimeSpanValue::Span(_))));
/// assert_eq!(parse_yarn_duration("0"), Ok(TimeSpanValue::Disabled));
/// assert_eq!(parse_yarn_duration("${AGE}"), Err(TimeSpanError::Malformed));
/// ```
pub fn parse_yarn_duration(raw: &str) -> Result<TimeSpanValue, TimeSpanError> {
    let number = YarnNumber::split(raw).ok_or(TimeSpanError::Malformed)?;
    if number.mantissa_is_zero() {
        return Ok(TimeSpanValue::Disabled);
    }
    match (number.fraction_len, number.unit) {
        (0, YarnUnit::Exact(unit)) => {
            let count = number
                .mantissa
                .parse()
                .map_err(|_| TimeSpanError::Overflow)?;
            NativeTimeSpan::from_count(count, unit)
        }
        (fraction_len, unit) => number.rounded_span(fraction_len, unit),
    }
}

/// The unit suffix of a Yarn duration.
#[derive(Debug, Clone, Copy)]
enum YarnUnit {
    /// A whole unit the span can keep verbatim.
    Exact(TimeUnit),
    /// `ms`: always normalised through seconds.
    Millis,
}

/// A Yarn duration split into digits, the number of fraction digits and the unit.
struct YarnNumber {
    /// Integer and fraction digits concatenated, trailing fraction zeros removed.
    mantissa: String,
    fraction_len: u32,
    unit: YarnUnit,
}

impl YarnNumber {
    /// Largest fraction (after trailing-zero removal) accepted before reporting overflow.
    const MAX_FRACTION_DIGITS: u32 = 18;

    fn split(raw: &str) -> Option<Self> {
        let int_len = raw.bytes().take_while(u8::is_ascii_digit).count();
        let (int_digits, rest) = raw.split_at(int_len);
        let (fraction, rest) = match rest.strip_prefix('.') {
            Some(after) => {
                let len = after.bytes().take_while(u8::is_ascii_digit).count();
                if len == 0 {
                    return None;
                }
                after.split_at(len)
            }
            None => ("", rest),
        };
        if int_digits.is_empty() && fraction.is_empty() {
            return None;
        }
        let unit = match rest {
            "" | "m" => YarnUnit::Exact(TimeUnit::Minute),
            "s" => YarnUnit::Exact(TimeUnit::Second),
            "h" => YarnUnit::Exact(TimeUnit::Hour),
            "d" => YarnUnit::Exact(TimeUnit::Day),
            "w" => YarnUnit::Exact(TimeUnit::Week),
            "ms" => YarnUnit::Millis,
            _ => return None,
        };
        let fraction = fraction.trim_end_matches('0');
        Some(Self {
            mantissa: format!("{int_digits}{fraction}"),
            fraction_len: u32::try_from(fraction.len()).unwrap_or(u32::MAX),
            unit,
        })
    }

    fn mantissa_is_zero(&self) -> bool {
        self.mantissa.bytes().all(|b| b == b'0')
    }

    /// Converts to whole seconds (rounded up) and picks the largest unit dividing them evenly.
    fn rounded_span(
        &self,
        fraction_len: u32,
        unit: YarnUnit,
    ) -> Result<TimeSpanValue, TimeSpanError> {
        if fraction_len > Self::MAX_FRACTION_DIGITS {
            return Err(TimeSpanError::Overflow);
        }
        let unit_millis: u128 = match unit {
            YarnUnit::Exact(unit) => u128::from(unit.secs()) * 1000,
            YarnUnit::Millis => 1,
        };
        let mantissa: u128 = self.mantissa.parse().map_err(|_| TimeSpanError::Overflow)?;
        let scaled_millis = mantissa
            .checked_mul(unit_millis)
            .ok_or(TimeSpanError::Overflow)?;
        let denominator = 10_u128.pow(fraction_len) * 1000;
        let secs = u64::try_from(scaled_millis.div_ceil(denominator))
            .map_err(|_| TimeSpanError::Overflow)?;
        let unit = [
            TimeUnit::Week,
            TimeUnit::Day,
            TimeUnit::Hour,
            TimeUnit::Minute,
            TimeUnit::Second,
        ]
        .into_iter()
        .find(|unit| secs % unit.secs() == 0)
        .unwrap_or(TimeUnit::Second);
        NativeTimeSpan::from_count(secs / unit.secs(), unit)
    }
}

type CountAndUnit = (Result<u64, TimeSpanError>, TimeUnit);

/// Splits a leading digit run off `text`; the count is `Err(Overflow)` when it exceeds `u64`.
fn split_count(text: &str) -> Option<(Result<u64, TimeSpanError>, &str)> {
    let digits_len = text.bytes().take_while(u8::is_ascii_digit).count();
    let (digits, rest) = text.split_at(digits_len);
    (!digits.is_empty()).then(|| (digits.parse().map_err(|_| TimeSpanError::Overflow), rest))
}

/// A single-term ISO 8601 duration after the `P`: `<n>W`, `<n>D`, `T<n>H`, `T<n>M` or `T<n>S`.
///
/// Calendar units (`P1M`, `P1Y`) and combined terms (`P1DT2H`) are not matched.
fn parse_iso_term(iso: &str) -> Option<CountAndUnit> {
    let (time_part, body) = match iso.strip_prefix(['T', 't']) {
        Some(body) => (true, body),
        None => (false, iso),
    };
    let (count, designator) = split_count(body)?;
    let unit = match (time_part, designator.to_ascii_uppercase().as_str()) {
        (false, "W") => TimeUnit::Week,
        (false, "D") => TimeUnit::Day,
        (true, "H") => TimeUnit::Hour,
        (true, "M") => TimeUnit::Minute,
        (true, "S") => TimeUnit::Second,
        _ => return None,
    };
    Some((count, unit))
}

fn friendly_unit(rest: &str) -> Option<TimeUnit> {
    let word = rest.strip_prefix(' ').unwrap_or(rest).to_ascii_lowercase();
    match word.as_str() {
        "second" | "seconds" | "sec" | "secs" => Some(TimeUnit::Second),
        "minute" | "minutes" | "min" | "mins" => Some(TimeUnit::Minute),
        "hour" | "hours" | "hr" | "hrs" => Some(TimeUnit::Hour),
        "day" | "days" => Some(TimeUnit::Day),
        "week" | "weeks" | "wk" | "wks" => Some(TimeUnit::Week),
        _ => None,
    }
}

/// An absolute instant before which releases are eligible, as configured (`npm before`,
/// uv `exclude-newer` timestamps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeCutoff(PublishTime);

impl NativeCutoff {
    /// Parses an RFC 3339 timestamp.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::native_cooldown::NativeCutoff;
    ///
    /// let cutoff = NativeCutoff::parse_rfc3339("2026-01-01T02:00:00+02:00").unwrap();
    /// assert_eq!(cutoff.to_string(), "2026-01-01T00:00:00Z");
    /// assert!(NativeCutoff::parse_rfc3339("2026-01-01").is_none());
    /// ```
    #[must_use]
    pub fn parse_rfc3339(raw: &str) -> Option<Self> {
        PublishTime::parse_rfc3339(raw).map(Self)
    }

    /// Parses npm's `before` value: an RFC 3339 timestamp or a date-only value at midnight UTC.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::native_cooldown::NativeCutoff;
    ///
    /// let date = NativeCutoff::parse_npm_date("2026-01-01").unwrap();
    /// assert_eq!(Some(date), NativeCutoff::parse_rfc3339("2026-01-01T00:00:00Z"));
    /// assert!(NativeCutoff::parse_npm_date("soon").is_none());
    /// ```
    #[must_use]
    pub fn parse_npm_date(raw: &str) -> Option<Self> {
        let date_only = raw.len() == 10
            && raw.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 4 | 7) {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            });
        if date_only {
            PublishTime::parse_rfc3339(&format!("{raw}T00:00:00Z")).map(Self)
        } else {
            Self::parse_rfc3339(raw)
        }
    }
}

impl fmt::Display for NativeCutoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_unix_secs();
        let (days, day_secs) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            day_secs / 3600,
            day_secs % 3600 / 60,
            day_secs % 60
        )
    }
}

/// Proleptic Gregorian date of a day count since 1970-01-01 (the `civil_from_days` algorithm).
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// What a native setting restricts: a relative age or an absolute cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeLimit {
    /// Releases younger than the span are held.
    MinAge(NativeTimeSpan),
    /// Releases published after the cutoff are held, indefinitely.
    PublishedAfter(NativeCutoff),
}

impl fmt::Display for NativeLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MinAge(span) => span.fmt(f),
            Self::PublishedAfter(cutoff) => cutoff.fmt(f),
        }
    }
}

/// How long a version stays held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeHold {
    /// Eligible again after this many seconds.
    For(u64),
    /// Never becomes eligible under the configured cutoff.
    Indefinite,
}

impl NativeHold {
    /// The clause completing a hold sentence: how long until the version is eligible.
    #[must_use]
    pub fn eligibility_clause(self) -> String {
        match self {
            Self::For(secs) => format!("eligible in {}", crate::format_remaining_duration(secs)),
            Self::Indefinite => "not eligible while the cutoff stays in place".to_owned(),
        }
    }
}

/// Whether `name` is non-empty, at most `max_len` bytes, and ASCII alphanumerics plus `-_.`:
/// safe to quote in a diagnostic without sanitising.
fn is_safe_label(name: &str, max_len: usize) -> bool {
    !name.is_empty()
        && name.len() <= max_len
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A PyPI package name restricted to characters safe to quote in a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PypiPackageLabel(String);

impl PypiPackageLabel {
    /// Longest name accepted; PyPI names are short.
    const MAX_LEN: usize = 128;

    /// Wraps `name`, or `None` when it is empty or has a character outside PEP 508 names.
    #[must_use]
    pub fn new(name: &str) -> Option<Self> {
        is_safe_label(name, Self::MAX_LEN).then(|| Self(name.to_owned()))
    }

    /// The label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An npm scope key as written under `npmScopes` (no leading `@`), restricted to a charset safe
/// to quote in a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmScopeLabel(String);

impl NpmScopeLabel {
    /// Longest scope accepted (npm's own package-name limit).
    const MAX_LEN: usize = 214;

    /// Wraps `scope`, or `None` when it is empty, oversized or outside the safe charset.
    #[must_use]
    pub fn new(scope: &str) -> Option<Self> {
        is_safe_label(scope, Self::MAX_LEN).then(|| Self(scope.to_owned()))
    }

    /// The label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A uv index name as written in `[[tool.uv.index]] name = ...`, restricted like a
/// [`PypiPackageLabel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvIndexLabel(String);

impl UvIndexLabel {
    /// Wraps `name`, or `None` when it is empty, oversized or outside the safe charset.
    #[must_use]
    pub fn new(name: &str) -> Option<Self> {
        is_safe_label(name, PypiPackageLabel::MAX_LEN).then(|| Self(name.to_owned()))
    }

    /// The label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether a per-scope Yarn window was written in the file or is Yarn's own default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOrigin {
    /// The key is present in the configuration file.
    Configured,
    /// Yarn applies its built-in default; the file does not state the value.
    ManagerDefault,
}

/// A non-zero publish-age window, clamped to ten years.
///
/// # Examples
///
/// ```
/// use deps_core::native_cooldown::{
///     NativeCooldown, NativeCooldownSource, NativeLimit, TimeSpanValue, parse_time_span,
/// };
///
/// let Ok(TimeSpanValue::Span(span)) = parse_time_span("7 days") else { unreachable!() };
/// let window = NativeCooldown::new(NativeLimit::MinAge(span), NativeCooldownSource::CargoGlobal)
///     .age_window()
///     .unwrap();
/// assert!(window.contains(3600));
/// assert!(!window.contains(7 * 86_400));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeWindow(CooldownWindow);

impl NativeWindow {
    /// Builds the window for `span`, clamping absurd values to ten years.
    fn new(span: NativeTimeSpan) -> Self {
        Self(CooldownWindow::from_secs(
            span.as_secs().min(MAX_WINDOW_SECS),
        ))
    }

    /// Whether a publish age in seconds falls inside the window (the bound is exclusive).
    #[must_use]
    pub const fn contains(self, age_secs: u64) -> bool {
        self.0.contains(age_secs)
    }

    /// The window length in seconds (after clamping).
    const fn as_secs(self) -> u64 {
        self.0.as_secs()
    }
}

/// A registry alias as written in `[registries.<alias>]`, restricted to what Cargo itself
/// accepts for a registry name (ASCII letters, digits, `-` and `_`).
///
/// The restriction makes the alias safe to quote in a diagnostic or hover without sanitising,
/// even though it comes from repository-controlled configuration.
///
/// # Examples
///
/// ```
/// use deps_core::native_cooldown::RegistryAlias;
///
/// assert!(RegistryAlias::new("corp-mirror_2").is_some());
/// assert!(RegistryAlias::new("bad name`").is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryAlias(String);

impl RegistryAlias {
    /// Longest alias accepted; real registry names are short.
    const MAX_LEN: usize = 64;

    /// Wraps `alias`, or `None` when it is empty, too long, or has a character Cargo does not
    /// allow in a registry name.
    #[must_use]
    pub fn new(alias: &str) -> Option<Self> {
        let valid = !alias.is_empty()
            && alias.len() <= Self::MAX_LEN
            && alias
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        valid.then(|| Self(alias.to_owned()))
    }

    /// The alias text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which configuration key a native window came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeCooldownSource {
    /// `registry.global-min-publish-age`.
    CargoGlobal,
    /// `registries.<alias>.min-publish-age`.
    CargoRegistry {
        /// The registry the key belongs to.
        alias: RegistryAlias,
    },
    /// npm `min-release-age` in `.npmrc`.
    NpmMinReleaseAge,
    /// npm `before` in `.npmrc`.
    NpmBefore,
    /// pnpm `minimumReleaseAge` in `pnpm-workspace.yaml`.
    PnpmMinimumReleaseAge,
    /// Bun `minimumReleaseAge` in `bunfig.toml`.
    BunMinimumReleaseAge,
    /// uv `exclude-newer`.
    UvExcludeNewer,
    /// uv `exclude-newer-package` for one package.
    UvExcludeNewerPackage {
        /// The package the override belongs to.
        package: PypiPackageLabel,
    },
    /// Yarn `npmMinimalAgeGate` in `.yarnrc.yml`.
    YarnNpmMinimalAgeGate,
    /// Yarn `npmScopes.<scope>.npmMinimalAgeGate` in `.yarnrc.yml`.
    YarnScopeNpmMinimalAgeGate {
        /// The scope the key belongs to.
        scope: NpmScopeLabel,
        /// Whether the window was written or is Yarn's default.
        origin: GateOrigin,
    },
    /// uv `index.<name>.exclude-newer`.
    UvIndexExcludeNewer {
        /// The index the key belongs to.
        index: UvIndexLabel,
    },
}

/// A native window together with the setting it came from.
///
/// # Examples
///
/// ```
/// use deps_core::native_cooldown::{
///     NativeCooldown, NativeCooldownSource, NativeLimit, TimeSpanValue, parse_time_span,
/// };
///
/// let Ok(TimeSpanValue::Span(span)) = parse_time_span("7 days") else { unreachable!() };
/// let cooldown = NativeCooldown::new(NativeLimit::MinAge(span), NativeCooldownSource::CargoGlobal);
/// assert_eq!(cooldown.to_string(), "cargo registry.global-min-publish-age = 7 days");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCooldown {
    limit: NativeLimit,
    source: NativeCooldownSource,
    exempt_versions: Arc<[ConcreteVersion]>,
}

impl NativeCooldown {
    /// Builds a cooldown from a limit and its source.
    #[must_use]
    pub fn new(limit: NativeLimit, source: NativeCooldownSource) -> Self {
        Self {
            limit,
            source,
            exempt_versions: Arc::from([]),
        }
    }

    /// Releases the listed exact versions from the limit (`name@version` exemptions).
    #[must_use]
    pub fn with_exempt_versions(mut self, versions: Arc<[ConcreteVersion]>) -> Self {
        self.exempt_versions = versions;
        self
    }

    /// The configured limit.
    #[must_use]
    pub const fn limit(&self) -> &NativeLimit {
        &self.limit
    }

    /// Whether `version`, published at `published_at`, is held at `now`, and for how long.
    ///
    /// Lock membership is not consulted; callers apply it on top.
    #[must_use]
    pub fn hold(
        &self,
        published_at: Option<PublishTime>,
        version: &ConcreteVersion,
        now: PublishTime,
    ) -> Option<NativeHold> {
        if self.exempt_versions.contains(version) {
            return None;
        }
        let published_at = published_at?;
        match self.limit {
            NativeLimit::MinAge(span) => {
                let window = NativeWindow::new(span);
                let age = published_at.age_secs_from(now);
                window
                    .contains(age)
                    .then(|| NativeHold::For(window.as_secs() - age))
            }
            NativeLimit::PublishedAfter(cutoff) => (published_at.as_unix_secs()
                > cutoff.0.as_unix_secs())
            .then_some(NativeHold::Indefinite),
        }
    }

    /// The configuration key this window came from.
    #[must_use]
    pub const fn source(&self) -> &NativeCooldownSource {
        &self.source
    }

    /// The relative-age window this cooldown enforces; `None` for an absolute cutoff.
    #[must_use]
    pub fn age_window(&self) -> Option<NativeWindow> {
        match self.limit {
            NativeLimit::MinAge(span) => Some(NativeWindow::new(span)),
            NativeLimit::PublishedAfter(_) => None,
        }
    }
}

impl fmt::Display for NativeCooldown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let limit = &self.limit;
        match &self.source {
            NativeCooldownSource::CargoGlobal => {
                write!(f, "cargo registry.global-min-publish-age = {limit}")
            }
            NativeCooldownSource::CargoRegistry { alias } => {
                write!(
                    f,
                    "cargo registries.{}.min-publish-age = {limit}",
                    alias.as_str()
                )
            }
            NativeCooldownSource::NpmMinReleaseAge => {
                write!(f, "npm min-release-age = {limit}")
            }
            NativeCooldownSource::NpmBefore => write!(f, "npm before = {limit}"),
            NativeCooldownSource::PnpmMinimumReleaseAge => {
                write!(f, "pnpm minimumReleaseAge = {limit}")
            }
            NativeCooldownSource::BunMinimumReleaseAge => {
                write!(f, "bun minimumReleaseAge = {limit}")
            }
            NativeCooldownSource::UvExcludeNewer => write!(f, "uv exclude-newer = {limit}"),
            NativeCooldownSource::UvExcludeNewerPackage { package } => {
                write!(f, "uv exclude-newer-package.{} = {limit}", package.as_str())
            }
            NativeCooldownSource::YarnNpmMinimalAgeGate => {
                write!(f, "yarn npmMinimalAgeGate = {limit}")
            }
            NativeCooldownSource::YarnScopeNpmMinimalAgeGate { scope, origin } => {
                write!(
                    f,
                    "yarn npmScopes.{}.npmMinimalAgeGate = {limit}",
                    scope.as_str()
                )?;
                match origin {
                    GateOrigin::Configured => Ok(()),
                    GateOrigin::ManagerDefault => f.write_str(" (Yarn default)"),
                }
            }
            NativeCooldownSource::UvIndexExcludeNewer { index } => {
                write!(f, "uv index.{}.exclude-newer = {limit}", index.as_str())
            }
        }
    }
}

/// Read-time predicate deciding whether a version is held back by a native window.
///
/// Built per dependency from the dependency's own window and the lock maps of a
/// [`VersionData`], and applied to the publish time of whatever version list a surface renders
/// (live or cached). A version that appears in the lock file stays eligible: the package
/// manager keeps resolving what it already locked.
#[derive(Debug, Clone)]
pub struct NativeGate<'a> {
    cooldown: &'a NativeCooldown,
    name: NormalizedName,
    resolved: &'a ResolvedVersionsMap,
    candidates: Option<&'a ResolvedCandidatesMap>,
    now: PublishTime,
}

impl<'a> NativeGate<'a> {
    /// Builds the gate for `dep`, or `None` when it has no native window.
    #[must_use]
    pub fn for_dependency(
        dep: &'a dyn Dependency,
        key: &PackageKey,
        versions: &VersionData<'a>,
    ) -> Option<Self> {
        Some(Self::for_name(
            dep.native_cooldown()?,
            key.normalized(),
            versions,
        ))
    }

    /// Builds the gate for the package `name` under a window already resolved for it, reading
    /// the lock maps and the instant from `versions`.
    #[must_use]
    pub fn for_name(
        cooldown: &'a NativeCooldown,
        name: &NormalizedName,
        versions: &VersionData<'a>,
    ) -> Self {
        Self {
            cooldown,
            name: name.clone(),
            resolved: versions.resolved_map(),
            candidates: versions.candidates_map(),
            now: versions.now,
        }
    }

    /// The cooldown this gate enforces, for wording.
    #[must_use]
    pub const fn cooldown(&self) -> &'a NativeCooldown {
        self.cooldown
    }

    /// The instant this gate judges against: [`VersionData::now`] at construction.
    #[must_use]
    pub const fn now(&self) -> PublishTime {
        self.now
    }

    fn is_locked(&self, version: &ConcreteVersion) -> bool {
        self.resolved.get(&self.name) == Some(version)
            || self
                .candidates
                .and_then(|candidates| candidates.get(&self.name))
                .is_some_and(|candidates| candidates.versions().contains(version))
    }

    /// How long `version`, published at `published_at`, stays held at `now`; `None` when it
    /// is eligible (no publish time, outside the limit, or locked).
    #[must_use]
    pub fn hold(
        &self,
        published_at: Option<PublishTime>,
        version: &ConcreteVersion,
        now: PublishTime,
    ) -> Option<NativeHold> {
        if self.is_locked(version) {
            return None;
        }
        self.cooldown.hold(published_at, version, now)
    }

    /// Whether `version`, published at `published_at`, is held back at `now`.
    ///
    /// A missing publish time is eligible, matching Cargo. A future publish time counts as age
    /// zero, so it is held.
    #[must_use]
    pub fn excludes(
        &self,
        published_at: Option<PublishTime>,
        version: &ConcreteVersion,
        now: PublishTime,
    ) -> bool {
        self.hold(published_at, version, now).is_some()
    }
}

/// The native window of each package of `parse_result` that has one, by normalized name.
///
/// For consumers that judge packages by name rather than by dependency (the CLI's
/// cooldown-fallback view). A name is listed only when **every** dependency of that name carries
/// the same window: a crate declared from crates.io (window) and also from a git, path or other
/// registry source (different or no window) is ambiguous by name, so it is left out and the
/// per-dependency gate alone decides.
#[must_use]
pub fn native_cooldowns_by_name(
    parse_result: &dyn crate::ParsedManifest,
) -> HashMap<NormalizedName, NativeCooldown> {
    let mut seen: HashMap<NormalizedName, Option<NativeCooldown>> = HashMap::new();
    parse_result.for_each_formatted_dependency(&mut |bound| {
        let dependency = bound.dependency();
        let key = PackageKey::new(dependency.name(), bound.formatter());
        let cooldown = dependency.native_cooldown().cloned();
        seen.entry(key.normalized().clone())
            .and_modify(|existing| {
                if *existing != cooldown {
                    *existing = None;
                }
            })
            .or_insert(cooldown);
    });
    seen.into_iter()
        .filter_map(|(name, cooldown)| Some((name, cooldown?)))
        .collect()
}
