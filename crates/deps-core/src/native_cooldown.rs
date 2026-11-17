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
use std::path::{Path, PathBuf};

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
    pub fn from_count(_count: u64, _unit: TimeUnit) -> Result<TimeSpanValue, TimeSpanError> {
        todo!("native release-age gate: NativeTimeSpan::from_count")
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
    if count == 0 {
        return Ok(TimeSpanValue::Disabled);
    }
    let secs = count
        .checked_mul(unit.secs())
        .ok_or(TimeSpanError::Overflow)?;
    Ok(TimeSpanValue::Span(NativeTimeSpan { count, unit, secs }))
}

/// Parses uv's `exclude-newer` span grammar (friendly units and ISO 8601 durations).
///
/// # Errors
///
/// [`TimeSpanError::Malformed`] outside the grammar; [`TimeSpanError::Overflow`] when the span
/// exceeds `u64` seconds.
pub fn parse_uv_span(_raw: &str) -> Result<TimeSpanValue, TimeSpanError> {
    todo!("native release-age gate: parse_uv_span")
}

/// An absolute instant before which releases are eligible, as configured (`npm before`,
/// uv `exclude-newer` timestamps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeCutoff(PublishTime);

impl NativeCutoff {
    /// Parses an RFC 3339 timestamp.
    #[must_use]
    pub fn parse_rfc3339(_raw: &str) -> Option<Self> {
        todo!("native release-age gate: NativeCutoff::parse_rfc3339")
    }

    /// Parses npm's `before` value: an RFC 3339 timestamp or a date-only value at midnight UTC.
    #[must_use]
    pub fn parse_npm_date(_raw: &str) -> Option<Self> {
        todo!("native release-age gate: NativeCutoff::parse_npm_date")
    }
}

impl fmt::Display for NativeCutoff {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("native release-age gate: NativeCutoff Display")
    }
}

/// What a native setting restricts: a relative age or an absolute cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeLimit {
    /// Releases younger than the span are held.
    MinAge(NativeTimeSpan),
    /// Releases published after the cutoff are held, indefinitely.
    PublishedAfter(NativeCutoff),
}

/// How long a version stays held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeHold {
    /// Eligible again after this many seconds.
    For(u64),
    /// Never becomes eligible under the configured cutoff.
    Indefinite,
}

/// A PyPI package name restricted to characters safe to quote in a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PypiPackageLabel(String);

impl PypiPackageLabel {
    /// Wraps `name`, or `None` when it is empty or has a character outside PEP 508 names.
    #[must_use]
    pub fn new(_name: &str) -> Option<Self> {
        todo!("native release-age gate: PypiPackageLabel::new")
    }

    /// The label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
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
///     .window();
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
}

impl NativeCooldown {
    /// Builds a cooldown from a limit and its source.
    #[must_use]
    pub const fn new(limit: NativeLimit, source: NativeCooldownSource) -> Self {
        Self { limit, source }
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
        _published_at: Option<PublishTime>,
        _version: &ConcreteVersion,
        _now: PublishTime,
    ) -> Option<NativeHold> {
        todo!("native release-age gate: NativeCooldown::hold")
    }

    /// The configured span, as the user wrote it.
    // TODO(review): removed when the Cargo surfaces move to `hold`; panics for a cutoff limit.
    #[must_use]
    pub fn span(&self) -> NativeTimeSpan {
        match self.limit {
            NativeLimit::MinAge(span) => span,
            NativeLimit::PublishedAfter(_) => todo!("native release-age gate: span of a cutoff"),
        }
    }

    /// The configuration key this window came from.
    #[must_use]
    pub const fn source(&self) -> &NativeCooldownSource {
        &self.source
    }

    /// The window this cooldown enforces.
    #[must_use]
    pub fn window(&self) -> NativeWindow {
        NativeWindow::new(self.span())
    }
}

impl fmt::Display for NativeCooldown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            NativeCooldownSource::CargoGlobal => {
                write!(f, "cargo registry.global-min-publish-age = {}", self.span())
            }
            NativeCooldownSource::CargoRegistry { alias } => write!(
                f,
                "cargo registries.{}.min-publish-age = {}",
                alias.as_str(),
                self.span()
            ),
            NativeCooldownSource::NpmMinReleaseAge
            | NativeCooldownSource::NpmBefore
            | NativeCooldownSource::PnpmMinimumReleaseAge
            | NativeCooldownSource::BunMinimumReleaseAge
            | NativeCooldownSource::UvExcludeNewer
            | NativeCooldownSource::UvExcludeNewerPackage { .. } => {
                todo!("native release-age gate: Display for the npm-family and uv sources")
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

    /// Seconds until `version`, published at `published_at`, becomes eligible at `now`;
    /// `None` when it is eligible (no publish time, outside the window, or locked).
    #[must_use]
    pub fn remaining(
        &self,
        published_at: Option<PublishTime>,
        version: &ConcreteVersion,
        now: PublishTime,
    ) -> Option<u64> {
        let age = published_at?.age_secs_from(now);
        let window = self.cooldown.window();
        (window.contains(age) && !self.is_locked(version)).then(|| window.as_secs() - age)
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
        self.remaining(published_at, version, now).is_some()
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

/// Package-manager dialect an exemption list is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExemptionSyntax {
    /// npm `min-release-age-exclude` (minimatch `*` within one path segment).
    Npm,
    /// pnpm `minimumReleaseAgeExclude`.
    Pnpm,
    /// Bun `minimumReleaseAgeExcludes`.
    Bun,
    /// uv `exclude-newer-package` names.
    Uv,
}

/// Which versions of a package an exemption list releases from the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exemption {
    /// The package is not exempt.
    None,
    /// Every version of the package is exempt.
    AllVersions,
    /// Only the listed versions are exempt.
    Versions(Vec<String>),
}

/// Why an exemption list was rejected as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExemptionError {
    /// An entry uses syntax this reader does not support.
    #[error("unsupported exemption entry")]
    Unsupported,
    /// The list or one of its entries exceeds the size caps.
    #[error("exemption list too large")]
    TooLarge,
}

/// A parsed per-package exemption list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExemptionList {
    entries: Vec<String>,
}

impl ExemptionList {
    /// What the list exempts for the package `name`.
    #[must_use]
    pub fn lookup(&self, _name: &str) -> Exemption {
        todo!("native release-age gate: ExemptionList::lookup")
    }
}

/// Parses `entries` in the given dialect.
///
/// # Errors
///
/// [`ExemptionError`] when any entry is unsupported or a size cap is exceeded; the whole list is
/// rejected so a partially understood list never exempts more than the user wrote.
pub fn parse_exemptions(
    _entries: &[&str],
    _syntax: ExemptionSyntax,
) -> Result<ExemptionList, ExemptionError> {
    todo!("native release-age gate: parse_exemptions")
}

/// The directories whose repository-level config applies to one manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryScope {
    dirs: Vec<PathBuf>,
}

impl RepositoryScope {
    /// Scope from `manifest_dir` up to `root` inclusive, never including `home`.
    #[must_use]
    pub fn new(_manifest_dir: &Path, _root: &Path, _home: Option<&Path>) -> Self {
        todo!("native release-age gate: RepositoryScope::new")
    }

    /// The config directories, closest to the manifest first.
    #[must_use]
    pub fn config_dirs(&self) -> Vec<PathBuf> {
        self.dirs.clone()
    }
}
