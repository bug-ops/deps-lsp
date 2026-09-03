//! Shared LSP response builders.

use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp_server::ls_types::{Position, Range, TextEdit, Uri};

use crate::osv::VulnerabilityMap;
use crate::{
    ConcreteVersion, Deprecation, DepsDevClient, EcosystemId, FetchFailure, PackageName,
    RemovalStatus,
};

mod code_actions;
mod code_lenses;
mod diagnostics;
mod formatter;
mod hover;
mod in_use_version;
mod inlay_hints;
#[cfg(test)]
mod test_support;

pub use code_actions::generate_code_actions;
pub use code_lenses::{collect_update_all_edits, generate_code_lenses};
pub use diagnostics::{
    DEPRECATED_DIAGNOSTIC_CODE, DiagnosticSeverities, UNSATISFIABLE_DIAGNOSTIC_CODE,
    compile_requirement_unless, generate_diagnostics_from_cache, requirement_is_unsatisfiable,
    truncate_for_diagnostic,
};
pub use formatter::{
    DiagnosticMessages, DiagnosticPolicy, EcosystemFormatter, OsvNaming, PackageNaming,
    PackageRendering, RequirementResolution, SourcePolicy,
};
pub use hover::{CMD_DOT_FOOTER, generate_hover};
pub use in_use_version::{concrete_pin_version, in_use_version, is_full_semver_shape};
pub use inlay_hints::generate_inlay_hints;

/// Maximum number of recent versions hover's "Recent versions" section renders.
///
/// Also the walk target for registries (NuGet, npm) that must fetch publish times for
/// only the versions actually rendered, rather than the entire version history.
pub const HOVER_RECENT_VERSIONS: usize = 8;

/// Registry version data for one package, fetched together in a single round trip.
///
/// `latest` and `available` are deliberately asymmetric — this is load-bearing, not an
/// oversight:
/// - `latest` comes from this ecosystem's own `Registry::select_latest_matching(.., "*")`
///   pick, which excludes yanked (and, for semver/node-semver `*`, prerelease) versions —
///   the same value `get_latest_matching` returned before this type existed.
/// - `available` is the **unfiltered** `get_versions` output: every published version,
///   newest-first, yanked and prerelease entries included.
///
/// The unsatisfiable-requirement check (see `crate::lsp_helpers::requirement_is_unsatisfiable`)
/// scans `available` and deliberately does not filter it: a requirement that only matches a
/// yanked or prerelease version is still satisfied, so filtering `available` the same way
/// `latest` is filtered would produce false "no published version satisfies" warnings.
///
/// `yanked` is the subset of `available` (same version-string encoding) that the registry
/// reported as yanked/deprecated, paired with each entry's [`RemovalStatus`]. It exists
/// because `Registry::get_latest_matching` — the call that used to populate this cache —
/// filters yanked entries out by contract on every current registry implementation, so a
/// per-version yanked flag threaded through *that* call would always read `false` (see
/// #233). `available` now comes from the unfiltered `get_versions` instead, which does
/// observe yanked entries, so `yanked` is derived from that same fetch rather than
/// discarded.
///
/// The status rides alongside each version (rather than a bare membership list) so
/// [`crate::lsp_helpers::generate_diagnostics_from_cache`]'s #247 "requirement satisfiable
/// only by a yanked version" check can gate its own package-level-deprecation suppression
/// on `AdvisoryDeprecated` specifically, never on a genuine `Yanked` finding — mirroring
/// [`VersionData::outcomes`]'s D5 gate for the #263 in-use-version check (see #437).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVersions {
    /// Latest usable version for this package.
    pub latest: ConcreteVersion,
    /// Every published version, newest-first, unfiltered.
    pub available: Arc<[ConcreteVersion]>,
    /// Subset of `available` reported as yanked/deprecated by the registry, each paired
    /// with its [`RemovalStatus`].
    pub yanked: Arc<[(ConcreteVersion, RemovalStatus)]>,
    /// When `latest` was published, if the registry exposes it. `None` when
    /// the ecosystem doesn't wire [`crate::Version::published_at`] or the fetch
    /// never ran.
    ///
    /// Deliberately a field on this single per-package struct rather than a
    /// second parallel map keyed alongside `latest` — the earlier two-map
    /// design (issue #227 critique C3) let `latest` and its age drift apart
    /// silently whenever one map was updated (e.g. lockfile-resolved
    /// overwrite) without the other. Bundling them here makes that
    /// desync impossible: whoever sets `latest` sets `published_at` too.
    pub published_at: Option<crate::freshness::PublishTime>,
}

impl PackageVersions {
    /// Builds a `PackageVersions` from only the "latest" version string, with `available`
    /// populated as the single-element list `[latest]`.
    ///
    /// **Test-only in intent.** The one-element `available` this produces is a real, if
    /// small, version list — it is not "empty/unknown", so `requirement_is_unsatisfiable`
    /// will evaluate a requirement against it. Do **not** use this for a lock-file-only
    /// population path that has no real version list to offer (use
    /// [`latest_without_list`](Self::latest_without_list) there instead, which leaves
    /// `available` genuinely empty) — that exact substitution is the false-positive N5 was
    /// written to prevent: it would let the unsatisfiable-requirement check produce a
    /// verdict against a fabricated one-entry list before any registry fetch has run. Real
    /// registry fetches always populate `available` from the full `get_versions` result
    /// instead of using either constructor.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{ConcreteVersion, PackageVersions};
    ///
    /// let versions = PackageVersions::latest_only("1.0.214");
    /// assert_eq!(versions.latest, "1.0.214");
    /// assert_eq!(&*versions.available, &[ConcreteVersion::new("1.0.214")]);
    /// ```
    pub fn latest_only(latest: impl Into<ConcreteVersion>) -> Self {
        let latest = latest.into();
        let available = Arc::from(vec![latest.clone()]);
        Self {
            latest,
            available,
            yanked: Arc::from(Vec::new()),
            published_at: None,
        }
    }

    /// Builds a `PackageVersions` with no version list — used where only the "latest" value
    /// is known and probing further would be misleading, notably the lock-file population
    /// path (`crates/deps-lsp/src/document/lifecycle.rs`), which must not populate a
    /// plausible-looking one-element `available` list before any registry fetch has run: the
    /// unsatisfiable-requirement check treats an empty `available` as "still loading, skip".
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageVersions;
    ///
    /// let versions = PackageVersions::latest_without_list("1.0.195");
    /// assert_eq!(versions.latest, "1.0.195");
    /// assert!(versions.available.is_empty());
    /// ```
    pub fn latest_without_list(latest: impl Into<ConcreteVersion>) -> Self {
        Self {
            latest: latest.into(),
            available: Arc::from(Vec::new()),
            yanked: Arc::from(Vec::new()),
            published_at: None,
        }
    }
}

/// Everything the lifecycle fetch learned about one package, keyed by its normalized name.
///
/// All three channels can hold simultaneously for the same package — this is load-bearing,
/// not an incidental shape. The D5 status gate in
/// [`generate_diagnostics_from_cache`] reads the [`Self::deprecation`] and [`Self::yanked`]
/// entries for the same normalized name together and compares their [`RemovalStatus`], and on
/// the didChange path a surviving deprecation can coexist with a later fetch failure. A single
/// enum variant per package could not express that overlap.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DependencyOutcome {
    /// The version found yanked (the in-use version, or `latest` when only `latest` itself is
    /// yanked), paired with its [`RemovalStatus`]. See [`VersionData::outcomes`]'s prior
    /// semantics (#233/#263).
    pub yanked: Option<(ConcreteVersion, RemovalStatus)>,
    /// Package-level deprecation finding (#205). See [`Deprecation`].
    pub deprecation: Option<Deprecation>,
    /// Registry fetch errored, timed out, or was never attempted (#267). See [`FetchFailure`].
    pub fetch_failure: Option<FetchFailure>,
    /// The registry fetch succeeded (no [`Self::fetch_failure`]) but produced zero
    /// comparable versions — e.g. a real GitHub repository whose only tags don't parse
    /// as full `major.minor.patch` semver (`dtolnay/rust-toolchain`'s sole tag `v1`,
    /// issue #550). Distinct from both an absent [`DependencyOutcome`] entry ("never
    /// fetched") and [`Self::fetch_failure`] ("couldn't be asked"): this package
    /// demonstrably exists, so [R5](crate::lsp_helpers::generate_diagnostics_from_cache)
    /// must not claim it is unknown.
    pub no_comparable_versions: bool,
}

impl DependencyOutcome {
    /// True when none of the four channels are set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.yanked.is_none()
            && self.deprecation.is_none()
            && self.fetch_failure.is_none()
            && !self.no_comparable_versions
    }
}

/// Normalized-package-name -> [`DependencyOutcome`] map.
///
/// A newtype rather than a bare `HashMap` so the empty-entry pruning invariant (an entry is
/// removed once all three of its channels are cleared) lives in one place, and so test
/// fixtures get chainable `with_*` constructors instead of building three ad-hoc `HashMap`s.
/// Mirrors the existing [`crate::osv::VulnerabilityMap`] convention of a `String`-keyed map by
/// normalized name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DependencyOutcomes(HashMap<String, DependencyOutcome>);

impl DependencyOutcomes {
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up the full outcome recorded for `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&DependencyOutcome> {
        self.0.get(name)
    }

    /// Looks up the yanked-version finding for `name`.
    #[must_use]
    pub fn yanked(&self, name: &str) -> Option<&(ConcreteVersion, RemovalStatus)> {
        self.0.get(name)?.yanked.as_ref()
    }

    /// Looks up the package-level deprecation finding for `name`.
    #[must_use]
    pub fn deprecation(&self, name: &str) -> Option<&Deprecation> {
        self.0.get(name)?.deprecation.as_ref()
    }

    /// Looks up the fetch-failure finding for `name`.
    #[must_use]
    pub fn fetch_failure(&self, name: &str) -> Option<&FetchFailure> {
        self.0.get(name)?.fetch_failure.as_ref()
    }

    /// True when the registry fetch for `name` succeeded but produced zero comparable
    /// versions (#550). See [`DependencyOutcome::no_comparable_versions`].
    #[must_use]
    pub fn no_comparable_versions(&self, name: &str) -> bool {
        self.0.get(name).is_some_and(|o| o.no_comparable_versions)
    }

    /// Records a yanked-version finding for `name`, creating the entry if absent.
    pub fn set_yanked(&mut self, name: String, yanked: (ConcreteVersion, RemovalStatus)) {
        self.0.entry(name).or_default().yanked = Some(yanked);
    }

    /// Records a package-level deprecation finding for `name`, creating the entry if absent.
    pub fn set_deprecation(&mut self, name: String, deprecation: Deprecation) {
        self.0.entry(name).or_default().deprecation = Some(deprecation);
    }

    /// Records a fetch-failure finding for `name`, creating the entry if absent.
    pub fn set_fetch_failure(&mut self, name: String, failure: FetchFailure) {
        self.0.entry(name).or_default().fetch_failure = Some(failure);
    }

    /// Records a fetch-failure finding for `name` only if one is not already recorded,
    /// creating the entry if absent.
    pub fn set_fetch_failure_if_absent(&mut self, name: String, failure: FetchFailure) {
        self.0
            .entry(name)
            .or_default()
            .fetch_failure
            .get_or_insert(failure);
    }

    /// Records that `name`'s registry fetch succeeded but produced zero comparable
    /// versions (#550), creating the entry if absent.
    pub fn set_no_comparable_versions(&mut self, name: String) {
        self.0.entry(name).or_default().no_comparable_versions = true;
    }

    /// Clears the no-comparable-versions channel for `name`, pruning the entry if it
    /// becomes empty.
    pub fn clear_no_comparable_versions(&mut self, name: &str) {
        if let Some(entry) = self.0.get_mut(name) {
            entry.no_comparable_versions = false;
            self.prune(name);
        }
    }

    /// Clears the yanked-version channel for `name`, pruning the entry if it becomes empty.
    pub fn clear_yanked(&mut self, name: &str) {
        if let Some(entry) = self.0.get_mut(name) {
            entry.yanked = None;
            self.prune(name);
        }
    }

    /// Clears the deprecation channel for `name`, pruning the entry if it becomes empty.
    pub fn clear_deprecation(&mut self, name: &str) {
        if let Some(entry) = self.0.get_mut(name) {
            entry.deprecation = None;
            self.prune(name);
        }
    }

    /// Clears the fetch-failure channel for `name`, pruning the entry if it becomes empty.
    pub fn clear_fetch_failure(&mut self, name: &str) {
        if let Some(entry) = self.0.get_mut(name) {
            entry.fetch_failure = None;
            self.prune(name);
        }
    }

    /// Removes the whole entry for `name`, regardless of which channels are set.
    pub fn remove(&mut self, name: &str) {
        self.0.remove(name);
    }

    fn prune(&mut self, name: &str) {
        if self.0.get(name).is_some_and(DependencyOutcome::is_empty) {
            self.0.remove(name);
        }
    }

    /// Number of entries currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when no entries are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of entries with a yanked-version finding, for logging/`Debug`.
    #[must_use]
    pub fn yanked_count(&self) -> usize {
        self.0.values().filter(|o| o.yanked.is_some()).count()
    }

    /// Number of entries with a deprecation finding, for logging/`Debug`.
    #[must_use]
    pub fn deprecation_count(&self) -> usize {
        self.0.values().filter(|o| o.deprecation.is_some()).count()
    }

    /// Number of entries with a fetch-failure finding, for logging/`Debug`.
    #[must_use]
    pub fn fetch_failure_count(&self) -> usize {
        self.0
            .values()
            .filter(|o| o.fetch_failure.is_some())
            .count()
    }

    /// Chainable builder recording a yanked-version finding. Test/fixture ergonomics.
    #[must_use]
    pub fn with_yanked(
        mut self,
        name: impl Into<String>,
        yanked: (ConcreteVersion, RemovalStatus),
    ) -> Self {
        self.set_yanked(name.into(), yanked);
        self
    }

    /// Chainable builder recording a package-level deprecation finding. Test/fixture
    /// ergonomics.
    #[must_use]
    pub fn with_deprecation(mut self, name: impl Into<String>, deprecation: Deprecation) -> Self {
        self.set_deprecation(name.into(), deprecation);
        self
    }

    /// Chainable builder recording a fetch-failure finding. Test/fixture ergonomics.
    #[must_use]
    pub fn with_fetch_failure(mut self, name: impl Into<String>, failure: FetchFailure) -> Self {
        self.set_fetch_failure(name.into(), failure);
        self
    }

    /// Chainable builder recording a no-comparable-versions finding (#550). Test/fixture
    /// ergonomics.
    #[must_use]
    pub fn with_no_comparable_versions(mut self, name: impl Into<String>) -> Self {
        self.set_no_comparable_versions(name.into());
        self
    }
}

/// Bundles the two per-package version maps (`cached`, `resolved`) that LSP handlers pass
/// together everywhere.
///
/// Grouping them prevents accidentally swapping the two map arguments at a call site, since
/// the compiler can no longer typecheck them positionally.
///
/// # Examples
///
/// ```
/// use deps_core::{ConcreteVersion, PackageName, PackageVersions, VersionData};
/// use std::collections::HashMap;
///
/// let mut cached = HashMap::new();
/// cached.insert(PackageName::new("serde"), PackageVersions::latest_only("1.0.214"));
///
/// let mut resolved = HashMap::new();
/// resolved.insert(PackageName::new("serde"), ConcreteVersion::new("1.0.200"));
///
/// let versions = VersionData::new(&cached, &resolved);
///
/// assert_eq!(versions.cached.get("serde").map(|v| v.latest.as_str()), Some("1.0.214"));
/// assert_eq!(versions.resolved.get("serde").map(ConcreteVersion::as_str), Some("1.0.200"));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct VersionData<'a> {
    /// Latest known versions and full version lists from the registry, keyed by package name.
    pub cached: &'a HashMap<PackageName, PackageVersions>,
    /// Versions actually resolved in the lock file, keyed by package name.
    pub resolved: &'a HashMap<PackageName, ConcreteVersion>,
    /// OSV scan results, keyed by normalized package name. `None` when no
    /// scan has run yet (e.g. the feature is disabled) — distinct from an
    /// empty map, which would mean "scanned, nothing found".
    pub vulnerabilities: Option<&'a VulnerabilityMap>,
    /// Yanked, deprecation, and fetch-failure findings from the most recent lifecycle fetch,
    /// keyed by normalized package name — see [`DependencyOutcome`] for what each channel
    /// means and why they must stay readable together off one lookup (D5 in
    /// [`generate_diagnostics_from_cache`], #233/#263/#205/#267). `None` when no fetch has run
    /// yet — distinct from an empty map, which would mean "checked, nothing found".
    pub outcomes: Option<&'a DependencyOutcomes>,
    /// This document's ecosystem, when the caller has one to give. `None` in
    /// most test fixtures and a handful of ecosystem-crate self-tests that
    /// predate this field.
    ///
    /// Enables two occurrence-aware refinements added for #394 (duplicate
    /// dependency names no longer collapsing into one shared finding):
    /// [`generate_diagnostics_from_cache`] only emits a yanked-version
    /// diagnostic on the occurrence whose own in-use version actually
    /// matches the recorded finding (S1), and the vulnerability lookups in
    /// `generate_diagnostics_from_cache`, [`generate_hover`], and
    /// `generate_code_actions` prefer a version-qualified
    /// [`crate::osv::VulnerabilityMap`] key over the plain name when more
    /// than one occurrence of a name has a distinct in-use version (S2).
    /// When `None`, both fall back to their pre-#394 name-only behavior.
    pub ecosystem: Option<EcosystemId>,
    /// Whether `network.offline` is set (issue #483). When `true`, [`generate_hover`]
    /// appends a footer stating that version *and vulnerability* data were not checked —
    /// deliberately more specific than a bare "showing cached data" notice, since
    /// `hover.rs`'s `Some(ScanOutcome::Skipped(_)) | None` arm renders nothing for an
    /// offline OSV skip, which would otherwise look identical to a scanned-and-clean
    /// dependency.
    pub offline: bool,
    /// The deps.dev client to fetch a supply-chain trust signal through
    /// (spec 037), when the caller wants hover to attempt one. `None` by
    /// default and left `None` by every surface but `handlers/hover.rs`
    /// (deps-lsp) — diagnostics, code actions, inlay hints, and code lenses
    /// never set this, which is what makes FR-010's hover-only scope
    /// structural rather than convention: those surfaces cannot reach
    /// deps.dev because they are never handed a client. `&'a Arc<..>`, not
    /// `&'a DepsDevClient`, so [`generate_hover`] can clone the `Arc` into a
    /// detached background task.
    pub trust: Option<&'a Arc<DepsDevClient>>,
}

impl<'a> VersionData<'a> {
    /// Creates a new `VersionData` from the cached and resolved version maps.
    ///
    /// `vulnerabilities` starts `None`; chain [`Self::with_vulnerabilities`]
    /// to attach a scan result.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved);
    /// assert!(versions.cached.is_empty());
    /// assert!(versions.vulnerabilities.is_none());
    /// ```
    pub fn new(
        cached: &'a HashMap<PackageName, PackageVersions>,
        resolved: &'a HashMap<PackageName, ConcreteVersion>,
    ) -> Self {
        Self {
            cached,
            resolved,
            vulnerabilities: None,
            outcomes: None,
            ecosystem: None,
            offline: false,
            trust: None,
        }
    }

    /// Attaches an OSV scan result to this `VersionData`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::osv::VulnerabilityMap;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let vulns = VulnerabilityMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulns);
    /// assert!(versions.vulnerabilities.is_some());
    /// ```
    #[must_use]
    pub fn with_vulnerabilities(mut self, vulnerabilities: &'a VulnerabilityMap) -> Self {
        self.vulnerabilities = Some(vulnerabilities);
        self
    }

    /// Attaches yanked, deprecation, and fetch-failure findings to this `VersionData`. See
    /// [`Self::outcomes`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::lsp_helpers::DependencyOutcomes;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let outcomes = DependencyOutcomes::new();
    /// let versions = VersionData::new(&cached, &resolved).with_outcomes(&outcomes);
    /// assert!(versions.outcomes.is_some());
    /// ```
    #[must_use]
    pub fn with_outcomes(mut self, outcomes: &'a DependencyOutcomes) -> Self {
        self.outcomes = Some(outcomes);
        self
    }

    /// Attaches this document's ecosystem, enabling the occurrence-aware
    /// refinements described on [`Self::ecosystem`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{EcosystemId, VersionData};
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_ecosystem(EcosystemId::Cargo);
    /// assert_eq!(versions.ecosystem, Some(EcosystemId::Cargo));
    /// ```
    #[must_use]
    pub const fn with_ecosystem(mut self, ecosystem: EcosystemId) -> Self {
        self.ecosystem = Some(ecosystem);
        self
    }

    /// Marks this `VersionData` as built while `network.offline` was set, so
    /// [`generate_hover`] appends its offline footer.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_offline(true);
    /// assert!(versions.offline);
    /// ```
    #[must_use]
    pub const fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Attaches a deps.dev client, enabling [`generate_hover`] to attempt a
    /// supply-chain trust signal for the hovered dependency. See
    /// [`Self::trust`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{DepsDevClient, HttpCache, VersionData};
    /// use std::collections::HashMap;
    /// use std::sync::Arc;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let client = Arc::new(DepsDevClient::new(Arc::new(HttpCache::new())));
    /// let versions = VersionData::new(&cached, &resolved).with_trust(&client);
    /// assert!(versions.trust.is_some());
    /// ```
    #[must_use]
    pub const fn with_trust(mut self, client: &'a Arc<DepsDevClient>) -> Self {
        self.trust = Some(client);
        self
    }
}

/// Checks whether a cursor position falls within an LSP range (inclusive on both ends).
pub fn position_in_range(pos: Position, range: Range) -> bool {
    if pos.line < range.start.line || pos.line > range.end.line {
        return false;
    }
    if pos.line == range.start.line && pos.character < range.start.character {
        return false;
    }
    if pos.line == range.end.line && pos.character > range.end.character {
        return false;
    }
    true
}

/// Converts byte offsets in source text to LSP `Position` values.
///
/// Precomputes line-start byte offsets once, then maps any byte offset to a
/// `(line, character)` position. Characters are counted as UTF-16 code units
/// as required by the LSP specification.
pub struct LineOffsetTable {
    line_starts: Vec<usize>,
}

impl LineOffsetTable {
    /// Builds the table for `content`.
    pub fn new(content: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, c) in content.char_indices() {
            if c == '\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    /// Absolute byte offset where `line` (0-indexed) starts, or `None` if
    /// `line` is out of range.
    ///
    /// Prefer this over re-deriving a line's start via cursor arithmetic
    /// (`cursor += line.len() + 1`): `str::lines()` strips a trailing `\r`,
    /// so that approach under-counts by one byte per CRLF line and corrupts
    /// every subsequent offset in the file. This table is built by scanning
    /// `char_indices()` for `\n` (see [`new`](Self::new)), which counts the
    /// `\r`, so it stays correct for LF, CRLF and mixed line endings alike.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::LineOffsetTable;
    ///
    /// let table = LineOffsetTable::new("a\r\nb\r\nc");
    /// assert_eq!(table.line_start(0), Some(0));
    /// assert_eq!(table.line_start(1), Some(3));
    /// assert_eq!(table.line_start(2), Some(6));
    /// assert_eq!(table.line_start(3), None);
    /// ```
    pub fn line_start(&self, line: usize) -> Option<usize> {
        self.line_starts.get(line).copied()
    }

    /// Converts a byte offset into an LSP `Position`.
    pub fn byte_offset_to_position(&self, content: &str, offset: usize) -> Position {
        let offset = offset.min(content.len());
        // `offset` is not always a toml-span offset (boundary-safe by
        // construction) — the requirements.txt line parser derives offsets
        // via hand-rolled byte arithmetic, which can land inside a
        // multi-byte character (e.g. a non-ASCII comment or marker string
        // combined with an off-by-a-byte cut). Clamp down to the nearest
        // char boundary rather than panicking on the slice below.
        let offset = content.floor_char_boundary(offset);
        let line = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let line_start = self.line_starts[line];
        let character = content[line_start..offset]
            .chars()
            .map(|c| c.len_utf16() as u32)
            .sum();
        Position::new(line as u32, character)
    }

    /// Converts an LSP `Position` back into a byte offset — the inverse of
    /// [`byte_offset_to_position`](Self::byte_offset_to_position). Out-of-range lines or
    /// UTF-16 characters clamp to `content.len()` rather than panicking, matching the
    /// forward conversion's `.min(content.len())` guard.
    pub fn position_to_byte_offset(&self, content: &str, position: Position) -> usize {
        let Some(&line_start) = self.line_starts.get(position.line as usize) else {
            return content.len();
        };
        let line_end = self
            .line_starts
            .get(position.line as usize + 1)
            .copied()
            .unwrap_or(content.len());
        let line = &content[line_start..line_end];
        crate::completion::utf16_to_byte_offset(line, position.character)
            .map_or(line_end, |offset| line_start + offset)
            .min(content.len())
    }
}

/// Escapes Markdown syntax characters so untrusted text cannot break out of the
/// Markdown structure it is embedded in.
///
/// Applied to manifest-controlled text (dependency names) before it is written into
/// hover markdown link labels, and to registry-controlled completion metadata
/// (package name/version, description, repository/documentation URLs) before it is
/// written into completion-item link labels and link destinations. Every ASCII
/// punctuation character is backslash-escaped (CommonMark's full escapable set — not
/// just brackets/parens, which would still leave e.g. `<https://evil.example>`
/// autolinks live), and control characters (including newlines) are replaced with a
/// space so the text cannot terminate the single-line block it is embedded in and
/// splice in new content.
///
/// Backslash-escaping is valid in link destinations as well as regular text, so this
/// also neutralizes `)`/`]` breakout attempts in a `[label](destination)` URL. It does
/// *not* block dangerous URI schemes (e.g. `javascript:`) in a destination — that is a
/// separate concern from breaking out of the surrounding Markdown structure.
///
/// Backslash-escaping does *not* work inside inline code spans (CommonMark §6.1) —
/// use [`markdown_code_span`] for text embedded in `` `...` `` instead.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::escape_markdown;
///
/// assert_eq!(escape_markdown("pkg](evil)[pkg"), r"pkg\]\(evil\)\[pkg");
/// assert_eq!(escape_markdown("a\nb"), "a b");
/// ```
pub fn escape_markdown(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            escaped.push(' ');
            continue;
        }
        if c.is_ascii_punctuation() {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// Wraps `content` in a Markdown inline code span (backticks included) that safely
/// contains arbitrary untrusted text, regardless of embedded backticks.
///
/// Backslash-escaping does not work inside code spans (CommonMark §6.1), so instead
/// this fences with one more backtick than the longest run found in `content`, and
/// pads with a single space on each side when `content` starts or ends with a
/// backtick or space (required by CommonMark to keep the fence unambiguous). Control
/// characters (including newlines) are replaced with a space first, since the raw
/// hover string is otherwise free to merge into an adjacent Markdown block.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::markdown_code_span;
///
/// assert_eq!(markdown_code_span("1.0.0"), "`1.0.0`");
/// assert_eq!(markdown_code_span("a`b"), "``a`b``");
/// ```
pub fn markdown_code_span(content: &str) -> String {
    let sanitized: String = content
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();

    let max_backtick_run = sanitized
        .split(|c| c != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(max_backtick_run + 1);

    if sanitized.is_empty() {
        format!("{fence} {fence}")
    } else if sanitized.starts_with(['`', ' ']) || sanitized.ends_with(['`', ' ']) {
        format!("{fence} {sanitized} {fence}")
    } else {
        format!("{fence}{sanitized}{fence}")
    }
}

/// Checks if two version strings have the same major and minor version.
pub fn is_same_major_minor(v1: &str, v2: &str) -> bool {
    if v1.is_empty() || v2.is_empty() {
        return false;
    }

    let mut parts1 = v1.split('.');
    let mut parts2 = v2.split('.');

    if parts1.next() != parts2.next() {
        return false;
    }

    match (parts1.next(), parts2.next()) {
        (Some(m1), Some(m2)) => m1 == m2,
        _ => true,
    }
}

/// Result of checking whether a dependency's declared requirement is already satisfied by
/// the latest known version.
///
/// Diagnostics and inlay hints read this result differently: diagnostics only need to know
/// whether it is safe to skip the "Newer version available" warning, so both `UpToDate` and
/// `Unresolved` suppress it. Inlay hints additionally need to distinguish `Unresolved` from
/// `UpToDate`, since an unresolved requirement (e.g. a dangling Gradle version-catalog
/// `version.ref` alias, or an unexpanded Maven `${property}`) must not render an "up to
/// date" badge that was never actually verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementStatus {
    /// The latest version satisfies the declared requirement.
    UpToDate,
    /// The latest version does not satisfy the declared requirement — a newer version is
    /// available.
    Outdated,
    /// The requirement could not be resolved to a concrete constraint, so no comparison
    /// could be made.
    Unresolved,
}

/// A `requirement` compiled by one ecosystem, ready to test candidate versions against.
///
/// Produced by [`formatter::RequirementResolution::compile_requirement`]. Kept as a separate object
/// (rather than a single "does any version match" function) so the requirement is parsed
/// once per dependency, and so the scanning loop — including the empty-list guard, the
/// early-exit on first match, and the "skip an unparseable candidate" rule — lives once in
/// [`requirement_is_unsatisfiable`] instead of being reimplemented by all eleven ecosystems.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::RequirementMatcher;
/// use deps_core::ConcreteVersion;
///
/// struct ExactMatch(String);
///
/// impl RequirementMatcher for ExactMatch {
///     fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
///         Some(version.as_str() == self.0)
///     }
/// }
///
/// let matcher = ExactMatch("1.0.0".to_string());
/// assert_eq!(matcher.matches(&ConcreteVersion::new("1.0.0")), Some(true));
/// assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
/// ```
pub trait RequirementMatcher: Send + Sync {
    /// Tests one candidate version string against the compiled requirement.
    ///
    /// `Some(true)` / `Some(false)`: this candidate provably does / does not satisfy the
    /// requirement. `None`: this candidate *string* could not be parsed by this ecosystem's
    /// version format (e.g. a PyPI legacy release identifier, a Maven timestamped snapshot
    /// qualifier) — the caller skips it and keeps scanning the rest of the list. Never
    /// return `None` to mean "the requirement itself is unusable"; that is
    /// [`formatter::RequirementResolution::compile_requirement`]'s job, via returning `None` from that
    /// method instead of constructing a matcher at all.
    fn matches(&self, version: &ConcreteVersion) -> Option<bool>;
}

/// Whether `segment` is exactly `.` or `..`.
///
/// Unlike ordinary path characters, a literal `.`/`..` segment is not neutralized by
/// percent-encoding: `.` is an unreserved character (RFC 3986), so `urlencoding::encode`
/// leaves it untouched, and the URL parser's dot-segment removal (RFC 3986 §5.2.4) still
/// collapses it after encoding — `%2E` decodes back to `.` before that normalization runs.
/// A registry-fetch URL built as `{base}/{prefix}/{name}` (no fixed suffix after `name`)
/// must reject a `name`/path segment satisfying this predicate rather than encode it,
/// since encoding alone does not stop the collapse (#341, #349).
///
/// Shared by `deps-npm`'s scope/package segment guard and `deps-dart`'s package-name
/// guard — both ecosystems' registry APIs key a fetch on a bare, suffix-less path segment.
///
/// **Scope**: this predicate (and the `#365` regression sweep built around it) guards
/// registry-*fetch* URL builders — the sink is a request this process actually
/// dereferences, so a retargeted URL can make it fetch attacker-chosen data. It
/// deliberately does *not* extend to a "docs link"/`package_url`-style builder (the
/// per-ecosystem hover/display link, e.g. `deps_cargo::crate_url`, `deps_go::package_url`):
/// those interpolate the name into a link rendered in hover text and never fetched by
/// this process, so an unrejected `.`/`..` name there produces at worst a misleading
/// same-host link (the registry's package-listing root), not a traversal off-host (#379).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_dot_segment;
///
/// assert!(is_dot_segment(".."));
/// assert!(is_dot_segment("."));
/// assert!(!is_dot_segment("left-pad"));
/// ```
pub fn is_dot_segment(segment: &str) -> bool {
    segment == "." || segment == ".."
}

/// Whether `version` is safe to embed in a manifest [`TextEdit`] or completion item.
///
/// Guards every call into
/// [`formatter::PackageRendering::format_version_replacing`]/[`formatter::PackageRendering::format_version_for_text_edit`]
/// and every completion item's `insert_text`/`text_edit`.
///
/// Must be applied to the raw version string *before* formatting, never to a
/// formatter's output: some formatters legitimately produce structural
/// characters in their output from an already-validated version plus fixed,
/// trusted operators (e.g. PyPI's `>=1.2.3,<2`), so validating the output
/// would wrongly reject those.
///
/// An allowlist, not a denylist: `version` must be non-empty, at most 64
/// bytes, and contain only `[A-Za-z0-9.+_~:*^!-]` — the character set real
/// version strings use across every ecosystem this workspace supports
/// (SemVer, PEP 440 including epochs like `1!2.0`, Maven qualifiers, npm's
/// `^`/`~`/`*` range tokens, Go's `+incompatible` suffix). A denylist here
/// would need to anticipate every dangerous token a target manifest format
/// (or a build tool evaluating it, e.g. Gradle's Kotlin/Groovy DSL
/// interpolating `${...}` inside a version literal) could ever act on;
/// failing closed on an unrecognized character is cheaper and safer.
///
/// This is the single validation chokepoint shared by every producer of a
/// version-derived `TextEdit`/completion item in this workspace, including
/// OSV advisory data (an `Advisory.fixed_versions` entry is exactly as
/// untrusted as a registry-reported version).
///
/// # Examples
///
/// ```
/// use deps_core::is_safe_version_string;
///
/// assert!(is_safe_version_string("1.2.3-alpha.1+build"));
/// assert!(!is_safe_version_string("1.2.3\", git = \"https://evil"));
/// ```
pub fn is_safe_version_string(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '+' | '_' | '~' | ':' | '*' | '^' | '!' | '-')
        })
}

/// Whether `segment` is safe to embed as a Maven `groupId`/`artifactId` value in a
/// pom.xml [`TextEdit`] or completion item.
///
/// Guards Maven's group/artifact completion producer, which builds a completion item's
/// `insert_text`/`text_edit` from one field of a Maven Central search result — a value
/// type distinct from a version string (see [`is_safe_version_string`]'s doc comment for
/// why version-derived and non-version-derived sinks each get their own allowlist).
///
/// An allowlist, not a denylist: `segment` must be non-empty, at most 128 bytes, not
/// exactly `.`/`..` (see [`is_dot_segment`]), and contain only `[A-Za-z0-9._-]` — the
/// character set real Maven Central group ids (reverse-DNS style, e.g.
/// `org.apache.commons`) and artifact ids (hyphen/underscore separated, e.g.
/// `commons-lang3`) use. Deliberately excludes `:` — the `groupId:artifactId` separator —
/// because this validates one already-split coordinate field at a time, never the joined
/// pair. Failing closed on an unrecognized character (e.g. `<`, `"`, a newline) keeps a
/// malicious/compromised search result from restructuring the pom.xml it's inserted into;
/// the dedicated `.`/`..` rejection closes the same dot-segment URL-normalization gap
/// [`is_dot_segment`] guards elsewhere (`artifactId` reaches a registry-fetch URL as a bare
/// path segment in `deps-maven::registry::metadata_urls`, unlike `groupId`, whose `.`→`/`
/// expansion can never itself produce a literal `..` component).
///
/// # Examples
///
/// ```
/// use deps_core::is_safe_maven_coordinate_segment;
///
/// assert!(is_safe_maven_coordinate_segment("org.apache.commons"));
/// assert!(is_safe_maven_coordinate_segment("commons-lang3"));
/// assert!(!is_safe_maven_coordinate_segment("commons</artifactId><parent>"));
/// assert!(!is_safe_maven_coordinate_segment(".."));
/// ```
pub fn is_safe_maven_coordinate_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && !is_dot_segment(segment)
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Whether `url` is safe to embed as a Swift Package Manager repository URL in a
/// Package.swift [`TextEdit`] or completion item.
///
/// Guards Swift's URL-completion producer, which builds a `.package(url: "...")`
/// string-literal replacement from a package registry search result's URL — a value
/// type distinct from a version string (see [`is_safe_version_string`]'s doc comment for
/// why version-derived and non-version-derived sinks each get their own allowlist).
///
/// An allowlist, not a denylist: `url` must be non-empty, at most 2048 bytes, start with
/// `https://` — every real Swift package registry response is HTTPS (GitHub's `html_url`
/// never downgrades), so accepting plain `http://` would only hand a
/// compromised/malicious registry a transport-downgrade lever for zero legitimate
/// benefit — and otherwise contain only RFC 3986 URL characters (`A-Za-z0-9` plus
/// `` -._~:/?#[]@!$&'()*+,;=% ``). Deliberately excludes `"`, `\`, control characters,
/// and whitespace — none of those are valid unencoded URL characters, and any of them
/// could close the surrounding Swift string literal or otherwise corrupt the manifest.
/// Failing closed on an unrecognized character keeps a malicious/compromised search
/// result from breaking out of the string it's inserted into.
///
/// # Examples
///
/// ```
/// use deps_core::is_safe_registry_url;
///
/// assert!(is_safe_registry_url("https://github.com/apple/swift-nio"));
/// assert!(!is_safe_registry_url("https://evil.example\", .exact(\"1\")) // "));
/// ```
pub fn is_safe_registry_url(url: &str) -> bool {
    !url.is_empty()
        && url.len() <= 2048
        && url.starts_with("https://")
        && url.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '-' | '.'
                        | '_'
                        | '~'
                        | ':'
                        | '/'
                        | '?'
                        | '#'
                        | '['
                        | ']'
                        | '@'
                        | '!'
                        | '$'
                        | '&'
                        | '\''
                        | '('
                        | ')'
                        | '*'
                        | '+'
                        | ','
                        | ';'
                        | '='
                        | '%'
                )
        })
}

/// Whether `name` is safe to embed as a package name in a manifest [`TextEdit`] or
/// completion item.
///
/// Guards every arm of `create_package_completion_item`
/// (`crates/deps-lsp/src/handlers/completion.rs`) as a single upfront check, applied
/// before the raw `name` reaches any ecosystem-specific snippet — including Maven and
/// Swift, which additionally validate a *derived* value on top of this gate
/// ([`is_safe_maven_coordinate_segment`] on each split coordinate segment,
/// [`is_safe_registry_url`] on the constructed URL) because a value type distinct from
/// the raw name needs its own allowlist — see [`is_safe_version_string`]'s doc comment
/// for why version-derived and non-version-derived sinks each get their own allowlist.
/// [`PackageName::new`](crate::PackageName::new) is documented as never validating or
/// modifying its input, so this predicate is the first gate a registry-reported name
/// passes through before reaching a manifest. Two sinks that key a bare TOML/YAML
/// entry by `name` (Cargo/PyPI, Dart) additionally quote that key in the snippet, since
/// `.` and `@` are legal here but would otherwise be read as TOML's dotted-key
/// separator or break a YAML plain scalar.
///
/// An allowlist, not a denylist: `name` must be non-empty, at most 256 bytes, and
/// contain only `[A-Za-z0-9._@:/~-]` — the character set real package names use across
/// every ecosystem this predicate guards: Cargo/PyPI/Dart/NuGet/Bundler
/// (alphanumeric, `-`, `_`, `.`), npm/Deno scoped names (`@scope/name`, adding `@` and
/// `/`), Composer (`vendor/package`, `/`), Go module paths (domain-qualified paths like
/// `github.com/org/repo`, `/`, `.`, and `~` — legal in a Go path element and already
/// allowed by [`is_safe_version_string`]/[`is_safe_registry_url`]), and Gradle's
/// colon-delimited `group:artifact` short form (`:`). A denylist here would need to
/// anticipate every dangerous token a target manifest format (TOML/JSON/YAML/XML
/// string literals, a live Kotlin/Groovy build-script DSL) could ever act on; failing
/// closed on an unrecognized character — notably `"`, `'`, `<`, `>`, `` ` ``, and all
/// control characters/newlines — is cheaper and safer.
///
/// # Examples
///
/// ```
/// use deps_core::is_safe_package_name;
///
/// assert!(is_safe_package_name("serde"));
/// assert!(is_safe_package_name("@scope/name"));
/// assert!(is_safe_package_name("org.apache.commons:commons-lang3"));
/// assert!(!is_safe_package_name("evil\"\nbackdoor = \"9.9.9"));
/// ```
pub fn is_safe_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | ':' | '/' | '-' | '~')
        })
}

/// Logs a `tracing::warn!` for a value rejected by an `is_safe_*` predicate (or an
/// equivalent value-rejecting gate) before it reaches a manifest edit or registry URL.
///
/// Deliberately logs only `value`'s byte length, never its content: `value` is
/// registry-controlled and, by construction, already failed an allowlist — logging it
/// verbatim at `warn` would let a malicious/compromised registry response inject arbitrary
/// content into this project's own log stream (a second-order log-injection concern),
/// mirroring why `deps-pypi`'s `truncate_for_log` bounds a logged excerpt instead of
/// logging a value verbatim. This is this helper's own contract, not a claim that every
/// `tracing` call site in the workspace avoids logging a raw value — e.g. `deps-lsp`'s
/// `deps-lsp.updateVersion` handler and an OSV malformed-`fixed`-version warning predate
/// this helper and log their rejected value directly; they are unrelated call sites, not a
/// place this helper is used.
///
/// `gate` names the predicate/guard that rejected `value` (e.g.
/// `"is_safe_maven_coordinate_segment"`); `context` is a short description of the call site
/// (e.g. `"maven groupId completion"`).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::warn_rejected_value;
///
/// warn_rejected_value("is_safe_version_string", "code lens latest version", "1.0.0\"; evil");
/// ```
pub fn warn_rejected_value(gate: &str, context: &str, value: &str) {
    tracing::warn!(
        gate,
        context,
        len = value.len(),
        "rejected unsafe value before manifest/registry sink"
    );
}

/// Builds a single-entry [`WorkspaceEdit::changes`] map replacing `range` in `uri`
/// with `new_text`.
///
/// Shared by every quickfix/refactor code action in `code_actions` that edits exactly
/// one span in the current document (`build_vulnerability_fix_action`,
/// `build_unsatisfiable_fix_action`, and the plain "update to `<version>`" loop in
/// [`generate_code_actions`]).
fn single_file_edit(uri: &Uri, range: Range, new_text: String) -> HashMap<Uri, Vec<TextEdit>> {
    let mut edits = HashMap::new();
    edits.insert(uri.clone(), vec![TextEdit { range, new_text }]);
    edits
}

/// Strips every whitespace character from `s`, so two textually-equivalent strings that
/// differ only in spacing compare equal.
///
/// Shared by every no-op/literal-match guard across `code_actions` and `code_lenses`
/// (`build_vulnerability_fix_action`'s N1 guard, `generate_code_actions`'s REFACTOR-loop
/// guard, `literal_span_matches`, and `collect_update_all_edits`'s no-op guard), all of
/// which compare a declared requirement
/// string against a differently-normalized counterpart — e.g. pep508's `>=1.7, <2.0` vs. a
/// formatter's `>=1.7,<2.0`.
fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Slices `content` over an LSP `Range` using a pre-built `LineOffsetTable`, returning
/// `""` for an inverted or out-of-bounds range instead of panicking.
///
/// `table` is document-invariant — callers iterating over multiple dependencies in the
/// same document must build it once and reuse it, rather than rebuilding it (an O(n)
/// scan of `content`) per dependency.
fn slice_for_range<'a>(content: &'a str, table: &LineOffsetTable, range: Range) -> &'a str {
    let start = table.position_to_byte_offset(content, range.start);
    let end = table.position_to_byte_offset(content, range.end);
    if start > end {
        return "";
    }
    content.get(start..end).unwrap_or("")
}

/// Checks whether `slice` — `content` sliced over a dependency's `version_range` — still
/// holds the literal version text declared by `requirement`.
///
/// Whitespace is stripped from both sides before comparison, since pep508's normalized
/// requirement string can diverge from the original source spacing (PyPI's `>=1.7,<2.0`
/// renders as `>=1.7, <2.0`) while `version_range` still spans the un-normalized source.
///
/// The second branch accepts `slice` wrapped in brackets matching `requirement` — the
/// exact inverse of NuGet's parser wrapping a bare source version as `format!("[{v}]")`
/// (`crates/deps-nuget/src/parser.rs`). This is deliberately **not** a symmetric bracket
/// strip: NuGet's `Version="1.0.0"` produces requirement `[1.0.0]` over a bare-literal
/// span, so a *symmetric* strip (stripping one bracket pair from both operands) would
/// compare `1.0.0` against `1.0.0` — coincidentally correct there, but the same strip
/// applied to `Version="[1.0.0]"` (requirement `[[1.0.0]]`, a spelling
/// `crates/deps-nuget/src/formatter.rs` explicitly supports) leaves `[1.0.0]` vs
/// `1.0.0` and **falsely rejects** an editable dependency. Wrapping only the slice side
/// handles both spellings without that false reject.
fn literal_span_matches(slice: &str, requirement: &str) -> bool {
    let norm_slice = strip_whitespace(slice);
    let norm_req = strip_whitespace(requirement);
    norm_slice == norm_req || format!("[{norm_slice}]") == norm_req
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::{PackageName, VersionReq};

    /// The empty-entry pruning invariant: an entry is removed once its last set channel
    /// is cleared, one channel at a time, in every order — never left behind as a
    /// vacuous `Some(DependencyOutcome::default())` that would inflate `len()`.
    #[test]
    fn test_dependency_outcomes_prunes_entry_once_all_channels_cleared() {
        let mut outcomes = DependencyOutcomes::new()
            .with_yanked("pkg", ("1.0.0".into(), RemovalStatus::Yanked))
            .with_deprecation(
                "pkg",
                Deprecation {
                    reason: None,
                    replacement: None,
                },
            )
            .with_fetch_failure("pkg", FetchFailure::Transient);
        assert_eq!(outcomes.len(), 1);

        outcomes.clear_yanked("pkg");
        assert!(
            outcomes.get("pkg").is_some(),
            "entry must survive while other channels are still set"
        );

        outcomes.clear_deprecation("pkg");
        assert!(
            outcomes.get("pkg").is_some(),
            "entry must survive while the fetch-failure channel is still set"
        );

        outcomes.clear_fetch_failure("pkg");
        assert!(
            outcomes.is_empty(),
            "entry must be pruned once its last channel is cleared, not left as a vacuous Some"
        );
        assert_eq!(outcomes.len(), 0);
    }

    /// Clearing a channel that was never set on an existing entry must not spuriously
    /// prune channels that ARE still set (each `clear_*` only nulls its own field).
    #[test]
    fn test_dependency_outcomes_clear_on_unset_channel_is_a_no_op_for_others() {
        let mut outcomes = DependencyOutcomes::new()
            .with_yanked("pkg", ("1.0.0".into(), RemovalStatus::AdvisoryDeprecated));

        outcomes.clear_deprecation("pkg");
        outcomes.clear_fetch_failure("pkg");

        assert!(
            outcomes.yanked("pkg").is_some(),
            "clearing unset channels must not touch the still-set yanked channel"
        );
        assert_eq!(outcomes.len(), 1);
    }

    /// `remove` drops the whole entry regardless of which channels are set, unlike the
    /// per-channel `clear_*` methods.
    #[test]
    fn test_dependency_outcomes_remove_drops_entry_with_multiple_channels_set() {
        let mut outcomes = DependencyOutcomes::new()
            .with_yanked("pkg", ("1.0.0".into(), RemovalStatus::Yanked))
            .with_fetch_failure("pkg", FetchFailure::Transient);

        outcomes.remove("pkg");

        assert!(outcomes.get("pkg").is_none());
        assert!(outcomes.is_empty());
    }

    /// `set_fetch_failure_if_absent` (impl-critic M2) must never clobber a genuine
    /// `Actionable`/`Transient` failure already recorded for the name — only `set_fetch_failure`
    /// unconditionally overwrites.
    #[test]
    fn test_dependency_outcomes_set_fetch_failure_if_absent_does_not_clobber_existing() {
        let mut outcomes = DependencyOutcomes::new().with_fetch_failure(
            "pkg",
            FetchFailure::Actionable("set GITHUB_TOKEN".to_string()),
        );

        outcomes.set_fetch_failure_if_absent("pkg".to_string(), FetchFailure::NotAttempted);

        assert_eq!(
            outcomes.fetch_failure("pkg"),
            Some(&FetchFailure::Actionable("set GITHUB_TOKEN".to_string())),
            "an existing genuine failure must survive a collided-name NotAttempted marker"
        );
    }

    /// The mirror case: when no failure is recorded yet, `set_fetch_failure_if_absent` does
    /// populate the entry.
    #[test]
    fn test_dependency_outcomes_set_fetch_failure_if_absent_populates_when_unset() {
        let mut outcomes = DependencyOutcomes::new();

        outcomes.set_fetch_failure_if_absent("pkg".to_string(), FetchFailure::NotAttempted);

        assert_eq!(
            outcomes.fetch_failure("pkg"),
            Some(&FetchFailure::NotAttempted)
        );
    }

    #[test]
    fn test_line_offset_table_line_start_crlf() {
        let table = LineOffsetTable::new("a\r\nbb\r\nc");
        assert_eq!(table.line_start(0), Some(0));
        assert_eq!(table.line_start(1), Some(3));
        assert_eq!(table.line_start(2), Some(7));
        assert_eq!(table.line_start(3), None);
    }

    #[test]
    fn test_byte_offset_to_position_clamps_to_char_boundary_instead_of_panicking() {
        // "é" is a 2-byte UTF-8 sequence; offset 1 lands inside it.
        let content = "é";
        let table = LineOffsetTable::new(content);
        // Must not panic; clamps down to the nearest boundary (offset 0).
        let pos = table.byte_offset_to_position(content, 1);
        assert_eq!(pos, Position::new(0, 0));
    }

    #[test]
    fn test_byte_offset_to_position_multi_byte_boundary_in_longer_line() {
        let content = "ab é cd";
        let table = LineOffsetTable::new(content);
        // Byte 3 is 'é's leading byte (boundary); byte 4 is its continuation
        // byte (not a boundary) and must clamp back to 3 rather than panic.
        assert!(content.is_char_boundary(3));
        assert!(!content.is_char_boundary(4));
        let pos = table.byte_offset_to_position(content, 4);
        assert_eq!(pos, table.byte_offset_to_position(content, 3));
    }

    #[test]
    fn test_position_in_range_inside() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 15);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_at_start() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 10);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_at_end() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 20);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_before() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 5);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_after() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 25);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_different_line_before() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(4, 15);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_different_line_after() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(6, 15);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_multiline() {
        let range = Range::new(Position::new(5, 10), Position::new(7, 5));
        let position = Position::new(6, 0);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_escape_markdown_link_breakout_payload() {
        let payload = "real-pkg](https://legit-looking-typosquat.example/download)[real-pkg";
        let escaped = escape_markdown(payload);
        assert_eq!(
            escaped,
            r"real\-pkg\]\(https\:\/\/legit\-looking\-typosquat\.example\/download\)\[real\-pkg"
        );
        assert!(!escaped.contains("]("));
    }

    #[test]
    fn test_escape_markdown_backslash_and_backtick() {
        assert_eq!(escape_markdown(r"a\b`c"), r"a\\b\`c");
    }

    #[test]
    fn test_escape_markdown_autolink_angle_brackets() {
        // `<...>` around a bare URL is a CommonMark autolink; `<`/`>` must be escaped
        // so it cannot render as a live link independent of the `[]`/`()` escaping.
        let escaped = escape_markdown("pkg <https://evil.example>");
        assert_eq!(escaped, r"pkg \<https\:\/\/evil\.example\>");
        assert!(!escaped.contains('<') || escaped.contains(r"\<"));
    }

    #[test]
    fn test_escape_markdown_control_chars_become_spaces() {
        assert_eq!(escape_markdown("a\nb"), "a b");
        assert_eq!(escape_markdown("a\r\nb"), "a  b");
        assert_eq!(escape_markdown("a\tb"), "a b");
        assert_eq!(escape_markdown("a\0b"), "a b");
    }

    #[test]
    fn test_escape_markdown_newline_cannot_break_out_of_heading() {
        // A raw newline used to terminate the ATX heading line early, letting the
        // rest of the name (potentially another "# [...](...)" sequence) render as
        // separate, unescaped Markdown blocks.
        let escaped = escape_markdown("react\n# [fake](https://evil.example)");
        assert!(!escaped.contains('\n'));
    }

    #[test]
    fn test_escape_markdown_hyphenated_name_round_trips_visually() {
        // Escaping a hyphen (ASCII punctuation) is visually inert on render — CommonMark
        // renders `\-` as a literal `-` — so common package names are unaffected in
        // practice even though the raw Markdown source now escapes them.
        assert_eq!(escape_markdown("tokio-util"), r"tokio\-util");
    }

    #[test]
    fn test_markdown_code_span_plain_content() {
        assert_eq!(markdown_code_span("1.0.0"), "`1.0.0`");
    }

    #[test]
    fn test_markdown_code_span_widens_fence_for_embedded_backticks() {
        assert_eq!(markdown_code_span("a`b"), "``a`b``");
        assert_eq!(markdown_code_span("``double``"), "``` ``double`` ```");
    }

    #[test]
    fn test_markdown_code_span_pads_when_content_starts_or_ends_with_backtick() {
        let span = markdown_code_span("`leading");
        assert!(span.starts_with("`` `"));
    }

    #[test]
    fn test_markdown_code_span_replaces_control_chars() {
        let span = markdown_code_span("1.0\n[evil](https://evil.example)");
        assert!(!span.contains('\n'));
    }

    #[test]
    fn test_markdown_code_span_empty_content() {
        assert_eq!(markdown_code_span(""), "` `");
    }

    #[test]
    fn test_markdown_code_span_backtick_payload_cannot_break_span() {
        // A payload attempting to close the code span early and splice in a live
        // link must not succeed regardless of backtick count in the content.
        let payload = "1.0` <https://evil.example>` more";
        let span = markdown_code_span(payload);
        // The fence must be strictly longer than any backtick run in the (sanitized)
        // content, so no substring of `span` after the opening fence can act as a
        // closing fence before the real one.
        let opening_fence_len = span.chars().take_while(|&c| c == '`').count();
        let inner = &span[opening_fence_len..span.len() - opening_fence_len];
        assert!(
            !inner.contains(&"`".repeat(opening_fence_len)),
            "content contains a run of backticks as long as the fence: {span}"
        );
    }

    #[test]
    fn test_is_same_major_minor_full_match() {
        assert!(is_same_major_minor("1.2.3", "1.2.9"));
    }

    #[test]
    fn test_is_same_major_minor_exact_match() {
        assert!(is_same_major_minor("1.2.3", "1.2.3"));
    }

    #[test]
    fn test_is_same_major_minor_major_only_match() {
        assert!(is_same_major_minor("1", "1.2.3"));
        assert!(is_same_major_minor("1.2.3", "1"));
    }

    #[test]
    fn test_is_same_major_minor_no_match_different_minor() {
        assert!(!is_same_major_minor("1.2.3", "1.3.0"));
    }

    #[test]
    fn test_is_same_major_minor_no_match_different_major() {
        assert!(!is_same_major_minor("1.2.3", "2.2.3"));
    }

    #[test]
    fn test_is_same_major_minor_empty_strings() {
        assert!(!is_same_major_minor("", ""));
        assert!(!is_same_major_minor("1.2.3", ""));
        assert!(!is_same_major_minor("", "1.2.3"));
    }

    #[test]
    fn test_is_safe_version_string_accepts_ordinary_versions() {
        assert!(is_safe_version_string("1.2.3"));
        assert!(is_safe_version_string("1.2.3-beta.1+build"));
        assert!(is_safe_version_string("v1.2.3"));
    }

    #[test]
    fn test_is_safe_version_string_rejects_empty_or_whitespace() {
        assert!(!is_safe_version_string(""));
        assert!(!is_safe_version_string("   "));
        assert!(!is_safe_version_string("\t\n"));
    }

    #[test]
    fn test_is_safe_version_string_rejects_control_and_structural_characters() {
        for bad in [
            "1.2.3\n",
            "1.2.3\t",
            "1.2.3\"",
            "1.2.3'",
            "1.2.3<",
            "1.2.3>",
            "1.2.3&",
            "1.2.3\\",
            "1.0.0\", \"malicious\": \"true",
        ] {
            assert!(
                !is_safe_version_string(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_version_string_rejects_gradle_interpolation_payload() {
        // Regression (critic S2): `$`/`{`/`}` are outside the allowlist, so a
        // Gradle Kotlin/Groovy `${...}` interpolation payload written into
        // build.gradle(.kts) can never reach a version literal via this gate.
        for bad in ["1.0${System.getenv(\"X\")}", "1.0$var", "${evil}"] {
            assert!(
                !is_safe_version_string(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_version_string_rejects_invisible_unicode() {
        // Regression (critic M1): `char::is_control()` alone only covers
        // category Cc — format/separator characters like the bidi override
        // U+202E, zero-width space U+200B, and the JS/JSON5 line terminators
        // U+2028/U+2029 must also be rejected by the allowlist.
        for bad in ["1.2.3\u{202E}", "1.2.3\u{200B}", "1.2.3\u{2028}"] {
            assert!(
                !is_safe_version_string(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_version_string_accepts_pep440_epoch() {
        // PEP 440 epochs (`1!2.0`) are legitimate PyPI versions.
        assert!(is_safe_version_string("1!2.0"));
    }

    #[test]
    fn test_is_safe_version_string_length_cap() {
        assert!(is_safe_version_string(&"1".repeat(64)));
        assert!(!is_safe_version_string(&"1".repeat(65)));
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_accepts_real_ids() {
        assert!(is_safe_maven_coordinate_segment("org.apache.commons"));
        assert!(is_safe_maven_coordinate_segment("commons-lang3"));
        assert!(is_safe_maven_coordinate_segment("jackson-core_2.13"));
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_rejects_empty() {
        assert!(!is_safe_maven_coordinate_segment(""));
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_rejects_xml_structural_characters() {
        for bad in [
            "commons</artifactId><parent>",
            "commons\"",
            "commons'",
            "commons&amp;",
            "commons\nlang3",
            "commons\tlang3",
        ] {
            assert!(
                !is_safe_maven_coordinate_segment(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_rejects_group_artifact_colon() {
        assert!(!is_safe_maven_coordinate_segment(
            "org.apache.commons:commons-lang3"
        ));
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_length_cap() {
        assert!(is_safe_maven_coordinate_segment(&"a".repeat(128)));
        assert!(!is_safe_maven_coordinate_segment(&"a".repeat(129)));
    }

    #[test]
    fn test_is_safe_registry_url_accepts_real_urls() {
        assert!(is_safe_registry_url("https://github.com/apple/swift-nio"));
        assert!(is_safe_registry_url(
            "https://github.com/apple/swift-nio.git"
        ));
        assert!(is_safe_registry_url("https://github.com/apple/swift%2Dnio"));
    }

    #[test]
    fn test_is_safe_registry_url_rejects_non_https_scheme() {
        // Every real Swift package registry response is HTTPS; accepting `http://` would
        // only hand a compromised registry a transport-downgrade lever.
        assert!(!is_safe_registry_url("http://example.com/repo"));
        assert!(!is_safe_registry_url("file:///etc/passwd"));
        assert!(!is_safe_registry_url("javascript:alert(1)"));
        assert!(!is_safe_registry_url("ftp://example.com/repo"));
        assert!(!is_safe_registry_url(""));
    }

    #[test]
    fn test_is_safe_registry_url_rejects_swift_string_literal_breakout() {
        for bad in [
            "https://evil.example\", .exact(\"1.0.0\")), .package(url: \"https://real",
            "https://evil.example\\",
            "https://evil.example\nlet x = 1",
            "https://evil.example`echo`",
            "https://evil.example<script>",
        ] {
            assert!(
                !is_safe_registry_url(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_registry_url_length_cap() {
        let prefix = "https://example.com/";
        let at_cap = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
        assert_eq!(at_cap.len(), 2048);
        assert!(is_safe_registry_url(&at_cap));

        let over_cap = format!("{at_cap}a");
        assert_eq!(over_cap.len(), 2049);
        assert!(!is_safe_registry_url(&over_cap));
    }

    #[test]
    fn test_is_safe_package_name_accepts_real_names_across_ecosystems() {
        for good in [
            "serde",                            // Cargo
            "requests",                         // PyPI
            "@scope/name",                      // npm/Deno scoped
            "monolog/monolog",                  // Composer vendor/package
            "github.com/org/repo",              // Go module path
            "path",                             // Dart
            "org.apache.commons:commons-lang3", // Gradle group:artifact
            "Newtonsoft.Json",                  // NuGet
            "rails",                            // Bundler
            "npm:react",                        // Deno npm-scheme specifier
            "jsr:@std/fs",                      // Deno jsr-scheme specifier
            "github.com/foo/bar~compat",        // Go path element with `~`
        ] {
            assert!(
                is_safe_package_name(good),
                "expected {good:?} to be accepted"
            );
        }
    }

    #[test]
    fn test_is_safe_package_name_rejects_empty() {
        assert!(!is_safe_package_name(""));
    }

    #[test]
    fn test_is_safe_package_name_rejects_non_ascii() {
        // Deliberately excluded: the allowlist is ASCII-only, so a legacy non-ASCII
        // npm package name (a handful exist, e.g. Unicode-normalized scopes) is
        // rejected rather than risking homograph/normalization tricks in a manifest.
        assert!(!is_safe_package_name("café"));
        assert!(!is_safe_package_name("пакет"));
    }

    #[test]
    fn test_is_safe_package_name_accepts_dot_dot_shapes() {
        // `.`/`/` are individually legal (PyPI dotted names, npm/Composer scopes), so
        // `..`/`../..` pass the charset too. This is not a path-traversal risk: every
        // sink treats `name` as manifest text (a TOML/JSON/YAML/XML value or a
        // string-literal argument), never as a filesystem path.
        assert!(is_safe_package_name(".."));
        assert!(is_safe_package_name("../.."));
    }

    #[test]
    fn test_is_safe_package_name_rejects_structural_breakout_characters() {
        for bad in [
            "evil\"\nbackdoor = \"9.9.9",
            "evil\", git = \"https://evil",
            "evil\\",
            "evil'",
            "evil<script>",
            "evil`echo`",
            "evil\ninjected = true",
            "evil\tname",
        ] {
            assert!(
                !is_safe_package_name(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_package_name_length_cap() {
        assert!(is_safe_package_name(&"a".repeat(256)));
        assert!(!is_safe_package_name(&"a".repeat(257)));
    }

    #[test]
    fn test_is_same_major_minor_partial_versions() {
        assert!(is_same_major_minor("1.2", "1.2.3"));
        assert!(is_same_major_minor("1.2.3", "1.2"));
    }

    #[test]
    fn test_ecosystem_formatter_defaults() {
        let formatter = MockFormatter;
        assert_eq!(
            formatter.normalize_package_name(&pkg("test-pkg")),
            "test-pkg"
        );
        assert_eq!(formatter.yanked_message(), "This version has been yanked");
        assert_eq!(formatter.yanked_label(), "*(yanked)*");
    }

    #[test]
    fn test_format_version_replacing_for_default_delegates_to_format_version_replacing() {
        let formatter = MockFormatter;
        let dep = MockDep {
            name: pkg("test-pkg"),
            version_req: VersionReq::new("1.0.0"),
            version_range: Range::default(),
            name_range: Range::default(),
        };
        assert_eq!(
            formatter.format_version_replacing_for(&dep, &ConcreteVersion::new("1.2.3"), "1.0.0"),
            formatter.format_version_replacing(&ConcreteVersion::new("1.2.3"), "1.0.0")
        );
    }

    #[test]
    fn test_ecosystem_formatter_version_satisfies() {
        let formatter = MockFormatter;

        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1.2.3"));

        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "^1.2"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "~1.2"));

        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1.2"));

        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "2.0.0"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1.3"));
    }

    #[test]
    fn test_ecosystem_formatter_custom_normalize() {
        struct PyPIFormatter;

        impl PackageNaming for PyPIFormatter {
            fn normalize_package_name(&self, name: &PackageName) -> String {
                name.as_str().to_lowercase().replace('-', "_")
            }
        }

        impl PackageRendering for PyPIFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                format!(
                    ">={},<{}",
                    version,
                    version.as_str().split('.').next().unwrap_or("0")
                )
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://pypi.org/project/{}", name)
            }
        }

        impl RequirementResolution for PyPIFormatter {}

        impl DiagnosticMessages for PyPIFormatter {}

        impl DiagnosticPolicy for PyPIFormatter {}

        impl SourcePolicy for PyPIFormatter {}

        impl OsvNaming for PyPIFormatter {}

        let formatter = PyPIFormatter;
        assert_eq!(
            formatter.normalize_package_name(&pkg("Test-Package")),
            "test_package"
        );
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("1.2.3")),
            ">=1.2.3,<1"
        );
        assert_eq!(
            formatter.package_url(&pkg("requests")),
            "https://pypi.org/project/requests"
        );
    }
}
