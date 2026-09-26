//! Per-package signal state for a single [`super::DocumentState`] (issues #1477/#1471):
//! [`PackageSignals`] groups the nine per-package maps plus the resolved-versions
//! generation counter that were previously loose fields on `DocumentState`, and
//! [`SignalsSnapshot`] lets a handler build an owned, opt-in-per-dimension snapshot of
//! them instead of hand-cloning raw maps and hand-chaining `deps_core::VersionData::with_*`.
//!
//! A child module of `state` (not a sibling of it) so [`PackageSignals::default`] can
//! reach [`super::ResolvedGeneration`]'s private `INITIAL` constant — module-private
//! items are visible to descendant modules, and `signals` is a descendant of `state`.

use deps_core::lsp_helpers::EcosystemFormatter;
use deps_core::osv::VulnerabilityMap;
use deps_core::{
    ConcreteVersion, DependencyOutcomes, GossipFindings, PackageName, PackageVersions,
    TyposquatSignal, VersionData,
};
use std::collections::{HashMap, HashSet};

use super::ResolvedGeneration;

/// The per-package signal maps for a single document, plus the resolved-versions
/// generation counter (issues #1477/#1471).
///
/// Everything `DocumentState` tracks per declared dependency rather than per document as
/// a whole. Every mutator that used to live directly on `DocumentState` for these fields still
/// does (`update_cached_versions`, `merge_licenses`, `evict_licenses`, and so on) — this
/// type only groups the storage, it does not move behavior. `Self::prune_removed` is
/// the one new method, replacing a pruning loop that previously lived inline in
/// `document::lifecycle::commit_parsed_document`.
#[derive(Clone)]
pub struct PackageSignals {
    /// Latest known version and full version list per package, fetched together in a
    /// single registry round trip (see [`PackageVersions`]).
    pub cached_versions: HashMap<PackageName, PackageVersions>,
    /// Resolved versions from lock file
    pub resolved_versions: HashMap<PackageName, ConcreteVersion>,
    /// Every lock-file-resolved version for a package name with more than one retained
    /// entry (issue #649), built alongside [`Self::resolved_versions`] by the same lock
    /// file load. Additive: only names with more than one occurrence get an entry here —
    /// see [`deps_core::VersionData::resolved_version_candidates`] for the per-occurrence
    /// disambiguation this enables.
    pub resolved_version_candidates: HashMap<PackageName, Vec<ConcreteVersion>>,
    /// Set by every `DocumentState::update_resolved_versions` call (issue #1395 critic S3):
    /// distinguishes two resolved-version snapshots taken at the same `DocumentState::content`
    /// (a lock-file-only reload never changes content, so that guard alone cannot order two
    /// OSV phase-A/B pairs that raced on which one saw the fresher resolved versions).
    /// `document::osv_scan::run_osv_scan_phase_a` snapshots this alongside the document's
    /// content when it builds scan targets, and `document::osv_scan::run_osv_phase_b_and_commit`'s
    /// staleness guard requires an exact match on both before committing. Always drawn from
    /// `ServerState::next_resolved_versions_generation` (issue #1395 critic M10), never
    /// incremented from this field's own prior value — see that method's doc for why a
    /// per-document-instance counter is unsafe across a `did_close`/reopen.
    pub(crate) resolved_versions_generation: ResolvedGeneration,
    /// OSV.dev scan results, keyed by normalized package name. Empty until
    /// the first background scan completes; carried across document edits
    /// by `preserve_cache` so it is not wiped on every keystroke.
    pub vulnerabilities: VulnerabilityMap,
    /// Yanked, deprecation, and fetch-failure findings from the lifecycle's registry
    /// fetch, keyed by **normalized** package name. This is deliberately a different
    /// type from `FetchResult`'s raw-keyed triple: the split makes a forgotten
    /// normalization at a store/merge site a compile error rather than a silent bug for
    /// ecosystems where normalization changes the name (e.g. PyPI). See
    /// [`DependencyOutcome`](deps_core::DependencyOutcome) for what each of the three
    /// channels means. Empty until the first fetch completes; carried across document
    /// edits by `preserve_cache` so it doesn't flicker off on every keystroke.
    pub outcomes: DependencyOutcomes,
    /// License data available *synchronously* for this document's dependencies (issue
    /// #660/#661), keyed by raw (unnormalized) package name — the map #661's policy
    /// diagnostics reads, since diagnostics generation is sync/cache-only by design and
    /// cannot await hover's live per-request fetch. Two disjoint populating sources,
    /// which can coexist safely because a document has exactly one ecosystem, so only
    /// one of the two ever contributes real (non-empty) data for it:
    /// - **Tier-1 backfill**: `document::fetch::merge_registry_fetch_result`, via
    ///   `DocumentState::merge_licenses`, from `Version::license()` on the already-fetched
    ///   version-list entry — today, only Composer's `impl_version!` includes a
    ///   `license:` field (`deps-composer/src/types.rs`); any ecosystem whose
    ///   `impl_version!` gains one automatically starts populating this map with no
    ///   further `fetch.rs` changes. **Not** populated for the deps.dev-routed tier-2
    ///   ecosystems (Cargo, npm, PyPI, Go, Bundler, Maven, NuGet) — their license is only
    ///   ever fetched by `trust_signal()`, which is deliberately hover-only (see
    ///   `VersionData::trust`'s docs); reaching it from here would mean a new deps.dev
    ///   call on every document open/edit, out of this backfill's "already in hand, no
    ///   new network calls" scope.
    /// - **Tier-3 pre-fetch**: `document::osv_scan::run_license_prefetch` (Dart, Swift,
    ///   Gradle, Deno only — see that function's docs), via `DocumentState::merge_licenses`
    ///   (round 3 finding #2: a plain `update_licenses` full replace would drop a
    ///   dependency's previously-cached, still-valid license whenever *any other*
    ///   dependency's fetch transiently failed this round), from a dedicated
    ///   per-ecosystem background fetch, mirroring [`Self::vulnerabilities`]'s
    ///   background-pre-fetch shape. A genuinely removed dependency's stale entry is
    ///   reclaimed by `document::lifecycle::commit_parsed_document`'s manifest-diff
    ///   pruning loop, not by this merge.
    ///
    /// Empty until the relevant fetch completes; carried across document edits by
    /// `preserve_cache` so it doesn't flicker off on every keystroke.
    pub licenses: HashMap<PackageName, Vec<String>>,
    /// Background-pre-fetched typosquat-suspect signal per declared dependency (issue
    /// #1437), keyed by raw (unnormalized) package name — mirrors [`Self::licenses`]'s exact
    /// shape and rationale. Populated by `document::osv_scan::run_typosquat_prefetch`, via
    /// `DocumentState::merge_typosquats` (never a full replace, for the same "one dependency's
    /// transient failure must not drop another's still-valid signal" reason
    /// [`Self::licenses`]'s doc gives). Read synchronously into
    /// `deps_core::VersionData::typosquat_prefetch` by `handlers::diagnostics`, never
    /// fetched inline on the diagnostics-generation path itself (NFR-002). Empty until the
    /// prefetch completes or when `policy.typosquat.enabled` is `false`; carried across
    /// document edits by `preserve_cache` so the diagnostic doesn't flicker off on every
    /// keystroke.
    pub typosquats: HashMap<PackageName, TyposquatSignal>,
    /// The declared (name, source-eligibility) set as of the last typosquat pre-fetch this
    /// document actually spawned (issue #1455 batch item 1, critic S1; the eligibility half of
    /// the key added by issue #1462) — compared against the *current* set by
    /// `document::lifecycle`'s debounced-edit gate, instead of that edit's own local
    /// `DependencyDiff`. A per-edit diff alone misses a name added by an edit whose own change
    /// task got aborted (superseded by the very next debounced edit) before ever reaching the
    /// pre-fetch spawn — the added name would then never be checked, since the *next* edit's
    /// own diff shows no name change either. Comparing against this persisted set self-corrects
    /// across any number of such aborted edits: whatever the document's true current
    /// (name, eligibility) pairs are, they either already match what was last actually checked,
    /// or they don't and a re-check is due, independent of which specific edit's diff would
    /// have flagged it. Pairing each name with its
    /// `super::super::osv_scan::TyposquatSourceEligibility` closes issue
    /// #1462's gap: only an eligible dependency is ever sent to deps.dev
    /// (`deps_core::lsp_helpers::fetch_typosquat_signals` applies the same filter), so a
    /// name-only key couldn't tell "already checked, still ineligible" apart from "same name,
    /// newly eligible" when a dependency's source flips (e.g. git -> registry) without its name
    /// changing. Carried across edits by `preserve_cache`, same as [`Self::typosquats`], and
    /// reset to empty on a fresh `DocumentState` (a cold-open/reopen document that has never
    /// been checked has nothing to compare against, so its first check is unconditional —
    /// matching the open-path pre-fetch's own unconditional spawn). Never pruned by
    /// [`Self::prune_removed`] (see that method's doc).
    pub(crate) typosquat_checked_names: HashSet<(
        PackageName,
        super::super::osv_scan::TyposquatSourceEligibility,
    )>,
    /// GOSSIP-sourced cooldown/low-usage findings per declared dependency (issue #1456,
    /// spec 072), keyed by raw (unnormalized) package name — mirrors [`Self::typosquats`]'s
    /// exact shape and rationale. Populated by `document::gossip_prefetch::run_gossip_prefetch`
    /// (see `DocumentState::merge_gossip_findings`), whose single call per prefetch cycle combines
    /// the per-package `DepsDevClient` memo's hits with this document's own
    /// `GetFindingsBatch` results for memo-misses — a name already claimed by another
    /// concurrent prefetch (elsewhere) is skipped this round rather than joined, so it
    /// lands here on that *other* prefetch's own commit or this document's next trigger,
    /// not necessarily this one (security/impl-critic review, corrects an earlier design
    /// note that claimed a true three-way join). A mid-fetch content change no longer drops
    /// the whole result (security/impl-critic S1) — the result is filtered down to names
    /// still declared in the document's current content and merged. Read synchronously into
    /// `deps_core::VersionData::gossip_prefetch` by `handlers::hover`/`handlers::diagnostics`,
    /// never fetched inline on either generation path. Empty until the prefetch completes
    /// or when `policy.gossip.enabled` is `false`; carried across document edits by
    /// `preserve_cache` so the signal doesn't flicker off on every keystroke.
    pub gossip_findings: HashMap<PackageName, GossipFindings>,
}

impl std::fmt::Debug for PackageSignals {
    /// Hand-written, not `#[derive(Debug)]`: a derived impl would dump every cached
    /// version list, license string, vulnerability record, and typosquat/GOSSIP finding
    /// in full whenever a `DocumentState` is formatted, instead of the count-only summary
    /// this mirrors from the pre-#1477 `DocumentState::fmt`. The exhaustive `let Self {..}`
    /// destructure (no `..`) makes a future field addition a compile error here until it's
    /// explicitly counted or deliberately omitted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            cached_versions,
            resolved_versions,
            resolved_version_candidates,
            resolved_versions_generation,
            vulnerabilities,
            outcomes,
            licenses,
            typosquats,
            typosquat_checked_names,
            gossip_findings,
        } = self;
        f.debug_struct("PackageSignals")
            .field("cached_versions_count", &cached_versions.len())
            .field("resolved_versions_count", &resolved_versions.len())
            .field(
                "resolved_version_candidates_count",
                &resolved_version_candidates.len(),
            )
            .field("resolved_versions_generation", resolved_versions_generation)
            .field("vulnerabilities_count", &vulnerabilities.len())
            .field("licenses_count", &licenses.len())
            .field("typosquats_count", &typosquats.len())
            .field(
                "typosquat_checked_names_count",
                &typosquat_checked_names.len(),
            )
            .field("gossip_findings_count", &gossip_findings.len())
            .field("yanked_versions_count", &outcomes.yanked_count())
            .field("deprecations_count", &outcomes.deprecation_count())
            .field("fetch_failed_count", &outcomes.fetch_failure_count())
            .finish()
    }
}

impl Default for PackageSignals {
    /// Every fresh or `did_close`-reopened `DocumentState` starts here — see
    /// `ResolvedGeneration`'s own doc for why sharing `INITIAL` across independent
    /// documents is safe.
    ///
    /// Hand-written rather than `#[derive(Default)]` so `ResolvedGeneration`
    /// itself never needs a `Default` impl (issue #1398 S1: a mintable default on that
    /// type would be exactly the arbitrary-value escape hatch it exists to forbid).
    fn default() -> Self {
        Self {
            cached_versions: HashMap::new(),
            resolved_versions: HashMap::new(),
            resolved_version_candidates: HashMap::new(),
            resolved_versions_generation: ResolvedGeneration::INITIAL,
            vulnerabilities: VulnerabilityMap::new(),
            outcomes: DependencyOutcomes::new(),
            licenses: HashMap::new(),
            typosquats: HashMap::new(),
            typosquat_checked_names: HashSet::new(),
            gossip_findings: HashMap::new(),
        }
    }
}

impl PackageSignals {
    /// Drops every raw-name-keyed entry for `removed`, and the corresponding
    /// normalized-name-keyed entry from [`Self::vulnerabilities`]/[`Self::outcomes`] —
    /// replaces the pruning loop that used to live inline in
    /// `document::lifecycle::commit_parsed_document` (issue #1477).
    ///
    /// Deliberately mirrors *only* the `diff.removed` loop, not a `retain_keys(current)`
    /// full resync: [`Self::vulnerabilities`] also holds version-qualified
    /// [`deps_core::osv::VulnKey`]s for dependencies no longer declared, which a
    /// resync-to-current-names approach would additionally drop (a behavior change out of
    /// scope for this refactor — see #1477's tracked follow-up).
    ///
    /// [`Self::resolved_versions_generation`] and [`Self::typosquat_checked_names`] are
    /// never pruned here: the generation is a document-wide scalar epoch, not
    /// per-package data, and pruning the checked-names set would make the very next
    /// debounced edit see a name/eligibility mismatch and re-spawn a typosquat pre-fetch
    /// for names that never actually changed (issue #1455 critic S1).
    pub(crate) fn prune_removed(
        &mut self,
        removed: &[PackageName],
        formatter: &dyn EcosystemFormatter,
    ) {
        let Self {
            cached_versions,
            resolved_versions,
            resolved_version_candidates,
            resolved_versions_generation: _,
            vulnerabilities,
            outcomes,
            licenses,
            typosquats,
            typosquat_checked_names: _,
            gossip_findings,
        } = self;
        for removed_dep in removed {
            cached_versions.remove(removed_dep);
            resolved_versions.remove(removed_dep);
            resolved_version_candidates.remove(removed_dep);
            licenses.remove(removed_dep);
            typosquats.remove(removed_dep);
            gossip_findings.remove(removed_dep);
            let normalized = formatter.normalize_package_name(removed_dep);
            vulnerabilities.retain(|key, _| key.as_str() != normalized);
            outcomes.remove(&normalized);
        }
    }

    /// Starts building an owned, opt-in-per-dimension [`SignalsSnapshot`] of this
    /// document's signals (issue #1471) — the shared replacement for every handler's own
    /// hand-cloned tuple of raw maps. `cached`/`resolved` are always included, mirroring
    /// [`deps_core::VersionData::new`]'s own two mandatory fields; every other dimension is
    /// opt-in via a `with_*` builder method, so a handler that never calls
    /// e.g. [`SignalsSnapshotBuilder::with_vulnerabilities`] never pays for cloning that map.
    pub(crate) fn snapshot(&self) -> SignalsSnapshotBuilder<'_> {
        SignalsSnapshotBuilder {
            signals: self,
            cached: self.cached_versions.clone(),
            resolved: self.resolved_versions.clone(),
            candidates: None,
            vulnerabilities: None,
            outcomes: None,
            licenses: None,
            typosquats: None,
            gossip: None,
        }
    }
}

/// Whether a prefetched typosquat/GOSSIP signal should actually be rendered by the
/// handler building a [`SignalsSnapshot`] (issue #1471) — an enum rather than a bare
/// `bool` flag, per this project's type-safety conventions.
///
/// A `Suppress`ed dimension is still attached to the resulting [`deps_core::VersionData`]
/// as `Some(&<empty map>)`, never left `None` (see [`SignalsSnapshotBuilder::with_typosquat_prefetch`]'s
/// doc) — callers downstream distinguish "checked, found nothing" (`Some` + empty) from
/// "never checked at all" (`None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrefetchVisibility {
    /// Attach the document's real prefetched map.
    Render,
    /// Attach an empty map instead of the document's real one — the feature is
    /// disabled, offline, or otherwise not currently applicable, but a previously
    /// populated map must not keep rendering (issue #1437 security review N1, issue
    /// #1456 spec 072's identical rationale for GOSSIP).
    Suppress,
}

/// Builder for [`SignalsSnapshot`], returned by [`PackageSignals::snapshot`]. Each
/// `with_*` method clones exactly one additional map out of the source [`PackageSignals`]
/// into the snapshot being built; a dimension never requested stays `None` in the
/// finished [`SignalsSnapshot`], and its clone is never performed.
pub(crate) struct SignalsSnapshotBuilder<'a> {
    signals: &'a PackageSignals,
    cached: HashMap<PackageName, PackageVersions>,
    resolved: HashMap<PackageName, ConcreteVersion>,
    candidates: Option<HashMap<PackageName, Vec<ConcreteVersion>>>,
    vulnerabilities: Option<VulnerabilityMap>,
    outcomes: Option<DependencyOutcomes>,
    licenses: Option<HashMap<PackageName, Vec<String>>>,
    typosquats: Option<HashMap<PackageName, TyposquatSignal>>,
    gossip: Option<HashMap<PackageName, GossipFindings>>,
}

impl SignalsSnapshotBuilder<'_> {
    /// Attaches [`PackageSignals::resolved_version_candidates`].
    #[must_use]
    pub(crate) fn with_resolved_version_candidates(mut self) -> Self {
        self.candidates = Some(self.signals.resolved_version_candidates.clone());
        self
    }

    /// Attaches [`PackageSignals::vulnerabilities`].
    #[must_use]
    pub(crate) fn with_vulnerabilities(mut self) -> Self {
        self.vulnerabilities = Some(self.signals.vulnerabilities.clone());
        self
    }

    /// Attaches [`PackageSignals::outcomes`].
    #[must_use]
    pub(crate) fn with_outcomes(mut self) -> Self {
        self.outcomes = Some(self.signals.outcomes.clone());
        self
    }

    /// Attaches [`PackageSignals::licenses`] as tier-3 license-prefetch data (see
    /// [`deps_core::VersionData::license_prefetch`]).
    #[must_use]
    pub(crate) fn with_license_prefetch(mut self) -> Self {
        self.licenses = Some(self.signals.licenses.clone());
        self
    }

    /// Attaches [`PackageSignals::typosquats`], or an empty map when `visibility` is
    /// [`PrefetchVisibility::Suppress`] — see that type's doc for why this is `Some(&empty)`,
    /// never `None`, in the suppressed case.
    #[must_use]
    pub(crate) fn with_typosquat_prefetch(mut self, visibility: PrefetchVisibility) -> Self {
        self.typosquats = Some(match visibility {
            PrefetchVisibility::Render => self.signals.typosquats.clone(),
            PrefetchVisibility::Suppress => HashMap::new(),
        });
        self
    }

    /// Attaches [`PackageSignals::gossip_findings`], or an empty map when `visibility` is
    /// [`PrefetchVisibility::Suppress`] — mirrors [`Self::with_typosquat_prefetch`]'s exact
    /// rationale.
    #[must_use]
    pub(crate) fn with_gossip_prefetch(mut self, visibility: PrefetchVisibility) -> Self {
        self.gossip = Some(match visibility {
            PrefetchVisibility::Render => self.signals.gossip_findings.clone(),
            PrefetchVisibility::Suppress => HashMap::new(),
        });
        self
    }

    /// Finishes the snapshot, consuming the builder.
    #[must_use]
    pub(crate) fn finish(self) -> SignalsSnapshot {
        SignalsSnapshot {
            cached: self.cached,
            resolved: self.resolved,
            candidates: self.candidates,
            vulnerabilities: self.vulnerabilities,
            outcomes: self.outcomes,
            licenses: self.licenses,
            typosquats: self.typosquats,
            gossip: self.gossip,
        }
    }
}

/// An owned, per-handler-scoped snapshot of a document's [`PackageSignals`] (issue
/// #1471), built via [`PackageSignals::snapshot`] and consumed by [`Self::version_data`].
///
/// Replaces each handler's own hand-cloned tuple of raw maps plus hand-chained
/// `deps_core::VersionData::with_*` calls: a handler now opts into exactly the
/// dimensions it uses (e.g. `.with_vulnerabilities()`), and every dimension it doesn't
/// request simply isn't cloned.
pub(crate) struct SignalsSnapshot {
    cached: HashMap<PackageName, PackageVersions>,
    resolved: HashMap<PackageName, ConcreteVersion>,
    candidates: Option<HashMap<PackageName, Vec<ConcreteVersion>>>,
    vulnerabilities: Option<VulnerabilityMap>,
    outcomes: Option<DependencyOutcomes>,
    licenses: Option<HashMap<PackageName, Vec<String>>>,
    typosquats: Option<HashMap<PackageName, TyposquatSignal>>,
    gossip: Option<HashMap<PackageName, GossipFindings>>,
}

impl SignalsSnapshot {
    /// Builds a [`deps_core::VersionData`] borrowing from this snapshot's owned maps,
    /// attaching every dimension the snapshot was built with. Scalar dimensions
    /// (ecosystem, offline, license source/policy, trust, gossip client) are not part of
    /// a `SignalsSnapshot` — they aren't per-package state — and stay on the caller's own
    /// `VersionData::with_*` chain after this call.
    pub(crate) fn version_data(&self) -> VersionData<'_> {
        let mut data = VersionData::new(&self.cached, &self.resolved);
        if let Some(candidates) = &self.candidates {
            data = data.with_resolved_version_candidates(candidates);
        }
        if let Some(vulnerabilities) = &self.vulnerabilities {
            data = data.with_vulnerabilities(vulnerabilities);
        }
        if let Some(outcomes) = &self.outcomes {
            data = data.with_outcomes(outcomes);
        }
        if let Some(licenses) = &self.licenses {
            data = data.with_license_prefetch(licenses);
        }
        if let Some(typosquats) = &self.typosquats {
            data = data.with_typosquat_prefetch(typosquats);
        }
        if let Some(gossip) = &self.gossip {
            data = data.with_gossip_prefetch(gossip);
        }
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::osv::ScanOutcome;
    use deps_core::test_util::{StubFormatter, vuln_key};
    use deps_core::{DependencyOutcomes, RemovalStatus};

    const LOWERCASE_FORMATTER: StubFormatter = StubFormatter::new().with_lowercase_names();

    fn eligible() -> crate::document::osv_scan::TyposquatSourceEligibility {
        crate::document::osv_scan::TyposquatSourceEligibility::Eligible
    }

    /// One entry for `"MyPkg"` (the name every test below asks `prune_removed` to remove)
    /// and one for `"Other"` (a survivor) in each map `prune_removed` actually prunes.
    /// `vulnerabilities`/`outcomes` additionally get a `"mypkg"` (already-normalized-cased)
    /// entry, since those two are normalized-name-keyed — mirroring a Composer/PyPI-style
    /// ecosystem where `normalize_package_name` changes the string.
    ///
    /// `typosquats`/`gossip_findings` are deliberately left empty here: their value types
    /// (`TyposquatSignal`, `GossipFindings`) are `#[non_exhaustive]` with no public or
    /// `test_util` constructor (by design — see `handlers::diagnostics`'s
    /// `resolve_test_crossenv_typosquat_signal` test helper, which resolves a real signal
    /// through a mocked deps.dev server for exactly this reason), so a unit-level fixture
    /// can't populate them. Both fields are pruned by the exact same one-line
    /// `map.remove(removed_dep)` call this fixture already exercises for `licenses` below.
    fn fixture() -> PackageSignals {
        let mut signals = PackageSignals::default();
        signals.cached_versions.insert(
            PackageName::new("MyPkg"),
            PackageVersions::latest_only("1.0.0"),
        );
        signals.cached_versions.insert(
            PackageName::new("Other"),
            PackageVersions::latest_only("2.0.0"),
        );
        signals
            .resolved_versions
            .insert(PackageName::new("MyPkg"), ConcreteVersion::new("1.0.0"));
        signals
            .resolved_versions
            .insert(PackageName::new("Other"), ConcreteVersion::new("2.0.0"));
        signals.resolved_version_candidates.insert(
            PackageName::new("MyPkg"),
            vec![ConcreteVersion::new("1.0.0")],
        );
        signals.resolved_version_candidates.insert(
            PackageName::new("Other"),
            vec![ConcreteVersion::new("2.0.0")],
        );
        signals
            .licenses
            .insert(PackageName::new("MyPkg"), vec!["MIT".to_string()]);
        signals
            .licenses
            .insert(PackageName::new("Other"), vec!["Apache-2.0".to_string()]);
        // Normalized-keyed: an entry under the *normalized* ("mypkg") form must be pruned; one
        // under the raw-cased ("MyPkg") form must NOT be — a different key from
        // `prune_removed`'s point of view, proving normalization (not the raw name) drives the
        // comparison.
        signals
            .vulnerabilities
            .insert(vuln_key("mypkg"), ScanOutcome::Clean);
        signals
            .vulnerabilities
            .insert(vuln_key("MyPkg"), ScanOutcome::Clean);
        signals
            .vulnerabilities
            .insert(vuln_key("other"), ScanOutcome::Clean);
        signals.outcomes = DependencyOutcomes::new()
            .with_yanked(
                "mypkg",
                (ConcreteVersion::new("1.0.0"), RemovalStatus::Yanked),
            )
            .with_yanked(
                "other",
                (ConcreteVersion::new("2.0.0"), RemovalStatus::Yanked),
            );
        signals
            .typosquat_checked_names
            .insert((PackageName::new("MyPkg"), eligible()));
        signals
    }

    #[test]
    fn prune_removed_drops_raw_and_normalized_entries_for_removed_name_only() {
        let mut signals = fixture();
        signals.prune_removed(&[PackageName::new("MyPkg")], &LOWERCASE_FORMATTER);

        // Raw-name-keyed maps: the removed name's entry is gone, the survivor's is not.
        assert!(
            !signals
                .cached_versions
                .contains_key(&PackageName::new("MyPkg"))
        );
        assert!(
            signals
                .cached_versions
                .contains_key(&PackageName::new("Other"))
        );
        assert!(
            !signals
                .resolved_versions
                .contains_key(&PackageName::new("MyPkg"))
        );
        assert!(
            signals
                .resolved_versions
                .contains_key(&PackageName::new("Other"))
        );
        assert!(
            !signals
                .resolved_version_candidates
                .contains_key(&PackageName::new("MyPkg"))
        );
        assert!(
            signals
                .resolved_version_candidates
                .contains_key(&PackageName::new("Other"))
        );
        assert!(!signals.licenses.contains_key(&PackageName::new("MyPkg")));
        assert!(signals.licenses.contains_key(&PackageName::new("Other")));

        // Normalized-name-keyed maps: only the entry matching the *normalized* removed name
        // is dropped; a raw-cased key that differs from the normalized form survives.
        assert!(!signals.vulnerabilities.contains_key(&vuln_key("mypkg")));
        assert!(signals.vulnerabilities.contains_key(&vuln_key("MyPkg")));
        assert!(signals.vulnerabilities.contains_key(&vuln_key("other")));
        assert!(signals.outcomes.yanked("mypkg").is_none());
        assert!(signals.outcomes.yanked("other").is_some());
    }

    #[test]
    fn prune_removed_never_touches_generation_or_checked_names() {
        let mut signals = fixture();
        let generation_before = signals.resolved_versions_generation;
        let checked_before = signals.typosquat_checked_names.clone();

        signals.prune_removed(&[PackageName::new("MyPkg")], &LOWERCASE_FORMATTER);

        assert_eq!(signals.resolved_versions_generation, generation_before);
        assert_eq!(signals.typosquat_checked_names, checked_before);
    }

    #[test]
    fn default_generation_starts_at_initial() {
        assert!(
            PackageSignals::default()
                .resolved_versions_generation
                .is_initial()
        );
    }

    #[test]
    fn snapshot_leaves_unselected_dimensions_as_none() {
        let signals = fixture();
        let snapshot = signals.snapshot().finish();
        let data = snapshot.version_data();
        assert!(data.resolved_version_candidates.is_none());
        assert!(data.vulnerabilities.is_none());
        assert!(data.outcomes.is_none());
        assert!(data.license_prefetch.is_none());
        assert!(data.typosquat_prefetch.is_none());
        assert!(data.gossip_prefetch.is_none());
    }

    #[test]
    fn snapshot_selected_dimensions_attach_source_data() {
        let signals = fixture();
        let snapshot = signals
            .snapshot()
            .with_resolved_version_candidates()
            .with_vulnerabilities()
            .with_outcomes()
            .with_license_prefetch()
            .finish();
        let data = snapshot.version_data();
        assert_eq!(data.resolved_version_candidates.map(HashMap::len), Some(2));
        assert_eq!(data.vulnerabilities.map(HashMap::len), Some(3));
        assert_eq!(
            data.outcomes.map(|o| o.yanked("mypkg").is_some()),
            Some(true)
        );
        assert_eq!(data.license_prefetch.map(HashMap::len), Some(2));
    }

    #[test]
    fn snapshot_suppressed_typosquat_and_gossip_prefetch_is_some_empty_not_none() {
        let snapshot = fixture()
            .snapshot()
            .with_typosquat_prefetch(PrefetchVisibility::Suppress)
            .with_gossip_prefetch(PrefetchVisibility::Suppress)
            .finish();
        let data = snapshot.version_data();
        // Suppressed: attached (`Some`) but empty, not `None` — downstream distinguishes
        // "checked, found nothing" from "never checked" (see `PrefetchVisibility`'s doc).
        assert_eq!(data.typosquat_prefetch, Some(&HashMap::new()));
        assert_eq!(data.gossip_prefetch, Some(&HashMap::new()));
    }
}
