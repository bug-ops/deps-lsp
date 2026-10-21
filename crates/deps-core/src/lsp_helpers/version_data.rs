//! [`VersionData`]: the read-only bundle of per-document registry, lock-file and scan state
//! every LSP response builder consumes.

use std::collections::HashMap;
use std::sync::Arc;

#[cfg(all(doc, feature = "lsp-responses"))]
use super::generate_hover;
#[cfg(doc)]
use super::{
    DependencyOutcome, REGISTRY_FETCH_BUDGET, await_interactive_fetch, candidate_verdict,
    generate_diagnostics_from_cache, latest_verdict, local_cooldown_precedence,
};
use super::{DependencyOutcomes, GossipFindings, InteractiveFetchGate};
use crate::licenses::LicensePolicy;
use crate::osv::{CandidateStatusMap, LatestStatusMap, VulnerabilityMap};
use crate::{
    ConcreteVersion, DepsDevClient, EcosystemId, LicenseSource, NormalizedName, PackageKey,
    PackageVersions, TyposquatSignal,
};

/// Registry data per package, keyed by the ecosystem-normalized name.
///
/// A declared name cannot probe it:
///
/// ```compile_fail
/// use deps_core::{CachedVersionsMap, PackageName};
///
/// let cached = CachedVersionsMap::new();
/// let _ = cached.get(&PackageName::new("serde"));
/// ```
pub type CachedVersionsMap = HashMap<NormalizedName, PackageVersions>;

/// Lock-file-resolved version per package, keyed by the ecosystem-normalized name.
pub type ResolvedVersionsMap = HashMap<NormalizedName, ConcreteVersion>;

/// Every retained lock-file version per package, keyed by the ecosystem-normalized name.
pub type ResolvedCandidatesMap = HashMap<NormalizedName, Vec<ConcreteVersion>>;

/// Bundles the per-package version maps (`cached`, `resolved`, the optional lock-file
/// candidates) that LSP handlers pass together everywhere.
///
/// Grouping them prevents accidentally swapping the map arguments at a call site, since the
/// compiler can no longer typecheck them positionally. Every per-package map is keyed by
/// [`NormalizedName`], so a read takes a [`PackageKey`] ([`Self::cached_for`],
/// [`Self::resolved_for`], [`Self::resolved_candidates_for`], [`Self::is_resolved`]) and a
/// declared [`crate::PackageName`] cannot probe one by accident.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::PackageNaming;
/// use deps_core::{ConcreteVersion, PackageKey, PackageName, PackageVersions, VersionData};
/// use std::collections::HashMap;
///
/// struct Identity;
/// impl PackageNaming for Identity {}
///
/// let key = PackageKey::new(&PackageName::new("serde"), &Identity);
///
/// let mut cached = HashMap::new();
/// cached.insert(key.normalized().clone(), PackageVersions::latest_only("1.0.214"));
///
/// let mut resolved = HashMap::new();
/// resolved.insert(key.normalized().clone(), ConcreteVersion::new("1.0.200"));
///
/// let versions = VersionData::new(&cached, &resolved);
///
/// assert_eq!(versions.cached_for(&key).map(|v| v.latest.as_str()), Some("1.0.214"));
/// assert_eq!(versions.resolved_for(&key).map(ConcreteVersion::as_str), Some("1.0.200"));
/// ```
///
/// The maps themselves are not reachable from outside the crate:
///
/// ```compile_fail
/// use deps_core::VersionData;
/// use std::collections::HashMap;
///
/// let cached = HashMap::new();
/// let resolved = HashMap::new();
/// let versions = VersionData::new(&cached, &resolved);
/// let _ = versions.cached.len();
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct VersionData<'a> {
    /// Latest known versions and full version lists from the registry, keyed by normalized package name.
    cached: &'a CachedVersionsMap,
    /// Versions actually resolved in the lock file, keyed by normalized package name.
    resolved: &'a ResolvedVersionsMap,
    /// Every lock-file-resolved version for a normalized package name, when more than one is retained
    /// (issue #649) — additive alongside [`Self::resolved_for`], which stays the single
    /// collapsed value for the common case. `None` by default (most call sites have no such
    /// map); [`crate::lsp_helpers::resolve_in_use_version`] and [`crate::osv::vulnerability_keys`]
    /// consult it to disambiguate two manifest occurrences of one resolved name (e.g. a
    /// Cargo `package = "..."` rename pinning an older major) by each occurrence's own
    /// `version_requirement()`, falling back to [`Self::resolved_for`] when a name has at most
    /// one candidate.
    resolved_version_candidates: Option<&'a ResolvedCandidatesMap>,
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
    /// The current [`NetworkMode`](crate::NetworkMode) (issue #483). When
    /// [`NetworkMode::Offline`](crate::NetworkMode::Offline), [`generate_hover`] appends a
    /// footer stating that version *and vulnerability* data were not checked — deliberately
    /// more specific than a bare "showing cached data" notice, since `hover.rs`'s
    /// `Some(ScanOutcome::Skipped(_)) | None` arm renders nothing for an offline OSV skip,
    /// which would otherwise look identical to a scanned-and-clean dependency.
    pub network: crate::NetworkMode,
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
    /// Background-pre-fetched license data for ecosystems `deps_dev_system` doesn't
    /// cover and whose hot-path registry response carries no license field — Dart,
    /// Swift, Gradle, Deno (issue #660, spec 010 plan §1 tier 3), keyed by normalized
    /// package name. `None` by default. Populated from `DocumentState`'s
    /// per-document pre-fetch cache (`document::osv_scan::run_license_prefetch` on
    /// document open/change — mirrors [`Self::vulnerabilities`]'s "populated by a
    /// background task, read synchronously here" shape) by `handlers/hover.rs` (deps-lsp)
    /// for hover, and by `handlers/diagnostics.rs`'s `textDocument/diagnostic` pull path
    /// for [`generate_diagnostics_from_cache`]'s license-policy rule (issue #661) — see
    /// [`Self::license_policy`].
    ///
    /// **What version this actually reflects is per-ecosystem, not uniformly the
    /// resolved version** (critic S1 — corrects a previous blanket claim here that it
    /// "only ever covers the resolved version"): Gradle's Maven Central POM fetch and
    /// Deno's JSR per-version API are genuinely fetched at the dependency's resolved/
    /// in-use version. Dart's pub.dev `/score` endpoint is per-*package*, not
    /// per-version — it reflects pana's detection on whatever pub.dev most recently
    /// scored, unrelated to which version is resolved. Swift's GitHub
    /// `GET /repos/{owner}/{repo}` reflects the repository's default branch, not the
    /// resolved version's tag. Every source here is still a background pre-fetch gated
    /// on a version having been resolved at all (no in-use version means nothing to
    /// look up), but only Gradle/Deno are actually version-*specific* in what they
    /// return.
    pub license_prefetch: Option<&'a HashMap<NormalizedName, Vec<String>>>,
    /// How [`Self::license_prefetch`]'s (and, for a resolved-version match, the
    /// registry-declared) license strings are sourced (issue #688), consulted by
    /// [`generate_hover`] for the "(detected)" qualifier and by
    /// [`generate_diagnostics_from_cache`]'s license-policy rule to decide whether
    /// [`crate::licenses::resolve_license_entries`] must normalize free text before
    /// evaluation. `None` in most test fixtures and any handler that doesn't go through
    /// [`crate::Ecosystem::generate_hover`]/[`crate::Ecosystem::generate_diagnostics`]'s
    /// default implementation, which is what actually attaches this field via
    /// `self.license_source()` — falls back to
    /// [`LicenseSource::RegistryDeclaredSpdx`] (`Default`) wherever consumed.
    pub license_source: Option<LicenseSource>,
    /// SPDX allow-list/deny-list license policy (issue #661, spec 010 Phase 2), when the
    /// caller wants diagnostics evaluated against one. `None` by default.
    ///
    /// Unlike [`Self::trust`], this is **not** hover-only-scoped: `deps-lsp`'s
    /// `handlers/diagnostics.rs::generate_diagnostics_internal` attaches the currently
    /// configured policy (cached on `ServerState`, kept live-updated by
    /// `Backend::initialize`/`did_change_configuration`) unconditionally, so every
    /// diagnostics-generation call site — the `textDocument/diagnostic` pull path *and*
    /// every push-path background refresh (fetch-completion, watched-config reparse,
    /// lock-file change) — evaluates the same policy. An earlier revision scoped this
    /// field to the pull path only, following `Self::trust`'s hover-only precedent; that
    /// was a false analogy (issue #660/#661 critic C1) — `trust` is safe hover-only
    /// because hover has exactly one producer per request, but diagnostics has multiple
    /// producers all replacing the same client-visible `publish_diagnostics` set, so a
    /// caller-scoped policy meant the license diagnostic flickered in and out on every
    /// edit and was invisible to push-only clients.
    /// [`generate_diagnostics_from_cache`]'s license-policy rule reads this alongside
    /// [`Self::license_prefetch`] — so today it only actually fires for tier-3 ecosystems
    /// (Dart/Swift/Deno; Gradle is explicitly excluded, see that rule's doc comment), the
    /// only ones `license_prefetch` covers; this field and the rule are otherwise
    /// ecosystem-agnostic and need no change as `license_prefetch`'s coverage widens.
    pub license_policy: Option<&'a LicensePolicy>,
    /// Background-pre-fetched typosquat-suspect signal per declared dependency (issue
    /// #1437, spec 071), keyed by normalized package name — mirrors
    /// [`Self::license_prefetch`]'s exact shape and rationale (NFR-002: this must never be
    /// an inline `.await` on the diagnostics-generation path, so it is resolved ahead of
    /// time by a document-lifecycle background task,
    /// `deps-lsp::document::typosquat::run_typosquat_prefetch`, and merely read
    /// synchronously here — see that function's doc). Consumed directly inside
    /// [`generate_diagnostics_from_cache`] itself (not gated behind
    /// `Ecosystem::generate_diagnostics`'s default impl), the same way
    /// [`Self::license_prefetch`] is, so every ecosystem's `generate_diagnostics`
    /// override — not just the shared default — picks up the diagnostic automatically
    /// (issue #1437 security-review finding: an override that calls
    /// [`generate_diagnostics_from_cache`] directly, as `deps-npm`'s catalog-diagnostics
    /// override does, must never be able to silently bypass this). `None` when the feature
    /// is disabled, the ecosystem isn't deps.dev-covered, offline, or no dependency in the
    /// document cleared the ratio gate.
    pub typosquat_prefetch: Option<&'a HashMap<NormalizedName, TyposquatSignal>>,
    /// Background-pre-fetched deps.dev GOSSIP cooldown/low-usage findings per declared
    /// dependency (issue #1456, spec 072), keyed by normalized package name —
    /// mirrors [`Self::typosquat_prefetch`]'s exact shape and rationale: populated by
    /// `deps-lsp::document::gossip_prefetch`, via `DocumentState::signals.gossip_findings`, and
    /// merely read synchronously here — never fetched inline on the hover/diagnostics-
    /// generation path itself.
    ///
    /// A lookup hit is only trustworthy for the version it was resolved against
    /// (spec 072 FR-008) — the entry's own [`crate::GossipFindings::version`] field must
    /// be compared against the version actually being displayed at each call site (hover's
    /// `latest_line`, diagnostics' `package_versions.latest`) before use; a mismatch is
    /// treated as a cache miss and falls back to [`local_cooldown_precedence`]. `None`
    /// when the feature is disabled, offline, the ecosystem isn't deps.dev-covered, or no
    /// dependency in the document has a prefetch result yet.
    pub gossip_prefetch: Option<&'a HashMap<NormalizedName, GossipFindings>>,
    /// The deps.dev client to fetch hover's live GOSSIP low-usage signal through (issue
    /// #1456, spec 072 FR-005/FR-009), when the caller wants hover to attempt one. `None`
    /// by default, mirroring [`Self::trust`]'s exact "presence is the gate" shape (FR-010's
    /// structural pattern) — set only by `handlers/hover.rs` (deps-lsp) when
    /// `GossipConfig.enabled` is set and not offline. Deliberately a **separate** field
    /// from [`Self::trust`], not reused: `SupplyChainConfig.enabled` (opt-out, default
    /// `true`) and `GossipConfig.enabled` (opt-in, default `false`) are independently
    /// switchable — conflating the two fields would let disabling supply-chain trust
    /// signals silently disable GOSSIP's low-usage fetch too, or vice versa. `&'a Arc<..>`,
    /// not `&'a DepsDevClient`, for the same "clone into a detached background task"
    /// reason [`Self::trust`]'s doc gives.
    pub gossip_client: Option<&'a Arc<DepsDevClient>>,
    /// Phase B's per-key "latest" check result (issue #1517), keyed the same way as
    /// [`Self::vulnerabilities`] — see [`crate::osv::LatestStatusMap`]. `None` means OSV
    /// checking is disabled or offline for this scan entirely, distinct from `Some(map)` with a
    /// missing/`Unverified` entry for one dependency (which [`latest_verdict`] treats as
    /// fail-closed, not "not applicable"). Every renderer that surfaces a dependency's `latest`
    /// as an upgrade recommendation (hover, diagnostics, code actions, code lens, inlay hints,
    /// completion) must consult [`latest_verdict`] with this field before treating that `latest`
    /// as safe.
    pub latest_status: Option<&'a LatestStatusMap>,
    /// Phase B's per-(dependency, candidate-version) OSV check result (#1524) — see
    /// [`crate::osv::CandidateStatusMap`]. `None` means OSV checking is disabled or offline for
    /// this scan entirely, mirroring [`Self::latest_status`]'s identical distinction. A
    /// candidate-offering surface (code actions' "update to X" list, completion's version
    /// items) must consult [`candidate_verdict`] with this field for every version it is about
    /// to offer, not only the one [`Self::latest_status`] already covers.
    pub candidate_status: Option<&'a CandidateStatusMap>,
    /// Failure memo and concurrency cap for hover's and code actions' interactive registry
    /// await (#1830). `None` by default — and for every surface but `handlers/hover.rs` and
    /// `handlers/code_actions.rs` (deps-lsp) — which keeps the plain
    /// [`REGISTRY_FETCH_BUDGET`]-bounded await; see [`await_interactive_fetch`].
    pub interactive_fetch: Option<&'a InteractiveFetchGate>,
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
    /// assert!(versions.vulnerabilities.is_none());
    /// ```
    pub fn new(cached: &'a CachedVersionsMap, resolved: &'a ResolvedVersionsMap) -> Self {
        Self {
            cached,
            resolved,
            resolved_version_candidates: None,
            vulnerabilities: None,
            outcomes: None,
            ecosystem: None,
            network: crate::NetworkMode::Online,
            trust: None,
            license_prefetch: None,
            license_source: None,
            license_policy: None,
            typosquat_prefetch: None,
            gossip_prefetch: None,
            gossip_client: None,
            latest_status: None,
            candidate_status: None,
            interactive_fetch: None,
        }
    }

    /// The registry entry for `key`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::PackageNaming;
    /// use deps_core::{PackageKey, PackageName, PackageVersions, VersionData};
    /// use std::collections::HashMap;
    ///
    /// struct Identity;
    /// impl PackageNaming for Identity {}
    ///
    /// let hit = PackageKey::new(&PackageName::new("serde"), &Identity);
    /// let mut cached = HashMap::new();
    /// cached.insert(hit.normalized().clone(), PackageVersions::latest_only("1.0.214"));
    /// let resolved = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved);
    ///
    /// let miss = PackageKey::new(&PackageName::new("tokio"), &Identity);
    /// assert!(versions.cached_for(&hit).is_some());
    /// assert!(versions.cached_for(&miss).is_none());
    /// ```
    #[must_use]
    pub fn cached_for(&self, key: &PackageKey) -> Option<&'a PackageVersions> {
        self.cached.get(key.normalized())
    }

    /// The lock-file-resolved version for `key`.
    #[must_use]
    pub fn resolved_for(&self, key: &PackageKey) -> Option<&'a ConcreteVersion> {
        self.resolved.get(key.normalized())
    }

    /// Whether the lock file resolved `key`.
    #[must_use]
    pub fn is_resolved(&self, key: &PackageKey) -> bool {
        self.resolved_for(key).is_some()
    }

    /// Every lock-file-resolved version retained for `key` (see
    /// [`Self::with_resolved_version_candidates`]), or `None` when no candidates map is attached
    /// or it has no entry for the package.
    #[must_use]
    pub fn resolved_candidates_for(&self, key: &PackageKey) -> Option<&'a [ConcreteVersion]> {
        self.resolved_version_candidates
            .and_then(|candidates| candidates.get(key.normalized()))
            .map(Vec::as_slice)
    }

    /// The whole lock-file map, for deps-core helpers that take the raw map.
    pub(crate) const fn resolved_map(&self) -> &'a ResolvedVersionsMap {
        self.resolved
    }

    /// The whole candidates map, for deps-core helpers that take the raw map.
    pub(crate) const fn candidates_map(&self) -> Option<&'a ResolvedCandidatesMap> {
        self.resolved_version_candidates
    }

    /// Attaches the interactive-fetch gate that lets hover and code actions skip a registry
    /// await already known to fail (#1830).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::lsp_helpers::InteractiveFetchGate;
    /// use std::collections::HashMap;
    /// use std::num::NonZeroUsize;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let gate = InteractiveFetchGate::new(NonZeroUsize::new(4).unwrap());
    /// let versions = VersionData::new(&cached, &resolved).with_interactive_fetch_gate(&gate);
    /// assert!(versions.interactive_fetch.is_some());
    /// ```
    #[must_use]
    pub const fn with_interactive_fetch_gate(mut self, gate: &'a InteractiveFetchGate) -> Self {
        self.interactive_fetch = Some(gate);
        self
    }

    /// Attaches the per-name lock-file candidates map, enabling the per-occurrence
    /// disambiguation described on [`Self::resolved_candidates_for`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::PackageNaming;
    /// use deps_core::{ConcreteVersion, PackageKey, PackageName, VersionData};
    /// use std::collections::HashMap;
    ///
    /// struct Identity;
    /// impl PackageNaming for Identity {}
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let key = PackageKey::new(&PackageName::new("serde"), &Identity);
    /// let mut candidates = HashMap::new();
    /// candidates.insert(key.normalized().clone(), vec![ConcreteVersion::new("1.0.200")]);
    /// let versions =
    ///     VersionData::new(&cached, &resolved).with_resolved_version_candidates(&candidates);
    /// assert_eq!(versions.resolved_candidates_for(&key).map(<[_]>::len), Some(1));
    /// ```
    #[must_use]
    pub const fn with_resolved_version_candidates(
        mut self,
        candidates: &'a ResolvedCandidatesMap,
    ) -> Self {
        self.resolved_version_candidates = Some(candidates);
        self
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

    /// Attaches phase B's per-key "latest" check result to this `VersionData`. See
    /// [`Self::latest_status`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::osv::LatestStatusMap;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let latest_status = LatestStatusMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_latest_status(&latest_status);
    /// assert!(versions.latest_status.is_some());
    /// ```
    #[must_use]
    pub fn with_latest_status(mut self, latest_status: &'a LatestStatusMap) -> Self {
        self.latest_status = Some(latest_status);
        self
    }

    /// Attaches phase B's per-candidate-version check result to this `VersionData`. See
    /// [`Self::candidate_status`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::osv::CandidateStatusMap;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let candidate_status = CandidateStatusMap::new();
    /// let versions =
    ///     VersionData::new(&cached, &resolved).with_candidate_status(&candidate_status);
    /// assert!(versions.candidate_status.is_some());
    /// ```
    #[must_use]
    pub fn with_candidate_status(mut self, candidate_status: &'a CandidateStatusMap) -> Self {
        self.candidate_status = Some(candidate_status);
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
    /// let versions = VersionData::new(&cached, &resolved).with_network(deps_core::NetworkMode::Offline);
    /// assert_eq!(versions.network, deps_core::NetworkMode::Offline);
    /// ```
    #[must_use]
    pub const fn with_network(mut self, network: crate::NetworkMode) -> Self {
        self.network = network;
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

    /// Attaches tier-3 pre-fetched license data. See [`Self::license_prefetch`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let licenses = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_license_prefetch(&licenses);
    /// assert!(versions.license_prefetch.is_some());
    /// ```
    #[must_use]
    pub const fn with_license_prefetch(
        mut self,
        licenses: &'a HashMap<NormalizedName, Vec<String>>,
    ) -> Self {
        self.license_prefetch = Some(licenses);
        self
    }

    /// Attaches this ecosystem's license source. See [`Self::license_source`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{LicenseSource, VersionData};
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let versions =
    ///     VersionData::new(&cached, &resolved).with_license_source(LicenseSource::PomFreeText);
    /// assert_eq!(versions.license_source, Some(LicenseSource::PomFreeText));
    /// ```
    #[must_use]
    pub const fn with_license_source(mut self, source: LicenseSource) -> Self {
        self.license_source = Some(source);
        self
    }

    /// Attaches a license policy for diagnostics evaluation. See [`Self::license_policy`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{LicensePolicy, VersionData};
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);
    /// let versions = VersionData::new(&cached, &resolved).with_license_policy(&policy);
    /// assert!(versions.license_policy.is_some());
    /// ```
    #[must_use]
    pub const fn with_license_policy(mut self, policy: &'a LicensePolicy) -> Self {
        self.license_policy = Some(policy);
        self
    }

    /// Attaches background-pre-fetched typosquat signals. See [`Self::typosquat_prefetch`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let typosquat = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_typosquat_prefetch(&typosquat);
    /// assert!(versions.typosquat_prefetch.is_some());
    /// ```
    #[must_use]
    pub const fn with_typosquat_prefetch(
        mut self,
        typosquat_prefetch: &'a HashMap<NormalizedName, TyposquatSignal>,
    ) -> Self {
        self.typosquat_prefetch = Some(typosquat_prefetch);
        self
    }

    /// Attaches background-pre-fetched GOSSIP findings. See [`Self::gossip_prefetch`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let gossip = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_gossip_prefetch(&gossip);
    /// assert!(versions.gossip_prefetch.is_some());
    /// ```
    #[must_use]
    pub const fn with_gossip_prefetch(
        mut self,
        gossip_prefetch: &'a HashMap<NormalizedName, GossipFindings>,
    ) -> Self {
        self.gossip_prefetch = Some(gossip_prefetch);
        self
    }

    /// Attaches a deps.dev client, enabling hover to attempt a live GOSSIP low-usage fetch.
    /// See [`Self::gossip_client`].
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
    /// let versions = VersionData::new(&cached, &resolved).with_gossip_client(&client);
    /// assert!(versions.gossip_client.is_some());
    /// ```
    #[must_use]
    pub const fn with_gossip_client(mut self, client: &'a Arc<DepsDevClient>) -> Self {
        self.gossip_client = Some(client);
        self
    }
}
