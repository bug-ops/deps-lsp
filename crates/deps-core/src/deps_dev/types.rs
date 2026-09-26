//! Wire types for deps.dev API v3 responses, plus the public,
//! ecosystem-agnostic types the hover-formatting layer consumes.
//!
//! Wire types declare only the fields this spec actually reads — serde
//! ignores unknown fields by default, so deps.dev's much larger response
//! shape (`licenses`, `isDeprecated`, `advisoryKeys`, `checks[]`,
//! `scorecard.version`, ...) never needs a struct field here (spec §5,
//! Out of Scope).

use serde::{Deserialize, Serialize};

/// Parsed subset of `GET /v3/systems/{system}/packages/{name}/versions/{version}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DepsDevVersionInfo {
    #[serde(default)]
    pub(super) slsa_provenances: Vec<ProvenanceEntry>,
    #[serde(default)]
    pub(super) attestations: Vec<ProvenanceEntry>,
    #[serde(default)]
    pub(super) related_projects: Vec<RelatedProject>,
    /// SPDX license identifier(s) reported for this version (issue #204). Read
    /// directly from the same version-call response `slsa_provenances`/`attestations`
    /// come from — no new deps.dev endpoint.
    #[serde(default)]
    pub(super) licenses: Vec<String>,
}

/// One `slsaProvenances[]`/`attestations[]` entry.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProvenanceEntry {
    #[serde(default)]
    pub(super) verified: bool,
}

/// One `relatedProjects[]` entry.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RelatedProject {
    pub(super) project_key: ProjectKey,
    pub(super) relation_type: String,
    #[serde(default)]
    pub(super) relation_provenance: String,
}

/// The nested `projectKey` object carrying the project's id
/// (e.g. `github.com/expressjs/express`).
#[derive(Deserialize)]
pub(super) struct ProjectKey {
    pub(super) id: String,
}

/// Parsed subset of `GET /v3/projects/{project-key}`.
#[derive(Deserialize)]
pub(super) struct DepsDevProject {
    pub(super) scorecard: Option<DepsDevScorecardWire>,
}

/// The `scorecard` object's consumed field.
///
/// `overall_score` is `Option<f32>` with **no** `#[serde(default)]`: serde
/// already treats a missing or `null` key as `None` for an `Option` field,
/// but this must stay `Option`, never a defaulted `f32`, so an absent score
/// can never be conflated with a real `0.0` (a defaulted zero would itself be
/// a false trust claim — a project deps.dev has no Scorecard for would render
/// as maximally damning instead of simply omitted).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DepsDevScorecardWire {
    pub(super) overall_score: Option<f32>,
}

/// Parsed subset of `GET /v3alpha/systems/{system}/packages/{name}:similarlyNamedPackages`
/// (issue #1437, spec 071) — identity only, no popularity field (live-verified 2026-09-25;
/// see `deps_dev::typosquat`'s module doc for how popularity is resolved separately).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SimilarlyNamedPackagesWire {
    #[serde(default)]
    pub(super) packages: Vec<SimilarPackageWire>,
}

/// One `packages[]` entry of [`SimilarlyNamedPackagesWire`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SimilarPackageWire {
    pub(super) package_key: SimilarPackageKeyWire,
}

/// The candidate's own `packageKey.name` — a distinct wire shape from [`ProjectKey`], whose
/// `id` is a *project* key (e.g. `github.com/expressjs/express`), not a package name.
#[derive(Deserialize)]
pub(super) struct SimilarPackageKeyWire {
    pub(super) name: String,
}

/// Parsed subset of `GET /v3alpha/systems/{system}/packages/{name}` (issue #1437) — only
/// what is needed to find the package's default version.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GetPackageWire {
    #[serde(default)]
    pub(super) versions: Vec<PackageVersionWire>,
}

/// One `versions[]` entry of [`GetPackageWire`] — only the fields needed to find the
/// default version.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PackageVersionWire {
    pub(super) version_key: VersionKeyWire,
    #[serde(default)]
    pub(super) is_default: bool,
}

/// The `versionKey.version` string of one [`PackageVersionWire`] entry.
#[derive(Deserialize)]
pub(super) struct VersionKeyWire {
    pub(super) version: String,
}

/// Parsed subset of
/// `GET /v3alpha/systems/{system}/packages/{name}/versions/{version}:dependents` (issue
/// #1437) — the only popularity-shaped metric deps.dev v3alpha exposes for an arbitrary
/// package (plan.md §1).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DependentsWire {
    #[serde(default)]
    pub(super) dependent_count: u64,
}

/// One [`GossipFindingsWire`] entry's `packageKey` — identity only, mirrors
/// [`SimilarPackageKeyWire`]'s shape (a distinct wire struct since deps.dev's GOSSIP
/// endpoints use the same field name for a different purpose than the typosquat
/// endpoint's candidate identity).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipPackageKeyWire {
    pub(super) name: String,
}

/// The `GetFindings`/`GetFindingsBatch` findings payload for one package or version (issue
/// #1456, spec 072) — declares only the two fields this feature actually reads.
///
/// `defaultVersion` is the only reliable field for "is the package's latest version in
/// cooldown" (spec 072 §5): `recommendedVersions[]`, deps.dev's list of low-risk version
/// suggestions, is frequently EMPTY while the default version is itself in cooldown, and is
/// therefore never read here.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipFindingsWire {
    // No `packageKey`/`versionKey` identity field: the package-scoped response (used
    // inside a batch entry) carries `packageKey`, the version-scoped `GetFindings`
    // response carries `versionKey` instead — neither is read (the batch entry's own
    // `request.packageKey.name`, from `GossipBatchRequestEchoWire`, is what identifies a
    // batch result), so this struct only declares the fields both shapes share.
    #[serde(default)]
    pub(super) default_version: Option<GossipVersionFindingsWire>,
    #[serde(default)]
    pub(super) requested_version: Option<GossipVersionFindingsWire>,
}

/// Top-level `POST /v3alpha/findingsbatch` request body (issue #1456, spec 072 §5) — a
/// typed request struct, not an ad hoc `serde_json::Value` mutated per page: avoids
/// `clippy::indexing_slicing` on a `Value`-indexing assignment for `pageToken`, and gives
/// the request shape the same type-safety guarantee every other wire type in this module
/// has.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipFindingsBatchRequestWire<'a> {
    pub(super) requests: &'a [GossipBatchRequestWire<'a>],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) page_token: Option<&'a str>,
}

/// One `requests[]` entry of [`GossipFindingsBatchRequestWire`] — package-scoped only (see
/// [`super::DepsDevClient::gossip_findings_batch`]'s doc for why).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipBatchRequestWire<'a> {
    pub(super) package_key: GossipPackageKeyRefWire<'a>,
}

/// A borrowed `packageKey` for one outbound [`GossipBatchRequestWire`] — `system` is
/// deps.dev's uppercase system name (`"NPM"`, not `"npm"`; live-verified 2026-09-26: the
/// batch endpoint's JSON body rejects a lowercase value with 400, unlike the path-segment
/// `system` every other deps.dev call in this module uses).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipPackageKeyRefWire<'a> {
    pub(super) system: &'a str,
    pub(super) name: &'a str,
}

/// Top-level `POST /v3alpha/findingsbatch` response (issue #1456, spec 072 §5),
/// live-verified 2026-09-26 against `npm/vite` + `npm/left-pad`:
/// `{"responses": [{"request": {"packageKey": {...}}, "findings": {...}}],
/// "nextPageToken": ""}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipFindingsBatchWire {
    #[serde(default)]
    pub(super) responses: Vec<GossipBatchResponseEntryWire>,
    /// Empty string (not absent) when there is no further page, live-verified above.
    #[serde(default)]
    pub(super) next_page_token: String,
}

/// One `responses[]` entry of [`GossipFindingsBatchWire`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipBatchResponseEntryWire {
    /// The uncanonicalized request this entry answers — read instead of assuming
    /// response order matches request order, since deps.dev's own docs only guarantee
    /// this field echoes the request, not that ordering is preserved.
    pub(super) request: GossipBatchRequestEchoWire,
    pub(super) findings: GossipFindingsWire,
}

/// The `responses[].request` echo of one [`GossipBatchResponseEntryWire`] — package-scoped
/// only, since [`super::DepsDevClient::gossip_findings_batch`] only ever sends
/// `packageKey`-shaped requests (never `versionKey`-scoped ones, which are reserved for the
/// version-scoped `GetFindings` call `gossip_findings_for_version` uses instead).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipBatchRequestEchoWire {
    pub(super) package_key: GossipPackageKeyWire,
}

/// One `GetFindingsBatch`/`GetFindings` response's `defaultVersion`/`requestedVersion`
/// object.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipVersionFindingsWire {
    pub(super) version_key: GossipVersionKeyWire,
    #[serde(default)]
    pub(super) findings: Vec<GossipFindingWire>,
    /// Historical, always-present sibling of `findings[]`'s `COOLDOWN` entry — live-verified
    /// 2026-09-26 (issue #1456 security/impl-critic review, S2): present even when no
    /// `COOLDOWN` finding exists (e.g. `django` 6.1.1, past `cooldownEnd`, empty
    /// `findings[]`). Used as a fallback end-date source in [`super::gossip_findings_from_entry`]
    /// so a version-matched response with no `COOLDOWN` finding can still be told apart from
    /// "no GOSSIP data at all" — see that function's doc for why this closes FR-002's
    /// "authoritative when available" gap.
    #[serde(default)]
    pub(super) cooldown_end: Option<String>,
}

/// The `versionKey.version` string of a [`GossipVersionFindingsWire`] entry.
#[derive(Debug, Deserialize)]
pub(super) struct GossipVersionKeyWire {
    pub(super) version: String,
}

/// One `findings[]` entry (issue #1456, spec 072 §5). Live-verified shape for an active
/// cooldown (`vite`, npm, 2026-09-26): `{"type": "COOLDOWN", "risk": "RISK_HIGH",
/// "cooldownContext": {"end": "<RFC3339>"}}`.
///
/// `low_usage_context` is typed from `docs.deps.dev/api/v3alpha`'s own published field
/// documentation (`lowUsageContext.alternativePackages[]`), not from a live-observed
/// example — no live `LOW_USAGE` finding was captured across ~20 combined probes (spec
/// 072 FR-001) — but the field is deps.dev's own documented schema, not a guess.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipFindingWire {
    #[serde(rename = "type")]
    pub(super) finding_type: GossipFindingType,
    #[serde(default)]
    pub(super) risk: GossipRiskWire,
    #[serde(default)]
    pub(super) cooldown_context: Option<GossipCooldownContextWire>,
    #[serde(default)]
    pub(super) low_usage_context: Option<GossipLowUsageContextWire>,
}

/// The `cooldownContext` object of a [`GossipFindingWire`] whose `finding_type` is
/// [`GossipFindingType::Cooldown`].
#[derive(Debug, Deserialize)]
pub(super) struct GossipCooldownContextWire {
    pub(super) end: String,
}

/// The `lowUsageContext` object of a [`GossipFindingWire`] whose `finding_type` is
/// [`GossipFindingType::LowUsage`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GossipLowUsageContextWire {
    #[serde(default)]
    pub(super) alternative_packages: Vec<String>,
}

/// `findings[].type` (spec 072 §5) — only `Cooldown`/`LowUsage` are ever surfaced;
/// every other value (`NOT_FOUND`, `MALICIOUS`, `DEPRECATED`, `VULNERABLE`,
/// `REMEDIATION`) collapses into [`Self::Other`] and is never rendered as a diagnostic
/// (NFR-002: `NOT_FOUND` in particular is ambiguous between "malicious/removed" and
/// "too new to be indexed yet").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum GossipFindingType {
    Cooldown,
    LowUsage,
    #[serde(other)]
    Other,
}

/// `findings[].risk` (spec 072 §5). Defaults to [`Self::Informational`] on a missing or
/// unrecognized value — a risk level is advisory context on top of `finding_type`, never
/// the sole gate on whether a finding is surfaced at all, so an unrecognized value must
/// not itself discard an otherwise-valid `Cooldown`/`LowUsage` finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub(super) enum GossipRiskWire {
    #[serde(rename = "RISK_CRITICAL")]
    Critical,
    #[serde(rename = "RISK_HIGH")]
    High,
    #[serde(rename = "RISK_MEDIUM")]
    Medium,
    #[serde(rename = "RISK_LOW")]
    Low,
    #[serde(other)]
    #[default]
    Informational,
}

/// The three-state SLSA/attestation provenance verdict for one resolved version (FR-004).
///
/// [`Self::Verified`] and [`Self::Unverified`] are both only reachable when the
/// version-level query itself succeeded, so a caller can distinguish "we checked and
/// found nothing" from "we didn't check" via `Option<ProvenanceStatus>` at the
/// [`SupplyChainTrustSignal`] level.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceStatus {
    /// At least one `slsaProvenances[]`/`attestations[]` entry has `verified == true`.
    Verified,
    /// Both arrays are non-empty, but no entry has `verified == true`.
    Unverified,
    /// Both arrays are empty.
    None,
}

/// The hover-facing OpenSSF Scorecard summary for a package's linked source
/// repository.
///
/// Output-only: constructed internally by [`crate::deps_dev`]'s own deps.dev response
/// parsing, never by external code — no constructor is provided.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct ScorecardSummary {
    /// deps.dev's `scorecard.overallScore`, already validated to be a finite
    /// value in `0.0..=10.0` — never a defaulted zero.
    pub overall_score: f32,
    /// `true` when the `SOURCE_REPO` relation this score was fetched for was
    /// only `UNVERIFIED_METADATA` (package-self-reported), not
    /// `SLSA_ATTESTATION` — see [`crate::deps_dev`] module docs for why this
    /// matters and how it is rendered.
    pub self_reported: bool,
}

/// The ecosystem-agnostic aggregate assembled from deps.dev's two calls,
/// consumed by the hover-formatting layer.
///
/// Every field being `None` means "nothing to render". `trust_signal`'s
/// success path never actually produces that all-`None` shape today
/// (`provenance` is always `Some` once the version call itself succeeds),
/// so `push_trust_signal_hover_section`'s own `scorecard.is_none() &&
/// provenance.is_none()` check is defensive, not dead. Modelling both
/// fields as independently `Option` still matters: see
/// [`ProvenanceStatus`]'s docs for why `provenance` in particular stays
/// `Option` rather than collapsing into `scorecard`'s shape.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SupplyChainTrustSignal {
    /// The linked source repository's OpenSSF Scorecard, when one could be
    /// resolved and fetched (FR-002/FR-003/FR-005).
    pub scorecard: Option<ScorecardSummary>,
    /// This version's SLSA/attestation provenance status, when the
    /// version-level query itself succeeded (FR-004).
    pub provenance: Option<ProvenanceStatus>,
    /// SPDX license identifier(s) for this resolved version (issue #204), from the
    /// same version-level deps.dev call `provenance` is derived from. Empty when the
    /// version call succeeded but reported no license, or when the call itself never
    /// succeeded (mirrors [`crate::registry::Version::license`]'s "empty means
    /// unknown" convention).
    pub licenses: Vec<String>,
}

/// `findings[].risk` (issue #1456, spec 072 §5), consumer-facing counterpart of
/// `GossipRiskWire`.
///
/// # Examples
///
/// ```
/// use deps_core::deps_dev::GossipRiskLevel;
///
/// assert_eq!(GossipRiskLevel::default(), GossipRiskLevel::Informational);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GossipRiskLevel {
    /// `RISK_CRITICAL`.
    Critical,
    /// `RISK_HIGH`.
    High,
    /// `RISK_MEDIUM`.
    Medium,
    /// `RISK_LOW`.
    Low,
    /// `RISK_INFORMATIONAL`, or an unrecognized/missing value.
    #[default]
    Informational,
}

impl From<GossipRiskWire> for GossipRiskLevel {
    fn from(wire: GossipRiskWire) -> Self {
        match wire {
            GossipRiskWire::Critical => Self::Critical,
            GossipRiskWire::High => Self::High,
            GossipRiskWire::Medium => Self::Medium,
            GossipRiskWire::Low => Self::Low,
            GossipRiskWire::Informational => Self::Informational,
        }
    }
}

/// A GOSSIP `COOLDOWN` finding for one package version (issue #1456, spec 072).
///
/// `end` is compared against `now()` at every read (`end > now()` means still active) —
/// **never** precompute or store an "is active" boolean (spec 072 FR-011): this makes an
/// ended cooldown self-clear with zero refetch cost, and is the single rule every reader
/// (hover, diagnostics) applies via [`Self::is_active`].
///
/// # Examples
///
/// ```
/// use deps_core::PublishTime;
/// use deps_core::deps_dev::{GossipCooldown, GossipRiskLevel};
///
/// let cooldown = GossipCooldown::new(PublishTime::from_unix_secs(2_000), GossipRiskLevel::High);
/// assert!(cooldown.is_active(PublishTime::from_unix_secs(1_000)));
/// assert!(!cooldown.is_active(PublishTime::from_unix_secs(3_000)));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipCooldown {
    /// The instant this version's cooldown window ends, per deps.dev's
    /// `cooldownContext.end`.
    pub end: crate::freshness::PublishTime,
    /// The finding's reported risk level.
    pub risk: GossipRiskLevel,
}

impl GossipCooldown {
    /// Constructs a `GossipCooldown`.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PublishTime;
    /// use deps_core::deps_dev::{GossipCooldown, GossipRiskLevel};
    ///
    /// let cooldown = GossipCooldown::new(PublishTime::from_unix_secs(2_000), GossipRiskLevel::High);
    /// assert_eq!(cooldown.end, PublishTime::from_unix_secs(2_000));
    /// ```
    #[must_use]
    pub const fn new(end: crate::freshness::PublishTime, risk: GossipRiskLevel) -> Self {
        Self { end, risk }
    }

    /// Whether this cooldown is still active as of `now` — `self.end > now`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PublishTime;
    /// use deps_core::deps_dev::{GossipCooldown, GossipRiskLevel};
    ///
    /// let cooldown = GossipCooldown::new(PublishTime::from_unix_secs(2_000), GossipRiskLevel::High);
    /// assert!(cooldown.is_active(PublishTime::from_unix_secs(1_999)));
    /// assert!(!cooldown.is_active(PublishTime::from_unix_secs(2_000)));
    /// ```
    #[must_use]
    pub fn is_active(&self, now: crate::freshness::PublishTime) -> bool {
        self.end > now
    }
}

/// A GOSSIP `LOW_USAGE` finding for one package version (issue #1456, spec 072) —
/// slopsquatting-risk signal, surfaced as-is (no corroborating-signal gate, spec 072 §9).
///
/// `alternative_packages` is typed from `docs.deps.dev/api/v3alpha`'s own published
/// `lowUsageContext.alternativePackages[]` field documentation — no live `LOW_USAGE`
/// finding was captured across ~20 combined probes (spec 072 FR-001), but the shape comes
/// from deps.dev's own schema reference, not a guess (avoids an untyped
/// `serde_json::Value` placeholder, this project's type-safety rule).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct GossipLowUsage {
    /// The finding's reported risk level.
    pub risk: GossipRiskLevel,
    /// Packages with similar names that have higher usage, per deps.dev's own
    /// documentation. Empty when deps.dev reported none.
    pub alternative_packages: Vec<String>,
}

/// GOSSIP-sourced findings for one package version (issue #1456, spec 072), stored in
/// `deps-lsp`'s `DocumentState.gossip_findings` and read from
/// [`crate::lsp_helpers::VersionData::gossip_prefetch`].
///
/// [`Self::version`] is the exact version this data applies to — every reader compares it
/// against the version actually being displayed (spec 072 FR-008) before trusting
/// [`Self::cooldown`]/[`Self::low_usage`]; a mismatch is treated as a cache miss, never a
/// stale-but-close-enough answer.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct GossipFindings {
    /// The exact version [`Self::cooldown`]/[`Self::low_usage`] were computed for.
    pub version: String,
    /// This version's active-or-expired cooldown window, if GOSSIP reported one.
    pub cooldown: Option<GossipCooldown>,
    /// This version's low-usage/slopsquatting-risk finding, if GOSSIP reported one.
    pub low_usage: Option<GossipLowUsage>,
}
