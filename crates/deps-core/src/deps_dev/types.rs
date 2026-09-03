//! Wire types for deps.dev API v3 responses, plus the public,
//! ecosystem-agnostic types the hover-formatting layer consumes.
//!
//! Wire types declare only the fields this spec actually reads — serde
//! ignores unknown fields by default, so deps.dev's much larger response
//! shape (`licenses`, `isDeprecated`, `advisoryKeys`, `checks[]`,
//! `scorecard.version`, ...) never needs a struct field here (spec §5,
//! Out of Scope).

use serde::Deserialize;

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

/// The three-state SLSA/attestation provenance verdict for one resolved version (FR-004).
///
/// [`Self::Verified`] and [`Self::Unverified`] are both only reachable when the
/// version-level query itself succeeded, so a caller can distinguish "we checked and
/// found nothing" from "we didn't check" via `Option<ProvenanceStatus>` at the
/// [`SupplyChainTrustSignal`] level.
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
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SupplyChainTrustSignal {
    /// The linked source repository's OpenSSF Scorecard, when one could be
    /// resolved and fetched (FR-002/FR-003/FR-005).
    pub scorecard: Option<ScorecardSummary>,
    /// This version's SLSA/attestation provenance status, when the
    /// version-level query itself succeeded (FR-004).
    pub provenance: Option<ProvenanceStatus>,
}
