//! The background-probe sequence shared by `deps-cli` and `deps-lsp`.
//!
//! Probes gather evidence that synchronous, network-free diagnostics cannot (see
//! [`deps_core::ParsedManifest::background_probes`]). The CLI runs them in a fixed order so its
//! findings equal the server's for the same registry answers:
//!
//! 1. parse the manifest;
//! 2. [`ProbePhase::PreFetch`] probes ([`pre_fetch_decision`], or [`parse_with_pre_fetch_probes`]
//!    for callers that only want the parse), which may ask for one re-parse;
//! 3. the registry fetch;
//! 4. [`ProbePhase::PostFetch`] probes ([`run_background_probes`]);
//! 5. classify.
//!
//! Which probe runs first inside a pass (lineage, then membership, then branch) and the
//! concurrency bound live in [`deps_core::lsp_helpers::run_probe_pass`], shared by the
//! ecosystems that probe.

use std::sync::Arc;

use deps_core::lsp_helpers::{ProbeEffect, ProbePhase, ProbeReport};
use deps_core::{Ecosystem, NetworkMode, ParsedManifest};
use url::Url;

/// Runs the probes of the ecosystem that parsed `document` for `phase`.
///
/// Offline runs issue nothing: a probe is an optional request, never a reason to leave the
/// cache.
///
/// # Examples
///
/// ```no_run
/// # async fn run(
/// #     parsed: &dyn deps_core::ParsedManifest,
/// # ) {
/// use deps_core::NetworkMode;
/// use deps_core::lsp_helpers::ProbePhase;
/// use deps_engine::probe::run_background_probes;
///
/// let report = run_background_probes(parsed, ProbePhase::PostFetch, NetworkMode::Online).await;
/// println!("{} probes unanswered", report.unanswered());
/// # }
/// ```
pub async fn run_background_probes(
    document: &dyn ParsedManifest,
    phase: ProbePhase,
    network: NetworkMode,
) -> ProbeReport {
    if network.is_offline() {
        return ProbeReport::default();
    }
    document.background_probes(phase).await
}

/// What the [`ProbePhase::PreFetch`] probes decided about a parse result.
///
/// Callers that must commit or diff around the re-parse (the language server) match on this;
/// [`parse_with_pre_fetch_probes`] is the parse-and-return form built on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreFetchDecision {
    /// Offline: no probe ran, so there is no report and nothing was learned about the document.
    Skipped,
    /// The probes ran and the parse result stands.
    Keep(ProbeReport),
    /// The probes ran and changed an input the parse depends on: parse once more. That parse
    /// must run no probe, so the sequence cannot loop.
    Reparse(ProbeReport),
}

/// Runs the [`ProbePhase::PreFetch`] probes of the ecosystem that parsed `document` and reports
/// whether the caller must parse again.
///
/// # Examples
///
/// ```no_run
/// # async fn run(
/// #     parsed: &dyn deps_core::ParsedManifest,
/// # ) {
/// use deps_core::NetworkMode;
/// use deps_engine::probe::{PreFetchDecision, pre_fetch_decision};
///
/// match pre_fetch_decision(parsed, NetworkMode::Online).await {
///     PreFetchDecision::Reparse(_) => println!("parse again, without probing"),
///     PreFetchDecision::Keep(_) | PreFetchDecision::Skipped => {}
/// }
/// # }
/// ```
pub async fn pre_fetch_decision(
    document: &dyn ParsedManifest,
    network: NetworkMode,
) -> PreFetchDecision {
    if network.is_offline() {
        return PreFetchDecision::Skipped;
    }
    let report = document.background_probes(ProbePhase::PreFetch).await;
    match report.effect {
        ProbeEffect::Reparse => PreFetchDecision::Reparse(report),
        ProbeEffect::Unchanged | ProbeEffect::Republish => PreFetchDecision::Keep(report),
    }
}

/// Parses `content`, runs the [`ProbePhase::PreFetch`] probes, and re-parses once when a probe
/// returned [`ProbeEffect::Reparse`].
///
/// The re-parse runs no probe: a probe that changed the parse is applied exactly once, so the
/// sequence cannot loop. The returned report is the pre-fetch pass's (empty when offline).
///
/// # Errors
///
/// Returns the parse error of either parse.
pub async fn parse_with_pre_fetch_probes(
    ecosystem: &Arc<dyn Ecosystem>,
    content: &str,
    uri: &Url,
    network: NetworkMode,
) -> deps_core::error::Result<(Box<dyn ParsedManifest>, ProbeReport)> {
    let parsed = deps_core::parse_manifest_blocking(ecosystem, content, uri).await?;
    match pre_fetch_decision(parsed.as_ref(), network).await {
        PreFetchDecision::Skipped => Ok((parsed, ProbeReport::default())),
        PreFetchDecision::Keep(report) => Ok((parsed, report)),
        PreFetchDecision::Reparse(report) => {
            let reparsed = deps_core::parse_manifest_blocking(ecosystem, content, uri).await?;
            Ok((reparsed, report))
        }
    }
}

/// The probes a CLI run did not get an answer for, summed over every manifest.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::ProbeReport;
/// use deps_engine::probe::ProbeSummary;
///
/// let mut summary = ProbeSummary::default();
/// assert!(summary.unanswered_note().is_none());
/// summary.add(&ProbeReport { skipped_over_budget: 3, inconclusive: 1, ..ProbeReport::default() });
/// assert_eq!(
///     summary.unanswered_note().as_deref(),
///     Some("4 ref probes skipped (rate budget/inconclusive); set GITHUB_TOKEN/GITLAB_TOKEN in CI")
/// );
/// ```
///
/// Identity lookups are counted apart from ref probes:
///
/// ```
/// use deps_core::lsp_helpers::ProbeReport;
/// use deps_engine::probe::ProbeSummary;
///
/// let mut summary = ProbeSummary::default();
/// summary.add(&ProbeReport { incomplete_identity_lookups: 2, ..ProbeReport::default() });
/// assert_eq!(summary.incomplete_identity_lookups(), 2);
/// assert!(summary.unanswered_note().is_none());
/// assert_eq!(
///     summary.incomplete_identity_lookups_note().as_deref(),
///     Some("2 registry identity lookups incomplete; using source-control versions")
/// );
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeSummary {
    unanswered: usize,
    incomplete_identity_lookups: usize,
}

impl ProbeSummary {
    /// Adds one pass's unanswered probes.
    pub const fn add(&mut self, report: &ProbeReport) {
        self.unanswered += report.unanswered();
        self.incomplete_identity_lookups += report.incomplete_identity_lookups;
    }

    /// Registry identity lookups that got no answer so far (spec 088 FR-019).
    #[must_use]
    pub const fn incomplete_identity_lookups(&self) -> usize {
        self.incomplete_identity_lookups
    }

    /// The one stderr note a run prints when identity lookups were incomplete, `None` when all
    /// completed; those dependencies keep their source-control versions.
    ///
    /// Separate from [`Self::unanswered_note`] and, like it, never changes the exit code.
    #[must_use]
    pub fn incomplete_identity_lookups_note(&self) -> Option<String> {
        (self.incomplete_identity_lookups > 0).then(|| {
            format!(
                "{} registry identity lookups incomplete; using source-control versions",
                self.incomplete_identity_lookups
            )
        })
    }

    /// Probes that got no answer so far.
    #[must_use]
    pub const fn unanswered(&self) -> usize {
        self.unanswered
    }

    /// The one stderr note a run prints when probes went unanswered, `None` when all were.
    ///
    /// It never changes the exit code: with no evidence there is no finding.
    #[must_use]
    pub fn unanswered_note(&self) -> Option<String> {
        (self.unanswered > 0).then(|| {
            format!(
                "{} ref probes skipped (rate budget/inconclusive); set GITHUB_TOKEN/GITLAB_TOKEN in CI",
                self.unanswered
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{ProbeScript, TestTier3Ecosystem};

    fn uri() -> Url {
        deps_core::test_util::test_uri("/x/manifest")
    }

    fn scripted(pre_fetch: ProbeEffect) -> Arc<TestTier3Ecosystem> {
        Arc::new(
            TestTier3Ecosystem::returning(vec![]).with_probes(ProbeScript {
                pre_fetch,
                post_fetch: ProbeEffect::Republish,
            }),
        )
    }

    #[test]
    fn summary_adds_skipped_and_inconclusive_only() {
        let mut summary = ProbeSummary::default();
        summary.add(&ProbeReport {
            issued: 9,
            skipped_over_budget: 2,
            inconclusive: 1,
            incomplete_identity_lookups: 0,
            effect: ProbeEffect::Republish,
        });
        assert_eq!(summary.unanswered(), 3);
        assert!(
            summary
                .unanswered_note()
                .unwrap()
                .starts_with("3 ref probes skipped")
        );
    }

    #[tokio::test]
    async fn offline_issues_no_probe() {
        let eco = scripted(ProbeEffect::Unchanged);
        let dynamic: Arc<dyn Ecosystem> = eco.clone();
        let parsed = deps_core::parse_manifest_blocking(&dynamic, "", &uri())
            .await
            .unwrap();
        let report =
            run_background_probes(parsed.as_ref(), ProbePhase::PostFetch, NetworkMode::Offline)
                .await;
        assert_eq!(report, ProbeReport::default());
        assert!(eco.probe_calls().is_empty());
    }

    #[tokio::test]
    async fn pre_fetch_reparse_parses_exactly_twice_and_probes_once() {
        let eco = scripted(ProbeEffect::Reparse);
        let dynamic: Arc<dyn Ecosystem> = eco.clone();

        let (_, report) = parse_with_pre_fetch_probes(&dynamic, "", &uri(), NetworkMode::Online)
            .await
            .unwrap();

        assert_eq!(report.effect, ProbeEffect::Reparse);
        assert_eq!(eco.parse_count(), 2);
        assert_eq!(eco.probe_calls(), [ProbePhase::PreFetch]);
    }

    #[tokio::test]
    async fn pre_fetch_without_reparse_parses_once() {
        let eco = scripted(ProbeEffect::Republish);
        let dynamic: Arc<dyn Ecosystem> = eco.clone();

        parse_with_pre_fetch_probes(&dynamic, "", &uri(), NetworkMode::Online)
            .await
            .unwrap();

        assert_eq!(eco.parse_count(), 1);
    }

    #[tokio::test]
    async fn offline_parse_with_pre_fetch_probes_never_reparses() {
        let eco = scripted(ProbeEffect::Reparse);
        let dynamic: Arc<dyn Ecosystem> = eco.clone();

        parse_with_pre_fetch_probes(&dynamic, "", &uri(), NetworkMode::Offline)
            .await
            .unwrap();

        assert_eq!(eco.parse_count(), 1);
        assert!(eco.probe_calls().is_empty());
    }

    #[tokio::test]
    async fn decision_is_skipped_offline_and_never_probes() {
        let eco = scripted(ProbeEffect::Reparse);
        let dynamic: Arc<dyn Ecosystem> = eco.clone();
        let parsed = deps_core::parse_manifest_blocking(&dynamic, "", &uri())
            .await
            .unwrap();

        let decision = pre_fetch_decision(parsed.as_ref(), NetworkMode::Offline).await;

        assert_eq!(decision, PreFetchDecision::Skipped);
        assert!(eco.probe_calls().is_empty());
    }

    #[tokio::test]
    async fn decision_maps_each_effect() {
        for (effect, expect_reparse) in [
            (ProbeEffect::Reparse, true),
            (ProbeEffect::Republish, false),
            (ProbeEffect::Unchanged, false),
        ] {
            let eco = scripted(effect);
            let dynamic: Arc<dyn Ecosystem> = eco.clone();
            let parsed = deps_core::parse_manifest_blocking(&dynamic, "", &uri())
                .await
                .unwrap();

            let decision = pre_fetch_decision(parsed.as_ref(), NetworkMode::Online).await;

            assert_eq!(
                matches!(decision, PreFetchDecision::Reparse(_)),
                expect_reparse
            );
            assert_eq!(eco.probe_calls(), [ProbePhase::PreFetch]);
        }
    }

    #[tokio::test]
    async fn post_fetch_reports_the_ecosystems_effect() {
        let eco = scripted(ProbeEffect::Unchanged);
        let dynamic: Arc<dyn Ecosystem> = eco.clone();
        let parsed = deps_core::parse_manifest_blocking(&dynamic, "", &uri())
            .await
            .unwrap();

        let report =
            run_background_probes(parsed.as_ref(), ProbePhase::PostFetch, NetworkMode::Online)
                .await;

        assert_eq!(report.effect, ProbeEffect::Republish);
        assert_eq!(eco.probe_calls(), [ProbePhase::PostFetch]);
    }

    #[test]
    fn identity_lookups_are_summed_apart_from_ref_probes() {
        let mut summary = ProbeSummary::default();
        summary.add(&ProbeReport {
            incomplete_identity_lookups: 2,
            ..ProbeReport::default()
        });
        summary.add(&ProbeReport {
            incomplete_identity_lookups: 1,
            inconclusive: 4,
            ..ProbeReport::default()
        });

        assert_eq!(summary.incomplete_identity_lookups(), 3);
        assert_eq!(summary.unanswered(), 4);
        assert_eq!(
            summary.incomplete_identity_lookups_note().as_deref(),
            Some("3 registry identity lookups incomplete; using source-control versions")
        );
        assert!(
            ProbeSummary::default()
                .incomplete_identity_lookups_note()
                .is_none()
        );
    }
}
