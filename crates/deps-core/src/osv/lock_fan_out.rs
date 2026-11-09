//! Fan-out of a [`ScanTarget`] over its lock-file alternatives (#1981).
//!
//! A lock file can hold several entries that satisfy one dependency's requirement, and it
//! cannot say which one the package manager installed. [`expand`] turns each alternative into an
//! internal sub-target under a synthetic key, and [`merge`] folds the sub-outcomes back into one
//! outcome per real key, so no synthetic key ever reaches a caller.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::types::{
    Advisory, AlternativeCoverage, Capped, DependencyVulnerabilities, MatchOrigin, MatchedTags,
    OsvId, OsvVersion, ScanOutcome, ScanTarget, SiblingMatches, SkipReason, VulnKey,
    VulnerabilityMap,
};
use super::{LockPresence, MAX_ADVISORY_RECORDS, MAX_LOCK_ALTERNATIVES};
use crate::ConcreteVersion;

/// The sub-targets one real target fanned out into.
pub(super) struct Fan {
    key: VulnKey,
    version: OsvVersion,
    alternatives: Vec<(VulnKey, ConcreteVersion)>,
    coverage: AlternativeCoverage,
}

/// Returns `targets` followed by one sub-target per scanned lock alternative, plus the
/// bookkeeping [`merge`] needs. Only the first target per key fans out, as duplicate keys share
/// one result.
pub(super) fn expand(targets: &[ScanTarget]) -> (Vec<ScanTarget>, Vec<Fan>) {
    let mut expanded = targets.to_vec();
    let mut fans = Vec::new();
    let mut seen: HashSet<&VulnKey> = HashSet::with_capacity(targets.len());
    for target in targets {
        if target.lock_alternatives().is_empty() || !seen.insert(&target.key) {
            continue;
        }
        let scanned = target
            .lock_alternatives()
            .iter()
            .take(MAX_LOCK_ALTERNATIVES)
            .enumerate();
        let mut alternatives = Vec::new();
        for (index, alternative) in scanned {
            let key = target.key.lock_alternative(index);
            expanded.push(ScanTarget::new(
                key.clone(),
                target.osv_name.clone(),
                alternative.version().clone(),
                alternative.display_version().clone(),
            ));
            alternatives.push((key, alternative.display_version().clone()));
        }
        fans.push(Fan {
            key: target.key.clone(),
            version: target.version.clone(),
            alternatives,
            coverage: target.alternative_coverage(),
        });
    }
    (expanded, fans)
}

/// Replaces each fanned-out key's outcome in `outcomes` with the merge of its sub-outcomes and
/// drops every synthetic key.
pub(super) fn merge(outcomes: &mut VulnerabilityMap, fans: Vec<Fan>) {
    for fan in fans {
        let alternatives = fan
            .alternatives
            .into_iter()
            .map(|(key, version)| {
                let outcome = outcomes
                    .remove(&key)
                    .unwrap_or(ScanOutcome::Skipped(SkipReason::QueryFailed));
                (version, outcome)
            })
            .collect();
        let primary = outcomes
            .remove(&fan.key)
            .unwrap_or(ScanOutcome::Skipped(SkipReason::QueryFailed));
        outcomes.insert(
            fan.key,
            merge_outcomes(primary, &fan.version, alternatives, fan.coverage),
        );
    }
}

/// Merges the primary's outcome with its alternatives' (lowest version first).
///
/// In order:
/// 1. Any `Vulnerable` sub-outcome wins: the result is the deduplicated union of advisories,
///    and an advisory only an alternative matched carries [`MatchOrigin::LockEntry`] tags. The
///    list is marked incomplete when any other sub-outcome was skipped or alternatives
///    were truncated.
/// 2. Otherwise a skipped primary keeps its own reason.
/// 3. Otherwise the first skipped alternative's reason stands when it is a coverage gap, else
///    [`SkipReason::LockAlternativesUnchecked`], so a structural reason cannot make the
///    dependency vanish from both "clean" and "unchecked".
/// 4. Otherwise overflow alone is [`SkipReason::LockAlternativesUnchecked`]; it only ever turns
///    a clean answer into a skip.
fn merge_outcomes(
    primary: ScanOutcome,
    primary_version: &OsvVersion,
    alternatives: Vec<(ConcreteVersion, ScanOutcome)>,
    coverage: AlternativeCoverage,
) -> ScanOutcome {
    let overflowed = coverage == AlternativeCoverage::Truncated;
    let mut primary_vulnerable = None;
    let mut primary_skip = None;
    match primary {
        ScanOutcome::Clean => {}
        ScanOutcome::Vulnerable(dv) => primary_vulnerable = Some(dv),
        ScanOutcome::Skipped(reason) => primary_skip = Some(reason),
    }
    let mut vulnerable_alternatives = Vec::new();
    let mut first_alternative_skip = None;
    for (version, outcome) in alternatives {
        match outcome {
            ScanOutcome::Clean => {}
            ScanOutcome::Vulnerable(dv) => vulnerable_alternatives.push((version, dv)),
            ScanOutcome::Skipped(reason) => {
                first_alternative_skip.get_or_insert(reason);
            }
        }
    }

    if primary_vulnerable.is_none() && vulnerable_alternatives.is_empty() {
        return match (primary_skip, first_alternative_skip, overflowed) {
            (Some(reason), _, _) => ScanOutcome::Skipped(reason),
            (None, Some(reason), _) => ScanOutcome::Skipped(
                reason
                    .coverage_gap(LockPresence::Found)
                    .map_or(SkipReason::LockAlternativesUnchecked, |_| reason),
            ),
            (None, None, true) => ScanOutcome::Skipped(SkipReason::LockAlternativesUnchecked),
            (None, None, false) => ScanOutcome::Clean,
        };
    }

    let incomplete = primary_skip.is_some() || first_alternative_skip.is_some() || overflowed;
    ScanOutcome::Vulnerable(union_advisories(
        primary_vulnerable.as_ref(),
        &vulnerable_alternatives,
        primary_version,
        incomplete,
    ))
}

fn union_advisories(
    primary: Option<&DependencyVulnerabilities>,
    alternatives: &[(ConcreteVersion, DependencyVulnerabilities)],
    primary_version: &OsvVersion,
    incomplete: bool,
) -> DependencyVulnerabilities {
    let primary_ids: HashSet<&OsvId> = primary
        .into_iter()
        .flat_map(|dv| dv.advisories.items())
        .map(|advisory| advisory.id())
        .collect();
    let mut advisories: Vec<Arc<Advisory>> = Vec::new();
    let mut seen: HashSet<OsvId> = HashSet::new();
    let mut alternative_only: HashMap<OsvId, Vec<ConcreteVersion>> = HashMap::new();
    let mut unfetched = 0usize;

    if let Some(dv) = primary {
        unfetched += dv.advisories.remaining();
        for advisory in dv.advisories.items() {
            if seen.insert(advisory.id().clone()) {
                advisories.push(Arc::clone(advisory));
            }
        }
    }
    for (version, dv) in alternatives {
        unfetched += dv.advisories.remaining();
        for advisory in dv.advisories.items() {
            if !primary_ids.contains(advisory.id()) {
                alternative_only
                    .entry(advisory.id().clone())
                    .or_default()
                    .push(version.clone());
            }
            if seen.insert(advisory.id().clone()) {
                advisories.push(Arc::clone(advisory));
            }
        }
    }

    let total = advisories.len() + unfetched;
    advisories.truncate(MAX_ADVISORY_RECORDS);

    let mut matches = SiblingMatches::new(primary_version.clone());
    for advisory in &advisories {
        if let Some(versions) = alternative_only.remove(advisory.id())
            && let Some(tags) = MatchedTags::from_versions(MatchOrigin::LockEntry, versions)
        {
            matches.insert(advisory.id().clone(), tags);
        }
    }
    let counted = Capped::new(advisories, total);
    let counted = if incomplete {
        counted.with_total_as_lower_bound()
    } else {
        counted
    };
    let merged = DependencyVulnerabilities::new(counted);
    if matches.is_empty() {
        merged
    } else {
        merged.with_sibling_matches(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::{OsvPackageName, OsvQueryName, VulnSeverity};
    use std::assert_matches;

    fn vulnerable(ids: &[&str]) -> ScanOutcome {
        let advisories: Vec<Arc<Advisory>> = ids
            .iter()
            .map(|id| {
                Arc::new(
                    Advisory::new(
                        (*id).to_string(),
                        "2023-01-01T00:00:00Z".into(),
                        VulnSeverity::High,
                    )
                    .unwrap(),
                )
            })
            .collect();
        let total = advisories.len();
        ScanOutcome::Vulnerable(DependencyVulnerabilities::new(Capped::new(
            advisories, total,
        )))
    }

    fn merged(
        primary: ScanOutcome,
        alternatives: Vec<(&str, ScanOutcome)>,
        overflowed: bool,
    ) -> ScanOutcome {
        let alternatives = alternatives
            .into_iter()
            .map(|(v, outcome)| (ConcreteVersion::new(v), outcome))
            .collect();
        merge_outcomes(
            primary,
            &OsvVersion::new("1.2.8"),
            alternatives,
            if overflowed {
                AlternativeCoverage::Truncated
            } else {
                AlternativeCoverage::Complete
            },
        )
    }

    fn dv(outcome: &ScanOutcome) -> &DependencyVulnerabilities {
        match outcome {
            ScanOutcome::Vulnerable(dv) => dv,
            other => panic!("expected Vulnerable, got {other:?}"),
        }
    }

    fn skip(outcome: &ScanOutcome) -> SkipReason {
        match outcome {
            ScanOutcome::Skipped(reason) => *reason,
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    fn ids(outcome: &ScanOutcome) -> Vec<&str> {
        dv(outcome)
            .advisories
            .items()
            .iter()
            .map(|a| a.id().as_str())
            .collect()
    }

    fn names(tags: &MatchedTags) -> Vec<&str> {
        tags.iter().map(ConcreteVersion::as_str).collect()
    }

    #[test]
    fn clean_everywhere_is_clean() {
        let outcome = merged(
            ScanOutcome::Clean,
            vec![("1.2.5", ScanOutcome::Clean)],
            false,
        );
        assert_matches!(outcome, ScanOutcome::Clean);
    }

    #[test]
    fn advisory_only_an_alternative_matched_carries_lock_entry_tags() {
        let outcome = merged(
            ScanOutcome::Clean,
            vec![("1.2.5", vulnerable(&["GHSA-aaaa-bbbb-cccc"]))],
            false,
        );

        let id = crate::test_util::osv_id("GHSA-aaaa-bbbb-cccc");
        let tags = dv(&outcome)
            .sibling_match(&id)
            .expect("alternative-only match");
        assert_eq!(tags.origin(), MatchOrigin::LockEntry);
        assert_eq!(names(tags), ["1.2.5"]);
        assert!(dv(&outcome).advisories.is_complete());
        assert_eq!(
            dv(&outcome).sibling_only_tags().map(|t| t.origin()),
            Some(MatchOrigin::LockEntry)
        );
    }

    #[test]
    fn advisory_matching_primary_and_alternative_is_deduplicated_without_a_lock_entry_note() {
        let outcome = merged(
            vulnerable(&["GHSA-aaaa-bbbb-cccc"]),
            vec![
                (
                    "1.2.5",
                    vulnerable(&["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]),
                ),
                ("1.2.6", vulnerable(&["GHSA-dddd-eeee-ffff"])),
            ],
            false,
        );

        assert_eq!(
            ids(&outcome),
            ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]
        );
        let shared = crate::test_util::osv_id("GHSA-aaaa-bbbb-cccc");
        assert!(dv(&outcome).sibling_match(&shared).is_none());
        let only = crate::test_util::osv_id("GHSA-dddd-eeee-ffff");
        let tags = dv(&outcome).sibling_match(&only).unwrap();
        assert_eq!(names(tags), ["1.2.5", "1.2.6"]);
    }

    #[test]
    fn vulnerable_primary_with_a_failed_alternative_stays_vulnerable_but_incomplete() {
        let outcome = merged(
            vulnerable(&["GHSA-aaaa-bbbb-cccc"]),
            vec![("1.2.5", ScanOutcome::Skipped(SkipReason::QueryFailed))],
            false,
        );

        assert_eq!(ids(&outcome), ["GHSA-aaaa-bbbb-cccc"]);
        assert!(!dv(&outcome).advisories.is_complete());
    }

    #[test]
    fn failed_alternative_keeps_the_known_total_and_reports_a_lower_bound() {
        let outcome = merged(
            vulnerable(&["GHSA-aaaa-bbbb-cccc"]),
            vec![("1.2.5", ScanOutcome::Skipped(SkipReason::QueryFailed))],
            false,
        );

        let advisories = &dv(&outcome).advisories;
        assert_eq!(advisories.total(), 1);
        assert_eq!(
            advisories.overflow(),
            Some(crate::osv::AdvisoryCount::AtLeast(0))
        );
    }

    #[test]
    fn fully_scanned_alternatives_report_an_exact_count() {
        let outcome = merged(vulnerable(&["GHSA-aaaa-bbbb-cccc"]), vec![], false);
        assert_eq!(dv(&outcome).advisories.overflow(), None);
    }

    #[test]
    fn clean_primary_with_a_failed_alternative_is_query_failed() {
        let outcome = merged(
            ScanOutcome::Clean,
            vec![("1.2.5", ScanOutcome::Skipped(SkipReason::QueryFailed))],
            false,
        );
        assert_eq!(skip(&outcome), SkipReason::QueryFailed);
    }

    #[test]
    fn clean_primary_with_a_structurally_skipped_alternative_is_lock_alternatives_unchecked() {
        let outcome = merged(
            ScanOutcome::Clean,
            vec![(
                "1.2.5",
                ScanOutcome::Skipped(SkipReason::UnmatchableVersion),
            )],
            false,
        );
        assert_eq!(skip(&outcome), SkipReason::LockAlternativesUnchecked);
    }

    #[test]
    fn skipped_primary_keeps_its_own_reason() {
        let outcome = merged(
            ScanOutcome::Skipped(SkipReason::Truncated),
            vec![("1.2.5", ScanOutcome::Skipped(SkipReason::QueryFailed))],
            false,
        );
        assert_eq!(skip(&outcome), SkipReason::Truncated);
    }

    #[test]
    fn first_skipped_alternative_in_version_order_decides() {
        let outcome = merged(
            ScanOutcome::Clean,
            vec![
                ("1.2.3", ScanOutcome::Skipped(SkipReason::Truncated)),
                ("1.2.5", ScanOutcome::Skipped(SkipReason::QueryFailed)),
            ],
            false,
        );
        assert_eq!(skip(&outcome), SkipReason::Truncated);
    }

    #[test]
    fn overflow_turns_clean_into_unchecked() {
        let outcome = merged(
            ScanOutcome::Clean,
            vec![("1.2.5", ScanOutcome::Clean)],
            true,
        );
        assert_eq!(skip(&outcome), SkipReason::LockAlternativesUnchecked);
    }

    #[test]
    fn overflow_never_overrides_vulnerable() {
        let outcome = merged(
            ScanOutcome::Clean,
            vec![("1.2.5", vulnerable(&["GHSA-aaaa-bbbb-cccc"]))],
            true,
        );
        assert_eq!(ids(&outcome), ["GHSA-aaaa-bbbb-cccc"]);
        assert!(!dv(&outcome).advisories.is_complete());
    }

    fn target_with_alternatives(count: usize, coverage: AlternativeCoverage) -> ScanTarget {
        let versions: Vec<ConcreteVersion> = (0..count)
            .map(|n| ConcreteVersion::new(format!("1.0.{n}")))
            .collect();
        let in_use = crate::lsp_helpers::InUseVersions::for_test_with_alternative_coverage(
            ConcreteVersion::new("2.0.0"),
            versions,
            coverage,
        );
        ScanTarget::from_native(
            crate::test_util::vuln_key("pkg"),
            OsvQueryName::Confirmed(OsvPackageName::new("pkg").unwrap()),
            ConcreteVersion::new("2.0.0"),
            &crate::test_util::StubFormatter::DEFAULT,
        )
        .with_lock_alternatives(&in_use, &crate::test_util::StubFormatter::DEFAULT)
    }

    #[test]
    fn expand_scans_every_listed_alternative_and_truncation_turns_clean_into_unchecked() {
        let target =
            target_with_alternatives(MAX_LOCK_ALTERNATIVES, AlternativeCoverage::Truncated);
        let (expanded, fans) = expand(std::slice::from_ref(&target));

        assert_eq!(expanded.len(), 1 + MAX_LOCK_ALTERNATIVES);
        assert_eq!(fans.len(), 1);
        let distinct: HashSet<&VulnKey> = expanded.iter().map(|t| &t.key).collect();
        assert_eq!(distinct.len(), expanded.len());

        let mut outcomes: VulnerabilityMap = expanded
            .iter()
            .map(|t| (t.key.clone(), ScanOutcome::Clean))
            .collect();
        merge(&mut outcomes, fans);

        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            skip(&outcomes[&target.key]),
            SkipReason::LockAlternativesUnchecked
        );
    }

    #[test]
    fn expand_fans_out_only_the_first_target_of_a_duplicate_key() {
        let target = target_with_alternatives(2, AlternativeCoverage::Complete);
        let (expanded, fans) = expand(&[target.clone(), target]);

        assert_eq!(expanded.len(), 2 + 2);
        assert_eq!(fans.len(), 1);
    }
}
