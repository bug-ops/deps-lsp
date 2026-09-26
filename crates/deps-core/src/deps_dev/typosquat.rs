//! Pure typosquat ratio-gate logic (issue #1437, spec 071 / plan.md §1, §3).
//!
//! Deliberately free of any HTTP/caching concern, so [`evaluate_candidates`] is
//! unit-testable without `mockito` — [`super`] resolves the `dependent_count`s this module
//! compares from deps.dev's `GetSimilarlyNamedPackages`/`GetPackage`/`GetDependents` calls.

/// One `packages[]` entry from a `GetSimilarlyNamedPackages` response — identity only, no
/// popularity field (live-verified against the real v3alpha API, 2026-09-25; see plan.md
/// §1). [`super::DepsDevClient::similar_packages`] resolves and memoizes these; popularity
/// is a separate, per-candidate resolution ([`super::DepsDevClient::popularity`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SimilarPackageCandidate {
    pub(super) name: String,
}

/// Resolved, ratio-gated outcome for one declared dependency (spec §5).
///
/// Output-only: constructed internally by `evaluate_candidates`, never by external code.
///
/// Carries no `declared_name` field (issue #1455 batch item 2, removed after a #1437 review):
/// every caller already keys its `TyposquatSignal` by the declared package's `PackageName`
/// (`HashMap<PackageName, TyposquatSignal>` in `deps-lsp::DocumentState::signals.typosquats` and
/// `lsp_helpers::diagnostics::fetch_typosquat_signals`'s return type), and the sole diagnostic
/// renderer, `lsp_helpers::diagnostics::apply_typosquat_rule`, already builds its message from
/// the dependency it's iterating (`ctx.dep.name()`), never from this struct — a `declared_name`
/// field here would only ever duplicate its own map key with no reader.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct TyposquatSignal {
    /// The candidate deps.dev reports as similarly named and materially more popular.
    pub suspected_name: String,
    /// `GetDependents` `dependentCount` for the declared package's default version.
    pub declared_dependent_count: u64,
    /// `GetDependents` `dependentCount` for the suspected package's default version.
    pub suspected_dependent_count: u64,
}

/// Minimum popularity ratio (`candidate dependent_count / declared dependent_count`) that
/// promotes a similarity candidate to a typosquat suspect.
///
/// Empirically derived (plan.md §1): observed true positives ranged 300x-3000x
/// (`cross-env`/`crossenv`, `express`/`expres`, `lodash`/`loadash`, `request`/`requests`),
/// the closest known legitimate similarly-named pair found was ~6.9x
/// (`coffee-script`/`coffeescript`) — 50x sits with wide margin on both sides. Not
/// user-configurable (an internal tuning knob, like `DEPS_DEV_SUCCESS_TTL`); do not re-tune
/// without new empirical evidence (spec §8 "Ask First").
pub(super) const TYPOSQUAT_RATIO_THRESHOLD: u64 = 50;

/// Floor on a qualifying candidate's own `dependent_count`, independent of the ratio —
/// guards against two obscure packages (e.g. 1 vs 60 dependents) producing a large but
/// meaningless ratio for a signal that would not be actionable either way.
pub(super) const TYPOSQUAT_MIN_CANDIDATE_DEPENDENTS: u64 = 50;

/// Upper bound on how many `packages[]` candidates [`super::DepsDevClient::typosquat_signal`]
/// resolves popularity for (issue #1437 security review M1) — `GetSimilarlyNamedPackages`
/// documents no upper bound on `packages[]`, and each candidate costs 2 sequential deps.dev
/// calls, so an unbounded loop is a real (if server-side-triggered, not attacker-controlled)
/// resource-exhaustion risk. 5 is generous relative to this plan's own live-sampled evidence,
/// where every real pair had exactly one relevant candidate.
pub(super) const TYPOSQUAT_MAX_CANDIDATES_CHECKED: usize = 5;

/// Picks the highest-`dependent_count` candidate that clears both the ratio gate
/// ([`TYPOSQUAT_RATIO_THRESHOLD`]) and the popularity floor
/// ([`TYPOSQUAT_MIN_CANDIDATE_DEPENDENTS`]), excluding any candidate whose name exactly
/// matches `declared_name` (FR-006: a self-match means the declared package is itself the
/// canonical/popular side of the pair, never a typosquat suspect).
///
/// `candidates` is `(name, dependent_count)` pairs already resolved by the caller — this
/// function does no I/O and cannot fail; an empty slice (or every entry filtered out)
/// simply yields `None`.
pub(super) fn evaluate_candidates(
    declared_name: &str,
    declared_dependent_count: u64,
    candidates: &[(String, u64)],
) -> Option<TyposquatSignal> {
    candidates
        .iter()
        .filter(|(name, _)| name != declared_name)
        .filter(|(_, count)| *count >= TYPOSQUAT_MIN_CANDIDATE_DEPENDENTS)
        .filter(|(_, count)| {
            *count >= declared_dependent_count.saturating_mul(TYPOSQUAT_RATIO_THRESHOLD)
        })
        .max_by_key(|(_, count)| *count)
        .map(|(name, count)| TyposquatSignal {
            suspected_name: name.clone(),
            declared_dependent_count,
            suspected_dependent_count: *count,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_candidates_49x_ratio_does_not_fire() {
        let candidates = [("popular".to_string(), 49)];
        assert!(evaluate_candidates("tiny", 1, &candidates).is_none());
    }

    #[test]
    fn evaluate_candidates_50x_ratio_fires() {
        let candidates = [("popular".to_string(), 50)];
        let signal = evaluate_candidates("tiny", 1, &candidates).expect("must fire at exactly 50x");
        assert_eq!(signal.suspected_name, "popular");
        assert_eq!(signal.declared_dependent_count, 1);
        assert_eq!(signal.suspected_dependent_count, 50);
    }

    #[test]
    fn evaluate_candidates_51x_ratio_fires() {
        let candidates = [("popular".to_string(), 51)];
        assert!(evaluate_candidates("tiny", 1, &candidates).is_some());
    }

    /// `declared_dependent_count = 0` makes the ratio gate trivially satisfied (any count is
    /// `>= 0`), isolating the popularity floor as the sole remaining gate.
    #[test]
    fn evaluate_candidates_below_floor_never_fires_even_at_trivially_high_ratio() {
        let candidates = [("obscure".to_string(), 40)];
        assert!(evaluate_candidates("tiny", 0, &candidates).is_none());
    }

    #[test]
    fn evaluate_candidates_at_floor_with_trivial_ratio_fires() {
        let candidates = [("popular".to_string(), 50)];
        assert!(evaluate_candidates("tiny", 0, &candidates).is_some());
    }

    /// FR-006: the declared package itself must never appear as its own suspect.
    #[test]
    fn evaluate_candidates_excludes_exact_name_match() {
        let candidates = [("tiny".to_string(), 10_000)];
        assert!(evaluate_candidates("tiny", 1, &candidates).is_none());
    }

    #[test]
    fn evaluate_candidates_empty_list_returns_none() {
        assert!(evaluate_candidates("tiny", 1, &[]).is_none());
    }

    #[test]
    fn evaluate_candidates_picks_highest_dependent_count_among_multiple_qualifying() {
        let candidates = [("mid".to_string(), 100), ("top".to_string(), 500)];
        let signal = evaluate_candidates("tiny", 1, &candidates).expect("must fire");
        assert_eq!(signal.suspected_name, "top");
        assert_eq!(signal.suspected_dependent_count, 500);
    }
}
