//! Local matching of an in-use version against an OSV record's affected ranges, for ecosystems
//! where OSV.dev does not version-match server-side ([`super::types::VersionMatching::LocalUnversioned`],
//! issue #1675).
//!
//! Follows OSV's range-evaluation algorithm for `SEMVER`/`ECOSYSTEM` ranges: events are sorted
//! by version and folded, `introduced`/`fixed`/`last_affected` toggling the affected state.
//! Anything that cannot be evaluated (a non-numeric bound, an unrecognized range type, an entry
//! with only `GIT` ranges) yields [`Verdict::Undeterminable`] rather than a guess, so it can
//! never read as clean. Build metadata is ignored on both sides, per the SemVer spec.
//!
//! A range that only ever `introduced` (no `fixed`/`last_affected`) is open-ended. GitHub's
//! advisory export then puts the real ceiling in the entry's
//! `database_specific.last_known_affected_version_range` (`< X` / `<= X`); it is honored
//! as the upper bound, and an unparsable one makes the range undeterminable (issue #1707).

use semver::{BuildMetadata, Version};

use super::OsvVersion;
use super::types::{OsvAffected, OsvEvent, OsvRange, OsvRangeType};

/// A full SemVer version parsed from an [`OsvVersion`] — the only shape locally matchable.
///
/// A floating tag (`4`, `4.1`), a SHA pin, or a branch name has no single position on the
/// version line, so it never parses and stays "not checked". Build metadata is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalVersion(Version);

impl LocalVersion {
    pub(super) fn parse(version: &OsvVersion) -> Option<Self> {
        Version::parse(version.as_str())
            .ok()
            .map(|v| Self(strip_build(v)))
    }
}

fn strip_build(mut version: Version) -> Version {
    version.build = BuildMetadata::EMPTY;
    version
}

/// Parses an OSV bound (or `versions` entry): optional `v` prefix, `0` as the lower sentinel,
/// and 1-2 component numeric forms (`41`, `2.1`) zero-padded — GHA advisories use them. The
/// in-use pin never gets this leniency.
fn parse_bound(raw: &str) -> Option<Version> {
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let is_numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let components = raw.split('.').count();
    let padded = if raw.split('.').all(is_numeric) {
        match components {
            1 => format!("{raw}.0.0"),
            2 => format!("{raw}.0"),
            _ => raw.to_owned(),
        }
    } else {
        raw.to_owned()
    };
    Version::parse(&padded).ok().map(strip_build)
}

/// Outcome of matching one record against one [`LocalVersion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    Affected,
    NotAffected,
    Undeterminable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeVerdict {
    Affected,
    NotAffected,
    Undeterminable,
    /// A `GIT` range says nothing about released versions.
    Irrelevant,
}

/// The entry's `database_specific.last_known_affected_version_range`, when present.
#[derive(Debug)]
enum LastKnownRange {
    Below(Version),
    AtMost(Version),
    Unparsable,
}

impl LastKnownRange {
    /// Reads the raw string off `entry`; `None` when the key is absent or not a string.
    fn of(entry: &OsvAffected) -> Option<Self> {
        let raw = entry
            .database_specific
            .as_ref()?
            .get("last_known_affected_version_range")?
            .as_str()?;
        Some(Self::parse(raw))
    }

    fn parse(raw: &str) -> Self {
        let raw = raw.trim();
        let (bound, inclusive) = match raw.strip_prefix("<=") {
            Some(rest) => (rest, true),
            None => match raw.strip_prefix('<') {
                Some(rest) => (rest, false),
                None => return Self::Unparsable,
            },
        };
        match parse_bound(bound.trim()) {
            Some(v) if inclusive => Self::AtMost(v),
            Some(v) => Self::Below(v),
            None => Self::Unparsable,
        }
    }

    fn verdict(&self, version: &LocalVersion) -> RangeVerdict {
        let inside = match self {
            Self::Below(bound) => version.0 < *bound,
            Self::AtMost(bound) => version.0 <= *bound,
            Self::Unparsable => return RangeVerdict::Undeterminable,
        };
        if inside {
            RangeVerdict::Affected
        } else {
            RangeVerdict::NotAffected
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Edge {
    Introduced,
    Fixed,
    LastAffected,
}

/// Matches `affected` (the entries already filtered to the queried package) against `version`.
///
/// No entry at all is [`Verdict::Undeterminable`], as is an entry carrying neither an
/// evaluable range nor a `versions` list: the record cannot be shown not to apply.
pub(super) fn match_affected(affected: &[&OsvAffected], version: &LocalVersion) -> Verdict {
    let mut verdict = if affected.is_empty() {
        Verdict::Undeterminable
    } else {
        Verdict::NotAffected
    };
    for entry in affected {
        let last_known = LastKnownRange::of(entry);
        if entry
            .versions
            .iter()
            .filter_map(|v| parse_bound(v))
            .any(|v| v == version.0)
        {
            return Verdict::Affected;
        }
        let mut evaluable = !entry.versions.is_empty();
        for range in &entry.ranges {
            match match_range(range, version, last_known.as_ref()) {
                RangeVerdict::Affected => return Verdict::Affected,
                RangeVerdict::Undeterminable => verdict = Verdict::Undeterminable,
                RangeVerdict::NotAffected => evaluable = true,
                RangeVerdict::Irrelevant => {}
            }
        }
        if !evaluable {
            verdict = Verdict::Undeterminable;
        }
    }
    verdict
}

fn match_range(
    range: &OsvRange,
    version: &LocalVersion,
    last_known: Option<&LastKnownRange>,
) -> RangeVerdict {
    match range.range_type {
        OsvRangeType::Git => RangeVerdict::Irrelevant,
        OsvRangeType::Unknown => RangeVerdict::Undeterminable,
        OsvRangeType::Semver | OsvRangeType::Ecosystem => {
            let mut edges = Vec::with_capacity(range.events.len());
            for event in &range.events {
                match event_edge(event) {
                    Ok(Some(edge)) => edges.push(edge),
                    Ok(None) => {}
                    Err(UnparsableBound) => return RangeVerdict::Undeterminable,
                }
            }
            edges.sort_by(|a, b| a.1.cmp(&b.1));
            // Every event must be `introduced`: a mixed range's trailing `introduced` is not capped.
            let open_ended = edges
                .iter()
                .all(|(edge, _)| matches!(edge, Edge::Introduced));
            let mut affected = false;
            for (edge, bound) in edges {
                match edge {
                    Edge::Introduced if version.0 >= bound => affected = true,
                    Edge::Fixed if version.0 >= bound => affected = false,
                    Edge::LastAffected if version.0 > bound => affected = false,
                    Edge::Introduced | Edge::Fixed | Edge::LastAffected => {}
                }
            }
            if affected && open_ended {
                last_known.map_or(RangeVerdict::Affected, |r| r.verdict(version))
            } else if affected {
                RangeVerdict::Affected
            } else {
                RangeVerdict::NotAffected
            }
        }
    }
}

/// A range event whose bound is not a (paddable) numeric version; the whole range is then
/// undeterminable.
struct UnparsableBound;

/// `Ok(None)` = an event carrying no bound this matcher needs (`limit`), skipped.
fn event_edge(event: &OsvEvent) -> Result<Option<(Edge, Version)>, UnparsableBound> {
    let (edge, raw) = if let Some(v) = &event.introduced {
        (Edge::Introduced, v)
    } else if let Some(v) = &event.fixed {
        (Edge::Fixed, v)
    } else if let Some(v) = &event.last_affected {
        (Edge::LastAffected, v)
    } else {
        return Ok(None);
    };
    let bound = parse_bound(raw).ok_or(UnparsableBound)?;
    Ok(Some((edge, bound)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn verdict_for(entries: &[serde_json::Value], version: &str) -> Verdict {
        let entries: Vec<OsvAffected> = entries
            .iter()
            .map(|e| serde_json::from_value(e.clone()).unwrap())
            .collect();
        let refs: Vec<&OsvAffected> = entries.iter().collect();
        let version = LocalVersion::parse(&OsvVersion::new(version)).unwrap();
        match_affected(&refs, &version)
    }

    fn verdict(entry: serde_json::Value, version: &str) -> Verdict {
        verdict_for(&[entry], version)
    }

    fn semver_range(events: serde_json::Value) -> serde_json::Value {
        json!({"ranges": [{"type": "SEMVER", "events": events}]})
    }

    #[test]
    fn introduced_fixed_range_brackets_the_affected_versions() {
        let r = || semver_range(json!([{"introduced": "4.0.0"}, {"fixed": "4.1.3"}]));
        assert_eq!(verdict(r(), "4.1.2"), Verdict::Affected);
        assert_eq!(verdict(r(), "4.0.0"), Verdict::Affected);
        assert_eq!(verdict(r(), "4.1.3"), Verdict::NotAffected);
        assert_eq!(verdict(r(), "3.9.9"), Verdict::NotAffected);
    }

    #[test]
    fn introduced_zero_and_last_affected_is_inclusive() {
        let r = || semver_range(json!([{"introduced": "0"}, {"last_affected": "2.0.0"}]));
        assert_eq!(verdict(r(), "0.0.1"), Verdict::Affected);
        assert_eq!(verdict(r(), "2.0.0"), Verdict::Affected);
        assert_eq!(verdict(r(), "2.0.1"), Verdict::NotAffected);
    }

    #[test]
    fn build_metadata_is_ignored_on_pin_and_bounds() {
        let r = || semver_range(json!([{"introduced": "0"}, {"last_affected": "2.0.0"}]));
        assert_eq!(verdict(r(), "2.0.0+b"), Verdict::Affected);
        let fixed = || semver_range(json!([{"introduced": "0"}, {"fixed": "2.0.0+meta"}]));
        assert_eq!(verdict(fixed(), "2.0.0"), Verdict::NotAffected);
        assert_eq!(verdict(fixed(), "1.9.9+x"), Verdict::Affected);
        assert_eq!(
            verdict(json!({"versions": ["v1.2.3"]}), "1.2.3+build"),
            Verdict::Affected
        );
    }

    #[test]
    fn events_are_sorted_before_folding() {
        let r = semver_range(json!([{"fixed": "4.1.3"}, {"introduced": "4.0.0"}]));
        assert_eq!(verdict(r, "4.1.2"), Verdict::Affected);
    }

    #[test]
    fn multiple_introduced_fixed_pairs_in_one_range() {
        let r = || {
            semver_range(json!([
                {"introduced": "1.0.0"}, {"fixed": "1.5.0"},
                {"introduced": "2.0.0"}, {"fixed": "2.5.0"}
            ]))
        };
        assert_eq!(verdict(r(), "1.2.0"), Verdict::Affected);
        assert_eq!(verdict(r(), "1.7.0"), Verdict::NotAffected);
        assert_eq!(verdict(r(), "2.1.0"), Verdict::Affected);
        assert_eq!(verdict(r(), "2.5.0"), Verdict::NotAffected);
    }

    #[test]
    fn any_affecting_range_or_entry_wins() {
        let two_ranges = json!({"ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "3.5.0"}]}
        ]});
        assert_eq!(verdict(two_ranges, "3.1.0"), Verdict::Affected);
        let miss = semver_range(json!([{"introduced": "0"}, {"fixed": "1.0.0"}]));
        let hit = semver_range(json!([{"introduced": "5.0.0"}]));
        assert_eq!(verdict_for(&[miss, hit], "6.0.0"), Verdict::Affected);
    }

    #[test]
    fn prerelease_orders_before_its_release() {
        let r = || semver_range(json!([{"introduced": "0"}, {"fixed": "2.0.0"}]));
        assert_eq!(verdict(r(), "2.0.0-rc.1"), Verdict::Affected);
        let from = semver_range(json!([{"introduced": "2.0.0"}]));
        assert_eq!(verdict(from, "2.0.0-rc.1"), Verdict::NotAffected);
    }

    #[test]
    fn limit_event_is_ignored() {
        let r = semver_range(json!([{"introduced": "1.0.0"}, {"limit": "2.0.0"}]));
        assert_eq!(verdict(r, "9.0.0"), Verdict::Affected);
    }

    #[test]
    fn same_bound_introduced_and_fixed_follow_input_order() {
        let r = || semver_range(json!([{"introduced": "1.0.0"}, {"fixed": "1.0.0"}]));
        assert_eq!(verdict(r(), "1.0.0"), Verdict::NotAffected);
        assert_eq!(verdict(r(), "1.0.1"), Verdict::NotAffected);
    }

    #[test]
    fn bare_major_and_minor_bounds_are_padded() {
        let fixed = || semver_range(json!([{"introduced": "0"}, {"fixed": "41"}]));
        assert_eq!(verdict(fixed(), "40.9.9"), Verdict::Affected);
        assert_eq!(verdict(fixed(), "41.0.0"), Verdict::NotAffected);
        let introduced = || semver_range(json!([{"introduced": "5"}, {"fixed": "6"}]));
        assert_eq!(verdict(introduced(), "4.9.9"), Verdict::NotAffected);
        assert_eq!(verdict(introduced(), "5.0.0"), Verdict::Affected);
        assert_eq!(verdict(introduced(), "6.0.0"), Verdict::NotAffected);
        let minor = semver_range(json!([{"introduced": "v2.1"}, {"fixed": "2.3"}]));
        assert_eq!(verdict(minor, "2.2.9"), Verdict::Affected);
    }

    #[test]
    fn non_numeric_bounds_stay_undeterminable() {
        for bad in [
            "v4-beta",
            "latest",
            "abcdef1234567890abcdef1234567890abcdef12",
            "",
        ] {
            let fixed = semver_range(json!([{"introduced": "0"}, {"fixed": bad}]));
            assert_eq!(verdict(fixed, "1.0.0"), Verdict::Undeterminable, "{bad}");
        }
        let introduced = semver_range(json!([{"introduced": "main"}]));
        assert_eq!(verdict(introduced, "1.0.0"), Verdict::Undeterminable);
        let last = semver_range(json!([{"introduced": "0"}, {"last_affected": "x"}]));
        assert_eq!(verdict(last, "1.0.0"), Verdict::Undeterminable);
    }

    #[test]
    fn explicit_versions_list_is_v_normalised() {
        assert_eq!(
            verdict(json!({"versions": ["v0.1.21", "1.2.3"]}), "0.1.21"),
            Verdict::Affected
        );
        assert_eq!(
            verdict(json!({"versions": ["1.2.3"]}), "1.2.4"),
            Verdict::NotAffected
        );
    }

    #[test]
    fn unknown_range_is_undeterminable_but_a_hit_still_wins() {
        let unknown = json!({"ranges": [{"events": [{"introduced": "0"}]}]});
        assert_eq!(verdict(unknown.clone(), "1.0.0"), Verdict::Undeterminable);
        let hit = semver_range(json!([{"introduced": "0"}]));
        assert_eq!(verdict_for(&[unknown, hit], "1.0.0"), Verdict::Affected);
    }

    #[test]
    fn undeterminable_is_sticky_across_later_entries() {
        let bad = semver_range(json!([{"introduced": "0"}, {"fixed": "zzz"}]));
        let miss = semver_range(json!([{"introduced": "0"}, {"fixed": "1.0.0"}]));
        assert_eq!(
            verdict_for(&[bad.clone(), miss.clone()], "2.0.0"),
            Verdict::Undeterminable
        );
        assert_eq!(verdict_for(&[miss, bad], "2.0.0"), Verdict::Undeterminable);
    }

    #[test]
    fn git_only_entry_is_undeterminable_but_git_beside_a_semver_range_is_not() {
        let git =
            json!({"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]});
        assert_eq!(verdict(git, "1.0.0"), Verdict::Undeterminable);
        let both = json!({"ranges": [
            {"type": "GIT", "events": [{"introduced": "0"}]},
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}
        ]});
        assert_eq!(verdict(both, "2.0.0"), Verdict::NotAffected);
    }

    #[test]
    fn empty_entry_list_is_undeterminable() {
        let version = LocalVersion::parse(&OsvVersion::new("1.0.0")).unwrap();
        assert_eq!(match_affected(&[], &version), Verdict::Undeterminable);
    }

    fn codeql_open_ended_entries() -> Vec<serde_json::Value> {
        vec![
            json!({
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.26.11"}, {"fixed": "3.28.3"}]}],
                "database_specific": {"last_known_affected_version_range": "<= 3.28.2"}
            }),
            json!({
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.26.11"}]}],
                "database_specific": {"last_known_affected_version_range": "< 3.0.0"}
            }),
        ]
    }

    #[test]
    fn ghsa_vqf5_open_ended_range_is_capped_by_last_known_affected_range() {
        let entries = codeql_open_ended_entries();
        for affected in ["3.28.2", "3.26.11", "2.26.11", "2.30.0", "2.99.99"] {
            assert_eq!(
                verdict_for(&entries, affected),
                Verdict::Affected,
                "{affected}"
            );
        }
        for clean in ["3.28.3", "4.38.2", "2.26.10", "3.0.0", "3.26.10"] {
            assert_eq!(
                verdict_for(&entries, clean),
                Verdict::NotAffected,
                "{clean}"
            );
        }
    }

    #[test]
    fn last_known_affected_range_at_most_is_inclusive() {
        let e = json!({
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}],
            "database_specific": {"last_known_affected_version_range": "<= 2.0.0"}
        });
        assert_eq!(verdict(e.clone(), "2.0.0"), Verdict::Affected);
        assert_eq!(verdict(e.clone(), "2.0.1"), Verdict::NotAffected);
        assert_eq!(verdict(e, "0.9.0"), Verdict::NotAffected);
    }

    #[test]
    fn unparsable_last_known_affected_range_is_undeterminable() {
        for bad in [">= 1.0.0", "3.0.0", "< latest", "", "<"] {
            let e = json!({
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}],
                "database_specific": {"last_known_affected_version_range": bad}
            });
            assert_eq!(verdict(e, "2.0.0"), Verdict::Undeterminable, "{bad:?}");
        }
    }

    #[test]
    fn last_known_affected_range_ignored_without_open_ended_range_or_key() {
        let closed = json!({
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
            "database_specific": {"last_known_affected_version_range": "< 1.5.0"}
        });
        assert_eq!(verdict(closed, "1.9.0"), Verdict::Affected);
        let no_key = json!({
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}],
            "database_specific": {"informational": "unmaintained"}
        });
        assert_eq!(verdict(no_key, "9.0.0"), Verdict::Affected);
        let non_string = json!({
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}],
            "database_specific": {"last_known_affected_version_range": 3}
        });
        assert_eq!(verdict(non_string, "9.0.0"), Verdict::Affected);
    }

    #[test]
    fn last_known_cap_scope_is_per_entry_and_all_introduced_only() {
        let capped = json!({
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}],
            "database_specific": {"last_known_affected_version_range": "< 2.0.0"}
        });
        let uncapped = semver_range(json!([{"introduced": "1.0.0"}]));
        assert_eq!(verdict_for(&[capped, uncapped], "9.0.0"), Verdict::Affected);
        let mixed = json!({
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "1.0.0"}, {"fixed": "2.0.0"}, {"introduced": "3.0.0"}
            ]}],
            "database_specific": {"last_known_affected_version_range": "< 4.0.0"}
        });
        assert_eq!(verdict(mixed, "9.0.0"), Verdict::Affected);
    }

    #[test]
    fn introduced_zero_with_last_known_upper_bound() {
        let e = || {
            json!({
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                "database_specific": {"last_known_affected_version_range": "< 2.0.0"}
            })
        };
        assert_eq!(verdict(e(), "1.9.9"), Verdict::Affected);
        assert_eq!(verdict(e(), "2.0.0"), Verdict::NotAffected);
        assert_eq!(verdict(e(), "3.0.0"), Verdict::NotAffected);
    }

    #[test]
    fn only_full_semver_pins_parse() {
        for bad in [
            "4",
            "4.1",
            "v4.1.2",
            "main",
            "1234567890abcdef1234567890abcdef12345678",
        ] {
            assert!(
                LocalVersion::parse(&OsvVersion::new(bad)).is_none(),
                "{bad}"
            );
        }
        for good in ["4.1.2", "4.1.2+meta", "4.1.2-rc.1"] {
            assert!(
                LocalVersion::parse(&OsvVersion::new(good)).is_some(),
                "{good}"
            );
        }
    }
}
