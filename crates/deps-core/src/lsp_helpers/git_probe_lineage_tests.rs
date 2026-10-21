//! Table tests for the compare/merge-base to lineage and membership mappings.

use super::{CommitLineage, CommitSha, CompareStatus, CompareSummary, DefaultBranchMembership};

const ALL_STATUSES: [CompareStatus; 4] = [
    CompareStatus::Ahead,
    CompareStatus::Behind,
    CompareStatus::Diverged,
    CompareStatus::Identical,
];

fn summary(status: CompareStatus, ahead_by: u32) -> CompareSummary {
    CompareSummary { status, ahead_by }
}

fn sha(digit: char) -> CommitSha {
    CommitSha::parse(&digit.to_string().repeat(40)).unwrap()
}

#[test]
fn lineage_from_compare_is_ahead_only_for_ahead() {
    for status in ALL_STATUSES {
        let expected = match status {
            CompareStatus::Ahead => CommitLineage::AheadOfLatest { ahead_by: Some(7) },
            CompareStatus::Behind | CompareStatus::Diverged | CompareStatus::Identical => {
                CommitLineage::NotAhead
            }
        };
        assert_eq!(
            CommitLineage::from_compare(summary(status, 7)),
            expected,
            "{status:?}"
        );
    }
}

#[test]
fn membership_from_compare_is_reachable_for_behind_and_identical() {
    for status in ALL_STATUSES {
        let expected = match status {
            CompareStatus::Behind | CompareStatus::Identical => DefaultBranchMembership::Reachable,
            CompareStatus::Ahead | CompareStatus::Diverged => DefaultBranchMembership::NotProven,
        };
        assert_eq!(
            DefaultBranchMembership::from_compare(summary(status, 0)),
            expected,
            "{status:?}"
        );
    }
}

#[test]
fn lineage_from_merge_base_table() {
    let (latest, pin, other) = (sha('a'), sha('b'), sha('c'));
    let ahead = CommitLineage::AheadOfLatest { ahead_by: None };
    let cases = [
        (
            "merge base is the release, pin differs",
            &latest,
            &pin,
            ahead,
        ),
        (
            "pin equals the release",
            &latest,
            &latest,
            CommitLineage::NotAhead,
        ),
        (
            "merge base is another commit",
            &other,
            &pin,
            CommitLineage::NotAhead,
        ),
        ("merge base is the pin", &pin, &pin, CommitLineage::NotAhead),
    ];
    for (name, merge_base, pin, expected) in cases {
        assert_eq!(
            CommitLineage::from_merge_base(merge_base, &latest, pin),
            expected,
            "{name}"
        );
    }
}

#[test]
fn membership_from_merge_base_table() {
    let (pin, other) = (sha('b'), sha('c'));
    assert_eq!(
        DefaultBranchMembership::from_merge_base(&pin, &pin),
        DefaultBranchMembership::Reachable
    );
    assert_eq!(
        DefaultBranchMembership::from_merge_base(&other, &pin),
        DefaultBranchMembership::NotProven
    );
}
