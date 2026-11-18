//! #2072 acceptance: `deps_core::DependencyKind` is an exhaustive five-variant enum.
//! Written tests-first; the type does not exist yet.

use deps_core::DependencyKind;

/// Compiles only while the enum is exhaustive with exactly these variants and no
/// `#[non_exhaustive]` (project rule: adding a variant must break every `match`).
const fn label(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Normal => "normal",
        DependencyKind::Development => "development",
        DependencyKind::Build => "build",
        DependencyKind::Peer => "peer",
        DependencyKind::Optional => "optional",
    }
}

#[test]
fn dependency_kind_variants_are_distinct_and_copy() {
    let all = [
        DependencyKind::Normal,
        DependencyKind::Development,
        DependencyKind::Build,
        DependencyKind::Peer,
        DependencyKind::Optional,
    ];
    let copied = all;
    for (index, kind) in all.iter().enumerate() {
        for (other_index, other) in copied.iter().enumerate() {
            assert_eq!(index == other_index, kind == other);
        }
        assert!(!label(*kind).is_empty());
    }
}
