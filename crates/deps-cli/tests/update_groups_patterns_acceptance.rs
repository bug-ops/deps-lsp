//! #2072 acceptance: `[update.groups.<name>]` gains `patterns` (`*`-only globs) and
//! `dependency_type` (`production|development|build|peer|optional`), and
//! `UpdateGroup::contains` takes the dependency's `Option<DependencyKind>`.
//!
//! Written tests-first against architect v1 + v2 (S1, S5). Missing today: `GroupRule::patterns`,
//! `GroupRule::dependency_type`, `deps_core::DependencyKind`, the third `contains` parameter,
//! `PlannedUpdateItem::with_dependency_kind`.

#![expect(clippy::expect_used, reason = "test code")]

use std::assert_matches;
use std::str::FromStr;

use deps_cli::config::GroupName;
use deps_cli::update::group::{UpdateGroup, demote_outside_group};
use deps_cli::update::{CurrentVersion, Outcome, PlannedUpdateItem, SkipReason};
use deps_core::DependencyKind;
use deps_core::edit::{ManifestEdit, UpdateKind};
use deps_core::position::Range;
use deps_core::{ConcreteVersion, NormalizedName};

const FORMATTER: deps_core::test_util::StubFormatter =
    deps_core::test_util::StubFormatter::new().with_package_url_prefix("");

fn normalized(name: &str) -> NormalizedName {
    deps_core::test_util::package_key(name).normalized().clone()
}

fn load(body: &str) -> Result<deps_cli::config::CliConfig, deps_cli::config::ConfigError> {
    let dir = tempfile::tempdir().expect("config dir");
    let path = dir.path().join("deps.toml");
    std::fs::write(&path, body).expect("write config");
    deps_cli::config::load(Some(&path), dir.path())
}

fn group(body: &str) -> UpdateGroup {
    let mut config = load(body).expect("config must parse");
    let name = GroupName::from_str("g").expect("group name");
    let rule = config.update.groups.remove(&name).expect("group g");
    UpdateGroup::new(name, rule, &FORMATTER)
}

fn contains(group: &UpdateGroup, name: &str, kind: Option<DependencyKind>) -> bool {
    group.contains(&normalized(name), UpdateKind::Minor, kind)
}

// --- config schema ---

#[test]
fn config_load_accepts_patterns_and_every_dependency_type_token() {
    assert!(load("[update.groups.g]\npatterns = [\"serde*\", \"*-core\"]\n").is_ok());
    for token in ["production", "development", "build", "peer", "optional"] {
        let body = format!("[update.groups.g]\ndependency_type = \"{token}\"\n");
        assert!(load(&body).is_ok(), "{token}");
    }
}

#[test]
fn config_load_rejects_unknown_dependency_type_and_malformed_patterns() {
    let too_long = format!("[update.groups.g]\npatterns = [\"{}\"]\n", "a".repeat(215));
    for body in [
        "[update.groups.g]\ndependency_type = \"dev\"\n",
        "[update.groups.g]\ndependency_type = \"Development\"\n",
        "[update.groups.g]\npatterns = [\"\"]\n",
        "[update.groups.g]\npatterns = [\"ser de*\"]\n",
        "[update.groups.g]\npatterns = [\"serde\\n*\"]\n",
        too_long.as_str(),
    ] {
        assert!(load(body).is_err(), "must be rejected: {body}");
    }
}

// --- patterns ---

#[test]
fn contains_pattern_selects_by_wildcard_over_normalized_names() {
    let group = group("[update.groups.g]\npatterns = [\"serde*\"]\n");

    assert!(contains(&group, "serde", Some(DependencyKind::Normal)));
    assert!(contains(&group, "serde_json", Some(DependencyKind::Normal)));
    assert!(!contains(&group, "tokio", Some(DependencyKind::Normal)));
}

#[test]
fn contains_patterns_and_dependencies_are_a_union() {
    let group = group("[update.groups.g]\ndependencies = [\"tokio\"]\npatterns = [\"serde*\"]\n");

    assert!(contains(&group, "tokio", None));
    assert!(contains(&group, "serde_json", None));
    assert!(!contains(&group, "rand", None));
}

#[test]
fn contains_pattern_still_requires_update_types_to_admit() {
    let group = group("[update.groups.g]\npatterns = [\"serde*\"]\nupdate_types = [\"patch\"]\n");

    assert!(group.contains(&normalized("serde"), UpdateKind::Patch, None));
    assert!(!group.contains(&normalized("serde"), UpdateKind::Major, None));
}

// --- dependency_type ---

#[test]
fn contains_production_admits_every_known_kind_but_development() {
    let group = group("[update.groups.g]\ndependency_type = \"production\"\n");

    for (kind, expected) in [
        (DependencyKind::Normal, true),
        (DependencyKind::Build, true),
        (DependencyKind::Peer, true),
        (DependencyKind::Optional, true),
        (DependencyKind::Development, false),
    ] {
        assert_eq!(contains(&group, "x", Some(kind)), expected, "{kind:?}");
    }
}

#[test]
fn contains_other_dependency_types_match_exactly_one_kind() {
    for (token, only) in [
        ("development", DependencyKind::Development),
        ("build", DependencyKind::Build),
        ("peer", DependencyKind::Peer),
        ("optional", DependencyKind::Optional),
    ] {
        let group = group(&format!(
            "[update.groups.g]\ndependency_type = \"{token}\"\n"
        ));
        for kind in [
            DependencyKind::Normal,
            DependencyKind::Development,
            DependencyKind::Build,
            DependencyKind::Peer,
            DependencyKind::Optional,
        ] {
            assert_eq!(
                contains(&group, "x", Some(kind)),
                kind == only,
                "{token} {kind:?}"
            );
        }
    }
}

#[test]
fn contains_unknown_kind_is_outside_every_dependency_type_group_but_inside_others() {
    for token in ["production", "development", "build", "peer", "optional"] {
        let group = group(&format!(
            "[update.groups.g]\ndependency_type = \"{token}\"\n"
        ));
        assert!(!contains(&group, "x", None), "{token}");
    }
    let untyped = group("[update.groups.g]\ndependencies = [\"x\"]\n");
    assert!(contains(&untyped, "x", None));
}

#[test]
fn contains_dependency_type_combines_with_patterns_by_intersection() {
    let group =
        group("[update.groups.g]\npatterns = [\"serde*\"]\ndependency_type = \"development\"\n");

    assert!(contains(
        &group,
        "serde_json",
        Some(DependencyKind::Development)
    ));
    assert!(!contains(
        &group,
        "serde_json",
        Some(DependencyKind::Normal)
    ));
    assert!(!contains(
        &group,
        "tokio",
        Some(DependencyKind::Development)
    ));
}

// --- demotion wiring ---

fn applied_item(name: &str, kind: Option<DependencyKind>) -> PlannedUpdateItem {
    PlannedUpdateItem::new(
        name.to_owned(),
        CurrentVersion::Resolved(ConcreteVersion::from("1.0.0")),
        Outcome::Applied {
            edit: ManifestEdit {
                range: Range::default(),
                new_text: "1.1.0".to_owned(),
            },
            target: ConcreteVersion::from("1.1.0"),
        },
        Vec::new(),
        false,
        None,
        None,
    )
    .with_dependency_kind(kind)
}

#[test]
fn demote_outside_group_uses_each_items_dependency_kind() {
    let group = group("[update.groups.g]\ndependency_type = \"development\"\n");
    let mut items = vec![
        applied_item("dev-dep", Some(DependencyKind::Development)),
        applied_item("prod-dep", Some(DependencyKind::Normal)),
        applied_item("unknown-dep", None),
    ];

    demote_outside_group(&mut items, &group, &FORMATTER);

    assert_matches!(items[0].outcome, Outcome::Applied { .. });
    for item in &items[1..] {
        assert_matches!(
            item.outcome,
            Outcome::Skipped {
                reason: SkipReason::NotInGroup,
                ..
            },
            "{}",
            item.name
        );
    }
}

#[test]
fn planned_update_item_new_leaves_the_dependency_kind_unknown() {
    let item = PlannedUpdateItem::new(
        "x".to_owned(),
        CurrentVersion::Unknown,
        Outcome::Skipped {
            reason: SkipReason::NotInGroup,
            target: None,
        },
        Vec::new(),
        false,
        None,
        None,
    );

    assert_eq!(item.dependency_kind, None);
    assert_eq!(
        item.with_dependency_kind(Some(DependencyKind::Build))
            .dependency_kind,
        Some(DependencyKind::Build)
    );
}
