//! Acceptance tests for #1118 (`[update.groups]`, `--group`), written tests-first against spec 104
//! (FR-015 to FR-019) and its plan's contracts.
//!
//! Also holds the FR-019 guard: `update_exit_code` keeps its pre-change result for every
//! `Outcome`/`SkipReason`/`UnfixableReason` variant after it becomes an exhaustive `match`.
//! Declared in `update/mod.rs` as `#[cfg(test)] mod group_tests;`.

#![allow(clippy::expect_used, clippy::panic)]

use std::assert_matches;
use std::str::FromStr;

use clap::Parser;
use deps_core::edit::{ManifestEdit, UnplannableReason, UpdateKind};
use deps_core::position::Range;
use deps_core::{ConcreteVersion, NormalizedName};

use super::group::{UpdateGroup, demote_outside_group};
use super::regen::{LockfileOutcome, NotApplicableReason, RegenerationError};
use super::{CurrentVersion, LockfileFix, Outcome, PlannedUpdateItem, SkipReason, UnfixableReason};
use super::{UpdatePlan, UpdateRun};
use crate::cli::Cli;
use crate::config::GroupName;
use crate::exit::{EXIT_CLEAN, EXIT_EXECUTION_ERROR, EXIT_POLICY_VIOLATION, update_exit_code};

const STUB_FORMATTER: deps_core::test_util::StubFormatter =
    deps_core::test_util::StubFormatter::new().with_package_url_prefix("");

fn normalized(declared: &str) -> NormalizedName {
    deps_core::test_util::package_key(declared)
        .normalized()
        .clone()
}

/// Loads `body` as an explicit `--config` file and returns the `[update.groups.<group>]` rule;
/// panics when the file is rejected.
fn rule_from(body: &str, group: &str) -> (GroupName, crate::config::GroupRule) {
    let dir = tempfile::tempdir().expect("config dir");
    let path = dir.path().join("deps.toml");
    std::fs::write(&path, body).expect("write config");
    let mut config = crate::config::load(Some(&path), dir.path()).expect("config must parse");
    let name = GroupName::from_str(group).expect("valid group name");
    let rule = config
        .update
        .groups
        .remove(&name)
        .expect("the group must be parsed");
    (name, rule)
}

/// The `[update.groups.<group>]` rule of `body` as an [`UpdateGroup`] over the identity formatter.
pub(super) fn group_from(body: &str, group: &str) -> UpdateGroup {
    let (name, rule) = rule_from(body, group);
    UpdateGroup::new(name, rule, &STUB_FORMATTER)
}

fn load_result(body: &str) -> bool {
    let dir = tempfile::tempdir().expect("config dir");
    let path = dir.path().join("deps.toml");
    std::fs::write(&path, body).expect("write config");
    crate::config::load(Some(&path), dir.path()).is_ok()
}

pub(super) fn item(name: &str, current: &str, outcome: Outcome) -> PlannedUpdateItem {
    PlannedUpdateItem {
        name: name.to_owned(),
        current: CurrentVersion::Resolved(ConcreteVersion::from(current)),
        outcome,
        advisory_ids: Vec::new(),
        ignore_rule_overridden: false,
        gossip_excluded_version: None,
        cooldown_fallback: None,
        osv_sibling_match: None,
        native_hold: None,
        lockfile_fix: LockfileFix::default(),
    }
}

pub(super) fn applied(target: &str) -> Outcome {
    Outcome::Applied {
        edit: ManifestEdit {
            range: Range::default(),
            new_text: target.to_owned(),
        },
        target: ConcreteVersion::from(target),
    }
}

pub(super) fn skipped(reason: SkipReason) -> Outcome {
    Outcome::Skipped {
        reason,
        target: None,
    }
}

fn run_of(items: Vec<PlannedUpdateItem>, lockfile: LockfileOutcome) -> UpdateRun {
    UpdateRun {
        plan: UpdatePlan { items },
        lockfile,
    }
}

fn clean_lockfile() -> LockfileOutcome {
    LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied)
}

// --- FR-015: config schema ---

#[test]
fn test_config_load_group_with_unknown_key_is_rejected() {
    assert!(!load_result(
        "[update.groups.g]\ndependencies = [\"a\"]\nbogus = 1\n"
    ));
}

#[test]
fn test_config_load_group_names_outside_the_grammar_are_rejected() {
    let too_long = "a".repeat(65);
    for name in ["-x", "x-", "X", "a_b", "a.b", "", too_long.as_str()] {
        assert!(
            !load_result(&format!("[update.groups.\"{name}\"]\n")),
            "group name {name:?} must be rejected"
        );
    }
}

#[test]
fn test_config_load_group_names_inside_the_grammar_are_accepted() {
    let longest = "a".repeat(64);
    for name in ["a", "a-b", "0", "minor-patch", longest.as_str()] {
        assert!(
            load_result(&format!("[update.groups.\"{name}\"]\n")),
            "group name {name:?} must be accepted"
        );
    }
}

// --- FR-018: membership truth table ---

/// (dependencies, update_types, item name, kind, inside), the lists as TOML array bodies.
type MembershipRow<'a> = (Option<&'a str>, Option<&'a str>, &'a str, UpdateKind, bool);

#[test]
fn test_group_contains_requires_name_and_kind_to_match() {
    #[rustfmt::skip]
    let rows: &[MembershipRow] = &[
        // (dependencies, update_types, item name, kind, inside)
        (None,                       None,                    "tokio", UpdateKind::Major,   true),
        (None,                       None,                    "tokio", UpdateKind::Unknown, true),
        (Some("\"tokio\", \"serde\""), None,                  "serde", UpdateKind::Patch,   true),
        (Some("\"tokio\""),          None,                    "serde", UpdateKind::Patch,   false),
        (None,                       Some("\"minor\", \"patch\""), "x", UpdateKind::Minor,  true),
        (None,                       Some("\"minor\", \"patch\""), "x", UpdateKind::Patch,  true),
        (None,                       Some("\"minor\", \"patch\""), "x", UpdateKind::Major,  false),
        (None,                       Some("\"minor\", \"patch\""), "x", UpdateKind::Unknown, false),
        (Some("\"tokio\""),          Some("\"patch\""),       "tokio", UpdateKind::Patch,   true),
        (Some("\"tokio\""),          Some("\"patch\""),       "tokio", UpdateKind::Minor,   false),
        (Some("\"tokio\""),          Some("\"patch\""),       "other", UpdateKind::Patch,   false),
    ];
    for &(dependencies, update_types, name, kind, inside) in rows {
        let mut body = String::from("[update.groups.g]\n");
        if let Some(list) = dependencies {
            body.push_str(&format!("dependencies = [{list}]\n"));
        }
        if let Some(list) = update_types {
            body.push_str(&format!("update_types = [{list}]\n"));
        }
        let group = group_from(&body, "g");
        assert_eq!(
            group.contains(&normalized(name), kind),
            inside,
            "dependencies={dependencies:?} update_types={update_types:?} item={name} kind={kind:?}"
        );
    }
}

// --- FR-018: names are normalized with the ecosystem's formatter ---

#[cfg(feature = "pypi")]
#[test]
fn test_group_names_are_normalized_with_the_ecosystem_formatter_on_both_sides() {
    use deps_core::PackageName;
    use deps_core::lsp_helpers::NormalizeName;
    use deps_engine::setup::PypiFormatter;

    let (name, rule) = rule_from("[update.groups.g]\ndependencies = [\"Flask_Login\"]\n", "g");
    let group = UpdateGroup::new(name, rule, &PypiFormatter);
    let mut items = vec![
        item("Flask.Login", "1.0.0", applied("1.0.1")),
        item("other", "1.0.0", applied("1.0.1")),
    ];

    demote_outside_group(&mut items, &group, &PypiFormatter);

    let key = PypiFormatter.normalize_package_name(&PackageName::new("flask-login"));
    assert!(group.contains(&key, UpdateKind::Patch));
    assert_matches!(items[0].outcome, Outcome::Applied { .. });
    assert_matches!(
        items[1].outcome,
        Outcome::Skipped {
            reason: SkipReason::NotInGroup,
            ..
        }
    );
}

// --- FR-017: demotion ---

#[test]
fn test_demote_outside_group_demotes_only_applied_items_outside_the_group() {
    let group = group_from(
        "[update.groups.minor-patch]\nupdate_types = [\"minor\", \"patch\"]\n",
        "minor-patch",
    );
    let mut items = vec![
        item("inside", "1.0.0", applied("1.1.0")),
        item("outside", "1.0.0", applied("2.0.0")),
        item("ignored", "1.0.0", skipped(SkipReason::IgnoreRule)),
        item(
            "lockfile-only",
            "1.0.0",
            Outcome::RequiresLockfileUpdate {
                target: ConcreteVersion::from("2.0.0"),
            },
        ),
        item(
            "via-lockfile",
            "1.0.0",
            Outcome::AppliedViaLockfile {
                target: ConcreteVersion::from("2.0.0"),
            },
        ),
    ];

    demote_outside_group(&mut items, &group, &STUB_FORMATTER);

    assert_matches!(items[0].outcome, Outcome::Applied { .. });
    assert_eq!(
        items[1].outcome,
        Outcome::Skipped {
            reason: SkipReason::NotInGroup,
            target: Some(ConcreteVersion::from("2.0.0")),
        }
    );
    assert_eq!(items[2].outcome, skipped(SkipReason::IgnoreRule));
    assert_matches!(items[3].outcome, Outcome::RequiresLockfileUpdate { .. });
    assert_matches!(items[4].outcome, Outcome::AppliedViaLockfile { .. });
}

#[test]
fn test_demote_outside_group_unclassifiable_kind_is_inside_only_a_group_without_update_types() {
    let typed = group_from("[update.groups.t]\nupdate_types = [\"patch\"]\n", "t");
    let untyped = group_from("[update.groups.u]\ndependencies = [\"dep\"]\n", "u");
    let unknown_current = || {
        let mut unknown = item("dep", "1.0.0", applied("1.0.1"));
        unknown.current = CurrentVersion::Unknown;
        vec![unknown]
    };

    let mut for_typed = unknown_current();
    demote_outside_group(&mut for_typed, &typed, &STUB_FORMATTER);
    let mut for_untyped = unknown_current();
    demote_outside_group(&mut for_untyped, &untyped, &STUB_FORMATTER);

    assert_matches!(
        for_typed[0].outcome,
        Outcome::Skipped {
            reason: SkipReason::NotInGroup,
            ..
        }
    );
    assert_matches!(for_untyped[0].outcome, Outcome::Applied { .. });
}

#[test]
fn test_not_in_group_reason_text_names_the_group_selection() {
    let mut demoted = item(
        "dep",
        "1.0.0",
        Outcome::Skipped {
            reason: SkipReason::NotInGroup,
            target: Some(ConcreteVersion::from("2.0.0")),
        },
    );
    demoted.current = CurrentVersion::Resolved(ConcreteVersion::from("1.0.0"));

    assert!(
        demoted.reason().contains("outside the selected --group"),
        "{}",
        demoted.reason()
    );
}

// --- FR-016 / FR-001: clap surface ---

#[test]
fn test_cli_group_requires_config_and_conflicts_with_security_only() {
    let parse = |extra: &[&str]| {
        let mut args = vec!["deps-cli", "update"];
        args.extend_from_slice(extra);
        args.push("Cargo.toml");
        Cli::try_parse_from(args)
    };

    assert!(parse(&["--group", "g"]).is_err(), "--group needs --config");
    assert!(
        parse(&["--group", "g", "--config", "deps.toml", "--security-only"]).is_err(),
        "--group conflicts with --security-only"
    );
    assert!(parse(&["--group", "g", "--config", "deps.toml"]).is_ok());
    assert!(
        parse(&["--group", "Not Valid", "--config", "deps.toml"]).is_err(),
        "an invalid group name is rejected at parse time"
    );
}

// --- FR-019: update_exit_code keeps its pre-change table ---

#[test]
fn test_update_exit_code_every_outcome_variant_keeps_its_pre_change_code() {
    let target = || ConcreteVersion::from("2.0.0");
    #[rustfmt::skip]
    let rows: Vec<(&str, Outcome, i32)> = vec![
        ("applied",                applied("2.0.0"),                                         EXIT_CLEAN),
        ("applied-via-lockfile",   Outcome::AppliedViaLockfile { target: target() },         EXIT_CLEAN),
        ("requires-lockfile",      Outcome::RequiresLockfileUpdate { target: target() },     EXIT_POLICY_VIOLATION),
        ("unfixable-no-fix",       Outcome::Unfixable(UnfixableReason::NoVerifiedFix),       EXIT_POLICY_VIOLATION),
        ("unfixable-fetch",        Outcome::Unfixable(UnfixableReason::FetchFailedOrAbsent), EXIT_POLICY_VIOLATION),
        ("unfixable-yanked",       Outcome::Unfixable(UnfixableReason::Yanked { target: target() }), EXIT_POLICY_VIOLATION),
        ("unfixable-shape",        Outcome::Unfixable(UnfixableReason::UnsupportedRequirementShape { target: target() }), EXIT_POLICY_VIOLATION),
        ("unfixable-oversized",    Outcome::Unfixable(UnfixableReason::OversizedRequirement { target: target() }), EXIT_POLICY_VIOLATION),
        ("unfixable-no-tag",       Outcome::Unfixable(UnfixableReason::NoReleaseTagForFix { target: target() }), EXIT_POLICY_VIOLATION),
        ("skip-ignore-rule",       skipped(SkipReason::IgnoreRule),                          EXIT_CLEAN),
        ("skip-not-requested",     skipped(SkipReason::NotRequested),                        EXIT_CLEAN),
        ("skip-overlaps",          skipped(SkipReason::OverlapsAnotherEdit),                 EXIT_CLEAN),
        ("skip-freshness",         skipped(SkipReason::WithinFreshnessCooldown),             EXIT_CLEAN),
        ("skip-native-cooldown",   skipped(SkipReason::WithinNativeCooldown),                EXIT_CLEAN),
        ("skip-not-safely-editable", skipped(SkipReason::NotSafelyEditable(UnplannableReason::UnsafeLatestVersion)), EXIT_POLICY_VIOLATION),
    ];
    for (label, outcome, expected) in rows {
        let run = run_of(vec![item("dep", "1.0.0", outcome)], clean_lockfile());
        assert_eq!(update_exit_code(&run), expected, "{label}");
    }
}

#[test]
fn test_update_exit_code_failed_lockfile_is_an_execution_error_even_with_clean_items() {
    let run = run_of(
        vec![item("dep", "1.0.0", applied("2.0.0"))],
        LockfileOutcome::Failed(RegenerationError::TimedOut {
            after: std::time::Duration::from_secs(1),
        }),
    );

    assert_eq!(update_exit_code(&run), EXIT_EXECUTION_ERROR);
}

#[test]
fn test_update_exit_code_not_in_group_skip_is_clean_alone_and_beside_applied() {
    let demoted = || {
        item(
            "dep",
            "1.0.0",
            Outcome::Skipped {
                reason: SkipReason::NotInGroup,
                target: Some(ConcreteVersion::from("2.0.0")),
            },
        )
    };

    let alone = run_of(vec![demoted()], clean_lockfile());
    let beside_applied = run_of(
        vec![item("other", "1.0.0", applied("1.1.0")), demoted()],
        clean_lockfile(),
    );
    let beside_unfixable = run_of(
        vec![
            demoted(),
            item(
                "bad",
                "1.0.0",
                Outcome::Unfixable(UnfixableReason::NoVerifiedFix),
            ),
        ],
        clean_lockfile(),
    );

    assert_eq!(update_exit_code(&alone), EXIT_CLEAN);
    assert_eq!(update_exit_code(&beside_applied), EXIT_CLEAN);
    assert_eq!(update_exit_code(&beside_unfixable), EXIT_POLICY_VIOLATION);
}
