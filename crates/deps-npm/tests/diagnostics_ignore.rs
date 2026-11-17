//! `diagnostics.ignore` (#1967, spec 094 FR-010 as amended): the typed config surface and how
//! it resolves per package. Exercised through npm's real name normalization.

#![allow(clippy::unwrap_used)]

use deps_core::lsp_helpers::{PackageSuppression, SuppressionKind};
use deps_core::policy_config::DiagnosticsConfig;
use deps_core::{PackageKey, PackageName};
use deps_npm::NpmFormatter;
use serde_json::json;
use std::assert_matches;

fn config(value: serde_json::Value) -> DiagnosticsConfig {
    serde_json::from_value(value).unwrap()
}

fn resolve(config: &DiagnosticsConfig, name: &str) -> PackageSuppression {
    let key = PackageKey::new(&PackageName::new(name), &NpmFormatter);
    config
        .effective_suppression()
        .resolve(&NpmFormatter)
        .for_package(key.normalized())
}

#[test]
fn effective_suppression_is_empty_by_default() {
    assert!(
        DiagnosticsConfig::default()
            .effective_suppression()
            .is_empty()
    );
}

#[test]
fn effective_suppression_with_only_ignore_is_not_empty() {
    let cfg = config(json!({"ignore": ["request"]}));
    assert!(!cfg.effective_suppression().is_empty());
}

#[test]
fn for_package_exact_ignore_is_ignored() {
    let cfg = config(json!({"ignore": ["request"]}));
    assert_matches!(resolve(&cfg, "request"), PackageSuppression::Ignored);
}

#[test]
fn for_package_glob_ignore_matches_scoped_family_only() {
    let cfg = config(json!({"ignore": ["@types/*"]}));
    assert_matches!(resolve(&cfg, "@types/node"), PackageSuppression::Ignored);
    assert_matches!(resolve(&cfg, "@types/react"), PackageSuppression::Ignored);
    assert_matches!(resolve(&cfg, "types-extra"), PackageSuppression::Kinds(k) if k.is_empty());
}

#[test]
fn for_package_unlisted_package_has_no_suppressed_kinds() {
    let cfg = config(json!({"ignore": ["request"]}));
    assert_matches!(resolve(&cfg, "left-pad"), PackageSuppression::Kinds(k) if k.is_empty());
}

#[test]
fn for_package_suppress_rule_yields_its_kinds() {
    let cfg =
        config(json!({"suppress": [{"package": "left-pad", "kinds": ["outdated", "yanked"]}]}));
    match resolve(&cfg, "left-pad") {
        PackageSuppression::Kinds(kinds) => {
            assert!(kinds.contains(SuppressionKind::Outdated));
            assert!(kinds.contains(SuppressionKind::Yanked));
            assert!(!kinds.contains(SuppressionKind::Deprecated));
            assert!(!kinds.contains(SuppressionKind::License));
        }
        PackageSuppression::Ignored => panic!("a suppress rule is not a whole-package ignore"),
    }
}

#[test]
fn for_package_ignore_wins_over_a_suppress_rule_for_the_same_package() {
    let cfg = config(json!({
        "ignore": ["left-pad"],
        "suppress": [{"package": "left-pad", "kinds": ["outdated"]}],
    }));
    assert_matches!(resolve(&cfg, "left-pad"), PackageSuppression::Ignored);
}

#[test]
fn ignore_rejects_a_bare_wildcard() {
    assert!(serde_json::from_value::<DiagnosticsConfig>(json!({"ignore": ["*"]})).is_err());
}

#[test]
fn ignore_rejects_an_empty_pattern() {
    assert!(serde_json::from_value::<DiagnosticsConfig>(json!({"ignore": [""]})).is_err());
}

#[test]
fn ignore_rejects_a_wildcard_in_the_middle() {
    assert!(serde_json::from_value::<DiagnosticsConfig>(json!({"ignore": ["a*b"]})).is_err());
}

#[test]
fn ignore_rejects_non_string_entries() {
    assert!(serde_json::from_value::<DiagnosticsConfig>(json!({"ignore": [1]})).is_err());
}
