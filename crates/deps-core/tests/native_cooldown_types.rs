//! #1982 / spec 099 Phase 1 acceptance: the typed native-window value, the shared duration
//! grammar (`parse_time_span`, Cargo's table) and the window-independent publish times a
//! `PackageVersions` carries so the read-time gate can judge cached data.
//!
//! Written tests-first against plan v4 (`.local/handoff/2026-11-17T13-20-11-architect.md`); the
//! API they name does not exist yet.

#![expect(clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

use std::sync::Arc;

use deps_core::native_cooldown::{
    NativeCooldown, NativeCooldownSource, NativeLimit, NativeWindow, TimeSpanError, TimeSpanValue,
    parse_time_span,
};
use deps_core::{ConcreteVersion, PackageVersions, PublishTime};

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;
const MONTH: u64 = 2_629_746;
const MAX_SECS: u64 = 10 * 365 * DAY;

/// The window a raw value parses to, as `NativeWindow`; `None` for `Disabled`.
fn window_of(raw: &str) -> Option<NativeWindow> {
    match parse_time_span(raw).unwrap_or_else(|e| panic!("{raw:?} must parse, got {e:?}")) {
        TimeSpanValue::Disabled => None,
        TimeSpanValue::Span(span) => Some(
            NativeCooldown::new(NativeLimit::MinAge(span), NativeCooldownSource::CargoGlobal)
                .age_window()
                .expect("a span limit has an age window"),
        ),
    }
}

/// Asserts `raw` parses to exactly `secs` (the window contains `secs - 1` but not `secs`).
fn assert_secs(raw: &str, secs: u64) {
    let window = window_of(raw).unwrap_or_else(|| panic!("{raw:?} must not be Disabled"));
    assert!(
        window.contains(secs - 1),
        "{raw:?} must contain {}",
        secs - 1
    );
    assert!(!window.contains(secs), "{raw:?} must not contain {secs}");
}

#[test]
fn parse_time_span_accepts_cargo_grammar_with_documented_unit_factors() {
    for (raw, secs) in [
        ("1second", 1),
        ("30 seconds", 30),
        ("1 minute", MINUTE),
        ("90 minutes", 90 * MINUTE),
        ("1 hour", HOUR),
        ("12 hours", 12 * HOUR),
        ("1 day", DAY),
        ("7 days", 7 * DAY),
        ("1 week", WEEK),
        ("2 weeks", 2 * WEEK),
        ("1 month", MONTH),
        ("3 months", 3 * MONTH),
    ] {
        assert_secs(raw, secs);
    }
}

#[test]
fn parse_time_span_rejects_everything_outside_the_grammar_as_malformed() {
    for raw in [
        "",
        "1",
        "day",
        "+2 seconds",
        "-1 days",
        "1.5 days",
        "1 dayz",
        " 1 day",
        "1 day ",
        "1  second",
    ] {
        assert_eq!(
            parse_time_span(raw),
            Err(TimeSpanError::Malformed),
            "{raw:?} must be Malformed"
        );
    }
}

#[test]
fn parse_time_span_zero_in_any_spelling_is_disabled() {
    for raw in ["0", "0 days", "0 seconds"] {
        assert_eq!(parse_time_span(raw), Ok(TimeSpanValue::Disabled), "{raw:?}");
    }
}

#[test]
fn parse_time_span_count_overflowing_u64_seconds_is_overflow_error() {
    assert_eq!(
        parse_time_span("99999999999999999999 weeks"),
        Err(TimeSpanError::Overflow)
    );
    assert_eq!(
        parse_time_span("18446744073709551615 months"),
        Err(TimeSpanError::Overflow)
    );
}

#[test]
fn native_window_value_above_maximum_is_clamped_to_ten_years() {
    let window = window_of("1000000000 months").expect("a huge span is a window, not Disabled");
    assert!(window.contains(MAX_SECS - 1));
    assert!(
        !window.contains(MAX_SECS),
        "must be clamped to 10 x 365 days"
    );
}

#[test]
fn native_window_just_below_maximum_is_not_clamped() {
    assert_secs("3649 days", 3649 * DAY);
}

#[test]
fn native_cooldown_display_names_the_setting_and_keeps_the_configured_text() {
    let TimeSpanValue::Span(span) = parse_time_span("7 days").expect("parses") else {
        panic!("7 days is a span");
    };
    let cooldown =
        NativeCooldown::new(NativeLimit::MinAge(span), NativeCooldownSource::CargoGlobal);
    assert_eq!(
        cooldown.to_string(),
        "cargo registry.global-min-publish-age = 7 days"
    );
}

#[test]
fn native_cooldown_display_of_clamped_window_keeps_configured_text() {
    let TimeSpanValue::Span(span) = parse_time_span("40000 days").expect("parses") else {
        panic!("40000 days is a span");
    };
    let cooldown =
        NativeCooldown::new(NativeLimit::MinAge(span), NativeCooldownSource::CargoGlobal);
    assert_eq!(
        cooldown.to_string(),
        "cargo registry.global-min-publish-age = 40000 days"
    );
}

/// Exhaustiveness is a compile-time property (no `_` arm, no `#[non_exhaustive]`).
#[test]
fn native_cooldown_source_is_matched_exhaustively_without_wildcard() {
    fn label(source: &NativeCooldownSource) -> &'static str {
        match source {
            NativeCooldownSource::CargoGlobal => "global",
            NativeCooldownSource::CargoRegistry { .. } => "registry",
            NativeCooldownSource::NpmMinReleaseAge => "npm-min-release-age",
            NativeCooldownSource::NpmBefore => "npm-before",
            NativeCooldownSource::PnpmMinimumReleaseAge => "pnpm",
            NativeCooldownSource::BunMinimumReleaseAge => "bun",
            NativeCooldownSource::UvExcludeNewer => "uv",
            NativeCooldownSource::UvExcludeNewerPackage { .. } => "uv-package",
            NativeCooldownSource::YarnNpmMinimalAgeGate => "yarn",
            NativeCooldownSource::YarnScopeNpmMinimalAgeGate { .. } => "yarn-scope",
            NativeCooldownSource::UvIndexExcludeNewer { .. } => "uv-index",
        }
    }
    assert_eq!(label(&NativeCooldownSource::CargoGlobal), "global");
}

fn t(secs: i64) -> PublishTime {
    PublishTime::from_unix_secs(secs)
}

fn cv(raw: &str) -> ConcreteVersion {
    ConcreteVersion::new(raw)
}

fn three_versions() -> PackageVersions {
    PackageVersions::new(
        cv("3.0.0"),
        Arc::from(vec![cv("3.0.0"), cv("2.0.0"), cv("1.0.0")]),
    )
}

#[test]
fn published_at_of_indexes_publish_times_by_position_in_available() {
    let versions =
        three_versions().with_publish_times(Arc::from(vec![Some(t(300)), None, Some(t(100))]));
    assert_eq!(versions.published_at_of(&cv("3.0.0")), Some(t(300)));
    assert_eq!(versions.published_at_of(&cv("2.0.0")), None);
    assert_eq!(versions.published_at_of(&cv("1.0.0")), Some(t(100)));
}

#[test]
fn published_at_of_unlisted_version_is_none() {
    let versions =
        three_versions().with_publish_times(Arc::from(vec![Some(t(3)), Some(t(2)), Some(t(1))]));
    assert_eq!(versions.published_at_of(&cv("9.9.9")), None);
}

#[test]
fn published_at_of_length_mismatch_falls_back_to_latest_published_at_only() {
    let versions = three_versions()
        .with_published_at(t(777))
        .with_publish_times(Arc::from(vec![Some(t(1))]));
    assert_eq!(versions.published_at_of(&cv("3.0.0")), Some(t(777)));
    assert_eq!(versions.published_at_of(&cv("2.0.0")), None);
}

#[test]
fn published_at_of_without_publish_times_uses_latest_published_at_for_latest() {
    let versions = three_versions().with_published_at(t(42));
    assert_eq!(versions.published_at_of(&cv("3.0.0")), Some(t(42)));
    assert_eq!(versions.published_at_of(&cv("1.0.0")), None);
}

#[test]
fn published_at_of_latest_without_list_never_panics() {
    let versions = PackageVersions::latest_without_list("1.0.195");
    assert_eq!(versions.published_at_of(&cv("1.0.195")), None);
}
