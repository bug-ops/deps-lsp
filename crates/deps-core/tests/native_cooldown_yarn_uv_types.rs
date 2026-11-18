//! #2051 / #2052 acceptance (track B): `parse_yarn_duration`, the Yarn and uv-index window
//! sources with their `Display`, and the `NpmScopeLabel` / `UvIndexLabel` validators.
//!
//! Written tests-first against plan revision 3 (`.local/handoff/2026-11-18T00-57-21-architect.md`);
//! the API they name does not exist yet.

#![allow(clippy::expect_used, clippy::panic)]

use deps_core::native_cooldown::{
    GateOrigin, NativeCooldown, NativeCooldownSource, NativeLimit, NpmScopeLabel, TimeSpanError,
    TimeSpanValue, UvIndexLabel, parse_yarn_duration,
};

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;

/// The `Display` of a Yarn window parsed from `raw`, or the parse error.
fn rendered(raw: &str) -> Result<Option<String>, TimeSpanError> {
    parse_yarn_duration(raw).map(|value| match value {
        TimeSpanValue::Disabled => None,
        TimeSpanValue::Span(span) => Some(
            NativeCooldown::new(
                NativeLimit::MinAge(span),
                NativeCooldownSource::YarnNpmMinimalAgeGate,
            )
            .to_string(),
        ),
    })
}

/// Asserts `raw` parses to a window of exactly `secs` seconds.
fn assert_secs(raw: &str, secs: u64) {
    let Ok(TimeSpanValue::Span(span)) = parse_yarn_duration(raw) else {
        panic!("{raw:?} must parse to a span");
    };
    let window = NativeCooldown::new(
        NativeLimit::MinAge(span),
        NativeCooldownSource::YarnNpmMinimalAgeGate,
    )
    .age_window()
    .expect("a span limit has an age window");
    assert!(
        window.contains(secs - 1),
        "{raw:?} must contain {}",
        secs - 1
    );
    assert!(!window.contains(secs), "{raw:?} must not contain {secs}");
}

#[test]
fn parse_yarn_duration_unitless_is_minutes() {
    assert_secs("1", MINUTE);
    assert_secs("10080", WEEK);
    assert_eq!(
        rendered("10080").expect("parses"),
        Some("yarn npmMinimalAgeGate = 10080 minutes".to_string())
    );
}

#[test]
fn parse_yarn_duration_integer_units_keep_their_unit_in_display() {
    for (raw, secs, shown) in [
        ("30s", 30, "30 seconds"),
        ("1m", MINUTE, "1 minute"),
        ("36h", 36 * HOUR, "36 hours"),
        ("1d", DAY, "1 day"),
        ("7d", WEEK, "7 days"),
        ("2w", 2 * WEEK, "2 weeks"),
    ] {
        assert_secs(raw, secs);
        assert_eq!(
            rendered(raw).expect("parses"),
            Some(format!("yarn npmMinimalAgeGate = {shown}")),
            "{raw}"
        );
    }
}

#[test]
fn parse_yarn_duration_fraction_and_ms_ceil_to_seconds_with_the_largest_dividing_unit() {
    for (raw, secs, shown) in [
        ("0.5d", 12 * HOUR, "12 hours"),
        ("1.5h", 90 * MINUTE, "90 minutes"),
        ("0.5", 30, "30 seconds"),
        (".5d", 12 * HOUR, "12 hours"),
        ("500ms", 1, "1 second"),
        ("1500ms", 2, "2 seconds"),
        ("1000ms", 1, "1 second"),
        ("90000ms", 90, "90 seconds"),
    ] {
        assert_secs(raw, secs);
        assert_eq!(
            rendered(raw).expect("parses"),
            Some(format!("yarn npmMinimalAgeGate = {shown}")),
            "{raw}"
        );
    }
}

#[test]
fn parse_yarn_duration_zero_in_any_spelling_is_disabled() {
    for raw in ["0", "0d", "0ms", "0.0", "0w", ".0"] {
        assert_eq!(
            parse_yarn_duration(raw),
            Ok(TimeSpanValue::Disabled),
            "{raw:?}"
        );
    }
}

#[test]
fn parse_yarn_duration_rejects_everything_outside_the_grammar() {
    for raw in [
        "", "d", "${AGE}", "-1d", "+1d", "1y", "1 d", " 1d", "1d ", "1.", "1.5.5d", "1e3", "1D",
        "1day", "P1D", "ms", "1mo",
    ] {
        assert_eq!(
            parse_yarn_duration(raw),
            Err(TimeSpanError::Malformed),
            "{raw:?}"
        );
    }
}

#[test]
fn parse_yarn_duration_reports_overflow_past_u64_seconds() {
    assert_eq!(
        parse_yarn_duration("99999999999999999999d"),
        Err(TimeSpanError::Overflow)
    );
    assert_eq!(
        parse_yarn_duration("18446744073709551615w"),
        Err(TimeSpanError::Overflow)
    );
}

#[test]
fn native_cooldown_display_yarn_global_scope_and_manager_default_sources() {
    let Ok(TimeSpanValue::Span(week)) = parse_yarn_duration("7d") else {
        panic!("7d parses");
    };
    let Ok(TimeSpanValue::Span(day)) = parse_yarn_duration("1d") else {
        panic!("1d parses");
    };
    let scope = NpmScopeLabel::new("myorg").expect("valid scope");

    let global = NativeCooldown::new(
        NativeLimit::MinAge(week),
        NativeCooldownSource::YarnNpmMinimalAgeGate,
    );
    let configured = NativeCooldown::new(
        NativeLimit::MinAge(week),
        NativeCooldownSource::YarnScopeNpmMinimalAgeGate {
            scope: scope.clone(),
            origin: GateOrigin::Configured,
        },
    );
    let default = NativeCooldown::new(
        NativeLimit::MinAge(day),
        NativeCooldownSource::YarnScopeNpmMinimalAgeGate {
            scope,
            origin: GateOrigin::ManagerDefault,
        },
    );

    assert_eq!(global.to_string(), "yarn npmMinimalAgeGate = 7 days");
    assert_eq!(
        configured.to_string(),
        "yarn npmScopes.myorg.npmMinimalAgeGate = 7 days"
    );
    assert_eq!(
        default.to_string(),
        "yarn npmScopes.myorg.npmMinimalAgeGate = 1 day (Yarn default)"
    );
}

#[test]
fn native_cooldown_display_uv_index_source() {
    let Ok(TimeSpanValue::Span(week)) = deps_core::native_cooldown::parse_uv_span("7 days") else {
        panic!("7 days parses");
    };
    let cooldown = NativeCooldown::new(
        NativeLimit::MinAge(week),
        NativeCooldownSource::UvIndexExcludeNewer {
            index: UvIndexLabel::new("internal").expect("valid index name"),
        },
    );
    assert_eq!(
        cooldown.to_string(),
        "uv index.internal.exclude-newer = 7 days"
    );
}

#[test]
fn npm_scope_label_new_accepts_scope_keys_without_the_at_sign() {
    for scope in ["myorg", "my-org", "my_org", "my.org", "My0rg"] {
        assert!(NpmScopeLabel::new(scope).is_some(), "{scope:?}");
    }
}

#[test]
fn npm_scope_label_new_rejects_empty_unsafe_and_oversized_values() {
    let long = "a".repeat(1000);
    for scope in [
        "", "@myorg", "my/org", "my org", "my\norg", "my\0org", &long,
    ] {
        assert!(NpmScopeLabel::new(scope).is_none(), "{scope:?}");
    }
}

#[test]
fn uv_index_label_new_accepts_and_rejects_like_a_pypi_package_label() {
    for name in ["internal", "my-index", "my_index", "my.index", "Index1"] {
        assert!(UvIndexLabel::new(name).is_some(), "{name:?}");
    }
    let long = "a".repeat(129);
    for name in ["", "my index", "my/index", "my\nindex", "idx\u{e9}", &long] {
        assert!(UvIndexLabel::new(name).is_none(), "{name:?}");
    }
}
