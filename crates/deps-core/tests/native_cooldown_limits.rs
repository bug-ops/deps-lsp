//! #2041 / #2042 / spec 099 Phase 2-3 acceptance: the cutoff-capable native limit, the uv span
//! grammar, the npm/RFC 3339 cutoff parsers, the lock-independent `hold` predicate and the
//! per-source `Display` wording.
//!
//! Written tests-first against the plans `2026-11-17T18-35-26-architect` .. `20-32-28-architect`.
//! Assumed seams: `NativeCooldown::new(NativeLimit, NativeCooldownSource)`,
//! `NativeCutoff` and `PypiPackageLabel` living in `deps_core::native_cooldown`.

#![expect(clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

use deps_core::native_cooldown::{
    NativeCooldown, NativeCooldownSource, NativeCutoff, NativeHold, NativeLimit, NativeTimeSpan,
    PypiPackageLabel, TimeSpanError, TimeSpanValue, TimeUnit, parse_uv_span,
};
use deps_core::{ConcreteVersion, PublishTime};

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;
/// 2026-01-01T00:00:00Z.
const JAN_1_2026: i64 = 1_767_225_600;

fn t(secs: i64) -> PublishTime {
    PublishTime::from_unix_secs(secs)
}

fn cv(raw: &str) -> ConcreteVersion {
    ConcreteVersion::new(raw)
}

fn span_of(value: Result<TimeSpanValue, TimeSpanError>) -> NativeTimeSpan {
    match value.expect("must parse") {
        TimeSpanValue::Span(span) => span,
        TimeSpanValue::Disabled => panic!("expected a span, got Disabled"),
    }
}

fn min_age(count: u64, unit: TimeUnit, source: NativeCooldownSource) -> NativeCooldown {
    NativeCooldown::new(
        NativeLimit::MinAge(span_of(NativeTimeSpan::from_count(count, unit))),
        source,
    )
}

fn cutoff(raw: &str) -> NativeCutoff {
    NativeCutoff::parse_rfc3339(raw).expect("valid RFC 3339")
}

fn pinned_at_cutoff() -> NativeCooldown {
    NativeCooldown::new(
        NativeLimit::PublishedAfter(cutoff("2026-01-01T00:00:00Z")),
        NativeCooldownSource::UvExcludeNewer,
    )
}

#[test]
fn from_count_zero_is_disabled() {
    assert_eq!(
        NativeTimeSpan::from_count(0, TimeUnit::Day),
        Ok(TimeSpanValue::Disabled)
    );
}

#[test]
fn from_count_multiplication_overflow_is_overflow_error() {
    assert_eq!(
        NativeTimeSpan::from_count(u64::MAX, TimeUnit::Week),
        Err(TimeSpanError::Overflow)
    );
}

#[test]
fn from_count_display_pluralizes_the_configured_unit() {
    assert_eq!(
        span_of(NativeTimeSpan::from_count(1, TimeUnit::Minute)).to_string(),
        "1 minute"
    );
    assert_eq!(
        span_of(NativeTimeSpan::from_count(1440, TimeUnit::Minute)).to_string(),
        "1440 minutes"
    );
}

#[test]
fn parse_uv_span_accepts_friendly_units_in_every_documented_spelling() {
    for (raw, secs) in [
        ("30 seconds", 30),
        ("1 sec", 1),
        ("5 mins", 5 * MINUTE),
        ("1 minute", MINUTE),
        ("2 hours", 2 * HOUR),
        ("3 hrs", 3 * HOUR),
        ("1 day", DAY),
        ("7 days", 7 * DAY),
        ("1 week", WEEK),
        ("2 wks", 2 * WEEK),
        ("1week", WEEK),
    ] {
        let hold = min_age_hold(parse_uv_span(raw), secs);
        assert_eq!(hold, Some(NativeHold::For(1)), "{raw:?} must be {secs}s");
    }
}

/// Window of `value` judged against a version aged `secs - 1`: held for exactly 1 more second
/// only when the window is `secs` long; `None` otherwise.
fn min_age_hold(value: Result<TimeSpanValue, TimeSpanError>, secs: u64) -> Option<NativeHold> {
    let span = span_of(value);
    let cooldown = NativeCooldown::new(
        NativeLimit::MinAge(span),
        NativeCooldownSource::UvExcludeNewer,
    );
    let now = t(1_000_000_000);
    let published = t(1_000_000_000 - i64::try_from(secs - 1).expect("fits"));
    cooldown.hold(Some(published), &cv("1.0.0"), now)
}

#[test]
fn parse_uv_span_accepts_iso_durations_case_insensitively() {
    for (raw, secs) in [
        ("P1W", WEEK),
        ("p2d", 2 * DAY),
        ("PT3H", 3 * HOUR),
        ("pt30m", 30 * MINUTE),
        ("PT45S", 45),
    ] {
        assert_eq!(
            min_age_hold(parse_uv_span(raw), secs),
            Some(NativeHold::For(1)),
            "{raw:?} must be {secs}s"
        );
    }
}

#[test]
fn parse_uv_span_zero_is_disabled() {
    for raw in ["0 days", "0 seconds", "PT0S", "P0D"] {
        assert_eq!(parse_uv_span(raw), Ok(TimeSpanValue::Disabled), "{raw:?}");
    }
}

#[test]
fn parse_uv_span_rejects_calendar_multi_term_signs_fractions_and_padding() {
    for raw in [
        "",
        "1 month",
        "1 year",
        "P1M",
        "P1Y",
        "P1DT2H",
        "1 day 2 hours",
        "-1 days",
        "+1 days",
        "1.5 days",
        " 1 day",
        "1 day ",
        "2026-01-01",
        "yesterday",
    ] {
        assert_eq!(
            parse_uv_span(raw),
            Err(TimeSpanError::Malformed),
            "{raw:?} must be Malformed"
        );
    }
}

#[test]
fn parse_uv_span_count_overflow_is_overflow_error() {
    assert_eq!(
        parse_uv_span("18446744073709551615 weeks"),
        Err(TimeSpanError::Overflow)
    );
}

#[test]
fn cutoff_parse_rfc3339_accepts_zulu_and_offsets_and_normalizes_to_utc() {
    let zulu = cutoff("2026-01-01T00:00:00Z");
    let offset = cutoff("2026-01-01T02:00:00+02:00");
    assert_eq!(zulu, offset);
    assert_eq!(zulu.to_string(), "2026-01-01T00:00:00Z");
}

#[test]
fn cutoff_parse_rfc3339_rejects_date_only_and_garbage() {
    for raw in [
        "2026-01-01",
        "",
        "tomorrow",
        "2026-13-01T00:00:00Z",
        "1767225600",
    ] {
        assert!(NativeCutoff::parse_rfc3339(raw).is_none(), "{raw:?}");
    }
}

#[test]
fn cutoff_parse_npm_date_accepts_date_only_as_midnight_utc() {
    let date_only = NativeCutoff::parse_npm_date("2026-01-01").expect("date-only is valid for npm");
    assert_eq!(date_only, cutoff("2026-01-01T00:00:00Z"));
    assert!(NativeCutoff::parse_npm_date("2026-01-01T00:00:00Z").is_some());
    assert!(NativeCutoff::parse_npm_date("not a date").is_none());
}

#[test]
fn hold_min_age_inside_window_is_for_remaining_seconds() {
    let cooldown = min_age(7, TimeUnit::Day, NativeCooldownSource::UvExcludeNewer);
    let now = t(10_000_000);
    let published = t(10_000_000 - i64::try_from(DAY).expect("fits"));
    assert_eq!(
        cooldown.hold(Some(published), &cv("1.0.0"), now),
        Some(NativeHold::For(6 * DAY))
    );
}

#[test]
fn hold_min_age_at_exact_window_boundary_is_eligible() {
    let cooldown = min_age(7, TimeUnit::Day, NativeCooldownSource::UvExcludeNewer);
    let now = t(10_000_000);
    let published = t(10_000_000 - i64::try_from(7 * DAY).expect("fits"));
    assert_eq!(cooldown.hold(Some(published), &cv("1.0.0"), now), None);
}

#[test]
fn hold_without_publish_time_is_eligible_for_both_limits() {
    let now = t(JAN_1_2026 + 1000);
    assert_eq!(
        min_age(7, TimeUnit::Day, NativeCooldownSource::UvExcludeNewer).hold(
            None,
            &cv("1.0.0"),
            now
        ),
        None
    );
    assert_eq!(pinned_at_cutoff().hold(None, &cv("1.0.0"), now), None);
}

#[test]
fn hold_cutoff_newer_than_cutoff_is_indefinite() {
    assert_eq!(
        pinned_at_cutoff().hold(Some(t(JAN_1_2026 + 1)), &cv("1.0.0"), t(JAN_1_2026 + 10)),
        Some(NativeHold::Indefinite)
    );
}

#[test]
fn hold_cutoff_exactly_at_cutoff_is_eligible() {
    assert_eq!(
        pinned_at_cutoff().hold(Some(t(JAN_1_2026)), &cv("1.0.0"), t(JAN_1_2026 + 10)),
        None
    );
}

#[test]
fn hold_cutoff_older_than_cutoff_is_eligible() {
    assert_eq!(
        pinned_at_cutoff().hold(Some(t(JAN_1_2026 - 1)), &cv("1.0.0"), t(JAN_1_2026 + 10)),
        None
    );
}

#[test]
fn hold_cutoff_far_in_the_future_never_becomes_eligible_by_time() {
    let far_future = t(JAN_1_2026 + 50 * 365 * i64::try_from(DAY).expect("fits"));
    assert_eq!(
        pinned_at_cutoff().hold(Some(far_future), &cv("1.0.0"), far_future),
        Some(NativeHold::Indefinite)
    );
}

#[test]
fn native_hold_is_matched_exhaustively_without_wildcard() {
    fn label(hold: &NativeHold) -> &'static str {
        match hold {
            NativeHold::For(_) => "for",
            NativeHold::Indefinite => "indefinite",
        }
    }
    assert_eq!(label(&NativeHold::For(3)), "for");
    assert_eq!(label(&NativeHold::Indefinite), "indefinite");
}

#[test]
fn native_limit_is_matched_exhaustively_without_wildcard() {
    fn label(limit: &NativeLimit) -> &'static str {
        match limit {
            NativeLimit::MinAge(_) => "age",
            NativeLimit::PublishedAfter(_) => "cutoff",
        }
    }
    assert_eq!(label(pinned_at_cutoff().limit()), "cutoff");
}

#[test]
fn display_names_every_new_source_and_its_setting() {
    let cases = [
        (
            NativeCooldownSource::NpmMinReleaseAge,
            "min-release-age",
            true,
        ),
        (
            NativeCooldownSource::PnpmMinimumReleaseAge,
            "minimumReleaseAge",
            true,
        ),
        (
            NativeCooldownSource::BunMinimumReleaseAge,
            "minimumReleaseAge",
            true,
        ),
        (NativeCooldownSource::UvExcludeNewer, "exclude-newer", true),
    ];
    for (source, key, has_span) in cases {
        let text = min_age(3, TimeUnit::Day, source).to_string();
        assert!(text.contains(key), "{text:?} must name {key}");
        assert_eq!(text.contains("3 days"), has_span, "{text:?}");
    }
}

#[test]
fn display_npm_before_quotes_the_cutoff_not_a_span() {
    let cooldown = NativeCooldown::new(
        NativeLimit::PublishedAfter(cutoff("2026-01-01T00:00:00Z")),
        NativeCooldownSource::NpmBefore,
    );
    let text = cooldown.to_string();
    assert!(text.contains("before"), "{text:?}");
    assert!(text.contains("2026-01-01T00:00:00Z"), "{text:?}");
}

#[test]
fn display_uv_exclude_newer_package_names_the_package() {
    let package = PypiPackageLabel::new("requests").expect("valid PEP 508 name");
    let source = NativeCooldownSource::UvExcludeNewerPackage { package };
    let text = min_age(3, TimeUnit::Day, source).to_string();
    assert!(text.contains("exclude-newer-package"), "{text:?}");
    assert!(text.contains("requests"), "{text:?}");
}

#[test]
fn pypi_package_label_rejects_names_unsafe_to_quote() {
    for raw in ["", "bad name", "back`tick", "new\nline", "a/b", "<script>"] {
        assert!(PypiPackageLabel::new(raw).is_none(), "{raw:?}");
    }
    assert!(PypiPackageLabel::new("zope.interface").is_some());
    assert!(PypiPackageLabel::new("my-pkg_2").is_some());
}
