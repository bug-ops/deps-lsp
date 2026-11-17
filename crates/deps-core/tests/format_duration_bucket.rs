//! #1982: `format_duration_bucket` (the "eligible in ..." span) and its byte-identity with the
//! pre-existing `format_relative_age` bucketing it was extracted from.

use deps_core::{format_duration_bucket, format_relative_age};

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;
const MONTH: u64 = 30 * DAY;
const YEAR: u64 = 365 * DAY;

/// `(seconds, bucket text)` around every unit boundary.
const BUCKETS: [(u64, &str); 24] = [
    (MINUTE, "1 minute"),
    (2 * MINUTE, "2 minutes"),
    (HOUR - 1, "59 minutes"),
    (HOUR, "1 hour"),
    (2 * HOUR, "2 hours"),
    (DAY - 1, "23 hours"),
    (DAY, "1 day"),
    (2 * DAY, "2 days"),
    (3 * DAY + 60, "3 days"),
    (WEEK - 1, "6 days"),
    (WEEK, "1 week"),
    (2 * WEEK, "2 weeks"),
    (MONTH - 1, "4 weeks"),
    (MONTH, "1 month"),
    (2 * MONTH, "2 months"),
    (YEAR - 1, "12 months"),
    (YEAR, "1 year"),
    (2 * YEAR, "2 years"),
    (10 * YEAR, "10 years"),
    (59 * MINUTE + 59, "59 minutes"),
    (89 * MINUTE, "1 hour"),
    (2 * HOUR - 1, "1 hour"),
    (WEEK + DAY, "1 week"),
    (MONTH + WEEK, "1 month"),
];

#[test]
fn format_duration_bucket_names_the_largest_whole_unit() {
    for (secs, expected) in BUCKETS {
        assert_eq!(format_duration_bucket(secs), expected, "{secs}s");
    }
}

#[test]
fn format_duration_bucket_below_one_minute_is_less_than_a_minute() {
    for secs in [0, 1, 30, MINUTE - 1] {
        assert_eq!(
            format_duration_bucket(secs),
            "less than a minute",
            "{secs}s"
        );
    }
}

#[test]
fn format_duration_bucket_pluralizes_only_above_one() {
    assert_eq!(format_duration_bucket(DAY), "1 day");
    assert_eq!(format_duration_bucket(2 * DAY), "2 days");
    assert_eq!(format_duration_bucket(300), "5 minutes");
}

/// Byte-identity after the extraction: every age renders as `"<bucket> ago"` (or `"just now"`).
#[test]
fn format_relative_age_equals_the_bucket_with_ago_for_every_boundary() {
    for (secs, _) in BUCKETS {
        assert_eq!(
            format_relative_age(secs),
            format!("{} ago", format_duration_bucket(secs)),
            "{secs}s"
        );
    }
    for secs in [0, 1, MINUTE - 1] {
        assert_eq!(format_relative_age(secs), "just now", "{secs}s");
    }
}

#[test]
fn format_relative_age_keeps_its_documented_output() {
    for (secs, expected) in [
        (0, "just now"),
        (59, "just now"),
        (60, "1 minute ago"),
        (300, "5 minutes ago"),
        (3600, "1 hour ago"),
        (86_400, "1 day ago"),
        (604_800, "1 week ago"),
        (2_592_000, "1 month ago"),
        (31_536_000, "1 year ago"),
    ] {
        assert_eq!(format_relative_age(secs), expected, "{secs}s");
    }
}
