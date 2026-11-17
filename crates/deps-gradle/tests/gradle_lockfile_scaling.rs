//! Regression: `gradle.lockfile` parsing must stay linear when one coordinate carries many
//! distinct versions (quadratic dedupe took tens of seconds at 160k lines).

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use deps_gradle::lockfile::parse_gradle_lockfile;

const DISTINCT_VERSIONS: usize = 100_000;

#[test]
fn many_distinct_versions_of_one_coordinate_parse_in_linear_time() {
    let mut content = String::new();
    for i in 0..DISTINCT_VERSIONS {
        writeln!(content, "org.example:lib:1.0.{i}=compileClasspath").unwrap();
    }
    // Repeats must still collapse to one candidate per distinct version.
    for i in 0..DISTINCT_VERSIONS {
        writeln!(content, "org.example:lib:1.0.{i}=runtimeClasspath").unwrap();
    }

    let started = Instant::now();
    let packages = parse_gradle_lockfile(&content);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(30),
        "parsing {DISTINCT_VERSIONS} distinct versions took {elapsed:?}"
    );
    let all = packages.all("org.example:lib").expect("coordinate present");
    assert_eq!(all.len(), DISTINCT_VERSIONS);
}
