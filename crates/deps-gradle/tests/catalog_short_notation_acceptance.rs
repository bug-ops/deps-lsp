//! #2162: a version-catalog library given in short notation (`alias = "group:artifact[:version]"`)
//! is a dependency, with ranges that edit only the coordinate and the version segment.

#![expect(clippy::unwrap_used, reason = "test code")]

use deps_core::position::{Position, Range};
use deps_gradle::{GradleDependency, parse_gradle};

fn parse(content: &str) -> Vec<GradleDependency> {
    let uri = deps_core::test_util::test_uri("/project/gradle/libs.versions.toml");
    parse_gradle(content, &uri).unwrap().dependencies
}

fn byte_offset(content: &str, position: Position) -> usize {
    let line_start: usize = content
        .split_inclusive('\n')
        .take(position.line as usize)
        .map(str::len)
        .sum();
    let line = content
        .split_inclusive('\n')
        .nth(position.line as usize)
        .unwrap();
    let mut units = 0;
    for (offset, ch) in line.char_indices() {
        if units == position.character {
            return line_start + offset;
        }
        units += u32::try_from(ch.len_utf16()).unwrap();
    }
    assert_eq!(units, position.character, "position past the end of line");
    line_start + line.len()
}

fn slice(content: &str, range: Range) -> &str {
    content
        .get(byte_offset(content, range.start)..byte_offset(content, range.end))
        .unwrap()
}

fn catalog(libraries: &str) -> String {
    format!("[versions]\nx = \"1\"\n\n[libraries]\n{libraries}\n")
}

#[test]
fn short_notation_with_version_is_a_dependency_with_exact_ranges() {
    let content = catalog("log4j-core = \"org.apache.logging.log4j:log4j-core:2.14.1\"");
    let deps = parse(&content);

    assert_eq!(deps.len(), 1);
    let dep = &deps[0];
    assert_eq!(dep.name, "org.apache.logging.log4j:log4j-core");
    assert_eq!(dep.group_id, "org.apache.logging.log4j");
    assert_eq!(dep.artifact_id, "log4j-core");
    assert_eq!(dep.version_req.as_ref().unwrap().as_str(), "2.14.1");
    assert_eq!(dep.configuration, "");
    assert_eq!(
        slice(&content, dep.name_range),
        "org.apache.logging.log4j:log4j-core"
    );
    assert_eq!(slice(&content, dep.version_range.unwrap()), "2.14.1");
}

#[test]
fn short_notation_without_version_has_no_version_fields() {
    let content = catalog("junit = \"junit:junit\"");
    let deps = parse(&content);

    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "junit:junit");
    assert!(deps[0].version_req.is_none());
    assert!(deps[0].version_range.is_none());
    assert_eq!(slice(&content, deps[0].name_range), "junit:junit");
}

#[test]
fn short_notation_mixes_with_table_entries_and_literal_strings() {
    let content = catalog(
        "guava = { module = \"com.google.guava:guava\", version = \"33.0.0-jre\" }\n\
         log4j-core = \"org.apache.logging.log4j:log4j-core:2.14.1\"\n\
         commons = 'org.apache.commons:commons-lang3:3.14.0'\n\
         commons-io = { group = \"commons-io\", name = \"commons-io\", version = \"2.15.0\" }",
    );
    let deps = parse(&content);

    let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
    assert_eq!(deps.len(), 4, "{names:?}");
    for expected in [
        "com.google.guava:guava",
        "org.apache.logging.log4j:log4j-core",
        "org.apache.commons:commons-lang3",
        "commons-io:commons-io",
    ] {
        assert!(names.contains(&expected), "{expected} missing in {names:?}");
    }
    let literal = deps
        .iter()
        .find(|dep| dep.name == "org.apache.commons:commons-lang3")
        .unwrap();
    assert_eq!(slice(&content, literal.version_range.unwrap()), "3.14.0");
    assert_eq!(
        slice(&content, literal.name_range),
        "org.apache.commons:commons-lang3"
    );
}

#[test]
fn malformed_short_notation_is_skipped_without_panicking() {
    for value in ["a", "a:b:c:d", ":b:1", "a::1", "a:b:", "", ":", "::"] {
        let content = catalog(&format!("bad = \"{value}\""));
        assert!(parse(&content).is_empty(), "{value:?} must yield no dep");
    }
}

#[test]
fn short_notation_with_an_escape_reports_the_whole_value_and_no_version_range() {
    let content = catalog("lib = \"org.example:l\\u0069b:1.0\"");
    let deps = parse(&content);

    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "org.example:lib");
    assert_eq!(deps[0].version_req.as_ref().unwrap().as_str(), "1.0");
    assert!(deps[0].version_range.is_none());
    assert_eq!(
        slice(&content, deps[0].name_range),
        "org.example:l\\u0069b:1.0"
    );
}

#[test]
fn short_notation_with_a_multibyte_group_keeps_utf16_ranges() {
    let content = catalog("lib = \"org.\u{1F600}x:art:1.0\"");
    let deps = parse(&content);

    assert_eq!(deps.len(), 1);
    assert_eq!(slice(&content, deps[0].name_range), "org.\u{1F600}x:art");
    assert_eq!(slice(&content, deps[0].version_range.unwrap()), "1.0");
    let name_range = deps[0].name_range;
    assert_eq!(
        name_range.end.character - name_range.start.character,
        u32::try_from("org.\u{1F600}x:art".encode_utf16().count()).unwrap()
    );
}
