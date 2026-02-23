//! Parser for gradle.properties files.
//!
//! Provides key-value parsing and directory-walking lookup.

use std::collections::HashMap;
use std::path::Path;

/// Parses a gradle.properties content into key-value pairs.
///
/// Lines starting with `#` or empty lines are ignored.
/// Each line is split on the first `=`.
pub fn parse_properties(content: &str) -> HashMap<String, String> {
    content
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Finds and parses gradle.properties files by walking up from `start_dir`.
///
/// Merges properties from all levels, with child values overriding parent values.
pub fn load_gradle_properties(start_dir: &Path) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut chain = Vec::new();
    let mut dir = Some(start_dir);

    while let Some(d) = dir {
        let props_file = d.join("gradle.properties");
        if props_file.exists() {
            chain.push(props_file);
        }
        dir = d.parent();
    }

    // Apply from root to leaf so child values override parent
    for path in chain.into_iter().rev() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            result.extend(parse_properties(&content));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let content = "kotlinVersion=2.1.10\nspringVersion=3.2.0\n";
        let props = parse_properties(content);
        assert_eq!(
            props.get("kotlinVersion").map(|s| s.as_str()),
            Some("2.1.10")
        );
        assert_eq!(
            props.get("springVersion").map(|s| s.as_str()),
            Some("3.2.0")
        );
    }

    #[test]
    fn test_parse_ignores_comments() {
        let content = "# this is a comment\nkey=value\n";
        let props = parse_properties(content);
        assert_eq!(props.len(), 1);
        assert_eq!(props.get("key").map(|s| s.as_str()), Some("value"));
    }

    #[test]
    fn test_parse_ignores_empty_lines() {
        let content = "\nkey=value\n\n";
        let props = parse_properties(content);
        assert_eq!(props.len(), 1);
    }

    #[test]
    fn test_parse_trims_whitespace() {
        let content = "  key  =  value  \n";
        let props = parse_properties(content);
        assert_eq!(props.get("key").map(|s| s.as_str()), Some("value"));
    }

    #[test]
    fn test_parse_value_with_equals() {
        // Only splits on the first '='
        let content = "url=https://example.com?a=b\n";
        let props = parse_properties(content);
        assert_eq!(
            props.get("url").map(|s| s.as_str()),
            Some("https://example.com?a=b")
        );
    }

    #[test]
    fn test_parse_empty() {
        let props = parse_properties("");
        assert!(props.is_empty());
    }
}
