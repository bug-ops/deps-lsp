//! Parser for gradle.properties files.
//!
//! Provides key-value parsing and directory-walking lookup.

use deps_core::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH;
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
/// Merges properties from all levels, with child values overriding parent values. The walk
/// stops after [`MAX_CONFIG_ANCESTOR_DEPTH`] ancestors regardless of whether the filesystem
/// root has been reached, and each file is read through
/// [`deps_core::fs_probe::read_to_string_capped`] — bounded by
/// [`deps_core::MAX_CACHED_FILE_BYTES`], the same cap `deps-cargo`'s/`deps-npm`'s own
/// config-file ancestor walks use (a `gradle.properties` file is a small config file, not a
/// lock file, so it does not need `deps_core::lockfile::MAX_LOCKFILE_BYTES`'s larger cap) —
/// so an oversized or maliciously deep ancestor chain cannot force unbounded work (CWE-400).
pub fn load_gradle_properties(start_dir: &Path) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut chain = Vec::new();
    let mut dir = Some(start_dir);
    let mut depth = 0usize;

    while let Some(d) = dir {
        if depth >= MAX_CONFIG_ANCESTOR_DEPTH {
            break;
        }
        depth += 1;

        let props_file = d.join("gradle.properties");
        if deps_core::fs_probe::is_file(&props_file) {
            chain.push(props_file);
        }
        dir = d.parent();
    }

    // Apply from root to leaf so child values override parent
    for path in chain.into_iter().rev() {
        // Cheap `stat` pre-filter (mirrors `MtimeFileCache::get_or_parse`): skips opening an
        // obviously oversized file. The capped read below still enforces the bound on the
        // read itself regardless of what this reports, closing the TOCTOU gap (CWE-367) a
        // stat-only check alone would leave open.
        if let Ok(metadata) = deps_core::fs_probe::metadata(&path)
            && metadata.len() > deps_core::MAX_CACHED_FILE_BYTES
        {
            tracing::warn!(
                path = %path.display(),
                len = metadata.len(),
                cap = deps_core::MAX_CACHED_FILE_BYTES,
                "gradle.properties exceeds size cap; not reading"
            );
            continue;
        }

        match deps_core::fs_probe::read_to_string_capped(&path, deps_core::MAX_CACHED_FILE_BYTES) {
            Ok(Some(content)) => result.extend(parse_properties(&content)),
            Ok(None) => tracing::warn!(
                path = %path.display(),
                cap = deps_core::MAX_CACHED_FILE_BYTES,
                "gradle.properties exceeds size cap during read; not reading"
            ),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read gradle.properties");
            }
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

    /// An oversized `gradle.properties` must be rejected by the capped read rather than
    /// read into memory in full (CWE-400). Uses real `key=value` content padded past the
    /// cap, not a sparse NUL-filled file: an earlier version of this test used
    /// `set_len(MAX+1)` and asserted the resulting *parsed* map was empty, but a NUL-filled
    /// file has no `=` and parses to an empty map regardless of whether the size cap is
    /// applied — that assertion still passed against the pre-fix unbounded `read_to_string`.
    /// Padding with `#` comment lines after a real `key=value` line means `key` can only be
    /// absent here if the whole file was actually rejected by the cap.
    #[test]
    fn test_load_gradle_properties_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let props_file = dir.path().join("gradle.properties");
        let padding = "#".repeat(deps_core::MAX_CACHED_FILE_BYTES as usize);
        std::fs::write(&props_file, format!("key=value\n{padding}\n")).unwrap();

        let result = load_gradle_properties(dir.path());

        assert!(
            !result.contains_key("key"),
            "an oversized gradle.properties must not contribute any properties, even ones \
             that appear before the size cap is exceeded"
        );
    }

    /// The ancestor walk stops at [`MAX_CONFIG_ANCESTOR_DEPTH`] instead of climbing to the
    /// filesystem root — a pathologically deep tree must not do unbounded work per parse.
    #[test]
    fn test_load_gradle_properties_stops_at_max_ancestor_depth() {
        let root = tempfile::tempdir().unwrap();

        // Build a chain deeper than MAX_CONFIG_ANCESTOR_DEPTH, with a distinguishing
        // `gradle.properties` at the very top (beyond the cap) that must never be found.
        let mut current = root.path().to_path_buf();
        for i in 0..(MAX_CONFIG_ANCESTOR_DEPTH + 5) {
            current = current.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&current).unwrap();

        std::fs::write(root.path().join("gradle.properties"), "beyondCap=true\n").unwrap();

        let result = load_gradle_properties(&current);

        assert!(
            !result.contains_key("beyondCap"),
            "a gradle.properties beyond MAX_CONFIG_ANCESTOR_DEPTH must not be found"
        );
    }

    /// Boundary case for the depth cap: a `gradle.properties` exactly
    /// [`MAX_CONFIG_ANCESTOR_DEPTH`] ancestors up must still be found — only a *deeper* one
    /// should be excluded. An off-by-one in the depth check would falsely reject this
    /// legitimate boundary case (the failure mode `test_load_gradle_properties_stops_at_max_ancestor_depth`
    /// alone cannot catch, since it only proves *some* cap at or below the tested depth
    /// exists).
    #[test]
    fn test_load_gradle_properties_finds_file_exactly_at_max_ancestor_depth() {
        let root = tempfile::tempdir().unwrap();

        let mut current = root.path().to_path_buf();
        for i in 0..(MAX_CONFIG_ANCESTOR_DEPTH - 1) {
            current = current.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&current).unwrap();

        std::fs::write(root.path().join("gradle.properties"), "atCap=true\n").unwrap();

        let result = load_gradle_properties(&current);

        assert_eq!(
            result.get("atCap").map(String::as_str),
            Some("true"),
            "a gradle.properties exactly at the ancestor depth cap boundary must still be found"
        );
    }

    /// The real bound is "one `stat` per ancestor, capped at
    /// `MAX_CONFIG_ANCESTOR_DEPTH`" — verified by counting `stat` calls via
    /// `deps_core::fs_probe`, not merely inferred from which files got found. Mirrors
    /// `deps-cargo`'s `test_discover_workspace_stats_at_most_two_per_ancestor`. No
    /// `gradle.properties` exists anywhere in the synthetic chain, so the walk never
    /// short-circuits early on a hit.
    #[test]
    fn test_load_gradle_properties_stats_exactly_once_per_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let mut current = root.path().to_path_buf();
        for i in 0..(MAX_CONFIG_ANCESTOR_DEPTH + 5) {
            current = current.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&current).unwrap();

        let (stats_before, _) = deps_core::fs_probe::snapshot();
        let result = load_gradle_properties(&current);
        let (stats_after, _) = deps_core::fs_probe::snapshot();

        assert!(result.is_empty());
        assert_eq!(
            stats_after - stats_before,
            MAX_CONFIG_ANCESTOR_DEPTH,
            "expected exactly one stat per ancestor for all MAX_CONFIG_ANCESTOR_DEPTH levels"
        );
    }
}
