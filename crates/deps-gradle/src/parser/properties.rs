//! Parser for gradle.properties files.
//!
//! Provides key-value parsing and directory-walking lookup.

use deps_core::interpolation::PropertyValue;
use deps_core::{DEFAULT_MAX_CACHED_FILES, MtimeFileCache};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Parses a gradle.properties content into key-value pairs.
///
/// Lines starting with `#` or empty lines are ignored. Each line is split on the first `=`.
/// A value exceeding `deps_core::interpolation::MAX_INTERPOLATED_VALUE_BYTES` is dropped
/// (#1481) rather than retained unbounded — logged at `debug` with its length only, never
/// its content.
pub fn parse_properties(content: &str) -> HashMap<String, PropertyValue> {
    let mut result = HashMap::new();
    for (k, v) in content
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| l.split_once('='))
    {
        deps_core::interpolation::insert_bounded(
            &mut result,
            k.trim().to_string(),
            v.trim().to_string(),
            "gradle property",
        );
    }
    result
}

/// Per-file memoization of parsed `gradle.properties` contents, invalidated by mtime.
///
/// A thin newtype over [`deps_core::MtimeFileCache`] — the same mtime-gated caching mechanism
/// `deps-cargo`'s `ConfigFileCache` and `deps-npm`'s `NpmConfigCache` use for their own
/// ancestor config-file walks (#1514). Before this type existed, every ancestor
/// `gradle.properties` was re-read and re-parsed on every call to [`load_gradle_properties`]
/// instead of being cached across calls.
#[derive(Debug)]
pub struct GradlePropertiesCache(MtimeFileCache<HashMap<String, PropertyValue>>);

impl Default for GradlePropertiesCache {
    fn default() -> Self {
        Self::new()
    }
}

impl GradlePropertiesCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self(MtimeFileCache::new(
            DEFAULT_MAX_CACHED_FILES,
            "gradle properties",
        ))
    }

    /// Returns `path`'s parsed properties, from cache if `path`'s mtime is unchanged.
    /// `None` if `path` does not exist, is not a regular file, exceeds
    /// [`deps_core::MAX_CACHED_FILE_BYTES`], or cannot be read.
    fn get_or_parse(&self, path: &Path) -> Option<Arc<HashMap<String, PropertyValue>>> {
        self.0.get_or_parse(path, parse_properties)
    }
}

/// Finds and parses gradle.properties files by walking up from `start_dir`.
///
/// Merges properties from all levels, with child values overriding parent values, reusing
/// `cache`'s memoized per-file results instead of unconditionally re-reading and re-parsing.
/// The walk stops after [`deps_core::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH`] ancestors regardless
/// of whether the filesystem root has been reached, and each file is read through
/// [`GradlePropertiesCache`] — bounded by [`deps_core::MAX_CACHED_FILE_BYTES`], the same cap
/// `deps-cargo`'s/`deps-npm`'s own config-file ancestor walks use (a `gradle.properties` file
/// is a small config file, not a lock file, so it does not need
/// [`deps_core::lockfile::MAX_LOCKFILE_BYTES`]'s larger cap) — so an oversized or maliciously
/// deep ancestor chain cannot force unbounded work (CWE-400).
pub fn load_gradle_properties(
    start_dir: &Path,
    cache: &GradlePropertiesCache,
) -> HashMap<String, PropertyValue> {
    let mut result = HashMap::new();
    let mut chain = Vec::new();

    for d in deps_core::fs_probe::config_ancestors(start_dir) {
        let props_file = d.join("gradle.properties");
        if deps_core::fs_probe::is_file(&props_file) {
            chain.push(props_file);
        }
    }

    // Apply from root to leaf so child values override parent
    for path in chain.into_iter().rev() {
        match cache.get_or_parse(&path) {
            Some(parsed) => result.extend(parsed.iter().map(|(k, v)| (k.clone(), v.clone()))),
            // `path` passed `is_file` above, so a `None` here means the cache rejected it
            // after that check — already logged with the specific reason (size cap) when
            // that's the cause; this covers every other case (TOCTOU race, permission
            // denied, other I/O failure) that `MtimeFileCache::get_or_parse`'s `Option`
            // return does not otherwise surface to this caller.
            None => tracing::warn!(
                path = %path.display(),
                "gradle.properties could not be read or parsed; skipping"
            ),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH;

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

    /// #1481: a value past `MAX_INTERPOLATED_VALUE_BYTES` is dropped from the returned map
    /// rather than retained unbounded.
    #[test]
    fn test_parse_drops_oversized_value() {
        let oversized = "x".repeat(deps_core::interpolation::MAX_INTERPOLATED_VALUE_BYTES + 1);
        let content = format!("kept=short\nbig={oversized}\n");
        let props = parse_properties(&content);
        assert_eq!(props.get("kept").map(PropertyValue::as_str), Some("short"));
        assert!(!props.contains_key("big"));
    }

    /// #1481: a value exactly at the cap is kept.
    #[test]
    fn test_parse_keeps_value_at_exact_cap() {
        let at_cap = "x".repeat(deps_core::interpolation::MAX_INTERPOLATED_VALUE_BYTES);
        let content = format!("big={at_cap}\n");
        let props = parse_properties(&content);
        assert_eq!(
            props.get("big").map(PropertyValue::as_str),
            Some(at_cap.as_str())
        );
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

        // Held even though this test does not itself diff a snapshot: it still calls
        // `load_gradle_properties`, which bumps the same process-global fs_probe counters
        // `test_load_gradle_properties_stats_exactly_once_per_ancestor` diffs elsewhere in
        // this module — without the guard here, a concurrently running `cargo test` thread
        // could corrupt that test's count mid-diff.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let result = load_gradle_properties(dir.path(), &GradlePropertiesCache::new());

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

        // See the comment in `test_load_gradle_properties_rejects_oversized_file` on why a
        // non-diffing test still needs this guard.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let result = load_gradle_properties(&current, &GradlePropertiesCache::new());

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

        // See the comment in `test_load_gradle_properties_rejects_oversized_file` on why a
        // non-diffing test still needs this guard.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let result = load_gradle_properties(&current, &GradlePropertiesCache::new());

        assert_eq!(
            result.get("atCap").map(PropertyValue::as_str),
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

        let _guard = deps_core::fs_probe::snapshot_guard();
        let (stats_before, _) = deps_core::fs_probe::snapshot();
        let result = load_gradle_properties(&current, &GradlePropertiesCache::new());
        let (stats_after, _) = deps_core::fs_probe::snapshot();

        assert!(result.is_empty());
        assert_eq!(
            stats_after - stats_before,
            MAX_CONFIG_ANCESTOR_DEPTH,
            "expected exactly one stat per ancestor for all MAX_CONFIG_ANCESTOR_DEPTH levels"
        );
    }

    /// The whole point of [`GradlePropertiesCache`] (#1514): a cache reused across two
    /// `load_gradle_properties` calls with an unchanged ancestor file must not re-read its
    /// content on the second call. Mirrors `deps_core::mtime_cache::tests::hit_does_zero_reads_and_exactly_one_stat`
    /// at the wiring level, not just the underlying `MtimeFileCache` primitive.
    #[test]
    fn test_load_gradle_properties_reuses_cache_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("gradle.properties"), "key=value\n").unwrap();

        let cache = GradlePropertiesCache::new();
        let _guard = deps_core::fs_probe::snapshot_guard();

        let first = load_gradle_properties(dir.path(), &cache);
        assert_eq!(first.get("key").map(PropertyValue::as_str), Some("value"));

        let (_, reads_before) = deps_core::fs_probe::snapshot();
        let second = load_gradle_properties(dir.path(), &cache);
        let (_, reads_after) = deps_core::fs_probe::snapshot();

        assert_eq!(
            reads_after - reads_before,
            0,
            "a second call through the same cache with an unchanged mtime must not re-read \
             the file"
        );
        assert_eq!(second.get("key").map(PropertyValue::as_str), Some("value"));
    }
}
