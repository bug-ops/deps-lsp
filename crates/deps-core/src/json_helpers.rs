//! Shared `serde_json`-side helpers for parsing a JSON manifest's *semantic* dependency-map
//! content (#624).
//!
//! `deps-npm` and `deps-composer` each parse a dependency section as a raw
//! `serde_json::Map<String, Value>` and apply the same "is this a valid dependency
//! declaration" rule to every entry — this module is where that rule lives, so both crates
//! share one implementation and one set of tests instead of duplicating both.
//!
//! This is a different concern from [`crate::json_ast`], which recovers a dependency's
//! *position* in the source text from a separate jsonc-AST parse of the same content — this
//! module never touches that AST, only the `serde_json::Value` tree callers already hold.

/// Iterates a JSON object's entries, yielding only those whose value is a plain string.
///
/// A manifest entry whose value isn't a string (e.g. an object, number, bool, null, or array)
/// is not a valid dependency declaration — callers skip it rather than fabricating an entry
/// with no version requirement that would still be queried against the registry (`deps-npm`
/// #619, `deps-composer` #621).
///
/// Yields entries in `entries`' own iteration order, which `serde_json::Map` derives from
/// either `BTreeMap` (sorted by key) or `IndexMap` (insertion order), depending on this
/// build's `serde_json/preserve_order` feature unification — do not write a test against a
/// specific order without accounting for that.
///
/// # Examples
///
/// ```
/// use deps_core::json_helpers::string_valued_entries;
/// use serde_json::json;
///
/// let deps = json!({"express": "^4.18.2", "nested-shadow": {"express": "0.0.1"}});
/// let deps = deps.as_object().unwrap();
///
/// let entries: Vec<_> = string_valued_entries(deps).collect();
/// assert_eq!(entries, vec![("express", "^4.18.2")]);
/// ```
pub fn string_valued_entries(
    entries: &serde_json::Map<String, serde_json::Value>,
) -> impl Iterator<Item = (&str, &str)> {
    entries
        .iter()
        .filter_map(|(name, value)| Some((name.as_str(), value.as_str()?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- `string_valued_entries` (#624: consolidated from deps-npm #619 / deps-composer #621) ---

    #[test]
    fn test_string_valued_entries_skips_every_non_string_value_kind() {
        let deps = serde_json::json!({
            "bad-object": {"nested": "0.0.1"},
            "bad-number": 1,
            "bad-bool": true,
            "bad-null": null,
            "bad-array": ["1.0.0"],
            "express": "^4.18.2",
        });
        let deps = deps.as_object().unwrap();

        let mut entries: Vec<_> = string_valued_entries(deps).collect();
        entries.sort_unstable();
        assert_eq!(entries, vec![("express", "^4.18.2")]);
    }

    #[test]
    fn test_string_valued_entries_all_invalid_yields_empty() {
        let deps = serde_json::json!({
            "bad-object": {"nested": "0.0.1"},
            "bad-number": 1,
        });
        let deps = deps.as_object().unwrap();

        assert_eq!(string_valued_entries(deps).count(), 0);
    }

    #[test]
    fn test_string_valued_entries_empty_object_yields_empty() {
        let deps = serde_json::json!({});
        let deps = deps.as_object().unwrap();

        assert_eq!(string_valued_entries(deps).count(), 0);
    }
}
