//! Shared `serde_json`-side helpers for leniently interpreting untrusted JSON value shapes
//! from a manifest or registry response (#624, #662).
//!
//! `deps-npm` and `deps-composer` each parse a dependency section as a raw
//! `serde_json::Map<String, Value>` and apply the same "is this a valid dependency
//! declaration" rule to every entry; `deps-composer` and `deps-nuget` each accept a field
//! that may be a bare string or an array of strings — this module is where those rules
//! live, so every ecosystem crate that needs them shares one implementation and one set of
//! tests instead of duplicating both.
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

/// Accepts a JSON value that is either a single string or an array of strings, and
/// normalizes it to `Option<Vec<String>>` — never erroring on an unexpected shape.
///
/// #662, consolidated from `deps-composer`'s `deserialize_license` (#204) and
/// `deps-nuget`'s `deserialize_type_list` (#523).
///
/// Input classes and their result:
///
/// - a bare string (`"MIT"`) → `Some(vec!["MIT"])`
/// - an array of strings (`["MIT", "Apache-2.0"]`) → `Some(vec!["MIT", "Apache-2.0"])`
/// - an empty array (`[]`) → `Some(vec![])`
/// - a mixed array with some non-string elements (`["MIT", 7]`) → `Some(vec!["MIT"])`,
///   dropping only the non-string elements
/// - a non-empty array whose elements are *all* non-string (`[7, 8]`), or any other JSON
///   shape (a number, bool, object, `null`, or an absent field) → `None`
///
/// The general contract this establishes: `None` means "this value was not meaningfully
/// present" and `Some(vec![])` means "this value was present and is explicitly empty" — a
/// caller with no such absent-vs-empty distinction to make can collapse both to an empty
/// list via `.unwrap_or_default()`. The `[7, 8]` → `None` case (rather than `Some(vec![])`)
/// exists so that a caller treating `Some(_)` as an explicit override never sees a
/// fabricated empty override manufactured from malformed input data — see
/// `deps-composer`'s `MinifiedVersion::license` doc for a concrete case where this
/// distinction is load-bearing.
///
/// # Errors
///
/// Returns an error only if the underlying `deserializer` cannot produce a
/// `serde_json::Value` at all (e.g. malformed input at the transport level) — no JSON
/// *shape* this function receives is itself treated as an error.
///
/// # Examples
///
/// ```
/// use deps_core::json_helpers::deserialize_string_or_string_array;
/// use serde_json::json;
///
/// assert_eq!(
///     deserialize_string_or_string_array(json!("MIT")).unwrap(),
///     Some(vec!["MIT".to_string()])
/// );
/// assert_eq!(
///     deserialize_string_or_string_array(json!(["MIT", 7])).unwrap(),
///     Some(vec!["MIT".to_string()])
/// );
/// assert_eq!(deserialize_string_or_string_array(json!([7, 8])).unwrap(), None);
/// assert_eq!(deserialize_string_or_string_array(json!(null)).unwrap(), None);
/// ```
pub fn deserialize_string_or_string_array<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::String(s) => Some(vec![s]),
        serde_json::Value::Array(entries) => {
            // A non-empty raw array whose every element is a non-string (e.g. `[7, 8]`)
            // must degrade to `None` ("not meaningfully present"), not `Some(vec![])`
            // ("explicitly empty") — see this function's doc for why that distinction
            // matters to a caller like `deps-composer`'s inheritance chain.
            let had_entries = !entries.is_empty();
            let strings: Vec<String> = entries
                .into_iter()
                .filter_map(|entry| match entry {
                    serde_json::Value::String(s) => Some(s),
                    _ => None,
                })
                .collect();
            if had_entries && strings.is_empty() {
                None
            } else {
                Some(strings)
            }
        }
        _ => None,
    })
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

    // --- `deserialize_string_or_string_array` (#662: consolidated from deps-composer's
    //     `deserialize_license` / #204 and deps-nuget's `deserialize_type_list` / #523) ---

    #[test]
    fn test_deserialize_string_or_string_array_bare_string() {
        assert_eq!(
            deserialize_string_or_string_array(serde_json::json!("MIT")).unwrap(),
            Some(vec!["MIT".to_string()])
        );
    }

    #[test]
    fn test_deserialize_string_or_string_array_of_strings() {
        assert_eq!(
            deserialize_string_or_string_array(serde_json::json!(["MIT", "Apache-2.0"])).unwrap(),
            Some(vec!["MIT".to_string(), "Apache-2.0".to_string()])
        );
    }

    #[test]
    fn test_deserialize_string_or_string_array_empty_array() {
        assert_eq!(
            deserialize_string_or_string_array(serde_json::json!([])).unwrap(),
            Some(vec![])
        );
    }

    #[test]
    fn test_deserialize_string_or_string_array_mixed_array_keeps_only_strings() {
        assert_eq!(
            deserialize_string_or_string_array(serde_json::json!(["MIT", 7, "Apache-2.0"]))
                .unwrap(),
            Some(vec!["MIT".to_string(), "Apache-2.0".to_string()])
        );
    }

    /// Non-empty array with no string element must degrade to `None` ("not present"), not
    /// `Some(vec![])` ("explicitly empty") — a caller like `deps-composer`'s minified-entry
    /// inheritance chain would otherwise treat a malformed array as an explicit override
    /// that silently wipes out (and then propagates) a real inherited value.
    #[test]
    fn test_deserialize_string_or_string_array_all_non_string_array_is_none() {
        assert_eq!(
            deserialize_string_or_string_array(serde_json::json!([7, 8])).unwrap(),
            None
        );
    }

    #[test]
    fn test_deserialize_string_or_string_array_other_shapes_are_none() {
        for value in [
            serde_json::json!(42),
            serde_json::json!(true),
            serde_json::json!({"not": "a list"}),
            serde_json::json!(null),
        ] {
            assert_eq!(deserialize_string_or_string_array(value).unwrap(), None);
        }
    }
}
