//! `bun.lock` parsing (Bun 1.2+ text lock file, JSONC), spec 090.
//!
//! Only resolved-version extraction is implemented: checksums, registry URLs and dependency
//! graphs are out of scope. The input is untrusted repository content, so the parse goes
//! through the shared depth-bounded JSONC path ([`deps_core::json_ast::parse_jsonc_typed`]).

use std::collections::{HashMap, HashSet};
use std::fmt;

use deps_core::error::{DepsError, Result};
use deps_core::json_ast::parse_jsonc_typed;
use deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource};
use serde::Deserialize;
use serde::de::{IgnoredAny, SeqAccess, Visitor};

use super::split_specifier;

const FILE_TYPE: &str = "bun.lock";

/// Lowest supported `lockfileVersion`; real files for each of `0..=3` are pinned in the tests.
const MIN_LOCKFILE_VERSION: u32 = 0;
/// Highest supported `lockfileVersion`; newer lock files fail closed (spec 090 FR-006).
const MAX_LOCKFILE_VERSION: u32 = 3;

/// A `lockfileVersion` value as written: an unsigned integer, or anything else (kept only to
/// name it in the error).
#[derive(Deserialize)]
#[serde(untagged)]
enum RawLockfileVersion {
    Integer(u32),
    Other(serde_json::Value),
}

/// The parts of `bun.lock` this parser reads; `workspaces`, `overrides`, `catalogs`,
/// `configVersion` and every other key are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BunLock {
    lockfile_version: Option<RawLockfileVersion>,
    #[serde(default)]
    packages: HashMap<String, BunPackageEntry>,
}

/// One `packages` value: normally a tuple led by a `name@resolution` label, but a value of any
/// other shape must not fail the whole file.
#[derive(Deserialize)]
#[serde(untagged)]
enum BunPackageEntry {
    Tuple(BunPackageLabel),
    Unrecognized(IgnoredAny),
}

/// The `name@resolution` head of a `packages` tuple; `None` when the head is not a string.
struct BunPackageLabel(Option<String>);

#[derive(Deserialize)]
#[serde(untagged)]
enum TupleHead {
    Label(String),
    Other(IgnoredAny),
}

impl<'de> Deserialize<'de> for BunPackageLabel {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct LabelVisitor;

        impl<'de> Visitor<'de> for LabelVisitor {
            type Value = BunPackageLabel;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bun.lock package tuple")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let head = seq.next_element::<TupleHead>()?;
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(BunPackageLabel(match head {
                    Some(TupleHead::Label(label)) => Some(label),
                    Some(TupleHead::Other(_)) | None => None,
                }))
            }
        }

        deserializer.deserialize_seq(LabelVisitor)
    }
}

fn parse_error(message: &str) -> DepsError {
    DepsError::parse_error(FILE_TYPE, &message)
}

fn check_lockfile_version(raw: Option<RawLockfileVersion>) -> Result<()> {
    match raw {
        None => Err(parse_error("missing lockfileVersion")),
        Some(RawLockfileVersion::Integer(version))
            if (MIN_LOCKFILE_VERSION..=MAX_LOCKFILE_VERSION).contains(&version) =>
        {
            Ok(())
        }
        Some(RawLockfileVersion::Integer(version)) => Err(parse_error(&format!(
            "unsupported lockfileVersion '{version}' (supported \
             {MIN_LOCKFILE_VERSION}..={MAX_LOCKFILE_VERSION})"
        ))),
        Some(RawLockfileVersion::Other(value)) => Err(parse_error(&format!(
            "unparseable lockfileVersion ({})",
            describe_json_value(&value)
        ))),
    }
}

/// Longest string prefix echoed into a `lockfileVersion` error.
const MAX_PREVIEW_CHARS: usize = 64;

/// Names a JSON value's type, with a bounded preview for scalars: the value comes from an
/// untrusted file and may be megabytes long, so it is never echoed whole.
fn describe_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(flag) => format!("boolean {flag}"),
        serde_json::Value::Number(number) => format!("number {number}"),
        serde_json::Value::String(text) => {
            let preview: String = text.chars().take(MAX_PREVIEW_CHARS).collect();
            let ellipsis = if text.chars().count() > MAX_PREVIEW_CHARS {
                "..."
            } else {
                ""
            };
            format!(
                "string '{}{ellipsis}'",
                deps_core::redact::redact_declaration_key(&preview)
            )
        }
        serde_json::Value::Array(_) => "array".to_string(),
        serde_json::Value::Object(_) => "object".to_string(),
    }
}

/// Parses `bun.lock` content (already read and size-capped) into resolved packages.
///
/// Empty, whitespace-only and comment-only content yields an empty result. Entries with a
/// non-tuple shape, a non-string head, or a resolution that is not a semver version
/// (`workspace:`, `link:`, `file:`, git and tarball sources) are skipped: Bun records no
/// version for them, and a resolution string stored as a version would reach hover and OSV
/// queries (spec 090 FR-008, same rule as `pnpm-lock.yaml` and `yarn.lock`). Registry URL and
/// checksum stay empty so no credential-bearing URL is retained.
///
/// # Errors
///
/// Returns [`DepsError::ParseError`] for malformed JSONC, nesting beyond the shared depth
/// bound, an absent, non-integer or unsupported `lockfileVersion`, or a document that is not
/// an object.
pub(super) fn parse_bun_lock(content: &str) -> Result<ResolvedPackages> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let Some(lock) = parse_jsonc_typed::<BunLock>(content, FILE_TYPE)? else {
        return Ok(ResolvedPackages::new());
    };
    check_lockfile_version(lock.lockfile_version)?;

    let mut packages = ResolvedPackages::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for (key, entry) in lock.packages {
        let BunPackageEntry::Tuple(BunPackageLabel(Some(label))) = entry else {
            tracing::debug!(
                key = %deps_core::redact::redact_declaration_key(&key),
                "skipping bun.lock entry without a name@resolution label"
            );
            continue;
        };
        let Some((name, resolution)) = split_specifier(&label) else {
            continue;
        };
        if node_semver::Version::parse(resolution).is_err() {
            tracing::debug!(
                package = ?name,
                resolution = %deps_core::redact::redact_declaration_key(resolution),
                "skipping bun.lock entry with a non-semver resolution"
            );
            continue;
        }
        if seen.insert((name.to_string(), resolution.to_string())) {
            packages.insert(ResolvedPackage::new(
                name.to_string(),
                resolution.to_string(),
                ResolvedSource::Registry {
                    url: String::new(),
                    checksum: String::new(),
                },
            ));
        }
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    // Fixtures are trimmed from real Bun output, taken from the MIT-licensed
    // `dependabot/dependabot-core` repository (`bun/spec/fixtures/projects/bun/`:
    // `simple_v0`, `simple_v1`, `simple_v2`, `simple_v3`, `aliased_dependency`,
    // `github_dependency_no_ref`, `simple_workspace_v0`). Integrity hashes are shortened.

    const V0: &str = r#"{
  "lockfileVersion": 0,
  "workspaces": { "": { "dependencies": { "fetch-factory": "^0.0.1", }, }, },
  "packages": {
    "es6-promise": ["es6-promise@3.3.1", "", {}, "sha512-SOp9"],

    "fetch-factory": ["fetch-factory@0.0.1", "", { "dependencies": { "lodash": "^3.10.1" } }, "sha512-gexR"],

    "lodash": ["lodash@3.10.1", "", {}, "sha512-9mDD"],
  }
}"#;

    const V1_ALIAS_AND_REMOTE: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": { "": { "dependencies": { "my-fetch-factory": "npm:fetch-factory@0.0.1" } } },
  "packages": {
    "@types/bun": ["@types/bun@1.2.2", "", { "dependencies": { "bun-types": "1.2.2" } }, "sha512-tr74"],

    "is-number": ["is-number@github:jonschlinkert/is-number#98e8ff1", {}, "jonschlinkert-is-number-98e8ff1"],

    "my-fetch-factory": ["fetch-factory@0.0.1", "", {}, "sha512-gexR"],
  }
}"#;

    const V2: &str = r#"{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": { "": { "dependencies": { "etag": "1.0.1", "is-number": "7.0.0", }, }, },
  "packages": {
    "etag": ["etag@1.0.1", "", {}, "sha512-UT24"],

    "is-number": ["is-number@7.0.0", "", {}, "sha512-41Ci"],
  }
}"#;

    const V3_NESTED: &str = r#"{
  "lockfileVersion": 3,
  "configVersion": 1,
  "workspaces": { "": { "dependencies": { "is-number": "7.0.0", "is-odd": "3.0.1", }, }, },
  "overrides": { "is-odd": { "is-number": "6.0.0", }, },
  "packages": {
    "is-number": ["is-number@7.0.0", "", {}, "sha512-41Ci"],

    "is-odd": ["is-odd@3.0.1", "", { "dependencies": { "is-number": "^6.0.0" } }, "sha512-CQpn"],

    "is-odd/is-number": ["is-number@6.0.0", "", {}, "sha512-Wu1V"],
  }
}"#;

    // The `sib` (link:) and `loc` (file:) entries are synthetic, not taken from real Bun output.
    const WORKSPACE_V0: &str = r#"{
  "lockfileVersion": 0,
  "workspaces": {
    "": { "dependencies": { "bar": "packages/bar", }, },
    "packages/bar": { "name": "bar", "version": "0.0.1", "dependencies": { "chalk": "0.3.0", }, },
  },
  "packages": {
    "bar": ["bar@workspace:packages/bar", { "dependencies": { "chalk": "0.3.0" } }],

    "chalk": ["chalk@0.3.0", "", {}, "sha512-OcfgS"],

    "sib": ["sib@link:../sib"],

    "loc": ["loc@file:../loc", {}],
  }
}"#;

    fn parse(content: &str) -> ResolvedPackages {
        parse_bun_lock(content).unwrap()
    }

    fn versions(packages: &ResolvedPackages, name: &str) -> Vec<String> {
        let mut found: Vec<String> = packages
            .all(name)
            .unwrap_or_default()
            .iter()
            .map(|p| p.version.clone())
            .collect();
        found.sort();
        found
    }

    #[test]
    fn every_supported_lockfile_version_parses() {
        assert_eq!(parse(V0).version("fetch-factory"), Some("0.0.1"));
        assert_eq!(
            parse(V1_ALIAS_AND_REMOTE).version("@types/bun"),
            Some("1.2.2")
        );
        assert_eq!(parse(V2).version("etag"), Some("1.0.1"));
        assert_eq!(parse(V3_NESTED).version("is-odd"), Some("3.0.1"));
    }

    #[test]
    fn trailing_commas_and_comments_parse_like_clean_json() {
        let with_noise = "// Bun lock\n{ /* v */ \"lockfileVersion\": 2, \"packages\": { \"etag\": [\"etag@1.0.1\", \"\", {},], }, }";
        let clean = r#"{"lockfileVersion": 2, "packages": {"etag": ["etag@1.0.1", "", {}]}}"#;
        assert_eq!(
            parse(with_noise).version("etag"),
            parse(clean).version("etag")
        );
        assert_eq!(parse(with_noise).version("etag"), Some("1.0.1"));
    }

    #[test]
    fn alias_entry_is_recorded_under_the_real_registry_name() {
        let packages = parse(V1_ALIAS_AND_REMOTE);
        assert_eq!(packages.version("fetch-factory"), Some("0.0.1"));
        assert_eq!(packages.version("my-fetch-factory"), None);
    }

    #[test]
    fn nested_keys_use_their_own_label_and_all_versions_are_candidates() {
        let packages = parse(V3_NESTED);
        assert_eq!(versions(&packages, "is-number"), ["6.0.0", "7.0.0"]);
        assert_eq!(packages.version("is-number"), Some("7.0.0"));
    }

    #[test]
    fn same_name_and_version_under_two_keys_is_recorded_once() {
        let packages = parse(
            r#"{"lockfileVersion": 3, "packages": {
              "a": ["dup@1.0.0", "", {}], "b/dup": ["dup@1.0.0", "", {}]}}"#,
        );
        assert_eq!(versions(&packages, "dup"), ["1.0.0"]);
    }

    #[test]
    fn non_registry_resolutions_are_not_recorded_as_versions() {
        let packages = parse(WORKSPACE_V0);
        for name in ["bar", "sib", "loc"] {
            assert!(packages.all(name).is_none(), "{name} must be skipped");
        }
        assert_eq!(packages.version("chalk"), Some("0.3.0"));
        assert!(parse(V1_ALIAS_AND_REMOTE).all("is-number").is_none());
    }

    #[test]
    fn registry_entries_carry_no_copied_url_or_checksum() {
        let packages = parse(V2);
        assert_matches!(
            &packages.get("etag").unwrap().source,
            ResolvedSource::Registry { url, checksum } if url.is_empty() && checksum.is_empty()
        );
    }

    #[test]
    fn empty_whitespace_and_comment_only_content_is_an_empty_result() {
        for content in ["", "  \n\t", "// nothing\n", "\u{feff}"] {
            assert!(parse(content).is_empty(), "{content:?}");
        }
    }

    #[test]
    fn missing_packages_key_is_an_empty_result() {
        assert!(parse(r#"{"lockfileVersion": 3, "workspaces": {"": {}}}"#).is_empty());
    }

    #[test]
    fn unsupported_or_unreadable_lockfile_version_fails_closed_naming_the_value() {
        for (content, needle) in [
            (r#"{"lockfileVersion": 4, "packages": {}}"#, "'4'"),
            (r#"{"lockfileVersion": -1, "packages": {}}"#, "number -1"),
            (
                r#"{"lockfileVersion": "two", "packages": {}}"#,
                "string 'two'",
            ),
            (r#"{"lockfileVersion": 1.5, "packages": {}}"#, "number 1.5"),
            (r#"{"lockfileVersion": [1], "packages": {}}"#, "array"),
            (r#"{"lockfileVersion": {"a": 1}, "packages": {}}"#, "object"),
            (r#"{"lockfileVersion": null, "packages": {}}"#, "missing"),
        ] {
            let err = parse_bun_lock(content).unwrap_err();
            assert_matches!(err, DepsError::ParseError { .. }, "{content}");
            assert!(err.to_string().contains(needle), "{err}");
        }
    }

    #[test]
    fn oversized_lockfile_version_is_not_echoed_whole() {
        let content = format!(r#"{{"lockfileVersion": "{}"}}"#, "x".repeat(100_000));
        let message = parse_bun_lock(&content).unwrap_err().to_string();
        assert!(message.len() < 400, "{}", message.len());
        assert!(message.contains("..."), "{message}");
    }

    #[test]
    fn absent_lockfile_version_and_non_object_documents_are_errors() {
        for content in [r#"{"packages": {}}"#, "{}", "[]", "42", "{ not json"] {
            assert_matches!(
                parse_bun_lock(content),
                Err(DepsError::ParseError { .. }),
                "{content}"
            );
        }
    }

    #[test]
    fn malformed_entries_are_skipped_without_failing_the_file() {
        let packages = parse(
            r#"{"lockfileVersion": 3, "packages": {
              "a": "not-an-array", "b": [], "c": [7, "x"], "d": {"k": 1}, "e": null,
              "f": ["no-separator"], "ok": ["ok@1.2.3", "", {}]}}"#,
        );
        assert_eq!(packages.version("ok"), Some("1.2.3"));
        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn over_deep_nesting_is_rejected_with_the_shared_failure_kind() {
        let deep = format!(
            r#"{{"lockfileVersion": 3, "x": {}1{}}}"#,
            "[".repeat(deps_core::MAX_JSON_NESTING_DEPTH + 1),
            "]".repeat(deps_core::MAX_JSON_NESTING_DEPTH + 1)
        );
        let err = parse_bun_lock(&deep).unwrap_err();
        assert_eq!(
            err.parse_failure_kind(),
            Some(deps_core::ParseFailureKind::NestingTooDeep)
        );
    }
}
