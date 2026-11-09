//! `bun.lock` parsing (Bun 1.2+ text lock file, JSONC), spec 090.
//!
//! Only resolved-version extraction is implemented: checksums, registry URLs and dependency
//! graphs are out of scope. The input is untrusted repository content, so the parse goes
//! through the shared depth-bounded JSONC path ([`deps_core::json_ast::parse_jsonc_typed`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use deps_core::error::Result;
use deps_core::json_ast::parse_jsonc_typed;
use deps_core::lockfile::{
    EntryOwner, EntryPlacement, ImporterPath, ResolvedPackage, ResolvedPackages, ResolvedSource,
};
use serde::de::value::MapAccessDeserializer;
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::{lockfile_parse_error, split_specifier};

const FILE_TYPE: &str = "bun.lock";

/// Lowest supported `lockfileVersion`; real files for each of `0..=3` are pinned in the tests.
const MIN_LOCKFILE_VERSION: u32 = 0;
/// Highest supported `lockfileVersion`; newer lock files fail closed (spec 090 FR-006).
const MAX_LOCKFILE_VERSION: u32 = 3;

/// Generates the `visit_*` methods that accept a value of an unwanted shape and yield
/// `$unrecognized`, so a value of any other shape never fails the whole file. Each shape is
/// consumed without building it (sequences and maps are drained as `IgnoredAny`).
macro_rules! ignore_shapes {
    (@bool $u:expr) => {
        fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<Self::Value, E> {
            Ok($u)
        }
    };
    (@i64 $u:expr) => {
        fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<Self::Value, E> {
            Ok($u)
        }
    };
    (@u64 $u:expr) => {
        fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<Self::Value, E> {
            Ok($u)
        }
    };
    (@f64 $u:expr) => {
        fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
            Ok($u)
        }
    };
    (@str $u:expr) => {
        fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<Self::Value, E> {
            Ok($u)
        }
    };
    (@unit $u:expr) => {
        fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok($u)
        }
    };
    (@seq $u:expr) => {
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok($u)
        }
    };
    (@map $u:expr) => {
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok($u)
        }
    };
    ($unrecognized:expr; $($shape:ident),+ $(,)?) => { $(ignore_shapes!(@$shape $unrecognized);)+ };
}

/// A `lockfileVersion` value as written: an unsigned integer, or anything else (kept only to
/// name it in the error).
enum RawLockfileVersion {
    Integer(u32),
    Other(OtherValue),
}

/// The shape of a non-integer `lockfileVersion`; composite values are drained, never kept.
enum OtherValue {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    Array,
    Object,
}

impl<'de> Deserialize<'de> for RawLockfileVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct VersionVisitor;

        impl VersionVisitor {
            fn other(value: OtherValue) -> RawLockfileVersion {
                RawLockfileVersion::Other(value)
            }
        }

        impl<'de> Visitor<'de> for VersionVisitor {
            type Value = RawLockfileVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bun.lock lockfileVersion")
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(u32::try_from(value).map_or_else(
                    |_| Self::other(OtherValue::Number(value.to_string())),
                    RawLockfileVersion::Integer,
                ))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(u32::try_from(value).map_or_else(
                    |_| Self::other(OtherValue::Number(value.to_string())),
                    RawLockfileVersion::Integer,
                ))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
                let text = serde_json::Number::from_f64(value)
                    .map_or_else(|| value.to_string(), |number| number.to_string());
                Ok(Self::other(OtherValue::Number(text)))
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(Self::other(OtherValue::Bool(value)))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(Self::other(OtherValue::Text(value.to_owned())))
            }

            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(Self::other(OtherValue::Null))
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Self::other(OtherValue::Array))
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Self::other(OtherValue::Object))
            }
        }

        deserializer.deserialize_any(VersionVisitor)
    }
}

/// The parts of `bun.lock` this parser reads; `overrides`, `catalogs`, `configVersion` and every
/// other key are ignored. `workspaces` is read only for each member's `name` (spec 090 decision
/// 4, amended by #1993): a `packages` key prefixed with a member's name is installed under it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BunLock {
    lockfile_version: Option<RawLockfileVersion>,
    #[serde(default)]
    workspaces: BunWorkspaces,
    #[serde(default)]
    packages: BTreeMap<String, BunPackageLabel>,
}

/// A string value, or `None` for a value of any other shape.
#[derive(Default)]
struct LenientString(Option<String>);

impl<'de> Deserialize<'de> for LenientString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct StringVisitor;

        impl<'de> Visitor<'de> for StringVisitor {
            type Value = LenientString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any value")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(LenientString(Some(value.to_owned())))
            }

            ignore_shapes!(LenientString(None); bool, i64, u64, f64, unit, seq, map);
        }

        deserializer.deserialize_any(StringVisitor)
    }
}

/// The `workspaces` value: path -> member's name. A value of any other shape yields no members
/// rather than failing the whole file.
#[derive(Default)]
struct BunWorkspaces(BTreeMap<String, LenientString>);

impl<'de> Deserialize<'de> for BunWorkspaces {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct WorkspacesVisitor;

        impl<'de> Visitor<'de> for WorkspacesVisitor {
            type Value = BunWorkspaces;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any value")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut members = BTreeMap::new();
                while let Some((path, member)) = map.next_entry::<String, WorkspaceMember>()? {
                    members.insert(path, member.name);
                }
                Ok(BunWorkspaces(members))
            }

            ignore_shapes!(BunWorkspaces::default(); bool, i64, u64, f64, str, unit, seq);
        }

        deserializer.deserialize_any(WorkspacesVisitor)
    }
}

/// One workspace member: only its `name` is read; a non-object member has no name.
struct WorkspaceMember {
    name: LenientString,
}

impl<'de> Deserialize<'de> for WorkspaceMember {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields {
            #[serde(default)]
            name: LenientString,
        }

        struct MemberVisitor;

        impl<'de> Visitor<'de> for MemberVisitor {
            type Value = WorkspaceMember;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any value")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let fields = Fields::deserialize(MapAccessDeserializer::new(map))?;
                Ok(WorkspaceMember { name: fields.name })
            }

            ignore_shapes!(
                WorkspaceMember { name: LenientString(None) };
                bool, i64, u64, f64, str, unit, seq
            );
        }

        deserializer.deserialize_any(MemberVisitor)
    }
}

/// Workspace member name -> its directory, for the members that declare a name and a valid
/// path.
fn workspace_directories(workspaces: BunWorkspaces) -> HashMap<String, ImporterPath> {
    let mut directories = HashMap::new();
    for (path, member) in workspaces.0 {
        let LenientString(Some(name)) = member else {
            continue;
        };
        if let Ok(path) = ImporterPath::parse(&path) {
            directories.entry(name).or_insert(path);
        }
    }
    directories
}

/// Splits a `packages` key into its package-name components: `app/@types/node` is `app` then
/// `@types/node`, and `@org/app/x` is `@org/app` then `x`.
fn key_components(key: &str) -> Vec<&str> {
    let mut components = Vec::new();
    let mut rest = key;
    while !rest.is_empty() {
        let mut slashes = rest.match_indices('/').map(|(index, _)| index);
        let end = if rest.starts_with('@') {
            slashes.nth(1)
        } else {
            slashes.next()
        }
        .unwrap_or(rest.len());
        let (component, tail) = rest.split_at_checked(end).unwrap_or((rest, ""));
        components.push(component);
        rest = tail.strip_prefix('/').unwrap_or_default();
    }
    components
}

/// The importer a `packages` key is installed under: a bare key is hoisted to the root, a key
/// under a workspace member's name belongs to that member, and any other prefix is a copy
/// nested under another package, which only serves that package.
fn key_importer(key: &str, directories: &HashMap<String, ImporterPath>) -> Option<ImporterPath> {
    match key_components(key).as_slice() {
        [_] => Some(ImporterPath::root()),
        [member, _] => directories.get(*member).cloned(),
        _ => None,
    }
}

/// The `name@resolution` head of a `packages` tuple; `None` when the value is not a tuple or
/// its head is not a string. The tuple's remaining elements are drained without being built.
struct BunPackageLabel(Option<String>);

impl<'de> Deserialize<'de> for BunPackageLabel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
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
                let head = seq.next_element::<LenientString>()?;
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(BunPackageLabel(head.and_then(|head| head.0)))
            }

            ignore_shapes!(BunPackageLabel(None); bool, i64, u64, f64, str, unit, map);
        }

        deserializer.deserialize_any(LabelVisitor)
    }
}

fn check_lockfile_version(raw: Option<RawLockfileVersion>) -> Result<()> {
    match raw {
        None => Err(lockfile_parse_error(FILE_TYPE, "missing lockfileVersion")),
        Some(RawLockfileVersion::Integer(version))
            if (MIN_LOCKFILE_VERSION..=MAX_LOCKFILE_VERSION).contains(&version) =>
        {
            Ok(())
        }
        Some(RawLockfileVersion::Integer(version)) => Err(lockfile_parse_error(
            FILE_TYPE,
            &format!(
                "unsupported lockfileVersion '{version}' (supported \
             {MIN_LOCKFILE_VERSION}..={MAX_LOCKFILE_VERSION})"
            ),
        )),
        Some(RawLockfileVersion::Other(value)) => Err(lockfile_parse_error(
            FILE_TYPE,
            &format!(
                "unparseable lockfileVersion ({})",
                describe_json_value(&value)
            ),
        )),
    }
}

/// Longest string prefix echoed into a `lockfileVersion` error.
const MAX_PREVIEW_CHARS: usize = 64;

/// Names a JSON value's type, with a bounded preview for scalars: the value comes from an
/// untrusted file and may be megabytes long, so it is never echoed whole.
fn describe_json_value(value: &OtherValue) -> String {
    match value {
        OtherValue::Null => "null".to_string(),
        OtherValue::Bool(flag) => format!("boolean {flag}"),
        OtherValue::Number(number) => format!("number {number}"),
        OtherValue::Text(text) => {
            let preview = deps_core::lsp_helpers::truncate_for_diagnostic(text, MAX_PREVIEW_CHARS);
            format!(
                "string '{}'",
                deps_core::redact::redact_declaration_key(&preview)
            )
        }
        OtherValue::Array => "array".to_string(),
        OtherValue::Object => "object".to_string(),
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
/// Returns [`deps_core::error::DepsError::ParseError`] for malformed JSONC, nesting beyond the shared depth
/// bound, an absent, non-integer or unsupported `lockfileVersion`, or a document that is not
/// an object.
pub(super) fn parse_bun_lock(content: &str) -> Result<ResolvedPackages> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let Some(lock) = parse_jsonc_typed::<BunLock>(content, FILE_TYPE)? else {
        return Ok(ResolvedPackages::new());
    };
    check_lockfile_version(lock.lockfile_version)?;

    let directories = workspace_directories(lock.workspaces);
    let mut installs: BTreeMap<(String, String), BTreeSet<Option<ImporterPath>>> = BTreeMap::new();
    for (key, entry) in lock.packages {
        let BunPackageLabel(Some(label)) = entry else {
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
        let importer = key_importer(&key, &directories);
        let importers = installs
            .entry((name.to_string(), resolution.to_string()))
            .or_default();
        importers.insert(importer);
    }

    let mut packages = ResolvedPackages::new();
    for ((name, version), importers) in installs {
        let owners: Vec<ImporterPath> = importers.into_iter().flatten().collect();
        let placements: Vec<EntryPlacement> = if owners.is_empty() {
            vec![EntryPlacement::Nested]
        } else {
            owners
                .into_iter()
                .map(|path| EntryPlacement::Hoisted {
                    owner: EntryOwner::Importer(path),
                })
                .collect()
        };
        for placement in placements {
            packages.insert(
                ResolvedPackage::new(
                    name.clone(),
                    version.clone(),
                    ResolvedSource::Registry {
                        url: String::new(),
                        checksum: String::new(),
                    },
                )
                .with_placement(placement),
            );
        }
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;
    use deps_core::error::DepsError;

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
    fn key_components_keep_scoped_names_whole() {
        for (key, expected) in [
            ("left-pad", &["left-pad"][..]),
            ("@types/node", &["@types/node"]),
            ("app/@types/node", &["app", "@types/node"]),
            ("@org/app/x", &["@org/app", "x"]),
            ("@org/app/@types/node", &["@org/app", "@types/node"]),
            ("a/b/c", &["a", "b", "c"]),
        ] {
            assert_eq!(key_components(key), expected, "{key}");
        }
    }

    const WORKSPACE_OWNERS: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "root", "dependencies": { "lodash": "^4.0.0" } },
    "packages/a": { "name": "a", "dependencies": { "lodash": "^3.0.0" } },
    "packages/b": { "name": "b", "dependencies": { "lodash": "^2.0.0" } },
  },
  "packages": {
    "lodash": ["lodash@4.0.0", "", {}, "sha512-x"],
    "a/lodash": ["lodash@3.0.0", "", {}, "sha512-y"],
    "b/lodash": ["lodash@2.0.0", "", {}, "sha512-z"],
    "lodash/inner": ["inner@1.0.0", "", {}, "sha512-w"],
  }
}"#;

    fn collapsed_for(packages: &ResolvedPackages, scope: &str) -> Option<String> {
        let naming = deps_core::test_util::StubFormatter::new();
        let scope = ImporterPath::parse(scope).unwrap();
        let (versions, _) = packages.split_normalized_for(&naming, &scope);
        versions
            .iter()
            .find(|(name, _)| name.as_str() == "lodash")
            .map(|(_, version)| version.as_str().to_string())
    }

    #[test]
    fn workspace_prefixed_keys_are_owned_by_that_member() {
        let packages = parse(WORKSPACE_OWNERS);
        assert_eq!(
            collapsed_for(&packages, "packages/a").as_deref(),
            Some("3.0.0")
        );
        assert_eq!(
            collapsed_for(&packages, "packages/b").as_deref(),
            Some("2.0.0")
        );
        assert_eq!(collapsed_for(&packages, "").as_deref(), Some("4.0.0"));
        assert_eq!(
            collapsed_for(&packages, "packages/c").as_deref(),
            Some("4.0.0"),
            "a member without its own entry resolves through the root"
        );
        assert_eq!(versions(&packages, "inner"), ["1.0.0"]);
    }

    /// Intended (#1993, extends #1981 to bun): a copy nested under another package stops being
    /// a lock alternative once a hoisted entry of the same name exists.
    #[test]
    fn nested_copies_are_demoted_when_a_hoisted_entry_exists() {
        let naming = deps_core::test_util::StubFormatter::new();
        let (versions, candidates) = parse(V3_NESTED).split_normalized(&naming);
        assert_eq!(
            versions
                .iter()
                .find(|(name, _)| name.as_str() == "is-number")
                .map(|(_, version)| version.as_str()),
            Some("7.0.0")
        );
        assert!(
            candidates.keys().all(|name| name.as_str() != "is-number"),
            "{candidates:?}"
        );
    }

    /// Owners are a set per `(name, version)`: a repeated importer is one entry, and N members
    /// give exactly N entries (no per-insert linear scan).
    #[test]
    fn owners_are_deduplicated_per_name_and_version() {
        const MEMBERS: usize = 500;
        let mut workspaces = vec![r#""": {"name": "root"}"#.to_string()];
        let mut entries = vec![
            r#""x": ["x@1.0.0", "", {}, "sha512-a"]"#.to_string(),
            r#""alias": ["x@1.0.0", "", {}, "sha512-a"]"#.to_string(),
        ];
        for n in 0..MEMBERS {
            workspaces.push(format!(r#""p{n}": {{"name": "w{n}"}}"#));
            entries.push(format!(r#""w{n}/x": ["x@1.0.0", "", {{}}, "sha512-a"]"#));
        }
        let content = format!(
            r#"{{"lockfileVersion": 1, "workspaces": {{{}}}, "packages": {{{}}}}}"#,
            workspaces.join(","),
            entries.join(",")
        );
        assert_eq!(parse(&content).all("x").unwrap().len(), MEMBERS + 1);
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
        assert!(message.contains('…'), "{message}");
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
    fn unrecognized_workspace_shapes_are_ignored_without_failing_the_file() {
        for workspaces in [
            "[]",
            "7",
            r#""x""#,
            "null",
            r#"{"": 1, "a": [], "b": {"name": 7}, "c": {"name": {"n": []}}}"#,
        ] {
            let packages = parse(&format!(
                r#"{{"lockfileVersion": 3, "workspaces": {workspaces},
                    "packages": {{"ok": ["ok@1.2.3"]}}}}"#
            ));
            assert_eq!(packages.version("ok"), Some("1.2.3"), "{workspaces}");
        }
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
