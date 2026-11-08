//! `yarn.lock` parsing (Yarn classic v1 and Yarn Berry), spec 089.
//!
//! Only resolved-version extraction is implemented: checksums, `resolved` URLs beyond source
//! classification, and dependency graphs are out of scope. The input is untrusted repository
//! content, so both parsers are single-pass and linear in the input size.

use std::borrow::Cow;
use std::collections::HashSet;

use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource};
use deps_core::yaml_scalar_string;
use yaml_rust2::{Yaml, YamlLoader};

const FILE_TYPE: &str = "yarn.lock";

/// Most distinct package names recorded from one v1 entry header. A header normally lists a
/// handful of specifiers; the cap bounds the per-entry fan-out of a crafted header.
const MAX_V1_NAMES_PER_HEADER: usize = 256;

/// Lowest supported Berry `__metadata.version` (spec 089 FR-014).
const MIN_BERRY_METADATA_VERSION: u32 = 4;
/// Highest supported Berry `__metadata.version`; newer lock files fail closed (FR-014).
const MAX_BERRY_METADATA_VERSION: u32 = 8;

/// Which `yarn.lock` dialect the content is written in (FR-004), decided from content only.
#[derive(Clone, Copy, PartialEq, Eq)]
enum YarnFormat {
    /// Yarn classic's custom line format.
    V1,
    /// Yarn 2+ (Berry) YAML, identified by its top-level `__metadata` key.
    Berry,
}

impl YarnFormat {
    fn detect(content: &str) -> Self {
        if content.lines().any(|line| line.starts_with("__metadata:")) {
            Self::Berry
        } else {
            Self::V1
        }
    }
}

/// Parses `yarn.lock` content (already read and size-capped) into resolved packages.
///
/// # Errors
///
/// Returns [`DepsError::ParseError`] for malformed Berry YAML, an unsupported Berry
/// `__metadata.version`, an unsupported v1 header version, or content exceeding the shared
/// YAML bounds.
pub(super) fn parse_yarn_lock(content: &str) -> Result<ResolvedPackages> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    match YarnFormat::detect(content) {
        YarnFormat::V1 => parse_v1(content),
        YarnFormat::Berry => parse_berry(content),
    }
}

fn parse_error(message: &str) -> DepsError {
    DepsError::parse_error(FILE_TYPE, &message)
}

fn skip_non_semver(name: &str, version: &str) -> bool {
    if node_semver::Version::parse(version).is_ok() {
        return false;
    }
    tracing::debug!(
        package = ?name,
        version = %deps_core::redact::redact_declaration_key(version),
        "skipping yarn.lock entry with non-semver version"
    );
    true
}

/// Splits `name@range` (scoped names start with `@`) at the first `@` after the first
/// character. Returns `None` when there is no range part.
fn split_specifier(specifier: &str) -> Option<(&str, &str)> {
    let at = specifier
        .char_indices()
        .skip(1)
        .find_map(|(i, c)| (c == '@').then_some(i))?;
    let (name, range) = specifier.split_at(at);
    Some((name, range.strip_prefix('@').unwrap_or(range)))
}

/// Real package name behind a specifier, unwrapping `alias@npm:real@range` (FR-008).
fn real_name(specifier: &str) -> Option<(&str, &str)> {
    let (name, range) = split_specifier(specifier)?;
    // `npm:^1.0.0` (no inner `@`) is the plain registry form, not an alias.
    let aliased = range.strip_prefix("npm:").and_then(split_specifier);
    Some(aliased.unwrap_or((name, range)))
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

// ---------------------------------------------------------------- Yarn v1

#[derive(Default)]
struct V1Entry<'a> {
    header: &'a str,
    field_indent: Option<usize>,
    version: Option<&'a str>,
    resolved: Option<&'a str>,
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

fn parse_v1(content: &str) -> Result<ResolvedPackages> {
    let mut packages = ResolvedPackages::new();
    let mut current: Option<V1Entry<'_>> = None;

    for raw in content.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let indent = indent_of(line);

        if indent == 0 {
            if let Some(entry) = current.take() {
                finish_v1_entry(&entry, &mut packages);
            }
            if let Some(comment) = line.strip_prefix('#') {
                check_v1_header_version(comment)?;
            } else if let Some(header) = line.strip_suffix(':') {
                current = Some(V1Entry {
                    header,
                    ..V1Entry::default()
                });
            }
            continue;
        }

        let Some(entry) = current.as_mut() else {
            continue;
        };
        let field_indent = *entry.field_indent.get_or_insert(indent);
        if indent != field_indent {
            continue;
        }
        let Some((key, value)) = line.trim_start().split_once([' ', '\t']) else {
            continue;
        };
        let value = unquote(value);
        match key {
            "version" => entry.version = Some(value),
            "resolved" => entry.resolved = Some(value),
            _ => {}
        }
    }
    if let Some(entry) = current.take() {
        finish_v1_entry(&entry, &mut packages);
    }

    Ok(packages)
}

/// Rejects a `# yarn lockfile vN` header whose `N` is not `1` (FR-014).
fn check_v1_header_version(comment: &str) -> Result<()> {
    let Some(version) = comment.trim().strip_prefix("yarn lockfile v") else {
        return Ok(());
    };
    if version == "1" {
        return Ok(());
    }
    Err(parse_error(&format!(
        "unsupported yarn lockfile version '{}'",
        deps_core::redact::redact_declaration_key(version)
    )))
}

fn finish_v1_entry(entry: &V1Entry<'_>, packages: &mut ResolvedPackages) {
    let Some(version) = entry.version else {
        tracing::debug!("skipping yarn.lock entry with no version");
        return;
    };

    let mut seen: HashSet<&str> = HashSet::new();
    for specifier in entry.header.split(',') {
        if seen.len() >= MAX_V1_NAMES_PER_HEADER {
            tracing::debug!("yarn.lock entry header lists too many packages; ignoring the rest");
            break;
        }
        let Some((name, range)) = real_name(unquote(specifier)) else {
            continue;
        };
        if !seen.insert(name) || skip_non_semver(name, version) {
            continue;
        }
        packages.insert(ResolvedPackage::new(
            name.to_string(),
            version.to_string(),
            v1_source(range, entry.resolved.unwrap_or_default()),
        ));
    }
}

/// Classifies a v1 entry's source. Only the registry-vs-not distinction is consumed
/// downstream, so url/checksum/rev stay empty: copying the `resolved` line per package name
/// would multiply memory by the header's name count and retain credential-bearing git URLs.
fn v1_source(range: &str, resolved: &str) -> ResolvedSource {
    if range.starts_with("file:") || range.starts_with("link:") {
        return ResolvedSource::Path {
            path: String::new(),
        };
    }
    let is_git = ["git+", "git://", "git@", "github:"]
        .iter()
        .any(|prefix| range.starts_with(prefix) || resolved.starts_with(prefix));
    if is_git {
        return ResolvedSource::Git {
            url: String::new(),
            rev: String::new(),
        };
    }
    ResolvedSource::Registry {
        url: String::new(),
        checksum: String::new(),
    }
}

// ------------------------------------------------------------- Yarn Berry

/// What a Berry `resolution` reference (the part after `name@`) points at.
enum BerryRef<'a> {
    /// `npm:<version>`: a registry package.
    Npm(&'a str),
    /// `patch:<inner>#...`: a patched package; resolves to the inner reference.
    Patch(&'a str),
    /// A local-only reference (`workspace:`, `link:`, `portal:`, `exec:`): not a registry
    /// package, contributes nothing (FR-007).
    LocalOnly,
    /// `file:<path>`.
    File(&'a str),
    /// Anything else (git, github, tarball URLs): a remote, non-registry source.
    Remote(&'a str),
}

impl<'a> BerryRef<'a> {
    fn classify(reference: &'a str) -> Self {
        if let Some(version) = reference.strip_prefix("npm:") {
            Self::Npm(version)
        } else if let Some(inner) = reference.strip_prefix("patch:") {
            Self::Patch(inner)
        } else if ["workspace:", "link:", "portal:", "exec:"]
            .iter()
            .any(|p| reference.starts_with(p))
        {
            Self::LocalOnly
        } else if let Some(path) = reference.strip_prefix("file:") {
            Self::File(path)
        } else {
            Self::Remote(reference)
        }
    }
}

fn percent_decode(input: &str) -> Cow<'_, str> {
    if !input.contains('%') {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let decoded = (b == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| {
                let &[hi, lo] = hex else { return None };
                let hi = char::from(hi).to_digit(16)?;
                let lo = char::from(lo).to_digit(16)?;
                u8::try_from(hi * 16 + lo).ok()
            });
        if let Some(byte) = decoded {
            out.push(byte);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// Name and reference of the package a Berry `resolution` ultimately points at, unwrapping a
/// single `patch:` layer (FR-008). A nested patch is not unwrapped further, which bounds the
/// work to one extra pass regardless of input shape.
fn resolve_berry_reference(resolution: &str) -> Option<(String, String)> {
    let (name, reference) = split_specifier(resolution)?;
    let BerryRef::Patch(inner) = BerryRef::classify(reference) else {
        return Some((name.to_string(), reference.to_string()));
    };
    let inner = inner.split_once('#').map_or(inner, |(head, _)| head);
    let decoded = percent_decode(inner);
    let (inner_name, inner_reference) = split_specifier(&decoded)?;
    Some((inner_name.to_string(), inner_reference.to_string()))
}

fn check_berry_metadata(doc: &Yaml) -> Result<()> {
    let Some(raw) = yaml_scalar_string(&doc["__metadata"]["version"]) else {
        return Err(parse_error("missing or non-scalar __metadata.version"));
    };
    let version: u32 = raw.parse().map_err(|_| {
        parse_error(&format!(
            "unparseable __metadata.version '{}'",
            deps_core::redact::redact_declaration_key(&raw)
        ))
    })?;
    if (MIN_BERRY_METADATA_VERSION..=MAX_BERRY_METADATA_VERSION).contains(&version) {
        Ok(())
    } else {
        Err(parse_error(&format!(
            "unsupported __metadata.version '{version}' (supported \
             {MIN_BERRY_METADATA_VERSION}..={MAX_BERRY_METADATA_VERSION})"
        )))
    }
}

fn parse_berry(content: &str) -> Result<ResolvedPackages> {
    deps_core::check_yaml_bounds(content, FILE_TYPE)?;

    let docs = YamlLoader::load_from_str(content).map_err(|e| {
        parse_error(&format!(
            "invalid YAML: {}",
            deps_core::net_policy::redact_parse_error_for_log(&e.to_string())
        ))
    })?;
    let Some(doc) = docs.first() else {
        return Ok(ResolvedPackages::new());
    };
    check_berry_metadata(doc)?;

    let mut packages = ResolvedPackages::new();
    let Yaml::Hash(entries) = doc else {
        return Ok(packages);
    };

    for (key, entry) in entries {
        let Some(key) = key.as_str() else { continue };
        if key == "__metadata" {
            continue;
        }
        if let Some(package) = berry_package(key, entry) {
            packages.insert(package);
        }
    }
    Ok(packages)
}

fn berry_package(key: &str, entry: &Yaml) -> Option<ResolvedPackage> {
    let entry_version = yaml_scalar_string(&entry["version"]);

    let (name, reference) = match entry["resolution"].as_str() {
        Some(resolution) => resolve_berry_reference(resolution)?,
        None => {
            let (name, _) = real_name(unquote(key.split(',').next()?))?;
            (name.to_string(), "npm:".to_string())
        }
    };

    let (version, source) = match BerryRef::classify(&reference) {
        BerryRef::Npm(resolved) => (
            if entry["resolution"].is_badvalue() {
                entry_version?
            } else {
                // Private registries append `::__archiveUrl=...` to the resolution.
                resolved
                    .split_once("::")
                    .map_or(resolved, |(v, _)| v)
                    .to_string()
            },
            ResolvedSource::Registry {
                url: String::new(),
                checksum: entry["checksum"].as_str().unwrap_or_default().to_string(),
            },
        ),
        BerryRef::File(path) => (
            entry_version?,
            ResolvedSource::Path {
                path: path.to_string(),
            },
        ),
        BerryRef::Remote(url) => {
            let (base, fragment) = url.split_once('#').unwrap_or((url, ""));
            let rev = fragment.strip_prefix("commit=").unwrap_or(fragment);
            (
                entry_version?,
                ResolvedSource::Git {
                    url: base.to_string(),
                    rev: rev.to_string(),
                },
            )
        }
        BerryRef::Patch(_) | BerryRef::LocalOnly => return None,
    };

    if skip_non_semver(&name, &version) {
        return None;
    }
    Some(ResolvedPackage::new(name, version, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn parse(content: &str) -> ResolvedPackages {
        parse_yarn_lock(content).unwrap()
    }

    #[test]
    fn v1_simple_multi_specifier_and_scoped() {
        let packages = parse(
            r#"# THIS IS AN AUTOGENERATED FILE.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#abc"
  integrity sha512-xyz
  dependencies:
    "@babel/highlight" "^7.12.13"

request@^2.88.2:
  version "2.88.2"
  resolved "https://registry.yarnpkg.com/request/-/request-2.88.2.tgz#def"
"#,
        );
        assert_eq!(packages.len(), 2);
        assert_eq!(packages.version("@babel/code-frame"), Some("7.12.13"));
        assert_eq!(packages.all("@babel/code-frame").unwrap().len(), 1);
        assert_eq!(packages.version("request"), Some("2.88.2"));
        assert!(packages.get("request").unwrap().source.is_registry());
    }

    #[test]
    fn v1_alias_resolves_real_name() {
        let packages = parse("\"my-react@npm:react@^18.0.0\":\n  version \"18.2.0\"\n");
        assert_eq!(packages.version("react"), Some("18.2.0"));
        assert_eq!(packages.version("my-react"), None);
    }

    #[test]
    fn v1_scoped_alias_resolves_real_name() {
        let packages = parse("\"p@npm:@myorg/pkg@^1.0.0\":\n  version \"1.2.3\"\n");
        assert_eq!(packages.version("@myorg/pkg"), Some("1.2.3"));
    }

    #[test]
    fn v1_several_versions_of_one_name_are_all_recorded() {
        let packages = parse(
            "lodash@^3.0.0:\n  version \"3.10.1\"\n\nlodash@^4.0.0:\n  version \"4.17.21\"\n",
        );
        assert_eq!(packages.all("lodash").unwrap().len(), 2);
        assert_eq!(packages.version("lodash"), Some("4.17.21"));
    }

    #[test]
    fn v1_crlf_bom_and_tabs_parse_like_lf() {
        let packages =
            parse("\u{feff}# yarn lockfile v1\r\n\r\nfoo@^1.0.0:\r\n\tversion \"1.2.3\"\r\n");
        assert_eq!(packages.version("foo"), Some("1.2.3"));
    }

    #[test]
    fn v1_header_without_version_is_skipped_and_parse_continues() {
        let packages =
            parse("broken@^1.0.0:\n  resolved \"x\"\n\nok@^1.0.0:\n  version \"1.0.0\"\n");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages.version("ok"), Some("1.0.0"));
    }

    #[test]
    fn v1_nested_dependency_version_field_is_not_the_entry_version() {
        let packages =
            parse("a@^1.0.0:\n  version \"1.0.0\"\n  dependencies:\n    version \"9.9.9\"\n");
        assert_eq!(packages.version("a"), Some("1.0.0"));
    }

    #[test]
    fn v1_non_semver_version_is_skipped() {
        let packages = parse("a@^1.0.0:\n  version \"not-a-version\"\n");
        assert!(packages.is_empty());
    }

    #[test]
    fn v1_file_and_git_specifiers_map_to_non_registry_sources() {
        let packages = parse(
            "\"loc@file:../loc\":\n  version \"1.0.0\"\n\n\
             \"g@git+https://github.com/u/g.git#abc\":\n  version \"2.0.0\"\n  resolved \"git+https://github.com/u/g.git#abc\"\n",
        );
        assert_matches!(
            &packages.get("loc").unwrap().source,
            ResolvedSource::Path { .. }
        );
        assert_matches!(
            &packages.get("g").unwrap().source,
            ResolvedSource::Git { .. }
        );
    }

    #[test]
    fn v1_header_name_fan_out_is_capped_and_sources_carry_no_copied_strings() {
        let names = MAX_V1_NAMES_PER_HEADER * 4;
        let header = (0..names)
            .map(|i| format!("p{i}@^1.0.0"))
            .collect::<Vec<_>>()
            .join(", ");
        let resolved = "x".repeat(100_000);
        let packages = parse(&format!(
            "{header}:\n  version \"1.0.0\"\n  resolved \"{resolved}\"\n  integrity sha512-abc\n"
        ));
        assert_eq!(packages.len(), MAX_V1_NAMES_PER_HEADER);
        for (_, package) in packages.iter() {
            assert_matches!(
                &package.source,
                ResolvedSource::Registry { url, checksum } if url.is_empty() && checksum.is_empty()
            );
        }
    }

    #[test]
    fn v1_missing_version_log_does_not_include_the_header() {
        let secret = "https://user:ghp_SECRETTOKEN@host/repo.git";
        let content = format!("\"g@git+{secret}\":\n  resolved \"x\"\n");
        let log = deps_core::test_util::capture_tracing_output_at(tracing::Level::DEBUG, || {
            assert!(parse(&content).is_empty());
        });
        assert!(!log.contains("ghp_SECRETTOKEN"), "{log}");
    }

    #[test]
    fn v1_unsupported_header_version_is_parse_error() {
        assert_matches!(
            parse_yarn_lock("# yarn lockfile v2\n"),
            Err(DepsError::ParseError { .. })
        );
    }

    #[test]
    fn empty_and_comment_only_content_is_empty() {
        assert!(parse("").is_empty());
        assert!(parse("# yarn lockfile v1\n\n").is_empty());
    }

    const BERRY: &str = r#"# This file is generated by running "yarn install"

__metadata:
  version: 8
  cacheKey: 10c0

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/abc
  languageName: node
  linkType: hard

"my-react@npm:react@^18.0.0":
  version: 18.2.0
  resolution: "react@npm:18.2.0"
  languageName: node
  linkType: hard

"typescript@patch:typescript@npm%3A^5.3.0#optional!builtin<compat/typescript>":
  version: 5.3.3
  resolution: "typescript@patch:typescript@npm%3A5.3.3#optional!builtin<compat/typescript>::version=5.3.3&hash=e012d7"
  languageName: node
  linkType: hard

"@types/node@npm:^20.0.0":
  version: 20.1.0
  resolution: "@types/node@npm:20.1.0"
  languageName: node
  linkType: hard

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  languageName: unknown
  linkType: soft

"sib@link:../sib::locator=app%40workspace%3A.":
  version: 0.0.0-use.local
  resolution: "sib@link:../sib::locator=app%40workspace%3A."
  languageName: node
  linkType: soft

"gitdep@https://github.com/u/gitdep.git#commit=deadbeef":
  version: 1.0.0
  resolution: "gitdep@https://github.com/u/gitdep.git#commit=deadbeef"
  languageName: node
  linkType: hard
"#;

    #[test]
    fn berry_registry_alias_patch_scoped() {
        let packages = parse(BERRY);
        assert_eq!(packages.version("lodash"), Some("4.17.21"));
        assert_eq!(packages.version("react"), Some("18.2.0"));
        assert_eq!(packages.version("my-react"), None);
        assert_eq!(packages.version("typescript"), Some("5.3.3"));
        assert_eq!(packages.version("@types/node"), Some("20.1.0"));
    }

    #[test]
    fn berry_archive_url_suffix_is_stripped_from_the_version() {
        let packages = parse(
            "__metadata:\n  version: 8\n\n\"priv@npm:^1.0.0\":\n  version: 1.2.3\n  resolution: \"priv@npm:1.2.3::__archiveUrl=https%3A%2F%2Freg.example%2Fpriv.tgz\"\n\n\"pp@patch:pp@npm%3A2.0.0%3A%3A__archiveUrl=https%253A%252F%252Fr%252Fpp.tgz#x\":\n  version: 2.0.0\n  resolution: \"pp@patch:pp@npm%3A2.0.0%3A%3A__archiveUrl=https%253A%252F%252Fr%252Fpp.tgz#x\"\n",
        );
        assert_eq!(packages.version("priv"), Some("1.2.3"));
        assert_eq!(packages.version("pp"), Some("2.0.0"));
    }

    #[test]
    fn berry_workspace_and_link_entries_are_skipped() {
        let packages = parse(BERRY);
        assert_eq!(packages.version("app"), None);
        assert_eq!(packages.version("sib"), None);
    }

    #[test]
    fn berry_git_entry_is_not_a_registry_package() {
        let packages = parse(BERRY);
        assert_matches!(
            &packages.get("gitdep").unwrap().source,
            ResolvedSource::Git { url, rev }
                if url == "https://github.com/u/gitdep.git" && rev == "deadbeef"
        );
    }

    #[test]
    fn berry_unsupported_metadata_version_fails_closed() {
        let err = parse_yarn_lock("__metadata:\n  version: 9\n").unwrap_err();
        assert!(err.to_string().contains('9'), "{err}");
        assert_matches!(
            parse_yarn_lock("__metadata:\n  version: 3\n"),
            Err(DepsError::ParseError { .. })
        );
    }

    #[test]
    fn berry_only_metadata_is_empty() {
        assert!(parse("__metadata:\n  version: 8\n  cacheKey: 10c0\n").is_empty());
    }

    #[test]
    fn berry_malformed_yaml_is_parse_error() {
        assert_matches!(
            parse_yarn_lock("__metadata:\n  version: 8\nx: [unterminated\n"),
            Err(DepsError::ParseError { .. })
        );
    }

    #[test]
    fn berry_missing_resolution_falls_back_to_key_and_version() {
        let packages =
            parse("__metadata:\n  version: 6\n\n\"left-pad@npm:^1.0.0\":\n  version: 1.3.0\n");
        assert_eq!(packages.version("left-pad"), Some("1.3.0"));
    }

    #[test]
    fn berry_nested_patch_is_skipped_not_recursed() {
        let packages = parse(
            "__metadata:\n  version: 8\n\n\"a@patch:a@patch:a@npm%3A1.0.0#x#y\":\n  version: 1.0.0\n  resolution: \"a@patch:a@patch:a@npm%3A1.0.0#x#y\"\n",
        );
        assert!(packages.is_empty());
    }

    #[test]
    fn percent_decode_handles_invalid_sequences() {
        assert_eq!(percent_decode("a%3Ab"), "a:b");
        assert_eq!(percent_decode("a%zzb%"), "a%zzb%");
    }

    #[test]
    fn format_detection_is_content_based() {
        assert!(YarnFormat::detect("__metadata:\n  version: 8\n") == YarnFormat::Berry);
        assert!(YarnFormat::detect("# yarn lockfile v1\n") == YarnFormat::V1);
    }
}
