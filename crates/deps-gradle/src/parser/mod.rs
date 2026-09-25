//! Gradle manifest parser dispatcher.
//!
//! Routes parsing to the appropriate module based on file extension/name.

pub mod catalog;
pub mod groovy;
pub mod kotlin;
pub mod properties;
pub mod settings;

use crate::types::GradleDependency;
use deps_core::Result;
use deps_core::position::{Position, Range};
use regex::{Captures, Regex};
use std::collections::HashMap;
use std::sync::LazyLock;
use url::Url;

pub use deps_core::lsp_helpers::LineOffsetTable;

/// Configuration words that follow neither the suffix convention
/// ([`CONFIGURATION_SUFFIXES`]) nor the prefix convention
/// ([`CONFIGURATION_PREFIXES`]) and must be matched literally.
///
/// Includes the pre-Gradle-7 legacy configurations `compile`, `testCompile`,
/// and `provided`: Gradle still parses them regardless of which DSL a build
/// script uses, so a `build.gradle.kts` migrated from an old `build.gradle`
/// (or targeting a project not yet updated) can legitimately contain them.
/// Restricting recognition to one DSL would be silent drift, not an
/// intentional scoping decision. `classpath` has no variant form at all.
const CONFIGURATION_LITERALS: &[&str] = &["classpath", "compile", "testCompile", "provided"];

/// `(bare, suffix)` pairs for configuration base words that Gradle core
/// plugins (`java`, `java-library`) and common first-party plugins (Android
/// Gradle Plugin, `java-test-fixtures`) combine with an arbitrary
/// variant/source-set prefix, e.g. `debugImplementation`,
/// `androidTestImplementation`, `testFixturesImplementation` — and
/// `compileOnlyApi`, matched by the `Api` suffix.
///
/// `bare` is the word used with no prefix (`implementation`); `suffix` is the
/// same word capitalized, as it appears after a prefix. A literal whitelist
/// can't keep up with plugin-registered configurations following this
/// convention (arbitrary build types/flavors in Android, custom source
/// sets), so membership is decided by suffix instead — safe because Gradle
/// itself treats any name ending in one of these words as that kind of
/// configuration.
const CONFIGURATION_SUFFIXES: &[(&str, &str)] = &[
    ("implementation", "Implementation"),
    ("api", "Api"),
    ("compileOnly", "CompileOnly"),
    ("runtimeOnly", "RuntimeOnly"),
    ("annotationProcessor", "AnnotationProcessor"),
];

/// Kotlin annotation-processing plugin configurations (`kapt`, KSP's `ksp`)
/// follow a *prefix* convention instead: bare for the main source set, or
/// `<word><Variant>` for others — e.g. `kaptTest`, `kaptAndroidTest`,
/// `kspDebug`, `kspCommonMainMetadata`. [`CONFIGURATION_SUFFIXES`] can't
/// express this since the variant comes after the word, not before it.
const CONFIGURATION_PREFIXES: &[&str] = &["kapt", "ksp"];

/// Returns whether `config` is a recognized Gradle dependency configuration
/// word: a legacy literal ([`CONFIGURATION_LITERALS`]), a name ending in one
/// of [`CONFIGURATION_SUFFIXES`]'s base words, or a name starting with one of
/// [`CONFIGURATION_PREFIXES`]'s words followed by a capitalized variant.
pub(crate) fn is_dependency_configuration(config: &str) -> bool {
    CONFIGURATION_LITERALS.contains(&config)
        || CONFIGURATION_SUFFIXES
            .iter()
            .any(|(bare, suffix)| config == *bare || config.ends_with(suffix))
        || CONFIGURATION_PREFIXES.iter().any(|prefix| {
            config == *prefix
                || config
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()))
        })
}

/// Returns whether `trimmed` (a line with surrounding whitespace stripped)
/// opens a Gradle `dependencies { }` block.
///
/// Requires the brace to follow the `dependencies` keyword (any amount of
/// whitespace, including none, in between) so that unrelated blocks whose
/// name merely starts with the word — e.g. Android's `dependenciesInfo { }`
/// — aren't mistaken for it.
pub(crate) fn opens_dependencies_block(trimmed: &str) -> bool {
    trimmed
        .strip_prefix("dependencies")
        .is_some_and(|rest| rest.trim_start().starts_with('{'))
}

/// Builds a [`GradleDependency`] from a regex match's captures.
///
/// All Groovy and Kotlin DSL regex variants share identical capture group
/// indices — 1: configuration, 2: group id, 3: artifact id, 4: version (when
/// present) — so `has_version` alone distinguishes the two capture shapes.
pub(crate) fn build_dependency(
    caps: &Captures<'_>,
    line: &str,
    line_idx: u32,
    has_version: bool,
    config: &str,
) -> GradleDependency {
    debug_assert_eq!(
        caps.len(),
        if has_version { 5 } else { 4 },
        "regex capture count must match has_version so group 4 (version) is only read when present"
    );

    let match_start = caps.get(0).map_or(0, |m| m.start());
    let group_id = caps.get(2).map_or("", |m| m.as_str()).to_string();
    let artifact_id = caps.get(3).map_or("", |m| m.as_str()).to_string();
    let name = format!("{group_id}:{artifact_id}");
    let name_range = find_name_range(line, line_idx, match_start, &group_id, &artifact_id);

    let (version_req, version_range) = if has_version {
        let version = caps.get(4).map_or("", |m| m.as_str()).trim().to_string();
        let version_range = find_version_range(line, line_idx, match_start, &version);
        (Some(version.into()), Some(version_range))
    } else {
        (None, None)
    };

    GradleDependency {
        group_id,
        artifact_id,
        name: name.into(),
        name_range,
        version_req,
        version_range,
        configuration: config.to_string(),
        source: deps_core::parser::DependencySource::Registry,
    }
}

/// Result of parsing a Gradle build script, settings file, or version catalog.
#[non_exhaustive]
#[derive(Debug)]
pub struct GradleParseResult {
    /// Dependencies found in the file.
    pub dependencies: Vec<GradleDependency>,
    /// URI of the manifest this result was parsed from.
    pub uri: Url,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

/// Resolves `$var` and `${var}` references in dependency versions using the given properties map.
///
/// If a version is a variable reference and the variable is found in `properties`,
/// the version is replaced with the resolved value. The version_range is kept as-is
/// (pointing to the variable reference in source).
pub fn resolve_variables(deps: &mut [GradleDependency], properties: &HashMap<String, String>) {
    for dep in deps.iter_mut() {
        if let Some(ref ver) = dep.version_req
            && let Some(resolved) = resolve_variable_ref(ver.as_str(), properties)
        {
            dep.version_req = Some(resolved.into());
        }
    }
}

/// Returns the resolved value if `value` is a `$name` or `${name}` reference. Returns `None` otherwise.
fn resolve_variable_ref(value: &str, properties: &HashMap<String, String>) -> Option<String> {
    let trimmed = value.trim();
    if let Some(name) = trimmed.strip_circumfix("${", '}') {
        properties.get(name).cloned()
    } else if let Some(name) = trimmed.strip_prefix('$') {
        properties.get(name).cloned()
    } else {
        None
    }
}

/// Which Gradle manifest shape a URI's basename identifies (issue #1436), so the parser and
/// `ecosystem::GradleEcosystem::detect_completion_context` dispatch from the same
/// classification instead of independently re-deriving (and potentially diverging on) it from
/// the raw URI string — mirrors `deps_pypi::ecosystem::PypiManifestKind`'s `from_uri` pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GradleManifestKind {
    /// `libs.versions.toml` version catalog.
    Catalog,
    /// `settings.gradle`/`settings.gradle.kts`: plugin-management declarations, not the
    /// dependency-coordinate DSL `build.gradle(.kts)` uses.
    Settings,
    /// `build.gradle.kts` (Kotlin DSL).
    KotlinBuild,
    /// `build.gradle` (Groovy DSL).
    GroovyBuild,
    /// Not a recognized Gradle manifest shape.
    Other,
}

impl GradleManifestKind {
    pub(crate) fn from_uri(uri: &Url) -> Self {
        let path = uri.path();
        if path.ends_with("libs.versions.toml") {
            Self::Catalog
        } else if path.ends_with("settings.gradle.kts") || path.ends_with("settings.gradle") {
            Self::Settings
        } else if path.ends_with(".gradle.kts") {
            Self::KotlinBuild
        } else if path.ends_with(".gradle") {
            Self::GroovyBuild
        } else {
            Self::Other
        }
    }
}

/// Parses a Gradle file, dispatching to the catalog/settings/Kotlin-DSL/Groovy-DSL
/// parser based on its filename, then resolves `$var`/`${var}` property references
/// for build files.
///
/// # Errors
///
/// Returns an error if the file's dedicated parser fails (e.g. malformed TOML for
/// a version catalog).
pub fn parse_gradle(content: &str, uri: &Url) -> Result<GradleParseResult> {
    let kind = GradleManifestKind::from_uri(uri);
    let mut result = match kind {
        GradleManifestKind::Catalog => catalog::parse_version_catalog(content, uri)?,
        GradleManifestKind::Settings => settings::parse_settings(content, uri)?,
        GradleManifestKind::KotlinBuild => kotlin::parse_kotlin_dsl(content, uri)?,
        GradleManifestKind::GroovyBuild => groovy::parse_groovy_dsl(content, uri)?,
        GradleManifestKind::Other => {
            return Ok(GradleParseResult {
                dependencies: vec![],
                uri: uri.clone(),
                dependency_truncation: None,
            });
        }
    };

    if matches!(
        kind,
        GradleManifestKind::KotlinBuild | GradleManifestKind::GroovyBuild
    ) {
        // Directory derived via `resolve_manifest_file_path` (#1090), not the raw `uri.path()`
        // string used for dispatch above: that string has no scheme/host check, so joining it
        // straight onto `load_gradle_properties` would let a non-file:/remote-host URI read a
        // real gradle.properties from this process's local filesystem.
        if let Some(dir) = deps_core::lockfile::resolve_manifest_file_path(uri)
            .as_deref()
            .and_then(std::path::Path::parent)
        {
            let props = properties::load_gradle_properties(dir);
            if !props.is_empty() {
                resolve_variables(&mut result.dependencies, &props);
            }
        }

        // #1212: `content { includeGroup(...) }`-restricted `repositories { }` entries are a
        // real static per-group binding, unlike general-purpose `repositories { }` DSL
        // evaluation — pure text analysis, no filesystem access needed.
        let restrictions = parse_repository_content_restrictions(content);
        if !restrictions.is_empty() {
            apply_repository_content_restrictions(&mut result.dependencies, &restrictions);
        }
    }

    Ok(result)
}

deps_core::impl_parse_result!(
    GradleParseResult,
    GradleDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
    }
);

/// One `content { includeGroup(...) }`-style restriction read from a `repositories { }` block
/// (#1212), naming the repository's own declared `url` (empty when the block declares none,
/// e.g. a named repository resolved by a plugin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepositoryContentRestriction {
    /// The bound coordinate: a bare group id (`includeGroup`/`includeGroupByRegex`), or a
    /// `"group:module"` pair (`includeModule`) matched against the dependency's exact
    /// `group:artifact`.
    pattern: String,
    /// `true` when `pattern` is an `includeGroupByRegex` regular expression rather than an
    /// exact `includeGroup`/`includeModule` match.
    is_regex: bool,
    /// The repository's own declared `url`, becoming `CustomRegistry`'s `url` field for a
    /// matching dependency.
    repository_url: String,
}

// Compile-time-constant patterns; a malformed literal is a build-visible programmer error,
// not attacker-influenceable input.
#[allow(clippy::expect_used)]
static RE_INCLUDE_GROUP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"includeGroup\s*\(\s*["']([^"']+)["']\s*\)"#).expect("RE_INCLUDE_GROUP")
});
// Same guarantee as RE_INCLUDE_GROUP above.
#[allow(clippy::expect_used)]
static RE_INCLUDE_GROUP_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"includeGroupByRegex\s*\(\s*["']([^"']+)["']\s*\)"#)
        .expect("RE_INCLUDE_GROUP_REGEX")
});
// Same guarantee as RE_INCLUDE_GROUP above.
#[allow(clippy::expect_used)]
static RE_INCLUDE_MODULE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"includeModule\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*\)"#)
        .expect("RE_INCLUDE_MODULE")
});
/// Matches a repository's own `url` declaration inside its body: Kotlin's `url = uri("...")`/
/// `url = "..."`, or Groovy's `url '...'`/`url "..."`/`url = '...'` — both DSLs tolerated. Also
/// matches `setUrl("...")` and the Gradle 7/8 lazy-property idiom `url.set("...")`/
/// `url.set(uri("..."))` (impl-critic #3 follow-up to #1212).
// Same guarantee as RE_INCLUDE_GROUP above.
#[allow(clippy::expect_used)]
static RE_REPOSITORY_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:\burl\s*=?\s*(?:uri\()?|\bsetUrl\s*\(\s*|\burl\.set\s*\(\s*(?:uri\()?)["']([^"']+)["']\)?"#,
    )
    .expect("RE_REPOSITORY_URL")
});
/// Matches a repository call's own parenthesized URL argument, positional
/// (`maven("https://...")`) or named (`maven(url = "https://...")`) — G1 (impl-critic): the
/// idiomatic Kotlin DSL form for a repo declared with a `content { }` filter, e.g. `maven(
/// "https://...") { content { includeGroup("...") } }`. Anchored to the *whole* call-args text
/// (via [`extract_call_paren_url`]'s own extraction, not this pattern) so an unexpected extra
/// argument fails closed (no url) rather than guessing.
// Same guarantee as RE_INCLUDE_GROUP above.
#[allow(clippy::expect_used)]
static RE_REPO_CALL_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*(?:url\s*=\s*)?["']([^"']+)["']\s*$"#).expect("RE_REPO_CALL_URL")
});

/// Returns the byte index of the `}` matching the `{` at `open` (which must be a `{` byte),
/// tracking brace depth only — no string/comment awareness, the same fidelity as the rest of
/// this parser's line-scanning (a full Groovy/Kotlin lexer is out of scope, see
/// [`GradleDependency`]'s `source` doc). `None` if the file has no matching close.
///
/// Known limitation (impl-critic minor, documented not fixed): a `{`/`}` character inside a
/// `//` line comment or `/* */` block comment is counted as real nesting, desyncing the
/// remaining scan for the rest of the file. Not fixed by comment-stripping here because a
/// naive stripper would itself corrupt a `url = "https://..."` literal (`//` inside a URL is
/// not a comment) — a correct fix needs quote-aware scanning, out of scope for this pass.
fn find_matching_brace(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (i, b) in text.as_bytes().iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Byte ranges of every `buildscript { }` block found anywhere in `content` (#1212 impl-critic
/// S1, regardless of nesting depth — this is a linear text scan, not a depth-aware walk): a
/// `content { }` restriction declared inside `buildscript { repositories { ... } }` scopes
/// *plugin* resolution, not the project's own `dependencies { }` — [`parse_repository_content_restrictions`]
/// must never let it reclassify an unrelated project dependency.
// Every slice bound comes from `str::find` of the ASCII literal "buildscript"/"{" or from
// `find_matching_brace`'s brace byte position — always a char boundary.
#[allow(clippy::string_slice)]
fn find_buildscript_spans(content: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut search_from = 0usize;

    while let Some(rel) = content[search_from..].find("buildscript") {
        let kw_start = search_from + rel;
        let after_kw = kw_start + "buildscript".len();

        let preceded_by_ident_char = content
            .as_bytes()
            .get(kw_start.wrapping_sub(1))
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if kw_start > 0 && preceded_by_ident_char {
            search_from = after_kw;
            continue;
        }

        let rest = &content[after_kw..];
        let trimmed = rest.trim_start();
        if !trimmed.starts_with('{') {
            search_from = after_kw;
            continue;
        }
        let open = after_kw + (rest.len() - trimmed.len());
        let Some(close) = find_matching_brace(content, open) else {
            break;
        };

        spans.push((kw_start, close));
        search_from = close + 1;
    }

    spans
}

/// Scans `content` for every `repositories { }` block and, within each, every nested
/// repository entry (`maven { ... }`, `ivy { ... }`, etc.) that declares a `content { }`
/// restriction, returning one [`RepositoryContentRestriction`] per `includeGroup`/
/// `includeGroupByRegex`/`includeModule` call found.
///
/// Skips any `repositories { }` block nested inside a `buildscript { }` block (#1212
/// impl-critic S1, see [`find_buildscript_spans`]) — that scopes plugin resolution, not the
/// project's own dependencies.
///
/// Known limitations (impl-critic minor, documented not fixed): only `includeGroup`/
/// `includeGroupByRegex`/`includeModule` are read — Gradle's `exclusiveContent { }` wrapper and
/// `includeGroupAndSubgroups` are not, narrower than the full `content { }` DSL surface. See
/// also [`find_matching_brace`]'s doc for the comment-blindness limitation.
// Every slice bound here comes from `str::find` of an ASCII literal ("repositories", "{") or
// from `find_matching_brace`'s brace byte position — always a char boundary.
#[allow(clippy::string_slice)]
pub(crate) fn parse_repository_content_restrictions(
    content: &str,
) -> Vec<RepositoryContentRestriction> {
    let mut restrictions = Vec::new();
    let buildscript_spans = find_buildscript_spans(content);
    let mut search_from = 0usize;

    while let Some(rel) = content[search_from..].find("repositories") {
        let kw_start = search_from + rel;
        let after_kw = kw_start + "repositories".len();

        // Skip a longer identifier merely containing "repositories" (e.g. a hypothetical
        // "myRepositories" call) — never a real Gradle block.
        let preceded_by_ident_char = content
            .as_bytes()
            .get(kw_start.wrapping_sub(1))
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if kw_start > 0 && preceded_by_ident_char {
            search_from = after_kw;
            continue;
        }

        // S1: a `repositories { }` inside `buildscript { }` configures plugin resolution —
        // skip straight past the whole enclosing `buildscript { }` block.
        if let Some(&(_, span_end)) = buildscript_spans
            .iter()
            .find(|&&(start, end)| kw_start >= start && kw_start <= end)
        {
            search_from = span_end + 1;
            continue;
        }

        let rest = &content[after_kw..];
        let trimmed = rest.trim_start();
        if !trimmed.starts_with('{') {
            search_from = after_kw;
            continue;
        }
        let open = after_kw + (rest.len() - trimmed.len());
        let Some(close) = find_matching_brace(content, open) else {
            break;
        };

        extract_repository_entries(&content[open + 1..close], &mut restrictions);
        search_from = close + 1;
    }

    restrictions
}

/// Extracts a URL argument from the repository call's own parens immediately preceding `open`
/// (only whitespace allowed between the call's closing `)` and the `{` at `open`) — G1
/// (impl-critic): `maven("https://...") { }`/`maven(url = "https://...") { }`. `None` (not a
/// guess) if no call parens immediately precede `open` at all (a bare `maven { }`/`google { }`
/// shorthand), the parens are unbalanced, or the call-args text doesn't match a single url
/// argument.
///
/// Known limitation (impl-critic #5, documented not fixed): the backward paren-scan below has
/// no string-literal awareness — a URL containing a literal `)` (e.g.
/// `maven("https://example.com/api(v2)") { }`) desyncs the scan, and the restriction is
/// silently discarded via the caller's empty-url guard even though a real URL was declared.
/// Not fixed here for the same reason [`find_matching_brace`]'s comment-blindness isn't: a
/// correct fix needs quote-aware scanning, out of scope for this narrow pattern.
fn extract_call_paren_url(body: &str, open: usize) -> Option<String> {
    let before = body.get(..open)?;
    let trimmed = before.trim_end();
    if !trimmed.ends_with(')') {
        return None;
    }

    let mut depth = 0i32;
    let mut open_paren = None;
    for (i, &b) in trimmed.as_bytes().iter().enumerate().rev() {
        match b {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open_paren = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let open_paren = open_paren?;

    let call_args = trimmed.get(open_paren + 1..trimmed.len() - 1)?;
    RE_REPO_CALL_URL
        .captures(call_args)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Splits a `repositories { }` block's body into its individual `name { ... }` entries (via
/// [`find_matching_brace`]) and extracts each entry's content restrictions, if any.
// Every slice bound comes from `str::find('{')` or `find_matching_brace`'s brace byte
// position — always a char boundary.
#[allow(clippy::string_slice)]
fn extract_repository_entries(body: &str, out: &mut Vec<RepositoryContentRestriction>) {
    let mut pos = 0usize;
    while let Some(rel) = body[pos..].find('{') {
        let open = pos + rel;
        let Some(close) = find_matching_brace(body, open) else {
            break;
        };
        let entry = &body[open..=close];

        if let Some(content_body) = find_content_block(entry) {
            let url = RE_REPOSITORY_URL
                .captures(entry)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .or_else(|| extract_call_paren_url(body, open))
                .unwrap_or_default();

            // C1 (impl-critic): a shorthand repo call with no explicit `url = ...` literal —
            // `google()`/`mavenCentral()`/`gradlePluginPortal()`/`mavenLocal()` being the
            // canonical real-world cases (all commonly used with a `content { }` block to
            // restrict what they serve, e.g. Android's `google { content { includeGroupByRegex(
            // "androidx.*") } }`) — must never classify a matching dependency as
            // `CustomRegistry` with an empty url. These are registry-shaped repositories
            // (public or local-cache), not a non-registry signal; treat the whole entry as if
            // it declared no `content { }` restriction at all.
            if !url.is_empty() {
                for caps in RE_INCLUDE_GROUP.captures_iter(content_body) {
                    if let Some(group) = caps.get(1) {
                        out.push(RepositoryContentRestriction {
                            pattern: group.as_str().to_string(),
                            is_regex: false,
                            repository_url: url.clone(),
                        });
                    }
                }
                for caps in RE_INCLUDE_GROUP_REGEX.captures_iter(content_body) {
                    if let Some(group) = caps.get(1) {
                        out.push(RepositoryContentRestriction {
                            pattern: group.as_str().to_string(),
                            is_regex: true,
                            repository_url: url.clone(),
                        });
                    }
                }
                for caps in RE_INCLUDE_MODULE.captures_iter(content_body) {
                    if let (Some(group), Some(module)) = (caps.get(1), caps.get(2)) {
                        out.push(RepositoryContentRestriction {
                            pattern: format!("{}:{}", group.as_str(), module.as_str()),
                            is_regex: false,
                            repository_url: url.clone(),
                        });
                    }
                }
            }
        }

        // #2 (impl-critic, CRITICAL — caught before merge): multiple repository declarations
        // can be grouped inside a shared wrapper brace, e.g. `if (cond) { maven { ... } maven {
        // ... } }` — without this, `entry` above is the *whole* wrapper block, and
        // `find_content_block` only ever finds the first `content { }` in it, silently
        // dropping every sibling repository's own restriction (a privacy leak: that sibling's
        // dependency stays `Registry` and its name is sent to the public registry). Recursing
        // into this entry's own inner body finds any nested repo declaration alongside the
        // first one. Harmless when `entry` is itself a single ordinary repo call: recursing
        // into its own `content { }`/`credentials { }` sub-blocks finds no further nested
        // `content` keyword there, so no extra restriction is produced. Known minor byproduct:
        // when `entry` *is* a wrapper, the wrapper's own (over-broad) pass already pushed one
        // restriction for its first nested repo — recursion pushes that same restriction again,
        // correctly re-scoped, alongside every sibling's own. A harmless duplicate (`Vec`
        // entries, not classification behavior — `apply_repository_content_restrictions` is
        // idempotent per dependency), not a second bug — see
        // `test_multiple_maven_blocks_under_shared_wrapper_brace_all_collected`.
        if let Some(inner) = entry.get(1..entry.len().saturating_sub(1)) {
            extract_repository_entries(inner, out);
        }

        pos = close + 1;
    }
}

/// Finds a nested `content { }` block's own body within a single repository entry's text
/// (which itself already includes its outer `{`/`}` pair).
// Every slice bound comes from `str::find` of the ASCII literal "content"/"{" or from
// `find_matching_brace`'s brace byte position — always a char boundary.
#[allow(clippy::string_slice)]
fn find_content_block(entry: &str) -> Option<&str> {
    let rel = entry.find("content")?;
    let after = rel + "content".len();
    let preceded_by_ident_char = entry
        .as_bytes()
        .get(rel.wrapping_sub(1))
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
    if rel > 0 && preceded_by_ident_char {
        return None;
    }
    let rest = &entry[after..];
    let trimmed = rest.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    let open = after + (rest.len() - trimmed.len());
    let close = find_matching_brace(entry, open)?;
    Some(&entry[open + 1..close])
}

/// Compiles an `includeGroupByRegex` pattern (captured verbatim from Gradle Kotlin/Groovy
/// source) into a [`Regex`] matching Gradle's own whole-group-match semantics (#1212
/// impl-critic C2).
///
/// Two corrections vs. compiling the captured source text directly:
/// - Un-escapes a doubled backslash: `\\.` as written in a Kotlin/Groovy string literal means
///   a single `\.` after that language's own string-literal parsing, but this parser captures
///   the raw source text — compiling `\\.` directly means "a literal backslash then any
///   character", not "a literal dot", so the near-universal real-world spelling
///   (`includeGroupByRegex("com\\.acme.*")`) never matches anything.
/// - Anchors the pattern (`^(?:...)$`): Gradle's own implementation requires the *whole*
///   group id to match, not a substring — an unanchored `androidx.*` would also match an
///   unrelated group like `com.myandroidxtra.lib`.
fn compile_group_regex(pattern: &str) -> Option<Regex> {
    let unescaped = pattern.replace("\\\\", "\\");
    Regex::new(&format!("^(?:{unescaped})$")).ok()
}

/// Applies every [`RepositoryContentRestriction`] to `dependencies`, reclassifying a matching
/// dependency's `source` to [`deps_core::parser::DependencySource::CustomRegistry`] (#1212).
/// First matching restriction wins, mirroring Composer's own declaration-order classification
/// (`deps_composer::parser::classify_repositories`) — achieved here by iterating restrictions
/// in the outer loop and skipping a dependency once it is no longer `Registry`, rather than the
/// reverse nesting, so each restriction's regex compiles at most once per parse instead of once
/// per (dependency × restriction) pair (#1212 impl-critic S2 perf finding). An
/// `includeGroupByRegex` pattern that fails to compile matches nothing (fails closed).
pub(crate) fn apply_repository_content_restrictions(
    dependencies: &mut [GradleDependency],
    restrictions: &[RepositoryContentRestriction],
) {
    for restriction in restrictions {
        let compiled_regex = restriction
            .is_regex
            .then(|| compile_group_regex(&restriction.pattern));

        for dep in dependencies.iter_mut() {
            if !matches!(dep.source, deps_core::parser::DependencySource::Registry) {
                continue;
            }

            let is_match = if let Some((group, module)) = restriction.pattern.split_once(':') {
                dep.group_id == group && dep.artifact_id == module
            } else if let Some(maybe_re) = &compiled_regex {
                maybe_re
                    .as_ref()
                    .is_some_and(|re| re.is_match(&dep.group_id))
            } else {
                dep.group_id == restriction.pattern
            };

            if is_match {
                dep.source = deps_core::parser::DependencySource::CustomRegistry {
                    url: restriction.repository_url.clone(),
                };
            }
        }
    }
}

/// Returns the number of UTF-16 code units in `s`.
pub(crate) fn utf16_len(s: &str) -> usize {
    s.chars().map(|c| c.len_utf16()).sum()
}

/// Finds the LSP range of `"group_id:artifact_id"` within the dependency
/// declaration's own match span (`line[match_start..]`), not the whole line.
///
/// Scoping to `match_start` matters when two dependencies share an identical
/// coordinate on one line — e.g.
/// `implementation("a:b:1.0.0"); testImplementation("a:b:1.0.0")` — so the
/// second dependency's range isn't mis-attributed to the first's position.
// `match_start` is a regex match start; `abs_start` derives from `find` of an ASCII
// coordinate string. Every slice bound is always a char boundary.
#[allow(clippy::string_slice)]
pub(crate) fn find_name_range(
    line: &str,
    line_idx: u32,
    match_start: usize,
    group_id: &str,
    artifact_id: &str,
) -> Range {
    let scoped = &line[match_start..];
    let search = format!("{group_id}:{artifact_id}");
    if let Some(rel) = scoped.find(&search) {
        let abs_start = match_start + rel;
        let col_u32 = utf16_len(&line[..abs_start]) as u32;
        let end_u32 = col_u32 + utf16_len(&search) as u32;
        Range::new(
            Position::new(line_idx, col_u32),
            Position::new(line_idx, end_u32),
        )
    } else {
        Range::default()
    }
}

/// Finds the LSP range of `version` after the second `:` within the
/// dependency declaration's own match span (`line[match_start..]`), not the
/// whole line.
///
/// Scoping to `match_start` matters when two dependencies share the same
/// version string on one line — e.g.
/// `implementation("a:b:1.0.0"); implementation("c:d:1.0.0")` — so the
/// second dependency's range isn't mis-attributed to the first's position.
// `match_start` is a regex match start; `colon_pos` comes from `char_indices()`; `abs_start`
// derives from `find` of the version string. Every slice bound is always a char boundary.
#[allow(clippy::string_slice)]
pub(crate) fn find_version_range(
    line: &str,
    line_idx: u32,
    match_start: usize,
    version: &str,
) -> Range {
    let scoped = &line[match_start..];
    let second_colon = scoped
        .char_indices()
        .filter(|(_, c)| *c == ':')
        .nth(1)
        .map(|(i, _)| i);

    if let Some(colon_pos) = second_colon {
        let after_colon = &scoped[colon_pos + 1..];
        if let Some(rel) = after_colon.find(version) {
            let abs_start = match_start + colon_pos + 1 + rel;
            let col_start = utf16_len(&line[..abs_start]) as u32;
            let col_end = col_start + utf16_len(version) as u32;
            return Range::new(
                Position::new(line_idx, col_start),
                Position::new(line_idx, col_end),
            );
        }
    }
    Range::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uri(path: &str) -> Url {
        deps_core::test_util::test_uri(path)
    }

    #[test]
    fn test_dispatch_catalog() {
        let content = "[versions]\nspring = \"3.2.0\"\n\n[libraries]\nspring-boot = { module = \"org.springframework.boot:spring-boot-starter\", version.ref = \"spring\" }\n";
        let uri = make_uri("/project/gradle/libs.versions.toml");
        let result = parse_gradle(content, &uri).unwrap();
        assert!(!result.dependencies.is_empty());
    }

    #[test]
    fn test_dispatch_kotlin() {
        // Held per `deps_core::fs_probe::snapshot_guard`'s doc: `parse_gradle` calls
        // `properties::load_gradle_properties` for a `build.gradle`/`.kts` URI, which
        // transitively touches fs_probe, and this test runs in the same binary as
        // `parser/properties.rs`'s diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let content = "dependencies {\n    implementation(\"org.springframework.boot:spring-boot-starter:3.2.0\")\n}\n";
        let uri = make_uri("/project/build.gradle.kts");
        let result = parse_gradle(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_dispatch_groovy() {
        // See the comment in `test_dispatch_kotlin` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let content = "dependencies {\n    implementation 'org.springframework.boot:spring-boot-starter:3.2.0'\n}\n";
        let uri = make_uri("/project/build.gradle");
        let result = parse_gradle(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_dispatch_settings_gradle() {
        let content = "pluginManagement {\n    plugins {\n        id \"org.jetbrains.kotlin.jvm\" version \"2.1.10\"\n    }\n}\n";
        let uri = make_uri("/project/settings.gradle");
        let result = parse_gradle(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_dispatch_settings_gradle_kts() {
        let content = "pluginManagement {\n    plugins {\n        id(\"org.springframework.boot\") version \"3.2.0\"\n    }\n}\n";
        let uri = make_uri("/project/settings.gradle.kts");
        let result = parse_gradle(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_dispatch_unknown() {
        let uri = make_uri("/project/something.xml");
        let result = parse_gradle("", &uri).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_resolve_variables_dollar_brace() {
        let props: HashMap<String, String> =
            [("kotlinVersion".to_string(), "2.1.10".to_string())].into();
        let mut deps = vec![GradleDependency {
            group_id: "org.jetbrains.kotlin".into(),
            artifact_id: "kotlin-stdlib".into(),
            name: "org.jetbrains.kotlin:kotlin-stdlib".into(),
            name_range: Range::default(),
            version_req: Some("${kotlinVersion}".into()),
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }];
        resolve_variables(&mut deps, &props);
        assert_eq!(deps[0].version_req, Some("2.1.10".into()));
    }

    #[test]
    fn test_resolve_variables_dollar_plain() {
        let props: HashMap<String, String> =
            [("springVersion".to_string(), "3.2.0".to_string())].into();
        let mut deps = vec![GradleDependency {
            group_id: "org.springframework.boot".into(),
            artifact_id: "spring-boot-starter".into(),
            name: "org.springframework.boot:spring-boot-starter".into(),
            name_range: Range::default(),
            version_req: Some("$springVersion".into()),
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }];
        resolve_variables(&mut deps, &props);
        assert_eq!(deps[0].version_req, Some("3.2.0".into()));
    }

    #[test]
    fn test_resolve_variables_not_found_keeps_raw() {
        let props: HashMap<String, String> = HashMap::new();
        let mut deps = vec![GradleDependency {
            group_id: "com.example".into(),
            artifact_id: "lib".into(),
            name: "com.example:lib".into(),
            name_range: Range::default(),
            version_req: Some("$unknownVar".into()),
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }];
        resolve_variables(&mut deps, &props);
        assert_eq!(deps[0].version_req, Some("$unknownVar".into()));
    }

    #[test]
    fn test_resolve_variables_literal_version_unchanged() {
        let props: HashMap<String, String> = [("v".to_string(), "9.9.9".to_string())].into();
        let mut deps = vec![GradleDependency {
            group_id: "com.example".into(),
            artifact_id: "lib".into(),
            name: "com.example:lib".into(),
            name_range: Range::default(),
            version_req: Some("1.2.3".into()),
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }];
        resolve_variables(&mut deps, &props);
        assert_eq!(deps[0].version_req, Some("1.2.3".into()));
    }

    /// #1090 S1: `parse_gradle` derived the `gradle.properties` search directory from the raw
    /// `uri.path()` string, never `to_file_path()`/a scheme+host guard — a non-`file:` scheme
    /// or remote-host `file:` URI would still walk and read a real on-disk `gradle.properties`
    /// as long as its path component looked like a real directory. Uses a real
    /// `gradle.properties` a bypass would resolve `$serdeVersion` from, to prove the guard
    /// (not merely a missing-directory coincidence) blocks it.
    #[test]
    fn test_parse_gradle_rejects_malicious_uri_for_property_resolution() {
        // See the comment in `test_dispatch_kotlin` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            temp_dir.path().join("gradle.properties"),
            "serdeVersion=1.0.0\n",
        )
        .unwrap();
        let manifest_path = temp_dir.path().join("build.gradle");
        let content = "dependencies {\n    implementation(\"com.example:lib:$serdeVersion\")\n}\n";

        let file_uri = Url::from_file_path(&manifest_path).unwrap();
        let path_part = file_uri.as_str().strip_prefix("file://").unwrap();

        // Positive control: a real `file:` URI must resolve the variable from the real
        // `gradle.properties` — proves the fixture itself is live.
        let good_result = parse_gradle(content, &file_uri).unwrap();
        assert_eq!(
            good_result.dependencies[0].version_req,
            Some("1.0.0".into()),
            "test premise: the real file: URI must resolve $serdeVersion from disk"
        );

        // `"file://attacker.example"` used to be a third prefix in this loop. It was removed
        // (#1090 guard-gap follow-up): when this test's real temp-dir path is
        // Windows-drive-letter-shaped (`C:\...`, as `tempfile::tempdir()` produces on a real
        // Windows machine), a `file:` URI with a non-empty host and that path cannot be
        // represented by a parsed `url::Url` at all — the WHATWG URL Standard's file-host
        // parsing rule (`SyntaxViolation::FileWithHostAndWindowsDrive`) strips the host
        // before this test's `parse_gradle` call (or any code holding only a `&Url`) can see
        // it, so that sub-case asserted an unreachable invariant and failed on
        // `windows-latest` CI. On Unix the path is never drive-letter-shaped, so the host
        // survives parsing and the per-layer host guard stays live and testable there — this
        // comment only concerns the Windows-shaped case, not a claim that the guard is dead
        // on every platform. This exact bypass is guarded and tested platform-independently
        // at the point where untrusted URIs are first parsed:
        // `deps_lsp::lsp_types_interop::from_lsp_uri`, see its test
        // `test_from_lsp_uri_rejects_windows_drive_host_bypass`.
        for prefix in ["untitled:", "https://attacker.example"] {
            let uri: Url = format!("{prefix}{path_part}").parse().unwrap();
            let result = parse_gradle(content, &uri).unwrap();
            assert_eq!(
                result.dependencies[0].version_req,
                Some("$serdeVersion".into()),
                "a malicious-scheme/host URI ({prefix}) must not resolve gradle.properties \
                 from a real directory"
            );
        }
    }

    #[test]
    fn test_parse_result_trait() {
        use deps_core::ParseResult;

        // See the comment in `test_dispatch_kotlin` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let uri = make_uri("/project/build.gradle");
        let result = parse_gradle("", &uri).unwrap();
        assert!(result.dependencies().is_empty());
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<GradleParseResult>());
    }

    #[test]
    fn test_line_offset_table() {
        let content = "line0\nline1\nline2";
        let table = LineOffsetTable::new(content);
        let pos = table.byte_offset_to_position(content, 6);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);

        let pos = table.byte_offset_to_position(content, 8);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 2);
    }

    #[test]
    fn test_find_name_range() {
        let line = "    implementation(\"com.example:lib:1.0.0\")";
        let range = find_name_range(line, 5, 0, "com.example", "lib");
        assert_eq!(range.start.line, 5);
        assert!(range.start.character > 0);
    }

    #[test]
    fn test_find_name_range_scoped_to_match_start() {
        // Two dependencies with an identical coordinate on one line: scoping
        // the search to the second dependency's match_start must not return
        // the first dependency's name_range.
        let line = "implementation(\"a:b:1.0.0\"); testImplementation(\"a:b:1.0.0\")";
        let second_match_start = line.rfind("testImplementation").unwrap();
        let range = find_name_range(line, 0, second_match_start, "a", "b");
        let first_range = find_name_range(line, 0, 0, "a", "b");
        assert_ne!(range.start.character, first_range.start.character);
        assert!(range.start.character > second_match_start as u32);
    }

    #[test]
    fn test_is_dependency_configuration_kapt_ksp_prefix_variants() {
        for config in [
            "kapt",
            "kaptTest",
            "kaptAndroidTest",
            "ksp",
            "kspDebug",
            "kspCommonMainMetadata",
        ] {
            assert!(
                is_dependency_configuration(config),
                "{config} should be recognized"
            );
        }
        // "kaptx" has no capitalized variant boundary after the prefix.
        assert!(!is_dependency_configuration("kaptx"));
    }

    #[test]
    fn test_is_dependency_configuration_suffix_near_miss_is_accepted() {
        // Known, documented tradeoff of suffix-matching: any name ending in
        // a recognized suffix is accepted even if it isn't a real Gradle
        // configuration, since a coordinate-shaped string literal argument
        // is still required and Gradle itself would reject the unknown name.
        assert!(is_dependency_configuration("someRandomApi"));
        assert!(is_dependency_configuration("myOwnImplementation"));
    }

    #[test]
    fn test_opens_dependencies_block_tolerates_extra_whitespace() {
        assert!(opens_dependencies_block("dependencies  {"));
        assert!(opens_dependencies_block("dependencies\t{"));
        assert!(opens_dependencies_block("dependencies {"));
        assert!(opens_dependencies_block("dependencies{"));
        assert!(!opens_dependencies_block("dependenciesInfo {"));
        assert!(!opens_dependencies_block("dependenciesInfo{"));
    }

    #[test]
    fn test_find_version_range() {
        let line = "    implementation(\"com.example:lib:1.0.0\")";
        let range = find_version_range(line, 5, 0, "1.0.0");
        assert_eq!(range.start.line, 5);
        // "1.0.0" is 5 chars, end = start + 5
        assert_eq!(range.end.character - range.start.character, 5);
    }

    #[test]
    fn test_find_version_range_scoped_to_match_start() {
        // Two dependencies sharing the same version on one line: scoping the
        // search to the second dependency's match_start must not return the
        // first dependency's colon/version position.
        let line = "implementation(\"a:b:1.0.0\"); implementation(\"c:d:1.0.0\")";
        let second_match_start = line.rfind("implementation").unwrap();
        let range = find_version_range(line, 0, second_match_start, "1.0.0");
        let first_range = find_version_range(line, 0, 0, "1.0.0");
        assert_ne!(range.start.character, first_range.start.character);
        assert!(range.start.character > second_match_start as u32);
    }

    #[test]
    fn test_utf16_len_ascii() {
        assert_eq!(utf16_len("hello"), 5);
    }

    /// #1212: `includeGroup` inside a repository's `content { }` block is a real static
    /// per-group binding — a dependency in that group must classify as `CustomRegistry`.
    #[test]
    fn test_repository_content_include_group_classifies_matching_dependency() {
        let content = r#"
repositories {
    maven {
        url = "https://repo.acme.internal/maven"
        content {
            includeGroup("com.acme")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        assert_eq!(restrictions.len(), 1);
        assert_eq!(restrictions[0].pattern, "com.acme");
        assert!(!restrictions[0].is_regex);
        assert_eq!(
            restrictions[0].repository_url,
            "https://repo.acme.internal/maven"
        );

        let mut deps = vec![
            GradleDependency {
                group_id: "com.acme".into(),
                artifact_id: "secretlib".into(),
                name: "com.acme:secretlib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            GradleDependency {
                group_id: "org.springframework.boot".into(),
                artifact_id: "spring-boot-starter".into(),
                name: "org.springframework.boot:spring-boot-starter".into(),
                name_range: Range::default(),
                version_req: Some("3.2.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
        ];
        apply_repository_content_restrictions(&mut deps, &restrictions);

        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.acme.internal/maven".into(),
            }
        );
        assert_eq!(
            deps[1].source,
            deps_core::parser::DependencySource::Registry,
            "an unrelated group must never be swept in by another repository's content filter"
        );
    }

    /// #1212: Groovy DSL uses `url '...'` (no `=`), single-quoted — must be tolerated too.
    #[test]
    fn test_repository_content_groovy_style_url_and_quotes() {
        let content = r"
repositories {
    maven {
        url 'https://repo.acme.internal/maven'
        content {
            includeGroup 'com.acme'
        }
    }
}
";
        // Groovy also allows bare-word method calls without parens; the restriction regexes
        // require parens, matching Composer's own explicit-syntax-only policy (no heuristics
        // beyond the documented DSL shape) — so `includeGroup 'com.acme'` (no parens) is not
        // matched, only `url` without `=` is exercised here.
        let restrictions = parse_repository_content_restrictions(content);
        assert!(restrictions.is_empty());
    }

    /// G1 (impl-critic follow-up to #1212): the idiomatic Kotlin DSL form passes the
    /// repository's URL as a call argument (`maven("https://...")`), not a brace-body `url =
    /// ...` property — the most common real-world spelling for exactly this feature's target
    /// use case (a private repo scoped by `content { }`). Both positional and named-argument
    /// forms must be read.
    #[test]
    fn test_repository_content_call_paren_url_positional_and_named() {
        let positional = r#"
repositories {
    maven("https://repo.acme.internal/maven") {
        content {
            includeGroup("com.acme")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(positional);
        assert_eq!(restrictions.len(), 1);
        assert_eq!(
            restrictions[0].repository_url,
            "https://repo.acme.internal/maven"
        );

        let named = r#"
repositories {
    maven(url = "https://repo.acme.internal/maven") {
        content {
            includeGroup("com.acme")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(named);
        assert_eq!(restrictions.len(), 1);
        assert_eq!(
            restrictions[0].repository_url,
            "https://repo.acme.internal/maven"
        );

        let mut deps = vec![GradleDependency {
            group_id: "com.acme".into(),
            artifact_id: "secretlib".into(),
            name: "com.acme:secretlib".into(),
            name_range: Range::default(),
            version_req: Some("1.0.0".into()),
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }];
        apply_repository_content_restrictions(&mut deps, &restrictions);
        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.acme.internal/maven".into(),
            }
        );
    }

    /// G1: a bare shorthand repo (`google { }`, no call parens at all) must still classify as
    /// having no url — [`extract_call_paren_url`] must not misread an unrelated preceding
    /// statement's parens as this entry's own call arguments.
    #[test]
    fn test_call_paren_url_absent_for_bare_shorthand_repo() {
        let content = r#"
repositories {
    google {
        content {
            includeGroup("com.acme")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        assert!(
            restrictions.is_empty(),
            "a bare `google {{ }}` with no call parens must never acquire a url from thin air: \
             {restrictions:?}"
        );
    }

    /// #1212: `includeGroupByRegex` restrictions are matched as a regex against the group id.
    #[test]
    fn test_repository_content_include_group_by_regex() {
        let content = r#"
repositories {
    maven {
        url = "https://repo.acme.internal/maven"
        content {
            includeGroupByRegex("com\.acme\..*")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        assert_eq!(restrictions.len(), 1);
        assert!(restrictions[0].is_regex);

        let mut deps = vec![GradleDependency {
            group_id: "com.acme.internal".into(),
            artifact_id: "lib".into(),
            name: "com.acme.internal:lib".into(),
            name_range: Range::default(),
            version_req: Some("1.0.0".into()),
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }];
        apply_repository_content_restrictions(&mut deps, &restrictions);
        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.acme.internal/maven".into(),
            }
        );
    }

    /// #1212: `includeModule` binds an exact `group:module` coordinate.
    #[test]
    fn test_repository_content_include_module() {
        let content = r#"
repositories {
    maven {
        url = "https://repo.acme.internal/maven"
        content {
            includeModule("com.acme", "secretlib")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        assert_eq!(restrictions.len(), 1);
        assert_eq!(restrictions[0].pattern, "com.acme:secretlib");

        let mut deps = vec![
            GradleDependency {
                group_id: "com.acme".into(),
                artifact_id: "secretlib".into(),
                name: "com.acme:secretlib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            GradleDependency {
                group_id: "com.acme".into(),
                artifact_id: "otherlib".into(),
                name: "com.acme:otherlib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
        ];
        apply_repository_content_restrictions(&mut deps, &restrictions);
        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.acme.internal/maven".into(),
            }
        );
        assert_eq!(
            deps[1].source,
            deps_core::parser::DependencySource::Registry,
            "includeModule binds only the exact module, not the whole group"
        );
    }

    /// #1212: a `repositories { }` block with no `content { }` restriction at all (the
    /// general, unbound case) must never classify anything — same accepted-gap policy as
    /// Composer's bare `vcs`/`path`/`artifact` repository.
    #[test]
    fn test_repository_without_content_block_never_classifies() {
        let content = r#"
repositories {
    mavenCentral()
    maven {
        url = "https://repo.acme.internal/maven"
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        assert!(restrictions.is_empty());
    }

    /// C1 (impl-critic, #1212): the canonical Android template — `google { content {
    /// includeGroupByRegex("androidx.*") } }`, `google()`/`mavenCentral()`/etc. have no literal
    /// `url = ...` — must never classify a matching dependency as `CustomRegistry` with an
    /// empty url. Doing so silently disables OSV scanning/hover/completion for every dependency
    /// in that group, in a shape that's near-universal in real Android `build.gradle.kts`
    /// files — the exact false-positive/silent-disable class #1211 removed a heuristic for.
    #[test]
    fn test_google_shorthand_repo_with_no_literal_url_never_classifies() {
        let content = r#"
repositories {
    google {
        content {
            includeGroupByRegex("androidx.*")
            includeGroupByRegex("com\\.android.*")
        }
    }
    mavenCentral()
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        assert!(
            restrictions.is_empty(),
            "a shorthand repo with no literal url must produce zero restrictions, not a \
             CustomRegistry-with-empty-url restriction: {restrictions:?}"
        );

        let mut deps = vec![GradleDependency {
            group_id: "androidx.core".into(),
            artifact_id: "core-ktx".into(),
            name: "androidx.core:core-ktx".into(),
            name_range: Range::default(),
            version_req: Some("1.12.0".into()),
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }];
        apply_repository_content_restrictions(&mut deps, &restrictions);
        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::Registry,
            "androidx.core:core-ktx must stay Registry — google() is a real public registry, \
             not a non-registry source, and there is no url to route it to anyway"
        );
    }

    /// #3 (impl-critic follow-up to #1212): `url.set(uri("..."))` (and `url.set("...")`) is the
    /// Gradle 7/8 lazy-property idiom for setting a repository's url in Kotlin DSL — must not
    /// trip the C1 empty-url guard and silently discard the `content { }` restriction.
    #[test]
    fn test_url_set_lazy_property_idiom_is_recognized() {
        let with_uri = r#"
repositories {
    maven {
        url.set(uri("https://repo.acme.internal/maven"))
        content {
            includeGroup("com.acme")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(with_uri);
        assert_eq!(restrictions.len(), 1);
        assert_eq!(
            restrictions[0].repository_url,
            "https://repo.acme.internal/maven"
        );

        let bare = r#"
repositories {
    maven {
        url.set("https://repo.acme.internal/maven")
        content {
            includeGroup("com.acme")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(bare);
        assert_eq!(restrictions.len(), 1);
        assert_eq!(
            restrictions[0].repository_url,
            "https://repo.acme.internal/maven"
        );

        let mut deps = vec![GradleDependency {
            group_id: "com.acme".into(),
            artifact_id: "secretlib".into(),
            name: "com.acme:secretlib".into(),
            name_range: Range::default(),
            version_req: Some("1.0.0".into()),
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }];
        apply_repository_content_restrictions(&mut deps, &restrictions);
        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.acme.internal/maven".into(),
            }
        );
    }

    /// C2 (impl-critic, #1212): `includeGroupByRegex("com\\.acme.*")` — the real-world spelling
    /// with a doubled backslash, as Kotlin/Groovy string-literal escaping requires for a
    /// literal-dot regex — must actually match, and the match must be anchored to the whole
    /// group id, not an unanchored substring search.
    #[test]
    fn test_include_group_by_regex_unescapes_backslash_and_anchors_whole_match() {
        let content = r#"
repositories {
    maven {
        url = "https://repo.acme.internal/maven"
        content {
            includeGroupByRegex("com\\.acme.*")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        assert_eq!(restrictions.len(), 1);

        let mut deps = vec![
            GradleDependency {
                group_id: "com.acme".into(),
                artifact_id: "secretlib".into(),
                name: "com.acme:secretlib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            GradleDependency {
                group_id: "com.acme.internal".into(),
                artifact_id: "lib".into(),
                name: "com.acme.internal:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            GradleDependency {
                group_id: "com.notacme.other".into(),
                artifact_id: "lib".into(),
                name: "com.notacme.other:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            // G2 (impl-critic follow-up): unlike `com.notacme.other` (which `com\.acme.*`
            // never matches even unanchored, since "acme" alone isn't "com.acme"), this group
            // genuinely contains the substring "com.acme" starting at byte 1 — an *unanchored*
            // `is_match` would incorrectly accept it, so this is the case that actually
            // discriminates the anchoring fix from a no-op.
            GradleDependency {
                group_id: "xcom.acme".into(),
                artifact_id: "lib".into(),
                name: "xcom.acme:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
        ];
        apply_repository_content_restrictions(&mut deps, &restrictions);

        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.acme.internal/maven".into(),
            },
            "the escaped-dot regex must actually match a real com.acme group (C2a: escaping)"
        );
        assert_eq!(
            deps[1].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.acme.internal/maven".into(),
            },
            "com.acme.internal must also match — com\\.acme.* covers any subgroup"
        );
        assert_eq!(
            deps[2].source,
            deps_core::parser::DependencySource::Registry,
            "com.notacme.other must NOT match merely because it contains 'acme' as a substring"
        );
        assert_eq!(
            deps[3].source,
            deps_core::parser::DependencySource::Registry,
            "xcom.acme must NOT match — it contains \"com.acme\" as a substring starting at \
             byte 1, which an unanchored is_match would incorrectly accept (C2b: the match \
             must be anchored to the whole group id, not merely contain the pattern)"
        );
    }

    /// S1 (impl-critic, #1212): a `content { }` restriction declared inside `buildscript {
    /// repositories { } }` (plugin resolution) must never reclassify an unrelated dependency in
    /// the project's own `dependencies { }` block.
    #[test]
    fn test_buildscript_repositories_do_not_leak_into_project_classification() {
        let content = r#"
buildscript {
    repositories {
        maven {
            url = "https://plugins.acme.internal/maven"
            content {
                includeGroup("com.acme")
            }
        }
    }
    dependencies {
        classpath("com.acme:some-plugin:1.0.0")
    }
}

dependencies {
    implementation("com.acme:runtime-lib:1.0.0")
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        assert!(
            restrictions.is_empty(),
            "a content{{}} restriction scoped to buildscript's own repositories{{}} must never \
             surface as a project-wide restriction: {restrictions:?}"
        );

        let mut deps = vec![GradleDependency {
            group_id: "com.acme".into(),
            artifact_id: "runtime-lib".into(),
            name: "com.acme:runtime-lib".into(),
            name_range: Range::default(),
            version_req: Some("1.0.0".into()),
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }];
        apply_repository_content_restrictions(&mut deps, &restrictions);
        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::Registry,
            "com.acme:runtime-lib is a project dependency, unrelated to buildscript's own \
             plugin-resolution repository — must stay Registry"
        );
    }

    /// Test-coverage gap (tester follow-up to #1212): multiple `repositories { }` blocks (a
    /// real Gradle shape — e.g. one per source-set-specific configuration block) and multiple
    /// `content { }`-restricted entries within the same file must all be collected, each
    /// independently classifying only its own matching group.
    #[test]
    fn test_multiple_repositories_blocks_and_restricted_entries_all_collected() {
        let content = r#"
repositories {
    maven {
        url = "https://repo.acme.internal/maven"
        content {
            includeGroup("com.acme")
        }
    }
}
repositories {
    maven {
        url = "https://repo.other.internal/maven"
        content {
            includeGroup("com.other")
        }
    }
    maven {
        url = "https://repo.third.internal/maven"
        content {
            includeGroup("com.third")
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        assert_eq!(
            restrictions.len(),
            3,
            "all 3 restrictions across both repositories{{}} blocks must be collected: {restrictions:?}"
        );

        let mut deps = vec![
            GradleDependency {
                group_id: "com.acme".into(),
                artifact_id: "lib".into(),
                name: "com.acme:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            GradleDependency {
                group_id: "com.other".into(),
                artifact_id: "lib".into(),
                name: "com.other:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            GradleDependency {
                group_id: "com.third".into(),
                artifact_id: "lib".into(),
                name: "com.third:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
        ];
        apply_repository_content_restrictions(&mut deps, &restrictions);

        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.acme.internal/maven".into(),
            }
        );
        assert_eq!(
            deps[1].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.other.internal/maven".into(),
            }
        );
        assert_eq!(
            deps[2].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.third.internal/maven".into(),
            }
        );
    }

    /// Impl-critic #2 (CRITICAL, caught before merge): multiple repository declarations
    /// grouped inside a shared wrapper brace (e.g. a conditional block) must all be collected,
    /// not just the first — a real privacy-leak class: before this fix, `com.b`'s dependency
    /// would have stayed `Registry` and its name would have been sent to the public registry.
    #[test]
    fn test_multiple_maven_blocks_under_shared_wrapper_brace_all_collected() {
        let content = r#"
repositories {
    if (true) {
        maven {
            url = "https://a.internal/maven"
            content {
                includeGroup("com.a")
            }
        }
        maven {
            url = "https://b.internal/maven"
            content {
                includeGroup("com.b")
            }
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        // >= 2, not == 2: the recursive fix for this bug can push a harmless duplicate
        // restriction for the wrapper's first nested repo (see the doc comment on the
        // recursive call in `extract_repository_entries`) — classification *outcome* below is
        // the property that actually matters, not the exact restriction count.
        assert!(
            restrictions.len() >= 2,
            "both maven {{ }} blocks under the shared `if` wrapper must be collected: \
             {restrictions:?}"
        );
        assert!(
            restrictions
                .iter()
                .any(|r| r.pattern == "com.a" && r.repository_url == "https://a.internal/maven"),
            "com.a's restriction must be present: {restrictions:?}"
        );
        assert!(
            restrictions
                .iter()
                .any(|r| r.pattern == "com.b" && r.repository_url == "https://b.internal/maven"),
            "com.b's restriction must be present: {restrictions:?}"
        );

        let mut deps = vec![
            GradleDependency {
                group_id: "com.a".into(),
                artifact_id: "lib".into(),
                name: "com.a:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            GradleDependency {
                group_id: "com.b".into(),
                artifact_id: "lib".into(),
                name: "com.b:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
        ];
        apply_repository_content_restrictions(&mut deps, &restrictions);

        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://a.internal/maven".into(),
            }
        );
        assert_eq!(
            deps[1].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://b.internal/maven".into(),
            },
            "com.b must not stay Registry just because it shares a wrapper brace with com.a's \
             repository declaration"
        );
    }

    /// Reviewer follow-up to impl-critic #2: the fix was manually traced to generalize to N
    /// siblings under one wrapper brace, not just 2 — this makes that explicit rather than
    /// relying on the trace. Three `maven { }` blocks share one wrapper; all three must
    /// classify.
    #[test]
    fn test_three_maven_blocks_under_shared_wrapper_brace_all_collected() {
        let content = r#"
repositories {
    if (true) {
        maven {
            url = "https://a.internal/maven"
            content {
                includeGroup("com.a")
            }
        }
        maven {
            url = "https://b.internal/maven"
            content {
                includeGroup("com.b")
            }
        }
        maven {
            url = "https://c.internal/maven"
            content {
                includeGroup("com.c")
            }
        }
    }
}
"#;
        let restrictions = parse_repository_content_restrictions(content);
        for (group, url) in [
            ("com.a", "https://a.internal/maven"),
            ("com.b", "https://b.internal/maven"),
            ("com.c", "https://c.internal/maven"),
        ] {
            assert!(
                restrictions
                    .iter()
                    .any(|r| r.pattern == group && r.repository_url == url),
                "{group}'s restriction must be present: {restrictions:?}"
            );
        }

        let mut deps = vec![
            GradleDependency {
                group_id: "com.a".into(),
                artifact_id: "lib".into(),
                name: "com.a:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            GradleDependency {
                group_id: "com.b".into(),
                artifact_id: "lib".into(),
                name: "com.b:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
            GradleDependency {
                group_id: "com.c".into(),
                artifact_id: "lib".into(),
                name: "com.c:lib".into(),
                name_range: Range::default(),
                version_req: Some("1.0.0".into()),
                version_range: None,
                configuration: "implementation".into(),
                source: deps_core::parser::DependencySource::Registry,
            },
        ];
        apply_repository_content_restrictions(&mut deps, &restrictions);

        assert_eq!(
            deps[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://a.internal/maven".into(),
            }
        );
        assert_eq!(
            deps[1].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://b.internal/maven".into(),
            }
        );
        assert_eq!(
            deps[2].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://c.internal/maven".into(),
            },
            "com.c (the third sibling) must not stay Registry — the fix must generalize past 2 \
             siblings under one wrapper brace"
        );
    }

    /// #1212 end-to-end: `parse_gradle` on a real `build.gradle.kts` wires the restriction
    /// parsing and application together.
    #[test]
    fn test_parse_gradle_applies_repository_content_restriction_end_to_end() {
        // See the comment in `test_dispatch_kotlin` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let content = r#"
repositories {
    maven {
        url = "https://repo.acme.internal/maven"
        content {
            includeGroup("com.acme")
        }
    }
}
dependencies {
    implementation("com.acme:secretlib:1.0.0")
    implementation("org.springframework.boot:spring-boot-starter:3.2.0")
}
"#;
        let uri = make_uri("/project/build.gradle.kts");
        let result = parse_gradle(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let secret = result
            .dependencies
            .iter()
            .find(|d| d.group_id == "com.acme")
            .unwrap();
        let spring = result
            .dependencies
            .iter()
            .find(|d| d.group_id == "org.springframework.boot")
            .unwrap();

        assert_eq!(
            secret.source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://repo.acme.internal/maven".into(),
            }
        );
        assert_eq!(spring.source, deps_core::parser::DependencySource::Registry);
    }
}
