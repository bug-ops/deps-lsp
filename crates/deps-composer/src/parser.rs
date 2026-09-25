//! composer.json parser with position tracking.
//!
//! Parses composer.json files and extracts dependency information with precise
//! source positions for LSP operations. Platform packages (php, ext-*, lib-*)
//! are filtered out as they are not Packagist packages.

use crate::types::{ComposerDependency, ComposerSection};
use deps_core::Result;
use deps_core::json_ast::{JsonAst, JsonSection};
use deps_core::json_helpers::string_valued_entries;
use deps_core::lsp_helpers::LineOffsetTable;
use deps_core::{InvalidStabilityOccurrence, StabilityFloor};
use serde_json::Value;
use url::Url;

/// The manifest's own top-level `minimum-stability` field, as parsed (#1444).
///
/// Composer's project-wide default stability floor, one of `dev`, `alpha`, `beta`, `RC`,
/// `stable` (case-insensitive) — see [`StabilityFloor`]. Distinguishing [`Self::Absent`] from
/// [`Self::Invalid`] (rather than collapsing both to `None`) lets
/// [`deps_core::ParseResult::invalid_minimum_stability`] surface only the latter as a
/// diagnostic: an absent field is Composer's own documented default, not a mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinimumStability {
    /// The manifest has no `minimum-stability` field at all — Composer itself treats this as
    /// `stable`.
    Absent,
    /// The manifest declares a recognized stability keyword.
    Declared(StabilityFloor),
    /// The manifest declares a `minimum-stability` value that isn't one of the five
    /// recognized keywords (an unrecognized string, or a non-string JSON value). Selection
    /// still falls back to [`StabilityFloor::Stable`] (see [`Self::floor`]), but
    /// [`deps_core::ParseResult::invalid_minimum_stability`] surfaces the occurrence so the
    /// fallback is visible rather than silent.
    Invalid(InvalidStabilityOccurrence),
}

impl MinimumStability {
    /// The effective stability floor: `Some` only for [`Self::Declared`]. Both [`Self::Absent`]
    /// and [`Self::Invalid`] give `None`, so [`deps_core::SelectionContext::none`]'s own
    /// `stable` fallback applies identically to either case.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_composer::parser::MinimumStability;
    /// use deps_core::StabilityFloor;
    ///
    /// assert_eq!(MinimumStability::Absent.floor(), None);
    /// assert_eq!(
    ///     MinimumStability::Declared(StabilityFloor::Beta).floor(),
    ///     Some(StabilityFloor::Beta)
    /// );
    /// ```
    #[must_use]
    pub const fn floor(&self) -> Option<StabilityFloor> {
        match self {
            Self::Declared(floor) => Some(*floor),
            Self::Absent | Self::Invalid(_) => None,
        }
    }
}

/// Result of parsing a composer.json file.
///
/// Contains all non-platform dependencies found in the file with their positions.
#[non_exhaustive]
#[derive(Debug)]
pub struct ComposerParseResult {
    /// Non-platform dependencies found in the manifest.
    pub dependencies: Vec<ComposerDependency>,
    /// URI of the manifest this result was parsed from.
    pub uri: Url,
    /// The manifest's own top-level `minimum-stability` field, as parsed — see
    /// [`MinimumStability`]'s own doc.
    pub minimum_stability: MinimumStability,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

// Hand-written rather than `deps_core::impl_parse_result!`: that macro's optional fields
// (`workspace_root`, `dependency_truncation`, `blocked_registries`) are all plain
// field-to-getter passthroughs, but `selection_context`/`invalid_minimum_stability` both read
// `minimum_stability` (#1433/#1444) — Composer is the only implementor today, so baking that
// one-ecosystem shape into the shared macro would be premature generalization rather than DRY.
impl deps_core::ParseResult for ComposerParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }

    fn uri(&self) -> &Url {
        &self.uri
    }

    fn dependency_truncation(&self) -> Option<(usize, usize)> {
        self.dependency_truncation
    }

    /// Surfaces [`Self::minimum_stability`]'s effective floor so hover, completion, and code
    /// actions can no longer disagree with diagnostics about what "latest" means for the same
    /// dependency (#1433) — see [`deps_core::SelectionContext`]'s own doc.
    fn selection_context(&self) -> deps_core::SelectionContext {
        self.minimum_stability
            .floor()
            .map_or_else(deps_core::SelectionContext::none, |floor| {
                deps_core::SelectionContext::with_minimum_stability(floor)
            })
    }

    /// Surfaces [`Self::minimum_stability`]'s [`MinimumStability::Invalid`] occurrence, if
    /// any, so `deps_core::lsp_helpers::diagnostics`' shared notice can warn about it (#1444).
    fn invalid_minimum_stability(&self) -> Option<InvalidStabilityOccurrence> {
        match &self.minimum_stability {
            MinimumStability::Invalid(occurrence) => Some(occurrence.clone()),
            MinimumStability::Absent | MinimumStability::Declared(_) => None,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Returns true if the package is a platform requirement (not a Packagist package).
///
/// Platform packages include:
/// - `php`, and its variants `php-64bit`, `php-ipv6`, `php-zts`, `php-debug` — PHP version
///   requirements
/// - `hhvm` — HHVM version requirement
/// - `composer` — the Composer CLI version itself
/// - `ext-*` — PHP extensions
/// - `lib-*` — PHP libraries
/// - `composer-plugin-api`, `composer-runtime-api` — Composer's own virtual packages
///
/// Mirrors Composer's `PlatformRepository` package set (#402 critique S1: an incomplete list
/// here previously let a real platform requirement like `composer-plugin-api` — present in
/// essentially every Composer plugin's `composer.json` — reach the Packagist-shaped
/// `vendor/package` name validator and get flagged "Invalid package name"; M6: `composer`
/// itself was still missing from the set).
///
/// Every platform package name is a single bare token with no `/` — a real Packagist package
/// always has a `vendor/package` shape — so any name containing `/` returns `false`
/// immediately, before the prefix checks below. Without this guard, `starts_with("php-")` (and
/// `ext-`/`lib-`) would also match a real package merely because its *vendor* happens to start
/// with that prefix (e.g. `php-di/php-di`, `php-amqplib/php-amqplib`, `ext-mongo/whatever`),
/// silently dropping it from the dependency list entirely — no diagnostic, hover, inlay hint,
/// or code lens — rather than validating it as a normal dependency (#402 critique C2).
pub fn is_platform_package(name: &str) -> bool {
    if name.contains('/') {
        return false;
    }
    name == "php"
        || name.starts_with("php-")
        || name == "hhvm"
        || name == "composer"
        || name.starts_with("ext-")
        || name.starts_with("lib-")
        || name == "composer-plugin-api"
        || name == "composer-runtime-api"
}

/// Parses a composer.json file and extracts all non-platform dependencies with positions.
///
/// Handles `require` and `require-dev` sections.
/// Platform packages (php, ext-*, lib-*) are silently filtered out.
///
/// # Errors
///
/// Returns an error if JSON parsing fails.
///
/// # Examples
///
/// ```no_run
/// use deps_composer::parser::parse_composer_json;
/// use url::Url;
///
/// let json = r#"{
///   "require": {
///     "symfony/console": "^6.0"
///   }
/// }"#;
/// let uri = Url::from_file_path("/project/composer.json").unwrap();
///
/// let result = parse_composer_json(json, &uri).unwrap();
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name, "symfony/console");
/// ```
pub fn parse_composer_json(content: &str, uri: &Url) -> Result<ComposerParseResult> {
    parse_composer_json_inner(content, uri).map(|(result, _)| result)
}

/// Parses a composer.json file, then cross-checks against `composer.lock` when needed (#1212).
///
/// When the manifest declares a bare (no `only` filter) `vcs`/`path`/`artifact` repository,
/// every dependency left `Registry`-classified is cross-checked against an ancestor
/// `composer.lock`'s own per-package `source.type` field.
///
/// A bare repository entry has no static per-package name binding in the Composer manifest
/// format at all (Composer tries every declared repository, in order, for any required
/// package), so [`parse_composer_json`] deliberately leaves every such dependency `Registry`
/// (see `ComposerRepository::only`'s doc). `composer.lock`, once `composer install` has run,
/// is the one place that records which source actually resolved a given package — this
/// consults only that explicit, per-package field, never a URL/vendor substring heuristic (the
/// kind #1211 removed for false positives). Falls back to [`parse_composer_json`]'s behavior
/// verbatim when no bare repository is declared, or when no lock file is present/parseable.
///
/// Only overrides to [`deps_core::parser::DependencySource::Path`], never `Git` — see
/// `apply_lockfile_classification`'s doc for why a lock entry's `source.type == "git"` is not
/// a trustworthy non-registry signal on its own.
///
/// Known limitation (impl-critic minor, documented not fixed): the ancestor lockfile lookup
/// (`LockFileProvider::locate_lockfile`, shared with every other lockfile-aware ecosystem) can
/// walk up to 5 directory levels, so a manifest with no `composer.lock` of its own in an
/// unconventional monorepo layout could adopt an unrelated parent directory's lock file. This
/// is the same pre-existing ancestor-walk behavior `deps-lsp`'s in-use-version resolution
/// already relies on for every ecosystem, not a new risk this fix introduces.
///
/// `lockfile_cache` is read through, never bypassed with a fresh read (impl-critic follow-up):
/// `composer.lock` can be large and this runs on every reparse, so a raw
/// `LockFileProvider::parse_lockfile` call here would re-stat, re-read, and re-parse it on
/// every keystroke, and a second time relative to whatever else in this process already caches
/// it by mtime (e.g. `deps-lsp`'s own in-use-version resolution) — [`crate::ecosystem::ComposerEcosystem::with_context`]
/// shares one cache instance between both.
///
/// # Errors
///
/// Returns an error if JSON parsing fails. A missing or unparseable `composer.lock` is not an
/// error — classification simply falls back to `Registry` for the affected dependencies.
///
/// # Examples
///
/// ```no_run
/// # use deps_composer::parser::parse_composer_json_with_lockfile;
/// # use deps_core::lockfile::LockFileCache;
/// # use url::Url;
/// # #[tokio::main]
/// # async fn main() {
/// let json = r#"{
///   "require": {
///     "symfony/console": "^6.0"
///   }
/// }"#;
/// let uri = Url::from_file_path("/project/composer.json").unwrap();
/// let lockfile_cache = LockFileCache::new();
///
/// let result = parse_composer_json_with_lockfile(json, &uri, &lockfile_cache)
///     .await
///     .unwrap();
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name, "symfony/console");
/// # }
/// ```
pub async fn parse_composer_json_with_lockfile(
    content: &str,
    uri: &Url,
    lockfile_cache: &deps_core::lockfile::LockFileCache,
) -> Result<ComposerParseResult> {
    let (mut result, has_bare_repo) = parse_composer_json_inner(content, uri)?;
    if has_bare_repo {
        use deps_core::lockfile::LockFileProvider;
        let provider = crate::lockfile::ComposerLockParser;
        if let Some(lock_path) = provider.locate_lockfile(uri)
            && let Ok(resolved) = lockfile_cache.get_or_parse(&provider, &lock_path).await
        {
            apply_lockfile_classification(&mut result.dependencies, &resolved);
        }
    }
    Ok(result)
}

/// Shared parsing body for [`parse_composer_json`]/[`parse_composer_json_with_lockfile`],
/// additionally reporting whether the manifest declares a bare (no `only`) `vcs`/`path`/
/// `artifact` repository (see [`has_bare_non_registry_repository`]) so the async wrapper knows
/// whether consulting `composer.lock` is even worth the I/O.
fn parse_composer_json_inner(content: &str, uri: &Url) -> Result<(ComposerParseResult, bool)> {
    let root: Value = deps_core::parse_json_checked(content.as_bytes())?;

    let line_table = LineOffsetTable::new(content);
    let ast = JsonAst::parse(content);
    if ast.is_none() {
        tracing::warn!(
            "jsonc-parser failed to parse composer.json content serde_json already accepted; \
             dependency positions will default to (0,0)"
        );
    }
    let mut dependencies = Vec::new();
    // Shared across every section below (#796) — the ceiling is per-document, not
    // per-section.
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    // Parse each section, reading each entry's position directly from the AST (#613) — the
    // AST's own `Object::properties` only ever lists a given object's *direct* children, so a
    // name repeated across sections (e.g. also present in `require-dev`) or nested inside an
    // unrelated value never gets confused with the real top-level occurrence, independent of
    // `serde_json::Map` iteration order (#610).
    const SECTIONS: [(&str, ComposerSection); 2] = [
        ("require", ComposerSection::Require),
        ("require-dev", ComposerSection::RequireDev),
    ];

    for (key, section) in SECTIONS {
        if let Some(deps) = root.get(key).and_then(|v| v.as_object()) {
            let positions = ast.as_ref().and_then(|ast| ast.section(key));
            dependencies.extend(parse_section(
                content,
                deps,
                section,
                positions.as_ref(),
                &line_table,
                &mut budget,
            ));
        }
    }

    let (repositories, packagist_disabled) = parse_repositories(&root);
    let has_bare_repo = has_bare_non_registry_repository(&repositories);
    if !repositories.is_empty() || packagist_disabled {
        classify_repositories(&mut dependencies, &repositories, packagist_disabled);
    }

    let minimum_stability = match root.get("minimum-stability") {
        None => MinimumStability::Absent,
        Some(value) => {
            // Shared by both `Invalid` arms below: the value's own span for a string that
            // fails to parse, the declaring key's span for a non-string value.
            let position = || {
                ast.as_ref().and_then(|ast| {
                    ast.root_property_position("minimum-stability", content, &line_table)
                })
            };
            match value {
                Value::String(raw) => match raw.parse::<StabilityFloor>() {
                    Ok(floor) => MinimumStability::Declared(floor),
                    Err(_) => {
                        let range = position()
                            .and_then(|(name_range, value_range)| value_range.or(Some(name_range)))
                            .unwrap_or_default();
                        MinimumStability::Invalid(InvalidStabilityOccurrence {
                            range,
                            raw: raw.clone(),
                        })
                    }
                },
                other => {
                    let range = position()
                        .map(|(name_range, _)| name_range)
                        .unwrap_or_default();
                    MinimumStability::Invalid(InvalidStabilityOccurrence {
                        range,
                        raw: other.to_string(),
                    })
                }
            }
        }
    };

    Ok((
        ComposerParseResult {
            dependencies,
            uri: uri.clone(),
            minimum_stability,
            dependency_truncation: budget.truncation(),
        },
        has_bare_repo,
    ))
}

/// Parses a single dependency section and extracts positions, filtering platform packages.
///
/// `positions` is this section's own direct properties, pre-indexed by name (see
/// [`JsonAst::section`]) — `None` when the AST parse degraded (see [`parse_composer_json`]),
/// in which case every dependency falls back to a default, zero position rather than being
/// dropped.
fn parse_section(
    content: &str,
    deps: &serde_json::Map<String, Value>,
    section: ComposerSection,
    positions: Option<&JsonSection<'_>>,
    line_table: &LineOffsetTable,
    budget: &mut deps_core::DependencyBudget,
) -> Vec<ComposerDependency> {
    let mut result = Vec::new();

    // A manifest entry whose value isn't a string (e.g. an object) is not a valid dependency
    // declaration — `string_valued_entries` skips it rather than fabricating an entry with no
    // `version_req` that would still be queried against the registry (#621, same bug class as
    // npm's #619).
    for (name, version_req) in string_valued_entries(deps) {
        if is_platform_package(name) {
            continue;
        }
        if !budget.allow() {
            continue;
        }

        let (name_range, version_range) = positions
            .and_then(|s| s.position(name, content, line_table))
            .unwrap_or_default();

        result.push(ComposerDependency {
            name: name.into(),
            name_range,
            version_req: Some(version_req.into()),
            version_range,
            section,
            source: deps_core::parser::DependencySource::Registry,
        });
    }

    result
}

/// One `repositories` entry classifying `vcs`/`path`/`artifact`/`package` sources (#1202) —
/// every other declared type (`composer`, `pear`, ...) is still registry-shaped and ignored.
struct ComposerRepository {
    kind: ComposerRepositoryKind,
    url: String,
    /// Explicit `"only": ["vendor/pkg", "vendor/*", ...]` filter — Composer's own documented
    /// way to bind a `vcs`/`path`/`artifact` repository to specific package names, with `*`
    /// as a wildcard (see [`composer_pattern_matches`]). This is the *only* binding this
    /// parser trusts for those three types (critic S4): a bare repository declaration with
    /// no `only` has no static name association at all in the Composer manifest format
    /// (every declared repository is simply tried, in order, for any required package), and
    /// a substring-of-the-URL heuristic previously used here mis-classified unrelated public
    /// packages that merely shared an org/vendor token with the URL (e.g. one `vcs` repo for
    /// `github.com/symfony/monolog-bundle` silently reclassified `symfony/console`,
    /// `symfony/http-kernel`, and even unrelated `monolog/monolog` as non-`Registry`,
    /// silently disabling their OSV scan). Team-lead policy call: an occasional false
    /// negative (a private package with no `only` filter staying `Registry`, the
    /// pre-existing status quo this issue is fixing) is preferable to that false-positive.
    only: Option<Vec<String>>,
}

enum ComposerRepositoryKind {
    Vcs,
    Path,
    Artifact,
    /// `{"type": "package", "package": {"name": "...", ...}}` — unlike the other three
    /// variants, this one carries an exact, manifest-declared package name (critic S3), so
    /// it needs no `only` filter or heuristic at all.
    Package {
        name: String,
        is_git: bool,
    },
}

impl ComposerRepositoryKind {
    fn classify(&self, url: &str) -> deps_core::parser::DependencySource {
        match self {
            Self::Vcs => deps_core::parser::DependencySource::Git {
                url: url.to_string(),
                rev: None,
            },
            Self::Path => deps_core::parser::DependencySource::Path {
                path: url.to_string(),
            },
            Self::Artifact => deps_core::parser::DependencySource::Url {
                url: url.to_string(),
            },
            Self::Package { is_git, .. } => {
                if *is_git {
                    deps_core::parser::DependencySource::Git {
                        url: url.to_string(),
                        rev: None,
                    }
                } else {
                    deps_core::parser::DependencySource::Url {
                        url: url.to_string(),
                    }
                }
            }
        }
    }
}

/// Parses the manifest-level `repositories` declaration (array or Composer 2's
/// object-map-by-label form — both carry the same per-entry shape) into the repositories
/// this parser can classify against, plus whether any entry disables the implicit
/// `packagist.org` fallback (`{"packagist.org": false}`, critic S3) — Composer's documented
/// way to opt every otherwise-unmatched dependency out of the public registry entirely.
fn parse_repositories(root: &Value) -> (Vec<ComposerRepository>, bool) {
    let Some(repositories) = root.get("repositories") else {
        return (Vec::new(), false);
    };
    let entries: Vec<&Value> = match repositories {
        Value::Array(entries) => entries.iter().collect(),
        Value::Object(entries) => entries.values().collect(),
        _ => return (Vec::new(), false),
    };
    let packagist_disabled = entries.iter().any(|entry| {
        entry
            .as_object()
            .and_then(|obj| obj.get("packagist.org"))
            .and_then(Value::as_bool)
            == Some(false)
    });
    let repos = entries
        .into_iter()
        .filter_map(parse_repository_entry)
        .collect();
    (repos, packagist_disabled)
}

fn parse_repository_entry(entry: &Value) -> Option<ComposerRepository> {
    let obj = entry.as_object()?;
    match obj.get("type").and_then(Value::as_str)? {
        "package" => parse_package_repository_entry(obj),
        kind_str => {
            let kind = match kind_str {
                "vcs" | "github" | "gitlab" | "bitbucket" | "git" | "hg" | "fossil"
                | "perforce" | "svn" => ComposerRepositoryKind::Vcs,
                "path" => ComposerRepositoryKind::Path,
                "artifact" => ComposerRepositoryKind::Artifact,
                _ => return None,
            };
            let url = obj.get("url").and_then(Value::as_str)?.to_string();
            let only = obj.get("only").and_then(Value::as_array).map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            });
            Some(ComposerRepository { kind, url, only })
        }
    }
}

/// `{"type": "package", "package": {"name", "source"|"dist"}}` — the exact-binding form
/// (critic S3). `source.url` (a real VCS checkout) is preferred over `dist.url` (a
/// pre-built artifact) when both are present, matching Composer's own installation
/// preference order.
fn parse_package_repository_entry(
    obj: &serde_json::Map<String, Value>,
) -> Option<ComposerRepository> {
    let package = obj.get("package")?.as_object()?;
    let name = package.get("name").and_then(Value::as_str)?.to_string();
    let source = package.get("source").and_then(Value::as_object);
    if let Some(url) = source.and_then(|s| s.get("url")).and_then(Value::as_str) {
        let is_git = source.and_then(|s| s.get("type")).and_then(Value::as_str) == Some("git");
        return Some(ComposerRepository {
            kind: ComposerRepositoryKind::Package { name, is_git },
            url: url.to_string(),
            only: None,
        });
    }
    let dist_url = package
        .get("dist")
        .and_then(Value::as_object)
        .and_then(|d| d.get("url"))
        .and_then(Value::as_str)?;
    Some(ComposerRepository {
        kind: ComposerRepositoryKind::Package {
            name,
            is_git: false,
        },
        url: dist_url.to_string(),
        only: None,
    })
}

/// Classifies each `Registry`-defaulted dependency against `repositories`, in manifest
/// declaration order (first matching repository wins, mirroring Composer's own resolution
/// order), then applies `packagist_disabled` (critic S3) to whatever is still unmatched.
fn classify_repositories(
    dependencies: &mut [ComposerDependency],
    repositories: &[ComposerRepository],
    packagist_disabled: bool,
) {
    for repo in repositories {
        for dep in &mut *dependencies {
            if !matches!(dep.source, deps_core::parser::DependencySource::Registry) {
                continue;
            }
            let name = dep.name.as_str();
            let is_match = match &repo.kind {
                ComposerRepositoryKind::Package {
                    name: bound_name, ..
                } => bound_name == name,
                ComposerRepositoryKind::Vcs
                | ComposerRepositoryKind::Path
                | ComposerRepositoryKind::Artifact => repo.only.as_ref().is_some_and(|only| {
                    only.iter()
                        .any(|pattern| composer_pattern_matches(pattern, name))
                }),
            };
            if is_match {
                dep.source = repo.kind.classify(&repo.url);
            }
        }
    }

    if packagist_disabled {
        for dep in &mut *dependencies {
            if matches!(dep.source, deps_core::parser::DependencySource::Registry) {
                // `url` normally names a real index this LSP has (or could) resolve against;
                // there is none here — `packagist.org` is disabled outright, not pointed
                // elsewhere — so this is the host name being disabled, not a resolvable URL.
                dep.source = deps_core::parser::DependencySource::CustomRegistry {
                    url: "packagist.org".to_string(),
                };
            }
        }
    }
}

/// Returns true if any declared repository is a bare `vcs`/`path`/`artifact` entry — one with
/// no `only` filter at all (#1212). This is the trigger [`parse_composer_json_with_lockfile`]
/// uses to decide whether consulting `composer.lock` is worthwhile: a `Package`-kind entry
/// already carries an exact name and never needs this, and a `vcs`/`path`/`artifact` entry
/// *with* an `only` filter was already classified by [`classify_repositories`] above.
///
/// Known limitation (impl-critic minor, documented not fixed): a bare `artifact` repository
/// triggers this the same as `vcs`/`path`, but [`crate::lockfile::parse_composer_lock`] only
/// maps a lock entry's `source.type` of `"git"`/`"path"` — an artifact-sourced package's lock
/// entry has no `source` block at all (only `dist`), so [`apply_lockfile_classification`] can
/// never actually reclassify one. Harmless (a wasted lockfile read, never a wrong answer), so
/// left as-is rather than special-cased out of this trigger.
fn has_bare_non_registry_repository(repositories: &[ComposerRepository]) -> bool {
    repositories.iter().any(|repo| {
        repo.only.is_none()
            && matches!(
                repo.kind,
                ComposerRepositoryKind::Vcs
                    | ComposerRepositoryKind::Path
                    | ComposerRepositoryKind::Artifact
            )
    })
}

/// Overrides a still-`Registry`-classified dependency's source using `composer.lock`'s own
/// per-package `source.type` (#1212, see [`parse_composer_json_with_lockfile`]).
///
/// Only `ResolvedSource::Path` is treated as a signal here — deliberately *not*
/// `ResolvedSource::Git`, even though [`crate::lockfile::parse_composer_lock`] does map a
/// lock entry's `"git"` `source.type` to it. `composer.lock` records a real git checkout's
/// `source` block for essentially every ordinary Packagist-resolved package too (Packagist
/// itself mirrors GitHub/GitLab/Bitbucket-hosted packages), so `source.type == "git"` alone
/// cannot distinguish a genuinely private/non-registry package from `symfony/console`. Since
/// this function scans *every* still-`Registry` dependency once triggered (not only the one
/// named by the bare repository), trusting that ambiguous signal would reclassify ordinary
/// public packages present in the same lock file — the exact false-positive class #1211
/// removed the URL-substring heuristic for. `source.type == "path"` has no such ambiguity: no
/// Packagist-resolved package is ever recorded that way, only a genuine local-path repository
/// entry. (Impl-critic follow-up to the original #1212 direction, which specified both
/// mappings — narrowed after review; see `test_lockfile_never_reclassifies_unrelated_git_sourced_registry_package`.)
fn apply_lockfile_classification(
    dependencies: &mut [ComposerDependency],
    resolved: &deps_core::lockfile::ResolvedPackages,
) {
    for dep in dependencies {
        if !matches!(dep.source, deps_core::parser::DependencySource::Registry) {
            continue;
        }
        let Some(pkg) = resolved.get(&dep.name.as_str().to_lowercase()) else {
            continue;
        };
        if let deps_core::lockfile::ResolvedSource::Path { path } = &pkg.source {
            dep.source = deps_core::parser::DependencySource::Path { path: path.clone() };
        }
    }
}

/// Matches `name` against a Composer `only` entry, which may contain `*` wildcards
/// (Composer's own documented glob syntax, e.g. `"acme/*"` — critic S2) matching any run of
/// characters. No other glob metacharacter (`?`, `[...]`) is part of Composer's own syntax,
/// so none is supported here either.
// `idx` and `idx + segment.len()` both come from `str::find`'s match bounds, always char
// boundaries.
#[allow(clippy::string_slice)]
fn composer_pattern_matches(pattern: &str, name: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == name;
    }
    let mut segments = pattern.split('*');
    // `split('*')` on a pattern containing at least one `*` always yields >= 2 items, so the
    // first `next()` never falls through to the default.
    let Some(rest) = name.strip_prefix(segments.next().unwrap_or_default()) else {
        return false;
    };
    let mut rest = rest;
    let mut middle: Vec<&str> = segments.collect();
    let last = middle.pop();
    for segment in &middle {
        if segment.is_empty() {
            continue;
        }
        let Some(idx) = rest.find(segment) else {
            return false;
        };
        rest = &rest[idx + segment.len()..];
    }
    last.is_none_or(|last_segment| rest.ends_with(last_segment))
}

#[cfg(test)]
mod tests {
    use super::*;

    use deps_core::position::Range;
    use std::assert_matches;

    fn test_uri() -> Url {
        deps_core::test_util::test_uri("/test/composer.json")
    }

    /// #1202 repro: a `vcs` repository with an exact `only` filter must classify the matching
    /// `require` entry as `Git` rather than leave it `Registry` (which would send
    /// `acme/secretpkg`'s name to Packagist).
    #[test]
    fn test_vcs_repository_with_only_classifies_matching_dependency() {
        let json = r#"{
  "repositories": [
    { "type": "vcs", "url": "ssh://git@git.acme.internal/private.git", "only": ["acme/secretpkg"] }
  ],
  "require": {
    "acme/secretpkg": "^1.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Git {
                url: "ssh://git@git.acme.internal/private.git".into(),
                rev: None,
            }
        );
    }

    /// Critic S4: a `vcs`/`path`/`artifact` repository with no `only` filter has no static
    /// name binding in the Composer manifest format at all — this parser now deliberately
    /// stays `Registry` for every dependency in that case, accepting a false negative (the
    /// pre-existing status-quo bug) rather than the substring-heuristic's false positive
    /// (silently disabling OSV scanning for unrelated public packages that merely share an
    /// org/vendor token with the repository's URL).
    #[test]
    fn test_vcs_repository_without_only_never_reclassifies_anything() {
        let json = r#"{
  "repositories": [
    { "type": "vcs", "url": "https://github.com/symfony/monolog-bundle.git" }
  ],
  "require": {
    "symfony/console": "^6.0",
    "symfony/http-kernel": "^6.0",
    "monolog/monolog": "^3.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        for dep in &result.dependencies {
            assert_eq!(
                dep.source,
                deps_core::parser::DependencySource::Registry,
                "{} must stay Registry — a bare vcs repo with no `only` must never sweep in \
                 unrelated packages that merely share a vendor/org token with its URL",
                dep.name.as_str()
            );
        }
    }

    /// Impl-critic follow-up to #1212: a bare `vcs` repository's lock entry alone must never
    /// reclassify a dependency to `Git` — `composer.lock`'s `source.type == "git"` is recorded
    /// for essentially every ordinary Packagist-resolved package too (Packagist mirrors
    /// GitHub/GitLab/Bitbucket), so it cannot distinguish `acme/secretpkg` (genuinely private,
    /// resolved only via the bare `vcs` repo) from an ordinary public package. This stays the
    /// already-accepted `Registry` gap the original #1202 fix documented — see
    /// [`apply_lockfile_classification`]'s doc.
    #[tokio::test]
    async fn test_lockfile_never_reclassifies_via_bare_vcs_repo_git_source() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("composer.json");
        let json = r#"{
  "repositories": [
    { "type": "vcs", "url": "ssh://git@git.acme.internal/private.git" }
  ],
  "require": {
    "acme/secretpkg": "^1.0"
  }
}"#;
        tokio::fs::write(&manifest_path, json).await.unwrap();
        let lock_json = r#"{
  "packages": [
    {
      "name": "acme/secretpkg",
      "version": "1.0.0",
      "source": {
        "type": "git",
        "url": "ssh://git@git.acme.internal/private.git",
        "reference": "deadbeef"
      }
    }
  ],
  "packages-dev": []
}"#;
        tokio::fs::write(temp_dir.path().join("composer.lock"), lock_json)
            .await
            .unwrap();

        let uri = Url::from_file_path(&manifest_path).unwrap();
        let lockfile_cache = deps_core::lockfile::LockFileCache::new();
        let result = parse_composer_json_with_lockfile(json, &uri, &lockfile_cache)
            .await
            .unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry,
            "a lock entry's source.type == \"git\" alone must never override classification, \
             even for the exact package a bare vcs repository was declared for"
        );
    }

    /// Impl-critic follow-up to #1212 (the regression the team lead's review flagged): a bare
    /// `path` repository triggering the lockfile check must not sweep in an *unrelated*,
    /// ordinary Packagist package that merely happens to share the same `composer.lock` and
    /// have a `source.type: "git"` entry (true for essentially every real public package) —
    /// the same false-positive bug class #1211 removed the URL-substring heuristic for.
    #[tokio::test]
    async fn test_lockfile_never_reclassifies_unrelated_git_sourced_registry_package() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("composer.json");
        let json = r#"{
  "repositories": [
    { "type": "path", "url": "../acme-local" }
  ],
  "require": {
    "acme/localpkg": "^1.0",
    "symfony/console": "^6.0"
  }
}"#;
        tokio::fs::write(&manifest_path, json).await.unwrap();
        let lock_json = r#"{
  "packages": [
    {
      "name": "acme/localpkg",
      "version": "1.0.0",
      "source": {
        "type": "path",
        "url": "../acme-local"
      }
    },
    {
      "name": "symfony/console",
      "version": "6.0.0",
      "source": {
        "type": "git",
        "url": "https://github.com/symfony/console.git",
        "reference": "abc123"
      }
    }
  ],
  "packages-dev": []
}"#;
        tokio::fs::write(temp_dir.path().join("composer.lock"), lock_json)
            .await
            .unwrap();

        let uri = Url::from_file_path(&manifest_path).unwrap();
        let lockfile_cache = deps_core::lockfile::LockFileCache::new();
        let result = parse_composer_json_with_lockfile(json, &uri, &lockfile_cache)
            .await
            .unwrap();
        let local = result
            .dependencies
            .iter()
            .find(|d| d.name == "acme/localpkg")
            .unwrap();
        let console = result
            .dependencies
            .iter()
            .find(|d| d.name == "symfony/console")
            .unwrap();

        assert_eq!(
            local.source,
            deps_core::parser::DependencySource::Path {
                path: "../acme-local".into(),
            },
            "the genuinely path-sourced package must still be reclassified"
        );
        assert_eq!(
            console.source,
            deps_core::parser::DependencySource::Registry,
            "an unrelated, ordinary git-hosted Packagist package must never be swept in just \
             because a bare path repository elsewhere in the manifest triggered the lockfile \
             check"
        );
    }

    /// #1212: same as above, for a `path` repository/lock source.
    #[tokio::test]
    async fn test_lockfile_overrides_bare_repo_path_source() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("composer.json");
        let json = r#"{
  "repositories": [
    { "type": "path", "url": "../acme-local" }
  ],
  "require": {
    "acme/localpkg": "^1.0"
  }
}"#;
        tokio::fs::write(&manifest_path, json).await.unwrap();
        let lock_json = r#"{
  "packages": [
    {
      "name": "acme/localpkg",
      "version": "1.0.0",
      "source": {
        "type": "path",
        "url": "../acme-local"
      }
    }
  ],
  "packages-dev": []
}"#;
        tokio::fs::write(temp_dir.path().join("composer.lock"), lock_json)
            .await
            .unwrap();

        let uri = Url::from_file_path(&manifest_path).unwrap();
        let lockfile_cache = deps_core::lockfile::LockFileCache::new();
        let result = parse_composer_json_with_lockfile(json, &uri, &lockfile_cache)
            .await
            .unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path {
                path: "../acme-local".into(),
            }
        );
    }

    /// #1212: a lockless manifest (no `composer.lock` on disk) is an accepted gap — a bare
    /// repository with no lock file to consult must stay `Registry`, never guess.
    #[tokio::test]
    async fn test_lockless_manifest_with_bare_repo_stays_registry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("composer.json");
        let json = r#"{
  "repositories": [
    { "type": "vcs", "url": "ssh://git@git.acme.internal/private.git" }
  ],
  "require": {
    "acme/secretpkg": "^1.0"
  }
}"#;
        tokio::fs::write(&manifest_path, json).await.unwrap();

        let uri = Url::from_file_path(&manifest_path).unwrap();
        let lockfile_cache = deps_core::lockfile::LockFileCache::new();
        let result = parse_composer_json_with_lockfile(json, &uri, &lockfile_cache)
            .await
            .unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
    }

    /// Test-coverage gap (tester follow-up to #1212): a bare repository is declared and
    /// `composer.lock` is present, but this exact dependency has no entry in it at all (e.g. a
    /// stale lock file from before the dependency was added) — `resolved.get(...)` must return
    /// `None` and the dependency must stay `Registry`, not panic or misclassify.
    #[tokio::test]
    async fn test_bare_repo_with_lockfile_present_but_dependency_absent_from_lock() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("composer.json");
        let json = r#"{
  "repositories": [
    { "type": "path", "url": "../acme-local" }
  ],
  "require": {
    "acme/notinlock": "^1.0"
  }
}"#;
        tokio::fs::write(&manifest_path, json).await.unwrap();
        // composer.lock exists (proving the lockfile IS consulted) but has no entry for
        // acme/notinlock at all.
        let lock_json = r#"{
  "packages": [
    {
      "name": "symfony/console",
      "version": "6.0.0",
      "source": { "type": "git", "url": "https://github.com/symfony/console.git", "reference": "abc123" }
    }
  ],
  "packages-dev": []
}"#;
        tokio::fs::write(temp_dir.path().join("composer.lock"), lock_json)
            .await
            .unwrap();

        let uri = Url::from_file_path(&manifest_path).unwrap();
        let lockfile_cache = deps_core::lockfile::LockFileCache::new();
        let result = parse_composer_json_with_lockfile(json, &uri, &lockfile_cache)
            .await
            .unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry,
            "a dependency absent from an otherwise-present composer.lock must stay Registry, \
             not panic or guess"
        );
    }

    /// #1212: the lockfile override only fires when a bare non-registry repository is
    /// declared — a manifest with no `repositories` at all must never consult `composer.lock`,
    /// even when the lock file's `source.type` for an ordinary registry package happens to be
    /// `"git"` (true for virtually every Packagist package, since Packagist mirrors GitHub).
    /// Consulting it unconditionally would silently disable OSV scanning for every dependency,
    /// the same false-positive bug class #1211 removed the URL-substring heuristic for.
    #[tokio::test]
    async fn test_lockfile_not_consulted_without_bare_repository() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("composer.json");
        let json = r#"{
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
        tokio::fs::write(&manifest_path, json).await.unwrap();
        let lock_json = r#"{
  "packages": [
    {
      "name": "symfony/console",
      "version": "6.0.0",
      "source": {
        "type": "git",
        "url": "https://github.com/symfony/console.git",
        "reference": "abc123"
      }
    }
  ],
  "packages-dev": []
}"#;
        tokio::fs::write(temp_dir.path().join("composer.lock"), lock_json)
            .await
            .unwrap();

        let uri = Url::from_file_path(&manifest_path).unwrap();
        let lockfile_cache = deps_core::lockfile::LockFileCache::new();
        let result = parse_composer_json_with_lockfile(json, &uri, &lockfile_cache)
            .await
            .unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry,
            "no bare repository is declared, so composer.lock must never be consulted for \
             classification — every Packagist package's lock entry also has source.type \
             \"git\", which would otherwise misclassify it"
        );
    }

    /// Critic S2: `only` supports Composer's own `*` wildcard glob syntax.
    #[test]
    fn test_repository_only_filter_supports_wildcard() {
        let json = r#"{
  "repositories": [
    { "type": "vcs", "url": "ssh://git@git.acme.internal/private.git", "only": ["acme/*"] }
  ],
  "require": {
    "acme/secretpkg": "^1.0",
    "other/pkg": "^1.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        let secret = result
            .dependencies
            .iter()
            .find(|d| d.name == "acme/secretpkg")
            .unwrap();
        let other = result
            .dependencies
            .iter()
            .find(|d| d.name == "other/pkg")
            .unwrap();
        assert_eq!(
            secret.source,
            deps_core::parser::DependencySource::Git {
                url: "ssh://git@git.acme.internal/private.git".into(),
                rev: None,
            }
        );
        assert_eq!(other.source, deps_core::parser::DependencySource::Registry);
    }

    /// Critic S3: a `package`-type repository carries an exact, manifest-declared package
    /// name — no `only` filter or heuristic needed.
    #[test]
    fn test_package_type_repository_classifies_exact_name() {
        let json = r#"{
  "repositories": [
    {
      "type": "package",
      "package": {
        "name": "acme/secretpkg",
        "version": "1.0.0",
        "source": { "type": "git", "url": "ssh://git@git.acme.internal/private.git", "reference": "main" }
      }
    }
  ],
  "require": {
    "acme/secretpkg": "^1.0",
    "symfony/console": "^6.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        let secret = result
            .dependencies
            .iter()
            .find(|d| d.name == "acme/secretpkg")
            .unwrap();
        let console = result
            .dependencies
            .iter()
            .find(|d| d.name == "symfony/console")
            .unwrap();
        assert_eq!(
            secret.source,
            deps_core::parser::DependencySource::Git {
                url: "ssh://git@git.acme.internal/private.git".into(),
                rev: None,
            }
        );
        assert_eq!(
            console.source,
            deps_core::parser::DependencySource::Registry
        );
    }

    /// Critic S3: `{"packagist.org": false}` disables the implicit public-registry fallback
    /// for every otherwise-unmatched dependency.
    #[test]
    fn test_packagist_org_disabled_fails_closed_for_unmatched_dependencies() {
        let json = r#"{
  "repositories": [
    { "packagist.org": false },
    { "type": "vcs", "url": "ssh://git@git.acme.internal/private.git", "only": ["acme/secretpkg"] }
  ],
  "require": {
    "acme/secretpkg": "^1.0",
    "symfony/console": "^6.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        let secret = result
            .dependencies
            .iter()
            .find(|d| d.name == "acme/secretpkg")
            .unwrap();
        let console = result
            .dependencies
            .iter()
            .find(|d| d.name == "symfony/console")
            .unwrap();
        assert_eq!(
            secret.source,
            deps_core::parser::DependencySource::Git {
                url: "ssh://git@git.acme.internal/private.git".into(),
                rev: None,
            },
            "the only-matched dependency keeps its explicit classification"
        );
        assert_eq!(
            console.source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "packagist.org".into(),
            },
            "an unmatched dependency must fail closed, never fall back to Registry, once \
             packagist.org itself is disabled"
        );
    }

    /// Team-lead follow-up: the `artifact` repository kind (a pre-built package archive,
    /// e.g. a local/network directory of zip files) had no test at all — classifies as `Url`,
    /// distinct from `vcs`'s `Git` and `path`'s `Path`.
    #[test]
    fn test_artifact_repository_classifies_as_url() {
        let json = r#"{
  "repositories": [
    { "type": "artifact", "url": "file:///opt/composer-artifacts", "only": ["acme/secretpkg"] }
  ],
  "require": {
    "acme/secretpkg": "^1.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Url {
                url: "file:///opt/composer-artifacts".into(),
            }
        );
    }

    /// Team-lead follow-up: every one of Composer's 8 documented `vcs`-equivalent `type`
    /// aliases must classify identically to plain `"vcs"` — previously only implicitly
    /// exercised via one alias in the vendor-heuristic test that was since removed (S4).
    #[test]
    fn test_all_vcs_type_aliases_classify_as_git() {
        for alias in [
            "vcs",
            "github",
            "gitlab",
            "bitbucket",
            "git",
            "hg",
            "fossil",
            "perforce",
            "svn",
        ] {
            let json = format!(
                r#"{{
  "repositories": [
    {{ "type": "{alias}", "url": "ssh://git@git.acme.internal/private.git", "only": ["acme/secretpkg"] }}
  ],
  "require": {{
    "acme/secretpkg": "^1.0"
  }}
}}"#
            );

            let result = parse_composer_json(&json, &test_uri()).unwrap();
            assert_eq!(
                result.dependencies[0].source,
                deps_core::parser::DependencySource::Git {
                    url: "ssh://git@git.acme.internal/private.git".into(),
                    rev: None,
                },
                "type: \"{alias}\" must classify identically to type: \"vcs\""
            );
        }
    }

    /// Team-lead follow-up: Composer 2's object-map form of `repositories` (keyed by an
    /// arbitrary label instead of a bare array) must classify identically to the array form —
    /// previously only the array form had any test coverage.
    #[test]
    fn test_repositories_object_map_form_classifies_same_as_array_form() {
        let json = r#"{
  "repositories": {
    "acme-private": { "type": "vcs", "url": "ssh://git@git.acme.internal/private.git", "only": ["acme/secretpkg"] }
  },
  "require": {
    "acme/secretpkg": "^1.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Git {
                url: "ssh://git@git.acme.internal/private.git".into(),
                rev: None,
            }
        );
    }

    #[test]
    fn test_repository_only_filter_is_exact() {
        let json = r#"{
  "repositories": [
    { "type": "path", "url": "../local-packages/*", "only": ["acme/local-pkg"] }
  ],
  "require": {
    "acme/local-pkg": "*",
    "symfony/console": "^6.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        let local = result
            .dependencies
            .iter()
            .find(|d| d.name == "acme/local-pkg")
            .unwrap();
        let console = result
            .dependencies
            .iter()
            .find(|d| d.name == "symfony/console")
            .unwrap();

        assert_eq!(
            local.source,
            deps_core::parser::DependencySource::Path {
                path: "../local-packages/*".into(),
            }
        );
        assert_eq!(
            console.source,
            deps_core::parser::DependencySource::Registry,
            "an `only`-filtered repository must not affect packages outside its list"
        );
    }

    #[test]
    fn test_no_repositories_stays_registry() {
        let json = r#"{ "require": { "symfony/console": "^6.0" } }"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
    }

    #[test]
    fn test_parse_require() {
        let json = r#"{
  "require": {
    "symfony/console": "^6.0",
    "monolog/monolog": "^3.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        // JSON object iteration order is not guaranteed, so find by name
        let symfony = result
            .dependencies
            .iter()
            .find(|d| d.name == "symfony/console")
            .expect("symfony/console not found");
        assert_eq!(symfony.version_req, Some("^6.0".into()));
        assert_matches!(symfony.section, ComposerSection::Require);

        let monolog = result
            .dependencies
            .iter()
            .find(|d| d.name == "monolog/monolog")
            .expect("monolog/monolog not found");
        assert_eq!(monolog.version_req, Some("^3.0".into()));
    }

    #[test]
    fn test_parse_require_dev() {
        let json = r#"{
  "require-dev": {
    "phpunit/phpunit": "^10.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(result.dependencies[0].section, ComposerSection::RequireDev);
    }

    #[test]
    fn test_filter_platform_packages() {
        let json = r#"{
  "require": {
    "php": ">=8.1",
    "ext-mbstring": "*",
    "lib-xml": "*",
    "symfony/console": "^6.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "symfony/console");
    }

    #[test]
    fn test_is_platform_package() {
        assert!(is_platform_package("php"));
        assert!(is_platform_package("ext-mbstring"));
        assert!(is_platform_package("ext-json"));
        assert!(is_platform_package("lib-xml"));
        assert!(!is_platform_package("symfony/console"));
        assert!(!is_platform_package("monolog/monolog"));
        assert!(!is_platform_package("extended/package")); // not ext- prefix
    }

    /// #402 critique S1: the platform-package set previously covered only `php`/`ext-*`/
    /// `lib-*`, so a real requirement like `composer-plugin-api` fell through to the
    /// Packagist-shaped `vendor/package` name validator and was flagged "Invalid package
    /// name" instead of being silently filtered like the other platform packages.
    #[test]
    fn test_is_platform_package_covers_full_composer_platform_set() {
        for name in [
            "php-64bit",
            "php-ipv6",
            "php-zts",
            "php-debug",
            "hhvm",
            "composer",
            "composer-plugin-api",
            "composer-runtime-api",
        ] {
            assert!(
                is_platform_package(name),
                "expected {name:?} to be recognized as a platform package"
            );
        }
    }

    /// #402 critique C2: a real Packagist package under a vendor whose name happens to start
    /// with a platform prefix (`php-di/php-di`, `php-amqplib/php-amqplib`,
    /// `ext-mongo/whatever`, `lib-xml/whatever`) must not be misclassified as a platform
    /// package — that would silently drop it from the dependency list entirely, with no
    /// diagnostic, hover, inlay hint, or code lens, rather than validating it normally.
    #[test]
    fn test_is_platform_package_does_not_swallow_real_packages_with_platform_like_vendors() {
        for name in [
            "php-di/php-di",
            "php-amqplib/php-amqplib",
            "php-debugbar/php-debugbar",
            "php-ffmpeg/php-ffmpeg",
            "ext-mongo/whatever",
            "lib-xml/whatever",
            "hhvm/whatever",
            "composer/whatever",
        ] {
            assert!(
                !is_platform_package(name),
                "expected {name:?} to NOT be recognized as a platform package"
            );
        }
    }

    #[test]
    fn test_parse_both_sections() {
        let json = r#"{
  "require": {
    "symfony/console": "^6.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let require_count = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.section, ComposerSection::Require))
            .count();
        let dev_count = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.section, ComposerSection::RequireDev))
            .count();

        assert_eq!(require_count, 1);
        assert_eq!(dev_count, 1);
    }

    #[test]
    fn test_non_string_dependency_value_is_skipped() {
        // #621, same bug class as npm's #619: an object-valued entry (e.g. accidentally
        // nested config) is not a valid dependency declaration and must not be surfaced or
        // queried against the registry. Full coverage of every non-string value kind lives in
        // `deps_core::json_helpers::string_valued_entries`'s own tests (#624).
        let json = r#"{
  "require": {
    "nested-shadow": { "acme/express": "0.0.1" },
    "symfony/console": "^6.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "symfony/console");
        assert_eq!(result.dependencies[0].version_req, Some("^6.0".into()));
    }

    #[test]
    fn test_all_invalid_dependency_values_skipped_across_both_sections_end_to_end() {
        // #621: end-to-end confirmation that the skip applies uniformly across `require` and
        // `require-dev`, and to more than one non-string kind — this only guards the
        // parser/helper wiring; full value-kind coverage lives in
        // `deps_core::json_helpers::string_valued_entries`'s own tests (#624).
        let json = r#"{
  "require": {
    "bad/object": { "nested": "0.0.1" },
    "bad/number": 1,
    "symfony/console": "^6.0"
  },
  "require-dev": {
    "bad/object-dev": { "nested": "0.0.1" }
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "symfony/console");
    }

    /// #424: `minimum-stability` is parsed from the manifest root when present.
    #[test]
    fn test_parse_minimum_stability_present() {
        let json = r#"{
  "minimum-stability": "beta",
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.minimum_stability,
            MinimumStability::Declared(StabilityFloor::Beta)
        );
    }

    /// #424: a manifest with no `minimum-stability` field parses to `Absent`, not a
    /// fabricated `"stable"` — the stable default is applied by the registry, not the parser.
    #[test]
    fn test_parse_minimum_stability_absent() {
        let json = r#"{"require": {"symfony/console": "^6.0"}}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.minimum_stability, MinimumStability::Absent);
    }

    /// #1444: an unrecognized `minimum-stability` string parses to `Invalid`, with the range
    /// pointing at the value.
    #[test]
    fn test_parse_minimum_stability_invalid_string() {
        let json = r#"{
  "minimum-stability": "betta",
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        let MinimumStability::Invalid(occurrence) = &result.minimum_stability else {
            panic!("expected Invalid, got {:?}", result.minimum_stability);
        };
        assert_eq!(occurrence.raw, "betta");
        assert_eq!(occurrence.range.start.line, 1);
        let line = "  \"minimum-stability\": \"betta\",";
        assert_eq!(
            occurrence.range.start.character,
            line.find("betta").unwrap() as u32
        );
    }

    /// #1444: a non-string `minimum-stability` value (a number) parses to `Invalid`, with the
    /// range falling back to the declaring key since there is no string value span.
    #[test]
    fn test_parse_minimum_stability_invalid_number() {
        let json = r#"{
  "minimum-stability": 42,
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        let MinimumStability::Invalid(occurrence) = &result.minimum_stability else {
            panic!("expected Invalid, got {:?}", result.minimum_stability);
        };
        assert_eq!(occurrence.raw, "42");
        assert_eq!(occurrence.range.start.line, 1);
        let line = "  \"minimum-stability\": 42,";
        assert_eq!(
            occurrence.range.start.character,
            line.find("minimum-stability").unwrap() as u32
        );
    }

    /// #1444: a `null` `minimum-stability` value also parses to `Invalid`.
    #[test]
    fn test_parse_minimum_stability_invalid_null() {
        let json = r#"{
  "minimum-stability": null,
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_matches!(result.minimum_stability, MinimumStability::Invalid(_));
    }

    /// #1433: `ParseResult::selection_context()` surfaces the parsed `minimum-stability`
    /// through the shared `SelectionContext` type — the same value hover/completion/code
    /// actions now read to agree with diagnostics about "latest".
    #[test]
    fn test_selection_context_carries_minimum_stability() {
        use deps_core::ParseResult;

        let json = r#"{
  "minimum-stability": "alpha",
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.selection_context().minimum_stability(),
            Some(StabilityFloor::Alpha)
        );
    }

    /// #1433: a manifest with no `minimum-stability` field surfaces an empty
    /// `SelectionContext`, matching `minimum_stability`'s own `Absent` default.
    #[test]
    fn test_selection_context_none_when_minimum_stability_absent() {
        use deps_core::ParseResult;

        let json = r#"{"require": {"symfony/console": "^6.0"}}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.selection_context().minimum_stability(), None);
    }

    /// #1444: `selection_context()` for an `Invalid` `minimum-stability` equals
    /// `SelectionContext::none()` — the range/raw text of the invalid occurrence must not
    /// leak into `SelectionContext` (it derives `PartialEq`, and a caller diffs it to decide
    /// whether to refetch; see `ParseResult::invalid_minimum_stability`'s own doc for why this
    /// is deliberate).
    #[test]
    fn test_selection_context_none_when_minimum_stability_invalid() {
        use deps_core::ParseResult;

        let json = r#"{
  "minimum-stability": "betta",
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.selection_context(),
            deps_core::SelectionContext::none()
        );
    }

    /// #1444: `invalid_minimum_stability()` is `None` for both `Absent` and `Declared`.
    #[test]
    fn test_invalid_minimum_stability_none_for_absent_and_declared() {
        use deps_core::ParseResult;

        let absent =
            parse_composer_json(r#"{"require": {"symfony/console": "^6.0"}}"#, &test_uri())
                .unwrap();
        assert!(absent.invalid_minimum_stability().is_none());

        let declared = parse_composer_json(
            r#"{"minimum-stability": "beta", "require": {"symfony/console": "^6.0"}}"#,
            &test_uri(),
        )
        .unwrap();
        assert!(declared.invalid_minimum_stability().is_none());
    }

    #[test]
    fn test_parse_empty() {
        let json = r#"{"name": "vendor/project"}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_composer_json("{invalid json}", &test_uri());
        assert_matches!(result, Err(deps_core::DepsError::Json(_)));
    }

    #[test]
    fn test_parse_deeply_nested_json_rejected_before_parse() {
        // #430: a deeply nested `composer.json` must be rejected by the
        // depth guard rather than handed to `serde_json::from_str`. Reported
        // as `DepsError::Json`, the same variant a genuinely malformed
        // `composer.json` produces (unified via `deps_core::parse_json_checked`).
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        let result = parse_composer_json(&json, &test_uri());
        assert_matches!(result, Err(deps_core::DepsError::Json(_)));
    }

    #[test]
    fn test_parse_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"require": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let result = parse_composer_json(&json, &test_uri());
        assert!(result.is_ok());
    }

    #[test]
    fn test_position_tracking() {
        let json = r#"{
  "require": {
    "symfony/console": "^6.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name_range.start.line, 2);
        assert!(dep.version_range.is_some());
        assert_eq!(dep.version_range.unwrap().start.line, 2);
    }

    #[test]
    fn test_parse_empty_require() {
        let json = r#"{"require": {}}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    /// Regression test for https://github.com/bug-ops/deps-lsp/issues/84
    ///
    /// `serde_json::Map` iterates alphabetically without the `preserve_order` feature:
    /// guzzlehttp/guzzle → laravel/framework → symfony/console. The parser's original
    /// implementation searched for each dependency's position using a single
    /// monotonically-advancing cursor in that iteration order, so laravel/framework (file
    /// line 2) was searched for only after the cursor had already advanced past line 3,
    /// leaving its name_range and version_range at (0,0)→(0,0). Positions now come from an
    /// AST index keyed by name (#613), independent of `serde_json::Map` iteration order
    /// entirely — the same fix later generalized for the cross-section case in #610.
    #[test]
    fn test_position_tracking_out_of_alphabetical_order() {
        let json = r#"{
    "require": {
        "laravel/framework": "^10.0",
        "guzzlehttp/guzzle": "^7.5",
        "symfony/console": "~6.0"
    }
}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        for dep in &result.dependencies {
            // Every dependency must have a valid (non-zero) name position.
            assert!(
                dep.name_range.start.line > 0,
                "name_range for '{}' is at line 0 — position tracking regressed",
                dep.name.as_str()
            );
            assert!(
                dep.version_range.is_some(),
                "version_range for '{}' is missing",
                dep.name.as_str()
            );
        }

        let laravel = result
            .dependencies
            .iter()
            .find(|d| d.name == "laravel/framework")
            .unwrap();
        assert_eq!(laravel.name_range.start.line, 2);

        let guzzle = result
            .dependencies
            .iter()
            .find(|d| d.name == "guzzlehttp/guzzle")
            .unwrap();
        assert_eq!(guzzle.name_range.start.line, 3);

        let symfony = result
            .dependencies
            .iter()
            .find(|d| d.name == "symfony/console")
            .unwrap();
        assert_eq!(symfony.name_range.start.line, 4);
    }

    #[test]
    fn test_parse_composer_json_no_panic_with_multibyte_field_after_dependency() {
        // Public-API-level regression test for issue #245: an ordinary manifest where a
        // later top-level field (`description`) contains multi-byte UTF-8 must not upset
        // position tracking for an *earlier* dependency. AST-derived positions (#613) make
        // this structurally impossible (no byte-offset search window to straddle), but the
        // regression test stays as end-to-end coverage through the only entry point the LSP
        // layer actually calls.
        let json = r#"{
  "require": {
    "symfony/console": "^6.0"
  },
  "authors": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "description": "Gestão de projetos"
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let symfony = &result.dependencies[0];
        assert_eq!(symfony.name, "symfony/console");
        assert_eq!(symfony.version_req, Some("^6.0".into()));
        assert!(symfony.version_range.is_some());
    }

    // --- #610: duplicate dependency names across sections ---

    #[test]
    fn test_duplicate_name_across_require_and_require_dev() {
        // #610, same bug class as npm's #605: "vendor/pkg" appears in both `require` and
        // `require-dev`, with keys not in source-text order relative to each section's
        // start. The original implementation threaded a single, monotonically-advancing
        // `search_start` cursor across `serde_json::Map` iteration, so it could skip past —
        // or land on — the wrong occurrence whenever `Map` iteration order didn't match
        // source-text order. Positions now come from a per-section AST index (#613), so each
        // occurrence resolves to its own section's node directly, independent of both
        // `Map` iteration order and source-text order entirely.
        let json = r#"{
  "require": {
    "zzz/other": "^1.0",
    "vendor/pkg": "^2.0"
  },
  "require-dev": {
    "vendor/pkg": "^9.9",
    "aaa/other": "^1.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 4);

        let require_pkg = result
            .dependencies
            .iter()
            .find(|d| d.name == "vendor/pkg" && matches!(d.section, ComposerSection::Require))
            .expect("vendor/pkg in require");
        let dev_pkg = result
            .dependencies
            .iter()
            .find(|d| d.name == "vendor/pkg" && matches!(d.section, ComposerSection::RequireDev))
            .expect("vendor/pkg in require-dev");

        assert_eq!(require_pkg.version_req, Some("^2.0".into()));
        assert_eq!(dev_pkg.version_req, Some("^9.9".into()));

        assert_eq!(require_pkg.name_range.start.line, 3);
        assert_eq!(dev_pkg.name_range.start.line, 6);

        let require_version = require_pkg
            .version_range
            .expect("require vendor/pkg version_range");
        let dev_version = dev_pkg
            .version_range
            .expect("require-dev vendor/pkg version_range");
        assert_eq!(require_version.start.line, 3);
        assert_eq!(dev_version.start.line, 6);
    }

    // --- #613: AST-based position recovery edge cases ---

    /// A dependency's value can itself be a nested object containing a key with the same
    /// name as a real top-level dependency in this section (e.g. a malformed/unusual
    /// manifest). A text-based scanner finds the nested occurrence first; the AST only
    /// ever indexes a section's own *direct* properties, so the real top-level occurrence's
    /// position is never stolen by one nested inside a sibling's value. `a/b` itself has an
    /// object value, so it is skipped entirely (#621) — only `c/d` survives.
    #[test]
    fn test_nested_object_value_with_colliding_key_resolves_to_top_level_position() {
        let json = r#"{
  "require": {
    "a/b": {
      "c/d": "0.0.1"
    },
    "c/d": "^2.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let c_d = result
            .dependencies
            .iter()
            .find(|d| d.name == "c/d")
            .expect("c/d");
        assert_eq!(c_d.version_req, Some("^2.0".into()));
        // The real top-level "c/d" is on line 5, not line 3 (nested inside "a/b"'s value).
        assert_eq!(c_d.name_range.start.line, 5);
        let version_range = c_d.version_range.expect("c/d version_range");
        assert_eq!(version_range.start.line, 5);
    }

    /// JSON permits (if unusual) a duplicate top-level key; `serde_json::Map` keeps only the
    /// *last* occurrence's value (last-key-wins during deserialization, `preserve_order` or
    /// not). The AST lookup must resolve the identically-named "require" key the same way —
    /// the last one — not the first, or the surviving dependency's position silently defaults
    /// to `Range::default()` whenever the two sections don't share every name.
    #[test]
    fn test_duplicate_top_level_section_key_resolves_to_last_occurrence() {
        let json = r#"{
  "require": {
    "only-in-first": "^1.0"
  },
  "require": {
    "vendor/pkg": "^2.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let pkg = &result.dependencies[0];
        assert_eq!(pkg.name, "vendor/pkg");
        assert_eq!(pkg.version_req, Some("^2.0".into()));
        assert_ne!(pkg.name_range, Range::default());
        assert_eq!(pkg.name_range.start.line, 5);
        assert!(pkg.version_range.is_some());
    }

    /// M6(c): when the AST parse degrades (e.g. a future `jsonc-parser` disagreement with
    /// `serde_json` on content this crate's own `parse_composer_json` never actually
    /// produces — see [`JsonAst::parse`]'s doc), `positions: None` must still yield a
    /// dependency entry with a default, zero position rather than dropping it or panicking.
    #[test]
    fn test_parse_section_with_no_ast_positions_falls_back_to_default_range() {
        let mut deps = serde_json::Map::new();
        deps.insert("vendor/pkg".to_string(), Value::String("^1.0".into()));
        let content = r#"{"require": {"vendor/pkg": "^1.0"}}"#;
        let line_table = LineOffsetTable::new(content);

        let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);
        let result = parse_section(
            content,
            &deps,
            ComposerSection::Require,
            None,
            &line_table,
            &mut budget,
        );

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "vendor/pkg");
        assert_eq!(result[0].name_range, Range::default());
        assert!(result[0].version_range.is_none());
    }
}
