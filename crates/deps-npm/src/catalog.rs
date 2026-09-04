//! pnpm `pnpm-workspace.yaml` catalog resolution (spec 046).
//!
//! pnpm's "catalogs" feature lets a workspace define one or more named version catalogs in
//! `pnpm-workspace.yaml`, and a member `package.json` reference an entry by name instead of a
//! literal semver range: `"react": "catalog:"` (the default catalog) or
//! `"react": "catalog:react17"` (a named one).
//!
//! # The totality invariant
//!
//! Once the `catalog:` gate fires for a document (at least one dependency value starts with
//! `catalog:`), [`apply`] assigns every such dependency a [`CatalogOutcome`] before returning.
//! Failure to obtain a usable catalog map — a non-`file:` manifest URI, no ancestor
//! `pnpm-workspace.yaml`, a workspace file that vanished or is not a regular file, malformed
//! YAML, or a duplicate default catalog — is itself an outcome, never a skip: after [`apply`]
//! runs, no dependency has `version_req == Some(s)` with `s.starts_with("catalog:")`. This is
//! what makes it structurally impossible for the "Update all outdated dependencies" quick-fix
//! or code lens to rewrite `"react": "catalog:"` into a literal version — both gate on
//! [`deps_core::Dependency::version_requirement`] being `Some`. The invariant is enforced by
//! splitting the work into a fallible half ([`load`], which may legitimately return `None`) and
//! a total half ([`apply`], which has no early return and consumes `load`'s `Option` as a value
//! rather than short-circuiting on it).
//!
//! The raw `catalog:...` specifier text stays available via [`CatalogOrigin::specifier`] for
//! hover to anchor to, even when `version_req` is `None`.
//!
//! # The `Resolved` path's *different* protection
//!
//! For [`CatalogOutcome::Resolved`], `version_requirement()` is deliberately `Some(range)` (so
//! the ordinary registry/hover/diagnostic pipeline runs) — the totality invariant above does
//! not apply to it, and cannot: `version_req` is not `None`. What still stops "Update all
//! outdated dependencies" from rewriting `"react": "catalog:"` into a literal version here is
//! `literal_span_matches` (`deps_core::lsp_helpers`): it compares the manifest text sliced at
//! `version_range` (still `"catalog:"` — the parser never rewrites the *span*, only
//! `version_req`) against `version_literal().unwrap_or(version_req.as_str())`, and
//! `"catalog:"` never equals a real semver range. This holds only because
//! [`crate::types::NpmDependency`] does not override
//! [`deps_core::Dependency::version_literal`] (the trait default is `None`). If a future change
//! adds that override for some other reason, it must special-case the `Resolved` catalog path
//! (return `None` for it, or something that still fails `literal_span_matches`) or this
//! protection silently disarms. See
//! `parser::tests::test_resolved_catalog_dependency_blocks_update_all_rewrite` for the pinning
//! regression test.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use yaml_rust2::{Yaml, YamlLoader};

use crate::types::NpmDependency;

/// Reserved catalog-name key the default catalog (from either a top-level `catalog:` block or
/// a `catalogs.default:` section) is stored under in [`PnpmWorkspaceConfig`]'s map.
const DEFAULT_CATALOG_KEY: &str = "default";

/// Why a `pnpm-workspace.yaml`, once found, cannot resolve any catalog specifier at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDefect {
    /// The file could not be parsed as YAML, exceeded a nesting/expansion guard, or a
    /// `catalog:`/`catalogs:`/`catalogs.<name>` key held a non-mapping, non-null value.
    Malformed,
    /// Both a top-level `catalog:` block and a `catalogs.default:` section are present.
    /// pnpm's own `checkDefaultCatalogIsDefinedOnce` rejects the whole workspace manifest
    /// before returning any catalog map in this situation, so this defect applies to every
    /// catalog specifier in the workspace, not only default-catalog references.
    DuplicateDefaultCatalog,
}

/// One catalog entry's YAML leaf value, classified during parsing so a non-string leaf (e.g.
/// `react: {version: ^18}`) can be told apart from a genuinely absent key later, without
/// unwrapping an unexpected shape and panicking (NFR-003).
#[derive(Debug, Clone, PartialEq, Eq)]
enum CatalogValue {
    /// A scalar string leaf — pnpm's only documented catalog-entry shape.
    Range(String),
    /// The entry exists but its value isn't a scalar string.
    Malformed,
}

/// Parsed, catalog-relevant contents of one `pnpm-workspace.yaml`.
///
/// Keyed by catalog name, with the default catalog (from either definition site) stored under
/// the reserved key `"default"`. `defect` being set means the file is unusable for *any* catalog
/// specifier — see [`ConfigDefect`].
#[derive(Debug, Default)]
pub struct PnpmWorkspaceConfig {
    catalogs: HashMap<String, HashMap<String, CatalogValue>>,
    defect: Option<ConfigDefect>,
}

impl PnpmWorkspaceConfig {
    fn defective(defect: ConfigDefect) -> Self {
        Self {
            catalogs: HashMap::new(),
            defect: Some(defect),
        }
    }
}

/// Classifies a `catalog:`/`catalogs.<name>` YAML node into its flat dependency-name to
/// [`CatalogValue`] map.
///
/// `Ok(None)` — absent (missing key, indexed via [`Yaml`]'s `Index<&str>`, which collapses a
/// missing key to [`Yaml::BadValue`]) or an explicit null value (M2: a common result of
/// commenting a catalog block out, and *not* malformed — matches pnpm's own `!= null` gate).
/// `Ok(Some(map))` — a mapping; each leaf is classified independently so one bad leaf can't
/// fail the whole node. `Err(())` — anything else (a scalar or a sequence): the caller treats
/// this as the whole workspace file being malformed.
fn classify_catalog_node(node: &Yaml) -> Result<Option<HashMap<String, CatalogValue>>, ()> {
    match node {
        Yaml::BadValue | Yaml::Null => Ok(None),
        Yaml::Hash(map) => Ok(Some(
            map.iter()
                .filter_map(|(key, value)| {
                    key.as_str()
                        .map(|name| (name.to_string(), classify_entry(value)))
                })
                .collect(),
        )),
        _ => Err(()),
    }
}

/// Classifies one catalog entry's leaf value.
fn classify_entry(value: &Yaml) -> CatalogValue {
    match value.as_str() {
        Some(range) => CatalogValue::Range(range.to_string()),
        None => CatalogValue::Malformed,
    }
}

/// Classifies the top-level `catalogs:` node — a mapping of catalog name to its own flat
/// entry map — using the same absent/null/wrong-shape rule as [`classify_catalog_node`].
fn classify_catalogs_section(node: &Yaml) -> Result<Option<&yaml_rust2::yaml::Hash>, ()> {
    match node {
        Yaml::BadValue | Yaml::Null => Ok(None),
        Yaml::Hash(map) => Ok(Some(map)),
        _ => Err(()),
    }
}

/// Parses one `pnpm-workspace.yaml`'s catalog-relevant content into a [`PnpmWorkspaceConfig`].
///
/// Infallible by design (see [`deps_core::MtimeFileCache::get_or_parse`]'s `parse` parameter):
/// every failure mode — depth/expansion guard rejection, unparseable YAML, a non-mapping
/// `catalog:`/`catalogs:`/`catalogs.<name>` — collapses to a defective
/// [`PnpmWorkspaceConfig`] with [`ConfigDefect::Malformed`] rather than propagating an error,
/// so a broken workspace file degrades this dependency's resolution instead of panicking or
/// blocking the rest of the document's diagnostics (NFR-003).
fn parse_pnpm_workspace(content: &str) -> PnpmWorkspaceConfig {
    if deps_core::check_yaml_nesting_depth(content, deps_core::MAX_YAML_NESTING_DEPTH).is_err()
        || deps_core::check_yaml_expansion(content, deps_core::MAX_YAML_EXPANDED_BYTES).is_err()
    {
        return PnpmWorkspaceConfig::defective(ConfigDefect::Malformed);
    }

    let Ok(docs) = YamlLoader::load_from_str(content) else {
        return PnpmWorkspaceConfig::defective(ConfigDefect::Malformed);
    };
    let Some(doc) = docs.first() else {
        return PnpmWorkspaceConfig::default();
    };

    let top_level_catalog = match classify_catalog_node(&doc["catalog"]) {
        Ok(entries) => entries,
        Err(()) => return PnpmWorkspaceConfig::defective(ConfigDefect::Malformed),
    };
    let named_catalogs = match classify_catalogs_section(&doc["catalogs"]) {
        Ok(section) => section,
        Err(()) => return PnpmWorkspaceConfig::defective(ConfigDefect::Malformed),
    };

    let mut catalogs: HashMap<String, HashMap<String, CatalogValue>> = HashMap::new();
    let mut named_default = None;

    if let Some(named_catalogs) = named_catalogs {
        for (name, value) in named_catalogs {
            let Some(name) = name.as_str() else { continue };
            let entries = match classify_catalog_node(value) {
                Ok(entries) => entries,
                Err(()) => return PnpmWorkspaceConfig::defective(ConfigDefect::Malformed),
            };
            let Some(entries) = entries else { continue };
            if name == DEFAULT_CATALOG_KEY {
                named_default = Some(entries);
            } else {
                catalogs.insert(name.to_string(), entries);
            }
        }
    }

    // M1: a top-level `catalog:` block and a `catalogs.default:` section both present is
    // unresolvable, matching pnpm's `checkDefaultCatalogIsDefinedOnce` — never per-key merged.
    let default_entries = match (top_level_catalog, named_default) {
        (Some(_), Some(_)) => {
            return PnpmWorkspaceConfig::defective(ConfigDefect::DuplicateDefaultCatalog);
        }
        (Some(entries), None) | (None, Some(entries)) => Some(entries),
        (None, None) => None,
    };
    if let Some(entries) = default_entries {
        catalogs.insert(DEFAULT_CATALOG_KEY.to_string(), entries);
    }

    PnpmWorkspaceConfig {
        catalogs,
        defect: None,
    }
}

/// Per-path memoization of `pnpm-workspace.yaml` parses, invalidated by mtime.
///
/// The pnpm catalog analogue of [`crate::config::NpmConfigCache`], reusing the same
/// [`deps_core::MtimeFileCache`] primitive (spec NFR-001).
#[derive(Debug)]
pub struct PnpmWorkspaceCache(deps_core::MtimeFileCache<PnpmWorkspaceConfig>);

impl Default for PnpmWorkspaceCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PnpmWorkspaceCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self(deps_core::MtimeFileCache::new(
            deps_core::DEFAULT_MAX_CACHED_FILES,
            "pnpm workspace",
        ))
    }

    /// Returns `path`'s parsed contents, from cache if `path`'s mtime is unchanged, else
    /// re-reading and re-parsing. `None` if `path` does not exist, is not a regular file
    /// (including a directory sharing the name), or cannot be read.
    fn get_or_parse(&self, path: &Path) -> Option<Arc<PnpmWorkspaceConfig>> {
        self.0.get_or_parse(path, parse_pnpm_workspace)
    }
}

/// A parsed `catalog:` / `catalog:<name>` dependency value.
///
/// `catalog:` and `catalog:default` are the same reference (pnpm.io/catalogs: the shorthand is
/// documented as equivalent to the explicit long form for the default catalog only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CatalogSpecifier<'a> {
    /// `catalog:` or `catalog:default`.
    Default,
    /// `catalog:<name>` for a non-empty, non-`default` `<name>`.
    Named(&'a str),
}

impl<'a> CatalogSpecifier<'a> {
    /// Parses `value` as a catalog specifier, or `None` if it doesn't start with `catalog:` at
    /// all (including the `npm:<pkg>@catalog:<name>` alias form — not detected; see
    /// [`apply`]'s doc).
    ///
    /// Deliberately does **not** trim whitespace around `<name>` — a conservative choice
    /// pending confirmation against pnpm's own specifier-parser source, not verified pnpm
    /// behavior. A trimmed name could only ever resolve something pnpm itself rejects, never
    /// the reverse, so declining to trim is the safe direction either way.
    fn parse(value: &'a str) -> Option<Self> {
        let name = value.strip_prefix("catalog:")?;
        match name {
            "" | DEFAULT_CATALOG_KEY => Some(Self::Default),
            other => Some(Self::Named(other)),
        }
    }
}

/// Why a `catalog:` / `catalog:<name>` specifier did or didn't resolve to a usable semver
/// range.
///
/// Every variant but [`Self::Resolved`] means [`deps_core::Dependency::version_requirement`]
/// is `None` for that dependency (see the module's totality invariant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogOutcome {
    /// Resolved to the given semver range, fed into the ordinary registry/hover/diagnostic
    /// pipeline exactly as a literal-range dependency would be.
    Resolved(String),
    /// The catalog entry exists but its value isn't a semver range pnpm's own `node-semver`
    /// would accept (e.g. `workspace:*`, a git URL) — hover-only, no diagnostic: a typo can't
    /// be told apart from a legitimate non-registry specifier, and a false warning is worse
    /// than silence.
    NonSemverEntry {
        /// The raw, unparsed catalog entry value.
        value: String,
    },
    /// The catalog entry exists but its value isn't even a scalar string (e.g.
    /// `react: {version: ^18}`) — distinct from [`Self::MissingEntry`] so the message doesn't
    /// send the user looking for a key that's right in front of them.
    MalformedEntry,
    /// No `pnpm-workspace.yaml` was found in any ancestor directory of the `package.json`
    /// being parsed (or the manifest has no filesystem directory to search from at all, e.g. a
    /// non-`file:` URI).
    NoWorkspaceFile,
    /// A `pnpm-workspace.yaml` was found but could not be parsed, or had a
    /// `catalog:`/`catalogs:`/`catalogs.<name>` key of the wrong shape.
    MalformedWorkspaceFile,
    /// The workspace file defines the default catalog twice (a top-level `catalog:` block
    /// *and* a `catalogs.default:` section) — unresolvable, workspace-wide (see
    /// [`ConfigDefect::DuplicateDefaultCatalog`]).
    DuplicateDefaultCatalog,
    /// `catalog:<name>` names a catalog that doesn't exist in `catalogs:`.
    UnknownCatalog,
    /// The referenced catalog exists (or the workspace file has neither a `catalog:` nor a
    /// `catalogs:` key at all, which behaves as an empty default catalog) but has no entry for
    /// this dependency's name.
    MissingEntry,
}

/// Where a catalog-referencing dependency's resolution came from, and what happened.
///
/// Stored on [`NpmDependency::catalog`], `None` for every non-catalog dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogOrigin {
    /// The raw `catalog:...` text as written in the manifest (e.g. `"catalog:react17"`).
    pub specifier: String,
    /// The referenced catalog's name, or `None` for the default catalog.
    pub catalog: Option<String>,
    /// What resolving `specifier` against the workspace's catalog map produced.
    pub outcome: CatalogOutcome,
}

/// Upper bound (Unicode scalar values) on how much of any single attacker-controlled fragment
/// (the raw specifier, a dependency name, or a catalog name — all ultimately sourced from a
/// cloned repository's `package.json`/`pnpm-workspace.yaml`) is ever interpolated into a
/// diagnostic or hover message. Mirrors `deps-github-actions`'s
/// `MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS` precedent (security audit LOW finding: without a
/// bound, a multi-megabyte catalog entry value renders in full on every hover).
const MAX_CATALOG_MESSAGE_VALUE_CHARS: usize = 128;

/// Length-bounds `s` before it is wrapped for interpolation — see
/// [`MAX_CATALOG_MESSAGE_VALUE_CHARS`].
fn bounded(s: &str) -> std::borrow::Cow<'_, str> {
    deps_core::lsp_helpers::truncate_for_diagnostic(s, MAX_CATALOG_MESSAGE_VALUE_CHARS)
}

impl CatalogOrigin {
    /// The diagnostic message for this outcome, or `None` when nothing should be reported —
    /// either the specifier resolved cleanly, or (for [`CatalogOutcome::NonSemverEntry`]) a
    /// warning would be less accurate than silence (see that variant's doc).
    ///
    /// Plain text: an LSP diagnostic message is never rendered as Markdown by any client, so
    /// this leaves `dependency_name`/catalog names unescaped (only length-bounded) rather than
    /// paying `escape_markdown`'s backslash-per-punctuation cost for common, harmless values
    /// like a scoped package name (`@myorg/pkg`). See [`Self::hover_detail`] for the sibling
    /// rendering that *does* feed Markdown and therefore must escape.
    #[must_use]
    pub fn diagnostic_message(&self, dependency_name: &str) -> Option<String> {
        self.render(dependency_name, |s| format!("`{s}`"), str::to_string)
    }

    /// Markdown-safe rendering of this outcome for the hover `**Catalog**` line.
    ///
    /// Security audit HIGH finding: this string is spliced directly into
    /// `MarkupKind::Markdown` hover content, unlike [`Self::diagnostic_message`]'s plain-text
    /// diagnostic — so every attacker-controlled fragment must go through
    /// [`deps_core::lsp_helpers::markdown_code_span`] (the specifier/range/value) or
    /// [`deps_core::lsp_helpers::escape_markdown`] (a dependency or catalog name) before
    /// interpolation, closing the Markdown-breakout (`` ` `` / `]( `) and auto-loaded-image
    /// (`![]()`) vectors a raw `format!` would otherwise open.
    #[must_use]
    pub fn hover_detail(&self, dependency_name: &str) -> String {
        use deps_core::lsp_helpers::{escape_markdown, markdown_code_span};

        match &self.outcome {
            CatalogOutcome::Resolved(range) => format!(
                "{} → {}",
                markdown_code_span(&bounded(&self.specifier)),
                markdown_code_span(&bounded(range))
            ),
            CatalogOutcome::NonSemverEntry { value } => format!(
                "{} → {} (not a version range)",
                markdown_code_span(&bounded(&self.specifier)),
                markdown_code_span(&bounded(value))
            ),
            _ => self
                .render(dependency_name, markdown_code_span, escape_markdown)
                .unwrap_or_default(),
        }
    }

    /// Shared message shape for every non-`Resolved`/`NonSemverEntry` outcome — `code` wraps
    /// the (length-bounded) specifier, `text` wraps a (length-bounded) dependency or catalog
    /// name. Two callers, two escaping strategies (see [`Self::diagnostic_message`] vs
    /// [`Self::hover_detail`]), one message shape to keep them from drifting apart.
    fn render(
        &self,
        dependency_name: &str,
        code: impl Fn(&str) -> String,
        text: impl Fn(&str) -> String,
    ) -> Option<String> {
        let specifier = code(&bounded(&self.specifier));
        let dependency_name = text(&bounded(dependency_name));
        let catalog_phrase = match self.catalog.as_deref() {
            None => "the default catalog".to_string(),
            Some(name) => format!("catalog '{}'", text(&bounded(name))),
        };

        match &self.outcome {
            CatalogOutcome::Resolved(_) | CatalogOutcome::NonSemverEntry { .. } => None,
            CatalogOutcome::MalformedEntry => Some(format!(
                "the entry for '{dependency_name}' in {catalog_phrase} of pnpm-workspace.yaml is not a version string"
            )),
            CatalogOutcome::MissingEntry => Some(format!(
                "{specifier} has no entry for '{dependency_name}' in {catalog_phrase} of pnpm-workspace.yaml"
            )),
            CatalogOutcome::UnknownCatalog => {
                let name = text(&bounded(self.catalog.as_deref().unwrap_or_default()));
                Some(format!(
                    "{specifier} refers to catalog '{name}', which is not defined in pnpm-workspace.yaml"
                ))
            }
            CatalogOutcome::NoWorkspaceFile => Some(format!(
                "{specifier} requires a pnpm-workspace.yaml in an ancestor directory; none was found"
            )),
            CatalogOutcome::MalformedWorkspaceFile => Some(format!(
                "pnpm-workspace.yaml could not be parsed; {specifier} cannot be resolved"
            )),
            CatalogOutcome::DuplicateDefaultCatalog => Some(format!(
                "pnpm-workspace.yaml defines the default catalog twice (top-level `catalog:` and \
                 `catalogs.default:`); pnpm rejects this, so {specifier} cannot be resolved"
            )),
        }
    }
}

/// Resolves one dependency's already-parsed `specifier` against `config`.
fn resolve(
    config: Option<&PnpmWorkspaceConfig>,
    specifier: CatalogSpecifier<'_>,
    dependency_name: &str,
) -> CatalogOutcome {
    let Some(config) = config else {
        return CatalogOutcome::NoWorkspaceFile;
    };
    if let Some(defect) = config.defect {
        return match defect {
            ConfigDefect::Malformed => CatalogOutcome::MalformedWorkspaceFile,
            ConfigDefect::DuplicateDefaultCatalog => CatalogOutcome::DuplicateDefaultCatalog,
        };
    }

    let (key, is_default) = match specifier {
        CatalogSpecifier::Default => (DEFAULT_CATALOG_KEY, true),
        CatalogSpecifier::Named(name) => (name, false),
    };

    let Some(catalog) = config.catalogs.get(key) else {
        // Spec §6: a workspace file with neither `catalog:` nor `catalogs:` at all behaves as
        // "no entry" for the default catalog, not "unknown catalog" — there is no name to be
        // unknown in that case.
        return if is_default {
            CatalogOutcome::MissingEntry
        } else {
            CatalogOutcome::UnknownCatalog
        };
    };

    match catalog.get(dependency_name) {
        None => CatalogOutcome::MissingEntry,
        Some(CatalogValue::Malformed) => CatalogOutcome::MalformedEntry,
        Some(CatalogValue::Range(range)) => match node_semver::Range::parse(range) {
            Ok(_) => CatalogOutcome::Resolved(range.clone()),
            Err(_) => CatalogOutcome::NonSemverEntry {
                value: range.clone(),
            },
        },
    }
}

/// Walks up from `manifest_dir` looking for the nearest-ancestor `pnpm-workspace.yaml` — the
/// first match wins and the walk stops there, matching pnpm's own `find-workspace-dir`
/// algorithm and its documented single-root-per-tree design (spec §6/§9).
fn find_workspace_file(manifest_dir: &Path) -> Option<PathBuf> {
    let mut current = Some(manifest_dir);
    let mut depth = 0usize;
    while let Some(dir) = current {
        if depth >= crate::config::MAX_CONFIG_ANCESTOR_DEPTH {
            break;
        }
        depth += 1;

        // `exists()` rather than `is_file()`: a `pnpm-workspace.yaml` that exists but is a
        // directory (or another irregular file) still counts as "found" here — the file-type
        // check belongs to `PnpmWorkspaceCache::get_or_parse`, whose `None` `load` maps to a
        // defective `Malformed` config rather than to a *different* ancestor's file (or none
        // at all) being silently substituted.
        let candidate = dir.join("pnpm-workspace.yaml");
        if candidate.exists() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

/// The fallible half of catalog resolution: locates and parses the nearest-ancestor
/// `pnpm-workspace.yaml`, if any.
///
/// `None` means there is nothing to resolve against — no `manifest_dir` at all (e.g. a
/// non-`file:` manifest URI), or no ancestor `pnpm-workspace.yaml` found. A workspace file that
/// was found but is unreadable (vanished between discovery and read, or is not a regular file)
/// instead comes back as a defective [`PnpmWorkspaceConfig`] carrying
/// [`ConfigDefect::Malformed`], not `None` — [`apply`] treats both `None` and a defective
/// config as an unresolved outcome, but keeping them distinct here matches
/// [`deps_core::MtimeFileCache::get_or_parse`]'s own contract.
///
/// # Examples
///
/// ```
/// use deps_npm::catalog::{PnpmWorkspaceCache, load};
/// use std::path::Path;
///
/// let cache = PnpmWorkspaceCache::new();
/// assert!(load(Some(Path::new("/nonexistent/workspace")), &cache).is_none());
/// assert!(load(None, &cache).is_none());
/// ```
#[must_use]
pub fn load(
    manifest_dir: Option<&Path>,
    cache: &PnpmWorkspaceCache,
) -> Option<Arc<PnpmWorkspaceConfig>> {
    let dir = manifest_dir?;
    let path = find_workspace_file(dir)?;
    Some(
        cache
            .get_or_parse(&path)
            .unwrap_or_else(|| Arc::new(PnpmWorkspaceConfig::defective(ConfigDefect::Malformed))),
    )
}

/// The total half of catalog resolution.
///
/// Assigns every `catalog:`-referencing dependency in `deps` a [`CatalogOrigin`] (and rewrites
/// `version_req` for a resolved one), including when `config` is `None`. See the module's
/// totality invariant.
///
/// Deliberately does not detect the npm-alias form `"npm:<pkg>@catalog:<name>"` — no user
/// story covers it and it is not a regression (today's pre-feature behavior is identical); see
/// `docs/ECOSYSTEM_GUIDE.md`'s pnpm Catalogs "Known limitations".
pub fn apply(deps: &mut [NpmDependency], config: Option<&PnpmWorkspaceConfig>) {
    for dep in deps {
        let Some(raw) = dep.version_req.as_ref().map(deps_core::VersionReq::as_str) else {
            continue;
        };
        let Some(specifier) = CatalogSpecifier::parse(raw) else {
            continue;
        };

        let specifier_text = raw.to_string();
        let catalog_name = match specifier {
            CatalogSpecifier::Default => None,
            CatalogSpecifier::Named(name) => Some(name.to_string()),
        };

        let outcome = resolve(config, specifier, dep.name.as_str());
        dep.version_req = match &outcome {
            CatalogOutcome::Resolved(range) => Some(deps_core::VersionReq::from(range.clone())),
            _ => None,
        };
        dep.catalog = Some(CatalogOrigin {
            specifier: specifier_text,
            catalog: catalog_name,
            outcome,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NpmDependencySection;
    use std::assert_matches;
    use tower_lsp_server::ls_types::Range;

    fn dep(name: &str, version_req: &str) -> NpmDependency {
        NpmDependency {
            name: name.into(),
            name_range: Range::default(),
            version_req: Some(version_req.into()),
            version_range: Some(Range::default()),
            section: NpmDependencySection::Dependencies,
            source: deps_core::parser::DependencySource::Registry,
            catalog: None,
        }
    }

    fn workspace(dir: &std::path::Path, content: &str) {
        std::fs::write(dir.join("pnpm-workspace.yaml"), content).unwrap();
    }

    // --- CatalogSpecifier::parse ---

    #[test]
    fn test_parse_shorthand_and_explicit_default_are_the_same() {
        assert_eq!(
            CatalogSpecifier::parse("catalog:"),
            CatalogSpecifier::parse("catalog:default")
        );
        assert_eq!(
            CatalogSpecifier::parse("catalog:"),
            Some(CatalogSpecifier::Default)
        );
    }

    #[test]
    fn test_parse_named() {
        assert_eq!(
            CatalogSpecifier::parse("catalog:react17"),
            Some(CatalogSpecifier::Named("react17"))
        );
    }

    #[test]
    fn test_parse_non_catalog_value_is_none() {
        assert_eq!(CatalogSpecifier::parse("^18.3.0"), None);
        assert_eq!(CatalogSpecifier::parse("workspace:*"), None);
    }

    // --- apply / load end-to-end (US-001..US-004, edge-case table) ---

    #[test]
    fn test_apply_default_catalog_resolves() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog:\n  react: ^18.3.0\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, Some("^18.3.0".into()));
        assert_matches!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::Resolved(ref r) if r == "^18.3.0"
        );
    }

    #[test]
    fn test_apply_named_catalog_beats_default() {
        let root = tempfile::tempdir().unwrap();
        workspace(
            root.path(),
            "catalog:\n  react: ^18.3.0\ncatalogs:\n  react17:\n    react: ^17.0.2\n",
        );
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:react17")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, Some("^17.0.2".into()));
    }

    #[test]
    fn test_apply_catalog_default_alias_resolves_like_shorthand() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog:\n  react: ^18.3.0\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:default")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, Some("^18.3.0".into()));
    }

    #[test]
    fn test_apply_catalogs_default_section_alone_defines_default() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalogs:\n  default:\n    react: ^18.3.0\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, Some("^18.3.0".into()));
    }

    #[test]
    fn test_apply_missing_entry() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog:\n  react: ^18.3.0\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("left-pad", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, None);
        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::MissingEntry
        );
        assert!(
            deps[0]
                .catalog
                .as_ref()
                .unwrap()
                .diagnostic_message("left-pad")
                .unwrap()
                .contains("left-pad")
        );
    }

    #[test]
    fn test_apply_unknown_catalog() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog:\n  react: ^18.3.0\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:react17")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, None);
        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::UnknownCatalog
        );
    }

    #[test]
    fn test_apply_no_workspace_file_found_anywhere() {
        let root = tempfile::tempdir().unwrap();
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("left-pad", "catalog:missing-entry")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, None);
        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::NoWorkspaceFile
        );
    }

    #[test]
    fn test_apply_no_manifest_dir_is_no_workspace_file() {
        let cache = PnpmWorkspaceCache::new();
        let config = load(None, &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, None);
        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::NoWorkspaceFile
        );
    }

    #[test]
    fn test_apply_workspace_file_with_neither_key_is_missing_entry_not_unknown() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "packages:\n  - packages/*\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::MissingEntry
        );
    }

    #[test]
    fn test_apply_duplicate_default_catalog_is_workspace_wide() {
        let root = tempfile::tempdir().unwrap();
        workspace(
            root.path(),
            "catalog:\n  react: ^18.3.0\ncatalogs:\n  default:\n    react: ^18.3.0\n  react17:\n    react: ^17.0.2\n",
        );
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:"), dep("react", "catalog:react17")];
        apply(&mut deps, config.as_deref());

        for d in &deps {
            assert_eq!(d.version_req, None);
            assert_eq!(
                d.catalog.as_ref().unwrap().outcome,
                CatalogOutcome::DuplicateDefaultCatalog
            );
        }
    }

    #[test]
    fn test_apply_non_mapping_catalog_shape_is_malformed_not_panicking() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog: \"not-a-map\"\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::MalformedWorkspaceFile
        );
    }

    #[test]
    fn test_apply_non_mapping_catalogs_sequence_is_malformed() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalogs:\n  - a\n  - b\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:x")];
        apply(&mut deps, config.as_deref());

        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::MalformedWorkspaceFile
        );
    }

    #[test]
    fn test_apply_null_top_level_catalog_is_absent_not_malformed_and_not_duplicate() {
        let root = tempfile::tempdir().unwrap();
        workspace(
            root.path(),
            "catalog:\ncatalogs:\n  default:\n    react: ^18.3.0\n",
        );
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        // M2: a null top-level `catalog:` is absent, so `catalogs.default` alone defines the
        // default catalog — never `Malformed`, never `DuplicateDefaultCatalog`.
        assert_eq!(deps[0].version_req, Some("^18.3.0".into()));
    }

    #[test]
    fn test_apply_malformed_yaml_is_malformed_workspace_file() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog: [unterminated\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, None);
        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::MalformedWorkspaceFile
        );
    }

    #[test]
    fn test_apply_non_string_entry_value_is_malformed_entry() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog:\n  react:\n    version: \"^18\"\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, None);
        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::MalformedEntry
        );
        let message = deps[0]
            .catalog
            .as_ref()
            .unwrap()
            .diagnostic_message("react")
            .unwrap();
        assert!(message.contains("react"));
        assert!(message.contains("not a version string"));
    }

    #[test]
    fn test_apply_non_semver_entry_is_hover_only_no_diagnostic() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog:\n  left-pad: \"workspace:*\"\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("left-pad", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, None);
        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::NonSemverEntry {
                value: "workspace:*".to_string()
            }
        );
        assert!(
            deps[0]
                .catalog
                .as_ref()
                .unwrap()
                .diagnostic_message("left-pad")
                .is_none()
        );
    }

    #[test]
    fn test_apply_nested_roots_nearest_wins() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog:\n  react: ^17.0.0\n");
        let nested = root.path().join("nested-monorepo");
        std::fs::create_dir(&nested).unwrap();
        workspace(&nested, "catalog:\n  react: ^18.3.0\n");
        let pkg_dir = nested.join("packages").join("app");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(&pkg_dir), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, Some("^18.3.0".into()));
    }

    #[test]
    fn test_apply_literal_range_dependency_is_untouched() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path(), "catalog:\n  react: ^18.3.0\n");
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("express", "^4.18.2")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, Some("^4.18.2".into()));
        assert!(deps[0].catalog.is_none());
    }

    /// M4: a directory named `pnpm-workspace.yaml` exercises the "found but unreadable"
    /// branch deterministically (no race), since `MtimeFileCache::get_or_parse` rejects
    /// anything but a regular file.
    #[test]
    fn test_apply_workspace_path_is_a_directory_degrades_to_malformed() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("pnpm-workspace.yaml")).unwrap();
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(deps[0].version_req, None);
        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::MalformedWorkspaceFile
        );
    }

    #[test]
    fn test_apply_billion_laughs_rejected_by_guards() {
        let root = tempfile::tempdir().unwrap();
        let mut content = String::from("catalog:\n");
        for i in 0..=deps_core::MAX_YAML_NESTING_DEPTH {
            content.push_str(&"  ".repeat(i + 1));
            content.push_str(&format!("l{i}:\n"));
        }
        workspace(root.path(), &content);
        let cache = PnpmWorkspaceCache::new();
        let config = load(Some(root.path()), &cache);

        let mut deps = vec![dep("react", "catalog:")];
        apply(&mut deps, config.as_deref());

        assert_eq!(
            deps[0].catalog.as_ref().unwrap().outcome,
            CatalogOutcome::MalformedWorkspaceFile
        );
    }

    #[test]
    fn test_apply_gate_is_vacuous_with_no_catalog_dependencies() {
        // No `catalog:`-prefixed value anywhere — `apply` must leave every dependency alone
        // even when handed a `None` config.
        let mut deps = vec![dep("express", "^4.18.2"), dep("lodash", "^4.17.21")];
        apply(&mut deps, None);

        assert_eq!(deps[0].version_req, Some("^4.18.2".into()));
        assert_eq!(deps[1].version_req, Some("^4.17.21".into()));
        assert!(deps[0].catalog.is_none());
        assert!(deps[1].catalog.is_none());
    }

    // --- Security audit HIGH finding: Markdown injection in hover_detail/diagnostic_message ---

    fn origin(specifier: &str, catalog: Option<&str>, outcome: CatalogOutcome) -> CatalogOrigin {
        CatalogOrigin {
            specifier: specifier.to_string(),
            catalog: catalog.map(str::to_string),
            outcome,
        }
    }

    /// A1: an entry value breaking out of a code span with a live Markdown link must not
    /// produce an unescaped `](` sequence in the hover text.
    #[test]
    fn test_hover_detail_neutralizes_markdown_link_breakout_in_resolved_range() {
        // A raw `format!("`{s}`")` breaks out of its own code span here: the embedded
        // backtick closes the span early, so `[CLICK-ME](...)` renders as a live Markdown
        // link. `markdown_code_span` must widen the fence to contain the whole payload as
        // literal text — assert the fence is a *balanced*, wider pair around the entire raw
        // value (never merely "the substring is present somewhere"), matching that helper's
        // own documented widening behavior exactly.
        let malicious = "x` [CLICK-ME](https://evil.example/steal) `y";
        let o = origin(
            "catalog:",
            None,
            CatalogOutcome::Resolved(malicious.to_string()),
        );
        let detail = o.hover_detail("react");
        let expected = format!(
            "{} → {}",
            deps_core::lsp_helpers::markdown_code_span("catalog:"),
            deps_core::lsp_helpers::markdown_code_span(malicious)
        );
        assert_eq!(detail, expected);
        assert!(
            detail.contains("``x` [CLICK-ME](https://evil.example/steal) `y``"),
            "expected the whole payload inside one widened, balanced fence: {detail}"
        );
    }

    /// A2: an entry value containing a blank line must not end the paragraph and let
    /// following text render as a real Markdown block (e.g. an auto-loaded image beacon). The
    /// `![](...)` substring legitimately survives *inside* a widened code-span fence (as inert
    /// literal text) — the actual vulnerability is a raw, un-fenced newline splitting the
    /// hover markdown into separate blocks, so assert on newline absence, not substring
    /// absence.
    #[test]
    fn test_hover_detail_neutralizes_paragraph_break_and_image_beacon_in_non_semver_entry() {
        let malicious = "workspace:*\n\n# heading\n![](https://evil.example/beacon.png)";
        let o = origin(
            "catalog:",
            None,
            CatalogOutcome::NonSemverEntry {
                value: malicious.to_string(),
            },
        );
        let detail = o.hover_detail("react");
        assert!(
            !detail.contains('\n'),
            "a raw newline survived outside the code span, able to split the hover into \
             separate Markdown blocks: {detail:?}"
        );
        assert_eq!(
            detail,
            format!(
                "{} → {} (not a version range)",
                deps_core::lsp_helpers::markdown_code_span("catalog:"),
                deps_core::lsp_helpers::markdown_code_span(malicious)
            )
        );
    }

    /// A3/A4: a dependency name or catalog name containing `![](url)` must render as literal
    /// text in hover, not an auto-loaded image — `markdown_code_span`'s A1/A2 protection does
    /// not apply here since these are interpolated between plain quotes, not backticks.
    #[test]
    fn test_hover_detail_escapes_image_syntax_in_dependency_and_catalog_names() {
        let evil_name = "![](https://evil.example/beacon.png)";
        let missing = origin("catalog:x", Some("x"), CatalogOutcome::MissingEntry);
        let detail = missing.hover_detail(evil_name);
        assert!(
            !detail.contains("![]("),
            "dependency name escaped auto-loaded image survived: {detail}"
        );

        let unknown = origin(
            "catalog:evil",
            Some(evil_name),
            CatalogOutcome::UnknownCatalog,
        );
        let detail = unknown.hover_detail("react");
        assert!(
            !detail.contains("![]("),
            "catalog name escaped auto-loaded image survived: {detail}"
        );
    }

    /// The plain-text diagnostic message is a different sink (never rendered as Markdown by
    /// any LSP client) — it must stay readable for the overwhelmingly common case of a scoped
    /// package name, not pay `escape_markdown`'s backslash-per-punctuation cost.
    #[test]
    fn test_diagnostic_message_does_not_escape_scoped_package_names() {
        let o = origin("catalog:", None, CatalogOutcome::MissingEntry);
        let message = o.diagnostic_message("@myorg/pkg").unwrap();
        assert!(
            message.contains("@myorg/pkg"),
            "expected the scoped name unescaped in a plain-text diagnostic: {message}"
        );
    }

    /// Security audit LOW finding: an unbounded catalog entry value must not render in full.
    #[test]
    fn test_hover_detail_truncates_oversized_untrusted_values() {
        let huge = "x".repeat(2_000_000);
        let o = origin("catalog:", None, CatalogOutcome::Resolved(huge));
        let detail = o.hover_detail("react");
        assert!(
            detail.len() < 1_000,
            "hover detail was not truncated: {} bytes",
            detail.len()
        );
    }

    #[test]
    fn test_diagnostic_message_truncates_oversized_dependency_name() {
        let huge_name = "x".repeat(2_000_000);
        let o = origin("catalog:", None, CatalogOutcome::MissingEntry);
        let message = o.diagnostic_message(&huge_name).unwrap();
        assert!(
            message.len() < 1_000,
            "diagnostic message was not truncated: {} bytes",
            message.len()
        );
    }
}
