//! pom.xml parser with byte-accurate position tracking.
//!
//! Uses quick-xml SAX reader to parse Maven POM files.
//! Tracks byte positions for LSP range computation.
//!
//! No element-count/scan-position bound is applied here (#698): the input is a local
//! manifest already capped by `deps-lsp`'s `MAX_FILE_SIZE` (10 MB) read path, unlike
//! `deps-maven::registry::parse_metadata_xml`'s remote, unbounded-by-default input.
//!
//! The `<repositories>` `file://` probe (#1503) is the one exception: unlike the rest of
//! this module, it performs real filesystem I/O (`fs_probe::metadata`), so it carries its own
//! separate bound (`MAX_TOTAL_PROBE_ATTEMPTS`) independent of the string-parsing cost
//! the rest of this module's lack of a scan-position bound accepts.

use crate::types::{MavenDependency, MavenScope};
use deps_core::interpolation::{MAX_INTERPOLATED_VALUE_BYTES, PropertyValue};
use deps_core::lsp_helpers::{LineOffsetTable, byte_span_to_range};
use deps_core::position::Range;
use deps_core::{DepsError, Result};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::HashMap;
use url::Url;

/// Result of parsing a `pom.xml` file.
#[non_exhaustive]
#[derive(Debug)]
pub struct MavenParseResult {
    /// Dependencies found across `<dependencies>` and `<dependencyManagement>`.
    pub dependencies: Vec<MavenDependency>,
    /// The `<properties>` section, for resolving `${...}` version placeholders.
    pub properties: HashMap<String, PropertyValue>,
    /// URI of the manifest this result was parsed from.
    pub uri: Url,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

/// Context stack element for SAX parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseContext {
    Root,
    Dependencies,
    DependencyManagement,
    Plugins,
    Dependency,
    Plugin,
    Properties,
    Repositories,
    Repository,
}

/// Accumulator for a single dependency being parsed.
#[derive(Default)]
struct DepAccum {
    group_id: Option<String>,
    artifact_id: Option<String>,
    artifact_id_start: u64,
    artifact_id_end: u64,
    version: Option<String>,
    version_start: u64,
    version_end: u64,
    /// Byte offset right after `<version>`'s opening tag, captured unconditionally on
    /// `Start` (independent of whether a `Text` event ever follows) — quick-xml's reader
    /// (`trim_text(true)`) emits no `Text` event at all for an empty or whitespace-only
    /// `<version></version>`, so this is the only position captured for that shape (#1161).
    version_open_pos: Option<u64>,
    /// Buffer position captured before reading the `End` event for `</version>`, set only
    /// when no `Text` event set `version` — see `version_open_pos`.
    version_close_pos: Option<u64>,
    scope: Option<String>,
    /// `<systemPath>` text, present only for a `scope: system` dependency (#1202, Maven fix)
    /// — the explicit, already-per-dependency local-jar binding `MavenScope::System` names.
    system_path: Option<String>,
}

/// Upper bound on how many distinct `file://` repository directories a single `pom.xml` can
/// make [`parse_pom_xml`] probe (#1503) — bounds the filesystem I/O one manifest parse can
/// trigger, independent of how many `<repository>` entries it declares.
const MAX_FILE_REPO_DIRS: usize = 8;

/// Upper bound on the total number of `fs_probe::metadata` calls a single `pom.xml` parse can
/// make across every dependency × repository combination (#1503) — without this, a manifest
/// with `MAX_FILE_REPO_DIRS` repositories and `MAX_DEPENDENCIES_PER_DOCUMENT`
/// dependencies could trigger up to 8 × 5000 = 40,000 blocking `stat` calls in one parse,
/// synchronously inside the async `parse_manifest` future, on every edit (CWE-400). Once
/// exhausted, probing stops entirely for the rest of the document — every dependency not yet
/// probed keeps its current classification, a best-effort cap rather than a guarantee that
/// declaration order doesn't matter.
const MAX_TOTAL_PROBE_ATTEMPTS: usize = 256;

/// True if `segment` is exactly one plain path component ([`std::path::Component::Normal`]) —
/// structurally rejects an empty string, `.`, `..`, a leading/embedded path separator, and a
/// Windows drive-letter/UNC-prefix shape (`C:`) all at once, rather than an ad-hoc character
/// blocklist. A blocklist missed that `group_id.replace('.', MAIN_SEPARATOR_STR)` turns a
/// `.`-prefixed segment like `.etc` into an absolute-looking `/etc` path component, which
/// [`std::path::Path::join`] then treats as *replacing* the whole base path outright rather
/// than joining onto it (#1503 M1) — checking `Component` structure instead catches every
/// path-escape shape a filesystem actually recognizes, on any platform, not just the ones an
/// character list happened to enumerate.
fn is_plain_path_component(segment: &str) -> bool {
    let mut components = std::path::Path::new(segment).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

/// True if every `.`-delimited segment of `group_id` (each becomes its own directory level via
/// `group_id.replace('.', MAIN_SEPARATOR_STR)`), plus `artifact_id` and `version` verbatim, is
/// a single plain path component — see [`is_plain_path_component`]. `group_id`/`artifact_id`/
/// the version text are attacker-controlled `pom.xml` content (#1503).
fn is_safe_maven_coordinate(group_id: &str, artifact_id: &str, version: &str) -> bool {
    !group_id.is_empty()
        && group_id.split('.').all(is_plain_path_component)
        && is_plain_path_component(artifact_id)
        && is_plain_path_component(version)
}

/// True if `version` uses Maven version-range syntax (`[1.0,2.0)`, `(,1.0]`, …), which has no
/// single corresponding directory to probe (#1503).
fn is_version_range_syntax(version: &str) -> bool {
    version.contains(['[', ']', '(', ')', ','])
}

/// A dependency finalized during parsing, paired with whether it came from `<plugins>` rather
/// than `<dependencies>`/`<dependencyManagement>` (#1503) — kept together (rather than as two
/// index-correlated `Vec`s) so the file:// probing loop below can never desync which flag
/// belongs to which dependency. A `<plugin>` resolves via the separate `<pluginRepositories>`
/// config, so it must never be reclassified by a `<repositories>` file:// match.
struct AccumulatedDep {
    dep: MavenDependency,
    is_plugin: bool,
}

/// Parses a `pom.xml` document into a [`MavenParseResult`].
///
/// # Errors
///
/// Returns an error if the content is not well-formed XML.
pub fn parse_pom_xml(content: &str, doc_uri: &Url) -> Result<MavenParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut dependencies: Vec<AccumulatedDep> = Vec::new();
    let mut properties = HashMap::new();

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut context_stack: Vec<ParseContext> = vec![ParseContext::Root];
    let mut current_dep: Option<DepAccum> = None;
    let mut current_tag: Option<String> = None;
    let mut current_prop_key: Option<String> = None;
    let mut root_tag: Option<String> = None;
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);
    // Raw `<repository><url>` text, resolved and scheme-checked only after the full parse
    // (#1503): properties referenced by a repository URL may be declared anywhere in the
    // document relative to the `<repositories>` block.
    let mut repository_urls: Vec<String> = Vec::new();

    loop {
        let pos = reader.buffer_position();
        let event = reader
            .read_event()
            .map_err(|e| DepsError::parse_error("pom.xml", &e))?;

        match event {
            Event::Start(ref e) => {
                let tag = e.local_name().as_ref().to_string();
                let ctx = context_stack.last().cloned().unwrap_or(ParseContext::Root);

                match (ctx, tag.as_str()) {
                    (ParseContext::Root, "dependencies") => {
                        context_stack.push(ParseContext::Dependencies);
                    }
                    (ParseContext::Root, "dependencyManagement") => {
                        context_stack.push(ParseContext::DependencyManagement);
                    }
                    (ParseContext::DependencyManagement, "dependencies") => {
                        context_stack.push(ParseContext::Dependencies);
                    }
                    (ParseContext::Root, "plugins") => {
                        // Matches both top-level <plugins> and <build><plugins>:
                        // <build> is silently ignored (falls through `_ => {}`), so
                        // when <plugins> is encountered inside <build> the stack is
                        // still at Root — this is intentional for MVP simplicity.
                        context_stack.push(ParseContext::Plugins);
                    }
                    (ParseContext::Dependencies, "dependency") => {
                        context_stack.push(ParseContext::Dependency);
                        current_dep = Some(DepAccum::default());
                        current_tag = None;
                    }
                    (ParseContext::Plugins, "plugin") => {
                        context_stack.push(ParseContext::Plugin);
                        current_dep = Some(DepAccum::default());
                        current_tag = None;
                    }
                    (ParseContext::Root, "properties") => {
                        context_stack.push(ParseContext::Properties);
                    }
                    (ParseContext::Properties, key) => {
                        current_prop_key = Some(key.to_string());
                    }
                    (ParseContext::Root, "repositories") => {
                        context_stack.push(ParseContext::Repositories);
                    }
                    (ParseContext::Repositories, "repository") => {
                        context_stack.push(ParseContext::Repository);
                        current_tag = None;
                    }
                    (ParseContext::Repository, field) => {
                        current_tag = Some(field.to_string());
                    }
                    (ParseContext::Dependency | ParseContext::Plugin, field) => {
                        current_tag = Some(field.to_string());
                        if field == "version"
                            && let Some(dep) = current_dep.as_mut()
                        {
                            dep.version_open_pos = Some(reader.buffer_position());
                        }
                    }
                    (ParseContext::Root, tag @ ("version" | "groupId" | "artifactId")) => {
                        root_tag = Some(tag.to_string());
                    }
                    _ => {}
                }
                let _ = pos;
            }
            Event::Text(ref e) => {
                let text_start = pos;
                let text = {
                    let s = e.trim().to_string();
                    quick_xml::escape::unescape(&s)
                        .map(|c| c.into_owned())
                        .unwrap_or(s)
                };
                let text_end = reader.buffer_position();

                let ctx = context_stack.last().cloned().unwrap_or(ParseContext::Root);

                if matches!(ctx, ParseContext::Dependency | ParseContext::Plugin) {
                    if let (Some(ref tag), Some(ref mut dep)) =
                        (current_tag.clone(), current_dep.as_mut())
                    {
                        match tag.as_str() {
                            "groupId" => {
                                dep.group_id = Some(text.clone());
                            }
                            "artifactId" => {
                                dep.artifact_id = Some(text.clone());
                                dep.artifact_id_start = text_start;
                                dep.artifact_id_end = text_end;
                            }
                            "version" => {
                                dep.version = Some(text.clone());
                                dep.version_start = text_start;
                                dep.version_end = text_end;
                            }
                            "scope" => {
                                dep.scope = Some(text.clone());
                            }
                            "systemPath" => {
                                dep.system_path = Some(text.clone());
                            }
                            _ => {}
                        }
                    }
                } else if ctx == ParseContext::Properties
                    && let Some(key) = current_prop_key.take()
                {
                    deps_core::interpolation::insert_bounded(
                        &mut properties,
                        key,
                        text,
                        "maven property",
                    );
                } else if ctx == ParseContext::Repository && current_tag.as_deref() == Some("url") {
                    repository_urls.push(text.clone());
                } else if ctx == ParseContext::Root
                    && let Some(tag) = root_tag.take()
                {
                    let prop_key = format!("project.{tag}");
                    deps_core::interpolation::insert_bounded(
                        &mut properties,
                        prop_key,
                        text,
                        "maven property",
                    );
                }
            }
            Event::Empty(ref e) => {
                // A self-closing `<version/>` never fires `Start`+`End` — quick-xml emits a
                // single `Empty` event for it instead — so without this arm it fell through
                // the wildcard `_ => {}` below and `version_open_pos`/`version_close_pos`
                // were never captured, reproducing #1161's original symptom verbatim for
                // this manifest shape (S1 critic/tester follow-up). There is no separate
                // open/close position for a self-closing tag, so both are set to the same
                // "right after this tag" offset, matching `<version></version>`'s and
                // `<version>   </version>`'s treatment as "an empty, present version" rather
                // than "no version tag at all".
                let tag = e.local_name().as_ref().to_string();
                let ctx = context_stack.last().cloned().unwrap_or(ParseContext::Root);
                if tag == "version"
                    && matches!(ctx, ParseContext::Dependency | ParseContext::Plugin)
                    && let Some(dep) = current_dep.as_mut()
                {
                    let p = reader.buffer_position();
                    dep.version_open_pos = Some(p);
                    dep.version_close_pos = Some(p);
                }
            }
            Event::End(ref e) => {
                let tag = e.local_name().as_ref().to_string();
                let ctx = context_stack.last().cloned().unwrap_or(ParseContext::Root);

                match (ctx, tag.as_str()) {
                    (ParseContext::Dependency, "dependency") | (ParseContext::Plugin, "plugin") => {
                        let this_is_plugin = tag == "plugin";
                        context_stack.pop();
                        if let Some(dep) = current_dep.take()
                            && let Some(maven_dep) =
                                finalize_dep(dep, content, &line_table, &properties)
                            && budget.allow()
                        {
                            dependencies.push(AccumulatedDep {
                                dep: maven_dep,
                                is_plugin: this_is_plugin,
                            });
                        }
                        current_tag = None;
                    }
                    (ParseContext::Dependencies, "dependencies")
                    | (ParseContext::DependencyManagement, "dependencyManagement")
                    | (ParseContext::Plugins, "plugins")
                    | (ParseContext::Properties, "properties")
                    | (ParseContext::Repositories, "repositories") => {
                        context_stack.pop();
                    }
                    (ParseContext::Repository, "repository") => {
                        context_stack.pop();
                        current_tag = None;
                    }
                    (ParseContext::Repository, _) => {
                        current_tag = None;
                    }
                    (ParseContext::Dependency | ParseContext::Plugin, "version") => {
                        if let Some(dep) = current_dep.as_mut()
                            && dep.version.is_none()
                        {
                            dep.version_close_pos = Some(pos);
                        }
                        current_tag = None;
                    }
                    (ParseContext::Dependency | ParseContext::Plugin, _) => {
                        current_tag = None;
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    // #1503: Maven's `<repository>` element has no per-package binding to exploit
    // heuristically — every declared repository is tried, in order, for any dependency — so
    // rather than a coarse "any file:// repository present -> every dependency is Path"
    // rule (which would also silence OSV/outdated diagnostics for implicit Maven Central
    // dependencies that have nothing to do with the local repo — a P3 bug's fix must not
    // regress into a missed-CVE risk), this probes the standard Maven repository layout
    // (`<group-path>/<artifact>/<version>/<artifact>-<version>.jar`) under each declared
    // `file://` repository directory and only classifies a dependency as `Path` when its jar
    // is actually found there.
    //
    // Gated on `doc_uri` itself resolving to a real local file (#1090's existing "only touch
    // the local filesystem when the manifest is a genuine local file" rule) — skipped
    // entirely for a non-local `doc_uri` (`untitled:`, `https:`, an in-memory buffer, …).
    if let Some(manifest_path) = deps_core::lockfile::resolve_manifest_file_path(doc_uri) {
        // `${project.basedir}` (Maven's own name for the pom.xml's containing directory) is
        // the idiomatic way to declare a repository relative to the project, so it is resolved
        // here as a local overlay over the parsed `<properties>` — never overriding a pom that
        // already defines its own `project.basedir` (#1503 S2). The value is the URL-path
        // form (`Url::from_file_path`'s `.path()`: forward-slash-separated, percent-encoded,
        // e.g. `/C:/Users/...` on Windows) rather than `Path::display()`'s native separators —
        // this text is about to be substituted back into a `file://` URL string
        // (`file://${project.basedir}/repo`), where a Windows-native `C:\Users\...` would not
        // parse as a valid URL.
        let basedir_overlay: Option<HashMap<String, PropertyValue>> =
            if properties.contains_key("project.basedir") {
                None
            } else {
                manifest_path.parent().and_then(|basedir| {
                    let basedir_url = Url::from_file_path(basedir).ok()?;
                    PropertyValue::new(basedir_url.path().to_string())
                        .ok()
                        .map(|value| {
                            let mut overlay = properties.clone();
                            overlay.insert("project.basedir".to_string(), value);
                            overlay
                        })
                })
            };
        let repo_properties = basedir_overlay.as_ref().unwrap_or(&properties);

        // Each candidate repository URL is resolved the same way `resolve_manifest_file_path`
        // resolves `doc_uri` above (host check + `to_file_path`), not just a bare `file://`
        // scheme check — a `file://attacker.example/share` URL keeps its host, and
        // `to_file_path()` alone would hand back a Windows UNC path; any subsequent filesystem
        // access against it makes Windows silently attempt SMB/NTLM auth against that host
        // (#1503 C1). Reused from `deps_core::lockfile` (#1090) rather than re-deriving the
        // same host check locally.
        let mut file_repositories: Vec<std::path::PathBuf> = Vec::new();
        for raw in &repository_urls {
            let resolved = resolve_properties(raw, repo_properties);
            let Ok(url) = Url::parse(resolved.trim()) else {
                continue;
            };
            let Some(dir) = deps_core::lockfile::resolve_manifest_file_path(&url) else {
                continue;
            };
            if file_repositories.contains(&dir) {
                continue;
            }
            file_repositories.push(dir);
            if file_repositories.len() >= MAX_FILE_REPO_DIRS {
                break;
            }
        }

        if !file_repositories.is_empty() {
            // Sync `fs_probe` calls here are bounded (`MAX_TOTAL_PROBE_ATTEMPTS`) and
            // follow the same inline pattern as deps-npm's `config_ancestors` walk
            // (`catalog.rs`) — no `spawn_blocking` needed for this class of bounded fs_probe
            // call.
            //
            // Only the default `jar` packaging layout is probed — a `<type>` other than the
            // implicit default, a timestamped SNAPSHOT filename, or a classifier are out of
            // scope for this probe.
            let mut probes_remaining = MAX_TOTAL_PROBE_ATTEMPTS;
            'dependencies: for accum in &mut dependencies {
                if accum.is_plugin
                    || accum.dep.source != deps_core::parser::DependencySource::Registry
                {
                    continue;
                }
                let Some(version) = accum
                    .dep
                    .version_req
                    .as_ref()
                    .map(|v| v.as_ref().to_string())
                else {
                    continue;
                };
                let group_id = accum.dep.group_id.as_str();
                let artifact_id = accum.dep.artifact_id.as_str();
                if !is_safe_maven_coordinate(group_id, artifact_id, &version)
                    || is_version_range_syntax(&version)
                {
                    continue;
                }
                let group_path = group_id.replace('.', std::path::MAIN_SEPARATOR_STR);
                for repo_dir in &file_repositories {
                    let candidate = repo_dir
                        .join(&group_path)
                        .join(artifact_id)
                        .join(&version)
                        .join(format!("{artifact_id}-{version}.jar"));
                    // Belt-and-suspenders on top of `is_safe_maven_coordinate` (#1503 M1):
                    // if the joined path ever ends up outside `repo_dir` despite the segment
                    // checks above, treat it as unresolvable rather than probe it.
                    if !candidate.starts_with(repo_dir) {
                        continue;
                    }
                    if probes_remaining == 0 {
                        break 'dependencies;
                    }
                    probes_remaining -= 1;
                    if deps_core::fs_probe::metadata(&candidate).is_ok() {
                        accum.dep.source = deps_core::parser::DependencySource::Path {
                            path: candidate.display().to_string(),
                        };
                        break;
                    }
                }
            }
        }
    }

    Ok(MavenParseResult {
        dependencies: dependencies.into_iter().map(|accum| accum.dep).collect(),
        properties,
        uri: doc_uri.clone(),
        dependency_truncation: budget.truncation(),
    })
}

fn finalize_dep(
    dep: DepAccum,
    content: &str,
    line_table: &LineOffsetTable,
    properties: &HashMap<String, PropertyValue>,
) -> Option<MavenDependency> {
    let group_id = dep.group_id?;
    let artifact_id = dep.artifact_id?;
    let name = format!("{group_id}:{artifact_id}");

    // name_range covers the artifactId text (primary hover/action target)
    let name_range = text_range(
        content,
        line_table,
        dep.artifact_id_start as usize,
        dep.artifact_id_end as usize,
        &artifact_id,
    );

    let version_range = if let Some(v) = dep.version.as_ref() {
        Some(text_range(
            content,
            line_table,
            dep.version_start as usize,
            dep.version_end as usize,
            v,
        ))
    } else if let (Some(open), Some(close)) = (dep.version_open_pos, dep.version_close_pos) {
        // `<version></version>` (or whitespace-only content quick-xml elides entirely under
        // `trim_text(true)`) — `text_range` bails out on empty text since it has nothing to
        // search for, so build the (possibly zero-width) span directly from the tag's own
        // boundaries instead (#1161). `version_req` below deliberately stays `None`: there is
        // still no literal text to report as a requirement, only a trackable position.
        let start = content.floor_char_boundary(open as usize);
        let end = content.floor_char_boundary((close as usize).max(open as usize));
        Some(byte_span_to_range(content, line_table, start, end))
    } else {
        None
    };

    let scope = dep
        .scope
        .as_deref()
        .unwrap_or("compile")
        .parse::<MavenScope>()
        .unwrap_or_default();

    // #1202 (critic Maven fix): `scope: system` is an explicit, per-dependency local-jar
    // binding via `<systemPath>` — a real per-dependency field this parser reads, so
    // classifying it needs no heuristic at all (contrast with the `<repositories>` file://
    // probe in `parse_pom_xml`, #1503, which runs after this and only overrides a dependency
    // still left as `Registry`, never one already `Path` here). Falls back to `Registry` only
    // if a malformed manifest declares `scope: system` with no `systemPath` at all (never
    // crashes on it, but there is nothing to classify against either).
    let source = if scope == MavenScope::System {
        dep.system_path
            .as_deref()
            .map(|path| deps_core::parser::DependencySource::Path {
                path: resolve_properties(path, properties),
            })
            .unwrap_or(deps_core::parser::DependencySource::Registry)
    } else {
        deps_core::parser::DependencySource::Registry
    };

    let version_req = dep.version.map(|v| resolve_properties(&v, properties));

    Some(MavenDependency {
        group_id,
        artifact_id,
        name: name.into(),
        name_range,
        version_req: version_req.map(Into::into),
        version_range,
        scope,
        source,
    })
}

/// Resolves `${property}` references in a string using the properties map.
///
/// Handles `${project.version}` and similar Maven property expressions.
/// Unresolved properties are left as-is. The cap (#1481, [`MAX_INTERPOLATED_VALUE_BYTES`])
/// applies to the whole resolved string, not just a single substituted value, so a
/// legitimately long `systemPath` expansion (paths can run up to `PATH_MAX`, e.g. 4096 on
/// Linux) can stay unresolved rather than being truncated — accepted as low-likelihood in
/// practice.
// All indices come from `find("${")`/`find('}')`, both ASCII tokens, so every slice bound
// is always a char boundary.
#[allow(clippy::string_slice)]
fn resolve_properties(input: &str, properties: &HashMap<String, PropertyValue>) -> String {
    let mut result = input.to_string();
    // Capped at 5 to bound rare nested property references.
    for _ in 0..5 {
        let Some(start) = result.find("${") else {
            break;
        };
        let Some(end) = result[start..].find('}') else {
            break;
        };
        let key = &result[start + 2..start + end];
        let Some(value) = properties.get(key) else {
            break;
        };
        // Self-referential properties (e.g. `<p>${p}AAAA</p>`) can grow the result by up to
        // one bounded value per round across all 5 rounds (#1481) — stop before this round's
        // substitution once the predicted length would exceed the cap, leaving this
        // placeholder unresolved. `break` (not discarding `result`) keeps this consistent
        // with the missing-property fallback above: earlier rounds' successful, unrelated
        // substitutions are preserved rather than reverted to the pristine input (review
        // follow-up).
        let predicted_len = result.len() - (end + 1) + value.len();
        if predicted_len > MAX_INTERPOLATED_VALUE_BYTES {
            break;
        }
        result = format!(
            "{}{}{}",
            &result[..start],
            value.as_str(),
            &result[start + end + 1..]
        );
    }
    result
}

/// Finds the LSP range of `text` within content, searching near `hint_start`.
///
/// Limitation: uses `str::find` which returns the first occurrence at or after
/// `hint_start`. For pom.xml files with duplicate artifactId values across
/// different groupIds, the range may point to an earlier occurrence if the
/// byte hint is imprecise. This is acceptable for MVP single-version-tag use.
// `search_from` is floor_char_boundary-clamped just below before slicing `content`.
#[allow(clippy::string_slice)]
fn text_range(
    content: &str,
    line_table: &LineOffsetTable,
    hint_start: usize,
    _hint_end: usize,
    text: &str,
) -> Range {
    if text.is_empty() {
        return Range::default();
    }
    // `hint_start` is a quick-xml buffer offset; `floor_char_boundary` clamps it to both
    // `content.len()` (if past the end) and the nearest char boundary, since it is not
    // guaranteed to land on either (#680).
    let search_from = content.floor_char_boundary(hint_start);
    if let Some(rel) = content[search_from..].find(text) {
        let abs_start = search_from + rel;
        let abs_end = abs_start + text.len();
        byte_span_to_range(content, line_table, abs_start, abs_end)
    } else {
        Range::default()
    }
}

deps_core::impl_parse_result!(
    MavenParseResult,
    MavenDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;
    use std::fmt::Write as _;

    fn test_uri() -> Url {
        deps_core::test_util::test_uri("/test/pom.xml")
    }

    #[test]
    fn test_parse_simple_pom() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
  </dependencies>
</project>"#;

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.group_id, "org.apache.commons");
        assert_eq!(dep.artifact_id, "commons-lang3");
        assert_eq!(dep.name, "org.apache.commons:commons-lang3");
        assert_eq!(dep.version_req, Some("3.14.0".into()));
        assert_matches!(dep.scope, MavenScope::Compile);
    }

    #[test]
    fn test_parse_multiple_deps() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "com.google.guava:guava");
        assert_eq!(result.dependencies[1].name, "junit:junit");
        assert_matches!(result.dependencies[1].scope, MavenScope::Test);
    }

    /// #1202 (critic Maven fix): a `scope: system` dependency's `<systemPath>` classifies as
    /// `Path` — never sent to repo1.maven.org/OSV, and its hover link is suppressed.
    #[test]
    fn test_system_scope_dependency_classifies_as_path() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-jar</artifactId>
      <version>1.0.0</version>
      <scope>system</scope>
      <systemPath>/opt/lib/internal-jar-1.0.0.jar</systemPath>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(result.dependencies[0].scope, MavenScope::System);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path {
                path: "/opt/lib/internal-jar-1.0.0.jar".into(),
            }
        );
    }

    /// A regular (non-`system`) dependency keeps resolving through the registry, even when
    /// other dependencies in the same manifest are `system`-scoped.
    #[test]
    fn test_non_system_scope_stays_registry_alongside_system_scope() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-jar</artifactId>
      <version>1.0.0</version>
      <scope>system</scope>
      <systemPath>/opt/lib/internal-jar-1.0.0.jar</systemPath>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        let system = result
            .dependencies
            .iter()
            .find(|d| d.artifact_id == "internal-jar")
            .unwrap();
        let guava = result
            .dependencies
            .iter()
            .find(|d| d.artifact_id == "guava")
            .unwrap();
        assert_eq!(
            system.source,
            deps_core::parser::DependencySource::Path {
                path: "/opt/lib/internal-jar-1.0.0.jar".into(),
            }
        );
        assert_eq!(guava.source, deps_core::parser::DependencySource::Registry);
    }

    /// Creates `<repo_root>/<group-path>/<artifact_id>/<version>/<artifact_id>-<version>.jar`
    /// (an empty file — only its existence is probed), for #1503's per-package probe tests.
    fn write_fake_jar(
        repo_root: &std::path::Path,
        group_id: &str,
        artifact_id: &str,
        version: &str,
    ) {
        let group_path = group_id.replace('.', std::path::MAIN_SEPARATOR_STR);
        let dir = repo_root.join(group_path).join(artifact_id).join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{artifact_id}-{version}.jar")), b"").unwrap();
    }

    /// #1503: a dependency whose jar is actually present at the standard Maven layout path
    /// under a declared `file://` repository classifies as `Path`.
    #[test]
    fn test_file_repository_probe_classifies_present_jar_as_path() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        write_fake_jar(tmp.path(), "com.acme", "internal-lib", "1.0.0");
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path { .. }
        );
    }

    /// #1503 S1 regression: a dependency declared alongside a `file://` repository, but whose
    /// jar does NOT exist under it (e.g. a Central-resolvable package with no local presence),
    /// must stay `Registry` — the coarse "any file:// repo present" rule this replaces would
    /// have wrongly silenced OSV/outdated diagnostics for it.
    #[test]
    fn test_file_repository_probe_leaves_unresolved_jar_as_registry() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
    }

    /// #1503 S2 regression: a `<plugin>` entry is never reclassified by the `file://` probe,
    /// even when a matching jar happens to exist at its derived path — plugins resolve via
    /// the separate `<pluginRepositories>` config, not `<repositories>`.
    #[test]
    fn test_file_repository_probe_never_reclassifies_plugin_entries() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        write_fake_jar(
            tmp.path(),
            "org.apache.maven.plugins",
            "maven-compiler-plugin",
            "3.11.0",
        );
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
      </plugin>
    </plugins>
  </build>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
    }

    /// #1503 security regression: `groupId`/`artifactId`/version text is attacker-controlled
    /// `pom.xml` content used to build a filesystem path — a path-traversal-shaped `groupId`
    /// must be rejected (left `Registry`) before it ever reaches `Path::join`, never panic.
    #[test]
    fn test_file_repository_probe_rejects_path_traversal_group_id() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>../../etc</groupId>
      <artifactId>passwd</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
    }

    /// #1503 security regression (same as the `groupId` variant, exercised via `artifactId`).
    #[test]
    fn test_file_repository_probe_rejects_path_traversal_artifact_id() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>../../etc/passwd</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
    }

    /// #1503 security regression (same as the `groupId` variant, exercised via the version
    /// text).
    #[test]
    fn test_file_repository_probe_rejects_path_traversal_version() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>../../../../etc/passwd</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
    }

    /// #1503 M1 regression: `group_id = "com..etc"` (or, without any `..` substring at all,
    /// `group_id = ".etc"`) passes a `..`/slash-only character blocklist since neither
    /// individual character appears, but after `group_id.replace('.', MAIN_SEPARATOR_STR)` a
    /// leading-dot segment becomes an absolute-looking path component that `Path::join` would
    /// treat as replacing the whole base directory outright, escaping the repo entirely. The
    /// structural per-segment `Component::Normal` check must reject this even though no
    /// individual disallowed character is present.
    #[test]
    fn test_file_repository_probe_rejects_dot_prefixed_group_id_segment() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        // If the bypass were still present, this would resolve to `/etc/passwd/1.0.0/...`
        // on the real filesystem — assert it does NOT touch the filesystem at all.
        let before = deps_core::fs_probe::snapshot();
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>.etc</groupId>
      <artifactId>passwd</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        let after = deps_core::fs_probe::snapshot();

        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
        assert_eq!(
            before, after,
            "a dot-prefixed group_id segment must never reach fs_probe::metadata"
        );
    }

    /// #1503: more than `MAX_FILE_REPO_DIRS` (8) distinct `file://` repositories
    /// silently stop being added past the cap — the 9th+ are never probed, and parsing never
    /// panics.
    #[test]
    fn test_file_repository_probe_caps_at_max_repositories_probed() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        // The dependency's jar only exists under the 9th repository directory — if the cap is
        // enforced correctly, this repository is never added to the probe list, so the
        // dependency stays `Registry`.
        let dirs: Vec<_> = (0..9).map(|_| tempfile::TempDir::new().unwrap()).collect();
        write_fake_jar(dirs[8].path(), "com.acme", "internal-lib", "1.0.0");

        let mut repositories = String::new();
        for (i, dir) in dirs.iter().enumerate() {
            let url = Url::from_file_path(dir.path()).unwrap();
            writeln!(
                repositories,
                "<repository><id>repo-{i}</id><url>{url}</url></repository>"
            )
            .unwrap();
        }

        let xml = format!(
            r"<project>
  <repositories>
    {repositories}
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry,
            "the 9th repository (the only one with a matching jar) must never be probed \
             once MAX_FILE_REPO_DIRS is reached"
        );
    }

    /// #1503 M7: once `MAX_TOTAL_PROBE_ATTEMPTS` (256) probe calls have been spent on
    /// earlier dependencies with no matching jar, a later dependency's genuinely-present jar
    /// is never probed and stays `Registry` — an accepted best-effort-cap limitation (the
    /// budget does not guarantee declaration order doesn't matter), not a bug.
    #[test]
    fn test_file_repository_probe_stops_after_total_budget_exhausted() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        write_fake_jar(tmp.path(), "com.acme", "internal-lib", "1.0.0");
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let mut fillers = String::new();
        for i in 0..MAX_TOTAL_PROBE_ATTEMPTS {
            writeln!(
                fillers,
                "<dependency><groupId>com.filler</groupId><artifactId>dep-{i}</artifactId>\
                 <version>1.0.0</version></dependency>"
            )
            .unwrap();
        }

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    {fillers}
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), MAX_TOTAL_PROBE_ATTEMPTS + 1);
        let internal_lib = result
            .dependencies
            .iter()
            .find(|d| d.artifact_id == "internal-lib")
            .unwrap();
        assert_eq!(
            internal_lib.source,
            deps_core::parser::DependencySource::Registry,
            "a dependency declared after the total probe budget is exhausted must stay \
             Registry, even though its jar genuinely exists in the repo"
        );
    }

    /// #1503 M7: a non-local `doc_uri` (`untitled:`, `https:`, an in-memory buffer, …) skips
    /// the whole file:// probing block outright — never touches `fs_probe` at all, verified
    /// via a zero stat-count diff, and every dependency keeps its non-probed classification.
    #[test]
    fn test_file_repository_probe_skips_entirely_for_non_local_doc_uri() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let before = deps_core::fs_probe::snapshot();

        let tmp = tempfile::TempDir::new().unwrap();
        write_fake_jar(tmp.path(), "com.acme", "internal-lib", "1.0.0");
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"
        );

        let non_local_uri: Url = "untitled:/test/pom.xml".parse().unwrap();
        let result = parse_pom_xml(&xml, &non_local_uri).unwrap();
        let after = deps_core::fs_probe::snapshot();

        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
        assert_eq!(
            before, after,
            "a non-local doc_uri must skip the whole file:// probing block, never touching \
             fs_probe"
        );
    }

    /// #1503: a version-range requirement (`[1.0,2.0)`) has no single corresponding directory
    /// to probe, so it is skipped (left `Registry`) rather than probed against a literal,
    /// bracket-containing path segment.
    #[test]
    fn test_file_repository_probe_skips_version_range_syntax() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>ranged-lib</artifactId>
      <version>[1.0,2.0)</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
    }

    /// #1503: multiple declared `file://` repositories are probed in declaration order; a
    /// match in a later repository still classifies the dependency as `Path`.
    #[test]
    fn test_file_repository_probe_checks_all_repositories_in_order() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp_empty = tempfile::TempDir::new().unwrap();
        let tmp_hit = tempfile::TempDir::new().unwrap();
        write_fake_jar(tmp_hit.path(), "com.acme", "internal-lib", "1.0.0");

        let repo_url_empty = Url::from_file_path(tmp_empty.path()).unwrap();
        let repo_url_hit = Url::from_file_path(tmp_hit.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>empty-repo</id>
      <url>{repo_url_empty}</url>
    </repository>
    <repository>
      <id>hit-repo</id>
      <url>{repo_url_hit}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path { .. }
        );
    }

    /// #1503: a `scope: system` dependency's `<systemPath>` classification is untouched by the
    /// `file://` probe even when a `file://` repository is also declared in the same
    /// `pom.xml` — the probe only ever overrides a dependency still classified `Registry`.
    #[test]
    fn test_file_repository_probe_does_not_clobber_system_path_classification() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-jar</artifactId>
      <version>1.0.0</version>
      <scope>system</scope>
      <systemPath>/opt/lib/internal-jar-1.0.0.jar</systemPath>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path {
                path: "/opt/lib/internal-jar-1.0.0.jar".into(),
            }
        );
    }

    /// #1503: a `${property}`-resolved repository URL (e.g. `file://${local.repo.path}`)
    /// still probes correctly once resolved.
    #[test]
    fn test_file_repository_probe_resolves_property_in_url() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        write_fake_jar(tmp.path(), "com.acme", "internal-lib", "1.0.0");
        let repo_url = Url::from_file_path(tmp.path()).unwrap();
        let repo_url_suffix = repo_url
            .as_str()
            .strip_prefix("file://")
            .expect("from_file_path always produces a file:// URL");

        let xml = format!(
            r"<project>
  <properties>
    <local.repo.path>{repo_url_suffix}</local.repo.path>
  </properties>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>file://${{local.repo.path}}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path { .. }
        );
    }

    /// #1503 C1 (critical security regression): a `file://` repository URL that carries a
    /// host (e.g. `file://attacker.example/share`) can resolve to a Windows UNC path, which
    /// would make any subsequent filesystem access attempt SMB/NTLM auth against that host.
    /// Such a URL must be rejected before probing — left `Registry` — and, more importantly,
    /// must never reach `fs_probe::metadata` at all, verified via a stat-count snapshot diff.
    #[test]
    fn test_file_repository_probe_rejects_unc_host_and_never_touches_filesystem() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let before = deps_core::fs_probe::snapshot();

        let xml = r"<project>
  <repositories>
    <repository>
      <id>evil-repo</id>
      <url>file://attacker.example/share</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        let after = deps_core::fs_probe::snapshot();

        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
        assert_eq!(
            before, after,
            "a host-bearing file:// repository URL must never reach fs_probe::metadata"
        );
    }

    /// #1503 S2 regression: `${project.basedir}` (the idiomatic, most common way to declare a
    /// repository relative to the project) resolves correctly against a real `doc_uri`, and
    /// the probe still finds a jar declared relative to it.
    #[test]
    fn test_file_repository_probe_resolves_project_basedir_property() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        write_fake_jar(
            &tmp.path().join("local-maven-repo"),
            "com.acme",
            "internal-lib",
            "1.0.0",
        );
        let pom_uri = Url::from_file_path(tmp.path().join("pom.xml")).unwrap();

        let xml = r"<project>
  <repositories>
    <repository>
      <id>local-repo</id>
      <url>file://${project.basedir}/local-maven-repo</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &pom_uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path { .. }
        );
    }

    /// #1503 regression: a `pom.xml` with only `http(s)://` repositories must keep the
    /// default `Registry` classification.
    #[test]
    fn test_http_only_repository_keeps_registry_classification() {
        let xml = r"<project>
  <repositories>
    <repository>
      <id>central-mirror</id>
      <url>https://mirror.example.com/maven2</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>public-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
    }

    /// #1503: mixed `file://` and `http(s)://` repositories in the same `pom.xml` — the
    /// `http(s)://` entry is ignored for probing purposes, and the dependency whose jar is
    /// actually present under the `file://` entry still classifies as `Path`, while a sibling
    /// with no matching jar stays `Registry` (the per-package probe, not a blanket rule).
    #[test]
    fn test_mixed_repositories_probes_only_file_scheme_entries() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        write_fake_jar(tmp.path(), "com.acme", "internal-lib", "1.0.0");
        let repo_url = Url::from_file_path(tmp.path()).unwrap();

        let xml = format!(
            r"<project>
  <repositories>
    <repository>
      <id>central-mirror</id>
      <url>https://mirror.example.com/maven2</url>
    </repository>
    <repository>
      <id>local-repo</id>
      <url>{repo_url}</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        let internal_lib = result
            .dependencies
            .iter()
            .find(|d| d.artifact_id == "internal-lib")
            .unwrap();
        let guava = result
            .dependencies
            .iter()
            .find(|d| d.artifact_id == "guava")
            .unwrap();
        assert_matches!(
            internal_lib.source,
            deps_core::parser::DependencySource::Path { .. }
        );
        assert_eq!(guava.source, deps_core::parser::DependencySource::Registry);
    }

    #[test]
    fn test_parse_dependency_management() {
        let xml = r"<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>3.2.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_matches!(result.dependencies[0].scope, MavenScope::Import);
    }

    #[test]
    fn test_parse_plugin_deps() {
        let xml = r"<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
      </plugin>
    </plugins>
  </build>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.apache.maven.plugins:maven-compiler-plugin"
        );
    }

    #[test]
    fn test_parse_scopes() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>a</groupId>
      <artifactId>b</artifactId>
      <scope>runtime</scope>
    </dependency>
    <dependency>
      <groupId>c</groupId>
      <artifactId>d</artifactId>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].scope, MavenScope::Runtime);
        assert_matches!(result.dependencies[1].scope, MavenScope::Provided);
    }

    #[test]
    fn test_parse_no_version() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_req.is_none());
    }

    // #1161: an empty `<version></version>` tag must still resolve a trackable, zero-width
    // `version_range` for completion to anchor on, while `version_req` stays `None` — same as
    // `test_parse_no_version` above. code_actions/code_lenses/most diagnostics rules already
    // gate on `version_req` being `Some`, unaffected either way; hover/inlay-hints/the
    // remaining diagnostics rules (deprecation, vulnerability, in-use-yanked) matched or
    // anchored on `version_range` alone and needed their own `version_req`-aware guard —
    // see `deps_core::lsp_helpers::{hover, inlay_hints, diagnostics::version_anchor_range}`
    // (#1161 M1 critic follow-up).
    #[test]
    fn test_parse_empty_version_tag_sets_zero_width_range_but_no_requirement() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>foo</artifactId>
      <version></version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        let range = dep
            .version_range
            .expect("empty tag must still yield a trackable range");
        assert_eq!(
            range.start, range.end,
            "empty tag content must be zero-width"
        );
        let line = xml.lines().nth(range.start.line as usize).unwrap();
        let expected_character = u32::try_from("      <version>".chars().count()).unwrap();
        assert_eq!(
            range.start.character, expected_character,
            "range must sit right after the opening tag on {line:?}, not at (0, 0)"
        );
    }

    // #1161 follow-up: whitespace-only content between the tags must behave identically to
    // fully empty, since quick-xml elides an all-whitespace text node under `trim_text(true)`
    // the same way it elides a genuinely empty one.
    #[test]
    fn test_parse_whitespace_only_version_tag_sets_zero_width_range_but_no_requirement() {
        let xml = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>foo</artifactId>\n      <version>   </version>\n    </dependency>\n  </dependencies>\n</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        let range = dep
            .version_range
            .expect("whitespace-only tag must still yield a trackable range");
        assert_eq!(
            range.start, range.end,
            "whitespace-only tag content must be zero-width"
        );
        // Empirically verified (quick-xml 0.42.0): a whitespace-only text node between tags
        // is elided entirely under `trim_text(true)` — no `Event::Text` fires at all, so this
        // takes the exact same `version_open_pos`/`version_close_pos` fallback path as a fully
        // empty tag, landing right after `<version>` rather than at a bogus `(0, 0)` (the
        // position `text_range` would produce if an empty-string `Event::Text` ever did fire
        // here and got routed through the `Some(v)` branch instead).
        let expected_character = u32::try_from("      <version>".chars().count()).unwrap();
        assert_eq!(range.start.character, expected_character);
        assert_eq!(range.start.line, 5);
    }

    // S1 (critic/tester follow-up to #1161): a self-closing `<version/>` fires a single
    // quick-xml `Event::Empty`, never `Start`+`End` — without a dedicated arm for it, this
    // reproduces the original #1161 symptom (`version_range = None`) verbatim, since neither
    // `version_open_pos` nor `version_close_pos` would ever be set.
    #[test]
    fn test_parse_self_closing_version_tag_sets_zero_width_range_but_no_requirement() {
        let xml = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>foo</artifactId>\n      <version/>\n    </dependency>\n  </dependencies>\n</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        let range = dep
            .version_range
            .expect("self-closing tag must still yield a trackable range");
        assert_eq!(
            range.start, range.end,
            "self-closing tag content must be zero-width"
        );
        assert_eq!(range.start.line, 5);
    }

    #[test]
    fn test_parse_property_version_resolved() {
        let xml = r"<project>
  <properties>
    <slf4j.version>2.0.16</slf4j.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("2.0.16".into()));
    }

    #[test]
    fn test_parse_property_version_unresolved() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        // Unresolved property kept as-is
        assert_eq!(
            result.dependencies[0].version_req,
            Some("${slf4j.version}".into())
        );
    }

    #[test]
    fn test_parse_project_version_property() {
        let xml = r"<project>
  <groupId>org.example</groupId>
  <artifactId>my-app</artifactId>
  <version>2.5.0</version>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>my-lib</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("2.5.0".into()));
        assert_eq!(
            result
                .properties
                .get("project.version")
                .map(PropertyValue::as_str),
            Some("2.5.0")
        );
        assert_eq!(
            result
                .properties
                .get("project.groupId")
                .map(PropertyValue::as_str),
            Some("org.example")
        );
        assert_eq!(
            result
                .properties
                .get("project.artifactId")
                .map(PropertyValue::as_str),
            Some("my-app")
        );
    }

    #[test]
    fn test_parse_empty_pom() {
        let xml = r#"<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
</project>"#;

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_parse_invalid_xml() {
        // Stray < inside text is a well-formed XML error
        let xml = "<project><dependencies><dependency><groupId>a</groupId><artifactId>b < c</artifactId></dependency></dependencies></project>";
        let result = parse_pom_xml(xml, &test_uri());
        // quick-xml may or may not error on this; either empty deps or error is acceptable
        if let Ok(ref r) = result {
            // If parsed, groupId should not contain invalid XML content
            let _ = r.dependencies.len();
        }
        // Malformed attribute triggers a hard error
        let xml2 = r#"<project attr="unclosed></project>"#;
        let result2 = parse_pom_xml(xml2, &test_uri());
        assert_matches!(
            result2,
            Err(DepsError::ParseError { file_type, .. }) if file_type == "pom.xml"
        );
    }

    /// #1243: `quick_xml`'s `IllFormed::MismatchedEndTag` embeds the raw tag-name text
    /// verbatim in its `Display` output, so a credential-shaped tag name must be redacted
    /// the same way `toml_span`/`yaml_rust2` parse errors already are (#1240/#1241).
    #[test]
    fn test_parse_mismatched_end_tag_error_redacts_credential() {
        let xml = "<root><https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x ></root>";

        let message = parse_pom_xml(xml, &test_uri()).unwrap_err().to_string();
        assert!(!message.contains("ghp_SUPERSECRETTOKEN123"));
        assert!(!message.contains("svcacct"));
        assert!(message.contains("pkg.internal.corp"));
    }

    #[test]
    fn test_parse_mismatched_end_tag_error_benign_name_unchanged() {
        let xml = "<root><foo></bar></root>";

        // Derived from the raw quick-xml error, not hardcoded, so assert_eq! gates a
        // redaction regression (mirrors #1240 M5's convention).
        let mut reader = quick_xml::Reader::from_str(xml);
        reader.config_mut().trim_text(true);
        let raw_err = loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Eof) => panic!("expected a parse error"),
                Ok(_) => {}
                Err(e) => break e,
            }
        };
        let expected = format!("failed to parse pom.xml: {raw_err}");

        let message = parse_pom_xml(xml, &test_uri()).unwrap_err().to_string();
        assert_eq!(message, expected);
    }

    #[test]
    fn test_parse_with_namespaces() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>"#;

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "junit:junit");
    }

    #[test]
    fn test_position_tracking() {
        let xml = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>my-lib</artifactId>\n      <version>1.0.0</version>\n    </dependency>\n  </dependencies>\n</project>";
        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        // artifactId "my-lib" is on line 4 (0-indexed)
        assert_eq!(dep.name_range.start.line, 4);
    }

    #[test]
    fn test_text_range_hint_start_inside_multibyte_char_does_not_panic() {
        // #680: `hint_start` (a quick-xml buffer offset) is not guaranteed to land on a char
        // boundary. "café" is 5 bytes ('é' occupies bytes 3-4); hint_start = 4 lands inside it.
        let content = "café<version>1.0</version>";
        let line_table = LineOffsetTable::new(content);

        // hint_start = 0 is a safe boundary, used as the known-good baseline.
        let expected = text_range(content, &line_table, 0, 0, "1.0");
        // hint_start = 4 lands mid-character in 'é' and must clamp down rather than panic,
        // while still locating the same text.
        let actual = text_range(content, &line_table, 4, 4, "1.0");

        assert_eq!(actual.start.line, expected.start.line);
        assert_eq!(actual.start.character, expected.start.character);
        assert_eq!(actual.end.line, expected.end.line);
        assert_eq!(actual.end.character, expected.end.character);
        assert_ne!(
            actual.start.character, actual.end.character,
            "must locate real text"
        );
    }

    #[test]
    fn test_parse_result_trait() {
        use deps_core::ParseResult;

        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>a</groupId>
      <artifactId>b</artifactId>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies().len(), 1);
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<MavenParseResult>());
    }

    #[test]
    fn test_resolve_properties() {
        let mut props = HashMap::new();
        props.insert(
            "ver".to_string(),
            PropertyValue::new("1.0".to_string()).unwrap(),
        );
        props.insert(
            "suffix".to_string(),
            PropertyValue::new("RELEASE".to_string()).unwrap(),
        );

        assert_eq!(resolve_properties("${ver}", &props), "1.0");
        assert_eq!(resolve_properties("plain", &props), "plain");
        assert_eq!(resolve_properties("${missing}", &props), "${missing}");
        assert_eq!(
            resolve_properties("${ver}-${suffix}", &props),
            "1.0-RELEASE"
        );
    }

    #[test]
    fn test_parse_properties() {
        let xml = r"<project>
  <properties>
    <java.version>17</java.version>
    <spring.version>3.2.0</spring.version>
  </properties>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(
            result
                .properties
                .get("java.version")
                .map(PropertyValue::as_str),
            Some("17")
        );
        assert_eq!(
            result
                .properties
                .get("spring.version")
                .map(PropertyValue::as_str),
            Some("3.2.0")
        );
    }

    /// #1481: a property value past the cap is dropped from the map at insertion time, so a
    /// reference to it falls through the same "unresolved" path as a genuinely missing
    /// property, rather than retaining an unbounded value.
    #[test]
    fn test_oversized_property_value_dropped_leaves_reference_unresolved() {
        let oversized = "x".repeat(MAX_INTERPOLATED_VALUE_BYTES + 1);
        let xml = format!(
            r"<project>
  <properties>
    <big.version>{oversized}</big.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>foo</artifactId>
      <version>${{big.version}}</version>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert!(!result.properties.contains_key("big.version"));
        assert_eq!(
            result.dependencies[0].version_req,
            Some("${big.version}".into())
        );
    }

    /// #1481: a property value exactly at the cap is kept and resolves normally.
    #[test]
    fn test_property_value_at_exact_cap_resolves() {
        let at_cap = "1".repeat(MAX_INTERPOLATED_VALUE_BYTES);
        let mut props = HashMap::new();
        props.insert(
            "ver".to_string(),
            PropertyValue::new(at_cap.clone()).unwrap(),
        );

        assert_eq!(resolve_properties("${ver}", &props), at_cap);
    }

    /// #1202/#1481 (systemPath sink): an oversized property referenced from `<systemPath>`
    /// also falls through unresolved rather than retaining the raw text.
    #[test]
    fn test_oversized_property_value_in_system_path_stays_unresolved() {
        let oversized = "x".repeat(MAX_INTERPOLATED_VALUE_BYTES + 1);
        let xml = format!(
            r"<project>
  <properties>
    <jar.path>{oversized}</jar.path>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-jar</artifactId>
      <version>1.0.0</version>
      <scope>system</scope>
      <systemPath>${{jar.path}}</systemPath>
    </dependency>
  </dependencies>
</project>"
        );

        let result = parse_pom_xml(&xml, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path {
                path: "${jar.path}".into(),
            }
        );
    }

    /// #1481 (review follow-up): a self-referential property (`${p}` inside `p`'s own
    /// definition) must not grow the resolved result unboundedly across the 5 substitution
    /// rounds — once a later round's predicted length would exceed the cap, resolution stops
    /// with the last successful substitution kept (round 1's expansion here), rather than
    /// either performing a partial *over-cap* expansion or discarding round 1's already-safe
    /// substitution back to the pristine input. `${p}` itself stays unresolved in the result
    /// (round 2 never ran), which is the "no partial expansion past the cap" guarantee.
    #[test]
    fn test_self_referential_property_growth_stays_unresolved() {
        let mut props = HashMap::new();
        let filler = "A".repeat(MAX_INTERPOLATED_VALUE_BYTES - 4);
        let self_ref_value = format!("${{p}}{filler}");
        props.insert(
            "p".to_string(),
            PropertyValue::new(self_ref_value.clone()).unwrap(),
        );

        let result = resolve_properties("${p}", &props);
        assert_eq!(
            result, self_ref_value,
            "round 1's successful substitution must be kept; only round 2's would-exceed-cap \
             substitution is skipped, leaving the inner ${{p}} unresolved"
        );
        assert!(
            result.contains("${p}"),
            "the never-run round 2 substitution must leave its placeholder unresolved"
        );
    }

    /// #1481 review follow-up: a cap-exceeded bail in one round must not discard an earlier
    /// round's unrelated, already-successful substitution — only the offending placeholder
    /// stays unresolved, matching the missing-property fallback's `break` semantics.
    #[test]
    fn test_cap_exceeded_bail_preserves_unrelated_earlier_substitution() {
        let mut props = HashMap::new();
        props.insert(
            "a".to_string(),
            PropertyValue::new("1.0".to_string()).unwrap(),
        );
        // At the per-value cap: round 1 resolves "${a}" to "1.0" (result becomes
        // "1.0-${big}", 10 bytes), then round 2's predicted length for "${big}" is
        // 10 - 6 + 1024 = 1028, over the cap, so round 2 bails via `break` — this value
        // must itself be a valid `PropertyValue` (<= cap) to isolate the multi-round
        // *combined*-length bail from the already-covered oversized-single-value case.
        let at_cap = "X".repeat(MAX_INTERPOLATED_VALUE_BYTES);
        props.insert("big".to_string(), PropertyValue::new(at_cap).unwrap());

        let result = resolve_properties("${a}-${big}", &props);
        assert_eq!(
            result, "1.0-${big}",
            "the unrelated ${{a}} substitution from round 1 must survive round 2's bail"
        );
    }

    /// #1481 critic M4 follow-up: growth across rounds that lands *exactly* at the cap in a
    /// round after the first must still resolve normally, not be mistaken for the
    /// over-the-cap case `test_self_referential_property_growth_stays_unresolved` covers.
    /// `p1` resolves to `${p2}` plus a 500-byte filler (round 1); `p2` then resolves to a
    /// 524-byte value (round 2), landing the predicted length at exactly
    /// `MAX_INTERPOLATED_VALUE_BYTES` (500 + 524 = 1024) on that second round.
    #[test]
    fn test_multi_round_growth_landing_exactly_at_cap_resolves() {
        let mut props = HashMap::new();
        let filler1 = "A".repeat(500);
        let value2 = "B".repeat(524);
        props.insert(
            "p1".to_string(),
            PropertyValue::new(format!("${{p2}}{filler1}")).unwrap(),
        );
        props.insert(
            "p2".to_string(),
            PropertyValue::new(value2.clone()).unwrap(),
        );

        let result = resolve_properties("${p1}", &props);
        assert_eq!(
            result,
            format!("{value2}{filler1}"),
            "a predicted length landing exactly at the cap on round 2 must still resolve"
        );
    }
}
