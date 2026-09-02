//! Completion handler implementation.
//!
//! Delegates to ecosystem-specific completion logic.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::EcosystemId;
use deps_core::completion::COMPLETION_SEARCH_TIMEOUT;
use deps_core::{
    is_safe_maven_coordinate_segment, is_safe_package_name, is_safe_registry_url,
    is_safe_version_string, lsp_helpers::warn_rejected_value,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, CompletionList, CompletionParams, CompletionResponse,
    InsertTextFormat,
};

// Completion is keystroke-driven and must stay responsive, so registry-backed
// completion work gets its own short timeout instead of sharing the 30s HTTP client
// timeout used elsewhere ([`COMPLETION_SEARCH_TIMEOUT`]).
//
// Shared with `deps_core::completion` (rather than kept local) because
// registry-backed completion paths that retry internally on failure (e.g.
// `deps-maven`'s `search_typed`, #274) must size their own retry budget against
// this same value — see `deps_core::completion::COMPLETION_SEARCH_TIMEOUT`'s doc.

/// Handles completion requests.
///
/// Delegates to the appropriate ecosystem implementation based on the document type.
/// Falls back to text-based completion when TOML parsing fails (user is still typing).
pub async fn handle_completion(
    state: Arc<ServerState>,
    params: CompletionParams,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Option<CompletionResponse> {
    let uri = &params.text_document_position.text_document.uri;
    let position = params.text_document_position.position;

    tracing::info!(
        "completion request: uri={:?}, line={}, character={}",
        uri,
        position.line,
        position.character
    );

    // Snapshot before any document lookup, matching hover.rs/diagnostics.rs's ordering —
    // this acquires the config RwLock before the DashMap shard guard, never the reverse.
    let freshness = { config.read().await.freshness.to_settings() };

    // Resolved once, from the URI alone via `get_for_uri` (the same routing
    // `handle_document_open` uses), rather than from the loaded document's
    // `ecosystem_id` — that would only be available *after* the document-load and
    // document-lookup early returns below. `is_some_and` (not `?`) so an
    // unrecognized URI falls through to `false` (matching every ecosystem's
    // default) rather than short-circuiting this function.
    let package_search_is_incomplete = state
        .ecosystem_registry
        .get_for_uri(uri)
        .is_some_and(|e| e.package_search_is_incomplete());

    // Shared by the document-load and document-lookup early returns below, so
    // both report `isIncomplete` consistently for an ecosystem whose package-name
    // search (the only kind of completion either path could otherwise have
    // produced, via `fallback_completion`) may be a truncated view of a larger
    // candidate set (#419 S1) — `None` would serialize as LSP `null`, which
    // carries no `isIncomplete` and leaves the client with nothing to invalidate
    // on the next keystroke.
    let context_less_response = || {
        if package_search_is_incomplete {
            Some(CompletionResponse::List(CompletionList {
                is_incomplete: true,
                items: vec![],
            }))
        } else {
            None
        }
    };

    // Check if document is loaded, if not try to load with short timeout
    // Completion is latency-critical, so we use a 200ms timeout
    if state.get_document(uri).is_none() {
        tracing::info!("completion: document not loaded, loading from disk");

        // Try to load with short timeout (200ms)
        let load_result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            ensure_document_loaded(uri, Arc::clone(&state), client.clone(), Arc::clone(&config)),
        )
        .await;

        match load_result {
            Ok(true) => {
                // Document loaded successfully, continue with completion
                tracing::debug!("completion: document loaded successfully");
            }
            Ok(false) | Err(_) => {
                // Load failed or timed out, return empty completions
                tracing::warn!("completion: document load failed or timed out");
                return context_less_response();
            }
        }
    }

    // Own everything needed from the document in a single shard acquisition, then
    // release the `Ref` immediately: two separate acquisitions (one for `content`, a
    // later one for `parse_result`) would let a concurrent `didChange` land in
    // between, pairing a `parse_result` with `content` from a different document
    // revision — `generate_completions` correlates the two (e.g. `extract_prefix`
    // slicing `content` at a range taken from `parse_result`), so a torn pair risks
    // wrong or out-of-bounds-guarded-empty completions (#319 review).
    // `with_document` makes releasing the guard structural rather than a convention
    // to remember (#333).
    let Some((ecosystem_id, ecosystem_kind, content, parse_result)) =
        state.with_document(uri, |doc| {
            (
                doc.ecosystem_id(),
                doc.ecosystem,
                doc.content.clone(),
                doc.parse_result_arc(),
            )
        })
    else {
        tracing::warn!("completion: document not found: {:?}", uri);
        return context_less_response();
    };

    tracing::info!(
        "completion: ecosystem={}, has_parse_result={}",
        ecosystem_id,
        parse_result.is_some()
    );

    // Try parse_result first, fallback to text-based detection. `is_incomplete` is
    // the per-call signal `generate_completions` computed for the actual completion
    // context it served (#427). Whenever `fallback_completion` actually runs — the
    // primary result was empty, or there was no `parse_result` to call
    // `generate_completions` with at all — it is OR'd with
    // `ecosystem.package_search_is_incomplete()`: `fallback_completion` always
    // performs a raw package-name search via `Registry::search` regardless of the
    // primary context, so it inherits the primary's `is_incomplete` only by
    // coincidence, not because the two searches share a completeness signal.
    let (items, is_incomplete) = if let Some(parse_result) = parse_result {
        match state.ecosystem_registry.get(ecosystem_id) {
            Some(ecosystem) => {
                // The DashMap shard `Ref` was already dropped above, before this
                // timeout-bound await: the search can run for up to
                // `COMPLETION_SEARCH_TIMEOUT`, and holding the guard that long would
                // block a concurrent `documents.get_mut` on the same shard for the
                // duration (#319).
                let completion_result = tokio::time::timeout(
                    COMPLETION_SEARCH_TIMEOUT,
                    ecosystem.generate_completions(
                        parse_result.as_ref(),
                        position,
                        &content,
                        freshness,
                    ),
                )
                .await;

                match completion_result {
                    // Ecosystem returned no completions: try fallback, since this
                    // handles the case where the user is typing a NEW package name.
                    Ok(completions) if completions.items.is_empty() => {
                        tracing::info!("completion: ecosystem returned empty, trying fallback");
                        let fallback_items =
                            fallback_completion(&state, ecosystem_kind, position, &content).await;
                        (
                            fallback_items,
                            completions.is_incomplete || ecosystem.package_search_is_incomplete(),
                        )
                    }
                    Ok(completions) => (completions.items, completions.is_incomplete),
                    // Timed out, not genuinely empty: the registry is slow right now,
                    // so a fallback search against the same registry would likely
                    // time out too. Skip it instead of doubling the worst-case
                    // latency.
                    Err(_) => {
                        tracing::warn!(
                            "completion: generate_completions timed out after \
                             {}s, skipping fallback search",
                            COMPLETION_SEARCH_TIMEOUT.as_secs()
                        );
                        (vec![], false)
                    }
                }
            }
            None => {
                tracing::warn!("completion: ecosystem not found for id: {ecosystem_id}");
                (vec![], false)
            }
        }
    } else {
        // Fallback: detect context from raw text. No `parse_result` means
        // `generate_completions` was never called, so `package_search_is_incomplete`
        // (already resolved for this URI's ecosystem above) is the only signal
        // available — matches the every-`didChange`-with-a-parse-failure case
        // (`document/lifecycle.rs`'s `new_without_parse_result`), exactly the
        // mid-typing state for a new package name.
        (
            fallback_completion(&state, ecosystem_kind, position, &content).await,
            package_search_is_incomplete,
        )
    };

    tracing::info!("completion: returning {} items", items.len());

    if is_incomplete {
        // Must still be a `List` when `items` is empty: `None` serializes as LSP
        // `null`, which carries no `isIncomplete` and leaves the client with
        // nothing to invalidate on the next keystroke (#419 C1) — this is the
        // cold-start-returns-empty case PyPI's search index relies on.
        Some(CompletionResponse::List(CompletionList {
            is_incomplete: true,
            items,
        }))
    } else if items.is_empty() {
        None
    } else {
        Some(CompletionResponse::Array(items))
    }
}

/// Fallback completion when document parsing fails.
///
/// Detects dependencies sections from raw text and provides package name suggestions.
async fn fallback_completion(
    state: &ServerState,
    ecosystem_kind: EcosystemId,
    position: tower_lsp_server::ls_types::Position,
    content: &str,
) -> Vec<CompletionItem> {
    tracing::info!(
        "fallback_completion: starting for ecosystem={}",
        ecosystem_kind
    );

    // Get the current line
    let line = match content.lines().nth(position.line as usize) {
        Some(l) => l,
        None => {
            tracing::info!("fallback_completion: line {} not found", position.line);
            return vec![];
        }
    };

    tracing::info!("fallback_completion: line content = {:?}", line);

    if !is_in_dependencies_section(content, position.line as usize, ecosystem_kind) {
        tracing::info!("fallback_completion: not in dependencies section");
        return vec![];
    }

    // Extract what user has typed (from start of line to cursor)
    let prefix = extract_prefix(line, position.character, ecosystem_kind);

    tracing::info!("fallback_completion: prefix = {:?}", prefix);

    // If it looks like a package name (letters, no = sign, at least 2 chars).
    // Count Unicode scalar values, not bytes: a single multi-byte character
    // (e.g. one CJK character) must not satisfy the "at least 2 chars" intent.
    if prefix.is_empty() || prefix.contains('=') || prefix.chars().count() < 2 {
        tracing::info!("fallback_completion: prefix rejected (empty, contains =, or < 2 chars)");
        return vec![];
    }

    // Get ecosystem and search for packages
    let ecosystem = match state.ecosystem_registry.get(ecosystem_kind.id()) {
        Some(e) => e,
        None => return vec![],
    };

    let registry = ecosystem.registry();

    // Search for packages matching the prefix
    search_packages(registry.as_ref(), ecosystem_kind, prefix).await
}

/// Extracts what the user has typed on `line` up to the cursor (`character`), trimmed
/// of whitespace.
///
/// For JSON manifests (package.json, composer.json) a quote can survive on either
/// side: a leading `"` when the cursor sits before the closing quote of a still-typed
/// key, or a trailing `"` when the cursor sits right after a closing quote (e.g. an
/// editor auto-closed it, or the user retyped it). Either would otherwise reach the
/// registry as part of the search query and suppress exact matches. PyPI's
/// `pyproject.toml` entries (`"pytes` inside `dependencies = [...]`) carry the same
/// surviving-quote shape, just as a TOML array element rather than a JSON key — see
/// [`uses_toml_string_array_values`].
///
/// For XML manifests (`pom.xml`) an opening tag survives on the left instead (cursor
/// inside `<artifactId>gua`) — stripped so the extracted text matches what the
/// ecosystem's own primary completion path (e.g. `MavenEcosystem::detect_xml_context`)
/// searches for at the same cursor position. Without this, the raw-text fallback path
/// searches the registry for markup-polluted text instead of the real prefix, and (#282
/// C1) a per-query dedup/cache mechanism keyed on the search string never recognizes
/// the fallback's call as a repeat of the primary path's call for the same prefix.
fn extract_prefix(line: &str, character: u32, ecosystem_kind: EcosystemId) -> &str {
    let prefix_end =
        deps_core::completion::utf16_to_byte_offset(line, character).unwrap_or(line.len());
    let prefix = line[..prefix_end].trim();
    if uses_json_quoted_keys(ecosystem_kind) || uses_toml_string_array_values(ecosystem_kind) {
        prefix.trim_matches('"')
    } else if uses_xml_tag_values(ecosystem_kind) {
        strip_leading_xml_tag(prefix)
    } else {
        prefix
    }
}

/// Whether `ecosystem_kind`'s manifest wraps a completable value in an XML open tag on
/// the same line (`<artifactId>gua`), so [`extract_prefix`] must strip that tag.
///
/// Exhaustively matched, like [`uses_json_quoted_keys`], so a future XML-manifest
/// ecosystem forces a decision here instead of silently leaking tag markup into a
/// registry search query. NuGet is XML too but correctly `false`: its dependencies are
/// attribute-valued (`<PackageReference Include="..." Version="..." />`), not tag-value
/// wrapped like Maven's, and its `is_in_dependencies_section` arm is already `false`
/// (see that function's doc), so it never reaches `extract_prefix` regardless.
const fn uses_xml_tag_values(ecosystem_kind: EcosystemId) -> bool {
    match ecosystem_kind {
        EcosystemId::Maven => true,
        EcosystemId::Npm
        | EcosystemId::Composer
        | EcosystemId::Cargo
        | EcosystemId::Pypi
        | EcosystemId::Go
        | EcosystemId::Dart
        | EcosystemId::Gradle
        | EcosystemId::Swift
        | EcosystemId::NuGet
        | EcosystemId::Bundler
        | EcosystemId::Deno
        | EcosystemId::GithubActions => false,
    }
}

/// Strips everything up to and including the *last* `>` in `prefix` (`<artifactId>gua`
/// -> `gua`); returns `prefix` unchanged if it contains no `>` at all (e.g. the tag is
/// not yet closed, as when the user is still typing the tag name itself).
///
/// Scans for the last `>`, not the first, to mirror `MavenEcosystem::
/// detect_xml_context`'s own `rfind`-based tag lookup (`crates/deps-maven/src/
/// ecosystem.rs`): that function locates the closest opening tag *before the cursor*,
/// which is the last one on the line, not the first. A first-`>` version of this
/// function diverges from it whenever more than one tag precedes the cursor on a line
/// (`<groupId>com.google.guava</groupId><artifactId>gua` — the first `>` sits inside
/// `<groupId>`, well short of the real value), or when the cursor sits right after a
/// closing tag (`<artifactId>guava</artifactId>` with the cursor at the end: the last
/// `>` is the line's very last character, correctly yielding an empty string — matching
/// `detect_xml_context`'s own "no context" outcome for that position, since its
/// `between.contains("</")` guard rejects it too).
fn strip_leading_xml_tag(prefix: &str) -> &str {
    prefix.rfind('>').map_or(prefix, |gt| &prefix[gt + 1..])
}

/// Whether `ecosystem_kind`'s manifest keys are typed as JSON string literals
/// (package.json, composer.json), and so can carry a stray quote into [`extract_prefix`].
///
/// Exhaustively matched, like [`is_in_dependencies_section`], so a future JSON-manifest
/// ecosystem forces a decision here instead of silently keeping a stray quote.
///
/// `Deno` is deliberately `false` despite `deno.json` being JSON, unlike npm/Composer:
/// the npm analogy doesn't hold here because the completable text at a package-name
/// position in `deno.json` is the JSON *value* (the `jsr:`/`npm:` specifier string), not
/// the *key* (the import alias) — `extract_prefix`'s whole-line-to-cursor-then-trim
/// approach only strips a stray quote correctly for a key-position completion, so
/// applying it to Deno would leak the alias and colon into the fallback search query.
///
/// Fallback (raw-text) completion does still *run* for Deno — `is_in_dependencies_section`
/// returns `true` inside `imports`, same as any other JSON ecosystem — but it is harmless:
/// the raw line-start-to-cursor text `extract_prefix` produces is always preceded by the
/// alias key, colon and opening quote in real JSON (`"@std/fs": "jsr:@std/f`), so it can
/// never coincide with a bare `jsr:`/`npm:` prefix. `DenoRegistry::search` (`deps-deno`)
/// therefore always takes its scheme-less `None => Ok(vec![])` arm for this path, so the
/// fallback query is effectively a no-op rather than a source of garbage results — it is
/// the primary `detect_completion_context`-based path
/// (`DenoEcosystem::generate_completions`) that does the real work.
const fn uses_json_quoted_keys(ecosystem_kind: EcosystemId) -> bool {
    match ecosystem_kind {
        EcosystemId::Npm | EcosystemId::Composer => true,
        EcosystemId::Cargo
        | EcosystemId::Pypi
        | EcosystemId::Go
        | EcosystemId::Dart
        | EcosystemId::Maven
        | EcosystemId::Gradle
        | EcosystemId::Swift
        | EcosystemId::NuGet
        | EcosystemId::Bundler
        | EcosystemId::Deno
        | EcosystemId::GithubActions => false,
    }
}

/// Whether `ecosystem_kind`'s manifest completes a value positioned as a TOML
/// string-array *element* (`"pytes` inside `dependencies = [...]`), so
/// [`extract_prefix`] must strip a surviving quote the same way it does for
/// [`uses_json_quoted_keys`]'s JSON object-key shape.
///
/// PyPI only for now: PEP 621's `dependencies`/`optional-dependencies` entries are
/// the only raw-text-detected (see [`is_in_dependencies_section`]) dependency shape
/// in this file that is a bare TOML array of strings. Cargo also flows through
/// `is_in_toml_dependencies`, but its dependency shape is a *key* (`name =
/// "version"`), not an array element, so it must stay `false` here — a `true`
/// value would incorrectly strip a quote from a still-typed Cargo key.
const fn uses_toml_string_array_values(ecosystem_kind: EcosystemId) -> bool {
    match ecosystem_kind {
        EcosystemId::Pypi => true,
        EcosystemId::Cargo
        | EcosystemId::Npm
        | EcosystemId::Composer
        | EcosystemId::Go
        | EcosystemId::Dart
        | EcosystemId::Maven
        | EcosystemId::Gradle
        | EcosystemId::Swift
        | EcosystemId::NuGet
        | EcosystemId::Bundler
        | EcosystemId::Deno
        | EcosystemId::GithubActions => false,
    }
}

/// Checks if a line is inside a dependencies section.
///
/// Dispatches to a per-ecosystem raw-text heuristic. Matching on [`EcosystemId`]
/// rather than the raw ecosystem id string makes this exhaustive: adding a new
/// ecosystem forces a decision here instead of silently disabling section-aware
/// completion for it (see issue #118).
fn is_in_dependencies_section(
    content: &str,
    line_number: usize,
    ecosystem_id: EcosystemId,
) -> bool {
    match ecosystem_id {
        EcosystemId::Cargo => is_in_toml_dependencies(content, line_number),
        // PyPI's PEP 621 primary dependency list is a `dependencies = [...]` array
        // under `[project]`, not a section header like Cargo's `[dependencies]` —
        // `is_in_toml_dependencies` alone never matches it (see
        // `is_in_pypi_project_dependencies_array`'s doc). `[project.optional-
        // dependencies]` groups, by contrast, ARE a real header and stay covered by
        // `is_in_toml_dependencies`.
        EcosystemId::Pypi => {
            is_in_toml_dependencies(content, line_number)
                || is_in_pypi_project_dependencies_array(content, line_number)
        }
        EcosystemId::Npm => is_in_json_dependencies(
            content,
            line_number,
            &[
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ],
        ),
        EcosystemId::Composer => {
            is_in_json_dependencies(content, line_number, &["require", "require-dev"])
        }
        EcosystemId::Maven => is_in_xml_tag_section(content, line_number, "dependencies"),
        EcosystemId::Go => is_in_go_require(content, line_number),
        EcosystemId::Dart => is_in_yaml_dependencies(content, line_number),
        // TODO(#118 follow-up): Gemfile has no delimited dependencies section —
        // `gem "name"` calls are valid anywhere at the top level or inside
        // `group ... do ... end` blocks, so there is no raw-text boundary to detect.
        // `false` matches the pre-fix behavior (fallback completion disabled) rather
        // than `true`: `fallback_completion` fires on every keystroke where the
        // ecosystem's own completion is empty, using the *whole trimmed line* as the
        // search query (not a token), so a permissive `true` here would fire a live
        // registry search on unrelated text and insert results with unrelated syntax.
        EcosystemId::Bundler => false,
        // TODO(#118 follow-up): Package.swift dependencies are `.package(...)` calls
        // matched anywhere in the file by the real parser (not confined to the
        // `dependencies: [...]` array), so there is no reliable raw-text section
        // boundary here either. See the Bundler arm above for why this is `false`.
        EcosystemId::Swift => false,
        // TODO(#118 follow-up): Gradle spans five manifest formats (TOML version
        // catalog, Groovy DSL, Kotlin DSL) with no raw-text section marker shared
        // across all of them. See the Bundler arm above for why this is `false`.
        EcosystemId::Gradle => false,
        // TODO(#118 follow-up): NuGet spans three schemas: csproj/Directory.Packages
        // .props nest PackageReference/PackageVersion in `<ItemGroup>`, while
        // packages.config lists `<package>` elements directly under its root with no
        // such wrapper. See the Bundler arm above for why this is `false`.
        EcosystemId::NuGet => false,
        EcosystemId::Deno => is_in_json_dependencies(content, line_number, &["imports"]),
        // A `uses:` step key can appear at any nesting depth in a workflow file
        // (`jobs.*.steps[].uses`, `jobs.<id>.uses`), so unlike the other YAML/TOML/
        // JSON ecosystems above there is no enclosing section header to track —
        // the target line itself is the only signal needed.
        EcosystemId::GithubActions => is_github_actions_uses_line(content, line_number),
    }
}

/// Whether line `line_number` of `content` is a workflow `uses:` step key
/// (`uses: owner/repo@ref` or, as a sequence item, `- uses: owner/repo@ref`).
fn is_github_actions_uses_line(content: &str, line_number: usize) -> bool {
    content
        .lines()
        .nth(line_number)
        .map(str::trim_start)
        .is_some_and(|trimmed| trimmed.starts_with("uses:") || trimmed.starts_with("- uses:"))
}

/// Checks if a line is inside a TOML dependencies section.
///
/// Looks for `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` sections
/// in Cargo.toml or `[project.dependencies]` in pyproject.toml.
fn is_in_toml_dependencies(content: &str, line_number: usize) -> bool {
    // Walk backwards from current line to find the most recent section header
    // Collect lines up to target, then iterate backwards
    let lines: Vec<_> = content.lines().enumerate().take(line_number + 1).collect();

    for (_, line) in lines.iter().rev() {
        let line = line.trim();

        // Check if this is a section header
        if line.starts_with('[') && line.ends_with(']') {
            // Check if it's a dependencies section
            return line == "[dependencies]"
                || line == "[dev-dependencies]"
                || line == "[build-dependencies]"
                || line == "[workspace.dependencies]"
                || line == "[project.dependencies]"
                || line == "[project.optional-dependencies]"
                || line.starts_with("[target.")
                    && (line.contains(".dependencies]")
                        || line.contains(".dev-dependencies]")
                        || line.contains(".build-dependencies]"));
        }
    }

    false
}

/// Checks if a line is inside PEP 621's `dependencies = [...]` array under the
/// `[project]` table.
///
/// Unlike `[dependencies]`/`[project.optional-dependencies]`, PEP 621's primary
/// dependency list is a *value* (an array assigned to the `dependencies` key), not
/// a section header — no real `pyproject.toml` ever writes a literal
/// `[project.dependencies]` header — so it needs its own bracket-depth scan rather
/// than `is_in_toml_dependencies`'s header-string match.
///
/// The bracket-depth counter has no string awareness, so an unbalanced `[`/`]`
/// inside a still-typed extras spec (`"uvicorn[stan`) or a comment would otherwise
/// desync it permanently. TOML forbids a table header inside an array value, so a
/// bare `[...]` header line (checked on every line, not just outside the array) is
/// used as an unambiguous resync point regardless of the counter's state.
fn is_in_pypi_project_dependencies_array(content: &str, line_number: usize) -> bool {
    let mut in_project = false;
    let mut in_array = false;
    let mut depth: i32 = 0;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }
        let trimmed = strip_trailing_toml_comment(line.trim());

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_array = false;
            in_project = trimmed == "[project]";
            continue;
        }

        if !in_array && in_project && is_dependencies_array_start(trimmed) {
            in_array = true;
            depth = 0;
        }

        if in_array {
            if i == line_number {
                return true;
            }
            for ch in trimmed.chars() {
                match ch {
                    '[' => depth += 1,
                    ']' => depth -= 1,
                    _ => {}
                }
            }
            if depth <= 0 {
                in_array = false;
            }
        }
    }

    false
}

/// Strips a trailing TOML comment (`# ...`) from `line`, ignoring a `#` that
/// appears inside a quoted string.
///
/// Naive like this file's other hand-rolled raw-text scanners (e.g.
/// `is_in_json_dependencies`'s brace counting): does not handle a `\"` escape
/// inside a double-quoted string, which would end the string one character too
/// early. Good enough for the fallback-completion heuristic this feeds.
fn strip_trailing_toml_comment(line: &str) -> &str {
    let mut in_string: Option<char> = None;
    for (idx, ch) in line.char_indices() {
        match in_string {
            Some(quote) if ch == quote => in_string = None,
            Some(_) => {}
            None if ch == '"' || ch == '\'' => in_string = Some(ch),
            None if ch == '#' => return line[..idx].trim_end(),
            None => {}
        }
    }
    line
}

/// Whether `trimmed` opens the `dependencies = [...]` array (`dependencies = [` or
/// the single-line `dependencies = [...]`), used by
/// [`is_in_pypi_project_dependencies_array`].
fn is_dependencies_array_start(trimmed: &str) -> bool {
    trimmed
        .strip_prefix("dependencies")
        .map(str::trim_start)
        .and_then(|rest| rest.strip_prefix('='))
        .is_some_and(|rest| rest.trim_start().starts_with('['))
}

/// Checks if a line is inside a JSON dependencies-like section.
///
/// Looks for `"{key}": {` for any of the given `keys`, e.g. `dependencies` /
/// `devDependencies` in package.json, or `require` / `require-dev` in composer.json.
fn is_in_json_dependencies(content: &str, line_number: usize, keys: &[&str]) -> bool {
    let mut in_dependencies = false;
    let mut brace_depth = 0;
    // Build each `"{key}":` needle once per call rather than once per line.
    let needles: Vec<String> = keys.iter().map(|key| format!("\"{key}\":")).collect();

    for (i, line) in content.lines().enumerate() {
        // Early exit: stop if we've passed the target line
        if i > line_number {
            break;
        }

        let trimmed = line.trim();

        // Check if we're entering a dependencies-like section
        if trimmed.starts_with('"')
            && needles
                .iter()
                .any(|needle| trimmed.contains(needle.as_str()))
        {
            in_dependencies = true;
            brace_depth = 0;
        }

        // Track brace depth when in dependencies section
        if in_dependencies {
            for ch in trimmed.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => {
                        brace_depth -= 1;
                        // If we've closed the dependencies section
                        if brace_depth <= 0 {
                            in_dependencies = false;
                        }
                    }
                    _ => {}
                }
            }

            // If we're at the target line and inside dependencies section with depth > 0
            if i == line_number && in_dependencies && brace_depth > 0 {
                return true;
            }
        }
    }

    false
}

/// Checks if a line is inside an XML `<tag>...</tag>` element.
///
/// Tracks nested open/close tag counts (ignoring attributes and self-closing tags) to
/// find whether the target line falls within any occurrence of the element, e.g.
/// `<dependencies>` in pom.xml (including nested inside `<dependencyManagement>`).
fn is_in_xml_tag_section(content: &str, line_number: usize, tag: &str) -> bool {
    let open_prefix = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut depth: usize = 0;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let opens_here = count_open_tags(line, &open_prefix);
        depth += opens_here;
        // A line with an opening tag counts as "inside" even if the same line also
        // closes it (`<dependencies></dependencies>`), consistent with the target
        // line being the header itself in `is_in_toml_dependencies`.
        if i == line_number && opens_here > 0 {
            return true;
        }

        depth = depth.saturating_sub(line.matches(close.as_str()).count());
        if i == line_number && depth > 0 {
            return true;
        }
    }

    false
}

/// Counts real `<{open_prefix}...>` tag occurrences on `line`, i.e. `open_prefix`
/// followed by `>` or whitespace (an attribute) rather than more tag-name characters
/// (so `<dependencies` doesn't also match a longer, unrelated tag name).
fn count_open_tags(line: &str, open_prefix: &str) -> usize {
    let mut count = 0;
    let mut search_from = 0;

    while let Some(rel_idx) = line[search_from..].find(open_prefix) {
        let idx = search_from + rel_idx;
        let after = &line[idx + open_prefix.len()..];
        if after.starts_with('>') || after.starts_with(char::is_whitespace) {
            count += 1;
        }
        search_from = idx + open_prefix.len();
    }

    count
}

/// Checks if a line is inside a go.mod `require` directive.
///
/// Handles both the single-line form (`require module version`) and the
/// parenthesized block form (`require (` ... `)`).
fn is_in_go_require(content: &str, line_number: usize) -> bool {
    let mut in_require_block = false;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let trimmed = line.trim();
        let is_block_start = trimmed
            .strip_prefix("require")
            .is_some_and(|rest| rest.trim_start().starts_with('('));

        if is_block_start {
            in_require_block = true;
        } else if in_require_block && trimmed.starts_with(')') {
            in_require_block = false;
        }

        if i == line_number {
            return in_require_block || is_block_start || trimmed.starts_with("require ");
        }
    }

    false
}

/// Checks if a line is inside a pubspec.yaml dependency section.
///
/// Dart's `dependencies`, `dev_dependencies`, and `dependency_overrides` keys are
/// top-level (unindented) YAML mappings; their entries stay part of the section until
/// the next unindented key starts a new one.
fn is_in_yaml_dependencies(content: &str, line_number: usize) -> bool {
    const SECTION_KEYS: &[&str] = &[
        "dependencies:",
        "dev_dependencies:",
        "dependency_overrides:",
    ];
    let mut in_dependencies = false;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Top-level (unindented) key: starts a new section, or leaves the current one.
        if trimmed.len() == line.len() {
            in_dependencies = SECTION_KEYS.iter().any(|key| trimmed.starts_with(key));
        }
    }

    in_dependencies
}

/// Searches for packages and returns completion items.
///
/// Bounded by [`deps_core::completion::COMPLETION_SEARCH_TIMEOUT`] as a direct, in-place timeout (not a
/// detached `tokio::spawn`): this keeps the search cancellable by the LSP server's own
/// `$/cancelRequest` handling, which wraps the whole request future and aborts it on
/// cancellation — a detached task would sit outside that abort and keep the request's
/// registry connection open regardless.
async fn search_packages(
    registry: &dyn deps_core::Registry,
    ecosystem_id: EcosystemId,
    query: &str,
) -> Vec<CompletionItem> {
    tracing::info!(
        "search_packages: query={:?}, ecosystem={}",
        query,
        ecosystem_id
    );

    let results =
        match tokio::time::timeout(COMPLETION_SEARCH_TIMEOUT, registry.search(query, 50)).await {
            Ok(Ok(r)) => {
                tracing::info!("search_packages: found {} results", r.len());
                r
            }
            Ok(Err(e)) => {
                tracing::warn!("search_packages: search failed: {}", e);
                return vec![];
            }
            Err(_) => {
                tracing::warn!(
                    "search_packages: timed out after {}s",
                    COMPLETION_SEARCH_TIMEOUT.as_secs()
                );
                return vec![];
            }
        };

    // Convert search results to completion items
    results
        .iter()
        .filter_map(|metadata| create_package_completion_item(metadata.as_ref(), ecosystem_id))
        .collect()
}

/// Creates a completion item for a package.
///
/// The insert text mirrors each ecosystem's manifest syntax, exhaustively matched on
/// [`EcosystemId`] so a new ecosystem must supply its own snippet instead of silently
/// inheriting Cargo's `name = "version"` TOML syntax (see issue #118).
///
/// Returns `None` when a value this function interpolates into `insert_text` fails its
/// allowlist — `latest` against [`is_safe_version_string`] (whenever non-empty; several
/// arms legitimately omit the version clause when it's empty, so an empty `latest` is not
/// itself unsafe), a Maven `groupId`/`artifactId` against
/// [`is_safe_maven_coordinate_segment`], and a Swift repository URL against
/// [`is_safe_registry_url`]. `metadata` comes straight from a registry search response, so
/// a malicious/compromised registry must not be able to write structural
/// characters into the manifest this text is inserted into.
fn create_package_completion_item(
    metadata: &dyn deps_core::Metadata,
    ecosystem_id: EcosystemId,
) -> Option<CompletionItem> {
    let name = metadata.name();
    let latest = metadata.latest_version().as_str();
    let description = metadata.description();

    if !is_safe_package_name(name.as_str()) {
        warn_rejected_value(
            "is_safe_package_name",
            "package name completion item",
            name.as_str(),
        );
        return None;
    }

    if !latest.is_empty() && !is_safe_version_string(latest) {
        warn_rejected_value(
            "is_safe_version_string",
            "package name completion item",
            latest,
        );
        return None;
    }

    let insert_text = match ecosystem_id {
        // The key is quoted, not bare: a bare TOML key containing `.` (allowed by
        // `is_safe_package_name` for Cargo crate names) expands into a nested table
        // instead of a dependency entry — quoting closes that dotted-key injection.
        EcosystemId::Cargo => format!("\"{name}\" = \"{latest}\""),
        // Both real PEP 621 shapes (`dependencies = [...]` and an
        // `[project.optional-dependencies]` group) are TOML string-array elements,
        // not a key=value table entry like Cargo's — the surrounding quotes already
        // exist in the manifest (or the user is still typing them), matching the
        // bare-name insert `build_package_completion` already uses for PyPI at the
        // same cursor position on the primary (parsed) completion path.
        EcosystemId::Pypi => name.to_string(),
        EcosystemId::Npm | EcosystemId::Composer => format!("\"{name}\": \"^{latest}\""),
        EcosystemId::Go => format!("{name} {latest}"),
        // The key is quoted: an unquoted YAML plain scalar can't start with `@`
        // (allowed by `is_safe_package_name` for npm/Deno-shaped names), which would
        // otherwise emit invalid YAML instead of a dependency entry.
        EcosystemId::Dart => format!("\"{name}\": ^{latest}"),
        EcosystemId::Maven => {
            // The predicate rejects `:` by design (see its doc comment), so it must
            // validate each half of the coordinate after splitting, never the joined
            // `name`.
            let (group_id, artifact_id) = match name.as_str().split_once(':') {
                Some((group_id, artifact_id)) => (Some(group_id), artifact_id),
                None => (None, name.as_str()),
            };
            if !is_safe_maven_coordinate_segment(artifact_id) {
                warn_rejected_value(
                    "is_safe_maven_coordinate_segment",
                    "maven package name completion item",
                    artifact_id,
                );
                return None;
            }
            if let Some(g) = group_id
                && !is_safe_maven_coordinate_segment(g)
            {
                warn_rejected_value(
                    "is_safe_maven_coordinate_segment",
                    "maven package name completion item",
                    g,
                );
                return None;
            }
            group_id.map_or_else(
                || format!("<artifactId>{artifact_id}</artifactId><version>{latest}</version>"),
                |group_id| format!(
                    "<groupId>{group_id}</groupId><artifactId>{artifact_id}</artifactId><version>{latest}</version>"
                ),
            )
        }
        EcosystemId::Gradle => format!("implementation(\"{name}:{latest}\")"),
        EcosystemId::Swift => {
            let url = metadata
                .repository()
                .map_or_else(|| format!("https://github.com/{name}"), str::to_string);
            if !is_safe_registry_url(&url) {
                warn_rejected_value(
                    "is_safe_registry_url",
                    "swift package name completion item",
                    &url,
                );
                return None;
            }
            if latest.is_empty() {
                format!(".package(url: \"{url}\")")
            } else {
                format!(".package(url: \"{url}\", from: \"{latest}\")")
            }
        }
        EcosystemId::NuGet => {
            format!("<PackageReference Include=\"{name}\" Version=\"{latest}\" />")
        }
        EcosystemId::Bundler => format!("gem \"{name}\", \"~> {latest}\""),
        EcosystemId::Deno => {
            // D11: the alias key is conventionally the bare name (scheme stripped); the
            // value is the full scheme-qualified specifier.
            let bare = name
                .as_str()
                .split_once(':')
                .map_or(name.as_str(), |(_, rest)| rest);
            // N5: an empty `latest` (a JSR search hit with no `latestVersion`) must not
            // insert a dangling `@^` with nothing after it — mirrors the Swift arm's
            // `latest.is_empty()` guard above.
            if latest.is_empty() {
                format!("\"{bare}\": \"{name}\"")
            } else {
                format!("\"{bare}\": \"{name}@^{latest}\"")
            }
        }
        // GHA's `search()` always returns `Ok(vec![])` (MVP scope — see
        // `deps-github-actions`'s registry docs), so this arm is unreachable in
        // practice today; it exists only to keep the match exhaustive (#118) and to
        // behave correctly if package-name search is ever added. The `owner/repo`
        // shape check is inlined rather than calling
        // `deps_github_actions::is_valid_github_identity` — that dependency is
        // feature-gated, while this match (on `EcosystemId`, not a per-feature type)
        // is compiled unconditionally.
        EcosystemId::GithubActions => {
            if !name.as_str().contains('/') {
                warn_rejected_value(
                    "owner/repo shape",
                    "github actions package name completion item",
                    name.as_str(),
                );
                return None;
            }
            if latest.is_empty() {
                name.to_string()
            } else {
                format!("{name}@{latest}")
            }
        }
    };

    // Build detail text
    let detail = if latest.is_empty() {
        None
    } else {
        Some(format!("Latest: {latest}"))
    };

    Some(CompletionItem {
        label: name.to_string(),
        kind: Some(CompletionItemKind::MODULE),
        detail,
        documentation: description
            .map(|d| tower_lsp_server::ls_types::Documentation::String(d.into())),
        insert_text: Some(insert_text),
        insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::DocumentState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use tower_lsp_server::ls_types::{
        Position, TextDocumentIdentifier, TextDocumentPositionParams,
    };

    /// Builds a `ServerState` whose `id`/`manifest_filename` ecosystem entry is
    /// overridden to route registry search through `registry`, so `fallback_completion`
    /// tests can observe (or forbid) a search call without hitting the network.
    fn mock_ecosystem_state(
        id: &'static str,
        manifest_filename: &'static str,
        registry: Arc<dyn deps_core::Registry>,
    ) -> ServerState {
        use deps_core::{
            DiagnosticMessages, DiagnosticPolicy, Ecosystem, EcosystemFormatter, OsvNaming,
            PackageNaming, PackageRendering, ParseResult, RequirementResolution, SourcePolicy,
        };
        use std::any::Any;
        use tower_lsp_server::ls_types::Uri;

        struct MockFormatter;
        impl PackageNaming for MockFormatter {}

        impl PackageRendering for MockFormatter {
            fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for MockFormatter {}

        impl DiagnosticMessages for MockFormatter {}

        impl DiagnosticPolicy for MockFormatter {}

        impl SourcePolicy for MockFormatter {}

        impl OsvNaming for MockFormatter {}

        struct MockEcosystem {
            id: &'static str,
            manifest_filename: &'static str,
            registry: Arc<dyn deps_core::Registry>,
        }
        impl deps_core::ecosystem::private::Sealed for MockEcosystem {}
        impl Ecosystem for MockEcosystem {
            fn id(&self) -> &'static str {
                self.id
            }
            fn display_name(&self) -> &'static str {
                self.id
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                std::slice::from_ref(&self.manifest_filename)
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a Uri,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn deps_core::Registry> {
                Arc::clone(&self.registry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &MockFormatter
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = ServerState::new();
        state.ecosystem_registry.register(Arc::new(MockEcosystem {
            id,
            manifest_filename,
            registry,
        }));
        state
    }

    /// Builds a `ServerState` whose `"cargo"` ecosystem entry is overridden to route
    /// registry search through `registry`, so `fallback_completion` tests can observe
    /// (or forbid) a search call without hitting the network.
    fn mock_cargo_state(registry: Arc<dyn deps_core::Registry>) -> ServerState {
        mock_ecosystem_state("cargo", "Cargo.toml", registry)
    }

    /// Same as [`mock_cargo_state`], but for the `"maven"` ecosystem.
    fn mock_maven_state(registry: Arc<dyn deps_core::Registry>) -> ServerState {
        mock_ecosystem_state("maven", "pom.xml", registry)
    }

    /// Same as [`mock_cargo_state`], but for the `"pypi"` ecosystem.
    fn mock_pypi_state(registry: Arc<dyn deps_core::Registry>) -> ServerState {
        mock_ecosystem_state("pypi", "pyproject.toml", registry)
    }

    #[tokio::test]
    async fn test_completion_returns_empty_for_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;
        // With cold start support, missing documents trigger background load and
        // return empty completions for the first request, collapsing to `None`.
        assert!(result.is_none());
    }

    /// #419 S1 regression, still required after #427: the document-not-loaded/
    /// load-failed early return never reaches `generate_completions` — there is no
    /// completion context yet to compute a precise per-call `is_incomplete` from
    /// (see [`Completions`](deps_core::completion::Completions)) — but it must still
    /// report `isIncomplete: true` for an ecosystem whose package-name search (the
    /// only kind `fallback_completion` could otherwise have produced) is truncated,
    /// via [`Ecosystem::package_search_is_incomplete`]. `None` serializes as LSP
    /// `null`, which carries no `isIncomplete` and would leave the client with
    /// nothing to invalidate on the next keystroke.
    #[tokio::test]
    async fn test_completion_missing_document_reports_incomplete_for_flagged_ecosystem() {
        use deps_core::completion::Completions;
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            DiagnosticMessages, DiagnosticPolicy, Ecosystem, EcosystemFormatter, Metadata,
            OsvNaming, PackageNaming, PackageRendering, ParseResult, Registry,
            RequirementResolution, SourcePolicy, Version,
        };
        use std::any::Any;
        use tower_lsp_server::ls_types::Uri;

        struct NoopRegistry;
        impl Registry for NoopRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct NoopFormatter;
        impl PackageNaming for NoopFormatter {}

        impl PackageRendering for NoopFormatter {
            fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for NoopFormatter {}

        impl DiagnosticMessages for NoopFormatter {}

        impl DiagnosticPolicy for NoopFormatter {}

        impl SourcePolicy for NoopFormatter {}

        impl OsvNaming for NoopFormatter {}

        /// Stands in for `PypiEcosystem`: overrides `package_search_is_incomplete`
        /// the same way, and `generate_completions` is deliberately `unimplemented!()`
        /// since this test never lets it run.
        struct IncompleteEcosystem;
        impl Sealed for IncompleteEcosystem {}
        impl Ecosystem for IncompleteEcosystem {
            fn id(&self) -> &'static str {
                "cargo"
            }
            fn display_name(&self) -> &'static str {
                "cargo"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &["Cargo.toml"]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a Uri,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &NoopFormatter
            }
            fn package_search_is_incomplete(&self) -> bool {
                true
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                Box::pin(async move { unimplemented!() })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = Arc::new(ServerState::new());
        state
            .ecosystem_registry
            .register(Arc::new(IncompleteEcosystem));
        // Deliberately never inserted into `state.documents` — the document-load
        // path below must time out/fail against a nonexistent file, exactly the
        // `test_completion_returns_empty_for_missing_document` shape.
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;
        match result {
            Some(CompletionResponse::List(list)) => {
                assert!(list.is_incomplete);
                assert!(list.items.is_empty());
            }
            other => panic!("expected List{{is_incomplete:true, items:[]}}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_completion_delegates_to_ecosystem() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let content = "[dependencies]\nserde = \"1.0\"".to_string();

        // Parse the manifest to get a proper parse result
        let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
        let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();

        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 9),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        // Should return Some or None based on ecosystem implementation
        // We don't test the actual completions here as that's ecosystem-specific
        let (client, config) = create_test_client_and_config();
        let _result = handle_completion(state, params, client, config).await;
        // Just verify it doesn't panic - actual completion logic is in ecosystem
    }

    /// #319 liveness regression: `handle_completion` must release the DashMap shard
    /// `Ref` on the document *before* entering the `COMPLETION_SEARCH_TIMEOUT`-bounded
    /// await, so a concurrent `documents.get_mut` on the same URI (e.g. a `didChange`)
    /// is never blocked behind an in-flight (or stuck) registry-backed search.
    ///
    /// `BlockingEcosystem::generate_completions` waits on a `Barrier` before blocking
    /// forever (`std::future::pending`), standing in for a registry call that never
    /// returns — the worst case for a shard `Ref` held across the search. The test
    /// only proceeds to race the writer once that future has demonstrably started
    /// executing (via the barrier), which — pre-fix — would still be *after* the old
    /// code's `let doc = state.get_document(uri)?;` acquisition but *before* its
    /// `drop(doc)`, since that drop ran only once the whole timeout resolved. A
    /// concurrent write racing here would previously deadlock against the `parking_lot`
    /// shard guard for the life of the (never-resolving) search; post-fix it must
    /// complete almost immediately, since the `Ref` was already dropped before the
    /// search was ever awaited.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_document_write_not_blocked_by_in_flight_completion_search() {
        use crate::test_utils::blocking_ecosystem::{
            BlockingEcosystem, BlockingHook, MockParseResult,
        };
        use deps_core::ParseResult;
        use tokio::sync::Barrier;

        let state = Arc::new(ServerState::new());
        let started = Arc::new(Barrier::new(2));
        state
            .ecosystem_registry
            .register(Arc::new(BlockingEcosystem {
                started: Arc::clone(&started),
                hook: BlockingHook::Completions,
            }));

        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let (client, config) = create_test_client_and_config();

        let completion_task = tokio::spawn({
            let state = Arc::clone(&state);
            let uri = uri.clone();
            async move {
                let params = CompletionParams {
                    text_document_position: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier { uri },
                        position: Position::new(1, 9),
                    },
                    work_done_progress_params: Default::default(),
                    partial_result_params: Default::default(),
                    context: None,
                };
                handle_completion(state, params, client, config).await
            }
        });

        // Block until `generate_completions` has actually started executing — i.e.
        // `handle_completion` has reached (and is now inside) the
        // `COMPLETION_SEARCH_TIMEOUT`-bounded await — before racing the writer below.
        started.wait().await;

        // Spawned onto its own task (rather than awaited inline) deliberately:
        // `DashMap::get_mut` blocks the OS thread synchronously on a `parking_lot`
        // lock, with no `.await` point of its own. Wrapping that blocking call
        // directly in `tokio::time::timeout` would not work — a `Future::poll` that
        // never returns can't be preempted by a sibling timer that only fires between
        // polls. Spawning it gives the *join* a real async yield point, so the
        // `timeout` below can race against it and fire even while the spawned task
        // sits blocked on the shard lock.
        let write_task = tokio::spawn({
            let state = Arc::clone(&state);
            let uri = uri.clone();
            async move {
                state.documents.get_mut(&uri).unwrap().set_loading();
            }
        });
        let write_result =
            tokio::time::timeout(std::time::Duration::from_millis(500), write_task).await;

        completion_task.abort();

        assert!(
            write_result.is_ok(),
            "#319 regression: a concurrent documents.get_mut on the same URI must not \
             block on an in-flight completion search — the DashMap shard Ref must be \
             dropped before the COMPLETION_SEARCH_TIMEOUT-bounded await, not after it"
        );
    }

    /// Issue #227 tester gap: `build_version_completion`'s `label_details`
    /// present/absent-when-`freshness.enabled`-toggles behavior is already unit-tested
    /// directly in `deps_core::completion` — this test covers the piece that isn't: that
    /// `handle_completion` (`completion.rs:47`) re-reads `config.freshness` on *every*
    /// call, so a `workspace/didChangeConfiguration`-driven config update (simulated here
    /// by writing directly to the shared `Arc<RwLock<DepsConfig>>`, exactly what
    /// `Backend::did_change_configuration` does) changes completion's age-suffix presence
    /// on the very next request, with no server restart and no re-opening the document.
    #[tokio::test]
    async fn test_completion_freshness_enabled_live_reload_changes_label_details_on_next_request() {
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            Dependency, DiagnosticMessages, DiagnosticPolicy, Ecosystem, EcosystemFormatter,
            Metadata, OsvNaming, PackageNaming, PackageRendering, ParseResult, Registry,
            RequirementResolution, SourcePolicy, Version,
        };
        use std::any::Any;
        use std::path::Path;
        use tower_lsp_server::ls_types::{CompletionItemLabelDetails, Uri};

        struct NoopRegistry;
        impl Registry for NoopRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct NoopFormatter;
        impl PackageNaming for NoopFormatter {}

        impl PackageRendering for NoopFormatter {
            fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for NoopFormatter {}

        impl DiagnosticMessages for NoopFormatter {}

        impl DiagnosticPolicy for NoopFormatter {}

        impl SourcePolicy for NoopFormatter {}

        impl OsvNaming for NoopFormatter {}

        /// Stands in for a real ecosystem's `generate_completions`, echoing whatever
        /// `freshness.enabled` it was called with into `label_details` — exactly the
        /// signal real ecosystems derive from `build_version_completion`, without
        /// needing a real registry fetch or parsed manifest.
        struct FreshnessEchoEcosystem;
        impl Sealed for FreshnessEchoEcosystem {}
        impl Ecosystem for FreshnessEchoEcosystem {
            fn id(&self) -> &'static str {
                "cargo"
            }
            fn display_name(&self) -> &'static str {
                "cargo"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &["Cargo.toml"]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a Uri,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &NoopFormatter
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions>
            {
                Box::pin(async move {
                    vec![CompletionItem {
                        label: "1.0.0".to_string(),
                        kind: Some(CompletionItemKind::VALUE),
                        label_details: freshness.enabled.then(|| CompletionItemLabelDetails {
                            detail: Some("  1 hour ago".to_string()),
                            description: None,
                        }),
                        ..Default::default()
                    }]
                    .into()
                })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            uri: Uri,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = Arc::new(ServerState::new());
        // Overwrites the real Cargo ecosystem for this state instance only.
        state
            .ecosystem_registry
            .register(Arc::new(FreshnessEchoEcosystem));
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let params = || CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let (client, config) = create_test_client_and_config();
        assert!(
            config.read().await.freshness.enabled,
            "default config ships freshness enabled"
        );

        let before = handle_completion(
            Arc::clone(&state),
            params(),
            client.clone(),
            Arc::clone(&config),
        )
        .await
        .expect("completion response");
        let CompletionResponse::Array(items) = before else {
            panic!("expected an array response");
        };
        assert!(
            items[0].label_details.is_some(),
            "freshness enabled by default: label_details must be present"
        );

        // Exactly what `Backend::did_change_configuration` does to the stored config —
        // no document reload, no server restart.
        config.write().await.freshness.enabled = false;

        let after = handle_completion(state, params(), client, config)
            .await
            .expect("completion response");
        let CompletionResponse::Array(items) = after else {
            panic!("expected an array response");
        };
        assert!(
            items[0].label_details.is_none(),
            "freshness disabled via live-reload: label_details must disappear on the very \
             next completion request"
        );
    }

    #[test]
    fn test_is_in_toml_dependencies_basic() {
        let content = r#"
[package]
name = "test"

[dependencies]
serde
"#;
        assert!(is_in_toml_dependencies(content, 5));
        assert!(!is_in_toml_dependencies(content, 1));
    }

    #[test]
    fn test_is_in_toml_dependencies_dev_deps() {
        let content = r"
[dev-dependencies]
tokio
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_build_deps() {
        let content = r"
[build-dependencies]
cc
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_project_deps() {
        let content = r"
[project.dependencies]
requests
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_workspace_deps() {
        let content = r#"
[workspace.dependencies]
serde = "1.0"
"#;
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_target_specific() {
        let content = r"
[target.'cfg(windows)'.dependencies]
winapi
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_wrong_section() {
        let content = r#"
[package]
name = "test"

[profile.release]
opt-level = 3
"#;
        assert!(!is_in_toml_dependencies(content, 2));
        assert!(!is_in_toml_dependencies(content, 5));
    }

    #[test]
    fn test_is_in_toml_dependencies_multiple_sections() {
        let content = r#"
[dependencies]
serde = "1.0"

[dev-dependencies]
tokio
"#;
        assert!(is_in_toml_dependencies(content, 2));
        assert!(is_in_toml_dependencies(content, 5));
    }

    const NPM_KEYS: &[&str] = &[
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ];

    #[test]
    fn test_is_in_json_dependencies_basic() {
        let content = r#"{
  "name": "test",
  "dependencies": {
    "express"
  }
}"#;
        assert!(is_in_json_dependencies(content, 3, NPM_KEYS));
        assert!(!is_in_json_dependencies(content, 1, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_dev_deps() {
        let content = r#"{
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_peer_deps() {
        let content = r#"{
  "peerDependencies": {
    "react"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_optional_deps() {
        let content = r#"{
  "optionalDependencies": {
    "fsevents": "^2.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_outside_section() {
        let content = r#"{
  "name": "test",
  "dependencies": {
    "express": "^4.0.0"
  },
  "scripts": {
    "start": "node index.js"
  }
}"#;
        assert!(is_in_json_dependencies(content, 3, NPM_KEYS));
        assert!(!is_in_json_dependencies(content, 6, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_nested_braces() {
        let content = r#"{
  "dependencies": {
    "package": "1.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_custom_keys() {
        let content = r#"{
  "require": {
    "monolog/monolog": "^2.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^9.0"
  }
}"#;
        assert!(is_in_json_dependencies(
            content,
            2,
            &["require", "require-dev"]
        ));
        assert!(is_in_json_dependencies(
            content,
            5,
            &["require", "require-dev"]
        ));
    }

    #[test]
    fn test_is_in_dependencies_section_cargo() {
        let content = r"
[dependencies]
serde
";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Cargo));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::Cargo));
    }

    #[test]
    fn test_is_in_dependencies_section_pypi() {
        let content = r"
[project.dependencies]
requests
";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Pypi));
    }

    /// #390 root cause 1: real PEP 621 files never write a literal
    /// `[project.dependencies]` header — the primary dependency list is a
    /// `dependencies = [...]` array under `[project]`.
    #[test]
    fn test_is_in_dependencies_section_pypi_project_array_no_literal_header() {
        let content = "[project]\nname = \"myapp\"\nversion = \"0.1.0\"\ndependencies = [\n    \"requests>=2.31.0\",\n    \"flas\n]\n";
        // Unterminated entry line ("flas), mid-array.
        assert!(is_in_dependencies_section(content, 5, EcosystemId::Pypi));
        // A completed entry line.
        assert!(is_in_dependencies_section(content, 4, EcosystemId::Pypi));
        // Unrelated `[project]` keys must not be treated as inside the array.
        assert!(!is_in_dependencies_section(content, 1, EcosystemId::Pypi));
        assert!(!is_in_dependencies_section(content, 2, EcosystemId::Pypi));
        // The `[project]` header line itself is not "inside" the array.
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::Pypi));
    }

    #[test]
    fn test_is_in_dependencies_section_pypi_project_array_single_line() {
        let content = "[project]\ndependencies = [\"requests>=2.0.0\"]\n";
        assert!(is_in_dependencies_section(content, 1, EcosystemId::Pypi));
    }

    /// A `dependencies = [...]` array under a table other than `[project]` (e.g. an
    /// optional-dependencies group using the same key name) must not be picked up
    /// by the `[project]`-scoped array scan.
    #[test]
    fn test_is_in_dependencies_section_pypi_project_array_scoped_to_project_table() {
        let content = "[tool.other]\ndependencies = [\n    \"foo\n]\n";
        assert!(!is_in_dependencies_section(content, 2, EcosystemId::Pypi));
    }

    /// #390 C2: an unbalanced `[` inside a still-typed extras spec (`"uvicorn[stan`,
    /// common real syntax like `celery[redis]`) must not permanently desync the
    /// bracket-depth counter. A later, real table header is an unambiguous resync
    /// point (TOML forbids a header inside an array), so lines under it must not be
    /// misreported as still inside the dependencies array.
    #[test]
    fn test_is_in_dependencies_section_pypi_project_array_resyncs_after_unbalanced_extras_bracket()
    {
        let content = "[project]\ndependencies = [\n    \"uvicorn[stan\n]\n\n[tool.pytest.ini_options]\naddopts = \"-v\"\n";
        // Mid-typing the extras spec: still correctly inside the array.
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Pypi));
        // A line under the unrelated later table must not be swept in by the
        // desynced counter.
        assert!(!is_in_dependencies_section(content, 6, EcosystemId::Pypi));
    }

    /// #390 C2: a `#` comment containing `[` inside the array (e.g. `# pinned per
    /// [PEP 621`) must not be counted as a real bracket — the comment is stripped
    /// before depth tracking, so the array still closes at its real `]`.
    #[test]
    fn test_is_in_dependencies_section_pypi_project_array_ignores_bracket_in_comment() {
        let content = "[project]\ndependencies = [\n    \"requests>=2.0.0\",  # pinned per [PEP 621\n    \"flas\n]\nrequires-python = \">=3.9\"\n";
        // Still inside the array on the unterminated entry.
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Pypi));
        // The array has closed by the time an unrelated `[project]` key follows.
        assert!(!is_in_dependencies_section(content, 5, EcosystemId::Pypi));
    }

    /// #390 C3: a trailing comment on the `[project]` header itself (ordinary TOML)
    /// must not make the whole array-detection scan inert.
    #[test]
    fn test_is_in_dependencies_section_pypi_project_header_with_trailing_comment() {
        let content = "[project]  # main metadata\ndependencies = [\n    \"flas\n]\n";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Pypi));
    }

    /// #390 C4: a commented non-`[project]` header must correctly clear `in_project`
    /// (fixed for free by C3's comment stripping) — a later table's own
    /// `dependencies = [...]` array must not be mistaken for PEP 621's.
    #[test]
    fn test_is_in_dependencies_section_pypi_project_state_cleared_by_commented_other_header() {
        let content = "[project]\nname = \"x\"\n\n[tool.hatch.envs.default] # test env\ndependencies = [\n    \"other\n]\n";
        assert!(!is_in_dependencies_section(content, 5, EcosystemId::Pypi));
    }

    #[test]
    fn test_is_in_dependencies_section_npm() {
        let content = r#"{
  "dependencies": {
    "express"
  }
}"#;
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Npm));
    }

    #[test]
    fn test_is_in_dependencies_section_composer() {
        let content = r#"{
  "require": {
    "monolog/monolog": "^2.0"
  },
  "scripts": {
    "test": "phpunit"
  }
}"#;
        assert!(is_in_dependencies_section(
            content,
            2,
            EcosystemId::Composer
        ));
        assert!(!is_in_dependencies_section(
            content,
            5,
            EcosystemId::Composer
        ));
    }

    #[test]
    fn test_is_in_dependencies_section_maven() {
        let content = r"
<project>
  <dependencies>
    <dependency></dependency>
  </dependencies>
</project>
";
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Maven));
        assert!(!is_in_dependencies_section(content, 1, EcosystemId::Maven));
    }

    #[test]
    fn test_is_in_dependencies_section_maven_single_line() {
        let content = "<project><dependencies></dependencies></project>\n";
        assert!(is_in_dependencies_section(content, 0, EcosystemId::Maven));
    }

    #[test]
    fn test_is_in_dependencies_section_maven_attributed_tag() {
        let content = r#"
<project>
  <dependencies xmlns="http://maven.apache.org/POM/4.0.0">
    <dependency></dependency>
  </dependencies>
</project>
"#;
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Maven));
    }

    #[test]
    fn test_is_in_dependencies_section_maven_no_false_positive_on_longer_tag_name() {
        let content = r"
<project>
  <dependencyManagement>
    <dependencies>
      <dependency></dependency>
    </dependencies>
  </dependencyManagement>
</project>
";
        // Line 2 opens `<dependencyManagement>`, not `<dependencies>` — must not match.
        assert!(!is_in_dependencies_section(content, 2, EcosystemId::Maven));
        // Line 4 is genuinely inside the nested `<dependencies>` block.
        assert!(is_in_dependencies_section(content, 4, EcosystemId::Maven));
    }

    #[test]
    fn test_is_in_dependencies_section_go_single_line() {
        let content = "module example.com/myapp\n\nrequire github.com/gin-gonic/gin v1.9.1\n";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Go));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::Go));
    }

    #[test]
    fn test_is_in_dependencies_section_go_block() {
        let content =
            "module example.com/myapp\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Go));
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Go));
        assert!(!is_in_dependencies_section(content, 4, EcosystemId::Go));
    }

    #[test]
    fn test_is_in_dependencies_section_dart() {
        let content =
            "name: myapp\ndependencies:\n  http: ^1.0.0\nenvironment:\n  sdk: '>=3.0.0'\n";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Dart));
        assert!(!is_in_dependencies_section(content, 4, EcosystemId::Dart));
    }

    #[test]
    fn test_is_in_dependencies_section_dart_column_zero_comment() {
        // A column-0 `#` comment inside a section must not read as a new top-level
        // key and reset `in_dependencies` to false.
        let content = "name: myapp\ndependencies:\n# a comment\n  http: ^1.0.0\n";
        assert!(is_in_dependencies_section(content, 2, EcosystemId::Dart));
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Dart));
    }

    #[test]
    fn test_is_in_dependencies_section_deno() {
        let content = r#"{
  "name": "test",
  "imports": {
    "@std/fs": "jsr:@std/fs@^1.0"
  }
}"#;
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Deno));
        assert!(!is_in_dependencies_section(content, 1, EcosystemId::Deno));
    }

    #[test]
    fn test_is_in_dependencies_section_no_raw_text_boundary_ecosystems() {
        // No existing raw-text section boundary: `false` preserves pre-fix behavior
        // (fallback completion disabled) rather than risking spurious registry
        // searches on arbitrary lines. See the TODO comments in
        // `is_in_dependencies_section` for the per-ecosystem rationale.
        let content = "anything at all\n";
        assert!(!is_in_dependencies_section(
            content,
            0,
            EcosystemId::Bundler
        ));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::Swift));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::Gradle));
        assert!(!is_in_dependencies_section(content, 0, EcosystemId::NuGet));
    }

    #[test]
    fn test_create_package_completion_item_cargo() {
        struct MockMetadata {
            name: deps_core::PackageName,
        }
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &deps_core::PackageName {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                Some("A serialization framework")
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &deps_core::ConcreteVersion {
                static VERSION: std::sync::LazyLock<deps_core::ConcreteVersion> =
                    std::sync::LazyLock::new(|| deps_core::ConcreteVersion::new("1.0.214"));
                &VERSION
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata {
            name: deps_core::PackageName::new("serde"),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Cargo).unwrap();

        assert_eq!(item.label, "serde");
        assert_eq!(item.kind, Some(CompletionItemKind::MODULE));
        assert_eq!(item.detail, Some("Latest: 1.0.214".to_string()));
        assert_eq!(
            item.insert_text,
            Some("\"serde\" = \"1.0.214\"".to_string())
        );
        assert_eq!(item.insert_text_format, Some(InsertTextFormat::PLAIN_TEXT));
    }

    #[test]
    fn test_create_package_completion_item_npm() {
        struct MockMetadata {
            name: deps_core::PackageName,
        }
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &deps_core::PackageName {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                Some("Fast web framework")
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &deps_core::ConcreteVersion {
                static VERSION: std::sync::LazyLock<deps_core::ConcreteVersion> =
                    std::sync::LazyLock::new(|| deps_core::ConcreteVersion::new("4.18.2"));
                &VERSION
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata {
            name: deps_core::PackageName::new("express"),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Npm).unwrap();

        assert_eq!(item.label, "express");
        assert_eq!(
            item.insert_text,
            Some("\"express\": \"^4.18.2\"".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_pypi() {
        struct MockMetadata {
            name: deps_core::PackageName,
        }
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &deps_core::PackageName {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                None
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &deps_core::ConcreteVersion {
                static VERSION: std::sync::LazyLock<deps_core::ConcreteVersion> =
                    std::sync::LazyLock::new(|| deps_core::ConcreteVersion::new("2.31.0"));
                &VERSION
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata {
            name: deps_core::PackageName::new("requests"),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Pypi).unwrap();

        assert_eq!(item.label, "requests");
        // #390 C1: both real PEP 621 shapes (`dependencies = [...]` and an
        // `[project.optional-dependencies]` group) are TOML array elements, so the
        // surrounding quotes already exist in the manifest — a bare name matches
        // `build_package_completion`'s primary-path insert for PyPI at the same
        // cursor position, unlike Cargo's key=value table-entry shape.
        assert_eq!(item.insert_text, Some("requests".to_string()));
    }

    struct MockMetadata {
        name: deps_core::PackageName,
        repository: Option<&'static str>,
        latest_version: deps_core::ConcreteVersion,
    }
    impl deps_core::Metadata for MockMetadata {
        fn name(&self) -> &deps_core::PackageName {
            &self.name
        }
        fn description(&self) -> Option<&str> {
            None
        }
        fn repository(&self) -> Option<&str> {
            self.repository
        }
        fn documentation(&self) -> Option<&str> {
            None
        }
        fn latest_version(&self) -> &deps_core::ConcreteVersion {
            &self.latest_version
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn test_create_package_completion_item_cargo_dotted_name_quotes_toml_key() {
        // S1: a bare TOML key containing `.` (legal here — real crate names can use
        // it) expands into a nested table instead of a dependency entry
        // (`serde.path = "vendor"` parses as `serde = { path = "vendor" }`). Quoting
        // the key keeps the dotted name a single dependency entry regardless of
        // ecosystem-legit or attacker-supplied intent. Cargo only: after #390 C1,
        // PyPI no longer emits a TOML key at all (see
        // `test_create_package_completion_item_pypi_dotted_name_stays_bare_string`).
        let meta = MockMetadata {
            name: deps_core::PackageName::new("some.crate"),
            repository: None,
            latest_version: "6.1".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Cargo).unwrap();

        assert_eq!(
            item.insert_text,
            Some("\"some.crate\" = \"6.1\"".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_pypi_dotted_name_stays_bare_string() {
        // A dotted PyPI name (`zope.interface`) has no TOML-key-injection meaning
        // once the insert is a bare array-element string, unlike Cargo's key=value
        // shape (see `test_create_package_completion_item_cargo_dotted_name_quotes_toml_key`).
        let meta = MockMetadata {
            name: deps_core::PackageName::new("zope.interface"),
            repository: None,
            latest_version: "6.1".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Pypi).unwrap();

        assert_eq!(item.insert_text, Some("zope.interface".to_string()));
    }

    #[test]
    fn test_create_package_completion_item_maven_group_artifact() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("org.apache.commons:commons-lang3"),
            repository: None,
            latest_version: "3.14.0".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Maven).unwrap();

        assert_eq!(
            item.insert_text,
            Some(
                "<groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>\
                 <version>3.14.0</version>"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_create_package_completion_item_maven_no_colon() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("commons-lang3"),
            repository: None,
            latest_version: "3.14.0".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Maven).unwrap();

        assert_eq!(
            item.insert_text,
            Some("<artifactId>commons-lang3</artifactId><version>3.14.0</version>".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_maven_rejects_xml_breakout_artifact_id() {
        // S1: the identical breakout `build_field_completion` (deps-maven) now guards
        // against must also be rejected on this fallback-search path, not just the
        // primary XML-context path.
        let meta = MockMetadata {
            name: deps_core::PackageName::new(
                "org.apache.commons:commons</artifactId><parent><groupId>evil",
            ),
            repository: None,
            latest_version: "3.14.0".into(),
        };

        assert!(create_package_completion_item(&meta, EcosystemId::Maven).is_none());
    }

    #[test]
    fn test_create_package_completion_item_maven_rejects_xml_breakout_group_id() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("org.evil</groupId><parent>:commons-lang3"),
            repository: None,
            latest_version: "3.14.0".into(),
        };

        assert!(create_package_completion_item(&meta, EcosystemId::Maven).is_none());
    }

    #[test]
    fn test_create_package_completion_item_maven_no_colon_rejects_xml_breakout() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("commons</artifactId><parent>"),
            repository: None,
            latest_version: "3.14.0".into(),
        };

        assert!(create_package_completion_item(&meta, EcosystemId::Maven).is_none());
    }

    #[test]
    fn test_create_package_completion_item_rejects_unsafe_latest_version() {
        // S2: `latest` is interpolated into every ecosystem's insert_text but was
        // previously never validated on this path (unlike the other five `TextEdit`
        // producers `is_safe_version_string` guards).
        let meta = MockMetadata {
            name: deps_core::PackageName::new("serde"),
            repository: None,
            latest_version: "1.0.0\", git = \"https://evil".into(),
        };

        assert!(create_package_completion_item(&meta, EcosystemId::Cargo).is_none());
    }

    #[test]
    fn test_create_package_completion_item_swift_with_repository() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio"),
            repository: Some("https://github.com/apple/swift-nio"),
            latest_version: "2.62.0".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Swift).unwrap();

        assert_eq!(
            item.insert_text,
            Some(
                ".package(url: \"https://github.com/apple/swift-nio\", from: \"2.62.0\")"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_create_package_completion_item_swift_empty_latest_omits_from_clause() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio"),
            repository: Some("https://github.com/apple/swift-nio"),
            latest_version: "".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Swift).unwrap();

        assert_eq!(
            item.insert_text,
            Some(".package(url: \"https://github.com/apple/swift-nio\")".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_swift_no_repository_falls_back_to_name() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio"),
            repository: None,
            latest_version: "2.62.0".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Swift).unwrap();

        assert_eq!(
            item.insert_text,
            Some(
                ".package(url: \"https://github.com/apple/swift-nio\", from: \"2.62.0\")"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_create_package_completion_item_swift_rejects_string_literal_breakout_repository() {
        // S1: the identical breakout `build_url_completion` (deps-swift) now guards
        // against must also be rejected on this fallback-search path.
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio"),
            repository: Some(
                "https://evil.example\", .exact(\"1.0.0\")), .package(url: \"https://real",
            ),
            latest_version: "2.62.0".into(),
        };

        assert!(create_package_completion_item(&meta, EcosystemId::Swift).is_none());
    }

    #[test]
    fn test_create_package_completion_item_swift_rejects_malicious_name_in_fallback_url() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio\", .exact(\"1\")) //"),
            repository: None,
            latest_version: "2.62.0".into(),
        };

        assert!(create_package_completion_item(&meta, EcosystemId::Swift).is_none());
    }

    #[test]
    fn test_create_package_completion_item_swift_rejects_malicious_name_even_with_repository() {
        // M4: the upfront `is_safe_package_name` gate runs before the match arm, so it
        // now also filters names that never reach `insert_text` on this path — when
        // `repository` is provided, the name-derived fallback-URL branch doesn't run
        // at all. Intentional: a registry response with a malicious name is
        // untrustworthy as a whole, not just in the fields the formatter happens to
        // interpolate.
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio\", .exact(\"1\")) //"),
            repository: Some("https://github.com/apple/swift-nio"),
            latest_version: "2.62.0".into(),
        };

        assert!(create_package_completion_item(&meta, EcosystemId::Swift).is_none());
    }

    #[test]
    fn test_create_package_completion_item_deno_strips_scheme_for_alias_key() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("jsr:@std/fs"),
            repository: None,
            latest_version: "1.0.24".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Deno).unwrap();

        assert_eq!(
            item.insert_text,
            Some("\"@std/fs\": \"jsr:@std/fs@^1.0.24\"".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_deno_npm_scheme() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("npm:react"),
            repository: None,
            latest_version: "18.3.1".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Deno).unwrap();

        assert_eq!(
            item.insert_text,
            Some("\"react\": \"npm:react@^18.3.1\"".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_deno_empty_latest_omits_version_clause() {
        // N5: a JSR search hit lacking `latestVersion` must not insert a dangling `@^`.
        let meta = MockMetadata {
            name: deps_core::PackageName::new("jsr:@std/fs"),
            repository: None,
            latest_version: "".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Deno).unwrap();

        assert_eq!(
            item.insert_text,
            Some("\"@std/fs\": \"jsr:@std/fs\"".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_composer() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("monolog/monolog"),
            repository: None,
            latest_version: "3.5.0".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Composer).unwrap();

        assert_eq!(
            item.insert_text,
            Some("\"monolog/monolog\": \"^3.5.0\"".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_go() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("github.com/stretchr/testify"),
            repository: None,
            latest_version: "v1.9.0".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Go).unwrap();

        assert_eq!(
            item.insert_text,
            Some("github.com/stretchr/testify v1.9.0".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_dart() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("path"),
            repository: None,
            latest_version: "1.9.0".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Dart).unwrap();

        assert_eq!(item.insert_text, Some("\"path\": ^1.9.0".to_string()));
    }

    #[test]
    fn test_create_package_completion_item_gradle() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("org.apache.commons:commons-lang3"),
            repository: None,
            latest_version: "3.14.0".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Gradle).unwrap();

        assert_eq!(
            item.insert_text,
            Some("implementation(\"org.apache.commons:commons-lang3:3.14.0\")".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_nuget() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("Newtonsoft.Json"),
            repository: None,
            latest_version: "13.0.3".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::NuGet).unwrap();

        assert_eq!(
            item.insert_text,
            Some("<PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_bundler() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("rails"),
            repository: None,
            latest_version: "7.1.3".into(),
        };
        let item = create_package_completion_item(&meta, EcosystemId::Bundler).unwrap();

        assert_eq!(
            item.insert_text,
            Some("gem \"rails\", \"~> 7.1.3\"".to_string())
        );
    }

    #[test]
    fn test_create_package_completion_item_rejects_malicious_name_toml_json_breakout() {
        // Issue #336: a registry-reported name breaking out of a TOML/JSON/XML/YAML/
        // Kotlin-Groovy-DSL/Ruby string literal must be rejected for every ecosystem
        // that interpolates it raw, not just Maven/Swift.
        let evil = deps_core::PackageName::new("evil\"\nbackdoor = \"9.9.9");
        for ecosystem in [
            EcosystemId::Cargo,
            EcosystemId::Pypi,
            EcosystemId::Npm,
            EcosystemId::Composer,
            EcosystemId::Go,
            EcosystemId::Dart,
            EcosystemId::Gradle,
            EcosystemId::NuGet,
            EcosystemId::Bundler,
            EcosystemId::Deno,
        ] {
            let meta = MockMetadata {
                name: evil.clone(),
                repository: None,
                latest_version: "9.9.9".into(),
            };
            assert!(
                create_package_completion_item(&meta, ecosystem).is_none(),
                "expected {ecosystem:?} to reject the malicious name"
            );
        }
    }

    #[tokio::test]
    async fn test_fallback_triggered_when_parse_fails() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        // Malformed content that will fail to parse
        let content = r"[dependencies]
ser"
        .to_string();

        // Create document without parse result (simulating parse failure)
        let doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, content.clone());
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 3), // After "ser"
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        // Should use fallback completion (won't panic, may return empty if search fails)
        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;
        // Just verify it doesn't panic - actual results depend on registry availability
        // In a real scenario with mocked registry, we'd verify it returns search results
        drop(result);
    }

    #[test]
    fn test_fallback_rejects_single_char_prefix() {
        let content = r"
[dependencies]
s
";

        // Extract prefix at position (1 char)
        let line = content.lines().nth(2).unwrap();
        let prefix = extract_prefix(line, 1, EcosystemId::Cargo);

        // Should reject single char (< 2 chars requirement)
        assert_eq!(prefix.len(), 1);
        assert!(prefix.chars().count() < 2);
    }

    #[tokio::test]
    async fn test_fallback_completion_rejects_single_cjk_char_prefix() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        // A single CJK character is 3 bytes, so byte-length guard `prefix.len() < 2`
        // wrongly let it reach the registry; `search` panics here so the test fails
        // loudly if the guard regresses instead of silently returning empty either way.
        struct PanicsIfSearchedRegistry;
        impl Registry for PanicsIfSearchedRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                panic!("guard must short-circuit before reaching registry search");
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = mock_cargo_state(Arc::new(PanicsIfSearchedRegistry));
        let content = "[dependencies]\n日\n";
        let position = Position::new(1, 1); // after the single CJK char

        let items = fallback_completion(&state, EcosystemId::Cargo, position, content).await;
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn test_fallback_completion_passes_two_char_prefixes_to_search() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct MockMetadata {
            name: deps_core::PackageName,
        }
        impl Metadata for MockMetadata {
            fn name(&self) -> &deps_core::PackageName {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                None
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &deps_core::ConcreteVersion {
                static VERSION: std::sync::LazyLock<deps_core::ConcreteVersion> =
                    std::sync::LazyLock::new(|| deps_core::ConcreteVersion::new("1.0.0"));
                &VERSION
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct StubRegistry;
        impl Registry for StubRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockMetadata {
                        name: deps_core::PackageName::new("serde"),
                    }) as Box<dyn Metadata>])
                })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        // Two CJK characters: byte count (6) and char count (2) agree, so this was
        // never affected by the bug, but it must keep passing through to search.
        let cjk_state = mock_cargo_state(Arc::new(StubRegistry));
        let cjk_items = fallback_completion(
            &cjk_state,
            EcosystemId::Cargo,
            Position::new(1, 2),
            "[dependencies]\n日本\n",
        )
        .await;
        assert_eq!(cjk_items.len(), 1);
        assert_eq!(cjk_items[0].label, "serde");

        // Two ASCII chars: regression check that the char-count guard didn't change
        // behavior for the common case.
        let ascii_state = mock_cargo_state(Arc::new(StubRegistry));
        let ascii_items = fallback_completion(
            &ascii_state,
            EcosystemId::Cargo,
            Position::new(1, 2),
            "[dependencies]\nse\n",
        )
        .await;
        assert_eq!(ascii_items.len(), 1);
        assert_eq!(ascii_items[0].label, "serde");
    }

    #[test]
    fn test_extract_prefix_strips_leading_xml_tag_for_maven() {
        // Cursor right after "gua" in `<artifactId>gua`.
        assert_eq!(
            extract_prefix("  <artifactId>gua", 17, EcosystemId::Maven),
            "gua"
        );
    }

    #[test]
    fn test_extract_prefix_maven_unclosed_tag_is_unchanged() {
        // Cursor mid-tag-name, before `>` exists yet: nothing to strip.
        assert_eq!(
            extract_prefix("  <artifactId", 13, EcosystemId::Maven),
            "<artifactId"
        );
    }

    /// #282 S1 (second critic round): a first-`>`-based strip diverges from
    /// `MavenEcosystem::detect_xml_context`'s own `rfind`-based (last-tag) lookup
    /// whenever more than one tag precedes the cursor on a line — the first `>` here
    /// sits inside `<groupId>`, well short of the real value. Mirrored by
    /// `deps-maven`'s `test_detect_xml_context_compact_multi_tag_line_matches_completion_extractor`
    /// using the identical line/cursor position.
    #[test]
    fn test_extract_prefix_maven_strips_last_tag_not_first() {
        let line = "    <dependency><groupId>com.google.guava</groupId><artifactId>gua";
        assert_eq!(extract_prefix(line, 66, EcosystemId::Maven), "gua");
    }

    /// #282 S1 (second critic round): cursor right after a fully closed tag must yield
    /// an empty prefix (rejected by `fallback_completion`'s existing empty-prefix
    /// guard), matching `detect_xml_context`'s own "no context" outcome for the same
    /// position (its `between.contains("</")` guard rejects it too) instead of sending
    /// `solrsearch` a markup-polluted live query for an ordinary explicit-invoke
    /// position. Mirrored by `deps-maven`'s
    /// `test_detect_xml_context_after_closed_tag_yields_no_context` using the identical
    /// line/cursor position.
    #[test]
    fn test_extract_prefix_maven_after_closed_tag_is_empty() {
        let line = "    <artifactId>guava</artifactId>";
        assert_eq!(extract_prefix(line, 34, EcosystemId::Maven), "");
    }

    /// #282 C1 regression guard: the primary completion path (`MavenEcosystem::
    /// detect_xml_context`) searches the registry for the bare tag value (`"gua"` for
    /// `<artifactId>gua`), not the raw line text. Before this fix, `fallback_completion`
    /// searched for `"<artifactId>gua"` instead — a different query string that broke
    /// both search relevance and any per-query dedup/cache mechanism (the fast-failure
    /// amplification fix in `deps-maven`) keyed on the query matching across the
    /// primary and fallback paths for the same cursor position.
    #[tokio::test]
    async fn test_fallback_completion_maven_query_matches_tag_value() {
        use deps_core::{Metadata, Registry};
        use std::any::Any;
        use std::sync::Mutex;

        struct CapturingRegistry {
            captured_query: Mutex<Option<String>>,
        }
        impl Registry for CapturingRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::Result<Vec<Box<dyn deps_core::Version>>>,
            > {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::Result<Option<Box<dyn deps_core::Version>>>,
            > {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                *self.captured_query.lock().unwrap() = Some(query.to_string());
                Box::pin(async move { Ok(vec![]) })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry = Arc::new(CapturingRegistry {
            captured_query: Mutex::new(None),
        });
        let state = mock_maven_state(Arc::clone(&registry) as Arc<dyn Registry>);

        let content = "<dependencies>\n  <dependency>\n    <artifactId>gua\n";
        fallback_completion(&state, EcosystemId::Maven, Position::new(2, 19), content).await;

        assert_eq!(
            registry.captured_query.lock().unwrap().as_deref(),
            Some("gua")
        );
    }

    /// #390 (C5, tester Gap 1 / critic): a direct end-to-end proof, through
    /// `fallback_completion` itself rather than `is_in_dependencies_section` and
    /// `extract_prefix` in isolation, that the two root-cause fixes actually compose.
    /// Verbatim issue repro step 1: an unterminated entry inside the primary
    /// `dependencies = [...]` array (no literal `[project.dependencies]` header
    /// anywhere in the fixture) — the registry must see `flas`, not `"flas`.
    #[tokio::test]
    async fn test_fallback_completion_pypi_project_array_query_has_no_leaked_quote() {
        use deps_core::{Metadata, Registry};
        use std::any::Any;
        use std::sync::Mutex;

        struct CapturingRegistry {
            captured_query: Mutex<Option<String>>,
        }
        impl Registry for CapturingRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::Result<Vec<Box<dyn deps_core::Version>>>,
            > {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::Result<Option<Box<dyn deps_core::Version>>>,
            > {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                *self.captured_query.lock().unwrap() = Some(query.to_string());
                Box::pin(async move { Ok(vec![]) })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry = Arc::new(CapturingRegistry {
            captured_query: Mutex::new(None),
        });
        let state = mock_pypi_state(Arc::clone(&registry) as Arc<dyn Registry>);

        let content = "[project]\nname = \"myapp\"\nversion = \"0.1.0\"\ndependencies = [\n    \"requests>=2.31.0\",\n    \"flas\n]\n";
        fallback_completion(&state, EcosystemId::Pypi, Position::new(5, 9), content).await;

        assert_eq!(
            registry.captured_query.lock().unwrap().as_deref(),
            Some("flas")
        );
    }

    /// #390 (C5, tester Gap 1): the one PEP 621 shape that legitimately uses a
    /// section header (`[project.optional-dependencies]`) exercised through the real
    /// `is_in_dependencies_section`/`extract_prefix` composition, not just
    /// `is_in_toml_dependencies`'s header match in isolation — the existing
    /// `test_is_in_dependencies_section_pypi` only covers the literal
    /// `[project.dependencies]` header this fix's own docs say never occurs in real
    /// files.
    #[test]
    fn test_is_in_dependencies_section_and_extract_prefix_pypi_optional_dependencies_group() {
        let content = "[project.optional-dependencies]\ndev = [\n    \"pytest\",\n    \"flas\n]\n";
        assert!(is_in_dependencies_section(content, 3, EcosystemId::Pypi));

        let line = content.lines().nth(3).unwrap();
        assert_eq!(
            extract_prefix(line, line.len() as u32, EcosystemId::Pypi),
            "flas"
        );
    }

    #[test]
    fn test_fallback_rejects_prefix_with_equals() {
        let content = r#"
[dependencies]
serde = "1.0"
"#;

        // Extract prefix at position (contains '=')
        let line = content.lines().nth(2).unwrap();
        let prefix = extract_prefix(line, 12, EcosystemId::Cargo); // "serde = \"1.0"

        // Should reject prefix containing '='
        assert!(prefix.contains('='));
    }

    #[test]
    fn test_prefix_extraction_cursor_beyond_line() {
        let content = r"
[dependencies]
serde
";

        // Try to extract prefix with cursor beyond line length
        let line = content.lines().nth(2).unwrap();
        assert_eq!(line, "serde");

        // Cursor at position 100 (beyond line)
        let prefix = extract_prefix(line, 100, EcosystemId::Cargo);

        // Should clamp to line length
        assert_eq!(prefix, "serde");
        assert_eq!(prefix.len(), 5); // Not 100
    }

    #[test]
    fn test_extract_prefix_fallback_when_character_exceeds_line() {
        // `character` beyond the line's UTF-16 length hits `utf16_to_byte_offset`'s
        // `None` branch; `unwrap_or(line.len())` must clamp to the full line rather
        // than panic, even when the line contains multi-byte characters.
        let line = "café";
        let character = line.chars().map(|c| c.len_utf16() as u32).sum::<u32>() + 10;
        assert_eq!(extract_prefix(line, character, EcosystemId::Cargo), "café");
    }

    #[test]
    fn test_extract_prefix_strips_leading_quote_for_json_ecosystems() {
        // package.json / composer.json: cursor sits before the closing quote while the
        // key is still being typed, e.g. `    "expr` with the cursor right after "expr".
        let line = "    \"expr";
        assert_eq!(
            extract_prefix(line, line.len() as u32, EcosystemId::Npm),
            "expr"
        );
        assert_eq!(
            extract_prefix(line, line.len() as u32, EcosystemId::Composer),
            "expr"
        );
    }

    #[test]
    fn test_extract_prefix_strips_trailing_quote_for_json_ecosystems() {
        // Cursor right after a closing quote (editor auto-close, or the user retyped
        // it): `    "express"` with the cursor placed just past the closing quote.
        let line = "    \"express\"";
        assert_eq!(
            extract_prefix(line, line.len() as u32, EcosystemId::Npm),
            "express"
        );
        assert_eq!(
            extract_prefix(line, line.len() as u32, EcosystemId::Composer),
            "express"
        );
    }

    #[test]
    fn test_extract_prefix_leaves_quotes_for_non_json_ecosystems() {
        // Cargo keys are typed unquoted, so a leading/trailing `"` should never appear
        // in practice, but the strip must stay scoped: Cargo does not get it (unlike
        // PyPI's TOML array-element shape, see
        // `test_extract_prefix_strips_leading_quote_for_pypi_toml_array`).
        let line = "\"expr";
        assert_eq!(
            extract_prefix(line, line.len() as u32, EcosystemId::Cargo),
            "\"expr"
        );
    }

    /// #390 root cause 2: PyPI's `dependencies`/`optional-dependencies` entries are
    /// TOML array elements (`"pytes`), a different quoting shape from JSON-quoted
    /// keys, but must still have the surviving quote stripped before it reaches the
    /// registry search.
    #[test]
    fn test_extract_prefix_strips_leading_quote_for_pypi_toml_array() {
        let line = "    \"flas";
        assert_eq!(
            extract_prefix(line, line.len() as u32, EcosystemId::Pypi),
            "flas"
        );
    }

    #[test]
    fn test_extract_prefix_strips_trailing_quote_for_pypi_toml_array() {
        let line = "    \"pytest\"";
        assert_eq!(
            extract_prefix(line, line.len() as u32, EcosystemId::Pypi),
            "pytest"
        );
    }

    #[test]
    fn test_extract_prefix_does_not_panic_on_multibyte_char_boundary() {
        // `character` is a UTF-16 code unit count; using it as a raw byte index (the
        // pre-fix bug) split "é" mid-encoding here and panicked on the slice.
        let line = "    \"é";
        let character: u32 = line.chars().map(|c| c.len_utf16() as u32).sum();
        assert_eq!(extract_prefix(line, character, EcosystemId::Cargo), "\"é");
    }

    #[test]
    fn test_extract_prefix_multibyte_word_not_truncated() {
        let line = "café";
        let character: u32 = line.chars().map(|c| c.len_utf16() as u32).sum();
        assert_eq!(extract_prefix(line, character, EcosystemId::Cargo), "café");
    }

    #[test]
    fn test_extract_prefix_cjk_word_not_truncated() {
        let line = "日本";
        let character: u32 = line.chars().map(|c| c.len_utf16() as u32).sum();
        assert_eq!(extract_prefix(line, character, EcosystemId::Cargo), "日本");
    }

    #[tokio::test]
    async fn test_search_packages_returns_results_within_timeout() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct MockMetadata {
            name: deps_core::PackageName,
        }
        impl Metadata for MockMetadata {
            fn name(&self) -> &deps_core::PackageName {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                None
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &deps_core::ConcreteVersion {
                static VERSION: std::sync::LazyLock<deps_core::ConcreteVersion> =
                    std::sync::LazyLock::new(|| deps_core::ConcreteVersion::new("4.18.2"));
                &VERSION
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct FastRegistry;
        impl Registry for FastRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockMetadata {
                        name: deps_core::PackageName::new("express"),
                    }) as Box<dyn Metadata>])
                })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let items = search_packages(&FastRegistry, EcosystemId::Npm, "express").await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "express");
    }

    #[tokio::test]
    async fn test_search_packages_drops_maven_xml_breakout_keeps_safe_result() {
        // S1: this is the fallback-search path a malicious/compromised Maven registry
        // response can reach when `deps-maven`'s own XML-context completion produces no
        // (safe) results — it must apply the same allowlist, not just the primary path.
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct MockMetadata {
            name: deps_core::PackageName,
        }
        impl Metadata for MockMetadata {
            fn name(&self) -> &deps_core::PackageName {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                None
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &deps_core::ConcreteVersion {
                static VERSION: std::sync::LazyLock<deps_core::ConcreteVersion> =
                    std::sync::LazyLock::new(|| deps_core::ConcreteVersion::new("3.14.0"));
                &VERSION
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MavenRegistry;
        impl Registry for MavenRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![
                        Box::new(MockMetadata {
                            name: deps_core::PackageName::new("org.apache.commons:commons-lang3"),
                        }) as Box<dyn Metadata>,
                        Box::new(MockMetadata {
                            name: deps_core::PackageName::new(
                                "org.evil:payload</artifactId><parent>",
                            ),
                        }) as Box<dyn Metadata>,
                    ])
                })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let items = search_packages(&MavenRegistry, EcosystemId::Maven, "commons").await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "org.apache.commons:commons-lang3");
    }

    #[tokio::test(start_paused = true)]
    async fn test_search_packages_times_out_and_returns_empty() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        struct SlowRegistry;
        impl Registry for SlowRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    // Well beyond COMPLETION_SEARCH_TIMEOUT; paused time makes this
                    // resolve instantly instead of actually waiting.
                    tokio::time::sleep(Duration::from_mins(1)).await;
                    Ok(vec![])
                })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let items = search_packages(&SlowRegistry, EcosystemId::Npm, "expr").await;

        assert!(
            items.is_empty(),
            "should return empty on timeout, not block"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_handle_completion_primary_path_times_out_and_skips_fallback() {
        use deps_core::{
            Dependency, DiagnosticMessages, DiagnosticPolicy, Ecosystem, EcosystemFormatter,
            OsvNaming, PackageNaming, PackageRendering, ParseResult, RequirementResolution,
            SourcePolicy,
        };
        use std::any::Any;
        use std::path::Path;
        use std::time::Duration;
        use tower_lsp_server::ls_types::Uri;

        struct MockFormatter;
        impl PackageNaming for MockFormatter {}

        impl PackageRendering for MockFormatter {
            fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for MockFormatter {}

        impl DiagnosticMessages for MockFormatter {}

        impl DiagnosticPolicy for MockFormatter {}

        impl SourcePolicy for MockFormatter {}

        impl OsvNaming for MockFormatter {}

        // Deliberately `unimplemented!()`: if a primary-path timeout ever falls through
        // to `fallback_completion` again (the N1 double-timeout bug), that path calls
        // `registry()` and this test panics instead of just running slow.
        struct SlowEcosystem;
        impl deps_core::ecosystem::private::Sealed for SlowEcosystem {}
        impl Ecosystem for SlowEcosystem {
            fn id(&self) -> &'static str {
                "cargo"
            }
            fn display_name(&self) -> &'static str {
                "Cargo (slow mock)"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &["Cargo.toml"]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a Uri,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn deps_core::Registry> {
                unimplemented!()
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &MockFormatter
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions>
            {
                Box::pin(async move {
                    // Well beyond COMPLETION_SEARCH_TIMEOUT; paused time resolves
                    // this instantly instead of actually waiting.
                    tokio::time::sleep(Duration::from_mins(1)).await;
                    deps_core::completion::Completions::default()
                })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            uri: Uri,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        // Overwrites the real Cargo ecosystem for this state instance only.
        state.ecosystem_registry.register(Arc::new(SlowEcosystem));

        let content = "[dependencies]\nserde = \"1\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 5), // after "serde"
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;

        // Empty items collapse to `None` (see `handle_completion`'s tail); reaching
        // this at all (rather than hanging or panicking) is what this test checks.
        assert!(result.is_none());
    }

    /// #419 C1 regression, now driven by a per-call [`Completions::is_incomplete`]
    /// (#427) rather than a static per-ecosystem flag: an ecosystem whose
    /// `generate_completions` reports `is_incomplete: true` for the served context
    /// (PyPI's package-search-index-backed completion) must always get back
    /// `CompletionResponse::List { is_incomplete: true, .. }` — on the empty-items
    /// branch (the cold-start case rev 4's fix missed, since `None` serializes as
    /// LSP `null` and carries no `isIncomplete`) as well as the non-empty branch.
    /// An ecosystem that always reports `is_incomplete: false` (the
    /// `test_concurrent_document_write_not_blocked_by_in_flight_completion_search`
    /// test just above proves the empty case) keeps returning `None`/`Array`
    /// unchanged.
    #[tokio::test]
    async fn test_generate_completions_is_incomplete_flows_into_response_both_branches() {
        use deps_core::completion::Completions;
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            Dependency, DiagnosticMessages, DiagnosticPolicy, Ecosystem, EcosystemFormatter,
            Metadata, OsvNaming, PackageNaming, PackageRendering, ParseResult, Registry,
            RequirementResolution, SourcePolicy, Version,
        };
        use std::any::Any;
        use tower_lsp_server::ls_types::Uri;

        struct NoopRegistry;
        impl Registry for NoopRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct NoopFormatter;
        impl PackageNaming for NoopFormatter {}

        impl PackageRendering for NoopFormatter {
            fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for NoopFormatter {}

        impl DiagnosticMessages for NoopFormatter {}

        impl DiagnosticPolicy for NoopFormatter {}

        impl SourcePolicy for NoopFormatter {}

        impl OsvNaming for NoopFormatter {}

        /// Stands in for `PypiEcosystem`: always reports incomplete results, and
        /// returns either zero or one completion item depending on `has_item`.
        struct IncompleteEcosystem {
            has_item: bool,
        }
        impl Sealed for IncompleteEcosystem {}
        impl Ecosystem for IncompleteEcosystem {
            fn id(&self) -> &'static str {
                "cargo"
            }
            fn display_name(&self) -> &'static str {
                "cargo"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &["Cargo.toml"]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a Uri,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &NoopFormatter
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                let items = if self.has_item {
                    vec![CompletionItem {
                        label: "requests".to_string(),
                        ..Default::default()
                    }]
                } else {
                    vec![]
                };
                Box::pin(async move {
                    Completions {
                        items,
                        is_incomplete: true,
                    }
                })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            uri: Uri,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        async fn run(has_item: bool) -> Option<CompletionResponse> {
            let state = Arc::new(ServerState::new());
            state
                .ecosystem_registry
                .register(Arc::new(IncompleteEcosystem { has_item }));

            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
            let doc =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc);

            let params = CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri },
                    position: Position::new(0, 0),
                },
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
                context: None,
            };

            let (client, config) = create_test_client_and_config();
            handle_completion(state, params, client, config).await
        }

        match run(false).await {
            Some(CompletionResponse::List(list)) => {
                assert!(
                    list.is_incomplete,
                    "empty branch must still carry is_incomplete"
                );
                assert!(list.items.is_empty());
            }
            other => panic!("expected List{{is_incomplete:true, items:[]}}, got {other:?}"),
        }

        match run(true).await {
            Some(CompletionResponse::List(list)) => {
                assert!(list.is_incomplete);
                assert_eq!(list.items.len(), 1);
                assert_eq!(list.items[0].label, "requests");
            }
            other => panic!("expected List{{is_incomplete:true, items:[requests]}}, got {other:?}"),
        }
    }
}
