use std::sync::Arc;
use std::time::Duration;

use tower_lsp_server::ls_types::Position;

use crate::deps_dev::deps_dev_system;
use crate::edit::requirement_is_placeholder_for;
use crate::hover::Hover;
use crate::licenses::resolve_license_entries_for_display;
use crate::osv::ScanOutcome;
use crate::{
    ConcreteVersion, Dependency, DependencySource, Deprecation, LicenseSource, ParseResult,
    ProvenanceStatus, PublishTime, Registry, SupplyChainTrustSignal, Version, VersionReq,
    is_within_cooldown,
};

use super::diagnostics::{MAX_DIAGNOSTIC_NAME_CHARS, MAX_DIAGNOSTIC_VALUE_CHARS};
// Only referenced from this module's own tests now that the corresponding
// `push_*_hover_section` functions go through a `FieldKind` instead of the raw
// constant (#1310).
#[cfg(test)]
use super::diagnostics::{MAX_DIAGNOSTIC_PROSE_CHARS, MAX_VERSION_DIAGNOSTIC_CHARS};
use super::hover_markdown::{FieldKind, HoverMarkdown};
use super::{
    EcosystemFormatter, HOVER_RECENT_VERSIONS, VersionData, await_versions_fetch, escape_markdown,
    in_use_version, markdown_code_span, position_in_range, resolve_in_use_version,
    resolve_scan_outcome,
};
use crate::github::normalize_tag;

/// Bounds how long [`generate_hover`] *waits* for the spawned deps.dev trust-signal
/// fetch — never the fetch itself, which keeps running to completion and warms
/// [`crate::deps_dev::DepsDevClient`]'s memo even after this deadline elapses
/// (spec 037, plan.md §8's "spawn-and-warm" design). Deliberately not named
/// `..._TOTAL_...`: merging this with the fetch's own per-call timeouts would
/// silently kill spawn-and-warm — an over-budget fetch would then die entirely
/// instead of finishing into the memo, and the next hover would re-fire it under
/// the short error TTL rather than getting a memo hit.
const DEPS_DEV_WAIT_BUDGET: Duration = Duration::from_millis(700);

/// Computes the age (in seconds) of one "Recent versions" hover entry, for
/// [`HoverMarkdown::push_relative_age`].
///
/// Returns `None` when the registry doesn't expose a publish timestamp for `version`
/// (`published_at()` is `None`), so the entry renders exactly as it did before this
/// feature existed (graceful degradation, US-003).
///
/// `now` is taken as an explicit parameter rather than read internally so every entry
/// in the same "Recent versions" list is aged against one consistent instant.
fn version_age_secs(version: &dyn Version, now: PublishTime) -> Option<u64> {
    version
        .published_at()
        .map(|published| published.age_secs_from(now))
}

/// Bounds the `Registry::get_latest_matching` fallback (#373) hover fires when the
/// list-based `**Latest**` pick fails on a non-empty live list. Hover responses must
/// return quickly (`.claude/rules/rust-code.md`), and without this the fallback would
/// stack on top of `get_versions_with`'s own up-to-30s `reqwest` client timeout
/// (`HttpCache`), doubling worst-case hover latency to ~60s. `generate_hover` has no
/// `timeout_secs` config threaded in the way `lifecycle.rs`'s background fetch does, so
/// this is a fixed local bound rather than a configurable one — a few seconds is enough
/// slack for the already-rare "list-based pick failed" path without meaningfully
/// delaying the common case, which never reaches this fallback at all.
const HOVER_FALLBACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The `Cmd+.` update-footer markdown this function appends when a code action may exist
/// for the hovered dependency.
///
/// `pub` (re-exported from `lsp_helpers`) so an ecosystem's own `generate_hover` override
/// can restore it post-hoc for an action source this shared gate has no visibility into
/// (e.g. GHA's `TagIndex`-driven SHA-pin quickfix, #501) without hand-copying the literal
/// and risking drift between the two.
pub const CMD_DOT_FOOTER: &str = "\n---\n⌨️ **Press `Cmd+.` to update version**";

/// Builds the hover response for the dependency under `position`, if any.
///
/// Shared by every ecosystem's default [`crate::ecosystem::Ecosystem::generate_hover`]
/// implementation: locates the dependency whose name or version range contains
/// `position`, resolves its version data against `registry`, and renders the
/// result through `formatter`. Returns `None` when no dependency covers the position.
pub async fn generate_hover<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    position: Position,
    versions: VersionData<'_>,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
    freshness: crate::freshness::FreshnessSettings,
    now: PublishTime,
) -> Option<Hover> {
    let dep = parse_result.dependencies().into_iter().find(|d| {
        // #905: `position_in_range` is inclusive on both ends, so without this guard hovering
        // the document's first character (a synthetic `name_range()`'s `Range::default()`
        // sentinel) would match whichever synthetic-range dependency lists first.
        let on_name =
            !d.name_range_is_synthetic() && position_in_range(position.into(), d.name_range());
        // `!version_range_is_synthetic_empty` gate (#1161 M1 code-review follow-up, second
        // round): Maven's empty `<version></version>` gives `version_range()` a real,
        // zero-width position purely so completion can locate the dependency there, with no
        // requirement text to hover over — that degenerate case must not match here. A blanket
        // `version_requirement().is_some()` gate over-corrected this: Gradle's version-catalog
        // `version.ref` pointing at a dangling/rich-version alias legitimately has a REAL,
        // non-empty `version_range()` (the alias-reference text) with `version_requirement()`
        // still `None`, and hovering it worked before #1161 — the zero-width check keeps that
        // working while still suppressing Maven's genuinely degenerate position.
        let on_version = !super::version_range_is_synthetic_empty(*d)
            && d.version_range()
                .is_some_and(|r| position_in_range(position.into(), r));
        on_name || on_version
    })?;

    // A non-resolvable source (`CustomRegistry`, Git, Path) must skip the registry lookup —
    // fetching by name would silently check an unrelated public-registry package (#248).
    // `can_resolve_source`, not the bare `is_version_resolvable`, so an ecosystem routing more
    // sources than the generic default (e.g. Cargo's `AlternateRegistry`) still gets hover.
    let dep_source = dep.source();
    let resolvable = formatter.can_resolve_source(&dep_source);

    // Hoisted so the fetch is spawned before awaiting the registry fetch below, letting the
    // two requests overlap instead of stacking (spec 037, plan.md §8 M6).
    let normalized_name = formatter.normalize_package_name(dep.name());

    let trust_handle = spawn_trust_signal_fetch(
        dep,
        &dep_source,
        &versions,
        formatter,
        normalized_name.as_str(),
    );

    // `now` is caller-supplied (#227 M4), not `PublishTime::now()`, so tests can pin an exact
    // cooldown-boundary instant and every age in this response is aged consistently.
    //
    // `.ok()`, not `.ok()?`: a fetch failure (off-VPN, expired token, DNS-blocked internal
    // host) must degrade to the same basic card the `!resolvable` branch renders, not vanish
    // the whole hover response.
    let available_versions = if resolvable {
        await_versions_fetch(
            registry.get_versions_from(dep.name(), &dep_source, freshness),
            dep.name(),
            "hover",
        )
        .await
        .0
    } else {
        None
    };

    // FR-014: a resolved-but-not-default-registry source (e.g. Cargo's `AlternateRegistry`)
    // must not link to the ecosystem's default registry — misleading confirmation once live
    // version data renders below. `.filter(|u| !u.is_empty())` is defense-in-depth (#474)
    // against a dead `[name]()` link if an ecosystem forgets `suppress_package_url`.
    let url = (!formatter.suppress_package_url(&dep_source))
        .then(|| formatter.package_url(dep.name()))
        .filter(|u| !u.is_empty());

    let mut markdown = HoverMarkdown::new();
    push_header_hover_section(&mut markdown, dep, url.as_deref());

    let resolved: Option<&str> = if formatter.manifest_requirement_is_resolved_version(dep) {
        dep.version_requirement().map(VersionReq::as_str)
    } else {
        in_use_version::resolve_occurrence_version(
            dep,
            normalized_name.as_str(),
            versions.resolved,
            versions.resolved_version_candidates,
            formatter,
        )
        .map(ConcreteVersion::as_str)
    };
    push_current_or_requirement_hover_section(&mut markdown, dep, resolved);

    push_markers_hover_section(&mut markdown, dep);

    // `**Latest**` prefers the just-fetched live list over the Ch1 cache whenever a live fetch
    // happened — Ch1 alone could render a version older than "Recent versions"'s own
    // `*(latest)*` entry (#227 F5). Falls back to Ch1 only when there's no live list at all,
    // since an all-pre-release live list still means a fetch happened (#313).
    //
    // Exception (#373): when the list-based pick fails on a non-empty list, `latest_line` can
    // render an unmarked version from `list_fallback_latest` instead (Go's pseudo-versions) —
    // a correct-but-unmarked latest beats none.
    //
    // `live_latest_idx`, not raw index 0, since the list sorts purely by version number and a
    // pre-release could sort first without being "latest stable". Delegated to
    // `Registry::select_latest_matching_with_context`, threading `parse_result`'s own
    // `SelectionContext` (e.g. Composer's `minimum-stability`, #1433) — the same call
    // `lifecycle.rs`'s background fetch uses, so the two never disagree (e.g. npm's #338
    // non-deprecated preference, #347/#348 S1's label). Recorded as an index so the "Recent
    // versions" marker matches by position.
    let wildcard_req = crate::existence_wildcard_req();
    let selection_context = parse_result.selection_context();
    let live_latest_idx = available_versions.as_ref().and_then(|v| {
        registry.select_latest_matching_with_context(v, &wildcard_req, &selection_context)
    });
    // #373: a non-empty live list can still leave `live_latest_idx` `None` — e.g. Go's
    // `/@v/list` never enumerates pseudo-versions, so an untagged module's all-pre-release
    // history fails the list-based pick. Mirrors `lifecycle.rs`'s own fallback: a second call
    // to `Registry::get_latest_matching`, which some registries (Go's `/@latest`) answer more
    // completely than the list endpoint. Bounded by `HOVER_FALLBACK_TIMEOUT`; any failure,
    // timeout, or `None` degrades gracefully to no `**Latest**` line.
    let list_fallback_latest = if available_versions.as_ref().is_some_and(|v| !v.is_empty())
        && live_latest_idx.is_none()
    {
        match tokio::time::timeout(
            HOVER_FALLBACK_TIMEOUT,
            registry.get_latest_matching_from(
                dep.name(),
                &dep_source,
                &wildcard_req,
                &selection_context,
            ),
        )
        .await
        {
            Ok(Ok(found)) => {
                tracing::debug!(package = %dep.name().for_tracing(), found = found.is_some(), "hover latest fallback (get_latest_matching) resolved");
                found
            }
            Ok(Err(error)) => {
                tracing::warn!(package = %dep.name().for_tracing(), %error, "hover latest fallback (get_latest_matching) failed");
                None
            }
            Err(_) => {
                tracing::warn!(
                    package = %dep.name().for_tracing(),
                    timeout_secs = HOVER_FALLBACK_TIMEOUT.as_secs(),
                    "hover latest fallback (get_latest_matching) timed out"
                );
                None
            }
        }
    } else {
        None
    };
    let cached_latest = resolvable
        .then(|| {
            versions
                .cached
                .get(normalized_name.as_str())
                .or_else(|| versions.cached.get(dep.name()))
        })
        .flatten();
    // A non-empty live list with no stable entry tries `list_fallback_latest` (#373) first
    // rather than Ch1, since the cache's version wouldn't be part of what the live list just
    // showed. An empty live list has no such contradiction risk and falls back to Ch1 as usual.
    // `.get(idx)` degrades to the fallback rather than trusting `select_latest_matching`'s
    // in-bounds behavior, undocumented across its 14 per-ecosystem impls (#673 S2).
    let latest_line: Option<(&str, Option<PublishTime>)> = match &available_versions {
        Some(v) if !v.is_empty() => live_latest_idx
            .and_then(|idx| v.get(idx))
            .map(|live| (live.version_string().as_str(), live.published_at()))
            .or_else(|| {
                list_fallback_latest
                    .as_deref()
                    .map(|live| (live.version_string().as_str(), live.published_at()))
            }),
        _ => cached_latest.map(|v| (v.latest.as_str(), v.published_at)),
    };
    push_latest_hover_section(&mut markdown, latest_line, freshness, now);

    // #394 S2: version-qualified key so a hover on one occurrence of a duplicated name never
    // shows another occurrence's OSV result.
    let vuln_keys = versions.ecosystem.map(|ecosystem| {
        crate::osv::vulnerability_keys(
            parse_result,
            versions.resolved,
            versions.resolved_version_candidates,
            formatter,
            ecosystem,
        )
    });
    let vuln_outcome = versions
        .vulnerabilities
        .and_then(|m| resolve_scan_outcome(m, dep, vuln_keys.as_ref(), &normalized_name));
    let deprecation = versions
        .outcomes
        .and_then(|o| o.deprecation(&normalized_name));
    // Package-level context (#205) renders before per-version security advisories:
    // deprecation is a property of the package, advisories of the version.
    push_deprecation_hover_section(&mut markdown, formatter, deprecation);
    push_vulnerability_hover_section(&mut markdown, formatter, vuln_outcome);

    // Awaited last so the wait overlaps as much of this function's own work as possible.
    // Bounds only the wait: over budget, the spawned task keeps running and warms
    // `DepsDevClient`'s memo regardless (`DEPS_DEV_WAIT_BUDGET`). A `JoinHandle` `Err` (panic)
    // is swallowed like a timeout or fetch failure — FR-006 must hold here too.
    let trust_signal = match trust_handle {
        Some(handle) => match tokio::time::timeout(DEPS_DEV_WAIT_BUDGET, handle).await {
            Ok(Ok(signal)) => signal,
            Ok(Err(_)) | Err(_) => None,
        },
        None => None,
    };
    push_trust_signal_hover_section(&mut markdown, trust_signal.as_ref());

    // #204 (spec 010): resolved-version license first tries the already-fetched
    // `available_versions` list, then falls back to `trust_signal`'s `licenses`
    // (deps.dev-covered ecosystems). Latest-version license only ever comes from the native
    // list — deps.dev only targets the resolved version, so a deps.dev-routed ecosystem's
    // latest license degrades to "(unavailable)" (spec 010 §6) rather than a second call.
    //
    // Keys on `resolve_in_use_version`, not the weaker `resolved` the Current/Requirement line
    // uses — it adds a `concrete_pin_version` fallback for an exact pin with no lock file.
    let in_use_version_str: Option<String> = versions.ecosystem.and_then(|ecosystem| {
        resolve_in_use_version(
            dep,
            normalized_name.as_str(),
            versions.resolved,
            versions.resolved_version_candidates,
            formatter,
            ecosystem,
        )
    });
    // Shared key for the resolved-license lookup below and the latest-license shortcut
    // further down — both must agree, or the shortcut can miss a version the lookup found
    // (round 3 M1 regression: comparing against the weaker `resolved` reintroduced S1's
    // spurious "unavailable" note).
    let resolved_key: Option<&str> = in_use_version_str.as_deref().or(resolved);
    let license_source = versions.license_source.unwrap_or_default();
    // `normalize_tag` on both sides, not `==` (#664 S1): a bare pin with no `v` (Composer's
    // `"8.1.6"`) must still match a `v`-prefixed registry tag, and vice versa.
    let resolved_license: Vec<String> = resolved_key
        .and_then(|r| {
            available_versions.as_ref().and_then(|versions| {
                versions
                    .iter()
                    .find(|v| normalize_tag(v.version_string().as_str()) == normalize_tag(r))
            })
        })
        .map(|v| v.license().to_vec())
        .filter(|l| !l.is_empty())
        .or_else(|| {
            trust_signal
                .as_ref()
                .map(|s| s.licenses.clone())
                .filter(|l| !l.is_empty())
        })
        // Tier 3 (#660): Dart/Swift/Gradle/Deno have no deps.dev coverage or version-list
        // license field, so the only source left is `DocumentState`'s pre-fetch cache.
        // Resolved via `resolve_license_entries_for_display` (#687 S1/S2), not the
        // policy-evaluation `resolve_license_entries`: an unrecognized Gradle POM name falls
        // back to raw text instead of vanishing.
        .or_else(|| {
            versions
                .license_prefetch
                .and_then(|m| m.get(dep.name()))
                .filter(|raw| !raw.is_empty())
                .map(|raw| resolve_license_entries_for_display(license_source, raw))
        })
        .unwrap_or_default();
    // `None` (no latest version) is distinct from `Some(&[])` (latest exists, license
    // unknown): the former renders no note, the latter "(latest version license
    // unavailable)" (impl-critic S1). Reuses `resolved_license` when the latest version is
    // the resolved one (up to date), avoiding a spurious "unavailable" note on the common
    // case. Skipped once `resolved_license` is already empty.
    //
    // Deliberately has no `license_prefetch` fallback of its own (round 3 finding #6):
    // `license_prefetch` is a single per-package or per-resolved-version entry, never
    // per-latest-version, so reusing `resolved_license` for a tier-3 dependency whose latest
    // differs from resolved would misrepresent the resolved version's license as the
    // latest's, suppressing a real "License changed" note or fabricating a false "no change".
    let latest_license: Option<Vec<String>> = (!resolved_license.is_empty())
        .then(|| {
            latest_line.map(|(latest_ver, _)| {
                if resolved_key == Some(latest_ver) {
                    resolved_license.clone()
                } else {
                    live_latest_idx
                        .and_then(|idx| available_versions.as_ref().and_then(|v| v.get(idx)))
                        .map(|v| v.license().to_vec())
                        .filter(|l| !l.is_empty())
                        .unwrap_or_default()
                }
            })
        })
        .flatten();
    // Dart's license comes from pub.dev's `/score` detector tag (pana's heuristic) and
    // Swift's from GitHub's `license.spdx_id` (the `licensee` gem) — both detector output,
    // not author-declared registry metadata (spec 010 §1, NFR-005 exception; critic S2).
    // Every other ecosystem's license is a genuine registry-declared field, so only a
    // `DetectedSpdx` source (Dart, Swift — #688) gets the "(detected)" qualifier.
    let license_is_detected = license_source == LicenseSource::DetectedSpdx;
    push_license_hover_section(
        &mut markdown,
        &resolved_license,
        latest_license.as_deref(),
        license_is_detected,
    );

    // `!v.is_empty()`, not just `Some(_)` (#550): a resolvable source's live fetch can
    // succeed with a genuinely empty list — e.g. a real GitHub repository whose only
    // tags don't parse as full semver (`dtolnay/rust-toolchain`'s sole tag `v1`) — and
    // a "**Recent versions**:" header with no entries under it is never useful,
    // regardless of ecosystem.
    if let Some(available_versions) = available_versions.as_ref().filter(|v| !v.is_empty()) {
        push_recent_versions_hover_section(
            &mut markdown,
            available_versions,
            live_latest_idx,
            freshness,
            now,
            formatter,
        );
    }

    // #1402: an unexpanded template placeholder (`{{ VAR }}`, `${VAR}`, ...) is refused by
    // the same write-path guard `codeAction` routes every fix through (`edit::replacement_text`
    // / #1393), so `Cmd+.` would return zero actions here regardless of what data was rendered
    // above — the footer must consult the identical predicate to avoid advertising a dead action.
    let requirement_is_placeholder = dep
        .version_requirement()
        .is_some_and(|req| requirement_is_placeholder_for(formatter, dep, req.as_str()));
    push_cmd_dot_footer_hover_section(
        &mut markdown,
        CmdDotFooterState {
            resolvable,
            available_versions: available_versions.as_deref(),
            cached_latest,
            vuln_outcome,
            deprecation,
            offline: versions.offline,
            requirement_is_placeholder,
        },
    );

    push_offline_footer_hover_section(&mut markdown, resolvable, versions.offline);
    push_skip_reason_footer_hover_section(
        &mut markdown,
        resolvable,
        versions.offline,
        vuln_outcome,
    );

    Some(markdown.finish(Some(dep.name_range())))
}

/// Spawns the deps.dev supply-chain trust-signal fetch (spec 037) as a detached
/// background task. Only `handlers/hover.rs` (deps-lsp) ever sets `versions.trust`,
/// which is what makes FR-010's hover-only scope structural: every other surface
/// (diagnostics, code actions, inlay hints, code lenses) is never handed a client and
/// so can never reach deps.dev.
///
/// Gated on all of: a client was handed in, `network.offline` is not set, the source
/// resolves against a **public** registry, the ecosystem is one of the seven
/// `deps_dev_system` maps, and a concrete in-use version exists — the last two
/// checked with **no** network I/O, so an ecosystem `deps_dev_system` excludes
/// (Composer, Dart, Swift, ...) spawns nothing at all.
///
/// `formatter.source_is_public_registry_content(dep_source)`, not the weaker
/// `EcosystemFormatter::can_resolve_source`: that predicate is deliberately widened
/// by some ecosystems (e.g. `deps-cargo`'s `AlternateRegistry`) to cover *any*
/// configured registry, private/internal ones included — reusing it here would send
/// a private package's name and version to deps.dev by default (security audit M2).
/// `source_is_public_registry_content` is the same, stricter predicate this server's
/// other third-party lookup (OSV) already gates on (`lifecycle.rs`).
///
/// `!versions.offline`: every other network-gated hover section [`generate_hover`]
/// builds checks `versions.offline` (the `Cmd+.` footer, the offline footer) —
/// without it here, offline mode still spawns a task per hover and writes a 90s
/// negative memo entry, keeping the signal absent for up to 90s per package after
/// reconnecting for no reason (critic C4).
///
/// `tokio::spawn` panics outside a Tokio runtime — every caller of [`generate_hover`]
/// is `#[tokio::test]`-async or the real LSP server, so this is safe here, but no
/// doc-test may call it directly. The spawned future captures only owned/`'static`
/// data (`Arc<DepsDevClient>`, `&'static str`, owned `String`s) so it satisfies
/// `Send + 'static` with no borrow from `dep`.
fn spawn_trust_signal_fetch(
    dep: &dyn Dependency,
    dep_source: &DependencySource,
    versions: &VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
    normalized_name: &str,
) -> Option<tokio::task::JoinHandle<Option<SupplyChainTrustSignal>>> {
    versions.trust.and_then(|client| {
        let ecosystem = versions.ecosystem?;
        let system = deps_dev_system(ecosystem)?;
        if versions.offline || !formatter.source_is_public_registry_content(dep_source) {
            return None;
        }
        let version = resolve_in_use_version(
            dep,
            normalized_name,
            versions.resolved,
            versions.resolved_version_candidates,
            formatter,
            ecosystem,
        )?;
        let client = Arc::clone(client);
        let name = dep.name().as_str().to_string();
        Some(tokio::spawn(async move {
            client.trust_signal(system, &name, &version).await
        }))
    })
}

/// Appends the hover header: the dependency name, linked to its registry page when
/// `url` (from [`crate::lsp_helpers::PackageRendering::package_url`]) is present.
///
/// `package_url`'s producer-side hostile-input gate
/// (`crate::conformance::assert_package_url_hostile_input_safe`, run for every
/// ecosystem formatter via `formatter_conformance!`) is the *primary* defense for this
/// destination — every real `package_url` impl percent-encodes or allowlist-validates
/// the name before building the URL. [`HoverMarkdown::push_link`]'s consumer-side
/// stripping of `url`'s bidi-override/invisible characters (#1259) is
/// defense-in-depth on top of that gate, not a replacement for it, and — per that
/// method's own doc — deliberately does not length-cap `url` (#1272 critic S4). The
/// **label** (`dep.name()`) *is* capped, at [`FieldKind::Name`], via
/// [`HoverMarkdown::push_link`]/[`HoverMarkdown::push_label`]'s escape-then-truncate
/// order (#1310, folding in #1259's original per-site cap).
fn push_header_hover_section(
    markdown: &mut HoverMarkdown,
    dep: &dyn Dependency,
    url: Option<&str>,
) {
    markdown.push_static("# ");
    match url {
        Some(url) => {
            markdown.push_link(dep.name().as_str(), FieldKind::Name, url);
        }
        None => {
            markdown.push_label(dep.name().as_str(), FieldKind::Name);
        }
    }
    markdown.push_static("\n\n");
}

/// Appends the hover "Current"/"Requirement" line. `resolved` — already selecting
/// between an ecosystem's resolved manifest requirement and the lockfile-resolved
/// version, per [`crate::lsp_helpers::RequirementResolution::manifest_requirement_is_resolved_version`] —
/// wins over the bare manifest requirement when present.
fn push_current_or_requirement_hover_section(
    markdown: &mut HoverMarkdown,
    dep: &dyn Dependency,
    resolved: Option<&str>,
) {
    // `resolved`/`version_requirement` are lockfile- and manifest-controlled,
    // unbounded-length strings — `FieldKind::Version` matches diagnostics.rs's
    // sibling sink for the same field shape (#1311).
    if let Some(resolved_ver) = resolved {
        markdown.push_static("**Current**: ");
        markdown.push_code(resolved_ver, FieldKind::Version);
        markdown.push_static("\n\n");
    } else if let Some(version_req) = dep.version_requirement() {
        markdown.push_static("**Requirement**: ");
        markdown.push_code(version_req.as_str(), FieldKind::Version);
        markdown.push_static("\n\n");
    }
}

/// Appends the hover "Active when" line for an environment-marker-gated dependency
/// (e.g. PEP 508's `python_version >= '3.8'`). Ecosystem-specific; renders nothing
/// when [`Dependency::markers`] is `None`.
fn push_markers_hover_section(markdown: &mut HoverMarkdown, dep: &dyn Dependency) {
    // `marker_expr` is manifest-controlled with no upstream length bound (#1311).
    // `FieldKind::Name`, not `Prose` (#1313 reclassification): a PEP 508 marker
    // expression is a version-constraint-shaped identifier, not free prose — it has no
    // legitimate use for an invisible/bidi character, so it gets the `sanitize_invisible`
    // sweep `Name`/`Version` carry.
    if let Some(marker_expr) = dep.markers() {
        markdown.push_static("**Active when**: ");
        markdown.push_code(marker_expr, FieldKind::Name);
        markdown.push_static("\n\n");
    }
}

/// Appends the hover "Latest" line and, when the version is still within the
/// configured cooldown window, the "Recently published" callout beneath it.
///
/// `latest_line` renders nothing when `None` — no header, matching an empty "Recent
/// versions" list below. See [`generate_hover`]'s derivation of `latest_line` for the
/// full Ch1/Ch2/fallback precedence rules (issue #227 F5, #313, #373).
fn push_latest_hover_section(
    markdown: &mut HoverMarkdown,
    latest_line: Option<(&str, Option<PublishTime>)>,
    freshness: crate::freshness::FreshnessSettings,
    now: PublishTime,
) {
    let Some((latest_ver, raw_published_at)) = latest_line else {
        return;
    };
    let published_at = freshness.enabled.then_some(raw_published_at).flatten();
    let age_secs = published_at.map(|p| p.age_secs_from(now));
    // `latest_ver` is registry-reported and unbounded — `FieldKind::Version` matches
    // diagnostics.rs's sibling sink (#1311).
    markdown.push_static("**Latest**: ");
    markdown.push_code(latest_ver, FieldKind::Version);
    if let Some(age_secs) = age_secs {
        markdown.push_static(" *(published ");
        markdown.push_relative_age(age_secs);
        markdown.push_static(")*");
    }
    markdown.push_static("\n\n");
    if age_secs.is_some_and(|age| is_within_cooldown(age, freshness.cooldown_secs)) {
        markdown.push_static(
            "> ⏳ **Recently published** — this release is still within the cooldown window.\n\
             > It may still be yanked or superseded; consider verifying before upgrading.\n\n",
        );
    }
}

/// Appends the "Recent versions" list: up to [`HOVER_RECENT_VERSIONS`] entries drawn from
/// `available_versions`, each optionally aged (freshness-gated) and marked
/// `*(latest)*` at `live_latest_idx` — matched by position against the header's
/// stable-latest pick rather than raw index 0 or string equality: `available_versions`
/// is sorted purely by version number, so index 0 can be a pre-release the header
/// itself doesn't call "latest" (issue #313), and matching by version string instead
/// of index could tag more than one entry if two ever shared a version string.
///
/// If `live_latest_idx` falls outside the raw-order `HOVER_RECENT_VERSIONS`-entry
/// window (e.g. 9+ consecutive pre-releases ahead of the first stable release), the
/// pick is bumped into the window as its final entry instead of being silently
/// dropped from the list — mirroring
/// [`crate::completion::prepare_version_display_items`]'s identical bounded-scan
/// fix for completion/code-actions (#956, #961). Unlike that helper, no separate
/// filter pass is needed first: this list already renders every entry regardless of
/// removal status (flagged ones just gain `formatter.yanked_label()`), so the pick
/// can be looked up by direct index instead of a bounded scan over survivors.
///
/// Renders nothing when `available_versions` is empty (issue #550): an empty
/// "Recent versions" header with no entries under it is never useful.
fn push_recent_versions_hover_section(
    markdown: &mut HoverMarkdown,
    available_versions: &[Box<dyn Version>],
    live_latest_idx: Option<usize>,
    freshness: crate::freshness::FreshnessSettings,
    now: PublishTime,
    formatter: &dyn EcosystemFormatter,
) {
    if available_versions.is_empty() {
        return;
    }

    let mut entries: Vec<(usize, &Box<dyn Version>)> = available_versions
        .iter()
        .enumerate()
        .take(HOVER_RECENT_VERSIONS)
        .collect();

    if let Some(idx) = live_latest_idx
        && idx >= HOVER_RECENT_VERSIONS
        && let Some(pick) = available_versions.get(idx)
    {
        entries.truncate(HOVER_RECENT_VERSIONS - 1);
        entries.push((idx, pick));
    }

    markdown.push_static("**Recent versions**:\n");
    for (i, version) in entries {
        let age_secs = freshness
            .enabled
            .then(|| version_age_secs(version.as_ref(), now))
            .flatten();
        markdown.push_static("- ");
        // `version_string()` is registry-reported and unbounded — `FieldKind::Version`
        // matches diagnostics.rs's sibling sink (#1311).
        markdown.push_code(version.version_string().as_str(), FieldKind::Version);
        let is_latest = Some(i) == live_latest_idx;
        let flagged = version.removal_status().is_flagged();
        // The resolved "latest" can itself be flagged (e.g. npm's ranking preference
        // falls through to a deprecated version when no clean one exists) — the
        // deprecation/yank warning must not silently vanish just because this entry
        // also carries the `(latest)` marker (#347/#348 S1).
        match (is_latest, flagged) {
            (true, true) => {
                markdown.push_static(" *(latest)* ");
                markdown.push_static(formatter.yanked_label());
            }
            (true, false) => {
                markdown.push_static(" *(latest)*");
            }
            (false, true) => {
                markdown.push_static(" ");
                markdown.push_static(formatter.yanked_label());
            }
            (false, false) => {}
        }
        if let Some(age_secs) = age_secs {
            markdown.push_static(" — ");
            markdown.push_relative_age(age_secs);
        }
        markdown.push_static("\n");
    }
}

/// Appends the `Cmd+.` code-action footer — advertised only when a fix action could
/// actually exist for this dependency, since none is ever offered for a source that
/// is deliberately non-resolvable (e.g. a local composite action or a Docker image
/// ref), so rendering it unconditionally is misleading there (#474).
///
/// Gated on `resolvable` alone, not on `available_versions`/`cached_latest` also
/// being populated: a vulnerability-fix or unsatisfiable-fix code action
/// (`code_actions.rs`) can exist from `vuln_outcome` — populated independently of the
/// registry fetch (`lifecycle.rs`) — even when both of those are empty (e.g. a
/// registry fetch failure), so requiring them too would silently drop the footer
/// while `Cmd+.` still offers a fix.
///
/// Also gated on offline data availability (#501): `HttpCache` deliberately serves
/// warm entries while offline (it force-enables caching in that mode), and doc-state
/// fields — vulnerabilities/cached latest/deprecation — survive an online-to-offline
/// transition via `preserve_cache`, so `Cmd+.` can still produce a real
/// REFACTOR/fix/replacement action offline as long as *some* version, vulnerability,
/// or deprecation data was actually rendered above. Only suppress when offline AND
/// none of that data is present — a cold process with nothing cached yet, where no
/// producer in `generate_code_actions` has anything to act on.
///
/// `matches!(vuln_outcome, Some(ScanOutcome::Vulnerable(_)))`, not
/// `vuln_outcome.is_some()` (#501 C5): offline does not skip the OSV scan, it lets it
/// run and fail, which writes `ScanOutcome::Skipped(_)` for every dependency —
/// `is_some()` would be true in exactly #501's own cold-start repro and only
/// `Vulnerable` ever backs `build_vulnerability_fix_action` (`code_actions.rs`).
///
/// A live fetch that genuinely succeeded with zero entries (`Some(&[])`, distinct
/// from `None` — a fetch that errored or never ran, where an unrelated Cmd+. action
/// such as an unsatisfiable-fix might still exist per the reasoning above) is
/// definitive proof there is nothing version-wise to update to (#550): combined with
/// no cached/vulnerability/deprecation data either, the footer would otherwise
/// advertise an action that provably does not exist — the "empty Recent versions
/// section plus a stray footer" bug reported against GHA's
/// `dtolnay/rust-toolchain@stable` but not specific to any one ecosystem. Every other
/// online case (a non-empty live list, or no live fetch at all) keeps the pre-#550
/// unconditional-when-resolvable behavior.
///
/// `requirement_is_placeholder` (#1402) suppresses the footer independent of all of the
/// above: an unexpanded template placeholder (`{{ VAR }}`, `${VAR}`, `$var`, ...) is
/// rejected by the same write-path guard every `codeAction` fix routes through
/// ([`crate::edit::requirement_is_placeholder_for`], default-on across ecosystems since
/// #1393), so `Cmd+.` would return zero actions regardless of how much version,
/// vulnerability, or deprecation data was rendered above.
fn push_cmd_dot_footer_hover_section(markdown: &mut HoverMarkdown, state: CmdDotFooterState<'_>) {
    let has_offline_actionable_data = state.available_versions.is_some_and(|v| !v.is_empty())
        || state.cached_latest.is_some()
        || matches!(state.vuln_outcome, Some(ScanOutcome::Vulnerable(_)))
        || state.deprecation.is_some();
    let live_fetch_definitively_empty = state.available_versions.is_some_and(<[_]>::is_empty);
    let footer_actionable =
        has_offline_actionable_data || (!live_fetch_definitively_empty && !state.offline);
    if state.resolvable && footer_actionable && !state.requirement_is_placeholder {
        markdown.push_static(CMD_DOT_FOOTER);
    }
}

/// Bundles [`push_cmd_dot_footer_hover_section`]'s parameters — kept as one struct (rather
/// than eight positional parameters) to stay under `clippy::too_many_arguments`.
struct CmdDotFooterState<'a> {
    resolvable: bool,
    available_versions: Option<&'a [Box<dyn Version>]>,
    cached_latest: Option<&'a super::PackageVersions>,
    vuln_outcome: Option<&'a ScanOutcome>,
    deprecation: Option<&'a Deprecation>,
    offline: bool,
    requirement_is_placeholder: bool,
}

/// Appends the "Offline: version and vulnerability data not checked" footer (issue
/// #483) — the OSV lookup that produced `ScanOutcome::Skipped` for this dependency
/// renders nothing in the vulnerability section, which would otherwise be visually
/// indistinguishable from a scanned, vulnerability-free dependency; this footer calls
/// out that vulnerability data specifically was not checked, not just version data
/// (S2).
///
/// Gated on `resolvable` too, matching the `Cmd+.` footer (#474/#475): a dependency
/// that is never network-resolved under any setting (a local composite action, a
/// Docker image ref, a Git/path dependency) must not claim its version or
/// vulnerability data went unchecked *because of* `network.offline` — nothing there
/// was ever going to be checked regardless.
fn push_offline_footer_hover_section(
    markdown: &mut HoverMarkdown,
    resolvable: bool,
    offline: bool,
) {
    if offline && resolvable {
        markdown.push_static("\n---\n📴 *Offline: version and vulnerability data not checked*");
    }
}

/// Appends a "vulnerability data not checked" footer for a non-offline
/// [`SkipReason`] (issue #1392) — extends #483's offline-only footer to the far more
/// common case where the OSV scan itself skipped this dependency (most often
/// `NoConcreteVersion`: a semver-range requirement with no committed lock file),
/// which otherwise renders nothing and is visually indistinguishable from a
/// scanned, vulnerability-free dependency (`push_vulnerability_hover_section`'s
/// `Some(ScanOutcome::Skipped(_)) | None => {}` arm).
///
/// Suppressed while `offline`: [`push_offline_footer_hover_section`] already covers
/// that case with its own, broader wording (version *and* vulnerability data), and
/// showing both footers together would be redundant. Gated on `resolvable` for the
/// same reason as that function; `SkipReason::unchecked_reason` returning `None` for
/// `NonRegistrySource` is belt-and-suspenders for the same case.
fn push_skip_reason_footer_hover_section(
    markdown: &mut HoverMarkdown,
    resolvable: bool,
    offline: bool,
    vuln_outcome: Option<&ScanOutcome>,
) {
    if offline || !resolvable {
        return;
    }
    if let Some(ScanOutcome::Skipped(reason)) = vuln_outcome
        && let Some(text) = reason.unchecked_reason()
    {
        markdown.push_static("\n---\n🔍 *Vulnerability data not checked: ");
        markdown.push_static(text);
        markdown.push_static("*");
    }
}

/// Lowercase display label for a [`crate::osv::VulnSeverity`], used only in hover text.
///
/// `Malicious` renders as `"confirmed malicious package"` — deliberately
/// distinct from both `"unknown severity"` (a record this could not grade,
/// carrying no urgency signal of its own) and every graded label
/// (`critical`/`high`/`medium`/`low`), since a confirmed-malicious-package
/// finding is categorically different from a graded-but-uncertain risk.
///
/// `Informational` renders as `"maintenance-status notice, not a
/// vulnerability"` — deliberately not `"unknown severity"` and not any
/// graded label (FR-003, issue #1007): a maintenance-status notice (e.g.
/// RUSTSEC's `"unmaintained"`) stands alone as a comprehensible category
/// even when the advisory has no `summary`, which "unknown severity" alone
/// would not convey.
const fn severity_label(severity: crate::osv::VulnSeverity) -> &'static str {
    match severity {
        crate::osv::VulnSeverity::Critical => "critical",
        crate::osv::VulnSeverity::High => "high",
        crate::osv::VulnSeverity::Medium => "medium",
        crate::osv::VulnSeverity::Low => "low",
        crate::osv::VulnSeverity::Unknown => "unknown severity",
        crate::osv::VulnSeverity::Malicious => "confirmed malicious package",
        crate::osv::VulnSeverity::Informational => "maintenance-status notice, not a vulnerability",
    }
}

/// Appends the hover "Deprecated" section (issue #205), gated strictly on `deprecation`
/// being present — never rendered as "not deprecated" for a clean package, the same
/// discipline [`push_vulnerability_hover_section`] applies to `Skipped`/`None`.
///
/// Deliberately not deduped against npm's per-row `*(deprecated)*` "Recent versions"
/// labels (S4, plan.md D6): suppressing those would require threading this finding into
/// the version-list renderer, which takes no such parameter today.
fn push_deprecation_hover_section(
    markdown: &mut HoverMarkdown,
    formatter: &dyn EcosystemFormatter,
    deprecation: Option<&Deprecation>,
) {
    let Some(deprecation) = deprecation else {
        return;
    };

    // I3: each part gets its own blank-line-separated paragraph, mirroring
    // `push_vulnerability_hover_section` — consecutive lines with no blank line between
    // them collapse into one CommonMark paragraph instead of distinct lines.
    markdown.push_static("### Deprecated\n\n");
    markdown.push_static(formatter.deprecated_message());
    markdown.push_static("\n\n");
    // `deprecation.reason`/`replacement` are registry-reported and unbounded (#1311).
    // `reason` is genuinely free prose (`FieldKind::Prose`), matching diagnostics.rs's
    // cap for the same field shape. `replacement` is a package *name*, not prose
    // (`FieldKind::Name`, #1313 reclassification — this is the exact field #1313's own
    // doc names as #1311's still-open gap): it has no legitimate use for an
    // invisible/bidi character, so it gets the `sanitize_invisible` sweep.
    if let Some(reason) = deprecation.reason.as_deref().filter(|r| !r.is_empty()) {
        markdown.push_text(reason, FieldKind::Prose);
        markdown.push_static("\n\n");
    }
    if let Some(replacement) = deprecation.replacement.as_deref().filter(|r| !r.is_empty()) {
        markdown.push_static("Suggested replacement: ");
        markdown.push_code(replacement, FieldKind::Name);
        markdown.push_static("\n\n");
    }
}

/// Whether the "Latest version is also affected" hover line should render
/// for a [`crate::osv::UpgradeStatus::CandidateVulnerable`] result (FR-008,
/// issue #1007, revised architecture per impl-critic findings S1/S2):
/// `check_candidates()` and `UpgradeStatus` themselves stay entirely
/// unchanged by this spec (they have no [`crate::osv::VulnSeverity`] to read
/// — `advisory_ids` is just a list of ids), so the informational-only
/// suppression is applied purely at render time here, by looking each
/// candidate id's severity up in `known_advisories` — the *current*
/// version's own already-fetched, already-severity-classified advisory
/// list, which in practice shares ids with the candidate's own vulnerable
/// set (the same advisory typically covers both versions' ranges).
///
/// The line is suppressed only when `candidate_ids` is [`crate::osv::Capped::is_complete`]
/// (see below) AND EVERY id in it is found in `known_advisories` AND
/// classified [`crate::osv::VulnSeverity::Informational`]. An id this crate
/// cannot find a severity for (not present in `known_advisories` — e.g.
/// beyond `MAX_ADVISORY_RECORDS`, or genuinely a different advisory set for
/// the candidate version) is conservatively treated as "not informational",
/// so a real vulnerability signal is never silently dropped just because
/// its severity could not be confirmed at render time.
///
/// `candidate_ids` takes [`crate::osv::Capped::is_complete`] as a fail-open
/// gate, checked before anything else (FR-010, security finding L2): if
/// `check_candidates()`'s own scan was truncated (more advisories exist on
/// the candidate than the displayed/fetched slice reports), an undisplayed
/// advisory beyond the cap could be a real, non-`Informational` finding this
/// function has no way to see — so an incomplete set always renders the
/// line, regardless of what the displayed ids classify as.
///
/// An EMPTY (and complete) `candidate_ids` also fails open (impl-critic
/// finding N1): `CandidateVulnerable` with a zero-length `advisory_ids` is
/// reachable — `check_candidates()`'s inner scan can produce
/// `Capped::new(vec![], total)` with `total > 0` when every matched record's
/// detail fetch failed or failed `into_advisory` validation, i.e. "the
/// candidate is affected by something, but we could not confirm what it
/// is." Treating that as "nothing to report" would silently drop a real
/// signal this feature must never suppress.
fn candidate_vulnerable_line_should_render(
    candidate_ids: &crate::osv::Capped<String>,
    known_advisories: &[Arc<crate::osv::Advisory>],
) -> bool {
    if !candidate_ids.is_complete() || candidate_ids.items().is_empty() {
        return true;
    }
    !candidate_ids.items().iter().all(|id| {
        known_advisories
            .iter()
            .find(|advisory| &advisory.id == id)
            .is_some_and(|advisory| advisory.severity == crate::osv::VulnSeverity::Informational)
    })
}

/// Appends the hover "Security advisories" section, gated strictly on the
/// scan outcome — never on map absence.
///
/// `Vulnerable` gets the advisories list, `Clean` may state the affirmative
/// "no known vulnerabilities", and `Skipped` (or no scan at all) says
/// **nothing**: saying "clean" about a dependency that was never queried is
/// worse than saying nothing at all (`architecture.md` §8 invariant 0).
///
/// Every OSV-reported field rendered here is length- (and, for `aliases`, count-) capped
/// before display (#1272) — but not all through the same order, since `id` is rendered
/// as a link label and the rest are not: `id` ([`FieldKind::Prose`]) goes through
/// [`HoverMarkdown::push_link`]'s escape-before-truncate order (rendered-length bound,
/// the same as `push_header_hover_section`'s name label), while `summary`
/// ([`FieldKind::Prose`]) and `fixed_versions`/the candidate `version`
/// ([`FieldKind::Version`]) go through [`HoverMarkdown::push_text`]/
/// [`HoverMarkdown::push_code`]'s truncate-before-escape order (raw-character bound,
/// matching `diagnostics.rs`'s sibling sinks). `aliases` is capped/escaped per-element and
/// count-capped by [`format_advisory_aliases`] itself before reaching the builder. All are
/// untrusted, unbounded OSV data. `advisory.url()` is exempt: [`crate::osv::Advisory::new`]
/// derives it from the already-validated, `<= 128`-byte `id` rather than accepting it raw
/// (#1271), so no length cap applies to it here — [`HoverMarkdown::push_link`] only strips
/// it, matching that exemption.
fn push_vulnerability_hover_section(
    markdown: &mut HoverMarkdown,
    formatter: &dyn EcosystemFormatter,
    outcome: Option<&ScanOutcome>,
) {
    match outcome {
        Some(ScanOutcome::Vulnerable(dv)) => {
            markdown.push_static("### Security advisories\n\n");

            let display_advisories = dv.advisories_for_display();
            for advisory in display_advisories.items() {
                markdown.push_static("- **");
                markdown.push_link(&advisory.id, FieldKind::Prose, advisory.url());
                markdown.push_static("** — ");
                markdown.push_static(severity_label(advisory.severity));
                markdown.push_static("\n  ");
                markdown.push_text(
                    advisory
                        .summary
                        .as_deref()
                        .unwrap_or("(no summary provided)"),
                    FieldKind::Prose,
                );
                markdown.push_static("\n");

                let has_fixed = advisory.fixed_versions.last().is_some();
                let has_aliases = !advisory.aliases.is_empty();
                if has_fixed || has_aliases {
                    markdown.push_static("  ");
                    if let Some(fixed) = advisory.fixed_versions.last() {
                        // #1423: `fixed_versions` is OSV's wire spelling — convert to this
                        // ecosystem's native namespace before showing it (Go's mandatory `v`
                        // prefix is the live-verified symptom otherwise).
                        let native = formatter.osv_version_to_native(fixed);
                        markdown.push_static("Fixed in: ");
                        markdown.push_code(native.as_str(), FieldKind::Version);
                    }
                    if has_aliases {
                        if has_fixed {
                            markdown.push_static(" \u{b7} ");
                        }
                        markdown.push_static("Aliases: ");
                        // `format_advisory_aliases` already caps/escapes each alias and the
                        // list itself before returning — a pre-sanitized fragment, not raw
                        // OSV text (#1310 critic S1).
                        markdown.push_trusted(format_advisory_aliases(&advisory.aliases));
                    }
                    markdown.push_static("\n");
                }
            }

            let remaining = display_advisories.remaining();
            if remaining > 0 {
                markdown.push_static("- *(+");
                markdown.push_number(remaining);
                markdown.push_static(" more advisories)*\n");
            }

            if let crate::osv::UpgradeStatus::CandidateVulnerable {
                version,
                advisory_ids,
            } = &dv.upgrade_status
                // Deliberately the full (fix-computation) `dv.advisories`, not
                // `display_advisories`: a larger known-severity index only ever makes this
                // informational-suppression check more accurate, never less (#1422).
                && candidate_vulnerable_line_should_render(advisory_ids, dv.advisories.items())
            {
                markdown.push_static("\n\u{26a0}\u{fe0f} Latest version ");
                markdown.push_code(version, FieldKind::Version);
                markdown.push_static(" is also affected.\n");
            }

            markdown.push_static("\n");
        }
        Some(ScanOutcome::Clean) => {
            markdown.push_static("**No known vulnerabilities** (OSV.dev)\n\n");
        }
        Some(ScanOutcome::Skipped(_)) | None => {}
    }
}

/// Cap on how many alias identifiers (CVE, GHSA, ...) [`push_vulnerability_hover_section`]
/// renders from one advisory before collapsing the remainder into "(+N more)" — mirrors
/// [`MAX_LICENSE_ENTRIES_RENDERED`]'s defense-in-depth reasoning for the same kind of
/// OSV-reported, unbounded-count list (#1272).
const MAX_ADVISORY_ALIASES_RENDERED: usize = 8;

/// Formats an advisory's alias list (CVE, GHSA, ...) as an escaped, comma-separated string:
/// each identifier is truncated at [`MAX_DIAGNOSTIC_NAME_CHARS`] (the same id/name-shaped
/// bound `diagnostics.rs` uses), then the count-capped join itself delegates to
/// [`crate::licenses::join_capped`] (capped at [`MAX_ADVISORY_ALIASES_RENDERED`] entries,
/// with a "(+N more)" suffix) rather than a fourth hand-rolled copy of that shape — `aliases`
/// is OSV-reported, unbounded in both dimensions (#1272).
fn format_advisory_aliases(aliases: &[String]) -> String {
    let truncated: Vec<String> = aliases
        .iter()
        .map(|a| super::truncate_for_diagnostic(a, MAX_DIAGNOSTIC_NAME_CHARS).into_owned())
        .collect();
    escape_markdown(&crate::licenses::join_capped(
        &truncated,
        MAX_ADVISORY_ALIASES_RENDERED,
    ))
}

/// Appends the hover "Supply chain" line (spec 037): one line, no `###` header,
/// deliberately lighter than the deprecation/advisory sections above — this signal
/// is informational-only (FR-012) and carries no severity language.
///
/// `signal` is `None` both when no fetch was ever attempted (deps.dev disabled,
/// unsupported ecosystem, no in-use version, ...) and when both deps.dev calls
/// failed or the wait budget elapsed — every case renders nothing, matching
/// FR-006/US-004. A `Some` signal whose scorecard and provenance are *both*
/// `None` (possible only via `SupplyChainTrustSignal::default()`, never returned by
/// `DepsDevClient::trust_signal` itself) also renders nothing, defensively.
fn push_trust_signal_hover_section(
    markdown: &mut HoverMarkdown,
    signal: Option<&SupplyChainTrustSignal>,
) {
    let Some(signal) = signal else {
        return;
    };
    if signal.scorecard.is_none() && signal.provenance.is_none() {
        return;
    }

    let mut parts: Vec<String> = Vec::with_capacity(2);
    if let Some(scorecard) = &signal.scorecard {
        let mut part = format!(
            "OpenSSF Scorecard {}/10",
            markdown_code_span(&format!("{:.1}", scorecard.overall_score))
        );
        if scorecard.self_reported {
            part.push_str(" *(self-reported repo)*");
        }
        parts.push(part);
    }
    if let Some(provenance) = signal.provenance {
        let label = match provenance {
            ProvenanceStatus::Verified => "verified",
            ProvenanceStatus::Unverified => "attested but unverified",
            ProvenanceStatus::None => "none found",
        };
        // "Provenance", not "SLSA provenance": `classify_provenance` unions
        // `slsaProvenances[]` with `attestations[]`, and an attestation's `type` isn't
        // necessarily SLSA — labeling every verified entry as SLSA would misrepresent one
        // that only came from `attestations[]` (critic C3).
        parts.push(format!("Provenance: {label}"));
    }

    // `scorecard.overall_score`/`provenance` are both structurally bounded (a fixed-precision
    // float, a 3-way enum), not attacker-controlled — `push_trusted`.
    markdown.push_static("\u{1f510} **Supply chain**: ");
    markdown.push_trusted(parts.join(" \u{b7} "));
    markdown.push_static("\n\n");
}

/// Cap on how many license identifiers [`format_license_list`] renders from one
/// version's license list before collapsing the remainder into "(+N more)" —
/// defense-in-depth against a malicious/compromised registry response reporting an
/// excessive number of license entries for a single version (security review S3-1).
const MAX_LICENSE_ENTRIES_RENDERED: usize = 8;

/// Formats a license list as comma-separated Markdown code spans, e.g. `` `MIT`, `Apache-2.0` ``.
/// Each identifier is truncated at [`MAX_DIAGNOSTIC_VALUE_CHARS`] — reuses
/// `diagnostics::MAX_DIAGNOSTIC_VALUE_CHARS` directly (issue #1278) rather than declaring a
/// separate constant, for the same untrusted-registry-string concern (security review
/// S3-1) — and the list itself capped at [`MAX_LICENSE_ENTRIES_RENDERED`] entries (with a
/// "(+N more)" suffix) — `licenses` is registry-reported data, not validated or bounded
/// upstream.
fn format_license_list(licenses: &[String]) -> String {
    let shown = licenses.len().min(MAX_LICENSE_ENTRIES_RENDERED);
    #[expect(
        clippy::indexing_slicing,
        reason = "shown is min(licenses.len(), MAX_LICENSE_ENTRIES_RENDERED), always <= \
                  licenses.len()"
    )]
    let mut rendered: Vec<String> = licenses[..shown]
        .iter()
        .map(|l| {
            markdown_code_span(&super::truncate_for_diagnostic(
                l,
                MAX_DIAGNOSTIC_VALUE_CHARS,
            ))
        })
        .collect();
    let remaining = licenses.len() - shown;
    if remaining > 0 {
        rendered.push(format!("(+{remaining} more)"));
    }
    rendered.join(", ")
}

/// Order-insensitive, case-insensitive set comparison for two license lists (spec 010
/// FR-003): a dependency re-declaring the same licenses in a different order or
/// casing (registry `license[]` fields are author-supplied free text, not a
/// normalized enum — e.g. `"MIT"` vs `"mit"`) must not be reported as "changed".
fn license_sets_differ(a: &[String], b: &[String]) -> bool {
    let a_set: std::collections::BTreeSet<String> = a.iter().map(|l| l.to_lowercase()).collect();
    let b_set: std::collections::BTreeSet<String> = b.iter().map(|l| l.to_lowercase()).collect();
    a_set != b_set
}

/// Appends the hover "License" line (issue #204, spec 010): the resolved version's
/// SPDX license identifier(s), and — when the latest version's license is also known
/// and differs (order/case-insensitive) — a "License changed" flag (FR-003).
///
/// `detected` renders the line as "**License (detected)**" instead of "**License**"
/// (issue #660, spec 010 plan §1 "Dart source"/"Swift source" rows, NFR-005 exception;
/// critic S2): Dart's license comes from pub.dev's best-effort `/score` detector tag,
/// and Swift's from GitHub's `licensee`-detected `license.spdx_id`, rather than
/// author-declared registry metadata, so both must be visually distinguished from
/// Gradle/Deno's genuinely registry-declared license fields.
///
/// Renders nothing when `resolved_license` is empty: mirrors
/// [`push_vulnerability_hover_section`]'s discipline of never rendering a positive
/// "License: (unknown)" claim for a dependency this feature never actually checked
/// (no resolved version, an ecosystem/source out of this PR's scope, ...) — spec 010
/// NFR-003 permits either wording or omission for missing data, and omission avoids
/// noise on every dependency this PR simply doesn't cover yet.
///
/// `latest_license` is three-valued (impl-critic review S1): `None` means no latest
/// version exists to compare against at all (no `**Latest**` line was rendered
/// either) — renders no note. `Some(&[])` means a latest version exists but its
/// license could not be determined — renders the "(unavailable)" note. `Some(licenses)`
/// with entries renders a "License changed" flag only when the sets actually differ.
///
/// The "License changed" line is written as its own Markdown paragraph (blank line
/// before it, via `\n\n`) rather than a single `\n` — a lone `\n` is a CommonMark soft
/// break, which strict renderers (e.g. VS Code's hover widget) collapse onto the same
/// visual line as the License line above it (impl-critic review S3).
fn push_license_hover_section(
    markdown: &mut HoverMarkdown,
    resolved_license: &[String],
    latest_license: Option<&[String]>,
    detected: bool,
) {
    if resolved_license.is_empty() {
        return;
    }

    // `format_license_list`'s output is already capped/escaped internally —
    // `push_trusted`, not `push_text`.
    markdown.push_static("**License");
    if detected {
        markdown.push_static(" (detected)");
    }
    markdown.push_static("**: ");
    markdown.push_trusted(format_license_list(resolved_license));

    match latest_license {
        None => {}
        Some([]) => {
            markdown.push_static(" *(latest version license unavailable)*");
        }
        Some(latest) if license_sets_differ(resolved_license, latest) => {
            markdown.push_static("\n\n\u{26a0}\u{fe0f} **License changed**: ");
            markdown.push_trusted(format_license_list(resolved_license));
            markdown.push_static(" \u{2192} ");
            markdown.push_trusted(format_license_list(latest));
        }
        Some(_) => {}
    }
    markdown.push_static("\n\n");
}

#[cfg(test)]
#[expect(
    clippy::cast_possible_truncation,
    reason = "#673: fixed test-fixture lengths cast to u32 for Position fixtures never approach \
              truncation range"
)]
mod tests {
    use super::*;
    use crate::RemovalStatus;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::*;
    use crate::position::{Position, Range};

    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn license_sets_differ_is_order_insensitive() {
        let a = vec!["MIT".to_string(), "Apache-2.0".to_string()];
        let b = vec!["Apache-2.0".to_string(), "MIT".to_string()];
        assert!(!license_sets_differ(&a, &b));
    }

    #[test]
    fn license_sets_differ_detects_real_change() {
        let a = vec!["MIT".to_string()];
        let b = vec!["GPL-3.0".to_string()];
        assert!(license_sets_differ(&a, &b));
    }

    /// impl-critic review M2: `license[]` is author-supplied free text, not a
    /// normalized enum — a casing difference alone must not flag a false change.
    #[test]
    fn license_sets_differ_is_case_insensitive() {
        let a = vec!["MIT".to_string()];
        let b = vec!["mit".to_string()];
        assert!(!license_sets_differ(&a, &b));
    }

    #[test]
    fn format_license_list_caps_entries_and_labels_the_remainder() {
        let licenses: Vec<String> = (0..12).map(|i| format!("LICENSE-{i}")).collect();
        let rendered = format_license_list(&licenses);
        assert!(rendered.contains("(+4 more)"), "got: {rendered}");
        assert!(rendered.contains("`LICENSE-0`"));
        assert!(
            !rendered.contains("LICENSE-11"),
            "the 12th entry must not render; got: {rendered}"
        );
    }

    #[test]
    fn format_license_list_truncates_an_overlong_identifier() {
        let long_id = "A".repeat(500);
        let rendered = format_license_list(std::slice::from_ref(&long_id));
        assert!(
            rendered.len() < long_id.len(),
            "an untrusted, excessively long license id must be truncated; got len {}",
            rendered.len()
        );
    }

    /// #1272: mirrors `format_license_list_caps_entries_and_labels_the_remainder`'s pattern
    /// for `push_vulnerability_hover_section`'s alias list, the same kind of OSV-reported,
    /// unbounded-count list.
    #[test]
    fn format_advisory_aliases_caps_entries_and_labels_the_remainder() {
        // `format_advisory_aliases` runs the joined result through `escape_markdown`
        // (backslash-escaping every ASCII punctuation character), so assertions match
        // against digit substrings rather than the raw `-`-containing id.
        let aliases: Vec<String> = (0..12).map(|i| format!("CVE-2020-{i:04}")).collect();
        let rendered = format_advisory_aliases(&aliases);
        assert!(rendered.contains("+4 more"), "got: {rendered}");
        assert!(rendered.contains("0000"));
        assert!(
            !rendered.contains("0011"),
            "the 12th entry must not render; got: {rendered}"
        );
    }

    #[test]
    fn format_advisory_aliases_truncates_an_overlong_alias() {
        let long_alias = "A".repeat(500);
        let rendered = format_advisory_aliases(std::slice::from_ref(&long_alias));
        assert_eq!(
            rendered,
            format!("{}…", "A".repeat(MAX_DIAGNOSTIC_NAME_CHARS))
        );
    }

    /// #1272 round 2 critic M3: `truncate_for_diagnostic` is char-based, not byte-based —
    /// pin that a multi-byte-per-char alias is cut on a char boundary rather than
    /// panicking or corrupting the string mid-codepoint.
    #[test]
    fn format_advisory_aliases_truncates_a_multi_byte_alias_on_a_char_boundary() {
        let long_alias = "é".repeat(500);
        let rendered = format_advisory_aliases(std::slice::from_ref(&long_alias));
        assert_eq!(
            rendered,
            format!("{}…", "é".repeat(MAX_DIAGNOSTIC_NAME_CHARS))
        );
    }

    /// #1311: `resolved`/`version_requirement` are lockfile- and manifest-controlled,
    /// unbounded-length strings — mirrors the diagnostics.rs `MAX_VERSION_DIAGNOSTIC_CHARS`
    /// truncation test pattern.
    #[test]
    fn push_current_or_requirement_hover_section_truncates_overlong_current() {
        let dep = MockDep {
            name: "pkg".into(),
            version_req: "1.0".into(),
            version_range: Range::default(),
            name_range: Range::default(),
        };
        let long = "9".repeat(5000);
        let mut markdown = HoverMarkdown::new();
        push_current_or_requirement_hover_section(&mut markdown, &dep, Some(&long));
        assert!(markdown.as_str().len() < long.len(), "got: {markdown}");
        assert!(markdown.as_str().contains('…'));
    }

    #[test]
    fn push_current_or_requirement_hover_section_truncates_overlong_requirement() {
        let long = "9".repeat(5000);
        let dep = MockDep {
            name: "pkg".into(),
            version_req: long.as_str().into(),
            version_range: Range::default(),
            name_range: Range::default(),
        };
        let mut markdown = HoverMarkdown::new();
        push_current_or_requirement_hover_section(&mut markdown, &dep, None);
        assert!(markdown.as_str().len() < long.len(), "got: {markdown}");
        assert!(markdown.as_str().contains('…'));
    }

    /// #1310 critic M2: boundary (at cap / over cap) using `MAX_VERSION_DIAGNOSTIC_CHARS`
    /// specifically, not the 5000-char extreme — catches an off-by-one in the cap logic
    /// or a `FieldKind` swap, which an extreme-only test can't (all three kinds resolve
    /// to the same literal 128 today).
    #[test]
    fn push_current_or_requirement_hover_section_current_boundary_at_and_over_cap() {
        let dep = MockDep {
            name: "pkg".into(),
            version_req: "1.0".into(),
            version_range: Range::default(),
            name_range: Range::default(),
        };
        let cap = MAX_VERSION_DIAGNOSTIC_CHARS;

        let at_cap = "9".repeat(cap);
        let mut markdown = HoverMarkdown::new();
        push_current_or_requirement_hover_section(&mut markdown, &dep, Some(&at_cap));
        assert_eq!(markdown.as_str(), format!("**Current**: `{at_cap}`\n\n"));

        let over_cap = "9".repeat(cap + 1);
        let mut markdown = HoverMarkdown::new();
        push_current_or_requirement_hover_section(&mut markdown, &dep, Some(&over_cap));
        assert_eq!(
            markdown.as_str(),
            format!("**Current**: `{}…`\n\n", "9".repeat(cap))
        );
    }

    #[test]
    fn push_current_or_requirement_hover_section_requirement_boundary_at_and_over_cap() {
        let cap = MAX_VERSION_DIAGNOSTIC_CHARS;

        let at_cap = "9".repeat(cap);
        let dep = MockDep {
            name: "pkg".into(),
            version_req: at_cap.as_str().into(),
            version_range: Range::default(),
            name_range: Range::default(),
        };
        let mut markdown = HoverMarkdown::new();
        push_current_or_requirement_hover_section(&mut markdown, &dep, None);
        assert_eq!(
            markdown.as_str(),
            format!("**Requirement**: `{at_cap}`\n\n")
        );

        let over_cap = "9".repeat(cap + 1);
        let dep = MockDep {
            name: "pkg".into(),
            version_req: over_cap.as_str().into(),
            version_range: Range::default(),
            name_range: Range::default(),
        };
        let mut markdown = HoverMarkdown::new();
        push_current_or_requirement_hover_section(&mut markdown, &dep, None);
        assert_eq!(
            markdown.as_str(),
            format!("**Requirement**: `{}…`\n\n", "9".repeat(cap))
        );
    }

    /// #1311/#1313: `resolved`/`version_requirement` are `FieldKind::Version`, so they
    /// must strip a `sanitize_invisible`-only codepoint (U+0600 ARABIC NUMBER SIGN)
    /// that `is_markdown_unsafe` alone does not catch — deliberately exempt per
    /// #1248/#1323.
    #[test]
    fn push_current_or_requirement_hover_section_strips_u0600() {
        let value = format!("1.0{}0", '\u{0600}');
        let dep = MockDep {
            name: "pkg".into(),
            version_req: value.as_str().into(),
            version_range: Range::default(),
            name_range: Range::default(),
        };

        let mut markdown = HoverMarkdown::new();
        push_current_or_requirement_hover_section(&mut markdown, &dep, Some(&value));
        assert!(!markdown.as_str().contains('\u{0600}'), "got: {markdown}");

        let mut markdown = HoverMarkdown::new();
        push_current_or_requirement_hover_section(&mut markdown, &dep, None);
        assert!(!markdown.as_str().contains('\u{0600}'), "got: {markdown}");
    }

    #[test]
    fn push_markers_hover_section_truncates_overlong_marker_expr() {
        let long = "x".repeat(5000);
        let dep = MockMarkedDep {
            name: "pkg".into(),
            name_range: Range::default(),
            markers: Some(long.clone()),
        };
        let mut markdown = HoverMarkdown::new();
        push_markers_hover_section(&mut markdown, &dep);
        assert!(markdown.as_str().len() < long.len(), "got: {markdown}");
        assert!(markdown.as_str().contains('…'));
    }

    /// #1310 critic M2: boundary case using `MAX_DIAGNOSTIC_NAME_CHARS` specifically —
    /// `marker_expr` moved off `FieldKind::Prose` onto `FieldKind::Name` (#1313
    /// reclassification), so this now matches the name-shaped cap, not the prose one.
    #[test]
    fn push_markers_hover_section_boundary_at_and_over_cap() {
        let cap = MAX_DIAGNOSTIC_NAME_CHARS;

        let at_cap = "x".repeat(cap);
        let dep = MockMarkedDep {
            name: "pkg".into(),
            name_range: Range::default(),
            markers: Some(at_cap.clone()),
        };
        let mut markdown = HoverMarkdown::new();
        push_markers_hover_section(&mut markdown, &dep);
        assert_eq!(
            markdown.as_str(),
            format!("**Active when**: `{at_cap}`\n\n")
        );

        let over_cap = "x".repeat(cap + 1);
        let dep = MockMarkedDep {
            name: "pkg".into(),
            name_range: Range::default(),
            markers: Some(over_cap),
        };
        let mut markdown = HoverMarkdown::new();
        push_markers_hover_section(&mut markdown, &dep);
        assert_eq!(
            markdown.as_str(),
            format!("**Active when**: `{}…`\n\n", "x".repeat(cap))
        );
    }

    #[test]
    fn push_latest_hover_section_truncates_overlong_latest_version() {
        let long = "9".repeat(5000);
        let mut markdown = HoverMarkdown::new();
        push_latest_hover_section(
            &mut markdown,
            Some((long.as_str(), None)),
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        );
        assert!(markdown.as_str().len() < long.len(), "got: {markdown}");
        assert!(markdown.as_str().contains('…'));
    }

    /// #1310 critic M2: boundary case using `MAX_VERSION_DIAGNOSTIC_CHARS` specifically.
    #[test]
    fn push_latest_hover_section_boundary_at_and_over_cap() {
        let cap = MAX_VERSION_DIAGNOSTIC_CHARS;

        let at_cap = "9".repeat(cap);
        let mut markdown = HoverMarkdown::new();
        push_latest_hover_section(
            &mut markdown,
            Some((at_cap.as_str(), None)),
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        );
        assert_eq!(markdown.as_str(), format!("**Latest**: `{at_cap}`\n\n"));

        let over_cap = "9".repeat(cap + 1);
        let mut markdown = HoverMarkdown::new();
        push_latest_hover_section(
            &mut markdown,
            Some((over_cap.as_str(), None)),
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        );
        assert_eq!(
            markdown.as_str(),
            format!("**Latest**: `{}…`\n\n", "9".repeat(cap))
        );
    }

    /// #1311/#1313: `latest_ver` is `FieldKind::Version`, so it must strip a
    /// `sanitize_invisible`-only codepoint (U+0600 ARABIC NUMBER SIGN) that
    /// `is_markdown_unsafe` alone does not catch — deliberately exempt per #1248/#1323.
    #[test]
    fn push_latest_hover_section_strips_u0600() {
        let value = format!("1.0{}0", '\u{0600}');
        let mut markdown = HoverMarkdown::new();
        push_latest_hover_section(
            &mut markdown,
            Some((value.as_str(), None)),
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        );
        assert!(!markdown.as_str().contains('\u{0600}'), "got: {markdown}");
    }

    #[test]
    fn push_recent_versions_hover_section_truncates_overlong_version_string() {
        let long = "9".repeat(5000);
        let versions: Vec<Box<dyn crate::Version>> = vec![Box::new(TestVersion {
            version: long.as_str().into(),
            yanked: false,
        })];
        let mut markdown = HoverMarkdown::new();
        push_recent_versions_hover_section(
            &mut markdown,
            &versions,
            None,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
            &MOCK_FORMATTER,
        );
        assert!(markdown.as_str().len() < long.len(), "got: {markdown}");
        assert!(markdown.as_str().contains('…'));
    }

    /// #1310 critic M2: boundary case using `MAX_VERSION_DIAGNOSTIC_CHARS` specifically.
    #[test]
    fn push_recent_versions_hover_section_boundary_at_and_over_cap() {
        let cap = MAX_VERSION_DIAGNOSTIC_CHARS;

        let at_cap = "9".repeat(cap);
        let versions: Vec<Box<dyn crate::Version>> = vec![Box::new(TestVersion {
            version: at_cap.as_str().into(),
            yanked: false,
        })];
        let mut markdown = HoverMarkdown::new();
        push_recent_versions_hover_section(
            &mut markdown,
            &versions,
            None,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
            &MOCK_FORMATTER,
        );
        assert_eq!(
            markdown.as_str(),
            format!("**Recent versions**:\n- `{at_cap}`\n")
        );

        let over_cap = "9".repeat(cap + 1);
        let versions: Vec<Box<dyn crate::Version>> = vec![Box::new(TestVersion {
            version: over_cap.as_str().into(),
            yanked: false,
        })];
        let mut markdown = HoverMarkdown::new();
        push_recent_versions_hover_section(
            &mut markdown,
            &versions,
            None,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
            &MOCK_FORMATTER,
        );
        assert_eq!(
            markdown.as_str(),
            format!("**Recent versions**:\n- `{}…`\n", "9".repeat(cap))
        );
    }

    /// #1311/#1313: `version_string()` is `FieldKind::Version`, so it must strip a
    /// `sanitize_invisible`-only codepoint (U+0600 ARABIC NUMBER SIGN) that
    /// `is_markdown_unsafe` alone does not catch — deliberately exempt per #1248/#1323.
    #[test]
    fn push_recent_versions_hover_section_strips_u0600() {
        let value = format!("1.0{}0", '\u{0600}');
        let versions: Vec<Box<dyn crate::Version>> = vec![Box::new(TestVersion {
            version: value.as_str().into(),
            yanked: false,
        })];
        let mut markdown = HoverMarkdown::new();
        push_recent_versions_hover_section(
            &mut markdown,
            &versions,
            None,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
            &MOCK_FORMATTER,
        );
        assert!(!markdown.as_str().contains('\u{0600}'), "got: {markdown}");
    }

    #[test]
    fn push_deprecation_hover_section_truncates_overlong_reason_and_replacement() {
        let long_reason = "r".repeat(5000);
        let long_replacement = "p".repeat(5000);
        let deprecation = Deprecation {
            reason: Some(long_reason.clone()),
            replacement: Some(long_replacement.clone()),
        };
        let mut markdown = HoverMarkdown::new();
        push_deprecation_hover_section(&mut markdown, &MOCK_FORMATTER, Some(&deprecation));
        assert!(
            markdown.as_str().len() < long_reason.len() + long_replacement.len(),
            "got: {markdown}"
        );
        assert!(markdown.as_str().contains('…'));
    }

    /// #1310 critic M2: boundary case using `MAX_DIAGNOSTIC_PROSE_CHARS` specifically,
    /// for `reason` (via `push_text`).
    #[test]
    fn push_deprecation_hover_section_reason_boundary_at_and_over_cap() {
        let cap = MAX_DIAGNOSTIC_PROSE_CHARS;

        let at_cap = "r".repeat(cap);
        let deprecation = Deprecation {
            reason: Some(at_cap.clone()),
            replacement: None,
        };
        let mut markdown = HoverMarkdown::new();
        push_deprecation_hover_section(&mut markdown, &MOCK_FORMATTER, Some(&deprecation));
        assert!(
            markdown.as_str().contains(&format!("{at_cap}\n\n")),
            "got: {markdown}"
        );
        assert!(!markdown.as_str().contains('…'));

        let over_cap = "r".repeat(cap + 1);
        let deprecation = Deprecation {
            reason: Some(over_cap),
            replacement: None,
        };
        let mut markdown = HoverMarkdown::new();
        push_deprecation_hover_section(&mut markdown, &MOCK_FORMATTER, Some(&deprecation));
        assert!(
            markdown
                .as_str()
                .contains(&format!("{}…\n\n", "r".repeat(cap))),
            "got: {markdown}"
        );
    }

    /// Same as above, for `replacement` (via `push_code`) — `MAX_DIAGNOSTIC_NAME_CHARS`,
    /// not `MAX_DIAGNOSTIC_PROSE_CHARS`: `replacement` moved off `FieldKind::Prose` onto
    /// `FieldKind::Name` (#1313 reclassification, a package name is not free prose).
    #[test]
    fn push_deprecation_hover_section_replacement_boundary_at_and_over_cap() {
        let cap = MAX_DIAGNOSTIC_NAME_CHARS;

        let at_cap = "p".repeat(cap);
        let deprecation = Deprecation {
            reason: None,
            replacement: Some(at_cap.clone()),
        };
        let mut markdown = HoverMarkdown::new();
        push_deprecation_hover_section(&mut markdown, &MOCK_FORMATTER, Some(&deprecation));
        assert!(
            markdown
                .as_str()
                .contains(&format!("Suggested replacement: `{at_cap}`\n\n")),
            "got: {markdown}"
        );

        let over_cap = "p".repeat(cap + 1);
        let deprecation = Deprecation {
            reason: None,
            replacement: Some(over_cap),
        };
        let mut markdown = HoverMarkdown::new();
        push_deprecation_hover_section(&mut markdown, &MOCK_FORMATTER, Some(&deprecation));
        assert!(
            markdown.as_str().contains(&format!(
                "Suggested replacement: `{}…`\n\n",
                "p".repeat(cap)
            )),
            "got: {markdown}"
        );
    }

    /// #1309 regression guard: the length cap must not reintroduce a bidi/invisible
    /// spoofing gap — `deprecation.reason` still goes through `escape_markdown`'s
    /// narrow filter, which deliberately preserves ZWJ (U+200D) while blocking the
    /// RLO override (U+202E).
    #[test]
    fn push_deprecation_hover_section_still_blocks_rlo_override_after_truncation() {
        let reason = format!("safe {}text", '\u{202e}');
        let deprecation = Deprecation {
            reason: Some(reason),
            replacement: None,
        };
        let mut markdown = HoverMarkdown::new();
        push_deprecation_hover_section(&mut markdown, &MOCK_FORMATTER, Some(&deprecation));
        assert!(
            !markdown.as_str().contains('\u{202e}'),
            "RLO override must still be blocked; got: {markdown:?}"
        );
    }

    /// #1313 reclassification: `deprecation.replacement` moved off `FieldKind::Prose`
    /// onto `FieldKind::Name`, so it must now strip a `sanitize_invisible`-only
    /// codepoint (U+0600 ARABIC NUMBER SIGN, deliberately exempt from
    /// `is_markdown_unsafe` per #1248/#1323) that `is_markdown_unsafe` alone does not
    /// catch — the exact gap #1313's own doc names as #1311's still-open example.
    #[test]
    fn push_deprecation_hover_section_replacement_strips_u0600() {
        let replacement = format!("left{}pad", '\u{0600}');
        let deprecation = Deprecation {
            reason: None,
            replacement: Some(replacement),
        };
        let mut markdown = HoverMarkdown::new();
        push_deprecation_hover_section(&mut markdown, &MOCK_FORMATTER, Some(&deprecation));
        assert!(
            !markdown.as_str().contains('\u{0600}'),
            "U+0600 must be stripped from the name-shaped replacement field; got: {markdown:?}"
        );
    }

    /// `deprecation.reason` is genuine prose and stays on `FieldKind::Prose` — it must
    /// still carry U+0600 and legitimate RTL marks unchanged (by design), so this
    /// reclassification doesn't accidentally sweep the one field that must stay
    /// untouched. Uses U+0600 rather than U+206A (the pre-#1323 exemplar): #1323
    /// widened `is_markdown_unsafe` to block U+206A even in Prose, via `Hover::new`'s
    /// whole-document sweep, while U+0600 remains deliberately exempt (#1248/#1323).
    #[test]
    fn push_deprecation_hover_section_reason_does_not_strip_u0600_or_rtl_marks() {
        let reason = format!("note{} with RTL{}mark", '\u{0600}', '\u{200f}');
        let deprecation = Deprecation {
            reason: Some(reason),
            replacement: None,
        };
        let mut markdown = HoverMarkdown::new();
        push_deprecation_hover_section(&mut markdown, &MOCK_FORMATTER, Some(&deprecation));
        assert!(
            markdown.as_str().contains('\u{0600}') && markdown.as_str().contains('\u{200f}'),
            "reason (Prose) must preserve U+0600 and RTL marks unchanged; got: {markdown:?}"
        );
    }

    /// #1313 reclassification: `marker_expr` moved off `FieldKind::Prose` onto
    /// `FieldKind::Name`, so it must now strip U+0600 too.
    #[test]
    fn push_markers_hover_section_strips_u0600() {
        let dep = MockMarkedDep {
            name: "pkg".into(),
            name_range: Range::default(),
            markers: Some(format!("python_version{}>= '3.8'", '\u{0600}')),
        };
        let mut markdown = HoverMarkdown::new();
        push_markers_hover_section(&mut markdown, &dep);
        assert!(
            !markdown.as_str().contains('\u{0600}'),
            "U+0600 must be stripped from the name-shaped marker expression; got: {markdown:?}"
        );
    }

    #[test]
    fn push_license_hover_section_renders_nothing_when_resolved_unknown() {
        let mut markdown = HoverMarkdown::new();
        push_license_hover_section(&mut markdown, &[], Some(&["MIT".to_string()]), false);
        assert!(markdown.as_str().is_empty());
    }

    /// impl-critic review S1: no latest version exists at all (`None`, distinct from
    /// `Some(&[])`) — no note should render, since nothing was ever shown to compare
    /// against.
    #[test]
    fn push_license_hover_section_renders_nothing_extra_when_no_latest_version_exists() {
        let mut markdown = HoverMarkdown::new();
        push_license_hover_section(&mut markdown, &["MIT".to_string()], None, false);
        assert!(markdown.as_str().contains("**License**: `MIT`"));
        assert!(!markdown.as_str().contains("unavailable"));
        assert!(!markdown.as_str().contains("License changed"));
    }

    #[test]
    fn push_license_hover_section_renders_resolved_only_when_latest_unavailable() {
        let mut markdown = HoverMarkdown::new();
        push_license_hover_section(&mut markdown, &["MIT".to_string()], Some(&[]), false);
        assert!(markdown.as_str().contains("**License**: `MIT`"));
        assert!(
            markdown
                .as_str()
                .contains("latest version license unavailable")
        );
        assert!(!markdown.as_str().contains("License changed"));
    }

    #[test]
    fn push_license_hover_section_flags_change_when_licenses_differ() {
        let mut markdown = HoverMarkdown::new();
        push_license_hover_section(
            &mut markdown,
            &["MIT".to_string()],
            Some(&["Apache-2.0".to_string()]),
            false,
        );
        assert!(markdown.as_str().contains("**License**: `MIT`"));
        assert!(markdown.as_str().contains("License changed"));
        assert!(markdown.as_str().contains("`MIT` \u{2192} `Apache-2.0`"));
    }

    /// Issue #660: Dart's best-effort detected license must render with the
    /// "(detected)" qualifier, distinguishing it from every other ecosystem's
    /// genuinely registry-declared license field (spec 010 NFR-005 exception).
    #[test]
    fn push_license_hover_section_detected_flag_adds_qualifier() {
        let mut markdown = HoverMarkdown::new();
        push_license_hover_section(&mut markdown, &["MIT".to_string()], None, true);
        assert!(markdown.as_str().contains("**License (detected)**: `MIT`"));
    }

    /// impl-critic review S3: the "License changed" line must be its own Markdown
    /// paragraph (blank line before it), not a bare `\n` soft break that a strict
    /// CommonMark renderer (VS Code's hover widget) would collapse onto the License
    /// line above it.
    #[test]
    fn push_license_hover_section_change_line_is_a_separate_paragraph() {
        let mut markdown = HoverMarkdown::new();
        push_license_hover_section(
            &mut markdown,
            &["MIT".to_string()],
            Some(&["Apache-2.0".to_string()]),
            false,
        );
        assert!(
            markdown
                .as_str()
                .contains("`MIT`\n\n\u{26a0}\u{fe0f} **License changed**"),
            "expected a blank line (paragraph break) before the License changed line; got: {markdown:?}"
        );
    }

    #[test]
    fn push_license_hover_section_no_flag_when_licenses_equal() {
        let mut markdown = HoverMarkdown::new();
        push_license_hover_section(
            &mut markdown,
            &["MIT".to_string()],
            Some(&["MIT".to_string()]),
            false,
        );
        assert!(markdown.as_str().contains("**License**: `MIT`"));
        assert!(!markdown.as_str().contains("License changed"));
        assert!(!markdown.as_str().contains("unavailable"));
    }

    /// Issue #204 end-to-end: a native version-list source (Composer/tier-1 shape,
    /// via `MockRegistryWithLicensedVersions`) whose resolved and latest versions
    /// carry different licenses renders both the resolved license and the "License
    /// changed" flag in the actual hover response.
    #[tokio::test]
    async fn test_generate_hover_renders_license_changed_from_native_version_list() {
        use std::collections::HashMap;

        let registry = MockRegistryWithLicensedVersions {
            versions: vec![
                MockVersionWithLicense {
                    version: "2.0.0".into(),
                    license: vec!["Apache-2.0".to_string()],
                },
                MockVersionWithLicense {
                    version: "1.0.0".into(),
                    license: vec!["MIT".to_string()],
                },
            ],
        };
        let parse_result = freshness_test_parse_result("example");
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example".into(), "1.0.0".into());

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(content.contains("**License**: `MIT`"), "got: {}", content);
        assert!(
            content.contains("License changed"),
            "resolved (1.0.0/MIT) and latest (2.0.0/Apache-2.0) licenses differ; got: {}",
            content
        );
    }

    /// Critic finding S1 (#905): `position_in_range` is inclusive on both ends, so without a
    /// guard, hovering the document's very first character — the typical `Range::default()`
    /// sentinel a synthetic `name_range()` resolves to (e.g. `deps-dart`'s container-anchor
    /// alias resolution) — would match whichever such dependency `dependencies()` lists first,
    /// showing hover info for an arbitrary unrelated package instead of nothing.
    #[tokio::test]
    async fn test_generate_hover_does_not_match_a_synthetic_range_dependency_at_position_zero() {
        use std::collections::HashMap;

        let parse_result = MockMixedParseResult {
            deps: vec![
                Box::new(MockSyntheticRangeDep {
                    name: "synthetic-pkg".into(),
                }),
                Box::new(MockDep {
                    name: "real-pkg".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(3, 10), Position::new(3, 20)),
                    name_range: Range::new(Position::new(3, 0), Position::new(3, 8)),
                }),
            ],
            uri: crate::test_util::test_uri("/test/pubspec.yaml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 0).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await;

        assert!(
            hover.is_none(),
            "position (0,0) must not match the synthetic-range dependency's \
             Range::default() sentinel"
        );
    }

    /// #1161 M1 (critic follow-up): a dependency whose `version_range()` is `Some` but which
    /// has no `version_requirement()` at all — e.g. Maven's `<version></version>`, whose
    /// zero-width `version_range()` exists purely so completion can locate the dependency —
    /// must not match on `version_range()` alone. Without the `version_requirement().is_some()`
    /// gate, hovering exactly at that position would fire a registry fetch for a dependency
    /// that every other consumer (diagnostics, inlay hints) treats as having no version range.
    #[tokio::test]
    async fn test_generate_hover_does_not_match_version_range_with_no_requirement() {
        use std::collections::HashMap;

        let version_range = Range::new(Position::new(5, 15), Position::new(5, 15));
        let parse_result = MockMixedParseResult {
            deps: vec![Box::new(MockNoRequirementDep {
                name: "com.example:foo".into(),
                name_range: Range::new(Position::new(4, 18), Position::new(4, 21)),
                version_range,
            })],
            uri: crate::test_util::test_uri("/test/pom.xml"),
        };

        let hover = generate_hover(
            &parse_result,
            version_range.start.into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await;

        assert!(
            hover.is_none(),
            "must not match a version_range with no version_requirement behind it"
        );
    }

    /// #1161 M1 code-review follow-up (second round): a REAL, non-empty `version_range()`
    /// with no `version_requirement()` — Gradle's version-catalog `version.ref` pointing at a
    /// dangling or rich-version `[versions]` alias, whose `version_range()` spans the real
    /// alias-reference text (`crates/deps-gradle/src/parser/catalog.rs`'s `extract_version`)
    /// — is a genuinely different shape from Maven's zero-width degenerate position, and must
    /// still match here: hovering it worked before #1161, and a blanket
    /// `version_requirement().is_some()` gate would have silently broken it.
    #[tokio::test]
    async fn test_generate_hover_matches_non_empty_version_range_with_no_requirement() {
        use std::collections::HashMap;

        let version_range = Range::new(Position::new(4, 40), Position::new(4, 45));
        let parse_result = MockMixedParseResult {
            deps: vec![Box::new(MockNoRequirementDep {
                name: "com.example:guava".into(),
                name_range: Range::new(Position::new(4, 18), Position::new(4, 21)),
                version_range,
            })],
            uri: crate::test_util::test_uri("/test/libs.versions.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            version_range.start.into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await;

        assert!(
            hover.is_some(),
            "must match a real, non-empty version_range even with no version_requirement"
        );
    }

    /// impl-critic review S1: when the resolved version *is* the latest version (the
    /// common up-to-date case), the resolved license must be reused for the latest
    /// comparison instead of re-deriving it — must render neither a spurious
    /// "(unavailable)" note nor a self-vs-self "License changed" flag.
    #[tokio::test]
    async fn test_generate_hover_up_to_date_dependency_shows_no_spurious_unavailable_note() {
        use std::collections::HashMap;

        let registry = MockRegistryWithLicensedVersions {
            versions: vec![MockVersionWithLicense {
                version: "1.0.0".into(),
                license: vec!["MIT".to_string()],
            }],
        };
        let parse_result = freshness_test_parse_result("example");
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example".into(), "1.0.0".into());

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(content.contains("**License**: `MIT`"));
        assert!(
            !content.contains("unavailable"),
            "the resolved version is the latest version, so its already-known license \
             must be reused rather than reported unavailable; got: {}",
            content
        );
        assert!(
            !content.contains("License changed"),
            "resolved and latest are the same version, so no change flag should fire; got: {}",
            content
        );
    }

    /// impl-critic review M1: an exact manifest pin (`=1.0.0`) with no lock-file
    /// resolution renders no `**Current**` line (`resolved` stays `None` —
    /// `resolve_occurrence_version` has nothing to match against an empty
    /// `resolved_versions` map), but the license must still be found via the same
    /// `resolve_in_use_version` concrete-pin fallback `spawn_trust_signal_fetch` already
    /// uses for the deps.dev path — the native-list lookup must be at least as
    /// capable, not silently weaker just because it reused the `resolved` variable.
    #[tokio::test]
    async fn test_generate_hover_native_list_license_found_via_concrete_pin_fallback() {
        use std::collections::HashMap;

        let registry = MockRegistryWithLicensedVersions {
            versions: vec![MockVersionWithLicense {
                version: "1.0.0".into(),
                license: vec!["MIT".to_string()],
            }],
        };
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "example".into(),
                version_req: "=1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 7)),
            }],
            uri: crate::test_util::test_uri("/test/composer.json"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new())
                .with_ecosystem(crate::EcosystemId::Composer),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            !content.contains("**Current**"),
            "no lock-file resolution exists, so no Current line should render; got: {}",
            content
        );
        assert!(
            content.contains("**License**: `MIT`"),
            "the concrete-pin fallback (=1.0.0) should still resolve a license even \
             without a lock-file match; got: {}",
            content
        );
    }

    /// Issue #660 (spec 010 plan §1 tier 3): with no license in the native version list
    /// and no deps.dev trust signal, the only remaining source is
    /// `VersionData::license_prefetch` — and for the Dart ecosystem specifically, the
    /// line must carry the "(detected)" qualifier (NFR-005 exception).
    #[tokio::test]
    async fn test_generate_hover_dart_license_from_prefetch_is_labeled_detected() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("example");
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example".into(), "1.0.0".into());
        let mut licenses = HashMap::new();
        licenses.insert(
            crate::PackageName::new("example"),
            vec!["BSD-3-Clause".to_string()],
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Dart)
                .with_license_source(crate::LicenseSource::DetectedSpdx)
                .with_license_prefetch(&licenses),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**License (detected)**: `BSD-3-Clause`"),
            "got: {}",
            content
        );
    }

    /// Same tier-3 pre-fetch source as above, for Swift: GitHub's `license.spdx_id` is
    /// `licensee` detector output on the repo's default branch, not an author-declared
    /// registry field, so it must carry the same "(detected)" qualifier as Dart's
    /// pana-detected license (critic S2 — the doc comment previously claiming every
    /// non-Dart source is "author-declared registry metadata" was factually wrong for
    /// Swift specifically).
    #[tokio::test]
    async fn test_generate_hover_swift_license_from_prefetch_is_labeled_detected() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("example");
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example".into(), "1.0.0".into());
        let mut licenses = HashMap::new();
        licenses.insert(
            crate::PackageName::new("example"),
            vec!["Apache-2.0".to_string()],
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Swift)
                .with_license_source(crate::LicenseSource::DetectedSpdx)
                .with_license_prefetch(&licenses),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**License (detected)**: `Apache-2.0`"),
            "got: {}",
            content
        );
    }

    /// Tier-3 pre-fetch source for Gradle (a genuine registry-declared POM
    /// `<licenses>` field, not detector output): the license line must render as plain
    /// "**License**", with no "(detected)" qualifier — that label is Dart/Swift-only.
    #[tokio::test]
    async fn test_generate_hover_gradle_license_from_prefetch_is_not_labeled_detected() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("example");
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example".into(), "1.0.0".into());
        let mut licenses = HashMap::new();
        licenses.insert(
            crate::PackageName::new("example"),
            vec!["Apache-2.0".to_string()],
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Gradle)
                .with_license_source(crate::LicenseSource::PomFreeText)
                .with_license_prefetch(&licenses),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**License**: `Apache-2.0`"),
            "got: {}",
            content
        );
        assert!(!content.contains("(detected)"));
    }

    /// Issue #687: hover must render the *normalized* SPDX id for a recognized Gradle
    /// POM free-text `<license><name>` value, not the raw POM text — matching what
    /// `generate_diagnostics_from_cache`'s license-policy rule evaluates for the same
    /// dependency (`resolve_license_entries_for_display`, driven by
    /// [`crate::LicenseSource::PomFreeText`], is the single normalization call site both
    /// read through). See the two tests below for the unrecognized-entry and
    /// ambiguous-SPDX-convention cases this function's display semantics diverge from
    /// the policy-evaluation `resolve_license_entries` for (issue #687 critic S1/S2).
    #[tokio::test]
    async fn test_generate_hover_gradle_pom_free_text_license_is_normalized() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("example");
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example".into(), "1.0.0".into());
        let mut licenses = HashMap::new();
        licenses.insert(
            crate::PackageName::new("example"),
            vec!["The Apache Software License, Version 2.0".to_string()],
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Gradle)
                .with_license_source(crate::LicenseSource::PomFreeText)
                .with_license_prefetch(&licenses),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**License**: `Apache-2.0`"),
            "expected the normalized SPDX id, not raw POM text, got: {}",
            content
        );
        assert!(!content.contains("The Apache Software License"));
    }

    /// Issue #687 critic S1: a Gradle POM free-text license the normalization table
    /// doesn't recognize must still render *something* in hover — falling back to the
    /// raw POM text — rather than vanishing entirely. `KNOWN_POM_LICENSE_NAMES` is
    /// deliberately non-exhaustive (see `deps_core::licenses`' module docs), so this is
    /// the designed-for path, not a rare edge case: before this fix, routing hover
    /// through the same fail-closed function `generate_diagnostics_from_cache` uses for
    /// policy evaluation dropped the entry and `push_license_hover_section` rendered no
    /// License line at all.
    #[tokio::test]
    async fn test_generate_hover_gradle_unrecognized_pom_license_falls_back_to_raw_text() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("example");
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example".into(), "1.0.0".into());
        let mut licenses = HashMap::new();
        licenses.insert(
            crate::PackageName::new("example"),
            vec!["Some Bespoke Corporate License".to_string()],
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Gradle)
                .with_license_source(crate::LicenseSource::PomFreeText)
                .with_license_prefetch(&licenses),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**License**: `Some Bespoke Corporate License`"),
            "expected the raw POM text as a fallback, got: {}",
            content
        );
    }

    /// Issue #687 critic S2: a POM free-text license ambiguous between SPDX conventions
    /// (the GPL/LGPL/AGPL families) normalizes to a multi-id synonym slice for policy
    /// matching (`GPL-3.0`/`GPL-3.0-only`/`GPL-3.0-or-later`, so a `deny`/`allow` list
    /// written in any convention still matches) — but hover must render only the single
    /// canonical id, not all three, since this is genuinely one declared license, not
    /// three.
    #[tokio::test]
    async fn test_generate_hover_gradle_gpl_family_renders_single_canonical_id() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("example");
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example".into(), "1.0.0".into());
        let mut licenses = HashMap::new();
        licenses.insert(
            crate::PackageName::new("example"),
            vec!["GNU General Public License v3".to_string()],
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Gradle)
                .with_license_source(crate::LicenseSource::PomFreeText)
                .with_license_prefetch(&licenses),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**License**: `GPL-3.0`"),
            "expected exactly one canonical id, got: {}",
            content
        );
        assert!(
            !content.contains("GPL-3.0-only") && !content.contains("GPL-3.0-or-later"),
            "must not render the full policy-matching synonym slice in hover, got: {}",
            content
        );
    }

    /// Code-review must-fix: unlike the GPL-family case above, `"CDDL + GPLv2 with
    /// classpath exception"` normalizes to two SPDX ids naming two genuinely different
    /// licenses (`CDDL-1.1` and `GPL-2.0-with-classpath-exception`), not synonyms of
    /// one — collapsing this to a single id would misrepresent a dual-licensed
    /// dependency as solely CDDL-licensed. Both ids must render.
    #[tokio::test]
    async fn test_generate_hover_gradle_disjunctive_license_renders_both_ids() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("example");
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example".into(), "1.0.0".into());
        let mut licenses = HashMap::new();
        licenses.insert(
            crate::PackageName::new("example"),
            vec!["CDDL + GPLv2 with classpath exception".to_string()],
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Gradle)
                .with_license_source(crate::LicenseSource::PomFreeText)
                .with_license_prefetch(&licenses),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("CDDL-1.1") && content.contains("GPL-2.0-with-classpath-exception"),
            "expected both disjunctive ids, got: {}",
            content
        );
    }

    /// Review round 3 regression: for a deps.dev-routed ecosystem, `available_versions[idx]`
    /// entries never carry license (that trait method's default is empty — only the
    /// native-list ecosystems like Composer override it), so the "latest == resolved"
    /// shortcut MUST use the same `resolve_in_use_version`-derived key the resolved-license
    /// lookup itself used, not the weaker bare `resolved`. An earlier draft compared
    /// the shortcut against `resolved` (which stays `None` here — no lock-file entry
    /// matches an exact `=4.19.2` pin) while the lookup used `in_use_version_str`
    /// (which resolves the pin via `concrete_pin_version`): the mismatch made the
    /// shortcut miss, falling through to the empty-by-default native-list branch and
    /// re-introducing S1's spurious "(latest version license unavailable)" note right
    /// next to an already-known, unchanged license.
    #[tokio::test]
    async fn test_generate_hover_deps_dev_no_lockfile_exact_pin_matching_latest_reuses_license() {
        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [], "licenses": ["MIT"]}"#,
            )
            .create_async()
            .await;
        let deps_dev = Arc::new(deps_dev);

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "express".into(),
                version_req: "=4.19.2".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 7)),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };
        // No lock-file entries: `versions.resolved` stays empty, so the bare
        // `resolved` variable used for the `**Current**` line has no match — only
        // `resolve_in_use_version`'s `concrete_pin_version` fallback resolves the pin.
        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "4.19.2".into(),
                yanked: false,
                published_at: None,
            }],
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new())
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            !content.contains("**Current**"),
            "no lock-file resolution exists, so no Current line should render; got: {}",
            content
        );
        assert!(content.contains("**License**: `MIT`"), "got: {}", content);
        assert!(
            !content.contains("unavailable"),
            "the exact pin (4.19.2) equals the only/live-latest version, so the \
             already-known license must be reused, not reported unavailable; got: {}",
            content
        );
        assert!(!content.contains("License changed"));
    }

    #[test]
    fn severity_label_for_malicious_is_distinct_from_unknown_and_every_graded_label() {
        let malicious = severity_label(crate::osv::VulnSeverity::Malicious);
        assert_ne!(malicious, "unknown severity");
        for graded in [
            crate::osv::VulnSeverity::Critical,
            crate::osv::VulnSeverity::High,
            crate::osv::VulnSeverity::Medium,
            crate::osv::VulnSeverity::Low,
        ] {
            assert_ne!(malicious, severity_label(graded));
        }
    }

    #[test]
    fn severity_label_for_informational_is_distinct_from_unknown_and_every_graded_label() {
        // FR-003 (issue #1007): a maintenance-status notice must never
        // render as "unknown severity" or any graded label.
        let informational = severity_label(crate::osv::VulnSeverity::Informational);
        assert_ne!(informational, "unknown severity");
        assert_ne!(
            informational,
            severity_label(crate::osv::VulnSeverity::Malicious)
        );
        for graded in [
            crate::osv::VulnSeverity::Critical,
            crate::osv::VulnSeverity::High,
            crate::osv::VulnSeverity::Medium,
            crate::osv::VulnSeverity::Low,
        ] {
            assert_ne!(informational, severity_label(graded));
        }
    }

    #[test]
    fn candidate_vulnerable_line_suppressed_only_when_every_id_is_known_informational() {
        use crate::osv::{Capped, VulnSeverity};

        let informational = sample_advisory("RUSTSEC-2024-0320", VulnSeverity::Informational);
        let graded = sample_advisory("RUSTSEC-2020-0071", VulnSeverity::High);

        assert!(
            !candidate_vulnerable_line_should_render(
                &Capped::new(vec!["RUSTSEC-2024-0320".to_string()], 1),
                std::slice::from_ref(&informational)
            ),
            "all-known-Informational, complete set must suppress the line"
        );
        assert!(
            candidate_vulnerable_line_should_render(
                &Capped::new(
                    vec![
                        "RUSTSEC-2024-0320".to_string(),
                        "RUSTSEC-2020-0071".to_string()
                    ],
                    2
                ),
                &[informational.clone(), graded]
            ),
            "mixed set must still render the line"
        );
        assert!(
            candidate_vulnerable_line_should_render(
                &Capped::new(vec!["RUSTSEC-UNKNOWN-ID".to_string()], 1),
                std::slice::from_ref(&informational)
            ),
            "an id with no known severity must default to rendering the line, not suppressing it"
        );
        assert!(
            candidate_vulnerable_line_should_render(
                &Capped::new(vec![], 0),
                std::slice::from_ref(&informational)
            ),
            "N1: an empty (and complete) candidate_ids set is reachable (a real \
             advisory whose detail fetch/into_advisory validation failed) and \
             must fail open — rendering the line, not silently suppressing a \
             real signal"
        );
        assert!(
            candidate_vulnerable_line_should_render(
                &Capped::new(vec!["RUSTSEC-2024-0320".to_string()], 2),
                std::slice::from_ref(&informational)
            ),
            "L2/FR-010: an all-known-Informational but INCOMPLETE (truncated) set \
             must still fail open — an undisplayed advisory beyond the cap could \
             be a real, non-Informational finding"
        );
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_shows_age_when_known() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".into(),
                yanked: false,
                // 2 days ago — safely mid-bucket, immune to sub-second test flakiness.
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 2 * 24 * 60 * 60,
                )),
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("- `1.2.3` *(latest)* — 2 days ago"),
            "got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_omits_age_when_unknown() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".into(),
                yanked: false,
                published_at: None,
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        // Exactly the pre-feature line: no trailing age suffix.
        assert!(content.contains("- `1.2.3` *(latest)*\n"));
        assert!(!content.contains("ago"));
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_skips_prerelease_at_raw_top() {
        use std::collections::HashMap;

        // Raw registry order (newest by version number first): a pre-release sorts above
        // the actual stable latest, mirroring NuGet's Newtonsoft.Json 13.0.5-beta1 vs
        // 13.0.4 (#313).
        let registry = MockRegistryWithVersions {
            versions: vec![
                MockVersionWithAge {
                    version: "13.0.5-beta1".into(),
                    yanked: false,
                    published_at: None,
                },
                MockVersionWithAge {
                    version: "13.0.4".into(),
                    yanked: false,
                    published_at: None,
                },
            ],
        };
        let parse_result = freshness_test_parse_result("Newtonsoft.Json");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(content.contains("**Latest**: `13.0.4`"), "got: {}", content);
        assert!(
            content.contains("- `13.0.4` *(latest)*"),
            "the stable version, not the raw-top pre-release, should carry the marker; got: {}",
            content
        );
        assert!(
            !content.contains("13.0.5-beta1` *(latest)*"),
            "the pre-release must not be tagged latest; got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_bumped_in_when_stable_outside_top_n() {
        use std::collections::HashMap;

        // Nine pre-releases followed by one stable version: the stable pick sits past
        // `HOVER_RECENT_VERSIONS`, so it must be bumped into the rendered list's final
        // slot rather than silently dropped (#961).
        let mut versions: Vec<MockVersionWithAge> = (0..=HOVER_RECENT_VERSIONS)
            .map(|i| MockVersionWithAge {
                version: format!("2.0.0-alpha{i}").into(),
                yanked: false,
                published_at: None,
            })
            .collect();
        versions.push(MockVersionWithAge {
            version: "1.9.0".into(),
            yanked: false,
            published_at: None,
        });
        let registry = MockRegistryWithVersions { versions };
        let parse_result = freshness_test_parse_result("example");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(content.contains("**Latest**: `1.9.0`"), "got: {}", content);
        assert!(
            content.contains("- `1.9.0` *(latest)*"),
            "the stable pick must be bumped into the capped list instead of omitted; got: {}",
            content
        );
        assert_eq!(
            content.matches("*(latest)*").count(),
            1,
            "exactly one entry should carry the marker; got: {}",
            content
        );
        assert_eq!(
            content.lines().filter(|l| l.starts_with("- `")).count(),
            HOVER_RECENT_VERSIONS,
            "the list must stay capped at HOVER_RECENT_VERSIONS entries even after the bump-in; got: {}",
            content
        );
        assert!(
            !content.contains("2.0.0-alpha7"),
            "the displaced 8th natural entry must not remain in the capped list; got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_at_last_window_slot_not_bumped() {
        use std::collections::HashMap;

        // The stable pick sits exactly at `HOVER_RECENT_VERSIONS - 1` — already the last
        // entry the raw-order window naturally displays — so it must render once, in
        // place, without triggering the bump-in path (boundary just inside the window).
        let mut versions: Vec<MockVersionWithAge> = (0..HOVER_RECENT_VERSIONS - 1)
            .map(|i| MockVersionWithAge {
                version: format!("2.0.0-alpha{i}").into(),
                yanked: false,
                published_at: None,
            })
            .collect();
        versions.push(MockVersionWithAge {
            version: "1.9.0".into(),
            yanked: false,
            published_at: None,
        });
        assert_eq!(versions.len(), HOVER_RECENT_VERSIONS);
        let registry = MockRegistryWithVersions { versions };
        let parse_result = freshness_test_parse_result("example");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert_eq!(
            content.matches("- `1.9.0` *(latest)*").count(),
            1,
            "the in-window pick must render exactly once, not duplicated by a bump-in; got: {}",
            content
        );
        assert_eq!(
            content.lines().filter(|l| l.starts_with("- `")).count(),
            HOVER_RECENT_VERSIONS,
            "got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_one_past_window_triggers_bump() {
        use std::collections::HashMap;

        // The stable pick sits at exactly `HOVER_RECENT_VERSIONS` — the first index the
        // bump-in path must catch (minimal boundary, one past
        // `test_generate_hover_latest_marker_at_last_window_slot_not_bumped` above).
        let mut versions: Vec<MockVersionWithAge> = (0..HOVER_RECENT_VERSIONS)
            .map(|i| MockVersionWithAge {
                version: format!("2.0.0-alpha{i}").into(),
                yanked: false,
                published_at: None,
            })
            .collect();
        versions.push(MockVersionWithAge {
            version: "1.9.0".into(),
            yanked: false,
            published_at: None,
        });
        assert_eq!(versions.len(), HOVER_RECENT_VERSIONS + 1);
        let registry = MockRegistryWithVersions { versions };
        let parse_result = freshness_test_parse_result("example");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("- `1.9.0` *(latest)*"),
            "the pick at index HOVER_RECENT_VERSIONS must be bumped in; got: {}",
            content
        );
        assert!(
            !content.contains(&format!("2.0.0-alpha{}", HOVER_RECENT_VERSIONS - 1)),
            "the displaced last natural entry must not remain in the capped list; got: {}",
            content
        );
        assert_eq!(
            content.lines().filter(|l| l.starts_with("- `")).count(),
            HOVER_RECENT_VERSIONS,
            "got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_flagged_pick_bumped_in_keeps_yanked_label() {
        use crate::RemovalStatus;
        use std::collections::HashMap;

        // Hover's "Recent versions" list has no removal-status filter (unlike completion's
        // `prepare_version_display_items`), so the bumped-in pick can itself be flagged: eight
        // `Yanked` entries fill the window, so `select_latest_for_existence` falls through to
        // an `AdvisoryDeprecated` entry past it. Must render both `*(latest)*` and the flag
        // label together (#961).
        let mut versions: Vec<MockVersionWithStatus> = (0..HOVER_RECENT_VERSIONS)
            .map(|i| MockVersionWithStatus {
                version: format!("5.0.{i}").into(),
                status: RemovalStatus::Yanked,
            })
            .collect();
        versions.push(MockVersionWithStatus {
            version: "5.0.99".into(),
            status: RemovalStatus::AdvisoryDeprecated,
        });
        let registry = MockRegistryPreferringUnflagged { versions };
        let parse_result = freshness_test_parse_result("example");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("- `5.0.99` *(latest)* *(yanked)*"),
            "the bumped-in flagged pick must carry both the latest marker and its flag label; got: {}",
            content
        );
        assert!(
            !content.contains("5.0.7`"),
            "the displaced last natural entry must not remain in the capped list; got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_all_prerelease_degrades_gracefully() {
        use std::collections::HashMap;

        // No stable version exists anywhere in the list: `find_latest_stable` returns
        // `None`, and there is no Ch1 cache to fall back to either (#313 edge case).
        let registry = MockRegistryWithVersions {
            versions: vec![
                MockVersionWithAge {
                    version: "2.0.0-beta2".into(),
                    yanked: false,
                    published_at: None,
                },
                MockVersionWithAge {
                    version: "2.0.0-beta1".into(),
                    yanked: false,
                    published_at: None,
                },
                MockVersionWithAge {
                    version: "1.9.0-alpha1".into(),
                    yanked: false,
                    published_at: None,
                },
            ],
        };
        let parse_result = freshness_test_parse_result("example");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor, not panic");

        let content = hover.markdown();
        assert!(
            !content.contains("**Latest**:"),
            "no stable version exists, so the header should be omitted rather than picking a pre-release; got: {}",
            content
        );
        assert!(
            !content.contains("*(latest)*"),
            "no stable version exists, so no entry in the list should be marked latest; got: {}",
            content
        );
        assert!(
            content.contains("2.0.0-beta2"),
            "the raw version list should still render even without a latest marker; got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_all_prerelease_live_list_ignores_stale_cache() {
        use std::collections::HashMap;

        // A live fetch happened but every entry is a pre-release, so `live_latest_idx` is
        // `None`. A stale Ch1 cache is also present, recording a version not in the live list
        // — falling back to it would contradict the live "Recent versions" list below, the
        // same self-contradiction #227 F5 fixed, reached via this all-prerelease path (#313 S2).
        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "2.0.0-beta2".into(),
                yanked: false,
                published_at: None,
            }],
        };
        let parse_result = freshness_test_parse_result("example");
        let mut cached_versions = HashMap::new();
        cached_versions.insert("example".into(), PackageVersions::latest_only("1.5.0"));

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor, not panic");

        let content = hover.markdown();
        assert!(
            !content.contains("**Latest**:"),
            "a live fetch with no stable entry must not fall back to a stale cached version \
             that isn't in the live list; got: {}",
            content
        );
        assert!(
            !content.contains("1.5.0"),
            "the stale cached version must not leak into the response at all; got: {}",
            content
        );
    }

    /// #373: Go's `/@v/list` never enumerates pseudo-versions, so an untagged module whose
    /// entire tagged history is pre-release fails `select_latest_matching`'s list-based pick
    /// even though the live fetch succeeded and returned a non-empty list. Hover must fall
    /// back to `Registry::get_latest_matching` (mirroring `lifecycle.rs`'s background-fetch
    /// fallback, which answers this from Go's `/@latest` endpoint) instead of rendering no
    /// `**Latest**` line at all.
    #[tokio::test]
    async fn test_generate_hover_latest_falls_back_to_get_latest_matching_when_list_pick_fails() {
        use std::collections::HashMap;

        let registry = MockRegistryListFailsLatestFallbackSucceeds {
            versions: vec![MockVersionWithAge {
                version: "v0.0.0-20230101000000-abcdef123456".into(),
                yanked: false,
                published_at: None,
            }],
            fallback_latest: MockVersionWithAge {
                version: "v1.2.3".into(),
                yanked: false,
                published_at: None,
            },
            list_pick_index: None,
            get_latest_matching_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let parse_result = freshness_test_parse_result("example.com/mod");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**Latest**: `v1.2.3`"),
            "the list-based pick failed, so hover must fall back to get_latest_matching's \
             result instead of omitting the Latest line; got: {}",
            content
        );
    }

    /// #373 M4: the fallback must not fire on the common "list-based pick already
    /// succeeded" path — asserted via a call counter on the mock, guarding against a
    /// future regression that would make every hover pay for a second registry round
    /// trip regardless of whether the list-based pick worked.
    #[tokio::test]
    async fn test_generate_hover_does_not_call_fallback_when_list_pick_succeeds() {
        use std::collections::HashMap;
        use std::sync::atomic::Ordering;

        let registry = MockRegistryListFailsLatestFallbackSucceeds {
            versions: vec![MockVersionWithAge {
                version: "v1.2.3".into(),
                yanked: false,
                published_at: None,
            }],
            fallback_latest: MockVersionWithAge {
                version: "v9.9.9".into(),
                yanked: false,
                published_at: None,
            },
            list_pick_index: Some(0),
            get_latest_matching_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let parse_result = freshness_test_parse_result("example.com/mod");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**Latest**: `v1.2.3`"),
            "expected the list-based pick's own version, not the fallback's; got: {}",
            content
        );
        assert_eq!(
            registry.get_latest_matching_calls.load(Ordering::Relaxed),
            0,
            "get_latest_matching must not be called when the list-based pick already succeeded"
        );
    }

    /// Review regression: a fetch failure for a resolvable source (off-VPN, an expired
    /// token, a DNS-blocked internal host — routine for a private-registry user) must
    /// degrade to the basic name/requirement/features card, not vanish the whole hover
    /// response. `.ok()?` on the fetch would have propagated `None` out of the entire
    /// function here; `.ok()` must let `available_versions` become `None` instead.
    #[tokio::test]
    async fn test_generate_hover_renders_basic_card_when_fetch_fails() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &ErrorRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover must still render on a fetch failure, not disappear entirely");

        let content = hover.markdown();
        assert!(
            content.contains("serde"),
            "basic card must still render the package name; got: {}",
            content
        );
        assert!(
            !content.contains("**Latest**"),
            "no version data is available on a fetch failure; got: {}",
            content
        );
    }

    /// #1204: the primary `get_versions_from` fetch must not block hover forever — once
    /// `REGISTRY_FETCH_BUDGET` elapses the timeout's `Err(_)` arm must degrade to the same
    /// basic card a genuine fetch error renders, not hang or panic. `start_paused` lets the
    /// budget elapse without a real wall-clock wait.
    #[tokio::test(start_paused = true)]
    async fn test_generate_hover_registry_fetch_timeout_degrades_to_basic_card() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");
        let registry = SlowRegistry {
            delay: REGISTRY_FETCH_BUDGET + Duration::from_secs(1),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover must still render when the primary fetch times out, not hang or panic");

        let content = hover.markdown();
        assert!(
            content.contains("serde"),
            "basic card must still render the package name; got: {}",
            content
        );
        assert!(
            !content.contains("**Latest**"),
            "no version data is available once the fetch times out; got: {}",
            content
        );
    }

    /// #1209 C1 (impl-critic follow-up): `await_versions_fetch`'s timeout WARN
    /// (`lsp_helpers::mod::await_versions_fetch`) used to interpolate the raw `dep.name()`
    /// directly — this call site (`hover.rs`'s primary fetch, feeding `mod.rs`'s shared sink)
    /// arrived in #1210, after the original #1209 security audit, which is why it was missed.
    /// Now redacted via `dep.name().for_tracing()` at the call site. Asserts against the fully
    /// rendered captured line, mirroring the `deps-engine::classify::fetch` precedent.
    #[tokio::test(start_paused = true)]
    async fn test_generate_hover_registry_fetch_timeout_log_redacts_credential_shaped_package_name()
    {
        use std::collections::HashMap;

        let sentinel_name = "com.example:deploy:AUDITSENTINEL0000@git.internal.corp";
        let parse_result = freshness_test_parse_result(sentinel_name);
        let registry = SlowRegistry {
            delay: REGISTRY_FETCH_BUDGET + Duration::from_secs(1),
        };

        let log = crate::test_util::capture_tracing_output_async_at(tracing::Level::WARN, async {
            generate_hover(
                &parse_result,
                Position::new(0, 2).into(),
                VersionData::new(&HashMap::new(), &HashMap::new()),
                &registry,
                &MOCK_FORMATTER,
                crate::freshness::FreshnessSettings::default(),
                PublishTime::now(),
            )
            .await
            .expect("hover must still render when the primary fetch times out");
        })
        .await;

        assert!(
            log.contains("primary registry version fetch timed out"),
            "expected the primary-fetch-timeout WARN to fire: {log:?}"
        );
        assert!(
            !log.contains("AUDITSENTINEL0000"),
            "tracing output leaked a credential-shaped package name: {log:?}"
        );
        assert!(
            log.contains("git.internal.corp"),
            "host should survive redaction: {log:?}"
        );
    }

    /// #1209 C1: the "hover latest fallback" WARN (`hover.rs`'s own event, not the shared
    /// `await_versions_fetch` sink) used to interpolate `dep.name()` raw. Now redacted via
    /// `dep.name().for_tracing()`.
    #[tokio::test]
    async fn test_generate_hover_fallback_failure_log_redacts_credential_shaped_package_name() {
        use std::any::Any;
        use std::collections::HashMap;

        struct FallbackFailsRegistry;

        impl crate::Registry for FallbackFailsRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a crate::PackageName,
            ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(TestVersion {
                        version: ConcreteVersion::new("1.2.3"),
                        yanked: false,
                    }) as Box<dyn crate::Version>])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a crate::PackageName,
                _req: &'a crate::VersionReq,
            ) -> crate::ecosystem::BoxFuture<
                'a,
                crate::error::Result<Option<Box<dyn crate::Version>>>,
            > {
                Box::pin(async move {
                    Err(crate::error::DepsError::CacheError(
                        "transient backend failure".to_string(),
                    ))
                })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let sentinel_name = "com.example:deploy:AUDITSENTINEL0000@git.internal.corp";
        let parse_result = freshness_test_parse_result(sentinel_name);
        let registry = FallbackFailsRegistry;

        let log = crate::test_util::capture_tracing_output_async_at(tracing::Level::WARN, async {
            generate_hover(
                &parse_result,
                Position::new(0, 2).into(),
                VersionData::new(&HashMap::new(), &HashMap::new()),
                &registry,
                &MOCK_FORMATTER,
                crate::freshness::FreshnessSettings::default(),
                PublishTime::now(),
            )
            .await
            .expect("hover must still render when the fallback fetch fails");
        })
        .await;

        assert!(
            log.contains("hover latest fallback (get_latest_matching) failed"),
            "expected the fallback-failure WARN to fire: {log:?}"
        );
        assert!(
            !log.contains("AUDITSENTINEL0000"),
            "tracing output leaked a credential-shaped package name: {log:?}"
        );
        assert!(
            log.contains("git.internal.corp"),
            "host should survive redaction: {log:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_hover_go_prefers_manifest_requirement_over_stale_resolved_version() {
        use std::collections::HashMap;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "example.com/mod".into(),
                version_req: "v0.8.1".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 16)),
            }],
            uri: crate::test_util::test_uri("/test/go.mod"),
        };

        // Stale go.sum entry left behind by a downgrade (#235): go.mod's `require`
        // line was downgraded back to v0.8.1, but the ledger-only go.sum still
        // records the higher v0.9.1 and sorts last, so it would win naive
        // last-occurrence-wins parsing if hover trusted `versions.resolved` here.
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example.com/mod".into(), "v0.9.1".into());
        let cached_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MOCK_GO_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**Current**: `v0.8.1`"),
            "expected hover to show go.mod's pinned version, got: {}",
            content
        );
        assert!(
            !content.contains("v0.9.1"),
            "hover must not surface the stale go.sum version: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_non_go_formatter_uses_resolved_lockfile_version() {
        use std::collections::HashMap;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.2.0".into());
        let cached_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        // Non-Go formatters must keep showing the lockfile-resolved version
        // ("1.2.0"), not the raw manifest requirement ("1.0.0") — confirms the Go
        // override does not leak into other ecosystems.
        assert!(
            content.contains("**Current**: `1.2.0`"),
            "expected hover to show the resolved lockfile version, got: {}",
            content
        );
        assert!(!content.contains("**Current**: `1.0.0`"));
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_preserves_yanked_marker_with_age() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![
                MockVersionWithAge {
                    version: "1.2.3".into(),
                    yanked: false,
                    published_at: None,
                },
                MockVersionWithAge {
                    version: "1.2.1".into(),
                    yanked: true,
                    // ~5 months ago.
                    published_at: Some(PublishTime::from_unix_secs(
                        PublishTime::now().as_unix_secs() - 5 * 30 * 24 * 60 * 60,
                    )),
                },
            ],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("- `1.2.1` *(yanked)* — 5 months ago"),
            "got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_respects_freshness_disabled() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".into(),
                yanked: false,
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 2 * 24 * 60 * 60,
                )),
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings {
                enabled: false,
                cooldown_secs: crate::freshness::DEFAULT_COOLDOWN_SECS,
            },
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(content.contains("- `1.2.3` *(latest)*\n"));
        assert!(!content.contains("ago"));
    }

    /// Issue #227 §4.2a: the `**Latest**` line gets a publish-age suffix and, within the
    /// cooldown window, the "Recently published" callout.
    #[tokio::test]
    async fn test_generate_hover_latest_line_shows_age_and_cooldown_callout_when_within_cooldown() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                // 1 hour ago — well within the default 3-day cooldown.
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**Latest**: `2.0.0` *(published 1 hour ago)*"),
            "got: {}",
            content
        );
        assert!(
            content.contains(
                "> ⏳ **Recently published** — this release is still within the cooldown window."
            ),
            "got: {}",
            content
        );
    }

    /// Same setup, but `latest` was published well outside the cooldown window — the age
    /// suffix still renders, but the callout must not.
    #[tokio::test]
    async fn test_generate_hover_latest_line_no_callout_when_outside_cooldown() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                // 10 days ago — outside the default 3-day cooldown.
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 10 * 24 * 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**Latest**: `2.0.0` *(published 1 week ago)*"),
            "got: {}",
            content
        );
        assert!(!content.contains("Recently published"));
    }

    /// A `latest` with no known publish time renders exactly the pre-feature line — no age
    /// suffix, no callout.
    #[tokio::test]
    async fn test_generate_hover_latest_line_omits_age_when_published_at_unknown() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.0.0"));
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(content.contains("**Latest**: `2.0.0`\n\n"));
        assert!(!content.contains("published"));
        assert!(!content.contains("Recently published"));
    }

    /// `freshness.enabled: false` suppresses both the age suffix and the cooldown callout
    /// on the `**Latest**` line, even when the publish time would otherwise qualify.
    #[tokio::test]
    async fn test_generate_hover_latest_line_respects_freshness_disabled() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings {
                enabled: false,
                cooldown_secs: crate::freshness::DEFAULT_COOLDOWN_SECS,
            },
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(content.contains("**Latest**: `2.0.0`\n\n"));
        assert!(!content.contains("published"));
        assert!(!content.contains("Recently published"));
    }

    /// Deterministic boundary test (issue #227 M4): `now` is threaded in as a parameter
    /// rather than read internally, so `published_at`/`now`/`cooldown_secs` can be pinned
    /// to fixed absolute values with no wall-clock dependency. `age == cooldown_secs`
    /// exactly must NOT be within cooldown — the bound is exclusive (`age < cooldown`).
    #[tokio::test]
    async fn test_generate_hover_latest_line_cooldown_boundary_is_exclusive() {
        use std::collections::HashMap;

        const COOLDOWN_SECS: u64 = 100;
        let now = PublishTime::from_unix_secs(10_000);
        let published_at_at_boundary =
            PublishTime::from_unix_secs(10_000 - COOLDOWN_SECS.cast_signed());

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(published_at_at_boundary),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            !content.contains("Recently published"),
            "age exactly equal to cooldown_secs must not be within cooldown, got: {}",
            content
        );
    }

    /// Same fixture, one second younger — must flip to within cooldown.
    #[tokio::test]
    async fn test_generate_hover_latest_line_cooldown_boundary_one_second_inside_shows_callout() {
        use std::collections::HashMap;

        const COOLDOWN_SECS: u64 = 100;
        let now = PublishTime::from_unix_secs(10_000);
        let published_at_just_inside =
            PublishTime::from_unix_secs(10_000 - (COOLDOWN_SECS.cast_signed() - 1));

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(published_at_just_inside),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("Recently published"),
            "age == cooldown_secs - 1 must be within cooldown, got: {}",
            content
        );
    }

    /// Issue #227 F5: the Ch1 cache (`versions.cached`, populated by the lifecycle's
    /// background fetch) can go stale relative to the live Ch2 fetch this same hover call
    /// just made (`registry.get_versions_with`) — e.g. a new version published between the
    /// last background fetch and now. Before this fix, the `**Latest**` line and cooldown
    /// callout read Ch1 alone, so hover could render a self-contradictory response: an
    /// older `**Latest**` line sitting above a "Recent versions" list whose own `*(latest)*`
    /// entry is a newer version. The line must prefer the live entry instead.
    #[tokio::test]
    async fn test_generate_hover_latest_line_prefers_live_fetch_over_stale_ch1_cache() {
        use std::collections::HashMap;

        let now = PublishTime::now();
        let live_latest_published = PublishTime::from_unix_secs(now.as_unix_secs() - 60 * 60);
        let registry = MockRegistryWithVersions {
            versions: vec![
                MockVersionWithAge {
                    version: "1.0.214".into(),
                    yanked: false,
                    published_at: Some(live_latest_published),
                },
                MockVersionWithAge {
                    version: "1.0.213".into(),
                    yanked: false,
                    published_at: Some(PublishTime::from_unix_secs(
                        now.as_unix_secs() - 30 * 24 * 60 * 60,
                    )),
                },
            ],
        };

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        // Stale Ch1 entry: an older version, with an even older publish time, standing in
        // for a background fetch that ran before 1.0.214 was published.
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "1.0.213".into(),
                available: Arc::from(vec!["1.0.213".into()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(PublishTime::from_unix_secs(
                    now.as_unix_secs() - 90 * 24 * 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**Latest**: `1.0.214` *(published 1 hour ago)*"),
            "Latest line must reflect the live Ch2 fetch, not the stale Ch1 cache entry \
             `1.0.213`, got: {}",
            content
        );
        assert!(
            !content.contains("**Latest**: `1.0.213`"),
            "must not render the stale Ch1 version, got: {}",
            content
        );
        assert!(
            content.contains("- `1.0.214` *(latest)* — 1 hour ago"),
            "the Recent versions list's own *(latest)* entry must agree with the Latest \
             line above it, got: {}",
            content
        );
    }

    /// #347/#348 S1: npm-shaped package `[2.0.0 AdvisoryDeprecated, 1.9.0 Available]`.
    /// `is_stable()` accepts `AdvisoryDeprecated`, so a naive `is_stable()`-based scan for
    /// "latest" picks `2.0.0` — disagreeing with npm's own `select_latest_matching`, which
    /// deliberately ranks a non-deprecated version ahead of a deprecated one (#338 NFR-002)
    /// and would resolve `1.9.0` instead (this is exactly what `lifecycle.rs` caches and
    /// diagnostics read). Hover must delegate to the registry's `select_latest_matching`
    /// instead of re-deriving the pick, so it agrees with that cached value, and the
    /// resolved `2.0.0`-would-be-latest case below must still carry its deprecated label
    /// when a deprecated version *is* the resolved latest.
    #[tokio::test]
    async fn test_generate_hover_latest_agrees_with_npm_shaped_deprecated_ranking() {
        use std::collections::HashMap;

        let now = PublishTime::now();
        let registry = MockRegistryPreferringUnflagged {
            versions: vec![
                MockVersionWithStatus {
                    version: "2.0.0".into(),
                    status: RemovalStatus::AdvisoryDeprecated,
                },
                MockVersionWithStatus {
                    version: "1.9.0".into(),
                    status: RemovalStatus::Available,
                },
            ],
        };

        let parse_result = freshness_test_parse_result("pkg");
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**Latest**: `1.9.0`"),
            "hover must agree with select_latest_matching's non-deprecated-preferred pick \
             (1.9.0), not a naive is_stable() scan that would pick the newer but deprecated \
             2.0.0, got: {}",
            content
        );
        assert!(
            content.contains("- `1.9.0` *(latest)*"),
            "the Recent versions list's own *(latest)* marker must agree with the Latest \
             line above it, got: {}",
            content
        );
        assert!(
            content.contains("- `2.0.0` *(yanked)*"),
            "2.0.0 must keep its flagged label even though it isn't the resolved latest, \
             got: {}",
            content
        );
    }

    /// #347/#348 S1: when every version is flagged, the registry's own ranking (rung 2 of
    /// `MockRegistryPreferringUnflagged`) can still resolve a flagged version as "latest" —
    /// hover must keep that entry's deprecated/yanked label instead of letting `*(latest)*`
    /// silently replace it (issue #227-F5/#313's self-contradiction class).
    #[tokio::test]
    async fn test_generate_hover_latest_keeps_flagged_label_when_resolved_version_is_flagged() {
        use std::collections::HashMap;

        let now = PublishTime::now();
        let registry = MockRegistryPreferringUnflagged {
            versions: vec![MockVersionWithStatus {
                version: "2.0.0".into(),
                status: RemovalStatus::AdvisoryDeprecated,
            }],
        };

        let parse_result = freshness_test_parse_result("pkg");
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**Latest**: `2.0.0`"),
            "the only version resolves as latest even though it's flagged, got: {}",
            content
        );
        assert!(
            content.contains("- `2.0.0` *(latest)* *(yanked)*"),
            "the resolved latest must keep its flagged label instead of the warning \
             silently vanishing behind *(latest)*, got: {}",
            content
        );
    }

    /// #364 rung 3: an *all-yanked* package (Cargo/PyPI/Dart-shaped —
    /// `RemovalStatus::Yanked` blocks resolution, unlike npm's `AdvisoryDeprecated`) must
    /// still resolve a "latest" via [`crate::select_latest_for_existence`]'s unconditional
    /// last rung, instead of hover rendering no `**Latest**` line at all (the pre-#364
    /// `None` behavior that read as a false "Unknown package").
    #[tokio::test]
    async fn test_generate_hover_latest_resolves_when_all_versions_yanked() {
        use std::collections::HashMap;

        let now = PublishTime::now();
        let registry = MockRegistryPreferringUnflagged {
            versions: vec![
                MockVersionWithStatus {
                    version: "2.0.0".into(),
                    status: RemovalStatus::Yanked,
                },
                MockVersionWithStatus {
                    version: "1.9.0".into(),
                    status: RemovalStatus::Yanked,
                },
            ],
        };

        let parse_result = freshness_test_parse_result("pkg");
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("**Latest**: `2.0.0`"),
            "an all-yanked package still exists: hover must resolve the newest yanked \
             version as latest rather than showing no Latest line, got: {}",
            content
        );
        assert!(
            content.contains("- `2.0.0` *(latest)* *(yanked)*"),
            "the resolved latest must keep its yanked label, got: {}",
            content
        );
    }

    /// npm-shaped formatter stub for T7: overrides `yanked_label` to npm's actual
    /// `"*(deprecated)*"` wording (`deps-npm/src/formatter.rs`), everything else default.
    struct NpmLikeFormatter;

    impl PackageNaming for NpmLikeFormatter {}

    impl PackageRendering for NpmLikeFormatter {
        fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
            version.to_string()
        }

        fn package_url(&self, name: &crate::PackageName) -> String {
            format!("https://example.com/{}", name.as_str())
        }
    }

    impl RequirementResolution for NpmLikeFormatter {}

    impl DiagnosticMessages for NpmLikeFormatter {
        fn yanked_label(&self) -> &'static str {
            "*(deprecated)*"
        }
    }

    impl DiagnosticPolicy for NpmLikeFormatter {}

    impl SourcePolicy for NpmLikeFormatter {}

    impl OsvNaming for NpmLikeFormatter {}

    /// T7 (S4, accepted redundancy): hover for a deprecated npm-shaped package renders
    /// **both** the new `### Deprecated` section (D6) and the pre-existing per-row
    /// `*(deprecated)*` "Recent versions" labels — pinning the deliberate decision not to
    /// dedupe them (plan.md D6), so a later dedupe reads as an intentional change rather
    /// than a silent regression.
    #[tokio::test]
    async fn test_generate_hover_deprecated_section_and_per_row_labels_both_render() {
        use std::collections::HashMap;

        let now = PublishTime::now();
        let registry = MockRegistryPreferringUnflagged {
            versions: vec![MockVersionWithStatus {
                version: "1.0.0".into(),
                status: RemovalStatus::AdvisoryDeprecated,
            }],
        };

        let parse_result = freshness_test_parse_result("pkg");
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let outcomes = crate::lsp_helpers::DependencyOutcomes::new().with_deprecation(
            "pkg",
            crate::Deprecation {
                reason: Some("no longer maintained".to_string()),
                replacement: None,
            },
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &registry,
            &NpmLikeFormatter,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("### Deprecated"),
            "expected the package-level Deprecated section, got: {}",
            content
        );
        assert!(
            content.contains("no longer maintained"),
            "expected the deprecation reason, got: {}",
            content
        );
        // I3: the message and the reason must render as separate CommonMark paragraphs
        // (blank-line separated), not collapse into one joined paragraph.
        assert!(
            content.contains("This package is deprecated\n\nno longer maintained"),
            "expected the message and reason on separate paragraphs, got: {}",
            content
        );
        assert!(
            content.contains("- `1.0.0` *(latest)* *(deprecated)*"),
            "expected the pre-existing per-row label to still render alongside the new \
             section (deliberately not deduped, S4), got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_surfaces_markers() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "numpy".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                markers: Some("python_full_version >= '3.9'".to_string()),
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(content.contains("**Active when**: `python_full_version >= '3.9'`"));
    }

    #[tokio::test]
    async fn test_generate_hover_omits_active_when_without_markers() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "requests".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 8)),
                markers: None,
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(!content.contains("Active when"));
    }

    #[tokio::test]
    async fn test_generate_hover_escapes_malicious_dependency_name() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let malicious_name = "real-pkg](https://legit-looking-typosquat.example/download)[real-pkg";

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: malicious_name.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, malicious_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();

        // The link label (between the H1's "# [" and the "](") must be the fully
        // escaped name, with no raw "](" sequence that could close the label early
        // and splice in an attacker-controlled markdown link.
        let header_line = content
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let label = header_line
            .strip_prefix("# [")
            .expect("header starts with link label")
            .split("](")
            .next()
            .expect("header contains label/url separator");
        assert_eq!(
            label,
            r"real\-pkg\]\(https\:\/\/legit\-looking\-typosquat\.example\/download\)\[real\-pkg"
        );
    }

    #[tokio::test]
    async fn test_generate_hover_newline_in_name_cannot_forge_new_heading() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // Combines S1 (newline breaks out of the ATX heading line) with an
        // autolink payload that needs no brackets/parens at all.
        let malicious_name = "react\n# [fake](https://evil.example) <https://evil.example>";

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: malicious_name.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, malicious_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();

        // The link label must be the exact single-line escaped name: no raw
        // newline breaking the ATX heading, and the autolink's `<`/`>` escaped so
        // it cannot render as a live link independent of the `[]`/`()` escaping.
        let header_line = content
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let label = header_line
            .strip_prefix("# [")
            .expect("header starts with link label")
            .split("](")
            .next()
            .expect("header contains label/url separator");
        assert_eq!(label, escape_markdown(malicious_name));
        assert!(!label.contains('\n'));
        assert!(label.contains(r"\<https"));
    }

    #[tokio::test]
    async fn test_generate_hover_bidi_override_in_name_cannot_spoof_rendered_label() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // Trojan Source (CVE-2021-42574, #1248): a RIGHT-TO-LEFT OVERRIDE in the
        // dependency name must not reach the rendered hover label, where it could
        // visually reorder the name into a spoofed, different-looking package.
        let malicious_name = "real\u{202E}gnp.sj";

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: malicious_name.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, malicious_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();

        // The link label (the escape_markdown sink #1248 targets) must not carry the bidi
        // override; the link *destination* is sanitized too (#1259), see the dedicated
        // `test_generate_hover_bidi_override_in_name_cannot_spoof_link_destination` test below.
        let header_line = content
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let label = header_line
            .strip_prefix("# [")
            .expect("header starts with link label")
            .split("](")
            .next()
            .expect("header contains label/url separator");
        assert!(!label.contains('\u{202E}'));
        assert!(!header_line.contains('\u{202E}'));
    }

    /// #1259: a bidi-override embedded in a dependency name must not survive into the
    /// hover header's link *destination* either (defense-in-depth on top of
    /// `conformance::assert_package_url_hostile_input_safe`'s producer-side gate — see
    /// `push_header_hover_section`'s doc). Critic finding S3: the fix must strip the
    /// character rather than substitute a space for it, or the destination stops being
    /// a valid, parseable link destination at all — asserted here via `url::Url::parse`,
    /// the same check `conformance.rs`'s gate uses, not just absence of the bidi char.
    #[tokio::test]
    async fn test_generate_hover_bidi_override_in_name_cannot_spoof_link_destination() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let malicious_name = "real\u{202E}gnp.sj";

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: malicious_name.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, malicious_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();

        let header_line = content
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let destination = header_line
            .split("](")
            .nth(1)
            .expect("header contains label/url separator")
            .strip_suffix(')')
            .expect("destination ends with a closing paren");
        assert!(
            !destination.contains('\u{202E}'),
            "link destination must not carry the bidi override; got: {destination}"
        );
        assert!(
            url::Url::parse(destination).is_ok(),
            "sanitized destination must still be a valid, parseable URL — a space \
             substitution (rather than removal) would break the link; got: {destination:?}"
        );
        assert_eq!(
            destination, "https://example.com/realgnp.sj",
            "removing the bidi char must not introduce a stray space or other artifact"
        );
    }

    /// #1259 critic S4, code-review follow-up: the hover header's link *label* must
    /// not render unbounded, and the cap must bound the actual *rendered* (post-escape)
    /// length, not just the source-character count. A name built entirely of
    /// punctuation (every `-` becomes `\-` under `escape_markdown`, doubling length —
    /// common in real package names too, e.g. `-`/`_`/`.`/`@`) is exactly the case that
    /// would slip past a truncate-before-escape ordering: truncating 300 raw dashes to
    /// 128 raw chars and then escaping would still yield a 256-char rendered label, not
    /// the 129 this test asserts.
    #[tokio::test]
    async fn test_generate_hover_header_caps_rendered_label_length_after_escaping() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let punctuation_heavy_name = "-".repeat(300);

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: punctuation_heavy_name.clone().into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 310), Position::new(0, 320)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, punctuation_heavy_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();

        let header_line = content
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let label = header_line
            .strip_prefix("# [")
            .expect("header starts with link label")
            .split("](")
            .next()
            .expect("header contains label/url separator");

        assert_eq!(
            label.chars().count(),
            MAX_DIAGNOSTIC_NAME_CHARS + 1,
            "rendered (post-escape) label must be capped to MAX_DIAGNOSTIC_NAME_CHARS \
             chars plus the ellipsis marker, proving truncation runs after escaping, \
             not before; got: {label}"
        );
        assert!(
            label.ends_with('…'),
            "expected truncation marker; got: {label}"
        );
    }

    /// #1259 code-review follow-up: a long but entirely legitimate `package_url`
    /// destination — e.g. a Go module path or an npm scoped package near npm's 214-char
    /// limit — must render in full, not get cut at a fixed raw-character boundary. An
    /// earlier version of the S4 fix capped the destination the same way as the label
    /// and broke exactly this case; the destination's safety instead rests on
    /// `package_url`'s producer-side conformance gate (percent-encoding/allowlisting),
    /// not a length cap here.
    #[tokio::test]
    async fn test_generate_hover_header_does_not_truncate_long_legitimate_destination() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let long_legitimate_name = "x".repeat(200);

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: long_legitimate_name.clone().into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 210), Position::new(0, 220)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, long_legitimate_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();

        let header_line = content
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let destination = header_line
            .split("](")
            .nth(1)
            .expect("header contains label/url separator")
            .strip_suffix(')')
            .expect("destination ends with a closing paren");
        let expected = format!("https://example.com/{long_legitimate_name}");

        assert_eq!(
            destination, expected,
            "a long but legitimate destination must render in full, untruncated"
        );
        assert!(
            url::Url::parse(destination).is_ok(),
            "destination must still be a valid, parseable URL; got: {destination:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_hover_marker_with_parens_renders_unescaped() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // Regression guard (M4): a legitimate PEP 508 marker with parentheses must
        // render as-is inside its code span, not with visible `\(`/`\)` escapes —
        // backslash-escaping does not apply inside code spans.
        let marker = "python_version >= \"3.8\" and (sys_platform == \"linux\")";
        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "numpy".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                markers: Some(marker.to_string()),
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(content.contains(&format!("**Active when**: `{marker}`")));
    }

    #[tokio::test]
    async fn test_generate_hover_registry_sections_suppressed_for_non_registry_sources() {
        use crate::parser::DependencySource;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "9.9.9".into(),
                yanked: false,
                published_at: None,
            }],
        };
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert("dep".into(), PackageVersions::latest_only("9.9.9"));
            m
        };
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("dep"),
                DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
            ),
            uri: uri.clone(),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should still be generated for a non-resolvable-source dependency");

        let content = hover.markdown();
        assert!(!content.contains("**Latest**"));
        assert!(!content.contains("**Recent versions**"));
        assert!(content.contains("**Requirement**"));

        // Control: the same fixture on a Registry-source dependency DOES show
        // both registry-derived sections, proving the fixture isn't vacuous.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let hover = generate_hover(
            &registry_parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let content = hover.markdown();
        assert!(content.contains("**Latest**"));
        assert!(content.contains("**Recent versions**"));
    }

    #[tokio::test]
    async fn test_generate_hover_clean_outcome_states_no_known_vulnerabilities() {
        use crate::osv::{ScanOutcome, VulnerabilityMap};

        let parse_result = MockParseResult {
            deps: vec![dep_at("clean-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(crate::test_util::vuln_key("clean-pkg"), ScanOutcome::Clean);

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(content.contains("No known vulnerabilities"));
    }

    #[tokio::test]
    async fn test_generate_hover_skipped_outcome_says_nothing_about_vulnerabilities() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let parse_result = MockParseResult {
            deps: vec![dep_at("path-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("path-pkg"),
            ScanOutcome::Skipped(SkipReason::NonRegistrySource),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(!content.contains("Security advisories"));
        assert!(!content.contains("No known vulnerabilities"));
    }

    #[tokio::test]
    async fn test_generate_hover_vulnerable_outcome_shows_advisories_and_more_count() {
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let parse_result = MockParseResult {
            deps: vec![dep_at("bad-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("bad-pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(
                    vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::Critical)],
                    3,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::CandidateVulnerable {
                    version: "2.0.0".into(),
                    advisory_ids: Capped::new(vec!["RUSTSEC-2020-0071".to_string()], 1),
                },
            }),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(content.contains("Security advisories"));
        assert!(content.contains("RUSTSEC-2020-0071"));
        assert!(content.contains("Fixed in"));
        assert!(content.contains("1.5.0"), "must show highest fixed version");
        assert!(content.contains("+2 more advisories"));
        assert!(content.contains("also affected"));
    }

    /// #1272: `fixed_versions`, the candidate `version`, `summary`, and `aliases` are all
    /// untrusted, unbounded OSV data — every one of them must be capped before rendering.
    #[test]
    fn push_vulnerability_hover_section_caps_fixed_version_summary_and_aliases() {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, ScanOutcome, UpgradeStatus,
            VulnSeverity,
        };

        let mut advisory = Advisory::new(
            "RUSTSEC-2020-0071".to_string(),
            "2023-01-01T00:00:00Z".to_string(),
            VulnSeverity::High,
        )
        .expect("valid osv id");
        advisory.summary = Some("S".repeat(500));
        advisory.fixed_versions = vec![OsvVersion::new("F".repeat(500))];
        // A non-ASCII, multi-byte-per-char alias (within the first `MAX_ADVISORY_ALIASES_RENDERED`
        // entries, so it actually renders) pins that the per-alias cap
        // (`truncate_for_diagnostic`) is genuinely char-based, not byte-based — a
        // byte-based cut through a multi-byte UTF-8 sequence would panic or corrupt the
        // string (#1272 round 2 critic M3).
        let mut aliases: Vec<String> = (0..7).map(|i| format!("CVE-2020-{i:04}")).collect();
        aliases.push("é".repeat(500));
        aliases.extend((7..11).map(|i| format!("CVE-2020-{i:04}")));
        advisory.aliases = aliases;

        let dv = DependencyVulnerabilities::new(Capped::new(vec![Arc::new(advisory)], 1))
            .with_upgrade_status(UpgradeStatus::CandidateVulnerable {
                version: "V".repeat(500),
                advisory_ids: Capped::new(vec!["RUSTSEC-2020-0071".to_string()], 1),
            });

        let outcome = ScanOutcome::Vulnerable(dv);
        let mut markdown = HoverMarkdown::new();
        push_vulnerability_hover_section(&mut markdown, &MOCK_FORMATTER, Some(&outcome));

        // `S`/`F`/`V` are not ASCII punctuation, so `escape_markdown`/`markdown_code_span`
        // leave them untouched — the rendered run is pinned to exactly
        // `MAX_DIAGNOSTIC_PROSE_CHARS`/`MAX_VERSION_DIAGNOSTIC_CHARS` chars plus the `…`
        // marker, not merely "shorter than 500".
        assert!(
            markdown
                .as_str()
                .contains(&format!("{}…", "S".repeat(MAX_DIAGNOSTIC_PROSE_CHARS))),
            "summary must be truncated to exactly {MAX_DIAGNOSTIC_PROSE_CHARS} chars plus an \
             ellipsis; got: {markdown}"
        );
        assert!(
            !markdown
                .as_str()
                .contains(&"S".repeat(MAX_DIAGNOSTIC_PROSE_CHARS + 1)),
            "summary must not exceed the cap; got: {markdown}"
        );
        assert!(
            markdown
                .as_str()
                .contains(&format!("{}…", "F".repeat(MAX_VERSION_DIAGNOSTIC_CHARS))),
            "fixed version must be truncated to exactly {MAX_VERSION_DIAGNOSTIC_CHARS} chars \
             plus an ellipsis; got: {markdown}"
        );
        assert!(
            markdown
                .as_str()
                .contains(&format!("{}…", "V".repeat(MAX_VERSION_DIAGNOSTIC_CHARS))),
            "candidate version must be truncated to exactly {MAX_VERSION_DIAGNOSTIC_CHARS} \
             chars plus an ellipsis; got: {markdown}"
        );
        assert!(
            markdown
                .as_str()
                .contains(&format!("{}…", "é".repeat(MAX_DIAGNOSTIC_NAME_CHARS))),
            "a multi-byte alias must be truncated on a char boundary, not a byte boundary; \
             got: {markdown}"
        );
        assert!(
            markdown.as_str().contains("+4 more"),
            "alias list must be capped; got: {markdown}"
        );
    }

    /// Regression for #1423 (live-verified Go symptom): a `Fixed in:` line must render an
    /// advisory's `fixed_versions` entry through `OsvNaming::osv_version_to_native`, not the
    /// raw OSV wire spelling. Uses a non-identity, Go-style formatter (adds back the `v`
    /// prefix `osv_version_to_native` strips by default) — the identity `MOCK_FORMATTER` used
    /// by the sibling test above would pass even if `push_vulnerability_hover_section`
    /// silently stopped converting, since identity conversion can't distinguish "converted"
    /// from "never converted".
    #[test]
    fn push_vulnerability_hover_section_converts_fixed_version_to_native_namespace() {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, ScanOutcome, VulnSeverity,
        };

        const GO_STYLE_FORMATTER: crate::test_util::StubFormatter =
            crate::test_util::StubFormatter::new().with_go_style_osv_version_to_native();

        let advisory = Advisory::new(
            "RUSTSEC-2024-0432".to_string(),
            "2024-01-01T00:00:00Z".to_string(),
            VulnSeverity::High,
        )
        .expect("valid osv id")
        // OSV's wire spelling for Go never carries the `v` prefix `go.mod` requires.
        .with_fixed_versions(vec![OsvVersion::new("0.55.0")]);

        let dv = DependencyVulnerabilities::new(Capped::new(vec![Arc::new(advisory)], 1));
        let outcome = ScanOutcome::Vulnerable(dv);
        let mut markdown = HoverMarkdown::new();
        push_vulnerability_hover_section(&mut markdown, &GO_STYLE_FORMATTER, Some(&outcome));

        assert!(
            markdown.as_str().contains("v0.55.0"),
            "Fixed in: must render the native-namespace version (v0.55.0), not the raw OSV \
             wire spelling (0.55.0); got: {markdown}"
        );
        assert!(
            !markdown.as_str().contains("Fixed in: `0.55.0`"),
            "must not render the unconverted OSV wire spelling; got: {markdown}"
        );
    }

    #[tokio::test]
    async fn test_generate_hover_malicious_advisory_never_renders_unknown_severity() {
        // SC-001: a MAL-* advisory (e.g. the live MAL-2025-47141 record for
        // npm `@ctrl/tinycolor`) must never render as "unknown severity".
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let parse_result = MockParseResult {
            deps: vec![dep_at("bad-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("bad-pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(
                    vec![sample_advisory("MAL-2025-47141", VulnSeverity::Malicious)],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(content.contains("MAL-2025-47141"));
        assert!(content.contains("confirmed malicious package"));
        assert!(!content.contains("unknown severity"));
    }

    #[tokio::test]
    async fn test_generate_hover_informational_advisory_never_renders_unknown_severity() {
        // SC-001 (issue #1007): the live RUSTSEC-2024-0320 (yaml-rust)
        // "unmaintained" record must never render as "unknown severity",
        // and must stand alone as a comprehensible notice even without a
        // `summary` (FR-003 edge case).
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let parse_result = MockParseResult {
            deps: vec![dep_at("yaml-rust")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        // Deliberately not `sample_advisory` here (unlike the other tests in
        // this module): this test needs `summary: None`, which
        // `sample_advisory` always sets to `Some(...)`.
        let advisory = Advisory::new(
            "RUSTSEC-2024-0320".to_string(),
            "2024-11-01T12:31:51Z".to_string(),
            VulnSeverity::Informational,
        )
        .expect("valid osv id");

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("yaml-rust"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(vec![std::sync::Arc::new(advisory)], 1),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(content.contains("RUSTSEC-2024-0320"));
        assert!(!content.contains("unknown severity"));
        // FR-003: even with no `summary`, the label itself must read as a
        // self-contained notice — not a bare category word that only makes
        // sense alongside prose the advisory doesn't have here.
        assert!(
            content.contains(severity_label(VulnSeverity::Informational)),
            "label must stand alone as a comprehensible notice: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_suppresses_also_affected_when_candidate_is_all_informational() {
        // FR-008 (#1007): `check_candidates()`/`UpgradeStatus` are untouched — suppression
        // happens purely at hover-render time by looking candidate advisory ids up in the
        // dependency's already-classified list. Every id here maps to `Informational`, so the
        // line must not render.
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let parse_result = MockParseResult {
            deps: vec![dep_at("yaml-rust")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let advisory = sample_advisory("RUSTSEC-2024-0320", VulnSeverity::Informational);

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("yaml-rust"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(vec![advisory], 1),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::CandidateVulnerable {
                    version: "0.5.0".to_string(),
                    advisory_ids: Capped::new(vec!["RUSTSEC-2024-0320".to_string()], 1),
                },
            }),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            !content.contains("also affected"),
            "an all-Informational candidate-vulnerable set must not render the \
             misleading 'also affected' line: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_still_shows_also_affected_when_candidate_is_mixed() {
        // FR-008 edge case (M5, revised architecture): when the
        // candidate-vulnerable set mixes an Informational id with a real
        // (non-Informational) one, the line must still render — a real
        // vulnerability signal must never be silently dropped.
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let parse_result = MockParseResult {
            deps: vec![dep_at("mixed-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let informational_advisory =
            sample_advisory("RUSTSEC-2024-0320", VulnSeverity::Informational);
        let graded_advisory = sample_advisory("RUSTSEC-2020-0071", VulnSeverity::High);

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("mixed-pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(vec![informational_advisory, graded_advisory], 2),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::CandidateVulnerable {
                    version: "2.0.0".to_string(),
                    advisory_ids: Capped::new(
                        vec![
                            "RUSTSEC-2024-0320".to_string(),
                            "RUSTSEC-2020-0071".to_string(),
                        ],
                        2,
                    ),
                },
            }),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            content.contains("also affected"),
            "a mixed informational+graded candidate-vulnerable set must still \
             render the line: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_vulnerability_not_shared_across_duplicate_name_occurrences() {
        // #394 S2: `pkg` declared twice with different pins — one vulnerable,
        // one patched. Hover on the patched occurrence must not show the
        // vulnerable occurrence's advisory just because they share a name.
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let vulnerable_dep = MockDep {
            name: "pkg".into(),
            version_req: "=1.0.0".into(),
            version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
        };
        let patched_dep = MockDep {
            name: "pkg".into(),
            version_req: "=2.0.0".into(),
            version_range: Range::new(Position::new(3, 10), Position::new(3, 20)),
            name_range: Range::new(Position::new(3, 0), Position::new(3, 5)),
        };
        let parse_result = MockParseResult {
            deps: vec![vulnerable_dep, patched_dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let keys = crate::osv::vulnerability_keys(
            &parse_result,
            &resolved_versions,
            None,
            &MOCK_FORMATTER,
            crate::EcosystemId::Cargo,
        );
        let deps = parse_result.dependencies();
        let vulnerable_key = keys.get(&deps[0].name_range()).unwrap().clone();
        let patched_key = keys.get(&deps[1].name_range()).unwrap().clone();
        assert_ne!(vulnerable_key, patched_key);

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            vulnerable_key,
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(
                    vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::Critical)],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );
        vulns.insert(patched_key, ScanOutcome::Clean);

        let versions = VersionData::new(&cached_versions, &resolved_versions)
            .with_vulnerabilities(&vulns)
            .with_ecosystem(crate::EcosystemId::Cargo);

        let hover_on_patched = generate_hover(
            &parse_result,
            Position::new(3, 2).into(),
            versions,
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let patched_content = hover_on_patched.markdown();
        assert!(
            !patched_content.contains("RUSTSEC-2020-0071"),
            "the patched occurrence must not show the other occurrence's advisory: {}",
            patched_content
        );
        assert!(patched_content.contains("No known vulnerabilities"));

        let hover_on_vulnerable = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            versions,
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let vulnerable_content = hover_on_vulnerable.markdown();
        assert!(vulnerable_content.contains("RUSTSEC-2020-0071"));
    }

    /// Issue #649 US-001/US-002/SC-001/SC-002, end-to-end through `generate_hover` with a
    /// real `resolved_version_candidates` map (the largest gap flagged by the pre-review
    /// test-coverage audit — every prior duplicate-name hover test disambiguated via a
    /// concrete manifest pin, never exercising the lockfile-candidates path). Mirrors the
    /// serde/serde_old rename scenario: both occurrences resolve the name `serde`, one
    /// plain (`"1.0"`) and one renamed to an older major (`"0.9"`); the "Current" line must
    /// show each occurrence's own resolved version (SC-001), and an advisory affecting only
    /// the current major must not leak onto the renamed occurrence's hover (SC-002).
    #[tokio::test]
    async fn test_generate_hover_attributed_via_resolved_version_candidates() {
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let current_major = MockDep {
            name: "serde".into(),
            version_req: "1.0".into(),
            version_range: Range::new(Position::new(0, 8), Position::new(0, 13)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
        };
        let renamed_old_major = MockDep {
            name: "serde".into(),
            version_req: "0.9".into(),
            version_range: Range::new(Position::new(1, 8), Position::new(1, 13)),
            name_range: Range::new(Position::new(1, 0), Position::new(1, 9)),
        };
        let parse_result = MockParseResult {
            deps: vec![current_major, renamed_old_major],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), ConcreteVersion::from("1.0.219"));
        let mut resolved_version_candidates = HashMap::new();
        resolved_version_candidates.insert(
            "serde".into(),
            vec![
                ConcreteVersion::from("0.9.15"),
                ConcreteVersion::from("1.0.219"),
            ],
        );

        let keys = crate::osv::vulnerability_keys(
            &parse_result,
            &resolved_versions,
            Some(&resolved_version_candidates),
            &MOCK_FORMATTER,
            crate::EcosystemId::Cargo,
        );
        let deps = parse_result.dependencies();
        let current_key = keys.get(&deps[0].name_range()).unwrap().clone();
        let renamed_key = keys.get(&deps[1].name_range()).unwrap().clone();
        assert_ne!(current_key, renamed_key);

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            current_key,
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(
                    vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::Critical)],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );
        vulns.insert(renamed_key, ScanOutcome::Clean);

        let versions = VersionData::new(&cached_versions, &resolved_versions)
            .with_resolved_version_candidates(&resolved_version_candidates)
            .with_vulnerabilities(&vulns)
            .with_ecosystem(crate::EcosystemId::Cargo);

        let hover_on_renamed = generate_hover(
            &parse_result,
            Position::new(1, 2).into(),
            versions,
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let renamed_content = hover_on_renamed.markdown();
        assert!(
            renamed_content.contains("0.9.15"),
            "renamed occurrence must show its own resolved version, not the collapsed 1.0.219: {}",
            renamed_content
        );
        assert!(
            !renamed_content.contains("RUSTSEC-2020-0071"),
            "the renamed (0.9) occurrence must not show the other occurrence's advisory: {}",
            renamed_content
        );
        assert!(renamed_content.contains("No known vulnerabilities"));

        let hover_on_current = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            versions,
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let current_content = hover_on_current.markdown();
        assert!(current_content.contains("1.0.219"));
        assert!(current_content.contains("RUSTSEC-2020-0071"));
    }

    /// #366, revised by the PR-431 review's Critical finding #3: a registry error
    /// classified as `PackageNotFound` (e.g. `deps-maven`'s `metadata_urls` rejecting a
    /// dot-segment coordinate like `com.example:..`, mirrored here by [`NotFoundRegistry`])
    /// used to make hover return `None` entirely via `.ok()?`. That chain was widened to
    /// plain `.ok()` because a *transient* fetch failure (off-VPN, an expired token, a
    /// DNS-blocked internal host) must degrade to the basic name/requirement/features
    /// card instead of vanishing the whole hover response — a real regression once a
    /// resolvable source could be a private registry rather than always crates.io. A
    /// `PackageNotFound` error takes the same, now-shared path: hover still renders (the
    /// basic card, exactly as the non-resolvable-source branch already produces), just
    /// with no version section — never "a broken hover section built from an empty
    /// version list".
    #[tokio::test]
    async fn test_generate_hover_renders_basic_card_when_registry_reports_not_found() {
        let parse_result = MockParseResult {
            deps: vec![dep_at("com.example:..")],
            uri: crate::test_util::test_uri("/test/pom.xml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &NotFoundRegistry,
            &MOCK_FORMATTER,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover must still render the basic card on a registry error");

        let content = hover.markdown();
        assert!(
            !content.contains("**Latest**"),
            "no version data is available on a registry error; got: {}",
            content
        );
        assert!(
            !content.contains("Recent versions"),
            "must not render a broken version section from an empty list; got: {}",
            content
        );
    }

    /// #474: the "Press `Cmd+.` to update version" footer advertises a code action that
    /// only exists for a resolvable source with actual version data — a resolvable
    /// `Registry` source with a live (even empty) fetch must still show it.
    #[tokio::test]
    async fn test_generate_hover_footer_shown_for_resolvable_source_with_live_versions() {
        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".into(),
                yanked: false,
                published_at: None,
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("Press `Cmd+.` to update version"),
            "a resolvable source with live version data must show the update footer; got: {}",
            content
        );
    }

    /// #1402: an unexpanded template placeholder requirement (`{{ VAR }}`) is rejected by
    /// the same write-path guard every `codeAction` fix routes through
    /// (`edit::requirement_is_placeholder_for`, default-on since #1393), so `codeAction`
    /// returns zero actions for it — the footer must not advertise `Cmd+.` here even though
    /// live version data was fetched, or it becomes a false affordance.
    #[tokio::test]
    async fn test_generate_hover_footer_omitted_for_placeholder_requirement() {
        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".into(),
                yanked: false,
                published_at: None,
            }],
        };
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "{{ SERDE_VERSION }}".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            !content.contains("Press `Cmd+.` to update version"),
            "an unresolved template placeholder has no code action `Cmd+.` could ever \
             produce, so the footer must not render; got: {}",
            content
        );
    }

    /// #474: a non-resolvable source (e.g. a local path or a Docker-style URL ref,
    /// mirrored here by `DependencySource::Path`) offers no diagnostic, inlay hint, or
    /// code action — the footer advertising `Cmd+.` must not render for it, even though a
    /// cached `latest` value exists in `versions.cached` (which `resolvable.then(...)`
    /// must gate *before* it ever reaches the footer condition).
    #[tokio::test]
    async fn test_generate_hover_footer_omitted_for_non_resolvable_source() {
        use crate::parser::DependencySource;

        let uri = crate::test_util::test_uri("/test/workflow.yml");
        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("local-action"),
                DependencySource::Path {
                    path: "./local-action".into(),
                },
            ),
            uri,
        };
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert("local-action".into(), PackageVersions::latest_only("9.9.9"));
            m
        };
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should still be generated for a non-resolvable-source dependency");

        let content = hover.markdown();
        assert!(
            !content.contains("Press `Cmd+.` to update version"),
            "a non-resolvable source offers no update code action, even with a cached \
             latest value present; got: {}",
            content
        );
    }

    /// #501: while `network.offline` is set, `HttpCache` can still serve warm data and
    /// doc-state (`versions.vulnerabilities`/`cached_latest`/deprecation) can still survive
    /// the transition (see `test_generate_hover_footer_shown_when_offline_with_warm_cache_versions`),
    /// so the footer isn't suppressed on `offline` alone — only when offline AND no such
    /// actionable data exists at all. This test is that cold-start case: nothing cached,
    /// nothing resolved, and the OSV scan's own offline failure (`Skipped(QueryFailed)`,
    /// not `Vulnerable`) counts as "no data" too (#501 C5).
    #[tokio::test]
    async fn test_generate_hover_footer_omitted_when_offline_with_no_cached_data() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        // Cold process, nothing cached yet (#501's actual repro): the registry fetch fails
        // (offline, no warm `HttpCache` entry) and there is no cached/resolved/deprecation
        // doc state either, so no `generate_code_actions` producer has anything to act on.
        //
        // `vulnerabilities` carries a `Skipped(QueryFailed)` entry rather than being empty
        // (#501 C5): offline doesn't skip the OSV scan, it lets it run and fail, which is
        // exactly what a real offline cold start writes for every dependency — the gate must
        // not treat that `Skipped` presence as an actionable `Vulnerable` outcome.
        let parse_result = freshness_test_parse_result("serde");
        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("serde"),
            ScanOutcome::Skipped(SkipReason::QueryFailed),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new())
                .with_offline(true)
                .with_vulnerabilities(&vulns),
            &ErrorRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            !content.contains("Press `Cmd+.` to update version"),
            "no code action can be produced while offline with nothing cached, so the \
             footer must not render; got: {}",
            content
        );
        assert!(
            content.contains("📴 *Offline: version and vulnerability data not checked*"),
            "the existing offline notice must still render; got: {}",
            content
        );
    }

    /// #501 (impl-critic C1): `HttpCache` deliberately serves warm entries while offline, so
    /// a `Cmd+.` REFACTOR "update to X" action is still genuinely available whenever a live
    /// version list came back — the footer must not be suppressed just because
    /// `versions.offline` is set.
    #[tokio::test]
    async fn test_generate_hover_footer_shown_when_offline_with_warm_cache_versions() {
        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".into(),
                yanked: false,
                published_at: None,
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()).with_offline(true),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("Press `Cmd+.` to update version"),
            "a warm-cache live version list still offers a real REFACTOR action while \
             offline, so the footer must render; got: {}",
            content
        );
    }

    /// Issue #483 I1: the offline footer must render for a resolvable source, mirroring
    /// the `Cmd+.` footer's own `resolvable` gate immediately above it.
    #[tokio::test]
    async fn test_generate_hover_offline_footer_shown_for_resolvable_source() {
        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".into(),
                yanked: false,
                published_at: None,
            }],
        };
        let parse_result = freshness_test_parse_result("serde");
        let cached = HashMap::new();
        let resolved = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached, &resolved).with_offline(true),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let content = hover.markdown();
        assert!(
            content.contains("Offline: version and vulnerability data not checked"),
            "a resolvable source must show the offline footer when versions.offline is set; \
             got: {}",
            content
        );
    }

    /// Issue #483 I1 (regression guard for the #474/#475 bug class): a non-resolvable
    /// source must never render the offline footer — it was never going to be checked
    /// regardless of `network.offline`, so claiming otherwise is misleading, exactly like
    /// the `Cmd+.` footer this mirrors.
    #[tokio::test]
    async fn test_generate_hover_offline_footer_omitted_for_non_resolvable_source() {
        use crate::parser::DependencySource;

        let uri = crate::test_util::test_uri("/test/workflow.yml");
        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("local-action"),
                DependencySource::Path {
                    path: "./local-action".into(),
                },
            ),
            uri,
        };
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert("local-action".into(), PackageVersions::latest_only("9.9.9"));
            m
        };
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&cached_versions, &resolved_versions).with_offline(true),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should still be generated for a non-resolvable-source dependency");

        let content = hover.markdown();
        assert!(
            !content.contains("Offline:"),
            "a non-resolvable source must not show the offline footer, even with \
             versions.offline set; got: {}",
            content
        );
    }

    /// Issue #1392: a non-offline `Skipped(NoConcreteVersion)` outcome — the common case
    /// of a semver-range requirement with no committed lock file — must surface a footer
    /// explaining vulnerability data was not checked, instead of rendering nothing (the
    /// pre-fix behavior [`test_generate_hover_skipped_outcome_says_nothing_about_vulnerabilities`]
    /// documents for `NonRegistrySource`).
    #[tokio::test]
    async fn test_generate_hover_skip_reason_footer_shown_for_no_concrete_version() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let parse_result = freshness_test_parse_result("serde");
        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("serde"),
            ScanOutcome::Skipped(SkipReason::NoConcreteVersion),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            content.contains("Vulnerability data not checked: no resolved or exact version"),
            "a resolvable source with a NoConcreteVersion skip must show the reason-specific \
             footer; got: {}",
            content
        );
    }

    /// Issue #1392: the reason-specific footer must not double up with the existing #483
    /// offline footer — while offline, only the broader "Offline: version and
    /// vulnerability data not checked" wording should render.
    #[tokio::test]
    async fn test_generate_hover_skip_reason_footer_omitted_while_offline() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let parse_result = freshness_test_parse_result("serde");
        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("serde"),
            ScanOutcome::Skipped(SkipReason::QueryFailed),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new())
                .with_vulnerabilities(&vulns)
                .with_offline(true),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            content.contains("Offline: version and vulnerability data not checked"),
            "offline must still show its own broader footer; got: {}",
            content
        );
        assert!(
            !content.contains("Vulnerability data not checked: the OSV.dev query failed"),
            "the reason-specific footer must not also render while offline; got: {}",
            content
        );
    }

    /// Issue #1392 (tester gap 2): `QueryFailed` while online (not offline, unlike the
    /// test right above) must show its own reason-specific footer — a real OSV.dev query
    /// failure with network reachable, distinct from the offline case.
    #[tokio::test]
    async fn test_generate_hover_skip_reason_footer_shown_for_query_failed_online() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let parse_result = freshness_test_parse_result("serde");
        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("serde"),
            ScanOutcome::Skipped(SkipReason::QueryFailed),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            content.contains("Vulnerability data not checked: the OSV.dev query failed"),
            "an online QueryFailed skip must show the reason-specific footer; got: {}",
            content
        );
    }

    /// Issue #1392 (tester gap 2): table-driven coverage for the remaining `SkipReason`
    /// variants at the hover integration level (`UnmappableName`, `UnmappableEcosystem`,
    /// `Truncated`) — the hover footer shows every non-`NonRegistrySource` reason,
    /// unlike the diagnostics notice (M1), so all three must render here.
    #[tokio::test]
    async fn test_generate_hover_skip_reason_footer_covers_remaining_variants() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let cases = [
            (
                SkipReason::UnmappableName,
                "the package name could not be mapped",
            ),
            (
                SkipReason::UnmappableEcosystem,
                "this ecosystem is not supported",
            ),
            (
                SkipReason::Truncated,
                "the OSV.dev result set was truncated",
            ),
        ];
        for (reason, expected_fragment) in cases {
            let parse_result = freshness_test_parse_result("serde");
            let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
            vulns.insert(
                crate::test_util::vuln_key("serde"),
                ScanOutcome::Skipped(reason),
            );

            let hover = generate_hover(
                &parse_result,
                Position::new(0, 2).into(),
                VersionData::new(&HashMap::new(), &HashMap::new()).with_vulnerabilities(&vulns),
                &MockRegistry,
                &MOCK_FORMATTER,
                crate::freshness::FreshnessSettings::default(),
                PublishTime::now(),
            )
            .await
            .expect("hover should be generated");

            let content = hover.markdown();
            assert!(
                content.contains(expected_fragment),
                "{reason:?} must show its reason-specific footer; got: {content}"
            );
        }
    }

    /// Issue #1392: `NonRegistrySource` must not gain a reason-specific footer either —
    /// mirrors [`test_generate_hover_offline_footer_omitted_for_non_resolvable_source`]'s
    /// reasoning for a source that was never going to be checked regardless.
    #[tokio::test]
    async fn test_generate_hover_skip_reason_footer_omitted_for_non_registry_source() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let parse_result = MockParseResult {
            deps: vec![dep_at("path-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            crate::test_util::vuln_key("path-pkg"),
            ScanOutcome::Skipped(SkipReason::NonRegistrySource),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &HashMap::new()).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            !content.contains("Vulnerability data not checked"),
            "a non-registry source must never render the reason-specific footer; got: {}",
            content
        );
    }

    // --- Supply-chain trust signal (spec 037) ---

    async fn deps_dev_mock_client() -> (mockito::ServerGuard, crate::DepsDevClient) {
        let server = mockito::Server::new_async().await;
        let client =
            crate::DepsDevClient::for_test(Arc::new(crate::HttpCache::new()), server.url());
        (server, client)
    }

    /// A single dependency (`express@4.19.2`) whose in-use version resolves via
    /// `resolved_versions`, ready to attach to `VersionData::with_trust`.
    fn express_fixture() -> (
        MockParseResult,
        HashMap<crate::PackageName, ConcreteVersion>,
    ) {
        let parse_result = freshness_test_parse_result("express");
        let resolved_versions = HashMap::from([(
            crate::PackageName::new("express"),
            ConcreteVersion::new("4.19.2"),
        )]);
        (parse_result, resolved_versions)
    }

    /// SC-001, pinned to the deterministic path per critic N4: the mock responds
    /// instantly, so `generate_hover`'s `DEPS_DEV_WAIT_BUDGET` await reliably
    /// completes well within budget rather than depending on a cold-memo race.
    #[tokio::test]
    async fn test_generate_hover_trust_signal_renders_score_and_verified_provenance() {
        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [{"verified": true}], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/expressjs/express"}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}
                ]}"#,
            )
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(200)
            .with_body(r#"{"scorecard": {"overallScore": 8.5}}"#)
            .create_async()
            .await;
        let deps_dev = Arc::new(deps_dev);

        let (parse_result, resolved_versions) = express_fixture();
        let registry = MockRegistryWithVersions { versions: vec![] };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        let line = content
            .lines()
            .find(|l| l.contains("Supply chain"))
            .unwrap_or_else(|| panic!("expected a Supply chain line, got: {}", content));
        insta::assert_snapshot!(line, @"🔐 **Supply chain**: OpenSSF Scorecard `8.5`/10 · Provenance: verified");
    }

    /// Issue #204 (impl-critic review S2 / tester's independent gap): the deps.dev
    /// path is the *only* license source for 7 of this PR's 8 ecosystems
    /// (Cargo/npm/Go/Maven/Bundler/NuGet/PyPI) — only Composer's native-list path had
    /// an end-to-end `generate_hover` test before this one.
    #[tokio::test]
    async fn test_generate_hover_deps_dev_license_renders_license_line() {
        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [], "licenses": ["MIT"]}"#,
            )
            .create_async()
            .await;
        let deps_dev = Arc::new(deps_dev);

        let (parse_result, resolved_versions) = express_fixture();
        let registry = MockRegistryWithVersions { versions: vec![] };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            content.contains("**License**: `MIT`"),
            "expected the deps.dev-sourced license to render; got: {}",
            content
        );
        // No live version list was fetched (`MockRegistryWithVersions { versions: vec![] }`),
        // so no `**Latest**` line exists either — the "(latest version license
        // unavailable)" note must not render for a dependency with no latest version
        // at all (impl-critic review S1).
        assert!(
            !content.contains("unavailable"),
            "no latest version exists to compare against; got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_trust_signal_unverified_provenance() {
        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [{"verified": false}], "attestations": [], "relatedProjects": []}"#,
            )
            .create_async()
            .await;
        let deps_dev = Arc::new(deps_dev);

        let (parse_result, resolved_versions) = express_fixture();
        let registry = MockRegistryWithVersions { versions: vec![] };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            content.contains("Provenance: attested but unverified"),
            "got: {}",
            content
        );
    }

    #[tokio::test]
    async fn test_generate_hover_trust_signal_none_provenance_and_self_reported_marker() {
        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/expressjs/express"}, "relationType": "SOURCE_REPO", "relationProvenance": "UNVERIFIED_METADATA"}
                ]}"#,
            )
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(200)
            .with_body(r#"{"scorecard": {"overallScore": 7.2}}"#)
            .create_async()
            .await;
        let deps_dev = Arc::new(deps_dev);

        let (parse_result, resolved_versions) = express_fixture();
        let registry = MockRegistryWithVersions { versions: vec![] };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            content.contains("Provenance: none found"),
            "got: {}",
            content
        );
        assert!(
            content.contains("*(self-reported repo)*"),
            "an UNVERIFIED_METADATA-only relation must be disclosed; got: {}",
            content
        );
    }

    /// SC-004: every ecosystem `deps_dev_system` does not cover (not just
    /// Composer) must issue zero deps.dev requests — checked before any
    /// spawn, per plan.md §8's gate.
    #[tokio::test]
    async fn test_generate_hover_trust_signal_skips_uncovered_ecosystems() {
        for ecosystem in [
            crate::EcosystemId::Composer,
            crate::EcosystemId::Dart,
            crate::EcosystemId::Swift,
        ] {
            let (mut server, deps_dev) = deps_dev_mock_client().await;
            let never_called = server
                .mock("GET", mockito::Matcher::Regex("^/v3/.*".into()))
                .expect(0)
                .create_async()
                .await;
            let deps_dev = Arc::new(deps_dev);

            let (parse_result, resolved_versions) = express_fixture();
            let registry = MockRegistryWithVersions { versions: vec![] };

            let hover = generate_hover(
                &parse_result,
                Position::new(0, 2).into(),
                VersionData::new(&HashMap::new(), &resolved_versions)
                    .with_ecosystem(ecosystem)
                    .with_trust(&deps_dev),
                &registry,
                &MOCK_FORMATTER,
                crate::freshness::FreshnessSettings::default(),
                PublishTime::now(),
            )
            .await
            .expect("hover should be generated");

            let content = hover.markdown();
            assert!(
                !content.contains("Supply chain"),
                "{ecosystem:?}: got: {}",
                content
            );
            never_called.assert_async().await;
        }
    }

    /// Regression for security M2 / critic C2: a private/non-mirror
    /// `AlternateRegistry` source must never reach deps.dev, even though it
    /// resolves against this ecosystem's own registry (`resolvable` alone
    /// is the wrong, too-permissive gate — see
    /// `MOCK_WIDENED_RESOLVE_FORMATTER`'s docs).
    #[tokio::test]
    async fn test_generate_hover_trust_signal_skips_private_registry_source() {
        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let never_called = server
            .mock("GET", mockito::Matcher::Regex("^/v3/.*".into()))
            .expect(0)
            .create_async()
            .await;
        let deps_dev = Arc::new(deps_dev);

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("internal-pkg"),
                crate::parser::DependencySource::AlternateRegistry {
                    index: "https://index.mycorp.internal".to_string(),
                    mirrors_crates_io: false,
                },
            ),
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let resolved_versions = HashMap::from([(
            crate::PackageName::new("internal-pkg"),
            ConcreteVersion::new("1.0.0"),
        )]);
        let registry = MockRegistryWithVersions { versions: vec![] };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Cargo)
                .with_trust(&deps_dev),
            &registry,
            &MOCK_WIDENED_RESOLVE_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(
            !content.contains("Supply chain"),
            "a private registry's package name/version must never reach deps.dev; got: {}",
            content
        );
        never_called.assert_async().await;
    }

    /// Regression for review C4 / critic C4: `versions.offline` must be
    /// checked in the same gate as every other network-gated hover section
    /// — offline must not spawn a task or write a negative memo entry.
    #[tokio::test]
    async fn test_generate_hover_trust_signal_skips_when_offline() {
        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let never_called = server
            .mock("GET", mockito::Matcher::Regex("^/v3/.*".into()))
            .expect(0)
            .create_async()
            .await;
        let deps_dev = Arc::new(deps_dev);

        let (parse_result, resolved_versions) = express_fixture();
        let registry = MockRegistryWithVersions { versions: vec![] };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev)
                .with_offline(true),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let content = hover.markdown();
        assert!(!content.contains("Supply chain"), "got: {}", content);
        never_called.assert_async().await;
    }

    /// SC-003: a deps.dev outage must leave every other hover section
    /// byte-identical to a hover generated with no trust client at all.
    #[tokio::test]
    async fn test_generate_hover_trust_signal_failure_leaves_other_content_unchanged() {
        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(500)
            .create_async()
            .await;
        let deps_dev = Arc::new(deps_dev);

        let (parse_result, resolved_versions) = express_fixture();
        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "4.19.2".into(),
                yanked: false,
                published_at: None,
            }],
        };

        let with_failing_trust = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let without_trust = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let a = with_failing_trust.markdown();
        let b = without_trust.markdown();
        assert!(!a.contains("Supply chain"), "got: {}", a);
        assert_eq!(a, b);
    }

    /// Exercises `generate_hover`'s own real `tokio::time::timeout(DEPS_DEV_WAIT_BUDGET,
    /// handle)` wrap directly — not a smaller artificial stand-in (review's flagged test
    /// gap: the only prior test of the underlying mechanism drove
    /// `DepsDevClient::trust_signal` with its own 5ms timeout, never through
    /// `generate_hover` at all).
    ///
    /// Both deps.dev calls are delayed just under the internal `DEPS_DEV_CALL_TIMEOUT`
    /// (400ms each) but together exceed the real `DEPS_DEV_WAIT_BUDGET` (700ms) — the only
    /// way to reach the hover-level timeout without either call tripping its own shorter
    /// per-call cap first. `flavor = "multi_thread"` so the blocking `std::thread::sleep`
    /// inside the mock handler runs on a different worker thread than the test's own
    /// timer, matching
    /// `deps_dev::tests::trust_signal_survives_dropped_join_handle_and_warms_memo`'s
    /// technique.
    ///
    /// Deliberately does **not** also assert that a later hover picks up the memo the
    /// background task warms — two prior attempts at that (a tight 50ms poll, then a
    /// spaced 5×1s retry) both passed locally but failed consistently on CI's Linux
    /// runners (stable and beta; macOS and Windows were unaffected), each time burning
    /// its *entire* budget rather than merely running late. That symmetry between two
    /// very different waiting strategies points at the environment, not the margin, and
    /// nothing here can distinguish "the background task is still running, slowly" from
    /// "it already failed and negative-cached the result" from inside this same racing
    /// test — see the sibling test below for a deterministic replacement that proves the
    /// warm-memo path without racing this timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_generate_hover_trust_signal_over_real_wait_budget_omits_section() {
        const CALL_DELAY: std::time::Duration = std::time::Duration::from_millis(375);

        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body_from_request(move |_req| {
                std::thread::sleep(CALL_DELAY);
                r#"{"slsaProvenances": [{"verified": true}], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/expressjs/express"}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}
                ]}"#
                .as_bytes()
                .to_vec()
            })
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(200)
            .with_body_from_request(move |_req| {
                std::thread::sleep(CALL_DELAY);
                r#"{"scorecard": {"overallScore": 8.5}}"#.as_bytes().to_vec()
            })
            .create_async()
            .await;
        let deps_dev = Arc::new(deps_dev);

        let (parse_result, resolved_versions) = express_fixture();
        let registry = MockRegistryWithVersions { versions: vec![] };

        let first = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let first_content = first.markdown();
        assert!(
            !first_content.contains("Supply chain"),
            "the real ~750ms two-call sequence must exceed the 700ms wait budget on the \
             first hover; got: {}",
            first_content
        );
        // The detached task spawned above keeps running past this point by design
        // (that's the whole point of spawn-and-warm) — deliberately not awaited or
        // polled for here; see this function's doc comment.
    }

    /// The warm-memo half of the spawn-and-warm design (plan.md §12), proved
    /// deterministically rather than by racing the timeout test above: a memo entry
    /// populated by a direct, un-delayed `DepsDevClient::trust_signal` call (no timing
    /// involved — it is simply `.await`ed to completion) is read by a subsequent
    /// `generate_hover` call through the exact same `VersionData::with_trust` /
    /// `push_trust_signal_hover_section` path the timeout test above exercises. Together
    /// the two tests cover `generate_hover`'s real integration with `DepsDevClient` on
    /// both the "too slow, omit" and "already warm, render" branches, without either one
    /// depending on winning a race against the ambient test suite's scheduling.
    #[tokio::test]
    async fn test_generate_hover_renders_trust_signal_from_a_warm_memo() {
        let (mut server, deps_dev) = deps_dev_mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [{"verified": true}], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/expressjs/express"}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}
                ]}"#,
            )
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(200)
            .with_body(r#"{"scorecard": {"overallScore": 8.5}}"#)
            .create_async()
            .await;

        let warmed = deps_dev
            .trust_signal("npm", "express", "4.19.2")
            .await
            .expect("the direct, un-delayed call must warm the memo deterministically");
        assert!(warmed.scorecard.is_some(), "fixture includes a scorecard");

        let deps_dev = Arc::new(deps_dev);
        let (parse_result, resolved_versions) = express_fixture();
        let registry = MockRegistryWithVersions { versions: vec![] };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2).into(),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MOCK_FORMATTER,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let content = hover.markdown();
        assert!(
            content.contains("Supply chain"),
            "a hover reading an already-warm memo must render the trust signal \
             immediately; got: {}",
            content
        );
    }
}
