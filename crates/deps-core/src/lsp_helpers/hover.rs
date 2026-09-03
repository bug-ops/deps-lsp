use std::sync::Arc;
use std::time::Duration;

use tower_lsp_server::ls_types::{Hover, HoverContents, MarkupContent, MarkupKind, Position};

use crate::deps_dev::deps_dev_system;
use crate::osv::ScanOutcome;
use crate::{
    ConcreteVersion, Deprecation, ParseResult, ProvenanceStatus, PublishTime, Registry,
    SupplyChainTrustSignal, Version, VersionReq, format_relative_age, is_within_cooldown,
};

use super::{
    EcosystemFormatter, HOVER_RECENT_VERSIONS, VersionData, escape_markdown, in_use_version,
    markdown_code_span, position_in_range,
};

/// Bounds how long [`generate_hover`] *waits* for the spawned deps.dev trust-signal
/// fetch — never the fetch itself, which keeps running to completion and warms
/// [`crate::deps_dev::DepsDevClient`]'s memo even after this deadline elapses
/// (spec 037, plan.md §8's "spawn-and-warm" design). Deliberately not named
/// `..._TOTAL_...`: merging this with the fetch's own per-call timeouts would
/// silently kill spawn-and-warm — an over-budget fetch would then die entirely
/// instead of finishing into the memo, and the next hover would re-fire it under
/// the short error TTL rather than getting a memo hit.
const DEPS_DEV_WAIT_BUDGET: Duration = Duration::from_millis(700);

/// Formats the relative-age suffix for one "Recent versions" hover entry.
///
/// Returns an empty string when the registry doesn't expose a publish timestamp for
/// `version` (`published_at()` is `None`), so the entry renders exactly as it did
/// before this feature existed (graceful degradation, US-003).
///
/// `now` is taken as an explicit parameter rather than read internally so every entry
/// in the same "Recent versions" list is aged against one consistent instant.
fn version_age_suffix(version: &dyn Version, now: PublishTime) -> String {
    version
        .published_at()
        .map(|published| format!(" — {}", format_relative_age(published.age_secs_from(now))))
        .unwrap_or_default()
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

pub async fn generate_hover<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    position: Position,
    versions: VersionData<'_>,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
    freshness: crate::freshness::FreshnessSettings,
    now: PublishTime,
) -> Option<Hover> {
    use std::fmt::Write;

    let dep = parse_result.dependencies().into_iter().find(|d| {
        let on_name = position_in_range(position, d.name_range());
        let on_version = d
            .version_range()
            .is_some_and(|r| position_in_range(position, r));
        on_name || on_version
    })?;

    // A non-resolvable source (e.g. `CustomRegistry`, Git, Path) doesn't resolve
    // against `registry` at all — fetching by name here would silently check an
    // unrelated or coincidentally-named public-registry package (#248), so hover
    // must skip the registry lookup and every section built from it entirely.
    // `can_resolve_source` (not the bare `DependencySource::is_version_resolvable`)
    // so an ecosystem whose registry routes more sources than the generic default
    // (e.g. `deps-cargo`'s resolved `AlternateRegistry`) gets hover support for
    // them without a new gate here.
    let dep_source = dep.source();
    let resolvable = formatter.can_resolve_source(&dep_source);

    // Hoisted above the registry fetch below (moved from its previous position
    // right before the `**Current**`/`**Requirement**` line) so the deps.dev gate
    // just below can use it: both need "the normalized name", and the gate must be
    // built and the fetch spawned *before* awaiting the registry fetch so the two
    // requests overlap instead of stacking (spec 037, plan.md §8 M6).
    let normalized_name = formatter.normalize_package_name(dep.name());

    // Supply-chain trust signal (spec 037): spawned as a detached background task,
    // concurrently with the registry fetch just below, so a slow or cold-memo
    // deps.dev never adds its own latency on top of the registry fetch's. Only
    // `handlers/hover.rs` (deps-lsp) ever sets `versions.trust`, which is what makes
    // FR-010's hover-only scope structural: every other surface (diagnostics, code
    // actions, inlay hints, code lenses) is never handed a client and so can never
    // reach deps.dev.
    //
    // Gated on all of: a client was handed in, `network.offline` is not set, the source
    // resolves against a **public** registry, the ecosystem is one of the seven
    // `deps_dev_system` maps, and a concrete in-use version exists — the last two
    // checked with **no** network I/O, so an ecosystem `deps_dev_system` excludes
    // (Composer, Dart, Swift, ...) spawns nothing at all.
    //
    // `formatter.source_is_public_registry_content(&dep_source)`, not the weaker
    // `resolvable` (`can_resolve_source`): `resolvable` is deliberately widened by some
    // ecosystems (e.g. `deps-cargo`'s `AlternateRegistry`) to cover *any* configured
    // registry, private/internal ones included — reusing it here would send a private
    // package's name and version to deps.dev by default (security audit M2). `source_is_
    // public_registry_content` is the same, stricter predicate this server's other
    // third-party lookup (OSV) already gates on (`lifecycle.rs`).
    //
    // `!versions.offline`: every other network-gated hover section in this function
    // checks `versions.offline` (the `Cmd+.` footer, the offline footer itself below) —
    // without it here, offline mode still spawns a task per hover and writes a 90s
    // negative memo entry, keeping the signal absent for up to 90s per package after
    // reconnecting for no reason (critic C4).
    //
    // `tokio::spawn` panics outside a Tokio runtime — every caller of `generate_hover`
    // is `#[tokio::test]`-async or the real LSP server, so this is safe here, but no
    // doc-test may call this function directly. The spawned future captures only
    // owned/`'static` data (`Arc<DepsDevClient>`, `&'static str`, owned `String`s) so
    // it satisfies `Send + 'static` with no borrow from `dep`/`parse_result`.
    let trust_handle = versions.trust.and_then(|client| {
        let ecosystem = versions.ecosystem?;
        let system = deps_dev_system(ecosystem)?;
        if versions.offline || !formatter.source_is_public_registry_content(&dep_source) {
            return None;
        }
        let version = in_use_version(
            dep,
            normalized_name.as_str(),
            versions.resolved,
            formatter,
            ecosystem,
        )?;
        let client = Arc::clone(client);
        let name = dep.name().to_string();
        Some(tokio::spawn(async move {
            client.trust_signal(system, &name, &version).await
        }))
    });

    // `now` is a caller-supplied parameter (issue #227 M4) rather than computed
    // internally via `PublishTime::now()` — this is what lets tests pin an exact
    // cooldown-boundary instant deterministically, and guarantees every age rendered
    // in this single hover response (the `**Latest**` line and the "Recent versions"
    // list below) is aged against the same instant.
    //
    // `.ok()`, not `.ok()?`: a fetch failure here (off-VPN, an expired token, a
    // DNS-blocked internal host — routine for a self-hosted registry's normal users)
    // must degrade to the same basic name/requirement/features card the `!resolvable`
    // branch below renders, not vanish the entire hover response. Propagating `None`
    // out of the whole function on any transient fetch error was a real regression
    // once a resolvable source could be a private index rather than always crates.io.
    let available_versions = if resolvable {
        registry
            .get_versions_from(dep.name(), &dep_source, freshness)
            .await
            .ok()
    } else {
        None
    };

    // FR-014: a resolved-but-not-crates.io source (e.g. Cargo's `AlternateRegistry`) must
    // not carry a link to the ecosystem's *default* registry — once live version data from
    // the real registry renders below, an unrelated link reads as confirmation it's real.
    //
    // `.filter(|u| !u.is_empty())`: an `EcosystemFormatter::package_url` implementation can
    // return an empty string for a dependency name it can't turn into a real URL (e.g. a
    // name that isn't a valid identity for that ecosystem's registry) without also
    // overriding `suppress_package_url` — defense-in-depth so an empty URL can never render
    // as a dead `[name]()` markdown link regardless of which ecosystem forgot the override
    // (#474).
    let url = (!formatter.suppress_package_url(&dep_source))
        .then(|| formatter.package_url(dep.name()))
        .filter(|u| !u.is_empty());

    // Pre-allocate with estimated capacity to reduce allocations
    let mut markdown = String::with_capacity(512);
    match &url {
        Some(url) => write!(
            &mut markdown,
            "# [{}]({})\n\n",
            escape_markdown(dep.name().as_str()),
            url
        ),
        None => write!(
            &mut markdown,
            "# {}\n\n",
            escape_markdown(dep.name().as_str())
        ),
    }
    .unwrap();

    let resolved: Option<&str> = if formatter.manifest_requirement_is_resolved_version(dep) {
        dep.version_requirement().map(VersionReq::as_str)
    } else {
        versions
            .resolved
            .get(normalized_name.as_str())
            .or_else(|| versions.resolved.get(dep.name()))
            .map(ConcreteVersion::as_str)
    };
    if let Some(resolved_ver) = resolved {
        write!(
            &mut markdown,
            "**Current**: {}\n\n",
            markdown_code_span(resolved_ver)
        )
        .unwrap();
    } else if let Some(version_req) = dep.version_requirement() {
        write!(
            &mut markdown,
            "**Requirement**: {}\n\n",
            markdown_code_span(version_req.as_str())
        )
        .unwrap();
    }

    if let Some(marker_expr) = dep.markers() {
        write!(
            &mut markdown,
            "**Active when**: {}\n\n",
            markdown_code_span(marker_expr)
        )
        .unwrap();
    }

    // The `**Latest**` line prefers the just-fetched Ch2 list (`available_versions`) over
    // the Ch1 cache (`versions.cached`, populated by the lifecycle's background fetch)
    // whenever a live fetch is available. Ch1 alone would let this line render a version
    // older than the one the "Recent versions" list right below it shows as `*(latest)*` —
    // a self-contradictory response when a new version is published between the last
    // background fetch and this hover call, with the cooldown callout then decided off the
    // stale operand too (issue #227 F5). Falls back to Ch1 only when there is no live list
    // at all (non-resolvable source) — NOT merely when the live list has no stable entry:
    // a live list that's all pre-release still means a live fetch happened, and rendering
    // a stale Ch1 version that may not even appear in the live "Recent versions" list below
    // would be exactly the self-contradiction #227 F5 fixed, via a different path (#313).
    //
    // Exception (#373): when the list-based pick fails on a non-empty list, `latest_line`
    // can render a version sourced from `list_fallback_latest` — `Registry::get_latest_matching`
    // instead of the list — which the "Recent versions" list below is built from `available_versions`
    // alone and so may not contain (Go's `/@latest` can answer with a pseudo-version `/@v/list`
    // never enumerates). No entry is marked `*(latest)*` in that case, since `live_latest_idx`
    // is `None`. This is an accepted, narrower trade-off than the contradiction #227 F5/#313
    // guard against: rendering *a* correct latest version, even one absent from or unmarked in
    // the list below, beats rendering no `**Latest**` line at all.
    //
    // `live_latest_idx` (not raw index 0) picks the entry: `available_versions` is sorted
    // purely by version number, so a pre-release with the highest number can sort to index 0
    // even though it isn't the ecosystem's "latest stable" pick — mirroring this line to the
    // raw top entry would tag a pre-release as `(latest)` below. The pick is delegated to
    // `Registry::select_latest_matching` — the exact same call `lifecycle.rs`'s background
    // fetch uses to populate `versions.cached`'s `latest` and every cache-backed diagnostic —
    // rather than re-derived here with a generic `is_stable()` scan. The two must never
    // disagree about what "latest" is: an ecosystem whose `select_latest_matching` applies a
    // ranking preference beyond plain resolvability (e.g. npm's #338 NFR-002, which prefers a
    // non-deprecated version over a newer deprecated one) gets that same preference reflected
    // in this hover response instead of hover independently picking a different version and
    // silently dropping that version's `*(deprecated)*`/`*(yanked)*` label because it thinks
    // it's `(latest)` (#347/#348 S1). Recorded as an index rather than a version string so the
    // "Recent versions" marker below can match by position instead of string equality, which
    // could spuriously tag more than one entry if two ever shared a version string.
    let wildcard_req = VersionReq::new("*");
    let live_latest_idx = available_versions
        .as_ref()
        .and_then(|v| registry.select_latest_matching(v, &wildcard_req));
    // #373: `live_latest_idx` can be `None` even though a live fetch DID happen and the
    // list is non-empty — e.g. Go's `/@v/list` never enumerates pseudo-versions, so an
    // untagged module whose whole tagged history is pre-release fails the list-based pick
    // entirely. This must not fall straight to the Ch1 cache (see the comment on
    // `latest_line` below) — instead mirror the exact fallback `lifecycle.rs`'s background
    // fetch already uses for this same case: a second call to `Registry::get_latest_matching`,
    // which some registries (Go's `/@latest`) answer from a source more complete than the
    // list endpoint. Only attempted for a non-empty live list with no list-based pick; an
    // empty or absent live list keeps falling back to Ch1 untouched. Bounded by
    // `HOVER_FALLBACK_TIMEOUT` and logged like `lifecycle.rs`'s own fallback — a failure,
    // timeout, or `None` here degrades gracefully to no `**Latest**` line, same as today:
    // `available_versions` already succeeded, so this fallback's own error must not abort
    // the rest of the hover.
    let list_fallback_latest = if available_versions.as_ref().is_some_and(|v| !v.is_empty())
        && live_latest_idx.is_none()
    {
        match tokio::time::timeout(
            HOVER_FALLBACK_TIMEOUT,
            registry.get_latest_matching_from(dep.name(), &dep_source, &wildcard_req, None),
        )
        .await
        {
            Ok(Ok(found)) => {
                tracing::debug!(package = %dep.name(), found = found.is_some(), "hover latest fallback (get_latest_matching) resolved");
                found
            }
            Ok(Err(error)) => {
                tracing::warn!(package = %dep.name(), %error, "hover latest fallback (get_latest_matching) failed");
                None
            }
            Err(_) => {
                tracing::warn!(
                    package = %dep.name(),
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
    // A non-empty live list with no stable entry is deliberately treated differently from
    // an empty (or absent) live list: the former tries `list_fallback_latest` (#373) first —
    // a second registry call for the rare "list-based pick failed but a live fetch happened"
    // case — before giving up, rather than falling back to the Ch1 cache, since the cache's
    // version wouldn't be part of what the live list just showed. Only once that fallback
    // also yields nothing does the line render nothing at all (no header, matching the empty
    // "Recent versions" list right beneath it). An empty live list carries no such
    // contradiction risk — it has nothing to contradict — so it keeps falling back to Ch1,
    // same as when there's no live fetch.
    let latest_line: Option<(&str, Option<PublishTime>)> = match &available_versions {
        Some(v) if !v.is_empty() => live_latest_idx
            .map(|idx| &v[idx])
            .map(|live| (live.version_string().as_str(), live.published_at()))
            .or_else(|| {
                list_fallback_latest
                    .as_deref()
                    .map(|live| (live.version_string().as_str(), live.published_at()))
            }),
        _ => cached_latest.map(|v| (v.latest.as_str(), v.published_at)),
    };
    if let Some((latest_ver, raw_published_at)) = latest_line {
        let published_at = freshness.enabled.then_some(raw_published_at).flatten();
        let age_secs = published_at.map(|p| p.age_secs_from(now));
        write!(
            &mut markdown,
            "**Latest**: {}",
            markdown_code_span(latest_ver)
        )
        .unwrap();
        if let Some(age_secs) = age_secs {
            write!(
                &mut markdown,
                " *(published {})*",
                format_relative_age(age_secs)
            )
            .unwrap();
        }
        markdown.push_str("\n\n");
        if age_secs.is_some_and(|age| is_within_cooldown(age, freshness.cooldown_secs)) {
            markdown.push_str(
                "> ⏳ **Recently published** — this release is still within the cooldown window.\n\
                 > It may still be yanked or superseded; consider verifying before upgrading.\n\n",
            );
        }
    }

    // #394 S2: prefer the version-qualified key so a hover on one occurrence
    // of a duplicated name never shows another occurrence's OSV result. See
    // `crate::osv::vulnerability_keys` for when qualification kicks in.
    let vuln_key = versions.ecosystem.and_then(|ecosystem| {
        crate::osv::vulnerability_keys(parse_result, versions.resolved, formatter, ecosystem)
            .remove(&dep.name_range())
    });
    let vuln_outcome = versions.vulnerabilities.and_then(|m| {
        vuln_key
            .as_deref()
            .and_then(|key| m.get(key))
            .or_else(|| m.get(&normalized_name))
            .or_else(|| m.get(dep.name().as_str()))
    });
    let deprecation = versions
        .outcomes
        .and_then(|o| o.deprecation(&normalized_name));
    // Package-level context (#205) renders before per-version security advisories:
    // deprecation is a property of the package, advisories of the version.
    push_deprecation_hover_section(&mut markdown, formatter, deprecation);
    push_vulnerability_hover_section(&mut markdown, vuln_outcome);

    // Awaited last, after every other section above that needed no network I/O of
    // its own, so the wait below overlaps as much of this function's own work as
    // possible — by now `available_versions` has already resolved too. Bounds only
    // the *wait*: over budget, the spawned task above keeps running and warms
    // `DepsDevClient`'s memo regardless (see `DEPS_DEV_WAIT_BUDGET`'s docs). A
    // `JoinHandle` `Err` (the task panicked) is swallowed exactly like a timeout or a
    // fetch failure — FR-006 must hold on this path too, not just the network ones.
    let trust_signal = match trust_handle {
        Some(handle) => match tokio::time::timeout(DEPS_DEV_WAIT_BUDGET, handle).await {
            Ok(Ok(signal)) => signal,
            Ok(Err(_)) | Err(_) => None,
        },
        None => None,
    };
    push_trust_signal_hover_section(&mut markdown, trust_signal.as_ref());

    // `!v.is_empty()`, not just `Some(_)` (#550): a resolvable source's live fetch can
    // succeed with a genuinely empty list — e.g. a real GitHub repository whose only
    // tags don't parse as full semver (`dtolnay/rust-toolchain`'s sole tag `v1`) — and
    // a "**Recent versions**:" header with no entries under it is never useful,
    // regardless of ecosystem.
    if let Some(available_versions) = available_versions.as_ref().filter(|v| !v.is_empty()) {
        // Matched by position against `live_latest_idx` (the header's stable-latest pick)
        // rather than raw index 0 or string equality: `available_versions` is sorted purely
        // by version number, so index 0 can be a pre-release the header itself doesn't call
        // "latest" (issue #313), and matching by version string instead of index could tag
        // more than one entry if two ever shared a version string. No match in the rendered
        // top-N slice simply omits the marker.
        markdown.push_str("**Recent versions**:\n");
        for (i, version) in available_versions
            .iter()
            .take(HOVER_RECENT_VERSIONS)
            .enumerate()
        {
            let version_span = markdown_code_span(version.version_string().as_str());
            let age_suffix = if freshness.enabled {
                version_age_suffix(version.as_ref(), now)
            } else {
                String::new()
            };
            if Some(i) == live_latest_idx {
                if version.removal_status().is_flagged() {
                    // The resolved "latest" can itself be flagged (e.g. npm's ranking
                    // preference falls through to a deprecated version when no clean one
                    // exists) — the deprecation/yank warning must not silently vanish just
                    // because this entry also carries the `(latest)` marker (#347/#348 S1).
                    writeln!(
                        &mut markdown,
                        "- {version_span} *(latest)* {}{age_suffix}",
                        formatter.yanked_label()
                    )
                    .unwrap();
                } else {
                    writeln!(&mut markdown, "- {version_span} *(latest)*{age_suffix}").unwrap();
                }
            } else if version.removal_status().is_flagged() {
                writeln!(
                    &mut markdown,
                    "- {} {}{}",
                    version_span,
                    formatter.yanked_label(),
                    age_suffix
                )
                .unwrap();
            } else {
                writeln!(&mut markdown, "- {version_span}{age_suffix}").unwrap();
            }
        }
    }

    // The footer advertises a `Cmd+.` code action — none is ever offered for a source that
    // is deliberately non-resolvable (e.g. a local composite action or a Docker image ref),
    // so rendering it unconditionally is misleading there (#474). Gated on `resolvable`
    // alone, not on `available_versions`/`cached_latest` also being populated: a
    // vulnerability-fix or unsatisfiable-fix code action (`code_actions.rs`) can exist from
    // `versions.vulnerabilities` — populated independently of the registry fetch
    // (`lifecycle.rs`) — even when both of those are empty (e.g. a registry fetch failure),
    // so requiring them too would silently drop the footer while `Cmd+.` still offers a fix.
    //
    // Also gated on offline data availability (#501): `HttpCache` deliberately serves warm
    // entries while offline (it force-enables caching in that mode), and doc-state fields —
    // `versions.vulnerabilities`/`cached_latest`/deprecation — survive an online-to-offline
    // transition via `preserve_cache`, so `Cmd+.` can still produce a real REFACTOR/fix/
    // replacement action offline as long as *some* version, vulnerability, or deprecation
    // data was actually rendered above. Only suppress when offline AND none of that data is
    // present — a cold process with nothing cached yet, where no producer in
    // `generate_code_actions` has anything to act on.
    //
    // `matches!(vuln_outcome, Some(ScanOutcome::Vulnerable(_)))`, not `vuln_outcome.is_some()`
    // (#501 C5): offline does not skip the OSV scan, it lets it run and fail, which writes
    // `ScanOutcome::Skipped(_)` for every dependency — `is_some()` would be true in exactly
    // #501's own cold-start repro and only `Vulnerable` ever backs
    // `build_vulnerability_fix_action` (`code_actions.rs`).
    let has_offline_actionable_data = available_versions.as_ref().is_some_and(|v| !v.is_empty())
        || cached_latest.is_some()
        || matches!(vuln_outcome, Some(ScanOutcome::Vulnerable(_)))
        || deprecation.is_some();
    // #550: a live fetch that genuinely succeeded with zero entries (`Some(&[])`,
    // distinct from `None` — a fetch that errored or never ran, where an unrelated
    // Cmd+. action such as an unsatisfiable-fix might still exist per #474's own
    // reasoning above) is definitive proof there is nothing version-wise to update to.
    // Combined with no cached/vulnerability/deprecation data either
    // (`!has_offline_actionable_data`, which already folds in this same emptiness
    // check), the footer would otherwise advertise an action that provably does not
    // exist — the "empty Recent versions section plus a stray footer" bug reported
    // against GHA's `dtolnay/rust-toolchain@stable` but not specific to any one
    // ecosystem. Every other online case (a non-empty live list, or no live fetch at
    // all) keeps the pre-#550 unconditional-when-resolvable behavior.
    let live_fetch_definitively_empty = available_versions.as_ref().is_some_and(Vec::is_empty);
    let footer_actionable =
        has_offline_actionable_data || (!live_fetch_definitively_empty && !versions.offline);
    if resolvable && footer_actionable {
        markdown.push_str(CMD_DOT_FOOTER);
    }

    // `versions.offline` (issue #483): the OSV lookup that produced `ScanOutcome::Skipped`
    // for this dependency renders nothing above (the `Some(ScanOutcome::Skipped(_)) | None`
    // arm below), which would otherwise be visually indistinguishable from a scanned,
    // vulnerability-free dependency — this footer must explicitly call out that
    // vulnerability data specifically was not checked, not just version data (S2).
    //
    // Gated on `resolvable` too, matching the `Cmd+.` footer immediately above (#474/#475):
    // a dependency that is never network-resolved under any setting (a local composite
    // action, a Docker image ref, a Git/path dependency) must not claim its version or
    // vulnerability data went unchecked *because of* `network.offline` — nothing there was
    // ever going to be checked regardless.
    if versions.offline && resolvable {
        markdown.push_str("\n---\n📴 *Offline: version and vulnerability data not checked*");
    }

    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: markdown,
        }),
        range: Some(dep.name_range()),
    })
}

/// Lowercase display label for a [`crate::osv::VulnSeverity`], used only in hover text.
const fn severity_label(severity: crate::osv::VulnSeverity) -> &'static str {
    match severity {
        crate::osv::VulnSeverity::Critical => "critical",
        crate::osv::VulnSeverity::High => "high",
        crate::osv::VulnSeverity::Medium => "medium",
        crate::osv::VulnSeverity::Low => "low",
        crate::osv::VulnSeverity::Unknown => "unknown severity",
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
    markdown: &mut String,
    formatter: &dyn EcosystemFormatter,
    deprecation: Option<&Deprecation>,
) {
    use std::fmt::Write as _;

    let Some(deprecation) = deprecation else {
        return;
    };

    // I3: each part gets its own blank-line-separated paragraph, mirroring
    // `push_vulnerability_hover_section`'s discipline — three bare consecutive
    // `writeln!` lines with no blank line between them collapse into one CommonMark
    // paragraph, rendering the message/reason/replacement joined instead of as the
    // visually distinct lines the section is meant to show.
    markdown.push_str("### Deprecated\n\n");
    let _ = writeln!(markdown, "{}\n", formatter.deprecated_message());
    if let Some(reason) = deprecation.reason.as_deref().filter(|r| !r.is_empty()) {
        let _ = writeln!(markdown, "{}\n", escape_markdown(reason));
    }
    if let Some(replacement) = deprecation.replacement.as_deref().filter(|r| !r.is_empty()) {
        let _ = writeln!(
            markdown,
            "Suggested replacement: {}\n",
            markdown_code_span(replacement)
        );
    }
}

/// Appends the hover "Security advisories" section, gated strictly on the
/// scan outcome — never on map absence.
///
/// `Vulnerable` gets the advisories list, `Clean` may state the affirmative
/// "no known vulnerabilities", and `Skipped` (or no scan at all) says
/// **nothing**: saying "clean" about a dependency that was never queried is
/// worse than saying nothing at all (`architecture.md` §8 invariant 0).
fn push_vulnerability_hover_section(markdown: &mut String, outcome: Option<&ScanOutcome>) {
    use std::fmt::Write;

    match outcome {
        Some(ScanOutcome::Vulnerable(dv)) => {
            markdown.push_str("### Security advisories\n\n");

            for advisory in dv.advisories.items() {
                writeln!(
                    markdown,
                    "- **[{}]({})** — {}",
                    escape_markdown(&advisory.id),
                    advisory.url,
                    severity_label(advisory.severity)
                )
                .unwrap();
                writeln!(
                    markdown,
                    "  {}",
                    escape_markdown(
                        advisory
                            .summary
                            .as_deref()
                            .unwrap_or("(no summary provided)")
                    )
                )
                .unwrap();

                let mut details = Vec::with_capacity(2);
                if let Some(fixed) = advisory.fixed_versions.last() {
                    details.push(format!("Fixed in: {}", markdown_code_span(fixed)));
                }
                if !advisory.aliases.is_empty() {
                    details.push(format!(
                        "Aliases: {}",
                        escape_markdown(&advisory.aliases.join(", "))
                    ));
                }
                if !details.is_empty() {
                    writeln!(markdown, "  {}", details.join(" \u{b7} ")).unwrap();
                }
            }

            let remaining = dv.advisories.remaining();
            if remaining > 0 {
                writeln!(markdown, "- *(+{remaining} more advisories)*").unwrap();
            }

            if let crate::osv::UpgradeStatus::CandidateVulnerable { version, .. } =
                &dv.upgrade_status
            {
                writeln!(
                    markdown,
                    "\n\u{26a0}\u{fe0f} Latest version {} is also affected.",
                    markdown_code_span(version)
                )
                .unwrap();
            }

            markdown.push('\n');
        }
        Some(ScanOutcome::Clean) => {
            markdown.push_str("**No known vulnerabilities** (OSV.dev)\n\n");
        }
        Some(ScanOutcome::Skipped(_)) | None => {}
    }
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
fn push_trust_signal_hover_section(markdown: &mut String, signal: Option<&SupplyChainTrustSignal>) {
    use std::fmt::Write;

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
        // "Provenance", not "SLSA provenance": `classify_provenance` deliberately unions
        // `slsaProvenances[]` with `attestations[]` (plan-mandated), and an attestation
        // entry's `type` is not necessarily SLSA — labeling every verified entry as SLSA
        // specifically would misrepresent which standard was actually verified for a
        // package whose only verified entry came from `attestations[]` (critic C3).
        parts.push(format!("Provenance: {label}"));
    }

    writeln!(
        markdown,
        "\u{1f510} **Supply chain**: {}",
        parts.join(" \u{b7} ")
    )
    .unwrap();
    markdown.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RemovalStatus;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::*;

    use std::collections::HashMap;
    use std::sync::Arc;

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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("- `1.2.3` *(latest)* — 2 days ago"),
            "got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        // Exactly the pre-feature line: no trailing age suffix.
        assert!(content.value.contains("- `1.2.3` *(latest)*\n"));
        assert!(!content.value.contains("ago"));
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Latest**: `13.0.4`"),
            "got: {}",
            content.value
        );
        assert!(
            content.value.contains("- `13.0.4` *(latest)*"),
            "the stable version, not the raw-top pre-release, should carry the marker; got: {}",
            content.value
        );
        assert!(
            !content.value.contains("13.0.5-beta1` *(latest)*"),
            "the pre-release must not be tagged latest; got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_omitted_when_stable_outside_top_n() {
        use std::collections::HashMap;

        // Nine pre-releases followed by one stable version: the stable pick sits past
        // `HOVER_RECENT_VERSIONS`, so it never appears in the rendered list.
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Latest**: `1.9.0`"),
            "got: {}",
            content.value
        );
        assert!(
            !content.value.contains("*(latest)*"),
            "the stable latest isn't in the truncated top-N slice, so no entry should be marked; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor, not panic");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("**Latest**:"),
            "no stable version exists, so the header should be omitted rather than picking a pre-release; got: {}",
            content.value
        );
        assert!(
            !content.value.contains("*(latest)*"),
            "no stable version exists, so no entry in the list should be marked latest; got: {}",
            content.value
        );
        assert!(
            content.value.contains("2.0.0-beta2"),
            "the raw version list should still render even without a latest marker; got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_all_prerelease_live_list_ignores_stale_cache() {
        use std::collections::HashMap;

        // A live fetch happened (so `available_versions` is `Some`), but every entry in it
        // is a pre-release: `live_latest_idx` is `None`. A stale Ch1 cache is also present,
        // recording a version that isn't part of the live list at all. Falling back to that
        // stale cached value here would render a `**Latest**` line that contradicts the live
        // "Recent versions" list right below it — exactly the self-contradiction #227 F5 was
        // fixed to prevent, just reached through this all-prerelease path instead (#313 S2).
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor, not panic");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("**Latest**:"),
            "a live fetch with no stable entry must not fall back to a stale cached version \
             that isn't in the live list; got: {}",
            content.value
        );
        assert!(
            !content.value.contains("1.5.0"),
            "the stale cached version must not leak into the response at all; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Latest**: `v1.2.3`"),
            "the list-based pick failed, so hover must fall back to get_latest_matching's \
             result instead of omitting the Latest line; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Latest**: `v1.2.3`"),
            "expected the list-based pick's own version, not the fallback's; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &ErrorRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover must still render on a fetch failure, not disappear entirely");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("serde"),
            "basic card must still render the package name; got: {}",
            content.value
        );
        assert!(
            !content.value.contains("**Latest**"),
            "no version data is available on a fetch failure; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockGoFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Current**: `v0.8.1`"),
            "expected hover to show go.mod's pinned version, got: {}",
            content.value
        );
        assert!(
            !content.value.contains("v0.9.1"),
            "hover must not surface the stale go.sum version: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        // Non-Go formatters must keep showing the lockfile-resolved version
        // ("1.2.0"), not the raw manifest requirement ("1.0.0") — confirms the Go
        // override does not leak into other ecosystems.
        assert!(
            content.value.contains("**Current**: `1.2.0`"),
            "expected hover to show the resolved lockfile version, got: {}",
            content.value
        );
        assert!(!content.value.contains("**Current**: `1.0.0`"));
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("- `1.2.1` *(yanked)* — 5 months ago"),
            "got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings {
                enabled: false,
                cooldown_secs: crate::freshness::DEFAULT_COOLDOWN_SECS,
            },
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("- `1.2.3` *(latest)*\n"));
        assert!(!content.value.contains("ago"));
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("**Latest**: `2.0.0` *(published 1 hour ago)*"),
            "got: {}",
            content.value
        );
        assert!(
            content.value.contains(
                "> ⏳ **Recently published** — this release is still within the cooldown window."
            ),
            "got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("**Latest**: `2.0.0` *(published 1 week ago)*"),
            "got: {}",
            content.value
        );
        assert!(!content.value.contains("Recently published"));
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("**Latest**: `2.0.0`\n\n"));
        assert!(!content.value.contains("published"));
        assert!(!content.value.contains("Recently published"));
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings {
                enabled: false,
                cooldown_secs: crate::freshness::DEFAULT_COOLDOWN_SECS,
            },
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("**Latest**: `2.0.0`\n\n"));
        assert!(!content.value.contains("published"));
        assert!(!content.value.contains("Recently published"));
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("Recently published"),
            "age exactly equal to cooldown_secs must not be within cooldown, got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("Recently published"),
            "age == cooldown_secs - 1 must be within cooldown, got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("**Latest**: `1.0.214` *(published 1 hour ago)*"),
            "Latest line must reflect the live Ch2 fetch, not the stale Ch1 cache entry \
             `1.0.213`, got: {}",
            content.value
        );
        assert!(
            !content.value.contains("**Latest**: `1.0.213`"),
            "must not render the stale Ch1 version, got: {}",
            content.value
        );
        assert!(
            content
                .value
                .contains("- `1.0.214` *(latest)* — 1 hour ago"),
            "the Recent versions list's own *(latest)* entry must agree with the Latest \
             line above it, got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Latest**: `1.9.0`"),
            "hover must agree with select_latest_matching's non-deprecated-preferred pick \
             (1.9.0), not a naive is_stable() scan that would pick the newer but deprecated \
             2.0.0, got: {}",
            content.value
        );
        assert!(
            content.value.contains("- `1.9.0` *(latest)*"),
            "the Recent versions list's own *(latest)* marker must agree with the Latest \
             line above it, got: {}",
            content.value
        );
        assert!(
            content.value.contains("- `2.0.0` *(yanked)*"),
            "2.0.0 must keep its flagged label even though it isn't the resolved latest, \
             got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Latest**: `2.0.0`"),
            "the only version resolves as latest even though it's flagged, got: {}",
            content.value
        );
        assert!(
            content.value.contains("- `2.0.0` *(latest)* *(yanked)*"),
            "the resolved latest must keep its flagged label instead of the warning \
             silently vanishing behind *(latest)*, got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Latest**: `2.0.0`"),
            "an all-yanked package still exists: hover must resolve the newest yanked \
             version as latest rather than showing no Latest line, got: {}",
            content.value
        );
        assert!(
            content.value.contains("- `2.0.0` *(latest)* *(yanked)*"),
            "the resolved latest must keep its yanked label, got: {}",
            content.value
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
            format!("https://example.com/{name}")
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &registry,
            &NpmLikeFormatter,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("### Deprecated"),
            "expected the package-level Deprecated section, got: {}",
            content.value
        );
        assert!(
            content.value.contains("no longer maintained"),
            "expected the deprecation reason, got: {}",
            content.value
        );
        // I3: the message and the reason must render as separate CommonMark paragraphs
        // (blank-line separated), not collapse into one joined paragraph.
        assert!(
            content
                .value
                .contains("This package is deprecated\n\nno longer maintained"),
            "expected the message and reason on separate paragraphs, got: {}",
            content.value
        );
        assert!(
            content
                .value
                .contains("- `1.0.0` *(latest)* *(deprecated)*"),
            "expected the pre-existing per-row label to still render alongside the new \
             section (deliberately not deduped, S4), got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_surfaces_markers() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("**Active when**: `python_full_version >= '3.9'`")
        );
    }

    #[tokio::test]
    async fn test_generate_hover_omits_active_when_without_markers() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!content.value.contains("Active when"));
    }

    #[tokio::test]
    async fn test_generate_hover_escapes_malicious_dependency_name() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };

        // The link label (between the H1's "# [" and the "](") must be the fully
        // escaped name, with no raw "](" sequence that could close the label early
        // and splice in an attacker-controlled markdown link.
        let header_line = content
            .value
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
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };

        // The link label must be the exact single-line escaped name: no raw
        // newline breaking the ATX heading, and the autolink's `<`/`>` escaped so
        // it cannot render as a live link independent of the `[]`/`()` escaping.
        let header_line = content
            .value
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
    async fn test_generate_hover_marker_with_parens_renders_unescaped() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains(&format!("**Active when**: `{marker}`"))
        );
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should still be generated for a non-resolvable-source dependency");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!content.value.contains("**Latest**"));
        assert!(!content.value.contains("**Recent versions**"));
        assert!(content.value.contains("**Requirement**"));

        // Control: the same fixture on a Registry-source dependency DOES show
        // both registry-derived sections, proving the fixture isn't vacuous.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let hover = generate_hover(
            &registry_parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("**Latest**"));
        assert!(content.value.contains("**Recent versions**"));
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
        vulns.insert("clean-pkg".to_string(), ScanOutcome::Clean);

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MockFormatter,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("No known vulnerabilities"));
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
            "path-pkg".to_string(),
            ScanOutcome::Skipped(SkipReason::NonRegistrySource),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MockFormatter,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!content.value.contains("Security advisories"));
        assert!(!content.value.contains("No known vulnerabilities"));
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
            "bad-pkg".to_string(),
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MockFormatter,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("Security advisories"));
        assert!(content.value.contains("RUSTSEC-2020-0071"));
        assert!(content.value.contains("Fixed in"));
        assert!(
            content.value.contains("1.5.0"),
            "must show highest fixed version"
        );
        assert!(content.value.contains("+2 more advisories"));
        assert!(content.value.contains("also affected"));
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
            &MockFormatter,
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
            Position::new(3, 2),
            versions,
            &MockRegistry,
            &MockFormatter,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let HoverContents::Markup(patched_content) = hover_on_patched.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !patched_content.value.contains("RUSTSEC-2020-0071"),
            "the patched occurrence must not show the other occurrence's advisory: {}",
            patched_content.value
        );
        assert!(patched_content.value.contains("No known vulnerabilities"));

        let hover_on_vulnerable = generate_hover(
            &parse_result,
            Position::new(0, 2),
            versions,
            &MockRegistry,
            &MockFormatter,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let HoverContents::Markup(vulnerable_content) = hover_on_vulnerable.contents else {
            panic!("expected markup hover contents");
        };
        assert!(vulnerable_content.value.contains("RUSTSEC-2020-0071"));
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &NotFoundRegistry,
            &MockFormatter,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover must still render the basic card on a registry error");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("**Latest**"),
            "no version data is available on a registry error; got: {}",
            content.value
        );
        assert!(
            !content.value.contains("Recent versions"),
            "must not render a broken version section from an empty list; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("Press `Cmd+.` to update version"),
            "a resolvable source with live version data must show the update footer; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should still be generated for a non-resolvable-source dependency");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("Press `Cmd+.` to update version"),
            "a non-resolvable source offers no update code action, even with a cached \
             latest value present; got: {}",
            content.value
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
            "serde".to_string(),
            ScanOutcome::Skipped(SkipReason::QueryFailed),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new())
                .with_offline(true)
                .with_vulnerabilities(&vulns),
            &ErrorRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("Press `Cmd+.` to update version"),
            "no code action can be produced while offline with nothing cached, so the \
             footer must not render; got: {}",
            content.value
        );
        assert!(
            content
                .value
                .contains("📴 *Offline: version and vulnerability data not checked*"),
            "the existing offline notice must still render; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()).with_offline(true),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("Press `Cmd+.` to update version"),
            "a warm-cache live version list still offers a real REFACTOR action while \
             offline, so the footer must render; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached, &resolved).with_offline(true),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("Offline: version and vulnerability data not checked"),
            "a resolvable source must show the offline footer when versions.offline is set; \
             got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_offline(true),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should still be generated for a non-resolvable-source dependency");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("Offline:"),
            "a non-resolvable source must not show the offline footer, even with \
             versions.offline set; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        let line = content
            .value
            .lines()
            .find(|l| l.contains("Supply chain"))
            .unwrap_or_else(|| panic!("expected a Supply chain line, got: {}", content.value));
        insta::assert_snapshot!(line, @"🔐 **Supply chain**: OpenSSF Scorecard `8.5`/10 · Provenance: verified");
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("Provenance: attested but unverified"),
            "got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("Provenance: none found"),
            "got: {}",
            content.value
        );
        assert!(
            content.value.contains("*(self-reported repo)*"),
            "an UNVERIFIED_METADATA-only relation must be disclosed; got: {}",
            content.value
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
                Position::new(0, 2),
                VersionData::new(&HashMap::new(), &resolved_versions)
                    .with_ecosystem(ecosystem)
                    .with_trust(&deps_dev),
                &registry,
                &MockFormatter,
                crate::freshness::FreshnessSettings::default(),
                PublishTime::now(),
            )
            .await
            .expect("hover should be generated");

            let HoverContents::Markup(content) = hover.contents else {
                panic!("expected markup hover contents");
            };
            assert!(
                !content.value.contains("Supply chain"),
                "{ecosystem:?}: got: {}",
                content.value
            );
            never_called.assert_async().await;
        }
    }

    /// Regression for security M2 / critic C2: a private/non-mirror
    /// `AlternateRegistry` source must never reach deps.dev, even though it
    /// resolves against this ecosystem's own registry (`resolvable` alone
    /// is the wrong, too-permissive gate — see
    /// `MockWidenedResolveFormatter`'s docs).
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Cargo)
                .with_trust(&deps_dev),
            &registry,
            &MockWidenedResolveFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("Supply chain"),
            "a private registry's package name/version must never reach deps.dev; got: {}",
            content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev)
                .with_offline(true),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("Supply chain"),
            "got: {}",
            content.value
        );
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let without_trust = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(a) = with_failing_trust.contents else {
            panic!("expected markup hover contents");
        };
        let HoverContents::Markup(b) = without_trust.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!a.value.contains("Supply chain"), "got: {}", a.value);
        assert_eq!(a.value, b.value);
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let HoverContents::Markup(first_content) = first.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !first_content.value.contains("Supply chain"),
            "the real ~750ms two-call sequence must exceed the 700ms wait budget on the \
             first hover; got: {}",
            first_content.value
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
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &resolved_versions)
                .with_ecosystem(crate::EcosystemId::Npm)
                .with_trust(&deps_dev),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("Supply chain"),
            "a hover reading an already-warm memo must render the trust signal \
             immediately; got: {}",
            content.value
        );
    }
}
