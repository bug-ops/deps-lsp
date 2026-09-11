//! Best-effort license fetch from a Maven Central POM (issue #660, spec 010 plan §1
//! tier 3).
//!
//! `deps_dev_system` excludes the Gradle ecosystem (unlike the Maven ecosystem crate,
//! which shares the exact same `groupId:artifactId` coordinate format but is
//! tier-2/deps.dev-covered), and `maven-metadata.xml` — the version-list endpoint
//! [`deps_maven::MavenCentralRegistry`] already fetches — carries no license field at
//! all. Only a specific version's POM file's `<licenses>` block does; live-verified
//! 2026-09-08 against `com.squareup.okhttp3:okhttp:4.12.0`, whose POM carries
//! `<licenses><license><name>The Apache Software License, Version 2.0</name>...`.
//!
//! Deliberately targets Maven Central only (`repo1.maven.org`), not the Google Maven /
//! Gradle Plugin Portal fallbacks `MavenCentralRegistry`'s version lookup also tries —
//! those two are edge cases for the small minority of Android/plugin-only coordinates,
//! and this is a best-effort secondary signal (NFR-003 graceful degradation already
//! covers a POM that 404s there).
//!
//! **Parent POM traversal (issue #692)**: a Maven multi-module project commonly declares
//! `<licenses>` only on a shared parent POM, leaving each module's own (leaf) POM to
//! reference it via `<parent>` — Guava's own leaf POM (`guava-32.0.1-jre.pom`) has no
//! `<licenses>` element at all; the license is declared only on `guava-parent`'s POM.
//! [`fetch_license_from`] follows a leaf POM's `<parent>` coordinate when its own
//! `<licenses>` block is empty, bounded by [`MAX_POM_FETCHES`] so a pathological (or
//! adversarial) parent chain can't turn one hover request into an unbounded fetch chain.

use deps_core::xml_bounds::exhausted_with;
use deps_core::{HttpCache, MAX_POM_LICENSE_NAME_RAW_CHARS, is_safe_maven_coordinate_segment};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::sync::Arc;

/// Maximum number of `<licenses><license><name>` entries [`parse_pom_licenses`] retains
/// from a single POM (issue #690; raised from an initial 8 to 64 per impl-critic S2).
/// Generously above any real-world POM's actual license count (dual-licensing is the
/// practical ceiling) and, more importantly, above what
/// `deps_core::licenses::evaluate`'s `license_policy` check needs: that function scans
/// every entry in the returned `Vec` with no cap of its own, so an 8-entry retention cap
/// could have silently hidden a policy violation carried by a real 9th+ license entry.
/// `deps-core::lsp_helpers::hover`'s separate `MAX_LICENSE_ENTRIES_RENDERED` (8) only
/// truncates hover *rendering* — it says nothing about how many entries diagnostics
/// evaluate, so this constant must not be tied to it. CPU/memory cost on a hostile
/// response is bounded independently by [`MAX_POM_LICENSE_BYTES_SCANNED`], not by this
/// cap. Kept as a Gradle-crate-local constant rather than a shared `deps-core` export
/// since no other ecosystem crate parses this shape yet (see this module's `pom_url` doc
/// for the same "not worth a cross-crate helper yet" reasoning).
const MAX_POM_LICENSE_ENTRIES: usize = 64;

/// Hard cap, in bytes of `reader.buffer_position()`, on how far into a POM
/// [`parse_pom_licenses`] will read (issue #690, impl-critic S1 — through three rounds of
/// counterexamples). A cap on *retained* entries alone doesn't bound CPU, and every
/// attempt to budget by counting a specific event shape instead (a `<name>` text node, a
/// `<name>` `Event::Start`) turned out to be shape-dependent and bypassable: a truly empty
/// `<name></name>` emits no `Event::Text`; a self-closing `<name/>` emits `Event::Empty`,
/// never `Event::Start`; and a `<license>` with no `<name>` child at all — or a flood of
/// unrelated junk elements — emits neither. Each of those consumed **zero** budget under a
/// shape-keyed counter while quick-xml still walked the reader to EOF (measured: a 32 MiB
/// flood of bare `<a/>` elements took ~117 ms with zero counted nodes). A byte-position
/// bound sidesteps this entirely — it advances on *every* event regardless of what it is,
/// so it cannot be starved by omitting one element shape. A real POM's `<licenses>` block
/// (and everything preceding it) is realistically well under this bound; the reader simply
/// stops handing back events once it's exhausted, degrading gracefully to whatever was
/// found so far — acceptable for this best-effort secondary signal (see module docs).
const MAX_POM_LICENSE_BYTES_SCANNED: usize = 1024 * 1024;

/// Maven Central's repository root. Mirrors `deps-maven`'s own (private)
/// `MAVEN_REPO_BASE` — kept as an independent constant rather than a shared one so this
/// crate does not need a new public export from `deps-maven` for a single string.
const MAVEN_REPO_BASE: &str = "https://repo1.maven.org/maven2";

/// Builds the Maven Central POM URL for `coordinate` (`"group:artifact"`) at
/// `version`, or `None` if `coordinate` isn't in that shape or any path segment (each
/// dot-separated `group` component, `artifact`, or `version`) fails
/// [`is_safe_maven_coordinate_segment`].
///
/// Security P3 (impl-critic): a bare exact-match `.`/`..` reject is not enough here —
/// Gradle's own coordinate/version parsers allow characters (notably `/`) this
/// function used to interpolate raw, so a `version` (or `group`/`artifact` component)
/// of e.g. `"../../../etc/passwd"` was never exactly `".."` and passed the old check
/// unfiltered, then split the URL path into extra traversal segments once
/// interpolated. Reuses [`is_safe_maven_coordinate_segment`] — the same allowlist
/// `deps-maven`/`deps-gradle`'s own coordinate formatters already validate this exact
/// `groupId`/`artifactId` shape against (`deps-maven/src/registry.rs:589-614`,
/// `deps-gradle/src/formatter.rs:171-174`) — rather than switching to percent-encoding
/// alone: this codebase has already hit the case where percent-encoding does *not*
/// neutralize a traversal segment (`deps-dart::registry::package_metadata_url`'s doc,
/// #349) — a segment of exactly `.`/`..` survives unreserved-character percent-encoding
/// unchanged, since `.` is an RFC 3986 unreserved character no encoder in this
/// codebase's `urlencoding` dependency escapes. An allowlist that fails closed on `/`
/// and any other non-`[A-Za-z0-9._-]` character closes both the embedded-slash
/// injection *and* the exact-dot-segment case in one already-audited helper, so no
/// separate encoding step is needed.
///
/// The `groupId:artifactId` -> URL-path construction itself is shared with
/// `deps-maven::registry::metadata_urls` via [`deps_core::maven_coordinate_path`] (#702) —
/// this function only adds the `version`/`.pom` filename suffix on top.
fn pom_url(base: &str, coordinate: &str, version: &str) -> Option<String> {
    let (group, artifact) = coordinate.split_once(':')?;
    if !is_safe_maven_coordinate_segment(version) {
        return None;
    }
    let coordinate_path = deps_core::maven_coordinate_path(group, artifact)?;
    Some(format!(
        "{base}/{coordinate_path}/{version}/{artifact}-{version}.pom"
    ))
}

/// Bounds how many POM fetches [`fetch_license_from`] performs for one license lookup —
/// the requested (leaf) coordinate itself, plus up to `MAX_POM_FETCHES - 1` `<parent>`
/// hops when each POM in the chain declares no `<licenses>` block of its own (issue
/// #692). A real Maven parent chain is rarely more than one or two levels deep (a leaf
/// module -> its immediate parent POM), so this leaves headroom for that common shape
/// while still capping a pathological or adversarial chain at a small, fixed number of
/// network round trips.
const MAX_POM_FETCHES: u8 = 3;

/// Fetches `coordinate`'s (`"group:artifact"`) license at `version` from Maven
/// Central.
///
/// Returns an empty `Vec` (never an error) when `coordinate` isn't in the expected
/// `"group:artifact"` shape, the fetch fails (network error, 404 — a large fraction of
/// Gradle plugin/Android coordinates live on Google Maven or the Gradle Plugin Portal
/// instead, not Maven Central), or neither the POM nor any `<parent>` POM within
/// [`MAX_POM_FETCHES`] declares a `<licenses>` block — graceful degradation (NFR-003),
/// since this is a best-effort secondary signal, not core version data.
pub(crate) async fn fetch_license(
    cache: &Arc<HttpCache>,
    coordinate: &str,
    version: &str,
) -> Vec<String> {
    fetch_license_from(cache, MAVEN_REPO_BASE, coordinate, version).await
}

/// [`fetch_license`]'s implementation, parameterized over the repository base URL so
/// tests can point it at a mockito server instead of live Maven Central — mirrors
/// `deps-dart::PubDevRegistry::with_base`/`deps-swift`'s equivalent test-only base
/// override (tester gap: unlike Swift/Dart/Deno's fetch layer, Gradle's had no
/// HTTP-mocked coverage at all, only the malformed-coordinate short-circuit below).
///
/// Follows `<parent>` POM coordinates (issue #692) when a fetched POM's own
/// `<licenses>` is empty, up to [`MAX_POM_FETCHES`] total fetches (the leaf plus its
/// parent chain). Each hop re-validates its coordinate/version through [`pom_url`] —
/// the same allowlist the leaf fetch uses — so a malicious `<parent>` value can no more
/// escape Maven Central's URL space than a malicious leaf coordinate could.
///
/// Deliberately the sole instrumented function on this path (issue #823): the actual
/// bounded fetch loop lives in [`fetch_license_hops`], a plain, uninstrumented helper
/// that only returns data, so `hops` is recorded exactly once here rather than at each
/// of that loop's several exit paths — see that function's doc for why.
#[tracing::instrument(
    skip_all,
    fields(package = ?coordinate, version = ?version, hops = tracing::field::Empty),
    level = "debug"
)]
async fn fetch_license_from(
    cache: &Arc<HttpCache>,
    base: &str,
    coordinate: &str,
    version: &str,
) -> Vec<String> {
    let (licenses, hops) = fetch_license_hops(cache, base, coordinate, version).await;
    tracing::Span::current().record("hops", hops);
    licenses
}

/// Runs [`fetch_license_from`]'s bounded POM fetch loop and returns the discovered
/// licenses together with the number of POM fetches actually performed (issue #823),
/// i.e. how many times [`HttpCache::get_cached`] was actually called — *not* how many
/// loop iterations ran, since the [`pom_url`] guard can reject a coordinate/version
/// before any network call is made (the documented malformed-coordinate short-circuit,
/// both for the leaf and for a malformed `<parent>` hop) and that iteration must not be
/// counted as a fetch.
///
/// Kept as a separate, non-instrumented function (impl-critic M2 on issue #823) so
/// [`fetch_license_from`] can record the `hops` span field at its single return point
/// instead of at every one of this loop's exit paths, where a future added `return`
/// could silently omit it — the same silent-omission failure mode issue #819 removes
/// from the completion-context dispatch, reintroduced one level down if each exit had
/// to remember its own `Span::current().record` call.
async fn fetch_license_hops(
    cache: &Arc<HttpCache>,
    base: &str,
    coordinate: &str,
    version: &str,
) -> (Vec<String>, u64) {
    let mut current_coordinate = coordinate.to_string();
    let mut current_version = version.to_string();

    for hop in 0..MAX_POM_FETCHES {
        let Some(url) = pom_url(base, &current_coordinate, &current_version) else {
            // No network call happens on this path, so `hop` (not `hop + 1`) is the
            // count of fetches actually performed so far.
            return (Vec::new(), u64::from(hop));
        };
        let pom = match cache.get_cached(&url).await {
            Ok(data) => parse_pom(&data),
            Err(e) => {
                // Logs both the requested (leaf) coordinate and the current hop's —
                // code-review nit: a parent-hop failure logged only the reassigned
                // parent coordinate, making it hard to correlate back to the dependency
                // the manifest/hover actually shows (e.g. `guava-parent` instead of
                // `guava` for a failed hop past a successfully-fetched leaf POM).
                tracing::debug!(
                    requested_coordinate = coordinate,
                    requested_version = version,
                    coordinate = current_coordinate,
                    version = current_version,
                    error = %e,
                    "gradle license pom fetch failed"
                );
                return (Vec::new(), u64::from(hop) + 1);
            }
        };
        if !pom.licenses.is_empty() {
            return (pom.licenses, u64::from(hop) + 1);
        }
        match pom.parent {
            Some((parent_coordinate, parent_version)) => {
                current_coordinate = parent_coordinate;
                current_version = parent_version;
            }
            None => return (Vec::new(), u64::from(hop) + 1),
        }
    }

    (Vec::new(), u64::from(MAX_POM_FETCHES))
}

/// One parsed Maven POM XML document's license-relevant content: its own declared
/// licenses, and — when present — the `<parent>` coordinate/version
/// [`fetch_license_from`] follows next if [`Self::licenses`] is empty (issue #692).
struct PomInfo {
    licenses: Vec<String>,
    /// `("group:artifact", version)` from `<parent><groupId>`/`<artifactId>`/`<version>`,
    /// present only when the POM declares all three.
    parent: Option<(String, String)>,
}

/// Extracts every `<licenses><license><name>` text value, and the `<parent>` coordinate
/// if any, from a POM XML document.
///
/// A dependency can declare more than one license (dual-licensed artifacts, e.g. EPL
/// and GPL-with-classpath-exception), so this collects all of them — consistent with
/// every other ecosystem's `license: Vec<String>` shape (spec 010 plan §1 "License
/// shape" decision). Non-UTF-8 or malformed XML degrades to an empty `Vec` and no
/// parent rather than an error, matching this module's overall graceful-degradation
/// contract.
fn parse_pom(data: &[u8]) -> PomInfo {
    let Ok(content) = std::str::from_utf8(data) else {
        return PomInfo {
            licenses: Vec::new(),
            parent: None,
        };
    };

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut licenses = Vec::new();
    let mut in_licenses = false;
    let mut in_license = false;
    let mut in_name = false;

    // Scoped to `<parent>...</parent>` (via `in_parent`) so the project's own top-level
    // `<groupId>`/`<artifactId>`/`<version>` elements — which every POM also has,
    // outside `<parent>` — are never mistaken for the parent coordinate.
    let mut in_parent = false;
    let mut in_parent_group_id = false;
    let mut in_parent_artifact_id = false;
    let mut in_parent_version = false;
    let mut parent_group_id = String::new();
    let mut parent_artifact_id = String::new();
    let mut parent_version = String::new();

    loop {
        // Shape-independent budget (impl-critic S1, through three rounds of
        // counterexamples that each defeated a shape-keyed counter): advances on every
        // event regardless of what it is, so it cannot be starved by a document that
        // simply omits the element type a narrower counter was watching for.
        if exhausted_with(
            licenses.len(),
            reader.buffer_position(),
            MAX_POM_LICENSE_ENTRIES,
            MAX_POM_LICENSE_BYTES_SCANNED,
        ) {
            break;
        }
        match reader.read_event() {
            Ok(Event::Start(ref e)) => match e.local_name().as_ref() {
                "licenses" => in_licenses = true,
                "license" if in_licenses => in_license = true,
                "name" if in_license => in_name = true,
                "parent" => in_parent = true,
                "groupId" if in_parent => in_parent_group_id = true,
                "artifactId" if in_parent => in_parent_artifact_id = true,
                "version" if in_parent => in_parent_version = true,
                _ => {}
            },
            Ok(Event::Text(ref e)) if in_name => {
                let raw = e.trim();
                if raw.len() <= MAX_POM_LICENSE_NAME_RAW_CHARS {
                    let raw = raw.to_string();
                    let text = quick_xml::escape::unescape(&raw)
                        .map(|c| c.into_owned())
                        .unwrap_or(raw);
                    if !text.is_empty() {
                        licenses.push(text);
                    }
                }
            }
            Ok(Event::Text(ref e)) if in_parent_group_id => {
                parent_group_id = e.trim().to_string();
            }
            Ok(Event::Text(ref e)) if in_parent_artifact_id => {
                parent_artifact_id = e.trim().to_string();
            }
            Ok(Event::Text(ref e)) if in_parent_version => {
                parent_version = e.trim().to_string();
            }
            Ok(Event::End(ref e)) => match e.local_name().as_ref() {
                "licenses" => in_licenses = false,
                "license" => in_license = false,
                "name" => in_name = false,
                "parent" => in_parent = false,
                "groupId" => in_parent_group_id = false,
                "artifactId" => in_parent_artifact_id = false,
                "version" => in_parent_version = false,
                _ => {}
            },
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }

    let parent =
        if parent_group_id.is_empty() || parent_artifact_id.is_empty() || parent_version.is_empty()
        {
            None
        } else {
            Some((
                format!("{parent_group_id}:{parent_artifact_id}"),
                parent_version,
            ))
        };

    PomInfo { licenses, parent }
}

/// Thin [`parse_pom`] wrapper keeping the pre-#692 `Vec<String>`-only shape for callers
/// (and existing tests) that only need the declared licenses, not parent traversal.
#[cfg(test)]
fn parse_pom_licenses(data: &[u8]) -> Vec<String> {
    parse_pom(data).licenses
}

/// Fuzz-only entry point for [`parse_pom`] (issue #691). Gated on the `fuzzing` Cargo
/// feature (never enabled by this crate's own default set) so this stays out of the
/// crate's public API surface in a normal build. This module itself stays unconditionally
/// private (impl-critic M1) — only this one function is reachable externally, via the
/// `#[doc(hidden)]` `pub use` re-export in `lib.rs`. Targets `parse_pom` directly (not the
/// test-only `parse_pom_licenses` wrapper, added by #692's parent-POM traversal) so
/// fuzzing continues to exercise the real production parser, including its `<parent>`
/// coordinate extraction.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_pom_licenses(data: &[u8]) {
    let _ = parse_pom(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pom_url_builds_group_path_from_dots() {
        let url = pom_url(MAVEN_REPO_BASE, "com.squareup.okhttp3:okhttp", "4.12.0").unwrap();
        assert_eq!(
            url,
            "https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.pom"
        );
    }

    #[test]
    fn pom_url_rejects_malformed_coordinate() {
        assert!(pom_url(MAVEN_REPO_BASE, "no-colon-here", "1.0").is_none());
    }

    #[test]
    fn pom_url_rejects_dot_segment_group_component() {
        assert!(pom_url(MAVEN_REPO_BASE, "com..evil:artifact", "1.0").is_none());
        assert!(pom_url(MAVEN_REPO_BASE, "..:artifact", "1.0").is_none());
    }

    #[test]
    fn pom_url_rejects_dot_segment_artifact_or_version() {
        assert!(pom_url(MAVEN_REPO_BASE, "com.example:..", "1.0").is_none());
        assert!(pom_url(MAVEN_REPO_BASE, "com.example:artifact", "..").is_none());
    }

    #[test]
    fn pom_url_rejects_empty_segments() {
        assert!(pom_url(MAVEN_REPO_BASE, "com..example:artifact", "1.0").is_none());
        assert!(pom_url(MAVEN_REPO_BASE, ":artifact", "1.0").is_none());
        assert!(pom_url(MAVEN_REPO_BASE, "com.example:", "1.0").is_none());
        assert!(pom_url(MAVEN_REPO_BASE, "com.example:artifact", "").is_none());
    }

    /// Security P3 (impl-critic): the pre-fix guard only rejected a segment that was
    /// *exactly* `.`/`..` — a `version` (or `artifact`/group component) containing an
    /// embedded `/` was never exactly `".."`, so it passed unfiltered and, once
    /// interpolated raw into the URL, split the path into extra traversal segments.
    /// `is_safe_maven_coordinate_segment`'s allowlist (no `/` permitted at all) closes
    /// this for every coordinate segment, not just an exact dot-segment match.
    #[test]
    fn pom_url_rejects_embedded_slash_path_traversal_in_version() {
        assert!(
            pom_url(
                MAVEN_REPO_BASE,
                "com.example:artifact",
                "../../../etc/passwd"
            )
            .is_none()
        );
        assert!(pom_url(MAVEN_REPO_BASE, "com.example:artifact", "1.0/../../evil").is_none());
    }

    #[test]
    fn pom_url_rejects_embedded_slash_path_traversal_in_artifact() {
        assert!(pom_url(MAVEN_REPO_BASE, "com.example:../../evil", "1.0").is_none());
    }

    #[test]
    fn pom_url_rejects_embedded_slash_path_traversal_in_group() {
        assert!(pom_url(MAVEN_REPO_BASE, "com.example/../evil:artifact", "1.0").is_none());
    }

    #[test]
    fn parse_pom_licenses_single_license() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <licenses>
    <license>
      <name>The Apache Software License, Version 2.0</name>
      <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
    </license>
  </licenses>
</project>"#;
        assert_eq!(
            parse_pom_licenses(pom.as_bytes()),
            vec!["The Apache Software License, Version 2.0".to_string()]
        );
    }

    #[test]
    fn parse_pom_licenses_dual_license() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <licenses>
    <license><name>EPL-2.0</name></license>
    <license><name>GPL-2.0-with-classpath-exception</name></license>
  </licenses>
</project>"#;
        assert_eq!(
            parse_pom_licenses(pom.as_bytes()),
            vec![
                "EPL-2.0".to_string(),
                "GPL-2.0-with-classpath-exception".to_string()
            ]
        );
    }

    #[test]
    fn parse_pom_licenses_caps_entry_count() {
        let mut entries = String::new();
        for i in 0..(MAX_POM_LICENSE_ENTRIES + 20) {
            entries.push_str(&format!("<license><name>License-{i}</name></license>"));
        }
        let pom =
            format!(r#"<?xml version="1.0"?><project><licenses>{entries}</licenses></project>"#);
        let licenses = parse_pom_licenses(pom.as_bytes());
        assert_eq!(licenses.len(), MAX_POM_LICENSE_ENTRIES);
        let expected: Vec<String> = (0..MAX_POM_LICENSE_ENTRIES)
            .map(|i| format!("License-{i}"))
            .collect();
        assert_eq!(licenses, expected);
    }

    /// Builds a synthetic POM whose `<licenses>` block is `entry` repeated past
    /// [`MAX_POM_LICENSE_BYTES_SCANNED`], followed by one valid trailing `<license>` —
    /// used to prove the byte budget bails out before ever reaching that trailing entry,
    /// regardless of what `entry` looks like (impl-critic S1: three rounds of
    /// shape-specific counters, each defeated by a different `entry` shape).
    fn flood_pom(entry: &str) -> String {
        let mut entries = String::new();
        while entries.len() < MAX_POM_LICENSE_BYTES_SCANNED {
            entries.push_str(entry);
        }
        entries.push_str("<license><name>Apache-2.0</name></license>");
        format!(r#"<?xml version="1.0"?><project><licenses>{entries}</licenses></project>"#)
    }

    /// A `<name>` longer than `MAX_POM_LICENSE_NAME_RAW_CHARS` is skipped without being
    /// retained, so a cap on retained entries alone never trips.
    #[test]
    fn parse_pom_licenses_byte_budget_stops_oversized_name_flood() {
        let long_name = "a".repeat(MAX_POM_LICENSE_NAME_RAW_CHARS + 1);
        let entry = format!("<license><name>{long_name}</name></license>");
        assert!(parse_pom_licenses(flood_pom(&entry).as_bytes()).is_empty());
    }

    /// A truly empty `<name></name>` (no whitespace) emits no `Event::Text` under
    /// quick-xml's `trim_text(true)`, so a budget keyed off text content never sees it.
    #[test]
    fn parse_pom_licenses_byte_budget_stops_empty_name_flood() {
        assert!(
            parse_pom_licenses(flood_pom("<license><name></name></license>").as_bytes()).is_empty()
        );
    }

    /// A self-closing `<name/>` emits `Event::Empty`, never `Event::Start` — so a budget
    /// keyed off `<name>` element entry never sees it either.
    #[test]
    fn parse_pom_licenses_byte_budget_stops_self_closing_name_flood() {
        assert!(parse_pom_licenses(flood_pom("<license><name/></license>").as_bytes()).is_empty());
    }

    /// A `<license>` with no `<name>` child at all never enters the `in_name` state, so
    /// any counter scoped to that state stays at zero for the whole document.
    #[test]
    fn parse_pom_licenses_byte_budget_stops_license_without_name_flood() {
        assert!(parse_pom_licenses(flood_pom("<license></license>").as_bytes()).is_empty());
    }

    /// Impl-critic S1 (third round) — the sharpest counterexample: no
    /// `<license>`/`<name>` element at all, just unrelated junk. Any counter keyed to a
    /// specific tag shape advances zero times here while quick-xml still walks the whole
    /// document to EOF (measured pre-fix: ~117 ms for a 32 MiB flood of this shape, worse
    /// than #690's own ~63 ms baseline). Only a shape-independent byte bound catches it.
    #[test]
    fn parse_pom_licenses_byte_budget_stops_junk_element_flood() {
        assert!(parse_pom_licenses(flood_pom("<a/>").as_bytes()).is_empty());
    }

    #[test]
    fn parse_pom_licenses_skips_oversized_entry() {
        let long_name = "a".repeat(MAX_POM_LICENSE_NAME_RAW_CHARS + 1);
        let pom = format!(
            r#"<?xml version="1.0"?><project><licenses>
                <license><name>{long_name}</name></license>
                <license><name>Apache-2.0</name></license>
            </licenses></project>"#
        );
        assert_eq!(
            parse_pom_licenses(pom.as_bytes()),
            vec!["Apache-2.0".to_string()]
        );
    }

    #[test]
    fn parse_pom_licenses_no_licenses_block() {
        let pom = r#"<?xml version="1.0"?><project><groupId>com.example</groupId></project>"#;
        assert!(parse_pom_licenses(pom.as_bytes()).is_empty());
    }

    #[test]
    fn parse_pom_licenses_malformed_xml_degrades_to_empty() {
        assert!(parse_pom_licenses(b"not xml at all <<<").is_empty());
    }

    #[test]
    fn parse_pom_licenses_non_utf8_degrades_to_empty() {
        assert!(parse_pom_licenses(&[0xff, 0xfe, 0x00, 0x01]).is_empty());
    }

    #[tokio::test]
    async fn fetch_license_malformed_coordinate_returns_empty_without_network() {
        let cache = Arc::new(HttpCache::new());
        assert!(fetch_license(&cache, "no-colon", "1.0").await.is_empty());
    }

    // --- Tester gap: `fetch_license`'s HTTP layer had no mockito coverage, unlike
    // Swift/Dart/Deno's equivalent tests, which exercise both a valid response and a
    // network/parse failure through the real fetch path. ---

    #[tokio::test]
    async fn fetch_license_from_success_parses_pom_response() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                "/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.pom",
            )
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <licenses>
    <license><name>Apache-2.0</name></license>
  </licenses>
</project>"#,
            )
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let licenses = fetch_license_from(
            &cache,
            &server.url(),
            "com.squareup.okhttp3:okhttp",
            "4.12.0",
        )
        .await;

        assert_eq!(licenses, vec!["Apache-2.0".to_string()]);
    }

    #[tokio::test]
    async fn fetch_license_from_network_error_degrades_to_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/com/example/missing/1.0.0/missing-1.0.0.pom")
            .with_status(404)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let licenses =
            fetch_license_from(&cache, &server.url(), "com.example:missing", "1.0.0").await;

        assert!(licenses.is_empty());
    }

    #[tokio::test]
    async fn fetch_license_from_malformed_xml_degrades_to_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/com/example/broken/1.0.0/broken-1.0.0.pom")
            .with_status(200)
            .with_body("not xml at all <<<")
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let licenses =
            fetch_license_from(&cache, &server.url(), "com.example:broken", "1.0.0").await;

        assert!(licenses.is_empty());
    }

    // --- Issue #692: parent POM traversal ---

    #[test]
    fn parse_pom_extracts_parent_coordinate() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.google.guava</groupId>
    <artifactId>guava-parent</artifactId>
    <version>32.0.1-jre</version>
  </parent>
  <artifactId>guava</artifactId>
</project>"#;
        let info = parse_pom(pom.as_bytes());
        assert!(info.licenses.is_empty());
        assert_eq!(
            info.parent,
            Some((
                "com.google.guava:guava-parent".to_string(),
                "32.0.1-jre".to_string()
            ))
        );
    }

    /// The project's own top-level `<artifactId>`/`<version>` (outside `<parent>`) must
    /// never be mistaken for the parent coordinate.
    #[test]
    fn parse_pom_ignores_project_own_coordinate_outside_parent() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>leaf</artifactId>
  <version>9.9.9</version>
</project>"#;
        assert_eq!(parse_pom(pom.as_bytes()).parent, None);
    }

    #[test]
    fn parse_pom_parent_missing_a_field_returns_none() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-module</artifactId>
  </parent>
</project>"#;
        assert_eq!(parse_pom(pom.as_bytes()).parent, None);
    }

    #[test]
    fn parse_pom_licenses_and_parent_together() {
        let pom = r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-module</artifactId>
    <version>1.0.0</version>
  </parent>
  <licenses>
    <license><name>MIT</name></license>
  </licenses>
</project>"#;
        let info = parse_pom(pom.as_bytes());
        assert_eq!(info.licenses, vec!["MIT".to_string()]);
        assert_eq!(
            info.parent,
            Some(("com.example:parent-module".to_string(), "1.0.0".to_string()))
        );
    }

    /// Live pattern (issue #692): Guava's own leaf POM has no `<licenses>` at all — the
    /// license is declared only on `guava-parent`'s POM.
    #[tokio::test]
    async fn fetch_license_from_follows_parent_pom_when_leaf_has_no_licenses() {
        let mut server = mockito::Server::new_async().await;
        let _leaf = server
            .mock(
                "GET",
                "/com/google/guava/guava/32.0.1-jre/guava-32.0.1-jre.pom",
            )
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.google.guava</groupId>
    <artifactId>guava-parent</artifactId>
    <version>32.0.1-jre</version>
  </parent>
  <artifactId>guava</artifactId>
</project>"#,
            )
            .create_async()
            .await;
        let _parent = server
            .mock(
                "GET",
                "/com/google/guava/guava-parent/32.0.1-jre/guava-parent-32.0.1-jre.pom",
            )
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <licenses>
    <license><name>Apache-2.0</name></license>
  </licenses>
</project>"#,
            )
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let licenses = fetch_license_from(
            &cache,
            &server.url(),
            "com.google.guava:guava",
            "32.0.1-jre",
        )
        .await;

        assert_eq!(licenses, vec!["Apache-2.0".to_string()]);
    }

    /// Tester gap: the single-hop test above (leaf -> parent, license found on the
    /// immediate parent) and `fetch_license_from_bounds_parent_hops` (a >3-hop chain
    /// that never finds a license) don't together prove a genuine 2-hop *success* case —
    /// leaf -> parent -> grandparent, with the license found on the grandparent, staying
    /// within `MAX_POM_FETCHES`. This is the one scenario mockito coverage didn't
    /// actually exercise before this test.
    #[tokio::test]
    async fn fetch_license_from_follows_two_parent_hops_to_grandparent_license() {
        let mut server = mockito::Server::new_async().await;
        let _leaf = server
            .mock("GET", "/com/example/leaf/1.0.0/leaf-1.0.0.pom")
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-module</artifactId>
    <version>1.0.0</version>
  </parent>
</project>"#,
            )
            .create_async()
            .await;
        let _parent = server
            .mock(
                "GET",
                "/com/example/parent-module/1.0.0/parent-module-1.0.0.pom",
            )
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>grandparent-module</artifactId>
    <version>1.0.0</version>
  </parent>
</project>"#,
            )
            .create_async()
            .await;
        let _grandparent = server
            .mock(
                "GET",
                "/com/example/grandparent-module/1.0.0/grandparent-module-1.0.0.pom",
            )
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <licenses>
    <license><name>MIT</name></license>
  </licenses>
</project>"#,
            )
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let licenses = fetch_license_from(&cache, &server.url(), "com.example:leaf", "1.0.0").await;

        assert_eq!(
            licenses,
            vec!["MIT".to_string()],
            "expected the grandparent POM's license, found within MAX_POM_FETCHES"
        );
    }

    /// Security (critic L1): `fetch_license_from`'s doc claims a malicious `<parent>`
    /// coordinate can no more escape Maven Central's URL space than a malicious leaf
    /// coordinate could, since every hop re-enters [`pom_url`]'s same allowlist — this
    /// locks that claim in with a test, mirroring the leaf-level
    /// `pom_url_rejects_embedded_slash_path_traversal_in_group` coverage. No mock is
    /// registered for a "second" request: if the parent hop's own `pom_url` validation
    /// were bypassed, the fetch would 501 from mockito's unmatched-route handling and
    /// still degrade to empty — this test instead asserts the malicious-parent case
    /// takes the same `None`-from-`pom_url` short-circuit as a malformed leaf coordinate,
    /// never issuing a second HTTP request at all.
    #[tokio::test]
    async fn fetch_license_from_rejects_path_traversal_in_parent_coordinate() {
        let mut server = mockito::Server::new_async().await;
        let _leaf = server
            .mock("GET", "/com/example/leaf/1.0.0/leaf-1.0.0.pom")
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example/../evil</groupId>
    <artifactId>parent-module</artifactId>
    <version>1.0.0</version>
  </parent>
</project>"#,
            )
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let licenses = fetch_license_from(&cache, &server.url(), "com.example:leaf", "1.0.0").await;

        assert!(
            licenses.is_empty(),
            "a path-traversal parent coordinate must degrade to empty, not be followed"
        );
    }

    // --- Issue #823 impl-critic M1: `hops` must count POM fetches actually performed
    // (HTTP calls that happened), not loop iterations — the `pom_url` guard can reject a
    // coordinate/version, both for the leaf and for a malformed `<parent>` hop, before any
    // network call is made, and that iteration must not inflate the count. ---

    #[tokio::test]
    async fn fetch_license_hops_malformed_leaf_coordinate_records_zero_hops() {
        let cache = Arc::new(HttpCache::new());
        let (licenses, hops) = fetch_license_hops(&cache, MAVEN_REPO_BASE, "no-colon", "1.0").await;

        assert!(licenses.is_empty());
        assert_eq!(
            hops, 0,
            "no network call happens, so zero fetches were performed"
        );
    }

    #[tokio::test]
    async fn fetch_license_hops_single_successful_fetch_records_one_hop() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                "/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.pom",
            )
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <licenses>
    <license><name>Apache-2.0</name></license>
  </licenses>
</project>"#,
            )
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let (licenses, hops) = fetch_license_hops(
            &cache,
            &server.url(),
            "com.squareup.okhttp3:okhttp",
            "4.12.0",
        )
        .await;

        assert_eq!(licenses, vec!["Apache-2.0".to_string()]);
        assert_eq!(hops, 1);
    }

    /// The exact regression this section guards against: before the M1 fix, this
    /// scenario recorded `hops == 2` (one real leaf fetch, plus the rejected parent hop
    /// counted as a second) instead of the correct `1`.
    #[tokio::test]
    async fn fetch_license_hops_malformed_parent_coordinate_after_leaf_fetch_records_one_hop() {
        let mut server = mockito::Server::new_async().await;
        let _leaf = server
            .mock("GET", "/com/example/leaf/1.0.0/leaf-1.0.0.pom")
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example/../evil</groupId>
    <artifactId>parent-module</artifactId>
    <version>1.0.0</version>
  </parent>
</project>"#,
            )
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let (licenses, hops) =
            fetch_license_hops(&cache, &server.url(), "com.example:leaf", "1.0.0").await;

        assert!(licenses.is_empty());
        assert_eq!(
            hops, 1,
            "only the leaf fetch actually hit the network; the malicious parent hop was \
             rejected by pom_url before any request"
        );
    }

    #[tokio::test]
    async fn fetch_license_from_leaf_with_no_licenses_and_no_parent_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/com/example/orphan/1.0.0/orphan-1.0.0.pom")
            .with_status(200)
            .with_body(r#"<?xml version="1.0"?><project><artifactId>orphan</artifactId></project>"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let licenses =
            fetch_license_from(&cache, &server.url(), "com.example:orphan", "1.0.0").await;

        assert!(licenses.is_empty());
    }

    /// A parent chain longer than [`MAX_POM_FETCHES`] must stop rather than keep
    /// following `<parent>` indefinitely — `mod3`'s POM (which does declare a license)
    /// must never be fetched.
    #[tokio::test]
    async fn fetch_license_from_bounds_parent_hops() {
        let mut server = mockito::Server::new_async().await;
        let parent_pom = |next: &str| {
            format!(
                r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>{next}</artifactId>
    <version>1.0.0</version>
  </parent>
</project>"#
            )
        };
        let _mod0 = server
            .mock("GET", "/com/example/mod0/1.0.0/mod0-1.0.0.pom")
            .with_status(200)
            .with_body(parent_pom("mod1"))
            .create_async()
            .await;
        let _mod1 = server
            .mock("GET", "/com/example/mod1/1.0.0/mod1-1.0.0.pom")
            .with_status(200)
            .with_body(parent_pom("mod2"))
            .create_async()
            .await;
        let _mod2 = server
            .mock("GET", "/com/example/mod2/1.0.0/mod2-1.0.0.pom")
            .with_status(200)
            .with_body(parent_pom("mod3"))
            .create_async()
            .await;
        let mod3 = server
            .mock("GET", "/com/example/mod3/1.0.0/mod3-1.0.0.pom")
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<project>
  <licenses>
    <license><name>Should-Not-Be-Reached</name></license>
  </licenses>
</project>"#,
            )
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let licenses = fetch_license_from(&cache, &server.url(), "com.example:mod0", "1.0.0").await;

        assert!(
            licenses.is_empty(),
            "parent traversal must stop at MAX_POM_FETCHES, got: {licenses:?}"
        );
        mod3.assert_async().await;
    }
}
