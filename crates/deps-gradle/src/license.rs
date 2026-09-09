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

use deps_core::{HttpCache, is_safe_maven_coordinate_segment};
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

/// Maximum raw byte length of a single `<license><name>` text node [`parse_pom_licenses`]
/// allocates (issue #690). Mirrors `deps-core::licenses`'s private
/// `MAX_POM_LICENSE_NAME_RAW_CHARS` (also 128, applied to the same POM-license-name shape
/// during normalization) — an oversized entry is dropped by normalization further
/// downstream regardless, so rejecting it here avoids allocating a `String` for it at all.
const MAX_POM_LICENSE_NAME_RAW_CHARS: usize = 128;

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
/// DRY nit (round 3 finding #7, left as a doc note rather than an extraction — see
/// below for why): this re-derives the same `groupId:artifactId` -> URL-path
/// construction `deps-maven::registry::metadata_urls` already implements for the
/// identical coordinate/host shape, with genuinely diverging per-segment validation
/// granularity between the two, not just a cosmetic difference — `metadata_urls`
/// validates the *whole* (unsplit) `group_id` string against
/// [`is_safe_maven_coordinate_segment`] (which permits internal `.` characters) and
/// only then blindly `.replace('.', "/")`s it, so a group of `"com..evil"` passes that
/// check and produces an empty path segment (`"com//evil"`) — degrading to a harmless
/// 404, not a traversal, but still a latent looseness this function's per-split-segment
/// validation (each `group.split('.')` component checked individually, rejecting an
/// empty one outright) does not share. A shared helper would need to pick one of the
/// two behaviors as authoritative for both crates, which is more than a pure
/// code-motion refactor and out of this fix's scope — flagging for a dedicated
/// fast-follow rather than changing `deps-maven`'s hot registry path as a drive-by here.
fn pom_url(base: &str, coordinate: &str, version: &str) -> Option<String> {
    let (group, artifact) = coordinate.split_once(':')?;
    if !is_safe_maven_coordinate_segment(artifact) || !is_safe_maven_coordinate_segment(version) {
        return None;
    }
    let group_segments: Vec<&str> = group.split('.').collect();
    if group_segments.is_empty()
        || group_segments
            .iter()
            .any(|s| !is_safe_maven_coordinate_segment(s))
    {
        return None;
    }
    let group_path = group_segments.join("/");
    Some(format!(
        "{base}/{group_path}/{artifact}/{version}/{artifact}-{version}.pom"
    ))
}

/// Fetches `coordinate`'s (`"group:artifact"`) license at `version` from Maven
/// Central.
///
/// Returns an empty `Vec` (never an error) when `coordinate` isn't in the expected
/// `"group:artifact"` shape, the fetch fails (network error, 404 — a large fraction of
/// Gradle plugin/Android coordinates live on Google Maven or the Gradle Plugin Portal
/// instead, not Maven Central), or the POM has no `<licenses>` block — graceful
/// degradation (NFR-003), since this is a best-effort secondary signal, not core
/// version data.
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
async fn fetch_license_from(
    cache: &Arc<HttpCache>,
    base: &str,
    coordinate: &str,
    version: &str,
) -> Vec<String> {
    let Some(url) = pom_url(base, coordinate, version) else {
        return Vec::new();
    };
    match cache.get_cached(&url).await {
        Ok(data) => parse_pom_licenses(&data),
        Err(e) => {
            tracing::debug!(coordinate, version, error = %e, "gradle license pom fetch failed");
            Vec::new()
        }
    }
}

/// Extracts every `<licenses><license><name>` text value from a POM XML document.
///
/// A dependency can declare more than one license (dual-licensed artifacts, e.g. EPL
/// and GPL-with-classpath-exception), so this collects all of them — consistent with
/// every other ecosystem's `license: Vec<String>` shape (spec 010 plan §1 "License
/// shape" decision). Non-UTF-8 or malformed XML degrades to an empty `Vec` rather than
/// an error, matching this module's overall graceful-degradation contract.
fn parse_pom_licenses(data: &[u8]) -> Vec<String> {
    let Ok(content) = std::str::from_utf8(data) else {
        return Vec::new();
    };

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut licenses = Vec::new();
    let mut in_licenses = false;
    let mut in_license = false;
    let mut in_name = false;

    loop {
        // Shape-independent budget (impl-critic S1, through three rounds of
        // counterexamples that each defeated a shape-keyed counter): advances on every
        // event regardless of what it is, so it cannot be starved by a document that
        // simply omits the element type a narrower counter was watching for.
        if licenses.len() >= MAX_POM_LICENSE_ENTRIES
            || reader.buffer_position() as usize >= MAX_POM_LICENSE_BYTES_SCANNED
        {
            break;
        }
        match reader.read_event() {
            Ok(Event::Start(ref e)) => match e.local_name().as_ref() {
                "licenses" => in_licenses = true,
                "license" if in_licenses => in_license = true,
                "name" if in_license => in_name = true,
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
            Ok(Event::End(ref e)) => match e.local_name().as_ref() {
                "licenses" => in_licenses = false,
                "license" => in_license = false,
                "name" => in_name = false,
                _ => {}
            },
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }

    licenses
}

/// Fuzz-only entry point for [`parse_pom_licenses`] (issue #691). Gated on the `fuzzing`
/// Cargo feature (never enabled by this crate's own default set) so this stays out of the
/// crate's public API surface in a normal build. This module itself stays unconditionally
/// private (impl-critic M1) — only this one function is reachable externally, via the
/// `#[doc(hidden)]` `pub use` re-export in `lib.rs`.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_pom_licenses(data: &[u8]) {
    let _ = parse_pom_licenses(data);
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
}
