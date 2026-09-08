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
        match reader.read_event() {
            Ok(Event::Start(ref e)) => match e.local_name().as_ref() {
                "licenses" => in_licenses = true,
                "license" if in_licenses => in_license = true,
                "name" if in_license => in_name = true,
                _ => {}
            },
            Ok(Event::Text(ref e)) if in_name => {
                let raw = e.trim().to_string();
                let text = quick_xml::escape::unescape(&raw)
                    .map(|c| c.into_owned())
                    .unwrap_or(raw);
                if !text.is_empty() {
                    licenses.push(text);
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
