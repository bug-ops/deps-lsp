//! Test fixtures and helpers shared across ecosystem crates.
//!
//! Test fixtures throughout the workspace write absolute paths in Unix
//! style (e.g. `/project/Cargo.toml`) for readability. `Uri::from_file_path`
//! requires a platform-absolute path, and a Unix-style path is not
//! recognized as absolute on Windows (no drive letter), so calling it
//! directly with such a literal panics on Windows only. [`test_uri`]
//! normalizes the path per host platform before constructing the [`Uri`].
//!
//! [`assert_dot_segment_gated_or_contained`]/[`assert_dot_segment_gated_or_contained_transformed`]
//! guard the recurring dot-segment / unvalidated-URL-sink defect class (#337, #341, #349,
//! #357, #361, #365, #371) against further recurrence.
//!
//! [`capture_tracing_output`]/[`capture_tracing_output_async`] let a test assert a
//! `tracing` call actually fired (originally added standalone in `deps-swift` for #357,
//! then duplicated per-crate for #380/#378's `warn_rejected_value` coverage before being
//! consolidated here).

use tower_lsp_server::ls_types::Uri;

/// Builds a [`Uri`] from a Unix-style absolute test path.
///
/// On Windows, a synthetic `C:` drive is prefixed so the path is
/// recognized as absolute; on other platforms the path is used as-is.
///
/// # Panics
///
/// Panics if the resulting path is not a valid file URI. This is a test
/// helper: fixture paths are expected to always be well-formed.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::test_uri;
///
/// let uri = test_uri("/project/Cargo.toml");
/// assert!(uri.path().as_str().ends_with("Cargo.toml"));
/// ```
#[must_use]
pub fn test_uri(unix_path: &str) -> Uri {
    #[cfg(windows)]
    let owned;
    #[cfg(windows)]
    let path: &str = {
        owned = format!("C:{unix_path}");
        &owned
    };
    #[cfg(not(windows))]
    let path: &str = unix_path;

    Uri::from_file_path(path).expect("test_uri: fixture path must be a valid file URI")
}

/// Canonical adversarial identifier values for the recurring dot-segment /
/// unvalidated-URL-sink defect class (#337, #341, #349, #357, #361).
///
/// A manifest-declared package name, scope, or coordinate segment spliced into a
/// registry/API URL via `format!`/string interpolation without validation. A bare `.`/`..`
/// survives naive percent-encoding unchanged (`.` is an RFC 3986 unreserved character) and
/// is silently removed by a URL parser's dot-segment normalization once the string is
/// assembled and parsed, letting the request escape the intended host or path prefix; the
/// remaining entries cover a would-be traversal attempt, whitespace, and query/fragment
/// injection.
pub const ADVERSARIAL_URL_SEGMENTS: &[&str] = &[
    ".",
    "..",
    "../../etc/passwd",
    "a b",
    "a?b=1",
    "a#frag",
    "%2e%2e",
];

/// Exercises one ecosystem's identifier-to-URL sink against every
/// [`ADVERSARIAL_URL_SEGMENTS`] entry.
///
/// `resolve` should mirror the real request path: apply whatever validation gate
/// (`is_dot_segment`, `is_safe_package_name`, `is_safe_maven_coordinate_segment`, ...) the
/// production code runs before building the request, returning `None` when the gate would
/// reject the identifier (the request is never built, so there is nothing to check), or
/// `Some(url)` with the URL the identifier resolves to when it reaches the real
/// fetch-URL-builder function directly.
///
/// For every input that reaches `Some(url)`, asserts `url` parses, stays under
/// `expected_host`/`expected_path_prefix`, and that `segment` itself survives the round
/// trip. That last check is the one that actually catches a missing/deleted gate: for an
/// ecosystem whose identifier is the *first* path component (no fixed sub-path to nest
/// under, e.g. `deps-cargo`'s sparse-index path or `deps-npm`'s bare
/// `registry.npmjs.org/{name}`), `expected_path_prefix` can only ever be `"/"` — trivially
/// satisfied by any path — so the prefix check alone is a tautology there. Deleting the
/// real gate collapses `..`/`.` via dot-segment normalization, which removes it from the
/// path entirely; the survival check catches that regardless of how trivial
/// `expected_path_prefix` is, so passing `"/"` is fine as long as this check is also in
/// effect.
///
/// The survival check itself takes one of two forms depending on `segment`:
/// - For a bare `.`/`..` (the only values `url`'s dot-segment normalization treats
///   specially): some path segment, once percent-decoded, must *start with* that value.
///   A whole-path substring search would be too weak here — a coincidental `.` baked into
///   a static suffix the sink always appends (e.g. `.json`) would satisfy `contains` even
///   if the real `.`/`..` segment was silently removed, leaving no trace of it anywhere.
///   `starts_with` (not exact equality) still accommodates a sink that glues the
///   identifier directly onto a static suffix with no separator (e.g. `deps-bundler`'s
///   `versions_url`, which decodes a `..` identifier to the segment `"..json"`).
/// - For every other adversarial entry: the percent-decoded *whole path* must contain
///   `segment` (or `transform(segment)`) as a substring — safe here since none of those
///   entries collides with a static suffix the way a bare `.` does.
///
/// # Panics
///
/// Panics if a returned URL fails to parse, escapes `expected_host` or
/// `expected_path_prefix`, if the (possibly transformed) segment is empty despite
/// `resolve` returning `Some`, or if the segment does not survive per the rules above.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::assert_dot_segment_gated_or_contained;
///
/// fn build(name: &str) -> String {
///     format!("https://example.com/api/{}", urlencoding::encode(name))
/// }
///
/// fn resolve(name: &str) -> Option<String> {
///     (name != "." && name != "..").then(|| build(name))
/// }
///
/// assert_dot_segment_gated_or_contained(resolve, "example.com", "/api/");
/// ```
pub fn assert_dot_segment_gated_or_contained(
    resolve: impl Fn(&str) -> Option<String>,
    expected_host: &str,
    expected_path_prefix: &str,
) {
    assert_dot_segment_gated_or_contained_transformed(
        resolve,
        str::to_string,
        expected_host,
        expected_path_prefix,
    );
}

/// As [`assert_dot_segment_gated_or_contained`], but for a `resolve` whose production gate
/// legitimately transforms the identifier before it reaches the URL builder.
///
/// E.g. PyPI's PEP 503 `name::normalize`, which collapses `.`/`_`/`-` runs, rather than
/// passing the identifier through unchanged. `transform` computes what the identifier looks
/// like once it reaches the sink, so the survival check compares the decoded path against
/// that instead of the raw adversarial `segment` (which would otherwise never appear
/// literally, producing a false-positive failure with no real bug behind it).
///
/// # Panics
///
/// Same conditions as [`assert_dot_segment_gated_or_contained`], with `transform(segment)`
/// in place of `segment` for the survival check.
pub fn assert_dot_segment_gated_or_contained_transformed(
    resolve: impl Fn(&str) -> Option<String>,
    transform: impl Fn(&str) -> String,
    expected_host: &str,
    expected_path_prefix: &str,
) {
    for segment in ADVERSARIAL_URL_SEGMENTS {
        let Some(built) = resolve(segment) else {
            continue;
        };
        let parsed = url::Url::parse(&built).unwrap_or_else(|e| {
            panic!("adversarial segment {segment:?} produced an unparsable URL {built:?}: {e}")
        });
        assert_eq!(
            parsed.host_str(),
            Some(expected_host),
            "adversarial segment {segment:?} escaped host: {built}"
        );
        assert!(
            parsed.path().starts_with(expected_path_prefix),
            "adversarial segment {segment:?} escaped path prefix {expected_path_prefix:?}: {built}"
        );
        let expected_fragment = transform(segment);
        assert!(
            !expected_fragment.is_empty(),
            "adversarial segment {segment:?} transformed to an empty fragment but `resolve` \
             still returned Some(url) — an empty identifier must be rejected (return `None`) \
             before reaching the sink, since an empty survival check would trivially pass \
             (\"\".contains(\"\") is always true) and hide a real gate deletion"
        );
        if expected_fragment == "." || expected_fragment == ".." {
            // A whole-path substring search is too weak here: a coincidental `.` baked
            // into a static suffix the sink always appends (e.g. `.json`/`.xml`) would
            // satisfy `contains` even if the real gate is deleted and the actual `.`/`..`
            // segment was silently removed by dot-segment normalization, leaving no trace
            // of it anywhere. Require a per-segment match instead: some path segment, once
            // decoded, must itself start with the dot-segment value — `starts_with` (not
            // exact equality) accommodates a sink that glues the identifier directly onto a
            // static suffix with no separator (e.g. deps-bundler's `versions_url`, which
            // decodes a `..` identifier to the segment `"..json"`).
            let matched = parsed.path_segments().is_some_and(|mut segs| {
                segs.any(|seg| {
                    urlencoding::decode(seg)
                        .is_ok_and(|decoded| decoded.starts_with(expected_fragment.as_str()))
                })
            });
            assert!(
                matched,
                "adversarial segment {segment:?} (expected to survive as {expected_fragment:?}) \
                 did not survive as its own path segment (silently dropped/collapsed by \
                 dot-segment normalization?): built url {built}"
            );
        } else {
            let decoded_path = urlencoding::decode(parsed.path()).unwrap_or_else(|e| {
                panic!(
                    "adversarial segment {segment:?}'s URL path failed to percent-decode: {built:?}: {e}"
                )
            });
            assert!(
                decoded_path.contains(&expected_fragment),
                "adversarial segment {segment:?} (expected to survive as {expected_fragment:?}) \
                 did not survive intact in the decoded path (silently dropped/collapsed by \
                 dot-segment normalization?): decoded path {decoded_path:?}, built url {built}"
            );
        }
    }
}

// Gated separately from the rest of this module (which also compiles under plain
// `cfg(test)`, i.e. `cargo test -p deps-core` with no explicit features): `tracing-subscriber`
// is an *optional* dependency enabled only by the `test-util` feature, so a build that hits
// this module via bare `cfg(test)` alone would fail to resolve it without this narrower gate.
#[cfg(feature = "test-util")]
#[derive(Clone, Default)]
struct CapturingWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(feature = "test-util")]
impl std::io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "test-util")]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(feature = "test-util")]
fn capturing_subscriber_at(
    max_level: tracing::Level,
) -> (CapturingWriter, impl tracing::Subscriber) {
    let writer = CapturingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_max_level(max_level)
        .without_time()
        .with_target(false)
        .finish();
    (writer, subscriber)
}

#[cfg(feature = "test-util")]
fn capturing_subscriber() -> (CapturingWriter, impl tracing::Subscriber) {
    // INFO (not WARN): some call sites emit `tracing::info!` (e.g. deps-swift's
    // release-dates token-gate skip) that a WARN-only filter would silently drop,
    // alongside every `warn_rejected_value`/other WARN-level emission this helper
    // exists to assert on.
    capturing_subscriber_at(tracing::Level::INFO)
}

/// Captures `tracing` output emitted synchronously during `f` into a `String`.
///
/// Lets a test assert a `tracing::warn!`/`info!` call actually fired — e.g.
/// [`crate::lsp_helpers::warn_rejected_value`] — without a real logging sink or a
/// network-dependent end-to-end path. Filters below `INFO`, so a `tracing::debug!`/`trace!`
/// emission never appears here — use [`capture_tracing_output_at`] for those.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::capture_tracing_output;
///
/// let output = capture_tracing_output(|| tracing::warn!("something rejected"));
/// assert!(output.contains("something rejected"));
/// ```
#[cfg(feature = "test-util")]
#[must_use]
pub fn capture_tracing_output(f: impl FnOnce()) -> String {
    let (writer, subscriber) = capturing_subscriber();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8(writer.0.lock().unwrap().clone()).expect("tracing output is valid utf8")
}

/// Like [`capture_tracing_output`], but capturing every level up to and including `max_level`
/// (e.g. `tracing::Level::DEBUG`).
///
/// Needed to positively assert a `tracing::debug!` line fired, or that a `tracing::warn!`
/// specifically (as opposed to any level) did not — [`capture_tracing_output`]'s fixed `INFO`
/// filter makes both assertions vacuous, since a `debug!` call is invisible there regardless of
/// whether the code under test emits it correctly.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::capture_tracing_output_at;
///
/// let output =
///     capture_tracing_output_at(tracing::Level::DEBUG, || tracing::debug!("quiet detail"));
/// assert!(output.contains("quiet detail"));
/// ```
#[cfg(feature = "test-util")]
#[must_use]
pub fn capture_tracing_output_at(max_level: tracing::Level, f: impl FnOnce()) -> String {
    let (writer, subscriber) = capturing_subscriber_at(max_level);
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8(writer.0.lock().unwrap().clone()).expect("tracing output is valid utf8")
}

/// Async counterpart of [`capture_tracing_output`], for a `tracing` emission inside an
/// `async fn`/`.await`ed future.
///
/// Relies on a `#[tokio::test]` current-thread runtime polling `fut` on the same thread
/// that installed the subscriber as the thread-local default.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::capture_tracing_output_async;
///
/// # #[tokio::main]
/// # async fn main() {
/// let output = capture_tracing_output_async(async {
///     tracing::warn!("something rejected");
/// })
/// .await;
/// assert!(output.contains("something rejected"));
/// # }
/// ```
#[cfg(feature = "test-util")]
pub async fn capture_tracing_output_async(fut: impl std::future::Future<Output = ()>) -> String {
    let (writer, subscriber) = capturing_subscriber();
    let guard = tracing::subscriber::set_default(subscriber);
    fut.await;
    drop(guard);
    String::from_utf8(writer.0.lock().unwrap().clone()).expect("tracing output is valid utf8")
}

/// Like [`capture_tracing_output_async`], but capturing every level up to and including
/// `max_level`.
///
/// The async counterpart of [`capture_tracing_output_at`], needed to assert a
/// `tracing::debug!` emission inside an `async fn`/`.await`ed future.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::capture_tracing_output_async_at;
///
/// # #[tokio::main]
/// # async fn main() {
/// let output = capture_tracing_output_async_at(tracing::Level::DEBUG, async {
///     tracing::debug!("quiet detail");
/// })
/// .await;
/// assert!(output.contains("quiet detail"));
/// # }
/// ```
#[cfg(feature = "test-util")]
pub async fn capture_tracing_output_async_at(
    max_level: tracing::Level,
    fut: impl std::future::Future<Output = ()>,
) -> String {
    let (writer, subscriber) = capturing_subscriber_at(max_level);
    let guard = tracing::subscriber::set_default(subscriber);
    fut.await;
    drop(guard);
    String::from_utf8(writer.0.lock().unwrap().clone()).expect("tracing output is valid utf8")
}
