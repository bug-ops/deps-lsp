// Fixture/helper infrastructure exercised only from test binaries (see the module gate
// below), matching `test_util.rs`'s identical allow: every `.unwrap()`/`.expect()` here is
// on a fixture filesystem/temp-dir operation that cannot fail in a single-threaded test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Shared conformance-test scaffolding for ecosystem crates (#758).
//!
//! Every ecosystem crate historically hand-copied the same family of tests — "does
//! `Ecosystem::id()` match", "does `package_url` produce this exact link", "does locating a
//! lock file work in the same directory", "does a too-short completion prefix return no
//! results", "does JSON nesting beyond the shared depth cap get rejected", "does a registry
//! actually override `select_latest_matching` instead of inheriting the trait's `None`
//! default" — with no structural link between the copies, so a fix or a new edge case applied
//! to one crate's copy routinely never reached the other thirteen. This module is the single
//! implementation of each family;
//! the six `#[macro_export]`ed macros below only generate `#[test] fn` scaffolding around the
//! plain `assert_*` functions here, so a fix to an assertion fixes every ecosystem invoking it
//! at once.
//!
//! Gated identically to [`crate::test_util`] (`#[cfg(any(test, feature = "test-util"))]`):
//! usable from this crate's own tests and from any workspace crate that enables `test-util` in
//! its `[dev-dependencies]`.
//!
//! This module does **not** duplicate [`crate::EcosystemId`]'s universal, offline invariants
//! (id round-trip, non-empty `display_name`/routing surface, `completion_insert_text` not
//! panicking) — those are Layer 1, in `deps-lsp`'s own test suite: an all-features-gated
//! completeness check that every [`crate::EcosystemId::ALL`] variant is actually registered,
//! plus an *ungated* per-ecosystem invariants loop over whatever that build's
//! `registry.ecosystem_ids()` produced, so it keeps working under any feature subset. What lives
//! here is Layer 2: **exact**, per-crate values (a crate's specific manifest filename, its
//! specific `package_url` output, its specific naming grammar) that only that one crate can
//! supply. The one exception (#782 gap 1) is `package_url`'s hostile-input-safety check itself
//! (`assert_package_url_hostile_input_safe`): both layers call the same shared implementation,
//! Layer 1 across every *registered* ecosystem at once and Layer 2 (via
//! `formatter_conformance!`, unconditionally) per crate — so a regression is reachable from
//! `cargo nextest run -p <crate>` alone, not only a full workspace run.
//!
//! [`crate::conformance::HOSTILE_DISPLAY_LINK_PAYLOAD`] is a fixture for
//! [`crate::lsp_helpers::PackageRendering::package_url`]
//! — the *display* sink — and is deliberately a separate const from
//! [`crate::test_util::ADVERSARIAL_URL_SEGMENTS`], which guards the unrelated *fetch* sink
//! (dot-segment/traversal class). See that const's doc for the sink split.

use std::any::Any;
use std::path::Path;
use std::time::{Duration, SystemTime};

use tower_lsp_server::ls_types::{CompletionItem, Uri};

use crate::lockfile::LockFileProvider;
use crate::lsp_helpers::EcosystemFormatter;
use crate::{ConcreteVersion, Ecosystem, PackageName};

/// Adversarial payload for the `package_url` *display* sink, not the dot-segment fetch-URL
/// sink [`crate::test_util::ADVERSARIAL_URL_SEGMENTS`] guards.
///
/// The real sink is `lsp_helpers::hover`'s `# [{name}]({url})` markdown link, whose
/// *destination* is written raw (only the label goes through
/// [`crate::lsp_helpers::escape_markdown`]) — so every character that can break out of a
/// `[label](destination)` link is a hazard here, not just newline/autolink/percent: `\n`,
/// `<`, `>`, a bare `%` (must come back encoded as `%25`), and the destination-closing/
/// markup-reopening set `` ` ``, `(`, `)`, `[`, `]` `escape_markdown`'s own doc names as this
/// project's contract for this exact sink. Also embeds a raw U+202E right-to-left override
/// (display-spoofing) and is checked generically for any other control character. Replaces 7
/// independently hand-copied `test_package_url_encodes_newline_autolink_and_percent` tests
/// (deps-maven, deps-pypi, deps-npm, deps-go, deps-dart, deps-composer, deps-nuget) that only
/// asserted the narrower newline/autolink/percent subset.
pub const HOSTILE_DISPLAY_LINK_PAYLOAD: &str = "evil\n<https://evil%zz.example>)([]`\u{202e}";

// ---------------------------------------------------------------------------------------
// Macro 1: `ecosystem_conformance!` — exact `Ecosystem` identity values.
// ---------------------------------------------------------------------------------------

/// Asserts [`Ecosystem::id`] equals `expected`, and that [`Ecosystem::ecosystem_id`] agrees
/// with it.
///
/// [`Ecosystem::id`] is a *provided* method with a default derived from
/// [`Ecosystem::ecosystem_id`] — but, being provided, it stays overridable, so nothing else
/// forces the two to stay in sync for an implementor that overrides `id()` directly. Without
/// this second assertion, a crate could pass `expected` here via a compensating `id()`
/// override while its `ecosystem_id()` names the wrong variant — silently wrong for every
/// caller that branches on `ecosystem_id()` (`osv_ecosystem()`, `DocumentState`
/// classification, formatter context) instead of the string.
pub fn assert_ecosystem_id(eco: &dyn Ecosystem, expected: &str) {
    assert_eq!(eco.id(), expected, "Ecosystem::id() mismatch");
    assert_eq!(
        eco.ecosystem_id().id(),
        eco.id(),
        "Ecosystem::ecosystem_id() disagrees with Ecosystem::id()"
    );
}

/// Asserts [`Ecosystem::display_name`] equals `expected`.
pub fn assert_ecosystem_display_name(eco: &dyn Ecosystem, expected: &str) {
    assert_eq!(
        eco.display_name(),
        expected,
        "Ecosystem::display_name() mismatch"
    );
}

/// Asserts [`Ecosystem::manifest_filenames`] equals `expected`.
pub fn assert_manifest_filenames(eco: &dyn Ecosystem, expected: &[&str]) {
    assert_eq!(
        eco.manifest_filenames(),
        expected,
        "Ecosystem::manifest_filenames() mismatch"
    );
}

/// Asserts [`Ecosystem::lockfile_filenames`] equals `expected`.
pub fn assert_lockfile_filenames(eco: &dyn Ecosystem, expected: &[&str]) {
    assert_eq!(
        eco.lockfile_filenames(),
        expected,
        "Ecosystem::lockfile_filenames() mismatch"
    );
}

/// Asserts [`Ecosystem::as_any`] downcasts to `T`.
pub fn assert_as_any_downcasts<T: Any>(eco: &dyn Ecosystem) {
    assert!(
        eco.as_any().is::<T>(),
        "Ecosystem::as_any() did not downcast to the expected concrete type"
    );
}

/// Smoke-checks that [`Ecosystem::registry`] returns without panicking.
///
/// The type system already guarantees the `Arc<dyn Registry>` return type, so there is
/// nothing further to assert; this exists so `ecosystem_conformance!`-generated coverage has
/// a named test the crate-specific `test_registry_creation`/`test_registry_returns_arc`
/// copies it replaces used to provide.
pub fn assert_registry_returns_arc(eco: &dyn Ecosystem) {
    let _registry = eco.registry();
}

/// Asserts an ecosystem declares no lock file support at all (#782 gap 2).
///
/// Both [`Ecosystem::lockfile_filenames`] is empty and [`Ecosystem::lockfile_provider`] is
/// `None`. Strictly stronger than the cross-check `deps-lsp`'s
/// `test_registered_ecosystems_universal_invariants` runs across every *registered* ecosystem —
/// that check only asserts the two *agree* (`lockfile_filenames().is_empty() ==
/// lockfile_provider().is_none()`), true for a lockfile-*having* ecosystem too, whereas this
/// asserts both are specifically absent. This is the per-crate, `cargo nextest run -p
/// <crate>`-reachable implementation of that stronger, lockfile-less-specific invariant,
/// replacing the `test_lockfile_filenames_empty`/`test_lockfile_provider_none` pair
/// `deps-maven`/`deps-gradle` used to hand-copy.
pub fn assert_no_lockfile_support(eco: &dyn Ecosystem) {
    assert!(
        eco.lockfile_filenames().is_empty(),
        "Ecosystem::lockfile_filenames() must be empty for a lockfile-less ecosystem"
    );
    assert!(
        eco.lockfile_provider().is_none(),
        "Ecosystem::lockfile_provider() must be None for a lockfile-less ecosystem"
    );
}

// ---------------------------------------------------------------------------------------
// Macro 2: `formatter_conformance!` — exact `EcosystemFormatter` values.
// ---------------------------------------------------------------------------------------

/// `formatter.package_url(HOSTILE_DISPLAY_LINK_PAYLOAD)` — the shared call both
/// [`assert_package_url_hostile_input_safe`] and [`assert_package_url_hostile_input_expected`]
/// build on (#782 code-review cleanup 2), so the fixture name/lookup can't drift between them.
fn hostile_package_url(formatter: &dyn EcosystemFormatter) -> String {
    let hostile_name = PackageName::new(HOSTILE_DISPLAY_LINK_PAYLOAD);
    formatter.package_url(&hostile_name)
}

/// Asserts `formatter.package_url(HOSTILE_DISPLAY_LINK_PAYLOAD)` is safe (#782 gap 1).
///
/// Safe for the markdown `# [{name}]({url})` hover-heading link sink: either empty, or a
/// parseable URL free of every character that could break out of a `[label](destination)`
/// link, free of any raw control character or raw U+202E right-to-left override, and with any
/// literal `%` in the input percent-encoded as `%25` in the output.
///
/// Identical to the check `deps-lsp`'s own `test_registered_ecosystems_universal_invariants`
/// (Layer 1) runs for every *registered* ecosystem at once — this is the single shared
/// implementation both layers call, so a fix to the check applies to both without drifting
/// apart. Layer 1 additionally proves every [`crate::EcosystemId::ALL`] variant is actually
/// wired into the running server; this function alone proves nothing about registration, only
/// that a given formatter's `package_url` is safe for this payload — which is why
/// `formatter_conformance!` (Layer 2) calls it unconditionally for every ecosystem crate,
/// catching a regression with `cargo nextest run -p <crate>` alone rather than only a full
/// workspace run.
///
/// **Vacuous for a formatter that fails closed to `""` for this payload** (#782 critic M2): the
/// early return below means such a formatter passes this check no matter *why* `package_url`
/// returned empty — a future refactor that stops rejecting the hostile name here would not be
/// caught. [`assert_package_url_hostile_input_expected`] (paired with `formatter_conformance!`'s
/// optional `hostile_package_url_expected` arm) closes that for the crates it actually applies
/// to, pinning the exact value instead of merely accepting emptiness.
pub fn assert_package_url_hostile_input_safe(formatter: &dyn EcosystemFormatter, context: &str) {
    let url = hostile_package_url(formatter);
    assert!(
        url.is_empty() || url::Url::parse(&url).is_ok(),
        "{context}: package_url produced an unparsable non-empty URL: {url:?}"
    );
    if url.is_empty() {
        return;
    }
    for hazard in ['\n', '<', '>', '(', ')', '[', ']', '`'] {
        assert!(
            !url.contains(hazard),
            "{context}: package_url leaked a literal {hazard:?} — a markdown \
             `[label](destination)` link-destination breakout character: {url:?}"
        );
    }
    assert!(
        !url.chars().any(char::is_control),
        "{context}: package_url leaked a raw control character: {url:?}"
    );
    assert!(
        !url.contains('\u{202e}'),
        "{context}: package_url leaked a raw U+202E right-to-left override \
         (display-spoofing): {url:?}"
    );
    assert!(
        url.contains("%25"),
        "{context}: package_url did not encode the payload's literal '%' as %25: {url:?}"
    );
}

/// Asserts `formatter.package_url(HOSTILE_DISPLAY_LINK_PAYLOAD)` equals `expected` exactly
/// (#782 critic M2).
///
/// Pairs with [`assert_package_url_hostile_input_safe`]/`formatter_conformance!`'s
/// unconditional check, which returns early (accepting) once `package_url` is empty — that
/// early return makes the unconditional check vacuous for a formatter that always fails closed
/// to `""` for this payload, proving nothing about *why* it is empty. Use this (via the
/// optional `hostile_package_url_expected` arm) for exactly those formatters, to pin the actual
/// value rather than merely tolerate emptiness.
pub fn assert_package_url_hostile_input_expected(
    formatter: &dyn EcosystemFormatter,
    expected: &str,
    context: &str,
) {
    let url = hostile_package_url(formatter);
    assert_eq!(
        url, expected,
        "{context}: package_url(HOSTILE_DISPLAY_LINK_PAYLOAD) mismatch"
    );
}

/// Asserts `formatter.format_version_for_text_edit(version)` equals `expected` (#782 coverage
/// gap).
///
/// Closes the `test_format_version` family for ecosystems that had no coverage of this method
/// at all (deps-composer, deps-deno, deps-github-actions, deps-gitlab-ci), and for deps-go,
/// folds in the one case (deps-go's pre-existing, now-deleted hand-written test) that was
/// covering it without going through this macro.
pub fn assert_format_version(formatter: &dyn EcosystemFormatter, version: &str, expected: &str) {
    assert_eq!(
        formatter.format_version_for_text_edit(&ConcreteVersion::new(version)),
        expected,
        "format_version_for_text_edit({version:?}) mismatch"
    );
}

/// Asserts `formatter.package_url(name)` equals `expected`.
pub fn assert_package_url(formatter: &dyn EcosystemFormatter, name: &str, expected: &str) {
    assert_eq!(
        formatter.package_url(&PackageName::new(name)),
        expected,
        "package_url({name:?}) mismatch"
    );
}

/// Asserts `formatter.validate_package_name(name)` is `Ok`.
pub fn assert_validate_package_name_accepts(formatter: &dyn EcosystemFormatter, name: &str) {
    assert!(
        formatter.validate_package_name(name).is_ok(),
        "expected {name:?} to be accepted"
    );
}

/// Asserts `formatter.validate_package_name(name)` is `Err`.
pub fn assert_validate_package_name_rejects(formatter: &dyn EcosystemFormatter, name: &str) {
    assert!(
        formatter.validate_package_name(name).is_err(),
        "expected {name:?} to be rejected"
    );
}

/// Asserts `formatter.version_satisfies_requirement(version, requirement)` equals `expected`.
pub fn assert_version_satisfies_requirement(
    formatter: &dyn EcosystemFormatter,
    version: &str,
    requirement: &str,
    expected: bool,
) {
    assert_eq!(
        formatter.version_satisfies_requirement(&ConcreteVersion::new(version), requirement),
        expected,
        "version_satisfies_requirement({version:?}, {requirement:?}) mismatch"
    );
}

// ---------------------------------------------------------------------------------------
// Macro 3: `lockfile_conformance!` — `LockFileProvider` behavior, looped over a
// (filename, content) list at runtime (an ecosystem may recognize more than one lock file).
// ---------------------------------------------------------------------------------------

/// Asserts `parser.locate_lockfile` returns `None` when no lock file is present next to the
/// manifest.
pub fn assert_locate_lockfile_not_found(
    parser: &dyn LockFileProvider,
    manifest_name: &str,
    manifest_content: &str,
) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = temp_dir.path().join(manifest_name);
    std::fs::write(&manifest_path, manifest_content).expect("write manifest");
    let manifest_uri = Uri::from_file_path(&manifest_path).expect("valid file uri");

    assert!(
        parser.locate_lockfile(&manifest_uri).is_none(),
        "locate_lockfile must return None when no lock file exists"
    );
}

/// Asserts `parser.locate_lockfile` finds `lock_name` in the manifest's own directory.
pub fn assert_locate_lockfile_same_directory(
    parser: &dyn LockFileProvider,
    manifest_name: &str,
    manifest_content: &str,
    lock_name: &str,
    lock_content: &str,
) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = temp_dir.path().join(manifest_name);
    let lock_path = temp_dir.path().join(lock_name);
    std::fs::write(&manifest_path, manifest_content).expect("write manifest");
    std::fs::write(&lock_path, lock_content).expect("write lockfile");
    let manifest_uri = Uri::from_file_path(&manifest_path).expect("valid file uri");

    assert_eq!(
        parser.locate_lockfile(&manifest_uri),
        Some(lock_path),
        "expected {lock_name} to be located in the manifest's own directory"
    );
}

/// Asserts a freshly written lock file is not considered stale against its own mtime.
pub fn assert_lockfile_not_stale_when_unmodified(
    parser: &dyn LockFileProvider,
    lock_name: &str,
    lock_content: &str,
) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let lockfile_path = temp_dir.path().join(lock_name);
    std::fs::write(&lockfile_path, lock_content).expect("write lockfile");
    let mtime = std::fs::metadata(&lockfile_path)
        .expect("metadata")
        .modified()
        .expect("mtime");

    assert!(
        !parser.is_lockfile_stale(&lockfile_path, mtime),
        "{lock_name} should not be stale when mtime matches"
    );
}

/// Asserts a lock file is considered stale against an old `last_modified` timestamp.
pub fn assert_lockfile_stale_when_old(
    parser: &dyn LockFileProvider,
    lock_name: &str,
    lock_content: &str,
) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let lockfile_path = temp_dir.path().join(lock_name);
    std::fs::write(&lockfile_path, lock_content).expect("write lockfile");

    assert!(
        parser.is_lockfile_stale(&lockfile_path, SystemTime::UNIX_EPOCH),
        "{lock_name} should be stale when last_modified is old"
    );
}

/// Asserts a non-existent lock file is considered stale.
pub fn assert_lockfile_stale_when_missing(parser: &dyn LockFileProvider) {
    let non_existent = Path::new("/nonexistent/lockfile-conformance-fixture");

    assert!(
        parser.is_lockfile_stale(non_existent, SystemTime::now()),
        "a non-existent lock file should be considered stale"
    );
}

/// Asserts a lock file is not considered stale against a future `last_modified` timestamp.
pub fn assert_lockfile_not_stale_in_future(
    parser: &dyn LockFileProvider,
    lock_name: &str,
    lock_content: &str,
) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let lockfile_path = temp_dir.path().join(lock_name);
    std::fs::write(&lockfile_path, lock_content).expect("write lockfile");
    let future_time = SystemTime::now() + Duration::from_hours(24);

    assert!(
        !parser.is_lockfile_stale(&lockfile_path, future_time),
        "{lock_name} should not be stale when last_modified is in the future"
    );
}

/// Asserts parsing a malformed lock file never panics.
///
/// Resolves to either `Err` or an empty [`crate::lockfile::ResolvedPackages`] — never `Ok`
/// with fabricated data (#758 M3): several parsers are line-skipping and tolerantly return
/// `Ok(empty)` on garbage input, which is an accepted outcome; silently returning non-empty,
/// made-up packages would not be.
pub async fn assert_parse_malformed_lockfile_does_not_panic(
    parser: &dyn LockFileProvider,
    lock_name: &str,
    malformed_content: &str,
) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let lockfile_path = temp_dir.path().join(lock_name);
    std::fs::write(&lockfile_path, malformed_content).expect("write malformed lockfile");

    if let Ok(packages) = parser.parse_lockfile(&lockfile_path).await {
        assert!(
            packages.is_empty(),
            "malformed {lock_name} content parsed to non-empty packages instead of Err or empty"
        );
    }
}

// ---------------------------------------------------------------------------------------
// Macro 4: `completion_guard_conformance!` — the shared prefix-length guard
// (`crate::completion::complete_package_names_generic`'s `is_valid_completion_prefix_len`).
// ---------------------------------------------------------------------------------------

/// A [`crate::Registry`] whose `search` deterministically returns one fixed, non-empty
/// result, regardless of the query.
///
/// [`assert_completion_guard`] uses this to distinguish "the length guard rejected this
/// prefix" from "the registry search returned nothing" — a real (or offline-failing)
/// registry returns empty for *every* prefix, so an assertion built only on "does a
/// short/long prefix come back empty" cannot tell the guard firing apart from the network
/// call simply failing (#758 impl-critic M1). Because this registry always has a result to
/// give back, a valid-length prefix reaching it is guaranteed non-empty — so a guard that
/// wrongly rejects a valid prefix, or a `complete` closure not wired to the guard at all,
/// both become visible.
struct AlwaysHasResultsRegistry;

impl crate::Registry for AlwaysHasResultsRegistry {
    fn get_versions<'a>(
        &'a self,
        _name: &'a PackageName,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = crate::Result<Vec<Box<dyn crate::Version>>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move { Ok(vec![]) })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a PackageName,
        _req: &'a crate::VersionReq,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = crate::Result<Option<Box<dyn crate::Version>>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move { Ok(None) })
    }

    fn search<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = crate::Result<Vec<Box<dyn crate::Metadata>>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let metadata = crate::test_util::MockMetadata::new("conformance-probe", "1.0.0");
            Ok(vec![Box::new(metadata) as Box<dyn crate::Metadata>])
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Asserts a package-name completion function rejects a too-short, empty, and too-long
/// prefix by returning no completions.
///
/// Mirrors [`crate::completion::complete_package_names_generic`]'s shared guard — and, against
/// `AlwaysHasResultsRegistry`, that a valid-length prefix actually returns that registry's
/// result, so the rejection above can't be explained away by "this registry never returns
/// anything" (#758 impl-critic M1).
///
/// `complete` returns a boxed, lifetime-parameterized future rather than a plain associated
/// `Fut: Future`: the natural implementation borrows the `&dyn Registry` argument across the
/// `.await` (an `async fn(&dyn Registry, ...)` call), and a single fixed `Fut` type cannot
/// express "the future's lifetime depends on the reference passed at each call" — only a
/// `for<'a> Fn(&'a ..., ...) -> Pin<Box<dyn Future + 'a>>` bound can. A plain `Fn(..) -> Fut`
/// bound compiles here but fails at every real call site with "lifetime may not live long
/// enough" (verified: this was this function's first, broken signature).
pub async fn assert_completion_guard<C>(complete: C)
where
    C: for<'a> Fn(
        &'a dyn crate::Registry,
        String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Vec<CompletionItem>> + Send + 'a>,
    >,
{
    let registry = AlwaysHasResultsRegistry;

    let results = complete(&registry, "s".to_string()).await;
    assert!(
        results.is_empty(),
        "a 1-character prefix must return no completions"
    );

    let results = complete(&registry, String::new()).await;
    assert!(
        results.is_empty(),
        "an empty prefix must return no completions"
    );

    let long_prefix = "a".repeat(201);
    let results = complete(&registry, long_prefix).await;
    assert!(
        results.is_empty(),
        "a 201-character prefix must return no completions"
    );

    let results = complete(&registry, "conformance-probe".to_string()).await;
    assert!(
        !results.is_empty(),
        "a valid-length prefix against a registry that always has a result must return it — \
         an empty result here means either the guard over-rejects a valid prefix, or \
         `complete` isn't actually wired to the registry this test supplied"
    );
}

// ---------------------------------------------------------------------------------------
// Macro 5: `json_depth_conformance!` — the shared JSON-nesting depth cap
// (`crate::MAX_JSON_NESTING_DEPTH` / `crate::check_json_nesting_depth`).
// ---------------------------------------------------------------------------------------

/// Asserts `parse` accepts a JSON payload nested exactly to [`crate::MAX_JSON_NESTING_DEPTH`].
///
/// `wrap` embeds a nested-array fragment of the given depth into a payload shape `parse`
/// otherwise recognizes.
pub fn assert_json_nesting_at_max_depth_accepted<T, E>(
    parse: impl Fn(&[u8]) -> Result<T, E>,
    wrap: impl Fn(&str) -> String,
) {
    let depth = crate::MAX_JSON_NESTING_DEPTH;
    let nested = format!("{}1{}", "[".repeat(depth - 1), "]".repeat(depth - 1));
    let json = wrap(&nested);

    assert!(
        parse(json.as_bytes()).is_ok(),
        "nesting at the maximum allowed depth ({depth}) must be accepted"
    );
}

/// Asserts `parse` rejects a JSON payload nested one level beyond
/// [`crate::MAX_JSON_NESTING_DEPTH`].
pub fn assert_json_nesting_over_max_depth_rejected<T, E>(
    parse: impl Fn(&[u8]) -> Result<T, E>,
    wrap: impl Fn(&str) -> String,
) {
    let depth = crate::MAX_JSON_NESTING_DEPTH + 1;
    let nested = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
    let json = wrap(&nested);

    assert!(
        parse(json.as_bytes()).is_err(),
        "nesting beyond the maximum allowed depth must be rejected"
    );
}

// ---------------------------------------------------------------------------------------
// Macro 6: `registry_conformance!` — a [`crate::Registry`] actually overrides
// [`crate::Registry::select_latest_matching`] rather than inheriting its `None` default.
// ---------------------------------------------------------------------------------------

/// Asserts `registry.select_latest_matching(versions, &VersionReq::new(req))` equals
/// `Some(expected_index)`.
///
/// `expected_index` is `usize`, not `Option<usize>`, so the trait's `None` default is
/// inexpressible by construction here — a registry that never overrides
/// [`crate::Registry::select_latest_matching`] fails this assertion rather than passing it
/// vacuously (#784).
///
/// `versions` must be newest-first (the same ordering [`crate::Registry::get_versions`]
/// returns) — `expected_index` indexes this slice as given, not re-sorted.
pub fn assert_select_latest_matching_overridden(
    registry: &dyn crate::Registry,
    versions: &[Box<dyn crate::Version>],
    req: &str,
    expected_index: usize,
) {
    let req = crate::VersionReq::new(req);
    assert_eq!(
        registry.select_latest_matching(versions, &req),
        Some(expected_index),
        "select_latest_matching({req:?}) index mismatch"
    );
}

// ---------------------------------------------------------------------------------------
// Macros
// ---------------------------------------------------------------------------------------

/// Generates exact-value conformance tests for an [`Ecosystem`] implementation (#758 macro 1).
///
/// Replaces per-crate `test_ecosystem_id`/`test_ecosystem_display_name`/
/// `test_ecosystem_manifest_filenames`/`test_ecosystem_lockfile_filenames`/`test_as_any`/
/// `test_registry_creation`-shaped tests. `lockfile_filenames` is omitted for an ecosystem
/// with no lock file format; pair that omission with `no_lockfile_support: true;` (#782 gap
/// 2) to also assert [`Ecosystem::lockfile_provider`] agrees — replacing the
/// `test_lockfile_filenames_empty`/`test_lockfile_provider_none` pair `deps-maven`/
/// `deps-gradle` used to hand-copy. Supplying both `lockfile_filenames` and
/// `no_lockfile_support: true;` on the same invocation is a compile error — the two are
/// mutually exclusive by construction.
///
/// Must be invoked inside your own `#[cfg(test)] mod tests { ... }` — this macro does not
/// emit its own `#[cfg(test)]` (a doctest is not compiled with `--cfg test`, so a
/// macro-emitted `#[cfg(test)]` would cfg-strip the generated body out of every doctest
/// before it is even type-checked, silently making the `# Examples` below prove nothing).
///
/// Each generated assertion also lives in a plain, non-`#[test]` `_impl` fn called by a
/// thin `#[test]` wrapper, for the same reason and one more: the compiler elides a
/// `#[test]`-attributed item's *body* entirely outside a real `--test` build — the same
/// mechanism `#[cfg(test)]` uses, just built into the `#[test]` attribute itself — so an
/// `expr`/`ty` fragment substituted straight into a `#[test]` fn is never type-checked in a
/// doctest even once the redundant `#[cfg(test)]` above is removed (verified empirically:
/// a bare, cfg-free `#[test] fn` calling an undefined function still compiles clean in
/// `cargo test --doc`). A plain sibling fn holding the substitution is not elided, so it
/// gets checked in every build, doctests included.
///
/// # Examples
///
/// Wrapped in an explicit `mod example` because the generated `mod`'s `use super::*;`
/// needs a real parent module to see `Fake`/`build_fake` through — a merged doctest's own
/// implicit wrapping does not give it one.
///
/// ```
/// mod example {
/// # use std::any::Any;
/// # use std::sync::Arc;
/// # struct FakeRegistry;
/// # impl deps_core::Registry for FakeRegistry {
/// #     fn get_versions<'a>(&'a self, _name: &'a deps_core::PackageName)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Vec<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(vec![]) })
/// #     }
/// #     fn get_latest_matching<'a>(&'a self, _name: &'a deps_core::PackageName, _req: &'a deps_core::VersionReq)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Option<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(None) })
/// #     }
/// #     fn search<'a>(&'a self, _query: &'a str, _limit: usize)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(vec![]) })
/// #     }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// # struct Fake { registry: Arc<FakeRegistry> }
/// # impl deps_core::ecosystem::private::Sealed for Fake {}
/// # impl deps_core::Ecosystem for Fake {
/// #     fn id(&self) -> &'static str { "fake" }
/// #     fn ecosystem_id(&self) -> deps_core::EcosystemId { deps_core::EcosystemId::Cargo }
/// #     fn display_name(&self) -> &'static str { "Fake" }
/// #     fn manifest_filenames(&self) -> &[&'static str] { &["fake.toml"] }
/// #     fn registry(&self) -> Arc<dyn deps_core::Registry> { self.registry.clone() }
/// #     fn formatter(&self) -> &dyn deps_core::lsp_helpers::EcosystemFormatter { unimplemented!() }
/// #     fn parse_manifest<'a>(&'a self, _content: &'a str, _uri: &'a tower_lsp_server::ls_types::Uri)
/// #         -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn deps_core::ParseResult>>> {
/// #         unimplemented!()
/// #     }
/// #     fn generate_completions<'a>(&'a self, _parse_result: &'a dyn deps_core::ParseResult, _position: tower_lsp_server::ls_types::Position, _content: &'a str, _freshness: deps_core::FreshnessSettings)
/// #         -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions> {
/// #         unimplemented!()
/// #     }
/// #     fn completion_insert_text(&self, _metadata: &dyn deps_core::Metadata) -> Option<String> { None }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// # fn build_fake() -> Fake { Fake { registry: Arc::new(FakeRegistry) } }
/// deps_core::ecosystem_conformance! {
///     mod fake_ecosystem_conformance;
///     build: build_fake();
///     ty: Fake;
///     id: "fake";
///     display_name: "Fake";
///     manifest_filenames: &["fake.toml"];
/// }
/// }
/// ```
#[macro_export]
macro_rules! ecosystem_conformance {
    // Rejects the mutually-exclusive combination at compile time (#782 code-review cleanup 1):
    // an ecosystem cannot both list lock file names and declare it has no lock file support.
    // Tried first — `macro_rules!` matches arms in order — so this only intercepts the one
    // invalid combination; every other invocation (0 or 1 of the two fields) falls through
    // to the real arm below unchanged.
    (
        mod $mod_name:ident;
        build: $build:expr;
        ty: $ty:ty;
        id: $id:expr;
        display_name: $display_name:expr;
        manifest_filenames: $manifest_filenames:expr;
        lockfile_filenames: $lockfile_filenames:expr;
        no_lockfile_support: $no_lockfile_support:literal;
    ) => {
        compile_error!(
            "ecosystem_conformance!: `lockfile_filenames` and `no_lockfile_support` are \
             mutually exclusive — an ecosystem cannot both have lock file names and declare \
             it has no lock file support; supply at most one of the two"
        );
    };
    (
        mod $mod_name:ident;
        build: $build:expr;
        ty: $ty:ty;
        id: $id:expr;
        display_name: $display_name:expr;
        manifest_filenames: $manifest_filenames:expr;
        $(lockfile_filenames: $lockfile_filenames:expr;)?
        $(no_lockfile_support: $no_lockfile_support:literal;)?
    ) => {
        mod $mod_name {
            use super::*;

            // Each assertion lives in a plain (non-`#[test]`) `_impl` fn, called by a thin
            // `#[test]` wrapper. The compiler elides a `#[test]`-attributed item's body
            // entirely outside a real `--test` build (the same mechanism `#[cfg(test)]`
            // uses) — a plain doctest is never built with `--test`, so an `expr`/`ty`
            // substituted directly into a `#[test]` fn's body is never type-checked there.
            // Splitting the substitution into a plain fn keeps it checked in every build,
            // doctests included (#758 impl-critic S1).

            fn ecosystem_id_matches_impl() {
                $crate::conformance::assert_ecosystem_id(&($build), $id);
            }
            #[test]
            fn ecosystem_id_matches() {
                ecosystem_id_matches_impl();
            }

            fn ecosystem_display_name_matches_impl() {
                $crate::conformance::assert_ecosystem_display_name(&($build), $display_name);
            }
            #[test]
            fn ecosystem_display_name_matches() {
                ecosystem_display_name_matches_impl();
            }

            fn ecosystem_manifest_filenames_match_impl() {
                $crate::conformance::assert_manifest_filenames(&($build), $manifest_filenames);
            }
            #[test]
            fn ecosystem_manifest_filenames_match() {
                ecosystem_manifest_filenames_match_impl();
            }

            $(
                fn ecosystem_lockfile_filenames_match_impl() {
                    $crate::conformance::assert_lockfile_filenames(&($build), $lockfile_filenames);
                }
                #[test]
                fn ecosystem_lockfile_filenames_match() {
                    ecosystem_lockfile_filenames_match_impl();
                }
            )?

            $(
                // `$no_lockfile_support` must be the literal `true` — `false` would silently
                // generate this assertion anyway if left unchecked (`macro_rules` can only
                // gate on the arm's *presence*, not inspect a captured literal's value), so a
                // `const` context `assert!` rejects anything else at compile time, in every
                // profile (unlike `debug_assert!`, which release builds strip) (#782 critic M1).
                const _: () = assert!(
                    $no_lockfile_support,
                    "no_lockfile_support only accepts `true` — omit the field entirely for a \
                     lockfile-having ecosystem, never write `no_lockfile_support: false;`",
                );

                fn ecosystem_has_no_lockfile_support_impl() {
                    $crate::conformance::assert_no_lockfile_support(&($build));
                }
                #[test]
                fn ecosystem_has_no_lockfile_support() {
                    ecosystem_has_no_lockfile_support_impl();
                }
            )?

            fn ecosystem_as_any_downcasts_impl() {
                $crate::conformance::assert_as_any_downcasts::<$ty>(&($build));
            }
            #[test]
            fn ecosystem_as_any_downcasts() {
                ecosystem_as_any_downcasts_impl();
            }

            fn ecosystem_registry_returns_arc_impl() {
                $crate::conformance::assert_registry_returns_arc(&($build));
            }
            #[test]
            fn ecosystem_registry_returns_arc() {
                ecosystem_registry_returns_arc_impl();
            }
        }
    };
}

/// Generates exact-value conformance tests for an [`EcosystemFormatter`] implementation
/// (#758 macro 2).
///
/// `accepts`/`rejects`/`version_roundtrip`/`format_version`/`hostile_package_url_expected` are
/// optional. Unconditionally also generates a `package_url` hostile-input-safety test (#782 gap 1),
/// via [`assert_package_url_hostile_input_safe`] — the same check Layer 1 (`deps-lsp`'s
/// `EcosystemId::ALL` loop) runs universally across every *registered* ecosystem at once, but
/// reachable here with `cargo nextest run -p <crate>` alone, without needing a full workspace
/// run. This holds for every ecosystem crate invoking this macro today (proven by Layer 1
/// already passing for all of them), so adding it is not a per-crate opt-in. That unconditional
/// check is vacuous for a formatter that fails closed to a fixed (typically empty) result for
/// the hostile payload (#782 critic M2) — set `hostile_package_url_expected: "<value>";` to
/// additionally pin the exact value for such a formatter, via
/// [`assert_package_url_hostile_input_expected`].
///
/// Must be invoked inside your own `#[cfg(test)] mod tests { ... }` — see
/// [`ecosystem_conformance!`]'s doc for why this macro does not emit its own `#[cfg(test)]`.
///
/// Wrapped in an explicit `mod example` — see [`ecosystem_conformance!`]'s doc for why.
///
/// # Examples
///
/// ```
/// mod example {
/// # struct Fake;
/// # impl deps_core::lsp_helpers::PackageNaming for Fake {}
/// # impl deps_core::lsp_helpers::PackageRendering for Fake {
/// #     fn format_version_for_text_edit(&self, v: &deps_core::ConcreteVersion) -> String { v.as_str().to_string() }
/// #     fn package_url(&self, name: &deps_core::PackageName) -> String {
/// #         // Percent-encoded (`urlencoding::encode`, the same idiom every real ecosystem's
/// #         // `package_url` uses) so this toy formatter also passes the hostile-input-safety
/// #         // test the macro generates unconditionally below (#782 gap 1) — a naive
/// #         // `format!("https://example.com/{name}")` would leak the payload's raw hazard
/// #         // characters straight into the URL.
/// #         format!("https://example.com/{}", urlencoding::encode(name.as_str()))
/// #     }
/// # }
/// # impl deps_core::lsp_helpers::RequirementResolution for Fake {}
/// # impl deps_core::lsp_helpers::DiagnosticMessages for Fake {}
/// # impl deps_core::lsp_helpers::DiagnosticPolicy for Fake {}
/// # impl deps_core::lsp_helpers::SourcePolicy for Fake {}
/// # impl deps_core::lsp_helpers::OsvNaming for Fake {}
/// deps_core::formatter_conformance! {
///     mod fake_formatter_conformance;
///     build: Fake;
///     package_url: { "serde" => "https://example.com/serde" };
/// }
/// }
/// ```
#[macro_export]
macro_rules! formatter_conformance {
    (
        mod $mod_name:ident;
        build: $build:expr;
        package_url: { $($name:literal => $expected:literal),+ $(,)? };
        $(accepts: [ $($accept_name:literal),+ $(,)? ];)?
        $(rejects: [ $($reject_name:literal),+ $(,)? ];)?
        $(version_roundtrip: [ $($version:literal, $requirement:literal => $roundtrip_expected:literal),+ $(,)? ];)?
        $(format_version: [ $($fv_version:literal => $fv_expected:literal),+ $(,)? ];)?
        $(hostile_package_url_expected: $hostile_expected:literal;)?
    ) => {
        mod $mod_name {
            use super::*;

            // See `ecosystem_conformance!`'s doc for why each assertion is a plain `_impl`
            // fn called by a thin `#[test]` wrapper, not inlined directly into the `#[test]`
            // fn's own body.

            fn formatter_package_url_matches_impl() {
                $( $crate::conformance::assert_package_url(&($build), $name, $expected); )+
            }
            #[test]
            fn formatter_package_url_matches() {
                formatter_package_url_matches_impl();
            }

            // Unconditional (#782 gap 1) — see this macro's doc for why every invocation
            // gets this test regardless of whether `package_url` is even reachable for a
            // hostile name.
            fn formatter_package_url_hostile_input_safe_impl() {
                $crate::conformance::assert_package_url_hostile_input_safe(
                    &($build), stringify!($mod_name),
                );
            }
            #[test]
            fn formatter_package_url_hostile_input_safe() {
                formatter_package_url_hostile_input_safe_impl();
            }

            $(
                // #782 critic M2: pins the exact value for a formatter whose `package_url`
                // fails closed to a fixed result (typically `""`) for the hostile payload —
                // the unconditional check above alone is vacuous for such a formatter, since
                // it accepts any empty result without proving *why* it is empty.
                fn formatter_package_url_hostile_input_expected_impl() {
                    $crate::conformance::assert_package_url_hostile_input_expected(
                        &($build), $hostile_expected, stringify!($mod_name),
                    );
                }
                #[test]
                fn formatter_package_url_hostile_input_expected() {
                    formatter_package_url_hostile_input_expected_impl();
                }
            )?

            $(
                fn formatter_format_version_matches_impl() {
                    $( $crate::conformance::assert_format_version(&($build), $fv_version, $fv_expected); )+
                }
                #[test]
                fn formatter_format_version_matches() {
                    formatter_format_version_matches_impl();
                }
            )?

            $(
                fn formatter_validate_package_name_accepts_impl() {
                    $( $crate::conformance::assert_validate_package_name_accepts(&($build), $accept_name); )+
                }
                #[test]
                fn formatter_validate_package_name_accepts() {
                    formatter_validate_package_name_accepts_impl();
                }
            )?

            $(
                fn formatter_validate_package_name_rejects_impl() {
                    $( $crate::conformance::assert_validate_package_name_rejects(&($build), $reject_name); )+
                }
                #[test]
                fn formatter_validate_package_name_rejects() {
                    formatter_validate_package_name_rejects_impl();
                }
            )?

            $(
                fn formatter_version_satisfies_requirement_matches_impl() {
                    $(
                        $crate::conformance::assert_version_satisfies_requirement(
                            &($build), $version, $requirement, $roundtrip_expected,
                        );
                    )+
                }
                #[test]
                fn formatter_version_satisfies_requirement_matches() {
                    formatter_version_satisfies_requirement_matches_impl();
                }
            )?
        }
    };
}

/// Generates [`LockFileProvider`] conformance tests, looping over `lockfiles` at runtime.
///
/// `macro_rules!` cannot concatenate identifiers to generate one test function per lock file
/// name, so each generated test iterates the list instead (#758 macro 3, M2/M3).
///
/// Must be invoked inside your own `#[cfg(test)] mod tests { ... }` — see
/// [`ecosystem_conformance!`]'s doc for why this macro does not emit its own `#[cfg(test)]`.
///
/// # Examples
///
/// A multi-entry `lockfiles:` list (an ecosystem recognizing more than one lock file format,
/// e.g. npm's `package-lock.json`/`pnpm-lock.yaml`). Wrapped in an explicit `mod example` —
/// see [`ecosystem_conformance!`]'s doc for why:
///
/// ```
/// mod example {
/// # use deps_core::lockfile::{LockFileProvider, ResolvedPackages, locate_lockfile_for_manifest, read_and_parse_lockfile};
/// # use std::path::{Path, PathBuf};
/// # use tower_lsp_server::ls_types::Uri;
/// struct FakeLockParser;
/// impl LockFileProvider for FakeLockParser {
///     fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
///         locate_lockfile_for_manifest(manifest_uri, &["fake.lock", "fake-alt.lock"])
///     }
///     fn parse_lockfile<'a>(&'a self, path: &'a Path)
///         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<ResolvedPackages>> + Send + 'a>> {
///         Box::pin(async move { read_and_parse_lockfile(path, "fake.lock", |_| Ok(ResolvedPackages::new())).await })
///     }
/// }
///
/// deps_core::lockfile_conformance! {
///     mod fake_lockfile_conformance;
///     build: FakeLockParser;
///     manifest: "fake.toml" => "name = \"test\"";
///     lockfiles: [
///         "fake.lock" => "locked = true",
///         "fake-alt.lock" => "locked: true\n",
///     ];
///     malformed: "\u{0}not a lockfile";
/// }
/// }
/// ```
#[macro_export]
macro_rules! lockfile_conformance {
    (
        mod $mod_name:ident;
        build: $build:expr;
        manifest: $manifest_name:literal => $manifest_content:literal;
        lockfiles: [ $( $lock_name:literal => $lock_content:literal ),+ $(,)? ];
        malformed: $malformed:literal $(;)?
    ) => {
        mod $mod_name {
            use super::*;

            const LOCKFILES: &[(&str, &str)] = &[ $( ($lock_name, $lock_content) ),+ ];

            // See `ecosystem_conformance!`'s doc for why each assertion is a plain `_impl`
            // fn called by a thin `#[test]`/`#[::tokio::test]` wrapper.

            fn locate_lockfile_not_found_impl() {
                $crate::conformance::assert_locate_lockfile_not_found(
                    &($build), $manifest_name, $manifest_content,
                );
            }
            #[test]
            fn locate_lockfile_not_found() {
                locate_lockfile_not_found_impl();
            }

            fn locate_lockfile_same_directory_impl() {
                for (name, content) in LOCKFILES {
                    $crate::conformance::assert_locate_lockfile_same_directory(
                        &($build), $manifest_name, $manifest_content, name, content,
                    );
                }
            }
            #[test]
            fn locate_lockfile_same_directory() {
                locate_lockfile_same_directory_impl();
            }

            fn is_lockfile_stale_not_modified_impl() {
                for (name, content) in LOCKFILES {
                    $crate::conformance::assert_lockfile_not_stale_when_unmodified(&($build), name, content);
                }
            }
            #[test]
            fn is_lockfile_stale_not_modified() {
                is_lockfile_stale_not_modified_impl();
            }

            fn is_lockfile_stale_modified_impl() {
                for (name, content) in LOCKFILES {
                    $crate::conformance::assert_lockfile_stale_when_old(&($build), name, content);
                }
            }
            #[test]
            fn is_lockfile_stale_modified() {
                is_lockfile_stale_modified_impl();
            }

            fn is_lockfile_stale_deleted_impl() {
                $crate::conformance::assert_lockfile_stale_when_missing(&($build));
            }
            #[test]
            fn is_lockfile_stale_deleted() {
                is_lockfile_stale_deleted_impl();
            }

            fn is_lockfile_stale_future_time_impl() {
                for (name, content) in LOCKFILES {
                    $crate::conformance::assert_lockfile_not_stale_in_future(&($build), name, content);
                }
            }
            #[test]
            fn is_lockfile_stale_future_time() {
                is_lockfile_stale_future_time_impl();
            }

            async fn parse_malformed_lockfile_does_not_panic_impl() {
                let (name, _) = LOCKFILES[0];
                $crate::conformance::assert_parse_malformed_lockfile_does_not_panic(
                    &($build), name, $malformed,
                )
                .await;
            }
            #[::tokio::test]
            async fn parse_malformed_lockfile_does_not_panic() {
                parse_malformed_lockfile_does_not_panic_impl().await;
            }
        }
    };
}

/// Generates conformance tests for the shared completion-prefix-length guard (#758 macro 4).
///
/// `complete` takes a `&dyn Registry` and the owned prefix `String`, returning a boxed,
/// lifetime-parameterized future of the completion items (`Pin<Box<dyn Future<Output =
/// Vec<CompletionItem>> + Send + '_>>`, matching [`assert_completion_guard`]'s bound — see
/// its doc for why a plain `Fut: Future` associated type does not work here) — call your
/// ecosystem's own guard-checking logic (e.g.
/// [`crate::completion::complete_package_names_generic`]) with the supplied registry
/// substituted for your ecosystem's real one, rather than routing through a live network
/// call: [`assert_completion_guard`] needs a registry it controls to tell "the guard
/// rejected this prefix" apart from "the network call failed/returned nothing" — an
/// always-offline or always-failing registry can't distinguish the two.
///
/// **Known limitation (#782 gap 3):** every real call site's `complete` closure re-invokes
/// [`crate::completion::complete_package_names_generic`] (or an equivalent) directly, inline
/// in the test — it does not call through the ecosystem's own production `generate_completions`
/// wiring. This macro therefore proves the shared generic guard itself behaves correctly, but
/// cannot detect a production bug where an ecosystem's real completion path fails to route
/// through that guard at all (wiring drift between the tested closure and the actual runtime
/// call graph is invisible here). No fix is applied for this: threading a real
/// `generate_completions`-shaped entry point through this macro generically, across ecosystems
/// with different `ParseResult`/position/content parameters, is not additive — it would need a
/// broader macro redesign, tracked separately rather than attempted here.
///
/// Must be invoked inside your own `#[cfg(test)] mod tests { ... }` — see
/// [`ecosystem_conformance!`]'s doc for why this macro does not emit its own `#[cfg(test)]`.
///
/// Wrapped in an explicit `mod example` — see [`ecosystem_conformance!`]'s doc for why.
///
/// # Examples
///
/// ```
/// mod example {
/// # use deps_core::Registry;
/// # use tower_lsp_server::ls_types::{CompletionItem, Range};
/// fn complete_fake<'a>(
///     registry: &'a dyn Registry,
///     prefix: String,
/// ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<CompletionItem>> + Send + 'a>> {
///     Box::pin(async move {
///         deps_core::completion::complete_package_names_generic(registry, &prefix, 20, Range::default()).await
///     })
/// }
///
/// deps_core::completion_guard_conformance! {
///     mod fake_completion_guard_conformance;
///     complete: |registry: &dyn Registry, prefix: String| complete_fake(registry, prefix);
/// }
/// }
/// ```
#[macro_export]
macro_rules! completion_guard_conformance {
    (
        mod $mod_name:ident;
        complete: $complete:expr $(;)?
    ) => {
        mod $mod_name {
            use super::*;

            // See `ecosystem_conformance!`'s doc for why this is a plain `_impl` fn called
            // by a thin `#[::tokio::test]` wrapper.
            async fn completion_guard_rejects_short_empty_and_over_length_prefixes_impl() {
                $crate::conformance::assert_completion_guard($complete).await;
            }
            #[::tokio::test]
            async fn completion_guard_rejects_short_empty_and_over_length_prefixes() {
                completion_guard_rejects_short_empty_and_over_length_prefixes_impl().await;
            }
        }
    };
}

/// Generates conformance tests for the shared JSON-nesting-depth cap (#758 macro 5).
///
/// `parse` is the ecosystem's own response parser; `wrap` embeds a nested-array fragment of
/// a given depth into a payload shape `parse` recognizes (e.g. as an `"extra"` field next to
/// the real, minimal response body).
///
/// **Known imprecision (#782 gap 5):** [`assert_json_nesting_at_max_depth_accepted`]/
/// [`assert_json_nesting_over_max_depth_rejected`] size the embedded *fragment* to exactly
/// [`crate::MAX_JSON_NESTING_DEPTH`] / `MAX_JSON_NESTING_DEPTH + 1` array levels — but `wrap`
/// typically nests that fragment inside at least one more JSON container (an object field,
/// as in the example below), so the *final* payload's absolute nesting depth as seen by
/// `parse` is one or more levels deeper than the fragment alone. This macro is therefore not
/// independently boundary-tight at the wrapped payload's true edge; it exercises "near the
/// cap", not "at exactly `MAX_JSON_NESTING_DEPTH`/`+ 1` in the payload `parse` receives". No
/// fix is applied: the cap itself is exact-boundary-tested directly (unwrapped) in
/// `deps-core/src/parser.rs`, so duplicating that precision here per-ecosystem would be
/// redundant rather than additive.
///
/// Must be invoked inside your own `#[cfg(test)] mod tests { ... }` — see
/// [`ecosystem_conformance!`]'s doc for why this macro does not emit its own `#[cfg(test)]`.
///
/// Wrapped in an explicit `mod example` — see [`ecosystem_conformance!`]'s doc for why.
///
/// # Examples
///
/// ```
/// mod example {
/// fn parse_fake(data: &[u8]) -> Result<(), std::io::Error> {
///     deps_core::check_json_nesting_depth(data, deps_core::MAX_JSON_NESTING_DEPTH)
///         .map_err(|depth| std::io::Error::other(format!("nesting depth {depth} exceeded")))
/// }
///
/// deps_core::json_depth_conformance! {
///     mod fake_json_depth_conformance;
///     parse: |bytes: &[u8]| parse_fake(bytes);
///     wrap: |nested: &str| format!(r#"{{"items": [], "extra": {nested}}}"#);
/// }
/// }
/// ```
#[macro_export]
macro_rules! json_depth_conformance {
    (
        mod $mod_name:ident;
        parse: $parse:expr;
        wrap: $wrap:expr $(;)?
    ) => {
        mod $mod_name {
            use super::*;

            // See `ecosystem_conformance!`'s doc for why each assertion is a plain `_impl`
            // fn called by a thin `#[test]` wrapper.

            fn json_nesting_at_max_depth_accepted_impl() {
                $crate::conformance::assert_json_nesting_at_max_depth_accepted($parse, $wrap);
            }
            #[test]
            fn json_nesting_at_max_depth_accepted() {
                json_nesting_at_max_depth_accepted_impl();
            }

            fn json_nesting_over_max_depth_rejected_impl() {
                $crate::conformance::assert_json_nesting_over_max_depth_rejected($parse, $wrap);
            }
            #[test]
            fn json_nesting_over_max_depth_rejected() {
                json_nesting_over_max_depth_rejected_impl();
            }
        }
    };
}

/// Generates a `select_latest_matching_not_default_none` conformance test for a
/// [`crate::Registry`] implementation (#758 macro 6, #784).
///
/// [`crate::Registry::select_latest_matching`] defaults to `None` so that test doubles
/// which never resolve a "latest" compile unchanged; a real registry reachable from the LSP
/// fetch path must override it. This macro proves that override actually fires for at least
/// one non-wildcard requirement, rather than silently inheriting the default.
///
/// **Known limitation** (mirrors [`ecosystem_conformance!`]'s and
/// [`completion_guard_conformance!`]'s doc on what a directly-constructed fixture cannot
/// prove): this constructs the registry type directly via `build:`/`build_arc:`, so it
/// proves that *type* overrides the method — not that the owning
/// [`Ecosystem::registry()`](crate::Ecosystem::registry) actually wires that type into the
/// LSP fetch path. Where that wiring is itself the risk (a registry type shared across
/// crates via a facade), invoke with `build_arc:` against the real `Ecosystem::registry()`
/// call instead of `build:` against the type directly.
///
/// Two mutually exclusive forms, chosen by which keyword introduces the fixture:
/// - `build:` — `$build` must be an **owned, concrete** registry type (uniform with every
///   other macro's `build:` arm). `&Arc<dyn Registry>` does not unsize-coerce to
///   `&dyn Registry`, so a `build:` expression that yields an `Arc` is a compile error, not
///   a runtime failure — use `build_arc:` instead for that shape.
/// - `build_arc:` — `$build` must yield `Arc<dyn Registry>` (typically
///   `SomeEcosystem::new(..).registry()`); the macro dereferences it before asserting. Use
///   this to prove the wiring path itself, e.g. when the registry type is defined in a
///   different crate than the ecosystem invoking this macro and a `build:` fixture would
///   only duplicate that other crate's own conformance test.
///
/// `versions` must be an explicit `Vec<Box<dyn Version>>` — the annotation is load-bearing:
/// it lets a bare `vec![Box::new(..), ..]` coerce each element without the call site
/// importing [`crate::Version`] itself.
///
/// Must be invoked inside your own `#[cfg(test)] mod tests { ... }` — see
/// [`ecosystem_conformance!`]'s doc for why this macro does not emit its own `#[cfg(test)]`,
/// and for why each assertion is a plain `_impl` fn called by a thin `#[test]` wrapper.
///
/// # Examples
///
/// `build:` against an owned, concrete registry. Wrapped in an explicit `mod example` — see
/// [`ecosystem_conformance!`]'s doc for why:
///
/// ```
/// mod example {
/// # use std::any::Any;
/// # struct FakeVersion { version: deps_core::ConcreteVersion }
/// # deps_core::impl_version!(FakeVersion {
/// #     version: version,
/// #     status: |_: &FakeVersion| deps_core::RemovalStatus::Available,
/// # });
/// # struct FakeRegistry;
/// # impl deps_core::Registry for FakeRegistry {
/// #     fn get_versions<'a>(&'a self, _name: &'a deps_core::PackageName)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Vec<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(vec![]) })
/// #     }
/// #     fn get_latest_matching<'a>(&'a self, _name: &'a deps_core::PackageName, _req: &'a deps_core::VersionReq)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Option<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(None) })
/// #     }
/// #     fn search<'a>(&'a self, _query: &'a str, _limit: usize)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(vec![]) })
/// #     }
/// #     fn select_latest_matching(&self, versions: &[Box<dyn deps_core::Version>], req: &deps_core::VersionReq) -> Option<usize> {
/// #         let req = req.as_str();
/// #         versions.iter().position(|v| v.version_string().as_str() == req)
/// #     }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// deps_core::registry_conformance! {
///     mod fake_registry_conformance;
///     build: FakeRegistry;
///     select_latest_matching: {
///         versions: vec![
///             Box::new(FakeVersion { version: "2.0.0".into() }),
///             Box::new(FakeVersion { version: "1.0.0".into() }),
///         ];
///         req: "1.0.0";
///         expected_index: 1;
///     };
/// }
/// }
/// ```
#[macro_export]
macro_rules! registry_conformance {
    (
        mod $mod_name:ident;
        build: $build:expr;
        select_latest_matching: {
            versions: $versions:expr;
            req: $req:literal;
            expected_index: $expected:literal;
        } $(;)?
    ) => {
        mod $mod_name {
            use super::*;

            fn select_latest_matching_not_default_none_impl() {
                let registry = $build;
                let versions: ::std::vec::Vec<::std::boxed::Box<dyn $crate::Version>> = $versions;
                $crate::conformance::assert_select_latest_matching_overridden(
                    &registry, &versions, $req, $expected,
                );
            }
            #[test]
            fn select_latest_matching_not_default_none() {
                select_latest_matching_not_default_none_impl();
            }
        }
    };
    (
        mod $mod_name:ident;
        build_arc: $build:expr;
        select_latest_matching: {
            versions: $versions:expr;
            req: $req:literal;
            expected_index: $expected:literal;
        } $(;)?
    ) => {
        mod $mod_name {
            use super::*;

            fn select_latest_matching_not_default_none_impl() {
                let registry: ::std::sync::Arc<dyn $crate::Registry> = $build;
                let versions: ::std::vec::Vec<::std::boxed::Box<dyn $crate::Version>> = $versions;
                $crate::conformance::assert_select_latest_matching_overridden(
                    &*registry, &versions, $req, $expected,
                );
            }
            #[test]
            fn select_latest_matching_not_default_none() {
                select_latest_matching_not_default_none_impl();
            }
        }
    };
}
