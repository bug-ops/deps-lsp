// No `.unwrap()` call in this module actually triggers `unwrap_used`; kept as a plain
// `#[allow]` rather than `#[expect]`.
#![allow(clippy::unwrap_used)]
#![expect(
    clippy::expect_used,
    reason = "fixture/helper infrastructure exercised only from test binaries (see the module \
              gate below): every .expect() here is on a fixture filesystem/temp-dir operation \
              that cannot fail in a single-threaded test"
)]

//! Shared conformance-test scaffolding for ecosystem crates (#758).
//!
//! Every ecosystem crate historically hand-copied the same family of tests — "does
//! `Ecosystem::id()` match", "does `package_url` produce this exact link", "does locating a
//! lock file work in the same directory", "does a too-short completion prefix return no
//! results", "does JSON nesting beyond the shared depth cap get rejected", "does a registry
//! actually override `select_latest_matching` instead of inheriting the trait's `None`
//! default" — with no structural link between the copies, so a fix or a new edge case applied
//! to one crate's copy routinely never reached the other thirteen. This module is the single
//! implementation of each family; most `#[macro_export]`ed macros below only generate
//! `#[test] fn` scaffolding around the plain `assert_*` functions here, so a fix to an
//! assertion fixes every ecosystem invoking it at once. The one exception is
//! [`complete_versions_test_shim!`], which generates a reusable *inherent method* (not a
//! test) — see its own doc for why.
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

#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::CompletionItem;

use crate::lockfile::LockFileProvider;
use crate::lsp_helpers::EcosystemFormatter;
use crate::{ConcreteVersion, Ecosystem, PackageName};

/// Adversarial payload for the `package_url` *display* sink, not the dot-segment fetch-URL
/// sink [`crate::test_util::ADVERSARIAL_URL_SEGMENTS`] guards.
///
/// The real sink is `lsp_helpers::hover`'s `# [{name}]({url})` markdown link. This
/// producer-side gate is the *primary* defense for that destination — every character
/// that can break out of a `[label](destination)` link is a hazard here, not just
/// newline/autolink/percent: `\n`, `<`, `>`, a bare `%` (must come back encoded as
/// `%25`), and the destination-closing/markup-reopening set `` ` ``, `(`, `)`, `[`, `]`
/// `escape_markdown`'s own doc names as this project's contract for this exact sink.
/// Also embeds a raw U+202E right-to-left override (display-spoofing) and is checked
/// generically for any other control character. Replaces 7 independently hand-copied
/// `test_package_url_encodes_newline_autolink_and_percent` tests (deps-maven, deps-pypi,
/// deps-npm, deps-go, deps-dart, deps-composer, deps-nuget) that only asserted the
/// narrower newline/autolink/percent subset.
///
/// `lsp_helpers::hover::push_header_hover_section` (#1259) additionally strips the
/// narrow bidi/invisible-character subset from the destination *after* `package_url`
/// builds it, as consumer-side defense-in-depth against a future `package_url`
/// implementation that regresses this gate — it does **not** cover the structural
/// breakout set (`(`, `)`, `[`, `]`, `` ` ``, `<`, `>`) this gate is the sole guard
/// for, so this gate must stay in force; it is not redundant with the hover-side filter.
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
    // Held per `fs_probe::snapshot_guard`'s doc: `locate_lockfile` transitively touches
    // fs_probe, and this macro-expanded helper runs in test binaries some ecosystems
    // (deps-cargo, deps-npm, deps-nuget) share with a diffing test.
    let _guard = crate::fs_probe::snapshot_guard();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = temp_dir.path().join(manifest_name);
    std::fs::write(&manifest_path, manifest_content).expect("write manifest");
    let manifest_uri = url::Url::from_file_path(&manifest_path).expect("valid file uri");

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
    // See the comment in `assert_locate_lockfile_not_found` on why this guard is needed here.
    let _guard = crate::fs_probe::snapshot_guard();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = temp_dir.path().join(manifest_name);
    let lock_path = temp_dir.path().join(lock_name);
    std::fs::write(&manifest_path, manifest_content).expect("write manifest");
    std::fs::write(&lock_path, lock_content).expect("write lockfile");
    let manifest_uri = url::Url::from_file_path(&manifest_path).expect("valid file uri");

    assert_eq!(
        parser.locate_lockfile(&manifest_uri),
        Some(lock_path),
        "expected {lock_name} to be located in the manifest's own directory"
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
    // See `assert_locate_lockfile_not_found` for why this guard is needed; async variant
    // since this helper runs under `#[tokio::test]`.
    let _guard = crate::fs_probe::snapshot_guard_async().await;
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
/// result, regardless of the query, and records whether it was ever called.
///
/// [`assert_completion_guard`] uses this to distinguish "the length guard rejected this
/// prefix" from "the registry search returned nothing" — a real (or offline-failing)
/// registry returns empty for *every* prefix, so an assertion built only on "does a
/// short/long prefix come back empty" cannot tell the guard firing apart from the network
/// call simply failing (#758 impl-critic M1). Because this registry always has a result to
/// give back, a valid-length prefix reaching it is guaranteed non-empty — so a guard that
/// wrongly rejects a valid prefix, or a `complete` closure not wired to the guard at all,
/// both become visible.
///
/// [`Self::search_was_called`] additionally lets [`assert_completion_guard`]'s
/// credential-shaped-prefix case assert the stronger claim issue #1206's remediation actually
/// asks for: not just "the returned items are empty" (which a redact-then-search-then-drop
/// implementation would also satisfy), but "`search` was never invoked at all" (#1206 M3).
#[cfg(feature = "lsp-responses")]
struct AlwaysHasResultsRegistry {
    search_called: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "lsp-responses")]
impl AlwaysHasResultsRegistry {
    fn new() -> Self {
        Self {
            search_called: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Whether [`crate::Registry::search_raw`] was invoked on this instance since [`Self::new`].
    fn search_was_called(&self) -> bool {
        self.search_called.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(feature = "lsp-responses")]
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
        _selection_context: &'a crate::SelectionContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = crate::Result<Option<Box<dyn crate::Version>>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move { Ok(None) })
    }

    fn search_raw<'a>(
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
        self.search_called
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            let metadata = crate::test_util::MockMetadata::new("conformance-probe", "1.0.0");
            Ok(vec![Box::new(metadata) as Box<dyn crate::Metadata>])
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Asserts a package-name completion function rejects a too-short, empty, too-long, or
/// credential-shaped prefix by returning no completions.
///
/// Mirrors [`crate::completion::complete_package_names_generic`]'s shared guards — and,
/// against `AlwaysHasResultsRegistry`, that a valid-length prefix actually returns that
/// registry's result, so the rejection above can't be explained away by "this registry never
/// returns anything" (#758 impl-critic M1). The credential-shaped case (#1206) reuses the same
/// always-has-results registry for the identical reason.
///
/// `complete` returns a boxed, lifetime-parameterized future rather than a plain associated
/// `Fut: Future`: the natural implementation borrows the `&dyn Registry` argument across the
/// `.await` (an `async fn(&dyn Registry, ...)` call), and a single fixed `Fut` type cannot
/// express "the future's lifetime depends on the reference passed at each call" — only a
/// `for<'a> Fn(&'a ..., ...) -> Pin<Box<dyn Future + 'a>>` bound can. A plain `Fn(..) -> Fut`
/// bound compiles here but fails at every real call site with "lifetime may not live long
/// enough" (verified: this was this function's first, broken signature).
#[cfg(feature = "lsp-responses")]
pub async fn assert_completion_guard<C>(complete: C)
where
    C: for<'a> Fn(
        &'a dyn crate::Registry,
        String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Vec<CompletionItem>> + Send + 'a>,
    >,
{
    let registry = AlwaysHasResultsRegistry::new();

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

    // #1206: a fresh registry, not the one reused above, so `search_was_called` below reflects only this call.
    let credential_registry = AlwaysHasResultsRegistry::new();
    let results = complete(
        &credential_registry,
        "user:hunter2@registry.example".to_string(),
    )
    .await;
    assert!(
        results.is_empty(),
        "a credential-shaped prefix must return no completions (issue #1206)"
    );
    // #1206 M3: proves `search` itself was never called, not just that its result was discarded.
    assert!(
        !credential_registry.search_was_called(),
        "a credential-shaped prefix must be rejected before ever calling `registry.search` \
         (issue #1206) — redacting the value and searching anyway, then dropping the result, \
         would still satisfy the empty-result assertion above but fail this one"
    );
}

/// Asserts that `eco.generate_completions`, at the version position of the first dependency
/// parsed from `content`, returns zero completion items (#1136).
///
/// Parses `content` (as `manifest_name`) through `eco.parse_manifest`, then fails loudly —
/// before ever calling `generate_completions` — if the fixture itself is not shaped
/// correctly: its first dependency must both (a) have a source
/// [`crate::lsp_helpers::SourcePolicy::can_resolve_source`] rejects, so the test is actually
/// exercising the #1136 gate rather than passing vacuously, and (b) carry a literal version
/// field ([`crate::ecosystem::Dependency::version_range`] must be `Some`), since
/// [`crate::completion::detect_completion_context`] only ever produces a `Version` context
/// at such a position in the first place — a fixture without one would make this assertion
/// trivially true without ever reaching the code path under test.
///
/// Returns the [`crate::completion::Completions`] so the caller can additionally assert on
/// side effects only it can observe (e.g. that a registry double was never queried) — see
/// `completion_source_gate_conformance!`'s doc (below, in this same module) for the intended
/// pattern.
///
/// # Panics
///
/// Panics (via `.expect`/`assert!`) if `content` fails to parse, produces no dependencies,
/// or the fixture-sanity checks above fail — all indicating a broken fixture, not a
/// `generate_completions` behavior under test.
#[cfg(feature = "lsp-responses")]
pub async fn assert_completion_source_gate(
    eco: &dyn Ecosystem,
    manifest_name: &str,
    content: &str,
) -> crate::completion::Completions {
    let uri = crate::test_util::test_uri(&format!("/test/{manifest_name}"));
    let parse_result = eco
        .parse_manifest(content, &uri)
        .await
        .expect("fixture manifest must parse");
    let dep = parse_result
        .dependencies()
        .into_iter()
        .next()
        .expect("fixture manifest must produce at least one dependency");

    assert!(
        !eco.formatter().can_resolve_source(&dep.source()),
        "fixture dependency's source ({:?}) must NOT be resolvable, or this test would pass \
         vacuously without ever exercising the #1136 gate",
        dep.source(),
    );
    let position = dep
        .version_range()
        .expect(
            "fixture dependency must have a literal version field — detect_completion_context \
             never produces a Version context without one, so the gate under test would never \
             even be reached",
        )
        .start
        .into();

    // impl-critic M2: without this, an ecosystem whose context detection regressed to
    // `CompletionContext::None` (e.g. a `manifest_name` extension the ecosystem's own
    // `detect_completion_context` no longer recognizes) would also yield zero items and zero
    // registry calls — passing this test vacuously without the `can_resolve_source` gate ever
    // being reached. Pinning the context first proves the call below actually exercises it.
    assert!(
        matches!(
            crate::completion::detect_completion_context(parse_result.as_ref(), position, content),
            crate::completion::CompletionContext::Version { .. }
        ),
        "fixture's dependency-version position must resolve to a Version completion context, \
         or this test cannot be exercising the #1136 gate at all"
    );

    eco.generate_completions(
        parse_result.as_ref(),
        position,
        content,
        crate::FreshnessSettings::default(),
    )
    .await
}

// ---------------------------------------------------------------------------------------
// Macro 4b: `assert_non_registry_source_yields_no_fetch`, wired into `ecosystem_conformance!`
// below — a classified non-`Registry` source must never be fetchable or trusted as
// public-registry content (#1202).
// ---------------------------------------------------------------------------------------

/// Asserts that parsing `content` (as `manifest_name`) through `eco.parse_manifest`
/// classifies at least one dependency as a non-[`crate::parser::DependencySource::Registry`]
/// source.
///
/// Also asserts that every gate #1136/#1203 built for exactly this case actually holds for
/// it: neither [`crate::lsp_helpers::SourcePolicy::can_resolve_source`] nor
/// [`crate::lsp_helpers::SourcePolicy::source_is_public_registry_content`] treats it as
/// fetchable/trustworthy public-registry content, and
/// [`crate::lsp_helpers::PackageRendering::suppress_package_url`] hides its hover link — the
/// same architecture [`assert_completion_source_gate`] drives end-to-end for the completion
/// path specifically, checked here directly against the gates themselves so it also covers
/// hover/diagnostics/OSV, which never go through completion at all.
///
/// An ecosystem that cannot yet supply such a fixture (its parser classifies nothing but
/// `Registry` — the exact #1202 gap this conformance check exists to close) must not call
/// this function at all, and must instead pass `ecosystem_conformance!`'s
/// `no_non_registry_fixture: "<reason>";` arm at its own invocation, rather than silently
/// having no coverage here — that macro enforces exactly one of the two arms is always
/// present, so omitting both is a compile error, not a silent gap.
///
/// # Panics
///
/// Panics if `content` fails to parse, or if no dependency classifies as a non-`Registry`
/// source — both indicating a broken fixture, not a genuine gate failure.
pub async fn assert_non_registry_source_yields_no_fetch(
    eco: &dyn Ecosystem,
    manifest_name: &str,
    content: &str,
) {
    let uri = crate::test_util::test_uri(&format!("/test/{manifest_name}"));
    let parse_result = eco
        .parse_manifest(content, &uri)
        .await
        .expect("fixture manifest must parse");
    let sources: Vec<crate::parser::DependencySource> = parse_result
        .dependencies()
        .into_iter()
        .map(crate::ecosystem::Dependency::source)
        .filter(|source| !matches!(source, crate::parser::DependencySource::Registry))
        .collect();
    assert!(
        !sources.is_empty(),
        "fixture manifest must classify at least one dependency as a non-Registry source — \
         otherwise this test cannot be exercising the #1202 classification gate at all",
    );

    // Critic S5: checks *every* non-Registry-classified dependency the fixture produced, not
    // just the first — a fixture with a `Require` entry left unclassified alongside a
    // correctly-classified `Replace` entry for the same module (deps-go's own C1 regression)
    // would otherwise pass vacuously despite the gate being inert for the unchecked entry.
    let formatter = eco.formatter();
    for source in &sources {
        assert!(
            !formatter.can_resolve_source(source),
            "non-registry source {source:?} must not be resolvable — resolving it would send \
             this dependency's name to the wrong (or a public) registry"
        );
        assert!(
            !formatter.source_is_public_registry_content(source),
            "non-registry source {source:?} must never be treated as public-registry content \
             for OSV/deps.dev/hover-trust-signal purposes"
        );
        assert!(
            formatter.suppress_package_url(source),
            "non-registry source {source:?} must suppress the public-registry hover link"
        );
    }
}

// Note (M9, critic): this used to be its own standalone `non_registry_source_conformance!`
// macro, invoked separately alongside `ecosystem_conformance!`. Removed (pre-1.0: no
// deprecation shim) once `ecosystem_conformance!`'s own mandatory `non_registry_fixture`/
// `no_non_registry_fixture` arm (below) made a separate opt-in invocation redundant — every
// ecosystem now gets this coverage (or a recorded, reviewable opt-out) automatically.

// ---------------------------------------------------------------------------------------
// Macro 4b: `unresolved_requirement_conformance!` — issue #1354: an unexpanded
// placeholder/interpolation in a version requirement must never be rewritten, whether or not
// `RequirementResolution::compile_requirement`/`requirement_already_resolves_to` happen to
// short-circuit it first.
// ---------------------------------------------------------------------------------------

/// Dependency name a `reachable: false` fixture must include, with an ordinary, resolvable
/// version, alongside its placeholder-bearing dependency/dependencies.
///
/// Lets [`assert_unresolved_requirements_never_rewritten`] tell "the parser correctly
/// degraded the placeholder" apart from "the parser is broken and returns nothing for
/// everything" — #1354 critic M3: without this canary, a parser regressing to always-empty
/// output would still satisfy "no dependency has `Some(version_requirement)`" vacuously (as
/// PyPI's already-empty-by-design `requirements.txt` fixture demonstrates it can).
pub const UNRESOLVED_REQUIREMENT_CONTROL_DEPENDENCY_NAME: &str = "known-good-control";

/// Asserts that every placeholder-bearing dependency in `content` is immune to
/// [`crate::edit::plan_vulnerability_fix`] rewriting it.
///
/// Checked for two out-of-range fix targets (`0.0.1`, one below any real release, and
/// `999.0.0`, one above) — and, independently of that gate, that
/// [`crate::edit::replacement_text`] itself is `None` when called directly with either
/// target, called with the declared requirement string as `current` — exactly as both
/// production callers do (`lsp_helpers::code_actions::build_vulnerability_fix_action`,
/// `deps-cli`'s `update::security`), never `dep.version_literal()` directly (though
/// `replacement_text` itself also consults `version_literal()`, see
/// [`crate::edit::requirement_is_placeholder_for`]).
///
/// The second, independent check is the one that actually matters (#1354/#1391 security
/// audit): a formatter can pass the first check by coincidence — e.g. because
/// `RequirementResolution::requirement_already_resolves_to` or `compile_requirement` happens
/// to answer `Some(true)`/decisively for the placeholder — while `replacement_text` would
/// still destructively rewrite the placeholder if its upstream gate
/// (`RequirementResolution::requirement_is_placeholder`) were ever wrong. Asserting
/// `replacement_text`'s own `None` result directly closes that gap.
///
/// `reachable` records whether this ecosystem's manifest parser preserves the placeholder as
/// `Some(version_requirement)` (`true`, e.g. GitHub Actions' `${{ env.V }}`) or degrades it to
/// `None` before it can ever reach the gate (`false`, e.g. NuGet's `$(Property)`, PyPI's
/// `${VAR}`, npm's `catalog:`) — asserted up front so a parser change that starts/stops
/// preserving the placeholder is caught here rather than silently making the fixture vacuous.
///
/// # Panics
///
/// Panics (via `assert!`/`assert_eq!`) on any dependency in `content` whose declared
/// requirement is rewritten by either path, or if `reachable` does not match what the parser
/// actually produced.
///
/// A `reachable: false` fixture must also include a dependency named
/// [`UNRESOLVED_REQUIREMENT_CONTROL_DEPENDENCY_NAME`] with an ordinary, resolvable version —
/// see that constant's doc for why (#1354 critic M3).
pub async fn assert_unresolved_requirements_never_rewritten(
    eco: &dyn Ecosystem,
    manifest_name: &str,
    content: &str,
    reachable: bool,
) {
    use crate::osv::{
        Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
    };

    let uri = crate::test_util::test_uri(&format!("/test/{manifest_name}"));
    let parse_result = eco
        .parse_manifest(content, &uri)
        .await
        .expect("fixture manifest must parse");
    let deps = parse_result.dependencies();
    let formatter = eco.formatter();
    if reachable {
        let has_requirement = deps.iter().any(|dep| dep.version_requirement().is_some());
        assert!(
            !deps.is_empty(),
            "fixture manifest must produce at least one dependency"
        );
        assert!(
            has_requirement,
            "reachable: true fixture must have at least one dependency with \
             Some(version_requirement) — otherwise this fixture never exercises the gate at all"
        );
    } else {
        let control_resolved = deps.iter().any(|dep| {
            dep.name().as_str() == UNRESOLVED_REQUIREMENT_CONTROL_DEPENDENCY_NAME
                && dep.version_requirement().is_some()
        });
        assert!(
            control_resolved,
            "reachable: false fixture must include a dependency named {:?} with an ordinary, \
             resolvable version requirement — without this canary, a parser that silently \
             returns zero dependencies for everything (not just the placeholder) would still \
             pass this test vacuously",
            UNRESOLVED_REQUIREMENT_CONTROL_DEPENDENCY_NAME
        );
        let unexpected_requirement = deps.iter().any(|dep| {
            dep.name().as_str() != UNRESOLVED_REQUIREMENT_CONTROL_DEPENDENCY_NAME
                && dep.version_requirement().is_some()
        });
        assert!(
            !unexpected_requirement,
            "reachable: false fixture must have every non-control dependency's \
             version_requirement degrade to None before reaching the gate — if the parser now \
             preserves it, switch this fixture to reachable: true"
        );
    }

    // Review finding (code-review, high effort): counts how many dependencies actually reach
    // the checks below (rather than being skipped by one of the three `continue`s above), so
    // the `reachable: true` assertion after the loop can catch a future fixture whose
    // placeholder-bearing dependency has `Some(version_requirement)` but a `None`
    // `version_range` or a non-public-registry source — both of which would silently skip
    // every dependency and make this test pass vacuously without ever calling
    // `plan_vulnerability_fix`/`edit::replacement_text` at all.
    let mut exercised_count = 0usize;

    for dep in &deps {
        if dep.name().as_str() == UNRESOLVED_REQUIREMENT_CONTROL_DEPENDENCY_NAME {
            continue;
        }
        let Some(req) = dep.version_requirement() else {
            continue;
        };
        if dep.version_range().is_none() {
            continue;
        }
        if !formatter.source_is_public_registry_content(&dep.source()) {
            continue;
        }
        exercised_count += 1;
        // #1370 critic S2: the central `requirement_is_placeholder` gate itself must classify
        // this fixture's requirement as a placeholder — without this, a formatter whose
        // override was accidentally dropped (or never added) would still pass every check
        // below via the legacy per-formatter guards alone, leaving the central gate
        // unenforced by this macro.
        assert!(
            formatter.requirement_is_placeholder(req),
            "reachable: true fixture dependency {:?} (requirement {:?}) must be classified a \
             placeholder by requirement_is_placeholder — the central #1370 gate",
            dep.name().as_str(),
            req.as_str()
        );
        // `req.as_str()`, not `dep.version_literal()` — both production callers
        // (`lsp_helpers::code_actions::build_vulnerability_fix_action` and
        // `deps-cli`'s `update::security`) pass the declared requirement string as `current`,
        // never the literal span. Using the literal here would hide exactly the bug class this
        // macro exists to catch: `current` (a synthesized comparator, e.g. Swift's
        // `">=\(v), <1.0.0"` for `from: "\(v)"`) can differ from `version_literal` (the raw
        // `\(v)` span the edit is actually spliced into) — `edit::requirement_is_placeholder_for`
        // checks both, but a formatter whose classification only ever saw `version_literal`
        // (never `current` itself) could still miss this exact case.
        let current = req.as_str();

        for target in ["0.0.1", "999.0.0"] {
            let native = formatter.osv_version_to_native(&OsvVersion::new(target));
            let advisory = std::sync::Arc::new(
                Advisory::new(
                    "GHSA-1354-conformance".to_string(),
                    "2024-01-01T00:00:00Z".to_string(),
                    VulnSeverity::High,
                )
                .expect("valid osv id")
                .with_fixed_versions(vec![OsvVersion::new(target)]),
            );
            let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
                .with_fix_target_status(UpgradeStatus::CandidateClean {
                    version: native.to_string(),
                });

            let planned = crate::edit::plan_vulnerability_fix(
                *dep,
                dep.version_range().expect("checked above"),
                current,
                &dv,
                formatter,
            );
            // #1391: tightened to `UnresolvedPlaceholder` alone — the assertion above already
            // proved `requirement_is_placeholder(req)` is `true` for this fixture, and
            // `plan_verified_fix`'s central gate (`deps_core::edit::requirement_is_placeholder_for`)
            // now fires unconditionally on that before either the `requirement_already_resolves_to`
            // short-circuit or a formatter-level no-op guard could ever be reached — those two
            // are no longer reachable alternate causes for this fixture shape.
            assert!(
                matches!(
                    planned,
                    Err(crate::edit::VulnFixSkip::UnresolvedPlaceholder)
                ),
                "plan_vulnerability_fix must skip an unresolved requirement {current:?} \
                 (dependency {:?}) targeting {target} via UnresolvedPlaceholder, got {planned:?}",
                dep.name().as_str()
            );

            // #1391: `edit::replacement_text` — the sole production rewrite path — must be
            // `None`, independent of the `plan_vulnerability_fix` gate above (the per-crate
            // `format_version_replacing`/`format_version_replacing_for` no-op guards this used
            // to assert against directly are gone; the placeholder gate now lives upstream of
            // both methods).
            assert_eq!(
                crate::edit::replacement_text(formatter, *dep, &native, current),
                None,
                "edit::replacement_text must be None for an unresolved requirement {current:?} \
                 (dependency {:?}) even when called directly, independent of the \
                 plan_vulnerability_fix gate (target {target})",
                dep.name().as_str()
            );
        }
    }

    if reachable {
        assert!(
            exercised_count > 0,
            "reachable: true fixture must have at least one dependency that reaches the \
             per-dependency check loop (Some(version_requirement) AND Some(version_range) AND \
             a public-registry source) — otherwise plan_vulnerability_fix/\
             edit::replacement_text are never actually invoked and this test passes vacuously"
        );
    }
}

/// A minimal, generic [`crate::Dependency`] used only to probe
/// [`crate::edit::replacement_text`] in [`assert_formatter_guarded_placeholders_never_rewritten`]
/// — every ecosystem's placeholder classification checks the requirement text itself before
/// ever consulting `dep` (downcast or otherwise), so a dependency carrying no real identity is
/// sufficient to exercise it.
struct PlaceholderProbeDependency {
    name: PackageName,
}

impl crate::Dependency for PlaceholderProbeDependency {
    fn name(&self) -> &PackageName {
        &self.name
    }

    fn name_range(&self) -> crate::position::Range {
        crate::position::Range::default()
    }

    fn version_requirement(&self) -> Option<&crate::VersionReq> {
        None
    }

    fn version_range(&self) -> Option<crate::position::Range> {
        None
    }

    fn source(&self) -> crate::parser::DependencySource {
        crate::parser::DependencySource::Registry
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Generic external-templating placeholder forms every ecosystem must recognize (#1391).
///
/// One example each of the shared
/// [`requirement_contains_template_placeholder`](crate::lsp_helpers::requirement_contains_template_placeholder)
/// detector's `{{ }}`, `<%= %>`, `@VAR@`, `%VAR%`, `${VAR}`, `$VAR`, and `$(VAR)` forms
/// (plus `$(MOD-VERSION)`, the hyphenated `$(...)` grammar spec 070/#1421 added), its `{% %}`
/// Jinja-tag form, and a version string with an *embedded* (not whole-value) placeholder —
/// recognized regardless of what native placeholder syntax (if any) an ecosystem also has.
///
/// `test_generic_template_placeholders_fixture_matches_detector` (in `lsp_helpers::mod`'s own
/// test module) guards this list against drifting out of sync with the detector it exists to
/// exercise.
pub const GENERIC_TEMPLATE_PLACEHOLDERS: &[&str] = &[
    "{{ version }}",
    "<%= version %>",
    "@PACKAGE_VERSION@",
    "%VERSION%",
    "${VERSION}",
    "$VERSION",
    "$(VERSION)",
    "$(MOD-VERSION)",
    "{% if x %}",
    "1.0.0-$BUILD",
];

/// Asserts every entry of [`GENERIC_TEMPLATE_PLACEHOLDERS`] is recognized and never rewritten.
///
/// Per entry: classified a placeholder, never reported as an unsatisfiable requirement, and
/// never produces a replacement via [`crate::edit::replacement_text`].
///
/// The mandatory, non-opt-out conformance gate #1391 introduces. Called unconditionally from
/// every `formatter_conformance!` invocation (per-crate) and from `deps-engine`'s
/// universal-invariants loop over every *registered* ecosystem (the two-layer split
/// [`assert_package_url_hostile_input_safe`] precedents, #782). This catches a
/// `requirement_is_placeholder` override that replaced the shared detector instead of composing
/// with it (`shared || native`), with no per-crate opt-in and no gap for a future 15th
/// ecosystem.
///
/// No exemption parameter is offered: every real ecosystem in this workspace passes this
/// unconditionally (verified per-form when each crate's `requirement_is_placeholder` was
/// composed for #1391). Add one only if a genuine future ecosystem proves structurally unable
/// to, with a reason string recorded alongside it.
///
/// `context` names the caller for a failure message (mirrors
/// [`assert_package_url_hostile_input_safe`]'s own `context` parameter).
///
/// # Panics
///
/// Panics (via `assert!`/`assert_eq!`) if any entry of [`GENERIC_TEMPLATE_PLACEHOLDERS`] is
/// not classified [`crate::lsp_helpers::RequirementResolution::requirement_is_placeholder`],
/// is reported unsatisfiable by [`crate::lsp_helpers::requirement_is_unsatisfiable`], or
/// produces `Some(_)` from [`crate::edit::replacement_text`].
pub fn assert_generic_template_placeholders_guarded(
    formatter: &dyn EcosystemFormatter,
    context: &str,
) {
    let probe = PlaceholderProbeDependency {
        name: PackageName::new("generic-template-placeholder-probe"),
    };
    let available = [ConcreteVersion::new("1.0.0")];
    for &placeholder in GENERIC_TEMPLATE_PLACEHOLDERS {
        let req = crate::VersionReq::new(placeholder);
        assert!(
            formatter.requirement_is_placeholder(&req),
            "{context}: {placeholder:?} must be classified as a placeholder by \
             requirement_is_placeholder"
        );
        assert!(
            !crate::lsp_helpers::requirement_is_unsatisfiable(formatter, &req, &available),
            "{context}: {placeholder:?} must never be reported as an unsatisfiable requirement"
        );
        assert_eq!(
            crate::edit::replacement_text(
                formatter,
                &probe,
                &ConcreteVersion::new("9.9.9"),
                placeholder,
            ),
            None,
            "{context}: edit::replacement_text must be None for placeholder {placeholder:?}"
        );
    }
}

/// Asserts that each of `placeholders` is recognized as an unresolved placeholder directly
/// against `formatter` — no parser or source-policy gating involved.
///
/// The `formatter_guarded` counterpart to [`assert_unresolved_requirements_never_rewritten`],
/// for an ecosystem whose parser/source-policy shape makes neither the `reachable: true` nor
/// `reachable: false` fixture form of that function constructible (#1372, `deps-gitlab-ci`:
/// every dependency is a non-`Registry` source, so `source_is_public_registry_content` is
/// always `false`, and its coordinate-naming grammar rejects
/// [`UNRESOLVED_REQUIREMENT_CONTROL_DEPENDENCY_NAME`] outright). Checked directly against the
/// [`crate::lsp_helpers::RequirementResolution`] methods instead of routing through a parsed
/// manifest and [`crate::edit::plan_vulnerability_fix`].
///
/// Rewrite-safety is checked via [`crate::edit::replacement_text`] (#1391: the sole
/// production rewrite path), mirroring [`assert_unresolved_requirements_never_rewritten`] —
/// every real central edit-planning call site (`plan_verified_fix`,
/// `build_unsatisfiable_fix_action`, the REFACTOR loop) calls it, so a single check here
/// covers every one of them.
///
/// The unsatisfiable-diagnostic check goes through
/// [`crate::lsp_helpers::requirement_is_unsatisfiable`] rather than asserting
/// `compile_requirement(..).is_none()` directly: an ecosystem's `compile_requirement` may
/// legitimately compile a placeholder into an always-satisfied matcher (`GradleFormatter`
/// does, for `$var`) rather than returning `None` — `requirement_is_unsatisfiable` is the
/// actual diagnostic-facing question this exists to protect, and it short-circuits via
/// `requirement_is_unresolved`/`requirement_is_placeholder` before ever reaching
/// `compile_requirement`, so it is `false` either way a formatter chooses to implement the
/// undecidable case.
///
/// `non_placeholders` is the negative control (#1370 critic M2): requirement strings that
/// look superficially similar to `placeholders` but must NOT be classified as one — e.g. a
/// SHA or an ordinary branch/tag name for an ecosystem whose placeholder grammar could
/// otherwise be conflated with its concrete-but-undecidable-ref grammar. Pass an empty slice
/// if the ecosystem has no such adjacent shape worth pinning.
///
/// # Panics
///
/// Panics (via `assert!`) if any `placeholders` entry is not classified
/// [`crate::lsp_helpers::RequirementResolution::requirement_is_placeholder`], is reported
/// unsatisfiable by [`crate::lsp_helpers::requirement_is_unsatisfiable`], or is rewritten by
/// [`crate::edit::replacement_text`]; or if any `non_placeholders` entry IS classified a
/// placeholder.
pub fn assert_formatter_guarded_placeholders_never_rewritten(
    formatter: &dyn EcosystemFormatter,
    placeholders: &[&str],
    non_placeholders: &[&str],
) {
    let probe = PlaceholderProbeDependency {
        name: PackageName::new("placeholder-probe"),
    };
    let available = [ConcreteVersion::new("1.0.0")];
    for &placeholder in placeholders {
        let req = crate::VersionReq::new(placeholder);
        assert!(
            formatter.requirement_is_placeholder(&req),
            "{placeholder:?} must be classified as a placeholder by requirement_is_placeholder"
        );
        assert!(
            !crate::lsp_helpers::requirement_is_unsatisfiable(formatter, &req, &available),
            "{placeholder:?} must never be reported as an unsatisfiable requirement"
        );
        assert_eq!(
            crate::edit::replacement_text(
                formatter,
                &probe,
                &ConcreteVersion::new("9.9.9"),
                placeholder,
            ),
            None,
            "edit::replacement_text must be None for placeholder {placeholder:?}"
        );
    }
    for &non_placeholder in non_placeholders {
        assert!(
            !formatter.requirement_is_placeholder(&crate::VersionReq::new(non_placeholder)),
            "{non_placeholder:?} must NOT be classified as a placeholder by \
             requirement_is_placeholder — negative control"
        );
    }
}

/// Generates conformance tests asserting an ecosystem never rewrites an unexpanded
/// placeholder/interpolation in a version requirement (issue #1354).
///
/// Four mutually exclusive forms:
/// - `reachable: true; fixture: "name" => "content";` — the parser preserves the placeholder
///   as `Some(version_requirement)`, so it reaches [`crate::edit::plan_vulnerability_fix`] and
///   [`crate::edit::replacement_text`] directly (e.g. GitHub Actions'
///   `${{ env.V }}`, Bundler's `"~> #{V}"`, Swift's `.package(url:, from: "\(v)")`).
/// - `reachable: false; fixture: "name" => "content";` — the parser degrades the placeholder
///   to `None` before either function is ever reached (e.g. NuGet's `$(Property)`, PyPI's
///   `${VAR}`, npm's `catalog:`); the fixture still exercises
///   [`assert_unresolved_requirements_never_rewritten`]'s degradation check. Must also declare
///   a dependency named
///   [`UNRESOLVED_REQUIREMENT_CONTROL_DEPENDENCY_NAME`] with an ordinary, resolvable version —
///   see that constant's doc for why (#1354 critic M3).
/// - `formatter_guarded: <expr>; placeholders: ["p1", "p2", ...]; non_placeholders: [...];` —
///   asserts directly against the formatter (see
///   [`assert_formatter_guarded_placeholders_never_rewritten`]), for an ecosystem whose
///   parser/source-policy shape makes neither `reachable` form constructible (#1372).
///   `non_placeholders` (may be empty, `[]`) is the negative control.
/// - `no_placeholder_syntax: "<reason>";` — an exhaustiveness marker (no tests emitted) for an
///   ecosystem whose version-requirement grammar has no placeholder/variable syntax at all.
///
/// See [`assert_unresolved_requirements_never_rewritten`] for what each `reachable` generated
/// test actually asserts.
///
/// # Examples
///
/// ```
/// deps_core::unresolved_requirement_conformance! {
///     mod example_no_placeholder_syntax;
///     no_placeholder_syntax: "doctest fixture — this ecosystem's grammar has no placeholder \
///                             syntax to demonstrate";
/// }
/// ```
#[macro_export]
macro_rules! unresolved_requirement_conformance {
    (
        mod $mod_name:ident;
        build: $build:expr;
        reachable: true;
        fixture: $file:literal => $content:literal;
    ) => {
        mod $mod_name {
            use super::*;

            async fn unresolved_requirement_never_rewritten_impl() {
                $crate::conformance::assert_unresolved_requirements_never_rewritten(
                    &($build),
                    $file,
                    $content,
                    true,
                )
                .await;
            }

            #[::tokio::test]
            async fn unresolved_requirement_never_rewritten() {
                unresolved_requirement_never_rewritten_impl().await;
            }
        }
    };
    (
        mod $mod_name:ident;
        build: $build:expr;
        reachable: false;
        fixture: $file:literal => $content:literal;
    ) => {
        mod $mod_name {
            use super::*;

            async fn unresolved_requirement_never_rewritten_impl() {
                $crate::conformance::assert_unresolved_requirements_never_rewritten(
                    &($build),
                    $file,
                    $content,
                    false,
                )
                .await;
            }

            #[::tokio::test]
            async fn unresolved_requirement_never_rewritten() {
                unresolved_requirement_never_rewritten_impl().await;
            }
        }
    };
    (
        mod $mod_name:ident;
        formatter_guarded: $build:expr;
        placeholders: [$($placeholder:literal),+ $(,)?];
        non_placeholders: [$($non_placeholder:literal),* $(,)?];
    ) => {
        mod $mod_name {
            use super::*;

            #[test]
            fn unresolved_requirement_never_rewritten() {
                $crate::conformance::assert_formatter_guarded_placeholders_never_rewritten(
                    &($build),
                    &[$($placeholder),+],
                    &[$($non_placeholder),*],
                );
            }
        }
    };
    (
        mod $mod_name:ident;
        no_placeholder_syntax: $reason:literal;
    ) => {
        #[allow(dead_code)]
        mod $mod_name {
            const _: &str = $reason;
        }
    };
    // A friendly compile-time error for any invocation matching none of the four arms above
    // (missing/misspelled field, wrong order, wrong literal type) — mirrors
    // `ecosystem_conformance!`'s own fallback arm just below, rather than leaving the caller
    // with `macro_rules!`'s generic "no rules expected this token" message.
    (
        mod $mod_name:ident;
        $($rest:tt)*
    ) => {
        compile_error!(
            "unresolved_requirement_conformance!: expected one of `build: <expr>; reachable: \
             true; fixture: \"name\" => \"content\";`, `build: <expr>; reachable: false; \
             fixture: \"name\" => \"content\";`, `formatter_guarded: <expr>; placeholders: \
             [\"p1\", \"p2\", ...]; non_placeholders: [...];`, or `no_placeholder_syntax: \
             \"<reason>\";` after `mod <name>;`"
        );
    };
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
        registry.select_latest_matching(versions, &req, &crate::SelectionContext::none()),
        Some(expected_index),
        "select_latest_matching({req:?}) index mismatch"
    );
}

/// Poison trait for [`registry_conformance!`]'s `ty:` form (#834 critic S5).
///
/// A blanket impl providing the same 4 method names as a no-op on every type. Without
/// this, `<$ty>::get_versions` (etc.) resolves through *any* in-scope trait providing that
/// name just as happily as through a true inherent method — so if a future contributor
/// added a module-level `use deps_core::Registry;` to an ecosystem crate's `registry.rs`
/// (today every such `use` in this workspace is function-local, so it doesn't leak into
/// the macro's generated module via its `use super::*;`), the `ty:` check would keep
/// compiling even after the crate's actual inherent method was renamed or deleted —
/// exactly the drift #834 exists to catch, becoming silent instead of loud.
///
/// With this trait `use`d into the generated module, a name reachable *only* via a trait
/// (this one, or `Registry`, or both) is ambiguous — multiple applicable trait
/// items, `error[E0034]` — while a genuine inherent method still resolves unambiguously,
/// since inherent methods always take priority over trait methods in Rust's method
/// resolution regardless of how many trait candidates are also in scope. Never call these
/// methods; `#[doc(hidden)]` since this exists purely for the macro's own use.
#[doc(hidden)]
pub trait NotInherent {
    /// Poison stand-in for `get_versions`. See the trait's own doc.
    fn get_versions(&self) {}
    /// Poison stand-in for `get_versions_with`. See the trait's own doc.
    fn get_versions_with(&self) {}
    /// Poison stand-in for `get_latest_matching`. See the trait's own doc.
    fn get_latest_matching(&self) {}
    /// Poison stand-in for `search`. See the trait's own doc.
    fn search(&self) {}
}

impl<T: ?Sized> NotInherent for T {}

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
/// #     fn get_latest_matching<'a>(&'a self, _name: &'a deps_core::PackageName, _req: &'a deps_core::VersionReq, _selection_context: &'a deps_core::SelectionContext)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Option<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(None) })
/// #     }
/// #     fn search_raw<'a>(&'a self, _query: &'a str, _limit: usize)
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
/// #     fn parse_manifest<'a>(&'a self, _content: &'a str, _uri: &'a url::Url)
/// #         -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn deps_core::ParseResult>>> {
/// #         unimplemented!()
/// #     }
/// #     fn complete_version<'a>(&'a self, _request: deps_core::completion::CompletionRequest<'a>, _package_name: deps_core::PackageName, _prefix: String)
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
///     no_non_registry_fixture: "doctest fixture — no real classification behavior to demonstrate";
/// }
/// }
/// ```
#[macro_export]
macro_rules! ecosystem_conformance {
    // Rejects at compile time (#782 cleanup 1) an ecosystem listing lock file names while
    // declaring no lock file support. Tried first since `macro_rules!` matches in order;
    // every other invocation falls through to the real arm below.
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
    // Critic S5 (#1202 part 2): `non_registry_fixture`/`no_non_registry_fixture` are a
    // mandatory *pair* of arms, exactly one of which must be present — mirroring the
    // `lockfile_filenames`/`no_lockfile_support` pattern above, but non-optional, so a
    // 15th ecosystem crate cannot add `ecosystem_conformance!` without an invocation that
    // either supplies a real non-registry-source fixture or explicitly records, in a
    // reviewable string literal, why it cannot yet. Omitting both is not a third option:
    // neither this arm nor the one below it matches, and `macro_rules!` itself fails the
    // build with "no rules expected this token" — silently skipping this check is not
    // possible by construction.
    (
        mod $mod_name:ident;
        build: $build:expr;
        ty: $ty:ty;
        id: $id:expr;
        display_name: $display_name:expr;
        manifest_filenames: $manifest_filenames:expr;
        $(lockfile_filenames: $lockfile_filenames:expr;)?
        $(no_lockfile_support: $no_lockfile_support:literal;)?
        non_registry_fixture: $nrf_name:literal => $nrf_content:literal;
    ) => {
        $crate::ecosystem_conformance_base! {
            mod $mod_name;
            build: $build;
            ty: $ty;
            id: $id;
            display_name: $display_name;
            manifest_filenames: $manifest_filenames;
            $(lockfile_filenames: $lockfile_filenames;)?
            $(no_lockfile_support: $no_lockfile_support;)?
            extra: {
                async fn ecosystem_non_registry_source_yields_no_fetch_impl() {
                    $crate::conformance::assert_non_registry_source_yields_no_fetch(
                        &($build),
                        $nrf_name,
                        $nrf_content,
                    )
                    .await;
                }
                #[::tokio::test]
                async fn ecosystem_non_registry_source_yields_no_fetch() {
                    ecosystem_non_registry_source_yields_no_fetch_impl().await;
                }
            }
        }
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
        no_non_registry_fixture: $nrf_reason:literal;
    ) => {
        // `$nrf_reason` is deliberately unused beyond being required to be a string literal
        // at this call site — its only job is to force a reviewable, human-written
        // justification into the source next to the opt-out, not to be asserted on.
        const _: &str = $nrf_reason;
        $crate::ecosystem_conformance_base! {
            mod $mod_name;
            build: $build;
            ty: $ty;
            id: $id;
            display_name: $display_name;
            manifest_filenames: $manifest_filenames;
            $(lockfile_filenames: $lockfile_filenames;)?
            $(no_lockfile_support: $no_lockfile_support;)?
            extra: {}
        }
    };
    // M11 (critic): a friendly compile-time error for the "neither arm above matched"
    // case — omitting both `non_registry_fixture` and `no_non_registry_fixture` entirely
    // falls through every other arm (each requires one or the other) to this one, which
    // matches the same prefix fields and nothing else. Without this arm the same mistake
    // would still fail to compile, but with `macro_rules!`'s own generic (and much less
    // helpful) "no rules expected this token" message instead.
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
        compile_error!(
            "ecosystem_conformance!: missing a mandatory `non_registry_fixture:` or \
             `no_non_registry_fixture:` arm (#1202) — supply either a real non-registry-source \
             manifest fixture (`non_registry_fixture: \"name\" => \"content\";`) or a \
             reviewable reason this ecosystem cannot yet supply one \
             (`no_non_registry_fixture: \"reason\";`)"
        );
    };
}

/// Shared body [`ecosystem_conformance!`]'s two required-fixture-arm variants both expand
/// into — not part of this crate's public macro API (call [`ecosystem_conformance!`]
/// instead), but must be `#[macro_export]`ed like any other macro invoked from another
/// crate's expansion.
#[doc(hidden)]
#[macro_export]
macro_rules! ecosystem_conformance_base {
    (
        mod $mod_name:ident;
        build: $build:expr;
        ty: $ty:ty;
        id: $id:expr;
        display_name: $display_name:expr;
        manifest_filenames: $manifest_filenames:expr;
        $(lockfile_filenames: $lockfile_filenames:expr;)?
        $(no_lockfile_support: $no_lockfile_support:literal;)?
        extra: { $($extra:item)* }
    ) => {
        mod $mod_name {
            use super::*;

            // Each assertion lives in a plain `_impl` fn called by a thin `#[test]` wrapper:
            // a `#[test]`-attributed item's body is elided outside a `--test` build, so a
            // doctest's substituted `expr`/`ty` would never be type-checked there otherwise
            // (#758 impl-critic S1).

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
                // `$no_lockfile_support` must be literal `true`: `macro_rules` can only gate on
                // the arm's presence, not a captured literal's value, so a `const` `assert!`
                // rejects anything else at compile time in every profile (#782 critic M1).
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

            $($extra)*
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
/// Also unconditionally generates a generic-template-placeholder guard test (#1391), via
/// [`assert_generic_template_placeholders_guarded`] — the same "every invocation, no opt-in"
/// precedent as the hostile-input-safety check above.
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

            // Unconditional (#1391) — every ecosystem's `requirement_is_placeholder` must
            // recognize the generic external-templating placeholder forms, whether or not
            // this ecosystem also has native placeholder syntax of its own. See this macro's
            // doc for the same "no per-crate opt-in" precedent as the hostile-input check
            // above.
            fn formatter_generic_template_placeholders_guarded_impl() {
                $crate::conformance::assert_generic_template_placeholders_guarded(
                    &($build), stringify!($mod_name),
                );
            }
            #[test]
            fn formatter_generic_template_placeholders_guarded() {
                formatter_generic_template_placeholders_guarded_impl();
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
/// # use url::Url;
/// struct FakeLockParser;
/// impl LockFileProvider for FakeLockParser {
///     fn locate_lockfile(&self, manifest_uri: &Url) -> Option<PathBuf> {
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
#[cfg(feature = "lsp-responses")]
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
/// A third, unrelated form — `ty:` — takes only a type and asserts the canonical
/// **inherent** registry-client method names (#834: `get_versions`, `get_versions_with`,
/// `get_latest_matching`, `search`) exist on it, so a future rename or removal breaks this
/// crate's own `cargo check --tests` instead of silently reintroducing the pre-#834 naming
/// drift. The four names are hardcoded in the macro expansion, not caller-supplied — a
/// misnamed or missing method on `$ty` cannot be worked around by pointing the macro at a
/// different name, unlike a form that took the names as arguments would allow. Each is
/// referenced as a plain path (`<$ty>::get_versions`), never called — this needs no live
/// registry instance, no network request, and no knowledge of the method's argument shape
/// (which legitimately varies per ecosystem); it only proves the name resolves as a
/// callable item on `$ty`.
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
/// #     fn get_latest_matching<'a>(&'a self, _name: &'a deps_core::PackageName, _req: &'a deps_core::VersionReq, _selection_context: &'a deps_core::SelectionContext)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Option<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(None) })
/// #     }
/// #     fn search_raw<'a>(&'a self, _query: &'a str, _limit: usize)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(vec![]) })
/// #     }
/// #     fn select_latest_matching(&self, versions: &[Box<dyn deps_core::Version>], req: &deps_core::VersionReq, _selection_context: &deps_core::SelectionContext) -> Option<usize> {
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
///
/// `ty:` — the canonical inherent-method-set check. `FakeInherentRegistry` here has nothing
/// to do with [`crate::Registry`] at all; the macro only cares that these four method names
/// resolve on `$ty`, with any argument shape:
///
/// ```
/// mod example_ty {
/// # struct FakeInherentRegistry;
/// # impl FakeInherentRegistry {
/// #     async fn get_versions(&self, _name: &str) -> Vec<String> { vec![] }
/// #     async fn get_versions_with(&self, _name: &str, _fresh: bool) -> Vec<String> { vec![] }
/// #     async fn get_latest_matching(&self, _name: &str, _req: &str) -> Option<String> { None }
/// #     async fn search(&self, _query: &str, _limit: usize) -> Vec<String> { vec![] }
/// # }
/// deps_core::registry_conformance! {
///     mod fake_registry_api_conformance;
///     ty: FakeInherentRegistry;
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
    (
        mod $mod_name:ident;
        ty: $ty:ty;
    ) => {
        mod $mod_name {
            #[allow(unused_imports)]
            use super::*;
            #[allow(unused_imports)]
            use $crate::Registry as _;
            #[allow(unused_imports)]
            use $crate::conformance::NotInherent as _;

            /// Never called (see the `ty:` form's doc on [`registry_conformance!`]): each
            /// name is hardcoded here, not caller-supplied, so this actually pins the
            /// vocabulary — a caller cannot make it pass by pointing it at some other name.
            /// [`$crate::Registry`] **and** [`$crate::conformance::NotInherent`] must both
            /// be brought into scope here — ambiguity (`E0034`) only fires when at least
            /// two same-named trait candidates compete for a name that has no inherent
            /// winner. `NotInherent` alone is not enough: a name reachable through exactly
            /// one trait resolves to that trait's method with **no error at all**, so a
            /// `$ty` missing the inherent method would pass silently once `Registry`
            /// itself supplies `get_versions`/`get_versions_with`/`get_latest_matching`/
            /// `search` as its own default-or-overridden trait methods (#834 critic,
            /// rustc-verified: dropping this `use` was an earlier, broken version of this
            /// guard that always passed regardless of whether `$ty` had the inherent
            /// method).
            #[allow(dead_code)]
            fn canonical_registry_methods_exist() {
                let _ = <$ty>::get_versions;
                let _ = <$ty>::get_versions_with;
                let _ = <$ty>::get_latest_matching;
                let _ = <$ty>::search;
            }
        }
    };
}

/// Generates a conformance test asserting `Ecosystem::generate_completions` rejects a
/// non-registry-resolvable source.
///
/// #758-shaped macro, closing #1136's coverage gap: the original bug — the old
/// `complete_versions_generic`'s `DependencySource::Registry`-hardcoded wrapper skipping the
/// `can_resolve_source` gate entirely — was never caught because no test drove a real
/// ecosystem's `generate_completions` with a non-resolvable-source fixture; unit tests only
/// ever exercised the shared helper directly with an already-`DependencySource::Registry`
/// package name.
///
/// `build` must evaluate (as an `async` block) to `(impl Ecosystem, mockito::Mock, _server)`:
/// an ecosystem instance whose registry is pointed at the mock server, a handle to a mock
/// configured to fail its own expectation (typically `.expect(0)`) if actually queried, and
/// the server guard itself (e.g. `mockito::ServerGuard`) kept alive alongside it — dropping
/// the guard before the assertion below runs makes `mock.assert_async()` fail regardless of
/// whether the gate under test actually held, so `build` must return it rather than let it
/// drop at the end of its own block. The generated test calls `mock.assert_async().await`
/// after [`assert_completion_source_gate`] returns, so an ecosystem whose completion wiring
/// bypasses the gate and reaches the registry anyway fails loudly on the mock's own
/// expectation, not just on an empty-items assertion that a coincidental network/parse
/// failure could also produce.
///
/// `manifest` must parse to a first dependency that is both non-resolvable and literally
/// versioned — see [`assert_completion_source_gate`]'s fixture-sanity checks, which fail the
/// test explicitly (not vacuously) if either does not hold.
///
/// **Known gap**: not every ecosystem crate invokes this macro today — applied so far to
/// `deps-cargo`, `deps-bundler`, `deps-dart`, `deps-pypi`. The #1136 fix itself (the
/// `can_resolve_source` gate inside `complete_versions_generic_from`) applies uniformly to
/// all 14 ecosystem crates regardless, and is verified for every one of them at the shared
/// helper level by `crates/deps-core/src/completion.rs`'s own gate unit tests — this macro
/// additionally proves the fix end-to-end, through a real `generate_completions` call, only
/// where a fixture is actually constructible:
///
/// - `deps-composer`, `deps-maven`, `deps-gradle`, `deps-deno`: `Dependency::source()` is
///   structurally always `DependencySource::Registry` in their parsers — no non-registry
///   source exists to construct a fixture from.
/// - `deps-github-actions`: its only non-registry sources (`Path`/`Url`, for a local
///   composite action or a Docker image reference) never carry a `version_range`, so
///   `detect_completion_context` can never reach a `Version` context for them.
/// - `deps-swift`: `SwiftRegistry` has no test-mockable HTTP-base-URL constructor (its only
///   non-network-dependent tests are `#[ignore]`d), so a discriminating `build` cannot be
///   constructed without adding that test infrastructure first.
/// - `deps-npm`, `deps-nuget`: their non-registry source (an unresolved custom registry
///   alias) is only reachable through ancestor-config-file resolution (`.npmrc`/
///   `NuGet.Config`) tied to the manifest's real on-disk directory — incompatible with
///   [`assert_completion_source_gate`]'s synthetic, non-existent fixture URI. Both already
///   have dedicated hand-written tests proving this exact scenario at the ecosystem level
///   (e.g. `deps-npm`'s `test_complete_versions_custom_registry_source_offers_nothing`).
/// - `deps-go`: a fixture is possible in principle (`DependencySource::CustomRegistry` via a
///   blocked/private `GOPROXY` chain) but this crate already routed completion through the
///   gated `complete_versions_at_position` entry point before #1136 — not added here,
///   tracked as a follow-up rather than blocking this fix.
/// - `deps-gitlab-ci`: **not** already gated before this PR — its `complete_version` hook
///   calls `complete_versions_generic_from` directly (never `complete_versions_at_position`),
///   and this PR had to add the missing `formatter` argument to that exact call site
///   (`crates/deps-gitlab-ci/src/ecosystem.rs`) alongside the other 8 originally-reported
///   ungated crates. It is still excluded from this macro specifically because
///   `GitlabCiRegistry::get_versions_from` independently fails closed
///   (`Err(PackageNotFound)`) for anything but a *registered* `AlternateRegistry` route,
///   with no host to dial in the first place for `CustomRegistry` — so a mock-server
///   `.expect(0)` here could never distinguish "the `can_resolve_source` gate held" from
///   "the registry's own routing has no host to call regardless of the gate" (the exact
///   vacuity this macro's own `assert_completion_source_gate` guards against for every other
///   user). The #1136 gate is still real, verified defense-in-depth for this crate (proven at
///   the shared-helper level, and by `test_generate_completions_version_context_dispatches_by_dependency_source`'s
///   explicit `is_empty()` assertion at the ecosystem level) — just not independently provable
///   via this macro's network-mock technique.
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
/// # use std::any::Any;
/// # use std::sync::Arc;
/// # use deps_core::parser::DependencySource;
/// # use deps_core::position::{Position, Range};
/// # struct FakeRegistry;
/// # impl deps_core::Registry for FakeRegistry {
/// #     fn get_versions<'a>(&'a self, _name: &'a deps_core::PackageName)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Vec<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         panic!("must not be queried: the #1136 gate should reject this fixture's source first");
/// #     }
/// #     fn get_latest_matching<'a>(&'a self, _name: &'a deps_core::PackageName, _req: &'a deps_core::VersionReq, _selection_context: &'a deps_core::SelectionContext)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Option<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         panic!("must not be queried: the #1136 gate should reject this fixture's source first");
/// #     }
/// #     fn search_raw<'a>(&'a self, _query: &'a str, _limit: usize)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(vec![]) })
/// #     }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// # struct FakeDep { name: deps_core::PackageName }
/// # impl deps_core::ecosystem::Dependency for FakeDep {
/// #     fn name(&self) -> &deps_core::PackageName { &self.name }
/// #     fn name_range(&self) -> Range { Range::default() }
/// #     fn version_requirement(&self) -> Option<&deps_core::VersionReq> { None }
/// #     fn version_range(&self) -> Option<Range> {
/// #         Some(Range::new(Position::new(0, 0), Position::new(0, 3)))
/// #     }
/// #     fn source(&self) -> DependencySource { DependencySource::Path { path: "../local".into() } }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// # struct FakeParseResult { dep: FakeDep, uri: url::Url }
/// # impl deps_core::ParseResult for FakeParseResult {
/// #     fn dependencies(&self) -> Vec<&dyn deps_core::ecosystem::Dependency> { vec![&self.dep] }
/// #     fn workspace_root(&self) -> Option<&std::path::Path> { None }
/// #     fn uri(&self) -> &url::Url { &self.uri }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// # struct FakeFormatter;
/// # impl deps_core::lsp_helpers::PackageNaming for FakeFormatter {}
/// # impl deps_core::lsp_helpers::PackageRendering for FakeFormatter {
/// #     fn format_version_for_text_edit(&self, v: &deps_core::ConcreteVersion) -> String { v.as_str().to_string() }
/// #     fn package_url(&self, name: &deps_core::PackageName) -> String { format!("https://example.com/{}", name.as_str()) }
/// # }
/// # impl deps_core::lsp_helpers::RequirementResolution for FakeFormatter {}
/// # impl deps_core::lsp_helpers::DiagnosticMessages for FakeFormatter {}
/// # impl deps_core::lsp_helpers::DiagnosticPolicy for FakeFormatter {}
/// # impl deps_core::lsp_helpers::SourcePolicy for FakeFormatter {}
/// # impl deps_core::lsp_helpers::OsvNaming for FakeFormatter {}
/// # struct Fake { registry: Arc<FakeRegistry>, formatter: FakeFormatter }
/// # impl deps_core::ecosystem::private::Sealed for Fake {}
/// # impl deps_core::Ecosystem for Fake {
/// #     fn id(&self) -> &'static str { "fake" }
/// #     fn ecosystem_id(&self) -> deps_core::EcosystemId { deps_core::EcosystemId::Cargo }
/// #     fn display_name(&self) -> &'static str { "Fake" }
/// #     fn manifest_filenames(&self) -> &[&'static str] { &["fake.toml"] }
/// #     fn registry(&self) -> Arc<dyn deps_core::Registry> { self.registry.clone() }
/// #     fn formatter(&self) -> &dyn deps_core::lsp_helpers::EcosystemFormatter { &self.formatter }
/// #     fn parse_manifest<'a>(&'a self, _content: &'a str, uri: &'a url::Url)
/// #         -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn deps_core::ParseResult>>> {
/// #         let dep = FakeDep { name: deps_core::PackageName::new("private-pkg") };
/// #         let uri = uri.clone();
/// #         Box::pin(async move { Ok(Box::new(FakeParseResult { dep, uri }) as Box<dyn deps_core::ParseResult>) })
/// #     }
/// #     fn complete_version<'a>(&'a self, _request: deps_core::completion::CompletionRequest<'a>, _package_name: deps_core::PackageName, _prefix: String)
/// #         -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions> {
/// #         Box::pin(std::future::ready(deps_core::completion::Completions::default()))
/// #     }
/// #     fn completion_insert_text(&self, _metadata: &dyn deps_core::Metadata) -> Option<String> { None }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// deps_core::completion_source_gate_conformance! {
///     mod fake_completion_source_gate_conformance;
///     build: async {
///         let mut server = mockito::Server::new_async().await;
///         let mock = server
///             .mock("GET", mockito::Matcher::Any)
///             .expect(0)
///             .create_async()
///             .await;
///         let eco = Fake { registry: Arc::new(FakeRegistry), formatter: FakeFormatter };
///         (eco, mock, server)
///     };
///     manifest: "fake.toml" => "local = { path = \"../local\" }\n1.0.0";
/// }
/// }
/// ```
#[cfg(feature = "lsp-responses")]
#[macro_export]
macro_rules! completion_source_gate_conformance {
    (
        mod $mod_name:ident;
        build: $build:expr;
        manifest: $manifest_name:literal => $manifest_content:literal $(;)?
    ) => {
        mod $mod_name {
            use super::*;

            // See `ecosystem_conformance!`'s doc for why this is a plain `_impl` fn called
            // by a thin `#[::tokio::test]` wrapper.
            //
            // `_server` (a `mockito::ServerGuard`, or any RAII handle `build` returns) must
            // stay bound here, not be dropped inside `build`'s own async block: mockito's
            // hit-count bookkeeping that `mock.assert_async()` queries lives with the
            // server task, so dropping the guard before the assertion below runs makes
            // `assert_async()` fail with "could not retrieve enough information about the
            // remote mock" regardless of whether the gate under test actually held.
            async fn completion_source_gate_rejects_non_resolvable_source_impl() {
                let (eco, mock, _server) = { $build }.await;
                let result = $crate::conformance::assert_completion_source_gate(
                    &eco,
                    $manifest_name,
                    $manifest_content,
                )
                .await;
                mock.assert_async().await;
                assert!(
                    result.items.is_empty(),
                    "a dependency whose source is not version-resolvable must yield zero \
                     completions, got: {:?}",
                    result.items,
                );
                assert_eq!(
                    result.origin,
                    $crate::completion::CompletionOrigin::Version,
                    "the fixture's dependency-version position must stamp a Version origin"
                );
            }
            #[::tokio::test]
            async fn completion_source_gate_rejects_non_resolvable_source() {
                completion_source_gate_rejects_non_resolvable_source_impl().await;
            }
        }
    };
}

/// Asserts `operator_chars` includes every character in `required`.
///
/// **This is a change-detector, not independent parser verification** (#1137 critic S2):
/// `required` is not derived by actually driving the ecosystem's own constraint matcher —
/// it is a second, hand-written copy of the same operator set the caller believes
/// `operator_chars` needs, typically justified in `operator_chars`'s own doc comment by a
/// citation into that ecosystem's parser. This function only proves the two hand-written
/// copies still agree; it cannot catch a set that was wrong (or went stale) in *both*
/// places at once. Its value is forcing a second, separate line to update — and a second,
/// separate doc-comment justification to write — whenever either one changes, rather than
/// independently confirming either is correct.
///
/// [`crate::completion::complete_versions_generic_from`]'s
/// `prefix.trim_start_matches(operator_chars)` only strips characters `operator_chars`
/// lists; an operator the parser accepts but the array omits is left attached to the typed
/// prefix, so it never matches any real version string and completion silently falls back
/// to an unfiltered top-5 list instead of the intended prefix-filtered one — the drift class
/// that let deps-pypi's array go without `^` despite parsing Poetry's caret constraints, and
/// let deps-maven/deps-gradle/deps-nuget's arrays go empty despite all three parsing a
/// bracket-delimited range (#1137).
pub fn assert_operator_chars_cover(ecosystem: &str, operator_chars: &[char], required: &[char]) {
    let missing: Vec<char> = required
        .iter()
        .copied()
        .filter(|c| !operator_chars.contains(c))
        .collect();
    assert!(
        missing.is_empty(),
        "{ecosystem}: operator_chars {operator_chars:?} is missing {missing:?} — required \
         (hand-derived from this ecosystem's parser) lists these, but operator_chars omits \
         them: the two copies have drifted"
    );
}

/// Generates a regression test asserting an ecosystem's completion `operator_chars` array
/// is a superset of `required` (#1137).
///
/// The array is the one its `complete_versions_at_position`/`complete_versions_generic_from`
/// call site passes.
///
/// **Not independent parser verification** — see [`assert_operator_chars_cover`]'s doc for
/// what this macro does and does not prove. `required` must be an operator set you derived
/// by hand from that ecosystem's own parser (cite the specific function/module in a comment
/// next to `required`, mirroring `operator_chars`'s own doc comment), not a value you
/// intend to keep in sync with `operator_chars` by construction — the whole point is that
/// the two are written independently, so a future editor who narrows one without
/// reconsidering the other gets a failing test instead of silence.
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
/// deps_core::operator_chars_conformance! {
///     mod fake_operator_chars_conformance;
///     ecosystem: "fake";
///     operator_chars: &['^', '~', '=', '<', '>', '*'];
///     required: &['^', '~', '=', '<', '>', '*'];
/// }
/// }
/// ```
#[macro_export]
macro_rules! operator_chars_conformance {
    (
        mod $mod_name:ident;
        ecosystem: $ecosystem:literal;
        operator_chars: $operator_chars:expr;
        required: $required:expr $(;)?
    ) => {
        mod $mod_name {
            use super::*;

            // See `ecosystem_conformance!`'s doc for why this is a plain `_impl` fn called
            // by a thin `#[test]` wrapper.
            fn operator_chars_cover_parser_operators_impl() {
                $crate::conformance::assert_operator_chars_cover(
                    $ecosystem,
                    $operator_chars,
                    $required,
                );
            }
            #[test]
            fn operator_chars_cover_parser_operators() {
                operator_chars_cover_parser_operators_impl();
            }
        }
    };
}

/// Generates a test-only `complete_versions` inherent async method on `$ecosystem_ty`.
///
/// Signature: `(&self, parse_result, position, prefix, freshness) -> Vec<CompletionItem>`,
/// reproducing the pre-#1223 per-ecosystem private helper's call shape over
/// [`crate::Ecosystem::complete_version`]'s shared default implementation
/// (`self.registry()`/`self.formatter()`/`self.version_operator_chars()` +
/// [`crate::completion::complete_versions_at_position`]).
///
/// Every ecosystem crate migrated onto the shared `complete_version` default (#1223) had its
/// own hand-written `complete_versions` test helper with this exact signature, called from
/// its pre-existing version-completion tests. Generating it here instead of leaving multiple
/// hand-copies in sync keeps those tests' call sites unchanged while making sure they all
/// exercise the real, now-shared code path rather than a bespoke per-crate copy of it.
///
/// `PackageName::new("")` is a throwaway inside the generated body: the default
/// `complete_version` implementation never reads its `package_name` argument, deriving the
/// dependency from `parse_result` and cursor `position` instead (issue #593).
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
/// # use std::any::Any;
/// # use std::sync::Arc;
/// # struct FakeRegistry;
/// # impl deps_core::Registry for FakeRegistry {
/// #     fn get_versions<'a>(&'a self, _name: &'a deps_core::PackageName)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Vec<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(vec![]) })
/// #     }
/// #     fn get_latest_matching<'a>(&'a self, _name: &'a deps_core::PackageName, _req: &'a deps_core::VersionReq, _selection_context: &'a deps_core::SelectionContext)
/// #         -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::Result<Option<Box<dyn deps_core::Version>>>> + Send + 'a>> {
/// #         Box::pin(async move { Ok(None) })
/// #     }
/// #     fn search_raw<'a>(&'a self, _query: &'a str, _limit: usize)
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
/// #     fn parse_manifest<'a>(&'a self, _content: &'a str, _uri: &'a url::Url)
/// #         -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn deps_core::ParseResult>>> {
/// #         unimplemented!()
/// #     }
/// #     fn completion_insert_text(&self, _metadata: &dyn deps_core::Metadata) -> Option<String> { None }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// deps_core::complete_versions_test_shim!(Fake);
/// }
/// ```
#[macro_export]
macro_rules! complete_versions_test_shim {
    ($ecosystem_ty:ty) => {
        impl $ecosystem_ty {
            async fn complete_versions(
                &self,
                parse_result: &dyn $crate::ParseResult,
                position: tower_lsp_server::ls_types::Position,
                prefix: &str,
                freshness: $crate::FreshnessSettings,
            ) -> Vec<tower_lsp_server::ls_types::CompletionItem> {
                use $crate::Ecosystem as _;
                self.complete_version(
                    $crate::completion::CompletionRequest::new(parse_result, position, freshness),
                    $crate::PackageName::new(""),
                    prefix.to_string(),
                )
                .await
                .items
            }
        }
    };
}

// ---------------------------------------------------------------------------------------
// Macro 7: `debug_redaction_conformance!` — a manual `Debug` impl actually redacts a
// credential-shaped field instead of leaking it (CWE-532, #1222).
// ---------------------------------------------------------------------------------------

/// URL-shaped credential probe for [`crate::debug_redaction_conformance!`] — plant into a
/// `url`-typed field a manual `Debug` impl is expected to run through
/// [`crate::redact::RedactedUrl`].
pub const CREDENTIAL_PROBE_URL: &str = "https://deploy:hunter2@git.internal.corp/team/x.git";

/// Coordinate/key-shaped credential probe for [`crate::debug_redaction_conformance!`].
///
/// Plant into a name/path/key-typed field a manual `Debug` impl is expected to run through
/// [`crate::redact::redact_declaration_key`].
pub const CREDENTIAL_PROBE_KEY: &str = "org.example:deploy:hunter2@git.internal.corp";

/// The password half of both probe constants — must never appear in a redacted `Debug`
/// rendering.
pub const CREDENTIAL_PROBE_SECRET: &str = "hunter2";

/// The marker both [`crate::redact::RedactedUrl`] and
/// [`crate::redact::redact_declaration_key`] converge on for either probe constant —
/// the anti-vacuity signal [`assert_debug_redacts_credentials`] counts occurrences of.
const PROBE_MARKER: &str = "***@git.internal.corp";

/// Asserts `value`'s `Debug` rendering redacts every planted credential probe
/// ([`CREDENTIAL_PROBE_URL`]/[`CREDENTIAL_PROBE_KEY`]) instead of leaking it (CWE-532, #1222).
///
/// Three checks against `format!("{value:?}")`:
/// 1. does not contain [`CREDENTIAL_PROBE_SECRET`] (the password half);
/// 2. does not contain `"deploy:"` (the username half — a redactor that stripped only the
///    password would still fail this);
/// 3. `rendered.matches(PROBE_MARKER).count() >= planted_fields` — the anti-vacuity check.
///    Both redactors converge on the same `***@git.internal.corp` marker for both probe
///    constants, so one substring covers URL-shaped and key-shaped fields alike. Without this,
///    a caller that forgot to plant the probe, or an impl that silently dropped the field from
///    its `Debug`, would pass trivially on checks 1/2 alone.
///
/// # Panics
///
/// Panics (via `assert!`) if any of the three checks fails.
pub fn assert_debug_redacts_credentials<T: std::fmt::Debug>(
    value: &T,
    planted_fields: usize,
    context: &str,
) {
    let rendered = format!("{value:?}");
    assert!(
        !rendered.contains(CREDENTIAL_PROBE_SECRET),
        "{context}: Debug output leaked the planted credential's password half: {rendered}"
    );
    assert!(
        !rendered.contains("deploy:"),
        "{context}: Debug output leaked the planted credential's username half: {rendered}"
    );
    let matches = rendered.matches(PROBE_MARKER).count();
    assert!(
        matches >= planted_fields,
        "{context}: expected at least {planted_fields} redacted occurrence(s) of {PROBE_MARKER:?}, \
         found {matches} in: {rendered}"
    );
}

/// Generates a `#[test]` asserting `$build`'s `Debug` rendering redacts every planted
/// credential probe (CWE-532, #1222).
///
/// **Invocation contract — this is the load-bearing part.** `$build` must construct its value
/// via an *exhaustive* struct/enum literal — never `..Default::default()`, never `..base`. This
/// makes adding a new field to the type a *compile error* here — forcing whoever adds it to
/// explicitly name the new field in this literal (and so notice it), rather than silently
/// inheriting an unredacted default via `..Default::default()`/`..base`. This holds regardless
/// of whether the type is `#[non_exhaustive]` or constructed from outside its own crate
/// elsewhere — an exhaustive literal has no `..` to hide a field behind either way. It only
/// forces the field to be *named*, not correctly redacted — `$planted` must still match the
/// number of probes actually planted for [`assert_debug_redacts_credentials`]'s anti-vacuity
/// check to catch a field silently dropped from `Debug`.
///
/// Must be invoked inside your own `#[cfg(test)] mod tests { ... }` — like every other macro in
/// this module, this generates its own `mod $name { ... }` rather than a bare `#[test] fn`
/// (see [`ecosystem_conformance!`]'s doc for why a bare `#[test]`-attributed fn body would be
/// silently elided, and thus never actually type-checked, in a doctest).
///
/// # Examples
///
/// Wrapped in an explicit `mod example` — see [`ecosystem_conformance!`]'s doc for why.
///
/// ```
/// mod example {
/// struct Fake {
///     url: String,
/// }
///
/// impl std::fmt::Debug for Fake {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.debug_struct("Fake")
///             .field("url", &deps_core::redact::RedactedUrl::new(&self.url))
///             .finish()
///     }
/// }
///
/// deps_core::debug_redaction_conformance!(
///     fake_debug_redacts_credentials,
///     1,
///     Fake {
///         url: deps_core::conformance::CREDENTIAL_PROBE_URL.to_string(),
///     },
/// );
/// }
/// ```
#[macro_export]
macro_rules! debug_redaction_conformance {
    ($name:ident, $planted:expr, $build:expr $(,)?) => {
        mod $name {
            use super::*;

            // See `ecosystem_conformance!`'s doc for why this is a plain `_impl` fn called by
            // a thin `#[test]` wrapper.
            fn debug_redaction_conformance_impl() {
                $crate::conformance::assert_debug_redacts_credentials(
                    &($build),
                    $planted,
                    stringify!($name),
                );
            }
            #[test]
            fn debug_redaction_conformance() {
                debug_redaction_conformance_impl();
            }
        }
    };
}
