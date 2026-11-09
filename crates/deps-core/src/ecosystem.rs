use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

mod manifest;
pub mod typed;

#[cfg(any(test, feature = "test-util"))]
pub(crate) use manifest::EcosystemManifest;
pub use manifest::ParsedManifest;
#[cfg(feature = "lsp-responses")]
pub use typed::{HoverDecoration, HoverDecorator, code_actions, hover};
pub use typed::{TypedEcosystem, diagnostics};

use crate::{
    Registry,
    lsp_helpers::EcosystemFormatter,
    position::Range,
    registry::Metadata,
    selection::{InvalidStabilityOccurrence, SelectionContext},
};

/// Soft-sealing mechanism for [`Ecosystem`], shared by every ecosystem crate in this
/// workspace (`deps-cargo`, `deps-npm`, ...) — each implements [`private::Sealed`] for
/// its own ecosystem type.
///
/// Rust's privacy system has no "visible to this workspace, not beyond" level: `pub(crate)`
/// would restrict `Sealed` to `deps-core` alone, breaking every sibling ecosystem crate's
/// `impl Sealed for ...`, since each of those is a separate compilation unit. Making this
/// module `pub` is therefore required, not a mistake — but it means [`private::Sealed`] is
/// technically nameable, and implementable, from any crate that depends on `deps-core`, not
/// only from within this workspace. `#[doc(hidden)]` keeps it out of generated public docs to
/// avoid inviting that. There is no compiler-enforced wall against it: this is a documented
/// contract enforced by code review, not a hard guarantee, and [`Ecosystem`]'s default
/// methods may gain new required behavior without that counting as a breaking change for an
/// external implementor who ignored this notice.
#[doc(hidden)]
pub mod private {
    /// Marker trait every ecosystem crate in this workspace implements for its own
    /// ecosystem type, per [`super::private`]'s module doc.
    ///
    /// [`Ecosystem`](super::Ecosystem) requires `Self: Sealed`, which is how the
    /// trait stays extensible (new default methods can be added without
    /// breaking in-workspace implementors).
    pub trait Sealed {}
}

/// A boxed, type-erased future used throughout the [`Ecosystem`] trait's async methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Runs `ecosystem.parse_manifest(content, uri)` on the blocking-thread pool instead of the
/// calling tokio worker.
///
/// Every [`TypedEcosystem::parse`] implementation is synchronous work wrapped in an
/// immediately-ready `async move` block (verified: no implementation contains a real
/// `.await`). Driving that future to completion via [`tokio::runtime::Handle::block_on`]
/// from inside [`tokio::task::spawn_blocking`] moves the CPU-bound parse off the tokio
/// worker without changing the trait's async signature — mirrors
/// [`crate::lockfile::read_and_parse_lockfile`]'s `spawn_blocking` pattern for the
/// equivalent lock-file path (#723/#730). This closes #743: a large minified manifest
/// parsed synchronously on an LSP request's tokio worker would otherwise stall every other
/// request sharing that worker for the parse's full duration.
///
/// `content`/`uri` are cloned internally rather than moved+returned: the caller's own copy
/// must remain valid (to store into `DocumentState`) even if the blocking task panics, and a
/// panic here is already an anomalous condition, not a path worth optimizing a clone away
/// for. Manifest sizes are capped (10MB) and typically far smaller, so the clone's added
/// *time* cost is negligible next to the parse itself and the thread-pool hop. It does
/// briefly double transient *peak memory* (both the caller's and the cloned copy live at
/// once) on exactly the large-manifest path this function targets; a future `Arc<str>`
/// threaded through the caller would remove that duplication if it ever proves significant.
///
/// `Handle::block_on` called from inside a `spawn_blocking` closure is a documented,
/// supported tokio pattern (distinct from `Runtime::block_on`, which panics if called from
/// within a runtime). Almost every implementation's future never actually yields
/// (`Poll::Pending`), so `block_on` resolves on the first poll for those — negligible overhead
/// beyond the `spawn_blocking` thread-hop itself. **Correction (spec 076 round-1 critic L1):**
/// this is not universally true — Composer's `parse_manifest` genuinely awaits
/// (`LockFileCache::get_or_parse` → `tokio::fs::metadata`) when the manifest declares a bare
/// vcs/path/artifact repository and a `composer.lock` exists. `block_on` still resolves
/// correctly here since it runs inside `spawn_blocking` on a real tokio worker thread, but an
/// unoverridden [`TypedEcosystem::parse_sync`] default's `now_or_never()` cannot drive that
/// same await to completion — [`parse_manifest_now`] uses that method rather than
/// [`TypedEcosystem::parse`] directly for exactly this reason (issue #1570): Composer
/// overrides it instead of racing the await, see its own doc.
///
/// # Errors
///
/// Returns whatever [`TypedEcosystem::parse`] returns for a malformed manifest, or a
/// [`crate::error::DepsError::ParseError`] if the blocking task panics or is cancelled.
///
/// # Examples
///
/// ```no_run
/// use deps_core::Ecosystem;
/// use std::sync::Arc;
/// use url::Url;
///
/// # async fn example(ecosystem: Arc<dyn Ecosystem>, uri: Url) -> deps_core::error::Result<()> {
/// let parsed = deps_core::ecosystem::parse_manifest_blocking(&ecosystem, "content", &uri).await?;
/// println!("{} dependencies", parsed.dependencies().len());
/// # Ok(())
/// # }
/// ```
pub async fn parse_manifest_blocking(
    ecosystem: &Arc<dyn Ecosystem>,
    content: &str,
    uri: &url::Url,
) -> crate::error::Result<Box<dyn ParsedManifest>> {
    let ecosystem = Arc::clone(ecosystem);
    let owned_content = content.to_owned();
    let owned_uri = uri.clone();
    let handle = tokio::runtime::Handle::current();
    // Single chokepoint for #796: `parse_manifest` wraps every ecosystem's parse result in a
    // manifest that caps its dependencies, once, rather than each ecosystem crate's own parser
    // bounding its dependency count independently.
    tokio::task::spawn_blocking(move || {
        handle.block_on(ecosystem.parse_manifest(&owned_content, &owned_uri))
    })
    .await
    .map_err(|e| crate::error::DepsError::parse_error(format!("manifest at {uri:?}"), &e))?
}

/// Synchronous sibling of [`parse_manifest_blocking`], for a caller that cannot `.await`.
///
/// Spec 076 FR-024: the fallback-edit re-parse guard, evaluated inside `deps-cli`'s synchronous
/// planner. Drives [`TypedEcosystem::parse_sync`] instead of spawning onto the
/// blocking-thread pool; the returned manifest applies the SAME dependency cap
/// [`parse_manifest_blocking`] applies — a raw `now_or_never()` call site with no cap
/// would otherwise be a second, uncapped parse entry point (round-3 critic M2, #796).
///
/// Returns `None` when called outside a tokio runtime context, when
/// [`Ecosystem::parse_manifest_sync`] itself returns `None` (the default impl: the future does
/// not resolve on its first poll), or when the parse fails. Per [`Ecosystem::parse_manifest`]'s
/// documented invariant, almost every implementation resolves immediately via
/// [`Ecosystem::parse_manifest_sync`]'s default — Composer overrides that method instead of
/// racing a genuine await (bare vcs/path/artifact repository plus a `composer.lock`, see
/// [`parse_manifest_blocking`]'s doc and issue #1570) so this guard never depends on
/// `now_or_never()` scheduler timing for that case. Polling an unoverridden default's future
/// with no tokio runtime entered at all would otherwise panic ("there is no reactor running")
/// instead of returning `None` — this function checks for a current runtime handle first
/// specifically to keep the `None` contract a true fail-closed guarantee, not merely a
/// fail-closed guarantee "as long as a runtime happens to be active".
///
/// **Re-parse is not pure** (spec 076 round-4 critic M4): Cargo, Go, Deno, and npm's
/// `parse_manifest` register alternate indices or GOPROXY chains into shared context as a side
/// effect, and Cargo, NuGet, and Gradle perform synchronous disk reads for ancestor config
/// files. This is safe to call repeatedly only because registration is idempotent — keyed by
/// URL or chain key via `register_capped`/`register_capped_with_occupied` — so re-parsing the
/// same document twice (once for the original content, once for an edited scratch copy) never
/// duplicates a registration.
///
/// # Examples
///
/// ```no_run
/// use deps_core::Ecosystem;
/// use url::Url;
///
/// # fn example(ecosystem: &std::sync::Arc<dyn Ecosystem>, uri: Url) {
/// if let Some(parsed) = deps_core::ecosystem::parse_manifest_now(ecosystem, "content", &uri) {
///     println!("{} dependencies", parsed.dependencies().len());
/// }
/// # }
/// ```
pub fn parse_manifest_now(
    ecosystem: &Arc<dyn Ecosystem>,
    content: &str,
    uri: &url::Url,
) -> Option<Box<dyn ParsedManifest>> {
    // Fail closed instead of panicking when called outside a tokio runtime context (fix-cycle
    // security LOW-1): an unoverridden `parse_manifest_sync` default drives a real future via
    // `now_or_never()`, which panics ("there is no reactor running") if that future touches
    // tokio with no runtime entered — this check turns that into a documented `None`, never a
    // crash.
    tokio::runtime::Handle::try_current().ok()?;

    Arc::clone(ecosystem).parse_manifest_sync(content, uri)
}

/// Defines [`EcosystemId`] together with [`EcosystemId::ALL`], [`EcosystemId::id`] and its
/// [`std::str::FromStr`] impl from one variant list, so the four can never drift apart
/// (#758) — a 15th ecosystem is added in exactly this one place or the workspace does not
/// compile. `macro_rules!` is textual-order scoped, so this definition must precede its
/// invocation below.
macro_rules! ecosystem_ids {
    ( $( $(#[$vmeta:meta])* $variant:ident => $id:literal ),+ $(,)? ) => {
        /// Canonical, exhaustive identifier for every package ecosystem the workspace supports.
        ///
        /// [`EcosystemBase::id`] returns a `&'static str` for registry lookups and document
        /// storage, but any code that needs to *branch* on ecosystem identity should match on
        /// this enum instead of re-deriving its own partial match over that string: an
        /// unhandled variant here is a compile error, while an unhandled string is a silent
        /// runtime bug (see the fix for issue #118, where two call sites silently mishandled
        /// ecosystems missing from an incomplete string match).
        ///
        /// Deliberately **not** `#[non_exhaustive]`: adding a new ecosystem must force every
        /// exhaustive `match` on this type across the workspace to be updated at compile time.
        ///
        /// # Examples
        ///
        /// ```
        /// use deps_core::EcosystemId;
        ///
        /// let id: EcosystemId = "npm".parse().unwrap();
        /// assert_eq!(id, EcosystemId::Npm);
        /// assert_eq!(id.id(), "npm");
        /// assert_eq!(id.to_string(), "npm");
        ///
        /// assert!("unknown".parse::<EcosystemId>().is_err());
        /// ```
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum EcosystemId {
            $( $(#[$vmeta])* $variant, )+
        }

        impl EcosystemId {
            /// Every [`EcosystemId`] variant, in declaration order.
            ///
            /// Generated from the same list as [`Self::id`] and this type's
            /// [`std::str::FromStr`] impl, so none of the three can silently drift out of
            /// sync with the enum's variants (#758) — a forgotten 15th variant here is a
            /// missing-match compile error, not a silently incomplete set.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// Returns the canonical string identifier, matching [`EcosystemBase::id`] for the
            /// corresponding ecosystem implementation.
            #[must_use]
            pub const fn id(self) -> &'static str {
                match self {
                    $( Self::$variant => $id, )+
                }
            }
        }

        impl std::str::FromStr for EcosystemId {
            type Err = crate::error::DepsError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $( $id => Ok(Self::$variant), )+
                    _ => Err(crate::error::DepsError::UnsupportedEcosystem(s.to_string())),
                }
            }
        }
    };
}

ecosystem_ids! {
    /// Rust Cargo ecosystem (`Cargo.toml`).
    Cargo => "cargo",
    /// JavaScript/TypeScript npm ecosystem (`package.json`).
    Npm => "npm",
    /// Python PyPI ecosystem (`pyproject.toml`).
    Pypi => "pypi",
    /// Go modules ecosystem (`go.mod`).
    Go => "go",
    /// Ruby Bundler ecosystem (`Gemfile`).
    Bundler => "bundler",
    /// Dart/Flutter pub ecosystem (`pubspec.yaml`).
    Dart => "dart",
    /// Java/Kotlin Maven ecosystem (`pom.xml`).
    Maven => "maven",
    /// PHP Composer ecosystem (`composer.json`).
    Composer => "composer",
    /// Java/Kotlin Gradle ecosystem (`build.gradle`, `build.gradle.kts`, version catalogs).
    Gradle => "gradle",
    /// Swift Package Manager ecosystem (`Package.swift`).
    Swift => "swift",
    /// .NET NuGet ecosystem (`.csproj`/`.fsproj`/`.vbproj`, `Directory.Packages.props`, `packages.config`).
    NuGet => "nuget",
    /// Deno ecosystem (`deno.json`/`deno.jsonc`), mixing `jsr:` and `npm:` specifiers.
    Deno => "deno",
    /// GitHub Actions ecosystem (`.github/workflows/*.yml`/`*.yaml`).
    GithubActions => "github-actions",
    /// GitLab CI/CD ecosystem (`.gitlab-ci.yml`, `.gitlab/ci/*.yml`/`*.yaml`).
    GitlabCi => "gitlab-ci",
}

impl EcosystemId {
    /// OSV.dev `package.ecosystem` value for this ecosystem, or `None` if
    /// OSV has no equivalent.
    ///
    /// An exhaustive `match` rather than a lookup table: adding a 12th
    /// ecosystem becomes a compile error here instead of a silent
    /// zero-results ecosystem in OSV queries. Every arm below was verified
    /// live against `https://api.osv.dev` (each returned real advisories for
    /// a known-vulnerable version) — see `architecture.md` §2.
    ///
    /// Hand-written rather than generated by the `ecosystem_ids!` macro: this mapping is not 1:1
    /// (`Npm | Deno` both map to `"npm"`, `Maven | Gradle` both map to `"Maven"`, `GitlabCi`
    /// maps to `None`), so folding it into the shared list would need per-arm escape
    /// hatches that cost more than they save — and match exhaustiveness already forces
    /// this `match` to be updated for a new variant, which is the property that matters.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::EcosystemId;
    /// use deps_core::osv::OsvEcosystem;
    ///
    /// assert_eq!(EcosystemId::Cargo.osv_ecosystem(), Some(OsvEcosystem::CratesIo));
    /// assert_eq!(EcosystemId::Gradle.osv_ecosystem(), Some(OsvEcosystem::Maven));
    /// ```
    #[must_use]
    pub const fn osv_ecosystem(self) -> Option<crate::osv::OsvEcosystem> {
        use crate::osv::OsvEcosystem;
        match self {
            Self::Cargo => Some(OsvEcosystem::CratesIo),
            Self::Npm | Self::Deno => Some(OsvEcosystem::Npm),
            Self::Pypi => Some(OsvEcosystem::PyPI),
            Self::Go => Some(OsvEcosystem::Go),
            Self::Bundler => Some(OsvEcosystem::RubyGems),
            Self::Dart => Some(OsvEcosystem::Pub),
            Self::Maven | Self::Gradle => Some(OsvEcosystem::Maven),
            Self::Composer => Some(OsvEcosystem::Packagist),
            Self::Swift => Some(OsvEcosystem::SwiftURL),
            Self::NuGet => Some(OsvEcosystem::NuGet),
            Self::GithubActions => Some(OsvEcosystem::GitHubActions),
            // A git-tag/release pin has no OSV coordinate by name (mirrors
            // `deps_gitlab_ci::formatter::GitlabCiFormatter`'s `OsvNaming` docs).
            Self::GitlabCi => None,
        }
    }
}

impl std::fmt::Display for EcosystemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// The shape shared by [`BlockedRegistryOccurrence`] and [`RejectedRegistryOccurrence`].
///
/// A dependency's name range plus which config declaration produced the notice (#1438 code
/// review: extracted so `deps_core::lsp_helpers::diagnostics` can group/collapse both
/// occurrence types through one generic algorithm instead of two near-identical copies).
pub trait RegistryOccurrence {
    /// Range of the affected dependency's name in the manifest.
    fn range(&self) -> Range;
    /// Implementation-opaque string identifying which underlying config declaration produced
    /// this entry.
    fn declaration_key(&self) -> &str;
}

/// One dependency declaration whose registry-index resolution was blocked by a
/// workspace-registry reachability policy — returned by [`ParseResult::blocked_registries`].
///
/// A named struct rather than a positional tuple (#944 M9): [`Self::raw_value`] and
/// [`Self::declaration_key`] are both `String`s, so a positional tuple would let them be
/// silently swapped at any call site with no compile error — the same shape as the value/key
/// mixup this type exists to rule out.
#[derive(Clone, crate::redact_debug::RedactingDebug)]
pub struct BlockedRegistryOccurrence {
    /// Range of the affected dependency's name in the manifest.
    #[raw]
    pub range: Range,
    /// The blocked host: its classification and the rule that refused it.
    #[raw]
    pub block: crate::net_policy::BlockedHost,
    /// The exact `registry`/`registry-index` alias or URL the dependency declared, so two
    /// different blocked aliases render as two distinguishable diagnostic messages, not one
    /// byte-identical warning.
    #[redact(url)]
    pub raw_value: String,
    /// Implementation-opaque string identifying *which underlying config declaration*
    /// produced this entry — never the resolved value itself (code-review correctness fix,
    /// #925). See [`ParseResult::blocked_registries`]'s doc for why this must be distinct
    /// from [`Self::raw_value`].
    #[redact(key)]
    pub declaration_key: String,
}

impl RegistryOccurrence for BlockedRegistryOccurrence {
    fn range(&self) -> Range {
        self.range
    }

    fn declaration_key(&self) -> &str {
        &self.declaration_key
    }
}

/// One host-class/raw-value/declaration-key classification an ecosystem config's own
/// `blocked_class_for` helper produces.
///
/// One layer below the [`ParseResult::blocked_registries`] trait boundary — same field shape as
/// [`BlockedRegistryOccurrence`] minus [`BlockedRegistryOccurrence::range`], which the config
/// layer never knows: the caller attaches it per affected dependency via
/// [`Self::into_occurrence`].
///
/// A named struct rather than a positional tuple (#966): [`Self::raw_value`] and
/// [`Self::declaration_key`] are both `String`s, so a positional tuple would let them be
/// silently swapped at any call site with no compile error — the exact field-swap risk
/// [`BlockedRegistryOccurrence`] itself was already converted off of (#944 M9). Implemented by
/// `deps_nuget::config::NuGetConfig::blocked_class_for`, `deps_npm::config::NpmConfig::blocked_class_for`,
/// and `deps_pypi::config::PypiIndexConfig::blocked_class_for`.
#[derive(Clone, PartialEq, Eq, crate::redact_debug::RedactingDebug)]
pub struct BlockedSourceClass {
    /// The blocked host: its classification and the rule that refused it.
    #[raw]
    pub block: crate::net_policy::BlockedHost,
    /// The exact declared value (URL/alias) that resolved to a blocked host.
    #[redact(url)]
    pub raw_value: String,
    /// Implementation-opaque string identifying which underlying config declaration produced
    /// this entry — see [`BlockedRegistryOccurrence::declaration_key`]'s doc for why this must
    /// stay distinct from [`Self::raw_value`].
    #[redact(key)]
    pub declaration_key: String,
}

impl BlockedSourceClass {
    /// Attaches the affected dependency's `range` to produce the [`BlockedRegistryOccurrence`]
    /// a `ParseResult::blocked_registries()` override reports.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::{BlockedHost, HostClass};
    /// use deps_core::BlockedSourceClass;
    /// use deps_core::position::{Position, Range};
    ///
    /// let class = BlockedSourceClass {
    ///     block: BlockedHost::floor(HostClass::Loopback).unwrap(),
    ///     raw_value: "https://internal.example/index".to_string(),
    ///     declaration_key: "primary".to_string(),
    /// };
    /// let range = Range::new(Position::new(0, 0), Position::new(0, 4));
    /// let occurrence = class.into_occurrence(range);
    /// assert_eq!(occurrence.declaration_key, "primary");
    /// ```
    #[must_use]
    pub fn into_occurrence(self, range: Range) -> BlockedRegistryOccurrence {
        BlockedRegistryOccurrence {
            range,
            block: self.block,
            raw_value: self.raw_value,
            declaration_key: self.declaration_key,
        }
    }
}

/// One dependency declaration whose registry-config entry was rejected for a reason other
/// than a policy-blocked host — returned by [`ParseResult::rejected_registries`] (#1438).
///
/// Same field shape as [`BlockedRegistryOccurrence`], with
/// [`crate::net_policy::RegistryRejectionReason`] in place of
/// [`crate::net_policy::HostClass`]: a `BlockedHost` rejection already has its own diagnostic
/// path via [`BlockedRegistryOccurrence`], so the two occurrence types are deliberately
/// disjoint rather than merged into one `class`-like field covering every reason.
#[derive(Clone, crate::redact_debug::RedactingDebug)]
pub struct RejectedRegistryOccurrence {
    /// Range of the affected dependency's name in the manifest.
    #[raw]
    pub range: Range,
    /// Why the entry was rejected.
    #[raw]
    pub reason: crate::net_policy::RegistryRejectionReason,
    /// The exact `registry`/`registry-index` alias or URL the dependency declared.
    #[redact(url)]
    pub raw_value: String,
    /// Implementation-opaque string identifying *which underlying config declaration*
    /// produced this entry — same purpose and shape as
    /// [`BlockedRegistryOccurrence::declaration_key`].
    #[redact(key)]
    pub declaration_key: String,
}

impl RegistryOccurrence for RejectedRegistryOccurrence {
    fn range(&self) -> Range {
        self.range
    }

    fn declaration_key(&self) -> &str {
        &self.declaration_key
    }
}

/// One reason/raw-value/declaration-key classification an ecosystem config's own
/// `rejected_reason_for`-style helper produces.
///
/// The [`RegistryRejectionReason`] counterpart to [`BlockedSourceClass`] (#1438).
///
/// [`RegistryRejectionReason`]: crate::net_policy::RegistryRejectionReason
#[derive(Clone, PartialEq, Eq, crate::redact_debug::RedactingDebug)]
pub struct RejectedSourceClass {
    /// Why the entry was rejected.
    #[raw]
    pub reason: crate::net_policy::RegistryRejectionReason,
    /// The exact declared value (URL/alias) that was rejected.
    #[redact(url)]
    pub raw_value: String,
    /// Implementation-opaque string identifying which underlying config declaration produced
    /// this entry — see [`BlockedRegistryOccurrence::declaration_key`]'s doc for why this must
    /// stay distinct from [`Self::raw_value`].
    #[redact(key)]
    pub declaration_key: String,
}

impl RejectedSourceClass {
    /// Attaches the affected dependency's `range` to produce the
    /// [`RejectedRegistryOccurrence`] a `ParseResult::rejected_registries()` override reports.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::RegistryRejectionReason;
    /// use deps_core::RejectedSourceClass;
    /// use deps_core::position::{Position, Range};
    ///
    /// let class = RejectedSourceClass {
    ///     reason: RegistryRejectionReason::InvalidUrl,
    ///     raw_value: "not-a-url".to_string(),
    ///     declaration_key: "top-level".to_string(),
    /// };
    /// let range = Range::new(Position::new(0, 0), Position::new(0, 4));
    /// let occurrence = class.into_occurrence(range);
    /// assert_eq!(occurrence.declaration_key, "top-level");
    /// ```
    #[must_use]
    pub fn into_occurrence(self, range: Range) -> RejectedRegistryOccurrence {
        RejectedRegistryOccurrence {
            range,
            reason: self.reason,
            raw_value: self.raw_value,
            declaration_key: self.declaration_key,
        }
    }
}

/// Parse result trait containing dependencies and metadata.
///
/// Implementations hold ecosystem-specific dependency types
/// but expose them through trait object interfaces.
///
/// A new provided method must also be forwarded by `ParsedView`'s and the internal
/// `EcosystemManifest`'s impls (both deny `clippy::missing_trait_methods`), or it silently
/// falls back to the default on every document.
pub trait ParseResult: Send + Sync {
    /// All dependencies found in the manifest
    fn dependencies(&self) -> Vec<&dyn Dependency>;

    /// Workspace root path (for monorepo support)
    fn workspace_root(&self) -> Option<&std::path::Path>;

    /// Document URI
    fn uri(&self) -> &url::Url;

    /// Dependency lines whose registry-index resolution was blocked by a workspace-registry
    /// reachability policy (spec `.local/specs/023-cargo-custom-registries/plan-1b.md` §1.7,
    /// #443). Used by [`crate::lsp_helpers::generate_diagnostics_from_cache`] to surface an
    /// [`tower_lsp_server::ls_types::DiagnosticSeverity::INFORMATION`] diagnostic on the
    /// blocked dependency's line so the block never degrades silently.
    ///
    /// [`BlockedRegistryOccurrence::declaration_key`] is an implementation-opaque string
    /// identifying *which underlying config declaration* produced this entry — never the
    /// resolved value itself (code-review correctness fix, #925): a config-global declaration
    /// (e.g. a single blocked npm `.npmrc` `registry=` line, or one `NuGet.Config` `<add key>`
    /// source) applies identically to every dependency it affects, so
    /// [`crate::lsp_helpers::generate_diagnostics_from_cache`] groups by this key alone to
    /// collapse that fan-out — but two *independently* declared sources that merely happen to
    /// share the same raw value/host class (e.g. an npm top-level `registry=` and an unrelated
    /// `@scope:registry=` both blocked to the same URL) must carry *different* keys, or the
    /// second declaration's own dependents would silently lose their diagnostic even though
    /// nothing links the two declarations. An implementor with no realistic risk of two
    /// distinct declarations coincidentally sharing a raw value (e.g. `deps_cargo`, where the
    /// raw value is always either a unique alias name or the literal URL the dependency itself
    /// wrote) may reuse the raw value as its own declaration key.
    ///
    /// Default empty. An ecosystem overrides this when it enforces `net_policy` reachability
    /// restrictions on a configurable registry/proxy host via
    /// [`crate::net_policy::validate_index_url`] with [`crate::net_policy::PolicyGate::Enforce`]
    /// — an ecosystem with no such configurable host (nothing a workspace or user config could
    /// point at an unreachable-by-policy host) has nothing to report here and keeps the default.
    fn blocked_registries(&self) -> Vec<BlockedRegistryOccurrence> {
        Vec::new()
    }

    /// Manifest-scoped state that can refine "latest matching" version selection beyond the
    /// plain requirement text — see [`SelectionContext`]'s own doc.
    ///
    /// Default: [`SelectionContext::none()`] — every ecosystem with no selection-context
    /// concept of its own (all but Composer, as of #1433) needs no override. Composer's own
    /// `ComposerParseResult` overrides this to surface its manifest's `minimum-stability`
    /// field.
    fn selection_context(&self) -> SelectionContext {
        SelectionContext::none()
    }

    /// A manifest-declared `minimum-stability`-style value that failed to parse, if any (#1444).
    ///
    /// E.g. Composer's `minimum-stability: "betta"` (unrecognized keyword) or
    /// `minimum-stability: 42` (non-string).
    ///
    /// Kept separate from [`Self::selection_context`] rather than folded into
    /// [`SelectionContext`] itself: an invalid occurrence's `range`/`raw` would otherwise
    /// participate in [`SelectionContext`]'s derived [`PartialEq`], so a manifest edit that
    /// merely shifts line numbers around an *unrelated* invalid value would spuriously look
    /// like a selection-context change to a caller diffing two parses (e.g. `deps-lsp`'s
    /// edit-triggered refetch escalation) — selection still falls back to
    /// [`crate::selection::StabilityFloor::Stable`] exactly as before, but the fallback is
    /// now visible as a diagnostic via `deps_core::lsp_helpers::diagnostics`' shared notice
    /// instead of silent.
    ///
    /// Default: `None` — every ecosystem with no manifest-declared stability-floor concept of
    /// its own needs no override. Composer's own `ComposerParseResult` overrides this when its
    /// `minimum-stability` value fails to parse via
    /// [`std::str::FromStr`] for [`crate::selection::StabilityFloor`].
    fn invalid_minimum_stability(&self) -> Option<InvalidStabilityOccurrence> {
        None
    }

    /// Dependency lines whose registry-config entry was rejected for a reason other than a
    /// policy-blocked host (#1438) — e.g. a malformed URL, a non-https scheme, embedded
    /// userinfo, or an undefined `${VAR}` reference. Without this, such an entry is dropped
    /// from the fetch queue with only a `tracing::warn!`, indistinguishable in the editor from
    /// a dependency that was simply never checked yet. Used by
    /// [`crate::lsp_helpers::generate_diagnostics_from_cache`] to surface an
    /// [`tower_lsp_server::ls_types::DiagnosticSeverity::WARNING`] diagnostic, mirroring
    /// [`Self::blocked_registries`]'s own mechanism but for every other rejection reason.
    ///
    /// Default empty. An ecosystem overrides this when it produces
    /// [`crate::net_policy::InvalidEntry`]-based rejections beyond the blocked-host case
    /// already covered by [`Self::blocked_registries`] — at the time of writing, `deps_npm`,
    /// `deps_pypi`, and `deps_go`.
    fn rejected_registries(&self) -> Vec<RejectedRegistryOccurrence> {
        Vec::new()
    }

    /// Dependency-count ceiling info (#796): `Some((kept, total))` once this document's
    /// dependency count was truncated to [`crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT`]
    /// by [`parse_manifest_blocking`], `None` otherwise.
    ///
    /// The default (and every concrete ecosystem parser) returns `None` — only the
    /// [`ParsedManifest`] [`parse_manifest_blocking`] returns reports a truncation, so this
    /// needs no per-ecosystem implementation. Read by
    /// `deps_core::lsp_helpers::diagnostics`' truncation notice.
    fn dependency_truncation(&self) -> Option<(usize, usize)> {
        None
    }
}

/// Generic dependency trait.
///
/// All parsed dependencies must implement this for generic handler access.
pub trait Dependency: Send + Sync {
    /// Package name
    fn name(&self) -> &crate::PackageName;

    /// Range of the dependency name
    fn name_range(&self) -> Range;

    /// Version requirement string (e.g., "^1.0", ">=2.0")
    fn version_requirement(&self) -> Option<&crate::VersionReq>;

    /// Range of the version string
    fn version_range(&self) -> Option<Range>;

    /// Dependency source (registry, git, path)
    fn source(&self) -> crate::parser::DependencySource;

    /// Feature flags (ecosystem-specific, empty if not supported)
    fn features(&self) -> &[String] {
        &[]
    }

    /// Range of the features array (ecosystem-specific, None if not supported)
    fn features_range(&self) -> Option<Range> {
        None
    }

    /// Environment marker expression gating this dependency (e.g. PEP 508's
    /// `python_version >= '3.8'`). Ecosystem-specific, `None` if not supported
    /// or not present on this dependency.
    fn markers(&self) -> Option<&str> {
        None
    }

    /// Range of the environment marker expression (ecosystem-specific,
    /// `None` if not supported or not present).
    fn markers_range(&self) -> Option<Range> {
        None
    }

    /// The raw manifest text spanned by [`version_range`](Dependency::version_range),
    /// when it differs from [`version_requirement`](Dependency::version_requirement).
    ///
    /// Most ecosystems' `version_requirement()` is (up to whitespace) exactly the text at
    /// `version_range()`, so the default `None` — telling callers to fall back to
    /// `version_requirement()` — is correct for them. An ecosystem whose parser synthesizes
    /// a comparator string from a bare literal (e.g. `deps-swift`'s `.exact("4.50.0")`
    /// becoming requirement `"=4.50.0"` while `version_range()` still spans only `4.50.0`)
    /// overrides this to return that literal, so `lsp_helpers`' literal-span guard
    /// (`literal_span_matches`, used by both `generate_code_actions` and
    /// `collect_update_all_edits`) compares `version_range`'s slice against the text it was
    /// actually derived from instead of the synthesized comparator, which would otherwise
    /// never match and silently suppress every fix action for that dependency.
    ///
    /// A sibling mechanism already exists for the same underlying problem: `deps-nuget`
    /// wraps a bare source version as requirement `[1.0.0]`, and `literal_span_matches`
    /// special-cases that bracket wrapping inline rather than going through this hook. This
    /// method exists for the general case — an ecosystem whose synthesized requirement is
    /// not a simple wrap (`deps-swift`'s comparator range is not recoverable from
    /// `version_requirement()` by stripping fixed characters) needs its own literal, not a
    /// transform `literal_span_matches` could hard-code.
    ///
    /// **Must not** be set when `version_range()` spans only part of a multi-literal
    /// requirement whose other part(s) are not being rewritten — e.g. a `"lower"..<"upper"`
    /// range, where `version_range()` covers only `lower`. Reporting `lower` as the literal
    /// would let the guard pass and an edit rewrite `lower` alone, corrupting the
    /// requirement (`deps-swift` leaves this `None` for both its range-literal forms for
    /// exactly this reason — see `crates/deps-swift/src/parser.rs`'s range-form comments).
    fn version_literal(&self) -> Option<&str> {
        None
    }

    /// Whether [`name_range`](Dependency::name_range) is a synthetic placeholder rather than a
    /// real position in the manifest, for a dependency whose name was resolved from something
    /// other than the live document text — e.g. `deps-dart`'s container-anchor alias
    /// resolution (issue #905), where a whole `dependencies:`/`environment:` section aliased
    /// via `*anchor` is reconstructed from a buffered subtree replayed at the alias site, so no
    /// position in *this* occurrence's own text corresponds to the resolved name.
    ///
    /// `name_range()` itself has no `Option` to express this (unlike `version_range()`), so
    /// callers that would otherwise treat it as a stable, real, per-dependency position must
    /// check this hook first. In particular: a `HashMap` keyed by `name_range()` (e.g.
    /// [`crate::osv::vulnerability_keys`]) must not key on it when this returns `true` — every
    /// such dependency would share the exact same synthetic range and silently collide, one
    /// evicting another's entry — and a hover/diagnostic anchor must not render at it either
    /// (it typically resolves to `Range::default()`, i.e. document start).
    ///
    /// The default `false` is correct for every ecosystem whose dependency name is always
    /// literal text at a real position — which, as of this writing, is every ecosystem except
    /// the one case named above.
    fn name_range_is_synthetic(&self) -> bool {
        false
    }
}

/// Configuration for LSP inlay hints feature.
///
/// Since this type is `#[non_exhaustive]`, `deps-lsp`'s `handlers/inlay_hints.rs` builds one
/// via [`Self::new`] plus a `with_*` chain rather than a struct literal — adding a field here
/// no longer forces that call site to update at compile time. A new field must be wired into
/// it by hand, or it silently keeps [`Self::new`]'s default forever.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct EcosystemConfig {
    /// Whether to show inlay hints for up-to-date dependencies
    pub show_up_to_date_hints: bool,
    /// Text to display for up-to-date dependencies
    pub up_to_date_text: String,
    /// Text to display for dependencies needing updates (use {} for version placeholder)
    pub needs_update_text: String,
    /// Text to display while loading registry data
    pub loading_text: String,
    /// Whether to show loading hints in inlay hints
    pub show_loading_hints: bool,
    /// The current [`crate::NetworkMode`] (issue #483): when [`crate::NetworkMode::Offline`]
    /// and no cached latest version exists for a dependency,
    /// [`crate::lsp_helpers::generate_inlay_hints`] shows an offline marker instead of
    /// silently falling back to the resolved-version display, which would otherwise look
    /// identical to a normal pre-fetch state.
    pub network: crate::NetworkMode,
}

impl Default for EcosystemConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EcosystemConfig {
    /// Builds the default configuration (mirrors [`Self::default`]).
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must chain the `with_*` setters onto this
    /// constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{EcosystemConfig, NetworkMode};
    ///
    /// let config = EcosystemConfig::new().with_network(NetworkMode::Offline);
    /// assert_eq!(config.network, NetworkMode::Offline);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        }
    }

    /// Overrides [`Self::show_up_to_date_hints`]. See [`Self::new`].
    #[must_use]
    pub const fn with_show_up_to_date_hints(mut self, show_up_to_date_hints: bool) -> Self {
        self.show_up_to_date_hints = show_up_to_date_hints;
        self
    }

    /// Overrides [`Self::up_to_date_text`]. See [`Self::new`].
    #[must_use]
    pub fn with_up_to_date_text(mut self, up_to_date_text: impl Into<String>) -> Self {
        self.up_to_date_text = up_to_date_text.into();
        self
    }

    /// Overrides [`Self::needs_update_text`]. See [`Self::new`].
    #[must_use]
    pub fn with_needs_update_text(mut self, needs_update_text: impl Into<String>) -> Self {
        self.needs_update_text = needs_update_text.into();
        self
    }

    /// Overrides [`Self::loading_text`]. See [`Self::new`].
    #[must_use]
    pub fn with_loading_text(mut self, loading_text: impl Into<String>) -> Self {
        self.loading_text = loading_text.into();
        self
    }

    /// Overrides [`Self::show_loading_hints`]. See [`Self::new`].
    #[must_use]
    pub const fn with_show_loading_hints(mut self, show_loading_hints: bool) -> Self {
        self.show_loading_hints = show_loading_hints;
        self
    }

    /// Overrides [`Self::network`]. See [`Self::new`].
    #[must_use]
    pub const fn with_network(mut self, network: crate::NetworkMode) -> Self {
        self.network = network;
        self
    }
}

/// What a change to a [`WatchedConfig`] file does to an ecosystem's parsed documents.
///
/// Exhaustive on purpose: a caller reacting to a config change must decide what each
/// effect means for its refetch strategy, and adding a variant must fail to compile there.
///
/// # Examples
///
/// ```
/// use deps_core::WatchedConfigEffect;
///
/// assert_ne!(
///     WatchedConfigEffect::RewritesRequirements,
///     WatchedConfigEffect::ChangesRouting
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchedConfigEffect {
    /// The config rewrites a dependency's version requirement directly (e.g. npm's
    /// `pnpm-workspace.yaml` catalog), so an ordinary diff against the previous parse result
    /// already detects the change.
    RewritesRequirements,
    /// The config changes which registry a dependency resolves through without touching
    /// names or requirements, so a diff would look like a no-op and a full re-fetch is
    /// required (issue #1232).
    ChangesRouting,
}

/// Which manifests a [`WatchedConfig`] file declares it can affect, relative to the directory that
/// owns it.
///
/// Exhaustive on purpose: a caller scoping a reparse must decide what each reach means, and a
/// new variant must fail to compile there (issue #1793). The resolved [`OwnerReach`] adds the
/// one reach a config cannot declare.
///
/// # Examples
///
/// ```
/// use deps_core::ConfigReach;
///
/// assert_ne!(ConfigReach::Subtree, ConfigReach::OwnerDirectory);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigReach {
    /// The ecosystem walks ancestor directories looking for this file, so it affects every
    /// manifest in the owner directory and below (bounded by
    /// [`crate::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH`]).
    Subtree,
    /// The ecosystem reads this file only next to the manifest, with no ancestor walk, so it
    /// affects manifests in the owner directory itself.
    OwnerDirectory,
}

/// How far a changed config file's influence reaches once its owner directory is known: a
/// [`ConfigReach`] plus [`Self::AllDocuments`], which only [`ConfigOwner::for_user_home`]
/// produces.
///
/// # Examples
///
/// ```
/// use deps_core::{ConfigReach, OwnerReach};
///
/// assert_eq!(OwnerReach::from(ConfigReach::Subtree), OwnerReach::Subtree);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnerReach {
    /// See [`ConfigReach::Subtree`].
    Subtree,
    /// See [`ConfigReach::OwnerDirectory`].
    OwnerDirectory,
    /// A user-level file (the config sits in the user's home directory): the ecosystem reads it
    /// for every manifest wherever the manifest lives, so it affects every open document of the
    /// ecosystem.
    AllDocuments,
}

impl From<ConfigReach> for OwnerReach {
    fn from(reach: ConfigReach) -> Self {
        match reach {
            ConfigReach::Subtree => Self::Subtree,
            ConfigReach::OwnerDirectory => Self::OwnerDirectory,
        }
    }
}

/// The user's home directory, resolved once so classifying a changed config never touches the
/// filesystem.
///
/// [`Self::current`] resolves the process's home directory on first use;
/// [`EcosystemRegistry::new`](crate::EcosystemRegistry::new) triggers it at startup.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use deps_core::UserHome;
///
/// let home = UserHome::new(PathBuf::from("/home/me"));
/// assert_eq!(home.path().to_str(), Some("/home/me"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserHome {
    raw: PathBuf,
    canonical: Option<PathBuf>,
}

impl UserHome {
    /// A home directory compared as given, with no filesystem access.
    #[must_use]
    pub const fn new(raw: PathBuf) -> Self {
        Self {
            raw,
            canonical: None,
        }
    }

    /// A home directory that also matches its canonical (symlink-free) spelling.
    ///
    /// Blocks on the filesystem once; call it at startup, not per event.
    #[must_use]
    pub fn resolve(raw: PathBuf) -> Self {
        let canonical = std::fs::canonicalize(&raw).ok();
        Self { raw, canonical }
    }

    /// The process's home directory, resolved on first use and cached; `None` when the platform
    /// reports none or reports one that is not an absolute path (a relative home would be
    /// resolved against whatever directory the server runs in, so it is never operator-owned).
    #[must_use]
    pub fn current() -> Option<&'static Self> {
        static HOME: std::sync::OnceLock<Option<UserHome>> = std::sync::OnceLock::new();
        HOME.get_or_init(|| absolute_home(std::env::home_dir()).map(Self::resolve))
            .as_ref()
    }

    /// The home directory as given.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.raw
    }

    fn is(&self, dir: &Path) -> bool {
        self.raw == dir || self.canonical.as_deref() == Some(dir)
    }
}

/// `home` when it is an absolute path: a relative home would resolve against whatever directory
/// the server runs in, so it counts as no home.
fn absolute_home(home: Option<PathBuf>) -> Option<PathBuf> {
    home.filter(|home| home.is_absolute())
}

#[cfg(test)]
mod home_tests {
    use super::absolute_home;
    use std::path::PathBuf;

    #[test]
    fn a_relative_home_is_no_home() {
        assert_eq!(absolute_home(Some(PathBuf::from("relative/home"))), None);
        assert_eq!(absolute_home(Some(PathBuf::new())), None);
        assert_eq!(absolute_home(None), None);
        let absolute = std::env::temp_dir();
        assert_eq!(absolute_home(Some(absolute.clone())), Some(absolute));
    }
}

/// The directory that owns a changed [`WatchedConfig`] file, plus how far its influence reaches.
///
/// # Examples
///
/// ```
/// use std::path::{Path, PathBuf};
/// use deps_core::{ConfigOwner, ConfigReach, UserHome};
///
/// let owner = ConfigOwner::new(PathBuf::from("/work"), ConfigReach::Subtree);
/// assert!(owner.covers(Path::new("/work/pkg/package.json")));
/// assert!(!owner.covers(Path::new("/other/package.json")));
///
/// let local = ConfigOwner::new(PathBuf::from("/work"), ConfigReach::OwnerDirectory);
/// assert!(local.covers(Path::new("/work/Package.swift")));
/// assert!(!local.covers(Path::new("/work/pkg/Package.swift")));
///
/// let home = UserHome::new(PathBuf::from("/work"));
/// let user = local.for_user_home(Some(&home));
/// assert!(user.covers(Path::new("/elsewhere/Package.swift")));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigOwner {
    dir: PathBuf,
    reach: OwnerReach,
}

impl ConfigOwner {
    /// Creates an owner for the config file's containing directory `dir`.
    #[must_use]
    pub fn new(dir: PathBuf, reach: impl Into<OwnerReach>) -> Self {
        Self {
            dir,
            reach: reach.into(),
        }
    }

    /// The directory owning the config file.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// How far the config file's influence reaches.
    #[must_use]
    pub const fn reach(&self) -> OwnerReach {
        self.reach
    }

    /// Whether the manifest file at `manifest` resolves through this owner's config file.
    ///
    /// Both paths must be normalized the same way (e.g. both canonical).
    #[must_use]
    pub fn covers(&self, manifest: &Path) -> bool {
        let Some(manifest_dir) = manifest.parent() else {
            return false;
        };
        match self.reach {
            OwnerReach::Subtree => {
                crate::fs_probe::config_ancestors(manifest_dir).any(|dir| dir == self.dir)
            }
            OwnerReach::OwnerDirectory => manifest_dir == self.dir,
            OwnerReach::AllDocuments => true,
        }
    }

    /// This owner widened to [`OwnerReach::AllDocuments`] when its directory is `home` (the file
    /// is then the user-level tier), else unchanged. Does no filesystem access.
    #[must_use]
    pub fn for_user_home(self, home: Option<&UserHome>) -> Self {
        if home.is_some_and(|home| home.is(&self.dir)) {
            Self {
                reach: OwnerReach::AllDocuments,
                ..self
            }
        } else {
            self
        }
    }
}

/// A non-lockfile config file an ecosystem resolves during manifest parsing, identified by
/// the trailing path components it must end with.
///
/// Matching is component-wise ([`Path::ends_with`]), so a suffix such as
/// `.swiftpm/configuration/registries.json` does not match an unrelated
/// `docs/registries.json`, and works with the host's path separator.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use deps_core::{ConfigReach, WatchedConfig, WatchedConfigEffect};
///
/// const NPMRC: WatchedConfig =
///     WatchedConfig::new(".npmrc", WatchedConfigEffect::ChangesRouting, ConfigReach::Subtree);
///
/// assert!(NPMRC.matches(Path::new("/work/app/.npmrc")));
/// assert!(!NPMRC.matches(Path::new("/work/app/x.npmrc")));
/// assert_eq!(NPMRC.glob_pattern(), "**/.npmrc");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedConfig {
    path_suffix: &'static str,
    effect: WatchedConfigEffect,
    reach: ConfigReach,
}

const fn assert_plain_relative_suffix(suffix: &str) {
    let mut rest = suffix.as_bytes();
    assert!(!rest.is_empty(), "watched config suffix is empty");
    assert!(
        !matches!(rest, [b'/', ..]),
        "watched config suffix is absolute"
    );
    let mut component_len = 0usize;
    let mut component_dots = 0usize;
    while let [byte, tail @ ..] = rest {
        rest = tail;
        if *byte == b'/' {
            assert!(
                !(component_len == 2 && component_dots == 2),
                "watched config suffix contains `..`"
            );
            component_len = 0;
            component_dots = 0;
            continue;
        }
        assert!(
            !matches!(*byte, b'*' | b'?' | b'[' | b'\\'),
            "watched config suffix contains a glob or separator character"
        );
        component_len += 1;
        if *byte == b'.' {
            component_dots += 1;
        }
    }
    assert!(
        !(component_len == 2 && component_dots == 2),
        "watched config suffix contains `..`"
    );
}

impl WatchedConfig {
    /// Creates a watched config. `path_suffix` is a relative, `/`-separated path (no `..`,
    /// no glob characters) that a changed file's path must end with.
    ///
    /// # Panics
    ///
    /// Panics (at compile time when used in a `const`) if `path_suffix` is empty, absolute,
    /// contains `*`, `?`, `[`, `\` or a `..` component.
    ///
    /// ```compile_fail
    /// use deps_core::{ConfigReach, WatchedConfig, WatchedConfigEffect};
    ///
    /// const BAD: WatchedConfig = WatchedConfig::new(
    ///     "../.npmrc",
    ///     WatchedConfigEffect::ChangesRouting,
    ///     ConfigReach::Subtree,
    /// );
    /// ```
    #[must_use]
    pub const fn new(
        path_suffix: &'static str,
        effect: WatchedConfigEffect,
        reach: ConfigReach,
    ) -> Self {
        assert_plain_relative_suffix(path_suffix);
        Self {
            path_suffix,
            effect,
            reach,
        }
    }

    /// Which manifests a change to this file can affect.
    #[must_use]
    pub const fn reach(&self) -> ConfigReach {
        self.reach
    }

    /// The directory owning `changed`, i.e. `changed` with this config's suffix components
    /// removed; `None` when `changed` is not this config file.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::Path;
    /// use deps_core::{ConfigReach, WatchedConfig, WatchedConfigEffect};
    ///
    /// const SWIFT: WatchedConfig = WatchedConfig::new(
    ///     ".swiftpm/configuration/registries.json",
    ///     WatchedConfigEffect::ChangesRouting,
    ///     ConfigReach::OwnerDirectory,
    /// );
    ///
    /// let changed = Path::new("/p/.swiftpm/configuration/registries.json");
    /// assert_eq!(SWIFT.owner_dir(changed), Some(Path::new("/p")));
    /// assert_eq!(SWIFT.owner_dir(Path::new("/p/docs/registries.json")), None);
    /// ```
    #[must_use]
    pub fn owner_dir<'a>(&self, changed: &'a Path) -> Option<&'a Path> {
        if !self.matches(changed) {
            return None;
        }
        changed
            .ancestors()
            .nth(Path::new(self.path_suffix).components().count())
    }

    /// The trailing path the watched file must end with.
    #[must_use]
    pub const fn path_suffix(&self) -> &'static str {
        self.path_suffix
    }

    /// What a change to this file does to parsed documents.
    #[must_use]
    pub const fn effect(&self) -> WatchedConfigEffect {
        self.effect
    }

    /// Whether `path` is this config file.
    #[must_use]
    pub fn matches(&self, path: &Path) -> bool {
        path.ends_with(self.path_suffix)
    }

    /// The client-side file-watcher glob that covers this config file.
    #[must_use]
    pub fn glob_pattern(&self) -> String {
        format!("**/{}", self.path_suffix)
    }
}

/// How this ecosystem's license strings are sourced.
///
/// Drives three ecosystem-specific license behaviors that used to be re-derived
/// independently at each consumer via a non-exhaustive `matches!`/`==` on
/// [`EcosystemId`] instead of the sealed [`Ecosystem`] trait every other per-ecosystem
/// capability goes through (issue #688): hover's "(detected)" qualifier, which only
/// applies to [`Self::DetectedSpdx`]; whether
/// [`crate::licenses::resolve_license_entries`] must normalize free text to SPDX
/// identifiers before hover displays it or a [`crate::licenses::LicensePolicy`]
/// evaluates it, which only applies to [`Self::PomFreeText`]; and, via
/// [`Self::requires_dedicated_fetch`] (issue #697), whether
/// [`EcosystemBase::fetch_license`] is a dedicated async fetch or a no-op because the
/// license already arrived in the hot-path registry response.
///
/// # Examples
///
/// ```
/// use deps_core::LicenseSource;
///
/// assert_eq!(LicenseSource::default(), LicenseSource::RegistryDeclaredSpdx);
/// assert_ne!(LicenseSource::PomFreeText, LicenseSource::DetectedSpdx);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LicenseSource {
    /// Author-declared SPDX identifier(s) already present in the hot-path registry
    /// response — the default for every ecosystem that doesn't override
    /// [`EcosystemBase::license_source`], and the only variant for which
    /// [`Self::requires_dedicated_fetch`] is `false`.
    #[default]
    RegistryDeclaredSpdx,
    /// Author-declared SPDX identifier(s) that require a dedicated fetch separate
    /// from the hot-path registry response: JSR's package-metadata endpoint (Deno).
    FetchedDeclaredSpdx,
    /// A detector's best-effort guess, not an author declaration, that requires a
    /// dedicated fetch: pub.dev's `/score` endpoint (Dart) and GitHub's
    /// `license.spdx_id` (Swift) are both driven by a license-detection heuristic run
    /// against repository content, rather than metadata the package author explicitly
    /// declared to a registry.
    DetectedSpdx,
    /// Maven POM `<licenses><license><name>` free text (Gradle), fetched via a
    /// dedicated request — never an SPDX identifier, so it must be normalized via
    /// [`crate::licenses::resolve_license_entries`] before display or policy evaluation.
    PomFreeText,
}

impl LicenseSource {
    /// Whether this source requires [`EcosystemBase::fetch_license`]'s dedicated async
    /// fetch, as opposed to arriving for free in the hot-path registry response.
    ///
    /// This is the single answer to "is this a tier-3 license ecosystem" (issue #697):
    /// capability and shape can no longer disagree, because both come from the same
    /// [`EcosystemBase::license_source`] call.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::LicenseSource;
    ///
    /// assert!(!LicenseSource::RegistryDeclaredSpdx.requires_dedicated_fetch());
    /// assert!(LicenseSource::FetchedDeclaredSpdx.requires_dedicated_fetch());
    /// assert!(LicenseSource::DetectedSpdx.requires_dedicated_fetch());
    /// assert!(LicenseSource::PomFreeText.requires_dedicated_fetch());
    /// ```
    #[must_use]
    pub const fn requires_dedicated_fetch(self) -> bool {
        match self {
            Self::RegistryDeclaredSpdx => false,
            Self::FetchedDeclaredSpdx | Self::DetectedSpdx | Self::PomFreeText => true,
        }
    }
}

/// The parse-result-free surface of a package ecosystem: identity, manifest routing, registry
/// access, lock files, fallback completion and license sourcing.
///
/// Every ecosystem implements this trait directly, next to [`TypedEcosystem`], which carries
/// everything that reads a parsed document. Type-erased consumers reach both through
/// [`Ecosystem`], whose supertrait this is.
///
/// # Sealing
///
/// This trait requires `Self: private::Sealed`, making it sealed in the sense described
/// on that module's doc: a documented contract enforced by code review, not a
/// compiler-enforced wall. Every sibling ecosystem crate in this workspace (`deps-cargo`,
/// `deps-npm`, ...) implements [`private::Sealed`] for its own ecosystem type, which requires
/// `private` to be `pub`; Rust has no visibility level that admits sibling crates while
/// excluding a truly external one, so this guarantee cannot be enforced any harder than that
/// without inverting the crate's whole multi-crate extension-point architecture. See
/// [`private::Sealed`]'s own doc for the full reasoning.
///
/// # Examples
///
/// See [`TypedEcosystem`] for a complete implementation.
pub trait EcosystemBase: Send + Sync + private::Sealed {
    /// Exhaustively typed ecosystem identity.
    ///
    /// Every implementor lives in this sealed trait's own workspace, so the enum is
    /// authoritative for identity and [`Self::id`] is derived from it rather than
    /// independently authored — a typo or rename here is a compile error instead of a
    /// runtime mismatch between [`EcosystemId::ALL`] and this ecosystem's registration.
    fn ecosystem_id(&self) -> EcosystemId;

    /// Unique identifier (e.g., "cargo", "npm", "pypi")
    ///
    /// This identifier is used for ecosystem registration and routing. The default
    /// implementation derives it from [`Self::ecosystem_id`], so an implementor that leaves
    /// `id()` at its default can no longer author a mismatched string independently — but
    /// `id()` remains a provided (overridable) method, so this guarantee holds only for that
    /// default, not for an implementor that overrides `id()` directly (as some test doubles
    /// deliberately do). Code needing the two to agree should verify it explicitly, e.g. via
    /// [`crate::conformance::assert_ecosystem_id`].
    fn id(&self) -> &'static str {
        self.ecosystem_id().id()
    }

    /// Human-readable name (e.g., "Cargo (Rust)", "npm (JavaScript)")
    ///
    /// This name is displayed in diagnostic messages and logs.
    fn display_name(&self) -> &'static str;

    /// Manifest filenames this ecosystem handles (e.g., ["Cargo.toml"])
    ///
    /// The ecosystem registry uses these filenames to route file URIs
    /// to the appropriate ecosystem implementation.
    fn manifest_filenames(&self) -> &[&'static str];

    /// File extensions this ecosystem handles when the manifest basename is
    /// not fixed (e.g. `[".csproj", ".fsproj"]` for NuGet project files).
    ///
    /// Consulted by [`crate::EcosystemRegistry::for_filename`] only after
    /// an exact [`manifest_filenames`](EcosystemBase::manifest_filenames) match
    /// fails. Empty by default, indicating this ecosystem is routed solely by
    /// exact filename.
    fn manifest_extensions(&self) -> &[&'static str] {
        &[]
    }

    /// Basename glob patterns this ecosystem handles, each containing exactly
    /// one `*` wildcard (e.g. `["requirements*.txt"]`).
    ///
    /// Consulted by [`crate::EcosystemRegistry::for_filename`] as a third
    /// routing stage, tried after an exact
    /// [`manifest_filenames`](EcosystemBase::manifest_filenames) match fails and
    /// before [`manifest_extensions`](EcosystemBase::manifest_extensions) — for
    /// basenames that are neither fixed nor identified by extension alone
    /// (e.g. `requirements.txt`, `requirements-dev.txt`). Empty by default.
    /// Matching is case-sensitive, unlike the extension stage: these patterns
    /// target canonically-lowercase filenames (pip, Renovate and Dependabot
    /// all treat `requirements.txt` as lowercase), whereas the extension
    /// stage exists specifically for Windows/MSBuild project files whose
    /// case genuinely varies.
    fn manifest_patterns(&self) -> &[&'static str] {
        &[]
    }

    /// `(directory_path, file_suffix)` pairs identifying a file solely by its
    /// containing directory path and suffix. `directory_path` may be a single
    /// segment (e.g. `[("requirements", ".txt")]` for Python's
    /// `requirements/base.txt` split-file layout) or multiple `/`-joined
    /// segments (e.g. `[(".github/workflows", ".yml")]` for GitHub Actions
    /// workflow files) — either way it is matched against the *tail* of the
    /// file's directory path on segment boundaries, not just the immediate
    /// parent, so a multi-segment pattern matches regardless of how many
    /// ancestor directories precede it. Used when the basename alone carries
    /// no ecosystem signal.
    ///
    /// Consulted by [`crate::EcosystemRegistry::for_uri`] only, after both
    /// [`manifest_patterns`](EcosystemBase::manifest_patterns) and
    /// [`manifest_extensions`](EcosystemBase::manifest_extensions) miss on the
    /// basename — it needs the full path, so it is never reachable from
    /// [`crate::EcosystemRegistry::for_filename`]. Empty by default.
    fn manifest_directory_patterns(&self) -> &[(&'static str, &'static str)] {
        &[]
    }

    /// Lock file filenames this ecosystem uses (e.g., ["Cargo.lock"])
    ///
    /// Used for file watching - LSP will monitor changes to these files
    /// and refresh UI when they change. Returns empty slice if ecosystem
    /// doesn't use lock files.
    ///
    /// # Default Implementation
    ///
    /// Returns empty slice by default, indicating no lock files are used.
    fn lockfile_filenames(&self) -> &[&'static str] {
        &[]
    }

    /// Non-lockfile config files this ecosystem resolves *during* [`TypedEcosystem::parse`]
    /// (e.g. `pnpm-workspace.yaml` and `.npmrc` for npm's catalog and registry resolution),
    /// whose values end up baked into a manifest's `ParseResult` rather than looked up
    /// separately the way a [`Self::lockfile_provider`] is.
    ///
    /// Used for file watching alongside [`Self::lockfile_filenames`] — LSP monitors changes
    /// to these files too, but reacts by fully re-parsing every open document of this
    /// ecosystem (not merely refreshing cached resolved versions, since the value isn't kept
    /// separately from the parse result to refresh in place). Each entry's
    /// [`WatchedConfig::effect`] tells the caller whether a routing-only edit needs a full
    /// re-fetch instead of a diff (issue #1232).
    ///
    /// # Default Implementation
    ///
    /// Returns an empty slice: no config files are watched.
    fn watched_configs(&self) -> &[WatchedConfig] {
        &[]
    }

    /// Get the registry client for this ecosystem
    ///
    /// The registry provides version lookup and package search capabilities.
    fn registry(&self) -> Arc<dyn Registry>;

    /// Get the lock file provider for this ecosystem.
    ///
    /// Returns `None` if the ecosystem doesn't support lock files.
    /// Lock files provide resolved dependency versions without network requests.
    fn lockfile_provider(&self) -> Option<Arc<dyn crate::lockfile::LockFileProvider>> {
        None
    }

    /// Subscribes to the [`RefreshEvent`](crate::RefreshEvent)s of this ecosystem.
    ///
    /// An ecosystem whose registry keeps a shared [`TagIndex`](crate::lsp_helpers::TagIndex)
    /// sends [`RefreshEvent::TagIndex`](crate::RefreshEvent::TagIndex) for a repository
    /// whenever a fetch first populates its index or changes its tag-to-commit mapping. A
    /// document that did not trigger the fetch uses it to re-evaluate findings that depend on
    /// the index (a vulnerability scan of a SHA pin only resolves once the index is warm).
    /// Background probes add [`RefreshEvent::ProbeEvidence`](crate::RefreshEvent::ProbeEvidence)
    /// (republish only) and identity changes add
    /// [`RefreshEvent::ReparseOpenDocuments`](crate::RefreshEvent::ReparseOpenDocuments). Each
    /// call returns an independent receiver; a lagged receiver must treat every repository as
    /// refreshed.
    ///
    /// The default is `None`: the ecosystem announces nothing, or its findings cannot change
    /// when anything it could announce happens.
    fn refresh_events(&self) -> Option<crate::RefreshEvents> {
        None
    }

    /// Raw-text search prefix at `position` for `deps-lsp`'s fallback (parse-failure)
    /// completion path, used when the manifest failed to parse (typically mid-edit) so
    /// [`TypedEcosystem::completions`]'s parsed-AST path has no [`ParseResult`] to work
    /// from.
    ///
    /// `content` is the whole manifest text; the implementation locates the line at
    /// `position`, decides whether that line falls inside a dependencies-like section
    /// using its own raw-text heuristic (see `deps_core::fallback_completion` for the
    /// scanners shared across ecosystems, e.g. [`crate::fallback_completion::
    /// is_in_toml_dependencies`]), and — only when it does — extracts the text the user
    /// has typed up to the cursor, stripping any manifest-syntax wrapper (a JSON
    /// string's quotes, an XML tag or attribute value) so the returned prefix is a bare
    /// candidate package-name fragment. `None` means either the cursor is not at a
    /// completable position at all, or this ecosystem's manifest format has no raw-text
    /// section boundary cheap enough to detect this way (e.g. Gradle's five manifest
    /// formats, or Swift's/Bundler's whole-file-scoped dependency calls).
    ///
    /// The caller applies its own ecosystem-agnostic guards to the returned prefix
    /// (length 2-200 chars, no `=` character) before searching the registry — this method
    /// only answers "is there a prefix here, and what manifest-syntax wrapper does it
    /// need stripped", not "is this prefix worth searching for".
    ///
    /// Default `None`: correct for every ecosystem with no raw-text section boundary.
    /// Unlike [`Self::completion_insert_text`], deliberately *not* required — a missing
    /// override only disables fallback completion for a 15th ecosystem (a feature gap),
    /// never silently emits wrong manifest syntax the way an unhandled
    /// [`Self::completion_insert_text`] arm could (see issue #118's failure mode).
    fn fallback_completion_prefix<'a>(
        &self,
        _content: &'a str,
        _position: crate::position::Position,
    ) -> Option<&'a str> {
        None
    }

    /// Manifest-syntax snippet to insert for a completed package, given its registry
    /// search `metadata` — the ecosystem-specific counterpart to
    /// [`Self::fallback_completion_prefix`]. Called only from `deps-lsp`'s raw-text
    /// fallback (parse-failure) completion path; the primary (parsed) completion path
    /// builds its own insert text via `deps_core::completion::build_package_completion`
    /// / `complete_package_names_generic` and never calls this method.
    ///
    /// Takes `&dyn Metadata` rather than separate `name`/`latest_version` parameters:
    /// an ecosystem's snippet may need more than those two fields (Swift's needs
    /// [`Metadata::repository`] to build a `.package(url:, from:)` call). Returns `None`
    /// to reject the completion entirely — e.g. a per-ecosystem gate on a structural
    /// character that would otherwise let a malicious/compromised registry response
    /// break out of the inserted snippet's syntax (Maven's coordinate-segment gate,
    /// Swift's registry-URL gate, GitHub Actions' `owner/repo` shape check). The caller
    /// (`deps-lsp`) does not log a rejection itself — an implementation that rejects a
    /// value is expected to log it via [`crate::lsp_helpers::warn_rejected_value`]
    /// first, the way Maven/Swift/GitHub Actions do inside their own overrides.
    ///
    /// Deliberately **required**, no default: a missing override here would silently
    /// insert wrong manifest syntax for whatever ecosystem forgot to implement it
    /// (exactly the failure mode issue #118 fixed for ecosystem-identity matching in
    /// general — this is the same principle applied to completion-insert syntax).
    ///
    /// The two upfront, ecosystem-agnostic gates — [`crate::lsp_helpers::
    /// is_safe_package_name`] on `metadata.name()` and [`crate::lsp_helpers::
    /// is_safe_version_string`] on `metadata.latest_version()` (whenever non-empty) —
    /// run in the caller before this method is invoked, not inside it: every ecosystem
    /// interpolates those two fields, so checking them once in `deps-lsp` avoids
    /// re-deriving the same two allowlist checks in every implementation.
    fn completion_insert_text(&self, metadata: &dyn Metadata) -> Option<String>;

    /// Whether the prefix [`Self::fallback_completion_prefix`] just returned for this
    /// `content`/`position` sits inside manifest markup that can only safely hold the
    /// bare candidate text — an already-open XML tag/attribute value, JSON object key,
    /// or TOML quoted string — rather than [`Self::completion_insert_text`]'s normal
    /// full snippet.
    ///
    /// Inserting the full snippet where markup is already open would nest a duplicate
    /// copy of it (issue #724, the original NuGet report: `Include="Newt` accepting a
    /// completion produced `Include="Newt<PackageReference Include="..." .../>`).
    /// `deps-lsp`'s fallback-completion caller checks this once per call, alongside
    /// [`Self::fallback_completion_prefix`], and routes to
    /// [`Self::fallback_bare_insert_text`] instead of [`Self::completion_insert_text`]
    /// when it returns `true`.
    ///
    /// Default `false`: correct for every ecosystem whose manifest syntax has no
    /// concept of "already open" markup around a fallback-completion cursor. Overridden
    /// today by Maven/NuGet (XML tag/attribute), npm/Composer (JSON object key), and
    /// PyPI (TOML quoted string). Not required, like [`Self::fallback_completion_prefix`]:
    /// a missing override only means a future markup-shaped ecosystem always gets the
    /// full-snippet insert, a feature gap rather than #118's "silently wrong syntax"
    /// failure mode.
    fn fallback_completion_is_bare(
        &self,
        _content: &str,
        _position: crate::position::Position,
    ) -> bool {
        false
    }

    /// Bare candidate-name text to insert when [`Self::fallback_completion_is_bare`]
    /// reports the cursor already sits inside open markup — the counterpart to
    /// [`Self::completion_insert_text`] for that case. Only called when
    /// [`Self::fallback_completion_is_bare`] returned `true` for the same
    /// `content`/`position`.
    ///
    /// Returns `None` to reject the completion entirely, the same rejection semantics
    /// as [`Self::completion_insert_text`] — e.g. Maven's `artifactId` half still needs
    /// its own [`crate::is_safe_maven_coordinate_segment`] gate here, since the two
    /// upfront ecosystem-agnostic gates the caller runs beforehand
    /// ([`crate::lsp_helpers::is_safe_package_name`] on `metadata.name()` and
    /// [`crate::lsp_helpers::is_safe_version_string`] on `metadata.latest_version()`)
    /// validate the *whole* `name`, not a substring split out of it.
    ///
    /// Default: `metadata.name()` verbatim — correct for NuGet (and any future
    /// attribute-valued ecosystem whose full snippet's name field is the bare name
    /// unmodified), since `metadata.name()` already passed the caller's
    /// `is_safe_package_name` gate before this method runs. Maven overrides this: its
    /// `name` is a `group:artifact` compound, and only the `artifact` half belongs in
    /// an already-open `<artifactId>` tag.
    fn fallback_bare_insert_text(&self, metadata: &dyn Metadata) -> Option<String> {
        Some(metadata.name().as_str().to_string())
    }

    /// Whether this ecosystem's package-name search may return a truncated view of
    /// a larger candidate set (see e.g. `PypiRegistry::search`'s doc comment).
    ///
    /// [`generate_completions`](TypedEcosystem::completions) already reports
    /// this precisely per call via [`crate::completion::Completions::is_incomplete`] whenever a real
    /// completion context is available. This method exists only for the two
    /// `deps-lsp` code paths that cannot compute that precise per-call signal
    /// because no context has been resolved yet:
    ///
    /// - the raw-text fallback search (`fallback_completion`), which always
    ///   performs a package-name lookup via `<dyn Registry>::search` regardless
    ///   of what completion context (or lack thereof) triggered it;
    /// - the document-not-loaded early return, before any `ParseResult` — and so
    ///   any completion context — exists to call `generate_completions` with.
    ///
    /// Unlike the ecosystem-wide `completions_are_incomplete()` flag this method
    /// superseded (#419, removed in #427), it never gates the *primary*
    /// `generate_completions` response — only these two context-less fallbacks.
    /// Default `false` preserves existing behavior for every ecosystem whose
    /// package-name search is always exhaustive.
    fn package_search_is_incomplete(&self) -> bool {
        false
    }

    /// Fetches `name`'s license at `version` from this ecosystem's own tier-3 license
    /// source (issue #660/#688/#697), via `deps-engine`'s shared
    /// `classify::license::prefetch_tier3_licenses`/`fetch_tier3_licenses` (issue #1133) —
    /// `deps-lsp`'s `document::osv_scan::run_license_prefetch` calls it as a background
    /// pre-fetch, and `deps-cli`'s `report::check_manifest` calls it directly before
    /// evaluating `license_policy`. Never called from `deps-lsp`'s hover critical path
    /// directly, since it may perform network I/O.
    ///
    /// Only ever called when
    /// <code>self.[license_source](Self::license_source)().[requires_dedicated_fetch](LicenseSource::requires_dedicated_fetch)()</code>
    /// is `true`; the default implementation returns an already-resolved empty result
    /// and is never actually awaited by a correctly gated caller. Overriding this
    /// without also overriding [`Self::license_source`] to a variant whose
    /// `requires_dedicated_fetch()` is `true` leaves the override dead code — nothing
    /// automated cross-checks the two methods against each other, so keeping them in
    /// sync for a new override is the implementor's responsibility.
    fn fetch_license<'a>(
        &'a self,
        _name: &'a crate::PackageName,
        _version: &'a crate::ConcreteVersion,
    ) -> BoxFuture<'a, Vec<String>> {
        Box::pin(std::future::ready(Vec::new()))
    }

    /// How this ecosystem's license strings are sourced. See [`LicenseSource`].
    ///
    /// Default [`LicenseSource::RegistryDeclaredSpdx`] is correct for every ecosystem
    /// whose license is an author-declared SPDX identifier already present in the
    /// hot-path registry response. This is also the single answer to whether
    /// [`Self::fetch_license`] is ever called for this ecosystem — see
    /// [`LicenseSource::requires_dedicated_fetch`].
    fn license_source(&self) -> LicenseSource {
        LicenseSource::RegistryDeclaredSpdx
    }

    /// Singular/plural noun for this ecosystem's bulk "Pin N {noun} to commit SHA" lens
    /// title (e.g. `{ singular: "action", plural: "actions" }` for GitHub Actions),
    /// consulted only when [`TypedEcosystem::pin_all_to_sha_edits`] returns at least one
    /// edit. Default `{ "ref", "refs" }` is a generic fallback; override to match the
    /// ecosystem's own vocabulary.
    #[cfg(feature = "lsp-responses")]
    fn pin_all_to_sha_noun(&self) -> crate::lsp_helpers::PinNoun {
        crate::lsp_helpers::PinNoun {
            singular: "ref",
            plural: "refs",
        }
    }
}

/// The type-erased view of a package ecosystem, as stored in [`crate::EcosystemRegistry`] and
/// handed to consumers as `Arc<dyn Ecosystem>`.
///
/// Its only implementation is the blanket `impl<T: TypedEcosystem> Ecosystem for T`, so an
/// ecosystem is written as an [`EcosystemBase`] plus a [`TypedEcosystem`] and can never
/// implement this trait directly. Parsing returns a [`ParsedManifest`], a document paired with
/// the ecosystem that parsed it, so no erased code ever holds a parse result apart from the
/// ecosystem and formatter that understand it.
///
/// The parse-result-free methods are inherited from [`EcosystemBase`].
pub trait Ecosystem: EcosystemBase + typed::BlanketOnly {
    /// The dependency-free formatter of this ecosystem.
    ///
    /// For anything that reads a single dependency, use the formatter bound to it by
    /// [`ParsedManifest::for_each_formatted_dependency`] instead.
    fn formatter(&self) -> &dyn EcosystemFormatter;

    /// Parses a manifest into a [`ParsedManifest`] that owns an `Arc` of this ecosystem.
    ///
    /// See [`TypedEcosystem::parse`] for the contract of the underlying parse.
    ///
    /// # Errors
    ///
    /// Returns the error [`TypedEcosystem::parse`] reports for a malformed manifest.
    fn parse_manifest<'a>(
        self: Arc<Self>,
        content: &'a str,
        uri: &'a url::Url,
    ) -> BoxFuture<'a, crate::error::Result<Box<dyn ParsedManifest>>>;

    /// Synchronous variant of [`Self::parse_manifest`], see [`TypedEcosystem::parse_sync`].
    fn parse_manifest_sync(
        self: Arc<Self>,
        content: &str,
        uri: &url::Url,
    ) -> Option<Box<dyn ParsedManifest>>;

    /// How this ecosystem's own formatter routes a dependency named `name` that resolves from
    /// `source` (see [`DependencyFormatter::non_public_route`]).
    ///
    /// The conformance probe behind `deps-engine/tests/osv_non_public_routes.rs` (#1977): it
    /// builds a real dependency of this ecosystem through [`ProbeDependency`], so a
    /// cross-ecosystem test can iterate every registered ecosystem without a synthetic
    /// dependency. Only available with the `test-util` feature, never reachable from a
    /// production build.
    ///
    /// [`DependencyFormatter::non_public_route`]: crate::lsp_helpers::DependencyFormatter::non_public_route
    /// [`ProbeDependency`]: crate::lsp_helpers::ProbeDependency
    #[cfg(any(test, feature = "test-util"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    fn probe_non_public_route(
        &self,
        name: crate::PackageName,
        source: crate::parser::DependencySource,
    ) -> crate::osv::NonPublicRoute;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "lsp-responses")]
    use crate::completion::Completions;
    use std::assert_matches;
    #[cfg(feature = "lsp-responses")]
    use tower_lsp_server::ls_types::Position;

    fn owner(dir: &str, reach: ConfigReach) -> ConfigOwner {
        ConfigOwner::new(PathBuf::from(dir), reach)
    }

    #[test]
    fn test_config_owner_subtree_covers_owner_dir_and_descendants_only() {
        let owner = owner("/work", ConfigReach::Subtree);
        assert!(owner.covers(Path::new("/work/package.json")));
        assert!(owner.covers(Path::new("/work/pkg/deep/package.json")));
        assert!(!owner.covers(Path::new("/work2/package.json")));
        assert!(!owner.covers(Path::new("/other/work/package.json")));
        assert!(!owner.covers(Path::new("/package.json")));
    }

    #[test]
    fn test_config_owner_subtree_respects_ancestor_depth_cap() {
        let owner = owner("/r", ConfigReach::Subtree);
        let within: PathBuf =
            std::iter::repeat_n("d", crate::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH - 1)
                .fold(PathBuf::from("/r"), |p, c| p.join(c))
                .join("package.json");
        assert!(owner.covers(&within));
        let beyond = within.parent().unwrap().join("d").join("package.json");
        assert!(!owner.covers(&beyond));
    }

    #[test]
    fn test_config_owner_owner_directory_covers_only_the_directory_itself() {
        let owner = owner("/work", ConfigReach::OwnerDirectory);
        assert!(owner.covers(Path::new("/work/Package.swift")));
        assert!(!owner.covers(Path::new("/work/other/Package.swift")));
        assert!(!owner.covers(Path::new("/Package.swift")));
    }

    #[test]
    fn test_config_owner_rootless_manifest_is_not_covered() {
        assert!(!owner("/", ConfigReach::Subtree).covers(Path::new("")));
    }

    #[test]
    fn test_watched_config_owner_dir_strips_every_suffix_component() {
        const NPMRC: WatchedConfig = WatchedConfig::new(
            ".npmrc",
            WatchedConfigEffect::ChangesRouting,
            ConfigReach::Subtree,
        );
        assert_eq!(
            NPMRC.owner_dir(Path::new("/a/b/.npmrc")),
            Some(Path::new("/a/b"))
        );
        assert_eq!(NPMRC.owner_dir(Path::new("/a/b/x.npmrc")), None);
        assert_eq!(NPMRC.reach(), ConfigReach::Subtree);
    }

    #[test]
    fn test_ecosystem_id_roundtrip() {
        const ALL: &[EcosystemId] = &[
            EcosystemId::Cargo,
            EcosystemId::Npm,
            EcosystemId::Pypi,
            EcosystemId::Go,
            EcosystemId::Bundler,
            EcosystemId::Dart,
            EcosystemId::Maven,
            EcosystemId::Composer,
            EcosystemId::Gradle,
            EcosystemId::Swift,
            EcosystemId::NuGet,
            EcosystemId::Deno,
            EcosystemId::GithubActions,
            EcosystemId::GitlabCi,
        ];

        for id in ALL {
            let parsed: EcosystemId = id.id().parse().unwrap();
            assert_eq!(parsed, *id);
            assert_eq!(id.to_string(), id.id());
        }
    }

    #[test]
    fn test_osv_ecosystem_mapping_pinned() {
        let expected: &[(EcosystemId, &str)] = &[
            (EcosystemId::Cargo, "crates.io"),
            (EcosystemId::Npm, "npm"),
            (EcosystemId::Pypi, "PyPI"),
            (EcosystemId::Go, "Go"),
            (EcosystemId::Bundler, "RubyGems"),
            (EcosystemId::Dart, "Pub"),
            (EcosystemId::Maven, "Maven"),
            (EcosystemId::Composer, "Packagist"),
            (EcosystemId::Gradle, "Maven"),
            (EcosystemId::Swift, "SwiftURL"),
            (EcosystemId::NuGet, "NuGet"),
            (EcosystemId::Deno, "npm"),
            (EcosystemId::GithubActions, "GitHub Actions"),
        ];

        for (id, expected_str) in expected {
            assert_eq!(
                id.osv_ecosystem().map(crate::osv::OsvEcosystem::as_str),
                Some(*expected_str),
                "unexpected OSV ecosystem string for {id:?}"
            );
        }

        // A git-tag/release pin has no OSV coordinate by name (see `osv_ecosystem`'s doc).
        assert_eq!(EcosystemId::GitlabCi.osv_ecosystem(), None);
    }

    #[test]
    fn test_ecosystem_id_from_str_unknown() {
        let err = "unknown".parse::<EcosystemId>().unwrap_err();
        assert_matches!(err, crate::error::DepsError::UnsupportedEcosystem(s) if s == "unknown");
    }

    #[test]
    fn test_ecosystem_config_default() {
        let config = EcosystemConfig::default();
        assert!(config.show_up_to_date_hints);
        assert_eq!(config.up_to_date_text, "✅");
        assert_eq!(config.needs_update_text, "❌ {}");
    }

    #[test]
    fn test_ecosystem_config_custom() {
        let config = EcosystemConfig {
            show_up_to_date_hints: false,
            up_to_date_text: "OK".to_string(),
            needs_update_text: "Update to {}".to_string(),
            loading_text: "Loading...".to_string(),
            show_loading_hints: false,
            network: crate::NetworkMode::Online,
        };
        assert!(!config.show_up_to_date_hints);
        assert_eq!(config.up_to_date_text, "OK");
        assert_eq!(config.needs_update_text, "Update to {}");
    }

    #[test]
    fn test_ecosystem_config_clone() {
        let config1 = EcosystemConfig::default();
        let config2 = config1.clone();
        assert_eq!(config1.up_to_date_text, config2.up_to_date_text);
        assert_eq!(config1.show_up_to_date_hints, config2.show_up_to_date_hints);
        assert_eq!(config1.needs_update_text, config2.needs_update_text);
    }

    #[test]
    fn test_dependency_default_features() {
        struct MockDep;
        impl Dependency for MockDep {
            fn name(&self) -> &crate::PackageName {
                static NAME: std::sync::LazyLock<crate::PackageName> =
                    std::sync::LazyLock::new(|| crate::PackageName::new("test"));
                &NAME
            }
            fn name_range(&self) -> Range {
                Range::default()
            }
            fn version_requirement(&self) -> Option<&crate::VersionReq> {
                None
            }
            fn version_range(&self) -> Option<Range> {
                None
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
        }

        let dep = MockDep;
        assert_eq!(dep.features(), &[] as &[String]);
    }

    /// Ecosystem stub for [`parse_manifest_blocking`] tests: `parse` either asserts it runs
    /// off `calling_thread` or panics, per `should_panic`.
    struct StubEcosystem {
        calling_thread: std::thread::ThreadId,
        should_panic: bool,
        /// Dependency count the parse result reports — `0` for every test except
        /// [`test_parse_manifest_blocking_caps_dependencies_over_the_ceiling`] (#796).
        dep_count: usize,
    }

    impl private::Sealed for StubEcosystem {}

    impl EcosystemBase for StubEcosystem {
        fn id(&self) -> &'static str {
            "stub"
        }

        fn ecosystem_id(&self) -> EcosystemId {
            EcosystemId::Cargo
        }

        fn display_name(&self) -> &'static str {
            "Stub"
        }

        fn manifest_filenames(&self) -> &[&'static str] {
            &[]
        }

        fn registry(&self) -> Arc<dyn crate::Registry> {
            unimplemented!()
        }

        fn completion_insert_text(&self, _metadata: &dyn crate::Metadata) -> Option<String> {
            unimplemented!()
        }
    }

    impl TypedEcosystem for StubEcosystem {
        type Parsed = crate::test_util::StubParseResult;
        type Formatter = crate::test_util::StubFormatter;

        fn own_formatter(&self) -> &Self::Formatter {
            &crate::test_util::StubFormatter::DEFAULT
        }

        fn parse<'a>(
            &'a self,
            _content: &'a str,
            uri: &'a url::Url,
        ) -> BoxFuture<'a, crate::error::Result<Self::Parsed>> {
            Box::pin(async move {
                assert!(!self.should_panic, "boom");
                assert_ne!(
                    std::thread::current().id(),
                    self.calling_thread,
                    "parse must run on the blocking pool, not the calling thread"
                );
                Ok(crate::test_util::StubParseResult::new(
                    uri.clone(),
                    self.dep_count,
                ))
            })
        }
    }

    /// #1195: the default [`TypedEcosystem::completions`] dispatch — not an ecosystem
    /// override — must stamp [`crate::completion::CompletionOrigin::PackageName`]/`Version`/
    /// `Feature` on whichever hook it dispatches to, and `Unresolved` when no
    /// [`crate::completion::CompletionContext`] resolves. This is the mapping every
    /// default-dispatch ecosystem crate (11 of 14) relies on for `deps-lsp`'s fallback gate
    /// without any code of its own.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_default_dispatch_stamps_origin_per_context() {
        use crate::completion::CompletionOrigin;
        use crate::typed_boundary::{ParsedView, TypedParseResult};

        struct OriginMockDep {
            name: Range,
            version: Range,
            features: Range,
        }
        crate::impl_unprobed_dependency!(OriginMockDep);
        impl Dependency for OriginMockDep {
            fn name(&self) -> &crate::PackageName {
                static NAME: std::sync::LazyLock<crate::PackageName> =
                    std::sync::LazyLock::new(|| crate::PackageName::new("demo"));
                &NAME
            }
            fn name_range(&self) -> Range {
                self.name
            }
            fn version_requirement(&self) -> Option<&crate::VersionReq> {
                static REQ: std::sync::LazyLock<crate::VersionReq> =
                    std::sync::LazyLock::new(|| crate::VersionReq::new("1.0"));
                Some(&REQ)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn features_range(&self) -> Option<Range> {
                Some(self.features)
            }
        }

        struct OriginMockParseResult {
            deps: [OriginMockDep; 1],
            uri: url::Url,
        }
        impl ParseResult for OriginMockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![&self.deps[0]]
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
        }
        impl TypedParseResult for OriginMockParseResult {
            type Dep = OriginMockDep;
            fn own_dependencies(&self) -> &[OriginMockDep] {
                &self.deps
            }
        }

        struct OriginMockEcosystem;
        impl private::Sealed for OriginMockEcosystem {}
        impl EcosystemBase for OriginMockEcosystem {
            fn ecosystem_id(&self) -> EcosystemId {
                EcosystemId::Cargo
            }
            fn display_name(&self) -> &'static str {
                "origin-mock"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &[]
            }
            fn registry(&self) -> Arc<dyn crate::Registry> {
                unimplemented!()
            }
            fn completion_insert_text(&self, _metadata: &dyn crate::Metadata) -> Option<String> {
                unimplemented!()
            }
        }
        impl TypedEcosystem for OriginMockEcosystem {
            type Parsed = OriginMockParseResult;
            type Formatter = crate::test_util::StubFormatter<OriginMockDep>;

            fn own_formatter(&self) -> &Self::Formatter {
                const FORMATTER: crate::test_util::StubFormatter<OriginMockDep> =
                    crate::test_util::StubFormatter::new().for_dependency();
                &FORMATTER
            }
            fn parse<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a url::Url,
            ) -> BoxFuture<'a, crate::error::Result<Self::Parsed>> {
                Box::pin(async move { unimplemented!() })
            }
            fn complete_version<'a>(
                &'a self,
                _request: crate::completion::CompletionRequest<'a, Self::Parsed>,
                _package_name: crate::PackageName,
                _prefix: String,
            ) -> BoxFuture<'a, Completions> {
                Box::pin(std::future::ready(Completions::new(vec![])))
            }
        }
        // `complete_package_name`/`complete_feature` use the trait defaults
        // (`Completions::default()`) — this test only cares about the stamped `origin`.

        let content = "demo\n1.0\nderive\n";
        let dep = OriginMockDep {
            name: Range::new(
                crate::position::Position::new(0, 0),
                crate::position::Position::new(0, 4),
            ),
            version: Range::new(
                crate::position::Position::new(1, 0),
                crate::position::Position::new(1, 3),
            ),
            features: Range::new(
                crate::position::Position::new(2, 0),
                crate::position::Position::new(2, 6),
            ),
        };
        let parse_result = OriginMockParseResult {
            deps: [dep],
            uri: crate::test_util::test_uri("/test/manifest.toml"),
        };
        let eco = OriginMockEcosystem;
        let freshness = crate::FreshnessSettings::default();
        let _: &dyn crate::lsp_helpers::EcosystemFormatter = eco.own_formatter();

        for (position, expected) in [
            (Position::new(0, 2), CompletionOrigin::PackageName),
            (Position::new(1, 1), CompletionOrigin::Version),
            (Position::new(2, 3), CompletionOrigin::Feature),
            (Position::new(3, 0), CompletionOrigin::Unresolved),
        ] {
            let result = eco
                .completions(ParsedView::new(&parse_result), position, content, freshness)
                .await;
            assert_eq!(
                result.origin, expected,
                "position {position:?} expected origin {expected:?}, got {:?}",
                result.origin
            );
        }
    }

    /// Proves `parse_manifest_blocking` actually runs the parse off the calling (async)
    /// thread via `spawn_blocking`, mirroring `lockfile.rs`'s
    /// `test_read_and_parse_lockfile_runs_parse_off_calling_thread`.
    #[tokio::test]
    async fn test_parse_manifest_blocking_runs_parse_off_calling_thread() {
        let ecosystem: Arc<dyn Ecosystem> = Arc::new(StubEcosystem {
            calling_thread: std::thread::current().id(),
            should_panic: false,
            dep_count: 0,
        });
        let uri = crate::test_util::test_uri("/test/manifest.toml");

        let parsed = parse_manifest_blocking(&ecosystem, "content", &uri)
            .await
            .unwrap();
        assert_eq!(parsed.uri(), &uri);
    }

    #[test]
    fn test_refresh_events_defaults_to_none() {
        let ecosystem = StubEcosystem {
            calling_thread: std::thread::current().id(),
            should_panic: false,
            dep_count: 0,
        };
        assert!(ecosystem.refresh_events().is_none());
    }

    #[test]
    fn test_parse_depends_on_defaults_to_reparsing_every_document() {
        let ecosystem = StubEcosystem {
            calling_thread: std::thread::current().id(),
            should_panic: false,
            dep_count: 0,
        };
        let parsed = crate::test_util::StubParseResult::new(
            crate::test_util::test_uri("/test/manifest.toml"),
            0,
        );
        assert!(ecosystem.depends_on(
            crate::typed_boundary::ParsedView::new(&parsed),
            &crate::ParseInputKey::new("any")
        ));
    }

    /// #796: `parse_manifest_blocking` is the single chokepoint every ecosystem's parse
    /// result flows through — proves it actually caps the returned manifest, not just that the
    /// manifest behaves correctly in isolation (covered by `manifest`'s own tests).
    #[tokio::test]
    async fn test_parse_manifest_blocking_caps_dependencies_over_the_ceiling() {
        let ecosystem: Arc<dyn Ecosystem> = Arc::new(StubEcosystem {
            calling_thread: std::thread::current().id(),
            should_panic: false,
            dep_count: crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT + 1,
        });
        let uri = crate::test_util::test_uri("/test/manifest.toml");

        let parsed = parse_manifest_blocking(&ecosystem, "content", &uri)
            .await
            .unwrap();

        assert_eq!(
            parsed.dependencies().len(),
            crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT
        );
        assert_eq!(
            parsed.dependency_truncation(),
            Some((
                crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT,
                crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT + 1
            ))
        );
    }

    /// A panicking `parse` must surface as `Err(DepsError::ParseError)` with the
    /// panic message preserved, mirroring `lockfile.rs`'s
    /// `test_read_and_parse_lockfile_panic_in_parse_becomes_parse_error`.
    #[tokio::test]
    async fn test_parse_manifest_blocking_panic_becomes_parse_error() {
        let ecosystem: Arc<dyn Ecosystem> = Arc::new(StubEcosystem {
            calling_thread: std::thread::current().id(),
            should_panic: true,
            dep_count: 0,
        });
        let uri = crate::test_util::test_uri("/test/manifest.toml");

        let Err(err) = parse_manifest_blocking(&ecosystem, "content", &uri).await else {
            panic!("expected parse_manifest_blocking to return an error");
        };

        match err {
            crate::error::DepsError::ParseError {
                file_type, source, ..
            } => {
                assert!(file_type.contains("manifest at"));
                assert!(
                    source.to_string().contains("boom"),
                    "panic message should be preserved in the error source, got: {source}"
                );
            }
            other => panic!("Expected ParseError, got: {other:?}"),
        }
    }

    /// Spec 076 SC-016 (T002): `parse_manifest_now` applies the SAME cap
    /// `parse_manifest_blocking`'s async path applies — a raw `now_or_never()` call
    /// site with no cap would otherwise be a second, uncapped parse entry point (round-3 critic
    /// M2, #796).
    // `#[tokio::test]` (fix-cycle security LOW-1 follow-up), not a plain `#[test]`: the new
    // runtime-handle guard in `parse_manifest_now` needs a current tokio runtime, or this would
    // fail for the wrong reason (no runtime) instead of exercising the cap.
    #[tokio::test]
    async fn test_parse_manifest_now_caps_dependencies_over_the_ceiling() {
        // `now_or_never()` polls on the CURRENT thread (no `spawn_blocking` hop), so
        // `calling_thread` is set to a different, foreign thread's id — this stub's assertion
        // exists only for `parse_manifest_blocking`'s own off-thread test above.
        let foreign_thread = std::thread::spawn(|| std::thread::current().id())
            .join()
            .unwrap();
        let ecosystem: Arc<dyn Ecosystem> = Arc::new(StubEcosystem {
            calling_thread: foreign_thread,
            should_panic: false,
            dep_count: crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT + 1,
        });
        let uri = crate::test_util::test_uri("/test/manifest.toml");

        let parsed = parse_manifest_now(&ecosystem, "content", &uri)
            .expect("an immediately-ready parse must resolve on the first poll");

        assert_eq!(
            parsed.dependencies().len(),
            crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT
        );
        assert_eq!(
            parsed.dependency_truncation(),
            Some((
                crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT,
                crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT + 1
            ))
        );
    }

    /// Spec 076 FR-024 known limitation (Composer's genuinely-awaiting `parse`):
    /// `parse_manifest_now` fails closed (`None`) rather than blocking, when the future does
    /// not resolve on its first poll. Deliberately `#[tokio::test]` (fix-cycle security LOW-1
    /// follow-up), not a plain `#[test]`: a bare `#[test]` has no current tokio runtime handle
    /// either, so it would pass for the WRONG reason (the new runtime-handle guard below, not
    /// the `Pending`-future path this test names) — see
    /// `test_parse_manifest_now_returns_none_outside_a_tokio_runtime` for that case.
    #[tokio::test]
    async fn test_parse_manifest_now_returns_none_for_a_pending_future() {
        struct PendingEcosystem;
        impl private::Sealed for PendingEcosystem {}
        impl EcosystemBase for PendingEcosystem {
            fn ecosystem_id(&self) -> EcosystemId {
                EcosystemId::Composer
            }
            fn display_name(&self) -> &'static str {
                "pending-stub"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &[]
            }
            fn registry(&self) -> Arc<dyn crate::Registry> {
                unimplemented!()
            }
            fn completion_insert_text(&self, _metadata: &dyn crate::Metadata) -> Option<String> {
                unimplemented!()
            }
        }
        impl TypedEcosystem for PendingEcosystem {
            type Parsed = crate::test_util::StubParseResult;
            type Formatter = crate::test_util::StubFormatter;

            fn own_formatter(&self) -> &Self::Formatter {
                &crate::test_util::StubFormatter::DEFAULT
            }
            fn parse<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a url::Url,
            ) -> BoxFuture<'a, crate::error::Result<Self::Parsed>> {
                Box::pin(std::future::pending())
            }
        }

        let ecosystem: Arc<dyn Ecosystem> = Arc::new(PendingEcosystem);
        let uri = crate::test_util::test_uri("/test/manifest.toml");

        assert!(parse_manifest_now(&ecosystem, "content", &uri).is_none());
    }

    /// Fix-cycle (security LOW-1): `parse_manifest_now` must fail closed (`None`), never
    /// panic, when called with no tokio runtime entered at all — reproduces the
    /// "there is no reactor running" panic security's live probe found for Composer's
    /// genuinely-awaiting path, and proves the runtime-handle guard now catches it before ever
    /// polling the future. Deliberately a plain `#[test]` (no runtime).
    #[test]
    fn test_parse_manifest_now_returns_none_outside_a_tokio_runtime() {
        let ecosystem: Arc<dyn Ecosystem> = Arc::new(StubEcosystem {
            calling_thread: std::thread::current().id(),
            should_panic: false,
            dep_count: 0,
        });
        let uri = crate::test_util::test_uri("/test/manifest.toml");

        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "this test must run with no ambient tokio runtime for the assertion below to mean \
             anything"
        );
        assert!(parse_manifest_now(&ecosystem, "content", &uri).is_none());
    }

    crate::debug_redaction_conformance!(
        test_blocked_registry_occurrence_debug_redacts_credentials,
        2,
        BlockedRegistryOccurrence {
            range: Range::default(),
            block: crate::net_policy::BlockedHost::floor(crate::net_policy::HostClass::Loopback)
                .unwrap(),
            raw_value: crate::conformance::CREDENTIAL_PROBE_URL.to_string(),
            declaration_key: crate::conformance::CREDENTIAL_PROBE_KEY.to_string(),
        },
    );

    crate::debug_redaction_conformance!(
        test_blocked_source_class_debug_redacts_credentials,
        2,
        BlockedSourceClass {
            block: crate::net_policy::BlockedHost::floor(crate::net_policy::HostClass::Loopback)
                .unwrap(),
            raw_value: crate::conformance::CREDENTIAL_PROBE_URL.to_string(),
            declaration_key: crate::conformance::CREDENTIAL_PROBE_KEY.to_string(),
        },
    );
}
