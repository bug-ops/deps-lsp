//! Ecosystem-specific formatting and comparison logic, split into concern-scoped traits.
//!
//! [`EcosystemFormatter`] is kept as a single object-safe marker bound so every existing
//! `&dyn EcosystemFormatter` call site is untouched; it is automatically implemented for any
//! type implementing all seven concern traits below via a blanket impl, so implementors never
//! write `impl EcosystemFormatter for X` themselves. The seven traits are independent siblings
//! — none of them has a default method that calls a method living in a different trait — so
//! implementing a subset of them (e.g. in a test mock that only needs [`PackageRendering`]) is
//! always sufficient for calling that subset's methods directly, without pulling in the rest.

use tower_lsp_server::ls_types::Position;

use super::{RequirementMatcher, RequirementStatus, is_same_major_minor, position_in_range};
use crate::{ConcreteVersion, Dependency, InvalidPackageName, PackageName, VersionReq};

/// Ecosystem-specific package name normalization and validation.
///
/// Implementors guarantee that [`normalize_package_name`](Self::normalize_package_name)
/// produces a stable lookup key for the same logical package regardless of how its name is
/// spelled in a manifest, and that [`validate_package_name`](Self::validate_package_name) is a
/// diagnostic lint only — never a construction-time gate. Callers may assume both methods are
/// cheap, side-effect-free, and safe to call on unvalidated, manifest-sourced input.
pub trait PackageNaming: Send + Sync {
    /// Normalize package name for lookup (default: identity).
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.to_string()
    }

    /// Lints `name` against ecosystem-specific naming rules.
    ///
    /// Default: permissive, always `Ok(())`. This is a diagnostic lint, not a
    /// construction-time gate — [`PackageName::new`](crate::PackageName::new)
    /// stays infallible regardless of what this returns. Override only to warn
    /// on names an ecosystem's own tooling would never accept; err on the side
    /// of accepting anything ambiguous, since a false positive here is a
    /// warning on a manifest the user's actual package manager treats as fine.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] carrying the reason `name` fails this
    /// ecosystem's naming rules. The default implementation never errs.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::PackageNaming;
    ///
    /// struct PermissiveFormatter;
    ///
    /// impl PackageNaming for PermissiveFormatter {}
    ///
    /// // The default is permissive: any name, including one that would fail an
    /// // ecosystem-specific override, is accepted.
    /// assert!(PermissiveFormatter.validate_package_name("../not/a/real/rule").is_ok());
    /// ```
    fn validate_package_name(&self, _name: &str) -> Result<(), InvalidPackageName> {
        Ok(())
    }
}

/// How a package/version renders into manifest text edits and hover content.
///
/// Implementors guarantee that [`format_version_for_text_edit`](Self::format_version_for_text_edit)
/// and [`package_url`](Self::package_url) — the trait's only two required methods — produce
/// text safe to embed directly in a manifest or hover response for any version/name that has
/// already passed the workspace's shared safety gates
/// ([`crate::is_safe_version_string`], [`crate::is_safe_package_name`]). Callers may assume the
/// replacement-preserving methods ([`format_version_replacing`](Self::format_version_replacing),
/// [`format_version_replacing_for`](Self::format_version_replacing_for)) never change a
/// requirement's semantics unless the ecosystem has explicitly opted in to that transformation.
pub trait PackageRendering: Send + Sync {
    /// Format version string for code action text edit.
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String;

    /// Format `version` as a replacement for the existing requirement text
    /// `current`, preserving `current`'s operator/pin style where the
    /// ecosystem supports more than one.
    ///
    /// Default: ignores `current`, delegating to
    /// [`format_version_for_text_edit`](Self::format_version_for_text_edit).
    /// Override when a bare `format_version_for_text_edit` replacement would
    /// silently change the requirement's semantics — e.g. PyPI's `==1.0.1`
    /// pin becoming `>=1.0.1,<2` on "update version" would defeat the point
    /// of pinning.
    fn format_version_replacing(&self, version: &ConcreteVersion, _current: &str) -> String {
        self.format_version_for_text_edit(version)
    }

    /// Like [`format_version_replacing`](Self::format_version_replacing), but also
    /// carries the dependency identity `version`/`current` apply to.
    ///
    /// Default: ignores `dep`, delegating to
    /// [`format_version_replacing`](Self::format_version_replacing). Override when the
    /// replacement text cannot be derived from `version`/`current` alone — e.g.
    /// `deps-github-actions`'s SHA-pinned `uses: owner/repo@<sha> # vX.Y.Z` form, where
    /// the new SHA for a given tag is looked up per `dep.name()` (a tag's commit SHA is
    /// per-repository, unknowable from the tag string alone) in a registry-populated
    /// index the formatter holds a shared handle to.
    ///
    /// Every shared call site that builds a version-update edit (the vulnerability and
    /// unsatisfiable-requirement quickfixes, the REFACTOR-loop "update to X" actions, and
    /// the "Update N outdated dependencies" code lens) already has `dep` in scope and
    /// calls this method instead of [`format_version_replacing`](Self::format_version_replacing)
    /// directly, so an override here is picked up on every edit path at once.
    fn format_version_replacing_for(
        &self,
        _dep: &dyn Dependency,
        version: &ConcreteVersion,
        current: &str,
    ) -> String {
        self.format_version_replacing(version, current)
    }

    /// Get package URL for hover markdown.
    fn package_url(&self, name: &PackageName) -> String;

    /// Whether hover should omit [`Self::package_url`]'s heading link for a dependency
    /// resolved against `source`.
    ///
    /// [`Self::package_url`] always names the ecosystem's *default* public registry (e.g.
    /// crates.io) — correct for a plain [`DependencySource::Registry`](crate::parser::DependencySource::Registry)
    /// dependency, but wrong for one resolved against a different registry entirely (e.g.
    /// `deps-cargo`'s resolved `AlternateRegistry`): once live version data from that other
    /// registry renders alongside the link, an unrelated crates.io link reads as
    /// confirmation the link is real, which is worse than showing no link at all.
    ///
    /// Default `false` — every ecosystem with only one registry concept keeps its existing
    /// hover heading unchanged; only `deps-cargo`'s `CargoFormatter` overrides this.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::PackageRendering;
    /// use deps_core::parser::DependencySource;
    /// use deps_core::{ConcreteVersion, PackageName};
    ///
    /// struct DefaultFormatter;
    /// impl PackageRendering for DefaultFormatter {
    ///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
    ///         version.to_string()
    ///     }
    ///     fn package_url(&self, name: &PackageName) -> String {
    ///         name.to_string()
    ///     }
    /// }
    ///
    /// assert!(!DefaultFormatter.suppress_package_url(&DependencySource::Registry));
    /// ```
    fn suppress_package_url(&self, source: &crate::parser::DependencySource) -> bool {
        let _ = source;
        false
    }

    /// Detect if cursor position is on a dependency for code actions.
    fn is_position_on_dependency(&self, dep: &dyn Dependency, position: Position) -> bool {
        dep.version_range()
            .is_some_and(|r| position_in_range(position, r))
    }
}

/// Requirement parsing, matching, and up-to-date status.
///
/// Implementors guarantee every method here is a pure function of its arguments — no network
/// or filesystem access — since these run on the hot hover/diagnostic path. The default
/// [`requirement_status`](Self::requirement_status) maps
/// [`requirement_is_unresolved`](Self::requirement_is_unresolved) to its `Unresolved` variant
/// and otherwise defers to [`is_requirement_up_to_date`](Self::is_requirement_up_to_date) — but
/// an override of one without the other is not a contract violation: an ecosystem whose
/// requirement syntax can be unresolved (Maven, Gradle, NuGet, `deps-github-actions`) overrides
/// `requirement_is_unresolved` precisely so `requirement_status` can distinguish "not yet
/// decidable" from "decided outdated", a distinction the boolean method has no variant for.
/// Callers needing that distinction use `requirement_status`, not the boolean method.
pub trait RequirementResolution: Send + Sync {
    /// Check if a version satisfies a requirement string.
    ///
    /// General constraint check (e.g. for completion/candidate filtering) — not the
    /// "is this dependency up to date" hook. That is `is_requirement_up_to_date` below,
    /// which has its own default and its own override points; an ecosystem whose bare
    /// requirement is a floor rather than an auto-following range (see `deps-nuget`)
    /// overrides that method, not this one.
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        // Handle caret (^) - allows changes that don't modify left-most non-zero
        // ^2.0 allows 2.x.x, ^0.2 allows 0.2.x, ^0.0.3 allows only 0.0.3
        if let Some(req) = requirement.strip_prefix('^') {
            let req_parts: Vec<&str> = req.split('.').collect();
            let ver_parts: Vec<&str> = version.split('.').collect();

            // Must have same major version
            if req_parts.first() != ver_parts.first() {
                return false;
            }

            // For ^X.Y where X > 0, any X.*.* is allowed
            if req_parts.first().is_some_and(|m| *m != "0") {
                return true;
            }

            // For ^0.Y, must have same minor
            if req_parts.len() >= 2 && ver_parts.len() >= 2 {
                return req_parts[1] == ver_parts[1];
            }

            return true;
        }

        // Handle tilde (~) - allows patch-level changes
        // ~2.0 allows 2.0.x, ~2.0.1 allows 2.0.x where x >= 1
        if let Some(req) = requirement.strip_prefix('~') {
            return is_same_major_minor(req, version);
        }

        // Plain version or partial version
        let req_parts: Vec<&str> = requirement.split('.').collect();
        let is_partial_version = req_parts.len() <= 2;

        version == requirement
            || (is_partial_version && is_same_major_minor(requirement, version))
            || (is_partial_version && version.starts_with(requirement))
    }

    /// Whether an unresolved dependency (no lock-file version) should be reported as
    /// up to date against `latest`, given its declared `requirement`.
    ///
    /// Default: `latest` satisfies `requirement` — correct for range-based ecosystems
    /// (Cargo's `^1.2`, npm's `~1.2`, ...) where the declared requirement already
    /// expresses forward compatibility, so a `latest` it accepts is not "newer" in any
    /// actionable sense. Ecosystems where a bare requirement is a minimum floor rather
    /// than an auto-following range (NuGet's bare `Version="1.0.0"`) must override this,
    /// since "does the floor accept `latest`" and "is the pin already `latest`" are
    /// different questions there.
    fn is_requirement_up_to_date(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> bool {
        self.version_satisfies_requirement(latest, requirement.as_str())
    }

    /// Whether `requirement` could not be resolved to a concrete version constraint (e.g. an
    /// unexpanded property/variable placeholder rather than a real version or range).
    ///
    /// Default: always resolvable. Ecosystems whose requirement syntax can contain
    /// unresolved placeholders (Maven's `${property}`, Gradle's `$var`/`${var}`) override
    /// this single predicate; both `version_satisfies_requirement`'s "treat as satisfied"
    /// short-circuit and `requirement_status`'s `Unresolved` variant are derived from it, so
    /// the two can't drift out of sync with each other.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::RequirementResolution;
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(!DefaultFormatter.requirement_is_unresolved(&VersionReq::new("^1.2")));
    /// ```
    fn requirement_is_unresolved(&self, _requirement: &VersionReq) -> bool {
        false
    }

    /// Tri-state variant of `is_requirement_up_to_date` that distinguishes "confirmed up to
    /// date" from "could not be resolved, so we don't know."
    ///
    /// Default: `Unresolved` when `requirement_is_unresolved` says so, otherwise maps the
    /// boolean result of `is_requirement_up_to_date` to `UpToDate`/`Outdated`. Callers
    /// needing the distinction — inlay hints, in particular — use this instead of
    /// `is_requirement_up_to_date` so they can tell "verified up to date" apart from
    /// "resolution failed."
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{RequirementResolution, RequirementStatus};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert_eq!(
    ///     DefaultFormatter.requirement_status(&VersionReq::new("^1.2"), &ConcreteVersion::new("1.5.0")),
    ///     RequirementStatus::UpToDate
    /// );
    /// assert_eq!(
    ///     DefaultFormatter.requirement_status(&VersionReq::new("^1.2"), &ConcreteVersion::new("2.0.0")),
    ///     RequirementStatus::Outdated
    /// );
    /// ```
    fn requirement_status(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        if self.requirement_is_unresolved(requirement) {
            return RequirementStatus::Unresolved;
        }
        if self.is_requirement_up_to_date(requirement, latest) {
            RequirementStatus::UpToDate
        } else {
            RequirementStatus::Outdated
        }
    }

    /// Like [`requirement_status`](Self::requirement_status), but also hands the ecosystem
    /// the dependency itself — for an ecosystem whose requirement *text* alone is ambiguous
    /// between two shapes with different resolution rules, and which already computed the
    /// disambiguating classification once, at parse time, onto the dependency (`deps-gitlab-ci`'s
    /// `PinStyle`, #466 review M-c: a bare `"1.2"` is `Partial` under its `component:` pin
    /// grammar but `Branch` under its simpler `project:` ref grammar — indistinguishable from
    /// the text alone).
    ///
    /// Default: forwards to [`requirement_status`](Self::requirement_status), ignoring `dep`
    /// — every other ecosystem's requirement text alone is unambiguous, so this is a no-op
    /// for them. Callers that already have `dep` in hand (the diagnostic pipeline's outdated
    /// rule) call this instead of `requirement_status` directly, mirroring
    /// `Registry::select_latest_matching_with_context`'s identical additive-default pattern.
    fn requirement_status_for(
        &self,
        dep: &dyn Dependency,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        let _ = dep;
        self.requirement_status(requirement, latest)
    }

    /// Compiles `requirement` into a matcher for precise membership testing against a list
    /// of candidate version strings, or `None` when this ecosystem cannot parse or cannot
    /// model this requirement form — in which case no unsatisfiable-requirement diagnostic
    /// is produced for it.
    ///
    /// Distinct from `version_satisfies_requirement`, which answers the looser "treat as up
    /// to date" question and is deliberately permissive (see that method's docs). This one
    /// gates a WARNING diagnostic claiming "no published version satisfies this
    /// requirement", so it must never guess: an ecosystem that has not opted in by
    /// overriding this method emits no such diagnostic at all, rather than one derived from
    /// a loose heuristic.
    ///
    /// `None` has two distinct causes, both correct to suppress the diagnostic for: the
    /// requirement string fails to parse under this ecosystem's own comparator (`deps-cargo`,
    /// `deps-npm`, `deps-pypi`, `deps-swift` — `.ok()` on a fallible parse), or the
    /// requirement parses fine but names a version-space region the fetched `available` list
    /// structurally cannot contain regardless — a Go pseudo-version, a Composer
    /// dev-branch/`@dev` flag, a RubyGems exact pin indistinguishable from one that matches
    /// only a yanked release, a malformed Maven/Gradle/NuGet range. Scanning either case would
    /// always decide `Some(false)` for every candidate, producing a false "no published
    /// version satisfies" verdict instead of correctly suppressing the check. Implementors of
    /// the second (predicate-guard) shape should use
    /// [`crate::lsp_helpers::compile_requirement_unless`], which
    /// centralizes this contract instead of re-deriving it per ecosystem. `deps-dart` is the
    /// only ecosystem with neither cause: every requirement string is a valid Dart constraint
    /// by construction, so its override is always `Some`.
    ///
    /// Default: `None` — an ecosystem that has not opted in emits no unsatisfiable-requirement
    /// diagnostics.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::RequirementResolution;
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(
    ///     DefaultFormatter
    ///         .compile_requirement(&VersionReq::new("^1.2"))
    ///         .is_none()
    /// );
    /// ```
    fn compile_requirement(
        &self,
        _requirement: &VersionReq,
    ) -> Option<Box<dyn RequirementMatcher>> {
        None
    }

    /// Whether this ecosystem's registry can silently omit a *published* version from
    /// `available` in a way indistinguishable from "never published" — and, if so, whether
    /// `requirement` names a version-space region that specific omission could explain, given
    /// the versions actually observed in `available`.
    ///
    /// Called by [`crate::lsp_helpers::requirement_is_unsatisfiable`] before compiling `requirement`; returning
    /// `true` suppresses the "no published version satisfies this requirement" diagnostic for
    /// this dependency, the same as [`Self::compile_requirement`] returning `None` — but,
    /// unlike that method, this one sees `available` and can therefore narrow the suppression
    /// instead of disabling it for every requirement of a given shape.
    ///
    /// Default `false` — no ecosystem has this problem unless it opts in. `deps-bundler`
    /// overrides it (see `BundlerFormatter::requirement_is_undecidable_given_available` and
    /// its helper for the RubyGems-specific rationale and heuristic).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::RequirementResolution;
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(!DefaultFormatter.requirement_is_undecidable_given_available(
    ///     &VersionReq::new("1.6.13"),
    ///     &[ConcreteVersion::new("1.6.9"), ConcreteVersion::new("1.6.14")],
    /// ));
    /// ```
    fn requirement_is_undecidable_given_available(
        &self,
        _requirement: &VersionReq,
        _available: &[ConcreteVersion],
    ) -> bool {
        false
    }

    /// Whether `dep`'s manifest version-requirement line is itself the exact
    /// version already selected — never a range.
    ///
    /// True only for a Go `require`-directive dependency: `go.mod`'s
    /// `require` line already holds the module version selected by Go's
    /// MVS, unlike Cargo/npm where the manifest holds a range and the lock
    /// file holds the pin. When true, hover and inlay hints prefer
    /// [`Dependency::version_requirement`] over the lock-file-derived entry
    /// in [`crate::lsp_helpers::VersionData::resolved`], because `go.sum` is a checksum ledger
    /// that `go get`/`go build` only ever append to (only `go mod tidy`
    /// prunes it) — a stale, no-longer-selected higher version can remain
    /// recorded there after a downgrade and, since go.sum is written sorted
    /// ascending by semver, always sorts last and wins naive
    /// last-occurrence-wins parsing (overridden in `deps-go`; see `#235`).
    ///
    /// Takes `dep` (precedent: [`OsvNaming::osv_package_name`]) because Go's
    /// `exclude`/`replace` directives are also surfaced as dependencies
    /// whose `version_requirement()` is *not* an in-use version (the
    /// excluded version, or the replaced-from version) — the `deps-go`
    /// override inspects the directive kind and returns `true` only for
    /// `require`.
    fn manifest_requirement_is_resolved_version(&self, dep: &dyn Dependency) -> bool {
        let _ = dep;
        false
    }
}

/// Static wording for diagnostics and hover about yanked/deprecated package state.
///
/// Implementors guarantee every method here returns a `'static` string with no per-call
/// computation — this is display copy, not logic — so callers may cache or repeat these
/// values freely across an entire diagnostics pass without re-invoking the formatter.
pub trait DiagnosticMessages: Send + Sync {
    /// Message for yanked/deprecated versions in diagnostics.
    fn yanked_message(&self) -> &'static str {
        "This version has been yanked"
    }

    /// Label for yanked versions in hover.
    fn yanked_label(&self) -> &'static str {
        "*(yanked)*"
    }

    /// Message for a package-level deprecation/abandonment diagnostic (issue #205).
    ///
    /// Distinct from [`Self::yanked_message`]: that one describes a single flagged
    /// *version*, this one describes the *package* being deprecated/abandoned/archived.
    /// Default wording is generic; `ComposerFormatter` overrides both this and
    /// [`Self::deprecated_label`] to "abandoned", matching Packagist's own vocabulary —
    /// the same pattern it already applies to the yanked pair.
    fn deprecated_message(&self) -> &'static str {
        "This package is deprecated"
    }

    /// Label for a deprecated package in hover.
    fn deprecated_label(&self) -> &'static str {
        "*(deprecated)*"
    }
}

/// Per-ecosystem opt-outs for which diagnostics apply to which dependency/requirement shapes.
///
/// Implementors guarantee these hooks only ever narrow or disable a diagnostic a shared,
/// ecosystem-agnostic pass would otherwise emit unconditionally — never widen or fabricate one.
/// An override does not always mean "this ecosystem is broken": `NpmFormatter` returns `false`
/// from [`yanked_diagnostic_applies_to`](Self::yanked_diagnostic_applies_to) unconditionally not
/// because the underlying signal is wrong, but to avoid duplicating the separate #205
/// package-level deprecation diagnostic that would otherwise fire alongside it.
pub trait DiagnosticPolicy: Send + Sync {
    /// Whether this ecosystem's requirement/version syntax follows strict SemVer 2.0.0
    /// pre-release semantics: a pre-release version (`X.Y.Z-pre`) is excluded from matching
    /// `requirement` unless `requirement` itself pins to the same `X.Y.Z` tuple with a
    /// pre-release tag — the rule Cargo's `semver` crate and npm's `node-semver` both
    /// implement, and that `compile_requirement`'s matcher inherits from its underlying
    /// comparator.
    ///
    /// Used by [`crate::lsp_helpers::requirement_is_unsatisfiable`]'s caller in `generate_diagnostics_from_cache`
    /// to decide whether the unsatisfiable-requirement WARNING should be enriched with a
    /// mention of a published pre-release that would satisfy `requirement` if pre-release
    /// exclusion were relaxed (#299). Maven/NuGet/Composer/Gradle use non-strict,
    /// ecosystem-specific range models where this premise does not hold — they must not
    /// override this.
    ///
    /// Default `false`. `deps-cargo`, `deps-npm`, and `deps-swift` override this to `true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::DiagnosticPolicy;
    ///
    /// struct DefaultFormatter;
    /// impl DiagnosticPolicy for DefaultFormatter {}
    ///
    /// assert!(!DefaultFormatter.strict_semver_prerelease_exclusion());
    /// ```
    fn strict_semver_prerelease_exclusion(&self) -> bool {
        false
    }

    /// Whether this ecosystem's deprecation payload ([`crate::Deprecation::replacement`])
    /// is safe to offer as a "Replace with X" rename quickfix.
    ///
    /// Default `false`. Only an ecosystem whose replacement name comes from a
    /// **structured, registry-validated** field may override this to `true` — never one
    /// synthesized by parsing free text, which is a typosquatting vector (npm's
    /// `deprecated` message names a successor only in prose). `ComposerFormatter`
    /// overrides this to `true`: Packagist's `abandoned` replacement is a real package
    /// name field, not extracted text.
    fn supports_package_rename(&self) -> bool {
        false
    }

    /// Whether the "requirement satisfiable only by a yanked version" diagnostic
    /// (`crate::lsp_helpers::requirement_matches_only_yanked`) should evaluate `requirement`
    /// at all for this ecosystem.
    ///
    /// Default `true` — no restriction, every requirement shape is checked. Override to
    /// `false` for a requirement shape (or, returning `false` unconditionally, for every
    /// requirement) where this diagnostic would duplicate a more specific one, or where this
    /// ecosystem's `Version::removal_status()` is not a reliable enough per-version signal.
    /// This is independent of
    /// [`Registry::reports_yanked`](crate::Registry::reports_yanked): that flag gates whether
    /// `removal_status()` data is trusted at all (and thus whether the separate #263
    /// in-use-version yanked check runs), while this hook only narrows *this* diagnostic.
    ///
    /// `dep` is passed alongside `requirement` (rather than `requirement` alone) so an
    /// implementor can key its decision off the dependency's package name — needed by
    /// `DenoFormatter` (#448) to tell its `jsr:`- and `npm:`-scheme specifiers apart, since
    /// the scheme lives in the name, not in the requirement text. At the sole call site
    /// (`crate::lsp_helpers::diagnostics::generate_diagnostics_from_cache`), `requirement`
    /// is always `dep.version_requirement().unwrap()` for the same `dep` — the two are
    /// never independent, though an implementor is free to key off either or both.
    ///
    /// `DenoFormatter` returns `false` unconditionally for `npm:` specifiers, mirroring
    /// `NpmFormatter` (#448), and applies unconditionally (`true`, the same as leaving this
    /// hook at its default) for `jsr:` specifiers, for any requirement shape (#454): unlike
    /// npm's `deprecated`, JSR's `yanked` flag is a genuine per-version signal with no
    /// package-level deprecation diagnostic to conflate with, so `jsr:` needs no restriction
    /// here at all — see that formatter's docs. `NpmFormatter` returns `false`
    /// unconditionally (#436): npm's `AdvisoryDeprecated` is genuinely per-version but
    /// commonly applied package-wide, so even an exact pin would often just duplicate the
    /// dedicated package-level deprecation diagnostic ([`DiagnosticMessages::deprecated_message`],
    /// issue #205); npm keeps `reports_yanked() == true`; so the #263 in-use-version check
    /// stays live. `ComposerFormatter` does not override this hook at all — it opts out at
    /// the registry level instead
    /// ([`Registry::reports_yanked`](crate::Registry::reports_yanked) `== false`, pre-dating
    /// #436, independently justified by #233 R2): Packagist's `abandoned` is package-level via
    /// p2 minified inheritance, so its yanked map is never populated and this hook has nothing
    /// to restrict.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::DiagnosticPolicy;
    /// use deps_core::{Dependency, PackageName, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl DiagnosticPolicy for DefaultFormatter {}
    ///
    /// # struct FakeDep(PackageName);
    /// # impl Dependency for FakeDep {
    /// #     fn name(&self) -> &PackageName {
    /// #         &self.0
    /// #     }
    /// #     fn name_range(&self) -> tower_lsp_server::ls_types::Range {
    /// #         tower_lsp_server::ls_types::Range::default()
    /// #     }
    /// #     fn version_requirement(&self) -> Option<&VersionReq> {
    /// #         None
    /// #     }
    /// #     fn version_range(&self) -> Option<tower_lsp_server::ls_types::Range> {
    /// #         None
    /// #     }
    /// #     fn source(&self) -> deps_core::parser::DependencySource {
    /// #         deps_core::parser::DependencySource::Registry
    /// #     }
    /// #     fn as_any(&self) -> &dyn std::any::Any {
    /// #         self
    /// #     }
    /// # }
    /// #
    /// let dep = FakeDep(PackageName::new("example"));
    /// assert!(DefaultFormatter.yanked_diagnostic_applies_to(&dep, &VersionReq::new("^1.2")));
    /// ```
    fn yanked_diagnostic_applies_to(
        &self,
        _dep: &dyn Dependency,
        _requirement: &VersionReq,
    ) -> bool {
        true
    }
}

/// What a [`DependencySource`](crate::parser::DependencySource) may be used for: resolution,
/// vulnerability scanning, and cache-key/link trust.
///
/// Implementors guarantee [`can_resolve_source`](Self::can_resolve_source) and
/// [`source_is_public_registry_content`](Self::source_is_public_registry_content) answer
/// independent questions — a source can be resolvable without being public-registry content
/// (e.g. a non-mirroring alternate registry), so callers must not assume one implies the
/// other.
pub trait SourcePolicy: Send + Sync {
    /// Whether this ecosystem's registry can resolve version data for `source`.
    ///
    /// Hover, diagnostics, and code actions gate every registry lookup on this instead of
    /// [`crate::parser::DependencySource::is_version_resolvable`] directly, so an ecosystem
    /// whose `Registry` implementation routes *more* sources than the generic
    /// crates.io-shaped default (e.g. `deps-cargo`'s `CargoRegistry`, which additionally
    /// resolves a `DependencySource::AlternateRegistry` against a private sparse index) can
    /// opt those sources in without widening the `Registry` trait itself or touching any of
    /// this hook's call sites.
    ///
    /// Default: delegates to
    /// [`DependencySource::is_version_resolvable`](crate::parser::DependencySource::is_version_resolvable),
    /// so every ecosystem that does not override this method keeps its exact pre-existing
    /// resolvability answer.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::SourcePolicy;
    /// use deps_core::parser::DependencySource;
    ///
    /// struct DefaultFormatter;
    /// impl SourcePolicy for DefaultFormatter {}
    ///
    /// assert!(DefaultFormatter.can_resolve_source(&DependencySource::Registry));
    /// assert!(!DefaultFormatter.can_resolve_source(&DependencySource::AlternateRegistry {
    ///     index: "https://index.mycorp.dev".into(),
    ///     mirrors_crates_io: false,
    /// }));
    /// ```
    fn can_resolve_source(&self, source: &crate::parser::DependencySource) -> bool {
        source.is_version_resolvable()
    }

    /// Whether `source`'s content is exactly the default public registry's — safe to treat
    /// as such for OSV vulnerability scanning, cache-key signature construction, and hover
    /// heading links.
    ///
    /// Default `matches!(source, DependencySource::Registry)` — every ecosystem with only
    /// one registry concept keeps its existing behavior. `deps-cargo`'s `CargoFormatter`
    /// overrides this to also accept `AlternateRegistry { mirrors_crates_io: true, .. }`:
    /// Cargo verifies per-version checksum equality against crates.io for a
    /// `[source.crates-io] replace-with` mirror, so its content is exactly as trustworthy as
    /// crates.io's own, even though the fetch itself goes to the mirror's index, not to
    /// crates.io (plan `.local/specs/023-cargo-custom-registries/plan-1b.md` §1.3, F1/F1b/F2).
    ///
    /// Deliberately distinct from [`Self::can_resolve_source`]: an `AlternateRegistry` that
    /// is *not* a crates.io mirror is resolvable (this LSP can fetch its version data) but is
    /// not public-registry content (its data must not be treated as crates.io's own for
    /// vulnerability-advisory or link purposes) — the two questions are orthogonal, and a
    /// single hook conflating them would force every non-Cargo ecosystem to answer a
    /// mirror-specific question it has no concept of.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::SourcePolicy;
    /// use deps_core::parser::DependencySource;
    ///
    /// struct DefaultFormatter;
    /// impl SourcePolicy for DefaultFormatter {}
    ///
    /// assert!(DefaultFormatter.source_is_public_registry_content(&DependencySource::Registry));
    /// assert!(!DefaultFormatter.source_is_public_registry_content(&DependencySource::AlternateRegistry {
    ///     index: "https://index.mycorp.dev".into(),
    ///     mirrors_crates_io: true,
    /// }));
    /// ```
    fn source_is_public_registry_content(&self, source: &crate::parser::DependencySource) -> bool {
        matches!(source, crate::parser::DependencySource::Registry)
    }
}

/// Native <-> OSV.dev namespace bridging for package names and version strings.
///
/// Implementors guarantee every method is the identity transform unless this ecosystem's
/// native naming/versioning genuinely diverges from OSV.dev's own convention for it — callers
/// (the OSV scan-target builder and advisory matcher) rely on the defaults being safe no-ops
/// for the common case of an ecosystem with no such divergence.
pub trait OsvNaming: Send + Sync {
    /// OSV.dev's canonical spelling for `dep`'s package name, or `None` if
    /// this dependency cannot be mapped (e.g. a non-GitHub Swift package).
    ///
    /// Deliberately **not** routed through [`PackageNaming::normalize_package_name`]:
    /// that method produces this project's internal lookup key, while this
    /// one produces the name sent on the wire to OSV. They coincide for most
    /// ecosystems and diverge for NuGet (case-preserving; normalizing would
    /// lowercase it and zero out results), Composer (OSV wants lowercase,
    /// overridden in `deps-composer`), and Swift (prefixed to
    /// `github.com/{owner}/{repo}`, overridden in `deps-swift`). Takes
    /// `&dyn Dependency` rather than `&str` because the Swift override needs
    /// to downcast to inspect the dependency's source URL host — see
    /// `architecture.md` §2.
    ///
    /// The default implementation is the identity: OSV is case-sensitive in
    /// every ecosystem this project supports except PyPI, and for Cargo, npm,
    /// Go, Maven, Gradle, Dart, Bundler, NuGet, and PyPI the manifest's raw
    /// name already matches OSV's canonical spelling.
    fn osv_package_name(&self, dep: &dyn Dependency) -> Option<String> {
        Some(dep.name().to_string())
    }

    /// Converts a version string as it appears in an OSV advisory record
    /// (e.g. [`crate::osv::Advisory::fixed_versions`]) into this ecosystem's
    /// own version namespace, as used in manifests and by the registry.
    ///
    /// Default: identity — correct for ecosystems whose OSV records carry
    /// the native version string verbatim. Override when OSV's namespace
    /// diverges from the native one (Go module versions carry a `v` prefix
    /// that OSV's SEMVER ranges never use).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::OsvNaming;
    ///
    /// struct DefaultFormatter;
    /// impl OsvNaming for DefaultFormatter {}
    ///
    /// assert_eq!(DefaultFormatter.osv_version_to_native("1.2.3"), "1.2.3");
    /// ```
    fn osv_version_to_native(&self, version: &str) -> String {
        version.to_string()
    }

    /// Rewrites a native-ecosystem version string into the spelling OSV.dev's
    /// SEMVER range matching expects.
    ///
    /// Deliberately the inverse of [`Self::osv_package_name`] rather than a
    /// field on [`crate::osv::ScanTarget`] itself: the caller (`deps-lsp`'s
    /// scan-target builder) has only the native version string at hand, so
    /// each ecosystem's formatter is the natural place to own the transform.
    /// The default implementation is the identity: OSV accepts every
    /// supported ecosystem's native version spelling unchanged except Go,
    /// whose module versions carry a mandatory `v` prefix
    /// (`golang.org/x/mod/module` convention) that OSV's SEMVER matcher
    /// rejects — overridden in `deps-go` to strip it.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::OsvNaming;
    ///
    /// struct DefaultFormatter;
    /// impl OsvNaming for DefaultFormatter {}
    ///
    /// assert_eq!(DefaultFormatter.osv_version("1.2.3"), "1.2.3");
    /// ```
    fn osv_version(&self, version: &str) -> String {
        version.to_string()
    }
}

/// Umbrella marker for a complete ecosystem formatter.
///
/// This trait is intentionally empty: it exists only so `&dyn EcosystemFormatter` keeps
/// working as a single trait-object type at every existing call site
/// (`Ecosystem::formatter`, hover, diagnostics, code actions, code lenses, inlay hints,
/// in-use-version resolution, and OSV scan-target construction). Implementors never write
/// `impl EcosystemFormatter for X` directly — the blanket impl below supplies it
/// automatically for any type implementing all seven concern traits
/// ([`PackageNaming`], [`PackageRendering`], [`RequirementResolution`],
/// [`DiagnosticMessages`], [`DiagnosticPolicy`], [`SourcePolicy`], [`OsvNaming`]). To add a
/// new ecosystem formatter, implement those seven traits; to call one specific behavior
/// (e.g. in a test mock), implement only the trait that owns it.
pub trait EcosystemFormatter:
    PackageNaming
    + PackageRendering
    + RequirementResolution
    + DiagnosticMessages
    + DiagnosticPolicy
    + SourcePolicy
    + OsvNaming
{
}

impl<
    T: PackageNaming
        + PackageRendering
        + RequirementResolution
        + DiagnosticMessages
        + DiagnosticPolicy
        + SourcePolicy
        + OsvNaming,
> EcosystemFormatter for T
{
}
