//! Wire types for the OSV.dev batch and single-query APIs, and the
//! `deps-lsp`-facing types derived from them.
//!
//! The wire types deliberately mirror OSV's schema sparsely: every optional
//! field uses `#[serde(default)]` because OSV records are sparse and the
//! schema evolves, and a missing field must never fail the whole response
//! (see `architecture.md` §6).

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::ConcreteVersion;
use crate::lsp_helpers::is_safe_version_string;

/// The `package.ecosystem` value OSV.dev expects for a queried [`crate::EcosystemId`]
/// (`crate::EcosystemId::osv_ecosystem`'s return type).
///
/// An exhaustive enum rather than `&'static str` (project rule: closed value sets are typed,
/// not stringly-typed): the 11 OSV ecosystem names this crate actually queries with. Not every
/// [`crate::EcosystemId`] variant has one — `GitlabCi` maps to `None` in
/// `crate::EcosystemId::osv_ecosystem` — and this enum only enumerates the ones that do.
/// [`Self::as_str`] is the single conversion to OSV's wire spelling, used at request-body
/// construction and inbound `package.ecosystem` string comparisons.
///
/// # Examples
///
/// ```
/// use deps_core::EcosystemId;
/// use deps_core::osv::OsvEcosystem;
///
/// assert_eq!(EcosystemId::Cargo.osv_ecosystem(), Some(OsvEcosystem::CratesIo));
/// assert_eq!(OsvEcosystem::CratesIo.as_str(), "crates.io");
/// ```
///
/// `PartialOrd`/`Ord` are derived (declaration order, which carries no meaning of its own)
/// only because [`crate::osv::OsvClient`]'s `query_cache` key tuple includes an
/// `OsvEcosystem` and its `Ord`-bounded eviction heap (`cache_policy::evict_oldest_batch`)
/// needs *some* total order to break ties — mirroring [`OsvVersion`]'s identical rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OsvEcosystem {
    /// `crates.io` — Rust/Cargo.
    CratesIo,
    /// `npm` — shared by npm and Deno's `npm:` specifiers.
    Npm,
    /// `PyPI` — Python.
    PyPI,
    /// `Go` — Go modules.
    Go,
    /// `RubyGems` — Bundler.
    RubyGems,
    /// `Pub` — Dart.
    Pub,
    /// `Maven` — shared by Maven and Gradle.
    Maven,
    /// `Packagist` — PHP Composer.
    Packagist,
    /// `SwiftURL` — Swift Package Manager.
    SwiftURL,
    /// `NuGet` — .NET.
    NuGet,
    /// `GitHub Actions` — GitHub Actions workflows.
    GitHubActions,
}

impl OsvEcosystem {
    /// OSV.dev's wire spelling for this ecosystem — the only conversion point to a plain
    /// string, used at the HTTP request-body boundary and for comparing against
    /// `OsvPackage::ecosystem` (a `String` since it is deserialized from arbitrary
    /// OSV-supplied values, not produced from this enum).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CratesIo => "crates.io",
            Self::Npm => "npm",
            Self::PyPI => "PyPI",
            Self::Go => "Go",
            Self::RubyGems => "RubyGems",
            Self::Pub => "Pub",
            Self::Maven => "Maven",
            Self::Packagist => "Packagist",
            Self::SwiftURL => "SwiftURL",
            Self::NuGet => "NuGet",
            Self::GitHubActions => "GitHub Actions",
        }
    }

    /// How OSV.dev evaluates a queried version for this ecosystem — the single place a new
    /// ecosystem is forced (by exhaustiveness) to declare whether the server can be trusted to
    /// version-match, or whether affected ranges must be matched locally (issue #1675).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{OsvEcosystem, VersionMatching};
    ///
    /// assert_eq!(OsvEcosystem::CratesIo.version_matching(), VersionMatching::ServerSide);
    /// assert_eq!(OsvEcosystem::GitHubActions.version_matching(), VersionMatching::LocalUnversioned);
    /// ```
    #[must_use]
    pub const fn version_matching(self) -> VersionMatching {
        match self {
            Self::CratesIo
            | Self::Npm
            | Self::PyPI
            | Self::Go
            | Self::RubyGems
            | Self::Pub
            | Self::Maven
            | Self::Packagist
            | Self::SwiftURL
            | Self::NuGet => VersionMatching::ServerSide,
            Self::GitHubActions => VersionMatching::LocalUnversioned,
        }
    }
}

/// Where an [`OsvEcosystem`]'s queried version is matched against advisory ranges.
///
/// OSV.dev returns `{}` for a `version`-carrying query in the `GitHub Actions` ecosystem even
/// when the version is inside an advisory's affected range (issue #1675), so a versioned query
/// there reads as a false "clean". [`Self::LocalUnversioned`] ecosystems are queried without
/// `version` and matched locally against each record's `affected[].ranges`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionMatching {
    /// OSV.dev matches `version` server-side; the query carries it.
    ServerSide,
    /// The query omits `version`; advisory ranges are matched locally against the in-use version.
    LocalUnversioned,
}

/// A version string in OSV.dev's own wire spelling — distinct from [`ConcreteVersion`], the
/// ecosystem-native spelling, so the two can never be silently swapped at a call site
/// (issue #1423).
///
/// The two spellings coincide for every ecosystem except Go, where OSV's SEMVER ranges never
/// carry the mandatory `v` prefix `go.mod` requires — [`crate::lsp_helpers::OsvNaming::osv_version`]
/// and [`crate::lsp_helpers::OsvNaming::osv_version_to_native`] are the only sanctioned
/// conversions between the two.
///
/// # Examples
///
/// ```
/// use deps_core::osv::OsvVersion;
///
/// let version = OsvVersion::new("1.2.3");
/// assert_eq!(version.as_str(), "1.2.3");
/// assert_eq!(version, "1.2.3");
/// ```
///
/// `PartialOrd`/`Ord` are derived (raw byte-string order, unlike sibling newtypes such as
/// [`ConcreteVersion`] or `VulnKey`, which derive neither) only because
/// [`crate::osv::OsvClient`]'s `query_cache` key tuple includes an `OsvVersion` and its
/// `Ord`-bounded eviction heap (`cache_policy::evict_oldest_batch`) needs *some* total order to
/// break ties, not a version-semantic one. Never use this ordering to compare two versions —
/// go through `compare_version_strings` (or an ecosystem's own parser) for that.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OsvVersion(String);

impl OsvVersion {
    /// Wraps `value` as an `OsvVersion`, unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::OsvVersion;
    ///
    /// let version = OsvVersion::new(String::from("1.0.0"));
    /// assert_eq!(version.as_str(), "1.0.0");
    /// ```
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the OSV wire version as a string slice.
    ///
    /// Kept `pub` (not narrowed to `pub(crate)`) because a real ecosystem's own
    /// [`crate::lsp_helpers::OsvNaming`] override lives in a *different* crate
    /// (`deps-go::formatter::GoFormatter`) and needs the raw wire text to compute its native
    /// spelling — the same reason [`ConcreteVersion::as_str`] stays `pub`. This does not
    /// reopen the swap risk [`OsvVersion`] exists to close: the type-level distinction
    /// prevents a wire value from being passed where a native one is expected (or vice versa)
    /// at a function boundary; `as_str` only lets already-correctly-typed code read the bytes
    /// it already has, the same escape hatch every string newtype in this crate exposes
    /// (`ConcreteVersion`, `PackageName`, `RedactedUrl`, ...).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::OsvVersion;
    ///
    /// let version = OsvVersion::new("4.5.6");
    /// assert_eq!(version.as_str(), "4.5.6");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the `OsvVersion`, returning the wrapped `String`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::OsvVersion;
    ///
    /// let version = OsvVersion::new("4.5.6");
    /// let owned: String = version.into_string();
    /// assert_eq!(owned, "4.5.6");
    /// ```
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for OsvVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for OsvVersion {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for OsvVersion {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl AsRef<str> for OsvVersion {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for OsvVersion {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for OsvVersion {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// OSV's canonical package name for one dependency — the spelling sent on the wire and matched
/// against `affected[].package.name` in a returned record.
///
/// Distinct from the project-internal lookup key (`VulnKey`) and the ecosystem-native name
/// (`PackageName`): the transform between them is not round-trippable (Swift `owner/repo` ->
/// `github.com/owner/repo`; Composer lowercased), so a bare `String` would let a native name be
/// passed where the wire name is required. Deliberately has no `From<String>`/`From<&str>`:
/// construction goes through [`OsvPackageName::new`] only, so every wrap is greppable, and it
/// rejects an empty name: OSV answers a `querybatch` containing one empty package name with
/// HTTP 400 for the *whole* batch, dropping every sibling's advisories (issue #1678).
///
/// # Examples
///
/// ```
/// use deps_core::osv::OsvPackageName;
///
/// let name = OsvPackageName::new("github.com/apple/swift-nio").unwrap();
/// assert_eq!(name.as_str(), "github.com/apple/swift-nio");
/// assert_eq!(name, "github.com/apple/swift-nio");
/// assert!(OsvPackageName::new("").is_err());
/// ```
///
/// `PartialOrd`/`Ord` are derived (raw byte-string order) only because
/// [`crate::osv::OsvClient`]'s `query_cache` key tuple includes an `OsvPackageName` and its
/// `Ord`-bounded eviction heap needs *some* total order to break ties.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OsvPackageName(String);

/// Error returned by [`OsvPackageName::new`] for an empty package name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("OSV package name must not be empty")]
pub struct EmptyOsvPackageName;

impl OsvPackageName {
    /// Wraps `value` as an `OsvPackageName`, unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyOsvPackageName`] if `value` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::OsvPackageName;
    ///
    /// let name = OsvPackageName::new(String::from("serde")).unwrap();
    /// assert_eq!(name.as_str(), "serde");
    /// assert!(OsvPackageName::new("").is_err());
    /// ```
    pub fn new(value: impl Into<String>) -> Result<Self, EmptyOsvPackageName> {
        let value = value.into();
        if value.is_empty() {
            return Err(EmptyOsvPackageName);
        }
        Ok(Self(value))
    }

    /// Like [`Self::new`], but maps an empty name to `None` after logging that the dependency
    /// is skipped — the shared handling for `OsvNaming::osv_package_name` implementations,
    /// so one empty key never poisons a whole batch (issue #1678).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::OsvPackageName;
    ///
    /// assert!(OsvPackageName::new_or_skip("serde").is_some());
    /// assert!(OsvPackageName::new_or_skip("").is_none());
    /// ```
    #[must_use]
    pub fn new_or_skip(value: impl Into<String>) -> Option<Self> {
        Self::new(value)
            .inspect_err(|e| tracing::warn!(error = %e, "skipping dependency from OSV scan"))
            .ok()
    }

    /// Returns the OSV wire package name as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::OsvPackageName;
    ///
    /// assert_eq!(OsvPackageName::new("tokio").unwrap().as_str(), "tokio");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the `OsvPackageName`, returning the wrapped `String`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::OsvPackageName;
    ///
    /// let owned: String = OsvPackageName::new("tokio").unwrap().into_string();
    /// assert_eq!(owned, "tokio");
    /// ```
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for OsvPackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for OsvPackageName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for OsvPackageName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for OsvPackageName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod osv_package_name_tests {
    use super::OsvPackageName;

    #[test]
    fn new_rejects_empty_name_and_new_or_skip_maps_it_to_none() {
        assert_eq!(OsvPackageName::new(""), Err(super::EmptyOsvPackageName));
        assert_eq!(OsvPackageName::new_or_skip(""), None);
        assert!(OsvPackageName::new_or_skip("serde").is_some());
    }

    #[test]
    fn test_display_as_ref_and_str_equality() {
        let name = OsvPackageName::new("github.com/apple/swift-nio").unwrap();
        assert_eq!(name.to_string(), "github.com/apple/swift-nio");
        assert_eq!(AsRef::<str>::as_ref(&name), "github.com/apple/swift-nio");
        assert_eq!(name, *"github.com/apple/swift-nio");
        assert_eq!(name, "github.com/apple/swift-nio");
        assert!(name != "other");
    }
}

/// The package name a [`ScanTarget`] is queried under, tagged with how far a *negative* answer
/// for it can be trusted.
///
/// OSV's `GitHub Actions` names are exact-case, so a name that is not confirmed canonical may
/// simply be the wrong spelling: a hit on it is real (OSV matched that exact name), but an empty
/// result proves nothing. Carrying the distinction in the type — with no `AsRef<str>` and no
/// default — forces every producer to state it and every consumer to match on it.
///
/// `Debug` prints the variant and the redacted name.
///
/// # Examples
///
/// ```
/// use deps_core::osv::{OsvPackageName, OsvQueryName};
///
/// let name = OsvPackageName::new("actions/checkout").unwrap();
/// assert_eq!(OsvQueryName::Confirmed(name.clone()).name(), &name);
/// assert_eq!(OsvQueryName::Provisional(name.clone()).name(), &name);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub enum OsvQueryName {
    /// The canonical name; both positive and negative results are authoritative.
    Confirmed(OsvPackageName),
    /// The name as written in the manifest; only a positive result is authoritative, a clean
    /// result stays unchecked.
    Provisional(OsvPackageName),
}

impl OsvQueryName {
    /// The wrapped name, regardless of trust — for the wire, cache keys and advisory matching,
    /// where the result for an exact name is objective.
    #[must_use]
    pub const fn name(&self) -> &OsvPackageName {
        match self {
            Self::Confirmed(name) | Self::Provisional(name) => name,
        }
    }
}

impl fmt::Debug for OsvQueryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (variant, name) = match self {
            Self::Confirmed(name) => ("Confirmed", name),
            Self::Provisional(name) => ("Provisional", name),
        };
        f.debug_tuple(variant)
            .field(&crate::redact::redact_declaration_key(name.as_str()))
            .finish()
    }
}

/// One dependency to query against OSV.
///
/// Four distinct strings, deliberately: `key` is this project's internal
/// lookup key (`EcosystemFormatter::normalize_package_name`), `osv_name` is
/// OSV's canonical spelling (`EcosystemFormatter::osv_package_name`). The
/// transform from `key` to `osv_name` is not round-trippable (Swift
/// `owner/repo` -> `github.com/owner/repo`; NuGet raw vs Composer lowercased),
/// so the client cannot reconstruct the map key from what it sends on the
/// wire — both must be carried alongside each other.
///
/// `version` and `display_version` are the same split, one level down: `version`
/// is what gets sent on the wire (`EcosystemFormatter::osv_version`), while
/// `display_version` is the ecosystem-native spelling a caller should surface
/// back to the user (e.g. in [`crate::osv::UpgradeStatus`]). They coincide for
/// every ecosystem except Go, where `osv_version` strips the mandatory `v`
/// prefix — a caller that echoed `version` in an upgrade suggestion would show
/// `1.2.3` instead of the `go.mod`-native `v1.2.3`.
///
/// # Examples
///
/// ```
/// use deps_core::ConcreteVersion;
/// use deps_core::osv::{OsvPackageName, OsvQueryName, OsvVersion, ScanTarget};
/// use deps_core::test_util::vuln_key;
///
/// let target = ScanTarget::new(
///     vuln_key("time"),
///     OsvQueryName::Confirmed(OsvPackageName::new("time").unwrap()),
///     OsvVersion::new("0.1.43"),
///     ConcreteVersion::new("0.1.43"),
/// );
/// assert!(*target.osv_name.name() == target.key.as_str());
/// ```
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, crate::redact_debug::RedactingDebug)]
pub struct ScanTarget {
    /// This project's internal lookup key — used to key [`VulnerabilityMap`].
    #[redact(key)]
    pub key: VulnKey,
    /// The package name to send on the wire, with the trust its negative answer deserves.
    #[raw]
    pub osv_name: OsvQueryName,
    /// Concrete version to query, resolved per the version-selection policy
    /// and rewritten to OSV's wire spelling via
    /// `EcosystemFormatter::osv_version`. Never surface this to the user —
    /// use [`Self::display_version`] instead.
    #[raw]
    pub version: OsvVersion,
    /// The same version in the ecosystem's native spelling (pre-`osv_version`
    /// rewrite), for callers that need to display it back to the user rather
    /// than send it to OSV.
    #[raw]
    pub display_version: ConcreteVersion,
    /// Other release tags naming the same commit as [`Self::version`]; an advisory affecting any
    /// of them affects the dependency. Set only via [`Self::with_siblings`].
    #[raw]
    siblings: Vec<ScanVersion>,
}

/// One sibling release tag of a [`ScanTarget`]: the same wire/native split as the target's own
/// `version`/`display_version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanVersion {
    version: OsvVersion,
    display_version: ConcreteVersion,
}

impl ScanVersion {
    /// The version in OSV's wire spelling.
    #[must_use]
    pub const fn version(&self) -> &OsvVersion {
        &self.version
    }

    /// The version in the ecosystem's native spelling, for display.
    #[must_use]
    pub const fn display_version(&self) -> &ConcreteVersion {
        &self.display_version
    }
}

impl ScanTarget {
    /// Constructs a `ScanTarget` from its four fields.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// Prefer [`Self::from_native`] when `version` is simply `display_version` rewritten via
    /// [`crate::lsp_helpers::OsvNaming::osv_version`] — the common production shape — so the
    /// pair is derived rather than hand-rolled at every call site.
    ///
    /// # Arguments
    ///
    /// * `key` - This project's internal lookup key — used to key [`VulnerabilityMap`],
    ///   **not** what gets sent to OSV
    /// * `osv_name` - OSV's package name for this ecosystem — sent on the wire, distinct from
    ///   `key` because the two do not always round-trip (see [`Self::key`]'s docs) — with its
    ///   trust level
    /// * `version` - Concrete version rewritten to OSV's wire spelling
    ///   (`EcosystemFormatter::osv_version`) — sent to OSV, never shown to the user
    /// * `display_version` - The same version in the ecosystem's native spelling, for
    ///   surfacing back to the user instead of `version`
    #[must_use]
    pub fn new(
        key: VulnKey,
        osv_name: OsvQueryName,
        version: OsvVersion,
        display_version: ConcreteVersion,
    ) -> Self {
        Self {
            key,
            osv_name,
            version,
            display_version,
            siblings: Vec::new(),
        }
    }

    /// Attaches the sibling release tags of `versions`, deriving each wire version via
    /// `naming.osv_version`.
    ///
    /// Taking a sealed [`crate::lsp_helpers::TaggedVersions`] (only
    /// [`crate::lsp_helpers::InUseVersions`] and [`crate::lsp_helpers::CandidateSiblings`]
    /// implement it) keeps arbitrary tags from being attached. The target's own `version` and
    /// `display_version` are never touched. Only [`crate::osv::OsvClient`]'s local-matching path
    /// evaluates siblings; a server-side matched target carrying any is skipped fail-closed.
    #[must_use]
    pub fn with_siblings(
        mut self,
        versions: &impl crate::lsp_helpers::TaggedVersions,
        naming: &dyn crate::lsp_helpers::OsvNaming,
    ) -> Self {
        self.siblings = versions
            .siblings()
            .iter()
            .map(|native| ScanVersion {
                version: naming.osv_version(native),
                display_version: native.clone(),
            })
            .collect();
        self
    }

    /// The sibling release tags attached via [`Self::with_siblings`].
    #[must_use]
    pub fn siblings(&self) -> &[ScanVersion] {
        &self.siblings
    }

    /// Constructs a `ScanTarget` from a native (ecosystem-spelled) version, deriving the wire
    /// `version` field via `naming.osv_version(&native)` — so a caller no longer hand-rolls the
    /// `(formatter.osv_version(&v), v)` pair [`Self::new`] would otherwise require.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    /// use deps_core::lsp_helpers::OsvNaming;
    /// use deps_core::osv::{OsvPackageName, OsvQueryName, ScanTarget};
    /// use deps_core::test_util::vuln_key;
    ///
    /// struct DefaultFormatter;
    /// impl OsvNaming for DefaultFormatter {}
    ///
    /// let target = ScanTarget::from_native(
    ///     vuln_key("time"),
    ///     OsvQueryName::Confirmed(OsvPackageName::new("time").unwrap()),
    ///     ConcreteVersion::new("0.1.43"),
    ///     &DefaultFormatter,
    /// );
    /// assert_eq!(target.version, "0.1.43");
    /// assert_eq!(target.display_version, "0.1.43");
    /// ```
    #[must_use]
    pub fn from_native(
        key: VulnKey,
        osv_name: OsvQueryName,
        native: ConcreteVersion,
        naming: &dyn crate::lsp_helpers::OsvNaming,
    ) -> Self {
        let version = naming.osv_version(&native);
        Self::new(key, osv_name, version, native)
    }
}

#[cfg(test)]
mod scan_target_debug_redaction_tests {
    use super::{OsvPackageName, OsvQueryName, OsvVersion, ScanTarget, VulnKey};
    use crate::ConcreteVersion;

    crate::debug_redaction_conformance!(
        test_scan_target_debug_redacts_credentials,
        2,
        ScanTarget {
            key: VulnKey(crate::conformance::CREDENTIAL_PROBE_KEY.into()),
            osv_name: OsvQueryName::Confirmed(
                OsvPackageName::new(crate::conformance::CREDENTIAL_PROBE_KEY).unwrap()
            ),
            version: OsvVersion::new("1.0.0"),
            display_version: ConcreteVersion::new("1.0.0"),
            siblings: Vec::new(),
        },
    );
}

/// Severity bucket derived from an OSV advisory record.
///
/// See `architecture.md` §6 for the precedence rules used to derive this
/// from a raw record, and [`crate::osv::diagnostic_severity_for`] for the mapping to
/// [`crate::diagnostic::Severity`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnSeverity {
    /// `database_specific.severity` or `ecosystem_specific.severity` reported `CRITICAL`.
    Critical,
    /// Reported `HIGH`.
    High,
    /// Reported `MODERATE` or `MEDIUM`.
    Medium,
    /// Reported `LOW`.
    Low,
    /// No severity field was present or recognized on the record.
    Unknown,
    /// The advisory's `id`, or any entry in its `aliases`, carries OSV's
    /// `MAL-` prefix, identifying a confirmed-malicious-package record
    /// ingested from the OpenSSF `malicious-packages` feed: this exact
    /// published version is known malware (typically "fully compromised,
    /// rotate all secrets"), not a graded-but-uncertain risk. `MAL-*`
    /// records carry no CVSS-style severity field at all, so without this
    /// variant they would collapse into [`Self::Unknown`] and render
    /// identically to a merely unscored, low-confidence CVE — see the
    /// `MAL-` prefix check (on both `id` and `aliases`) this crate's OSV
    /// severity classification runs before its graded-severity fallback,
    /// and `architecture.md` §6. The `aliases` check matters because OSV
    /// can serve one confirmed-malicious-package event under a non-`MAL-`
    /// primary id, cross-referencing the canonical `MAL-*` id only via
    /// `aliases`. Deliberately not folded into [`Self::Critical`] either: a
    /// confirmed compromise is categorically different from a graded
    /// CVSS-CRITICAL score, and collapsing the two would make them
    /// indistinguishable to a reader.
    Malicious,
    /// A relevant `affected[]` entry carries a non-empty
    /// `database_specific.informational` value (e.g. RUSTSEC's
    /// `"unmaintained"`) and no graded severity was found anywhere on the
    /// record. Distinct from [`Self::Unknown`]: this is not a vulnerability
    /// this crate failed to grade, it is OSV explicitly saying the record is
    /// a maintenance-status notice rather than a security finding — see
    /// `crate::osv::severity::classify`'s two-pass precedence (issue #1007).
    Informational,
}

/// A single vulnerability advisory, converted from OSV's wire format at the
/// crate boundary.
///
/// # Examples
///
/// ```
/// use deps_core::osv::{Advisory, OsvVersion, VulnSeverity};
///
/// let advisory = Advisory::new(
///     "RUSTSEC-2020-0071".to_string(),
///     "2023-01-01T00:00:00Z".to_string(),
///     VulnSeverity::High,
/// )
/// .expect("valid osv id")
/// .with_summary("Potential segfault in the time crate".to_string())
/// .with_aliases(vec!["CVE-2020-26235".to_string()])
/// .with_fixed_versions(vec![OsvVersion::new("0.2.23")]);
/// assert_eq!(advisory.fixed_versions.last(), Some(&OsvVersion::new("0.2.23")));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// Advisory identifier (e.g. `"RUSTSEC-2020-0071"`, `"GHSA-..."`).
    pub id: String,
    /// RFC3339 last-modified timestamp — the [`crate::osv::OsvClient`] record-cache validator.
    pub modified: String,
    /// Human-readable one-line summary, if OSV provided one.
    pub summary: Option<String>,
    /// Alternate identifiers (CVE, GHSA, ...).
    pub aliases: Vec<String>,
    /// Derived severity bucket.
    pub severity: VulnSeverity,
    /// Raw CVSS vector string, shown verbatim in hover but never parsed.
    pub cvss_vector: Option<String>,
    /// All `fixed` events found in the record's ranges, ascending, in OSV's wire spelling —
    /// convert via [`crate::lsp_helpers::OsvNaming::osv_version_to_native`] before showing one
    /// to the user or using it in a manifest edit/registry lookup. May be empty if OSV
    /// recorded no fix. The highest entry is the one to surface as "the fix" — see
    /// `architecture.md` §6 for why the *first* one is not.
    pub fixed_versions: Vec<OsvVersion>,
    /// `https://osv.dev/vulnerability/{id}`, always derived from [`Self::id`] via
    /// [`validated_osv_url`]. Private (not `pub`) rather than a plain field — see
    /// [`Self::new`]'s doc for why (#1271). Read via [`Self::url()`].
    url: String,
}

impl Advisory {
    /// Constructs an `Advisory` from its required fields, deriving [`Self::url()`] from `id`,
    /// with [`Self::summary`], [`Self::aliases`], [`Self::cvss_vector`], and
    /// [`Self::fixed_versions`] left empty/`None` — chain the corresponding `with_*` setters
    /// to attach them.
    ///
    /// Returns `None` if `id` fails [`is_valid_osv_id`] — mirrors
    /// `OsvVulnRecord::into_advisory`'s own early return for the same check, so a
    /// caller cannot construct an `Advisory` whose URL [`validated_osv_url`] could not
    /// build safely.
    ///
    /// This is the only way to set the URL outside this module: unlike a merely
    /// `#[non_exhaustive]` `pub` field — which still allows a direct field write
    /// (`advisory.url = "...".into()`) from any crate holding an owned value — the private
    /// `url` field makes an unvalidated/unsanitized URL structurally unconstructible from
    /// outside this file (#1271). Mirrors `Diagnostic`'s own private-field-plus-getter
    /// pattern for `message`/`code`, adopted there for the identical reason (closing "a
    /// sanitization-backstop bypass via ... a direct field write").
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate (including test code) must go through this
    /// constructor instead.
    ///
    /// # Arguments
    ///
    /// * `id` - Advisory identifier (e.g. `"RUSTSEC-2020-0071"`, `"GHSA-..."`)
    /// * `modified` - RFC3339 last-modified timestamp — not the advisory's publish date
    /// * `severity` - Derived severity bucket
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{Advisory, OsvVersion, VulnSeverity};
    ///
    /// let advisory = Advisory::new(
    ///     "RUSTSEC-2020-0071".to_string(),
    ///     "2023-01-01T00:00:00Z".to_string(),
    ///     VulnSeverity::High,
    /// )
    /// .expect("valid osv id")
    /// .with_fixed_versions(vec![OsvVersion::new("0.2.23")]);
    /// assert_eq!(advisory.fixed_versions.last(), Some(&OsvVersion::new("0.2.23")));
    /// ```
    #[must_use]
    pub fn new(id: String, modified: String, severity: VulnSeverity) -> Option<Self> {
        let url = validated_osv_url(&id)?;
        Some(Self {
            id,
            modified,
            summary: None,
            aliases: Vec::new(),
            severity,
            cvss_vector: None,
            fixed_versions: Vec::new(),
            url,
        })
    }

    /// Returns `https://osv.dev/vulnerability/{id}` — [`Self::id`]'s advisory page on
    /// OSV.dev.
    ///
    /// The only accessor for the private `url` field (#1271): every `Advisory` in existence
    /// was built by [`Self::new`], so this value is always [`validated_osv_url`]'s output for
    /// [`Self::id`], never an arbitrary caller-supplied string.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{Advisory, VulnSeverity};
    ///
    /// let advisory = Advisory::new(
    ///     "RUSTSEC-2020-0071".to_string(),
    ///     "2023-01-01T00:00:00Z".to_string(),
    ///     VulnSeverity::High,
    /// )
    /// .expect("valid osv id");
    /// assert_eq!(advisory.url(), "https://osv.dev/vulnerability/RUSTSEC-2020-0071");
    /// ```
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Attaches a human-readable one-line summary. See [`Self::summary`].
    #[must_use]
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Attaches alternate identifiers (CVE, GHSA, ...). See [`Self::aliases`].
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }

    /// Attaches the raw CVSS vector string. See [`Self::cvss_vector`].
    #[must_use]
    pub fn with_cvss_vector(mut self, cvss_vector: impl Into<String>) -> Self {
        self.cvss_vector = Some(cvss_vector.into());
        self
    }

    /// Attaches the `fixed` events found in the record's ranges. See [`Self::fixed_versions`].
    #[must_use]
    pub fn with_fixed_versions(mut self, fixed_versions: Vec<OsvVersion>) -> Self {
        self.fixed_versions = fixed_versions;
        self
    }
}

/// A list that may have been truncated when it was produced, paired with the
/// true count of items that existed at the source.
///
/// Exists so a truncated list can never be silently read as complete: items are
/// only reachable through [`Capped::items`] and the real count only through
/// [`Capped::total`], so `items().len()` is never mistaken for "everything there
/// is". [`DependencyVulnerabilities::advisories`] and [`UpgradeStatus::CandidateVulnerable`]
/// both use it, capped at [`crate::osv::MAX_ADVISORY_RECORDS`]; the render-only view
/// [`DependencyVulnerabilities::advisories_for_display`] returns a further-truncated
/// `Capped` of its own, capped at [`crate::osv::ADVISORY_DISPLAY_CAP`].
///
/// # Examples
///
/// ```
/// use deps_core::osv::Capped;
///
/// let truncated = Capped::new(vec!["A1".to_string(), "A2".to_string()], 5);
/// assert_eq!(truncated.items().len(), 2);
/// assert_eq!(truncated.total(), 5);
/// assert!(!truncated.is_complete());
/// assert_eq!(truncated.remaining(), 3);
///
/// let complete = Capped::new(vec!["A1".to_string()], 1);
/// assert!(complete.is_complete());
/// assert_eq!(complete.remaining(), 0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capped<T> {
    items: Vec<T>,
    total: usize,
}

impl<T> Capped<T> {
    /// Pairs an already-truncated `items` list with the `total` the source
    /// reported, which may exceed `items.len()`.
    #[must_use]
    pub fn new(items: Vec<T>, total: usize) -> Self {
        Self { items, total }
    }

    /// The items actually retained — **not necessarily all [`Self::total`] of them**.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// The count the source reported, independent of how many items were retained.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Whether [`Self::items`] holds everything the source reported.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.items.len() >= self.total
    }

    /// How many items were dropped — the render layer's "+N more" count.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.total.saturating_sub(self.items.len())
    }
}

#[cfg(test)]
mod capped_tests {
    use super::Capped;

    #[test]
    fn new_exposes_items_and_total_as_given() {
        let capped = Capped::new(vec!["A1", "A2"], 5);
        assert_eq!(capped.items(), ["A1", "A2"]);
        assert_eq!(capped.total(), 5);
    }

    #[test]
    fn is_complete_true_when_items_cover_total() {
        let capped = Capped::new(vec!["A1"], 1);
        assert!(capped.is_complete());
    }

    #[test]
    fn is_complete_false_when_truncated() {
        let capped = Capped::new(vec!["A1"], 2);
        assert!(!capped.is_complete());
    }

    #[test]
    fn remaining_reports_truncated_count() {
        let capped = Capped::new(vec!["A1", "A2"], 5);
        assert_eq!(capped.remaining(), 3);
    }

    #[test]
    fn remaining_is_zero_when_not_truncated() {
        let capped = Capped::new(vec!["A1"], 1);
        assert_eq!(capped.remaining(), 0);
    }

    #[test]
    fn empty_items_with_zero_total_is_complete() {
        let capped: Capped<&str> = Capped::new(vec![], 0);
        assert!(capped.is_complete());
        assert_eq!(capped.remaining(), 0);
    }
}

/// Result of checking whether a recommended upgrade target is itself affected.
///
/// Populated by [`crate::osv::OsvClient::check_candidates`] (phase B, issue #1517: now run for
/// every dependency with a registry-cached latest, not only ones phase A already flagged
/// [`ScanOutcome::Vulnerable`]). Used for both the registry's "latest" candidate (the per-key
/// entry in [`crate::osv::LatestStatusMap`]) and the independently-verified fix target F
/// ([`DependencyVulnerabilities::fix_target_status`]) — see the latter's doc for why F needs its
/// own verification result distinct from latest's.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeStatus {
    /// Phase B has not run for this dependency (phase A found nothing, or
    /// phase B has not completed yet).
    NotChecked,
    /// The candidate upgrade version is not itself affected by any known advisory.
    CandidateClean {
        /// The version that was checked.
        version: ConcreteVersion,
    },
    /// The candidate upgrade version is itself affected.
    CandidateVulnerable {
        /// The version that was checked.
        version: ConcreteVersion,
        /// Advisory IDs that still apply to the candidate version, capped at
        /// [`crate::osv::MAX_ADVISORY_RECORDS`] the same way
        /// [`DependencyVulnerabilities::advisories`] is (#462 critic M1) —
        /// **not necessarily exhaustive**. Check [`Capped::is_complete`] before
        /// treating it as the complete set of advisories still affecting this
        /// candidate; an incomplete list means some are missing, not that none
        /// exist.
        advisory_ids: Capped<String>,
        /// The most severe [`VulnSeverity`] among `advisory_ids`'s full records, or `None` when
        /// no record could be fetched for any of them (issue #1517) — a caller must treat `None`
        /// as blocking (never render this candidate as safe), never as "no advisories". Exists
        /// so an [`VulnSeverity::Informational`]-only advisory that affects every version of a
        /// dependency (common for RUSTSEC-style maintenance notices) does not wrongly suppress
        /// "outdated" status for that dependency's latest — a caller checks this field before
        /// treating [`Self::CandidateVulnerable`] as a hard block.
        worst_severity: Option<VulnSeverity>,
    },
    /// The candidate upgrade version's OSV status could not be determined, but a version was
    /// still attempted or is otherwise known: either the check itself failed (transient — query
    /// failure, timeout, truncation) or the reason is structural but a real candidate version
    /// was already on hand ([`SkipReason::UnmappableName`]/[`SkipReason::UnmappableEcosystem`]
    /// — the registry's "latest" is known, only its OSV mapping is not). See
    /// [`Self::StructurallyUnchecked`] for the case where no version is known at all. A caller
    /// must fail closed (never render this as "verified safe") until a later phase B run
    /// replaces it — [`SkipReason::is_structural`] tells a transient reason apart from a
    /// structural-but-version-known one, which callers treat differently (issue #1517).
    CandidateUnverified {
        /// The version that was attempted.
        version: ConcreteVersion,
        /// Why the check did not produce a definite clean/vulnerable verdict.
        reason: SkipReason,
    },
    /// This dependency's source/ecosystem is never checked against OSV at all, and no candidate
    /// version is known either, so there is nothing to report — unlike
    /// [`Self::CandidateUnverified`], which always names a version even when its reason is also
    /// structural. Only ever holds a [`StructuralSkipReason`] (issue #1624 S1): unlike a bare
    /// [`SkipReason`], which also admits transient reasons like
    /// [`SkipReason::QueryFailed`], this makes "this dependency is never checked, for a
    /// permanent reason" the only state this variant can represent — a caller (e.g.
    /// `crate::lsp_helpers::latest_verdict`) degrades it to "not applicable" rather than
    /// "unverified" (issue #1517).
    StructurallyUnchecked(StructuralSkipReason),
}

/// Vulnerability data for one dependency that OSV reported as non-clean.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DependencyVulnerabilities {
    /// Advisories fetched in full, capped at [`crate::osv::MAX_ADVISORY_RECORDS`] (invariant 3
    /// in `architecture.md` §8) — the input [`Self::recommended_fix`] and
    /// `lsp_helpers::code_actions::fix_target_is_verified` compute over. The total advisory
    /// count OSV reported is carried alongside via [`Capped::total`], independent of how many
    /// were actually fetched.
    ///
    /// **Not for direct rendering** (#1422): `MAX_ADVISORY_RECORDS` is deliberately larger than
    /// [`crate::osv::ADVISORY_DISPLAY_CAP`], so a hover/diagnostics/`deps-cli` renderer that
    /// iterates this field directly would list far more advisories than the UI is meant to
    /// show. Use [`Self::advisories_for_display`] instead, which truncates to
    /// `ADVISORY_DISPLAY_CAP` and is the source of the render layer's "+N more advisories"
    /// count (`architecture.md` §7).
    pub advisories: Capped<Arc<Advisory>>,
    /// Independent verification of [`Self::recommended_fix`]'s target version F, if F
    /// differs from the "latest" candidate (looked up by the caller from
    /// [`crate::osv::LatestStatusMap`], the single source of truth for phase B's "latest" check —
    /// issue #1517 removed this struct's own parallel `upgrade_status` field). Left at
    /// [`UpgradeStatus::NotChecked`] until [`Self::recommended_fix`] has been computed and F's
    /// status resolved — either reused from the latest-status map entry when F equals latest, or
    /// checked live via [`crate::osv::OsvClient::check_candidates`] otherwise (always live-checked when
    /// F differs from latest: a data-derived shortcut was tried and rejected — see git history
    /// on this field and #462's critique — because it degenerates into checking F against
    /// exactly the advisories it was computed from, proving nothing about an advisory phase
    /// A never fetched at all, which is the actual gap #462 closes). See
    /// `run_osv_phase_b_and_commit` in `deps-lsp` for the resolution order.
    ///
    /// A caller must not treat a bare [`UpgradeStatus::CandidateClean`] check as the only valid
    /// "verified" state: [`UpgradeStatus::CandidateVulnerable`] can also be a legitimate,
    /// presentable fix when every reported id is an advisory [`Self::recommended_fix`] already
    /// declined to claim (excluded via `still_applying`, or never had a known fix) — see
    /// `deps-core`'s `lsp_helpers::code_actions::fix_target_is_verified` (the actual gate
    /// `generate_code_actions` uses) for the full contract, rather than re-deriving it ad hoc.
    pub fix_target_status: UpgradeStatus,
    /// For advisories matched only through a sibling release tag of the scanned commit, which
    /// tags they matched; `None` when no advisory matched that way. Read through
    /// [`Self::sibling_match`].
    pub(crate) sibling_matches: Option<SiblingMatches>,
}

/// Sibling release tags an advisory matched, never empty by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedTags {
    first: ConcreteVersion,
    rest: Vec<ConcreteVersion>,
}

impl MatchedTags {
    pub(crate) fn from_tags(tags: Vec<ConcreteVersion>) -> Option<Self> {
        let mut tags = tags.into_iter();
        let first = tags.next()?;
        Some(Self {
            first,
            rest: tags.collect(),
        })
    }

    /// The matched tags, lowest version first.
    pub fn iter(&self) -> impl Iterator<Item = &ConcreteVersion> {
        std::iter::once(&self.first).chain(&self.rest)
    }
}

/// Sibling tags matched per advisory id, bound to the scanned primary version.
///
/// Holds only advisories that do not match the primary itself. Built only by
/// [`crate::osv::OsvClient`], so tags can never exist without their primary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingMatches {
    primary: OsvVersion,
    tags: HashMap<String, MatchedTags>,
}

impl SiblingMatches {
    pub(crate) fn new(primary: OsvVersion) -> Self {
        Self {
            primary,
            tags: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, id: String, tags: MatchedTags) {
        self.tags.insert(id, tags);
    }

    /// Whether `advisory` matched only through a sibling and its fix does not lie above the
    /// scanned primary version: following it would rewrite the pin to the same or an older release.
    fn fix_is_not_an_upgrade(&self, advisory: &Advisory) -> bool {
        let (Some(fixed), true) = (
            advisory.fixed_versions.last(),
            self.tags.contains_key(&advisory.id),
        ) else {
            return false;
        };
        super::compare_version_strings(fixed.as_str(), self.primary.as_str())
            != std::cmp::Ordering::Greater
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

impl DependencyVulnerabilities {
    /// Constructs a `DependencyVulnerabilities` from its fetched advisories, with
    /// [`Self::fix_target_status`] left at [`UpgradeStatus::NotChecked`] — chain
    /// [`Self::with_fix_target_status`] to attach phase B's result.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate (including test code) must go through this
    /// constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{Capped, DependencyVulnerabilities};
    ///
    /// let dv = DependencyVulnerabilities::new(Capped::new(vec![], 0));
    /// assert!(dv.advisories.items().is_empty());
    /// ```
    #[must_use]
    pub fn new(advisories: Capped<Arc<Advisory>>) -> Self {
        Self {
            advisories,
            fix_target_status: UpgradeStatus::NotChecked,
            sibling_matches: None,
        }
    }

    /// Attaches the sibling-tag matches. See [`Self::sibling_match`].
    #[must_use]
    pub(crate) fn with_sibling_matches(mut self, sibling_matches: SiblingMatches) -> Self {
        self.sibling_matches = Some(sibling_matches);
        self
    }

    /// The sibling release tags advisory `id` matched instead of the scanned primary version;
    /// `None` when it matched the primary version itself.
    #[must_use]
    pub fn sibling_match(&self, id: &str) -> Option<&MatchedTags> {
        self.sibling_matches.as_ref()?.tags.get(id)
    }

    /// Whether any advisory matched only through a sibling release tag.
    #[must_use]
    pub const fn has_sibling_matches(&self) -> bool {
        self.sibling_matches.is_some()
    }

    /// Whether the "fixed in" version of `advisory` may be shown or followed as an upgrade: false
    /// for an advisory matched only through a sibling whose fix is not newer than the scanned
    /// version, since following it would keep or lower the pin.
    #[must_use]
    pub fn fix_is_upgrade(&self, advisory: &Advisory) -> bool {
        !self
            .sibling_matches
            .as_ref()
            .is_some_and(|m| m.fix_is_not_an_upgrade(advisory))
    }

    /// Attaches the independent verification of the recommended fix target. See
    /// [`Self::fix_target_status`].
    #[must_use]
    pub fn with_fix_target_status(mut self, fix_target_status: UpgradeStatus) -> Self {
        self.fix_target_status = fix_target_status;
        self
    }

    /// Advisories intended for direct rendering (hover footer, diagnostics list, `deps-cli`
    /// report), sorted worst-severity-first (tied by id, mirroring [`Self::recommended_fix`]'s
    /// own [`FixRecommendation::advisory_ids`] ordering) and truncated to
    /// [`crate::osv::ADVISORY_DISPLAY_CAP`] regardless of how many [`Self::advisories`] holds
    /// for fix computation (#1422) — the structural guard against a renderer accidentally
    /// consuming the larger fix-computation set unclipped. [`Capped::total`] still reports
    /// OSV's real advisory count, so the "+N more advisories" hint stays accurate even when
    /// [`Self::advisories`] itself holds more than `ADVISORY_DISPLAY_CAP` entries.
    ///
    /// The sort is deliberate, not cosmetic (#1422 S1): [`Self::advisories`] is populated by a
    /// concurrent, `buffer_unordered` record fetch (`crate::osv::OsvClient::fetch_records`), so
    /// its item order is completion order, not OSV's reported order — a bare `take` would make
    /// which advisories get shown vary run-to-run, and could hide a `Malicious`/`Critical`
    /// advisory behind a lower-severity one that merely finished fetching first. Sorting here
    /// makes the displayed set both stable and always the most severe subset available.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{
    ///     ADVISORY_DISPLAY_CAP, Advisory, Capped, DependencyVulnerabilities, VulnSeverity,
    /// };
    /// use std::sync::Arc;
    ///
    /// let advisories: Vec<Arc<Advisory>> = (0..ADVISORY_DISPLAY_CAP + 3)
    ///     .map(|i| {
    ///         Arc::new(
    ///             Advisory::new(
    ///                 format!("ADV-{i}"),
    ///                 "2023-01-01T00:00:00Z".to_string(),
    ///                 VulnSeverity::High,
    ///             )
    ///             .expect("valid osv id"),
    ///         )
    ///     })
    ///     .collect();
    /// let dv = DependencyVulnerabilities::new(Capped::new(advisories, ADVISORY_DISPLAY_CAP + 5));
    ///
    /// let display = dv.advisories_for_display();
    /// assert_eq!(display.items().len(), ADVISORY_DISPLAY_CAP);
    /// assert_eq!(display.total(), ADVISORY_DISPLAY_CAP + 5);
    /// ```
    #[must_use]
    pub fn advisories_for_display(&self) -> Capped<Arc<Advisory>> {
        let mut items: Vec<Arc<Advisory>> = self.advisories.items().to_vec();
        items.sort_by(|a, b| {
            severity_rank(b.severity)
                .cmp(&severity_rank(a.severity))
                .then_with(|| a.id.cmp(&b.id))
        });
        items.truncate(super::ADVISORY_DISPLAY_CAP);
        Capped::new(items, self.advisories.total())
    }
}

/// A single upgrade target recommended by [`DependencyVulnerabilities::recommended_fix`].
///
/// `version` is in OSV's version namespace (see
/// [`crate::lsp_helpers::OsvNaming::osv_version_to_native`] for the
/// conversion callers must apply before using it in a manifest edit or a
/// registry lookup).
///
/// Output-only: constructed internally by [`DependencyVulnerabilities::recommended_fix`],
/// never by external code — no constructor is provided.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixRecommendation {
    /// The highest [`Advisory::fixed_versions`] entry across the advisories
    /// named in `advisory_ids` — the lowest version that resolves everything
    /// this recommendation actually claims to fix.
    pub version: OsvVersion,
    /// Advisory ids this recommendation actually resolves, sorted by
    /// severity descending (worst first) and tied by id — the order a
    /// title should list them in.
    pub advisory_ids: Vec<String>,
}

/// Numeric ranking used only to sort [`FixRecommendation::advisory_ids`],
/// worst severity first.
///
/// `Malicious` ranks above `Critical`: a confirmed-malicious-package finding
/// is more urgent than any graded CVSS score. In practice a `Malicious`
/// advisory rarely reaches this ranking at all, since `recommended_fix` only
/// considers advisories with a known fix and a malicious-package record
/// typically has none.
const fn severity_rank(severity: VulnSeverity) -> u8 {
    match severity {
        VulnSeverity::Malicious => 6,
        VulnSeverity::Critical => 5,
        VulnSeverity::High => 4,
        VulnSeverity::Medium => 3,
        VulnSeverity::Low => 2,
        VulnSeverity::Unknown => 1,
        VulnSeverity::Informational => 0,
    }
}

/// The most severe [`VulnSeverity`] among `advisories`, by [`severity_rank`] — `None` when
/// `advisories` is empty.
///
/// Used by [`crate::osv::OsvClient::check_candidates`] (issue #1517) to populate
/// [`UpgradeStatus::CandidateVulnerable::worst_severity`] so a caller can tell an
/// [`VulnSeverity::Informational`]-only candidate (e.g. a RUSTSEC "unmaintained" notice
/// affecting every version) apart from a genuinely blocking one.
pub(crate) fn worst_severity(advisories: &[Arc<Advisory>]) -> Option<VulnSeverity> {
    advisories
        .iter()
        .map(|a| a.severity)
        .max_by_key(|&s| severity_rank(s))
}

impl DependencyVulnerabilities {
    /// Recommends a single upgrade target that resolves as many of this
    /// dependency's known advisories as possible.
    ///
    /// `advisory_ids` is computed first: every advisory with a known fix,
    /// minus — when phase B ([`UpgradeStatus::CandidateVulnerable`]) reports
    /// that some ids still apply to the checked candidate — those ids,
    /// since claiming a fix for them would be false. `version` is then the
    /// highest [`Advisory::fixed_versions`] entry across only the
    /// *remaining* claimed advisories, not every advisory: computing it over
    /// the full set first would let an advisory this method just excluded
    /// (because its own fix is known not to hold) drag the recommendation
    /// past a lower version that already clears everything actually being
    /// claimed. Returns `None` when no advisory has a claimable fix.
    ///
    /// The subtraction's premise is that the checked candidate is at least
    /// as new as `version`; when phase B checked an older candidate the
    /// subtraction is merely over-conservative (it only ever removes
    /// claims), so this is documented rather than guarded against.
    ///
    /// # Limitations
    ///
    /// `advisories` is capped at fetch time
    /// ([`crate::osv::MAX_ADVISORY_RECORDS`], deliberately larger than the render-only
    /// [`crate::osv::ADVISORY_DISPLAY_CAP`] — see [`Self::advisories_for_display`] — so this
    /// method sees every advisory a renderer would not), so `version` is the max over a
    /// possibly incomplete subset only when a dependency exceeds `MAX_ADVISORY_RECORDS`
    /// advisories — the "+N more advisories" hint already signals that incompleteness, so this
    /// is an accepted under-report, not a bug. `Advisory` also retains only `fixed_versions`, never
    /// `introduced` events, so a version reintroduced above its own last
    /// known fix (and not yet re-fixed) can still be claimed as a fix
    /// whenever phase B has not run for this dependency
    /// ([`UpgradeStatus::NotChecked`]) — the post-edit rescan is what
    /// surfaces that case.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::{
    ///     Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
    /// };
    /// use std::sync::Arc;
    ///
    /// fn advisory(id: &str, fixed: &str) -> Arc<Advisory> {
    ///     Arc::new(
    ///         Advisory::new(
    ///             id.to_string(),
    ///             "2023-01-01T00:00:00Z".to_string(),
    ///             VulnSeverity::High,
    ///         )
    ///         .expect("valid osv id")
    ///         .with_fixed_versions(vec![OsvVersion::new(fixed)]),
    ///     )
    /// }
    ///
    /// let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory("RUSTSEC-1", "1.2.0")], 1));
    ///
    /// let fix = dv.recommended_fix(None).unwrap();
    /// assert_eq!(fix.version, "1.2.0");
    /// assert_eq!(fix.advisory_ids, vec!["RUSTSEC-1".to_string()]);
    /// ```
    ///
    /// # Arguments
    ///
    /// * `latest` - This dependency's entry (looked up by the caller via its [`VulnKey`]) in the
    ///   shared [`crate::osv::LatestStatusMap`] phase B's "latest" check populates (issue #1517)
    ///   — `None` when OSV's latest-check never ran for this dependency (matches the previous
    ///   `upgrade_status` field's [`UpgradeStatus::NotChecked`] default).
    #[must_use]
    pub fn recommended_fix(&self, latest: Option<&UpgradeStatus>) -> Option<FixRecommendation> {
        let still_applying: &[String] = match latest {
            Some(UpgradeStatus::CandidateVulnerable { advisory_ids, .. }) => advisory_ids.items(),
            Some(
                UpgradeStatus::NotChecked
                | UpgradeStatus::CandidateClean { .. }
                | UpgradeStatus::CandidateUnverified { .. }
                | UpgradeStatus::StructurallyUnchecked(_),
            )
            | None => &[],
        };

        let mut claimed: Vec<&Advisory> = self
            .advisories
            .items()
            .iter()
            .map(Arc::as_ref)
            .filter(|a| !a.fixed_versions.is_empty())
            .filter(|a| !still_applying.contains(&a.id))
            .filter(|a| self.fix_is_upgrade(a))
            .collect();

        if claimed.is_empty() {
            return None;
        }

        // The minimum version that clears every *claimed* advisory — not the
        // max over every advisory (including ones just excluded above),
        // which could push the recommendation past a version that resolves
        // nothing beyond what a lower, still-claimed fix already covers.
        let version = claimed
            .iter()
            .filter_map(|a| a.fixed_versions.last())
            .max_by(|a, b| super::compare_version_strings(a.as_str(), b.as_str()))?
            .clone();

        claimed.sort_by(|a, b| {
            severity_rank(b.severity)
                .cmp(&severity_rank(a.severity))
                .then_with(|| a.id.cmp(&b.id))
        });

        Some(FixRecommendation {
            version,
            advisory_ids: claimed.into_iter().map(|a| a.id.clone()).collect(),
        })
    }
}

/// Why a dependency produced no advisories.
///
/// Absence from [`VulnerabilityMap`] is never a synonym for "clean" — every
/// input to [`crate::osv::OsvClient::scan`] gets an entry, and every filtered-out or
/// failed path must declare itself as one of these reasons rather than
/// silently vanishing from the map (`architecture.md` §6, §8 invariant 0).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// `dep.source()` was not [`crate::parser::DependencySource::Registry`] (§3 step 0).
    NonRegistrySource,
    /// No lockfile-resolved or concrete version was available (§3 steps 1-3).
    NoConcreteVersion,
    /// A tag was resolved (e.g. a SHA pin's hover `**Resolved**` line) but it is a moving
    /// alias or a non-version name, not a full version OSV.dev can be queried with (#1668).
    ResolvedTagNotFullVersion,
    /// `EcosystemFormatter::osv_package_name` returned `None`.
    UnmappableName,
    /// The OSV package name depends on registry data (a repository's canonical casing) that
    /// has not been fetched yet, or could not be; retried once the ecosystem's `TagIndex`
    /// is populated.
    CanonicalNameUnconfirmed,
    /// `EcosystemId::osv_ecosystem` returned `None`.
    UnmappableEcosystem,
    /// The batch or single-package query failed (network error, non-2xx, malformed JSON,
    /// or a chunk whose result count did not match its query count).
    QueryFailed,
    /// The batch result was truncated (`next_page_token` present) and the
    /// bounded individual-requery budget was exhausted before this entry
    /// could be recovered (§8 invariant 2).
    Truncated,
    /// The ecosystem is matched locally ([`OsvEcosystem::version_matching`]) and the in-use
    /// version is not a full SemVer version (a floating `v4` tag, a SHA pin, a branch).
    UnmatchableVersion,
    /// The ecosystem is matched locally and an advisory exists for the package, but its
    /// affected ranges could not be evaluated against the in-use version — possibly vulnerable.
    UnevaluableAdvisoryRange,
    /// A candidate version's sibling release tags could not be established (cold or partial tag
    /// index), so a clean answer for the candidate alone is not trustworthy. Phase B only.
    SiblingTagsUnknown,
}

impl SkipReason {
    /// Short tag used in the `info`-level scan summary log line.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NonRegistrySource => "non-registry-source",
            Self::NoConcreteVersion => "no-concrete-version",
            Self::ResolvedTagNotFullVersion => "resolved-tag-not-full-version",
            Self::UnmappableName => "unmappable-name",
            Self::CanonicalNameUnconfirmed => "canonical-name-unconfirmed",
            Self::UnmappableEcosystem => "unmappable-ecosystem",
            Self::QueryFailed => "query-failed",
            Self::Truncated => "truncated",
            Self::UnmatchableVersion => "unmatchable-version",
            Self::UnevaluableAdvisoryRange => "unevaluable-advisory-range",
            Self::SiblingTagsUnknown => "sibling-tags-unknown",
        }
    }

    /// Human-readable clause explaining why vulnerability data was never checked,
    /// for the hover footer and diagnostic notice that surface a [`ScanOutcome::Skipped`]
    /// outcome to the user (issue #1392) — the single source of wording both call sites
    /// share, so the two surfaces never drift into describing the same reason differently.
    ///
    /// `NonRegistrySource` has no entry here: callers gate that case out themselves
    /// (mirroring the pre-existing `resolvable` hover gate), since a source that is
    /// never network-resolved under any setting was never going to be checked
    /// regardless of this feature.
    ///
    /// The two call sites apply different additional filtering on top of this method
    /// (issue #1392 M1): `deps-core::lsp_helpers::hover`'s per-dependency, on-demand
    /// footer shows every reason returned here, but
    /// `deps-core::lsp_helpers::diagnostics`'s file-level, persistent Problems-panel
    /// notice further excludes `UnmappableName`/`UnmappableEcosystem` — those are
    /// structurally permanent for as long as a dependency is declared the way it is
    /// (every `jsr:`-pinned dependency is `UnmappableName` forever, for example), so a
    /// standing diagnostic for them would be unresolvable noise, unlike the transient/
    /// environment-dependent `NoConcreteVersion`/`QueryFailed`/`Truncated`. Wording here
    /// states only the fact, never a remedy (e.g. never "add a lock file to fix this"):
    /// resolving a version does not itself re-run the OSV scan for an already-open
    /// document, so promising that the message clears immediately would overclaim.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::SkipReason;
    ///
    /// assert_eq!(
    ///     SkipReason::NoConcreteVersion.unchecked_reason(),
    ///     Some("no resolved or exact version was available to query")
    /// );
    /// assert_eq!(
    ///     SkipReason::ResolvedTagNotFullVersion.unchecked_reason(),
    ///     Some("the resolved tag is not a full version, so it was not queried")
    /// );
    /// assert_eq!(SkipReason::NonRegistrySource.unchecked_reason(), None);
    /// ```
    #[must_use]
    pub const fn unchecked_reason(self) -> Option<&'static str> {
        match self {
            Self::NonRegistrySource => None,
            Self::NoConcreteVersion => Some("no resolved or exact version was available to query"),
            Self::ResolvedTagNotFullVersion => {
                Some("the resolved tag is not a full version, so it was not queried")
            }
            Self::UnmappableName => {
                Some("the package name could not be mapped to an OSV.dev ecosystem")
            }
            Self::CanonicalNameUnconfirmed => {
                Some("the repository's canonical name has not been confirmed by GitHub")
            }
            Self::UnmappableEcosystem => Some("this ecosystem is not supported by OSV.dev"),
            Self::QueryFailed => Some("the OSV.dev query failed"),
            Self::Truncated => Some("the OSV.dev result set was truncated"),
            Self::UnmatchableVersion => {
                Some("the version could not be matched against advisory ranges")
            }
            Self::UnevaluableAdvisoryRange => Some(
                "an advisory exists for this package but its affected range could not be evaluated",
            ),
            Self::SiblingTagsUnknown => {
                Some("the release tags sharing this version's commit could not be determined")
            }
        }
    }

    /// Whether this reason is structural — permanent for as long as a dependency is declared
    /// the way it is (a mapping/ecosystem-support gap) — as opposed to transient (a timeout or
    /// a temporary OSV outage, which a retry could resolve).
    ///
    /// Used by callers deciding whether a dependency whose "latest" was never checked (issue
    /// #1517) should be treated as not-applicable (structural) or unverified/fail-closed
    /// (transient) — a [`Self::QueryFailed`]/[`Self::Truncated`]/[`Self::NoConcreteVersion`]
    /// skip must never be silently treated as "this dependency has no latest to verify", since a
    /// retry or a resolved lockfile could turn it into a real, checkable result later.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::osv::SkipReason;
    ///
    /// assert!(SkipReason::UnmappableName.is_structural());
    /// assert!(!SkipReason::QueryFailed.is_structural());
    /// ```
    #[must_use]
    pub const fn is_structural(self) -> bool {
        matches!(
            self,
            Self::NonRegistrySource | Self::UnmappableName | Self::UnmappableEcosystem
        )
    }
}

/// The subset of [`SkipReason`] that is structural (see [`SkipReason::is_structural`]).
///
/// Permanent for as long as a dependency is declared the way it is, never resolved merely by a
/// retry. The only reasons [`UpgradeStatus::StructurallyUnchecked`] and
/// [`CandidateStatuses::Structural`] can hold, so a transient reason (e.g.
/// [`SkipReason::QueryFailed`]) is structurally impossible to store as "this dependency is
/// never checked against OSV" (issue #1624) — unlike a bare `SkipReason` payload, which would
/// let a future producer bug (or test fixture) construct e.g. `StructurallyUnchecked(QueryFailed)`
/// and have it silently resolve to `NotApplicable` (fail-open) instead of `Unverified`, since
/// nothing but an unenforced runtime `is_structural()` check would catch it.
///
/// # Examples
///
/// ```
/// use deps_core::osv::{SkipReason, StructuralSkipReason};
///
/// assert_eq!(
///     StructuralSkipReason::NonRegistrySource.as_skip_reason(),
///     SkipReason::NonRegistrySource
/// );
/// assert_eq!(
///     SkipReason::from(StructuralSkipReason::UnmappableName),
///     SkipReason::UnmappableName
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralSkipReason {
    /// See [`SkipReason::NonRegistrySource`].
    NonRegistrySource,
    /// See [`SkipReason::UnmappableName`].
    UnmappableName,
    /// See [`SkipReason::UnmappableEcosystem`].
    UnmappableEcosystem,
}

impl StructuralSkipReason {
    /// Widens to the full [`SkipReason`] enum, e.g. to reuse
    /// [`SkipReason::unchecked_reason`]/`SkipReason::as_str` for rendering or logging.
    #[must_use]
    pub const fn as_skip_reason(self) -> SkipReason {
        match self {
            Self::NonRegistrySource => SkipReason::NonRegistrySource,
            Self::UnmappableName => SkipReason::UnmappableName,
            Self::UnmappableEcosystem => SkipReason::UnmappableEcosystem,
        }
    }
}

impl From<StructuralSkipReason> for SkipReason {
    fn from(value: StructuralSkipReason) -> Self {
        value.as_skip_reason()
    }
}

#[cfg(test)]
mod skip_reason_unchecked_reason_tests {
    use super::SkipReason;

    /// Table-driven coverage for every `SkipReason` variant (issue #1392 tester gap 2) —
    /// the doctest on `unchecked_reason` only asserts `NoConcreteVersion`/`NonRegistrySource`.
    #[test]
    fn unchecked_reason_covers_every_variant() {
        let cases: &[(SkipReason, Option<&str>)] = &[
            (SkipReason::NonRegistrySource, None),
            (
                SkipReason::NoConcreteVersion,
                Some("no resolved or exact version was available to query"),
            ),
            (
                SkipReason::UnmappableName,
                Some("the package name could not be mapped to an OSV.dev ecosystem"),
            ),
            (
                SkipReason::UnmappableEcosystem,
                Some("this ecosystem is not supported by OSV.dev"),
            ),
            (
                SkipReason::ResolvedTagNotFullVersion,
                Some("the resolved tag is not a full version, so it was not queried"),
            ),
            (
                SkipReason::CanonicalNameUnconfirmed,
                Some("the repository's canonical name has not been confirmed by GitHub"),
            ),
            (SkipReason::QueryFailed, Some("the OSV.dev query failed")),
            (
                SkipReason::Truncated,
                Some("the OSV.dev result set was truncated"),
            ),
            (
                SkipReason::UnmatchableVersion,
                Some("the version could not be matched against advisory ranges"),
            ),
            (
                SkipReason::UnevaluableAdvisoryRange,
                Some(
                    "an advisory exists for this package but its affected range could not be evaluated",
                ),
            ),
            (
                SkipReason::SiblingTagsUnknown,
                Some("the release tags sharing this version's commit could not be determined"),
            ),
        ];
        for (reason, expected) in cases {
            assert_eq!(
                reason.unchecked_reason(),
                *expected,
                "unexpected text for {reason:?}"
            );
        }
    }

    /// #1727: unknown candidate sibling tags are transient and never storable as structural.
    #[test]
    fn sibling_tags_unknown_is_transient() {
        let reason = SkipReason::SiblingTagsUnknown;
        assert!(!reason.is_structural());
        assert_eq!(reason.as_str(), "sibling-tags-unknown");
    }

    /// #1683: the unconfirmed-name skip is transient and never storable as structural.
    #[test]
    fn canonical_name_unconfirmed_is_transient() {
        let reason = SkipReason::CanonicalNameUnconfirmed;
        assert!(!reason.is_structural());
        assert_eq!(reason.as_str(), "canonical-name-unconfirmed");
    }

    /// None of the wordings promise an immediate remedy (issue #1392 S1: resolving a
    /// version does not itself re-run the OSV scan for an already-open document, so
    /// claiming a fix would overclaim).
    #[test]
    fn unchecked_reason_never_promises_a_remedy() {
        for reason in [
            SkipReason::NoConcreteVersion,
            SkipReason::ResolvedTagNotFullVersion,
            SkipReason::UnmappableName,
            SkipReason::UnmappableEcosystem,
            SkipReason::CanonicalNameUnconfirmed,
            SkipReason::QueryFailed,
            SkipReason::Truncated,
        ] {
            let lower = reason.unchecked_reason().expect("has text").to_lowercase();
            for forbidden in ["fix", "lockfile", "lock file", "resolve this", "add a"] {
                assert!(
                    !lower.contains(forbidden),
                    "{reason:?}'s text must state only the fact, not a remedy \
                     (found {forbidden:?} in {lower:?})"
                );
            }
        }
    }
}

/// Outcome of scanning one dependency.
///
/// The three variants are mutually exclusive and collectively exhaustive for
/// every dependency passed to [`crate::osv::OsvClient::scan`] — see `architecture.md` §6 for
/// why this must never collapse back to `Option<DependencyVulnerabilities>`.
// Exhaustive: deliberate trichotomy per the doc above — a new "no data" case becomes a new
// `SkipReason` variant, never a 4th `ScanOutcome` variant (issue #769).
#[derive(Debug, Clone)]
pub enum ScanOutcome {
    /// Never queried, or the query could not be resolved — say nothing about it.
    Skipped(SkipReason),
    /// Queried; OSV reported no advisories.
    Clean,
    /// Queried; OSV reported one or more advisories.
    Vulnerable(DependencyVulnerabilities),
}

/// Per-scan result map, keyed by [`VulnKey`].
///
/// See [`vulnerability_keys`] for how a key is derived — normally the normalized dependency
/// name, but version-qualified for a duplicated dependency name's ambiguous occurrences.
pub type VulnerabilityMap = HashMap<VulnKey, ScanOutcome>;

/// Per-key "latest"-check result map (issue #1517).
///
/// The single source of truth for every renderer (hover, diagnostics, code actions, code lens,
/// inlay hints, completion) and `deps-cli update`/`check` deciding whether a dependency's
/// recommended upgrade target is itself safe to adopt.
///
/// Unlike [`VulnerabilityMap`] (populated for every dependency phase A considered, vulnerable or
/// not), this map is populated only for dependencies that have a registry-cached "latest" to
/// check — see `deps_engine::classify::osv::build_latest_check_targets` for how entries are
/// built, including the structural [`UpgradeStatus::CandidateUnverified`] entries for a
/// dependency whose source/ecosystem is never checked against OSV at all. A key absent from this
/// map (as opposed to present with [`UpgradeStatus::NotChecked`]/
/// [`UpgradeStatus::CandidateUnverified`]) means OSV checking is disabled or offline for this
/// scan entirely — `crate::lsp_helpers::latest_verdict` treats the two differently.
pub type LatestStatusMap = HashMap<VulnKey, UpgradeStatus>;

/// A dependency's phase B candidate-check result set (#1524, issue #1624).
///
/// Replaces an earlier design that recorded a structural skip under an empty-string sentinel
/// key inside the per-version map — a shape that let "structurally skipped" and "has real
/// per-version data" coexist for the same dependency, which is meaningless. This enum makes
/// that state unrepresentable: a dependency is either structurally unchecked as a whole, or has
/// zero or more real per-version verdicts, never both.
///
/// Deliberately not `#[non_exhaustive]` (project rule, #1624 critique S2): every match site
/// across the workspace is compiler-forced to handle a new variant, rather than one crate's
/// `#[non_exhaustive]`-mandated wildcard silently swallowing it (as the old `if let PerVersion`
/// in `deps-lsp`'s B.1b round-merge would have).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateStatuses {
    /// This dependency's source/ecosystem is never checked against OSV at all — applies to
    /// every candidate version alike, so no per-version map is kept. Only ever holds a
    /// [`StructuralSkipReason`], not a bare [`SkipReason`], for the same reason
    /// [`UpgradeStatus::StructurallyUnchecked`] does (issue #1624 S1).
    Structural(StructuralSkipReason),
    /// Per-candidate verdicts from phase B's candidate-check rounds, keyed by the exact
    /// ecosystem-native version a candidate-offering surface (code actions' "update to X"
    /// list, completion's version items) is about to display — one entry per version phase B's
    /// candidate-check round actually covered for this dependency.
    PerVersion(HashMap<ConcreteVersion, UpgradeStatus>),
}

/// Per-dependency, per-candidate-version OSV verdict (#1524).
///
/// The sibling of [`LatestStatusMap`] for callers that need more than one candidate version's
/// own status, not only the registry's single "latest" pick. See [`CandidateStatuses`] for what
/// a single entry can hold.
///
/// A dependency entirely absent from this map means phase B's candidate-check round simply
/// never covered it yet — [`crate::lsp_helpers::candidate_verdict`] treats that the same as an
/// unchecked version: [`crate::lsp_helpers::LatestVerdict::Unverified`], never silently safe.
pub type CandidateStatusMap = HashMap<VulnKey, CandidateStatuses>;

/// A single occurrence's [`VulnerabilityMap`] lookup key, as computed by [`vulnerability_keys`]
/// or [`vuln_key_for`].
///
/// A newtype rather than a bare `String` so a key value is never silently interchangeable
/// with a plain declared or normalized package name at a call site — see [`VulnKeys`] for why
/// that distinction is the point of this whole type pair. Deliberately has no `Borrow<str>`
/// impl: that would let a caller look `VulnerabilityMap` up by a raw `&str`, reopening the
/// exact bug class this type closes (#1413).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VulnKey(String);

impl VulnKey {
    /// Borrows the key as a string slice, e.g. to look it up in a [`VulnerabilityMap`].
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this key belongs to the dependency with this normalized name — either the plain
    /// name key or a version-qualified key [`vulnerability_keys`] derives for a duplicated name.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::test_util::vuln_key;
    ///
    /// assert!(vuln_key("serde").is_for_name("serde"));
    /// assert!(!vuln_key("serde_json").is_for_name("serde"));
    /// assert!(vuln_key("serde\u{0}v:1.0").is_for_name("serde"));
    /// ```
    #[must_use]
    pub fn is_for_name(&self, normalized_name: &str) -> bool {
        self.0
            .split_once(VERSION_QUALIFIER_SEPARATOR)
            .map_or(self.0.as_str(), |(name, _)| name)
            == normalized_name
    }

    /// Builds a key directly from an already-computed name, for `deps-core`-internal fallback
    /// construction (e.g. [`crate::lsp_helpers::resolve_scan_outcome`]'s normalized/declared-name
    /// lookups) where going through [`vuln_key_for`] would require a full [`crate::Dependency`].
    pub(crate) fn from_name(name: String) -> Self {
        Self(name)
    }
}

impl AsRef<str> for VulnKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VulnKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sanitizes only for rendering (CWE-117, #1501) — the stored string is left untouched
        // so the `\u{0}` name/signature separator `vulnerability_keys` relies on for
        // disambiguation keeps working as a `HashMap` key.
        f.write_str(&crate::redact::sanitize_invisible(&self.0))
    }
}

/// Separates the normalized name from the version signature in a duplicated dependency's key.
const VERSION_QUALIFIER_SEPARATOR: char = '\u{0}';

/// Per-occurrence [`VulnKey`]s for one document, keyed by
/// [`Dependency::name_range`](crate::Dependency::name_range) — returned by
/// [`vulnerability_keys`].
///
/// Deliberately exposes no public lookup by [`Range`](crate::position::Range): only
/// [`vuln_key_for`] and [`crate::lsp_helpers::resolve_scan_outcome`] may read an entry, which
/// makes a forgotten normalized-name/declared-name fallback impossible for any caller outside
/// `deps-core` — the exact bug class (four independently hand-written copies of the same
/// 3-step chain) issue #1400 closes on the read-by-range side. Combined with
/// [`VulnerabilityMap`] itself being keyed by `VulnKey` (#1413), a producer or consumer can no
/// longer bypass [`vuln_key_for`]/[`crate::lsp_helpers::resolve_scan_outcome`] with a raw
/// string insert/lookup — the type system rejects it at the call site.
///
/// One caveat survives the re-key: a dependency with a synthetic
/// [`name_range`](crate::Dependency::name_range) has no entry here — [`vulnerability_keys`]
/// excludes it deliberately, since a synthetic range is not a stable per-occurrence position —
/// so it falls back to [`vuln_key_for`]'s plain normalized-name key. Two or more synthetic-range
/// occurrences that share a name therefore still share one [`VulnerabilityMap`] entry.
#[derive(Debug, Clone, Default)]
pub struct VulnKeys(HashMap<crate::position::Range, VulnKey>);

impl VulnKeys {
    /// Looks up the [`VulnKey`] for one occurrence's name range — `pub(crate)` only: the
    /// public entry points are [`vuln_key_for`] (produces a key, falling back to the
    /// normalized name) and [`crate::lsp_helpers::resolve_scan_outcome`] (looks an outcome
    /// up, falling back further to the declared name).
    pub(crate) fn get(&self, range: &crate::position::Range) -> Option<&VulnKey> {
        self.0.get(range)
    }
}

/// Returns the [`VulnKey`] `dep`'s occurrence should be scanned/looked-up under.
///
/// Prefers `keys`' version-qualified entry for `dep`'s
/// [`name_range`](crate::Dependency::name_range) (see [`vulnerability_keys`]); falls back to
/// `formatter`'s ecosystem-normalized name when `keys` is `None` (a caller with no
/// [`EcosystemId`](crate::EcosystemId) to give `vulnerability_keys`, e.g. most test fixtures)
/// or has no entry for this occurrence (e.g. a synthetic name range, which
/// [`vulnerability_keys`] deliberately excludes).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::osv::vuln_key_for;
/// use deps_core::position::{Position, Range};
/// use deps_core::{ConcreteVersion, Dependency, PackageName, VersionReq};
/// use std::any::Any;
///
/// struct SimpleDep {
///     name: PackageName,
///     name_range: Range,
/// }
///
/// impl Dependency for SimpleDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> Range {
///         self.name_range
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         None
///     }
///     fn version_range(&self) -> Option<Range> {
///         None
///     }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// struct SimpleFormatter;
/// impl PackageNaming for SimpleFormatter {}
/// impl PackageRendering for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.as_str().to_string()
///     }
/// }
/// impl RequirementResolution for SimpleFormatter {}
/// impl DiagnosticMessages for SimpleFormatter {}
/// impl DiagnosticPolicy for SimpleFormatter {}
/// impl SourcePolicy for SimpleFormatter {}
/// impl OsvNaming for SimpleFormatter {}
///
/// let dep = SimpleDep {
///     name: PackageName::new("time"),
///     name_range: Range::new(Position::new(0, 0), Position::new(0, 4)).into(),
/// };
///
/// // No `VulnKeys` map (e.g. no `EcosystemId` available) falls back to the normalized name.
/// let key = vuln_key_for(&dep, None, &SimpleFormatter);
/// assert_eq!(key.as_str(), "time");
/// ```
#[must_use]
pub fn vuln_key_for(
    dep: &dyn crate::Dependency,
    keys: Option<&VulnKeys>,
    formatter: &dyn crate::lsp_helpers::EcosystemFormatter,
) -> VulnKey {
    keys.and_then(|k| k.get(&dep.name_range()).cloned())
        .unwrap_or_else(|| VulnKey(formatter.normalize_package_name(dep.name())))
}

/// Computes the [`VulnerabilityMap`] key each occurrence in `parse_result`
/// should be scanned/looked-up under.
///
/// Keyed by [`Dependency::name_range`](crate::Dependency::name_range) —
/// unique per occurrence within one document, so callers holding a specific
/// `dep` (not just its name) can look their own key up directly.
///
/// Normally an occurrence's key is just its normalized name (the common
/// case, and the only form most `VulnerabilityMap` test fixtures use). When
/// two or more occurrences of the *same* name resolve to different signatures
/// — e.g. the same crate under `[dependencies]` and `[dev-dependencies]`, or
/// multiple `[target.'cfg(...)'.dependencies]` blocks (#394), pinned to
/// different versions, or mixing a registry source with a git/path fork —
/// each such occurrence's key is instead qualified with a signature specific
/// to it, so their OSV results can never collide in the shared map.
/// Occurrences that share both a name and an identical signature
/// (registry-source, same in-use version) intentionally keep the plain,
/// shared key and get scanned once: the OSV result would be identical
/// either way, so collapsing them is a dedup, not a gap.
///
/// Every caller that builds or looks up a `VulnerabilityMap` entry for a
/// *specific* dependency occurrence — `deps-lsp`'s `build_scan_targets`,
/// and the vulnerability lookups in `generate_diagnostics_from_cache`,
/// `generate_hover`, and `generate_code_actions` — must go through this
/// function so key construction never drifts out of sync between producer
/// and consumer. A caller with no [`EcosystemId`](crate::EcosystemId) to
/// give (most test fixtures) skips this and falls back to the plain
/// normalized name, which still finds any entry a test inserted under that
/// name directly.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::osv::vulnerability_keys;
/// use deps_core::position::{Position, Range};
/// use deps_core::{ConcreteVersion, Dependency, EcosystemId, PackageName, ParseResult, VersionReq};
/// use std::any::Any;
/// use std::collections::HashMap;
/// use url::Url;
///
/// struct SimpleDep {
///     name: PackageName,
///     version_req: Option<VersionReq>,
///     name_range: Range,
/// }
///
/// impl Dependency for SimpleDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> Range {
///         self.name_range
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         self.version_req.as_ref()
///     }
///     fn version_range(&self) -> Option<Range> {
///         None
///     }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// struct SimpleParseResult {
///     deps: Vec<SimpleDep>,
///     uri: Url,
/// }
///
/// impl ParseResult for SimpleParseResult {
///     fn dependencies(&self) -> Vec<&dyn Dependency> {
///         self.deps.iter().map(|d| d as &dyn Dependency).collect()
///     }
///     fn workspace_root(&self) -> Option<&std::path::Path> {
///         None
///     }
///     fn uri(&self) -> &Url {
///         &self.uri
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// struct SimpleFormatter;
/// impl PackageNaming for SimpleFormatter {}
/// impl PackageRendering for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.as_str().to_string()
///     }
/// }
/// impl RequirementResolution for SimpleFormatter {}
/// impl DiagnosticMessages for SimpleFormatter {}
/// impl DiagnosticPolicy for SimpleFormatter {}
/// impl SourcePolicy for SimpleFormatter {}
/// impl OsvNaming for SimpleFormatter {}
///
/// // `time` declared twice, pinned to two different versions.
/// let parse_result = SimpleParseResult {
///     deps: vec![
///         SimpleDep {
///             name: PackageName::new("time"),
///             version_req: Some(VersionReq::new("=0.1.43")),
///             name_range: Range::new(Position::new(0, 0), Position::new(0, 4)).into(),
///         },
///         SimpleDep {
///             name: PackageName::new("time"),
///             version_req: Some(VersionReq::new("=0.1.44")),
///             name_range: Range::new(Position::new(3, 0), Position::new(3, 4)).into(),
///         },
///     ],
///     uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
/// };
/// let resolved: HashMap<PackageName, ConcreteVersion> = HashMap::new();
///
/// let keys = vulnerability_keys(&parse_result, &resolved, None, &SimpleFormatter, EcosystemId::Cargo);
/// let deps = parse_result.dependencies();
/// let key0 = deps_core::osv::vuln_key_for(deps[0], Some(&keys), &SimpleFormatter);
/// let key1 = deps_core::osv::vuln_key_for(deps[1], Some(&keys), &SimpleFormatter);
/// assert_ne!(key0, key1, "differently-pinned occurrences of one name get distinct keys");
/// ```
pub fn vulnerability_keys(
    parse_result: &dyn crate::ParseResult,
    resolved: &HashMap<crate::PackageName, crate::ConcreteVersion>,
    resolved_candidates: Option<&HashMap<crate::PackageName, Vec<crate::ConcreteVersion>>>,
    formatter: &dyn crate::lsp_helpers::EcosystemFormatter,
    ecosystem: crate::EcosystemId,
) -> VulnKeys {
    use crate::lsp_helpers::resolve_in_use_versions;

    let deps = parse_result.dependencies();

    // One signature per occurrence: public-registry-content deps (F1b) carry their own
    // in-use version ("u" when undeterminable); every other source always carries "n"
    // (`ScanOutcome` is always `Skipped(NonRegistrySource)` there).
    //
    // `resolved_candidates` (#649) lets two occurrences of a renamed/aliased name pinned to
    // different lock-file majors compute distinct `v:{version}` signatures instead of
    // colliding — see `resolve_occurrence_version`.
    let signatures: Vec<(String, String)> = deps
        .iter()
        .map(|dep| {
            let name = formatter.normalize_package_name(dep.name());
            let signature = if formatter.source_is_public_registry_content(&dep.source()) {
                match resolve_in_use_versions(
                    *dep,
                    &name,
                    resolved,
                    resolved_candidates,
                    formatter,
                    ecosystem,
                ) {
                    Some(v) => {
                        let mut signature = format!("v:{}", v.primary());
                        for sibling in v.siblings() {
                            signature.push(' ');
                            signature.push_str(sibling.as_str());
                        }
                        signature
                    }
                    None => "u".to_string(),
                }
            } else {
                "n".to_string()
            };
            (name, signature)
        })
        .collect();

    let mut distinct_signatures_by_name: HashMap<&str, std::collections::HashSet<&str>> =
        HashMap::new();
    for (name, signature) in &signatures {
        distinct_signatures_by_name
            .entry(name.as_str())
            .or_default()
            .insert(signature.as_str());
    }

    let map = deps
        .iter()
        .zip(&signatures)
        // A synthetic `name_range()` is not a stable per-dependency position — every such
        // dependency would share the same key, each insertion evicting the last. Excluding
        // them here falls through to `apply_vulnerability_rule`'s own name-based fallback.
        .filter(|(dep, _)| !dep.name_range_is_synthetic())
        .map(|(dep, (name, signature))| {
            let ambiguous = distinct_signatures_by_name
                .get(name.as_str())
                .is_some_and(|s| s.len() > 1);
            let key = if ambiguous {
                format!("{name}{VERSION_QUALIFIER_SEPARATOR}{signature}")
            } else {
                name.clone()
            };
            (dep.name_range(), VulnKey(key))
        })
        .collect();
    VulnKeys(map)
}

#[cfg(test)]
mod vuln_key_display_tests {
    use super::VulnKey;

    /// #1501: a manifest-controlled dependency name reaching `VulnKey` must not be able to
    /// forge a fake log line via `\n`/`\r` when rendered at a `tracing::warn!(dep = %key, ...)`
    /// call site — `tracing-subscriber` 0.3.23 escapes ESC/C1 on its own but not `\n`/`\r`.
    #[test]
    fn display_sanitizes_newlines_and_carriage_returns() {
        let key = VulnKey::from_name("evil\nWARN forged log line\r\n".to_string());
        let rendered = key.to_string();
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\r'));
    }

    /// #1501 impl-critic M2: the stored string itself must stay untouched by `Display`
    /// sanitization, since `vulnerability_keys` embeds a raw `\u{0}` separator in it for
    /// name/signature disambiguation and that byte must keep surviving as a distinct
    /// `HashMap` key. Pinned on `Display`'s actual rendered output (not just `Eq`, which
    /// would pass identically even if sanitization ran at construction instead of at
    /// render time).
    #[test]
    fn display_sanitizes_render_but_not_the_stored_disambiguation_separator() {
        let key = VulnKey::from_name("pkg\u{0}v:1.0".to_string());

        // Stored identity — what `Hash`/`Eq`, and thus `HashMap` lookups, key off of —
        // still carries the raw `\u{0}` separator.
        assert!(key.as_str().contains('\u{0}'));

        // `Display` sanitizes it away when rendering (e.g. for a `tracing` field).
        let rendered = key.to_string();
        assert!(!rendered.contains('\u{0}'));
        assert_eq!(rendered, "pkg v:1.0");
    }
}

// ---- OSV wire types (private) -------------------------------------------

#[derive(Debug, Serialize)]
pub(super) struct OsvBatchRequest {
    pub(super) queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
pub(super) struct OsvQuery {
    pub(super) package: OsvPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) version: Option<String>,
}

impl OsvQuery {
    pub(super) fn new(target: &ScanTarget, osv_eco: OsvEcosystem) -> Self {
        Self {
            package: OsvPackage {
                name: target.osv_name.name().clone().into_string(),
                ecosystem: osv_eco.as_str().to_owned(),
            },
            version: match osv_eco.version_matching() {
                VersionMatching::ServerSide => Some(target.version.clone().into_string()),
                VersionMatching::LocalUnversioned => None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct OsvPackage {
    pub(super) name: String,
    pub(super) ecosystem: String,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvBatchResponse {
    #[serde(default)]
    pub(super) results: Vec<OsvBatchResult>,
}

/// One entry in a batch response. `vulns` may be entirely absent (not just
/// empty) when the aggregate batch result was paginated — see `architecture.md`
/// §8 invariant 2. `next_page_token`'s presence, not `vulns`'s absence, is
/// the truncation signal.
#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvBatchResult {
    #[serde(default)]
    pub(super) vulns: Vec<OsvVulnStub>,
    #[serde(default)]
    pub(super) next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OsvVulnStub {
    pub(super) id: String,
    #[serde(default)]
    pub(super) modified: String,
}

/// Response shape of `POST /v1/query` — deliberately distinct from the batch
/// endpoint: full advisory records inline, not id stubs (`architecture.md` §8).
///
/// `next_page_token` is deserialized (even though this endpoint is only ever
/// used to *recover from* batch truncation) because `/v1/query` can itself
/// paginate — trusting `vulns.len()` as the authoritative count without
/// checking this field would reintroduce §8 invariant 2 one layer below the
/// fix that closed it for the batch endpoint.
#[derive(Debug, Deserialize, Default)]
pub(super) struct OsvSingleQueryResponse {
    #[serde(default)]
    pub(super) vulns: Vec<OsvVulnRecord>,
    #[serde(default)]
    pub(super) next_page_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(super) struct OsvVulnRecord {
    pub(super) id: String,
    #[serde(default)]
    pub(super) modified: String,
    #[serde(default)]
    pub(super) summary: Option<String>,
    #[serde(default)]
    pub(super) aliases: Vec<String>,
    #[serde(default)]
    pub(super) severity: Vec<OsvSeverityEntry>,
    #[serde(default)]
    pub(super) database_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) affected: Vec<OsvAffected>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct OsvSeverityEntry {
    #[serde(rename = "type", default)]
    pub(super) kind: String,
    #[serde(default)]
    pub(super) score: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(super) struct OsvAffected {
    /// Which package this entry describes. A single OSV record can cover
    /// several packages sharing one advisory id (e.g. a GHSA affecting both
    /// `log4j-core` and `log4j-api`), so this must be checked before
    /// extracting `fixed`/severity data — see `into_advisory`.
    #[serde(default)]
    pub(super) package: Option<OsvPackage>,
    #[serde(default)]
    pub(super) ecosystem_specific: Option<serde_json::Value>,
    /// Per-entry `database_specific` — distinct from [`OsvVulnRecord`]'s
    /// record-level `database_specific` field (already read for
    /// `severity`). Carries OSV's `informational` value (e.g.
    /// RUSTSEC's `"unmaintained"`), read by `severity::classify` (issue
    /// #1007, FR-001).
    #[serde(default)]
    pub(super) database_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) ranges: Vec<OsvRange>,
    #[serde(default)]
    pub(super) versions: Vec<String>,
}

/// OSV's `affected[].ranges[].type` discriminator (issue #1482).
///
/// A `GIT` range's `fixed` event is a 40-hex commit SHA, not a version string in any
/// ecosystem's namespace — [`OsvVulnRecord::into_advisory`] must never let one reach
/// [`Advisory::fixed_versions`], since [`super::compare_version_strings`]'s digit-leading
/// heuristic (and any ecosystem-native comparator) has no meaningful way to rank a SHA
/// against a real version, and [`is_safe_version_string`] alone does not exclude
/// SHA-shaped strings (they are ordinary alphanumeric text).
///
/// [`Self::Unknown`] is the `#[serde(other)]`/`Default` catch-all for a type OSV's schema
/// has not yet documented, or a range with the field omitted entirely — deliberately
/// excluded from [`Advisory::fixed_versions`] the same way `Git` is (fail closed), rather
/// than assumed to be `Semver`/`Ecosystem`-shaped. A record with one unrecognized range
/// among several still resolves normally; only that range's `fixed` events are dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum OsvRangeType {
    /// A SemVer range — `fixed` is a SemVer-shaped version string.
    Semver,
    /// An ecosystem-native range (PEP 440, Maven, npm's `node-semver`, ...) — `fixed` is a
    /// version string in that ecosystem's own namespace.
    Ecosystem,
    /// A git commit-range — `fixed` is a 40-hex commit SHA, never a version string.
    Git,
    /// Unrecognized or omitted `type` value.
    #[serde(other)]
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(super) struct OsvRange {
    #[serde(rename = "type", default)]
    pub(super) range_type: OsvRangeType,
    #[serde(default)]
    pub(super) events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(super) struct OsvEvent {
    #[serde(default)]
    pub(super) introduced: Option<String>,
    #[serde(default)]
    pub(super) fixed: Option<String>,
    #[serde(default)]
    pub(super) last_affected: Option<String>,
}

/// Returns `true` if `id` matches OSV's advisory id grammar
/// (`[A-Za-z0-9._-]+`, non-empty, capped at 128 bytes).
///
/// The same alphabet every real id scheme in this space uses (`RUSTSEC-2020-0071`,
/// `GHSA-xxxx-yyyy-zzzz`, `CVE-2020-26235`); real ids are a few dozen
/// characters, so the cap exists only to bound how much of a record-supplied
/// string can ride along into `Diagnostic.code`, hover markdown, and a
/// `CodeAction` title. `id` is echoed verbatim into a markdown link
/// destination (`push_vulnerability_hover_section`) and a `Diagnostic.code`,
/// so this is the parse-boundary chokepoint that keeps a malformed id from
/// ever reaching either — rejecting it here means every downstream consumer
/// can treat `Advisory.id` as inherently safe, rather than needing to
/// sanitize it again at each render site.
///
/// The bare character class alone is not sufficient (issue #1077 review): `.` is an allowed
/// character (real ids can contain it), so a lone `id` of exactly `"."` or `".."` — RFC 3986's
/// two dot-segments — would otherwise still pass, and `https://osv.dev/vulnerability/..`
/// normalizes (`remove_dot_segments`) to `https://osv.dev/`, walking a consumer's link up and
/// out of `/vulnerability/` without `id` ever containing a literal `/`. Both are rejected as an
/// explicit special case.
pub fn is_valid_osv_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Builds `https://osv.dev/vulnerability/{id}`, or `None` if `id` fails [`is_valid_osv_id`].
///
/// The single validated construction path for this URL (issue #1077 review): used by
/// `OsvVulnRecord::into_advisory` to build [`Advisory::url`], and reusable by any downstream
/// consumer that only has a bare advisory-id *string* (not a whole [`Advisory`]) and needs to
/// independently confirm it is safe to embed as a URI path segment before doing so — e.g.
/// `deps-cli`'s SARIF `helpUri`, which cannot assume every `code` string it sees necessarily
/// went through this crate's own OSV-response parsing (`crate::report::classify`'s documented
/// "any unrecognized diagnostic code -> Vulnerable" fallback can hand it a string this crate
/// never validated at all).
#[must_use]
pub fn validated_osv_url(id: &str) -> Option<String> {
    is_valid_osv_id(id).then(|| format!("https://osv.dev/vulnerability/{id}"))
}

impl OsvVulnRecord {
    /// The `affected[]` entries describing `osv_name`/`osv_eco` (or omitting `package`) — one
    /// record can cover several unrelated packages sharing an advisory id.
    pub(super) fn affected_for(
        &self,
        osv_name: &OsvPackageName,
        osv_eco: OsvEcosystem,
    ) -> Vec<&OsvAffected> {
        self.affected
            .iter()
            .filter(|a| {
                a.package
                    .as_ref()
                    .is_none_or(|p| osv_name == p.name.as_str() && p.ecosystem == osv_eco.as_str())
            })
            .collect()
    }

    /// Converts a raw wire record into the `deps-lsp`-facing [`Advisory`],
    /// or `None` if the record's id fails [`is_valid_osv_id`] (dropped, same
    /// as a 404 on `/v1/vulns/{id}` — the dependency renders with whichever
    /// advisories did resolve, never a half-trusted one). Individual `fixed`
    /// events failing [`is_safe_version_string`] are dropped the same way,
    /// but only that entry — the record as a whole still renders with its
    /// remaining, valid `fixed_versions`.
    ///
    /// `osv_name`/`osv_eco` are the package actually queried: a record can
    /// legitimately cover several unrelated packages sharing one advisory id
    /// (critique S3), so `affected[]` is filtered to entries whose `package`
    /// matches (or omits) before `fixed_versions`/severity are extracted —
    /// otherwise a stranger package's fix version or severity could leak
    /// into this one's rendering.
    pub(super) fn into_advisory(
        self,
        osv_name: &OsvPackageName,
        osv_eco: OsvEcosystem,
    ) -> Option<Advisory> {
        if !is_valid_osv_id(&self.id) {
            tracing::warn!(id = ?self.id, "OSV record has a malformed id, dropping");
            return None;
        }

        let relevant = self.affected_for(osv_name, osv_eco);
        // Every `affected[]` entry named a different package: OSV returned
        // this record in response to our exact query, so that should not
        // happen in practice. Fall back to using every entry rather than
        // rendering fixed_versions/severity as empty/Unknown outright.
        let used_fallback_all = relevant.is_empty() && !self.affected.is_empty();
        let relevant: Vec<&OsvAffected> = if used_fallback_all {
            tracing::warn!(
                id = %self.id, %osv_name, osv_eco = osv_eco.as_str(),
                "no affected[] entry matched the queried package; using all entries"
            );
            self.affected.iter().collect()
        } else {
            relevant
        };

        // FR-002b: `classify()` requires each candidate's `package` to equal
        // `osv_name`/`osv_eco` exactly before trusting its `informational` value, so a
        // `package`-less or fallback-pulled entry can never downgrade this classification
        // for a package it doesn't confirmedly describe (impl-critic M2).
        let severity = super::severity::classify(
            &self.id,
            &self.aliases,
            self.database_specific.as_ref(),
            &relevant,
            osv_name,
            osv_eco,
        );
        let cvss_vector = self
            .severity
            .iter()
            .find(|s| s.kind == "CVSS_V3")
            .or_else(|| self.severity.first())
            .map(|s| s.score.clone());

        // #1482 impl-critic M2: `Git` is routine (every scanned ecosystem has real GIT-range
        // advisories) and warrants no log, but an `Unknown` range carrying a `fixed` event is a
        // signal OSV's schema grew a range `type` this crate doesn't recognize yet — silently
        // dropping it would otherwise make a genuinely fixable advisory quietly render as
        // "no fix available" with nothing in the logs to explain why.
        for range in relevant.iter().flat_map(|a| a.ranges.iter()) {
            if range.range_type == OsvRangeType::Unknown
                && range.events.iter().any(|e| e.fixed.is_some())
            {
                tracing::debug!(
                    id = %self.id,
                    "OSV record has a range with an unrecognized type carrying a fixed event; excluding it from fixed_versions"
                );
            }
        }

        let mut fixed_versions: Vec<String> = relevant
            .iter()
            .flat_map(|a| a.ranges.iter())
            // #1482: a `GIT` range's `fixed` event is a commit SHA, never a version string —
            // and an unrecognized range `type` is excluded the same way, fail closed. Only
            // `SEMVER`/`ECOSYSTEM` ranges carry a `fixed` event safe to treat as a version.
            .filter(|r| matches!(r.range_type, OsvRangeType::Semver | OsvRangeType::Ecosystem))
            .flat_map(|r| r.events.iter())
            .filter_map(|e| e.fixed.clone())
            .filter(|v| {
                let valid = is_safe_version_string(v);
                if !valid {
                    tracing::warn!(
                        id = %self.id, version = %v,
                        "OSV record has a malformed fixed version, dropping"
                    );
                }
                valid
            })
            .collect();
        fixed_versions.sort_by(|a, b| super::compare_version_strings(a, b));
        fixed_versions.dedup();

        // Exhaustive literal (not `Advisory::new`) so a future new field fails to compile here.
        let url = validated_osv_url(&self.id)?;

        Some(Advisory {
            id: self.id,
            modified: self.modified,
            summary: self.summary,
            aliases: self.aliases,
            severity,
            cvss_vector,
            fixed_versions: fixed_versions.into_iter().map(OsvVersion::new).collect(),
            url,
        })
    }
}

#[cfg(test)]
mod recommended_fix_tests {
    use super::*;

    fn advisory(id: &str, severity: VulnSeverity, fixed_versions: &[&str]) -> Arc<Advisory> {
        Arc::new(Advisory {
            id: id.to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity,
            cvss_vector: None,
            fixed_versions: fixed_versions
                .iter()
                .copied()
                .map(OsvVersion::new)
                .collect(),
            url: String::new(),
        })
    }

    fn dv(advisories: Vec<Arc<Advisory>>) -> DependencyVulnerabilities {
        let total = advisories.len();
        DependencyVulnerabilities {
            sibling_matches: None,
            advisories: Capped::new(advisories, total),
            fix_target_status: UpgradeStatus::NotChecked,
        }
    }

    #[test]
    fn no_advisory_has_a_fix_returns_none() {
        let vulns = dv(vec![advisory("A1", VulnSeverity::High, &[])]);
        assert!(vulns.recommended_fix(None).is_none());
    }

    #[test]
    fn multiple_advisories_combine_into_one_fix_at_the_highest_version() {
        // A1 fixed at 1.1.0, A2 fixed at 1.3.0: the recommendation targets
        // the highest of the two and claims both ids.
        let vulns = dv(vec![
            advisory("A1", VulnSeverity::High, &["1.1.0"]),
            advisory("A2", VulnSeverity::Critical, &["1.3.0"]),
        ]);

        let fix = vulns.recommended_fix(None).unwrap();
        assert_eq!(fix.version, "1.3.0");
        // Sorted by severity descending: Critical (A2) before High (A1).
        assert_eq!(fix.advisory_ids, vec!["A2".to_string(), "A1".to_string()]);
    }

    #[test]
    fn candidate_vulnerable_subtracts_only_the_ids_it_names() {
        // Critic's counterexample: A1 fixed 1.1.0, A2 fixed 1.2.0. Phase B
        // reports the candidate is still affected by A1 only, so A1 must be
        // dropped from the claim while A2 survives.
        let vulns = dv(vec![
            advisory("A1", VulnSeverity::High, &["1.1.0"]),
            advisory("A2", VulnSeverity::Medium, &["1.2.0"]),
        ]);
        let latest = UpgradeStatus::CandidateVulnerable {
            version: ConcreteVersion::new("1.2.0"),
            advisory_ids: Capped::new(vec!["A1".to_string()], 1),
            worst_severity: Some(VulnSeverity::High),
        };

        let fix = vulns.recommended_fix(Some(&latest)).unwrap();
        assert_eq!(fix.version, "1.2.0");
        assert_eq!(fix.advisory_ids, vec!["A2".to_string()]);
    }

    #[test]
    fn candidate_vulnerable_subtracting_every_claimed_id_returns_none() {
        let vulns = dv(vec![advisory("A1", VulnSeverity::High, &["1.1.0"])]);
        let latest = UpgradeStatus::CandidateVulnerable {
            version: ConcreteVersion::new("1.1.0"),
            advisory_ids: Capped::new(vec!["A1".to_string()], 1),
            worst_severity: Some(VulnSeverity::High),
        };
        assert!(vulns.recommended_fix(Some(&latest)).is_none());
    }

    #[test]
    fn candidate_clean_subtracts_nothing() {
        let vulns = dv(vec![advisory("A1", VulnSeverity::High, &["1.1.0"])]);
        let latest = UpgradeStatus::CandidateClean {
            version: ConcreteVersion::new("2.0.0"),
        };
        let fix = vulns.recommended_fix(Some(&latest)).unwrap();
        assert_eq!(fix.advisory_ids, vec!["A1".to_string()]);
    }

    #[test]
    fn candidate_unverified_subtracts_nothing() {
        // Issue #1517: an unresolved latest-check (timeout/structural skip) must not be
        // mistaken for a confirmed-vulnerable candidate — `still_applying` stays empty.
        let vulns = dv(vec![advisory("A1", VulnSeverity::High, &["1.1.0"])]);
        let latest = UpgradeStatus::CandidateUnverified {
            version: ConcreteVersion::new("2.0.0"),
            reason: SkipReason::QueryFailed,
        };
        let fix = vulns.recommended_fix(Some(&latest)).unwrap();
        assert_eq!(fix.advisory_ids, vec!["A1".to_string()]);
    }

    #[test]
    fn advisory_without_a_fix_is_excluded_from_the_claim() {
        let vulns = dv(vec![
            advisory("A1", VulnSeverity::High, &["1.1.0"]),
            advisory("A2", VulnSeverity::Critical, &[]),
        ]);

        let fix = vulns.recommended_fix(None).unwrap();
        assert_eq!(fix.version, "1.1.0");
        assert_eq!(fix.advisory_ids, vec!["A1".to_string()]);
    }

    #[test]
    fn subtracted_advisory_with_a_higher_fix_does_not_inflate_the_recommended_version() {
        // Critic S1 counterexample: A1 (fixed 3.0.0) still applies at the candidate and is
        // excluded; A2 (fixed 1.2.0) is claimed. Recommended version must be 1.2.0, computed
        // over what's actually claimed — not 3.0.0, which doesn't even resolve A1.
        let vulns = dv(vec![
            advisory("A1", VulnSeverity::High, &["3.0.0"]),
            advisory("A2", VulnSeverity::Medium, &["1.2.0"]),
        ]);
        let latest = UpgradeStatus::CandidateVulnerable {
            version: ConcreteVersion::new("3.0.0"),
            advisory_ids: Capped::new(vec!["A1".to_string()], 1),
            worst_severity: Some(VulnSeverity::High),
        };

        let fix = vulns.recommended_fix(Some(&latest)).unwrap();
        assert_eq!(fix.version, "1.2.0");
        assert_eq!(fix.advisory_ids, vec!["A2".to_string()]);
    }

    #[test]
    fn equal_severity_ties_break_lexicographically_by_id() {
        let vulns = dv(vec![
            advisory("B1", VulnSeverity::High, &["1.0.0"]),
            advisory("A1", VulnSeverity::High, &["1.0.0"]),
        ]);

        let fix = vulns.recommended_fix(None).unwrap();
        assert_eq!(fix.advisory_ids, vec!["A1".to_string(), "B1".to_string()]);
    }
}

#[cfg(test)]
mod advisories_for_display_tests {
    use super::*;

    fn advisory(id: &str, severity: VulnSeverity) -> Arc<Advisory> {
        Arc::new(Advisory {
            id: id.to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity,
            cvss_vector: None,
            fixed_versions: vec![],
            url: String::new(),
        })
    }

    fn dv(advisories: Vec<Arc<Advisory>>, total: usize) -> DependencyVulnerabilities {
        DependencyVulnerabilities {
            sibling_matches: None,
            advisories: Capped::new(advisories, total),
            fix_target_status: UpgradeStatus::NotChecked,
        }
    }

    /// #1422 S1 regression: `advisories.items()` reflects `fetch_records`'
    /// `buffer_unordered` completion order, not severity or OSV's reported order — a bare
    /// `take(ADVISORY_DISPLAY_CAP)` could show only low-severity advisories while hiding a
    /// `Critical`/`Malicious` one that merely finished fetching last. `advisories_for_display`
    /// must always surface the most severe subset, regardless of input order.
    #[test]
    fn returns_the_most_severe_subset_regardless_of_input_order() {
        // Deliberately out of severity order and larger than ADVISORY_DISPLAY_CAP (5):
        // the single Critical/Malicious advisories are the least-recently-"completed" (last in
        // the vec), exactly the case a plain `take` would drop.
        let advisories = vec![
            advisory("LOW-1", VulnSeverity::Low),
            advisory("MED-1", VulnSeverity::Medium),
            advisory("UNK-1", VulnSeverity::Unknown),
            advisory("LOW-2", VulnSeverity::Low),
            advisory("MED-2", VulnSeverity::Medium),
            advisory("CRIT-1", VulnSeverity::Critical),
            advisory("MAL-1", VulnSeverity::Malicious),
        ];
        let vulns = dv(advisories, 7);

        let display = vulns.advisories_for_display();
        let ids: Vec<&str> = display.items().iter().map(|a| a.id.as_str()).collect();

        assert_eq!(ids.len(), crate::osv::ADVISORY_DISPLAY_CAP);
        // Worst severity first: Malicious, Critical, the two Mediums (tied, by id), then the
        // lower-id Low — UNK-1 (rank below Low) is correctly the one truncated away.
        assert_eq!(ids, vec!["MAL-1", "CRIT-1", "MED-1", "MED-2", "LOW-1"]);
        assert_eq!(display.total(), 7);
    }

    /// Same input, permuted — the output must not depend on arrival order at all, which is
    /// the actual property S1 requires (stability across repeated/concurrent fetches).
    #[test]
    fn output_is_stable_across_differently_ordered_input() {
        let ordered_a = vec![
            advisory("A", VulnSeverity::High),
            advisory("B", VulnSeverity::Critical),
            advisory("C", VulnSeverity::Low),
        ];
        let ordered_b = vec![
            advisory("C", VulnSeverity::Low),
            advisory("B", VulnSeverity::Critical),
            advisory("A", VulnSeverity::High),
        ];

        let ids_a: Vec<String> = dv(ordered_a, 3)
            .advisories_for_display()
            .items()
            .iter()
            .map(|a| a.id.clone())
            .collect();
        let ids_b: Vec<String> = dv(ordered_b, 3)
            .advisories_for_display()
            .items()
            .iter()
            .map(|a| a.id.clone())
            .collect();

        assert_eq!(ids_a, ids_b);
        assert_eq!(
            ids_a,
            vec!["B".to_string(), "A".to_string(), "C".to_string()]
        );
    }

    #[test]
    fn equal_severity_ties_break_lexicographically_by_id() {
        let vulns = dv(
            vec![
                advisory("B1", VulnSeverity::High),
                advisory("A1", VulnSeverity::High),
            ],
            2,
        );

        let display = vulns.advisories_for_display();
        let ids: Vec<&str> = display.items().iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["A1", "B1"]);
    }
}

#[cfg(test)]
mod osv_version_validation_tests {
    use super::*;

    fn record_with_fixed(fixed: &[&str]) -> OsvVulnRecord {
        OsvVulnRecord {
            id: "RUSTSEC-2020-0071".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![OsvAffected {
                versions: vec![],
                package: None,
                ecosystem_specific: None,
                database_specific: None,
                ranges: vec![OsvRange {
                    range_type: OsvRangeType::Ecosystem,
                    events: fixed
                        .iter()
                        .map(|f| OsvEvent {
                            introduced: None,
                            last_affected: None,
                            fixed: Some((*f).to_string()),
                        })
                        .collect(),
                }],
            }],
        }
    }

    #[test]
    fn is_valid_osv_id_rejects_over_length_cap() {
        let long_id = "A".repeat(129);
        assert!(!is_valid_osv_id(&long_id));
        assert!(is_valid_osv_id(&"A".repeat(128)));
    }

    /// Regression test for issue #1077 review: `.`/`..` pass the bare character-class
    /// allowlist (`.` is an allowed character) but are RFC 3986 dot-segments that would
    /// normalize `https://osv.dev/vulnerability/{id}` up and out of `/vulnerability/`.
    #[test]
    fn is_valid_osv_id_rejects_dot_segments() {
        assert!(!is_valid_osv_id("."));
        assert!(!is_valid_osv_id(".."));
        // A real id containing dots (but not equal to a bare dot-segment) is still valid.
        assert!(is_valid_osv_id("RUSTSEC-2020-0071"));
    }

    #[test]
    fn validated_osv_url_builds_the_expected_url_for_a_valid_id() {
        assert_eq!(
            validated_osv_url("RUSTSEC-2020-0071"),
            Some("https://osv.dev/vulnerability/RUSTSEC-2020-0071".to_string())
        );
    }

    #[test]
    fn validated_osv_url_rejects_a_dot_segment_id() {
        assert_eq!(validated_osv_url(".."), None);
    }

    #[test]
    fn validated_osv_url_rejects_an_id_containing_a_slash() {
        // A `/` is not in the allowlist, so a multi-segment traversal attempt embedded in the
        // id (e.g. `../evil`) can never reach `Uri` parsing in the first place.
        assert_eq!(validated_osv_url("../evil"), None);
    }

    /// #1271: `Advisory::new` takes only `id`, never a caller-supplied `url` — this asserts
    /// the derived value actually matches `validated_osv_url`'s own formula, so the two can't
    /// drift apart.
    #[test]
    fn advisory_new_derives_url_from_id() {
        let advisory = Advisory::new(
            "RUSTSEC-2020-0071".to_string(),
            "2023-01-01T00:00:00Z".to_string(),
            VulnSeverity::High,
        )
        .expect("valid osv id");
        assert_eq!(
            advisory.url(),
            validated_osv_url("RUSTSEC-2020-0071").unwrap()
        );
    }

    /// #1271: an id that fails `is_valid_osv_id` (and so cannot produce a safe `url`) must
    /// make `Advisory` unconstructible via `new` — a future caller cannot bypass this by
    /// supplying a raw `url` directly, since the constructor no longer accepts one at all.
    #[test]
    fn advisory_new_rejects_a_malformed_id() {
        assert!(
            Advisory::new(
                "..".to_string(),
                "2023-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .is_none()
        );
        // #1272 round 2 critic M4: the length cap matters at least as much as the
        // dot-segment case for the unbounded-length story this issue is about.
        assert!(
            Advisory::new(
                "A".repeat(129),
                "2023-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .is_none()
        );
    }

    /// Regression test for issue #1077 review: a record whose id is a dot-segment must be
    /// dropped by `into_advisory` itself (same as any other malformed id), not merely have a
    /// bad `helpUri` built from it somewhere downstream.
    #[test]
    fn into_advisory_drops_a_record_whose_id_is_a_dot_segment() {
        let record = OsvVulnRecord {
            id: "..".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![],
        };
        assert!(
            record
                .into_advisory(&OsvPackageName::new("pkg").unwrap(), OsvEcosystem::CratesIo)
                .is_none()
        );
    }

    /// #1505 finding 6: a malformed OSV record id used to be interpolated raw
    /// (`id = %self.id`), letting a spoofed/malicious OSV response forge a log line.
    /// `id` is now a `?`-Debug field, which escapes a raw newline instead of emitting a real
    /// line break.
    #[test]
    #[cfg(feature = "test-util")]
    fn into_advisory_malformed_id_with_control_char_logs_sanitized() {
        let malicious_id = "not-a-real-id\r\n\x1b[31mERROR deps_lsp: FORGED";
        let record = OsvVulnRecord {
            id: malicious_id.to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![],
        };

        let log = crate::test_util::capture_tracing_output(|| {
            assert!(
                record
                    .into_advisory(&OsvPackageName::new("pkg").unwrap(), OsvEcosystem::CratesIo)
                    .is_none()
            );
        });

        assert_eq!(
            log.lines().count(),
            1,
            "a malformed id must not forge an extra log line: {log:?}"
        );
        assert!(
            !log.contains(malicious_id),
            "the raw, un-escaped payload (with its literal CR/ESC bytes) must not survive \
             intact: {log:?}"
        );
    }

    #[test]
    fn malformed_fixed_version_is_dropped_but_record_still_resolves() {
        // Security S-1: a `fixed` value containing manifest-breakout
        // characters (quotes, comma, newline) must never reach
        // `Advisory::fixed_versions`, since that field is later written
        // verbatim into a `TextEdit`.
        let record = record_with_fixed(&["1.0.0", "1.0.0\", git = \"https://evil/x"]);
        let advisory = record
            .into_advisory(&OsvPackageName::new("pkg").unwrap(), OsvEcosystem::CratesIo)
            .expect("valid id, should still resolve");

        assert_eq!(advisory.fixed_versions, vec![OsvVersion::new("1.0.0")]);
    }

    #[test]
    fn fixed_version_over_length_cap_is_dropped() {
        let long_version = format!("1.0.0-{}", "a".repeat(64));
        let record = record_with_fixed(&["1.0.0", &long_version]);
        let advisory = record
            .into_advisory(&OsvPackageName::new("pkg").unwrap(), OsvEcosystem::CratesIo)
            .unwrap();

        assert_eq!(advisory.fixed_versions, vec![OsvVersion::new("1.0.0")]);
    }

    /// #1663: a multi-package PyPI record (`quart` + `werkzeug`) queried under the PEP 503
    /// normalized name keeps only `werkzeug`'s fix, so `PypiFormatter::osv_package_name` must
    /// hand the matcher that normalized spelling.
    #[test]
    fn into_advisory_pypi_multi_package_record_keeps_only_queried_package_fix() {
        let affected = |name: &str, fixed: &str| OsvAffected {
            versions: vec![],
            package: Some(OsvPackage {
                name: name.to_string(),
                ecosystem: "PyPI".to_string(),
            }),
            ecosystem_specific: None,
            database_specific: None,
            ranges: vec![OsvRange {
                range_type: OsvRangeType::Ecosystem,
                events: vec![OsvEvent {
                    introduced: None,
                    last_affected: None,
                    fixed: Some(fixed.to_string()),
                }],
            }],
        };
        let record = OsvVulnRecord {
            id: "GHSA-hrfv-mqp8-q5rw".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![affected("quart", "0.19.4"), affected("werkzeug", "3.0.1")],
        };

        let advisory = record
            .into_advisory(
                &OsvPackageName::new("werkzeug").unwrap(),
                OsvEcosystem::PyPI,
            )
            .expect("valid id");
        assert_eq!(advisory.fixed_versions, vec![OsvVersion::new("3.0.1")]);
    }

    /// #1482: a PYSEC-shaped record with a `GIT` range's commit-SHA `fixed` event alongside
    /// an `ECOSYSTEM` range's real version fix. The SHA must never enter `fixed_versions` —
    /// mirrors the real `requests` PYSEC-2023-74 shape (`74ea7cf7...` `GIT`-range fix vs.
    /// `2.31.0` `ECOSYSTEM`-range fix).
    #[test]
    fn git_range_fixed_sha_is_excluded_but_ecosystem_range_fix_survives() {
        let record = OsvVulnRecord {
            id: "PYSEC-2023-74".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![OsvAffected {
                versions: vec![],
                package: None,
                ecosystem_specific: None,
                database_specific: None,
                ranges: vec![
                    OsvRange {
                        range_type: OsvRangeType::Git,
                        events: vec![OsvEvent {
                            introduced: None,
                            last_affected: None,
                            fixed: Some("74ea7cf7b6a3e2ff56cd76ce0d7bfa7ddd7bcaba".to_string()),
                        }],
                    },
                    OsvRange {
                        range_type: OsvRangeType::Ecosystem,
                        events: vec![OsvEvent {
                            introduced: None,
                            last_affected: None,
                            fixed: Some("2.31.0".to_string()),
                        }],
                    },
                ],
            }],
        };

        let advisory = record
            .into_advisory(
                &OsvPackageName::new("requests").unwrap(),
                OsvEcosystem::PyPI,
            )
            .expect("valid id, should resolve");

        assert_eq!(advisory.fixed_versions, vec![OsvVersion::new("2.31.0")]);
    }

    /// #1482 end-to-end: the GIT-range SHA must never win `recommended_fix()` over the real
    /// ECOSYSTEM-range fix — the actual degradation this issue reports (a genuinely fixable
    /// vulnerability collapsing to "no fix available", or recommending an unusable SHA as the
    /// upgrade target).
    #[test]
    fn recommended_fix_never_targets_a_git_range_sha() {
        let record = OsvVulnRecord {
            id: "PYSEC-2023-74".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![OsvAffected {
                versions: vec![],
                package: None,
                ecosystem_specific: None,
                database_specific: None,
                ranges: vec![
                    OsvRange {
                        range_type: OsvRangeType::Git,
                        events: vec![OsvEvent {
                            introduced: None,
                            last_affected: None,
                            fixed: Some("74ea7cf7b6a3e2ff56cd76ce0d7bfa7ddd7bcaba".to_string()),
                        }],
                    },
                    OsvRange {
                        range_type: OsvRangeType::Ecosystem,
                        events: vec![OsvEvent {
                            introduced: None,
                            last_affected: None,
                            fixed: Some("2.31.0".to_string()),
                        }],
                    },
                ],
            }],
        };
        let advisory = Arc::new(
            record
                .into_advisory(
                    &OsvPackageName::new("requests").unwrap(),
                    OsvEcosystem::PyPI,
                )
                .expect("valid id, should resolve"),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1));

        let fix = dv.recommended_fix(None).expect("a fix must be recommended");
        assert_eq!(fix.version, "2.31.0");
    }

    /// Tester gap: every prior GIT-range test pairs the SHA with an ECOSYSTEM/SEMVER fix in
    /// the same record. When a record's `affected[].ranges` are *all* `GIT`-typed — no
    /// verified fix exists at all — `fixed_versions` must end up empty and `recommended_fix()`
    /// must return `None`, not silently fall back to treating the SHA as usable.
    #[test]
    fn all_git_range_record_has_no_fixed_versions_and_no_recommended_fix() {
        let record = OsvVulnRecord {
            id: "GHSA-all-git".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![OsvAffected {
                versions: vec![],
                package: None,
                ecosystem_specific: None,
                database_specific: None,
                ranges: vec![OsvRange {
                    range_type: OsvRangeType::Git,
                    events: vec![OsvEvent {
                        introduced: None,
                        last_affected: None,
                        fixed: Some("74ea7cf7b6a3e2ff56cd76ce0d7bfa7ddd7bcaba".to_string()),
                    }],
                }],
            }],
        };
        let advisory = record
            .into_advisory(&OsvPackageName::new("pkg").unwrap(), OsvEcosystem::CratesIo)
            .expect("valid id, should resolve");
        assert!(
            advisory.fixed_versions.is_empty(),
            "an all-GIT-range record has no verified fix"
        );

        let dv = DependencyVulnerabilities::new(Capped::new(vec![Arc::new(advisory)], 1));
        assert!(
            dv.recommended_fix(None).is_none(),
            "recommended_fix must return None when no advisory has a claimable fix"
        );
    }

    /// #1482: a range whose `type` OSV has not documented (or that is malformed) must be
    /// excluded the same way `GIT` is — fail closed rather than assumed usable.
    #[test]
    fn unrecognized_range_type_is_excluded() {
        let record = OsvVulnRecord {
            id: "GHSA-unknown-type".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: vec![],
            database_specific: None,
            affected: vec![OsvAffected {
                versions: vec![],
                package: None,
                ecosystem_specific: None,
                database_specific: None,
                ranges: vec![OsvRange {
                    range_type: OsvRangeType::Unknown,
                    events: vec![OsvEvent {
                        introduced: None,
                        last_affected: None,
                        fixed: Some("1.2.3".to_string()),
                    }],
                }],
            }],
        };

        let advisory = record
            .into_advisory(&OsvPackageName::new("pkg").unwrap(), OsvEcosystem::CratesIo)
            .expect("valid id, should resolve");

        assert!(advisory.fixed_versions.is_empty());
    }

    /// A range's `type` field missing entirely from the wire JSON must deserialize as
    /// [`OsvRangeType::Unknown`] (fail closed), not silently default to `Semver`/`Ecosystem`.
    #[test]
    fn range_type_defaults_to_unknown_when_field_is_absent() {
        let json = r#"{"events":[{"fixed":"1.2.3"}]}"#;
        let range: OsvRange = serde_json::from_str(json).unwrap();
        assert_eq!(range.range_type, OsvRangeType::Unknown);
    }

    #[test]
    fn range_type_deserializes_known_variants() {
        for (wire, expected) in [
            (r#""SEMVER""#, OsvRangeType::Semver),
            (r#""ECOSYSTEM""#, OsvRangeType::Ecosystem),
            (r#""GIT""#, OsvRangeType::Git),
            (r#""SOME-FUTURE-TYPE""#, OsvRangeType::Unknown),
        ] {
            let got: OsvRangeType = serde_json::from_str(wire).unwrap();
            assert_eq!(got, expected, "unexpected mapping for {wire}");
        }
    }

    #[test]
    fn every_fixed_version_malformed_yields_empty_fixed_versions_not_a_dropped_advisory() {
        let record = record_with_fixed(&["1.0.0\nEvil"]);
        let advisory = record
            .into_advisory(&OsvPackageName::new("pkg").unwrap(), OsvEcosystem::CratesIo)
            .expect("the advisory itself is still valid, just with no usable fix");

        assert!(advisory.fixed_versions.is_empty());
    }

    #[test]
    fn realistic_version_syntax_is_accepted() {
        // SemVer, PEP 440 pre/post-release segments, Go's `+incompatible`.
        for v in [
            "1.2.3",
            "1.2.3-alpha.1",
            "1.2.3+incompatible",
            "1.2.3.post1",
        ] {
            assert!(is_safe_version_string(v), "expected {v:?} to be valid");
        }
    }

    #[test]
    fn manifest_breakout_characters_are_rejected() {
        for v in ["1.0.0\", git = \"evil", "1.0.0,2.0.0", "1.0.0\nEvil", ""] {
            assert!(!is_safe_version_string(v), "expected {v:?} to be rejected");
        }
    }
}

/// Issue #1007: `into_advisory` end-to-end against the exact live-verified OSV wire
/// shape for `RUSTSEC-2024-0320` (`yaml-rust`) — re-queried 2026-09-14 via
/// `POST https://api.osv.dev/v1/query {"package":{"name":"yaml-rust","ecosystem":"crates.io"},
/// "version":"0.4.5"}`. Captured as a fixture rather than a live HTTP call per the
/// project's existing `mockito`-based test convention.
#[cfg(test)]
mod informational_record_tests {
    use super::*;

    const YAML_RUST_RUSTSEC_2024_0320: &str = r#"{
        "id": "RUSTSEC-2024-0320",
        "summary": "yaml-rust is unmaintained.",
        "modified": "2024-11-01T12:31:51Z",
        "database_specific": { "license": "CC0-1.0" },
        "affected": [
            {
                "package": {
                    "name": "yaml-rust",
                    "ecosystem": "crates.io",
                    "purl": "pkg:cargo/yaml-rust"
                },
                "ranges": [
                    { "type": "SEMVER", "events": [{ "introduced": "0.0.0-0" }] }
                ],
                "ecosystem_specific": {
                    "affects": { "arch": [], "functions": [], "os": [] },
                    "affected_functions": null
                },
                "database_specific": {
                    "categories": [],
                    "cvss": null,
                    "informational": "unmaintained",
                    "source": "https://github.com/rustsec/advisory-db/blob/osv/crates/RUSTSEC-2024-0320.json"
                }
            }
        ],
        "schema_version": "1.7.3"
    }"#;

    #[test]
    fn live_yaml_rust_unmaintained_record_classifies_as_informational() {
        let record: OsvVulnRecord = serde_json::from_str(YAML_RUST_RUSTSEC_2024_0320).unwrap();
        let advisory = record
            .into_advisory(
                &OsvPackageName::new("yaml-rust").unwrap(),
                OsvEcosystem::CratesIo,
            )
            .expect("valid id, should resolve");

        assert_eq!(advisory.severity, VulnSeverity::Informational);
        assert!(
            advisory.fixed_versions.is_empty(),
            "an unmaintained notice has no fixed version"
        );
        assert_eq!(
            advisory.summary.as_deref(),
            Some("yaml-rust is unmaintained.")
        );
    }

    /// M3 (impl-critic): confirms `into_advisory` itself computes the
    /// genuine-match signal end-to-end — not just that `classify()` respects
    /// a pre-computed flag handed to it directly. Queries a *different*
    /// package than the record's sole `affected[]` entry names, so
    /// `into_advisory` falls back to its "no entry matched; using all
    /// entries" path (FR-002b) — the `informational` value on that stranger
    /// entry must not classify the record as `Informational`.
    #[test]
    fn into_advisory_rejects_informational_from_fallback_all_entries() {
        let record: OsvVulnRecord = serde_json::from_str(YAML_RUST_RUSTSEC_2024_0320).unwrap();
        let advisory = record
            .into_advisory(
                &OsvPackageName::new("some-other-crate").unwrap(),
                OsvEcosystem::CratesIo,
            )
            .expect("valid id, should resolve");

        assert_ne!(advisory.severity, VulnSeverity::Informational);
    }

    /// M2/M3 (impl-critic): an `affected[]` entry with no `package` field at
    /// all is lenient-matched into `into_advisory`'s `relevant` set (not the
    /// fallback-all path — see the existing `is_none_or` filter), but must
    /// still not count as a genuine per-package match for the informational
    /// check specifically.
    #[test]
    fn into_advisory_rejects_informational_from_package_less_entry() {
        let json = r#"{
            "id": "RUSTSEC-2020-0071",
            "modified": "2023-01-01T00:00:00Z",
            "affected": [
                { "database_specific": { "informational": "unmaintained" } }
            ]
        }"#;
        let record: OsvVulnRecord = serde_json::from_str(json).unwrap();
        let advisory = record
            .into_advisory(
                &OsvPackageName::new("yaml-rust").unwrap(),
                OsvEcosystem::CratesIo,
            )
            .expect("valid id, should resolve");

        assert_ne!(advisory.severity, VulnSeverity::Informational);
    }

    /// H1 (security): RUSTSEC's `"unsound"` category (live-verified shape,
    /// e.g. `RUSTSEC-2021-0145`/`atty`) is a real memory-safety/UB finding,
    /// not a maintenance-status notice — `into_advisory` must never classify
    /// it as `Informational`.
    #[test]
    fn into_advisory_rejects_unsound_value() {
        let json = r#"{
            "id": "RUSTSEC-2021-0145",
            "modified": "2021-07-06T00:00:00Z",
            "affected": [
                {
                    "package": { "name": "atty", "ecosystem": "crates.io" },
                    "database_specific": { "informational": "unsound" }
                }
            ]
        }"#;
        let record: OsvVulnRecord = serde_json::from_str(json).unwrap();
        let advisory = record
            .into_advisory(
                &OsvPackageName::new("atty").unwrap(),
                OsvEcosystem::CratesIo,
            )
            .expect("valid id, should resolve");

        assert_ne!(
            advisory.severity,
            VulnSeverity::Informational,
            "an unsound (UB/memory-safety) advisory must never be downgraded to Informational"
        );
    }

    /// M4 (impl-critic, low): a non-object `database_specific` and a
    /// non-string `informational` value must never panic — both guard
    /// chains (`.as_object()`-free `.get()`/`.as_str()`) already handle
    /// this by returning `None`, this pins that behavior.
    #[test]
    fn into_advisory_does_not_panic_on_non_object_database_specific_or_non_string_informational() {
        let json = r#"{
            "id": "RUSTSEC-2020-0071",
            "modified": "2023-01-01T00:00:00Z",
            "affected": [
                {
                    "package": { "name": "yaml-rust", "ecosystem": "crates.io" },
                    "database_specific": "not-an-object"
                },
                {
                    "package": { "name": "yaml-rust", "ecosystem": "crates.io" },
                    "database_specific": { "informational": 12345 }
                }
            ]
        }"#;
        let record: OsvVulnRecord = serde_json::from_str(json).unwrap();
        let advisory = record
            .into_advisory(
                &OsvPackageName::new("yaml-rust").unwrap(),
                OsvEcosystem::CratesIo,
            )
            .expect("valid id, should resolve");

        assert_eq!(advisory.severity, VulnSeverity::Unknown);
    }
}

/// Issue #649 FR-004: `vulnerability_keys` with a populated `resolved_candidates` map, the
/// exact call shape `deps-lsp`'s `build_scan_targets`/phase A OSV scan use. Every production
/// `vulnerability_keys` call site was migrated to accept this parameter, but per the
/// pre-review test-coverage audit, every *test* call site only ever passed `None` — this
/// closes that direct-coverage gap.
#[cfg(test)]
mod vulnerability_keys_candidates_tests {
    use super::*;
    use crate::lsp_helpers::test_support::{MOCK_FORMATTER, MockDep};
    use crate::position::{Position, Range};
    use crate::{ConcreteVersion, EcosystemId, PackageName, ParseResult, VersionReq};

    #[test]
    fn distinct_signatures_for_two_occurrences_resolving_to_different_candidates() {
        // The serde/serde_old shape from issue #649: one plain occurrence pinned to the
        // current major, one renamed occurrence pinned to an older major, both sharing the
        // resolved package name `serde`.
        let current_major = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("1.0"),
            version_range: Range::new(Position::new(0, 0), Position::new(0, 4)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
        };
        let renamed_old_major = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("0.9"),
            version_range: Range::new(Position::new(1, 0), Position::new(1, 4)),
            name_range: Range::new(Position::new(1, 0), Position::new(1, 9)),
        };

        struct TwoOccurrenceParseResult {
            deps: Vec<MockDep>,
            uri: url::Url,
        }
        impl crate::ParseResult for TwoOccurrenceParseResult {
            fn dependencies(&self) -> Vec<&dyn crate::Dependency> {
                self.deps
                    .iter()
                    .map(|d| d as &dyn crate::Dependency)
                    .collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let parse_result = TwoOccurrenceParseResult {
            deps: vec![current_major, renamed_old_major],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut resolved = std::collections::HashMap::new();
        resolved.insert(PackageName::new("serde"), ConcreteVersion::from("1.0.219"));
        let mut candidates = std::collections::HashMap::new();
        candidates.insert(
            PackageName::new("serde"),
            vec![
                ConcreteVersion::from("0.9.15"),
                ConcreteVersion::from("1.0.219"),
            ],
        );

        let keys = vulnerability_keys(
            &parse_result,
            &resolved,
            Some(&candidates),
            &MOCK_FORMATTER,
            EcosystemId::Cargo,
        );
        let deps = parse_result.dependencies();
        let current_key = keys.get(&deps[0].name_range()).unwrap();
        let renamed_key = keys.get(&deps[1].name_range()).unwrap();

        assert_ne!(
            current_key, renamed_key,
            "the current-major and renamed-old-major occurrences must not share an OSV key"
        );
        assert!(
            current_key.as_str().ends_with("v:1.0.219"),
            "current-major occurrence's key must carry its own resolved version: {current_key}"
        );
        assert!(
            renamed_key.as_str().ends_with("v:0.9.15"),
            "renamed occurrence's key must carry its own resolved version, not the collapsed \
             1.0.219: {renamed_key}"
        );
    }

    /// Critic finding S1 (#905): a dependency with a synthetic `name_range()` (e.g.
    /// `deps-dart`'s container-anchor alias resolution) must not get an entry in this map —
    /// every such dependency in one document would share the exact same key
    /// (`Range::default()`), each insertion silently evicting the last, so a real dependency
    /// that happens to collide with that same sentinel (a pre-existing, rarer miss case on
    /// other ecosystems) could otherwise be handed an unrelated package's OSV lookup key.
    #[test]
    fn vulnerability_keys_excludes_synthetic_range_dependencies() {
        use crate::lsp_helpers::test_support::{MockMixedParseResult, MockSyntheticRangeDep};

        let parse_result = MockMixedParseResult {
            deps: vec![
                Box::new(MockSyntheticRangeDep {
                    name: PackageName::new("synthetic-pkg"),
                }),
                Box::new(MockDep {
                    name: PackageName::new("real-pkg"),
                    version_req: VersionReq::new("1.0.0"),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 8)),
                }),
            ],
            uri: crate::test_util::test_uri("/test/pubspec.yaml"),
        };

        let resolved = std::collections::HashMap::new();
        let keys = vulnerability_keys(
            &parse_result,
            &resolved,
            None,
            &MOCK_FORMATTER,
            EcosystemId::Cargo,
        );

        let deps = parse_result.dependencies();
        assert!(
            keys.get(&deps[0].name_range()).is_none(),
            "the synthetic-range dependency must not be keyed"
        );
        assert!(
            keys.get(&deps[1].name_range()).is_some(),
            "the real dependency's own range must still be present"
        );
    }

    /// Resolves each occurrence's `version_requirement()` text to a fixed tag set on one commit.
    struct PinByRequirementFormatter;

    impl crate::lsp_helpers::PackageNaming for PinByRequirementFormatter {}
    impl crate::lsp_helpers::PackageRendering for PinByRequirementFormatter {
        fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
            version.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.as_str().to_string()
        }
    }
    impl crate::lsp_helpers::RequirementResolution for PinByRequirementFormatter {
        fn resolved_pin_version(
            &self,
            dep: &dyn crate::Dependency,
        ) -> crate::lsp_helpers::PinResolution {
            let Some(req) = dep.version_requirement() else {
                return crate::lsp_helpers::PinResolution::Unresolved;
            };
            let tags: &[&str] = match req.as_str() {
                "with-sibling" => &["v4.8.0", "v4.9.0"],
                _ => &["v4.8.0"],
            };
            let sha = crate::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap();
            let index = crate::lsp_helpers::TagIndex::from_tags(tags.iter().map(|t| (*t, &sha)));
            index.pin_resolution(&sha, None)
        }
    }
    impl crate::lsp_helpers::DiagnosticMessages for PinByRequirementFormatter {}
    impl crate::lsp_helpers::DiagnosticPolicy for PinByRequirementFormatter {}
    impl crate::lsp_helpers::SourcePolicy for PinByRequirementFormatter {}
    impl crate::lsp_helpers::OsvNaming for PinByRequirementFormatter {}

    /// #1709 (M6): synthetic-range occurrences of one name have no per-occurrence key, so they
    /// share the plain normalized-name key however their sibling sets differ (known caveat).
    #[test]
    fn synthetic_range_occurrences_share_the_plain_key() {
        use crate::lsp_helpers::test_support::{MockMixedParseResult, MockSyntheticRangeDep};

        let parse_result = MockMixedParseResult {
            deps: vec![
                Box::new(MockSyntheticRangeDep {
                    name: PackageName::new("actions/checkout"),
                }),
                Box::new(MockSyntheticRangeDep {
                    name: PackageName::new("actions/checkout"),
                }),
            ],
            uri: crate::test_util::test_uri("/test/workflow.yml"),
        };
        let keys = vulnerability_keys(
            &parse_result,
            &std::collections::HashMap::new(),
            None,
            &PinByRequirementFormatter,
            EcosystemId::GithubActions,
        );
        let deps = parse_result.dependencies();
        let key = |i: usize| vuln_key_for(deps[i], Some(&keys), &PinByRequirementFormatter);
        assert_eq!(key(0), key(1));
        assert_eq!(key(0).as_str(), "actions/checkout");
    }

    /// #1709: two occurrences sharing a primary tag but not their sibling sets must not share a
    /// key, or the dedup in `build_scan_targets` would drop the one carrying siblings.
    #[test]
    fn vulnerability_keys_differ_when_only_the_sibling_set_differs() {
        use crate::lsp_helpers::test_support::MockParseResult;

        let dep = |requirement: &str, line: u32| MockDep {
            name: PackageName::new("actions/checkout"),
            version_req: VersionReq::new(requirement),
            version_range: Range::new(Position::new(line, 10), Position::new(line, 20)),
            name_range: Range::new(Position::new(line, 0), Position::new(line, 8)),
        };
        let parse_result = MockParseResult {
            deps: vec![dep("with-sibling", 0), dep("alone", 1)],
            uri: crate::test_util::test_uri("/test/workflow.yml"),
        };

        let keys = vulnerability_keys(
            &parse_result,
            &std::collections::HashMap::new(),
            None,
            &PinByRequirementFormatter,
            EcosystemId::GithubActions,
        );
        let deps = parse_result.dependencies();
        assert_ne!(
            keys.get(&deps[0].name_range()),
            keys.get(&deps[1].name_range())
        );
    }
}
