//! `.cargo/config.toml` discovery and `[registries.*]`/`[source.*]` resolution.
//!
//! Resolves a Cargo `registry = "<alias>"` dependency's alias into a concrete, fetchable
//! sparse index URL by reading the same `.cargo/config.toml` hierarchy (and
//! `$CARGO_HOME/config.toml`) Cargo itself consults, plus the
//! `CARGO_REGISTRIES_<NAME>_INDEX`/`_TOKEN` environment variable overrides Cargo
//! documents. Also resolves a `[source.crates-io] replace-with` chain into a mirror index
//! for plain (`Registry`-sourced) dependencies (spec FR-005/006/007).
//!
//! # Security model (read before touching this module)
//!
//! A workspace's own `Cargo.toml`/`.cargo/config.toml` is attacker-controlled the moment a
//! hostile repository is cloned and opened — this LSP parses on file open, before any build
//! ever runs. Two related threats this module closes, each by its own decision:
//!
//! - **Egress** (where a request may go, #443). Every index URL is classified by the shared
//!   URL-alone rule, [`OperatorRegistries::classify`]: a URL equal to one the operator declared
//!   (`$CARGO_HOME/config.toml`, or a `CARGO_REGISTRIES_<ALIAS>_INDEX` variable) is
//!   [`RegistryTrust::Trusted`] and skips the workspace policy; any other URL is
//!   [`RegistryTrust::WorkspaceDeclared`] and is checked against the live
//!   [`deps_core::net_policy::RegistryAccessPolicy`]. The never-a-registry floor applies to both,
//!   so a `$CARGO_HOME` registry on a loopback or link-local host is rejected. Provenance plays no
//!   part: a workspace alias that names an operator URL gets the operator URL's trust.
//! - **Credential exfiltration.** A credential is a separate decision and lives inside
//!   [`RegistryIndex`] as `IndexAccess::Credentialed`, which exists only for an index that
//!   classified Trusted. It is bound to a *URL the operator declared*: the same URL gets the same
//!   credential whichever alias or manifest field names it, so the result never depends on
//!   registration order, and no other URL ever gets one. Enforced **structurally**:
//!   - `parse_workspace_registries_raw` has no return type capable of expressing a token.
//!   - Only `parse_cargo_home_registries_raw` and the `CARGO_REGISTRIES_<ALIAS>_TOKEN` lookup
//!     produce an `AuthToken`, and `cargo_operator_with_env` binds each to the URL its alias
//!     declares. An index receives a credential only through `RegistryIndex::declared_bound`,
//!     from that binding, and only when the URL classified Trusted.
//!   - No constructor takes a [`Provenance`] or a [`RegistryTrust`]: a caller cannot assert trust,
//!     only present a URL to the operator set. [`Provenance`] is diagnostics only.
//!   - A request carrying a credential travels over an origin-confined transport, so a redirect
//!     cannot move the header to another origin.
//!
//! See spec `specs/023-cargo-custom-registries/spec.md` FR-008/FR-009, spec 084 and the
//! design review handoffs cited there for the rounds of critique the credential boundary
//! survived.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use toml_span::value::Table;

use deps_core::config_trust::{EnvPath, OperatorEnvVar, OperatorPath};
use deps_core::net_policy::{
    BlockedHost, DeclaredRegistry, EnvSource, IndexUrlError, OperatorRegistries, ProcessEnv,
    RedactedUrl, RegistryAccessPolicy, RegistryRejectionClassifier, RegistryRejectionReason,
    RegistryUrlKind, TrustedConstantRegistryUrl, TrustedPrefix, ValidatedRegistryUrl,
};
use deps_core::{DEFAULT_MAX_CACHED_FILES, EcosystemId, MtimeFileCache};

/// A registry bearer-token credential, redacted everywhere except the one call site that
/// formats it into an `Authorization` header.
///
/// Constructible only from within this module (see the module-level security-model docs) —
/// no other code path in this crate has the means to produce one. A thin wrapper over
/// [`deps_core::secret::Redacted`] rather than a bare type alias: `Debug` prints
/// `AuthToken(***)`, not `Redacted(***)`, so a panic message or log line still names which
/// credential leaked its type.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthToken(deps_core::secret::Redacted);

impl AuthToken {
    /// Wraps `token`. Kept `pub(crate)`: the module-level security-model docs above are the
    /// enforcement, and a token only ever reaches an index through `RegistryIndex::declared_bound`.
    pub(crate) fn new(token: String) -> Self {
        Self(deps_core::secret::Redacted::new(token))
    }

    /// The wrapped secret, for building the `Authorization` value.
    pub(crate) const fn as_redacted(&self) -> &deps_core::secret::Redacted {
        &self.0
    }

    /// The raw token value, for asserting on it in tests.
    #[cfg(test)]
    pub(crate) fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthToken(***)")
    }
}

impl std::fmt::Display for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// Where a [`ResolvedRegistryEntry`] came from.
///
/// **Diagnostics and logging only.** Nothing decides egress or a credential from it: the
/// egress decision is the URL-alone rule ([`OperatorRegistries::classify`]) and a credential is
/// held by the [`RegistryIndex`] itself (see the module-level docs). A change that starts
/// branching on this to decide either reintroduces the vulnerability class this design closed.
///
/// **Exhaustive** (issue #769): a closed 2-variant `CargoHome`/`Workspace` split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Resolved from `$CARGO_HOME/config.toml` or a `CARGO_REGISTRIES_*` environment
    /// variable — the user's own trusted environment, not something a cloned repository
    /// controls.
    CargoHome,
    /// Resolved from a `.cargo/config.toml` found while walking up from the opened
    /// manifest's directory — a file a repository being opened can fully control.
    Workspace,
}

/// Cargo's registry trust is the core [`RegistryTrust`]: the same URL-alone rule as Go, npm,
/// NuGet and Swift decides it, and it decides egress only. Whether a credential is sent is a
/// separate decision held by [`RegistryIndex`] (#1855).
pub use deps_core::net_policy::RegistryTrust;

/// The less-trusted of `a` and `b` — `WorkspaceDeclared` if either is, `Trusted` only if both
/// are.
///
/// Used by [`crate::registry::CargoRegistry::register_alternate`] (issue #455, C3) to fold a
/// re-registration of the same index URL to the stricter of its old and new trust tier.
pub(crate) const fn stricter(a: RegistryTrust, b: RegistryTrust) -> RegistryTrust {
    match (a, b) {
        (RegistryTrust::WorkspaceDeclared, _) | (_, RegistryTrust::WorkspaceDeclared) => {
            RegistryTrust::WorkspaceDeclared
        }
        (RegistryTrust::Trusted, RegistryTrust::Trusted) => RegistryTrust::Trusted,
    }
}

/// The `sparse+` protocol prefix Cargo allows on an index URL.
const SPARSE_PREFIX: &str = "sparse+";

/// An index URL text with its optional `sparse+` prefix removed.
///
/// Only [`strip_sparse_prefix`] makes one, and every consumer takes this type, so a value is
/// stripped exactly once and the operator set and the classifier always see the same text (a
/// second strip of `sparse+sparse+https://…` would classify a different URL than was declared).
#[derive(Debug, Clone, Copy)]
pub(crate) struct StrippedIndexUrl<'a>(&'a str);

impl<'a> StrippedIndexUrl<'a> {
    pub(crate) const fn as_str(self) -> &'a str {
        self.0
    }
}

/// `raw` without a leading `sparse+`.
pub(crate) fn strip_sparse_prefix(raw: &str) -> StrippedIndexUrl<'_> {
    StrippedIndexUrl(raw.strip_prefix(SPARSE_PREFIX).unwrap_or(raw))
}

/// [`RegistryUrlKind`] marker selecting Cargo's validation rules for an index URL.
pub enum CargoIndexKind {}

impl deps_core::net_policy::private::Sealed for CargoIndexKind {}

impl RegistryUrlKind for CargoIndexKind {
    const ECOSYSTEM: EcosystemId = EcosystemId::Cargo;
    const REJECT_QUERY_FRAGMENT: bool = false;
    type Error = RegistryIndexError;
}

impl TrustedConstantRegistryUrl for CargoIndexKind {}

/// Why a candidate index URL failed [`RegistryIndex::declared`]'s validation.
///
/// An alias of the shared [`deps_core::net_policy::IndexUrlError`] — see that type's docs
/// for the variants and their wording.
pub use deps_core::net_policy::IndexUrlError as RegistryIndexError;

/// A credential for a registry index the operator declared.
///
/// Its only constructor takes the classification of the index it is for and returns it only for
/// [`RegistryTrust::Trusted`], so a credential for a workspace-declared index cannot be built.
#[derive(Clone, PartialEq, Eq)]
struct OperatorCredential(AuthToken);

impl OperatorCredential {
    fn for_trusted(
        token: AuthToken,
        classified: &DeclaredRegistry<CargoIndexKind>,
    ) -> Option<Self> {
        match classified.trust() {
            RegistryTrust::Trusted => Some(Self(token)),
            RegistryTrust::WorkspaceDeclared => None,
        }
    }
}

impl std::fmt::Debug for OperatorCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperatorCredential(***)")
    }
}

/// How requests against a [`RegistryIndex`] authenticate.
///
/// `Credentialed` implies [`RegistryTrust::Trusted`]: its only constructor is
/// [`OperatorCredential::for_trusted`]. `Anonymous` carries the URL-alone classification.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IndexAccess {
    Credentialed(OperatorCredential),
    Anonymous(RegistryTrust),
}

/// A validated, `sparse+`-prefix-stripped sparse-index URL.
///
/// `https` scheme, no userinfo, and (for a [`RegistryTrust::WorkspaceDeclared`] candidate) a host
/// the live [`deps_core::net_policy::RegistryAccessPolicy`] allows. Validated at construction so
/// an invalid or unsafe URL (`http://`, a scheme other than `sparse+https`, a `user:pass@`
/// component, or a workspace-declared host the policy blocks) can never reach a network call —
/// this is SSRF-adjacent input, since a workspace file controls a network destination (spec
/// NFR-002, plan-1b §1.1-§1.2).
///
/// Carries its own credential, if it has one: egress trust and credential are two decisions,
/// and the credential exists only for a URL the operator declared (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryIndex {
    url: ValidatedRegistryUrl<CargoIndexKind>,
    base: TrustedPrefix,
    access: IndexAccess,
}

/// Everything the operator declared for Cargo: the registry URLs, and the credentials bound to
/// them by URL equality.
///
/// Built from `$CARGO_HOME/config.toml` and the `CARGO_REGISTRIES_*` variables of the whole
/// process environment, never from the manifest being parsed, so it is the same for every
/// manifest and every alias order. A credential is looked up by the classified URL of an index,
/// whichever alias or manifest field named it.
#[derive(Default)]
pub(crate) struct CargoOperator {
    registries: OperatorRegistries,
    credentials: HashMap<String, AuthToken>,
}

impl std::fmt::Debug for CargoOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CargoOperator")
            .field("registries", &self.registries)
            .field("credentials", &self.credentials.len())
            .finish()
    }
}

impl CargoOperator {
    /// An operator that declares `registries` and binds no credential.
    pub(crate) fn declaring(registries: OperatorRegistries) -> Self {
        Self {
            registries,
            credentials: HashMap::new(),
        }
    }

    /// Binds `token` to the URL `stripped` when the operator declares it and it passes the
    /// never-a-registry floor. The first binding of a URL wins, so callers bind in a fixed order.
    pub(crate) fn bind(&mut self, stripped: StrippedIndexUrl<'_>, token: AuthToken) {
        let text = stripped.as_str();
        let policy = RegistryAccessPolicy::default();
        if let Ok(classified) = self
            .registries
            .classify::<CargoIndexKind>(text, text, &policy)
        {
            self.credentials
                .entry(classified.as_str().to_string())
                .or_insert(token);
        }
    }
}

impl RegistryIndex {
    fn from_classified(
        classified: DeclaredRegistry<CargoIndexKind>,
        credential: Option<&AuthToken>,
    ) -> Result<Self, RegistryIndexError> {
        let base = TrustedPrefix::parse(classified.as_str())
            .map_err(|_| IndexUrlError::InvalidUrl(RedactedUrl::new(classified.as_str())))?;
        let access = match credential
            .and_then(|token| OperatorCredential::for_trusted(token.clone(), &classified))
        {
            Some(credential) => IndexAccess::Credentialed(credential),
            None => IndexAccess::Anonymous(classified.trust()),
        };
        Ok(Self {
            url: classified.url().clone(),
            base,
            access,
        })
    }

    /// Validates and classifies `raw` — a `registry-index` manifest value, a
    /// `.cargo/config.toml` `[registries.<name>].index` value, or a `[source.<name>]
    /// registry` value, either optionally prefixed with `sparse+` — with no credential.
    ///
    /// A URL equal to one in `operator` is [`RegistryTrust::Trusted`] and skips the workspace
    /// policy; any other URL is checked against `policy`. The never-a-registry floor applies to
    /// both.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryIndexError`] if `raw` does not parse as a URL, is not `https`,
    /// carries a userinfo component, resolves to a host class that is never a registry, or (for
    /// a workspace-declared URL) to a host class the current policy blocks.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cargo::config::{RegistryIndex, RegistryTrust};
    /// use deps_core::net_policy::{OperatorRegistries, RegistryAccessPolicy};
    ///
    /// let policy = RegistryAccessPolicy::default();
    /// let none = OperatorRegistries::default();
    /// let index = RegistryIndex::declared("sparse+https://index.mycorp.dev", &none, &policy)
    ///     .unwrap();
    /// assert_eq!(index.trust(), RegistryTrust::WorkspaceDeclared);
    /// assert!(RegistryIndex::declared("http://index.mycorp.dev", &none, &policy).is_err());
    /// assert!(
    ///     RegistryIndex::declared("https://user:pass@index.mycorp.dev", &none, &policy).is_err()
    /// );
    /// ```
    pub fn declared(
        raw: &str,
        operator: &OperatorRegistries,
        policy: &RegistryAccessPolicy,
    ) -> Result<Self, RegistryIndexError> {
        let stripped = strip_sparse_prefix(raw).as_str();
        Self::from_classified(
            operator.classify::<CargoIndexKind>(stripped, stripped, policy)?,
            None,
        )
    }

    /// [`Self::declared`] against the full [`CargoOperator`], for a value whose `sparse+` prefix
    /// is already stripped: an index the operator declared also gets the credential the operator
    /// bound to its URL, whichever alias or manifest field named it.
    pub(crate) fn declared_bound(
        stripped: StrippedIndexUrl<'_>,
        operator: &CargoOperator,
        policy: &RegistryAccessPolicy,
    ) -> Result<Self, RegistryIndexError> {
        let text = stripped.as_str();
        let classified = operator
            .registries
            .classify::<CargoIndexKind>(text, text, policy)?;
        let credential = operator.credentials.get(classified.as_str());
        Self::from_classified(classified, credential)
    }

    /// Wraps a compile-time-known-safe literal (e.g. crates.io's own sparse index base), which
    /// is [`RegistryTrust::Trusted`] without an operator file vouching for it.
    ///
    /// `pub(crate)` — for a literal known at compile time, not a workspace-provenance value.
    ///
    /// # Panics
    ///
    /// Panics if `raw` fails validation. Covered by a unit test so this panic is unreachable in
    /// practice.
    #[must_use]
    pub(crate) fn builtin(raw: &'static str) -> Self {
        DeclaredRegistry::<CargoIndexKind>::trusted_constant(raw)
            .and_then(|classified| Self::from_classified(classified, None))
            .unwrap_or_else(|error| {
                panic!("builtin registry index {raw:?} failed validation: {error}")
            })
    }

    /// The normalized URL, never carrying a trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// This index as a [`TrustedPrefix`] (no re-parse).
    #[must_use]
    pub(crate) fn trusted_prefix(&self) -> TrustedPrefix {
        self.base.clone()
    }

    /// The [`RegistryTrust`] the URL-alone rule gave this index.
    #[must_use]
    pub const fn trust(&self) -> RegistryTrust {
        match self.access {
            IndexAccess::Credentialed(_) => RegistryTrust::Trusted,
            IndexAccess::Anonymous(trust) => trust,
        }
    }

    /// Whether requests against this index carry a credential. The credential itself is never
    /// exposed outside the crate.
    #[must_use]
    pub const fn has_credential(&self) -> bool {
        matches!(self.access, IndexAccess::Credentialed(_))
    }

    /// The credential, when the index has one.
    pub(crate) const fn credential(&self) -> Option<&AuthToken> {
        match &self.access {
            IndexAccess::Credentialed(credential) => Some(&credential.0),
            IndexAccess::Anonymous(_) => None,
        }
    }

    /// Test-only: an anonymous index of the given trust, built through the same classification
    /// path as production (an operator set holding `raw` for [`RegistryTrust::Trusted`]).
    ///
    /// # Panics
    ///
    /// Panics if `raw` fails validation.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test(raw: &str, trust: RegistryTrust) -> Self {
        let operator = Self::test_operator(raw, trust, None);
        Self::declared_bound(strip_sparse_prefix(raw), &operator, &Self::test_policy())
            .unwrap_or_else(|error| panic!("test index {raw:?} failed validation: {error}"))
    }

    /// Test-only: [`Self::for_test`] for a Trusted index that carries `token`.
    ///
    /// # Panics
    ///
    /// Panics if `raw` fails validation.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn credentialed_for_test(raw: &str, token: &str) -> Self {
        let operator = Self::test_operator(raw, RegistryTrust::Trusted, Some(token));
        Self::declared_bound(strip_sparse_prefix(raw), &operator, &Self::test_policy())
            .unwrap_or_else(|error| panic!("test index {raw:?} failed validation: {error}"))
    }

    #[cfg(any(test, feature = "test-util"))]
    fn test_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(deps_core::net_policy::WorkspaceRegistryAccess::All)
    }

    #[cfg(any(test, feature = "test-util"))]
    fn test_operator(raw: &str, trust: RegistryTrust, token: Option<&str>) -> CargoOperator {
        let stripped = strip_sparse_prefix(raw);
        let mut operator = match trust {
            RegistryTrust::Trusted => CargoOperator::declaring(OperatorRegistries::declared_in(
                &OperatorPath::for_test("/test/.cargo/config.toml"),
                [stripped.as_str()],
            )),
            RegistryTrust::WorkspaceDeclared => CargoOperator::default(),
        };
        if let Some(token) = token {
            operator.bind(stripped, AuthToken::new(token.to_string()));
        }
        operator
    }
}

impl std::fmt::Display for RegistryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One resolved `[registries.<name>]` entry.
///
/// Output-only: constructed internally by this module's own resolution logic, never by
/// external code — no constructor is provided.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ResolvedRegistryEntry {
    /// The validated, fetchable index. Carries its own credential, if it has one.
    pub index: RegistryIndex,
    /// Where this entry was resolved from. Diagnostics/logging only.
    pub provenance: Provenance,
}

/// The merged, resolved view of a workspace's `.cargo/config.toml` hierarchy plus
/// `$CARGO_HOME/config.toml`, for the aliases a manifest actually referenced.
///
/// Built by [`resolve`] — this type itself is a plain lookup table with no resolution
/// logic of its own, so a caller holding one can check [`Self::get`] without needing to
/// know anything about tiers, precedence, or the environment.
#[derive(Debug, Default)]
pub struct CargoConfig {
    registries: HashMap<String, ResolvedRegistryEntry>,
    /// Aliases whose resolution failed, paired with why (issue #1468 item 4). Previously two
    /// disjoint `HashMap<String, _>`s (`blocked`/`rejected`) — resolution only ever inserts
    /// one or the other for a given alias, never both, but that "at most one" invariant was
    /// only a convention encoded in call order (`blocked_class` checked before
    /// `rejected_reason` at every caller); [`UnresolvedIndex`] makes it a structural
    /// impossibility instead, since a single map slot can only ever hold one variant.
    unresolved: HashMap<String, UnresolvedIndex>,
}

/// Why a `.cargo/config.toml`/`$CARGO_HOME` alias failed to resolve to a usable registry
/// index — see [`CargoConfig::blocked_class`]/[`CargoConfig::rejected_reason`].
#[derive(Debug, Clone, Copy)]
enum UnresolvedIndex {
    /// The current [`deps_core::net_policy::RegistryAccessPolicy`] blocked the candidate
    /// host (spec #443, plan-1b §1.7) — as opposed to "no matching config entry" or any
    /// other validation failure. Surfaced by `crate::parser::resolve_alternate_registries`
    /// as a positional diagnostic on the offending dependency's line.
    Blocked(BlockedHost),
    /// The `.cargo/config.toml` `[registries.<name>] index = ...` entry failed validation
    /// for a reason other than a policy-blocked host (#1453, mirrors [`Self::Blocked`]) —
    /// an invalid URL, a non-https scheme, or embedded userinfo. Surfaced the same way
    /// [`Self::Blocked`] is.
    Rejected(RegistryRejectionReason),
}

impl UnresolvedIndex {
    /// The cause a failed validation is surfaced as, if it is surfaced at all.
    fn from_error(error: &RegistryIndexError) -> Option<Self> {
        match error {
            RegistryIndexError::BlockedHost { block } => Some(Self::Blocked(*block)),
            other => other.rejection_reason().into_reason().map(Self::Rejected),
        }
    }
}

impl CargoConfig {
    /// The resolved entry for `alias`, if it resolved successfully.
    #[must_use]
    pub fn get(&self, alias: &str) -> Option<&ResolvedRegistryEntry> {
        self.registries.get(alias)
    }

    /// The host class that blocked `alias`'s resolution, if that (and specifically that) is
    /// why it did not resolve.
    #[must_use]
    pub(crate) fn blocked_class(&self, alias: &str) -> Option<BlockedHost> {
        match self.unresolved.get(alias) {
            Some(UnresolvedIndex::Blocked(host)) => Some(*host),
            Some(UnresolvedIndex::Rejected(_)) | None => None,
        }
    }

    /// [`Self::blocked_class`]'s counterpart for every rejection reason other than a
    /// policy-blocked host (#1453) — why `alias`'s `[registries.<name>] index = ...` entry
    /// failed validation, if that (and specifically that) is why it did not resolve.
    #[must_use]
    pub(crate) fn rejected_reason(&self, alias: &str) -> Option<RegistryRejectionReason> {
        match self.unresolved.get(alias) {
            Some(UnresolvedIndex::Rejected(reason)) => Some(*reason),
            Some(UnresolvedIndex::Blocked(_)) | None => None,
        }
    }
}

/// Where a `[source.crates-io] replace-with` chain resolved to, for plain (`Registry`-sourced)
/// dependencies (spec FR-005/FR-006/FR-007).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum SourceReplacement {
    /// No `[source]` override applies — no `[source.crates-io]` table, a `directory`/
    /// `local-registry`/non-sparse-git terminal (FR-006), a cyclic/unbounded chain
    /// (FR-007), or a terminal that failed [`RegistryIndex::declared`]'s validation/policy gate.
    /// Plain dependencies keep resolving against crates.io, unchanged from today.
    None,
    /// The chain terminated at a `sparse+https://` index (FR-005).
    SparseMirror {
        /// The validated, fetchable mirror index. It carries a credential only when every link
        /// of the chain is an operator link (plan-1b §1.4's "coupled trust trap" guard): a
        /// single workspace-tier link anywhere in the chain leaves it anonymous, even if the
        /// terminal itself is a `$CARGO_HOME` `[registries]` entry carrying a token.
        index: RegistryIndex,
    },
}

/// A raw (unvalidated) `[source.<name>]` table entry, as parsed from one config file —
/// unvalidated because validation ([`RegistryIndex::declared`]'s policy gate, in particular)
/// must run per parse against the live policy, never cached (plan-1b §1.5(b)).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceEntry {
    /// The table's own kind, if it declares one recognizable by [`classify_source_kind`].
    /// `None` for a table with neither a `registry`/`directory`/`local-registry`/`git`
    /// field nor (therefore) any classification — e.g. a bare `[source.crates-io]
    /// replace-with = "..."` table, which has no kind of its own.
    kind: Option<SourceKind>,
    /// This table's own `replace-with` value, if any.
    replace_with: Option<String>,
}

/// The kind of source a `[source.<name>]` table declares — classified purely by the
/// `sparse+` prefix on a `registry` value (spec FR-005/FR-006), never carrying an
/// [`RegistryTrust`] of its own: trust is derived from the [`CachedTier`] the containing file
/// belongs to at merge time, not tagged per entry (plan-1b §1.4/§1.5(c) — the same
/// "per-entry tag a later reader must get right" hazard §1.5(c) already eliminated for
/// `[registries]` entries).
#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceKind {
    /// `registry = "sparse+https://…"` — a terminal FR-005 candidate.
    SparseRegistry {
        /// The raw (unvalidated, `sparse+`-prefixed) index value.
        raw: String,
    },
    /// `registry = "<bare https git index>"`, `directory = "…"`, `git = "…"`, or
    /// `local-registry = "…"` — a terminal that keeps resolving plain dependencies against
    /// crates.io, unchanged (FR-006/US-003).
    NonSparse,
}

/// Classifies a `[source.<name>]` table's own kind, per [`SourceKind`]'s doc.
fn classify_source_kind(entry: &Table<'_>) -> Option<SourceKind> {
    if let Some(registry) = entry.get("registry").and_then(|v| v.as_str()) {
        return Some(if registry.starts_with("sparse+") {
            SourceKind::SparseRegistry {
                raw: registry.to_string(),
            }
        } else {
            SourceKind::NonSparse
        });
    }
    let has_non_sparse_field = ["directory", "local-registry", "git"]
        .iter()
        .any(|field| entry.get(*field).and_then(|v| v.as_str()).is_some());
    if has_non_sparse_field {
        return Some(SourceKind::NonSparse);
    }
    None
}

/// Upper bound on the number of `[source.<name>]` tables read from a single config file
/// (M6): the nesting-depth guard already bounds table *depth*, not table *count*, so this
/// exists to bound that separately-unbounded dimension. `visited`-set cycle detection
/// already bounds chain-following iteration on top of this.
const MAX_SOURCE_ENTRIES: usize = 256;

/// Parses one config file's `[source.<name>]` tables into raw (unvalidated) entries.
///
/// Shared by both tiers — a `[source]` table carries no token concept of its own (unlike
/// `[registries]`), so there is nothing tier-specific about this extraction; the tier only
/// matters when this file's [`SourceEntry`]s are later merged into a chain-resolution walk
/// (see [`resolve_source_chain`]).
fn parse_source_entries_raw(content: &str) -> HashMap<String, SourceEntry> {
    let mut out = HashMap::new();
    let doc = match deps_core::parse_toml_checked(content) {
        Ok(doc) => doc,
        Err(deps_core::CheckedTomlError::NestingTooDeep { .. }) => {
            tracing::warn!("skipping [source] tables: nesting depth exceeds maximum");
            return out;
        }
        Err(deps_core::CheckedTomlError::Syntax(_)) => return out,
    };
    let Some(sources) = doc
        .as_table()
        .and_then(|t| t.get("source"))
        .and_then(|v| v.as_table())
    else {
        return out;
    };
    for (key, value) in sources {
        if out.len() >= MAX_SOURCE_ENTRIES {
            tracing::warn!(
                cap = MAX_SOURCE_ENTRIES,
                "[source] table count exceeds maximum; ignoring remaining entries"
            );
            break;
        }
        let Some(entry_table) = value.as_table() else {
            continue;
        };
        let kind = classify_source_kind(entry_table);
        let replace_with = entry_table
            .get("replace-with")
            .and_then(|v| v.as_str())
            .map(String::from);
        out.insert(key.name.to_string(), SourceEntry { kind, replace_with });
    }
    out
}

/// Parses a table value's `index` field into a raw (unvalidated) string, warning and
/// returning `None` only when the field is missing or not a string — actual URL validation
/// happens per parse in [`RegistryIndex::declared`], never here (plan-1b §1.5(b)): caching a
/// validated `RegistryIndex` would go stale across a `didChangeConfiguration` policy change.
fn parse_raw_index_field(entry: &Table<'_>) -> Option<String> {
    entry
        .get("index")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Parses a workspace-declared `.cargo/config.toml`'s `[registries.<name>]` table into
/// alias -> raw index string entries.
///
/// **No `token` field exists anywhere in this function's return type.** This is the
/// structural half of the auth-provenance guarantee described in the module docs — a
/// workspace-tier [`CachedTier::Workspace`] cannot represent a token at all, so no later
/// reader can populate one for a workspace-sourced entry even by mistake (plan-1b §1.5(c)).
fn parse_workspace_registries_raw(content: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let doc = match deps_core::parse_toml_checked(content) {
        Ok(doc) => doc,
        Err(deps_core::CheckedTomlError::NestingTooDeep { .. }) => {
            tracing::warn!("skipping .cargo/config.toml: nesting depth exceeds maximum");
            return out;
        }
        Err(deps_core::CheckedTomlError::Syntax(_)) => return out,
    };
    let Some(registries) = doc
        .as_table()
        .and_then(|t| t.get("registries"))
        .and_then(|v| v.as_table())
    else {
        return out;
    };
    for (key, value) in registries {
        let Some(entry) = value.as_table() else {
            continue;
        };
        if let Some(raw_index) = parse_raw_index_field(entry) {
            out.insert(key.name.to_string(), raw_index);
        }
    }
    out
}

/// Parses `$CARGO_HOME/config.toml`'s `[registries.<name>]` table into alias -> (raw index,
/// token) entries — the one function in this module permitted to construct a populated
/// [`AuthToken`], since its input is, by construction, always `$CARGO_HOME`-sourced.
fn parse_cargo_home_registries_raw(content: &str) -> HashMap<String, (String, Option<AuthToken>)> {
    let mut out = HashMap::new();
    let doc = match deps_core::parse_toml_checked(content) {
        Ok(doc) => doc,
        Err(deps_core::CheckedTomlError::NestingTooDeep { .. }) => {
            tracing::warn!("skipping $CARGO_HOME/config.toml: nesting depth exceeds maximum");
            return out;
        }
        Err(deps_core::CheckedTomlError::Syntax(_)) => return out,
    };
    let Some(registries) = doc
        .as_table()
        .and_then(|t| t.get("registries"))
        .and_then(|v| v.as_table())
    else {
        return out;
    };
    for (key, value) in registries {
        let Some(entry) = value.as_table() else {
            continue;
        };
        let Some(raw_index) = parse_raw_index_field(entry) else {
            continue;
        };
        let token = entry
            .get("token")
            .and_then(|v| v.as_str())
            .map(|t| AuthToken::new(t.to_string()));
        out.insert(key.name.to_string(), (raw_index, token));
    }
    out
}

/// Cargo's env-var naming convention for a registry setting: uppercase the alias and
/// replace every `-` with `_` (Cargo does the same substitution, which is exactly why two
/// spellings of "the same" alias can collide — see spec FR-015).
fn env_var_name(alias: &str, suffix: &str) -> String {
    let screaming = alias.to_uppercase().replace('-', "_");
    format!("CARGO_REGISTRIES_{screaming}_{suffix}")
}

/// One tier's raw registries table, plus the raw `[source]` tables from the same file —
/// cached per config-file path by [`deps_core::MtimeFileCache`], keyed on mtime for
/// invalidation (plan-1b §1.5(a)).
///
/// **Absence is never cached** (N5): only a file that existed, was a regular file, and
/// parsed successfully gets an entry — a `.cargo/config.toml` created after the cache was
/// first populated is picked up on the very next parse with no extra bookkeeping, since the
/// ancestor walk re-checks existence every parse regardless.
#[derive(Debug)]
struct ParsedConfigFile {
    tier: CachedTier,
    sources: HashMap<String, SourceEntry>,
}

/// Which tier a [`ParsedConfigFile`] belongs to, chosen once — by the same
/// canonicalized-path comparison against `$CARGO_HOME/config.toml` that already decides
/// precedence in [`resolve`] — rather than becoming a per-entry tag later code must read
/// correctly (plan-1b §1.5(c)).
///
/// The `Workspace` variant's map is `HashMap<String, String>`, with **no token field
/// anywhere in its type** — [`parse_workspace_registries_raw`] keeps the guarantee its doc
/// comment already claims: a function whose body has no code path that could populate one.
#[derive(Debug)]
enum CachedTier {
    /// A `.cargo/config.toml` found by the ancestor walk. Alias -> raw index string.
    Workspace(HashMap<String, String>),
    /// `$CARGO_HOME/config.toml`. Alias -> (raw index string, token).
    CargoHome(HashMap<String, (String, Option<AuthToken>)>),
}

/// Per-config-file memoization for `.cargo/config.toml`/`$CARGO_HOME/config.toml` parsing
/// (spec NFR-005, plan-1b §1.5).
///
/// Caches **raw**, unvalidated tables — alias filtering, env overrides,
/// [`RegistryIndex::declared`] validation, and `[source]` chain walking all run **per parse**
/// against these cached tables, never cached themselves. This is what keeps a policy change
/// (`didChangeConfiguration`), a newly-referenced alias, or an env-var change taking effect
/// immediately without any cache invalidation of their own.
///
/// Owned by `crate::parser::CargoParseContext` and shared across every document this
/// ecosystem parses, so hundreds of workspace members sharing one `.cargo/config.toml`
/// collapse to a single cached entry. A thin newtype over [`deps_core::MtimeFileCache`] —
/// the mtime-gated caching mechanism itself lives there, shared with `deps-npm`.
#[derive(Debug)]
pub struct ConfigFileCache(MtimeFileCache<ParsedConfigFile>);

impl Default for ConfigFileCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigFileCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self(MtimeFileCache::new(
            DEFAULT_MAX_CACHED_FILES,
            "cargo config",
        ))
    }

    /// Returns `path`'s parsed workspace-tier contents, from cache if `path`'s mtime is
    /// unchanged, else re-reading and re-parsing.
    fn get_or_parse_workspace(&self, path: &Path) -> Option<Arc<ParsedConfigFile>> {
        self.0.get_or_parse(path, |content| ParsedConfigFile {
            tier: CachedTier::Workspace(parse_workspace_registries_raw(content)),
            sources: parse_source_entries_raw(content),
        })
    }

    /// [`Self::get_or_parse_workspace`], but for `$CARGO_HOME/config.toml`.
    fn get_or_parse_cargo_home(&self, path: &Path) -> Option<Arc<ParsedConfigFile>> {
        self.0.get_or_parse(path, |content| ParsedConfigFile {
            tier: CachedTier::CargoHome(parse_cargo_home_registries_raw(content)),
            sources: parse_source_entries_raw(content),
        })
    }
}

/// `$CARGO_HOME/config.toml`'s path, or `None` if `$CARGO_HOME` is unset or relative.
///
/// Deliberately reads only the `CARGO_HOME` environment variable — no fallback to
/// `$HOME`/`%USERPROFILE%` when it is unset (spec FR-004), and no `dirs`/`home` crate
/// dependency added to compute one. A relative `CARGO_HOME` would resolve against a directory a
/// repository can influence, so it names no operator-owned location and is ignored.
#[must_use]
pub fn cargo_home_config_path() -> Option<OperatorPath> {
    cargo_home_config_path_with_env(&ProcessEnv)
}

/// [`cargo_home_config_path`], but reading the environment through `env` instead of the process
/// environment — lets tests inject a fake environment instead of mutating the real
/// (`unsafe`-only, since Rust 2024) process environment.
pub(crate) fn cargo_home_config_path_with_env(
    env: &(impl EnvSource + ?Sized),
) -> Option<OperatorPath> {
    match OperatorPath::from_env(env, OperatorEnvVar::CargoHome) {
        EnvPath::Path(home) => Some(home.join("config.toml")),
        EnvPath::Unset => None,
        EnvPath::Ignored => {
            tracing::warn!("ignoring a relative CARGO_HOME: it names no operator-owned location");
            None
        }
    }
}

/// The loaded, per-file tiers a [`resolve`] call operates against — workspace tiers
/// closest-first, plus the (at most one) `$CARGO_HOME` tier, both already excluding the
/// canonicalized-path duplicate case (see [`resolve_with_env`]'s doc).
struct LoadedTiers {
    workspace: Vec<Arc<ParsedConfigFile>>,
    cargo_home: Option<Arc<ParsedConfigFile>>,
}

fn load_tiers(
    workspace_config_paths: &[PathBuf],
    cargo_home_config_path: Option<&OperatorPath>,
    config_cache: &ConfigFileCache,
) -> LoadedTiers {
    let cargo_home_path = cargo_home_config_path.map(OperatorPath::as_path);
    // Under the default layout, `~/.cargo/config.toml` is also found by the workspace-tier
    // walk — uncompared, it'd double-count as workspace-tier, winning over the real
    // `$CARGO_HOME` tier and silently dropping its token. Canonicalizing also catches a
    // symlinked `$CARGO_HOME`.
    let cargo_home_canonical = cargo_home_path.and_then(|p| std::fs::canonicalize(p).ok());

    let workspace = workspace_config_paths
        .iter()
        .filter(|path| {
            std::fs::canonicalize(path).ok().as_deref() != cargo_home_canonical.as_deref()
        })
        .filter_map(|path| config_cache.get_or_parse_workspace(path))
        .collect();

    let cargo_home = cargo_home_path.and_then(|path| config_cache.get_or_parse_cargo_home(path));

    LoadedTiers {
        workspace,
        cargo_home,
    }
}

/// Resolves `referenced_aliases` against the `.cargo/config.toml` hierarchy and
/// `$CARGO_HOME/config.toml`.
///
/// Separately resolves the `[source.crates-io] replace-with` chain (if any) for plain
/// dependencies.
///
/// `referenced_aliases` is every distinct `registry = "<alias>"` value this manifest's
/// dependencies declared; `workspace_config_paths` and `cargo_home_config_path` come from
/// `crate::parser`'s merged ancestor walk (closest-first); `config_cache` memoizes each
/// distinct config file's raw contents (spec NFR-005); `policy` gates every
/// [`RegistryTrust::WorkspaceDeclared`] [`RegistryIndex`] this call constructs.
///
/// # Trust
///
/// The operator set is every index URL `$CARGO_HOME/config.toml` declares (`[registries]` and
/// `[source]` sparse terminals) plus the value of every `CARGO_REGISTRIES_<ALIAS>_INDEX`
/// variable of the process environment, independent of which aliases this manifest references.
/// Every index, whichever file or field named it, is classified against that set by
/// [`OperatorRegistries::classify`]. A credential is bound to a URL the operator declared and
/// follows that URL, so the result never depends on alias or registration order.
///
/// # Precedence
///
/// For one alias (or the `[source]` chain): the closest workspace `.cargo/config.toml`
/// entry wins outright — if it resolves, the `$CARGO_HOME` tier (config file and
/// environment variables alike) is never consulted for that alias at all. This is a
/// deliberate divergence from Cargo's own env-beats-all-config-files precedence: an
/// environment variable can never redirect an alias a workspace file has shadowed (spec
/// FR-009/US-004) — see the module-level security-model docs.
///
/// # Examples
///
/// ```
/// use deps_cargo::config::{ConfigFileCache, SourceReplacement, resolve};
/// use deps_core::net_policy::RegistryAccessPolicy;
/// use std::collections::HashSet;
///
/// let aliases: HashSet<String> = std::iter::once("unconfigured".to_string()).collect();
/// let cache = ConfigFileCache::new();
/// let policy = RegistryAccessPolicy::default();
/// let (config, source_replacement) = resolve(&aliases, &[], None, &cache, &policy);
/// assert!(config.get("unconfigured").is_none());
/// assert_eq!(source_replacement, SourceReplacement::None);
/// ```
#[must_use]
pub fn resolve(
    referenced_aliases: &HashSet<String>,
    workspace_config_paths: &[PathBuf],
    cargo_home_config_path: Option<&OperatorPath>,
    config_cache: &ConfigFileCache,
    policy: &RegistryAccessPolicy,
) -> (CargoConfig, SourceReplacement) {
    resolve_with_env(
        referenced_aliases,
        workspace_config_paths,
        cargo_home_config_path,
        config_cache,
        policy,
        &ProcessEnv,
    )
}

/// [`resolve`], but reading environment variables through `env` instead of the process
/// environment — lets tests inject a fake environment instead of mutating the real process
/// environment (this workspace forbids `unsafe`, and Rust 2024 made
/// `std::env::set_var`/`remove_var` `unsafe fn`s, so a test cannot do that mutation at
/// all). Production callers always go through [`resolve`].
pub(crate) fn resolve_with_env(
    referenced_aliases: &HashSet<String>,
    workspace_config_paths: &[PathBuf],
    cargo_home_config_path: Option<&OperatorPath>,
    config_cache: &ConfigFileCache,
    policy: &RegistryAccessPolicy,
    env: &(impl EnvSource + ?Sized),
) -> (CargoConfig, SourceReplacement) {
    let tiers = load_tiers(workspace_config_paths, cargo_home_config_path, config_cache);
    let operator = cargo_operator_with_env(cargo_home_config_path, config_cache, env);

    let env_collided = env_collided_aliases(referenced_aliases);
    let env_indexes = read_env_indexes(referenced_aliases, &env_collided, env);

    let registries =
        resolve_registries(referenced_aliases, &tiers, &operator, &env_indexes, policy);
    let source_replacement = resolve_source_chain(&tiers, &operator, policy);

    (registries, source_replacement)
}

const ENV_REGISTRY_PREFIX: &str = "CARGO_REGISTRIES_";
const ENV_INDEX_SUFFIX: &str = "_INDEX";
const ENV_TOKEN_SUFFIX: &str = "_TOKEN";

/// Text of an index value for the operator set: the same `sparse+` removal the classifier uses.
fn stripped_text(raw: &str) -> &str {
    strip_sparse_prefix(raw).as_str()
}

/// Builds the [`CargoOperator`]: every URL declared by `$CARGO_HOME/config.toml` and by a
/// `CARGO_REGISTRIES_*_INDEX` variable, and the credentials bound to them. Independent of any
/// manifest, so every manifest of a process classifies a URL the same way.
///
/// A token is bound to the URL its alias (or variable) declares, with the environment token
/// beating the file token; where two aliases give one URL different tokens, the alias that sorts
/// first wins, so the result is deterministic.
pub(crate) fn cargo_operator_with_env(
    cargo_home_config_path: Option<&OperatorPath>,
    config_cache: &ConfigFileCache,
    env: &(impl EnvSource + ?Sized),
) -> CargoOperator {
    let file = cargo_home_config_path.and_then(|path| {
        config_cache
            .get_or_parse_cargo_home(path.as_path())
            .map(|file| (path, file))
    });

    let mut env_index_vars = env.var_names_with_prefix(ENV_REGISTRY_PREFIX);
    env_index_vars.retain(|name| name.ends_with(ENV_INDEX_SUFFIX));
    env_index_vars.sort();

    let mut registries = match &file {
        Some((path, file)) => {
            OperatorRegistries::declared_in(path, cargo_home_index_values(file).map(stripped_text))
        }
        None => OperatorRegistries::default(),
    };
    registries.extend(OperatorRegistries::declared_in_env(
        env,
        &env_index_vars,
        stripped_text,
    ));
    let mut operator = CargoOperator::declaring(registries);

    let mut covered_env_vars = HashSet::new();
    if let Some((_, file)) = &file
        && let CachedTier::CargoHome(map) = &file.tier
    {
        let mut aliases: Vec<&String> = map.keys().collect();
        aliases.sort();
        for alias in aliases {
            let Some((raw_index, file_token)) = map.get(alias) else {
                continue;
            };
            let index_var = env_var_name(alias, "INDEX");
            let token = env_string(env, &env_var_name(alias, "TOKEN"))
                .map(AuthToken::new)
                .or_else(|| file_token.clone());
            if let Some(token) = token {
                if let Some(env_index) = env_string(env, &index_var) {
                    operator.bind(strip_sparse_prefix(&env_index), token.clone());
                }
                operator.bind(strip_sparse_prefix(raw_index), token);
            }
            covered_env_vars.insert(index_var);
        }
    }
    for index_var in &env_index_vars {
        if covered_env_vars.contains(index_var) {
            continue;
        }
        let token_var = format!(
            "{}{ENV_TOKEN_SUFFIX}",
            index_var.trim_end_matches(ENV_INDEX_SUFFIX)
        );
        if let (Some(raw_index), Some(token)) =
            (env_string(env, index_var), env_string(env, &token_var))
        {
            operator.bind(strip_sparse_prefix(&raw_index), AuthToken::new(token));
        }
    }
    operator
}

/// Aliases whose derived `CARGO_REGISTRIES_*` variable name collides with another referenced
/// alias's (FR-015): two spellings deriving the same env-var name (e.g. "my-corp"/"my_corp")
/// must not let either pick up an override meant for the other. Detected once over the whole
/// set — a per-alias check would have nothing to compare against.
fn env_collided_aliases(referenced_aliases: &HashSet<String>) -> HashSet<&str> {
    let mut env_name_to_aliases: HashMap<String, Vec<&String>> = HashMap::new();
    for alias in referenced_aliases {
        env_name_to_aliases
            .entry(env_var_name(alias, "INDEX"))
            .or_default()
            .push(alias);
    }
    env_name_to_aliases
        .values()
        .filter(|aliases| aliases.len() > 1)
        .flat_map(|aliases| {
            let names: Vec<&str> = aliases.iter().map(|s| s.as_str()).collect();
            // Same as `resolve_alternate_registries`' unresolved-alias WARN (#536): `alias` may
            // itself carry `user:pass@` userinfo or a query-string credential, so redact with
            // `RedactedUrl` (not `redact_userinfo` alone, which keeps the query — #767).
            let redacted: Vec<RedactedUrl> =
                names.iter().map(|name| RedactedUrl::new(name)).collect();
            tracing::warn!(
                aliases = ?redacted,
                "two aliases derive the same CARGO_REGISTRIES_*_INDEX/_TOKEN environment \
                 variable name; ignoring the environment override for all of them"
            );
            names
        })
        .collect()
}

/// The raw `CARGO_REGISTRIES_<ALIAS>_INDEX` value of every referenced alias that did not
/// collide, keyed by alias.
fn read_env_indexes(
    referenced_aliases: &HashSet<String>,
    env_collided: &HashSet<&str>,
    env: &(impl EnvSource + ?Sized),
) -> HashMap<String, String> {
    referenced_aliases
        .iter()
        .filter(|alias| !env_collided.contains(alias.as_str()))
        .filter_map(|alias| {
            env_string(env, &env_var_name(alias, "INDEX")).map(|value| (alias.clone(), value))
        })
        .collect()
}

/// The environment variable `name` as text, when set and valid Unicode.
fn env_string(env: &(impl EnvSource + ?Sized), name: &str) -> Option<String> {
    env.var_os(name).and_then(|value| value.into_string().ok())
}

/// Every index URL a `$CARGO_HOME` config file declares: its `[registries]` entries and its
/// `[source]` tables that end at a `sparse+` registry.
fn cargo_home_index_values(file: &ParsedConfigFile) -> impl Iterator<Item = &str> {
    let registries = match &file.tier {
        CachedTier::CargoHome(map) => Some(map.values().map(|(raw, _token)| raw.as_str())),
        CachedTier::Workspace(_) => None,
    };
    let sources = file.sources.values().filter_map(|entry| match &entry.kind {
        Some(SourceKind::SparseRegistry { raw }) => Some(raw.as_str()),
        Some(SourceKind::NonSparse) | None => None,
    });
    registries.into_iter().flatten().chain(sources)
}

fn resolve_registries(
    referenced_aliases: &HashSet<String>,
    tiers: &LoadedTiers,
    operator: &CargoOperator,
    env_indexes: &HashMap<String, String>,
    policy: &RegistryAccessPolicy,
) -> CargoConfig {
    let mut registries = HashMap::new();
    let mut unresolved = HashMap::new();
    for alias in referenced_aliases {
        if let Some(raw_index) = tiers.workspace.iter().find_map(|file| match &file.tier {
            CachedTier::Workspace(map) => map.get(alias),
            CachedTier::CargoHome(_) => None,
        }) {
            match RegistryIndex::declared_bound(strip_sparse_prefix(raw_index), operator, policy) {
                Ok(index) => {
                    registries.insert(
                        alias.clone(),
                        ResolvedRegistryEntry {
                            index,
                            provenance: Provenance::Workspace,
                        },
                    );
                }
                Err(error) => {
                    if let Some(cause) = UnresolvedIndex::from_error(&error) {
                        unresolved.insert(alias.clone(), cause);
                    }
                    tracing::warn!(alias, %error, "registry index failed validation");
                }
            }
            continue;
        }

        match resolve_cargo_home_tier(
            alias,
            tiers.cargo_home.as_deref(),
            env_indexes.get(alias).map(String::as_str),
            operator,
            policy,
        ) {
            CargoHomeResolution::Resolved(entry) => {
                registries.insert(alias.clone(), entry);
            }
            CargoHomeResolution::Unresolved(cause) => {
                unresolved.insert(alias.clone(), cause);
            }
            CargoHomeResolution::Absent => {}
        }
    }

    CargoConfig {
        registries,
        unresolved,
    }
}

/// Outcome of [`resolve_cargo_home_tier`].
enum CargoHomeResolution {
    /// Resolved to a usable index (possibly with a credential).
    Resolved(ResolvedRegistryEntry),
    /// A `CARGO_REGISTRIES_*_INDEX` override or `$CARGO_HOME/config.toml` entry existed but
    /// failed validation (#1453 S1). The operator's own URLs skip the workspace policy, so a
    /// [`UnresolvedIndex::Blocked`] here can only be the never-a-registry floor; the other
    /// rejections (`InvalidUrl`/`NotHttps`/`UserInfoPresent`) apply too. This tier used to drop
    /// such an entry silently with only a `tracing::warn!`, exactly the #1453 shape for a
    /// workspace-tier entry.
    Unresolved(UnresolvedIndex),
    /// No entry at all — the ordinary "alias not configured in this tier" outcome.
    Absent,
}

/// Resolves one alias against the `$CARGO_HOME` tier: the environment-variable index override
/// `env_index` first (when one was read for this alias), then `$CARGO_HOME/config.toml`'s own
/// entry.
fn resolve_cargo_home_tier(
    alias: &str,
    cargo_home_file: Option<&ParsedConfigFile>,
    env_index: Option<&str>,
    operator: &CargoOperator,
    policy: &RegistryAccessPolicy,
) -> CargoHomeResolution {
    let cargo_home_map = cargo_home_file.and_then(|file| match &file.tier {
        CachedTier::CargoHome(map) => Some(map),
        CachedTier::Workspace(_) => None,
    });

    // #1453 S1: an invalid env override still falls through to the file tier exactly as
    // before — only remembered here so its failure can be reported if the file tier also
    // yields nothing usable (a valid file-tier entry silently wins, matching the pre-#1453
    // "env override failed, fall back" behavior).
    let mut env_failure = None;
    if let Some(index_override) = env_index {
        match RegistryIndex::declared_bound(strip_sparse_prefix(index_override), operator, policy) {
            Ok(index) => {
                return CargoHomeResolution::Resolved(ResolvedRegistryEntry {
                    index,
                    provenance: Provenance::CargoHome,
                });
            }
            Err(error) => {
                tracing::warn!(alias, %error, "CARGO_REGISTRIES_*_INDEX environment override failed validation");
                env_failure = UnresolvedIndex::from_error(&error);
            }
        }
    }

    let Some((raw_index, _token)) = cargo_home_map.and_then(|map| map.get(alias)) else {
        return env_failure.map_or(CargoHomeResolution::Absent, CargoHomeResolution::Unresolved);
    };
    match RegistryIndex::declared_bound(strip_sparse_prefix(raw_index), operator, policy) {
        Ok(index) => CargoHomeResolution::Resolved(ResolvedRegistryEntry {
            index,
            provenance: Provenance::CargoHome,
        }),
        Err(error) => {
            tracing::warn!(alias, %error, "registry index failed validation");
            // #1453 code-review finding 3: when the env override *and* the file-tier entry
            // are both invalid, prefer the env override's own reason — it was the first
            // (and, per this function's own precedence, the intended) value for this alias;
            // reporting the file-tier's unrelated failure instead would misattribute why the
            // env override the user actually set didn't take effect.
            env_failure
                .or_else(|| UnresolvedIndex::from_error(&error))
                .map_or(CargoHomeResolution::Absent, CargoHomeResolution::Unresolved)
        }
    }
}

/// Upper bound on `[source]` replace-with chain hops, on top of the `visited`-set cycle
/// check — belt-and-braces (plan-1b §6 M6): the `visited` set alone already bounds a chain
/// to at most the number of distinct source ids ever declared, but a small explicit cap
/// keeps a pathological (though non-cyclic) chain from doing unbounded work in one parse.
const MAX_SOURCE_REPLACEMENT_HOPS: usize = 16;

/// Looks up `id` in the merged, raw `[registries]` tables (stage 1 of `[source]` id
/// resolution, spec FR-005's "two-stage: alias -> source id", critic S4) — closest
/// workspace tier first, then `$CARGO_HOME`. Returns only the raw index string; a credential is
/// bound later, by the classified URL.
fn lookup_raw_registry_index<'a>(id: &str, tiers: &'a LoadedTiers) -> Option<&'a str> {
    for file in &tiers.workspace {
        if let CachedTier::Workspace(map) = &file.tier
            && let Some(raw) = map.get(id)
        {
            return Some(raw.as_str());
        }
    }
    if let Some(file) = &tiers.cargo_home
        && let CachedTier::CargoHome(map) = &file.tier
        && let Some((raw, _token)) = map.get(id)
    {
        return Some(raw.as_str());
    }
    None
}

/// Resolves the `[source.crates-io] replace-with` chain (spec FR-005/006/007, plan-1b §1.4).
///
/// Two-stage id resolution at every hop: the merged `[source]` tables first, then (stage 1,
/// critic S4) the merged `[registries]` tables via [`lookup_raw_registry_index`] — a
/// `[registries]` hit is terminal by construction, since a `[registries]` entry has no
/// `replace-with` of its own.
fn resolve_source_chain(
    tiers: &LoadedTiers,
    operator: &CargoOperator,
    policy: &RegistryAccessPolicy,
) -> SourceReplacement {
    let mut current_id = "crates-io".to_string();
    let mut visited: HashSet<String> = HashSet::new();

    for _hop in 0..MAX_SOURCE_REPLACEMENT_HOPS {
        if !visited.insert(current_id.clone()) {
            tracing::warn!(
                id = ?current_id,
                "[source] replace-with chain is cyclic; leaving crates-io unresolved"
            );
            return SourceReplacement::None;
        }

        let found_source = tiers
            .workspace
            .iter()
            .find_map(|file| file.sources.get(&current_id))
            .or_else(|| {
                tiers
                    .cargo_home
                    .as_deref()
                    .and_then(|file| file.sources.get(&current_id))
            });

        if let Some(entry) = found_source {
            // Cargo resolves `replace-with` **before** consulting the table's own kind (critic
            // S2): an explicit `registry =`/`directory =`/etc. alongside `replace-with` does
            // not disable the replacement — the shape most public mirror setup docs publish
            // verbatim. Checking `kind` first (an earlier revision) silently dropped it.
            if let Some(next_id) = &entry.replace_with {
                current_id = next_id.clone();
                continue;
            }
            match &entry.kind {
                Some(SourceKind::SparseRegistry { raw }) => {
                    return finalize_source_replacement(raw, &current_id, operator, policy);
                }
                Some(SourceKind::NonSparse) | None => {
                    return SourceReplacement::None;
                }
            }
        }

        // Stage 1 (critic S4): not declared as a `[source]` entry — try a `[registries]`
        // crossover before giving up on this id.
        if let Some(raw_index) = lookup_raw_registry_index(&current_id, tiers) {
            if raw_index.starts_with(SPARSE_PREFIX) {
                return finalize_source_replacement(raw_index, &current_id, operator, policy);
            }
            return SourceReplacement::None;
        }

        // Unknown id — most commonly no `[source.crates-io]` table declared at all.
        return SourceReplacement::None;
    }

    tracing::warn!(
        max_hops = MAX_SOURCE_REPLACEMENT_HOPS,
        "[source] replace-with chain exceeded the maximum hop count; leaving crates-io unresolved"
    );
    SourceReplacement::None
}

fn finalize_source_replacement(
    raw: &str,
    terminal_id: &str,
    operator: &CargoOperator,
    policy: &RegistryAccessPolicy,
) -> SourceReplacement {
    match RegistryIndex::declared_bound(strip_sparse_prefix(raw), operator, policy) {
        Ok(index) => SourceReplacement::SparseMirror { index },
        Err(error) => {
            tracing::warn!(
                id = terminal_id,
                %error,
                "[source] replace-with terminal index failed validation/policy; leaving crates-io unresolved"
            );
            SourceReplacement::None
        }
    }
}

/// Every distinct alias `dependencies` declares via `registry = "<alias>"`.
///
/// This is the input [`resolve`] needs to know which aliases are actually worth
/// resolving, so config discovery is skipped entirely (spec NFR-004) when this is empty.
#[must_use]
pub fn referenced_aliases(dependencies: &[crate::types::CargoDependency]) -> HashSet<String> {
    dependencies
        .iter()
        .filter_map(|dep| match &dep.source {
            deps_core::parser::DependencySource::CustomRegistry { url } => Some(url.clone()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::net_policy::{MapEnv, WorkspaceRegistryAccess};
    use std::assert_matches;

    #[test]
    fn test_registry_index_trusted_prefix_matches_index_and_confines_to_its_path() {
        let index = RegistryIndex::builtin("https://artifacts.corp/cargo/index");
        let prefix = index.trusted_prefix();

        assert_eq!(prefix.as_str(), index.as_str());
        assert!(
            prefix.permits(
                &url::Url::parse("https://artifacts.corp/cargo/index/se/rd/serde").unwrap()
            )
        );
        assert!(
            !prefix
                .permits(&url::Url::parse("https://artifacts.corp/cargo/index-public/x").unwrap())
        );
    }

    fn public_only_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly)
    }

    fn all_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::with_allowlist(
            WorkspaceRegistryAccess::All,
            Arc::new(deps_core::net_policy::PrivateRegistryAllowlist::for_test(
                &["10.0.0.0/8"],
            )),
        )
    }

    fn off_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off)
    }

    fn no_operator() -> OperatorRegistries {
        OperatorRegistries::default()
    }

    fn operator_declaring(urls: &[&str]) -> OperatorRegistries {
        OperatorRegistries::declared_in(
            &OperatorPath::for_test("/home/me/.cargo/config.toml"),
            urls.iter().copied(),
        )
    }

    fn cargo_home_config(dir: &Path) -> OperatorPath {
        OperatorPath::for_test(dir.join("config.toml"))
    }

    #[test]
    fn test_registry_index_strips_sparse_prefix() {
        let policy = all_policy();
        let index =
            RegistryIndex::declared("sparse+https://index.mycorp.dev", &no_operator(), &policy)
                .unwrap();
        assert_eq!(index.as_str(), "https://index.mycorp.dev");
    }

    #[test]
    fn test_registry_index_rejects_http() {
        let policy = all_policy();
        assert_matches!(
            RegistryIndex::declared("http://index.mycorp.dev", &no_operator(), &policy),
            Err(RegistryIndexError::NotHttps(_))
        );
    }

    #[test]
    fn test_registry_index_rejects_userinfo() {
        let policy = all_policy();
        assert_matches!(
            RegistryIndex::declared(
                "https://user:pass@index.mycorp.dev",
                &no_operator(),
                &policy
            ),
            Err(RegistryIndexError::UserInfoPresent)
        );
    }

    #[test]
    fn test_registry_index_rejects_bare_username() {
        let policy = all_policy();
        assert_matches!(
            RegistryIndex::declared("https://user@index.mycorp.dev", &no_operator(), &policy),
            Err(RegistryIndexError::UserInfoPresent)
        );
    }

    #[test]
    fn test_registry_index_rejects_invalid_url() {
        let policy = all_policy();
        assert_matches!(
            RegistryIndex::declared("not a url", &no_operator(), &policy),
            Err(RegistryIndexError::InvalidUrl(_))
        );
    }

    /// S1: a userinfo-bearing `index = "…"` value that also fails `Url::parse` for an
    /// unrelated reason (an invalid port here) lands in `RegistryIndexError::InvalidUrl`, not
    /// `UserInfoPresent` — every call site here logs this error via `tracing::warn!(alias,
    /// %error, …)`, so the credential must never survive into `InvalidUrl`'s payload or its
    /// `Display`. Fixed once inside `deps_core::net_policy::validate_index_url`, which every
    /// `RegistryIndex::declared` call routes through — no separate redaction needed here.
    #[test]
    fn test_registry_index_invalid_url_error_redacts_userinfo() {
        let policy = all_policy();
        let err = RegistryIndex::declared(
            "https://user:hunter2@index.mycorp.dev:99999",
            &no_operator(),
            &policy,
        )
        .unwrap_err();
        assert_matches!(err, RegistryIndexError::InvalidUrl(_));
        assert!(!err.to_string().contains("hunter2"), "Display: {err}");
    }

    #[test]
    fn test_registry_index_accepts_https_without_sparse_prefix() {
        let policy = all_policy();
        assert!(
            RegistryIndex::declared("https://index.mycorp.dev", &no_operator(), &policy).is_ok()
        );
    }

    #[test]
    fn test_registry_index_builtin_crates_io() {
        // Also the coverage that makes `builtin`'s panic path unreachable in practice.
        let index = RegistryIndex::builtin("https://index.crates.io");
        assert_eq!(index.as_str(), "https://index.crates.io");
    }

    /// The URL-alone rule, not the caller, assigns trust: a URL the operator declared is
    /// Trusted and any other is workspace-declared.
    #[test]
    fn test_registry_index_trust_follows_the_operator_set() {
        let policy = all_policy();
        let url = "https://index.mycorp.dev";
        let trusted = RegistryIndex::declared(url, &operator_declaring(&[url]), &policy).unwrap();
        assert_eq!(trusted.trust(), RegistryTrust::Trusted);

        let workspace_declared = RegistryIndex::declared(url, &no_operator(), &policy).unwrap();
        assert_eq!(workspace_declared.trust(), RegistryTrust::WorkspaceDeclared);
    }

    // Issue #455, test-plan item 11: `builtin` is always `Trusted`.
    #[test]
    fn test_registry_index_builtin_is_trusted() {
        let index = RegistryIndex::builtin("https://index.crates.io");
        assert_eq!(index.trust(), RegistryTrust::Trusted);
    }

    /// An operator-declared URL skips the workspace policy under every level, but never the
    /// never-a-registry floor: the cloud-metadata address is rejected even though the operator
    /// named it (#1855).
    #[test]
    fn test_registry_index_operator_declared_metadata_ip_rejected_by_the_floor() {
        let url = "https://169.254.169.254/";
        for policy in [off_policy(), public_only_policy(), all_policy()] {
            assert_matches!(
                RegistryIndex::declared(url, &operator_declaring(&[url]), &policy),
                Err(RegistryIndexError::BlockedHost { .. }),
                "the floor applies to a Trusted candidate too"
            );
        }
    }

    #[test]
    fn test_registry_index_operator_declared_private_host_skips_the_policy() {
        let url = "https://10.0.0.1/";
        let index =
            RegistryIndex::declared(url, &operator_declaring(&[url]), &off_policy()).unwrap();
        assert_eq!(index.trust(), RegistryTrust::Trusted);
    }

    #[test]
    fn test_registry_index_workspace_declared_metadata_ip_blocked_under_public_only() {
        let policy = public_only_policy();
        assert_matches!(
            RegistryIndex::declared("https://169.254.169.254/", &no_operator(), &policy),
            Err(RegistryIndexError::BlockedHost { .. })
        );
    }

    #[test]
    fn test_registry_index_workspace_declared_global_allowed_under_public_only() {
        let policy = public_only_policy();
        assert!(
            RegistryIndex::declared("https://index.mycorp.dev", &no_operator(), &policy).is_ok()
        );
    }

    #[test]
    fn test_registry_index_workspace_declared_blocked_under_off() {
        let policy = off_policy();
        assert_matches!(
            RegistryIndex::declared("https://index.mycorp.dev", &no_operator(), &policy),
            Err(RegistryIndexError::BlockedHost { .. })
        );
    }

    #[test]
    fn test_registry_index_workspace_declared_rfc1918_allowed_under_all() {
        let policy = all_policy();
        assert!(RegistryIndex::declared("https://10.0.0.1/", &no_operator(), &policy).is_ok());
    }

    /// #1855: a credential follows the operator-declared URL it is bound to, in any spelling, and
    /// no other URL gets one: not an operator URL without a token, not a workspace URL.
    #[test]
    fn test_declared_bound_attaches_the_credential_to_its_url_only() {
        let policy = all_policy();
        let bound = "https://index.mycorp.dev/bound";
        let unbound = "https://index.mycorp.dev/unbound";
        let mut operator = CargoOperator::declaring(operator_declaring(&[bound, unbound]));
        operator.bind(
            strip_sparse_prefix(bound),
            AuthToken::new("operator-token".to_string()),
        );
        let index =
            |raw: &str| RegistryIndex::declared_bound(strip_sparse_prefix(raw), &operator, &policy);

        for spelling in [
            bound,
            "https://index.mycorp.dev/bound/",
            "sparse+https://index.mycorp.dev/bound",
        ] {
            let found = index(spelling).unwrap();
            assert_eq!(
                found.credential().map(AuthToken::expose_secret),
                Some("operator-token"),
                "{spelling}"
            );
        }

        let operator_without_token = index(unbound).unwrap();
        assert_eq!(operator_without_token.trust(), RegistryTrust::Trusted);
        assert!(!operator_without_token.has_credential());

        let workspace = index("https://index.mycorp.dev/elsewhere").unwrap();
        assert_eq!(workspace.trust(), RegistryTrust::WorkspaceDeclared);
        assert!(!workspace.has_credential());
    }

    /// The first binding of a URL wins, and the operator binds in a fixed order, so two aliases
    /// declaring one URL always give the same credential.
    #[test]
    fn test_bind_keeps_the_first_credential_for_a_url() {
        let url = "https://index.mycorp.dev/first-wins";
        let mut operator = CargoOperator::declaring(operator_declaring(&[url]));
        operator.bind(
            strip_sparse_prefix(url),
            AuthToken::new("first".to_string()),
        );
        operator.bind(
            strip_sparse_prefix(url),
            AuthToken::new("second".to_string()),
        );

        let index =
            RegistryIndex::declared_bound(strip_sparse_prefix(url), &operator, &all_policy())
                .unwrap();
        assert_eq!(
            index.credential().map(AuthToken::expose_secret),
            Some("first")
        );
    }

    #[test]
    fn test_auth_token_debug_and_display_redact() {
        let token = AuthToken::new("super-secret-value".to_string());
        assert_eq!(format!("{token:?}"), "AuthToken(***)");
        assert_eq!(format!("{token}"), "***");
        assert!(!format!("{token:?}").contains("super-secret-value"));
    }

    #[test]
    fn test_parse_workspace_registries_raw_never_populates_auth() {
        let content = r#"
[registries.my-corp]
index = "sparse+https://index.mycorp.dev"
token = "should-be-ignored"
"#;
        let result = parse_workspace_registries_raw(content);
        // The return type itself has no token field — this just also confirms the `index`
        // value is captured correctly alongside the ignored `token` key.
        assert_eq!(
            result.get("my-corp").map(String::as_str),
            Some("sparse+https://index.mycorp.dev")
        );
    }

    #[test]
    fn test_parse_cargo_home_registries_raw_reads_token() {
        let content = r#"
[registries.my-corp]
index = "sparse+https://index.mycorp.dev"
token = "secret-token"
"#;
        let result = parse_cargo_home_registries_raw(content);
        let (raw_index, token) = result.get("my-corp").unwrap();
        assert_eq!(raw_index, "sparse+https://index.mycorp.dev");
        assert_eq!(
            token.as_ref().unwrap().as_redacted().expose_secret(),
            "secret-token"
        );
    }

    #[test]
    fn test_parse_registries_raw_malformed_toml_fails_closed() {
        let content = "this is [ not valid toml";
        assert!(parse_workspace_registries_raw(content).is_empty());
        assert!(parse_cargo_home_registries_raw(content).is_empty());
    }

    #[test]
    fn test_parse_registries_raw_rejects_excessive_nesting() {
        let content = format!("a = {}1{}", "[".repeat(300), "]".repeat(300));
        assert!(parse_workspace_registries_raw(&content).is_empty());
        assert!(parse_cargo_home_registries_raw(&content).is_empty());
    }

    #[test]
    fn test_cargo_home_config_path_none_when_unset() {
        assert!(cargo_home_config_path_with_env(&MapEnv::new()).is_none());
    }

    #[test]
    fn test_cargo_home_config_path_some_when_set() {
        let dir = tempfile::tempdir().unwrap();
        let env = MapEnv::new().with_var("CARGO_HOME", dir.path().to_str().unwrap());
        let path = cargo_home_config_path_with_env(&env).unwrap();
        assert_eq!(path.as_path(), dir.path().join("config.toml"));
    }

    /// A relative `CARGO_HOME` would resolve against a directory a repository can influence, so
    /// it names no operator-owned location and is ignored (#1855).
    #[test]
    fn test_cargo_home_config_path_ignores_a_relative_cargo_home() {
        let env = MapEnv::new().with_var("CARGO_HOME", "relative/.cargo");
        assert!(cargo_home_config_path_with_env(&env).is_none());
    }

    #[test]
    fn test_resolve_workspace_wins_over_cargo_home() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://workspace.example\"\n",
        )
        .unwrap();

        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://real.example\"\ntoken = \"real-token\"\n",
        )
        .unwrap();

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve(
            &aliases,
            &[root.path().join(".cargo/config.toml")],
            Some(&cargo_home_config(cargo_home.path())),
            &cache,
            &policy,
        );

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://workspace.example");
        assert!(
            !entry.index.has_credential(),
            "workspace-shadowed entry must never carry the cargo-home token"
        );
        assert_eq!(entry.provenance, Provenance::Workspace);
    }

    /// Regression: a project living under `$HOME` (the default `CARGO_HOME=~/.cargo`
    /// layout) has the ancestor walk pick up `~/.cargo/config.toml` — the *same file* as
    /// `$CARGO_HOME/config.toml` — as a workspace-tier candidate. Before the
    /// canonicalized-path exclusion, that duplicate entry won the workspace-tier-always-wins
    /// precedence and silently dropped the token: the alias still resolved, just
    /// unauthenticated, which looks like success.
    #[test]
    fn test_resolve_home_nested_project_does_not_lose_cargo_home_token() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".cargo")).unwrap();
        let cargo_home_config = home.path().join(".cargo/config.toml");
        std::fs::write(
            &cargo_home_config,
            "[registries.my-corp]\nindex = \"sparse+https://real.example\"\ntoken = \"real-token\"\n",
        )
        .unwrap();

        // Reproduces the ancestor-walk collision directly, without depending on
        // `crate::parser`'s merged walk (tested separately in `parser.rs`).
        let workspace_paths = vec![cargo_home_config.clone()];

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve(
            &aliases,
            &workspace_paths,
            Some(&OperatorPath::for_test(cargo_home_config)),
            &cache,
            &policy,
        );

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://real.example");
        assert_eq!(entry.provenance, Provenance::CargoHome);
        assert_eq!(
            entry.index.credential().map(AuthToken::expose_secret),
            Some("real-token"),
            "the CARGO_HOME token must not be lost just because the project lives \
             under $HOME"
        );
    }

    #[test]
    fn test_resolve_falls_back_to_cargo_home_when_no_workspace_entry() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://real.example\"\ntoken = \"real-token\"\n",
        )
        .unwrap();

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve(
            &aliases,
            &[],
            Some(&cargo_home_config(cargo_home.path())),
            &cache,
            &policy,
        );

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://real.example");
        assert_eq!(
            entry.index.credential().unwrap().expose_secret(),
            "real-token"
        );
        assert_eq!(entry.provenance, Provenance::CargoHome);
    }

    /// #1453 impl-critic S1: a `$CARGO_HOME/config.toml` `[registries.<name>] index = ...`
    /// entry that fails validation for a non-blocked-host reason must populate
    /// `CargoConfig::rejected` exactly like a workspace-tier entry does — `RegistryTrust::Trusted`
    /// only skips the policy gate, not the scheme/userinfo/URL-shape checks
    /// `validate_index_url` still applies.
    #[test]
    fn test_resolve_cargo_home_file_entry_rejected_populates_rejected() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.my-corp]\nindex = \"http://insecure.example\"\n",
        )
        .unwrap();

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve(
            &aliases,
            &[],
            Some(&cargo_home_config(cargo_home.path())),
            &cache,
            &policy,
        );

        assert!(config.get("my-corp").is_none());
        assert_eq!(
            config.rejected_reason("my-corp"),
            Some(RegistryRejectionReason::NotHttps)
        );
    }

    /// #1453 impl-critic S1: an invalid `CARGO_REGISTRIES_*_INDEX` env override must not be
    /// reported as a rejection when the file-tier fallback resolves to a valid entry — the
    /// env override silently loses to the working fallback exactly as before, so nothing new
    /// should surface as a diagnostic for this case.
    #[test]
    fn test_resolve_env_var_index_override_rejected_falls_back_silently_to_valid_file_entry() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://real.example\"\n",
        )
        .unwrap();

        let env = MapEnv::new().with_var("CARGO_REGISTRIES_MY_CORP_INDEX", "not-a-valid-url");

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve_with_env(
            &aliases,
            &[],
            Some(&cargo_home_config(cargo_home.path())),
            &cache,
            &policy,
            &env,
        );

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://real.example");
        assert_eq!(config.rejected_reason("my-corp"), None);
    }

    /// #1453 impl-critic S1: an invalid `CARGO_REGISTRIES_*_INDEX` env override with no
    /// file-tier fallback at all must populate `CargoConfig::rejected` — previously this
    /// silently dropped the alias with only a `tracing::warn!`.
    #[test]
    fn test_resolve_env_var_index_override_rejected_with_no_file_entry_populates_rejected() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let env = MapEnv::new().with_var(
            "CARGO_REGISTRIES_MY_CORP_INDEX",
            "sparse+https://user:pass@index.mycorp.dev",
        );

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve_with_env(&aliases, &[], None, &cache, &policy, &env);

        assert!(config.get("my-corp").is_none());
        assert_eq!(
            config.rejected_reason("my-corp"),
            Some(RegistryRejectionReason::UserInfoPresent)
        );
    }

    /// #1453 code-review finding 3: when *both* the `CARGO_REGISTRIES_*_INDEX` env override
    /// and the `$CARGO_HOME/config.toml` file-tier entry are independently invalid, the env
    /// override's own reason must be reported — not silently discarded in favor of the
    /// unrelated file-tier failure.
    #[test]
    fn test_resolve_env_and_file_both_rejected_prefers_env_reason() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.my-corp]\nindex = \"http://insecure.example\"\n",
        )
        .unwrap();

        let env = MapEnv::new().with_var(
            "CARGO_REGISTRIES_MY_CORP_INDEX",
            "sparse+https://user:pass@index.mycorp.dev",
        );

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve_with_env(
            &aliases,
            &[],
            Some(&cargo_home_config(cargo_home.path())),
            &cache,
            &policy,
            &env,
        );

        assert!(config.get("my-corp").is_none());
        assert_eq!(
            config.rejected_reason("my-corp"),
            Some(RegistryRejectionReason::UserInfoPresent),
            "the env override's own reason must survive, not the unrelated file entry's"
        );
    }

    #[test]
    fn test_resolve_unconfigured_alias_stays_unresolved() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let aliases: HashSet<String> = std::iter::once("unknown".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve(&aliases, &[], None, &cache, &policy);
        assert!(config.get("unknown").is_none());
    }

    #[test]
    fn test_resolve_env_var_index_override() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let aliases: HashSet<String> = std::iter::once("env-only-corp".to_string()).collect();
        let env = MapEnv::new()
            .with_var(
                "CARGO_REGISTRIES_ENV_ONLY_CORP_INDEX",
                "sparse+https://env.example",
            )
            .with_var("CARGO_REGISTRIES_ENV_ONLY_CORP_TOKEN", "env-token");

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve_with_env(&aliases, &[], None, &cache, &policy, &env);
        let entry = config.get("env-only-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://env.example");
        assert_eq!(
            entry.index.credential().unwrap().expose_secret(),
            "env-token"
        );
        assert_eq!(entry.provenance, Provenance::CargoHome);
    }

    /// FR-015: two distinct alias spellings deriving the same env-var name must both be
    /// skipped for env resolution, not have one arbitrarily win.
    #[test]
    fn test_resolve_env_var_name_collision_disables_both() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let aliases: HashSet<String> = ["my-corp".to_string(), "my_corp".to_string()]
            .into_iter()
            .collect();
        let env = MapEnv::new().with_var(
            "CARGO_REGISTRIES_MY_CORP_INDEX",
            "sparse+https://ambiguous.example",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve_with_env(&aliases, &[], None, &cache, &policy, &env);
        assert!(config.get("my-corp").is_none());
        assert!(config.get("my_corp").is_none());
    }

    /// The env-var TOKEN override must never resurrect a credential for an alias a
    /// workspace file has shadowed — the exact US-004 scenario, exercised through
    /// `resolve` end-to-end rather than only at the raw-parse unit level.
    #[test]
    fn test_resolve_env_token_never_attaches_to_workspace_shadowed_alias() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.github]\nindex = \"sparse+https://attacker.example\"\n",
        )
        .unwrap();

        let env = MapEnv::new().with_var("CARGO_REGISTRIES_GITHUB_TOKEN", "legitimate-token");

        let aliases: HashSet<String> = std::iter::once("github".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve_with_env(
            &aliases,
            &[root.path().join(".cargo/config.toml")],
            None,
            &cache,
            &policy,
            &env,
        );

        let entry = config.get("github").unwrap();
        assert_eq!(entry.index.as_str(), "https://attacker.example");
        assert!(
            !entry.index.has_credential(),
            "the legitimate env token must never attach to the attacker-controlled index"
        );
    }

    /// #1855: a `sparse+` registry in `$CARGO_HOME` is operator-declared, so it classifies
    /// Trusted and carries its token.
    #[test]
    fn test_resolve_sparse_prefixed_cargo_home_registry_is_trusted_with_credential() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.corp]\nindex = \"sparse+https://corp.example/index\"\ntoken = \"corp-token\"\n",
        )
        .unwrap();

        let aliases: HashSet<String> = std::iter::once("corp".to_string()).collect();
        let (config, _) = resolve_with_env(
            &aliases,
            &[],
            Some(&cargo_home_config(cargo_home.path())),
            &ConfigFileCache::new(),
            &off_policy(),
            &MapEnv::new(),
        );

        let entry = config.get("corp").unwrap();
        assert_eq!(entry.index.trust(), RegistryTrust::Trusted);
        assert_eq!(
            entry.index.credential().map(AuthToken::expose_secret),
            Some("corp-token")
        );
    }

    /// #1855: an operator registry declared only through `CARGO_REGISTRIES_<ALIAS>_INDEX`, with
    /// `$CARGO_HOME` unset, is still operator-declared: Trusted, policy skipped, token attached.
    #[test]
    fn test_resolve_env_only_operator_registry_is_trusted_without_cargo_home() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let env = MapEnv::new()
            .with_var(
                "CARGO_REGISTRIES_ENVREG_INDEX",
                "sparse+https://envreg.example",
            )
            .with_var("CARGO_REGISTRIES_ENVREG_TOKEN", "env-token");

        let aliases: HashSet<String> = std::iter::once("envreg".to_string()).collect();
        let (config, _) = resolve_with_env(
            &aliases,
            &[],
            None,
            &ConfigFileCache::new(),
            &off_policy(),
            &env,
        );

        let entry = config.get("envreg").unwrap();
        assert_eq!(entry.index.trust(), RegistryTrust::Trusted);
        assert_eq!(
            entry.index.credential().map(AuthToken::expose_secret),
            Some("env-token")
        );
    }

    /// #1855: a workspace alias that names an operator-declared URL gets that URL's egress trust
    /// (the policy is skipped, even under `off`) and the credential bound to that URL.
    #[test]
    fn test_resolve_workspace_alias_naming_an_operator_url_gets_the_urls_trust_and_credential() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.repo-alias]\nindex = \"sparse+https://corp.example/index/\"\n",
        )
        .unwrap();
        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.corp]\nindex = \"sparse+https://corp.example/index\"\ntoken = \"corp-token\"\n",
        )
        .unwrap();

        let aliases: HashSet<String> = std::iter::once("repo-alias".to_string()).collect();
        let (config, _) = resolve_with_env(
            &aliases,
            &[root.path().join(".cargo/config.toml")],
            Some(&cargo_home_config(cargo_home.path())),
            &ConfigFileCache::new(),
            &off_policy(),
            &MapEnv::new(),
        );

        let entry = config.get("repo-alias").unwrap();
        assert_eq!(entry.provenance, Provenance::Workspace);
        assert_eq!(entry.index.trust(), RegistryTrust::Trusted);
        assert_eq!(
            entry.index.credential().map(AuthToken::expose_secret),
            Some("corp-token")
        );
    }

    /// #1855: a workspace alias naming a URL the operator did not declare stays
    /// workspace-declared and is refused under `off`.
    #[test]
    fn test_resolve_workspace_alias_for_an_undeclared_url_is_policy_gated() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.repo-alias]\nindex = \"sparse+https://repo-chosen.example/index\"\n",
        )
        .unwrap();

        let aliases: HashSet<String> = std::iter::once("repo-alias".to_string()).collect();
        let (config, _) = resolve_with_env(
            &aliases,
            &[root.path().join(".cargo/config.toml")],
            None,
            &ConfigFileCache::new(),
            &off_policy(),
            &MapEnv::new(),
        );

        assert!(config.get("repo-alias").is_none());
        assert!(config.blocked_class("repo-alias").is_some());
    }

    /// #1855: the never-a-registry floor applies to an operator-declared `$CARGO_HOME` registry
    /// too: loopback and link-local hosts are rejected and reported as blocked.
    #[test]
    fn test_resolve_cargo_home_registry_on_loopback_or_link_local_is_blocked() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.loop]\nindex = \"sparse+https://127.0.0.1:8443\"\n\
             [registries.metadata]\nindex = \"sparse+https://169.254.169.254\"\n",
        )
        .unwrap();

        let aliases: HashSet<String> = ["loop".to_string(), "metadata".to_string()]
            .into_iter()
            .collect();
        let (config, _) = resolve_with_env(
            &aliases,
            &[],
            Some(&cargo_home_config(cargo_home.path())),
            &ConfigFileCache::new(),
            &all_policy(),
            &MapEnv::new(),
        );

        for alias in ["loop", "metadata"] {
            assert!(config.get(alias).is_none(), "{alias}");
            assert!(config.blocked_class(alias).is_some(), "{alias}");
        }
    }

    /// #1855: `sparse+` is removed exactly once, so the operator set and the classifier agree on
    /// the text; a doubled prefix is left as `sparse+https://…` and refused as not https.
    #[test]
    fn test_resolve_strips_the_sparse_prefix_once() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let env = MapEnv::new().with_var(
            "CARGO_REGISTRIES_DOUBLE_INDEX",
            "sparse+sparse+https://double.example",
        );
        let aliases: HashSet<String> = std::iter::once("double".to_string()).collect();
        let (config, _) = resolve_with_env(
            &aliases,
            &[],
            None,
            &ConfigFileCache::new(),
            &all_policy(),
            &env,
        );

        assert!(config.get("double").is_none());
        assert_eq!(
            config.rejected_reason("double"),
            Some(RegistryRejectionReason::NotHttps)
        );
    }

    #[test]
    fn test_referenced_aliases_collects_custom_registry_urls() {
        use crate::types::{CargoDependency, CargoDependencySection};
        use deps_core::parser::DependencySource;
        use deps_core::position::Range;

        let deps = vec![
            CargoDependency {
                name: "a".into(),
                name_range: Range::default(),
                version_req: None,
                version_range: None,
                features: vec![],
                features_range: None,
                source: DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
                section: CargoDependencySection::Dependencies,
                package: None,
                custom_registry_origin: None,
            },
            CargoDependency {
                name: "b".into(),
                name_range: Range::default(),
                version_req: None,
                version_range: None,
                features: vec![],
                features_range: None,
                source: DependencySource::Registry,
                section: CargoDependencySection::Dependencies,
                package: None,
                custom_registry_origin: None,
            },
        ];

        let aliases = referenced_aliases(&deps);
        assert_eq!(aliases.len(), 1);
        assert!(aliases.contains("my-corp"));
    }

    // ---- ConfigFileCache ----

    #[test]
    fn test_config_file_cache_hit_reuses_parsed_arc_without_reparsing() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[registries.a]\nindex = \"sparse+https://a.example\"\n",
        )
        .unwrap();

        let cache = ConfigFileCache::new();
        let first = cache.get_or_parse_workspace(&path).unwrap();
        let second = cache.get_or_parse_workspace(&path).unwrap();

        assert!(
            Arc::ptr_eq(&first, &second),
            "a cache hit must return the same Arc, not re-parse"
        );
    }

    /// P1 (plan-1b §4 Performance/M4, flagged missing by the tester validator): the real
    /// bound is "at most two stats per ancestor directory... and zero filesystem reads per
    /// parse on a cache hit" — `Arc::ptr_eq` alone proves the *value* is reused, not that no
    /// syscall ran. This counts actual `stat`/`read` calls via `fs_probe`.
    #[test]
    fn test_config_file_cache_hit_does_zero_reads_and_exactly_one_stat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[registries.a]\nindex = \"sparse+https://a.example\"\n",
        )
        .unwrap();

        let cache = ConfigFileCache::new();
        // Acquired before the priming call too: that warm-up still does one real stat/read
        // through fs_probe, which must not race a sibling test's own measured window either.
        let _guard = deps_core::fs_probe::snapshot_guard();
        // Prime the cache — the first call is necessarily a miss (one stat, one read).
        cache.get_or_parse_workspace(&path).unwrap();

        let (stats_before, reads_before) = deps_core::fs_probe::snapshot();
        let hit = cache.get_or_parse_workspace(&path).unwrap();
        let (stats_after, reads_after) = deps_core::fs_probe::snapshot();

        assert_eq!(
            reads_after - reads_before,
            0,
            "a cache hit must perform zero content reads"
        );
        assert_eq!(
            stats_after - stats_before,
            1,
            "a cache hit still pays exactly one mtime stat"
        );
        match &hit.tier {
            CachedTier::Workspace(map) => assert!(map.contains_key("a")),
            CachedTier::CargoHome(_) => panic!("expected Workspace tier"),
        }
    }

    /// S3: adding a new `registry = "…"` alias to the manifest must resolve without any
    /// config-file change — the raw tables are cached, but alias *filtering* runs per
    /// parse.
    #[test]
    fn test_resolve_new_alias_resolves_without_config_file_change() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.a]\nindex = \"sparse+https://a.example\"\n\
             [registries.b]\nindex = \"sparse+https://b.example\"\n",
        )
        .unwrap();

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let workspace_paths = vec![root.path().join(".cargo/config.toml")];

        let first_aliases: HashSet<String> = std::iter::once("a".to_string()).collect();
        let (first, _) = resolve(&first_aliases, &workspace_paths, None, &cache, &policy);
        assert!(first.get("a").is_some());
        assert!(first.get("b").is_none(), "b was not yet referenced");

        // No config-file write between these two calls — only the referenced-alias set
        // changed, simulating a manifest edit that adds `registry = "b"`.
        let second_aliases: HashSet<String> =
            ["a".to_string(), "b".to_string()].into_iter().collect();
        let (second, _) = resolve(&second_aliases, &workspace_paths, None, &cache, &policy);
        assert!(
            second.get("b").is_some(),
            "newly-referenced alias b must resolve immediately"
        );
    }

    /// A `didChangeConfiguration`-driven policy change must take effect immediately, with
    /// no cache invalidation of its own — the policy is not part of the cache at all.
    #[test]
    fn test_resolve_policy_change_takes_effect_with_no_cache_invalidation() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.metadata]\nindex = \"https://10.0.0.1\"\n",
        )
        .unwrap();

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let workspace_paths = vec![root.path().join(".cargo/config.toml")];
        let aliases: HashSet<String> = std::iter::once("metadata".to_string()).collect();

        let (first, _) = resolve(&aliases, &workspace_paths, None, &cache, &policy);
        assert!(first.get("metadata").is_some(), "allowed under All");

        policy.set(WorkspaceRegistryAccess::PublicOnly);
        let (second, _) = resolve(&aliases, &workspace_paths, None, &cache, &policy);
        assert!(
            second.get("metadata").is_none(),
            "blocked under PublicOnly, same cache"
        );
    }

    // ---- [source] chain resolution ----

    fn write_config(dir: &Path, content: &str) -> PathBuf {
        std::fs::create_dir_all(dir.join(".cargo")).unwrap();
        let path = dir.join(".cargo/config.toml");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_source_chain_single_hop_to_sparse() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"my-mirror\"\n\
             [source.my-mirror]\nregistry = \"sparse+https://mirror.example\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        match replacement {
            SourceReplacement::SparseMirror { index } => {
                assert_eq!(index.as_str(), "https://mirror.example");
                assert!(!index.has_credential());
            }
            SourceReplacement::None => panic!("expected a resolved mirror"),
        }
    }

    #[test]
    fn test_source_chain_two_hops() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"intermediate\"\n\
             [source.intermediate]\nreplace-with = \"terminal\"\n\
             [source.terminal]\nregistry = \"sparse+https://terminal.example\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        assert_matches!(replacement, SourceReplacement::SparseMirror { .. });
    }

    #[test]
    fn test_source_chain_directory_falls_back_to_none() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"vendored\"\n\
             [source.vendored]\ndirectory = \"vendor\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        assert_eq!(replacement, SourceReplacement::None);
    }

    #[test]
    fn test_source_chain_local_registry_falls_back_to_none() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"local\"\n\
             [source.local]\nlocal-registry = \"local-registry\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        assert_eq!(replacement, SourceReplacement::None);
    }

    #[test]
    fn test_source_chain_bare_https_git_index_falls_back_to_none() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"git-mirror\"\n\
             [source.git-mirror]\nregistry = \"https://github.com/rust-lang/crates.io-index\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        assert_eq!(replacement, SourceReplacement::None);
    }

    #[test]
    fn test_source_chain_self_referential_stops() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"crates-io\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        assert_eq!(replacement, SourceReplacement::None);
    }

    #[test]
    fn test_source_chain_three_cycle_stops() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"a\"\n\
             [source.a]\nreplace-with = \"b\"\n\
             [source.b]\nreplace-with = \"crates-io\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        assert_eq!(replacement, SourceReplacement::None);
    }

    #[test]
    fn test_source_chain_seventeen_hops_exceeds_bound() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let mut toml = String::from("[source.crates-io]\nreplace-with = \"hop0\"\n");
        for i in 0..16 {
            toml.push_str(&format!(
                "[source.hop{i}]\nreplace-with = \"hop{}\"\n",
                i + 1
            ));
        }
        toml.push_str("[source.hop16]\nregistry = \"sparse+https://terminal.example\"\n");
        let path = write_config(root.path(), &toml);

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        // 17 hops (crates-io -> hop0 -> ... -> hop16) exceeds MAX_SOURCE_REPLACEMENT_HOPS (16).
        assert_eq!(replacement, SourceReplacement::None);
    }

    /// #1505 P4: the cyclic `[source] replace-with` chain warning used to interpolate the
    /// revisited source id raw (`id = %current_id`), letting a manifest-adjacent
    /// `.cargo/config.toml` with a crafted source table name forge a log line. `id` is now a
    /// `?`-Debug field.
    #[test]
    fn test_source_chain_cyclic_id_logs_sanitized() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let malicious_id = "bad\r\n\x1b[31mERROR deps_lsp: FORGED";
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"bad\\r\\n\\u001b[31mERROR deps_lsp: FORGED\"\n\
             [source.\"bad\\r\\n\\u001b[31mERROR deps_lsp: FORGED\"]\nreplace-with = \"bad\\r\\n\\u001b[31mERROR deps_lsp: FORGED\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();

        let log = deps_core::test_util::capture_tracing_output(|| {
            let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);
            assert_eq!(replacement, SourceReplacement::None);
        });

        assert_eq!(
            log.lines().count(),
            1,
            "a crafted source id must not forge an extra log line: {log:?}"
        );
        assert!(
            !log.contains(malicious_id),
            "the raw, un-escaped payload (with its literal CR/ESC bytes) must not survive \
             intact: {log:?}"
        );
    }

    #[test]
    fn test_source_chain_terminal_blocked_by_policy() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"metadata\"\n\
             [source.metadata]\nregistry = \"sparse+https://169.254.169.254/\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = public_only_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        assert_eq!(replacement, SourceReplacement::None);
    }

    /// Stage-1 crossover (critic S4): a `replace-with` naming a `[registries]` entry, not
    /// a `[source]` entry, must still resolve.
    #[test]
    fn test_source_chain_stage_one_registries_crossover() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"my-corp\"\n\
             [registries.my-corp]\nindex = \"sparse+https://index.mycorp.dev\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        match replacement {
            SourceReplacement::SparseMirror { index, .. } => {
                assert_eq!(index.as_str(), "https://index.mycorp.dev");
            }
            SourceReplacement::None => panic!("expected the [registries] crossover to resolve"),
        }
    }

    /// S2 regression: `[source.crates-io]` carrying an explicit definition (here, a bare
    /// git-index `registry =`, exactly the shape Cargo treats as the implicit builtin
    /// crates.io definition) *and* `replace-with` in the same table — the shape every large
    /// public mirror's setup instructions publish verbatim. Cargo applies `replace-with`
    /// regardless of the explicit definition; this must resolve the mirror, not `None`.
    #[test]
    fn test_source_chain_replace_with_wins_over_explicit_kind_on_same_table() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\n\
             registry = \"https://github.com/rust-lang/crates.io-index\"\n\
             replace-with = \"mirror\"\n\
             [source.mirror]\nregistry = \"sparse+https://mirror.example/index/\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        match replacement {
            SourceReplacement::SparseMirror { index, .. } => {
                assert_eq!(index.as_str(), "https://mirror.example/index");
            }
            SourceReplacement::None => panic!(
                "replace-with must apply even though [source.crates-io] also declares an explicit kind"
            ),
        }
    }

    /// The inverse S2 shape: a table declaring both a *sparse* `registry =` of its own AND a
    /// `replace-with` pointing elsewhere. Cargo still follows `replace-with`, never the
    /// table's own `registry` value — asserting the resolved index is the replacement
    /// target, not the table's own (differently-hosted) sparse registry.
    #[test]
    fn test_source_chain_replace_with_wins_over_own_sparse_registry() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[source.crates-io]\n\
             registry = \"sparse+https://a.example/index/\"\n\
             replace-with = \"b\"\n\
             [source.b]\nregistry = \"sparse+https://b.example/index/\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        match replacement {
            SourceReplacement::SparseMirror { index, .. } => {
                assert_eq!(
                    index.as_str(),
                    "https://b.example/index",
                    "replace-with must win over the table's own sparse `registry` value"
                );
            }
            SourceReplacement::None => panic!("expected the replace-with target to resolve"),
        }
    }

    /// A workspace-tier `replace-with` crossing into a `$CARGO_HOME` `[registries]` entry that
    /// carries a token resolves to the operator's own URL, so it carries the credential bound to
    /// that URL: the credential follows the URL, not the workspace link that reached it (it goes
    /// to the operator's server and nowhere else).
    #[test]
    fn test_source_chain_workspace_crossover_into_an_operator_url_uses_its_bound_credential() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let workspace_path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"my-corp\"\n",
        );

        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://index.mycorp.dev\"\ntoken = \"operator-token\"\n",
        )
        .unwrap();

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(
            &HashSet::new(),
            &[workspace_path],
            Some(&cargo_home_config(cargo_home.path())),
            &cache,
            &policy,
        );

        match replacement {
            SourceReplacement::SparseMirror { index } => {
                assert_eq!(index.as_str(), "https://index.mycorp.dev");
                assert_eq!(
                    index.credential().map(AuthToken::expose_secret),
                    Some("operator-token")
                );
            }
            SourceReplacement::None => panic!("expected the mirror to resolve"),
        }
    }

    /// The positive counterpart: when the *whole* chain is `$CARGO_HOME`-declared, the
    /// terminal `[registries]` entry's token is legitimately attached.
    #[test]
    fn test_source_chain_fully_trusted_chain_attaches_cargo_home_token() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[source.crates-io]\nreplace-with = \"my-corp\"\n\
             [registries.my-corp]\nindex = \"sparse+https://index.mycorp.dev\"\ntoken = \"real-token\"\n",
        )
        .unwrap();

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(
            &HashSet::new(),
            &[],
            Some(&cargo_home_config(cargo_home.path())),
            &cache,
            &policy,
        );

        match replacement {
            SourceReplacement::SparseMirror { index } => {
                assert_eq!(
                    index.credential().map(AuthToken::expose_secret),
                    Some("real-token")
                );
            }
            SourceReplacement::None => panic!("expected the fully-trusted chain to resolve"),
        }
    }

    #[test]
    fn test_source_chain_no_source_section_resolves_none() {
        // Per `fs_probe::snapshot_guard`'s doc: every fs_probe-touching test here must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let path = write_config(
            root.path(),
            "[registries.other]\nindex = \"sparse+https://other.example\"\n",
        );

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(&HashSet::new(), &[path], None, &cache, &policy);

        assert_eq!(replacement, SourceReplacement::None);
    }
}
