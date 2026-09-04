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
//! ever runs. Two, related, threats this module closes:
//!
//! - **Credential exfiltration.** [`AuthToken`] must never be attachable to a request whose
//!   destination URL provenance traces to a workspace file. This is enforced
//!   **structurally**, not by a runtime check:
//!   - `parse_workspace_registries_raw` has no return type capable of expressing a token —
//!     its value type is a bare `String`, with no token field anywhere. There is no `token`
//!     field lookup anywhere in that function's body.
//!   - Only `parse_cargo_home_registries_raw` (fed `$CARGO_HOME/config.toml`'s content) and
//!     the environment-variable lookup in [`resolve`] ever construct `Some(AuthToken)`.
//!   - [`Provenance`] exists purely for logging/diagnostics. Nothing in this crate branches
//!     on it to decide whether to attach a credential — grepping for `Provenance` outside
//!     this module should find no such branch (verified in this PR's security review).
//! - **Internal-network reachability (SSRF-adjacent, #443).** [`RegistryIndex::new`] requires
//!   an [`IndexTrust`] and a [`deps_core::net_policy::RegistryAccessPolicy`]: a
//!   `WorkspaceDeclared` URL is checked against the live policy before it can ever become a
//!   fetchable index, while a `Trusted` (`$CARGO_HOME`-provenance) URL is never
//!   policy-checked at all — it is the user's own configuration, not something a cloned
//!   repository controls. See `.local/specs/023-cargo-custom-registries/plan-1b.md` §1-§2.
//!
//! See spec `.local/specs/023-cargo-custom-registries/spec.md` FR-008/FR-009 and the design
//! review handoffs cited there for the two rounds of critique the credential boundary
//! survived.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use toml_span::value::Table;

use deps_core::net_policy::{
    HostClass, PolicyGate, RegistryAccessPolicy, redact_userinfo, validate_index_url,
};
use deps_core::{DEFAULT_MAX_CACHED_FILES, MtimeFileCache};

/// A registry bearer-token credential, redacted everywhere except the one call site that
/// formats it into an `Authorization` header.
///
/// Constructible only from within this module (see the module-level security-model docs) —
/// no other code path in this crate has the means to produce one. A thin wrapper over
/// [`deps_core::secret::Redacted`] rather than a bare type alias: `Debug` prints
/// `AuthToken(***)`, not `Redacted(***)`, so a panic message or log line still names which
/// credential leaked its type.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthToken(deps_core::secret::Redacted);

impl AuthToken {
    /// Wraps `token`. Kept `pub(crate)` rather than `pub`: the module-level security-model
    /// docs above are the enforcement, and widening this to `pub` would let any other crate
    /// construct one with no [`Provenance`]/[`IndexTrust`] to account for at all.
    pub(crate) fn new(token: String) -> Self {
        Self(deps_core::secret::Redacted::new(token))
    }

    /// The raw token value, for building an `Authorization` header. Never logged, printed,
    /// or otherwise surfaced — callers must not pass this to anything but a header value.
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
/// **Diagnostics and logging only.** Never gates whether [`ResolvedRegistryEntry::auth`]
/// is populated — that is a structural property of which parsing function produced the
/// entry (see the module-level docs), not a runtime branch on this enum. A future change
/// that starts branching on this to decide whether to attach a credential reintroduces the
/// exact vulnerability class this design closed.
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

/// Whose input a candidate registry index URL is, for [`RegistryIndex::new`]'s
/// [`deps_core::net_policy::RegistryAccessPolicy`] gate.
///
/// A new enum rather than a reuse of [`Provenance`], even though the variants map 1:1:
/// `Provenance`'s doc comment is an explicit "nothing ever branches on this" invariant
/// protecting the auth boundary; adding a policy branch on it would make that sentence false
/// and invite a future reader to add an auth branch too. Two small enums, one invariant
/// each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexTrust {
    /// `$CARGO_HOME/config.toml` or a `CARGO_REGISTRIES_*` environment variable — the
    /// user's own environment. Never policy-checked (see [`RegistryIndex::new`]).
    Trusted,
    /// A workspace file: the `Cargo.toml` alias target itself, or any ancestor
    /// `.cargo/config.toml`/`[source]` chain link within the workspace. Checked against the
    /// live [`deps_core::net_policy::RegistryAccessPolicy`].
    WorkspaceDeclared,
}

impl IndexTrust {
    /// The less-trusted of `self` and `other` — `WorkspaceDeclared` if either is, `Trusted`
    /// only if both are.
    ///
    /// Used to fold a `[source]` replace-with chain's trust (plan-1b §1.4 step 3): one
    /// workspace-tier link anywhere in the chain makes the whole chain `WorkspaceDeclared`,
    /// closing the shape where a hostile `[source.crates-io] replace-with = "corp"` in the
    /// repo borrows a `$CARGO_HOME`-defined source's credential. Also used by
    /// [`crate::registry::CargoRegistry::register_alternate`] (issue #455, C3) to fold a
    /// re-registration of the same index URL to the stricter of its old and new trust tier.
    #[must_use]
    pub(crate) const fn min(self, other: Self) -> Self {
        match (self, other) {
            (Self::WorkspaceDeclared, _) | (_, Self::WorkspaceDeclared) => Self::WorkspaceDeclared,
            (Self::Trusted, Self::Trusted) => Self::Trusted,
        }
    }
}

/// A validated, `sparse+`-prefix-stripped sparse-index URL: `https` scheme, no userinfo, and
/// (for a `WorkspaceDeclared` candidate) a host the live
/// [`deps_core::net_policy::RegistryAccessPolicy`] allows.
///
/// Validated at construction so an invalid or unsafe URL (`http://`, a scheme other than
/// `sparse+https`, a `user:pass@` component, or a workspace-declared host the policy blocks)
/// can never reach a network call — this is SSRF-adjacent input, since a workspace file
/// controls a network destination (spec NFR-002, plan-1b §1.1-§1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegistryIndex {
    url: url::Url,
    /// This candidate's [`IndexTrust`] tier, carried alongside the validated URL so a
    /// consumer (issue #455's [`crate::sparse::SparseIndexClient`] fail-closed auth gate, C2;
    /// [`crate::registry::CargoRegistry::register_alternate`]'s trust fold, C3) never needs a
    /// second, disconnected argument that could drift from the tier this URL was actually
    /// validated under.
    trust: IndexTrust,
}

/// Why a candidate index URL failed [`RegistryIndex::new`]'s validation.
///
/// An alias of the shared [`deps_core::net_policy::IndexUrlError`] — see that type's docs
/// for the variants and their wording.
pub use deps_core::net_policy::IndexUrlError as RegistryIndexError;

impl RegistryIndex {
    /// Validates and wraps `raw` — a `registry-index` manifest value, a
    /// `.cargo/config.toml` `[registries.<name>].index` value, or a `[source.<name>]
    /// registry` value, either optionally prefixed with `sparse+`.
    ///
    /// `trust` states whose input `raw` is; for [`IndexTrust::WorkspaceDeclared`], `policy`'s
    /// current [`deps_core::net_policy::WorkspaceRegistryAccess`] setting is consulted — a
    /// [`IndexTrust::Trusted`] candidate is never policy-checked at all, since it is the
    /// user's own `$CARGO_HOME` configuration, not something a cloned repository controls.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryIndexError`] if `raw` does not parse as a URL, is not `https`,
    /// carries a userinfo component, or (for a `WorkspaceDeclared` candidate) resolves to a
    /// host class the current policy blocks.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cargo::config::{IndexTrust, RegistryIndex};
    /// use deps_core::net_policy::RegistryAccessPolicy;
    ///
    /// let policy = RegistryAccessPolicy::default();
    /// assert!(
    ///     RegistryIndex::new("sparse+https://index.mycorp.dev", IndexTrust::Trusted, &policy)
    ///         .is_ok()
    /// );
    /// assert!(
    ///     RegistryIndex::new("http://index.mycorp.dev", IndexTrust::Trusted, &policy).is_err()
    /// );
    /// assert!(
    ///     RegistryIndex::new(
    ///         "https://user:pass@index.mycorp.dev",
    ///         IndexTrust::Trusted,
    ///         &policy
    ///     )
    ///     .is_err()
    /// );
    /// ```
    pub fn new(
        raw: &str,
        trust: IndexTrust,
        policy: &RegistryAccessPolicy,
    ) -> Result<Self, RegistryIndexError> {
        let stripped = raw.strip_prefix("sparse+").unwrap_or(raw);
        let gate = match trust {
            IndexTrust::Trusted => PolicyGate::Skip,
            IndexTrust::WorkspaceDeclared => PolicyGate::Enforce(policy),
        };
        let url = validate_index_url(stripped, stripped, "cargo", gate)?;
        Ok(Self { url, trust })
    }

    /// Wraps a compile-time-known-safe literal (e.g. crates.io's own sparse index base),
    /// bypassing [`IndexTrust`]/policy entirely — equivalent to [`Self::new`] with
    /// [`IndexTrust::Trusted`], since a `Trusted` candidate is never policy-checked.
    ///
    /// `pub(crate)` — for a literal known at compile time, not a workspace-provenance value.
    ///
    /// # Panics
    ///
    /// Panics if `raw` fails [`Self::new`]'s validation. Covered by a unit test so this
    /// panic is unreachable in practice.
    #[must_use]
    pub(crate) fn builtin(raw: &'static str) -> Self {
        let policy = RegistryAccessPolicy::default();
        Self::new(raw, IndexTrust::Trusted, &policy).unwrap_or_else(|error| {
            panic!("builtin registry index {raw:?} failed validation: {error}")
        })
    }

    /// The validated URL as a string, with no trailing slash guarantee either way (callers
    /// splicing a path onto this must trim as needed — see `sparse::sparse_index_url`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// The [`IndexTrust`] tier this index was validated under.
    #[must_use]
    pub const fn trust(&self) -> IndexTrust {
        self.trust
    }
}

impl std::fmt::Display for RegistryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One resolved `[registries.<name>]` entry.
#[derive(Debug, Clone)]
pub struct ResolvedRegistryEntry {
    /// The validated, fetchable index URL.
    pub index: RegistryIndex,
    /// The bearer token to attach to requests against `index`, if any. `Some` only when
    /// `provenance` is [`Provenance::CargoHome`] — see the module-level security-model
    /// docs for why this is a structural, not runtime, guarantee.
    pub auth: Option<AuthToken>,
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
    /// Aliases whose resolution failed *specifically* because the current
    /// [`deps_core::net_policy::RegistryAccessPolicy`] blocked the candidate host (spec
    /// #443, plan-1b §1.7) — as opposed to "no matching config entry" or any other
    /// validation failure. Surfaced by `crate::parser::resolve_alternate_registries` as a
    /// positional diagnostic on the offending dependency's line.
    blocked: HashMap<String, HostClass>,
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
    pub(crate) fn blocked_class(&self, alias: &str) -> Option<HostClass> {
        self.blocked.get(alias).copied()
    }
}

/// Where a `[source.crates-io] replace-with` chain resolved to, for plain (`Registry`-sourced)
/// dependencies (spec FR-005/FR-006/FR-007).
#[derive(Debug, Clone, PartialEq)]
pub enum SourceReplacement {
    /// No `[source]` override applies — no `[source.crates-io]` table, a `directory`/
    /// `local-registry`/non-sparse-git terminal (FR-006), a cyclic/unbounded chain
    /// (FR-007), or a terminal that failed [`RegistryIndex::new`]'s validation/policy gate.
    /// Plain dependencies keep resolving against crates.io, unchanged from today.
    None,
    /// The chain terminated at a `sparse+https://` index (FR-005).
    SparseMirror {
        /// The validated, fetchable mirror index.
        index: RegistryIndex,
        /// The bearer token to attach to requests against `index`, if any — populated only
        /// when the whole chain's [`IndexTrust`] folded to [`IndexTrust::Trusted`] (plan-1b
        /// §1.4's "coupled trust trap" guard): a single workspace-tier link anywhere in the
        /// chain forces this to `None`, even if the terminal itself is a `$CARGO_HOME`
        /// `[registries]` entry carrying a token.
        auth: Option<AuthToken>,
    },
}

/// A raw (unvalidated) `[source.<name>]` table entry, as parsed from one config file —
/// unvalidated because validation ([`RegistryIndex::new`]'s policy gate, in particular)
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
/// [`IndexTrust`] of its own: trust is derived from the [`CachedTier`] the containing file
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
    if deps_core::check_toml_nesting_depth(content, deps_core::MAX_TOML_NESTING_DEPTH).is_err() {
        tracing::warn!("skipping [source] tables: nesting depth exceeds maximum");
        return out;
    }
    let Ok(doc) = toml_span::parse(content) else {
        return out;
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
/// happens per parse in [`RegistryIndex::new`], never here (plan-1b §1.5(b)): caching a
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
    if deps_core::check_toml_nesting_depth(content, deps_core::MAX_TOML_NESTING_DEPTH).is_err() {
        tracing::warn!("skipping .cargo/config.toml: nesting depth exceeds maximum");
        return out;
    }
    let Ok(doc) = toml_span::parse(content) else {
        return out;
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
    if deps_core::check_toml_nesting_depth(content, deps_core::MAX_TOML_NESTING_DEPTH).is_err() {
        tracing::warn!("skipping $CARGO_HOME/config.toml: nesting depth exceeds maximum");
        return out;
    }
    let Ok(doc) = toml_span::parse(content) else {
        return out;
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
/// [`RegistryIndex::new`] validation, and `[source]` chain walking all run **per parse**
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

/// `$CARGO_HOME/config.toml`'s path, or `None` if `$CARGO_HOME` is not set.
///
/// Deliberately reads only the `CARGO_HOME` environment variable — no fallback to
/// `$HOME`/`%USERPROFILE%` when it is unset (spec FR-004), and no `dirs`/`home` crate
/// dependency added to compute one.
#[must_use]
pub fn cargo_home_config_path() -> Option<PathBuf> {
    cargo_home_config_path_with_env(|name| std::env::var_os(name))
}

/// [`cargo_home_config_path`], but reading the environment through `env` instead of
/// [`std::env::var_os`] directly — lets tests inject a fake environment instead of
/// mutating the real (`unsafe`-only, since Rust 2024) process environment.
fn cargo_home_config_path_with_env(
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    env("CARGO_HOME").map(|home| PathBuf::from(home).join("config.toml"))
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
    cargo_home_config_path: Option<&Path>,
    config_cache: &ConfigFileCache,
) -> LoadedTiers {
    // A project living under `$HOME` (the default `CARGO_HOME=~/.cargo` layout) has
    // `$HOME` as an ancestor directory, so the workspace-tier ancestor walk finds
    // `~/.cargo/config.toml` too — the *same file* as `$CARGO_HOME/config.toml`. Left
    // uncompared, that file would be double-counted as a workspace-tier entry, which wins
    // outright over the real `$CARGO_HOME` tier and silently drops its token: the registry
    // still resolves, just unauthenticated, so the bug looks like success. Comparing
    // canonicalized paths (not just string equality) also catches a symlinked
    // `$CARGO_HOME`.
    let cargo_home_canonical = cargo_home_config_path.and_then(|p| std::fs::canonicalize(p).ok());

    let workspace = workspace_config_paths
        .iter()
        .filter(|path| {
            std::fs::canonicalize(path).ok().as_deref() != cargo_home_canonical.as_deref()
        })
        .filter_map(|path| config_cache.get_or_parse_workspace(path))
        .collect();

    let cargo_home =
        cargo_home_config_path.and_then(|path| config_cache.get_or_parse_cargo_home(path));

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
/// `WorkspaceDeclared` [`RegistryIndex`] this call constructs.
///
/// # Precedence
///
/// For one alias (or the `[source]` chain): the closest workspace `.cargo/config.toml`
/// entry wins outright — if it resolves, the `$CARGO_HOME` tier (config file and
/// environment variables alike) is never consulted for that alias at all. This is a
/// deliberate divergence from Cargo's own env-beats-all-config-files precedence: since
/// environment variables and `$CARGO_HOME/config.toml` are folded into one
/// `$CARGO_HOME`-provenance tier here, an environment variable can never resurrect a
/// credential for an alias a workspace file has shadowed (spec FR-009/US-004) — see the
/// module-level security-model docs.
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
    cargo_home_config_path: Option<&Path>,
    config_cache: &ConfigFileCache,
    policy: &RegistryAccessPolicy,
) -> (CargoConfig, SourceReplacement) {
    resolve_with_env(
        referenced_aliases,
        workspace_config_paths,
        cargo_home_config_path,
        config_cache,
        policy,
        &|name| std::env::var(name).ok(),
    )
}

/// [`resolve`], but reading environment variables through `env` instead of
/// [`std::env::var`] directly — lets tests inject a fake environment instead of mutating
/// the real process environment (this workspace forbids `unsafe`, and Rust 2024 made
/// `std::env::set_var`/`remove_var` `unsafe fn`s, so a test cannot do that mutation at
/// all). Production callers always go through [`resolve`].
fn resolve_with_env(
    referenced_aliases: &HashSet<String>,
    workspace_config_paths: &[PathBuf],
    cargo_home_config_path: Option<&Path>,
    config_cache: &ConfigFileCache,
    policy: &RegistryAccessPolicy,
    env: &dyn Fn(&str) -> Option<String>,
) -> (CargoConfig, SourceReplacement) {
    let tiers = load_tiers(workspace_config_paths, cargo_home_config_path, config_cache);

    let registries = resolve_registries(referenced_aliases, &tiers, policy, env);
    let source_replacement = resolve_source_chain(&tiers, policy);

    (registries, source_replacement)
}

fn resolve_registries(
    referenced_aliases: &HashSet<String>,
    tiers: &LoadedTiers,
    policy: &RegistryAccessPolicy,
    env: &dyn Fn(&str) -> Option<String>,
) -> CargoConfig {
    // FR-015: two distinct alias spellings deriving the same env-var name (e.g.
    // "my-corp"/"my_corp" both -> CARGO_REGISTRIES_MY_CORP_INDEX) must not let either one
    // pick up an env override meant for the other. Detected once, up front, over the whole
    // referenced-alias set, rather than per-alias — a per-alias check would have nothing to
    // compare against.
    let mut env_name_to_aliases: HashMap<String, Vec<&String>> = HashMap::new();
    for alias in referenced_aliases {
        env_name_to_aliases
            .entry(env_var_name(alias, "INDEX"))
            .or_default()
            .push(alias);
    }
    let env_collided: HashSet<&str> = env_name_to_aliases
        .values()
        .filter(|aliases| aliases.len() > 1)
        .flat_map(|aliases| {
            let names: Vec<&str> = aliases.iter().map(|s| s.as_str()).collect();
            // Same as `resolve_alternate_registries`' unresolved-alias WARN (#536): `alias`
            // here is a raw manifest `registry-index`/`registry` value, not a config-file
            // alias name, so it may itself carry `user:pass@` userinfo — redact each entry
            // before logging.
            let redacted: Vec<String> = names.iter().map(|name| redact_userinfo(name)).collect();
            tracing::warn!(
                aliases = ?redacted,
                "two aliases derive the same CARGO_REGISTRIES_*_INDEX/_TOKEN environment \
                 variable name; ignoring the environment override for all of them"
            );
            names
        })
        .collect();

    let mut registries = HashMap::new();
    let mut blocked = HashMap::new();
    for alias in referenced_aliases {
        if let Some(entry) = tiers.workspace.iter().find_map(|file| match &file.tier {
            CachedTier::Workspace(map) => map.get(alias).map(|raw_index| (raw_index, file)),
            CachedTier::CargoHome(_) => None,
        }) {
            let (raw_index, _file) = entry;
            match RegistryIndex::new(raw_index, IndexTrust::WorkspaceDeclared, policy) {
                Ok(index) => {
                    registries.insert(
                        alias.clone(),
                        ResolvedRegistryEntry {
                            index,
                            auth: None,
                            provenance: Provenance::Workspace,
                        },
                    );
                }
                Err(RegistryIndexError::BlockedHost { class }) => {
                    blocked.insert(alias.clone(), class);
                }
                Err(error) => {
                    tracing::warn!(alias, %error, "registry index failed validation");
                }
            }
            continue;
        }

        if let Some(entry) = resolve_cargo_home_tier(
            alias,
            tiers.cargo_home.as_deref(),
            !env_collided.contains(alias.as_str()),
            policy,
            env,
        ) {
            registries.insert(alias.clone(), entry);
        }
    }

    CargoConfig {
        registries,
        blocked,
    }
}

/// Resolves one alias against the `$CARGO_HOME` tier: an environment-variable override
/// first (when `env_allowed`), then `$CARGO_HOME/config.toml`'s own entry.
fn resolve_cargo_home_tier(
    alias: &str,
    cargo_home_file: Option<&ParsedConfigFile>,
    env_allowed: bool,
    policy: &RegistryAccessPolicy,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<ResolvedRegistryEntry> {
    let cargo_home_map = cargo_home_file.and_then(|file| match &file.tier {
        CachedTier::CargoHome(map) => Some(map),
        CachedTier::Workspace(_) => None,
    });

    if env_allowed && let Some(index_override) = env(&env_var_name(alias, "INDEX")) {
        match RegistryIndex::new(&index_override, IndexTrust::Trusted, policy) {
            Ok(index) => {
                let auth = env(&env_var_name(alias, "TOKEN"))
                    .map(AuthToken::new)
                    .or_else(|| {
                        cargo_home_map
                            .and_then(|map| map.get(alias))
                            .and_then(|(_, token)| token.clone())
                    });
                return Some(ResolvedRegistryEntry {
                    index,
                    auth,
                    provenance: Provenance::CargoHome,
                });
            }
            Err(error) => {
                tracing::warn!(alias, %error, "CARGO_REGISTRIES_*_INDEX environment override failed validation");
            }
        }
    }

    let (raw_index, mut auth) = cargo_home_map.and_then(|map| map.get(alias)).cloned()?;
    if env_allowed && let Some(token_override) = env(&env_var_name(alias, "TOKEN")) {
        auth = Some(AuthToken::new(token_override));
    }
    match RegistryIndex::new(&raw_index, IndexTrust::Trusted, policy) {
        Ok(index) => Some(ResolvedRegistryEntry {
            index,
            auth,
            provenance: Provenance::CargoHome,
        }),
        Err(error) => {
            tracing::warn!(alias, %error, "registry index failed validation");
            None
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
/// workspace tier first, then `$CARGO_HOME`.
///
/// Returns **only** the raw index string and its tier's [`IndexTrust`] — never the
/// `$CARGO_HOME` tier's token, so a workspace-tier chain crossing into a `[registries]`
/// entry has no way to carry that entry's credential forward even by accident (plan-1b
/// §1.4's "coupled trust trap" guard, critic N3): the drop is enforced by this function's
/// signature, not by a caller remembering to discard it.
fn lookup_raw_registry_index<'a>(
    id: &str,
    tiers: &'a LoadedTiers,
) -> Option<(&'a str, IndexTrust)> {
    for file in &tiers.workspace {
        if let CachedTier::Workspace(map) = &file.tier
            && let Some(raw) = map.get(id)
        {
            return Some((raw.as_str(), IndexTrust::WorkspaceDeclared));
        }
    }
    if let Some(file) = &tiers.cargo_home
        && let CachedTier::CargoHome(map) = &file.tier
        && let Some((raw, _token)) = map.get(id)
    {
        return Some((raw.as_str(), IndexTrust::Trusted));
    }
    None
}

/// Looks `id` up as a `[registries]` alias in the `$CARGO_HOME` tier *specifically for its
/// token* — used only once a chain's overall trust has already folded to
/// [`IndexTrust::Trusted`], to re-derive the credential to attach rather than ever reading
/// one off [`lookup_raw_registry_index`]'s result (plan-1b §1.4's coupled-trust-trap guard).
fn cargo_home_token_for(tiers: &LoadedTiers, id: &str) -> Option<AuthToken> {
    let file = tiers.cargo_home.as_deref()?;
    let CachedTier::CargoHome(map) = &file.tier else {
        return None;
    };
    map.get(id).and_then(|(_, token)| token.clone())
}

/// Resolves the `[source.crates-io] replace-with` chain (spec FR-005/006/007, plan-1b §1.4).
///
/// Two-stage id resolution at every hop: the merged `[source]` tables first, then (stage 1,
/// critic S4) the merged `[registries]` tables via [`lookup_raw_registry_index`] — a
/// `[registries]` hit is terminal by construction, since a `[registries]` entry has no
/// `replace-with` of its own.
fn resolve_source_chain(tiers: &LoadedTiers, policy: &RegistryAccessPolicy) -> SourceReplacement {
    let mut current_id = "crates-io".to_string();
    let mut visited: HashSet<String> = HashSet::new();
    let mut chain_trust = IndexTrust::Trusted;

    for _hop in 0..MAX_SOURCE_REPLACEMENT_HOPS {
        if !visited.insert(current_id.clone()) {
            tracing::warn!(
                id = %current_id,
                "[source] replace-with chain is cyclic; leaving crates-io unresolved"
            );
            return SourceReplacement::None;
        }

        let found_source = tiers
            .workspace
            .iter()
            .find_map(|file| {
                file.sources
                    .get(&current_id)
                    .map(|entry| (entry, IndexTrust::WorkspaceDeclared))
            })
            .or_else(|| {
                tiers
                    .cargo_home
                    .as_deref()
                    .and_then(|file| file.sources.get(&current_id))
                    .map(|entry| (entry, IndexTrust::Trusted))
            });

        if let Some((entry, entry_trust)) = found_source {
            chain_trust = chain_trust.min(entry_trust);
            // Cargo resolves `replace-with` **before** consulting the table's own kind
            // (critic S2): `[source.crates-io]` carries an implicit builtin definition, and
            // an explicit `registry =`/`directory =`/etc. alongside `replace-with` does not
            // disable the replacement — the shape every large public mirror's setup
            // instructions publish verbatim (`[source.crates-io] registry = "…git-index…"`
            // *and* `replace-with = "mirror"` in the same table). Checking `kind` first, as
            // an earlier revision of this function did, silently dropped the replacement for
            // exactly that case.
            if let Some(next_id) = &entry.replace_with {
                current_id = next_id.clone();
                continue;
            }
            match &entry.kind {
                Some(SourceKind::SparseRegistry { raw }) => {
                    return finalize_source_replacement(
                        raw,
                        chain_trust,
                        &current_id,
                        tiers,
                        policy,
                    );
                }
                Some(SourceKind::NonSparse) | None => {
                    return SourceReplacement::None;
                }
            }
        }

        // Stage 1 (critic S4): not declared as a `[source]` entry — try a `[registries]`
        // crossover before giving up on this id.
        if let Some((raw_index, crossover_trust)) = lookup_raw_registry_index(&current_id, tiers) {
            chain_trust = chain_trust.min(crossover_trust);
            if raw_index.starts_with("sparse+") {
                return finalize_source_replacement(
                    raw_index,
                    chain_trust,
                    &current_id,
                    tiers,
                    policy,
                );
            }
            return SourceReplacement::None;
        }

        // Unknown id (most commonly: no `[source.crates-io]` table declared at all, the
        // common no-`[source]`-section case).
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
    chain_trust: IndexTrust,
    terminal_id: &str,
    tiers: &LoadedTiers,
    policy: &RegistryAccessPolicy,
) -> SourceReplacement {
    match RegistryIndex::new(raw, chain_trust, policy) {
        Ok(index) => {
            // Never read a token off the `[registries]` crossover lookup itself (see
            // `lookup_raw_registry_index`'s docs) — re-derive it here, gated purely on
            // whether the *whole chain* folded to `Trusted` (plan-1b §1.4).
            let auth = if chain_trust == IndexTrust::Trusted {
                cargo_home_token_for(tiers, terminal_id)
            } else {
                None
            };
            SourceReplacement::SparseMirror { index, auth }
        }
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
pub fn referenced_aliases(dependencies: &[crate::types::ParsedDependency]) -> HashSet<String> {
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
    use deps_core::net_policy::WorkspaceRegistryAccess;
    use std::assert_matches;

    fn public_only_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly)
    }

    fn all_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)
    }

    fn off_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off)
    }

    #[test]
    fn test_registry_index_strips_sparse_prefix() {
        let policy = all_policy();
        let index = RegistryIndex::new(
            "sparse+https://index.mycorp.dev",
            IndexTrust::Trusted,
            &policy,
        )
        .unwrap();
        assert_eq!(index.as_str(), "https://index.mycorp.dev/");
    }

    #[test]
    fn test_registry_index_rejects_http() {
        let policy = all_policy();
        assert_matches!(
            RegistryIndex::new("http://index.mycorp.dev", IndexTrust::Trusted, &policy),
            Err(RegistryIndexError::NotHttps(_))
        );
    }

    #[test]
    fn test_registry_index_rejects_userinfo() {
        let policy = all_policy();
        assert_matches!(
            RegistryIndex::new(
                "https://user:pass@index.mycorp.dev",
                IndexTrust::Trusted,
                &policy
            ),
            Err(RegistryIndexError::UserInfoPresent)
        );
    }

    #[test]
    fn test_registry_index_rejects_bare_username() {
        let policy = all_policy();
        assert_matches!(
            RegistryIndex::new(
                "https://user@index.mycorp.dev",
                IndexTrust::Trusted,
                &policy
            ),
            Err(RegistryIndexError::UserInfoPresent)
        );
    }

    #[test]
    fn test_registry_index_rejects_invalid_url() {
        let policy = all_policy();
        assert_matches!(
            RegistryIndex::new("not a url", IndexTrust::Trusted, &policy),
            Err(RegistryIndexError::InvalidUrl(_))
        );
    }

    /// S1: a userinfo-bearing `index = "…"` value that also fails `Url::parse` for an
    /// unrelated reason (an invalid port here) lands in `RegistryIndexError::InvalidUrl`, not
    /// `UserInfoPresent` — every call site here logs this error via `tracing::warn!(alias,
    /// %error, …)`, so the credential must never survive into `InvalidUrl`'s payload or its
    /// `Display`. Fixed once inside `deps_core::net_policy::validate_index_url`, which every
    /// `RegistryIndex::new` call routes through — no separate redaction needed here.
    #[test]
    fn test_registry_index_invalid_url_error_redacts_userinfo() {
        let policy = all_policy();
        let err = RegistryIndex::new(
            "https://user:hunter2@index.mycorp.dev:99999",
            IndexTrust::Trusted,
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
            RegistryIndex::new("https://index.mycorp.dev", IndexTrust::Trusted, &policy).is_ok()
        );
    }

    #[test]
    fn test_registry_index_builtin_crates_io() {
        // Also the coverage that makes `builtin`'s panic path unreachable in practice.
        let index = RegistryIndex::builtin("https://index.crates.io");
        assert_eq!(index.as_str(), "https://index.crates.io/");
    }

    // Issue #455, test-plan item 11: `RegistryIndex::trust()` round-trips `new`'s argument.
    #[test]
    fn test_registry_index_trust_round_trips_new_argument() {
        let policy = all_policy();
        let trusted =
            RegistryIndex::new("https://index.mycorp.dev", IndexTrust::Trusted, &policy).unwrap();
        assert_eq!(trusted.trust(), IndexTrust::Trusted);

        let workspace_declared = RegistryIndex::new(
            "https://index.mycorp.dev",
            IndexTrust::WorkspaceDeclared,
            &policy,
        )
        .unwrap();
        assert_eq!(workspace_declared.trust(), IndexTrust::WorkspaceDeclared);
    }

    // Issue #455, test-plan item 11: `builtin` is always `Trusted`.
    #[test]
    fn test_registry_index_builtin_is_trusted() {
        let index = RegistryIndex::builtin("https://index.crates.io");
        assert_eq!(index.trust(), IndexTrust::Trusted);
    }

    /// Policy gate matrix (plan-1b §4): every `WorkspaceRegistryAccess` x `IndexTrust`
    /// combination against a metadata-IP URL. `Trusted` is always allowed (it is the
    /// user's own `$CARGO_HOME` config, never policy-checked); `WorkspaceDeclared` follows
    /// the policy exactly.
    #[test]
    fn test_registry_index_trusted_metadata_ip_always_allowed() {
        for policy in [off_policy(), public_only_policy(), all_policy()] {
            assert!(
                RegistryIndex::new("https://169.254.169.254/", IndexTrust::Trusted, &policy)
                    .is_ok(),
                "a Trusted candidate must never be policy-checked"
            );
        }
    }

    #[test]
    fn test_registry_index_workspace_declared_metadata_ip_blocked_under_public_only() {
        let policy = public_only_policy();
        assert_matches!(
            RegistryIndex::new(
                "https://169.254.169.254/",
                IndexTrust::WorkspaceDeclared,
                &policy
            ),
            Err(RegistryIndexError::BlockedHost { .. })
        );
    }

    #[test]
    fn test_registry_index_workspace_declared_global_allowed_under_public_only() {
        let policy = public_only_policy();
        assert!(
            RegistryIndex::new(
                "https://index.mycorp.dev",
                IndexTrust::WorkspaceDeclared,
                &policy
            )
            .is_ok()
        );
    }

    #[test]
    fn test_registry_index_workspace_declared_blocked_under_off() {
        let policy = off_policy();
        assert_matches!(
            RegistryIndex::new(
                "https://index.mycorp.dev",
                IndexTrust::WorkspaceDeclared,
                &policy
            ),
            Err(RegistryIndexError::BlockedHost { .. })
        );
    }

    #[test]
    fn test_registry_index_workspace_declared_rfc1918_allowed_under_all() {
        let policy = all_policy();
        assert!(
            RegistryIndex::new("https://10.0.0.1/", IndexTrust::WorkspaceDeclared, &policy).is_ok()
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
        assert_eq!(token.as_ref().unwrap().expose_secret(), "secret-token");
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
        assert!(cargo_home_config_path_with_env(|_| None).is_none());
    }

    #[test]
    fn test_cargo_home_config_path_some_when_set() {
        let path = cargo_home_config_path_with_env(|name| {
            (name == "CARGO_HOME").then(|| std::ffi::OsString::from("/home/user/.cargo"))
        });
        assert_eq!(path, Some(PathBuf::from("/home/user/.cargo/config.toml")));
    }

    #[test]
    fn test_resolve_workspace_wins_over_cargo_home() {
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
            Some(&cargo_home.path().join("config.toml")),
            &cache,
            &policy,
        );

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://workspace.example/");
        assert!(
            entry.auth.is_none(),
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
            Some(&cargo_home_config),
            &cache,
            &policy,
        );

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://real.example/");
        assert_eq!(entry.provenance, Provenance::CargoHome);
        assert_eq!(
            entry.auth.as_ref().map(AuthToken::expose_secret),
            Some("real-token"),
            "the CARGO_HOME token must not be lost just because the project lives \
             under $HOME"
        );
    }

    #[test]
    fn test_resolve_falls_back_to_cargo_home_when_no_workspace_entry() {
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
            Some(&cargo_home.path().join("config.toml")),
            &cache,
            &policy,
        );

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://real.example/");
        assert_eq!(entry.auth.as_ref().unwrap().expose_secret(), "real-token");
        assert_eq!(entry.provenance, Provenance::CargoHome);
    }

    #[test]
    fn test_resolve_unconfigured_alias_stays_unresolved() {
        let aliases: HashSet<String> = std::iter::once("unknown".to_string()).collect();
        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve(&aliases, &[], None, &cache, &policy);
        assert!(config.get("unknown").is_none());
    }

    #[test]
    fn test_resolve_env_var_index_override() {
        let aliases: HashSet<String> = std::iter::once("env-only-corp".to_string()).collect();
        let env = |name: &str| match name {
            "CARGO_REGISTRIES_ENV_ONLY_CORP_INDEX" => {
                Some("sparse+https://env.example".to_string())
            }
            "CARGO_REGISTRIES_ENV_ONLY_CORP_TOKEN" => Some("env-token".to_string()),
            _ => None,
        };

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (config, _) = resolve_with_env(&aliases, &[], None, &cache, &policy, &env);
        let entry = config.get("env-only-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://env.example/");
        assert_eq!(entry.auth.as_ref().unwrap().expose_secret(), "env-token");
        assert_eq!(entry.provenance, Provenance::CargoHome);
    }

    /// FR-015: two distinct alias spellings deriving the same env-var name must both be
    /// skipped for env resolution, not have one arbitrarily win.
    #[test]
    fn test_resolve_env_var_name_collision_disables_both() {
        let aliases: HashSet<String> = ["my-corp".to_string(), "my_corp".to_string()]
            .into_iter()
            .collect();
        let env = |name: &str| {
            (name == "CARGO_REGISTRIES_MY_CORP_INDEX")
                .then(|| "sparse+https://ambiguous.example".to_string())
        };

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
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.github]\nindex = \"sparse+https://attacker.example\"\n",
        )
        .unwrap();

        let env = |name: &str| {
            (name == "CARGO_REGISTRIES_GITHUB_TOKEN").then(|| "legitimate-token".to_string())
        };

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
        assert_eq!(entry.index.as_str(), "https://attacker.example/");
        assert!(
            entry.auth.is_none(),
            "the legitimate env token must never attach to the attacker-controlled index"
        );
    }

    #[test]
    fn test_referenced_aliases_collects_custom_registry_urls() {
        use crate::types::{DependencySection, ParsedDependency};
        use deps_core::parser::DependencySource;
        use tower_lsp_server::ls_types::Range;

        let deps = vec![
            ParsedDependency {
                name: "a".into(),
                name_range: Range::default(),
                version_req: None,
                version_range: None,
                features: vec![],
                features_range: None,
                source: DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
                section: DependencySection::Dependencies,
            },
            ParsedDependency {
                name: "b".into(),
                name_range: Range::default(),
                version_req: None,
                version_range: None,
                features: vec![],
                features_range: None,
                source: DependencySource::Registry,
                section: DependencySection::Dependencies,
            },
        ];

        let aliases = referenced_aliases(&deps);
        assert_eq!(aliases.len(), 1);
        assert!(aliases.contains("my-corp"));
    }

    // ---- ConfigFileCache ----

    #[test]
    fn test_config_file_cache_hit_reuses_parsed_arc_without_reparsing() {
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
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.metadata]\nindex = \"https://169.254.169.254\"\n",
        )
        .unwrap();

        let cache = ConfigFileCache::new();
        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::All);
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
            SourceReplacement::SparseMirror { index, auth } => {
                assert_eq!(index.as_str(), "https://mirror.example/");
                assert!(auth.is_none());
            }
            SourceReplacement::None => panic!("expected a resolved mirror"),
        }
    }

    #[test]
    fn test_source_chain_two_hops() {
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

    #[test]
    fn test_source_chain_terminal_blocked_by_policy() {
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
                assert_eq!(index.as_str(), "https://index.mycorp.dev/");
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
                assert_eq!(index.as_str(), "https://mirror.example/index/");
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
                    "https://b.example/index/",
                    "replace-with must win over the table's own sparse `registry` value"
                );
            }
            SourceReplacement::None => panic!("expected the replace-with target to resolve"),
        }
    }

    /// The named regression test for the coupled-trust trap (critic N3): a workspace-tier
    /// `replace-with` crossing into a `$CARGO_HOME` `[registries]` entry that carries a
    /// token must resolve with `auth: None` — the workspace-tier link in the chain must
    /// never let a `$CARGO_HOME` credential ride along.
    #[test]
    fn test_source_chain_coupled_trust_trap_workspace_crossover_never_carries_cargo_home_token() {
        let root = tempfile::tempdir().unwrap();
        let workspace_path = write_config(
            root.path(),
            "[source.crates-io]\nreplace-with = \"my-corp\"\n",
        );

        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://index.mycorp.dev\"\ntoken = \"leaked-if-buggy\"\n",
        )
        .unwrap();

        let cache = ConfigFileCache::new();
        let policy = all_policy();
        let (_, replacement) = resolve(
            &HashSet::new(),
            &[workspace_path],
            Some(&cargo_home.path().join("config.toml")),
            &cache,
            &policy,
        );

        match replacement {
            SourceReplacement::SparseMirror { index, auth } => {
                assert_eq!(index.as_str(), "https://index.mycorp.dev/");
                assert!(
                    auth.is_none(),
                    "a workspace-tier chain link must never let a $CARGO_HOME token ride along"
                );
            }
            SourceReplacement::None => panic!("expected the mirror to resolve, just without auth"),
        }
    }

    /// The positive counterpart: when the *whole* chain is `$CARGO_HOME`-declared, the
    /// terminal `[registries]` entry's token is legitimately attached.
    #[test]
    fn test_source_chain_fully_trusted_chain_attaches_cargo_home_token() {
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
            Some(&cargo_home.path().join("config.toml")),
            &cache,
            &policy,
        );

        match replacement {
            SourceReplacement::SparseMirror { auth, .. } => {
                assert_eq!(
                    auth.as_ref().map(AuthToken::expose_secret),
                    Some("real-token")
                );
            }
            SourceReplacement::None => panic!("expected the fully-trusted chain to resolve"),
        }
    }

    #[test]
    fn test_source_chain_no_source_section_resolves_none() {
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
