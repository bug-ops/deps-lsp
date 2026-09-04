//! Private/custom PyPI index resolution — `--index-url`/`--extra-index-url`
//! (`requirements.txt`), Poetry `[[tool.poetry.source]]`, and uv
//! `[tool.uv.index]`/`[tool.uv.sources]`.
//!
//! # Security model (read before touching this module)
//!
//! A `requirements.txt`/`pyproject.toml` index declaration is attacker-controlled the moment a
//! hostile repository is cloned and opened — this LSP parses on file open, before any build
//! ever runs. Phase 1 carries no authentication at all (spec Out of Scope: no URL userinfo, no
//! `keyring`/`.netrc`), which closes the credential half of the threat model this module would
//! otherwise have to solve, but two things still apply:
//!
//! - **No credential-shaped value is ever parsed.** [`PypiIndexUrl::new`] rejects any URL
//!   carrying `username()`/`password()` outright (FR-006/FR-011) — there is no expansion step
//!   for PyPI config (unlike npm's `${VAR}`), so [`InvalidEntry::raw`] and every
//!   `tracing::warn!` here name the as-written value with any embedded userinfo stripped first
//!   (see `redact_userinfo`) — the raw value is otherwise preserved so a warning or a
//!   [`DependencySource::CustomRegistry`] naming an unresolved primary/named source still shows
//!   the user what they actually typed, minus the credential.
//! - **FR-005's resolution order is the load-bearing security invariant of this whole
//!   feature.** Case (a) (an explicit `--index-url`/Poetry primary/uv `default`): the
//!   explicit primary is checked first, then extras — a deliberate user choice, no
//!   disclosure risk. Case (b) (no explicit primary, extras only): declared extras are
//!   checked **before** the implicit public `pypi.org` fallback, never the reverse — this is
//!   what stops a private package's name from being sent to `pypi.org` before the user's own
//!   declared index has had a chance, and what stops a same-named public package from
//!   silently shadowing a private one. See [`PypiIndexConfig::resolve_source_for`] and
//!   [`ResolvedChain`]'s docs.
//!
//! See `specs/033-pypi-private-index-support/spec.md` FR-001–FR-014 and
//! `specs/033-pypi-private-index-support/plan.md` §1/§3 for the design review this module
//! implements.

use std::collections::HashMap;

use deps_core::net_policy::{
    PolicyGate, RegistryAccessPolicy, redact_userinfo, validate_index_url,
};
use deps_core::parser::DependencySource;

/// Why a candidate index URL failed [`PypiIndexUrl::new`]'s validation.
///
/// An alias of the shared [`deps_core::net_policy::IndexUrlError`] — see that type's docs
/// for the variants and their wording.
pub use deps_core::net_policy::IndexUrlError as PypiIndexUrlError;

/// A validated, normalized, https-only PyPI-protocol index URL with no embedded userinfo.
///
/// Mirrors `deps_npm::config::NpmRegistryIndex` (see FR-006/FR-011); kept `deps-pypi`-local
/// rather than promoted to `deps-core` per this spec's Open Questions (consolidate only once a
/// third near-identical type makes the duplication concrete).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PypiIndexUrl {
    /// The validated URL, normalized by stripping a trailing `/` — matches
    /// `simple_api_url`'s existing `{base}/{name}/` join convention (PEP 503).
    normalized: String,
}

impl PypiIndexUrl {
    /// Validates and normalizes `raw` against `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`PypiIndexUrlError`] if `raw` does not parse as a URL, is not `https` (outside
    /// the `cfg(test)`/`test-util` loopback carve-out), carries a userinfo component, or
    /// resolves to a host class the current `policy` blocks.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use deps_pypi::config::PypiIndexUrl;
    ///
    /// let policy = RegistryAccessPolicy::default();
    /// assert!(PypiIndexUrl::new("https://pypi.mycorp.example/simple", &policy).is_ok());
    /// assert!(PypiIndexUrl::new("http://pypi.mycorp.example/simple", &policy).is_err());
    /// assert!(PypiIndexUrl::new("https://user:pass@pypi.mycorp.example", &policy).is_err());
    /// ```
    pub fn new(raw: &str, policy: &RegistryAccessPolicy) -> Result<Self, PypiIndexUrlError> {
        let url = validate_index_url(raw, raw, "pypi", PolicyGate::Enforce(policy))?;
        let normalized = url.as_str().trim_end_matches('/').to_string();
        Ok(Self { normalized })
    }

    /// The normalized index URL. Never carries a trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }
}

impl std::fmt::Display for PypiIndexUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A present-but-unusable index entry — an invalid URL, a policy-blocked host, or a
/// well-formed-but-non-https/userinfo-bearing value.
///
/// Carries the raw value as written, **with any embedded userinfo redacted** (M1 fix — see
/// [`deps_core::net_policy::redact_userinfo`]), so [`PypiIndexConfig::resolve_source_for`] can build
/// [`DependencySource::CustomRegistry`] for an explicit primary/named source, or log a warning
/// naming what the user wrote for a dropped extra, without ever holding or surfacing the
/// credential itself: a `CustomRegistry.url` can reach hover/diagnostics text, and a
/// `UserInfoPresent` rejection is exactly the case where `raw` would otherwise still contain
/// `user:pass@`.
#[derive(Debug, Clone)]
pub struct InvalidEntry {
    /// The raw index value, as written in the source file, with any `user:pass@`/`user@`
    /// userinfo component stripped.
    pub raw: String,
    /// Why it was rejected.
    pub reason: PypiIndexUrlError,
}

/// Validates and normalizes one raw index value, logging a `tracing::warn!` naming the raw
/// value (userinfo redacted — see [`deps_core::net_policy::redact_userinfo`]) on failure.
/// `pub(crate)`: every parser
/// surface (`requirements.rs`, `pyproject.rs`) that discovers a candidate index value calls
/// this before handing the result to a [`PypiIndexConfig`] setter.
pub(crate) fn resolve_entry(
    raw: &str,
    policy: &RegistryAccessPolicy,
) -> Result<PypiIndexUrl, InvalidEntry> {
    PypiIndexUrl::new(raw, policy).map_err(|reason| {
        let redacted = redact_userinfo(raw);
        tracing::warn!(raw = %redacted, %reason, "PyPI index URL failed validation");
        InvalidEntry {
            raw: redacted,
            reason,
        }
    })
}

/// One fully-resolved, ready-to-register routing chain — produced by
/// [`PypiIndexConfig::resolved_chains`], consumed by
/// `PypiRegistry::register_chain`/`register_named_source`.
#[derive(Debug, Clone)]
pub struct ResolvedChain {
    /// Composite identity — becomes both the router's `alternates` map key and the
    /// `DependencySource::AlternateRegistry.index` value for a plain (non-named-source)
    /// dependency.
    ///
    /// For a primary/extras chain (case a/b): an opaque, single-line hashed token produced by
    /// [`deps_core::hash_routing_key`] (`"pypi-chain"`) over the ordered hop strings plus the
    /// [`Self::implicit_public_fallback`] flag — **never** a newline-joined or otherwise
    /// URL-shaped value: `deps-core`'s `AlternateRegistry.index` doc describes this field as
    /// "the resolved index URL" for Cargo/npm, and a value that merely *looks* like a URL
    /// (but isn't one) would violate that contract for any future reader — see plan.md's N6
    /// fix. An explicit chain `[A, B]` and an implicit chain that happens to resolve to the
    /// same hops `[A, B]` plus the fallback flag produce **different** keys (this is what
    /// closes the C2 aliasing defect: two files sharing a primary but differing extras never
    /// collide, and editing a file's extras changes its key on the next reparse).
    ///
    /// For a named-source chain (Poetry `source =`/uv `index =`): the source's own literal
    /// URL, matching Cargo/npm's convention for a single resolved index.
    pub key: String,
    /// Ordered, already-validated hops. Hop 0 becomes the registered client's own
    /// `simple_base`; the rest become its `fallback_chain`. Never empty — see
    /// [`PypiIndexConfig::resolved_chains`]'s zero-hop handling.
    pub hops: Vec<PypiIndexUrl>,
    /// `true` only for a case-(b) chain (spec FR-005(b)) whose final hop is the implicit
    /// public `pypi.org` root, appended at registration time rather than present in
    /// [`Self::hops`] — `PypiRegistry::register_chain` builds that hop itself.
    pub implicit_public_fallback: bool,
}

impl ResolvedChain {
    fn chain(hops: Vec<PypiIndexUrl>, implicit_public_fallback: bool) -> Self {
        let flag = if implicit_public_fallback {
            "true"
        } else {
            "false"
        };
        let key = deps_core::hash_routing_key(
            "pypi-chain",
            hops.iter()
                .map(PypiIndexUrl::as_str)
                .chain(std::iter::once(flag)),
        );
        Self {
            key,
            hops,
            implicit_public_fallback,
        }
    }

    fn named_source(url: PypiIndexUrl) -> Self {
        Self {
            key: url.as_str().to_string(),
            hops: vec![url],
            implicit_public_fallback: false,
        }
    }
}

/// The effective case-(b) hop list (spec FR-005(b)): declared extras, in order, plus a final
/// hop that is either a concrete uv `default = true` index or the implicit public fallback.
struct CaseBChain {
    hops: Vec<PypiIndexUrl>,
    implicit_public_fallback: bool,
}

/// Resolved index configuration for one `requirements.txt`/`pyproject.toml` file.
///
/// Built once per parse (two-pass for `requirements.txt` — see `parser::requirements`'s
/// module doc; single-pass for `pyproject.toml`, whose TOML tree is fully available before any
/// dependency is resolved), consulted per-dependency via [`Self::resolve_source_for`].
#[derive(Debug, Default)]
pub struct PypiIndexConfig {
    /// Explicit `--index-url`, a Poetry `primary`/`default`-priority source (including one
    /// with no `priority` key at all — FR-007), or a Poetry `explicit`/unrecognized-priority
    /// source contributes nothing here. uv **never** populates this field (FR-013's r3
    /// correction) — a pure-uv config always routes through [`Self::case_b_chain`] instead.
    /// `None` when no explicit primary is declared (spec FR-005(b) applies).
    primary: Option<Result<PypiIndexUrl, InvalidEntry>>,
    /// `--extra-index-url` values (declaration order preserved) plus Poetry
    /// `supplemental`/`secondary`-priority sources plus every non-`default`/non-`explicit` uv
    /// `[tool.uv.index]` entry — FR-005's fallback chain. An `Err(InvalidEntry)` here is
    /// dropped (with a warning already logged by [`resolve_entry`]) rather than escalated,
    /// per FR-006's extra-specific rule.
    extras: Vec<Result<PypiIndexUrl, InvalidEntry>>,
    /// uv's `default = true` index, if any (uv permits at most one) — uv's lowest-priority,
    /// last-resort hop, replacing the implicit public fallback in that final slot. `None` for
    /// every non-uv config, and for a uv config that declares no `default` entry (the
    /// implicit public fallback is used instead).
    tail_hop: Option<Result<PypiIndexUrl, InvalidEntry>>,
    /// Poetry `[[tool.poetry.source]]` entries (all priorities, including `explicit`) keyed
    /// by `name`, plus every uv `[tool.uv.index]` entry keyed by its own `name` — consulted
    /// only when a dependency declares `source = "<name>"` (Poetry) or an `index = "<name>"`
    /// uv-sources binding (FR-013), never auto-included in the primary/extras/tail chain.
    named_sources: HashMap<String, Result<PypiIndexUrl, InvalidEntry>>,
}

impl PypiIndexConfig {
    /// An empty config — every dependency resolves to plain [`DependencySource::Registry`],
    /// byte-identical to today (US-004).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// FR-002: sets (overwriting any prior value) the explicit `--index-url`/Poetry
    /// `primary`-equivalent primary. Matches pip's own `argparse` `store` semantics for
    /// `--index-url` (not `append`, unlike `--extra-index-url`) — the last occurrence in a
    /// file wins.
    pub fn set_primary(&mut self, raw: &str, policy: &RegistryAccessPolicy) {
        self.primary = Some(resolve_entry(raw, policy));
    }

    /// Like [`Self::set_primary`], but for a caller that already resolved (or is re-using an
    /// already-resolved) candidate — avoids re-validating and double-logging a value that
    /// must also be reachable as a named source (Poetry/uv).
    ///
    /// **First registration wins** (validator finding S3, fixes a silent-overwrite bug): a
    /// second call is ignored, with a `tracing::warn!` naming the raw value that got dropped
    /// — unlike [`Self::set_primary`] (`requirements.txt`'s `--index-url`, where pip's own
    /// `argparse` `store` semantics make *last*-wins correct), Poetry has no documented
    /// ordering for multiple `primary`/`default`-priority (or unlabeled) `[[tool.poetry.source]]`
    /// entries, so silently picking whichever happened to parse last is an arbitrary,
    /// non-deterministic-looking outcome — keeping the first and logging every later one is
    /// deterministic and discoverable instead.
    pub(crate) fn set_primary_resolved(&mut self, result: Result<PypiIndexUrl, InvalidEntry>) {
        if self.primary.is_some() {
            let raw = match &result {
                Ok(url) => url.as_str(),
                Err(invalid) => invalid.raw.as_str(),
            };
            tracing::warn!(
                raw,
                "multiple primary-priority index sources declared; keeping the first, \
                 ignoring this one"
            );
            return;
        }
        self.primary = Some(result);
    }

    /// FR-003: appends an `--extra-index-url`/Poetry supplemental-priority/uv non-default
    /// entry to the fallback chain, in declaration order.
    pub fn add_extra(&mut self, raw: &str, policy: &RegistryAccessPolicy) {
        self.extras.push(resolve_entry(raw, policy));
    }

    /// Like [`Self::add_extra`], but for an already-resolved candidate — see
    /// [`Self::set_primary_resolved`]'s rationale.
    pub(crate) fn add_extra_resolved(&mut self, result: Result<PypiIndexUrl, InvalidEntry>) {
        self.extras.push(result);
    }

    /// FR-013: sets (overwriting any prior value — uv permits at most one) uv's
    /// `default = true` index, an already-resolved candidate.
    pub(crate) fn set_tail_hop_resolved(&mut self, result: Result<PypiIndexUrl, InvalidEntry>) {
        self.tail_hop = Some(result);
    }

    /// FR-007/FR-013: registers a Poetry/uv named source, reachable via
    /// [`Self::resolve_source_for`] with `Some(name)`. An already-resolved candidate — see
    /// [`Self::set_primary_resolved`]'s rationale.
    pub(crate) fn add_named_source_resolved(
        &mut self,
        name: String,
        result: Result<PypiIndexUrl, InvalidEntry>,
    ) {
        self.named_sources.insert(name, result);
    }

    /// The valid (`Ok`) subset of [`Self::extras`], in declaration order.
    fn valid_extras(&self) -> Vec<PypiIndexUrl> {
        self.extras
            .iter()
            .filter_map(|e| e.as_ref().ok())
            .cloned()
            .collect()
    }

    /// The effective case-(b) chain (spec FR-005(b)), or `None` when this config has no
    /// case-(b) declaration at all (no extras, no uv tail hop) — the "nothing declared"
    /// state, distinct from "declared but every hop turned out invalid" (the zero-hop case,
    /// which returns `Some` with an empty `hops`).
    ///
    /// An invalid uv `default` entry (`tail_hop` is `Some(Err(_))`) degrades to the implicit
    /// public fallback rather than being dropped with no replacement — the same
    /// fail-toward-availability rule FR-006 applies to every other extra.
    fn case_b_chain(&self) -> Option<CaseBChain> {
        if self.extras.is_empty() && self.tail_hop.is_none() {
            return None;
        }
        let mut hops = self.valid_extras();
        let implicit_public_fallback = match &self.tail_hop {
            Some(Ok(tail)) => {
                hops.push(tail.clone());
                false
            }
            Some(Err(_)) | None => true,
        };
        Some(CaseBChain {
            hops,
            implicit_public_fallback,
        })
    }

    /// FR-002/FR-003/FR-005/FR-006/FR-007/FR-013: resolves one dependency's
    /// [`DependencySource`].
    ///
    /// `named_source` is `Some("internal")` for a dependency declaring `source = "internal"`
    /// (Poetry) or an `index = "internal"` uv-sources binding; `None` for every other
    /// dependency (routes through `primary`/`extras`/`tail_hop` per FR-005 instead).
    ///
    /// - A named-source reference resolves to that source's own URL, or
    ///   [`DependencySource::CustomRegistry`] if the name is unresolved or the source is
    ///   invalid (fail-closed, never a silent `pypi.org` fallback — FR-006).
    /// - No override anywhere (no primary, no case-(b) declaration) -> plain
    ///   [`DependencySource::Registry`] (US-004).
    /// - An explicit primary present but invalid -> [`DependencySource::CustomRegistry`]
    ///   (fail-closed — never falls through to the extras chain, matching an explicit
    ///   `--index-url`'s *replace*, not *add*, semantics).
    /// - Otherwise -> [`DependencySource::AlternateRegistry`] pointing at the chain
    ///   [`ResolvedChain::key`] this same config's [`Self::resolved_chains`] registers.
    #[must_use]
    pub fn resolve_source_for(&self, named_source: Option<&str>) -> DependencySource {
        if let Some(name) = named_source {
            return match self.named_sources.get(name) {
                Some(Ok(url)) => DependencySource::AlternateRegistry {
                    index: url.as_str().to_string(),
                    mirrors_crates_io: false,
                },
                Some(Err(invalid)) => DependencySource::CustomRegistry {
                    url: invalid.raw.clone(),
                },
                None => DependencySource::CustomRegistry {
                    url: name.to_string(),
                },
            };
        }

        match &self.primary {
            Some(Ok(primary)) => {
                let mut hops = vec![primary.clone()];
                hops.extend(self.valid_extras());
                DependencySource::AlternateRegistry {
                    index: ResolvedChain::chain(hops, false).key,
                    mirrors_crates_io: false,
                }
            }
            Some(Err(invalid)) => DependencySource::CustomRegistry {
                url: invalid.raw.clone(),
            },
            None => match self.case_b_chain() {
                Some(chain) if !chain.hops.is_empty() => DependencySource::AlternateRegistry {
                    index: ResolvedChain::chain(chain.hops, chain.implicit_public_fallback).key,
                    mirrors_crates_io: false,
                },
                _ => DependencySource::Registry,
            },
        }
    }

    /// Every chain this config implies, ready for registration — FR-005(a)/(b) resolved to
    /// concrete hop lists, plus one single-hop chain per valid named source. Empty when the
    /// file declares nothing (US-004) or when every case-(b) hop turned out invalid with no
    /// explicit primary (N5's zero-hop case — [`Self::resolve_source_for`] returns plain
    /// `Registry` in that case, and there is nothing to register).
    #[must_use]
    pub fn resolved_chains(&self) -> Vec<ResolvedChain> {
        let mut chains = Vec::new();

        match &self.primary {
            Some(Ok(primary)) => {
                let mut hops = vec![primary.clone()];
                hops.extend(self.valid_extras());
                chains.push(ResolvedChain::chain(hops, false));
            }
            Some(Err(_)) => {}
            None => {
                if let Some(chain) = self.case_b_chain()
                    && !chain.hops.is_empty()
                {
                    chains.push(ResolvedChain::chain(
                        chain.hops,
                        chain.implicit_public_fallback,
                    ));
                }
            }
        }

        for url in self.named_sources.values().flatten() {
            chains.push(ResolvedChain::named_source(url.clone()));
        }

        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::net_policy::WorkspaceRegistryAccess;

    fn all_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)
    }

    fn off_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off)
    }

    // --- PypiIndexUrl ---

    #[test]
    fn test_index_url_accepts_https() {
        let policy = all_policy();
        assert!(PypiIndexUrl::new("https://pypi.mycorp.example/simple", &policy).is_ok());
    }

    #[test]
    fn test_index_url_rejects_http_non_loopback() {
        let policy = all_policy();
        assert!(matches!(
            PypiIndexUrl::new("http://pypi.mycorp.example/simple", &policy),
            Err(PypiIndexUrlError::NotHttps(_))
        ));
    }

    #[test]
    fn test_index_url_accepts_http_loopback_under_test_cfg() {
        let policy = all_policy();
        assert!(PypiIndexUrl::new("http://127.0.0.1:9999/simple", &policy).is_ok());
        assert!(PypiIndexUrl::new("http://localhost:9999/simple", &policy).is_ok());
    }

    #[test]
    fn test_index_url_rejects_http_near_miss_loopback() {
        let policy = all_policy();
        assert!(matches!(
            PypiIndexUrl::new("http://localhost.evil.com/simple", &policy),
            Err(PypiIndexUrlError::NotHttps(_))
        ));
    }

    #[test]
    fn test_index_url_rejects_userinfo() {
        let policy = all_policy();
        assert!(matches!(
            PypiIndexUrl::new("https://user:pass@pypi.mycorp.example/simple", &policy),
            Err(PypiIndexUrlError::UserInfoPresent)
        ));
    }

    #[test]
    fn test_index_url_rejects_invalid_url() {
        let policy = all_policy();
        assert!(matches!(
            PypiIndexUrl::new("not-a-valid-url", &policy),
            Err(PypiIndexUrlError::InvalidUrl(_))
        ));
    }

    #[test]
    fn test_index_url_normalizes_trailing_slash() {
        let policy = all_policy();
        let with_slash = PypiIndexUrl::new("https://pypi.mycorp.example/simple/", &policy).unwrap();
        let without_slash =
            PypiIndexUrl::new("https://pypi.mycorp.example/simple", &policy).unwrap();
        assert_eq!(with_slash, without_slash);
        assert!(!with_slash.as_str().ends_with('/'));
    }

    #[test]
    fn test_index_url_policy_matrix() {
        assert!(PypiIndexUrl::new("https://127.0.0.1:9999/simple", &all_policy()).is_ok());
        assert!(matches!(
            PypiIndexUrl::new("https://127.0.0.1:9999/simple", &off_policy()),
            Err(PypiIndexUrlError::BlockedHost { .. })
        ));
    }

    // --- PypiIndexConfig::resolve_source_for / resolved_chains ---

    #[test]
    fn test_no_declaration_resolves_to_plain_registry() {
        let config = PypiIndexConfig::new();
        assert_eq!(config.resolve_source_for(None), DependencySource::Registry);
        assert!(config.resolved_chains().is_empty());
    }

    /// FR-005(a): an explicit primary alone.
    #[test]
    fn test_case_a_primary_only() {
        let policy = all_policy();
        let mut config = PypiIndexConfig::new();
        config.set_primary("https://pypi.mycorp.example/simple", &policy);

        let source = config.resolve_source_for(None);
        let DependencySource::AlternateRegistry {
            index,
            mirrors_crates_io,
        } = source
        else {
            panic!("expected AlternateRegistry");
        };
        assert!(!mirrors_crates_io);
        assert!(index.starts_with("pypi-chain:"));

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].key, index);
        assert_eq!(chains[0].hops.len(), 1);
        assert!(!chains[0].implicit_public_fallback);
    }

    /// Validator finding S3: `set_primary_resolved` keeps the first registration when called
    /// more than once — a second Poetry `primary`/`default`-priority source must not silently
    /// overwrite the first.
    #[test]
    fn test_set_primary_resolved_keeps_first_on_duplicate() {
        let policy = all_policy();
        let mut config = PypiIndexConfig::new();
        config.set_primary_resolved(resolve_entry("https://first.example/simple", &policy));
        config.set_primary_resolved(resolve_entry("https://second.example/simple", &policy));

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 1);
        assert_eq!(chains[0].hops[0].as_str(), "https://first.example/simple");
    }

    /// FR-005(a): primary + extras — no implicit public hop appended.
    #[test]
    fn test_case_a_primary_plus_extras() {
        let policy = all_policy();
        let mut config = PypiIndexConfig::new();
        config.set_primary("https://primary.example/simple", &policy);
        config.add_extra("https://extra.example/simple", &policy);

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 2);
        assert_eq!(chains[0].hops[0].as_str(), "https://primary.example/simple");
        assert_eq!(chains[0].hops[1].as_str(), "https://extra.example/simple");
        assert!(!chains[0].implicit_public_fallback);
    }

    /// FR-005(b): extras only, no explicit primary — implicit public fallback is the last
    /// hop.
    #[test]
    fn test_case_b_extras_only_no_primary() {
        let policy = all_policy();
        let mut config = PypiIndexConfig::new();
        config.add_extra("https://extra.example/simple", &policy);

        let source = config.resolve_source_for(None);
        assert!(matches!(source, DependencySource::AlternateRegistry { .. }));

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 1);
        assert!(chains[0].implicit_public_fallback);
    }

    /// N5/second critic pass: every extra dropped (e.g. policy-blocked) and no explicit
    /// primary -> zero-hop case, degrades to plain `Registry`, nothing registered.
    #[test]
    fn test_zero_hop_case_degrades_to_plain_registry() {
        let policy = off_policy();
        let mut config = PypiIndexConfig::new();
        config.add_extra("https://extra.example/simple", &policy);

        assert_eq!(config.resolve_source_for(None), DependencySource::Registry);
        assert!(config.resolved_chains().is_empty());
    }

    /// C2 regression: an explicit chain `[A, B]` and an implicit chain that resolves to the
    /// same hops `[A, B]` (plus the fallback flag) must produce different keys.
    #[test]
    fn test_chain_key_distinguishes_explicit_from_implicit() {
        let policy = all_policy();

        let mut explicit = PypiIndexConfig::new();
        explicit.set_primary("https://a.example/simple", &policy);
        explicit.add_extra("https://b.example/simple", &policy);

        let mut implicit = PypiIndexConfig::new();
        implicit.add_extra("https://a.example/simple", &policy);
        implicit.add_extra("https://b.example/simple", &policy);

        let explicit_key = explicit.resolved_chains()[0].key.clone();
        let implicit_key = implicit.resolved_chains()[0].key.clone();
        assert_ne!(explicit_key, implicit_key);
    }

    /// C2 regression: two configs sharing a primary but differing extras produce different
    /// keys.
    #[test]
    fn test_chain_key_differs_by_extras() {
        let policy = all_policy();

        let mut one = PypiIndexConfig::new();
        one.set_primary("https://primary.example/simple", &policy);
        one.add_extra("https://extra-a.example/simple", &policy);

        let mut two = PypiIndexConfig::new();
        two.set_primary("https://primary.example/simple", &policy);
        two.add_extra("https://extra-b.example/simple", &policy);

        assert_ne!(one.resolved_chains()[0].key, two.resolved_chains()[0].key);
    }

    /// An invalid explicit primary fails closed — never falls through to extras.
    #[test]
    fn test_invalid_primary_fails_closed() {
        let policy = all_policy();
        let mut config = PypiIndexConfig::new();
        config.set_primary("not-a-valid-url", &policy);
        config.add_extra("https://extra.example/simple", &policy);

        assert_eq!(
            config.resolve_source_for(None),
            DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            }
        );
        assert!(config.resolved_chains().is_empty());
    }

    /// An invalid extra is dropped, not escalated to `CustomRegistry` — the primary still
    /// resolves via its remaining valid hop(s) (S6-shaped: one bad extra must not break a
    /// chain that still has a working hop).
    #[test]
    fn test_invalid_extra_dropped_not_escalated() {
        let policy = all_policy();
        let mut config = PypiIndexConfig::new();
        config.set_primary("https://primary.example/simple", &policy);
        config.add_extra("not-a-valid-url", &policy);

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 1);
        assert_eq!(chains[0].hops[0].as_str(), "https://primary.example/simple");
    }

    /// Named source: resolves independently of primary/extras.
    #[test]
    fn test_named_source_resolves_independently() {
        let policy = all_policy();
        let mut config = PypiIndexConfig::new();
        config.add_named_source_resolved(
            "internal".to_string(),
            resolve_entry("https://internal.example/simple", &policy),
        );

        let source = config.resolve_source_for(Some("internal"));
        assert_eq!(
            source,
            DependencySource::AlternateRegistry {
                index: "https://internal.example/simple".to_string(),
                mirrors_crates_io: false,
            }
        );

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].key, "https://internal.example/simple");
    }

    /// A `source = "<name>"` reference with no matching entry fails closed, not a silent
    /// public-registry fallback.
    #[test]
    fn test_unresolved_named_source_fails_closed() {
        let config = PypiIndexConfig::new();
        assert_eq!(
            config.resolve_source_for(Some("does-not-exist")),
            DependencySource::CustomRegistry {
                url: "does-not-exist".to_string(),
            }
        );
    }

    /// uv shape: a `default = true` entry is the last-resort hop, not checked first, and
    /// never populates `primary`.
    #[test]
    fn test_uv_default_is_last_resort_not_primary() {
        let policy = all_policy();
        let mut config = PypiIndexConfig::new();
        config.add_extra("https://non-default.example/simple", &policy);
        config.set_tail_hop_resolved(resolve_entry("https://default.example/simple", &policy));

        assert!(config.primary.is_none());

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 2);
        assert_eq!(
            chains[0].hops[0].as_str(),
            "https://non-default.example/simple"
        );
        assert_eq!(chains[0].hops[1].as_str(), "https://default.example/simple");
        assert!(!chains[0].implicit_public_fallback);
    }

    /// An invalid uv `default` entry degrades to the implicit public fallback rather than
    /// leaving the chain with no final hop at all.
    #[test]
    fn test_uv_invalid_default_degrades_to_implicit_public() {
        let policy = all_policy();
        let mut config = PypiIndexConfig::new();
        config.add_extra("https://non-default.example/simple", &policy);
        config.set_tail_hop_resolved(resolve_entry("not-a-valid-url", &policy));

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 1);
        assert!(chains[0].implicit_public_fallback);
    }

    /// NFR-001/SC-005 structural guarantee: a URL carrying userinfo is rejected at
    /// construction (FR-011 — reject, never strip-and-proceed), so no [`PypiIndexUrl`] ever
    /// exists whose `normalized` field holds a credential. `PypiIndexConfig`/`InvalidEntry`
    /// have no `${VAR}`-expansion step (unlike npm) and no separate auth-shaped key field
    /// anywhere in this module. See [`test_resolve_entry_redacts_userinfo_from_raw_and_log`]
    /// below for the M1 fix: `InvalidEntry::raw` and the `tracing::warn!` line built from it
    /// also never retain the credential itself, even though both otherwise preserve the raw,
    /// as-written value.
    #[test]
    fn test_userinfo_rejected_never_retained_in_index_url() {
        let policy = all_policy();
        let err =
            PypiIndexUrl::new("https://user:hunter2@pypi.example/simple", &policy).unwrap_err();
        assert_eq!(err, PypiIndexUrlError::UserInfoPresent);
    }

    /// M1 fix: `resolve_entry`'s `InvalidEntry::raw` and its `tracing::warn!` line must never
    /// carry a userinfo-bearing URL's credential through — both are built from
    /// [`redact_userinfo`], not the untouched raw string, even though the raw value is
    /// otherwise preserved (FR-006) so a warning or a `CustomRegistry.url` a user might see in
    /// hover/diagnostics still names what they typed, minus the secret.
    #[test]
    fn test_resolve_entry_redacts_userinfo_from_raw_and_log() {
        let policy = all_policy();
        let log = deps_core::test_util::capture_tracing_output(|| {
            let invalid =
                resolve_entry("https://user:hunter2@pypi.example/simple", &policy).unwrap_err();
            assert!(matches!(invalid.reason, PypiIndexUrlError::UserInfoPresent));
            assert!(
                !invalid.raw.contains("hunter2"),
                "InvalidEntry::raw leaked the credential: {}",
                invalid.raw
            );
            assert!(
                !invalid.raw.contains("user:"),
                "InvalidEntry::raw leaked the username: {}",
                invalid.raw
            );
            assert!(
                invalid.raw.contains("pypi.example"),
                "host should survive redaction"
            );
        });
        assert!(
            !log.contains("hunter2"),
            "tracing output leaked the credential: {log:?}"
        );
    }

    /// [`redact_userinfo`] is a no-op for a value with no userinfo component (the common
    /// case), and for `"not-a-valid-url"` specifically — no `://` at all, so there is no
    /// authority for even the parse-independent fallback to inspect (see
    /// `deps_core::net_policy`'s own `test_redact_userinfo_redacts_unparseable_url_with_userinfo`
    /// for the case where an unparseable value *does* still carry userinfo).
    #[test]
    fn test_redact_userinfo_noop_cases() {
        assert_eq!(
            redact_userinfo("https://pypi.mycorp.example/simple"),
            "https://pypi.mycorp.example/simple"
        );
        assert_eq!(redact_userinfo("not-a-valid-url"), "not-a-valid-url");
    }

    #[test]
    fn test_redact_userinfo_strips_username_and_password() {
        let redacted = redact_userinfo("https://user:hunter2@pypi.example/simple");
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("user:"));
        // Spec's exact example format: a fixed `***@` marker, not a bare stripped host — this
        // keeps a redacted value visibly distinct from a URL that never carried userinfo.
        assert_eq!(redacted, "https://***@pypi.example/simple");
    }

    /// S1: a userinfo-bearing index value that also fails `Url::parse` for an unrelated reason
    /// (an invalid port here) lands in `PypiIndexUrlError::InvalidUrl`, not `UserInfoPresent` —
    /// the shape `redact_userinfo`'s original parse-gated no-op missed. Checks every channel:
    /// `InvalidEntry::raw`, the `%reason` `Display`, and the captured log.
    #[test]
    fn test_resolve_entry_redacts_literal_userinfo_from_unparseable_raw() {
        let policy = all_policy();
        let log = deps_core::test_util::capture_tracing_output(|| {
            let invalid = resolve_entry("https://user:hunter2@pypi.example:99999/simple", &policy)
                .unwrap_err();
            assert!(matches!(invalid.reason, PypiIndexUrlError::InvalidUrl(_)));
            assert!(
                !invalid.raw.contains("hunter2"),
                "InvalidEntry::raw leaked the credential: {}",
                invalid.raw
            );
            assert!(
                !invalid.reason.to_string().contains("hunter2"),
                "reason Display leaked the credential: {}",
                invalid.reason
            );
        });
        assert!(
            !log.contains("hunter2"),
            "tracing output leaked the credential: {log:?}"
        );
    }
}
