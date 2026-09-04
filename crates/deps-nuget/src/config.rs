//! `NuGet.Config` `<packageSources>`/`<packageSourceMapping>` discovery and resolution —
//! private/custom feed support (issue #523).
//!
//! # Security model (read before touching this module)
//!
//! A repository's `NuGet.Config` is attacker-controlled the moment a hostile repository is
//! cloned and opened — this LSP parses on file open, before any build ever runs.
//!
//! - **No credential is ever parsed.** `<packageSourceCredentials>` is walked for *child
//!   element names only* (each names a source key) into a set — no `Username`/
//!   `ClearTextPassword`/`Password` value is ever deserialized into a field, so no code path
//!   in this module can hold a credential (NFR-001 is then structurally provable). A source
//!   named there becomes [`NuGetFeedUrlError::HasCredentials`] and is dropped, fail-closed.
//! - **`<clear/>` is merged root→leaf, not "nearest file wins".** A root `NuGet.Config`
//!   `<clear/>` that removes the implicit `nuget.org` hop must stay removed for every
//!   descendant project, even one whose own `NuGet.Config` adds a feed without repeating the
//!   `<clear/>` — otherwise a leaf file would silently resurrect the public hop the root
//!   explicitly cleared (the #248 bug class). See [`resolve`]'s accumulation loop.
//! - **`<packageSourceMapping>` is merged across every level too**, not "nearest file wins":
//!   a root mapping `{CorpFeed: ["MyCompany.*"], nuget.org: ["*"]}` combined with a leaf
//!   mapping `{nuget.org: ["*"]}` must still route `MyCompany.Internal` to `CorpFeed` — taking
//!   only the leaf's `*` entire would leak the private package name to `nuget.org`, exactly
//!   the dependency-confusion attack this feature exists to close. See
//!   `PackageSourceMapping::resolve_keys_for`.
//! - **A `packageSourceMapping` key resolving to more than one distinct declared source is
//!   treated as unresolvable, not fanned out to every match.** Source-key matching is
//!   deliberately case/XML-name-insensitive (union of the raw and decoded forms — FR-009), and
//!   growing an *exclusion* set (disabled/credentialed) that way is fail-closed, but growing
//!   an *inclusion* set (which feed a mapped package routes to) the same way is fail-open — see
//!   `resolve_mapping_source_key`.
//! - **The public `nuget.org` source is identified by normalized URL, never by a source's
//!   configured `key`.** A hostile config can name a private feed `"nuget.org"`; only an exact
//!   match against `crate::registry::NUGET_ORG_INDEX_URL` restores the OSV/deps.dev/hover
//!   trust signal a genuine public-registry dependency gets — see
//!   `crate::registry::is_public_registry_url`.
//! - **A config chain that clears every source down to zero, with nothing re-added, is an
//!   explicit fail-closed state**, never a silent fallback to `nuget.org` — see
//!   `NO_SOURCES_CONFIGURED_SENTINEL`.
//!
//! See `specs/035-nuget-private-feed-support/spec.md` for the full requirements.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use deps_core::PackageName;
use deps_core::net_policy::{
    IndexUrlError, PolicyGate, RegistryAccessPolicy, redact_userinfo, validate_index_url,
};
use deps_core::parser::DependencySource;
use quick_xml::Reader;
use quick_xml::events::Event;

/// Upper bound on the in-repo `NuGet.Config` ancestor walk, matching `deps-npm`'s/
/// `deps-cargo`'s identical `MAX_CONFIG_ANCESTOR_DEPTH`.
const MAX_CONFIG_ANCESTOR_DEPTH: usize = 64;

/// Candidate filenames checked per directory, in order — real NuGet is case-insensitive on
/// Linux/macOS and all three spellings occur in the wild. `is_file()` stats, not `read_dir`.
const CONFIG_FILENAMES: &[&str] = &["NuGet.Config", "nuget.config", "NuGet.config"];

/// Sentinel [`DependencySource::CustomRegistry`] URL for a config chain that clears every
/// package source down to zero with nothing re-added — R4: this must be a distinct,
/// explicitly-named fail-closed state, never allowed to fall through to plain
/// [`DependencySource::Registry`] (the #248 bug re-entering through the empty-set door).
/// Never fetched — informational text only, safe to render in hover/diagnostics.
const NO_SOURCES_CONFIGURED_SENTINEL: &str = "<clear/> removed every NuGet package source";

/// Why a candidate `<add value="...">` failed validation, or why it was dropped as
/// disabled/credentialed/unsupported.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NuGetFeedUrlError {
    /// The value did not parse as a URL at all.
    #[error("not a valid URL: {0}")]
    InvalidUrl(String),
    /// The URL's scheme is not `https`.
    #[error("registry feed must use https, got scheme {0:?}")]
    NotHttps(String),
    /// The URL carries a `user:pass@`/`user@` component.
    #[error("registry feed URL must not carry userinfo")]
    UserInfoPresent,
    /// The candidate's host is blocked by the current
    /// [`deps_core::net_policy::WorkspaceRegistryAccess`] policy.
    #[error("registry feed host class {class} blocked by registries.workspace_registries policy")]
    BlockedHost {
        /// The blocked host's classification.
        class: deps_core::net_policy::HostClass,
    },
    /// The source has an entry under `<packageSourceCredentials>` — credentials are never
    /// read, so the source is dropped rather than queried unauthenticated (FR-009).
    #[error("source has packageSourceCredentials configured; credentials are never read")]
    HasCredentials,
    /// The source is named in `<disabledPackageSources>` with a `true` value (FR-004).
    #[error("source is disabled via disabledPackageSources")]
    Disabled,
    /// A `protocolVersion="2"` (NuGet V2) source — only V3 feeds are supported.
    #[error("unsupported NuGet protocolVersion {0:?}; only V3 feeds are supported")]
    UnsupportedProtocolVersion(String),
    /// A local filesystem/UNC path feed (e.g. `../packages`, `\\server\share`) — legitimate
    /// and common, but out of scope; logged at `debug!`, not `warn!` (unlike a genuinely
    /// malformed value), so a normal local-feed setup doesn't warn on every parse.
    #[error("local/UNC feed paths are not supported")]
    LocalFeedUnsupported,
}

impl From<IndexUrlError> for NuGetFeedUrlError {
    fn from(error: IndexUrlError) -> Self {
        match error {
            IndexUrlError::InvalidUrl(raw) => Self::InvalidUrl(raw),
            IndexUrlError::NotHttps(scheme) => Self::NotHttps(scheme),
            IndexUrlError::UserInfoPresent => Self::UserInfoPresent,
            IndexUrlError::BlockedHost { class } => Self::BlockedHost { class },
        }
    }
}

/// A validated, normalized, https-only NuGet V3 service index URL with no embedded userinfo.
///
/// Mirrors `deps_pypi::config::PypiIndexUrl`/`deps_npm::config::NpmRegistryIndex`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NuGetFeedUrl {
    /// The validated URL, normalized by stripping a trailing `/`.
    normalized: String,
}

impl NuGetFeedUrl {
    /// Validates and normalizes `raw` against `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`NuGetFeedUrlError`] if `raw` does not parse as a URL, is not `https` (outside
    /// the `cfg(test)`/`test-util` loopback carve-out), carries a userinfo component, or
    /// resolves to a host class the current `policy` blocks.
    pub fn new(raw: &str, policy: &RegistryAccessPolicy) -> Result<Self, NuGetFeedUrlError> {
        let url = validate_index_url(raw, raw, "nuget", PolicyGate::Enforce(policy))?;
        Ok(Self {
            normalized: url.as_str().trim_end_matches('/').to_string(),
        })
    }

    /// The normalized feed URL. Never carries a trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// The real public NuGet service index, trusted unconditionally — never policy-gated,
    /// since it is a hardcoded constant this LSP already queries ungated for every project
    /// declaring no `NuGet.Config` override at all (FR-010's carve-out), not workspace
    /// provenance. Used only for S1 (impl-critic): a `<packageSourceMapping>` key literally
    /// naming `nuget.org` that does not resolve to any declared `<packageSources>` entry —
    /// the near-universal real shape where `nuget.org` itself is declared in the
    /// machine/user-profile config this feature deliberately does not read.
    fn trusted_public() -> Self {
        Self {
            normalized: crate::registry::NUGET_ORG_INDEX_URL.to_string(),
        }
    }
}

impl std::fmt::Display for NuGetFeedUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A present-but-unusable `<add>` entry — an invalid URL, a policy-blocked host, a
/// disabled/credentialed source, or an unsupported protocol/local-feed value.
#[derive(Debug, Clone)]
pub struct InvalidEntry {
    /// The raw value, as written (or the source's resolved URL if it was invalidated only
    /// after passing URL validation, e.g. disabled/credentialed), with any embedded userinfo
    /// redacted.
    pub raw: String,
    /// Why it was rejected.
    pub reason: NuGetFeedUrlError,
}

/// One resolved `<packageSources>` entry, keyed by its declared `key` (case preserved, but
/// every comparison against it goes through `key_candidates`).
#[derive(Debug, Clone)]
pub struct PackageSourceEntry {
    pub key: String,
    pub value: Result<NuGetFeedUrl, InvalidEntry>,
}

/// One fully-resolved routing chain, produced by [`NuGetConfig::resolved_chains`], consumed by
/// `NuGetRegistry::register_chain`. Mirrors `deps_pypi::config::ResolvedChain` exactly.
#[derive(Debug, Clone)]
pub struct NuGetSourceChain {
    /// Opaque, hashed identity — `format!("nuget-chain:{:016x}", digest)` over the ordered hop
    /// strings plus [`Self::implicit_public_fallback`]. [`NuGetConfig::resolve_source_for`] and
    /// [`NuGetConfig::resolved_chains`] recompute this independently and must agree.
    pub key: String,
    /// Ordered, already-validated hops. Never empty.
    pub hops: Vec<NuGetFeedUrl>,
    /// `true` only for the plain (non-mapping) chain when no ancestor `<clear/>` removed the
    /// implicit public fallback — the public hop is appended at registration time, never
    /// present in [`Self::hops`]. Always `false` for a `<packageSourceMapping>`-derived
    /// chain: a mapping is authoritative once it names a package, so the chain never appends
    /// the public hop even when `<clear/>` is absent (this is the dependency-confusion leak
    /// fix — see this module's doc).
    pub implicit_public_fallback: bool,
}

impl NuGetSourceChain {
    fn chain(hops: Vec<NuGetFeedUrl>, implicit_public_fallback: bool) -> Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for hop in &hops {
            hop.as_str().hash(&mut hasher);
        }
        implicit_public_fallback.hash(&mut hasher);
        Self {
            key: format!("nuget-chain:{:016x}", hasher.finish()),
            hops,
            implicit_public_fallback,
        }
    }
}

/// `<packageSourceMapping>` rules, merged across every level of the config chain (R1 — see
/// this module's doc). Grouped by normalized pattern: `patterns[i] = (pattern, source_keys)`.
#[derive(Debug, Clone, Default)]
struct PackageSourceMapping {
    patterns: Vec<(String, Vec<String>)>,
}

/// A pattern's match specificity: `Wildcard` < `Prefix(len)` < `Exact(len)`, so the derived
/// `Ord` implements NuGet's real tie-break rule (exact always beats prefix, regardless of
/// either's character length; among same-kind matches, the longer one wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchScore {
    Wildcard,
    Prefix(usize),
    Exact(usize),
}

impl PackageSourceMapping {
    fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Adds one accumulated `(source_key, patterns)` declaration — called once per ancestor
    /// file, root-to-leaf, so a pattern declared at multiple levels accumulates every source
    /// key that ever named it (R1's merge, replacing "nearest file wins").
    fn extend(&mut self, source_key: &str, patterns: &[String]) {
        for pattern in patterns {
            let normalized_pattern = pattern.to_lowercase();
            if let Some((_, keys)) = self
                .patterns
                .iter_mut()
                .find(|(p, _)| *p == normalized_pattern)
            {
                let dup = keys.iter().any(|k| key_candidates_overlap(k, source_key));
                if !dup {
                    keys.push(source_key.to_string());
                }
            } else {
                self.patterns
                    .push((normalized_pattern, vec![source_key.to_string()]));
            }
        }
    }

    /// Real NuGet `<packageSourceMapping>` matching: bare `*`, a trailing-`*` prefix glob, or
    /// an exact id — case-insensitive, longest/most-specific match wins, ties make every tied
    /// pattern's source keys eligible (declaration order, deduplicated by `key_candidates`).
    /// `None` when no pattern matches `name_lower` at all (FR-008: fail closed, never falls
    /// through to an unmapped registry).
    fn resolve_keys_for(&self, name_lower: &str) -> Option<Vec<&str>> {
        let mut best: Option<MatchScore> = None;
        let mut winners: Vec<&(String, Vec<String>)> = Vec::new();

        for entry @ (pattern, _) in &self.patterns {
            let score = if pattern == "*" {
                Some(MatchScore::Wildcard)
            } else if let Some(prefix) = pattern.strip_suffix('*') {
                name_lower
                    .starts_with(prefix)
                    .then(|| MatchScore::Prefix(prefix.chars().count()))
            } else {
                (name_lower == pattern).then(|| MatchScore::Exact(pattern.chars().count()))
            };
            let Some(score) = score else { continue };
            match best {
                Some(b) if score < b => {}
                Some(b) if score == b => winners.push(entry),
                _ => {
                    best = Some(score);
                    winners = vec![entry];
                }
            }
        }

        if winners.is_empty() {
            return None;
        }
        let mut keys: Vec<&str> = Vec::new();
        for (_, group_keys) in winners {
            for k in group_keys {
                if !keys
                    .iter()
                    .any(|existing| key_candidates_overlap(existing, k))
                {
                    keys.push(k.as_str());
                }
            }
        }
        Some(keys)
    }
}

/// Inverse of .NET `XmlConvert.EncodeLocalName`: decodes `_xHHHH_` escapes (4 hex digits) back
/// to their UTF-16 code unit — `_x005F_` decodes to a literal `_`. NuGet XML-encodes
/// non-alphanumeric characters in a `<packageSourceCredentials>` child element name (a source
/// named `Corp Feed` appears as `<Corp_x0020_Feed>`).
///
/// Malformed sequences and lone surrogates are left literal rather than erroring — the raw
/// candidate (see `key_candidates`) still covers them, so nothing is ever dropped, only
/// possibly not perfectly reconstructed.
fn decode_xml_name(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '_' && chars.get(i + 1) == Some(&'x') && chars.get(i + 6) == Some(&'_') {
            let hex: String = chars[i + 2..i + 6].iter().collect();
            if hex.chars().all(|c| c.is_ascii_hexdigit())
                && let Ok(code) = u32::from_str_radix(&hex, 16)
                && let Some(ch) = char::from_u32(code)
            {
                out.push(ch);
                i += 7;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Union comparison funnel for **every** source key comparison (FR-009): a source key
/// matches `other` if either its raw-lowercased or XML-name-decoded-lowercased form matches
/// the same for `other`. Used both as an *exclusion* filter (disabled/credentialed — where
/// matching more is fail-closed) and, with an extra unambiguous-resolution requirement layered
/// on top (see `resolve_mapping_source_key`), for `<packageSourceMapping>` key lookups.
fn key_candidates(raw: &str) -> [String; 2] {
    [raw.to_lowercase(), decode_xml_name(raw).to_lowercase()]
}

fn key_candidates_overlap(a: &str, b: &str) -> bool {
    let ca = key_candidates(a);
    let cb = key_candidates(b);
    ca.iter().any(|x| cb.contains(x))
}

/// R2 fix: resolves a `<packageSourceMapping>` key to *exactly one* declared source. Zero
/// matches (the key names a source absent from `<packageSources>`, e.g. because it was never
/// declared or was filtered out as disabled/credentialed) and more-than-one match (an
/// ambiguous union collision) both return `None` — contributing nothing, rather than fanning a
/// mapped package out to every candidate. Unlike the disabled/credentialed exclusion sets,
/// this is an *inclusion* lookup, where growing the match set on a union comparison would be
/// fail-open, not fail-closed.
fn resolve_mapping_source_key<'s>(
    mapping_key: &str,
    sources: &'s [PackageSourceEntry],
) -> Option<&'s PackageSourceEntry> {
    let mut matches = sources
        .iter()
        .filter(|s| key_candidates_overlap(&s.key, mapping_key));
    let first = matches.next()?;
    if matches.next().is_some() {
        tracing::debug!(
            key = mapping_key,
            "packageSourceMapping key resolves to more than one declared source; treating as unresolvable"
        );
        return None;
    }
    Some(first)
}

/// Resolved `NuGet.Config` view for one manifest's directory — the merged result of every
/// in-repo ancestor `NuGet.Config` (root-to-leaf accumulation, see this module's doc).
#[derive(Debug, Default)]
pub struct NuGetConfig {
    sources: Vec<PackageSourceEntry>,
    /// Sticky across the whole ancestor walk: once any ancestor's `<clear/>` removed the
    /// implicit public fallback, a leaf that adds a feed without repeating `<clear/>` does
    /// not resurrect it.
    cleared: bool,
    /// Sticky across the whole ancestor walk, same rationale as `cleared`: once any ancestor
    /// explicitly `<remove key="nuget.org"/>`s the implicit public source (S4, impl-critic),
    /// the implicit fallback stays removed — distinct from `cleared`, which additionally
    /// wipes every other accumulated source. An explicit `<add key="..."
    /// value="https://api.nuget.org/v3/index.json"/>` still resurrects it as a normal
    /// declared hop, exactly as it does after `<clear/>`.
    nuget_org_removed: bool,
    mapping: PackageSourceMapping,
}

impl NuGetConfig {
    /// FR-002–FR-009: resolves one dependency's [`DependencySource`].
    #[must_use]
    pub fn resolve_source_for(&self, package: &PackageName) -> DependencySource {
        if !self.mapping.is_empty() {
            return self.resolve_via_mapping(package);
        }
        self.resolve_plain()
    }

    fn resolve_via_mapping(&self, package: &PackageName) -> DependencySource {
        let name_lower = package.as_str().to_lowercase();
        let Some(keys) = self.mapping.resolve_keys_for(&name_lower) else {
            return no_source(package);
        };
        let hops = self.hops_for_mapping_keys(&keys);
        if hops.is_empty() {
            return no_source(package);
        }
        if hops.len() == 1 && crate::registry::is_public_registry_url(hops[0].as_str()) {
            return DependencySource::Registry;
        }
        DependencySource::AlternateRegistry {
            index: NuGetSourceChain::chain(hops, false).key,
            mirrors_crates_io: false,
        }
    }

    /// S1 fix (impl-critic): a mapping key naming the literal, well-known `nuget.org` source
    /// that resolves to **no** declared `<packageSources>` entry falls back to the real
    /// public feed instead of contributing nothing — real NuGet's implicit machine-tier
    /// `nuget.org` source is exactly this shape (declared in the machine/user-profile config
    /// this feature deliberately does not read, so it is never a `PackageSourceEntry` here).
    /// Without this, the near-universal real-world config shape — `<packageSources>` adding
    /// only a private feed, plus a `<packageSourceMapping>` whose `*` pattern names
    /// `nuget.org` — would fail every public package closed. This does not weaken R3: R3
    /// forbids trusting the *key* of a source that **is** declared and points elsewhere;
    /// here nothing is declared under that key at all, so there is no spoofable entry to
    /// misidentify.
    fn hops_for_mapping_keys(&self, keys: &[&str]) -> Vec<NuGetFeedUrl> {
        let mut hops = Vec::new();
        for key in keys {
            let resolved = resolve_mapping_source_key(key, &self.sources)
                .and_then(|entry| entry.value.as_ref().ok())
                .cloned()
                .or_else(|| {
                    key.eq_ignore_ascii_case("nuget.org")
                        .then(NuGetFeedUrl::trusted_public)
                });
            if let Some(url) = resolved
                && !hops
                    .iter()
                    .any(|h: &NuGetFeedUrl| h.as_str() == url.as_str())
            {
                hops.push(url);
            }
        }
        hops
    }

    /// FR-002–FR-004/FR-008/R4: zero *usable* hops means two different things depending on
    /// `cleared`. Without a `<clear/>` anywhere in the chain, a source that was declared but
    /// then dropped (invalid, disabled, credentialed, or simply never declared at all) leaves
    /// the implicit `nuget.org` tail exactly as reachable as if nothing had been configured —
    /// plain `Registry`, byte-identical to today (US-004/NFR-004). With a `<clear/>`
    /// somewhere in the chain, the implicit tail is gone too, so zero usable hops is an
    /// explicit fail-closed state (R4) — never a silent fall-through to `Registry`, whether
    /// there is a nameable invalid entry or genuinely nothing left to name.
    fn resolve_plain(&self) -> DependencySource {
        let valid_hops = self.valid_hops();
        if valid_hops.is_empty() {
            if self.implicit_public_fallback() {
                return DependencySource::Registry;
            }
            let raw = self
                .sources
                .iter()
                .find_map(|s| s.value.as_ref().err().map(|e| e.raw.clone()))
                .unwrap_or_else(|| NO_SOURCES_CONFIGURED_SENTINEL.to_string());
            return DependencySource::CustomRegistry { url: raw };
        }
        // M2 (impl-critic): mirrors `resolve_via_mapping`'s identical check — an explicit
        // `<clear/>` + `<add key="nuget.org" value="https://api.nuget.org/v3/index.json"/>`
        // (Microsoft's own canonical source-pinning pattern) resolves to plain `Registry`,
        // keeping OSV/deps.dev/hover-trust, rather than an `AlternateRegistry` chain whose
        // only hop happens to be the same URL.
        if valid_hops.len() == 1 && crate::registry::is_public_registry_url(valid_hops[0].as_str())
        {
            return DependencySource::Registry;
        }
        DependencySource::AlternateRegistry {
            index: NuGetSourceChain::chain(valid_hops, self.implicit_public_fallback()).key,
            mirrors_crates_io: false,
        }
    }

    /// Whether the implicit `nuget.org` tail hop is still in effect — `false` once either an
    /// ancestor's `<clear/>` (`cleared`) or an explicit `<remove key="nuget.org"/>`
    /// (`nuget_org_removed`, S4) has taken it out; both are sticky across the whole ancestor
    /// walk.
    fn implicit_public_fallback(&self) -> bool {
        !self.cleared && !self.nuget_org_removed
    }

    fn valid_hops(&self) -> Vec<NuGetFeedUrl> {
        self.sources
            .iter()
            .filter_map(|s| s.value.as_ref().ok().cloned())
            .collect()
    }

    /// Every chain this config implies, ready for `NuGetRegistry::register_chain` — one chain
    /// per distinct `<packageSourceMapping>` hop-set (when a mapping is declared), or the
    /// single plain accumulated chain otherwise. Empty when nothing is registrable (US-004,
    /// R4's fail-closed states, or a mapping group that resolves to only the public source).
    #[must_use]
    pub fn resolved_chains(&self) -> Vec<NuGetSourceChain> {
        let mut chains = Vec::new();
        let mut seen = HashSet::new();

        if self.mapping.is_empty() {
            let valid_hops = self.valid_hops();
            let is_public_only = valid_hops.len() == 1
                && crate::registry::is_public_registry_url(valid_hops[0].as_str());
            if !valid_hops.is_empty() && !is_public_only {
                chains.push(NuGetSourceChain::chain(
                    valid_hops,
                    self.implicit_public_fallback(),
                ));
            }
        } else {
            for (_, group_keys) in &self.mapping.patterns {
                let keys: Vec<&str> = group_keys.iter().map(String::as_str).collect();
                let hops = self.hops_for_mapping_keys(&keys);
                if hops.is_empty()
                    || (hops.len() == 1
                        && crate::registry::is_public_registry_url(hops[0].as_str()))
                {
                    continue;
                }
                let chain = NuGetSourceChain::chain(hops, false);
                if seen.insert(chain.key.clone()) {
                    chains.push(chain);
                }
            }
        }
        chains
    }
}

fn no_source(package: &PackageName) -> DependencySource {
    DependencySource::CustomRegistry {
        url: package.as_str().to_string(),
    }
}

/// One `<add key="..." value="..." protocolVersion="...">` entry, unvalidated.
#[derive(Debug, Default, Clone)]
struct RawSourceAdd {
    key: String,
    value: String,
    protocol_version: Option<String>,
}

/// One `NuGet.Config` file's raw, unvalidated, un-cross-referenced contents.
#[derive(Debug, Default, Clone)]
struct RawNuGetConfigFile {
    sources_cleared: bool,
    sources: Vec<RawSourceAdd>,
    /// Raw keys named by `<packageSources><remove key="..."/></packageSources>` (S4,
    /// impl-critic) — applied after this file's own `<add>`s during accumulation, per-file,
    /// the same "clear/add/remove processed as one file-level batch, not in strict document
    /// order" approximation `sources_cleared` already makes for `<clear/>` (real configs
    /// overwhelmingly put `<clear/>` first and `<remove>` after any local `<add>`, so this
    /// matches the common case exactly).
    removed: Vec<String>,
    /// `(key, value)` from `<disabledPackageSources><add key=".." value=".."/></...>`.
    disabled: Vec<(String, String)>,
    /// Child element names under `<packageSourceCredentials>` — never their contents.
    credentialed_keys: Vec<String>,
    /// `(packageSource key, patterns)` from `<packageSourceMapping>`.
    mapping: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigSection {
    Sources,
    Disabled,
    Credentials,
    Mapping,
}

/// Parses one `NuGet.Config` file's content into its raw sections. Never fails: a malformed
/// XML document degrades to an all-default (empty) [`RawNuGetConfigFile`] rather than
/// propagating a parse error — a syntactically broken config must not crash the LSP or block
/// every other manifest's resolution.
fn parse_nuget_config_raw(content: &str) -> RawNuGetConfigFile {
    let mut out = RawNuGetConfigFile::default();
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut section: Option<ConfigSection> = None;
    let mut credential_source: Option<String> = None;
    let mut mapping_source_key: Option<String> = None;

    loop {
        // H1 fix (security review): a malformed document must degrade to the all-default
        // (empty) `RawNuGetConfigFile` this function's own doc already promises — never the
        // partially-accumulated value up to the parse error. `<packageSourceMapping>`,
        // `<packageSourceCredentials>`, and `<disabledPackageSources>` conventionally follow
        // `<packageSources>` in the file, so returning a partial result would silently drop
        // every restriction declared after the malformed point.
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "malformed NuGet.Config XML; ignoring this file's declarations entirely"
                );
                return RawNuGetConfigFile::default();
            }
        };
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let is_start = matches!(event, Event::Start(_));
                let local: String = e.local_name().as_ref().to_string();

                if section.is_none() {
                    // S2 fix (impl-critic): a self-closing section element (`<packageSources
                    // />`) emits no matching `Event::End`, so it must never latch `section` —
                    // doing so would swallow every later element in the document (including
                    // an unrelated `<packageSources><clear/>...`) into this section, silently
                    // neutralizing the `<clear/>` protection. Only `Event::Start` opens a
                    // section; an empty section has no children to process either way.
                    if is_start {
                        section = match local.as_str() {
                            "packageSources" => Some(ConfigSection::Sources),
                            "disabledPackageSources" => Some(ConfigSection::Disabled),
                            "packageSourceCredentials" => Some(ConfigSection::Credentials),
                            "packageSourceMapping" => Some(ConfigSection::Mapping),
                            _ => None,
                        };
                    }
                    continue;
                }

                match (section, local.as_str()) {
                    (Some(ConfigSection::Sources), "clear") => out.sources_cleared = true,
                    (Some(ConfigSection::Sources), "remove") => {
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == "key" {
                                out.removed.push(decode_attr(&attr.value));
                            }
                        }
                    }
                    (Some(ConfigSection::Sources), "add") => {
                        let mut add = RawSourceAdd::default();
                        for attr in e.attributes().flatten() {
                            match attr.key.local_name().as_ref() {
                                "key" => add.key = decode_attr(&attr.value),
                                "value" => add.value = decode_attr(&attr.value),
                                "protocolVersion" => {
                                    add.protocol_version = Some(decode_attr(&attr.value));
                                }
                                _ => {}
                            }
                        }
                        if !add.key.is_empty() {
                            out.sources.push(add);
                        }
                    }
                    (Some(ConfigSection::Disabled), "add") => {
                        let mut key = String::new();
                        let mut value = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.local_name().as_ref() {
                                "key" => key = decode_attr(&attr.value),
                                "value" => value = decode_attr(&attr.value),
                                _ => {}
                            }
                        }
                        if !key.is_empty() {
                            out.disabled.push((key, value));
                        }
                    }
                    (Some(ConfigSection::Credentials), _) if credential_source.is_none() => {
                        out.credentialed_keys.push(local.clone());
                        if is_start {
                            credential_source = Some(local);
                        }
                    }
                    (Some(ConfigSection::Mapping), "packageSource") => {
                        let mut key = String::new();
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == "key" {
                                key = decode_attr(&attr.value);
                            }
                        }
                        if !key.is_empty() {
                            if is_start {
                                mapping_source_key = Some(key.clone());
                            }
                            out.mapping.push((key, Vec::new()));
                        }
                    }
                    (Some(ConfigSection::Mapping), "package") if mapping_source_key.is_some() => {
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == "pattern"
                                && let Some(last) = out.mapping.last_mut()
                            {
                                last.1.push(decode_attr(&attr.value));
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::End(ref e) => {
                let local: String = e.local_name().as_ref().to_string();
                match section {
                    Some(ConfigSection::Sources) if local == "packageSources" => section = None,
                    Some(ConfigSection::Disabled) if local == "disabledPackageSources" => {
                        section = None;
                    }
                    Some(ConfigSection::Credentials) if local == "packageSourceCredentials" => {
                        section = None;
                    }
                    Some(ConfigSection::Mapping) if local == "packageSourceMapping" => {
                        section = None;
                    }
                    Some(ConfigSection::Mapping) if local == "packageSource" => {
                        mapping_source_key = None;
                    }
                    Some(ConfigSection::Credentials)
                        if credential_source.as_deref() == Some(local.as_str()) =>
                    {
                        credential_source = None;
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    out
}

fn decode_attr(raw: &str) -> String {
    quick_xml::escape::unescape(raw)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| raw.to_string())
}

/// Validates one raw `<add>` entry, logging at `debug!` (an unsupported-but-legitimate shape:
/// V2 protocol, a local/UNC path) or `warn!` (a genuinely malformed/blocked value).
fn resolve_source_entry(add: &RawSourceAdd, policy: &RegistryAccessPolicy) -> InvalidOrValid {
    if add.protocol_version.as_deref() == Some("2") {
        tracing::debug!(
            key = %add.key,
            "skipping NuGet V2 (protocolVersion=\"2\") package source; only V3 feeds are supported"
        );
        return Err(InvalidEntry {
            raw: redact_userinfo(&add.value),
            reason: NuGetFeedUrlError::UnsupportedProtocolVersion("2".to_string()),
        });
    }
    if !add.value.contains("://") {
        tracing::debug!(
            key = %add.key,
            value = %add.value,
            "skipping local/UNC NuGet package source; only V3 http(s) feeds are supported"
        );
        return Err(InvalidEntry {
            raw: redact_userinfo(&add.value),
            reason: NuGetFeedUrlError::LocalFeedUnsupported,
        });
    }
    NuGetFeedUrl::new(&add.value, policy).map_err(|reason| {
        let redacted = redact_userinfo(&add.value);
        tracing::warn!(key = %add.key, raw = %redacted, %reason, "NuGet package source failed validation");
        InvalidEntry {
            raw: redacted,
            reason,
        }
    })
}

type InvalidOrValid = Result<NuGetFeedUrl, InvalidEntry>;

fn upsert_source(
    sources: &mut Vec<PackageSourceEntry>,
    add: &RawSourceAdd,
    policy: &RegistryAccessPolicy,
) {
    let value = resolve_source_entry(add, policy);
    // LOW (security review): use the same `key_candidates_overlap` union funnel as every
    // other key comparison in this module (documented invariant at this module's
    // `PackageSourceEntry` doc) — raw-lowercase-only comparison here would let
    // `key="Corp Feed"` in one ancestor file and `key="Corp_x0020_Feed"` in another produce
    // two entries instead of correctly upserting one.
    if let Some(existing) = sources
        .iter_mut()
        .find(|s| key_candidates_overlap(&s.key, &add.key))
    {
        existing.value = value;
    } else {
        sources.push(PackageSourceEntry {
            key: add.key.clone(),
            value,
        });
    }
}

/// Per-`NuGet.Config`-file-path memoization.
///
/// Mirrors `deps_npm::config::NpmConfigCache` exactly in shape. Caches **raw, unvalidated**
/// entries — URL validation and policy gating re-run per parse against these cached entries,
/// so a `didChangeConfiguration` policy change takes effect immediately with no cache
/// invalidation of its own.
#[derive(Debug)]
pub struct NuGetConfigCache(deps_core::MtimeFileCache<RawNuGetConfigFile>);

impl Default for NuGetConfigCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NuGetConfigCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self(deps_core::MtimeFileCache::new(
            deps_core::DEFAULT_MAX_CACHED_FILES,
            "nuget config",
        ))
    }

    fn get_or_parse(&self, path: &Path) -> Option<Arc<RawNuGetConfigFile>> {
        self.0.get_or_parse(path, parse_nuget_config_raw)
    }
}

/// Owned by `NuGetEcosystem`, shared across every document it parses.
#[derive(Debug, Clone, Default)]
pub struct NuGetParseContext {
    /// Gates every workspace-declared [`NuGetFeedUrl`] this parse constructs.
    pub policy: Arc<RegistryAccessPolicy>,
    /// Memoizes each distinct `NuGet.Config` file's raw, unvalidated contents.
    pub config_cache: Arc<NuGetConfigCache>,
}

/// Resolves `manifest_dir`'s in-repo `NuGet.Config` ancestor chain into a merged
/// [`NuGetConfig`] (FR-001/FR-002, C1's root-to-leaf accumulation).
#[must_use]
pub fn resolve(
    manifest_dir: &Path,
    config_cache: &NuGetConfigCache,
    policy: &RegistryAccessPolicy,
) -> NuGetConfig {
    let mut ancestors: Vec<Arc<RawNuGetConfigFile>> = Vec::new();
    let mut current: Option<&Path> = Some(manifest_dir);
    let mut depth = 0usize;
    while let Some(dir) = current {
        if depth >= MAX_CONFIG_ANCESTOR_DEPTH {
            break;
        }
        depth += 1;

        for name in CONFIG_FILENAMES {
            let candidate: PathBuf = dir.join(name);
            if candidate.is_file() {
                if let Some(parsed) = config_cache.get_or_parse(&candidate) {
                    ancestors.push(parsed);
                }
                break;
            }
        }

        current = dir.parent();
    }

    let mut sources: Vec<PackageSourceEntry> = Vec::new();
    let mut cleared = false;
    let mut nuget_org_removed = false;
    let mut disabled_raw: Vec<(String, String)> = Vec::new();
    let mut credentialed_raw: Vec<String> = Vec::new();
    let mut mapping = PackageSourceMapping::default();

    // C1: apply root -> leaf (reverse of the leaf-to-root discovery order above). `cleared`
    // is sticky for the rest of the walk once set — see this module's doc.
    for file in ancestors.iter().rev() {
        if file.sources_cleared {
            sources.clear();
            cleared = true;
        }
        for add in &file.sources {
            upsert_source(&mut sources, add, policy);
        }
        // S4 fix (impl-critic): `<remove key="..."/>` removes a source accumulated so far
        // (this file's own `<add>`s or an inherited ancestor entry) — without this, an
        // explicitly removed `nuget.org`/private source stayed reachable, the same #248-class
        // silent-inclusion bug this feature exists to close in the opposite direction.
        for key in &file.removed {
            sources.retain(|s| !key_candidates_overlap(&s.key, key));
            if key.eq_ignore_ascii_case("nuget.org") {
                nuget_org_removed = true;
            }
        }
        disabled_raw.extend(file.disabled.iter().cloned());
        credentialed_raw.extend(file.credentialed_keys.iter().cloned());
        for (source_key, patterns) in &file.mapping {
            mapping.extend(source_key, patterns);
        }
    }

    let mut disabled_keys: HashSet<String> = HashSet::new();
    for (key, value) in &disabled_raw {
        if value.eq_ignore_ascii_case("true") {
            disabled_keys.extend(key_candidates(key));
        }
    }
    let mut credentialed_keys: HashSet<String> = HashSet::new();
    for key in &credentialed_raw {
        credentialed_keys.extend(key_candidates(key));
    }

    for entry in &mut sources {
        if entry.value.is_err() {
            continue;
        }
        let candidates = key_candidates(&entry.key);
        let is_credentialed = candidates.iter().any(|c| credentialed_keys.contains(c));
        let is_disabled = candidates.iter().any(|c| disabled_keys.contains(c));
        if is_credentialed || is_disabled {
            let raw = match &entry.value {
                Ok(url) => url.as_str().to_string(),
                Err(invalid) => invalid.raw.clone(),
            };
            let reason = if is_credentialed {
                NuGetFeedUrlError::HasCredentials
            } else {
                NuGetFeedUrlError::Disabled
            };
            entry.value = Err(InvalidEntry { raw, reason });
        }
    }

    NuGetConfig {
        sources,
        cleared,
        nuget_org_removed,
        mapping,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::net_policy::WorkspaceRegistryAccess;

    fn all_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)
    }

    fn pkg(name: &str) -> PackageName {
        PackageName::new(name)
    }

    fn write_config(dir: &Path, content: &str) {
        std::fs::write(dir.join("NuGet.Config"), content).unwrap();
    }

    // --- NuGetFeedUrl ---

    #[test]
    fn test_feed_url_accepts_https() {
        let policy = all_policy();
        assert!(NuGetFeedUrl::new("https://feed.mycorp.example/v3/index.json", &policy).is_ok());
    }

    #[test]
    fn test_feed_url_rejects_userinfo() {
        let policy = all_policy();
        assert!(matches!(
            NuGetFeedUrl::new("https://user:pass@feed.example/v3/index.json", &policy),
            Err(NuGetFeedUrlError::UserInfoPresent)
        ));
    }

    #[test]
    fn test_feed_url_normalizes_trailing_slash() {
        let policy = all_policy();
        let a = NuGetFeedUrl::new("https://feed.example/v3/index.json/", &policy).unwrap();
        let b = NuGetFeedUrl::new("https://feed.example/v3/index.json", &policy).unwrap();
        assert_eq!(a, b);
    }

    // --- decode_xml_name / key_candidates (C3) ---

    #[test]
    fn test_decode_xml_name_space() {
        assert_eq!(decode_xml_name("Corp_x0020_Feed"), "Corp Feed");
    }

    #[test]
    fn test_decode_xml_name_literal_underscore() {
        assert_eq!(decode_xml_name("Corp_x005F_Feed"), "Corp_Feed");
    }

    #[test]
    fn test_decode_xml_name_no_escapes_is_identity() {
        assert_eq!(decode_xml_name("CorpFeed"), "CorpFeed");
    }

    #[test]
    fn test_key_candidates_overlap_case_insensitive() {
        assert!(key_candidates_overlap("CorpFeed", "corpfeed"));
    }

    #[test]
    fn test_key_candidates_overlap_decoded_form() {
        assert!(key_candidates_overlap("Corp_x0020_Feed", "Corp Feed"));
    }

    // --- resolve_mapping_source_key (R2) ---

    fn source(key: &str, url: &str, policy: &RegistryAccessPolicy) -> PackageSourceEntry {
        PackageSourceEntry {
            key: key.to_string(),
            value: NuGetFeedUrl::new(url, policy).map_err(|reason| InvalidEntry {
                raw: url.to_string(),
                reason,
            }),
        }
    }

    #[test]
    fn test_resolve_mapping_source_key_unique_match() {
        let policy = all_policy();
        let sources = vec![source(
            "CorpFeed",
            "https://corp.example/v3/index.json",
            &policy,
        )];
        assert!(resolve_mapping_source_key("CorpFeed", &sources).is_some());
        assert!(resolve_mapping_source_key("corpfeed", &sources).is_some());
    }

    #[test]
    fn test_resolve_mapping_source_key_absent_source_is_none() {
        let sources: Vec<PackageSourceEntry> = Vec::new();
        assert!(resolve_mapping_source_key("Missing", &sources).is_none());
    }

    /// R2: an ambiguous union match (two declared sources whose raw/decoded candidates both
    /// cover the mapping key) must resolve to nothing, not fan out to both.
    #[test]
    fn test_resolve_mapping_source_key_ambiguous_is_none() {
        let policy = all_policy();
        let sources = vec![
            source(
                "Corp_x0020_Feed",
                "https://a.example/v3/index.json",
                &policy,
            ),
            source("Corp Feed", "https://b.example/v3/index.json", &policy),
        ];
        assert!(resolve_mapping_source_key("Corp Feed", &sources).is_none());
    }

    // --- NuGetConfig::resolve_source_for: plain (non-mapping) chain ---

    #[test]
    fn test_no_config_resolves_to_plain_registry() {
        let config = NuGetConfig::default();
        assert_eq!(
            config.resolve_source_for(&pkg("Newtonsoft.Json")),
            DependencySource::Registry
        );
        assert!(config.resolved_chains().is_empty());
    }

    #[test]
    fn test_single_alternate_source_no_clear_appends_implicit_public_fallback() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        let source = config.resolve_source_for(&pkg("Any.Package"));
        assert!(matches!(source, DependencySource::AlternateRegistry { .. }));
        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 1);
        assert!(chains[0].implicit_public_fallback);
    }

    #[test]
    fn test_clear_suppresses_implicit_public_fallback() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <clear />
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert!(!chains[0].implicit_public_fallback);
    }

    /// R4: `<clear/>` with nothing re-added must be an explicit fail-closed
    /// `CustomRegistry`, never a fall-through to plain `Registry`.
    #[test]
    fn test_clear_with_nothing_readded_is_explicit_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            "<configuration><packageSources><clear /></packageSources></configuration>",
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        let source = config.resolve_source_for(&pkg("Any.Package"));
        assert_eq!(
            source,
            DependencySource::CustomRegistry {
                url: NO_SOURCES_CONFIGURED_SENTINEL.to_string(),
            }
        );
        assert!(config.resolved_chains().is_empty());
    }

    /// C1: a root `<clear/>` + CorpFeed, with a leaf adding a second feed and no `<clear/>`
    /// of its own, must never resurrect the implicit `nuget.org` hop (the #248 bug class).
    #[test]
    fn test_c1_root_clear_survives_leaf_without_clear() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("src").join("App");
        std::fs::create_dir_all(&leaf).unwrap();
        write_config(
            root.path(),
            r#"<configuration><packageSources>
                <clear />
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        write_config(
            &leaf,
            r#"<configuration><packageSources>
                <add key="SecondFeed" value="https://second.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(&leaf, &cache, &policy);

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert!(!chains[0].implicit_public_fallback);
        assert_eq!(chains[0].hops.len(), 2);
        assert_eq!(
            chains[0].hops[0].as_str(),
            "https://corp.example/v3/index.json"
        );
        assert_eq!(
            chains[0].hops[1].as_str(),
            "https://second.example/v3/index.json"
        );
    }

    /// A leaf `<clear/>` must still be able to wipe an ancestor's feed (the reverse
    /// direction) — sticky-`cleared` is not a one-way ratchet against the leaf itself.
    #[test]
    fn test_leaf_clear_wipes_ancestor_source() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("src").join("App");
        std::fs::create_dir_all(&leaf).unwrap();
        write_config(
            root.path(),
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        write_config(
            &leaf,
            "<configuration><packageSources><clear /></packageSources></configuration>",
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(&leaf, &cache, &policy);

        assert!(config.resolved_chains().is_empty());
        assert_eq!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::CustomRegistry {
                url: NO_SOURCES_CONFIGURED_SENTINEL.to_string(),
            }
        );
    }

    // --- disabled / credentialed (C3, FR-004/FR-009) ---

    #[test]
    fn test_disabled_source_case_insensitive_key_match() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <disabledPackageSources>
                    <add key="corpfeed" value="True" />
                </disabledPackageSources>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert!(config.resolved_chains().is_empty());
        assert_eq!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::Registry
        );
    }

    #[test]
    fn test_credentialed_source_dropped_with_decoded_name_match() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSources>
                    <add key="Corp Feed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <packageSourceCredentials>
                    <Corp_x0020_Feed>
                        <add key="Username" value="user" />
                        <add key="ClearTextPassword" value="pass" />
                    </Corp_x0020_Feed>
                </packageSourceCredentials>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert!(config.resolved_chains().is_empty());
    }

    // --- packageSourceMapping (C2/R1/R3) ---

    #[test]
    fn test_mapping_unmatched_package_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <packageSourceMapping>
                    <packageSource key="CorpFeed">
                        <package pattern="MyCompany.*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert_eq!(
            config.resolve_source_for(&pkg("Unrelated.Package")),
            DependencySource::CustomRegistry {
                url: "Unrelated.Package".to_string(),
            }
        );
    }

    #[test]
    fn test_mapping_matched_private_pattern_never_falls_back_to_public() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
                </packageSources>
                <packageSourceMapping>
                    <packageSource key="CorpFeed">
                        <package pattern="MyCompany.*" />
                    </packageSource>
                    <packageSource key="nuget.org">
                        <package pattern="*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        let source = config.resolve_source_for(&pkg("MyCompany.Internal"));
        let DependencySource::AlternateRegistry { index, .. } = source else {
            panic!("expected AlternateRegistry, private package must never route to nuget.org");
        };
        let chains = config.resolved_chains();
        let chain = chains.iter().find(|c| c.key == index).unwrap();
        assert_eq!(chain.hops.len(), 1);
        assert_eq!(chain.hops[0].as_str(), "https://corp.example/v3/index.json");
        assert!(!chain.implicit_public_fallback);
    }

    /// R3: a package whose winning pattern maps only to the *real* nuget.org source (by
    /// normalized URL, not by key name) resolves to plain `Registry` — keeping OSV/deps.dev.
    #[test]
    fn test_mapping_public_only_pattern_resolves_to_plain_registry() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSources>
                    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
                </packageSources>
                <packageSourceMapping>
                    <packageSource key="nuget.org">
                        <package pattern="*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert_eq!(
            config.resolve_source_for(&pkg("Newtonsoft.Json")),
            DependencySource::Registry
        );
        assert!(config.resolved_chains().is_empty());
    }

    /// R3: a hostile config naming a private feed `nuget.org` must not be mistaken for the
    /// real public registry — identification is by normalized URL, never by key.
    #[test]
    fn test_mapping_source_named_nuget_org_but_different_url_is_not_public() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSources>
                    <add key="nuget.org" value="https://evil.example/v3/index.json" />
                </packageSources>
                <packageSourceMapping>
                    <packageSource key="nuget.org">
                        <package pattern="*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert!(matches!(
            config.resolve_source_for(&pkg("Newtonsoft.Json")),
            DependencySource::AlternateRegistry { .. }
        ));
    }

    /// R1 counterexample from the critic review: a root mapping `{CorpFeed: MyCompany.*,
    /// nuget.org: *}` merged with a leaf mapping `{nuget.org: *}` must still route
    /// `MyCompany.Internal` to CorpFeed — "nearest file wins" would leak it to nuget.org.
    #[test]
    fn test_r1_mapping_merges_across_ancestor_and_leaf_not_nearest_wins() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("src").join("App");
        std::fs::create_dir_all(&leaf).unwrap();
        write_config(
            root.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
                </packageSources>
                <packageSourceMapping>
                    <packageSource key="CorpFeed">
                        <package pattern="MyCompany.*" />
                    </packageSource>
                    <packageSource key="nuget.org">
                        <package pattern="*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        write_config(
            &leaf,
            r#"<configuration>
                <packageSourceMapping>
                    <packageSource key="nuget.org">
                        <package pattern="*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(&leaf, &cache, &policy);

        let source = config.resolve_source_for(&pkg("MyCompany.Internal"));
        let DependencySource::AlternateRegistry { index, .. } = source else {
            panic!("R1 regression: MyCompany.Internal leaked to nuget.org via nearest-wins");
        };
        let chains = config.resolved_chains();
        let chain = chains.iter().find(|c| c.key == index).unwrap();
        assert_eq!(chain.hops[0].as_str(), "https://corp.example/v3/index.json");

        // The unrelated public package must still resolve via the merged `*` -> nuget.org
        // mapping, unaffected by the merge.
        assert_eq!(
            config.resolve_source_for(&pkg("Newtonsoft.Json")),
            DependencySource::Registry
        );
    }

    // --- protocolVersion / local feeds ---

    #[test]
    fn test_protocol_version_2_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <add key="Legacy" value="https://legacy.example/api/v2" protocolVersion="2" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert!(config.resolved_chains().is_empty());
        assert_eq!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::Registry
        );
    }

    #[test]
    fn test_local_feed_path_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <add key="Local" value="../packages" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert!(config.resolved_chains().is_empty());
    }

    // --- chain key invariant ---

    #[test]
    fn test_resolve_source_for_and_resolved_chains_agree_on_key() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        let DependencySource::AlternateRegistry { index, .. } =
            config.resolve_source_for(&pkg("Any.Package"))
        else {
            panic!("expected AlternateRegistry");
        };
        assert_eq!(config.resolved_chains()[0].key, index);
    }

    // --- NuGetConfigCache ---

    #[test]
    fn test_config_cache_reparses_after_mtime_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("NuGet.Config");
        std::fs::write(
            &path,
            r#"<configuration><packageSources><add key="A" value="https://a.example/v3/index.json" /></packageSources></configuration>"#,
        )
        .unwrap();
        let cache = NuGetConfigCache::new();
        let first = cache.get_or_parse(&path).unwrap();
        assert_eq!(first.sources.len(), 1);

        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::write(
            &path,
            r#"<configuration><packageSources>
                <add key="A" value="https://a.example/v3/index.json" />
                <add key="B" value="https://b.example/v3/index.json" />
            </packageSources></configuration>"#,
        )
        .unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(future)
            .unwrap();

        let second = cache.get_or_parse(&path).unwrap();
        assert_eq!(second.sources.len(), 2);
    }

    #[test]
    fn test_resolve_with_no_config_anywhere_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);
        assert!(config.resolved_chains().is_empty());
        assert_eq!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::Registry
        );
    }

    // --- H1: malformed XML degrades to the all-default RawNuGetConfigFile ---

    /// A mistyped closing tag after `<packageSources>` must not silently drop
    /// `<packageSourceCredentials>`/`<disabledPackageSources>`/`<packageSourceMapping>` that
    /// would otherwise have followed — the whole file degrades to empty (fail closed in the
    /// safe direction: a broken file behaves as if it declared nothing, never as if it
    /// declared only the part before the break).
    #[test]
    fn test_h1_malformed_xml_degrades_to_all_default_not_partial() {
        let raw = parse_nuget_config_raw(
            r#"<configuration><packageSources>
                <clear />
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSource></configuration>"#,
        );
        assert!(!raw.sources_cleared);
        assert!(raw.sources.is_empty());
    }

    #[test]
    fn test_h1_malformed_config_file_resolves_as_if_absent() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <clear />
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSource></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);
        assert!(config.resolved_chains().is_empty());
        assert_eq!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::Registry
        );
    }

    // --- S2: a self-closing section element must not latch parser state ---

    #[test]
    fn test_s2_self_closing_credentials_section_does_not_swallow_later_elements() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSourceCredentials />
                <packageSources>
                    <clear />
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1, "packageSources must not be swallowed");
        assert!(!chains[0].implicit_public_fallback);
    }

    #[test]
    fn test_s2_self_closing_sources_section_does_not_latch() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSources />
                <disabledPackageSources>
                    <add key="CorpFeed" value="true" />
                </disabledPackageSources>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        // The disabled entry must actually be recognized as disabled (proving
        // `disabledPackageSources` was reached as its own section, not folded into a latched
        // `packageSources` state), so CorpFeed contributes nothing and the implicit public
        // default remains.
        assert!(config.resolved_chains().is_empty());
        assert_eq!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::Registry
        );
    }

    // --- S1: a packageSourceMapping key naming the undeclared implicit nuget.org ---

    #[test]
    fn test_s1_mapping_undeclared_nuget_org_key_falls_back_to_real_public_source() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <packageSourceMapping>
                    <packageSource key="CorpFeed">
                        <package pattern="MyCompany.*" />
                    </packageSource>
                    <packageSource key="nuget.org">
                        <package pattern="*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        // The near-universal real-world shape: nuget.org itself lives in the machine/user
        // config this feature does not read, so it is never a declared `PackageSourceEntry`
        // here — without the S1 fix this would fail every public package closed.
        assert_eq!(
            config.resolve_source_for(&pkg("Newtonsoft.Json")),
            DependencySource::Registry
        );
        // The private pattern must still route to CorpFeed, unaffected.
        assert!(matches!(
            config.resolve_source_for(&pkg("MyCompany.Internal")),
            DependencySource::AlternateRegistry { .. }
        ));
    }

    #[test]
    fn test_s1_mapping_undeclared_key_other_than_nuget_org_still_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSourceMapping>
                    <packageSource key="SomeOtherUndeclaredFeed">
                        <package pattern="*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert_eq!(
            config.resolve_source_for(&pkg("Newtonsoft.Json")),
            DependencySource::CustomRegistry {
                url: "Newtonsoft.Json".to_string(),
            }
        );
    }

    // --- S4: <remove key="..."/> ---

    #[test]
    fn test_s4_remove_excludes_previously_declared_source() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                <remove key="CorpFeed" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert!(config.resolved_chains().is_empty());
        assert_eq!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::Registry
        );
    }

    #[test]
    fn test_s4_remove_across_ancestor_files() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("src").join("App");
        std::fs::create_dir_all(&leaf).unwrap();
        write_config(
            root.path(),
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        write_config(
            &leaf,
            r#"<configuration><packageSources>
                <remove key="CorpFeed" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(&leaf, &cache, &policy);

        assert!(config.resolved_chains().is_empty());
        assert_eq!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::Registry
        );
    }

    /// `<remove key="nuget.org"/>` with no `<clear/>` must suppress the implicit public
    /// fallback too — the same #248-class bug in the opposite direction (an explicitly
    /// removed public source staying reachable).
    #[test]
    fn test_s4_remove_nuget_org_suppresses_implicit_fallback() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <remove key="nuget.org" />
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert!(
            !chains[0].implicit_public_fallback,
            "explicitly-removed nuget.org must not be resurrected as the implicit tail"
        );
    }

    /// `<remove key="nuget.org"/>` alone, with no other source declared, must fail closed —
    /// not silently degrade to plain `Registry` the way "nothing declared at all" does.
    #[test]
    fn test_s4_remove_nuget_org_alone_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <remove key="nuget.org" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert!(config.resolved_chains().is_empty());
        assert!(matches!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::CustomRegistry { .. }
        ));
    }

    // --- M2: plain-chain path treats a public-only hop like the mapping path does ---

    #[test]
    fn test_m2_explicit_clear_plus_nuget_org_add_resolves_to_plain_registry() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration><packageSources>
                <clear />
                <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert_eq!(
            config.resolve_source_for(&pkg("Newtonsoft.Json")),
            DependencySource::Registry
        );
        assert!(config.resolved_chains().is_empty());
    }

    // --- resolve_keys_for: genuine pattern competition (tester gap #3) ---

    #[test]
    fn test_resolve_keys_for_exact_beats_longer_prefix() {
        let mut mapping = PackageSourceMapping::default();
        mapping.extend("ExactSource", &["MyCompany.Foo".to_string()]);
        mapping.extend("PrefixSource", &["MyCompany.*".to_string()]);

        let keys = mapping.resolve_keys_for("mycompany.foo").unwrap();
        assert_eq!(keys, vec!["ExactSource"]);
    }

    #[test]
    fn test_resolve_keys_for_longer_prefix_beats_shorter_prefix() {
        let mut mapping = PackageSourceMapping::default();
        mapping.extend("ShortPrefix", &["My.*".to_string()]);
        mapping.extend("LongPrefix", &["My.Company.*".to_string()]);

        let keys = mapping.resolve_keys_for("my.company.internal").unwrap();
        assert_eq!(keys, vec!["LongPrefix"]);
    }

    #[test]
    fn test_resolve_keys_for_prefix_beats_wildcard() {
        let mut mapping = PackageSourceMapping::default();
        mapping.extend("Wildcard", &["*".to_string()]);
        mapping.extend("Prefix", &["My.*".to_string()]);

        let keys = mapping.resolve_keys_for("my.internal").unwrap();
        assert_eq!(keys, vec!["Prefix"]);
    }

    /// A genuine tie (identical pattern text declared for two different sources — the only
    /// way a tie can occur, since two distinct pattern texts can never score equal against
    /// the same candidate name) makes both sources eligible.
    #[test]
    fn test_resolve_keys_for_tie_on_identical_pattern_fans_out() {
        let mut mapping = PackageSourceMapping::default();
        mapping.extend("SourceA", &["*".to_string()]);
        mapping.extend("SourceB", &["*".to_string()]);

        let mut keys = mapping.resolve_keys_for("any.package").unwrap();
        keys.sort_unstable();
        assert_eq!(keys, vec!["SourceA", "SourceB"]);
    }

    // --- R4 mapping-side empty state (tester gap #4) ---

    /// A package's winning `<packageSourceMapping>` pattern resolves only to a source that
    /// was then filtered out as disabled — must fail closed, never fall through to any other
    /// source or to plain `Registry`.
    #[test]
    fn test_r4_mapping_winning_pattern_resolves_only_to_disabled_source() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <disabledPackageSources>
                    <add key="CorpFeed" value="true" />
                </disabledPackageSources>
                <packageSourceMapping>
                    <packageSource key="CorpFeed">
                        <package pattern="MyCompany.*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(dir.path(), &cache, &policy);

        assert_eq!(
            config.resolve_source_for(&pkg("MyCompany.Internal")),
            DependencySource::CustomRegistry {
                url: "MyCompany.Internal".to_string(),
            }
        );
        assert!(config.resolved_chains().is_empty());
    }

    // --- LOW: upsert_source dedupes through the same key_candidates union as elsewhere ---

    #[test]
    fn test_upsert_source_dedupes_across_xml_encoded_key_variants() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("src").join("App");
        std::fs::create_dir_all(&leaf).unwrap();
        write_config(
            root.path(),
            r#"<configuration><packageSources>
                <add key="Corp Feed" value="https://old.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        write_config(
            &leaf,
            r#"<configuration><packageSources>
                <add key="Corp_x0020_Feed" value="https://new.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve(&leaf, &cache, &policy);

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(
            chains[0].hops.len(),
            1,
            "XML-name-equivalent keys must upsert into one entry, not two"
        );
        assert_eq!(
            chains[0].hops[0].as_str(),
            "https://new.example/v3/index.json"
        );
    }
}
