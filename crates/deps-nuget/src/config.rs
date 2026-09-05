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
//!   explicitly cleared (the #248 bug class). See [`resolve_with_context`]'s accumulation loop.
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
use std::sync::atomic::AtomicBool;

use base64::Engine;
use deps_core::PackageName;
use deps_core::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH;
use deps_core::net_policy::{
    IndexUrlError, PolicyGate, RegistryAccessPolicy, redact_userinfo, validate_index_url,
};
use deps_core::parser::DependencySource;
use quick_xml::Reader;
use quick_xml::events::Event;
use zeroize::Zeroizing;

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
    /// A DPAPI-encrypted `<Password>` credential value (issue #561, FR-003) — Windows-only,
    /// `CryptUnprotectData`-dependent, not portably decryptable. Permanently out of scope;
    /// rejected at parse time rather than attempting decryption or silently dropping it.
    #[error("DPAPI-encrypted <Password> credentials are not supported")]
    EncryptedPasswordUnsupported,
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

/// Which tier a parsed `NuGet.Config` file came from (issue #561, FR-001).
///
/// Diagnostics/gating metadata only — mirrors `deps_cargo::config::Provenance`'s "nothing
/// branches on this to *widen* trust" invariant. In particular, [`PackageSourceEntry::tier`]
/// is **not** consulted by the credential-binding logic in [`resolve_with_context`] (see that function's
/// docs, §C2) — only by the [`resolve_with_context`] accumulation loop's own gate (which contribution half
/// applies) and by `tracing::debug!` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigTier {
    /// A user-profile-tier `NuGet.Config` (issue #561, FR-001) — not something a cloned
    /// repository controls.
    UserProfile,
    /// An in-repo `NuGet.Config`, discovered by the ancestor walk (spec 035 FR-001) —
    /// attacker-controlled the moment a hostile repository is opened.
    Repo,
}

/// A pre-formatted `Basic base64(username:password)` `Authorization` header value (issue #561).
///
/// Redacted everywhere except the one call site (`crate::registry::NuGetRegistry::fetch`) that
/// reads it into a request header. Constructible only from within this crate (see this
/// module's security-model doc) and deliberately does **not** derive `Hash` — making "a fully
/// expanded, ready-to-send `Authorization` credential inside a hash key" a compile error rather
/// than a review item for *this type specifically* (NFR-001/FR-016), not a blanket
/// no-credential-derives-`Hash` rule for the module — see this module's private
/// `RedactedSecret` type's own `Hash` derive for the (deliberately different, and
/// narrower-risk) case that one exists for. Never stores the username/password separately once
/// constructed.
///
/// A thin wrapper over [`deps_core::secret::Redacted`] rather than a bare type alias:
/// `Debug` prints `NuGetAuth(***)`, not `Redacted(***)`, so a panic message or log line
/// still names which credential leaked its type.
#[derive(Clone, PartialEq, Eq)]
pub struct NuGetAuth(deps_core::secret::Redacted);

impl NuGetAuth {
    /// Formats `username`/`password` into a `Basic` header value. `pub(crate)`: only
    /// [`resolve_with_context`]'s final C2 pass, gated on [`ConfigTier::UserProfile`], ever constructs one.
    ///
    /// Every intermediate (the raw `user:pass` string, and the base64 encoding of it —
    /// reversible, not encryption) is held in [`Zeroizing`] from the point of construction,
    /// not just the final header value, so no un-zeroized plaintext copy is left behind.
    pub(crate) fn new(username: &str, password: &str) -> Self {
        let mut user_pass =
            Zeroizing::new(String::with_capacity(username.len() + 1 + password.len()));
        user_pass.push_str(username);
        user_pass.push(':');
        user_pass.push_str(password);
        let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*user_pass));
        Self(deps_core::secret::Redacted::new(format!(
            "Basic {}",
            *encoded
        )))
    }

    /// The pre-formatted header value. Never logged, printed, or otherwise surfaced — callers
    /// must not pass this to anything but an `Authorization` header.
    pub(crate) fn header_value(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for NuGetAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NuGetAuth(***)")
    }
}

impl std::fmt::Display for NuGetAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// A `<packageSourceCredentials>` `Username`/`ClearTextPassword` literal, held **pre-%ENV_VAR%-
/// expansion** (issue #561, FR-002) — redacted everywhere except [`resolve_with_context`]'s final pass,
/// which expands and consumes it into a [`NuGetAuth`].
///
/// Unlike [`NuGetAuth`] (which deliberately does not derive `Hash`, see its doc), this type
/// does — exempt from that concern because its only `Hash` use is
/// `resolve_with_context`'s `config_fingerprint` (via `RawCredential`/`RawNuGetConfigFile`),
/// a process-local `u64` debounce key for [`fail_closed`]'s warning dedup. That key is never
/// logged, serialized, sent over the wire, or compared across processes — only inserted into an
/// in-memory `DashSet` for the lifetime of one server run — so hashing a still-unexpanded,
/// pre-`%ENV_VAR%` literal into it carries none of the "credential reaches a place it
/// shouldn't" risk the `NuGetAuth` restriction guards against.
///
/// A thin wrapper over [`deps_core::secret::Redacted`] rather than a bare type alias:
/// `Debug` prints `RedactedSecret(***)`, not `Redacted(***)`. `Redacted<T>`'s own `Hash` impl
/// (opt-in via `T: Hash`) is what makes the derive below possible without reaching around the
/// wrapper's redaction/zeroize guarantees.
#[derive(Clone, PartialEq, Eq, Hash)]
struct RedactedSecret(deps_core::secret::Redacted);

impl RedactedSecret {
    fn new(value: String) -> Self {
        Self(deps_core::secret::Redacted::new(value))
    }

    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactedSecret(***)")
    }
}

impl std::fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
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
    /// Which tier's file last set [`Self::value`] (issue #561) — diagnostics/gating metadata
    /// only, see [`ConfigTier`]'s doc for the "never a credential gate" invariant.
    pub tier: ConfigTier,
    /// Set only by [`resolve_with_context`]'s final C2 pass, gated on [`ConfigTier::UserProfile`] — never
    /// during accumulation (`upsert_source` always writes `None` here; see its doc).
    pub auth: Option<NuGetAuth>,
}

/// One resolved hop in a [`NuGetSourceChain`] (issue #561, FR-016).
///
/// Replaces the plain `NuGetFeedUrl` a hop used to be, so `NuGetConfig::resolve_source_for` and
/// `NuGetConfig::resolved_chains` (both of which reach `NuGetSourceChain::chain` exclusively
/// through `NuGetConfig::valid_hops`/`NuGetConfig::hops_for_mapping_keys`) necessarily agree on
/// each hop's credential data — there is no second, independently-maintained argument for it to
/// disagree with.
#[derive(Debug, Clone)]
pub struct ResolvedHop {
    pub url: NuGetFeedUrl,
    /// The lowercased declared `<add key>` that supplied [`Self::auth`], or `None` when this
    /// hop carries no credential. Used (not the credential value) by
    /// `NuGetSourceChain::chain`'s hash and by `NuGetRegistry::register_chain`'s
    /// rotation-detection, so a chain's identity is stable across a credential *value*
    /// rotation under the same declared key.
    pub slot: Option<String>,
    /// Never hashed (see `NuGetSourceChain::chain`) and never fully `Debug`-printed
    /// ([`NuGetAuth`] redacts).
    pub auth: Option<NuGetAuth>,
}

impl ResolvedHop {
    /// Two-part `&str` encoding of [`Self::slot`] for [`NuGetSourceChain::chain`]'s hash — a
    /// presence marker (`"slot"`/`"no-slot"`) followed by the slot string itself (`""` when
    /// absent). Keeping the per-hop part count constant, rather than folding presence into a
    /// single sentinel value, means no possible `<add key>` value can ever collide with the
    /// no-slot case. A dedicated accessor rather than `format!("{:?}", self.slot)`: chain
    /// identity must not depend on `Option`'s `Debug` formatting, and writing one narrow
    /// accessor per hashed field (instead of reaching for `Debug` on whatever is convenient)
    /// keeps `NuGetSourceChain::chain` from ever needing to `Debug`-format [`Self::auth`],
    /// which deliberately does not derive `Hash` (see its doc) precisely so that a credential
    /// cannot be added to this hash without a visible, deliberate type change.
    fn slot_key_parts(&self) -> [&str; 2] {
        self.slot
            .as_deref()
            .map_or(["no-slot", ""], |slot| ["slot", slot])
    }
}

/// One fully-resolved routing chain, produced by [`NuGetConfig::resolved_chains`], consumed by
/// `NuGetRegistry::register_chain`. Mirrors `deps_pypi::config::ResolvedChain` exactly.
#[derive(Debug, Clone)]
pub struct NuGetSourceChain {
    /// Opaque, hashed identity produced by [`deps_core::hash_routing_key`] (`"nuget-chain"`)
    /// over each hop's URL and [`ResolvedHop::slot`] (**never** [`ResolvedHop::auth`] — FR-016)
    /// plus [`Self::implicit_public_fallback`]. [`NuGetConfig::resolve_source_for`] and
    /// [`NuGetConfig::resolved_chains`] recompute this independently and must agree.
    pub key: String,
    /// Ordered, already-validated hops. Never empty.
    pub hops: Vec<ResolvedHop>,
    /// `true` only for the plain (non-mapping) chain when no ancestor `<clear/>` removed the
    /// implicit public fallback — the public hop is appended at registration time, never
    /// present in [`Self::hops`]. Always `false` for a `<packageSourceMapping>`-derived
    /// chain: a mapping is authoritative once it names a package, so the chain never appends
    /// the public hop even when `<clear/>` is absent (this is the dependency-confusion leak
    /// fix — see this module's doc).
    pub implicit_public_fallback: bool,
}

impl NuGetSourceChain {
    fn chain(hops: Vec<ResolvedHop>, implicit_public_fallback: bool) -> Self {
        let flag = if implicit_public_fallback {
            "true"
        } else {
            "false"
        };
        let key = deps_core::hash_routing_key(
            "nuget-chain",
            hops.iter()
                .flat_map(|hop| {
                    let [presence, slot] = hop.slot_key_parts();
                    [hop.url.as_str(), presence, slot]
                })
                .chain(std::iter::once(flag)),
        );
        Self {
            key,
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

/// Resolves `key` to *exactly one* item of `items` whose `key_of` overlaps it (§3.6, FR-009).
/// Zero matches and more-than-one match (an ambiguous union collision) both return `None` —
/// contributing nothing, rather than fanning out to every candidate. Used at exactly three
/// *inclusion* lookup sites: [`resolve_mapping_source_key`] (R2), and — in `resolve`'s final
/// C2 pass — condition (1) (credential key -> resolved entry) and condition (2) (credential key
/// -> `user_profile_add` entry). Every other [`key_candidates_overlap`] use in this module is an
/// *exclusion* lookup (disabled/credentialed membership, the §3.4 suppression set,
/// `file.removed`'s `retain`) and correctly stays a plain union match — union is the
/// fail-closed direction for an exclusion, exactly-one is the fail-closed direction for an
/// inclusion.
fn unique_overlap<'s, T>(key: &str, items: &'s [T], key_of: impl Fn(&T) -> &str) -> Option<&'s T> {
    let mut matches = items
        .iter()
        .filter(|t| key_candidates_overlap(key_of(t), key));
    let first = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(first)
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
    let resolved = unique_overlap(mapping_key, sources, |s| s.key.as_str());
    if resolved.is_none()
        && sources
            .iter()
            .any(|s| key_candidates_overlap(&s.key, mapping_key))
    {
        tracing::debug!(
            key = mapping_key,
            "packageSourceMapping key resolves to more than one declared source; treating as unresolvable"
        );
    }
    resolved
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
        if hops.len() == 1 && crate::registry::is_public_registry_url(hops[0].url.as_str()) {
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
    fn hops_for_mapping_keys(&self, keys: &[&str]) -> Vec<ResolvedHop> {
        let mut hops = Vec::new();
        for key in keys {
            let resolved = resolve_mapping_source_key(key, &self.sources)
                .and_then(|entry| {
                    entry.value.as_ref().ok().map(|url| ResolvedHop {
                        url: url.clone(),
                        slot: entry.auth.is_some().then(|| entry.key.to_lowercase()),
                        auth: entry.auth.clone(),
                    })
                })
                .or_else(|| {
                    key.eq_ignore_ascii_case("nuget.org").then(|| ResolvedHop {
                        url: NuGetFeedUrl::trusted_public(),
                        slot: None,
                        auth: None,
                    })
                });
            if let Some(hop) = resolved
                && !hops
                    .iter()
                    .any(|h: &ResolvedHop| h.url.as_str() == hop.url.as_str())
            {
                hops.push(hop);
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
        if valid_hops.len() == 1
            && crate::registry::is_public_registry_url(valid_hops[0].url.as_str())
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

    fn valid_hops(&self) -> Vec<ResolvedHop> {
        self.sources
            .iter()
            .filter_map(|s| {
                let url = s.value.as_ref().ok()?.clone();
                Some(ResolvedHop {
                    url,
                    slot: s.auth.is_some().then(|| s.key.to_lowercase()),
                    auth: s.auth.clone(),
                })
            })
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
                && crate::registry::is_public_registry_url(valid_hops[0].url.as_str());
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
                        && crate::registry::is_public_registry_url(hops[0].url.as_str()))
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
#[derive(Debug, Default, Clone, Hash)]
struct RawSourceAdd {
    key: String,
    value: String,
    protocol_version: Option<String>,
}

/// One `<packageSourceCredentials>` child element's raw, pre-expansion credential values
/// (issue #561, FR-002) — parsed unconditionally (parsing is tier-blind and memoized), but only
/// ever read by [`resolve_with_context`]'s final pass when the owning file is [`ConfigTier::UserProfile`].
#[derive(Debug, Default, Clone, Hash)]
struct RawCredential {
    /// The credential element's raw (undecoded) name — a source key, compared via
    /// [`key_candidates_overlap`] like every other source key in this module.
    key: String,
    username: Option<RedactedSecret>,
    /// `<ClearTextPassword>`.
    password: Option<RedactedSecret>,
    /// Whether a DPAPI-encrypted `<Password>` child was present (FR-003) — a distinct fail
    /// reason from a missing/absent password, never itself held as a value.
    encrypted: bool,
}

/// One `NuGet.Config` file's raw, unvalidated, un-cross-referenced contents.
///
/// Derives `Hash` (C1 fix, impl-critic follow-up on issue #576's logging) so
/// `resolve_with_context`'s `config_fingerprint` can hash the parsed *content* of every
/// ancestor file directly (`Arc<T>`'s `Hash` impl forwards to `T`, not the pointer) rather than
/// each file's `Arc` pointer address — the latter is vulnerable to allocator address reuse:
/// once an ancestor's cached `Arc` is dropped (replaced on a genuine mtime change in
/// `MtimeFileCache`), a later, *differently-content* `Arc` can be allocated at the exact same
/// address, silently colliding two distinct config states onto one fingerprint.
#[derive(Debug, Default, Clone, Hash)]
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
    /// Per-credential-element raw `Username`/`ClearTextPassword` literals (issue #561, FR-002)
    /// — one entry per element under `<packageSourceCredentials>` that had a `Start` (not
    /// self-closing) tag, in document order.
    credentials: Vec<RawCredential>,
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
                            out.credentials.push(RawCredential {
                                key: local.clone(),
                                ..Default::default()
                            });
                            credential_source = Some(local);
                        }
                    }
                    // Issue #561, FR-002/FR-003: `Username`/`ClearTextPassword`/`Password`
                    // children of an already-open credential element. Values are held
                    // pre-expansion (`RedactedSecret`) — `%ENV_VAR%` expansion happens only in
                    // `resolve`, never here (S5: the memoized raw-file parse must never hold an
                    // expanded secret, so env-var rotation is visible without an mtime change).
                    (Some(ConfigSection::Credentials), "add") if credential_source.is_some() => {
                        let mut attr_key = String::new();
                        let mut attr_value = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.local_name().as_ref() {
                                "key" => attr_key = decode_attr(&attr.value),
                                "value" => attr_value = decode_attr(&attr.value),
                                _ => {}
                            }
                        }
                        if let Some(cred) = out.credentials.last_mut() {
                            match attr_key.as_str() {
                                "Username" => {
                                    cred.username = Some(RedactedSecret::new(attr_value));
                                }
                                "ClearTextPassword" => {
                                    cred.password = Some(RedactedSecret::new(attr_value));
                                }
                                "Password" => cred.encrypted = true,
                                _ => {}
                            }
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
    tier: ConfigTier,
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
        // S1 (issue #561): whole-struct assignment — a future field addition is a compile
        // error to miss, not a silent gap. `key` is deliberately NOT rewritten (not
        // security-load-bearing; rewriting would perturb shipped `<packageSourceMapping>`
        // resolution). `auth` stays `None` here unconditionally — only `resolve`'s final C2
        // pass ever sets it, after every file's accumulation has already run.
        *existing = PackageSourceEntry {
            key: existing.key.clone(),
            value,
            tier,
            auth: None,
        };
    } else {
        sources.push(PackageSourceEntry {
            key: add.key.clone(),
            value,
            tier,
            auth: None,
        });
    }
}

/// Per-`NuGet.Config`-file-path memoization.
///
/// Mirrors `deps_npm::config::NpmConfigCache` exactly in shape. Caches **raw, unvalidated**
/// entries — URL validation and policy gating re-run per parse against these cached entries,
/// so a `didChangeConfiguration` policy change takes effect immediately with no cache
/// invalidation of its own.
/// Caps [`NuGetConfigCache::warned`] — unlike `files` (evicted per-path by
/// [`deps_core::MtimeFileCache`]'s own capacity), nothing here ever removes an individual
/// entry, since a `(config state, source, reason)` triple isn't tied to a single path that
/// could later get its own eviction hook. Reusing `DEFAULT_MAX_CACHED_FILES` as the bound keeps
/// the two caches' working-set sizes comparable without inventing a second tuning knob.
const WARNED_CAPACITY: usize = deps_core::DEFAULT_MAX_CACHED_FILES;

#[derive(Debug)]
pub struct NuGetConfigCache {
    files: deps_core::MtimeFileCache<RawNuGetConfigFile>,
    /// Dedups the fail-closed credential-binding warning (impl-critic S2 follow-up, issue
    /// #576) to once per distinct config state. Keyed on a hash combining
    /// `resolve_with_context`'s content-derived `config_fingerprint` (see
    /// [`RawNuGetConfigFile`]'s doc) with the source key and
    /// [`FailClosedCause`]/[`NuGetFeedUrlError`] discriminants — see `fail_closed`'s doc.
    ///
    /// Capped at [`WARNED_CAPACITY`] (impl-critic C1 follow-up): this set has no natural upper
    /// bound the way `files` does (one entry per path), since it grows one entry per distinct
    /// `(config state, source, reason)` triple ever observed, which for a long-lived server
    /// process is unbounded in principle. On overflow the whole set is cleared rather than
    /// LRU-evicted — simpler, and the only visible cost is a handful of warnings re-firing once
    /// after the clear, an acceptable tradeoff for a diagnostic-only signal.
    ///
    /// Deliberate, documented consequence of "once per distinct state" (impl-critic M2 note):
    /// reverting a config from X to Y and back to X does not re-warn on the revert to X, since
    /// that exact state was already seen and its hash is still in this set — only ever seeing
    /// a *new* state re-warns, not returning to an old one.
    warned: dashmap::DashSet<u64>,
}

impl Default for NuGetConfigCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NuGetConfigCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: deps_core::MtimeFileCache::new(
                deps_core::DEFAULT_MAX_CACHED_FILES,
                "nuget config",
            ),
            warned: dashmap::DashSet::new(),
        }
    }

    fn get_or_parse(&self, path: &Path) -> Option<Arc<RawNuGetConfigFile>> {
        self.files.get_or_parse(path, parse_nuget_config_raw)
    }

    /// Returns `true` the first time `key` is seen, `false` on every repeat — see
    /// [`Self::warned`]'s doc for the capacity/eviction policy.
    fn should_warn_once(&self, key: u64) -> bool {
        if self.warned.len() >= WARNED_CAPACITY && !self.warned.contains(&key) {
            self.warned.clear();
        }
        self.warned.insert(key)
    }
}

/// Owned by `NuGetEcosystem`, shared across every document it parses.
#[derive(Debug, Clone, Default)]
pub struct NuGetParseContext {
    /// Gates every workspace-declared [`NuGetFeedUrl`] this parse constructs.
    pub policy: Arc<RegistryAccessPolicy>,
    /// Memoizes each distinct `NuGet.Config` file's raw, unvalidated contents.
    pub config_cache: Arc<NuGetConfigCache>,
    /// The resolved user-profile-tier `NuGet.Config` path (issue #561, FR-001), resolved once
    /// at construction — never re-walked per parse (a profile created after server start is
    /// picked up only on restart, a documented limitation, not a bug). `None` when no
    /// candidate exists; [`NuGetParseContext::default`] leaves this `None`, so tests that
    /// don't care about the user-profile tier are unaffected.
    pub user_profile_config: Option<PathBuf>,
    /// Live-updatable `registries.nuget_user_profile_sources` setting (FR-006) — gates only the
    /// *routing* half of a user-profile file's contribution (see [`resolve_with_context`]'s doc); the
    /// credential half always applies regardless of this flag.
    pub user_profile_sources: Arc<AtomicBool>,
}

impl NuGetParseContext {
    /// Production constructor: discovers the user-profile-tier config path once (FR-001) and
    /// wires it alongside `policy`/`config_cache`/`user_profile_sources`.
    #[must_use]
    pub fn new(
        policy: Arc<RegistryAccessPolicy>,
        config_cache: Arc<NuGetConfigCache>,
        user_profile_sources: Arc<AtomicBool>,
    ) -> Self {
        Self {
            policy,
            config_cache,
            user_profile_config: discover_user_profile_config(),
            user_profile_sources,
        }
    }
}

/// FR-001: the first-existing user-profile-tier `NuGet.Config` candidate, in order — Windows
/// `%APPDATA%\NuGet\NuGet.Config`; Unix `$XDG_CONFIG_HOME/NuGet/NuGet.Config` (if set) ->
/// `~/.config/NuGet/NuGet.Config` -> `~/.nuget/NuGet/NuGet.Config`. Exactly one file, never
/// merged — mirrors [`CONFIG_FILENAMES`]'s existing first-match idiom.
fn user_profile_config_candidates(home: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if cfg!(windows) {
        if let Ok(appdata) = std::env::var("APPDATA") {
            candidates.push(PathBuf::from(appdata).join("NuGet").join("NuGet.Config"));
        }
    } else {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
            && !xdg.is_empty()
        {
            candidates.push(PathBuf::from(xdg).join("NuGet").join("NuGet.Config"));
        }
        if let Some(home) = home {
            candidates.push(home.join(".config").join("NuGet").join("NuGet.Config"));
            candidates.push(home.join(".nuget").join("NuGet").join("NuGet.Config"));
        }
    }
    candidates
}

/// [`discover_user_profile_config`], but taking `home` explicitly instead of [`dirs::home_dir`]
/// — lets tests inject a fixture home directory, mirroring `deps_npm::config::resolve_with_home`.
fn discover_user_profile_config_with_home(home: Option<PathBuf>) -> Option<PathBuf> {
    user_profile_config_candidates(home.as_deref())
        .into_iter()
        .find(|p| p.is_file())
}

/// Resolves the user-profile-tier `NuGet.Config` path once (FR-001) — call at
/// [`NuGetParseContext`] construction, never per manifest parse.
#[must_use]
fn discover_user_profile_config() -> Option<PathBuf> {
    discover_user_profile_config_with_home(dirs::home_dir())
}

/// Test-only convenience: [`NuGetEcosystem::parse_manifest`] calls [`resolve_with_context`]
/// directly, so this 3-arg form (no user-profile tier, flag off) has no production caller —
/// it exists solely to keep the 28 tests that don't exercise the user-profile path from
/// repeating its two extra always-`None`/`false` arguments. See [`resolve_with_context`] for
/// the full resolution algorithm this delegates to.
#[cfg(test)]
#[must_use]
pub(crate) fn resolve(
    manifest_dir: &Path,
    config_cache: &NuGetConfigCache,
    policy: &RegistryAccessPolicy,
) -> NuGetConfig {
    resolve_with_context(
        manifest_dir,
        config_cache,
        policy,
        None,
        &AtomicBool::new(false),
    )
}

/// Resolves `manifest_dir`'s in-repo `NuGet.Config` ancestor chain, plus the user-profile tier
/// (issue #561), into a merged [`NuGetConfig`] (FR-001/FR-002, C1's root-to-leaf accumulation).
///
/// The form `NuGetEcosystem::parse_manifest` calls, threading [`NuGetParseContext`]'s
/// `user_profile_config`/`user_profile_sources` fields through.
///
/// # Credential half vs. routing half (§3.8, FR-005/FR-006)
///
/// A [`ConfigTier::UserProfile`] file's contribution splits into two halves:
///
/// - **Credential half — always applied, regardless of `user_profile_sources`**:
///   `credentialed_keys`, the §3.4 credential-suppression set (from its own
///   `<disabledPackageSources>`), its raw `<packageSourceCredentials>` values, and
///   `user_profile_add` (its own `<clear/>`/`<add>`/`<remove>` batch, tracked separately from
///   the shared `sources` routing state).
/// - **Routing half — skipped entirely when `user_profile_sources` is false**: `sources`,
///   `sources_cleared`, `removed`/`nuget_org_removed`, `disabled`, `mapping` — all six,
///   together. With the flag off, a user-profile file's `<clear/>`/`<remove>`/
///   `<disabledPackageSources>`/`<packageSourceMapping>` reach no project at all (NFR-005).
///
/// A repo-tier file's contribution is unaffected by `user_profile_sources` and always applies
/// in full — byte-identical to spec 035.
///
/// # Credential binding (§3.2, FR-007)
///
/// The final pass, in `bind_credentials_and_finalize`, binds a user-profile credential to a
/// resolved entry `E` iff all of:
/// (0) `E.key` does not overlap the credential-suppression set (union, exclusion); (1) exactly
/// one user-profile credential's key-candidates overlap `E.key`; (2) exactly one
/// `user_profile_add` entry's key-candidates overlap that credential's own key; (3) `E`'s URL
/// equals `user_profile_add`'s URL, by normalized full-URL string equality (not origin
/// equality — see §3.2's rationale). Any credential-key match on `E` failing any condition
/// fails `E` closed as `HasCredentials`, except the FR-008 public-index carve-out. Repo-tier
/// `<packageSourceCredentials>` (FR-004) is checked first and wins unconditionally,
/// independent of any C2 outcome.
#[must_use]
pub fn resolve_with_context(
    manifest_dir: &Path,
    config_cache: &NuGetConfigCache,
    policy: &RegistryAccessPolicy,
    user_profile_config: Option<&Path>,
    user_profile_sources: &AtomicBool,
) -> NuGetConfig {
    let ancestors = collect_config_ancestors(manifest_dir, config_cache, user_profile_config);

    let user_profile_sources_enabled =
        user_profile_sources.load(std::sync::atomic::Ordering::Relaxed);

    // S2 fix (impl-critic, issue #576 follow-up): identity of the exact config state this
    // resolve is built from — see `config_ancestors_fingerprint`'s doc. Computed before the
    // tier-accumulation walk so `bind_credentials_and_finalize` can debounce its fail-closed
    // warnings against it below.
    let config_fingerprint = config_ancestors_fingerprint(&ancestors);

    let accumulated = accumulate_config_tiers(&ancestors, policy, user_profile_sources_enabled);

    bind_credentials_and_finalize(accumulated, config_cache, config_fingerprint)
}

/// Walks `manifest_dir`'s ancestor directories collecting each `NuGet.Config` found (FR-001),
/// then resolves the user-profile-tier file, if any, dropping it when it is the same file
/// (by canonicalized path) as one already found in the repo walk — a user-profile candidate
/// reachable at both tiers is treated as `Repo` (lower trust wins) rather than loaded a
/// second time under the higher-trust tier. A `canonicalize` failure on the user-profile
/// candidate itself drops it entirely (fail closed).
///
/// Returns the merged chain in leaf-to-root discovery order with the user-profile file
/// appended last, so reversing it (as [`accumulate_config_tiers`] does) processes the
/// user-profile tier first and lets any repo-tier file override it (§3.8).
fn collect_config_ancestors(
    manifest_dir: &Path,
    config_cache: &NuGetConfigCache,
    user_profile_config: Option<&Path>,
) -> Vec<(ConfigTier, Arc<RawNuGetConfigFile>)> {
    let mut repo_ancestors: Vec<Arc<RawNuGetConfigFile>> = Vec::new();
    let mut repo_paths: Vec<PathBuf> = Vec::new();
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
                    repo_ancestors.push(parsed);
                    repo_paths.push(candidate);
                }
                break;
            }
        }

        current = dir.parent();
    }

    let user_profile_file: Option<Arc<RawNuGetConfigFile>> = user_profile_config.and_then(|upc| {
        let canon = std::fs::canonicalize(upc).ok()?;
        let is_repo_dup = repo_paths
            .iter()
            .any(|p| std::fs::canonicalize(p).ok().as_deref() == Some(canon.as_path()));
        if is_repo_dup {
            return None;
        }
        config_cache.get_or_parse(&canon)
    });

    let mut ancestors: Vec<(ConfigTier, Arc<RawNuGetConfigFile>)> = repo_ancestors
        .into_iter()
        .map(|f| (ConfigTier::Repo, f))
        .collect();
    if let Some(user_file) = user_profile_file {
        ancestors.push((ConfigTier::UserProfile, user_file));
    }
    ancestors
}

/// Content-derived identity of `ancestors`' exact config state (S2 fix, impl-critic, issue
/// #576 follow-up), derived from *content* rather than `Arc` pointer address (C1 fix,
/// impl-critic follow-up — pointer identity collides once an old `Arc` is dropped and a
/// later, differently-content `Arc` is allocated at the same freed address; see
/// `RawNuGetConfigFile`'s doc). `Arc<T>`'s own `Hash` impl already forwards to `T`'s `Hash`
/// rather than hashing the pointer, so this is stable across repeat calls that hit
/// `config_cache` for every ancestor (same content, same hash) and changes the instant any
/// ancestor's parsed content actually differs. Lets [`fail_closed`] debounce its warning to
/// once per distinct config state instead of once per resolve call (this pass isn't itself
/// cached, unlike the per-file raw parse).
fn config_ancestors_fingerprint(ancestors: &[(ConfigTier, Arc<RawNuGetConfigFile>)]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for (tier, file) in ancestors {
        tier.hash(&mut hasher);
        file.hash(&mut hasher);
    }
    hasher.finish()
}

/// State [`accumulate_config_tiers`] builds while walking the merged ancestor chain root-to-
/// leaf (C1), threaded into [`bind_credentials_and_finalize`] for the credential-binding pass
/// and the final [`NuGetConfig`] assembly. Kept as one struct rather than a long parameter
/// list since every field is produced together by the same walk and consumed together by the
/// same pass.
struct AccumulatedConfig {
    sources: Vec<PackageSourceEntry>,
    cleared: bool,
    nuget_org_removed: bool,
    disabled_raw: Vec<(String, String)>,
    repo_credentialed_raw: Vec<String>,
    user_credentialed_raw: Vec<String>,
    mapping: PackageSourceMapping,
    /// Credential-half accumulators (§3.8) — populated identically regardless of
    /// `user_profile_sources`.
    user_credentials: Vec<RawCredential>,
    user_profile_add: Vec<PackageSourceEntry>,
    user_profile_credential_suppressed: HashSet<String>,
}

/// C1: applies each ancestor's contribution root -> leaf (reverse of `ancestors`' leaf-to-root
/// discovery order), accumulating package sources, `<clear/>`/`<remove>` state, disabled/
/// credentialed key sets, and `<packageSourceMapping>` into one [`AccumulatedConfig`].
///
/// A [`ConfigTier::UserProfile`] file's contribution splits into two halves (§3.8, FR-005/
/// FR-006): its credential half (`credentialed_keys`, the §3.4 suppression set, raw
/// `<packageSourceCredentials>` values, and its own `<clear/>`/`<add>`/`<remove>` batch
/// tracked separately as `user_profile_add`) always applies; its routing half (`sources`,
/// `sources_cleared`, `removed`/`nuget_org_removed`, `disabled`, `mapping`) is skipped
/// entirely when `user_profile_sources_enabled` is false (NFR-005). A repo-tier file's
/// contribution is unaffected by the flag and always applies in full. `cleared` is sticky for
/// the rest of the walk once set — see this module's doc.
fn accumulate_config_tiers(
    ancestors: &[(ConfigTier, Arc<RawNuGetConfigFile>)],
    policy: &RegistryAccessPolicy,
    user_profile_sources_enabled: bool,
) -> AccumulatedConfig {
    let mut sources: Vec<PackageSourceEntry> = Vec::new();
    let mut cleared = false;
    let mut nuget_org_removed = false;
    let mut disabled_raw: Vec<(String, String)> = Vec::new();
    let mut repo_credentialed_raw: Vec<String> = Vec::new();
    let mut user_credentialed_raw: Vec<String> = Vec::new();
    let mut mapping = PackageSourceMapping::default();

    // Credential-half accumulators (§3.8) — populated identically regardless of the flag.
    let mut user_credentials: Vec<RawCredential> = Vec::new();
    let mut user_profile_add: Vec<PackageSourceEntry> = Vec::new();
    let mut user_profile_credential_suppressed: HashSet<String> = HashSet::new();

    for (tier, file) in ancestors.iter().rev() {
        let tier = *tier;

        if tier == ConfigTier::UserProfile {
            // Credential half — always runs, regardless of `user_profile_sources` (§3.8).
            user_credentialed_raw.extend(file.credentialed_keys.iter().cloned());
            user_credentials.extend(file.credentials.iter().cloned());
            for (key, value) in &file.disabled {
                if value.eq_ignore_ascii_case("true") {
                    user_profile_credential_suppressed.extend(key_candidates(key));
                }
            }
            if file.sources_cleared {
                user_profile_add.clear();
            }
            for add in &file.sources {
                upsert_source(&mut user_profile_add, add, policy, ConfigTier::UserProfile);
            }
            for key in &file.removed {
                user_profile_add.retain(|e| !key_candidates_overlap(&e.key, key));
            }

            if !user_profile_sources_enabled {
                // Routing half skipped entirely for this file (FR-006).
                continue;
            }
        } else {
            repo_credentialed_raw.extend(file.credentialed_keys.iter().cloned());
        }

        // Routing half: repo tier always; user-profile tier only when the flag is on. Note
        // `file.disabled` is deliberately NOT added to `disabled_raw` for a user-profile-tier
        // file even here — §3.4 keeps user-profile `<disabledPackageSources>` out of the
        // machine-wide set unconditionally; it only ever feeds the suppression set above.
        if file.sources_cleared {
            sources.clear();
            cleared = true;
        }
        for add in &file.sources {
            upsert_source(&mut sources, add, policy, tier);
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
        if tier == ConfigTier::Repo {
            disabled_raw.extend(file.disabled.iter().cloned());
        }
        for (source_key, patterns) in &file.mapping {
            mapping.extend(source_key, patterns);
        }
    }

    AccumulatedConfig {
        sources,
        cleared,
        nuget_org_removed,
        disabled_raw,
        repo_credentialed_raw,
        user_credentialed_raw,
        mapping,
        user_credentials,
        user_profile_add,
        user_profile_credential_suppressed,
    }
}

/// Final pass (§3.2, FR-007): binds a user-profile credential to each resolved source entry
/// where all of conditions (0)-(3) hold (see [`resolve_with_context`]'s doc for the full
/// condition list), applying the FR-004 repo-tier-credentialed check and the FR-008 public-
/// index carve-out first, and fails an entry closed via [`fail_closed`] whenever a credential
/// match cannot be bound cleanly. Consumes `accumulated` and returns the finished
/// [`NuGetConfig`], since nothing else in [`resolve_with_context`] needs the intermediate
/// accumulator state after this point.
fn bind_credentials_and_finalize(
    mut accumulated: AccumulatedConfig,
    config_cache: &NuGetConfigCache,
    config_fingerprint: u64,
) -> NuGetConfig {
    let mut disabled_keys: HashSet<String> = HashSet::new();
    for (key, value) in &accumulated.disabled_raw {
        if value.eq_ignore_ascii_case("true") {
            disabled_keys.extend(key_candidates(key));
        }
    }
    let repo_credentialed_keys: HashSet<String> = accumulated
        .repo_credentialed_raw
        .iter()
        .flat_map(|k| key_candidates(k))
        .collect();
    let user_credentialed_keys: HashSet<String> = accumulated
        .user_credentialed_raw
        .iter()
        .flat_map(|k| key_candidates(k))
        .collect();

    for entry in &mut accumulated.sources {
        let Ok(url) = entry.value.as_ref() else {
            continue;
        };
        let resolved_url = url.as_str().to_string();
        let candidates = key_candidates(&entry.key);
        let is_disabled = candidates.iter().any(|c| disabled_keys.contains(c));
        let is_repo_credentialed = candidates
            .iter()
            .any(|c| repo_credentialed_keys.contains(c));
        let is_user_credentialed = candidates
            .iter()
            .any(|c| user_credentialed_keys.contains(c));
        let is_public = crate::registry::is_public_registry_url(&resolved_url);

        // FR-004: repo-tier `<packageSourceCredentials>` always wins, unconditionally —
        // matching spec 035 FR-009 verbatim, independent of any C2 outcome and of the FR-008
        // public-index carve-out (a repo declaring `nuget.org` under
        // `<packageSourceCredentials>` still fails closed, exactly as it did before this
        // feature).
        if is_repo_credentialed {
            fail_closed(
                entry,
                NuGetFeedUrlError::HasCredentials,
                FailClosedCause::RepoTierCredentialed,
                config_cache,
                config_fingerprint,
            );
            continue;
        }
        if is_disabled {
            fail_closed(
                entry,
                NuGetFeedUrlError::Disabled,
                FailClosedCause::MachineDisabled,
                config_cache,
                config_fingerprint,
            );
            continue;
        }
        // FR-008: the public-index carve-out — a user-profile-derived credentialed-key match
        // never forces `HasCredentials`, and never attaches, for the real public index.
        if is_public {
            continue;
        }

        match bind_user_profile_credential(
            entry,
            &accumulated.user_credentials,
            &accumulated.user_profile_add,
            &accumulated.user_profile_credential_suppressed,
            &resolved_url,
        ) {
            Some(Ok(auth)) => entry.auth = Some(auth),
            Some(Err((reason, cause))) => {
                fail_closed(entry, reason, cause, config_cache, config_fingerprint);
            }
            None if is_user_credentialed => {
                fail_closed(
                    entry,
                    NuGetFeedUrlError::HasCredentials,
                    FailClosedCause::AmbiguousCredentialKeyMatch,
                    config_cache,
                    config_fingerprint,
                );
            }
            None => {}
        }
    }

    NuGetConfig {
        sources: accumulated.sources,
        cleared: accumulated.cleared,
        nuget_org_removed: accumulated.nuget_org_removed,
        mapping: accumulated.mapping,
    }
}

/// Why a source failed closed during the C2 credential-binding pass — logging-only detail,
/// deliberately separate from [`NuGetFeedUrlError`] (issue #576 S1 follow-up, impl-critic).
///
/// Several structurally different C2 sub-conditions all resolve to the same
/// [`NuGetFeedUrlError::HasCredentials`] reason (by design — it stays the single, hover/
/// diagnostic-safe, user-facing error), so logging `reason` alone makes issue #576's own repro
/// (a user-profile `<packageSourceCredentials>` entry with no matching same-file
/// `<packageSources><add>`, condition (2)) byte-identical in the log to an unrelated cause like
/// a plain repo-tier `<packageSourceCredentials>` declaration. This enum exists only to break
/// that tie in `fail_closed`'s log line.
#[derive(Debug, Clone, Copy, Hash)]
enum FailClosedCause {
    /// FR-004: the source itself is named under a repo-tier `<packageSourceCredentials>`.
    RepoTierCredentialed,
    /// FR-004: the source is named in `<disabledPackageSources>` with a `true` value —
    /// intentional, expected configuration, not a misconfiguration (see `fail_closed`'s level
    /// choice for this cause).
    MachineDisabled,
    /// C2 condition (0): a user-profile credential's key overlaps a key the user profile
    /// itself suppresses via `<disabledPackageSources>`.
    UserProfileSuppressed,
    /// C2 condition (2): the credential's own key does not resolve to exactly one
    /// `user_profile_add` entry (zero or ambiguous matches) — issue #576's own repro shape.
    NoMatchingUserProfileAdd,
    /// C2 condition (2): the one matched `user_profile_add` entry's own value failed URL
    /// validation, so there is no URL to compare under condition (3).
    UserProfileAddEntryInvalid,
    /// C2 condition (3): the matched `user_profile_add` entry's URL does not equal the
    /// resolved entry's URL (not origin equality — see `bind_user_profile_credential`'s doc).
    UserProfileUrlMismatch,
    /// Condition (1)'s `unique_overlap` found more than one user-profile credential whose key
    /// overlaps `entry.key` (M2 fix, impl-critic: this is only ever reached via the
    /// `is_user_credentialed` guard at this cause's one call site, which already establishes at
    /// least one raw-declared credential key overlaps `entry.key` — so a `None` here can only
    /// mean *ambiguous*, never *zero*, and this variant is named accordingly, not shared with a
    /// zero-match case).
    AmbiguousCredentialKeyMatch,
    /// The matched credential itself failed to expand (missing `ClearTextPassword`, an unset
    /// `%ENV_VAR%` reference, or a DPAPI-encrypted `<Password>` — the last of which
    /// `expand_credential` already logs itself; see `fail_closed`'s double-log guard).
    CredentialExpansionFailed,
}

/// Overwrites `entry.value` with `Err(InvalidEntry { reason, .. })`, preserving whatever raw
/// text was already resolvable (the URL if valid, or the prior `InvalidEntry::raw` if not).
///
/// Issue #576: this is the C2 credential-binding pass's own fail-closed path — unlike
/// `resolve_source_entry`'s URL-validation failures (which already `tracing::warn!`), this path
/// previously dropped a source from resolution with zero log output at any level, making a
/// misconfigured `<packageSourceCredentials>` binding indistinguishable from "package simply has
/// no versions" in the logs.
///
/// Severity mirrors `resolve_source_entry`'s existing debug!/warn! split (impl-critic S3 follow-
/// up), not a blanket `warn!`: [`NuGetFeedUrlError::Disabled`] is an intentional, expected
/// config state (analogous to a `protocolVersion="2"` or local-feed source there), so it logs
/// at `debug!`; every other reason is a genuine, actionable misconfiguration and logs at
/// `warn!`. [`NuGetFeedUrlError::EncryptedPasswordUnsupported`] logs nothing here at all —
/// `expand_credential` already emits its own `debug!` for that case, and warning again here
/// would double-log the identical event.
///
/// Debounced via `config_cache`'s dedup set (impl-critic S2 follow-up): without this, the
/// warning would re-fire on every `resolve_with_context` call (e.g. every LSP `did_change`
/// re-parse) even when the underlying config chain hasn't changed at all, unlike every other
/// warning in this module (naturally debounced by `MtimeFileCache` only re-parsing, and thus
/// only re-logging, on a genuine mtime change).
fn fail_closed(
    entry: &mut PackageSourceEntry,
    reason: NuGetFeedUrlError,
    cause: FailClosedCause,
    config_cache: &NuGetConfigCache,
    config_fingerprint: u64,
) {
    let raw = match &entry.value {
        Ok(url) => url.as_str().to_string(),
        Err(invalid) => invalid.raw.clone(),
    };

    if !matches!(reason, NuGetFeedUrlError::EncryptedPasswordUnsupported) {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        config_fingerprint.hash(&mut hasher);
        entry.key.hash(&mut hasher);
        cause.hash(&mut hasher);
        std::mem::discriminant(&reason).hash(&mut hasher);
        if config_cache.should_warn_once(hasher.finish()) {
            if matches!(reason, NuGetFeedUrlError::Disabled) {
                tracing::debug!(
                    key = %entry.key,
                    %reason,
                    ?cause,
                    "NuGet package source fails closed on credential binding"
                );
            } else {
                tracing::warn!(
                    key = %entry.key,
                    %reason,
                    ?cause,
                    "NuGet package source fails closed on credential binding"
                );
            }
        }
    }

    entry.value = Err(InvalidEntry { raw, reason });
}

/// §3.2/FR-007: attempts to bind a user-profile credential to `entry` (whose resolved URL is
/// `resolved_url`). Returns `None` when no user-profile credential key matches `entry.key` at
/// all (nothing to bind, not an error — the caller decides separately whether that's fine).
/// Returns `Some(Err((reason, cause)))` when a credential key matched but conditions (0)-(3)
/// failed, or the matched credential itself failed to expand (unset `%ENV_VAR%`,
/// DPAPI-encrypted) — `cause` is a logging-only detail (see [`FailClosedCause`]), never part of
/// the user-facing `reason`. Returns `Some(Ok(auth))` on a successful bind.
fn bind_user_profile_credential(
    entry: &PackageSourceEntry,
    user_credentials: &[RawCredential],
    user_profile_add: &[PackageSourceEntry],
    suppressed: &HashSet<String>,
    resolved_url: &str,
) -> Option<Result<NuGetAuth, (NuGetFeedUrlError, FailClosedCause)>> {
    // (0): suppression — union match, the fail-closed direction for an exclusion. Checked here
    // rather than short-circuiting on it alone, because (0) only matters once (1) below has
    // established that a credential actually exists to suppress — otherwise there is nothing to
    // bind and the correct return is `None`, not `Some(Err(..))`.
    let candidates = key_candidates(&entry.key);
    let suppressed_match = candidates.iter().any(|c| suppressed.contains(c));

    // (1): exactly one user-profile credential's key-candidates overlap `entry.key`.
    let credential = unique_overlap(&entry.key, user_credentials, |c| c.key.as_str())?;

    if suppressed_match {
        return Some(Err((
            NuGetFeedUrlError::HasCredentials,
            FailClosedCause::UserProfileSuppressed,
        )));
    }

    // (2): exactly one `user_profile_add` entry's key-candidates overlap the credential's own
    // key.
    let Some(add_entry) = unique_overlap(&credential.key, user_profile_add, |e| e.key.as_str())
    else {
        return Some(Err((
            NuGetFeedUrlError::HasCredentials,
            FailClosedCause::NoMatchingUserProfileAdd,
        )));
    };

    // (3): normalized full-URL equality — not origin equality (see §3.2's rationale).
    let Ok(add_url) = add_entry.value.as_ref() else {
        return Some(Err((
            NuGetFeedUrlError::HasCredentials,
            FailClosedCause::UserProfileAddEntryInvalid,
        )));
    };
    if add_url.as_str() != resolved_url {
        return Some(Err((
            NuGetFeedUrlError::HasCredentials,
            FailClosedCause::UserProfileUrlMismatch,
        )));
    }

    Some(
        expand_credential(credential)
            .map_err(|reason| (reason, FailClosedCause::CredentialExpansionFailed)),
    )
}

/// FR-002/FR-003: expands `%ENV_VAR%` references (post-cache, credential values only) and
/// formats the result into a [`NuGetAuth`]. A DPAPI-encrypted `<Password>` fails closed as
/// [`NuGetFeedUrlError::EncryptedPasswordUnsupported`]; a missing `ClearTextPassword`, or any
/// referenced environment variable being unset, fails closed as
/// [`NuGetFeedUrlError::HasCredentials`].
fn expand_credential(credential: &RawCredential) -> Result<NuGetAuth, NuGetFeedUrlError> {
    if credential.encrypted {
        tracing::debug!(
            key = %credential.key,
            "DPAPI-encrypted <Password> is not supported; dropping credential"
        );
        return Err(NuGetFeedUrlError::EncryptedPasswordUnsupported);
    }
    let Some(password) = &credential.password else {
        return Err(NuGetFeedUrlError::HasCredentials);
    };
    let username = credential
        .username
        .as_ref()
        .map(RedactedSecret::expose_secret)
        .unwrap_or("");
    let username = expand_env_vars(username)?;
    let password = expand_env_vars(password.expose_secret())?;
    Ok(NuGetAuth::new(&username, &password))
}

/// Expands every `%NAME%` reference in `raw` against the process environment. Any referenced
/// variable being unset fails the *whole* expansion closed (FR-002) — never a partial
/// substitution. `%` sequences that don't form a well-formed `%NAME%` reference (empty name, a
/// non-alphanumeric/underscore character, or an unterminated `%`) are left as literal text.
///
/// Returns [`Zeroizing`], not a bare `String` — the caller (`expand_credential`) only ever
/// expands a secret (`RedactedSecret` username/password), never an ordinary value.
fn expand_env_vars(raw: &str) -> Result<Zeroizing<String>, NuGetFeedUrlError> {
    expand_env_vars_with(raw, |name| std::env::var(name).ok().map(Zeroizing::new))
}

/// [`expand_env_vars`], but reading variables through `lookup` instead of [`std::env::var`]
/// directly — lets tests inject a fake environment instead of mutating the real process
/// environment (this workspace forbids `unsafe`, and Rust 2024 made `std::env::set_var` an
/// `unsafe fn`, so a test cannot do that mutation at all; mirrors
/// `deps_npm::config::expand_env_vars_with`'s identical rationale).
///
/// Scans `raw` (and each looked-up value) by `&str` slice, never collecting the secret into
/// an intermediate `Vec<char>` copy, and precomputes the exact output length from the
/// resolved segments before allocating — so the returned [`Zeroizing`] buffer is never grown
/// past its initial capacity. `zeroize`'s own docs note it cannot guarantee a `Vec`/`String`
/// reallocation didn't leave a stale copy on the heap; sizing exactly once, up front, is what
/// avoids that reallocation in the first place, rather than merely zeroizing after the fact.
fn expand_env_vars_with(
    raw: &str,
    lookup: impl Fn(&str) -> Option<Zeroizing<String>>,
) -> Result<Zeroizing<String>, NuGetFeedUrlError> {
    enum Segment<'a> {
        Literal(&'a str),
        Value(Zeroizing<String>),
    }

    let mut segments = Vec::new();
    let mut rest = raw;
    while let Some(pct) = rest.find('%') {
        let literal = &rest[..pct];
        let after = &rest[pct + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                if !literal.is_empty() {
                    segments.push(Segment::Literal(literal));
                }
                let value = lookup(name).ok_or(NuGetFeedUrlError::HasCredentials)?;
                segments.push(Segment::Value(value));
                rest = &after[end + 1..];
                continue;
            }
        }
        // Not a well-formed `%NAME%` reference: keep everything up to and including this
        // `%` as literal text, then keep scanning from just past it.
        segments.push(Segment::Literal(&rest[..=pct]));
        rest = &rest[pct + 1..];
    }
    if !rest.is_empty() {
        segments.push(Segment::Literal(rest));
    }

    let total_len: usize = segments
        .iter()
        .map(|segment| match segment {
            Segment::Literal(s) => s.len(),
            Segment::Value(v) => v.len(),
        })
        .sum();
    let mut out = Zeroizing::new(String::with_capacity(total_len));
    for segment in &segments {
        match segment {
            Segment::Literal(s) => out.push_str(s),
            Segment::Value(v) => out.push_str(v.as_str()),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::net_policy::WorkspaceRegistryAccess;
    use std::assert_matches;

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
        assert_matches!(
            NuGetFeedUrl::new("https://user:pass@feed.example/v3/index.json", &policy),
            Err(NuGetFeedUrlError::UserInfoPresent)
        );
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
            tier: ConfigTier::Repo,
            auth: None,
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
        assert_matches!(source, DependencySource::AlternateRegistry { .. });
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
            chains[0].hops[0].url.as_str(),
            "https://corp.example/v3/index.json"
        );
        assert_eq!(
            chains[0].hops[1].url.as_str(),
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
        assert_eq!(
            chain.hops[0].url.as_str(),
            "https://corp.example/v3/index.json"
        );
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

        assert_matches!(
            config.resolve_source_for(&pkg("Newtonsoft.Json")),
            DependencySource::AlternateRegistry { .. }
        );
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
        assert_eq!(
            chain.hops[0].url.as_str(),
            "https://corp.example/v3/index.json"
        );

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
        assert_matches!(
            config.resolve_source_for(&pkg("MyCompany.Internal")),
            DependencySource::AlternateRegistry { .. }
        );
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
        assert_matches!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::CustomRegistry { .. }
        );
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
            chains[0].hops[0].url.as_str(),
            "https://new.example/v3/index.json"
        );
    }

    // --- issue #561: user-profile credentials, C2 binding, %ENV_VAR% expansion ---

    fn write_user_profile(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join("UserProfile.NuGet.Config");
        std::fs::write(&path, content).unwrap();
        path
    }

    fn resolve_ctx(
        repo_dir: &Path,
        cache: &NuGetConfigCache,
        policy: &RegistryAccessPolicy,
        user_profile: Option<&Path>,
        flag_on: bool,
    ) -> NuGetConfig {
        resolve_with_context(
            repo_dir,
            cache,
            policy,
            user_profile,
            &AtomicBool::new(flag_on),
        )
    }

    const CORP_CRED_USER_PROFILE: &str = r#"<configuration>
        <packageSources>
            <add key="CorpFeed" value="https://corp.example/v3/index.json" />
        </packageSources>
        <packageSourceCredentials>
            <CorpFeed>
                <add key="Username" value="user" />
                <add key="ClearTextPassword" value="pat-value" />
            </CorpFeed>
        </packageSourceCredentials>
    </configuration>"#;

    /// SC-001/SC-006: a repo `<add key="CorpFeed">` at the exact URL the user-profile config
    /// declares gets the credential attached.
    #[test]
    fn test_c2_exact_url_match_attaches_credential() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let user_profile = write_user_profile(root.path(), CORP_CRED_USER_PROFILE);
        write_config(
            &repo,
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);

        let chains = config.resolved_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 1);
        assert!(
            chains[0].hops[0].auth.is_some(),
            "matching-URL repo entry must receive the user-profile credential"
        );
        assert_eq!(chains[0].hops[0].slot.as_deref(), Some("corpfeed"));
    }

    /// SC-006: same-origin-different-path repo entry must fail closed as `HasCredentials` —
    /// condition (3) is full-URL equality, not origin equality.
    #[test]
    fn test_c2_same_origin_different_path_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let user_profile = write_user_profile(
            root.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://pkgs.dev.azure.com/real-org/_packaging/x/nuget/v3/index.json" />
                </packageSources>
                <packageSourceCredentials>
                    <CorpFeed>
                        <add key="Username" value="user" />
                        <add key="ClearTextPassword" value="pat" />
                    </CorpFeed>
                </packageSourceCredentials>
            </configuration>"#,
        );
        write_config(
            &repo,
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://pkgs.dev.azure.com/attacker-org/_packaging/x/nuget/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);

        assert!(
            config.resolved_chains().is_empty(),
            "URL mismatch must fail the source closed, not attach nor route it"
        );
    }

    /// SC-007/§3.4: a user-profile-disabled key never receives a credential on a matching
    /// repo-declared source, while the repo source is still queried (just unauthenticated is
    /// impossible here since it has real credentials configured — so it must fail closed, not
    /// merely "unauthenticated", per condition (0)).
    #[test]
    fn test_c2_condition_0_suppressed_key_fails_closed_not_machine_disabled() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let user_profile = write_user_profile(
            root.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <packageSourceCredentials>
                    <CorpFeed>
                        <add key="Username" value="user" />
                        <add key="ClearTextPassword" value="pat" />
                    </CorpFeed>
                </packageSourceCredentials>
                <disabledPackageSources>
                    <add key="CorpFeed" value="true" />
                </disabledPackageSources>
            </configuration>"#,
        );
        write_config(
            &repo,
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);

        // The repo's CorpFeed is not machine-wide disabled by a user-profile suppression —
        // only the credential binding is refused, which here means the entry fails closed
        // (HasCredentials) since it *did* match a credential key.
        assert!(config.resolved_chains().is_empty());
    }

    /// SC-002: `%ENV_VAR%` expansion — set resolves, unset fails closed, and the unexpanded
    /// literal is never leaked into the result. Exercises `expand_env_vars_with` directly
    /// (this workspace forbids `unsafe`, so a test cannot mutate the real process
    /// environment — see that function's doc).
    #[test]
    fn test_env_var_expansion_set_and_unset() {
        let set = expand_env_vars_with("%CORP_FEED_PAT%", |name| {
            (name == "CORP_FEED_PAT").then(|| Zeroizing::new("secret-pat".to_string()))
        });
        assert_eq!(set.unwrap().as_str(), "secret-pat");

        let unset = expand_env_vars_with("%CORP_FEED_PAT%", |_| None);
        assert_matches!(unset, Err(NuGetFeedUrlError::HasCredentials));
    }

    /// Regression coverage for the `&str`-slice rewrite of `expand_env_vars_with` (it no
    /// longer collects `raw` into an intermediate `Vec<char>`): surrounding literal text,
    /// back-to-back substitutions with no literal between them, a malformed name (non
    /// alphanumeric/underscore character) left as literal text, and an unterminated `%` at
    /// end-of-string left as literal text — all must behave exactly as the prior
    /// char-by-char scan did.
    #[test]
    fn test_env_var_expansion_edge_cases() {
        let lookup = |name: &str| match name {
            "A" => Some(Zeroizing::new("1".to_string())),
            "B" => Some(Zeroizing::new("2".to_string())),
            _ => None,
        };

        assert_eq!(
            expand_env_vars_with("pre-%A%-post", lookup)
                .unwrap()
                .as_str(),
            "pre-1-post"
        );
        assert_eq!(
            expand_env_vars_with("%A%%B%", lookup).unwrap().as_str(),
            "12"
        );
        assert_eq!(
            expand_env_vars_with("abc%1bad!name%def", lookup)
                .unwrap()
                .as_str(),
            "abc%1bad!name%def"
        );
        assert_eq!(
            expand_env_vars_with("abc%A", lookup).unwrap().as_str(),
            "abc%A"
        );
        assert_eq!(expand_env_vars_with("%%", lookup).unwrap().as_str(), "%%");
        assert_matches!(
            expand_env_vars_with("pre-%UNSET%-post", lookup),
            Err(NuGetFeedUrlError::HasCredentials)
        );
    }

    /// SC-002 end-to-end: the same expansion wired through `resolve`'s credential-binding
    /// pass — a credential whose `RawCredential` has no `password` (the shape an unset env
    /// var's literal string alone cannot distinguish from a real missing `ClearTextPassword`
    /// at this layer) fails closed via `expand_credential`.
    #[test]
    fn test_expand_credential_missing_password_fails_closed() {
        let credential = RawCredential {
            key: "CorpFeed".to_string(),
            username: Some(RedactedSecret::new("user".to_string())),
            password: None,
            encrypted: false,
        };
        assert_matches!(
            expand_credential(&credential),
            Err(NuGetFeedUrlError::HasCredentials)
        );
    }

    /// SC-002/NFR-001: `Debug`/`Display` on the credential-holding types never leak the
    /// literal secret.
    #[test]
    fn test_nuget_auth_and_redacted_secret_never_debug_print_the_literal() {
        // codeql[rust/hard-coded-cryptographic-value] -- test fixture literal, not a real credential
        let auth = NuGetAuth::new("user", "super-secret-pat");
        assert!(!format!("{auth:?}").contains("super-secret-pat"));
        assert!(!format!("{auth}").contains("super-secret-pat"));

        let secret = RedactedSecret::new("super-secret-pat".to_string());
        assert!(!format!("{secret:?}").contains("super-secret-pat"));
        assert!(!format!("{secret}").contains("super-secret-pat"));
    }

    /// FR-003: a DPAPI-encrypted `<Password>` fails closed with a distinct reason, never
    /// `HasCredentials`.
    #[test]
    fn test_dpapi_encrypted_password_rejected_distinctly() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let user_profile = write_user_profile(
            root.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <packageSourceCredentials>
                    <CorpFeed>
                        <add key="Username" value="user" />
                        <add key="Password" value="AQAAANCM...encrypted..." />
                    </CorpFeed>
                </packageSourceCredentials>
            </configuration>"#,
        );
        write_config(
            &repo,
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);

        assert!(config.resolved_chains().is_empty());
        // No `<clear/>` anywhere in the chain, so the dropped CorpFeed leaves the implicit
        // `nuget.org` tail reachable exactly as if nothing had been configured (NFR-004,
        // matching `test_disabled_source_case_insensitive_key_match`'s identical shape) — the
        // distinct-reason assertion is in `expand_credential`'s own unit test below instead.
        assert_eq!(
            config.resolve_source_for(&pkg("Any.Package")),
            DependencySource::Registry
        );
    }

    /// FR-003: the distinct-reason assertion for a DPAPI-encrypted credential, at the
    /// `expand_credential` unit level (see the end-to-end test above for the resolve()-level
    /// fail-closed behavior).
    #[test]
    fn test_expand_credential_encrypted_password_is_distinct_reason() {
        let credential = RawCredential {
            key: "CorpFeed".to_string(),
            username: Some(RedactedSecret::new("user".to_string())),
            password: None,
            encrypted: true,
        };
        assert_matches!(
            expand_credential(&credential),
            Err(NuGetFeedUrlError::EncryptedPasswordUnsupported)
        );
    }

    /// FR-004/SC-010: repo-tier `<packageSourceCredentials>` fails closed unconditionally,
    /// independent of any C2 binding outcome — even when the user-profile config *also*
    /// credentials the exact same URL.
    #[test]
    fn test_repo_tier_credential_always_fails_closed_even_with_matching_user_profile() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let user_profile = write_user_profile(root.path(), CORP_CRED_USER_PROFILE);
        write_config(
            &repo,
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <packageSourceCredentials>
                    <CorpFeed>
                        <add key="Username" value="repo-user" />
                        <add key="ClearTextPassword" value="repo-pass" />
                    </CorpFeed>
                </packageSourceCredentials>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);

        assert!(
            config.resolved_chains().is_empty(),
            "repo-tier credentialed source must fail closed regardless of C2"
        );
    }

    /// Issue #576: `fail_closed` must log, not silently drop the source — a user-profile
    /// `<packageSourceCredentials>` entry for a key with no matching `<packageSources><add>` in
    /// that same user-profile file fails condition (2), so the repo-declared source is dropped
    /// with no other observable signal anywhere (no hover `Latest`, no diagnostic).
    #[test]
    fn test_fail_closed_logs_warning_with_key_and_reason() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let user_profile = write_user_profile(
            root.path(),
            r#"<configuration>
                <packageSourceCredentials>
                    <CorpFeed>
                        <add key="Username" value="user" />
                        <add key="ClearTextPassword" value="pat" />
                    </CorpFeed>
                </packageSourceCredentials>
            </configuration>"#,
        );
        write_config(
            &repo,
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();

        let log = deps_core::test_util::capture_tracing_output(|| {
            let config = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);
            assert!(
                config.resolved_chains().is_empty(),
                "unresolvable credential binding must still fail the source closed"
            );
        });

        assert!(
            log.contains("CorpFeed") && log.contains("packageSourceCredentials"),
            "expected fail-closed warning naming the source key and reason in log: {log:?}"
        );
        // S1 fix (impl-critic): this specific C2 sub-condition (2) must be distinguishable in
        // the log from an unrelated cause that maps to the same `HasCredentials` reason (e.g. a
        // plain repo-tier `<packageSourceCredentials>` declaration, asserted separately below).
        assert!(
            log.contains("NoMatchingUserProfileAdd"),
            "expected the specific C2 sub-condition cause in log: {log:?}"
        );
    }

    /// S1 fix (impl-critic): a repo-tier `<packageSourceCredentials>` declaration and issue
    /// #576's user-profile-condition-(2) repro (tested above) both resolve to the same
    /// `NuGetFeedUrlError::HasCredentials` reason, but must log a different `cause` — proving
    /// the two are no longer byte-identical in the log.
    #[test]
    fn test_fail_closed_repo_tier_and_c2_causes_are_distinguishable() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        write_config(
            &repo,
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <packageSourceCredentials>
                    <CorpFeed>
                        <add key="Username" value="repo-user" />
                        <add key="ClearTextPassword" value="repo-pass" />
                    </CorpFeed>
                </packageSourceCredentials>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();

        let log = deps_core::test_util::capture_tracing_output(|| {
            let _ = resolve_ctx(&repo, &cache, &policy, None, false);
        });

        assert!(
            log.contains("RepoTierCredentialed"),
            "expected the repo-tier cause, distinct from NoMatchingUserProfileAdd, in log: {log:?}"
        );
        assert!(
            !log.contains("NoMatchingUserProfileAdd"),
            "repo-tier cause must not be conflated with the C2 sub-condition cause: {log:?}"
        );
    }

    /// S2 fix (impl-critic, issue #576 follow-up): the fail-closed warning must debounce to
    /// once per distinct config state, not once per `resolve_with_context` call (e.g. every LSP
    /// `did_change` re-parse against unchanged `NuGet.Config` content).
    #[test]
    fn test_fail_closed_warning_debounced_across_repeat_resolves() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let config_path = repo.join("NuGet.Config");
        write_config(
            &repo,
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <packageSourceCredentials>
                    <CorpFeed>
                        <add key="Username" value="repo-user" />
                        <add key="ClearTextPassword" value="repo-pass" />
                    </CorpFeed>
                </packageSourceCredentials>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();

        let log = deps_core::test_util::capture_tracing_output(|| {
            for _ in 0..4 {
                let _ = resolve_ctx(&repo, &cache, &policy, None, false);
            }

            // C1/S2 fix (impl-critic): a genuine content change (distinguishable mtime) must
            // re-trigger the warning exactly once more, not once per subsequent resolve —
            // proving the debounce tracks config *content* rather than suppressing the warning
            // forever once fired. Mirrors deps-go's
            // `test_goenv_oversized_goprivate_warning_debounced_across_resolves` precedent.
            //
            // M1 fix (impl-critic follow-up): the source `key` (`CorpFeed`) and `cause`
            // (`RepoTierCredentialed`) are held deliberately constant across the change — only
            // the `value=` URL differs. `fail_closed`'s dedup hash also includes `entry.key`
            // and `cause` independently of `config_fingerprint`, so changing the key here too
            // (as an earlier version of this test did) would pass even against a broken,
            // pointer-identity-based fingerprint that never changes on real content edits — the
            // key change alone would already produce a fresh hash. Holding everything else
            // constant makes `config_fingerprint` the *only* thing that can distinguish the two
            // rounds, so this test actually regression-guards the C1 fix.
            let future = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
            write_config(
                &repo,
                r#"<configuration>
                    <packageSources>
                        <add key="CorpFeed" value="https://corp.example/v3/index-v2.json" />
                    </packageSources>
                    <packageSourceCredentials>
                        <CorpFeed>
                            <add key="Username" value="repo-user" />
                            <add key="ClearTextPassword" value="repo-pass" />
                        </CorpFeed>
                    </packageSourceCredentials>
                </configuration>"#,
            );
            std::fs::OpenOptions::new()
                .write(true)
                .open(&config_path)
                .unwrap()
                .set_modified(future)
                .unwrap();

            for _ in 0..2 {
                let _ = resolve_ctx(&repo, &cache, &policy, None, false);
            }
        });

        assert_eq!(
            log.matches("fails closed on credential binding").count(),
            2,
            "expected one warning for the original content and one more after a genuine \
             content change: {log:?}"
        );
    }

    /// M1 fix (impl-critic follow-up): a machine-disabled source (`<disabledPackageSources>`)
    /// must still fail closed (unchanged behavior), but per S3 must log at `debug!`, not
    /// `warn!`. Captured at `DEBUG` (not the vacuous `INFO`-only capture, under which a
    /// `debug!` line is invisible regardless of whether the code is correct) so this test can
    /// positively assert the message fired, at the right level, rather than merely asserting
    /// its absence at a level that would hide it either way.
    #[test]
    fn test_disabled_source_fails_closed_at_debug_level_not_warn() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        write_config(
            &repo,
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <disabledPackageSources>
                    <add key="CorpFeed" value="true" />
                </disabledPackageSources>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();

        let log = deps_core::test_util::capture_tracing_output_at(tracing::Level::DEBUG, || {
            let config = resolve_ctx(&repo, &cache, &policy, None, false);
            assert_eq!(
                config.resolve_source_for(&pkg("CorpFeed.Package")),
                DependencySource::Registry,
                "a disabled-but-not-cleared source still leaves the implicit nuget.org tail reachable"
            );
        });

        let line = log
            .lines()
            .find(|l| l.contains("fails closed on credential binding"))
            .unwrap_or_else(|| panic!("expected a fail-closed log line at DEBUG level: {log:?}"));
        assert!(
            line.contains("MachineDisabled"),
            "expected the MachineDisabled cause on the fail-closed line: {line}"
        );
        assert!(
            line.contains("DEBUG"),
            "MachineDisabled must log at debug!: {line}"
        );
        assert!(
            !line.contains("WARN"),
            "MachineDisabled must not log at warn!: {line}"
        );
    }

    /// M1 fix (impl-critic follow-up): a DPAPI-encrypted `<Password>` must not double-log —
    /// `expand_credential` already emits its own `debug!` for this case, so `fail_closed` must
    /// not also emit a line for the same event, at any level. Captured at `DEBUG` so both the
    /// expected `debug!` line's presence and `fail_closed`'s line's absence are meaningfully
    /// asserted (at the old `INFO`-only capture, both would be invisible regardless of whether
    /// `fail_closed` incorrectly emitted a second `debug!`).
    #[test]
    fn test_dpapi_encrypted_password_does_not_double_log() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let user_profile = write_user_profile(
            root.path(),
            r#"<configuration>
                <packageSources>
                    <add key="CorpFeed" value="https://corp.example/v3/index.json" />
                </packageSources>
                <packageSourceCredentials>
                    <CorpFeed>
                        <add key="Username" value="user" />
                        <add key="Password" value="AQAAANCM...encrypted..." />
                    </CorpFeed>
                </packageSourceCredentials>
            </configuration>"#,
        );
        write_config(
            &repo,
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();

        let log = deps_core::test_util::capture_tracing_output_at(tracing::Level::DEBUG, || {
            let _ = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);
        });

        assert_eq!(
            log.matches("DPAPI-encrypted <Password> is not supported")
                .count(),
            1,
            "expected exactly one debug! from expand_credential: {log:?}"
        );
        assert!(
            !log.contains("fails closed on credential binding"),
            "fail_closed must not double-log the DPAPI case at any level: {log:?}"
        );
    }

    /// SC-012/FR-008: a user-profile credential named for `nuget.org` never attaches to, nor
    /// blocks, a repo entry resolving to the real public index.
    #[test]
    fn test_public_index_carve_out_never_blocks_or_authenticates() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let user_profile = write_user_profile(
            root.path(),
            r#"<configuration>
                <packageSources>
                    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
                </packageSources>
                <packageSourceCredentials>
                    <nuget.org>
                        <add key="Username" value="user" />
                        <add key="ClearTextPassword" value="upstream-pat" />
                    </nuget.org>
                </packageSourceCredentials>
            </configuration>"#,
        );
        write_config(
            &repo,
            r#"<configuration><packageSources>
                <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();
        let config = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);

        // Resolves to plain `Registry` (public index), never `HasCredentials`.
        assert_eq!(
            config.resolve_source_for(&pkg("Newtonsoft.Json")),
            DependencySource::Registry
        );
    }

    /// SC-005/NFR-005: with the flag off, a user-profile file's `<clear/>`/
    /// `<packageSourceMapping>`/`<disabledPackageSources>` produce byte-identical
    /// `valid_hops`/routing to a run with no user-profile file at all.
    #[test]
    fn test_flag_off_user_profile_routing_directives_have_zero_effect() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        write_config(
            &repo,
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let user_profile = write_user_profile(
            root.path(),
            r#"<configuration>
                <packageSources>
                    <clear />
                    <add key="EvilFeed" value="https://evil.example/v3/index.json" />
                </packageSources>
                <disabledPackageSources>
                    <add key="CorpFeed" value="true" />
                </disabledPackageSources>
                <packageSourceMapping>
                    <packageSource key="EvilFeed">
                        <package pattern="*" />
                    </packageSource>
                </packageSourceMapping>
            </configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();

        let with_profile = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);
        let without_profile = resolve_ctx(&repo, &cache, &policy, None, false);

        let hops_of = |c: &NuGetConfig| -> Vec<String> {
            c.valid_hops()
                .into_iter()
                .map(|h| h.url.as_str().to_string())
                .collect()
        };
        assert_eq!(hops_of(&with_profile), hops_of(&without_profile));
        assert_eq!(
            with_profile.resolve_source_for(&pkg("Any.Package")),
            without_profile.resolve_source_for(&pkg("Any.Package"))
        );
    }

    /// SC-005/US-005: with the flag on, a user-profile-only `<add>` (no repo `NuGet.Config`
    /// declaring it) becomes an `AlternateRegistry` routing hop.
    #[test]
    fn test_flag_on_user_profile_only_source_becomes_routing_hop() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let user_profile = write_user_profile(
            root.path(),
            r#"<configuration><packageSources>
                <add key="CorpFeed" value="https://corp.example/v3/index.json" />
            </packageSources></configuration>"#,
        );
        let cache = NuGetConfigCache::new();
        let policy = all_policy();

        let flag_off = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), false);
        assert!(flag_off.resolved_chains().is_empty());

        let flag_on = resolve_ctx(&repo, &cache, &policy, Some(&user_profile), true);
        assert_matches!(
            flag_on.resolve_source_for(&pkg("Any.Package")),
            DependencySource::AlternateRegistry { .. }
        );
    }

    /// FR-009: the non-transitive key-aliasing counterexample from the critic review —
    /// `"Corp_x005f_x0020_Feed"` and `"Corp Feed"` don't overlap each other directly, but both
    /// overlap `"Corp_x0020_Feed"`. `unique_overlap` must resolve this as ambiguous (>=2
    /// matches), not silently pick one.
    #[test]
    fn test_unique_overlap_non_transitive_aliasing_is_ambiguous() {
        let policy = all_policy();
        let items = [
            source(
                "Corp_x005f_x0020_Feed",
                "https://a.example/v3/index.json",
                &policy,
            ),
            source("Corp Feed", "https://b.example/v3/index.json", &policy),
        ];
        assert!(unique_overlap("Corp_x0020_Feed", &items, |s| s.key.as_str()).is_none());
    }
}
