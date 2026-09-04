//! `$GOENV` discovery and `GOPROXY`/`GOPRIVATE` resolution.
//!
//! Go persists `go env -w`-set variables in a single `KEY=VALUE` file (`$GOENV`, defaulting to
//! `os.UserConfigDir()/go/env`) rather than a project manifest — unlike Cargo/npm/PyPI, whose
//! private-registry config lives inside or alongside the workspace being parsed. This module
//! resolves that file once per process (memoized, mtime-gated — see [`GoEnvCache`]) into a
//! [`GoEnvConfig`] consulted by every `go.mod` parse.
//!
//! # Security model (read before touching this module)
//!
//! `$GOENV` is a process-wide, user-owned file, not workspace-controlled content — but the
//! resolved `GOPROXY` chain still names hosts a cloned repository's dependencies get resolved
//! against, so the same discipline Cargo/npm/PyPI apply carries over:
//!
//! - **No credential-shaped value is ever parsed** (FR-014/NFR-001). [`GoProxyUrl::new`]
//!   rejects any URL carrying `username()`/`password()` outright — there is no `${VAR}`
//!   expansion step for `$GOENV` (unlike npm's `.npmrc`), so [`InvalidEntry::raw`] and every
//!   `tracing::warn!` here name the as-written value with any embedded userinfo redacted first
//!   (see [`deps_core::net_policy::redact_userinfo`]).
//! - **FR-009's per-hop fail-closed rule is the load-bearing security invariant.** An invalid
//!   `GOPROXY` hop is dropped when other valid hops remain; only when every hop is invalid does
//!   the whole chain fail closed to [`deps_core::parser::DependencySource::CustomRegistry`].
//!   Neither case ever falls back to `proxy.golang.org` — see
//!   [`GoEnvConfig::resolve_source_for`].
//! - **FR-008's `GOPRIVATE` bypass never reaches a configured proxy hop at all** — a module
//!   whose path matches a `GOPRIVATE` glob resolves straight to the `direct` terminal hop,
//!   regardless of what `GOPROXY` is configured to. See [`GoEnvConfig::resolve_source_for`].
//!
//! See `specs/034-go-goproxy-private-registry/spec.md` FR-001–FR-016 for the design this module
//! implements.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use deps_core::net_policy::{
    PolicyGate, RegistryAccessPolicy, redact_userinfo, validate_index_url,
};
use deps_core::parser::DependencySource;

/// Why a candidate `GOPROXY` hop URL failed [`GoProxyUrl::new`]'s validation.
///
/// An alias of the shared [`deps_core::net_policy::IndexUrlError`] — see that type's docs for
/// the variants and their wording.
pub use deps_core::net_policy::IndexUrlError as GoProxyUrlError;

/// A validated, normalized, https-only Go module proxy URL with no embedded userinfo.
///
/// Mirrors `deps_pypi::config::PypiIndexUrl`/`deps_npm::config::NpmRegistryIndex`; kept
/// `deps-go`-local rather than promoted to `deps-core` per this spec's Open Questions
/// (consolidate only once a fourth near-identical implementation makes the duplication
/// concrete).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GoProxyUrl {
    /// The validated URL, normalized by stripping a trailing `/` — matches the
    /// `{base}/{module}/@v/...` join convention `crate::registry` already uses for
    /// `PROXY_BASE`.
    normalized: String,
}

impl GoProxyUrl {
    /// Validates and normalizes `raw` against `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`GoProxyUrlError`] if `raw` does not parse as a URL, is not `https` (outside
    /// the `cfg(test)`/`test-util` loopback carve-out), carries a userinfo component, or
    /// resolves to a host class the current `policy` blocks.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use deps_go::config::GoProxyUrl;
    ///
    /// let policy = RegistryAccessPolicy::default();
    /// assert!(GoProxyUrl::new("https://goproxy.mycorp.example", &policy).is_ok());
    /// assert!(GoProxyUrl::new("http://goproxy.mycorp.example", &policy).is_err());
    /// assert!(GoProxyUrl::new("https://user:pass@goproxy.mycorp.example", &policy).is_err());
    /// ```
    pub fn new(raw: &str, policy: &RegistryAccessPolicy) -> Result<Self, GoProxyUrlError> {
        let url = validate_index_url(raw, raw, "go", PolicyGate::Enforce(policy))?;
        // F3 (spec 034 review): every request URL is built by appending
        // `/{module}/@v/...`/`/{module}/@latest` after this normalized base
        // (`crate::registry::versions_list_url_at` and friends) — a hop carrying a query
        // string or fragment has no well-defined append point (`https://host/?tok=x` would
        // silently become `https://host/?tok=x/github.com/.../@v/list`, an entirely
        // different — and likely 404ing — request than intended), so it is rejected here
        // rather than joined incorrectly. `InvalidUrl` is the closest existing
        // `GoProxyUrlError` variant (no `deps-core` change for a Go-only validation rule).
        if url.query().is_some() || url.fragment().is_some() {
            return Err(GoProxyUrlError::InvalidUrl(redact_userinfo(raw)));
        }
        let normalized = url.as_str().trim_end_matches('/').to_string();
        Ok(Self { normalized })
    }

    /// The normalized proxy URL. Never carries a trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }
}

impl std::fmt::Display for GoProxyUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One `GOPROXY` chain entry (FR-002): either a validated proxy URL, or one of the two
/// sentinel values `go help goproxy` defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoProxyHop {
    /// A validated, fetchable proxy host.
    Url(GoProxyUrl),
    /// `direct`: resolve straight from the VCS host — phase 1 has no direct-VCS resolution
    /// mechanism (see this crate's module docs / spec FR-006), so this is a fail-closed
    /// terminal hop that never issues a network request.
    Direct,
    /// `off`: disallow all downloads for the affected module (FR-004) — a fail-closed
    /// terminal hop, identical in observable behavior to [`Self::Direct`].
    Off,
}

/// A present-but-unusable `GOPROXY` hop — an invalid URL or a policy-blocked host (FR-009).
///
/// Carries the raw value as written, **with any embedded userinfo redacted**, so
/// [`GoEnvConfig::resolve_source_for`] can build a
/// [`DependencySource::CustomRegistry`] when every hop in a chain is invalid, or log a warning
/// naming a dropped hop, without ever holding or surfacing the credential itself.
#[derive(Debug, Clone)]
pub struct InvalidEntry {
    /// The raw `GOPROXY` hop value, as written in `$GOENV`, with any `user:pass@`/`user@`
    /// userinfo component stripped.
    pub raw: String,
    /// Why it was rejected.
    pub reason: GoProxyUrlError,
}

/// Parses and validates one `,`-or-`|`-separated `GOPROXY` chain entry (FR-002), logging a
/// `tracing::warn!` naming the raw value (userinfo redacted) on failure.
fn parse_hop(raw: &str, policy: &RegistryAccessPolicy) -> Result<GoProxyHop, InvalidEntry> {
    match raw {
        "direct" => Ok(GoProxyHop::Direct),
        "off" => Ok(GoProxyHop::Off),
        _ => GoProxyUrl::new(raw, policy)
            .map(GoProxyHop::Url)
            .map_err(|reason| {
                let redacted = redact_userinfo(raw);
                tracing::warn!(raw = %redacted, %reason, "GOPROXY hop failed validation");
                InvalidEntry {
                    raw: redacted,
                    reason,
                }
            }),
    }
}

/// Which fallback rule governs a `GOPROXY` chain hop's failure (spec 034 S2).
///
/// `go help goproxy` and Go's own `modfetch/proxy.go` give `,` and `|` genuinely different
/// semantics — this crate's `,`-and-`|`-both-fall-through-on-not-found first cut collapsed
/// that distinction; see [`GoRegistry::get_versions_chained`](crate::registry::GoRegistry)
/// (registry.rs) for where this is consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainSeparator {
    /// `,`: fall through to the next hop only on an explicit not-found response (`404`/`410`)
    /// — a transport failure (timeout, connection error, 5xx) is terminal for the whole
    /// chain.
    NotFoundOnly,
    /// `|`: fall through to the next hop on *any* error, including a transport failure.
    AnyError,
}

/// One fully-resolved, ready-to-register `GOPROXY` chain — produced by
/// [`GoEnvConfig::goproxy_chain`], consumed by `GoRegistry::register_chain`.
#[derive(Debug, Clone, Default)]
pub struct GoProxyChain {
    /// Opaque, composite identity — becomes both the router's `alternates` map key and the
    /// `DependencySource::AlternateRegistry.index` value. A hashed token
    /// (`format!("go-proxy:{:016x}", digest)`) over the ordered hop values, mirroring
    /// `deps_pypi::config::ResolvedChain::key`'s "opaque routing key" widening of
    /// `AlternateRegistry.index`'s contract.
    pub key: String,
    /// Ordered, already-validated hops (FR-002/FR-005 declaration order preserved). Never
    /// empty — see [`GoEnvConfig::goproxy_chain`]'s zero-hop handling. Truncated after the
    /// first [`GoProxyHop::Direct`]/[`GoProxyHop::Off`] entry: both are terminal by
    /// definition (FR-004/FR-006), so any hop declared after one is unreachable and dropped
    /// at parse time rather than carried into the registered chain.
    pub hops: Vec<GoProxyHop>,
    /// `separators[i]` is the fallback rule governing the transition from `hops[i]` to
    /// `hops[i + 1]` (spec 034 S2) — `hops.len().saturating_sub(1)` entries when produced by
    /// `parse_goproxy`. A shorter (or empty, `Default`) vector — every hand-constructed test
    /// chain, and the single-hop `GOPRIVATE`-bypass chain — defaults every unspecified
    /// transition to [`ChainSeparator::NotFoundOnly`], preserving this feature's original
    /// (comma-only) behavior.
    pub separators: Vec<ChainSeparator>,
}

impl GoProxyChain {
    fn keyed(hops: Vec<GoProxyHop>, separators: Vec<ChainSeparator>) -> Self {
        let mut hasher = DefaultHasher::new();
        for hop in &hops {
            match hop {
                GoProxyHop::Url(url) => url.as_str().hash(&mut hasher),
                GoProxyHop::Direct => "direct".hash(&mut hasher),
                GoProxyHop::Off => "off".hash(&mut hasher),
            }
        }
        for sep in &separators {
            sep.hash(&mut hasher);
        }
        Self {
            key: format!("go-proxy:{:016x}", hasher.finish()),
            hops,
            separators,
        }
    }
}

/// Fixed routing key for the `GOPRIVATE`-bypass chain (FR-008).
///
/// A single [`GoProxyHop::Direct`] hop, registered once whenever `$GOENV` declares any
/// `GOPRIVATE` pattern, regardless of what (if anything) `GOPROXY` is configured to. Content
/// never varies, so a fixed key (rather than a hash) is sufficient and stable across
/// re-parses.
pub const GOPRIVATE_CHAIN_KEY: &str = "go-private:direct";

/// Parses a raw `GOPROXY` value (FR-002) into either a non-empty [`GoProxyChain`], or — when
/// every declared hop turned out invalid — the first [`InvalidEntry`] encountered, so the
/// caller can fail the whole chain closed to `CustomRegistry` (FR-009) rather than silently
/// falling back to the default public chain.
///
/// Tracks which separator (`,`/`|`) preceded each entry (spec 034 S2) so the resulting
/// [`GoProxyChain::separators`] preserves Go's own distinction between the two — a manual
/// scan rather than `str::split([',', '|'])`, which would discard exactly that information.
///
/// **Known limitation** (spec 034 follow-up C1, issue #559 — documented, not fixed here; see
/// `docs/ECOSYSTEM_GUIDE.md`'s GOPROXY section): when one or more invalid entries (FR-009)
/// are dropped between two surviving hops, only the separator immediately preceding the
/// *surviving* hop is kept — a separator that preceded a *dropped* entry is discarded, not
/// merged. E.g. `a|invalid,c` records `,` (the separator after the dropped entry), not `|`
/// (the separator the user actually wrote before it). Pre-existing since PR #558; the
/// underlying carry-over behavior is out of scope for this PR (tracked as a separate
/// follow-up) — only the doc/test gap around it is closed here.
fn parse_goproxy(raw: &str, policy: &RegistryAccessPolicy) -> Result<GoProxyChain, InvalidEntry> {
    let mut hops: Vec<GoProxyHop> = Vec::new();
    let mut separators: Vec<ChainSeparator> = Vec::new();
    let mut first_invalid: Option<InvalidEntry> = None;
    // The separator that preceded the entry about to be processed this iteration — `None`
    // for the first entry (nothing precedes it).
    let mut sep_before_current: Option<ChainSeparator> = None;

    let mut remaining = raw;
    loop {
        let (entry, trailing_sep, rest) = match remaining.find([',', '|']) {
            Some(idx) => {
                let sep = if remaining.as_bytes()[idx] == b'|' {
                    ChainSeparator::AnyError
                } else {
                    ChainSeparator::NotFoundOnly
                };
                (&remaining[..idx], Some(sep), &remaining[idx + 1..])
            }
            None => (remaining, None, ""),
        };

        let trimmed = entry.trim();
        if !trimmed.is_empty() {
            match parse_hop(trimmed, policy) {
                Ok(hop) => {
                    let terminal = matches!(hop, GoProxyHop::Direct | GoProxyHop::Off);
                    if !hops.is_empty() {
                        separators.push(sep_before_current.unwrap_or(ChainSeparator::NotFoundOnly));
                    }
                    hops.push(hop);
                    if terminal {
                        // FR-004/FR-006: everything after a terminal hop is unreachable.
                        break;
                    }
                }
                Err(invalid) => {
                    if first_invalid.is_none() {
                        first_invalid = Some(invalid);
                    }
                }
            }
        }

        let Some(sep) = trailing_sep else {
            break;
        };
        sep_before_current = Some(sep);
        remaining = rest;
    }

    if hops.is_empty() {
        Err(first_invalid.unwrap_or_else(|| InvalidEntry {
            raw: redact_userinfo(raw),
            reason: GoProxyUrlError::InvalidUrl(redact_userinfo(raw)),
        }))
    } else {
        Ok(GoProxyChain::keyed(hops, separators))
    }
}

/// Upper bound on a single `GOPRIVATE` glob pattern's length (spec 034 perf fix). `$GOENV` is
/// not length-limited elsewhere, and a legitimate module-path-prefix glob has no reason to
/// approach this size — an oversized pattern is treated the same as a malformed one (never
/// compiled, never matches) rather than rejected with an error, matching the existing
/// "malformed pattern never panics, just doesn't match" contract.
const MAX_GLOB_PATTERN_LENGTH: usize = 256;

/// One compiled `GOPRIVATE` glob pattern token — see `compile_glob`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GlobToken {
    /// `*`: matches any run of zero or more non-`/` characters.
    Star,
    /// `?`: matches exactly one non-`/` character.
    Any,
    /// A literal character (including a literal `/`, the segment separator).
    Literal(char),
    /// `[...]`/`[^...]`: matches exactly one character against a set of literals/ranges.
    Class {
        negate: bool,
        entries: Vec<ClassEntry>,
    },
}

/// One entry inside a `[...]` character class.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClassEntry {
    Char(char),
    Range(char, char),
}

impl GlobToken {
    /// Whether this (non-[`Self::Star`]) token matches `c`. Panics if called on `Star` — the
    /// caller (`tokens_match`) always handles `Star` separately before reaching this.
    fn matches_char(&self, c: char) -> bool {
        match self {
            Self::Star => unreachable!("Star is matched by the caller, never directly"),
            Self::Any => c != '/',
            Self::Literal(l) => *l == c,
            Self::Class { negate, entries } => {
                let matched = entries.iter().any(|e| match e {
                    ClassEntry::Char(ch) => *ch == c,
                    ClassEntry::Range(lo, hi) => (*lo..=*hi).contains(&c),
                });
                matched != *negate
            }
        }
    }
}

/// One `GOPRIVATE`/`GONOPROXY`-style glob pattern (FR-007).
///
/// Matched against a module path per Go's own `GlobsMatchPath` + `path.Match` semantics (`go
/// help goprivate`): only the pattern's own number of `/`-separated elements is compared
/// against the module path's leading elements, then matched with shell-glob syntax (`*`, `?`,
/// `[...]`/`[^...]`) that never crosses a `/`.
///
/// Compiles its pattern once at construction into a token sequence, matched by the iterative
/// `tokens_match` rather than naive recursive backtracking — a naive backtracking
/// implementation is exponential (`O(2^n)`) on an adversarial pattern like many consecutive
/// `*`s against a non-matching text (spec 034 perf review finding: 15 stars took ~19s, 20
/// timed out); the token/iterative-pointer approach used here is `O(pattern length * matched
/// text length)`, the same bound the classic "wildcard matching" two-pointer algorithm gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobPattern {
    /// The pattern as written — used only to count `/`-separated elements for the
    /// segment-truncation step in [`Self::matches`]; matching itself always goes through
    /// `Self::tokens`.
    raw: String,
    /// Precompiled once at construction (see `compile_glob`). `None` for a malformed
    /// (unterminated `[`) or oversized (see `MAX_GLOB_PATTERN_LENGTH`) pattern — never
    /// matches any text, mirroring `path.Match`'s own `ErrBadPattern` degrading to "no match".
    tokens: Option<Vec<GlobToken>>,
}

impl GlobPattern {
    /// Wraps and compiles `raw` — no validation surfaced to the caller, matching
    /// `path.Match`'s own behavior (a malformed or oversized pattern simply never matches, per
    /// `Self::tokens`'s doc). An oversized pattern also logs a `tracing::warn!` (spec 034
    /// follow-up F6, issue #559): unlike a malformed `GOPROXY` hop, a `GOPRIVATE` pattern that
    /// never matches fails **open** on confidentiality (the module it should have hidden from
    /// the public proxy routes there instead), so this failure must be visible rather than
    /// silent.
    #[must_use]
    pub fn new(raw: &str) -> Self {
        let tokens = if raw.len() > MAX_GLOB_PATTERN_LENGTH {
            tracing::warn!(
                pattern_length = raw.len(),
                max_length = MAX_GLOB_PATTERN_LENGTH,
                "GOPRIVATE pattern exceeds max length; it will never match, so affected modules \
                 route to the public proxy instead of being treated as private"
            );
            None
        } else {
            compile_glob(raw)
        };
        Self {
            raw: raw.to_string(),
            tokens,
        }
    }

    /// Whether `module_path` matches this pattern (FR-008).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_go::config::GlobPattern;
    ///
    /// let pattern = GlobPattern::new("git.mycorp.example/*");
    /// assert!(pattern.matches("git.mycorp.example/internal/auth"));
    /// assert!(!pattern.matches("github.com/other/repo"));
    /// ```
    #[must_use]
    pub fn matches(&self, module_path: &str) -> bool {
        let Some(tokens) = &self.tokens else {
            return false;
        };
        let elements = self.raw.matches('/').count() + 1;
        let mut slashes_seen = 0usize;
        let mut cut_at = None;
        for (i, b) in module_path.bytes().enumerate() {
            if b == b'/' {
                slashes_seen += 1;
                if slashes_seen == elements {
                    cut_at = Some(i);
                    break;
                }
            }
        }
        let prefix = match cut_at {
            Some(i) => &module_path[..i],
            None if slashes_seen + 1 == elements => module_path,
            None => return false,
        };
        let text: Vec<char> = prefix.chars().collect();
        tokens_match(tokens, &text)
    }
}

/// Compiles `pattern` (Go's `path.Match` glob syntax) into a token sequence for
/// `tokens_match`. Returns `None` for an unterminated `[...]` character class — the whole
/// pattern is then permanently non-matching (see `GlobPattern::tokens`'s doc), the same
/// outcome the old recursive matcher produced for this case (it just failed the match at that
/// point instead of failing to compile).
fn compile_glob(pattern: &str) -> Option<Vec<GlobToken>> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                tokens.push(GlobToken::Star);
                i += 1;
            }
            '?' => {
                tokens.push(GlobToken::Any);
                i += 1;
            }
            '[' => {
                let negate = chars.get(i + 1) == Some(&'^');
                let class_start = if negate { i + 2 } else { i + 1 };
                let mut j = class_start;
                let mut entries = Vec::new();
                while j < chars.len() && (chars[j] != ']' || j == class_start) {
                    if chars.get(j + 1) == Some(&'-') && chars.get(j + 2).is_some_and(|&c| c != ']')
                    {
                        entries.push(ClassEntry::Range(chars[j], chars[j + 2]));
                        j += 3;
                    } else {
                        entries.push(ClassEntry::Char(chars[j]));
                        j += 1;
                    }
                }
                if chars.get(j) != Some(&']') {
                    return None; // unterminated class -> whole pattern invalid
                }
                tokens.push(GlobToken::Class { negate, entries });
                i = j + 1;
            }
            c => {
                tokens.push(GlobToken::Literal(c));
                i += 1;
            }
        }
    }
    Some(tokens)
}

/// Iterative glob matcher (spec 034 perf fix) — the classic two-pointer "wildcard matching"
/// algorithm, generalized from `*`-only to this crate's full token set (`?`/`[...]`).
/// `O(tokens.len() * text.len())` worst case, never exponential: each mismatch either advances
/// `si` (bounded by `text.len()`) or terminates immediately (no star to retry), so the total
/// number of loop iterations is bounded by `text.len()` restarts times `tokens.len()` work per
/// restart, not `2^n`.
///
/// A `GlobToken::Star` never "jumps over" a `/` — matches `GlobToken::Star`'s
/// doc and the previous recursive implementation's identical rule (a private module path's
/// segment boundaries must stay meaningful to the glob).
fn tokens_match(tokens: &[GlobToken], text: &[char]) -> bool {
    let mut ti = 0usize;
    let mut si = 0usize;
    // (token index right after the star, text index the star currently "starts consuming
    // from") — `None` until the first `*` is encountered.
    let mut star: Option<(usize, usize)> = None;

    while si < text.len() {
        if matches!(tokens.get(ti), Some(GlobToken::Star)) {
            star = Some((ti + 1, si));
            ti += 1;
            continue;
        }
        if tokens.get(ti).is_some_and(|tok| tok.matches_char(text[si])) {
            ti += 1;
            si += 1;
            continue;
        }
        match star {
            Some((next_ti, star_si)) if text[star_si] != '/' => {
                let new_si = star_si + 1;
                star = Some((next_ti, new_si));
                ti = next_ti;
                si = new_si;
            }
            _ => return false,
        }
    }
    while matches!(tokens.get(ti), Some(GlobToken::Star)) {
        ti += 1;
    }
    ti == tokens.len()
}

/// Resolved `$GOENV` configuration (FR-001–FR-008), consulted per-dependency via
/// [`Self::resolve_source_for`].
#[derive(Debug, Default)]
pub struct GoEnvConfig {
    /// `None` when `$GOENV` declares no `GOPROXY` override (FR-003/US-005: every dependency
    /// keeps resolving to plain [`DependencySource::Registry`], byte-identical to today).
    goproxy: Option<Result<GoProxyChain, InvalidEntry>>,
    /// `GOPRIVATE` glob patterns (FR-007). Empty when absent/declares nothing.
    goprivate: Vec<GlobPattern>,
}

impl GoEnvConfig {
    /// Parses `$GOENV` file content (FR-001: `KEY=VALUE` lines, `#`-comments and blank lines
    /// ignored) into a resolved config, validating any `GOPROXY` hop against `policy`
    /// (FR-011).
    #[must_use]
    pub fn parse(content: &str, policy: &RegistryAccessPolicy) -> Self {
        Self::from_raw(&parse_goenv_raw(content), policy)
    }

    fn from_raw(raw: &RawGoEnv, policy: &RegistryAccessPolicy) -> Self {
        Self {
            goproxy: raw
                .goproxy
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|raw| parse_goproxy(raw, policy)),
            goprivate: raw
                .goprivate
                .as_deref()
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(GlobPattern::new)
                .collect(),
        }
    }

    /// FR-002/FR-007/FR-008/FR-009: resolves one module's [`DependencySource`].
    ///
    /// - A `GOPRIVATE`-matched module bypasses `GOPROXY` entirely, routing to the fixed
    ///   [`GOPRIVATE_CHAIN_KEY`] chain (FR-008) — checked first, regardless of `GOPROXY`.
    /// - No `GOPROXY` override declared -> plain [`DependencySource::Registry`] (US-005).
    /// - A `GOPROXY` override where every hop is invalid -> [`DependencySource::CustomRegistry`]
    ///   (FR-009, fail-closed, never a `proxy.golang.org` fallback).
    /// - Otherwise -> [`DependencySource::AlternateRegistry`] pointing at the chain
    ///   [`Self::goproxy_chain`] registers.
    #[must_use]
    pub fn resolve_source_for(&self, module_path: &str) -> DependencySource {
        if self
            .goprivate
            .iter()
            .any(|pattern| pattern.matches(module_path))
        {
            return DependencySource::AlternateRegistry {
                index: GOPRIVATE_CHAIN_KEY.to_string(),
                mirrors_crates_io: false,
            };
        }

        match &self.goproxy {
            None => DependencySource::Registry,
            Some(Ok(chain)) => DependencySource::AlternateRegistry {
                index: chain.key.clone(),
                mirrors_crates_io: false,
            },
            Some(Err(invalid)) => DependencySource::CustomRegistry {
                url: invalid.raw.clone(),
            },
        }
    }

    /// The resolved `GOPROXY` chain to register, if any (`None` when absent or every hop was
    /// invalid — nothing to register in either case).
    #[must_use]
    pub fn goproxy_chain(&self) -> Option<&GoProxyChain> {
        self.goproxy.as_ref().and_then(|r| r.as_ref().ok())
    }

    /// Whether any `GOPRIVATE` pattern is declared — gates whether the caller must also
    /// register the fixed [`GOPRIVATE_CHAIN_KEY`] chain.
    #[must_use]
    pub fn has_goprivate(&self) -> bool {
        !self.goprivate.is_empty()
    }

    /// Every chain this config implies, ready for `GoRegistry::register_chain` — the resolved
    /// `GOPROXY` chain (if any), plus the fixed [`GOPRIVATE_CHAIN_KEY`] bypass chain when any
    /// `GOPRIVATE` pattern is declared (registered regardless of whether `GOPROXY` itself is
    /// also declared — FR-008 applies independently of `GOPROXY`). Empty when `$GOENV`
    /// declares no override at all (US-005: nothing to register).
    #[must_use]
    pub fn resolved_chains(&self) -> Vec<GoProxyChain> {
        let mut chains = Vec::new();
        if let Some(chain) = self.goproxy_chain() {
            chains.push(chain.clone());
        }
        if self.has_goprivate() {
            chains.push(GoProxyChain {
                key: GOPRIVATE_CHAIN_KEY.to_string(),
                hops: vec![GoProxyHop::Direct],
                separators: Vec::new(),
            });
        }
        chains
    }
}

/// One `$GOENV` file's raw (unvalidated) `GOPROXY`/`GOPRIVATE` values — see
/// [`parse_goenv_raw`]'s doc for exactly which keys this can ever contain.
#[derive(Debug, Default)]
struct RawGoEnv {
    /// Raw, unvalidated `GOPROXY` value, which may carry embedded userinfo until
    /// [`GoProxyUrl::new`] rejects it per-hop. Retained for the process lifetime by
    /// [`GoEnvCache`]'s memoization, mirroring `deps_npm::config::NpmConfigCache`'s identical
    /// shape exactly — precedent-consistent, not a regression to fix (spec 034 security
    /// review, F4). Never logged or transmitted as-is (FR-014); only [`redact_userinfo`]'d
    /// output ever leaves this module.
    goproxy: Option<String>,
    goprivate: Option<String>,
}

/// Parses `$GOENV` file content into its raw `GOPROXY`/`GOPRIVATE` values (FR-001).
///
/// Grammar: one `KEY=VALUE` per line (`go env -w`'s own written format); `#`-prefixed comment
/// lines and blank lines are ignored; any other key is ignored (this crate has no use for
/// `GONOSUMCHECK`/`GOFLAGS`/etc — see spec Out of Scope). A key declared more than once keeps
/// its last occurrence, matching plain assignment-overwrite semantics.
fn parse_goenv_raw(content: &str) -> RawGoEnv {
    let mut raw = RawGoEnv::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "GOPROXY" => raw.goproxy = Some(value.trim().to_string()),
            "GOPRIVATE" => raw.goprivate = Some(value.trim().to_string()),
            _ => {}
        }
    }
    raw
}

/// Per-`$GOENV`-file-path memoization, mirroring `deps_npm::config::NpmConfigCache` exactly in
/// shape.
///
/// Caches **raw, unvalidated** entries — [`GoProxyUrl::new`] validation and policy gating
/// re-run **per parse** against these cached entries, never cached themselves, so a
/// `didChangeConfiguration` policy change takes effect immediately with no cache invalidation
/// of its own. A thin newtype over [`deps_core::MtimeFileCache`].
#[derive(Debug)]
pub struct GoEnvCache(deps_core::MtimeFileCache<RawGoEnv>);

impl Default for GoEnvCache {
    fn default() -> Self {
        Self::new()
    }
}

impl GoEnvCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self(deps_core::MtimeFileCache::new(
            deps_core::DEFAULT_MAX_CACHED_FILES,
            "go env",
        ))
    }

    fn get_or_parse(&self, path: &Path) -> Option<Arc<RawGoEnv>> {
        self.0.get_or_parse(path, parse_goenv_raw)
    }
}

/// Owned by `GoEcosystem`, shared across every document it parses.
#[derive(Debug, Clone, Default)]
pub struct GoParseContext {
    /// Gates every `GOPROXY`-declared [`GoProxyUrl`] this parse constructs.
    pub policy: Arc<RegistryAccessPolicy>,
    /// Memoizes `$GOENV`'s raw, unvalidated contents across every parse that reads it.
    pub config_cache: Arc<GoEnvCache>,
    /// The resolved `$GOENV` path to consult, if any — resolved once by the caller rather
    /// than looked up internally, so nothing in this crate reads the live host environment
    /// implicitly (spec 034 follow-up C3/C4, issue #559). Production callers
    /// (`crate::lib::register_ecosystems`) pass [`goenv_path`]'s result; tests pass a fixture
    /// path. `None` — the [`Default`] value — means "no `$GOENV` file", the same hermetic,
    /// zero-host-read behavior [`crate::parser::parse_go_mod`]'s doc already promises.
    pub goenv_path: Option<PathBuf>,
}

/// Resolves `$GOENV`'s path (FR-001).
///
/// The `GOENV` environment variable if set and non-empty, else the platform default
/// `os.UserConfigDir()/go/env` (`~/.config/go/env` on Linux/macOS, `%AppData%\go\env` on
/// Windows).
#[must_use]
pub fn goenv_path() -> Option<PathBuf> {
    goenv_path_with_env(std::env::var("GOENV").ok())
}

/// [`goenv_path`], but taking the `GOENV` environment variable's value explicitly instead of
/// reading the real process environment — lets tests inject a fixture value without mutating
/// process-global state (this crate forbids `unsafe` code, so an actual `std::env::set_var`
/// call, which is `unsafe` since Rust 2024, is not an option here).
fn goenv_path_with_env(env_value: Option<String>) -> Option<PathBuf> {
    if let Some(value) = env_value.filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(value));
    }
    dirs::config_dir().map(|dir| dir.join("go").join("env"))
}

/// Resolves `$GOENV` into a [`GoEnvConfig`] (spec FR-001–FR-008).
///
/// `None`/an unreadable path (no `$GOENV` file at all) resolves to [`GoEnvConfig::default`] —
/// every dependency keeps resolving to plain [`DependencySource::Registry`] (US-005, NFR-004:
/// no additional filesystem/network activity beyond the one `stat` `MtimeFileCache` already
/// performs).
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::RegistryAccessPolicy;
/// use deps_go::config::{GoEnvCache, resolve};
///
/// let cache = GoEnvCache::new();
/// let policy = RegistryAccessPolicy::default();
/// let config = resolve(&cache, &policy);
/// // No override anywhere in a typical test/CI environment with no $GOENV file.
/// assert!(config.goproxy_chain().is_none() || config.goproxy_chain().is_some());
/// ```
#[must_use]
pub fn resolve(cache: &GoEnvCache, policy: &RegistryAccessPolicy) -> GoEnvConfig {
    resolve_at(cache, policy, goenv_path())
}

/// Resolves `$GOENV` into a [`GoEnvConfig`], reading the already-resolved
/// [`GoParseContext::goenv_path`] instead of calling [`goenv_path`] itself.
///
/// This is the seam `crate::parser::parse_go_mod_with_context` calls in production, and the
/// way tests exercise the full parse -> resolve -> `register_chain` -> `get_versions_from`
/// path without depending on the real host `$GOENV`.
#[must_use]
pub fn resolve_with_context(ctx: &GoParseContext) -> GoEnvConfig {
    resolve_at(&ctx.config_cache, &ctx.policy, ctx.goenv_path.clone())
}

/// [`resolve`], but taking the `$GOENV` path explicitly instead of [`goenv_path`] — lets tests
/// inject a fixture path.
fn resolve_at(
    cache: &GoEnvCache,
    policy: &RegistryAccessPolicy,
    path: Option<PathBuf>,
) -> GoEnvConfig {
    let Some(path) = path else {
        return GoEnvConfig::default();
    };
    let Some(raw) = cache.get_or_parse(&path) else {
        return GoEnvConfig::default();
    };
    GoEnvConfig::from_raw(&raw, policy)
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

    // --- GoProxyUrl ---

    #[test]
    fn test_proxy_url_accepts_https() {
        assert!(GoProxyUrl::new("https://goproxy.mycorp.example", &all_policy()).is_ok());
    }

    #[test]
    fn test_proxy_url_rejects_http() {
        assert!(matches!(
            GoProxyUrl::new("http://goproxy.mycorp.example", &all_policy()),
            Err(GoProxyUrlError::NotHttps(_))
        ));
    }

    #[test]
    fn test_proxy_url_rejects_userinfo() {
        assert!(matches!(
            GoProxyUrl::new("https://user:pass@goproxy.mycorp.example", &all_policy()),
            Err(GoProxyUrlError::UserInfoPresent)
        ));
    }

    #[test]
    fn test_proxy_url_rejects_invalid() {
        assert!(matches!(
            GoProxyUrl::new("not-a-valid-url", &all_policy()),
            Err(GoProxyUrlError::InvalidUrl(_))
        ));
    }

    /// F3: a query string breaks the `{base}/{module}/@v/...` path-join convention every
    /// request URL builder relies on — rejected rather than silently mis-joined.
    #[test]
    fn test_proxy_url_rejects_query_string() {
        assert!(matches!(
            GoProxyUrl::new("https://goproxy.mycorp.example/?tok=abc", &all_policy()),
            Err(GoProxyUrlError::InvalidUrl(_))
        ));
    }

    /// F3: a fragment is rejected for the same path-join reason as a query string.
    #[test]
    fn test_proxy_url_rejects_fragment() {
        assert!(matches!(
            GoProxyUrl::new("https://goproxy.mycorp.example/#frag", &all_policy()),
            Err(GoProxyUrlError::InvalidUrl(_))
        ));
    }

    #[test]
    fn test_proxy_url_policy_matrix() {
        assert!(GoProxyUrl::new("https://goproxy.mycorp.example", &off_policy()).is_err());
    }

    // --- glob matching (FR-007/FR-008) ---

    #[test]
    fn test_glob_pattern_prefix_wildcard_matches() {
        let pattern = GlobPattern::new("git.mycorp.example/*");
        assert!(pattern.matches("git.mycorp.example/internal/auth"));
        assert!(pattern.matches("git.mycorp.example/anything"));
    }

    #[test]
    fn test_glob_pattern_no_match() {
        let pattern = GlobPattern::new("git.mycorp.example/*");
        assert!(!pattern.matches("github.com/other/repo"));
    }

    #[test]
    fn test_glob_pattern_exact_element_match() {
        let pattern = GlobPattern::new("github.com/myorg");
        assert!(pattern.matches("github.com/myorg"));
        assert!(pattern.matches("github.com/myorg/repo"));
        assert!(!pattern.matches("github.com/otherorg"));
    }

    #[test]
    fn test_glob_pattern_not_enough_segments_no_match() {
        // Pattern needs 3 elements; target has only 2.
        let pattern = GlobPattern::new("git.mycorp.example/internal/*");
        assert!(!pattern.matches("git.mycorp.example/internal"));
    }

    #[test]
    fn test_glob_pattern_question_mark() {
        let pattern = GlobPattern::new("git.mycorp.example/repo?");
        assert!(pattern.matches("git.mycorp.example/repo1"));
        assert!(!pattern.matches("git.mycorp.example/repo12"));
    }

    #[test]
    fn test_glob_pattern_character_class() {
        let pattern = GlobPattern::new("git.mycorp.example/repo[12]");
        assert!(pattern.matches("git.mycorp.example/repo1"));
        assert!(pattern.matches("git.mycorp.example/repo2"));
        assert!(!pattern.matches("git.mycorp.example/repo3"));
    }

    #[test]
    fn test_glob_pattern_negated_character_class() {
        let pattern = GlobPattern::new("git.mycorp.example/repo[^12]");
        assert!(!pattern.matches("git.mycorp.example/repo1"));
        assert!(pattern.matches("git.mycorp.example/repo3"));
    }

    #[test]
    fn test_glob_pattern_range_character_class() {
        let pattern = GlobPattern::new("git.mycorp.example/repo[a-c]");
        assert!(pattern.matches("git.mycorp.example/repob"));
        assert!(!pattern.matches("git.mycorp.example/repod"));
    }

    #[test]
    fn test_glob_pattern_malformed_class_never_panics_no_match() {
        let pattern = GlobPattern::new("git.mycorp.example/repo[unterminated");
        assert!(!pattern.matches("git.mycorp.example/repo1"));
    }

    #[test]
    fn test_glob_pattern_wildcard_never_crosses_slash() {
        let pattern = GlobPattern::new("git.mycorp.example/*");
        // `*` is scoped to one path element after truncation; the truncated prefix for a
        // 2-element pattern never contains more than 2 segments, so this is inherently
        // satisfied — asserted here as a regression guard.
        assert!(pattern.matches("git.mycorp.example/internal/auth/deep/nested"));
    }

    /// Perf regression guard (spec 034 review finding): the naive recursive-backtracking
    /// matcher this replaced was `O(2^n)` on an adversarial many-consecutive-`*` pattern
    /// against a non-matching text — empirically 15 stars took ~19s and 20 stars timed out.
    /// The iterative token matcher must resolve this in well under a second.
    #[test]
    fn test_glob_pattern_many_stars_no_exponential_blowup() {
        let pattern = GlobPattern::new(&format!("{}x", "*".repeat(30)));
        let text = "a".repeat(60);

        let start = std::time::Instant::now();
        let matched = pattern.matches(&text);
        let elapsed = start.elapsed();

        assert!(
            !matched,
            "pattern requires a literal 'x' the text never has"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "glob matching took too long: {elapsed:?} (possible backtracking regression)"
        );
    }

    /// Defense-in-depth: an oversized pattern (beyond `MAX_GLOB_PATTERN_LENGTH`) is treated
    /// as permanently non-matching rather than compiled at all.
    #[test]
    fn test_glob_pattern_oversized_pattern_never_matches() {
        let long_pattern = "*".repeat(MAX_GLOB_PATTERN_LENGTH + 1);
        let pattern = GlobPattern::new(&long_pattern);
        assert!(!pattern.matches(&"a".repeat(100)));
    }

    /// F6 (spec 034 follow-up, issue #559 C2): an oversized `GOPRIVATE` pattern's silent
    /// fail-open must actually log a `tracing::warn!`, not just be non-matching.
    #[test]
    fn test_glob_pattern_oversized_pattern_logs_warning() {
        let long_pattern = "*".repeat(MAX_GLOB_PATTERN_LENGTH + 1);
        let log = deps_core::test_util::capture_tracing_output(|| {
            let _ = GlobPattern::new(&long_pattern);
        });
        assert!(
            log.contains("GOPRIVATE pattern exceeds max length"),
            "expected oversized-pattern warning in log: {log:?}"
        );
    }

    // --- GoEnvConfig::parse / resolve_source_for (FR-001-FR-009) ---

    #[test]
    fn test_empty_content_resolves_to_plain_registry() {
        let config = GoEnvConfig::parse("", &all_policy());
        assert_eq!(
            config.resolve_source_for("github.com/gin-gonic/gin"),
            DependencySource::Registry
        );
        assert!(config.goproxy_chain().is_none());
        assert!(!config.has_goprivate());
    }

    #[test]
    fn test_comments_and_blank_lines_ignored() {
        let content = "# a comment\n\nGOPROXY=https://goproxy.mycorp.example\n";
        let config = GoEnvConfig::parse(content, &all_policy());
        assert!(config.goproxy_chain().is_some());
    }

    /// US-001: a single-hop `GOPROXY,direct` chain resolves to `AlternateRegistry`.
    #[test]
    fn test_goproxy_single_hop_plus_direct() {
        let config = GoEnvConfig::parse(
            "GOPROXY=https://goproxy.mycorp.example,direct",
            &all_policy(),
        );
        let source = config.resolve_source_for("github.com/gin-gonic/gin");
        let DependencySource::AlternateRegistry {
            index,
            mirrors_crates_io,
        } = source
        else {
            panic!("expected AlternateRegistry");
        };
        assert!(!mirrors_crates_io);
        let chain = config.goproxy_chain().unwrap();
        assert_eq!(chain.key, index);
        assert_eq!(chain.hops.len(), 2);
        assert!(matches!(chain.hops[0], GoProxyHop::Url(_)));
        assert!(matches!(chain.hops[1], GoProxyHop::Direct));
    }

    /// US-004: `GOPROXY=off` as sole entry.
    #[test]
    fn test_goproxy_off_sole_entry() {
        let config = GoEnvConfig::parse("GOPROXY=off", &all_policy());
        let chain = config.goproxy_chain().unwrap();
        assert_eq!(chain.hops, vec![GoProxyHop::Off]);
    }

    /// FR-009: sole invalid entry fails the whole chain closed to `CustomRegistry`.
    #[test]
    fn test_goproxy_sole_invalid_entry_fails_closed() {
        let config = GoEnvConfig::parse("GOPROXY=not-a-valid-url", &all_policy());
        assert_eq!(
            config.resolve_source_for("github.com/gin-gonic/gin"),
            DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            }
        );
        assert!(config.goproxy_chain().is_none());
    }

    /// FR-009: an invalid hop is dropped when a valid one remains, no `CustomRegistry`
    /// escalation.
    #[test]
    fn test_goproxy_invalid_hop_dropped_when_valid_hop_remains() {
        let config = GoEnvConfig::parse(
            "GOPROXY=not-a-valid-url,https://goproxy.mycorp.example",
            &all_policy(),
        );
        let chain = config.goproxy_chain().unwrap();
        assert_eq!(chain.hops.len(), 1);
        assert!(matches!(chain.hops[0], GoProxyHop::Url(_)));
    }

    /// FR-011: a policy-blocked hop is treated the same as an invalid one.
    #[test]
    fn test_goproxy_policy_blocked_hop_fails_closed() {
        let config = GoEnvConfig::parse("GOPROXY=https://goproxy.mycorp.example", &off_policy());
        assert!(matches!(
            config.resolve_source_for("github.com/gin-gonic/gin"),
            DependencySource::CustomRegistry { .. }
        ));
    }

    /// FR-002: everything declared after a terminal `direct`/`off` hop is unreachable and
    /// dropped at parse time.
    #[test]
    fn test_goproxy_hops_after_terminal_are_dropped() {
        let config = GoEnvConfig::parse(
            "GOPROXY=https://a.example,direct,https://b.example",
            &all_policy(),
        );
        let chain = config.goproxy_chain().unwrap();
        assert_eq!(chain.hops.len(), 2);
        assert!(matches!(chain.hops[1], GoProxyHop::Direct));
    }

    /// FR-002: pipe-separated entries parse the same as comma-separated ones.
    #[test]
    fn test_goproxy_pipe_separated() {
        let config =
            GoEnvConfig::parse("GOPROXY=https://a.example|https://b.example", &all_policy());
        let chain = config.goproxy_chain().unwrap();
        assert_eq!(chain.hops.len(), 2);
    }

    /// S2: `,` and `|` are recorded with their real, distinct semantics rather than both
    /// collapsing to the same fallback rule.
    #[test]
    fn test_goproxy_separators_recorded_distinctly() {
        let config = GoEnvConfig::parse(
            "GOPROXY=https://a.example,https://b.example|https://c.example",
            &all_policy(),
        );
        let chain = config.goproxy_chain().unwrap();
        assert_eq!(chain.hops.len(), 3);
        assert_eq!(
            chain.separators,
            vec![ChainSeparator::NotFoundOnly, ChainSeparator::AnyError]
        );
    }

    /// S2: an all-comma chain (the common case) still records every transition as
    /// `NotFoundOnly`, matching this feature's original behavior.
    #[test]
    fn test_goproxy_all_comma_separators() {
        let config = GoEnvConfig::parse(
            "GOPROXY=https://a.example,https://b.example,direct",
            &all_policy(),
        );
        let chain = config.goproxy_chain().unwrap();
        assert_eq!(
            chain.separators,
            vec![ChainSeparator::NotFoundOnly, ChainSeparator::NotFoundOnly]
        );
    }

    /// FR-008/US-002: a `GOPRIVATE`-matched module bypasses `GOPROXY` entirely.
    #[test]
    fn test_goprivate_bypasses_goproxy() {
        let content =
            "GOPROXY=https://goproxy.mycorp.example,direct\nGOPRIVATE=git.mycorp.example/*\n";
        let config = GoEnvConfig::parse(content, &all_policy());

        let private_source = config.resolve_source_for("git.mycorp.example/internal/auth");
        assert_eq!(
            private_source,
            DependencySource::AlternateRegistry {
                index: GOPRIVATE_CHAIN_KEY.to_string(),
                mirrors_crates_io: false,
            }
        );

        let public_source = config.resolve_source_for("github.com/gin-gonic/gin");
        assert!(matches!(
            public_source,
            DependencySource::AlternateRegistry { .. }
        ));
        assert_ne!(private_source, public_source);
        assert!(config.has_goprivate());
    }

    /// FR-008: `GOPRIVATE` alone (no `GOPROXY` declared) still routes a matched module to the
    /// bypass chain.
    #[test]
    fn test_goprivate_without_goproxy() {
        let config = GoEnvConfig::parse("GOPRIVATE=git.mycorp.example/*", &all_policy());
        assert!(config.goproxy_chain().is_none());
        assert_eq!(
            config.resolve_source_for("git.mycorp.example/internal/auth"),
            DependencySource::AlternateRegistry {
                index: GOPRIVATE_CHAIN_KEY.to_string(),
                mirrors_crates_io: false,
            }
        );
        assert_eq!(
            config.resolve_source_for("github.com/other/repo"),
            DependencySource::Registry
        );
    }

    /// Edge case (issue #559): `GOPROXY=`/`GOPRIVATE=` with nothing after the `=` parse
    /// successfully but resolve exactly as if the key were absent — no phantom empty-string
    /// hop/pattern, no panic.
    #[test]
    fn test_goenv_empty_goproxy_and_goprivate_values_are_absent() {
        let config = GoEnvConfig::parse("GOPROXY=\nGOPRIVATE=\n", &all_policy());
        assert!(config.goproxy_chain().is_none());
        assert!(!config.has_goprivate());
        assert_eq!(
            config.resolve_source_for("github.com/gin-gonic/gin"),
            DependencySource::Registry
        );
    }

    /// Edge case (issue #559): a `$GOENV` line with no `=` at all (not a comment, not blank)
    /// is silently ignored rather than panicking or corrupting the previous/next key.
    #[test]
    fn test_goenv_malformed_line_without_equals_is_ignored() {
        let content = "GARBAGE LINE WITH NO EQUALS\nGOPROXY=https://goproxy.mycorp.example\n";
        let config = GoEnvConfig::parse(content, &all_policy());
        assert!(config.goproxy_chain().is_some());
    }

    /// Edge case (issue #559): the same `GOPRIVATE` glob pattern declared twice still matches
    /// (no dedup requirement, no panic) — duplicates are just redundant, not invalid.
    #[test]
    fn test_goenv_duplicate_goprivate_patterns_still_match() {
        let config = GoEnvConfig::parse(
            "GOPRIVATE=git.mycorp.example/*,git.mycorp.example/*",
            &all_policy(),
        );
        assert!(config.has_goprivate());
        assert_eq!(
            config.resolve_source_for("git.mycorp.example/internal/auth"),
            DependencySource::AlternateRegistry {
                index: GOPRIVATE_CHAIN_KEY.to_string(),
                mirrors_crates_io: false,
            }
        );
    }

    /// Edge case (issue #559): a chain mixing `|` before `,` (rather than the `,`-then-`|`
    /// order `test_goproxy_separators_recorded_distinctly` already covers) still records each
    /// transition with its own real semantics, not the first separator seen in the value.
    #[test]
    fn test_goproxy_mixed_pipe_then_comma_separators() {
        let config = GoEnvConfig::parse(
            "GOPROXY=https://a.example|https://b.example,direct",
            &all_policy(),
        );
        let chain = config.goproxy_chain().unwrap();
        assert_eq!(chain.hops.len(), 3);
        assert!(matches!(chain.hops[2], GoProxyHop::Direct));
        assert_eq!(
            chain.separators,
            vec![ChainSeparator::AnyError, ChainSeparator::NotFoundOnly]
        );
    }

    /// C1 (spec 034 follow-up, issue #559) — **known limitation, pinned deliberately, not a
    /// desired behavior**: a separator preceding a *dropped* invalid hop is discarded rather
    /// than carried onto the merged transition between the two surviving hops. Here the
    /// user's `|` (fall through on any error) before the invalid entry is lost, and the `,`
    /// (fall through on not-found only) that happened to follow the dropped entry wins
    /// instead — see `parse_goproxy`'s doc and `docs/ECOSYSTEM_GUIDE.md`'s GOPROXY section.
    /// Pre-existing since PR #558; fixing the underlying carry-over behavior is out of scope
    /// for this PR and tracked as a separate follow-up.
    #[test]
    fn test_goproxy_separator_before_dropped_hop_is_not_carried_over() {
        let config = GoEnvConfig::parse(
            "GOPROXY=https://a.example|not-a-valid-url,https://c.example",
            &all_policy(),
        );
        let chain = config.goproxy_chain().unwrap();
        assert_eq!(chain.hops.len(), 2);
        assert_eq!(chain.separators, vec![ChainSeparator::NotFoundOnly]);
    }

    // --- redaction (FR-014/NFR-001) ---

    /// M1-shaped guard: `InvalidEntry::raw` and the `tracing::warn!` line built from it must
    /// never carry a userinfo-bearing hop's credential through.
    #[test]
    fn test_invalid_hop_redacts_userinfo_from_raw_and_log() {
        let log = deps_core::test_util::capture_tracing_output(|| {
            let config = GoEnvConfig::parse(
                "GOPROXY=https://user:hunter2@goproxy.mycorp.example",
                &all_policy(),
            );
            let source = config.resolve_source_for("github.com/gin-gonic/gin");
            let DependencySource::CustomRegistry { url } = source else {
                panic!("expected CustomRegistry");
            };
            assert!(!url.contains("hunter2"), "leaked credential: {url}");
            assert!(!url.contains("user:"), "leaked username: {url}");
        });
        assert!(
            !log.contains("hunter2"),
            "tracing output leaked credential: {log:?}"
        );
    }

    /// NFR-001/SC-005 structural guarantee: a URL carrying userinfo is rejected at
    /// construction (never stripped-and-proceeded), so no [`GoProxyUrl`] ever holds a
    /// credential.
    #[test]
    fn test_userinfo_rejected_never_retained() {
        let err =
            GoProxyUrl::new("https://user:hunter2@goproxy.example", &all_policy()).unwrap_err();
        assert_eq!(err, GoProxyUrlError::UserInfoPresent);
    }

    // --- $GOENV path resolution (FR-001) ---

    #[test]
    fn test_resolve_at_no_path_is_default() {
        let cache = GoEnvCache::new();
        let config = resolve_at(&cache, &all_policy(), None);
        assert!(config.goproxy_chain().is_none());
    }

    #[test]
    fn test_resolve_at_nonexistent_path_is_default() {
        let cache = GoEnvCache::new();
        let config = resolve_at(
            &cache,
            &all_policy(),
            Some(PathBuf::from("/nonexistent/go/env")),
        );
        assert!(config.goproxy_chain().is_none());
    }

    #[test]
    fn test_resolve_at_reads_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");
        std::fs::write(&path, "GOPROXY=https://goproxy.mycorp.example,direct\n").unwrap();

        let cache = GoEnvCache::new();
        let config = resolve_at(&cache, &all_policy(), Some(path));
        assert!(config.goproxy_chain().is_some());
    }

    #[test]
    fn test_goenv_path_honors_env_var() {
        let path = goenv_path_with_env(Some("/custom/goenv/path".to_string()));
        assert_eq!(path, Some(PathBuf::from("/custom/goenv/path")));
    }

    #[test]
    fn test_goenv_path_empty_env_var_falls_back_to_platform_default() {
        let with_empty = goenv_path_with_env(Some(String::new()));
        let with_none = goenv_path_with_env(None);
        assert_eq!(with_empty, with_none);
    }
}
