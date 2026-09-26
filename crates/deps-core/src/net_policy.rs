//! Reachability policy for registry index URLs declared by a workspace file.
//!
//! A `.cargo/config.toml`/`Cargo.toml` value is attacker-controlled the moment a hostile
//! repository is cloned and opened — this LSP fetches on parse, before any build ever runs
//! (spec `.local/specs/023-cargo-custom-registries/spec.md` NFR-003). [`classify_host`]
//! answers "is this URL's host the kind no legitimate registry index or redirect ever
//! targets" from the URL alone (no DNS resolution — see [`classify_host`]'s docs for why),
//! and [`RegistryAccessPolicy`] is the live-updatable, process-wide switch a caller checks
//! before ever fetching a workspace-declared URL.
//!
//! Placed in `deps-core`, not an ecosystem crate: [`RegistryAccessPolicy`] must be held by
//! `ServerState` without a `#[cfg(feature = "cargo")]` gate, and host classification belongs
//! beside [`crate::cache`]'s existing `ensure_https`/loopback checks, which already perform
//! the same class of validation (DRY). [`crate::cache`]'s redirect-hop hardening also needs
//! this exact classifier — see [`HostClass::never_a_registry`].
//!
//! # Moved
//!
//! URL/log/error-message redaction (log-safe credential stripping, not host policy) now lives
//! in [`crate::redact`], re-exported below for compatibility. This module keeps host
//! classification and index-URL validation only.

use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU8, Ordering};

use crate::EcosystemId;

/// Classification of a URL's host, for [`RegistryAccessPolicy`] to evaluate against
/// [`WorkspaceRegistryAccess`].
///
/// Computed from the URL alone (see [`classify_host`]) — never from a DNS resolution, so an
/// attacker-controlled hostname that merely *resolves* to a blocked range is not caught here.
/// This residual scope is by design, not an open gap: the DNS-rebinding TOCTOU it would
/// otherwise allow is closed separately, at connect time, by `crate::cache`'s
/// `BlockedAddrResolver` (a `reqwest::dns::Resolve` implementation, fail-closed on lookup
/// errors, wired into every client via `build_guarded_client`) — see [`classify_addr`], its
/// counterpart for already-resolved addresses.
///
/// `#[non_exhaustive]`: unlike most security-sensitive enums in this module, a new host
/// class is a realistic, desirable future addition — a newly-documented cloud-metadata
/// endpoint or reserved range should ship as a non-breaking patch, not force a major version
/// bump on every consumer. No exhaustive `match` on this enum exists outside `deps-core`
/// today (`crate::cache::hop_targets_blocked_host` and other callers compare by equality or
/// [`Self::never_a_registry`], not an exhaustive match), so this costs nothing in-tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostClass {
    /// `127.0.0.0/8`, `::1`, `localhost`, `*.localhost`.
    Loopback,
    /// `169.254.0.0/16`, `fe80::/10` — includes [`HostClass::CloudMetadata`]'s narrower range.
    LinkLocal,
    /// `169.254.169.254` / `fd00:ec2::254`, or the names cloud providers document for their
    /// instance-metadata endpoint (`metadata.google.internal`, `metadata.goog`) — a
    /// deliberately narrower label inside [`HostClass::LinkLocal`]/[`HostClass::InternalName`],
    /// kept separate only so a blocked-host warning can name it specifically.
    CloudMetadata,
    /// `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
    PrivateV4,
    /// `100.64.0.0/10` — carrier-grade NAT.
    Cgnat,
    /// `fc00::/7`.
    UniqueLocalV6,
    /// `0.0.0.0`, `::`.
    Unspecified,
    /// A name ending in `.internal`/`.local`/`.home.arpa`, or any single-label host (no dot) —
    /// never a real public registry's hostname.
    InternalName,
    /// Everything else: a public IP literal, or a multi-label name not matching any of the
    /// above suffixes.
    Global,
}

impl HostClass {
    /// Whether this class is one no legitimate registry index (or a redirect from one) could
    /// ever legitimately target.
    ///
    /// Used unconditionally by [`crate::cache`]'s redirect-hop hardening, independent of
    /// [`WorkspaceRegistryAccess`]: deliberately narrower than [`WorkspaceRegistryAccess::PublicOnly`]
    /// blocks outright, since [`HostClass::PrivateV4`]/[`HostClass::Cgnat`]/
    /// [`HostClass::UniqueLocalV6`]/[`HostClass::InternalName`] are legitimate redirect
    /// targets for a corporate registry's own network — only the classes below are never a
    /// registry under any policy.
    ///
    /// Fail-open by construction for a variant not listed below: since [`HostClass`] is
    /// `#[non_exhaustive]`, a future variant (e.g. a newly-documented cloud-metadata range)
    /// defaults to "not never-a-registry" here until this function is explicitly updated to
    /// include it — a new variant must be triaged into this list, not assumed covered.
    #[must_use]
    pub const fn never_a_registry(self) -> bool {
        matches!(
            self,
            Self::Loopback | Self::LinkLocal | Self::CloudMetadata | Self::Unspecified
        )
    }
}

impl std::fmt::Display for HostClass {
    /// A human-readable label for this class, used in user-facing warnings/diagnostics —
    /// never the `{:?}` derive, which renders the Rust identifier rather than prose.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::CloudMetadata => "cloud metadata",
            Self::PrivateV4 => "private (RFC1918)",
            Self::Cgnat => "carrier-grade NAT",
            Self::UniqueLocalV6 => "unique-local IPv6",
            Self::Unspecified => "unspecified",
            Self::InternalName => "internal name",
            Self::Global => "global",
        })
    }
}

/// Unwraps an IPv4-mapped (`::ffff:a.b.c.d`) or NAT64-embedded (`64:ff9b::a.b.c.d`, RFC 6052
/// well-known prefix) IPv6 address to its embedded IPv4 form, so classification cannot be
/// bypassed by writing the same address in either v4-in-v6 form (e.g. `::ffff:169.254.169.254`
/// or `64:ff9b::a9fe:a9fe`). The NAT64 case matters here specifically because an attacker's DNS
/// answer can return any AAAA record it likes, and a client behind a NAT64/DNS64 gateway (or a
/// local 464XLAT/CLAT translator) treats `64:ff9b::/96` as routable to the embedded IPv4 address
/// (impl-critic finding, verified empirically: `64:ff9b::a9fe:a9fe` classified `Global` before
/// this fix).
///
/// Deliberately does **not** additionally unwrap:
/// - The deprecated IPv4-*compatible* form (`::a.b.c.d`, RFC 4291 §2.5.5.1, no `ffff` prefix):
///   `Ipv6Addr::to_ipv4()` treats *any* address with its first 96 bits zero as embedding an
///   IPv4 address, which would misclassify `::1` (loopback) as `0.0.0.1` and `::` (unspecified)
///   as `0.0.0.0` — a narrower, *new* bypass in exchange for closing a narrower, legacy one.
///   Modern network stacks generally do not route this deprecated form at all, so it is
///   accepted as low-real-world-risk (impl-critic finding, unwrap-mapped-v6/NAT64 are the
///   actively-exploitable forms and are handled above).
/// - 6to4 (`2002::/16`, RFC 3056), which also embeds an IPv4 address in its prefix: a narrower,
///   largely-deprecated IPv6-transition mechanism — NAT64/DNS64 remains commonly deployed
///   today, 6to4 does not — documented as a residual, not fixed by this pass.
fn unwrap_mapped_v4(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .or_else(|| nat64_embedded_v4(v6))
            .map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

/// Extracts the IPv4 address embedded in a NAT64 well-known-prefix (RFC 6052 `64:ff9b::/96`)
/// IPv6 address, e.g. `64:ff9b::a9fe:a9fe` -> `169.254.169.254`.
fn nat64_embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = v6.segments();
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        let [a, b] = segments[6].to_be_bytes();
        let [c, d] = segments[7].to_be_bytes();
        Some(Ipv4Addr::new(a, b, c, d))
    } else {
        None
    }
}

/// Classifies `addr` (already unwrapped of any IPv4-mapping) into a [`HostClass`].
fn classify_ip(addr: IpAddr) -> HostClass {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                HostClass::Loopback
            } else if v4 == Ipv4Addr::new(169, 254, 169, 254) {
                HostClass::CloudMetadata
            } else if v4.is_link_local() {
                HostClass::LinkLocal
            } else if v4.is_unspecified() {
                HostClass::Unspecified
            } else if v4.is_private() {
                HostClass::PrivateV4
            } else if v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000 {
                // 100.64.0.0/10
                HostClass::Cgnat
            } else {
                HostClass::Global
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                HostClass::Loopback
            } else if v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254] {
                HostClass::CloudMetadata
            } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                // fe80::/10
                HostClass::LinkLocal
            } else if v6.is_unspecified() {
                HostClass::Unspecified
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                // fc00::/7
                HostClass::UniqueLocalV6
            } else {
                HostClass::Global
            }
        }
    }
}

/// Classifies a hostname (never an IP literal — those go through [`classify_ip`]) into a
/// [`HostClass`].
fn classify_name(host: &str) -> HostClass {
    let lower = host.to_ascii_lowercase();
    // `url::Url` keeps a trailing root-label dot (`localhost.` != `localhost`); strip it or a
    // single appended `.` bypasses every check below into `Global` (security review S1).
    // `trim_end_matches` (not `strip_suffix`) also handles `localhost..` for free.
    let lower = lower.trim_end_matches('.');
    if lower == "localhost" || lower.ends_with(".localhost") {
        return HostClass::Loopback;
    }
    if lower == "metadata.google.internal" || lower == "metadata.goog" {
        return HostClass::CloudMetadata;
    }
    if lower.ends_with(".internal") || lower.ends_with(".local") || lower.ends_with(".home.arpa") {
        return HostClass::InternalName;
    }
    if !lower.contains('.') {
        // A single-label host (no dot at all) can never be a real public registry name.
        return HostClass::InternalName;
    }
    HostClass::Global
}

/// Classifies a DNS-resolved socket address into a [`HostClass`].
///
/// The counterpart to [`classify_host`] used by [`crate::cache`]'s connect-time resolver guard
/// (issue #449) to close the DNS-rebinding TOCTOU gap the module docs describe: a hostname's
/// *resolved* address, not just its string form, needs the same classification. Reuses this
/// module's own private IP-classification and mapped-address-unwrapping helpers rather than
/// duplicating their match arms (DRY).
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::{HostClass, classify_addr};
///
/// let addr = "169.254.169.254".parse().unwrap();
/// assert_eq!(classify_addr(addr), HostClass::CloudMetadata);
/// ```
#[must_use]
pub fn classify_addr(addr: IpAddr) -> HostClass {
    classify_ip(unwrap_mapped_v4(addr))
}

/// Classifies `url`'s host into a [`HostClass`], from the URL alone — **no DNS resolution**
/// is performed (see the module docs' residual-risk note).
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::{HostClass, classify_host};
/// use url::Url;
///
/// let url = Url::parse("https://169.254.169.254/latest/meta-data/").unwrap();
/// assert_eq!(classify_host(&url), HostClass::CloudMetadata);
///
/// let url = Url::parse("https://index.crates.io/").unwrap();
/// assert_eq!(classify_host(&url), HostClass::Global);
/// ```
#[must_use]
pub fn classify_host(url: &url::Url) -> HostClass {
    match url.host() {
        Some(url::Host::Ipv4(v4)) => classify_ip(unwrap_mapped_v4(IpAddr::V4(v4))),
        Some(url::Host::Ipv6(v6)) => classify_ip(unwrap_mapped_v4(IpAddr::V6(v6))),
        Some(url::Host::Domain(name)) => classify_name(name),
        None => HostClass::InternalName,
    }
}

/// Whether `candidate` is trusted against `trusted`: they share an [`url::Url::origin`], and
/// `candidate`'s path lies at or under `trusted`'s path at a proper path-segment boundary.
///
/// The origin-and-path pin shared by [`crate::cache::HttpCache`]'s trusted-origin request
/// family (redirect-hop confinement) and `deps-nuget`'s registration-hive page `@id`
/// pre-check — centralized here (issue #795 S1/S2) because both independently needed the
/// same fix for the same class of bug: a raw `str::starts_with` test — on the full URL
/// string, or even on the path alone — is satisfied by a same-origin *sibling* whose path
/// merely shares a textual prefix. A trusted path of `/cargo/index` must reject
/// `/cargo/indexEVIL`, `/cargo/index-public/steal`, and `/cargo/index.evil/x` alike, while
/// still accepting `/cargo/index` itself and `/cargo/index/se/rd/serde`. Comparing origins
/// structurally (not textually) closes the analogous host-level bypass this same function
/// also guards against — see [`classify_host`]'s sibling concerns and issue #795's own
/// bypass shapes (`<host>.evil.com`, `<host>@evil.com`, `<host>-evil.com`).
///
/// Correct regardless of whether `trusted`'s path happens to already end in `/`: `/cargo/index`
/// and `/cargo/index/` are treated identically as the trust boundary.
///
/// Assumes a special URL scheme (`http`/`https`): for any other scheme, [`url::Url::origin`]
/// returns a fresh opaque origin per parse that never compares equal to another, even a
/// re-parse of the identical string, so this fails closed (rejects everything) rather than
/// silently trusting one.
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::is_trusted_prefix;
/// use url::Url;
///
/// let trusted = Url::parse("https://artifacts.corp/cargo/index").unwrap();
/// let sibling = Url::parse("https://artifacts.corp/cargo/indexEVIL/steal").unwrap();
/// let nested = Url::parse("https://artifacts.corp/cargo/index/se/rd/serde").unwrap();
/// let off_host = Url::parse("https://artifacts.corp.evil.com/cargo/index").unwrap();
///
/// assert!(!is_trusted_prefix(&sibling, &trusted));
/// assert!(is_trusted_prefix(&nested, &trusted));
/// assert!(!is_trusted_prefix(&off_host, &trusted));
/// ```
#[must_use]
pub fn is_trusted_prefix(candidate: &url::Url, trusted: &url::Url) -> bool {
    candidate.origin() == trusted.origin() && path_under_prefix(candidate.path(), trusted.path())
}

/// Whether `path` equals `prefix`, or continues immediately after a `/` following it —
/// [`is_trusted_prefix`]'s path-segment-boundary check, extracted so both branches (exact
/// match and proper-child match) are independently readable. A trailing `/` on `prefix` is
/// normalized away first, so a caller-supplied trusted path is compared identically whether
/// or not it happens to end in one.
fn path_under_prefix(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The user-facing policy governing whether a workspace-declared registry index is ever
/// fetched at all.
///
/// Applied **only** to workspace-provenance URLs (a `Cargo.toml`/`.cargo/config.toml` value
/// found inside the opened workspace) — a `$CARGO_HOME`-provenance index is the user's own
/// trusted configuration and is never policy-checked, under any variant here.
///
/// **Exhaustive** (issue #769): security-sensitive gate for registry fetches — a new variant
/// landing in a wildcard arm at any consuming match site would silently pick an unintended
/// access level instead of failing to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WorkspaceRegistryAccess {
    /// Block every workspace-declared index — the only complete boundary. Also blocks the
    /// `registry`/`registry-index` alias path, not only `[source]` replace-with.
    Off,
    /// Allow only [`HostClass::Global`] hosts — blocks the observed attack shape (an IP
    /// literal in a metadata/RFC1918 range) while leaving a corporate `https://index.mycorp.dev`
    /// working, since a DNS name cannot be classified without resolving it (the residual risk
    /// this variant's name is honest about — see the module docs).
    #[default]
    PublicOnly,
    /// Allow every class — today's pre-hardening behavior, the escape hatch for a workspace
    /// that legitimately points at an RFC1918/loopback registry.
    All,
}

impl WorkspaceRegistryAccess {
    /// Whether a workspace-declared URL classified as `class` may be fetched under this
    /// policy.
    #[must_use]
    pub const fn allows(self, class: HostClass) -> bool {
        match self {
            Self::Off => false,
            Self::PublicOnly => matches!(class, HostClass::Global),
            Self::All => true,
        }
    }

    /// Numeric encoding for [`RegistryAccessPolicy`]'s lock-free storage, and — via
    /// `crate::cache`'s workspace-tier cache-key computation — for the digit distinguishing
    /// one policy era's workspace cache entries from another's.
    pub(crate) const fn to_u8(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::PublicOnly => 1,
            Self::All => 2,
        }
    }

    /// Inverse of [`Self::to_u8`]; any value the atomic could not have produced falls back to
    /// the safe default rather than panicking.
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Off,
            2 => Self::All,
            _ => Self::PublicOnly,
        }
    }
}

/// Live-updatable, `Arc`-shareable handle to the current [`WorkspaceRegistryAccess`] setting.
///
/// Backed by an `AtomicU8` rather than a lock: the manifest parse path that reads this is a
/// synchronous call inside an async fn, where a `tokio::sync::RwLock` cannot be awaited and a
/// `std::sync::RwLock` would be unnecessary ceremony for one small `Copy` enum. `initialize`
/// and `workspace/didChangeConfiguration` call [`Self::set`]; every manifest parse calls
/// [`Self::get`].
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
///
/// let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off);
/// assert_eq!(policy.get(), WorkspaceRegistryAccess::Off);
/// policy.set(WorkspaceRegistryAccess::PublicOnly);
/// assert_eq!(policy.get(), WorkspaceRegistryAccess::PublicOnly);
/// ```
#[derive(Debug)]
pub struct RegistryAccessPolicy(AtomicU8);

impl RegistryAccessPolicy {
    /// Creates a handle initialized to `initial`.
    #[must_use]
    pub fn new(initial: WorkspaceRegistryAccess) -> Self {
        Self(AtomicU8::new(initial.to_u8()))
    }

    /// The current policy.
    #[must_use]
    pub fn get(&self) -> WorkspaceRegistryAccess {
        WorkspaceRegistryAccess::from_u8(self.0.load(Ordering::Relaxed))
    }

    /// Updates the current policy, effective for every parse after this call returns.
    ///
    /// A tightening (e.g. `All` -> `PublicOnly`/`Off`) only gates *future* parses: it does not
    /// purge state a looser policy already produced, such as `deps-cargo`'s
    /// `CargoRegistry::alternates` map — an already-registered alternate-registry client for a
    /// now-blocked host stays reachable until its owning document is next re-parsed (today,
    /// `workspace/didChangeConfiguration` does not trigger a re-parse of open documents). This
    /// is pre-existing behavior, unrelated to this type's own storage, and unchanged by it.
    ///
    /// # Warning
    ///
    /// Calling this directly on a handle already bound to an
    /// [`crate::cache::HttpCache`] (via [`crate::cache::HttpCache::with_policy`]) updates this
    /// value but does not rebuild that cache's workspace transport, leaving its `AddrGuard` and
    /// cache-key namespace on the stale policy. For a bound cache, always mutate through
    /// [`crate::cache::HttpCache::set_registry_policy`] instead, which updates this handle and
    /// rebuilds the transport together.
    pub fn set(&self, value: WorkspaceRegistryAccess) {
        self.0.store(value.to_u8(), Ordering::Relaxed);
    }
}

impl Default for RegistryAccessPolicy {
    fn default() -> Self {
        Self::new(WorkspaceRegistryAccess::default())
    }
}

/// Why a candidate registry/index URL failed [`validate_index_url`].
///
/// Shared by `deps-cargo`, `deps-npm`, and `deps-pypi` — each ecosystem crate either
/// re-exports this directly (`deps-cargo`, `deps-pypi`) or wraps it in its own
/// `From`-mapped error enum (`deps-npm`, which needs an extra `${VAR}`-expansion variant).
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::{IndexUrlError, PolicyGate, RedactedUrl, validate_index_url};
/// use deps_core::EcosystemId;
///
/// let err =
///     validate_index_url("not a url", "not a url", EcosystemId::Cargo, PolicyGate::Skip).unwrap_err();
/// assert_eq!(err, IndexUrlError::InvalidUrl(RedactedUrl::new("not a url")));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexUrlError {
    /// The value did not parse as a URL at all.
    #[error("not a valid URL: {0}")]
    InvalidUrl(RedactedUrl),
    /// The URL's scheme is not `https`.
    #[error("registry index must use https, got scheme {0:?}")]
    NotHttps(String),
    /// The URL carries a `user:pass@`/`user@` component.
    #[error("registry index URL must not carry userinfo")]
    UserInfoPresent,
    /// The candidate's host is blocked by the current [`WorkspaceRegistryAccess`] policy.
    #[error("registry index host class {class} blocked by registries.workspace_registries policy")]
    BlockedHost {
        /// The blocked host's classification.
        class: HostClass,
    },
}

/// Whether [`validate_index_url`] must check a candidate's host against a live
/// [`RegistryAccessPolicy`].
///
/// An explicit enum, not `Option`/`bool`: a trusted-provenance candidate (e.g. `deps-cargo`'s
/// `$CARGO_HOME`-sourced `IndexTrust::Trusted`) skipping the policy check entirely is a
/// security-relevant decision each call site must make visibly, not something that can be
/// expressed by a `None` a reader might mistake for "no policy configured yet".
///
/// # Examples
///
/// ```
/// use deps_core::EcosystemId;
/// use deps_core::net_policy::{
///     PolicyGate, RegistryAccessPolicy, WorkspaceRegistryAccess, validate_index_url,
/// };
///
/// let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off);
/// assert!(
///     validate_index_url(
///         "https://index.mycorp.dev",
///         "https://index.mycorp.dev",
///         EcosystemId::Cargo,
///         PolicyGate::Skip
///     )
///     .is_ok()
/// );
/// assert!(
///     validate_index_url(
///         "https://index.mycorp.dev",
///         "https://index.mycorp.dev",
///         EcosystemId::Cargo,
///         PolicyGate::Enforce(&policy)
///     )
///     .is_err()
/// );
/// ```
///
/// **Exhaustive** (issue #769): a closed 2-variant Skip/Enforce gate — a third state would
/// change the calling convention at every `validate_index_url` call site, not slot into an
/// existing wildcard arm.
#[derive(Debug, Clone, Copy)]
pub enum PolicyGate<'a> {
    /// Skip the policy check entirely — the candidate's provenance is already trusted (e.g.
    /// the user's own `$CARGO_HOME` configuration), not something a cloned repository
    /// controls.
    Skip,
    /// Check the candidate's host against `policy` — the candidate's provenance is a
    /// workspace file, which an opened repository fully controls.
    Enforce(&'a RegistryAccessPolicy),
}

/// Redaction helpers moved to [`crate::redact`] (issue #1247) — re-exported here so existing
/// `deps_core::net_policy::*` paths keep resolving.
pub use crate::redact::{
    MAX_PARSE_ERROR_LOG_BYTES, RedactedName, RedactedUrl, is_credential_or_query_bearing,
    parse_error_source, redact_declaration_key, redact_parse_error_for_log, redact_userinfo,
    sanitize_invisible, url_for_tracing,
};

/// Whether `url`'s host is loopback (`127.0.0.1`, `localhost`, or `::1`) with an `http`
/// scheme — the shape every `mockito::Server` binds to.
///
/// Only compiled into test builds (see [`validate_index_url`]): a non-loopback host must
/// never be allowed to bypass the https requirement, even under `cfg(test)`/`test-util`.
#[cfg(any(test, feature = "test-util"))]
fn is_loopback_url(url: &url::Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
}

/// Validates a candidate registry/index URL: `https` scheme, no userinfo, and — when `gate`
/// is [`PolicyGate::Enforce`] — a host the live [`RegistryAccessPolicy`] allows.
///
/// `candidate` is the string actually parsed (e.g. `deps-npm`'s already `${VAR}`-expanded
/// value); `raw_for_log` is what an error payload and the blocked-host `tracing::warn!` name
/// instead — the pre-expansion `.npmrc` value for `deps-npm`, or the same string as
/// `candidate` for every other caller (none of which has an expansion step). Preferring the
/// pre-expansion value over the live one for `deps-npm` still matters even though both are
/// redacted identically below (defense in depth against a credential elsewhere in the URL,
/// e.g. a path segment, that this function's redaction does not strip — see
/// [`url_for_tracing`]'s own doc) — but both are always redacted the same way here: an
/// earlier revision tried to log `raw_for_log` more permissively when it was known to be a
/// pre-expansion literal, on the theory that a literal can only ever spell a placeholder like
/// `${VAR}`, never a real secret. That assumption doesn't hold — a hostile `.npmrc`/config
/// file can write a credential directly into the raw value with no expansion involved at all
/// (#767 S2b) — so `raw_for_log` is *always* redacted via [`url_for_tracing`] regardless of
/// its provenance. `ecosystem` is carried on the blocked-host warning only, to tell call
/// sites apart in the logs.
///
/// The check order — parse, then https, then userinfo, then the policy gate — is
/// load-bearing: userinfo is rejected *before* the policy gate runs, which is what lets a
/// caller safely log `raw_for_log` on a [`IndexUrlError::BlockedHost`] warning without a
/// separate userinfo-redaction step, since a userinfo-bearing candidate can never reach that
/// point. Do not reorder.
///
/// [`IndexUrlError::InvalidUrl`] is the one variant this invariant can't cover — `candidate`
/// failed to parse *before* any userinfo check could run, so `raw_for_log` might still carry
/// one (S1 finding: an otherwise-valid `user:pass@host` URL can fail to parse for an unrelated
/// reason, e.g. an invalid port). [`url_for_tracing`] strips userinfo as well as the query
/// string/fragment, so this is covered by the same call as the query-string redaction above.
///
/// # Errors
///
/// Returns [`IndexUrlError`] if `candidate` does not parse as a URL, is not `https` (outside
/// the `cfg(test)`/`test-util` loopback carve-out), carries a userinfo component, or (under
/// [`PolicyGate::Enforce`]) resolves to a host class the current policy blocks.
///
/// # Examples
///
/// ```
/// use deps_core::EcosystemId;
/// use deps_core::net_policy::{PolicyGate, validate_index_url};
///
/// let url = validate_index_url(
///     "https://index.mycorp.dev",
///     "https://index.mycorp.dev",
///     EcosystemId::Cargo,
///     PolicyGate::Skip,
/// )
/// .unwrap();
/// assert_eq!(url.as_str(), "https://index.mycorp.dev/");
///
/// assert!(
///     validate_index_url(
///         "http://example.com",
///         "http://example.com",
///         EcosystemId::Cargo,
///         PolicyGate::Skip
///     )
///     .is_err()
/// );
/// ```
pub fn validate_index_url(
    candidate: &str,
    raw_for_log: &str,
    ecosystem: EcosystemId,
    gate: PolicyGate<'_>,
) -> Result<url::Url, IndexUrlError> {
    let url = url::Url::parse(candidate)
        .map_err(|_| IndexUrlError::InvalidUrl(RedactedUrl::new(raw_for_log)))?;
    let is_https = url.scheme() == "https";
    #[cfg(any(test, feature = "test-util"))]
    let is_https = is_https || is_loopback_url(&url);
    if !is_https {
        return Err(IndexUrlError::NotHttps(url.scheme().to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(IndexUrlError::UserInfoPresent);
    }
    if let PolicyGate::Enforce(policy) = gate {
        let class = classify_host(&url);
        if !policy.get().allows(class) {
            tracing::warn!(
                url = %RedactedUrl::new(raw_for_log),
                ?class,
                %ecosystem,
                "workspace-declared registry index host blocked by registries.workspace_registries policy"
            );
            return Err(IndexUrlError::BlockedHost { class });
        }
    }
    Ok(url)
}

/// Soft-sealing mechanism for [`RegistryUrlKind`]/[`TrustedConstantRegistryUrl`], shared by
/// every ecosystem crate in this workspace that defines a marker (`deps-pypi`, `deps-npm`, ...)
/// — each implements [`private::Sealed`] for its own marker type. Mirrors
/// `deps_core::ecosystem::private` exactly; see that module's doc for why `pub` (not
/// `pub(crate)`) is required for a "sibling workspace crate, not a truly external one" sealing
/// level, and why that makes this a documented contract enforced by code review rather than a
/// compiler-enforced wall.
#[doc(hidden)]
pub mod private {
    /// Marker trait every ecosystem crate in this workspace implements for its own
    /// [`super::RegistryUrlKind`] marker type.
    pub trait Sealed {}
}

/// Marker trait selecting one ecosystem's validation rules for [`ValidatedRegistryUrl`].
///
/// An uninhabited type (`enum Foo {}`) implementing this trait carries everything that used to
/// vary between `deps-pypi`/`deps-npm`/`deps-go`/`deps-nuget`'s independently-defined,
/// near-identical validated-URL newtypes (issue #959): the tracing label
/// [`validate_index_url`] logs under, whether a query string/fragment is rejected (`deps-go`
/// only, see [`Self::REJECT_QUERY_FRAGMENT`]), and the crate's own error type each
/// `new`/`new_with_raw_for_log` call returns. A marker type, not a value parameter, because
/// every ecosystem crate needs its *own* [`ValidatedRegistryUrl<K>`] to stay a distinct type —
/// `PypiIndexUrl` and `NpmRegistryIndex` must never be interchangeable even though they
/// validate identically today.
///
/// # Sealing
///
/// Requires `Self: private::Sealed`, exactly as [`crate::ecosystem::Ecosystem`] does — see that
/// trait's `# Sealing` doc section for the full reasoning. This matters more here than it
/// otherwise might (issue #959 code review, S1/M5): without it, a foreign crate could mint its
/// own marker and, combined with an ungated construction path, produce a "validated" URL that
/// never ran [`classify_host`]. [`ValidatedRegistryUrl::new`]/
/// [`ValidatedRegistryUrl::new_with_raw_for_log`] always enforce the policy gate regardless of
/// sealing — sealing closes who can define new *kinds*, not a gap in what an already-sealed
/// kind can do.
///
/// # Examples
///
/// ```
/// use deps_core::EcosystemId;
/// use deps_core::net_policy::{
///     IndexUrlError, RegistryAccessPolicy, RegistryUrlKind, ValidatedRegistryUrl,
/// };
///
/// pub enum MyIndexKind {}
///
/// // Real in-workspace ecosystem crates implement `Sealed` exactly like this — see
/// // `deps_core::ecosystem::private`'s doc for why this line compiling here, out-of-crate, is
/// // not a bug.
/// impl deps_core::net_policy::private::Sealed for MyIndexKind {}
///
/// impl RegistryUrlKind for MyIndexKind {
///     // A real marker uses its own real `EcosystemId` variant; this example reuses `Cargo`'s
///     // purely for illustration.
///     const ECOSYSTEM: EcosystemId = EcosystemId::Cargo;
///     const REJECT_QUERY_FRAGMENT: bool = false;
///     type Error = IndexUrlError;
/// }
///
/// type MyIndexUrl = ValidatedRegistryUrl<MyIndexKind>;
///
/// let policy = RegistryAccessPolicy::default();
/// assert!(MyIndexUrl::new("https://index.mycorp.example", &policy).is_ok());
/// ```
pub trait RegistryUrlKind: private::Sealed {
    /// [`validate_index_url`]'s `ecosystem` tracing label for this kind.
    const ECOSYSTEM: EcosystemId;
    /// Whether a query string or fragment on the candidate is rejected outright, after the
    /// shared [`validate_index_url`] checks pass. `false` for every kind except `deps-go`'s (F3,
    /// spec 034 review): a `GOPROXY` hop is later suffixed with `/{module}/@v/...`, which has no
    /// well-defined append point onto a URL that already carries either.
    ///
    /// No default value (issue #959 code review, M1): matches this project's `EcosystemId`
    /// convention (#118) of forcing every new implementor to state security-relevant behavior
    /// explicitly at compile time, rather than silently inheriting the permissive default.
    const REJECT_QUERY_FRAGMENT: bool;
    /// This kind's own error type — must be constructible from [`IndexUrlError`] so
    /// [`ValidatedRegistryUrl::new_with_raw_for_log`] can propagate a shared validation failure
    /// via `?`.
    type Error: From<IndexUrlError>;
}

/// Opt-in capability for a [`RegistryUrlKind`] that needs to validate one compile-time-known
/// trusted constant without checking it against a live policy.
///
/// See [`ValidatedRegistryUrl::new_trusted_constant`] — `deps-nuget`'s hardcoded public service
/// index is the motivating case. Deliberately a separate, narrower trait rather than a flag on
/// [`RegistryUrlKind`] itself
/// (issue #959 code review, S1): only the one marker type that actually owns a trusted constant
/// implements it, so `PypiIndexUrl`/`NpmRegistryIndex`/`GoProxyUrl` — which are always built
/// from workspace-provenance input, never a compile-time literal — get no policy-skipping
/// construction path at all, public or otherwise. Sealed transitively through its
/// [`RegistryUrlKind`] supertrait bound.
pub trait TrustedConstantRegistryUrl: RegistryUrlKind {}

/// A validated, normalized, https-only registry/index URL with no embedded userinfo,
/// parameterized by an ecosystem marker `K` (see [`RegistryUrlKind`]).
///
/// Promotes the four near-identical newtypes `deps-pypi`'s `PypiIndexUrl`, `deps-npm`'s
/// `NpmRegistryIndex`, `deps-go`'s `GoProxyUrl`, and `deps-nuget`'s `NuGetFeedUrl` used to
/// define independently into one generic type (issue #959) — `K` is what keeps
/// `ValidatedRegistryUrl<PypiIndexKind>` and `ValidatedRegistryUrl<NpmRegistryIndexKind>`
/// distinct at the type level despite sharing an implementation, and what lets each ecosystem's
/// `new`/`as_str` keep returning its own error type via [`RegistryUrlKind::Error`] rather than
/// forcing every call site onto a shared, less specific one.
///
/// `deps-cargo`'s `RegistryIndex` deliberately does not migrate to this type (issue #959, D1):
/// it stores a `url::Url` rather than a normalized `String`, does not trim a trailing `/`, and
/// carries an `IndexTrust` this type has no field for.
///
/// Carries no bound on `K` itself — [`Clone`], [`Debug`](std::fmt::Debug), [`PartialEq`],
/// [`Eq`], [`Hash`](std::hash::Hash), and [`Display`](std::fmt::Display) are all hand-written
/// below (not derived) so that none of them require `K: Clone`/`K: Debug`/etc., and
/// `PhantomData<fn() -> K>` (rather than `PhantomData<K>`) keeps [`Send`]/[`Sync`] unconditional
/// regardless of `K`.
pub struct ValidatedRegistryUrl<K> {
    normalized: String,
    kind: PhantomData<fn() -> K>,
}

impl<K> Clone for ValidatedRegistryUrl<K> {
    fn clone(&self) -> Self {
        Self {
            normalized: self.normalized.clone(),
            kind: PhantomData,
        }
    }
}

/// Bounded on `K: RegistryUrlKind` (unlike every other hand-written impl on this type) so the
/// rendered name carries `K::ECOSYSTEM` instead of the generic `ValidatedRegistryUrl` — issue
/// #959 code review (M4): a debug dump of a containing struct must still read
/// `pypi("https://...")`-shaped, not lose which ecosystem the URL belongs to. This bound is on
/// `K: RegistryUrlKind`, never `K: Debug`, so it costs nothing extra: every `K` this type is
/// ever instantiated with already implements `RegistryUrlKind`.
impl<K: RegistryUrlKind> std::fmt::Debug for ValidatedRegistryUrl<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple(K::ECOSYSTEM.id())
            .field(&self.normalized)
            .finish()
    }
}

impl<K> PartialEq for ValidatedRegistryUrl<K> {
    fn eq(&self, other: &Self) -> bool {
        self.normalized == other.normalized
    }
}

impl<K> Eq for ValidatedRegistryUrl<K> {}

impl<K> std::hash::Hash for ValidatedRegistryUrl<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.normalized.hash(state);
    }
}

impl<K> std::fmt::Display for ValidatedRegistryUrl<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.normalized)
    }
}

impl<K: RegistryUrlKind> ValidatedRegistryUrl<K> {
    /// Validates and normalizes `raw` against `policy`.
    ///
    /// # Errors
    ///
    /// Returns `K::Error` if `raw` does not parse as a URL, is not `https` (outside the
    /// `cfg(test)`/`test-util` loopback carve-out), carries a userinfo component, or resolves to
    /// a host class the current `policy` blocks.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::EcosystemId;
    /// use deps_core::net_policy::{
    ///     IndexUrlError, RegistryAccessPolicy, RegistryUrlKind, ValidatedRegistryUrl,
    /// };
    ///
    /// pub enum MyIndexKind {}
    ///
    /// impl deps_core::net_policy::private::Sealed for MyIndexKind {}
    ///
    /// impl RegistryUrlKind for MyIndexKind {
    ///     const ECOSYSTEM: EcosystemId = EcosystemId::Cargo;
    ///     const REJECT_QUERY_FRAGMENT: bool = false;
    ///     type Error = IndexUrlError;
    /// }
    ///
    /// let policy = RegistryAccessPolicy::default();
    /// let url =
    ///     ValidatedRegistryUrl::<MyIndexKind>::new("https://index.mycorp.example/", &policy)
    ///         .unwrap();
    /// assert_eq!(url.as_str(), "https://index.mycorp.example");
    /// ```
    pub fn new(raw: &str, policy: &RegistryAccessPolicy) -> Result<Self, K::Error> {
        Self::new_with_raw_for_log(raw, raw, policy)
    }

    /// Like [`Self::new`], but validates `candidate` (the value actually parsed) while using
    /// `raw_for_log` — a pre-expansion or otherwise-earlier form of the same value — for every
    /// error payload and `tracing::warn!` call. Always enforces `policy` — unlike the internal
    /// `Self::build` this delegates to, this public entry point never accepts
    /// [`PolicyGate::Skip`] (issue #959 code review, S1): every value this constructs is
    /// workspace-provenance input, so there is no legitimate reason for an ecosystem crate to
    /// skip the live policy check here — only `new_trusted_constant` (gated by
    /// [`TrustedConstantRegistryUrl`]) may do that, for the one real compile-time-constant case.
    ///
    /// `deps-npm`'s `.npmrc` `${VAR}` expansion is the reason this split from [`Self::new`]
    /// exists: a rejected candidate built from `${SOME_TOKEN}` must never leak that token's
    /// expanded value into a log line or an error payload — `raw_for_log` is always redacted the
    /// same way regardless of which caller it came from (#767 S2b). `RedactedUrl::new`, not
    /// `redact_userinfo` alone, is what performs that redaction throughout this type and
    /// [`InvalidEntry::logged`]: a query-string credential must be stripped too, not just
    /// userinfo, since `raw_for_log`/`InvalidEntry::raw` can both surface in
    /// ecosystem-crate-built hover/diagnostics text.
    ///
    /// # Errors
    ///
    /// Returns `K::Error` under the same conditions as [`Self::new`], plus — only when
    /// `K::REJECT_QUERY_FRAGMENT` is `true` (`deps-go`) — a candidate carrying a query string or
    /// fragment.
    pub fn new_with_raw_for_log(
        candidate: &str,
        raw_for_log: &str,
        policy: &RegistryAccessPolicy,
    ) -> Result<Self, K::Error> {
        Self::build(candidate, raw_for_log, PolicyGate::Enforce(policy))
    }

    /// The shared construction logic behind [`Self::new_with_raw_for_log`] and
    /// [`Self::new_trusted_constant`] — deliberately not `pub` (issue #959 code review, S1): a
    /// public `gate` parameter would let any caller pass [`PolicyGate::Skip`] directly, for
    /// every ecosystem at once, reopening exactly the ungated-construction gap this split
    /// exists to close. Only this module's own two public constructors may choose a gate.
    fn build(candidate: &str, raw_for_log: &str, gate: PolicyGate<'_>) -> Result<Self, K::Error> {
        let url = validate_index_url(candidate, raw_for_log, K::ECOSYSTEM, gate)?;
        if K::REJECT_QUERY_FRAGMENT && (url.query().is_some() || url.fragment().is_some()) {
            return Err(IndexUrlError::InvalidUrl(RedactedUrl::new(raw_for_log)).into());
        }
        let normalized = url.as_str().trim_end_matches('/').to_string();
        Ok(Self {
            normalized,
            kind: PhantomData,
        })
    }

    /// The normalized URL. Never carries a trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }
}

impl<K: TrustedConstantRegistryUrl> ValidatedRegistryUrl<K> {
    /// Validates `raw` — a compile-time-known literal, never workspace-declared input — without
    /// checking it against a live [`RegistryAccessPolicy`] (`raw` is trusted by construction, not
    /// by provenance the policy could meaningfully gate). Only callable for a `K` whose
    /// ecosystem crate opted into [`TrustedConstantRegistryUrl`] (issue #959 code review, S1) —
    /// `deps-nuget`'s hardcoded public service index is, at the time of writing, the only real
    /// user of this.
    ///
    /// Still runs every other [`Self::new`] check (https-only, no userinfo, no rejected query
    /// string/fragment) — only the policy gate is skipped, not URL-shape validation.
    ///
    /// # Errors
    ///
    /// Returns `K::Error` if `raw` fails any non-policy check [`Self::new`] would also apply.
    pub fn new_trusted_constant(raw: &'static str) -> Result<Self, K::Error> {
        Self::build(raw, raw, PolicyGate::Skip)
    }
}

/// Whether an ecosystem's own validation-failure reason names a policy-blocked host — the
/// shared half of [`InvalidEntry::blocked_class`].
pub trait BlockedHostReason {
    /// `Some(class)` iff `self` is the blocked-host variant, naming the blocked [`HostClass`].
    fn blocked_host_class(&self) -> Option<HostClass>;
}

impl BlockedHostReason for IndexUrlError {
    fn blocked_host_class(&self) -> Option<HostClass> {
        match self {
            Self::BlockedHost { class } => Some(*class),
            _ => None,
        }
    }
}

/// A registry/index entry rejected for a reason other than a policy-blocked host (#1438).
///
/// [`BlockedHostReason`]/[`HostClass`] already give a policy-blocked host its own diagnostic
/// path (`crate::BlockedRegistryOccurrence`) — every *other* validation-failure reason an
/// `InvalidEntry`-based ecosystem config can produce (a malformed URL, a non-https scheme,
/// embedded userinfo, an undefined `${VAR}`, ...) had no equivalent: the affected dependency
/// was simply dropped from the fetch queue with only a `tracing::warn!`, invisible to the
/// editor user. This is that path's classification, deliberately excluding the blocked-host
/// case (`rejection_reason` returns [`RejectionOutcome::HandledByBlockedHostPath`] for it) so
/// the two mechanisms never double-report the same rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryRejectionReason {
    /// The value did not parse as a URL at all.
    InvalidUrl,
    /// The URL's scheme is not `https`.
    NotHttps,
    /// The URL carried a `user:pass@`/`user@` component.
    UserInfoPresent,
    /// A `${VAR}` placeholder named an environment variable that is not set.
    UndefinedEnvVar,
    /// `${VAR}` expansion was attempted where it is not permitted (e.g. a project-tier
    /// `.npmrc` value, issue #1420).
    EnvVarExpansionNotPermitted,
    /// The source has credentials configured elsewhere in its ecosystem's own config (e.g.
    /// NuGet's `<packageSourceCredentials>`, issue #1442) that this source cannot use — two
    /// distinct shapes share this one reason, deliberately, since neither is more actionable
    /// than the other for the user: a credential this ecosystem categorically never reads for
    /// this declaration (e.g. NuGet's repo-tier `<packageSourceCredentials>`, FR-009 — no
    /// binding is ever attempted), or one it *did* read and attempt to bind but failed (a
    /// missing value, an unresolvable/ambiguous binding — see NuGet's own user-profile binding,
    /// issue #576) for a reason not covered by a more specific variant below. Never phrase this
    /// reason's text as "never read"/"could not be resolved" — both would misdescribe one of
    /// the two shapes.
    HasCredentials,
    /// The source's credential is encrypted in a way this server cannot decrypt (e.g. NuGet's
    /// DPAPI-encrypted `<Password>`, issue #1442) — permanently out of scope, not a transient
    /// binding failure, so kept distinct from [`Self::HasCredentials`].
    EncryptedCredentialUnsupported,
}

impl std::fmt::Display for RegistryRejectionReason {
    /// A human-readable label for this reason, used in user-facing diagnostics — never the
    /// `{:?}` derive, which renders the Rust identifier rather than prose.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidUrl => "not a valid URL",
            Self::NotHttps => "does not use https",
            Self::UserInfoPresent => "contains embedded credentials",
            Self::UndefinedEnvVar => "references an undefined environment variable",
            Self::EnvVarExpansionNotPermitted => {
                "uses environment-variable expansion, which is not permitted for this entry"
            }
            Self::HasCredentials => "has credentials that cannot be used",
            Self::EncryptedCredentialUnsupported => {
                "uses an encrypted credential, which is not supported"
            }
        })
    }
}

/// Three-state outcome of classifying a registry-entry rejection (issue #1455 batch item 4).
///
/// Before this type existed, [`RegistryRejectionClassifier::rejection_reason`] returned
/// `Option<RegistryRejectionReason>` and used `None` for two semantically different cases —
/// [`Self::HandledByBlockedHostPath`] (the trait's original, documented meaning) and
/// [`Self::IntentionallySilent`] (a rejection reason some ecosystem deliberately never
/// surfaces as a diagnostic, e.g. NuGet's `Disabled`/`UnsupportedProtocolVersion`/
/// `LocalFeedUnsupported`) — collapsing a real distinction the doc comment never actually
/// allowed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionOutcome {
    /// A rejection reason that should surface as its own diagnostic.
    Reject(RegistryRejectionReason),
    /// A policy-blocked host — already reported through [`BlockedHostReason`]'s own
    /// diagnostic path, so [`InvalidEntry::rejection_reason`] must not double-report it.
    HandledByBlockedHostPath,
    /// Deliberately silent: this rejection reason is never surfaced as a diagnostic, by
    /// design (not merely "not yet classified").
    IntentionallySilent,
}

impl RejectionOutcome {
    /// Extracts the [`RegistryRejectionReason`] a caller should report, collapsing
    /// [`Self::HandledByBlockedHostPath`] and [`Self::IntentionallySilent`] to `None` — both
    /// mean "do not surface a reason here", just for different reasons.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::{RegistryRejectionReason, RejectionOutcome};
    ///
    /// assert_eq!(
    ///     RejectionOutcome::Reject(RegistryRejectionReason::NotHttps).into_reason(),
    ///     Some(RegistryRejectionReason::NotHttps)
    /// );
    /// assert!(RejectionOutcome::HandledByBlockedHostPath.into_reason().is_none());
    /// assert!(RejectionOutcome::IntentionallySilent.into_reason().is_none());
    /// ```
    #[must_use]
    pub const fn into_reason(self) -> Option<RegistryRejectionReason> {
        match self {
            Self::Reject(reason) => Some(reason),
            Self::HandledByBlockedHostPath | Self::IntentionallySilent => None,
        }
    }
}

/// Whether an ecosystem's own validation-failure reason names a rejection other than a
/// policy-blocked host — the shared half of [`InvalidEntry::rejection_reason`].
///
/// A separate trait from [`BlockedHostReason`] rather than folding into it (#1438): the
/// blocked-host case already has its own diagnostic path, so this trait's
/// [`RejectionOutcome::HandledByBlockedHostPath`] arm for that case is not "unclassified", it
/// is "handled elsewhere" — see [`RejectionOutcome`]'s own doc for the third,
/// [`RejectionOutcome::IntentionallySilent`] arm this trait also distinguishes.
pub trait RegistryRejectionClassifier {
    /// Classifies this rejection reason into one of [`RejectionOutcome`]'s three states.
    fn rejection_reason(&self) -> RejectionOutcome;
}

impl RegistryRejectionClassifier for IndexUrlError {
    fn rejection_reason(&self) -> RejectionOutcome {
        match self {
            Self::InvalidUrl(_) => RejectionOutcome::Reject(RegistryRejectionReason::InvalidUrl),
            Self::NotHttps(_) => RejectionOutcome::Reject(RegistryRejectionReason::NotHttps),
            Self::UserInfoPresent => {
                RejectionOutcome::Reject(RegistryRejectionReason::UserInfoPresent)
            }
            Self::BlockedHost { .. } => RejectionOutcome::HandledByBlockedHostPath,
        }
    }
}

/// A present-but-unusable registry/index entry — an invalid URL, a policy-blocked host, or any
/// other reason `E` names.
///
/// Shared by `deps-pypi`, `deps-npm`, `deps-go`, and `deps-nuget` (issue #959), each of which
/// aliases this with its own error type `E` (`PypiIndexUrlError`, `NpmRegistryIndexError`,
/// `GoProxyUrlError`, `NuGetFeedUrlError`) rather than redefining an identically-shaped struct.
///
/// `#[non_exhaustive]`: a caller builds one only via [`Self::new`]/[`Self::logged`], never a
/// struct literal — slightly weaker than each ecosystem crate's previous "output-only, no
/// constructor is provided" doc invariant (accepted, pre-1.0, workspace-internal per #959's
/// review), but keeps a struct-literal escape hatch closed to any consumer outside the crate
/// that owns a given `E`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct InvalidEntry<E = IndexUrlError> {
    /// The raw value, as written, with any embedded userinfo and query string/fragment
    /// redacted — see [`RedactedUrl`].
    pub raw: RedactedUrl,
    /// Why it was rejected.
    pub reason: E,
}

impl<E> InvalidEntry<E> {
    /// Builds an entry directly from an already-redacted `raw` and a `reason`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::{IndexUrlError, InvalidEntry, RedactedUrl};
    ///
    /// let entry = InvalidEntry::new(
    ///     RedactedUrl::new("https://example.com"),
    ///     IndexUrlError::UserInfoPresent,
    /// );
    /// assert_eq!(entry.raw.to_string(), "https://example.com");
    /// ```
    #[must_use]
    pub fn new(raw: RedactedUrl, reason: E) -> Self {
        Self { raw, reason }
    }

    /// Redacts `raw`, emits a `tracing::warn!` naming it, `ecosystem`, and `reason` under
    /// `message`, then builds the resulting entry — the repeated redact-then-log-then-construct
    /// shape each ecosystem's own `resolve_entry`/`parse_hop` used to write out longhand.
    /// `RedactedUrl::new`, not `redact_userinfo` alone (#767 S2a), is what performs the
    /// redaction: a query-string credential must be stripped too, not just userinfo, since the
    /// resulting entry's `raw` field can surface in an ecosystem crate's own
    /// hover/diagnostics text (e.g. `DependencySource::CustomRegistry`).
    ///
    /// Takes `ecosystem` explicitly (issue #959 code review, M2) so this warning carries the
    /// same `ecosystem` field [`validate_index_url`] logs with, under the same
    /// `deps_core::net_policy` target every caller now shares post-migration — without it, a
    /// `RUST_LOG=deps_npm=warn`-style filter (`deps-lsp/src/main.rs`'s `EnvFilter`) would no
    /// longer surface this warning at all, since it would carry no field naming which ecosystem
    /// it came from.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::EcosystemId;
    /// use deps_core::net_policy::{IndexUrlError, InvalidEntry};
    ///
    /// let entry = InvalidEntry::logged(
    ///     "https://user:pass@example.com",
    ///     IndexUrlError::UserInfoPresent,
    ///     EcosystemId::Npm,
    ///     "index URL failed validation",
    /// );
    /// assert_eq!(entry.raw.to_string(), "https://***@example.com/");
    /// ```
    pub fn logged(raw: &str, reason: E, ecosystem: EcosystemId, message: &'static str) -> Self
    where
        E: std::fmt::Display,
    {
        let redacted = RedactedUrl::new(raw);
        tracing::warn!(raw = %redacted, %reason, %ecosystem, "{}", message);
        Self::new(redacted, reason)
    }
}

impl<E: BlockedHostReason> InvalidEntry<E> {
    /// `Some((class, raw))` iff this entry was rejected specifically for a policy-blocked host —
    /// the shared half of each ecosystem's own `blocked_class`/`blocked_class_for`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::{HostClass, IndexUrlError, InvalidEntry, RedactedUrl};
    ///
    /// let blocked = InvalidEntry::new(
    ///     RedactedUrl::new("https://127.0.0.1:9999"),
    ///     IndexUrlError::BlockedHost {
    ///         class: HostClass::Loopback,
    ///     },
    /// );
    /// assert_eq!(
    ///     blocked.blocked_class(),
    ///     Some((HostClass::Loopback, "https://127.0.0.1:9999".to_string()))
    /// );
    ///
    /// let other = InvalidEntry::new(RedactedUrl::new("not-a-url"), IndexUrlError::UserInfoPresent);
    /// assert_eq!(other.blocked_class(), None);
    /// ```
    #[must_use]
    pub fn blocked_class(&self) -> Option<(HostClass, String)> {
        self.reason
            .blocked_host_class()
            .map(|class| (class, self.raw.to_string()))
    }
}

impl<E: RegistryRejectionClassifier> InvalidEntry<E> {
    /// `Some((reason, raw))` iff this entry was rejected for a reason other than a
    /// policy-blocked host (#1438) — the shared half of an ecosystem's own
    /// `rejected_reason_for` helper, mirroring [`Self::blocked_class`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::{HostClass, IndexUrlError, InvalidEntry, RedactedUrl, RegistryRejectionReason};
    ///
    /// let rejected = InvalidEntry::new(
    ///     RedactedUrl::new("https://example.com"),
    ///     IndexUrlError::UserInfoPresent,
    /// );
    /// assert_eq!(
    ///     rejected.rejection_reason(),
    ///     Some((RegistryRejectionReason::UserInfoPresent, "https://example.com".to_string()))
    /// );
    ///
    /// // The blocked-host case is already covered by `Self::blocked_class` — this method
    /// // returns `None` for it, so the two mechanisms never double-report.
    /// let blocked = InvalidEntry::new(
    ///     RedactedUrl::new("https://127.0.0.1"),
    ///     IndexUrlError::BlockedHost { class: HostClass::Loopback },
    /// );
    /// assert!(blocked.rejection_reason().is_none());
    /// ```
    #[must_use]
    pub fn rejection_reason(&self) -> Option<(RegistryRejectionReason, String)> {
        self.reason
            .rejection_reason()
            .into_reason()
            .map(|reason| (reason, self.raw.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;

    fn host_class(url: &str) -> HostClass {
        classify_host(&url::Url::parse(url).unwrap())
    }

    fn trusted_prefix(candidate: &str, trusted: &str) -> bool {
        is_trusted_prefix(
            &url::Url::parse(candidate).unwrap(),
            &url::Url::parse(trusted).unwrap(),
        )
    }

    /// Issue #1455 batch item 4: [`IndexUrlError`]'s [`RegistryRejectionClassifier`] impl is the
    /// shared default every ecosystem's `Url(#[from] IndexUrlError)` variant delegates to
    /// (`NuGetFeedUrlError::Url`, `NpmRegistryIndexError::Url`, ...) — a direct test here, rather
    /// than only exercising it transitively through an ecosystem's `rejected_reason_for`, is
    /// what would catch a `Reject`/`HandledByBlockedHostPath` mix-up: both currently collapse to
    /// the same observable `None` at `InvalidEntry::rejection_reason`'s wrapper, so a swapped
    /// mapping would not fail any test that only checks that wrapper's behavior.
    #[test]
    fn test_index_url_error_rejection_reason_variants() {
        assert_eq!(
            IndexUrlError::InvalidUrl(RedactedUrl::new("not a url")).rejection_reason(),
            RejectionOutcome::Reject(RegistryRejectionReason::InvalidUrl)
        );
        assert_eq!(
            IndexUrlError::NotHttps("ftp".to_string()).rejection_reason(),
            RejectionOutcome::Reject(RegistryRejectionReason::NotHttps)
        );
        assert_eq!(
            IndexUrlError::UserInfoPresent.rejection_reason(),
            RejectionOutcome::Reject(RegistryRejectionReason::UserInfoPresent)
        );
        assert_eq!(
            IndexUrlError::BlockedHost {
                class: HostClass::Loopback
            }
            .rejection_reason(),
            RejectionOutcome::HandledByBlockedHostPath,
            "a policy-blocked host must classify as HandledByBlockedHostPath, not IntentionallySilent \
             or a generic Reject — it already has its own diagnostic path via BlockedHostReason"
        );
    }

    /// Issue #795 S1: a trusted path with no trailing slash (the real `deps-cargo` sparse
    /// index shape, `RegistryIndex::as_str()`) must still reject a same-origin sibling whose
    /// path merely shares a textual prefix — the exact repro the critic supplied.
    #[test]
    fn test_is_trusted_prefix_rejects_sibling_path_no_trailing_slash() {
        let trusted = "https://artifacts.corp/cargo/index";
        assert!(!trusted_prefix(
            "https://artifacts.corp/cargo/index-public/steal",
            trusted
        ));
        assert!(!trusted_prefix(
            "https://artifacts.corp/cargo/indexEVIL",
            trusted
        ));
        assert!(!trusted_prefix(
            "https://artifacts.corp/cargo/index.evil/x",
            trusted
        ));
    }

    /// Companion: the trusted path itself and a proper child path are still accepted when
    /// the trusted path has no trailing slash.
    #[test]
    fn test_is_trusted_prefix_accepts_self_and_child_no_trailing_slash() {
        let trusted = "https://artifacts.corp/cargo/index";
        assert!(trusted_prefix(
            "https://artifacts.corp/cargo/index",
            trusted
        ));
        assert!(trusted_prefix(
            "https://artifacts.corp/cargo/index/se/rd/serde",
            trusted
        ));
    }

    /// A trusted path *with* a trailing slash must behave identically to the no-trailing-
    /// slash form above — the trailing slash is normalized away, not load-bearing.
    #[test]
    fn test_is_trusted_prefix_trailing_slash_equivalent_to_no_trailing_slash() {
        let trusted = "https://artifacts.corp/cargo/index/";
        assert!(!trusted_prefix(
            "https://artifacts.corp/cargo/indexEVIL",
            trusted
        ));
        assert!(trusted_prefix(
            "https://artifacts.corp/cargo/index/se/rd/serde",
            trusted
        ));
    }

    /// A trusted path with more than one trailing slash must still trust its legitimate
    /// single-slash children — `trim_end_matches` (not a single `strip_suffix`) is required
    /// to fully normalize the prefix before comparison.
    #[test]
    fn test_is_trusted_prefix_doubled_trailing_slash_still_trusts_children() {
        let trusted = "https://artifacts.corp/v3-flatcontainer//";
        assert!(trusted_prefix(
            "https://artifacts.corp/v3-flatcontainer/serde/index.json",
            trusted
        ));
    }

    /// Origin mismatch is rejected even when the path would otherwise match — the
    /// origin-equality half of this check, independent of the path half.
    #[test]
    fn test_is_trusted_prefix_rejects_origin_mismatch() {
        assert!(!trusted_prefix(
            "https://artifacts.corp.evil.com/cargo/index",
            "https://artifacts.corp/cargo/index"
        ));
    }

    /// A root-path trusted origin (`/`) trusts every path on that origin — the shape every
    /// non-NuGet caller (`deps-pypi`, `deps_dev`, `deps-gitlab-ci`) uses.
    #[test]
    fn test_is_trusted_prefix_root_path_trusts_everything_on_origin() {
        assert!(trusted_prefix(
            "https://registry.example/anything/at/all",
            "https://registry.example/"
        ));
    }

    #[test]
    fn test_classify_cloud_metadata_ipv4() {
        assert_eq!(
            host_class("https://169.254.169.254/"),
            HostClass::CloudMetadata
        );
    }

    #[test]
    fn test_classify_cloud_metadata_ipv4_mapped_v6_bypass() {
        // The mapped-address bypass: written as an IPv6 literal embedding the same IPv4
        // address, this must classify identically to the bare IPv4 form, not fall through
        // to `Global` as an unrecognized v6 address.
        assert_eq!(
            host_class("https://[::ffff:169.254.169.254]/"),
            HostClass::CloudMetadata
        );
    }

    #[test]
    fn test_classify_cloud_metadata_nat64_bypass() {
        // The NAT64 well-known-prefix bypass (impl-critic finding, verified empirically):
        // `64:ff9b::/96` embeds an IPv4 address and must classify identically to the bare
        // IPv4 form, not fall through to `Global`.
        assert_eq!(
            host_class("https://[64:ff9b::a9fe:a9fe]/"),
            HostClass::CloudMetadata
        );
    }

    #[test]
    fn test_classify_cloud_metadata_ec2_ipv6() {
        assert_eq!(
            host_class("https://[fd00:ec2::254]/"),
            HostClass::CloudMetadata
        );
    }

    #[test]
    fn test_classify_link_local_ipv6() {
        assert_eq!(host_class("https://[fe80::1]/"), HostClass::LinkLocal);
    }

    #[test]
    fn test_classify_private_v4() {
        assert_eq!(host_class("https://10.0.0.1/"), HostClass::PrivateV4);
    }

    #[test]
    fn test_classify_cgnat() {
        assert_eq!(host_class("https://100.64.0.1/"), HostClass::Cgnat);
    }

    #[test]
    fn test_classify_private_v4_192_168() {
        assert_eq!(host_class("https://192.168.1.1/"), HostClass::PrivateV4);
    }

    #[test]
    fn test_classify_unique_local_v6() {
        assert_eq!(host_class("https://[fc00::1]/"), HostClass::UniqueLocalV6);
    }

    #[test]
    fn test_classify_unspecified_v4() {
        assert_eq!(host_class("https://0.0.0.0/"), HostClass::Unspecified);
    }

    #[test]
    fn test_classify_localhost_name() {
        assert_eq!(host_class("https://localhost/"), HostClass::Loopback);
    }

    #[test]
    fn test_classify_localhost_subdomain() {
        assert_eq!(host_class("https://foo.localhost/"), HostClass::Loopback);
    }

    #[test]
    fn test_classify_google_metadata_name() {
        assert_eq!(
            host_class("https://metadata.google.internal/"),
            HostClass::CloudMetadata
        );
    }

    #[test]
    fn test_classify_internal_suffix_name() {
        assert_eq!(
            host_class("https://registry.internal/"),
            HostClass::InternalName
        );
    }

    #[test]
    fn test_classify_single_label_name() {
        assert_eq!(host_class("https://single-label/"), HostClass::InternalName);
    }

    /// S1 (security + impl-critic): `url::Url` preserves a trailing root-label dot, so a
    /// workspace file can append one FQDN-terminating `.` and walk straight past every
    /// name-based classification (both `PublicOnly` and the unconditional S5 redirect-hop
    /// guard) unless `classify_name` strips it before matching.
    #[test]
    fn test_classify_localhost_trailing_dot() {
        assert_eq!(host_class("https://localhost./"), HostClass::Loopback);
    }

    #[test]
    fn test_classify_google_metadata_trailing_dot() {
        assert_eq!(
            host_class("https://metadata.google.internal./"),
            HostClass::CloudMetadata
        );
    }

    #[test]
    fn test_classify_internal_suffix_trailing_dot() {
        assert_eq!(
            host_class("https://registry.internal./"),
            HostClass::InternalName
        );
    }

    /// Belt-and-braces (review nit): `trim_end_matches` closes the double-trailing-dot case
    /// too, not just a single one.
    #[test]
    fn test_classify_localhost_double_trailing_dot() {
        assert_eq!(host_class("https://localhost../"), HostClass::Loopback);
    }

    #[test]
    fn test_classify_global_public_name() {
        assert_eq!(host_class("https://index.crates.io/"), HostClass::Global);
    }

    #[test]
    fn test_classify_addr_cloud_metadata() {
        let addr: IpAddr = "169.254.169.254".parse().unwrap();
        assert_eq!(classify_addr(addr), HostClass::CloudMetadata);
    }

    #[test]
    fn test_classify_addr_private_v4() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(classify_addr(addr), HostClass::PrivateV4);
    }

    #[test]
    fn test_classify_addr_unwraps_mapped_v4() {
        let addr: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert_eq!(classify_addr(addr), HostClass::CloudMetadata);
    }

    #[test]
    fn test_classify_addr_unwraps_nat64_cloud_metadata() {
        // impl-critic S2: verified empirically that this classified `Global` before the fix.
        let addr: IpAddr = "64:ff9b::a9fe:a9fe".parse().unwrap();
        assert_eq!(classify_addr(addr), HostClass::CloudMetadata);
    }

    #[test]
    fn test_classify_addr_unwraps_nat64_loopback() {
        // impl-critic S2's second verified example: `64:ff9b::7f00:1` embeds `127.0.0.1`.
        let addr: IpAddr = "64:ff9b::7f00:1".parse().unwrap();
        assert_eq!(classify_addr(addr), HostClass::Loopback);
    }

    #[test]
    fn test_classify_addr_global() {
        let addr: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(classify_addr(addr), HostClass::Global);
    }

    #[test]
    fn test_never_a_registry_classes() {
        assert!(HostClass::Loopback.never_a_registry());
        assert!(HostClass::LinkLocal.never_a_registry());
        assert!(HostClass::CloudMetadata.never_a_registry());
        assert!(HostClass::Unspecified.never_a_registry());
        assert!(!HostClass::PrivateV4.never_a_registry());
        assert!(!HostClass::Cgnat.never_a_registry());
        assert!(!HostClass::UniqueLocalV6.never_a_registry());
        assert!(!HostClass::InternalName.never_a_registry());
        assert!(!HostClass::Global.never_a_registry());
    }

    #[test]
    fn test_workspace_registry_access_off_blocks_everything() {
        let policy = WorkspaceRegistryAccess::Off;
        assert!(!policy.allows(HostClass::Global));
        assert!(!policy.allows(HostClass::PrivateV4));
        assert!(!policy.allows(HostClass::Loopback));
    }

    #[test]
    fn test_workspace_registry_access_public_only_allows_global_only() {
        let policy = WorkspaceRegistryAccess::PublicOnly;
        assert!(policy.allows(HostClass::Global));
        assert!(!policy.allows(HostClass::PrivateV4));
        assert!(!policy.allows(HostClass::CloudMetadata));
    }

    #[test]
    fn test_workspace_registry_access_all_allows_everything() {
        let policy = WorkspaceRegistryAccess::All;
        assert!(policy.allows(HostClass::Global));
        assert!(policy.allows(HostClass::PrivateV4));
        assert!(policy.allows(HostClass::Loopback));
    }

    #[test]
    fn test_registry_access_policy_default_is_public_only() {
        let policy = RegistryAccessPolicy::default();
        assert_eq!(policy.get(), WorkspaceRegistryAccess::PublicOnly);
    }

    #[test]
    fn test_registry_access_policy_live_update() {
        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::All);
        assert_eq!(policy.get(), WorkspaceRegistryAccess::All);
        policy.set(WorkspaceRegistryAccess::Off);
        assert_eq!(policy.get(), WorkspaceRegistryAccess::Off);
    }

    /// Load-bearing check order: userinfo must be rejected *before* the policy gate runs —
    /// this is what lets a caller safely log `raw_for_log` unredacted on a `BlockedHost`
    /// warning, since a userinfo-bearing candidate can never reach that point. This URL's
    /// host (`169.254.169.254`) would also fail as `BlockedHost` under `Off`, so a
    /// `UserInfoPresent` result here proves the order, not just that one check fires.
    #[test]
    fn test_validate_index_url_userinfo_rejected_before_policy_gate() {
        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off);
        let result = validate_index_url(
            "https://user:pass@169.254.169.254/",
            "https://user:pass@169.254.169.254/",
            EcosystemId::Cargo,
            PolicyGate::Enforce(&policy),
        );
        assert_eq!(result, Err(IndexUrlError::UserInfoPresent));
    }

    /// `PolicyGate::Skip` bypasses the policy check entirely — the same candidate accepted
    /// under `Skip` is rejected under `Enforce` against a policy that blocks its host class,
    /// proving the gate is truly skipped rather than defaulting to a permissive policy.
    #[test]
    fn test_validate_index_url_policy_gate_skip_vs_enforce() {
        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off);
        assert!(
            validate_index_url(
                "https://169.254.169.254/",
                "https://169.254.169.254/",
                EcosystemId::Cargo,
                PolicyGate::Skip
            )
            .is_ok()
        );
        assert_matches!(
            validate_index_url(
                "https://169.254.169.254/",
                "https://169.254.169.254/",
                EcosystemId::Cargo,
                PolicyGate::Enforce(&policy)
            ),
            Err(IndexUrlError::BlockedHost { .. })
        );
    }

    /// #767: every caller (including `deps-npm`'s pre-expansion `.npmrc` value) must have
    /// its blocked-host log redacted the same way — S2b found that a "literal" value is not
    /// actually safe to log verbatim, since a hostile config file can write a credential
    /// directly into it with no expansion step involved at all.
    #[cfg(feature = "test-util")]
    #[test]
    fn test_validate_index_url_blocked_host_log_redacts_query_string() {
        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off);
        let raw = "https://169.254.169.254/?ApiKey=super-secret-value";
        let log = crate::test_util::capture_tracing_output(|| {
            let result =
                validate_index_url(raw, raw, EcosystemId::Cargo, PolicyGate::Enforce(&policy));
            assert_matches!(result, Err(IndexUrlError::BlockedHost { .. }));
        });
        assert!(!log.contains("super-secret-value"), "log: {log}");
    }

    /// S1: `IndexUrlError::InvalidUrl`'s payload is where the leak actually surfaced — every
    /// caller (`deps-cargo`, `deps-npm`, `deps-pypi`) logs/retains this error's `%error`/
    /// `Display`, so the redaction must happen inside `validate_index_url` itself, not rely on
    /// each caller to redact separately.
    #[test]
    fn test_validate_index_url_redacts_userinfo_in_invalid_url_error() {
        let raw = "https://user:hunter2@registry.example:99999/simple";
        let err = validate_index_url(raw, raw, EcosystemId::Cargo, PolicyGate::Skip).unwrap_err();
        let IndexUrlError::InvalidUrl(redacted) = &err else {
            panic!("expected InvalidUrl, got {err:?}");
        };
        assert!(
            !redacted.as_ref().contains("hunter2"),
            "redacted: {redacted}"
        );
        assert!(!err.to_string().contains("hunter2"), "Display: {err}");
    }

    /// #767 S2/S2b: `IndexUrlError::InvalidUrl` used to be built from `redact_userinfo`
    /// alone, which deliberately preserves the query string — every caller could leak a
    /// query-string credential through this error's payload/`Display`, reaching e.g.
    /// `deps-cargo`'s `%error` logs and a user-visible `deps-nuget` `DepsError::ParseError`.
    /// A `raw_for_log` value's provenance (a live URL vs. `deps-npm`'s pre-expansion
    /// `.npmrc` literal) does not change this: a literal value can carry a real credential
    /// too, written directly with no expansion involved, so this is asserted for both.
    #[test]
    fn test_validate_index_url_invalid_url_redacts_query_string() {
        let raw = "https://user:hunter2@registry.example:99999/simple?token=super-secret-value";
        for ecosystem in [EcosystemId::Cargo, EcosystemId::Npm] {
            let err = validate_index_url(raw, raw, ecosystem, PolicyGate::Skip).unwrap_err();
            let IndexUrlError::InvalidUrl(redacted) = &err else {
                panic!("expected InvalidUrl, got {err:?}");
            };
            assert!(
                !redacted.as_ref().contains("hunter2"),
                "redacted: {redacted}"
            );
            assert!(
                !redacted.as_ref().contains("super-secret-value"),
                "redacted: {redacted}"
            );
            assert!(
                !err.to_string().contains("super-secret-value"),
                "Display: {err}"
            );
        }
    }

    // --- ValidatedRegistryUrl / InvalidEntry generic machinery (issue #959 code review) ---

    /// Test-only permissive marker (`REJECT_QUERY_FRAGMENT = false`) — mirrors
    /// `deps-pypi`/`deps-npm`/`deps-nuget`'s real markers, so the generic dispatch is proven
    /// correct independent of any downstream ecosystem crate's own tests.
    enum PermissiveTestKind {}

    impl private::Sealed for PermissiveTestKind {}

    impl RegistryUrlKind for PermissiveTestKind {
        const ECOSYSTEM: EcosystemId = EcosystemId::Cargo;
        const REJECT_QUERY_FRAGMENT: bool = false;
        type Error = IndexUrlError;
    }

    /// Test-only rejecting marker (`REJECT_QUERY_FRAGMENT = true`) — mirrors `deps-go`'s real
    /// marker, so the generic dispatch is proven correct independent of `deps-go`'s own tests.
    enum RejectingTestKind {}

    impl private::Sealed for RejectingTestKind {}

    impl RegistryUrlKind for RejectingTestKind {
        const ECOSYSTEM: EcosystemId = EcosystemId::Go;
        const REJECT_QUERY_FRAGMENT: bool = true;
        type Error = IndexUrlError;
    }

    // Both test-only markers opt into the trusted-constant escape hatch too, so the same two
    // markers cover every generic-machinery test below — a real ecosystem marker (e.g.
    // `deps-nuget`'s `NuGetFeedKind`) implements only one of these traits, never both; nothing
    // stops a test-only marker from implementing both for coverage convenience.
    impl TrustedConstantRegistryUrl for PermissiveTestKind {}

    impl TrustedConstantRegistryUrl for RejectingTestKind {}

    fn permissive_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)
    }

    #[test]
    fn test_validated_registry_url_accepts_query_string_when_kind_opts_out() {
        let url = ValidatedRegistryUrl::<PermissiveTestKind>::new(
            "https://example.com/path?token=abc",
            &permissive_policy(),
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://example.com/path?token=abc");
    }

    #[test]
    fn test_validated_registry_url_accepts_fragment_when_kind_opts_out() {
        let url = ValidatedRegistryUrl::<PermissiveTestKind>::new(
            "https://example.com/path#frag",
            &permissive_policy(),
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://example.com/path#frag");
    }

    #[test]
    fn test_validated_registry_url_rejects_query_string_when_kind_opts_in() {
        assert_matches!(
            ValidatedRegistryUrl::<RejectingTestKind>::new(
                "https://example.com/path?token=abc",
                &permissive_policy(),
            ),
            Err(IndexUrlError::InvalidUrl(_))
        );
    }

    #[test]
    fn test_validated_registry_url_rejects_fragment_when_kind_opts_in() {
        assert_matches!(
            ValidatedRegistryUrl::<RejectingTestKind>::new(
                "https://example.com/path#frag",
                &permissive_policy(),
            ),
            Err(IndexUrlError::InvalidUrl(_))
        );
    }

    #[test]
    fn test_validated_registry_url_debug_names_ecosystem() {
        let url = ValidatedRegistryUrl::<PermissiveTestKind>::new(
            "https://example.com",
            &permissive_policy(),
        )
        .unwrap();
        assert_eq!(format!("{url:?}"), "cargo(\"https://example.com\")");
    }

    /// Backs [`ValidatedRegistryUrl`]'s doc claim that `Send`/`Sync` stay unconditional
    /// regardless of `K` — `PermissiveTestKind` is an uninhabited marker with no derives at
    /// all, so this instantiation would fail to compile if `PhantomData<fn() -> K>` ever
    /// leaked a `K: Send`/`K: Sync` requirement onto the outer type.
    #[test]
    fn test_validated_registry_url_send_sync_unconditional_regardless_of_kind() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ValidatedRegistryUrl<PermissiveTestKind>>();
    }

    #[test]
    fn test_validated_registry_url_new_trusted_constant_skips_policy() {
        // A host `all_policy`/`permissive_policy` already allows, so this only proves
        // `new_trusted_constant` performs the non-policy checks (rather than proving the
        // policy was actually skipped) — see the next test for that.
        let url =
            ValidatedRegistryUrl::<PermissiveTestKind>::new_trusted_constant("https://example.com")
                .unwrap();
        assert_eq!(url.as_str(), "https://example.com");
    }

    #[test]
    fn test_validated_registry_url_new_trusted_constant_bypasses_blocked_host_policy() {
        // `new` (Enforce) rejects a loopback host under a public-only policy; the same host,
        // through `new_trusted_constant`, must still succeed — this is the "policy actually
        // skipped, not merely satisfied" half of the S1 fix's coverage.
        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly);
        assert_matches!(
            ValidatedRegistryUrl::<RejectingTestKind>::new("https://127.0.0.1:9999", &policy),
            Err(IndexUrlError::BlockedHost { .. })
        );
        let url = ValidatedRegistryUrl::<RejectingTestKind>::new_trusted_constant(
            "https://127.0.0.1:9999",
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://127.0.0.1:9999");
    }

    #[test]
    fn test_invalid_entry_blocked_class_some_for_blocked_host() {
        let entry = InvalidEntry::new(
            RedactedUrl::new("https://127.0.0.1:9999"),
            IndexUrlError::BlockedHost {
                class: HostClass::Loopback,
            },
        );
        assert_eq!(
            entry.blocked_class(),
            Some((HostClass::Loopback, "https://127.0.0.1:9999".to_string()))
        );
    }

    #[test]
    fn test_invalid_entry_blocked_class_none_for_other_reason() {
        let entry = InvalidEntry::new(
            RedactedUrl::new("not-a-url"),
            IndexUrlError::InvalidUrl(RedactedUrl::new("not-a-url")),
        );
        assert_eq!(entry.blocked_class(), None);
    }
}
