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

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU8, Ordering};

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
    // `url::Url` preserves a trailing root-label dot (`https://localhost./` parses to the
    // host `"localhost."`, not `"localhost"`) — every suffix/equality check below must see
    // the FQDN with that label stripped, or a single appended `.` walks straight past this
    // entire classifier into `Global` (security review S1). `trim_end_matches` (not
    // `strip_suffix`, which removes only one) also closes the `localhost..` double-dot
    // edge case for free — not independently exploitable (an empty DNS label never
    // resolves), but belt-and-braces at zero extra cost.
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
///
/// let err = validate_index_url("not a url", "not a url", "cargo", PolicyGate::Skip).unwrap_err();
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
/// use deps_core::net_policy::{
///     PolicyGate, RegistryAccessPolicy, WorkspaceRegistryAccess, validate_index_url,
/// };
///
/// let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off);
/// assert!(
///     validate_index_url(
///         "https://index.mycorp.dev",
///         "https://index.mycorp.dev",
///         "cargo",
///         PolicyGate::Skip
///     )
///     .is_ok()
/// );
/// assert!(
///     validate_index_url(
///         "https://index.mycorp.dev",
///         "https://index.mycorp.dev",
///         "cargo",
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

/// Replaces any embedded `user:pass@`/`user@` userinfo component in `raw` with a fixed
/// `***@` marker, for a caller to log or retain instead of the raw credential-bearing value.
///
/// A userinfo-bearing index URL is always rejected ([`IndexUrlError::UserInfoPresent`]), but
/// the *raw* value naming what was rejected must never itself carry the credential through to
/// a `tracing::warn!` line or an `InvalidEntry`-shaped struct's `raw` field a user might see
/// surfaced as `DependencySource::CustomRegistry`'s `url` in hover/diagnostics text. A fixed
/// marker (rather than stripping the component outright) keeps the redacted value visibly
/// distinct from a URL that never carried userinfo at all, so a user can still tell *that* a
/// credential was present and removed, without ever seeing what it was. Shared by
/// `deps-npm`'s and `deps-pypi`'s `resolve_entry` (M1 fix).
///
/// `raw` failing [`url::Url::parse`] is not proof it carries no userinfo (S1 finding) — an
/// otherwise-valid `user:pass@host` can still fail to parse for a reason unrelated to the
/// userinfo component itself (an invalid port, a malformed IPv6 literal, a non-ASCII host, or
/// simply a missing scheme — #536 C2), so this falls back to a parse-independent redaction
/// rather than returning `raw` untouched; the fallback scans from the `://` scheme separator
/// when one is present, or from the very start of `raw` otherwise. When that scan finds no `@`,
/// a colon-separated credential with no `@` at all (e.g. `oauth2:glpat-...`, a GitLab CI job
/// token, or a bare `.npmrc` `key:value` line — #810) is redacted next; `raw` is returned
/// unchanged only once both scans come up empty.
///
/// Successfully parsing is not proof of an authority-bearing URL either (#811): for a
/// non-special scheme, the WHATWG parser accepts a bare `scheme:/path` (any number of
/// leading slashes, including zero, one, or an empty double-slash authority like
/// `scheme:///path`) as valid, with `host()` staying `None` throughout — `username()`/
/// `password()` never see a credential-shaped `user:pass@host` sitting right there in what
/// the parser treats as an opaque-ish path (e.g. `c:/user:hunter2@evil`,
/// `c:///user:hunter2@evil`). Counting slashes right after the scheme cannot distinguish this
/// from a legitimate empty-authority path value (e.g. `file:///etc/passwd`, or
/// `C:/Users/john.doe@corp/project` where `john.doe` is just a directory name) — both shapes
/// parse to the exact same `host() == None`. So whenever `host()` is `None`, every `@` in the
/// path is checked, and the last one whose own preceding segment looks userinfo-shaped
/// (contains a `:`, e.g. `user:hunter2`) rather than an ordinary path component (e.g.
/// `john.doe`, `@types`) is the one redacted.
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::redact_userinfo;
///
/// assert_eq!(
///     redact_userinfo("https://user:hunter2@registry.example/simple"),
///     "https://***@registry.example/simple"
/// );
/// assert_eq!(
///     redact_userinfo("https://registry.example/simple"),
///     "https://registry.example/simple"
/// );
/// assert_eq!(
///     redact_userinfo("user:hunter2@registry.example/simple"),
///     "***@registry.example/simple"
/// );
/// assert_eq!(redact_userinfo("c:/user:hunter2@evil"), "c:***@evil");
/// ```
// #901: `authority_start` comes from `find(':')` followed by `scheme_separator_end`, both
// ASCII-byte scans, so it always lands on a char boundary.
#[allow(clippy::string_slice)]
#[must_use]
pub fn redact_userinfo(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return redact_userinfo_unparseable(raw);
    };
    // A schemeless `user:pass@host` literal (no `://`) does not fail `Url::parse` outright
    // (#536 C2): the word before the first `:` parses as a valid opaque scheme (e.g.
    // `"user"`), and with no `//` following it the whole rest becomes a cannot-be-a-base
    // opaque path — `username()`/`password()` never see the literal userinfo that follows,
    // since there is no authority component at all from the parser's point of view. Fall
    // back to the same parse-independent scan used for an outright parse failure.
    if url.cannot_be_a_base() {
        return redact_userinfo_unparseable(raw);
    }
    // An empty authority (#811) cannot be told apart from a legitimate empty-authority path
    // value by slash-counting alone — `c:///user:hunter2@evil` and `file:///etc/passwd` parse
    // to the exact same `host() == None` regardless of how many slashes follow the scheme —
    // so every empty-authority `raw` is scanned, and the scan itself (not slash position)
    // decides whether anything looks like a credential.
    if url.host().is_none() {
        return redact_userinfo_opaque_path(raw);
    }
    // #901: a host-having URL with no userinfo at all is not proof the rest of `raw` is
    // credential-free — a path segment can still be userinfo-shaped (e.g.
    // `https://example.com/api/user:glpat-SECRET@internal`, or a `c:/`-corrupted authority
    // like `https://c:/user:glpat-SECRET@h/p` that still parses to an empty-userinfo host).
    // Scanned the same way `redact_authority_url_tail` scans the *post-userinfo* tail of a
    // URL that does have userinfo, anchored past the scheme separator so a leading `c:/`-style
    // segment before the real authority is not itself mistaken for the credential.
    //
    // The anchor is `raw`'s own first `:` (the scheme separator, same derivation
    // `redact_userinfo_opaque_path` uses), never `find("://")`: a slash-less `scheme:host`
    // form (e.g. `https:example.com/user:SECRET@h?r=http://y`) can have its own `://`
    // appear later, inside the path/query, which would let `find("://")` skip straight past
    // the credential (#901 S1); anchoring on the first `:` instead is a no-op for every
    // `scheme://` input, since `scheme_separator_end` consumes the following slash run to the
    // identical offset either way.
    //
    // This puts `redact_secondary_colon_credential`'s existing false-positive population
    // (REST paths like `.../v1/items:search`, Maven coordinates `group:artifact`, RFC 3339
    // timestamps `T08:40:19Z`) on every host-having, userinfo-free URL — previously only
    // reachable via the fallback paths for unparseable/opaque URLs — since this is now the
    // primary redaction path for the common case. Accepted for the same reason as elsewhere in
    // this module: over-redacting a non-credential is always safer than leaking a real one.
    // Two shapes still survive unredacted here, as elsewhere in this module. A token-shaped
    // credential with no separating colon (`.../ghp_TOKENVALUE@internal`) is not fixed since
    // doing so would require routing through `RegionKind::Authority` and reopening the #887
    // over-redaction regression pinned by
    // `test_redact_userinfo_authority_widen_branch_token_prefix_over_redaction_is_accepted`
    // and `..._no_token_prefix_is_unaffected`. A percent-encoded separator
    // (`user%3Aglpat-SECRET%40internal`) is a different, structural gap, not a deliberate
    // trade: with no literal `:` or `@` anywhere in `raw`, no colon/at-sign-based scan in this
    // module — this one included — can see it.
    if url.username().is_empty() && url.password().is_none() {
        let authority_start = raw
            .find(':')
            .map_or(0, |scheme_end| scheme_separator_end(raw, scheme_end));
        let tail = &raw[authority_start..];
        // Mirrors `redact_span_colon_credential`'s own `Cow::Borrowed` short-circuit: most
        // URLs reaching this branch (an ordinary `scheme://host/path` with no colon past the
        // authority) have nothing for the scan to find, so skip both the scan's own internal
        // `to_string()` and the `format!` allocation below on that common, credential-free path.
        if !tail.contains(':') {
            return raw.to_string();
        }
        return format!(
            "{}{}",
            &raw[..authority_start],
            redact_secondary_colon_credential(tail)
        );
    }
    // `set_username`/`set_password` only fail for a cannot-be-a-base URL — never true here,
    // since a URL with `username()`/`password()` set is always base-having by construction —
    // but a hardcoded fallback marker is used instead of ever risking the original,
    // credential-bearing string leaking through an unexpected `Err` path.
    if url.set_username("***").is_err() || url.set_password(None).is_err() {
        return "<redacted: index URL contained userinfo>".to_string();
    }
    redact_authority_url_tail(url.as_str())
}

/// #869: an authority-having URL's own userinfo is masked above via `Url::set_username`/
/// `set_password` directly, never through [`redact_credential`]'s `mask_at` — but the same
/// tail-leak family still applies here (e.g. `https://user:hunter2@evil/tok:SECRET`, where
/// `tok:SECRET` sits untouched in the path). `serialized` (the already-userinfo-masked
/// `url.as_str()`) is expected to contain the literal `***@` marker at this call site, since it is
/// only reached once both `set_username("***")` and `set_password(None)` succeeded — but rather
/// than trust that as an unchecked guarantee, the marker-not-found branch still scans the whole
/// string via [`redact_secondary_colon_credential`] instead of skipping tail redaction outright,
/// so an unexpected `url` serialization change can only ever *widen* what gets redacted, never
/// silently fail open (review M1).
///
/// This necessarily extends [`redact_colon_credential`]'s existing false-positive population
/// (e.g. a REST-style path segment like `.../v1/items:search`, or an RFC 3339 timestamp) to every
/// authority-having URL that also carries userinfo — previously such a path/query passed through
/// this function verbatim; now it is colon-scanned like any other `mask_at` tail (review M3).
/// Accepted for the same reason the rest of this file accepts it: the output only ever feeds a
/// `tracing` line or error string, and over-redacting a non-credential is always safer than
/// leaking a real one.
// `serialized.find("***@")` locates an ASCII marker, so `tail_start` always lands on a char
// boundary.
#[allow(clippy::string_slice)]
fn redact_authority_url_tail(serialized: &str) -> String {
    let Some(marker_at) = serialized.find("***@") else {
        return redact_secondary_colon_credential(serialized);
    };
    let tail_start = marker_at + "***@".len();
    format!(
        "{}{}",
        &serialized[..tail_start],
        redact_secondary_colon_credential(&serialized[tail_start..])
    )
}

/// Finds a credential-shaped userinfo `@` in `region`, for use *only* on a region that has no
/// reliable authority boundary of its own (the widened tail of an unparseable authority, or an
/// opaque `scheme:/path` value) — never on a real bounded authority, where every `@` is a
/// userinfo delimiter regardless of whether it looks credential-shaped (see
/// [`redact_credential`]'s own bounded `rfind('@')` pass for that case, [`RegionKind::Authority`]
/// only).
///
/// Returns the *last* `@` whose own preceding segment — back to the previous `@` in `region`, or
/// the start of `region` if this is the first one — contains a `:` that is not a Windows
/// drive-letter colon (`C:\`, `c:/`; see [`segment_has_credential_colon`]), i.e. looks
/// credential-shaped (`user:pass@...`) rather than an ordinary path/query component
/// (`@scope/pkg`, `john.doe@corp`, `file:///C:/Users/x@corp/project`). An `@` whose segment has
/// no such `:` is skipped, not treated as a scan boundary — this is what lets an S3-style case
/// (a trailing unrelated `@scope/pkg` after a real credential, e.g.
/// `c:///user:hunter2@evil/@scope/pkg`) resolve to the earlier, truly credential-shaped `@`
/// instead of the last `@` overall.
///
/// Delimiting segments by the previous `@` instead of the previous `/` (an earlier revision's
/// approach) is what closes #826's password-containing-`/` gap: a password containing `/`
/// (`user:pa/ss@evil`) still has its `:` in the *same* since-last-`@` segment as the `@` that
/// follows it, however many `/`s sit between them.
// `at` comes from `match_indices('@')` on ASCII '@' bytes, so every slice bound is always a
// char boundary.
#[allow(clippy::string_slice)]
fn find_credential_at(region: &str) -> Option<usize> {
    let mut prev_at = 0;
    let mut found = None;
    for (at, _) in region.match_indices('@') {
        if segment_has_credential_colon(&region[prev_at..at]) {
            found = Some(at);
        }
        prev_at = at + 1;
    }
    found
}

/// Case-sensitive prefixes of well-known API-token/secret formats (GitHub, GitLab, npm, PyPI,
/// Slack, AWS, Stripe-style, Google, DigitalOcean, HashiCorp Vault, Shopify, Figma, Docker, and
/// other common cloud-key shapes), used as [`find_token_prefix_at`]'s only discriminator for an
/// `OpaquePath` credential that has no password and so is not colon-shaped enough for
/// [`find_credential_at`] to recognize (#858). Not exhaustive in either direction: it neither
/// covers every real token format (see [`find_token_prefix_at`]'s own doc for exactly which
/// segment shapes it does and doesn't catch — a prefix not at that function's own segment-start
/// boundary still goes unrecognized, not just an unprefixed username), nor is it free of false
/// positives on ordinary text (`sk-` in particular is loose enough to match an unrelated
/// `pkg@1.0.0` name like `sk-lang@2.0.0`) — accepted, consistent with this module's broader
/// over-redaction-over-leaking trade (see [`redact_colon_credential`]'s own doc comment for the
/// same trade made elsewhere in this file).
const TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "gldt-",
    "glrt-",
    "glsoat-",
    "glptt-",
    "gloas-",
    "npm_",
    "pypi-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxo-",
    "xoxs-",
    "xoxr-",
    "AKIA",
    "ASIA",
    "ABIA",
    "ACCA",
    "sk-",
    "sk_live_",
    "rk_live_",
    "pk_live_",
    "AIza",
    "ya29.",
    "dop_v1_",
    "dor_v1_",
    "doo_v1_",
    "hvs.",
    "hvb.",
    "shpat_",
    "shpss_",
    "shpca_",
    "shppa_",
    "figd_",
    "dckr_pat_",
    "AKCp",
];

/// [`find_credential_at`]'s fallback for [`RegionKind::OpaquePath`] (#858, S4): finds a `@` whose
/// own `/`/`?`/`#`/`\`-delimited segment *starts with* one of [`TOKEN_PREFIXES`] — a
/// username-only credential with no password, which has no `:` and so is invisible to
/// [`find_credential_at`]'s colon-shape check. This is the precise, canonical statement of the
/// carve-out's rule — anything else in this module referring to it should defer to this doc
/// rather than restate it, since "starts with" (not merely "contains") is what actually bounds
/// the false-positive population: a token prefix sitting anywhere *other than* a segment's own
/// start (e.g. `c:/a;ghp_TOKEN@evil`, where `;` is a legitimate RFC 3986 path-parameter
/// separator, not one of this function's boundary characters) still goes unrecognized and is not
/// covered by this carve-out — see [`redact_credential`]'s own doc comment, C1, for the fuller
/// picture of what remains unredacted. Only ever called when [`find_credential_at`] already
/// returned `None` (see [`redact_credential`]'s `OpaquePath` branch), so this can only widen what
/// gets redacted, never override a colon-shaped match.
///
/// A single forward pass over `region`, tracking only the current segment's start — unlike
/// [`find_credential_at`]'s per-`@` backward rescan of its own segment, this doesn't need one,
/// since a token prefix is a property of the segment's own start, not something that requires
/// looking back past earlier `@`s once a boundary has reset `seg_start`. Verified equivalent to,
/// and measurably faster than, a per-`@` `rfind` alternative over a 400k-input randomized corpus
/// (#858 security audit).
///
/// Returns the *last* qualifying `@`, matching [`find_credential_at`]'s own last-match
/// convention, so a decoy `@` segment following the real credential still resolves to the
/// earlier, genuinely token-prefixed one rather than stopping at the first candidate.
///
/// Treats `\` as a segment boundary, unlike [`extend_credential_at`], which deliberately does
/// not (see that function's own doc comment for why). The asymmetry is safe today — both
/// directions only ever widen what gets redacted — but is undocumented anywhere else, so a future
/// "unify the boundary sets" cleanup should know it would change behavior for `c:\ghp_X@evil`
/// before doing so.
// `i`/`seg_start` come from `enumerate()` over `region.bytes()` and ASCII byte-literal matches
// against '@'/'/'/'?'/'#'/'\\', so every slice bound stays a char boundary.
#[allow(clippy::string_slice)]
fn find_token_prefix_at(region: &str) -> Option<usize> {
    let mut seg_start = 0;
    let mut found = None;
    for (i, b) in region.bytes().enumerate() {
        match b {
            b'@' => {
                if TOKEN_PREFIXES
                    .iter()
                    .any(|p| region[seg_start..i].starts_with(p))
                {
                    found = Some(i);
                }
                seg_start = i + 1;
            }
            b'/' | b'?' | b'#' | b'\\' => seg_start = i + 1,
            _ => {}
        }
    }
    found
}

/// Widens a credential-shaped `@` found by [`find_credential_at`] forward across any further `@`
/// in `region` that is not separated from it by a `/`, `?`, or `#` (#859) — the `OpaquePath`
/// counterpart to [`RegionKind::Authority`]'s own last-`@`-*overall*-wins bounded pass, needed
/// because [`find_credential_at`] returns the *last* credential-shaped `@` only, and treats
/// everything past it (including a literal `@` inside the password itself) as outside the match:
/// `at` is `find_credential_at`'s result for `user:pa@ss@evil`, but the real credential/host
/// boundary is the *second* `@` — the segment between them (`ss`) is still part of the password,
/// not a new path component.
///
/// Stops as soon as a `/`, `?`, or `#` appears before the next `@` — the same boundary set
/// [`redact_credential`]'s own `Authority` bounded pass and [`redact_colon_credential`] already
/// use, so this doesn't re-introduce the boundary-rule duplication PR #863 unified. `/` is what
/// keeps `user:hunter2@evil/@scope/pkg` from extending into `@scope` (#845's own boundary); `?`
/// and `#` matter because [`redact_userinfo`] itself preserves the query string/fragment for its
/// own direct callers — a `/`-only stop set would let a query-shaped `@` (e.g.
/// `user:pw@host?email=a@b`) get pulled into the masked span, consuming the `?`/`#` and any
/// content after it that a direct [`redact_userinfo`] caller expects kept intact (impl-critic
/// C1). Since #866, [`url_for_tracing`] no longer depends on this boundary for its own
/// correctness — it truncates the raw string at the first `?`/`#` before redacting at all — but
/// [`redact_userinfo`]'s own contract still requires it.
///
/// Deliberately does **not** stop at `\`: unlike `/`/`?`/`#`, a backslash is not treated as a
/// general segment boundary anywhere else in this file (only [`colon_is_drive_letter`] gives it
/// positional meaning, for detecting a standalone drive letter specifically) — an unrelated
/// `\`-separated Windows-path-shaped tail extending into the masked span is accepted as an
/// over-redaction trade-off, not a leak, consistent with this file's existing
/// over-redaction/false-positive trade-offs (see [`redact_colon_credential`]'s own doc comment).
// `at`/`next` come from `find('@')` on ASCII '@' bytes, so every slice bound is always a char
// boundary.
#[allow(clippy::string_slice)]
fn extend_credential_at(region: &str, at: usize) -> usize {
    let mut at = at;
    loop {
        let tail = &region[at + 1..];
        let Some(next) = tail.find('@') else {
            return at;
        };
        if tail[..next].contains(['/', '?', '#']) {
            return at;
        }
        at += 1 + next;
    }
}

/// Whether `segment` contains a `:` that is not a Windows drive-letter colon, not a bracketed
/// IPv6 literal's own colon ([`bracket_host_shape_end`]), and not a `host:port`-shaped port
/// separator ([`is_port_like`]) — [`find_credential_at`]'s shape check. A bare
/// `segment.contains(':')` would mistake `file:///C:/Users/x@corp/project`'s drive letter for
/// evidence of a credential (S2 finding): once `@`-delimited segments can span past a `/`, the
/// `C:` in a `file:///C:/...` path sits in the same segment as a later, unrelated `@`. It would
/// likewise mistake `[::1]:8443/pkg@1.0.0`'s own address/port colons for a credential (code
/// review Finding 2) for the same reason — an ordinary bracketed-IPv6 registry host ends up in
/// the same segment as a completely unrelated trailing `@version`.
///
/// A bracket found anywhere in `segment` — not just at its start — has its IPv6-shaped span
/// skipped over first (#860, D1); only its *immediately*-following port-separator `:` (nothing
/// else in the segment) is then checked by [`is_port_like`] rather than being exempted
/// unconditionally regardless of what follows it. Deliberately scoped this narrowly (impl-critic
/// S1): an earlier revision applied [`is_port_like`] to *every* colon in the segment, not just a
/// bracket-adjacent one, which silently exempted an ordinary ≤5-digit value having nothing to do
/// with any bracket (`c:/user:12345/x@evil` used to redact on `main`, since any non-drive-letter
/// colon there is already accepted as an over-redaction false positive — see this function's own
/// top-level doc comment — and stopped redacting once every colon got the port exemption).
///
/// The "immediately-following" colon only earns that exemption when [`bracket_host_shape_end`]
/// actually advanced past a real closing `]` (code review finding): an earlier revision granted
/// it whenever a bracket was merely *attempted*, even one that never closed, so a stray `[`
/// immediately followed by a colon (`[:12345`) was wrongly treated as if it opened a genuine
/// IPv6 host and had its own next colon exempted as a "port" — this scanner's contract is that
/// only a real bracket licenses that carve-out, an ordinary (non-bracket) colon gets none.
///
/// `next_bracket`/`next_colon` are threaded and translated via [`translate_bracket`]/
/// [`translate_offset`] exactly like [`colon_credential_match_seeded`]'s own loop (#896, the same
/// pattern #893/#894 fixed there): an unconditional `remaining.find('[')` on every iteration must
/// scan all of `remaining` just to *prove absence* of a bracket, and the drive-letter branch below
/// only advances `cursor` by 2-3 bytes per iteration, so a long bracket-free run (e.g. a Windows
/// path segment, `("c:/" * n) + "@x"`) turned this quadratic before caching — verified
/// byte-for-byte equivalent to the pre-fix scan via `redact_userinfo`, over all 271,452 strings of
/// length 1-5 drawn from the 12-character alphabet `[ ] : / ? # \ c a 0 x @` (not committed as a
/// permanent test; see #896's own tracked follow-up for a durable equivalence harness).
// `bracket`/`colon` come from `find`/`starts_with` of ASCII `[`/`]`/`:` bytes, so every slice
// bound is always a char boundary.
#[allow(clippy::string_slice)]
fn segment_has_credential_colon(segment: &str) -> bool {
    let mut cursor = 0;
    let mut bracket_adjacent = false;
    let mut next_bracket = segment.find('[');
    let mut next_colon = segment.find(':');
    while cursor < segment.len() {
        let remaining = &segment[cursor..];

        let colon_here = translate_offset(next_colon, cursor, remaining, ':');
        next_colon = colon_here.map(|c| cursor + c);
        let bracket_here = translate_bracket(next_bracket, cursor, remaining);
        next_bracket = bracket_here.map(|b| cursor + b);

        if let Some(bracket) = bracket_here {
            if let Some(colon) = colon_here.filter(|&c| c < bracket) {
                if !colon_is_drive_letter(segment, cursor + colon) {
                    return true;
                }
                cursor += colon + 1;
                bracket_adjacent = false;
                continue;
            }
            let shape_end = bracket_host_shape_end(remaining, bracket);
            // code review: only a genuinely *closed* bracket (the byte just before `shape_end` is
            // an actual `]`) licenses the `is_port_like` exemption below on the colon that
            // follows — an earlier revision set this unconditionally, so a stray unclosed `[`
            // (e.g. `[:12345`) got treated as if it opened a real IPv6 host and its own
            // immediately-following colon was wrongly exempted as a "port", when it should have
            // been evaluated as an entirely ordinary (unexempted) colon instead. Checking the
            // actual closing byte, rather than inferring closure from `shape_end > bracket + 1`,
            // is defensive since #891: closure is no longer reliably inferable from `shape_end`
            // alone now that `bracket_host_shape_end` can also advance more than one byte past an
            // *unclosed* run of consecutive `[` (to stay amortized-linear) — the guard that keeps
            // that run-skip from ever landing past a genuinely unclosed run (`i == open + 1`, see
            // that function's own doc comment) happens to keep the old inference sound here too,
            // but this explicit check does not depend on that happening to hold.
            bracket_adjacent = remaining.as_bytes().get(shape_end - 1) == Some(&b']');
            cursor += shape_end;
            continue;
        }

        let Some(colon) = colon_here else {
            return false;
        };
        let colon_is_bracket_adjacent = bracket_adjacent && colon == 0;
        bracket_adjacent = false;

        if colon_is_drive_letter(segment, cursor + colon) {
            cursor += colon + 1;
            continue;
        }
        if colon_is_bracket_adjacent {
            let value_start = colon + 1;
            let value_end = remaining[value_start..]
                .find(['/', '?', '#'])
                .map_or(remaining.len(), |i| value_start + i);
            if is_port_like(&remaining[value_start..value_end]) {
                cursor += value_end.max(colon + 1);
                continue;
            }
        }
        return true;
    }
    false
}

/// Byte offset in `text` just past the bracketed-IPv6-host *shape* opened at `text[open] ==
/// '['`, recognized independent of whether it ever closes with a `]` — the single carve-out
/// [`segment_has_credential_colon`], [`bounded_has_credential_colon`], and
/// [`redact_colon_credential`] all share (#860, D1), replacing what used to be three
/// independently-evolving implementations of the same rule (one of them, `redact_colon_credential`'s,
/// anchored to the scan's starting cursor rather than recognizing a bracket anywhere ahead of it).
///
/// An IPv6 literal's alphabet is exactly hex digits, `:`, and `.` (an embedded IPv4 tail) — the
/// explicit IPv6-shape gate that tells "this bracket really opens an IPv6 host" apart from a
/// stray `[` that merely sits elsewhere in the string (e.g. an npm dist-tag-shaped path
/// segment): this scans forward from `open + 1` while a byte stays in that alphabet, stopping
/// only at a `]` — the *only* thing this function ever treats as confirming the span was really
/// an IPv6 host literal rather than some other bracket-adjacent text. **Skips nothing at all**
/// (returns `open + 1`, past the bracket alone) when the alphabet run ends without ever finding
/// a `]` — an impl-critic finding (C3): an earlier revision skipped as far as the alphabet run
/// went even when it never closed, which is exactly what let an unclosed literal's own
/// pseudo-colons swallow a *real* credential colon sitting right after the disqualifying byte
/// (`[::1:glpat-SECRET` — no `]` anywhere — used to skip past `[::1:` as if it were a closed
/// host, treating the credential's own `:` as part of the address and leaking `glpat-SECRET`
/// untouched). Only ever crediting a *genuinely closed* bracket keeps every colon inside an
/// unclosed one visible to the caller's own ordinary colon scan instead.
///
/// Deliberately does **not** also consume an immediately-following `:port` separator, unlike an
/// earlier revision's unconditional skip: that unconditional skip is exactly what let
/// `[::1]:glpat-SECRET` pass through unredacted (#860's own issue body) — *nothing* after a
/// closing bracket's colon was ever inspected. Every caller now runs that colon back through its
/// own ordinary [`is_port_like`]-gated logic once this span is skipped, so a real port
/// (`[::1]:8443`) stays exempt while anything else (`[::1]:glpat-SECRET`, or the previously
/// accepted `[::1]:abc`/`[::1]:notaport` collisions) is treated exactly like any other
/// non-bracket credential-shaped colon and gets redacted.
///
/// A `[` immediately following `open` (i.e. `text[open + 1] == b'['`, two or more consecutive `[`
/// bytes) is not itself in the IPv6-literal alphabet, so every `[` in such a run except the *last*
/// one is provably not a valid opener — its own fate never depends on what comes after it, only
/// the last one's does (#891). Rather than returning `open + 1` and making the caller rediscover
/// this one byte at a time (this function's quadratic-prone callers — `colon_credential_match_seeded`,
/// and, since #896, `segment_has_credential_colon` too — each re-scan their own remaining tail with
/// `find(':')` on every iteration — advancing 1 byte per call turned a long run of `[` into O(n²)),
/// this scans the whole run in one pass and returns the offset of its *last* `[` (`open + L` for a
/// run of length `L >= 2`) directly, so the caller's next iteration lands there and evaluates that
/// one bracket as an ordinary (possibly-closed) opener — behavior-equivalent to the
/// one-byte-at-a-time version since only `[` bytes (never a candidate opener) are skipped.
///
/// Deliberately restricted to `i == open + 1` (impl-critic C1): the alphabet-run loop below can
/// also reach a *later* `[` after first consuming in-alphabet bytes (`:`, `.`, hex digits) — e.g.
/// `[0:0[ghp_SECRET`'s second `[` at `i` well past `open + 1`. Treating that later `[` the same
/// way would return an offset past the real credential-separating `:` at `i`'s position, making
/// the caller's cursor jump straight over it and leave the whole value completely unredacted (a
/// leak, not just a missed optimization) — confirmed by exhaustive differential testing against
/// unguarded code (960,799 inputs of length 1-7 over `[ ] : 0 x @ /`: 10,669 divergences, all in
/// the leak direction, 0 safe). Restricting the run-skip to a `[` that opens *immediately*, with no
/// intervening alphabet byte, keeps it provably limited to brackets that could never have been a
/// valid opener regardless of what preceded them.
// `open`/`i`/`j` are ASCII byte offsets (`[`, `]`, hex digits, `:`, `.` are all single-byte ASCII),
// so every slice bound derived from this function's return value is always a char boundary.
fn bracket_host_shape_end(text: &str, open: usize) -> usize {
    let bytes = text.as_bytes();
    let mut i = open + 1;
    while let Some(byte) = bytes.get(i) {
        match byte {
            b']' => return i + 1,
            b':' | b'.' | b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => i += 1,
            b'[' if i == open + 1 => {
                let mut j = i;
                while bytes.get(j) == Some(&b'[') {
                    j += 1;
                }
                return j - 1;
            }
            _ => break,
        }
    }
    open + 1
}

/// Whether the `:` at byte offset `colon` in `text` is a Windows drive-letter colon: a single
/// ASCII letter — itself preceded by the start of `text`, `/`, or `\` (so it's a standalone
/// token, not the tail of a longer word) — immediately followed by `/` or `\`. Mirrors
/// [`redact_colon_credential`]'s own `is_drive_letter` carve-out, which only ever checks this at
/// the very start of its scan window; this variant checks an arbitrary byte offset, since
/// [`segment_has_credential_colon`] scans a whole segment rather than a cursor-anchored prefix.
///
/// Returns `false` outright when `text[colon]` is not `:` — a no-op guard for both existing
/// callers (each already derives `colon` from its own `find(':')`), which makes the helper total
/// over any offset instead of assuming its precondition. This is what lets
/// [`redact_colon_credential`]'s own inline 3-byte drive-letter test collapse to exactly
/// `colon_is_drive_letter(remaining, 1)`: with `colon == 1`, `letter_is_standalone` short-circuits
/// to `true`, reducing the helper to `bytes[0].is_ascii_alphabetic() && bytes[1] == b':' &&
/// bytes[2] in {'/', '\\'}` — the same conjunction, reordered.
///
/// A genuine single-letter *username* immediately followed by a `/`-leading password is
/// shape-identical to a drive letter and is therefore also left unredacted (M4 finding,
/// pre-existing HEAD behavior, e.g. `c:/a:/b@evil` stays a no-op) — contrived enough (a
/// one-character username, itself followed by a password starting with `/`) to accept rather
/// than fix.
fn colon_is_drive_letter(text: &str, colon: usize) -> bool {
    let bytes = text.as_bytes();
    if bytes.get(colon) != Some(&b':') {
        return false;
    }
    let is_letter = colon
        .checked_sub(1)
        .and_then(|i| bytes.get(i))
        .is_some_and(u8::is_ascii_alphabetic);
    let letter_is_standalone = colon == 1
        || colon
            .checked_sub(2)
            .and_then(|i| bytes.get(i))
            .is_some_and(|b| matches!(b, b'/' | b'\\'));
    is_letter && letter_is_standalone && matches!(bytes.get(colon + 1), Some(b'/' | b'\\'))
}

/// Whether `value` (the text right after a `:`, up to the next delimiter or end of input) looks
/// like a port number (`host:8443`) rather than a credential — 1-5 ASCII digits. Shared by
/// [`redact_colon_credential`]'s own carve-out and [`redact_userinfo_unparseable`]'s widening
/// gate, so both agree on what counts as "just a port" (#826).
fn is_port_like(value: &str) -> bool {
    !value.is_empty() && value.len() <= 5 && value.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `bounded` (the authority text up to — but not including — the genuine `/`/`?`/`#`
/// boundary that truncated it) contains a `:` that is *not* just a trailing `host:port` suffix,
/// i.e. evidence a credential may already have started before that boundary character rather
/// than the boundary genuinely ending a plain `host[:port]` authority. Gates whether
/// [`redact_authority_suffix`] even attempts [`find_credential_at`]'s `@`-shape check on the
/// wider `region`, or goes straight to [`redact_colon_credential`]'s unrestricted colon scan
/// (#826).
///
/// Only the boundary's own trailing colon is checked against [`is_port_like`] — `gitlab.corp:8443`
/// strips down to `gitlab.corp` (no further `:`, not widened) while `user:hunter2:8443` strips
/// only its trailing port to `user:hunter2` (still contains `:`, still widened) — so a
/// credential followed by an incidental port-shaped suffix is not missed just because the very
/// last colon in `bounded` happens to look like a port.
///
/// A `bounded` starting with a bracketed IPv6 literal (`[::1]:8443`) has only that bracket's own
/// IPv6-shaped span stripped first (#860, D1, [`bracket_host_shape_end`]) — a colon immediately
/// following it (the `]:port` separator) is left in place for the trailing `rfind`/[`is_port_like`]
/// check below to evaluate on its own merits, exactly like any other colon in `bounded`, rather
/// than being exempted unconditionally regardless of what follows it: a well-formed port
/// (`[::1]:8443`) still strips away cleanly (`is_port_like` accepts it), while anything else
/// (`[::1]:notaport`, `[::1]:glpat-SECRET`) now correctly reads as evidence a credential may be
/// present, instead of being silently exempted just for sitting next to a bracket. An unclosed
/// bracket leaves the rest of `bounded` for the same trailing check to evaluate, rather than
/// returning early — distinct from [`segment_has_credential_colon`]'s "return `false`" on the
/// same case, since this function's contract is "does `bounded` contain a credential-shaped
/// colon at all", not "identify a specific one".
// `bracket_host_shape_end`'s return and `colon` (from `rfind` of an ASCII `:` byte) are always
// char-boundary-safe byte offsets, so every slice bound below is always a char boundary.
#[allow(clippy::string_slice)]
fn bounded_has_credential_colon(bounded: &str) -> bool {
    let bounded = if bounded.starts_with('[') {
        &bounded[bracket_host_shape_end(bounded, 0)..]
    } else {
        bounded
    };
    let trimmed = bounded.rfind(':').map_or(bounded, |colon| {
        if is_port_like(&bounded[colon + 1..]) {
            &bounded[..colon]
        } else {
            bounded
        }
    });
    trimmed.contains(':')
}

/// The one semantic difference [`redact_credential`] handles between its two call sites: whether
/// `region` is a real URL authority span, where the WHATWG parser gives *every* `@` up to the
/// first `/`/`?`/`#` unconditional userinfo-delimiter status (licensing an unconditional bounded
/// `@` pass, regardless of whether what precedes it looks credential-shaped), or an opaque
/// `scheme:/path` value with no authority at all, where an `@` can just as easily be an ordinary
/// path separator (`file:///home/user@example/file`) and must be shape-checked via
/// [`find_credential_at`] before it can be trusted. That difference is real and both traversals
/// stay separate in [`redact_credential`] — only the *rules* each one applies are deduplicated.
/// See [`redact_credential`]'s own doc comment for the coverage table this asymmetry produces.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegionKind {
    /// A URL authority span — `raw` after `scheme://`, up to the first `/`, `?`, or `#`.
    /// Produced by [`redact_userinfo_unparseable`].
    Authority,
    /// An opaque `scheme:/path` value with no authority (`Url::host() == None`). Produced by
    /// [`redact_userinfo_opaque_path`].
    OpaquePath,
}

/// [`redact_credential`]'s `Authority`-branch host-boundary scan (#862): a plain
/// `region.find(['/', '?', '#'])` stops on the first `/` of a *nested* `scheme://` just as
/// readily as on a real path separator, handing the bounded `@` pass that follows a window
/// truncated before the real credential whenever a credential-shaped `@` sits earlier in
/// `region` (`a@b://user:hunter2@evil` — a plain scan stops at `b`'s `/` and would mask `a`
/// instead of `hunter2`). A `/` only counts as a genuine boundary when it is not itself part of
/// a scheme separator: a run of one or more consecutive `/` immediately preceded by a `:` (a
/// scheme separator can have any number of slashes, not just the canonical two) is not a
/// boundary. `?`/`#` never appear inside a scheme, so they always terminate the scan
/// immediately.
///
/// Returns as soon as it can determine the answer, and never re-examines a byte once it has
/// decided that byte's run is scheme punctuation: whether a run of `/` is a scheme separator
/// depends only on the single byte *before* the run (`:` or not), which is already known the
/// instant the run starts — so a non-scheme run returns immediately without scanning to its end,
/// and a scheme-shaped run is skipped in one inner loop rather than being walked byte-by-byte
/// from the outer scan. An earlier revision instead deferred that check until it found the byte
/// *after* the run, forcing a full scan of the run's length just to answer "is this a boundary"
/// — quadratic when [`redact_authority_suffix`] calls this once per remaining `/` in a long
/// contiguous run (verified live: 100 KB of contiguous `/` took 1.3s in a release build vs. the
/// fixed version's low-single-digit-millisecond cost for the same input).
// Every index here is an ASCII-byte position (`:`, `/`, `?`, `#` are all single-byte ASCII), so
// the returned boundary always lands on a char boundary.
fn host_boundary_scheme_aware(region: &str) -> usize {
    let bytes = region.as_bytes();
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        match byte {
            b'?' | b'#' => return i,
            b'/' => {
                if i > 0 && bytes.get(i - 1) == Some(&b':') {
                    // A scheme separator: skip the whole run in this one inner loop instead of
                    // returning to the outer loop per byte, so a long run is visited once.
                    while bytes.get(i) == Some(&b'/') {
                        i += 1;
                    }
                } else {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    bytes.len()
}

/// [`redact_userinfo_unparseable`]'s and [`redact_userinfo_opaque_path`]'s shared credential
/// scanner (#846, tracked under parent issue #856): one implementation of every carve-out rule
/// (drive-letter, bracketed-IPv6, port-shaped, credential-colon shape), called once per
/// [`RegionKind`] with its own `start` offset and its own traversal — see that type's own doc
/// comment for why the two traversals stay separate rather than merging into one.
///
/// `region` is `&raw[start..]`. [`RegionKind::Authority`] delegates to
/// [`redact_authority_suffix`], which keeps looking past every genuine `/`/`?`/`#` boundary
/// ([`host_boundary_scheme_aware`]) for a further nested credential rather than trusting the
/// first bounded match (#862) — see that function's own doc comment for its full algorithm.
/// [`RegionKind::OpaquePath`] skips straight to the shared tail: [`find_credential_at`] on the
/// whole `region`, falling back to [`find_token_prefix_at`] when that finds nothing (#858),
/// masking with `***@` on `Some` from either, falling through unconditionally to
/// [`redact_colon_credential`] only when both return `None` (#810/#818) — see "Coverage per
/// `RegionKind`" below, class S3/#857, for why `OpaquePath` no longer special-cases this
/// fallthrough.
///
/// # Coverage per `RegionKind`
///
/// Every carve-out below is shared by both kinds *except* the one marked `Authority`-only
/// (S4, #858) — a class PR #845 fixed on the `Authority` side only, tracked under the parent
/// issue #856, with an `OpaquePath`-side follow-up filed rather than fixed here:
///
/// - Username-only userinfo with no password (`ghp_TOKEN@github.com`) — **`Authority` only**,
///   with one narrower exception on `OpaquePath` (C1). The bounded `@` pass never shape-checks,
///   so a bare username redacts correctly on `Authority` regardless of its shape; the
///   `OpaquePath` twin only redacts when [`find_token_prefix_at`] recognizes the username's own
///   segment as *starting with* one of [`TOKEN_PREFIXES`] (`c:/ghp_TOKEN@evil` → `c:***@evil`,
///   #858, S4) — see that function's own doc comment for the precise, canonical statement of
///   which shapes qualify. An unprefixed username-only credential (`c:/hunter2@evil`) still has
///   no authority span to license unconditional redaction and stays unredacted, by design: there
///   is no discriminator that distinguishes it from an ordinary path segment without
///   ecosystem-specific token-prefix sniffing. A *prefixed* one can still leak too, though, when
///   the prefix isn't at a `/`/`?`/`#`/`\` segment start (`c:/a;ghp_TOKEN@evil` — `;` is a
///   legitimate RFC 3986 path-parameter separator, not one of those boundary characters) — the
///   residual gap this carve-out leaves is broader than "unprefixed only". A token-prefixed
///   credential sitting in `mask_at`'s tail, past an already-masked colon-shaped credential, also
///   still leaks (`c:/user:pw@evil/ghp_BBB@evil2` → `c:***@evil/ghp_BBB@evil2`) — pre-existing,
///   byte-identical to `main`, not a regression: [`redact_secondary_colon_credential`]/
///   [`redact_further_credential`] have no prefix awareness of their own, and wiring one in was
///   the audit's rejected #875-adjacent approach (19 new leaks elsewhere).
///
/// `OpaquePath` used to additionally disable the [`redact_colon_credential`] fallback outright
/// (first for *any* `@` in the region, later — #857's own first pass — narrowed to only a
/// bracketed-IPv6-host shape) rather than sharing this fallthrough with `Authority`. Removed
/// entirely (impl-critic C1): a differential probe over the bracket/colon input space showed
/// every case the guard was meant to protect (`c:/[::1]:8443/pkg@1.0.0`,
/// `c:/[2001:db8::1]:443/pkg@1.0.0`) already comes back byte-identical from
/// [`redact_colon_credential`] alone — #860's fix already makes that scanner safe for a genuine
/// bracket shape — while the guard itself, not requiring an `@` to relate to the bracket at all,
/// opened brand-new leaks the *pre-#857* code never had (`c:/[]/token:glpat-SECRET`,
/// `file:///home/u/pkg[1]/gitlab-ci-token:JOBTOKEN` — any bracket shape anywhere in the value
/// silently disabled redaction of a completely unrelated credential elsewhere in it).
///
/// Shared by both kinds:
/// - A leading empty-userinfo `@` (`@types/node`) never short-circuits — both fall through past
///   it rather than returning early (code-review Finding 1).
/// - An `@` inside a password (`user:pa@ss@evil` → `***@evil`) is fully redacted for `Authority`
///   via its bounded pass, which takes last-`@`-*overall*-wins directly, and for `OpaquePath` via
///   [`extend_credential_at`], which widens [`find_credential_at`]'s credential-shaped `@` across
///   any further `@` not separated from it by a `/`/`?`/`#` (#859). `extend_credential_at` is
///   invoked only when `kind == OpaquePath` — `Authority`'s own rare fall-through into
///   [`redact_authority_suffix`]'s shared tail (the `#826` straddle case, where the bounded pass
///   finds no `@` of its own) deliberately does **not** get widened further, so it can still
///   partially leak through that narrow, pre-existing path (e.g. `user:pa/ss@wo@rd@evil`),
///   unchanged from `main` (impl-critic S2): widening it too would be an untested, out-of-scope
///   behavior change, not a fix for a specific leak.
/// - A drive-letter colon (`C:\`, `c:/`) is never credential-shaped ([`colon_is_drive_letter`]).
/// - A bracketed IPv6 literal's own colon is never credential-shaped
///   ([`bracket_host_shape_end`]); its immediately-following port separator, once reached, is
///   evaluated by the exact same [`is_port_like`] rule as any other colon (#860, D1).
/// - A `host:port` suffix (1-5 ASCII digits) is never credential-shaped ([`is_port_like`]).
/// - A colon-separated credential with no `@` at all falls through to
///   [`redact_colon_credential`] unconditionally, which itself keeps scanning past a masked
///   value for a further `@`-shaped credential rather than stopping at its first match (#862,
///   see that function's own doc comment).
// `start` is an ASCII byte offset (`find("://")`/`find(':')` on `raw`), so `region` always
// starts on a char boundary; every further offset comes from `find`/`rfind` of ASCII tokens on
// `region`, so every slice bound stays a char boundary throughout.
#[allow(clippy::string_slice)]
fn redact_credential(raw: &str, start: usize, kind: RegionKind) -> String {
    let region = &raw[start..];

    if kind == RegionKind::Authority {
        return format!("{}{}", &raw[..start], redact_authority_suffix(region));
    }

    // #869: a masked credential's own tail is not proof there is no further, independent
    // credential later in the same OpaquePath value — route it through
    // `redact_secondary_colon_credential` rather than emitting it verbatim. `Authority` never
    // reaches this closure (it returns above via `redact_authority_suffix`, which has its own,
    // more thorough continuation past a masked credential).
    let mask_at = |at: usize| {
        format!(
            "{}***@{}",
            &raw[..start],
            redact_secondary_colon_credential(&region[at + 1..])
        )
    };
    match find_credential_at(region).or_else(|| find_token_prefix_at(region)) {
        Some(at) => mask_at(extend_credential_at(region, at)),
        None => redact_colon_credential(raw, start, region),
    }
}

/// [`redact_credential`]'s `Authority`-branch worker (#862): walks `region` one
/// [`host_boundary_scheme_aware`]-delimited window at a time. `has_nested_scheme` — whether `://`
/// appears anywhere in `region` — is computed once up front and gates the one case that isn't
/// resolved immediately from a single window:
///
/// 1. A window with a credential-shaped `@` of its own (`window.rfind('@')`, excluding a leading
///    `@` at offset 0) masks it and moves on to the text right after that `@`, over-redacting
///    rather than guessing which of several candidate `@`s is real — unconditionally, regardless
///    of whether the caller anchored on a real preceding `scheme://` or not, since a
///    well-anchored match is not a safe reason to stop either
///    (`https://x@y:notaport/a@b/c://user:hunter2@evil` anchors on a real `https://` just as
///    confidently as a genuine credential would, yet `x@y` is decorative and the real credential
///    is `hunter2`, past the genuine `/`). This step is deliberately *not* gated on
///    `has_nested_scheme`/colon evidence past the first window either (#875, considered and
///    reverted): a colon-less `TOKEN@host` credential sitting past an earlier masked `@`, in a
///    value with no `://` and no colon anywhere at all (`a@b/ghp_TOKEN@evil`), is
///    shape-identical to an ordinary decoy `@` segment (`a@b/lib@2.0.0`) — there is no
///    discriminator here that doesn't also hide the real credential, so this function accepts
///    over-redacting every such decoy rather than risk it (see this function's own "Guarantees
///    and known gaps" section below for #875's current status).
/// 2. A window with credential-colon evidence ([`bounded_has_credential_colon`]) but no `@` of
///    its own widens immediately to the unrestricted, colon-based fallback (#810/#826):
///    [`find_credential_at`] is tried on everything from `region`'s own start (not just this
///    window — see below), falling back to [`redact_colon_credential`] when it finds nothing.
///    [`redact_colon_credential`] no longer stops at its own first masked value either (#862's
///    own C2: a decoy non-port-like value before a nested scheme, e.g. `notaport` in
///    `host/x@y:notaport/c://user:hunter2@evil`, used to be masked and returned immediately,
///    leaving a real credential further into the tail unexamined; see that function's own doc
///    comment for the fix).
/// 3. A window with **neither** an `@` **nor** colon evidence, but `has_nested_scheme` is true and
///    a further genuine boundary is still ahead, is left undecided and scanning continues past it
///    (#862, impl-critic C1): an ordinary host segment with no `@` and no colon (`host`,
///    `npmjs.org`) is not by itself evidence there is no credential *anywhere* in `region` when a
///    `scheme://` is known to follow — a bare `TOKEN@host` (`ghp_`/`glpat`-shaped, no `:` at all)
///    sitting behind an ordinary decoy path segment (`pkg@1.0.0`, `@scope`, `repo@v1.2.3`) needs
///    exactly this continuation to ever be reached, since neither [`find_credential_at`] nor
///    [`redact_colon_credential`] can recognize a colon-less credential on their own — only an
///    unconditional bounded `@` pass can. An earlier revision gave up at the first such window
///    unconditionally (no `has_nested_scheme` gate) and fell straight to
///    [`redact_colon_credential`] on the whole remaining `region`, which is exactly what missed
///    this family — but *also*, without the gate, mistook an ordinary trailing version segment
///    for a credential purely because nothing else was found first: impl-critic S4's own
///    `nexus.corp:8081/repo/lib@2.0.0` (no nested scheme anywhere) must stay fully visible, so a
///    genuine `://` still ahead is what licenses looking further, not merely "nothing found yet".
/// 4. Neither an `@`, colon evidence, nor (`has_nested_scheme` false or no boundary left) reason
///    to keep looking: the streak is over. If nothing has been masked yet, this widens to the
///    unrestricted colon fallback exactly as step 2 does (round 6's original, narrower behavior
///    for a plain host with no colon and no scheme nesting, e.g. `gitlab.corp/user:hunter2@evil`
///    still redacts to `gitlab.corp/user:***`, not `gitlab.corp/***@evil`); if a credential has
///    already been masked, whatever textually remains is emitted unchanged.
///
/// Colon evidence (step 2) is checked *before* falling through to step 3's continuation, on this
/// window alone — not the accumulated span since `region`'s start — precisely so a real
/// `host:port`-shaped credential prefix (`host:abc/x`, where `abc` is not port-like) widens
/// immediately rather than being treated as an undecided pass-through window; the fallback itself
/// still receives `region` from its own true start (not just this window) so
/// [`redact_colon_credential`]'s bracket-tracking state sees anything — e.g. a `[` — from several
/// windows back.
///
/// This necessarily also masks a credential-shaped `@` in ordinary path/query content that
/// happens to sit past a well-anchored URL's own first path separator (e.g. the `b://c@d`
/// segment in `https://user:hunter2@registry.example:99999/a/b://c@d` is masked too) — accepted
/// over-redaction of a tracing-only value, per this module's own doc, traded for never
/// under-redacting.
///
/// Implemented as a single forward loop over `region`, not recursion: a `format!`-per-boundary
/// recursive version has no depth bound, so an untrusted value with enough `/`-separated segments
/// aborts the whole process with a stack overflow rather than a catchable panic. This loop instead
/// tracks two absolute offsets into `region` — `base` (the true start of the still-undecided
/// streak) and `window_start` (the current window alone) — and appends to one growing `output`
/// buffer, so recursion depth is `O(1)` regardless of how many boundaries `region` contains. Total
/// work is `O(region.len())`: `window_start` only ever advances, and each call to
/// `host_boundary_scheme_aware(&region[window_start..])` scans no further than that call's own
/// boundary — so a byte is scanned by more than one call only in the narrow span between a masked
/// `@` and the window boundary that was already found past it (`window_start` moves back to just
/// after the `@`, which can sit before that boundary), meaning every byte is charged to at most
/// two `host_boundary_scheme_aware` calls, not re-scanned an unbounded number of times.
/// [`bounded_has_credential_colon`] is likewise checked once per window, on that window alone,
/// rather than on the growing `region[base..]` span (an earlier revision re-scanned that growing
/// span on every iteration, which is quadratic on a long run of colon-free, `@`-free windows) —
/// verified live in a release build at up to 3.2 MB of a single contiguous `/` run, and
/// separately over many small colon-free/`@`-free windows (the two-cursor path this fix added),
/// with linear scaling at every size tested in both shapes
/// (`test_redact_userinfo_unparseable_contiguous_slash_run_is_linear_time`,
/// `test_redact_userinfo_unparseable_many_small_undecided_windows_is_linear_time`).
///
/// # Guarantees and known gaps (after 7 rounds of adversarial verification, plus #871)
///
/// Confirmed fixed by live A/B comparison against `origin/main`, using the adversarial corpus
/// (~90,000 distinct shapes) accumulated across all 7 rounds: the original #862 report
/// (colon-less `TOKEN@host` credentials reachable only behind a scheme-aware backward anchor),
/// impl-critic's C1/C2 decoy-`@`/nested-scheme leak families, the `?`/`#`-terminated window
/// classes, and the colon-decoy-`@` classes found in rounds 4-6. Steps 1-4 above are what those
/// rounds converged on.
///
/// Also fixed, in separate follow-up rounds:
/// - **#871**: `has_nested_scheme` was computed once over the whole `region`, not scoped to "a
///   genuine `://` still ahead of the current window" as step 3 above implies — when the
///   caller's backward anchor had already consumed the string's only `://` while computing
///   `region`'s start, the gate read `false` and step 3's continuation was skipped even though a
///   credential sat past the next boundary (`://://?ghp_TOKEN@` used to come back unchanged).
///   Fixed at the source rather than in this function: [`redact_userinfo_unparseable`]'s anchor
///   now picks the *first* `://` preceding the credential's `@`, not the nearest one, so `region`
///   retains more of what preceded it than the nearest-preceding choice did. See that function's
///   own doc comment for the honest trade this represents — a net improvement on the adversarial
///   corpus, not a strictly monotonic one.
/// - **#870/#873/#874** (fixed together, as one unified change — see
///   [`redact_further_credential`]'s own doc comment): every fallback path in this function and
///   in [`redact_colon_credential`] that used to stop looking after finding one credential of a
///   single shape now keeps scanning the tail for a further credential of *either* shape
///   (`@`-shaped or colon-only) via that shared helper — `colon_evidence`'s per-window gate
///   (step 2) is unchanged (still `base == 0`-scoped, by design), but the two points that used to
///   emit an unexamined tail verbatim once it stopped applying (the widen branch's own
///   `find_credential_at` hit, and the loop-exhaustion branch) now route that tail through it
///   instead.
///
/// One narrow, low-severity gap remains, from the #875 report, deliberately deferred rather than
/// chased further:
/// - **#875**: multi-`@` input with no nested scheme anywhere can be over-redacted on every `@`
///   once the first is masked, not just the first — over-redaction, not a leak, and only reaches
///   a `tracing`/error-message sink. A gate that avoids this over-redaction was tried and
///   reverted: any discriminator narrow enough to let `a@b/lib@2.0.0`'s decoy `@` through is also
///   narrow enough to let a colon-less `TOKEN@host` credential in the exact same shape
///   (`a@b/ghp_TOKEN@evil`) through unmasked, since the two are byte-for-byte indistinguishable
///   without ecosystem-specific token-prefix sniffing — the same fundamental ambiguity #858
///   already documents as unfixed for `OpaquePath`. Spending a real credential leak to buy back
///   cosmetic text fidelity on a `tracing`-only sink is not an acceptable trade under this
///   module's own stated design rule (accepted over-redaction, never under-redaction); #875
///   stays open pending dedicated research into a real discriminator, not a quick heuristic.
///
/// This doc comment has overclaimed completeness in earlier rounds; treat the step-by-step
/// description above as bounded by this one documented, tracked exception, not as a
/// completeness guarantee.
#[allow(clippy::string_slice)]
fn redact_authority_suffix(region: &str) -> String {
    // Gates whether a window with neither an `@` nor colon evidence of its own is worth looking
    // past at all (#862, impl-critic C1's own follow-up finding): continuing unconditionally
    // reopens exactly the over-redaction impl-critic S4 fixed — an ordinary registry
    // `host:port/repo/pkg@1.0.0` path, or `[::1]:8443/pkg@1.0.0`, has no nested scheme anywhere
    // and must stay fully visible, not have its trailing version-shaped `@` mistaken for
    // userinfo. A colon-less `TOKEN@host` credential is only ever reachable *behind* a nested
    // `scheme://`, so a genuine `://` still ahead is what licenses looking further; computed once
    // up front, not re-checked per window, so this costs `O(region.len())` total rather than
    // `O(region.len())` again on every window.
    let has_nested_scheme = region.contains("://");
    let mut output = String::new();
    // Start of the still-undecided streak: every byte from here on has neither been masked nor
    // confirmed safe to emit yet. Stays put while a window has no `@` of its own, so that once
    // colon evidence does turn up (or the streak runs out), `redact_colon_credential`/
    // `find_credential_at` see the *whole* accumulated span from its true start — not just the
    // latest window — which matters for `redact_colon_credential`'s own bracket-tracking state
    // (a `[` several windows back must still be visible to it).
    let mut base = 0;
    // Start of the single window currently being checked for its own `@`. Always advances past
    // a boundary a window turns out to have neither evidence in, independent of `base`, so a
    // bare `@` several windows past a colon-free host segment is still found as *that window's
    // own* userinfo delimiter — not merged into one giant mask starting at `base`.
    let mut window_start = 0;
    // Sticky bracket state carried across the mask site below (#886): the span it emits instead
    // of recursing back into this function is handed to [`redact_span_colon_credential`], which
    // cannot see anything before its own start, so whether a `[` appeared earlier in `region` —
    // inside text already replaced by an earlier `***@` mask — has to be threaded through
    // explicitly. Updated only here, using `base`'s value from *before* it advances, since this
    // is the only place text disappears from `output` without ever being colon-scanned.
    let mut bracket_before_base = false;
    loop {
        let host_boundary = host_boundary_scheme_aware(&region[window_start..]);
        let boundary_abs = window_start + host_boundary;
        let window = &region[window_start..boundary_abs];
        if let Some(at) = window.rfind('@').filter(|&at| at != 0) {
            let at_abs = window_start + at;
            output.push_str(&redact_span_colon_credential(
                &region[base..window_start],
                bracket_before_base,
            ));
            output.push_str("***@");
            bracket_before_base |= region[base..=at_abs].contains('[');
            base = at_abs + 1;
            window_start = base;
            continue;
        }
        // Checked per-window rather than on the accumulated `region[base..boundary_abs]` span:
        // `:` never straddles a genuine `/`/`?`/`#` boundary (only IPv6-bracket/port shapes can
        // span the *start* of a window, and those still resolve correctly window-by-window — see
        // this function's own doc comment), so nothing is lost by not re-scanning the whole
        // streak from `base` on every iteration. Re-scanning a growing span here was an earlier
        // revision's O(n²) regression on a long run of colon-free, `@`-free windows (a bracket-
        // free host path with many segments) — `bounded_has_credential_colon` costs
        // `O(window.len())` and was being called on a span that grows by one window each
        // iteration, for `O(n²)` total.
        // `base` is only ever reassigned above, to `at_abs + 1` (always >= 1), so `base == 0`
        // here is equivalent to "no `@` has been masked yet" without a separate flag.
        let colon_evidence = base == 0 && bounded_has_credential_colon(window);
        if colon_evidence || (base == 0 && !has_nested_scheme) {
            let remaining = &region[base..];
            // No colon evidence and no nested scheme ahead: this is exactly round-6's original,
            // narrower widening — go straight to the unrestricted colon scan without ever trying
            // `find_credential_at`, so an ordinary no-colon host (`gitlab.corp`, `nexus.corp:8081`)
            // does not have a wholly unrelated trailing `@` (`pkg@1.0.0`) mistaken for a
            // credential just because nothing else was found.
            if colon_evidence && let Some(at) = find_credential_at(remaining) {
                output.push_str("***@");
                // #873: continue the very same bounded-`@` pass (`base`/`window_start`, `continue`)
                // instead of returning immediately — an earlier revision returned right here,
                // which is exactly what stopped this loop from ever reaching a later, colon-less
                // `TOKEN@host` credential via its own unconditional per-window `@` check above:
                // `colon_evidence` requires `base == 0` (see its own definition), so `remaining`
                // is `region` itself here and `at` is already an absolute offset into it.
                //
                // Deliberately does not update `bracket_before_base` (#886 review): this branch
                // only ever runs while `base == 0`, and `bracket_before_base` is only ever set
                // `true` at the mask-site branch above, together with advancing `base` away from
                // `0` — so it is still `false` here by construction, with nothing yet to widen
                // from. Once this branch fires, `base` never returns to `0`, so it can't fire
                // again either. A `[` inside the span it just replaced with `***@`
                // (`region[..at]`) has no bearing on anything scanned afterward: unlike the
                // mask-site's `redact_span_colon_credential` call, this branch's masking comes
                // from `find_credential_at`'s `@`-shape check, not from a colon-boundary scan, so
                // there is no colon-scan state here for an earlier bracket to widen — any further
                // credential past `at` is still found on its own merits by whichever of this
                // loop's own branches (or `redact_further_credential`'s fallback) reaches it next.
                base = at + 1;
                window_start = base;
                continue;
            }
            // #887: neither this window's own `@` check (line ~1389) nor `find_credential_at`
            // above ever reaches a colon-less `TOKEN@host` credential sitting in a *later*
            // window once this arm widens to the unrestricted colon scan below — that scan only
            // recognizes a `:`-separated credential, so `redact_colon_credential` alone returns
            // `remaining` verbatim when there is no colon anywhere in it at all (its own no-colon
            // branch), silently skipping past a username-only credential like `ghp_TOKEN@evil`.
            // Checked here, terminally (mask-and-`return`, never fed back into the bounded-`@`
            // loop via `continue`): looping back in would set `base != 0`, which permanently
            // disables `colon_evidence` (hard-gated to `base == 0`) and makes a later window's own
            // `@` branch emit an unexamined `region[base..window_start]` span verbatim — that span
            // can itself contain a colon-separated credential this function would otherwise have
            // masked (reproduced live: `h/ghp_X@a/oauth2:SECRET/b@c` regresses to leaking `SECRET`
            // under a mask-and-`continue` variant). Accepted trade-off, consistent with this
            // module's over-redaction-over-leaking design rule: `TOKEN_PREFIXES` entries like
            // `sk-`/`npm_`/`pypi-` can shape-collide with an ordinary package name segment
            // (`docs.rs/sk-lang@1.2.3` read as schemeless/malformed text), over-redacting a
            // version-shaped `@` that was never a credential — but only for schemeless/malformed
            // input reaching this fallback at all, since a well-formed `https://` URL parses and
            // never enters `redact_authority_suffix` in the first place. The trade also runs the
            // other way on a small population: returning here instead of falling into
            // `redact_colon_credential` can narrow what its own `bracket_seen` stickiness would
            // have masked through to end-of-string, occasionally *revealing* a glued, credential-
            // shaped-but-non-matching span past the terminal `@` (e.g. an `AKIA`-prefixed segment
            // stuck directly onto a host with no `/`/`?`/`#`/`\` boundary before it, so
            // `find_token_prefix_at`'s own segment-start rule does not recognize it) — never a
            // regression on a credential this module actually detects (see the differential
            // audit backing this fix), just a smaller sliver of incidental text than the old,
            // stickier over-redaction happened to hide.
            if let Some(at) = find_token_prefix_at(remaining) {
                let at = extend_credential_at(remaining, at);
                output.push_str("***@");
                let tail = &remaining[at + 1..];
                output.push_str(&redact_further_credential(tail, tail.find('[')));
                return output;
            }
            output.push_str(&redact_colon_credential(remaining, 0, remaining));
            return output;
        }
        if boundary_abs < region.len() {
            window_start = boundary_abs + 1;
            continue;
        }
        // #870: this used to append `&region[base..]` unchanged once any `@` had been masked
        // earlier (`colon_evidence` above is hard-gated to `base == 0` by design), so a
        // colon-only credential past that point was never checked at all — see
        // `redact_further_credential`'s own doc comment. No pre-known bracket offset is available
        // here (unlike `redact_colon_credential`'s call site), so it's derived once, fresh.
        //
        // Deliberately not seeded from `bracket_before_base` (#886 review): a `[` in a segment
        // `region[..base]` already replaced by an earlier mask-site `***@` can only ever widen
        // how much trailing text a colon match that `redact_further_credential` (or the
        // `colon_credential_match` it drives) *already decided to mask* gets extended over —
        // never whether a credential is found in the first place, since every discovery path here
        // (the per-window `@` pass above, `find_credential_at`, `colon_credential_match` itself)
        // matches on shape alone. `remaining.find('[')` scoped to just this call's own span is
        // exactly the same fresh-derivation `redact_colon_credential`'s unseeded call site already
        // uses outside this function, so this stays consistent with that existing pattern rather
        // than being a special case.
        let remaining = &region[base..];
        output.push_str(&redact_further_credential(remaining, remaining.find('[')));
        return output;
    }
}

/// #869: `mask_at`'s tail — everything after the `@` it selects — is not proof there is no
/// *second*, independent credential later in the same string (e.g. `evil/tok:SECRET` after
/// `user:hunter2@`); scans `tail` for a colon-separated credential in isolation, reusing
/// [`redact_colon_credential`] with `authority_start == 0` so `tail` is both the `raw` and the
/// `authority` argument — the same self-contained call shape [`redact_credential`]'s own no-`@`
/// fallback already uses on `region` as a whole.
fn redact_secondary_colon_credential(tail: &str) -> String {
    redact_colon_credential(tail, 0, tail)
}

/// [`colon_credential_match`]'s scan for the case neither of the `@`-based fallbacks covers on
/// its own: a colon-separated credential with no `@` at all (#810), e.g. `oauth2:glpat-SECRET`, a
/// GitLab CI `gitlab-ci-token:JOBTOKEN` job token, or a bare `.npmrc` `//registry/:_authToken=...`
/// line. Unlike the `@` scan above, this is not restricted to the authority span before the first
/// `/`/`?`/`#` — `gitlab.corp/user:hunter2@evil` (repro from #810) has its credential colon
/// *after* a `/`, so the whole of `authority` (everything after the scheme, or all of `raw`
/// when there is none) is searched.
///
/// Not every colon is a credential separator, so several shapes are left unredacted, checked
/// in this order:
/// - a Windows drive letter (`C:\Users\x\.npmrc`, `c:/packages/feed`) — a single ASCII letter
///   followed by `:` and then `\` or `/`;
/// - a bracketed IPv6 literal (`[::1]`, closed or not — [`bracket_host_shape_end`]) found
///   anywhere ahead of the next colon is skipped as a unit first (#860, D1: this used to be
///   anchored to the very start of the current scan window, which is what let a bracket sitting
///   a few bytes in, e.g. `x/[::1]:glpat-SECRET`, be missed and its own internal `::` colon
///   mistaken for the credential separator instead); its own `]:port` separator, once reached,
///   is then just another colon subject to the very next rule rather than an unconditional
///   exemption — so `[::1]:8443` still strips away as a plain port, but `[::1]:glpat-SECRET` no
///   longer does;
/// - no colon found in the searched span at all;
/// - a `host:port` pair, where the value side (up to the next `/`, `?`, `#`, or end) is 1-5
///   ASCII digits;
/// - an empty value side (`token:`), mirroring the empty-userinfo no-op above.
///
/// A carve-out hit does not stop the scan: it *skips past* the exempted colon and keeps
/// looking, so a leading non-credential colon (a port, a drive-letter prefix, a bracketed
/// IPv6 literal) cannot mask a real credential later in the same value — `raw` is returned
/// unchanged only once the scan runs out of colons entirely. This matters because #810's own
/// repro (`gitlab.corp/user:hunter2@evil`) is exactly this shape with a `host:port` prefix
/// added (`gitlab.corp:8443/user:hunter2@evil`): stopping at the first exempted colon would
/// silently reopen the vulnerability the scan-width widening above was meant to close.
///
/// Only the *first non-exempt* colon is ever treated as the split point (`a:b:c` redacts to
/// `a:***`, not `a:b:***`), and an empty left side is still redacted (`:secret` becomes
/// `:***`) — for a `:` pair the credential is the value on the right, unlike `@` where it is
/// the component on the left. That first match is not assumed to be the *only* credential,
/// though (#862): a non-credential value can shape-collide with this scan's own carve-outs
/// (`notaport` in `host/x@y:notaport/c://user:hunter2@evil` is not port-like, so it is masked as
/// if it were the credential), so a real credential sitting past it must still be reachable.
/// This function only finds and masks the *first* match, though — it does not itself look past
/// its own match; [`redact_further_credential`] is what keeps scanning the returned tail for a
/// further credential of either shape (#874: an earlier revision had this function's caller,
/// [`redact_colon_credential`], check only for a further `@`-shaped credential via
/// [`find_credential_at`] directly, missing a further colon-only one).
///
/// This intentionally produces some false positives on non-credential colon pairs — a Maven
/// coordinate (`com.google.guava:guava` → `com.google.guava:***`), an npm alias spec
/// (`mvn:group:artifact:1.0` → `mvn:***`), an RFC 3339 timestamp (`2026-09-11T08:40:19Z` →
/// `2026-09-11T08:***`), a path segment that happens to contain a colon
/// (`https://[:::1]/v1/items:search` → `.../items:***`), or — since #860 closed the
/// bracket-adjacent collision this used to document as accepted — a malformed IPv6 port
/// (`[::1]:notaport` → `[::1]:***`) or a genuinely ambiguous bracket-adjacent value
/// (`[::1]:abc` → `[::1]:***`) — accepted because this function only ever feeds a `tracing`
/// line, a user-visible error message, or a redacted-URL type, never a value used for further
/// parsing or comparison, and over-redacting a non-credential is always the safer failure mode
/// than under-redacting a real one. One shape collision remains a documented limitation: a
/// ≤5-digit credential collides with the `host:port` carve-out (`oauth2:12345` stays
/// unredacted).
///
/// Translates a previously-known `needle` offset into "relative to `remaining`", a string that
/// begins `consumed` bytes past whatever base `known` was itself relative to — or, when `known`
/// has fallen *behind* `consumed` (the position it named has already been passed, either properly
/// handled as a bracket span or silently swallowed inside an ordinary masked value), re-derives it
/// fresh by scanning only `remaining` itself, never the longer string it came from. `None` stays
/// `None` unconditionally: it means "provably no `needle` anywhere in the string this offset is
/// tracked against", and every `remaining` any caller here ever passes is a suffix of that string,
/// so it can't have gained one.
///
/// The one caching rule every place in this module that carries a `[` or `:` offset across a
/// shrinking string uses, instead of independently-maintained copies of the same match arms
/// (impl-critic S1/S2's fix for `[`, then a DRY finding on its own near-duplicated call sites,
/// then #894, which needed the identical rule a second time for `:` and consolidated both into
/// this one generic helper rather than adding a second copy): [`translate_bracket`] (itself called
/// from [`colon_credential_match`]'s own loop twice — once per iteration relative to `remaining`,
/// once for the tail it returns — and from [`redact_further_credential`]'s `@`-branch) and both
/// [`colon_credential_match_seeded`]'s and [`segment_has_credential_colon`]'s own `next_colon`
/// tracking (#896), each of which calls this directly with `':'` since nothing outside their own
/// loop ever needs the colon offset. See those functions' own doc comments for why this pattern is
/// sound and what performance regression it fixes.
fn translate_offset(
    known: Option<usize>,
    consumed: usize,
    remaining: &str,
    needle: char,
) -> Option<usize> {
    match known {
        Some(o) if o >= consumed => Some(o - consumed),
        Some(_) => remaining.find(needle),
        None => None,
    }
}

/// [`translate_offset`] specialized for the nearest `[` — the offset threaded as `next_bracket`
/// across [`colon_credential_match_seeded`]'s own loop, [`segment_has_credential_colon`]'s own
/// loop (#896), and [`redact_further_credential`]'s `@`-branch. See `translate_offset`'s own doc
/// comment for the underlying translate-or-rescan rule and why it is sound.
fn translate_bracket(known: Option<usize>, consumed: usize, remaining: &str) -> Option<usize> {
    translate_offset(known, consumed, remaining, '[')
}

/// Returns `None` when the scan runs out of colons in `authority` (mirrors
/// [`redact_colon_credential`]'s own "no colon" no-op); on a match, returns the masked
/// `"{prefix}:***"` piece, the still-unexamined tail *after* the masked value, and that tail's own
/// next-bracket offset (see `next_bracket` below) so a caller looping over successive calls (only
/// [`redact_further_credential`] does) never has to re-derive it from scratch.
///
/// `next_bracket` is the offset of the nearest `[` in `authority`, relative to `authority`'s own
/// start — `Some` when the caller already knows it (typically from a previous call's own returned
/// next-bracket offset), `None` when there is provably no `[` anywhere in `authority` at all.
/// Passing it in instead of this function re-deriving it via its own `remaining.find('[')` on
/// every iteration (impl-critic S1, then S2 once a *single* `[` anywhere in a long value was found
/// to still cost `remaining.find('[')` on every repeated call to this function — see
/// [`redact_further_credential`]'s own doc comment) is what turns a long, colon-dense value with
/// one or more brackets back from `O(n²)` to amortized `O(n)`: `next_bracket`, being an offset
/// rather than a boolean, only needs a fresh scan on the rare iteration where the previously-known
/// bracket position falls *behind* the current `cursor` (i.e. it was actually consumed — either
/// properly skipped as an IPv6-host span, or silently swallowed inside an ordinary masked value),
/// and that rescan only ever covers `remaining` — not the original, much longer `authority` — so
/// its cost is charged to the region it discovers, not repeated on every colon match before it.
///
/// The colon scan itself is amortized the same way (#894): #893 fixed the quadratic scan for a
/// run of *consecutive* `[`, by threading `next_bracket` as above, but a pattern that alternates
/// a `[` with an intervening non-`[`/non-`:` byte never takes the bracket-run-skip arm at all, so
/// the loop's own `remaining.find(':')` — previously re-derived from scratch on every iteration
/// regardless of how far `cursor` advanced — stayed `O(n)` per iteration. `next_colon` is now
/// tracked and translated via [`translate_offset`] exactly like `next_bracket` is via
/// [`translate_bracket`], closing this sibling gap.
fn colon_credential_match(
    authority: &str,
    next_bracket: Option<usize>,
) -> Option<(String, &str, Option<usize>)> {
    colon_credential_match_seeded(authority, next_bracket, false)
}

/// [`colon_credential_match`], but with `bracket_seen`'s initial value taken from the caller
/// (`seed_bracket`) instead of always starting `false` — used by [`redact_span_colon_credential`]
/// so a `[` in text scanned by [`redact_authority_suffix`] before this span started (and
/// therefore never re-examined here) still puts the sticky bracket flag in the same state a
/// single call over the whole region would have reached (#886). Still threads `next_bracket` as
/// a bare `Option<usize>` offset rather than a whole-tail rescan, so seeding costs nothing extra
/// asymptotically.
// All indices come from `find` of ASCII tokens (`:`, `]`, `/`, `?`, `#`) or byte-level ASCII
// checks, so every slice bound is always a char boundary. `cursor` only ever advances (every
// branch below adds at least 1 to it before looping), so the scan is guaranteed to terminate.
#[allow(clippy::string_slice)]
fn colon_credential_match_seeded(
    authority: &str,
    next_bracket: Option<usize>,
    seed_bracket: bool,
) -> Option<(String, &str, Option<usize>)> {
    // `next_bracket` is a bare offset whose only contract is "relative to `authority`", enforced
    // by doc comments rather than the type system — a future call site passing an offset relative
    // to some *other* string would silently misjudge bracket carve-outs into an under-redaction
    // (a leak), not a panic, so this catches the mismatch immediately in debug builds instead.
    debug_assert!(
        next_bracket.is_none_or(|b| b < authority.len()),
        "next_bracket must be an offset into `authority` itself"
    );
    let mut cursor = 0;
    let mut next_bracket = next_bracket;
    // #894: seeded once here, up front, from the whole (uncursored) `authority` — mirrors how
    // `next_bracket` arrives already seeded by the caller — then threaded/translated the same way
    // on every iteration below instead of re-derived via `remaining.find(':')` each time.
    let mut next_colon = authority.find(':');
    // impl-critic R3: sticky for the rest of the scan once any bracket span has been skipped —
    // not reset per colon like an earlier revision's `bracket_adjacent`/`colon_is_bracket_adjacent`
    // pairing (C2), and not a proxy check on `value` itself (the `value.contains(']')`
    // generalization that same revision added). Both prior forms are narrower than the real
    // ambiguity: once a `[` has been seen anywhere in `authority`, every judgment this function
    // makes about where a "value" safely ends is suspect for the rest of the scan (a fuzz-found
    // counterexample, `[/::1/x]:abc/user:SECRET`, still leaked under the value-contains-`]`
    // check — the orphaned `]` had moved one path segment further away from the colon it was
    // meant to flag). A single sticky flag closes that whole family at once, at the cost of
    // over-redacting more of the tail once any bracket has appeared — the safe direction.
    let mut bracket_seen = seed_bracket;
    loop {
        let remaining = &authority[cursor..];

        // `colon_is_drive_letter(remaining, 1)` reduces exactly to a 3-byte
        // `bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] in {'/', '\\'}` test
        // when `colon == 1` (see that function's own doc comment) — this is the same check,
        // sharing the one drive-letter rule with `segment_has_credential_colon`.
        if colon_is_drive_letter(remaining, 1) {
            cursor += 2;
            continue;
        }

        // #894: same `translate_offset` rule as `next_bracket` below, applied to the nearest
        // `:` — see `translate_offset`'s own doc comment for why `next_bracket` and `next_colon`
        // are tracked independently rather than sharing one cached offset.
        let next_colon_here = translate_offset(next_colon, cursor, remaining, ':');
        next_colon = next_colon_here.map(|c| cursor + c);
        // See `translate_bracket`'s own doc comment for the translate-or-rescan rule. The result
        // is re-absolutized (relative to `authority` again, via `cursor +`) so `next_bracket`
        // stays consistent for the next loop iteration — a no-op when the cheap path was taken
        // (`cursor + (b - cursor) == b`), the freshly-found position when it wasn't.
        let bracket_here = translate_bracket(next_bracket, cursor, remaining);
        next_bracket = bracket_here.map(|b| cursor + b);
        if let Some(bracket) = bracket_here {
            // A bracket ahead of the next colon (#860, D1: not just one anchored at the very
            // start of `remaining`) opens an IPv6-host span that must be skipped as a unit
            // before any colon inside it — including its own `]:port` separator — can be
            // evaluated as a possible credential separator by the checks below.
            if next_colon_here.is_none_or(|colon| bracket < colon) {
                cursor += bracket_host_shape_end(remaining, bracket);
                // Deliberately unconditional, unlike `segment_has_credential_colon`'s own
                // `bracket_adjacent` flag (which requires a genuinely *closed* bracket before
                // granting its `is_port_like` exemption — a code review fix): `bracket_seen`
                // grants no exemption here, it only ever widens how much gets masked once a
                // redaction is already forced, so treating even an unclosed/stray `[` as reason
                // for extra caution is the safe direction, not a bug — R3's own counterexample
                // (`[/::1]:abc/user:SECRET`) is exactly an *unclosed* bracket, so requiring
                // closure here would silently reopen that leak.
                bracket_seen = true;
                continue;
            }
        }

        let colon = next_colon_here?;

        let value_start = colon + 1;
        let value_end = remaining[value_start..]
            .find(['/', '?', '#'])
            .map_or(remaining.len(), |i| value_start + i);
        let value = &remaining[value_start..value_end];

        if value.is_empty() || is_port_like(value) {
            cursor += value_end.max(colon + 1);
            continue;
        }

        // impl-critic C2/R3: a value redacted anywhere downstream of a bracket is shape-identical
        // to a real credential purely because of #860's own carve-out convergence, not because it
        // is actually known to *be* one — so the usual `/`/`?`/`#` value boundary cannot be
        // trusted to end the mask: `[::1]:abc/user:glpat-SECRET` must not stop masking at `abc`
        // and reveal the genuine `user:glpat-SECRET` credential sitting right after it in the
        // unredacted tail. Masking through to the end of `authority` once any bracket has been
        // seen is the safe direction — it can only ever over-redact, never leak.
        let end = if bracket_seen {
            remaining.len()
        } else {
            value_end
        };

        let consumed = cursor + end;
        let tail = &authority[consumed..];
        // Same `translate_bracket` rule, now relative to the *returned* tail instead of
        // `remaining` — this is what lets the caller's next call skip straight to the cheap
        // subtraction path too, rather than starting the whole cache over from `None`.
        let tail_bracket = translate_bracket(next_bracket, consumed, tail);

        return Some((
            format!("{}:***", &authority[..cursor + colon]),
            tail,
            tail_bracket,
        ));
    }
}

/// [`redact_userinfo_unparseable`]'s (and, since #818, [`redact_userinfo_opaque_path`]'s)
/// fallback for the case neither covers on its own: a colon-separated credential with no `@` at
/// all. See [`colon_credential_match`] for the actual scan (carve-outs, bracket handling); this
/// wrapper only adds `raw`/`authority_start` formatting and hands the tail past the match to
/// [`redact_further_credential`] for whatever else might still be in it (#874: this used to check
/// only for a further `@`-shaped credential via [`find_credential_at`] directly, missing a
/// further colon-only one — see that function's own doc comment).
fn redact_colon_credential(raw: &str, authority_start: usize, authority: &str) -> String {
    redact_colon_credential_seeded(raw, authority_start, authority, false)
}

/// [`redact_colon_credential`], but with `bracket_seen`'s initial value taken from the caller
/// instead of always starting `false` — see [`colon_credential_match_seeded`], which this
/// delegates to.
// `authority_start` is always caller-derived from `find`/`rfind` of ASCII tokens, so it always
// lands on a char boundary.
#[allow(clippy::string_slice)]
fn redact_colon_credential_seeded(
    raw: &str,
    authority_start: usize,
    authority: &str,
    seed_bracket: bool,
) -> String {
    match colon_credential_match_seeded(authority, authority.find('['), seed_bracket) {
        None => raw.to_string(),
        Some((masked, tail, tail_bracket)) => format!(
            "{}{}{}",
            &raw[..authority_start],
            masked,
            // `tail_bracket` was already computed by `colon_credential_match_seeded` above —
            // threaded through instead of discarded and re-derived via a second `tail.find('[')`
            // (a code-review finding: bounded, not asymptotic, but avoidable).
            redact_further_credential(tail, tail_bracket)
        ),
    }
}

/// Redacts a colon-separated credential anywhere in `span` (#886): the one remaining verbatim
/// `push_str` exit in [`redact_authority_suffix`] — the mask site's own pass-through streak
/// between two masked `@`-credentials — goes through this instead of being appended unexamined,
/// so a colon-only credential sitting in that streak (`oauth2:SECRET` in `a@b/oauth2:SECRET/c@d`)
/// is no longer emitted verbatim just because the `@`-based scan moved past it without ever
/// widening to the unrestricted colon fallback. `bracket_seen` seeds the sticky bracket-tracking
/// flag with whatever an `[` earlier in `region` — outside `span`, already consumed into a
/// `***@` mask — would have left it at, so a bracket several windows back still forces the same
/// mask-through-to-the-end caution [`colon_credential_match_seeded`]'s own doc comment describes,
/// even though this call never sees that earlier text again.
///
/// Returns [`Cow::Borrowed`] when `span` has no `:` at all, rather than always allocating: most
/// spans reaching this function (an ordinary host or path segment between two credentials) have
/// no colon, and the caller stitches many such spans together per input.
fn redact_span_colon_credential(span: &str, bracket_seen: bool) -> Cow<'_, str> {
    if !span.contains(':') {
        return Cow::Borrowed(span);
    }
    Cow::Owned(redact_colon_credential_seeded(span, 0, span, bracket_seen))
}

/// The one place every fallback in this module now asks "is there anything else, of *either*
/// shape, left in this tail" (#870/#873/#874): an `@`-shaped credential ([`find_credential_at`])
/// or a colon-only one ([`colon_credential_match`]), whichever comes first, masked and then looked
/// past again — instead of stopping after the first credential of whichever single shape a given
/// call site happened to check for.
///
/// Before this fix, three call sites each asked a narrower version of this question and each
/// missed the *other* shape past their own match:
/// - [`redact_authority_suffix`]'s colon-evidence widen path (`find_credential_at` hit) returned
///   immediately after masking one `@`-shaped credential, never checking whether a further
///   colon-only credential sat past it (#873).
/// - [`redact_authority_suffix`]'s loop-exhaustion path emitted whatever remained after the last
///   masked `@` completely unchecked once any `@` had been masked, since its own `colon_evidence`
///   gate is (by design — see that function's own doc comment) hard-gated to fire at most once
///   (#870).
/// - [`redact_colon_credential`]'s own tail re-scan called [`find_credential_at`] directly,
///   missing a further colon-only credential past its first match (#874).
///
/// This is also the first place `RegionKind::Authority`'s own fallback paths widen an `@`-shaped
/// match via [`extend_credential_at`] (previously wired only for `OpaquePath`'s `mask_at`) — but
/// only for a credential found *by this loop*, in a tail that already required falling through to
/// the unrestricted colon/`@` scan in the first place. It does not touch, and must never be
/// confused with, `redact_authority_suffix`'s *primary* bounded `@` pass (`window.rfind('@')`),
/// which impl-critic S2 still deliberately leaves unwidened — see
/// `test_redact_userinfo_unparseable_straddle_fallthrough_is_not_widened`'s own doc comment.
///
/// Implemented as a loop rather than mutual recursion between this scan and
/// [`colon_credential_match`]/[`find_credential_at`] (which is how each of the three call sites
/// used to check "is there one more, of the other shape") so that a value chaining many decoy or
/// real credentials stays bounded to `O(1)` stack depth, consistent with
/// [`redact_authority_suffix`]'s own loop for the same reason. Each iteration strictly shrinks
/// `remaining` (an `@`-shaped match always advances past its own `@`; a colon match always
/// consumes at least its own colon), so the loop is guaranteed to terminate.
///
/// impl-critic S1/S2: two per-iteration costs are hoisted/latched to keep the *total* work `O(n)`
/// (amortized) rather than `O(n²)` on a long, colon-dense, `@`-free-past-the-first-match value —
/// with or without a `[` anywhere in it — e.g. `"u:p@h/" + "a:b/".repeat(k) + "z"` (measured at
/// 21.3s for 1.6 MB before this fix) or the same shape with a single trailing `"[::1]"` (S2:
/// still 2.8s at 800 KB with only a whole-tail `bool` fix for S1, since one `[` anywhere still
/// cost a fresh `remaining.find('[')` on every one of the `k` calls below):
/// - `next_bracket` is the caller-supplied offset of the nearest `[` in `tail` (`Some`) or a proof
///   there is none (`None`) — never re-derived here via a fresh `tail.find('[')`, since every
///   caller already knows it as a side effect of finding `tail` itself (see
///   [`redact_colon_credential`], the only other caller, which threads through the exact offset
///   [`colon_credential_match`] already computed rather than discarding it). Every
///   [`colon_credential_match`] call this loop makes both consumes the tracked offset (translating
///   it for the tail it returns, via [`translate_bracket`]) and hands back the translated value
///   for the *next* call, so no call after the first ever re-derives it from scratch; see that
///   function's own doc comment for why a stale offset only forces a rescan of `remaining` (never
///   the original, much longer `tail`), and only on the rare iteration where the tracked bracket
///   was actually just consumed.
/// - `find_credential_at` is only ever called until it first returns `None`, then `at_exhausted`
///   latches and every later iteration skips straight to the colon scan. This is sound not because
///   `segment_has_credential_colon` is monotone under left-truncation in general — it is *not*:
///   `segment_has_credential_colon("C:/x")` is `false` (drive-letter exemption) while its own
///   suffix `":/x"` is `true`, and the same applies to a cut landing inside a skipped bracket span
///   or between a `[` and its adjacent port colon (impl-critic M4) — but because every cut this
///   loop's `remaining` can ever undergo lands at a position [`colon_credential_match`] itself
///   guarantees is safe: its returned tail always begins at a `/`, `?`, or `#` byte (or is empty,
///   since `bracket_seen` forces `end = remaining.len()`), and neither the drive-letter exemption
///   (whose own third byte *is* one of `/`/`\`, but is never itself consumed by the 2-byte jump,
///   so it stays intact for whatever comes after) nor a closed bracket span (`bracket_host_shape_end`'s
///   own alphabet is hex digits, `:`, and `.` — never `/`, `?`, or `#`) can straddle across one of
///   those three bytes. So a cut point can never land mid-drive-colon, mid-bracket-span, or between
///   a `[` and its port colon — the one thing that would let a shorter segment gain evidence a
///   longer one didn't have. `extend_credential_at`'s own cut (`remaining[at + 1..]`, right after an
///   `@`) has no such guarantee in general, but only ever shrinks the segment for whichever `@` is
///   now first, which can only lose evidence, never gain it (an `@`-anchored cut can't land inside
///   a drive-colon/bracket shape, since none of those contain `@`). Either way, a `None` this
///   function's own `find_credential_at` call returns stays a `None` for every further shrink — a
///   future change to `value_end`'s boundary set (`/`, `?`, `#`) or to `bracket_host_shape_end`'s
///   alphabet that lets either span cross one of those three bytes would break this invariant and
///   must re-examine this latch, since silently getting it wrong here is an under-redaction (a
///   leak), not just a missed optimization.
#[allow(
    clippy::string_slice,
    reason = "`at` comes from `extend_credential_at`, itself derived from `match_indices('@')` \
              on an ASCII byte, so it always lands on a char boundary"
)]
fn redact_further_credential(tail: &str, next_bracket: Option<usize>) -> String {
    debug_assert!(
        next_bracket.is_none_or(|b| b < tail.len()),
        "next_bracket must be an offset into `tail` itself"
    );
    let mut next_bracket = next_bracket;
    let mut at_exhausted = false;
    let mut output = String::new();
    let mut remaining = tail;
    loop {
        // An `@`-shaped credential is checked first, matching every other call site in this file
        // (a colon-less credential can only be `@`-shaped, so this must run before concluding
        // there's nothing left just because the colon scan found nothing) — but only while it can
        // still find one; see this function's own doc comment for why `None` here is sticky.
        if !at_exhausted {
            match find_credential_at(remaining) {
                Some(at) => {
                    let at = extend_credential_at(remaining, at);
                    output.push_str("***@");
                    let consumed = at + 1;
                    let new_remaining = &remaining[consumed..];
                    next_bracket = translate_bracket(next_bracket, consumed, new_remaining);
                    remaining = new_remaining;
                    continue;
                }
                None => at_exhausted = true,
            }
        }
        match colon_credential_match(remaining, next_bracket) {
            Some((masked, next_tail, tail_bracket)) => {
                output.push_str(&masked);
                remaining = next_tail;
                next_bracket = tail_bracket;
            }
            None => {
                output.push_str(remaining);
                return output;
            }
        }
    }
}

/// [`redact_userinfo`]'s fallback for a `raw` that fails `Url::parse` outright (S1 finding), or
/// that parses but is a schemeless `user:pass@host` literal with no `://` at all (#536 C2) —
/// delegates to [`redact_credential`] with [`RegionKind::Authority`]. `authority_start` locates
/// the `://` scheme separator that actually bounds the credential-bearing authority: it scans
/// *forward*, from the start of `raw` up to the **first** `@` in `raw`, for the **first**
/// `://` in that span — not the first `://` anywhere in the whole string (#862), not the
/// *nearest* preceding one (#871), and not the last `@` either. The precise guarantee this
/// provides: `authority_start` never advances past the first `@` in `raw`. That is exactly what
/// both directions of #862 require —
/// - a later, unrelated `://` after the credential (e.g. `user:hunter2@evil://x`) can't push the
///   scan window past the credential (the original report — anchoring on the *first* `://`
///   anywhere in the whole string, as this used to, put the whole credential before the scan
///   window and it was never examined at all — restricting the search to `raw[..at]` is what
///   rules this out, independent of first-vs-nearest within that restricted span);
/// - a later, unrelated `@` anywhere after it — in the path/query (e.g.
///   `https://user:hunter2@registry.example/redirect?to=http://evil@x`), or appended directly
///   (e.g. `user:hunter2@evil://x@y`) — can't pull the window past the *real* credential's own
///   `@` either (anchoring on the *last* `@` instead of the first would reopen exactly this).
///
/// Picking the *first* `://` in `raw[..at]`, not the nearest one to `at` (#871), matters when
/// more than one genuine `scheme://` separator precedes the credential (`://://?ghp_TOKEN@`):
/// the nearest-preceding choice used to consume the string's *only* `://` still visible to
/// [`redact_authority_suffix`]'s own `has_nested_scheme` gate, since everything before it —
/// including any earlier `://` — fell outside `region` entirely; that starved the gate of the
/// evidence it needs to keep scanning past a `?`/`#`-truncated first window and leaked a
/// colon-less credential sitting right after it. Anchoring on the first occurrence instead keeps
/// every `://` from the second one onward inside `region`, so the gate sees exactly what is
/// still ahead.
///
/// This is **not** a strictly monotonic widening, despite `region` only ever growing: pulling
/// more prefix content into `region` also hands it to [`redact_authority_suffix`]'s own
/// early-decision machinery, which can occasionally resolve *differently* once it sees that
/// extra content, in a way that narrows what gets examined rather than only ever broadening it.
/// Two mechanisms found by adversarial differential testing against the nearest-preceding
/// baseline (23 new leaks in the corpus, versus 866 leaks the wider anchor fixes — a net
/// improvement, not a completeness guarantee):
/// - widening can turn an additional decoy `@` into a masked one, making `base` non-zero earlier
///   than before — which then permanently disables `redact_authority_suffix`'s own
///   `colon_evidence` fallback for the rest of the scan (deferred gap #870, "hard-gated on
///   `base == 0`"), silently reopening #870 on a value that used to reach the colon fallback
///   before that extra decoy was ever masked:
///   `redact_userinfo("https://registry.example:99999/http://mirror/a@b/oauth2:glpat-SECRET")`
///   redacts to `https://***@b/oauth2:glpat-SECRET` (`glpat-SECRET` leaks) where the
///   nearest-preceding anchor redacted to `.../a@b/oauth2:***`;
/// - the pulled-in prefix's own `://` supplies its colon as spurious `bounded_has_credential_colon`
///   evidence for `region`'s very first window, routing that window through
///   [`find_credential_at`]'s immediate-return match instead of [`redact_colon_credential`]'s
///   full-tail rescan:
///   `redact_userinfo("://://[::1]/a@b/oauth2:SECRET")` redacts to `://***@b/oauth2:SECRET`
///   (`SECRET` leaks) where the nearest-preceding anchor redacted to
///   `://://[::1]/a@b/oauth2:***` — this specific input was not leaking before the anchor
///   change; the underlying find-vs-rescan ordering is a pre-existing mechanism, but the widened
///   anchor is what exposes it on this shape.
///
/// Both counterexamples are pre-existing, deferred gaps (#870, and the `find_credential_at`-vs-
/// `redact_colon_credential` ordering underlying #873) reached via a different path, not new leak
/// classes this anchor change introduces on its own — and the wider anchor is kept because #871's
/// fix (866 leaks closed) dominates this trade on the adversarial corpus. Treat this as an honest
/// net-positive trade, not a proof that widening `region` can only ever help.
///
/// An `@` that precedes the real credential and is itself credential-shaped (e.g.
/// `a@b://user:hunter2@evil`, or with any number of slashes after the `:`) does not misdirect
/// this anchor either: [`redact_authority_suffix`]'s own boundary scan
/// ([`host_boundary_scheme_aware`]) does not treat a nested scheme separator's slashes as a path
/// terminator, so its bounded `@` pass correctly skips past `a@b://` to find `hunter2`'s `@`
/// instead of stopping short at `a`'s. [`scheme_separator_end`] (rather than a fixed `+ 3`)
/// consumes every slash in the separator actually matched, not just the two `find` itself found
/// — a third or later slash left dangling at `region`'s own start would otherwise look, to
/// [`host_boundary_scheme_aware`], like an ordinary leading path separator instead of more
/// scheme punctuation (impl-critic C1's second sub-shape).
///
/// When `raw` has no `@` at all, this falls back to scanning from the very start of `raw` for
/// the first `://` instead, since [`redact_colon_credential`] (which that branch ultimately
/// reaches) has no authority-vs-credential distinction to anchor against. See
/// [`redact_credential`]'s own doc comment for the full carve-out list and its per-`RegionKind`
/// coverage table.
// `authority_start` comes from `find('@')` followed by `find("://")` on ASCII bytes, so it
// always lands on a char boundary.
#[allow(clippy::string_slice)]
fn redact_userinfo_unparseable(raw: &str) -> String {
    let authority_start = match raw.find('@') {
        Some(at) => raw[..at]
            .find("://")
            .map_or(0, |scheme_end| scheme_separator_end(raw, scheme_end)),
        None => raw
            .find("://")
            .map_or(0, |scheme_end| scheme_separator_end(raw, scheme_end)),
    };
    redact_credential(raw, authority_start, RegionKind::Authority)
}

/// Byte offset in `text` just past the `://` scheme separator whose `:` sits at `colon` — but,
/// unlike a fixed `colon + 3`, consuming *every* consecutive `/` that follows it, not just the
/// two `"://"` itself matched (#862, impl-critic C1's second sub-shape). A scheme separator can
/// have any number of slashes (`host_boundary_scheme_aware`'s own boundary rule already treats a
/// whole such run as one unit), so a third or later slash is still part of the separator, not the
/// authority that follows: `redact_userinfo_unparseable`'s anchor landing one slash short of the
/// true authority start (`region` beginning with a leftover `/`) is indistinguishable, to
/// [`host_boundary_scheme_aware`], from a *genuine* leading path separator — it has no visibility
/// into what preceded `region`, so a leftover `/` at `region`'s own start (`i == 0`) reads as an
/// immediate boundary rather than more scheme punctuation, defeating the very continuation
/// [`redact_authority_suffix`] needs to reach a credential just past it.
fn scheme_separator_end(text: &str, colon: usize) -> usize {
    let bytes = text.as_bytes();
    let mut i = colon + 1;
    while bytes.get(i) == Some(&b'/') {
        i += 1;
    }
    i
}

/// [`redact_userinfo`]'s fallback for a *parseable* `raw` whose scheme has an empty authority
/// (`host() == None`) because it uses some `scheme:/path` form rather than `scheme://host`
/// (#811) — delegates to [`redact_credential`] with [`RegionKind::OpaquePath`]. `path_start`
/// (right after the scheme's first `:`) is found textually via `raw.find(':')` rather than
/// derived from `url.scheme().len()`, since `Url::parse` strips leading whitespace/C0-control
/// bytes before computing the scheme — a length-based offset would misalign against `raw` for
/// such an input, even though `raw`'s own first `:` still always marks the scheme separator (M2
/// finding). See [`redact_credential`]'s own doc comment for the full carve-out list and its
/// per-`RegionKind` coverage table.
// `path_start` comes from `find(':')` on an ASCII byte, so it always lands on a char boundary.
fn redact_userinfo_opaque_path(raw: &str) -> String {
    let path_start = raw.find(':').map_or(0, |scheme_end| scheme_end + 1);
    redact_credential(raw, path_start, RegionKind::OpaquePath)
}

/// Strips the query string, fragment, and any userinfo from `raw`, for attaching to a
/// `tracing` span field or log line at an outbound-request chokepoint.
///
/// Unlike [`redact_userinfo`] (which preserves the query string), this additionally drops
/// the query string and fragment outright: a chokepoint like
/// `HttpCache::get_cached_with_headers_via` or
/// [`crate::github::GithubTagsClient::fetch_authenticated`] serves every ecosystem's outbound
/// requests, including a custom-registry URL built from an `.npmrc`-style `${VAR}`
/// expansion (see `deps-npm`'s `NpmRegistryIndex` security model) — a token embedded in a
/// query parameter (`?token=...`) is exactly as sensitive as one embedded in userinfo, and
/// this chokepoint cannot assume any particular query-param naming convention is safe to
/// keep.
///
/// A `raw` that fails to parse as a URL is not returned unredacted outright: this still
/// applies [`redact_userinfo`]'s own textual fallback (redacting a `user:pass@`-shaped span,
/// or failing that a colon-separated `key:value` credential with no `@` — #810) and still
/// truncates at the first `?`/`#` character found anywhere in the string, the same as for a
/// parseable URL. There is no placeholder substitution, though — an unparseable string with
/// no redactable userinfo/credential shape and no `?`/`#` is returned unchanged, since nothing
/// in it looks like a component to strip. The outbound-request URLs this guards (built from
/// `https://...` values, always with a scheme) are not expected to hit that residual case in
/// practice.
///
/// #866's truncate-before-redact ordering (below) is monotonically safer specifically for the
/// query/fragment-credential-leak class it targets — it can never leak *more* of a query string
/// than the old redact-then-truncate order did — but is not strictly monotonic output-for-output
/// against arbitrary hand-constructed input: e.g. `c:/glpat-SECRET?u=user:pw@a&token=OTHER` used
/// to redact to `c:***@a&token=OTHER` (leaking the whole query, while incidentally hiding the
/// bare, non-credential-shaped `glpat-SECRET` path segment — the pre-existing #858/S4 gap, not
/// something this function ever redacted on its own) and now redacts to `c:/glpat-SECRET`
/// (correctly drops the query, but shows the path). The new output leaks strictly less — the
/// query is this function's one hard guarantee — just not byte-for-byte "a superset of what was
/// masked before" in every case (review M2).
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::url_for_tracing;
///
/// assert_eq!(
///     url_for_tracing("https://npm.internal/pkg?token=super-secret-value"),
///     "https://npm.internal/pkg"
/// );
/// assert_eq!(
///     url_for_tracing("https://user:hunter2@registry.example/simple?token=x"),
///     "https://***@registry.example/simple"
/// );
/// ```
#[must_use]
#[allow(
    clippy::string_slice,
    reason = "`end` comes from `find` of ASCII '?'/'#' bytes on the raw input string, so it \
              always lands on a valid char boundary"
)]
pub fn url_for_tracing(raw: &str) -> String {
    // #866: truncate the *raw* string at the first `?`/`#` before redacting, not after — a
    // credential-shaped `@` inside the query/fragment (e.g. `?u=user:pw@a&token=SECRET`) would
    // otherwise get widened over by `extend_credential_at` during redaction and consume the
    // real `?`/`#` boundary before this function ever gets to truncate on it, leaking the rest
    // of the query string.
    let end = raw.find(['?', '#']).unwrap_or(raw.len());
    redact_userinfo(&raw[..end])
}

/// A URL-bearing value that has already been redacted for safe inclusion in error or log
/// output — the structural chokepoint for outbound-URL redaction (issue #789).
///
/// Eagerly redacted at construction: [`Self::new`] applies [`url_for_tracing`]'s rules
/// immediately and retains only the resulting text, so the raw value passed in is never
/// stored, not even transiently. The only public read surface — [`Display`](std::fmt::Display),
/// [`AsRef<str>`], and a [`Debug`](std::fmt::Debug) impl that forwards to the redacted text —
/// is therefore always safe to log: there is no `expose_url()`-style escape hatch, because
/// nothing raw remains to expose. A caller that legitimately needs the raw URL (e.g. to
/// actually issue the HTTP request) keeps working with its own `String`/`reqwest::Url`,
/// entirely independent of any `RedactedUrl` built from the same source for error/log
/// purposes.
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::RedactedUrl;
///
/// let redacted = RedactedUrl::new("https://npm.internal/pkg?token=super-secret-value");
/// assert_eq!(redacted.to_string(), "https://npm.internal/pkg");
///
/// let redacted = RedactedUrl::new("https://user:hunter2@registry.example/simple");
/// assert_eq!(redacted.to_string(), "https://***@registry.example/simple");
/// ```
///
/// `PartialEq`/`Eq`/`Hash` compare the *redacted* text, not the original input: two distinct
/// URLs differing only by a stripped component (query string, fragment, or userinfo) compare
/// equal here even though they were different requests — e.g. `?token=a` and `?token=b`
/// against the same path both redact to the same value. This is intentional for this type's
/// own purpose (deduplicating/comparing error variants in tests, `deps_core::error`'s own
/// `assert_eq!` usage), but makes `RedactedUrl` unsuitable as a cache key or any other context
/// that needs to distinguish the underlying raw URLs — use the raw `String`/`reqwest::Url`
/// value for that instead.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RedactedUrl(String);

impl RedactedUrl {
    /// Redacts `raw` immediately via [`url_for_tracing`], retaining only the resulting text.
    #[must_use]
    pub fn new(raw: &str) -> Self {
        Self(url_for_tracing(raw))
    }
}

impl From<&str> for RedactedUrl {
    fn from(raw: &str) -> Self {
        Self::new(raw)
    }
}

impl From<String> for RedactedUrl {
    fn from(raw: String) -> Self {
        Self::new(&raw)
    }
}

impl std::fmt::Display for RedactedUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for RedactedUrl {
    /// Forwards to the redacted text's own `Debug` (a quoted string), not a struct-wrapper
    /// rendering — so a `RedactedUrl` embedded in a hand-written `Debug` impl (see
    /// `deps_core::error::DepsError`) reads identically to the plain `String` field it
    /// replaces.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl AsRef<str> for RedactedUrl {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

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
/// use deps_core::net_policy::{PolicyGate, validate_index_url};
///
/// let url = validate_index_url(
///     "https://index.mycorp.dev",
///     "https://index.mycorp.dev",
///     "cargo",
///     PolicyGate::Skip,
/// )
/// .unwrap();
/// assert_eq!(url.as_str(), "https://index.mycorp.dev/");
///
/// assert!(
///     validate_index_url("http://example.com", "http://example.com", "cargo", PolicyGate::Skip)
///         .is_err()
/// );
/// ```
pub fn validate_index_url(
    candidate: &str,
    raw_for_log: &str,
    ecosystem: &'static str,
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
                ecosystem,
                "workspace-declared registry index host blocked by registries.workspace_registries policy"
            );
            return Err(IndexUrlError::BlockedHost { class });
        }
    }
    Ok(url)
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
            "cargo",
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
                "cargo",
                PolicyGate::Skip
            )
            .is_ok()
        );
        assert_matches!(
            validate_index_url(
                "https://169.254.169.254/",
                "https://169.254.169.254/",
                "cargo",
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
            let result = validate_index_url(raw, raw, "cargo", PolicyGate::Enforce(&policy));
            assert_matches!(result, Err(IndexUrlError::BlockedHost { .. }));
        });
        assert!(!log.contains("super-secret-value"), "log: {log}");
    }

    /// FR-003: `RedactedUrl::new` must match `url_for_tracing`'s output byte-for-byte for
    /// every input this module's own regression suite already pins.
    #[test]
    fn test_redacted_url_matches_url_for_tracing_byte_for_byte() {
        let inputs = [
            "https://npm.internal/pkg?token=super-secret-value",
            "https://user:hunter2@registry.example/simple?token=x",
            "https://registry.example/simple",
            "not-a-url-at-all",
            "@types/node",
            "c:/user:hunter2@evil",
            "c:///user:hunter2@evil",
        ];
        for raw in inputs {
            assert_eq!(RedactedUrl::new(raw).to_string(), url_for_tracing(raw));
        }
    }

    /// NFR-004: the only public read surface (`Display`/`AsRef<str>`) returns redacted text
    /// only, for a known-sensitive input — there is no accessor that could return `raw`.
    #[test]
    fn test_redacted_url_display_and_as_ref_never_expose_raw_credential() {
        let raw = "https://user:hunter2@registry.example/simple?token=super-secret-value";
        let redacted = RedactedUrl::new(raw);
        assert!(!redacted.to_string().contains("hunter2"));
        assert!(!redacted.to_string().contains("super-secret-value"));
        assert!(!redacted.as_ref().contains("hunter2"));
        assert!(!redacted.as_ref().contains("super-secret-value"));
        assert_eq!(redacted.to_string(), "https://***@registry.example/simple");
    }

    /// `Debug` forwards to the redacted text's own quoted-string rendering, not a
    /// struct-wrapper form, and must never expose the raw credential either.
    #[test]
    fn test_redacted_url_debug_forwards_to_inner_string_and_redacts() {
        let redacted = RedactedUrl::new("https://user:hunter2@registry.example/simple");
        assert_eq!(
            format!("{redacted:?}"),
            "\"https://***@registry.example/simple\""
        );
    }

    /// The scoped-package-name no-op (#767 M1) must hold through `RedactedUrl` too.
    #[test]
    fn test_redacted_url_noop_for_scoped_package_name() {
        assert_eq!(RedactedUrl::new("@types/node").to_string(), "@types/node");
    }

    #[test]
    fn test_redact_userinfo_noop_cases() {
        assert_eq!(
            redact_userinfo("https://registry.example/simple"),
            "https://registry.example/simple"
        );
        assert_eq!(redact_userinfo("not-a-valid-url"), "not-a-valid-url");
    }

    #[test]
    fn test_redact_userinfo_strips_username_and_password() {
        let redacted = redact_userinfo("https://user:hunter2@registry.example/simple");
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("user:"));
        assert_eq!(redacted, "https://***@registry.example/simple");
    }

    /// S1: an otherwise-userinfo-bearing URL that fails `Url::parse` for an unrelated reason
    /// (an invalid port here) must still be redacted — `redact_userinfo` cannot rely on
    /// `Url::parse` succeeding to find the userinfo component.
    #[test]
    fn test_redact_userinfo_redacts_unparseable_url_with_userinfo() {
        let redacted = redact_userinfo("https://user:hunter2@registry.example:99999/simple");
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("user:"));
        assert_eq!(redacted, "https://***@registry.example:99999/simple");
    }

    /// #536 C2: a schemeless literal (no `://` at all) fails `Url::parse` for lacking a
    /// scheme, not for any userinfo-related reason — the pre-fix fallback bailed out as soon
    /// as it found no `://`, letting the credential through unredacted.
    #[test]
    fn test_redact_userinfo_redacts_schemeless_userinfo() {
        let redacted = redact_userinfo("user:hunter2@registry.example/simple");
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("user:"));
        assert_eq!(redacted, "***@registry.example/simple");
    }

    #[test]
    fn test_redact_userinfo_unparseable_no_userinfo_is_noop() {
        assert_eq!(
            redact_userinfo("https://registry.example:99999/simple"),
            "https://registry.example:99999/simple"
        );
    }

    /// #810: a colon-separated credential with no `@` at all (an OAuth2 npm auth line, a
    /// GitLab CI job token, and the `gitlab.corp/user:hunter2@evil` repro whose credential
    /// colon sits after a `/`, past the authority-only `@` scan's reach) must be redacted —
    /// before this fix, all three passed through `url_for_tracing` byte-for-byte unchanged.
    /// `gitlab.corp/user:hunter2@evil` keeps this exact shape even after #862 (impl-critic C1):
    /// its `gitlab.corp` window has no nested `scheme://` anywhere ahead of it, so
    /// [`redact_authority_suffix`] widens straight to the unrestricted colon fallback here
    /// (round 6's original behavior) rather than continuing past the boundary — that
    /// continuation is reserved for windows with a real `://` still ahead (impl-critic S4:
    /// unconditional continuation reopened over-redaction of ordinary `host:port/pkg@version`
    /// paths with no scheme nesting at all).
    #[test]
    fn test_url_for_tracing_redacts_colon_credential_no_at_sign() {
        let cases = [
            ("oauth2:glpat-SECRET", "oauth2:***"),
            ("gitlab-ci-token:JOBTOKEN", "gitlab-ci-token:***"),
            ("gitlab.corp/user:hunter2@evil", "gitlab.corp/user:***"),
            (
                "//registry.npmjs.org/:_authToken=npm_SECRET",
                "//registry.npmjs.org/:***",
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(url_for_tracing(raw), expected, "raw={raw:?}");
        }
    }

    /// S1 (impl-critic): a leading non-credential colon (a `host:port` prefix here) must not
    /// mask a real credential later in the same value — the scan must resume after a
    /// carve-out hit instead of bailing out on the first one. This is #810's own
    /// `gitlab.corp/user:hunter2@evil` repro shape with a port prepended, so a regression here
    /// silently reopens #810 through exactly the sink that motivated the scan-width widening
    /// (`GitlabHost::parse` → `deps-lsp/src/server.rs:90` `window/showMessage`).
    #[test]
    fn test_url_for_tracing_colon_credential_after_port_carve_out_is_still_redacted() {
        let cases = [
            (
                "gitlab.corp:8443/user:hunter2@evil",
                "gitlab.corp:8443/user:***",
            ),
            ("gitlab.corp:8443/user:hunter2", "gitlab.corp:8443/user:***"),
            (
                "//registry.npmjs.org:443/:_authToken=npm_SECRET",
                "//registry.npmjs.org:443/:***",
            ),
            ("[::1]:8443/user:hunter2", "[::1]:8443/user:***"),
        ];
        for (raw, expected) in cases {
            let redacted = url_for_tracing(raw);
            assert_eq!(redacted, expected, "raw={raw:?}");
            assert!(
                !redacted.contains("SECRET"),
                "raw={raw:?} redacted={redacted:?}"
            );
        }
    }

    /// S2 (impl-critic): the Windows drive-letter carve-out must exempt only the drive prefix
    /// itself (`C:\` / `c:/`), not the rest of the string — otherwise it is a 2-byte,
    /// attacker-controlled bypass prefix for any config scalar routed through this fallback.
    #[test]
    fn test_url_for_tracing_colon_credential_after_drive_letter_carve_out_is_still_redacted() {
        assert_eq!(url_for_tracing(r"C:\x:hunter2"), r"C:\x:***");
    }

    /// Documented limitation (impl-critic question, accepted as-is): a credential that happens
    /// to be 1-5 ASCII digits collides with the `host:port` carve-out. The sibling
    /// bracket-adjacent collision this test used to also document (`[::1]:glpat-SECRET` staying
    /// unredacted because a bracket-adjacent colon was never redacted regardless of what
    /// followed it) is fixed by #860 — see
    /// `test_redact_userinfo_bracket_adjacent_non_port_value_is_redacted` for its replacement
    /// coverage.
    #[test]
    fn test_url_for_tracing_colon_credential_documented_collisions() {
        assert_eq!(url_for_tracing("oauth2:12345"), "oauth2:12345");
    }

    /// #811's empty-authority `scheme:/path` fix (`redact_userinfo_opaque_path`), exercised
    /// through `url_for_tracing` rather than `redact_userinfo` directly: `c:/user:hunter2@evil`
    /// is redacted. `token:/hunter2:secret` (no `@` at all) used to be a distinct gap tracked in
    /// #818 — now fixed by routing the no-`@` case through [`redact_colon_credential`], the same
    /// scanner #810 already introduced for [`redact_userinfo_unparseable`]'s equivalent case.
    ///
    /// The empty-authority gap is narrow — only *non-special* schemes (anything other than
    /// `http`/`https`/`ws`/`wss`/`ftp`/`file`) hit it. A *special* scheme normalizes a single
    /// slash into an authority per the WHATWG URL spec, so the identical shape with `https:` is
    /// not a bypass at all: `https:/user:hunter2@evil` parses with a real, non-empty authority
    /// (`host="evil"`, `username="user"`, `password="hunter2"`) and is redacted correctly by
    /// the existing primary branch, same as any other URL with real userinfo.
    #[test]
    fn test_url_for_tracing_single_slash_scheme_path_redacted() {
        assert_eq!(url_for_tracing("c:/user:hunter2@evil"), "c:***@evil");
        let redacted = url_for_tracing("token:/hunter2:secret");
        assert!(!redacted.contains("secret"), "redacted={redacted:?}");
        assert_eq!(redacted, "token:/hunter2:***");
    }

    /// Contrast case for the #811 limitation above: a *special* scheme (`https`) does not
    /// share the gap — the WHATWG URL spec normalizes `scheme:/path` into a real authority for
    /// these schemes, so userinfo is still identified and redacted by the primary branch.
    #[test]
    fn test_url_for_tracing_special_scheme_single_slash_still_redacted() {
        assert_eq!(
            url_for_tracing("https:/user:hunter2@evil"),
            "https://***@evil/"
        );
    }

    /// #810 carve-outs: none of these colon-bearing values are credentials, so the
    /// colon-credential fallback must leave every one of them byte-for-byte unchanged. Note
    /// `[::1]:abc` is deliberately *not* in this list any more — #860 stopped exempting a
    /// bracket-adjacent colon unconditionally, so a non-numeric value there (indistinguishable
    /// in shape from a real credential like `glpat-SECRET`) is now redacted instead; see
    /// `test_redact_userinfo_bracket_adjacent_non_port_value_is_redacted`.
    #[test]
    fn test_url_for_tracing_colon_credential_false_positive_carve_outs() {
        let unchanged = [
            "gitlab.corp:8443",
            "gitlab.corp:8443/api",
            "git.corp:8443/*",
            "https://gitlab.corp:8443/api/v4",
            "https://host:99999/x",
            "[::1]:8443",
            "https://[::1]:8443/x",
            "https://[:::1]:8443/x",
            "c:/packages/feed",
            r"C:\Users\x\.npmrc",
            r"\\server\share\feed",
            "file:///Users/x/.npmrc",
            "@types/node",
            "1.2.3",
            "^1.2.3",
            "registry.example",
            "*.corp.example.com",
            "token:",
        ];
        for raw in unchanged {
            assert_eq!(url_for_tracing(raw), raw, "raw={raw:?}");
        }
    }

    /// #810 edge cases: an empty left side is still redacted (the credential is the value on
    /// the right for a `:` pair, unlike `@`), only the first colon in a multi-colon value ever
    /// splits, and a non-ASCII value is neither mangled nor causes a panic.
    #[test]
    fn test_url_for_tracing_colon_credential_edge_cases() {
        assert_eq!(url_for_tracing(":secret"), ":***");
        assert_eq!(url_for_tracing("a:b:c"), "a:***");

        let redacted = url_for_tracing("польз:секрет@хост");
        assert!(!redacted.contains("секрет"), "redacted={redacted:?}");
    }

    /// #810: a double-redaction regression — a URL with a real userinfo component next to an
    /// IPv6 host:port must still redact via the parseable-URL path (username/password), not
    /// get mangled a second time by the new colon-credential fallback.
    #[test]
    fn test_url_for_tracing_no_double_redaction_with_ipv6_port() {
        assert_eq!(
            url_for_tracing("https://user:pass@[::1]:8443/x"),
            "https://***@[::1]:8443/x"
        );
    }

    /// #810: a non-numeric port-like segment is not a `host:port` pair per the digit-only
    /// carve-out, so it falls through to the general colon-credential redaction.
    #[test]
    fn test_url_for_tracing_non_numeric_port_like_segment_redacted() {
        assert_eq!(url_for_tracing("https://host:abc/x"), "https://host:***/x");
    }

    /// Code-review follow-up on #767 (root-causing what `deps_core::error`'s `redact_if_url`
    /// had worked around locally): a scheme-less value that merely *starts* with `@` (an
    /// empty userinfo component) must not be mangled — there is no credential before the `@`
    /// to hide. An npm-scoped package name is the reproduced real-world example.
    #[test]
    fn test_redact_userinfo_leading_at_with_no_scheme_is_noop() {
        assert_eq!(redact_userinfo("@types/node"), "@types/node");
        assert_eq!(redact_userinfo("@angular/core"), "@angular/core");
    }

    /// Companion: a *non-empty* userinfo component before the same shape must still be
    /// redacted — this fix must not weaken the S1/#536 protection it sits next to.
    #[test]
    fn test_redact_userinfo_non_empty_userinfo_before_scoped_looking_path_still_redacted() {
        let redacted = redact_userinfo("user:hunter2@types/node");
        assert!(!redacted.contains("hunter2"));
        assert_eq!(redacted, "***@types/node");
    }

    /// #811: a non-special scheme's bare `scheme:/path` form (a single slash, no `://`
    /// authority marker) parses successfully with an empty authority — `username()`/
    /// `password()` never see a credential embedded in what the parser treats as an
    /// opaque-ish path, so the primary parseable-URL branch used to return this unchanged.
    #[test]
    fn test_redact_userinfo_redacts_single_slash_scheme_path_credential() {
        let redacted = redact_userinfo("c:/user:hunter2@evil");
        assert!(!redacted.contains("hunter2"));
        assert_eq!(redacted, "c:***@evil");
    }

    /// Companion case with a different non-special scheme, confirming the fix is not
    /// specific to a single scheme name.
    #[test]
    fn test_redact_userinfo_redacts_single_slash_scheme_path_credential_other_scheme() {
        let redacted = redact_userinfo("oauth2:/a:b@c/d");
        assert!(!redacted.contains("a:b"));
        assert_eq!(redacted, "oauth2:***@c/d");
    }

    /// Contrast case: a *special* scheme's `scheme:/path` form is normalized by the parser
    /// into a proper `scheme://host` authority (the WHATWG parser reserves this behavior for
    /// `http`/`https`/`file`/`ftp`/`ws`/`wss`), so it already redacts correctly through the
    /// pre-existing authority-bearing branch — this must keep working unchanged.
    #[test]
    fn test_redact_userinfo_normalizes_special_scheme_single_slash_to_authority() {
        let redacted = redact_userinfo("https:/user:hunter2@evil");
        assert!(!redacted.contains("hunter2"));
        assert_eq!(redacted, "https://***@evil/");
    }

    /// A `scheme://` value with an empty authority (e.g. a `file:` URL) parses to the exact
    /// same `host() == None` as the buggy shape, so it *is* scanned by the opaque-path
    /// fallback — but the `@`-preceding segment (`user`) is an ordinary path component, not
    /// userinfo-shaped (no `:`), so it stays a no-op.
    #[test]
    fn test_redact_userinfo_empty_authority_double_slash_form_is_noop() {
        assert_eq!(
            redact_userinfo("file:///home/user@example/file"),
            "file:///home/user@example/file"
        );
    }

    /// No `@` anywhere in the opaque path: nothing looks like a credential, so this stays a
    /// no-op just like the unparseable-fallback's own no-`@` case.
    #[test]
    fn test_redact_userinfo_single_slash_scheme_path_without_at_is_noop() {
        assert_eq!(redact_userinfo("c:/simple/path"), "c:/simple/path");
    }

    /// S1 (impl-critic finding on #811): the same empty-authority bypass reachable through an
    /// extra slash — `c:///user:hunter2@evil` parses to `host() == None` exactly like
    /// `c:/user:hunter2@evil`, so slash-counting after the scheme cannot be the redaction
    /// gate; only the scan-and-check-the-segment logic can tell this apart from a legitimate
    /// empty-authority path.
    #[test]
    fn test_redact_userinfo_redacts_triple_slash_scheme_path_credential() {
        let redacted = redact_userinfo("c:///user:hunter2@evil");
        assert!(!redacted.contains("hunter2"));
        assert_eq!(redacted, "c:***@evil");
    }

    /// Companion S1 case with a multi-character, `+`-containing scheme (a realistic
    /// `git+ssh`-style dependency-source scheme), confirming the fix isn't tied to
    /// single-letter schemes like `c`.
    #[test]
    fn test_redact_userinfo_redacts_triple_slash_scheme_path_credential_compound_scheme() {
        let redacted = redact_userinfo("git+ssh:///user:hunter2@evil");
        assert!(!redacted.contains("hunter2"));
        assert_eq!(redacted, "git+ssh:***@evil");
    }

    /// S2 (impl-critic finding on #811): a real `deps-nuget` local/UNC-feed-shaped path
    /// (`crates/deps-nuget/src/config.rs`'s `<add value="C:/...">` handling) containing an
    /// `@` in an ordinary directory name must not be mistaken for a credential — `john.doe`
    /// has no `:` before the `@`.
    #[test]
    fn test_redact_userinfo_single_slash_scheme_path_at_in_directory_name_is_noop() {
        assert_eq!(
            redact_userinfo("C:/Users/john.doe@corp/project"),
            "C:/Users/john.doe@corp/project"
        );
    }

    /// S2 companion: an npm-scoped package-with-version path (`@scope/pkg@1.0.0`) has two
    /// `@`s, neither preceded by a userinfo-shaped (`:`-containing) segment — must stay a
    /// no-op, preserving the #767 scoped-package protection through this new route too.
    #[test]
    fn test_redact_userinfo_single_slash_scheme_path_scoped_package_version_is_noop() {
        assert_eq!(
            redact_userinfo("npm:/@scope/pkg@1.0.0"),
            "npm:/@scope/pkg@1.0.0"
        );
    }

    /// S2 companion: a scoped package name with no version suffix, reached through this same
    /// opaque-path route (distinct from [`test_redact_userinfo_leading_at_with_no_scheme_is_noop`],
    /// which covers the schemeless case) — must also stay a no-op.
    #[test]
    fn test_redact_userinfo_single_slash_scheme_path_scoped_package_name_is_noop() {
        assert_eq!(
            redact_userinfo("c:/repo/@types/node"),
            "c:/repo/@types/node"
        );
    }

    /// S2 companion: an ordinary versioned filename (`file@v1.2.3`) must not be mistaken for
    /// a credential either.
    #[test]
    fn test_redact_userinfo_single_slash_scheme_path_versioned_filename_is_noop() {
        assert_eq!(
            redact_userinfo("c:/path/to/file@v1.2.3"),
            "c:/path/to/file@v1.2.3"
        );
    }

    /// M1 (impl-critic finding): an `@` with an empty segment before it (nothing since the
    /// previous `/`) has no `:` either, so it is never mistaken for a credential — this
    /// subsumes what an explicit `at == 0`-style guard would have covered.
    #[test]
    fn test_redact_userinfo_single_slash_scheme_path_bare_at_is_noop() {
        assert_eq!(redact_userinfo("c:/@only"), "c:/@only");
    }

    /// S3 (impl-critic finding, round 2): a trailing path segment with its own unrelated `@`
    /// (a scoped-package-with-version path following the credential) must not shadow the
    /// actual credential earlier in the string — only the last `@` whose *own* preceding
    /// segment is userinfo-shaped is the redaction point, not simply the last `@` overall.
    #[test]
    fn test_redact_userinfo_redacts_credential_followed_by_unrelated_at_segment() {
        let redacted = redact_userinfo("c:///user:hunter2@evil/@scope/pkg");
        assert!(!redacted.contains("hunter2"));
        assert_eq!(redacted, "c:***@evil/@scope/pkg");
    }

    /// S3 companion with a realistic private-registry-shaped host and a versioned trailing
    /// path segment.
    #[test]
    fn test_redact_userinfo_redacts_credential_followed_by_versioned_path_segment() {
        let redacted = redact_userinfo("nexus:/user:hunter2@host/repo/lib@2.0.0");
        assert!(!redacted.contains("hunter2"));
        assert_eq!(redacted, "nexus:***@host/repo/lib@2.0.0");
    }

    /// #818 (follow-up on #811, fixed by routing through [`redact_colon_credential`]): a bare
    /// colon-separated credential with no `@` at all — e.g. `token:/hunter2:secret` — is now
    /// caught by [`redact_userinfo_opaque_path`]'s no-`@` fallback, the same chokepoint
    /// [`redact_userinfo_unparseable`] already used for #810.
    #[test]
    fn test_redact_userinfo_single_slash_scheme_path_no_at_credential_is_redacted() {
        let redacted = redact_userinfo("token:/hunter2:secret");
        assert!(!redacted.contains("secret"), "redacted={redacted:?}");
        assert_eq!(redacted, "token:/hunter2:***");
    }

    /// #826 (fixed): a password containing `/` used to put the credential's `:` in an earlier
    /// path segment than the one immediately before `@`, so the old nearest-preceding-`/`
    /// segment check missed it. [`find_credential_at`] delimits segments by the previous `@`
    /// instead, so the whole span since the start of the path (or the previous `@`) is checked
    /// for a `:`, regardless of how many `/`s it contains.
    #[test]
    fn test_redact_userinfo_single_slash_scheme_path_password_with_slash_is_redacted() {
        let redacted = redact_userinfo("c:/user:pa/ss@evil");
        assert!(!redacted.contains("pa/ss"), "redacted={redacted:?}");
        assert_eq!(redacted, "c:***@evil");
    }

    /// #826 companion: the same password-contains-`/` fix through
    /// [`redact_userinfo_unparseable`] (a schemeless `user:pass@host` literal, no `scheme:/path`
    /// authority at all) — the sibling code path the issue named as sharing the same gap.
    #[test]
    fn test_redact_userinfo_unparseable_password_with_slash_is_redacted() {
        let redacted = redact_userinfo("user:pa/ss@evil");
        assert!(!redacted.contains("pa/ss"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@evil");
    }

    /// #826: a `?` inside a password used to truncate the authority-boundary scan before it
    /// ever reached the `@` that would trigger masking, leaking the fragment of the password
    /// before the `?` (partial leak). Covers both the scheme-bearing and schemeless shapes that
    /// route through [`redact_userinfo_unparseable`].
    #[test]
    fn test_redact_userinfo_unparseable_question_mark_in_password_is_redacted() {
        let redacted = redact_userinfo("https://user:pa?ss@evil");
        assert!(!redacted.contains("pa?ss"), "redacted={redacted:?}");
        assert_eq!(redacted, "https://***@evil");

        let redacted = redact_userinfo("user:pa?ss@evil");
        assert!(!redacted.contains("pa?ss"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@evil");
    }

    /// #826 companion: a `#` inside a password hits the exact same boundary-scan bug as `?` —
    /// both are treated identically by [`redact_userinfo_unparseable`]'s `host_boundary` scan.
    #[test]
    fn test_redact_userinfo_unparseable_hash_in_password_is_redacted() {
        assert_eq!(
            redact_userinfo("https://user:pa#ss@evil"),
            "https://***@evil"
        );
        assert_eq!(redact_userinfo("user:pa#ss@evil"), "***@evil");
    }

    /// #826: the equivalent `?`/`#`-in-password bug for [`redact_userinfo_opaque_path`] — the
    /// old `region.find(['?', '#'])` boundary had the same "cuts before reaching `@`" shape as
    /// [`redact_userinfo_unparseable`]'s `host_boundary`, just for a `scheme:/path` value
    /// instead of a `scheme://host` one.
    #[test]
    fn test_redact_userinfo_opaque_path_question_mark_and_hash_in_password_is_redacted() {
        assert_eq!(redact_userinfo("c:/user:pa?ss@evil"), "c:***@evil");
        assert_eq!(redact_userinfo("c:/user:pa#ss@evil"), "c:***@evil");
    }

    /// #810 regression guard: [`redact_userinfo_unparseable`]'s widened scan (triggered when the
    /// bounded authority already contains a `:`) must not fire when it does not — `gitlab.corp`
    /// before the first `/` has no `:`, so the unrelated `@evil` past it is left for
    /// [`redact_colon_credential`], unchanged from #810's own fix. A regression here would mean
    /// #826's widening silently broadened to redact a genuine host, not just a password.
    #[test]
    fn test_redact_userinfo_unparseable_widen_does_not_fire_without_leading_colon() {
        assert_eq!(
            url_for_tracing("gitlab.corp/user:hunter2@evil"),
            "gitlab.corp/user:***"
        );
    }

    /// impl-critic C1 (counterexample_hunt, regression on the #826 fix): a username-only
    /// userinfo with no password at all — the standard GitHub/GitLab CI token-auth URL shape —
    /// is still a real credential and must be redacted exactly like `user:pass@host`, even
    /// though it has no `:` at all. `find_credential_at`'s shape check must never run on the
    /// bounded authority pass; only `bounded.rfind('@')` (any `@` is a userinfo delimiter there)
    /// is correct.
    #[test]
    fn test_redact_userinfo_unparseable_username_only_userinfo_is_redacted() {
        assert_eq!(redact_userinfo("ghp_TOKEN@github.com"), "***@github.com");
        assert_eq!(
            redact_userinfo("x-access-token@github.com/repo.git"),
            "***@github.com/repo.git"
        );
        assert_eq!(
            redact_userinfo("https://ghp_TOKEN@github.com:99999/x"),
            "https://***@github.com:99999/x"
        );
        // Once the real credential is masked (`base != 0`), `redact_authority_suffix`'s loop
        // exhausts with no further `@` in `region[base..]` ("gitlab.corp:notaport/x") and now
        // (#870 fix) routes that remainder through `redact_further_credential` instead of
        // appending it verbatim — `notaport` is not port-like, so `colon_credential_match`'s own
        // pre-existing false-positive rule (documented on that function) masks it too. This is
        // over-redaction of ordinary path text, not a leak: this test's own purpose (the userinfo
        // `@` boundary is found correctly, and the real credential never leaks) is unaffected.
        let redacted = redact_userinfo("https://glpat-SECRET@gitlab.corp:notaport/x");
        assert!(!redacted.contains("glpat-SECRET"), "redacted={redacted:?}");
        assert_eq!(redacted, "https://***@gitlab.corp:***/x");
    }

    /// code-review Finding 1 (HIGH, confirmed leak): a bounded authority whose *only* `@` sits at
    /// position 0 (an npm-scope-shaped `@scope/...` prefix, empty userinfo) must not short-circuit
    /// to "no credential here" — a real credential can still exist past the `/`/`?`/`#` boundary.
    /// Before this fix, `bounded.rfind('@')` finding that leading `@` returned `raw` completely
    /// unredacted, leaking `user:hunter2` in full; the structurally near-identical
    /// `gitlab.corp/user:hunter2@evil` (no leading `@`) was already correctly redacted by the same
    /// function, which is what exposed the inconsistency.
    #[test]
    fn test_redact_userinfo_unparseable_leading_at_scope_does_not_hide_later_credential() {
        let redacted = redact_userinfo("@scope/user:hunter2@evil");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
    }

    /// code-review Finding 1 companion: the empty-userinfo no-op itself (no credential anywhere
    /// past the boundary) must still hold — this fix must not turn every leading `@` into a forced
    /// redaction.
    #[test]
    fn test_redact_userinfo_unparseable_leading_at_scope_with_no_later_credential_is_noop() {
        assert_eq!(redact_userinfo("@scope/pkg"), "@scope/pkg");
    }

    /// impl-critic S1 (counterexample_hunt, regression on the #826 fix): a literal `@` inside
    /// the password must not leak the tail of the value after it — the *last* `@` in the
    /// bounded authority is always the userinfo/host boundary (URL semantics), not the *last
    /// credential-shaped* `@`. Same root cause and fix as C1.
    #[test]
    fn test_redact_userinfo_unparseable_at_sign_inside_password_is_fully_redacted() {
        let redacted = redact_userinfo("user:pa@ss@evil");
        assert!(!redacted.contains("pa@ss"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@evil");

        // Same reasoning as the sibling test above: once `hunter2` is masked (`base != 0`), the
        // loop exhausts on `region[base..]` ("host:notaport/x") and (#870 fix) that remainder is
        // now routed through `redact_further_credential`, which masks the non-port-like
        // `notaport` too via `colon_credential_match`'s own pre-existing false-positive rule —
        // over-redaction of ordinary path text, not a leak. The `hunter2` assertion this test
        // actually exists to check is unaffected.
        let redacted = redact_userinfo("user:hunter2@evil@host:notaport/x");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@host:***/x");
    }

    /// #846 S4 (fixed by #858): `OpaquePath` has no authority span to license the
    /// `Authority`-only unconditional bounded `@` pass, so a username-only credential (no
    /// password) is not credential-shaped by [`find_credential_at`]'s own rules — but a
    /// token-prefixed one is now caught by [`find_token_prefix_at`], matching its `Authority`
    /// twin, pinned by `test_redact_userinfo_unparseable_username_only_userinfo_is_redacted`
    /// above.
    #[test]
    fn test_redact_userinfo_opaque_path_username_only_credential_is_redacted() {
        assert_eq!(redact_userinfo("c:/ghp_TOKEN@evil"), "c:***@evil");
    }

    /// #858 companion: a token-prefixed username-only credential is redacted regardless of which
    /// `OpaquePath`-eligible scheme precedes it.
    #[test]
    fn test_redact_userinfo_opaque_path_token_prefix_credential_is_redacted_nuget() {
        assert_eq!(
            redact_userinfo("nuget:///glpat-SECRET@feed.corp/v3"),
            "nuget:***@feed.corp/v3"
        );
    }

    /// #858 companion: same as above for a `file:///` scheme and a GitHub PAT prefix.
    #[test]
    fn test_redact_userinfo_opaque_path_token_prefix_credential_is_redacted_file() {
        assert_eq!(redact_userinfo("file:///ghp_TOKEN@evil"), "file:***@evil");
    }

    /// #858 required no-op pins: [`find_token_prefix_at`] must not fire on an unprefixed
    /// username, even one that superficially resembles a credential (an email-shaped path
    /// segment, a bare `@scope`) — these stay unredacted by design (see [`redact_credential`]'s
    /// own doc comment, C1).
    #[test]
    fn test_redact_userinfo_opaque_path_token_prefix_no_op_windows_path() {
        assert_eq!(
            redact_userinfo("file:///C:/Users/john.doe@corp/project"),
            "file:///C:/Users/john.doe@corp/project"
        );
    }

    #[test]
    fn test_redact_userinfo_opaque_path_token_prefix_no_op_bare_scope() {
        assert_eq!(redact_userinfo("c:///@scope/pkg"), "c:///@scope/pkg");
    }

    #[test]
    fn test_redact_userinfo_opaque_path_token_prefix_no_op_unprefixed_username() {
        assert_eq!(
            redact_userinfo("file:///home/user@example/file"),
            "file:///home/user@example/file"
        );
    }

    /// impl-critic F4.1: pins [`find_token_prefix_at`]'s `starts_with` (not `contains`) rule —
    /// the one property that keeps its false-positive population bounded. A leading `x` right
    /// before the token prefix, with no `/`/`?`/`#`/`\` boundary between them, must not match.
    #[test]
    fn test_redact_userinfo_opaque_path_token_prefix_requires_segment_start() {
        assert_eq!(redact_userinfo("c:/xghp_TOKEN@evil"), "c:/xghp_TOKEN@evil");
    }

    /// impl-critic F4.2: pins the `None` path — a token-prefixed value with no `@` at all is not
    /// a credential (nothing follows the username), previously untested.
    #[test]
    fn test_redact_userinfo_opaque_path_token_prefix_no_at_sign_is_noop() {
        assert_eq!(redact_userinfo("c:/ghp_TOKEN"), "c:/ghp_TOKEN");
    }

    /// impl-critic F4.3: pins [`find_token_prefix_at`]'s stated last-match-wins convention — two
    /// token-prefixed segments must resolve to the later, real credential/host boundary, not the
    /// first.
    #[test]
    fn test_redact_userinfo_opaque_path_token_prefix_last_match_wins() {
        assert_eq!(
            redact_userinfo("c:/ghp_AAA@evil/ghp_BBB@evil2"),
            "c:***@evil2"
        );
    }

    /// impl-critic F4.4/F6: pins the residual gap precisely — a token prefix not at a
    /// `/`/`?`/`#`/`\` segment start still leaks (`;` is a legitimate RFC 3986 path-parameter
    /// separator, not one of those boundary characters). This is *not* "unprefixed only"; see
    /// [`redact_credential`]'s own doc comment, C1, and [`find_token_prefix_at`]'s. Exists so a
    /// future boundary-set change is forced to notice and update this pin.
    #[test]
    fn test_redact_userinfo_opaque_path_token_prefix_not_at_segment_start_is_noop() {
        assert_eq!(
            redact_userinfo("c:/a;ghp_TOKEN@evil"),
            "c:/a;ghp_TOKEN@evil"
        );
    }

    /// #887: `redact_authority_suffix`'s widen branch (`base == 0 && !has_nested_scheme`) used to
    /// call `redact_colon_credential` directly, which returns its input verbatim when it finds no
    /// colon at all — so a colon-less `TOKEN@host` credential reachable only via this arm (an
    /// unparseable authority, e.g. an unclosed `[` that fails `Url::parse`) leaked in full. Fixed
    /// by trying [`find_token_prefix_at`] first, terminally (mask-and-`return`, matching this
    /// function's own doc comment for why it must never `continue` the bounded-`@` loop instead).
    #[test]
    fn test_redact_userinfo_authority_widen_branch_token_prefix_credential_is_redacted() {
        assert_eq!(
            redact_userinfo("https://[/ghp_TOKEN@evil"),
            "https://***@evil"
        );
        assert_eq!(redact_userinfo("c://[/ghp_TOKEN@evil"), "c://***@evil");
        assert_eq!(redact_userinfo("[/ghp_TOKEN@evil"), "***@evil");
    }

    /// #887 anti-naive-fix guard: the naive fix this issue explicitly warns against (masking the
    /// token-prefix credential and `continue`-ing the same bounded-`@` loop instead of returning)
    /// would leak `SECRET` here — reproduced separately during audit as `***@a/oauth2:SECRET/***@c`
    /// — because `continue`ing sets `base != 0`, which permanently disables `colon_evidence`
    /// (hard-gated to `base == 0`) and makes a later window's own `@` branch emit an unexamined
    /// span verbatim. The terminal mask-and-`return` this fix uses never reaches that state, so
    /// `SECRET` stays masked; the only behavior change from before this fix is that the
    /// `ghp_X`-prefixed credential earlier in the same string is now *also* masked (previously left
    /// fully visible, since the pre-fix widen branch only ever looked for a colon-based credential)
    /// — over-redaction of a second, genuine credential-shaped span, not a leak, and consistent
    /// with this module's over-redaction-over-leaking design rule.
    #[test]
    fn test_redact_userinfo_authority_widen_branch_anti_naive_continue_guard() {
        for raw in [
            "h/ghp_X@a/oauth2:SECRET/b@c",
            "h/ghp_X@[::1]:abc/oauth2:SECRET/b@c",
        ] {
            let redacted = redact_userinfo(raw);
            assert!(
                !redacted.contains("SECRET"),
                "raw={raw:?} redacted={redacted:?}"
            );
            assert!(
                !redacted.contains("ghp_X"),
                "raw={raw:?} redacted={redacted:?}"
            );
        }
        assert_eq!(redact_userinfo("h/ghp_X@a/oauth2:SECRET/b@c"), "***@***@c");
        assert_eq!(
            redact_userinfo("h/ghp_X@[::1]:abc/oauth2:SECRET/b@c"),
            "***@***@c"
        );
    }

    /// #887 bracket-sticky regression: a token-prefixed credential following an unclosed
    /// IPv6-bracket-shaped prefix must still be found and masked, and a further colon-only
    /// credential past it (`user:SECRET`) must stay masked too.
    #[test]
    fn test_redact_userinfo_authority_widen_branch_bracket_sticky_credential() {
        let redacted = redact_userinfo("[/::1/x]:abc/ghp_X@h/user:SECRET");
        assert!(!redacted.contains("SECRET"), "redacted={redacted:?}");
        assert!(!redacted.contains("ghp_X"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@h/user:***");
    }

    /// #887 narrowing direction (critic finding M3): the fix's terminal `return` can, on a small
    /// population, narrow what `redact_colon_credential`'s own `bracket_seen` stickiness would have
    /// masked through to end-of-string on `main` — occasionally revealing a glued, credential-
    /// shaped-but-non-matching span (here, an `AKIA`-prefixed segment with no boundary before it, so
    /// [`find_token_prefix_at`]'s segment-start rule does not recognize it as its own credential).
    /// Both real credentials in this input (`ghp_X`, `hunter2`) stay masked either way — this pins
    /// the exact, safe output rather than asserting the old, stickier over-redaction.
    #[test]
    fn test_redact_userinfo_authority_widen_branch_narrows_bracket_sticky_over_redaction() {
        let redacted = redact_userinfo("[/ghp_X@a/user:hunter2@evil/[::1]AKIAX@s3");
        assert!(!redacted.contains("ghp_X"), "redacted={redacted:?}");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@***@evil/[::1]AKIAX@s3");
    }

    /// #887 accepted over-redaction, asserted explicitly so it is a documented decision rather than
    /// an accident: [`TOKEN_PREFIXES`] entries like `sk-`/`npm_`/`pypi-` collide with ordinary
    /// package/mirror name segments, so a schemeless or otherwise-unparseable value whose path
    /// segment happens to start with one of them is over-redacted by the new widen-branch fallback
    /// even though nothing there is a real credential.
    #[test]
    fn test_redact_userinfo_authority_widen_branch_token_prefix_over_redaction_is_accepted() {
        assert_eq!(redact_userinfo("docs.rs/sk-lang@1.2.3"), "***@1.2.3");
        assert_eq!(redact_userinfo("unpkg.com/npm_thing@3"), "***@3");
        assert_eq!(redact_userinfo("host/pypi-mirror@2.0.0"), "***@2.0.0");
        assert_eq!(
            redact_userinfo("nexus.corp:8081/repo/sk-lib@2.0.0"),
            "***@2.0.0"
        );
        // A well-formed `https://` URL parses successfully and never reaches
        // `redact_authority_suffix`'s widen branch at all, so the over-redaction above is bounded
        // to schemeless/malformed input, not a risk for ordinary registry URLs.
        assert_eq!(
            redact_userinfo("https://docs.rs/sk-lang@1.2.3"),
            "https://docs.rs/sk-lang@1.2.3"
        );
    }

    /// #887 regression guards: none of these contain a [`TOKEN_PREFIXES`] match, so the new
    /// widen-branch fallback must never fire on them — byte-identical to pre-fix output. Most stay
    /// fully unredacted (no credential shape at all); `gitlab.corp/user:hunter2@evil` (#810) is the
    /// one genuine colon-credential in the set and must keep redacting exactly as before.
    #[test]
    fn test_redact_userinfo_authority_widen_branch_no_token_prefix_is_unaffected() {
        for raw in [
            "nexus.corp:8081/repo/lib@2.0.0",
            "[::1]:8443/pkg@1.0.0",
            "registry.example/@scope/pkg",
            "@types/node",
            "file:///C:/Users/x@corp/project",
        ] {
            assert_eq!(redact_userinfo(raw), raw, "raw={raw:?}");
        }
        assert_eq!(
            redact_userinfo("gitlab.corp/user:hunter2@evil"),
            "gitlab.corp/user:***"
        );
    }

    /// #846 S5 (fixed by #859): `OpaquePath` only had [`find_credential_at`]'s
    /// last-credential-shaped-`@`-wins, unlike `Authority`'s additional bounded
    /// last-`@`-*overall*-wins pass, so an `@` inside the password used to survive redaction —
    /// [`extend_credential_at`] closes the gap by widening the credential-shaped `@` forward
    /// across any further `@` not separated from it by a `/`, `?`, or `#`, matching its
    /// `Authority` twin (`***@evil`, pinned at
    /// `test_redact_userinfo_unparseable_at_sign_inside_password_is_fully_redacted` above).
    #[test]
    fn test_redact_userinfo_opaque_path_at_sign_inside_password_is_fully_redacted() {
        assert_eq!(redact_userinfo("c:/user:pa@ss@evil"), "c:***@evil");
    }

    /// #859 companion: a password containing more than one embedded `@` must still fully
    /// redact — each further `@` extends the match as long as no `/`, `?`, or `#` separates it
    /// from the previous one.
    #[test]
    fn test_redact_userinfo_opaque_path_multiple_at_signs_inside_password_is_fully_redacted() {
        assert_eq!(redact_userinfo("c:/user:pa@ss@wo@rd@evil"), "c:***@evil");
    }

    /// #859 companion: the extension must still stop at a `/`-separated trailing segment — an
    /// `@`-in-password credential immediately followed by #845's own `@scope/pkg` shape must
    /// redact the password in full without swallowing the unrelated scoped path.
    #[test]
    fn test_redact_userinfo_opaque_path_at_sign_inside_password_stops_at_slash_boundary() {
        assert_eq!(
            redact_userinfo("c:/user:pa@ss@evil/@scope/pkg"),
            "c:***@evil/@scope/pkg"
        );
    }

    /// impl-critic C1 (counterexample_hunt, regression on the #859 fix): `extend_credential_at`
    /// must also stop at `?`/`#`, not just `/` — a `/`-only stop set lets a query-shaped `@`
    /// past the credential get pulled into the masked span, swallowing the query string a
    /// direct [`redact_userinfo`] caller expects preserved. Since #866, `url_for_tracing` itself
    /// truncates at `?`/`#` before redacting at all, so it no longer depends on this boundary to
    /// avoid a leak here — this still asserts its end-to-end output stays correct regardless.
    #[test]
    fn test_redact_userinfo_opaque_path_at_sign_inside_password_stops_at_query_and_fragment_boundary()
     {
        let leaked =
            url_for_tracing("c:/user:pw@feed.corp?email=john@corp.com&token=glpat-SUPERSECRET");
        assert!(!leaked.contains("SUPERSECRET"), "leaked={leaked:?}");
        assert_eq!(leaked, "c:***@feed.corp");

        let leaked =
            url_for_tracing("c:/user:pw@feed.corp#email=john@corp.com&token=glpat-SUPERSECRET");
        assert!(!leaked.contains("SUPERSECRET"), "leaked={leaked:?}");
        assert_eq!(leaked, "c:***@feed.corp");
    }

    /// impl-critic S2 (assumption_audit): `Authority`'s own rare fall-through into
    /// [`redact_credential`]'s shared tail (the #826 straddle case — the bounded authority up to
    /// the first `/`/`?`/`#` has no `@` of its own, but does contain a credential-shaped `:`) must
    /// not additionally widen via [`extend_credential_at`], which is wired only for `OpaquePath`
    /// — that part is unchanged.
    ///
    /// #873 (fixed): the colon-evidenced match found via [`find_credential_at`] here used to
    /// `return` immediately, which is what let the second `@` (`host@corp`) sit past the point
    /// where the same unconditional bounded-`@` pass this loop uses for every other window would
    /// otherwise have found it. Now the match updates `base`/`window_start` and `continue`s the
    /// very same loop instead of returning — the same fix that closes #873's own colon-less-
    /// credential-behind-a-decoy repro — so `host` is masked too by that ordinary per-window
    /// check, not by [`extend_credential_at`]. Still no widening of the credential-shaped match
    /// itself, and `hunter2` still never leaks; `host` is over-redacted as ordinary path text, the
    /// safe direction this module always prefers.
    #[test]
    fn test_redact_userinfo_unparseable_straddle_fallthrough_is_not_widened() {
        assert_eq!(
            redact_userinfo("https://user:hunter2?x@host@corp"),
            "https://***@***@corp"
        );
    }

    /// #862: `redact_userinfo_unparseable` used to anchor its scan window at the *first* `://`
    /// anywhere in `raw`, so a credential preceding a later, unrelated `://` (an embedded
    /// nested-looking scheme) fell entirely before the scan window and leaked unredacted. The
    /// anchor now scans backward from the *first* `@` in `raw` for the nearest preceding `://`.
    #[test]
    fn test_redact_userinfo_unparseable_credential_before_later_unrelated_scheme_is_redacted() {
        assert_eq!(redact_userinfo("user:hunter2@evil://x"), "***@evil://x");
        assert_eq!(redact_userinfo("ghp_TOKEN@evil://x"), "***@evil://x");
        assert_eq!(redact_userinfo("a:user:hunter2@evil://x"), "***@evil://x");
        assert_eq!(redact_userinfo("://@evil"), "://@evil");
        assert_eq!(redact_userinfo("://"), "://");
        assert_eq!(redact_userinfo("@"), "@");
        assert_eq!(redact_userinfo(""), "");
        assert_eq!(redact_userinfo("üser:hünter2@évil://x"), "***@évil://x");
        assert_eq!(redact_userinfo("user:hunter2@evil"), "***@evil");
    }

    /// impl-critic C1/C2 on an earlier revision of the #862 fix that anchored on the *last* `@`
    /// in `raw` instead of the *first*: C1 was a brand-new leak where a real scheme + credential,
    /// followed by a later unrelated `://` past the first `/`/`?`/`#` (in a query value or a
    /// deeper path segment), pulled the scan window past the *real* credential; C2 was that #862
    /// itself stayed open whenever a further `@` was appended after the credential's own `://`.
    /// Anchoring on the *first* `@` instead closes both.
    #[test]
    fn test_redact_userinfo_unparseable_credential_before_and_after_unrelated_at_or_scheme() {
        assert_eq!(redact_userinfo("user:hunter2@evil://x@y"), "***@y");
        assert_eq!(
            redact_userinfo(
                "https://user:hunter2@registry.example:99999/redirect?to=http://evil@x"
            ),
            "https://***@registry.example:99999/redirect?***@x"
        );
        assert_eq!(
            redact_userinfo("https://user:hunter2@registry.example:99999/a/b://c@d"),
            "https://***@registry.example:99999/a/***@d"
        );
    }

    /// #862 (nested-scheme gap, closed by [`host_boundary_scheme_aware`]): an `@` that precedes
    /// the real credential and is itself credential-shaped no longer misdirects the anchor, even
    /// across multiple nested `scheme://`-look-alike spans and with no real scheme anywhere in
    /// `raw` at all.
    #[test]
    fn test_redact_userinfo_unparseable_leading_credential_shaped_at_before_nested_scheme_is_redacted()
     {
        assert_eq!(
            redact_userinfo("mailto:a@b://user:hunter2@evil"),
            "***@evil"
        );
        assert_eq!(redact_userinfo("a@b://c@d://user:hunter2@evil"), "***@evil");
        assert_eq!(
            redact_userinfo("mailto:a@b://user:hunter2@evil://x@y"),
            "***@y"
        );
        assert_eq!(redact_userinfo("a@b:///user:hunter2@evil"), "***@evil");
        assert_eq!(redact_userinfo("a@b:////user:hunter2@evil"), "***@evil");
    }

    /// #862: a genuine `/` path separator between a shallow, fake-looking `@` and a later,
    /// genuinely nested `scheme://` used to stop the bounded scan right at that `/`, leaving the
    /// real credential past the nested scheme untouched.
    #[test]
    fn test_redact_userinfo_unparseable_leading_at_before_genuine_path_separator_then_nested_scheme_is_redacted()
     {
        let redacted = redact_userinfo("a@b/c://user:hunter2@evil");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@b/***@evil");
    }

    /// #862: a well-anchored real `scheme://` is not a safe reason to stop scanning either — it
    /// anchors a *decorative* credential just as confidently as a genuine one.
    ///
    /// `notaport` here is now masked too (#886 fix): the mask site's pass-through streak between
    /// the `x@y` and `a@b` credentials is colon-scanned like any other span, and `notaport` is
    /// not port-like — the same accepted false-positive [`colon_credential_match`]'s own doc
    /// comment documents for a value like `[::1]:notaport`. This test's own purpose (`hunter2`
    /// never leaks) is unaffected.
    #[test]
    fn test_redact_userinfo_unparseable_well_anchored_scheme_is_not_a_safe_reason_to_stop_scanning()
    {
        let redacted = redact_userinfo("https://x@y:notaport/a@b/c://user:hunter2@evil");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
        assert_eq!(redacted, "https://***@y:***/***@b/***@evil");
    }

    /// #862 (`?`/`#` continuation gap): a genuine `?` (or `#`) boundary between a fake leading
    /// `@` and a nested `scheme://` used to hard-stop the continuation scan right there, leaking
    /// the real credential past it. The continuation now treats `?`/`#` the same as `/`.
    #[test]
    fn test_redact_userinfo_unparseable_leading_at_before_query_or_fragment_boundary_then_nested_scheme_is_redacted()
     {
        let redacted = redact_userinfo("a@b?c://user:hunter2@evil");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@b?***@evil");

        let redacted = redact_userinfo("a@b#c://user:hunter2@evil");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@b#***@evil");
    }

    /// #862 regression guard: further adversarial chains combining multiple fake `@`s, genuine
    /// `/` separators, and nested schemes at varying depths — none of these may ever leak
    /// `hunter2` again.
    #[test]
    fn test_redact_userinfo_unparseable_deeply_chained_fake_credentials_never_leak_the_real_one() {
        assert_eq!(
            redact_userinfo("a@b/c@d/e://user:hunter2@evil"),
            "***@b/***@d/***@evil"
        );
        assert_eq!(
            redact_userinfo("a@b/c/d/e://user:hunter2@evil"),
            "***@b/c/d/***@evil"
        );
        assert_eq!(
            redact_userinfo("a@b/c://user:hunter2@evil/d@e"),
            "***@b/***@evil/***@e"
        );
        assert_eq!(
            redact_userinfo("a@b/c://d@e/user:hunter2@evil"),
            "***@b/***@e/***@evil"
        );
    }

    /// #862 (impl-critic C2, the 60-shape leak family): a bounded prefix with **no** colon at all
    /// (an ordinary host, no port) used to route straight to [`redact_colon_credential`], whose
    /// first-match-wins scan latched onto a non-port-like decoy value (`notaport`) and returned
    /// before the real `user:hunter2` credential past a later `://` was ever examined. Fixed by
    /// having `redact_colon_credential` check its own masked value's tail for a further
    /// `@`-shaped credential rather than trusting the first hit alone.
    #[test]
    fn test_redact_userinfo_unparseable_decoy_colon_before_nested_scheme_does_not_hide_later_credential()
     {
        let cases = [
            "host/x@y:notaport/c://user:hunter2@evil",
            "host/d:e@f/c://user:hunter2@evil",
            "/x@y:notaport/c://user:hunter2@evil",
            "#d:e@f/c://user:hunter2@evil",
        ];
        for raw in cases {
            let redacted = redact_userinfo(raw);
            assert!(
                !redacted.contains("hunter2"),
                "raw={raw:?} redacted={redacted:?}"
            );
        }
    }

    /// #862 (impl-critic C1, round 7: the 923-shape username-only credential leak family): a
    /// decoy `@` with no colon at all — an ordinary npm/Go token shape (`pkg@1.0.0`, `@scope`,
    /// `repo@v1.2.3`) — used to pin `authority_start` at 0 and, once its own bounded window had
    /// neither an `@` nor colon evidence, route straight to `redact_colon_credential` on the
    /// whole string: a colon-less `TOKEN@host` credential (`ghp_`/`glpat`-shaped) sitting behind
    /// a nested `scheme://` was then unreachable by any of the three scanners (`redact_colon_credential`
    /// needs a `:`; `find_credential_at`'s own shape check also needs a `:`; only the unconditional
    /// bounded `@` pass finds it, and that pass never got a chance to look past the decoy).
    #[test]
    fn test_redact_userinfo_unparseable_username_only_credential_behind_decoy_at_sign_is_redacted()
    {
        let cases = [
            "npmjs.org/pkg@1.0.0/https://ghp_TOKEN@evil",
            "//registry.npmjs.org/@scope/-/x/https://glpat-TOKEN@evil",
            "github.com/owner/repo@v1.2.3/x://ghp_TOKEN@evil",
            "registry.corp/proxy@v2/https://ghp_TOKEN@evil",
            "host/d@e/c://ghp_TOKEN@evil",
            "/d@e://ghp_TOKEN@evil",
            "@/c://ghp_TOKEN@evil",
            "host/x@y:notaport/c://ghp_TOKEN@evil",
        ];
        for raw in cases {
            let redacted = redact_userinfo(raw);
            assert!(
                !redacted.contains("ghp_TOKEN") && !redacted.contains("glpat-TOKEN"),
                "raw={raw:?} redacted={redacted:?}"
            );
        }
        assert_eq!(
            redact_userinfo("host/d@e/c://ghp_TOKEN@evil"),
            "host/***@e/***@evil"
        );
    }

    /// #862 (impl-critic C1's second sub-shape): the backward anchor can land *inside* a
    /// multi-slash scheme separator when [`scheme_separator_end`] didn't consume every slash a
    /// `://` match was followed by, leaving `region` starting with a leftover `/` —
    /// indistinguishable, to [`host_boundary_scheme_aware`], from a genuine leading path
    /// separator (it has no visibility into what preceded `region`), which defeated the
    /// continuation the same way the first sub-shape did.
    #[test]
    fn test_redact_userinfo_unparseable_anchor_inside_multi_slash_scheme_separator_is_redacted() {
        let redacted = redact_userinfo("_://_hostv1:///ghp_TOKEN@h/");
        assert!(!redacted.contains("ghp_TOKEN"), "redacted={redacted:?}");
    }

    /// impl-critic S4 (round 7): the C1 fix's continuation must not reopen the over-redaction a
    /// prior round removed — an ordinary self-hosted registry `host:port/...` string with no
    /// nested scheme anywhere must stay fully visible, including a version-shaped trailing `@`
    /// (`pkg@1.0.0`) and a bracketed-IPv6 host with a well-formed port. The continuation past a
    /// colon-free, `@`-free window is gated on a genuine `://` still being present somewhere in
    /// `region` — none of these have one.
    #[test]
    fn test_redact_userinfo_unparseable_no_over_redaction_without_nested_scheme() {
        let cases = [
            "nexus.corp:8081/repo/lib@2.0.0",
            "registry.corp:4873/@scope/pkg",
            "localhost:8080/@types/node",
            "gitlab.corp:8443/repo/pkg@1.0.0",
            "[::1]:8443/pkg@1.0.0",
        ];
        for raw in cases {
            assert_eq!(redact_userinfo(raw), raw, "raw={raw:?}");
        }
    }

    /// #870 (fixed): `colon_evidence` in [`redact_authority_suffix`] is hard-gated on no `@`
    /// having been masked yet earlier in `region`, so once any `@` has been masked the colon
    /// fallback used to never run again, and a later colon-only credential (no `@` of its own) was
    /// emitted verbatim — `oauth2:glpat-SECRET` and `gitlab-ci-token:JOBTOKEN` are the two literal
    /// examples documented on [`redact_colon_credential`] itself (the #810 repro tokens). Fixed by
    /// routing the loop-exhaustion fallthrough through [`redact_further_credential`] instead of
    /// appending the unmasked remainder verbatim.
    #[test]
    fn test_redact_userinfo_unparseable_colon_only_credential_behind_decoy_at_is_redacted() {
        assert_eq!(
            redact_userinfo("npmjs.org/pkg@1.0.0/https://oauth2:glpat-SECRET"),
            "npmjs.org/***@1.0.0/https://oauth2:***"
        );
        assert_eq!(
            redact_userinfo("registry.corp/proxy@v2/https://gitlab-ci-token:JOBTOKEN"),
            "registry.corp/***@v2/https://gitlab-ci-token:***"
        );
    }

    /// #873 (fixed): [`redact_authority_suffix`]'s colon-evidenced widen branch used to `return`
    /// immediately after masking the `@`-shaped match [`find_credential_at`] found (`user1:pass1@`
    /// here), never continuing the loop far enough to reach a later, colon-less `TOKEN@host`
    /// credential (`ghp_TOKEN@evil2`) sitting behind an unrelated `/decoy/` path segment. Fixed by
    /// continuing the very same bounded-`@` pass (`base`/`window_start`, `continue`) instead of
    /// returning, so the ordinary per-window `@` check a few lines above catches it exactly as it
    /// would for any other window.
    #[test]
    fn test_redact_userinfo_unparseable_colon_less_credential_behind_colon_evidenced_decoy_is_redacted()
     {
        assert_eq!(
            redact_userinfo("host:x/user1:pass1@evil1/decoy/ghp_TOKEN@evil2"),
            "***@evil1/decoy/***@evil2"
        );
    }

    /// #874 (fixed): [`redact_colon_credential`]'s own tail re-scan used to check only for a
    /// further `@`-shaped credential via [`find_credential_at`] directly, so a *second* colon-only
    /// credential (`oauth2:glpat-SECRET`, no `@` at all) sitting past an already-masked decoy
    /// colon value (`notaport`) was never examined. Fixed by routing the tail through
    /// [`redact_further_credential`], which keeps scanning for a credential of either shape
    /// instead of just the one [`find_credential_at`] recognizes.
    #[test]
    fn test_redact_userinfo_unparseable_second_colon_only_credential_behind_decoy_colon_is_redacted()
     {
        assert_eq!(
            redact_userinfo("y:notaport/oauth2:glpat-SECRET"),
            "y:***/oauth2:***"
        );
    }

    /// #871 (impl-critic round 7, `assumption_audit`; fixed): `has_nested_scheme` in
    /// [`redact_authority_suffix`] used to be computed once over the whole `region`, not scoped
    /// to "a genuine `://` still ahead of the current window" as its own doc comment claimed —
    /// when the backward anchor in `redact_userinfo_unparseable` had already consumed the
    /// string's only `://` while computing `authority_start`, `region` had none left, the gate
    /// read `false`, and the continuation past a colon-free/`@`-free window was skipped even
    /// though a credential sat just past the next boundary. Fixed by anchoring on the *first*
    /// `://` preceding the credential's `@` instead of the nearest one, so `region` always
    /// retains every scheme separator after the first.
    #[test]
    fn test_redact_userinfo_unparseable_credential_past_anchor_consumed_scheme_is_redacted() {
        assert_eq!(redact_userinfo("://://?ghp_TOKEN@"), "://***@");
    }

    /// #875 (considered, reverted — see [`redact_authority_suffix`]'s own "Guarantees and known
    /// gaps" section): step 1 masks every window's own bare `@` unconditionally, so a multi-`@`
    /// value with no nested scheme anywhere over-redacts every `@` past the first, not just the
    /// first. A gate limiting this to `has_nested_scheme`/colon-evidenced windows was tried and
    /// reverted after adversarial testing found it converts this over-redaction into a real
    /// credential leak for a colon-less `TOKEN@host` credential in the exact same shape as the
    /// decoy it was meant to spare (see the companion test below) — pinning the still-over-redacts
    /// behavior here so a future attempt at this gate has to notice it regressed this case too.
    #[test]
    fn test_redact_userinfo_unparseable_multi_at_no_nested_scheme_over_redacts_every_at() {
        assert_eq!(
            redact_userinfo("a@b/c@d/host:8081/lib@2.0.0"),
            "***@b/***@d/host:8081/***@2.0.0"
        );
    }

    /// #875 companion (impl-critic S1): the shape that must never regress regardless of how #875
    /// is eventually addressed — a genuine colon-less `TOKEN@host` credential trailing an
    /// unrelated decoy `@`, with no nested scheme and no colon anywhere in the value at all,
    /// is shape-identical to an ordinary decoy `@` segment and must stay masked (over-redaction
    /// accepted, per this module's own never-under-redact guarantee) rather than leaked.
    #[test]
    fn test_redact_userinfo_unparseable_colonless_credential_after_decoy_at_no_scheme_is_redacted()
    {
        assert_eq!(redact_userinfo("a@b/ghp_TOKEN@evil"), "***@b/***@evil");
    }

    /// #862 correctness-gate: a large contiguous run of a single boundary character must not
    /// regress `host_boundary_scheme_aware`/`redact_authority_suffix` back to quadratic
    /// behavior — an earlier revision re-scanned the *entire* remaining run from scratch on every
    /// loop iteration when the run was one long contiguous block (as opposed to alternating
    /// `/x/x/x` segments, which stayed linear even under that bug). Verified in a release build.
    #[test]
    fn test_redact_userinfo_unparseable_contiguous_slash_run_is_linear_time() {
        let n = 400_000;
        let raw = format!("a@b{}y", "/".repeat(n));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&raw);
        let elapsed = start.elapsed();
        assert_eq!(redacted, format!("***@b{}y", "/".repeat(n)));
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "took {elapsed:?} for a {n}-byte contiguous slash run — \
             host_boundary_scheme_aware may have regressed to quadratic behavior"
        );
    }

    /// #862 correctness-gate (round 7): a long run of many small, colon-free, `@`-free windows,
    /// all undecided, with a genuine `://` only at the very end (so `has_nested_scheme` keeps the
    /// continuation going for the whole run) must stay linear — an earlier revision of this round
    /// checked `bounded_has_credential_colon` on the *accumulated* `region[base..boundary]` span,
    /// which grows by one window each iteration, making this `O(n²)`.
    #[test]
    fn test_redact_userinfo_unparseable_many_small_undecided_windows_is_linear_time() {
        let n = 200_000;
        let raw = format!("{}a@b://ghp_TOKEN@evil", "/x".repeat(n));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&raw);
        let elapsed = start.elapsed();
        assert!(
            !redacted.contains("ghp_TOKEN"),
            "redacted len={}",
            redacted.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "took {elapsed:?} for n={n} small undecided windows — bounded_has_credential_colon \
             may have regressed to scanning a growing accumulated span"
        );
    }

    /// impl-critic S1 (round 8 perf regression): [`redact_further_credential`] used to re-scan
    /// the entire (shrinking) tail for both a further `@` ([`find_credential_at`]) and a `[`
    /// bracket ([`colon_credential_match`]'s own `remaining.find('[')`) on every outer iteration,
    /// even once neither could ever be found again — turning a long, colon-dense,
    /// bracket-free, single-real-credential value into `O(n²)` (measured, release build: 21.3s at
    /// 1.6 MB before this fix). Fixed by making the `@` probe sticky and hoisting the
    /// bracket-presence check out of the per-iteration restart — see that function's own doc
    /// comment for why both are sound.
    #[test]
    fn test_redact_further_credential_colon_dense_chain_is_linear_time() {
        let k = 400_000;
        let raw = format!("u:SECRET@h/{}z", "a:b/".repeat(k));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&raw);
        let elapsed = start.elapsed();
        assert!(
            !redacted.contains("SECRET"),
            "redacted len={}",
            redacted.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "took {elapsed:?} for a {k}-segment colon-dense chain — redact_further_credential \
             may have regressed to quadratic behavior"
        );
    }

    /// impl-critic S2 (round 8 perf regression, found in re-review of the S1 fix above): a
    /// whole-tail `bool` ("does this value contain a `[` anywhere") is defeated by a *single* `[`
    /// — [`colon_credential_match`] still ran `remaining.find('[')` on every call once that bool
    /// was `true`, so one bracket anywhere in an otherwise colon-dense value (even one never
    /// actually reached) restored the same `O(n²)` S1 fixed for the bracket-free case (measured,
    /// release build: 2.8s at 800 KB with only the S1 fix). Fixed by tracking the bracket's own
    /// offset instead of a boolean, carried forward and translated (not re-scanned) on every call
    /// — see `redact_further_credential`'s and `colon_credential_match`'s own doc comments.
    #[test]
    fn test_redact_further_credential_colon_dense_chain_with_trailing_bracket_is_linear_time() {
        let k = 400_000;
        let raw = format!("u:SECRET@h/{}[::1]", "a:b/".repeat(k));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&raw);
        let elapsed = start.elapsed();
        assert!(
            !redacted.contains("SECRET"),
            "redacted len={}",
            redacted.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "took {elapsed:?} for a {k}-segment colon-dense chain with a trailing bracket — \
             colon_credential_match may have regressed to quadratic behavior on a bracket-present \
             value"
        );
    }

    /// #891: a run of consecutive `[` with no `:` anywhere made [`bracket_host_shape_end`] advance
    /// the caller's cursor one byte at a time, forcing `colon_credential_match_seeded`'s own
    /// `remaining.find(':')` to rescan the shrinking-by-one remainder on every iteration —
    /// quadratic in the run length (measured: ~799ms release / ~800ms debug at n=200,000 before
    /// this fix; ~321-339us after, ~16ms including test-harness overhead in a debug build here).
    /// 300ms keeps generous headroom above the fixed cost for slower CI runners while staying well
    /// under the unfixed one, so this actually fails if the run-skip regresses (the previous 5s
    /// bound did not: unfixed HEAD passes it too).
    #[test]
    fn test_redact_userinfo_consecutive_bracket_run_is_linear_time() {
        let n = 200_000;
        let input = format!("a@{}", "[".repeat(n));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&input);
        let elapsed = start.elapsed();
        // code-review: a future edit that stays fast but corrupts output would slip past a
        // timing-only assertion, so also pin down the expected shape — the lone `a` username has
        // no password to leak, but the mask must still fully cover it and leave every `[` alone.
        assert_eq!(
            redacted,
            format!("***@{}", "[".repeat(n)),
            "redacted len={}",
            redacted.len()
        );
        assert!(
            elapsed < std::time::Duration::from_millis(300),
            "took {elapsed:?} for n={n} consecutive '[' — bracket_host_shape_end may have \
             regressed to quadratic behavior"
        );
    }

    /// #894: #893 fixed the quadratic scan for a run of *consecutive* `[`, but
    /// [`colon_credential_match_seeded`] still called `remaining.find(':')` unconditionally on
    /// every loop iteration — a pattern that alternates `[` with an intervening non-`[`/non-`:`
    /// byte never takes the bracket-run-skip arm (each `[` is followed by a `0`, not another `[`),
    /// so every iteration only advances `cursor` by 2 while still re-scanning the whole shrinking
    /// remainder for the next `:`, i.e. still `O(n²)` (measured, release build: ~1.6s at 400 KB
    /// before this fix). Fixed by threading `next_colon` through the loop the same way
    /// `next_bracket`/`translate_bracket` already are — see [`translate_offset`].
    #[test]
    fn test_redact_userinfo_alternating_bracket_run_is_linear_time() {
        let n = 200_000;
        let input = format!("a@{}", "[0".repeat(n));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&input);
        let elapsed = start.elapsed();
        assert_eq!(
            redacted,
            format!("***@{}", "[0".repeat(n)),
            "redacted len={}",
            redacted.len()
        );
        assert!(
            elapsed < std::time::Duration::from_millis(300),
            "took {elapsed:?} for n={n} alternating '[0' pairs — colon_credential_match_seeded \
             may have regressed to quadratic behavior on the colon rescan"
        );
    }

    /// #891 companion: an odd-length run of stray `[` (three, none of them valid IPv6 openers on
    /// their own) immediately followed by a genuinely closed bracketed host and a real credential
    /// must still land the run-skip on the *last* `[` in the run and evaluate it normally — the
    /// host must be recognized (not itself mistaken for part of the stray run) and the trailing
    /// credential must still be redacted.
    #[test]
    fn test_redact_userinfo_bracket_run_then_real_host_is_still_redacted() {
        let redacted = redact_userinfo("[[[::1]:glpat-SECRET");
        assert!(!redacted.contains("glpat-SECRET"), "redacted={redacted:?}");
        assert_eq!(redacted, "[[[::1]:***");
    }

    /// #891 review follow-up (impl-critic C1, critical): a `[` encountered only *after* the
    /// alphabet-run loop already consumed some in-alphabet bytes (`:`, `.`, hex digits) — i.e. not
    /// immediately following `open` — must never be treated as the start of a skippable run: doing
    /// so lets the returned offset land past a real credential-separating `:`, so the caller's
    /// cursor jumps clean over the credential and nothing gets redacted at all (an under-redaction
    /// regression, not just a missed optimization). A first, unguarded version of the #891 fix
    /// regressed exactly this — confirmed by exhaustive differential testing against HEAD
    /// (960,799 inputs of length 1-7 over `[ ] : 0 x @ /`): 10,669 inputs went from
    /// correctly-redacted to fully unredacted, 0 in the safe direction. The `i == open + 1` guard
    /// on `bracket_host_shape_end`'s `[`-run arm is what closes this: it restricts the run-skip to
    /// brackets that could never have been a valid opener regardless of what preceded them.
    #[test]
    fn test_redact_userinfo_bracket_run_not_anchored_at_open_does_not_leak_credential() {
        assert_eq!(redact_userinfo("[:[ghp_SECRET"), "[:***");
        assert_eq!(redact_userinfo("[0:0[ghp_SECRET"), "[0:***");
        assert_eq!(redact_userinfo("[::1:0[glpat-SECRET"), "[:***");
        assert_eq!(redact_userinfo("[1.2:0[ghp_SECRET"), "[1.2:***");
    }

    /// #891 review follow-up: [`bounded_has_credential_colon`] is a third caller of
    /// [`bracket_host_shape_end`] outside the differential-fuzzing scope of the #891 fix itself
    /// (unlike [`segment_has_credential_colon`] and `colon_credential_match_seeded`, it only ever
    /// strips one leading bracket span, never loops back to re-examine what follows). Pins its
    /// behavior for a multi-`[`-run prefix: both cases below return `true` on this branch exactly
    /// as they did before #891 (verified by hand: the run's own length changes which single `[`
    /// the one-time strip lands on, but never the *tail* structure `rfind(':')`/[`is_port_like`]
    /// evaluate afterwards — a pre-existing over-approximation for a bracket-run prefix, not a
    /// regression introduced here).
    #[test]
    fn test_bounded_has_credential_colon_multi_bracket_run_prefix_is_unchanged() {
        assert!(bounded_has_credential_colon("[[[::1]:glpat-SECRET"));
        assert!(bounded_has_credential_colon("[[[::1]:8443"));
    }

    /// Stack-overflow guard: [`redact_authority_suffix`] must stay a single forward loop, not
    /// recursion, so a value with a huge number of `/`-separated segments cannot abort the whole
    /// process with an unbounded stack.
    #[test]
    fn test_redact_authority_suffix_large_slash_chain_is_iterative_not_recursive() {
        let n = 200_000;
        let raw = format!("a@b{}user:hunter2@evil", "/x".repeat(n));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&raw);
        let elapsed = start.elapsed();
        assert!(
            !redacted.contains("hunter2"),
            "redacted len={}",
            redacted.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "took {elapsed:?} for n={n} segments — may have regressed to recursive/quadratic \
             behavior"
        );
    }

    /// #886: [`redact_authority_suffix`]'s mask site used to `push_str` its pass-through streak
    /// (the text between two masked `@`-credentials) verbatim, unexamined — so a colon-only
    /// credential sitting in that streak (`oauth2:SECRET`, no `@` of its own) survived even
    /// though both the neighboring `@`-shaped decoys around it were masked.
    #[test]
    fn test_redact_authority_suffix_mask_site_colon_credential_between_two_at_signs_is_redacted() {
        let redacted = redact_userinfo("a@b/oauth2:SECRET/c@d");
        assert!(!redacted.contains("SECRET"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@b/oauth2:***/***@d");
    }

    /// #886 companion: more than two decoy `@`s around the mask-site leak, to confirm the fix
    /// isn't specific to exactly one pass-through streak.
    #[test]
    fn test_redact_authority_suffix_mask_site_colon_credential_between_many_at_signs_is_redacted() {
        let redacted = redact_userinfo("a@b/oauth2:SECRET/c@d/gitlab-ci-token:JOBTOKEN/e@f");
        assert!(!redacted.contains("SECRET"), "redacted={redacted:?}");
        assert!(!redacted.contains("JOBTOKEN"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@b/oauth2:***/***@d/gitlab-ci-token:***/***@f");
    }

    /// #886 (impl-critic perf validation): a single large colon-dense pass-through streak
    /// reaching the mask site must stay linear — [`redact_span_colon_credential`] delegates to
    /// the already-amortized [`colon_credential_match_seeded`]/[`redact_further_credential`]
    /// pair rather than re-deriving its own bracket-tracking state per call, so this must not
    /// regress to the `O(n²)` shape a naive `region[..base].contains('[')` recomputation (or a
    /// per-iteration `remaining.find('[')` rescan) would produce.
    #[test]
    fn test_redact_authority_suffix_mask_site_colon_dense_streak_is_linear_time() {
        let k = 400_000;
        let raw = format!("x@{}oauth2:SECRET@y", "p:q/".repeat(k));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&raw);
        let elapsed = start.elapsed();
        assert!(
            !redacted.contains("SECRET"),
            "redacted len={}",
            redacted.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "took {elapsed:?} for a {k}-segment colon-dense mask-site streak — \
             redact_span_colon_credential may have regressed to quadratic behavior"
        );
    }

    /// impl-critic (round 2 perf validation, #886): the exact repro shape flagged against the
    /// discarded pre-#881-aware design, kept as a regression pin against reintroducing a
    /// whole-region verbatim-`push_str` exit anywhere in [`redact_authority_suffix`].
    #[test]
    fn test_redact_authority_suffix_colon_dense_undecided_streak_after_single_at_sign_is_linear_time()
     {
        let n = 200_000;
        let raw = format!("a@{}", "/:".repeat(n));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&raw);
        let elapsed = start.elapsed();
        assert!(
            redacted.starts_with("***@"),
            "redacted len={}",
            redacted.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "took {elapsed:?} for n={n} `/:`repeats after a single `@` — may have regressed to \
             quadratic behavior"
        );
    }

    /// impl-critic S2 (second_order_effects, regression on the #826 fix): a `file:///C:/...`
    /// path (`deps-nuget`'s documented local/UNC feed shape) must not be mangled just because
    /// its Windows drive-letter colon sits in the same `@`-delimited segment as a later,
    /// unrelated `@` — `find_credential_at`'s shape check must ignore a drive-letter `:`.
    #[test]
    fn test_redact_userinfo_opaque_path_file_scheme_drive_letter_is_noop() {
        assert_eq!(
            redact_userinfo("file:///C:/Users/john.doe@corp/project"),
            "file:///C:/Users/john.doe@corp/project"
        );
        assert_eq!(
            redact_userinfo("file:///C:/feeds/pkg@1.0.0.nupkg"),
            "file:///C:/feeds/pkg@1.0.0.nupkg"
        );
        assert_eq!(
            redact_userinfo("nuget:///C:/Users/john.doe@corp/feed"),
            "nuget:///C:/Users/john.doe@corp/feed"
        );
    }

    /// code-review Finding 2 (HIGH, confirmed over-redaction): a bracketed IPv6 host with a
    /// perfectly well-formed numeric port must not be mistaken for a credential just because the
    /// address literal itself contains colons — reachable both through
    /// `redact_userinfo_unparseable`'s widened scan (`bounded_has_credential_colon` used to see
    /// `[::1]`'s own `::` as "a non-port colon") and directly through
    /// `redact_userinfo_opaque_path`'s `find_credential_at` (`segment_has_credential_colon` used
    /// to have no bracket awareness at all).
    #[test]
    fn test_redact_userinfo_bracketed_ipv6_well_formed_port_is_noop() {
        assert_eq!(
            redact_userinfo("[::1]:8443/pkg@1.0.0"),
            "[::1]:8443/pkg@1.0.0"
        );
        assert_eq!(
            redact_userinfo("c:/[::1]:8443/pkg@1.0.0"),
            "c:/[::1]:8443/pkg@1.0.0"
        );
    }

    /// code-review Finding 2 companion: a bracketed IPv6 host with a well-formed port still gets
    /// its real, unrelated credential caught when one is genuinely present elsewhere in the
    /// value — the bracket carve-out must not become a blanket no-op for the whole string.
    #[test]
    fn test_redact_userinfo_bracketed_ipv6_well_formed_port_with_real_credential_elsewhere() {
        let redacted = redact_userinfo("user:hunter2@[::1]:8443/pkg");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@[::1]:8443/pkg");
    }

    /// #860 D1: `redact_colon_credential`'s bracket carve-out used to be anchored to the very
    /// start of its scan window, so a bracket sitting a few bytes in (not at cursor 0) was
    /// invisible to it — its own internal pseudo-colon (`::1`'s second `:`) was then mistaken
    /// for the credential separator instead of the real one further down. This is the exact
    /// enumeration example from #860's issue body.
    #[test]
    fn test_redact_userinfo_bracket_not_at_scan_start_is_still_recognized() {
        let redacted = redact_userinfo("x/[::1]:glpat-SECRET");
        assert!(!redacted.contains("glpat-SECRET"), "redacted={redacted:?}");
        assert_eq!(redacted, "x/[::1]:***");
    }

    /// #860 (security-reviewer follow-up on the #846 refactor): a closing bracket's `:port`
    /// separator used to be exempted unconditionally, regardless of what followed it, which is
    /// exactly what let a real credential sitting in that position pass through completely
    /// unredacted — `glpat-SECRET` is shape-identical to a malformed port and was never even
    /// inspected. Fixed by routing that colon through the same `is_port_like` check every other
    /// colon in this scanner already gets.
    #[test]
    fn test_redact_userinfo_bracket_adjacent_non_port_value_is_redacted() {
        let redacted = redact_userinfo("[::1]:glpat-SECRET");
        assert!(!redacted.contains("glpat-SECRET"), "redacted={redacted:?}");
        assert_eq!(redacted, "[::1]:***");
    }

    /// #860 companion: a doubled/nested opening bracket (`[[::1]...`) must not let the outer,
    /// non-IPv6-shaped `[` mask the real bracketed host that follows it — the IPv6-shape gate
    /// ([`bracket_host_shape_end`]) recognizes the inner `[::1]` on its own once the outer
    /// stray `[` is skipped as a 1-byte non-match.
    #[test]
    fn test_redact_userinfo_doubled_bracket_prefix_is_still_redacted() {
        let redacted = redact_userinfo("[[::1]:glpat-SECRET");
        assert!(!redacted.contains("glpat-SECRET"), "redacted={redacted:?}");
        assert_eq!(redacted, "[[::1]:***");
    }

    /// #860 (security-reviewer follow-up): an *unclosed* bracket must not let its own internal
    /// pseudo-colons (`::1`) be mistaken for the real credential separator that follows it —
    /// before this fix, the scan treated the unclosed `[` as if there were no bracket at all,
    /// found `::1`'s own colon first, and masked at the wrong position, leaving the real
    /// `user:hunter2` credential to leak through in the tail
    /// (`redact_userinfo("[::1/user:hunter2@evil")` used to return `"[:***/user:hunter2@evil"`).
    #[test]
    fn test_redact_userinfo_unclosed_bracket_does_not_leak_later_credential() {
        assert_eq!(redact_userinfo("[::1/user:hunter2@evil"), "***@evil");
    }

    /// impl-critic C3: a bracket with *no closing `]` anywhere in the string* must never let its
    /// own pseudo-colons be treated as a closed IPv6 host's colons — an earlier revision's
    /// `bracket_host_shape_end` skipped as far as the alphabet run went even when it never
    /// closed, so `[::1:glpat-SECRET` (no `]` at all) skipped straight past the real credential's
    /// own colon and left it completely unredacted. Fixed: only a genuinely closed bracket is
    /// ever credited as a host shape; an unclosed one skips nothing, leaving every colon in it
    /// (including the credential's own) visible to the ordinary scan.
    #[test]
    fn test_redact_userinfo_bracket_with_no_closing_bracket_anywhere_is_still_redacted() {
        assert_eq!(redact_userinfo("[::1:glpat-SECRET"), "[:***");
    }

    /// impl-critic C2: redacting a bracket-adjacent non-port value is forced (#860 — it is
    /// shape-identical to a real credential), but the mask must extend to the end of the region,
    /// not just to the next `/`/`?`/`#` — otherwise a genuine credential sitting past that
    /// boundary leaks through the unredacted tail. Before this fix,
    /// `[::1]:abc/user:glpat-SECRET` returned `"[::1]:***/user:glpat-SECRET"` (the real
    /// credential fully exposed); it must now be masked away entirely, not just the ambiguous
    /// `abc`.
    #[test]
    fn test_redact_userinfo_bracket_adjacent_false_positive_does_not_leak_later_credential() {
        let redacted = redact_userinfo("[::1]:abc/user:glpat-SECRET");
        assert!(!redacted.contains("glpat-SECRET"), "redacted={redacted:?}");
        assert_eq!(redacted, "[::1]:***");
    }

    /// Differential-fuzz find, a generalization of C2: a `/` immediately after `[` disqualifies
    /// it as a real IPv6 shape (correctly — no legitimate host bracket ever looks like `[/...`),
    /// so the bracket skip is only 1 byte and the very next colon (inside the stray `::1]`) is
    /// *not* the colon immediately following it. An earlier fix tried a narrower `value`-based
    /// proxy for this (`value.contains(']')`) and was itself found leaking one segment further
    /// out (`[/::1/x]:abc/user:SECRET`) — replaced by the sticky "any bracket seen in this scan"
    /// flag (impl-critic R3), which closes the whole family at once: once *any* `[` has appeared
    /// anywhere in the string being scanned, every redaction from that point on masks through to
    /// the end of the region rather than stopping at the next `/`/`?`/`#`.
    #[test]
    fn test_redact_userinfo_orphaned_close_bracket_in_value_does_not_leak_later_credential() {
        assert_eq!(redact_userinfo("[/::1]:abc/user:glpat-SECRET"), "[/:***");
    }

    /// R3 companion: the fuzz-found counterexample that broke the narrower `value.contains(']')`
    /// proxy — moving the orphaned `]` one path segment further away from the colon it was meant
    /// to flag reopened the leak under that check, but the sticky "bracket seen anywhere" flag
    /// catches it regardless of how far downstream the ambiguous colon sits.
    #[test]
    fn test_redact_userinfo_sticky_bracket_seen_catches_farther_orphaned_bracket() {
        assert_eq!(redact_userinfo("[/::1/x]:abc/user:glpat-SECRET"), "[/:***");
    }

    /// code review: `segment_has_credential_colon`'s `is_port_like` exemption must only ever be
    /// granted to a colon immediately following a *genuinely closed* bracket — an earlier
    /// revision granted it whenever a bracket was merely attempted, closed or not, so a stray
    /// unclosed `[` immediately followed by a colon (`[:12345`) wrongly earned the same
    /// port-shape exemption a real `[::1]:8443` host would. This is a contract/robustness fix,
    /// not an independently exploitable path today — `redact_colon_credential`'s own fallback
    /// scan (unbounded by `@`, unlike `segment_has_credential_colon`'s) always includes the `@`
    /// itself in the span it checks against `is_port_like`, and `@` is never an ASCII digit, so
    /// the fallback already catches whatever this exemption might wrongly wave through; this
    /// pins that the input the reviewer named stays safely redacted regardless.
    #[test]
    fn test_redact_userinfo_unclosed_bracket_before_port_like_value_is_not_exempted() {
        assert_eq!(redact_userinfo("c:/[:12345@evil"), "c:***@evil");
    }

    /// Companion to the fix above, disambiguating a lookalike case: `"[:12345"` on its own (no
    /// `@`, no scheme) never reaches `segment_has_credential_colon` at all — with no `@`,
    /// `bounded_has_credential_colon` short-circuits straight to `redact_colon_credential`, whose
    /// *general* `is_port_like` check (applying to every colon uniformly, #810, unrelated to
    /// bracket-adjacency) exempts `"12345"` on its own merits. This is the same pre-existing,
    /// already-documented ≤5-digit collision `test_url_for_tracing_colon_credential_documented_collisions`
    /// already pins for `"oauth2:12345"` — a stray unclosed bracket changes nothing about it, so
    /// this staying a no-op is *not* evidence of the bracket_adjacent bug (which requires an `@`
    /// to even be reachable) and is not something to "fix" here without reopening that
    /// documented, accepted collision for every other colon in the codebase.
    #[test]
    fn test_redact_userinfo_bare_unclosed_bracket_digit_gap_is_documented_collision() {
        assert_eq!(redact_userinfo("[:12345"), "[:12345");
    }

    /// #857: `redact_userinfo_opaque_path`'s guard used to disable the `redact_colon_credential`
    /// fallback (#810) for *any* unrelated `@` anywhere in the opaque-path region, even one with
    /// nothing to do with the actual credential — an ordinary directory name (`user@host`) here
    /// completely hid a real, unrelated `token:glpat-SECRET` credential later in the same path.
    /// Fixed by removing the guard entirely (impl-critic C1): #860's fix already makes
    /// `redact_colon_credential` safe for the one case (a genuine bracket shape) the guard was
    /// meant to protect — see `test_redact_userinfo_opaque_path_bracket_host_stays_noop_without_guard`
    /// — so a separate guard was only ever a source of new leaks, never a needed protection.
    #[test]
    fn test_redact_userinfo_opaque_path_unrelated_at_does_not_hide_later_credential() {
        assert_eq!(
            redact_userinfo("c:/user@host/token:glpat-SECRET"),
            "c:/user@host/token:***"
        );
    }

    /// #857 companion with a realistic GitLab CI job-token shape and a `file://` scheme.
    #[test]
    fn test_redact_userinfo_opaque_path_unrelated_at_gitlab_ci_token_is_redacted() {
        let redacted = redact_userinfo("file:///home/u@corp/gitlab-ci-token:JOBTOKEN");
        assert!(!redacted.contains("JOBTOKEN"), "redacted={redacted:?}");
        assert_eq!(redacted, "file:///home/u@corp/gitlab-ci-token:***");
    }

    /// #857 companion (impl-critic C1): with the `OpaquePath` guard removed entirely, the
    /// bracket-adjacent no-op case it used to exist for must still hold on `redact_colon_credential`'s
    /// own merits alone — an ordinary bracketed-IPv6 host with a well-formed port, followed by an
    /// unrelated `@version` segment, stays a no-op exactly like its
    /// `test_redact_userinfo_bracketed_ipv6_well_formed_port_is_noop` sibling (which already pins
    /// this same input).
    #[test]
    fn test_redact_userinfo_opaque_path_bracket_host_stays_noop_without_guard() {
        assert_eq!(
            redact_userinfo("c:/[::1]:8443/pkg@1.0.0"),
            "c:/[::1]:8443/pkg@1.0.0"
        );
    }

    /// impl-critic C1 (second_order_effects, the new leak the removed guard introduced): a
    /// bracket shape *anywhere* in an opaque-path value — even one with nothing to do with the
    /// real credential — used to disable redaction of that credential entirely under the old
    /// narrowed guard, since the guard required only a bracket shape's presence, not any
    /// relation to the `@` or the credential itself.
    #[test]
    fn test_redact_userinfo_opaque_path_unrelated_bracket_does_not_hide_credential() {
        assert_eq!(
            redact_userinfo("c:/[]/token:glpat-SECRET"),
            "c:/[]/token:***"
        );
    }

    /// impl-critic S3/S4 (completeness_check, then second_order_effects): a password whose
    /// prefix before the `/`/`?`/`#` delimiter is 1-5 ASCII digits collides with the `host:port`
    /// carve-out and passes through unredacted — a deliberate, documented trade-off (S4), not a
    /// residual bug: an earlier revision closed this via a widened `@`-scan fallback, but that
    /// scan cannot tell `user:12345/rest@evil` (credential) apart from an ordinary self-hosted
    /// registry string like `nexus.corp:8081/repo/lib@2.0.0` (not a credential at all) — both are
    /// `word:digits/…@…` — so it mangled real hostnames in every non-default-port log line. This
    /// is the same accepted collision this file already documents for `oauth2:12345`.
    #[test]
    fn test_redact_userinfo_unparseable_digit_prefixed_password_is_accepted_gap() {
        for raw in [
            "user:12345/rest@evil",
            "user:12345?rest@evil",
            "user:12345#rest@evil",
        ] {
            assert_eq!(redact_userinfo(raw), raw, "raw={raw:?}");
        }
    }

    /// Contrast case: `https://user:1234/secret@evil` is *not* the same shape as the schemeless
    /// repros above — `https` is a special scheme, so `Url::parse` resolves `user:1234` as a
    /// genuine `host:port` authority (verified: `host="user"`, `port=1234`, `username`/`password`
    /// both empty) with `/secret@evil` as an ordinary path, not a credential at all. It never
    /// reaches `redact_userinfo_unparseable`, so leaving it unchanged is correct regardless of
    /// the S4 trade-off above.
    #[test]
    fn test_redact_userinfo_https_digit_after_colon_before_slash_is_not_a_credential() {
        assert_eq!(
            redact_userinfo("https://user:1234/secret@evil"),
            "https://user:1234/secret@evil"
        );
    }

    /// impl-critic S3 companion: the genuine `host:port` shape (#810's own repro, with a port
    /// prepended) must still resolve through `redact_colon_credential` and keep the host
    /// visible.
    #[test]
    fn test_redact_userinfo_unparseable_host_port_with_trailing_credential_unaffected_by_s3_fix() {
        assert_eq!(
            url_for_tracing("gitlab.corp:8443/user:hunter2@evil"),
            "gitlab.corp:8443/user:***"
        );
    }

    /// impl-critic S4 — the over-redaction this round's fix removed: an ordinary self-hosted
    /// registry `host:port/...` string with no credential anywhere must stay fully visible in
    /// logs/error output, including the `@scope`-package-name shape #767 already fought once
    /// (`registry.corp:4873/@scope/pkg`) and `localhost`, which defeats any "the host contains a
    /// dot" heuristic. `RedactedUrl::new` is applied to arbitrary values including cargo registry
    /// alias names (`deps-cargo`'s `parser.rs`), so mangling these would be user-visible on every
    /// request for anyone on a non-default port.
    #[test]
    fn test_redact_userinfo_unparseable_host_port_registry_strings_are_not_over_redacted() {
        for raw in [
            "nexus.corp:8081/repo/lib@2.0.0",
            "registry.corp:4873/@scope/pkg",
            "localhost:8080/@types/node",
            "gitlab.corp:8443/repo/pkg@1.0.0",
        ] {
            assert_eq!(redact_userinfo(raw), raw, "raw={raw:?}");
        }
    }

    /// impl-critic M3 (completeness_check) history: an IPv6 host with a malformed (non-numeric)
    /// port used to be over-redacted (no bracket-adjacent carve-out at all), then a later
    /// revision made it a no-op by exempting any bracket-adjacent colon unconditionally. #860
    /// closes that unconditional exemption — a non-numeric value right after a bracket's `]:`
    /// is shape-indistinguishable from a real credential (`[::1]:notaport` vs.
    /// `[::1]:glpat-SECRET`), so `bounded_has_credential_colon` now correctly treats it as
    /// evidence of a possible credential and widens into the `@`-masking path (not the
    /// colon-masking path — `notaport`'s own non-exemption is what routes this through
    /// `find_credential_at` and `mask_at` instead of `redact_colon_credential`).
    #[test]
    fn test_redact_userinfo_unparseable_ipv6_malformed_port_is_redacted() {
        assert_eq!(
            redact_userinfo("https://[::1]:notaport/x@y"),
            "https://***@y"
        );
    }

    /// impl-critic M4 (completeness_check, pre-existing HEAD behavior, not a regression): a
    /// single-letter username immediately followed by `:/` is indistinguishable from a Windows
    /// drive-letter prefix (`colon_is_drive_letter`'s shape), so `a:/b@evil` is treated as a
    /// drive-letter path and left unredacted. Contrived (a one-character username with a
    /// `/`-leading password), pinned here so the trade-off doesn't silently change.
    #[test]
    fn test_redact_userinfo_opaque_path_single_letter_username_matches_drive_letter_shape() {
        assert_eq!(redact_userinfo("c:/a:/b@evil"), "c:/a:/b@evil");
    }

    /// #756 C1 regression: a `HttpCache`/`GithubTagsClient` outbound-request chokepoint must
    /// never attach a token-bearing query string (e.g. an `.npmrc` `registry=` URL after
    /// `${VAR}` expansion, `NpmRegistryIndex`'s security model) to a `tracing` span field —
    /// exact repro from the finding.
    #[test]
    fn test_url_for_tracing_strips_query_string_token() {
        let safe = url_for_tracing("https://npm.internal/pkg?token=super-secret-value");
        assert!(!safe.contains("super-secret-value"));
        assert_eq!(safe, "https://npm.internal/pkg");
    }

    #[test]
    fn test_url_for_tracing_strips_fragment() {
        assert_eq!(
            url_for_tracing("https://registry.example/simple#token=x"),
            "https://registry.example/simple"
        );
    }

    #[test]
    fn test_url_for_tracing_strips_both_userinfo_and_query() {
        assert_eq!(
            url_for_tracing("https://user:hunter2@registry.example/simple?token=x"),
            "https://***@registry.example/simple"
        );
    }

    #[test]
    fn test_url_for_tracing_noop_for_plain_url() {
        assert_eq!(
            url_for_tracing("https://registry.example/simple"),
            "https://registry.example/simple"
        );
    }

    /// Doc-accuracy regression: an unparseable `raw` with no `@`/`?`/`#` at all is returned
    /// unchanged — there is no placeholder substitution, unlike the doc comment used to
    /// (inaccurately) claim. The outbound-request URLs this function actually guards always
    /// have a scheme, so this residual case is not expected to matter in practice — it is
    /// pinned here only so the doc comment's corrected wording stays honest.
    #[test]
    fn test_url_for_tracing_unparseable_with_no_redactable_shape_is_unchanged() {
        assert_eq!(url_for_tracing("not-a-url-at-all"), "not-a-url-at-all");
    }

    /// Doc-accuracy companion: an unparseable `raw` still gets its `?`/`#`-delimited suffix
    /// truncated, and any textually-detectable userinfo still redacted — the same two
    /// operations a parseable URL gets, just without going through `url::Url::parse`.
    #[test]
    fn test_url_for_tracing_unparseable_still_truncates_query_and_redacts_userinfo() {
        assert_eq!(
            url_for_tracing("not-a-url?token=super-secret-value"),
            "not-a-url"
        );
        assert_eq!(
            url_for_tracing("user:hunter2@registry.example/simple?token=x"),
            "***@registry.example/simple"
        );
    }

    /// #869: `mask_at`'s tail — everything after the `@` it selects — used to be left completely
    /// unredacted, so a second, independent colon-shaped credential sitting there (`tok:SECRET`)
    /// leaked in full alongside the correctly-masked `user:hunter2@`. This exact repro parses as
    /// an ordinary authority-having URL, which redacts userinfo via `Url::set_username`/
    /// `set_password` directly rather than through `mask_at` — so the same tail-leak family is
    /// closed there too (`redact_authority_url_tail`), not only in `mask_at` itself.
    #[test]
    fn test_redact_userinfo_secondary_colon_credential_in_tail_after_at_sign() {
        assert_eq!(
            redact_userinfo("https://user:hunter2@evil/tok:SECRET"),
            "https://***@evil/tok:***"
        );
    }

    /// #869 companion: the same tail-leak family reached directly through `mask_at`, via the
    /// `OpaquePath` (`scheme:/path`, #811) fallback that `redact_credential` implements `mask_at`
    /// for. `RegionKind::Authority` no longer reaches `mask_at` at all since #862 gave it its own
    /// continuation (`redact_authority_suffix`) — the schemeless, no-`://`-prefix `Authority` case
    /// this test used to also cover here is its own, separately-tracked gap; see
    /// [`test_redact_userinfo_unparseable_colon_only_credential_reachable_with_no_scheme_prefix_is_redacted`]
    /// below.
    #[test]
    fn test_redact_userinfo_secondary_colon_credential_in_tail_mask_at_fallbacks() {
        assert_eq!(
            redact_userinfo("c:/user:hunter2@evil/tok:SECRET"),
            "c:***@evil/tok:***"
        );
        assert_eq!(
            redact_userinfo("c:///user:hunter2@evil/tok:SECRET"),
            "c:***@evil/tok:***"
        );
    }

    /// #870 (fixed, same root cause, reached via a different dispatch path than the two examples
    /// already pinned above it): `redact_userinfo_unparseable` finds no `://` before the first
    /// `@` in `raw` (there is no scheme separator anywhere), so `authority_start` is `0` and the
    /// entire string is scanned as one `RegionKind::Authority` region. Once the first `@` is
    /// masked, `redact_authority_suffix`'s `colon_evidence` check is still hard-gated on
    /// `base == 0` by design, but the loop-exhaustion fallthrough now routes through
    /// [`redact_further_credential`] instead of appending the remainder verbatim, so a further
    /// colon-only credential (`tok:SECRET`, no `@` of its own) later in the same value is caught.
    #[test]
    fn test_redact_userinfo_unparseable_colon_only_credential_reachable_with_no_scheme_prefix_is_redacted()
     {
        assert_eq!(
            redact_userinfo("not-a-url:user:hunter2@evil/tok:SECRET"),
            "***@evil/tok:***"
        );
    }

    /// #866: `url_for_tracing` used to redact the credential-shaped span first and truncate the
    /// *result* at the first `?`/`#` afterward — so a credential-shaped `@` inside the query
    /// string itself (`u=user:pw@a`) got widened over by `extend_credential_at`, consuming the
    /// real `?`/`#` boundary before truncation ever ran, and the whole query string (including
    /// `token=SUPERSECRET`) survived unredacted. Truncating the *raw* input at `?`/`#` before
    /// redacting at all guarantees the query/fragment is dropped regardless of where any
    /// credential-shaped `@` lands within it.
    #[test]
    fn test_url_for_tracing_truncates_before_redacting_query_credential_at_sign() {
        assert_eq!(
            url_for_tracing("c:/path?u=user:pw@a&token=SUPERSECRET"),
            "c:/path"
        );
        assert_eq!(
            url_for_tracing("c:/path#u=user:pw@a&token=SUPERSECRET"),
            "c:/path"
        );
    }

    /// S1: `IndexUrlError::InvalidUrl`'s payload is where the leak actually surfaced — every
    /// caller (`deps-cargo`, `deps-npm`, `deps-pypi`) logs/retains this error's `%error`/
    /// `Display`, so the redaction must happen inside `validate_index_url` itself, not rely on
    /// each caller to redact separately.
    #[test]
    fn test_validate_index_url_redacts_userinfo_in_invalid_url_error() {
        let raw = "https://user:hunter2@registry.example:99999/simple";
        let err = validate_index_url(raw, raw, "cargo", PolicyGate::Skip).unwrap_err();
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
        for ecosystem in ["cargo", "npm"] {
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

    /// #896: a long, bracket-free run of drive-letter-shaped colons ahead of the loop's cursor
    /// (the issue's own repro shape, `("c:/" * n) + "@x"`) must stay linear —
    /// `segment_has_credential_colon`'s per-iteration `remaining.find('[')`/`remaining.find(':')`
    /// used to have to rescan the whole shrinking `remaining` on every 2-3-byte drive-letter
    /// step just to prove no bracket/colon was ahead, mirroring
    /// `test_redact_authority_suffix_mask_site_colon_dense_streak_is_linear_time`'s methodology
    /// but through `find_credential_at`'s segment scan instead of the mask-site tail.
    #[test]
    fn test_redact_userinfo_drive_letter_dense_streak_is_linear_time() {
        let k = 400_000;
        let raw = format!("{}@x", "c:/".repeat(k));
        let start = std::time::Instant::now();
        let redacted = redact_userinfo(&raw);
        let elapsed = start.elapsed();
        assert_eq!(redacted, raw, "redacted len={}", redacted.len());
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "took {elapsed:?} for a {k}-segment drive-letter-dense run before a single `@` — \
             segment_has_credential_colon may have regressed to quadratic behavior"
        );
    }

    /// #896 correctness companion: the drive-letter-dense repro shape itself (many `c:/`
    /// segments, no bracket, no real credential colon) must remain a no-op regardless of how
    /// many drive-letter steps the cached `next_bracket`/`next_colon` offsets have to be
    /// re-derived across.
    #[test]
    fn test_redact_userinfo_dense_drive_letter_run_before_unrelated_at_is_noop() {
        let raw = format!("{}@x", "c:/".repeat(50));
        assert_eq!(redact_userinfo(&raw), raw);
    }

    /// #896 correctness companion: a bracket appearing after one or more drive-letter colons
    /// must still be recognized once `next_bracket` is re-derived past the drive-letter cursor
    /// advances — the well-formed-port carve-out this mirrors
    /// (`test_redact_userinfo_bracketed_ipv6_well_formed_port_is_noop`) must not regress when
    /// more than one drive-letter segment precedes the bracket.
    #[test]
    fn test_redact_userinfo_drive_letter_run_then_bracket_is_noop() {
        assert_eq!(
            redact_userinfo("c:/c:/c:/[::1]:8443/pkg@1.0.0"),
            "c:/c:/c:/[::1]:8443/pkg@1.0.0"
        );
    }

    /// #896 correctness companion: a real, non-drive-letter credential colon following one or
    /// more drive-letter colons must still be found once the cached `next_colon` offset has
    /// fallen behind the cursor and is re-derived from the shrinking `remaining` — same shape
    /// as `test_redact_userinfo_unclosed_bracket_before_port_like_value_is_not_exempted`'s
    /// single-drive-letter case, extended to several.
    #[test]
    fn test_redact_userinfo_drive_letter_run_then_real_credential_is_redacted() {
        let redacted = redact_userinfo("c:/c:/user:hunter2@evil");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
        assert_eq!(redacted, "c:***@evil");
    }

    /// #896 correctness companion: a segment with neither a bracket nor any colon at all must
    /// return `false` immediately from `segment_has_credential_colon`'s no-colon fallback arm,
    /// unaffected by the `next_bracket`/`next_colon` seeding this fix introduced.
    #[test]
    fn test_redact_userinfo_no_colon_no_bracket_segment_is_noop() {
        assert_eq!(redact_userinfo("path/to/pkg@1.0.0"), "path/to/pkg@1.0.0");
    }

    /// #901: the "host present, empty userinfo" branch (net_policy.rs:605-607 pre-fix) used to
    /// `return raw.to_string()` unconditionally, so a `c:/`-corrupted authority that still
    /// parses to `host=Some(_)` with empty username/password left the entire rest of the string
    /// — including a credential-shaped path segment — completely unscanned. Covers all four
    /// issue repro shapes.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_c_drive_path_credential_is_redacted() {
        assert_eq!(
            redact_userinfo("https://c:/c:/user:glpat-SECRET@h/p"),
            "https://c:/c:/user:***/p"
        );
        assert_eq!(
            redact_userinfo("https://c:/[::1:glpat-SECRET@h/p"),
            "https://c:/[:***"
        );
        assert_eq!(
            redact_userinfo("https://c:/[[[[:glpat-SECRET@h/p"),
            "https://c:/[[[[:***"
        );
        assert_eq!(
            redact_userinfo("https://c:/[/::1]:abc/user:SECRET@h/p"),
            "https://c:/[/:***"
        );
    }

    /// #901 companion: the gap is not specific to a `c:/`-corrupted authority — any ordinary,
    /// uncorrupted `https://host/...` URL with empty userinfo hit the exact same unscanned
    /// early-return whenever its path happened to contain a credential-shaped colon.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_ordinary_host_path_credential_is_redacted()
    {
        assert_eq!(
            redact_userinfo("https://example.com/api/user:glpat-SECRET@internal"),
            "https://example.com/api/user:***"
        );
    }

    /// #901 regression guard: the #887 pinned decision that a well-formed `https://` URL never
    /// reaches `redact_authority_suffix`'s token-prefix widen branch must still hold after this
    /// fix — routing the new tail scan through [`redact_secondary_colon_credential`] instead of
    /// `redact_userinfo_unparseable` is exactly what keeps this byte-identical. Already pinned at
    /// [`test_redact_userinfo_authority_widen_branch_token_prefix_over_redaction_is_accepted`];
    /// asserted again here so this file's #901 test group is self-contained.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_no_credential_shape_is_noop() {
        assert_eq!(
            redact_userinfo("https://docs.rs/sk-lang@1.2.3"),
            "https://docs.rs/sk-lang@1.2.3"
        );
    }

    /// #901 boundary guard: a host-having URL whose path contains no colon at all (no credential
    /// shape anywhere in the tail) must stay byte-identical — the new scan must not introduce a
    /// false positive on ordinary paths.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_no_colon_in_path_is_noop() {
        for raw in [
            "https://example.com/no/colon/at/all",
            "https://example.com",
            "https://example.com/",
        ] {
            assert_eq!(redact_userinfo(raw), raw, "raw={raw:?}");
        }
    }

    /// #901 boundary guard: a `=`-shaped query parameter that merely contains the word "token"
    /// is not a colon-credential and must not be redacted — only an actual `key:value@` or
    /// bare `token:value` colon pair triggers the tail scan.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_query_param_without_colon_is_noop() {
        assert_eq!(
            redact_userinfo("https://example.com/search?token=glpat-SECRET"),
            "https://example.com/search?token=glpat-SECRET"
        );
    }

    /// #901 boundary guard: the new tail scan covers the query string too, not just the path —
    /// a colon-credential shape after `?` is redacted exactly like one in the path.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_colon_credential_in_query_is_redacted() {
        assert_eq!(
            redact_userinfo("https://example.com/path?token:SECRET@foo"),
            "https://example.com/path?token:***"
        );
    }

    /// #901 S1 (impl-critic finding): a slash-less `scheme:host` URL can carry its own `://`
    /// later in the path/query (e.g. a `?r=http://y` redirect param) — anchoring
    /// `authority_start` on `raw.find("://")` would skip straight past the real credential and
    /// leave it unredacted. Anchoring on `raw.find(':')` (the scheme separator itself) instead
    /// fixes both the `@`-bearing and colon-only-no-`@` shapes.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_slashless_scheme_credential_before_later_scheme_is_redacted()
     {
        assert_eq!(
            redact_userinfo("https:example.com/user:glpat-SECRET@h/x?r=http://y"),
            "https:example.com/user:***/x?r=http://y"
        );
        assert_eq!(
            redact_userinfo("https:h/oauth2:glpat-SECRET/x?r=http://y"),
            "https:h/oauth2:***/x?r=http://y"
        );
    }

    /// #901 S2 (impl-critic finding): the same slash-less `scheme:host` shape, with no
    /// credential anywhere, used to regress to `authority_start == 0` under the `find("://")`
    /// anchor — scanning the `scheme:` prefix itself and mangling it into `scheme:***`. Anchoring
    /// on `raw.find(':')` (still the scheme separator) instead keeps this byte-identical.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_slashless_scheme_no_credential_is_noop() {
        assert_eq!(redact_userinfo("https:example.com"), "https:example.com");
        assert_eq!(
            redact_userinfo("https:example.com/pkg"),
            "https:example.com/pkg"
        );
    }

    /// #901 boundary guard (impl-critic M3): a port or bracketed IPv6 host must stay exempt from
    /// the new tail scan, matching the module's existing well-formed-port carve-out — there is no
    /// credential-shaped colon anywhere past the scheme separator in either case.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_port_and_ipv6_host_is_noop() {
        assert_eq!(
            redact_userinfo("https://host:8443/x"),
            "https://host:8443/x"
        );
        assert_eq!(
            redact_userinfo("https://[::1]:8443/x"),
            "https://[::1]:8443/x"
        );
    }

    /// #901 boundary guard (impl-critic M3): the tail scan covers the fragment too, not just the
    /// path and query — a colon-credential shape after `#` is redacted the same way.
    #[test]
    fn test_redact_userinfo_host_present_empty_userinfo_colon_credential_in_fragment_is_redacted() {
        assert_eq!(
            redact_userinfo("https://example.com/x#u=user:SECRET@evil"),
            "https://example.com/x#u=user:***"
        );
    }
}
