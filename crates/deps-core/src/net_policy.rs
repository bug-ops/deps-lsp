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
// Exhaustive: security-sensitive SSRF classification — a new host class landing in a
// wildcard arm at any consuming match site would silently fall through as unclassified
// instead of failing to compile (issue #769).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
// Exhaustive: security-sensitive gate for registry fetches — a new variant landing in a
// wildcard arm would silently pick an unintended access level instead of failing to
// compile (issue #769).
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
// Exhaustive: closed 2-variant Skip/Enforce gate — a third state would change the calling
// convention at every `validate_index_url` call site, not slot into an existing wildcard
// arm (issue #769).
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
    if url.username().is_empty() && url.password().is_none() {
        return raw.to_string();
    }
    // `set_username`/`set_password` only fail for a cannot-be-a-base URL — never true here,
    // since a URL with `username()`/`password()` set is always base-having by construction —
    // but a hardcoded fallback marker is used instead of ever risking the original,
    // credential-bearing string leaking through an unexpected `Err` path.
    if url.set_username("***").is_err() || url.set_password(None).is_err() {
        return "<redacted: index URL contained userinfo>".to_string();
    }
    url.as_str().to_string()
}

/// Finds a credential-shaped userinfo `@` in `region`, for use *only* on a region that has no
/// reliable authority boundary of its own (the widened tail of an unparseable authority, or an
/// opaque `scheme:/path` value) — never on a real bounded authority, where every `@` is a
/// userinfo delimiter regardless of whether it looks credential-shaped (see
/// [`redact_userinfo_unparseable`]'s own `bounded.rfind('@')` pass for that case).
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

/// Whether `segment` contains a `:` that is not a Windows drive-letter colon and not a bracketed
/// IPv6 literal's own colon (or its immediately-following port separator) — [`find_credential_at`]'s
/// shape check. A bare `segment.contains(':')` would mistake `file:///C:/Users/x@corp/project`'s
/// drive letter for evidence of a credential (S2 finding): once `@`-delimited segments can span
/// past a `/`, the `C:` in a `file:///C:/...` path sits in the same segment as a later, unrelated
/// `@`. It would likewise mistake `[::1]:8443/pkg@1.0.0`'s own address/port colons for a
/// credential (code review Finding 2) for the same reason — an ordinary bracketed-IPv6 registry
/// host ends up in the same segment as a completely unrelated trailing `@version`.
///
/// A bracket found anywhere in `segment` (not just at its start) is skipped over — together with
/// its immediately-following port-separator `:`, unconditionally, matching
/// [`redact_colon_credential`]'s own bracket-adjacent carve-out exactly (regardless of whether
/// what follows the bracket looks like a valid port) — before the scan for a real credential
/// colon continues past it.
// `bracket`/`colon` come from `find`/`starts_with` of ASCII `[`/`]`/`:` bytes, so every slice
// bound is always a char boundary.
#[allow(clippy::string_slice)]
fn segment_has_credential_colon(segment: &str) -> bool {
    let mut cursor = 0;
    while cursor < segment.len() {
        let remaining = &segment[cursor..];

        if let Some(bracket) = remaining.find('[') {
            if let Some(colon) = remaining[..bracket].find(':') {
                if !colon_is_drive_letter(segment, cursor + colon) {
                    return true;
                }
                cursor += colon + 1;
                continue;
            }
            let bracket_end = remaining[bracket..]
                .find(']')
                .map_or(remaining.len(), |end| bracket + end + 1);
            let skips_port_sep = usize::from(remaining[bracket_end..].starts_with(':'));
            cursor += bracket_end + skips_port_sep;
            continue;
        }

        let Some(colon) = remaining.find(':') else {
            return false;
        };
        if !colon_is_drive_letter(segment, cursor + colon) {
            return true;
        }
        cursor += colon + 1;
    }
    false
}

/// Whether the `:` at byte offset `colon` in `text` is a Windows drive-letter colon: a single
/// ASCII letter — itself preceded by the start of `text`, `/`, or `\` (so it's a standalone
/// token, not the tail of a longer word) — immediately followed by `/` or `\`. Mirrors
/// [`redact_colon_credential`]'s own `is_drive_letter` carve-out, which only ever checks this at
/// the very start of its scan window; this variant checks an arbitrary byte offset, since
/// [`segment_has_credential_colon`] scans a whole segment rather than a cursor-anchored prefix.
///
/// A genuine single-letter *username* immediately followed by a `/`-leading password is
/// shape-identical to a drive letter and is therefore also left unredacted (M4 finding,
/// pre-existing HEAD behavior, e.g. `c:/a:/b@evil` stays a no-op) — contrived enough (a
/// one-character username, itself followed by a password starting with `/`) to accept rather
/// than fix.
fn colon_is_drive_letter(text: &str, colon: usize) -> bool {
    let bytes = text.as_bytes();
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

/// Whether `bounded` (the authority text up to — but not including — the `/`/`?`/`#` that
/// truncated it) contains a `:` that is *not* just a trailing `host:port` suffix, i.e. evidence
/// a credential may already have started before that boundary character rather than the
/// boundary genuinely ending a plain `host[:port]` authority.
///
/// Only the boundary's own trailing colon is checked against [`is_port_like`] — `gitlab.corp:8443`
/// strips down to `gitlab.corp` (no further `:`, not widened) while `user:hunter2:8443` strips
/// only its trailing port to `user:hunter2` (still contains `:`, still widened) — so a
/// credential followed by an incidental port-shaped suffix is not missed just because the very
/// last colon in `bounded` happens to look like a port.
///
/// A `bounded` starting with a bracketed IPv6 literal (`[::1]:8443`) has that bracket and its
/// immediately-following port-separator `:` stripped *unconditionally* before the port check
/// above — matching [`redact_colon_credential`]'s own bracket-adjacent carve-out, regardless of
/// whether what follows looks like a valid port — rather than just [`is_port_like`]'s digits-only
/// check: `is_port_like` alone would leave `[::1]:notaport` still "containing a `:`" (the address
/// literal's own colons) and wrongly trigger the widened scan even for the well-formed port case
/// (`[::1]:8443/pkg@1.0.0` — code review Finding 2). This also incidentally fixes a malformed
/// port's over-redaction (previously accepted as M3) rather than merely documenting it.
// `colon`/`bracket` come from `rfind`/`find` of ASCII `:`/`[`/`]` bytes, so every slice bound is
// always a char boundary.
#[allow(clippy::string_slice)]
fn bounded_has_credential_colon(bounded: &str) -> bool {
    let bounded = if bounded.starts_with('[') {
        bounded.find(']').map_or(bounded, |end| {
            let after_bracket = &bounded[end + 1..];
            after_bracket.strip_prefix(':').unwrap_or(after_bracket)
        })
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

/// [`redact_userinfo`]'s fallback for a `raw` that fails `Url::parse` outright (S1 finding):
/// locates the `://` scheme separator when present, then the *last* `@` before the next `/`,
/// `?`, or `#` (matching how a URL parser resolves multiple unescaped `@`s in the authority —
/// everything up to it is userinfo, never part of the host, **regardless of whether it looks
/// credential-shaped**: `ghp_TOKEN@github.com` and `x-access-token@github.com/repo.git` are
/// real, username-only userinfo with no password at all, and must be redacted exactly like a
/// `user:pass@host` pair — C1 finding), and replaces that whole userinfo span with `***@`. A
/// `raw` with no `://` at all (e.g. a schemeless `user:pass@host` literal, which fails
/// `Url::parse` for lacking a scheme rather than for any userinfo-related reason — #536 C2) is
/// treated the same way, scanning from the very start of `raw` instead of skipping a scheme.
/// An `@` that is the very first character of the bounded authority is *not* treated as this
/// function's answer on its own — an empty userinfo component (`@types/node`, code-review
/// follow-up on #767) carries no credential to hide, so masking through it would be a false
/// positive — but it must not short-circuit the function either (code-review Finding 1): a
/// leading empty-userinfo `@` is treated exactly like "no `@` in the bounded authority at all",
/// falling through to the same widen/`redact_colon_credential` logic below, since a bounded
/// prefix that merely *starts* with `@` (`@scope/user:hunter2@evil`) can still have a real
/// credential past the boundary.
///
/// If *no* `@` is found at all within that bounded authority, the bounded text is checked for a
/// `:` (#826): a `:` preceding the `/`/`?`/`#` boundary with no `@` yet found is evidence a
/// credential already started before that character, so the character is very likely sitting
/// *inside* the password (`https://user:pa?ss@evil`, `user:pa/ss@evil`) rather than genuinely
/// ending the authority — stopping the scan there let the password's own `?`/`#` (partial leak)
/// or `/` (full bypass) hide the `@` that would have triggered masking. When that's the case,
/// [`find_credential_at`] — *shape-checked*, unlike the bounded pass above, since widening past
/// the boundary re-admits ordinary non-credential path/query content that a plain last-`@` scan
/// would over-match — is tried against the full `authority`. A bounded text with no `:` at all
/// (`gitlab.corp` in `gitlab.corp/user:hunter2@evil`, #810's own repro) skips widening
/// entirely: there is no evidence a credential started before the boundary, so the `/` there is
/// a genuine host/path split.
///
/// A bounded text whose *only* `:` is port-shaped (`gitlab.corp:8443`) is ambiguous — it could
/// be a genuine `host:port` with an unrelated `@` past the boundary (#810's own repro, with a
/// port prepended, and the ordinary shape of a self-hosted-registry alias like
/// `nexus.corp:8081/repo/lib@2.0.0` or `localhost:8080/@types/node`), or a password that merely
/// happens to start with digits (`user:12345/rest@evil`). There is no textual discriminator
/// between these two — both are `word:digits/…@…`, and a "the word before the colon contains a
/// dot" heuristic is defeated by `localhost` — so this is a deliberate, documented trade-off
/// (S4 finding), not an oversight: [`redact_colon_credential`] alone resolves this case, with
/// **no** widened `@`-scan fallback. A digit-prefixed password whose prefix up to the first
/// `/`/`?`/`#` is exactly 1-5 ASCII digits therefore still passes through unredacted here — the
/// same accepted collision this file already documents for `oauth2:12345` — rather than risk
/// mangling an ordinary `host:port` registry URL (visible in every log line and error message
/// for any user on a non-default port) into an unreadable `***@...` on every request.
///
/// Falls through to [`redact_colon_credential`] whenever no credential-shaped `@` is found at
/// all (bounded, widened, or via the port-shaped-colon branch above) — a colon-separated
/// credential with no `@` (`oauth2:glpat-SECRET`, a GitLab CI `gitlab-ci-token:JOBTOKEN` job
/// token, an `.npmrc` `key:value` line) reaches this same fallback and, before #810, passed
/// through unredacted.
// All indices (`authority_start`, `host_boundary`, `at`) come from `find`/`rfind`/
// `match_indices` of ASCII tokens (`"://"`, `/`, `?`, `#`, `@`, `:`), so every slice bound is
// always a char boundary.
#[allow(clippy::string_slice)]
fn redact_userinfo_unparseable(raw: &str) -> String {
    let authority_start = raw.find("://").map_or(0, |scheme_end| scheme_end + 3);
    let authority = &raw[authority_start..];
    let host_boundary = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    let bounded = &authority[..host_boundary];

    let mask_at = |at: usize| format!("{}***@{}", &raw[..authority_start], &authority[at + 1..]);

    // A bounded `@` at any position other than 0 is always the true userinfo/host boundary
    // (URL semantics — see this function's own doc comment). One at position 0 (an *empty*
    // userinfo, e.g. `@types/node`) carries no credential of its own, but must NOT short-circuit
    // here (code-review Finding 1): a leading `@scope`-shaped bounded prefix (e.g.
    // `@scope/user:hunter2@evil`) still needs the same "check past the boundary" treatment as a
    // bounded prefix with no `@` at all, or a real credential past the boundary leaks in full.
    if let Some(at) = bounded.rfind('@').filter(|&at| at != 0) {
        return mask_at(at);
    }
    if !bounded.contains(':') {
        return redact_colon_credential(raw, authority_start, authority);
    }
    if bounded_has_credential_colon(bounded) {
        return find_credential_at(authority).map_or_else(
            || redact_colon_credential(raw, authority_start, authority),
            mask_at,
        );
    }

    // `bounded`'s only `:` is port-shaped: leave it to `redact_colon_credential` alone, with no
    // widened-scan fallback (S4 finding) — see this function's own doc comment for why.
    redact_colon_credential(raw, authority_start, authority)
}

/// [`redact_userinfo_unparseable`]'s (and, since #818, [`redact_userinfo_opaque_path`]'s)
/// fallback for the case neither covers on its own: a colon-separated credential with no `@` at
/// all (#810), e.g. `oauth2:glpat-SECRET`, a GitLab CI
/// `gitlab-ci-token:JOBTOKEN` job token, or a bare `.npmrc` `//registry/:_authToken=...` line.
/// Unlike the `@` scan above, this is not restricted to the authority span before the first
/// `/`/`?`/`#` — `gitlab.corp/user:hunter2@evil` (repro from #810) has its credential colon
/// *after* a `/`, so the whole of `authority` (everything after the scheme, or all of `raw`
/// when there is none) is searched.
///
/// Not every colon is a credential separator, so several shapes are left unredacted, checked
/// in this order:
/// - a Windows drive letter (`C:\Users\x\.npmrc`, `c:/packages/feed`) — a single ASCII letter
///   followed by `:` and then `\` or `/`;
/// - a colon immediately following a bracketed IPv6 literal (`[::1]:8443`, `[::1]:abc`) — this
///   is always a host:port separator, regardless of what follows, since an IPv6 host is never
///   itself a credential;
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
/// the component on the left.
///
/// This intentionally produces some false positives on non-credential colon pairs — a Maven
/// coordinate (`com.google.guava:guava` → `com.google.guava:***`), an npm alias spec
/// (`mvn:group:artifact:1.0` → `mvn:***`), an RFC 3339 timestamp (`2026-09-11T08:40:19Z` →
/// `2026-09-11T08:***`), or a path segment that happens to contain a colon
/// (`https://[:::1]/v1/items:search` → `.../items:***`) — accepted because this function only
/// ever feeds a `tracing` line, a user-visible error message, or a redacted-URL type, never a
/// value used for further parsing or comparison. Two shape collisions are accepted as
/// documented limitations rather than fixed: a bracket-adjacent colon is *never* redacted
/// regardless of what follows it (needed to keep `[::1]:abc` unchanged), so
/// `[::1]:glpat-SECRET` is indistinguishable from it and stays unredacted; and a ≤5-digit
/// credential collides with the `host:port` carve-out (`oauth2:12345` stays unredacted).
// All indices come from `find` of ASCII tokens (`:`, `]`, `/`, `?`, `#`) or byte-level ASCII
// checks, so every slice bound is always a char boundary. `cursor` only ever advances (every
// branch below adds at least 1 to it before looping), so the scan is guaranteed to terminate.
#[allow(clippy::string_slice)]
fn redact_colon_credential(raw: &str, authority_start: usize, authority: &str) -> String {
    let mut cursor = 0;
    loop {
        let remaining = &authority[cursor..];

        let bytes = remaining.as_bytes();
        let is_drive_letter = bytes.first().is_some_and(u8::is_ascii_alphabetic)
            && bytes.get(1) == Some(&b':')
            && matches!(bytes.get(2), Some(b'\\' | b'/'));
        if is_drive_letter {
            cursor += 2;
            continue;
        }

        let (scan_start, bracket_adjacent) = if remaining.starts_with('[') {
            remaining
                .find(']')
                .map_or((0, false), |end| (end + 1, true))
        } else {
            (0, false)
        };

        let Some(colon) = remaining[scan_start..].find(':').map(|i| i + scan_start) else {
            return raw.to_string();
        };
        if bracket_adjacent && colon == scan_start {
            cursor += colon + 1;
            continue;
        }

        let value_start = colon + 1;
        let value_end = remaining[value_start..]
            .find(['/', '?', '#'])
            .map_or(remaining.len(), |i| value_start + i);
        let value = &remaining[value_start..value_end];

        let is_port = is_port_like(value);
        if value.is_empty() || is_port {
            cursor += value_end.max(colon + 1);
            continue;
        }

        return format!(
            "{}{}:***{}",
            &raw[..authority_start],
            &authority[..cursor + colon],
            &authority[cursor + value_end..]
        );
    }
}

/// [`redact_userinfo`]'s fallback for a *parseable* `raw` whose scheme has an empty authority
/// (`host() == None`) because it uses some `scheme:/path` form rather than `scheme://host`
/// (#811) — `raw` is scanned for a userinfo-shaped path segment instead of trusting the
/// already-empty `username()`/`password()`.
///
/// `path_start` (right after the scheme's first `:`) is found textually via `raw.find(':')`
/// rather than derived from `url.scheme().len()`, since `Url::parse` strips leading
/// whitespace/C0-control bytes before computing the scheme — a length-based offset would
/// misalign against `raw` for such an input, even though `raw`'s own first `:` still always
/// marks the scheme separator (M2 finding).
///
/// From `path_start` to the end of `raw`, this does **not** stop at the first `/`, `?`, or `#`:
/// this shape has no real host segment to bound the scan against (the `/` right after the
/// scheme starts an opaque-ish path, not a host/path boundary), so an authority-shaped scan
/// would stop too early (S1 finding, e.g. `c:///user:hunter2@evil`'s credential sits past three
/// slashes) — and, for the same reason, bounding the scan by the first `?`/`#` is exactly as
/// unsafe as bounding it by `/`: a password containing either character (#826, e.g.
/// `c:/user:pa?ss@evil`) would otherwise hide the `@` that follows it from the scan entirely.
///
/// Finding an `@` is not by itself proof of a credential (S2 finding): an ordinary path can
/// contain one too (`file:///home/user@example/file`, an npm-scoped `npm:/@scope/pkg@1.0.0`,
/// a `deps-nuget` local/UNC feed path like `C:/Users/john.doe@corp/project`, or —
/// `file:///C:/Users/john.doe@corp/project`, a second S2 finding — the same path with a
/// `file://` scheme, whose drive-letter colon must not itself be mistaken for credential
/// evidence). Delegated to [`find_credential_at`]: only an `@` whose own since-the-previous-`@`
/// segment contains a non-drive-letter `:` — i.e. looks like `user:pass`, not an ordinary path
/// component or a `C:\`/`c:/` drive prefix — is treated as a credential, and among several such
/// candidates the last one wins (S3 finding, e.g. `c:/user:hunter2@evil/pkg@1.0.0` — the
/// *trailing* `pkg@1.0.0` `@` has no `:` in its own segment and must not be mistaken for the
/// redaction point, silently leaving `user:hunter2@evil` unredacted). This also subsumes the
/// empty-userinfo guard (see [`redact_userinfo_unparseable`]'s own bounded-`@` pass): an `@`
/// with an empty segment before it has no `:` either, so it is never mistaken for a credential.
///
/// Delimiting each `@`'s segment by the *previous* `@` (not the nearest preceding `/`, as an
/// earlier revision did) is what closes #826's password-containing-`/` gap: `c:/user:pa/ss@evil`
/// has no earlier `@`, so the whole `/user:pa/ss` since the start of the path is one segment,
/// and its `:` is found regardless of the `/` sitting between it and the `@`.
///
/// This heuristic can still over-redact a legitimate colon-containing path segment that isn't
/// a credential at all (e.g. `c:/logs/12:30@host/x`, a timestamp-like directory name) — an
/// accepted false-positive trade-off in exchange for never missing a real credential.
///
/// When no credential-shaped `@` is found but at least one `@` is present, `raw` is returned
/// unchanged — the same call as `find_credential_at` returning `None` above cannot distinguish
/// "no `@` at all" from "an `@` that isn't credential-shaped", so this checks for either
/// explicitly. When there is no `@` anywhere in `region`, this instead falls through to
/// [`redact_colon_credential`] (#818): a colon-separated credential with no `@` at all (e.g.
/// `token:/hunter2:secret`) is a distinct detection problem #811's original `@`-based scan never
/// covered, and reuses the same chokepoint [`redact_userinfo_unparseable`] already routes
/// through for its own no-`@` case, rather than reimplementing its host:port/IPv6/drive-letter
/// carve-outs here. This does extend [`redact_colon_credential`]'s existing documented
/// false-positive class to opaque-path values too (M2 finding, e.g. a Maven coordinate
/// `mvn:/com.google.guava:guava/1.0` → `mvn:/com.google.guava:***`, or an npm-scoped
/// `@scope/pkg:1.0.0` → `@scope/pkg:***`) — accepted for the same reason the original class was:
/// this fallback only ever feeds tracing/log/error output, never a value used for further
/// parsing or comparison.
// `path_start` is an ASCII ':' byte index; `at` comes from `find_credential_at`'s own
// `match_indices` scan of ASCII '@' bytes on `raw` from that point on, so every slice bound is
// always a char boundary.
#[allow(
    clippy::string_slice,
    reason = "all slice bounds are ASCII byte offsets from `find`/`match_indices`, never \
              landing inside a multi-byte character"
)]
fn redact_userinfo_opaque_path(raw: &str) -> String {
    let path_start = raw.find(':').map_or(0, |scheme_end| scheme_end + 1);
    let region = &raw[path_start..];
    match find_credential_at(region) {
        Some(at) => format!("{}***@{}", &raw[..path_start], &region[at + 1..]),
        None if region.contains('@') => raw.to_string(),
        None => redact_colon_credential(raw, path_start, region),
    }
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
    reason = "`end` comes from `find` of ASCII '?'/'#' bytes on the already-redacted \
              string, so it always lands on a valid char boundary"
)]
pub fn url_for_tracing(raw: &str) -> String {
    let without_userinfo = redact_userinfo(raw);
    let end = without_userinfo
        .find(['?', '#'])
        .unwrap_or(without_userinfo.len());
    without_userinfo[..end].to_string()
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

    /// Documented limitations (impl-critic questions, accepted as-is): a bracket-adjacent
    /// colon is *never* redacted regardless of what follows it (required to keep `[::1]:abc`
    /// unchanged), so a credential in that exact position is shape-indistinguishable from a
    /// real port and stays unredacted; and a credential that happens to be 1-5 ASCII digits
    /// collides with the `host:port` carve-out.
    #[test]
    fn test_url_for_tracing_colon_credential_documented_collisions() {
        assert_eq!(url_for_tracing("[::1]:glpat-SECRET"), "[::1]:glpat-SECRET");
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
    /// colon-credential fallback must leave every one of them byte-for-byte unchanged.
    #[test]
    fn test_url_for_tracing_colon_credential_false_positive_carve_outs() {
        let unchanged = [
            "gitlab.corp:8443",
            "gitlab.corp:8443/api",
            "git.corp:8443/*",
            "https://gitlab.corp:8443/api/v4",
            "https://host:99999/x",
            "[::1]:8443",
            "[::1]:abc",
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
        let redacted = redact_userinfo("https://glpat-SECRET@gitlab.corp:notaport/x");
        assert!(!redacted.contains("glpat-SECRET"), "redacted={redacted:?}");
        assert_eq!(redacted, "https://***@gitlab.corp:notaport/x");
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

        let redacted = redact_userinfo("user:hunter2@evil@host:notaport/x");
        assert!(!redacted.contains("hunter2"), "redacted={redacted:?}");
        assert_eq!(redacted, "***@host:notaport/x");
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

    /// impl-critic M3 (completeness_check), resolved as a side effect of code-review Finding 2:
    /// an IPv6 host with a malformed (non-numeric) port used to be over-redacted, because
    /// `bounded_has_credential_colon` saw `[::1]` itself as containing further `:`s (no
    /// bracket-adjacent carve-out) and triggered the widened scan. Now that
    /// `bounded_has_credential_colon` strips a leading bracket and its port-separator colon
    /// unconditionally — matching `redact_colon_credential`'s own bracket-adjacent carve-out,
    /// which never redacts that colon regardless of what follows it either — this stays a no-op
    /// like the well-formed-port case, not just the previously-accepted over-redaction.
    #[test]
    fn test_redact_userinfo_unparseable_ipv6_malformed_port_is_noop() {
        assert_eq!(
            redact_userinfo("https://[::1]:notaport/x@y"),
            "https://[::1]:notaport/x@y"
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
}
