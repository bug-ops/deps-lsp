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

use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, Ordering};

/// Classification of a URL's host, for [`RegistryAccessPolicy`] to evaluate against
/// [`WorkspaceRegistryAccess`].
///
/// Computed from the URL alone (see [`classify_host`]) — never from a DNS resolution, so an
/// attacker-controlled hostname that merely *resolves* to a blocked range is not caught here
/// (the residual risk spec NFR-003/§5 of the plan documents; closing it needs a
/// `reqwest::dns::Resolve` filter, deferred as a follow-up).
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

/// Unwraps an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its embedded IPv4 form, so
/// classification cannot be bypassed by writing the same address in its mapped form (e.g.
/// `::ffff:169.254.169.254`).
///
/// Deliberately does **not** additionally unwrap the deprecated IPv4-*compatible* form
/// (`::a.b.c.d`, RFC 4291 §2.5.5.1, no `ffff` prefix): `Ipv6Addr::to_ipv4()` treats *any*
/// address with its first 96 bits zero as embedding an IPv4 address, which would
/// misclassify `::1` (loopback) as `0.0.0.1` and `::` (unspecified) as `0.0.0.0` — a
/// narrower, *new* bypass in exchange for closing a narrower, legacy one. Modern network
/// stacks generally do not route this deprecated form at all, so it is accepted as
/// low-real-world-risk (impl-critic finding, unwrap-mapped-v6 is the actively-exploitable
/// form and is handled above).
fn unwrap_mapped_v4(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

/// Classifies `addr` (already unwrapped of any IPv4-mapping) into a [`HostClass`].
fn classify_ip(addr: IpAddr) -> HostClass {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                HostClass::Loopback
            } else if v4 == std::net::Ipv4Addr::new(169, 254, 169, 254) {
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

/// The user-facing policy governing whether a workspace-declared registry index is ever
/// fetched at all.
///
/// Applied **only** to workspace-provenance URLs (a `Cargo.toml`/`.cargo/config.toml` value
/// found inside the opened workspace) — a `$CARGO_HOME`-provenance index is the user's own
/// trusted configuration and is never policy-checked, under any variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

    /// Numeric encoding for [`RegistryAccessPolicy`]'s lock-free storage.
    const fn to_u8(self) -> u8 {
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
    pub fn set(&self, value: WorkspaceRegistryAccess) {
        self.0.store(value.to_u8(), Ordering::Relaxed);
    }
}

impl Default for RegistryAccessPolicy {
    fn default() -> Self {
        Self::new(WorkspaceRegistryAccess::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_class(url: &str) -> HostClass {
        classify_host(&url::Url::parse(url).unwrap())
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
}
