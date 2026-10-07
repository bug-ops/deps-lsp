//! Process-wide allowlist of private registry hosts, and the single reachability decision.
//!
//! `registries.workspace_registries = "all"` is a repository-controllable setting, so it cannot
//! by itself authorize reaching a private host. The authority lives here instead: an allowlist
//! read only from the `DEPS_LSP_PRIVATE_REGISTRY_HOSTS` environment variable, with no
//! `Deserialize` impl and no public constructor from an arbitrary string, so settings, config
//! files and manifests cannot produce one.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use ipnet::IpNet;

use super::{
    HostClass, WorkspaceRegistryAccess, classify_addr, classify_ip, classify_name, unwrap_mapped_v4,
};

/// Environment variable holding the comma-separated private registry allowlist.
pub const PRIVATE_REGISTRY_HOSTS_ENV: &str = "DEPS_LSP_PRIVATE_REGISTRY_HOSTS";

const MIN_V4_PREFIX: u8 = super::min_v4_prefix!();
const MIN_V6_PREFIX: u8 = super::min_v6_prefix!();

/// Why one allowlist entry was rejected. Deliberately carries no part of the entry text, so a
/// rejection can be logged and shown to the user without echoing a mistyped secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EntryRejection {
    /// The entry (or the whole value) is empty, e.g. from a stray comma.
    #[error("empty entry")]
    Empty,
    /// The value is not valid Unicode.
    #[error("value is not valid unicode")]
    NotUnicode,
    /// A port, path, userinfo, wildcard, bracket, or other residue that is not a bare host.
    #[error("entry must be a bare CIDR, IP address, or host name (no port, path, wildcard)")]
    Malformed,
    /// A host name that is not lowercase ASCII (punycode) without a trailing dot.
    #[error("host name must be lowercase ASCII (punycode) without a trailing dot")]
    NotNormalized,
    /// A CIDR range so wide it would recreate "allow everything".
    #[error(
        "prefix is too short (minimum /{} for IPv4, /{} for IPv6)",
        MIN_V4_PREFIX,
        MIN_V6_PREFIX
    )]
    PrefixTooShort,
}

/// The first rejected entry of an invalid `DEPS_LSP_PRIVATE_REGISTRY_HOSTS` value.
///
/// Identifies the entry by position only; see [`EntryRejection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("entry #{index} of DEPS_LSP_PRIVATE_REGISTRY_HOSTS rejected: {reason}")]
pub struct PrivateRegistryAllowlistError {
    index: usize,
    reason: EntryRejection,
}

impl PrivateRegistryAllowlistError {
    /// Zero-based position of the rejected entry.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Why the entry was rejected.
    #[must_use]
    pub const fn reason(&self) -> EntryRejection {
        self.reason
    }
}

/// Hosts and CIDR ranges a [`WorkspaceRegistryAccess::All`] policy may reach in addition to
/// public hosts.
///
/// Constructed only through [`Self::from_env`] (and [`Self::empty`]); fields are private and
/// there is no `Deserialize` impl. An allowlisted host is reachable on **any** port, so list
/// registry hosts or narrow CIDRs only.
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::PrivateRegistryAllowlist;
///
/// assert!(PrivateRegistryAllowlist::empty().is_empty());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivateRegistryAllowlist {
    nets: Vec<IpNet>,
    hosts: Vec<String>,
}

/// Result of reading [`PRIVATE_REGISTRY_HOSTS_ENV`].
///
/// An invalid value never yields a partial allowlist: it is reported as [`Self::Invalid`] and
/// [`Self::allowlist`] is empty, so it fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistOutcome {
    /// Unset, empty, `0`, or `false`: no private host is reachable.
    Unset,
    /// A valid, non-empty allowlist.
    Parsed(Arc<PrivateRegistryAllowlist>),
    /// At least one entry was rejected; no private host is reachable.
    Invalid(PrivateRegistryAllowlistError),
}

impl AllowlistOutcome {
    /// The allowlist to enforce: empty unless the value parsed.
    #[must_use]
    pub fn allowlist(&self) -> Arc<PrivateRegistryAllowlist> {
        match self {
            Self::Parsed(allowlist) => Arc::clone(allowlist),
            Self::Unset | Self::Invalid(_) => Arc::new(PrivateRegistryAllowlist::empty()),
        }
    }

    /// Builds a parsed outcome from literal entries; panics on an invalid entry.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test(entries: &[&str]) -> Self {
        Self::Parsed(Arc::new(PrivateRegistryAllowlist::for_test(entries)))
    }

    /// An [`Self::Invalid`] outcome, for tests of the invalid-variable paths.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub const fn invalid_for_test() -> Self {
        Self::Invalid(PrivateRegistryAllowlistError {
            index: 0,
            reason: EntryRejection::Malformed,
        })
    }
}

impl PrivateRegistryAllowlist {
    /// An allowlist that permits nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether the allowlist permits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty() && self.hosts.is_empty()
    }

    /// Reads [`PRIVATE_REGISTRY_HOSTS_ENV`]: a comma-separated list of CIDR ranges, bare IPs and
    /// exact lowercase host names.
    ///
    /// Unset, empty, `0` and `false` give [`AllowlistOutcome::Unset`] silently. Any invalid entry
    /// invalidates the whole variable (logged once, without the entry text) and the allowlist
    /// stays empty.
    #[must_use]
    pub fn from_env() -> AllowlistOutcome {
        Self::outcome_of(std::env::var_os(PRIVATE_REGISTRY_HOSTS_ENV).as_deref())
    }

    /// [`Self::from_env`] over an already-read raw value.
    pub(crate) fn outcome_of(value: Option<&std::ffi::OsStr>) -> AllowlistOutcome {
        let outcome = Self::from_os_value(value);
        if let AllowlistOutcome::Invalid(error) = &outcome {
            tracing::warn!(%error, "ignoring invalid private registry allowlist; no private host is reachable");
        }
        outcome
    }

    fn from_os_value(value: Option<&std::ffi::OsStr>) -> AllowlistOutcome {
        match value {
            None => AllowlistOutcome::Unset,
            Some(raw) => match raw.to_str() {
                Some(text) => Self::from_value(text),
                None => AllowlistOutcome::Invalid(PrivateRegistryAllowlistError {
                    index: 0,
                    reason: EntryRejection::NotUnicode,
                }),
            },
        }
    }

    fn from_value(value: &str) -> AllowlistOutcome {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed == "0" || trimmed.eq_ignore_ascii_case("false") {
            return AllowlistOutcome::Unset;
        }
        let mut allowlist = Self::empty();
        for (index, entry) in trimmed.split(',').enumerate() {
            match parse_entry(entry.trim()) {
                Ok(Entry::Net(net)) => allowlist.nets.push(net),
                Ok(Entry::Host(host)) => allowlist.hosts.push(host),
                Err(reason) => {
                    return AllowlistOutcome::Invalid(PrivateRegistryAllowlistError {
                        index,
                        reason,
                    });
                }
            }
        }
        AllowlistOutcome::Parsed(Arc::new(allowlist))
    }

    /// Builds an allowlist from literal entries; panics on an invalid entry.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test(entries: &[&str]) -> Self {
        match Self::from_value(&entries.join(",")) {
            AllowlistOutcome::Parsed(allowlist) => Arc::unwrap_or_clone(allowlist),
            AllowlistOutcome::Unset => Self::empty(),
            AllowlistOutcome::Invalid(error) => panic!("invalid test allowlist: {error}"),
        }
    }

    fn contains_ip(&self, ip: IpAddr) -> bool {
        let ip = unwrap_mapped_v4(ip);
        self.nets.iter().any(|net| net.contains(&ip))
    }

    fn has_nets(&self) -> bool {
        !self.nets.is_empty()
    }

    fn contains_name(&self, name: &str) -> bool {
        self.hosts.iter().any(|host| host == name)
    }
}

enum Entry {
    Net(IpNet),
    Host(String),
}

fn parse_entry(entry: &str) -> Result<Entry, EntryRejection> {
    if entry.is_empty() {
        return Err(EntryRejection::Empty);
    }
    if let Ok(net) = IpNet::from_str(entry) {
        return checked_net(net.trunc()).map(Entry::Net);
    }
    if let Ok(ip) = IpAddr::from_str(entry) {
        return Ok(Entry::Net(IpNet::from(unwrap_mapped_v4(ip))));
    }
    if entry.contains([':', '/', '@', '*', '[', ']']) || entry.contains(char::is_whitespace) {
        return Err(EntryRejection::Malformed);
    }
    match url::Host::parse(entry) {
        Ok(url::Host::Ipv4(v4)) => Ok(Entry::Net(IpNet::from(IpAddr::V4(v4)))),
        Ok(url::Host::Ipv6(v6)) => Ok(Entry::Net(IpNet::from(unwrap_mapped_v4(IpAddr::V6(v6))))),
        Ok(url::Host::Domain(domain)) => normalized_domain(entry, &domain).map(Entry::Host),
        Err(_) => Err(EntryRejection::Malformed),
    }
}

fn checked_net(net: IpNet) -> Result<IpNet, EntryRejection> {
    let min = match net {
        IpNet::V4(_) => MIN_V4_PREFIX,
        IpNet::V6(_) => MIN_V6_PREFIX,
    };
    if net.prefix_len() < min {
        return Err(EntryRejection::PrefixTooShort);
    }
    Ok(net)
}

fn normalized_domain(entry: &str, parsed: &str) -> Result<String, EntryRejection> {
    let ascii = parsed
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    if !ascii || parsed.split('.').any(str::is_empty) {
        return Err(EntryRejection::Malformed);
    }
    if parsed != entry {
        return Err(EntryRejection::NotNormalized);
    }
    Ok(parsed.to_owned())
}

/// What a reachability check is about: the host a URL declares, or an address a name resolved
/// to at connect time.
#[derive(Debug, Clone)]
pub(crate) enum Target<'a> {
    Declared(url::Host<&'a str>),
    Resolved { name: &'a str, ip: IpAddr },
}

impl Target<'_> {
    fn class(&self) -> HostClass {
        match self {
            Self::Declared(url::Host::Domain(name)) => classify_name(name),
            Self::Declared(url::Host::Ipv4(v4)) => classify_ip(unwrap_mapped_v4(IpAddr::V4(*v4))),
            Self::Declared(url::Host::Ipv6(v6)) => classify_ip(unwrap_mapped_v4(IpAddr::V6(*v6))),
            Self::Resolved { ip, .. } => classify_addr(*ip),
        }
    }

    fn defers_to_connect_guard(
        &self,
        class: HostClass,
        allowlist: &PrivateRegistryAllowlist,
    ) -> bool {
        matches!(self, Self::Declared(url::Host::Domain(_)))
            && class == HostClass::InternalName
            && allowlist.has_nets()
    }

    fn allowlisted(&self, allowlist: &PrivateRegistryAllowlist) -> bool {
        match self {
            Self::Declared(url::Host::Domain(name)) => allowlist.contains_name(name),
            Self::Declared(url::Host::Ipv4(v4)) => allowlist.contains_ip(IpAddr::V4(*v4)),
            Self::Declared(url::Host::Ipv6(v6)) => allowlist.contains_ip(IpAddr::V6(*v6)),
            Self::Resolved { name, ip } => {
                allowlist.contains_ip(*ip) || allowlist.contains_name(name)
            }
        }
    }
}

/// A value copy of a policy's level and allowlist, taken once when a transport is built so its
/// guard and its cache-key namespace agree.
#[derive(Debug, Clone)]
pub(crate) struct AccessSnapshot {
    pub(crate) level: WorkspaceRegistryAccess,
    pub(crate) allowlist: Arc<PrivateRegistryAllowlist>,
}

impl AccessSnapshot {
    /// The one reachability decision shared by parse time, redirect hops and connect time.
    ///
    /// `Off` permits nothing; `PublicOnly` only [`HostClass::Global`]; `All` additionally the
    /// allowlist, and never a [`HostClass::never_a_registry`] class (test builds treat
    /// loopback as allowlisted, mirroring the redirect-hop carve-out).
    ///
    /// A declared [`HostClass::InternalName`] (`*.internal`, `*.local`, single label) cannot be
    /// placed in a CIDR without resolving it, so with a non-empty CIDR list it is deferred to the
    /// connect-time guard (resolved IP in a CIDR, or a vouching name) instead of being refused
    /// here; parse time, redirect hops and connect time then agree.
    pub(crate) fn permits(&self, target: Target<'_>) -> bool {
        let class = target.class();
        match self.level {
            WorkspaceRegistryAccess::Off => false,
            WorkspaceRegistryAccess::PublicOnly => class == HostClass::Global,
            WorkspaceRegistryAccess::All => {
                class == HostClass::Global
                    || test_loopback(class)
                    || (!class.never_a_registry()
                        && (target.allowlisted(&self.allowlist)
                            || target.defers_to_connect_guard(class, &self.allowlist)))
            }
        }
    }

    pub(crate) fn permits_url(&self, url: &url::Url) -> bool {
        url.host()
            .is_some_and(|host| self.permits(Target::Declared(host)))
    }
}

const fn test_loopback(class: HostClass) -> bool {
    cfg!(any(test, feature = "test-util")) && matches!(class, HostClass::Loopback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn parsed(value: &str) -> PrivateRegistryAllowlist {
        match PrivateRegistryAllowlist::from_value(value) {
            AllowlistOutcome::Parsed(allowlist) => Arc::unwrap_or_clone(allowlist),
            other => panic!("expected Parsed, got {other:?}"),
        }
    }

    fn rejection(value: &str) -> EntryRejection {
        match PrivateRegistryAllowlist::from_value(value) {
            AllowlistOutcome::Invalid(error) => error.reason(),
            other => panic!("expected Invalid for {value:?}, got {other:?}"),
        }
    }

    fn snapshot(level: WorkspaceRegistryAccess, entries: &[&str]) -> AccessSnapshot {
        AccessSnapshot {
            level,
            allowlist: Arc::new(PrivateRegistryAllowlist::for_test(entries)),
        }
    }

    fn declared(url: &str) -> url::Url {
        url::Url::parse(url).unwrap()
    }

    #[test]
    fn unset_like_values_are_silent_and_empty() {
        for value in ["", "  ", "0", "false", "FALSE"] {
            assert_eq!(
                PrivateRegistryAllowlist::from_value(value),
                AllowlistOutcome::Unset,
                "{value:?}"
            );
        }
        assert_eq!(
            PrivateRegistryAllowlist::from_os_value(None),
            AllowlistOutcome::Unset
        );
    }

    #[test]
    fn parses_cidr_ip_and_host_entries() {
        let allowlist = parsed("10.0.0.0/8, 192.168.1.5, registry.corp.example ,fd00::/16");
        assert!(allowlist.contains_ip("10.9.9.9".parse().unwrap()));
        assert!(allowlist.contains_ip("192.168.1.5".parse().unwrap()));
        assert!(!allowlist.contains_ip("192.168.1.6".parse().unwrap()));
        assert!(allowlist.contains_ip("fd00::1".parse().unwrap()));
        assert!(allowlist.contains_name("registry.corp.example"));
        assert!(!allowlist.contains_name("other.corp.example"));
    }

    #[test]
    fn whatwg_ipv4_forms_are_stored_as_nets_not_names() {
        let allowlist = parsed("10.1");
        assert!(allowlist.hosts.is_empty());
        assert!(allowlist.contains_ip("10.0.0.1".parse().unwrap()));
        assert!(parsed("0x0a000001").contains_ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn mapped_addresses_are_unwrapped_on_both_sides() {
        let allowlist = parsed("::ffff:10.0.0.1");
        assert!(allowlist.contains_ip("10.0.0.1".parse().unwrap()));
        let v4_net = parsed("10.0.0.0/8");
        assert!(v4_net.contains_ip("::ffff:10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn rejects_ports_paths_wildcards_brackets_and_userinfo() {
        for value in [
            "registry.corp:8443",
            "registry.corp/path",
            "*.corp.example",
            "[::1]",
            "user@registry.corp",
            "10.0.0.1:8080",
            "a b.corp",
            "a..corp",
        ] {
            assert_eq!(rejection(value), EntryRejection::Malformed, "{value:?}");
        }
    }

    #[test]
    fn rejects_non_normalized_host_names() {
        assert_eq!(rejection("Registry.Corp"), EntryRejection::NotNormalized);
        assert_eq!(rejection("registry.corp."), EntryRejection::Malformed);
    }

    #[test]
    fn rejects_short_prefixes_including_zero() {
        for value in ["0.0.0.0/0", "10.0.0.0/7", "::/0", "fc00::/15"] {
            assert_eq!(
                rejection(value),
                EntryRejection::PrefixTooShort,
                "{value:?}"
            );
        }
        parsed("10.0.0.0/8");
        parsed("fd00::/16");
    }

    #[test]
    fn one_bad_entry_invalidates_the_whole_value_without_echoing_it() {
        let AllowlistOutcome::Invalid(error) =
            PrivateRegistryAllowlist::from_value("10.0.0.0/8,secret-host:99")
        else {
            panic!("expected Invalid");
        };
        assert_eq!(error.index(), 1);
        assert!(!error.to_string().contains("secret-host"));
        assert!(
            PrivateRegistryAllowlist::from_value("10.0.0.0/8,secret-host:99")
                .allowlist()
                .is_empty()
        );
    }

    #[test]
    fn trailing_comma_is_rejected() {
        assert_eq!(rejection("10.0.0.0/8,"), EntryRejection::Empty);
    }

    #[test]
    fn non_unicode_value_is_invalid() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let raw = std::ffi::OsStr::from_bytes(&[0xff, 0xfe]);
            assert_matches!(
                PrivateRegistryAllowlist::from_os_value(Some(raw)),
                AllowlistOutcome::Invalid(_)
            );
        }
    }

    #[test]
    fn all_with_empty_allowlist_equals_public_only() {
        let all = snapshot(WorkspaceRegistryAccess::All, &[]);
        let public = snapshot(WorkspaceRegistryAccess::PublicOnly, &[]);
        for url in [
            "https://index.crates.io/",
            "https://10.0.0.1/",
            "https://192.168.1.1/",
            "https://registry.corp.internal/",
            "https://169.254.169.254/",
        ] {
            let url = declared(url);
            assert_eq!(all.permits_url(&url), public.permits_url(&url), "{url}");
        }
    }

    #[test]
    fn permits_matrix_for_declared_targets() {
        let off = snapshot(WorkspaceRegistryAccess::Off, &["10.0.0.0/8"]);
        let public = snapshot(WorkspaceRegistryAccess::PublicOnly, &["10.0.0.0/8"]);
        let all = snapshot(
            WorkspaceRegistryAccess::All,
            &["10.0.0.0/8", "registry.corp.internal"],
        );
        let global = declared("https://index.crates.io/");
        let listed_ip = declared("https://10.0.0.1/");
        let unlisted_ip = declared("https://192.168.1.1/");
        let listed_name = declared("https://registry.corp.internal/");
        let unlisted_name = declared("https://other.corp.internal/");

        assert!(!off.permits_url(&global));
        assert!(public.permits_url(&global));
        assert!(!public.permits_url(&listed_ip));
        assert!(all.permits_url(&global));
        assert!(all.permits_url(&listed_ip));
        assert!(all.permits_url(&listed_name));
        assert!(!all.permits_url(&unlisted_ip));
        // Internal name + non-empty CIDR list: deferred to the connect-time guard.
        assert!(all.permits_url(&unlisted_name));
    }

    #[test]
    fn internal_names_are_blocked_without_cidrs_and_deferred_with_them() {
        let names_only = snapshot(WorkspaceRegistryAccess::All, &["registry.corp.internal"]);
        let with_cidr = snapshot(WorkspaceRegistryAccess::All, &["10.0.0.0/8"]);
        let empty = snapshot(WorkspaceRegistryAccess::All, &[]);
        for url in [
            "https://nexus.corp.internal/",
            "https://nexus.corp.local/",
            "https://nexus/",
        ] {
            let url = declared(url);
            assert!(!empty.permits_url(&url), "{url}");
            assert!(!names_only.permits_url(&url), "{url}");
            assert!(with_cidr.permits_url(&url), "{url}");
        }
        assert!(!with_cidr.permits_url(&declared("https://metadata.google.internal/")));
        assert!(
            !snapshot(WorkspaceRegistryAccess::PublicOnly, &["10.0.0.0/8"])
                .permits_url(&declared("https://nexus/"))
        );
    }

    #[test]
    fn deferred_internal_name_is_still_gated_by_the_connect_time_ip() {
        let all = snapshot(WorkspaceRegistryAccess::All, &["10.0.0.0/8"]);
        let resolved = |ip: &str| Target::Resolved {
            name: "nexus.corp.internal",
            ip: ip.parse().unwrap(),
        };
        assert!(all.permits(resolved("10.1.1.1")));
        assert!(!all.permits(resolved("192.168.1.1")));
    }

    #[test]
    fn empty_middle_entry_is_rejected() {
        assert_eq!(rejection("10.0.0.0/8,,10.1.0.0/16"), EntryRejection::Empty);
    }

    #[test]
    fn duplicate_entries_are_accepted_and_harmless() {
        let allowlist = parsed("10.0.0.0/8,10.0.0.0/8,registry.corp,registry.corp");
        assert!(allowlist.contains_ip("10.2.3.4".parse().unwrap()));
        assert!(allowlist.contains_name("registry.corp"));
    }

    #[test]
    fn non_ascii_and_uppercase_idn_hosts_are_rejected_punycode_accepted() {
        assert_matches!(
            rejection("münchen.example"),
            EntryRejection::Malformed | EntryRejection::NotNormalized
        );
        assert!(parsed("xn--mnchen-3ya.example").contains_name("xn--mnchen-3ya.example"));
    }

    #[test]
    fn ipv6_zone_ids_are_rejected() {
        assert_eq!(rejection("fe80::1%eth0"), EntryRejection::Malformed);
        assert_eq!(rejection("fd00::1%25eth0"), EntryRejection::Malformed);
    }

    #[test]
    fn allowlisted_host_is_reachable_on_any_port() {
        let all = snapshot(WorkspaceRegistryAccess::All, &["10.0.0.1"]);
        assert!(all.permits_url(&declared("https://10.0.0.1:1/")));
        assert!(all.permits_url(&declared("https://10.0.0.1:65535/")));
    }

    #[test]
    fn never_a_registry_classes_stay_blocked_under_a_matching_allowlist() {
        let all = snapshot(
            WorkspaceRegistryAccess::All,
            &["169.254.0.0/16", "metadata.google.internal", "192.0.0.0/24"],
        );
        assert!(!all.permits_url(&declared("https://169.254.169.254/")));
        assert!(!all.permits_url(&declared("https://metadata.google.internal/")));
        assert!(!all.permits_url(&declared("https://192.0.0.170/")));
    }

    #[test]
    fn test_builds_treat_loopback_as_allowlisted_only_under_all() {
        let loopback = declared("https://127.0.0.1:9/");
        assert!(snapshot(WorkspaceRegistryAccess::All, &[]).permits_url(&loopback));
        assert!(!snapshot(WorkspaceRegistryAccess::PublicOnly, &[]).permits_url(&loopback));
        assert!(!snapshot(WorkspaceRegistryAccess::Off, &[]).permits_url(&loopback));
    }

    #[test]
    fn resolved_target_requires_global_net_or_vouching_name() {
        let all = snapshot(
            WorkspaceRegistryAccess::All,
            &["10.0.0.0/8", "registry.corp.internal"],
        );
        let resolved = |name, ip: &str| Target::Resolved {
            name,
            ip: ip.parse().unwrap(),
        };
        assert!(all.permits(resolved("index.crates.io", "93.184.216.34")));
        assert!(all.permits(resolved("anything.example", "10.1.1.1")));
        assert!(all.permits(resolved("registry.corp.internal", "192.168.1.1")));
        assert!(!all.permits(resolved("rebinder.example", "192.168.1.1")));
        assert!(!all.permits(resolved("registry.corp.internal", "169.254.169.254")));
    }

    #[test]
    fn host_class_global_name_passes_public_only_without_allowlist() {
        let public = snapshot(WorkspaceRegistryAccess::PublicOnly, &[]);
        assert!(public.permits(Target::Resolved {
            name: "index.crates.io",
            ip: "93.184.216.34".parse().unwrap(),
        }));
    }
}
