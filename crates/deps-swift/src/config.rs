//! `registries.json` discovery, strict decoding, tier merging and registry trust.
//!
//! Resolves an `.package(id:)` dependency's SE-0292 registry the way SwiftPM does, from the
//! project tier (`<dir of Package.swift>/.swiftpm/configuration/registries.json`) merged over
//! the user tier (see [`UserConfigPath`]).
//!
//! # Security model (read before touching this module)
//!
//! A repository's own `registries.json` is attacker-controlled the moment it is opened, so:
//!
//! - **Trust is a function of the URL alone.** A registry URL is [`RegistryTrust::Trusted`] iff
//!   it equals a URL declared in the user tier (the user's own file), whichever tier declared it
//!   in the current workspace; otherwise it is [`RegistryTrust::WorkspaceDeclared`]. Trust,
//!   transport and credential binding therefore never differ between two workspaces sharing a
//!   URL.
//! - **An unusable tier fails closed.** A tier that exists but cannot be used (unreadable, not a
//!   regular file, over the size cap, or failing SwiftPM's strict decode) makes every `id:`
//!   dependency unresolved, never a fallback to the other tier, so a broken file cannot redirect
//!   private scope names to another registry.
//! - **The auth type comes from the user tier only**, keyed by `RegistryHostKey`, and the
//!   credential is attached only to `Trusted` URLs (see `crate::auth::bind_credential`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use deps_core::net_policy::{
    BlockedHostReason, HostClass, IndexUrlError, InvalidEntry, PolicyGate, RedactedUrl,
    RegistryAccessPolicy, RegistryRejectionClassifier, RejectionOutcome, classify_host,
    validate_index_url,
};
use deps_core::parser::DependencySource;
use deps_core::{BlockedSourceClass, EcosystemId, RejectedSourceClass};
use serde::Deserialize;
use url::Url;

use deps_core::keychain_credentials::KeychainCredentialsHandle;
use deps_core::policy_config::KeychainCredentials;

use crate::auth::{
    CredentialLookup, KeychainBinding, RegistryAuth, SwiftCredentialSource, bind_credential,
};
use crate::keychain::KeychainStore;
use crate::package_location::RegistryScope;

const REGISTRIES_FILE: &str = "registries.json";

/// Project-tier `registries.json` location relative to the directory of `Package.swift`.
pub(crate) const PROJECT_REGISTRIES_SUFFIX: &str = ".swiftpm/configuration/registries.json";
const DEFAULT_KEY: &str = "[default]";
const MAX_WARNED_KEYS: usize = 256;

/// Why a `registries.json` tier, or the path to it, cannot be used.
///
/// Payload-free on purpose: serde messages can echo values from the file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RegistriesConfigError {
    /// Not a regular file, over the size cap, or unreadable.
    #[error("not a readable regular file within the size cap")]
    Unreadable,
    /// Not valid JSON, or a required field is missing or has the wrong type.
    #[error("malformed at line {line}, column {column}")]
    Malformed {
        /// 1-based line of the decode failure.
        line: usize,
        /// 1-based column of the decode failure.
        column: usize,
    },
    /// `version` is a number other than 1.
    #[error("unsupported version {0}")]
    UnsupportedVersion(u32),
    /// A key of `registries` is neither `[default]` nor a valid scope.
    #[error("a registry key is not a valid scope")]
    InvalidScopeKey,
    /// `security` is present but not an object.
    #[error("`security` is not an object")]
    SecurityNotAnObject,
    /// `XDG_CONFIG_HOME` is set but empty or not an absolute path.
    #[error("XDG_CONFIG_HOME is empty or not an absolute path")]
    InvalidXdgConfigHome,
}

/// The `authentication.<host>.type` of a registry host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SwiftAuthType {
    /// `Authorization: Basic base64(user:password)`.
    Basic,
    /// `Authorization: Bearer <token>`.
    Token,
}

/// A registry host as `authentication` keys it: lowercase punycode host plus an explicit
/// non-default port.
///
/// Built only by parsing `https://{key}` through [`url`], so `h:443` equals `h`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RegistryHostKey(String);

impl RegistryHostKey {
    /// Parses an `authentication` key (a bare `host` or `host:port`); `None` for anything else.
    pub(crate) fn parse(key: &str) -> Option<Self> {
        let url = Url::parse(&format!("https://{key}")).ok()?;
        let bare = url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none();
        bare.then(|| Self::of(&url)).flatten()
    }

    fn of(url: &Url) -> Option<Self> {
        let host = url.host_str()?;
        Some(Self(match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        }))
    }
}

/// One `registries.json` file, decoded and with every key validated; nothing is resolved yet.
#[derive(Debug, Default, Clone)]
pub(crate) struct RawRegistries {
    default: Option<String>,
    scoped: HashMap<RegistryScope, String>,
    authentication: HashMap<RegistryHostKey, SwiftAuthType>,
}

#[derive(Deserialize)]
struct FileDto {
    version: u32,
    registries: BTreeMap<String, RegistryDto>,
    #[serde(default)]
    authentication: BTreeMap<String, AuthenticationDto>,
    #[serde(default)]
    security: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RegistryDto {
    url: String,
    #[serde(rename = "supportsAvailability")]
    _supports_availability: Option<bool>,
}

#[derive(Deserialize)]
struct AuthenticationDto {
    #[serde(rename = "type")]
    auth_type: SwiftAuthType,
    #[serde(rename = "loginAPIPath")]
    _login_api_path: Option<String>,
}

/// Decodes `content` with SwiftPM's Codable strictness for the fields this crate consumes.
///
/// Unknown keys are ignored, and the contents of `security` are never inspected beyond being an
/// object, so a value newer than this crate knows never invalidates the file.
fn parse_registries(content: &str) -> Result<Arc<RawRegistries>, RegistriesConfigError> {
    let dto: FileDto =
        serde_json::from_str(content).map_err(|e| RegistriesConfigError::Malformed {
            line: e.line(),
            column: e.column(),
        })?;
    if dto.version != 1 {
        return Err(RegistriesConfigError::UnsupportedVersion(dto.version));
    }
    if dto.security.as_ref().is_some_and(|s| !s.is_object()) {
        return Err(RegistriesConfigError::SecurityNotAnObject);
    }

    let mut raw = RawRegistries::default();
    for (key, entry) in dto.registries {
        if key == DEFAULT_KEY {
            raw.default = Some(entry.url);
        } else {
            let scope = RegistryScope::parse(&key).ok_or(RegistriesConfigError::InvalidScopeKey)?;
            raw.scoped.insert(scope, entry.url);
        }
    }
    for (host, entry) in dto.authentication {
        match RegistryHostKey::parse(&host) {
            Some(key) => {
                raw.authentication.insert(key, entry.auth_type);
            }
            None => tracing::debug!("ignoring an authentication key that is not a host"),
        }
    }
    Ok(Arc::new(raw))
}

/// The state of one tier file.
#[derive(Debug, Clone)]
pub(crate) enum TierFile {
    /// The file does not exist.
    Absent,
    /// The file decoded successfully.
    Parsed(Arc<RawRegistries>),
    /// The file exists (or its path is invalid) but cannot be used.
    Unusable(RegistriesConfigError),
}

/// A bounded set of already-warned keys.
#[derive(Debug)]
struct WarnOnce<K>(Mutex<HashSet<K>>);

impl<K: std::hash::Hash + Eq> WarnOnce<K> {
    fn new() -> Self {
        Self(Mutex::new(HashSet::new()))
    }

    /// `true` the first time `key` is seen; the set is cleared once it reaches its bound.
    fn first_time(&self, key: K) -> bool {
        let mut seen = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.len() >= MAX_WARNED_KEYS {
            seen.clear();
        }
        seen.insert(key)
    }
}

/// Memoizes decoded `registries.json` files by mtime and debounces their warnings.
///
/// Caches only the raw decode; trust classification and policy gating re-run on every parse, so
/// a policy or user-tier change takes effect without invalidation.
#[derive(Debug)]
pub struct SwiftRegistriesCache {
    files: deps_core::MtimeFileCache<Result<Arc<RawRegistries>, RegistriesConfigError>>,
    warned: WarnOnce<(PathBuf, Option<SystemTime>)>,
    warned_entries: WarnOnce<String>,
}

impl Default for SwiftRegistriesCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SwiftRegistriesCache {
    /// Creates an empty cache.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_swift::config::SwiftRegistriesCache;
    ///
    /// let cache = SwiftRegistriesCache::new();
    /// assert!(format!("{cache:?}").contains("SwiftRegistriesCache"));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: deps_core::MtimeFileCache::new(
                deps_core::DEFAULT_MAX_CACHED_FILES,
                "swift registries",
            ),
            warned: WarnOnce::new(),
            warned_entries: WarnOnce::new(),
        }
    }

    /// Warns about each rejected registry entry once, not on every reparse.
    fn warn_invalid_entries(&self, config: &SwiftRegistriesConfig) {
        for invalid in config.invalid_entries() {
            if self
                .warned_entries
                .first_time(format!("{}\0{}", invalid.raw, invalid.reason))
            {
                tracing::warn!(
                    raw = %invalid.raw,
                    reason = %invalid.reason,
                    ecosystem = %EcosystemId::Swift,
                    "swift registry url failed validation"
                );
            }
        }
    }

    /// Classifies `path` as absent, parsed or unusable.
    ///
    /// Stats first because [`deps_core::MtimeFileCache::get_or_parse`] alone cannot tell an
    /// absent file from an unreadable one.
    fn read(&self, path: &Path) -> TierFile {
        let metadata = match deps_core::fs_probe::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return TierFile::Absent,
            Err(_) => return self.unusable(path, None, RegistriesConfigError::Unreadable),
        };
        let mtime = metadata.modified().ok();
        match self.files.get_or_parse(path, parse_registries) {
            None => self.unusable(path, mtime, RegistriesConfigError::Unreadable),
            Some(parsed) => match &*parsed {
                Ok(raw) => TierFile::Parsed(Arc::clone(raw)),
                Err(e) => self.unusable(path, mtime, e.clone()),
            },
        }
    }

    fn unusable(
        &self,
        path: &Path,
        mtime: Option<SystemTime>,
        error: RegistriesConfigError,
    ) -> TierFile {
        if self.warned.first_time((path.to_path_buf(), mtime)) {
            tracing::warn!(
                path = %path.display(),
                reason = %error,
                "swift registries.json is unusable; id: dependencies stay unresolved"
            );
        }
        TierFile::Unusable(error)
    }
}

/// Which platform's user-tier location applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserConfigPlatform {
    /// `~/Library/org.swift.swiftpm/configuration/registries.json`.
    MacOs,
    /// `$XDG_CONFIG_HOME/swiftpm/...` if set, else `~/.swiftpm/...`.
    Other,
}

impl UserConfigPlatform {
    /// The platform this binary was compiled for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other
        }
    }
}

/// Where the user-tier `registries.json` lives, computed once and never probed among candidates.
///
/// # Examples
///
/// ```
/// use deps_swift::config::{UserConfigPath, UserConfigPlatform};
/// use std::path::Path;
///
/// let home = Path::new("home");
/// let path = UserConfigPath::resolve(UserConfigPlatform::Other, Some(home), None);
/// let expected = home.join(".swiftpm").join("configuration").join("registries.json");
/// assert_eq!(path, UserConfigPath::Path(expected));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserConfigPath {
    /// The single user-tier file path.
    Path(PathBuf),
    /// `XDG_CONFIG_HOME` is set but empty or not absolute: the user tier is unusable.
    InvalidXdgConfigHome,
    /// No home directory and no usable `XDG_CONFIG_HOME`: there is no user tier.
    NoUserTier,
}

impl UserConfigPath {
    /// Computes the user-tier path for `platform` from the home directory and `XDG_CONFIG_HOME`.
    #[must_use]
    pub fn resolve(
        platform: UserConfigPlatform,
        home: Option<&Path>,
        xdg_config_home: Option<&OsStr>,
    ) -> Self {
        let tail = Path::new("configuration").join(REGISTRIES_FILE);
        match platform {
            UserConfigPlatform::MacOs => home.map_or(Self::NoUserTier, |home| {
                Self::Path(home.join("Library/org.swift.swiftpm").join(tail))
            }),
            UserConfigPlatform::Other => match xdg_config_home {
                Some(xdg) if xdg.is_empty() || !Path::new(xdg).is_absolute() => {
                    Self::InvalidXdgConfigHome
                }
                Some(xdg) => Self::Path(Path::new(xdg).join("swiftpm").join(tail)),
                None => home.map_or(Self::NoUserTier, |home| {
                    Self::Path(home.join(".swiftpm").join(tail))
                }),
            },
        }
    }

    /// Computes the path from the running process's platform, home directory and environment.
    #[must_use]
    pub fn from_environment() -> Self {
        Self::resolve(
            UserConfigPlatform::current(),
            dirs::home_dir().as_deref(),
            std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        )
    }
}

/// Whether a registry URL may receive the environment credential and skip the workspace policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryTrust {
    /// Declared in, or equal to a URL declared in, the user-level `registries.json`.
    Trusted,
    /// Declared only by the workspace: policy-gated, never authenticated.
    WorkspaceDeclared,
}

/// What the user tier establishes: the trust anchors and the authentication types.
#[derive(Debug, Default, Clone)]
pub(crate) struct UserTier {
    urls: HashSet<String>,
    authentication: HashMap<RegistryHostKey, SwiftAuthType>,
}

impl UserTier {
    fn from_raw(raw: &RawRegistries) -> Self {
        let urls = raw
            .default
            .iter()
            .chain(raw.scoped.values())
            .filter_map(|url| validate_shape(url, PolicyGate::Skip).ok())
            .map(|url| normalize(&url))
            .collect();
        Self {
            urls,
            authentication: raw.authentication.clone(),
        }
    }

    fn contains(&self, normalized: &str) -> bool {
        self.urls.contains(normalized)
    }

    pub(crate) fn auth_type_for(&self, host: &RegistryHostKey) -> Option<SwiftAuthType> {
        self.authentication.get(host).copied()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        urls: &[&str],
        authentication: HashMap<RegistryHostKey, SwiftAuthType>,
    ) -> Self {
        Self {
            urls: urls.iter().map(|url| (*url).to_string()).collect(),
            authentication,
        }
    }
}

/// Why a candidate registry URL was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SwiftRegistryUrlError {
    /// Not a URL, not https, carries userinfo, query or fragment, or is policy-blocked.
    #[error(transparent)]
    Url(#[from] IndexUrlError),
    /// A user-declared host that is never a registry (loopback, link-local, cloud metadata,
    /// unspecified, reserved); no setting unblocks it.
    #[error("host class {0} is never a registry")]
    NeverARegistryHost(HostClass),
}

impl BlockedHostReason for SwiftRegistryUrlError {
    fn blocked_host_class(&self) -> Option<HostClass> {
        match self {
            Self::Url(e) => e.blocked_host_class(),
            Self::NeverARegistryHost(_) => None,
        }
    }
}

impl RegistryRejectionClassifier for SwiftRegistryUrlError {
    fn rejection_reason(&self) -> RejectionOutcome {
        match self {
            Self::Url(e) => e.rejection_reason(),
            Self::NeverARegistryHost(_) => RejectionOutcome::IntentionallySilent,
        }
    }
}

/// A validated, normalized SE-0292 registry base URL with its [`RegistryTrust`].
///
/// An own type rather than `ValidatedRegistryUrl`, which cannot skip the policy for a trusted
/// URL. Normalized (lowercase host, default port dropped, no trailing `/`, path case kept) so
/// string equality is URL equality.
///
/// Obtained from [`ResolvedSwiftRegistry::url`], never constructed directly.
///
/// # Examples
///
/// ```
/// use deps_swift::config::RegistryTrust;
/// use deps_swift::{SwiftParseContext, parse_package_swift_with_context};
///
/// let dir = tempfile::tempdir().unwrap();
/// let config = dir.path().join(".swiftpm/configuration/registries.json");
/// std::fs::create_dir_all(config.parent().unwrap()).unwrap();
/// std::fs::write(
///     &config,
///     r#"{"registries": {"[default]": {"url": "https://Swift.Acme.dev:443/api/"}}, "version": 1}"#,
/// )
/// .unwrap();
/// let uri = url::Url::from_file_path(dir.path().join("Package.swift")).unwrap();
/// let parsed = parse_package_swift_with_context(
///     r#".package(id: "acme.net", from: "1.0.0")"#,
///     &uri,
///     &SwiftParseContext::default(),
/// )
/// .unwrap();
///
/// let url = &parsed.resolved_registries[0].url;
/// assert_eq!(url.as_str(), "https://swift.acme.dev/api");
/// assert_eq!(url.trust(), RegistryTrust::WorkspaceDeclared);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftRegistryUrl {
    normalized: String,
    parsed: Url,
    trust: RegistryTrust,
    host_key: RegistryHostKey,
}

fn validate_shape(raw: &str, gate: PolicyGate<'_>) -> Result<Url, IndexUrlError> {
    let url = validate_index_url(raw, raw, EcosystemId::Swift, gate)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(IndexUrlError::InvalidUrl(RedactedUrl::new(raw)));
    }
    Ok(url)
}

fn normalize(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_string()
}

impl SwiftRegistryUrl {
    /// Validates `raw` and classifies its trust against `user_tier`.
    ///
    /// A URL in the user tier skips the workspace policy (the user's own configuration) but never
    /// a never-a-registry host; any other URL is validated under `policy`.
    fn resolve(
        raw: &str,
        user_tier: &UserTier,
        policy: &RegistryAccessPolicy,
    ) -> Result<Self, SwiftRegistryUrlError> {
        let shape = validate_shape(raw, PolicyGate::Skip)?;
        let normalized = normalize(&shape);
        let host_key = RegistryHostKey::of(&shape)
            .ok_or_else(|| IndexUrlError::InvalidUrl(RedactedUrl::new(raw)))?;
        let trust = if user_tier.contains(&normalized) {
            let class = classify_host(&shape);
            if class.never_a_registry() {
                return Err(SwiftRegistryUrlError::NeverARegistryHost(class));
            }
            RegistryTrust::Trusted
        } else {
            validate_shape(raw, PolicyGate::Enforce(policy))?;
            RegistryTrust::WorkspaceDeclared
        };
        Ok(Self {
            normalized,
            parsed: shape,
            trust,
            host_key,
        })
    }

    /// The normalized URL, with no trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// The validated URL, for host-based lookups.
    pub(crate) const fn url(&self) -> &Url {
        &self.parsed
    }

    /// Whether this URL is user-declared or only workspace-declared.
    #[must_use]
    pub const fn trust(&self) -> RegistryTrust {
        self.trust
    }

    pub(crate) const fn host_key(&self) -> &RegistryHostKey {
        &self.host_key
    }

    #[cfg(test)]
    pub(crate) fn for_test(normalized: &str, trust: RegistryTrust) -> Self {
        let url = Url::parse(normalized).unwrap();
        Self {
            normalized: normalized.trim_end_matches('/').to_string(),
            host_key: RegistryHostKey::of(&url).unwrap(),
            parsed: url,
            trust,
        }
    }
}

/// A registry URL together with the credential bound to it, ready to register a client.
#[derive(Debug, Clone)]
pub struct ResolvedSwiftRegistry {
    /// The validated base URL.
    pub url: SwiftRegistryUrl,
    /// The credential, present only for a `Trusted` URL: a ready `Authorization` value, or a
    /// Keychain item read when a request is made.
    pub(crate) auth: Option<RegistryAuth>,
}

impl ResolvedSwiftRegistry {
    /// A salted digest of the trust and credential, used to detect that a registered client is
    /// stale. Not a cache key and never logged.
    pub(crate) fn digest(&self) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        deps_core::secret::digest_salt().hash(&mut hasher);
        self.url.trust.hash(&mut hasher);
        match &self.auth {
            None => 0u8.hash(&mut hasher),
            Some(RegistryAuth::Header(auth)) => {
                1u8.hash(&mut hasher);
                auth.header_value().hash(&mut hasher);
            }
            Some(RegistryAuth::Keychain(credential)) => {
                2u8.hash(&mut hasher);
                credential.hash_identity(&mut hasher);
            }
        }
        hasher.finish()
    }
}

type Entry = Result<ResolvedSwiftRegistry, InvalidEntry<SwiftRegistryUrlError>>;

/// Which declaration an `id:` scope resolved through.
enum Declaration<'a> {
    Scoped(&'a RegistryScope),
    Default,
}

impl Declaration<'_> {
    fn key(&self) -> String {
        match self {
            Self::Scoped(scope) => format!("scope:{scope}"),
            Self::Default => DEFAULT_KEY.to_string(),
        }
    }
}

/// The merged, resolved view of a workspace's `registries.json` tiers.
#[derive(Debug, Default)]
pub(crate) struct SwiftRegistriesConfig {
    default: Option<Entry>,
    scoped: HashMap<RegistryScope, Entry>,
}

impl SwiftRegistriesConfig {
    /// Merges `project` over `user` (per scope key and for `[default]`) and resolves every entry.
    ///
    /// Either tier being unusable makes the whole config unusable, with no fallback.
    fn merge(
        project: TierFile,
        user: TierFile,
        policy: &RegistryAccessPolicy,
        credential: CredentialLookup<'_>,
    ) -> Self {
        let tier = |file: TierFile| match file {
            TierFile::Absent => Some(None),
            TierFile::Parsed(raw) => Some(Some(raw)),
            TierFile::Unusable(reason) => {
                tracing::debug!(%reason, "unusable registries.json tier; id: dependencies stay unresolved");
                None
            }
        };
        let (Some(project), Some(user)) = (tier(project), tier(user)) else {
            return Self::default();
        };

        let user_tier = user.as_deref().map(UserTier::from_raw).unwrap_or_default();
        let mut default = user.as_ref().and_then(|raw| raw.default.clone());
        let mut scoped = user
            .as_ref()
            .map(|raw| raw.scoped.clone())
            .unwrap_or_default();
        if let Some(project) = &project {
            if project.default.is_some() {
                default.clone_from(&project.default);
            }
            scoped.extend(project.scoped.clone());
        }

        let resolve = |raw: &str| -> Entry {
            SwiftRegistryUrl::resolve(raw, &user_tier, policy)
                .map(|url| ResolvedSwiftRegistry {
                    auth: bind_credential(&url, &user_tier, credential),
                    url,
                })
                .map_err(|reason| InvalidEntry::new(RedactedUrl::new(raw), reason))
        };
        Self {
            default: default.as_deref().map(resolve),
            scoped: scoped
                .iter()
                .map(|(scope, raw)| (scope.clone(), resolve(raw)))
                .collect(),
        }
    }

    /// `scoped[scope] ?? default`, SwiftPM's lookup after the merge.
    fn applicable(&self, scope: &RegistryScope) -> Option<(Declaration<'_>, &Entry)> {
        self.scoped
            .get_key_value(scope)
            .map(|(scope, entry)| (Declaration::Scoped(scope), entry))
            .or_else(|| {
                self.default
                    .as_ref()
                    .map(|entry| (Declaration::Default, entry))
            })
    }

    /// Resolves `scope` to its final [`DependencySource`]: `AlternateRegistry` for a valid entry,
    /// otherwise `CustomRegistry` (never fetched) naming the redacted raw URL or the scope.
    pub(crate) fn resolve_source_for(&self, scope: &RegistryScope) -> DependencySource {
        match self.applicable(scope) {
            Some((_, Ok(resolved))) => DependencySource::AlternateRegistry {
                index: resolved.url.as_str().to_string(),
                mirrors_crates_io: false,
            },
            Some((_, Err(invalid))) => DependencySource::CustomRegistry {
                url: invalid.raw.to_string(),
            },
            None => DependencySource::CustomRegistry {
                url: scope.to_string(),
            },
        }
    }

    /// Reports the policy-blocked class when the entry `scope` resolved through was rejected for
    /// a blocked host.
    pub(crate) fn blocked_class_for(&self, scope: &RegistryScope) -> Option<BlockedSourceClass> {
        let (declaration, entry) = self.applicable(scope)?;
        let (class, raw_value) = entry.as_ref().err().and_then(InvalidEntry::blocked_class)?;
        Some(BlockedSourceClass {
            class,
            raw_value,
            declaration_key: declaration.key(),
        })
    }

    /// Reports the rejection reason when the entry `scope` resolved through was rejected for a
    /// reason other than a blocked host.
    pub(crate) fn rejected_reason_for(&self, scope: &RegistryScope) -> Option<RejectedSourceClass> {
        let (declaration, entry) = self.applicable(scope)?;
        let (reason, raw_value) = entry
            .as_ref()
            .err()
            .and_then(InvalidEntry::rejection_reason)?;
        Some(RejectedSourceClass {
            reason,
            raw_value,
            declaration_key: declaration.key(),
        })
    }

    fn invalid_entries(&self) -> impl Iterator<Item = &InvalidEntry<SwiftRegistryUrlError>> {
        self.default
            .iter()
            .chain(self.scoped.values())
            .filter_map(|entry| entry.as_ref().err())
    }

    /// The valid registry `scope` resolved through, if any.
    pub(crate) fn resolved_registry_for(
        &self,
        scope: &RegistryScope,
    ) -> Option<&ResolvedSwiftRegistry> {
        match self.applicable(scope) {
            Some((_, Ok(resolved))) => Some(resolved),
            Some((_, Err(_))) | None => None,
        }
    }

    /// Every valid registry this config carries, deduplicated by URL.
    #[cfg(test)]
    pub(crate) fn resolved_registries(&self) -> Vec<ResolvedSwiftRegistry> {
        let mut seen = HashSet::new();
        self.default
            .iter()
            .chain(self.scoped.values())
            .filter_map(|entry| entry.as_ref().ok())
            .filter(|resolved| seen.insert(resolved.url.as_str().to_string()))
            .cloned()
            .collect()
    }
}

/// Shared by every Swift parse: the workspace policy, the file cache, the user-tier location and
/// the credential source.
///
/// `Default` is hermetic (no user tier, no credential); production uses
/// [`Self::from_environment`].
#[derive(Debug, Clone)]
pub struct SwiftParseContext {
    policy: Arc<RegistryAccessPolicy>,
    cache: Arc<SwiftRegistriesCache>,
    user_config: UserConfigPath,
    credential: Option<Arc<SwiftCredentialSource>>,
    keychain: Option<KeychainWiring>,
}

/// The opt-in Keychain source: the process-wide store, the live setting, and the platform it
/// may run on.
#[derive(Debug, Clone)]
enum KeychainWiring {
    Supported(KeychainBinding),
    Unsupported {
        handle: Arc<KeychainCredentialsHandle>,
        warned: Arc<AtomicBool>,
    },
}

impl Default for SwiftParseContext {
    fn default() -> Self {
        Self::new(
            Arc::default(),
            Arc::default(),
            UserConfigPath::NoUserTier,
            None,
        )
    }
}

impl SwiftParseContext {
    /// Builds a context from its parts.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use deps_swift::config::{SwiftRegistriesCache, UserConfigPath};
    /// use deps_swift::{SwiftParseContext, parse_package_swift_with_context};
    /// use std::sync::Arc;
    ///
    /// let context = SwiftParseContext::new(
    ///     Arc::new(RegistryAccessPolicy::default()),
    ///     Arc::new(SwiftRegistriesCache::new()),
    ///     UserConfigPath::NoUserTier,
    ///     None,
    /// );
    /// let uri = url::Url::parse("untitled:Package.swift").unwrap();
    /// let manifest = r#".package(id: "acme.net", from: "1.0.0")"#;
    /// let parsed = parse_package_swift_with_context(manifest, &uri, &context).unwrap();
    /// assert!(parsed.resolved_registries.is_empty());
    /// ```
    #[must_use]
    pub fn new(
        policy: Arc<RegistryAccessPolicy>,
        cache: Arc<SwiftRegistriesCache>,
        user_config: UserConfigPath,
        credential: Option<Arc<SwiftCredentialSource>>,
    ) -> Self {
        Self {
            policy,
            cache,
            user_config,
            credential,
            keychain: None,
        }
    }

    /// Adds the opt-in macOS Keychain credential source, gated by `handle` and owning the one
    /// process-wide store; clones of this context share that store and its memo.
    ///
    /// The Keychain is read only on macOS, ahead of `~/.netrc` and behind the environment and
    /// `SWIFTPM_NETRC_DATA`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::keychain_credentials::KeychainCredentialsHandle;
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use deps_swift::SwiftParseContext;
    /// use std::sync::Arc;
    ///
    /// let context = SwiftParseContext::from_environment(Arc::new(RegistryAccessPolicy::default()))
    ///     .with_keychain(Arc::new(KeychainCredentialsHandle::default()));
    /// assert!(format!("{context:?}").contains("keychain"));
    /// ```
    #[must_use]
    pub fn with_keychain(self, handle: Arc<KeychainCredentialsHandle>) -> Self {
        self.with_keychain_for(handle, UserConfigPlatform::current())
    }

    /// Wires the Keychain source for `platform`; off macOS no store is created and an enabled
    /// setting only warns once.
    pub(crate) fn with_keychain_for(
        self,
        handle: Arc<KeychainCredentialsHandle>,
        platform: UserConfigPlatform,
    ) -> Self {
        match platform {
            UserConfigPlatform::MacOs => {
                let store = KeychainStore::system(handle.resolved_sender());
                self.with_keychain_store(handle, Arc::new(store))
            }
            UserConfigPlatform::Other => Self {
                keychain: Some(KeychainWiring::Unsupported {
                    handle,
                    warned: Arc::default(),
                }),
                ..self
            },
        }
    }

    pub(crate) fn with_keychain_store(
        mut self,
        handle: Arc<KeychainCredentialsHandle>,
        store: Arc<KeychainStore>,
    ) -> Self {
        handle.register_observer(Arc::downgrade(&store) as _);
        self.keychain = Some(KeychainWiring::Supported(KeychainBinding::new(
            store, handle,
        )));
        self
    }

    /// The Keychain binding to use for `source`, when the setting is on, this platform has a
    /// Keychain, and no source SwiftPM prefers is configured.
    fn active_keychain(&self, source: Option<&SwiftCredentialSource>) -> Option<&KeychainBinding> {
        match self.keychain.as_ref()? {
            KeychainWiring::Supported(binding) => {
                binding.sync_generation();
                (binding.is_enabled()
                    && !source.is_some_and(SwiftCredentialSource::precedes_keychain))
                .then_some(binding)
            }
            KeychainWiring::Unsupported { handle, warned } => {
                if handle.get() == KeychainCredentials::Enabled
                    && !warned.swap(true, Ordering::Relaxed)
                {
                    tracing::warn!(
                        "registries.swift_keychain_credentials is only supported on macOS; ignoring it"
                    );
                }
                None
            }
        }
    }

    /// Builds the production context: the user-tier path and the credential source are chosen
    /// from the environment once, here.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use deps_swift::SwiftParseContext;
    /// use std::sync::Arc;
    ///
    /// let context = SwiftParseContext::from_environment(Arc::new(RegistryAccessPolicy::default()));
    /// assert!(!format!("{context:?}").contains("hunter2"));
    /// ```
    #[must_use]
    pub fn from_environment(policy: Arc<RegistryAccessPolicy>) -> Self {
        Self::new(
            policy,
            Arc::default(),
            UserConfigPath::from_environment(),
            SwiftCredentialSource::from_environment(UserConfigPlatform::current()).map(Arc::new),
        )
    }

    /// Resolves the registry configuration that applies to the manifest at `manifest_uri`.
    pub(crate) fn resolve(&self, manifest_uri: &Url) -> SwiftRegistriesConfig {
        let project = deps_core::lockfile::resolve_manifest_file_path(manifest_uri)
            .and_then(|path| {
                path.parent().map(|dir| {
                    Path::new(PROJECT_REGISTRIES_SUFFIX)
                        .components()
                        .fold(dir.to_path_buf(), |acc, component| acc.join(component))
                })
            })
            .map_or(TierFile::Absent, |path| self.cache.read(&path));
        let user = match &self.user_config {
            UserConfigPath::Path(path) => self.cache.read(path),
            UserConfigPath::InvalidXdgConfigHome => self.cache.unusable(
                Path::new("$XDG_CONFIG_HOME"),
                None,
                RegistriesConfigError::InvalidXdgConfigHome,
            ),
            UserConfigPath::NoUserTier => TierFile::Absent,
        };
        let merge = |credential: CredentialLookup<'_>| {
            SwiftRegistriesConfig::merge(project, user, &self.policy, credential)
        };
        let source = self.credential.as_deref();
        let config = match (self.active_keychain(source), source) {
            (Some(binding), _) => merge(CredentialLookup::Keychain(binding)),
            (None, Some(source)) => source.with_lookup(merge),
            (None, None) => merge(CredentialLookup::None),
        };
        self.cache.warn_invalid_entries(&config);
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::net_policy::{RegistryRejectionReason, WorkspaceRegistryAccess};
    use deps_core::secret::Redacted;
    use std::assert_matches;

    const PUBLIC: &str = "https://tuist.dev/api/registry/swift";
    const PRIVATE: &str = "https://swift.acme.dev/api";

    fn scope(name: &str) -> RegistryScope {
        RegistryScope::parse(name).unwrap()
    }

    fn registries(entries: &[(&str, &str)]) -> String {
        let body: Vec<String> = entries
            .iter()
            .map(|(key, url)| format!(r#""{key}": {{"url": "{url}"}}"#))
            .collect();
        format!(r#"{{"registries": {{{}}}, "version": 1}}"#, body.join(", "))
    }

    fn registries_with_auth(entries: &[(&str, &str)], authentication: &str) -> String {
        let mut json = registries(entries);
        json.truncate(json.rfind('}').unwrap());
        format!(r#"{json}, "authentication": {{{authentication}}}}}"#)
    }

    fn token(value: &str) -> Arc<SwiftCredentialSource> {
        Arc::new(SwiftCredentialSource::Environment(
            crate::auth::SwiftCredential::Token(Redacted::new(value.to_string())),
        ))
    }

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn project_file(&self) -> PathBuf {
            self.dir
                .path()
                .join("proj/.swiftpm/configuration/registries.json")
        }

        fn user_file(&self) -> PathBuf {
            self.dir.path().join("user/registries.json")
        }

        fn write(path: &Path, content: &str) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }

        fn set_mtime_secs_ahead(path: &Path, secs: u64) {
            let file = std::fs::File::options().write(true).open(path).unwrap();
            file.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(secs))
                .unwrap();
        }

        fn project(&self, content: &str) -> &Self {
            Self::write(&self.project_file(), content);
            self
        }

        fn user(&self, content: &str) -> &Self {
            Self::write(&self.user_file(), content);
            self
        }

        fn manifest_uri(&self) -> Url {
            Url::from_file_path(self.dir.path().join("proj/Package.swift")).unwrap()
        }

        fn context(
            &self,
            access: WorkspaceRegistryAccess,
            credential: Option<Arc<SwiftCredentialSource>>,
        ) -> SwiftParseContext {
            SwiftParseContext::new(
                Arc::new(RegistryAccessPolicy::new(access)),
                Arc::default(),
                UserConfigPath::Path(self.user_file()),
                credential,
            )
        }

        fn config(&self) -> SwiftRegistriesConfig {
            self.config_with(WorkspaceRegistryAccess::PublicOnly, None)
        }

        fn config_with(
            &self,
            access: WorkspaceRegistryAccess,
            credential: Option<Arc<SwiftCredentialSource>>,
        ) -> SwiftRegistriesConfig {
            self.context(access, credential)
                .resolve(&self.manifest_uri())
        }
    }

    fn alternate(url: &str) -> DependencySource {
        DependencySource::AlternateRegistry {
            index: url.to_string(),
            mirrors_crates_io: false,
        }
    }

    fn custom(url: &str) -> DependencySource {
        DependencySource::CustomRegistry {
            url: url.to_string(),
        }
    }

    fn find(config: &SwiftRegistriesConfig, url: &str) -> ResolvedSwiftRegistry {
        config
            .resolved_registries()
            .into_iter()
            .find(|r| r.url.as_str() == url)
            .unwrap_or_else(|| panic!("{url} is not a resolved registry"))
    }

    // --- SC-001: user tier path ---

    #[test]
    fn test_user_config_path_table() {
        use UserConfigPlatform::{MacOs, Other};
        let home = Path::new("home").join("u");
        let home = home.as_path();
        let tail = Path::new("configuration").join("registries.json");
        let xdg = std::env::temp_dir();
        let resolve =
            |platform, home, xdg: Option<&OsStr>| UserConfigPath::resolve(platform, home, xdg);

        assert_eq!(
            resolve(MacOs, Some(home), Some(xdg.as_os_str())),
            UserConfigPath::Path(home.join("Library/org.swift.swiftpm").join(&tail))
        );
        assert_eq!(
            resolve(Other, Some(home), Some(xdg.as_os_str())),
            UserConfigPath::Path(xdg.join("swiftpm").join(&tail))
        );
        assert_eq!(
            resolve(Other, Some(home), None),
            UserConfigPath::Path(home.join(".swiftpm").join(tail))
        );
        for bad in ["", "relative/dir"] {
            assert_eq!(
                resolve(Other, Some(home), Some(OsStr::new(bad))),
                UserConfigPath::InvalidXdgConfigHome,
                "{bad:?}"
            );
        }
        assert_eq!(resolve(Other, None, None), UserConfigPath::NoUserTier);
        assert_eq!(resolve(MacOs, None, None), UserConfigPath::NoUserTier);
    }

    #[test]
    fn test_invalid_xdg_makes_the_user_tier_unusable_even_with_a_project_registry() {
        let fx = Fixture::new();
        fx.project(&registries(&[("[default]", PRIVATE)]));
        let ctx = SwiftParseContext::new(
            Arc::default(),
            Arc::default(),
            UserConfigPath::InvalidXdgConfigHome,
            None,
        );
        let config = ctx.resolve(&fx.manifest_uri());
        assert_eq!(config.resolve_source_for(&scope("acme")), custom("acme"));
    }

    // --- SC-002: tri-state reads ---

    #[test]
    fn test_missing_files_are_absent_and_resolve_to_custom_registry() {
        let fx = Fixture::new();
        assert_eq!(
            fx.config().resolve_source_for(&scope("acme")),
            custom("acme")
        );
        assert!(matches!(
            SwiftRegistriesCache::new().read(&fx.project_file()),
            TierFile::Absent
        ));
    }

    #[test]
    fn test_non_regular_oversized_and_unreadable_files_are_unusable() {
        let fx = Fixture::new();
        let cache = SwiftRegistriesCache::new();

        let directory = fx.project_file();
        std::fs::create_dir_all(&directory).unwrap();
        assert_matches!(
            cache.read(&directory),
            TierFile::Unusable(RegistriesConfigError::Unreadable)
        );

        let oversized = fx.user_file();
        let padding =
            " ".repeat(usize::try_from(deps_core::mtime_cache::MAX_CACHED_FILE_BYTES).unwrap());
        Fixture::write(&oversized, &format!("{}{padding}", registries(&[])));
        assert_matches!(
            cache.read(&oversized),
            TierFile::Unusable(RegistriesConfigError::Unreadable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_swiftpm_dir_that_is_a_regular_file_makes_the_tier_unusable() {
        let fx = Fixture::new();
        let swiftpm = fx.dir.path().join("proj/.swiftpm");
        Fixture::write(&swiftpm, "not a directory");
        assert_matches!(
            SwiftRegistriesCache::new().read(&fx.project_file()),
            TierFile::Unusable(RegistriesConfigError::Unreadable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_fifo_is_unusable_without_being_opened() {
        let fx = Fixture::new();
        let path = fx.project_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let made = std::process::Command::new("mkfifo").arg(&path).status();
        assert!(
            made.is_ok_and(|status| status.success()),
            "mkfifo is required on unix CI"
        );
        assert_matches!(
            SwiftRegistriesCache::new().read(&path),
            TierFile::Unusable(RegistriesConfigError::Unreadable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_unreadable_file_is_unusable() {
        use std::os::unix::fs::PermissionsExt;

        let fx = Fixture::new();
        fx.project(&registries(&[("[default]", PRIVATE)]));
        let path = fx.project_file();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&path).is_ok() {
            eprintln!("skipped: permissions are not enforced for this user (privileged run)");
            return;
        }
        assert_matches!(
            SwiftRegistriesCache::new().read(&path),
            TierFile::Unusable(RegistriesConfigError::Unreadable)
        );
    }

    #[test]
    fn test_unusable_project_tier_never_falls_back_to_the_user_default() {
        let fx = Fixture::new();
        fx.user(&registries(&[("[default]", PRIVATE)]));
        fx.project(r#"{"registries": {}, "version": 2}"#);
        let config = fx.config();
        assert_eq!(config.resolve_source_for(&scope("acme")), custom("acme"));
        assert!(config.resolved_registries().is_empty());
    }

    #[test]
    fn test_unusable_user_tier_never_falls_back_to_the_project_default() {
        let fx = Fixture::new();
        fx.project(&registries(&[("[default]", PRIVATE)]));
        fx.user("not json");
        assert_eq!(
            fx.config().resolve_source_for(&scope("acme")),
            custom("acme")
        );
    }

    #[test]
    fn test_unusable_tier_warning_is_debounced_per_path_and_mtime() {
        let fx = Fixture::new();
        fx.project("not json");
        let ctx = fx.context(WorkspaceRegistryAccess::PublicOnly, None);
        let logs = deps_core::test_util::capture_tracing_output(|| {
            for _ in 0..3 {
                ctx.resolve(&fx.manifest_uri());
            }
        });
        assert_eq!(
            logs.matches("swift registries.json is unusable").count(),
            1,
            "{logs}"
        );
    }

    // --- SC-003: strict decode ---

    #[test]
    fn test_strict_decode_table() {
        let invalid: [(&str, RegistriesConfigError); 4] = [
            (
                r#"{"registries": {}, "version": 2}"#,
                RegistriesConfigError::UnsupportedVersion(2),
            ),
            (
                r#"{"registries": {"a.b": {"url": "https://x.dev"}}, "version": 1}"#,
                RegistriesConfigError::InvalidScopeKey,
            ),
            (
                r#"{"registries": {}, "security": 5, "version": 1}"#,
                RegistriesConfigError::SecurityNotAnObject,
            ),
            (
                r#"{"registries": {}, "security": [], "version": 1}"#,
                RegistriesConfigError::SecurityNotAnObject,
            ),
        ];
        for (json, expected) in invalid {
            assert_eq!(parse_registries(json).unwrap_err(), expected, "{json}");
        }

        let malformed = [
            r#"{"registries": {}}"#,
            r#"{"version": 1}"#,
            r#"{"registries": {}, "version": "1"}"#,
            r#"{"registries": {"x": {}}, "version": 1}"#,
            r#"{"registries": {"x": {"url": 3}}, "version": 1}"#,
            r#"{"registries": {}, "authentication": {"h": {"type": "oauth"}}, "version": 1}"#,
            r#"{"registries": {}, "authentication": {"h": {}}, "version": 1}"#,
            r#"{"registries": {"x": {"url": "https://x.dev", "supportsAvailability": "yes"}}, "version": 1}"#,
            "not json",
        ];
        for json in malformed {
            assert_matches!(
                parse_registries(json),
                Err(RegistriesConfigError::Malformed { .. }),
                "{json}"
            );
        }
    }

    #[test]
    fn test_decode_ignores_unknown_keys_and_security_contents() {
        let json = r#"{
            "registries": {"[default]": {"url": "https://x.dev", "supportsAvailability": true, "extra": 1}},
            "authentication": {"x.dev": {"type": "token", "loginAPIPath": "/login"}},
            "security": {"default": {"signing": {"onUnsigned": "fromTheFuture"}}},
            "somethingNew": [1, 2],
            "version": 1
        }"#;
        let raw = parse_registries(json).unwrap();
        assert_eq!(raw.default.as_deref(), Some("https://x.dev"));
        assert_eq!(
            raw.authentication
                .get(&RegistryHostKey::parse("x.dev").unwrap()),
            Some(&SwiftAuthType::Token)
        );
        assert!(parse_registries(r#"{"registries": {}, "security": null, "version": 1}"#).is_ok());
    }

    #[test]
    fn test_registry_host_key_normalizes_case_and_default_port() {
        let key = |k: &str| RegistryHostKey::parse(k).unwrap();
        assert_eq!(key("Swift.ACME.dev"), key("swift.acme.dev"));
        assert_eq!(key("swift.acme.dev:443"), key("swift.acme.dev"));
        assert_ne!(key("swift.acme.dev:8443"), key("swift.acme.dev"));
        assert!(RegistryHostKey::parse("swift.acme.dev/api").is_none());
        assert!(RegistryHostKey::parse("u@swift.acme.dev").is_none());
    }

    // --- SC-004: merge ---

    #[test]
    fn test_user_scoped_entry_beats_project_default() {
        let fx = Fixture::new();
        fx.user(&registries(&[("acme", PRIVATE)]));
        fx.project(&registries(&[("[default]", PUBLIC)]));
        let config = fx.config();
        assert_eq!(
            config.resolve_source_for(&scope("acme")),
            alternate(PRIVATE)
        );
        assert_eq!(
            config.resolve_source_for(&scope("other")),
            alternate(PUBLIC)
        );
    }

    #[test]
    fn test_project_overrides_user_per_scope_and_default() {
        let fx = Fixture::new();
        fx.user(&registries(&[("acme", PRIVATE), ("[default]", PRIVATE)]));
        fx.project(&registries(&[("acme", PUBLIC), ("[default]", PUBLIC)]));
        let config = fx.config();
        assert_eq!(config.resolve_source_for(&scope("acme")), alternate(PUBLIC));
        assert_eq!(config.resolve_source_for(&scope("zed")), alternate(PUBLIC));
    }

    #[test]
    fn test_scopes_match_case_insensitively() {
        let fx = Fixture::new();
        fx.user(&registries(&[("Acme", PRIVATE)]));
        let config = fx.config();
        assert_eq!(
            config.resolve_source_for(&RegistryScope::parse("ACME").unwrap()),
            alternate(PRIVATE)
        );
    }

    // --- SC-005 / SC-006: trust and binding ---

    #[test]
    fn test_trust_table() {
        let fx = Fixture::new();
        fx.user(&registries_with_auth(
            &[("acme", PRIVATE)],
            r#""only-auth.example": {"type": "basic"}"#,
        ));
        fx.project(&registries(&[
            ("same", PRIVATE),
            ("otherpath", "https://swift.acme.dev/api/other"),
            ("authonly", "https://only-auth.example/api"),
        ]));
        let config = fx.config_with(WorkspaceRegistryAccess::All, Some(token("t0k")));

        let trusted = find(&config, PRIVATE);
        assert_eq!(trusted.url.trust(), RegistryTrust::Trusted);
        assert!(trusted.auth.is_some());

        for url in [
            "https://swift.acme.dev/api/other",
            "https://only-auth.example/api",
        ] {
            let declared = find(&config, url);
            assert_eq!(
                declared.url.trust(),
                RegistryTrust::WorkspaceDeclared,
                "{url}"
            );
            assert!(declared.auth.is_none(), "{url}");
        }
        assert_eq!(
            config.resolve_source_for(&scope("same")),
            alternate(PRIVATE)
        );
    }

    #[test]
    fn test_trust_is_url_equality_after_normalization() {
        let fx = Fixture::new();
        fx.user(&registries(&[("acme", PRIVATE)]));
        fx.project(&registries(&[("same", "https://SWIFT.acme.dev:443/api/")]));
        let config = fx.config_with(WorkspaceRegistryAccess::PublicOnly, Some(token("t0k")));
        let same = find(&config, PRIVATE);
        assert_eq!(same.url.trust(), RegistryTrust::Trusted);
        assert_eq!(
            config.resolve_source_for(&scope("same")),
            alternate(PRIVATE)
        );
    }

    #[test]
    fn test_one_credential_reaches_every_user_tier_registry() {
        let fx = Fixture::new();
        fx.user(&registries(&[("[default]", PUBLIC), ("acme", PRIVATE)]));
        let config = fx.config_with(WorkspaceRegistryAccess::PublicOnly, Some(token("t0k")));
        for url in [PUBLIC, PRIVATE] {
            let resolved = find(&config, url);
            assert_eq!(resolved.auth.unwrap().header_value(), "Bearer t0k", "{url}");
        }
    }

    #[test]
    fn test_project_tier_authentication_has_no_effect_on_the_header_or_digest() {
        let fx = Fixture::new();
        fx.user(&registries(&[("acme", PRIVATE)]));
        let baseline = find(
            &fx.config_with(WorkspaceRegistryAccess::PublicOnly, Some(token("t0k"))),
            PRIVATE,
        );

        fx.project(&registries_with_auth(
            &[("acme", PRIVATE)],
            r#""swift.acme.dev": {"type": "basic"}"#,
        ));
        let with_project_auth = find(
            &fx.config_with(WorkspaceRegistryAccess::PublicOnly, Some(token("t0k"))),
            PRIVATE,
        );
        assert_eq!(
            with_project_auth.auth.as_ref().unwrap().header_value(),
            "Bearer t0k"
        );
        assert_eq!(baseline.digest(), with_project_auth.digest());
    }

    #[test]
    fn test_user_tier_authentication_selects_the_header_format() {
        let fx = Fixture::new();
        fx.user(&registries_with_auth(
            &[("acme", PRIVATE)],
            r#""swift.acme.dev": {"type": "basic"}"#,
        ));
        let config = fx.config_with(WorkspaceRegistryAccess::PublicOnly, Some(token("t0k")));
        assert_eq!(
            find(&config, PRIVATE).auth.unwrap().header_value(),
            "Basic dG9rZW46dDBr"
        );
    }

    #[test]
    fn test_authentication_is_keyed_by_host_and_non_default_port() {
        let with_port = "https://swift.acme.dev:8443/api";
        let fx = Fixture::new();
        fx.user(&registries_with_auth(
            &[("acme", with_port)],
            r#""swift.acme.dev:8443": {"type": "basic"}"#,
        ));
        let config = fx.config_with(WorkspaceRegistryAccess::PublicOnly, Some(token("t0k")));
        assert_eq!(
            find(&config, with_port).auth.unwrap().header_value(),
            "Basic dG9rZW46dDBr"
        );

        let fx = Fixture::new();
        fx.user(&registries_with_auth(
            &[("acme", with_port)],
            r#""swift.acme.dev": {"type": "basic"}"#,
        ));
        let config = fx.config_with(WorkspaceRegistryAccess::PublicOnly, Some(token("t0k")));
        assert_eq!(
            find(&config, with_port).auth.unwrap().header_value(),
            "Bearer t0k",
            "a portless key must not apply to a registry on another port"
        );
    }

    #[test]
    fn test_digest_tracks_credential_and_trust() {
        let fx = Fixture::new();
        fx.user(&registries(&[("acme", PRIVATE)]));
        let digest = |credential| {
            find(
                &fx.config_with(WorkspaceRegistryAccess::PublicOnly, credential),
                PRIVATE,
            )
            .digest()
        };
        let a = digest(Some(token("a")));
        assert_eq!(a, digest(Some(token("a"))));
        assert_ne!(a, digest(Some(token("b"))));
        assert_ne!(a, digest(None));
    }

    fn netrc_file_source(
        path: PathBuf,
        default_entry: deps_core::netrc::DefaultEntry,
    ) -> Arc<SwiftCredentialSource> {
        Arc::new(SwiftCredentialSource::NetrcFile {
            path,
            default_entry,
            cache: Arc::new(deps_core::mtime_cache::MtimeFileCache::new(8, "test netrc")),
            unreadable_warned: Arc::default(),
        })
    }

    #[test]
    fn test_netrc_file_is_reread_when_it_changes_and_absent_or_invalid_means_no_credential() {
        use deps_core::netrc::DefaultEntry;

        let fx = Fixture::new();
        fx.user(&registries(&[("[default]", PUBLIC), ("acme", PRIVATE)]));
        let netrc_path = fx.dir.path().join("home/.netrc");
        let source = netrc_file_source(netrc_path.clone(), DefaultEntry::Honor);
        let header = |url: &str| {
            find(
                &fx.config_with(
                    WorkspaceRegistryAccess::PublicOnly,
                    Some(Arc::clone(&source)),
                ),
                url,
            )
            .auth
            .map(|auth| auth.header_value().to_string())
        };

        assert_eq!(header(PRIVATE), None, "absent file");

        Fixture::write(&netrc_path, "machine swift.acme.dev login u password p");
        let first = find(
            &fx.config_with(
                WorkspaceRegistryAccess::PublicOnly,
                Some(Arc::clone(&source)),
            ),
            PRIVATE,
        );
        assert_eq!(first.auth.as_ref().unwrap().header_value(), "Basic dTpw");
        assert_eq!(header(PUBLIC), None, "no machine entry for the public host");

        Fixture::write(
            &netrc_path,
            "machine swift.acme.dev login u password rotated",
        );
        Fixture::set_mtime_secs_ahead(&netrc_path, 10);
        let second = find(
            &fx.config_with(
                WorkspaceRegistryAccess::PublicOnly,
                Some(Arc::clone(&source)),
            ),
            PRIVATE,
        );
        assert_ne!(first.digest(), second.digest());

        Fixture::write(&netrc_path, "machine swift.acme.dev login u");
        Fixture::set_mtime_secs_ahead(&netrc_path, 20);
        assert_eq!(header(PRIVATE), None, "invalid file");
    }

    #[cfg(unix)]
    #[test]
    fn test_unreadable_netrc_file_warns_once() {
        use deps_core::netrc::DefaultEntry;
        use std::os::unix::fs::PermissionsExt;

        let fx = Fixture::new();
        fx.user(&registries(&[("acme", PRIVATE)]));
        let netrc_path = fx.dir.path().join("home/.netrc");
        Fixture::write(&netrc_path, "machine swift.acme.dev login u password p");
        std::fs::set_permissions(&netrc_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&netrc_path).is_ok() {
            return;
        }
        let source = netrc_file_source(netrc_path, DefaultEntry::Honor);
        let logs = deps_core::test_util::capture_tracing_output(|| {
            for _ in 0..3 {
                let config = fx.config_with(
                    WorkspaceRegistryAccess::PublicOnly,
                    Some(Arc::clone(&source)),
                );
                assert!(find(&config, PRIVATE).auth.is_none());
            }
        });
        assert_eq!(logs.matches("cannot be read").count(), 1, "{logs}");
    }

    #[test]
    fn test_netrc_credential_never_reaches_a_workspace_declared_registry() {
        use deps_core::netrc::DefaultEntry;

        let fx = Fixture::new();
        fx.user(&registries(&[("acme", PRIVATE)]));
        fx.project(&registries(&[(
            "other",
            "https://swift.acme.dev/other-api",
        )]));
        let netrc_path = fx.dir.path().join("home/.netrc");
        Fixture::write(&netrc_path, "default login d password d");
        let source = netrc_file_source(netrc_path, DefaultEntry::Honor);
        let config = fx.config_with(WorkspaceRegistryAccess::All, Some(source));

        assert!(find(&config, PRIVATE).auth.is_some());
        let declared = find(&config, "https://swift.acme.dev/other-api");
        assert_eq!(declared.url.trust(), RegistryTrust::WorkspaceDeclared);
        assert!(declared.auth.is_none());
    }

    // --- SC-005a / policy ---

    #[test]
    fn test_trusted_never_a_registry_hosts_are_rejected_silently() {
        for host in [
            "https://127.0.0.1",
            "https://[::1]",
            "https://169.254.169.254",
            "https://0.0.0.0",
            "https://localhost:8443",
        ] {
            let fx = Fixture::new();
            fx.user(&registries(&[("acme", host)]));
            let config = fx.config_with(WorkspaceRegistryAccess::All, Some(token("t0k")));
            let acme = scope("acme");
            assert_matches!(
                config.resolve_source_for(&acme),
                DependencySource::CustomRegistry { .. },
                "{host}"
            );
            assert!(config.blocked_class_for(&acme).is_none(), "{host}");
            assert!(config.rejected_reason_for(&acme).is_none(), "{host}");
            assert!(config.resolved_registries().is_empty(), "{host}");
        }
    }

    #[test]
    fn test_never_a_registry_rejection_logs_the_class_and_not_the_credential() {
        let fx = Fixture::new();
        fx.user(&registries(&[("acme", "https://169.254.169.254")]));
        let logs = deps_core::test_util::capture_tracing_output(|| {
            fx.config_with(WorkspaceRegistryAccess::All, Some(token("hunter2")));
        });
        assert!(logs.contains("never a registry"), "{logs}");
        assert!(!logs.contains("hunter2"), "{logs}");
    }

    #[test]
    fn test_user_tier_rfc1918_literal_is_accepted_under_public_only() {
        let fx = Fixture::new();
        fx.user(&registries(&[("acme", "https://10.0.0.5")]));
        let config = fx.config();
        assert_eq!(
            config.resolve_source_for(&scope("acme")),
            alternate("https://10.0.0.5")
        );
        assert_eq!(
            find(&config, "https://10.0.0.5").url.trust(),
            RegistryTrust::Trusted
        );
    }

    #[test]
    fn test_project_tier_rfc1918_literal_is_blocked_by_the_policy() {
        let fx = Fixture::new();
        fx.project(&registries(&[("acme", "https://10.0.0.5")]));
        let config = fx.config();
        let acme = scope("acme");
        let blocked = config.blocked_class_for(&acme).unwrap();
        assert_eq!(blocked.class, HostClass::PrivateV4);
        assert_eq!(blocked.declaration_key, "scope:acme");
        assert_matches!(
            config.resolve_source_for(&acme),
            DependencySource::CustomRegistry { .. }
        );
        assert!(config.resolved_registries().is_empty());

        let allowed = fx.config_with(WorkspaceRegistryAccess::All, None);
        assert_eq!(
            allowed.resolve_source_for(&acme),
            alternate("https://10.0.0.5")
        );
    }

    #[test]
    fn test_invalid_project_entries_are_rejected_with_a_redacted_raw_value() {
        for (url, reason) in [
            ("http://swift.acme.dev", RegistryRejectionReason::NotHttps),
            ("not a url", RegistryRejectionReason::InvalidUrl),
            (
                "https://user:hunter2@swift.acme.dev/api",
                RegistryRejectionReason::UserInfoPresent,
            ),
            (
                "https://swift.acme.dev/api?token=hunter2",
                RegistryRejectionReason::InvalidUrl,
            ),
            (
                "https://swift.acme.dev/api#frag",
                RegistryRejectionReason::InvalidUrl,
            ),
        ] {
            let fx = Fixture::new();
            fx.project(&registries(&[("acme", url)]));
            let config = fx.config();
            let acme = scope("acme");
            let rejected = config.rejected_reason_for(&acme).unwrap();
            assert_eq!(rejected.reason, reason, "{url}");
            assert!(
                !rejected.raw_value.contains("hunter2"),
                "{url}: {}",
                rejected.raw_value
            );
            assert!(config.blocked_class_for(&acme).is_none());
            let DependencySource::CustomRegistry { url: shown } = config.resolve_source_for(&acme)
            else {
                panic!("{url} must resolve to CustomRegistry");
            };
            assert!(!shown.contains("hunter2"), "{shown}");
        }
    }

    #[test]
    fn test_invalid_entry_warning_is_emitted_once_across_reparses() {
        let fx = Fixture::new();
        fx.project(&registries(&[("acme", "http://swift.acme.dev")]));
        let ctx = fx.context(WorkspaceRegistryAccess::PublicOnly, None);
        let logs = deps_core::test_util::capture_tracing_output(|| {
            for _ in 0..3 {
                ctx.resolve(&fx.manifest_uri());
            }
        });
        assert_eq!(
            logs.matches("swift registry url failed validation").count(),
            1,
            "{logs}"
        );
    }

    #[test]
    fn test_default_declaration_key() {
        let fx = Fixture::new();
        fx.project(&registries(&[("[default]", "https://10.0.0.5")]));
        let blocked = fx.config().blocked_class_for(&scope("any")).unwrap();
        assert_eq!(blocked.declaration_key, "[default]");
    }

    #[test]
    fn test_resolved_registries_are_deduplicated_by_url() {
        let fx = Fixture::new();
        fx.user(&registries(&[
            ("a", PRIVATE),
            ("b", PRIVATE),
            ("[default]", PUBLIC),
        ]));
        assert_eq!(fx.config().resolved_registries().len(), 2);
    }

    #[test]
    fn test_registry_url_error_classification() {
        let silent = SwiftRegistryUrlError::NeverARegistryHost(HostClass::Loopback);
        assert_eq!(
            silent.rejection_reason(),
            RejectionOutcome::IntentionallySilent
        );
        assert_eq!(silent.blocked_host_class(), None);
        let blocked = SwiftRegistryUrlError::Url(IndexUrlError::BlockedHost {
            class: HostClass::PrivateV4,
        });
        assert_eq!(blocked.blocked_host_class(), Some(HostClass::PrivateV4));
        assert_eq!(
            blocked.rejection_reason(),
            RejectionOutcome::HandledByBlockedHostPath
        );
    }

    #[test]
    fn test_config_debug_never_renders_the_credential() {
        let fx = Fixture::new();
        fx.user(&registries(&[("acme", PRIVATE)]));
        let config = fx.config_with(WorkspaceRegistryAccess::PublicOnly, Some(token("hunter2")));
        assert!(!format!("{config:?}").contains("hunter2"));
        assert!(
            !format!(
                "{:?}",
                fx.context(WorkspaceRegistryAccess::All, Some(token("hunter2")))
            )
            .contains("hunter2")
        );
    }

    #[test]
    fn test_manifest_uri_without_a_filesystem_path_has_no_project_tier() {
        let fx = Fixture::new();
        fx.user(&registries(&[("acme", PRIVATE)]));
        let ctx = fx.context(WorkspaceRegistryAccess::PublicOnly, None);
        let config = ctx.resolve(&Url::parse("untitled:Package.swift").unwrap());
        assert_eq!(
            config.resolve_source_for(&scope("acme")),
            alternate(PRIVATE)
        );
    }

    // --- opt-in Keychain credential source (#1771) ---

    mod keychain_source {
        use super::*;
        use crate::auth::RegistryAuth;
        use crate::keychain::fake::Fake;
        use deps_core::keychain_credentials::KeychainCredentialsHandle;
        use deps_core::policy_config::KeychainCredentials;

        struct Wired {
            context: SwiftParseContext,
            handle: Arc<KeychainCredentialsHandle>,
            fake: Fake,
            store: Arc<KeychainStore>,
        }

        fn wired(
            fx: &Fixture,
            platform: UserConfigPlatform,
            setting: KeychainCredentials,
            source: Option<Arc<SwiftCredentialSource>>,
        ) -> Wired {
            let handle = Arc::new(KeychainCredentialsHandle::new(setting));
            let fake = Fake::found();
            let store = Arc::new(KeychainStore::new(fake.clone(), handle.resolved_sender()));
            let base = fx.context(WorkspaceRegistryAccess::All, source);
            let context = match platform {
                UserConfigPlatform::MacOs => {
                    base.with_keychain_store(Arc::clone(&handle), Arc::clone(&store))
                }
                UserConfigPlatform::Other => base.with_keychain_for(Arc::clone(&handle), platform),
            };
            Wired {
                context,
                handle,
                fake,
                store,
            }
        }

        fn auth_of(wired: &Wired, fx: &Fixture, url: &str) -> Option<RegistryAuth> {
            find(&wired.context.resolve(&fx.manifest_uri()), url).auth
        }

        fn user_declared_fixture() -> Fixture {
            let fx = Fixture::new();
            fx.user(&registries(&[("acme", PRIVATE)]));
            fx
        }

        #[test]
        fn test_enabled_on_macos_binds_a_deferred_keychain_credential_without_any_lookup() {
            let fx = user_declared_fixture();
            let wired = wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Enabled,
                None,
            );
            assert_matches!(
                auth_of(&wired, &fx, PRIVATE),
                Some(RegistryAuth::Keychain(_))
            );
            assert_eq!(wired.fake.find_calls.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn test_disabled_or_non_macos_never_selects_the_keychain() {
            let fx = user_declared_fixture();
            for (platform, setting) in [
                (UserConfigPlatform::MacOs, KeychainCredentials::Disabled),
                (UserConfigPlatform::Other, KeychainCredentials::Enabled),
            ] {
                let wired = wired(&fx, platform, setting, None);
                assert!(
                    auth_of(&wired, &fx, PRIVATE).is_none(),
                    "{platform:?} {setting:?}"
                );
            }
        }

        #[test]
        fn test_environment_and_netrc_data_take_precedence_over_the_keychain() {
            let fx = user_declared_fixture();
            let wired = wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Enabled,
                Some(token("env-token")),
            );
            let auth = auth_of(&wired, &fx, PRIVATE).unwrap();
            assert_eq!(auth.header_value(), "Bearer env-token");

            let netrc = deps_core::netrc::Netrc::parse(
                "machine swift.acme.dev login u password p",
                deps_core::netrc::NetrcFlavor::InMemory,
            )
            .unwrap();
            let data = Arc::new(SwiftCredentialSource::NetrcData(Arc::new(netrc)));
            let wired = self::wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Enabled,
                Some(data),
            );
            assert_matches!(auth_of(&wired, &fx, PRIVATE), Some(RegistryAuth::Header(_)));
        }

        #[test]
        fn test_keychain_replaces_the_netrc_file() {
            let fx = user_declared_fixture();
            let netrc_path = fx.dir.path().join("home/.netrc");
            Fixture::write(&netrc_path, "default login d password d");
            let file = netrc_file_source(netrc_path, deps_core::netrc::DefaultEntry::Honor);

            let on = wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Enabled,
                Some(Arc::clone(&file)),
            );
            assert_matches!(auth_of(&on, &fx, PRIVATE), Some(RegistryAuth::Keychain(_)));

            let off = wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Disabled,
                Some(file),
            );
            assert_matches!(auth_of(&off, &fx, PRIVATE), Some(RegistryAuth::Header(_)));
        }

        #[test]
        fn test_keychain_credential_never_reaches_a_workspace_declared_registry() {
            let fx = user_declared_fixture();
            fx.project(&registries(&[(
                "other",
                "https://swift.acme.dev/other-api",
            )]));
            let wired = wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Enabled,
                None,
            );
            assert!(auth_of(&wired, &fx, PRIVATE).is_some());
            assert!(auth_of(&wired, &fx, "https://swift.acme.dev/other-api").is_none());
        }

        #[test]
        fn test_digest_tells_keychain_from_no_credential_and_from_another_host() {
            let fx = Fixture::new();
            fx.user(&registries(&[
                ("a", PRIVATE),
                ("b", "https://swift.other.dev/api"),
            ]));
            let on = wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Enabled,
                None,
            );
            let config = on.context.resolve(&fx.manifest_uri());
            let a = find(&config, PRIVATE).digest();
            assert_eq!(
                a,
                find(&on.context.resolve(&fx.manifest_uri()), PRIVATE).digest()
            );
            assert_ne!(a, find(&config, "https://swift.other.dev/api").digest());
            on.handle.set(KeychainCredentials::Disabled);
            let off = find(&on.context.resolve(&fx.manifest_uri()), PRIVATE).digest();
            assert_ne!(a, off);
        }

        #[test]
        fn test_debug_of_a_keychain_bound_registry_shows_no_secret() {
            let fx = user_declared_fixture();
            let wired = wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Enabled,
                None,
            );
            let rendered = format!("{:?}", auth_of(&wired, &fx, PRIVATE));
            assert!(rendered.contains("KeychainCredential"));
            assert!(!rendered.contains("hunter2"));
        }

        #[tokio::test(start_paused = true)]
        async fn test_disabling_purges_found_secrets_immediately_with_no_swift_document() {
            let fx = user_declared_fixture();
            let wired = wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Enabled,
                None,
            );
            let Some(RegistryAuth::Keychain(credential)) = auth_of(&wired, &fx, PRIVATE) else {
                panic!("expected a keychain credential");
            };
            assert!(credential.authorization().await.auth.is_some());
            assert_eq!(wired.store.memoized_entries(), 1);

            wired.handle.set(KeychainCredentials::Disabled);
            assert_eq!(wired.store.memoized_entries(), 0);
        }

        #[tokio::test(start_paused = true)]
        async fn test_toggling_the_setting_purges_the_memo_on_the_next_resolve() {
            let fx = user_declared_fixture();
            let wired = wired(
                &fx,
                UserConfigPlatform::MacOs,
                KeychainCredentials::Enabled,
                None,
            );
            let Some(RegistryAuth::Keychain(credential)) = auth_of(&wired, &fx, PRIVATE) else {
                panic!("expected a keychain credential");
            };
            assert!(credential.authorization().await.auth.is_some());
            assert!(credential.authorization().await.auth.is_some());
            assert_eq!(wired.fake.secret_calls(), 1);

            wired.handle.set(KeychainCredentials::Disabled);
            assert!(credential.authorization().await.auth.is_none());
            wired.handle.set(KeychainCredentials::Enabled);
            auth_of(&wired, &fx, PRIVATE);
            assert!(credential.authorization().await.auth.is_some());
            assert_eq!(wired.fake.secret_calls(), 2);
        }
    }
}
