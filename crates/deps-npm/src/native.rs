//! The package managers' own release-age settings (spec 099, #2041): npm `min-release-age` /
//! `before` in `.npmrc`, pnpm `minimumReleaseAge` in `pnpm-workspace.yaml` and Bun
//! `[install] minimumReleaseAge` in `bunfig.toml`.
//!
//! Which manager applies is decided by the lock file the project resolves with, and only that
//! manager's own file is read, from the project root alone (the directory of the located lock
//! file, else the manifest directory). The root must lie inside the repository: the user's home
//! directory, and any directory above it, is never a project root, so a stray lock file there
//! cannot make the user's own config apply. A value this module cannot interpret exactly is
//! ignored with a warning naming the file, so a malformed setting never invents a window. Yarn
//! has no supported setting. Files are read through the shared mtime caches.

use std::path::{Path, PathBuf};

use deps_core::native_cooldown::{
    Exemption, ExemptionList, ExemptionSyntax, NativeCooldown, NativeCooldownSource, NativeCutoff,
    NativeLimit, NativeTimeSpan, RepositoryScope, TimeSpanValue, TimeUnit, parse_exemptions,
};
use deps_core::parser::DependencySource;
use deps_core::policy_config::NativeCooldownMode;
use deps_core::{Dependency, MtimeFileCache, fs_probe};
use url::Url;
use yaml_rust2::{Yaml, YamlLoader};

use crate::config::{NpmParseContext, NpmrcNative};
use crate::types::{NpmDependency, NpmDependencyOrigin};

const LOCKFILES: [(&str, Manager); 6] = [
    ("package-lock.json", Manager::Npm),
    ("pnpm-lock.yaml", Manager::Pnpm),
    ("yarn.lock", Manager::Yarn),
    ("bun.lock", Manager::Bun),
    ("bun.lockb", Manager::Bun),
    ("npm-shrinkwrap.json", Manager::Npm),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Manager {
    Npm,
    Pnpm,
    Bun,
    Yarn,
}

/// A parsed window with the exemption list that goes with it.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    limit: NativeLimit,
    source: NativeCooldownSource,
    exemptions: Option<ExemptionList>,
}

impl Settings {
    /// The cooldown of the dependency `dep`, or `None` when its package is exempt.
    fn cooldown_for(&self, dep: &NpmDependency) -> Option<NativeCooldown> {
        let cooldown = NativeCooldown::new(self.limit, self.source.clone());
        let exemption = self.exemptions.as_ref().map_or(Exemption::None, |list| {
            list.lookup(Dependency::name(dep).as_str())
        });
        match exemption {
            Exemption::None => Some(cooldown),
            Exemption::AllVersions => None,
            Exemption::Versions(versions) => Some(cooldown.with_exempt_versions(versions)),
        }
    }
}

/// Per-file memoization of the release-age settings of `pnpm-workspace.yaml` and `bunfig.toml`
/// files, keyed by path and invalidated by mtime. `.npmrc` goes through
/// [`crate::config::NpmConfigCache`] instead, so one parser reads that file.
#[derive(Debug)]
pub(crate) struct NativeSettingsCache {
    pnpm: MtimeFileCache<Option<Settings>>,
    bun: MtimeFileCache<Option<Settings>>,
}

impl Default for NativeSettingsCache {
    fn default() -> Self {
        Self {
            pnpm: MtimeFileCache::new(deps_core::DEFAULT_MAX_CACHED_FILES, "pnpm release-age"),
            bun: MtimeFileCache::new(deps_core::DEFAULT_MAX_CACHED_FILES, "bun release-age"),
        }
    }
}

/// Resolves the window of every registry dependency of the `package.json` at `uri`.
pub(crate) fn apply_to_manifest(
    dependencies: &mut [NpmDependency],
    uri: &Url,
    manifest_dir: Option<&Path>,
    ctx: &NpmParseContext,
) {
    if ctx.native_cooldown.get() == NativeCooldownMode::Ignore {
        return;
    }
    let Some(manifest_dir) = manifest_dir else {
        return;
    };
    let Some((root, manager)) = locate_root(uri, manifest_dir, ctx) else {
        return;
    };
    if let Some(settings) = read_settings(&root, manager, ctx) {
        apply(dependencies, &settings);
    }
}

/// Resolves the window of the catalog entries of an open `pnpm-workspace.yaml` from its own
/// buffer, never from disk.
pub(crate) fn apply_to_workspace_buffer(
    dependencies: &mut [NpmDependency],
    uri: &Url,
    content: &str,
    ctx: &NpmParseContext,
) {
    if ctx.native_cooldown.get() == NativeCooldownMode::Ignore {
        return;
    }
    if let Some(settings) = parse_pnpm(Path::new(uri.path()), content) {
        apply(dependencies, &settings);
    }
}

fn apply(dependencies: &mut [NpmDependency], settings: &Settings) {
    for dep in dependencies {
        let registry_dependency = matches!(
            dep.source,
            DependencySource::Registry | DependencySource::AlternateRegistry { .. }
        );
        let gated_origin = !matches!(dep.origin, NpmDependencyOrigin::Override { .. });
        if registry_dependency && gated_origin {
            dep.native_cooldown = settings.cooldown_for(dep);
        }
    }
}

/// The project root and the manager that owns it, or `None` when the root would lie outside
/// the repository (the home directory or anything above it).
fn locate_root(
    uri: &Url,
    manifest_dir: &Path,
    ctx: &NpmParseContext,
) -> Option<(PathBuf, Manager)> {
    let names: Vec<&str> = LOCKFILES.iter().map(|(name, _)| *name).collect();
    let in_scope = |root: &Path| {
        RepositoryScope::with_user_home(manifest_dir, root, ctx.user_home.as_ref()).contains(root)
    };
    // A lock file outside the repository (the home directory or above) is not this project's:
    // the project then resolves as if it had none.
    let located = deps_core::lockfile::locate_lockfile_for_manifest(uri, &names)
        .as_deref()
        .and_then(lock_root)
        .filter(|(root, _)| in_scope(root));
    let (root, manager) =
        located.unwrap_or_else(|| (manifest_dir.to_path_buf(), lockless_manager(manifest_dir)));
    in_scope(&root).then_some((root, manager))
}

fn lock_root(lock: &Path) -> Option<(PathBuf, Manager)> {
    let manager = lock
        .file_name()
        .and_then(|file| LOCKFILES.iter().find(|(name, _)| file == *name))
        .map(|(_, manager)| *manager)?;
    Some((lock.parent()?.to_path_buf(), manager))
}

fn lockless_manager(manifest_dir: &Path) -> Manager {
    if fs_probe::is_file(&manifest_dir.join("pnpm-workspace.yaml")) {
        Manager::Pnpm
    } else if fs_probe::is_file(&manifest_dir.join("bunfig.toml")) {
        Manager::Bun
    } else {
        Manager::Npm
    }
}

fn read_settings(root: &Path, manager: Manager, ctx: &NpmParseContext) -> Option<Settings> {
    match manager {
        Manager::Npm => ctx.config_cache.native(&root.join(".npmrc")),
        Manager::Pnpm => {
            let path = root.join("pnpm-workspace.yaml");
            cached(&ctx.native_cache.pnpm, &path, |content| {
                parse_pnpm(&path, content)
            })
        }
        Manager::Bun => {
            let path = root.join("bunfig.toml");
            cached(&ctx.native_cache.bun, &path, |content| {
                parse_bunfig(&path, content)
            })
        }
        Manager::Yarn => None,
    }
}

/// `Settings` of the file at `path` through `cache`.
fn cached(
    cache: &MtimeFileCache<Option<Settings>>,
    path: &Path,
    parse: impl FnOnce(&str) -> Option<Settings>,
) -> Option<Settings> {
    cache.get_or_parse(path, parse)?.as_ref().clone()
}

fn span(path: &Path, count: u64, unit: TimeUnit) -> Option<NativeLimit> {
    match NativeTimeSpan::from_count(count, unit) {
        Ok(TimeSpanValue::Span(span)) => Some(NativeLimit::MinAge(span)),
        Ok(TimeSpanValue::Disabled) => None,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "ignoring an out-of-range release-age setting");
            None
        }
    }
}

fn exemptions(
    path: &Path,
    entries: &[&str],
    syntax: ExemptionSyntax,
    key: &str,
) -> Option<ExemptionList> {
    if entries.is_empty() {
        return None;
    }
    match parse_exemptions(entries, syntax) {
        Ok(list) => Some(list),
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                key,
                "ignoring an unsupported exemption list; the window holds every package"
            );
            None
        }
    }
}

pub(crate) fn settings_from_npmrc(path: &Path, native: &NpmrcNative) -> Option<Settings> {
    let cutoff = native.before.as_deref().and_then(|raw| {
        let parsed = NativeCutoff::parse_npm_date(raw);
        if parsed.is_none() {
            tracing::warn!(path = %path.display(), "ignoring a malformed .npmrc `before` value");
        }
        parsed
    });
    let (limit, source) = match cutoff {
        Some(cutoff) => (
            NativeLimit::PublishedAfter(cutoff),
            NativeCooldownSource::NpmBefore,
        ),
        None => (
            native
                .min_release_age
                .as_deref()
                .and_then(|raw| parse_npm_days(path, raw))?,
            NativeCooldownSource::NpmMinReleaseAge,
        ),
    };
    let excluded: Vec<&str> = native.exclude.iter().map(String::as_str).collect();
    Some(Settings {
        limit,
        source,
        exemptions: exemptions(
            path,
            &excluded,
            ExemptionSyntax::Npm,
            "min-release-age-exclude",
        ),
    })
}

/// npm's `min-release-age` is a whole number of days; anything else is ignored.
fn parse_npm_days(path: &Path, raw: &str) -> Option<NativeLimit> {
    let Ok(days) = raw.parse::<u64>() else {
        tracing::warn!(path = %path.display(), "ignoring a non-integer .npmrc `min-release-age` value");
        return None;
    };
    span(path, days, TimeUnit::Day)
}

pub(crate) fn parse_pnpm(path: &Path, content: &str) -> Option<Settings> {
    deps_core::check_yaml_bounds(content, "pnpm-workspace.yaml").ok()?;
    let documents = YamlLoader::load_from_str(content).ok()?;
    let root = documents.first()?.as_hash()?;
    let get = |key: &str| root.get(&Yaml::String(key.to_owned()));
    if matches!(get("minimumReleaseAgeStrict"), Some(Yaml::Boolean(false))) {
        return None;
    }
    let limit = match get("minimumReleaseAge")? {
        Yaml::Integer(minutes) if *minutes > 0 => {
            span(path, u64::try_from(*minutes).ok()?, TimeUnit::Minute)?
        }
        Yaml::Integer(0) => return None,
        _ => {
            tracing::warn!(path = %path.display(), "ignoring a malformed pnpm `minimumReleaseAge` value");
            return None;
        }
    };
    let excluded: Vec<&str> = get("minimumReleaseAgeExclude")
        .and_then(Yaml::as_vec)
        .map(|entries| entries.iter().filter_map(Yaml::as_str).collect())
        .unwrap_or_default();
    Some(Settings {
        limit,
        source: NativeCooldownSource::PnpmMinimumReleaseAge,
        exemptions: exemptions(
            path,
            &excluded,
            ExemptionSyntax::Pnpm,
            "minimumReleaseAgeExclude",
        ),
    })
}

fn parse_bunfig(path: &Path, content: &str) -> Option<Settings> {
    let document = deps_core::parse_toml_checked(content).ok()?;
    let install = document.as_table()?.get("install")?.as_table()?;
    let seconds = install.get("minimumReleaseAge")?.as_integer();
    let Some(seconds) = seconds.and_then(|value| u64::try_from(value).ok()) else {
        tracing::warn!(path = %path.display(), "ignoring a malformed Bun `minimumReleaseAge` value");
        return None;
    };
    let excluded: Vec<&str> = install
        .get("minimumReleaseAgeExcludes")
        .and_then(|value| value.as_array())
        .map(|entries| entries.iter().filter_map(|entry| entry.as_str()).collect())
        .unwrap_or_default();
    Some(Settings {
        limit: span(path, seconds, TimeUnit::Second)?,
        source: NativeCooldownSource::BunMinimumReleaseAge,
        exemptions: exemptions(
            path,
            &excluded,
            ExemptionSyntax::Bun,
            "minimumReleaseAgeExcludes",
        ),
    })
}
