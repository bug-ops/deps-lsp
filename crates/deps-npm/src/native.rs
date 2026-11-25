//! The package managers' own release-age settings (spec 099, #2041): npm `min-release-age` /
//! `before` in `.npmrc`, pnpm `minimumReleaseAge` in `pnpm-workspace.yaml`, Bun
//! `[install] minimumReleaseAge` in `bunfig.toml` and Yarn `npmMinimalAgeGate` in `.yarnrc.yml`.
//!
//! Which manager applies is decided by the lock file the project resolves with, and only that
//! manager's own file is read, from the project root alone (the directory of the located lock
//! file, else the manifest directory). The root must lie inside the repository: the user's home
//! directory, and any directory above it, is never a project root, so a stray lock file there
//! cannot make the user's own config apply. A value this module cannot interpret exactly is
//! ignored with a warning naming the file, so a malformed setting never invents a window. Files
//! are read through the shared mtime caches.
//!
//! Yarn's gate needs Yarn >= 4.10 and its per-scope keys Yarn >= 4.17. A per-scope key under any
//! `npmScopes.<scope>` entry proves the latter (older Yarn rejects the key name), and only then
//! does a scope entry without the key get Yarn's own 1 day default; Yarn's global default is
//! never assumed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use deps_core::native_cooldown::{
    Exemption, ExemptionList, ExemptionSyntax, GateOrigin, NativeCooldown, NativeCooldownSource,
    NativeCutoff, NativeLimit, NativeTimeSpan, NpmScopeLabel, RepositoryScope, TimeSpanValue,
    TimeUnit, parse_exemptions, parse_yarn_duration,
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

/// A window together with the setting it came from.
#[derive(Debug, Clone)]
struct Window {
    limit: NativeLimit,
    source: NativeCooldownSource,
}

/// One `npmScopes.<scope>` entry of a `.yarnrc.yml` that declares per-scope keys.
#[derive(Debug, Clone, Copy)]
enum ScopeGate {
    /// The scope's own window, or Yarn's 1 day default for an entry without the key.
    Window {
        limit: NativeLimit,
        origin: GateOrigin,
    },
    /// The scope's own `0`: no window, whatever the global value is.
    Off,
    /// The scope's own value is malformed: dropped, the global window applies.
    Fallthrough,
}

/// Whether a `.yarnrc.yml` proves Yarn >= 4.17 (per-scope keys exist) by declaring one.
#[derive(Debug, Clone, Default)]
enum ScopedGates {
    /// No per-scope key anywhere: scope entries carry no window.
    #[default]
    Absent,
    /// At least one scope entry names the key; every mapping entry is listed by scope key.
    Declared(HashMap<String, ScopeGate>),
}

/// A parsed window with the exemption list that goes with it.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    global: Option<Window>,
    scopes: ScopedGates,
    exemptions: Option<ExemptionList>,
}

impl Settings {
    fn global(
        limit: NativeLimit,
        source: NativeCooldownSource,
        exemptions: Option<ExemptionList>,
    ) -> Self {
        Self {
            global: Some(Window { limit, source }),
            scopes: ScopedGates::Absent,
            exemptions,
        }
    }

    /// The window of package `name`: its scope's gate, else the global one.
    fn window_for(&self, name: &str) -> Option<Window> {
        let gate = match &self.scopes {
            ScopedGates::Declared(gates) => {
                scope_of(name).and_then(|scope| gates.get(scope).zip(Some(scope)))
            }
            ScopedGates::Absent => None,
        };
        match gate {
            Some((ScopeGate::Off, _)) => None,
            // A scope name outside the printable charset cannot be quoted in a source label, so
            // its window is dropped and the global one applies.
            Some((ScopeGate::Window { limit, origin }, scope)) => match NpmScopeLabel::new(scope) {
                Some(scope) => Some(Window {
                    limit: *limit,
                    source: NativeCooldownSource::YarnScopeNpmMinimalAgeGate {
                        scope,
                        origin: *origin,
                    },
                }),
                None => self.global.clone(),
            },
            Some((ScopeGate::Fallthrough, _)) | None => self.global.clone(),
        }
    }

    /// The cooldown of the dependency `dep`, or `None` when it has no window or is exempt.
    fn cooldown_for(&self, dep: &NpmDependency) -> Option<NativeCooldown> {
        let Window { limit, source } = self.window_for(Dependency::name(dep).as_str())?;
        let cooldown = NativeCooldown::new(limit, source);
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

/// The scope of an `@scope/name` package (without the `@`).
fn scope_of(name: &str) -> Option<&str> {
    name.strip_prefix('@')?
        .split_once('/')
        .map(|(scope, _)| scope)
}

/// Per-file memoization of the release-age settings of `pnpm-workspace.yaml`, `bunfig.toml` and
/// `.yarnrc.yml` files, keyed by path and invalidated by mtime. `.npmrc` goes through
/// [`crate::config::NpmConfigCache`] instead, so one parser reads that file.
#[derive(Debug)]
pub(crate) struct NativeSettingsCache {
    pnpm: MtimeFileCache<Option<Settings>>,
    bun: MtimeFileCache<Option<Settings>>,
    yarn: MtimeFileCache<Option<Settings>>,
}

impl Default for NativeSettingsCache {
    fn default() -> Self {
        Self {
            pnpm: MtimeFileCache::new(deps_core::DEFAULT_MAX_CACHED_FILES, "pnpm release-age"),
            bun: MtimeFileCache::new(deps_core::DEFAULT_MAX_CACHED_FILES, "bun release-age"),
            yarn: MtimeFileCache::new(deps_core::DEFAULT_MAX_CACHED_FILES, "yarn release-age"),
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
        Manager::Yarn => {
            let path = root.join(".yarnrc.yml");
            cached(&ctx.native_cache.yarn, &path, |content| {
                parse_yarnrc(&path, content)
            })
        }
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
    Some(Settings::global(
        limit,
        source,
        exemptions(
            path,
            &excluded,
            ExemptionSyntax::Npm,
            "min-release-age-exclude",
        ),
    ))
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
        .map_or_default(|entries| entries.iter().filter_map(Yaml::as_str).collect());
    Some(Settings::global(
        limit,
        NativeCooldownSource::PnpmMinimumReleaseAge,
        exemptions(
            path,
            &excluded,
            ExemptionSyntax::Pnpm,
            "minimumReleaseAgeExclude",
        ),
    ))
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
        .map_or_default(|entries| entries.iter().filter_map(|entry| entry.as_str()).collect());
    Some(Settings::global(
        span(path, seconds, TimeUnit::Second)?,
        NativeCooldownSource::BunMinimumReleaseAge,
        exemptions(
            path,
            &excluded,
            ExemptionSyntax::Bun,
            "minimumReleaseAgeExcludes",
        ),
    ))
}

const GATE_KEY: &str = "npmMinimalAgeGate";

/// A Yarn duration setting after parsing.
enum Gate {
    Window(NativeLimit),
    Off,
    Malformed,
}

/// The text of a YAML scalar as Yarn would read it, or `None` for a non-scalar.
fn scalar_text(value: &Yaml) -> Option<String> {
    match value {
        Yaml::String(text) | Yaml::Real(text) => Some(text.clone()),
        Yaml::Integer(number) => Some(number.to_string()),
        _ => None,
    }
}

fn parse_gate(value: &Yaml) -> Gate {
    match scalar_text(value).map(|raw| parse_yarn_duration(&raw)) {
        Some(Ok(TimeSpanValue::Span(span))) => Gate::Window(NativeLimit::MinAge(span)),
        Some(Ok(TimeSpanValue::Disabled)) => Gate::Off,
        Some(Err(_)) | None => Gate::Malformed,
    }
}

/// The settings of one `.yarnrc.yml` that were ignored, so a file with thousands of bad entries
/// logs one summary instead of one line per entry.
#[derive(Debug, Default)]
struct IgnoredSettings {
    count: usize,
    /// The first ignored setting, rendered with a charset-limited scope name.
    first: Option<String>,
}

/// One ignored `.yarnrc.yml` setting.
#[derive(Debug, Clone, Copy)]
enum Ignored<'a> {
    /// The global `npmMinimalAgeGate` has a malformed value.
    GlobalGate,
    /// `npmScopes.<scope>.npmMinimalAgeGate` has a malformed value.
    ScopeGate(&'a str),
    /// `npmScopes.<scope>` is not a mapping.
    ScopeEntry(&'a str),
}

/// A scope name safe to quote in a log line.
fn printable_scope(scope: &str) -> String {
    NpmScopeLabel::new(scope).map_or_else(
        || "<unprintable scope>".to_owned(),
        |label| label.as_str().to_owned(),
    )
}

impl IgnoredSettings {
    fn record(&mut self, ignored: Ignored<'_>) {
        self.count += 1;
        if self.first.is_none() {
            self.first = Some(match ignored {
                Ignored::GlobalGate => format!("malformed {GATE_KEY}"),
                Ignored::ScopeGate(scope) => {
                    format!("malformed npmScopes.{}.{GATE_KEY}", printable_scope(scope))
                }
                Ignored::ScopeEntry(scope) => {
                    format!("non-mapping npmScopes.{}", printable_scope(scope))
                }
            });
        }
    }

    fn warn(&self, path: &Path) {
        if let Some(first) = &self.first {
            tracing::warn!(
                path = %path.display(),
                count = self.count,
                first = %first,
                "ignoring malformed Yarn release-age settings"
            );
        }
    }
}

/// Yarn's built-in `npmMinimalAgeGate` default for a scope entry (berry >= 4.17): 1 day.
fn yarn_scope_default() -> Option<NativeLimit> {
    match NativeTimeSpan::from_count(1, TimeUnit::Day) {
        Ok(TimeSpanValue::Span(span)) => Some(NativeLimit::MinAge(span)),
        Ok(TimeSpanValue::Disabled) | Err(_) => None,
    }
}

/// The per-scope gates of `npmScopes`: `Declared` when some mapping entry names the gate key
/// (whatever its value), `Absent` otherwise.
fn parse_yarn_scopes(root: &yaml_rust2::yaml::Hash, ignored: &mut IgnoredSettings) -> ScopedGates {
    let Some(scopes) = root
        .get(&Yaml::String("npmScopes".to_owned()))
        .and_then(Yaml::as_hash)
    else {
        return ScopedGates::Absent;
    };
    let key = Yaml::String(GATE_KEY.to_owned());
    let entries: Vec<(&str, &yaml_rust2::yaml::Hash)> = scopes
        .iter()
        .filter_map(|(scope, entry)| {
            let (scope, entry) = (scope.as_str()?, entry.as_hash());
            if entry.is_none() {
                ignored.record(Ignored::ScopeEntry(scope));
            }
            Some((scope, entry?))
        })
        .collect();
    if !entries.iter().any(|(_, entry)| entry.contains_key(&key)) {
        return ScopedGates::Absent;
    }
    let gates = entries
        .into_iter()
        .map(|(scope, entry)| {
            let gate = match entry.get(&key) {
                Some(value) => match parse_gate(value) {
                    Gate::Window(limit) => ScopeGate::Window {
                        limit,
                        origin: GateOrigin::Configured,
                    },
                    Gate::Off => ScopeGate::Off,
                    Gate::Malformed => {
                        ignored.record(Ignored::ScopeGate(scope));
                        ScopeGate::Fallthrough
                    }
                },
                None => {
                    yarn_scope_default().map_or(ScopeGate::Fallthrough, |limit| ScopeGate::Window {
                        limit,
                        origin: GateOrigin::ManagerDefault,
                    })
                }
            };
            (scope.to_owned(), gate)
        })
        .collect();
    ScopedGates::Declared(gates)
}

fn parse_yarnrc(path: &Path, content: &str) -> Option<Settings> {
    deps_core::check_yaml_bounds(content, ".yarnrc.yml").ok()?;
    let documents = YamlLoader::load_from_str(content).ok()?;
    let root = documents.first()?.as_hash()?;
    let mut ignored = IgnoredSettings::default();
    let global = match root.get(&Yaml::String(GATE_KEY.to_owned())) {
        Some(value) => match parse_gate(value) {
            Gate::Window(limit) => Some(Window {
                limit,
                source: NativeCooldownSource::YarnNpmMinimalAgeGate,
            }),
            Gate::Off => None,
            Gate::Malformed => {
                ignored.record(Ignored::GlobalGate);
                None
            }
        },
        None => None,
    };
    let scopes = parse_yarn_scopes(root, &mut ignored);
    ignored.warn(path);
    if global.is_none() && matches!(scopes, ScopedGates::Absent) {
        return None;
    }
    let preapproved: Vec<&str> = root
        .get(&Yaml::String("npmPreapprovedPackages".to_owned()))
        .and_then(Yaml::as_vec)
        .map_or_default(|entries| entries.iter().filter_map(Yaml::as_str).collect());
    Some(Settings {
        global,
        scopes,
        exemptions: exemptions(
            path,
            &preapproved,
            ExemptionSyntax::Npm,
            "npmPreapprovedPackages",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn explicit_scope_off_wins_even_when_the_scope_name_is_not_a_valid_label() {
        let yaml = "npmMinimalAgeGate: 7d\nnpmScopes:\n  \"bad scope\":\n    npmMinimalAgeGate: 0\n  ok:\n    npmMinimalAgeGate: 3d\n";
        let settings = parse_yarnrc(Path::new(".yarnrc.yml"), yaml).expect("declared file");
        assert!(settings.window_for("@bad scope/x").is_none());
        assert!(settings.window_for("@ok/x").is_some());
        assert!(settings.window_for("lodash").is_some());
    }

    #[test]
    fn explicit_scope_window_with_an_invalid_label_falls_back_to_the_global_window() {
        let yaml =
            "npmMinimalAgeGate: 7d\nnpmScopes:\n  \"bad scope\":\n    npmMinimalAgeGate: 3d\n";
        let settings = parse_yarnrc(Path::new(".yarnrc.yml"), yaml).expect("declared file");
        let window = settings.window_for("@bad scope/x").expect("global window");
        assert_eq!(window.source, NativeCooldownSource::YarnNpmMinimalAgeGate);
    }

    #[test]
    fn ignored_settings_summarize_many_entries_into_one_first_name() {
        let mut ignored = IgnoredSettings::default();
        ignored.record(Ignored::ScopeGate("first"));
        for index in 0..10_000 {
            ignored.record(Ignored::ScopeEntry(&format!("scope{index}")));
        }
        assert_eq!(ignored.count, 10_001);
        assert_eq!(
            ignored.first.as_deref(),
            Some("malformed npmScopes.first.npmMinimalAgeGate")
        );
    }

    #[test]
    fn ignored_settings_never_echo_an_unprintable_scope_name() {
        let mut ignored = IgnoredSettings::default();
        ignored.record(Ignored::ScopeGate("evil\nscope"));
        assert_eq!(
            ignored.first.as_deref(),
            Some("malformed npmScopes.<unprintable scope>.npmMinimalAgeGate")
        );
    }

    #[test]
    fn a_global_malformed_gate_is_named_without_a_scope() {
        let mut ignored = IgnoredSettings::default();
        ignored.record(Ignored::GlobalGate);
        assert_eq!(
            ignored.first.as_deref(),
            Some("malformed npmMinimalAgeGate")
        );
    }

    #[test]
    fn a_non_mapping_scope_entry_is_named_as_such_and_does_not_declare_the_file() {
        let mut ignored = IgnoredSettings::default();
        ignored.record(Ignored::ScopeEntry("myorg"));
        assert_eq!(
            ignored.first.as_deref(),
            Some("non-mapping npmScopes.myorg")
        );

        let yaml = "npmMinimalAgeGate: 7d\nnpmScopes:\n  myorg: oops\n";
        let settings = parse_yarnrc(Path::new(".yarnrc.yml"), yaml).expect("global window");
        assert_matches!(settings.scopes, ScopedGates::Absent);
    }

    #[test]
    fn many_malformed_scope_entries_still_parse_in_one_pass() {
        let mut yaml = String::from("npmScopes:\n  ok:\n    npmMinimalAgeGate: 7d\n");
        for index in 0..2000 {
            yaml.push_str(&format!(
                "  bad{index}:\n    npmMinimalAgeGate: \"${{X}}\"\n"
            ));
        }
        let settings = parse_yarnrc(Path::new(".yarnrc.yml"), &yaml).expect("declared file");
        assert_matches!(settings.scopes, ScopedGates::Declared(ref gates) if gates.len() == 2001);
    }
}
