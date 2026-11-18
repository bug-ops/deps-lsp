//! uv's release-age settings (`exclude-newer`, `exclude-newer-package`) read from the
//! repository's own `uv.toml` and `[tool.uv]` tables.
//!
//! Resolution follows uv's nearest-file rule: only the closest directory (the manifest's, then
//! its parents) that holds a `uv.toml` or a `pyproject.toml` with a `[tool.uv]` table is read,
//! `uv.toml` wins over `[tool.uv]` in that directory, and nothing is merged with a farther
//! directory. Inside the chosen file a package-specific `exclude-newer-package` entry beats an
//! index-level `exclude-newer` (`[[tool.uv.index]]` / `[[index]]`), which beats the global
//! `exclude-newer`. A dependency's index is the one `[tool.uv.sources]` pins it to, else the
//! file's only non-explicit index when that index is `default = true`. Index-level
//! `exclude-newer-package` is not read. A workspace member reads its workspace root's file
//! instead of its own (uv ignores a member's `[tool.uv]`). The user's home directory is never
//! read, so a developer's personal config cannot change what an opened repository holds back.
//! An invalid value counts as absent and is reported in one warning per file.
//!
//! The open document's text is used for its own `pyproject.toml` (an unsaved edit takes effect
//! immediately); every other file is read from disk through an mtime-gated cache.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use deps_core::UserHome;
use deps_core::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH;
use deps_core::mtime_cache::{DEFAULT_MAX_CACHED_FILES, MtimeFileCache};
use deps_core::native_cooldown::{
    NativeCooldown, NativeCooldownSource, NativeCutoff, NativeLimit, PypiPackageLabel,
    TimeSpanValue, UvIndexLabel, parse_uv_span,
};
use toml_span::value::Table;

const UV_TOML: &str = "uv.toml";
const PYPROJECT_TOML: &str = "pyproject.toml";
const GLOBAL_KEY: &str = "exclude-newer";
const PACKAGE_KEY: &str = "exclude-newer-package";
const INDEX_KEY: &str = "index";
/// Index entries read per file; a hostile file cannot make a lookup expensive.
const MAX_INDEXES: usize = 256;

/// A valid value of one release-age key.
#[derive(Debug, Clone, Copy)]
enum Setting {
    /// A window or a fixed cutoff.
    Limit(NativeLimit),
    /// A zero span or `false`: the key turns the window off.
    Off,
}

impl Setting {
    const fn limit(self) -> Option<NativeLimit> {
        match self {
            Self::Limit(limit) => Some(limit),
            Self::Off => None,
        }
    }
}

/// One `[[index]]` / `[[tool.uv.index]]` entry that can carry a window.
#[derive(Debug)]
struct UvIndex {
    /// PEP 503-normalized name, the form `[tool.uv.sources]` bindings are keyed by.
    key: String,
    label: UvIndexLabel,
    is_default: bool,
    is_explicit: bool,
    setting: Option<Setting>,
}

/// The release-age keys of one `uv.toml` or `pyproject.toml`.
#[derive(Debug, Default)]
pub(crate) struct UvLayer {
    global: Option<Setting>,
    /// `exclude-newer-package` entries by PEP 503-normalized name.
    packages: HashMap<String, Setting>,
    indexes: Vec<UvIndex>,
    /// Whether the file configures uv at all: any `uv.toml`, or a pyproject with `[tool.uv]`.
    configures_uv: bool,
    /// Whether `[tool.uv.workspace]` is declared, which makes this directory a workspace root.
    declares_workspace: bool,
    /// `[tool.uv.workspace] members` and `exclude` globs, relative to this directory.
    workspace_members: Vec<String>,
    workspace_exclude: Vec<String>,
    invalid_keys: Vec<&'static str>,
    warned: AtomicBool,
}

impl UvLayer {
    /// Reads `content` as a `uv.toml` or a `pyproject.toml`.
    fn parse(content: &str, file: UvFile) -> Self {
        let mut layer = Self {
            configures_uv: file == UvFile::UvToml,
            ..Self::default()
        };
        let Ok(doc) = deps_core::parse_toml_checked(content) else {
            return layer;
        };
        let Some(root) = doc.as_table() else {
            return layer;
        };
        match file {
            UvFile::UvToml => layer.read_uv_table(root),
            UvFile::Pyproject => {
                if let Some(uv) = root
                    .get("tool")
                    .and_then(|tool| tool.as_table())
                    .and_then(|tool| tool.get("uv"))
                    .and_then(|uv| uv.as_table())
                {
                    layer.configures_uv = true;
                    if let Some(workspace) = uv.get("workspace").and_then(|ws| ws.as_table()) {
                        layer.declares_workspace = true;
                        layer.workspace_members = glob_list(workspace, "members");
                        layer.workspace_exclude = glob_list(workspace, "exclude");
                    }
                    layer.read_uv_table(uv);
                }
            }
        }
        layer
    }

    fn read_uv_table(&mut self, uv: &Table<'_>) {
        if let Some(value) = uv.get(GLOBAL_KEY) {
            match value.as_str().and_then(parse_limit) {
                Some(setting) => self.global = Some(setting),
                None => self.invalid_keys.push(GLOBAL_KEY),
            }
        }
        self.read_indexes(uv);
        if let Some(packages) = uv.get(PACKAGE_KEY) {
            let Some(packages) = packages.as_table() else {
                self.invalid_keys.push(PACKAGE_KEY);
                return;
            };
            for (name, value) in packages {
                let setting = match (value.as_bool(), value.as_str()) {
                    (Some(false), _) => Some(Setting::Off),
                    (_, Some(raw)) => parse_limit(raw),
                    _ => None,
                };
                match setting {
                    Some(setting) => {
                        self.packages
                            .insert(crate::name::normalize(&name.name), setting);
                    }
                    None => self.invalid_keys.push(PACKAGE_KEY),
                }
            }
        }
    }

    /// Reads the `name`, `default`, `explicit` and `exclude-newer` keys of every index entry;
    /// every other index key is irrelevant here and ignored without a warning.
    fn read_indexes(&mut self, uv: &Table<'_>) {
        let Some(entries) = uv.get(INDEX_KEY).and_then(|value| value.as_array()) else {
            return;
        };
        for table in entries
            .iter()
            .take(MAX_INDEXES)
            .filter_map(|entry| entry.as_table())
        {
            let Some(name) = table.get("name") else {
                continue;
            };
            let Some(name) = name.as_str() else {
                self.invalid_keys.push("index.name");
                continue;
            };
            let is_default = self.flag(table, "default", "index.default");
            let is_explicit = self.flag(table, "explicit", "index.explicit");
            let setting = table.get(GLOBAL_KEY).and_then(|value| {
                let setting = match (value.as_bool(), value.as_str()) {
                    (Some(false), _) => Some(Setting::Off),
                    (_, Some(raw)) => parse_limit(raw),
                    _ => None,
                };
                if setting.is_none() {
                    self.invalid_keys.push("index.exclude-newer");
                }
                setting
            });
            if let Some(label) = UvIndexLabel::new(name) {
                self.indexes.push(UvIndex {
                    key: crate::name::normalize(name),
                    label,
                    is_default,
                    is_explicit,
                    setting,
                });
            }
        }
    }

    /// A boolean index key; a non-boolean value is recorded as invalid and reads as `false`.
    fn flag(&mut self, table: &Table<'_>, key: &str, invalid: &'static str) -> bool {
        match table.get(key).map(|value| value.as_bool()) {
            None => false,
            Some(Some(flag)) => flag,
            Some(None) => {
                self.invalid_keys.push(invalid);
                false
            }
        }
    }

    /// The index whose window applies to a dependency: the pinned one, else the file's only
    /// non-explicit index when it is the default.
    fn index_for(&self, pinned: Option<&UvIndexLabel>) -> Option<&UvIndex> {
        if let Some(pinned) = pinned {
            return self
                .indexes
                .iter()
                .find(|index| index.key == pinned.as_str());
        }
        let mut open = self.indexes.iter().filter(|index| !index.is_explicit);
        let only = open.next().filter(|_| open.next().is_none())?;
        only.is_default.then_some(only)
    }

    /// Whether the project at `relative` (from this workspace root) is a member: matched by a
    /// `members` glob and not by an `exclude` glob.
    fn has_member(&self, relative: &Path) -> bool {
        let Some(relative) = relative.to_str() else {
            return false;
        };
        let relative = relative.replace('\\', "/");
        let matches = |globs: &[String]| globs.iter().any(|glob| glob_matches(glob, &relative));
        matches(&self.workspace_members) && !matches(&self.workspace_exclude)
    }

    fn warn_invalid_once(&self, path: &Path) {
        const MAX_NAMED_KEYS: usize = 5;
        if self.invalid_keys.is_empty() || self.warned.swap(true, Ordering::Relaxed) {
            return;
        }
        let keys = self
            .invalid_keys
            .iter()
            .take(MAX_NAMED_KEYS)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        tracing::warn!(
            path = %path.display(),
            count = self.invalid_keys.len(),
            %keys,
            "ignoring malformed uv release-age settings; no window applies from them"
        );
    }
}

/// Which uv configuration file a layer is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UvFile {
    UvToml,
    Pyproject,
}

impl UvFile {
    fn of(path: &Path) -> Self {
        if path.file_name().is_some_and(|name| name == UV_TOML) {
            Self::UvToml
        } else {
            Self::Pyproject
        }
    }
}

/// The string entries of a workspace glob list, bounded so a hostile file cannot make a
/// membership check expensive.
fn glob_list(workspace: &Table<'_>, key: &str) -> Vec<String> {
    const MAX_GLOBS: usize = 256;
    const MAX_GLOB_BYTES: usize = 512;
    workspace
        .get(key)
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.as_str())
        .filter(|glob| glob.len() <= MAX_GLOB_BYTES)
        .take(MAX_GLOBS)
        .map(|glob| {
            glob.trim_end_matches('/')
                .trim_start_matches("./")
                .to_owned()
        })
        .collect()
}

/// Matches `path` against a uv workspace glob: segments split on `/`, `*` and `?` stay within
/// a segment, and a `**` segment matches any number of segments.
fn glob_matches(glob: &str, path: &str) -> bool {
    let pattern: Vec<&str> = glob.split('/').collect();
    let segments: Vec<&str> = path.split('/').collect();
    segments_match(&pattern, &segments)
}

fn segments_match(pattern: &[&str], segments: &[&str]) -> bool {
    match pattern.split_first() {
        None => segments.is_empty(),
        Some((&"**", rest)) => (0..=segments.len()).any(|skip| {
            segments
                .get(skip..)
                .is_some_and(|tail| segments_match(rest, tail))
        }),
        Some((head, rest)) => segments.split_first().is_some_and(|(first, tail)| {
            segment_matches(head, first) && segments_match(rest, tail)
        }),
    }
}

/// Single-segment wildcard match (`*` any run, `?` one byte), iterative so it stays linear in
/// the pattern times the text.
fn segment_matches(pattern: &str, text: &str) -> bool {
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || Some(&c) == text.get(t) => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|&c| c == b'*'))
}

/// An `exclude-newer` value: a friendly or ISO 8601 span, or an RFC 3339 cutoff.
fn parse_limit(raw: &str) -> Option<Setting> {
    match parse_uv_span(raw) {
        Ok(TimeSpanValue::Span(span)) => Some(Setting::Limit(NativeLimit::MinAge(span))),
        Ok(TimeSpanValue::Disabled) => Some(Setting::Off),
        Err(_) => NativeCutoff::parse_rfc3339(raw)
            .map(|cutoff| Setting::Limit(NativeLimit::PublishedAfter(cutoff))),
    }
}

/// Per-file memoization of the release-age keys of `uv.toml` and `pyproject.toml` files.
#[derive(Debug)]
pub(crate) struct UvConfigCache(MtimeFileCache<UvLayer>);

impl Default for UvConfigCache {
    fn default() -> Self {
        Self(MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "uv config"))
    }
}

impl UvConfigCache {
    fn layer(&self, path: &Path) -> Option<Arc<UvLayer>> {
        let file = UvFile::of(path);
        let layer = self
            .0
            .get_or_parse(path, |content| UvLayer::parse(content, file))?;
        layer.warn_invalid_once(path);
        Some(layer)
    }

    /// The configuration file whose release-age keys apply to the `pyproject.toml` in
    /// `manifest_dir`. `buffer` is that document's current text.
    pub(crate) fn resolve(&self, manifest_dir: &Path, buffer: &str) -> UvNativeConfig {
        let home = UserHome::current();
        let dirs: Vec<&Path> = manifest_dir
            .ancestors()
            .take(MAX_CONFIG_ANCESTOR_DEPTH)
            .take_while(|dir| !home.is_some_and(|home| home.is(dir)))
            .collect();

        // Most pyprojects never mention uv, so the open buffer is parsed again only when it can.
        let buffer_layer = Arc::new(if buffer.contains("uv") {
            UvLayer::parse(buffer, UvFile::Pyproject)
        } else {
            UvLayer::default()
        });
        buffer_layer.warn_invalid_once(&manifest_dir.join(PYPROJECT_TOML));

        let layer_in = |dir: &Path| -> Option<Arc<UvLayer>> {
            let uv_toml = self.layer(&dir.join(UV_TOML));
            if uv_toml.is_some() {
                return uv_toml;
            }
            if dir == manifest_dir {
                return buffer_layer
                    .configures_uv
                    .then(|| Arc::clone(&buffer_layer));
            }
            self.layer(&dir.join(PYPROJECT_TOML))
                .filter(|layer| layer.configures_uv)
        };
        let is_member_of = |root: &Path, layer: &UvLayer| {
            manifest_dir
                .strip_prefix(root)
                .is_ok_and(|relative| layer.has_member(relative))
        };

        let workspace_root = if buffer_layer.declares_workspace {
            dirs.first().copied()
        } else {
            dirs.iter().skip(1).copied().find(|dir| {
                self.layer(&dir.join(PYPROJECT_TOML))
                    .is_some_and(|layer| layer.declares_workspace && is_member_of(dir, &layer))
            })
        };
        let layer = match workspace_root {
            Some(root) => layer_in(root),
            None => dirs.iter().find_map(|dir| layer_in(dir)),
        };
        UvNativeConfig { layer }
    }
}

/// The configuration file that applies to one manifest, if any.
#[derive(Debug)]
pub(crate) struct UvNativeConfig {
    layer: Option<Arc<UvLayer>>,
}

impl UvNativeConfig {
    /// The window for the package with PEP 503-normalized `name` pinned to `uv_index`, or `None`
    /// when no window applies. Precedence: package, then index, then global.
    pub(crate) fn cooldown_for(
        &self,
        name: &str,
        uv_index: Option<&UvIndexLabel>,
    ) -> Option<NativeCooldown> {
        let layer = self.layer.as_ref()?;
        if let Some(setting) = layer.packages.get(name).copied() {
            let package = PypiPackageLabel::new(name)?;
            return setting.limit().map(|limit| {
                NativeCooldown::new(
                    limit,
                    NativeCooldownSource::UvExcludeNewerPackage { package },
                )
            });
        }
        if let Some(index) = layer.index_for(uv_index)
            && let Some(setting) = index.setting
        {
            return setting.limit().map(|limit| {
                NativeCooldown::new(
                    limit,
                    NativeCooldownSource::UvIndexExcludeNewer {
                        index: index.label.clone(),
                    },
                )
            });
        }
        layer
            .global?
            .limit()
            .map(|limit| NativeCooldown::new(limit, NativeCooldownSource::UvExcludeNewer))
    }
}
