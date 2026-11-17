//! `deno.lock` resolved-version provider (#1924, spec 091).
//!
//! Only resolved-version extraction is implemented: integrity hashes, dependency graphs and the
//! `remote` section are out of scope. The Deno CLI normalizes the request keys of the
//! `specifiers` map (`^1.0.0` becomes `1`, an unversioned request becomes `*`, requests that
//! resolve identically may merge), so entries are matched to manifest dependencies by package
//! name (`jsr:@std/path`), never by the exact manifest specifier. The input is untrusted
//! repository content and goes through the shared depth-bounded JSONC path
//! ([`deps_core::json_ast::parse_jsonc_typed`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use deps_core::error::{DepsError, Result};
use deps_core::json_ast::parse_jsonc_typed;
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest, read_and_parse_lockfile,
};
use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::specifier::parse_specifier;

const FILE_TYPE: &str = "deno.lock";

/// Lock file names, the single source for both locating and `Ecosystem::lockfile_filenames`.
pub(crate) const LOCKFILE_NAMES: &[&str] = &["deno.lock"];

/// Schema versions of `deno.lock` this provider reads; any other value fails closed.
///
/// Exhaustive on purpose: a new schema version must be handled at every `match` on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchemaVersion {
    /// Specifiers nested under `packages`, values carry the `jsr:` / `npm:` prefix.
    V3,
    /// Top-level `specifiers`, values are bare versions (npm with a peer suffix).
    V4,
    /// Same layout as [`SchemaVersion::V4`] plus a `workspace` section.
    V5,
}

impl SchemaVersion {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "3" => Some(Self::V3),
            "4" => Some(Self::V4),
            "5" => Some(Self::V5),
            _ => None,
        }
    }
}

/// A JSON value that is either a string or anything else (ignored), so a value of an
/// unexpected shape never fails the whole file.
#[derive(Deserialize)]
#[serde(untagged)]
enum Lenient {
    Text(String),
    Other(IgnoredAny),
}

/// Either an object whose string-valued entries are kept, or any other shape (ignored).
#[derive(Deserialize)]
#[serde(untagged)]
enum LenientMap {
    Entries(HashMap<String, Lenient>),
    Other(IgnoredAny),
}

fn string_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    Ok(match LenientMap::deserialize(deserializer)? {
        LenientMap::Entries(entries) => entries
            .into_iter()
            .filter_map(|(key, value)| match value {
                Lenient::Text(text) => Some((key, text)),
                Lenient::Other(_) => None,
            })
            .collect(),
        LenientMap::Other(_) => BTreeMap::new(),
    })
}

/// The schema-3 `packages` wrapper that holds `specifiers`.
#[derive(Deserialize)]
struct RawPackages {
    #[serde(default, deserialize_with = "string_entries")]
    specifiers: BTreeMap<String, String>,
}

/// Lenient `packages` field: an object of the schema-3 shape, or any other shape (ignored).
#[derive(Deserialize)]
#[serde(untagged)]
enum LenientPackages {
    Packages(RawPackages),
    Other(IgnoredAny),
}

#[derive(Deserialize)]
struct RawLock {
    #[serde(default)]
    version: Option<Lenient>,
    #[serde(default, deserialize_with = "string_entries")]
    specifiers: BTreeMap<String, String>,
    #[serde(default)]
    packages: Option<LenientPackages>,
}

/// Resolves in-use versions of `jsr:` and `npm:` dependencies from a `deno.lock` file.
///
/// # Examples
///
/// ```no_run
/// use deps_core::lockfile::LockFileProvider;
/// use deps_deno::DenoLockParser;
/// use url::Url;
///
/// # async fn example() -> deps_core::error::Result<()> {
/// let manifest = Url::from_file_path("/path/to/deno.json").unwrap();
/// if let Some(lock) = DenoLockParser.locate_lockfile(&manifest) {
///     let resolved = DenoLockParser.parse_lockfile(&lock).await?;
///     println!("{:?}", resolved.version("jsr:@std/path"));
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct DenoLockParser;

impl LockFileProvider for DenoLockParser {
    fn locate_lockfile(&self, manifest_uri: &Url) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, LOCKFILE_NAMES)
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            let packages = read_and_parse_lockfile(lockfile_path, FILE_TYPE, |content| {
                parse_deno_lock(&content)
            })
            .await?;
            tracing::info!(
                "Parsed deno.lock: {} packages from {}",
                packages.len(),
                lockfile_path.display()
            );
            Ok(packages)
        })
    }
}

fn lock_error(message: &str) -> DepsError {
    DepsError::parse_error(FILE_TYPE, &message)
}

/// Parses `deno.lock` content (already read and size-capped) into resolved packages.
fn parse_deno_lock(content: &str) -> Result<ResolvedPackages> {
    let Some(raw) = parse_jsonc_typed::<RawLock>(content, FILE_TYPE)? else {
        return Ok(ResolvedPackages::new());
    };
    let version = match raw.version {
        Some(Lenient::Text(text)) => SchemaVersion::parse(&text)
            .ok_or_else(|| lock_error(&format!("unsupported deno.lock version \"{text}\"")))?,
        Some(Lenient::Other(_)) => return Err(lock_error("deno.lock version is not a string")),
        None => return Err(lock_error("deno.lock has no version field")),
    };

    let specifiers = match version {
        SchemaVersion::V3 => match raw.packages {
            Some(LenientPackages::Packages(packages)) => packages.specifiers,
            Some(LenientPackages::Other(_)) | None => BTreeMap::new(),
        },
        SchemaVersion::V4 | SchemaVersion::V5 => raw.specifiers,
    };

    let distinct: BTreeSet<(String, String)> = specifiers
        .iter()
        .filter_map(|(request, resolved)| resolve_entry(request, resolved))
        .collect();
    let mut packages = ResolvedPackages::new();
    for (name, version) in distinct {
        packages.insert(ResolvedPackage::new(
            name,
            version,
            ResolvedSource::RegistryPin,
        ));
    }
    Ok(packages)
}

/// Maps one `specifiers` entry to `(package name, resolved version)`.
///
/// The resolved value is a bare version in schema 4/5 and `jsr:name@version` in schema 3; both
/// are reduced to the version with any npm peer suffix (`_peer@x.y.z`) removed.
fn resolve_entry(request: &str, resolved: &str) -> Option<(String, String)> {
    let name = parse_specifier(request)?.name;
    let version = match parse_specifier(resolved) {
        Some(spec) => spec.version_req.unwrap_or_default(),
        None => resolved.to_owned(),
    };
    let version = version
        .split_once('_')
        .map_or(version.as_str(), |(base, _)| base)
        .to_owned();
    (!version.is_empty()).then_some((name, version))
}

/// Fuzz-only entry point for the `deno.lock` parser. Gated on the `fuzzing` Cargo feature so it
/// stays out of the crate's public API surface in a normal build.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_deno_lock(content: &str) {
    let _ = parse_deno_lock(content);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_entry_strips_peer_suffix_and_scheme_prefix() {
        assert_eq!(
            resolve_entry("npm:react-dom@^18", "18.3.1_react@18.3.1"),
            Some(("npm:react-dom".into(), "18.3.1".into()))
        );
        assert_eq!(
            resolve_entry("npm:chalk@^5", "npm:chalk@5.3.0"),
            Some(("npm:chalk".into(), "5.3.0".into()))
        );
    }
}
