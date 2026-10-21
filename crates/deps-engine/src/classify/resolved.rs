//! Lock-file and in-use dependency version resolution.

use deps_core::CachedVersionsMap;
use deps_core::ConcreteVersion;
use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::NormalizedName;
use deps_core::PackageKey;
use deps_core::PackageVersions;
use deps_core::ResolvedCandidatesMap;
use deps_core::ResolvedVersionsMap;
use deps_core::VersionReq;
use deps_core::lockfile::{LockFileCache, LockFileProvider};
use deps_core::lsp_helpers::{PackageNaming, resolve_in_use_version};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Builds `normalized_name -> [in_use_version, ...]` (§4.5/§4.6) for every dependency with a known
/// in-use version, for the yanked-check probe in `fetch_latest_versions_parallel`.
///
/// Skips non-registry dependencies (git/path forks, step 0 of `build_scan_targets`'s ladder)
/// so a patched fork is never flagged for a registry version it does not contain.
///
/// One entry per *occurrence* of a name, not a single collapsed value: the
/// same dependency name can appear more than once in a manifest (the same
/// crate under `[dependencies]`/`[dev-dependencies]` or multiple
/// `[target.'cfg(...)'.dependencies]` blocks — #394). A HashMap keyed by
/// name alone would silently drop all but the last occurrence's in-use
/// version from the yanked probe below.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy,
/// };
/// use deps_core::test_util::stub_parse_result_with_dependencies;
/// use deps_core::{ConcreteVersion, EcosystemId, NormalizedName, PackageName};
/// use deps_engine::classify::resolved::collect_in_use_versions;
/// use std::collections::HashMap;
///
/// struct SimpleFormatter;
/// impl PackageNaming for SimpleFormatter {}
/// impl PackageRendering for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.as_str().to_string()
///     }
/// }
/// impl RequirementResolution for SimpleFormatter {}
/// impl DiagnosticMessages for SimpleFormatter {}
/// impl DiagnosticPolicy for SimpleFormatter {}
/// impl SourcePolicy for SimpleFormatter {}
/// impl OsvNaming for SimpleFormatter {}
///
/// // A single registry-sourced dependency ("dep-0"), with a lock-file-resolved version.
/// let parsed = stub_parse_result_with_dependencies(1);
/// let mut resolved_versions = HashMap::new();
/// resolved_versions.insert(NormalizedName::for_test("dep-0"), ConcreteVersion::from("1.0.0"));
///
/// let in_use = collect_in_use_versions(
///     parsed.as_ref(),
///     &resolved_versions,
///     &HashMap::new(),
///     &SimpleFormatter,
///     EcosystemId::Cargo,
/// );
/// assert_eq!(
///     in_use.get(&NormalizedName::for_test("dep-0")),
///     Some(&vec![ConcreteVersion::from("1.0.0")])
/// );
/// ```
pub fn collect_in_use_versions(
    parse_result: &dyn deps_core::ParseResult,
    resolved_versions: &ResolvedVersionsMap,
    resolved_version_candidates: &ResolvedCandidatesMap,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem: EcosystemId,
) -> HashMap<NormalizedName, Vec<ConcreteVersion>> {
    let mut map: HashMap<NormalizedName, Vec<ConcreteVersion>> = HashMap::new();
    for dep in parse_result
        .dependencies()
        .into_iter()
        .filter(|dep| formatter.source_is_public_registry_content(&dep.source()))
    {
        let key = PackageKey::new(dep.name(), formatter);
        if let Some(v) = resolve_in_use_version(
            dep,
            &key,
            resolved_versions,
            Some(resolved_version_candidates),
            formatter,
            ecosystem,
        ) {
            map.entry(key.normalized().clone()).or_default().push(v);
        }
    }
    map
}

/// Builds `normalized_name -> [version_requirement, ...]` for every dependency in `pr`, one
/// entry per occurrence across every spelling of the name — the shape `DependencyDiff::compute`
/// needs.
///
/// A single value per name would silently collapse a duplicate name to its last occurrence,
/// losing any edit made to an earlier one (#394). Keying by the normalized name makes a
/// pure spelling change (`Django` -> `django`) compare equal, and deleting one of two
/// spellings change the survivor's list.
///
/// Occurrence order is whatever `pr.dependencies()` returns, which for
/// `deps-cargo` is *not* document order for multiple `[target.*]` blocks
/// (see `DependencyDiff::compute`'s doc). A consequence worth knowing: if
/// an edit only renames a `[target.'cfg(...)'.dependencies]` expression
/// (no version change), that occurrence can sort into a different position
/// in the new `Vec` than the old one, so `old.get(name) != new.get(name)`
/// trips even though every individual version requirement is unchanged —
/// a spurious but harmless `version_changed` (one extra registry
/// refetch/OSV rescan for that name, never a missed or misattributed one).
///
/// # Examples
///
/// ```
/// use deps_core::NormalizedName;
/// use deps_core::test_util::{StubFormatter, stub_parse_result_with_dependencies};
/// use deps_engine::classify::resolved::dependency_version_map;
///
/// let parsed = stub_parse_result_with_dependencies(2);
/// let map = dependency_version_map(parsed.as_ref(), &StubFormatter::new());
///
/// assert_eq!(map.len(), 2);
/// assert_eq!(map.get(&NormalizedName::for_test("dep-0")), Some(&vec![None]));
/// ```
pub fn dependency_version_map(
    pr: &dyn deps_core::ParseResult,
    naming: &(impl PackageNaming + ?Sized),
) -> HashMap<NormalizedName, Vec<Option<VersionReq>>> {
    let mut map: HashMap<NormalizedName, Vec<Option<VersionReq>>> = HashMap::new();
    for d in pr.dependencies() {
        map.entry(PackageKey::new(d.name(), naming).normalized().clone())
            .or_default()
            .push(d.version_requirement().cloned());
    }
    map
}

/// Builds a `cached_versions` map from lock-file-resolved versions, ahead of any registry
/// fetch.
///
/// `available` is deliberately left empty (`PackageVersions::latest_without_list`, not a
/// plausible-looking one-element list) — this runs before any registry fetch, and
/// `requirement_is_unsatisfiable` treats an empty `available` as "still loading, skip"
/// (FR-004). Using `latest_only` here instead would populate a bogus single-entry list and
/// let the unsatisfiable-requirement check compute a false verdict on every document open,
/// before the fetch that's supposed to suppress it has a chance to run.
///
/// # Examples
///
/// ```
/// use deps_core::NormalizedName;
/// use deps_engine::classify::resolved::cached_versions_from_lockfile;
/// use std::collections::HashMap;
///
/// let mut resolved = HashMap::new();
/// resolved.insert(NormalizedName::for_test("serde"), "1.0.195".into());
///
/// let cached = cached_versions_from_lockfile(&resolved);
///
/// let serde = cached.get(&NormalizedName::for_test("serde")).unwrap();
/// assert_eq!(serde.latest, "1.0.195");
/// assert!(serde.available.is_empty());
/// ```
pub fn cached_versions_from_lockfile(resolved: &ResolvedVersionsMap) -> CachedVersionsMap {
    resolved
        .iter()
        .map(|(name, version)| {
            (
                name.clone(),
                PackageVersions::latest_without_list(version.clone()),
            )
        })
        .collect()
}

/// Splits a parsed [`deps_core::lockfile::ResolvedPackages`] into two maps keyed by the
/// ecosystem-normalized name.
///
/// The collapsed `normalized_name -> version` map (FR-005 fast path) and a sibling
/// `normalized_name -> [version, ...]` map (issue #649) holding every distinct retained
/// lock-file version for names with more than one — and deliberately omitting a name with a
/// single distinct version entirely (NFR-003: the common case never pays for a
/// candidates-map lookup). Lock-file spellings that normalize alike are unioned; see
/// [`deps_core::ResolvedPackages::split_normalized`] for the collision rule.
///
/// Shared by both [`LockfileLoad::Loaded`] constructors: [`parse_known_lockfile`] (and thus
/// [`load_resolved_versions`]) and `deps-lsp`'s watched-lock-file-change handler, which calls
/// [`parse_known_lockfile`] directly — both re-parse a lock file and need the identical
/// split.
///
/// # Examples
///
/// ```
/// use deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource};
/// use deps_core::test_util::StubFormatter;
/// use deps_engine::classify::resolved::split_resolved_packages;
///
/// let mut resolved = ResolvedPackages::new();
/// resolved.insert(ResolvedPackage::new(
///     "serde".into(),
///     "1.0.195".into(),
///     ResolvedSource::Registry {
///         url: "https://github.com/rust-lang/crates.io-index".into(),
///         checksum: "abc123".into(),
///     },
/// ));
///
/// let (versions, candidates) = split_resolved_packages(&resolved, &StubFormatter::new());
/// assert_eq!(versions.len(), 1);
/// assert!(
///     candidates.is_empty(),
///     "a single-occurrence name has no candidates entry"
/// );
/// ```
pub fn split_resolved_packages(
    resolved: &deps_core::lockfile::ResolvedPackages,
    naming: &(impl PackageNaming + ?Sized),
) -> (ResolvedVersionsMap, ResolvedCandidatesMap) {
    resolved.split_normalized(naming)
}

/// Outcome of loading (or reloading) a lock file's resolved-version data.
///
/// Replaces the earlier `(HashMap, HashMap, bool)` return shape (issue #1424): the trailing
/// `bool` distinguished "reload OK: parsed, or genuinely absent" from "parse failed, or
/// discovery panicked" only via a doc-comment convention, which two of three call sites
/// simply ignored. As a named, exhaustive enum, that distinction is now a first-class value
/// with its own documented [`Self::reload_ok`] method, not a bare `bool` a caller receives
/// with no attached meaning. [`Self::into_maps`] is a deliberate escape hatch for a caller
/// that only wants the maps: it collapses [`Self::Absent`]/[`Self::Failed`] alike, so
/// nothing stops a caller from reaching for it without ever consulting [`Self::reload_ok`]
/// first, exactly as a caller of the old tuple could ignore its `bool`. The improvement here
/// is discoverability — the distinction has a name and a doc comment sitting right next to
/// `into_maps` — not a compiler-enforced guarantee that every caller gets it right.
///
/// # Examples
///
/// ```
/// use deps_core::{ConcreteVersion, NormalizedName};
/// use deps_engine::classify::resolved::LockfileLoad;
/// use std::collections::HashMap;
///
/// let load = LockfileLoad::Loaded {
///     versions: HashMap::from([(NormalizedName::for_test("serde"), ConcreteVersion::from("1.0.210"))]),
///     candidates: HashMap::new(),
/// };
/// assert!(load.reload_ok());
/// let (versions, _candidates) = load.into_maps();
/// assert_eq!(versions.len(), 1);
///
/// assert!(!LockfileLoad::Failed.reload_ok());
/// assert!(LockfileLoad::Absent.reload_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockfileLoad {
    /// No `LockFileProvider` for this ecosystem, or no lock file found on disk — a genuine,
    /// non-error absence.
    Absent,
    /// A lock file was found and parsed successfully, possibly to zero packages.
    Loaded {
        /// `normalized_name -> version`, one entry per name (see [`split_resolved_packages`]).
        versions: ResolvedVersionsMap,
        /// `normalized_name -> [version, ...]`, only for names with more than one distinct
        /// retained version.
        candidates: ResolvedCandidatesMap,
    },
    /// A lock file was found but failed to parse (e.g. caught mid-rewrite by the package
    /// manager), or its discovery task panicked. Conservative: a panic is not a definitive
    /// "no lock file" answer the way a located-but-absent path is, so it is classified the
    /// same as a parse failure rather than as [`Self::Absent`].
    Failed,
}

impl LockfileLoad {
    /// Whether an empty-vs-non-empty transition read from this outcome is trustworthy: a
    /// genuine absence ([`Self::Absent`]) or a successful parse ([`Self::Loaded`]) — never a
    /// transient [`Self::Failed`].
    ///
    /// Callers that treat such a transition as a real signal (a resolved-version move worth
    /// re-scanning/diffing against) must gate on this — otherwise a transient parse failure
    /// looks identical to every dependency genuinely losing its resolution, silently
    /// discarding known-good data and replacing correct OSV/license results with
    /// `Skipped`/stale ones (the #1395 M1 class this mirrors).
    #[must_use]
    pub fn reload_ok(&self) -> bool {
        !matches!(self, Self::Failed)
    }

    /// Extracts the resolved-version maps, falling back to a pair of empty maps for
    /// [`Self::Absent`]/[`Self::Failed`].
    #[must_use]
    pub fn into_maps(self) -> (ResolvedVersionsMap, ResolvedCandidatesMap) {
        match self {
            Self::Loaded {
                versions,
                candidates,
            } => (versions, candidates),
            Self::Absent | Self::Failed => (HashMap::new(), HashMap::new()),
        }
    }
}

/// Parses the lock file at `lockfile_path` through `lockfile_cache`, converting the result
/// into a [`LockfileLoad::Loaded`] or [`LockfileLoad::Failed`] outcome.
///
/// `lockfile_path` is a path already known to exist — resolved by
/// [`load_resolved_versions`]'s own discovery step, or by a caller reacting to a
/// file-watcher event for a path it already knows. Never returns [`LockfileLoad::Absent`] —
/// only [`load_resolved_versions`]'s discovery step (no lock file located at all) can
/// conclude that; a known path means discovery already succeeded.
///
/// `naming` is the document's formatter: the maps are keyed by the names it normalizes the
/// lock file's spellings to.
///
/// Shared by [`load_resolved_versions`] and `deps-lsp`'s watched-lock-file-change handler
/// (issue #1424) — both need the identical get-or-parse-then-split sequence, previously
/// duplicated between them.
///
/// # Examples
///
/// ```
/// use deps_core::{Ecosystem, HttpCache};
/// use deps_core::lockfile::LockFileCache;
/// use deps_engine::classify::resolved::{LockfileLoad, parse_known_lockfile};
/// use deps_engine::setup::CargoEcosystem;
/// use std::path::Path;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() {
///     let ecosystem = CargoEcosystem::new(Arc::new(HttpCache::new()));
///     let lockfile_cache = LockFileCache::new();
///     let lock_provider = ecosystem.lockfile_provider().unwrap();
///
///     // The path itself doesn't exist, so parsing fails.
///     let load = parse_known_lockfile(
///         &lockfile_cache,
///         lock_provider.as_ref(),
///         ecosystem.formatter(),
///         Path::new("/nonexistent-for-doctest/Cargo.lock"),
///     )
///     .await;
///     assert_eq!(load, LockfileLoad::Failed);
/// }
/// ```
pub async fn parse_known_lockfile(
    lockfile_cache: &LockFileCache,
    lock_provider: &dyn LockFileProvider,
    naming: &(impl PackageNaming + ?Sized),
    lockfile_path: &Path,
) -> LockfileLoad {
    match lockfile_cache
        .get_or_parse(lock_provider, lockfile_path)
        .await
    {
        Ok(resolved) => {
            tracing::info!(
                "Loaded {} resolved versions from {}",
                resolved.len(),
                lockfile_path.display()
            );
            let derived = lock_provider.derived_packages(&resolved);
            let (versions, candidates) = if derived.is_empty() {
                split_resolved_packages(&resolved, naming)
            } else {
                let mut merged = resolved;
                for package in derived {
                    merged.insert(package);
                }
                split_resolved_packages(&merged, naming)
            };
            LockfileLoad::Loaded {
                versions,
                candidates,
            }
        }
        Err(e) => {
            tracing::warn!(
                "Failed to parse lock file {}: {}",
                lockfile_path.display(),
                e
            );
            LockfileLoad::Failed
        }
    }
}

/// Loads resolved versions from lock file for a given manifest URI.
///
/// Uses the ecosystem's lockfile provider to locate the lock file, then
/// [`parse_known_lockfile`] to parse it. See [`LockfileLoad`] for what each outcome means.
///
/// # Examples
///
/// ```
/// use deps_core::HttpCache;
/// use deps_core::lockfile::LockFileCache;
/// use deps_core::test_util::test_uri;
/// use deps_engine::classify::resolved::{LockfileLoad, load_resolved_versions};
/// use deps_engine::setup::CargoEcosystem;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() {
///     let ecosystem = CargoEcosystem::new(Arc::new(HttpCache::new()));
///     let lockfile_cache = Arc::new(LockFileCache::new());
///     // No `Cargo.lock` exists at this synthetic path, so this is a genuine absence — the
///     // same fast path a manifest with no lock file takes in production.
///     let uri = test_uri("/nonexistent-for-doctest/Cargo.toml");
///
///     let load = load_resolved_versions(&uri, &lockfile_cache, &ecosystem).await;
///     assert_eq!(load, LockfileLoad::Absent);
/// }
/// ```
pub async fn load_resolved_versions(
    uri: &url::Url,
    lockfile_cache: &Arc<LockFileCache>,
    ecosystem: &dyn Ecosystem,
) -> LockfileLoad {
    let lock_provider = match ecosystem.lockfile_provider() {
        Some(p) => p,
        None => {
            tracing::debug!("No lock file provider for ecosystem {}", ecosystem.id());
            return LockfileLoad::Absent;
        }
    };

    // `locate_lockfile` does a synchronous ancestor-directory stat walk; run in
    // `spawn_blocking` rather than inline on the tokio worker (#963).
    let lock_provider_for_locate = Arc::clone(&lock_provider);
    let uri_for_locate = uri.clone();
    let located = tokio::task::spawn_blocking(move || {
        lock_provider_for_locate.locate_lockfile(&uri_for_locate)
    })
    .await;

    let lockfile_path = match located {
        Ok(Some(path)) => path,
        Ok(None) => {
            tracing::debug!("No lock file found for {:?}", uri);
            return LockfileLoad::Absent;
        }
        Err(e) => {
            tracing::warn!("Lock file discovery task panicked for {:?}: {}", uri, e);
            return LockfileLoad::Failed;
        }
    };

    parse_known_lockfile(
        lockfile_cache,
        lock_provider.as_ref(),
        ecosystem.formatter(),
        &lockfile_path,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N5 regression guard: the lock-file-population path must build every
    /// `PackageVersions` with an **empty** `available` list, never a populated one — an
    /// empty `available` is what makes `requirement_is_unsatisfiable`'s FR-004 guard
    /// suppress the check before any registry fetch has run. This is the exact function
    /// `handle_document_open`'s background task calls, so a regression here (e.g.
    /// swapping `latest_without_list` for `latest_only`) is caught directly, without
    /// racing the background task.
    #[test]
    fn test_cached_versions_from_lockfile_has_empty_available() {
        let mut resolved = HashMap::new();
        resolved.insert(NormalizedName::for_test("serde"), "1.0.195".into());
        resolved.insert(NormalizedName::for_test("tokio"), "1.35.0".into());

        let cached = cached_versions_from_lockfile(&resolved);

        assert_eq!(cached.len(), 2);
        let serde = cached.get(&NormalizedName::for_test("serde")).unwrap();
        assert_eq!(serde.latest, "1.0.195");
        assert!(
            serde.available.is_empty(),
            "lock-file-populated entries must have an empty available list, got: {:?}",
            serde.available
        );
        // #227 C3: a pinned version's age isn't actionable — never attach `published_at` here.
        assert_eq!(serde.published_at, None);
        let tokio = cached.get(&NormalizedName::for_test("tokio")).unwrap();
        assert_eq!(tokio.latest, "1.35.0");
        assert!(tokio.available.is_empty());
        assert_eq!(tokio.published_at, None);
    }

    #[test]
    fn test_cached_versions_from_lockfile_empty_input_is_empty_output() {
        let resolved = HashMap::new();
        assert!(cached_versions_from_lockfile(&resolved).is_empty());
    }

    /// Issue #1424: `Absent` and `Failed` both collapse to a pair of empty maps via
    /// `into_maps`, but are not the same outcome — `reload_ok` (what a caller gates a
    /// resolved-version-move rescan signal on) must still tell them apart, as a compiler-
    /// checked `match` rather than the prior doc-comment-only convention on the old
    /// `(HashMap, HashMap, bool)` return shape.
    #[test]
    fn test_lockfile_load_distinguishes_absent_from_failed() {
        assert!(LockfileLoad::Absent.reload_ok());
        assert!(!LockfileLoad::Failed.reload_ok());
        assert!(
            LockfileLoad::Loaded {
                versions: HashMap::new(),
                candidates: HashMap::new(),
            }
            .reload_ok()
        );

        assert_eq!(
            LockfileLoad::Absent.into_maps(),
            (HashMap::new(), HashMap::new())
        );
        assert_eq!(
            LockfileLoad::Failed.into_maps(),
            (HashMap::new(), HashMap::new())
        );
        assert_ne!(LockfileLoad::Absent, LockfileLoad::Failed);
    }

    mod spelling_tests {
        use super::*;
        use deps_core::position::{Position, Range};
        use deps_core::test_util::StubFormatter;
        use deps_core::{Dependency, PackageName};
        use std::any::Any;

        const LOWERCASE: StubFormatter = StubFormatter::new().with_lowercase_names();

        struct MockDep {
            name: PackageName,
            version_req: VersionReq,
            addr_tag: u32,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::new(
                    Position::new(0, self.addr_tag),
                    Position::new(0, self.addr_tag + 1),
                )
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                None
            }
            fn source(&self) -> deps_core::parser::DependencySource {
                deps_core::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult(Vec<MockDep>);

        impl deps_core::ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.0.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                static URI: std::sync::OnceLock<url::Url> = std::sync::OnceLock::new();
                URI.get_or_init(|| deps_core::test_util::test_uri("/test/requirements.txt"))
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        fn parse_result(deps: &[(&str, &str)]) -> MockParseResult {
            MockParseResult(
                deps.iter()
                    .zip(0u32..)
                    .map(|((name, req), addr_tag)| MockDep {
                        name: PackageName::new(*name),
                        version_req: VersionReq::new(*req),
                        addr_tag,
                    })
                    .collect(),
            )
        }

        #[test]
        fn dependency_version_map_treats_a_pure_rename_as_equal() {
            let before = dependency_version_map(&parse_result(&[("Django", "==4.0")]), &LOWERCASE);
            let after = dependency_version_map(&parse_result(&[("django", "==4.0")]), &LOWERCASE);

            assert_eq!(before, after);
        }

        #[test]
        fn dependency_version_map_changes_the_survivor_when_one_spelling_is_deleted() {
            let both = dependency_version_map(
                &parse_result(&[("Django", "==4.0"), ("django", "==4.1")]),
                &LOWERCASE,
            );
            let survivor =
                dependency_version_map(&parse_result(&[("django", "==4.1")]), &LOWERCASE);

            let key = NormalizedName::for_test("django");
            assert_eq!(both[&key].len(), 2);
            assert_ne!(both[&key], survivor[&key]);
        }

        #[test]
        fn collect_in_use_versions_is_keyed_by_the_normalized_name() {
            let resolved = ResolvedVersionsMap::from([(
                NormalizedName::for_test("django"),
                ConcreteVersion::from("4.1.0"),
            )]);

            let in_use = collect_in_use_versions(
                &parse_result(&[("Django", "==4.0")]),
                &resolved,
                &ResolvedCandidatesMap::new(),
                &LOWERCASE,
                EcosystemId::Pypi,
            );

            assert_eq!(
                in_use.get(&NormalizedName::for_test("django")),
                Some(&vec![ConcreteVersion::from("4.1.0")])
            );
        }

        #[test]
        fn split_resolved_packages_unions_lock_file_spellings() {
            use deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource};

            let mut packages = ResolvedPackages::new();
            for (name, version) in [("Newtonsoft.Json", "1.9.0"), ("newtonsoft.json", "1.10.0")] {
                packages.insert(ResolvedPackage::new(
                    name.into(),
                    version.into(),
                    ResolvedSource::Registry {
                        url: String::new(),
                        checksum: String::new(),
                    },
                ));
            }

            let (versions, candidates) = split_resolved_packages(&packages, &LOWERCASE);

            let key = NormalizedName::for_test("newtonsoft.json");
            assert_eq!(versions.len(), 1);
            assert_eq!(candidates[&key].len(), 2);
            assert!(versions.contains_key(&key));
        }
    }

    /// `parse_known_lockfile` end to end against a real `Cargo.lock`, not just the
    /// nonexistent-path `Failed` case its own doctest covers.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_parse_known_lockfile_loads_real_lockfile() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let lockfile_path = dir.path().join("Cargo.lock");
        std::fs::write(
            &lockfile_path,
            r#"# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "serde"
version = "1.0.195"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("write Cargo.lock");

        let provider = deps_cargo::lockfile::CargoLockParser;
        let cache = LockFileCache::new();

        match parse_known_lockfile(
            &cache,
            &provider,
            &deps_core::test_util::StubFormatter::new(),
            &lockfile_path,
        )
        .await
        {
            LockfileLoad::Loaded { versions, .. } => {
                assert_eq!(
                    versions.get(&NormalizedName::for_test("serde")),
                    Some(&ConcreteVersion::from("1.0.195"))
                );
            }
            other => panic!("expected Loaded, got {other:?}"),
        }
    }
}
