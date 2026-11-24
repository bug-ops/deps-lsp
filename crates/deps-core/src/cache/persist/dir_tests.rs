//! Acceptance tests for spec 051 T005 (`persist::dir`): cache directory resolution,
//! Unix ownership rules and pruning.
//!
//! Limits are restated as literals so the tests also pin the constants: 64 MiB, 2048 files,
//! scan cap 16384 entries, stale `*.tmp` after 1 hour, entries expire at 7 days.

use super::dir::{CacheDir, CachePlatform, NoCacheDir, PruneLimits, prune_dir};
use crate::net_policy::MapEnv;
use std::assert_matches;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

fn abs(name: &str) -> PathBuf {
    std::env::temp_dir().join("deps-lsp-dir-tests").join(name)
}

fn env_var(env: MapEnv, name: &str, path: &Path) -> MapEnv {
    env.with_var(name, path.to_str().expect("utf-8 path"))
}

fn resolve(env: &MapEnv, platform: CachePlatform) -> Result<PathBuf, NoCacheDir> {
    CacheDir::resolve(env, platform).map(|dir| dir.as_path().to_path_buf())
}

mod user_default_table {
    use super::*;

    #[test]
    fn resolve_unix_absolute_xdg_wins_over_home() {
        let env = env_var(
            env_var(MapEnv::new(), "XDG_CACHE_HOME", &abs("xdg")),
            "HOME",
            &abs("home"),
        );
        assert_eq!(resolve(&env, CachePlatform::Unix).unwrap(), abs("xdg"));
    }

    #[test]
    fn resolve_unix_xdg_unset_uses_home_dot_cache() {
        let env = env_var(MapEnv::new(), "HOME", &abs("home"));
        assert_eq!(
            resolve(&env, CachePlatform::Unix).unwrap(),
            abs("home").join(".cache")
        );
    }

    #[test]
    fn resolve_unix_empty_xdg_is_treated_as_unset() {
        let env = env_var(MapEnv::new(), "HOME", &abs("home")).with_var("XDG_CACHE_HOME", "");
        assert_eq!(
            resolve(&env, CachePlatform::Unix).unwrap(),
            abs("home").join(".cache")
        );
    }

    #[test]
    fn resolve_unix_absolute_xdg_without_home_is_ok() {
        let env = env_var(MapEnv::new(), "XDG_CACHE_HOME", &abs("xdg"));
        assert_eq!(resolve(&env, CachePlatform::Unix).unwrap(), abs("xdg"));
    }

    #[test]
    fn resolve_unix_relative_xdg_is_no_cache_dir_even_with_home() {
        let env =
            env_var(MapEnv::new(), "HOME", &abs("home")).with_var("XDG_CACHE_HOME", "rel/cache");
        assert_matches!(
            CacheDir::resolve(&env, CachePlatform::Unix),
            Err(NoCacheDir)
        );
    }

    #[test]
    fn resolve_unix_no_home_no_xdg_is_no_cache_dir() {
        assert_matches!(
            CacheDir::resolve(&MapEnv::new(), CachePlatform::Unix),
            Err(NoCacheDir)
        );
    }

    #[test]
    fn resolve_unix_relative_home_is_no_cache_dir() {
        let env = MapEnv::new().with_var("HOME", "rel/home");
        assert_matches!(
            CacheDir::resolve(&env, CachePlatform::Unix),
            Err(NoCacheDir)
        );
    }

    #[test]
    fn resolve_macos_uses_library_caches_and_ignores_xdg() {
        let env = env_var(
            env_var(MapEnv::new(), "XDG_CACHE_HOME", &abs("xdg")),
            "HOME",
            &abs("home"),
        );
        assert_eq!(
            resolve(&env, CachePlatform::MacOs).unwrap(),
            abs("home").join("Library").join("Caches")
        );
    }

    #[test]
    fn resolve_macos_without_home_is_no_cache_dir() {
        let env = env_var(MapEnv::new(), "XDG_CACHE_HOME", &abs("xdg"));
        assert_matches!(
            CacheDir::resolve(&env, CachePlatform::MacOs),
            Err(NoCacheDir)
        );
    }

    #[test]
    fn resolve_windows_uses_local_app_data_and_ignores_home_and_xdg() {
        let env = env_var(
            env_var(
                env_var(MapEnv::new(), "LOCALAPPDATA", &abs("local")),
                "HOME",
                &abs("home"),
            ),
            "XDG_CACHE_HOME",
            &abs("xdg"),
        );
        assert_eq!(resolve(&env, CachePlatform::Windows).unwrap(), abs("local"));
    }

    #[test]
    fn resolve_windows_missing_or_relative_local_app_data_is_no_cache_dir() {
        let only_home = env_var(MapEnv::new(), "HOME", &abs("home"));
        let relative = MapEnv::new().with_var("LOCALAPPDATA", "rel/local");
        for env in [only_home, relative] {
            assert_matches!(
                CacheDir::resolve(&env, CachePlatform::Windows),
                Err(NoCacheDir)
            );
        }
    }

    #[test]
    fn user_default_matches_resolve_for_current_platform() {
        let env = env_var(
            env_var(
                env_var(MapEnv::new(), "XDG_CACHE_HOME", &abs("xdg")),
                "HOME",
                &abs("home"),
            ),
            "LOCALAPPDATA",
            &abs("local"),
        );
        assert_eq!(
            CacheDir::user_default(&env).unwrap(),
            CacheDir::resolve(&env, CachePlatform::CURRENT).unwrap()
        );
    }

    #[test]
    fn user_default_touches_no_filesystem() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let env = env_var(MapEnv::new(), "HOME", tmp.path());
        let _ = CacheDir::user_default(&env);
        assert_eq!(fs::read_dir(tmp.path()).expect("read_dir").count(), 0);
    }
}

#[cfg(unix)]
mod unix_open {
    use super::super::dir::{DiskTierError, ProbeUid, entry_file_trusted};
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    const COMPONENTS: [&str; 3] = ["deps-lsp", "http", "v1"];

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn own_uid(path: &Path) -> ProbeUid {
        ProbeUid::new(fs::metadata(path).expect("metadata").uid())
    }

    fn foreign_uid(path: &Path) -> ProbeUid {
        ProbeUid::new(fs::metadata(path).expect("metadata").uid().wrapping_add(1))
    }

    fn is_root(uid: ProbeUid) -> bool {
        uid.as_raw() == 0
    }

    /// Home in a fresh tempdir plus an env whose `HOME` points at it and whose cache root is
    /// `$HOME/.cache`.
    struct Fixture {
        _tmp: tempfile::TempDir,
        home: PathBuf,
        env: MapEnv,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().expect("tempdir");
            let home = tmp.path().join("home");
            fs::create_dir(&home).expect("home");
            let env = env_var(MapEnv::new(), "HOME", &home);
            Self {
                _tmp: tmp,
                home,
                env,
            }
        }

        fn root(&self) -> PathBuf {
            self.home.join(".cache")
        }

        fn uid(&self) -> ProbeUid {
            own_uid(&self.home)
        }

        fn cache_dir(&self) -> CacheDir {
            CacheDir::resolve(&self.env, CachePlatform::Unix).expect("resolvable")
        }

        fn with_root(&self, root: &Path) -> (CacheDir, MapEnv) {
            let env = env_var(self.env.clone(), "XDG_CACHE_HOME", root);
            (
                CacheDir::resolve(&env, CachePlatform::Unix).expect("resolvable"),
                env,
            )
        }
    }

    #[test]
    fn open_missing_root_with_owned_home_creates_0700_chain() {
        let fx = Fixture::new();
        let store = fx.cache_dir().open_with(&fx.env, fx.uid()).expect("open");

        let root = fx.root();
        assert_eq!(store.path(), root.join("deps-lsp/http/v1"));
        assert_eq!(mode_of(&root), 0o700);
        let mut dir = root;
        for component in COMPONENTS {
            dir.push(component);
            assert!(fs::symlink_metadata(&dir).expect("metadata").is_dir());
            assert_eq!(mode_of(&dir), 0o700, "{}", dir.display());
        }
    }

    #[test]
    fn open_twice_ignores_already_exists() {
        let fx = Fixture::new();
        fx.cache_dir().open_with(&fx.env, fx.uid()).expect("first");
        let store = fx.cache_dir().open_with(&fx.env, fx.uid()).expect("second");
        assert_eq!(store.path(), fx.root().join("deps-lsp/http/v1"));
    }

    #[test]
    fn open_existing_root_is_not_mode_checked_or_changed() {
        let fx = Fixture::new();
        fs::create_dir(fx.root()).expect("root");
        set_mode(&fx.root(), 0o775);
        fx.cache_dir().open_with(&fx.env, fx.uid()).expect("open");
        assert_eq!(mode_of(&fx.root()), 0o775);
        assert_eq!(mode_of(&fx.root().join("deps-lsp")), 0o700);
    }

    #[test]
    fn open_root_symlink_to_owned_directory_is_followed() {
        let fx = Fixture::new();
        let target = fx.home.join("real-cache");
        fs::create_dir(&target).expect("target");
        symlink(&target, fx.root()).expect("symlink");
        fx.cache_dir().open_with(&fx.env, fx.uid()).expect("open");
        assert!(target.join("deps-lsp/http/v1").is_dir());
    }

    #[test]
    fn open_root_that_is_a_file_is_insecure() {
        let fx = Fixture::new();
        fs::write(fx.root(), b"x").expect("file");
        assert_matches!(
            fx.cache_dir().open_with(&fx.env, fx.uid()),
            Err(DiskTierError::InsecureDirectory)
        );
    }

    #[test]
    fn open_missing_root_whose_parent_is_not_home_creates_nothing() {
        let fx = Fixture::new();
        let other = fx.home.join("other");
        fs::create_dir(&other).expect("other");
        let sibling_root = other.join("cache");
        let nested_root = fx.home.join("a").join("b");

        for root in [&sibling_root, &nested_root] {
            let (dir, env) = fx.with_root(root);
            assert_matches!(
                dir.open_with(&env, fx.uid()),
                Err(DiskTierError::CreateFailed(_))
            );
            assert!(!root.exists(), "{}", root.display());
        }
        assert!(!fx.home.join("a").exists());
        assert_eq!(fs::read_dir(&other).expect("read_dir").count(), 0);
    }

    #[test]
    fn open_missing_root_without_home_creates_nothing() {
        let fx = Fixture::new();
        let root = fx.home.join("xdg-cache");
        let env = env_var(MapEnv::new(), "XDG_CACHE_HOME", &root);
        let dir = CacheDir::resolve(&env, CachePlatform::Unix).expect("resolvable");
        assert_matches!(
            dir.open_with(&env, fx.uid()),
            Err(DiskTierError::CreateFailed(_))
        );
        assert!(!root.exists());
    }

    #[test]
    fn open_missing_root_with_foreign_owned_home_creates_nothing() {
        let fx = Fixture::new();
        assert_matches!(
            fx.cache_dir().open_with(&fx.env, foreign_uid(&fx.home)),
            Err(DiskTierError::InsecureDirectory)
        );
        assert!(!fx.root().exists());
    }

    #[test]
    fn open_foreign_owned_root_creates_nothing_inside() {
        let fx = Fixture::new();
        fs::create_dir(fx.root()).expect("root");
        assert_matches!(
            fx.cache_dir().open_with(&fx.env, foreign_uid(&fx.home)),
            Err(DiskTierError::InsecureDirectory)
        );
        assert_eq!(fs::read_dir(fx.root()).expect("read_dir").count(), 0);
    }

    #[test]
    fn open_read_only_root_degrades_without_creating() {
        let fx = Fixture::new();
        if is_root(fx.uid()) {
            eprintln!("SKIPPED: root ignores directory permission bits, the test is vacuous");
            return;
        }
        fs::create_dir(fx.root()).expect("root");
        set_mode(&fx.root(), 0o500);
        let result = fx.cache_dir().open_with(&fx.env, fx.uid());
        let created = fs::read_dir(fx.root()).expect("read_dir").count();
        set_mode(&fx.root(), 0o700);
        assert_matches!(result, Err(DiskTierError::CreateFailed(_)));
        assert_eq!(created, 0);
    }

    #[test]
    fn open_preexisting_component_with_group_or_other_bits_is_insecure() {
        for depth in 0..COMPONENTS.len() {
            for mode in [0o750, 0o770, 0o701, 0o755] {
                let fx = Fixture::new();
                let mut dir = fx.root();
                fs::create_dir(&dir).expect("root");
                for component in &COMPONENTS[..=depth] {
                    dir.push(component);
                    fs::create_dir(&dir).expect("component");
                    set_mode(&dir, 0o700);
                }
                set_mode(&dir, mode);
                assert_matches!(
                    fx.cache_dir().open_with(&fx.env, fx.uid()),
                    Err(DiskTierError::InsecureDirectory),
                    "component {depth} mode {mode:o}"
                );
            }
        }
    }

    #[test]
    fn open_preexisting_component_symlink_is_insecure() {
        for depth in 0..COMPONENTS.len() {
            let fx = Fixture::new();
            let real = fx.home.join("real");
            fs::create_dir(&real).expect("real");
            set_mode(&real, 0o700);
            let mut dir = fx.root();
            fs::create_dir(&dir).expect("root");
            for component in &COMPONENTS[..depth] {
                dir.push(component);
                fs::create_dir(&dir).expect("component");
                set_mode(&dir, 0o700);
            }
            symlink(&real, dir.join(COMPONENTS[depth])).expect("symlink");
            assert_matches!(
                fx.cache_dir().open_with(&fx.env, fx.uid()),
                Err(DiskTierError::InsecureDirectory),
                "component {depth}"
            );
            assert_eq!(fs::read_dir(&real).expect("read_dir").count(), 0);
        }
    }

    #[test]
    fn probe_in_reports_owner_and_leaves_no_file_behind() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let uid = ProbeUid::probe_in(tmp.path()).expect("probe");
        assert_eq!(uid, own_uid(tmp.path()));
        assert_eq!(fs::read_dir(tmp.path()).expect("read_dir").count(), 0);
    }

    #[test]
    fn probe_in_missing_directory_is_probe_failed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_matches!(
            ProbeUid::probe_in(&tmp.path().join("missing")),
            Err(DiskTierError::ProbeFailed(_))
        );
    }

    #[test]
    fn probe_uses_temp_dir_and_matches_owned_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(ProbeUid::probe().expect("probe"), own_uid(tmp.path()));
    }

    #[test]
    fn open_resolves_probe_itself() {
        let fx = Fixture::new();
        let store = fx.cache_dir().open(&fx.env).expect("open");
        assert!(store.path().is_dir());
    }

    #[test]
    fn entry_file_trusted_table() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let uid = own_uid(tmp.path());
        let trusted = |mode: u32, probe: ProbeUid| {
            let path = tmp.path().join(format!("f-{mode:o}"));
            fs::write(&path, b"x").expect("file");
            set_mode(&path, mode);
            entry_file_trusted(&fs::symlink_metadata(&path).expect("metadata"), probe)
        };

        assert!(trusted(0o600, uid));
        assert!(trusted(0o644, uid), "read bits are not a defect");
        assert!(!trusted(0o620, uid), "group write");
        assert!(!trusted(0o602, uid), "other write");
        assert!(!trusted(0o660, uid));
        assert!(!trusted(0o600, foreign_uid(tmp.path())), "foreign owner");
    }

    #[test]
    fn entry_file_trusted_rejects_directory_and_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let uid = own_uid(tmp.path());
        let file = tmp.path().join("real");
        fs::write(&file, b"x").expect("file");
        set_mode(&file, 0o600);
        let link = tmp.path().join("link");
        symlink(&file, &link).expect("symlink");

        let dir_meta = fs::symlink_metadata(tmp.path()).expect("metadata");
        let link_meta = fs::symlink_metadata(&link).expect("metadata");
        assert!(!entry_file_trusted(&dir_meta, uid));
        assert!(!entry_file_trusted(&link_meta, uid));
    }
}

#[cfg(windows)]
mod windows_open {
    use super::super::dir::{DiskTierError, entry_file_trusted};
    use super::*;
    use std::os::windows::fs::symlink_dir;

    const COMPONENTS: [&str; 3] = ["deps-lsp", "http", "v1"];
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

    fn cache_dir(env: &MapEnv) -> CacheDir {
        CacheDir::resolve(env, CachePlatform::Windows).expect("resolvable")
    }

    fn env_for(root: &Path) -> MapEnv {
        env_var(MapEnv::new(), "LOCALAPPDATA", root)
    }

    #[test]
    fn open_missing_root_is_create_failed_and_creates_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("missing");
        let env = env_for(&root);
        assert_matches!(
            cache_dir(&env).open(&env),
            Err(DiskTierError::CreateFailed(_))
        );
        assert!(!root.exists());
    }

    #[test]
    fn open_existing_root_creates_plain_component_chain_and_is_idempotent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let env = env_for(tmp.path());
        let store = cache_dir(&env).open(&env).expect("open");
        let expected = COMPONENTS
            .iter()
            .fold(tmp.path().to_path_buf(), |dir, c| dir.join(c));
        assert_eq!(store.path(), expected);
        let mut dir = tmp.path().to_path_buf();
        for component in COMPONENTS {
            dir.push(component);
            let meta = fs::symlink_metadata(&dir).expect("metadata");
            assert!(meta.file_type().is_dir() && !meta.file_type().is_symlink());
        }
        assert!(cache_dir(&env).open(&env).is_ok());
    }

    #[test]
    fn open_root_that_is_a_file_is_insecure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("file");
        fs::write(&root, b"x").expect("file");
        let env = env_for(&root);
        assert_matches!(
            cache_dir(&env).open(&env),
            Err(DiskTierError::InsecureDirectory)
        );
    }

    #[test]
    fn open_component_that_is_a_file_is_insecure() {
        for depth in 0..COMPONENTS.len() {
            let tmp = tempfile::tempdir().expect("tempdir");
            let mut dir = tmp.path().to_path_buf();
            for component in &COMPONENTS[..depth] {
                dir.push(component);
                fs::create_dir(&dir).expect("component");
            }
            fs::write(dir.join(COMPONENTS[depth]), b"x").expect("file");
            let env = env_for(tmp.path());
            assert_matches!(
                cache_dir(&env).open(&env),
                Err(DiskTierError::InsecureDirectory),
                "component {depth}"
            );
        }
    }

    /// Covers the `is_dir()` refusal of name-surrogate reparse points only; std cannot create a
    /// junction or a non-surrogate reparse directory, so the `0x400` attribute branch is untested.
    #[test]
    fn open_component_directory_symlink_is_insecure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real");
        fs::create_dir(&real).expect("real");
        let root = tmp.path().join("root");
        fs::create_dir(&root).expect("root");
        match symlink_dir(&real, root.join(COMPONENTS[0])) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD) =>
            {
                eprintln!("SKIPPED: symlink creation needs a privilege, the test is vacuous");
                return;
            }
            Err(e) => panic!("symlink_dir: {e}"),
        }
        let env = env_for(&root);
        assert_matches!(
            cache_dir(&env).open(&env),
            Err(DiskTierError::InsecureDirectory)
        );
        assert_eq!(fs::read_dir(&real).expect("read_dir").count(), 0);
    }

    #[test]
    fn entry_file_trusted_accepts_regular_file_and_rejects_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = tmp.path().join("f");
        fs::write(&file, b"x").expect("file");
        assert!(entry_file_trusted(&fs::metadata(&file).expect("metadata")));
        assert!(!entry_file_trusted(
            &fs::metadata(tmp.path()).expect("metadata")
        ));
    }
}

mod prune {
    use super::*;

    const NOW_SKEW: Duration = Duration::from_hours(1);

    struct Store {
        tmp: tempfile::TempDir,
        now: SystemTime,
    }

    impl Store {
        fn new() -> Self {
            Self {
                tmp: tempfile::tempdir().expect("tempdir"),
                now: SystemTime::now(),
            }
        }

        fn put(&self, name: &str, len: usize, age: Duration) {
            let path = self.tmp.path().join(name);
            fs::write(&path, vec![b'x'; len]).expect("write");
            let stamp = self.now.checked_sub(age).expect("representable");
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open")
                .set_modified(stamp)
                .expect("set_modified");
        }

        fn put_at(&self, name: &str, len: usize, stamp: SystemTime) {
            let path = self.tmp.path().join(name);
            fs::write(&path, vec![b'x'; len]).expect("write");
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open")
                .set_modified(stamp)
                .expect("set_modified");
        }

        fn exists(&self, name: &str) -> bool {
            self.tmp.path().join(name).exists()
        }

        fn file_count(&self) -> usize {
            fs::read_dir(self.tmp.path()).expect("read_dir").count()
        }

        fn prune(&self, limits: PruneLimits) -> super::super::dir::PruneReport {
            prune_dir(self.tmp.path(), self.now, limits).expect("prune")
        }
    }

    fn roomy() -> PruneLimits {
        PruneLimits {
            max_bytes: u64::MAX,
            max_files: usize::MAX,
            max_scan: usize::MAX,
        }
    }

    #[test]
    fn prune_limits_default_pins_spec_constants() {
        assert_eq!(PruneLimits::DEFAULT.max_bytes, 64 * 1024 * 1024);
        assert_eq!(PruneLimits::DEFAULT.max_files, 2048);
        assert_eq!(PruneLimits::DEFAULT.max_scan, 16384);
    }

    #[test]
    fn prune_dir_removes_tmp_older_than_one_hour_only() {
        let s = Store::new();
        s.put("old.tmp", 1, NOW_SKEW + Duration::from_mins(1));
        s.put("fresh.tmp", 1, Duration::from_mins(10));
        s.put("a.entry", 1, Duration::from_mins(1));
        s.prune(roomy());
        assert!(!s.exists("old.tmp"));
        assert!(s.exists("fresh.tmp"));
        assert!(s.exists("a.entry"));
    }

    #[test]
    fn prune_dir_removes_expired_entries_under_the_caps() {
        let s = Store::new();
        s.put("expired.entry", 1, Duration::from_hours(24 * 8));
        s.put("stale.entry", 1, Duration::from_hours(24 * 6));
        s.put("fresh.entry", 1, Duration::from_mins(1));
        s.prune(roomy());
        assert!(!s.exists("expired.entry"));
        assert!(s.exists("stale.entry"));
        assert!(s.exists("fresh.entry"));
    }

    #[test]
    fn prune_dir_enforces_file_cap_least_recently_validated_first() {
        let s = Store::new();
        for (n, age) in [1, 2, 3, 4].into_iter().enumerate() {
            s.put(&format!("{n}.entry"), 1, Duration::from_mins(age));
        }
        let limits = PruneLimits {
            max_files: 2,
            ..roomy()
        };
        s.prune(limits);
        assert!(s.exists("0.entry") && s.exists("1.entry"));
        assert!(!s.exists("2.entry") && !s.exists("3.entry"));
    }

    #[test]
    fn prune_dir_enforces_byte_cap_removing_only_as_many_as_needed() {
        let s = Store::new();
        s.put("newest.entry", 10, Duration::from_mins(1));
        s.put("middle.entry", 10, Duration::from_mins(2));
        s.put("oldest.entry", 10, Duration::from_mins(3));
        let limits = PruneLimits {
            max_bytes: 25,
            ..roomy()
        };
        s.prune(limits);
        assert!(s.exists("newest.entry") && s.exists("middle.entry"));
        assert!(!s.exists("oldest.entry"));
    }

    #[test]
    fn prune_dir_expired_removal_counts_toward_the_caps() {
        let s = Store::new();
        s.put("expired.entry", 1, Duration::from_hours(24 * 8));
        s.put("a.entry", 1, Duration::from_mins(1));
        s.put("b.entry", 1, Duration::from_mins(2));
        let limits = PruneLimits {
            max_files: 2,
            ..roomy()
        };
        s.prune(limits);
        assert!(!s.exists("expired.entry"));
        assert!(s.exists("a.entry") && s.exists("b.entry"));
    }

    #[test]
    fn prune_dir_stale_tmp_removal_counts_toward_the_byte_cap() {
        let s = Store::new();
        s.put("stale.tmp", 100, NOW_SKEW + Duration::from_mins(5));
        s.put("a.entry", 10, Duration::from_mins(1));
        s.put("b.entry", 10, Duration::from_mins(2));
        let limits = PruneLimits {
            max_bytes: 20,
            ..roomy()
        };
        s.prune(limits);
        assert!(!s.exists("stale.tmp"));
        assert!(s.exists("a.entry") && s.exists("b.entry"));
    }

    #[test]
    fn prune_dir_scan_is_capped() {
        let s = Store::new();
        for n in 0..5 {
            s.put(&format!("{n}.tmp"), 1, NOW_SKEW + Duration::from_mins(5));
        }
        let limits = PruneLimits {
            max_scan: 3,
            ..roomy()
        };
        let report = s.prune(limits);
        assert_eq!(report.scanned, 3);
        assert_eq!(report.removed, 3);
        assert_eq!(s.file_count(), 2);
    }

    #[test]
    fn prune_dir_reports_removed_count() {
        let s = Store::new();
        s.put("old.tmp", 1, NOW_SKEW + Duration::from_mins(5));
        s.put("expired.entry", 1, Duration::from_hours(24 * 8));
        s.put("keep.entry", 1, Duration::from_mins(1));
        let report = s.prune(roomy());
        assert_eq!(report.scanned, 3);
        assert_eq!(report.removed, 2);
    }

    #[test]
    fn prune_dir_leaves_foreign_names_and_directories_alone() {
        let s = Store::new();
        let ancient = Duration::from_hours(24 * 365);
        s.put("notes.txt", 1, ancient);
        s.put("noextension", 1, ancient);
        s.put("x.entry.bak", 1, ancient);
        fs::create_dir(s.tmp.path().join("sub.entry")).expect("dir");
        fs::create_dir(s.tmp.path().join("sub.tmp")).expect("dir");
        let report = s.prune(roomy());
        assert_eq!((report.removed, report.failed), (0, 0));
        assert_eq!(s.file_count(), 5);
    }

    #[test]
    fn prune_dir_removes_an_entry_stamped_in_the_future() {
        let s = Store::new();
        s.put_at("future.entry", 1, s.now + Duration::from_hours(24));
        s.put("ok.entry", 1, Duration::from_mins(1));
        let report = s.prune(roomy());
        assert!(!s.exists("future.entry"));
        assert!(s.exists("ok.entry"));
        assert_eq!(report.removed, 1);
    }

    #[cfg(unix)]
    #[test]
    fn prune_dir_continues_after_a_removal_failure_and_counts_it() {
        use std::os::unix::fs::PermissionsExt;
        let s = Store::new();
        let sub = s.tmp.path();
        s.put("expired.entry", 1, Duration::from_hours(24 * 8));
        fs::set_permissions(sub, fs::Permissions::from_mode(0o500)).expect("chmod");
        let vacuous = fs::File::create(sub.join("probe")).is_ok();
        let result = prune_dir(sub, s.now, roomy());
        fs::set_permissions(sub, fs::Permissions::from_mode(0o700)).expect("chmod");
        if vacuous {
            eprintln!("SKIPPED: directory permissions are not enforced (root)");
            return;
        }
        let report = result.expect("a removal failure is not a pass failure");
        assert_eq!((report.removed, report.failed), (0, 1));
        assert!(s.exists("expired.entry"));
    }

    #[test]
    fn prune_dir_empty_directory_is_a_no_op() {
        let s = Store::new();
        let report = s.prune(PruneLimits::DEFAULT);
        assert_eq!((report.scanned, report.removed), (0, 0));
    }

    #[test]
    fn prune_dir_missing_directory_is_ignored() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let report = prune_dir(
            &tmp.path().join("gone"),
            SystemTime::now(),
            PruneLimits::DEFAULT,
        )
        .expect("NotFound is ignored");
        assert_eq!((report.scanned, report.removed), (0, 0));
    }
}
