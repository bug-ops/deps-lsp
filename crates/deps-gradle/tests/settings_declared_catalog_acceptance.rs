//! #2161: a `*.toml` file that `settings.gradle(.kts)` declares as a version catalog
//! (`versionCatalogs { create("x") { from(files("...")) } }`) is claimed by Gradle, though its
//! name matches no static manifest routing.

#![expect(clippy::unwrap_used, reason = "test code")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use deps_core::lockfile::LockFileProvider;
use deps_core::{EcosystemBase, EcosystemId, EcosystemRegistry, HttpCache};
use deps_gradle::{GradleEcosystem, GradleLockParser, parse_gradle};
use url::Url;

const KTS_DECLARING: &str = r#"
dependencyResolutionManagement {
    versionCatalogs {
        create("deps") {
            from(files("gradle/deps.toml"))
        }
    }
}
"#;

struct Project {
    root: tempfile::TempDir,
}

impl Project {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn root(&self) -> PathBuf {
        self.root.path().canonicalize().unwrap()
    }

    fn write(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.root().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }
}

fn ecosystem() -> GradleEcosystem {
    GradleEcosystem::new(Arc::new(HttpCache::new()))
}

fn registry() -> EcosystemRegistry {
    let registry = EcosystemRegistry::new();
    registry.register(Arc::new(ecosystem()));
    registry
}

/// Whether Gradle claims `candidate_rel` in a project whose settings file has `settings`.
fn claims(settings_name: &str, settings: &str, candidate_rel: &str) -> bool {
    let project = Project::new();
    project.write(settings_name, settings);
    let candidate = project.write(candidate_rel, "[libraries]\n");
    ecosystem().claims_unrouted_manifest(&candidate)
}

#[test]
fn registry_for_uri_blocking_routes_a_declared_kotlin_catalog_to_gradle() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let project = Project::new();
    project.write("settings.gradle.kts", KTS_DECLARING);
    let candidate = project.write("gradle/deps.toml", "[libraries]\n");
    let uri = Url::from_file_path(&candidate).unwrap();
    let registry = registry();

    assert!(registry.for_uri(&uri).is_none(), "for_uri stays pure");
    assert_eq!(
        registry.for_uri_blocking(&uri).unwrap().ecosystem_id(),
        EcosystemId::Gradle
    );
}

#[test]
fn registry_routes_nothing_without_a_declaring_settings_file() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let project = Project::new();
    let candidate = project.write("gradle/deps.toml", "[libraries]\n");
    let uri = Url::from_file_path(&candidate).unwrap();
    let registry = registry();

    assert!(registry.for_uri(&uri).is_none());
    assert!(registry.for_uri_blocking(&uri).is_none());
}

#[test]
fn claim_accepts_groovy_settings_in_every_from_form() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    for settings in [
        "dependencyResolutionManagement { versionCatalogs { deps { from(files('gradle/deps.toml')) } } }",
        "versionCatalogs {\n  deps {\n    from files('gradle/deps.toml')\n  }\n}",
        "versionCatalogs {\n  create('deps') {\n    from(files(\"gradle/deps.toml\"))\n  }\n}",
        "versionCatalogs { create(\"deps\") { from files(\"./gradle/deps.toml\") } }",
    ] {
        assert!(
            claims("settings.gradle", settings, "gradle/deps.toml"),
            "{settings}"
        );
    }
}

#[test]
fn claim_accepts_the_kotlin_form() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    assert!(claims(
        "settings.gradle.kts",
        KTS_DECLARING,
        "gradle/deps.toml"
    ));
}

#[test]
fn claim_rejects_undeclared_or_unsafe_declarations() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let cases = [
        (
            "a different path",
            "versionCatalogs { create(\"d\") { from(files(\"gradle/other.toml\")) } }",
        ),
        (
            "a commented line",
            "versionCatalogs {\n  create(\"d\") {\n    // from(files(\"gradle/deps.toml\"))\n  }\n}",
        ),
        (
            "an interpolated path",
            "versionCatalogs { create(\"d\") { from(files(\"$x/deps.toml\")) } }",
        ),
        (
            "an absolute path",
            "versionCatalogs { create(\"d\") { from(files(\"/etc/gradle/deps.toml\")) } }",
        ),
        (
            "a parent traversal",
            "versionCatalogs { create(\"d\") { from(files(\"../gradle/deps.toml\")) } }",
        ),
        (
            "a coordinate source",
            "versionCatalogs { create(\"d\") { from(\"g:a:1.0\") } }",
        ),
        (
            "no versionCatalogs block",
            "dependencies { from(files(\"gradle/deps.toml\")) }",
        ),
    ];
    for (label, settings) in cases {
        assert!(
            !claims("settings.gradle.kts", settings, "gradle/deps.toml"),
            "{label} must not be claimed"
        );
    }
}

#[test]
fn claim_ignores_an_unclosed_or_misnamed_block() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let unclosed = "versionCatalogs {\n  create(\"d\") {\n    from(files(\"gradle/deps.toml\"))\n";
    assert!(!claims("settings.gradle.kts", unclosed, "gradle/deps.toml"));
    let misnamed = "myversionCatalogs { from(files(\"gradle/deps.toml\")) }";
    assert!(!claims("settings.gradle.kts", misnamed, "gradle/deps.toml"));
}

#[test]
fn claim_reads_every_versioncatalogs_block() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let settings = "versionCatalogs { create(\"a\") { from(files(\"gradle/a.toml\")) } }\n\
                    versionCatalogs { create(\"b\") { from(files(\"gradle/b.toml\")) } }\n";
    assert!(claims("settings.gradle.kts", settings, "gradle/a.toml"));
    assert!(claims("settings.gradle.kts", settings, "gradle/b.toml"));
}

#[test]
fn parse_gradle_dispatches_any_toml_uri_to_the_catalog_parser() {
    let uri = deps_core::test_util::test_uri("/project/gradle/deps.toml");
    let content =
        "[libraries]\nguava = { module = \"com.google.guava:guava\", version = \"33.0.0-jre\" }\n";

    let deps = parse_gradle(content, &uri).unwrap().dependencies;

    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "com.google.guava:guava");
}

#[test]
fn claim_on_a_non_toml_path_makes_no_filesystem_probe() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let project = Project::new();
    project.write("settings.gradle.kts", KTS_DECLARING);
    let candidate = project.write("gradle/deps.txt", "x");
    let ecosystem = ecosystem();

    let before = deps_core::fs_probe::snapshot();
    let claimed = ecosystem.claims_unrouted_manifest(&candidate);
    let after = deps_core::fs_probe::snapshot();

    assert!(!claimed);
    assert_eq!(
        after, before,
        "a non-toml name must be rejected without fs calls"
    );
}

#[test]
fn locate_lockfile_for_a_declared_catalog_finds_the_root_lockfile() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let project = Project::new();
    project.write("settings.gradle.kts", KTS_DECLARING);
    let lockfile = project.write("gradle.lockfile", "");
    let catalog = project.write("gradle/deps.toml", "[libraries]\n");
    let uri = Url::from_file_path(&catalog).unwrap();

    let located = GradleLockParser
        .locate_lockfile(&uri)
        .map(|path| path.canonicalize().unwrap());
    assert_eq!(located, Some(lockfile.canonicalize().unwrap()));
}

#[test]
fn claim_never_panics_on_a_relative_or_missing_path() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let ecosystem = ecosystem();
    assert!(!ecosystem.claims_unrouted_manifest(Path::new("deps.toml")));
    assert!(!ecosystem.claims_unrouted_manifest(Path::new("/nonexistent-dir/gradle/deps.toml")));
}
