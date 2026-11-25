//! #2171: settings-declared catalog recognition follows what Gradle imports: comments and string
//! literals are not code, a `from(` call may span lines, a brace inside a string does not end the
//! block, and every settings file above the catalog is consulted, not only the nearest one.

#![expect(clippy::unwrap_used, reason = "test code")]

use std::path::PathBuf;
use std::sync::Arc;

use deps_core::{EcosystemBase, HttpCache};
use deps_gradle::GradleEcosystem;

const CANDIDATE: &str = "gradle/x.toml";

struct Project {
    root: tempfile::TempDir,
}

impl Project {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn write(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.root.path().canonicalize().unwrap().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }
}

fn claimed(candidate: &std::path::Path) -> bool {
    GradleEcosystem::new(Arc::new(HttpCache::new())).claims_unrouted_manifest(candidate)
}

fn claims(settings_name: &str, settings: &str, candidate_rel: &str) -> bool {
    let project = Project::new();
    project.write(settings_name, settings);
    let candidate = project.write(candidate_rel, "[libraries]\n");
    claimed(&candidate)
}

#[test]
fn declarations_inside_comments_or_string_literals_are_not_claimed() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let cases = [
        (
            "single-line block comment",
            "versionCatalogs {\n  create(\"d\") {\n    /* from(files(\"gradle/x.toml\")) */\n  }\n}",
        ),
        (
            "multi-line block comment",
            "versionCatalogs {\n  create(\"d\") {\n    /*\n    from(files(\"gradle/x.toml\"))\n    */\n  }\n}",
        ),
        (
            "trailing line comment after code",
            "versionCatalogs {\n  create(\"d\") {\n    version(\"a\", \"1\") // from(files(\"gradle/x.toml\"))\n  }\n}",
        ),
        (
            "string literal",
            "versionCatalogs {\n  create(\"d\") {\n    println(\"from(files(\\\"gradle/x.toml\\\"))\")\n  }\n}",
        ),
    ];
    for (label, settings) in cases {
        assert!(
            !claims("settings.gradle.kts", settings, CANDIDATE),
            "{label} must not be claimed"
        );
    }
}

#[test]
fn a_real_declaration_next_to_a_trailing_comment_claims_only_the_real_path() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let project = Project::new();
    project.write(
        "settings.gradle.kts",
        "versionCatalogs {\n  create(\"d\") {\n    from(files(\"gradle/x.toml\")) // from(files(\"gradle/y.toml\"))\n  }\n}",
    );
    let real = project.write("gradle/x.toml", "[libraries]\n");
    let decoy = project.write("gradle/y.toml", "[libraries]\n");

    assert!(claimed(&real));
    assert!(!claimed(&decoy));
}

#[test]
fn a_from_call_split_across_lines_is_claimed() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    for (name, settings) in [
        (
            "settings.gradle.kts",
            "versionCatalogs {\n  create(\"d\") {\n    from(\n      files(\"gradle/x.toml\")\n    )\n  }\n}",
        ),
        (
            "settings.gradle",
            "versionCatalogs {\n  d {\n    from(\n      files('gradle/x.toml'))\n  }\n}",
        ),
    ] {
        assert!(claims(name, settings, CANDIDATE), "{settings}");
    }
}

#[test]
fn braces_inside_strings_or_comments_do_not_end_the_block_early() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    for (name, settings) in [
        (
            "settings.gradle.kts",
            "versionCatalogs {\n  create(\"d\") {\n    val brace = \"}\"\n    from(files(\"gradle/x.toml\"))\n  }\n}",
        ),
        (
            "settings.gradle",
            "versionCatalogs {\n  d {\n    def brace = '}'\n    from(files('gradle/x.toml'))\n  }\n}",
        ),
        (
            "settings.gradle.kts",
            "versionCatalogs {\n  create(\"d\") {\n    /* } */\n    // }\n    from(files(\"gradle/x.toml\"))\n  }\n}",
        ),
    ] {
        assert!(claims(name, settings, CANDIDATE), "{settings}");
    }
}

#[test]
fn root_settings_declaration_is_found_through_a_nested_settings_file() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let project = Project::new();
    project.write(
        "settings.gradle.kts",
        "versionCatalogs { create(\"d\") { from(files(\"sub/gradle/x.toml\")) } }",
    );
    project.write("sub/settings.gradle.kts", "rootProject.name = \"sub\"\n");
    let candidate = project.write("sub/gradle/x.toml", "[libraries]\n");

    assert!(claimed(&candidate));
}

#[test]
fn nested_settings_declaration_is_still_found_and_unrelated_candidates_stay_unclaimed() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let project = Project::new();
    project.write("settings.gradle.kts", "rootProject.name = \"root\"\n");
    project.write(
        "sub/settings.gradle.kts",
        "versionCatalogs { create(\"d\") { from(files(\"gradle/x.toml\")) } }",
    );
    let declared = project.write("sub/gradle/x.toml", "[libraries]\n");
    let undeclared = project.write("sub/gradle/y.toml", "[libraries]\n");

    assert!(claimed(&declared));
    assert!(!claimed(&undeclared));
}
