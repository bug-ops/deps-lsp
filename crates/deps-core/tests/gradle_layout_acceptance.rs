//! #2174: the Gradle layout facts that deps-gradle and deps-cli both depend on (settings file
//! names, what counts as a version catalog) live once, in `deps_core::gradle_layout`.

use std::path::Path;

use deps_core::gradle_layout::{GradleSettingsFile, is_version_catalog_file};

#[test]
fn settings_file_names_are_listed_in_lookup_order_kotlin_first() {
    assert_eq!(
        GradleSettingsFile::ALL.map(GradleSettingsFile::file_name),
        ["settings.gradle.kts", "settings.gradle"]
    );
}

#[test]
fn is_version_catalog_file_accepts_exactly_toml_extensions_ignoring_ascii_case() {
    let cases = [
        ("gradle/libs.versions.toml", true),
        ("gradle/plugins.versions.toml", true),
        ("gradle/.versions.toml", true),
        ("plugins.versions.toml", true),
        ("gradle/versions.toml", true),
        ("gradle/deps.toml", true),
        ("gradle/Deps.TOML", true),
        ("gradle/plugins.version.toml", true),
        ("gradle/plugins.versions.toml.bak", false),
        ("gradle/plugins.versions.tom", false),
        ("gradle/plugins.versions", false),
        ("build.gradle.kts", false),
        ("gradle/plugins.versions.toml/build.gradle", false),
        ("", false),
    ];
    for (path, expected) in cases {
        assert_eq!(is_version_catalog_file(Path::new(path)), expected, "{path}");
    }
}
