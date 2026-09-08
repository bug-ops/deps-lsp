//! Fuzzes `deps_gradle::parser::parse_gradle`, the dispatching entry point over Gradle's
//! three manifest formats (Groovy DSL, Kotlin DSL, version catalog TOML) (#673).
//!
//! Property under test: never panics for any byte input, valid Gradle manifest syntax or
//! not, across all three formats this dispatches to.

#![no_main]

use deps_gradle::parser::parse_gradle;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

static GROOVY_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/build.gradle").expect("static fixture path"));
static KOTLIN_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/build.gradle.kts").expect("static fixture path"));
static CATALOG_URI: LazyLock<Uri> = LazyLock::new(|| {
    Uri::from_file_path("/fuzz/gradle/libs.versions.toml").expect("static fixture path")
});

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_gradle(content, &GROOVY_URI);
    let _ = parse_gradle(content, &KOTLIN_URI);
    let _ = parse_gradle(content, &CATALOG_URI);
});
