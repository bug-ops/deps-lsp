//! Fuzzes `deps_maven::parser::parse_pom_xml`, the user-opened `pom.xml` manifest
//! parser (#691).
//!
//! Property under test: never panics for any byte input, valid `pom.xml` syntax or not.

#![no_main]

use deps_maven::parser::parse_pom_xml;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use url::Url;

static POM_URI: LazyLock<Url> =
    LazyLock::new(|| Url::from_file_path("/fuzz/pom.xml").expect("static fixture path"));

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_pom_xml(content, &POM_URI);
});
