//! Fuzzes `deps_swift::parser::parse_package_swift`, the regex-based `Package.swift`
//! scanner (#673).
//!
//! Property under test: never panics for any byte input, valid Package.swift syntax or not.

#![no_main]

use deps_swift::parser::parse_package_swift;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

static FUZZ_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/Package.swift").expect("static fixture path"));

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_package_swift(content, &FUZZ_URI);
});
