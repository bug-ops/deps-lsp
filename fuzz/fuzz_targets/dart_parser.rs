//! Fuzzes `deps_dart::parse_pubspec_yaml`, the tree-and-text-search `pubspec.yaml` parser.
//!
//! Property under test: never panics for any byte input, valid YAML or not.

#![no_main]

use deps_dart::parse_pubspec_yaml;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

static PUBSPEC_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/pubspec.yaml").expect("static fixture path"));

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_pubspec_yaml(content, &PUBSPEC_URI);
});
