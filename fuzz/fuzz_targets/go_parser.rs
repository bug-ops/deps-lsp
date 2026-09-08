//! Fuzzes `deps_go::parser::parse_go_mod`, the regex-based `go.mod` scanner (#673).
//!
//! Property under test: never panics for any byte input, valid go.mod syntax or not.

#![no_main]

use deps_go::parser::parse_go_mod;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

static FUZZ_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/go.mod").expect("static fixture path"));

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_go_mod(content, &FUZZ_URI);
});
