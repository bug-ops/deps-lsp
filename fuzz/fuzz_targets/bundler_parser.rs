//! Fuzzes `deps_bundler::parser::parse_gemfile`, the regex-based `Gemfile` scanner (#673).
//!
//! Property under test: never panics for any byte input, valid Gemfile syntax or not.

#![no_main]

use deps_bundler::parser::parse_gemfile;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

static FUZZ_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/Gemfile").expect("static fixture path"));

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_gemfile(content, &FUZZ_URI);
});
