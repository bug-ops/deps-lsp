//! Fuzzes `deps_pypi::parser::PypiParser::parse_requirements`, which drives the PEP 508
//! requirement/marker split this issue specifically named (`semicolon_idx` handling in
//! `deps-pypi/src/parser/mod.rs`) (#673).
//!
//! Property under test: never panics for any byte input, valid `requirements.txt` syntax
//! or not.

#![no_main]

use deps_pypi::parser::PypiParser;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

static FUZZ_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/requirements.txt").expect("static fixture path"));

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let parser = PypiParser::new();
    let _ = parser.parse_requirements(content, &FUZZ_URI, false);
});
