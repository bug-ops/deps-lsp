//! Fuzzes `deps_core::parser::parse_toml_checked`, the single shared entry point every
//! untrusted-TOML parse site in the workspace routes through (manifests and lock files
//! alike) (#1406).
//!
//! Property under test: never panics for any UTF-8 string input, valid TOML or not.

#![no_main]

use deps_core::parser::parse_toml_checked;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_toml_checked(s);
    }
});
