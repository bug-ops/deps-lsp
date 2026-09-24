//! Fuzzes `deps_cli::fuzz_parse_config` (feature `fuzzing`), the `deps.toml` config loader.
//!
//! Property under test: never panics for any byte input, valid `deps.toml` or not.

#![no_main]

use deps_cli::fuzz_parse_config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    fuzz_parse_config(content);
});
