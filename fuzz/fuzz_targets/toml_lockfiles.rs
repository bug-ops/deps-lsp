//! Fuzzes `deps_cargo::fuzz_parse_cargo_lock` and `deps_pypi::fuzz_parse_pypi_lock`
//! (feature `fuzzing`), the `toml_span`-based `Cargo.lock` and `poetry.lock`/`uv.lock`
//! parsers, with the same input bytes (both share the same TOML threat model).
//!
//! Property under test: never panics for any byte input, valid TOML or not.

#![no_main]

use deps_cargo::fuzz_parse_cargo_lock;
use deps_pypi::fuzz_parse_pypi_lock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    fuzz_parse_cargo_lock(content.to_string());
    fuzz_parse_pypi_lock(content.to_string());
});
