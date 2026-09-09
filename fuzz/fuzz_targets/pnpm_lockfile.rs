//! Fuzzes `deps_npm::fuzz_parse_pnpm_lock_yaml` (feature `fuzzing`), the CPU-bound
//! `pnpm-lock.yaml` parser (#719): peer-suffix stripping, `name@version` alias splitting,
//! and `yaml_scalar_string` coercion of unquoted numeric-looking versions.
//!
//! Property under test: never panics for any byte input, valid YAML or not.

#![no_main]

use deps_npm::fuzz_parse_pnpm_lock_yaml;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    fuzz_parse_pnpm_lock_yaml(content);
});
