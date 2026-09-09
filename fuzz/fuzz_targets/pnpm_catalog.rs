//! Fuzzes `deps_npm::fuzz_parse_pnpm_workspace` (feature `fuzzing`), the
//! `pnpm-workspace.yaml` catalog parser (#719/spec 046).
//!
//! Property under test: never panics for any byte input, valid YAML or not.

#![no_main]

use deps_npm::fuzz_parse_pnpm_workspace;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    fuzz_parse_pnpm_workspace(content);
});
