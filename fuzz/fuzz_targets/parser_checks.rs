//! Fuzzes `deps_core::parser`'s depth/expansion checkers — the shared, single-pass
//! byte scanners every one of the 14 ecosystem crates routes untrusted manifest content
//! through before handing it to `toml-span`/`yaml-rust2`/`serde_json` (#673).
//!
//! Property under test: none of these checkers ever panics for any byte input, valid
//! UTF-8 or not.

#![no_main]

use deps_core::parser::{
    MAX_JSON_NESTING_DEPTH, MAX_TOML_NESTING_DEPTH, MAX_YAML_EXPANDED_BYTES,
    MAX_YAML_NESTING_DEPTH, check_json_nesting_depth, check_toml_nesting_depth,
    check_yaml_expansion, check_yaml_nesting_depth,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = check_json_nesting_depth(data, MAX_JSON_NESTING_DEPTH);

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = check_toml_nesting_depth(text, MAX_TOML_NESTING_DEPTH);
    let _ = check_yaml_nesting_depth(text, MAX_YAML_NESTING_DEPTH);
    let _ = check_yaml_expansion(text, MAX_YAML_EXPANDED_BYTES);
});
