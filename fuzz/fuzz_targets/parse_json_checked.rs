//! Fuzzes `deps_core::parser::parse_json_checked`, the single shared entry point every
//! untrusted-JSON parse site in the workspace routes through (manifest bodies and
//! registry response bodies alike) (#673).
//!
//! Property under test: never panics for any byte input, valid JSON or not.

#![no_main]

use deps_core::parser::parse_json_checked;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_json_checked::<serde_json::Value>(data);
});
