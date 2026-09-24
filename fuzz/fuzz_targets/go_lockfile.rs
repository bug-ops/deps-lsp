//! Fuzzes `deps_go::lockfile::parse_go_sum`, the `go.sum` parser.
//!
//! Property under test: never panics for any byte input, valid `go.sum` or not.

#![no_main]

use deps_go::lockfile::parse_go_sum;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_go_sum(content);
});
