//! Fuzzes `deps_gradle::fuzz_parse_gradle_lock`, the `gradle.lockfile` line parsers, unified and legacy grammars (#1925, #2039).
//!
//! Property under test: never panics for any byte input.

#![no_main]

use deps_gradle::fuzz_parse_gradle_lock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    fuzz_parse_gradle_lock(content);
});
