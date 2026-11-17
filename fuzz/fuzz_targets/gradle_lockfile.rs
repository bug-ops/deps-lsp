//! Fuzzes `deps_gradle::fuzz_parse_gradle_lock`, the `gradle.lockfile` line parser (#1925).
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
