//! Fuzzes `deps_dart::lockfile::parse_pubspec_lock`, the `pubspec.lock` parser.
//!
//! Property under test: never panics for any byte input, valid YAML or not.

#![no_main]

use deps_dart::lockfile::parse_pubspec_lock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_pubspec_lock(content);
});
