//! Fuzzes `deps_bundler::lockfile::parse_gemfile_lock`, the `Gemfile.lock` parser.
//!
//! Property under test: never panics for any byte input, valid `Gemfile.lock` or not.

#![no_main]

use deps_bundler::lockfile::parse_gemfile_lock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_gemfile_lock(content);
});
