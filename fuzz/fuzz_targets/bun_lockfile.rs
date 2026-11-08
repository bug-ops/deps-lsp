//! Fuzzes `deps_npm::lockfile::fuzz_parse_bun_lock` (feature `fuzzing`), the CPU-bound
//! `bun.lock` parser (spec 090): the shared depth-bounded JSONC parse, the lenient package-tuple
//! deserializer and `name@resolution` label splitting.
//!
//! Property under test: never panics for any byte input, valid lock file or not.

#![no_main]

use deps_npm::lockfile::fuzz_parse_bun_lock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    fuzz_parse_bun_lock(content);
});
