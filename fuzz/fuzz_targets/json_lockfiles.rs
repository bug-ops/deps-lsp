//! Fuzzes the `parse_json_checked`-based lock-file parsers (feature `fuzzing`) with the
//! same input bytes: `deps_npm::fuzz_parse_package_lock_json_content`
//! (`package-lock.json`), `deps_composer::fuzz_parse_composer_lock` (`composer.lock`),
//! `deps_nuget::fuzz_parse_packages_lock_json` (`packages.lock.json`), and
//! `deps_swift::fuzz_parse_package_resolved` (`Package.resolved`).
//!
//! Property under test: never panics for any byte input, valid JSON or not.

#![no_main]

use deps_composer::fuzz_parse_composer_lock;
use deps_npm::fuzz_parse_package_lock_json_content;
use deps_nuget::fuzz_parse_packages_lock_json;
use deps_swift::fuzz_parse_package_resolved;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    fuzz_parse_package_lock_json_content(content.to_string());
    fuzz_parse_composer_lock(content.to_string());
    fuzz_parse_packages_lock_json(content.to_string());
    fuzz_parse_package_resolved(content.to_string());
});
