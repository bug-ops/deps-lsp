//! Fuzzes the registry-response XML parsers that have no manifest-side fuzz coverage
//! (#691): `deps_maven::registry`'s `maven-metadata.xml` parser and
//! `deps_gradle::license`'s Maven Central POM `<licenses>` parser. Both are private to
//! their crates in a normal build; each exposes a `fuzzing`-feature-gated wrapper
//! (`fuzz_parse_metadata_xml`, `fuzz_parse_pom_licenses`) reachable only from this target
//! (`deps_gradle`'s wrapper is re-exported at the crate root — its `license` module stays
//! unconditionally private).
//!
//! Property under test: neither parser panics for any byte input, well-formed XML or not.

#![no_main]

use deps_gradle::fuzz_parse_pom_licenses;
use deps_maven::registry::fuzz_parse_metadata_xml;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_parse_metadata_xml(data);
    fuzz_parse_pom_licenses(data);
});
