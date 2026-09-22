//! `trybuild` compile-fail harness for `deps_core::redact_debug::RedactingDebug` (#1238, SC-002).
//!
//! Proves FR-005's compile errors actually fire — without this, a regression in the derive's
//! attribute-enforcement logic could silently start accepting unannotated fields again.
//!
//! **Known CI risk**: `trybuild`'s default mode does an exact string match against each
//! fixture's `.stderr` file, which embeds rustc's own diagnostic rendering (span underlines,
//! wording) — this can drift between the stable/beta toolchains this project's CI matrix runs
//! (`.claude/rules/branching.md`), causing a false failure with no code regression. If that
//! happens, regenerate the affected `.stderr` file(s) with `TRYBUILD=overwrite` on the
//! toolchain CI flagged and diff the result before committing, rather than loosening the
//! fixtures' assertions.

#[test]
fn redacting_debug_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/redacting_debug_compile_fail/fixtures/*.rs");
}
