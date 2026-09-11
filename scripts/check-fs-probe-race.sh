#!/bin/bash
# Verifies deps_core::fs_probe's snapshot-guard invariant: every test in a crate that
# touches fs_probe (directly or transitively) must hold snapshot_guard()/snapshot_guard_async()
# for the duration of its fs_probe-touching call, so a plain (non-nextest) threaded
# `cargo test` run never races another test's snapshot diff (issue #806).
#
# `cargo nextest run` (the project's normal test runner) gives each test its own process,
# so this race cannot happen there — it only reproduces under plain `cargo test`'s
# multi-threaded single-process model, and only reliably at higher thread counts than a
# typical developer machine's default. Run this after adding or changing any test in one
# of the crates below that touches the filesystem (tempdir/NamedTempFile, manifest/config/
# lock-file parsing, `Ecosystem::parse_manifest`, `load_document_from_disk`), to catch a
# newly-unguarded test before it reaches CI's i686 cross-test leg.
#
# Usage: scripts/check-fs-probe-race.sh [thread-count]

set -euo pipefail

THREADS="${1:-32}"
CRATES=(deps-core deps-gradle deps-cargo deps-npm deps-nuget deps-lsp)
RUNS=15
FAILED=0

for crate in "${CRATES[@]}"; do
    echo "=== $crate (--test-threads=$THREADS, x$RUNS) ==="
    for i in $(seq 1 "$RUNS"); do
        if ! cargo test -p "$crate" --lib --all-features -- --test-threads="$THREADS" \
            >/tmp/fs-probe-race-"$crate"-"$i".log 2>&1; then
            echo "FAILED: $crate run $i/$RUNS — see /tmp/fs-probe-race-$crate-$i.log"
            FAILED=1
        fi
    done
done

if [ "$FAILED" -ne 0 ]; then
    echo
    echo "fs_probe race check FAILED — a test is touching fs_probe without holding" \
         "deps_core::fs_probe::snapshot_guard()/snapshot_guard_async(). See" \
         "crates/deps-core/src/fs_probe.rs's snapshot_guard doc for the fix."
    exit 1
fi

echo
echo "fs_probe race check passed: $((${#CRATES[@]} * RUNS)) runs, 0 failures."
