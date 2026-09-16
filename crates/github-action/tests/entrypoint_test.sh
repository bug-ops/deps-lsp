#!/usr/bin/env bash
# Regression tests for entrypoint.sh (#1131, #1132). Runs entrypoint.sh directly against a
# stub deps-cli on PATH and a tempfile-backed GITHUB_OUTPUT — no docker required.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTRYPOINT="$SCRIPT_DIR/../entrypoint.sh"

TESTS_RUN=0
TESTS_FAILED=0

pass() { echo "PASS: $1"; }
fail() {
	echo "FAIL: $1" >&2
	TESTS_FAILED=$((TESTS_FAILED + 1))
}

# new_case sets up an isolated workdir ($WORK/cwd), stub-bin dir ($BIN) and an empty
# GITHUB_OUTPUT file ($OUT) for one test case.
new_case() {
	WORK="$(mktemp -d)"
	BIN="$WORK/bin"
	OUT="$WORK/github_output"
	ERR="$WORK/stderr"
	mkdir -p "$WORK/cwd" "$BIN"
	: >"$OUT"
	: >"$ERR"
}

write_stub() {
	cat >"$BIN/deps-cli" <<STUB
#!/usr/bin/env bash
$1
STUB
	chmod +x "$BIN/deps-cli"
}

run_entrypoint() {
	# A hermetic PATH: only $BIN (the per-case stub dir) plus the standard system
	# utility dirs, deliberately excluding any real deps-cli that may be installed
	# elsewhere on the developer's machine (e.g. ~/.cargo/bin) so case 3 (missing
	# binary) is reliable.
	(cd "$WORK/cwd" && PATH="$BIN:/usr/bin:/bin" GITHUB_OUTPUT="$OUT" bash "$ENTRYPOINT") 2>"$ERR"
	return $?
}

assert_exit_nonzero() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ "$1" -ne 0 ]; then
		pass "$2"
	else
		fail "$2 (expected non-zero entrypoint exit, got 0)"
	fi
}

assert_exit_zero() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ "$1" -eq 0 ]; then
		pass "$2"
	else
		fail "$2 (expected entrypoint exit 0, got $1)"
	fi
}

assert_output_contains() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if grep -qF -- "$2" "$OUT"; then
		pass "$3"
	else
		fail "$3 (expected \$GITHUB_OUTPUT to contain '$2', got: $(cat "$OUT"))"
	fi
}

assert_output_not_contains() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if grep -qF -- "$2" "$OUT"; then
		fail "$3 (expected \$GITHUB_OUTPUT to NOT contain '$2', got: $(cat "$OUT"))"
	else
		pass "$3"
	fi
}

assert_stderr_contains() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if grep -qF -- "$2" "$ERR"; then
		pass "$3"
	else
		fail "$3 (expected stderr to contain '$2', got: $(cat "$ERR"))"
	fi
}

valid_sarif_stub() {
	printf '%s\n' 'echo "{\"version\":\"2.1.0\",\"runs\":[]}"'
}

# --- Case 1: stub killed with SIGKILL (exit 137) -> execution error, no sarif-file. ---
new_case
write_stub 'kill -9 $$'
run_entrypoint
ec=$?
assert_exit_nonzero "$ec" "case 1: SIGKILL stub fails the entrypoint step"
assert_output_not_contains "$OUT" "sarif-file=" "case 1: sarif-file is not set on SIGKILL"
assert_output_contains "$OUT" "exit-code=137" "case 1: raw exit code 137 is still reported"

# --- Case 2: stub panics (exit 101) -> execution error, no sarif-file. ---
new_case
write_stub 'exit 101'
run_entrypoint
ec=$?
assert_exit_nonzero "$ec" "case 2: panic-exit stub fails the entrypoint step"
assert_output_not_contains "$OUT" "sarif-file=" "case 2: sarif-file is not set on panic exit"
assert_output_contains "$OUT" "exit-code=101" "case 2: raw exit code 101 is still reported"

# --- Case 3: no deps-cli on PATH at all (exit 127) -> execution error, no sarif-file. ---
new_case
run_entrypoint
ec=$?
assert_exit_nonzero "$ec" "case 3: missing deps-cli binary fails the entrypoint step"
assert_output_not_contains "$OUT" "sarif-file=" "case 3: sarif-file is not set when deps-cli is missing"
assert_output_contains "$OUT" "exit-code=127" "case 3: raw exit code 127 is still reported"

# --- Case 4: output path pre-placed as a symlink to a path outside cwd (#1132). The guard
# removes the symlink (never follows it), so a fresh local file is written and the outside
# target is left untouched -- the run itself still succeeds when deps-cli behaves normally.
new_case
mkdir -p "$WORK/outside"
echo "must-not-be-touched" >"$WORK/outside/target.txt"
ln -s "$WORK/outside/target.txt" "$WORK/cwd/deps-lsp-results.sarif"
write_stub "$(valid_sarif_stub)
exit 0"
run_entrypoint
ec=$?
assert_exit_zero "$ec" "case 4: symlink guard still allows a normal successful run"
assert_output_contains "$OUT" "sarif-file=deps-lsp-results.sarif" "case 4: sarif-file points at the local path, not the symlink target"
TESTS_RUN=$((TESTS_RUN + 1))
if [ "$(cat "$WORK/outside/target.txt")" = "must-not-be-touched" ]; then
	pass "case 4: symlink target outside cwd was not written"
else
	fail "case 4: symlink target outside cwd was overwritten"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if [ -L "$WORK/cwd/deps-lsp-results.sarif" ]; then
	fail "case 4: output path is still a symlink after the run"
else
	pass "case 4: output path is a regular file after the run"
fi

# --- Case 5: output path pre-placed as a directory -> cannot be removed, refuse to run. ---
new_case
mkdir -p "$WORK/cwd/deps-lsp-results.sarif"
write_stub "$(valid_sarif_stub)
exit 0"
run_entrypoint
ec=$?
assert_exit_nonzero "$ec" "case 5: pre-existing directory fails the entrypoint step"
assert_output_not_contains "$OUT" "sarif-file=" "case 5: sarif-file is not set when the output path is a directory"
assert_output_not_contains "$OUT" "exit-code=" "case 5: exit-code is not set when the action refuses to start"
assert_stderr_contains "$ERR" "could not be removed" "case 5: stderr reports the refusal-to-start reason"
assert_stderr_contains "$ERR" "type: directory" "case 5: warning correctly classifies the pre-existing path as a directory"

# --- Case 6: stub exits 0 but writes nothing -> positive control, refuse a clean-looking
# result backed by an empty file. ---
new_case
write_stub 'exit 0'
run_entrypoint
ec=$?
assert_exit_nonzero "$ec" "case 6: empty SARIF output fails the entrypoint step (positive control)"
assert_output_not_contains "$OUT" "sarif-file=" "case 6: sarif-file is not set for an empty output file"
assert_output_contains "$OUT" "exit-code=0" "case 6: raw exit code 0 is still reported"
assert_stderr_contains "$ERR" "refusing to report a clean scan" "case 6: stderr reports the positive-control reason, distinct from case 5"

# --- Case 7: stub exits 0 with a valid SARIF file -> success. ---
new_case
write_stub "$(valid_sarif_stub)
exit 0"
run_entrypoint
ec=$?
assert_exit_zero "$ec" "case 7: clean deps-cli run succeeds"
assert_output_contains "$OUT" "sarif-file=deps-lsp-results.sarif" "case 7: sarif-file is set on a clean run"
assert_output_contains "$OUT" "exit-code=0" "case 7: exit-code=0 is reported"

# --- Case 8: stub exits 1 (a --fail-on category matched) with a valid SARIF file -> the
# step itself must still succeed (FR-018 defers the policy decision to the consumer). ---
new_case
write_stub "$(valid_sarif_stub)
exit 1"
run_entrypoint
ec=$?
assert_exit_zero "$ec" "case 8: a --fail-on policy violation does not fail the step"
assert_output_contains "$OUT" "sarif-file=deps-lsp-results.sarif" "case 8: sarif-file is set on a policy-violation run"
assert_output_contains "$OUT" "exit-code=1" "case 8: exit-code=1 is reported"

# --- Case 9: stub exits 2 (the canonical, originally-documented execution-error code) ->
# execution error, no sarif-file. ---
new_case
write_stub 'exit 2'
run_entrypoint
ec=$?
assert_exit_nonzero "$ec" "case 9: exit-2 stub fails the entrypoint step"
assert_output_not_contains "$OUT" "sarif-file=" "case 9: sarif-file is not set on exit 2"
assert_output_contains "$OUT" "exit-code=2" "case 9: raw exit code 2 is still reported"

# --- Case 10: output path pre-placed as a plain leftover regular file (e.g. a committed
# baseline), not a symlink or directory -> removed and replaced, run proceeds normally. ---
new_case
echo "stale-baseline-content" >"$WORK/cwd/deps-lsp-results.sarif"
write_stub "$(valid_sarif_stub)
exit 0"
run_entrypoint
ec=$?
assert_exit_zero "$ec" "case 10: pre-existing regular file is removed and the run still succeeds"
assert_output_contains "$OUT" "sarif-file=deps-lsp-results.sarif" "case 10: sarif-file is set after replacing the stale file"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -qF "stale-baseline-content" "$WORK/cwd/deps-lsp-results.sarif"; then
	fail "case 10: stale file content was not replaced"
else
	pass "case 10: stale file content was replaced by the fresh SARIF output"
fi
assert_stderr_contains "$ERR" "removing pre-existing" "case 10: the removal of the stale file is logged as a warning"

echo
echo "$TESTS_RUN tests run, $((TESTS_RUN - TESTS_FAILED)) passed, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
