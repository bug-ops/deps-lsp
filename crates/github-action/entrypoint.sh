#!/usr/bin/env bash
set -uo pipefail

args=(check --format sarif)
[ -n "${DEPS_CLI_FAIL_ON:-}" ] && args+=(--fail-on "$DEPS_CLI_FAIL_ON")
[ -n "${DEPS_CLI_COOLDOWN:-}" ] && args+=(--cooldown "$DEPS_CLI_COOLDOWN")
[ -n "${DEPS_CLI_CONFIG:-}" ] && args+=(--config "$DEPS_CLI_CONFIG")
if [ -n "${DEPS_CLI_PATHS:-}" ]; then
	read -r -a paths_array <<<"$DEPS_CLI_PATHS"
	args+=("${paths_array[@]}")
fi

out=deps-lsp-results.sarif

# cwd is the scanned checkout — attacker-controlled under pull_request_target; a committed
# symlink would otherwise redirect this write outside it (#1132).
if [ -e "$out" ] || [ -L "$out" ]; then
	out_type="file"
	[ -d "$out" ] && out_type="directory"
	[ -L "$out" ] && out_type="symlink"
	echo "::warning::removing pre-existing $out (type: $out_type) before running deps-cli" >&2
fi
rm -f -- "$out"
if [ -e "$out" ] || [ -L "$out" ]; then
	echo "::error::refusing to run: $out exists in the scanned checkout and could not be removed." >&2
	exit 1
fi

deps-cli "${args[@]}" >"$out"
exit_code=$?

# deps-cli's contract is exactly 0/1/2; anything else (panic 101, missing binary 127,
# OOM 137, SIGSEGV 139) means the scan never completed.
if [ "$exit_code" -ne 0 ] && [ "$exit_code" -ne 1 ]; then
	echo "exit-code=$exit_code" >>"$GITHUB_OUTPUT"
	echo "::error::deps-cli check exited $exit_code (execution error) — no usable SARIF file was produced; see the job log above." >&2
	exit 1
fi

# Positive control: a failed redirect surfaces as exit 1 without running deps-cli at all.
if [ ! -f "$out" ] || [ ! -s "$out" ]; then
	echo "exit-code=$exit_code" >>"$GITHUB_OUTPUT"
	echo "::error::deps-cli check exited $exit_code but produced no usable SARIF file; refusing to report a clean scan." >&2
	exit 1
fi

{
	echo "sarif-file=$out"
	echo "exit-code=$exit_code"
} >>"$GITHUB_OUTPUT"
