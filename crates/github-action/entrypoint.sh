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

deps-cli "${args[@]}" >deps-lsp-results.sarif
exit_code=$?

if [ "$exit_code" -eq 2 ]; then
	# Execution error, not a policy decision (FR-018 only defers exit-1 policy
	# violations to the consumer) — the SARIF file may be missing or truncated,
	# so leave sarif-file unset rather than hand upload-sarif a potentially bad
	# file, and fail the step for real.
	echo "exit-code=$exit_code" >>"$GITHUB_OUTPUT"
	echo "::error::deps-cli check exited 2 (execution error) — no SARIF file was produced; see the job log above." >&2
	exit 1
fi

{
	echo "sarif-file=deps-lsp-results.sarif"
	echo "exit-code=$exit_code"
} >>"$GITHUB_OUTPUT"
