#!/usr/bin/env bash
# Publish workspace crates to crates.io in dependency order.
#
# Usage: scripts/publish-crates.sh [--list | --dry-run]
#   --list     print the publish order and exit
#   --dry-run  print what would be published, without calling `cargo publish`
#
# Auth: `cargo publish` reads CARGO_REGISTRY_TOKEN from the environment.
set -euo pipefail

MODE="publish"
case "${1:-}" in
  "") ;;
  --list) MODE="list" ;;
  --dry-run) MODE="dry-run" ;;
  *) echo "usage: $0 [--list | --dry-run]" >&2; exit 2 ;;
esac

PUBLISH_ATTEMPTS=30
PUBLISH_POLL_SECS=10
INDEX_SETTLE_SECS=5

# Kahn's algorithm over workspace-internal dependencies (dev-deps included:
# they carry a version requirement that crates.io resolves). Ties are broken
# alphabetically so the order is deterministic.
publish_order() {
  cargo metadata --no-deps --format-version 1 | python3 -c '
import heapq, json, sys

meta = json.load(sys.stdin)
members = set(meta["workspace_members"])
pkgs = {p["name"]: p for p in meta["packages"] if p["id"] in members and p["publish"] != []}

deps = {
    name: {d["name"] for d in p["dependencies"] if d["name"] in pkgs and d["name"] != name}
    for name, p in pkgs.items()
}
dependents = {name: [] for name in pkgs}
for name, ds in deps.items():
    for d in ds:
        dependents[d].append(name)

ready = [n for n, ds in deps.items() if not ds]
heapq.heapify(ready)
order = []
while ready:
    n = heapq.heappop(ready)
    order.append(n)
    for m in dependents[n]:
        deps[m].discard(n)
        if not deps[m]:
            heapq.heappush(ready, m)

if len(order) != len(pkgs):
    cyclic = sorted(set(pkgs) - set(order))
    sys.exit("dependency cycle among: " + ", ".join(cyclic))
print("\n".join(order))
'
}

workspace_version() {
  cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
meta = json.load(sys.stdin)
versions = {p["version"] for p in meta["packages"] if p["id"] in set(meta["workspace_members"]) and p["publish"] != []}
if len(versions) != 1:
    sys.exit("publishable crates have differing versions: " + ", ".join(sorted(versions)))
print(versions.pop())
'
}

is_published() {
  local crate="$1" version="$2"
  curl -sf "https://crates.io/api/v1/crates/${crate}/${version}" \
    -H "User-Agent: deps-lsp-release-ci" >/dev/null
}

ORDER="$(publish_order)"

if [ "$MODE" = "list" ]; then
  echo "$ORDER"
  exit 0
fi

VERSION="$(workspace_version)"

for CRATE in $ORDER; do
  if is_published "$CRATE" "$VERSION"; then
    echo "Skipping ${CRATE}@${VERSION} (already published)"
    continue
  fi

  if [ "$MODE" = "dry-run" ]; then
    echo "Would publish ${CRATE}@${VERSION}"
    continue
  fi

  echo "Publishing ${CRATE}@${VERSION}..."
  cargo publish --no-verify -p "$CRATE"

  # Dependents resolve this crate through the index, so wait until it is visible.
  for ((i = 1; i <= PUBLISH_ATTEMPTS; i++)); do
    if is_published "$CRATE" "$VERSION"; then
      sleep "$INDEX_SETTLE_SECS"
      break
    fi
    if [ "$i" -eq "$PUBLISH_ATTEMPTS" ]; then
      echo "${CRATE}@${VERSION} not visible on crates.io after $((PUBLISH_ATTEMPTS * PUBLISH_POLL_SECS))s" >&2
      exit 1
    fi
    sleep "$PUBLISH_POLL_SECS"
  done
done
