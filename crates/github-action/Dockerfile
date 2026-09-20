# syntax=docker/dockerfile:1

# Fetches the pre-built deps-cli release binary for the target architecture and verifies it
# against its published SHA256 checksum, mirroring scripts/install-deps-cli.sh's approach.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS fetch

# apk upgrade first: the alpine:3.22 layer can be stale relative to its own repo snapshot,
# shipping an already-patched CVE otherwise (e.g. CVE-2026-14456 in libssl3/libcrypto3).
RUN apk upgrade --no-cache && apk add --no-cache curl tar

ARG DEPS_CLI_VERSION
ARG TARGETARCH

WORKDIR /tmp/fetch

# DEPS_CLI_VERSION has no default: a docker-container action build (e.g. `uses:
# ./crates/github-action` from this repo's own ci.yml) never passes build-args, so an empty
# value here resolves "latest" the same way scripts/install-deps-cli.sh does, while
# release.yml's image-publish job always passes the exact version being released explicitly.
RUN set -eu; \
	case "${TARGETARCH}" in \
	amd64) target="x86_64-unknown-linux-musl" ;; \
	arm64) target="aarch64-unknown-linux-musl" ;; \
	*) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
	esac; \
	version="${DEPS_CLI_VERSION:-}"; \
	if [ -z "${version}" ]; then \
	version="$(curl -fsSL https://api.github.com/repos/bug-ops/deps-lsp/releases/latest | grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"; \
	[ -n "${version}" ] || { echo "failed to resolve latest deps-lsp release tag" >&2; exit 1; }; \
	fi; \
	archive="deps-cli-${target}.tar.gz"; \
	base_url="https://github.com/bug-ops/deps-lsp/releases/download/${version}"; \
	curl -fsSL -o "${archive}" "${base_url}/${archive}"; \
	curl -fsSL -o "${archive}.sha256" "${base_url}/${archive}.sha256"; \
	expected="$(awk '{print $1}' "${archive}.sha256")"; \
	actual="$(sha256sum "${archive}" | awk '{print $1}')"; \
	[ "${expected}" = "${actual}" ] || { echo "checksum mismatch for ${archive}: expected ${expected}, got ${actual}" >&2; exit 1; }; \
	tar -xzf "${archive}" deps-cli; \
	chmod +x deps-cli

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

RUN apk upgrade --no-cache && apk add --no-cache bash ca-certificates

COPY --from=fetch /tmp/fetch/deps-cli /usr/local/bin/deps-cli
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
