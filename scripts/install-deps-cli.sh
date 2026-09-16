#!/bin/sh
# Install deps-cli from a GitHub Release: curl -fsSL <raw-url-to-this-file> | sh
# POSIX sh (not bash-only) so it works under `sh` on any POSIX system without bash installed.
set -eu

REPO="bug-ops/deps-lsp"
BIN_NAME="deps-cli"
VERSION="${DEPS_CLI_VERSION:-}"
INSTALL_DIR="${DEPS_CLI_INSTALL_DIR:-}"

usage() {
	cat <<EOF
Usage: install-deps-cli.sh [--version|--tag <version>] [--install-dir <dir>]

Installs the deps-cli binary from a bug-ops/deps-lsp GitHub Release.

Options:
  --version, --tag <version>  Install a specific release tag (e.g. v1.0.0).
                               Defaults to the latest release.
                               Overrides \$DEPS_CLI_VERSION.
  --install-dir <dir>         Directory to install the binary into.
                               Overrides \$DEPS_CLI_INSTALL_DIR.
  -h, --help                  Show this help message.

Environment variables:
  DEPS_CLI_VERSION       Same as --version.
  DEPS_CLI_INSTALL_DIR   Same as --install-dir.
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--version | --tag)
		VERSION="$2"
		shift 2
		;;
	--install-dir)
		INSTALL_DIR="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown argument: $1" >&2
		usage >&2
		exit 1
		;;
	esac
done

log() { printf '%s\n' "$*" >&2; }
die() {
	log "error: $*"
	exit 1
}

command -v curl >/dev/null 2>&1 || die "curl is required but not found"
command -v tar >/dev/null 2>&1 || die "tar is required but not found"
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
	|| die "sha256sum or shasum is required but not found"

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

os="$(uname -s)"
case "$os" in
Linux)
	os_kind="linux"
	;;
Darwin)
	os_kind="darwin"
	;;
*)
	die "unsupported OS: $os. Windows is not supported by this script — download the .zip asset from https://github.com/${REPO}/releases instead."
	;;
esac

arch="$(uname -m)"
case "$arch" in
x86_64 | amd64)
	arch_kind="x86_64"
	;;
aarch64 | arm64)
	arch_kind="aarch64"
	;;
*)
	die "unsupported CPU architecture: $arch"
	;;
esac

if [ "$os_kind" = "linux" ]; then
	if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
		target="${arch_kind}-unknown-linux-musl"
	else
		target="${arch_kind}-unknown-linux-gnu"
	fi
else
	target="${arch_kind}-apple-darwin"
fi

archive="deps-cli-${target}.tar.gz"

if [ -z "$VERSION" ]; then
	log "Resolving latest ${BIN_NAME} release..."
	latest_url="https://api.github.com/repos/${REPO}/releases/latest"
	VERSION="$(curl -fsSL "$latest_url" | grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
	[ -n "$VERSION" ] || die "failed to resolve latest release tag from $latest_url"
fi

base_url="https://github.com/${REPO}/releases/download/${VERSION}"
archive_url="${base_url}/${archive}"
checksum_url="${archive_url}.sha256"

if [ -z "$INSTALL_DIR" ]; then
	if [ -n "${CARGO_HOME:-}" ] && [ -d "${CARGO_HOME}/bin" ]; then
		INSTALL_DIR="${CARGO_HOME}/bin"
	elif [ -d "${HOME}/.cargo/bin" ]; then
		INSTALL_DIR="${HOME}/.cargo/bin"
	else
		INSTALL_DIR="${HOME}/.local/bin"
	fi
fi

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT INT TERM

log "Downloading ${archive_url}..."
curl -fsSL -o "${tmp_dir}/${archive}" "$archive_url" \
	|| die "failed to download $archive_url (release $VERSION may not exist for target $target)"
curl -fsSL -o "${tmp_dir}/${archive}.sha256" "$checksum_url" \
	|| die "failed to download checksum file $checksum_url"

log "Verifying checksum..."
expected_sum="$(awk '{print $1}' "${tmp_dir}/${archive}.sha256")"
actual_sum="$(sha256 "${tmp_dir}/${archive}")"
[ "$expected_sum" = "$actual_sum" ] \
	|| die "checksum mismatch for $archive: expected $expected_sum, got $actual_sum"

log "Extracting ${archive}..."
tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir" "$BIN_NAME"
chmod +x "${tmp_dir}/${BIN_NAME}"

mkdir -p "$INSTALL_DIR"
mv "${tmp_dir}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"

log "Installed ${BIN_NAME} ${VERSION} to ${INSTALL_DIR}/${BIN_NAME}"
case ":$PATH:" in
*":${INSTALL_DIR}:"*) ;;
*) log "warning: ${INSTALL_DIR} is not in your \$PATH. Add it, e.g.: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
