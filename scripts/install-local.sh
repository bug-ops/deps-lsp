#!/bin/bash
# Install deps-lsp to ~/.local/bin for Zed dev extension testing

set -e

cargo build --release -p deps-lsp

# Copy binary and clear macOS extended attributes (quarantine, provenance)
# to prevent Gatekeeper from blocking execution
cp target/release/deps-lsp ~/.local/bin/
xattr -cr ~/.local/bin/deps-lsp 2>/dev/null || true

echo "✓ Installed deps-lsp to ~/.local/bin/"
echo "  Restart Zed to use the new version"
