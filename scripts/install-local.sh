#!/bin/bash
# Install deps-lsp to ~/.local/bin for Zed dev extension testing

set -e

cargo build --release -p deps-lsp

# Ensure target directory exists
mkdir -p ~/.local/bin

# Remove old binary first to avoid macOS file caching issues
rm -f ~/.local/bin/deps-lsp

# Copy new binary
cp target/release/deps-lsp ~/.local/bin/
chmod +x ~/.local/bin/deps-lsp

# Clear macOS extended attributes (quarantine, provenance) to prevent Gatekeeper blocking
xattr -cr ~/.local/bin/deps-lsp 2>/dev/null || true

echo "✓ Installed deps-lsp to ~/.local/bin/"
echo "  Restart Zed to use the new version"
