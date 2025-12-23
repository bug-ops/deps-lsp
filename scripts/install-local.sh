#!/bin/bash
# Install deps-lsp to ~/.local/bin for Zed dev extension testing

set -e

cargo build --release -p deps-lsp
cp target/release/deps-lsp ~/.local/bin/
echo "✓ Installed deps-lsp to ~/.local/bin/"
echo "  Restart Zed to use the new version"
