# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities privately through GitHub's Security Advisories:
[Report a vulnerability](https://github.com/bug-ops/deps-lsp/security/advisories/new).

**Please do not open a public issue for security vulnerabilities.**

You can expect:
- Acknowledgment within 48 hours
- Status update within 7 days
- Fix timeline based on severity

## Security Measures

This project implements:
- Zero unsafe code blocks
- TLS enforcement via rustls
- Automated vulnerability scanning with cargo-deny
- Dependency auditing via Dependabot

## Verifying Release Artifacts

Every archive published on the [Releases page](https://github.com/bug-ops/deps-lsp/releases)
(`deps-lsp-*` and `deps-cli-*`, for every target) ships with a `.sha256` checksum, a `.sig`
signature, and a `.pem` certificate.

**Checksum** (integrity only — protects against transfer corruption):
```bash
sha256sum -c deps-cli-x86_64-unknown-linux-gnu.tar.gz.sha256   # Linux/macOS
certUtil -hashfile deps-cli-x86_64-pc-windows-msvc.zip SHA256  # Windows
```

**Signature** (integrity and provenance — proves the artifact was built by this repository's
release workflow, not just that it wasn't corrupted in transit). Artifacts are signed keylessly
with [Sigstore/cosign](https://docs.sigstore.dev/cosign/installation/) via GitHub Actions OIDC,
so there is no key to trust or manage:
```bash
cosign verify-blob \
  --certificate deps-cli-x86_64-unknown-linux-gnu.tar.gz.pem \
  --signature   deps-cli-x86_64-unknown-linux-gnu.tar.gz.sig \
  --certificate-identity-regexp 'https://github.com/bug-ops/deps-lsp/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  deps-cli-x86_64-unknown-linux-gnu.tar.gz
```
