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
