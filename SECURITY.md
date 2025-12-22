# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it by emailing the maintainers directly.

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
