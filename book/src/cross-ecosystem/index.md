# Cross-Ecosystem Features

The behaviors in this chapter are implemented once in `deps-core` (see
[Architecture Overview](../architecture.md)) and apply, with the coverage noted in each section,
across most or all of the 14 supported ecosystems — rather than being reimplemented per crate.

- [Conventions](conventions.md) — the inlay hint icons and hover/diagnostic/code lens text
  conventions every ecosystem shares.
- [Licensing](licensing.md) — license hover and the license allow/deny policy diagnostic.
- [Yanked Versions & Vulnerabilities](yanked-and-vulnerabilities.md) — the two independent
  yanked-version diagnostics, the vulnerability-fix code action, and the supply-chain trust
  signal.
- [Version Diagnostics](version-diagnostics.md) — unsatisfiable requirements, package
  deprecation, the dependency-count ceiling, and the bulk "update outdated" code lens.
- [CI/CD Pinning](ci-pinning.md) — the mutable-ref-pin diagnostic and bulk "pin to SHA" code
  lens shared by GitHub Actions and GitLab CI/CD.

Ecosystem-specific behavior — parsing, registry resolution, custom/private registries — lives in
the [Ecosystem Reference](../ecosystems/index.md) chapters instead.
