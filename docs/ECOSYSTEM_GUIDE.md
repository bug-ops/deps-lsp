# Ecosystem Implementation Guide

This file has been superseded by the **deps-lsp book**, published at:

**<https://bug-ops.github.io/deps-lsp/book/>**

The book reorganizes this guide's content into three parts, from simple to advanced:

- [Architecture Overview](https://bug-ops.github.io/deps-lsp/book/architecture.html) — the
  `Ecosystem`, `Registry`, and `EcosystemFormatter` abstractions.
- [Cross-Ecosystem Features](https://bug-ops.github.io/deps-lsp/book/cross-ecosystem/index.html)
  and the [Ecosystem Reference](https://bug-ops.github.io/deps-lsp/book/ecosystems/index.html) —
  the per-feature and per-ecosystem content previously in this file's flat `###` section list,
  now organized by topic and by ecosystem instead of chronologically by issue number.
- [Adding a New Ecosystem](https://bug-ops.github.io/deps-lsp/book/contributing/index.html) —
  the Step 1-11 contributor tutorial, checklist, reference implementations, and API contracts.

The book's source lives in this repository under [`book/`](../book/) and builds locally with
`mdbook build book` (see `book/book.toml`).
