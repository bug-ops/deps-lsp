# Adding a New Ecosystem

This chapter walks through adding support for a new package ecosystem (e.g., a language or
build tool not yet covered) to `deps-lsp`, from an empty crate to a registered, tested
implementation. It assumes familiarity with the [Architecture Overview](../architecture.md) —
in particular the `Ecosystem` trait, `Registry`, and `EcosystemFormatter`.

Read the steps in order; each builds on artifacts (types, error variants) created in an earlier
one:

1. [Create the Crate](step-1-crate.md)
2. [Handle Errors](step-2-errors.md)
3. [Define Types](step-3-types.md)
4. [Implement the Parser](step-4-parser.md)
5. [Implement the Registry Client](step-5-registry.md)
6. [Implement the Ecosystem Trait](step-6-ecosystem-trait.md)
7. [Implement the Lock File Provider](step-7-lockfile.md)
8. [Implement the Formatter](step-8-formatter.md)
9. [Create `lib.rs`](step-9-libr.md)
10. [Register the Ecosystem](step-10-register.md)
11. [Add Tests](step-11-tests.md)

Once implemented, work through the [Checklist](checklist.md) before opening a PR. See
[Reference Implementations](reference-implementations.md) for existing crates to study, and
[Templates](templates.md) for a scaffold to start from. [Key API Contracts](key-api-contracts.md)
documents conventions (no `async_trait`, position tracking, `LockFileProvider` signatures,
registry client method naming) that apply across every step above.
