# deps-core-macros

[![Crates.io](https://img.shields.io/crates/v/deps-core-macros)](https://crates.io/crates/deps-core-macros)
[![docs.rs](https://img.shields.io/docsrs/deps-core-macros)](https://docs.rs/deps-core-macros)
[![License](https://img.shields.io/crates/l/deps-core-macros)](../../LICENSE)

Proc-macro derives for [`deps-core`](../deps-core): the `RedactingDebug` derive that forces every field of a credential-bearing struct to declare its redaction treatment.

> [!NOTE]
> This crate is an implementation detail. Depend on `deps-core` and use `deps_core::redact_debug::RedactingDebug` instead.

## License

MIT, see [LICENSE](../../LICENSE).
