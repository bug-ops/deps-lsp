//! Compile-time-enforced `Debug` redaction (issue #1238).
//!
//! [`RedactingDebug`](derive@crate::redact_debug::RedactingDebug) is a `#[derive(...)]` macro (implemented in the `deps-core-macros`
//! proc-macro crate, re-exported here so consumers depend on `deps-core` alone) that generates
//! a struct's `Debug` impl and requires every named field to declare exactly one of
//! `#[redact(url)]`, `#[redact(key)]`, or `#[raw]`. An unannotated field fails to compile,
//! closing the recurring gap where a new credential-shaped field was named in a
//! [`crate::debug_redaction_conformance!`] test but left unredacted (#936, #935, #1217, #1219,
//! #1220, #1221, #1222, #1225).
//!
//! Only structs with named fields are supported — an enum's redaction depends on which variant
//! is active, which does not fit this derive's per-field attribute model; such types stay on
//! the existing [`crate::debug_redaction_conformance!`] test-time path.
//!
//! # Examples
//!
//! Unlike [`crate::debug_redaction_conformance!`]'s own doc example (a type-check-only doctest
//! — see that macro's doc for why a `#[test]`-attributed fn body is silently elided outside a
//! real `--test` build), this one keeps the derive usage in its own `mod example` but calls the
//! check as a plain top-level statement below it, so the assertions actually execute when
//! `cargo test --doc` runs this example, not merely type-check.
//!
//! ```
//! mod example {
//!     use deps_core::redact_debug::RedactingDebug;
//!
//!     #[derive(RedactingDebug)]
//!     pub struct RegistryCredential {
//!         #[redact(url)]
//!         pub index_url: String,
//!         #[redact(key)]
//!         pub declaration_key: String,
//!         #[raw]
//!         pub is_default: bool,
//!     }
//! }
//!
//! let value = example::RegistryCredential {
//!     index_url: "https://user:hunter2@registry.example/simple".to_string(),
//!     declaration_key: "source:https://user:hunter2@10.0.0.1/index".to_string(),
//!     is_default: true,
//! };
//! let rendered = format!("{value:?}");
//! assert!(rendered.contains("***@registry.example/simple"));
//! assert!(rendered.contains("***@10.0.0.1/index"));
//! assert!(!rendered.contains("hunter2"));
//! assert!(rendered.contains("is_default: true"));
//! ```
pub use deps_core_macros::RedactingDebug;

/// Runtime helper backing a `#[redact(url)]` field in [`derive@RedactingDebug`]'s generated code.
///
/// `#[doc(hidden)]`: called only from the derive's macro-generated `impl Debug`, never meant
/// to be called directly. Delegates to [`crate::redact::url_for_tracing`] — the same
/// redactor every hand-written `Debug` impl this derive replaces already called.
#[doc(hidden)]
#[must_use]
pub fn __redact_url_field(value: &(impl AsRef<str> + ?Sized)) -> String {
    crate::redact::url_for_tracing(value.as_ref())
}

/// Runtime helper backing a `#[redact(key)]` field in [`derive@RedactingDebug`]'s generated code.
///
/// `#[doc(hidden)]`: called only from the derive's macro-generated `impl Debug`, never meant
/// to be called directly. Delegates to [`crate::redact::redact_declaration_key`] — the
/// same redactor every hand-written `Debug` impl this derive replaces already called.
#[doc(hidden)]
#[must_use]
pub fn __redact_key_field(value: &(impl AsRef<str> + ?Sized)) -> String {
    crate::redact::redact_declaration_key(value.as_ref())
}

#[cfg(test)]
mod tests {
    use super::RedactingDebug;

    #[derive(RedactingDebug)]
    #[expect(
        dead_code,
        reason = "fields are only read through the derived Debug impl, which rustc's \
                  dead-code analysis deliberately does not count as a read"
    )]
    struct Probe {
        #[redact(url)]
        index_url: String,
        #[redact(key)]
        declaration_key: String,
        #[raw]
        retries: u8,
    }

    // Actually executes under `cargo nextest run` — unlike this module's doctest (a real
    // execution too, since #1238's impl-critic review, but kept separately so the derive's
    // runtime behavior has coverage independent of `cargo test --doc`).
    #[test]
    fn redact_url_field_masks_userinfo_but_keeps_host() {
        let probe = Probe {
            index_url: "https://user:hunter2@registry.example/simple?token=abc".to_string(),
            declaration_key: "source:https://user:hunter2@10.0.0.1/index".to_string(),
            retries: 3,
        };
        let rendered = format!("{probe:?}");
        assert!(
            rendered.contains("***@registry.example/simple"),
            "expected redacted host to survive in: {rendered}"
        );
        assert!(
            !rendered.contains("hunter2"),
            "credential leaked into: {rendered}"
        );
        assert!(
            !rendered.contains("token=abc"),
            "query string leaked into: {rendered}"
        );
        assert!(
            rendered.contains("***@10.0.0.1/index"),
            "expected redacted key to survive in: {rendered}"
        );
        assert!(
            rendered.contains("retries: 3"),
            "expected #[raw] field unredacted in: {rendered}"
        );
    }
}
