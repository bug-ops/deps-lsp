//! Generic "never surfaced via `Debug`/`Display`" wrapper for in-memory secrets.
//!
//! `deps_core::github::AuthToken`, `deps_cargo::config::AuthToken`,
//! `deps_nuget::config::NuGetAuth`, and `deps_nuget::config::RedactedSecret` each
//! hand-rolled the same single-field tuple struct: a private/crate-visible constructor, an
//! `as_str()` accessor documented "never logged, printed, or otherwise surfaced", and
//! hand-written `Debug`/`Display` impls that print `***` (#573). [`Redacted<T>`] is the one
//! place that pattern is implemented, so the four call sites cannot silently diverge on it
//! and a fifth ecosystem crate needing the same guarantee does not reinvent it a fifth time.
//!
//! Placed beside [`crate::net_policy::redact_userinfo`], which owns the adjacent "a
//! credential must not leak via a log line" concern for URLs specifically, while this module
//! owns it for an owned secret value held in memory.
//!
//! Beyond redacting `Debug`/`Display`, [`Redacted<T>`] zeroizes its backing memory on drop
//! (issue #574) — after the value goes out of scope, a core dump or a read of freed/swapped
//! memory cannot recover the plaintext credential.

use zeroize::{Zeroize, Zeroizing};

/// A secret value whose `Debug`/`Display` output is always `***`, and whose backing memory
/// is zeroized when it is dropped.
///
/// Wrap any credential that must never reach a log line, a panic message, or a future
/// `#[derive(Debug)]` added to a struct embedding it. `T` defaults to `String`, the shape
/// every current call site needs; a caller that needs a different backing type must supply
/// one that implements [`Zeroize`] (e.g. secret bytes as `Vec<u8>`).
///
/// # Examples
///
/// ```
/// use deps_core::secret::Redacted;
///
/// let token = Redacted::new("super-secret-value".to_string());
/// assert_eq!(token.as_str(), "super-secret-value");
/// assert_eq!(format!("{token:?}"), "Redacted(***)");
/// assert_eq!(format!("{token}"), "***");
/// ```
#[derive(Clone)]
pub struct Redacted<T: Zeroize = String>(Zeroizing<T>);

impl<T: Zeroize> Redacted<T> {
    /// Wraps `value`. The only way to recover it is [`Self::as_str`] (for `T: AsRef<str>`).
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl<T: Zeroize + AsRef<str>> Redacted<T> {
    /// The raw secret value. Never pass this to anything but the one call site that needs
    /// it (e.g. attaching a header value to a request) — never to a log, error message, or
    /// anything `Debug`/`Display`-formatted downstream.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl<T: Zeroize> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Redacted(***)")
    }
}

impl<T: Zeroize> std::fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Redacted<T> {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl<T: Zeroize + Eq> Eq for Redacted<T> {}

/// Marker confirming [`Redacted<T>`] zeroizes its backing memory on drop — the actual
/// zeroing is performed by the wrapped [`Zeroizing<T>`] field's own [`Drop`] impl.
impl<T: Zeroize> zeroize::ZeroizeOnDrop for Redacted<T> {}

#[cfg(test)]
mod tests {
    use super::Redacted;

    #[test]
    fn debug_redacts() {
        let secret = Redacted::new("hunter2".to_string());
        assert_eq!(format!("{secret:?}"), "Redacted(***)");
    }

    #[test]
    fn display_redacts() {
        let secret = Redacted::new("hunter2".to_string());
        assert_eq!(format!("{secret}"), "***");
    }

    #[test]
    fn as_str_recovers_the_value() {
        let secret = Redacted::new("hunter2".to_string());
        assert_eq!(secret.as_str(), "hunter2");
    }

    #[test]
    fn equality_compares_the_wrapped_value() {
        assert_eq!(
            Redacted::new("hunter2".to_string()),
            Redacted::new("hunter2".to_string())
        );
        assert_ne!(
            Redacted::new("hunter2".to_string()),
            Redacted::new("other".to_string())
        );
    }

    #[test]
    fn embedding_in_a_debug_derive_still_redacts() {
        #[derive(Debug)]
        struct Wrapper {
            token: Redacted,
        }
        let wrapper = Wrapper {
            token: Redacted::new("hunter2".to_string()),
        };
        assert_eq!(wrapper.token.as_str(), "hunter2");
        let debug_output = format!("{wrapper:?}");
        assert!(debug_output.contains("Redacted(***)"), "{debug_output}");
        assert!(!debug_output.contains("hunter2"), "{debug_output}");
    }

    /// Compile-time proof `Redacted<T>` zeroizes on drop — inspecting freed memory
    /// portably isn't practical in a test, so this asserts the trait bound instead (the
    /// idiomatic pattern for the `zeroize` ecosystem).
    #[test]
    fn implements_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Redacted<String>>();
    }
}
