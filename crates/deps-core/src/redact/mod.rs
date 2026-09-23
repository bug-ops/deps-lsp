//! Redaction: collapsing an attacker-influenced value to a form that is always safe to log,
//! surface in a client-visible message, or retain in an error — across three axes: URL text
//! (`url`), declaration-key/parse-error text (`key`), and an in-memory secret value held
//! for the duration of a request ([`secret`]).
//!
//! Extracted from `crate::net_policy` (issue #1247): that module had grown to mix two
//! unrelated concerns — host/registry-URL *policy* (still `crate::net_policy`) and *text/value
//! redaction* (here) — past the point a single file's module doc could describe either
//! coherently. The old `crate::net_policy` paths for every item that moved here still resolve,
//! via this module's re-exports, so the ~475 existing call sites across the workspace's
//! ecosystem crates keep compiling unchanged; only `deps-core`'s own internal call sites were
//! migrated to the canonical path below.
//!
//! Every redaction here follows the same trade-off: over-redacting an ordinary, credential-free
//! value costs a user a slightly less legible log line or diagnostic; under-redacting leaks a
//! credential. Every function in this module is written to fail toward the former.

mod key;
mod url;
mod wrapper;

pub mod secret;

#[cfg(test)]
pub(crate) use key::is_invisible;
pub use key::{
    MAX_PARSE_ERROR_LOG_BYTES, is_credential_or_query_bearing, parse_error_source,
    redact_declaration_key, redact_parse_error_for_log, sanitize_invisible,
};
pub use url::{redact_userinfo, url_for_tracing};
pub use wrapper::{
    NameRedaction, RedactedName, RedactedText, RedactedUrl, RedactionKind, UrlRedaction,
};
