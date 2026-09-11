//! Fuzzes `deps_core::net_policy`'s credential-redaction chokepoint (#846) — the
//! parse-independent textual scanners `redact_userinfo`/`url_for_tracing` fall back to
//! whenever `Url::parse` fails outright or produces a cannot-be-a-base/no-host result.
//!
//! Two invariants:
//! (a) valid-UTF-8 input never panics `redact_userinfo`/`url_for_tracing` (guards every
//!     `#[allow(clippy::string_slice)]` slice-bound reasoning in `net_policy.rs`) — non-UTF-8
//!     bytes are skipped (`str::from_utf8` guard), not exercised, so this invariant does not
//!     cover raw non-UTF-8 input;
//! (b) a credential that reaches the fallback scanner is never left unredacted, for templates
//!     that exercise every rule `redact_credential`'s `Authority` side deduplicated by #846 —
//!     `redact_userinfo`'s own doc comment enumerates the ways `Url::parse` can fail or be
//!     cannot-be-a-base that route a value here.
//!
//! Invariant (b)'s templates keep the structural parts (`user`/`host`/scheme punctuation) and
//! the sentinel fixed, so the property can be asserted exactly; the fuzzer only varies an
//! alphanumeric-only tail appended after the structural part. A tail containing
//! `:`/`/`/`@`/`[`/`]`/`?`/`#` could otherwise corrupt the very structure each template is built
//! to exercise, or drift a template onto one of `net_policy.rs`'s documented accepted false
//! negatives (a bracket-adjacent colon, a ≤5-digit-prefixed value) — this target intentionally
//! avoids both a corrupted structure and re-fuzzing an already-accepted gap; it fuzzes only the
//! part outside either concern.
//!
//! Deliberately excluded from invariant (b): `OpaquePath`-shaped inputs (`scheme:/path`).
//! `RegionKind::OpaquePath` has two known, tracked leak classes (S4 `#858`, S5 `#859`) that
//! would make this invariant red on day one for a gap this target isn't meant to prove; those
//! are pinned instead as `#[ignore]`d regression tests in `net_policy.rs`.

#![no_main]

use deps_core::net_policy::{redact_userinfo, url_for_tracing};
use libfuzzer_sys::fuzz_target;

const SENTINEL: &str = "FUZZSECRET";

/// An alphanumeric-only tail derived from the fuzzer's raw bytes — see this file's own module
/// doc comment for why non-alphanumeric bytes are filtered out rather than passed through.
///
/// libFuzzer's CMP-tracing instrumentation observes `SENTINEL` inside this file's own `assert!`
/// and auto-adds it as a dictionary token, so the raw byte stream can — and, once discovered, will
/// repeatedly — spell out `SENTINEL` verbatim. Every template below places `tail` in a
/// non-credential position (the host/port), so a `tail` that happens to equal `SENTINEL` produces
/// an output that legitimately contains it outside any credential, which is not a leak but would
/// still trip invariant (b)'s blanket `!redacted.contains(SENTINEL)` check. Strip any occurrence
/// of `SENTINEL` from the tail so the assertion only ever observes the one deliberately injected
/// credential.
fn tail_from(data: &[u8]) -> String {
    let tail: String = data
        .iter()
        .filter(|b| b.is_ascii_alphanumeric())
        .take(16)
        .map(|&b| b as char)
        .collect();
    tail.replace(SENTINEL, "")
}

fuzz_target!(|data: &[u8]| {
    // Invariant (a): never panics, for any valid-UTF-8 input.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = redact_userinfo(text);
        let _ = url_for_tracing(text);
    }

    // Invariant (b): each template below is built to reach, and correctly redact through, a
    // specific branch of `redact_credential`'s `Authority` side — see the trailing comment on
    // each for which one.
    let tail = tail_from(data);
    let variants = [
        // Invalid port: fails `Url::parse` outright. Reaches the unconditional bounded
        // `rfind('@')` pass (the credential sits inside the bounded authority).
        format!("https://user:{SENTINEL}@host:999999{tail}"),
        // Malformed (unclosed) IPv6 literal: fails `Url::parse` outright. Also reaches the
        // bounded `rfind('@')` pass.
        format!("https://user:{SENTINEL}@[::1{tail}"),
        // Forbidden host code point (space): fails `Url::parse` outright. Also reaches the
        // bounded `rfind('@')` pass.
        format!("https://user:{SENTINEL}@ho st{tail}"),
        // Missing scheme: schemeless `user:pass@host` is cannot-be-a-base. Also reaches the
        // bounded `rfind('@')` pass.
        format!("user:{SENTINEL}@host{tail}"),
        // A `?`/`#`/`/` character before the real `@` empties the bounded authority of any `@`,
        // routing past the bounded pass into `bounded_has_credential_colon` ->
        // `find_credential_at` -> `segment_has_credential_colon` (the #826 widened-scan class).
        format!("https://user:{SENTINEL}?x@host:999999{tail}"),
        format!("https://user:{SENTINEL}#x@host:999999{tail}"),
        format!("https://user:{SENTINEL}/x@host:999999{tail}"),
        // No `@` anywhere: schemeless, cannot-be-a-base, reaches `redact_colon_credential`'s
        // no-`@` fallback directly (the #810 class) via `find_credential_at` returning `None`.
        format!("oauth2:{SENTINEL}{tail}"),
        // A bracketed IPv6 literal starts the bounded authority, with a real credential past a
        // `?` boundary: reaches `bounded_has_credential_colon`'s own `skip_bracketed_host` call,
        // then `find_credential_at` -> `segment_has_credential_colon`'s `skip_bracketed_host`
        // call too.
        format!("[::1]:8443:extra?user:{SENTINEL}@host{tail}"),
    ];
    for input in variants {
        let redacted = redact_userinfo(&input);
        assert!(
            !redacted.contains(SENTINEL),
            "credential leaked: input={input:?} output={redacted:?}"
        );
    }
});
