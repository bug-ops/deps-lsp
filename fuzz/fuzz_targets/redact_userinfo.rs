//! Fuzzes `deps_core::net_policy`'s credential-redaction chokepoint (#846) — the
//! parse-independent textual scanners `redact_userinfo`/`url_for_tracing` fall back to
//! whenever `Url::parse` fails outright or produces a cannot-be-a-base/no-host result.
//!
//! Four invariants:
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
//! to exercise, or drift a template onto the one remaining documented accepted false negative (a
//! ≤5-digit-prefixed value colliding with the `host:port` carve-out) — this target intentionally
//! avoids both a corrupted structure and re-fuzzing an already-accepted gap; it fuzzes only the
//! part outside either concern.
//!
//! Still excluded from invariant (b): `OpaquePath`-shaped inputs (`scheme:/path`) whose
//! credential is a username-only value (no password) that `find_token_prefix_at` in
//! `net_policy.rs` does not recognize — either genuinely unprefixed (`c:/hunter2@evil`) or
//! token-prefixed but not at that function's own `/`/`?`/`#`/`\` segment-start boundary
//! (`c:/a;ghp_TOKEN@evil`, where `;` is a legitimate RFC 3986 path-parameter separator, not one
//! of those boundary characters) — both stay unredacted by design (#858, S4's residual gap; see
//! `redact_credential`'s own doc comment, C1, and `find_token_prefix_at`'s own doc for the
//! precise, canonical statement of which shapes qualify) and would make this invariant red on
//! day one for a gap this target isn't meant to prove — the residual is broader than "unprefixed
//! only", so do not re-enable this invariant for `OpaquePath` just because unprefixed values are
//! handled. S5 (`#859`, an `@` inside the password) is fixed, and S4's segment-start-prefixed
//! case is now fixed too (#858) — see invariant (d) below, which fuzzes exactly that narrower
//! case with the sentinel given a real token prefix at a real segment start, so it stays in
//! scope.
//!
//! (c) a credential is never left unredacted across the bracket/colon delimiter space #860/#857
//!     rewrote — for *both* `RegionKind`s, since #857 removed `OpaquePath`'s special-cased
//!     guard entirely. This is the differential-fuzz coverage #860's own issue body named as a
//!     precondition for merging (an impl-critic review found the initial implementation skipped
//!     it and, empirically, net-increased leakage over `main`): the fuzzed "decoration" here is
//!     drawn from `[`/`]`/`/`/`@` only (never `:`, so it can only add bracket/slash/`@` noise
//!     around a scanner-controlled, always-present colon — never inject an uncontrolled one that
//!     could itself swallow the sentinel through the general, pre-existing "mask stops at the
//!     next path separator" limitation every colon-based match in this file has, in or out of a
//!     bracket, and which is out of scope for #860/#857 to fix). `@` was added to this alphabet by
//!     #869's fix, so the `mask_at`-tail family it closed (a second, independent colon-credential
//!     sitting in the tail after the chosen `@`) is fuzz-covered going forward.
//!
//! (d) a token-prefixed `OpaquePath` username-only credential (no password) is never left
//!     unredacted (#858, S4's fix): the sentinel itself is given a fixed, real token prefix
//!     (`ghp_`) so it can only be recognized via the prefix, never coincidentally via a colon —
//!     the fuzzed part is the `scheme:` and separator noise preceding it, drawn from the same
//!     bracket/slash alphabet as invariant (c) plus a handful of `OpaquePath`-eligible schemes. A
//!     literal `/` always separates that noise from the credential itself, since the fix's own
//!     contract requires the credential's segment to *start* with a known prefix — decoration
//!     glued directly onto it with no boundary in between is a documented non-match, not a leak
//!     this invariant is meant to catch.
//!
//! (e) `Authority`-side twin of (d) (#887): a token-prefixed, colon-less credential sitting past a
//!     `/` boundary in a `RegionKind::Authority` value that has no nested `://` scheme of its own
//!     (the region `redact_userinfo_unparseable` anchors on, or a value with no scheme at all)
//!     must never be left unredacted. `redact_authority_suffix`'s widen branch used to call
//!     `redact_colon_credential` directly there, which returns its input verbatim once it finds no
//!     colon at all — so this class leaked in full before #887's fix. As with (d), a literal `/`
//!     always separates the bracket/slash decoration from the credential's own segment start.

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

/// Bracket/slash/`@` "decoration" for invariant (c) — see this file's own module doc comment for
/// why `:` is deliberately excluded from this alphabet (it must never be the fuzzer, rather than
/// a fixed template literal, that introduces the one colon each template's assertion depends on).
/// `@` was added by #869 so this decoration can reach `mask_at`'s tail-redaction path too.
fn bracket_decoration(data: &[u8]) -> String {
    data.iter()
        .filter(|b| matches!(b, b'[' | b']' | b'/' | b'@'))
        .take(8)
        .map(|&b| b as char)
        .collect()
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
        // `?` boundary: reaches `bounded_has_credential_colon`'s own `bracket_host_shape_end`
        // call, then `find_credential_at` -> `segment_has_credential_colon`'s
        // `bracket_host_shape_end` call too.
        format!("[::1]:8443:extra?user:{SENTINEL}@host{tail}"),
    ];
    for input in variants {
        let redacted = redact_userinfo(&input);
        assert!(
            !redacted.contains(SENTINEL),
            "credential leaked: input={input:?} output={redacted:?}"
        );
    }

    // Invariant (c): every colon in each template below is a fixed literal, never
    // fuzzer-derived — only the bracket/slash decoration around them varies.
    let deco = bracket_decoration(data);
    let bracket_variants = [
        // C3: an unclosed bracket must never swallow the real credential's own colon, no matter
        // how much bracket/slash noise precedes or interrupts it.
        format!("{deco}[::1:{SENTINEL}"),
        format!("[::1{deco}:{SENTINEL}"),
        format!("x/{deco}[::1:{SENTINEL}"),
        // C2: a bracket-adjacent non-port value is forced to redact (#860) but must mask through
        // to the end of the region, never leaving a later, genuine credential exposed in the
        // unredacted tail.
        format!("[::1]:abc/user:{SENTINEL}"),
        format!("[{deco}::1]:abc/user:{SENTINEL}"),
        // C1: a bracket shape with nothing to do with the credential must never disable
        // redaction of an unrelated, real credential elsewhere in an `OpaquePath` value.
        format!("c:/{deco}[]/token:{SENTINEL}"),
        format!("c:/[0]{deco}/token:{SENTINEL}"),
        format!("file:///home/u{deco}[x]/gitlab-ci-token:{SENTINEL}"),
    ];
    for input in bracket_variants {
        let redacted = redact_userinfo(&input);
        assert!(
            !redacted.contains(SENTINEL),
            "credential leaked: input={input:?} output={redacted:?}"
        );
    }

    // Invariant (d): the sentinel always carries a real token prefix (`ghp_`) so it can only be
    // recognized via `find_token_prefix_at`'s prefix check, never a coincidental colon (there is
    // deliberately no `:` anywhere in these templates); only the `OpaquePath`-eligible scheme and
    // the bracket/slash noise preceding the credential vary. A literal `/` always separates
    // `deco` from the credential itself: `find_token_prefix_at` requires the credential's own
    // segment to *start* with a known prefix, so decoration glued directly onto the credential
    // with no boundary between them is a documented non-match, not a leak this invariant covers
    // (see that function's own doc comment and its `TOKEN_PREFIXES` const). A fixed `x` also
    // always separates the scheme's own `/` from `deco`: `c:/` has only one literal slash, so a
    // `deco` that itself starts with `/` could otherwise combine with it into `c://`, which
    // `Url::parse` treats as authority-having (empty host) rather than `OpaquePath` — a
    // pre-existing, unrelated gap (see the #858 security audit's "NEW FINDING"), not what this
    // invariant is scoped to cover.
    let token_credential = format!("ghp_{SENTINEL}");
    let opaque_variants = [
        format!("c:/x{deco}/{token_credential}@evil"),
        format!("file:///x{deco}/{token_credential}@evil"),
        format!("nuget:///x{deco}/{token_credential}@feed.corp/v3"),
    ];
    for input in opaque_variants {
        let redacted = redact_userinfo(&input);
        assert!(
            !redacted.contains(SENTINEL),
            "credential leaked: input={input:?} output={redacted:?}"
        );
    }

    // Invariant (e): `Authority`-side twin of (d) — a token-prefixed credential past a `/`
    // boundary, reached via `redact_authority_suffix`'s widen branch instead of `OpaquePath`'s
    // `mask_at`. No `:` anywhere in these templates, matching (d)'s own reasoning; `https://`
    // gives the outer value a scheme so it anchors through `redact_userinfo_unparseable`, but the
    // region past it has no further `://` of its own (the #887 repro shape).
    let authority_variants = [
        format!("https://[/x{deco}/{token_credential}@evil{tail}"),
        format!("[/x{deco}/{token_credential}@evil{tail}"),
        format!("x{deco}/{token_credential}@evil{tail}"),
    ];
    for input in authority_variants {
        let redacted = redact_userinfo(&input);
        assert!(
            !redacted.contains(SENTINEL),
            "credential leaked: input={input:?} output={redacted:?}"
        );
    }
});
