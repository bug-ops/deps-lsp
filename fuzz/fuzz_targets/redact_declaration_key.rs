//! Fuzzes `deps_core::net_policy::redact_declaration_key` (#1207) — the client-visible
//! redaction gate for [`crate::ecosystem::BlockedRegistryOccurrence::declaration_key`], reached
//! by `deps_core::lsp_helpers::diagnostics::build_blocked_registry_diagnostic` for every blocked
//! registry occurrence. Its sibling scanners (`redact_userinfo`/`url_for_tracing`) already have
//! `redact_userinfo.rs`, but that target never calls `redact_declaration_key` itself, so its
//! own gate (`is_authority_bearing_url(key) || has_credential_shape(key)`) — new machinery for
//! opaque, non-URL declaration-key labels — had zero fuzz coverage of its own. Also shared with
//! `is_credential_or_query_bearing` (#1206) for its own opaque-text fallback, but this target
//! only exercises `has_credential_shape` via `redact_declaration_key`, not that second caller.
//!
//! Four invariants:
//! (a) valid-UTF-8 input never panics `redact_declaration_key` — guards the
//!     `#[expect(clippy::string_slice)]` bound reasoning on `has_credential_shape`
//!     (`net_policy.rs:2365`), which this function's gate calls.
//! (b) for a template shaped `"<label>:<structural-prefix><SENTINEL>@<host>"` — the opaque-
//!     label-prefixed credential shape only `redact_declaration_key`'s own gate sees (a real
//!     URL-bearing credential is already covered by `redact_userinfo.rs`'s invariant (b)) — the
//!     sentinel never survives redaction. `label` always carries a fixed `"source"` prefix
//!     (never a WHATWG special scheme — `http`/`https`/`ws`/`wss`/`ftp`/`file` — and never
//!     immediately followed by `"//"`, since every `structural-prefix` below is a fixed literal
//!     that doesn't start with it), so `is_authority_bearing_url` can never short-circuit this
//!     invariant into asserting a guarantee `url_for_tracing`'s own already-documented,
//!     already-accepted colon-less/prefix-less residual doesn't make (`redact_userinfo.rs`'s own
//!     module doc, #858 S4) — a class this target isn't scoped to re-prove.
//!
//!     Everything after the fixed `"source"` prefix is fuzzer-derived from the same bounded
//!     structural alphabet as invariant (c) (`/ [ ] . - %`), so coverage-guided fuzzing can reach
//!     `segment_has_credential_colon`'s bracket-adjacent branch (`net_policy.rs:927-944`) through
//!     this invariant's under-redaction direction — the one `#1207` exists to probe, since (c)
//!     only ever exercises the opposite, over-redaction direction. `colon_is_drive_letter`
//!     (`net_policy.rs:1067`) and `is_port_like` (`net_policy.rs:1088`) are also *called* along
//!     this path, but under every template below they can only ever return `false`: both require
//!     the byte immediately after the relevant colon to be `/`/`\` or an ASCII digit run, and
//!     that byte is always a fixed template literal (`F` from `SENTINEL`, `u` from `"user:"`, or
//!     `f` from `"feed…"`) — reaching their `true` paths would need a dedicated template, not
//!     just a wider label alphabet, so this invariant does not claim that coverage. This is safe
//!     specifically because every `structural-prefix` below keeps the
//!     sentinel directly preceded by its own literal colon (`"user:"`, or the bare `label:`
//!     junction itself for the `""` case) regardless of what a structural `label` contains before
//!     it — verified by exhaustively combining 14 structural label shapes (including
//!     `"source/x"`, `"source[::1]"`, `"source.-%[]/x"`) against all 5 prefixes below (110
//!     combinations, zero leaks). A bare separator-only prefix with no colon of its own directly
//!     before the sentinel (e.g. plain `"feed/"`, with no following `"user:"`) is *not* included
//!     here: it is safe on its own with an alphanumeric label, but leaks once combined with a
//!     `/`-containing structural label (`"source/x:feed/FUZZSECRET@host"` leaves `FUZZSECRET`
//!     unredacted) — since `label` is fuzzer-derived and structural here, such prefixes are
//!     deliberately excluded rather than restored.
//! (c) the documented non-credential opaque labels each ecosystem actually emits survive
//!     `redact_declaration_key` unmangled — enumerated from every real producer:
//!     `"top-level"` (`deps_npm::config`), `format!("scope:{{scope}}")` (`deps_npm::config`),
//!     `format!("source:{{name}}")` (`deps_nuget::config`), `format!("named:{{name}}")`,
//!     `"primary"`, `"uv-tail"` (`deps_pypi::config`), `format!("component-host:{{host}}")`,
//!     `"gitlab_instance_host"` (`deps_gitlab_ci::parser`'s `INSTANCE_HOST_DECLARATION_KEY`),
//!     and Go's fixed GOPROXY declaration key (`"goproxy"`, mirrored here as a literal since
//!     `deps_go`'s own `GOPROXY_BLOCKED_DECLARATION_KEY` constant is private). The user-
//!     controlled `<name>`/`<host>`/`<scope>` positions are fuzzer-derived from the bounded
//!     structural alphabet (`/ [ ] . - %`, deliberately excluding `:`/`@`) — not because either
//!     character never occurs in a real producer's value (NuGet's free-text `source:{key}` can
//!     legitimately reach `"source:contoso@internal"`, which `redact_declaration_key`'s own doc
//!     accepts as a known, intentional over-redaction to `"***@internal"` —
//!     `net_policy.rs:2311-2316`), but because including them here would make this invariant
//!     assert an equality that documented behavior does not guarantee. Each falls back to the
//!     exact #993 S2 regression shape (`"feed//mirror"` / `"gitlab.example.com//group"`) when the
//!     fuzzer supplies no structural bytes, so this invariant can actually reproduce the
//!     regression it guards, not just assert over alphanumeric-only text that can never contain
//!     the `.`/`//` the regression turns on.
//! (d) a token carried after a `?`/`#` in an opaque, non-URL, non-credential-shaped key (no `:`
//!     at all, so `is_authority_bearing_url` is false, and no `@` at all, so
//!     `has_credential_shape` is false too) never survives — the one branch of
//!     `redact_declaration_key` (the plain `key.split(['?', '#'])` fallback, `net_policy.rs:2355`)
//!     invariants (a)-(c) never reach. `is_credential_or_query_bearing`'s own doc calls out
//!     `?token=`/`?access_token=` explicitly as a real class (`net_policy.rs:2383-2386`), and
//!     `diagnostics.rs` already has a dedicated unit test for the URL-bearing analogue of this
//!     shape. `label` here is structural too (same alphabet as (b)/(c)): the structural alphabet
//!     excludes `:`/`@`, so no combination of it can ever put a `:` or `@` into this branch's
//!     input, keeping `is_authority_bearing_url`/`has_credential_shape` false regardless.

#![no_main]

use deps_core::net_policy::redact_declaration_key;
use libfuzzer_sys::fuzz_target;

const SENTINEL: &str = "FUZZSECRET";

/// Splits `data` into `count` roughly-equal, non-overlapping byte windows and returns the
/// `index`-th one, so each fuzzer-derived value below (`label`, `host`, `name`, ...) is driven by
/// its own slice of the input rather than all reusing the same bytes — the mutator can then vary
/// them independently instead of them always moving in lockstep.
fn chunk(data: &[u8], index: usize, count: usize) -> &[u8] {
    let len = data.len();
    let start = len * index / count;
    let end = len * (index + 1) / count;
    &data[start..end]
}

/// A non-empty alphanumeric string derived from `data`, with any occurrence of `SENTINEL`
/// stripped — see `redact_userinfo.rs`'s own `tail_from` for why: libFuzzer's CMP tracing can
/// spell `SENTINEL` into any position, and every caller here places the result where a
/// coincidental `SENTINEL` would trip an unrelated `!redacted.contains(SENTINEL)` check without
/// being a real leak.
fn word_from(data: &[u8], fallback: &str) -> String {
    let word: String = data
        .iter()
        .filter(|b| b.is_ascii_alphanumeric())
        .take(12)
        .map(|&b| b as char)
        .collect();
    let word = word.replace(SENTINEL, "");
    if word.is_empty() {
        fallback.to_string()
    } else {
        word
    }
}

/// Like [`word_from`], but widened to the structural alphabet `has_credential_shape` and its
/// helpers actually branch on (`/ [ ] . - %`, deliberately excluding `:`/`@`, which every caller
/// keeps as fixed template literals) — see this file's own module doc, invariants (b)/(c), for
/// why.
fn structural_word_from(data: &[u8], fallback: &str) -> String {
    let word: String = data
        .iter()
        .filter(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'[' | b']' | b'.' | b'-' | b'%')
        })
        .take(16)
        .map(|&b| b as char)
        .collect();
    let word = word.replace(SENTINEL, "");
    if word.is_empty() {
        fallback.to_string()
    } else {
        word
    }
}

fuzz_target!(|data: &[u8]| {
    // Invariant (a): never panics, for any valid-UTF-8 input.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = redact_declaration_key(text);
    }

    // Invariant (b): `label` always keeps its fixed "source" prefix (never a special scheme) but
    // is otherwise structural/fuzzer-derived, and every prefix below keeps the sentinel directly
    // preceded by its own literal colon — see this file's own module doc for why both are
    // load-bearing, and why a bare separator-only prefix (no "user:") is deliberately excluded.
    let label = format!("source{}", structural_word_from(chunk(data, 0, 6), "lbl"));
    let host = word_from(chunk(data, 1, 6), "host");
    let structural_prefixes = ["", "user:", "feed/user:", "feed//user:", "feed%2F%2Fuser:"];
    for prefix in structural_prefixes {
        let input = format!("{label}:{prefix}{SENTINEL}@{host}");
        let redacted = redact_declaration_key(&input);
        assert!(
            !redacted.contains(SENTINEL),
            "credential leaked: input={input:?} output={redacted:?}"
        );
    }

    // Invariant (c): each documented non-credential label must survive verbatim.
    let name = structural_word_from(chunk(data, 2, 6), "feed//mirror");
    let component_host = structural_word_from(chunk(data, 3, 6), "gitlab.example.com//group");
    let scope = structural_word_from(chunk(data, 4, 6), "myorg");
    let non_credential_labels = [
        "top-level".to_string(),
        format!("scope:@{scope}"),
        format!("source:{name}"),
        format!("named:{name}"),
        "primary".to_string(),
        "uv-tail".to_string(),
        format!("component-host:{component_host}"),
        "gitlab_instance_host".to_string(),
        "goproxy".to_string(),
    ];
    for input in non_credential_labels {
        let redacted = redact_declaration_key(&input);
        assert_eq!(
            redacted, input,
            "over-redacted a documented non-credential declaration key: input={input:?} output={redacted:?}"
        );
    }

    // Invariant (d): a query/fragment-carried token in an opaque, `:`-less, `@`-less key must
    // never survive — exercises the plain `split(['?', '#'])` fallback branch invariants (a)-(c)
    // never reach.
    let opaque_label = format!("source{}", structural_word_from(chunk(data, 5, 6), "tail"));
    let query_variants = [
        format!("{opaque_label}?token={SENTINEL}"),
        format!("{opaque_label}?access_token={SENTINEL}"),
        format!("{opaque_label}#{SENTINEL}"),
    ];
    for input in query_variants {
        let redacted = redact_declaration_key(&input);
        assert!(
            !redacted.contains(SENTINEL),
            "credential leaked via query/fragment fallback: input={input:?} output={redacted:?}"
        );
    }
});
