//! Declaration-key and parse-error-message redaction: the credential-shape gate applied to a
//! value that is not always a URL (an opaque label, a manifest declaration key, or a parser's
//! error message), unlike [`super::url`]'s URL-specific redaction.

use super::url::{
    is_authority_bearing_url, redact_userinfo, segment_has_credential_colon, url_for_tracing,
};

/// Redacts a [`crate::ecosystem::BlockedRegistryOccurrence::declaration_key`] value for safe
/// inclusion in a client-visible diagnostic message.
///
/// `key` is not always a URL: most ecosystems set it to a short opaque label (`"top-level"`,
/// `"source:Blocked"`, `"scope:@myorg"`), and only some set it to a real registry URL, sometimes
/// prefixed with an opaque label of the ecosystem's own choosing
/// (`"source:https://user:pass@host/index"`). Running [`url_for_tracing`]'s aggressive
/// text-scan fallbacks unconditionally would mangle a label like `"scope:@myorg"` into
/// `"***@myorg"` (#981), so redaction only runs when `key` shows real URL structure
/// (`is_authority_bearing_url`) or a credential shape of its own: at least one `@` whose own
/// preceding segment (back to the previous `@`, or `key`'s own start) has a credential-shaped
/// `:` once its own trailing `:` is stripped (`segment_has_credential_colon`, checked
/// per-segment so a decoy trailing `label:@...` segment can't shadow an earlier real credential
/// — #993 M5). Stripping the trailing `:` first is what keeps `"scope:@myorg"` — an
/// empty-username userinfo shape used as an opaque label, not a credential — from matching,
/// since after stripping it the segment is just `"scope"`, with no `:` left to trip the check.
/// This is a shape check, not a separator check: it has no opinion on `/` at all, so it catches
/// a credential regardless of what separates the opaque label from it
/// (`"source:user:ghp_SECRET@host"`, `"source:feed/user:hunter2@host"`,
/// `"source:feed//user:hunter2@host"`, even a percent-encoded
/// `"source:feed%2F%2Fuser:hunter2@h"`, since the scan only looks at `:`/`@`, never `/`), while
/// never mangling a `/`-containing label that has no `@` at all (`"source:feed//mirror"`,
/// `"component-host:gitlab.example.com//group"` are left untouched — #993 S2, a regression in
/// an earlier, separator-based version of this gate). Every other key takes the plain
/// query/fragment-strip fallback instead.
///
/// Two accepted trade-offs, both favoring over-redaction over under-redaction per this module's
/// own stated design (see [`redact_userinfo`]'s doc):
/// - Once triggered, the actual redaction ([`url_for_tracing`]) can still destroy more of `key`
///   than just the credential — e.g. `"source:feed//user:hunter2@h"` redacts to `"***@h"`,
///   losing the `"source:feed//"` label entirely — since the fallback scan this reaches has no
///   way to tell where the opaque label ends and true userinfo begins once neither
///   `is_authority_bearing_url` nor a real authority is available to anchor on. This defeats
///   `declaration_key`'s own disambiguation purpose (see its doc, and
///   `build_blocked_registry_diagnostic`'s) for that one value.
/// - A non-credential `label:text@text`-shaped key is redacted too, since the gate cannot tell
///   it apart from a real credential — e.g. `"source:contoso@internal"` redacts to
///   `"***@internal"` even though `contoso` is just a source name, not a password. In practice
///   only a free-text label an ecosystem builds from unvalidated user input (e.g. NuGet's
///   `format!("source:{}", entry.key)` from a `NuGet.config` `<add key>` attribute) is likely to
///   contain an `@` at all — most ecosystems' own fixed/opaque labels cannot.
///
/// This is a best-effort heuristic gate, not a formally verified one: it closes every
/// known-realistic and known-adversarial leak shape found so far (#981, #993), but a
/// sufficiently unusual `key` could in principle still slip past both `is_authority_bearing_url`
/// and this shape check.
///
/// # Examples
///
/// ```
/// use deps_core::redact::redact_declaration_key;
///
/// assert_eq!(
///     redact_declaration_key("https://user:hunter2@10.0.0.1/index"),
///     "https://***@10.0.0.1/index"
/// );
/// assert_eq!(
///     redact_declaration_key("source:https://user:hunter2@10.0.0.1/v3/index.json"),
///     "source:https://***@10.0.0.1/v3/index.json"
/// );
/// assert_eq!(redact_declaration_key("source:Blocked"), "source:Blocked");
/// assert_eq!(redact_declaration_key("scope:@myorg"), "scope:@myorg");
/// // A single `/` (not `//`) still redacts — this is a credential-shape gate, not a
/// // separator-substring gate.
/// assert_eq!(
///     redact_declaration_key("source:feed/user:hunter2@nuget.internal"),
///     "***@nuget.internal"
/// );
/// // No `@` at all: never redacted, even with a `/`-heavy label.
/// assert_eq!(
///     redact_declaration_key("source:feed//mirror"),
///     "source:feed//mirror"
/// );
/// ```
#[must_use]
pub fn redact_declaration_key(key: &str) -> String {
    if is_authority_bearing_url(key) || has_credential_shape(key) {
        url_for_tracing(key)
    } else {
        key.split(['?', '#']).next().unwrap_or_default().to_string()
    }
}

/// Replaces every Unicode `Cc` (Control), `Cf` (Format), `Zl` (Line Separator), and `Zp`
/// (Paragraph Separator) character in `s` with a single space, borrowing when `s` has none
/// (#1242, #1246).
///
/// `Cc` covers ASCII/C1 control characters, including `\n`/`\r` and raw ANSI escape
/// (`\x1B`) bytes, that could otherwise splice new lines into a single-line rendering
/// (table row, JSON string, SARIF message) or forge terminal escape sequences. `Cf`
/// additionally covers invisible formatting characters with no glyph of their own —
/// bidirectional overrides (e.g. U+202E RIGHT-TO-LEFT OVERRIDE, the Trojan Source vector),
/// zero-width joiners/spaces (U+200B, U+200C, U+200D), and the byte-order mark (U+FEFF) —
/// which can visually reorder or hide text without tripping a `Cc`-only check. `Zl`/`Zp`
/// (U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR) are neither `Cc` nor `Cf`, but are
/// still line terminators for JS/`eval` consumers of `--format json` output and are treated
/// as breaks by some editor renderers (critic follow-up M1, #1246).
///
/// This is deliberately wider than [`crate::lsp_helpers::escape_markdown`] and
/// [`crate::lsp_helpers::markdown_code_span`]'s own narrow, explicit bidi/invisible-character
/// list (`is_markdown_unsafe`, #1248): those helpers also run on registry-supplied hover
/// *descriptions*, where legitimate right-to-left text carries real `Cf` marks (e.g. U+200F
/// RIGHT-TO-LEFT MARK, U+061C ARABIC LETTER MARK) and emoji ZWJ sequences carry U+200D, so
/// treating the whole `Cf` category as unsafe there would mangle genuine Arabic/Hebrew text
/// or emoji. A manifest-declared package/coordinate *name*, by contrast, has no legitimate
/// use for any `Cf`/`Zl`/`Zp` character, so this dedicated helper — for name-shaped values
/// only — can safely treat the whole categories as unsafe.
///
/// # Examples
///
/// ```
/// use deps_core::redact::sanitize_invisible;
///
/// assert_eq!(sanitize_invisible("left-pad"), "left-pad");
/// assert_eq!(sanitize_invisible("a\nb\rc"), "a b c");
/// assert_eq!(sanitize_invisible("bidi\u{202E}gnp.exe"), "bidi gnp.exe");
/// assert_eq!(sanitize_invisible("a\u{2028}b\u{2029}c"), "a b c");
/// ```
#[must_use]
pub fn sanitize_invisible(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(is_invisible) {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .map(|c| if is_invisible(c) { ' ' } else { c })
            .collect(),
    )
}

/// Whether `c` belongs to the Unicode `Cc`/`Cf`/`Zl`/`Zp` general categories
/// [`sanitize_invisible`] sweeps.
///
/// `pub(crate)` rather than private so `lsp_helpers::mod`'s drift-guard test (#1323) can
/// scan the full Unicode code space and assert that every character this predicate
/// flags is either blocked by `is_markdown_unsafe` or in that function's documented,
/// named exempt set — without duplicating this category logic in the test itself,
/// which would defeat the point of a drift guard.
pub(crate) fn is_invisible(c: char) -> bool {
    use unicode_general_category::{GeneralCategory, get_general_category};

    matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    )
}

/// Longest prefix (in bytes, not chars — see [`redact_parse_error_for_log`]'s slicing) of a
/// redacted parse-error message logged, post-redaction, by [`redact_parse_error_for_log`].
///
/// `pub`, not `pub(crate)`: `deps_pypi::parser::truncate_for_log` (a thin wrapper delegating to
/// [`redact_parse_error_for_log`]) mirrors this value for its own test fixtures rather than
/// hardcoding a second `200` that could silently drift from this one.
pub const MAX_PARSE_ERROR_LOG_BYTES: usize = 200;

/// Redacts, then bounds, a parse-error's `Display` text before it reaches a log sink.
///
/// `toml_span::Error` and `yaml_rust2::ScanError` can both embed a manifest/lockfile's
/// offending duplicate key or table name verbatim in their `Display` output, and that name can
/// itself be a credential-bearing URL (#1240). [`redact_declaration_key`] runs first, then the
/// result is truncated to a bounded prefix — in that order, since truncating first could cut the
/// string exactly at the boundary the credential-shape scan depends on, leaking a credential
/// that straddles the cut. Truncation is an independent concern from redaction: the file `raw`
/// derives from can be as large as the ~10 MB read cap
/// ([`crate::fs_probe::read_to_string_capped`]'s bound), so an unbounded
/// `tracing::warn!`/`debug!`/`error!` call would be a synchronous multi-megabyte write to a (by
/// default, unbuffered, stderr-backed) log sink — this mostly matters on the benign path, since
/// once redaction actually fires it collapses `raw` to a short fixed-shape string well under the
/// cap. Falls back to `raw` unchanged (as a `Cow::Borrowed`, so a caller that just needs to read
/// or forward the result avoids a second clone) when redaction was a no-op and it's already
/// short enough.
///
/// Note: this does not currently avoid the *first* allocation — [`redact_declaration_key`]
/// itself always builds an owned `String`, even on its own no-op branch, so a `Cow::Borrowed`
/// here still follows one allocation inside it. Making [`redact_declaration_key`] itself
/// `Cow`-returning would close that gap, but it has ~20 other call sites across the workspace,
/// so that's out of scope here (a possible follow-up, not done by this PR).
///
/// This is the single shared implementation behind both `deps-core`'s own parse-error sinks and
/// `deps_pypi::parser::truncate_for_log`'s delegation to it — see CLAUDE.md's cross-ecosystem
/// rule: the same redact-then-truncate shape was independently needed in ≥2 crates (#1228,
/// #1239, #1240), so it lives here once rather than being reimplemented per-crate.
///
/// # Examples
///
/// ```
/// use deps_core::redact::redact_parse_error_for_log;
///
/// assert_eq!(
///     redact_parse_error_for_log(
///         "duplicate key: `https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x`"
///     ),
///     "duplicate key: `https://***@pkg.internal.corp/x`"
/// );
/// // Benign errors are left unchanged — the credential-shape gate does not fire on them.
/// assert_eq!(redact_parse_error_for_log("duplicate key: `serde`"), "duplicate key: `serde`");
/// ```
#[must_use]
#[expect(
    clippy::string_slice,
    reason = "`boundary` comes from `floor_char_boundary`, so the slice always lands on a char \
              boundary"
)]
pub fn redact_parse_error_for_log(raw: &str) -> std::borrow::Cow<'_, str> {
    let redacted = redact_declaration_key(raw);
    let text: std::borrow::Cow<'_, str> = if redacted == raw {
        std::borrow::Cow::Borrowed(raw)
    } else {
        std::borrow::Cow::Owned(redacted)
    };
    if text.len() <= MAX_PARSE_ERROR_LOG_BYTES {
        return text;
    }
    let boundary = text.floor_char_boundary(MAX_PARSE_ERROR_LOG_BYTES);
    // `raw.len()`, not `text.len()`: the annotation describes the original attacker-controlled
    // payload's size, which redaction must not misreport just because it happened to shorten
    // the visible text (#1228 M1).
    std::borrow::Cow::Owned(format!(
        "{}... ({} bytes total)",
        &text[..boundary],
        raw.len()
    ))
}

/// Redacts `e` via [`redact_parse_error_for_log`] and wraps the result as the boxed error
/// [`crate::error::DepsError::ParseError`]'s `source` field expects.
///
/// Centralizes the whole "redact, then wrap into an `io::Error`" step — not just the redaction
/// itself — as one call, `deps_core::redact::parse_error_source(&e)`, in place of
/// `Box::new(std::io::Error::other(redact_parse_error_for_log(&e.to_string())))` repeated at
/// each `toml_span`/`yaml-rust2` `map_err` site. A future ecosystem crate adding a new parse-error
/// site is forced through the safe path by construction, rather than being able to copy an old,
/// unfixed `Box::new(std::io::Error::other(e.to_string()))` from elsewhere and reintroduce #1240.
///
/// # Examples
///
/// ```
/// use deps_core::redact::parse_error_source;
///
/// let source = parse_error_source(&"duplicate key: `serde`");
/// assert_eq!(source.to_string(), "duplicate key: `serde`");
/// ```
#[must_use]
pub fn parse_error_source(e: &dyn std::fmt::Display) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::other(
        redact_parse_error_for_log(&e.to_string()).into_owned(),
    ))
}

/// The segment-bounded `@`/`:` scan shared by [`redact_declaration_key`] (decides whether a
/// non-URL label needs redacting at all) and [`is_credential_or_query_bearing`] (decides whether an
/// outbound value must be rejected outright) — extracted so the two callers can't drift apart
/// on what counts as "looks like a credential" (#1206).
///
/// See [`redact_declaration_key`]'s own doc for the exact segment/trim rule this implements.
#[expect(
    clippy::string_slice,
    reason = "`at` comes from `match_indices('@')` on ASCII '@' bytes, so every slice bound \
              always lands on a char boundary"
)]
fn has_credential_shape(key: &str) -> bool {
    let mut prev = 0;
    key.match_indices('@').any(|(at, _)| {
        let segment = &key[prev..at];
        prev = at + 1;
        segment_has_credential_colon(segment.trim_end_matches(':'))
    })
}

/// Whether `value` carries credential-shaped userinfo of its own, or an untrusted
/// query/fragment component that could hide one.
///
/// Detects, in order:
/// - a `?`/`#` anywhere in `value` (#1206 S2) — a query string is exactly where a token can
///   travel (`?token=...`, `?access_token=...`) without ever taking the `user:pass@host`
///   shape the checks below look for, and [`url_for_tracing`] already treats *any* query or
///   fragment as untrusted-by-default (it drops both unconditionally, per #866/#858) — this
///   function applies that same always-suspect rule to the reject-before-search decision, not
///   just to what gets logged afterward;
/// - for a real URL authority (`host()` is `Some`), whether [`redact_userinfo`] would change
///   `value` at all — not just a non-empty username/password on the authority itself. A
///   credential-shaped `user:pass@host` span can also sit *after* the authority, later in the
///   path (e.g. `https://mirror.example/redirect/user:pass@evil.com`, code-review round 1
///   #1206 finding 1): checking only `url.username()`/`url.password()` missed this, since that
///   pair only reflects the authority's own userinfo. Delegating to `redact_userinfo` reuses
///   its existing authority-then-tail scan instead of re-deriving it, and is deliberately
///   scoped to the `host().is_some()` case alone — see the over-rejection note below for why
///   this isn't applied unconditionally to every input;
/// - for text with no parseable URL structure (e.g. a `.package(url: "...")` literal with its
///   scheme already stripped before reaching a registry-search query), the same
///   segment-bounded credential-colon shape [`redact_declaration_key`]'s fallback scan uses
///   (`has_credential_shape`).
///
/// Unlike `is_authority_bearing_url`, this is a genuine credential-detection predicate, not
/// "does this parse as a URL at all" — an ordinary credential-free, query-free URL
/// (`https://host/path`) returns `false` here.
///
/// Narrower than [`url_for_tracing`]'s own redaction coverage in one specific way: a
/// scheme-stripped, colon-less, token-only userinfo (e.g. `ghp_TOKEN@host/path`, with no `:`
/// anywhere) is not flagged here, even though `url_for_tracing` would still redact it via
/// `find_token_prefix_at`'s prefix sniffing. Not widened to match: probe-testing found that
/// treating "the redactor would change this string" as the reject criterion false-positives on
/// ordinary non-credential input containing a bare `@` with no colon at all — a Maven
/// coordinate like `com.google.guava:guava` (no `@`, unaffected) is fine, but an SSH-style Git
/// remote like `git@github.com:apple/swift-nio.git` would trip a token-prefix-agnostic
/// widening. The `user:pass@`/`label:value@` colon-shaped case this function does catch covers
/// every shape in the actual #1206 repro family (a full `.package(url:)` literal, with or
/// without its scheme).
///
/// Conversely, delegating to `redact_userinfo` for the `host().is_some()` case inherits that
/// function's own documented over-redaction: a colon in the path with no `@` at all (e.g.
/// `https://10.0.0.1/v1/items:search`, a REST-style path segment, no credential involved) is
/// still flagged here, because `redact_userinfo` still rewrites it. Accepted per this module's
/// stated over-redact/over-reject-over-leak trade-off (the same one the `?`/`#` check above
/// already applies) — an occasional false-positive-rejected completion keystroke costs far less
/// than a missed credential leak, and this narrower delegation (scoped to values that already
/// parse as a real URL authority) is far more targeted than falling through to
/// `has_credential_shape` would be, which over-triggers on *any* `scheme://...@...` value purely
/// from the scheme's own leading colon (verified while fixing this finding: naively falling
/// through to `has_credential_shape` for every `host().is_some()` value flagged an ordinary
/// scoped-package-style path like `https://github.com/@babel/core` with no credential anywhere).
///
/// Intended as a reject-before-search gate (issue #1206): a value this function flags must
/// never reach an outbound registry-search query or an unredacted `tracing` field — a redacted
/// value is not a useful search term, so the caller should drop the request entirely rather
/// than redact-and-search.
///
/// # Examples
///
/// ```
/// use deps_core::redact::is_credential_or_query_bearing;
///
/// assert!(is_credential_or_query_bearing(
///     "https://user:hunter2@registry.example/simple"
/// ));
/// // Scheme already stripped by the caller (e.g. Swift's `.package(url:)` completion) — no
/// // longer parses as a URL, but still shows the same credential shape.
/// assert!(is_credential_or_query_bearing(
///     "deploy:AUDITSENTINEL0000@git.internal.corp/team/x.git"
/// ));
/// // A query string can carry a token with no userinfo shape at all.
/// assert!(is_credential_or_query_bearing(
///     "https://github.com/apple/swift-nio?token=SECRET"
/// ));
/// // A credential-shaped span after the authority, later in the path, is caught too.
/// assert!(is_credential_or_query_bearing(
///     "https://mirror.example/redirect/user:pass@evil.com"
/// ));
/// assert!(!is_credential_or_query_bearing("apple/swift-nio"));
/// assert!(!is_credential_or_query_bearing("https://registry.example/simple"));
/// ```
#[must_use]
pub fn is_credential_or_query_bearing(value: &str) -> bool {
    if value.contains(['?', '#']) {
        return true;
    }
    if let Ok(url) = url::Url::parse(value)
        && !url.cannot_be_a_base()
        && url.host().is_some()
    {
        return redact_userinfo(value) != value;
    }
    has_credential_shape(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #993 M5 (impl-critic on the first credential-shape fix): the carve-out used to inspect
    /// only the *last* `@` found by the old `find_credential_at`-based scan, so a trailing
    /// `label:@`-shaped decoy segment could shadow an earlier, real credential. The per-segment
    /// scan (`segment_has_credential_colon` on each `@`-delimited segment, independently) fixes
    /// this: every segment is judged on its own, so a decoy segment after the real credential
    /// can no longer suppress redaction of the one before it.
    #[test]
    fn redact_declaration_key_trailing_decoy_segment_does_not_shadow_earlier_credential() {
        assert_eq!(
            redact_declaration_key("source:user:hunter2@nuget.internal:@x"),
            "***@x"
        );
        assert_eq!(
            redact_declaration_key("source:user:hunter2@host/scope:@myorg"),
            "***@host/***@myorg"
        );
        assert_eq!(redact_declaration_key("named:user:ghp_SECRET@h:@"), "***@");
        for adversarial in [
            "source:user:hunter2@nuget.internal:@x",
            "source:user:hunter2@host/scope:@myorg",
            "named:user:ghp_SECRET@h:@",
            "source:user:hunter2@h@scope:@myorg",
        ] {
            assert!(
                !redact_declaration_key(adversarial).contains("hunter2")
                    && !redact_declaration_key(adversarial).contains("SECRET"),
                "credential in {adversarial:?} must not survive redaction"
            );
        }
    }

    #[test]
    fn redact_parse_error_for_log_redacts_credential_and_keeps_host() {
        let redacted = redact_parse_error_for_log(
            "duplicate key: `https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x`",
        );
        assert!(!redacted.contains("ghp_SUPERSECRETTOKEN123"));
        assert!(!redacted.contains("svcacct"));
        assert!(redacted.contains("pkg.internal.corp"));
    }

    #[test]
    fn redact_parse_error_for_log_leaves_benign_message_unchanged() {
        assert_eq!(
            redact_parse_error_for_log("duplicate key: `serde`"),
            "duplicate key: `serde`"
        );
    }

    /// #1240 (impl-critic S3 follow-up on the developer's first attempt): the original fixture
    /// placed the whole credential past [`MAX_PARSE_ERROR_LOG_BYTES`], so a truncate-first bug
    /// would have dropped it too — the ordering invariant went untested. This fixture instead
    /// straddles the cut: the secret token sits before the boundary, and the disambiguating `@`
    /// that `has_credential_shape` needs lands after it. A truncate-first implementation would
    /// see only the `@`-less prefix, never detect a credential, and emit the secret almost
    /// verbatim; redact-then-truncate (the correct order) sees the whole string, including the
    /// `@`, and redacts it before the cut ever happens.
    ///
    /// #1240 round 2 (impl-critic R2-M1): asserting on the *full* `"ghp_SUPERSECRETTOKEN123"` is
    /// not load-bearing on its own — the boundary cuts mid-token (at byte 200, one byte before
    /// the token's own end at byte 201), so even a truncate-first bug drops the trailing digits
    /// and that assertion passes under either ordering. `"SUPERSECRETTOKEN"` (no trailing
    /// digits) ends before the boundary, so it fully survives a buggy truncate-first prefix —
    /// only the correct redact-first order removes it, making this assertion actually gate the
    /// invariant, same as the `"svcacct"` one already did.
    #[test]
    fn redact_parse_error_for_log_redacts_before_truncating() {
        let raw = format!(
            "{}svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x",
            "x".repeat(170)
        );
        // Named `needle_end`/`at_sign_offset`, not `secret_*` — these are byte offsets into the
        // fixture, not the credential text itself, but CodeQL's cleartext-logging heuristic
        // flags on variable-name pattern, not on what the value actually holds.
        let needle_end = raw.find("SUPERSECRETTOKEN").unwrap() + "SUPERSECRETTOKEN".len();
        let at_sign_offset = raw.find('@').unwrap();
        assert!(
            needle_end < MAX_PARSE_ERROR_LOG_BYTES && at_sign_offset > MAX_PARSE_ERROR_LOG_BYTES,
            "fixture must straddle the truncation boundary: needle ends at {needle_end}, '@' at {at_sign_offset}, boundary {MAX_PARSE_ERROR_LOG_BYTES}"
        );

        let redacted = redact_parse_error_for_log(&raw);
        assert!(!redacted.contains("SUPERSECRETTOKEN"));
        assert!(!redacted.contains("svcacct"));
    }

    /// #1240 round 2 (impl-critic R2-M2): the truncation branch itself — including the
    /// original-vs-redacted length annotation rule (round 1 S2) — was only exercised via
    /// `deps_pypi::parser::truncate_for_log`'s inherited test, not directly in `deps-core`.
    /// Mirrors that test's fixture here so the rule stays covered even if the pypi wrapper is
    /// ever removed.
    #[test]
    fn redact_parse_error_for_log_truncation_annotation_reports_original_length() {
        let credential = "user:hunter2very-long-password-padding-to-cross-the-cap@";
        let host_and_path = "example.com/".repeat(20);
        let raw = format!("https://{credential}{host_and_path}");
        assert!(
            raw.len() > MAX_PARSE_ERROR_LOG_BYTES,
            "fixture must exceed the cap"
        );

        let redacted = redact_parse_error_for_log(&raw);
        assert!(!redacted.contains("hunter2"));
        assert!(
            redacted.contains(&format!("({} bytes total)", raw.len())),
            "byte count must reflect the original input length, not the (shorter, \
             post-redaction) visible text: {redacted:?}"
        );
    }

    /// #993 M6: the credential-shape gate cannot distinguish a real credential from a
    /// non-credential `label:text@text` key, so a free-text label containing an `@` (only
    /// realistically reachable via NuGet's unvalidated `NuGet.config` `<add key>` attribute) is
    /// redacted too, even though nothing in it is a password. Accepted per this module's
    /// over-redact-over-leak design; pinned here as a documented, intentional trade-off rather
    /// than an accidental regression.
    #[test]
    fn redact_declaration_key_over_redacts_non_credential_label_at_text_shape() {
        assert_eq!(
            redact_declaration_key("source:contoso@internal"),
            "***@internal"
        );
        assert_eq!(redact_declaration_key("named:my-index@v1"), "***@v1");
    }

    // --- is_credential_or_query_bearing (#1206) ---

    #[test]
    fn is_credential_or_query_bearing_detects_real_url_userinfo() {
        assert!(is_credential_or_query_bearing(
            "https://user:hunter2@registry.example/simple"
        ));
        assert!(is_credential_or_query_bearing(
            "https://tokenonly@registry.example"
        ));
    }

    /// The exact shape of issue #1206: Swift's completion strips the `https://github.com/`
    /// scheme off a `.package(url:)` literal before it becomes a search query, so a
    /// credential-bearing value no longer parses as a URL by the time this gate sees it.
    #[test]
    fn is_credential_or_query_bearing_detects_scheme_stripped_credential() {
        assert!(is_credential_or_query_bearing(
            "deploy:AUDITSENTINEL0000@git.internal.corp/team/x.git"
        ));
    }

    #[test]
    fn is_credential_or_query_bearing_false_for_ordinary_url() {
        assert!(!is_credential_or_query_bearing(
            "https://registry.example/simple"
        ));
    }

    #[test]
    fn is_credential_or_query_bearing_false_for_plain_package_name() {
        assert!(!is_credential_or_query_bearing("apple/swift-nio"));
        assert!(!is_credential_or_query_bearing("serde"));
    }

    /// A scoped npm-style name (`@scope/pkg`) must not false-positive: the segment before its
    /// only `@` is empty, so no credential-shaped `:` can be found in it.
    #[test]
    fn is_credential_or_query_bearing_false_for_scoped_package_name() {
        assert!(!is_credential_or_query_bearing("@babel/core"));
    }

    /// A Windows drive-letter colon (`c:/...`) must not be mistaken for credential shape,
    /// mirroring `redact_userinfo`'s own drive-letter carve-out.
    #[test]
    fn is_credential_or_query_bearing_false_for_drive_letter_colon() {
        assert!(!is_credential_or_query_bearing("c:/user@evil"));
    }

    /// #1206 S2: a query-string token has no `user:pass@` userinfo shape at all, so it must be
    /// caught by the `?`/`#` check rather than falling through to the credential-colon scan.
    #[test]
    fn is_credential_or_query_bearing_true_for_query_string_token() {
        assert!(is_credential_or_query_bearing(
            "https://github.com/apple/swift-nio?token=SECRET"
        ));
        assert!(is_credential_or_query_bearing(
            "apple/swift-nio?token=SECRET"
        ));
        assert!(is_credential_or_query_bearing("apple/swift-nio#fragment"));
    }

    /// #1206 M1: a Maven coordinate and an SSH-style Git remote must not false-positive —
    /// pinned here since a naive "the redactor would touch this string" widening (considered
    /// and rejected, see this function's own doc) would flag both.
    #[test]
    fn is_credential_or_query_bearing_false_for_maven_coordinate_and_ssh_remote() {
        assert!(!is_credential_or_query_bearing("com.google.guava:guava"));
        assert!(!is_credential_or_query_bearing(
            "git@github.com:apple/swift-nio.git"
        ));
    }

    /// Code-review round 1 finding 1: a credential-shaped span after a real URL authority —
    /// not in the authority's own userinfo — must still be caught, matching what
    /// `url_for_tracing` already redacts for the identical input.
    #[test]
    fn is_credential_or_query_bearing_true_for_credential_after_authority_in_path() {
        assert!(is_credential_or_query_bearing(
            "https://mirror.example/redirect/user:pass@evil.com"
        ));
    }

    /// A scoped-package-style path segment (`@babel/core`-shaped) appended to a clean URL
    /// authority must not false-positive purely from the scheme's own leading colon — the
    /// specific over-trigger a naive fallback to `has_credential_shape` would have introduced
    /// (see this function's own doc; caught while fixing the finding above).
    #[test]
    fn is_credential_or_query_bearing_false_for_scoped_package_path_after_authority() {
        assert!(!is_credential_or_query_bearing(
            "https://github.com/@babel/core"
        ));
    }

    /// Documented, accepted over-rejection (see this function's own doc): a REST-style path
    /// colon with no credential at all still gets rejected, because `redact_userinfo` itself
    /// still rewrites it. Pinned so a future change to this trade-off is a deliberate doc +
    /// test update, not a silent behavior drift.
    #[test]
    fn is_credential_or_query_bearing_true_for_rest_style_path_colon_no_credential() {
        assert!(is_credential_or_query_bearing(
            "https://10.0.0.1/v1/items:search"
        ));
    }

    /// #1209: `redact_declaration_key` is the primitive [`crate::PackageName::for_tracing`]
    /// and [`RedactedName`] build on to redact package/coordinate names before they reach a
    /// log or client-visible message. One genuine, legitimate name per ecosystem (from the
    /// security audit's live probe against all 14 ecosystems) must survive unredacted —
    /// otherwise every hover/completion/diagnostic for that ecosystem would render a mangled
    /// name.
    #[test]
    fn redact_declaration_key_leaves_every_ecosystems_legitimate_names_untouched() {
        for name in [
            "serde",                                            // Cargo
            "com.google.guava:guava",                           // Maven/Gradle
            "org.springframework.boot:spring-boot-starter-web", // Maven/Gradle
            "@types/node",                                      // npm
            "@babel/core",                                      // npm
            "jsr:@std/path",                                    // Deno
            "npm:@scope/pkg",                                   // Deno
            "requests",                                         // PyPI
            "github.com/gin-gonic/gin",                         // Go
            "gopkg.in/yaml.v3",                                 // Go
            "rails",                                            // Bundler
            "path",                                             // Dart
            "git@github.com:apple/swift-nio.git",               // Swift
            "monolog/monolog",                                  // Composer
            "Newtonsoft.Json",                                  // NuGet
            "actions/checkout",                                 // GitHub Actions
            "gitlab.com/components/sast",                       // GitLab CI
            "ghcr.io/owner/image@sha256:abcdef",                // GitLab CI (component ref)
            "com.example:${project.version}",                   // Maven (unresolved property)
            "alternate registry (not registered)",              // shared fallback label
        ] {
            assert_eq!(
                redact_declaration_key(name),
                name,
                "legitimate name {name:?} must survive redaction unchanged"
            );
        }
    }

    /// #1209 M2 (impl-critic follow-up): `redact_declaration_key` cannot distinguish a real
    /// `label:value@suffix`-shaped name from a genuine credential — the same structural
    /// ambiguity [`redact_declaration_key`]'s own doc already calls out. No current ecosystem
    /// emits this shape in a `PackageName` (Deno keeps the version out of the name —
    /// `deps_deno::specifier::ParsedSpecifier`'s `name` field never carries a trailing
    /// `@version`), so this is not a live bug — but since [`RedactedName`] now feeds
    /// [`crate::DepsError::PackageNotFound`]'s `Display`, which reaches a `window/showMessage`
    /// toast, a future ecosystem emitting this shape would silently over-redact a legitimate
    /// name in a user-visible message. This test documents the known limitation explicitly
    /// (asserting the *actual*, over-redacting behavior) rather than leaving it as a silent
    /// gap — a change to any of these outcomes should be a deliberate, reviewed one.
    #[test]
    fn redact_declaration_key_over_redacts_documented_label_value_at_suffix_shapes() {
        assert_eq!(redact_declaration_key("npm:express@4.18.2"), "***@4.18.2");
        assert_eq!(
            redact_declaration_key("com.example:artifact@1.0"),
            "***@1.0"
        );
        assert_eq!(
            redact_declaration_key("alpine:3.18@sha256:abc"),
            "***@sha256:***"
        );
        assert_eq!(
            redact_declaration_key("ghcr.io/owner/image:1.2.3@sha256:abcdef"),
            "ghcr.io/owner/image:***"
        );
    }

    /// Critic follow-up M1 (#1242, #1246): `sanitize_invisible` covers `Cc`/`Cf`, but U+2028
    /// LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are neither category — both are line
    /// terminators for JS/`eval` consumers of `--format json` output and are treated as
    /// breaks by some editor renderers, so they must be sanitized too.
    #[test]
    fn sanitize_invisible_replaces_line_and_paragraph_separators() {
        assert_eq!(
            sanitize_invisible("a\u{2028}b\u{2029}c"),
            "a b c",
            "U+2028/U+2029 must not survive sanitize_invisible"
        );
    }

    #[test]
    fn sanitize_invisible_borrows_when_nothing_needs_sanitizing() {
        assert!(matches!(
            sanitize_invisible("com.google.guava:guava"),
            std::borrow::Cow::Borrowed(_)
        ));
    }
}
