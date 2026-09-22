//! Client-visible-text sanitization shared by this crate's warning and report sinks (#1299).
//!
//! Every attacker-controlled path this crate can print — a manifest path, a config path, a
//! walk root, or a path embedded in a third-party error's own `Display` output — is
//! neutralized at the boundary where it enters a `deps-cli`-owned type ([`crate::report`]'s
//! `CheckFinding`, [`crate::walk`]'s `WalkOutcome`/`DiscoveredManifest`), not decided anew at
//! each `eprintln!`/format call site. Per-call-site sanitization was tried first (#1299) and
//! missed two sites on the first pass — the omission class this module exists to make
//! structurally impossible instead of just individually fixed (#1299 round 2).

use deps_core::redact::sanitize_invisible;
use std::path::{Path, PathBuf};

/// Sanitizes `path` for any client-visible path sink.
///
/// Neutralizes every raw ANSI escape byte or Unicode control/format/line/paragraph-separator
/// character (in particular a bidi override such as U+202E, the Trojan Source /
/// CVE-2021-42574 vector) a crafted directory or file name could embed, using
/// [`deps_core::redact::sanitize_invisible`]. Deliberately does not truncate — unlike a
/// package name or requirement, a legitimate path has no natural short bound, and truncating
/// it would make the reported location misleading rather than just shorter.
#[must_use]
pub(crate) fn sanitize_path_for_display(path: &Path) -> PathBuf {
    PathBuf::from(sanitize_invisible(&path.to_string_lossy()).into_owned())
}

/// Sanitizes an already-formatted client-visible message.
///
/// For a sink that cannot isolate the path substring before formatting — chiefly a
/// third-party error's own `Display` output (e.g. `ignore::Error`, whose message embeds the
/// offending path verbatim) — sanitizing the whole message has the same effect as sanitizing
/// just the embedded path: the character classes [`sanitize_invisible`] strips (raw ANSI
/// escapes, bidi/invisible format characters) never legitimately occur in this crate's own
/// fixed English message text, so sweeping the full string is a no-op on everything except
/// the untrusted path fragment.
#[must_use]
pub(crate) fn sanitize_message_for_display(message: &str) -> String {
    sanitize_invisible(message).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_path_for_display_strips_ansi_and_bidi_but_keeps_legitimate_segments() {
        let path = Path::new("src/\u{202E}\x1Bsneaky/Cargo.toml");
        let sanitized = sanitize_path_for_display(path)
            .to_string_lossy()
            .into_owned();
        assert!(!sanitized.contains('\u{202E}'));
        assert!(!sanitized.contains('\x1B'));
        assert!(sanitized.contains("src"));
        assert!(sanitized.contains("Cargo.toml"));
    }

    #[test]
    fn sanitize_message_for_display_strips_a_payload_embedded_by_a_third_party_error() {
        let message = format!(
            "IO error for operation on {}locked: Permission denied (os error 13)",
            "ev\u{202E}il\x1B[31m/"
        );
        let sanitized = sanitize_message_for_display(&message);
        assert!(!sanitized.contains('\u{202E}'));
        assert!(!sanitized.contains('\x1B'));
        assert!(sanitized.contains("Permission denied"));
    }
}
