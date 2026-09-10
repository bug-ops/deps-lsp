//! Shared scan-budget constants for a bounded `quick-xml` event loop over a remote,
//! registry-generated XML response (#698).
//!
//! `deps-gradle::license`'s POM-parsing loop already bounds itself with a private
//! entry-count + `buffer_position()` pair (issue #690/#694); this module exists so a
//! second remote-XML consumer — `deps-maven::registry::parse_metadata_xml` — shares the
//! same budget shape instead of inventing its own. It deliberately does not wrap
//! `quick_xml::Reader` itself: the workspace's XML consumers split between
//! `Reader::from_str` + `read_event()` and `Reader::from_reader` + `read_event_into(&mut
//! buf)`, and at least one (`deps-nuget::parser`) relies on the zero-copy borrow that
//! `from_str` gives deliberately — a shared wrapper would have to fight that for no
//! security gain. Each consumer keeps its own reader setup and calls [`exhausted`] as a
//! loop-top guard.

/// Entry-count threshold at which a bounded XML scan is rejected as exhausted.
///
/// Once `<version>` (or equivalent per-entry) elements retained by the scan reach this
/// count, [`exhausted`] returns `true` and the caller returns `Err` — so the largest
/// document actually *accepted* holds `MAX_METADATA_VERSIONS - 1` entries, not this count
/// itself. Real Maven Central artifacts top out around 3-4k versions for even the
/// longest-lived groups, so this leaves generous headroom above any legitimate document.
pub const MAX_METADATA_VERSIONS: usize = 8192;

/// Hard cap, in bytes of `reader.buffer_position()`, on how far into a document a bounded XML scan will read.
///
/// A real `maven-metadata.xml` with a few thousand versions is on the order of 100 KB, so
/// this leaves generous headroom while still bounding a hostile or pathological response.
pub const MAX_METADATA_BYTES_SCANNED: usize = 8 * 1024 * 1024;

/// Whether a bounded XML scan has exceeded its budget and must stop.
///
/// Checked at the top of the read loop, before processing the next event — mirrors the
/// shape-independent guard `deps-gradle::license::parse_pom_licenses` already uses: it
/// advances on every event regardless of what it is, so it cannot be starved by a
/// document that simply omits the element type a narrower, shape-keyed counter would be
/// watching for.
///
/// Thin wrapper around [`exhausted_with`] using this module's own
/// [`MAX_METADATA_VERSIONS`]/[`MAX_METADATA_BYTES_SCANNED`] budget — use `exhausted_with`
/// directly for a consumer with its own, differently-sized budget (e.g.
/// `deps-gradle::license`'s POM scan, issue #725).
///
/// # Examples
///
/// ```
/// use deps_core::xml_bounds::{exhausted, MAX_METADATA_VERSIONS};
///
/// assert!(!exhausted(0, 0));
/// assert!(exhausted(MAX_METADATA_VERSIONS, 0));
/// ```
#[must_use]
pub fn exhausted(entries: usize, buffer_position: u64) -> bool {
    exhausted_with(
        entries,
        buffer_position,
        MAX_METADATA_VERSIONS,
        MAX_METADATA_BYTES_SCANNED,
    )
}

/// Whether a bounded XML scan has exceeded a caller-supplied entry/byte budget.
///
/// Same shape-independent check as [`exhausted`], parameterized so a consumer with its
/// own budget (e.g. a POM's license-entry cap, distinct from a `maven-metadata.xml`
/// version-list cap) can share this conversion instead of keeping a private, lossy `as
/// usize` copy of it (issue #725). The `usize::try_from(..).unwrap_or(usize::MAX)`
/// fail-closed path only differs from a lossy `as usize` cast on a target where `usize`
/// is narrower than `u64` — i.e. a 32-bit target; every target this workspace's CI
/// actually builds for (see `.github/workflows/ci.yml`'s `cross-check` matrix) is
/// 64-bit, where the two are equivalent. This is 32-bit-target hardening and DRY
/// consolidation of the budget check, not a fix for a bug reachable on a supported
/// target today.
///
/// # Examples
///
/// ```
/// use deps_core::xml_bounds::exhausted_with;
///
/// assert!(!exhausted_with(0, 0, 64, 1024));
/// assert!(exhausted_with(64, 0, 64, 1024));
/// assert!(exhausted_with(0, 2048, 64, 1024));
/// ```
#[must_use]
pub fn exhausted_with(
    entries: usize,
    buffer_position: u64,
    max_entries: usize,
    max_bytes: usize,
) -> bool {
    entries >= max_entries
        // Fails closed: a `buffer_position` too large to fit `usize` (only possible on a
        // 32-bit target) is treated as exceeding the cap rather than silently wrapping.
        || usize::try_from(buffer_position).unwrap_or(usize::MAX) >= max_bytes
}

#[cfg(test)]
mod tests {
    use super::{MAX_METADATA_BYTES_SCANNED, MAX_METADATA_VERSIONS, exhausted, exhausted_with};

    #[test]
    fn exhausted_delegates_to_exhausted_with_using_module_constants() {
        assert!(!exhausted(0, 0));
        assert!(exhausted(MAX_METADATA_VERSIONS, 0));
        assert!(exhausted(0, MAX_METADATA_BYTES_SCANNED as u64));
    }

    #[test]
    fn exhausted_with_respects_caller_supplied_budget() {
        assert!(!exhausted_with(0, 0, 64, 1024));
        assert!(exhausted_with(64, 0, 64, 1024));
        assert!(exhausted_with(0, 1024, 64, 1024));
        assert!(!exhausted_with(0, 1023, 64, 1024));
    }

    /// A `buffer_position` that overflows a 32-bit `usize` must fail closed — treated as
    /// exceeding the cap — rather than wrapping via a lossy `as usize` cast (the pre-#725
    /// bug). `u32::MAX + 1` is the smallest such value, and only fails to fit `usize` on
    /// a genuine 32-bit target, so this test is gated to actually distinguish the fix
    /// from the bug it replaces — asserting it on 64-bit (where the conversion always
    /// succeeds and the two implementations agree) would be a vacuous, always-passing
    /// test that proves nothing about the fix.
    #[test]
    #[cfg(target_pointer_width = "32")]
    fn exhausted_with_fails_closed_on_oversized_buffer_position() {
        let overflows_32_bit_usize = u64::from(u32::MAX) + 1;
        assert!(exhausted_with(
            0,
            overflows_32_bit_usize,
            usize::MAX,
            usize::MAX
        ));
    }
}
