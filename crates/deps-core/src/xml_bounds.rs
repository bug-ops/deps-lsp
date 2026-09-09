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
    entries >= MAX_METADATA_VERSIONS
        // Fails closed: a `buffer_position` too large to fit `usize` (only possible on a
        // 32-bit target) is treated as exceeding the cap rather than silently wrapping.
        || usize::try_from(buffer_position).unwrap_or(usize::MAX) >= MAX_METADATA_BYTES_SCANNED
}
