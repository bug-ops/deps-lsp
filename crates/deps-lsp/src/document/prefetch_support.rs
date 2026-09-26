//! Shared background-prefetch scaffolding for `document::gossip_prefetch` and
//! `document::typosquat` (issue #1476 finding #3).
//!
//! [`run_gossip_prefetch`](super::gossip_prefetch::run_gossip_prefetch) and
//! [`run_typosquat_prefetch`](super::typosquat::run_typosquat_prefetch) both (1) snapshot a
//! value from the currently open document, bailing out if the document or its parse result is
//! missing, then (2) run their own network fetch bounded by `fetch_timeout_secs` capped at a
//! per-prefetch ceiling. Those two shapes are identical across both call sites and are
//! centralized here; the merge/staleness decision that follows each fetch differs enough
//! between them (filter-and-keep vs. whole-drop on a mid-fetch edit, plus typosquat's extra
//! debounce-gate cleanup on a timeout/incomplete result) that it stays with each caller.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tower_lsp_server::ls_types::Uri;

use super::state::{DocumentState, ServerState};

/// Snapshots a value derived from `uri`'s currently open document and its parse result via
/// `snapshot`, or returns `None` if the document is not open or has no parse result yet.
pub(super) fn document_prefetch_snapshot<S>(
    state: &ServerState,
    uri: &Uri,
    snapshot: impl FnOnce(&DocumentState, &Arc<dyn deps_core::ParseResult>) -> S,
) -> Option<(S, Arc<dyn deps_core::ParseResult>)> {
    state
        .with_document(uri, |doc| {
            let parse_result = doc.parse_result_arc()?;
            Some((snapshot(doc, &parse_result), parse_result))
        })
        .flatten()
}

/// Runs `fetch` bounded by `fetch_timeout_secs`, capped at `timeout_ceiling_secs`. Returns
/// `None` after logging `"{label} pre-fetch timed out"` on timeout.
pub(super) async fn bounded_prefetch_fetch<T>(
    fetch_timeout_secs: u64,
    timeout_ceiling_secs: u64,
    label: &str,
    fetch: impl Future<Output = T>,
) -> Option<T> {
    let timeout_duration = Duration::from_secs(fetch_timeout_secs.min(timeout_ceiling_secs));
    match tokio::time::timeout(timeout_duration, fetch).await {
        Ok(value) => Some(value),
        Err(_) => {
            tracing::debug!("{label} pre-fetch timed out");
            None
        }
    }
}
