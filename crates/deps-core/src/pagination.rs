//! Generic paginated-fetch loop for a git-tags-shaped REST API returning `per_page=100` pages.
//!
//! Extracted from [`crate::github::paginate_tags`] so a second provider (GitLab CI's
//! `/repository/tags` and `/releases` endpoints) can share the exact
//! concurrency/ordering/error-mapping behavior instead of forking it.
//! [`crate::github::paginate_tags`] is now a thin delegation to [`paginate_pages`].

use crate::error::Result;
use bytes::Bytes;
use std::future::Future;

/// Number of pages fetched concurrently per batch, once page 1 is confirmed full.
///
/// See [`paginate_pages`]'s doc comment for why page 1 is always fetched alone first.
const CONCURRENCY: usize = 5;

/// Returns `true` when a fetched page came back full (`per_page=100` entries), meaning a
/// subsequent page may exist and should be fetched too. A page with fewer entries is
/// necessarily the last one.
#[must_use]
pub const fn page_has_more(page_len: usize) -> bool {
    page_len >= 100
}

/// Logs a warning when pagination for `name` stops at `max_pages` while `provider` still had
/// more pages available (`page_has_more(page_len)`).
///
/// Without this, hitting the safety ceiling on a pathological repo/project is
/// indistinguishable in logs from "there is genuinely no matching version" — this makes
/// truncation diagnosable. `provider` names the upstream API (`"GitHub"`, `"GitLab"`);
/// `ecosystem` names the caller ecosystem (e.g. `"Swift"`, `"GitHub Actions"`, `"GitLab
/// CI"`); `noun` names what is being paginated (`"tags"`, `"releases"`) in the warning text
/// — a caller pagintating a non-tags endpoint (e.g. GitLab CI's `/releases`) must not have
/// its warning hardcode "tags" pagination.
pub fn warn_if_pagination_truncated(
    provider: &str,
    ecosystem: &str,
    noun: &str,
    name: &str,
    page: u32,
    page_len: usize,
    max_pages: u32,
) {
    if page == max_pages && page_has_more(page_len) {
        tracing::warn!(
            package = name,
            pages_fetched = max_pages,
            "{ecosystem} {noun} pagination for '{name}' stopped at the {max_pages}-page cap \
             while {provider} reported more pages available; the fetched version list may be \
             truncated"
        );
    }
}

/// Drives a paginated-fetch loop against a `per_page=100`-shaped REST endpoint: page 1
/// alone, then subsequent pages in batches of up to `CONCURRENCY` pages.
///
/// Page 1 is always fetched by itself before any batching starts, for two reasons: most
/// repos/projects fit in one page, so this keeps the common case at exactly the one request
/// it took before this function gained concurrency; and an error on page 1 (bad auth,
/// tripped rate limit, unknown project) is surfaced from a single request instead of fanning
/// a doomed request out to `CONCURRENCY` pages at once.
///
/// Once page 1 is confirmed full, pages 2+ are fetched in batches of `CONCURRENCY`,
/// stopping once a partial/empty page is seen or `max_pages` is reached. Pages within a
/// batch are fetched concurrently, but always processed in page order — the pages
/// dispatched *after* the batch's partial page are simply discarded once found, not
/// avoided, since by the time a batch's first result comes back the rest of that batch's
/// requests are already in flight and cannot be un-sent. This bounds, but does not
/// eliminate, extra requests: at most `CONCURRENCY - 1` pages beyond the true last page may
/// be fetched and discarded, only when that last page doesn't land on a batch boundary.
/// A caller that dedups "first item wins" on page order depends on out-of-order *processing*
/// never happening — hence ordered `buffered`, not `buffer_unordered`.
///
/// `provider`/`ecosystem`/`noun`/`name` are forwarded to [`warn_if_pagination_truncated`] to
/// name the API, the caller, and what is being paginated in the truncation warning.
///
/// # Errors
///
/// Propagates the first error seen among `fetch_page`'s results (page 1's own error, or the
/// first in page order within a batch — any other in-flight futures in that batch are
/// dropped), or the error from `parse_page` when a page's body cannot be parsed.
pub async fn paginate_pages<T, F, Fut, P>(
    provider: &str,
    ecosystem: &str,
    noun: &str,
    name: &str,
    max_pages: u32,
    mut fetch_page: F,
    mut parse_page: P,
) -> Result<Vec<T>>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<Bytes>>,
    P: FnMut(&Bytes) -> Result<Vec<T>>,
{
    use futures::stream::{self, StreamExt};

    let mut items = Vec::new();

    let first_page = fetch_page(1).await?;
    let first_items = parse_page(&first_page)?;
    let first_page_len = first_items.len();
    items.extend(first_items);
    if !page_has_more(first_page_len) {
        // No call to `warn_if_pagination_truncated` here: it only fires at
        // `page == max_pages`, which page 1 can never equal since `max_pages > 1`.
        return Ok(items);
    }

    let mut page = 2u32;
    'batches: while page <= max_pages {
        let batch_end = (page + CONCURRENCY as u32 - 1).min(max_pages);
        let mut stream = stream::iter(page..=batch_end)
            .map(&mut fetch_page)
            .buffered(CONCURRENCY);

        let mut current_page = page;
        while let Some(data) = stream.next().await {
            let page_items = parse_page(&data?)?;
            let page_len = page_items.len();
            items.extend(page_items);
            if !page_has_more(page_len) {
                break 'batches;
            }
            warn_if_pagination_truncated(
                provider,
                ecosystem,
                noun,
                name,
                current_page,
                page_len,
                max_pages,
            );
            current_page += 1;
        }
        page = batch_end + 1;
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::capture_tracing_output_async;

    #[test]
    fn test_page_has_more_full_page_continues() {
        assert!(page_has_more(100));
    }

    #[test]
    fn test_page_has_more_partial_page_stops() {
        assert!(!page_has_more(99));
        assert!(!page_has_more(0));
    }

    /// Regression for #472 critic M8 (GitLab CI plan): the warning must key its fire
    /// condition and its `pages_fetched` field off the *passed* `max_pages`, not a
    /// hardcoded constant — a caller with a cap other than 30 must still warn on its own
    /// last page and never warn early.
    #[tokio::test]
    async fn test_warn_if_pagination_truncated_uses_passed_max_pages_not_a_constant() {
        let output = capture_tracing_output_async(async {
            warn_if_pagination_truncated("GitLab", "GitLab CI", "tags", "org/repo", 3, 100, 3);
        })
        .await;
        assert!(output.contains("org/repo"), "output was: {output}");
        assert!(output.contains("GitLab"), "output was: {output}");
        assert!(output.contains('3'), "output was: {output}");

        let silent = capture_tracing_output_async(async {
            warn_if_pagination_truncated("GitLab", "GitLab CI", "tags", "org/repo", 2, 100, 3);
        })
        .await;
        assert!(
            silent.is_empty(),
            "must not warn below the passed cap: {silent}"
        );
    }

    fn page_json(count: usize) -> Bytes {
        let entries: Vec<String> = (0..count).map(|i| format!(r#"{{"n":{i}}}"#)).collect();
        Bytes::from(format!("[{}]", entries.join(",")))
    }

    fn parse_page(data: &Bytes) -> Result<Vec<u32>> {
        let value: serde_json::Value = crate::parser::parse_json_checked(data)?;
        Ok(value
            .as_array()
            .map(|arr| (0..arr.len() as u32).collect())
            .unwrap_or_default())
    }

    #[tokio::test]
    async fn test_paginate_pages_single_page_fetches_exactly_once() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = AtomicU32::new(0);
        let result = paginate_pages(
            "GitLab",
            "GitLab CI",
            "tags",
            "org/repo",
            30,
            |page| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    match page {
                        1 => Ok(page_json(42)),
                        _ => panic!("page {page} must not be fetched"),
                    }
                }
            },
            parse_page,
        )
        .await
        .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(result.len(), 42);
    }

    #[tokio::test]
    async fn test_paginate_pages_stops_after_partial_page_at_custom_cap() {
        let result = paginate_pages(
            "GitLab",
            "GitLab CI",
            "tags",
            "org/repo",
            5,
            |page| async move {
                match page {
                    1 => Ok(page_json(100)),
                    2..=5 => Ok(page_json(10)),
                    _ => panic!("page {page} must not be fetched beyond the 5-page cap"),
                }
            },
            parse_page,
        )
        .await
        .unwrap();

        assert_eq!(result.len(), 110);
    }
}
