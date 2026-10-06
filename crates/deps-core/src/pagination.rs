//! Generic paginated-fetch loop for a git-tags-shaped REST API returning `per_page=100` pages.
//!
//! Extracted from [`crate::github::paginate_tags`] so a second provider (GitLab CI's
//! `/repository/tags` and `/releases` endpoints) can share the exact
//! concurrency/ordering/error-mapping behavior instead of forking it.
//! [`crate::github::paginate_tags`] is now a thin delegation to [`paginate_pages`].

use crate::EcosystemId;
use crate::error::Result;
use bytes::Bytes;
use std::future::Future;

/// Whether a paginated list reached its true end or was cut off at the page cap.
///
/// Absence-driven consumers (e.g. "this SHA is not any release tag") must only trust a
/// [`ListCoverage::Complete`] list; presence-driven consumers may use either.
///
/// # Examples
///
/// ```
/// use deps_core::pagination::ListCoverage;
///
/// assert_eq!(ListCoverage::default(), ListCoverage::Complete);
/// assert_ne!(ListCoverage::Truncated, ListCoverage::Complete);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ListCoverage {
    /// The last fetched page was partial, so no entries are missing.
    #[default]
    Complete,
    /// Fetching stopped at the page cap while more pages may exist.
    Truncated,
}

impl ListCoverage {
    /// Classifies a single-response list from its raw `Link` header (RFC 8288): [`Self::Truncated`]
    /// iff some link-value carries a `rel` token equal to `next` (case-insensitive, quoted or
    /// unquoted, possibly among several space-separated tokens), [`Self::Complete`] otherwise.
    ///
    /// The link target is never read or dereferenced; only the relation types are inspected.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::pagination::ListCoverage;
    ///
    /// let next = Some("<https://r.example/p?page=2>; rel=\"next\"");
    /// assert_eq!(ListCoverage::from_link_header(next), ListCoverage::Truncated);
    /// let canonical = Some("<https://r.example/p>; rel=\"canonical\"");
    /// assert_eq!(ListCoverage::from_link_header(canonical), ListCoverage::Complete);
    /// assert_eq!(ListCoverage::from_link_header(None), ListCoverage::Complete);
    /// ```
    #[must_use]
    pub fn from_link_header(link: Option<&str>) -> Self {
        if link.is_some_and(|header| !next_targets(header).is_empty()) {
            Self::Truncated
        } else {
            Self::Complete
        }
    }
}

/// What a response's `Link` header says about the page after the current one.
///
/// # Examples
///
/// ```
/// use deps_core::pagination::{NextPage, next_page};
/// use url::Url;
///
/// let current = Url::parse("https://r.example/api/acme/net").unwrap();
/// let trusted = Url::parse("https://r.example/api/").unwrap();
/// let link = Some("<https://r.example/api/acme/net?page=2>; rel=\"next\"");
/// assert_eq!(
///     next_page(&current, link, &trusted),
///     NextPage::Next(Url::parse("https://r.example/api/acme/net?page=2").unwrap())
/// );
/// assert_eq!(next_page(&current, None, &trusted), NextPage::Last);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextPage {
    /// No `rel="next"` link: the current page is the last one.
    Last,
    /// The single, validated URL of the next page.
    Next(url::Url),
    /// A `rel="next"` link exists but cannot be followed safely.
    Rejected,
}

/// Resolves the next page of a paginated list from a raw `Link` header (RFC 8288).
///
/// Exactly one distinct `rel="next"` target may exist across all link-values; the target is
/// resolved against `current` and must carry no userinfo and stay under the `trusted` prefix
/// (see [`crate::net_policy::is_trusted_prefix`]). Anything else, including an empty or
/// unparsable target, is [`NextPage::Rejected`] so the caller never follows a link that could
/// leave the registry or mix lists.
#[must_use]
pub fn next_page(current: &url::Url, link: Option<&str>, trusted: &url::Url) -> NextPage {
    let Some(header) = link else {
        return NextPage::Last;
    };
    let targets = next_targets(header);
    let Some((first, rest)) = targets.split_first() else {
        return NextPage::Last;
    };
    if first.is_empty() || rest.iter().any(|other| other != first) {
        return NextPage::Rejected;
    }
    match current.join(first) {
        Ok(next)
            if next.username().is_empty()
                && next.password().is_none()
                && crate::net_policy::is_trusted_prefix(&next, trusted) =>
        {
            NextPage::Next(next)
        }
        Ok(_) | Err(_) => NextPage::Rejected,
    }
}

/// The raw `<...>` targets of every link-value in `header` whose `rel` parameter contains the
/// `next` token; a malformed target yields an empty string.
fn next_targets(header: &str) -> Vec<&str> {
    split_outside_quotes(header, ',')
        .filter_map(|link_value| {
            let mut parts = split_outside_quotes(link_value, ';');
            let target = parts.next()?;
            parts.any(is_next_rel).then(|| {
                target
                    .trim()
                    .strip_circumfix('<', '>')
                    .map_or("", str::trim)
            })
        })
        .collect()
}

/// Whether a link parameter is `rel` with the `next` token among its values.
fn is_next_rel(param: &str) -> bool {
    let Some((name, value)) = param.split_once('=') else {
        return false;
    };
    name.trim().eq_ignore_ascii_case("rel")
        && value
            .trim()
            .trim_matches('"')
            .split_ascii_whitespace()
            .any(|token| token.eq_ignore_ascii_case("next"))
}

/// Splits `input` on `separator`, ignoring separators inside double quotes (honouring `\"`
/// quoted-pairs) or a `<...>` target.
fn split_outside_quotes(input: &str, separator: char) -> impl Iterator<Item = &str> {
    let mut in_quotes = false;
    let mut in_target = false;
    let mut start = 0;
    let mut pieces = Vec::new();
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if std::mem::take(&mut escaped) {
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' if !in_target => in_quotes = !in_quotes,
            '<' if !in_quotes => in_target = true,
            '>' if !in_quotes => in_target = false,
            c if c == separator && !in_quotes && !in_target => {
                pieces.extend(input.get(start..idx));
                start = idx + c.len_utf8();
            }
            _ => {}
        }
    }
    pieces.extend(input.get(start..));
    pieces.into_iter()
}

/// Items collected by [`paginate_pages`] together with how completely they cover the list.
///
/// # Examples
///
/// ```
/// use deps_core::pagination::{ListCoverage, Paginated};
///
/// fn absent_means_missing(tags: &Paginated<String>, wanted: &str) -> bool {
///     tags.coverage == ListCoverage::Complete && !tags.items.iter().any(|t| t == wanted)
/// }
///
/// let page = Paginated::new(vec!["v1".to_string()], ListCoverage::Complete);
/// assert!(absent_means_missing(&page, "v2"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Paginated<T> {
    /// Items in page order.
    pub items: Vec<T>,
    /// Whether `items` is the whole list.
    pub coverage: ListCoverage,
}

impl<T> Paginated<T> {
    /// Bundles `items` with the `coverage` of the list they were taken from.
    ///
    /// Needed because the struct is `#[non_exhaustive]`: other crates cannot use a literal.
    #[must_use]
    pub const fn new(items: Vec<T>, coverage: ListCoverage) -> Self {
        Self { items, coverage }
    }
}

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
/// truncation diagnosable. `provider` names the upstream API (`"GitHub"`, `"GitLab"`) — a
/// human-facing display name with no [`EcosystemId`] equivalent, so it stays a plain
/// `&'static str`. `ecosystem` names the caller ecosystem and is logged as a structured
/// `%ecosystem` field, matching every other ecosystem-labeled `tracing` call in this crate
/// (#1425); `noun` names what is being paginated (`"tags"`, `"releases"`) in the warning text
/// — a caller pagintating a non-tags endpoint (e.g. GitLab CI's `/releases`) must not have
/// its warning hardcode "tags" pagination.
pub fn warn_if_pagination_truncated(
    provider: &str,
    ecosystem: EcosystemId,
    noun: &str,
    name: &str,
    page: u32,
    page_len: usize,
    max_pages: u32,
) {
    if page == max_pages && page_has_more(page_len) {
        let name = crate::redact::redact_declaration_key(name);
        tracing::warn!(
            package = %name,
            pages_fetched = max_pages,
            %ecosystem,
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
///
/// The result is [`ListCoverage::Truncated`] when `max_pages` is exhausted without seeing a
/// partial page (conservatively including a list of exactly `max_pages * 100` entries).
pub async fn paginate_pages<T, F, Fut, P>(
    provider: &str,
    ecosystem: EcosystemId,
    noun: &str,
    name: &str,
    max_pages: u32,
    mut fetch_page: F,
    mut parse_page: P,
) -> Result<Paginated<T>>
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
        return Ok(Paginated {
            items,
            coverage: ListCoverage::Complete,
        });
    }

    let mut coverage = ListCoverage::Truncated;
    let mut page = 2u32;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "CONCURRENCY is a small hardcoded constant (5), never close to u32::MAX"
    )]
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
                coverage = ListCoverage::Complete;
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
    Ok(Paginated { items, coverage })
}

#[cfg(test)]
#[expect(
    clippy::cast_possible_truncation,
    reason = "#673: fixed test-fixture lengths cast to u32 never approach truncation range"
)]
mod tests {
    use super::*;
    #[cfg(feature = "test-util")]
    use crate::test_util::capture_tracing_output_async;

    #[test]
    fn from_link_header_grammar() {
        let truncated = [
            r#"<https://r/p?page=2>; rel="next""#,
            "<https://r/p?page=2>; rel=next",
            r#"<https://r/p?page=2>; rel="Next""#,
            r#"<https://r/p?page=2>; REL="NEXT""#,
            r#"<https://r/p?page=2>; rel="last next""#,
            r#"<https://r/p>; rel="latest-version", <https://r/p?page=2>; rel="next""#,
            r#"<https://r/p?a=1,2>; title="x, y"; rel="next""#,
            r#"<https://r/p>; title="a\", <https://r/q>; rel=\"x"; rel="next""#,
            r#"<https://r/p>; title="a \" b"; rel="next""#,
        ];
        for header in truncated {
            assert_eq!(
                ListCoverage::from_link_header(Some(header)),
                ListCoverage::Truncated,
                "{header}"
            );
        }
        let complete = [
            r#"<https://r/p>; rel="latest-version""#,
            r#"<https://r/p>; rel="canonical""#,
            r#"<https://r/next>; rel="nextish""#,
            r#"<https://r/p>; title="x \"; rel=next\" y""#,
            r#"<https://r/p?rel=next>; title="rel=next""#,
            "",
        ];
        for header in complete {
            assert_eq!(
                ListCoverage::from_link_header(Some(header)),
                ListCoverage::Complete,
                "{header}"
            );
        }
        assert_eq!(ListCoverage::from_link_header(None), ListCoverage::Complete);
    }

    fn next(current: &str, link: Option<&str>, trusted: &str) -> NextPage {
        next_page(
            &url::Url::parse(current).unwrap(),
            link,
            &url::Url::parse(trusted).unwrap(),
        )
    }

    #[test]
    fn next_page_follows_one_trusted_target_and_rejects_the_rest() {
        let current = "https://r.example/api/acme/net";
        let trusted = "https://r.example/api/";
        let url = |s: &str| NextPage::Next(url::Url::parse(s).unwrap());

        assert_eq!(next(current, None, trusted), NextPage::Last);
        assert_eq!(
            next(
                current,
                Some(r#"<https://r.example/api/acme/net>; rel="canonical""#),
                trusted
            ),
            NextPage::Last
        );
        assert_eq!(
            next(current, Some(r#"<?page=2>; rel="next""#), trusted),
            url("https://r.example/api/acme/net?page=2")
        );
        assert_eq!(
            next(
                current,
                Some(
                    r#"<https://r.example/api/acme/net?page=2>; rel=next, <https://r.example/api/acme/net?page=2>; rel="next""#
                ),
                trusted
            ),
            url("https://r.example/api/acme/net?page=2")
        );

        let rejected = [
            r#"<https://r.example/api/acme/net?page=2>; rel="next", <https://r.example/api/acme/net?page=3>; rel="next""#,
            r#"<>; rel="next""#,
            r#"https://r.example/api/acme/net?page=2; rel="next""#,
            r#"<https://evil.example/api/acme/net?page=2>; rel="next""#,
            r#"<https://r.example/other/acme/net?page=2>; rel="next""#,
            r#"<http://r.example/api/acme/net?page=2>; rel="next""#,
            r#"<https://user:pw@r.example/api/acme/net?page=2>; rel="next""#,
            r#"<https://r.example/apiEVIL/acme/net>; rel="next""#,
        ];
        for header in rejected {
            assert_eq!(
                next(current, Some(header), trusted),
                NextPage::Rejected,
                "{header}"
            );
        }
    }

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
    #[cfg(feature = "test-util")]
    #[tokio::test]
    async fn test_warn_if_pagination_truncated_uses_passed_max_pages_not_a_constant() {
        let output = capture_tracing_output_async(async {
            warn_if_pagination_truncated(
                "GitLab",
                EcosystemId::GitlabCi,
                "tags",
                "org/repo",
                3,
                100,
                3,
            );
        })
        .await;
        assert!(output.contains("org/repo"), "output was: {output}");
        assert!(output.contains("GitLab"), "output was: {output}");
        assert!(output.contains('3'), "output was: {output}");

        let silent = capture_tracing_output_async(async {
            warn_if_pagination_truncated(
                "GitLab",
                EcosystemId::GitlabCi,
                "tags",
                "org/repo",
                2,
                100,
                3,
            );
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
            EcosystemId::GitlabCi,
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
        assert_eq!(result.items.len(), 42);
    }

    #[tokio::test]
    async fn test_paginate_pages_stops_after_partial_page_at_custom_cap() {
        let result = paginate_pages(
            "GitLab",
            EcosystemId::GitlabCi,
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

        assert_eq!(result.items.len(), 110);
        assert_eq!(result.coverage, ListCoverage::Complete);
    }

    #[tokio::test]
    async fn test_paginate_pages_single_partial_page_is_complete() {
        let result = paginate_pages(
            "GitLab",
            EcosystemId::GitlabCi,
            "tags",
            "org/repo",
            5,
            |_page| async move { Ok(page_json(3)) },
            parse_page,
        )
        .await
        .unwrap();

        assert_eq!(result.coverage, ListCoverage::Complete);
    }

    #[tokio::test]
    async fn test_paginate_pages_cap_reached_with_full_last_page_is_truncated() {
        let result = paginate_pages(
            "GitLab",
            EcosystemId::GitlabCi,
            "tags",
            "org/repo",
            3,
            |_page| async move { Ok(page_json(100)) },
            parse_page,
        )
        .await
        .unwrap();

        assert_eq!(result.items.len(), 300);
        assert_eq!(result.coverage, ListCoverage::Truncated);
    }

    #[tokio::test]
    async fn test_paginate_pages_partial_page_exactly_at_cap_is_complete() {
        let result = paginate_pages(
            "GitLab",
            EcosystemId::GitlabCi,
            "tags",
            "org/repo",
            3,
            |page| async move {
                match page {
                    1 | 2 => Ok(page_json(100)),
                    3 => Ok(page_json(7)),
                    _ => panic!("page {page} must not be fetched beyond the 3-page cap"),
                }
            },
            parse_page,
        )
        .await
        .unwrap();

        assert_eq!(result.items.len(), 207);
        assert_eq!(result.coverage, ListCoverage::Complete);
    }

    #[test]
    fn test_list_coverage_default_is_complete() {
        assert_eq!(ListCoverage::default(), ListCoverage::Complete);
    }
}
