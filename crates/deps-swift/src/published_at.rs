//! Per-release `publishedAt` lookup for SE-0292 registries.
//!
//! The release list carries no dates; each date needs one `GET {base}/{scope}/{name}/{version}`.
//! [`PublishedAtCache`] bounds that cost: one concurrency limit per registry client, one deadline
//! around a whole batch, and a memo so that neither a warm call nor a broken registry repeats
//! requests. Everything is best-effort: a missing date never fails a version list.

use std::collections::HashSet;
use std::future::Future;
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};
use deps_core::cache::CachedResponse;
use deps_core::{DepsError, PublishTime, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio::time::timeout_at;

use crate::package_location::CanonicalIdentity;

/// Deadline for one whole batch of metadata requests (mirrors the GitHub release-dates fetch).
const PUBLISHED_AT_BUDGET: Duration = Duration::from_secs(2);

/// How long a failed metadata request is remembered (mirrors the GitHub release-dates memo).
const PUBLISHED_AT_FAILURE_TTL: Duration = Duration::from_secs(90);

/// Memo entries after which the memo is cleared.
const MAX_MEMO_ENTRIES: usize = 4096;

/// Metadata requests in flight at once, per registry client.
const MAX_CONCURRENT_REQUESTS: usize = 4;

/// What is known about one release's publication date.
#[derive(Debug, Clone, Copy)]
enum PublishedAtMemo {
    /// Releases are immutable, so this never expires; `None` means the registry has no usable date.
    Known(Option<PublishTime>),
    /// The request failed for a reason that may pass; retried once `until` has elapsed.
    Failed { until: Instant },
}

impl PublishedAtMemo {
    fn failed() -> Self {
        Self::Failed {
            until: Instant::now() + PUBLISHED_AT_FAILURE_TTL,
        }
    }

    fn is_settled(self) -> bool {
        match self {
            Self::Known(_) => true,
            Self::Failed { until } => Instant::now() < until,
        }
    }

    /// 200 and 410 are final answers; every other outcome is retried after a short TTL.
    fn classify(result: Result<CachedResponse>) -> Self {
        match result {
            Ok(response) => deps_core::parse_json_checked::<ReleaseMetadata>(&response.body)
                .map_or_else(
                    |_| Self::failed(),
                    |metadata| {
                        Self::Known(
                            metadata
                                .published_at
                                .as_deref()
                                .and_then(PublishTime::parse_rfc3339),
                        )
                    },
                ),
            Err(DepsError::HttpStatus { status: 410, .. }) => Self::Known(None),
            Err(_) => Self::failed(),
        }
    }
}

#[derive(Deserialize)]
struct ReleaseMetadata {
    #[serde(default, rename = "publishedAt")]
    published_at: Option<String>,
}

/// A release's version string exactly as the registry's `releases` object keys it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ReleaseVersion(String);

impl ReleaseVersion {
    pub(crate) const fn new(raw: String) -> Self {
        Self(raw)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identifies one release of one package in the memo.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReleaseKey {
    package: CanonicalIdentity,
    version: ReleaseVersion,
}

/// Memoized, bounded `publishedAt` lookups for one registry client.
#[derive(Debug)]
pub(crate) struct PublishedAtCache {
    memo: DashMap<ReleaseKey, PublishedAtMemo>,
    permits: Semaphore,
}

impl PublishedAtCache {
    pub(crate) fn new() -> Self {
        Self {
            memo: DashMap::new(),
            permits: Semaphore::new(MAX_CONCURRENT_REQUESTS),
        }
    }

    fn key(package: &CanonicalIdentity, version: &ReleaseVersion) -> ReleaseKey {
        ReleaseKey {
            package: package.clone(),
            version: version.clone(),
        }
    }

    /// The memoized publication date of `package`'s `version`, if one is known.
    pub(crate) fn get(
        &self,
        package: &CanonicalIdentity,
        version: &ReleaseVersion,
    ) -> Option<PublishTime> {
        let memo = *self.memo.get(&Self::key(package, version))?;
        match memo {
            PublishedAtMemo::Known(date) => date,
            PublishedAtMemo::Failed { .. } => None,
        }
    }

    fn is_settled(&self, package: &CanonicalIdentity, version: &ReleaseVersion) -> bool {
        self.memo
            .get(&Self::key(package, version))
            .is_some_and(|memo| memo.is_settled())
    }

    fn record(&self, package: &CanonicalIdentity, version: &ReleaseVersion, memo: PublishedAtMemo) {
        if self.memo.len() >= MAX_MEMO_ENTRIES {
            self.memo.clear();
        }
        self.memo.insert(Self::key(package, version), memo);
    }

    /// Fetches and memoizes the dates of the `versions` that have no settled memo entry yet.
    ///
    /// `fetch` performs one metadata request. All requests share one deadline; results that
    /// arrived before it are kept. Only a request that had started when the deadline hit is
    /// memoized as failed, so a candidate that never got a permit is simply retried next call.
    pub(crate) async fn resolve<F, Fut>(
        &self,
        package: &CanonicalIdentity,
        versions: &[ReleaseVersion],
        fetch: F,
    ) where
        F: Fn(&ReleaseVersion) -> Fut,
        Fut: Future<Output = Result<CachedResponse>>,
    {
        let mut pending: HashSet<&ReleaseVersion> = versions
            .iter()
            .filter(|version| !self.is_settled(package, version))
            .collect();
        if pending.is_empty() {
            return;
        }

        let started: DashSet<&ReleaseVersion> = DashSet::new();
        let mut in_flight: FuturesUnordered<_> = pending
            .iter()
            .map(|&version| {
                let started = &started;
                let request = fetch(version);
                async move {
                    let Ok(_permit) = self.permits.acquire().await else {
                        return (version, None);
                    };
                    started.insert(version);
                    (version, Some(PublishedAtMemo::classify(request.await)))
                }
            })
            .collect();

        let deadline = tokio::time::Instant::now() + PUBLISHED_AT_BUDGET;
        while let Ok(Some((version, outcome))) = timeout_at(deadline, in_flight.next()).await {
            pending.remove(version);
            if let Some(outcome) = outcome {
                self.record(package, version, outcome);
            }
        }
        drop(in_flight);

        for version in pending {
            if started.contains(version) {
                tracing::debug!("release metadata request did not finish within the budget");
                self.record(package, version, PublishedAtMemo::failed());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::assert_matches;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn response(body: &str) -> CachedResponse {
        CachedResponse::new(Bytes::from(body.to_string()))
    }

    fn versions(raws: &[&str]) -> Vec<ReleaseVersion> {
        raws.iter().map(|raw| version(raw)).collect()
    }

    fn version(raw: &str) -> ReleaseVersion {
        ReleaseVersion::new(raw.to_string())
    }

    fn pkg() -> CanonicalIdentity {
        crate::package_location::RegistryIdentity::parse("Acme.Net")
            .unwrap()
            .canonical()
    }

    #[test]
    fn test_classification_table() {
        let status = |status| DepsError::HttpStatus {
            url: "https://r.example/x".into(),
            status,
        };
        let dated = PublishedAtMemo::classify(Ok(response(
            r#"{"publishedAt": "2025-03-04T05:06:07.250Z"}"#,
        )));
        assert_matches!(dated, PublishedAtMemo::Known(Some(_)));

        for body in [
            r"{}",
            r#"{"publishedAt": null}"#,
            r#"{"publishedAt": "soon"}"#,
        ] {
            assert_matches!(
                PublishedAtMemo::classify(Ok(response(body))),
                PublishedAtMemo::Known(None),
                "{body}"
            );
        }
        assert_matches!(
            PublishedAtMemo::classify(Err(status(410))),
            PublishedAtMemo::Known(None)
        );
        for failed in [
            PublishedAtMemo::classify(Err(status(404))),
            PublishedAtMemo::classify(Err(status(503))),
            PublishedAtMemo::classify(Err(DepsError::CacheError("timeout".into()))),
            PublishedAtMemo::classify(Ok(response("not json"))),
        ] {
            assert_matches!(failed, PublishedAtMemo::Failed { .. });
        }
    }

    #[tokio::test]
    async fn test_resolved_dates_and_final_answers_are_memoized() {
        let cache = PublishedAtCache::new();
        let calls = AtomicUsize::new(0);
        let fetch = |raw: &ReleaseVersion| {
            calls.fetch_add(1, Ordering::SeqCst);
            let result = match raw.as_str() {
                "1.0.0" => Ok(response(r#"{"publishedAt": "2025-01-01T00:00:00Z"}"#)),
                _ => Ok(response("{}")),
            };
            async move { result }
        };
        let raws = versions(&["1.0.0", "2.0.0"]);
        cache.resolve(&pkg(), &raws, fetch).await;
        cache.resolve(&pkg(), &raws, fetch).await;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(cache.get(&pkg(), &version("1.0.0")).is_some());
        assert!(cache.get(&pkg(), &version("2.0.0")).is_none());
    }

    #[tokio::test]
    async fn test_failures_are_memoized_for_the_ttl_only() {
        let cache = PublishedAtCache::new();
        let calls = AtomicUsize::new(0);
        let fetch = |_: &ReleaseVersion| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<CachedResponse, _>(DepsError::HttpStatus {
                    url: "https://r.example/x".into(),
                    status: 503,
                })
            }
        };
        let raws = versions(&["1.0.0"]);
        cache.resolve(&pkg(), &raws, fetch).await;
        cache.resolve(&pkg(), &raws, fetch).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        cache.record(
            &pkg(),
            &version("1.0.0"),
            PublishedAtMemo::Failed {
                until: Instant::now(),
            },
        );
        cache.resolve(&pkg(), &raws, fetch).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_hanging_candidate_does_not_discard_a_finished_one() {
        let cache = PublishedAtCache::new();
        let fetch = |raw: &ReleaseVersion| {
            let hang = raw.as_str() == "2.0.0";
            async move {
                if hang {
                    std::future::pending::<()>().await;
                }
                Ok(response(r#"{"publishedAt": "2025-01-01T00:00:00Z"}"#))
            }
        };
        cache
            .resolve(&pkg(), &versions(&["1.0.0", "2.0.0"]), fetch)
            .await;

        assert!(cache.get(&pkg(), &version("1.0.0")).is_some());
        assert!(cache.is_settled(&pkg(), &version("1.0.0")));
        assert!(
            cache.is_settled(&pkg(), &version("2.0.0")),
            "the started-but-unfinished request is memoized as failed"
        );
        assert!(cache.get(&pkg(), &version("2.0.0")).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_candidates_that_never_got_a_permit_are_not_memoized() {
        let cache = PublishedAtCache::new();
        let fetch = |_: &ReleaseVersion| async {
            std::future::pending::<()>().await;
            Ok(response("{}"))
        };
        let raws: Vec<ReleaseVersion> = (0..MAX_CONCURRENT_REQUESTS + 2)
            .map(|n| version(&format!("1.0.{n}")))
            .collect();
        cache.resolve(&pkg(), &raws, fetch).await;

        let memoized = raws
            .iter()
            .filter(|raw| cache.is_settled(&pkg(), raw))
            .count();
        assert_eq!(memoized, MAX_CONCURRENT_REQUESTS);
    }
}
