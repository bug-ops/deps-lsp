//! Shared fixtures for the native-window CLI suites that need a counting-free, advisory-aware
//! OSV mock next to a registry reached through the public tier (#2053).

#![allow(dead_code, clippy::expect_used)]

use serde_json::json;

pub(crate) const DAY: i64 = 86_400;
pub(crate) const ADVISORY: &str = "GHSA-2053-test-0001";

pub(crate) fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("fits")
}

pub(crate) fn rfc3339(epoch: i64) -> String {
    let (days, rem) = (epoch.div_euclid(DAY), epoch.rem_euclid(DAY));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// One advisory affecting `package` in `ecosystem` from `0` up to (excluding) `fixed`, reported
/// by the OSV batch endpoint only for queries of exactly `vulnerable`.
pub(crate) struct AdvisoryFixture<'a> {
    pub(crate) ecosystem: &'a str,
    pub(crate) package: &'a str,
    pub(crate) range_type: &'a str,
    pub(crate) vulnerable: &'a str,
    pub(crate) fixed: &'a str,
}

/// A `mockito` OSV server serving `advisory`, and the mocks that keep its routes alive.
pub(crate) async fn osv_with_advisory(
    advisory: &AdvisoryFixture<'_>,
) -> (mockito::ServerGuard, Vec<mockito::Mock>) {
    let mut osv = mockito::Server::new_async().await;
    let vulnerable = advisory.vulnerable.to_owned();
    let batch = osv
        .mock("POST", "/v1/querybatch")
        .with_status(200)
        .with_body_from_request(move |request| {
            let body: serde_json::Value =
                serde_json::from_slice(request.body().expect("body")).expect("batch json");
            let results: Vec<_> = body
                .get("queries")
                .and_then(serde_json::Value::as_array)
                .expect("queries")
                .iter()
                .map(|query| {
                    let hit = query.get("version") == Some(&json!(vulnerable));
                    let vulns = if hit {
                        vec![json!({"id": ADVISORY, "modified": "2026-01-01T00:00:00Z"})]
                    } else {
                        Vec::new()
                    };
                    json!({ "vulns": vulns })
                })
                .collect();
            json!({ "results": results }).to_string().into_bytes()
        })
        .expect_at_least(0)
        .create_async()
        .await;
    let detail = json!({
        "id": ADVISORY,
        "modified": "2026-01-01T00:00:00Z",
        "summary": "s",
        "affected": [{
            "package": {"name": advisory.package, "ecosystem": advisory.ecosystem},
            "ranges": [{
                "type": advisory.range_type,
                "events": [{"introduced": "0"}, {"fixed": advisory.fixed}],
            }],
        }],
    });
    let vuln = osv
        .mock("GET", format!("/v1/vulns/{ADVISORY}").as_str())
        .with_status(200)
        .with_body(detail.to_string())
        .expect_at_least(0)
        .create_async()
        .await;
    (osv, vec![batch, vuln])
}
