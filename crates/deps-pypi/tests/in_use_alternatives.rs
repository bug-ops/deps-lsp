//! Lock alternatives for a uv fork-duplicate lock file (#1981).
//!
//! uv writes one `[[package]]` entry per resolution fork, so a dependency such as
//! `numpy>=1.20` can be locked at both 1.21.0 and 2.1.0. The lock file cannot say which one an
//! environment installs, so the highest is the primary and the other is a lock alternative the
//! OSV scan covers too.

// Test code: workspace-level `clippy::unwrap_used` is meant for library code (#689).
#![allow(clippy::unwrap_used)]

use deps_core::lockfile::LockFileProvider;
use deps_core::{EcosystemId, PackageKey};
use deps_pypi::{PypiFormatter, PypiLockParser, PypiParser};
use url::Url;

const PYPROJECT: &str = r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["numpy>=1.20", "requests>=2"]
"#;

const BARE_PYPROJECT: &str = r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["numpy"]
"#;

const UV_LOCK: &str = r#"version = 1
requires-python = ">=3.9"
resolution-markers = [
    "python_full_version < '3.10'",
    "python_full_version >= '3.10'",
]

[[package]]
name = "numpy"
version = "1.21.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version < '3.10'"]

[[package]]
name = "numpy"
version = "2.1.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version >= '3.10'"]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

async fn in_use(pyproject: &str, name: &str) -> deps_core::lsp_helpers::InUseVersions {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("uv.lock");
    tokio::fs::write(&lock_path, UV_LOCK).await.unwrap();

    let packages = PypiLockParser.parse_lockfile(&lock_path).await.unwrap();
    let (versions, candidates) = packages.split_normalized(&PypiFormatter);
    let uri = Url::from_file_path(dir.path().join("pyproject.toml")).unwrap();
    let parsed = PypiParser::new().parse_content(pyproject, &uri).unwrap();
    let dep = parsed
        .dependencies
        .iter()
        .find(|d| d.name.as_str() == name)
        .unwrap();
    let key = PackageKey::new(&dep.name, &PypiFormatter);
    deps_core::lsp_helpers::resolve_in_use_versions(
        dep,
        &key,
        &versions,
        Some(&candidates),
        &PypiFormatter,
        EcosystemId::Pypi,
    )
    .unwrap()
}

fn alternatives(in_use: &deps_core::lsp_helpers::InUseVersions) -> Vec<&str> {
    in_use
        .lock_alternatives()
        .iter()
        .map(|v| v.as_str())
        .collect()
}

#[tokio::test]
async fn uv_fork_duplicates_become_primary_and_lock_alternative() {
    let numpy = in_use(PYPROJECT, "numpy").await;
    assert_eq!(numpy.primary().as_str(), "2.1.0");
    assert_eq!(alternatives(&numpy), ["1.21.0"]);

    let requests = in_use(PYPROJECT, "requests").await;
    assert_eq!(requests.primary().as_str(), "2.31.0");
    assert!(requests.lock_alternatives().is_empty());
}

/// A bare name has no requirement to narrow the forks, so the older fork must still be scanned.
#[tokio::test]
async fn bare_name_scans_every_uv_fork() {
    let numpy = in_use(BARE_PYPROJECT, "numpy").await;
    assert_eq!(numpy.primary().as_str(), "2.1.0");
    assert_eq!(alternatives(&numpy), ["1.21.0"]);
}
