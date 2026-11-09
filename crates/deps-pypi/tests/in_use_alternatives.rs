//! Lock alternatives for a uv fork-duplicate lock file (#1981).
//!
//! uv writes one `[[package]]` entry per resolution fork, so a dependency such as
//! `numpy>=1.24` can be locked at both 1.26.4 and 2.1.0. The lock file cannot say which one an
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
dependencies = ["numpy>=1.24", "requests>=2"]
"#;

const UV_LOCK: &str = r#"version = 1
requires-python = ">=3.9"
resolution-markers = [
    "python_full_version < '3.10'",
    "python_full_version >= '3.10'",
]

[[package]]
name = "numpy"
version = "1.26.4"
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

#[tokio::test]
async fn uv_fork_duplicates_become_primary_and_lock_alternative() {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("uv.lock");
    tokio::fs::write(&lock_path, UV_LOCK).await.unwrap();

    let packages = PypiLockParser.parse_lockfile(&lock_path).await.unwrap();
    let (versions, candidates) = packages.split_normalized(&PypiFormatter);
    let uri = Url::from_file_path(dir.path().join("pyproject.toml")).unwrap();
    let parsed = PypiParser::new().parse_content(PYPROJECT, &uri).unwrap();

    let in_use = |name: &str| {
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
    };

    let numpy = in_use("numpy");
    assert_eq!(numpy.primary().as_str(), "2.1.0");
    assert_eq!(
        numpy
            .lock_alternatives()
            .iter()
            .map(|v| v.as_str())
            .collect::<Vec<_>>(),
        ["1.26.4"]
    );

    let requests = in_use("requests");
    assert_eq!(requests.primary().as_str(), "2.31.0");
    assert!(requests.lock_alternatives().is_empty());
}
