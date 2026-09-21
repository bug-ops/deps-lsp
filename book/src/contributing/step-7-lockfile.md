# Step 7: Implement the Lock File Provider

Create lock file parser in `lockfile.rs`:

```rust
//! Lock file parsing for {Ecosystem}.

use std::path::{Path, PathBuf};

use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest,
};
use url::Url;

/// Lock file parser for {Ecosystem}.
pub struct {Ecosystem}LockfileParser;

impl LockFileProvider for {Ecosystem}LockfileParser {
    fn locate_lockfile(&self, manifest_uri: &Url) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, &["{lockfile_name}"])
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::error::Result<ResolvedPackages>> + Send + 'a>> {
        Box::pin(async move {
            let content = tokio::fs::read_to_string(lockfile_path)
                .await
                .map_err(deps_core::DepsError::Io)?;

            parse_lock_content(&content)
        })
    }
}

fn parse_lock_content(content: &str) -> deps_core::error::Result<ResolvedPackages> {
    let mut packages = ResolvedPackages::new();

    // TODO: Parse lock file and call packages.insert(ResolvedPackage { ... })

    Ok(packages)
}
```

