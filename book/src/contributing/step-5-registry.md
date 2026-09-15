# Step 5: Implement the Registry Client

Create registry client in `registry.rs`:

```rust
//! {Registry} API client with HTTP caching.

use crate::types::{Ecosystem}Version;
use deps_core::{DepsError, HttpCache, Result, ecosystem::BoxFuture};
use std::any::Any;
use std::sync::Arc;

const REGISTRY_URL: &str = "https://registry.example.com";

/// {Registry} API client.
pub struct {Ecosystem}Registry {
    cache: Arc<HttpCache>,
}

impl {Ecosystem}Registry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a package.
    pub async fn get_versions(&self, name: &str) -> Result<Vec<{Ecosystem}Version>> {
        let url = format!("{}/{}", REGISTRY_URL, urlencoding::encode(name));

        let data = self.cache
            .get_cached(&url)
            .await
            .map_err(|e| DepsError::CacheError(e.to_string()))?;

        // TODO: Parse response and return versions
        Ok(vec![])
    }

    /// Gets the latest version matching a requirement.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        version_req: &str,
    ) -> Result<Option<{Ecosystem}Version>> {
        let versions = self.get_versions(name).await?;

        // TODO: Implement version matching logic
        Ok(versions.into_iter().find(|v| !v.yanked))
    }
}

// Implement deps_core::Registry trait using BoxFuture (no async_trait).
// The trait takes PackageName/VersionReq; the inherent methods above stay
// &str, so each forward converts with .as_str().
impl deps_core::Registry for {Ecosystem}Registry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> BoxFuture<'a, deps_core::error::Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions(name.as_str()).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        req: &'a deps_core::VersionReq,
    ) -> BoxFuture<'a, deps_core::error::Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self.get_latest_matching(name.as_str(), req.as_str()).await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn search<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> BoxFuture<'a, deps_core::error::Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
```

