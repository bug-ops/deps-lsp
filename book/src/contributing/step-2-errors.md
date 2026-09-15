# Step 2: Handle Errors

Construct `deps_core::DepsError` directly at call sites instead of using a local error wrapper. Use `deps_core::Result<T>` for function signatures:

```rust
use deps_core::DepsError;

/// Example: validation function
fn validate_module_path(path: &str) -> deps_core::Result<()> {
    if path.is_empty() {
        return Err(DepsError::InvalidVersionReq("module path is empty".into()));
    }
    if path.contains("..") {
        return Err(DepsError::InvalidVersionReq(
            format!("invalid module path: {}", path)
        ));
    }
    Ok(())
}

/// Example: parsing function
fn parse_manifest(content: &str, uri: &Uri) -> deps_core::Result<ParseResult> {
    // Parse logic...
    // On error: return Err(DepsError::ParseError { ... })
    // On success: return Ok(ParseResult { ... })
}

/// Example: registry function handling 404
const REGISTRY: &str = "example-registry";

fn fetch_versions(package: &str) -> deps_core::Result<Vec<Version>> {
    let response = http_client.get(&url).send()
        .map_err(|e| DepsError::CacheError(e.to_string()))?;
    
    if response.status() == 404 {
        return Err(DepsError::PackageNotFound {
            package: package.into(),
            registry: REGISTRY,
        });
    }
    
    let data: Vec<Version> = response.json()
        .map_err(|e| DepsError::ApiResponse {
            package: package.into(),
            registry: REGISTRY,
            source: e,
        })?;
    
    Ok(data)
}
```

