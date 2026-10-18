# Step 11: Add Tests

Create comprehensive tests co-located with each module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> url::Url {
        // `deps_core::test_util::test_uri("/test/{manifest_file}")` builds the same thing
        // (and handles the Windows `C:` prefix) — prefer it over hand-rolling this helper.
        url::Url::parse("file:///test/{manifest_file}").unwrap()
    }

    #[test]
    fn test_parse_simple_dependencies() {
        let content = r#"..."#;
        let result = parse_{manifest}(content, &test_uri()).unwrap();
        assert!(!result.dependencies.is_empty());
    }

    #[test]
    fn test_position_tracking() {
        let content = r#"..."#;
        let result = parse_{manifest}(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        // Verify positions are correct
        assert!(dep.name_range.start.line > 0);
        assert!(dep.version_range.is_some());
    }

    #[tokio::test]
    async fn test_ecosystem_trait() {
        let cache = Arc::new(HttpCache::new());
        let ecosystem = {Ecosystem}Ecosystem::new(cache);

        assert_eq!(ecosystem.id(), "{ecosystem_id}");
        assert!(ecosystem.manifest_filenames().contains(&"{manifest_file}"));
    }
}
```

## Complexity guards

A test that proves a parser, scanner or redactor stays linear on adversarial input must not
assert an absolute wall-clock bound such as `elapsed < Duration::from_secs(2)`: the outcome then
depends on runner load, not on the algorithm. Use `deps_core::test_util::scaling::assert_scaling`
instead. It times the same operation at `full_units / 8` and at `full_units`, interleaved, and
fails only when the time ratio exceeds the limit of the `ExpectedGrowth` you pass (`Linear`,
`Linearithmic` for `n log n` with no fixed-cost part, or `Bounded` for a capped scan or cached
lookup).

```rust
let redacted = assert_scaling(
    "contiguous slash run",
    ExpectedGrowth::Linear,
    400_000,
    |len| format!("a@b{}y", "/".repeat(len)),
    |raw| redact_userinfo(raw),
);
assert_eq!(redacted, format!("***@b{}y", "/".repeat(400_000)));
```

- Build the input in `prepare(units)` (untimed) and keep the correctness assertions on the
  returned full-size result.
- Pick `full_units` so a quadratic regression takes well over 100 ms; a full-size run under that
  noise floor is never compared.
- Latency or timeout checks (a request must answer within N seconds) are not complexity guards
  and keep their own bounds.
