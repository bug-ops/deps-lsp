# Step 6: Implement the Ecosystem Trait

> **Note:** everything below that touches `tower-lsp-server` types (`Range`, `CompletionItem`,
> the `generate_completions`/`complete_version` methods) belongs behind this crate's
> `lsp-responses` feature (see [Step 1](step-1-crate.md)) in the real implementation — e.g.
> `#[cfg(feature = "lsp-responses")] use tower_lsp_server::ls_types::Range;`. Omitted from the
> snippet below for readability; see `crates/deps-maven/src/ecosystem.rs` for the full
> `#[cfg(feature = "lsp-responses")]`-gated shape.

Create the main ecosystem implementation in `ecosystem.rs`:

```rust
//! {Ecosystem} implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::Range;
use url::Url;

use deps_core::{
    Ecosystem, HttpCache, PackageName, ParseResult as ParseResultTrait, Registry, Result,
    completion::{Completions, CompletionRequest, complete_package_names_generic, complete_versions_at_position},
    ecosystem::BoxFuture,
    lockfile::LockFileProvider,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::{Ecosystem}Formatter;
use crate::lockfile::{Ecosystem}LockfileParser;
use crate::parser::parse_{manifest};
use crate::registry::{Ecosystem}Registry;

/// {Ecosystem} ecosystem implementation.
pub struct {Ecosystem}Ecosystem {
    registry: Arc<{Ecosystem}Registry>,
    formatter: {Ecosystem}Formatter,
}

impl {Ecosystem}Ecosystem {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            registry: Arc::new({Ecosystem}Registry::new(cache)),
            formatter: {Ecosystem}Formatter,
        }
    }
}

// Required sealed trait impl — a documented contract (code review, not the compiler)
// restricting `Ecosystem` implementations to crates in this workspace; see
// `deps_core::ecosystem::private`'s doc for why Rust cannot enforce this any harder.
impl deps_core::ecosystem::private::Sealed for {Ecosystem}Ecosystem {}

impl Ecosystem for {Ecosystem}Ecosystem {
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::{Ecosystem}
    }

    fn display_name(&self) -> &'static str {
        "{Ecosystem Name}"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["{manifest_filename}"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["{lockfile_filename}"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Url,
    ) -> BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = parse_{manifest}(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn LockFileProvider>> {
        Some(Arc::new({Ecosystem}LockfileParser))
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    // generate_inlay_hints, generate_hover, generate_code_actions, generate_diagnostics,
    // generate_completions all have default implementations in the Ecosystem trait that
    // delegate to lsp_helpers / dispatch to the complete_* hooks below. Override only if
    // custom behavior is needed (issue #793: generate_completions's default is the
    // exhaustive match over CompletionContext — do NOT hand-write that match again in a
    // new ecosystem crate; implement the three hooks it dispatches to instead).

    // Required — every ecosystem serves version completion, and this is the one hook with
    // no default. Resolved by cursor position, not by name (issue #593):
    // complete_versions_at_position re-derives the dependency at `request.position` from
    // `request.parse_result` and gates the lookup on that dependency's own
    // `Dependency::source()` via the formatter's `SourcePolicy::can_resolve_source` — do NOT
    // call a registry directly from `package_name`/`prefix` alone (issue #1136: doing so
    // skips that gate and can leak a private/non-registry dependency's name to the public
    // registry on every keystroke).
    fn complete_version<'a>(
        &'a self,
        request: CompletionRequest<'a>,
        _package_name: PackageName,
        prefix: String,
    ) -> BoxFuture<'a, Completions> {
        Box::pin(async move {
            complete_versions_at_position(
                self.registry.as_ref(),
                &self.formatter,
                request.parse_result,
                request.position,
                &prefix,
                &[],
                request.freshness,
            )
            .await
            .into()
        })
    }

    // Optional — default is `Completions::default()` (no package-name search), correct
    // for an ecosystem with no package-name index. Override to search a registry:
    //
    // fn complete_package_name<'a>(
    //     &'a self,
    //     _request: CompletionRequest<'a>,
    //     prefix: String,
    //     range: Range,
    // ) -> BoxFuture<'a, Completions> {
    //     Box::pin(async move {
    //         complete_package_names_generic(self.registry.as_ref(), &prefix, 20, range)
    //             .await
    //             .into()
    //     })
    // }
    //
    // `is_incomplete` should stay `false` unless this ecosystem serves completions from a
    // capped/unranked index (see PyPI's `complete_package_name` override, which returns
    // `Completions::new(items).with_incomplete(true)`).

    // Optional — default is `Completions::default()` (no feature-flag concept). Override
    // only for a manifest format with a feature/flag array (e.g. Cargo, Go).

    // Raw-text fallback completion (parse-failure path, issue #722): override
    // `fallback_completion_prefix` only if this manifest format has a cheap raw-text
    // section boundary to detect (most do — see e.g. `deps_core::fallback_completion`'s
    // shared TOML/JSON/XML-tag scanners). Default `None` disables fallback completion
    // for this ecosystem, which is correct if there is none (e.g. a manifest format
    // with no delimited dependencies section).
    //
    // `completion_insert_text` is REQUIRED — no default — since a missing override
    // would silently insert another ecosystem's manifest syntax (issue #118's failure
    // mode). Called only from the raw-text fallback path above — the primary (parsed)
    // completion path builds its own insert text via
    // `build_package_completion`/`complete_package_names_generic` and never calls this.
    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        Some(format!("\"{}\" = \"{}\"", metadata.name(), metadata.latest_version()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
```

