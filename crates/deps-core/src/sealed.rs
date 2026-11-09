//! Supertraits that keep [`ParsedManifest`](crate::ParsedManifest) and
//! [`FormattedDependency`](crate::lsp_helpers::FormattedDependency) implementable only inside
//! this crate.
//!
//! The module is crate-private while its traits are `pub`, so a downstream crate can name neither
//! and cannot satisfy the bound. Both traits have exactly one implementation, over a typed
//! ecosystem and its formatter, which is what lets the erased views rely on the two sides
//! agreeing.

/// Implemented by `EcosystemManifest` alone.
pub trait ParsedManifest {}

/// Implemented by [`BoundDependency`](crate::lsp_helpers::BoundDependency) alone.
pub trait FormattedDependency {}
