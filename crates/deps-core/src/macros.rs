//! Macro utilities for reducing enum boilerplate.
//!
//! Provides macros for delegating method calls to enum variants,
//! eliminating repetitive match arms in UnifiedDependency and UnifiedVersion.

/// Delegate a method call to all enum variants.
///
/// This macro generates a match expression that delegates to the same
/// method on each enum variant, eliminating boilerplate.
///
/// # Examples
///
/// ```ignore
/// impl UnifiedDependency {
///     pub fn name(&self) -> &str {
///         delegate_to_variants!(self, name)
///     }
///
///     pub fn name_range(&self) -> Range {
///         delegate_to_variants!(self, name_range)
///     }
/// }
/// ```
///
/// Expands to:
/// ```ignore
/// match self {
///     UnifiedDependency::Cargo(dep) => dep.name(),
///     UnifiedDependency::Npm(dep) => dep.name(),
///     UnifiedDependency::Pypi(dep) => dep.name(),
/// }
/// ```
#[macro_export]
macro_rules! delegate_to_variants {
    ($self:ident, $method:ident $(, $arg:expr)*) => {
        match $self {
            Self::Cargo(dep) => dep.$method($($arg),*),
            Self::Npm(dep) => dep.$method($($arg),*),
            Self::Pypi(dep) => dep.$method($($arg),*),
        }
    };
}
