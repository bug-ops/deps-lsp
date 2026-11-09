//! The typed side of the parse-result boundary.
//!
//! An ecosystem's parser produces one concrete [`ParseResult`] holding one concrete
//! [`Dependency`] type. [`TypedParseResult`] names that dependency type, and [`ParsedView`] hands
//! it to the ecosystem's hooks and to the generic helpers in `lsp_helpers`, so no code needs to
//! recover a concrete type from a trait object: the types are carried by the generics instead.

use crate::ecosystem::{
    BlockedRegistryOccurrence, Dependency, ParseResult, RejectedRegistryOccurrence,
};
use crate::lsp_helpers::ProbeDependency;
use crate::selection::{InvalidStabilityOccurrence, SelectionContext};

/// A [`ParseResult`] that also exposes its dependencies as their concrete type.
///
/// [`Self::Dep`] is what ties a parse result to a formatter: a
/// [`DependencyFormatter`](crate::lsp_helpers::DependencyFormatter) reads exactly one dependency
/// type, and generic helpers require the two to be equal. `impl_parse_result!` implements this
/// trait from the dependencies field, so the field's element type is checked against the
/// declared dependency type.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::{StubDependency, stub_parse_result};
/// use deps_core::TypedParseResult;
///
/// let parsed = stub_parse_result(2);
/// let deps: &[StubDependency] = parsed.own_dependencies();
/// assert_eq!(deps.len(), 2);
/// ```
pub trait TypedParseResult: ParseResult {
    /// The concrete dependency type this parse result holds.
    ///
    /// [`ProbeDependency`] is required here as well as on `DependencyFormatter::Dep`: the two
    /// types are equated by `TypedEcosystem::Formatter`, and the compiler resolves the
    /// equality to this side.
    type Dep: ProbeDependency + 'static;

    /// All dependencies of the document, uncapped and in manifest order.
    fn own_dependencies(&self) -> &[Self::Dep];
}

/// A typed parse result together with its erased, possibly capped view.
///
/// Hooks and generic helpers receive a `ParsedView`. Through the view's own
/// [`ParseResult`] (delegating to the erased side) and [`TypedParseResult`] (the capped slice)
/// implementations they see the first
/// [`MAX_DEPENDENCIES_PER_DOCUMENT`](crate::MAX_DEPENDENCIES_PER_DOCUMENT) dependencies of a
/// document, as the erased [`ParseResult`] interface does. [`Self::typed`] is the exception: it is
/// the parser's own result, already bounded because every parser applies its
/// [`DependencyBudget`](crate::DependencyBudget). The view is [`Copy`].
///
/// # Examples
///
/// ```
/// use deps_core::test_util::stub_parse_result;
/// use deps_core::{ParsedView, TypedParseResult};
///
/// let parsed = stub_parse_result(3);
/// let view = ParsedView::new(&parsed);
/// assert_eq!(view.own_dependencies().len(), 3);
/// assert!(std::ptr::eq(view.typed(), &raw const parsed));
/// ```
pub struct ParsedView<'a, P: TypedParseResult> {
    typed: &'a P,
    erased: &'a dyn ParseResult,
    limit: usize,
}

impl<P: TypedParseResult> Clone for ParsedView<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: TypedParseResult> Copy for ParsedView<'_, P> {}

impl<P: TypedParseResult> std::fmt::Debug for ParsedView<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedView")
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl<'a, P: TypedParseResult> ParsedView<'a, P> {
    /// A view of `typed` whose erased side is `typed` itself, with no dependency cap.
    #[must_use]
    pub fn new(typed: &'a P) -> Self {
        Self {
            typed,
            erased: typed,
            limit: typed.own_dependencies().len(),
        }
    }

    /// A view of `typed` whose erased side is `erased` and whose typed dependencies are cut to
    /// `limit`.
    pub(crate) fn capped(typed: &'a P, erased: &'a dyn ParseResult, limit: usize) -> Self {
        Self {
            typed,
            erased,
            limit,
        }
    }

    /// The typed parse result, with every dependency the parser retained.
    ///
    /// This is the parser's own, already-budgeted result, not the capped set. Code that needs
    /// the capped dependencies must use [`Self::dependencies_slice`] or
    /// [`TypedParseResult::own_dependencies`] on the view.
    #[must_use]
    pub const fn typed(self) -> &'a P {
        self.typed
    }

    /// The capped dependencies, borrowed for the lifetime of the document rather than of this
    /// view.
    #[must_use]
    pub fn dependencies_slice(self) -> &'a [P::Dep] {
        let all = self.typed.own_dependencies();
        all.get(..self.limit).unwrap_or(all)
    }
}

#[deny(clippy::missing_trait_methods)]
impl<P: TypedParseResult> ParseResult for ParsedView<'_, P> {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        self.erased.dependencies()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        self.erased.workspace_root()
    }

    fn uri(&self) -> &url::Url {
        self.erased.uri()
    }

    fn blocked_registries(&self) -> Vec<BlockedRegistryOccurrence> {
        self.erased.blocked_registries()
    }

    fn selection_context(&self) -> SelectionContext {
        self.erased.selection_context()
    }

    fn invalid_minimum_stability(&self) -> Option<InvalidStabilityOccurrence> {
        self.erased.invalid_minimum_stability()
    }

    fn rejected_registries(&self) -> Vec<RejectedRegistryOccurrence> {
        self.erased.rejected_registries()
    }

    fn dependency_truncation(&self) -> Option<(usize, usize)> {
        self.erased.dependency_truncation()
    }
}

impl<P: TypedParseResult> TypedParseResult for ParsedView<'_, P> {
    type Dep = P::Dep;

    fn own_dependencies(&self) -> &[P::Dep] {
        self.dependencies_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::stub_parse_result;

    #[test]
    fn new_view_exposes_the_typed_document_and_every_dependency() {
        let parsed = stub_parse_result(4);
        let view = ParsedView::new(&parsed);

        assert!(std::ptr::eq(view.typed(), &raw const parsed));
        assert_eq!(view.own_dependencies().len(), 4);
        assert_eq!(view.dependencies().len(), 4);
        assert_eq!(view.uri(), parsed.uri());
    }

    #[test]
    fn capped_view_cuts_the_typed_slice_but_borrows_it_for_the_document_lifetime() {
        let parsed = stub_parse_result(5);
        let slice = {
            let view = ParsedView::capped(&parsed, &parsed, 2);
            view.dependencies_slice()
        };

        assert_eq!(slice.len(), 2);
        assert!(std::ptr::eq(
            slice.as_ptr(),
            parsed.own_dependencies().as_ptr()
        ));
    }

    #[test]
    fn view_reads_the_erased_side_for_erased_queries() {
        let parsed = stub_parse_result(3);
        let capped_erased = stub_parse_result(1);
        let view = ParsedView::capped(&parsed, &capped_erased, 3);

        assert_eq!(view.dependencies().len(), 1, "erased queries delegate");
        assert_eq!(
            view.own_dependencies().len(),
            3,
            "typed queries use the limit"
        );
    }
}
