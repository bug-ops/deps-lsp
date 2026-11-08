//! The one place a type-erased parse result or dependency becomes the concrete type an ecosystem
//! crate produced.
//!
//! [`ParseResult`] and [`Dependency`] reach an ecosystem's hooks as trait objects. A hook that
//! needs the ecosystem's own fields used to call `as_any().downcast_ref::<T>()` itself, picking
//! `T` at every call site. Here `T` is fixed once per ecosystem by an associated type
//! ([`OwnParseResult::Parsed`], [`OwnDependency::Dep`]), and the downcast lives in exactly two
//! method bodies, [`NarrowParseResult::own_parse_result`] and
//! [`NarrowDependency::own_dependency`]. Both extension traits are sealed blanket
//! implementations, so no crate can override the narrowing.
//!
//! A hook narrows the parse result once at its entry and then works on the typed `dependencies`
//! field, instead of narrowing every dependency of the type-erased view one by one.

use crate::ecosystem::{Dependency, Ecosystem, ParseResult};

mod sealed {
    pub trait ParseNarrower {}
    impl<T: super::OwnParseResult> ParseNarrower for T {}

    pub trait DependencyNarrower {}
    impl<T: super::OwnDependency> DependencyNarrower for T {}
}

/// An [`Ecosystem`] that names the concrete [`ParseResult`] its own parser produces.
///
/// Routing hands an ecosystem only documents it parsed itself, so a hook may assume the parse
/// result it receives is a [`Self::Parsed`]; [`NarrowParseResult::own_parse_result`] is how it
/// gets one.
///
/// Sealed through [`Ecosystem`]: only this workspace's ecosystem types can implement it.
///
/// # Examples
///
/// ```
/// # use std::any::Any;
/// # use std::sync::Arc;
/// # use deps_core::{
/// #     Dependency, Ecosystem, NarrowParseResult, OwnParseResult, ParseResult, Registry,
/// # };
/// # use deps_core::lsp_helpers::EcosystemFormatter;
/// # use url::Url;
/// # struct MyParsed {
/// #     uri: Url,
/// # }
/// # impl ParseResult for MyParsed {
/// #     fn dependencies(&self) -> Vec<&dyn Dependency> { Vec::new() }
/// #     fn workspace_root(&self) -> Option<&std::path::Path> { None }
/// #     fn uri(&self) -> &Url { &self.uri }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// # struct MyEcosystem;
/// # impl deps_core::ecosystem::private::Sealed for MyEcosystem {}
/// # impl Ecosystem for MyEcosystem {
/// #     fn ecosystem_id(&self) -> deps_core::EcosystemId { deps_core::EcosystemId::Cargo }
/// #     fn display_name(&self) -> &'static str { "My Ecosystem" }
/// #     fn manifest_filenames(&self) -> &[&'static str] { &["my-manifest.toml"] }
/// #     fn parse_manifest<'a>(
/// #         &'a self,
/// #         _content: &'a str,
/// #         _uri: &'a Url,
/// #     ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::error::Result<Box<dyn ParseResult>>> {
/// #         Box::pin(async move { todo!() })
/// #     }
/// #     fn registry(&self) -> Arc<dyn Registry> { todo!() }
/// #     fn formatter(&self) -> &dyn EcosystemFormatter { todo!() }
/// #     fn completion_insert_text(&self, _metadata: &dyn deps_core::Metadata) -> Option<String> {
/// #         None
/// #     }
/// #     fn as_any(&self) -> &dyn Any { self }
/// # }
/// impl OwnParseResult for MyEcosystem {
///     type Parsed = MyParsed;
/// }
///
/// let parsed = MyParsed { uri: Url::parse("file:///proj/my-manifest.toml").unwrap() };
/// let erased: &dyn ParseResult = &parsed;
///
/// let narrowed = MyEcosystem.own_parse_result(erased).unwrap();
/// assert_eq!(narrowed.uri.as_str(), "file:///proj/my-manifest.toml");
/// ```
pub trait OwnParseResult: Ecosystem {
    /// The parse result type this ecosystem's `parse_manifest` returns.
    type Parsed: ParseResult + 'static;
}

/// A type that names the one concrete [`Dependency`] it reads, typically an ecosystem's
/// formatter.
///
/// Unlike a parse result, a dependency can legitimately be foreign: `NpmFormatter` is also
/// driven with Deno dependencies. [`NarrowDependency::own_dependency`] therefore reports a
/// mismatch as `None`, never as an error.
///
/// # Examples
///
/// ```
/// use std::any::Any;
/// use deps_core::{Dependency, NarrowDependency, OwnDependency, PackageName, VersionReq};
/// use deps_core::parser::DependencySource;
/// use deps_core::position::Range;
///
/// struct Mine(PackageName);
/// struct Foreign;
///
/// macro_rules! stub_dependency {
///     ($ty:ty, |$s:ident| $name:expr) => {
///         impl Dependency for $ty {
///             fn name(&$s) -> &PackageName { $name }
///             fn name_range(&self) -> Range { Range::default() }
///             fn version_requirement(&self) -> Option<&VersionReq> { None }
///             fn version_range(&self) -> Option<Range> { None }
///             fn source(&self) -> DependencySource { DependencySource::Registry }
///             fn as_any(&self) -> &dyn Any { self }
///         }
///     };
/// }
/// stub_dependency!(Mine, |self| &self.0);
/// stub_dependency!(Foreign, |self| {
///     static NAME: std::sync::LazyLock<PackageName> =
///         std::sync::LazyLock::new(|| PackageName::new("foreign"));
///     &NAME
/// });
///
/// struct MyFormatter;
/// impl OwnDependency for MyFormatter {
///     type Dep = Mine;
/// }
///
/// let mine = Mine(PackageName::new("serde"));
/// let narrowed = MyFormatter.own_dependency(&mine).unwrap();
/// assert_eq!(narrowed.0.as_str(), "serde");
/// assert!(MyFormatter.own_dependency(&Foreign).is_none());
/// ```
pub trait OwnDependency {
    /// The dependency type this implementor reads.
    type Dep: Dependency + 'static;
}

/// Narrows a type-erased [`ParseResult`] to an ecosystem's [`OwnParseResult::Parsed`].
///
/// Implemented for every [`OwnParseResult`] by a sealed blanket impl; see its example.
pub trait NarrowParseResult: OwnParseResult + sealed::ParseNarrower {
    /// `parse_result` as this ecosystem's own parse result type.
    ///
    /// `None` means the document was routed to an ecosystem that did not parse it: a bug in
    /// routing or a test fixture. It is logged at `error` and trips a `debug_assert!`, while
    /// release builds fall back to whatever the caller does for `None`, as they did before.
    fn own_parse_result<'p>(&self, parse_result: &'p dyn ParseResult) -> Option<&'p Self::Parsed> {
        let narrowed = parse_result.as_any().downcast_ref::<Self::Parsed>();
        if narrowed.is_none() {
            let expected = std::any::type_name::<Self::Parsed>();
            tracing::error!(
                expected,
                "parse result routed to an ecosystem that did not produce it"
            );
            debug_assert!(narrowed.is_some(), "parse result is not a {expected}");
        }
        narrowed
    }
}

impl<T: OwnParseResult> NarrowParseResult for T {}

/// Narrows a type-erased [`Dependency`] to an [`OwnDependency::Dep`].
///
/// Implemented for every [`OwnDependency`] by a sealed blanket impl.
pub trait NarrowDependency: OwnDependency + sealed::DependencyNarrower {
    /// `dep` as this implementor's own dependency type, or `None` for a foreign dependency.
    fn own_dependency<'d>(&self, dep: &'d dyn Dependency) -> Option<&'d Self::Dep> {
        dep.as_any().downcast_ref::<Self::Dep>()
    }
}

impl<T: OwnDependency> NarrowDependency for T {}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::sync::{Arc, LazyLock};

    use super::*;
    use crate::ecosystem::{BoxFuture, EcosystemId, private};
    use crate::parser::DependencySource;
    use crate::position::Range;
    use crate::{PackageName, VersionReq};

    struct MineDep;
    struct OtherDep;

    macro_rules! stub_dependency {
        ($ty:ty) => {
            impl Dependency for $ty {
                fn name(&self) -> &PackageName {
                    static NAME: LazyLock<PackageName> = LazyLock::new(|| PackageName::new("stub"));
                    &NAME
                }
                fn name_range(&self) -> Range {
                    Range::default()
                }
                fn version_requirement(&self) -> Option<&VersionReq> {
                    None
                }
                fn version_range(&self) -> Option<Range> {
                    None
                }
                fn source(&self) -> DependencySource {
                    DependencySource::Registry
                }
                fn as_any(&self) -> &dyn Any {
                    self
                }
            }
        };
    }
    stub_dependency!(MineDep);
    stub_dependency!(OtherDep);

    struct MineParsed {
        uri: url::Url,
    }
    struct OtherParsed {
        uri: url::Url,
    }

    macro_rules! stub_parse_result {
        ($ty:ty) => {
            impl ParseResult for $ty {
                fn dependencies(&self) -> Vec<&dyn Dependency> {
                    Vec::new()
                }
                fn workspace_root(&self) -> Option<&std::path::Path> {
                    None
                }
                fn uri(&self) -> &url::Url {
                    &self.uri
                }
                fn as_any(&self) -> &dyn Any {
                    self
                }
            }
        };
    }
    stub_parse_result!(MineParsed);
    stub_parse_result!(OtherParsed);

    struct MineEcosystem;

    impl private::Sealed for MineEcosystem {}

    impl Ecosystem for MineEcosystem {
        fn id(&self) -> &'static str {
            "mine"
        }
        fn ecosystem_id(&self) -> EcosystemId {
            EcosystemId::Cargo
        }
        fn display_name(&self) -> &'static str {
            "Mine"
        }
        fn manifest_filenames(&self) -> &[&'static str] {
            &[]
        }
        fn parse_manifest<'a>(
            &'a self,
            _content: &'a str,
            _uri: &'a url::Url,
        ) -> BoxFuture<'a, crate::error::Result<Box<dyn ParseResult>>> {
            unimplemented!()
        }
        fn registry(&self) -> Arc<dyn crate::Registry> {
            unimplemented!()
        }
        fn formatter(&self) -> &dyn crate::lsp_helpers::EcosystemFormatter {
            unimplemented!()
        }
        #[cfg(feature = "lsp-responses")]
        fn generate_completions<'a>(
            &'a self,
            _parse_result: &'a dyn ParseResult,
            _position: tower_lsp_server::ls_types::Position,
            _content: &'a str,
            _freshness: crate::FreshnessSettings,
        ) -> BoxFuture<'a, crate::completion::Completions> {
            unimplemented!()
        }
        #[cfg(feature = "lsp-responses")]
        fn complete_version<'a>(
            &'a self,
            _request: crate::completion::CompletionRequest<'a>,
            _package_name: PackageName,
            _prefix: String,
        ) -> BoxFuture<'a, crate::completion::Completions> {
            unimplemented!()
        }
        fn completion_insert_text(&self, _metadata: &dyn crate::Metadata) -> Option<String> {
            unimplemented!()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl OwnParseResult for MineEcosystem {
        type Parsed = MineParsed;
    }

    impl OwnDependency for MineEcosystem {
        type Dep = MineDep;
    }

    fn uri() -> url::Url {
        crate::test_util::test_uri("/stub/manifest")
    }

    #[test]
    fn own_parse_result_returns_the_ecosystems_own_type() {
        let parsed = MineParsed { uri: uri() };
        let narrowed = MineEcosystem.own_parse_result(&parsed).unwrap();
        assert!(std::ptr::eq(narrowed, &raw const parsed));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "parse result is not a ")]
    fn own_parse_result_asserts_on_a_foreign_parse_result_in_debug_builds() {
        let foreign = OtherParsed { uri: uri() };
        let _ = MineEcosystem.own_parse_result(&foreign);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn own_parse_result_is_none_for_a_foreign_parse_result_in_release_builds() {
        let foreign = OtherParsed { uri: uri() };
        assert!(MineEcosystem.own_parse_result(&foreign).is_none());
    }

    #[test]
    fn own_dependency_returns_its_own_type_and_none_for_a_foreign_one() {
        let mine = MineDep;
        let narrowed = MineEcosystem.own_dependency(&mine).unwrap();
        assert!(std::ptr::eq(narrowed, &raw const mine));
        assert!(MineEcosystem.own_dependency(&OtherDep).is_none());
    }
}
