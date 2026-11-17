use deps_core::lsp_helpers::ProbeDependency;
use deps_core::parser::DependencySource;
use deps_core::position::Range;
use deps_core::{Dependency, PackageName, VersionReq};

struct PlainDependency {
    name: PackageName,
    name_range: Range,
    version: Option<VersionReq>,
    version_range: Option<Range>,
    source: DependencySource,
}

deps_core::impl_dependency!(PlainDependency {
    name: name,
    name_range: name_range,
    version: version,
    version_range: version_range,
    source: source,
});

impl ProbeDependency for PlainDependency {
    fn probe(name: PackageName, source: DependencySource) -> Self {
        Self {
            name,
            name_range: Range::default(),
            version: None,
            version_range: None,
            source,
        }
    }
}

fn main() {
    let _ = PlainDependency::probe(PackageName::new("serde"), DependencySource::Registry).name();
}
