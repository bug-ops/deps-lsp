//! #2072 acceptance: `Dependency::kind()` for Gemfile groups (architect v2 S5 mapping).
//! Written tests-first; `Dependency::kind` and `deps_core::DependencyKind` do not exist yet.

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

const GEMFILE: &str = r"source 'https://rubygems.org'

gem 'rails', '~> 7.0'

group :development do
  gem 'pry', '~> 0.14'
end

group :test do
  gem 'rspec', '~> 3.12'
end

group :production do
  gem 'puma', '~> 6.0'
end

group :staging do
  gem 'rack-mini-profiler', '~> 3.0'
end
";

#[test]
fn kind_maps_gemfile_groups_and_leaves_custom_groups_unknown() {
    let uri = url::Url::parse("file:///project/Gemfile").expect("uri");
    let result = deps_bundler::parse_gemfile(GEMFILE, &uri).expect("parse");
    let kind_of = |name: &str| {
        result
            .dependencies()
            .into_iter()
            .find(|dep| dep.name().as_str() == name)
            .expect("parsed")
            .kind()
    };

    assert_eq!(kind_of("rails"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("puma"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("pry"), Some(DependencyKind::Development));
    assert_eq!(kind_of("rspec"), Some(DependencyKind::Development));
    assert_eq!(kind_of("rack-mini-profiler"), None);
}
