//! Benchmarks for Gemfile parsing and Gemfile.lock parsing.
//!
//! Performance targets (based on LSP latency requirements):
//! - Parsing small files: < 1ms
//! - Parsing medium files (20-50 deps): < 5ms
//! - Parsing large files (100+ deps): < 20ms
//! - Gemfile.lock parsing: < 10ms for 100 packages

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use deps_bundler::lockfile::parse_gemfile_lock;
use deps_bundler::parser::parse_gemfile;
use std::hint::black_box;
use tower_lsp_server::ls_types::Uri;

fn bench_uri() -> Uri {
    Uri::from_file_path("/bench/Gemfile").unwrap()
}

/// Small Gemfile with 5 dependencies.
const SMALL_GEMFILE: &str = r"source 'https://rubygems.org'

ruby '3.2.2'

gem 'rails', '~> 7.0'
gem 'pg', '>= 1.1'
gem 'puma', '~> 6.0'
gem 'bootsnap', require: false
gem 'tzinfo-data', platforms: [:mingw, :mswin]
";

/// Medium Gemfile with 25 dependencies.
const MEDIUM_GEMFILE: &str = r"source 'https://rubygems.org'

ruby '3.2.2'

gem 'rails', '~> 7.0'
gem 'pg', '>= 1.1'
gem 'puma', '~> 6.0'
gem 'bootsnap', require: false
gem 'bcrypt', '~> 3.1.7'
gem 'redis', '~> 5.0'
gem 'sidekiq', '~> 7.0'
gem 'jbuilder'
gem 'image_processing', '~> 1.2'
gem 'rack-cors'
gem 'devise', '~> 4.9'
gem 'pundit', '~> 2.3'
gem 'kaminari', '~> 1.2'
gem 'ransack', '~> 4.0'
gem 'faraday', '~> 2.0'

group :development, :test do
  gem 'rspec-rails', '~> 6.0'
  gem 'factory_bot_rails'
  gem 'faker'
  gem 'pry-rails'
  gem 'dotenv-rails'
end

group :development do
  gem 'web-console'
  gem 'rack-mini-profiler'
  gem 'rubocop', require: false
  gem 'rubocop-rails', require: false
end
";

/// Large Gemfile with 100+ dependencies.
fn generate_large_gemfile() -> String {
    let mut content = String::from(
        r"source 'https://rubygems.org'

ruby '3.2.2'

",
    );

    // Generate 50 regular dependencies
    for i in 0..50 {
        content.push_str(&format!("gem 'gem_{}', '~> {}.{}.0'\n", i, i % 10, i % 20));
    }

    content.push_str("\ngroup :development do\n");
    for i in 50..75 {
        content.push_str(&format!("  gem 'dev_gem_{}', '~> {}.0'\n", i, i % 10));
    }
    content.push_str("end\n");

    content.push_str("\ngroup :test do\n");
    for i in 75..100 {
        content.push_str(&format!("  gem 'test_gem_{}', '~> {}.0'\n", i, i % 10));
    }
    content.push_str("end\n");

    content
}

/// Complex Gemfile with all dependency formats.
const COMPLEX_GEMFILE: &str = r"source 'https://rubygems.org'
source 'https://gems.example.com'

ruby '3.2.2'

# Regular gems
gem 'rails', '~> 7.0'
gem 'pg', '>= 1.1', '< 2.0'

# Git source
gem 'some_gem', git: 'https://github.com/user/some_gem.git'
gem 'another_gem', git: 'https://github.com/user/another.git', branch: 'main'

# GitHub shorthand
gem 'github_gem', github: 'user/github_gem'

# Path source
gem 'local_gem', path: '../local_gem'

# With require option
gem 'delayed_job', require: 'delayed/job'
gem 'bootsnap', require: false

# With platforms
gem 'tzinfo-data', platforms: [:mingw, :mswin, :jruby]

# Inline group
gem 'rspec', group: :test

# Complex version constraints
gem 'nokogiri', '>= 1.12', '< 2.0'

group :development, :test do
  gem 'pry-rails'
  gem 'rspec-rails', '~> 6.0'
end

group :production do
  gem 'unicorn'
end
";

/// Benchmark Gemfile parsing with different file sizes.
fn bench_gemfile_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("gemfile_parsing");
    let uri = bench_uri();

    group.bench_function("small_5_deps", |b| {
        b.iter(|| parse_gemfile(black_box(SMALL_GEMFILE), &uri));
    });

    group.bench_function("medium_25_deps", |b| {
        b.iter(|| parse_gemfile(black_box(MEDIUM_GEMFILE), &uri));
    });

    let large_gemfile = generate_large_gemfile();
    group.bench_function("large_100_deps", |b| {
        b.iter(|| parse_gemfile(black_box(&large_gemfile), &uri));
    });

    group.bench_function("complex_all_formats", |b| {
        b.iter(|| parse_gemfile(black_box(COMPLEX_GEMFILE), &uri));
    });

    group.finish();
}

/// Benchmark position tracking for Gemfile dependencies.
fn bench_position_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("position_tracking");
    let uri = bench_uri();

    let simple = "gem 'rails', '~> 7.0'\n";
    let with_options = "gem 'rails', '~> 7.0', require: false, group: :development\n";
    let git_source = "gem 'rails', git: 'https://github.com/rails/rails.git'\n";

    group.bench_function("simple_gem", |b| {
        b.iter(|| parse_gemfile(black_box(simple), &uri));
    });

    group.bench_function("gem_with_options", |b| {
        b.iter(|| parse_gemfile(black_box(with_options), &uri));
    });

    group.bench_function("git_source", |b| {
        b.iter(|| parse_gemfile(black_box(git_source), &uri));
    });

    group.finish();
}

/// Small Gemfile.lock with 5 packages.
const SMALL_GEMFILE_LOCK: &str = r"GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.8)
    pg (1.5.4)
    puma (6.4.0)
    bootsnap (1.17.0)
    tzinfo-data (1.2023.4)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  bootsnap
  pg (>= 1.1)
  puma (~> 6.0)
  rails (~> 7.0)
  tzinfo-data

BUNDLED WITH
   2.5.3
";

/// Medium Gemfile.lock with 25 packages.
fn generate_medium_gemfile_lock() -> String {
    let packages = [
        ("rails", "7.0.8"),
        ("pg", "1.5.4"),
        ("puma", "6.4.0"),
        ("bootsnap", "1.17.0"),
        ("bcrypt", "3.1.19"),
        ("redis", "5.0.8"),
        ("sidekiq", "7.2.0"),
        ("jbuilder", "2.11.5"),
        ("image_processing", "1.12.2"),
        ("rack-cors", "2.0.1"),
        ("devise", "4.9.3"),
        ("pundit", "2.3.1"),
        ("kaminari", "1.2.2"),
        ("ransack", "4.1.0"),
        ("faraday", "2.7.12"),
        ("rspec-rails", "6.1.0"),
        ("factory_bot_rails", "6.4.2"),
        ("faker", "3.2.2"),
        ("pry-rails", "0.3.9"),
        ("dotenv-rails", "2.8.1"),
        ("web-console", "4.2.1"),
        ("rack-mini-profiler", "3.3.0"),
        ("rubocop", "1.59.0"),
        ("rubocop-rails", "2.23.0"),
        ("activerecord", "7.0.8"),
    ];

    let mut content = String::from("GEM\n  remote: https://rubygems.org/\n  specs:\n");

    for (name, version) in packages {
        content.push_str(&format!("    {} ({})\n", name, version));
    }

    content.push_str(
        "\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (~> 7.0)\n\nBUNDLED WITH\n   2.5.3\n",
    );

    content
}

/// Large Gemfile.lock with 100 packages.
fn generate_large_gemfile_lock() -> String {
    let mut content = String::from("GEM\n  remote: https://rubygems.org/\n  specs:\n");

    for i in 0..100 {
        let version = format!("{}.{}.{}", i % 10, (i % 20) + 1, i % 5);
        content.push_str(&format!("    gem-{} ({})\n", i, version));
    }

    content.push_str("\nPLATFORMS\n  ruby\n  x86_64-linux\n\nDEPENDENCIES\n");

    for i in 0..100 {
        content.push_str(&format!("  gem-{}\n", i));
    }

    content.push_str("\nBUNDLED WITH\n   2.5.3\n");

    content
}

/// Complex Gemfile.lock with multiple sources.
const COMPLEX_GEMFILE_LOCK: &str = r"GIT
  remote: https://github.com/rails/rails.git
  revision: abc123def456
  branch: main
  specs:
    rails (7.1.0.alpha)

GIT
  remote: https://github.com/user/custom_gem.git
  revision: def789abc012
  specs:
    custom_gem (0.1.0)

PATH
  remote: ../local_gem
  specs:
    local_gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    pg (1.5.4)
    puma (6.4.0)
    bootsnap (1.17.0)
    bcrypt (3.1.19)
    redis (5.0.8)

GEM
  remote: https://gems.example.com/
  specs:
    private_gem (1.0.0)

PLATFORMS
  ruby
  x86_64-linux
  arm64-darwin

DEPENDENCIES
  rails!
  custom_gem!
  local_gem!
  pg (>= 1.1)
  puma (~> 6.0)
  bootsnap
  bcrypt
  redis
  private_gem

RUBY VERSION
   ruby 3.2.2p53

BUNDLED WITH
   2.5.3
";

/// Benchmark Gemfile.lock parsing with different file sizes.
fn bench_gemfile_lock_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("gemfile_lock_parsing");

    group.bench_function("small_5_packages", |b| {
        b.iter(|| parse_gemfile_lock(black_box(SMALL_GEMFILE_LOCK)));
    });

    let medium_lock = generate_medium_gemfile_lock();
    group.bench_function("medium_25_packages", |b| {
        b.iter(|| parse_gemfile_lock(black_box(&medium_lock)));
    });

    let large_lock = generate_large_gemfile_lock();
    group.bench_function("large_100_packages", |b| {
        b.iter(|| parse_gemfile_lock(black_box(&large_lock)));
    });

    group.bench_function("complex_multiple_sources", |b| {
        b.iter(|| parse_gemfile_lock(black_box(COMPLEX_GEMFILE_LOCK)));
    });

    group.finish();
}

/// Benchmark different gem declaration formats.
fn bench_gem_formats(c: &mut Criterion) {
    let mut group = c.benchmark_group("gem_formats");
    let uri = bench_uri();

    let formats = [
        ("simple", "gem 'rails'\n"),
        ("with_version", "gem 'rails', '~> 7.0'\n"),
        ("version_range", "gem 'nokogiri', '>= 1.12', '< 2.0'\n"),
        (
            "git_source",
            "gem 'rails', git: 'https://github.com/rails/rails.git'\n",
        ),
        ("github_source", "gem 'rails', github: 'rails/rails'\n"),
        ("path_source", "gem 'local', path: '../local'\n"),
        ("with_group", "gem 'rspec', group: :test\n"),
        ("with_require", "gem 'bootsnap', require: false\n"),
        (
            "with_platforms",
            "gem 'tzinfo-data', platforms: [:mingw, :mswin]\n",
        ),
        (
            "full_options",
            "gem 'rails', '~> 7.0', require: false, group: :development, platforms: [:ruby]\n",
        ),
    ];

    for (name, content) in formats {
        group.bench_with_input(BenchmarkId::from_parameter(name), &content, |b, content| {
            b.iter(|| parse_gemfile(black_box(content), &uri));
        });
    }

    group.finish();
}

/// Benchmark group block parsing.
fn bench_group_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group("group_blocks");
    let uri = bench_uri();

    let single_group = r"group :development do
  gem 'pry-rails'
  gem 'rubocop'
  gem 'solargraph'
end
";

    let multi_group = r"group :development, :test do
  gem 'rspec-rails'
  gem 'factory_bot_rails'
  gem 'faker'
end
";

    let nested_structure = r"gem 'rails'

group :development do
  gem 'pry-rails'
end

gem 'pg'

group :test do
  gem 'rspec'
end

gem 'puma'
";

    group.bench_function("single_group", |b| {
        b.iter(|| parse_gemfile(black_box(single_group), &uri));
    });

    group.bench_function("multi_group", |b| {
        b.iter(|| parse_gemfile(black_box(multi_group), &uri));
    });

    group.bench_function("nested_structure", |b| {
        b.iter(|| parse_gemfile(black_box(nested_structure), &uri));
    });

    group.finish();
}

/// Benchmark Gemfile.lock section parsing.
fn bench_lockfile_sections(c: &mut Criterion) {
    let mut group = c.benchmark_group("lockfile_sections");

    // GEM section only
    let gem_section = r"GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.8)
    pg (1.5.4)
    puma (6.4.0)

DEPENDENCIES
  rails

BUNDLED WITH
   2.5.3
";

    // GIT section
    let git_section = r"GIT
  remote: https://github.com/rails/rails.git
  revision: abc123def456
  specs:
    rails (7.1.0.alpha)

DEPENDENCIES
  rails!

BUNDLED WITH
   2.5.3
";

    // PATH section
    let path_section = r"PATH
  remote: ../local_gem
  specs:
    local_gem (0.1.0)

DEPENDENCIES
  local_gem!

BUNDLED WITH
   2.5.3
";

    group.bench_function("gem_section", |b| {
        b.iter(|| parse_gemfile_lock(black_box(gem_section)));
    });

    group.bench_function("git_section", |b| {
        b.iter(|| parse_gemfile_lock(black_box(git_section)));
    });

    group.bench_function("path_section", |b| {
        b.iter(|| parse_gemfile_lock(black_box(path_section)));
    });

    group.finish();
}

/// Benchmark parsing with comments.
fn bench_comment_handling(c: &mut Criterion) {
    let uri = bench_uri();

    let with_comments = r"source 'https://rubygems.org'

# Ruby version
ruby '3.2.2'

# Main framework
gem 'rails', '~> 7.0'

# Database
gem 'pg', '>= 1.1'

# Web server
gem 'puma', '~> 6.0'

# Development tools
group :development do
  # Debugging
  gem 'pry-rails'
  # Linting
  gem 'rubocop', require: false
  # gem 'disabled_gem' # commented out
end
";

    c.bench_function("parsing_with_comments", |b| {
        b.iter(|| parse_gemfile(black_box(with_comments), &uri));
    });
}

/// Benchmark Unicode handling in Gemfile.
fn bench_unicode_parsing(c: &mut Criterion) {
    let uri = bench_uri();

    let unicode_gemfile = r"source 'https://rubygems.org'

# Project with Unicode: 日本語
ruby '3.2.2'

gem 'rails', '~> 7.0'  # Веб-фреймворк
gem 'pg', '>= 1.1'     # База данных
";

    c.bench_function("unicode_parsing", |b| {
        b.iter(|| parse_gemfile(black_box(unicode_gemfile), &uri));
    });
}

criterion_group!(
    benches,
    bench_gemfile_parsing,
    bench_position_tracking,
    bench_gemfile_lock_parsing,
    bench_gem_formats,
    bench_group_blocks,
    bench_lockfile_sections,
    bench_comment_handling,
    bench_unicode_parsing
);
criterion_main!(benches);
