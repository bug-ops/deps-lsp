//! Benchmarks for NuGet manifest parsing and version operations.
//!
//! Performance targets (based on LSP latency requirements):
//! - Parsing small files (5 refs): < 1ms
//! - Parsing medium files (25 refs): < 5ms
//! - Parsing large files (100+ refs): < 20ms
//! - Version comparison: < 10μs per operation
//! - Range/floating resolution: < 50μs per operation
//! - Flat-container JSON parsing: < 2ms per response

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use deps_nuget::parser::{
    parse_directory_packages_props, parse_packages_config, parse_project_file,
};
use deps_nuget::registry::parse_flat_container;
use deps_nuget::version::{compare_versions, is_prerelease, resolve_float, satisfies};
use std::hint::black_box;
use tower_lsp_server::ls_types::Uri;

fn bench_uri() -> Uri {
    Uri::from_file_path("/bench/App.csproj").unwrap()
}

/// Small `.csproj` with 5 `PackageReference` entries (attribute form).
const SMALL_CSPROJ: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="3.1.1" />
    <PackageReference Include="Polly" Version="8.4.1" />
    <PackageReference Include="AutoMapper" Version="13.0.1" />
    <PackageReference Include="FluentValidation" Version="11.9.0" />
  </ItemGroup>
</Project>"#;

/// Medium `.csproj` with 25 `PackageReference` entries, mixing attribute and child-element
/// forms plus a central package management entry.
fn generate_medium_csproj() -> String {
    let mut content = String::from(
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
"#,
    );
    for i in 0..23 {
        content.push_str(&format!(
            "    <PackageReference Include=\"Package.{i}\" Version=\"{}.{}.{}\" />\n",
            i % 10,
            (i % 5) + 1,
            i % 3
        ));
    }
    content.push_str("    <PackageReference Include=\"ChildForm.Package\"><Version>1.2.3</Version></PackageReference>\n");
    content.push_str("    <PackageReference Include=\"MyCompany.Shared\" />\n");
    content.push_str("  </ItemGroup>\n</Project>");
    content
}

/// Large `.csproj` with 100+ `PackageReference` entries.
fn generate_large_csproj() -> String {
    let mut content = String::from(
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
"#,
    );
    for i in 0..120 {
        content.push_str(&format!(
            "    <PackageReference Include=\"Package.{i}\" Version=\"{}.{}.{}.{}\" />\n",
            i % 10,
            (i % 20) + 1,
            i % 5,
            i % 4
        ));
    }
    content.push_str("  </ItemGroup>\n</Project>");
    content
}

/// `.csproj` exercising every parser edge case in one file: attribute form, child-element
/// form, central package management, unresolved MSBuild property, and a `Condition`
/// attribute containing a literal `Version="` trap.
const COMPLEX_CSPROJ: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog"><Version>3.1.1</Version></PackageReference>
    <PackageReference Include="MyCompany.Shared" />
    <PackageReference Include="AutoMapper" Version="$(AutoMapperVersion)" />
    <PackageReference Include="System.Text.Json" Condition="'$(Foo)' == 'Version=&quot;1.0.0&quot;'" Version="8.0.5" />
  </ItemGroup>
</Project>"#;

fn bench_csproj_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("csproj_parsing");
    let uri = bench_uri();

    group.bench_function("small_5_refs", |b| {
        b.iter(|| parse_project_file(black_box(SMALL_CSPROJ), &uri));
    });

    let medium = generate_medium_csproj();
    group.bench_function("medium_25_refs", |b| {
        b.iter(|| parse_project_file(black_box(&medium), &uri));
    });

    let large = generate_large_csproj();
    group.bench_function("large_120_refs", |b| {
        b.iter(|| parse_project_file(black_box(&large), &uri));
    });

    group.bench_function("complex_mixed_forms", |b| {
        b.iter(|| parse_project_file(black_box(COMPLEX_CSPROJ), &uri));
    });

    group.finish();
}

fn bench_directory_packages_props_parsing(c: &mut Criterion) {
    let uri = Uri::from_file_path("/bench/Directory.Packages.props").unwrap();
    let mut content = String::from("<Project>\n  <ItemGroup>\n");
    for i in 0..25 {
        content.push_str(&format!(
            "    <PackageVersion Include=\"Package.{i}\" Version=\"{}.{}.0\" />\n",
            i % 10,
            (i % 5) + 1
        ));
    }
    content.push_str("  </ItemGroup>\n</Project>");

    c.bench_function("directory_packages_props_25_entries", |b| {
        b.iter(|| parse_directory_packages_props(black_box(&content), &uri));
    });
}

fn bench_packages_config_parsing(c: &mut Criterion) {
    let uri = Uri::from_file_path("/bench/packages.config").unwrap();
    let mut content = String::from("<packages>\n");
    for i in 0..25 {
        content.push_str(&format!(
            "  <package id=\"Package.{i}\" version=\"{}.{}.0\" targetFramework=\"net48\" />\n",
            i % 10,
            (i % 5) + 1
        ));
    }
    content.push_str("</packages>");

    c.bench_function("packages_config_25_entries", |b| {
        b.iter(|| parse_packages_config(black_box(&content), &uri));
    });
}

fn bench_version_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_comparison");

    group.bench_function("simple_versions", |b| {
        b.iter(|| compare_versions(black_box("13.0.1"), black_box("13.0.3")));
    });

    group.bench_function("four_component", |b| {
        b.iter(|| compare_versions(black_box("1.10.0.5"), black_box("1.9.0.20")));
    });

    group.bench_function("prerelease_case_insensitive", |b| {
        b.iter(|| compare_versions(black_box("13.0.0-RC.1"), black_box("13.0.0-rc.2")));
    });

    let versions = [
        "13.0.3",
        "13.0.0-beta1",
        "12.0.1",
        "14.0.0-preview.1",
        "13.0.2",
    ];
    group.bench_function("find_latest_version", |b| {
        b.iter(|| {
            versions
                .iter()
                .max_by(|a, b| compare_versions(black_box(a), black_box(b)))
                .copied()
        });
    });

    group.finish();
}

fn bench_is_prerelease(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_prerelease");

    let labels = [
        ("stable", "13.0.0"),
        ("rtm", "13.0.0-rtm"),
        ("servicing", "8.0.0-servicing.23"),
        ("ci_build", "1.0.0-CI-20240101"),
        ("preview", "7.0.0-preview.1"),
        ("with_build_metadata", "1.0.0+build-with-dash"),
    ];

    for (name, version) in labels {
        group.bench_with_input(BenchmarkId::from_parameter(name), &version, |b, version| {
            b.iter(|| is_prerelease(black_box(version)));
        });
    }

    group.finish();
}

fn bench_satisfies(c: &mut Criterion) {
    let mut group = c.benchmark_group("satisfies");

    let cases = [
        ("bare_floor", "2.0.0", "1.0.0"),
        ("exact_pin", "1.0.0", "[1.0.0]"),
        ("open_minimum", "1.5.0", "[1.0,)"),
        ("bounded", "1.5.0", "[1.0,2.0]"),
    ];

    for (name, version, range) in cases {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(version, range),
            |b, (v, r)| {
                b.iter(|| satisfies(black_box(v), black_box(r)));
            },
        );
    }

    group.finish();
}

fn bench_resolve_float(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve_float");

    let versions: Vec<String> = (0..25).map(|i| format!("1.{}.{}", i % 5, i % 10)).collect();

    group.bench_function("wildcard_any", |b| {
        b.iter(|| resolve_float(black_box(&versions), black_box("*")));
    });

    group.bench_function("numeric_prefix", |b| {
        b.iter(|| resolve_float(black_box(&versions), black_box("1.2.*")));
    });

    group.finish();
}

/// Realistic NuGet flat-container response for a popular package (based on the actual
/// `Newtonsoft.Json` response shape, ~84 versions in production).
fn generate_flat_container_response(count: usize) -> String {
    let mut content = String::from(r#"{"versions": ["#);
    for i in 0..count {
        content.push_str(&format!(
            "\"{}.{}.{}\"{}",
            i % 10,
            (i % 20) + 1,
            i % 5,
            if i + 1 < count { "," } else { "" }
        ));
    }
    content.push_str("]}");
    content
}

fn bench_flat_container_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("flat_container_parsing");

    let small = generate_flat_container_response(10);
    group.bench_function("small_10_versions", |b| {
        b.iter(|| parse_flat_container(black_box(small.as_bytes())));
    });

    let realistic = generate_flat_container_response(84);
    group.bench_function("realistic_84_versions", |b| {
        b.iter(|| parse_flat_container(black_box(realistic.as_bytes())));
    });

    let large = generate_flat_container_response(500);
    group.bench_function("large_500_versions", |b| {
        b.iter(|| parse_flat_container(black_box(large.as_bytes())));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_csproj_parsing,
    bench_directory_packages_props_parsing,
    bench_packages_config_parsing,
    bench_version_comparison,
    bench_is_prerelease,
    bench_satisfies,
    bench_resolve_float,
    bench_flat_container_parsing,
);
criterion_main!(benches);
