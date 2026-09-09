//! Fuzzes `deps_nuget::parser`'s three manifest entry points — `.csproj`/`.fsproj`/
//! `.vbproj` (`parse_project_file`), `Directory.Packages.props`
//! (`parse_directory_packages_props`), and `packages.config` (`parse_packages_config`)
//! (#691).
//!
//! Property under test: none of the three ever panics for any byte input, valid XML or
//! not.

#![no_main]

use deps_nuget::parser::{
    parse_directory_packages_props, parse_packages_config, parse_project_file,
};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

static CSPROJ_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/App.csproj").expect("static fixture path"));
static DIRECTORY_PACKAGES_URI: LazyLock<Uri> = LazyLock::new(|| {
    Uri::from_file_path("/fuzz/Directory.Packages.props").expect("static fixture path")
});
static PACKAGES_CONFIG_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/packages.config").expect("static fixture path"));

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_project_file(content, &CSPROJ_URI);
    let _ = parse_directory_packages_props(content, &DIRECTORY_PACKAGES_URI);
    let _ = parse_packages_config(content, &PACKAGES_CONFIG_URI);
});
