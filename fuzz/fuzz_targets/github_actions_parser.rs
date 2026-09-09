//! Fuzzes `deps_github_actions::parse_workflow_yaml`, the event-driven
//! (`MarkedEventReceiver`) YAML parser for both of #718's routed manifest shapes:
//! `.github/workflows/*.yml` workflows and `action.yml`/`action.yaml` composite actions.
//!
//! Property under test: never panics for any byte input, valid YAML or not, on either
//! entry point — including the marker-to-`Range` byte-offset slicing the parser does for
//! every `uses:` candidate.

#![no_main]

use deps_github_actions::parse_workflow_yaml;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

static WORKFLOW_URI: LazyLock<Uri> = LazyLock::new(|| {
    Uri::from_file_path("/fuzz/.github/workflows/ci.yml").expect("static fixture path")
});
static ACTION_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/action.yml").expect("static fixture path"));

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_workflow_yaml(content, &WORKFLOW_URI);
    let _ = parse_workflow_yaml(content, &ACTION_URI);
});
