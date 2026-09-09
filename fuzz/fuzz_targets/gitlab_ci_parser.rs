//! Fuzzes `deps_gitlab_ci::parse_gitlab_ci_yaml`, the `.gitlab-ci.yml` event-driven
//! (`MarkedEventReceiver`) YAML parser — the same hand-rolled `Vec<Frame>` state-machine
//! shape as `deps-github-actions`'s workflow parser.
//!
//! Property under test: never panics for any byte input, valid YAML or not, including the
//! marker-to-`Range` byte-offset slicing done for every `include:`/`component:` candidate.
//! Two disconnected [`GitlabInstanceHost`]s are shared across every call (hoisted to
//! `LazyLock`s instead of rebuilt per input) — one permanently `Unset` (`raw` stays `None`)
//! and one permanently `Set` to a fixed, harmless host string, so every input is parsed
//! against both states of `registries.gitlab_instance_host`. Both are configuration-only,
//! never derived from fuzz input, so no network access is ever attempted regardless of
//! input content. Driving only the `Unset` state would leave `resolve_project_host`'s/
//! `resolve_component_host`'s `Some` branch — including `GitlabHost::parse`'s own
//! URL-structural-character rejection and policy-gated host validation, per
//! `crate::parser`'s own `test_component_ci_server_fqdn_resolves_when_instance_host_set`
//! test — permanently dead to the fuzzer (code-review finding).

#![no_main]

use deps_core::net_policy::RegistryAccessPolicy;
use deps_gitlab_ci::{GitlabInstanceHost, parse_gitlab_ci_yaml};
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, LazyLock, RwLock};
use tower_lsp_server::ls_types::Uri;

static FUZZ_URI: LazyLock<Uri> =
    LazyLock::new(|| Uri::from_file_path("/fuzz/.gitlab-ci.yml").expect("static fixture path"));
static POLICY: LazyLock<RegistryAccessPolicy> = LazyLock::new(RegistryAccessPolicy::default);
static INSTANCE_HOST_UNSET: LazyLock<GitlabInstanceHost> = LazyLock::new(|| {
    GitlabInstanceHost::new(
        Arc::new(RwLock::new(None)),
        Arc::new(RegistryAccessPolicy::default()),
    )
});
static INSTANCE_HOST_SET: LazyLock<GitlabInstanceHost> = LazyLock::new(|| {
    GitlabInstanceHost::new(
        Arc::new(RwLock::new(Some("gitlab.example.com".to_string()))),
        Arc::new(RegistryAccessPolicy::default()),
    )
});

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_gitlab_ci_yaml(content, &FUZZ_URI, &POLICY, &INSTANCE_HOST_UNSET);
    let _ = parse_gitlab_ci_yaml(content, &FUZZ_URI, &POLICY, &INSTANCE_HOST_SET);
});
