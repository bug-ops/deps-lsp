//! #2072: every GitHub Actions `uses:` reference is a production dependency.

use deps_core::{DependencyKind, ParseResult};

#[test]
fn kind_is_normal_for_every_uses_reference() {
    let uri = url::Url::parse("file:///w/.github/workflows/ci.yml").expect("uri");
    let workflow = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n";
    let result = deps_github_actions::parse_workflow_yaml(workflow, &uri).expect("parse");

    let dependencies = result.dependencies();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].kind(), Some(DependencyKind::Normal));
}
