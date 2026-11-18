//! #2072: every NuGet `PackageReference` is a production dependency (`PrivateAssets` is not
//! stored).

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

#[test]
fn kind_is_normal_for_every_package_reference() {
    let uri = url::Url::from_file_path("/project/App.csproj").expect("uri");
    let project = r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" PrivateAssets="all" />
  </ItemGroup>
</Project>
"#;
    let result = deps_nuget::parse_project_file(project, &uri).expect("parse");

    let dependencies = result.dependencies();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].kind(), Some(DependencyKind::Normal));
}
