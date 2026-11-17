//! `Pipfile` parsing: pipenv's `[packages]` and `[dev-packages]` tables.
//!
//! Entries share Poetry's shape (a version string or an inline table), so they go through
//! the same table parser with `TableDialect::Pipfile` selecting pipenv's key names. Index
//! routing is limited to the first `[[source]]` (the primary index) and a per-package
//! `index = "<name>"` key; both go through the policy-gated [`PypiIndexConfig`] so a private
//! package name is never sent to pypi.org.

use super::pyproject::{IndexContext, TableDialect, parse_toml_document};
use super::{ParseResult, PypiParser};
use crate::config::PypiIndexConfig;
use crate::error::Result;
use crate::types::PypiDependencySection;
use deps_core::lsp_helpers::LineOffsetTable;
use deps_core::net_policy::RegistryAccessPolicy;
use std::cell::RefCell;
use std::collections::HashMap;
use toml_span::value::{Table, Value};
use url::Url;

impl PypiParser {
    /// Parses `Pipfile` content with the default (`public_only`) registry policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML is malformed or nested too deeply. A malformed individual
    /// entry is logged and skipped.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_pypi::parser::PypiParser;
    /// use url::Url;
    ///
    /// let content = "[packages]\nrequests = \"*\"\n\n[dev-packages]\npytest = \">=8\"\n";
    /// let uri = Url::parse("file:///project/Pipfile").unwrap();
    /// let result = PypiParser::new().parse_pipfile(content, &uri).unwrap();
    /// assert_eq!(result.dependencies.len(), 2);
    /// ```
    pub fn parse_pipfile(&self, content: &str, uri: &Url) -> Result<ParseResult> {
        self.parse_pipfile_with_policy(content, uri, &RegistryAccessPolicy::default())
    }

    /// Like [`Self::parse_pipfile`], resolving `[[source]]` declarations against `policy`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::parse_pipfile`].
    pub fn parse_pipfile_with_policy(
        &self,
        content: &str,
        uri: &Url,
        policy: &RegistryAccessPolicy,
    ) -> Result<ParseResult> {
        let doc = parse_toml_document(content)?;
        let line_table = LineOffsetTable::new(content);
        let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

        let mut config = PypiIndexConfig::new();
        if let Some(root) = doc.as_table() {
            collect_pipfile_sources(root, &mut config, policy);
        }
        let no_uv_bindings = HashMap::new();
        let ctx = IndexContext {
            dialect: TableDialect::Pipfile,
            config: &config,
            uv_named_by_dep: &no_uv_bindings,
            blocked_registries: RefCell::new(Vec::new()),
            rejected_registries: RefCell::new(Vec::new()),
        };

        let mut dependencies = Vec::new();
        for (key, section) in [
            ("packages", PypiDependencySection::PipfilePackages),
            ("dev-packages", PypiDependencySection::PipfileDevPackages),
        ] {
            let Some(table) = doc
                .as_table()
                .and_then(|root| root.get(key))
                .and_then(Value::as_table)
            else {
                continue;
            };
            dependencies.extend(self.parse_dependency_table(
                table,
                &section,
                content,
                &line_table,
                &ctx,
                &mut budget,
            ));
        }

        Ok(ParseResult {
            dependencies,
            workspace_root: None,
            uri: uri.clone(),
            document_links: Vec::new(),
            resolved_chains: config.resolved_chains(),
            blocked_registries: ctx.blocked_registries.into_inner(),
            rejected_registries: ctx.rejected_registries.into_inner(),
            dependency_truncation: budget.truncation(),
        })
    }
}

/// Registers every `[[source]]` entry as a named source and the first one as the primary
/// index. An entry missing `name` or `url` is skipped: there is nothing to register it under.
fn collect_pipfile_sources(
    root: &Table<'_>,
    config: &mut PypiIndexConfig,
    policy: &RegistryAccessPolicy,
) {
    let Some(sources) = root.get("source").and_then(Value::as_array) else {
        return;
    };

    let mut primary_set = false;
    for entry in sources {
        let Some(table) = entry.as_table() else {
            continue;
        };
        let (Some(name), Some(url)) = (
            table.get("name").and_then(Value::as_str),
            table.get("url").and_then(Value::as_str),
        ) else {
            continue;
        };

        let resolved = crate::config::resolve_entry(url, policy);
        config.add_named_source_resolved(name.to_string(), resolved.clone());
        if !primary_set {
            config.set_primary_resolved(resolved);
            primary_set = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PypiDependencySource;

    fn uri() -> Url {
        Url::parse("file:///project/Pipfile").unwrap()
    }

    fn parse(content: &str) -> ParseResult {
        PypiParser::new().parse_pipfile(content, &uri()).unwrap()
    }

    #[test]
    fn parses_packages_and_dev_packages() {
        let result = parse(
            "[packages]\nrequests = \"==2.31.0\"\nflask = { version = \">=3\", extras = [\"async\"] }\n\n[dev-packages]\npytest = \"*\"\n",
        );
        let by_name = |n: &str| {
            result
                .dependencies
                .iter()
                .find(|d| d.name.as_str() == n)
                .unwrap()
        };
        assert_eq!(result.dependencies.len(), 3);
        assert_eq!(
            by_name("requests").section,
            PypiDependencySection::PipfilePackages
        );
        assert_eq!(
            by_name("requests")
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("==2.31.0")
        );
        assert!(by_name("requests").version_range.is_some());
        assert_eq!(
            by_name("pytest").section,
            PypiDependencySection::PipfileDevPackages
        );
        assert_eq!(
            by_name("pytest")
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("*")
        );
        let flask = by_name("flask");
        assert_eq!(
            flask
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some(">=3")
        );
        assert_eq!(flask.extras, vec!["async".to_string()]);
        assert!(flask.version_range.is_none());
    }

    #[test]
    fn ignores_requires_and_custom_categories() {
        let result = parse(
            "[requires]\npython_version = \"3.12\"\n\n[docs]\nsphinx = \"*\"\n\n[packages]\nrequests = \"*\"\n",
        );
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn git_path_and_file_entries_are_non_registry() {
        let result = parse(
            "[packages]\na = { git = \"https://example.com/a.git\", ref = \"abc123\" }\nb = { path = \".\", editable = true }\nc = { file = \"https://example.com/c.tar.gz\" }\n",
        );
        let source = |n: &str| {
            result
                .dependencies
                .iter()
                .find(|d| d.name.as_str() == n)
                .unwrap()
                .source
                .clone()
        };
        assert_eq!(
            source("a"),
            PypiDependencySource::Git {
                url: "https://example.com/a.git".into(),
                rev: Some("abc123".into()),
            }
        );
        assert_eq!(source("b"), PypiDependencySource::Path { path: ".".into() });
        assert_eq!(
            source("c"),
            PypiDependencySource::Url {
                url: "https://example.com/c.tar.gz".into()
            }
        );
        assert!(result.dependencies.iter().all(|d| !d.source.is_registry()));
    }

    #[test]
    fn invalid_toml_is_an_error() {
        assert!(
            PypiParser::new()
                .parse_pipfile("[packages", &uri())
                .is_err()
        );
    }

    #[test]
    fn unsupported_entry_is_skipped() {
        let result = parse("[packages]\nbad = 42\nrequests = \"*\"\n");
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn primary_source_routes_unpinned_packages() {
        let result = parse(
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n\n[packages]\nrequests = \"*\"\n",
        );
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.blocked_registries.is_empty());
        assert!(result.rejected_registries.is_empty());
    }

    #[test]
    fn blocked_primary_source_is_reported_for_each_package() {
        let result = parse(
            "[[source]]\nname = \"internal\"\nurl = \"https://169.254.169.254/simple\"\n\n[packages]\nrequests = \"*\"\nflask = { version = \"*\" }\n",
        );
        assert_eq!(result.blocked_registries.len(), 2);
    }

    #[test]
    fn per_package_index_routes_to_named_source_only() {
        let result = parse(
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n\n[[source]]\nname = \"internal\"\nurl = \"https://169.254.169.254/simple\"\n\n[packages]\nrequests = \"*\"\nsecret = { version = \"*\", index = \"internal\" }\n",
        );
        assert_eq!(result.blocked_registries.len(), 1);
        let secret = result
            .dependencies
            .iter()
            .find(|d| d.name.as_str() == "secret")
            .unwrap();
        assert_eq!(result.blocked_registries[0].range, secret.name_range);
    }

    #[test]
    fn poetry_source_key_is_not_a_pipfile_index() {
        let result = parse(
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n\n[[source]]\nname = \"internal\"\nurl = \"https://169.254.169.254/simple\"\n\n[packages]\nrequests = { version = \"*\", source = \"internal\" }\n",
        );
        assert!(result.blocked_registries.is_empty());
    }
}
