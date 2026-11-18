//! Operator-selected OSV endpoint (`DEPS_OSV_BASE_URL`).

use std::net::IpAddr;

use url::{Host, Url};

use crate::net_policy::{EnvSource, TrustedPrefix, classify_host};

/// Environment variable naming an operator-supplied OSV base URL.
pub const OSV_BASE_URL_ENV: &str = "DEPS_OSV_BASE_URL";

/// Validated base URL of an operator-supplied OSV endpoint.
///
/// Has no public constructor; only [`OsvEndpoint::from_env`] produces one, so a plain-HTTP
/// waiver can never be minted from repository content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorOrigin {
    base: String,
    prefix: TrustedPrefix,
}

impl OperatorOrigin {
    /// The base URL without a trailing slash.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    pub(crate) const fn prefix(&self) -> &TrustedPrefix {
        &self.prefix
    }

    /// Whether plain `http` is waived for `url`: only for the exact scheme, host and port of
    /// an `http` operator base (validated at construction as a loopback IP literal).
    pub(crate) fn permits_plain_http(&self, url: &str) -> bool {
        let base = self.prefix.as_url();
        base.scheme() == "http"
            && Url::parse(url).is_ok_and(|parsed| parsed.origin() == base.origin())
    }
}

/// Which OSV endpoint the client talks to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsvEndpoint {
    /// The public `api.osv.dev` endpoint.
    Public,
    /// An operator-supplied endpoint validated from the environment.
    Operator(OperatorOrigin),
}

/// Why a `DEPS_OSV_BASE_URL` value was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OsvEndpointError {
    /// The value is not valid Unicode.
    #[error("invalid DEPS_OSV_BASE_URL: value is not valid Unicode")]
    NotUnicode,
    /// The value is not an absolute URL.
    #[error("invalid DEPS_OSV_BASE_URL: value is not an absolute URL")]
    Unparseable,
    /// The URL carries userinfo, a query or a fragment.
    #[error("invalid DEPS_OSV_BASE_URL: userinfo, query and fragment are not allowed")]
    ForbiddenComponent,
    /// The scheme is neither `https` nor `http`.
    #[error("invalid DEPS_OSV_BASE_URL: only https (or http to a loopback IP literal) is allowed")]
    UnsupportedScheme,
    /// Plain `http` to anything but a loopback IP literal.
    #[error("invalid DEPS_OSV_BASE_URL: http is only allowed to a loopback IP literal")]
    PlainHttpNotLoopback,
    /// The host is loopback, link-local, metadata or otherwise never a registry.
    #[error("invalid DEPS_OSV_BASE_URL: host is not an acceptable remote endpoint")]
    BlockedHost,
}

impl OsvEndpoint {
    /// Reads `DEPS_OSV_BASE_URL` from `env`; unset or empty selects [`OsvEndpoint::Public`].
    ///
    /// Accepts `https` to any host except loopback, link-local, cloud-metadata and unspecified
    /// addresses, or `http` to a loopback IP literal. Rejects userinfo, query and fragment.
    ///
    /// # Errors
    ///
    /// Returns [`OsvEndpointError`] when the value is not an acceptable base URL.
    pub fn from_env(env: &impl EnvSource) -> Result<Self, OsvEndpointError> {
        let Some(raw) = env.var_os(OSV_BASE_URL_ENV) else {
            return Ok(Self::Public);
        };
        let raw = raw
            .into_string()
            .map_err(|_| OsvEndpointError::NotUnicode)?;
        if raw.is_empty() {
            return Ok(Self::Public);
        }
        let url = Url::parse(&raw).map_err(|_| OsvEndpointError::Unparseable)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(OsvEndpointError::ForbiddenComponent);
        }
        match url.scheme() {
            "https" => {
                if classify_host(&url).never_a_registry() {
                    return Err(OsvEndpointError::BlockedHost);
                }
            }
            "http" => {
                let loopback_literal = match url.host() {
                    Some(Host::Ipv4(v4)) => IpAddr::V4(v4).is_loopback(),
                    Some(Host::Ipv6(v6)) => IpAddr::V6(v6).is_loopback(),
                    Some(Host::Domain(_)) | None => false,
                };
                if !loopback_literal {
                    return Err(OsvEndpointError::PlainHttpNotLoopback);
                }
            }
            _ => return Err(OsvEndpointError::UnsupportedScheme),
        }
        let base = url.as_str().trim_end_matches('/').to_owned();
        let prefix =
            TrustedPrefix::parse(&format!("{base}/")).map_err(|_| OsvEndpointError::Unparseable)?;
        Ok(Self::Operator(OperatorOrigin { base, prefix }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::net_policy::MapEnv;

    fn parse(value: &str) -> Result<OsvEndpoint, OsvEndpointError> {
        OsvEndpoint::from_env(&MapEnv::new().with_var(OSV_BASE_URL_ENV, value))
    }

    fn operator(value: &str) -> OperatorOrigin {
        match parse(value).expect("valid") {
            OsvEndpoint::Operator(origin) => origin,
            OsvEndpoint::Public => unreachable!("value is set"),
        }
    }

    #[test]
    fn base_has_no_trailing_slash() {
        assert_eq!(
            operator("https://osv.example.com/mirror/").base(),
            "https://osv.example.com/mirror"
        );
    }

    #[test]
    fn plain_http_waiver_covers_only_the_exact_origin() {
        let origin = operator("http://127.0.0.1:8080/mirror");
        assert!(origin.permits_plain_http("http://127.0.0.1:8080/v1/query"));
        assert!(!origin.permits_plain_http("http://127.0.0.1:8081/v1/query"));
        assert!(!origin.permits_plain_http("http://127.0.0.2:8080/v1/query"));
        assert!(!origin.permits_plain_http("http://localhost:8080/v1/query"));
        assert!(!origin.permits_plain_http("https://127.0.0.1:8080/v1/query"));
        assert!(!origin.permits_plain_http("http://127.0.0.1:8080@evil.com/x"));
    }

    #[test]
    fn https_operator_never_waives_plain_http() {
        let origin = operator("https://osv.example.com");
        assert!(!origin.permits_plain_http("http://osv.example.com/v1/query"));
    }

    #[test]
    fn rejection_reasons_are_typed() {
        assert_eq!(
            parse("http://example.com"),
            Err(OsvEndpointError::PlainHttpNotLoopback)
        );
        assert_eq!(
            parse("ftp://example.com"),
            Err(OsvEndpointError::UnsupportedScheme)
        );
        assert_eq!(
            parse("https://a:b@example.com"),
            Err(OsvEndpointError::ForbiddenComponent)
        );
        assert_eq!(
            parse("https://169.254.169.254/"),
            Err(OsvEndpointError::BlockedHost)
        );
        assert_eq!(parse("nope"), Err(OsvEndpointError::Unparseable));
    }
}
