//! #2074 acceptance: `OsvEndpoint::from_env` reads `DEPS_OSV_BASE_URL` through the sealed
//! `EnvSource`. Written tests-first; `deps_core::osv::{OsvEndpoint, OsvEndpointError}` do not
//! exist yet.

#![cfg(feature = "test-util")]

use std::assert_matches;

use deps_core::net_policy::MapEnv;
use deps_core::osv::OsvEndpoint;

const VAR: &str = "DEPS_OSV_BASE_URL";

fn parse(value: Option<&str>) -> Result<OsvEndpoint, deps_core::osv::OsvEndpointError> {
    let env = value.map_or_else(MapEnv::new, |value| MapEnv::new().with_var(VAR, value));
    OsvEndpoint::from_env(&env)
}

#[test]
fn from_env_unset_or_empty_is_the_public_endpoint() {
    assert_matches!(parse(None), Ok(OsvEndpoint::Public));
    assert_matches!(parse(Some("")), Ok(OsvEndpoint::Public));
}

#[test]
fn from_env_accepts_https_and_loopback_ip_literal_http() {
    for value in [
        "https://osv.example.com",
        "https://osv.example.com/mirror/",
        "http://127.0.0.1:8080",
        "http://127.0.0.1",
        "http://[::1]:8080",
    ] {
        assert_matches!(parse(Some(value)), Ok(OsvEndpoint::Operator(_)), "{value}");
    }
}

#[test]
fn from_env_rejects_unsafe_or_malformed_values() {
    for value in [
        "http://example.com",
        "http://10.0.0.1:8080",
        "http://localhost:8080",
        "https://user:pw@osv.example.com",
        "https://osv.example.com/?q=1",
        "https://osv.example.com/#frag",
        "ftp://osv.example.com",
        "https://169.254.169.254/",
        "not a url",
    ] {
        assert!(parse(Some(value)).is_err(), "{value} must be rejected");
    }
}
