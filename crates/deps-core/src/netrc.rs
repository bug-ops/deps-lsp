//! `.netrc` parsing and host lookup, following SwiftPM's `Netrc.swift` grammar.
//!
//! The grammar is token-level: a value is either `"..."` (no escapes) or a run of non-whitespace
//! characters, and `#` starts a comment only when preceded by whitespace. An entry is
//! `machine NAME` or `default`, followed contiguously by `login V [account A] password V` or
//! `password V [account A] login V`. Tokens that fit no entry (including `macdef` bodies) are
//! skipped, and an entry missing its login or password is dropped. Keywords are case-sensitive.
//!
//! Not replicated: SwiftPM's character-level regex quirks (a keyword embedded inside another
//! token, the replace-all way it strips comments); they only matter for malformed files.
//!
//! How hosts are matched depends on where the content came from, see [`NetrcFlavor`].

use thiserror::Error;
use url::{Host, Url};

use crate::secret::Redacted;

/// Whether a `default` entry applies to hosts that have no `machine` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultEntry {
    /// The `default` entry is used as the fallback login.
    Honor,
    /// The `default` entry is parsed and validated but never used for a lookup.
    Ignore,
}

/// The source a netrc was read from, which fixes SwiftPM's duplicate-machine and case rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetrcFlavor {
    /// In-memory content (`SWIFTPM_NETRC_DATA`): first matching machine wins, host names compare
    /// case-sensitively, `default` is always honored.
    InMemory,
    /// A netrc file (`~/.netrc`): last matching machine wins, host names compare
    /// case-insensitively, `default` per `default_entry`.
    File {
        /// Whether the `default` entry is used for lookups.
        default_entry: DefaultEntry,
    },
}

/// Why netrc content was rejected as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NetrcError {
    /// No `machine` or `default` entry could be read.
    #[error("netrc holds no usable machine entry")]
    NoMachines,
    /// A `default` entry is followed by another entry.
    #[error("netrc default entry is not the last entry")]
    DefaultNotLast,
}

/// A login and password read from a netrc entry; `Debug` never prints either.
#[derive(Debug, Clone)]
pub struct NetrcLogin {
    login: Redacted,
    password: Redacted,
}

impl NetrcLogin {
    /// The login name.
    #[must_use]
    pub const fn login(&self) -> &Redacted {
        &self.login
    }

    /// The password.
    #[must_use]
    pub const fn password(&self) -> &Redacted {
        &self.password
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MachineName {
    Host(String),
    Default,
}

#[derive(Debug, Clone)]
struct Machine {
    name: MachineName,
    login: NetrcLogin,
}

/// A parsed netrc: the entries in file order, plus the [`NetrcFlavor`] that governs lookups.
///
/// # Examples
///
/// ```
/// use deps_core::netrc::{Netrc, NetrcFlavor};
/// use url::Url;
///
/// let netrc = Netrc::parse(
///     "machine swift.acme.dev login deploy password hunter2",
///     NetrcFlavor::InMemory,
/// )
/// .unwrap();
/// let url = Url::parse("https://swift.acme.dev/api").unwrap();
/// assert!(netrc.login_for(&url).is_some());
/// assert!(netrc.login_for(&Url::parse("https://other.dev/").unwrap()).is_none());
/// assert!(!format!("{netrc:?}").contains("hunter2"));
/// ```
#[derive(Clone)]
pub struct Netrc {
    machines: Vec<Machine>,
    flavor: NetrcFlavor,
}

impl std::fmt::Debug for Netrc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Netrc")
            .field("machines", &self.machines.len())
            .field("flavor", &self.flavor)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
enum Token<'a> {
    Word(&'a str),
    Quoted(&'a str),
}

impl<'a> Token<'a> {
    const fn text(self) -> &'a str {
        match self {
            Self::Word(text) | Self::Quoted(text) => text,
        }
    }

    fn is_keyword(self, keyword: &str) -> bool {
        matches!(self, Self::Word(text) if text == keyword)
    }
}

fn tokenize(content: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut rest = content;
    let mut preceded_by_whitespace = false;
    loop {
        let trimmed = rest.trim_start();
        preceded_by_whitespace |= trimmed.len() != rest.len();
        rest = trimmed;
        let Some(first) = rest.chars().next() else {
            return tokens;
        };
        if first == '#' && preceded_by_whitespace {
            rest = rest.find('\n').map_or("", |end| rest.split_at(end).1);
            continue;
        }
        preceded_by_whitespace = false;
        if let Some((value, tail)) = rest
            .strip_prefix('"')
            .and_then(|quoted| quoted.split_once('"'))
        {
            tokens.push(Token::Quoted(value));
            rest = tail;
            continue;
        }
        let (word, tail) = rest.split_at(rest.find(char::is_whitespace).unwrap_or(rest.len()));
        tokens.push(Token::Word(word));
        rest = tail;
    }
}

/// Reads `login V [account A] password V` or `password V [account A] login V` at the start of
/// `tokens`, returning the login and the number of tokens consumed.
fn read_credentials(tokens: &[Token<'_>]) -> Option<(NetrcLogin, usize)> {
    let value_after = |index: usize, keyword: &str| -> Option<&str> {
        let [key, value] = tokens.get(index..index + 2)? else {
            return None;
        };
        key.is_keyword(keyword).then(|| value.text())
    };
    let first_is_login = tokens.first()?.is_keyword("login");
    let (first_keyword, second_keyword) = if first_is_login {
        ("login", "password")
    } else {
        ("password", "login")
    };
    let first = value_after(0, first_keyword)?;
    let mut consumed = 2;
    if let [key, value] = tokens.get(consumed..consumed + 2)?
        && key.is_keyword("account")
    {
        if matches!(value, Token::Quoted(text) if text.contains(char::is_whitespace)) {
            return None;
        }
        consumed += 2;
    }
    let second = value_after(consumed, second_keyword)?;
    consumed += 2;
    let (login, password) = if first_is_login {
        (first, second)
    } else {
        (second, first)
    };
    Some((
        NetrcLogin {
            login: Redacted::new(login.to_string()),
            password: Redacted::new(password.to_string()),
        },
        consumed,
    ))
}

fn read_machines(tokens: &[Token<'_>]) -> Vec<Machine> {
    let mut machines = Vec::new();
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        let (name, header_len) = if token.is_keyword("default") {
            (Some(MachineName::Default), 1)
        } else if token.is_keyword("machine") {
            let name = tokens
                .get(index + 1)
                .map(|name| MachineName::Host(name.text().to_string()));
            (name, 2)
        } else {
            index += 1;
            continue;
        };
        let credentials = name
            .zip(tokens.get(index + header_len..))
            .and_then(|(name, rest)| read_credentials(rest).map(|found| (name, found)));
        if let Some((name, (login, consumed))) = credentials {
            machines.push(Machine { name, login });
            index += header_len + consumed;
        } else {
            index += 1;
        }
    }
    machines
}

/// The bare host of `url` as netrc names it: IPv6 literals without brackets.
fn bare_host(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(domain) => Some(domain.to_string()),
        Host::Ipv4(addr) => Some(addr.to_string()),
        Host::Ipv6(addr) => Some(addr.to_string()),
    }
}

impl Netrc {
    /// Parses `content` under `flavor`.
    ///
    /// # Errors
    ///
    /// [`NetrcError::NoMachines`] when no entry could be read, [`NetrcError::DefaultNotLast`]
    /// when a `default` entry is followed by another entry.
    pub fn parse(content: &str, flavor: NetrcFlavor) -> Result<Self, NetrcError> {
        let machines = read_machines(&tokenize(content));
        if machines.is_empty() {
            return Err(NetrcError::NoMachines);
        }
        let default_position = machines
            .iter()
            .position(|machine| machine.name == MachineName::Default);
        if default_position.is_some_and(|position| position + 1 != machines.len()) {
            return Err(NetrcError::DefaultNotLast);
        }
        Ok(Self { machines, flavor })
    }

    /// The login for `url`'s host, per the rules of this netrc's [`NetrcFlavor`]; the port is
    /// ignored.
    #[must_use]
    pub fn login_for(&self, url: &Url) -> Option<&NetrcLogin> {
        let host = bare_host(url)?;
        let named = |machine: &&Machine| match (&machine.name, self.flavor) {
            (MachineName::Host(name), NetrcFlavor::InMemory) => *name == host,
            (MachineName::Host(name), NetrcFlavor::File { .. }) => name.eq_ignore_ascii_case(&host),
            (MachineName::Default, _) => false,
        };
        let matched = match self.flavor {
            NetrcFlavor::InMemory => self.machines.iter().find(named),
            NetrcFlavor::File { .. } => self.machines.iter().rev().find(named),
        };
        let uses_default = match self.flavor {
            NetrcFlavor::InMemory
            | NetrcFlavor::File {
                default_entry: DefaultEntry::Honor,
            } => true,
            NetrcFlavor::File {
                default_entry: DefaultEntry::Ignore,
            } => false,
        };
        matched
            .or_else(|| {
                uses_default
                    .then(|| {
                        self.machines
                            .iter()
                            .find(|machine| machine.name == MachineName::Default)
                    })
                    .flatten()
            })
            .map(|machine| &machine.login)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: NetrcFlavor = NetrcFlavor::File {
        default_entry: DefaultEntry::Honor,
    };

    fn parse(content: &str, flavor: NetrcFlavor) -> Result<Netrc, NetrcError> {
        Netrc::parse(content, flavor)
    }

    fn lookup(netrc: &Netrc, url: &str) -> Option<(String, String)> {
        netrc.login_for(&Url::parse(url).unwrap()).map(|found| {
            (
                found.login().expose_secret().to_string(),
                found.password().expose_secret().to_string(),
            )
        })
    }

    fn pair(login: &str, password: &str) -> Option<(String, String)> {
        Some((login.to_string(), password.to_string()))
    }

    #[test]
    fn test_entry_shapes() {
        let cases = [
            ("machine a.dev login u password p", pair("u", "p")),
            ("machine a.dev password p login u", pair("u", "p")),
            ("machine a.dev login u account x password p", pair("u", "p")),
            ("machine a.dev password p account x login u", pair("u", "p")),
            (
                r#"machine a.dev login u account "x" password p"#,
                pair("u", "p"),
            ),
            ("machine\na.dev\n\tlogin u\n\tpassword p\n", pair("u", "p")),
            (
                r#"machine a.dev login "u v" password "p # q""#,
                pair("u v", "p # q"),
            ),
            ("machine a.dev login u password p#q", pair("u", "p#q")),
        ];
        for (content, expected) in cases {
            let netrc = parse(content, NetrcFlavor::InMemory).unwrap();
            assert_eq!(lookup(&netrc, "https://a.dev/"), expected, "{content}");
        }
    }

    #[test]
    fn test_entries_that_do_not_match_are_dropped() {
        let dropped = [
            "machine a.dev login u",
            "machine a.dev password p",
            "machine a.dev foo login u password p",
            "machine a.dev login u foo password p",
            r#"machine a.dev login u account "x y" password p"#,
            "Machine a.dev login u password p",
            "machine a.dev LOGIN u password p",
        ];
        for content in dropped {
            let with_survivor = format!("{content}\nmachine b.dev login ok password ok");
            let netrc = parse(&with_survivor, NetrcFlavor::InMemory).unwrap();
            assert_eq!(lookup(&netrc, "https://a.dev/"), None, "{content}");
            assert_eq!(
                lookup(&netrc, "https://b.dev/"),
                pair("ok", "ok"),
                "{content}"
            );
        }
    }

    #[test]
    fn test_comments() {
        let content = "# leading words\nmachine a.dev # trailing\nlogin u password p";
        let netrc = parse(content, NetrcFlavor::InMemory).unwrap();
        assert_eq!(lookup(&netrc, "https://a.dev/"), pair("u", "p"));

        let at_offset_zero = parse("#machine a.dev login u password p", NetrcFlavor::InMemory);
        assert_eq!(at_offset_zero.unwrap_err(), NetrcError::NoMachines);

        let inside_token = parse("machine a.dev login u#v password p", NetrcFlavor::InMemory);
        assert_eq!(
            lookup(&inside_token.unwrap(), "https://a.dev/"),
            pair("u#v", "p")
        );
    }

    #[test]
    fn test_quoted_value_never_mints_a_machine() {
        let content = r#"machine a.dev login u password "x machine evil.dev login e password e""#;
        let netrc = parse(content, NetrcFlavor::InMemory).unwrap();
        assert_eq!(lookup(&netrc, "https://evil.dev/"), None);
        assert_eq!(
            lookup(&netrc, "https://a.dev/").map(|(_, password)| password),
            Some("x machine evil.dev login e password e".to_string())
        );
    }

    #[test]
    fn test_unmatched_tokens_and_macdef_bodies_are_skipped() {
        let content = "macdef init\nbogus line\nmachine a.dev login u password p";
        let netrc = parse(content, NetrcFlavor::InMemory).unwrap();
        assert_eq!(lookup(&netrc, "https://a.dev/"), pair("u", "p"));
    }

    #[test]
    fn test_whole_file_errors() {
        assert_eq!(parse("", FILE).unwrap_err(), NetrcError::NoMachines);
        assert_eq!(
            parse("machine a.dev login u", FILE).unwrap_err(),
            NetrcError::NoMachines
        );
        assert_eq!(
            parse(
                "default login d password d\nmachine a.dev login u password p",
                FILE
            )
            .unwrap_err(),
            NetrcError::DefaultNotLast
        );
        assert!(
            parse(
                "machine a.dev login u password p\ndefault login d password d",
                FILE
            )
            .is_ok()
        );
    }

    #[test]
    fn test_in_memory_flavor_first_wins_case_sensitive_and_honors_default() {
        let content = "machine a.dev login first password 1\n\
                       machine a.dev login second password 2\n\
                       machine B.dev login upper password 3\n\
                       default login d password d";
        let netrc = parse(content, NetrcFlavor::InMemory).unwrap();
        assert_eq!(lookup(&netrc, "https://a.dev/"), pair("first", "1"));
        assert_eq!(lookup(&netrc, "https://b.dev/"), pair("d", "d"));
        assert_eq!(lookup(&netrc, "https://unknown.dev/"), pair("d", "d"));
    }

    #[test]
    fn test_file_flavor_last_wins_case_insensitive() {
        let content = "machine a.dev login first password 1\n\
                       machine A.DEV login second password 2\n\
                       default login d password d";
        let netrc = parse(content, FILE).unwrap();
        assert_eq!(lookup(&netrc, "https://a.dev/"), pair("second", "2"));
        assert_eq!(lookup(&netrc, "https://unknown.dev/"), pair("d", "d"));
    }

    #[test]
    fn test_file_flavor_can_ignore_the_default_entry() {
        let content = "machine a.dev login u password p\ndefault login d password d";
        let flavor = NetrcFlavor::File {
            default_entry: DefaultEntry::Ignore,
        };
        let netrc = parse(content, flavor).unwrap();
        assert_eq!(lookup(&netrc, "https://a.dev/"), pair("u", "p"));
        assert_eq!(lookup(&netrc, "https://unknown.dev/"), None);
    }

    #[test]
    fn test_port_is_ignored_and_ipv6_hosts_compare_without_brackets() {
        let content = "machine a.dev login u password p\n\
                       machine 2001:db8::1 login six password 6";
        let netrc = parse(content, NetrcFlavor::InMemory).unwrap();
        assert_eq!(lookup(&netrc, "https://a.dev:8443/api"), pair("u", "p"));
        assert_eq!(
            lookup(&netrc, "https://[2001:db8::1]:8443/api"),
            pair("six", "6")
        );
    }

    #[test]
    fn test_debug_never_prints_a_credential() {
        let netrc = parse("machine a.dev login deploy password hunter2", FILE).unwrap();
        let found = netrc
            .login_for(&Url::parse("https://a.dev/").unwrap())
            .unwrap();
        for rendered in [format!("{netrc:?}"), format!("{found:?}")] {
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert!(!rendered.contains("deploy"), "{rendered}");
        }
    }
}
