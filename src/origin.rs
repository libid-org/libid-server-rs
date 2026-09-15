//! A configured origin in its canonical form: what every origin this bridge
//! admits, publishes or dials is checked into, once, at startup.

use std::fmt;

use serde::Serialize;
use url::Url;

use crate::error::{
    Error,
    Result,
};

/// A canonical origin: `https`, or `http` on exactly `localhost` or
/// `127.0.0.1`; a host and nothing after it; lowercase host, no default port;
/// made only of the bytes an origin is made of. Its two constructors are the
/// only way to get one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct Origin(String);

impl Origin {
    /// `spelling` folded to its canonical form: `Url::origin` lowercases the
    /// host and drops a default port. A refusal names `field`.
    pub(crate) fn parse(field: &str, spelling: &str) -> Result<Origin> {
        let url = Url::parse(spelling).map_err(|e| Error::Config {
            detail: format!("{field} {spelling}: {e}"),
        })?;
        let refuse = |why: &str| Error::Config {
            detail: format!(
                "{field} {spelling} {why}; it must be a bare origin, \
                 as in https://id.example.com"
            ),
        };
        if !matches!(url.scheme(), "http" | "https") {
            return Err(refuse("is not http or https"));
        }
        if url.host().is_none() {
            return Err(refuse("names no host"));
        }
        if !matches!(url.path(), "" | "/") {
            return Err(refuse("carries a path"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(refuse("carries a query or fragment"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(refuse("carries credentials"));
        }
        if url.scheme() == "http" && !is_plaintext_loopback(&url) {
            return Err(refuse(
                "is plaintext http on a host that is not localhost or 127.0.0.1",
            ));
        }
        // `;`, quotes and other bytes a Content-Security-Policy reads as syntax
        // are refused: the CCDP origin is spliced into `script-src` and
        // `frame-src`.
        let origin = url.origin().ascii_serialization();
        if !origin
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:[]/".contains(&b))
        {
            return Err(refuse(
                "carries a byte an origin is not made of, which a \
                 Content-Security-Policy would read as syntax",
            ));
        }
        Ok(Origin(origin))
    }

    /// `spelling` as written: refused unless it is already canonical, with
    /// the canonical spelling named rather than folded to.
    pub(crate) fn listed(field: &str, spelling: &str) -> Result<Origin> {
        let origin = Origin::parse(field, spelling)?;
        if origin.as_str() != spelling {
            return Err(Error::Config {
                detail: format!(
                    "{field} {spelling} is not canonical; write it as {origin}"
                ),
            });
        }
        Ok(origin)
    }

    /// The canonical spelling.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `url` is plaintext `http` on exactly `localhost` or `127.0.0.1`:
/// the one case a canonical origin is not HTTPS.
fn is_plaintext_loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `parse` folds; `listed` refuses what is not already canonical and names
    /// the spelling to write.
    #[test]
    fn parse_folds_and_listed_refuses_the_unfolded() {
        let folded = Origin::parse("T", "https://Bridge.example:443/").unwrap();
        assert_eq!(folded.as_str(), "https://bridge.example");
        assert_eq!(folded.to_string(), "https://bridge.example");

        let refusal = Origin::listed("T", "https://Bridge.example:443/").unwrap_err();
        assert!(
            refusal
                .to_string()
                .contains("write it as https://bridge.example"),
            "{refusal}"
        );
        assert_eq!(
            Origin::listed("T", "https://bridge.example").unwrap(),
            folded
        );
    }

    /// Plaintext `http` is admitted on exactly `localhost` and `127.0.0.1`,
    /// and refused everywhere else.
    #[test]
    fn plaintext_is_admitted_for_loopback_and_refused_everywhere_else() {
        for spelling in ["http://127.0.0.1:8722", "http://localhost:3000"] {
            assert!(Origin::parse("T", spelling).is_ok(), "{spelling}");
        }
        for spelling in [
            "http://[::1]:8722",
            "http://127.0.0.2:8722",
            "http://10.0.0.1",
            "http://192.168.1.1:8722",
            "http://app.example",
        ] {
            assert!(Origin::parse("T", spelling).is_err(), "{spelling}");
        }
    }

    /// An underscore in a host is admitted; the bytes a Content-Security-Policy
    /// reads as syntax are refused.
    #[test]
    fn an_underscore_in_a_host_is_an_origin_like_any_other() {
        for spelling in [
            "https://dev_box.example",
            "https://app_staging.example:8443",
        ] {
            assert!(Origin::parse("T", spelling).is_ok(), "{spelling}");
        }
        for hostile in ["https://a;b.example", "https://a'b.example"] {
            assert!(Origin::parse("T", hostile).is_err(), "{hostile}");
        }
    }

    /// Anything but a bare `http`/`https` origin with a host is refused,
    /// naming the field.
    #[test]
    fn what_is_not_a_bare_origin_is_refused() {
        for spelling in [
            "not an origin",
            "",
            "https://",
            "file:///etc/passwd",
            // Special schemes with a known default port, which `Url` drops.
            "ftp://dist.example",
            "ws://dist.example",
            "https://app.example/path",
            "https://app.example/?q=1",
            "https://app.example/#f",
            "https://user@app.example",
        ] {
            let refusal = Origin::parse("FIELD", spelling).unwrap_err();
            assert!(
                refusal.to_string().contains("FIELD"),
                "{spelling}: {refusal}"
            );
        }
    }
}
