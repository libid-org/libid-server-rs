//! Minimal identity/handles backend.
//!
//! Exactly the endpoints the OAuth handle-claim flow needs, and nothing
//! else: the UI does OAuth via this server, the server produces a
//! bind-ready proof via MPC-TLS with the notary, the UI submits the bind
//! on-chain itself. No database, no wallet routes, no sponsor pool, no
//! indexer, no JWKS rotator.

#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod oauth;
pub mod routes;
pub mod state;

use std::sync::Arc;

use error::{
    Error,
    Result,
};
use state::AppState;
use tokio::sync::Semaphore;
use url::Url;

/// Build the shared [`AppState`] from parsed configuration.
///
/// Everything that must be well-formed for a request to succeed is parsed
/// here, so a typo fails at startup rather than on someone's ceremony.
///
/// It holds no key material beyond GitHub's client secret, and signs nothing:
/// the notary signs, and this service carries what it said.
pub fn build_state(cfg: &config::Config) -> Result<Arc<AppState>> {
    if cfg.base_url.is_empty() {
        return Err(Error::Config {
            detail: "BASE_URL must be set \u{2014} it is this service's own origin, \
                     which the GitHub token route checks callers against"
                .into(),
        });
    }
    let server_origin = server_origin(&cfg.base_url)?;

    Ok(Arc::new(AppState {
        github_oauth: oauth::OAuthCredentials {
            client_id: cfg.gh_oauth_client_id.clone(),
            client_secret: cfg.gh_oauth_client_secret.clone(),
            // The registered redirect URI is the callback document this
            // service serves, and the browser sends the same bytes back in the
            // token request. Both sides must spell it identically or GitHub
            // refuses the exchange.
            redirect_uri: format!("{server_origin}/api/v1/ceremony/callback"),
        },
        notary_addr: notary_addr(&cfg.notary_url)?,
        exchange_permits: Arc::new(Semaphore::new(
            routes::github_token::MAX_CONCURRENT_EXCHANGES,
        )),
        server_origin,
    }))
}

/// The origin this service answers on, exactly as a browser spells it.
///
/// The token route compares a request's `Origin` against this string, so
/// anything a browser would not send refuses every legitimate call -- at
/// runtime, on someone's ceremony, which is what parsing it here prevents.
/// `Url::origin` does the spelling: it lowercases the host and drops a default
/// port, both of which browsers do too.
///
/// A base URL carrying a path is refused rather than trimmed. The router mounts
/// at the root, so a path would say this service lives somewhere it does not
/// serve, and the redirect URI derived from it would be one GitHub never sees.
fn server_origin(base_url: &str) -> Result<String> {
    let url = Url::parse(base_url).map_err(|e| Error::Config {
        detail: format!("BASE_URL {base_url}: {e}"),
    })?;
    let refuse = |why: &str| Error::Config {
        detail: format!(
            "BASE_URL {base_url} {why}; it must be a bare origin, \
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
    Ok(url.origin().ascii_serialization())
}

/// The `host:port` of the notary, taken from its configured URL.
///
/// The scheme is not consulted: the Rust prover speaks the notary's raw TCP
/// protocol, and `tcp://` is how the default spells that. What must be there
/// is an authority, because a session cannot be opened without one.
fn notary_addr(url: &Url) -> Result<String> {
    let host = url.host_str().ok_or_else(|| Error::NotaryUrl {
        detail: format!("{url} names no host"),
    })?;
    let port = url.port().ok_or_else(|| Error::NotaryUrl {
        detail: format!("{url} names no port"),
    })?;
    Ok(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(args: &[&str]) -> config::Config {
        let mut argv = vec![
            "libid-server-rs",
            "--gh-oauth-client-id",
            "Iv1.0123456789abcdef",
            "--gh-oauth-client-secret",
            "ghs_secret",
        ];
        argv.extend_from_slice(args);
        <config::Config as clap::Parser>::parse_from(argv)
    }

    /// The redirect URI is derived, not configured, and GitHub refuses an
    /// exchange whose two spellings differ. So it has to be exactly the
    /// callback route under the configured base URL.
    #[test]
    fn the_redirect_uri_is_the_callback_route_under_the_base_url() {
        let state = build_state(&config(&["--base-url", "https://id.example/"])).unwrap();
        assert_eq!(state.server_origin, "https://id.example");
        assert_eq!(
            state.github_oauth.redirect_uri,
            "https://id.example/api/v1/ceremony/callback"
        );
    }

    /// The notary address is resolved once here rather than per ceremony.
    #[test]
    fn the_state_carries_a_connectable_notary_address() {
        let state = build_state(&config(&[])).unwrap();
        assert_eq!(state.notary_addr, "127.0.0.1:7047");
        assert!(build_state(&config(&["--notary-url", "tcp://notary.example"])).is_err());
    }

    /// Whatever the operator writes, the route compares against what a browser
    /// sends -- so the two spellings a browser normalises away are normalised
    /// here rather than becoming a 403 on every call.
    #[test]
    fn a_base_url_is_reduced_to_the_origin_a_browser_would_send() {
        for spelling in [
            "https://id.example.com",
            "https://id.example.com/",
            "https://ID.Example.com",
            "https://id.example.com:443",
        ] {
            assert_eq!(
                server_origin(spelling).unwrap(),
                "https://id.example.com",
                "{spelling}"
            );
        }
        // A non-default port is part of the origin and stays.
        assert_eq!(
            server_origin("http://127.0.0.1:8722").unwrap(),
            "http://127.0.0.1:8722"
        );
    }

    /// Anything a browser never sends as `Origin` is refused at startup. Left
    /// alone, each of these starts cleanly and then refuses every ceremony,
    /// which is the failure this whole function exists to move earlier.
    #[test]
    fn a_base_url_that_is_not_a_bare_origin_stops_the_process() {
        for spelling in [
            "https://id.example.com/ceremony",
            "https://id.example.com?tenant=1",
            "https://id.example.com#frag",
            "https://user:pw@id.example.com",
            "ftp://id.example.com",
            "not a url",
        ] {
            assert!(
                server_origin(spelling).is_err(),
                "{spelling} must be refused"
            );
        }
    }

    /// And the redirect URI GitHub has registered is built on the normalised
    /// form, not on what was typed.
    #[test]
    fn the_redirect_uri_is_built_on_the_normalised_origin() {
        let state =
            build_state(&config(&["--base-url", "https://ID.example.com:443/"])).unwrap();
        assert_eq!(
            state.github_oauth.redirect_uri,
            "https://id.example.com/api/v1/ceremony/callback"
        );
    }

    /// The default spelling, and the one the deployment uses.
    #[test]
    fn a_tcp_notary_url_yields_its_authority() {
        let url = Url::parse("tcp://127.0.0.1:7047").unwrap();
        assert_eq!(notary_addr(&url).unwrap(), "127.0.0.1:7047");
    }

    /// The prover speaks the notary's raw TCP protocol, so there is no port to
    /// infer from a scheme. A URL missing either half is refused at startup
    /// rather than on the first ceremony that reaches it.
    #[test]
    fn a_notary_url_missing_an_authority_is_refused() {
        for spelling in ["tcp://notary.example", "tcp:7047", "file:///notary"] {
            let url = Url::parse(spelling).unwrap();
            assert!(notary_addr(&url).is_err(), "{spelling} names no host:port");
        }
    }
}
