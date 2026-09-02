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
    let server_origin = cfg.base_url.trim_end_matches('/').to_string();

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
        allowed_app_origins: cfg.allowed_origin_patterns(),
        notary_addr: notary_addr(&cfg.notary_url)?,
        app_url: (!cfg.app_url.is_empty()).then(|| cfg.app_url.clone()),
        server_origin,
    }))
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
    /// callback route under the configured base URL — including when that base
    /// URL is given with a trailing slash.
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
