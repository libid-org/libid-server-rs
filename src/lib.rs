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
        notary_url: cfg.notary_url.to_string(),
        app_url: (!cfg.app_url.is_empty()).then(|| cfg.app_url.clone()),
        server_origin,
    }))
}
