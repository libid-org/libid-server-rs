//! The OAuth Bridge's route table. The full surface, deliberately small:
//!
//! - `GET  /health`
//! - `GET  /api/v1/ceremony/config`
//! - `GET  {callback path}` (configured, default `/auth/callback`)
//! - `OPTIONS`, `POST /api/v1/ceremony/github-token` (only when GitHub is enabled)
//!
//! Everything the browser runs — the Callback module, Airlock, the prover, its
//! circuits and notarization client — is served by the CCDP Distribution at
//! the configured `ccdpOrigin`, not here. This service publishes
//! configuration, serves one callback shell, and performs the one exchange a
//! browser cannot: GitHub's, which needs a client secret.
//!
//! CORS is answered in two places and nowhere else. The configuration route
//! echoes an admitted application origin itself. The token route is called
//! cross-origin by the prover on the distribution, so it carries a layer that
//! answers the preflight for exactly the CCDP origin — `POST`, `Content-Type`,
//! no credentials — and gives every other origin no allow-origin header at
//! all. No layer sits on the callback:
//! it is a top-level navigation, which carries no `Origin` to check.

pub(crate) mod callback;
pub(crate) mod config;
pub mod github_token;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    http::HeaderValue,
    routing::{
        get,
        post,
    },
    Router,
};

use tower_http::cors::{
    AllowOrigin,
    CorsLayer,
};

use crate::state::AppState;

/// Liveness probe.
async fn health() -> &'static str {
    "OK"
}

/// The routes whose names this bridge fixes, in one place so the configured
/// callback path is checked against the same literals the router mounts.
/// `Router::route` panics on a duplicate, and a deployment would learn that by
/// failing to start with nothing saying which setting did it.
pub(crate) const HEALTH_PATH: &str = "/health";
/// The public ceremony configuration.
pub(crate) const CONFIG_PATH: &str = "/api/v1/ceremony/config";
/// The confidential GitHub exchange.
pub(crate) const TOKEN_PATH: &str = "/api/v1/ceremony/github-token";

/// Every fixed path, for the configured callback path to be checked against.
pub(crate) const FIXED_PATHS: [&str; 3] = [HEALTH_PATH, CONFIG_PATH, TOKEN_PATH];

/// Build the route table for this deployment.
///
/// It takes the state because the surface depends on it: the token route
/// exists only where GitHub is enabled, and the callback path is configured.
/// It returns a finished `Router`, so no caller can forget to attach state or
/// attach the wrong one -- the two halves carry their own.
pub fn build_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route(HEALTH_PATH, get(health))
        .route(CONFIG_PATH, get(config::config))
        .route(&state.callback_path.clone(), get(callback::callback))
        .with_state(state.clone());

    // Mounted with the exchange or not mounted at all. The handler has no
    // `Option` to unwrap and no way to be reached without a secret behind it.
    if let Some(github) = &state.github {
        router = router.merge(
            Router::new()
                .route(TOKEN_PATH, post(github_token::github_token))
                // A `TokenRequest` is a 1 KiB code and a 43-character
                // verifier. Without this, axum buffers up to its 2 MiB default
                // and runs serde before the handler's origin check ever
                // executes -- the extractor runs first, whatever order the
                // handler reads in.
                .layer(DefaultBodyLimit::max(8 * 1024))
                .layer(token_cors(&github.ccdp_origin))
                .with_state(github.clone()),
        );
    }
    router
}

/// A one-member LIST, not `AllowOrigin::exact`. `exact` emits the configured
/// origin unconditionally -- it compares nothing, and leaves the refusing to
/// the browser. A list is filtered against the request, so a caller from
/// anywhere else gets no allow-origin header at all and the layer is the gate
/// its name suggests. A malformed configured origin yields an empty list,
/// which admits nobody: it fails visibly rather than quietly widening.
///
/// The preflight admits `POST` and `Content-Type` and no credentials, and
/// carries no ceremony data: it is an answer about policy, not a response.
fn token_cors(ccdp_origin: &str) -> CorsLayer {
    let origin = HeaderValue::from_str(ccdp_origin)
        .map(|v| AllowOrigin::list([v]))
        .unwrap_or_else(|_| AllowOrigin::list([]));
    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}
