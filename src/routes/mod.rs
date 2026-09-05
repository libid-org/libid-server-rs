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
//! no credentials — and refuses every other. No layer sits on the callback:
//! it is a top-level navigation, which carries no `Origin` to check.

pub mod callback;
pub mod config;
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

/// The paths this service fixes. The configurable callback alias may not be
/// any of them: `Router::route` panics on a duplicate, and a deployment would
/// learn that by failing to start with nothing saying which setting did it.
pub const FIXED_PATHS: [&str; 3] = [
    "/health",
    "/api/v1/ceremony/config",
    "/api/v1/ceremony/github-token",
];

/// Build the route table for this deployment.
///
/// It takes the state because the surface depends on it: the token route
/// exists only where GitHub is enabled, the callback path is configured, and
/// the token route's CORS names the configured CCDP origin. A router that
/// mounted a confidential route with no secret behind it would answer where it
/// should not be found at all.
pub fn build_router(state: &AppState) -> Router<Arc<AppState>> {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/api/v1/ceremony/config", get(config::config))
        .route(&state.callback_path, get(callback::callback));

    if state.github_oauth.is_some() {
        let token = Router::new()
            .route(
                "/api/v1/ceremony/github-token",
                post(github_token::github_token),
            )
            // A `TokenRequest` is a 1 KiB code and a 43-character verifier.
            // Without this, axum buffers up to its 2 MiB default and runs
            // serde before the handler's origin check ever executes -- the
            // extractor runs first, whatever order the handler reads in.
            .layer(DefaultBodyLimit::max(8 * 1024))
            .layer(token_cors(&state.ccdp_origin));
        router = router.merge(token);
    }
    router
}

/// The preflight answer for the one origin that may call the token route.
///
/// Exact, not a pattern: `AllowOrigin::exact` compares the whole header value.
/// A malformed configured origin cannot become a permissive matcher — it
/// produces a layer that admits nothing, which fails visibly rather than
/// quietly widening. The preflight admits `POST` and `Content-Type` and no
/// credentials, and carries no ceremony data: it is an answer about policy,
/// not a response.
fn token_cors(ccdp_origin: &str) -> CorsLayer {
    let origin = HeaderValue::from_str(ccdp_origin)
        .map(AllowOrigin::exact)
        .unwrap_or_else(|_| AllowOrigin::list([]));
    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}
