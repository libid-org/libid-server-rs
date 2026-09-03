//! HTTP route table. The full endpoint surface, deliberately tiny:
//!
//! - `GET  /health`
//! - `GET  /api/v1/ceremony/config`
//! - `POST /api/v1/ceremony/github-token` (only when GitHub is enabled)
//!
//! One route does work, and it is the one a platform ceremony genuinely
//! requires of a server: GitHub's exchange needs a client secret, and a secret
//! in a browser is not a secret. Neither X nor Google needs one — their
//! ceremonies run in the browser against the notary.
//!
//! The CORS layer admits exactly one origin — this service's own, which is
//! the redirect origin the Canonical Runtime runs on. REQ-PLAT-43A requires
//! the preflight for that origin to be answered, and answering it is all the
//! layer does: the handler makes the same comparison itself and would refuse a
//! request that reached it from anywhere else. One origin and no patterns, per
//! REQ-PLAT-43 — an allow-list with a wildcard in it is not "only the compiled
//! redirect-runtime origin".

pub mod config;
pub mod github_token;

use std::sync::Arc;

use axum::{
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
pub const FIXED_PATHS: [&str; 4] = [
    "/health",
    "/api/v1/ceremony/config",
    "/api/v1/ceremony/github-token",
    "/ccdp/callback",
];

/// Build the route table for this deployment.
///
/// It takes the state because the surface depends on it: the token route
/// exists only where GitHub is enabled, and the callback alias is a configured
/// path. A router that mounted a confidential route with no secret behind it
/// would answer where it should not be found at all.
pub fn build_router(state: &AppState) -> Router<Arc<AppState>> {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/api/v1/ceremony/config", get(config::config));

    if state.github_oauth.is_some() {
        router = router.route(
            "/api/v1/ceremony/github-token",
            post(github_token::github_token),
        );
    }
    router
}

/// The preflight answer for the one origin this service serves.
///
/// Exact, not a pattern: `AllowOrigin::exact` compares the whole header value.
/// A malformed configured origin cannot become a permissive matcher — it
/// produces a layer that admits nothing, which fails visibly rather than
/// quietly widening.
pub fn cors_layer(server_origin: &str) -> CorsLayer {
    let origin = HeaderValue::from_str(server_origin)
        .map(AllowOrigin::exact)
        .unwrap_or_else(|_| AllowOrigin::list([]));
    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([axum::http::Method::POST, axum::http::Method::OPTIONS])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}
