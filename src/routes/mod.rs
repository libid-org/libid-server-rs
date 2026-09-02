//! HTTP route table and CORS. The full endpoint surface, deliberately tiny:
//!
//! - `GET  /health`
//! - `GET  /auth/gmail/callback`
//! - `POST /api/v1/ceremony/github-token`
//!
//! Neither X nor Google needs a confidential route: their ceremonies run in
//! the browser against the notary. Google keeps the relay above only because
//! it returns its credential in a fragment, which never reaches a server —
//! the relay hands that fragment back to the application origin and does
//! nothing else.
//!
//! GitHub's token route lands next, and is the one route a platform ceremony
//! genuinely requires of a server.

pub mod github_token;
pub mod gmail;

use std::sync::Arc;

use axum::{
    http::HeaderValue,
    routing::{
        get,
        post,
    },
    Router,
};
use tower_http::cors::CorsLayer;

use crate::state::AppState;

/// Liveness probe.
async fn health() -> &'static str {
    "OK"
}

/// Build the route table (no CORS applied; see [`cors_layer`]).
pub fn build_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health))
        .route("/auth/gmail/callback", get(gmail::gmail_callback))
        .route(
            "/api/v1/ceremony/github-token",
            post(github_token::github_token),
        )
}

/// CORS layer from a list of origin patterns (supports `*.suffix` and
/// `prefix*` wildcards).
pub fn cors_layer(allowed_origins: Vec<String>) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(
            move |origin: &HeaderValue, _req: &axum::http::request::Parts| {
                let origin_str = match origin.to_str() {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                allowed_origins.iter().any(|pattern| {
                    if pattern.contains('*') {
                        if let Some(suffix) = pattern.strip_prefix("*.") {
                            origin_str.ends_with(&format!(".{suffix}"))
                                || origin_str == suffix
                        } else if let Some(prefix) = pattern.strip_suffix('*') {
                            origin_str.starts_with(prefix)
                        } else {
                            false
                        }
                    } else {
                        origin_str == pattern
                    }
                })
            },
        ))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT])
}
