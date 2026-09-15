//! The OAuth Bridge's route table:
//!
//! - `GET  /health`
//! - `GET  /api/v1/ceremony/config`
//! - `GET  /auth/callback`
//!
//! Everything the browser runs is served by the CCDP Distribution at the
//! configured `ccdpOrigin`. The configuration route admits exactly one
//! `Origin`, in the effective set `allowedAppOrigins ∪ {ccdpOrigin}`, and
//! echoes it as the one origin allowed. The callback carries no CORS: it is a
//! top-level navigation. No other path is served, and no route performs a
//! token exchange or opens a notary connection.

pub(crate) mod callback;
pub(crate) mod config;

use std::sync::Arc;

use axum::{
    http::{
        header,
        HeaderName,
        HeaderValue,
    },
    routing::get,
    Router,
};

use crate::state::AppState;

/// How many `Origin` headers a request carried. The configuration route
/// admits exactly one, matching an admitted origin.
pub(crate) enum Origins<'a> {
    /// No `Origin`.
    Absent,
    /// Exactly one.
    One(&'a axum::http::HeaderValue),
    /// More than one; refused.
    Several,
}

impl<'a> Origins<'a> {
    /// The `Origin` headers of `headers`.
    pub(crate) fn of(headers: &'a axum::http::HeaderMap) -> Self {
        let mut seen = headers.get_all(axum::http::header::ORIGIN).iter();
        match (seen.next(), seen.next()) {
            (Some(one), None) => Origins::One(one),
            (Some(_), Some(_)) => Origins::Several,
            (None, _) => Origins::Absent,
        }
    }
}

/// `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`, on every
/// response this service writes.
pub(crate) const ON_EVERY_RESPONSE: [(HeaderName, HeaderValue); 2] = [
    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
    (
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ),
];

/// Liveness probe: `OK`. Not one of the contract's routes; the published
/// image's `HEALTHCHECK` targets it. It is the one route that accepts a query.
async fn health() -> impl axum::response::IntoResponse {
    (ON_EVERY_RESPONSE, "OK")
}

/// The liveness probe.
pub(crate) const HEALTH_PATH: &str = "/health";
/// The registered OAuth callback: the callback document.
pub const CALLBACK_PATH: &str = "/auth/callback";
/// The public ceremony configuration.
pub const CONFIG_PATH: &str = "/api/v1/ceremony/config";

/// The route table: the same three routes for every deployment.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(HEALTH_PATH, get(health))
        .route(CONFIG_PATH, get(config::config))
        .route(CALLBACK_PATH, get(callback::callback))
        .with_state(state)
}
