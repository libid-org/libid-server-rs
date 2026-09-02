//! HTTP route table. The full endpoint surface, deliberately tiny:
//!
//! - `GET  /health`
//! - `POST /api/v1/ceremony/github-token`
//!
//! One route does work, and it is the one a platform ceremony genuinely
//! requires of a server: GitHub's exchange needs a client secret, and a secret
//! in a browser is not a secret. Neither X nor Google needs one — their
//! ceremonies run in the browser against the notary.
//!
//! There is no CORS layer. Every route here is either a probe or same-origin:
//! the token route requires a request's `Origin` to be this service's own, and
//! a same-origin POST never asks for a preflight. A layer would decide nothing
//! the handler does not already decide more strictly.

pub mod github_token;

use std::sync::Arc;

use axum::{
    routing::{
        get,
        post,
    },
    Router,
};

use crate::state::AppState;

/// Liveness probe.
async fn health() -> &'static str {
    "OK"
}

/// Build the route table.
pub fn build_router() -> Router<Arc<AppState>> {
    Router::new().route("/health", get(health)).route(
        "/api/v1/ceremony/github-token",
        post(github_token::github_token),
    )
}
