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
//! configuration, serves one callback document, and performs the one exchange a
//! browser cannot: GitHub's, which needs a client secret.
//!
//! CORS is answered in two places and nowhere else. The configuration route
//! echoes an admitted origin itself. The token route is called
//! cross-origin by the prover on the distribution, so it carries a layer that
//! answers the preflight for exactly the CCDP origin — `POST`, `Content-Type`,
//! no credentials — and gives every other origin no allow-origin header at
//! all. No layer sits on the callback:
//! it is a top-level navigation, which carries no `Origin` to check.

pub(crate) mod callback;
pub(crate) mod config;
pub(crate) mod github_token;

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

/// How many `Origin` headers a request carried, which both gated routes have
/// to distinguish three ways.
///
/// One spelling, because it is one security rule. It was written twice --
/// `to_str().ok().filter(..)` on the configuration route and a raw byte
/// comparison on the token route -- and two spellings of one rule drift the
/// first time either is tightened.
pub(crate) enum Origins<'a> {
    /// No `Origin` at all. A top-level navigation looks like this, and so does
    /// a same-origin fetch, so only Fetch metadata can tell them apart.
    Absent,
    /// Exactly one, which is the only case that can be admitted on its value.
    One(&'a axum::http::HeaderValue),
    /// More than one. Not a request a browser sends, and reading the first
    /// would let the caller choose which one is read.
    Several,
}

/// Read them.
impl<'a> Origins<'a> {
    pub(crate) fn of(headers: &'a axum::http::HeaderMap) -> Self {
        let mut seen = headers.get_all(axum::http::header::ORIGIN).iter();
        match (seen.next(), seen.next()) {
            (Some(one), None) => Origins::One(one),
            (Some(_), Some(_)) => Origins::Several,
            (None, _) => Origins::Absent,
        }
    }
}

/// Liveness probe, and the one route the OAuth Bridge contract does not list.
///
/// The contract's route surface is closed -- "the bridge exposes only" three
/// routes -- and this is a fourth, kept deliberately: the published image
/// declares a `HEALTHCHECK` against it and an orchestrator needs somewhere to
/// ask. It is outside the ceremony surface rather than an addition to it: it
/// takes no ceremony input, reads nothing from the request, and answers two
/// bytes.
///
/// That is also why it is the one route that tolerates a query. The contract's
/// "bridge routes accept no query" governs the three routes it enumerates; a
/// liveness probe that answered `400` to a cache-buster would report a healthy
/// service as unhealthy and be restarted for it.
///
/// The response policy is every other route's: `nosniff` so the two bytes
/// cannot be sniffed into anything, and `no-store` so no cache answers on this
/// service's behalf about whether it is alive.
async fn health() -> impl axum::response::IntoResponse {
    (
        [
            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        "OK",
    )
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
        .route(&state.callback_path, get(callback::callback))
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
                // `route_layer`, not `layer`. `Router::layer` wraps the
                // sub-router's FALLBACK as well as its routes, and `merge`
                // carries that layered fallback out into the whole service --
                // so every path this bridge does not serve would answer a
                // preflight advertising `POST`, and hand the CCDP origin an
                // allow-origin header on its 404. The contract closes that
                // surface: "unsupported methods fail without route work".
                // `route_layer` runs only where a route matched, which is this
                // path and nothing else.
                .route_layer(token_cors(&github.ccdp_origin))
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
    // Exactly what the handler admits, and nothing more. The two are the same
    // rule seen from two places: a layer wider than the gate would advertise
    // access this route then refuses, and one narrower would let a caller past
    // the gate and have the browser discard the answer for want of a matching
    // allow-origin header -- a failure with no server-side symptom at all.
    let origin = HeaderValue::from_str(ccdp_origin)
        .map(|v| AllowOrigin::list([v]))
        .unwrap_or_else(|_| AllowOrigin::list([]));
    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}
