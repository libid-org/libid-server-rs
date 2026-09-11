//! The registered OAuth callback: one document, served at the configured
//! path, identical for every request. The handler reads nothing from the
//! request: no URI, query, `Origin` or `Referer`.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{
        header,
        HeaderName,
    },
    response::{
        IntoResponse,
        Response,
    },
};

use crate::state::AppState;

/// `GET {callback path}`.
pub(crate) async fn callback(State(state): State<Arc<AppState>>) -> Response {
    (
        [
            // `unsafe-none` keeps the opener the application holds.
            (
                HeaderName::from_static("cross-origin-opener-policy"),
                "unsafe-none",
            ),
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        // Computed once at startup over the bytes served.
        [(header::CONTENT_SECURITY_POLICY, state.callback.csp.clone())],
        state.callback.body.clone(),
    )
        .into_response()
}
