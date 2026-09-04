//! The registered OAuth callback: one document, served at the configured
//! path, identical for every request.
//!
//! This handler reads nothing from the request. No `Uri`, no query, no
//! `Origin`, no `Referer` — the provider's return arrives in the query, and the
//! strongest way to keep it out of every log and error this service could ever
//! produce is for no code here to be able to see it. The browser-side
//! bootstrap copies and clears it; the server never learns it existed.

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
pub async fn callback(State(state): State<Arc<AppState>>) -> Response {
    (
        [
            // The application opened this window and must keep it through the
            // provider's navigation. Isolating it here would sever the opener,
            // which is the failure the whole connection layer exists to
            // survive whenever platform policy has not already done it.
            (
                HeaderName::from_static("cross-origin-opener-policy"),
                "unsafe-none",
            ),
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (
                header::CONTENT_SECURITY_POLICY,
                state.callback_shell.csp.as_str(),
            ),
        ],
        state.callback_shell.body.clone(),
    )
        .into_response()
}
