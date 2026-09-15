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

use super::ON_EVERY_RESPONSE;
use crate::state::AppState;

/// `GET {callback path}`.
pub(crate) async fn callback(State(state): State<Arc<AppState>>) -> Response {
    // The borrow guard is released before the response is built.
    let published = state.callback.borrow().clone();
    (
        ON_EVERY_RESPONSE,
        [
            // `unsafe-none` keeps the opener the application holds.
            (
                HeaderName::from_static("cross-origin-opener-policy"),
                "unsafe-none",
            ),
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        // Computed when the document was composed, over the bytes served.
        [(
            header::CONTENT_SECURITY_POLICY,
            published.document.csp.clone(),
        )],
        published.document.body.clone(),
    )
        .into_response()
}
