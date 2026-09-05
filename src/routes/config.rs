//! The public ceremony configuration.
//!
//! Everything an application needs to start a ceremony against this
//! deployment, and nothing else. It carries no secret, no admitted origin, no
//! asset URL, no notary setting and nothing about a particular ceremony —
//! which is what lets one record answer every request, and why the record is
//! built once at startup rather than assembled per call.
//!
//! An application reads it once when it creates its ceremony client. The
//! callback shell never reads it: what that document needs is rendered into
//! it at startup, because a document that fetched its own configuration would
//! be a document whose behaviour depends on a request.

use std::sync::Arc;

use axum::{
    extract::{
        RawQuery,
        State,
    },
    http::{
        header,
        HeaderMap,
        StatusCode,
    },
    response::{
        IntoResponse,
        Response,
    },
    Json,
};
use serde_json::json;

use crate::state::AppState;

/// `GET /api/v1/ceremony/config`.
pub(crate) async fn config(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    // The origin decides before anything else looks at the request. A caller
    // that is not admitted learns that it is not admitted, and nothing about
    // whether the rest of its request would have been acceptable.
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|o| state.allowed_app_origins.iter().any(|a| a == o))
    else {
        return refuse(
            StatusCode::FORBIDDEN,
            "this configuration is readable only from an admitted application origin",
        );
    };

    if query.is_some_and(|q| !q.is_empty()) {
        return refuse(StatusCode::BAD_REQUEST, "this route takes no query");
    }

    (
        StatusCode::OK,
        [
            // The exact origin that asked, never `*` and never a list: the
            // record is not public to the web, only to the applications this
            // deployment admits. No credentials are permitted with it.
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.to_owned()),
            (header::VARY, header::ORIGIN.to_string()),
            (header::CONTENT_TYPE, "application/json".into()),
            (header::CACHE_CONTROL, "no-store".into()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".into()),
        ],
        state.ceremony_config.clone(),
    )
        .into_response()
}

/// A refusal carries no configuration and no allow-origin header, so a caller
/// that is not admitted cannot read the record out of an error.
fn refuse(status: StatusCode, message: &str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Json(json!({ "message": message })),
    )
        .into_response()
}
