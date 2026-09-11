//! The public ceremony configuration.
//!
//! Everything an application needs to start a ceremony against this
//! deployment, and nothing else. It carries no secret, no admitted origin, no
//! asset URL, no notary setting and nothing about a particular ceremony —
//! which is what lets one record answer every request, and why the record is
//! built once at startup rather than assembled per call.
//!
//! An application reads it once when it creates its ceremony client. The
//! callback document never reads it: what that document needs is inserted into
//! it before it is served, because a document that fetched its own
//! configuration would be a document whose behaviour depends on a request.

use std::sync::Arc;

use axum::{
    extract::{
        RawQuery,
        State,
    },
    http::{
        header,
        HeaderMap,
        HeaderValue,
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

/// What `Vary` names, on every response this route writes: `Origin` decides
/// the body, on refusals too.
const VARY_ON: &str = "origin";

/// The origin this request may read the configuration from, or `None`.
///
/// Exactly one `Origin`, matching an admitted origin exactly. `null`, a
/// malformed value, an unlisted one, two headers and none are all refused.
/// Neither `Referer` nor the request host is consulted.
fn admitted_origin(state: &AppState, headers: &HeaderMap) -> Option<HeaderValue> {
    match crate::routes::Origins::of(headers) {
        crate::routes::Origins::One(origin) => {
            let value = origin.to_str().ok()?;
            state
                .allowed_origins
                .iter()
                .any(|a| a == value)
                .then(|| origin.clone())
        }
        crate::routes::Origins::Several | crate::routes::Origins::Absent => None,
    }
}

/// `GET /api/v1/ceremony/config`.
pub(crate) async fn config(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    // Admission decides before anything else looks at the request. A caller
    // that is not admitted learns that it is not admitted, and nothing about
    // whether the rest of its request would have been acceptable.
    let Some(origin) = admitted_origin(&state, &headers) else {
        return refuse(
            StatusCode::FORBIDDEN,
            "this configuration is readable only from an admitted origin",
        );
    };

    if query.is_some_and(|q| !q.is_empty()) {
        return refuse(StatusCode::BAD_REQUEST, "this route takes no query");
    }

    // A `HeaderMap`, not an array or `AppendHeaders`: the body is `Bytes` and
    // sets its own `application/octet-stream`, so these have to REPLACE rather
    // than append or the caller reads the first of two content types.
    let mut out = HeaderMap::new();
    out.insert(header::VARY, HeaderValue::from_static(VARY_ON));
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    out.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    out.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // The exact origin that asked, never `*` and never a list. No credentials
    // are permitted with it.
    out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);

    (StatusCode::OK, out, state.ceremony_config.clone()).into_response()
}

/// A refusal carries no configuration and no allow-origin header, so a caller
/// that is not admitted cannot read the record out of an error.
fn refuse(status: StatusCode, message: &str) -> Response {
    (
        status,
        [
            (header::VARY, VARY_ON),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Json(json!({ "message": message })),
    )
        .into_response()
}
