//! The public ceremony configuration: `{ callbackPath, ccdpOrigin, platforms }`,
//! one record built at startup and served to every admitted origin. It carries
//! no secret, no admitted origin, no asset URL and no notary setting.

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

use super::ON_EVERY_RESPONSE;
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
    // Admission is decided before anything else is looked at.
    let Some(origin) = admitted_origin(&state, &headers) else {
        return refuse(
            StatusCode::FORBIDDEN,
            "this configuration is readable only from an admitted origin",
        );
    };

    if query.is_some_and(|q| !q.is_empty()) {
        return refuse(StatusCode::BAD_REQUEST, "this route takes no query");
    }

    // `insert`, not append: the `Bytes` body would otherwise add its own
    // content type.
    let mut out = HeaderMap::new();
    out.insert(header::VARY, HeaderValue::from_static(VARY_ON));
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for (name, value) in ON_EVERY_RESPONSE {
        out.insert(name, value);
    }
    // The exact origin that asked, never `*`; no credentials.
    out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);

    (StatusCode::OK, out, state.ceremony_config.clone()).into_response()
}

/// A refusal carries no configuration and no allow-origin header, so a caller
/// that is not admitted cannot read the record out of an error.
fn refuse(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::VARY, VARY_ON)],
        ON_EVERY_RESPONSE,
        Json(json!({ "message": message })),
    )
        .into_response()
}
