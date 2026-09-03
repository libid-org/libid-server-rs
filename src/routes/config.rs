//! The public ceremony configuration.
//!
//! Everything an application needs to start a ceremony against this
//! deployment, and nothing else. It carries no secret, no admitted origin, no
//! asset URL, no notary setting and nothing about a particular ceremony —
//! which is what lets one record answer every request, and why the record is
//! built once at startup rather than assembled per call.
//!
//! An application reads it once when it creates its ceremony client. The
//! callback and prover documents never read it: what they need is embedded in
//! them, because a document that fetched its own configuration would be a
//! document whose behaviour depends on a request.

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
use serde_json::{
    json,
    Map,
    Value,
};

use crate::{
    deployment::PlatformProfile,
    state::AppState,
};

/// The record this route serves, built once from the enabled set.
///
/// This is one of the two projections of that set — the other is the prover
/// profiles the shell embeds. What separates them is exactly what a public
/// record may carry: the client id and the versions travel, the circuit URL
/// does not, because an application selects a platform and a version and never
/// an artifact.
pub fn record(redirect_uri: &str, platforms: &[PlatformProfile]) -> Value {
    let mut by_id = Map::new();
    for p in platforms {
        by_id.insert(
            p.id.clone(),
            json!({
                "clientId": p.client_id,
                "ceremonyVersions": p.versions.iter().map(|v| v.version).collect::<Vec<_>>(),
            }),
        );
    }
    json!({ "redirectUri": redirect_uri, "platforms": Value::Object(by_id) })
}

/// `GET /api/v1/ceremony/config`.
pub async fn config(
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
            (header::CACHE_CONTROL, "no-store".into()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".into()),
        ],
        Json(state.ceremony_config.clone()),
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
