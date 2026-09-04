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

use bytes::Bytes;

use crate::{
    deployment::PlatformProfile,
    error::{
        Error,
        Result,
    },
    state::AppState,
};

/// The record this route serves, built once from the enabled set.
///
/// The client id and the versions travel; nothing about artifacts does,
/// because an application selects a platform and a version and never an
/// artifact. The CCDP origin travels too: it is where the application sends the
/// popup, and the one origin whose Callback this bridge's shell will import.
pub fn record(
    redirect_uri: &str,
    ccdp_origin: &str,
    platforms: &[PlatformProfile],
) -> Value {
    let mut by_id = Map::new();
    for p in platforms {
        by_id.insert(
            p.id.clone(),
            json!({
                "clientId": p.client_id,
                "ceremonyVersions": p.versions,
            }),
        );
    }
    json!({
        "redirectUri": redirect_uri,
        "ccdpOrigin": ccdp_origin,
        "platforms": Value::Object(by_id),
    })
}

/// The record as the bytes it is served in, serialized once at startup.
pub fn frozen(
    redirect_uri: &str,
    ccdp_origin: &str,
    platforms: &[PlatformProfile],
) -> Result<Bytes> {
    serde_json::to_vec(&record(redirect_uri, ccdp_origin, platforms))
        .map(Bytes::from)
        .map_err(|e| Error::Config {
            detail: format!("the ceremony configuration does not serialize: {e}"),
        })
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
