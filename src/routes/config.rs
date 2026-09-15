//! The public ceremony configuration: `{ ccdpOrigin, platforms }`, one record
//! built at startup and served to every admitted origin, and to a same-origin
//! read. It carries no secret, no admitted origin, no asset URL and no notary
//! setting.

use std::sync::Arc;

use axum::{
    extract::{
        RawQuery,
        State,
    },
    http::{
        header,
        HeaderMap,
        HeaderName,
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

/// What `Vary` names, on every response this route writes: `Origin` and
/// `Sec-Fetch-Site` decide the body, on refusals too.
const VARY_ON: &str = "origin, sec-fetch-site";

/// The fetch metadata header saying where a browser request came from,
/// relative to its target.
const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// How a request is admitted to read the configuration.
enum Admission {
    /// One `Origin`, matching an admitted origin exactly; echoed as the
    /// allow-origin.
    Listed(HeaderValue),
    /// No `Origin`: a same-origin browser `GET`, which carries none, on
    /// `Sec-Fetch-Site: same-origin`. It needs no CORS header.
    SameOrigin,
}

/// How this request may read the configuration, or `None`.
///
/// One `Origin` must match an admitted origin exactly: `null`, a malformed
/// value, an unlisted one and two headers are refused whatever else the
/// request carries. With no `Origin`, exactly one `Sec-Fetch-Site:
/// same-origin` admits. `Referer`, the request host and absent fetch
/// metadata admit nothing.
fn admission(state: &AppState, headers: &HeaderMap) -> Option<Admission> {
    match crate::routes::Origins::of(headers) {
        crate::routes::Origins::One(origin) => {
            let value = origin.to_str().ok()?;
            state
                .allowed_origins
                .iter()
                .any(|a| a.as_str() == value)
                .then(|| Admission::Listed(origin.clone()))
        }
        crate::routes::Origins::Several => None,
        crate::routes::Origins::Absent => {
            let mut sites = headers.get_all(SEC_FETCH_SITE).iter();
            match (sites.next(), sites.next()) {
                (Some(site), None) if site == "same-origin" => {
                    Some(Admission::SameOrigin)
                }
                _ => None,
            }
        }
    }
}

/// `GET /api/v1/ceremony/config`.
pub(crate) async fn config(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    // Admission is decided before anything else is looked at.
    let Some(admission) = admission(&state, &headers) else {
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
    // The exact origin that asked, never `*`; no credentials. A same-origin
    // read gets no allow-origin.
    if let Admission::Listed(origin) = admission {
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }

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
