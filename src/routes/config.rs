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

use crate::state::AppState;

/// Fetch metadata naming where a request came from. No `http` constant exists
/// for it, and it is the one header besides `Origin` that may admit a caller.
static SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// What `Vary` names, on every response this route writes.
///
/// Two headers decide the body, so both have to be named or a shared cache can
/// answer one caller with another's outcome. On refusals too: `no-store` should
/// already stop that, and a cache that ignores it must not get the chance to
/// replay a `403` to an origin this deployment admits.
const VARY_ON: &str = "origin, sec-fetch-site";

/// How a caller was admitted, which decides whether the answer carries CORS.
enum Admitted {
    /// A cross-origin read from this exact admitted origin, which is echoed.
    ///
    /// Carried as the header value that arrived, not as a `String`: it is
    /// going straight back out as a header, and re-parsing a value that was
    /// already one would add an error branch nothing can reach.
    Origin(HeaderValue),
    /// A same-origin read, which needs no CORS header at all.
    SameOrigin,
}

/// Whether this request may read the configuration, and on what grounds.
///
/// `Origin` decides whenever it is present. Only its absence reaches Fetch
/// metadata, and only `same-origin` is enough there -- `same-site`,
/// `cross-site`, `none` and a missing header are all refusals, because a
/// deployment cannot tell a sibling subdomain from itself without it. Neither
/// `Referer` nor the request host is consulted: both are shaped by the caller,
/// and this function does not read them.
impl Admitted {
    fn of(state: &AppState, headers: &HeaderMap) -> Option<Self> {
        let admitted = |o: &str| state.allowed_origins.iter().any(|a| a == o);

        match crate::routes::Origins::of(headers) {
            // Present and exact, or refused. `null`, a malformed value and an
            // unlisted one all land here and all fail.
            crate::routes::Origins::One(origin) => {
                origin.to_str().ok().filter(|o| admitted(o))?;
                return Some(Admitted::Origin(origin.clone()));
            }
            crate::routes::Origins::Several => return None,
            crate::routes::Origins::Absent => {}
        }

        // No `Origin` at all. A top-level navigation and a same-origin fetch both
        // look like this, so the metadata has to say which -- and the deployment
        // has to have admitted its own origin, or there is no same-origin
        // application to admit.
        let mut sites = headers.get_all(&SEC_FETCH_SITE).iter();
        match (sites.next(), sites.next()) {
            (Some(site), None) if site.as_bytes() == b"same-origin" => state
                .admits_same_origin_config
                .then_some(Admitted::SameOrigin),
            _ => None,
        }
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
    let Some(admitted) = Admitted::of(&state, &headers) else {
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
    // The exact origin that asked, never `*` and never a list: the record is
    // not public to the web, only to the applications this deployment admits.
    // No credentials are permitted with it. A same-origin read needs none of
    // this -- a header granting an origin access to itself says nothing.
    if let Admitted::Origin(origin) = admitted {
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }

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
