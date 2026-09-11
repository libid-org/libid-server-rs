//! HTTP-level tests over the axum router: the public configuration, the
//! callback document's invariance and policy, and the token route's origin gate.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{
        Request,
        StatusCode,
    },
};
use http_body_util::BodyExt;
use libid_server_rs::{
    fixtures::{
        self,
        Distribution,
    },
    routes,
    state::AppState,
};
use tower::ServiceExt;

const APP_ORIGIN: &str = "https://app.example";

/// The shared Distribution's origin: the deployment's CCDP origin, and so the
/// one origin the token route admits and the callback document names.
fn ccdp_origin() -> &'static str {
    Distribution::shared().origin()
}

/// A deployment admitting two applications, with `overrides` replacing any
/// flag they name.
async fn deployment(overrides: &[&str]) -> Arc<AppState> {
    let mut args = vec![
        "--allowed-app-origins",
        "https://app.example,https://wallet.example",
    ];
    args.extend_from_slice(overrides);
    AppState::fixture(&args).await
}

/// The default deployment: GitHub enabled, the full exchange ceiling free.
async fn test_state() -> Arc<AppState> {
    deployment(&[]).await
}

fn app(state: Arc<AppState>) -> axum::Router {
    routes::build_router(state)
}

#[tokio::test]
async fn health_answers_ok_and_carries_nosniff_like_every_other_route() {
    let resp = app(test_state().await)
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()[axum::http::header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"OK");
}

// ─── the GitHub token route ──────────────────────────────────────────────────
//
// Every case here is refused before a notary session is opened.

const VERIFIER: &str = "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I";

async fn post_token(origin: Option<&str>, body: String) -> axum::response::Response {
    let mut req = Request::post("/api/v1/ceremony/github-token")
        .header("content-type", "application/json");
    if let Some(origin) = origin {
        req = req.header("origin", origin);
    }
    app(test_state().await)
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

/// A notary as a request names one: the origin the browser resolved from the
/// ledger. This bridge dials its host on the fixture's dead wire port.
const NOTARY: &str = "https://127.0.0.1:7048";

/// The registered callback URL a request carries: the fixture's callback path
/// under a canonical origin.
const REDIRECT: &str = "https://bridge.example/auth/callback";

/// A request body carrying every field, varying only the two under test.
fn token_body(code: &str, verifier: &str) -> String {
    format!(
        r#"{{"code":"{code}","codeVerifier":"{verifier}","redirectUri":"{REDIRECT}","notaryAddress":"{NOTARY}"}}"#
    )
}

/// A code of the shape GitHub issues, for the cases where the code is not what
/// is under test.
const CODE: &str = "6b7f2c1d9e4a8035";

fn valid_body() -> String {
    token_body(CODE, VERIFIER)
}

#[tokio::test]
async fn github_token_refuses_a_foreign_origin() {
    let resp = post_token(Some("https://evil.example"), valid_body()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store",
        "a refusal is no more cacheable than an answer"
    );
}

#[tokio::test]
async fn github_token_refuses_a_request_with_no_origin() {
    let resp = post_token(None, valid_body()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A body carrying a `clientId` or an endpoint is refused rather than ignored.
#[tokio::test]
async fn github_token_refuses_a_body_that_tries_to_steer_the_exchange() {
    let body = format!(
        r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","redirectUri":"{REDIRECT}","notaryAddress":"{NOTARY}","clientId":"Iv1.other"}}"#
    );
    let resp = post_token(Some(ccdp_origin()), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// `redirectUri` is the callback path under a canonical origin; anything else
/// is refused before a session is opened.
#[tokio::test]
async fn github_token_refuses_a_redirect_uri_that_is_not_the_registered_callback_url() {
    for bad in [
        "https://bridge.example/other",
        "https://bridge.example/auth/callback/",
        "https://bridge.example/auth/callback?x=1",
        "http://bridge.example/auth/callback",
        "https://user@bridge.example/auth/callback",
        "/auth/callback",
        "",
    ] {
        let body = format!(
            r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","redirectUri":"{bad}","notaryAddress":"{NOTARY}"}}"#
        );
        let resp = post_token(Some(ccdp_origin()), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad:?}");
    }
    let body = format!(
        r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","notaryAddress":"{NOTARY}"}}"#
    );
    let resp = post_token(Some(ccdp_origin()), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "missing");
}

#[tokio::test]
async fn github_token_refuses_a_malformed_body() {
    let resp = post_token(Some(ccdp_origin()), "{\"code\":".into()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn github_token_refuses_an_over_long_code() {
    assert_eq!(
        answer_with_no_permit_free(token_body(&"a".repeat(4096), VERIFIER)).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn github_token_refuses_a_verifier_of_the_wrong_length() {
    assert_eq!(
        answer_with_no_permit_free(token_body(CODE, "tooshort")).await,
        StatusCode::BAD_REQUEST
    );
}

/// The control for the two bounds tests above: a body that passes the bounds
/// is answered `503` by the permit gate, so their `400`s are the bounds and
/// not the JSON rejection, which answers `400` with the same message.
#[tokio::test]
async fn a_body_within_the_bounds_gets_past_them() {
    assert_eq!(
        answer_with_no_permit_free(valid_body()).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

/// Post a body to a deployment holding every exchange permit, and answer what
/// the route said. Nothing is dialled: the permit gate refuses first.
async fn answer_with_no_permit_free(body: String) -> StatusCode {
    let state = test_state().await;
    let _held = state
        .exchange_permits()
        .expect("github is enabled")
        .try_acquire_many(libid_server_rs::state::MAX_CONCURRENT_EXCHANGES as u32)
        .expect("every permit is free at the start of this test");
    let req = Request::post("/api/v1/ceremony/github-token")
        .header("content-type", "application/json")
        .header("origin", ccdp_origin())
        .body(Body::from(body))
        .unwrap();
    app(state.clone()).oneshot(req).await.unwrap().status()
}

/// A request that finds every exchange permit held is shed with `503`, not
/// queued.
#[tokio::test]
async fn github_token_sheds_when_no_permit_is_free() {
    let req = Request::post("/api/v1/ceremony/github-token")
        .header("content-type", "application/json")
        .header("origin", ccdp_origin())
        .body(Body::from(valid_body()))
        .unwrap();
    let state = test_state().await;
    let _held = state
        .exchange_permits()
        .expect("github is enabled")
        .try_acquire_many(libid_server_rs::state::MAX_CONCURRENT_EXCHANGES as u32)
        .expect("every permit is free at the start of this test");
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
}

/// Whatever the body, a foreign origin is answered `403`.
#[tokio::test]
async fn github_token_checks_the_origin_before_the_body() {
    let resp = post_token(Some("https://evil.example"), "not json at all".into()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A `schema` member is an additional field, and refused.
#[tokio::test]
async fn github_token_refuses_a_body_carrying_a_schema() {
    let body = format!(
        r#"{{"schema":1,"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}"}}"#
    );
    let resp = post_token(Some(ccdp_origin()), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// The preflight admits exactly what the handler does: the CCDP origin,
/// `POST`, `Content-Type`, no credentials.
#[tokio::test]
async fn the_token_preflight_admits_exactly_what_the_handler_does() {
    let preflight = |origin: &'static str| async move {
        app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/v1/ceremony/github-token")
                    .header("origin", origin)
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    };

    let resp = preflight(ccdp_origin()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h.get("access-control-allow-origin").unwrap(), ccdp_origin());
    assert_eq!(h.get("access-control-allow-methods").unwrap(), "POST");
    assert_eq!(
        h.get("access-control-allow-headers").unwrap(),
        "content-type"
    );
    assert!(h.get("access-control-allow-credentials").is_none());
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty(), "a preflight carries no ceremony data");

    // Everything else gets no allow-origin header.
    for other in [APP_ORIGIN, "https://wallet.example", "https://evil.example"] {
        let resp = preflight(other).await;
        assert!(
            resp.headers().get("access-control-allow-origin").is_none(),
            "{other}"
        );
    }
}

/// This bridge's own origin is not the CCDP origin, so it is refused.
#[tokio::test]
async fn github_token_admits_the_ccdp_origin_and_not_the_bridges_own() {
    let resp = post_token(Some("http://127.0.0.1:8722"), valid_body()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── the public ceremony configuration ───────────────────────────────────────

async fn get_config(origin: Option<&str>, query: &str) -> axum::response::Response {
    let headers: Vec<(&str, &str)> = origin.into_iter().map(|o| ("origin", o)).collect();
    config_with(test_state().await, &headers, query).await
}

/// The same route with arbitrary headers.
async fn config_with(
    state: Arc<AppState>,
    headers: &[(&str, &str)],
    query: &str,
) -> axum::response::Response {
    let mut req = Request::get(format!("/api/v1/ceremony/config{query}"));
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    app(state)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body_of(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// An admitted application is answered with its own origin, never `*` and
/// never the list.
#[tokio::test]
async fn config_answers_each_admitted_origin_with_that_exact_origin() {
    for origin in [APP_ORIGIN, "https://wallet.example"] {
        let resp = get_config(Some(origin), "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{origin}");
        let h = resp.headers();
        assert_eq!(h.get("access-control-allow-origin").unwrap(), origin);
        assert!(h.get("access-control-allow-credentials").is_none());
        assert_eq!(h.get("cache-control").unwrap(), "no-store");
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("content-type").unwrap(), "application/json");
    }
}

/// A caller that is not admitted gets no configuration and no allow-origin
/// header; absent and unlisted are answered alike.
#[tokio::test]
async fn config_refuses_an_absent_or_unlisted_origin() {
    for origin in [
        None,
        Some("https://evil.example"),
        // A browser sends this for an opaque origin.
        Some("null"),
        // Near misses. A browser sends none of these for an admitted page.
        Some("https://APP.example"),
        Some("https://app.example/"),
        Some("https://app.example:8443"),
    ] {
        let resp = get_config(origin, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{origin:?}");
        assert!(resp.headers().get("access-control-allow-origin").is_none());
        let body = body_of(resp).await;
        assert!(
            body.get("platforms").is_none(),
            "{origin:?} learned nothing"
        );
    }
}

/// Two `Origin` headers is not a request a browser sends, and taking the first
/// would let a caller choose which one is read.
#[tokio::test]
async fn config_refuses_an_origin_sent_twice() {
    let two_origins = config_with(
        test_state().await,
        &[("origin", APP_ORIGIN), ("origin", "https://evil.example")],
        "",
    )
    .await;
    assert_eq!(two_origins.status(), StatusCode::FORBIDDEN, "two origins");
}

/// Neither is an authority input, and the handler does not read them.
#[tokio::test]
async fn config_admits_nothing_on_referer_or_host() {
    let resp = config_with(
        test_state().await,
        &[
            ("referer", "http://127.0.0.1:8722/"),
            ("host", "127.0.0.1:8722"),
        ],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// The response varies on `Origin`, on refusals too.
#[tokio::test]
async fn config_varies_on_origin() {
    let admitted = config_with(test_state().await, &[("origin", APP_ORIGIN)], "").await;
    assert_eq!(admitted.status(), StatusCode::OK);
    assert_eq!(admitted.headers().get("vary").unwrap(), "origin");

    let refused = config_with(
        test_state().await,
        &[("origin", "https://evil.example")],
        "",
    )
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(refused.headers().get("vary").unwrap(), "origin");
}

/// The record carries exactly `callbackPath`, `ccdpOrigin` and `platforms`:
/// no secret and no allowlist.
#[tokio::test]
async fn config_carries_no_secret_and_no_admitted_origin() {
    let body = body_of(get_config(Some(APP_ORIGIN), "").await).await;
    let object = body.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["callbackPath", "ccdpOrigin", "platforms"]);
    assert_eq!(body["ccdpOrigin"], ccdp_origin());
    assert_eq!(body["callbackPath"], "/auth/callback");
    assert_eq!(body["platforms"]["github"]["clientId"], fixtures::CLIENT_ID);
    assert_eq!(body["platforms"]["github"]["ceremonyVersions"][0], 1);

    let raw = body.to_string();
    assert!(!raw.contains(fixtures::CLIENT_SECRET));
    assert!(!raw.contains(APP_ORIGIN));
    assert!(
        !raw.contains("circuitUrl"),
        "an application selects no artifact"
    );
}

/// The origin is decided before the query.
#[tokio::test]
async fn config_refuses_a_query_but_reads_the_origin_first() {
    assert_eq!(
        get_config(Some(APP_ORIGIN), "?tenant=1").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get_config(Some("https://evil.example"), "?tenant=1")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
}

/// The token route is mounted only where GitHub is enabled.
#[tokio::test]
async fn the_token_route_is_absent_when_github_is_not_enabled() {
    let state = deployment(&[
        "--platforms",
        r#"[{"id":"x","client_id":"abc","versions":[1]}]"#,
        "--gh-oauth-client-secret",
        "",
    ])
    .await;
    let req = Request::post("/api/v1/ceremony/github-token")
        .header("content-type", "application/json")
        .header("origin", ccdp_origin())
        .body(Body::from(valid_body()))
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── the callback document ───────────────────────────────────────────────────

async fn get_callback(path: &str, headers: &[(&str, &str)]) -> axum::response::Response {
    let mut req = Request::get(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    app(test_state().await)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// One document, whatever arrives: no query, `Origin` or `Referer` changes a
/// byte of it.
#[tokio::test]
async fn the_callback_document_is_the_same_bytes_whatever_the_request() {
    /// Status, sorted headers, body -- everything a response is.
    type Observed = (StatusCode, Vec<(String, String)>, bytes::Bytes);
    let mut seen: Vec<Observed> = Vec::new();
    for (path, headers) in [
        ("/auth/callback", vec![]),
        ("/auth/callback?code=abc&state=v1.9e1f", vec![]),
        ("/auth/callback?error=access_denied&state=v1.9e1f", vec![]),
        ("/auth/callback", vec![("origin", "https://evil.example")]),
        (
            "/auth/callback",
            vec![("referer", "https://github.com/login")],
        ),
        // A fragment never reaches the wire.
        ("/auth/callback#id_token=x&state=v1.9e1f", vec![]),
    ] {
        let resp = get_callback(path, &headers).await;
        let status = resp.status();
        let mut hs: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
            .collect();
        hs.sort();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        seen.push((status, hs, body));
    }
    for other in &seen[1..] {
        assert_eq!(other, &seen[0]);
    }
    assert_eq!(seen[0].0, StatusCode::OK);
}

/// The response policy the contract lists; `cross-origin-opener-policy:
/// unsafe-none` keeps the opener.
#[tokio::test]
async fn the_callback_document_carries_the_exact_response_policy() {
    let resp = get_callback("/auth/callback", &[]).await;
    let h = resp.headers();
    assert_eq!(h.get("cross-origin-opener-policy").unwrap(), "unsafe-none");
    assert!(h.get("cross-origin-embedder-policy").is_none());
    assert_eq!(h.get("content-type").unwrap(), "text/html; charset=utf-8");
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
    assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");

    let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
    let directive = |name: &str| -> String {
        csp.split(';')
            .map(str::trim)
            .find(|d| d.split(' ').next() == Some(name))
            .unwrap_or_else(|| panic!("{name} missing from {csp}"))
            .to_owned()
    };
    for name in [
        "default-src",
        "object-src",
        "base-uri",
        "form-action",
        "frame-ancestors",
    ] {
        assert_eq!(directive(name), format!("{name} 'none'"));
    }
    assert_eq!(
        directive("frame-src"),
        format!("frame-src {}", ccdp_origin())
    );
    assert_eq!(directive("connect-src"), "connect-src 'none'");
    assert_eq!(directive("style-src"), "style-src 'unsafe-inline'");

    // Directive-scoped: `'unsafe-inline'` is legitimate in `style-src`.
    let script_src = directive("script-src");
    let tokens: Vec<&str> = script_src.split(' ').skip(1).collect();
    assert!(!tokens.is_empty(), "no hash in {script_src}");
    for token in &tokens {
        assert!(
            token.starts_with("'sha256-") && token.ends_with('\''),
            "{token} in {script_src} is not a hash"
        );
    }
    // No external script source: the artifact bundles its dependencies.
    assert!(
        !script_src.contains(ccdp_origin()),
        "an external script source survived in {script_src}"
    );

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("<main id=\"libid-root\"></main>"));
    assert!(!html.contains(fixtures::CLIENT_SECRET));

    // One module script, and one hash naming it.
    assert_eq!(html.matches("<script type=\"module\">").count(), 1);
    assert_eq!(tokens.len(), 1, "one script, one hash: {script_src}");

    // The deployment data reached the slot, and the marker did not survive.
    assert!(
        html.contains(APP_ORIGIN),
        "the admitted origins are inserted"
    );
    assert!(
        !html.contains("__LIBID_CALLBACK_CONFIG__"),
        "marker substituted"
    );
}

/// The callback document is a navigation target, and only that.
#[tokio::test]
async fn the_callback_document_admits_only_get() {
    let req = Request::post("/auth/callback").body(Body::empty()).unwrap();
    let resp = app(test_state().await).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// One callback path; nothing else is routed.
#[tokio::test]
async fn the_bridge_serves_no_ccdp_document_and_no_alias() {
    for path in [
        "/ccdp/callback",
        "/ccdp/prover",
        "/auth/v1/callback",
        "/api/v1/ceremony/callback",
    ] {
        let resp = get_callback(path, &[]).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

/// A query on the token route is refused before a permit or a session is
/// spent.
#[tokio::test]
async fn github_token_refuses_a_query() {
    let req = Request::post("/api/v1/ceremony/github-token?trace=1")
        .header("content-type", "application/json")
        .header("origin", ccdp_origin())
        .body(Body::from(valid_body()))
        .unwrap();
    let resp = app(test_state().await).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Exactly `application/json`; `application/*+json` is refused.
#[tokio::test]
async fn github_token_takes_exactly_one_media_type() {
    // A body the media check passes and validation refuses: an accepted media
    // type is proved by exactly `400`.
    let body = r#"{"code":"6b7f2c1d9e4a8035","codeVerifier":"tooshort"}"#;
    for (media, admitted) in [
        ("application/json", true),
        ("application/json; charset=utf-8", true),
        ("application/vnd.libid+json", false),
        ("text/plain", false),
    ] {
        let req = Request::post("/api/v1/ceremony/github-token")
            .header("content-type", media)
            .header("origin", ccdp_origin())
            .body(Body::from(body))
            .unwrap();
        let resp = app(test_state().await).oneshot(req).await.unwrap();
        let expected = if admitted {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        };
        assert_eq!(resp.status(), expected, "{media}");
    }
}

/// A notary on a private address is refused before anything is dialled: a
/// `403`. A loopback one is dialled -- on the fixture's dead port, so the dial
/// fails at once and the answer is a `502`.
#[tokio::test]
async fn github_token_refuses_a_private_notary_and_dials_a_loopback_one() {
    let body = format!(
        r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","redirectUri":"{REDIRECT}","notaryAddress":"https://10.0.0.1:7048"}}"#
    );
    let resp = post_token(Some(ccdp_origin()), body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = post_token(Some(ccdp_origin()), valid_body()).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

/// The localhost HTTP exception, exactly as the contract states it: the two
/// exact hosts and nothing that merely resembles them.
#[tokio::test]
async fn github_token_admits_the_localhost_http_exception_and_nothing_like_it() {
    for admitted in ["http://localhost:7048", "http://127.0.0.1:7048"] {
        let body = format!(
            r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","redirectUri":"{REDIRECT}","notaryAddress":"{admitted}"}}"#
        );
        // Past the gate and dialled, on a port nothing listens on: a `502` is
        // the origin being admitted, where a `400` would be it refused.
        let resp = post_token(Some(ccdp_origin()), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{admitted}");
    }
    for refused in [
        "http://127.0.0.2:7048",
        "http://[::1]:7048",
        "http://notary.example",
    ] {
        let body = format!(
            r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","redirectUri":"{REDIRECT}","notaryAddress":"{refused}"}}"#
        );
        let resp = post_token(Some(ccdp_origin()), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{refused}");
    }
}

/// Public plaintext destinations and non-origin URL components remain refused.
#[tokio::test]
async fn github_token_refuses_an_invalid_notary_origin() {
    for bad in [
        "http://notary.example:7048",
        "http://127.1:7048",
        "127.0.0.1:7048",
        "https://127.0.0.1:7048/path",
        "https://127.0.0.1:7048?q=1",
        "https://user:pw@127.0.0.1:7048",
        "https://a;b.example",
        "not a url",
        "",
    ] {
        let body = format!(
            r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","redirectUri":"{REDIRECT}","notaryAddress":"{bad}"}}"#
        );
        let resp = post_token(Some(ccdp_origin()), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad:?}");
    }
}

/// `notaryAddress` is required.
#[tokio::test]
async fn github_token_refuses_a_body_without_a_notary_address() {
    let body = format!(
        r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","redirectUri":"{REDIRECT}"}}"#
    );
    let resp = post_token(Some(ccdp_origin()), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// One valid `Origin`, exactly the configured CCDP origin, on every request.
#[tokio::test]
async fn github_token_admits_the_ccdp_origin_and_nothing_else() {
    // A body validation refuses, so admission is proved without a session.
    let body = r#"{"code":"6b7f2c1d9e4a8035","codeVerifier":"tooshort","notaryAddress":"https://127.0.0.1:7048"}"#;
    let post = |origins: Vec<&'static str>| async move {
        let mut req = Request::post("/api/v1/ceremony/github-token")
            .header("content-type", "application/json");
        for origin in origins {
            req = req.header("origin", origin);
        }
        app(test_state().await)
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap()
            .status()
    };

    assert_eq!(
        post(vec![ccdp_origin()]).await,
        StatusCode::BAD_REQUEST,
        "the CCDP origin"
    );

    for origins in [
        // Admitted to read the configuration, and that grants nothing here.
        vec![APP_ORIGIN],
        vec!["https://wallet.example"],
        vec!["https://evil.example"],
        vec!["null"],
        vec!["not a url"],
        vec![],
        // The right origin twice is still two origins.
        vec![ccdp_origin(), ccdp_origin()],
        vec![ccdp_origin(), "https://evil.example"],
    ] {
        assert_eq!(
            post(origins.clone()).await,
            StatusCode::FORBIDDEN,
            "{origins:?}"
        );
    }
}

/// The token route's CORS layer covers the token route and nothing else: an
/// unserved path answers no preflight and carries no allow-origin header.
#[tokio::test]
async fn no_cors_reaches_a_path_this_bridge_does_not_serve() {
    let resp = app(test_state().await)
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/does-not-exist")
                .header("origin", ccdp_origin())
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "a preflight for a path that does not exist is a 404, not an advertisement"
    );
    assert!(resp.headers().get("access-control-allow-methods").is_none());
    assert!(resp.headers().get("access-control-allow-origin").is_none());

    let resp = app(test_state().await)
        .oneshot(
            Request::get("/does-not-exist")
                .header("origin", ccdp_origin())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "a 404 grants the CCDP origin no CORS relationship"
    );
}

/// A body over the ceiling is answered `413`.
#[tokio::test]
async fn github_token_says_so_when_the_body_is_over_the_limit() {
    let code = "a".repeat(16 * 1024);
    let body = format!(r#"{{"code":"{code}","codeVerifier":"{VERIFIER}"}}"#);
    let resp = post_token(Some(ccdp_origin()), body).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// The extractor's rejection text, which quotes the caller's field names and
/// byte offsets, does not travel.
#[tokio::test]
async fn a_refusal_body_quotes_nothing_the_caller_sent() {
    let body = format!(
        r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","zzMarkerFieldzz":1}}"#
    );
    let resp = post_token(Some(ccdp_origin()), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = body_of(resp).await.to_string();
    assert!(
        !text.contains("zzMarkerFieldzz"),
        "the refusal echoed the caller's own field name: {text}"
    );
    assert!(!text.contains("line 1 column"), "nor its offsets: {text}");
}
