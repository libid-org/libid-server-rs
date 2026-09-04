//! HTTP-level tests over the axum router, plus the challenge lifecycle and
//! OAuth-state round-trip.

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
    routes,
    state::AppState,
};
use tokio::sync::Semaphore;
use tower::ServiceExt;

const APP_ORIGIN: &str = "http://localhost:3000";
const CCDP_ORIGIN: &str = "https://ccdp.example";

/// The state carries no signing identity: the service holds no key.
fn state_with(permits: usize, github: bool) -> Arc<AppState> {
    let redirect_uri = "http://127.0.0.1:8722/auth/callback";
    let allowed_app_origins: Vec<String> =
        vec![APP_ORIGIN.into(), "https://wallet.example".into()];
    Arc::new(AppState {
        server_origin: "http://127.0.0.1:8722".into(),
        callback_path: "/auth/callback".into(),
        ccdp_origin: CCDP_ORIGIN.into(),
        notary_addr: "127.0.0.1:7047".into(),
        ceremony_config: routes::config::frozen(
            redirect_uri,
            CCDP_ORIGIN,
            &libid_server_rs::deployment::platforms(
                r#"[{"id":"github","clientId":"test-client-id","versions":[1]}]"#,
            )
            .unwrap(),
        )
        .unwrap(),
        callback_shell: libid_server_rs::shell::callback(
            &libid_server_rs::shell::ShellInputs {
                ccdp_origin: CCDP_ORIGIN,
                supported_versions: &[1],
                allowed_app_origins: &allowed_app_origins,
                style_hash: "",
            },
        )
        .unwrap(),
        allowed_app_origins,
        github_oauth: github.then(|| libid_server_rs::oauth::OAuthCredentials {
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
            redirect_uri: redirect_uri.into(),
        }),
        exchange_permits: Arc::new(Semaphore::new(permits)),
    })
}

/// A state whose exchange ceiling is the default.
fn test_state() -> Arc<AppState> {
    state_with(routes::github_token::MAX_CONCURRENT_EXCHANGES, true)
}

fn app(state: Arc<AppState>) -> axum::Router {
    routes::build_router(&state).with_state(state)
}

#[tokio::test]
async fn health_is_ok() {
    let resp = app(test_state())
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"OK");
}

// ─── the GitHub token route ──────────────────────────────────────────────────
//
// Every case here is refused before a notary session is opened, which is the
// point: a request that will not be honoured must not cost an MPC-TLS session,
// and must not spend the client secret. That they can be driven at all without
// a notary listening is the evidence.

const ORIGIN: &str = CCDP_ORIGIN;
const VERIFIER: &str = "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I";

async fn post_token(origin: Option<&str>, body: String) -> axum::response::Response {
    let mut req = Request::post("/api/v1/ceremony/github-token")
        .header("content-type", "application/json");
    if let Some(origin) = origin {
        req = req.header("origin", origin);
    }
    app(test_state())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

fn valid_body() -> String {
    format!(r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}"}}"#)
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

/// The route takes a code and a verifier and nothing else. A body carrying a
/// `redirectUri`, a `clientId` or an endpoint is refused rather than ignored:
/// silently dropping them would leave a caller believing it had steered
/// something.
#[tokio::test]
async fn github_token_refuses_a_body_that_tries_to_steer_the_exchange() {
    let body = format!(
        r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","redirectUri":"https://evil.example/cb"}}"#
    );
    let resp = post_token(Some(ORIGIN), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn github_token_refuses_a_malformed_body() {
    let resp = post_token(Some(ORIGIN), "{\"code\":".into()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn github_token_refuses_an_over_long_code() {
    let body = format!(
        r#"{{"code":"{}","codeVerifier":"{VERIFIER}"}}"#,
        "a".repeat(4096)
    );
    let resp = post_token(Some(ORIGIN), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn github_token_refuses_a_verifier_of_the_wrong_length() {
    let body = r#"{"code":"6b7f2c1d9e4a8035","codeVerifier":"tooshort"}"#;
    let resp = post_token(Some(ORIGIN), body.into()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Each exchange is a full MPC-TLS session and an outbound request that spends
/// the client secret, and the origin check is not caller authentication. So the
/// ceiling is real, and a request that finds it is shed rather than queued —
/// held requests are the same exhaustion with a longer fuse.
#[tokio::test]
async fn github_token_sheds_when_no_permit_is_free() {
    let req = Request::post("/api/v1/ceremony/github-token")
        .header("content-type", "application/json")
        .header("origin", ORIGIN)
        .body(Body::from(valid_body()))
        .unwrap();
    let resp = app(state_with(0, true)).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
}

/// The origin is checked before the body is even parsed, so a foreign page
/// cannot use a malformed body to tell one refusal from the other.
#[tokio::test]
async fn github_token_checks_the_origin_before_the_body() {
    let resp = post_token(Some("https://evil.example"), "not json at all".into()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// The route carries no schema member — its path already versions the
/// transport — so one offered is an additional field like any other, and the
/// contract refuses it rather than ignoring it.
#[tokio::test]
async fn github_token_refuses_a_body_carrying_a_schema() {
    let body = format!(
        r#"{{"schema":1,"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}"}}"#
    );
    let resp = post_token(Some(ORIGIN), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// The prover runs on the CCDP Distribution and calls this route cross-origin,
/// so the preflight is answered — naming exactly that origin, with `POST` and
/// `Content-Type` and no credentials, and with no ceremony data in it. A page
/// anywhere else, this bridge's own origin included, is told the same thing,
/// which for it is a refusal.
#[tokio::test]
async fn the_token_preflight_is_answered_for_the_ccdp_origin_alone() {
    for (origin, admitted) in [
        (CCDP_ORIGIN, true),
        ("http://127.0.0.1:8722", false),
        ("https://evil.example", false),
    ] {
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/ceremony/github-token")
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .body(Body::empty())
            .unwrap();
        let resp = app(test_state()).oneshot(req).await.unwrap();
        let h = resp.headers();
        // The layer never echoes the caller. It names the one configured
        // origin whoever asks, and a browser anywhere else compares that
        // against its own origin and refuses on its side.
        assert_eq!(h.get("access-control-allow-origin").unwrap(), CCDP_ORIGIN);
        if !admitted {
            assert_ne!(h.get("access-control-allow-origin").unwrap(), origin);
        }
        let methods = h
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(methods.contains("POST"), "{methods}");
        let headers = h
            .get("access-control-allow-headers")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            headers.to_ascii_lowercase().contains("content-type"),
            "{headers}"
        );
        assert!(h.get("access-control-allow-credentials").is_none());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.is_empty(), "a preflight carries no ceremony data");
    }
}

/// The origin gate on the POST is the CCDP origin, and specifically NOT this
/// bridge's own: nothing on the bridge origin ever calls this route, so a
/// request claiming to be from it is a request claiming to be from nowhere.
#[tokio::test]
async fn github_token_admits_the_ccdp_origin_and_not_the_bridges_own() {
    let resp = post_token(Some("http://127.0.0.1:8722"), valid_body()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── the public ceremony configuration ───────────────────────────────────────

async fn get_config(origin: Option<&str>, query: &str) -> axum::response::Response {
    let mut req = Request::get(format!("/api/v1/ceremony/config{query}"));
    if let Some(origin) = origin {
        req = req.header("origin", origin);
    }
    app(test_state())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body_of(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// An admitted application is answered with its OWN origin, never a wildcard
/// and never the list: the record is readable by the applications this
/// deployment admits, not by the web.
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
/// header — so it cannot read the record out of the refusal either. Absent and
/// unlisted are answered the same way: which one it was is not the caller's
/// business.
#[tokio::test]
async fn config_refuses_an_absent_or_unlisted_origin() {
    for origin in [
        None,
        Some("https://evil.example"),
        // Near misses. A browser sends none of these for an admitted page.
        Some("http://LOCALHOST:3000"),
        Some("http://localhost:3000/"),
        Some("http://localhost:3001"),
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

/// The record carries what an application needs to start a ceremony and
/// nothing else. A secret or an admitted-origin list in here would be a
/// deployment publishing its own configuration to every application it admits.
#[tokio::test]
async fn config_carries_no_secret_and_no_admitted_origin() {
    let body = body_of(get_config(Some(APP_ORIGIN), "").await).await;
    let object = body.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["ccdpOrigin", "platforms", "redirectUri"]);
    assert_eq!(body["ccdpOrigin"], CCDP_ORIGIN);

    assert_eq!(
        body["redirectUri"], "http://127.0.0.1:8722/auth/callback",
        "the record publishes the same redirect URI the token request sends"
    );
    assert_eq!(body["platforms"]["github"]["clientId"], "test-client-id");
    assert_eq!(body["platforms"]["github"]["ceremonyVersions"][0], 1);

    let raw = body.to_string();
    assert!(!raw.contains("test-client-secret"));
    assert!(!raw.contains(APP_ORIGIN));
    assert!(
        !raw.contains("circuitUrl"),
        "an application selects no artifact"
    );
}

/// The origin is decided before the query, so an unlisted caller cannot use a
/// malformed request to tell one refusal from another.
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

/// The confidential route exists only where a secret backs it. A path that
/// answered without one would be worse than a path that is not there.
#[tokio::test]
async fn the_token_route_is_absent_when_github_is_not_enabled() {
    let state = state_with(routes::github_token::MAX_CONCURRENT_EXCHANGES, false);
    let req = Request::post("/api/v1/ceremony/github-token")
        .header("content-type", "application/json")
        .header("origin", ORIGIN)
        .body(Body::from(valid_body()))
        .unwrap();
    let resp = app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── the callback shell ──────────────────────────────────────────────────────

async fn get_shell(path: &str, headers: &[(&str, &str)]) -> axum::response::Response {
    let mut req = Request::get(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    app(test_state())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// The provider brings the return in the query; the shell must not care, and
/// no `Origin` or `Referer` may change a byte of it. One document, whatever
/// arrives.
#[tokio::test]
async fn the_callback_shell_is_the_same_bytes_whatever_the_request() {
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
        ("/auth/callback#id_token=x&state=v1.9e1f", vec![]),
    ] {
        let resp = get_shell(path, &headers).await;
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

/// The exact policy the contract lists, and the one that must not be got
/// wrong: NOT isolated, so the application opener survives the provider.
#[tokio::test]
async fn the_callback_shell_carries_the_exact_response_policy() {
    let resp = get_shell("/auth/callback", &[]).await;
    let h = resp.headers();
    assert_eq!(h.get("cross-origin-opener-policy").unwrap(), "unsafe-none");
    assert!(h.get("cross-origin-embedder-policy").is_none());
    assert_eq!(h.get("content-type").unwrap(), "text/html; charset=utf-8");
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
    assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
    let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
    for directive in [
        "default-src 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "frame-src https://ccdp.example",
        "connect-src 'none'",
        "'sha256-",
        "https://ccdp.example/ccdp/v1/callback.js",
    ] {
        assert!(csp.contains(directive), "{directive} missing from {csp}");
    }
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("<main id=\"libid-root\"></main>"));
    assert_eq!(html.matches("<script").count(), 1);
    assert!(!html.contains("test-client-secret"));
}

/// The shell is a navigation target, and only that.
#[tokio::test]
async fn the_callback_shell_admits_only_get() {
    let req = Request::post("/auth/callback").body(Body::empty()).unwrap();
    let resp = app(test_state()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// One callback path. The paths an earlier revision of this branch served —
/// and the alias it once had — are not routes on this bridge.
#[tokio::test]
async fn the_bridge_serves_no_ccdp_document_and_no_alias() {
    for path in [
        "/ccdp/callback",
        "/ccdp/prover",
        "/auth/v1/callback",
        "/api/v1/ceremony/callback",
    ] {
        let resp = get_shell(path, &[]).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
}
