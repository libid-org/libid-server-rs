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

/// The state carries no signing identity: the service holds no key.
fn state_with(permits: usize) -> Arc<AppState> {
    Arc::new(AppState {
        server_origin: "http://127.0.0.1:8722".into(),
        notary_addr: "127.0.0.1:7047".into(),
        github_oauth: libid_server_rs::oauth::OAuthCredentials {
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
            redirect_uri: "http://127.0.0.1:8722/api/v1/ceremony/callback".into(),
        },
        exchange_permits: Arc::new(Semaphore::new(permits)),
    })
}

/// A state whose exchange ceiling is the default.
fn test_state() -> Arc<AppState> {
    state_with(routes::github_token::MAX_CONCURRENT_EXCHANGES)
}

fn app(state: Arc<AppState>) -> axum::Router {
    routes::build_router().with_state(state)
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

const ORIGIN: &str = "http://127.0.0.1:8722";
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
    let resp = app(state_with(0)).oneshot(req).await.unwrap();
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

/// REQ-PLAT-43A: the preflight is answered, and REQ-PLAT-43 fixes what it is
/// answered with — one compiled origin. The layer never echoes the caller's,
/// so a page elsewhere is told it is not allowed, whoever asked.
#[tokio::test]
async fn the_preflight_names_the_one_origin_whoever_asks() {
    for origin in [ORIGIN, "https://evil.example"] {
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/ceremony/github-token")
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .body(Body::empty())
            .unwrap();
        let app = routes::build_router()
            .with_state(test_state())
            .layer(routes::cors_layer(ORIGIN));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            ORIGIN,
            "asked by {origin}"
        );
    }
}

/// A configured origin no header can carry produces a layer that allows
/// nothing, rather than one that allows everything.
#[tokio::test]
async fn an_unusable_configured_origin_allows_nobody() {
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/api/v1/ceremony/github-token")
        .header("origin", ORIGIN)
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let app = routes::build_router()
        .with_state(test_state())
        .layer(routes::cors_layer("not a header value\n"));
    let resp = app.oneshot(req).await.unwrap();
    assert!(!resp.headers().contains_key("access-control-allow-origin"));
}
