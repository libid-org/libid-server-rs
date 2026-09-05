//! HTTP-level tests over the axum router: the public configuration, the
//! callback shell's invariance and policy, and the token route's origin gate.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{
        Request,
        StatusCode,
    },
};
use clap::Parser;
use http_body_util::BodyExt;
use libid_server_rs::{
    build_state,
    config::Config,
    routes,
    state::AppState,
};
use tower::ServiceExt;

const APP_ORIGIN: &str = "http://localhost:3000";
const CCDP_ORIGIN: &str = "https://ccdp.example";
/// What `build_state` must derive from the base URL and the callback path.
/// Written here as a literal precisely so the derivation has something to be
/// checked against; the fixture no longer supplies it.
const REDIRECT_URI: &str = "http://127.0.0.1:8722/auth/callback";

/// A deployment, built the way the binary builds one.
///
/// Through `build_state` and not a struct literal, so every derivation this
/// suite then makes assertions about -- the redirect URI joined from the
/// origin and the callback path, the client id shared by the published record
/// and the token request, the CCDP origin reaching the shell, the record and
/// the token route's own gate -- is the one production performs. A hand-built
/// fixture asserts the literals the fixture typed.
///
/// It also means no test can construct a deployment `build_state` would
/// refuse, which is the only reason `build_router` may take an `AppState` and
/// route a configured path without being able to fail.
fn deployment(overrides: &[&str]) -> Arc<AppState> {
    let mut flags: Vec<(&str, &str)> = vec![
        ("--base-url", "http://127.0.0.1:8722"),
        (
            "--allowed-app-origins",
            "http://localhost:3000,https://wallet.example",
        ),
        ("--ccdp-origin", CCDP_ORIGIN),
        ("--notary-url", "tcp://127.0.0.1:7047"),
        (
            "--ceremony-platforms",
            r#"[{"id":"github","clientId":"test-client-id","versions":[1]}]"#,
        ),
        ("--gh-oauth-client-secret", "test-client-secret"),
    ];
    for pair in overrides.chunks(2) {
        let [flag, value] = pair else {
            panic!("test flags come in pairs, got {pair:?}")
        };
        match flags.iter_mut().find(|(f, _)| f == flag) {
            Some(slot) => slot.1 = value,
            None => flags.push((flag, value)),
        }
    }
    let mut argv = vec!["libid-server-rs"];
    for (flag, value) in &flags {
        argv.push(flag);
        argv.push(value);
    }
    build_state(&Config::parse_from(argv)).expect("a deployment this suite can serve")
}

/// The default deployment: GitHub enabled, the full exchange ceiling free.
fn test_state() -> Arc<AppState> {
    deployment(&[])
}

fn app(state: Arc<AppState>) -> axum::Router {
    routes::build_router(state)
}

#[tokio::test]
async fn health_answers_ok_and_carries_nosniff_like_every_other_route() {
    let resp = app(test_state())
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
    // Held, not configured away: the ceiling is what production sets, and
    // this is what a full one looks like from outside.
    let state = test_state();
    let github = state.github.clone().expect("github is enabled");
    let _held = github
        .permits
        .try_acquire_many(libid_server_rs::state::MAX_CONCURRENT_EXCHANGES as u32)
        .expect("every permit is free at the start of this test");
    let resp = app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
}

/// A foreign page cannot use a malformed body to tell one refusal from the
/// other: whatever the body, the answer is the origin's.
///
/// The parse itself happens first regardless -- it is an extractor, and axum
/// runs those before the handler -- which is why the route also carries a body
/// limit rather than relying on this ordering.
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
/// so the preflight is answered for that origin -- `POST`, `Content-Type`, no
/// credentials, no ceremony data. Every other origin gets no allow-origin
/// header at all: the layer filters rather than announcing a value and leaving
/// the refusal to the browser.
#[tokio::test]
async fn the_token_preflight_admits_the_ccdp_origin_and_no_other() {
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
        if admitted {
            assert_eq!(h.get("access-control-allow-origin").unwrap(), CCDP_ORIGIN);
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
        } else {
            assert!(
                h.get("access-control-allow-origin").is_none(),
                "{origin} must get no allow-origin header"
            );
        }
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

/// The record carries exactly what the contract lists and nothing else.
///
/// `allowedAppOrigins` is absent because the contract says the record contains
/// no such field -- not because the list is secret: the callback shell embeds
/// it in a document served to anyone, and the Callback module needs it there.
/// The secret is the field that genuinely must never appear.
#[tokio::test]
async fn config_carries_no_secret_and_no_admitted_origin() {
    let body = body_of(get_config(Some(APP_ORIGIN), "").await).await;
    let object = body.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["ccdpOrigin", "platforms", "redirectUri"]);
    assert_eq!(body["ccdpOrigin"], CCDP_ORIGIN);

    assert_eq!(
        body["redirectUri"], REDIRECT_URI,
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
    let state = deployment(&[
        "--ceremony-platforms",
        r#"[{"id":"x","clientId":"test-client-id","versions":[1]}]"#,
        "--gh-oauth-client-secret",
        "",
    ]);
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
        // Kept for the shape, not the coverage: a fragment never reaches the
        // wire, so `Uri` drops it and this is the bare path again. What clears
        // the fragment is the bootstrap, covered by
        // `shell::tests::the_bootstrap_clears_the_return_before_it_decides_anything`.
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

/// The contract says the token route's query is empty, and a query on a route
/// that carries an authorization code is exactly what a proxy access log
/// records by default. It is refused before a permit or a session is spent.
#[tokio::test]
async fn github_token_refuses_a_query() {
    let req = Request::post("/api/v1/ceremony/github-token?trace=1")
        .header("content-type", "application/json")
        .header("origin", ORIGIN)
        .body(Body::from(valid_body()))
        .unwrap();
    let resp = app(test_state()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// "Exactly `application/json`". The extractor alone would also admit any
/// `application/*+json`, which is a wider door than the contract opens.
#[tokio::test]
async fn github_token_takes_exactly_one_media_type() {
    for (media, ok) in [
        ("application/json", true),
        ("application/json; charset=utf-8", true),
        ("application/vnd.libid+json", false),
        ("text/plain", false),
    ] {
        let req = Request::post("/api/v1/ceremony/github-token")
            .header("content-type", media)
            .header("origin", ORIGIN)
            .body(Body::from(valid_body()))
            .unwrap();
        let resp = app(test_state()).oneshot(req).await.unwrap();
        if ok {
            assert_ne!(
                resp.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{media} is the media type the contract names"
            );
        } else {
            assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE, "{media}");
        }
    }
}

/// The token route's CORS layer covers the token route and nothing else.
///
/// `Router::layer` wraps a sub-router's fallback as well as its routes, and
/// `merge` carries that layered fallback out into the whole router. Applied
/// that way here, every path this bridge does not serve answered a preflight
/// advertising `POST` and handed the CCDP origin an allow-origin header on its
/// 404 -- a route surface the contract closes, and the opposite of "unsupported
/// methods fail without route work".
#[tokio::test]
async fn no_cors_reaches_a_path_this_bridge_does_not_serve() {
    let resp = app(test_state())
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/does-not-exist")
                .header("origin", CCDP_ORIGIN)
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

    let resp = app(test_state())
        .oneshot(
            Request::get("/does-not-exist")
                .header("origin", CCDP_ORIGIN)
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

/// A body over the ceiling is told so. `400` said only "your body is wrong",
/// which made the limit this route sets invisible to the caller it is set for.
#[tokio::test]
async fn github_token_says_so_when_the_body_is_over_the_limit() {
    let code = "a".repeat(16 * 1024);
    let body = format!(r#"{{"code":"{code}","codeVerifier":"{VERIFIER}"}}"#);
    let resp = post_token(Some(ORIGIN), body).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// "Failure returns no partial credential, attestation, or caller-selected
/// diagnostic content", says the contract. The extractor's own rejection text
/// quotes the caller's field names and byte offsets, so it does not travel.
#[tokio::test]
async fn a_refusal_body_quotes_nothing_the_caller_sent() {
    let body = format!(
        r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","zzMarkerFieldzz":1}}"#
    );
    let resp = post_token(Some(ORIGIN), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = body_of(resp).await.to_string();
    assert!(
        !text.contains("zzMarkerFieldzz"),
        "the refusal echoed the caller's own field name: {text}"
    );
    assert!(!text.contains("line 1 column"), "nor its offsets: {text}");
}
