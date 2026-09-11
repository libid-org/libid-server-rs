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

/// A deployment, built the way the binary builds one.
///
/// Through `build_state` and not a struct literal, so every derivation this
/// suite then makes assertions about -- the redirect URI joined from the
/// origin and the callback path, the client id shared by the published record
/// and the token request, the CCDP origin reaching the document, the record and
/// the token route's own gate -- is the one production performs. A hand-built
/// fixture asserts the literals the fixture typed.
///
/// It also means no test can construct a deployment `build_state` would
/// refuse, which is the only reason `build_router` may take an `AppState` and
/// route a configured path without being able to fail.
/// A loopback port nothing listens on, bound once and released: a session a
/// test does start fails at the dial instead of reaching a notary on this
/// machine.
fn dead_port() -> &'static str {
    static PORT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PORT.get_or_init(|| {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        free.local_addr().unwrap().port().to_string()
    })
}

fn deployment(overrides: &[&str]) -> Arc<AppState> {
    // Every flag that reads an environment variable is listed, so the process
    // environment reaches nothing. `--platforms` is this fixture's own: the
    // JSON records go to `Config::platforms`, which the binary fills from the
    // configuration file.
    let mut flags: Vec<(&str, &str)> = vec![
        ("--host", "127.0.0.1"),
        ("--port", "8722"),
        ("--callback-path", "/auth/callback"),
        (
            "--allowed-app-origins",
            "http://localhost:3000,https://wallet.example",
        ),
        ("--ccdp-origin", CCDP_ORIGIN),
        ("--notary-wire-port", dead_port()),
        (
            "--platforms",
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
    let platforms = flags
        .iter()
        .position(|(f, _)| *f == "--platforms")
        .map(|i| flags.remove(i).1)
        .expect("the fixture lists --platforms");
    let mut argv = vec!["libid-server-rs"];
    for (flag, value) in &flags {
        argv.push(flag);
        argv.push(value);
    }
    let mut cfg = Config::parse_from(argv);
    cfg.platforms =
        serde_json::from_str(platforms).expect("the fixture's platform records");
    build_state(&cfg).expect("a deployment this suite can serve")
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

/// A notary as a request names one: the origin the browser resolved from the
/// ledger, on the port its own WebSocket session used. That port is not this
/// bridge's business -- it dials the same host on the wire port, which is a
/// convention -- and loopback is what makes this one refusable: a private
/// destination is not dialled unless a deployment has permitted it.
const NOTARY: &str = "https://127.0.0.1:7048";

/// The registered callback URL a request carries: the fixture's callback path
/// under a canonical origin.
const REDIRECT: &str = "https://bridge.example/auth/callback";

/// A request body carrying every field, varying only the two under test.
///
/// One shape, because the tests below are a comparison: they mean something
/// only while the body they refuse and the body they admit differ in nothing
/// else. Built rather than written out, so a later edit cannot quietly drop a
/// field from one of them and leave the pair asserting nothing.
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
    let resp = post_token(Some(ORIGIN), body).await;
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
        let resp = post_token(Some(ORIGIN), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad:?}");
    }
    let body = format!(
        r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","notaryAddress":"{NOTARY}"}}"#
    );
    let resp = post_token(Some(ORIGIN), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "missing");
}

#[tokio::test]
async fn github_token_refuses_a_malformed_body() {
    let resp = post_token(Some(ORIGIN), "{\"code\":".into()).await;
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

/// The control the two tests above rest on, and the reason they hold a permit.
///
/// Both the JSON rejection and the `validate()` refusal answer `400` with the
/// same message -- deliberately, so a caller cannot tell one from the other --
/// so a `400` alone proves nothing about WHICH refused. These two once sent
/// bodies with no `notaryAddress` at all: serde refused them for the missing
/// field, and neither test ever reached the bound it is named for.
///
/// With no permit free, a body that gets past the bounds is answered `503` by
/// the next gate. So this and the two above form one comparison: three bodies
/// of one shape, differing only in the field under test, and the `400`s are the
/// bounds because this one is not a `400`.
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
    let state = test_state();
    let _held = state
        .exchange_permits()
        .expect("github is enabled")
        .try_acquire_many(libid_server_rs::state::MAX_CONCURRENT_EXCHANGES as u32)
        .expect("every permit is free at the start of this test");
    let req = Request::post("/api/v1/ceremony/github-token")
        .header("content-type", "application/json")
        .header("origin", ORIGIN)
        .body(Body::from(body))
        .unwrap();
    app(state.clone()).oneshot(req).await.unwrap().status()
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
    let _held = state
        .exchange_permits()
        .expect("github is enabled")
        .try_acquire_many(libid_server_rs::state::MAX_CONCURRENT_EXCHANGES as u32)
        .expect("every permit is free at the start of this test");
    let resp = app(state.clone()).oneshot(req).await.unwrap();
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

/// The preflight admits exactly what the handler does.
///
/// The two are one rule seen from two places: a layer wider than the gate
/// advertises access this route then refuses, and one narrower lets a caller
/// past the gate and has the browser discard the answer for want of a matching
/// allow-origin header -- a failure with no server-side symptom at all.
#[tokio::test]
async fn the_token_preflight_admits_exactly_what_the_handler_does() {
    let preflight = |origin: &'static str| async move {
        app(test_state())
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

    let resp = preflight(ORIGIN).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h.get("access-control-allow-origin").unwrap(), ORIGIN);
    assert_eq!(h.get("access-control-allow-methods").unwrap(), "POST");
    assert_eq!(
        h.get("access-control-allow-headers").unwrap(),
        "content-type"
    );
    assert!(h.get("access-control-allow-credentials").is_none());
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty(), "a preflight carries no ceremony data");

    // Everything else gets no allow-origin header at all: the layer filters
    // rather than announcing a value and leaving the refusal to the browser.
    // An application origin is refused here and admitted on `/config`, which is
    // the difference between the two rules.
    for other in [APP_ORIGIN, "https://wallet.example", "https://evil.example"] {
        let resp = preflight(other).await;
        assert!(
            resp.headers().get("access-control-allow-origin").is_none(),
            "{other}"
        );
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
    let headers: Vec<(&str, &str)> = origin.into_iter().map(|o| ("origin", o)).collect();
    config_with(test_state(), &headers, query).await
}

/// The same route with arbitrary headers, so a test can send Fetch metadata, a
/// `Referer`, or the same header twice -- none of which `get_config` can
/// express, and each of which the admission rule has something to say about.
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
        // A browser sends this for an opaque origin.
        Some("null"),
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

/// Two `Origin` headers is not a request a browser sends, and taking the first
/// would let a caller choose which one is read.
#[tokio::test]
async fn config_refuses_an_origin_sent_twice() {
    let two_origins = config_with(
        test_state(),
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
        test_state(),
        &[
            ("referer", "http://127.0.0.1:8722/"),
            ("host", "127.0.0.1:8722"),
        ],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// `Origin` decides the body, so a shared cache is told so -- on refusals as
/// well, or a cache that ignores `no-store` could replay a 403 to an origin
/// this deployment admits.
#[tokio::test]
async fn config_varies_on_origin() {
    let admitted = config_with(test_state(), &[("origin", APP_ORIGIN)], "").await;
    assert_eq!(admitted.status(), StatusCode::OK);
    assert_eq!(admitted.headers().get("vary").unwrap(), "origin");

    let refused =
        config_with(test_state(), &[("origin", "https://evil.example")], "").await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(refused.headers().get("vary").unwrap(), "origin");
}

/// The record carries exactly what the contract lists and nothing else.
///
/// The allowlist is absent because the contract says the record contains
/// no such field -- not because the list is secret: the callback document
/// carries
/// it in a document served to anyone, and the Callback module needs it there.
/// The secret is the field that genuinely must never appear.
#[tokio::test]
async fn config_carries_no_secret_and_no_admitted_origin() {
    let body = body_of(get_config(Some(APP_ORIGIN), "").await).await;
    let object = body.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["callbackPath", "ccdpOrigin", "platforms"]);
    assert_eq!(body["ccdpOrigin"], CCDP_ORIGIN);
    assert_eq!(body["callbackPath"], "/auth/callback");
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
        "--platforms",
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

// ─── the callback document ───────────────────────────────────────────────────

async fn get_callback(path: &str, headers: &[(&str, &str)]) -> axum::response::Response {
    let mut req = Request::get(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    app(test_state())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// The provider brings the return in the query; the document must not vary, and
/// no `Origin` or `Referer` may change a byte of it. One document, whatever
/// arrives.
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
        // Kept for the shape, not the coverage: a fragment never reaches the
        // wire, so `Uri` drops it and this is the bare path again. What clears
        // the fragment is the bootstrap, covered by
        // the artifact's own bundled code, which this bridge neither writes
        // nor inspects.
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

/// The exact policy the contract lists, and the one that must not be got
/// wrong: NOT isolated, so the application opener survives the provider.
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
    assert_eq!(directive("frame-src"), format!("frame-src {CCDP_ORIGIN}"));
    assert_eq!(directive("connect-src"), "connect-src 'none'");
    // The package owns its styles now; there is no stylesheet hash to
    // configure and no external stylesheet source to admit.
    assert_eq!(directive("style-src"), "style-src 'unsafe-inline'");

    // DIRECTIVE-SCOPED, not a substring search over the whole policy.
    // `'unsafe-inline'` is legitimate above, so a test that forbade the token
    // everywhere would either fail here or get "fixed" by deleting the very
    // token it exists to catch in `script-src`.
    let script_src = directive("script-src");
    let tokens: Vec<&str> = script_src.split(' ').skip(1).collect();
    assert!(!tokens.is_empty(), "no hash in {script_src}");
    for token in &tokens {
        assert!(
            token.starts_with("'sha256-") && token.ends_with('\''),
            "{token} in {script_src} is not a hash"
        );
    }
    // No external script source at all: the artifact bundles its dependencies,
    // so the CCDP module URL a generated shell would have imported is gone.
    assert!(
        !script_src.contains(CCDP_ORIGIN),
        "an external script source survived in {script_src}"
    );

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("<main id=\"libid-root\"></main>"));
    assert!(!html.contains("test-client-secret"));

    // One module script, and one hash naming it. That the hash is the RIGHT
    // one is asserted where `hash_source` lives, in `artifact::tests` -- it
    // cannot drift there, and this suite has no reason to own a copy of the
    // digest code.
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
        let resp = get_callback(path, &[]).await;
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
    // A body the media check passes and the NEXT check refuses, so an
    // accepted media type is proved by a `400` from validation rather than by
    // whatever an exchange would answer -- and asserted as exactly `400`, not
    // as "not 415", so an answer from further down cannot pass for admission.
    let body = r#"{"code":"6b7f2c1d9e4a8035","codeVerifier":"tooshort"}"#;
    for (media, admitted) in [
        ("application/json", true),
        ("application/json; charset=utf-8", true),
        ("application/vnd.libid+json", false),
        ("text/plain", false),
    ] {
        let req = Request::post("/api/v1/ceremony/github-token")
            .header("content-type", media)
            .header("origin", ORIGIN)
            .body(Body::from(body))
            .unwrap();
        let resp = app(test_state()).oneshot(req).await.unwrap();
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
    let resp = post_token(Some(ORIGIN), body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = post_token(Some(ORIGIN), valid_body()).await;
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
        let resp = post_token(Some(ORIGIN), body).await;
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
        let resp = post_token(Some(ORIGIN), body).await;
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
        let resp = post_token(Some(ORIGIN), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad:?}");
    }
}

/// The field is required: the contract makes it part of the request, and
/// `deny_unknown_fields` cuts both ways -- a body without it is not a
/// `TokenRequest`.
#[tokio::test]
async fn github_token_refuses_a_body_without_a_notary_address() {
    let body = format!(
        r#"{{"code":"6b7f2c1d9e4a8035","codeVerifier":"{VERIFIER}","redirectUri":"{REDIRECT}"}}"#
    );
    let resp = post_token(Some(ORIGIN), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// One valid `Origin`, exactly the configured CCDP origin, on every request.
///
/// Narrower than the configuration route on purpose: the caller here is the
/// Prover, which runs on that origin and nowhere else, so admitting an
/// application origin would widen the one route that spends the client secret
/// for no caller that exists.
#[tokio::test]
async fn github_token_admits_the_ccdp_origin_and_nothing_else() {
    // A body the NEXT check refuses, so admission is proved without opening a
    // notary session.
    let body = r#"{"code":"6b7f2c1d9e4a8035","codeVerifier":"tooshort","notaryAddress":"https://127.0.0.1:7048"}"#;
    let post = |origins: Vec<&'static str>| async move {
        let mut req = Request::post("/api/v1/ceremony/github-token")
            .header("content-type", "application/json");
        for origin in origins {
            req = req.header("origin", origin);
        }
        app(test_state())
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap()
            .status()
    };

    assert_eq!(
        post(vec![ORIGIN]).await,
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
        vec![ORIGIN, ORIGIN],
        vec![ORIGIN, "https://evil.example"],
    ] {
        assert_eq!(
            post(origins.clone()).await,
            StatusCode::FORBIDDEN,
            "{origins:?}"
        );
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
