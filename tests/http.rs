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
/// What `build_state` must derive from the base URL and the callback path.
/// Written here as a literal precisely so the derivation has something to be
/// checked against; the fixture no longer supplies it.
const REDIRECT_URI: &str = "http://127.0.0.1:8722/auth/callback";

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
fn deployment(overrides: &[&str]) -> Arc<AppState> {
    // EVERY flag that reads an environment variable is listed, including
    // ones no assertion cares about. clap falls back to the process
    // environment for any flag an argv does not carry, so an omitted one
    // is the developer's shell reaching into the fixture -- `CALLBACK_PATH`
    // exported for a local run makes the router mount somewhere else and
    // every callback assertion fails with a 404 that names no cause.
    let mut flags: Vec<(&str, &str)> = vec![
        ("--host", "127.0.0.1"),
        ("--port", "8722"),
        ("--callback-path", "/auth/callback"),
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

/// The preflight admits every member of the effective set and nothing else.
///
/// The handler admits the whole set, so a layer echoing only the CCDP origin
/// would let a configured application origin past the gate and then have the
/// browser discard the answer for want of a matching allow-origin header --
/// a failure with no server-side symptom at all.
#[tokio::test]
async fn the_token_preflight_admits_the_effective_set_and_no_other() {
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

    for origin in [ORIGIN, APP_ORIGIN, "https://wallet.example"] {
        let resp = preflight(origin).await;
        assert_eq!(resp.status(), StatusCode::OK, "{origin}");
        let h = resp.headers();
        assert_eq!(h.get("access-control-allow-origin").unwrap(), origin);
        assert_eq!(h.get("access-control-allow-methods").unwrap(), "POST");
        assert_eq!(
            h.get("access-control-allow-headers").unwrap(),
            "content-type"
        );
        // Noncredentialed, and it carries no ceremony data.
        assert!(h.get("access-control-allow-credentials").is_none());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty(), "{origin} got a body");
    }

    // Anything outside the set gets no allow-origin header at all: the layer
    // filters rather than announcing a value and leaving the refusal to the
    // browser.
    let resp = preflight("https://evil.example").await;
    assert!(resp.headers().get("access-control-allow-origin").is_none());
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

/// A deployment that admits its own origin, which is what opens the
/// same-origin exception at all. The default fixture deliberately does not.
fn admits_itself() -> Arc<AppState> {
    deployment(&[
        "--allowed-app-origins",
        "http://127.0.0.1:8722,http://localhost:3000",
    ])
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
        // A browser sends this for an opaque origin. It is a value, not an
        // absence, so it fails as an unlisted origin rather than reaching the
        // same-origin path.
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

/// A same-origin `GET` carries no `Origin`, so Fetch metadata is the only
/// thing that can distinguish it from a top-level navigation or a cross-site
/// request. It is admitted, and it gets no allow-origin header -- a header
/// granting an origin access to itself says nothing.
#[tokio::test]
async fn config_admits_a_same_origin_get_when_the_bridge_admits_its_own_origin() {
    let resp =
        config_with(admits_itself(), &[("sec-fetch-site", "same-origin")], "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "a same-origin read needs no CORS header"
    );
}

/// And the exception is closed for a deployment that does not admit itself:
/// there is no same-origin application to admit. The default fixture's
/// `--base-url` is deliberately absent from its `--allowed-app-origins`.
#[tokio::test]
async fn config_refuses_a_same_origin_get_when_the_bridge_is_not_in_its_own_allowlist() {
    let resp = config_with(test_state(), &[("sec-fetch-site", "same-origin")], "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// `same-origin` and nothing else. A missing header is refused too: absent
/// Fetch metadata is not evidence of anything, and treating it as same-origin
/// would admit every client that simply does not send it.
#[tokio::test]
async fn config_refuses_every_fetch_site_but_same_origin() {
    for site in [
        "same-site",
        "cross-site",
        "none",
        "SAME-ORIGIN",
        " same-origin",
    ] {
        let resp = config_with(admits_itself(), &[("sec-fetch-site", site)], "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{site:?}");
    }
    // No metadata at all.
    let resp = config_with(admits_itself(), &[], "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "missing metadata");
}

/// Two of either header is not a request a browser sends, and taking the first
/// would let a caller choose which one is read.
#[tokio::test]
async fn config_refuses_a_header_sent_twice() {
    let two_origins = config_with(
        admits_itself(),
        &[("origin", APP_ORIGIN), ("origin", "https://evil.example")],
        "",
    )
    .await;
    assert_eq!(two_origins.status(), StatusCode::FORBIDDEN, "two origins");

    let two_sites = config_with(
        admits_itself(),
        &[
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-site", "cross-site"),
        ],
        "",
    )
    .await;
    assert_eq!(two_sites.status(), StatusCode::FORBIDDEN, "two fetch sites");
}

/// An explicit `Origin` always decides, and never falls back to metadata --
/// otherwise an unlisted page could drop to the same-origin path by sending
/// `Sec-Fetch-Site: same-origin` alongside its own origin.
#[tokio::test]
async fn config_never_falls_back_to_metadata_when_an_origin_is_present() {
    for origin in ["https://evil.example", "null", "not a url"] {
        let resp = config_with(
            admits_itself(),
            &[("origin", origin), ("sec-fetch-site", "same-origin")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{origin}");
    }
}

/// Neither is an authority input, and the handler does not read them.
#[tokio::test]
async fn config_admits_nothing_on_referer_or_host() {
    let resp = config_with(
        admits_itself(),
        &[
            ("referer", "http://127.0.0.1:8722/"),
            ("host", "127.0.0.1:8722"),
        ],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Two headers decide the body, so a shared cache must be told both -- on
/// refusals as well, or a cache that ignores `no-store` could replay a 403 to
/// an origin this deployment admits.
#[tokio::test]
async fn config_varies_on_both_admission_headers() {
    let admitted = config_with(admits_itself(), &[("origin", APP_ORIGIN)], "").await;
    assert_eq!(admitted.status(), StatusCode::OK);
    assert_eq!(
        admitted.headers().get("vary").unwrap(),
        "origin, sec-fetch-site"
    );

    let refused =
        config_with(admits_itself(), &[("origin", "https://evil.example")], "").await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        refused.headers().get("vary").unwrap(),
        "origin, sec-fetch-site"
    );
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
    // whatever an exchange would answer. With a valid body these arms took a
    // permit and dialled `--notary-url`, which is the production default: on a
    // machine running a notary there, `cargo test` opened a real MPC-TLS
    // session to github.com carrying the fixture's client secret. They also
    // asserted only "not 415", so any answer passed.
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

/// One valid `Origin`, a member of the effective admission set, on every
/// request.
///
/// The ceremony's caller is the Prover on the CCDP origin, but the contract
/// makes this route use the same `allowedOrigins` rule as configuration and
/// Callback -- so a configured application origin is admitted here too, and
/// the CCDP origin is in the set whether or not anybody listed it.
#[tokio::test]
async fn github_token_admits_one_origin_from_the_effective_set() {
    // A body the NEXT check refuses, so admission is proved without opening a
    // notary session.
    let body = r#"{"code":"6b7f2c1d9e4a8035","codeVerifier":"tooshort"}"#;
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

    // The CCDP origin, and both configured application origins.
    for origin in [ORIGIN, APP_ORIGIN, "https://wallet.example"] {
        assert_eq!(
            post(vec![origin]).await,
            StatusCode::BAD_REQUEST,
            "{origin}"
        );
    }

    // Everything outside the set, and the shapes that are not one origin.
    for origins in [
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
