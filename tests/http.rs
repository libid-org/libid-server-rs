//! HTTP-level tests over the axum router: the public configuration, the
//! callback document's invariance and policy, and the absence of any other
//! route.

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

/// The shared Distribution's origin: the deployment's CCDP origin, which every
/// gated route admits and the callback document names.
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

/// The default deployment: GitHub enabled.
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

/// The response varies on `Origin` and `Sec-Fetch-Site`, on refusals too.
#[tokio::test]
async fn config_varies_on_origin_and_fetch_site() {
    let admitted = config_with(test_state().await, &[("origin", APP_ORIGIN)], "").await;
    assert_eq!(admitted.status(), StatusCode::OK);
    assert_eq!(
        admitted.headers().get("vary").unwrap(),
        "origin, sec-fetch-site"
    );

    let refused = config_with(
        test_state().await,
        &[("origin", "https://evil.example")],
        "",
    )
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        refused.headers().get("vary").unwrap(),
        "origin, sec-fetch-site"
    );
}

/// A page served from this bridge's own origin reads the configuration with
/// no `Origin` and no CORS: `Sec-Fetch-Site: same-origin` alone admits it,
/// whatever the allowlist holds.
#[tokio::test]
async fn config_admits_a_same_origin_read() {
    let resp =
        config_with(test_state().await, &[("sec-fetch-site", "same-origin")], "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert!(
        h.get("access-control-allow-origin").is_none(),
        "a same-origin read needs no CORS header"
    );
    assert_eq!(h.get("vary").unwrap(), "origin, sec-fetch-site");
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
    assert_eq!(h.get("content-type").unwrap(), "application/json");
    let body = body_of(resp).await;
    assert_eq!(body["ccdpOrigin"], ccdp_origin());
}

/// Fetch metadata admits nothing but exactly one `Sec-Fetch-Site:
/// same-origin`; `Referer`, `Host` and forwarding headers admit nothing; and
/// an explicit `Origin` is judged as an `Origin`, whatever the metadata says.
#[tokio::test]
async fn config_does_not_infer_admission_from_fetch_metadata_alone() {
    for headers in [
        vec![("sec-fetch-site", "same-site")],
        vec![("sec-fetch-site", "cross-site")],
        vec![("sec-fetch-site", "none")],
        vec![("sec-fetch-site", "SAME-ORIGIN")],
        vec![
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-site", "same-origin"),
        ],
        vec![
            ("origin", "https://evil.example"),
            ("sec-fetch-site", "same-origin"),
        ],
        vec![("origin", "null"), ("sec-fetch-site", "same-origin")],
        vec![
            ("referer", "https://bridge.example/"),
            ("host", "bridge.example"),
        ],
        vec![
            ("x-forwarded-host", "app.example"),
            ("forwarded", "for=203.0.113.9;host=app.example;proto=https"),
        ],
    ] {
        let resp = config_with(test_state().await, &headers, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{headers:?}");
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    let resp = config_with(
        test_state().await,
        &[("origin", APP_ORIGIN), ("sec-fetch-site", "cross-site")],
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an admitted Origin is judged as one"
    );
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        APP_ORIGIN
    );
}

/// The record carries exactly `ccdpOrigin` and `platforms`; the github entry
/// carries exactly its client id, its versions and its public client
/// credential. No allowlist, redirect URI or notary setting travels.
#[tokio::test]
async fn config_carries_the_public_credential_and_no_allowlist() {
    let body = body_of(get_config(Some(APP_ORIGIN), "").await).await;
    let object = body.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["ccdpOrigin", "platforms"]);
    assert_eq!(body["ccdpOrigin"], ccdp_origin());

    let github = body["platforms"]["github"].as_object().unwrap();
    let mut keys: Vec<_> = github.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["ceremonyVersions", "clientCredential", "clientId"]);
    assert_eq!(github["clientId"], fixtures::CLIENT_ID);
    assert_eq!(github["ceremonyVersions"], serde_json::json!([1]));
    assert_eq!(github["clientCredential"], fixtures::CLIENT_CREDENTIAL);

    let raw = body.to_string();
    assert!(!raw.contains(APP_ORIGIN));
    assert!(
        !raw.contains("redirectUri"),
        "an application derives the redirect URI"
    );
    assert!(
        !raw.contains("notaryAddress"),
        "an application resolves the notary"
    );
    assert!(
        !raw.contains("circuitUrl"),
        "an application selects no artifact"
    );
}

/// An enabled X platform is published as its client id and versions, and
/// nothing else: X's ceremony runs browser to notary as a public client, and
/// its entry carries no credential.
#[tokio::test]
async fn config_publishes_an_x_entry_of_exactly_client_id_and_versions() {
    let state = deployment(&[
        "--platforms",
        &format!(
            r#"[{{"id":"github","client_id":"{}","versions":[1],"client_credential":"{}"}},{{"id":"x","client_id":"WHRlc3RjbGllbnQ6MTpjaQ","versions":[1]}}]"#,
            fixtures::CLIENT_ID,
            fixtures::CLIENT_CREDENTIAL
        ),
    ])
    .await;
    let body = body_of(config_with(state, &[("origin", APP_ORIGIN)], "").await).await;

    let x = body["platforms"]["x"].as_object().expect("an x entry");
    let mut keys: Vec<_> = x.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["ceremonyVersions", "clientId"]);
    assert_eq!(x["clientId"], "WHRlc3RjbGllbnQ6MTpjaQ");
    assert_eq!(x["ceremonyVersions"], serde_json::json!([1]));
    assert_eq!(body["platforms"]["github"]["clientId"], fixtures::CLIENT_ID);
}

/// This bridge's own origin, sent as an `Origin`, is admitted exactly when
/// it is listed as an application origin, like any other: the bridge does
/// not know its own origin.
#[tokio::test]
async fn the_bridges_own_origin_is_admitted_only_when_listed() {
    const BRIDGE_ORIGIN: &str = "https://bridge.example";
    let resp = get_config(Some(BRIDGE_ORIGIN), "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "unlisted");

    let listed = deployment(&[
        "--allowed-app-origins",
        "https://app.example,https://bridge.example",
    ])
    .await;
    let resp = config_with(listed, &[("origin", BRIDGE_ORIGIN)], "").await;
    assert_eq!(resp.status(), StatusCode::OK, "listed");
    assert_eq!(resp.headers()["access-control-allow-origin"], BRIDGE_ORIGIN);
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

/// `/api/v1/ceremony/github-token` is not served: a `POST` and a preflight
/// there are answered `404` with no CORS header, GitHub enabled or not.
/// Nothing is exchanged and no notary is dialled.
#[tokio::test]
async fn the_github_token_path_is_not_served() {
    const PATH: &str = "/api/v1/ceremony/github-token";
    const BODY: &str = r#"{"code":"6b7f2c1d9e4a8035","codeVerifier":"iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I","notaryAddress":"https://127.0.0.1:7048"}"#;
    let x_only = deployment(&[
        "--platforms",
        r#"[{"id":"x","client_id":"abc","versions":[1]}]"#,
    ])
    .await;

    for state in [test_state().await, x_only] {
        let resp = app(state.clone())
            .oneshot(
                Request::post(PATH)
                    .header("origin", ccdp_origin())
                    .header("content-type", "application/json")
                    .body(Body::from(BODY))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(resp.headers().get("access-control-allow-origin").is_none());

        let resp = app(state)
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(PATH)
                    .header("origin", ccdp_origin())
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-headers", "content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(resp.headers().get("access-control-allow-origin").is_none());
        assert!(resp.headers().get("access-control-allow-methods").is_none());
    }
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
        // X's return: a long code, and X's own page as the referrer.
        (
            "/auth/callback?code=WjE2YmZDNVFrWXNOVHdyOHdLbWZ6dWpqUzRXbjZ4R1pyY2JmT2JJWGhMTXFhOjE3NTgwMDAwMDAwMDA6MTowOmFjOjE&state=v1.9e1f",
            vec![("referer", "https://x.com/")],
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
    assert!(
        !html.contains(fixtures::CLIENT_CREDENTIAL),
        "the document carries no platform configuration"
    );

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

/// An unserved path answers no preflight and carries no allow-origin header.
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
