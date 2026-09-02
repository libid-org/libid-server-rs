//! `GET /auth/gmail/callback` — the static CSP-locked fragment relay.
//!
//! Google returns the direct OIDC response (`id_token`, `state`) in
//! `location.hash`, which the browser never sends to any server. This
//! endpoint is the single redirect URI registered with Google; it serves a
//! tiny HTML page that copies `location.hash` onto the fixed frontend URL
//! (`{APP_URL}/auth/gmail/callback`) with `location.replace`, so the
//! fragment is forwarded explicitly in every UA.
//!
//! We do NOT rely on RFC 9110 §10.2.2 fragment inheritance (a fragmentless
//! 3xx Location re-using the request's fragment): it's spec-mandated but
//! subtle, and APP_URL is typically a different origin than this callback.
//!
//! Ported verbatim from the upstream monorepo's `server/routes/oidc.rs`.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{
        HeaderValue,
        StatusCode,
    },
    response::{
        Html,
        IntoResponse,
        Response,
    },
};
use url::Url;

use crate::state::AppState;

/// `GET /auth/gmail/callback` handler.
pub async fn gmail_callback(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let app_url = state.app_url.as_deref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "APP_URL not configured — set APP_URL env so the OIDC callback knows where the frontend lives".to_string(),
        )
    })?;
    gmail_callback_response(app_url).map_err(|detail| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("invalid APP_URL: {detail}"),
        )
    })
}

/// Build the full relay response with the hardening headers.
pub fn gmail_callback_response(app_url: &str) -> Result<Response, &'static str> {
    let target = gmail_callback_target(app_url)?;
    let mut response = Html(gmail_forward_html(&target)).into_response();
    let headers = response.headers_mut();
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    // Lock the page down: only the inline forwarder script may run, nothing
    // else loads. `target` is operator config (APP_URL), not user input.
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; script-src 'unsafe-inline'"),
    );
    Ok(response)
}

/// HTML that forwards the browser's URL fragment (Google's id_token, which
/// the server never sees) to the fixed frontend callback. `target` is
/// JSON-encoded into the script so a stray quote can't break out — and it's
/// already a validated absolute URL with a forced path and no
/// query/fragment.
fn gmail_forward_html(target: &Url) -> String {
    let target_js =
        serde_json::to_string(target.as_str()).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"robots\" content=\"noindex\"><title>Completing sign-in…</title></head>\
         <body><script>(function(){{location.replace({target_js}+location.hash);}})();</script>\
         <noscript>JavaScript is required to finish signing in.</noscript></body></html>"
    )
}

fn gmail_callback_target(app_url: &str) -> Result<Url, &'static str> {
    let mut target = Url::parse(app_url).map_err(|_| "must be an absolute URL")?;
    // The forwarded document holds Google's id_token in its fragment, so
    // require TLS: plain http to a routable host lets an on-path attacker
    // swap the page and read the token. Allow http only for loopback dev
    // hosts (localhost).
    match target.scheme() {
        "https" => {}
        "http" if is_loopback_host(&target) => {}
        "http" => {
            return Err("http APP_URL is only allowed for loopback hosts — use https")
        }
        _ => return Err("scheme must be http or https"),
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err("credentials are not allowed");
    }
    target.set_path("/auth/gmail/callback");
    target.set_query(None);
    target.set_fragment(None);
    Ok(target)
}

/// True when the URL's host is a loopback dev host — `localhost` /
/// `*.localhost` or a loopback IP (127.0.0.0/8, ::1). Used to permit plain
/// http only for local development, never a routable origin.
fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost" || d.ends_with(".localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{
        header,
        StatusCode,
    };

    use super::{
        gmail_callback_response,
        gmail_callback_target,
        gmail_forward_html,
    };

    #[test]
    fn gmail_callback_forwards_fragment_to_fixed_frontend() {
        let response = gmail_callback_response(
            "https://wallet.example/ignored?redirect=https://evil.example#ignored",
        )
        .unwrap();

        // 200 HTML (not a 3xx) with the hardening headers.
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            "default-src 'none'; script-src 'unsafe-inline'"
        );
        assert!(gmail_callback_response("javascript:alert(1)").is_err());

        // The forwarder navigates to the fixed frontend callback carrying
        // location.hash, and never to the attacker-controlled
        // query/fragment.
        let target = gmail_callback_target(
            "https://wallet.example/ignored?redirect=https://evil.example#ignored",
        )
        .unwrap();
        let html = gmail_forward_html(&target);
        assert!(html.contains("\"https://wallet.example/auth/gmail/callback\""));
        assert!(html.contains("location.replace"));
        assert!(html.contains("location.hash"));
        assert!(!html.contains("evil.example"));
    }

    #[test]
    fn gmail_callback_requires_https_except_loopback() {
        // https anywhere is fine.
        assert!(gmail_callback_response("https://wallet.example").is_ok());
        // http only for loopback dev hosts.
        assert!(gmail_callback_response("http://localhost:3000").is_ok());
        assert!(gmail_callback_response("http://127.0.0.1:3000").is_ok());
        assert!(gmail_callback_response("http://foo.localhost").is_ok());
        assert!(gmail_callback_response("http://[::1]:3000").is_ok());
        // http to a routable host is rejected — the id_token fragment would
        // be exposed to an on-path attacker.
        assert!(gmail_callback_response("http://wallet.example").is_err());
        assert!(gmail_callback_response("http://192.168.1.10").is_err());
        assert!(gmail_callback_response("http://localhost.evil.com").is_err());
    }
}
