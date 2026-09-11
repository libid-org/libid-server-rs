//! The confidential GitHub token exchange, performed inside a TLSNotary
//! session: the client id, the code, the redirect URI and the verifier are
//! revealed; the secret and the returned bearer are committed. Nothing is kept
//! between requests. The answer is the bearer, the notary's attestation and
//! the opening of the bearer's commitment, or a refusal carrying none of them.

use std::sync::Arc;

use axum::{
    extract::{
        RawQuery,
        State,
    },
    http::{
        header,
        HeaderMap,
        StatusCode,
    },
    response::{
        IntoResponse,
        Response,
    },
    Json,
};
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};
use libid_ceremony::token_exchange::TokenRequest;
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    error::Error,
    state::GithubExchange,
};

/// Reaching the notary a request names.
mod egress;
/// What this service sends, and the endpoint it sends it to.
mod request;
/// The notarized session, and what the notary hands back.
mod session;

pub use egress::NotaryEgress;
/// What the session discloses, and what the platform answered.
mod transcript;

pub(crate) use request::force_token_endpoint;

/// What the browser sends: the code, the PKCE verifier, the redirect URI its
/// authorization request carried, and the notary. The client, secret and
/// endpoint are this service's own.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TokenRequestBody {
    /// The authorization code the callback captured.
    code: String,
    /// The PKCE verifier the browser derived for this ceremony.
    code_verifier: String,
    /// The registered callback URL: this bridge's public origin followed by
    /// its callback path. Sent to GitHub byte for byte.
    redirect_uri: String,
    /// The notary the browser's identity session ran against, as a canonical
    /// origin: HTTPS, or HTTP on exactly `localhost` or `127.0.0.1`. This
    /// bridge dials its host on the wire port for the token session.
    notary_address: String,
}

/// The notary's attestation of the exchange: the bytes it signed, and the
/// signature over them, bounded separately (2 MiB and 65 bytes).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationBody {
    /// The attested record, byte for byte as the notary produced it.
    attested_data: String,
    /// EIP-191 over its keccak256 digest.
    signature: String,
}

/// What the browser gets back. `accessToken` is the bearer as GitHub spelled
/// it; the other two are unpadded URL-safe base64.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponseBody {
    /// The bearer, which the attestation commits to rather than discloses.
    access_token: String,
    /// The notary's attestation of the session that produced it.
    token_attestation: AttestationBody,
    /// What opens the attestation's committed bearer range.
    bearer_opening: String,
}

/// A refusal: a status and a reason, never a partial result.
pub(crate) struct TokenError {
    status: StatusCode,
    message: String,
}

impl TokenError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    /// A failure inside the exchange, answered by whose it is: a refused code
    /// is `400`, a refused notary `403`, everything else `502`.
    fn from_exchange(cause: Error) -> Self {
        match cause {
            Error::OAuthFailed { .. } => {
                tracing::warn!(%cause, "github refused the authorization code");
                Self {
                    status: StatusCode::BAD_REQUEST,
                    message: "the authorization code was refused; start a fresh ceremony"
                        .into(),
                }
            }
            Error::PlatformMisconfigured { .. } => {
                tracing::error!(
                    %cause,
                    "every ceremony on this deployment will fail until this is fixed"
                );
                Self {
                    status: StatusCode::BAD_GATEWAY,
                    message: "token exchange failed".into(),
                }
            }
            Error::NotaryRefused { .. } => {
                tracing::warn!(%cause, "refused to dial the notary a request named");
                Self {
                    status: StatusCode::FORBIDDEN,
                    message:
                        "this bridge does not dial private or internal notary addresses"
                            .into(),
                }
            }
            Error::Tlsn(e) => Self::foreign(&e),
            other => Self::upstream(other),
        }
    }

    /// The cause is logged, with this crate's own `Display`, and answered as
    /// `502 token exchange failed`.
    fn upstream(cause: impl std::fmt::Display) -> Self {
        tracing::error!(%cause, "github token exchange failed");
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: "token exchange failed".into(),
        }
    }

    /// The same refusal for a `libid_tlsn::Error`, whose detail may quote the
    /// platform response and is not logged; its kind and length are.
    fn foreign(cause: &libid_tlsn::Error) -> Self {
        let (kind, withheld) = match cause {
            libid_tlsn::Error::MpcTlsFailed { detail } => ("MPC-TLS", detail.len()),
            libid_tlsn::Error::UnsupportedTlsVersion { detail } => {
                ("TLS version", detail.len())
            }
            libid_tlsn::Error::Io(e) => ("session io", e.to_string().len()),
            libid_tlsn::Error::Transcript(e) => ("transcript", e.to_string().len()),
        };
        tracing::error!(
            kind,
            withheld_bytes = withheld,
            "github token exchange failed; the session driver's detail may quote \
             the platform response and is not logged"
        );
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: "token exchange failed".into(),
        }
    }
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        (
            self.status,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            Json(serde_json::json!({ "message": self.message })),
        )
            .into_response()
    }
}

/// `POST /api/v1/ceremony/github-token`.
pub(crate) async fn github_token(
    State(github): State<Arc<GithubExchange>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Result<Json<TokenRequestBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, TokenError> {
    // Exactly one `Origin`, and exactly the configured CCDP origin. Missing,
    // `null`, malformed and repeated all fail.
    let admitted = matches!(
        crate::routes::Origins::of(&headers),
        crate::routes::Origins::One(origin)
            if origin.as_bytes() == github.ccdp_origin.as_bytes()
    );
    if !admitted {
        return Err(TokenError {
            status: StatusCode::FORBIDDEN,
            message: "this route is callable only from the configured CCDP origin".into(),
        });
    }

    // The query is empty; a proxy access log would record one.
    if query.is_some_and(|q| !q.is_empty()) {
        return Err(TokenError::bad_request("this route takes no query"));
    }

    // Exactly `application/json`, case-insensitively (RFC 9110); axum's
    // extractor would also accept `application/*+json`.
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or(v).trim())
        .unwrap_or_default();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(TokenError {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            message: "this route takes exactly application/json".into(),
        });
    }

    // The message is this route's own; the extractor's text quotes the
    // caller's field names and offsets. A body over the ceiling is `413`,
    // everything else `400`.
    let Json(body) = body.map_err(|e| {
        let status = match &e {
            axum::extract::rejection::JsonRejection::BytesRejection(_) => e.status(),
            _ => StatusCode::BAD_REQUEST,
        };
        TokenError {
            status,
            message: "the request body is not a TokenRequest".into(),
        }
    })?;
    let redirect_uri = redirect_uri(&body.redirect_uri, &github.callback_path)
        .ok_or_else(|| {
            TokenError::bad_request(
                "redirectUri is not this bridge's callback path under a canonical origin",
            )
        })?;
    // The spelling is checked here; where the host resolves, and whether it
    // is dialled, is decided in `egress` after the permit is taken.
    let notary_host = notary_host(&body.notary_address).ok_or_else(|| {
        TokenError::bad_request(
            "notaryAddress is not a canonical HTTPS or localhost HTTP origin",
        )
    })?;

    let request = TokenRequest {
        code: body.code,
        code_verifier: body.code_verifier,
    };
    // Logged, not returned: `TokenExchangeError`'s `Display` carries byte
    // offsets from the caller's input.
    request.validate().map_err(|cause| {
        tracing::debug!(%cause, "refused a token request that does not validate");
        TokenError::bad_request("the request body is not a TokenRequest")
    })?;

    // One permit per session; a request that finds none is shed, not queued.
    let _permit = github.permits.try_acquire().map_err(|_| TokenError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: "too many exchanges in flight; retry shortly".into(),
    })?;

    let response = session::exchange(&github, &request, redirect_uri, &notary_host)
        .await
        .map_err(TokenError::from_exchange)?;
    // The bounds are checked on the way out as well.
    response
        .validate()
        .map_err(|e| TokenError::upstream(format!("built an invalid response: {e}")))?;

    Ok((
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Json(TokenResponseBody {
            access_token: response.access_token,
            token_attestation: AttestationBody {
                attested_data: b64(&response.token_attestation.attested_data),
                signature: b64(&response.token_attestation.signature),
            },
            bearer_opening: b64(&response.bearer_opening),
        }),
    )
        .into_response())
}

/// Unpadded URL-safe base64, for the byte strings of the response.
fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `spelling`, if it is the registered callback URL: a canonical origin --
/// HTTPS, or HTTP on exactly `localhost` or `127.0.0.1` -- followed by exactly
/// `callback_path`, with no query, fragment or credentials.
fn redirect_uri<'a>(spelling: &'a str, callback_path: &str) -> Option<&'a str> {
    let url = url::Url::parse(spelling).ok()?;
    let plaintext_loopback = url.scheme() == "http"
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1"));
    if !(url.scheme() == "https" || plaintext_loopback)
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != callback_path
        || format!("{}{callback_path}", url.origin().ascii_serialization()) != spelling
    {
        return None;
    }
    Some(spelling)
}

/// The host a notary origin names. HTTP is development-only on explicit
/// localhost/127.0.0.1, matching the browser's local transport exception.
fn notary_host(spelling: &str) -> Option<String> {
    let url = url::Url::parse(spelling).ok()?;
    if !(url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
            && url.origin().ascii_serialization() == spelling))
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let host = url.host_str()?;
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.:[]".contains(&b))
    {
        return None;
    }
    Some(host.to_owned())
}

#[cfg(test)]
mod fixtures {
    use libid_ceremony::token_exchange::TokenRequest;

    use crate::oauth::OAuthCredentials;

    /// The head this service writes, as `prover_generic` sends it: lowercase
    /// header names, and the `content-length` hyper adds.
    const HEAD: &str = "POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n";

    /// The credentials the fixture transcripts are built from.
    pub(super) fn credentials(client_secret: &str) -> crate::oauth::OAuthCredentials {
        crate::oauth::OAuthCredentials {
            client_id: "Iv1.0123456789abcdef".into(),
            client_secret: client_secret.into(),
        }
    }

    /// The registered callback URL the fixture request carries.
    pub(super) const REDIRECT_URI: &str = "http://127.0.0.1:8722/auth/callback";

    pub(super) fn request() -> TokenRequest {
        TokenRequest {
            code: "6b7f2c1d9e4a8035".into(),
            code_verifier: "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I".into(),
        }
    }

    /// What the session will see in the sent direction.
    pub(super) fn sent(
        credentials: &OAuthCredentials,
        request: &TokenRequest,
    ) -> Vec<u8> {
        let body = super::request::token_request_body(credentials, request, REDIRECT_URI);
        format!("{HEAD}content-length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        notary_host,
        redirect_uri,
    };

    /// The registered callback URL and nothing that merely resembles it.
    #[test]
    fn a_redirect_uri_is_the_callback_path_under_a_canonical_origin() {
        for ok in [
            "https://bridge.example/auth/callback",
            "https://bridge.example:8443/auth/callback",
            "http://localhost:8722/auth/callback",
            "http://127.0.0.1:8722/auth/callback",
        ] {
            assert_eq!(redirect_uri(ok, "/auth/callback"), Some(ok), "{ok}");
        }
        for bad in [
            "https://bridge.example/auth/callback/",
            "https://bridge.example/other",
            "https://bridge.example",
            "https://bridge.example:443/auth/callback",
            "https://BRIDGE.example/auth/callback",
            "https://bridge.example/auth/callback?x=1",
            "https://bridge.example/auth/callback#x",
            "https://user@bridge.example/auth/callback",
            "http://bridge.example/auth/callback",
            "http://[::1]:8722/auth/callback",
            "/auth/callback",
            "",
        ] {
            assert_eq!(redirect_uri(bad, "/auth/callback"), None, "{bad}");
        }
        assert_eq!(
            redirect_uri("https://bridge.example/auth/callback", "/oauth/return"),
            None
        );
    }

    #[test]
    fn plaintext_notary_is_limited_to_explicit_loopback_hosts() {
        for (origin, host) in [
            ("http://localhost:4687", "localhost"),
            ("http://127.0.0.1:4687", "127.0.0.1"),
            ("https://notary.example", "notary.example"),
        ] {
            assert_eq!(notary_host(origin).as_deref(), Some(host));
        }
        for origin in [
            "http://notary.example",
            "http://localhost.evil.test",
            "http://127.1:4687",
            "http://2130706433:4687",
            "http://0x7f000001:4687",
            "http://LOCALHOST:4687",
            "http://localhost:80",
            "http://localhost:4687/",
            "http://192.168.1.1",
            "http://localhost.",
            "ws://localhost:4687",
            "http://user@localhost:4687",
            "http://localhost:4687/path",
            "http://localhost:4687?x=1",
            "http://localhost:4687#x",
        ] {
            assert_eq!(notary_host(origin), None, "{origin}");
        }
    }

    use super::*;

    use libid_ceremony::token_exchange::{
        BEARER_OPENING_LEN,
        MAX_ACCESS_TOKEN_BYTES,
        MAX_ATTESTED_DATA_BYTES,
        MAX_RESPONSE_BYTES,
        SIGNATURE_LEN,
    };

    /// The largest response the bounds admit serializes to at most 3 MiB, the
    /// contract's ceiling on the encoded body.
    #[test]
    fn the_largest_response_the_bounds_admit_fits_the_contract() {
        let body = TokenResponseBody {
            access_token: "t".repeat(MAX_ACCESS_TOKEN_BYTES),
            token_attestation: AttestationBody {
                attested_data: b64(&vec![0xff; MAX_ATTESTED_DATA_BYTES]),
                signature: b64(&[0xff; SIGNATURE_LEN]),
            },
            bearer_opening: b64(&[0xff; BEARER_OPENING_LEN]),
        };
        let encoded = serde_json::to_vec(&body).unwrap();
        assert!(
            encoded.len() <= MAX_RESPONSE_BYTES,
            "the largest admissible response is {} bytes, over the {MAX_RESPONSE_BYTES} \
             the contract allows",
            encoded.len()
        );
    }

    /// A `libid_tlsn::Error`'s detail may quote the platform response: none of
    /// it is logged, and none of it reaches the caller.
    #[test]
    fn a_foreign_cause_is_answered_without_repeating_a_word_of_it() {
        const MARKER: &str = "zzPLATFORMBODYzz";
        for cause in [
            libid_tlsn::Error::MpcTlsFailed {
                detail: format!("API returned 403: {MARKER}"),
            },
            libid_tlsn::Error::UnsupportedTlsVersion {
                detail: MARKER.into(),
            },
            libid_tlsn::Error::Io(std::io::Error::other(MARKER)),
            libid_tlsn::Error::Transcript(libid_transcript::Error::Transcript {
                detail: MARKER.into(),
            }),
        ] {
            assert!(cause.to_string().contains(MARKER), "{cause}");

            let refusal = TokenError::from_exchange(Error::Tlsn(cause));
            assert_eq!(refusal.status, StatusCode::BAD_GATEWAY);
            assert!(
                !refusal.message.contains(MARKER),
                "the refusal repeated the platform body: {}",
                refusal.message
            );
            assert_eq!(refusal.message, "token exchange failed");
        }
    }

    /// A cause this service authors is logged whole and answered as `502`.
    #[test]
    fn a_cause_this_service_authored_is_still_answered_as_upstream() {
        let refusal = TokenError::from_exchange(Error::NotaryConnect {
            addr: "127.0.0.1:7047".into(),
            detail: "connection refused".into(),
        });
        assert_eq!(refusal.status, StatusCode::BAD_GATEWAY);
        assert_eq!(refusal.message, "token exchange failed");
    }
}
