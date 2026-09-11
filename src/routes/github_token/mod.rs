//! The confidential GitHub token exchange — the one route a platform ceremony
//! asks of a server.
//!
//! The browser owns the ceremony and cannot own this: the exchange needs a
//! client secret, and a secret in a browser is not a secret. So this service
//! performs the exchange **inside a TLSNotary session**, revealing what proves
//! the request was the ceremony's own — the client id, the code, the redirect
//! URI and the verifier — and committing the secret and the returned bearer
//! rather than disclosing them.
//!
//! It keeps nothing. One request, one session, one answer, and no record that
//! either happened: a timeout, a duplicate or a restart leaves nothing to
//! resume from, and recovery is a fresh ceremony.
//!
//! What comes back is one result from one session — the bearer, the notary's
//! attestation of that session, and the opening for the bearer's commitment.
//! Any two of them without the third are worthless, which is why a failure
//! returns none of them.

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

/// The notarized session that carries it, and what the notary hands back.
mod egress;
/// What this service sends, and the endpoint it sends it to.
mod request;
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

/// The notary's attestation of the exchange: the exact bytes it signed, and
/// the signature over them.
///
/// Two members, not one string. The record and the signature are bounded
/// separately — the data to 2 MiB, the signature to the 65 bytes a notary
/// signature is — and a single blob would have to be split before either
/// bound could be applied.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationBody {
    /// The attested record, byte for byte as the notary produced it.
    attested_data: String,
    /// EIP-191 over its keccak256 digest.
    signature: String,
}

/// What the browser gets back.
///
/// `accessToken` is the bearer as GitHub spelled it, verbatim, because that is
/// what the next request has to carry. The other two are byte strings and are
/// unpadded URL-safe base64 — a caller that decodes all three the same way
/// corrupts the one that was never encoded.
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

/// A refusal. The body carries a reason and never a partial result: two of the
/// three values without the third would leave the browser holding something it
/// cannot prove anything with.
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

    /// A failure inside the exchange, answered according to whose it is.
    ///
    /// A code that was spent, replayed or never valid is ordinary user
    /// behaviour — a double-clicked button, a reloaded callback — and the
    /// browser can act on being told so. Everything else is this service, the
    /// notary or GitHub, and the browser can only try again later.
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
            // Not `upstream`: this one names a fault an operator can fix, and
            // it is this service's own sentence, so it is safe to write whole.
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
            // Refused before any socket was opened: the caller named a notary
            // on a private or internal address this deployment has not
            // permitted. Its own sentence, safe to write whole.
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

    /// The cause is LOGGED, never serialized: an anonymous caller learns that
    /// the exchange failed and nothing about this service's configuration, its
    /// notary, or which step of the session refused it.
    ///
    /// What is logged is this crate's own `Display` and never a foreign one.
    /// Every `detail` written here is a literal, an io error, or a length and
    /// an index. `Error::Tlsn` is not: the session driver builds one of its
    /// details as `format!("API returned {status}: {body}")`, so GitHub's whole
    /// response body rides in it -- and the contract says platform-return
    /// values never enter logs, without exception. This service cannot tell
    /// which half of that string is its own, so it logs neither, and says how
    /// many bytes it withheld instead.
    ///
    /// That costs real diagnosis, and the cost is stated rather than hidden:
    /// GitHub's status is INSIDE the withheld text, so a notary handshake
    /// failure and a `403` from the token endpoint now write the same line.
    /// Recovering the status needs the upstream variant to carry it apart from
    /// the body, which is the fix -- here it can only be withheld whole or
    /// leaked whole.
    fn upstream(cause: impl std::fmt::Display) -> Self {
        tracing::error!(%cause, "github token exchange failed");
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: "token exchange failed".into(),
        }
    }

    /// The same refusal for a cause this service did not author.
    ///
    /// Kept apart from [`Self::upstream`] because the two differ in exactly
    /// one way that matters: whether the text is safe to write down.
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
    // Callable only from the configured CCDP origin: the prover runs there
    // and derives this route from the bridge's `redirectUri`. This is not
    // caller authentication — a request with no browser behind it carries
    // whatever `Origin` it likes — it stops a page on another origin from
    // spending this bridge's secret through someone else's browser.
    //
    // Exactly one, and exactly the configured CCDP origin -- NOT the effective
    // set the configuration route admits. The caller here is the Prover, which
    // runs on that origin and nowhere else, so admitting an application origin
    // would widen the one route that spends the client secret for no caller
    // that exists.
    //
    // Missing, `null`, malformed and repeated all fail, and the counting is
    // shared with the configuration route so the two cannot drift on the part
    // they do agree about.
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

    // The contract says the query is empty. It is also the field a proxy
    // access log records by default, which is why a route carrying a code has
    // no business having one.
    if query.is_some_and(|q| !q.is_empty()) {
        return Err(TokenError::bad_request("this route takes no query"));
    }

    // "Exactly `application/json`" -- axum's extractor also accepts any
    // `application/*+json`, which is a wider door than the contract opens.
    // Case-insensitively: RFC 9110 makes the type and subtype case-insensitive,
    // so `Application/JSON` is the media type the contract names, spelled by a
    // caller that is entitled to spell it that way.
    //
    // `split(';').next()` cannot be `None` -- `str::split` always yields at
    // least one item -- so the absent case is the ABSENT HEADER below, and only
    // that.
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

    // Malformed JSON fails before a session is opened and before the secret is
    // spent.
    //
    // Two things the extractor gets wrong for this route.
    //
    // Its text: `body_text()` embeds the caller's own field names and byte
    // offsets, and the contract says a failure returns no caller-selected
    // diagnostic content. So the message is this route's, and fixed.
    //
    // Its status, in one direction only. A body over the ceiling set on this
    // route came back as `400`, which made that ceiling invisible to the
    // caller it exists for -- `413` says retry is pointless. Deferred to the
    // rejection for that case alone, because `BytesRejection` covers both the
    // length limit and a body that simply would not read, and only the first
    // is a `413`. Everything else stays `400`, including the `422` axum
    // answers a well-formed body with the wrong fields: the contract fixes no
    // failure status, a caller can act on neither differently, and `400` is
    // what this route has always answered.
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
    // The reason is LOGGED, not returned. `TokenExchangeError`'s `Display`
    // carries byte offsets derived from what the caller sent, and this route's
    // contract says a failure returns no caller-selected diagnostic content --
    // the same rule that already governs the JSON rejection above. It also
    // belongs to a crate this service does not own, so a change there would
    // otherwise widen what this route says with nothing here to notice.
    request.validate().map_err(|cause| {
        tracing::debug!(%cause, "refused a token request that does not validate");
        TokenError::bad_request("the request body is not a TokenRequest")
    })?;

    // One permit, one session. Shed rather than queue: a caller told to come
    // back is better served than one held behind a queue it cannot see, and an
    // unbounded queue is the same exhaustion with a longer fuse.
    let _permit = github.permits.try_acquire().map_err(|_| TokenError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: "too many exchanges in flight; retry shortly".into(),
    })?;

    let response = session::exchange(&github, &request, redirect_uri, &notary_host)
        .await
        .map_err(TokenError::from_exchange)?;
    // The bounds are checked on the way out as well as in: the three values are
    // one result, and one of them out of shape makes the other two worthless.
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

/// How every byte string in the response is spelled: unpadded URL-safe base64.
///
/// All three byte strings of the response are spelled this way, and a browser
/// that decodes one differently from another gets a proof that will not verify.
/// The bearer is not among them: it is a string GitHub chose, not bytes.
fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// What every layout in this module is a function of: the credentials and the
/// request, and nothing else the route holds.
///
/// Shared because the same transcript is the subject of two modules — the one
/// that writes it and the one that reads it.
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

    /// The head this service writes, as `prover_generic` will send it: header
    /// names go on the wire lowercase, and hyper adds the `content-length` a
    /// sized body implies. A fixture missing it would put every offset below a
    /// few bytes away from the transcript a real session produces.
    const HEAD: &str = "POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n";

    /// The only part of the exchange state these tests read. The transcript
    /// and its layout are a function of the credentials and the request, and
    /// of nothing else the route holds -- so the fixture is the credentials.
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

    /// "The encoded response body is at most 3 MiB", says the contract, and
    /// nothing in this service enforces that number directly. It holds because
    /// the three parts are each bounded and base64 expands by a known ratio --
    /// so the way to know it still holds is to build the largest response the
    /// bounds admit and serialize it. A later bound raised past what 3 MiB can
    /// carry fails here rather than on a browser that cannot read the answer.
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

    /// "Credentials and OAuth-platform-return values never enter logs", says
    /// the contract, without exception. The session driver builds one of its
    /// details as `format!("API returned {status}: {body}")`, so GitHub's whole
    /// response body rides inside a `libid_tlsn::Error` -- and this service
    /// cannot tell which half of that string is its own. So none of it is
    /// logged, and none of it reaches the caller either.
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
            // The detail carries the marker, so a route that repeated it would
            // fail this rather than pass by accident.
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

    /// And the causes this service authors itself are logged whole, because
    /// every one of them is a literal, an io error, or a length and an index.
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
