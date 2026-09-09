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

use std::{
    ops::Range,
    sync::Arc,
    time::Duration,
};

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
use libid_ceremony::token_exchange::{
    TokenAttestation,
    TokenRequest,
    TokenResponse,
};
use libid_tlsn::Direction;
use libid_transcript::{
    ceremony,
    AttestationWire,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    error::Error,
    oauth::OAuthCredentials,
    state::GithubExchange,
};

/// GitHub's token endpoint. Pinned by the platform profile, never configured:
/// a caller-selected endpoint would let one ask this service to spend its
/// secret against a host of the caller's choosing.
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

/// The body field whose value is committed rather than revealed.
///
/// Named here rather than read from a profile table, because libid-rs stopped
/// carrying one: `ceremony::token_request` now takes the field name as an
/// argument, and every caller in libid-rs and the TypeScript verifier passes
/// this same literal.
///
/// It is safe to restate precisely because it is not a libID fact to drift
/// from. `client_secret` is OAuth 2.0's own parameter name (RFC 6749 §2.3.1),
/// fixed by the protocol GitHub implements, so this service and the Platform
/// Verifier agree on it for the same reason they agree on `code`.
///
/// What DOES have to hold is that this service orders the field last in the
/// body it sends. The layout commits `&client_secret=` to the transcript end,
/// so a field written anywhere else would leave a hole rather than a suffix
/// and the layout would refuse it — see `body()` below, and the test that
/// asserts the ordering.
const SECRET_FIELD: &str = "client_secret";

/// [`TOKEN_URL`] parsed, and the authority to send as `Host`.
///
/// A `const` string cannot vary, so this either always parses or never does;
/// doing it per request turned a startup-class error into a 502 at exchange
/// time, on a branch no test could reach. `expect` is honest here: the input
/// is a literal in this file, and a build in which it does not parse is a
/// build that must not start.
static TOKEN_ENDPOINT: std::sync::LazyLock<(hyper::Uri, String)> =
    std::sync::LazyLock::new(|| {
        let uri: hyper::Uri = TOKEN_URL
            .parse()
            .expect("the token endpoint is a valid URI");
        let host = uri
            .authority()
            .expect("the token endpoint names a host")
            .as_str()
            .to_owned();
        (uri, host)
    });

/// Parse the token endpoint now, so a build in which it does not parse fails
/// where the doc above says it does.
///
/// `LazyLock` defers to first use, and the first use is inside an exchange --
/// which would turn a startup-class error into a panic on somebody's ceremony.
/// `build_state` calls this.
pub(crate) fn force_token_endpoint() {
    std::sync::LazyLock::force(&TOKEN_ENDPOINT);
}

/// How long reaching the notary may take.
///
/// Kept separate from the session budget below, and short: a notary that is
/// down refuses at once, but one at an unroutable address hangs for the
/// kernel's own retry schedule — which would otherwise eat most of the session
/// budget before the protocol had started.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the session itself may take once the notary has answered.
///
/// An MPC-TLS session is a conversation with two other parties, and a notary
/// that stops answering mid-protocol leaves the prover waiting on a message
/// that will not come. Generous enough for a real session on a slow link, and
/// finite so a wedged notary costs one request rather than a connection held
/// until the process restarts.
const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the notary may take to hand back the record for a session it has
/// already run.
///
/// Its own budget, because the session's is spent by this point and all that
/// remains is a write. Without one, a notary that completes a session and then
/// stalls -- or writes half a length prefix and stops -- parks this request
/// until the process restarts, which is the failure the budget above exists to
/// rule out.
const RECORD_TIMEOUT: Duration = Duration::from_secs(30);

/// What the browser sends. Nothing else: this service uses only its own
/// compiled client, secret, redirect URI, endpoint and notary, and accepts no
/// caller-selected action, client, redirect, endpoint or return URL.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TokenRequestBody {
    /// The authorization code the callback captured.
    code: String,
    /// The PKCE verifier the browser derived for this ceremony.
    code_verifier: String,
    /// The Notary Service origin the Prover already resolved.
    ///
    /// It travels in the request rather than being configured because one
    /// resolution has to serve both sessions: a bridge that re-derived it could
    /// disagree with the browser about which notary signed, and the two
    /// attestations would then name different services.
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
    // The notary the Prover resolved must be the one this deployment serves.
    //
    // The contract makes this destination request-controlled and leaves egress
    // safeguards to carry the weight. This bridge does not dial a
    // caller-supplied host at all: it checks the request names the notary it is
    // already configured for, and refuses otherwise. Nothing caller-chosen ever
    // reaches a socket, so the SSRF surface the contract warns about does not
    // open here -- and when the transport moves to `wss://{notaryAddress}` the
    // configured value is what disappears, not this check.
    //
    // Compared by HOST, not `host:port`. The two name one service over
    // different transports and therefore different ports: a browser Prover
    // reaches the notary's WebSocket endpoint, this bridge dials its TCP wire
    // listener, and a deployment that runs both on one host is the normal
    // case. Requiring the ports to agree would refuse every such deployment.
    //
    // Nothing is lost by ignoring it: this bridge dials its CONFIGURED address
    // whatever the request says, so the port in the request is not a
    // destination and never was. What the check establishes is that the caller
    // and this deployment mean the same notary.
    let asked = notary_host(&body.notary_address).ok_or_else(|| {
        TokenError::bad_request("notaryAddress is not a canonical HTTPS origin")
    })?;
    if asked != github.notary.host {
        tracing::warn!(
            asked = %asked,
            serves = %github.notary.host,
            "refused a token request naming a notary this deployment does not serve"
        );
        return Err(TokenError {
            status: StatusCode::FORBIDDEN,
            message: "this bridge does not serve the notary this request names".into(),
        });
    }

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

    let response = exchange(&github, &request)
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

/// The host a canonical HTTPS notary origin names, or `None`.
///
/// Deliberately narrow, because this value arrives in a request: HTTPS only, no
/// credentials, path, query or fragment, and a host whose bytes are what a host
/// is made of. It is the same shape [`crate::canonical_origin`] holds a
/// configured origin to, minus that function's development exception for
/// loopback `http` -- a caller does not get to name a plaintext destination.
fn notary_host(spelling: &str) -> Option<String> {
    let url = url::Url::parse(spelling).ok()?;
    if url.scheme() != "https"
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

/// How every byte string in the response is spelled: unpadded URL-safe base64.
///
/// All three byte strings of the response are spelled this way, and a browser
/// that decodes one differently from another gets a proof that will not verify.
/// The bearer is not among them: it is a string GitHub chose, not bytes.
fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The body of the token request, in the exact field order the profile fixes.
///
/// The secret is last because the disclosure layout commits a suffix: with the
/// secret anywhere else the committed run would be a hole in the middle of the
/// revealed body, and the verifier's coverage check refuses a transcript it
/// cannot tile.
fn token_request_body(creds: &OAuthCredentials, request: &TokenRequest) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &creds.client_id)
        .append_pair("code", &request.code)
        .append_pair("redirect_uri", &creds.redirect_uri)
        .append_pair("code_verifier", &request.code_verifier)
        .append_pair(SECRET_FIELD, &creds.client_secret)
        .finish()
}

/// Where the bearer sits in the received transcript, per the response layout.
///
/// It is the run framed by the two revealed anchors: the `"access_token":"`
/// delimiter and the quote that closes the value. That framing is the whole
/// reason those two runs are revealed — it is what tells the committed bearer
/// apart from a `refresh_token`, or from any other substring a prover chose to
/// commit.
fn bearer_range(
    layout: &ceremony::Layout,
) -> Result<Range<usize>, ceremony::LayoutError> {
    let [anchor, closing_quote] = layout.reveal.as_slice() else {
        return Err(ceremony::LayoutError::MissingField("access_token".into()));
    };
    Ok(anchor.end..closing_quote.start)
}

/// Restate a layout refusal as a session failure.
///
/// A layout that will not form is a transcript this service cannot describe —
/// most often GitHub answering with an error object where the profile expects
/// `access_token`, which is a bad code or a spent one rather than a fault here.
fn layout_failed(e: &ceremony::LayoutError) -> libid_tlsn::Error {
    libid_tlsn::Error::Transcript(libid_transcript::Error::Transcript {
        detail: e.to_string(),
    })
}

/// The token request this service sends, as the session will transmit it.
///
/// `prover_generic` reads the URI's host for SNI and for the socket and writes
/// no header of its own — a notarized request is bytes a verifier compares
/// against a profile, so the party that knows the profile writes them. `Host`
/// is therefore set here, and read back off the same URI rather than spelled a
/// second time: a `Host` that disagrees with the authenticated name is exactly
/// what the attested authority exists to catch. Omit it entirely and GitHub
/// answers an error object, the response layout finds no `access_token` to
/// anchor on, and the session fails somewhere that looks like a notary fault.
///
/// Total, and not a `Result`: the URI is a constant parsed once, the host is
/// that URI's own authority, every header name and value is a literal, and the
/// body is bytes. Nothing here comes from the request, so the builder has
/// nothing to reject -- and a `Result` would be an error branch no input can
/// reach, tested by nothing, that a reader has to rule out by hand.
fn token_http_request(
    creds: &OAuthCredentials,
    request: &TokenRequest,
) -> hyper::Request<http_body_util::Full<bytes::Bytes>> {
    let (uri, host) = &*TOKEN_ENDPOINT;

    hyper::Request::builder()
        .method("POST")
        .uri(uri.clone())
        .header(header::HOST, host.as_str())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        // The session ends when the exchange does. Without it the connection is
        // kept alive and the prover waits on a response that is already
        // complete.
        .header(header::CONNECTION, "close")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            token_request_body(creds, request),
        )))
        .expect("every part of this request is a constant or bytes")
}

/// The blinder that opens the committed bearer, picked out of everything the
/// session committed.
///
/// Matched on the range it covers rather than taken by position. Upstream does
/// document the order -- `commitment_openings` is "one opening per commitment
/// this session made, in the order the layouts stated them" -- but that is a
/// doc comment over a `Vec`, not an invariant anything checks, and the wrong
/// blinder opens nothing while looking like an answer. Matching on the range
/// costs a comparison and does not depend on the promise holding.
///
/// Exactly one must match. None means the session did not commit what the
/// layout said it would; more than one means the bearer is not identified by
/// its range, and handing back either would be a guess.
fn bearer_blinder<'a>(
    openings: impl Iterator<Item = (Direction, &'a [Range<usize>], &'a [u8])>,
    bearer: &Range<usize>,
) -> Result<Vec<u8>, Error> {
    let mut matching = openings.filter_map(|(direction, ranges, blinder)| {
        (direction == Direction::Received && ranges == [bearer.clone()])
            .then_some(blinder)
    });
    match (matching.next(), matching.next()) {
        (Some(blinder), None) => Ok(blinder.to_vec()),
        _ => Err(Error::MpcTlsFailed {
            detail: "the session did not commit the bearer exactly once".into(),
        }),
    }
}

/// What one session discloses, and the bearer it committed.
struct Selection {
    /// What the request reveals, and what it commits.
    sent: ceremony::Layout,
    /// The same for the response.
    recv: ceremony::Layout,
    /// Where the bearer sits in the received transcript.
    bearer: Range<usize>,
    /// The bearer itself, taken from that range of that transcript.
    bearer_bytes: Vec<u8>,
}

/// What this session discloses, and where the bearer ends up.
///
/// The single decision that matters to everyone downstream: the notary signs
/// what these two layouts revealed, the Platform Verifier reads that record,
/// and the browser's proof rests on the committed run in between. Each
/// direction's commitments are the complement of its reveals, so both tile by
/// construction — which is what the verifier's coverage check demands.
impl Selection {
    fn of(sent: &[u8], recv: &[u8]) -> Result<Self, ceremony::LayoutError> {
        let sent_layout = ceremony::token_request(sent, Some(SECRET_FIELD))?;
        let recv_layout = ceremony::token_response(recv)?;
        let bearer = bearer_range(&recv_layout)?;
        // `"access_token":""` frames an empty run, which the layout's complement
        // never commits -- so no opening would match it, and the failure would
        // surface as a notary fault. It is the same thing as no bearer at all, and
        // it is GitHub's answer, not ours.
        if bearer.is_empty() {
            return Err(ceremony::LayoutError::MissingField("access_token".into()));
        }
        // Read here, off the transcript the notary attests, and never off the
        // decoded response body. OAUTH_BRIDGE.md asks for the exact bearer the
        // attestation commits, and the two are not always the same string: a JSON
        // escape decodes, and a chunk boundary landing inside the value shifts
        // everything after it. Handing back a bearer the commitment does not open
        // fails later, in the circuit, where the reason is invisible.
        let bearer_bytes = recv
            .get(bearer.clone())
            .ok_or_else(|| ceremony::LayoutError::MissingField("access_token".into()))?
            .to_vec();
        Ok(Selection {
            sent: sent_layout,
            recv: recv_layout,
            bearer,
            bearer_bytes,
        })
    }
}

/// The error code GitHub returns for a code that was spent, replayed or never
/// valid. The one refusal in its catalogue that the caller can act on.
const BAD_CODE: &[u8] = b"bad_verification_code";

/// The field GitHub names a refusal in. Its presence says the platform decided
/// something; its absence says the response was not a refusal at all.
const ERROR_FIELD: &[u8] = b"\"error\":\"";

/// What the platform actually answered, as far as this service can tell from
/// the received transcript.
///
/// Three outcomes, because there are three, and answering them alike is how an
/// operator ends up paged for a spent code or a user ends up told to retry
/// something that cannot succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformAnswer {
    /// `bad_verification_code`: spent, replayed, or never valid.
    RefusedTheCode,
    /// Some other named error -- `incorrect_client_credentials`,
    /// `redirect_uri_mismatch`. This deployment is broken for everybody.
    RefusedThisDeployment,
    /// No named error, and no bearer either: a `200` this service cannot use.
    /// Neither party can fix it by trying again.
    Unusable,
}

/// Read that answer off the transcript, where it exists and nowhere else.
///
/// The whole reading survives as one enum value. Nothing the platform wrote
/// travels further: what reaches a log or a caller is this service's own words.
impl PlatformAnswer {
    fn in_response(recv: &[u8]) -> Self {
        let holds = |needle: &[u8]| recv.windows(needle.len()).any(|w| w == needle);
        if holds(BAD_CODE) {
            PlatformAnswer::RefusedTheCode
        } else if holds(ERROR_FIELD) {
            PlatformAnswer::RefusedThisDeployment
        } else {
            PlatformAnswer::Unusable
        }
    }
}

/// GitHub answering the exchange with something other than a bearer.
///
/// The session ran and the response arrived carrying no `access_token` for the
/// layout to anchor on. WHOSE fault that is decides the answer, and GitHub
/// returns `200` for every one of them, so the status cannot decide it -- the
/// error code can, and [`PlatformAnswer::in_response`] reads it.
///
/// `bad_verification_code` is the caller's: a double-clicked button, a reloaded
/// callback, a stale link. Every other named code --
/// `incorrect_client_credentials`, `redirect_uri_mismatch` -- is this
/// deployment, broken for everybody until a setting changes. Answering those as
/// the caller's would tell every user to retry something that cannot succeed,
/// and leave nothing above `warn` in the log while it happened.
///
/// And a `200` naming NO error while carrying no bearer is neither. It is a
/// response this service cannot use, and calling it a bad code would page an
/// operator over credentials that are fine while telling a user to retry.
fn platform_refusal(
    refusal: Option<&ceremony::LayoutError>,
    answer: PlatformAnswer,
) -> Option<Error> {
    if !matches!(refusal, Some(ceremony::LayoutError::MissingField(f)) if f == "access_token")
    {
        return None;
    }
    Some(match answer {
        PlatformAnswer::RefusedTheCode => Error::OAuthFailed {
            platform: "github".into(),
            detail: "the token endpoint returned no access_token".into(),
        },
        PlatformAnswer::RefusedThisDeployment => Error::PlatformMisconfigured {
            platform: "github".into(),
            detail: "the token endpoint refused with an error that is not a bad \
                     verification code; check GH_OAUTH_CLIENT_SECRET and that the \
                     registered callback URL is exactly this deployment's redirect \
                     URI"
            .into(),
        },
        PlatformAnswer::Unusable => Error::MpcTlsFailed {
            detail: "the token endpoint answered with neither a bearer nor an error"
                .into(),
        },
    })
}

/// Open the session the notary answers on.
///
/// Its own budget, and a short one. A notary that is down refuses at once, but
/// one at an unroutable address hangs for the kernel's retry schedule — which
/// would otherwise be spent before the protocol had started, out of a budget
/// meant for the protocol.
async fn connect_notary(addr: &str) -> Result<tokio::net::TcpStream, Error> {
    let refused = |detail: String| Error::NotaryConnect {
        addr: addr.to_owned(),
        detail,
    };
    tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| refused("did not answer in time".into()))?
        .map_err(|e| refused(e.to_string()))
}

/// Run the exchange inside one notarized session and assemble what it produced.
async fn exchange(
    github: &GithubExchange,
    request: &TokenRequest,
) -> Result<TokenResponse, Error> {
    let http_request = token_http_request(&github.credentials, request);
    let socket = connect_notary(&github.notary.socket()).await?;

    // What the layout decided, kept from inside the session. The bearer's
    // offsets index the raw received transcript, so neither they nor the bytes
    // at them can be recovered afterwards from the decoded body.
    let mut selected: Option<(Range<usize>, Vec<u8>)> = None;
    // Why the layout would not form, for the same reason: the error
    // `prover_generic` propagates says a transcript was refused, not which of
    // the two parties has something to fix.
    let mut refusal: Option<ceremony::LayoutError> = None;
    // Whose refusal it was, decided here because this is the only place the
    // received transcript exists. Read, never kept: what survives the closure
    // is one enum value, and this service's own words are what get logged.
    let mut answer = PlatformAnswer::Unusable;

    // The layouts state what this session discloses, and each direction's
    // commitments are the complement of its reveals — so the transcript tiles
    // by construction, which is what the Platform Verifier's coverage check
    // demands.
    let session = tokio::time::timeout(
        SESSION_TIMEOUT,
        libid_tlsn::prover_generic(
            socket,
            http_request,
            |sent, recv| match Selection::of(sent, recv) {
                Ok(Selection {
                    sent,
                    recv,
                    bearer,
                    bearer_bytes,
                }) => {
                    selected = Some((bearer, bearer_bytes));
                    Ok((sent, recv))
                }
                Err(e) => {
                    answer = PlatformAnswer::in_response(recv);
                    let failed = layout_failed(&e);
                    refusal = Some(e);
                    Err(failed)
                }
            },
            |_step| {},
        ),
    )
    .await
    .map_err(|_| Error::MpcTlsFailed {
        detail: "the notarized session did not finish in time".into(),
    })?;

    let mut result = match session {
        Ok(result) => result,
        Err(e) => {
            return Err(
                platform_refusal(refusal.as_ref(), answer).unwrap_or_else(|| e.into())
            )
        }
    };

    let (bearer, bearer_bytes) = selected.ok_or_else(|| Error::MpcTlsFailed {
        detail: "the session produced no layout".into(),
    })?;

    let bearer_opening = bearer_blinder(
        result.commitment_openings.iter().map(|opening| {
            (
                opening.direction,
                opening.ranges.as_slice(),
                opening.blinder.as_slice(),
            )
        }),
        &bearer,
    )?;

    // The notary answers a completed session on the socket the session ran
    // over. It reads no attestation request: everything it signs it observed
    // itself, so there is nothing left for this side to ask for.
    let wire: AttestationWire = tokio::time::timeout(
        RECORD_TIMEOUT,
        libid_transcript::read_msg(&mut result.recovered_io),
    )
    .await
    .map_err(|_| Error::MpcTlsFailed {
        detail: "the notary ran the session and then sent no record in time".into(),
    })?
    .map_err(|e| Error::MpcTlsFailed {
        // Most often an end of file: the notary refused the session after
        // running it — its own signer failing, say — and closed without
        // writing a record. Said plainly here, because a bare io error at
        // this point reads as a network fault rather than a refusal.
        detail: format!("the notary sent no record for the session it ran: {e}"),
    })?;

    // The committed bytes, not a second reading of the same value: what the
    // browser is handed has to be what the attestation's commitment opens.
    let access_token =
        String::from_utf8(bearer_bytes).map_err(|e| Error::MpcTlsFailed {
            detail: format!("the committed bearer is not valid UTF-8: {e}"),
        })?;

    Ok(TokenResponse {
        access_token,
        token_attestation: TokenAttestation {
            attested_data: wire.attested_data,
            signature: wire.notary_signature,
        },
        bearer_opening,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use libid_ceremony::token_exchange::{
        BEARER_OPENING_LEN,
        MAX_ACCESS_TOKEN_BYTES,
        MAX_ATTESTED_DATA_BYTES,
        MAX_RESPONSE_BYTES,
        SIGNATURE_LEN,
    };

    /// The head this service writes, as `prover_generic` will send it: header
    /// names go on the wire lowercase, and hyper adds the `content-length` a
    /// sized body implies. A fixture missing it would put every offset below a
    /// few bytes away from the transcript a real session produces.
    const HEAD: &str = "POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n";

    /// The only part of the exchange state these tests read. The transcript
    /// and its layout are a function of the credentials and the request, and
    /// of nothing else the route holds -- so the fixture is the credentials.
    fn credentials(client_secret: &str) -> crate::oauth::OAuthCredentials {
        crate::oauth::OAuthCredentials {
            client_id: "Iv1.0123456789abcdef".into(),
            client_secret: client_secret.into(),
            redirect_uri: "http://127.0.0.1:8722/auth/callback".into(),
        }
    }

    fn request() -> TokenRequest {
        TokenRequest {
            code: "6b7f2c1d9e4a8035".into(),
            code_verifier: "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I".into(),
        }
    }

    /// What the session will see in the sent direction.
    fn sent(credentials: &OAuthCredentials, request: &TokenRequest) -> Vec<u8> {
        let body = token_request_body(credentials, request);
        format!("{HEAD}content-length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    /// The property the whole design rests on: everything that proves this
    /// request belongs to the ceremony is revealed, and the secret is the only
    /// thing hidden — as a suffix, so the transcript still tiles.
    #[test]
    fn the_secret_is_the_only_thing_the_request_hides() {
        let credentials = credentials("ghs_averyrealisticlookingclientsecret00");
        let transcript = sent(&credentials, &request());
        let layout = ceremony::token_request(&transcript, Some(SECRET_FIELD)).unwrap();

        assert_eq!(layout.reveal.len(), 1, "one revealed prefix");
        assert_eq!(layout.reveal[0].start, 0);
        assert_eq!(
            layout.commit.last().unwrap().end,
            transcript.len(),
            "the commitment reaches the transcript end, so nothing is left uncovered"
        );

        let revealed = &transcript[layout.reveal[0].clone()];
        for public in [
            b"client_id=Iv1.0123456789abcdef".as_slice(),
            b"code=6b7f2c1d9e4a8035".as_slice(),
            b"code_verifier=iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I".as_slice(),
            b"redirect_uri=".as_slice(),
        ] {
            assert!(
                revealed.windows(public.len()).any(|w| w == public),
                "{} is revealed",
                String::from_utf8_lossy(public)
            );
        }
        assert!(
            !revealed
                .windows(credentials.client_secret.len())
                .any(|w| w == credentials.client_secret.as_bytes()),
            "the secret is nowhere in what the notary is shown"
        );
    }

    /// A secret carrying `&` or `=` cannot make this service's own request
    /// decode as more fields than it sends: the serializer percent-encodes
    /// both, so the boundary the layout anchors on stays the one this service
    /// wrote.
    #[test]
    fn a_secret_carrying_form_delimiters_cannot_forge_a_field() {
        let secret = "sk&client_secret=forged&scope=admin";
        let credentials = credentials(secret);
        let body = token_request_body(&credentials, &request());

        let pairs: Vec<_> = url::form_urlencoded::parse(body.as_bytes()).collect();
        assert_eq!(pairs.len(), 5, "five fields, whatever the secret contains");
        assert_eq!(pairs[4].0, SECRET_FIELD);
        assert_eq!(pairs[4].1, secret, "and it round-trips unmangled");

        let transcript = sent(&credentials, &request());
        let layout = ceremony::token_request(&transcript, Some(SECRET_FIELD)).unwrap();
        assert_eq!(layout.reveal.len(), 1);

        // Searched for as it appears ON THE WIRE. The raw bytes of a secret
        // carrying `&` or `=` occur nowhere in a percent-encoded body, so an
        // assertion against those would hold for any layout at all -- including
        // one that revealed the whole transcript.
        let at = body.find(SECRET_FIELD).unwrap() + SECRET_FIELD.len() + 1;
        let on_the_wire = &body.as_bytes()[at..];
        assert!(
            on_the_wire.starts_with(b"sk%26client_secret%3D"),
            "percent-encoded"
        );
        let at = transcript
            .windows(on_the_wire.len())
            .position(|w| w == on_the_wire)
            .expect("the encoded secret is in the transcript this session sends");
        let encoded = at..at + on_the_wire.len();
        assert!(
            layout.reveal[0].end <= encoded.start,
            "the revealed prefix stops before the secret"
        );
        assert!(
            layout
                .commit
                .iter()
                .any(|c| c.start <= encoded.start && encoded.end <= c.end),
            "and a committed range covers it whole"
        );
    }

    const RECV: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"access_token\":\"gho_16C7e42F292c6912E7710c838347Ae178B4a\",\"token_type\":\"bearer\",\"scope\":\"\"}";

    /// Both directions must tile — reveals and commitments accounting for every
    /// byte, with no gap and no overlap — or the Platform Verifier refuses the
    /// record the notary signs over them.
    #[test]
    fn both_directions_of_the_session_tile() {
        let credentials = credentials("ghs_averyrealisticlookingclientsecret00");
        let sent = sent(&credentials, &request());
        let found = Selection::of(&sent, RECV).unwrap();

        for (layout, len, what) in [
            (&found.sent, sent.len(), "request"),
            (&found.recv, RECV.len(), "response"),
        ] {
            let mut spans: Vec<_> = layout
                .reveal
                .iter()
                .chain(layout.commit.iter())
                .cloned()
                .collect();
            spans.sort_by_key(|r| r.start);
            let mut at = 0;
            for span in spans {
                assert_eq!(span.start, at, "{what}: gap or overlap at {at}");
                assert!(span.end > span.start, "{what}: empty span at {at}");
                at = span.end;
            }
            assert_eq!(at, len, "{what}: coverage stops short");
        }

        assert_eq!(
            &RECV[found.bearer.clone()],
            b"gho_16C7e42F292c6912E7710c838347Ae178B4a"
        );
        // OAUTH_BRIDGE.md: what this route returns is the bearer the attestation
        // commits, read off the attested transcript rather than re-parsed from
        // the decoded body, which need not spell it the same way.
        assert_eq!(found.bearer_bytes, &RECV[found.bearer]);
    }

    /// GitHub answers a spent or forged code with `200` and an error object.
    /// There is no bearer to commit, so the session is refused rather than
    /// completed around an anchor that is not there.
    #[test]
    fn a_response_carrying_no_bearer_is_refused() {
        let credentials = credentials("ghs_secret");
        let sent = sent(&credentials, &request());
        const ERROR: &[u8] =
            b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"bad_verification_code\"}";
        assert!(Selection::of(&sent, ERROR).is_err());
    }

    /// GitHub answers `200` to a spent code AND to a wrong client secret, so
    /// the status tells the two apart from nothing. The error code does, and
    /// the two deserve opposite answers: one caller retries, the other means
    /// every ceremony on this deployment fails until somebody changes a
    /// setting.
    #[test]
    fn a_refused_code_and_a_broken_deployment_are_not_the_same_answer() {
        let refused = ceremony::LayoutError::MissingField("access_token".into());

        let callers =
            platform_refusal(Some(&refused), PlatformAnswer::RefusedTheCode).unwrap();
        assert!(matches!(callers, Error::OAuthFailed { .. }));
        assert_eq!(
            TokenError::from_exchange(callers).status,
            StatusCode::BAD_REQUEST,
            "a spent code is the caller's to fix"
        );

        let ours =
            platform_refusal(Some(&refused), PlatformAnswer::RefusedThisDeployment)
                .unwrap();
        assert!(matches!(ours, Error::PlatformMisconfigured { .. }));
        assert_eq!(
            TokenError::from_exchange(ours).status,
            StatusCode::BAD_GATEWAY,
            "a rejected client secret is not, and must not tell a user to retry"
        );

        // And nothing this service writes about it quotes the platform.
        let Some(Error::PlatformMisconfigured { detail, .. }) =
            platform_refusal(Some(&refused), PlatformAnswer::RefusedThisDeployment)
        else {
            panic!("a deployment fault")
        };
        assert!(!detail.contains("bad_verification_code"), "{detail}");
    }

    /// Which of the two it is comes off the received transcript, and the only
    /// thing that survives that reading is one bit.
    #[test]
    fn the_bad_code_marker_is_read_from_the_response_the_session_saw() {
        let names = |body: &[u8]| body.windows(BAD_CODE.len()).any(|w| w == BAD_CODE);
        assert!(names(
            b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"bad_verification_code\"}"
        ));
        for other in [
            b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"incorrect_client_credentials\"}"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"redirect_uri_mismatch\"}".as_slice(),
            b"HTTP/1.1 500 Internal Server Error\r\n\r\n{}".as_slice(),
        ] {
            assert!(!names(other), "{}", String::from_utf8_lossy(other));
        }
    }

    /// Everything else is this service, the notary or the network. A request
    /// body that will not form a layout is THIS service disagreeing with
    /// itself, and a caller can do nothing about it — so it must not be
    /// reported as the caller's fault.
    #[test]
    fn every_other_failure_stays_an_upstream_fault() {
        for other in [
            Some(&ceremony::LayoutError::MissingCredential),
            Some(&ceremony::LayoutError::NoHeadBoundary),
            None,
        ] {
            for answer in [
                PlatformAnswer::RefusedTheCode,
                PlatformAnswer::RefusedThisDeployment,
                PlatformAnswer::Unusable,
            ] {
                assert!(platform_refusal(other, answer).is_none(), "{other:?}");
            }
        }
        assert_eq!(
            TokenError::from_exchange(Error::MpcTlsFailed {
                detail: "the notary went away".into(),
            })
            .status,
            StatusCode::BAD_GATEWAY
        );
    }

    /// The opening this route hands back must open the bearer and not one of
    /// the two runs around it, so the range it is matched on has to be the
    /// framed value exactly.
    #[test]
    fn the_bearer_range_is_the_value_between_the_anchors() {
        let layout = ceremony::token_response(RECV).unwrap();
        let range = bearer_range(&layout).unwrap();

        assert_eq!(
            &RECV[range.clone()],
            b"gho_16C7e42F292c6912E7710c838347Ae178B4a"
        );
        assert!(
            layout.commit.contains(&range),
            "and it is a committed range, so an opening exists for it"
        );
    }

    /// `prover_generic` writes no header of its own, so the one that names the
    /// server has to be here. Its absence is the failure that looks like
    /// somebody else's.
    #[test]
    fn the_request_names_the_host_the_session_authenticates() {
        let credentials = credentials("ghs_secret");
        let req = token_http_request(&credentials, &request());

        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), TOKEN_URL);
        assert_eq!(
            req.headers()[header::HOST],
            req.uri().authority().unwrap().as_str(),
            "the header names exactly the host the session will authenticate"
        );
        assert_eq!(req.uri().host(), Some("github.com"));
        assert_eq!(req.headers()[header::ACCEPT], "application/json");
        assert_eq!(
            req.headers()[header::CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );
        assert_eq!(req.headers()[header::CONNECTION], "close");
    }

    const BEARER: Range<usize> = 64..96;

    /// One commitment opening, in the shape `exchange` maps them into.
    type Opening = (Direction, Vec<Range<usize>>, &'static [u8]);

    fn opening(
        direction: Direction,
        range: Range<usize>,
        blinder: &'static [u8],
    ) -> Opening {
        (direction, core::iter::once(range).collect(), blinder)
    }

    fn pick(openings: &[Opening]) -> Result<Vec<u8>, Error> {
        bearer_blinder(
            openings.iter().map(|(d, r, b)| (*d, r.as_slice(), *b)),
            &BEARER,
        )
    }

    /// The session commits three runs of the response and one of the request.
    /// Only one of them opens the bearer, and it is not the first.
    #[test]
    fn the_opening_is_chosen_by_the_range_it_covers() {
        let picked = pick(&[
            opening(Direction::Sent, BEARER, b"wrong direction"),
            opening(Direction::Received, 0..64, b"the run before"),
            opening(Direction::Received, BEARER, b"the bearer"),
            opening(Direction::Received, 96..128, b"the run after"),
        ])
        .unwrap();
        assert_eq!(picked, b"the bearer");
    }

    /// Handing back a blinder that opens something else would fail far from
    /// here, where the reason is no longer visible.
    #[test]
    fn an_ambiguous_or_absent_opening_is_refused_rather_than_guessed() {
        assert!(pick(&[opening(Direction::Received, 0..64, b"only the head")]).is_err());
        assert!(pick(&[
            opening(Direction::Received, BEARER, b"one"),
            opening(Direction::Received, BEARER, b"two"),
        ])
        .is_err());
        assert!(pick(&[]).is_err());
    }

    /// The notary is reached by address, and a refusal names the address it
    /// was refused at — the first thing an operator needs when a ceremony
    /// fails and nothing else in the reply says why.
    #[tokio::test]
    async fn a_notary_that_is_not_listening_is_reported_with_its_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        assert!(connect_notary(&addr).await.is_ok(), "one that is listening");

        drop(listener);
        let err = connect_notary(&addr).await.unwrap_err().to_string();
        assert!(err.contains(&addr), "{err} names where it failed");
    }

    /// A response layout of an unexpected shape is refused rather than sliced
    /// blindly: the wrong range would select an opening that opens the wrong
    /// bytes, which fails far from here.
    #[test]
    fn a_response_layout_without_both_anchors_is_refused() {
        let layout = ceremony::Layout {
            reveal: core::iter::once(0..8).collect(),
            commit: core::iter::once(8..16).collect(),
        };
        assert!(bearer_range(&layout).is_err());
    }

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

    /// `"access_token":""` frames an empty run. The layout forms -- both
    /// anchors are there -- and the complement never commits a zero-length
    /// range, so no opening would open it and the failure would arrive as a
    /// notary fault. It is GitHub answering with no bearer, which is the
    /// caller's to fix, so it is told apart here and answered as one.
    #[test]
    fn an_empty_bearer_is_refused_as_a_platform_refusal_and_not_a_notary_fault() {
        let credentials = credentials("ghs_secret");
        let sent = sent(&credentials, &request());
        let recv = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"access_token\":\"\",\"token_type\":\"bearer\"}";

        // Destructured rather than `unwrap_err`, which would need `Debug` on
        // `Selection` -- and `Selection` carries the bearer.
        let Err(refusal) = Selection::of(&sent, recv) else {
            panic!("an empty bearer must not produce a selection")
        };
        assert!(
            matches!(&refusal, ceremony::LayoutError::MissingField(f) if f == "access_token"),
            "got {refusal:?}"
        );
        // Classified from the SAME bytes production classifies, not from a
        // value the test chose. That distinction is the whole point: this
        // response names no error at all, so it is neither a spent code nor
        // wrong credentials -- and answering it as either would tell a user to
        // retry what cannot succeed, or page an operator over a secret that is
        // fine.
        let answer = PlatformAnswer::in_response(recv);
        assert_eq!(answer, PlatformAnswer::Unusable);
        let told = platform_refusal(Some(&refusal), answer).expect("a platform refusal");
        assert!(matches!(told, Error::MpcTlsFailed { .. }));
        assert_eq!(
            TokenError::from_exchange(told).status,
            StatusCode::BAD_GATEWAY
        );
    }

    /// The three answers a `200` can carry, read off the transcript the way the
    /// session reads it.
    #[test]
    fn the_platform_answer_is_read_from_the_response_the_session_saw() {
        let body = |json: &str| {
            format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{json}")
                .into_bytes()
        };
        for (json, expected) in [
            (
                r#"{"error":"bad_verification_code"}"#,
                PlatformAnswer::RefusedTheCode,
            ),
            (
                r#"{"error":"incorrect_client_credentials"}"#,
                PlatformAnswer::RefusedThisDeployment,
            ),
            (
                r#"{"error":"redirect_uri_mismatch"}"#,
                PlatformAnswer::RefusedThisDeployment,
            ),
            (r#"{"access_token":""}"#, PlatformAnswer::Unusable),
            (r#"{}"#, PlatformAnswer::Unusable),
        ] {
            assert_eq!(PlatformAnswer::in_response(&body(json)), expected, "{json}");
        }

        // And each maps to a different answer, which is why they are told
        // apart at all.
        let refused = ceremony::LayoutError::MissingField("access_token".into());
        for (answer, status) in [
            (PlatformAnswer::RefusedTheCode, StatusCode::BAD_REQUEST),
            (
                PlatformAnswer::RefusedThisDeployment,
                StatusCode::BAD_GATEWAY,
            ),
            (PlatformAnswer::Unusable, StatusCode::BAD_GATEWAY),
        ] {
            let told = platform_refusal(Some(&refused), answer).expect("a refusal");
            assert_eq!(TokenError::from_exchange(told).status, status, "{answer:?}");
        }
    }

    /// A response carrying no `access_token` anchor at all is the same
    /// refusal as one carrying an empty value, and both are answered the same
    /// way: GitHub had no bearer for this code, so the caller gets a `400` and
    /// is told to start a fresh ceremony.
    ///
    /// Every OTHER layout refusal is this service, the notary, or a transcript
    /// nobody can describe, and the caller can only try again later. That is
    /// the half `NoHeadBoundary` stands for here.
    #[test]
    fn a_missing_access_token_is_a_refused_code_and_every_other_refusal_is_not() {
        let credentials = credentials("ghs_secret");
        let sent = sent(&credentials, &request());
        let recv = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"error\":\"bad_verification_code\"}";

        let Err(refusal) = Selection::of(&sent, recv) else {
            panic!("a response with no bearer must not produce a selection")
        };
        let told = platform_refusal(Some(&refusal), PlatformAnswer::in_response(recv))
            .expect("a refusal");
        assert_eq!(
            TokenError::from_exchange(told).status,
            StatusCode::BAD_REQUEST,
            "no access_token plus a bad-code marker is the caller's to act on"
        );

        // And nothing else is. A layout that would not form for any other
        // reason is this service's or the notary's, and says so with a 502.
        for other in [
            ceremony::LayoutError::NoHeadBoundary,
            ceremony::LayoutError::MissingCredential,
            ceremony::LayoutError::MissingHeader("host"),
        ] {
            assert!(
                platform_refusal(Some(&other), PlatformAnswer::RefusedTheCode).is_none(),
                "{other} is not the caller's to fix"
            );
        }
        assert!(platform_refusal(None, PlatformAnswer::RefusedTheCode).is_none());
        assert_eq!(
            TokenError::upstream("anything at all").status,
            StatusCode::BAD_GATEWAY
        );

        // Restated for the session driver, it says a transcript was refused
        // and carries the reason, not a second guess at whose fault it is.
        let restated = layout_failed(&refusal);
        assert!(restated.to_string().contains("access_token"), "{restated}");
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
