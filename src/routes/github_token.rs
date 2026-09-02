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
    extract::State,
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
use libid_transcript::ceremony;
use serde::{
    Deserialize,
    Serialize,
};
use tlsn::transcript::Direction;

use crate::{
    error::Error,
    state::AppState,
};

/// GitHub's token endpoint. Pinned by the platform profile, never configured:
/// a caller-selected endpoint would let one ask this service to spend its
/// secret against a host of the caller's choosing.
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

/// The field the profile orders last, and the only one committed rather than
/// revealed. Ordered last so the committed run is a suffix of the body and not
/// a hole in the middle of it.
const SECRET_FIELD: &str = "client_secret";

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

/// What the browser sends. Nothing else: this service uses only its own
/// compiled client, secret, redirect URI, endpoint and notary, and accepts no
/// caller-selected action, client, redirect, endpoint or return URL.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenRequestBody {
    /// The authorization code the callback captured.
    code: String,
    /// The PKCE verifier the browser derived for this ceremony.
    code_verifier: String,
}

/// The notary's answer to a completed session, read off the recovered socket.
///
/// A mirror of `AttestationWire` in `notary/src/server.rs`, which is private
/// there and serialize-only. The two must agree field for field: this is a
/// length-prefixed JSON message, so a rename on either side fails at read time
/// with a JSON error that says nothing about which side moved.
#[derive(Deserialize)]
struct AttestationWire {
    /// The exact bytes of ceremony-common section 9.1.
    attested_data: Vec<u8>,
    /// EIP-191 over `keccak256(attested_data)`.
    notary_signature: Vec<u8>,
}

/// The bearer as GitHub returned it, read from the response body.
#[derive(Deserialize)]
struct GithubTokenBody {
    access_token: String,
}

/// The notary's attestation of the exchange: the exact bytes it signed, and
/// the signature over them.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationBody {
    /// The section 9.1 record, byte for byte as the notary produced it.
    attested_data: String,
    /// EIP-191 over its keccak256 digest.
    signature: String,
}

/// What the browser gets back. Every byte string is unpadded URL-safe base64.
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
pub struct TokenError {
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

    /// The cause is LOGGED, never serialized: an anonymous caller learns that
    /// the exchange failed and nothing about this service's configuration, its
    /// notary, or which step of the session refused it.
    fn upstream(cause: impl std::fmt::Display) -> Self {
        tracing::error!(%cause, "github token exchange failed");
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
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "message": self.message })),
        )
            .into_response()
    }
}

/// `POST /api/v1/ceremony/github-token`.
pub async fn github_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Result<Json<TokenRequestBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, TokenError> {
    // Callable only from this service's own origin. This is not caller
    // authentication — a request with no browser behind it carries whatever
    // `Origin` it likes — it stops a page on another origin from spending this
    // service's secret through someone else's browser.
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if origin != state.server_origin {
        return Err(TokenError {
            status: StatusCode::FORBIDDEN,
            message: "this route is callable only from the ceremony origin".into(),
        });
    }

    // Malformed JSON fails before a session is opened and before the secret is
    // spent.
    let Json(body) = body.map_err(|e| TokenError::bad_request(e.body_text()))?;
    let request = TokenRequest {
        code: body.code,
        code_verifier: body.code_verifier,
    };
    request
        .validate()
        .map_err(|e| TokenError::bad_request(e.to_string()))?;

    let response = exchange(&state, &request)
        .await
        .map_err(TokenError::upstream)?;
    // The bounds are checked on the way out as well as in: the three values are
    // one result, and one of them out of shape makes the other two worthless.
    response
        .validate()
        .map_err(|e| TokenError::upstream(format!("built an invalid response: {e}")))?;

    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
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
/// One function rather than three call sites, because the three values are one
/// result and a browser that decodes two of them differently from the third
/// gets a proof that will not verify.
fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The body of the token request, in the exact field order the profile fixes.
///
/// The secret is last because the disclosure layout commits a suffix: with the
/// secret anywhere else the committed run would be a hole in the middle of the
/// revealed body, and the verifier's coverage check refuses a transcript it
/// cannot tile.
fn token_request_body(state: &AppState, request: &TokenRequest) -> String {
    let creds = &state.github_oauth;
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
fn layout_failed(e: ceremony::LayoutError) -> libid_tlsn::Error {
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
fn token_http_request(
    state: &AppState,
    request: &TokenRequest,
) -> Result<hyper::Request<http_body_util::Full<bytes::Bytes>>, Error> {
    let uri: hyper::Uri = TOKEN_URL.parse().map_err(|e| Error::Config {
        detail: format!("token endpoint {TOKEN_URL}: {e}"),
    })?;
    let host = uri
        .authority()
        .ok_or_else(|| Error::Config {
            detail: format!("token endpoint {TOKEN_URL} names no host"),
        })?
        .as_str()
        .to_owned();

    hyper::Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        // The session ends when the exchange does. Without it the connection is
        // kept alive and the prover waits on a response that is already
        // complete.
        .header(header::CONNECTION, "close")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            token_request_body(state, request),
        )))
        .map_err(|e| Error::Config {
            detail: format!("token request: {e}"),
        })
}

/// The blinder that opens the committed bearer, picked out of everything the
/// session committed.
///
/// Matched on the range it covers rather than taken by position: nothing
/// upstream promises the openings arrive in the order the layouts stated them,
/// and the wrong blinder opens nothing while looking like an answer.
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

/// What this session discloses, and where the bearer ends up.
///
/// The single decision that matters to everyone downstream: the notary signs
/// what these two layouts revealed, the Platform Verifier reads that record,
/// and the browser's proof rests on the committed run in between. Each
/// direction's commitments are the complement of its reveals, so both tile by
/// construction — which is what the verifier's coverage check demands.
fn select_layouts(
    sent: &[u8],
    recv: &[u8],
) -> Result<(ceremony::Layout, ceremony::Layout, Range<usize>), libid_tlsn::Error> {
    let sent_layout =
        ceremony::token_request(sent, Some(SECRET_FIELD)).map_err(layout_failed)?;
    let recv_layout = ceremony::token_response(recv).map_err(layout_failed)?;
    let bearer = bearer_range(&recv_layout).map_err(layout_failed)?;
    Ok((sent_layout, recv_layout, bearer))
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
    state: &AppState,
    request: &TokenRequest,
) -> Result<TokenResponse, Error> {
    let http_request = token_http_request(state, request)?;
    let socket = connect_notary(&state.notary_addr).await?;

    // Where the bearer sat in the response, taken from the layout that decided
    // it rather than searched for again afterwards. The layout works on the
    // raw received transcript, so these offsets have no meaning in the decoded
    // body and cannot be recovered from it.
    let mut bearer: Option<Range<usize>> = None;

    // The layouts state what this session discloses, and each direction's
    // commitments are the complement of its reveals — so the transcript tiles
    // by construction, which is what the Platform Verifier's coverage check
    // demands.
    let mut result = tokio::time::timeout(
        SESSION_TIMEOUT,
        libid_tlsn::prover_generic(
            socket,
            http_request,
            |sent, recv| {
                let (sent_layout, recv_layout, found) = select_layouts(sent, recv)?;
                bearer = Some(found);
                Ok((sent_layout, recv_layout))
            },
            |_step| {},
        ),
    )
    .await
    .map_err(|_| Error::MpcTlsFailed {
        detail: "the notarized session did not finish in time".into(),
    })??;

    let bearer = bearer.ok_or_else(|| Error::MpcTlsFailed {
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
    let wire: AttestationWire = libid_transcript::read_msg(&mut result.recovered_io)
        .await
        .map_err(|e| Error::MpcTlsFailed {
            // Most often an end of file: the notary refused the session after
            // running it — its own signer failing, say — and closed without
            // writing a record. Said plainly here, because a bare io error at
            // this point reads as a network fault rather than a refusal.
            detail: format!("the notary sent no record for the session it ran: {e}"),
        })?;

    // The layout already proved the anchor is in the transcript, so a body
    // without the field here is this service disagreeing with itself rather
    // than GitHub refusing the exchange.
    let body: GithubTokenBody = serde_json::from_slice(&result.response_body)?;

    Ok(TokenResponse {
        access_token: body.access_token,
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

    /// The head this service writes, as `prover_generic` will send it: header
    /// names go on the wire lowercase, and the body follows the blank line.
    const HEAD: &[u8] = b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n\r\n";

    fn state(client_secret: &str) -> AppState {
        AppState {
            server_origin: "http://127.0.0.1:8722".into(),
            allowed_app_origins: Vec::new(),
            notary_addr: "127.0.0.1:7047".into(),
            github_oauth: crate::oauth::OAuthCredentials {
                client_id: "Iv1.0123456789abcdef".into(),
                client_secret: client_secret.into(),
                redirect_uri: "http://127.0.0.1:8722/api/v1/ceremony/callback".into(),
            },
            app_url: None,
        }
    }

    fn request() -> TokenRequest {
        TokenRequest {
            code: "6b7f2c1d9e4a8035".into(),
            code_verifier: "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I".into(),
        }
    }

    /// What the session will see in the sent direction.
    fn sent(state: &AppState, request: &TokenRequest) -> Vec<u8> {
        let mut out = HEAD.to_vec();
        out.extend_from_slice(token_request_body(state, request).as_bytes());
        out
    }

    /// The property the whole design rests on: everything that proves this
    /// request belongs to the ceremony is revealed, and the secret is the only
    /// thing hidden — as a suffix, so the transcript still tiles.
    #[test]
    fn the_secret_is_the_only_thing_the_request_hides() {
        let state = state("ghs_averyrealisticlookingclientsecret00");
        let transcript = sent(&state, &request());
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
                .windows(state.github_oauth.client_secret.len())
                .any(|w| w == state.github_oauth.client_secret.as_bytes()),
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
        let state = state(secret);
        let body = token_request_body(&state, &request());

        let pairs: Vec<_> = url::form_urlencoded::parse(body.as_bytes()).collect();
        assert_eq!(pairs.len(), 5, "five fields, whatever the secret contains");
        assert_eq!(pairs[4].0, SECRET_FIELD);
        assert_eq!(pairs[4].1, secret, "and it round-trips unmangled");

        let transcript = sent(&state, &request());
        let layout = ceremony::token_request(&transcript, Some(SECRET_FIELD)).unwrap();
        assert_eq!(layout.reveal.len(), 1);
        assert!(
            !transcript[layout.reveal[0].clone()]
                .windows(secret.len())
                .any(|w| w == secret.as_bytes()),
            "the whole secret is still committed, delimiters and all"
        );
    }

    const RECV: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"access_token\":\"gho_16C7e42F292c6912E7710c838347Ae178B4a\",\"token_type\":\"bearer\",\"scope\":\"\"}";

    /// Both directions must tile — reveals and commitments accounting for every
    /// byte, with no gap and no overlap — or the Platform Verifier refuses the
    /// record the notary signs over them.
    #[test]
    fn both_directions_of_the_session_tile() {
        let state = state("ghs_averyrealisticlookingclientsecret00");
        let sent = sent(&state, &request());
        let (sl, rl, bearer) = select_layouts(&sent, RECV).unwrap();

        for (layout, len, what) in
            [(sl, sent.len(), "request"), (rl, RECV.len(), "response")]
        {
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

        assert_eq!(&RECV[bearer], b"gho_16C7e42F292c6912E7710c838347Ae178B4a");
    }

    /// GitHub answers a spent or forged code with `200` and an error object.
    /// There is no bearer to commit, so the session is refused rather than
    /// completed around an anchor that is not there.
    #[test]
    fn a_response_carrying_no_bearer_is_refused() {
        let state = state("ghs_secret");
        let sent = sent(&state, &request());
        const ERROR: &[u8] =
            b"HTTP/1.1 200 OK\r\n\r\n{\"error\":\"bad_verification_code\"}";
        assert!(select_layouts(&sent, ERROR).is_err());
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
        let state = state("ghs_secret");
        let req = token_http_request(&state, &request()).unwrap();

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
}
