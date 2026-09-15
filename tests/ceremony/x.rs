//! The X ceremony's two sessions: the token exchange of a public PKCE client
//! and the identity read, as the X profile lays them out, and what the
//! Platform Verifier adds for X.

use axum::http::header;
use libid_ceremony::attestation::AttestedData;
use libid_transcript::ceremony::{
    profiles,
    IdentitySession,
    TokenSession,
};

use super::{
    notary::Notary,
    prover::Failed,
    session::{
        self,
        count,
        Bearer,
        Exchange,
        Identity,
        Request,
    },
};

/// X's token session, as the generated profile table declares it.
pub const TOKEN_SESSION: TokenSession = match profiles::X.token {
    Some(session) => session,
    None => panic!("the x profile notarizes a token session"),
};

/// X's identity session, as the generated profile table declares it.
pub const IDENTITY_SESSION: IdentitySession = match profiles::X.identity {
    Some(session) => session,
    None => panic!("the x profile notarizes an identity session"),
};

/// The token request the client sends: the body fields in the order the
/// client writes them, `Host` from the profile's authority.
pub fn token_request(
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Request {
    let session = TOKEN_SESSION.session;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", client_id)
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_verifier", code_verifier)
        .finish();
    hyper::Request::builder()
        .method(session.method)
        .uri(format!("https://{}{}", session.authority, session.path))
        .header(header::HOST, session.authority)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(header::CONNECTION, "close")
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .expect("every part of this request is a constant or bytes")
}

/// The identity request the client sends: exactly four headers, the bearer
/// first.
pub fn identity_request(bearer: &str) -> Request {
    let session = IDENTITY_SESSION.session;
    hyper::Request::builder()
        .method(session.method)
        .uri(format!("https://{}{}", session.authority, session.path))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::ACCEPT, "application/json")
        .header(header::HOST, session.authority)
        .header(header::CONNECTION, "close")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .expect("every part of this request is a constant or bytes")
}

/// The token session, run through `notary`: `request` revealed whole, the
/// response revealing the bearer's framing.
pub async fn exchange(notary: &Notary, request: Request) -> Result<Exchange, Failed> {
    Exchange::notarized(notary, request, &TOKEN_SESSION).await
}

/// The identity session, run through `notary` with `bearer`.
pub async fn identity(notary: &Notary, bearer: &str) -> Result<Identity, Failed> {
    Identity::notarized(notary, identity_request(bearer), &IDENTITY_SESSION).await
}

/// What the verifier demands of an X token record: the common checks, and a
/// body carrying the verifier REQ-COMMON-15A binds and the grant type.
pub fn check_token(
    record: &AttestedData,
    sent_len: usize,
    recv_len: usize,
    bearer: &Bearer,
) {
    let request =
        session::check_token(record, sent_len, recv_len, bearer, &TOKEN_SESSION);
    assert_eq!(count(&request, b"code_verifier="), 1);
    assert_eq!(count(&request, b"grant_type=authorization_code"), 1);
}

/// What the verifier demands of an X identity record read for the account
/// whose handle is `handle`: the common checks; the id a decimal string, the
/// username the account's. The id and username, as revealed.
pub fn check_identity(
    record: &AttestedData,
    sent_len: usize,
    recv_len: usize,
    bearer: &str,
    handle: &str,
) -> (String, String) {
    let (id, username) =
        session::check_identity(record, sent_len, recv_len, bearer, &IDENTITY_SESSION);
    assert!(
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
        "an X id is a decimal string: {id:?}"
    );
    assert!(
        username.eq_ignore_ascii_case(handle),
        "the username is the account's: {username:?}"
    );
    (id, username)
}

#[cfg(test)]
mod tests {
    use libid_transcript::ceremony::Layout;

    use super::{
        super::session::{
            fixtures::{
                bearer_in,
                record,
                wire,
            },
            joined,
        },
        *,
    };

    /// X's answer to the token request.
    const TOKEN_RECV: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json; charset=utf-8\r\nconnection: close\r\n\r\n{\"token_type\":\"bearer\",\"expires_in\":7200,\"access_token\":\"SECRETBEARER\",\"scope\":\"users.read tweet.read\"}";

    /// X's answer to the identity request.
    const ID_RECV: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json; charset=utf-8\r\nconnection: close\r\n\r\n{\"data\":{\"id\":\"2244994945\",\"name\":\"Al\",\"username\":\"alice\"}}";

    const AUTHORITY: &str = "api.x.com";

    /// The token request is what the X profile lays out: revealed whole, the
    /// required headers once each, the body in the client's field order.
    #[tokio::test]
    async fn the_token_request_is_laid_out_whole() {
        let sent = wire(token_request(
            "WHRlc3RjbGllbnQ6MTpjaQ",
            "Y29kZQ",
            "http://localhost:4682/auth/callback",
            "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I",
        ))
        .await;
        assert!(sent.starts_with(b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n"));
        assert_eq!(count(&sent, b"\r\n\r\n"), 1);
        let body = &sent[sent.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert_eq!(
            body,
            b"grant_type=authorization_code&client_id=WHRlc3RjbGllbnQ6MTpjaQ&code=Y29kZQ&redirect_uri=http%3A%2F%2Flocalhost%3A4682%2Fauth%2Fcallback&code_verifier=iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I"
        );

        let layout = Layout::token_request(&sent, &TOKEN_SESSION).unwrap();
        let whole = 0..sent.len();
        assert_eq!(layout.reveal, std::slice::from_ref(&whole));
        assert!(layout.commit.is_empty());

        let recv_layout = Layout::token_response(TOKEN_RECV).unwrap();
        check_token(
            &record(AUTHORITY, &sent, TOKEN_RECV, &layout, &recv_layout),
            sent.len(),
            TOKEN_RECV.len(),
            &bearer_in(TOKEN_RECV, "SECRETBEARER"),
        );
    }

    /// The identity request is what the X profile lays out: four headers,
    /// the bearer value the one committed run.
    #[tokio::test]
    async fn the_identity_request_hides_the_bearer_and_nothing_else() {
        let sent = wire(identity_request("SECRETBEARER")).await;
        assert_eq!(
            sent,
            b"GET /2/users/me HTTP/1.1\r\nauthorization: Bearer SECRETBEARER\r\naccept: application/json\r\nhost: api.x.com\r\nconnection: close\r\n\r\n"
        );

        let layout = Layout::identity_request(&sent).unwrap();
        let bearer = bearer_in(&sent, "SECRETBEARER");
        assert_eq!(layout.commit, std::slice::from_ref(&bearer.range));
        assert_eq!(layout.reveal.len(), 2);

        let recv_layout = Layout::identity_response(ID_RECV, &IDENTITY_SESSION).unwrap();
        let signed = record(AUTHORITY, &sent, ID_RECV, &layout, &recv_layout);
        let (id, username) =
            check_identity(&signed, sent.len(), ID_RECV.len(), "SECRETBEARER", "Alice");
        assert_eq!(id, "2244994945");
        assert_eq!(username, "alice");
        assert_eq!(
            count(&joined(&signed.received), b"Al\""),
            0,
            "the display name stays committed"
        );
    }

    /// A record revealing the bearer is refused.
    #[test]
    #[should_panic(expected = "exactly one commitment is framed as the bearer")]
    fn a_token_record_that_reveals_the_bearer_is_refused() {
        let sent = b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\ngrant_type=authorization_code&code_verifier=v";
        let sent_layout = Layout::token_request(sent, &TOKEN_SESSION).unwrap();
        let everything = Layout {
            reveal: std::iter::once(0..TOKEN_RECV.len()).collect(),
            commit: vec![],
        };
        check_token(
            &record(AUTHORITY, sent, TOKEN_RECV, &sent_layout, &everything),
            sent.len(),
            TOKEN_RECV.len(),
            &bearer_in(TOKEN_RECV, "SECRETBEARER"),
        );
    }
}
