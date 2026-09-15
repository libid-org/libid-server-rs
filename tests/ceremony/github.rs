//! The GitHub ceremony's two sessions: the token exchange of a public client
//! carrying the published credential as `client_secret`, revealed whole, and
//! the identity read, as the GitHub profile lays them out; and what the
//! Platform Verifier adds for GitHub.

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

/// GitHub's token session: the profile's, with the request revealed whole.
/// `client_secret` is public application configuration, not a committed
/// suffix.
pub const TOKEN_SESSION: TokenSession = TokenSession {
    secret_field: None,
    ..match profiles::GITHUB.token {
        Some(session) => session,
        None => panic!("the github profile notarizes a token session"),
    }
};

/// GitHub's identity session, as the generated profile table declares it.
pub const IDENTITY_SESSION: IdentitySession = match profiles::GITHUB.identity {
    Some(session) => session,
    None => panic!("the github profile notarizes an identity session"),
};

/// The five fields of the token request body, in the order the profile
/// fixes.
pub struct TokenFields<'a> {
    pub client_id: &'a str,
    pub code: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
    pub client_secret: &'a str,
}

impl TokenFields<'_> {
    /// The body: the form serialization of the five fields, in order.
    pub fn body(&self) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", self.client_id)
            .append_pair("code", self.code)
            .append_pair("redirect_uri", self.redirect_uri)
            .append_pair("code_verifier", self.code_verifier)
            .append_pair("client_secret", self.client_secret)
            .finish()
    }
}

/// The token request the client sends: the profile's request line and
/// headers, and the five-field body.
pub fn token_request(fields: &TokenFields) -> Request {
    let session = TOKEN_SESSION.session;
    hyper::Request::builder()
        .method(session.method)
        .uri(format!("https://{}{}", session.authority, session.path))
        .header(header::HOST, session.authority)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(header::CONNECTION, "close")
        .body(http_body_util::Full::new(bytes::Bytes::from(fields.body())))
        .expect("every part of this request is a constant or bytes")
}

/// The identity request the client sends: the bearer first, then the
/// `user-agent` GitHub's API requires of every caller.
pub fn identity_request(bearer: &str) -> Request {
    let session = IDENTITY_SESSION.session;
    hyper::Request::builder()
        .method(session.method)
        .uri(format!("https://{}{}", session.authority, session.path))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::ACCEPT, "application/json")
        .header(header::USER_AGENT, "libid-ceremony-suite")
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

/// What the verifier demands of a GitHub token record: the common checks,
/// and REQ-PLAT-61: the body is the serialization of exactly `fields`, byte
/// for byte, with no `grant_type` and no `authorization` header.
pub fn check_token(
    record: &AttestedData,
    sent_len: usize,
    recv_len: usize,
    bearer: &Bearer,
    fields: &TokenFields,
) {
    let request =
        session::check_token(record, sent_len, recv_len, bearer, &TOKEN_SESSION);
    let boundary = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("one head boundary")
        + 4;
    assert_eq!(
        &request[boundary..],
        fields.body().as_bytes(),
        "the body is the canonical five-field form"
    );
    assert_eq!(count(&request, b"grant_type="), 0);
    let mut normalized = request[..boundary].to_ascii_lowercase();
    normalized.retain(|&b| b != b' ' && b != b'\t');
    assert_eq!(count(&normalized, b"\r\nauthorization:"), 0);
}

/// What the verifier demands of a GitHub identity record read for the
/// account whose login is `handle`: the common checks; the id an integer,
/// the login the account's. The id and login, as revealed.
pub fn check_identity(
    record: &AttestedData,
    sent_len: usize,
    recv_len: usize,
    bearer: &str,
    handle: &str,
) -> (String, String) {
    let (id, login) =
        session::check_identity(record, sent_len, recv_len, bearer, &IDENTITY_SESSION);
    assert!(
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
        "a GitHub id is an integer: {id:?}"
    );
    assert!(
        login.eq_ignore_ascii_case(handle),
        "the login is the account's: {login:?}"
    );
    (id, login)
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

    /// GitHub's answer to the token request.
    const TOKEN_RECV: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json; charset=utf-8\r\nconnection: close\r\n\r\n{\"access_token\":\"SECRETBEARER\",\"token_type\":\"bearer\",\"scope\":\"read:user\"}";

    /// GitHub's answer to the identity request.
    const ID_RECV: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json; charset=utf-8\r\nconnection: close\r\n\r\n{\"login\":\"Alice\",\"id\":583231,\"node_id\":\"MDQ6VXNlcjU4MzIzMQ==\",\"name\":\"Alice Liddell\"}";

    const FIELDS: TokenFields<'static> = TokenFields {
        client_id: "Iv1.0123456789abcdef",
        code: "6b7f2c1d9e4a8035",
        redirect_uri: "https://localhost:4682/auth/callback",
        code_verifier: "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I",
        client_secret: "d3b07384d113edec49eaa6238ad5ff00c1f2e3a4",
    };

    /// The token request is the canonical five-field form, revealed whole:
    /// the profile's request line and headers, the body in the fixed order
    /// with the credential last, nothing committed.
    #[tokio::test]
    async fn the_token_request_is_the_canonical_five_field_form() {
        let sent = wire(token_request(&FIELDS)).await;
        assert!(sent.starts_with(
            b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n"
        ));
        assert_eq!(count(&sent, b"\r\n\r\n"), 1);
        let body = &sent[sent.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert_eq!(
            body,
            b"client_id=Iv1.0123456789abcdef&code=6b7f2c1d9e4a8035&redirect_uri=https%3A%2F%2Flocalhost%3A4682%2Fauth%2Fcallback&code_verifier=iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I&client_secret=d3b07384d113edec49eaa6238ad5ff00c1f2e3a4"
        );

        let layout = Layout::token_request(&sent, &TOKEN_SESSION).unwrap();
        let whole = 0..sent.len();
        assert_eq!(layout.reveal, std::slice::from_ref(&whole));
        assert!(layout.commit.is_empty());

        let recv_layout = Layout::token_response(TOKEN_RECV).unwrap();
        check_token(
            &record("github.com", &sent, TOKEN_RECV, &layout, &recv_layout),
            sent.len(),
            TOKEN_RECV.len(),
            &bearer_in(TOKEN_RECV, "SECRETBEARER"),
            &FIELDS,
        );
    }

    /// The identity request is what the GitHub profile lays out: the bearer
    /// value the one committed run, the integer id revealed with the comma
    /// that closes it, the display name committed.
    #[tokio::test]
    async fn the_identity_request_hides_the_bearer_and_nothing_else() {
        let sent = wire(identity_request("SECRETBEARER")).await;
        assert_eq!(
            sent,
            b"GET /user HTTP/1.1\r\nauthorization: Bearer SECRETBEARER\r\naccept: application/json\r\nuser-agent: libid-ceremony-suite\r\nhost: api.github.com\r\nconnection: close\r\n\r\n"
        );

        let layout = Layout::identity_request(&sent).unwrap();
        let bearer = bearer_in(&sent, "SECRETBEARER");
        assert_eq!(layout.commit, std::slice::from_ref(&bearer.range));
        assert_eq!(layout.reveal.len(), 2);

        let recv_layout = Layout::identity_response(ID_RECV, &IDENTITY_SESSION).unwrap();
        let signed = record("api.github.com", &sent, ID_RECV, &layout, &recv_layout);
        let (id, login) =
            check_identity(&signed, sent.len(), ID_RECV.len(), "SECRETBEARER", "alice");
        assert_eq!(id, "583231");
        assert_eq!(login, "Alice");
        let body = joined(&signed.received);
        assert_eq!(
            count(&body, b"Liddell"),
            0,
            "the display name stays committed"
        );
        assert_eq!(count(&body, b"node_id"), 0, "the node id stays committed");
    }

    /// A request laid out with the credential committed, the shape the
    /// profile table declares, is refused: nothing in the request is hidden.
    #[tokio::test]
    #[should_panic(expected = "a public client's request hides nothing")]
    async fn a_request_hiding_the_credential_is_refused() {
        let sent = wire(token_request(&FIELDS)).await;
        let hidden = profiles::GITHUB
            .token
            .expect("the profile table declares a token session");
        let sent_layout = Layout::token_request(&sent, &hidden).unwrap();
        assert_eq!(
            sent_layout.commit.len(),
            1,
            "the table's layout commits the credential"
        );
        let recv_layout = Layout::token_response(TOKEN_RECV).unwrap();
        check_token(
            &record("github.com", &sent, TOKEN_RECV, &sent_layout, &recv_layout),
            sent.len(),
            TOKEN_RECV.len(),
            &bearer_in(TOKEN_RECV, "SECRETBEARER"),
            &FIELDS,
        );
    }
}
