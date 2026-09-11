//! The request this service sends, and the one endpoint it may send it to.
//!
//! The endpoint is a constant and the field order is the profile's; the code,
//! the verifier and the redirect URI are the caller's. Nothing a caller sends
//! decides where this goes.

use axum::http::header;
use libid_ceremony::token_exchange::TokenRequest;
use libid_transcript::ceremony;

use crate::oauth::OAuthCredentials;

/// GitHub's token endpoint. A constant; a caller cannot select it.
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

/// GitHub's token session, as the generated profile table declares it; the
/// layouts are built from it. A profile table without one fails the build.
pub(super) const TOKEN_SESSION: ceremony::TokenSession =
    match ceremony::profiles::GITHUB.token {
        Some(session) => session,
        None => panic!("the github profile notarizes a token session"),
    };

/// The body field this service commits rather than reveals, read off the
/// profile.
pub(super) const SECRET_FIELD: &str = match TOKEN_SESSION.secret_field {
    Some(field) => field,
    None => panic!("the github token session commits a body field"),
};

/// [`TOKEN_URL`] parsed, and the authority sent as `Host`.
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

/// Parse the token endpoint at startup -- `build_state` calls this -- so a
/// build in which it does not parse fails there.
pub(crate) fn force_token_endpoint() {
    std::sync::LazyLock::force(&TOKEN_ENDPOINT);
}

/// The body of the token request, in the field order the profile fixes. The
/// secret is last: the committed range is a suffix, and the transcript tiles.
pub(super) fn token_request_body(
    creds: &OAuthCredentials,
    request: &TokenRequest,
    redirect_uri: &str,
) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &creds.client_id)
        .append_pair("code", &request.code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_verifier", &request.code_verifier)
        .append_pair(SECRET_FIELD, &creds.client_secret)
        .finish()
}

/// The token request this service sends, as the session transmits it. `Host`
/// is set here, from the URI's own authority; `prover_generic` writes no
/// header of its own.
pub(super) fn token_http_request(
    creds: &OAuthCredentials,
    request: &TokenRequest,
    redirect_uri: &str,
) -> hyper::Request<http_body_util::Full<bytes::Bytes>> {
    let (uri, host) = &*TOKEN_ENDPOINT;

    hyper::Request::builder()
        .method("POST")
        .uri(uri.clone())
        .header(header::HOST, host.as_str())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        // The session ends with the exchange; without it the connection stays
        // open.
        .header(header::CONNECTION, "close")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            token_request_body(creds, request, redirect_uri),
        )))
        .expect("every part of this request is a constant or bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    use libid_transcript::ceremony;

    use super::super::fixtures::{
        credentials,
        request,
        sent,
        REDIRECT_URI,
    };

    /// The fixture request as the session sends it, and its layout.
    fn laid_out(credentials: &OAuthCredentials) -> (Vec<u8>, ceremony::Layout) {
        let transcript = sent(credentials, &request());
        let layout =
            ceremony::Layout::token_request(&transcript, &TOKEN_SESSION).unwrap();
        (transcript, layout)
    }

    /// Everything that proves this request belongs to the ceremony is
    /// revealed; the secret is committed, as a suffix.
    #[test]
    fn the_secret_is_the_only_thing_the_request_hides() {
        let credentials = credentials("ghs_averyrealisticlookingclientsecret00");
        let (transcript, layout) = laid_out(&credentials);

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

    /// A secret carrying `&` or `=` is percent-encoded: the body has five
    /// fields whatever the secret contains, and the committed range covers the
    /// encoded secret whole.
    #[test]
    fn a_secret_carrying_form_delimiters_cannot_forge_a_field() {
        let secret = "sk&client_secret=forged&scope=admin";
        let credentials = credentials(secret);
        let body = token_request_body(&credentials, &request(), REDIRECT_URI);

        let pairs: Vec<_> = url::form_urlencoded::parse(body.as_bytes()).collect();
        assert_eq!(pairs.len(), 5, "five fields, whatever the secret contains");
        assert_eq!(pairs[4].0, SECRET_FIELD);
        assert_eq!(pairs[4].1, secret, "and it round-trips unmangled");

        let (transcript, layout) = laid_out(&credentials);
        assert_eq!(layout.reveal.len(), 1);

        // The secret as it appears on the wire, percent-encoded.
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

    /// `Host` names the host the session authenticates.
    #[test]
    fn the_request_names_the_host_the_session_authenticates() {
        let credentials = credentials("ghs_secret");
        let req = token_http_request(&credentials, &request(), REDIRECT_URI);

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
}
