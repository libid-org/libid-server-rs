//! The OAuth application this service authenticates as.
//!
//! What is left here is the registration and nothing else. The authorization
//! URL, the PKCE verifier and the redirect handling all moved to the browser,
//! which owns the ceremony: it derives the verifier from the Authorization
//! Digest and its nonce, opens the provider itself, and consumes the redirect
//! against its own live ceremony without asking this service anything.
//!
//! What the browser cannot hold is the client secret. That is the whole reason
//! a GitHub ceremony has a server side at all, and the only reason this struct
//! exists.

/// The confidential client registered with GitHub.
#[derive(Clone)]
pub struct OAuthCredentials {
    /// The client identifier. Public — the browser sends it in the
    /// authorization request and the token request reveals it.
    pub client_id: String,
    /// The client secret. It never leaves this process, is never revealed in a
    /// notarized transcript, and is committed rather than disclosed so that no
    /// party proves its contents.
    ///
    /// It must contain neither `&` nor `=`: the secret is redacted and nobody
    /// proves what is in it, so one carrying a form delimiter would make this
    /// service's own request decode as more fields than it sends.
    pub client_secret: String,
    /// The registered redirect URI, byte for byte as GitHub has it. The
    /// browser sends the same bytes in the token request, and GitHub refuses
    /// an exchange whose two spellings differ.
    pub redirect_uri: String,
}
