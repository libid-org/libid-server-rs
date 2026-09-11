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
    /// Nobody proves what is in it, so a secret carrying a form delimiter
    /// would be the one field able to forge another. It cannot: the request
    /// body is built with a form serializer, which percent-encodes `&` and `=`
    /// in a value, so the boundary the disclosure layout anchors on is always
    /// the one this service wrote.
    pub client_secret: String,
}
