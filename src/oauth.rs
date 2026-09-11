//! The OAuth application this service authenticates as.

/// The confidential client registered with GitHub.
#[derive(Clone)]
pub struct OAuthCredentials {
    /// The client identifier. Public: the browser sends it in the
    /// authorization request, and the token request reveals it.
    pub client_id: String,
    /// The client secret. It never leaves this process and is committed, not
    /// revealed, in the notarized transcript. The request body is
    /// form-encoded, so `&` and `=` in the value are percent-encoded.
    pub client_secret: String,
}
