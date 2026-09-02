//! What the service holds while it runs.
//!
//! Everything here is configuration read once at startup. There is no ceremony
//! state, no session, no challenge and no result: the ceremony lives in the
//! browser, and this service answers one synchronous request at a time and
//! remembers nothing about it. A timeout, a duplicate request, a restart or a
//! lost response therefore leave no record, and recovery is a fresh ceremony
//! rather than a lookup here.
//!
//! It holds no signing key either. The notary signs; this service only carries
//! what the notary said.

use crate::oauth::OAuthCredentials;

/// Configuration the request handlers read.
pub struct AppState {
    /// Where this service is reachable, as an exact origin. The GitHub token
    /// route compares a request's `Origin` against it, so a value that differs
    /// from what browsers actually send refuses every legitimate call.
    pub server_origin: String,
    /// The application origins allowed to read the public ceremony
    /// configuration.
    pub allowed_app_origins: Vec<String>,
    /// The notary this service opens its token session against.
    pub notary_url: String,
    /// GitHub's confidential client. The secret never leaves this process and
    /// is never revealed in a notarized transcript.
    pub github_oauth: OAuthCredentials,
    /// Where the Google relay forwards to, when one is configured.
    pub app_url: Option<String>,
}
