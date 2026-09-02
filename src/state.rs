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

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::oauth::OAuthCredentials;

/// Configuration the request handlers read.
pub struct AppState {
    /// Where this service is reachable, as an exact origin. The GitHub token
    /// route compares a request's `Origin` against it, so a value that differs
    /// from what browsers actually send refuses every legitimate call.
    pub server_origin: String,
    /// The notary this service opens its token session against, as the
    /// `host:port` a TCP connect takes.
    ///
    /// Resolved from the configured URL once at startup, so a notary URL that
    /// names no host or no port stops the process from coming up rather than
    /// failing the first ceremony that reaches it.
    pub notary_addr: String,
    /// GitHub's confidential client. The secret never leaves this process and
    /// is never revealed in a notarized transcript.
    pub github_oauth: OAuthCredentials,
    /// How many token exchanges may run at once.
    ///
    /// This is the only thing standing between an anonymous caller and as many
    /// MPC-TLS sessions as it cares to start — the origin check is not caller
    /// authentication and says so. A request that finds no permit is shed,
    /// not queued.
    pub exchange_permits: Arc<Semaphore>,
}
