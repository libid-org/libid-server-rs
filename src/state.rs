//! What the bridge holds while it runs.
//!
//! Everything here is configuration read once at startup. There is no ceremony
//! state, no session, no challenge and no result: the ceremony lives in the
//! browser, and this service answers one synchronous request at a time and
//! remembers nothing about it. A timeout, a duplicate request, a restart or a
//! lost response therefore leave no record, and recovery is a fresh ceremony
//! rather than a lookup here.
//!
//! It holds no signing key either. The notary signs; this bridge only carries
//! what the notary said.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::oauth::OAuthCredentials;

/// Everything the confidential exchange needs, and nothing any other route
/// does.
///
/// These four values are meaningful only where GitHub is enabled. Held beside
/// the rest of the state they were an invariant a doc comment asserted and the
/// type did not: a deployment without GitHub carried a notary address nothing
/// dialled and a permit nobody acquired, and the handler opened with a runtime
/// check for the state and the router disagreeing. Grouped here and reached
/// only as the token route's own state, the disagreement cannot be spelled --
/// the route is mounted with this or it is not mounted.
pub struct GithubExchange {
    /// GitHub's confidential client. The secret never leaves this process and
    /// is never revealed in a notarized transcript.
    pub credentials: OAuthCredentials,
    /// The notary this bridge opens its token session against, as the
    /// `host:port` a TCP connect takes.
    ///
    /// Resolved from the configured URL once at startup, so a notary URL that
    /// names no host or no port stops the process from coming up rather than
    /// failing the first ceremony that reaches it.
    pub notary_addr: String,
    /// The CCDP Distribution this bridge selects. The token route admits this
    /// origin and no other: the prover that calls it runs there.
    pub ccdp_origin: String,
    /// How many exchanges may run at once.
    ///
    /// This is the only thing standing between an anonymous caller and as many
    /// MPC-TLS sessions as it cares to start — the origin check is not caller
    /// authentication and says so. A request that finds no permit is shed,
    /// not queued.
    pub permits: Semaphore,
}

/// Configuration every route reads.
pub struct AppState {
    /// The configured path the providers redirect back to, where the callback
    /// shell answers.
    pub callback_path: String,
    /// The callback document, rendered once with its finished policy.
    pub callback_shell: crate::shell::RenderedShell,
    /// The application origins admitted to read the public configuration.
    ///
    /// Exact strings, canonicalised at startup the same way this bridge's own
    /// origin is, because the two are compared against what a browser sends.
    pub allowed_app_origins: Vec<String>,
    /// The public ceremony configuration, serialized once, as the exact bytes
    /// every admitted caller receives.
    ///
    /// One record for every request: it carries no secret and nothing a caller
    /// chose, so there is nothing to rebuild per request and nothing that
    /// could differ between two of them -- and nothing to re-serialize either.
    pub ceremony_config: bytes::Bytes,
    /// The confidential exchange, where the deployment enables GitHub.
    ///
    /// `None` means the token route is not mounted at all: a path that would
    /// answer without a secret is worse than one that is absent.
    pub github: Option<Arc<GithubExchange>>,
}
