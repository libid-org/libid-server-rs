//! What the bridge holds while it runs.
//!
//! Everything here is configuration read once at startup. There is no ceremony
//! state, no session, no challenge and no result: the ceremony lives in the
//! browser, and this service answers each request synchronously and in
//! isolation, remembering nothing about it. Requests do run concurrently --
//! the runtime is multi-threaded and up to [`MAX_CONCURRENT_EXCHANGES`]
//! exchanges are in flight at once -- but no two share anything mutable, which
//! is what "remembers nothing" buys. A timeout, a duplicate request, a restart
//! or a lost response therefore leave no record, and recovery is a fresh
//! ceremony rather than a lookup here.
//!
//! It holds no signing key either. The notary signs; this bridge only carries
//! what the notary said.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::oauth::OAuthCredentials;

/// How many exchanges may be in flight at once.
///
/// Each one is a full MPC-TLS session and an outbound request that spends the
/// client secret. The origin check is not caller authentication -- it says so
/// itself -- so without a ceiling an anonymous caller decides how much of this
/// service, and of the OAuth app's standing with GitHub, to consume.
///
/// Here rather than in the route, beside the `Semaphore` it sizes: the number
/// and the thing it is the size of are one fact.
pub const MAX_CONCURRENT_EXCHANGES: usize = 8;

/// Everything the confidential exchange needs, and nothing any other route
/// does.
///
/// These four values are meaningful only where GitHub is enabled, and this is
/// the token route's own state -- so it is mounted with them or it is not
/// mounted. There is no deployment that holds a notary address nothing dials,
/// and no request that has to check whether the state and the router agree.
pub struct GithubExchange {
    /// GitHub's confidential client. The secret never leaves this process and
    /// is never revealed in a notarized transcript.
    pub(crate) credentials: OAuthCredentials,
    /// The notary this bridge opens its token session against, as the
    /// `host:port` a TCP connect takes.
    ///
    /// Resolved from the configured URL once at startup, so a notary URL that
    /// names no host or no port stops the process from coming up rather than
    /// failing the first ceremony that reaches it.
    pub(crate) notary_addr: String,
    /// The CCDP Distribution this bridge selects. The token route admits this
    /// origin and no other: the prover that calls it runs there.
    pub(crate) ccdp_origin: String,
    /// How many exchanges may run at once.
    ///
    /// This is the only thing standing between an anonymous caller and as many
    /// MPC-TLS sessions as it cares to start — the origin check is not caller
    /// authentication and says so. A request that finds no permit is shed,
    /// not queued.
    pub(crate) permits: Semaphore,
}

/// Configuration every route reads.
pub struct AppState {
    /// The configured path the providers redirect back to, where the callback
    /// shell answers.
    pub(crate) callback_path: String,
    /// The callback document, rendered once with its finished policy.
    pub(crate) callback_shell: crate::shell::RenderedShell,
    /// The application origins admitted to read the public configuration.
    ///
    /// Exact strings, canonicalised at startup the same way this bridge's own
    /// origin is, because the two are compared against what a browser sends.
    pub(crate) allowed_app_origins: Vec<String>,
    /// The public ceremony configuration, serialized once, as the exact bytes
    /// every admitted caller receives.
    ///
    /// One record for every request: it carries no secret and nothing a caller
    /// chose, so there is nothing to rebuild per request and nothing that
    /// could differ between two of them -- and nothing to re-serialize either.
    pub(crate) ceremony_config: bytes::Bytes,
    /// The confidential exchange, where the deployment enables GitHub.
    ///
    /// `None` means the token route is not mounted at all: a path that would
    /// answer without a secret is worse than one that is absent.
    pub(crate) github: Option<Arc<GithubExchange>>,
}

impl AppState {
    /// The exchange ceiling, for a caller that needs to observe it full.
    ///
    /// The one thing outside this crate has any business reading off the
    /// state. Everything else it holds is either a secret or a value only a
    /// handler in this crate decodes, and the fields say so.
    pub fn exchange_permits(&self) -> Option<&Semaphore> {
        self.github.as_ref().map(|g| &g.permits)
    }
}
