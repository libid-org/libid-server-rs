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
/// does. Present exactly when GitHub is enabled: the token route is mounted
/// with it or not mounted.
pub struct GithubExchange {
    /// GitHub's confidential client. The secret never leaves this process and
    /// is never revealed in a notarized transcript.
    pub(crate) credentials: OAuthCredentials,
    /// The path providers redirect back to. A request's `redirectUri` is the
    /// bridge's origin followed by exactly this.
    pub(crate) callback_path: String,
    /// Dials the notary each token request names, on the wire port; refuses
    /// private and internal addresses.
    pub(crate) egress: crate::routes::github_token::NotaryEgress,
    /// The CCDP Distribution this bridge selects, and the ONLY origin the
    /// token route admits.
    ///
    /// Deliberately narrower than the effective set the configuration route
    /// uses. The caller here is the Prover, which runs on this origin and
    /// nowhere else, so admitting an application origin would widen the one
    /// route that spends the client secret for no caller that exists. It is
    /// not caller authentication either way -- a request with no browser
    /// behind it carries whatever `Origin` it likes -- so this is the browser
    /// boundary only, and the egress policy is what stands behind it.
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
    /// callback document answers.
    pub(crate) callback_path: String,
    /// The callback document and the policy it is served under, composed once
    /// at startup from the configured artifact.
    ///
    /// Held by value rather than behind a shared cell because nothing replaces
    /// it yet. When the bridge grows a refresh loop this becomes a
    /// `watch::Receiver`, and the handler's `.clone()` of two cheap fields
    /// becomes a `borrow().clone()` -- the route does not otherwise change.
    pub(crate) callback: crate::artifact::CallbackDocument,
    /// The effective admission set: `allowedAppOrigins ∪ {ccdpOrigin}`.
    ///
    /// Read by the configuration route and inserted into the callback
    /// document. The token route does NOT use it -- it admits `ccdpOrigin`
    /// alone.
    ///
    /// One set, derived once, governing the configuration route, the token
    /// route and what the callback document is told -- the contract makes it
    /// one rule, and three copies of one rule is three things to keep in step.
    ///
    /// Exact strings, canonicalised at startup the same way this bridge's own
    /// origin is, because they are compared against what a browser sends.
    pub(crate) allowed_origins: Arc<[String]>,
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
