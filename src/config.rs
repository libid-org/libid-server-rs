//! Configuration, parsed from CLI args / environment variables via `clap`.

use clap::Parser;
use url::Url;

/// Configuration for the handles backend server.
///
/// Every flag has an environment-variable form; the env names are the
/// deployment contract.
///
/// There is deliberately no signing key among them, and no
/// `BACKEND_SIGNING_KEY`: this service holds no key of its own. It used to
/// countersign every proof, which looked like a second trust root but never
/// was one — the backend IS that signer, so a compromised backend simply
/// signed whichever pairing it liked.
///
/// `NOTARY_ADDRESS`, `CHAIN_ID` and `VERIFIER_CONTRACT_ADDRESS` are gone with
/// it. They described a proof this service no longer verifies: the browser
/// checks the notary's attestation itself, and the Platform Verifier checks it
/// on chain. Nothing here reads a contract or a chain.
#[derive(Debug, Parser)]
#[command(name = "libid-server-rs", version, about)]
pub struct Config {
    /// Host to bind. Use 0.0.0.0 in containers.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind.
    #[arg(long, env = "PORT", default_value = "8722")]
    pub port: u16,

    /// Public base URL of THIS server, as a bare origin: scheme, host and, if
    /// it is not the default, port. A path, query, fragment or credentials are
    /// refused at startup, because the token route compares a request's
    /// `Origin` against this and a browser sends none of them.
    ///
    /// The GitHub OAuth callback URL is derived as
    /// `{BASE_URL}/api/v1/ceremony/callback` and must match the OAuth App
    /// registration exactly.
    #[arg(long, env = "BASE_URL", default_value = "http://127.0.0.1:8722")]
    pub base_url: String,

    /// Public URL of the web app. The Gmail fragment-relay callback bounces
    /// the popup to `{APP_URL}/auth/gmail/callback`. Empty disables the
    /// relay (it responds 500 with a pointed message).
    #[arg(long, env = "APP_URL", default_value = "")]
    pub app_url: String,

    /// Comma-separated CORS allow-list. Supports `*.suffix` and `prefix*`
    /// wildcards.
    #[arg(long, env = "ALLOWED_ORIGINS", default_value = "http://localhost:3000")]
    pub allowed_origins: String,

    /// URL of the notary server (TCP), e.g. `tcp://notary.example:7047`.
    #[arg(long, env = "NOTARY_URL", default_value = "tcp://127.0.0.1:7047")]
    pub notary_url: Url,

    /// GitHub OAuth App client ID (read-only app; no GitHub App needed).
    #[arg(long, env = "GH_OAUTH_CLIENT_ID")]
    pub gh_oauth_client_id: String,

    /// GitHub OAuth App client secret.
    #[arg(long, env = "GH_OAUTH_CLIENT_SECRET")]
    pub gh_oauth_client_secret: String,
}

impl Config {
    /// The comma-separated origins as a vector of patterns.
    pub fn allowed_origin_patterns(&self) -> Vec<String> {
        self.allowed_origins
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}
