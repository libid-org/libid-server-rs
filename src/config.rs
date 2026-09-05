//! Configuration, parsed from CLI args / environment variables via `clap`.

use clap::Parser;
use url::Url;

/// Everything this bridge reads from its environment.
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
#[derive(Parser)]
#[command(name = "libid-server-rs", version, about)]
pub struct Config {
    /// Host to bind. Use 0.0.0.0 in containers.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind.
    #[arg(long, env = "PORT", default_value = "8722")]
    pub port: u16,

    /// Public base URL of THIS bridge, as a bare origin: scheme, host and, if
    /// it is not the default, port. A path, query, fragment or credentials are
    /// refused at startup, because this is the origin every registered
    /// `redirect_uri` is built on and a browser sends none of them.
    ///
    /// HTTPS, unless the host is loopback: the bridge origin is a code-supply
    /// boundary for the callback shell, and a plaintext one is no boundary.
    ///
    /// The registered OAuth callback URL is derived as
    /// `{BASE_URL}{CALLBACK_PATH}` and must match every provider's
    /// registration exactly.
    #[arg(long, env = "BASE_URL", default_value = "http://127.0.0.1:8722")]
    pub base_url: String,

    /// URL of the notary server (TCP), e.g. `tcp://notary.example:7047`.
    #[arg(long, env = "NOTARY_URL", default_value = "tcp://127.0.0.1:7047")]
    pub notary_url: Url,

    /// Comma-separated application origins admitted to read the public
    /// ceremony configuration. Nonempty, and deployment data: it is never
    /// inferred from a request's `Origin`, `Referer`, query or body.
    #[arg(long, env = "ALLOWED_APP_ORIGINS")]
    pub allowed_app_origins: String,

    /// The path the providers redirect back to, and the one route whose name
    /// a deployment chooses. There is no alias and no redirect: every enabled
    /// platform registers this exact URL.
    #[arg(long, env = "CALLBACK_PATH", default_value = "/auth/callback")]
    pub callback_path: String,

    /// The CCDP Distribution this bridge selects: one canonical HTTPS origin
    /// that serves the Callback module the shell imports and everything the
    /// browser runs after it. Published in the configuration and embedded in
    /// the shell. It names no artifact, circuit or notary.
    #[arg(long, env = "CCDP_ORIGIN")]
    pub ccdp_origin: String,

    /// The closed list of CCDP versions whose Callback the shell may import,
    /// comma-separated. A version the distribution does not serve is a
    /// ceremony that fails after clearing its return.
    #[arg(long, env = "CCDP_SUPPORTED_VERSIONS", default_value = "1")]
    pub ccdp_supported_versions: String,

    /// The package-published CSP hash of the Callback stylesheet, as
    /// `sha256-…`. Empty means `style-src 'none'`: a shell whose stylesheet
    /// cannot be named renders unstyled rather than admit any stylesheet.
    #[arg(long, env = "CALLBACK_STYLE_HASH", default_value = "")]
    pub callback_style_hash: String,

    /// The enabled platforms, as JSON. One record per platform, each with its
    /// public client id and its advertised ceremony versions:
    ///
    /// ```json
    /// [{"id":"github","clientId":"Iv1.…","versions":[1]}]
    /// ```
    ///
    /// One record, one projection here: the public configuration. The prover
    /// profiles live on the CCDP Distribution, which pins its own circuits; a
    /// bridge advertises only pairs that distribution serves. A separate
    /// `GH_OAUTH_CLIENT_ID` is gone — it was a second list of platforms, kept
    /// in step by hand.
    #[arg(long, env = "CEREMONY_PLATFORMS")]
    pub ceremony_platforms: String,

    /// GitHub OAuth App client secret. Required exactly when the platforms
    /// above enable `github`, and refused when they do not: it is the one
    /// value that must never reach the public configuration, so it has no
    /// business being set for a platform nobody can select.
    #[arg(long, env = "GH_OAUTH_CLIENT_SECRET", default_value = "")]
    pub gh_oauth_client_secret: String,
}

/// Written by hand, and without the secret.
///
/// `Debug` is the one thing that can take a client secret out of this process:
/// a `dbg!`, a `tracing::debug!(?cfg)`, or a panic formatting the struct would
/// put it in the log stream. `OAuthCredentials` derives only `Clone` for the
/// same reason.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("base_url", &self.base_url)
            .field("notary_url", &self.notary_url)
            .field("allowed_app_origins", &self.allowed_app_origins)
            .field("callback_path", &self.callback_path)
            .field("ccdp_origin", &self.ccdp_origin)
            .field("ccdp_supported_versions", &self.ccdp_supported_versions)
            .field("callback_style_hash", &self.callback_style_hash)
            .field("ceremony_platforms", &self.ceremony_platforms)
            .field("gh_oauth_client_secret", &"<redacted>")
            .finish()
    }
}
