//! Minimal identity/handles backend.
//!
//! Exactly the endpoints the OAuth handle-claim flow needs, and nothing
//! else: the UI does OAuth via this server, the server produces a
//! bind-ready proof via MPC-TLS with the notary, the UI submits the bind
//! on-chain itself. No database, no wallet routes, no sponsor pool, no
//! indexer, no JWKS rotator.

#![warn(missing_docs)]

pub mod config;
pub mod deployment;
pub mod error;
pub mod oauth;
pub mod routes;
pub mod shell;
pub mod state;

use std::sync::Arc;

use error::{
    Error,
    Result,
};
use state::AppState;
use tokio::sync::Semaphore;
use url::Url;

/// Build the shared [`AppState`] from parsed configuration.
///
/// Everything that must be well-formed for a request to succeed is parsed
/// here, so a typo fails at startup rather than on someone's ceremony.
///
/// It holds no key material beyond GitHub's client secret, and signs nothing:
/// the notary signs, and this service carries what it said.
pub fn build_state(cfg: &config::Config) -> Result<Arc<AppState>> {
    if cfg.base_url.is_empty() {
        return Err(Error::Config {
            detail: "BASE_URL must be set \u{2014} it is this service's own origin, \
                     which the GitHub token route checks callers against"
                .into(),
        });
    }
    let server_origin = server_origin(&cfg.base_url)?;

    let callback_path = callback_path(&cfg.callback_path)?;
    // One string, three uses: the route the provider returns to, the bytes the
    // notarized token request sends, and the `redirectUri` the public
    // configuration publishes. Deriving all three from one place is what stops
    // them drifting into a `redirect_uri_mismatch` nobody can see.
    let redirect_uri = format!("{server_origin}{callback_path}");

    let allowed_app_origins = allowed_app_origins(&cfg.allowed_app_origins)?;
    let ccdp_origin = canonical_origin("CCDP_ORIGIN", &cfg.ccdp_origin)?;
    let ccdp_versions = ccdp_versions(&cfg.ccdp_supported_versions)?;
    let platforms = deployment::platforms(&cfg.ceremony_platforms)?;

    let github = platforms.iter().find(|p| p.is_github());
    if github.is_some() == cfg.gh_oauth_client_secret.is_empty() {
        return Err(Error::Config {
            detail: if github.is_some() {
                "CEREMONY_PLATFORMS enables github, so GH_OAUTH_CLIENT_SECRET \
                 must be set: the exchange is confidential or it is nothing"
            } else {
                "GH_OAUTH_CLIENT_SECRET is set but CEREMONY_PLATFORMS enables \
                 no github, so nothing can ever spend it"
            }
            .into(),
        });
    }

    Ok(Arc::new(AppState {
        github_oauth: github.map(|p| oauth::OAuthCredentials {
            client_id: p.client_id.clone(),
            client_secret: cfg.gh_oauth_client_secret.clone(),
            redirect_uri: redirect_uri.clone(),
        }),
        ceremony_config: routes::config::frozen(&redirect_uri, &ccdp_origin, &platforms)?,
        callback_shell: shell::callback(&shell::ShellInputs {
            ccdp_origin: &ccdp_origin,
            supported_versions: &ccdp_versions,
            allowed_app_origins: &allowed_app_origins,
            style_hash: &cfg.callback_style_hash,
        })?,
        allowed_app_origins,
        ccdp_origin,
        notary_addr: notary_addr(&cfg.notary_url)?,
        exchange_permits: Arc::new(Semaphore::new(
            routes::github_token::MAX_CONCURRENT_EXCHANGES,
        )),
        server_origin,
        callback_path,
    }))
}

/// The closed list of CCDP versions the shell may select.
fn ccdp_versions(list: &str) -> Result<Vec<u16>> {
    let mut out = Vec::new();
    for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let v: u16 = item.parse().map_err(|_| Error::Config {
            detail: format!("CCDP_SUPPORTED_VERSIONS: {item:?} is not a CCDP version"),
        })?;
        if out.contains(&v) {
            return Err(Error::Config {
                detail: format!("CCDP_SUPPORTED_VERSIONS names {v} more than once"),
            });
        }
        out.push(v);
    }
    if out.is_empty() {
        return Err(Error::Config {
            detail: "CCDP_SUPPORTED_VERSIONS is empty, so the shell could import \
                     no Callback at all"
                .into(),
        });
    }
    Ok(out)
}

/// The application origins admitted to read the configuration.
fn allowed_app_origins(list: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for (i, spelling) in list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        let origin = canonical_origin(&format!("ALLOWED_APP_ORIGINS[{i}]"), spelling)?;
        // A duplicate is refused, not folded: the contract says a duplicate
        // member is a deployment error rather than something the bridge
        // normalizes, and a list written twice is a list nobody is reading.
        if out.contains(&origin) {
            return Err(Error::Config {
                detail: format!("ALLOWED_APP_ORIGINS names {origin} more than once"),
            });
        }
        out.push(origin);
    }
    if out.is_empty() {
        return Err(Error::Config {
            detail: "ALLOWED_APP_ORIGINS is empty, so no application could \
                     read the ceremony configuration"
                .into(),
        });
    }
    Ok(out)
}

/// The origin this service answers on, exactly as a browser spells it.
///
/// The token route compares a request's `Origin` against this string, so
/// anything a browser would not send refuses every legitimate call -- at
/// runtime, on someone's ceremony, which is what parsing it here prevents.
/// `Url::origin` does the spelling: it lowercases the host and drops a default
/// port, both of which browsers do too.
///
/// A base URL carrying a path is refused rather than trimmed. The router mounts
/// at the root, so a path would say this service lives somewhere it does not
/// serve, and the redirect URI derived from it would be one GitHub never sees.
fn server_origin(base_url: &str) -> Result<String> {
    canonical_origin("BASE_URL", base_url)
}

/// The same reading for every origin-shaped input: this service's own, and
/// each application origin admitted to read the configuration. One function so
/// the two cannot be spelled by different rules and then compared.
fn canonical_origin(field: &str, spelling: &str) -> Result<String> {
    let url = Url::parse(spelling).map_err(|e| Error::Config {
        detail: format!("{field} {spelling}: {e}"),
    })?;
    let refuse = |why: &str| Error::Config {
        detail: format!(
            "{field} {spelling} {why}; it must be a bare origin, \
             as in https://id.example.com"
        ),
    };
    if !matches!(url.scheme(), "http" | "https") {
        return Err(refuse("is not http or https"));
    }
    if url.host().is_none() {
        return Err(refuse("names no host"));
    }
    if !matches!(url.path(), "" | "/") {
        return Err(refuse("carries a path"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(refuse("carries a query or fragment"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refuse("carries credentials"));
    }
    // Every origin the bridge trusts or publishes is a code-supply boundary,
    // and a plaintext one is no boundary. Loopback is the stated exception,
    // for development against a local server.
    if url.scheme() == "http" && !is_loopback(&url) {
        return Err(refuse("is plaintext http on a host that is not loopback"));
    }
    Ok(url.origin().ascii_serialization())
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// The path the providers redirect back to, and the only configurable route.
///
/// A spelling axum reads as a pattern -- anything with braces in it -- would
/// quietly turn one document into a wildcard. A path colliding with a fixed
/// route is worse: `Router::route` panics, and a deployment learns that by not
/// starting, with no line saying which setting did it.
fn callback_path(path: &str) -> Result<String> {
    let refuse = |why: &str| Error::Config {
        detail: format!("CALLBACK_PATH {path} {why}"),
    };
    if !path.starts_with('/') {
        return Err(refuse("does not begin with `/`"));
    }
    if path.contains(['{', '}']) {
        return Err(refuse(
            "contains a brace, which axum reads as a path pattern",
        ));
    }
    if path.contains(['?', '#'])
        || path.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(refuse(
            "carries a query, fragment, whitespace or control byte",
        ));
    }
    if routes::FIXED_PATHS.contains(&path) {
        return Err(refuse("collides with a route this service already serves"));
    }
    Ok(path.to_owned())
}

/// The `host:port` of the notary, taken from its configured URL.
///
/// The scheme is not consulted: the Rust prover speaks the notary's raw TCP
/// protocol, and `tcp://` is how the default spells that. What must be there
/// is an authority, because a session cannot be opened without one.
fn notary_addr(url: &Url) -> Result<String> {
    let host = url.host_str().ok_or_else(|| Error::NotaryUrl {
        detail: format!("{url} names no host"),
    })?;
    let port = url.port().ok_or_else(|| Error::NotaryUrl {
        detail: format!("{url} names no port"),
    })?;
    Ok(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(args: &[&str]) -> config::Config {
        let mut argv = vec![
            "libid-server-rs",
            "--allowed-app-origins",
            "https://app.example",
            "--ccdp-origin",
            "https://ccdp.example",
            "--ceremony-platforms",
            r#"[{"id":"github","clientId":"Iv1.0123456789abcdef","versions":[1]}]"#,
            "--gh-oauth-client-secret",
            "ghs_secret",
        ];
        argv.extend_from_slice(args);
        <config::Config as clap::Parser>::parse_from(argv)
    }

    /// The redirect URI is derived, not configured, and a provider refuses an
    /// exchange whose two spellings differ. So it has to be exactly the
    /// configured callback alias under the configured base URL — the same
    /// string the public configuration publishes and the alias route mounts.
    #[test]
    fn the_redirect_uri_is_the_callback_route_under_the_base_url() {
        let state = build_state(&config(&["--base-url", "https://id.example/"])).unwrap();
        assert_eq!(state.server_origin, "https://id.example");
        assert_eq!(
            state.github_oauth.as_ref().unwrap().redirect_uri,
            "https://id.example/auth/callback"
        );
    }

    /// The notary address is resolved once here rather than per ceremony.
    #[test]
    fn the_state_carries_a_connectable_notary_address() {
        let state = build_state(&config(&[])).unwrap();
        assert_eq!(state.notary_addr, "127.0.0.1:7047");
        assert!(build_state(&config(&["--notary-url", "tcp://notary.example"])).is_err());
    }

    /// Whatever the operator writes, the route compares against what a browser
    /// sends -- so the two spellings a browser normalises away are normalised
    /// here rather than becoming a 403 on every call.
    #[test]
    fn a_base_url_is_reduced_to_the_origin_a_browser_would_send() {
        for spelling in [
            "https://id.example.com",
            "https://id.example.com/",
            "https://ID.Example.com",
            "https://id.example.com:443",
        ] {
            assert_eq!(
                server_origin(spelling).unwrap(),
                "https://id.example.com",
                "{spelling}"
            );
        }
        // A non-default port is part of the origin and stays.
        assert_eq!(
            server_origin("http://127.0.0.1:8722").unwrap(),
            "http://127.0.0.1:8722"
        );
    }

    /// Anything a browser never sends as `Origin` is refused at startup. Left
    /// alone, each of these starts cleanly and then refuses every ceremony,
    /// which is the failure this whole function exists to move earlier.
    #[test]
    fn a_base_url_that_is_not_a_bare_origin_stops_the_process() {
        for spelling in [
            "https://id.example.com/ceremony",
            "https://id.example.com?tenant=1",
            "https://id.example.com#frag",
            "https://user:pw@id.example.com",
            "ftp://id.example.com",
            "not a url",
        ] {
            assert!(
                server_origin(spelling).is_err(),
                "{spelling} must be refused"
            );
        }
    }

    /// And the redirect URI GitHub has registered is built on the normalised
    /// form, not on what was typed.
    #[test]
    fn the_redirect_uri_is_built_on_the_normalised_origin() {
        let state =
            build_state(&config(&["--base-url", "https://ID.example.com:443/"])).unwrap();
        assert_eq!(
            state.github_oauth.as_ref().unwrap().redirect_uri,
            "https://id.example.com/auth/callback"
        );
    }

    /// The default spelling, and the one the deployment uses.
    #[test]
    fn a_tcp_notary_url_yields_its_authority() {
        let url = Url::parse("tcp://127.0.0.1:7047").unwrap();
        assert_eq!(notary_addr(&url).unwrap(), "127.0.0.1:7047");
    }

    /// The prover speaks the notary's raw TCP protocol, so there is no port to
    /// infer from a scheme. A URL missing either half is refused at startup
    /// rather than on the first ceremony that reaches it.
    #[test]
    fn a_notary_url_missing_an_authority_is_refused() {
        for spelling in ["tcp://notary.example", "tcp:7047", "file:///notary"] {
            let url = Url::parse(spelling).unwrap();
            assert!(notary_addr(&url).is_err(), "{spelling} names no host:port");
        }
    }
}
