//! The OAuth Bridge of a libID ceremony.
//!
//! Three contract routes and a liveness probe, and the contract is
//! `OAUTH_BRIDGE.md` in the libid repository. It publishes the configuration
//! an application starts from, serves the one callback document the OAuth
//! platforms redirect back to, and performs the one exchange a browser cannot:
//! GitHub's, which needs a client secret. `/health` is the fourth, outside the
//! contract's closed surface and kept for the container healthcheck.
//!
//! Everything the browser executes after that callback -- the Callback module
//! it imports, Airlock, the prover, its circuits and notarization client -- is
//! served by a separate CCDP Distribution at a configured origin. This service
//! verifies no proof, holds no key of its own, keeps no ceremony state, and
//! talks to no chain.

#![warn(missing_docs)]

pub mod config;
pub(crate) mod deployment;
pub mod error;
pub(crate) mod oauth;
pub mod routes;
pub(crate) mod shell;
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
            detail: "BASE_URL must be set \u{2014} it is this bridge's own origin, \
                     which every registered redirect URI is built on"
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
    let style_hash = style_hash(&cfg.callback_style_hash)?;
    let platforms = deployment::platforms(&cfg.ceremony_platforms)?;
    // A constant that either always parses or never does, parsed here so a
    // build in which it does not fails at startup rather than on the first
    // ceremony that reaches it.
    routes::github_token::force_token_endpoint();

    // One decision on the pair, and each arm is a whole answer: the exchange
    // this deployment can perform, the deployment that performs none, or the
    // two ways of naming half of one.
    let github = match (
        platforms.iter().find(|p| p.is_github()),
        cfg.gh_oauth_client_secret.as_str(),
    ) {
        (Some(profile), secret) if !secret.is_empty() => {
            Some(Arc::new(state::GithubExchange {
                credentials: oauth::OAuthCredentials {
                    client_id: profile.client_id.clone(),
                    client_secret: secret.to_owned(),
                    redirect_uri: redirect_uri.clone(),
                },
                notary_addr: notary_addr(&cfg.notary_url)?,
                ccdp_origin: ccdp_origin.clone(),
                permits: Semaphore::new(state::MAX_CONCURRENT_EXCHANGES),
            }))
        }
        (None, "") => None,
        (Some(_), _) => {
            return Err(Error::Config {
                detail: "CEREMONY_PLATFORMS enables github, so GH_OAUTH_CLIENT_SECRET \
                         must be set: the exchange is confidential or it is nothing"
                    .into(),
            })
        }
        (None, _) => {
            return Err(Error::Config {
                detail: "GH_OAUTH_CLIENT_SECRET is set but CEREMONY_PLATFORMS enables \
                         no github, so nothing can ever spend it"
                    .into(),
            })
        }
    };

    Ok(Arc::new(AppState {
        ceremony_config: deployment::config_record(
            &redirect_uri,
            &ccdp_origin,
            &platforms,
        ),
        callback_shell: shell::callback(&shell::ShellInputs {
            ccdp_origin: &ccdp_origin,
            supported_versions: &ccdp_versions,
            allowed_app_origins: &allowed_app_origins,
            style_hash,
        })?,
        allowed_app_origins,
        callback_path,
        github,
    }))
}

/// The package-published CSP hash of the shell's stylesheet.
///
/// Spliced into a `Content-Security-Policy`, where `;` starts a new directive
/// and the FIRST occurrence of a directive wins. An unchecked value carrying
/// one does not merely break the policy -- it prepends its own `connect-src`
/// and `frame-src` ahead of the intended ones, which are then ignored, and the
/// shell can send the OAuth return anywhere. So the shape is exact: a hash
/// algorithm the CSP grammar names, and base64 after it.
fn style_hash(hash: &str) -> Result<&str> {
    if hash.is_empty() {
        return Ok(hash);
    }
    let refuse = || Error::Config {
        detail: format!(
            "CALLBACK_STYLE_HASH {hash} is not a CSP hash source; it must be \
             sha256-, sha384- or sha512- followed by base64"
        ),
    };
    let b64 = ["sha256-", "sha384-", "sha512-"]
        .iter()
        .find_map(|p| hash.strip_prefix(p))
        .ok_or_else(refuse)?;
    if b64.is_empty()
        || !b64
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    {
        return Err(refuse());
    }
    Ok(hash)
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
        let field = format!("ALLOWED_APP_ORIGINS[{i}]");
        let origin = canonical_origin(&field, spelling)?;
        // "A duplicate or invalid member is a deployment error rather than
        // something the bridge normalizes", says the contract of this list
        // specifically. So a member that is not already canonical is refused
        // here, where an operator can see which one and what it should say,
        // rather than quietly admitted under a spelling they did not write.
        if origin != spelling {
            return Err(Error::Config {
                detail: format!(
                    "{field} {spelling} is not canonical; write it as {origin}"
                ),
            });
        }
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

/// The origin this bridge answers on, exactly as a browser spells it.
///
/// Every platform registers a `redirect_uri` built on this string, and a
/// provider refuses an exchange whose two spellings differ -- at runtime, on
/// someone's ceremony, which is what parsing it here prevents.
/// `Url::origin` does the spelling: it lowercases the host and drops a default
/// port, both of which browsers do too.
///
/// A base URL carrying a path is refused rather than trimmed. The router mounts
/// at the root, so a path would say this service lives somewhere it does not
/// serve, and the redirect URI derived from it would be one GitHub never sees.
fn server_origin(base_url: &str) -> Result<String> {
    canonical_origin("BASE_URL", base_url)
}

/// The same reading for every origin this deployment configures: this
/// service's own, the CCDP Distribution it selects, and each application
/// origin admitted to read the configuration. One function, because these
/// strings are compared against each other and against what a browser sends,
/// and two spellings of the same rule are two rules.
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
    // `Url` admits bytes in a host that no browser would ever send and that a
    // Content-Security-Policy reads as syntax: `;` there starts a new
    // directive, and CSP honours the FIRST occurrence of each. The CCDP origin
    // is spliced unescaped into `script-src` and `frame-src`, so
    // `https://a;b.example` silently truncates the module source and the shell
    // imports nothing. Closed to what an origin is actually made of, which is
    // the same shape `CALLBACK_STYLE_HASH` is held to and for the same reason.
    let origin = url.origin().ascii_serialization();
    if !origin
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-.:[]/".contains(&b))
    {
        return Err(refuse(
            "carries a byte an origin is not made of, which a \
             Content-Security-Policy would read as syntax",
        ));
    }
    Ok(origin)
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
    // `//x.example/cb` is a valid route to axum and a SCHEME-RELATIVE URL to a
    // browser: `history.replaceState(null, '', location.pathname)` then
    // resolves it cross-origin and throws, so the bootstrap dies before it
    // clears -- the authorization code stays in the address bar and in
    // history, nothing renders, and no server-side symptom exists at all.
    if path.starts_with("//") {
        return Err(refuse(
            "begins with `//`, which a browser reads as scheme-relative, so \
             the shell could not clear the return out of its own URL",
        ));
    }
    // Three spellings of the same mistake, and axum rejects all three at
    // `Router::route` -- with a panic naming neither the setting nor the path.
    // Braces are its current syntax; a segment opening with `:` or `*` is the
    // syntax it carried before, still refused rather than routed.
    if path.contains(['{', '}'])
        || path
            .split('/')
            .any(|seg| seg.starts_with(':') || seg.starts_with('*'))
    {
        return Err(refuse(
            "contains a brace, or a segment beginning with `:` or `*`, which \
             axum reads as a path pattern",
        ));
    }
    if path.contains(['?', '#'])
        || path.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(refuse(
            "carries a query, fragment, whitespace or control byte",
        ));
    }
    // A byte a browser percent-encodes is a byte axum never sees: it matches on
    // the raw path, so `/auth/cällback` registers one route and receives
    // requests for another. The service would start and refuse every ceremony.
    if !path.is_ascii() || path.chars().any(|c| "%\"<>\\^`|".contains(c)) {
        return Err(refuse(
            "carries a byte a browser would percent-encode, so the route it \
             registers is not the one requests arrive at",
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

    /// A deployment that starts, with `args` replacing any default it names.
    ///
    /// Overriding rather than appending, because clap refuses a flag given
    /// twice -- so a test that means "this one value differs" must not also
    /// leave the default behind.
    fn config(args: &[&str]) -> config::Config {
        let mut flags: Vec<(&str, &str)> = vec![
            ("--allowed-app-origins", "https://app.example"),
            ("--ccdp-origin", "https://ccdp.example"),
            (
                "--ceremony-platforms",
                r#"[{"id":"github","clientId":"Iv1.0123456789abcdef","versions":[1]}]"#,
            ),
            ("--gh-oauth-client-secret", "ghs_secret"),
        ];
        for pair in args.chunks(2) {
            let [flag, value] = pair else {
                panic!("test flags come in pairs, got {pair:?}")
            };
            match flags.iter_mut().find(|(f, _)| f == flag) {
                Some(slot) => slot.1 = value,
                None => flags.push((flag, value)),
            }
        }
        let mut argv = vec!["libid-server-rs"];
        for (flag, value) in &flags {
            argv.push(flag);
            argv.push(value);
        }
        <config::Config as clap::Parser>::parse_from(argv)
    }

    /// The redirect URI is derived, not configured, and a provider refuses an
    /// exchange whose two spellings differ. So it has to be exactly the
    /// configured callback path under the configured base URL — the same
    /// string the public configuration publishes and the router mounts.
    #[test]
    fn the_redirect_uri_is_the_callback_route_under_the_base_url() {
        let state = build_state(&config(&["--base-url", "https://id.example/"])).unwrap();
        assert_eq!(
            state.github.as_ref().unwrap().credentials.redirect_uri,
            "https://id.example/auth/callback"
        );
    }

    /// The notary address is resolved once at startup rather than per
    /// ceremony, so a URL that names no host or no port stops the process
    /// instead of failing the first exchange that dials it.
    #[test]
    fn a_notary_url_is_resolved_to_a_dialable_address_at_startup() {
        let state = build_state(&config(&[])).unwrap();
        assert_eq!(state.github.as_ref().unwrap().notary_addr, "127.0.0.1:7047");
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

    /// The plaintext exception is loopback and only loopback, in each of the
    /// three spellings a host can take. A deployment reaching a development
    /// server over `http` is why the exception exists; one reaching anything
    /// else over `http` has an unauthenticated code-supply boundary.
    #[test]
    fn plaintext_is_admitted_for_loopback_and_refused_everywhere_else() {
        for spelling in [
            "http://127.0.0.1:8722",
            "http://[::1]:8722",
            "http://localhost:3000",
        ] {
            assert!(canonical_origin("T", spelling).is_ok(), "{spelling}");
        }
        for spelling in [
            "http://10.0.0.1",
            "http://192.168.1.1:8722",
            "http://app.example",
        ] {
            assert!(canonical_origin("T", spelling).is_err(), "{spelling}");
        }
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
            state.github.as_ref().unwrap().credentials.redirect_uri,
            "https://id.example.com/auth/callback"
        );
    }

    /// Every one of these starts a process that then refuses real ceremonies,
    /// which is the whole reason these run at startup rather than per request.
    #[test]
    fn a_deployment_that_could_not_serve_a_ceremony_stops_the_process() {
        for (why, args) in [
            ("no admitted origin", vec!["--allowed-app-origins", ""]),
            (
                "a duplicate admitted origin",
                vec![
                    "--allowed-app-origins",
                    "https://app.example,https://app.example",
                ],
            ),
            (
                "a plaintext admitted origin that is not loopback",
                vec!["--allowed-app-origins", "http://app.example"],
            ),
            ("no CCDP version", vec!["--ccdp-supported-versions", ""]),
            (
                "a duplicate CCDP version",
                vec!["--ccdp-supported-versions", "1,1"],
            ),
            (
                "a CCDP version that is not one",
                vec!["--ccdp-supported-versions", "one"],
            ),
            (
                "a relative callback path",
                vec!["--callback-path", "auth/callback"],
            ),
            (
                "a callback path axum reads as a brace pattern",
                vec!["--callback-path", "/auth/{rest}"],
            ),
            // axum panics on both of these at `Router::route`, after
            // `build_state` has already returned -- so the deployment learns
            // by not starting, with nothing saying which setting did it.
            (
                "a callback path with a colon segment",
                vec!["--callback-path", "/auth/:cb"],
            ),
            (
                "a callback path with a star segment",
                vec!["--callback-path", "/auth/*rest"],
            ),
            (
                "a callback path a browser would percent-encode",
                vec!["--callback-path", "/auth/c\u{e4}llback"],
            ),
            (
                "a callback path colliding with a fixed route",
                vec!["--callback-path", "/api/v1/ceremony/config"],
            ),
            // Routed by axum, read as scheme-relative by a browser: the
            // bootstrap's `history.replaceState` throws cross-origin before it
            // clears, so the authorization code stays in the address bar and
            // nothing on this side ever hears about it.
            (
                "a scheme-relative callback path",
                vec!["--callback-path", "//evil.example/cb"],
            ),
            (
                "a stylesheet hash of no named algorithm",
                vec!["--callback-style-hash", "abc123"],
            ),
            // Two ways to forge a CSP directive out of this one setting, and
            // two different guards catch them: no named algorithm at all, and
            // a named algorithm followed by bytes that are not base64. The
            // second is the one a `sha256-` prefix would otherwise wave past.
            (
                "a stylesheet hash whose prefix is right and whose body is not base64",
                vec!["--callback-style-hash", "sha256-abc'; connect-src *"],
            ),
            (
                "a stylesheet hash of a named algorithm and nothing else",
                vec!["--callback-style-hash", "sha256-"],
            ),
            // `Url` keeps these in a host; a Content-Security-Policy reads the
            // first as a directive separator. Every configured origin is held
            // to the same shape, because all three reach a policy or a
            // comparison with what a browser sent.
            (
                "a base URL whose host carries a CSP directive separator",
                vec!["--base-url", "https://a;b.example"],
            ),
            (
                "a CCDP origin whose host carries a CSP directive separator",
                vec!["--ccdp-origin", "https://a;b.example"],
            ),
            (
                "an admitted origin whose host carries a CSP keyword quote",
                vec!["--allowed-app-origins", "https://a'b.example"],
            ),
            // The contract singles this list out: "a duplicate or invalid
            // member is a deployment error rather than something the bridge
            // normalizes". So each of these is refused with the canonical
            // spelling named, where `BASE_URL` would be folded.
            (
                "an admitted origin carrying a trailing slash",
                vec!["--allowed-app-origins", "https://app.example/"],
            ),
            (
                "an admitted origin spelled with an uppercase host",
                vec!["--allowed-app-origins", "https://APP.example"],
            ),
            (
                "an admitted origin carrying a default port",
                vec!["--allowed-app-origins", "https://app.example:443"],
            ),
        ] {
            assert!(
                build_state(&config(&args)).is_err(),
                "{why} must stop the process"
            );
        }
    }

    /// The whole catalog, in the configuration an application reads. Every
    /// platform is keyed by the name it is selected by, and the record carries
    /// the public client id and versions and nothing else.
    #[test]
    fn the_published_configuration_keys_every_enabled_platform_by_name() {
        let state = build_state(&config(&[
            "--ceremony-platforms",
            r#"[{"id":"google","clientId":"g","versions":[1,2]},{"id":"x","clientId":"xc","versions":[3]},{"id":"github","clientId":"gh","versions":[1]}]"#,
        ]))
        .unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(&state.ceremony_config).unwrap();
        let platforms = record["platforms"].as_object().unwrap();
        let mut names: Vec<&str> = platforms.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["github", "google", "x"]);
        assert_eq!(
            platforms["google"]["ceremonyVersions"],
            serde_json::json!([1, 2])
        );
        assert_eq!(platforms["x"]["clientId"], "xc");
        // The secret is the one thing the public record must never carry.
        assert!(!String::from_utf8_lossy(&state.ceremony_config).contains("ghs_secret"));
    }

    /// The secret and the platform that spends it travel together, or neither
    /// is any use: a route mounted with no secret answers where it should not
    /// exist, and a secret nothing can spend is a target with no purpose.
    #[test]
    fn the_github_secret_and_the_github_platform_require_each_other() {
        let no_secret = vec!["--gh-oauth-client-secret", ""];
        assert!(build_state(&config(&no_secret)).is_err());

        let x_only = vec![
            "--ceremony-platforms",
            r#"[{"id":"x","clientId":"abc","versions":[1]}]"#,
        ];
        assert!(
            build_state(&config(&x_only)).is_err(),
            "a secret with no github platform must stop the process"
        );

        let neither = vec![
            "--ceremony-platforms",
            r#"[{"id":"x","clientId":"abc","versions":[1]}]"#,
            "--gh-oauth-client-secret",
            "",
        ];
        let state = build_state(&config(&neither)).unwrap();
        assert!(state.github.is_none());
    }

    /// Every path this router mounts, actually mounted -- for the deployment
    /// that carries the token route and the one that does not.
    ///
    /// It does NOT exercise a collision: `callback_path` refuses one before
    /// `build_router` is reached, and that refusal is covered in the startup
    /// table above. What this catches is a path `build_router` mounts that
    /// `FIXED_PATHS` does not name, which `Router::route` answers with a panic
    /// the moment a deployment configures the callback there.
    #[test]
    fn building_the_router_for_a_configured_deployment_does_not_panic() {
        let state = build_state(&config(&[])).unwrap();
        let _: axum::Router = routes::build_router(state);

        let x_only = build_state(&config(&[
            "--ceremony-platforms",
            r#"[{"id":"x","clientId":"abc","versions":[1]}]"#,
            "--gh-oauth-client-secret",
            "",
        ]))
        .unwrap();
        let _: axum::Router = routes::build_router(x_only);
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
