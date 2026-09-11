//! The OAuth Bridge of a libID ceremony. The contract is `OAUTH_BRIDGE.md` in
//! the libid repository.
//!
//! It publishes the configuration an application starts from, serves the one
//! callback document the OAuth platforms redirect back to, and performs the
//! one exchange a browser cannot: GitHub's, which needs a client secret.
//! `/health` is a liveness probe for the container healthcheck.
//!
//! The callback document is the CCDP Distribution's artifact with this
//! deployment's data inserted into its one slot; everything the browser runs
//! after the callback is served by that Distribution. This service verifies
//! no proof, holds no key of its own, keeps no ceremony state, and talks to
//! no chain.

#![warn(missing_docs)]

pub(crate) mod artifact;
pub mod config;
pub(crate) mod deployment;
pub mod error;
#[cfg(any(test, feature = "fixtures"))]
#[doc(hidden)]
pub mod fixtures;
pub(crate) mod oauth;
pub mod routes;
pub mod state;

use std::sync::Arc;

use error::{
    Error,
    Result,
};
use state::AppState;
use tokio::sync::Semaphore;
use url::Url;

/// Build the shared [`AppState`] from the configuration. Everything that must
/// be well-formed for a request to succeed is checked here, at startup, and
/// the callback artifact is retrieved from the Distribution before this
/// returns; it returns `Err` when it cannot.
pub async fn build_state(cfg: &config::Config) -> Result<Arc<AppState>> {
    let callback_path = callback_path(&cfg.callback_path)?;

    let allowed_app_origins = allowed_app_origins(&cfg.allowed_app_origins)?;
    let ccdp_origin = canonical_origin("CCDP_ORIGIN", &cfg.ccdp_origin)?;
    // The effective set `allowedAppOrigins ∪ {ccdpOrigin}`, for the
    // configuration route and the callback document. The resolved CCDP
    // origin joins once; an overridden `CCDP_ORIGIN` does not keep
    // `https://lib.id` admitted unless it is listed.
    let allowed_origins: Arc<[String]> = {
        let mut set = allowed_app_origins.clone();
        if !set.contains(&ccdp_origin) {
            set.push(ccdp_origin.clone());
        }
        set.into()
    };
    let platforms = deployment::platforms(cfg.platforms.clone())?;
    routes::github_token::force_token_endpoint();

    // The exchange is present exactly when a github platform and a secret are
    // both set; one without the other refuses to start.
    let github = match (
        platforms.iter().find(|p| p.is_github()),
        cfg.gh_oauth_client_secret.as_str(),
    ) {
        (Some(profile), secret) if !secret.is_empty() => {
            Some(Arc::new(state::GithubExchange {
                credentials: oauth::OAuthCredentials {
                    client_id: profile.client_id.clone(),
                    client_secret: secret.to_owned(),
                },
                callback_path: callback_path.clone(),
                egress: routes::github_token::NotaryEgress::new(cfg.notary_wire_port),
                ccdp_origin: axum::http::HeaderValue::from_str(&ccdp_origin).map_err(
                    |e| Error::Config {
                        detail: format!("CCDP_ORIGIN {ccdp_origin}: {e}"),
                    },
                )?,
                permits: Semaphore::new(state::MAX_CONCURRENT_EXCHANGES),
            }))
        }
        (None, "") => None,
        (Some(_), _) => {
            return Err(Error::Config {
                detail: "the platforms enable github, so GH_OAUTH_CLIENT_SECRET must \
                         be set"
                    .into(),
            })
        }
        (None, _) => {
            return Err(Error::Config {
                detail: "GH_OAUTH_CLIENT_SECRET is set but no platform enables github"
                    .into(),
            })
        }
    };

    let upstream = artifact::upstream::Upstream::new(&ccdp_origin)?;
    let published = artifact::Published::retrieved(&upstream, &allowed_origins).await?;
    let (callback_tx, callback) = tokio::sync::watch::channel(Arc::new(published));

    Ok(Arc::new(AppState {
        ceremony_config: deployment::CeremonyConfig {
            callback_path: &callback_path,
            ccdp_origin: &ccdp_origin,
            platforms: &platforms,
        }
        .serialized(),
        callback,
        callback_tx,
        upstream,
        allowed_origins,
        callback_path,
        github,
    }))
}

/// Serve `state` on `listener` until `shutdown` resolves; in-flight requests
/// finish first. The callback artifact is revalidated for as long as this
/// runs.
pub async fn serve(
    state: Arc<AppState>,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = routes::build_router(state.clone());
    let refreshing = tokio::spawn(refresh_callback(state));
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await;
    refreshing.abort();
    served
}

/// Revalidate the callback artifact for as long as the process runs; it
/// returns only when the process ends.
pub async fn refresh_callback(state: Arc<AppState>) {
    artifact::upstream::refresh(state, artifact::upstream::Schedule::DEPLOYED).await
}

/// The application origins admitted to read the configuration.
fn allowed_app_origins(list: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for (i, spelling) in list
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        let field = format!("ALLOWED_APP_ORIGINS[{i}]");
        let origin = canonical_origin(&field, spelling)?;
        // A member that is not already canonical is refused with the canonical
        // spelling named, not folded.
        if origin != spelling {
            return Err(Error::Config {
                detail: format!(
                    "{field} {spelling} is not canonical; write it as {origin}"
                ),
            });
        }
        // A duplicate is refused, not folded.
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

/// The canonical form of a configured origin: `http` or `https`, a host, no
/// path, query, fragment or credentials; plaintext only on `localhost` or
/// `127.0.0.1`; a host made only of the bytes an origin is made of.
/// `Url::origin` lowercases the host and drops a default port.
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
    if url.scheme() == "http" && !is_plaintext_loopback(&url) {
        return Err(refuse(
            "is plaintext http on a host that is not localhost or 127.0.0.1",
        ));
    }
    // `;`, quotes and other bytes a Content-Security-Policy reads as syntax
    // are refused: the CCDP origin is spliced into `script-src` and
    // `frame-src`.
    let origin = url.origin().ascii_serialization();
    if !origin
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.:[]/".contains(&b))
    {
        return Err(refuse(
            "carries a byte an origin is not made of, which a \
             Content-Security-Policy would read as syntax",
        ));
    }
    Ok(origin)
}

/// Whether `url` is plaintext `http` on exactly `localhost` or `127.0.0.1`:
/// the one case a canonical origin is not HTTPS.
pub(crate) fn is_plaintext_loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
}

/// The path the providers redirect back to: begins with `/` and not `//`; no
/// braces and no segment beginning with `:` or `*`; no query, fragment,
/// whitespace, control byte or byte a browser would percent-encode; and not a
/// fixed route.
fn callback_path(path: &str) -> Result<String> {
    let refuse = |why: &str| Error::Config {
        detail: format!("CALLBACK_PATH {path} {why}"),
    };
    if !path.starts_with('/') {
        return Err(refuse("does not begin with `/`"));
    }
    // A browser reads `//host/...` as scheme-relative.
    if path.starts_with("//") {
        return Err(refuse(
            "begins with `//`, which a browser reads as scheme-relative, so \
             the document could not clear the return out of its own URL",
        ));
    }
    // axum path-pattern syntax, current and former.
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
    // axum matches the raw path; a browser sends these percent-encoded.
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

#[cfg(test)]
mod tests {
    use super::{
        config::Config,
        fixtures::Distribution,
        *,
    };

    /// An omitted CCDP origin selects the canonical libID Distribution: the
    /// declared default is `https://lib.id`, and the configured value reaches
    /// the published record.
    #[tokio::test]
    async fn an_omitted_ccdp_origin_selects_the_canonical_distribution() {
        let command = <config::Config as clap::CommandFactory>::command();
        let arg = command
            .get_arguments()
            .find(|a| a.get_id() == "ccdp_origin")
            .expect("the ccdp origin is an argument");
        assert_eq!(arg.get_default_values(), ["https://lib.id"]);

        let state = build_state(&Config::fixture(&[])).await.unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(&state.ceremony_config).unwrap();
        assert_eq!(record["ccdpOrigin"], Distribution::shared().origin());
    }

    /// Plaintext `http` is admitted on exactly `localhost` and `127.0.0.1`,
    /// and refused everywhere else.
    #[test]
    fn plaintext_is_admitted_for_loopback_and_refused_everywhere_else() {
        for spelling in ["http://127.0.0.1:8722", "http://localhost:3000"] {
            assert!(canonical_origin("T", spelling).is_ok(), "{spelling}");
        }
        for spelling in [
            "http://[::1]:8722",
            "http://127.0.0.2:8722",
            "http://10.0.0.1",
            "http://192.168.1.1:8722",
            "http://app.example",
        ] {
            assert!(canonical_origin("T", spelling).is_err(), "{spelling}");
        }
    }

    /// The effective set is `allowedAppOrigins ∪ {ccdpOrigin}`: the resolved
    /// origin joins once, and an origin already listed is not added twice.
    #[tokio::test]
    async fn the_effective_admission_set_is_the_allowlist_plus_the_ccdp_origin() {
        async fn origins(args: &[&str]) -> Vec<String> {
            build_state(&Config::fixture(args))
                .await
                .unwrap()
                .allowed_origins
                .to_vec()
        }
        let ccdp = Distribution::shared().origin().to_owned();

        let joined = origins(&[]).await;
        assert_eq!(joined, ["https://app.example".to_owned(), ccdp.clone()]);
        assert!(!joined.iter().any(|o| o == "https://lib.id"));

        let listed = format!("https://app.example,{ccdp}");
        assert_eq!(
            origins(&["--allowed-app-origins", &listed]).await,
            ["https://app.example".to_owned(), ccdp]
        );
    }

    /// An underscore in a host is admitted; the bytes a Content-Security-Policy
    /// reads as syntax are refused.
    #[test]
    fn an_underscore_in_a_host_is_an_origin_like_any_other() {
        for spelling in [
            "https://dev_box.example",
            "https://app_staging.example:8443",
        ] {
            assert!(canonical_origin("T", spelling).is_ok(), "{spelling}");
        }
        for hostile in ["https://a;b.example", "https://a'b.example"] {
            assert!(canonical_origin("T", hostile).is_err(), "{hostile}");
        }
    }

    /// Each of these is refused at startup.
    #[tokio::test]
    async fn a_deployment_that_could_not_serve_a_ceremony_stops_the_process() {
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
                "a plaintext admitted origin that is not localhost or 127.0.0.1",
                vec!["--allowed-app-origins", "http://app.example"],
            ),
            (
                "a relative callback path",
                vec!["--callback-path", "auth/callback"],
            ),
            (
                "a callback path axum reads as a brace pattern",
                vec!["--callback-path", "/auth/{rest}"],
            ),
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
            (
                "a scheme-relative callback path",
                vec!["--callback-path", "//evil.example/cb"],
            ),
            (
                "a CCDP origin whose host carries a CSP directive separator",
                vec!["--ccdp-origin", "https://a;b.example"],
            ),
            (
                "an admitted origin whose host carries a CSP keyword quote",
                vec!["--allowed-app-origins", "https://a'b.example"],
            ),
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
                build_state(&Config::fixture(&args)).await.is_err(),
                "{why} must stop the process"
            );
        }
    }

    /// The published record keys every enabled platform by name and carries
    /// its client id and versions, and no secret.
    #[tokio::test]
    async fn the_published_configuration_keys_every_enabled_platform_by_name() {
        let state = build_state(&Config::fixture(&[
            "--platforms",
            r#"[{"id":"google","client_id":"g","versions":[1,2]},{"id":"x","client_id":"xc","versions":[3]},{"id":"github","client_id":"gh","versions":[1]}]"#,
        ])).await
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
        assert!(!String::from_utf8_lossy(&state.ceremony_config).contains("ghs_secret"));
    }

    /// A github platform without a secret, or a secret without a github
    /// platform, refuses to start; neither is a deployment without the route.
    #[tokio::test]
    async fn the_github_secret_and_the_github_platform_require_each_other() {
        let no_secret = vec!["--gh-oauth-client-secret", ""];
        assert!(build_state(&Config::fixture(&no_secret)).await.is_err());

        let x_only = vec![
            "--platforms",
            r#"[{"id":"x","client_id":"abc","versions":[1]}]"#,
        ];
        assert!(
            build_state(&Config::fixture(&x_only)).await.is_err(),
            "a secret with no github platform must stop the process"
        );

        let neither = vec![
            "--platforms",
            r#"[{"id":"x","client_id":"abc","versions":[1]}]"#,
            "--gh-oauth-client-secret",
            "",
        ];
        let state = build_state(&Config::fixture(&neither)).await.unwrap();
        assert!(state.github.is_none());
    }

    /// `build_router` mounts every path for a deployment with the token route
    /// and one without.
    #[tokio::test]
    async fn building_the_router_for_a_configured_deployment_does_not_panic() {
        let state = build_state(&Config::fixture(&[])).await.unwrap();
        let _: axum::Router = routes::build_router(state);

        let x_only = build_state(&Config::fixture(&[
            "--platforms",
            r#"[{"id":"x","client_id":"abc","versions":[1]}]"#,
            "--gh-oauth-client-secret",
            "",
        ]))
        .await
        .unwrap();
        let _: axum::Router = routes::build_router(x_only);
    }

    /// The bound listener answers until told to stop, and `serve` returns.
    #[tokio::test]
    async fn serve_answers_until_told_to_stop() {
        use tokio::io::{
            AsyncReadExt,
            AsyncWriteExt,
        };

        let state = build_state(&Config::fixture(&[])).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(state, listener, async {
            let _ = stopped.await;
        }));

        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket
            .write_all(
                b"GET /health HTTP/1.1\r\nhost: bridge\r\nconnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut answer = Vec::new();
        socket.read_to_end(&mut answer).await.unwrap();
        assert!(
            answer.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&answer)
        );

        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
