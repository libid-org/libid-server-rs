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
/// be well-formed for a request to succeed is checked here, at startup.
pub fn build_state(cfg: &config::Config) -> Result<Arc<AppState>> {
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
                ccdp_origin: ccdp_origin.clone(),
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

    Ok(Arc::new(AppState {
        ceremony_config: deployment::CeremonyConfig {
            callback_path: &callback_path,
            ccdp_origin: &ccdp_origin,
            platforms: &platforms,
        }
        .serialized(),
        callback: artifact::CallbackDocument::for_deployment(
            cfg,
            &ccdp_origin,
            &allowed_origins,
        )?,
        allowed_origins,
        callback_path,
        github,
    }))
}

impl artifact::CallbackDocument {
    /// The document this deployment serves: the artifact
    /// `CALLBACK_ARTIFACT_PATH` names, or the compiled-in floor when it is
    /// empty. Both go through the same validation and composition. Read at
    /// startup, not fetched.
    fn for_deployment(
        cfg: &config::Config,
        ccdp_origin: &str,
        allowed_origins: &[String],
    ) -> Result<Self> {
        let path = cfg.callback_artifact_path.trim();
        let (html, source) = if path.is_empty() {
            (artifact::EMBEDDED.to_owned(), artifact::Source::Embedded)
        } else {
            (read_artifact(path)?, artifact::Source::Supplied)
        };

        let document = artifact::CallbackDocument::compose(
            &html,
            &artifact::DeploymentInputs {
                ccdp_origin,
                allowed_origins,
            },
            source,
        )
        .map_err(|e| Error::Config {
            detail: match source {
                artifact::Source::Embedded => {
                    format!("the compiled-in callback artifact is not serveable: {e}")
                }
                artifact::Source::Supplied => {
                    format!("CALLBACK_ARTIFACT_PATH {path} is not serveable: {e}")
                }
            },
        })?;

        match document.source {
            artifact::Source::Embedded => tracing::warn!(
                "serving the COMPILED-IN callback artifact: it clears the OAuth return \
             and renders fixed text, and completes no ceremony. Set \
             CALLBACK_ARTIFACT_PATH to a callback.html from the CCDP \
             Distribution before running this deployment."
            ),
            artifact::Source::Supplied => {
                tracing::info!(path, "serving the configured callback artifact")
            }
        }
        Ok(document)
    }
}

/// Read a configured artifact, refusing one over `MAX_ARTIFACT_BYTES` before
/// reading it. The size is read off the open handle, and bounded again while
/// reading.
fn read_artifact(path: &str) -> Result<String> {
    use std::io::Read as _;

    let refuse = |detail: String| Error::Config {
        detail: format!("CALLBACK_ARTIFACT_PATH {path}: {detail}"),
    };
    let file = std::fs::File::open(path).map_err(|e| refuse(format!("{e}")))?;
    let len = file.metadata().map_err(|e| refuse(format!("{e}")))?.len();
    let bound = artifact::scan::MAX_ARTIFACT_BYTES as u64;
    if len > bound {
        return Err(refuse(format!(
            "is {len} bytes, over the {bound}-byte bound"
        )));
    }
    // One byte over refuses; nothing is served from a prefix.
    let mut html = String::new();
    file.take(bound + 1)
        .read_to_string(&mut html)
        .map_err(|e| refuse(format!("{e}")))?;
    if html.len() as u64 > bound {
        return Err(refuse(format!("is over the {bound}-byte bound")));
    }
    Ok(html)
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
/// path, query, fragment or credentials; plaintext only on loopback; a host
/// made only of the bytes an origin is made of. `Url::origin` lowercases the
/// host and drops a default port.
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
    // Plaintext only on loopback.
    if url.scheme() == "http" && !is_loopback(&url) {
        return Err(refuse("is plaintext http on a host that is not loopback"));
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

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
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
    use super::*;

    /// A loopback port nothing listens on, bound once and released: a session
    /// a test does start fails at the dial instead of reaching a notary on
    /// this machine.
    fn dead_port() -> &'static str {
        static PORT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PORT.get_or_init(|| {
            let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            free.local_addr().unwrap().port().to_string()
        })
    }

    /// A deployment that starts, with `args` replacing any default it names.
    ///
    /// Every flag that reads an environment variable is listed, so the
    /// process environment reaches nothing. `--platforms` is this fixture's
    /// own: the JSON records go to `Config::platforms`, which the binary
    /// fills from the configuration file.
    fn config(args: &[&str]) -> config::Config {
        let mut flags: Vec<(&str, &str)> = vec![
            ("--host", "127.0.0.1"),
            ("--port", "8722"),
            ("--notary-wire-port", dead_port()),
            ("--callback-path", "/auth/callback"),
            ("--allowed-app-origins", "https://app.example"),
            ("--ccdp-origin", "https://ccdp.example"),
            (
                "--platforms",
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
        let platforms = flags
            .iter()
            .position(|(f, _)| *f == "--platforms")
            .map(|i| flags.remove(i).1)
            .expect("the fixture lists --platforms");
        let mut argv = vec!["libid-server-rs"];
        for (flag, value) in &flags {
            argv.push(flag);
            argv.push(value);
        }
        let mut cfg = <config::Config as clap::Parser>::parse_from(argv);
        cfg.platforms =
            serde_json::from_str(platforms).expect("the fixture's platform records");
        cfg
    }

    /// An omitted CCDP origin selects the canonical libID Distribution: the
    /// declared default is `https://lib.id`, and the configured value reaches
    /// the published record.
    #[test]
    fn an_omitted_ccdp_origin_selects_the_canonical_distribution() {
        let command = <config::Config as clap::CommandFactory>::command();
        let arg = command
            .get_arguments()
            .find(|a| a.get_id() == "ccdp_origin")
            .expect("the ccdp origin is an argument");
        assert_eq!(arg.get_default_values(), ["https://lib.id"]);

        let state = build_state(&config(&["--ccdp-origin", "https://lib.id"])).unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(&state.ceremony_config).unwrap();
        assert_eq!(record["ccdpOrigin"], "https://lib.id");
    }

    /// Plaintext `http` is admitted on loopback, in each spelling a host can
    /// take, and refused everywhere else.
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

    /// The effective set is `allowedAppOrigins ∪ {ccdpOrigin}`: the default
    /// joins, an override joins in its place, and an origin already listed is
    /// not added twice.
    #[test]
    fn the_effective_admission_set_is_the_allowlist_plus_the_ccdp_origin() {
        let origins = |args: &[&str]| -> Vec<String> {
            build_state(&config(args)).unwrap().allowed_origins.to_vec()
        };

        assert_eq!(
            origins(&["--ccdp-origin", "https://lib.id"]),
            ["https://app.example", "https://lib.id"]
        );

        let overridden = origins(&["--ccdp-origin", "https://ccdp.example"]);
        assert_eq!(overridden, ["https://app.example", "https://ccdp.example"]);
        assert!(!overridden.iter().any(|o| o == "https://lib.id"));

        assert_eq!(
            origins(&[
                "--allowed-app-origins",
                "https://app.example,https://ccdp.example",
                "--ccdp-origin",
                "https://ccdp.example",
            ]),
            ["https://app.example", "https://ccdp.example"]
        );
    }

    /// A configured artifact over `MAX_ARTIFACT_BYTES` is refused, naming the
    /// setting, before it is read; one within the bound is read and composed.
    #[test]
    fn an_artifact_file_over_the_bound_is_refused_before_it_is_read() {
        let dir = std::env::temp_dir().join(format!(
            "libid-artifact-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let too_big = dir.join("too-big.html");
        std::fs::write(&too_big, vec![b'x'; artifact::scan::MAX_ARTIFACT_BYTES + 1])
            .unwrap();
        let Err(refusal) = build_state(&config(&[
            "--callback-artifact-path",
            too_big.to_str().unwrap(),
        ])) else {
            panic!("an artifact over the bound is not serveable")
        };
        let detail = format!("{refusal}");
        assert!(detail.contains("bound"), "{detail}");
        assert!(detail.contains("CALLBACK_ARTIFACT_PATH"), "{detail}");

        let fine = dir.join("fine.html");
        std::fs::write(&fine, artifact::EMBEDDED).unwrap();
        let state = build_state(&config(&[
            "--callback-artifact-path",
            fine.to_str().unwrap(),
        ]))
        .expect("a configured artifact within the bound is serveable");
        assert_eq!(state.callback.source, artifact::Source::Supplied);

        std::fs::remove_dir_all(&dir).ok();
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
                build_state(&config(&args)).is_err(),
                "{why} must stop the process"
            );
        }
    }

    /// The published record keys every enabled platform by name and carries
    /// its client id and versions, and no secret.
    #[test]
    fn the_published_configuration_keys_every_enabled_platform_by_name() {
        let state = build_state(&config(&[
            "--platforms",
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
        assert!(!String::from_utf8_lossy(&state.ceremony_config).contains("ghs_secret"));
    }

    /// A github platform without a secret, or a secret without a github
    /// platform, refuses to start; neither is a deployment without the route.
    #[test]
    fn the_github_secret_and_the_github_platform_require_each_other() {
        let no_secret = vec!["--gh-oauth-client-secret", ""];
        assert!(build_state(&config(&no_secret)).is_err());

        let x_only = vec![
            "--platforms",
            r#"[{"id":"x","clientId":"abc","versions":[1]}]"#,
        ];
        assert!(
            build_state(&config(&x_only)).is_err(),
            "a secret with no github platform must stop the process"
        );

        let neither = vec![
            "--platforms",
            r#"[{"id":"x","clientId":"abc","versions":[1]}]"#,
            "--gh-oauth-client-secret",
            "",
        ];
        let state = build_state(&config(&neither)).unwrap();
        assert!(state.github.is_none());
    }

    /// `build_router` mounts every path for a deployment with the token route
    /// and one without.
    #[test]
    fn building_the_router_for_a_configured_deployment_does_not_panic() {
        let state = build_state(&config(&[])).unwrap();
        let _: axum::Router = routes::build_router(state);

        let x_only = build_state(&config(&[
            "--platforms",
            r#"[{"id":"x","clientId":"abc","versions":[1]}]"#,
            "--gh-oauth-client-secret",
            "",
        ]))
        .unwrap();
        let _: axum::Router = routes::build_router(x_only);
    }
}
