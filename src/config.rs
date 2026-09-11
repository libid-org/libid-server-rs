//! Configuration: a TOML file, environment variables and command-line flags.

use clap::{
    CommandFactory,
    FromArgMatches,
    Parser,
};
use serde::Deserialize;

use crate::{
    deployment::PlatformProfile,
    error::{
        Error,
        Result,
    },
};

/// The deployment's settings.
///
/// Every flag has an environment variable of the same name. Precedence is
/// command line, then environment, then the configuration file, then the
/// default.
#[derive(Parser)]
#[command(name = "libid-server-rs", version, about)]
pub struct Config {
    /// Path to a TOML configuration file. Every setting below can be written
    /// in it under its own name in lower case.
    #[arg(long, env = "LIBID_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Host to bind. Use 0.0.0.0 in containers.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind.
    #[arg(long, env = "PORT", default_value = "8722")]
    pub port: u16,

    /// The port of the notary's MPC-TLS wire listener. Each token request
    /// names the notary; this bridge dials that host on this port.
    #[arg(long, env = "NOTARY_WIRE_PORT", default_value_t = 7047)]
    pub notary_wire_port: u16,

    /// Comma-separated application origins admitted to read the public
    /// ceremony configuration. Nonempty, each in canonical form.
    #[arg(long, env = "ALLOWED_APP_ORIGINS", value_delimiter = ',')]
    pub allowed_app_origins: Vec<String>,

    /// The path the providers redirect back to. The registered OAuth callback
    /// URL is this bridge's public origin followed by this path.
    #[arg(long, env = "CALLBACK_PATH", default_value = "/auth/callback")]
    pub callback_path: String,

    /// The CCDP Distribution this bridge selects: the canonical origin serving
    /// the Callback artifact and everything the browser runs after it.
    /// Published in the configuration and inserted into the callback document.
    #[arg(long, env = "CCDP_ORIGIN", default_value = "https://lib.id")]
    pub ccdp_origin: String,

    /// A Callback artifact to serve instead of the compiled-in floor: the path
    /// to a `callback.html` obtained from the CCDP Distribution, read once at
    /// startup. Empty serves the floor, which completes no ceremony.
    #[arg(long, env = "CALLBACK_ARTIFACT_PATH", default_value = "")]
    pub callback_artifact_path: String,

    /// The enabled platforms, from the configuration file's `[[platforms]]`
    /// tables: each names a platform, its public client id and the ceremony
    /// versions it advertises.
    #[arg(skip)]
    pub platforms: Vec<PlatformProfile>,

    /// GitHub OAuth App client secret. Required when the platforms enable
    /// `github`, refused when they do not.
    #[arg(
        long,
        env = "GH_OAUTH_CLIENT_SECRET",
        hide_env_values = true,
        default_value = ""
    )]
    pub gh_oauth_client_secret: String,
}

/// The configuration file.
///
/// Every key is optional and corresponds to the [`Config`] field of the same
/// name; an unknown key is refused. `allowed_app_origins` is a list, and the
/// platforms are `[[platforms]]` tables.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// [`Config::host`].
    pub host: Option<String>,
    /// [`Config::port`].
    pub port: Option<u16>,
    /// [`Config::notary_wire_port`].
    pub notary_wire_port: Option<u16>,
    /// [`Config::allowed_app_origins`].
    pub allowed_app_origins: Option<Vec<String>>,
    /// [`Config::callback_path`].
    pub callback_path: Option<String>,
    /// [`Config::ccdp_origin`].
    pub ccdp_origin: Option<String>,
    /// [`Config::callback_artifact_path`].
    pub callback_artifact_path: Option<String>,
    /// [`Config::platforms`]:
    ///
    /// ```toml
    /// [[platforms]]
    /// id = "github"
    /// client_id = "Iv1.0123456789abcdef"
    /// versions = [1]
    /// ```
    pub platforms: Option<Vec<PlatformProfile>>,
    /// [`Config::gh_oauth_client_secret`].
    pub gh_oauth_client_secret: Option<String>,
}

/// Whether clap supplied `id` from its default rather than from the command
/// line or the environment.
fn defaulted(matches: &clap::ArgMatches, id: &str) -> bool {
    !matches!(
        matches.value_source(id),
        Some(clap::parser::ValueSource::CommandLine)
            | Some(clap::parser::ValueSource::EnvVariable)
    )
}

impl Config {
    /// Resolve the configuration from the process's arguments, environment
    /// and configuration file.
    pub fn resolve() -> Result<Config> {
        Config::resolve_from(std::env::args_os())
    }

    /// The same, from an explicit argv. A value from the file is used where
    /// neither a flag nor an environment variable set the field.
    pub fn resolve_from<I, T>(argv: I) -> Result<Config>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let matches = Config::command().get_matches_from(argv);
        let mut cfg = Config::from_arg_matches(&matches).map_err(|e| Error::Config {
            detail: e.to_string(),
        })?;
        let Some(path) = cfg.config.clone() else {
            return Ok(cfg);
        };

        let refuse = |detail: String| Error::Config {
            detail: format!("{}: {detail}", path.display()),
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| refuse(format!("cannot be read: {e}")))?;
        let file: FileConfig =
            toml::from_str(&text).map_err(|e| refuse(e.message().to_owned()))?;

        if defaulted(&matches, "host") {
            cfg.host = file.host.unwrap_or(cfg.host);
        }
        if defaulted(&matches, "port") {
            cfg.port = file.port.unwrap_or(cfg.port);
        }
        if defaulted(&matches, "notary_wire_port") {
            cfg.notary_wire_port = file.notary_wire_port.unwrap_or(cfg.notary_wire_port);
        }
        if defaulted(&matches, "callback_path") {
            cfg.callback_path = file.callback_path.unwrap_or(cfg.callback_path);
        }
        if defaulted(&matches, "ccdp_origin") {
            cfg.ccdp_origin = file.ccdp_origin.unwrap_or(cfg.ccdp_origin);
        }
        if defaulted(&matches, "callback_artifact_path") {
            cfg.callback_artifact_path = file
                .callback_artifact_path
                .unwrap_or(cfg.callback_artifact_path);
        }
        if defaulted(&matches, "gh_oauth_client_secret") {
            cfg.gh_oauth_client_secret = file
                .gh_oauth_client_secret
                .unwrap_or(cfg.gh_oauth_client_secret);
        }
        if defaulted(&matches, "allowed_app_origins") {
            cfg.allowed_app_origins =
                file.allowed_app_origins.unwrap_or(cfg.allowed_app_origins);
        }
        cfg.platforms = file.platforms.unwrap_or_default();
        Ok(cfg)
    }
}

/// `Debug` redacts the client secret.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("notary_wire_port", &self.notary_wire_port)
            .field("allowed_app_origins", &self.allowed_app_origins)
            .field("callback_path", &self.callback_path)
            .field("ccdp_origin", &self.ccdp_origin)
            .field("callback_artifact_path", &self.callback_artifact_path)
            .field("platforms", &self.platforms)
            .field("gh_oauth_client_secret", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;

    /// Write a configuration file and resolve against it.
    fn resolved(toml: &str, flags: &[&str]) -> Result<Config> {
        let path = std::env::temp_dir().join(format!(
            "libid-config-{}-{:?}.toml",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, toml).expect("a scratch config file");
        let mut argv = vec![
            "libid-server-rs".to_owned(),
            "--config".to_owned(),
            path.display().to_string(),
        ];
        argv.extend(flags.iter().map(|f| (*f).to_owned()));
        Config::resolve_from(argv)
    }

    /// A file supplies what nothing else did, the platform table included.
    #[test]
    fn a_file_supplies_what_no_flag_and_no_variable_named() {
        let cfg = resolved(
            r#"
            port = 9110
            callback_path = "/oauth/return"
            allowed_app_origins = ["https://app.example", "https://wallet.example"]
            gh_oauth_client_secret = "ghs_from_the_file"

            [[platforms]]
            id = "github"
            client_id = "Iv1.0123456789abcdef"
            versions = [1]
            "#,
            &[],
        )
        .expect("a file this deployment can read");

        assert_eq!(cfg.port, 9110);
        assert_eq!(cfg.callback_path, "/oauth/return");
        assert_eq!(
            cfg.allowed_app_origins,
            ["https://app.example", "https://wallet.example"]
        );
        assert_eq!(cfg.gh_oauth_client_secret, "ghs_from_the_file");
        let platforms = crate::deployment::platforms(cfg.platforms)
            .expect("the records the table describes");
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0].client_id, "Iv1.0123456789abcdef");
    }

    /// A flag beats the file.
    #[test]
    fn the_command_line_beats_the_file() {
        let cfg = resolved(
            "port = 9110\ngh_oauth_client_secret = \"ghs_from_the_file\"\n",
            &[
                "--port",
                "9999",
                "--gh-oauth-client-secret",
                "ghs_from_a_flag",
            ],
        )
        .expect("a file this deployment can read");
        assert_eq!(cfg.port, 9999);
        assert_eq!(cfg.gh_oauth_client_secret, "ghs_from_a_flag");
    }

    /// Where neither says anything, the default stands.
    #[test]
    fn a_silent_file_changes_nothing() {
        let cfg = resolved("port = 9110\n", &[]).expect("readable");
        assert_eq!(cfg.callback_path, "/auth/callback");
    }

    /// A file with no `[[platforms]]` table enables no platform, which the
    /// platform check refuses by name.
    #[test]
    fn no_platform_table_means_no_platform() {
        let cfg = resolved("port = 9110\n", &[]).expect("readable");
        assert!(cfg.platforms.is_empty());
        let err = crate::deployment::platforms(cfg.platforms).expect_err("no platform");
        assert!(err.to_string().contains("[[platforms]]"), "{err}");
    }

    /// The example file shipped beside this code is one the code accepts.
    #[test]
    fn the_example_file_is_one_this_bridge_accepts() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bridge.toml.example");
        let cfg = Config::resolve_from(["libid-server-rs", "--config", path])
            .expect("the example beside this code");

        assert_eq!(cfg.port, 8722);
        assert_eq!(cfg.notary_wire_port, 7047);
        assert_eq!(
            cfg.allowed_app_origins,
            ["https://app.example", "https://wallet.example"]
        );
        let platforms = crate::deployment::platforms(cfg.platforms)
            .expect("the example's platform table");
        assert!(platforms.iter().any(|p| p.is_github()));
    }

    /// A misspelled key is refused rather than ignored.
    #[test]
    fn a_misspelled_key_is_refused() {
        let err = resolved("prot = 9110\n", &[]).expect_err("an unknown key");
        assert!(err.to_string().contains("prot"), "{err}");
    }

    /// The flag beats the file, and `Debug` prints neither secret.
    #[test]
    fn the_secret_is_redacted_from_debug_output() {
        let cfg = resolved(
            "gh_oauth_client_secret = \"ghs_from_the_file\"\n",
            &["--gh-oauth-client-secret", "ghs_from_a_flag"],
        )
        .expect("readable");
        let printed = format!("{cfg:?}");
        assert!(!printed.contains("ghs_"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }
}
