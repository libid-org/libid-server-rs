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
#[derive(Parser, Debug)]
#[command(name = "libid-server-rs", version, about)]
pub struct Config {
    /// Path to a TOML configuration file. Every setting below can be written
    /// in it under its own name in lower case.
    #[arg(long, env = "LIBID_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Host to bind. Use 0.0.0.0 in containers. Flag or environment only:
    /// where the process listens is not ceremony configuration.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind. Flag or environment only.
    #[arg(long, env = "PORT", default_value = "8722")]
    pub port: u16,

    /// Comma-separated application origins admitted to read the public
    /// ceremony configuration. Nonempty, each in canonical form.
    #[arg(long, env = "ALLOWED_APP_ORIGINS", value_delimiter = ',')]
    pub allowed_app_origins: Vec<String>,

    /// The CCDP Distribution this bridge selects: the canonical origin serving
    /// the Callback artifact and everything the browser runs after it.
    /// Published in the configuration and inserted into the callback document.
    #[arg(long, env = "CCDP_ORIGIN", default_value = "https://lib.id")]
    pub ccdp_origin: String,

    /// The enabled platforms, from the configuration file's `[[platforms]]`
    /// tables: each names a platform, its public client id, the ceremony
    /// versions it advertises and, for `github`, the public client
    /// credential.
    #[arg(skip)]
    pub platforms: Vec<PlatformProfile>,
}

/// The configuration file.
///
/// Every key is optional and corresponds to the [`Config`] field of the same
/// name; an unknown key is refused. `allowed_app_origins` is a list, and the
/// platforms are `[[platforms]]` tables. The bind address and port are not
/// keys: a container image sets them in the environment, which beats a file,
/// so a file naming them would be read and not applied.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// [`Config::allowed_app_origins`].
    pub allowed_app_origins: Option<Vec<String>>,
    /// [`Config::ccdp_origin`].
    pub ccdp_origin: Option<String>,
    /// [`Config::platforms`]:
    ///
    /// ```toml
    /// [[platforms]]
    /// id = "github"
    /// client_id = "Iv1.0123456789abcdef"
    /// versions = [1]
    /// client_credential = "..."
    /// ```
    pub platforms: Option<Vec<PlatformProfile>>,
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
        Config::merged(Config::command(), argv)
    }

    /// The same, parsing with `command`: which environment variables reach a
    /// flag is that command's to say.
    fn merged<I, T>(command: clap::Command, argv: I) -> Result<Config>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let matches = command.get_matches_from(argv);
        let mut cfg = Config::from_arg_matches(&matches).map_err(|e| Error::Config {
            detail: e.to_string(),
        })?;
        // The enabled platforms are read from the file and nowhere else, so a
        // run that names none could serve no ceremony.
        let Some(path) = cfg.config.clone() else {
            return Err(Error::Config {
                detail: "no configuration file; name one with --config or \
                         LIBID_CONFIG. The enabled platforms are read from it."
                    .into(),
            });
        };

        let refuse = |detail: String| Error::Config {
            detail: format!("{}: {detail}", path.display()),
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| refuse(format!("cannot be read: {e}")))?;
        let file: FileConfig =
            toml::from_str(&text).map_err(|e| refuse(e.message().to_owned()))?;

        if defaulted(&matches, "ccdp_origin") {
            cfg.ccdp_origin = file.ccdp_origin.unwrap_or(cfg.ccdp_origin);
        }
        if defaulted(&matches, "allowed_app_origins") {
            cfg.allowed_app_origins =
                file.allowed_app_origins.unwrap_or(cfg.allowed_app_origins);
        }
        cfg.platforms = file.platforms.unwrap_or_default();
        Ok(cfg)
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;
    use crate::deployment::PlatformId;

    /// Write a configuration file and resolve against it, with no environment
    /// variable reaching a flag: what the file supplies is what this test
    /// wrote, whatever the machine running it exports.
    fn resolved(toml: &str, flags: &[&str]) -> Result<Config> {
        let path = std::env::temp_dir().join(format!(
            "libid-config-{}-{:?}.toml",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, toml).expect("a scratch config file");
        resolved_file(&path, flags)
    }

    /// The configuration `path` describes, with `flags` on the command line.
    fn resolved_file(path: &std::path::Path, flags: &[&str]) -> Result<Config> {
        let mut argv = vec![
            "libid-server-rs".to_owned(),
            "--config".to_owned(),
            path.display().to_string(),
        ];
        argv.extend(flags.iter().map(|f| (*f).to_owned()));
        Config::merged(Config::command().mut_args(|a| a.env(None::<&str>)), argv)
    }

    /// A file supplies what nothing else did, the platform table included.
    #[test]
    fn a_file_supplies_what_no_flag_and_no_variable_named() {
        let cfg = resolved(
            r#"
            ccdp_origin = "https://dist.example"
            allowed_app_origins = ["https://app.example", "https://wallet.example"]

            [[platforms]]
            id = "github"
            client_id = "Iv1.0123456789abcdef"
            versions = [1]
            client_credential = "c0ffee_from_the_file"
            "#,
            &[],
        )
        .expect("a file this deployment can read");

        assert_eq!(cfg.ccdp_origin, "https://dist.example");
        assert_eq!(
            cfg.allowed_app_origins,
            ["https://app.example", "https://wallet.example"]
        );
        let platforms = crate::deployment::platforms(cfg.platforms)
            .expect("the records the table describes");
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0].client_id(), "Iv1.0123456789abcdef");
        assert_eq!(
            platforms[0].client_credential(),
            Some("c0ffee_from_the_file")
        );
    }

    /// A `github` table without its credential is refused, with the missing
    /// key named.
    #[test]
    fn a_github_table_without_its_credential_is_refused() {
        let err = resolved(
            r#"
            [[platforms]]
            id = "github"
            client_id = "Iv1.0123456789abcdef"
            versions = [1]
            "#,
            &[],
        )
        .expect_err("no credential");
        assert!(err.to_string().contains("client_credential"), "{err}");
    }

    /// An `x` table carries a client id and versions and no credential.
    #[test]
    fn an_x_table_is_a_public_client_with_no_credential() {
        let cfg = resolved(
            r#"
            [[platforms]]
            id = "x"
            client_id = "WHRlc3RjbGllbnQ6MTpjaQ"
            versions = [1]
            "#,
            &[],
        )
        .expect("a file this deployment can read");
        let platforms = crate::deployment::platforms(cfg.platforms)
            .expect("the records the table describes");
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0].id(), PlatformId::X);
        assert_eq!(platforms[0].client_id(), "WHRlc3RjbGllbnQ6MTpjaQ");
        assert_eq!(platforms[0].versions(), [1]);
        assert!(platforms[0].client_credential().is_none());
    }

    /// A flag beats the file.
    #[test]
    fn the_command_line_beats_the_file() {
        let cfg = resolved(
            "ccdp_origin = \"https://dist.example\"\n",
            &["--ccdp-origin", "https://other.example"],
        )
        .expect("a file this deployment can read");
        assert_eq!(cfg.ccdp_origin, "https://other.example");
    }

    /// Where neither says anything, the default stands.
    #[test]
    fn a_silent_file_changes_nothing() {
        let cfg = resolved("allowed_app_origins = [\"https://app.example\"]\n", &[])
            .expect("readable");
        assert_eq!(cfg.ccdp_origin, "https://lib.id");
    }

    /// A file with no `[[platforms]]` table enables no platform, which the
    /// platform check refuses by name.
    #[test]
    fn no_platform_table_means_no_platform() {
        let cfg = resolved("allowed_app_origins = [\"https://app.example\"]\n", &[])
            .expect("readable");
        assert!(cfg.platforms.is_empty());
        let err = crate::deployment::platforms(cfg.platforms).expect_err("no platform");
        assert!(err.to_string().contains("[[platforms]]"), "{err}");
    }

    /// The example file shipped beside this code is one the code accepts.
    #[test]
    fn the_example_file_is_one_this_bridge_accepts() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bridge.toml.example");
        let cfg = resolved_file(std::path::Path::new(path), &[])
            .expect("the example beside this code");

        assert_eq!(cfg.ccdp_origin, "https://lib.id");
        assert_eq!(
            cfg.allowed_app_origins,
            ["https://app.example", "https://wallet.example"]
        );
        let platforms = crate::deployment::platforms(cfg.platforms)
            .expect("the example's platform table");
        let github = platforms
            .iter()
            .find(|p| p.id() == PlatformId::Github)
            .expect("the example enables github");
        assert!(github.client_credential().is_some());
    }

    /// A run that names no file is told that, not that the platforms the
    /// file would have carried are missing.
    #[test]
    fn a_run_that_names_no_file_is_told_so() {
        let err = Config::merged(
            Config::command().mut_args(|a| a.env(None::<&str>)),
            ["libid-server-rs"],
        )
        .expect_err("no configuration file");
        let text = err.to_string();
        assert!(text.contains("LIBID_CONFIG"), "{text}");
        assert!(text.contains("--config"), "{text}");
    }

    /// A misspelled key is refused rather than ignored.
    #[test]
    fn a_misspelled_key_is_refused() {
        let err = resolved("prot = 9110\n", &[]).expect_err("an unknown key");
        assert!(err.to_string().contains("prot"), "{err}");
    }

    /// The bind address and port, and the keys of the exchange this bridge
    /// does not perform, are not settings of this file: one naming any of
    /// them is refused like any other unknown key.
    #[test]
    fn a_key_this_bridge_does_not_read_is_refused() {
        for unread in [
            "host = \"0.0.0.0\"\n",
            "port = 8722\n",
            "public_origin = \"https://bridge.example\"\n",
            "notary_wire_port = 7047\n",
            "gh_oauth_client_secret = \"s\"\n",
        ] {
            let err = resolved(unread, &[]).expect_err("a key this bridge does not read");
            let key = unread.split(' ').next().unwrap();
            assert!(err.to_string().contains(key), "{err}");
        }
    }
}
