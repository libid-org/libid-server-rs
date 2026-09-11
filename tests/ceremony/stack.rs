//! A deployment for one test: the binary on a configuration file, pointed at
//! a notary of this suite, with the OAuth App's credentials from the
//! environment.

use libid_server_rs::{
    fixtures::{
        token_body_with,
        Distribution,
    },
    routes::TOKEN_PATH,
};

use super::{
    bridge::{
        Bridge,
        Reply,
    },
    notary::Notary,
};

/// The notary a request names. Its host is dialled on the wire port; the
/// origin's own port (443) is never dialled.
pub const DECLARED_NOTARY: &str = "https://127.0.0.1";

/// The variable `name`, from the environment or from `.env.test`. An exported
/// value wins over the file. Absent or empty is a panic naming the variable.
pub fn required(name: &str) -> String {
    dotenvy::from_filename(".env.test").ok();
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => panic!(
            "{name} is required by the live ceremony suite: put it in a gitignored \
             .env.test, or export it. A missing variable fails the suite; it never \
             skips."
        ),
    }
}

/// The callback URL the OAuth App registers, sent in every token request.
pub fn redirect_uri() -> String {
    required("LIBID_TEST_REDIRECT_URI")
}

/// Tracing to the test output, filtered by `RUST_LOG`, installed once.
pub fn logging() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    });
}

/// A running bridge and the notary it dials.
pub struct Stack {
    bridge: Bridge,
    notary: Notary,
}

impl Stack {
    /// The App's real credentials and a notary that attests.
    pub async fn attesting() -> Stack {
        Stack::with(
            Notary::attesting().await,
            &required("GH_OAUTH_CLIENT_SECRET"),
        )
        .await
    }

    /// The App's real client id with a secret GitHub refuses.
    pub async fn wrong_secret() -> Stack {
        Stack::with(Notary::attesting().await, "not-this-deployments-secret").await
    }

    /// The App's real credentials and a notary that never speaks.
    pub async fn silent_notary() -> Stack {
        Stack::with(Notary::silent().await, &required("GH_OAUTH_CLIENT_SECRET")).await
    }

    /// The binary on a configuration naming `notary`'s wire port, the shared
    /// Distribution and the App, with `secret` in its environment.
    async fn with(notary: Notary, secret: &str) -> Stack {
        logging();
        let callback_path = url::Url::parse(&redirect_uri())
            .expect("LIBID_TEST_REDIRECT_URI is a URL")
            .path()
            .to_owned();
        let config = format!(
            "host = \"127.0.0.1\"\nport = 0\nnotary_wire_port = {}\n\
             callback_path = \"{callback_path}\"\n\
             allowed_app_origins = [\"https://app.example\"]\n\
             ccdp_origin = \"{}\"\n\
             [[platforms]]\nid = \"github\"\nclient_id = \"{}\"\nversions = [1]\n",
            notary.wire_port(),
            Distribution::shared().origin(),
            required("GH_OAUTH_CLIENT_ID"),
        );
        let secret = secret.to_owned();
        let bridge = tokio::task::spawn_blocking(move || {
            Bridge::started(&config, &[("GH_OAUTH_CLIENT_SECRET", &secret)])
        })
        .await
        .expect("the bridge starts");
        Stack { bridge, notary }
    }

    /// The public key a record from this deployment's notary recovers to.
    pub fn notary_pubkey(&self) -> &str {
        self.notary.pubkey()
    }

    /// One token exchange over TCP, from the CCDP origin, with `code`.
    pub async fn exchange(&self, code: &str) -> Reply {
        let body = token_body_with(&[
            ("code", code),
            ("redirectUri", &redirect_uri()),
            ("notaryAddress", DECLARED_NOTARY),
        ]);
        let address = self.bridge.address;
        tokio::task::spawn_blocking(move || {
            Reply::to(
                address,
                "POST",
                TOKEN_PATH,
                &[
                    ("origin", Distribution::shared().origin()),
                    ("content-type", "application/json"),
                ],
                &body,
            )
        })
        .await
        .expect("the exchange answers")
    }
}
