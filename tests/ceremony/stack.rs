//! A deployment for one test: the binary on a configuration file naming the
//! App's public client id and credential from the environment, beside a
//! notary of this suite; and the environment the suite reads.

use libid_server_rs::{
    fixtures::Distribution,
    routes::CONFIG_PATH,
};

use super::{
    bridge::{
        Bridge,
        Reply,
    },
    notary::Notary,
};

/// The application origin the bridge under test admits, and the one the
/// suite reads the configuration as.
pub const APP_ORIGIN: &str = "https://app.example";

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

/// The variable `name`, from the environment or from `.env.test`; `None`
/// when it is absent or empty.
pub fn optional(name: &str) -> Option<String> {
    dotenvy::from_filename(".env.test").ok();
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// The origin the OAuth App's callback URL is registered under: the bridge
/// origin as the application knows it, a canonical origin with no path.
pub fn public_origin() -> String {
    let origin = required("LIBID_TEST_PUBLIC_ORIGIN");
    let parsed = url::Url::parse(&origin).expect("LIBID_TEST_PUBLIC_ORIGIN parses");
    assert_eq!(
        parsed.origin().ascii_serialization(),
        origin,
        "LIBID_TEST_PUBLIC_ORIGIN is a canonical origin"
    );
    origin
}

/// The callback URL the OAuth App registers: the public origin followed by
/// `/auth/callback`, as the application derives it from the bridge origin.
pub fn redirect_uri() -> String {
    format!(
        "{}{}",
        public_origin(),
        libid_server_rs::routes::CALLBACK_PATH
    )
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

/// A running bridge and a notary of this suite.
pub struct Stack {
    pub bridge: Bridge,
    pub notary: Notary,
}

/// The github entry the bridge published: what a ceremony starts from.
pub struct Published {
    pub client_id: String,
    pub credential: String,
}

impl Stack {
    /// The binary on a configuration naming the shared Distribution and the
    /// App, its client secret in the github table as the credential to
    /// publish, beside a notary that attests.
    pub async fn attesting() -> Stack {
        logging();
        let config = format!(
            "allowed_app_origins = [\"{APP_ORIGIN}\"]\n\
             ccdp_origin = \"{}\"\n\
             [[platforms]]\nid = \"github\"\nclient_id = \"{}\"\nversions = [1]\n\
             client_credential = \"{}\"\n",
            Distribution::shared().origin(),
            required("GH_OAUTH_CLIENT_ID"),
            required("GH_OAUTH_CLIENT_SECRET"),
        );
        let bridge = tokio::task::spawn_blocking(move || Bridge::started(&config))
            .await
            .expect("the bridge starts");
        Stack {
            bridge,
            notary: Notary::attesting().await,
        }
    }

    /// The github entry of the configuration the bridge publishes, read over
    /// TCP from the admitted application origin: the client id and the
    /// credential the configuration named.
    pub async fn published(&self) -> Published {
        let address = self.bridge.address;
        let reply = tokio::task::spawn_blocking(move || {
            Reply::to(address, "GET", CONFIG_PATH, &[("origin", APP_ORIGIN)], "")
        })
        .await
        .expect("the configuration answers");
        assert_eq!(reply.status, 200, "{}", reply.body);
        let record: serde_json::Value =
            serde_json::from_str(&reply.body).expect("a JSON record");
        let github = &record["platforms"]["github"];
        let published = Published {
            client_id: github["clientId"].as_str().expect("a client id").to_owned(),
            credential: github["clientCredential"]
                .as_str()
                .expect("the public credential")
                .to_owned(),
        };
        assert_eq!(published.client_id, required("GH_OAUTH_CLIENT_ID"));
        assert_eq!(published.credential, required("GH_OAUTH_CLIENT_SECRET"));
        published
    }
}
