//! The binary over TCP: it starts on a configuration file, answers every
//! route, stops on SIGINT; a configuration it cannot serve stops it before it
//! binds.

#[path = "common/bridge.rs"]
// Each suite uses its part of the module.
#[allow(dead_code)]
mod bridge;

use bridge::{
    Bridge,
    Reply,
};
use libid_server_rs::{
    fixtures::{
        self,
        Distribution,
    },
    routes::CONFIG_PATH,
};

/// A path this bridge does not serve.
const GITHUB_TOKEN_PATH: &str = "/api/v1/ceremony/github-token";

/// A configuration pointed at the shared Distribution, with `platforms`
/// appended.
fn config(platforms: &str) -> String {
    format!(
        "allowed_app_origins = [\"https://app.example\"]\n\
         ccdp_origin = \"{}\"\n{platforms}",
        Distribution::shared().origin(),
    )
}

/// A github table carrying the fixture client id and credential.
fn github_table() -> String {
    format!(
        "[[platforms]]\nid = \"github\"\nclient_id = \"{}\"\nversions = [1]\n\
         client_credential = \"{}\"\n",
        fixtures::CLIENT_ID,
        fixtures::CLIENT_CREDENTIAL
    )
}

/// The binary binds, answers every route as the router does, and exits `0`
/// on SIGINT.
#[test]
fn the_binary_serves_every_route_until_interrupted() {
    let bridge = Bridge::started(&config(&github_table()));
    let get = |path: &str, headers: &[(&str, &str)]| {
        Reply::to(bridge.address, "GET", path, headers, "")
    };

    let health = get("/health", &[]);
    assert_eq!(health.status, 200, "{}", health.body);
    assert_eq!(health.body, "OK");
    assert_eq!(health.header("x-content-type-options"), Some("nosniff"));

    let admitted = get(CONFIG_PATH, &[("origin", "https://app.example")]);
    assert_eq!(admitted.status, 200, "{}", admitted.body);
    assert_eq!(
        admitted.header("access-control-allow-origin"),
        Some("https://app.example")
    );
    let record: serde_json::Value =
        serde_json::from_str(&admitted.body).expect("a JSON record");
    assert_eq!(record["ccdpOrigin"], Distribution::shared().origin());
    assert_eq!(
        record["platforms"]["github"]["clientId"],
        fixtures::CLIENT_ID
    );
    assert_eq!(
        record["platforms"]["github"]["clientCredential"],
        fixtures::CLIENT_CREDENTIAL
    );

    let anonymous = get(CONFIG_PATH, &[]);
    assert_eq!(anonymous.status, 403, "{}", anonymous.body);
    assert_eq!(anonymous.header("access-control-allow-origin"), None);

    let callback = get("/auth/callback?code=abc&state=v1.9e1f", &[]);
    assert_eq!(callback.status, 200, "{}", callback.body);
    assert_eq!(
        callback.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    let policy = callback
        .header("content-security-policy")
        .expect("the callback carries its policy");
    assert!(policy.contains("script-src 'sha256-"), "{policy}");
    assert!(
        policy.contains(&format!("frame-src {}", Distribution::shared().origin())),
        "{policy}"
    );
    assert!(callback.body.contains("<main id=\"libid-root\"></main>"));
    assert!(!callback.body.contains("__LIBID_CALLBACK_CONFIG__"));

    let unserved = Reply::to(
        bridge.address,
        "POST",
        GITHUB_TOKEN_PATH,
        &[
            ("origin", Distribution::shared().origin()),
            ("content-type", "application/json"),
        ],
        r#"{"code":"6b7f2c1d9e4a8035","codeVerifier":"iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I","notaryAddress":"https://127.0.0.1:7048"}"#,
    );
    assert_eq!(unserved.status, 404, "{}", unserved.body);
    assert_eq!(unserved.header("access-control-allow-origin"), None);

    let (exit, printed) = bridge.interrupted();
    assert!(exit.success(), "{exit}");
    assert!(printed.contains("shutting down"), "{printed}");
}

/// A deployment enabling X alone starts, publishes the X entry and no github
/// entry, and answers a preflight on the github token path with `404`.
#[test]
fn an_x_only_deployment_starts_and_serves_no_token_route() {
    let bridge = Bridge::started(&config(
        "[[platforms]]\nid = \"x\"\nclient_id = \"WHRlc3RjbGllbnQ6MTpjaQ\"\n\
         versions = [1]\n",
    ));

    let published = Reply::to(
        bridge.address,
        "GET",
        CONFIG_PATH,
        &[("origin", "https://app.example")],
        "",
    );
    assert_eq!(published.status, 200, "{}", published.body);
    let record: serde_json::Value =
        serde_json::from_str(&published.body).expect("a JSON record");
    assert_eq!(
        record["platforms"]["x"]["clientId"],
        "WHRlc3RjbGllbnQ6MTpjaQ"
    );
    assert_eq!(
        record["platforms"]["x"]["ceremonyVersions"],
        serde_json::json!([1])
    );
    assert!(record["platforms"].get("github").is_none());

    let preflight = Reply::to(
        bridge.address,
        "OPTIONS",
        GITHUB_TOKEN_PATH,
        &[
            ("origin", Distribution::shared().origin()),
            ("access-control-request-method", "POST"),
        ],
        "",
    );
    assert_eq!(preflight.status, 404, "{}", preflight.body);
    assert_eq!(preflight.header("access-control-allow-methods"), None);

    let (exit, _) = bridge.interrupted();
    assert!(exit.success(), "{exit}");
}

/// A configuration enabling no platform stops the binary before it binds,
/// with the missing table named.
#[test]
fn a_configuration_the_binary_cannot_serve_stops_it() {
    let output = bridge::attempt(&config(""));
    assert!(!output.status.success(), "{}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[[platforms]]"), "{stderr}");
}

/// A run that names no configuration file stops before it binds, naming the
/// file it was not given rather than the platforms the file would carry.
#[test]
fn a_run_with_no_configuration_file_names_it() {
    let output = bridge::attempt_unconfigured();
    assert!(!output.status.success(), "{}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("LIBID_CONFIG"), "{stderr}");
    assert!(!stderr.contains("[[platforms]]"), "{stderr}");
}
