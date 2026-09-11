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
        token_body_with,
        Distribution,
    },
    routes::{
        CONFIG_PATH,
        TOKEN_PATH,
    },
};

/// A configuration pointed at the shared Distribution and a wire port
/// nothing listens on, with `platforms` appended.
fn config(platforms: &str) -> String {
    format!(
        "host = \"127.0.0.1\"\nport = 0\nnotary_wire_port = {}\n\
         allowed_app_origins = [\"https://app.example\"]\n\
         ccdp_origin = \"{}\"\n{platforms}",
        fixtures::dead_port(),
        Distribution::shared().origin(),
    )
}

/// The binary binds, answers every route as the router does, and exits `0`
/// on SIGINT.
#[test]
fn the_binary_serves_every_route_until_interrupted() {
    let bridge = Bridge::started(
        &config(&format!(
            "[[platforms]]\nid = \"github\"\nclient_id = \"{}\"\nversions = [1]\n",
            fixtures::CLIENT_ID
        )),
        &[("GH_OAUTH_CLIENT_SECRET", fixtures::CLIENT_SECRET)],
    );
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
    assert_eq!(record["callbackPath"], "/auth/callback");
    assert_eq!(record["ccdpOrigin"], Distribution::shared().origin());
    assert_eq!(
        record["platforms"]["github"]["clientId"],
        fixtures::CLIENT_ID
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

    let foreign = Reply::to(
        bridge.address,
        "POST",
        TOKEN_PATH,
        &[
            ("origin", "https://evil.example"),
            ("content-type", "application/json"),
        ],
        &token_body_with(&[]),
    );
    assert_eq!(foreign.status, 403, "{}", foreign.body);
    assert_eq!(foreign.header("cache-control"), Some("no-store"));

    let (exit, printed) = bridge.interrupted();
    assert!(exit.success(), "{exit}");
    assert!(printed.contains("shutting down"), "{printed}");
}

/// A configuration enabling no platform stops the binary before it binds,
/// with the missing table named.
#[test]
fn a_configuration_the_binary_cannot_serve_stops_it() {
    let output = bridge::attempt(
        &config(""),
        &[("GH_OAUTH_CLIENT_SECRET", fixtures::CLIENT_SECRET)],
    );
    assert!(!output.status.success(), "{}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[[platforms]]"), "{stderr}");
}
