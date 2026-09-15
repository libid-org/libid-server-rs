//! The binary: it starts on a configuration file, answers, and stops on
//! SIGINT; a configuration it cannot serve stops it before it binds.

use std::{
    io::{
        BufRead,
        BufReader,
        Read,
        Write,
    },
    process::{
        Child,
        ChildStdout,
        Command,
        ExitStatus,
        Stdio,
    },
};

use libid_server_rs::fixtures::{
    self,
    Distribution,
};

/// A configuration file for the binary, pointed at the shared Distribution.
fn config_file(platforms: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "libid-startup-{}-{:?}.toml",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(
        &path,
        format!(
            "allowed_app_origins = [\"https://app.example\"]\n\
             ccdp_origin = \"{}\"\n{platforms}",
            Distribution::shared().origin(),
        ),
    )
    .expect("a scratch configuration file");
    path
}

/// The binary, started on `config` with nothing but the configuration path,
/// the loopback port to bind and the log filter in its environment, and its
/// output captured.
fn binary(config: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_libid-server-rs"))
        .env_clear()
        // The coverage profile path, when this test runs under one.
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        .env("LIBID_CONFIG", config)
        // Where a test's bridge listens is not a key of its file.
        .env("HOST", "127.0.0.1")
        .env("PORT", "0")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts")
}

/// The binary, bound and serving.
struct Started {
    child: Child,
    stdout: BufReader<ChildStdout>,
    /// The address it listens on.
    address: String,
}

impl Started {
    /// Start the binary on `config` and wait for it to bind: the address is
    /// the one thing it says before it serves.
    fn on(config: &std::path::Path) -> Started {
        let mut child = binary(config);
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let address = loop {
            let mut line = String::new();
            assert!(
                stdout.read_line(&mut line).unwrap() > 0,
                "the binary exited before binding"
            );
            if let Some(rest) = line.split("listening on ").nth(1) {
                break rest.trim().to_owned();
            }
        };
        Started {
            child,
            stdout,
            address,
        }
    }

    /// One request on a connection of its own: the status and the body of
    /// the answer.
    fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (u16, String) {
        let mut socket = std::net::TcpStream::connect(&self.address).unwrap();
        let mut text =
            format!("{method} {path} HTTP/1.1\r\nhost: bridge\r\nconnection: close\r\n");
        for (name, value) in headers {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
        text.push_str(&format!("content-length: {}\r\n\r\n{body}", body.len()));
        socket.write_all(text.as_bytes()).unwrap();
        let mut answer = String::new();
        socket.read_to_string(&mut answer).unwrap();
        let (head, body) = answer
            .split_once("\r\n\r\n")
            .expect("a status line, headers and a body");
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("a status code");
        (status, body.to_owned())
    }

    /// SIGINT the binary: its exit status and what it said after the signal.
    fn interrupted(mut self) -> (ExitStatus, String) {
        let interrupted = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(interrupted.success());
        let exit = self.child.wait().unwrap();
        let mut rest = String::new();
        self.stdout.read_to_string(&mut rest).unwrap();
        (exit, rest)
    }
}

/// The binary binds, answers `/health`, and exits `0` on SIGINT.
#[test]
fn the_binary_serves_until_interrupted() {
    let config = config_file(&format!(
        "[[platforms]]\nid = \"github\"\nclient_id = \"{}\"\nversions = [1]\n\
         client_credential = \"{}\"\n",
        fixtures::CLIENT_ID,
        fixtures::CLIENT_CREDENTIAL
    ));
    let bridge = Started::on(&config);

    let (status, body) = bridge.request("GET", "/health", &[], "");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, "OK");

    let (exit, rest) = bridge.interrupted();
    assert!(exit.success(), "{exit}");
    assert!(rest.contains("shutting down"), "{rest}");
}

/// A deployment enabling X alone starts, publishes the X entry and no github
/// entry, and answers the former token path with `404`.
#[test]
fn an_x_only_deployment_starts_and_serves_no_token_route() {
    let config = config_file(
        "[[platforms]]\nid = \"x\"\nclient_id = \"WHRlc3RjbGllbnQ6MTpjaQ\"\n\
         versions = [1]\n",
    );
    let bridge = Started::on(&config);

    let (status, body) = bridge.request(
        "GET",
        "/api/v1/ceremony/config",
        &[("origin", "https://app.example")],
        "",
    );
    assert_eq!(status, 200, "{body}");
    let record: serde_json::Value = serde_json::from_str(&body).expect("a JSON record");
    assert_eq!(
        record["platforms"]["x"]["clientId"],
        "WHRlc3RjbGllbnQ6MTpjaQ"
    );
    assert_eq!(
        record["platforms"]["x"]["ceremonyVersions"],
        serde_json::json!([1])
    );
    assert!(record["platforms"].get("github").is_none());

    let (status, body) = bridge.request(
        "POST",
        "/api/v1/ceremony/github-token",
        &[
            ("origin", Distribution::shared().origin()),
            ("content-type", "application/json"),
        ],
        r#"{"code":"6b7f2c1d9e4a8035","codeVerifier":"iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I","notaryAddress":"https://127.0.0.1:7048"}"#,
    );
    assert_eq!(status, 404, "{body}");

    let (exit, _) = bridge.interrupted();
    assert!(exit.success(), "{exit}");
}

/// A configuration enabling no platform stops the binary before it binds,
/// with the missing table named.
#[test]
fn a_configuration_the_binary_cannot_serve_stops_it() {
    let config = config_file("");
    let output = binary(&config).wait_with_output().unwrap();
    assert!(!output.status.success(), "{}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[[platforms]]"), "{stderr}");
}

/// A run that names no configuration file stops before it binds, naming the
/// file it was not given rather than the platforms the file would carry.
#[test]
fn a_run_with_no_configuration_file_names_it() {
    let output = Command::new(env!("CARGO_BIN_EXE_libid-server-rs"))
        .env_clear()
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        .env("HOST", "127.0.0.1")
        .env("PORT", "0")
        .output()
        .expect("the binary runs");

    assert!(!output.status.success(), "{}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("LIBID_CONFIG"), "{stderr}");
    assert!(!stderr.contains("[[platforms]]"), "{stderr}");
}
