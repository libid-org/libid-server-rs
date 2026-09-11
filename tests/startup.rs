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
        Command,
        Stdio,
    },
};

use libid_server_rs::fixtures::{
    self,
    Distribution,
};

/// A configuration file for the binary, pointed at the shared Distribution
/// and a wire port nothing listens on.
fn config_file(platforms: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "libid-startup-{}-{:?}.toml",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(
        &path,
        format!(
            "host = \"127.0.0.1\"\nport = 0\nnotary_wire_port = {}\n\
             allowed_app_origins = [\"https://app.example\"]\n\
             ccdp_origin = \"{}\"\n{platforms}",
            fixtures::dead_port(),
            Distribution::shared().origin(),
        ),
    )
    .expect("a scratch configuration file");
    path
}

/// The binary, started on `config` with the secret in its environment and its
/// output captured.
fn binary(config: &std::path::Path) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_libid-server-rs"))
        .env_clear()
        // The coverage profile path, when this test runs under one.
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        .env("LIBID_CONFIG", config)
        .env("GH_OAUTH_CLIENT_SECRET", fixtures::CLIENT_SECRET)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts")
}

/// The binary binds, answers `/health`, and exits `0` on SIGINT.
#[test]
fn the_binary_serves_until_interrupted() {
    let config = config_file(&format!(
        "[[platforms]]\nid = \"github\"\nclient_id = \"{}\"\nversions = [1]\n",
        fixtures::CLIENT_ID
    ));
    let mut child = binary(&config);

    // The address is the one thing the binary says before it serves.
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

    let mut socket = std::net::TcpStream::connect(&address).unwrap();
    socket
        .write_all(b"GET /health HTTP/1.1\r\nhost: bridge\r\nconnection: close\r\n\r\n")
        .unwrap();
    let mut answer = String::new();
    socket.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    let interrupted = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(interrupted.success());
    let exit = child.wait().unwrap();
    assert!(exit.success(), "{exit}");
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    assert!(rest.contains("shutting down"), "{rest}");
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
