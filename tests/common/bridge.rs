//! The bridge as a process: the binary started on a configuration file, and
//! plain HTTP/1.1 requests to it over TCP.

use std::{
    io::{
        BufRead,
        BufReader,
        Read,
        Write,
    },
    net::{
        SocketAddr,
        TcpStream,
    },
    process::{
        Child,
        Command,
        Stdio,
    },
    sync::{
        Arc,
        Mutex,
    },
};

/// The binary's command with `config` written to a file it is pointed at and
/// `env` on top of an otherwise empty environment.
fn command(config: &str, env: &[(&str, &str)]) -> Command {
    let path = std::env::temp_dir().join(format!(
        "libid-bridge-{}-{:?}.toml",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, config).expect("a scratch configuration file");
    let mut command = Command::new(env!("CARGO_BIN_EXE_libid-server-rs"));
    command
        .env_clear()
        // The coverage profile path, when the test runs under one.
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        .env("LIBID_CONFIG", &path)
        .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// What the binary printed and how it exited, for a configuration it does
/// not start on.
pub fn attempt(config: &str, env: &[(&str, &str)]) -> std::process::Output {
    command(config, env)
        .spawn()
        .expect("the binary starts")
        .wait_with_output()
        .expect("the binary exits")
}

/// A running bridge.
pub struct Bridge {
    child: Child,
    /// Where it listens.
    pub address: SocketAddr,
    /// Everything it has printed after the address, forwarded to the test
    /// output as it arrives.
    printed: Arc<Mutex<String>>,
    forwarding: Option<std::thread::JoinHandle<()>>,
}

impl Bridge {
    /// The binary on `config` with `env`, once it has said where it listens.
    pub fn started(config: &str, env: &[(&str, &str)]) -> Bridge {
        let mut child = command(config, env).spawn().expect("the binary starts");
        let mut stdout = BufReader::new(child.stdout.take().expect("a piped stdout"));
        let address = loop {
            let mut line = String::new();
            let read = stdout.read_line(&mut line).expect("the binary's stdout");
            assert!(
                read > 0,
                "the binary exited before binding: {}",
                stderr_of(&mut child)
            );
            eprint!("{line}");
            if let Some(rest) = line.split("listening on ").nth(1) {
                break rest.trim().parse().expect("the address the binary printed");
            }
        };
        let printed = Arc::new(Mutex::new(String::new()));
        let sink = printed.clone();
        let forwarding = std::thread::spawn(move || {
            for line in stdout.lines().map_while(Result::ok) {
                eprintln!("{line}");
                sink.lock().unwrap().push_str(&line);
                sink.lock().unwrap().push('\n');
            }
        });
        Bridge {
            child,
            address,
            printed,
            forwarding: Some(forwarding),
        }
    }

    /// `SIGINT`, then the exit status and everything printed after the
    /// address.
    pub fn interrupted(mut self) -> (std::process::ExitStatus, String) {
        let signalled = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(signalled.success());
        let exit = self.child.wait().expect("the binary exits");
        if let Some(forwarding) = self.forwarding.take() {
            let _ = forwarding.join();
        }
        let printed = self.printed.lock().unwrap().clone();
        (exit, printed)
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stderr_of(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut text);
    }
    text
}

/// One HTTP/1.1 response, read whole over a connection that closes after it.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    /// The reply of the bridge at `address` to one request.
    pub fn to(
        address: SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Reply {
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nhost: {address}\r\nconnection: close\r\ncontent-length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);

        let mut socket = TcpStream::connect(address).expect("the bridge accepts");
        socket
            .write_all(request.as_bytes())
            .expect("the request is sent");
        let mut raw = Vec::new();
        socket.read_to_end(&mut raw).expect("the response is read");
        let raw = String::from_utf8_lossy(&raw);

        let (head, body) = raw
            .split_once("\r\n\r\n")
            .expect("a response head before the body");
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse().ok())
            .expect("a status line");
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        Reply {
            status,
            headers,
            body: body.to_owned(),
        }
    }

    /// The first header named `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The `message` a refusal carries; empty for any other body.
    pub fn message(&self) -> String {
        serde_json::from_str::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| v["message"].as_str().map(str::to_owned))
            .unwrap_or_default()
    }
}
