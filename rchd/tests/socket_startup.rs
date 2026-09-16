//! Exercise socket pinning through the real daemon, not a replacement resolver.
//! The unpinned XDG-default migration is deliberately outside this regression.
#![cfg(all(target_os = "linux", feature = "unix-sockets"))]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

struct OwnedDaemon(Child);

impl Drop for OwnedDaemon {
    fn drop(&mut self) {
        // Only this test's child is terminated. Never manage the host service.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fixture() -> PathBuf {
    let root = tempfile::Builder::new()
        .prefix("rch-socket-pin-")
        .tempdir_in("/tmp")
        .unwrap()
        .keep();
    for directory in ["home", "config", "runtime", "empty-bin"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    fs::write(root.join("config/workers.toml"), "workers = []\n").unwrap();
    root
}

fn daemon_command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rchd"));
    command
        .env_clear()
        .env("HOME", root.join("home"))
        .env("RCH_CONFIG_DIR", root.join("config"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        // No systemctl or worker tools: never contact real services/workers.
        .env("PATH", root.join("empty-bin"))
        .env("RCH_NO_SELF_HEALING", "1")
        .env("RCH_LOG_LEVEL", "off")
        .env("RUST_LOG", "off")
        .args([
            "--foreground",
            "--metrics-port",
            "0",
            "--no-hot-reload",
            "--workers-config",
        ])
        .arg(root.join("config/workers.toml"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(fs::File::create(root.join("daemon.stdout")).unwrap()))
        .stderr(Stdio::from(fs::File::create(root.join("daemon.stderr")).unwrap()));
    command
}

fn wait_for_exit(child: &mut OwnedDaemon, root: &Path) -> ExitStatus {
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "daemon did not exit; fixture={root:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn assert_serving(child: &mut OwnedDaemon, expected: &Path, root: &Path) {
    let deadline = Instant::now() + LIMIT;
    while !expected.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "daemon exited before binding {expected:?}; fixture={root:?}"
        );
        assert!(Instant::now() < deadline, "wrong daemon endpoint; fixture={root:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut stream = UnixStream::connect(expected).unwrap();
    stream.set_read_timeout(Some(LIMIT)).unwrap();
    stream.set_write_timeout(Some(LIMIT)).unwrap();
    stream.write_all(b"GET /status\n").unwrap();
    let mut response = String::new();
    stream.take(256 * 1024).read_to_string(&mut response).unwrap();
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
        .expect("complete daemon HTTP response");
    let mut status = headers.lines().next().unwrap().split_whitespace();
    assert!(matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")));
    assert_eq!(status.next(), Some("200"), "{response}");
    let body: serde_json::Value = serde_json::from_str(body).unwrap();
    assert!(body.is_object(), "{body}");
    fs::write(root.join("status-response.json"), body.to_string()).unwrap();
}

#[test]
fn socket_startup_real_daemon_honors_config_environment_and_cli() {
    for case in ["config", "alias-no-config", "alias", "canonical", "cli", "cli-default"] {
        let root = fixture();
        let configured = root.join("configured.sock");
        let alias = root.join("alias.sock");
        let canonical = root.join("canonical.sock");
        let explicit = root.join("explicit.sock");
        let default = root.join("runtime/rch.sock");
        if case != "alias-no-config" {
            fs::write(
                root.join("config/config.toml"),
                format!("[general]\nsocket_path = {:?}\n", configured.to_str().unwrap()),
            )
            .unwrap();
        }
        let mut command = daemon_command(&root);
        if case != "config" {
            command.env("RCH_DAEMON_SOCKET", &alias);
        }
        if matches!(case, "canonical" | "cli" | "cli-default") {
            command.env("RCH_SOCKET_PATH", &canonical);
        }
        let expected = match case {
            "config" => &configured,
            "alias-no-config" | "alias" => &alias,
            "canonical" => &canonical,
            "cli" => {
                command.arg("--socket").arg(&explicit);
                &explicit
            }
            "cli-default" => {
                // An explicit default-valued pin must still beat config/env.
                command.arg("-s").arg(&default);
                &default
            }
            _ => unreachable!(),
        };
        let mut child = OwnedDaemon(command.spawn().unwrap());
        assert_serving(&mut child, expected, &root);
        for other in [&configured, &alias, &canonical, &explicit, &default] {
            if other != expected {
                assert!(!other.exists(), "unexpected listener {other:?}; fixture={root:?}");
            }
        }
    }
}

#[test]
fn socket_startup_invalid_config_or_empty_canonical_refuses_before_binding() {
    for malformed in [true, false] {
        let root = fixture();
        let configured = root.join("configured.sock");
        let alias = root.join("alias.sock");
        let text = if malformed {
            "[general\n".to_owned()
        } else {
            format!("[general]\nsocket_path = {:?}\n", configured.to_str().unwrap())
        };
        let path = root.join("config/config.toml");
        fs::write(&path, &text).unwrap();
        let mut command = daemon_command(&root);
        command.env("RCH_DAEMON_SOCKET", &alias);
        if !malformed {
            command.env("RCH_SOCKET_PATH", "");
        }
        let mut child = OwnedDaemon(command.spawn().unwrap());
        let status = wait_for_exit(&mut child, &root);
        assert!(!status.success(), "invalid configuration was accepted; fixture={root:?}");
        for socket in [configured, alias, root.join("runtime/rch.sock")] {
            assert!(!socket.exists(), "bound {socket:?} before refusing invalid config");
        }
        assert_eq!(fs::read_to_string(path).unwrap(), text);
    }
}
