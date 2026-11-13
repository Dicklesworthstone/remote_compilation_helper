//! Bounded native harness for the actual worker shell protocol.

use std::fs::File;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

pub fn retained(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .disable_cleanup(true)
        .tempdir()
        .expect("retain protocol fixture")
}

pub fn shell(body: &str, arguments: &[&Path]) -> Command {
    let worker = rch_common::testing::worker_binary();
    let mut command = Command::new(&worker);
    command
        .args(["setsid", "--", "/bin/sh", "-c", body, "rch-native-protocol"])
        .args(arguments)
        .env("RCH_WKR_BIN", worker)
        .env("RCH_TIMING_SCALE", "1");
    command
}

pub fn exited(child: &Child) -> bool {
    rustix::process::waitid(
        WaitId::Pid(Pid::from_child(child)),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .expect("observe owned child without reaping")
    .is_some()
}

fn revoke_group(child: &mut Child) {
    let pid = Pid::from_child(child);
    // The unreaped direct child pins its identity, including after exit.
    if rustix::process::getpgid(Some(pid)).ok() == Some(pid) {
        let _ = rustix::process::kill_process_group(pid, Signal::KILL);
    }
    let _ = child.kill();
}

struct Owned(Option<Child>);

impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            revoke_group(&mut child);
            let _ = child.wait();
        }
    }
}

pub fn run(mut command: Command, timeout: Duration) -> Output {
    let directory = retained("rch-protocol-observation-");
    let stdout = directory.path().join("stdout");
    let stderr = directory.path().join("stderr");
    let mut child = Owned(Some(
        command
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .expect("start actual protocol shell"),
    ));
    let deadline = Instant::now() + timeout;
    loop {
        if exited(child.0.as_ref().unwrap()) {
            let mut completed = child.0.take().unwrap();
            // Even a regression that returned early cannot strand descendants.
            // Revoke the pinned group before reaping its exited leader.
            revoke_group(&mut completed);
            let status = completed.wait().unwrap();
            return Output {
                status,
                stdout: std::fs::read(&stdout).unwrap(),
                stderr: std::fs::read(&stderr).unwrap(),
            };
        }
        assert!(
            Instant::now() < deadline,
            "protocol exceeded {timeout:?}: stdout={:?}, stderr={:?}",
            std::fs::read(&stdout).unwrap(),
            std::fs::read(&stderr).unwrap()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
