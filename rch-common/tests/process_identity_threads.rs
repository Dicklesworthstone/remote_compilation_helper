//! Native regression for the Rust ownership observer, not the shell protocol.
//! Reuse the existing bounded pthread fixture: its leader exits while a second
//! thread continues writing. Requires Linux, Python 3 and a C compiler.
#![cfg(target_os = "linux")]

use rch_common::process_identity::{
    OwnerPresence, ProcessIdentity, ProcessObservation, ProcessStart, current_process_identity,
    observe_process, owner_presence,
};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Never signal a guessed or previously reaped PID. Child owns the
        // unreaped process; the C fixture has no child processes of its own.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn until(mut condition: impl FnMut() -> bool, detail: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "{detail}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stat_fields(pid: u32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(
        stat.rsplit_once(") ")?
            .1
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
    )
}

#[test]
fn dead_main_thread_does_not_release_a_live_process_lease() {
    let directory = tempfile::tempdir().expect("native process fixture");
    let factory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/remote_process_threads.py");
    let compiled = Command::new("python3")
        .args([
            "-I",
            "-c",
            "import runpy,sys; from pathlib import Path; runpy.run_path(sys.argv[1])['build_fixture'](Path(sys.argv[2]))",
        ])
        .arg(factory)
        .arg(directory.path())
        .stdin(Stdio::null())
        .output()
        .expect("compile existing pthread fixture (requires python3 and cc)");
    assert!(compiled.status.success(), "{compiled:?}");
    let mut child = OwnedChild(
        Command::new(directory.path().join("zombie_threads"))
            .arg(directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start owned pthread fixture"),
    );
    let pid = child.0.id();
    until(
        || {
            stat_fields(pid).is_some_and(|fields| {
                fields.first().is_some_and(|state| state == "Z")
                    && fields.get(17).is_some_and(|threads| threads == "2")
            })
        },
        "main pthread never reached Z with a surviving thread",
    );
    let fields = stat_fields(pid).expect("retained group leader");
    let expected = ProcessIdentity {
        boot_id: current_process_identity()
            .expect("observer identity")
            .boot_id,
        start: ProcessStart::Linux {
            ticks: fields[19].parse().expect("kernel birth ticks"),
        },
    };
    let writes = directory.path().join("writes");
    until(|| writes.exists(), "surviving thread did not write");
    let before = std::fs::metadata(&writes).unwrap().len();
    assert_eq!(
        observe_process(pid),
        ProcessObservation::Present(expected.clone()),
        "the zombie main thread does not describe the whole process"
    );
    assert_eq!(owner_presence(pid, Some(&expected)), OwnerPresence::Live);
    until(
        || std::fs::metadata(&writes).unwrap().len() > before,
        "no thread was executing while ownership was observed",
    );
    // Actual process death must still release ownership. Do not reap before
    // killing: retaining the Child prevents PID reuse throughout the fixture.
    child.0.kill().expect("terminate owned fixture");
    child.0.wait().expect("reap owned fixture");
    assert_eq!(observe_process(pid), ProcessObservation::Absent);
    assert_eq!(owner_presence(pid, Some(&expected)), OwnerPresence::Absent);
}
