//! Shared CPU admission through real native worker processes and their normal
//! UID-wide registry. This proves local cross-process exclusion and reclaim;
//! it does not qualify remote fleet behavior or kernel CPU quotas.

#![cfg(unix)]

use std::fs;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use serde_json::{Value, json};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");
const CPU_MARKER: &str = "RCH_NATIVE_CPU_TEST_CPU_BUDGET:";
const DISK_MARKER: &str = "RCH_NATIVE_CPU_TEST_DISK_BUDGET:";

struct Job {
    root: PathBuf,
    child: Option<Child>,
    pid: Pid,
}

impl Job {
    fn spawn(slots: Value) -> Self {
        let root = tempfile::Builder::new()
            .prefix("rch-native-cpu-")
            .tempdir()
            .unwrap()
            .keep()
            .canonicalize()
            .unwrap();
        let plan = json!({
            "probe": [&root], "output": [&root], "receipt": root.join("receipt"),
            "cpu_slots": slots,
        });
        let child = Command::new(WORKER)
            .args(["disk-supervise", "16777216", "0", DISK_MARKER])
            .arg(&root)
            .arg(plan.to_string())
            .args([
                "tracked", "/bin/sh", "-c",
                "printf ready > started; while [ ! -f release ]; do sleep 0.05; done; printf built > artifact",
            ])
            .env("RCH_TIMING_SCALE", "1")
            .env("TOKIO_WORKER_THREADS", "0")
            .current_dir(&root)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = Pid::from_child(&child);
        Self {
            root,
            child: Some(child),
            pid,
        }
    }

    fn started(&self) -> bool {
        fs::metadata(self.root.join("started")).is_ok_and(|info| info.len() > 0)
    }

    fn exited(&self) -> bool {
        rustix::process::waitid(
            WaitId::Pid(self.pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
        .unwrap()
        .is_some()
    }

    fn finish(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !self.exited() {
            assert!(
                Instant::now() < deadline,
                "worker did not finish: {}",
                self.root.display()
            );
            thread::sleep(Duration::from_millis(20));
        }
        // The leader remains unreaped through the last cleanup signal, so a
        // recycled historical PID never becomes authority to kill a group.
        let _ = rustix::process::kill_process_group(self.pid, Signal::KILL);
        self.child.take().unwrap().wait_with_output().unwrap()
    }

    fn refusal(&self) -> Value {
        let text = fs::read_to_string(self.root.join("receipt")).unwrap();
        assert_eq!(text.lines().count(), 1, "{text:?}");
        assert!(
            !text.contains(DISK_MARKER),
            "CPU refusal became a disk failure: {text}"
        );
        serde_json::from_str(text.trim_end().strip_prefix(CPU_MARKER).unwrap()).unwrap()
    }

    fn stop_owned_group(&self) {
        rustix::process::kill_process_group(self.pid, Signal::KILL).unwrap();
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = rustix::process::kill_process_group(self.pid, Signal::KILL);
            let _ = child.wait();
        }
    }
}

fn assert_refusal(job: &Job, requested: u32, capacity: u32) {
    assert!(!job.started(), "refused payload ran");
    let value = job.refusal();
    assert_eq!(value["reason"], "capacity_busy");
    assert_eq!(value["started"], false);
    assert_eq!(value["requested_slots"], requested);
    assert_eq!(value["capacity_slots"], capacity);
    assert!(value["reserved_slots"].as_u64().is_some());
}

fn wait_for_outcome(job: &Job) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !job.started() && !job.exited() {
        assert!(
            Instant::now() < deadline,
            "no admission outcome: {}",
            job.root.display()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn native_cpu_admission_is_atomic_and_reclaims_only_after_owner_exit() {
    let probe = Command::new(WORKER)
        .args(["disk-supervise", "probe-cpu"])
        .env("TOKIO_WORKER_THREADS", "0")
        .output()
        .unwrap();
    assert!(probe.status.success(), "{probe:?}");
    assert_eq!(probe.stdout, b"rch-wkr disk-supervise cpu-v1\n");
    assert!(probe.stderr.is_empty());

    for slots in [
        Value::Null,
        json!(0),
        json!(-1),
        json!(1.0),
        json!("1"),
        json!(true),
        json!(u64::from(u32::MAX) + 1),
    ] {
        let job = Job::spawn(slots);
        let root = job.root.clone();
        let output = job.finish();
        assert_eq!(output.status.code(), Some(120), "{output:?}");
        assert!(!root.join("started").exists());
    }

    let capacity = u32::try_from(thread::available_parallelism().unwrap().get()).unwrap();
    // A normal suite can have unrelated legacy worker tests using the real
    // registry. Wait for their owners to leave; never clear or replace it.
    let admission_deadline = Instant::now() + Duration::from_secs(90);
    let (winner, loser) = loop {
        let left = Job::spawn(json!(capacity));
        let right = Job::spawn(json!(capacity));
        let outcome_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(
                !(left.started() && right.started()),
                "both workers consumed the entire CPU pool"
            );
            if (left.started() && right.exited())
                || (right.started() && left.exited())
                || (left.exited() && right.exited())
            {
                break;
            }
            assert!(
                Instant::now() < outcome_deadline,
                "competing native workers did not settle"
            );
            thread::sleep(Duration::from_millis(20));
        }
        if left.started() {
            break (left, right);
        }
        if right.started() {
            break (right, left);
        }
        assert_refusal(&left, capacity, capacity);
        assert_refusal(&right, capacity, capacity);
        assert_eq!(left.finish().status.code(), Some(120));
        assert_eq!(right.finish().status.code(), Some(120));
        assert!(
            Instant::now() < admission_deadline,
            "unrelated worker owners kept the CPU pool busy"
        );
        thread::sleep(Duration::from_millis(100));
    };
    assert_refusal(&loser, capacity, capacity);
    assert!(loser.refusal()["reserved_slots"].as_u64().unwrap() >= u64::from(capacity));
    assert_eq!(loser.finish().status.code(), Some(120));

    // A fresh dispatcher sees the same active owner despite a distinct staging
    // directory. No payload is allowed until the old group's writers stop.
    let blocked = Job::spawn(json!(1));
    wait_for_outcome(&blocked);
    assert_refusal(&blocked, 1, capacity);
    assert_eq!(blocked.finish().status.code(), Some(120));

    winner.stop_owned_group();
    assert!(!winner.finish().status.success());

    // The normal admission census reclaims the dead group. Keep the old ledger
    // intact and exercise another worker process, rather than simulating release.
    let reuse_deadline = Instant::now() + Duration::from_secs(90);
    let replacement = loop {
        let job = Job::spawn(json!(capacity));
        wait_for_outcome(&job);
        if job.started() {
            break job;
        }
        assert_refusal(&job, capacity, capacity);
        assert_eq!(job.finish().status.code(), Some(120));
        assert!(
            Instant::now() < reuse_deadline,
            "worker capacity was not reclaimed"
        );
        thread::sleep(Duration::from_millis(100));
    };
    let root = replacement.root.clone();
    fs::write(root.join("release"), b"release").unwrap();
    let output = replacement.finish();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(root.join("artifact")).unwrap(), b"built");
    let receipt = fs::read_to_string(root.join("receipt")).unwrap();
    assert!(
        receipt.starts_with("RCH_NATIVE_CPU_TEST_DISK_USAGE:"),
        "{receipt:?}"
    );
    assert!(!receipt.contains(CPU_MARKER));
}
