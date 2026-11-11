//! Runs the Linux shell contract against real processes, not a reimplementation
//! of the embedded protocol. Cancellation uses native worker helpers and the
//! compiled protocol; the remaining policy parser fixture retains its coverage.

#![cfg(target_os = "linux")]

#[path = "support/owned_protocol.rs"]
mod owned_protocol;

use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, PidfdFlags, Signal};

const SELECT_POLICY: &str = r#"
rch_policy_select_file() {
    rch_policy_file=$RCH_TEST_POLICY_FILE
    rch_policy_owner=$(id -u)
}
"#;

// ananicy can place Cargo's test children in SCHED_IDLE, where ps prints NI
// as '-'. Normalize only this owned shell before evaluating the protocol;
// ordinary OTHER/BATCH hosts need no extra executable or scheduler mutation.
const NORMALIZE_SCHEDULER: &str = r#"
rch_test_normalize_scheduler() {
    IFS= read -r rch_test_stat < /proc/self/stat || return 1
    set -- ${rch_test_stat##*) }
    [ "$#" -ge 39 ] || return 1
    shift 38
    case "$1" in 0|3) return 0;; esac
    rch_test_chrt=$(command -v chrt) || {
        printf '%s\n' 'native policy fixture: chrt is required to leave the inherited scheduler class' >&2
        return 1
    }
    "$rch_test_chrt" --other --pid 0 "$$" || {
        printf '%s\n' 'native policy fixture: cannot restore SCHED_OTHER before launch' >&2
        return 1
    }
    IFS= read -r rch_test_stat < /proc/self/stat || return 1
    set -- ${rch_test_stat##*) }
    [ "$#" -ge 39 ] || return 1
    shift 38
    [ "$1" = 0 ]
}
rch_test_normalize_scheduler || exit 125
"#;

#[cfg(target_os = "linux")]
#[test]
fn worker_execution_policy_shell_contract() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/worker_execution_policy.py"
        ))
        .args([
            "WorkerExecutionPolicy.test_nice_grammar_boundaries",
            "WorkerExecutionPolicy.test_slice_and_manager_grammar",
            "WorkerExecutionPolicy.test_invalid_config_never_launches",
            "WorkerExecutionPolicy.test_binary_and_oversized_policy_refused",
            "WorkerExecutionPolicy.test_comments_and_final_line_without_newline",
            "WorkerExecutionPolicy.test_writable_file_refused",
            "WorkerExecutionPolicy.test_symlink_and_hardlink_refused",
            "WorkerExecutionPolicy.test_missing_or_directory_policy_refused_when_selected",
            "WorkerExecutionPolicy.test_no_policy_preserves_legacy_launch",
            "WorkerExecutionPolicy.test_real_priority_applied_before_record_and_payload",
            "WorkerExecutionPolicy.test_posixly_correct_cannot_turn_priority_into_increment",
            "WorkerExecutionPolicy.test_renice_failure_does_not_launch",
            "WorkerExecutionPolicy.test_successful_renice_without_effect_does_not_launch",
            "WorkerExecutionPolicy.test_priority_observation_failure_does_not_launch",
            "WorkerExecutionPolicy.test_missing_systemd_tool_does_not_launch",
            "WorkerExecutionPolicy.test_missing_user_manager_or_inactive_slice_does_not_launch",
            "WorkerExecutionPolicy.test_control_capture_rejects_binary_and_oversized_success",
            "WorkerExecutionPolicy.test_control_capture_preserves_failure_status_and_cleans_timeout",
            "WorkerExecutionPolicy.test_scope_permission_failure_does_not_launch",
            "WorkerExecutionPolicy.test_queued_scope_without_actual_cgroup_move_does_not_launch",
            "WorkerExecutionPolicy.test_real_systemd_placement",
        ])
        .status()
        .expect("Linux execution-policy integration tests require python3");
    assert!(status.success(), "worker execution policy contract failed");
}

struct PolicyFixture {
    directory: tempfile::TempDir,
    nice: i32,
}

impl PolicyFixture {
    fn new() -> Self {
        let directory = owned_protocol::retained("rch-native-policy-");
        let nice = rustix::process::getpriority_process(None).unwrap().max(10);
        let policy = directory.path().join("policy.conf");
        std::fs::write(&policy, format!("version=1\nnice={nice}\n")).unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self { directory, nice }
    }

    fn command(&self, body: &str, arguments: &[&Path]) -> std::process::Command {
        let script = format!(
            "{NORMALIZE_SCHEDULER}\n{}\n{SELECT_POLICY}\n{body}",
            rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
        );
        let mut command = owned_protocol::shell(&script, arguments);
        command.env(
            "RCH_TEST_POLICY_FILE",
            self.directory.path().join("policy.conf"),
        );
        command
    }

    fn run(&self, body: &str, arguments: &[&Path]) -> Output {
        owned_protocol::run(self.command(body, arguments), Duration::from_secs(12))
    }

    fn start(&self, build: &str) -> LiveBuild {
        let record = self.directory.path().join(format!("{build}.pgid"));
        let ready = self.directory.path().join(format!("{build}.ready"));
        let body = r#"
rch_remote_record "$1" "$2" || exit $?
/bin/sh -c 'trap "" TERM; printf "%s\n" "$$" > "$1"; exec /bin/sleep 60' rch-policy-survivor "$3" &
wait
"#;
        let child = self
            .command(body, &[&record, Path::new(build), &ready])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut live = LiveBuild {
            child,
            record,
            descendant: None,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(text) = std::fs::read_to_string(&ready)
                && let Ok(pid) = text.trim().parse::<i32>()
            {
                let pid = Pid::from_raw(pid).unwrap();
                live.descendant = Some((
                    pid,
                    rustix::process::pidfd_open(pid, PidfdFlags::empty()).unwrap(),
                ));
                return live;
            }
            assert!(!owned_protocol::exited(&live.child), "policy launch failed");
            assert!(
                Instant::now() < deadline,
                "policy build did not become ready"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn cancel(&self, record: &Path, build: &str, mode: &str) -> Output {
        self.run(
            "rch_remote_cancel \"$1\" \"$2\" \"$3\"",
            &[record, Path::new(build), Path::new(mode)],
        )
    }
}

struct LiveBuild {
    child: Child,
    record: PathBuf,
    descendant: Option<(Pid, OwnedFd)>,
}

impl LiveBuild {
    fn wait(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !owned_protocol::exited(&self.child) {
            assert!(Instant::now() < deadline, "cancelled leader remains alive");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for LiveBuild {
    fn drop(&mut self) {
        // No observation reaps this leader; even early exit keeps the group
        // number pinned until teardown, including before descendant readiness.
        let pid = Pid::from_child(&self.child);
        if rustix::process::getpgid(Some(pid)).ok() == Some(pid) {
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
        let _ = self.child.kill();
        if let Some((_, descriptor)) = &self.descendant {
            let _ = rustix::process::pidfd_send_signal(descriptor, Signal::KILL);
        }
        let _ = self.child.wait();
    }
}

#[test]
fn native_real_term_escalation_reaps_priority_bound_descendant() {
    let fixture = PolicyFixture::new();
    let mut live = fixture.start("42");
    for pid in [
        Pid::from_child(&live.child),
        live.descendant.as_ref().unwrap().0,
    ] {
        assert_eq!(
            rustix::process::getpriority_process(Some(pid)).unwrap(),
            fixture.nice
        );
    }
    let output = fixture.cancel(&live.record, "42", "term");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    live.wait();
    let output = fixture.run(
        "rch_read_record \"$1\" 42 && rch_group_state",
        &[&live.record],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

#[test]
fn native_fresh_channel_kill_mode_after_original_pipes_close() {
    let fixture = PolicyFixture::new();
    let mut live = fixture.start("42");
    drop(live.child.stdout.take());
    drop(live.child.stderr.take());
    assert!(!owned_protocol::exited(&live.child));
    let output = fixture.cancel(&live.record, "42", "kill");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    live.wait();
    let repeated = fixture.cancel(&live.record, "42", "kill");
    assert_eq!(repeated.status.code(), Some(0), "{repeated:?}");
}

#[test]
fn native_recovery_rejects_mismatched_identity_without_signalling() {
    let fixture = PolicyFixture::new();
    let mut live = fixture.start("42");
    let refused = fixture.cancel(&live.record, "43", "term");
    assert_eq!(refused.status.code(), Some(43), "{refused:?}");
    assert!(!owned_protocol::exited(&live.child));
    let stopped = fixture.cancel(&live.record, "42", "term");
    assert_eq!(stopped.status.code(), Some(0), "{stopped:?}");
    live.wait();
}

#[test]
fn native_concurrent_builds_keep_independent_process_authority() {
    let fixture = PolicyFixture::new();
    let mut first = fixture.start("42");
    let mut second = fixture.start("43");
    assert_ne!(first.child.id(), second.child.id());
    let evidence = std::fs::read(&second.record).unwrap();
    let stopped = fixture.cancel(&first.record, "42", "term");
    assert_eq!(stopped.status.code(), Some(0), "{stopped:?}");
    first.wait();
    assert!(!owned_protocol::exited(&second.child));
    assert_eq!(std::fs::read(&second.record).unwrap(), evidence);
    let stopped = fixture.cancel(&second.record, "43", "term");
    assert_eq!(stopped.status.code(), Some(0), "{stopped:?}");
    second.wait();
}
