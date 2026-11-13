//! Scope receipt/cleanup contract plus an opt-in real systemd lifecycle test.
//! The fast fixture doubles systemd/cgroupfs, not the production protocol.

#![cfg(target_os = "linux")]

#[path = "support/owned_protocol.rs"]
mod owned_protocol;

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

const INVOCATION: &str = "1234567890abcdef1234567890abcdef";

#[cfg(target_os = "linux")]
#[test]
fn remote_scope_recovery_contract() {
    // Keep the existing environment-driven live gate when the complete legacy
    // target runs. Native-only validation can select the ignored case directly.
    if std::env::var_os("RCH_TEST_SYSTEMD_SLICE").is_some_and(|value| !value.is_empty()) {
        native_setsid_descendant_is_reaped_after_leader_disconnect();
    }
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/remote_scope_recovery.py"
        ))
        .args([
            "ScopeProtocol.test_receipt_roundtrip_and_empty_original_group_does_not_mean_empty_scope",
            "ScopeProtocol.test_probe_opens_but_does_not_fire_kill",
            "ScopeProtocol.test_publisher_binds_scope_in_one_atomic_required_record",
            "ScopeProtocol.test_scope_without_cleanup_capability_starts_no_payload",
            "ScopeProtocol.test_slow_scope_snapshots_admit_only_after_both_generation_checks",
            "ScopeProtocol.test_unavailable_scope_snapshots_never_publish_or_start_payload",
            "ScopeProtocol.test_binding_ready_after_four_unknown_observations_publishes_once",
            "ScopeProtocol.test_binding_failure_expires_at_scaled_or_inherited_deadline",
            "ScopeProtocol.test_frozen_binding_clock_refuses_without_publication",
            "ScopeProtocol.test_slow_scope_state_and_kill_preserve_pinned_generation_authority",
            "ScopeProtocol.test_generation_change_during_slow_pinned_snapshot_never_authorizes_kill",
            "ScopeProtocol.test_descriptor_pin_survives_path_replacement",
            "ScopeProtocol.test_reused_systemd_generation_is_never_signalled",
            "ScopeProtocol.test_changed_boot_uid_namespace_mount_and_inode_refuse",
            "ScopeProtocol.test_invalid_or_incomplete_binding_is_not_a_legacy_record",
            "ScopeProtocol.test_wrong_build_and_unsafe_record_are_refused",
            "ScopeProtocol.test_failed_or_legacy_read_clears_scope_authority",
            "ScopeProtocol.test_no_kill_primitive_or_wrong_cgroup_type_refuses_admission",
            "ScopeProtocol.test_incomplete_populated_evidence_is_unknown",
            "ScopeProtocol.test_incomplete_or_contradictory_manager_snapshot_is_unknown",
            "ScopeProtocol.test_gc_requires_terminal_manager_and_physical_absence",
            "ScopeProtocol.test_symlinked_scope_does_not_authorize_kill_or_absence",
            "ScopeProtocol.test_concurrent_scopes_keep_distinct_cleanup_authority",
        ])
        .status()
        .expect("Linux scope-recovery integration tests require python3");
    assert!(status.success(), "remote scope recovery contract failed");
}

// These cancellation cases replace the corresponding legacy methods above.
// The manager and filesystem-type doubles are unchanged; files, descriptors,
// process census, native collector, timeout and production protocol are real.
struct ScopeFixture {
    _sentinel: GroupSentinel,
    directory: tempfile::TempDir,
    scope: PathBuf,
    snapshot: PathBuf,
    record: PathBuf,
    fields: Vec<String>,
    env: BTreeMap<String, String>,
}

// Keep the exited session leader as an unreaped direct child. Its PID cannot
// be recycled into a foreign process while fixture receipts still name it.
struct GroupSentinel(Child);

impl Drop for GroupSentinel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn identity(path: &Path) -> String {
    let metadata = path.metadata().unwrap();
    format!("{}.{}", metadata.dev(), metadata.ino())
}

fn read(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn write(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
    std::fs::write(path, bytes).unwrap();
}

fn status(output: &Output, expected: i32) {
    assert_eq!(output.status.code(), Some(expected), "{output:?}");
}

impl ScopeFixture {
    fn new() -> Self {
        let directory = owned_protocol::retained("rch-native-scope-recovery-");
        let root = directory.path();
        for path in ["cgroups/jobs.slice", "manager", "bin"] {
            std::fs::create_dir_all(root.join(path)).unwrap();
        }
        let sentinel = GroupSentinel(
            Command::new(rch_common::testing::worker_binary())
                .args(["setsid", "--", "/bin/sh", "-c", "exit 0"])
                .spawn()
                .unwrap(),
        );
        let pgid = sentinel.0.id();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !owned_protocol::exited(&sentinel.0) {
            assert!(Instant::now() < deadline, "scope sentinel did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid = rustix::process::Pid::from_child(&sentinel.0);
        assert_eq!(rustix::process::getpgid(Some(pid)).unwrap(), pid);
        let boot = read("/proc/sys/kernel/random/boot_id").trim().to_owned();
        let unit = format!("rch-{boot}-{pgid}-1.scope");
        let cgroup = format!("/jobs.slice/{unit}");
        let scope = root.join("cgroups").join(cgroup.trim_start_matches('/'));
        std::fs::create_dir(&scope).unwrap();
        write(scope.join("cgroup.events"), "populated 1\nfrozen 0\n");
        write(scope.join("cgroup.type"), "domain\n");
        write(scope.join("cgroup.kill"), "");
        let snapshot = root.join("manager").join(unit);
        write(
            &snapshot,
            format!(
                "LoadState=loaded\nActiveState=active\nInvocationID={INVOCATION}\nControlGroup={cgroup}\n"
            ),
        );
        let fields = vec![
            "RCH_REMOTE_PROCESS_V2".into(),
            "42".into(),
            boot,
            pgid.to_string(),
            "1".into(),
            rustix::process::getuid().as_raw().to_string(),
            "user".into(),
            INVOCATION.into(),
            Path::new("/proc/self/ns/cgroup")
                .metadata()
                .unwrap()
                .ino()
                .to_string(),
            identity(&root.join("cgroups")),
            identity(&scope),
            cgroup,
        ];
        let record = root.join(format!("{pgid}-1.pgid"));
        write(&record, format!("{}\n", fields.join(":")));
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        let env = BTreeMap::from([
            ("RCH_SCOPE_TEST_ROOT".into(), root.to_str().unwrap().into()),
            (
                "PATH".into(),
                format!("{}/bin:/usr/bin:/bin", root.display()),
            ),
        ]);
        let fixture = Self {
            _sentinel: sentinel,
            directory,
            scope,
            snapshot,
            record,
            fields,
            env,
        };
        fixture.executable(
            "stat",
            r#"
case "$1" in -fc|-fLc) printf '%s\n' cgroup2fs;; *) exec /usr/bin/stat "$@";; esac
"#,
        );
        fixture.executable("systemctl", SYSTEMCTL);
        fixture
    }

    fn root(&self) -> &Path {
        self.directory.path()
    }

    fn executable(&self, name: &str, body: &str) {
        let path = self.root().join("bin").join(name);
        write(&path, format!("#!/bin/sh\n{body}"));
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn run(&self, body: &str, arguments: &[&Path]) -> Output {
        let script = format!(
            "{}\nrch_scope_root() {{ printf '%s\\n' \"$RCH_SCOPE_TEST_ROOT/cgroups\"; }}\n{body}",
            rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
        );
        let mut command = owned_protocol::shell(&script, arguments);
        command.envs(&self.env);
        owned_protocol::run(command, Duration::from_secs(12))
    }

    fn operation(&self, operation: &str) -> Output {
        self.run(
            "rch_read_record \"$1\" 42 || exit $?\nrch_scope_operation \"$2\"",
            &[&self.record, Path::new(operation)],
        )
    }

    fn cancel(&self, mode: &str) -> Output {
        self.run(
            "rch_remote_cancel \"$1\" 42 \"$2\"",
            &[&self.record, Path::new(mode)],
        )
    }

    fn receipt(&self) -> (u64, Vec<u8>) {
        (
            self.record.metadata().unwrap().ino(),
            std::fs::read(&self.record).unwrap(),
        )
    }

    fn unchanged(&self, receipt: &(u64, Vec<u8>)) {
        assert_eq!(&self.receipt(), receipt);
        assert!(
            !self.root().join("payload").exists(),
            "recovery must never replay payload"
        );
    }

    fn kill(&self) -> String {
        read(self.scope.join("cgroup.kill"))
    }
    fn reset_kill(&self) {
        write(self.scope.join("cgroup.kill"), "");
    }
    fn reset_clock(&self) {
        write(self.root().join("clock"), "100\n");
    }
    fn reset_snapshots(&self) {
        write(self.root().join("snapshot-started"), "");
        write(self.root().join("snapshot-completed"), "");
    }
}

const SYSTEMCTL: &str = r#"
[ ! -e "$RCH_SCOPE_TEST_ROOT/manager-down" ] || exit 1
for unit do :; done
file="$RCH_SCOPE_TEST_ROOT/manager/$unit"
[ -f "$file" ] || exit 1
case " $* " in
    *' --all '* )
        phase=before_pin
        if [ -e /proc/self/fd/8/cgroup.events ]; then phase=pinned; fi
        printf '%s\n' "$phase" >> "$RCH_SCOPE_TEST_ROOT/snapshot-started"
        if [ "$phase" = before_pin ] &&
            [ -s "$RCH_SCOPE_TEST_ROOT/cgroups/jobs.slice/$unit/cgroup.kill" ]; then
            if [ -n "${RCH_SCOPE_TEST_SETTLE_STEP:-}" ]; then
                read -r settle_clock < "$RCH_SCOPE_TEST_ROOT/clock" || exit 1
                printf '%s\n' "$((settle_clock + RCH_SCOPE_TEST_SETTLE_STEP))" > "$RCH_SCOPE_TEST_ROOT/clock"
            fi
            if [ -n "${RCH_SCOPE_TEST_CLOCK_AFTER_KILL:-}" ]; then
                printf '%s\n' "$RCH_SCOPE_TEST_CLOCK_AFTER_KILL" > "$RCH_SCOPE_TEST_ROOT/clock"
                printf 'populated 0\nfrozen 0\n' > "$RCH_SCOPE_TEST_ROOT/cgroups/jobs.slice/$unit/cgroup.events"
            fi
        fi
        [ ! -e "$RCH_SCOPE_TEST_ROOT/snapshots-down" ] || exit 19
        delay=${RCH_SCOPE_TEST_SNAPSHOT_DELAY:-0}
        if [ "$phase" = pinned ]; then
            delay=${RCH_SCOPE_TEST_PINNED_DELAY:-$delay}
        elif [ -n "${RCH_SCOPE_TEST_CLOCK_AFTER_SNAPSHOT:-}" ]; then
            printf '%s\n' "$RCH_SCOPE_TEST_CLOCK_AFTER_SNAPSHOT" > "$RCH_SCOPE_TEST_ROOT/clock"
        fi
        sleep "$delay" || exit 1
        if [ "$phase" = pinned ] && [ -e "$RCH_SCOPE_TEST_ROOT/change-generation-when-pinned" ]; then
            sed 's/^InvocationID=.*/InvocationID=ffffffffffffffffffffffffffffffff/' "$file" > "$file.changed" || exit 1
            mv "$file.changed" "$file" || exit 1
        fi
        printf '%s\n' "$phase" >> "$RCH_SCOPE_TEST_ROOT/snapshot-completed";;
esac
case " $* " in
    *' --value '* )
        for arg do
            case "$arg" in --property=*) key=${arg#--property=};; esac
        done
        sed -n "s/^$key=//p" "$file";;
    *) cat "$file";;
esac
"#;

const TEST_CLOCK: &str = r#"
rch_observation_clock() { read -r rch_observation_now < "$RCH_SCOPE_TEST_ROOT/clock"; }
rch_remote_cancel "$1" 42 kill
"#;

#[test]
fn native_unavailable_post_exit_observation_retains_record_until_recovery() {
    let mut fixture = ScopeFixture::new();
    status(&fixture.operation("kill"), 0);
    write(fixture.scope.join("cgroup.events"), "populated 0\n");
    let unavailable = fixture.root().join("snapshots-down");
    write(&unavailable, "");
    let receipt = fixture.receipt();
    status(&fixture.cancel("kill"), 44);
    fixture.unchanged(&receipt);
    std::fs::rename(unavailable, fixture.root().join("snapshots-restored")).unwrap();
    fixture
        .env
        .insert("RCH_SCOPE_TEST_SNAPSHOT_DELAY".into(), "1.25".into());
    status(&fixture.cancel("kill"), 0);
    fixture.unchanged(&receipt);
    assert_eq!(fixture.kill(), "1\n");
}

#[test]
fn native_shared_budget_bounds_the_pinned_snapshot_without_granting_kill() {
    let mut fixture = ScopeFixture::new();
    let receipt = fixture.receipt();
    fixture
        .env
        .insert("RCH_SCOPE_TEST_PINNED_DELAY".into(), "1.25".into());
    for clock in ["3000", "3050"] {
        fixture.reset_clock();
        fixture.reset_snapshots();
        fixture
            .env
            .insert("RCH_SCOPE_TEST_CLOCK_AFTER_SNAPSHOT".into(), clock.into());
        status(&fixture.run(TEST_CLOCK, &[&fixture.record]), 44);
        assert_eq!(fixture.kill(), "");
        fixture.unchanged(&receipt);
        let started = read(fixture.root().join("snapshot-started"));
        let completed = read(fixture.root().join("snapshot-completed"));
        assert!(started.lines().any(|line| line == "before_pin"));
        assert!(!completed.lines().any(|line| line == "pinned"));
        assert_eq!(
            started.lines().any(|line| line == "pinned"),
            clock == "3000"
        );
    }
}

#[test]
fn native_initial_and_post_term_empty_census_must_finish_before_deadline() {
    let fixture = ScopeFixture::new();
    let receipt = fixture.receipt();
    for mode in ["kill", "term"] {
        for (clock, expected) in [("3099", 0), ("3100", 44), ("3101", 44)] {
            fixture.reset_kill();
            fixture.reset_clock();
            let output = fixture.run(
                r#"
rch_test_mode=$2
rch_test_finished=$3
rch_test_states=0
rch_observation_clock() { read -r rch_observation_now < "$RCH_SCOPE_TEST_ROOT/clock"; }
rch_group_state() {
    rch_test_states=$((rch_test_states + 1))
    if [ "$rch_test_mode" = term ] && [ "$rch_test_states" = 1 ]; then return 1; fi
    printf '%s\n' "$rch_test_finished" > "$RCH_SCOPE_TEST_ROOT/clock"
    return 0
}
rch_remote_cancel "$1" 42 "$rch_test_mode"
"#,
                &[&fixture.record, Path::new(mode), Path::new(clock)],
            );
            status(&output, expected);
            assert_eq!(read(fixture.root().join("clock")), format!("{clock}\n"));
            fixture.unchanged(&receipt);
            assert_eq!(fixture.kill(), "");
        }
    }
}

#[test]
fn native_settling_census_keeps_shared_deadline_after_retry_window() {
    let mut fixture = ScopeFixture::new();
    let receipt = fixture.receipt();
    for (clock, expected) in [("2900", 0), ("3100", 44)] {
        fixture.reset_kill();
        fixture.reset_clock();
        fixture.reset_snapshots();
        write(
            fixture.scope.join("cgroup.events"),
            "populated 1\nfrozen 0\n",
        );
        fixture
            .env
            .insert("RCH_SCOPE_TEST_CLOCK_AFTER_KILL".into(), clock.into());
        status(&fixture.run(TEST_CLOCK, &[&fixture.record]), expected);
        assert_eq!(fixture.kill(), "1\n");
        assert_eq!(read(fixture.root().join("clock")), format!("{clock}\n"));
        fixture.unchanged(&receipt);
        let completed = read(fixture.root().join("snapshot-completed"));
        assert_eq!(
            completed,
            if expected == 0 {
                "before_pin\npinned\nbefore_pin\npinned\nbefore_pin\npinned\n"
            } else {
                "before_pin\npinned\nbefore_pin\npinned\nbefore_pin\n"
            }
        );
    }
}

#[test]
fn native_settlement_retries_use_elapsed_time_and_keep_shared_budget() {
    let mut fixture = ScopeFixture::new();
    let receipt = fixture.receipt();
    fixture
        .env
        .insert("RCH_SCOPE_TEST_SETTLE_STEP".into(), "150".into());
    for (scale, clock) in [("1", "420\n"), ("2", "580\n"), ("10", "2180\n")] {
        fixture.env.insert("RCH_TIMING_SCALE".into(), scale.into());
        fixture.reset_kill();
        fixture.reset_clock();
        write(
            fixture.scope.join("cgroup.events"),
            "populated 1\nfrozen 0\n",
        );
        let output = fixture.run(
            r#"
rch_observation_clock() {
    read -r rch_observation_now < "$RCH_SCOPE_TEST_ROOT/clock" || return 1
    rch_timing_scaled=5
}
sleep() {
    [ "$1" = 0.1 ] || return 125
    read -r rch_test_tick < "$RCH_SCOPE_TEST_ROOT/clock" || return 1
    printf '%s\n' "$((rch_test_tick + 10))" > "$RCH_SCOPE_TEST_ROOT/clock"
}
rch_remote_cancel "$1" 42 kill
"#,
            &[&fixture.record],
        );
        status(&output, 45);
        assert_eq!(read(fixture.root().join("clock")), clock);
        assert_eq!(fixture.kill(), "1\n");
        fixture.unchanged(&receipt);
    }
}

#[test]
fn native_frozen_settlement_clock_cannot_wait_indefinitely_or_confirm_cleanup() {
    let mut fixture = ScopeFixture::new();
    let receipt = fixture.receipt();
    for scale in ["1", "10"] {
        fixture.env.insert("RCH_TIMING_SCALE".into(), scale.into());
        fixture.reset_kill();
        let started = std::time::Instant::now();
        status(&fixture.run("rch_observation_clock() { rch_observation_now=100; }\nrch_remote_cancel \"$1\" 42 kill", &[&fixture.record]), 44);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(fixture.kill(), "1\n");
        fixture.unchanged(&receipt);
    }
}

#[test]
fn native_invalid_snapshot_clock_cannot_confirm_an_empty_scope() {
    let mut fixture = ScopeFixture::new();
    write(fixture.scope.join("cgroup.events"), "populated 0\n");
    let receipt = fixture.receipt();
    for clock in ["99", "3100"] {
        fixture.reset_clock();
        fixture.reset_snapshots();
        fixture
            .env
            .insert("RCH_SCOPE_TEST_CLOCK_AFTER_SNAPSHOT".into(), clock.into());
        status(&fixture.run(TEST_CLOCK, &[&fixture.record]), 44);
        fixture.unchanged(&receipt);
        assert_eq!(fixture.kill(), "");
        assert_eq!(
            read(fixture.root().join("snapshot-started")),
            "before_pin\n"
        );
        assert_eq!(
            read(fixture.root().join("snapshot-completed")),
            "before_pin\n"
        );
    }
    fixture.env.remove("RCH_SCOPE_TEST_CLOCK_AFTER_SNAPSHOT");
    status(&fixture.cancel("kill"), 0);
    fixture.unchanged(&receipt);
}

#[test]
fn native_kill_targets_the_bound_subtree_not_a_pid_or_unit_name() {
    let fixture = ScopeFixture::new();
    status(&fixture.operation("kill"), 0);
    assert_eq!(fixture.kill(), "1\n");
    // Accepting the kill request alone cannot authorize cleanup success.
    status(&fixture.cancel("kill"), 45);
}

#[test]
fn native_missing_manager_cannot_downgrade_to_posix_cleanup() {
    let fixture = ScopeFixture::new();
    write(fixture.root().join("manager-down"), "");
    status(&fixture.cancel("kill"), 44);
    assert_eq!(fixture.kill(), "");
}

#[test]
fn native_failed_census_still_stops_authenticated_scope_then_rechecks_both_views() {
    let mut fixture = ScopeFixture::new();
    fixture.env.insert(
        "RCH_SCOPE_TEST_KILL".into(),
        fixture.scope.join("cgroup.kill").to_str().unwrap().into(),
    );
    fixture.env.insert(
        "RCH_SCOPE_TEST_EVENTS".into(),
        fixture.scope.join("cgroup.events").to_str().unwrap().into(),
    );
    fixture.executable(
        "ps",
        r#"
if [ ! -s "$RCH_SCOPE_TEST_KILL" ]; then
    case "$RCH_SCOPE_TEST_CENSUS_FAULT" in
        failed) exit 1;;
        malformed) printf 'incomplete census\n'; exit 0;;
    esac
fi
printf 'populated 0\nfrozen 0\n' > "$RCH_SCOPE_TEST_EVENTS"
exec /usr/bin/ps "$@"
"#,
    );
    let receipt = fixture.receipt();
    for fault in ["failed", "malformed"] {
        fixture
            .env
            .insert("RCH_SCOPE_TEST_CENSUS_FAULT".into(), fault.into());
        for mode in ["kill", "term"] {
            fixture.reset_kill();
            write(
                fixture.scope.join("cgroup.events"),
                "populated 1\nfrozen 0\n",
            );
            status(&fixture.cancel(mode), 0);
            assert_eq!(fixture.kill(), "1\n");
            fixture.unchanged(&receipt);
        }
    }
}

#[test]
fn native_persistent_failed_census_stops_scope_without_claiming_completion() {
    let fixture = ScopeFixture::new();
    fixture.executable("ps", "exit 1\n");
    for populated in [0, 1] {
        write(
            fixture.scope.join("cgroup.events"),
            format!("populated {populated}\n"),
        );
        for mode in ["kill", "term"] {
            fixture.reset_kill();
            status(&fixture.cancel(mode), 44);
            assert_eq!(
                fixture.kill(),
                "1\n",
                "unknown census must not suppress scoped stop"
            );
        }
    }
}

#[test]
fn native_failed_census_does_not_borrow_foreign_or_unavailable_scope_authority() {
    let fixture = ScopeFixture::new();
    fixture.executable("ps", "exit 1\n");
    let snapshot = read(&fixture.snapshot);
    write(
        &fixture.snapshot,
        snapshot.replace(INVOCATION, &"f".repeat(32)),
    );
    status(&fixture.cancel("kill"), 43);
    assert_eq!(fixture.kill(), "");
    write(&fixture.snapshot, snapshot);
    let original = read(&fixture.record);
    for (index, value, expected) in [
        (2, "00000000-0000-0000-0000-000000000000", 42),
        (8, "1", 43),
        (9, "1.1", 43),
        (10, "1.1", 43),
    ] {
        let mut fields = fixture.fields.clone();
        fields[index] = value.into();
        write(&fixture.record, format!("{}\n", fields.join(":")));
        status(&fixture.cancel("kill"), expected);
        assert_eq!(fixture.kill(), "");
    }
    write(&fixture.record, original);
    write(fixture.root().join("manager-down"), "");
    status(&fixture.cancel("kill"), 44);
    assert_eq!(fixture.kill(), "");
}

#[test]
fn native_failed_census_never_authorizes_legacy_group_signals() {
    let fixture = ScopeFixture::new();
    fixture.executable("ps", "exit 1\n");
    let legacy = fixture.root().join("legacy.pgid");
    write(
        &legacy,
        format!(
            "RCH_REMOTE_PROCESS_V1:42:{}:{}:1\n",
            fixture.fields[2], fixture.fields[3]
        ),
    );
    for mode in ["kill", "term"] {
        let output = fixture.run(
            r#"
kill() { printf '%s\n' "$*" >> "$RCH_SCOPE_TEST_ROOT/unexpected-signal"; return 0; }
rch_remote_cancel "$1" 42 "$2"
"#,
            &[&legacy, Path::new(mode)],
        );
        status(&output, 44);
        assert!(!fixture.root().join("unexpected-signal").exists());
        assert_eq!(fixture.kill(), "");
    }
}

#[test]
fn native_census_failure_after_graceful_term_cannot_prevent_scoped_escalation() {
    let mut fixture = ScopeFixture::new();
    fixture.env.insert(
        "RCH_SCOPE_TEST_KILL".into(),
        fixture.scope.join("cgroup.kill").to_str().unwrap().into(),
    );
    fixture.env.insert(
        "RCH_SCOPE_TEST_EVENTS".into(),
        fixture.scope.join("cgroup.events").to_str().unwrap().into(),
    );
    fixture.executable(
        "ps",
        r#"
count_file="$RCH_SCOPE_TEST_ROOT/census-count"
count=0
if [ -f "$count_file" ]; then read -r count < "$count_file"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
[ "$count" != 2 ] || exit 1
if [ -s "$RCH_SCOPE_TEST_KILL" ]; then
    printf 'populated 0\nfrozen 0\n' > "$RCH_SCOPE_TEST_EVENTS"
fi
exec /usr/bin/ps "$@"
"#,
    );
    status(&fixture.cancel("term"), 0);
    assert_eq!(fixture.kill(), "1\n");
    assert!(
        read(fixture.root().join("census-count"))
            .trim()
            .parse::<u32>()
            .unwrap()
            >= 3
    );
}

#[test]
fn native_new_channel_observes_terminal_evidence_without_policy_file() {
    let fixture = ScopeFixture::new();
    status(&fixture.operation("kill"), 0);
    write(fixture.scope.join("cgroup.events"), "populated 0\n");
    let output = fixture.run(
        r#"
rch_policy_select_file() { echo should-not-load-policy >&2; return 125; }
rch_remote_cancel "$1" 42 kill
"#,
        &[&fixture.record],
    );
    status(&output, 0);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("should-not-load-policy"));
}

#[test]
#[ignore = "requires RCH_TEST_SYSTEMD_SLICE naming an active disposable systemd user slice"]
fn native_setsid_descendant_is_reaped_after_leader_disconnect() {
    use rustix::process::{Pid, PidfdFlags, Signal};
    use std::os::fd::OwnedFd;
    use std::process::{Child, Stdio};
    use std::thread;
    use std::time::Instant;

    struct LiveScope {
        leader: Child,
        descendant: Option<OwnedFd>,
    }
    impl Drop for LiveScope {
        fn drop(&mut self) {
            if self.leader.try_wait().ok().flatten().is_none() {
                let _ = self.leader.kill();
            }
            if let Some(descriptor) = &self.descendant {
                let _ = rustix::process::pidfd_send_signal(descriptor, Signal::KILL);
            }
            let _ = self.leader.wait();
        }
    }

    let slice = std::env::var("RCH_TEST_SYSTEMD_SLICE")
        .expect("explicitly select an active disposable systemd user slice");
    let directory = owned_protocol::retained("rch-native-live-scope-");
    let policy = directory.path().join("policy");
    let record = directory.path().join("42.pgid");
    let ready = directory.path().join("child");
    write(&policy, format!("version=1\nsystemd_slice={slice}\n"));
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
    let script = format!(
        "{}\n{}",
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT,
        r#"
rch_policy_select_file() { rch_policy_file=$RCH_LIVE_POLICY; rch_policy_owner=$(id -u); }
rch_remote_record "$1" 42 || exit $?
"$RCH_WKR_BIN" setsid -- /bin/sh -c 'trap "" TERM; printf "%s\n" "$$" > "$1"; exec /bin/sleep 60' rch-detached-scope "$2" >/dev/null 2>&1 &
wait
"#
    );
    let child = owned_protocol::shell(&script, &[&record, &ready])
        .env("RCH_LIVE_POLICY", &policy)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut live = LiveScope {
        leader: child,
        descendant: None,
    };
    let deadline = Instant::now() + Duration::from_secs(12);
    let descendant = loop {
        if let Ok(text) = std::fs::read_to_string(&ready)
            && let Ok(pid) = text.trim().parse::<i32>()
        {
            break Pid::from_raw(pid).unwrap();
        }
        assert!(
            live.leader.try_wait().unwrap().is_none(),
            "live scope admission failed"
        );
        assert!(Instant::now() < deadline, "live scope did not become ready");
        thread::sleep(Duration::from_millis(20));
    };
    live.descendant = Some(rustix::process::pidfd_open(descendant, PidfdFlags::empty()).unwrap());
    assert_ne!(
        rustix::process::getpgid(Some(descendant)).unwrap(),
        Pid::from_child(&live.leader)
    );
    let receipt = read(&record);
    assert!(receipt.starts_with("RCH_REMOTE_PROCESS_V2:42:"));
    let cgroup = receipt.trim().split(':').next_back().unwrap();
    assert!(
        read(format!("/proc/{}/cgroup", descendant.as_raw_nonzero()))
            .lines()
            .any(|line| line == format!("0::{cgroup}"))
    );
    live.leader.kill().unwrap();
    live.leader.wait().unwrap();
    std::fs::rename(&policy, directory.path().join("policy.retained")).unwrap();
    let recover = format!(
        "{}\nrch_remote_cancel \"$1\" 42 kill",
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
    );
    status(
        &owned_protocol::run(
            owned_protocol::shell(&recover, &[&record]),
            Duration::from_secs(40),
        ),
        0,
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if rch_common::process_identity::observe_process(descendant.as_raw_nonzero().get() as u32)
            == rch_common::process_identity::ProcessObservation::Absent
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "detached descendant is still alive"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
