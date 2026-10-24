//! Exercise the actual embedded cancellation protocol, including a real Linux
//! process group whose leader exits on TERM while its child ignores TERM.
#![cfg(target_os = "linux")]

use std::process::Command;

fn run_case(body: &str) {
    for shell in ["sh", "bash"] {
        let directory = tempfile::tempdir().expect("create fixture directory");
        std::fs::write(
            directory.path().join("protocol.sh"),
            rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT,
        )
        .expect("write embedded production protocol");
        let script = format!("{}\n{body}", rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT);
        let output = Command::new(shell)
            .args(["-c", &script, "rch-process-test"])
            .arg(directory.path())
            .output()
            .expect("run shell regression");
        assert!(
            output.status.success(),
            "{shell}: {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

const LEADER_EXIT: &str = r#"
rch_test_dir=$1
rch_test_leader=
cleanup() {
    # Teardown also checks birth identity, never an unbound historical PGID.
    if rch_read_record "$rch_test_dir/receipt" regression; then
        if rch_remote_leader_matches; then
            kill -KILL -"$rch_pgid" 2>/dev/null || :
        elif [ -r "$rch_test_dir/witness" ]; then
            read -r test_pid test_start < "$rch_test_dir/witness"
            if rch_read_process "$test_pid" && [ "$rch_observed_start" = "$test_start" ]; then
                kill -KILL -"$rch_pgid" 2>/dev/null || :
            fi
        fi
    fi
    if [ -n "$rch_test_leader" ]; then wait "$rch_test_leader" 2>/dev/null || :; fi
}
trap cleanup 0
setsid sh -c '
    . "$1/protocol.sh"
    rch_remote_record "$1/receipt" regression || exit 70
    trap "exit 0" TERM
    sh -c '\''trap "" TERM; printf ready > "$1/ready"; exec sleep 30'\'' survivor "$1" &
    printf "%s\n" "$!" > "$1/member"
    wait
' leader "$rch_test_dir" >/dev/null 2>&1 &
rch_test_leader=$!
attempt=0
while [ ! -s "$rch_test_dir/member" ] || [ ! -f "$rch_test_dir/ready" ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 500 ] || { echo 'fixture did not start' >&2; exit 1; }
    sleep 0.01
done
read -r test_member < "$rch_test_dir/member"
rch_read_record "$rch_test_dir/receipt" regression || exit 1
rch_read_process "$test_member" || exit 1
printf '%s %s\n' "$test_member" "$rch_observed_start" > "$rch_test_dir/witness"
rch_remote_cancel "$rch_test_dir/receipt" regression term || {
    echo 'TERM-to-KILL escalation lost group ownership' >&2; exit 1;
}
if rch_read_process "$test_member"; then
    echo 'TERM-ignoring child survived cancellation' >&2
    exit 1
fi
wait "$rch_test_leader" || :
"#;

#[test]
fn term_escalation_survives_leader_exit() {
    run_case(LEADER_EXIT);
}

const WITNESS_FENCING: &str = r#"
rch_identified=1
rch_boot=boot
rch_pgid=300
rch_start=100
rch_witness_identity=boot:300:100
rch_witnesses='999:999 301:200'
rch_term_sent=1
test_boot=boot
test_start=200
test_member_live=1
test_signals=0
rch_remote_leader_matches() { return 1; }
rch_read_process() {
    [ "$1" = 301 ] && [ "$test_member_live" = 1 ] || return 1
    rch_observed_boot=$test_boot
    rch_observed_start=$test_start
}
# Observation now runs inside the bounded control exchange. Give that exact
# protocol copy the same explicit fake backend and export its changing facts.
# Signal interception and every refusal assertion remain in this observer.
export test_boot test_start test_member_live
rch_launch_source="$rch_launch_source"'
rch_read_process() {
    [ "$1" = 301 ] && [ "$test_member_live" = 1 ] || return 1
    rch_observed_boot=$test_boot
    rch_observed_start=$test_start
}
'
kill() { test_signals=$((test_signals + 1)); }
refused() {
    rch_signal_group "$1"
    code=$?
    [ "$code" = 43 ] && [ "$test_signals" = 1 ] || exit 1
}
# An unavailable first witness must not hide a later live, matching witness.
rch_signal_group KILL || exit 1
[ "$test_signals" = 1 ] || exit 1
# Witnesses authorize only escalation, never the initial TERM.
refused TERM
rch_term_sent=0
refused KILL
rch_term_sent=1
# PID reuse, reboot, exit/group departure, and a different receipt all fence it.
test_start=201
refused KILL
test_start=200
test_boot=other-boot
refused KILL
test_boot=boot
test_member_live=0
refused KILL
test_member_live=1
rch_witness_identity=boot:400:100
refused KILL
rch_witness_identity=boot:300:101
refused KILL
rch_witness_identity=boot:300:100
rch_identified=0
refused KILL
"#;

#[test]
fn witnesses_require_matching_birth_group_boot_and_current_term() {
    run_case(WITNESS_FENCING);
}

const CAPTURE_RACE: &str = r#"
rch_identified=1
rch_boot=boot
rch_pgid=300
rch_start=100
rch_snapshot='301 300 S'
rch_witnesses=stale
rch_witness_identity=stale
test_leader_reads=0
rch_remote_leader_matches() {
    test_leader_reads=$((test_leader_reads + 1))
    [ "$test_leader_reads" = 1 ]
}
rch_read_process() { rch_observed_boot=boot; rch_observed_start=200; }
# The collector observes the live leader, but it exits before the parent can
# accept those witnesses. The parent's second birth check MUST still fail.
rch_launch_source="$rch_launch_source"'
rch_remote_leader_matches() { return 0; }
rch_read_process() { rch_observed_boot=boot; rch_observed_start=200; }
'
rch_capture_group_witnesses
code=$?
[ "$code" = 43 ] && [ -z "$rch_witnesses" ] && [ -z "$rch_witness_identity" ] || exit 1
"#;

#[test]
fn leader_exit_during_capture_does_not_transfer_authority() {
    run_case(CAPTURE_RACE);
}

const NO_INHERITED_AUTHORITY: &str = r#"
# Even a parse failure must clear authority inherited from a previous call.
rch_witnesses='301:200'
rch_witness_identity=boot:300:100
rch_term_sent=1
rch_read_record() { return 42; }
rch_remote_cancel /unused regression term
code=$?
[ "$code" = 42 ] && [ -z "$rch_witnesses" ] &&
    [ -z "$rch_witness_identity" ] && [ "$rch_term_sent" = 0 ] || exit 1
# A live group with no matching leader at entry must remain quarantined.
rch_read_record() { rch_identified=1; rch_boot=boot; rch_pgid=300; rch_start=100; }
# Same boot (812d6a97 checks boot first; remote_reboot_recovery.py covers it).
rch_recovery_boot_state() { return 0; }
rch_group_state() { rch_snapshot='301 300 S'; return 1; }
rch_remote_leader_matches() { return 1; }
rch_read_process() { rch_observed_boot=boot; rch_observed_start=200; }
kill() { echo 'unexpected signal to unowned group' >&2; exit 99; }
for mode in term kill; do
    rch_witnesses='301:200'
    rch_witness_identity=boot:300:100
    rch_term_sent=1
    rch_remote_cancel /unused regression "$mode"
    code=$?
    [ "$code" = 43 ] || exit 1
done
"#;

#[test]
fn separate_calls_and_preexisting_orphans_cannot_inherit_authority() {
    run_case(NO_INHERITED_AUTHORITY);
}

const NAMESPACE_FENCING: &str = r#"
rch_test_dir=$1
# Simulate foreign, coincidentally equal, and missing namespace IDs through the
# production builtin-read boundary; this test needs no namespace privileges.
read() { rch_status_line=$test_status; }
cat() { printf unexpected > "$rch_test_dir/cat-called"; return 1; }
ps() { printf unexpected > "$rch_test_dir/ps-called"; return 1; }
kill() { echo 'unexpected signal with foreign procfs' >&2; exit 99; }
for test_status in "NSpid: $$ 1" "NSpid: $$ $$" "NSpid: 0" 'NSpid:'; do
    rch_pgid=300
    rch_read_process 301
    [ "$?" = 1 ] || exit 1
    rch_group_state
    [ "$?" = 2 ] || exit 1
    rch_remote_record "$rch_test_dir/receipt" regression
    [ "$?" = 1 ] && [ ! -e "$rch_test_dir/receipt" ] || exit 1
done
rch_read_record() { rch_identified=1; rch_boot=boot; rch_pgid=300; rch_start=100; }
rch_remote_cancel /unused regression term
[ "$?" = 44 ] || exit 1
# An unreadable status or a kernel with no NSpid must not prove group absence.
read() { return 1; }
rch_group_state
[ "$?" = 2 ] || exit 1
[ ! -e "$rch_test_dir/cat-called" ] && [ ! -e "$rch_test_dir/ps-called" ] || exit 1
"#;

#[test]
fn foreign_procfs_cannot_authorize_signals_or_empty_group_claims() {
    run_case(NAMESPACE_FENCING);
}

const SUBSHELL_OBSERVATION: &str = r#"
# $$ names the invoking shell inside ( ... ), but /proc/self is the subshell.
# The watchdog's timer reads its own sleep from a subshell; failing closed
# there silently disabled every remote build deadline.
rch_check_procfs_namespace || exit 1
( rch_check_procfs_namespace ) || exit 2
( ( rch_check_procfs_namespace ) ) || exit 3
(
    sleep 30 &
    test_sleep=$!
    rch_pgid=$(ps -o pgid= -p "$test_sleep" | tr -d ' ')
    rch_read_process "$test_sleep"
    test_code=$?
    kill "$test_sleep"
    wait "$test_sleep" 2>/dev/null
    [ "$test_code" = 0 ] && [ -n "$rch_observed_start" ]
) || exit 4
"#;

#[test]
fn subshells_observe_their_own_procfs_namespace() {
    run_case(SUBSHELL_OBSERVATION);
}

const PROCESS_STATES: &str = r#"
rch_test_dir=$1
rch_pgid=300
rch_check_procfs_namespace() { return 0; }
cat() {
    case "$1" in
        /proc/sys/kernel/random/boot_id)
            printf '01234567-89ab-cdef-0123-456789abcdef\n';;
        /proc/*)
            printf '301 (worker (test)) %s 1 300' "$test_state"
            field=0
            while [ "$field" -lt 16 ]; do printf ' 0'; field=$((field + 1)); done
            printf ' 200\n';;
        # The bounded census reads its captured output with cat.
        *) command cat "$@";;
    esac
}
# The census runs ps in a separate bounded shell (14aea498): a real fake ps on
# PATH reports this shell as the observer and member 301 in test_state.
mkdir -p "$rch_test_dir/bin"
printf '%s\n' '#!/bin/sh' \
    'printf "%s %s %s S 1\n301 301 300 %s 1\n" "$RCH_TEST_OBSERVER" "$RCH_TEST_OBSERVER" "$RCH_TEST_OBSERVER" "$test_state"' \
    > "$rch_test_dir/bin/ps"
chmod 700 "$rch_test_dir/bin/ps"
RCH_TEST_OBSERVER=$$
PATH="$rch_test_dir/bin:$PATH"
export RCH_TEST_OBSERVER PATH test_state
for test_state in R S D T t K W P I; do
    rch_read_process 301 || exit 1
    [ "$rch_observed_start" = 200 ] || exit 1
    rch_group_state
    [ "$?" = 1 ] || exit 1
done
for test_state in Z X x; do
    if rch_read_process 301; then echo 'dead member accepted' >&2; exit 1; fi
    rch_group_state
    [ "$?" = 0 ] || exit 1
done
for test_state in Q '?' SS; do
    if rch_read_process 301; then echo 'unknown member state accepted' >&2; exit 1; fi
done
test_state=Q
rch_group_state
[ "$?" = 2 ] || exit 1
"#;

#[test]
fn process_state_observation_is_conservative_and_handles_parentheses() {
    run_case(PROCESS_STATES);
}
