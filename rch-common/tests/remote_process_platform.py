#!/usr/bin/env python3
"""Kernel identity, lifecycle and busy-worker census regressions.

Darwin requires the candidate rch-wkr on PATH. Bounded probes use GNU timeout
when available, otherwise Python 3. PlatformIdentity uses real processes and
identities. LinuxBusyCensus explicitly doubles ps snapshots and scheduling,
including the 2,350-process / 4,800-thread incident shape; it does not claim
those are live host processes. NativeProcessStress is an opt-in real Linux
process/thread stress test, bounded by RCH_TEST_STRESS_PROCESSES (max 2,350).
"""
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
CORE = (ROOT / "rch-common/src/remote_process.sh").read_text()
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")


def quote_protocol_source(source):
    """The byte-preserving POSIX double-quote escaping in compile_protocol()."""
    return source.translate(str.maketrans({
        "\\": "\\\\", '"': '\\"', "$": "\\$", "`": "\\`", "!": "${rch_literal_bang}",
    }))


def replace_protocol_source(protocol, before, after):
    """Inject one explicit test adapter before the shared source is evaluated."""
    encoded = quote_protocol_source(before)
    if protocol.count(encoded) != 1:
        raise AssertionError("expected exactly one quoted production source fragment")
    return protocol.replace(encoded, quote_protocol_source(after), 1)


def assemble_protocol():
    # Expand the same literal inputs and escaping as the public Rust constant.
    # Native integration tests compare these bytes with the compiled constant;
    # standalone runs exercise shell behavior, not Rust constant evaluation.
    source = ROOT / "rch-common/src"
    rust = (source / "remote_scoped_launch.rs").read_text()

    def literal(name):
        expression = rust.split(f"const {name}: &str = concat!(\n", 1)[1].split("\n);", 1)[0]
        parts = []
        for line in expression.splitlines():
            item = line.strip().removesuffix(",")
            include = re.fullmatch(r'include_str!\(("[^"\n]+")\)', item)
            parts.append((source / json.loads(include[1])).read_text()
                         if include else json.loads(item))
        return "".join(parts)

    prefix = re.search(r'^const BOOTSTRAP_PREFIX: &str = (".*");$', rust, re.MULTILINE)
    if prefix is None:
        raise AssertionError("bootstrap prefix is no longer a literal Rust string")
    protocol = json.loads(prefix[1]) + quote_protocol_source(literal("LAUNCH_SOURCE")) + literal("BOOTSTRAP_SUFFIX")
    compiled = os.environ.get("RCH_TEST_PROTOCOL_SCRIPT")
    if compiled and Path(compiled).read_text() != protocol:
        raise AssertionError("source expansion differs from the compiled protocol")
    return protocol


PROTOCOL = assemble_protocol()


class PlatformIdentity(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-platform-identity-"))
        self.receipt = self.root / "receipt"
        self.ready = self.root / "ready"
        self.children = []
        self.groups = []
        self.addCleanup(self.stop_owned)

    def stop_owned(self):
        for child in self.children:
            # These session IDs came from our own unreaped direct children.
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)
        for pid, birth in self.groups:
            # Retain the original identity before the tests corrupt receipts.
            # A reused PID never grants cleanup authority to the test harness.
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
            except FileNotFoundError:
                continue
            if int(fields[19]) == birth and fields[0] not in "ZXx":
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def run_protocol(self, body):
        return subprocess.run([SHELL, "-c", PROTOCOL + "\n" + body, "rch-observer"],
                              text=True, capture_output=True, timeout=40)

    def assert_protocol(self, body):
        result = self.run_protocol(body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def launch(self, seconds=0, payload=None):
        if payload is None:
            payload = "trap '' TERM; echo ready > " + shlex.quote(str(self.ready)) + "; exec sleep 60"
        source = replace_protocol_source(PROTOCOL, CORE, CORE + "\nrch_policy_select_file() { rch_policy_file=; }\n")
        child = subprocess.Popen(
            [SHELL, "-c", "exec 3>&2\n" + source, "rch-build",
             str(self.receipt), str(seconds), "RCH_PLATFORM_DEADLINE", "115",
             SHELL, "-c", payload], start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(child)
        for _ in range(500):
            if self.receipt.exists() and (self.ready.exists() or payload == "exit 7"):
                fields = self.receipt.read_text().strip().split(":")
                self.groups.append((int(fields[3]), int(fields[4])))
                return child
            self.assertIsNone(child.poll(), "identity setup refused before workload")
            time.sleep(.01)
        self.fail("workload did not start")

    def cancel(self, mode="term"):
        return self.run_protocol(
            f"rch_remote_cancel {shlex.quote(str(self.receipt))} 115 {mode}")

    def test_initial_execution_preserves_exit_status(self):
        child = self.launch(payload="exit 7")
        self.assertEqual(child.wait(timeout=10), 7)
        self.assertTrue(self.receipt.read_text().startswith("RCH_REMOTE_PROCESS_V1:115:"))

    def test_fast_payload_disarms_long_watchdog(self):
        child = self.launch(seconds=30, payload="exit 7")
        # Completion must stop its own timer, not wait for the build deadline.
        self.assertEqual(child.wait(timeout=5), 7)
        self.assertEqual(self.cancel("kill").returncode, 0)

    def test_wrong_build_cannot_signal_live_group(self):
        child = self.launch()
        result = self.run_protocol(
            f"rch_remote_cancel {shlex.quote(str(self.receipt))} 116 kill")
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertIsNone(child.poll())

    def test_numeric_receipt_cannot_adopt_live_group(self):
        child = self.launch()
        self.receipt.write_text(f"{child.pid}\n")
        result = self.cancel("kill")
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertIsNone(child.poll())

    def test_multiline_receipt_cannot_signal_live_group(self):
        child = self.launch()
        with self.receipt.open("a") as receipt:
            receipt.write("\n")
        result = self.cancel("kill")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertIsNone(child.poll())

    def test_missing_receipt_cannot_confirm_cleanup(self):
        child = self.launch()
        absent = self.root / "not-published"
        result = self.run_protocol(
            f"rch_remote_cancel {shlex.quote(str(absent))} 115 kill")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertIsNone(child.poll())

    def test_observer_cannot_cancel_its_own_group(self):
        # Use a private session so a broken guard cannot reach the test runner.
        # Both publication and cancellation perform actual kernel observations.
        result = subprocess.run(
            [SHELL, "-c", CORE + r'''
rch_remote_record "$1" 115 || exit 90
rch_remote_cancel "$1" 115 kill
''', "rch-self-cancel-test", str(self.receipt)],
            start_new_session=True, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 44, result.stdout + result.stderr)

    def test_watchdog_and_timeout_recovery(self):
        child = self.launch(seconds=2)
        # The outside supervisor reports the workload's SIGKILL as 128+9.
        self.assertEqual(child.wait(timeout=12), 137)
        result = self.cancel("kill")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cancellation_escalates_and_recovery_confirms_empty(self):
        child = self.launch()
        result = self.cancel()
        self.assertEqual(result.returncode, 0, result.stderr)
        child.wait(timeout=10)
        self.assertEqual(self.cancel("kill").returncode, 0)

    def test_reused_birth_cannot_signal_live_group(self):
        child = self.launch()
        fields = self.receipt.read_text().strip().split(":")
        fields[-1] = str(int(fields[-1]) + 1)
        self.receipt.write_text(":".join(fields) + "\n")
        result = self.cancel()
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertIsNone(child.poll())

    def test_previous_boot_retires_only_old_execution(self):
        child = self.launch()
        fields = self.receipt.read_text().strip().split(":")
        fields[2] = "13572468-1234-4abc-8def-135724681357"
        self.receipt.write_text(":".join(fields) + "\n")
        result = self.cancel()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(child.poll())

    def test_actual_process_and_subshell_identity(self):
        self.assert_protocol(r'''
sleep 60 & member=$!
trap 'kill "$member"; wait "$member" 2>/dev/null' 0
rch_pgid=$(ps -o pgid= -p "$member" | tr -d ' ')
rch_read_process "$member" || exit 1
saved=$rch_observed_start
( rch_read_process "$member" && [ "$rch_observed_start" = "$saved" ] ) || exit 2
rch_pgid=2147483647
if rch_read_process "$member"; then exit 3; fi
''')

    def test_unavailable_observation_cannot_confirm_cleanup(self):
        child = self.launch()
        # Explicit fault injection after real launch/receipt creation. Losing
        # both observations must neither signal the child nor assert its death.
        result = self.run_protocol(
            "rch_group_state() { return 2; }\n"
            "rch_read_process() { return 1; }\n"
            f"rch_remote_cancel {shlex.quote(str(self.receipt))} 115 kill")
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assertIsNone(child.poll())


@unittest.skipUnless(sys.platform == "linux", "Linux process/thread census")
class LinuxBusyCensus(unittest.TestCase):
    """Incident-sized snapshots, with real bounded capture and parser code.

    The fake ps is a test executable, not a replaced census or completion
    result. Namespace validation, shell control capture, deadlines, selected
    process filtering and thread accounting all use the production code.
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-busy-census-"))
        self.env = {**os.environ, "PATH": f"{self.root}:{os.environ['PATH']}",
                    "RCH_BUSY_CENSUS_ROOT": str(self.root), "LC_ALL": "C"}
        helper = self.root / "ps"
        helper.write_text(f"#!{sys.executable}\n" + r'''
import json, os, sys, time
from pathlib import Path
root = Path(os.environ['RCH_BUSY_CENSUS_ROOT'])
observer = int(os.environ['RCH_BUSY_CENSUS_OBSERVER'])
target, group = 6000001, 6000000
mode = os.environ.get('RCH_BUSY_CENSUS_MODE', 'live')
args = sys.argv[1:]
with (root/'calls').open('a') as trace:
    trace.write(json.dumps(args) + '\n')
threads = 4096 if mode == 'many-threads' else 2 if mode.startswith('zombie-') else 1
state = 'S' if mode == 'live' else 'Z'
if args == ['-e', '-o', 'pid=', '-o', 'lwp=', '-o', 'pgid=', '-o', 's=', '-o', 'nlwp=']:
    time.sleep(float(os.environ.get('RCH_BUSY_CENSUS_DELAY', '0')))
    # 2,348 unrelated leaders + observer + target = 2,350 processes.
    # For the incident-shaped cases the NLWP sum is exactly 4,800.
    extra = max(0, 4800 - (2348 * 2 + threads + 1))
    rows = [f'{observer} {observer} 1 S 1']
    for index in range(2348):
        pid = 7000000 + index
        count = 2 + int(index < extra)
        rows.append(f'{pid} {pid} {pid} S {count}')
    rows.append(f'{target} {target} {group} {state} {threads}')
    if mode == 'malformed':
        rows.append('incomplete process row')
    print('\n'.join(rows), flush=True)
    if mode == 'failed-output':
        sys.exit(124)
    if mode == 'deadline-output':
        time.sleep(60)
    sys.exit(0)
if len(args) >= 3 and args[:2] == ['-L', '-q']:
    selected = args[2].split(',')
    if any(int(pid) not in (observer, target) for pid in selected):
        print('unrelated thread enumeration is forbidden', file=sys.stderr)
        sys.exit(91)
    for pid in selected:
        if int(pid) == observer:
            print(f'{observer} {observer} 1 S 1')
        else:
            print(f'{target} {target} {group} Z {threads}')
            if mode != 'zombie-missing':
                for offset in range(1, threads):
                    print(f'{target} {target + offset} {group} S {threads}')
    sys.exit(0)
print('unexpected process query: ' + repr(args), file=sys.stderr)
sys.exit(92)
''')
        helper.chmod(0o700)

    def run_state(self, mode, *, shell=SHELL, extra="", delay=0, repeats=1):
        body = r'''
rch_pgid=6000000; rch_scope_bound=0
RCH_BUSY_CENSUS_OBSERVER=$$; export RCH_BUSY_CENSUS_OBSERVER
''' + extra + "\n"
        if repeats == 1:
            body += "rch_group_state\n"
        else:
            body += f'''
rch_fixture_iteration=0
while [ "$rch_fixture_iteration" -lt {repeats} ]; do
    rch_group_state
    printf '%s\n' "$?"
    rch_fixture_iteration=$((rch_fixture_iteration + 1))
done
'''
        return subprocess.run(
            [shell, "-c", CORE + "\n" + body, "rch-busy-census"],
            env={**self.env, "RCH_BUSY_CENSUS_MODE": mode,
                 "RCH_BUSY_CENSUS_DELAY": str(delay)},
            capture_output=True, text=True, timeout=15)

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls").read_text().splitlines()]

    def test_twenty_busy_worker_censuses_prove_live_without_unrelated_threads(self):
        result = self.run_state("live", repeats=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["1"] * 20)
        self.assertEqual(len(self.calls()), 20)
        self.assertTrue(all(call[0] == "-e" for call in self.calls()),
                        "single-thread target must not enumerate 4,800 unrelated LWPs")

    def test_busy_worker_census_can_exceed_old_one_second_deadline(self):
        for shell in ("/bin/sh", "/bin/bash"):
            with self.subTest(shell=shell):
                result = self.run_state("live", shell=shell, delay=1.2)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_terminal_single_thread_target_needs_no_second_enumeration(self):
        result = self.run_state("terminal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls()), 1)

    def test_zombie_leader_requires_its_live_thread_census(self):
        result = self.run_state("zombie-live")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.calls()[-1][:2], ["-L", "-q"])
        self.assertEqual(len(self.calls()[-1][2].split(",")), 2,
                         "only target and observer threads may be enumerated")

    def test_missing_thread_never_proves_a_zombie_group_empty(self):
        result = self.run_state("zombie-missing")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(len(self.calls()), 2)

    def test_large_selected_thread_snapshot_still_proves_liveness(self):
        # This target's 4,096 thread rows exceed the old 64 KiB control-output
        # ceiling. A valid large census should not make a worker unusable.
        result = self.run_state("many-threads")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(self.calls()), 2)

    def test_failed_or_malformed_snapshot_never_proves_completion(self):
        for mode in ("failed-output", "malformed"):
            with self.subTest(mode=mode):
                result = self.run_state(mode)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_actual_timeout_discards_plausible_empty_snapshot_before_recovery(self):
        # Shorten ONLY the test's observer budget. The real timer kills a ps
        # that already emitted a plausible empty-group snapshot but never
        # completed. Neither output nor timeout may authorize release.
        result = self.run_state("deadline-output", extra=
                                "rch_observation_budget() { rch_observation_seconds=1; }")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        recovered = self.run_state("terminal")
        self.assertEqual(recovered.returncode, 0, recovered.stderr)


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("RCH_TEST_PROCESS_STRESS") == "1",
                     "opt-in native process/thread stress (dedicated host)")
class NativeProcessStress(unittest.TestCase):
    def test_busy_native_worker_admission_execution_completion_and_recovery(self):
        # Lightweight forked C sleepers share their executable pages; creating
        # thousands of Python interpreters would test memory exhaustion instead
        # of the reported census problem. The group owns all its descendants,
        # every process has a 60s emergency lifetime, and creation is capped.
        count = int(os.environ.get("RCH_TEST_STRESS_PROCESSES", "128"))
        self.assertGreaterEqual(count, 2)
        self.assertLessEqual(count, 2350)
        self.assertIsNotNone(shutil.which("cc"), "native stress requires a C compiler")
        root = Path(tempfile.mkdtemp(prefix="rch-native-census-stress-"))
        source, binary = root / "sleepers.c", root / "sleepers"
        source.write_text(r'''
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static void *sleeping_thread(void *unused) {
    (void)unused;
    for (;;) pause();
    return NULL;
}

static int add_thread(void) {
    pthread_t thread;
    pthread_attr_t attributes;
    if (pthread_attr_init(&attributes)) return 1;
    if (pthread_attr_setstacksize(&attributes, 65536)) return 1;
    int status = pthread_create(&thread, &attributes, sleeping_thread, NULL);
    pthread_attr_destroy(&attributes);
    if (status) fprintf(stderr, "pthread_create pid=%ld failed: %s (%d)\n", (long)getpid(), strerror(status), status);
    return status;
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    int count = atoi(argv[1]);
    if (count < 2 || count > 2350 || getpgrp() != getpid()) return 65;
    pid_t children[2350];
    int owned = 0, status = 0;
    signal(SIGTERM, request_stop);
    signal(SIGALRM, request_stop);
    alarm(60);
    int readiness[2];
    if (pipe(readiness)) return 66;
    for (int index = 1; index < count; ++index) {
        if (stop_requested) { status = 74; goto cleanup; }
        pid_t child = fork();
        if (child < 0) { perror("fork census sleeper"); status = 67; goto cleanup; }
        if (child == 0) {
            signal(SIGTERM, SIG_DFL);
            signal(SIGALRM, SIG_DFL);
            alarm(60);
            close(STDOUT_FILENO);
            close(readiness[0]);
            if (add_thread() || (index <= 100 && add_thread())) _exit(68);
            if (write(readiness[1], "r", 1) != 1) _exit(69);
            close(readiness[1]);
            for (;;) pause();
        }
        children[owned++] = child;
    }
    close(readiness[1]);
    for (int index = 1; index < count; ++index) {
        char ready;
        struct pollfd descriptor = {readiness[0], POLLIN, 0};
        while (poll(&descriptor, 1, 100) <= 0 && !stop_requested) {}
        if (stop_requested || read(readiness[0], &ready, 1) != 1 || ready != 'r') {
            status = 70;
            goto cleanup;
        }
    }
    close(readiness[0]);
    if (add_thread()) { status = 71; goto cleanup; }
    printf("READY %d %d\n", count, count * 2 + (count - 1 < 100 ? count - 1 : 100));
    if (fflush(stdout)) { status = 73; goto cleanup; }
    while (!stop_requested) {
        struct timespec delay = {0, 100000000};
        nanosleep(&delay, NULL);
    }
cleanup:
    for (int index = 0; index < owned; ++index) kill(children[index], SIGKILL);
    for (int index = 0; index < owned; ++index) {
        while (waitpid(children[index], NULL, 0) < 0 && errno == EINTR) {}
    }
    return status;
}
''')
        compiled = subprocess.run(["cc", "-O2", "-pthread", str(source), "-o", str(binary)],
                                  capture_output=True, text=True, timeout=20)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        errors = (root / "stderr").open("w+")
        self.addCleanup(errors.close)
        farm = subprocess.Popen([str(binary), str(count)], start_new_session=True,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errors)
        self.addCleanup(farm.stdout.close)

        def stop(child):
            if child.poll() is None:
                if child is farm:
                    # The C parent reaps every unreaped direct child itself.
                    child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                else:
                    os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)

        self.addCleanup(stop, farm)
        def farm_members():
            members = []
            for entry in Path("/proc").iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    fields = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if int(fields[2]) == farm.pid:
                    members.append((fields[0], int(fields[17])))
            return members

        # A pipe avoids ext4 directory lookup stalls while creating/checking
        # a readiness file. This fixture setup cap is separate from all of the
        # unchanged production admission, cancellation and observer deadlines.
        until = time.monotonic() + 30
        while not select.select([farm.stdout], [], [], .05)[0]:
            if (status := farm.poll()) is not None:
                self.fail(f"native farm exited {status} before readiness: "
                          f"{(root / 'stderr').read_text()[-2000:]}")
            if time.monotonic() >= until:
                members = farm_members()
                states = {}
                for state, _ in members:
                    states[state] = states.get(state, 0) + 1
                self.fail(f"native farm setup exceeded 30s: processes={len(members)}, "
                          f"threads={sum(member[1] for member in members)}, states={states}, "
                          f"stderr={(root / 'stderr').read_text()[-2000:]!r}")
        self.assertEqual(os.read(farm.stdout.fileno(), 128),
                         f"READY {count} {count * 2 + min(count - 1, 100)}\n".encode(),
                         (root / "stderr").read_text())
        # Independently verify the kernel's process and thread counts, rather
        # than treating the fixture's readiness declaration as stress proof.
        members = [threads for state, threads in farm_members() if state not in "ZXx"]
        self.assertEqual(len(members), count)
        self.assertEqual(sum(members), count * 2 + min(count - 1, 100))
        witness = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True)
        self.addCleanup(stop, witness)
        observe = subprocess.run([SHELL, "-c", CORE + f'''
rch_pgid={witness.pid}
rch_fixture_count=0
while [ "$rch_fixture_count" -lt 20 ]; do
    rch_group_state
    printf '%s\n' "$?"
    rch_fixture_count=$((rch_fixture_count + 1))
done
'''], capture_output=True, text=True, timeout=60)
        self.assertEqual(observe.returncode, 0, observe.stderr)
        self.assertEqual(observe.stdout.splitlines(), ["1"] * 20)
        record, executions = root / "record", root / "executions"
        source = replace_protocol_source(PROTOCOL, CORE, CORE + "\nrch_policy_select_file() { rch_policy_file=; }\n")
        payload = f"printf 'executed\\n' >> {shlex.quote(str(executions))}; exit 7"
        executed = subprocess.run([SHELL, "-c", source, "rch-build", str(record), "5",
                                   "RCH_STRESS_DEADLINE", "115", SHELL, "-c", payload],
                                  capture_output=True, text=True, timeout=60)
        self.assertEqual(executed.returncode, 7, executed.stderr)
        self.assertEqual(executions.read_text(), "executed\n")
        recovery = subprocess.run([SHELL, "-c", source + '\nrch_remote_cancel "$1" 115 kill\n',
                                   "rch-recovery", str(record)],
                                  capture_output=True, text=True, timeout=40)
        self.assertEqual(recovery.returncode, 0, recovery.stderr)
        cancel_record, cancel_ready = root / "cancel-record", root / "cancel-ready"
        cancelled = subprocess.Popen(
            [SHELL, "-c", source, "rch-build", str(cancel_record), "20", "RCH_STRESS_DEADLINE",
             "116", SHELL, "-c", f"printf ready > {shlex.quote(str(cancel_ready))}; exec sleep 30"],
            start_new_session=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=errors)
        self.addCleanup(stop, cancelled)
        until = time.monotonic() + 10
        while not cancel_ready.exists():
            self.assertIsNone(cancelled.poll(), (root / "stderr").read_text())
            self.assertLess(time.monotonic(), until, "cancellation payload did not start")
            time.sleep(.02)
        cancellation = subprocess.run(
            [SHELL, "-c", source + '\nrch_remote_cancel "$1" 116 kill\n',
             "rch-recovery", str(cancel_record)], capture_output=True, text=True, timeout=40)
        self.assertEqual(cancellation.returncode, 0, cancellation.stderr)
        self.assertEqual(cancelled.wait(timeout=10), 137)
        self.assertIsNone(witness.poll(), "unrelated witness was cancelled")
        self.assertIsNone(farm.poll(), "unrelated stress processes were cancelled")


class DarwinCensusBoundary(unittest.TestCase):
    def test_kernel_task_live_terminal_and_invalid_snapshots(self):
        # Deliberate census doubles complement (and do not replace) the native
        # lifecycle tests above. Darwin may report kernel_task as PID/PGID 0.
        script = CORE + r'''
uname() { printf 'Darwin\n'; }
rch_control_capture() { printf '%s\n' "$snapshot"; }
rch_pgid=2147483647
observer="$$ $$ S"
snapshot="0 0 R
$observer"
rch_group_state; [ "$?" = 0 ] || exit 1
snapshot="$snapshot
432 2147483647 E"
rch_group_state; [ "$?" = 1 ] || exit 2
snapshot="0 0 R
$observer
432 2147483647 Z"
rch_group_state; [ "$?" = 0 ] || exit 3
snapshot="$snapshot
malformed"
rch_group_state; [ "$?" = 2 ] || exit 4
snapshot="0 0 R
$observer
$observer"
rch_group_state; [ "$?" = 2 ] || exit 5
snapshot="0 0 R
$$ 2147483647 S"
rch_group_state; [ "$?" = 2 ] || exit 6
rch_control_capture() { return 1; }
rch_group_state; [ "$?" = 2 ] || exit 7
'''
        for shell in ("/bin/sh", "/bin/bash"):
            result = subprocess.run([shell, "-c", script], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, shell + result.stderr)


if __name__ == "__main__":
    unittest.main()
