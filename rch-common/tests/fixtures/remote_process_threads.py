"""Native regressions for the exact RCH shell protocol; requires Linux, cc, sh, bash.

No Rust logic is reimplemented. The test sources the supplied production script,
creates disposable owned process groups and asks its real cancellation functions
for a verdict. The C fixture deliberately exits its main pthread while a second
thread ignores TERM and continues writing. All fixtures have a natural bound.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

C_SOURCE = r"""
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static void *survivor(void *arg) {
    const char *root = arg;
    char name[4096];
    if (snprintf(name, sizeof name, "%s/ready", root) >= (int)sizeof name) _exit(91);
    FILE *ready = fopen(name, "w");
    if (!ready) _exit(92);
    fprintf(ready, "%ld %ld\n", (long)getpid(), (long)syscall(SYS_gettid));
    if (fclose(ready)) _exit(93);
    if (snprintf(name, sizeof name, "%s/writes", root) >= (int)sizeof name) _exit(94);
    FILE *writes = fopen(name, "a");
    if (!writes) _exit(95);
    for (int i = 0; i < 2000; ++i) {
        fputc('x', writes);
        fflush(writes);
        struct timespec delay = {0, 10000000};
        nanosleep(&delay, NULL);
    }
    fclose(writes);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    if (signal(SIGTERM, SIG_IGN) == SIG_ERR) return 96;
    pthread_t thread;
    if (pthread_create(&thread, NULL, survivor, argv[1])) return 97;
    pthread_exit(NULL);
}
"""

LAUNCH = r"""
. "$1"
# This test covers process ownership, not host-specific execution policy.
rch_apply_configured_worker_policy() { return 0; }
rch_remote_record "$2/record" regression || exit 77
"$3" "$2" &
wait "$!"
"""

CANCEL = r"""
. "$1"
rch_remote_cancel "$2/record" regression "$3"
code=$?
printf '%s\n' "$code"
"""

STATE = r"""
. "$1"
rch_read_record "$2/record" regression || exit 77
rch_group_state
code=$?
printf '%s\n' "$code"
"""

# The census runs `ps` in a separate bounded shell (14aea498), so a shell
# function cannot stand in for it: SNAPSHOT_PS is a real executable on PATH.
SNAPSHOT = r"""
. "$1"
rch_pgid=6000000
RCH_TEST_SNAPSHOT=$2
RCH_TEST_OBSERVER_LINE=$3
RCH_TEST_OBSERVER=$$
PATH="$4:$PATH"
export RCH_TEST_SNAPSHOT RCH_TEST_OBSERVER_LINE RCH_TEST_OBSERVER PATH
rch_group_state
"""

SNAPSHOT_PS = r"""#!/bin/sh
[ "$*" = '-e -L -o pid= -o lwp= -o pgid= -o stat= -o nlwp=' ] || exit 99
if [ "$RCH_TEST_OBSERVER_LINE" = yes ]; then
    printf '%s %s %s S 1\n' "$RCH_TEST_OBSERVER" "$RCH_TEST_OBSERVER" "$RCH_TEST_OBSERVER"
fi
if [ -n "$RCH_TEST_SNAPSHOT" ]; then printf '%s\n' "$RCH_TEST_SNAPSHOT"; fi
"""


def process_state(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
        return fields[0]
    except FileNotFoundError:
        return None


def running(pid):
    return process_state(pid) not in (None, b"Z", b"X", b"x")


def until(predicate):
    deadline = time.monotonic() + 5
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("native fixture did not settle")
        time.sleep(0.01)


def invoke(shell, body, protocol, root, *args):
    result = subprocess.run(
        [shell, "-c", body, "rch-thread-test", str(protocol), str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=8,
    )
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    return int(result.stdout.strip())


def native_case(protocol, binary, shell, mode):
    with tempfile.TemporaryDirectory(prefix="rch-thread-case-") as directory:
        root = Path(directory)
        launcher = subprocess.Popen(
            [shell, "-c", LAUNCH, "rch-thread-launch", str(protocol), str(root), str(binary)],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        unrelated = subprocess.Popen(["sleep", "20"], start_new_session=True)
        try:
            ready = root / "ready"
            ids = []

            def ready_ids():
                nonlocal ids
                try:
                    ids = [int(value) for value in ready.read_text().split()]
                    return len(ids) == 2
                except (FileNotFoundError, ValueError):
                    return False

            until(ready_ids)
            pid, tid = ids
            until(lambda: process_state(pid) == b"Z" and running(tid))
            until(lambda: (root / "writes").exists())
            if mode == "orphan":
                # Retain the unreaped launcher as a PID/PGID reuse fence. Do
                # not use poll()/wait() until all group cleanup is complete.
                launcher.kill()
                until(lambda: process_state(launcher.pid) == b"Z")
            state = invoke(shell, STATE, protocol, root)
            code = invoke(shell, CANCEL, protocol, root, "term")
            alive = running(tid)
            size = (root / "writes").stat().st_size
            time.sleep(0.08)
            growth = (root / "writes").stat().st_size - size
            assert unrelated.poll() is None, "unrelated job was signalled"
            return {"shell": shell, "case": mode, "state_before": state,
                    "cancel_code": code, "thread_alive": alive, "late_write_bytes": growth}
        finally:
            # This group belongs to our unreaped child, never a guessed PID.
            try:
                os.killpg(launcher.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            launcher.wait(timeout=5)
            unrelated.kill()
            unrelated.wait(timeout=5)


def build_fixture(directory):
    source = directory / "zombie_threads.c"
    source.write_text(C_SOURCE)
    binary = directory / "zombie_threads"
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
         str(source), "-o", str(binary)],
        check=True, timeout=30,
    )
    return binary


def run(protocol):
    assert sys.platform.startswith("linux"), "native Linux process semantics required"
    assert signal.getsignal(signal.SIGCHLD) != signal.SIG_IGN, "test needs unreaped child fencing"
    protocol = protocol.resolve(strict=True)
    count = 0
    with tempfile.TemporaryDirectory(prefix="rch-thread-native-") as directory:
        binary = build_fixture(Path(directory))
        for shell in ("sh", "bash"):
            row = native_case(protocol, binary, shell, "term")
            print(json.dumps(row), flush=True)
            assert row["state_before"] == 1, row
            assert row["cancel_code"] == 0, row
            assert not row["thread_alive"] and row["late_write_bytes"] == 0, row
            count += 1
            row = native_case(protocol, binary, shell, "orphan")
            print(json.dumps(row), flush=True)
            assert row["state_before"] == 1, row
            assert row["cancel_code"] == 43, row
            assert row["thread_alive"], row
            count += 1

            fake_bin = Path(tempfile.mkdtemp(prefix="rch-snapshot-ps-"))
            (fake_bin / "ps").write_text(SNAPSHOT_PS)
            (fake_bin / "ps").chmod(0o700)
            samples = [
                ("absent", "", "yes", 0),
                ("one-zombie", "6000001 6000001 6000000 Z 1", "yes", 0),
                ("terminal-threads", "6000001 6000001 6000000 Z 2\n6000001 6000002 6000000 Z 2", "yes", 0),
                ("live-thread", "6000001 6000001 6000000 Z 2\n6000001 6000002 6000000 S 2", "yes", 1),
                ("missing-thread", "6000001 6000001 6000000 Z 2", "yes", 2),
                ("changing-terminal-count", "6000001 6000001 6000000 Z 2\n6000001 6000002 6000000 Z 1", "yes", 2),
                ("changing-live-count", "6000001 6000001 6000000 Z 2\n6000001 6000002 6000000 S 3", "yes", 1),
                ("duplicate-tid", "6000001 6000001 6000000 Z 2\n6000001 6000001 6000000 Z 2", "yes", 2),
                ("zero-thread-count", "6000001 6000001 6000000 Z 0", "yes", 2),
                ("unknown-state", "6000001 6000001 6000000 Q 1", "yes", 2),
                ("missing-observer", "6000001 6000001 6000000 Z 1", "no", 2),
                ("truncated-record", "6000001 6000001 6000000", "yes", 2),
            ]
            for name, snapshot, observer, expected in samples:
                result = subprocess.run(
                    [shell, "-c", SNAPSHOT, "rch-snapshot-test", str(protocol), snapshot, observer,
                     str(fake_bin)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                )
                assert result.returncode == expected, (shell, name, result.returncode, result.stderr)
                count += 1
            print(f"{shell}: {len(samples)} snapshot refusal/liveness cases passed", flush=True)
    print(f"PASS: {count} native process and snapshot cases", flush=True)


if __name__ == "__main__":
    assert len(sys.argv) == 2, "usage: remote_process_threads.py <production-protocol.sh>"
    run(Path(sys.argv[1]))
