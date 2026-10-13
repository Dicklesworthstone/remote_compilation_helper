#!/usr/bin/env python3
"""Real-worker preparation transactions on Linux; no network or actual npm.

Pass the compiled rch-wkr binary as the only argument. The test-owned npm
records actual invocations. Fixtures are retained; teardown only stops worker
processes created here and releases the bounded test installers it launched.
"""

import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

WORKER = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else None
IDLE = b"RCH_PREPARE_V1:idle\n"
RUNNING = b"RCH_PREPARE_V1:running\n"

NPM = r'''#!/bin/sh
set -eu
[ "$#" = 1 ] && [ "$1" = ci ] || exit 90
printf 'install\n' >> "$RCH_PREPARE_TEST_STATE/events"
printf '%s\n' "$$" > "$RCH_PREPARE_TEST_STATE/started"
case "$RCH_PREPARE_TEST_MODE" in
    blocked)
        n=0
        while [ ! -f "$RCH_PREPARE_TEST_STATE/release" ]; do
            n=$((n + 1))
            [ "$n" -lt 2000 ] || exit 91
            sleep 0.01
        done
        ;;
    failure) exit 19 ;;
    timeout) exec sleep 30 ;;
    immediate) ;;
    *) exit 92 ;;
esac
mkdir -p node_modules
printf 'complete\n' > node_modules/fixture-dependency
printf 'finished\n' > "$RCH_PREPARE_TEST_STATE/finished"
'''


def eventually(predicate, message, timeout=6):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(message)


class PrepareTransactions(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-prepare-transactions-"))
        self.bin = self.root / "bin"
        self.home = self.root / "home"
        self.bin.mkdir()
        self.home.mkdir()
        self.children = []
        self.states = []
        # Never fall through to a machine's real npm, registry, or user config.
        for name in ("sh", "mkdir", "sleep"):
            executable = shutil.which(name)
            self.assertIsNotNone(executable, name)
            (self.bin / name).symlink_to(executable)
        npm = self.bin / "npm"
        npm.write_text(NPM)
        npm.chmod(0o700)
        tsc = self.bin / "tsc"
        tsc.write_text('#!/bin/sh\nprintf ran > "$RCH_PREPARE_TEST_STATE/user-command"\n')
        tsc.chmod(0o700)

    def tearDown(self):
        for state in self.states:
            (state / "release").write_bytes(b"release\n")
        for child in self.children:
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)

    def project(self, name):
        project = self.root / name
        state = self.root / (name + "-state")
        project.mkdir()
        state.mkdir()
        (project / "package.json").write_text('{"name":"fixture","version":"1.0.0"}\n')
        (project / "package-lock.json").write_text('{"lockfileVersion":3}\n')
        self.states.append(state)
        return project, state

    def start(self, project, state, mode="immediate", execute=False):
        args = (["execute", "--workdir", str(project), "--command", "tsc --noEmit"]
                if execute else ["prepare", "--project", str(project), "--runtime", "node"])
        env = {
            "PATH": str(self.bin), "HOME": str(self.home), "LC_ALL": "C",
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_STATE_HOME": str(self.home / ".local/state"),
            "TOKIO_WORKER_THREADS": "2", "RCH_PREPARE_INSTALL_TIMEOUT_SECS": "1" if mode == "timeout" else "20",
            "RCH_PREPARE_TEST_STATE": str(state), "RCH_PREPARE_TEST_MODE": mode,
        }
        child = subprocess.Popen([WORKER, *args], env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(child)
        return child

    def report(self, child, expected_code):
        stdout, stderr = child.communicate(timeout=8)
        self.assertEqual(child.returncode, expected_code, (stdout, stderr))
        return json.loads(stdout)

    def journals(self):
        return sorted((self.home / ".cache/rch/prepare-transactions").glob("*.lock"))

    def events(self, state):
        path = state / "events"
        return path.read_text().splitlines() if path.exists() else []

    def test_concurrent_processes_install_once_then_reuse(self):
        project, state = self.project("shared")
        first = self.start(project, state, "blocked")
        eventually(lambda: (state / "started").exists(), "first installer did not start")
        journal, = self.journals()
        self.assertEqual(journal.read_bytes(), RUNNING)
        with journal.open("r+b") as file:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        second = self.start(project / ".", state)

        def second_opened_gate():
            self.assertIsNone(second.poll(), "second worker exited before waiting on the live owner")
            try:
                return any(os.readlink(entry) == str(journal)
                           for entry in Path(f"/proc/{second.pid}/fd").iterdir())
            except FileNotFoundError:
                return False

        # Observe entry into the real lock acquisition, not a scheduling sleep.
        eventually(second_opened_gate, "second worker never opened the transaction gate")
        self.assertEqual(self.events(state), ["install"])
        (state / "release").write_bytes(b"release\n")
        self.assertEqual(self.report(first, 0)["action"], "Installed")
        self.assertEqual(self.report(second, 0)["action"], "Skipped")
        self.assertEqual(self.events(state), ["install"])
        self.assertEqual(journal.read_bytes(), IDLE)

    def test_disjoint_projects_progress_in_the_same_cache(self):
        a, sa = self.project("a")
        b, sb = self.project("b")
        first = self.start(a, sa, "blocked")
        eventually(lambda: (sa / "started").exists(), "first installer did not start")
        self.assertEqual(self.report(self.start(b, sb), 0)["action"], "Installed")
        self.assertIsNone(first.poll(), "unrelated project must finish while the first is still blocked")
        self.assertEqual(len(self.journals()), 2)
        (sa / "release").write_bytes(b"release\n")
        self.report(first, 0)

    def test_worker_crash_preserves_fence_while_installer_can_still_run(self):
        project, state = self.project("crash")
        first = self.start(project, state, "blocked")
        eventually(lambda: (state / "started").exists(), "installer did not start")
        journal, = self.journals()
        first.kill()  # Exact owned worker, never a historical PID/group lookup.
        first.communicate(timeout=5)
        self.assertEqual(journal.read_bytes(), RUNNING)
        self.assertEqual(self.report(self.start(project, state), 1)["action"], "Failed")
        self.assertEqual(self.events(state), ["install"], "uncertain owner must not trigger a second installer")
        (state / "release").write_bytes(b"release\n")
        eventually(lambda: (state / "finished").exists(), "retained fixture installer did not finish")
        self.assertEqual(journal.read_bytes(), RUNNING, "installer exit alone cannot manufacture a completed transaction")

    def test_terminal_install_failure_can_retry_without_reusing_a_stamp(self):
        project, state = self.project("failure")
        self.assertEqual(self.report(self.start(project, state, "failure"), 1)["action"], "Failed")
        journal, = self.journals()
        self.assertEqual(journal.read_bytes(), IDLE)
        self.assertEqual(self.report(self.start(project, state), 0)["action"], "Installed")
        self.assertEqual(self.events(state), ["install", "install"])

    def test_timeout_never_authorizes_a_retry_against_unconfirmed_descendants(self):
        project, state = self.project("timeout")
        self.assertEqual(self.report(self.start(project, state, "timeout"), 2)["action"], "Timeout")
        journal, = self.journals()
        self.assertEqual(journal.read_bytes(), RUNNING)
        self.assertEqual(self.report(self.start(project, state), 1)["action"], "Failed")
        self.assertEqual(self.events(state), ["install"])

    def test_prepare_io_error_cannot_launch_the_users_command(self):
        project, state = self.project("missing-manager")
        (self.bin / "npm").rename(self.bin / "npm-retained")
        child = self.start(project, state, execute=True)
        stdout, stderr = child.communicate(timeout=8)
        self.assertNotEqual(child.returncode, 0, (stdout, stderr))
        self.assertFalse((state / "user-command").exists(), "executor must not fail open after preparation IO error")

    def test_failed_stamp_publication_is_not_success(self):
        project, state = self.project("stamp-error")
        (project / ".rch_dep_fingerprint.json").mkdir()
        self.assertEqual(self.report(self.start(project, state), 1)["action"], "Failed")
        journal, = self.journals()
        self.assertEqual(journal.read_bytes(), RUNNING)
        self.assertEqual(self.report(self.start(project, state), 1)["action"], "Failed")
        self.assertEqual(self.events(state), ["install"])

    def test_journal_symlink_is_refused_without_changing_its_target(self):
        project, state = self.project("journal-type")
        self.report(self.start(project, state), 0)
        journal, = self.journals()
        journal.rename(journal.with_suffix(".retained"))
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"not a transaction")
        journal.symlink_to(sentinel)
        self.assertEqual(self.report(self.start(project, state), 1)["action"], "Failed")
        self.assertEqual(sentinel.read_bytes(), b"not a transaction")
        self.assertEqual(self.events(state), ["install"])


if __name__ == "__main__":
    if WORKER is None or not Path(WORKER).is_file():
        raise SystemExit("usage: prepare_transactions.py /absolute/path/to/rch-wkr")
    unittest.main(verbosity=2)
