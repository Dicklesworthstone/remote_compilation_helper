#!/usr/bin/env python3
"""Real-worker ownership of Yarn configuration-query descendants on Linux.

The manager here is an explicit deterministic test fixture, not real Yarn.
The worker, transaction journal, query capture and all-descendant supervisor
are production code. Authentic offline Yarn/TypeScript qualification lives in
prepare_yarn_pnp.py. Run with the compiled worker as the first argument.
"""

import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import sys
import unittest


spec = importlib.util.spec_from_file_location(
    "rch_prepare_transactions", Path(__file__).with_name("prepare_transactions.py")
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

QUERY = r'''#!/bin/sh
set -eu
case "${1-}" in
    --version) printf '4.18.1\n'; exit 0 ;;
    config)
        [ "$#" = 2 ] && [ "$2" = --json ] || exit 98
        case "$RCH_YARN_QUERY_MODE" in
            immediate) ;;
            failure) exit 29 ;;
            hold)
                printf '%s\n' "$$" > "$RCH_PREPARE_TEST_STATE/query-leader-pid"
                printf '%s\n' "$PPID" > "$RCH_PREPARE_TEST_STATE/query-supervisor-pid"
                printf ready > "$RCH_PREPARE_TEST_STATE/query-holding"
                count=0
                while [ ! -f "$RCH_PREPARE_TEST_STATE/query-release" ]; do
                    count=$((count + 1))
                    [ "$count" -lt 3000 ] || exit 97
                    sleep 0.01
                done
                ;;
            detached)
                # A session change and closed stdio defeat process-group-only
                # and pipe-EOF completion. The actual worker must still own it.
                setsid sh -c '
                    printf "%s\n" "$$" > "$RCH_PREPARE_TEST_STATE/query-descendant-pid"
                    printf ready > "$RCH_PREPARE_TEST_STATE/query-started"
                    count=0
                    while [ ! -f "$RCH_PREPARE_TEST_STATE/query-release" ]; do
                        count=$((count + 1))
                        [ "$count" -lt 3000 ] || exit 97
                        sleep 0.01
                    done
                    printf settled > "$RCH_PREPARE_TEST_STATE/query-finished"
                ' </dev/null >/dev/null 2>&1 &
                ;;
            *) exit 96 ;;
        esac
        printf '{"key":"nodeLinker","effective":"node-modules"}\n'
        exit 0 ;;
esac
'''


class YarnQueryTransactions(fixture.PrepareTransactions):
    def setUp(self):
        super().setUp()
        setsid = shutil.which("setsid")
        self.assertIsNotNone(setsid)
        (self.bin / "setsid").symlink_to(setsid)
        # Berry uses --immutable, independently asserted by this manager.
        installer = fixture.NPM.replace('[ "$2" = --frozen-lockfile ]',
                                        '[ "$2" = --immutable ]')
        (self.bin / "yarn").write_text(QUERY + installer.split("\n", 1)[1])

    def tearDown(self):
        for state in self.states:
            (state / "query-release").write_text("release\n")
        super().tearDown()

    def yarn_project(self, name):
        project, state = self.project(name, lock="yarn.lock")
        (project / "package.json").write_text(json.dumps({
            "name": name, "version": "1.0.0", "packageManager": "yarn@4.18.1",
        }))
        (project / "yarn.lock").write_text("__metadata:\n  version: 8\n")
        return project, state

    def query_worker(self, project, state, mode="detached"):
        return self.start(project, state, manager="yarn", plan="frozen",
                          extra_env={"RCH_YARN_QUERY_MODE": mode})

    def grouped_query_worker(self, project, state):
        # Own a separate session before starting the worker so the test may
        # signal this exact outer group without touching its own caller.
        environment = {
            "PATH": str(self.bin), "HOME": str(self.home), "LC_ALL": "C",
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_STATE_HOME": str(self.home / ".local/state"),
            "TOKIO_WORKER_THREADS": "2", "RCH_PREPARE_INSTALL_TIMEOUT_SECS": "20",
            "RCH_PREPARE_TEST_STATE": str(state), "RCH_PREPARE_TEST_MODE": "immediate",
            "RCH_PREPARE_EXPECT_MANAGER": "yarn", "RCH_PREPARE_EXPECT_PLAN": "frozen",
            "RCH_PREPARE_TEST_NEW_LOCK": "", "RCH_YARN_QUERY_MODE": "hold",
        }
        child = fixture.subprocess.Popen(
            [fixture.WORKER, "prepare", "--project", str(project), "--runtime", "node"],
            env=environment, stdin=fixture.subprocess.DEVNULL,
            stdout=fixture.subprocess.PIPE, stderr=fixture.subprocess.PIPE,
            start_new_session=True,
        )
        self.children.append(child)
        return child

    def descendant_handle(self, state):
        fixture.eventually(lambda: (state / "query-started").exists(),
                           "configuration query did not start its detached descendant")
        pid = int((state / "query-descendant-pid").read_text())
        return os.pidfd_open(pid)

    def assert_descendant_exited(self, handle):
        poller = select.poll()
        poller.register(handle, select.POLLIN)
        self.assertTrue(poller.poll(4000), "released query fixture descendant did not exit")

    def test_query_receipt_waits_for_detached_stdio_closed_writer(self):
        project, state = self.yarn_project("query-descendant")
        child = self.query_worker(project, state)
        handle = self.descendant_handle(state)
        try:
            with self.assertRaises(fixture.subprocess.TimeoutExpired):
                child.communicate(timeout=0.2)
            self.assertFalse((project / "node_modules").exists())
            self.assertEqual(self.journals()[0].read_bytes(), fixture.RUNNING)
            (state / "query-release").write_text("release\n")
            output, error = child.communicate(timeout=30)
            self.assertEqual(child.returncode, 0, (output, error))
            self.assertEqual(json.loads(output)["action"], "Installed")
            self.assertEqual((state / "query-finished").read_text(), "settled")
            self.assert_descendant_exited(handle)
            self.assertEqual(self.journals()[0].read_bytes(), fixture.IDLE)
            self.assertEqual(self.events(state), ["install"])
        finally:
            os.close(handle)

    def test_query_supervisor_and_foreground_manager_remain_in_outer_job_group(self):
        project, state = self.yarn_project("query-owned-group")
        child = self.grouped_query_worker(project, state)
        handles = []
        try:
            fixture.eventually(lambda: (state / "query-holding").exists(),
                               "foreground configuration query did not reach its hold point")
            leader = int((state / "query-leader-pid").read_text())
            supervisor = int((state / "query-supervisor-pid").read_text())
            handles.append(os.pidfd_open(supervisor))
            handles.append(os.pidfd_open(leader))
            group = os.getpgid(child.pid)
            print("\nquery process identities: " + json.dumps({
                "worker_pid": child.pid, "worker_group": group,
                "supervisor_pid": supervisor, "supervisor_group": os.getpgid(supervisor),
                "manager_pid": leader, "manager_group": os.getpgid(leader),
            }), flush=True)
            self.assertEqual(group, child.pid, "fixture must own a separate outer job group")
            self.assertEqual(os.getpgid(supervisor), group,
                             "query supervisor must not escape the outer job group")
            self.assertEqual(os.getpgid(leader), group,
                             "foreground query must remain inside the outer job group")
            journal, = self.journals()
            self.assertEqual(journal.read_bytes(), fixture.RUNNING)
            self.assertEqual(self.events(state), [])
            # This models outer-job cancellation, not a promise that killing
            # one PID contains a deliberately detached setsid descendant.
            os.killpg(group, signal.SIGKILL)
            output, error = child.communicate(timeout=8)
            self.assertEqual(child.returncode, -signal.SIGKILL, (output, error))
            self.assertEqual(output, b"")
            for handle in handles:
                self.assert_descendant_exited(handle)
            self.assertEqual(journal.read_bytes(), fixture.RUNNING)
            self.assertEqual(self.events(state), [])
            retry = self.query_worker(project, state, "immediate")
            retry_output, retry_error = retry.communicate(timeout=8)
            self.assertNotEqual(retry.returncode, 0, (retry_output, retry_error))
            self.assertEqual(json.loads(retry_output)["action"], "Failed")
            self.assertIn(b"interrupted or invalid transaction", retry_error)
            self.assertEqual(journal.read_bytes(), fixture.RUNNING)
        finally:
            (state / "query-release").write_text("release\n")
            try:
                for handle in handles:
                    poller = select.poll()
                    poller.register(handle, select.POLLIN)
                    if not poller.poll(4000):
                        # An old implementation can escape the owned outer
                        # group. Signal only the exact test process, identified
                        # by its live kernel handle, never its escaped group.
                        try:
                            signal.pidfd_send_signal(handle, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    self.assert_descendant_exited(handle)
            finally:
                for handle in handles:
                    os.close(handle)

    def test_query_timeout_and_cancellation_fence_future_preparation(self):
        for mode in ("timeout", "cancel"):
            with self.subTest(mode=mode):
                before = set(self.journals())
                project, state = self.yarn_project("query-" + mode)
                child = self.query_worker(project, state)
                handle = self.descendant_handle(state)
                try:
                    if mode == "cancel":
                        child.kill()
                    output, error = child.communicate(timeout=20)
                    self.assertNotEqual(child.returncode, 0, (output, error))
                    if mode == "cancel":
                        self.assertEqual(output, b"")
                    else:
                        self.assertEqual(json.loads(output)["action"], "Failed")
                    journal, = set(self.journals()) - before
                    self.assertEqual(journal.read_bytes(), fixture.RUNNING)
                    self.assertEqual(self.events(state), [])
                    self.assertFalse((state / "query-finished").exists())
                    retry = self.query_worker(project, state, "immediate")
                    retry_output, retry_error = retry.communicate(timeout=8)
                    self.assertNotEqual(retry.returncode, 0, (retry_output, retry_error))
                    self.assertEqual(json.loads(retry_output)["action"], "Failed")
                    self.assertIn(b"interrupted or invalid transaction", retry_error)
                    self.assertEqual(self.events(state), [])
                    self.assertEqual(journal.read_bytes(), fixture.RUNNING)
                    # Cancellation cannot claim that an escaped session was
                    # killed. Release only this test-owned bounded writer and
                    # prove its exact exit; late completion must not clear the
                    # worker's durable uncertainty fence.
                    (state / "query-release").write_text("release\n")
                    self.assert_descendant_exited(handle)
                    self.assertEqual(journal.read_bytes(), fixture.RUNNING)
                finally:
                    os.close(handle)

    def test_completed_query_failure_restores_idle_without_installing(self):
        project, state = self.yarn_project("query-failure")
        child = self.query_worker(project, state, "failure")
        output, error = child.communicate(timeout=15)
        self.assertNotEqual(child.returncode, 0, (output, error))
        self.assertEqual(json.loads(output)["action"], "Failed")
        self.assertIn(b"Yarn configuration query failed", error)
        self.assertEqual(self.events(state), [])
        self.assertEqual(self.journals()[0].read_bytes(), fixture.IDLE)
        retry = self.query_worker(project, state, "immediate")
        output, error = retry.communicate(timeout=30)
        self.assertEqual(retry.returncode, 0, (output, error))
        self.assertEqual(json.loads(output)["action"], "Installed")
        self.assertEqual(self.journals()[0].read_bytes(), fixture.IDLE)


if __name__ == "__main__":
    if fixture.WORKER is None or not Path(fixture.WORKER).is_file():
        raise SystemExit("usage: prepare_yarn_queries.py /absolute/path/to/rch-wkr [test_name ...]")
    names = sys.argv[1:] or sorted(name for name in YarnQueryTransactions.__dict__
                                   if name.startswith("test_"))
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.TestSuite(YarnQueryTransactions(name) for name in names)
    )
    raise SystemExit(not result.wasSuccessful())
