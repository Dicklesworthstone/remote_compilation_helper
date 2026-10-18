#!/usr/bin/env python3
"""Native launcher recovery tests, not Rust/Cargo/cache qualification.

The production launcher performs real procfs, pidfd, flock and socket I/O.
Reboot and PID-reuse histories are explicitly constructed receipt fixtures;
these tests do not reboot the host or force kernel PID recycling. The small
readiness server is a daemon double, never a compiler or serving-authority stub.
Test files are retained for inspection; only test-owned children are stopped.
"""

import concurrent.futures
import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

LAUNCHER = Path(os.environ.get("RABS_TEST_CARGO_LAUNCHER", str(
    Path(__file__).resolve().parents[1] / "cargo-rabs")))
LOADER = importlib.machinery.SourceFileLoader("rabs_incarnation_launcher", str(LAUNCHER))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
launcher = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(launcher)

SERVER = r'''
import json, os, pathlib, socket, sys, time
path = os.environ["RABS_SOCKET_PATH"]
if sys.argv[1:] == ["--check-config"]:
    print(json.dumps({"kind":"rabsd-config", "live_dependency":True, "socket_path":path}))
    sys.exit(0)
stop = pathlib.Path(os.environ["TEST_STOP"])
if os.path.lexists(path):
    # Test daemon, not the launcher, owns this stale-entry takeover. Retain it.
    os.rename(path, path + ".retained-" + str(os.getpid()))
with socket.socket(socket.AF_UNIX) as server:
    server.bind(path)
    os.chmod(path, 0o600)
    server.listen(16)
    server.settimeout(0.05)
    with open(os.environ["TEST_STARTS"], "a") as started:
        started.write(str(os.getpid()) + "\n")
    while not stop.exists():
        try:
            connection, _ = server.accept()
        except socket.timeout:
            continue
        with connection:
            connection.settimeout(1)
            with connection.makefile("rb") as reader:
                try:
                    hello = json.loads(reader.readline(65536))
                    assert hello["kind"] == "hello"
                    connection.sendall(b'{"kind":"hello-ok","transport":1,"application":1}\n')
                    status = json.loads(reader.readline(65536))
                    assert status["kind"] == "status"
                    connection.sendall(b'{"kind":"coord-status"}\n')
                except (ValueError, AssertionError, OSError):
                    pass
'''


@unittest.skipUnless(sys.platform == "linux", "native Linux recovery evidence")
class IncarnationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ri-", dir="/tmp"))
        self.state = self.root / "state"
        self.endpoint = str(self.root / "edge.sock")
        self.children = []
        self.stop = self.root / "stop"
        self.starts = self.root / "starts"
        self.server = self.root / "rabsd"
        self.server.write_text("#!" + sys.executable + " -S\n" + SERVER)
        self.server.chmod(0o700)
        self.env = dict(os.environ, RABS_SOCKET_PATH=self.endpoint,
                        TEST_STOP=str(self.stop), TEST_STARTS=str(self.starts))

    def tearDown(self):
        self.stop.write_bytes(b"stop owned readiness server")
        for child in self.children:
            if child.stdin is not None and not child.stdin.closed:
                child.stdin.close()
                child.stdin = None
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=2)
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()

    def child(self):
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c",
             "import sys; print('ready', flush=True); sys.stdin.buffer.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.children.append(child)
        self.assertEqual(child.stdout.readline(), b"ready\n")
        return child

    def lock(self):
        return launcher.StartupLock(str(self.state), self.endpoint, time.monotonic() + 2)

    def stale(self):
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(self.endpoint)
            os.chmod(self.endpoint, 0o600)
        return launcher.socket_identity(self.endpoint)

    def receipt(self, value):
        path = self.state / "cargo-launcher" / launcher.OWNER_RECEIPT
        with path.open("w") as stream:
            json.dump(value, stream, separators=(",", ":"))
        path.chmod(0o600)
        return path

    def past(self, child, reboot=False):
        identity = launcher.process_identity(child.pid)
        if reboot:
            identity["boot"] = ("00000000-0000-0000-0000-000000000001"
                                if identity["boot"] != "00000000-0000-0000-0000-000000000001"
                                else "00000000-0000-0000-0000-000000000002")
        else:
            # A synthetic previous incarnation, while the named PID is live.
            identity["start_ticks"] += 1
        return identity

    def launch(self):
        native = subprocess.Popen

        def owned(*args, **kwargs):
            child = native(*args, **kwargs)
            self.children.append(child)
            return child

        with mock.patch.object(launcher.subprocess, "Popen", side_effect=owned):
            launcher.ensure_daemon(str(self.server), self.endpoint, str(self.state),
                                   self.env, time.monotonic() + 3, False)

    def test_live_process_identity_matches_native_stat_and_never_proves_exit(self):
        child = self.child()
        identity = launcher.process_identity(child.pid)
        self.assertTrue(launcher.valid_process_identity(identity))
        raw = Path("/proc/{}/stat".format(child.pid)).read_bytes()
        self.assertEqual(identity["start_ticks"], int(raw.rsplit(b") ", 1)[1].split()[19]))
        self.assertFalse(launcher.process_exited(child.pid, identity))
        self.assertFalse(launcher.process_exited(child.pid))
        self.assertIsNone(child.poll())

    def test_real_exit_and_unreaped_zombie_are_recognized(self):
        child = self.child()
        identity = launcher.process_identity(child.pid)
        child.stdin.close()
        child.stdin = None
        deadline = time.monotonic() + 2
        while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.005)
        self.assertTrue(launcher.process_exited(child.pid, identity))
        self.assertTrue(launcher.process_exited(child.pid))
        self.assertEqual(child.wait(timeout=1), 0)
        self.assertTrue(launcher.process_exited(child.pid, identity))

    def test_reused_pid_witness_proves_only_the_old_owner_absent(self):
        child = self.child()
        old = self.past(child)
        with mock.patch.object(launcher.os, "kill", side_effect=AssertionError("must not signal")):
            self.assertTrue(launcher.process_exited(child.pid, old))
            self.assertFalse(launcher.process_exited(child.pid))
        self.assertIsNone(child.poll(), "the unrelated live process must remain alive")

    def test_previous_boot_witness_does_not_depend_on_current_pid_or_namespace(self):
        child = self.child()
        old = self.past(child, reboot=True)
        old["pid_namespace"][1] += 1
        with mock.patch.object(launcher, "process_identity", side_effect=AssertionError("old boot")):
            self.assertTrue(launcher.process_exited(child.pid, old))
        self.assertIsNone(child.poll())

    def test_same_boot_foreign_namespace_cannot_authorize_recovery(self):
        child = self.child()
        other = self.past(child)
        other["pid_namespace"][1] += 1
        with mock.patch.object(launcher, "pid_exited", side_effect=AssertionError("foreign PID")):
            self.assertFalse(launcher.process_exited(child.pid, other))

    def test_unknown_native_scope_or_process_never_falls_back_to_pid_only(self):
        child = self.child()
        old = self.past(child)
        for function in ("process_scope", "process_identity"):
            for error in (PermissionError("denied"), launcher.SetupError("malformed")):
                with self.subTest(function=function, error=type(error).__name__), \
                     mock.patch.object(launcher, function, side_effect=error), \
                     mock.patch.object(launcher, "pid_exited", side_effect=AssertionError("fallback")):
                    self.assertFalse(launcher.process_exited(child.pid, old))

    def test_changed_scope_during_observation_is_unknown(self):
        child = self.child()
        old = self.past(child)
        scope = launcher.process_scope()
        other = copy.deepcopy(scope)
        other["pid_namespace"][1] += 1
        current = launcher.process_identity(child.pid)
        with mock.patch.object(launcher, "process_identity", return_value=current), \
             mock.patch.object(launcher, "process_scope", side_effect=[scope, other]):
            self.assertFalse(launcher.process_exited(child.pid, old))
        with mock.patch.object(launcher, "process_scope", side_effect=[scope, other]):
            with self.assertRaises(launcher.SetupError):
                launcher.process_identity(child.pid)

    def test_mismatched_proc_mount_is_not_a_native_process_observation(self):
        with mock.patch.object(launcher.os, "readlink", return_value=str(os.getpid() + 1)):
            with self.assertRaises(launcher.SetupError):
                launcher.process_scope()

    def test_stat_parser_handles_opaque_comm_without_rounding_ticks(self):
        for comm in (b"plain", b"a ) tricky ( name", b"line\nbreak) \xff"):
            fields = [b"S"] + [b"0"] * 18 + [b"18446744073709551615", b"0", b"0"]
            data = b"27 (" + comm + b") " + b" ".join(fields) + b"\n"
            self.assertEqual(launcher.process_start_ticks(data, 27), 0xffffffffffffffff)
        for ticks in (b"0", b"01", b"-1", b"+1", b"1.0", b"18446744073709551616"):
            data = b"27 (name) S " + b"0 " * 18 + ticks
            with self.subTest(ticks=ticks), self.assertRaises(launcher.SetupError):
                launcher.process_start_ticks(data, 27)
        for data in (b"", b"27 (name) S 1", b"28 (name) S " + b"0 " * 18 + b"1"):
            with self.assertRaises(launcher.SetupError):
                launcher.process_start_ticks(data, 27)

    def test_identity_schema_is_shallow_bounded_and_bool_is_not_integer(self):
        good = launcher.process_identity(os.getpid())
        variants = [None, [], {}, dict(good, extra=1)]
        for field, values in {
            "boot": [None, True, "x", "A" * 36, good["boot"] + "\n"],
            "pid_namespace": [None, [1], [1, 2, 3], [True, 2], [1, False], [1, 0], [-1, 2]],
            "start_ticks": [None, True, "1", 0, -1, 1 << 64],
        }.items():
            variants.extend(dict(good, **{field: value}) for value in values)
        for value in variants:
            with self.subTest(value=value):
                self.assertFalse(launcher.valid_process_identity(value))
                if value is not None:
                    self.assertFalse(launcher.process_exited(os.getpid(), value))
        for pid in (0, 1, -1, True, "10", 1 << 31):
            self.assertFalse(launcher.process_exited(pid, good))

    def test_proc_reader_refuses_unbounded_nonregular_or_linked_input_without_fd_leaks(self):
        ordinary = self.root / "record"
        ordinary.write_bytes(b"bounded")
        alias = self.root / "alias"
        alias.symlink_to(ordinary)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        before = len(os.listdir("/proc/self/fd"))
        for path in (ordinary, alias, fifo, self.root):
            with self.subTest(path=path), self.assertRaises((OSError, launcher.SetupError)):
                launcher.read_proc_bytes(path, 3)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        self.assertEqual(launcher.read_proc_bytes(ordinary, 7), b"bounded")

    def test_new_owner_receipt_records_exact_native_incarnation_and_refuses_live_owner(self):
        child = self.child()
        identity = self.stale()
        with self.lock() as lock:
            self.assertTrue(lock.acquire(self.endpoint))
            lock.record_owner(child.pid, identity)
            path = self.state / "cargo-launcher" / launcher.OWNER_RECEIPT
            value = json.loads(path.read_bytes())
            self.assertEqual(value["v"], 2)
            self.assertEqual(value["process"], launcher.process_identity(child.pid))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertLessEqual(path.stat().st_size, launcher.MAX_OWNER_RECEIPT)
            with self.assertRaises(launcher.SetupError):
                lock.authorize_recovery(identity)
        self.assertEqual(launcher.socket_identity(self.endpoint), identity)

    def test_pid_reuse_and_reboot_receipts_pass_both_real_lock_and_socket_bindings(self):
        child = self.child()
        identity = self.stale()
        with self.lock() as lock:
            self.assertTrue(lock.acquire(self.endpoint))
            for reboot in (False, True):
                self.receipt(lock.owner_binding(child.pid, identity, self.past(child, reboot)))
                lock.authorize_recovery(identity)
                self.assertIsNone(child.poll())
                self.assertEqual(launcher.socket_identity(self.endpoint), identity)

    def test_legacy_receipt_retains_absence_only_behavior(self):
        child = self.child()
        identity = self.stale()
        with self.lock() as lock:
            self.assertTrue(lock.acquire(self.endpoint))
            self.receipt(lock.owner_binding(child.pid, identity))
            with self.assertRaises(launcher.SetupError):
                lock.authorize_recovery(identity)
            child.stdin.close()
            child.stdin = None
            child.wait(timeout=1)
            lock.authorize_recovery(identity)

    def test_new_identity_cannot_override_lock_socket_state_or_receipt_integrity(self):
        child = self.child()
        identity = self.stale()
        with self.lock() as lock:
            self.assertTrue(lock.acquire(self.endpoint))
            good = lock.owner_binding(child.pid, identity, self.past(child))
            variants = [dict(good, v=True), dict(good, v=3), dict(good, process=None),
                        dict(good, unexpected=True), dict(good, pid=True)]
            for name in ("socket", "state", "endpoint_lock"):
                changed = copy.deepcopy(good)
                changed[name][0] += 1
                variants.append(changed)
            for value in variants:
                self.receipt(value)
                with self.assertRaises(launcher.SetupError):
                    lock.authorize_recovery(identity)
            self.receipt(good)
            lock.acquired = False
            with self.assertRaises(launcher.SetupError):
                lock.authorize_recovery(identity)
        self.assertEqual(launcher.socket_identity(self.endpoint), identity)
        self.assertIsNone(child.poll())

    def test_missing_native_identity_does_not_replace_a_previous_receipt(self):
        child = self.child()
        identity = self.stale()
        with self.lock() as lock:
            self.assertTrue(lock.acquire(self.endpoint))
            path = self.receipt(lock.owner_binding(child.pid, identity))
            before = path.read_bytes()
            with mock.patch.object(launcher, "process_identity", side_effect=PermissionError("proc")):
                with self.assertRaises(PermissionError):
                    lock.record_owner(child.pid, identity)
            self.assertEqual(path.read_bytes(), before)

    def test_recovery_starts_one_ready_daemon_and_does_not_touch_reused_pid(self):
        unrelated = self.child()
        identity = self.stale()
        with self.lock() as lock:
            self.assertTrue(lock.acquire(self.endpoint))
            self.receipt(lock.owner_binding(unrelated.pid, identity, self.past(unrelated)))
        self.launch()
        self.launch()
        self.assertEqual(len(self.starts.read_text().splitlines()), 1)
        self.assertIsNone(unrelated.poll())
        value = json.loads((self.state / "cargo-launcher" / launcher.OWNER_RECEIPT).read_bytes())
        self.assertNotEqual(value["pid"], unrelated.pid)
        self.assertEqual(value["process"], launcher.process_identity(value["pid"]))

    def test_no_start_and_live_owner_never_spawn_even_with_a_stale_socket(self):
        child = self.child()
        identity = self.stale()
        with self.lock() as lock:
            self.assertTrue(lock.acquire(self.endpoint))
            lock.record_owner(child.pid, identity)
        with mock.patch.object(launcher.subprocess, "Popen", side_effect=AssertionError("no spawn")):
            for no_start in (True, False):
                with self.assertRaises(launcher.SetupError):
                    launcher.ensure_daemon(str(self.server), self.endpoint, str(self.state),
                                           self.env, time.monotonic() + 1, no_start)
        self.assertEqual(launcher.socket_identity(self.endpoint), identity)

    def test_real_daemon_exit_reopens_state_and_advances_the_native_owner_receipt(self):
        self.launch()
        receipt = self.state / "cargo-launcher" / launcher.OWNER_RECEIPT
        first = json.loads(receipt.read_bytes())
        self.stop.write_bytes(b"test-owned daemon exits, leaving its socket")
        self.assertEqual(self.children[0].wait(timeout=2), 0)
        self.stop = self.root / "stop-second"
        self.env["TEST_STOP"] = str(self.stop)
        self.launch()
        second = json.loads(receipt.read_bytes())
        self.assertNotEqual(first["pid"], second["pid"])
        self.assertEqual(first["state"], second["state"])
        self.assertEqual(first["endpoint_lock"], second["endpoint_lock"])
        self.assertNotEqual(first["socket"], second["socket"])
        self.assertEqual(second["process"], launcher.process_identity(second["pid"]))
        self.assertEqual(len(self.starts.read_text().splitlines()), 2)

    def test_connected_unresponsive_peer_is_never_recovery_evidence(self):
        import threading
        release = threading.Event()
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(self.endpoint)
            os.chmod(self.endpoint, 0o600)
            server.listen(1)
            server.settimeout(1)

            def hold():
                with server.accept()[0] as connection:
                    release.wait(1)

            thread = threading.Thread(target=hold)
            thread.start()
            try:
                with mock.patch.object(launcher.subprocess, "Popen", side_effect=AssertionError("no spawn")):
                    with self.assertRaises((launcher.SetupError, OSError)):
                        launcher.ensure_daemon(str(self.server), self.endpoint, str(self.state),
                                               self.env, time.monotonic() + 0.1, False)
            finally:
                release.set()
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(self.state.exists(), "a live peer never enters startup/recovery")

    def test_full_launcher_preserves_cargo_exec_argv_streams_jobserver_and_status(self):
        self.launch()
        cargo = self.root / "cargo"
        cargo.write_text("#!" + sys.executable + " -S\n"
            "import json,os,sys\n"
            "print(json.dumps({'pid':os.getpid(), 'argv':sys.argv[1:], "
            "'stdin':sys.stdin.buffer.read().hex(), 'wrapper':os.environ['RUSTC_WRAPPER'], "
            "'jobserver':os.read(int(os.environ['TEST_JOBSERVER']),1).hex()}), flush=True)\n"
            "sys.exit(23)\n")
        cargo.chmod(0o700)
        wrapper = self.root / "rabs-wrap"
        wrapper.write_text("#!/bin/sh\nexit 97\n")
        wrapper.chmod(0o700)
        reader, writer = os.pipe()
        try:
            os.write(writer, b"+")
            env = dict(self.env, CARGO=str(cargo), CARGO_RABS_DAEMON=str(self.server),
                       CARGO_RABS_WRAP=str(wrapper), RABS_STATE_DIR=str(self.state),
                       TEST_JOBSERVER=str(reader))
            env.pop("RUSTC_WRAPPER", None)
            env.pop("CARGO_BUILD_RUSTC_WRAPPER", None)
            args = ["check", "--features", "a b", "", "opaque-\udcff", "$(not executed)"]
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", str(LAUNCHER), "rabs", "--rabs-no-start",
                 "--rabs-require-daemon", "--"] + args,
                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(reader, writer),
            )
            self.children.append(process)
            out, err = process.communicate(b"original stdin\x00\xff", timeout=3)
            self.assertEqual(process.returncode, 23, err)
            observed = json.loads(out)
            self.assertEqual(observed, {
                "pid":process.pid, "argv":args, "stdin":b"original stdin\x00\xff".hex(),
                "wrapper":str(wrapper), "jobserver":b"+".hex(),
            })
            self.assertEqual(err, b"")
            self.assertEqual(len(self.starts.read_text().splitlines()), 1)
        finally:
            os.close(reader)
            os.close(writer)

    def test_parallel_recovery_has_one_daemon_and_preserves_lifetime_locks(self):
        child = self.child()
        identity = self.stale()
        with self.lock() as lock:
            self.assertTrue(lock.acquire(self.endpoint))
            self.receipt(lock.owner_binding(child.pid, identity, self.past(child, reboot=True)))
        native = subprocess.Popen

        def owned(*args, **kwargs):
            process = native(*args, **kwargs)
            self.children.append(process)
            return process

        def launch(_):
            launcher.ensure_daemon(str(self.server), self.endpoint, str(self.state),
                                   self.env, time.monotonic() + 3, False)

        with mock.patch.object(launcher.subprocess, "Popen", side_effect=owned):
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(launch, range(4)))
        self.assertEqual(len(self.starts.read_text().splitlines()), 1)
        with self.lock() as lock:
            self.assertFalse(lock.acquire(self.endpoint), "healthy daemon owns lifetime locks")
        self.assertIsNone(child.poll())


if __name__ == "__main__":
    unittest.main(verbosity=2)
