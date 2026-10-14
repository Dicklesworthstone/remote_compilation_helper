#!/usr/bin/env python3
"""Native launcher regressions; fake Cargo/rabsd, real processes and Unix sockets.

This does NOT claim Rust compilation or cache-hit conformance. The real Cargo
lane is covered separately by rabs-wrap/tests/live_cargo_worktrees.rs.
"""

import concurrent.futures
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

LAUNCHER = Path(__file__).resolve().parents[1] / "cargo-rabs"
loader = importlib.machinery.SourceFileLoader("cargo_rabs", str(LAUNCHER))
spec = importlib.util.spec_from_loader(loader.name, loader)
rabs = importlib.util.module_from_spec(spec)
loader.exec_module(rabs)

CARGO = r'''
import json, os, signal, sys
keys = ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTUP_TOOLCHAIN",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_MAKEFLAGS", "RABS_SOCKET_PATH",
        "RABS_STATE_DIR", "RABS_CONFIG", "RABS_BREAKER_FILE", "CARGO_TARGET_DIR"]
value = {"argv": [os.fsencode(x).hex() for x in sys.argv[1:]],
         "env": {k: os.environ[k] for k in keys if k in os.environ},
         "pid": os.getpid(), "cwd": os.getcwd()}
if "TEST_JOBSERVER_FD" in os.environ:
    value["jobserver"] = os.read(int(os.environ["TEST_JOBSERVER_FD"]), 1).hex()
print(json.dumps(value), flush=True)
print("cargo's own stderr", file=sys.stderr, flush=True)
if os.environ.get("TEST_CARGO_SIGNAL"):
    os.kill(os.getpid(), int(os.environ["TEST_CARGO_SIGNAL"]))
sys.exit(int(os.environ.get("TEST_CARGO_STATUS", "0")))
'''

DAEMON = r'''
import json, os, pathlib, socket, sys, time
root = pathlib.Path(os.environ["TEST_ROOT"])
path = os.environ["RABS_SOCKET_PATH"]
mode = os.environ.get("TEST_CONFIG", "good")
if sys.argv[1:] == ["--check-config"]:
    if mode == "hang":
        time.sleep(10)
    if mode == "oversize":
        print("x" * 100000)
        sys.exit(0)
    if mode == "invalid":
        print("{broken}")
        sys.exit(0)
    if mode == "refuse":
        sys.exit(2)
    print(json.dumps({"v": 1, "kind": "rabsd-config", "socket_path": path,
                     "log_level": "info", "live_dependency": mode != "old" and
                     os.environ.get("RABS_LIVE_DEPENDENCY") == "1"}))
    sys.exit(0)
with open(root / "starts", "a") as f:
    f.write(json.dumps({"pid": os.getpid(), "pgid": os.getpgrp(),
                        "live": os.environ.get("RABS_LIVE_DEPENDENCY")}) + "\n")
if os.environ.get("TEST_START_GATE"):
    gate = pathlib.Path(os.environ["TEST_START_GATE"])
    deadline = time.monotonic() + 10
    while not gate.exists() and root.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not gate.exists():
        sys.exit(32)
time.sleep(float(os.environ.get("TEST_START_DELAY", "0")))
if not root.exists():
    sys.exit(0)
if os.environ.get("TEST_START_FAIL"):
    sys.exit(31)
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(path)
os.chmod(path, 0o600)
listener.listen(64)
listener.settimeout(0.1)
end = time.monotonic() + 20
running = True
while running and time.monotonic() < end and root.exists():
    try:
        peer, _ = listener.accept()
    except socket.timeout:
        continue
    with peer:
        peer.settimeout(1)
        try:
            reader = peer.makefile("rb")
            request = json.loads(reader.readline())
            if request.get("kind") == "test-stop":
                running = False
                reader.close()
                continue
            if request.get("kind") != "hello":
                reader.close()
                continue
            peer.sendall(b'{"kind":"hello-ok","transport":1,"application":1}\n')
            request = json.loads(reader.readline())
            if request.get("kind") == "status":
                peer.sendall(b'{"kind":"coord-status","v":1}\n')
            reader.close()
        except (OSError, ValueError):
            pass
listener.close()
pathlib.Path(path).unlink(missing_ok=True)
(root / "stopped").write_text("yes")
'''


@unittest.skipUnless(sys.platform == "linux", "Linux peer credentials and flock")
class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rcl-", dir="/tmp")
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin with spaces"
        self.bin.mkdir()
        self.cargo = self.make_program("cargo", CARGO)
        self.daemon = self.make_program("rabsd", DAEMON)
        self.wrap = self.make_program("rabs-wrap", "raise SystemExit(0)\n")
        self.endpoint = self.root / "edge.sock"
        self.env = dict(os.environ)
        for key in list(self.env):
            if key.startswith(("CARGO", "RUST", "RABS")):
                del self.env[key]
        self.env.update({
            "TEST_ROOT": str(self.root), "HOME": str(self.root / "home"),
            "CARGO": str(self.cargo), "CARGO_RABS_DAEMON": str(self.daemon),
            "CARGO_RABS_WRAP": str(self.wrap), "RABS_SOCKET_PATH": str(self.endpoint),
            "RABS_STATE_DIR": str(self.root / "state"),
        })
        self.peers = []

    def tearDown(self):
        # Stop only our fixture service through its test-only protocol. The
        # production launcher has no stop, unlink, kill-group or restart path.
        if (self.root / "starts").exists():
            until = time.monotonic() + 3
            while time.monotonic() < until:
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                        peer.settimeout(0.1)
                        peer.connect(str(self.endpoint))
                        peer.sendall(b'{"kind":"test-stop"}\n')
                    break
                except OSError:
                    if (self.root / "stopped").exists():
                        break
                    time.sleep(0.025)
            while self.endpoint.exists() and time.monotonic() < until:
                time.sleep(0.025)
        for peer in self.peers:
            peer.close()
        self.temp.cleanup()

    def make_program(self, name, text):
        path = self.bin / name
        path.write_text("#!{} -S\n{}".format(sys.executable, text))
        path.chmod(0o755)
        return path

    def launch(self, args=(), changes=None, pass_fds=()):
        env = dict(self.env)
        env.update(changes or {})
        return subprocess.run(
            [sys.executable, "-S", str(LAUNCHER), "rabs"] + list(args),
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.root, timeout=8, pass_fds=pass_fds,
        )

    def cargo_result(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return json.loads(result.stdout)

    def starts(self):
        path = self.root / "starts"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def listening_peer(self):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.endpoint))
        os.chmod(self.endpoint, 0o600)
        listener.listen(4)
        self.peers.append(listener)
        return listener

    def test_help_does_not_probe_or_run_cargo(self):
        result = self.launch(["--help"], {"CARGO": "/nonexistent/cargo"})
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"Usage: cargo rabs", result.stdout)
        self.assertEqual(self.starts(), [])

    def test_first_build_starts_opted_in_service_and_preserves_cargo_contract(self):
        args = ["build", "--release", "--features", "a,b", "--manifest-path", "a path/Cargo.toml"]
        changes = {"RUSTC": "/toolchain/bin/rustc", "RUSTUP_TOOLCHAIN": "nightly-test",
                   "RUSTC_WORKSPACE_WRAPPER": "/separate/workspace-wrapper",
                   "CARGO_MAKEFLAGS": "-j --jobserver-fds=3,4", "CARGO_TARGET_DIR": "custom target",
                   "RABS_BREAKER_FILE": "custom breaker", "RABS_CONFIG": "custom config"}
        value = self.cargo_result(self.launch(args, changes))
        self.assertEqual(value["argv"], [os.fsencode(x).hex() for x in args])
        for key, expected in changes.items():
            self.assertEqual(value["env"][key], expected)
        self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.wrap))
        self.assertEqual(value["cwd"], str(self.root))
        self.assertEqual(len(self.starts()), 1)
        self.assertEqual(self.starts()[0]["live"], "1")
        self.assertEqual(self.starts()[0]["pid"], self.starts()[0]["pgid"])
        folder = self.root / "state/cargo-launcher"
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
        for path in folder.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_reuses_daemon_without_reconfiguration_or_restart(self):
        first = self.cargo_result(self.launch())
        identity = self.endpoint.stat().st_ino
        second = self.cargo_result(self.launch(["--rabs-no-start", "check"]))
        self.assertEqual(first["env"]["RUSTC_WRAPPER"], second["env"]["RUSTC_WRAPPER"])
        self.assertEqual(self.endpoint.stat().st_ino, identity)
        self.assertEqual(len(self.starts()), 1)

    def test_parallel_cargo_callers_start_exactly_one_service(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: self.launch(["check"], {"TEST_START_DELAY": "0.2"}), range(12)))
        for result in results:
            value = self.cargo_result(result)
            self.assertEqual(value["env"].get("RUSTC_WRAPPER"), str(self.wrap), result.stderr)
        self.assertEqual(len(self.starts()), 1)

    def test_timeout_retains_daemon_lock_before_socket_exists(self):
        settings = {"TEST_START_DELAY": "1.0", "CARGO_RABS_STARTUP_MS": "150"}
        first = self.cargo_result(self.launch(["check"], settings))
        second = self.cargo_result(self.launch(["check"], settings))
        self.assertNotIn("RUSTC_WRAPPER", first["env"])
        self.assertNotIn("RUSTC_WRAPPER", second["env"])
        self.assertEqual(len(self.starts()), 1)
        deadline = time.monotonic() + 3
        while not self.endpoint.exists() and time.monotonic() < deadline:
            time.sleep(0.025)
        third = self.cargo_result(self.launch(["check"]))
        self.assertEqual(third["env"].get("RUSTC_WRAPPER"), str(self.wrap))
        self.assertEqual(len(self.starts()), 1)

    def assert_prebind_endpoint_is_shared(self, follower_endpoint):
        # Hold the actual fixture daemon BEFORE bind, beyond two launchers'
        # deadlines. A socket-only readiness check cannot serialize this.
        gate = self.root / "allow-bind"
        settings = {"TEST_START_GATE": str(gate), "CARGO_RABS_STARTUP_MS": "300"}
        try:
            first = self.cargo_result(self.launch(["check"], settings))
            self.assertNotIn("RUSTC_WRAPPER", first["env"])
            self.assertEqual(len(self.starts()), 1, "the first daemon must have started")
            self.assertFalse(self.endpoint.exists(), "the bind gate must still be closed")
            second = self.cargo_result(self.launch(["check"], dict(
                settings, RABS_STATE_DIR=str(self.root / "other-state"),
                RABS_SOCKET_PATH=str(follower_endpoint))))
            self.assertNotIn("RUSTC_WRAPPER", second["env"])
            self.assertEqual(len(self.starts()), 1,
                             "another state directory must not admit a competing daemon")
        finally:
            gate.write_text("bind now")
            deadline = time.monotonic() + 3
            while not self.endpoint.exists() and time.monotonic() < deadline:
                time.sleep(0.025)
        third = self.cargo_result(self.launch(["check"], {
            "RABS_STATE_DIR": str(self.root / "other-state"),
            "RABS_SOCKET_PATH": str(follower_endpoint)}))
        self.assertEqual(third["env"].get("RUSTC_WRAPPER"), str(self.wrap))
        self.assertEqual(len(self.starts()), 1)

    def test_prebind_lock_survives_timeout_across_distinct_state_directories(self):
        self.assert_prebind_endpoint_is_shared(self.endpoint)

    def test_prebind_lock_converges_across_socket_parent_aliases(self):
        alias = self.root / "parent-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assert_prebind_endpoint_is_shared(alias / self.endpoint.name)

    def test_parallel_distinct_state_callers_share_one_ready_endpoint(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda index: self.launch(["check"], {
                "TEST_START_DELAY": "0.5",
                "RABS_STATE_DIR": str(self.root / ("state-" + str(index))),
            }), range(12)))
        self.assertEqual(len(self.starts()), 1)
        for result in results:
            value = self.cargo_result(result)
            self.assertEqual(value["env"].get("RUSTC_WRAPPER"), str(self.wrap), result.stderr)

    def test_ready_daemon_attach_does_not_create_unused_state(self):
        self.cargo_result(self.launch())
        unused = self.root / "unused-state"
        before = self.endpoint.stat().st_ino
        value = self.cargo_result(self.launch(changes={"RABS_STATE_DIR": str(unused)}))
        self.assertEqual(value["env"].get("RUSTC_WRAPPER"), str(self.wrap))
        self.assertEqual(self.endpoint.stat().st_ino, before)
        self.assertFalse(unused.exists())
        self.assertEqual(len(self.starts()), 1)

    def test_daemon_keeps_both_locks_after_its_launcher_is_killed(self):
        gate = self.root / "allow-bind"
        env = dict(self.env, TEST_START_GATE=str(gate))
        child = subprocess.Popen(
            [sys.executable, "-S", str(LAUNCHER), "rabs", "check"], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 3
            while not self.starts() and time.monotonic() < deadline:
                time.sleep(0.025)
            self.assertEqual(len(self.starts()), 1)
            self.assertIsNone(child.poll())
            self.assertFalse(self.endpoint.exists())
            child.kill()  # This test's launcher, never the shared daemon.
            child.communicate(timeout=3)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            follower = self.cargo_result(self.launch(changes={
                "RABS_STATE_DIR": str(self.root / "other-state"),
                "CARGO_RABS_STARTUP_MS": "300",
                "TEST_START_GATE": str(gate),
            }))
            self.assertNotIn("RUSTC_WRAPPER", follower["env"])
            self.assertEqual(len(self.starts()), 1)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=3)
            gate.write_text("bind now")
            deadline = time.monotonic() + 3
            while not self.endpoint.exists() and time.monotonic() < deadline:
                time.sleep(0.025)
        self.assertEqual(self.cargo_result(self.launch())["env"]["RUSTC_WRAPPER"], str(self.wrap))
        self.assertEqual(len(self.starts()), 1)

    def test_state_store_cannot_start_under_a_second_endpoint(self):
        self.cargo_result(self.launch())
        other = self.root / "other.sock"
        result = self.launch(["--rabs-require-daemon"], {
            "RABS_SOCKET_PATH": str(other), "CARGO_RABS_STARTUP_MS": "300",
        })
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(len(self.starts()), 1)
        self.assertFalse(other.exists())
        self.assertTrue(rabs.probe(str(self.endpoint), time.monotonic() + 1))

    def test_independent_states_and_endpoints_do_not_block_each_other(self):
        self.cargo_result(self.launch())
        other = self.root / "other.sock"
        try:
            result = self.cargo_result(self.launch(["--rabs-require-daemon"], {
                "RABS_SOCKET_PATH": str(other), "RABS_STATE_DIR": str(self.root / "other-state"),
            }))
            self.assertEqual(result["env"].get("RUSTC_WRAPPER"), str(self.wrap))
            self.assertEqual(len(self.starts()), 2)
            self.assertTrue(rabs.probe(str(self.endpoint), time.monotonic() + 1))
            self.assertTrue(rabs.probe(str(other), time.monotonic() + 1))
        finally:
            if other.exists():
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.settimeout(1)
                    peer.connect(str(other))
                    peer.sendall(b'{"kind":"test-stop"}\n')
                deadline = time.monotonic() + 3
                while other.exists() and time.monotonic() < deadline:
                    time.sleep(0.025)
                self.assertFalse(other.exists())

    def test_unsafe_endpoint_lock_entries_refuse_before_daemon_start(self):
        for fault in ["symlink", "hardlink", "public", "directory", "fifo"]:
            with self.subTest(fault=fault):
                endpoint = self.root / (fault + ".sock")
                path = self.root / (".rabs-" + endpoint.name + ".startup.lock")
                retained = self.root / ("retained-" + fault)
                retained.write_bytes(b"untouched")
                retained.chmod(0o600)
                if fault == "symlink":
                    path.symlink_to(retained)
                elif fault == "hardlink":
                    os.link(retained, path)
                elif fault == "public":
                    path.write_bytes(b"do not truncate")
                    path.chmod(0o666)
                elif fault == "directory":
                    path.mkdir(mode=0o700)
                else:
                    os.mkfifo(path, 0o600)
                before = path.lstat()
                result = self.launch(["--rabs-require-daemon"], {
                    "RABS_SOCKET_PATH": str(endpoint),
                })
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                after = path.lstat()
                self.assertEqual((before.st_dev, before.st_ino, before.st_mode, before.st_nlink),
                                 (after.st_dev, after.st_ino, after.st_mode, after.st_nlink))
                self.assertEqual(retained.read_bytes(), b"untouched")
                if fault == "public":
                    self.assertEqual(path.read_bytes(), b"do not truncate")
                self.assertEqual(self.starts(), [])

    def test_writable_socket_parent_is_not_silently_repaired(self):
        parent = self.root / "shared"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        result = self.launch(["--rabs-require-daemon"], {
            "RABS_SOCKET_PATH": str(parent / "edge.sock"),
        })
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o777)
        self.assertEqual(list(parent.iterdir()), [])
        self.assertEqual(self.starts(), [])

    def test_replaced_lock_inodes_cannot_authorize_startup_or_handoff(self):
        for name in ["state", "endpoint"]:
            for after_acquire in [False, True]:
                with self.subTest(name=name, after_acquire=after_acquire):
                    suffix = name + str(after_acquire)
                    state = self.root / ("state-" + suffix)
                    endpoint = self.root / (suffix + ".sock")
                    with rabs.StartupLock(str(state), str(endpoint), time.monotonic() + 2) as lock:
                        if after_acquire:
                            self.assertTrue(lock.acquire(str(endpoint)))
                        path = (state / "cargo-launcher/startup.lock" if name == "state" else
                                self.root / (".rabs-" + endpoint.name + ".startup.lock"))
                        path.rename(self.root / ("retained-lock-" + suffix))
                        path.write_bytes(b"replacement")
                        path.chmod(0o600)
                        with self.assertRaises(rabs.SetupError):
                            if after_acquire:
                                lock.inherited_fds()
                            else:
                                lock.acquire(str(endpoint))
                        self.assertEqual(path.read_bytes(), b"replacement")

    def test_retargeted_socket_parent_is_not_the_opened_endpoint_namespace(self):
        parent = self.root / "socket-parent"
        parent.mkdir(mode=0o700)
        state = self.root / "state"
        endpoint = parent / "edge.sock"
        with rabs.StartupLock(str(state), str(endpoint), time.monotonic() + 2) as lock:
            parent.rename(self.root / "retained-parent")
            parent.mkdir(mode=0o700)
            with self.assertRaises(rabs.SetupError):
                lock.acquire(str(endpoint))
            self.assertEqual(list(parent.iterdir()), [])

    def test_failed_endpoint_open_releases_all_setup_descriptors(self):
        target = self.root / "retained-lock"
        target.write_bytes(b"keep")
        (self.root / (".rabs-" + self.endpoint.name + ".startup.lock")).symlink_to(target)
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(5):
            with self.assertRaises(OSError):
                rabs.StartupLock(str(self.root / "state"), str(self.endpoint), time.monotonic() + 1)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        self.assertEqual(target.read_bytes(), b"keep")

    def test_missing_accelerator_runs_original_cargo_and_environment(self):
        value = self.cargo_result(self.launch(["test", "--", "--nocapture"], {"CARGO_RABS_WRAP": "/absent"}))
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertEqual(self.starts(), [])

    def test_explicit_wrapper_or_disable_is_never_overwritten(self):
        for name in ["RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER"]:
            for value in ["sccache", ""]:
                with self.subTest(name=name, value=value):
                    output = self.cargo_result(self.launch(changes={name: value}))
                    self.assertEqual(output["env"][name], value)
                    self.assertEqual(self.starts(), [])

    def test_same_wrapper_is_not_mistaken_for_a_conflict(self):
        link = self.bin / "wrapper-alias"
        link.symlink_to(self.wrap)
        value = self.cargo_result(self.launch(changes={"RUSTC_WRAPPER": str(link)}))
        self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.wrap))
        self.assertEqual(len(self.starts()), 1)

    def test_require_daemon_refuses_without_running_cargo(self):
        result = self.launch(["--rabs-no-start", "--rabs-require-daemon", "build"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(self.starts(), [])

    def test_no_start_fail_open_never_starts_service(self):
        value = self.cargo_result(self.launch(["--rabs-no-start", "build"]))
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertEqual(self.starts(), [])

    def test_regular_file_and_stale_socket_are_not_deleted_or_replaced(self):
        self.endpoint.write_text("not a socket")
        value = self.cargo_result(self.launch())
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertEqual(self.endpoint.read_text(), "not a socket")
        self.endpoint.unlink()  # Test-owned fixture, never production recovery.
        listener = self.listening_peer()
        identity = self.endpoint.stat().st_ino
        listener.close()
        value = self.cargo_result(self.launch())
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertEqual(self.endpoint.stat().st_ino, identity)
        self.assertEqual(self.starts(), [])

    def test_socket_permissions_and_symlinks_refuse_without_mutation(self):
        listener = self.listening_peer()
        os.chmod(self.endpoint, 0o666)
        value = self.cargo_result(self.launch())
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertEqual(stat.S_IMODE(self.endpoint.stat().st_mode), 0o666)
        listener.close()
        self.endpoint.unlink()
        target = self.root / "elsewhere"
        target.write_text("retained")
        self.endpoint.symlink_to(target)
        value = self.cargo_result(self.launch())
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertTrue(self.endpoint.is_symlink())
        self.assertEqual(target.read_text(), "retained")

    def test_bad_or_unavailable_configuration_never_starts_service(self):
        for mode in ["invalid", "refuse", "old", "oversize", "hang"]:
            with self.subTest(mode=mode):
                before = time.monotonic()
                result = self.launch(["--rabs-require-daemon"], {
                    "TEST_CONFIG": mode, "CARGO_RABS_STARTUP_MS": "250"})
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertLess(time.monotonic() - before, 2)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(self.starts(), [])

    def test_failed_daemon_start_preserves_cargo_status(self):
        result = self.launch(changes={"TEST_START_FAIL": "1", "TEST_CARGO_STATUS": "37"})
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn(b"rabsd exited during startup", result.stderr)
        self.assertNotIn("RUSTC_WRAPPER", json.loads(result.stdout)["env"])

    def test_cargo_exit_signal_and_pid_are_preserved(self):
        result = self.launch(changes={"CARGO_RABS_WRAP": "/absent", "TEST_CARGO_SIGNAL": str(signal.SIGTERM)})
        self.assertEqual(result.returncode, -signal.SIGTERM)
        env = dict(self.env, CARGO_RABS_WRAP="/absent")
        child = subprocess.Popen([sys.executable, "-S", str(LAUNCHER), "rabs", "check"], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, err)
        self.assertEqual(json.loads(out)["pid"], child.pid)

    def test_opaque_argv_and_inherited_jobserver_descriptor_survive_exec(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"+")
            result = self.launch(["rustc", "--", os.fsdecode(b"arg-\xff")],
                                 {"TEST_JOBSERVER_FD": str(read_fd)}, pass_fds=(read_fd,))
            value = self.cargo_result(result)
            self.assertEqual(value["argv"][-1], b"arg-\xff".hex())
            self.assertEqual(value["jobserver"], b"+".hex())
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_startup_lock_symlink_and_permissions_are_not_repaired(self):
        state = self.root / "state"
        state.mkdir()
        folder = state / "cargo-launcher"
        folder.mkdir(mode=0o700)
        target = self.root / "retained"
        target.write_text("keep")
        (folder / "startup.lock").symlink_to(target)
        value = self.cargo_result(self.launch())
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertEqual(target.read_text(), "keep")
        self.assertEqual(self.starts(), [])

    def test_unresponsive_existing_peer_is_bounded_and_never_replaced(self):
        self.listening_peer()
        identity = self.endpoint.stat().st_ino
        before = time.monotonic()
        value = self.cargo_result(self.launch(changes={"CARGO_RABS_STARTUP_MS": "200"}))
        self.assertLess(time.monotonic() - before, 2)
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertEqual(self.endpoint.stat().st_ino, identity)
        self.assertEqual(self.starts(), [])

    def test_cargo_self_recursion_is_refused(self):
        result = self.launch(changes={"CARGO": str(LAUNCHER)})
        self.assertEqual(result.returncode, 127)
        self.assertEqual(self.starts(), [])


class ProtocolTests(unittest.TestCase):
    def test_argument_boundary_does_not_consume_cargo_options(self):
        self.assertEqual(rabs.arguments(["rabs"]), (["build"], False, False))
        self.assertEqual(rabs.arguments(["rabs", "--rabs-no-start", "check", "--rabs-require-daemon"]),
                         (["check", "--rabs-require-daemon"], True, False))
        self.assertEqual(rabs.arguments(["--", "--help"]), (["--help"], False, False))
        self.assertEqual(rabs.arguments(["+nightly", "build"]), (["+nightly", "build"], False, False))

    def test_json_object_must_be_complete_unambiguous_and_utf8(self):
        for data in [b'[]', b'null', b'{"kind":"x","kind":"y"}', b'{"a":{"x":1,"x":2}}',
                     b'{} {}', b'{"a":"\xff"}', b'{']:
            with self.subTest(data=data), self.assertRaises(rabs.SetupError):
                rabs.decode_object(data)

    def test_frame_bound_partial_io_and_buffered_deadline(self):
        for data in [b'x' * rabs.MAX_FRAME, b'{}', b'{"kind":"x"}\n']:
            left, right = socket.socketpair()
            try:
                right.sendall(data)
                right.shutdown(socket.SHUT_WR)
                frames = rabs.Frames(left, time.monotonic() + 1)
                if data.endswith(b'\n'):
                    self.assertEqual(frames.receive(), {"kind": "x"})
                else:
                    with self.assertRaises(rabs.SetupError):
                        frames.receive()
            finally:
                left.close()
                right.close()
        left, right = socket.socketpair()
        try:
            frames = rabs.Frames(left, time.monotonic() - 1)
            frames.buffer.extend(b'{}\n')
            with self.assertRaises(rabs.SetupError):
                frames.receive()
        finally:
            left.close()
            right.close()

    def test_fragmented_hello_and_status_share_one_absolute_budget(self):
        left, right = socket.socketpair()
        def send():
            with right:
                for data in [b'{"kind":', b'"hello-ok"}\n', b'{"kind":"coord-status"}\n']:
                    right.sendall(data)
                    time.sleep(0.01)
        thread = threading.Thread(target=send)
        thread.start()
        try:
            frames = rabs.Frames(left, time.monotonic() + 1)
            self.assertEqual(frames.receive(), {"kind": "hello-ok"})
            self.assertEqual(frames.receive(), {"kind": "coord-status"})
        finally:
            left.close()
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
