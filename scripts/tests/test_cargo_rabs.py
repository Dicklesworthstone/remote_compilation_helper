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
from unittest import mock

LAUNCHER = Path(__file__).resolve().parents[1] / "cargo-rabs"
WORKER_ADAPTER = LAUNCHER.parent.parent / "rch-common/src/toolchain/worker_cache.py"
loader = importlib.machinery.SourceFileLoader("cargo_rabs", str(LAUNCHER))
spec = importlib.util.spec_from_loader(loader.name, loader)
rabs = importlib.util.module_from_spec(spec)
loader.exec_module(rabs)

CARGO = r'''
import json, os, signal, sys
keys = ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTUP_TOOLCHAIN",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_MAKEFLAGS", "RABS_SOCKET_PATH",
        "RABS_STATE_DIR", "RABS_CONFIG", "RABS_BREAKER_FILE", "CARGO_TARGET_DIR",
        "RABS_REUSE_CARGO_LAYOUT"]
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

RCH = r'''
import json, os, pathlib, signal, sys
keys = ["RCH_REQUIRE_REMOTE", "RCH_RABS_WORKER_CACHE", "CARGO_RABS_REMOTE_ACTIVE",
        "RCH_WORKER", "RCH_WORKERS", "RCH_CONFIG", "RUSTUP_TOOLCHAIN", "RUSTC",
        "RUSTC_WRAPPER", "CARGO", "CARGO_TARGET_DIR", "CARGO_MAKEFLAGS"]
value = {"argv": sys.argv[1:], "pid": os.getpid(), "cwd": os.getcwd(),
         "rabs_state_present": os.path.exists(os.environ["RABS_STATE_DIR"]),
         "env": {key: os.environ[key] for key in keys if key in os.environ}}
with open(pathlib.Path(os.environ["TEST_ROOT"]) / "rch-starts", "a") as stream:
    stream.write(json.dumps(value) + "\n")
if os.environ.get("TEST_RCH_WORKER_ADAPTER"):
    # Explicit RCH/transport double; the worker Python adapter below is real.
    assert sys.argv[1:5] == ["exec", "--source-content-receipt", "--", "cargo"]
    assert os.environ["RCH_REQUIRE_REMOTE"] == "1"
    assert os.environ["RCH_RABS_WORKER_CACHE"] == "1"
    os.execv(sys.executable, [sys.executable, "-S", os.environ["TEST_RCH_WORKER_ADAPTER"]]
             + sys.argv[4:])
if os.environ.get("TEST_RCH_STDIN"):
    value["stdin"] = sys.stdin.buffer.read().hex()
if "TEST_JOBSERVER_FD" in os.environ:
    value["jobserver"] = os.read(int(os.environ["TEST_JOBSERVER_FD"]), 1).hex()
if os.environ.get("TEST_RCH_RECURSE"):
    os.execv(sys.executable, [sys.executable, "-S", os.environ["TEST_RCH_RECURSE"],
                            "rabs", "--rabs-remote", "build"])
print(json.dumps(value), flush=True)
print("rch-owned stderr", file=sys.stderr, flush=True)
if os.environ.get("TEST_RCH_SIGNAL"):
    os.kill(os.getpid(), int(os.environ["TEST_RCH_SIGNAL"]))
sys.exit(int(os.environ.get("TEST_RCH_STATUS", "0")))
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
                        "live": os.environ.get("RABS_LIVE_DEPENDENCY"),
                        "layout": os.environ.get("RABS_REUSE_CARGO_LAYOUT")}) + "\n")
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
if pathlib.Path(path).exists():
    # Model rabsd's existing stale-socket takeover, only in this fixture.
    # The production launcher must leave the endpoint for the daemon to own.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        try:
            probe.connect(path)
        except ConnectionRefusedError:
            pathlib.Path(path).unlink()
        else:
            sys.exit(33)
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
                status = {"kind": "coord-status", "v": 1,
                          "live_dependency": os.environ.get("RABS_LIVE_DEPENDENCY") == "1"}
                status["remote_dependency"] = None
                worker_keys = ("RABS_DEPENDENCY_WORKER_LISTEN", "RABS_DEPENDENCY_WORKER_ID",
                               "RABS_DEPENDENCY_WORKER_SPKI_SHA256")
                if all(name in os.environ for name in worker_keys):
                    status["remote_dependency"] = {
        "remote_protocol": 1, "dependency_context": "dependency-exec-v5",
                        "listen": os.environ[worker_keys[0]],
                        "worker_id": os.environ[worker_keys[1]],
                        "worker_spki_sha256": os.environ[worker_keys[2]],
                    }
                if "TEST_STATUS_REMOTE_JSON" in os.environ:
                    status["remote_dependency"] = json.loads(os.environ["TEST_STATUS_REMOTE_JSON"])
                if os.environ.get("TEST_STATUS_LEGACY"):
                    status.pop("live_dependency")
                peer.sendall(json.dumps(status).encode() + b'\n')
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
        self.env.pop("RCH_RABS_WORKER_ACTIVE", None)
        self.env.update({
            "TEST_ROOT": str(self.root), "HOME": str(self.root / "home"),
            "CARGO": str(self.cargo), "CARGO_RABS_DAEMON": str(self.daemon),
            "CARGO_RABS_WRAP": str(self.wrap), "RABS_SOCKET_PATH": str(self.endpoint),
            "RABS_STATE_DIR": str(self.root / "state"),
        })
        self.peers = []

    def tearDown(self):
        # Stop only our fixture service through its test-only protocol. The
        # production launcher never stops or unlinks an existing daemon.
        if (self.root / "starts").exists() and any(
                not rabs.process_exited(item["pid"]) for item in self.starts()):
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
        self.assertEqual(self.starts()[0]["layout"], "1")
        self.assertNotIn("RABS_REUSE_CARGO_LAYOUT", value["env"])
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

    def test_explicit_layout_policy_is_preserved_for_daemon_and_cargo(self):
        value = self.cargo_result(self.launch(changes={"RABS_REUSE_CARGO_LAYOUT": "0"}))
        self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.wrap))
        self.assertEqual(value["env"]["RABS_REUSE_CARGO_LAYOUT"], "0")
        self.assertEqual(self.starts()[0]["layout"], "0")

    def test_layout_default_does_not_reconfigure_an_attached_daemon(self):
        self.cargo_result(self.launch(changes={"RABS_REUSE_CARGO_LAYOUT": "0"}))
        identity = rabs.socket_identity(self.endpoint)
        for options in (["check"], ["--rabs-no-start", "check"]):
            value = self.cargo_result(self.launch(options))
            self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.wrap))
            self.assertNotIn("RABS_REUSE_CARGO_LAYOUT", value["env"])
            self.assertEqual(rabs.socket_identity(self.endpoint), identity)
        self.assertEqual(len(self.starts()), 1)
        self.assertEqual(self.starts()[0]["layout"], "0")

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

    def test_existing_shadow_daemon_does_not_claim_live_cache_readiness(self):
        child = subprocess.Popen([str(self.daemon)],
                                 env=dict(self.env, RABS_LIVE_DEPENDENCY="0"))
        try:
            deadline = time.monotonic() + 3
            while not self.endpoint.exists():
                self.assertIsNone(child.poll(), "fixture daemon exited before binding")
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            identity = rabs.socket_identity(str(self.endpoint))
            result = self.launch(["check"])
            value = self.cargo_result(result)
            self.assertNotIn("RUSTC_WRAPPER", value["env"])
            self.assertIn(b"does not enable live dependency serving", result.stderr)
            self.assertIn(b"running stock Cargo", result.stderr)

            required = self.launch(["--rabs-require-daemon", "check"])
            self.assertEqual(required.returncode, 2, required.stderr)
            self.assertEqual(required.stdout, b"", "required setup must not run Cargo")
            self.assertIn(b"RABS_LIVE_DEPENDENCY=1", required.stderr)
            self.assertEqual(rabs.socket_identity(str(self.endpoint)), identity)
            self.assertEqual([item["pid"] for item in self.starts()], [child.pid])
            self.assertIsNone(child.poll(), "launcher stopped a shared shadow daemon")
        finally:
            child.terminate()
            child.wait(timeout=3)

    def test_existing_legacy_daemon_cannot_satisfy_required_live_setup(self):
        child = subprocess.Popen([str(self.daemon)],
                                 env=dict(self.env, RABS_LIVE_DEPENDENCY="1", TEST_STATUS_LEGACY="1"))
        try:
            deadline = time.monotonic() + 3
            while not self.endpoint.exists():
                self.assertIsNone(child.poll(), "fixture daemon exited before binding")
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            result = self.launch(["--rabs-require-daemon", "build"])
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"does not enable live dependency serving", result.stderr)
            self.assertEqual([item["pid"] for item in self.starts()], [child.pid])
            self.assertIsNone(child.poll())
        finally:
            child.terminate()
            child.wait(timeout=3)

    def dependency_worker_settings(self, **changes):
        settings = {
            "RABS_DEPENDENCY_WORKER_LISTEN": "127.0.0.1:9443",
            "RABS_DEPENDENCY_WORKER_ID": "compile-worker",
            "RABS_DEPENDENCY_WORKER_SPKI_SHA256": "ab" * 32,
        }
        settings.update(changes)
        return settings

    def test_requested_dependency_worker_is_verified_on_start_and_reuse(self):
        settings = self.dependency_worker_settings()
        first = self.cargo_result(self.launch(["--rabs-require-daemon", "check"], settings))
        identity = rabs.socket_identity(str(self.endpoint))
        for changes in [settings, {}]:
            value = self.cargo_result(self.launch(["--rabs-no-start", "--rabs-require-daemon", "check"], changes))
            self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.wrap))
        self.assertEqual(first["env"]["RUSTC_WRAPPER"], str(self.wrap))
        self.assertEqual(rabs.socket_identity(str(self.endpoint)), identity)
        self.assertEqual(len(self.starts()), 1)

    def test_local_daemon_cannot_silently_satisfy_explicit_dependency_worker(self):
        self.cargo_result(self.launch())
        identity = rabs.socket_identity(str(self.endpoint))
        settings = self.dependency_worker_settings()
        fallback = self.launch(["check"], settings)
        self.assertNotIn("RUSTC_WRAPPER", self.cargo_result(fallback)["env"])
        self.assertIn(b"dependency worker configuration", fallback.stderr)
        self.assertIn(b"running stock Cargo", fallback.stderr)
        required = self.launch(["--rabs-require-daemon", "check"], settings)
        self.assertEqual(required.returncode, 2, required.stderr)
        self.assertEqual(required.stdout, b"")
        self.assertIn(b"RABS_STATE_DIR and RABS_SOCKET_PATH", required.stderr)
        self.assertEqual(rabs.socket_identity(str(self.endpoint)), identity)
        self.assertEqual(len(self.starts()), 1)

    def test_each_attached_worker_identity_field_must_match_without_restart(self):
        settings = self.dependency_worker_settings()
        self.cargo_result(self.launch(changes=settings))
        identity = rabs.socket_identity(str(self.endpoint))
        for name, replacement in [
            ("RABS_DEPENDENCY_WORKER_LISTEN", "127.0.0.1:9444"),
            ("RABS_DEPENDENCY_WORKER_ID", "another-worker"),
            ("RABS_DEPENDENCY_WORKER_SPKI_SHA256", "cd" * 32),
        ]:
            with self.subTest(name=name):
                changed = dict(settings, **{name: replacement})
                result = self.launch(["--rabs-no-start", "--rabs-require-daemon", "check"], changed)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"dependency worker configuration", result.stderr)
        self.assertEqual(rabs.socket_identity(str(self.endpoint)), identity)
        self.assertEqual(len(self.starts()), 1)

    def test_new_daemon_with_old_dependency_context_reports_the_actual_mismatch(self):
        settings = self.dependency_worker_settings()
        old = {
            "remote_protocol": 1, "dependency_context": "dependency-exec-v2",
            "listen": settings["RABS_DEPENDENCY_WORKER_LISTEN"],
            "worker_id": settings["RABS_DEPENDENCY_WORKER_ID"],
            "worker_spki_sha256": settings["RABS_DEPENDENCY_WORKER_SPKI_SHA256"],
        }
        result = self.launch(["--rabs-require-daemon", "check"], dict(
            settings, TEST_STATUS_REMOTE_JSON=json.dumps(old)))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"dependency_context", result.stderr)
        self.assertNotIn(b"startup was not confirmed", result.stderr)
        self.assertEqual(len(self.starts()), 1)
        self.assertFalse(rabs.process_exited(self.starts()[0]["pid"]),
                         "an incompatible shared daemon remains owned and running")

    def test_prebind_lifetime_lock_handoff_rechecks_selected_dependency_worker(self):
        gate = self.root / "allow-remote-bind"
        entered = threading.Event()
        original_acquire = rabs.StartupLock.acquire

        def acquire(lock, endpoint):
            entered.set()
            return original_acquire(lock, endpoint)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.launch, ["check"], {"TEST_START_GATE": str(gate)})
            try:
                deadline = time.monotonic() + 3
                while not self.starts():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                self.assertFalse(self.endpoint.exists())
                selected = dict(self.env, **self.dependency_worker_settings())
                with mock.patch.object(rabs.StartupLock, "acquire", acquire):
                    follower = pool.submit(rabs.prepare, selected, False)
                    self.assertTrue(entered.wait(timeout=3), "follower must reach the held lifetime lock")
                    self.assertFalse(self.endpoint.exists())
                    gate.write_text("bind now")
                    with self.assertRaisesRegex(rabs.RemoteConfigurationMismatch, "dependency worker"):
                        follower.result(timeout=5)
                self.assertEqual(self.cargo_result(first.result(timeout=5))["env"]["RUSTC_WRAPPER"],
                                 str(self.wrap))
                self.assertEqual(len(self.starts()), 1)
            finally:
                gate.write_text("release fixture")
                first.result(timeout=5)

    def test_partial_dependency_worker_request_does_not_start_a_daemon(self):
        for name, value in self.dependency_worker_settings().items():
            with self.subTest(name=name):
                result = self.launch(["--rabs-require-daemon", "check"], {name: value})
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"all dependency worker settings are required", result.stderr)
        self.assertEqual(self.starts(), [])

    def test_cargo_self_recursion_is_refused(self):
        result = self.launch(changes={"CARGO": str(LAUNCHER)})
        self.assertEqual(result.returncode, 127)
        self.assertEqual(self.starts(), [])

    def remote_setup(self, **overrides):
        rch = self.make_program("rch", RCH)
        return dict(CARGO_RABS_RCH=str(rch), CARGO_RABS_REMOTE_ACTIVE="0",
                    RCH_RABS_WORKER_ACTIVE="0", **overrides)

    def rch_starts(self):
        path = self.root / "rch-starts"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_no_local_setup(self):
        self.assertEqual(self.starts(), [])
        self.assertFalse(self.endpoint.exists())
        self.assertFalse((self.root / "state").exists())

    def test_remote_dispatch_needs_no_dispatcher_cargo_or_rabs_installation(self):
        changes = self.remote_setup(CARGO="/absent/cargo", CARGO_RABS_DAEMON="/absent/rabsd",
                                    CARGO_RABS_WRAP="/absent/wrap")
        result = self.launch(["--rabs-remote"], changes)
        value = self.cargo_result(result)
        self.assertEqual(value["argv"], ["exec", "--source-content-receipt", "--", "cargo", "build"])
        for key in ("RCH_REQUIRE_REMOTE", "RCH_RABS_WORKER_CACHE", "CARGO_RABS_REMOTE_ACTIVE"):
            self.assertEqual(value["env"][key], "1")
        self.assertEqual(value["cwd"], str(self.root))
        self.assertEqual(len(self.rch_starts()), 1)
        self.assertEqual(result.stderr, b"rch-owned stderr\n")
        self.assert_no_local_setup()

    def test_remote_preserves_toolchain_routing_and_literal_arguments(self):
        args = ["+nightly-2026-08-31", "test", "--manifest-path", "a path/Cargo.toml",
                "--config", 'build.rustflags=["-C", "opt-level=1"]', "--", "",
                "'\"\\$HOME", "x;touch should-not-exist", "$(touch should-not-exist)",
                "*", "line\nbreak", "λ雪", "--rabs-no-start"]
        settings = dict(RUSTUP_TOOLCHAIN="nightly-test", RCH_WORKER="worker-a",
                        RCH_CONFIG="custom rch.toml", CARGO_TARGET_DIR="private target",
                        RUSTC_WRAPPER="/custom/wrapper", CARGO="/dispatcher/only/cargo",
                        RCH_REQUIRE_REMOTE="0", RCH_RABS_WORKER_CACHE="0")
        value = self.cargo_result(self.launch(["--rabs-remote"] + args,
                                            self.remote_setup(**settings)))
        self.assertEqual(value["argv"], ["exec", "--source-content-receipt", "--", "cargo"] + args)
        for key, expected in settings.items():
            if key not in ("RCH_REQUIRE_REMOTE", "RCH_RABS_WORKER_CACHE"):
                self.assertEqual(value["env"][key], expected)
        self.assertFalse((self.root / "should-not-exist").exists())
        self.assert_no_local_setup()

    def test_remote_switch_does_not_cross_the_cargo_argument_boundary(self):
        for args in (["check", "--rabs-remote"], ["--", "--rabs-remote"]):
            with self.subTest(args=args):
                value = self.cargo_result(self.launch(args, self.remote_setup()))
                expected = list(args[1:] if args[0] == "--" else args)
                self.assertEqual(value["argv"], [os.fsencode(arg).hex() for arg in expected])
                self.assertEqual(self.rch_starts(), [])
        self.assertEqual(len(self.starts()), 1)

    def test_remote_local_daemon_options_refuse_before_starting_anything(self):
        for local in ("--rabs-no-start", "--rabs-require-daemon"):
            for args in (["--rabs-remote", local], [local, "--rabs-remote"]):
                with self.subTest(args=args):
                    result = self.launch(args, self.remote_setup())
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, b"")
                    self.assertIn(b"cannot combine", result.stderr)
                    self.assertEqual(self.rch_starts(), [])
                    self.assert_no_local_setup()

    def test_remote_missing_and_recursive_executables_never_fall_back_locally(self):
        alias = self.bin / "rch-alias"
        alias.symlink_to(LAUNCHER)
        for path in ("/absent/rch", str(LAUNCHER), str(alias), str(self.bin)):
            with self.subTest(path=path):
                result = self.launch(["--rabs-remote"], {"CARGO_RABS_RCH": path})
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(self.rch_starts(), [])
                self.assert_no_local_setup()

    def test_remote_exec_failure_has_no_local_fallback(self):
        broken = self.bin / "broken-rch"
        broken.write_bytes(b"#! /missing/interpreter\n")
        broken.chmod(0o755)
        result = self.launch(["--rabs-remote"], {"CARGO_RABS_RCH": str(broken)})
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertIn(b"cannot execute RCH", result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assert_no_local_setup()

    def test_remote_statuses_never_trigger_a_launcher_retry(self):
        changes = self.remote_setup()
        for count, status in enumerate((0, 1, 2, 101, 102, 103, 125, 137, 255), 1):
            with self.subTest(status=status):
                result = self.launch(["--rabs-remote", "check"],
                                     dict(changes, TEST_RCH_STATUS=str(status)))
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(len(self.rch_starts()), count)
                self.assertEqual(json.loads(result.stdout)["argv"][-1], "check")
                self.assertEqual(result.stderr, b"rch-owned stderr\n")
                self.assert_no_local_setup()

    def test_remote_exec_preserves_pid_streams_cwd_and_jobserver_descriptor(self):
        read_fd, write_fd = os.pipe()
        child = None
        try:
            os.write(write_fd, b"+")
            env = dict(self.env, **self.remote_setup())
            env.update(TEST_RCH_STDIN="1", TEST_JOBSERVER_FD=str(read_fd),
                       CARGO_MAKEFLAGS="-j --jobserver-auth={},{}".format(read_fd, write_fd))
            child = subprocess.Popen(
                [sys.executable, "-S", str(LAUNCHER), "rabs", "--rabs-remote", "build"],
                env=env, cwd=self.root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, pass_fds=(read_fd, write_fd),
            )
            payload = b"original stdin\0\xff\n"
            out, err = child.communicate(payload, timeout=5)
            self.assertEqual(child.returncode, 0, err)
            value = json.loads(out)
            self.assertEqual(value["pid"], child.pid)
            self.assertEqual(value["cwd"], str(self.root))
            self.assertEqual(value["stdin"], payload.hex())
            self.assertEqual(value["jobserver"], b"+".hex())
            self.assertEqual(value["env"]["CARGO_MAKEFLAGS"], env["CARGO_MAKEFLAGS"])
            self.assertEqual(err, b"rch-owned stderr\n")
            self.assert_no_local_setup()
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate(timeout=3)
            os.close(read_fd)
            os.close(write_fd)

    def test_remote_signal_is_preserved_without_compiler_reexecution(self):
        result = self.launch(["--rabs-remote"],
                             self.remote_setup(TEST_RCH_SIGNAL=str(signal.SIGTERM)))
        self.assertEqual(result.returncode, -signal.SIGTERM, result.stderr)
        self.assertEqual(len(self.rch_starts()), 1)
        self.assert_no_local_setup()

    def test_remote_recursive_process_tree_refuses_second_dispatch(self):
        result = self.launch(["--rabs-remote"],
                             self.remote_setup(TEST_RCH_RECURSE=str(LAUNCHER)))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"nested remote dispatch", result.stderr)
        self.assertEqual(len(self.rch_starts()), 1)
        self.assertEqual(result.stdout, b"")
        self.assert_no_local_setup()

    def test_remote_worker_context_cannot_create_a_second_hop(self):
        for name in ("CARGO_RABS_REMOTE_ACTIVE", "RCH_RABS_WORKER_ACTIVE"):
            with self.subTest(name=name):
                changes = self.remote_setup()
                changes[name] = "1"
                result = self.launch(["--rabs-remote"], changes)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(b"nested remote dispatch", result.stderr)
                self.assertEqual(self.rch_starts(), [])
                self.assert_no_local_setup()

    def test_remote_non_utf8_argument_is_refused_not_replaced_or_compiled_locally(self):
        result = self.launch(["--rabs-remote", "rustc", "--", os.fsdecode(b"arg-\xff")],
                             self.remote_setup())
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"must be UTF-8", result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(self.rch_starts(), [])
        self.assert_no_local_setup()

    def test_remote_help_does_not_resolve_executables(self):
        result = self.launch(["--rabs-remote", "--help"],
                             {"CARGO": "/absent/cargo", "CARGO_RABS_RCH": "/absent/rch"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"--rabs-remote", result.stdout)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(self.rch_starts(), [])
        self.assert_no_local_setup()

    def test_remote_path_search_works_without_local_cargo(self):
        self.make_program("rch", RCH)
        value = self.cargo_result(self.launch(["--rabs-remote", "check"],
                                            {"PATH": str(self.bin), "CARGO": ""}))
        self.assertEqual(value["argv"][-2:], ["cargo", "check"])
        self.assert_no_local_setup()

    def test_remote_environment_copy_platform_and_nul_refusals(self):
        env = dict(self.env, **self.remote_setup())
        saved = dict(env)
        _, argv, selected = rabs.remote_invocation(["build"], env)
        self.assertEqual(env, saved)
        self.assertIsNot(env, selected)
        self.assertEqual(selected["RCH_REQUIRE_REMOTE"], "1")
        self.assertEqual(argv[-2:], ["cargo", "build"])
        with self.assertRaises(rabs.SetupError):
            rabs.remote_invocation(["build", "bad\0argument"], env)
        for platform in ("win32", "freebsd", "unknown"):
            with self.subTest(platform=platform), mock.patch.object(rabs.sys, "platform", platform):
                with self.assertRaises(rabs.SetupError):
                    rabs.remote_invocation(["build"], env)
        # This tests branch selection only, not native macOS execution.
        with mock.patch.object(rabs.sys, "platform", "darwin"):
            self.assertEqual(rabs.remote_invocation(["check"], env)[1][-1], "check")
        self.assertEqual(self.rch_starts(), [])
        self.assert_no_local_setup()

    def worker_route_setup(self, **overrides):
        (self.bin / "cargo-rabs").symlink_to(LAUNCHER)
        return self.remote_setup(TEST_RCH_WORKER_ADAPTER=str(WORKER_ADAPTER),
                                 PATH=str(self.bin) + os.pathsep + os.defpath, **overrides)

    def test_remote_worker_adapter_imports_updated_launcher_and_prepares_once(self):
        changes = self.worker_route_setup()
        for count in (1, 2):
            value = self.cargo_result(self.launch(["--rabs-remote", "check"], changes))
            self.assertEqual(value["argv"], [b"check".hex()])
            self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.wrap))
            self.assertEqual(len(self.starts()), 1)
            self.assertEqual(len(self.rch_starts()), count)
            self.assertEqual(value["pid"], self.rch_starts()[-1]["pid"])
        self.assertFalse(self.rch_starts()[0]["rabs_state_present"])
        self.assertTrue(self.rch_starts()[1]["rabs_state_present"])
        self.assertFalse(rabs.process_exited(self.starts()[0]["pid"]))

    def test_remote_worker_cache_failure_execs_cargo_once_without_local_setup(self):
        changes = self.worker_route_setup(CARGO_RABS_WRAP="/absent/wrapper", TEST_CARGO_STATUS="101")
        result = self.launch(["--rabs-remote", "test", "--no-run"], changes)
        self.assertEqual(result.returncode, 101, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["argv"], [b"test".hex(), b"--no-run".hex()])
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertEqual(len(self.rch_starts()), 1)
        self.assertEqual(value["pid"], self.rch_starts()[0]["pid"])
        self.assertIn(b"using stock Cargo", result.stderr)
        self.assert_no_local_setup()

    def test_remote_worker_preparation_leaves_jobserver_token_for_cargo(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"+")
            changes = self.worker_route_setup(TEST_JOBSERVER_FD=str(read_fd))
            value = self.cargo_result(self.launch(["--rabs-remote", "build"], changes,
                                                 pass_fds=(read_fd, write_fd)))
            self.assertEqual(value["jobserver"], b"+".hex())
            self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.wrap))
            self.assertEqual(value["pid"], self.rch_starts()[0]["pid"])
            self.assertEqual(len(self.starts()), 1)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def owner_receipt(self):
        return self.root / "state/cargo-launcher/daemon-owner.json"

    def crash_service(self):
        value = self.cargo_result(self.launch())
        self.assertEqual(value["env"].get("RUSTC_WRAPPER"), str(self.wrap))
        pid = self.starts()[-1]["pid"]
        receipt = json.loads(self.owner_receipt().read_text())
        identity = rabs.socket_identity(self.endpoint)
        self.assertEqual(receipt["pid"], pid)
        self.assertEqual(receipt["socket"], list(identity))
        os.kill(pid, signal.SIGKILL)  # Only our recorded fixture daemon.
        deadline = time.monotonic() + 3
        while not rabs.process_exited(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(rabs.process_exited(pid), "fixture must be dead before recovery")
        self.assertEqual(rabs.socket_identity(self.endpoint), identity)
        return pid, identity

    def test_crashed_managed_daemon_restarts_and_keeps_existing_state(self):
        old_pid, old_socket = self.crash_service()
        retained = self.root / "state/retained-state"
        retained.write_bytes(b"existing state must survive restart\0\xff")
        args = ["check", "--manifest-path", "a path/Cargo.toml"]
        value = self.cargo_result(self.launch(["--rabs-require-daemon"] + args))
        self.assertEqual(value["env"].get("RUSTC_WRAPPER"), str(self.wrap))
        self.assertEqual(value["argv"], [os.fsencode(arg).hex() for arg in args])
        self.assertEqual(len(self.starts()), 2)
        self.assertNotEqual(self.starts()[-1]["pid"], old_pid)
        self.assertNotEqual(rabs.socket_identity(self.endpoint), old_socket)
        self.assertEqual(retained.read_bytes(), b"existing state must survive restart\0\xff")
        receipt = json.loads(self.owner_receipt().read_text())
        self.assertEqual(receipt["pid"], self.starts()[-1]["pid"])
        self.assertEqual(receipt["socket"], list(rabs.socket_identity(self.endpoint)))
        self.assertEqual(stat.S_IMODE(self.owner_receipt().stat().st_mode), 0o600)

    def test_parallel_recovery_starts_exactly_one_replacement(self):
        self.crash_service()
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: self.launch(
                ["--rabs-require-daemon", "check"], {"TEST_START_DELAY": "0.2"}), range(12)))
        for result in results:
            value = self.cargo_result(result)
            self.assertEqual(value["env"].get("RUSTC_WRAPPER"), str(self.wrap), result.stderr)
        self.assertEqual(len(self.starts()), 2, "one original plus one recovery")

    def test_owner_binding_advances_across_multiple_crashes(self):
        self.crash_service()
        self.crash_service()
        value = self.cargo_result(self.launch(["--rabs-require-daemon"]))
        self.assertEqual(value["env"].get("RUSTC_WRAPPER"), str(self.wrap))
        self.assertEqual(len(self.starts()), 3)
        self.assertEqual(json.loads(self.owner_receipt().read_text())["pid"],
                         self.starts()[-1]["pid"])

    def test_no_start_never_recovers_even_with_a_valid_owner_receipt(self):
        _, identity = self.crash_service()
        receipt = self.owner_receipt().read_bytes()
        result = self.launch(["--rabs-no-start", "--rabs-require-daemon"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        value = self.cargo_result(self.launch(["--rabs-no-start"]))
        self.assertNotIn("RUSTC_WRAPPER", value["env"])
        self.assertEqual(len(self.starts()), 1)
        self.assertEqual(rabs.socket_identity(self.endpoint), identity)
        self.assertEqual(self.owner_receipt().read_bytes(), receipt)

    def test_recovery_never_adopts_a_different_state_directory(self):
        _, identity = self.crash_service()
        result = self.launch(["--rabs-require-daemon"], {
            "RABS_STATE_DIR": str(self.root / "other-state"),
        })
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(len(self.starts()), 1)
        self.assertEqual(rabs.socket_identity(self.endpoint), identity)

    def test_missing_and_malformed_owner_receipts_leave_stale_socket_untouched(self):
        _, identity = self.crash_service()
        receipt = self.owner_receipt()
        receipt.rename(receipt.with_name("retained-owner.json"))
        for content in [None, b"{", b"{}", b"x" * (rabs.MAX_OWNER_RECEIPT + 1),
                        b'{"v":1,"v":1}', b"[]"]:
            with self.subTest(content=content and content[:30]):
                if content is not None:
                    receipt.write_bytes(content)
                    receipt.chmod(0o600)
                result = self.launch(["--rabs-require-daemon"])
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(rabs.socket_identity(self.endpoint), identity)
                self.assertEqual(len(self.starts()), 1)
                if content is not None:
                    self.assertEqual(receipt.read_bytes(), content)

    def test_mismatched_receipt_or_live_pid_cannot_authorize_recovery(self):
        _, identity = self.crash_service()
        original = json.loads(self.owner_receipt().read_text())
        # V2 identifies the owner by PID AND process incarnation. Merely
        # replacing a PID while retaining a dead owner's start time describes
        # PID reuse, which is intentionally recoverable. Exercise a live
        # identity here; the dedicated incarnation tests cover reused PIDs.
        live_owner = {"pid": os.getpid()}
        if original["v"] == 2:
            live_owner["process"] = rabs.process_identity(os.getpid())
        cases = [live_owner, {"pid": True}, {"pid": -1},
                 {"pid": 0x80000000}, {"v": True}, {"v": 3},
                 {"state": [0, 0]}, {"endpoint_lock": [0, 0]},
                 {"socket": [identity[0], identity[1], identity[2] + 1]}]
        for changed in cases:
            with self.subTest(changed=changed):
                value = dict(original)
                value.update(changed)
                self.owner_receipt().write_text(json.dumps(value))
                result = self.launch(["--rabs-require-daemon"])
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(rabs.socket_identity(self.endpoint), identity)
                self.assertEqual(len(self.starts()), 1)

    def test_receipt_symlink_hardlink_fifo_directory_and_public_mode_are_not_repaired(self):
        _, identity = self.crash_service()
        receipt = self.owner_receipt()
        original = receipt.read_bytes()
        for fault in ["symlink", "hardlink", "fifo", "directory", "public"]:
            with self.subTest(fault=fault):
                receipt.rename(receipt.with_name("retained-" + fault))
                target = self.root / ("receipt-target-" + fault)
                target.write_bytes(original)
                target.chmod(0o600)
                if fault == "symlink":
                    receipt.symlink_to(target)
                elif fault == "hardlink":
                    os.link(target, receipt)
                elif fault == "fifo":
                    os.mkfifo(receipt, 0o600)
                elif fault == "directory":
                    receipt.mkdir(mode=0o700)
                else:
                    receipt.write_bytes(original)
                    receipt.chmod(0o666)
                before = receipt.lstat()
                started = time.monotonic()
                result = self.launch(["--rabs-require-daemon"])
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertLess(time.monotonic() - started, 2)
                after = receipt.lstat()
                self.assertEqual((before.st_ino, before.st_mode, before.st_nlink),
                                 (after.st_ino, after.st_mode, after.st_nlink))
                self.assertEqual(target.read_bytes(), original)
                self.assertEqual(rabs.socket_identity(self.endpoint), identity)
                self.assertEqual(len(self.starts()), 1)

    def test_live_unresponsive_recorded_daemon_is_not_restarted(self):
        self.cargo_result(self.launch())
        pid = self.starts()[0]["pid"]
        identity = rabs.socket_identity(self.endpoint)
        receipt = self.owner_receipt().read_bytes()
        os.kill(pid, signal.SIGSTOP)  # Pause only this fixture, then restore it.
        try:
            result = self.launch(["--rabs-require-daemon"], {"CARGO_RABS_STARTUP_MS": "200"})
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(len(self.starts()), 1)
            self.assertEqual(rabs.socket_identity(self.endpoint), identity)
            self.assertEqual(self.owner_receipt().read_bytes(), receipt)
        finally:
            os.kill(pid, signal.SIGCONT)

    def test_failed_recovery_preserves_stock_cargo_exit_and_original_state(self):
        _, identity = self.crash_service()
        receipt = self.owner_receipt().read_bytes()
        result = self.launch(changes={"TEST_START_FAIL": "1", "TEST_CARGO_STATUS": "37"})
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertNotIn("RUSTC_WRAPPER", json.loads(result.stdout)["env"])
        self.assertEqual(len(self.starts()), 2)
        self.assertEqual(rabs.socket_identity(self.endpoint), identity)
        self.assertEqual(self.owner_receipt().read_bytes(), receipt)

    def test_recovery_timeout_leaves_replacement_holding_both_locks(self):
        self.crash_service()
        receipt = self.owner_receipt().read_bytes()
        gate = self.root / "recovery-bind-gate"
        changes = {"TEST_START_GATE": str(gate), "CARGO_RABS_STARTUP_MS": "200"}
        try:
            first = self.cargo_result(self.launch(changes=changes))
            self.assertNotIn("RUSTC_WRAPPER", first["env"])
            self.assertEqual(len(self.starts()), 2)
            self.assertEqual(self.owner_receipt().read_bytes(), receipt)
            second = self.cargo_result(self.launch(changes=changes))
            self.assertNotIn("RUSTC_WRAPPER", second["env"])
            self.assertEqual(len(self.starts()), 2, "the incomplete restart owns both locks")
        finally:
            gate.write_text("allow bind")
        ready = self.cargo_result(self.launch(["--rabs-require-daemon"]))
        self.assertEqual(ready["env"].get("RUSTC_WRAPPER"), str(self.wrap))
        self.assertEqual(len(self.starts()), 2)

    def test_recovery_accepts_socket_parent_alias_but_not_changed_socket_generation(self):
        _, identity = self.crash_service()
        alias = self.root / "parent-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        value = self.cargo_result(self.launch(["--rabs-require-daemon"], {
            "RABS_SOCKET_PATH": str(alias / self.endpoint.name),
        }))
        self.assertEqual(value["env"].get("RUSTC_WRAPPER"), str(self.wrap))
        self.assertNotEqual(rabs.socket_identity(self.endpoint), identity)
        self.assertEqual(len(self.starts()), 2)

    def test_readiness_cannot_be_attributed_to_another_process(self):
        self.cargo_result(self.launch())
        with self.assertRaisesRegex(rabs.SetupError, "not the daemon"):
            rabs.probe(str(self.endpoint), time.monotonic() + 1, os.getpid())
        self.assertTrue(rabs.probe(str(self.endpoint), time.monotonic() + 1, self.starts()[0]["pid"]))

    def test_recovery_receipt_read_failures_do_not_leak_descriptors(self):
        _, identity = self.crash_service()
        self.owner_receipt().write_bytes(b"{broken}")
        with rabs.StartupLock(str(self.root / "state"), str(self.endpoint),
                              time.monotonic() + 2) as lock:
            self.assertTrue(lock.acquire(str(self.endpoint)))
            before = len(os.listdir("/proc/self/fd"))
            for _ in range(20):
                with self.assertRaises(rabs.SetupError):
                    lock.authorize_recovery(identity)
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)


class ProtocolTests(unittest.TestCase):
    def test_dependency_worker_configuration_normalizes_only_socket_address_spelling(self):
        settings = {
            "RABS_DEPENDENCY_WORKER_LISTEN": "[0:0:0:0:0:0:0:1]:09443",
            "RABS_DEPENDENCY_WORKER_ID": "compiler 雪",
            "RABS_DEPENDENCY_WORKER_SPKI_SHA256": "ab" * 32,
        }
        self.assertEqual(rabs.requested_dependency_worker(settings), {
            "remote_protocol": 1, "dependency_context": "dependency-exec-v5",
            "listen": "[::1]:9443", "worker_id": "compiler 雪",
            "worker_spki_sha256": "ab" * 32,
        })
        for spelling in ("[::ffff:192.0.2.1]:9443", "[::ffff:c000:201]:9443"):
            selected = rabs.requested_dependency_worker(dict(settings, RABS_DEPENDENCY_WORKER_LISTEN=spelling))
            self.assertEqual(selected["listen"], "[::ffff:192.0.2.1]:9443")
        self.assertIsNone(rabs.requested_dependency_worker({}))
        for name, bad in [
            ("RABS_DEPENDENCY_WORKER_LISTEN", "localhost:9443"),
            ("RABS_DEPENDENCY_WORKER_LISTEN", "127.0.0.1:0"),
            ("RABS_DEPENDENCY_WORKER_LISTEN", "::1:9443"),
            ("RABS_DEPENDENCY_WORKER_LISTEN", "[::1]:65536"),
            ("RABS_DEPENDENCY_WORKER_LISTEN", "[fe80::1%eth0]:9443"),
            ("RABS_DEPENDENCY_WORKER_ID", ""),
            ("RABS_DEPENDENCY_WORKER_ID", "worker\ncontrol"),
            ("RABS_DEPENDENCY_WORKER_ID", "雪" * 342),
            ("RABS_DEPENDENCY_WORKER_SPKI_SHA256", "0" * 64),
            ("RABS_DEPENDENCY_WORKER_SPKI_SHA256", "AB" * 32),
            ("RABS_DEPENDENCY_WORKER_SPKI_SHA256", "ab" * 31),
        ]:
            with self.subTest(name=name, bad=bad), self.assertRaises(rabs.SetupError):
                rabs.requested_dependency_worker(dict(settings, **{name: bad}))

    def test_dependency_worker_status_requires_typed_supported_capability(self):
        expected = {
            "remote_protocol": 1, "dependency_context": "dependency-exec-v5",
            "listen": "127.0.0.1:9443", "worker_id": "compiler",
            "worker_spki_sha256": "ab" * 32,
        }
        rabs.require_dependency_worker({"remote_dependency": expected}, expected)
        rabs.require_dependency_worker({}, None)
        for actual in [None, True, [], {}, dict(expected, remote_protocol=True),
                       dict(expected, remote_protocol=2),
                       dict(expected, dependency_context="dependency-exec-v1"),
                       dict(expected, dependency_context="dependency-exec-v2"),
                       dict(expected, dependency_context="dependency-exec-v3"),
                       dict(expected, dependency_context="dependency-exec-v4"),
                       dict(expected, dependency_context="dependency-exec-v6")]:
            with self.subTest(actual=actual), self.assertRaises(rabs.RemoteConfigurationMismatch):
                rabs.require_dependency_worker({"remote_dependency": actual}, expected)

    def test_argument_boundary_does_not_consume_cargo_options(self):
        self.assertEqual(rabs.arguments(["rabs"]), (["build"], False, False, False))
        self.assertEqual(rabs.arguments(["rabs", "--rabs-no-start", "check", "--rabs-require-daemon"]),
                         (["check", "--rabs-require-daemon"], True, False, False))
        self.assertEqual(rabs.arguments(["--", "--help"]), (["--help"], False, False, False))
        self.assertEqual(rabs.arguments(["+nightly", "build"]), (["+nightly", "build"], False, False, False))
        self.assertEqual(rabs.arguments(["rabs", "--rabs-remote"]), (["build"], False, False, True))
        self.assertEqual(rabs.arguments(["--rabs-remote", "--", "--help"]),
                         (["--help"], False, False, True))

    def test_json_object_must_be_complete_unambiguous_and_utf8(self):
        for data in [b'[]', b'null', b'{"kind":"x","kind":"y"}', b'{"a":{"x":1,"x":2}}',
                     b'{} {}', b'{"a":"\xff"}', b'{']:
            with self.subTest(data=data), self.assertRaises(rabs.SetupError):
                rabs.decode_object(data)

    def test_json_decoder_recursion_failure_is_a_setup_failure(self):
        # The JSON implementation/host recursion limit differs across Python
        # versions. Exercise its failure contract without changing global limits.
        with mock.patch.object(rabs.json, "loads", side_effect=RecursionError("deep JSON")):
            with self.assertRaises(rabs.SetupError):
                rabs.decode_object(b'{"kind":"coord-status"}')

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
