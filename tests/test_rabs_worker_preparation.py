#!/usr/bin/env python3
"""Native process checks for the production RCH/RABS preparation boundary.

The adapter, fork/exec, pipes, deadlines, signals and descriptor custody are
real. The installed preparation API and Cargo executable are explicit fixture
doubles. This suite does not compile Rust, contact a fleet, or prove cache hits.
"""

import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "rch-common/src/toolchain/worker_cache.py"
PROGRAM = ADAPTER.read_text()
SPEC = importlib.util.spec_from_file_location("worker_preparation", ADAPTER)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)

CARGO = r'''
import json, os, signal, sys
value = {"pid": os.getpid(), "argv": [os.fsencode(a).hex() for a in sys.argv[1:]],
         "cwd": os.getcwd(), "env": dict(os.environ)}
if os.environ.get("READ_STDIN") == "1":
    value["stdin"] = sys.stdin.buffer.read().hex()
if "JOBSERVER_READ" in os.environ:
    value["token"] = os.read(int(os.environ["JOBSERVER_READ"]), 1).hex()
with open(os.environ["TEST_ROOT"] + "/executions", "a") as output:
    output.write(json.dumps(value) + "\n")
print(json.dumps(value), flush=True)
if "CARGO_SIGNAL" in os.environ:
    os.kill(os.getpid(), int(os.environ["CARGO_SIGNAL"]))
sys.exit(int(os.environ.get("CARGO_STATUS", "0")))
'''


@unittest.skipUnless(sys.platform == "linux", "Linux worker preparation")
class WorkerPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rabs-prepare-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.cargo = self.bin / "cargo"
        self.cargo.write_text("#!" + sys.executable + "\n" + CARGO)
        self.cargo.chmod(0o755)
        self.launcher = self.bin / "cargo-rabs"
        self.env = dict(os.environ)
        for key in (adapter.ACTIVE, "CARGO_RABS_STARTUP_MS", "RUSTC_WRAPPER",
                    "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_SIGNAL", "CARGO_STATUS"):
            self.env.pop(key, None)
        self.env.update({"PATH": str(self.bin) + ":/usr/bin:/bin", "TEST_ROOT": str(self.root),
                         "RCH_RABS_PREPARE_TIMEOUT_MS": "1500"})
        self.replace("def prepare(env, **kw):\n    env['PREPARED'] = 'yes'\n    return env\n")

    def replace(self, body):
        self.launcher.write_text("RCH_WORKER_PREPARATION_API = 1\n" + body)
        self.launcher.chmod(0o755)

    def start(self, args=(), changes=None, pass_fds=(), command=None):
        environment = dict(self.env)
        environment.update(changes or {})
        return subprocess.Popen(
            [sys.executable, "-c", PROGRAM, *(command or [str(self.cargo)]), *args],
            env=environment, cwd=self.root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=pass_fds,
        )

    def finish(self, process, data=b"", timeout=5):
        try:
            stdout, stderr = process.communicate(data, timeout=timeout)
        except BaseException:
            process.kill()
            process.wait()
            raise
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def run_worker(self, args=(), changes=None, pass_fds=(), data=b"", command=None):
        process = self.start(args, changes, pass_fds, command)
        return self.finish(process, data), process.pid

    def one_execution(self, completed, status=0):
        self.assertEqual(completed.returncode, status, completed.stderr.decode(errors="replace"))
        values = (self.root / "executions").read_text().splitlines()
        self.assertEqual(len(values), 1, "Cargo must execute exactly once")
        self.assertEqual(len(completed.stdout.splitlines()), 1, "setup must not corrupt Cargo stdout")
        self.assertEqual(json.loads(values[0]), json.loads(completed.stdout))
        return json.loads(completed.stdout)

    def wait_for(self, name, process):
        path = self.root / name
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if path.exists() and path.read_text():
                return path.read_text()
            self.assertIsNone(process.poll(), "adapter exited before the test reached setup")
            time.sleep(0.01)
        self.fail("preparation helper did not publish its test rendezvous")

    def blocked_launcher(self, where="prepare"):
        body = ("import os, time\n"
                "def block():\n"
                "    with open(os.environ['TEST_ROOT'] + '/preparer', 'w') as output:\n"
                "        output.write(str(os.getpid()))\n"
                "    time.sleep(30)\n")
        if where == "import":
            body += "block()\ndef prepare(env, **kw): return env\n"
        else:
            body += "def prepare(env, **kw):\n    block()\n    return env\n"
        self.replace(body)

    def test_success_preserves_cargo_pid_argv_cwd_and_opaque_environment(self):
        arguments = ["+nightly", "build", "--", "", "a b", "line\nbreak", os.fsdecode(b"raw-\xff")]
        expected = {"RUSTUP_TOOLCHAIN": "nightly-2026-08-31", "RUSTC": "/chosen/rustc",
                    "RUSTC_WORKSPACE_WRAPPER": "/workspace/wrapper", "OPAQUE": os.fsdecode(b"\xff")}
        completed, pid = self.run_worker(arguments, expected)
        value = self.one_execution(completed)
        self.assertEqual(value["pid"], pid)
        self.assertEqual(value["argv"], [os.fsencode(a).hex() for a in arguments])
        self.assertEqual(value["cwd"], str(self.root))
        self.assertEqual(value["env"]["PREPARED"], "yes")
        for key, wanted in expected.items():
            self.assertEqual(value["env"][key], wanted)

    def test_preparation_cannot_consume_cargo_stdin_or_contaminate_json_stdout(self):
        self.replace("import sys\ndef prepare(env, **kw):\n"
                     "    assert sys.stdin.buffer.read() == b''\n"
                     "    print('setup output belongs on stderr')\n"
                     "    env['PREPARED'] = 'yes'\n    return env\n")
        completed, _ = self.run_worker(changes={"READ_STDIN": "1"}, data=b"Cargo input\x00\xff")
        value = self.one_execution(completed)
        self.assertEqual(value["stdin"], b"Cargo input\x00\xff".hex())
        self.assertIn(b"setup output belongs on stderr", completed.stderr)

    def test_jobserver_tokens_belong_to_cargo_not_the_preparer(self):
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)
        os.write(write, b"+")
        self.replace("import os\ndef prepare(env, **kw):\n"
                     "    try:\n        os.fstat(int(env['JOBSERVER_READ']))\n"
                     "    except OSError:\n        env['PREPARER_CLOSED_JOBSERVER'] = 'yes'\n"
                     "    return env\n")
        flags = "-j --jobserver-auth={},{}".format(read, write)
        completed, _ = self.run_worker(changes={"JOBSERVER_READ": str(read), "CARGO_MAKEFLAGS": flags},
                                       pass_fds=(read, write))
        value = self.one_execution(completed)
        self.assertEqual(value["token"], b"+".hex())
        self.assertEqual(value["env"]["CARGO_MAKEFLAGS"], flags)
        self.assertEqual(value["env"]["PREPARER_CLOSED_JOBSERVER"], "yes")

    def test_hung_api_falls_back_once_with_original_environment_and_status(self):
        self.blocked_launcher()
        started = time.monotonic()
        completed, _ = self.run_worker(changes={"RCH_RABS_PREPARE_TIMEOUT_MS": "150", "CARGO_STATUS": "43"})
        value = self.one_execution(completed, 43)
        self.assertLess(time.monotonic() - started, 2)
        self.assertNotIn("PREPARED", value["env"])
        self.assertNotIn(adapter.ACTIVE, value["env"])
        self.assertIn(b"preparation deadline expired", completed.stderr)
        preparer = int((self.root / "preparer").read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(preparer, 0)

    def test_module_import_is_inside_the_same_outer_deadline(self):
        self.blocked_launcher("import")
        completed, _ = self.run_worker(changes={"RCH_RABS_PREPARE_TIMEOUT_MS": "150"})
        self.one_execution(completed)
        self.assertIn(b"preparation deadline expired", completed.stderr)

    def test_setup_system_exit_cannot_exit_cargo_or_select_a_partial_environment(self):
        self.replace("def prepare(env, **kw):\n    env['PREPARED']='partial'\n    raise SystemExit(9)\n")
        completed, _ = self.run_worker()
        self.assertNotIn("PREPARED", self.one_execution(completed)["env"])
        self.assertIn(b"SystemExit", completed.stderr)

    def test_invalid_exec_environment_falls_back_before_the_exec_boundary(self):
        for environment in [{"": "empty"}, {"BAD=NAME": "value"}, {"BAD\0NAME": "value"}, {"BAD": "nul\0"}]:
            with self.subTest(environment=environment):
                self.replace("def prepare(env, **kw): return " + repr(environment) + "\n")
                completed, _ = self.run_worker()
                self.assertNotIn("PREPARED", self.one_execution(completed)["env"])
                self.assertIn(b"invalid environment", completed.stderr)
                (self.root / "executions").unlink()

    def test_oversized_result_does_not_reach_exec_or_exceed_frame_bound(self):
        self.replace("def prepare(env, **kw):\n    env['TOO_BIG']='x' * (2 * 1024 * 1024)\n    return env\n")
        completed, _ = self.run_worker()
        self.assertNotIn("TOO_BIG", self.one_execution(completed)["env"])
        self.assertIn(b"frame bound", completed.stderr)

    def test_setup_log_flood_is_drained_but_only_a_bounded_prefix_is_replayed(self):
        self.replace("import os\ndef prepare(env, **kw):\n"
                     "    for _ in range(1024): os.write(2, b'x' * 4096)\n"
                     "    env['PREPARED']='yes'\n    return env\n")
        completed, _ = self.run_worker(changes={"RCH_RABS_PREPARE_TIMEOUT_MS": "4000"})
        self.assertEqual(self.one_execution(completed)["env"]["PREPARED"], "yes")
        self.assertLess(len(completed.stderr), adapter.MAX_PREPARE_LOG_BYTES + 256)
        self.assertIn(b"diagnostics truncated", completed.stderr)

    def test_explicit_zero_and_recursive_entry_do_not_start_any_preparer(self):
        self.blocked_launcher("import")
        for changes in [{"RCH_RABS_PREPARE_TIMEOUT_MS": "0"}, {adapter.ACTIVE: "1"}]:
            with self.subTest(changes=changes):
                completed, _ = self.run_worker(changes=changes)
                self.one_execution(completed)
                self.assertFalse((self.root / "preparer").exists())
                (self.root / "executions").unlink()

    def test_keyboard_interrupt_from_setup_never_starts_cargo(self):
        self.replace("def prepare(env, **kw): raise KeyboardInterrupt()\n")
        completed, _ = self.run_worker()
        self.assertEqual(completed.returncode, 130, completed.stderr)
        self.assertFalse((self.root / "executions").exists())
        self.assertEqual(completed.stdout, b"")

    def test_external_cancellation_reaps_owned_helper_without_running_cargo(self):
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number):
                self.blocked_launcher()
                process = self.start(changes={"RCH_RABS_PREPARE_TIMEOUT_MS": "5000"})
                preparer = int(self.wait_for("preparer", process))
                process.send_signal(number)
                completed = self.finish(process)
                self.assertEqual(completed.returncode, 128 + number, completed.stderr)
                self.assertFalse((self.root / "executions").exists())
                with self.assertRaises(ProcessLookupError):
                    os.kill(preparer, 0)
                (self.root / "preparer").unlink()

    def test_unrelated_process_survives_preparation_timeout(self):
        sentinel = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            self.blocked_launcher()
            completed, _ = self.run_worker(changes={"RCH_RABS_PREPARE_TIMEOUT_MS": "150"})
            self.one_execution(completed)
            self.assertIsNone(sentinel.poll())
        finally:
            sentinel.terminate()
            sentinel.wait(timeout=3)

    def stop_peer(self, descriptor):
        try:
            if not select.select([descriptor], [], [], 0)[0]:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            self.assertTrue(select.select([descriptor], [], [], 3)[0])
        finally:
            os.close(descriptor)

    @unittest.skipUnless(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                         "identity-safe Linux process observation")
    def test_owned_descendant_cannot_hold_setup_streams_open_after_helper_exit(self):
        self.replace("import os, subprocess, sys\ndef prepare(env, **kw):\n"
                     "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
                     "    with open(env['TEST_ROOT'] + '/descendant', 'w') as output:\n"
                     "        output.write(str(child.pid))\n"
                     "    env['PREPARED']='partial'\n    return env\n")
        process = self.start(changes={"RCH_RABS_PREPARE_TIMEOUT_MS": "1000"})
        pid = int(self.wait_for("descendant", process))
        descriptor = os.pidfd_open(pid)
        self.addCleanup(self.stop_peer, descriptor)
        completed = self.finish(process)
        self.assertNotIn("PREPARED", self.one_execution(completed)["env"])
        self.assertIn(b"preparation deadline expired", completed.stderr)
        self.assertTrue(select.select([descriptor], [], [], 1)[0], "owned descendant must exit")

    @unittest.skipUnless(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                         "identity-safe Linux process observation")
    def test_separately_sessioned_daemon_survives_successful_preparer_cleanup(self):
        self.replace("import subprocess, sys\ndef prepare(env, **kw):\n"
                     "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],\n"
                     "        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,\n"
                     "        stderr=subprocess.DEVNULL, start_new_session=True)\n"
                     "    with open(env['TEST_ROOT'] + '/daemon', 'w') as output:\n"
                     "        output.write(str(child.pid))\n"
                     "    env['PREPARED']='yes'\n    return env\n")
        process = self.start()
        pid = int(self.wait_for("daemon", process))
        descriptor = os.pidfd_open(pid)
        self.addCleanup(self.stop_peer, descriptor)
        completed = self.finish(process)
        self.assertEqual(self.one_execution(completed)["env"]["PREPARED"], "yes")
        self.assertFalse(select.select([descriptor], [], [], 0)[0], "shared daemon must stay alive")

    def test_cargo_failure_and_signal_are_authoritative_and_not_retried(self):
        for changes, expected in [({"CARGO_STATUS": "19"}, 19), ({"CARGO_SIGNAL": str(signal.SIGTERM)}, -signal.SIGTERM)]:
            with self.subTest(changes=changes):
                completed, _ = self.run_worker(changes=changes)
                self.one_execution(completed, expected)
                (self.root / "executions").unlink()

    def test_python_signal_dispositions_are_not_leaked_to_the_real_command(self):
        completed, _ = self.run_worker(command=["/bin/sh", "-c", "kill -PIPE $$"])
        self.assertEqual(completed.returncode, -signal.SIGPIPE, completed.stderr)

    def test_missing_executable_keeps_exec_error_status(self):
        completed, _ = self.run_worker(command=[str(self.root / "no-such-program")])
        self.assertEqual(completed.returncode, 127)
        self.assertFalse((self.root / "executions").exists())

    def test_worker_budget_inherits_launcher_budget_and_is_bounded(self):
        self.assertEqual(adapter.preparation_seconds({}), 7)
        self.assertEqual(adapter.preparation_seconds({"CARGO_RABS_STARTUP_MS": "30000"}), 32)
        self.assertEqual(adapter.preparation_seconds({"RCH_RABS_PREPARE_TIMEOUT_MS": "999999"}), 35)
        self.assertEqual(adapter.preparation_seconds({"RCH_RABS_PREPARE_TIMEOUT_MS": "0"}), 0)
        self.assertEqual(adapter.preparation_seconds({"RCH_RABS_PREPARE_TIMEOUT_MS": "bad"}), 7)
        self.assertEqual(adapter.preparation_seconds({"CARGO_RABS_STARTUP_MS": "bad"}), 7)


if __name__ == "__main__":
    unittest.main()
