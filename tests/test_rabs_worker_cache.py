#!/usr/bin/env python3
"""Execute RCH's embedded worker adapter with the real cargo-rabs launcher.

Processes, Unix sockets, locks, exec, and descriptors are real. Cargo, rustup,
and rabsd are explicitly fixture executables, not a Rust/fleet/cache-hit proof.
"""

import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "rch-common/src/toolchain/worker_cache.py"
RUST = ROOT / "rch-common/src/toolchain/worker_cache.rs"
SHELL = re.search(r'const PLATFORM_RUNNER: &str = r#"(.*?)"#;',
                  RUST.read_text(), re.DOTALL).group(1)
PROGRAM = ADAPTER.read_text()
spec = importlib.util.spec_from_file_location(
    "launcher_fixtures", ROOT / "scripts/tests/test_cargo_rabs.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)

RUSTUP = r'''
import json, os, sys
assert sys.argv[1] == "run"
with open(os.environ["TEST_ROOT"] + "/rustup-called", "w") as output:
    json.dump(sys.argv[2:], output)
os.environ["RUSTUP_TOOLCHAIN"] = sys.argv[2]
argv = sys.argv[3:]
if argv[0] == "cargo" and "TEST_SELECTED_CARGO" in os.environ:
    argv[0] = os.environ["TEST_SELECTED_CARGO"]
os.execvpe(argv[0], argv, dict(os.environ))
'''


@unittest.skipUnless(sys.platform == "linux", "Linux launcher peer credentials")
class WorkerCacheTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.LauncherTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        self.bin = self.fixture.bin
        self.env = dict(self.fixture.env)
        self.env.pop("RCH_RABS_WORKER_ACTIVE", None)
        self.env["PATH"] = str(self.bin) + ":/usr/bin:/bin"
        self.launcher = self.bin / "cargo-rabs"
        self.launcher.symlink_to(fixtures.LAUNCHER)
        (self.bin / "python3").symlink_to(sys.executable)
        self.fixture.make_program("rustup", RUSTUP)

    def run_worker(self, args=(), changes=None, pass_fds=(), executable="cargo"):
        env = dict(self.env)
        env.update(changes or {})
        command = ["/bin/sh", "-c", SHELL, "rch-rabs-worker", PROGRAM, executable, *args]
        child = subprocess.Popen(command, env=env, cwd=self.root, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, pass_fds=pass_fds)
        try:
            stdout, stderr = child.communicate(timeout=8)
        except BaseException:
            child.kill()
            child.wait()
            raise
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr), child.pid

    def result(self, completed):
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(len(completed.stdout.splitlines()), 1, "exactly one Cargo execution")
        return json.loads(completed.stdout)

    def replace_launcher(self, text):
        candidate = self.bin / "replacement-launcher"
        candidate.write_text(text)
        candidate.chmod(0o755)
        candidate.replace(self.launcher)

    def test_remote_cargo_enters_existing_live_lane_without_a_second_cargo(self):
        arguments = ["build", "--release", "--manifest-path", "a b/Cargo.toml"]
        completed, pid = self.run_worker(arguments, {"CARGO": "/dispatcher/absent/cargo"})
        value = self.result(completed)
        self.assertEqual(value["pid"], pid, "adapter execs, it does not supervise another Cargo")
        self.assertEqual(value["argv"], [os.fsencode(arg).hex() for arg in arguments])
        self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.fixture.wrap))
        self.assertEqual(value["cwd"], str(self.root))
        self.assertEqual(len(self.fixture.starts()), 1)
        self.assertEqual(self.fixture.starts()[0]["live"], "1")
        self.assertEqual(completed.stderr, b"cargo's own stderr\n")

    def test_multiple_builds_reuse_one_daemon_and_existing_state(self):
        self.result(self.run_worker(["check"])[0])
        marker = self.root / "state" / "retained-state"
        marker.write_bytes(b"retained cache state")
        for args in (["test"], ["build", "--release"]):
            value = self.result(self.run_worker(args)[0])
            self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.fixture.wrap))
        self.assertEqual(len(self.fixture.starts()), 1)
        self.assertEqual(marker.read_bytes(), b"retained cache state")

    def test_concurrent_remote_builds_share_one_launcher_owned_daemon(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: self.run_worker(["build"])[0], range(12)))
        for result in results:
            self.assertEqual(self.result(result)["env"]["RUSTC_WRAPPER"], str(self.fixture.wrap))
        self.assertEqual(len(self.fixture.starts()), 1)

    def test_existing_launcher_crash_recovery_is_reused_not_reimplemented(self):
        self.result(self.run_worker(["build"])[0])
        first = self.fixture.starts()[0]["pid"]
        os.kill(first, signal.SIGKILL)
        deadline = time.monotonic() + 2
        while not fixtures.rabs.process_exited(first) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(fixtures.rabs.process_exited(first))
        self.assertTrue(self.fixture.endpoint.exists())
        self.result(self.run_worker(["build"])[0])
        self.assertEqual(len(self.fixture.starts()), 2)
        self.assertNotEqual(self.fixture.starts()[-1]["pid"], first)

    def test_opaque_argv_cwd_toolchain_and_cargo_environment_are_preserved(self):
        args = ["+nightly", "test", "--", "", "a'b\"c", "$HOME; echo nope", "line\nbreak",
                "日本語", os.fsdecode(b"opaque-\xff")]
        expected = {"RUSTUP_TOOLCHAIN": "nightly-2026-08-31", "RUSTC": "/selected/rustc",
                    "RUSTC_WORKSPACE_WRAPPER": "/workspace/wrapper",
                    "CARGO_TARGET_DIR": "private output", "CARGO_MAKEFLAGS": "-j"}
        value = self.result(self.run_worker(args, expected)[0])
        self.assertEqual(value["argv"], [os.fsencode(arg).hex() for arg in args])
        self.assertEqual(value["cwd"], str(self.root))
        for key, expected_value in expected.items():
            self.assertEqual(value["env"][key], expected_value)

    def test_jobserver_descriptors_survive_the_entire_setup_and_exec(self):
        read, write = os.pipe()
        try:
            os.write(write, b"+")
            changes = {"TEST_JOBSERVER_FD": str(read),
                       "CARGO_MAKEFLAGS": "-j --jobserver-fds={},{}".format(read, write)}
            value = self.result(self.run_worker(["build"], changes, (read, write))[0])
            self.assertEqual(value["jobserver"], "2b")
            self.assertEqual(value["env"]["CARGO_MAKEFLAGS"], changes["CARGO_MAKEFLAGS"])
        finally:
            os.close(read)
            os.close(write)

    def test_custom_or_disabled_wrappers_keep_stock_behavior(self):
        for name, value in [("RUSTC_WRAPPER", "/custom/wrapper"), ("RUSTC_WRAPPER", ""),
                            ("CARGO_BUILD_RUSTC_WRAPPER", "/custom/wrapper")]:
            with self.subTest(name=name, value=value):
                completed, _ = self.run_worker(["build"], {name: value})
                result = self.result(completed)
                self.assertEqual(result["env"][name], value)
                self.assertIn(b"using stock Cargo", completed.stderr)
                self.assertEqual(self.fixture.starts(), [])

    def test_missing_launcher_preserves_environment_and_exit_status(self):
        self.launcher.rename(self.bin / "launcher-not-on-path")
        completed, _ = self.run_worker(["test"], {"TEST_CARGO_STATUS": "43"})
        self.assertEqual(completed.returncode, 43)
        self.assertNotIn("RUSTC_WRAPPER", json.loads(completed.stdout)["env"])
        self.assertEqual(self.fixture.starts(), [])
        self.assertIn(b"cargo-rabs is not installed", completed.stderr)

    def test_incompatible_launcher_does_not_invoke_its_cli(self):
        self.replace_launcher("if __name__ == '__main__':\n    raise RuntimeError('CLI ran')\n")
        completed, _ = self.run_worker(["build"])
        self.result(completed)
        self.assertIn(b"lacks preparation API version 1", completed.stderr)
        self.assertEqual(self.fixture.starts(), [])

    def test_malformed_or_invalid_preparation_falls_back_before_cargo(self):
        for source in ["this is not Python!", "def prepare(*a, **k): return None\n",
                       "def prepare(*a, **k): return {'KEY': 4}\n",
                       "def prepare(env, **k):\n    env['RUSTC_WRAPPER']='bad'\n    raise OSError('no')\n"]:
            with self.subTest(source=source):
                self.replace_launcher("RCH_WORKER_PREPARATION_API = 1\n" + source)
                completed, _ = self.run_worker(["build"])
                self.assertNotIn("RUSTC_WRAPPER", self.result(completed)["env"])
                self.assertEqual(self.fixture.starts(), [])

    def test_setup_deadline_does_not_turn_into_a_second_or_failed_cargo(self):
        start = time.monotonic()
        completed, _ = self.run_worker(["check"], {"TEST_CONFIG": "hang",
                                                  "CARGO_RABS_STARTUP_MS": "120"})
        self.result(completed)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(self.fixture.starts(), [])
        self.assertIn(b"using stock Cargo", completed.stderr)

    def test_existing_bad_socket_is_not_removed_or_replaced(self):
        self.fixture.listening_peer()
        before = self.fixture.endpoint.stat()
        completed, _ = self.run_worker(["build"], {"CARGO_RABS_STARTUP_MS": "100"})
        self.result(completed)
        after = self.fixture.endpoint.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual(self.fixture.starts(), [])

    def test_recursive_setup_marker_never_grants_a_compiler_skip(self):
        completed, _ = self.run_worker(["build"], {"RCH_RABS_WORKER_ACTIVE": "1"})
        self.assertNotIn("RUSTC_WRAPPER", self.result(completed)["env"])
        self.assertEqual(self.fixture.starts(), [])

    def test_non_linux_platform_does_not_import_python_or_start_a_daemon(self):
        for platform in ["Darwin", "MINGW64_NT-10.0"]:
            self.fixture.make_program("uname", "print({!r})\n".format(platform))
            completed, _ = self.run_worker(["build"])
            self.assertNotIn("RUSTC_WRAPPER", self.result(completed)["env"])
            self.assertEqual(self.fixture.starts(), [])

    def test_missing_python_runs_the_original_cargo(self):
        isolated = self.root / "no-python"
        isolated.mkdir()
        (isolated / "cargo").symlink_to(self.fixture.cargo)
        (isolated / "uname").symlink_to("/usr/bin/uname")
        completed, _ = self.run_worker(["build"], {"PATH": str(isolated)})
        self.assertNotIn("RUSTC_WRAPPER", self.result(completed)["env"])
        self.assertEqual(self.fixture.starts(), [])

    def test_cargo_failure_or_signal_is_returned_without_any_reexecution(self):
        completed, _ = self.run_worker(["test"], {"TEST_CARGO_STATUS": "101"})
        self.assertEqual(completed.returncode, 101)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        completed, _ = self.run_worker(["test"], {"TEST_CARGO_SIGNAL": str(signal.SIGTERM)})
        self.assertEqual(completed.returncode, -signal.SIGTERM)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertEqual(len(self.fixture.starts()), 1)

    def test_python_sigpipe_ignore_does_not_leak_into_the_real_command(self):
        self.fixture.cargo.write_text("#!/bin/sh\nkill -PIPE $$\nprintf 'must not run'\n")
        completed, _ = self.run_worker(["build"])
        self.assertEqual(completed.returncode, -signal.SIGPIPE)
        self.assertEqual(completed.stdout, b"")

    def test_cancellation_during_setup_never_starts_cargo(self):
        self.replace_launcher("RCH_WORKER_PREPARATION_API = 1\n"
                              "def prepare(*a, **k): raise KeyboardInterrupt()\n")
        completed, _ = self.run_worker(["build"])
        self.assertEqual(completed.returncode, 130)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(self.fixture.starts(), [])

    def test_unknown_api_version_cannot_execute_top_level_launcher_code(self):
        for version in ["", "RCH_WORKER_PREPARATION_API = 2\n",
                        "RCH_WORKER_PREPARATION_API = True\n",
                        "RCH_WORKER_PREPARATION_API = 1\nRCH_WORKER_PREPARATION_API = 2\n"]:
            with self.subTest(version=version):
                marker = self.root / "must-not-run-cli"
                self.replace_launcher(version +
                                      "from pathlib import Path\nPath({!r}).touch()\n".format(str(marker)))
                completed, _ = self.run_worker(["build"])
                self.result(completed)
                self.assertFalse(marker.exists())
                self.assertEqual(self.fixture.starts(), [])

    def test_oversized_launcher_is_refused_before_any_source_executes(self):
        marker = self.root / "must-not-run-large-script"
        self.replace_launcher("RCH_WORKER_PREPARATION_API = 1\nfrom pathlib import Path\n"
                              "Path({!r}).touch()\n#".format(str(marker)) + "x" * (128 * 1024))
        completed, _ = self.run_worker(["build"])
        self.result(completed)
        self.assertFalse(marker.exists())
        self.assertIn(b"source bound", completed.stderr)

    def test_failed_exec_does_not_try_a_different_cargo(self):
        completed, _ = self.run_worker([], {"RCH_RABS_WORKER_ACTIVE": "1"},
                                      executable="/nonexistent/rch-cargo")
        self.assertEqual(completed.returncode, 127)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(self.fixture.starts(), [])

    def test_worker_setup_preserves_rustup_selection_after_env_sanitization(self):
        # This executes the exact embedded shell/Python payload. Assembly here
        # mirrors the Rust string builder; its unit tests cover actual assembly.
        toolchain = "nightly;echo should-not-run"
        args = ["cargo", "+stable", "build", "--features", "a'b ; $HOME"]
        runner = "sh -c {} rch-rabs-worker {}".format(shlex.quote(SHELL), shlex.quote(PROGRAM))
        command = "env -u RUSTC_WRAPPER {} rustup run {} {}".format(
            runner, shlex.quote(toolchain), " ".join(shlex.quote(arg) for arg in args))
        env = dict(self.env, RUSTC_WRAPPER="/dispatcher/absent/wrapper")
        completed = subprocess.run(["/bin/sh", "-c", command], cwd=self.root, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        value = self.result(completed)
        self.assertEqual(value["env"]["RUSTUP_TOOLCHAIN"], toolchain)
        self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.fixture.wrap))
        self.assertEqual(value["argv"], [os.fsencode(arg).hex() for arg in args[1:]])
        self.assertEqual(json.loads((self.root / "rustup-called").read_text())[0], toolchain)
        self.assertEqual(len(self.fixture.starts()), 1)

    def test_rustup_selected_cargo_is_not_replaced_by_a_path_shim(self):
        selected = self.root / "toolchain-cargo"
        self.fixture.cargo.rename(selected)
        self.fixture.make_program("cargo", "raise SystemExit(66)\n")
        env = dict(self.env, TEST_SELECTED_CARGO=str(selected))
        runner = "sh -c {} rch-rabs-worker {}".format(shlex.quote(SHELL), shlex.quote(PROGRAM))
        command = runner + " rustup run nightly cargo build"
        completed = subprocess.run(["/bin/sh", "-c", command], cwd=self.root, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        value = self.result(completed)
        self.assertEqual(value["env"]["RUSTC_WRAPPER"], str(self.fixture.wrap))
        self.assertEqual(value["env"]["RUSTUP_TOOLCHAIN"], "nightly")
        # Sensitivity: putting preparation INSIDE `rustup run ... sh` loses
        # Rustup's direct Cargo choice. The planted PATH shim catches that bug.
        wrong = subprocess.run(["/bin/sh", "-c", "rustup run nightly " + runner + " cargo build"],
                               cwd=self.root, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=8)
        self.assertEqual(wrong.returncode, 66)
        self.assertEqual(wrong.stdout, b"")


if __name__ == "__main__":
    unittest.main()
