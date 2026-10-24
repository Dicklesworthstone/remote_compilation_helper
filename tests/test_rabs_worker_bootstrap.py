#!/usr/bin/env python3
"""Run the shipped worker bootstrap against project/Python startup collisions.

The shell and worker_cache.py are production bytes. The installed preparation
API and Cargo are explicit fixtures; this is not a daemon, cache-hit or fleet
qualification. Cargo is a shell fixture, so poisoned Python settings cannot
contaminate the oracle itself. Test-owned directories are retained for diagnosis.
"""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rch-common/src/toolchain/worker_cache.rs"
ADAPTER = Path(os.environ.get("RCH_TEST_WORKER_ADAPTER",
                             ROOT / "rch-common/src/toolchain/worker_cache.py"))
RUNNER_FILE = os.environ.get("RCH_TEST_WORKER_RUNNER")
RUNNER = (Path(RUNNER_FILE).read_text() if RUNNER_FILE else
          re.search(r'const PLATFORM_RUNNER: &str = r#"(.*?)"#;',
                    RUST.read_text(), re.DOTALL).group(1))
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")
PYTHON = getattr(sys, "_base_executable", sys.executable)
PREPARE = '''RCH_WORKER_PREPARATION_API = 1
import json, os, sys

def prepare(env, no_start):
    with open(env["TEST_ROOT"] + "/prepare.json", "w") as report:
        json.dump({"isolated": sys.flags.isolated, "no_site": sys.flags.no_site,
                   "path": sys.path, "stdin": os.read(0, 1).hex()}, report)
    if env.get("TEST_PREPARE") == "error":
        raise RuntimeError("fixture setup unavailable")
    if env.get("TEST_PREPARE") == "cancel":
        raise KeyboardInterrupt
    result = dict(env)
    result["RUSTC_WRAPPER"] = "/fixture/rabs-wrap"
    return result
'''


def executable(path, content):
    path.write_text(content)
    path.chmod(0o700)


class Fixture:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-bootstrap-isolation-"))
        self.project = self.root / "project with ' quotes"
        self.tools = self.root / "tools"
        self.project.mkdir()
        self.tools.mkdir()
        (self.tools / "python3").symlink_to(PYTHON)
        (self.tools / "uname").symlink_to(shutil.which("uname"))
        executable(self.tools / "cargo-rabs", PREPARE)
        env_tool = shlex.quote(shutil.which("env"))
        cat = shlex.quote(shutil.which("cat"))
        executable(self.tools / "cargo", '#!/bin/sh\nset -eu\n'
                   'printf "%s\\n" "$$" >> "$TEST_ROOT/cargo.calls"\n'
                   'printf "%s\\0" "$@" > "$TEST_ROOT/argv"\n'
                   + env_tool + ' -0 > "$TEST_ROOT/environment"\n'
                   'printf "%s" "$PWD" > "$TEST_ROOT/cwd"\n'
                   + cat + ' > "$TEST_ROOT/stdin"\n'
                   'if [ -n "${TEST_FD-}" ]; then\n'
                   + cat + ' "/proc/self/fd/$TEST_FD" > "$TEST_ROOT/token"\nfi\n'
                   'printf "cargo stdout\\n"\nprintf "cargo stderr\\n" >&2\n'
                   'if [ -n "${TEST_SIGNAL-}" ]; then kill -"$TEST_SIGNAL" "$$"; fi\n'
                   'exit "${TEST_STATUS:-0}"\n')
        self.env = {"PATH": str(self.tools), "HOME": str(self.root), "LC_ALL": "C",
                    "TEST_ROOT": str(self.root), "RCH_RABS_PREPARE_TIMEOUT_MS": "1500"}
        self.marker = self.root / "unexpected-import"

    def poison(self, path, abort=True):
        path.parent.mkdir(parents=True, exist_ok=True)
        source = "open({!r}, 'a').write('imported\\n')\n".format(str(self.marker))
        if abort:
            source += "raise SystemExit(86)\n"
        path.write_text(source)

    def run(self, args=("check",), data=b"", pass_fds=()):
        process = subprocess.Popen(
            [SHELL, "-c", RUNNER, "rch-rabs-worker", ADAPTER.read_text(), "cargo", *args],
            cwd=self.project, env=self.env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=pass_fds,
        )
        try:
            out, err = process.communicate(data, timeout=6)
        except BaseException:
            process.kill()
            process.communicate(timeout=3)
            raise
        return process, out, err

    def environment(self):
        return dict(item.split(b"=", 1) for item in
                    (self.root / "environment").read_bytes().split(b"\0") if item)


@unittest.skipUnless(sys.platform == "linux", "worker-cache runtime is Linux-only")
class BootstrapIsolationTests(unittest.TestCase):
    def assert_cargo_once(self, fixture, result, status=0, prepared=True):
        process, out, err = result
        self.assertEqual(process.returncode, status, err)
        self.assertEqual(out, b"cargo stdout\n")
        self.assertTrue(err.endswith(b"cargo stderr\n"), err)
        self.assertEqual((fixture.root / "cargo.calls").read_text(), str(process.pid) + "\n")
        self.assertFalse(fixture.marker.exists(), "project/startup code executed before Cargo")
        self.assertEqual((fixture.root / "cwd").read_text(), str(fixture.project))
        environment = fixture.environment()
        if prepared:
            self.assertEqual(environment[b"RUSTC_WRAPPER"], b"/fixture/rabs-wrap")
            report = json.loads((fixture.root / "prepare.json").read_bytes())
            self.assertEqual(report["isolated"], 1)
            self.assertEqual(report["no_site"], 1)
            self.assertEqual(report["stdin"], "")
            self.assertNotIn("", report["path"])
            self.assertNotIn(str(fixture.project), report["path"])
        else:
            self.assertNotIn(b"RUSTC_WRAPPER", environment)
        return environment

    def test_project_modules_and_packages_cannot_replace_bootstrap_imports(self):
        for module in ("ast.py", "json.py", "selectors.py", "signal.py", "socket.py",
                       "shutil.py", "json/__init__.py"):
            with self.subTest(module=module):
                fixture = Fixture()
                fixture.poison(fixture.project / module)
                self.assert_cargo_once(fixture, fixture.run())

    def test_pythonpath_cannot_execute_sitecustomize_or_shadow_standard_library(self):
        for module in ("sitecustomize.py", "ast.py", "json/__init__.py"):
            for empty_component in (False, True):
                with self.subTest(module=module, empty_component=empty_component):
                    fixture = Fixture()
                    injected = fixture.root / "injected python path"
                    fixture.poison(injected / module)
                    fixture.env["PYTHONPATH"] = (":" if empty_component else "") + str(injected)
                    environment = self.assert_cargo_once(fixture, fixture.run())
                    self.assertEqual(environment[b"PYTHONPATH"], os.fsencode(fixture.env["PYTHONPATH"]))

    def test_invalid_python_startup_environment_is_preserved_only_for_the_workload(self):
        for key, value in (("PYTHONHOME", "/nonexistent/rch-python-home"),
                           ("PYTHONHASHSEED", "not-a-number")):
            with self.subTest(key=key):
                fixture = Fixture()
                fixture.env[key] = value
                environment = self.assert_cargo_once(fixture, fixture.run())
                self.assertEqual(environment[key.encode()], value.encode())

    def test_user_site_hooks_and_pth_code_are_not_startup_authority(self):
        for name in ("sitecustomize.py", "usercustomize.py", "bootstrap.pth"):
            with self.subTest(name=name):
                fixture = Fixture()
                base = fixture.root / "user-base"
                fixture.env["PYTHONUSERBASE"] = str(base)
                probe = subprocess.run([PYTHON, "-S", "-c",
                                        "import site; print(site.getusersitepackages())"],
                                       env=fixture.env, capture_output=True, timeout=3, check=True)
                site = Path(os.fsdecode(probe.stdout.strip()))
                site.mkdir(parents=True)
                if name.endswith(".pth"):
                    (site / name).write_text("import builtins; builtins.open({!r}, 'a').write('pth\\n')\n"
                                             .format(str(fixture.marker)))
                else:
                    fixture.poison(site / name, abort=False)
                environment = self.assert_cargo_once(fixture, fixture.run())
                self.assertEqual(environment[b"PYTHONUSERBASE"], os.fsencode(base))

    def test_isolation_preserves_arguments_stdin_environment_and_jobserver_descriptors(self):
        fixture = Fixture()
        fixture.poison(fixture.project / "ast.py")
        fixture.env.update({"PYTHONPATH": str(fixture.project), "RUSTUP_TOOLCHAIN": "pinned-nightly",
                            "RUSTFLAGS": "-C debuginfo=1", "CARGO_TARGET_DIR": "private target"})
        args = ("+nightly", "test", "--", "", "a'b ; $HOME", "line\nbreak", "日本語",
                os.fsdecode(b"opaque-\xff"))
        read, write = os.pipe()
        try:
            os.write(write, b"+")
        finally:
            os.close(write)
        fixture.env["TEST_FD"] = str(read)
        fixture.env["CARGO_MAKEFLAGS"] = "-j --jobserver-auth={},{}".format(read, read)
        try:
            environment = self.assert_cargo_once(fixture, fixture.run(args, b"input\x00\xff\n", (read,)))
        finally:
            os.close(read)
        self.assertEqual((fixture.root / "argv").read_bytes(),
                         b"".join(os.fsencode(arg) + b"\0" for arg in args))
        self.assertEqual((fixture.root / "stdin").read_bytes(), b"input\x00\xff\n")
        self.assertEqual((fixture.root / "token").read_bytes(), b"+")
        for key in ("PYTHONPATH", "RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_TARGET_DIR", "CARGO_MAKEFLAGS"):
            self.assertEqual(environment[key.encode()], os.fsencode(fixture.env[key]))

    def test_original_failure_and_signal_are_not_retried(self):
        for status, signum in ((101, None), (0, signal.SIGTERM), (0, signal.SIGPIPE)):
            with self.subTest(status=status, signum=signum):
                fixture = Fixture()
                fixture.env["TEST_STATUS"] = str(status)
                if signum is not None:
                    fixture.env["TEST_SIGNAL"] = str(signum)
                self.assert_cargo_once(fixture, fixture.run(), -signum if signum else status)

    def test_setup_refusal_or_bypass_preserves_stock_cargo_without_importing_project_code(self):
        for mode in ("error", "missing", "zero-budget", "recursive"):
            with self.subTest(mode=mode):
                fixture = Fixture()
                fixture.poison(fixture.project / "ast.py")
                if mode == "missing":
                    (fixture.tools / "cargo-rabs").rename(fixture.tools / "retained-launcher")
                elif mode == "zero-budget":
                    fixture.env["RCH_RABS_PREPARE_TIMEOUT_MS"] = "0"
                elif mode == "recursive":
                    fixture.env["RCH_RABS_WORKER_ACTIVE"] = "1"
                else:
                    fixture.env["TEST_PREPARE"] = mode
                self.assert_cargo_once(fixture, fixture.run(), prepared=False)

    def test_cancelled_preparation_never_starts_cargo(self):
        fixture = Fixture()
        fixture.poison(fixture.project / "ast.py")
        fixture.env["TEST_PREPARE"] = "cancel"
        process, out, _ = fixture.run()
        self.assertEqual(process.returncode, 130)
        self.assertEqual(out, b"")
        self.assertFalse((fixture.root / "cargo.calls").exists())
        self.assertFalse(fixture.marker.exists())

    def test_missing_python_and_other_platforms_keep_the_original_exec_path(self):
        for platform in ("missing-python", "Darwin", "MINGW64_NT-10.0"):
            with self.subTest(platform=platform):
                fixture = Fixture()
                fixture.poison(fixture.project / "ast.py")
                fixture.env["PYTHONHOME"] = "/nonexistent/rch-python-home"
                if platform == "missing-python":
                    (fixture.tools / "python3").rename(fixture.root / "retained-python3")
                else:
                    (fixture.tools / "uname").rename(fixture.root / "retained-uname")
                    executable(fixture.tools / "uname", "#!/bin/sh\nprintf '%s\\n' " +
                               shlex.quote(platform) + "\n")
                environment = self.assert_cargo_once(fixture, fixture.run(), prepared=False)
                self.assertEqual(environment[b"PYTHONHOME"], b"/nonexistent/rch-python-home")
                self.assertFalse((fixture.root / "prepare.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
