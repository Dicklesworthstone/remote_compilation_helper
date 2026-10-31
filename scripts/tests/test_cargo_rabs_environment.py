#!/usr/bin/env python3
"""Real launcher/exec/filesystem regressions; rabsd is an executable fixture.

These tests verify preparation intent, not native Cargo, TLS or cache serving.
The fixture records the unchanged driver environment separately from the saved
worker environment. No compiler or worker is started by this suite.
"""
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
import unittest

LAUNCHER = Path(__file__).resolve().parents[1] / "cargo-rabs"
loader = importlib.machinery.SourceFileLoader("cargo_rabs_env_test", str(LAUNCHER))
spec = importlib.util.spec_from_loader(loader.name, loader)
launcher = importlib.util.module_from_spec(spec)
loader.exec_module(launcher)

DRIVER = r'''
import json, os, pathlib, signal, sys
args = sys.argv[1:]
if "--prepare-from" in args:
    at = args.index("--prepare-from")
    request_path = pathlib.Path(args[at + 2])
    request = json.loads(request_path.read_text())
    operation = request_path.parent
else:
    assert args[:3] == ["--worker-build-tls", "--replay-diagnostics", "--resume"], args
    request_path = pathlib.Path(args[-3]) / "request.json"
    request = json.loads(request_path.read_text())
    operation = request_path.parent.parent
record = {"pid":os.getpid(), "args":args, "request":request, "operation":str(operation),
          "local_environment":dict(os.environ), "input":sys.stdin.buffer.read().hex()}
with open(os.environ["TEST_RECORD"], "a") as output:
    output.write(json.dumps(record) + "\n")
print("fixture-driver", flush=True)
if os.environ.get("TEST_SIGNAL"):
    os.kill(os.getpid(), signal.SIGTERM)
sys.exit(int(os.environ.get("TEST_EXIT", "0")))
'''


class CanonicalEnvironment(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory(prefix="rabs-env-")
        self.addCleanup(self.owner.cleanup)
        self.root = Path(self.owner.name)
        self.source = self.root / "source"
        self.tools = self.root / "tools"
        self.operations = self.root / "operations"
        for path in (self.source, self.tools / "bin", self.operations):
            path.mkdir(parents=True, mode=0o700)
        self.operations.chmod(0o700)
        (self.source / "Cargo.toml").write_text('[package]\nname="fixture"\nversion="0.1.0"\n')
        self.forbidden = self.root / "local-build-started"
        for name in ("cargo", "rustc", "cargo-clippy", "clippy-driver", "rch"):
            tool = self.tools / "bin" / name
            tool.write_text("#!/bin/sh\nprintf forbidden >> '" + str(self.forbidden) + "'\nexit 98\n")
            tool.chmod(0o700)
        self.driver = self.root / "rabsd"
        self.driver.write_text("#!" + sys.executable + " -S\n" + DRIVER)
        self.driver.chmod(0o700)
        self.record = self.root / "record.ndjson"
        self.profile = {
            "version":"canonical-cargo-v1", "listen":"127.0.0.1:45123", "worker":"worker-env",
            "worker_spki_sha256":"ab" * 32, "source_root":str(self.source),
            "toolchain_root":str(self.tools), "operation_root":str(self.operations),
        }
        self.profile_path = self.root / "profile.json"
        self.env = {
            "PATH":os.defpath, "HOME":str(self.root), "CARGO_RABS_DAEMON":str(self.driver),
            "CARGO":str(self.tools / "bin/cargo"), "CARGO_RABS_RCH":str(self.tools / "bin/rch"),
            "TEST_RECORD":str(self.record), "AMBIENT_SECRET":"not-an-input",
            "APP_VERSION":"dispatcher-only", "RABS_COORD_TLS_KEY":"/private/local-tls-key",
        }

    def save(self):
        self.profile_path.write_text(json.dumps(self.profile))

    def daemon_profile(self):
        endpoint = self.root / "daemon.sock"
        channel = socket.socket(socket.AF_UNIX)
        self.addCleanup(channel.close)
        channel.bind(str(endpoint))
        endpoint.chmod(0o600)
        self.profile["daemon_socket"] = str(endpoint)

    def run_launcher(self, args, env=None):
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", str(LAUNCHER)] + args,
            env=self.env if env is None else env, cwd=self.root,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = child.communicate(b"\x00\xffinput", timeout=8)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
        self.assertFalse(self.forbidden.exists(), "launcher executed a local build tool")
        return child.returncode, stdout, stderr, child.pid

    def invoke(self, args=None, env=None):
        self.save()
        return self.run_launcher(
            ["rabs", "--rabs-canonical", str(self.profile_path), "--"] + (args or ["build"]), env)

    def records(self):
        return [json.loads(line) for line in self.record.read_text().splitlines()]

    def assert_refused(self, args=None):
        count = len(self.records()) if self.record.exists() else 0
        retained = list(self.operations.iterdir())
        status, stdout, stderr, _ = self.invoke(args)
        self.assertEqual(status, 2, stderr.decode(errors="replace"))
        self.assertEqual(stdout, b"")
        self.assertEqual(len(self.records()) if self.record.exists() else 0, count)
        self.assertEqual(list(self.operations.iterdir()), retained)
        return stderr

    def test_literal_application_inputs_reach_every_command_and_both_dispatch_modes(self):
        values = {"APP_VERSION":"v1 '雪' $(touch never)", "EMPTY":"", "MULTILINE":"a\nb\t",
                  "SOURCE_DATE_EPOCH":"1700000000", "RUST_BACKTRACE":"1",
                  "GIT_COMMIT":"abcdef123456"}
        self.profile["env"] = values
        for daemon in (False, True):
            if daemon:
                self.daemon_profile()
            for args in (["build", "--workspace"], ["check", "--lib"],
                         ["test", "--no-run"], ["test", "chosen", "--", "--nocapture"],
                         ["clippy", "--workspace", "--", "-D", "warnings"]):
                with self.subTest(daemon=daemon, args=args):
                    status, stdout, stderr, pid = self.invoke(args, dict(self.env, TEST_EXIT="37"))
                    self.assertEqual(status, 37, stderr.decode(errors="replace"))
                    record = self.records()[-1]
                    self.assertEqual(record["pid"], pid)
                    self.assertEqual(record["input"], "00ff696e707574")
                    self.assertEqual(stdout, b"fixture-driver\n")
                    expected = dict(values, CARGO_INCREMENTAL="0")
                    if args[0] == "clippy":
                        expected.update(CARGO="/__rabs/toolchain/bin/cargo", RUSTC="/__rabs/toolchain/bin/rustc")
                    self.assertEqual(record["request"]["command_context"]["env"], expected)
                    self.assertEqual(record["request"]["request_id"], "allocate")
                    self.assertEqual(record["args"][0], "--job-build" if daemon else "--worker-build-tls")
                    metadata = json.loads((Path(record["operation"]) / "operation.json").read_text())
                    self.assertFalse(metadata["automatic_retry"])
                    self.assertFalse(metadata["publication_authorized"])
                    self.assertNotIn("env", metadata)
                    self.assertFalse((self.root / "never").exists())

    def test_worker_values_never_reconfigure_local_driver_or_inherit_ambient_values(self):
        self.profile["env"] = {"APP_VERSION":"worker-only", "NEW_INPUT":"worker-new"}
        status, _, stderr, _ = self.invoke()
        self.assertEqual(status, 0, stderr.decode(errors="replace"))
        record = self.records()[0]
        local = record["local_environment"]
        self.assertEqual(local["APP_VERSION"], "dispatcher-only")
        self.assertNotIn("NEW_INPUT", local)
        self.assertEqual(local["RABS_COORD_TLS_KEY"], self.env["RABS_COORD_TLS_KEY"])
        self.assertEqual(local["CARGO"], str(self.tools / "bin/cargo"))
        self.assertEqual(local["RUSTC"], str(self.tools / "bin/rustc"))
        self.assertNotIn("AMBIENT_SECRET", record["request"]["command_context"]["env"])
        self.assertNotIn("not-an-input", json.dumps(record["request"]))
        self.assertNotIn("local-tls-key", json.dumps(record["request"]))
        self.assertEqual(self.profile["env"], {"APP_VERSION":"worker-only", "NEW_INPUT":"worker-new"})

    def test_omission_empty_value_and_changed_value_have_distinct_saved_contexts(self):
        contexts = []
        for values in ({}, {"APP_VERSION":""}, {"APP_VERSION":"one"}, {"APP_VERSION":"two"}):
            self.profile["env"] = values
            self.assertEqual(self.invoke()[0], 0)
            contexts.append(self.records()[-1]["request"]["command_context"])
        self.assertEqual(len({json.dumps(value, sort_keys=True) for value in contexts}), 4)
        self.assertNotIn("APP_VERSION", contexts[0]["env"])
        self.assertEqual(contexts[1]["env"]["APP_VERSION"], "")

    def test_defaults_and_empty_environment_keep_original_compiler_bindings(self):
        for supplied in (False, True):
            if supplied:
                self.profile["env"] = {}
            for command in ("build", "check", "clippy", "test", "run", "bench"):
                self.assertEqual(self.invoke([command])[0], 0)
                expected = {"CARGO_INCREMENTAL":"0"}
                if command == "clippy":
                    expected.update(CARGO="/__rabs/toolchain/bin/cargo", RUSTC="/__rabs/toolchain/bin/rustc")
                self.assertEqual(self.records()[-1]["request"]["command_context"]["env"], expected)

    def test_profile_order_does_not_change_saved_specification_bytes(self):
        saved = []
        for values in ({"Z_INPUT":"last", "A_INPUT":"first"}, {"A_INPUT":"first", "Z_INPUT":"last"}):
            self.profile["env"] = values
            self.assertEqual(self.invoke()[0], 0)
            saved.append((Path(self.records()[-1]["operation"]) / "spec.json").read_bytes())
        self.assertEqual(saved[0], saved[1])

    def test_incremental_policy_is_explicit_request_state_and_never_an_environment_override(self):
        self.profile["incremental"] = True
        self.profile["env"] = {"APP_VERSION":"worker-only"}
        for ambient in ("0", "1"):
            with self.subTest(ambient=ambient):
                status, _, stderr, _ = self.invoke(env=dict(self.env, CARGO_INCREMENTAL=ambient))
                self.assertEqual(status, 0, stderr.decode(errors="replace"))
                record = self.records()[-1]
                self.assertEqual(record["local_environment"]["CARGO_INCREMENTAL"], ambient)
                self.assertEqual(record["request"]["command_context"]["env"], {
                    "APP_VERSION":"worker-only", "CARGO_INCREMENTAL":"1",
                })
                self.assertEqual(record["request"]["artifacts"]["cargo"], "cargo-private-incremental-json-v1")
        for value in ("0", "1", ""):
            with self.subTest(value=value):
                self.profile["env"] = {"CARGO_INCREMENTAL":value}
                self.assert_refused()

    def test_invalid_objects_names_and_values_refuse_before_operation_creation(self):
        bad = [None, False, 1, [], "A=B", {"": "v"}, {"1BAD":"v"}, {"BAD-NAME":"v"},
               {"A=B":"v"}, {"雪":"v"}, {"A" * 257:"v"}, {"A\0":"v"}, {"A\n":"v"},
               {"A":None}, {"A":True}, {"A":17}, {"A":[]}, {"A":{}}, {"A":"x\0y"}, {"A":"\udcff"}]
        for value in bad:
            with self.subTest(value=repr(value)):
                self.profile["env"] = value
                self.assert_refused()

    def test_worker_toolchain_jobserver_loader_and_coordination_controls_are_reserved(self):
        names = (
            "PATH", "HOME", "CARGO_HOME", "TMPDIR", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN",
            "LANG", "LC_ALL", "TZ", "MAKEFLAGS", "CARGO_MAKEFLAGS", "MFLAGS", "NUM_JOBS",
            "CARGO", "RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS", "GLIBC_TUNABLES",
            "CARGO_INCREMENTAL", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_TARGET_DIR", "CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_NET_OFFLINE",
            "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "RUSTDOC_LOG",
            "CLIPPY_ARGS", "CLIPPY_CONF_DIR", "RABS_STATE_DIR", "RABS_COORD_TLS_KEY",
            "RCH_REQUIRE_REMOTE", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
        )
        for name in names:
            with self.subTest(name=name):
                self.profile["env"] = {name:"sensitive-value-that-must-not-appear"}
                stderr = self.assert_refused()
                self.assertNotIn(b"sensitive-value-that-must-not-appear", stderr)

    def test_duplicate_environment_names_and_duplicate_env_objects_are_rejected(self):
        self.save()
        original = self.profile_path.read_text()
        for fragment in ('"env":{"A":"first","A":"second"},', '"env":{},"env":{"A":"v"},'):
            self.profile_path.write_text(original.replace("{", "{" + fragment, 1))
            status, stdout, _, _ = self.run_launcher(["--rabs-canonical", str(self.profile_path), "build"])
            self.assertEqual(status, 2)
            self.assertEqual(stdout, b"")
            self.assertFalse(self.record.exists())
            self.assertEqual(list(self.operations.iterdir()), [])

    def test_native_entry_limits_include_injected_toolchain_controls(self):
        for command, allowance in (("build", 255), ("clippy", 253)):
            self.profile["env"] = {"INPUT_" + str(at):"" for at in range(allowance)}
            self.assertEqual(self.invoke([command])[0], 0)
            self.assertEqual(len(self.records()[-1]["request"]["command_context"]["env"]), 256)
            self.profile["env"]["ONE_TOO_MANY"] = ""
            self.assert_refused([command])

    def test_utf8_value_and_total_budgets_match_native_limits(self):
        environment = launcher.canonical_command_environment({"A":"é" * 32768})
        self.assertEqual(len(environment["A"].encode("utf-8")), 65536)
        for values in ({"A":"é" * 32769}, {"A":"x" * 65536, "B":"y" * 65536}):
            with self.assertRaises(launcher.SetupError):
                launcher.canonical_command_environment(values)
        name = "A" * 256
        self.assertEqual(launcher.canonical_command_environment({name:"ok"})[name], "ok")

    def test_escaped_full_request_bound_is_checked_before_persisting_intent(self):
        # Values fit the native UTF-8 budget, but ensure_ascii JSON is larger.
        self.profile["env"] = {"APP":"雪" * 11000}
        self.assert_refused()
        # The profile fits; adding an independently bounded Cargo argument
        # makes the combined saved specification exceed the frame limit.
        self.profile["env"] = {"APP":"x" * 64000}
        self.assert_refused(["build", "--features=" + "a" * 2000])

    def test_environment_is_retained_privately_and_a_later_profile_cannot_mutate_it(self):
        self.profile["env"] = {"APP_VERSION":"first"}
        self.assertEqual(self.invoke()[0], 0)
        operation = Path(self.records()[0]["operation"])
        original = (operation / "spec.json").read_bytes()
        self.profile["env"]["APP_VERSION"] = "second"
        self.assertEqual(self.invoke()[0], 0)
        self.assertEqual((operation / "spec.json").read_bytes(), original)
        self.assertEqual(stat.S_IMODE(operation.stat().st_mode), 0o700)
        for path in operation.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_native_failures_and_signals_keep_exec_once_without_local_fallback(self):
        self.profile["env"] = {"APP_VERSION":"failure-input"}
        for status in (1, 2, 101, 125):
            self.assertEqual(self.invoke(env=dict(self.env, TEST_EXIT=str(status)))[0], status)
        status, _, _, _ = self.invoke(env=dict(self.env, TEST_SIGNAL="1"))
        self.assertEqual(status, -signal.SIGTERM)
        self.assertEqual(len(self.records()), 5)

    def test_recovery_keeps_prepared_environment_without_reading_changed_profile(self):
        self.profile["env"] = {"APP_VERSION":"original", "EMPTY":""}
        self.assertEqual(self.invoke()[0], 0)
        record = self.records()[0]
        operation = Path(record["operation"])
        bundle = operation / "bundle"
        bundle.mkdir(mode=0o700)
        # Explicit stand-in for a native prepared request; no allocation is claimed.
        prepared = dict(record["request"], request_id=7)
        request_path = bundle / "request.json"
        request_path.write_text(json.dumps(prepared))
        original = request_path.read_bytes()
        self.profile_path.write_text("not a valid profile anymore")
        status, _, stderr, _ = self.run_launcher(["--rabs-recover", str(operation)])
        self.assertEqual(status, 0, stderr.decode(errors="replace"))
        recovered = self.records()[-1]
        self.assertEqual(recovered["request"], prepared)
        self.assertEqual(request_path.read_bytes(), original)
        self.assertIn("--resume", recovered["args"])
        self.assertNotIn("--prepare-from", recovered["args"])
        self.assertEqual(len(self.records()), 2)


if __name__ == "__main__":
    unittest.main()
