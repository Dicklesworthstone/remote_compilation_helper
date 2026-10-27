#!/usr/bin/env python3
"""Real local launcher/exec/filesystem tests with an explicit native-driver double.

The fixture records the exact retained profile and process handoff. It does not
implement Cargo, the namespace, unit-graph admission, the coordinator or a cache;
passing these tests is not native compiler-skip evidence.
"""

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


LAUNCHER = Path(__file__).resolve().parents[1] / "cargo-rabs"
loader = importlib.machinery.SourceFileLoader("cargo_rabs_local_test", str(LAUNCHER))
spec = importlib.util.spec_from_loader(loader.name, loader)
launcher = importlib.util.module_from_spec(spec)
loader.exec_module(launcher)

DRIVER = r'''
import json, os, pathlib, signal, stat, sys
assert len(sys.argv) == 3 and sys.argv[1] == "--canonical-compile-local", sys.argv
path = pathlib.Path(sys.argv[2])
profile = json.loads(path.read_bytes())
assert profile["version"] == "canonical-compile-local-v1"
assert profile["command"] in ("check", "build", "test")
assert "selection" in profile
record = {"pid":os.getpid(), "argv":sys.argv, "profile":profile,
          "retained":str(path), "file_mode":stat.S_IMODE(path.stat().st_mode),
          "directory_mode":stat.S_IMODE(path.parent.stat().st_mode),
          "cwd":os.getcwd(), "environment":dict(os.environ),
          "input":sys.stdin.buffer.read().hex()}
if os.environ.get("TEST_INHERITED_FD"):
    record["inherited"] = os.read(int(os.environ["TEST_INHERITED_FD"]), 1024).hex()
with open(os.environ["TEST_DRIVER_RECORD"], "a") as output:
    output.write(json.dumps(record) + "\n")
sys.stdout.buffer.write(b"fixture check stdout\x00\xff\n")
sys.stdout.buffer.flush()
sys.stderr.buffer.write(b"fixture check stderr\x00\xfe\n")
sys.stderr.buffer.flush()
if os.environ.get("TEST_SIGNAL"):
    os.kill(os.getpid(), signal.SIGTERM)
sys.exit(int(os.environ.get("TEST_EXIT", "0")))
'''


class CanonicalLocalCargo(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory(prefix="rabs-local-launcher-")
        self.addCleanup(self.owner.cleanup)
        self.root = Path(self.owner.name)
        self.source = self.root / "source 雪"
        self.tools = self.root / "tools"
        self.state = self.root / "state"
        self.operations = self.root / "operations"
        for directory in (self.source, self.tools / "bin", self.state, self.operations):
            directory.mkdir(parents=True, mode=0o700)
        self.forbidden = self.root / "unexpected-build"
        for name in ("cargo", "rustc", "rch"):
            tool = self.tools / "bin" / name
            tool.write_text("#!/bin/sh\nprintf unexpected >> '" + str(self.forbidden) + "'\nexit 98\n")
            tool.chmod(0o700)
        self.wrapper = self.root / "rabs-wrap"
        self.wrapper.write_text("#!/bin/sh\nexit 97\n")
        self.wrapper.chmod(0o700)
        self.driver = self.root / "rabsd"
        self.driver.write_text("#!" + sys.executable + " -S\n" + DRIVER)
        self.driver.chmod(0o700)
        self.record = self.root / "driver.ndjson"
        self.profile_path = self.root / "profile.json"
        self.profile = {
            "version": "canonical-compile-local-v1", "source_root": str(self.source),
            "toolchain_root": str(self.tools), "state_root": str(self.state),
            "operation_root": str(self.operations), "wrapper": str(self.wrapper),
            "manifest": "member/Cargo.toml", "jobs": 3, "timeout_seconds": 600,
        }
        self.env = {
            "PATH": os.defpath, "HOME": str(self.root), "LC_ALL": "C.UTF-8",
            "CARGO_RABS_DAEMON": str(self.driver),
            "CARGO": str(self.tools / "bin/cargo"), "CARGO_RABS_RCH": str(self.tools / "bin/rch"),
            "TEST_DRIVER_RECORD": str(self.record), "RABS_CONFIG": str(self.root / "policy.toml"),
            "AMBIENT_INPUT": "not copied into the native profile",
        }
        self.save()

    def save(self):
        self.profile_path.write_text(json.dumps(self.profile))

    def invoke(self, args=None, env=None, prefix=None, input=b"", pass_fds=()):
        if prefix is None:
            prefix = ["rabs", "--rabs-canonical-local", str(self.profile_path), "--"]
        command = [sys.executable, "-I", "-S", str(LAUNCHER)] + prefix + (args or [])
        child = subprocess.Popen(
            command, cwd=self.root, env=self.env if env is None else env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=pass_fds,
        )
        try:
            stdout, stderr = child.communicate(input, timeout=8)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
        self.assertFalse(self.forbidden.exists(), "launcher ran stock Cargo/rustc/RCH")
        return child.returncode, stdout, stderr, child.pid

    def records(self):
        return [json.loads(line) for line in self.record.read_text().splitlines()]

    def assert_refused(self, args=None, env=None, prefix=None):
        operations = list(self.operations.iterdir())
        count = len(self.records()) if self.record.exists() else 0
        status, stdout, stderr, _ = self.invoke(args, env, prefix)
        self.assertEqual(status, 2, stderr.decode(errors="replace"))
        self.assertEqual(stdout, b"")
        self.assertEqual(list(self.operations.iterdir()), operations)
        self.assertEqual(len(self.records()) if self.record.exists() else 0, count)

    def test_exec_handoff_preserves_pid_status_raw_streams_stdin_and_native_policy_environment(self):
        original = self.profile_path.read_bytes()
        env = dict(self.env, TEST_EXIT="37", RABS_RELEASE_AUTHORIZATION="required")
        status, stdout, stderr, pid = self.invoke(["check", "--workspace"], env, input=b"\x00\xffstdin")
        self.assertEqual(status, 37)
        self.assertEqual(stdout, b"fixture check stdout\x00\xff\n")
        self.assertIn(b"fixture check stderr\x00\xfe\n", stderr)
        record, = self.records()
        self.assertEqual(record["pid"], pid)
        self.assertEqual(record["input"], "00ff737464696e")
        self.assertEqual(record["cwd"], str(self.root))
        self.assertEqual(record["environment"], dict(env, CARGO_RABS_CANONICAL_ACTIVE="1"))
        expected = dict(self.profile, command="check", selection={"workspace": True})
        self.assertEqual(record["profile"], expected)
        self.assertEqual(record["argv"], [str(self.driver), "--canonical-compile-local", record["retained"]])
        retained = Path(record["retained"])
        self.assertEqual(retained.parent.parent, self.operations)
        self.assertEqual(record["file_mode"], 0o600)
        self.assertEqual(record["directory_mode"], 0o700)
        self.assertEqual(json.loads(retained.read_bytes()), expected)
        self.assertEqual(self.profile_path.read_bytes(), original)
        self.assertNotIn("env", record["profile"])
        self.assertNotIn("AMBIENT_INPUT", retained.read_text())

    def test_default_check_replaces_saved_selection_with_cargo_defaults(self):
        self.profile["command"] = "test"
        self.profile["selection"] = {
            "lib": True, "features": ["from-profile"], "no_run": True,
            "test_filter": "saved-filter", "test_args": ["--nocapture"],
        }
        self.save()
        for args in ([], ["check"]):
            status, _, stderr, _ = self.invoke(args)
            self.assertEqual(status, 0, stderr.decode(errors="replace"))
            self.assertEqual(self.records()[-1]["profile"]["command"], "check")
            self.assertEqual(self.records()[-1]["profile"]["selection"], {})
        self.assertEqual(len(list(self.operations.iterdir())), 2)
        self.assertNotEqual(self.records()[0]["retained"], self.records()[1]["retained"])

    def test_private_target_configuration_survives_exact_native_handoff(self):
        for cache in ({"runtime_epoch": "host-image-2026.10"},
                      {"runtime_epoch": "image_v2", "max_bytes": 1024 ** 3, "max_families": 8},
                      {"runtime_epoch": "single", "max_families": 1},
                      {"runtime_epoch": "a" * 256, "max_bytes": 8 * 1024 ** 3,
                       "max_families": 32}):
            with self.subTest(cache=cache):
                self.profile["target_cache"] = cache
                self.save()
                status, _, stderr, _ = self.invoke(["build", "--features=fast"])
                self.assertEqual(status, 0, stderr.decode(errors="replace"))
                retained = self.records()[-1]["profile"]
                self.assertEqual(retained["target_cache"], cache)
                self.assertEqual(retained["selection"], {"features": ["fast"]})

    def test_private_target_configuration_is_bounded_before_native_handoff(self):
        for cache in (True, "enabled", {}, {"runtime_epoch": ""},
                      {"runtime_epoch": "a" * 257}, {"runtime_epoch": "host/image"},
                      {"runtime_epoch": "host\nimage"}, {"runtime_epoch": "höst"},
                      {"runtime_epoch": None}, {"runtime_epoch": True},
                      {"runtime_epoch": "v1", "root": "/other"},
                      {"runtime_epoch": "v1", "max_bytes": True},
                      {"runtime_epoch": "v1", "max_bytes": 0},
                      {"runtime_epoch": "v1", "max_bytes": 8 * 1024 ** 3 + 1},
                      {"runtime_epoch": "v1", "max_bytes": "1024"},
                      {"runtime_epoch": "v1", "max_families": True},
                      {"runtime_epoch": "v1", "max_families": 0},
                      {"runtime_epoch": "v1", "max_families": 33},
                      {"runtime_epoch": "v1", "max_families": 2.5},
                      {"runtime_epoch": "v1", "max_families": "8"}):
            with self.subTest(cache=cache):
                self.profile["target_cache"] = cache
                self.save()
                self.assert_refused(["check"])

    def test_build_selectors_and_compile_only_harnesses_reach_the_native_driver_once(self):
        self.profile["command"] = "check"
        self.profile["selection"] = {"lib": True, "features": ["from-profile"]}
        self.save()
        original = self.profile_path.read_bytes()
        for args, expected in (
            (["build"], {}),
            (["build", "--workspace", "--tests", "--examples", "--target=host-tuple", "--profile=release"],
             {"workspace": True, "tests": True, "examples": True, "target": ["host-tuple"], "profile": "release"}),
            (["build", "--package=app", "--bin=server", "--features=app/fast", "--release"],
             {"packages": ["app"], "bin": ["server"], "features": ["app/fast"], "release": True}),
        ):
            with self.subTest(args=args):
                status, _, stderr, pid = self.invoke(args)
                self.assertEqual(status, 0, stderr.decode(errors="replace"))
                record = self.records()[-1]
                self.assertEqual(record["pid"], pid)
                self.assertEqual(record["profile"], dict(self.profile, command="build", selection=expected))
                self.assertEqual(record["argv"], [str(self.driver), "--canonical-compile-local", record["retained"]])
                self.assertTrue(Path(record["retained"]).parent.name.startswith("build-"))
                self.assertEqual(self.profile_path.read_bytes(), original)
        self.assertEqual(len(self.records()), 3)
        self.assertEqual(len(list(self.operations.iterdir())), 3)

    def test_test_selectors_filters_and_literal_harness_tail_reach_native_driver_once(self):
        self.profile["command"] = "build"
        self.profile["selection"] = {"lib": True, "features": ["from-profile"]}
        self.save()
        original = self.profile_path.read_bytes()
        cases = (
            (["test"], {}),
            (["test", "--workspace", "--no-run", "--test=roundtrip", "--target=host-tuple"],
             {"workspace": True, "no_run": True, "test": ["roundtrip"], "target": ["host-tuple"]}),
            (["test", "--package=core", "--doc", "--no-fail-fast", "smoke::雪", "--", "--nocapture", "--test-threads=1"],
             {"packages": ["core"], "doc": True, "no_fail_fast": True,
              "test_filter": "smoke::雪", "test_args": ["--nocapture", "--test-threads=1"]}),
            (["test", "selected test", "--lib", "--features=fast", "--", "--exact", "--ignored"],
             {"test_filter": "selected test", "lib": True, "features": ["fast"],
              "test_args": ["--exact", "--ignored"]}),
            (["test", "--", "--manifest-path=/not-cargo", "--unit-graph", "--config=not-cargo", ""],
             {"test_args": ["--manifest-path=/not-cargo", "--unit-graph", "--config=not-cargo", ""]}),
            (["test", "", "--"], {"test_filter": ""}),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                status, _, stderr, pid = self.invoke(args)
                self.assertEqual(status, 0, stderr.decode(errors="replace"))
                record = self.records()[-1]
                self.assertEqual(record["pid"], pid)
                self.assertEqual(record["profile"], dict(self.profile, command="test", selection=expected))
                self.assertEqual(record["argv"], [str(self.driver), "--canonical-compile-local", record["retained"]])
                self.assertTrue(Path(record["retained"]).parent.name.startswith("test-"))
                self.assertEqual(self.profile_path.read_bytes(), original)
        self.assertEqual(len(self.records()), len(cases))
        self.assertEqual(len(list(self.operations.iterdir())), len(cases))

    def test_saved_test_selection_is_validated_then_replaced_by_explicit_command(self):
        self.profile["command"] = "test"
        self.profile["selection"] = {
            "doc": True, "no_fail_fast": True, "packages": ["saved-package"],
            "test_filter": "saved-filter", "test_args": ["--nocapture"],
        }
        self.save()
        original = self.profile_path.read_bytes()
        for args, command, selection in (
            (["test", "--no-run", "--lib"], "test", {"no_run": True, "lib": True}),
            (["test", "--", "--list"], "test", {"test_args": ["--list"]}),
            (["build", "--tests"], "build", {"tests": True}),
        ):
            with self.subTest(args=args):
                status, _, stderr, _ = self.invoke(args)
                self.assertEqual(status, 0, stderr.decode(errors="replace"))
                record = self.records()[-1]
                self.assertEqual(record["profile"]["command"], command)
                self.assertEqual(record["profile"]["selection"], selection)
                self.assertEqual(self.profile_path.read_bytes(), original)
        self.profile["selection"] = {"test_filter": None, "test_args": [], "no_run": False}
        self.save()
        status, _, stderr, _ = self.invoke(["test"])
        self.assertEqual(status, 0, stderr.decode(errors="replace"))
        self.assertEqual(self.records()[-1]["profile"]["selection"], {})

    def test_named_packages_features_and_targets_reach_the_retained_native_profile(self):
        args = ["check", "--workspace", "--exclude=integration-*", "-p", "core@1.0.0",
                "-papp", "--package=third", "--features", "app/fast,core/serde",
                "-Fcore/std", "-F=extra", "--features=雪", "--no-default-features",
                "--all-features", "--lib", "--bins", "--tests", "--examples", "--benches",
                "--all-targets", "--bin", "server", "--bin=cli", "--test", "roundtrip",
                "--example=client", "--bench", "throughput", "--release"]
        status, _, stderr, _ = self.invoke(args)
        self.assertEqual(status, 0, stderr.decode(errors="replace"))
        selected = self.records()[0]["profile"]["selection"]
        self.assertEqual(selected, {
            "workspace": True, "exclude": ["integration-*"],
            "packages": ["core@1.0.0", "app", "third"],
            "features": ["app/fast,core/serde", "core/std", "extra", "雪"],
            "no_default_features": True, "all_features": True,
            "lib": True, "bins": True, "tests": True, "examples": True, "benches": True,
            "all_targets": True, "bin": ["server", "cli"], "test": ["roundtrip"],
            "example": ["client"], "bench": ["throughput"], "release": True,
        })
        self.assertEqual(self.records()[0]["profile"]["manifest"], "member/Cargo.toml")
        self.assertEqual(self.records()[0]["profile"]["jobs"], 3)

    def test_compilation_targets_and_named_profile_reach_the_retained_native_profile(self):
        args = ["check", "--package", "app", "--lib", "--target", "wasm32-unknown-unknown",
                "--target=aarch64-unknown-linux-gnu", "--target", "host-tuple",
                "--profile=check_fast", "--features", "app/portable"]
        status, _, stderr, _ = self.invoke(args)
        self.assertEqual(status, 0, stderr.decode(errors="replace"))
        self.assertEqual(self.records()[0]["profile"]["selection"], {
            "packages": ["app"], "lib": True,
            "target": ["wasm32-unknown-unknown", "aarch64-unknown-linux-gnu", "host-tuple"],
            "profile": "check_fast", "features": ["app/portable"],
        })
        status, _, stderr, _ = self.invoke(["check", "--target=host-tuple", "-r"])
        self.assertEqual(status, 0, stderr.decode(errors="replace"))
        self.assertEqual(self.records()[1]["profile"]["selection"], {
            "target": ["host-tuple"], "release": True,
        })
        for profile in ("dev", "release", "test", "bench", "check-fast"):
            self.assertEqual(launcher.canonical_local_selection(["check", "--profile", profile]),
                             {"profile": profile})

    def test_saved_targets_and_profile_are_validated_then_replaced_by_command_selection(self):
        self.profile["selection"] = {"target": ["wasm32-unknown-unknown"], "profile": "check-fast"}
        self.save()
        original = self.profile_path.read_bytes()
        status, _, stderr, _ = self.invoke(["check", "--target", "host-tuple", "--profile", "dev"])
        self.assertEqual(status, 0, stderr.decode(errors="replace"))
        self.assertEqual(self.records()[0]["profile"]["selection"], {
            "target": ["host-tuple"], "profile": "dev",
        })
        self.assertEqual(self.profile_path.read_bytes(), original)
        status, _, stderr, _ = self.invoke(["check"])
        self.assertEqual(status, 0, stderr.decode(errors="replace"))
        self.assertEqual(self.records()[1]["profile"]["selection"], {})
        self.profile["selection"] = {"target": [], "profile": None}
        self.save()
        status, _, stderr, _ = self.invoke(["check"])
        self.assertEqual(status, 0, stderr.decode(errors="replace"))
        self.assertEqual(self.records()[2]["profile"]["selection"], {})

    def test_signal_exit_and_inherited_file_descriptors_survive_exec(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"inherited\x00\xff")
            os.close(write_fd)
            write_fd = None
            env = dict(self.env, TEST_SIGNAL="1", TEST_INHERITED_FD=str(read_fd))
            status, _, _, pid = self.invoke(["check", "-r"], env, pass_fds=(read_fd,))
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
        self.assertEqual(status, -signal.SIGTERM)
        record, = self.records()
        self.assertEqual(record["pid"], pid)
        self.assertEqual(record["inherited"], "696e6865726974656400ff")
        self.assertEqual(record["profile"]["selection"], {"release": True})

    def test_commands_authority_options_and_missing_values_refuse_before_handoff(self):
        rejected = [
            ["run"], ["bench"], ["doc"], ["clippy"], ["+nightly", "check"],
            ["check", "--config", "build.rustc=other"], ["check", "--config=other"],
            ["check", "--target-dir=/other"], ["check", "--manifest-path", "other/Cargo.toml"],
            ["check", "--message-format=json"], ["check", "-Zunstable-options"],
            ["check", "--target=/tmp/custom.json"], ["check", "--profile=../custom"],
            ["check", "--jobs=2"], ["check", "--", "--help"],
            ["check", "--exclude", "unselected"], ["check", "--package"],
            ["check", "--features="], ["check", "--bin", "--lib"],
            ["check", "--tests=true"], ["check", "--features", "invalid\nvalue"],
            ["check", "--features", "invalid\u0085value"],
            ["check", "--rabs-no-start"], ["check", "--rabs-remote"],
        ]
        for args in rejected:
            with self.subTest(args=args):
                self.assert_refused(args)

    def test_build_cannot_override_native_authority_or_request_program_execution(self):
        for args in (
            ["build", "--config=other"], ["build", "--target-dir=/other"],
            ["build", "--manifest-path", "other/Cargo.toml"], ["build", "--message-format=json"],
            ["build", "--out-dir=/other"], ["build", "--artifact-dir=/other"],
            ["build", "--tests", "--", "--nocapture"], ["build", "test"],
            ["build", "--no-run"], ["build", "--run"], ["build", "-Zunstable-options"],
            ["build", "--profile=dev", "--release"], ["build", "--target=/tmp/custom.json"],
        ):
            with self.subTest(args=args):
                self.assert_refused(args)

    def test_test_controls_cannot_override_cargo_authority_or_change_other_commands(self):
        for args in (
            ["test", "--config=other"], ["test", "--target-dir=/other"],
            ["test", "--manifest-path", "other/Cargo.toml"], ["test", "--message-format=json"],
            ["test", "--out-dir=/other"], ["test", "--artifact-dir=/other"],
            ["test", "--jobs=2"], ["test", "-Zunstable-options"],
            ["test", "--unit-graph"], ["test", "--run"],
            ["test", "one-filter", "another-filter"], ["test", "--no-run=true"],
            ["test", "--doc=true"], ["test", "--no-fail-fast=false"],
            ["test", "--profile=dev", "--release"],
        ):
            with self.subTest(args=args):
                self.assert_refused(args)
        for command in ("check", "build"):
            for option in ("--doc", "--no-run", "--no-fail-fast"):
                with self.subTest(command=command, option=option):
                    self.assert_refused([command, option])
            self.assert_refused([command, "--", "--nocapture"])

    def test_test_filter_and_harness_values_share_native_bounds_and_reject_controls(self):
        exact = ["test", "--"] + ["--nocapture"] * 128
        self.assertEqual(len(launcher.canonical_local_selection(exact)["test_args"]), 128)
        self.assert_refused(exact + ["one-more"])
        self.assert_refused(["test", "filter", "--"] + ["--nocapture"] * 128)
        mixed = ["test", "--package=app", "filter", "--"] + ["--nocapture"] * 126
        self.assertEqual(len(launcher.canonical_local_selection(mixed)["test_args"]), 126)
        self.assert_refused(mixed + ["one-more"])
        for value in ("a" * 1025, "雪" * 342, "bad\nvalue", "bad\rvalue", "bad\u0085value"):
            with self.subTest(value=value):
                self.assert_refused(["test", value])
                self.assert_refused(["test", "--", value])
        for args in (["test", "bad\0filter"], ["test", "--", "bad\0argument"]):
            with self.subTest(args=args):
                with self.assertRaises(launcher.SetupError):
                    launcher.canonical_local_selection(args)
        self.assertEqual(launcher.canonical_local_selection(["test", "a" * 1024])["test_filter"], "a" * 1024)
        self.assertEqual(launcher.canonical_local_selection(["test", "--", "雪" * 341])["test_args"], ["雪" * 341])
        self.assert_refused(["test", "--"] + ["a" * 1024] * 16)
        near = ["test"] + [item for _ in range(15) for item in ("--features", "a" * 1000)]
        self.assertEqual(len(launcher.canonical_local_selection(near + ["--", "a" * 1000])["test_args"]), 1)
        self.assert_refused(near + ["filter", "--", "a" * 1000, "a" * 1000])

    def test_target_specs_profile_paths_conflicts_and_duplicate_profiles_refuse_before_handoff(self):
        for option in ("--target", "--profile"):
            for value in ("", "custom.json", "./custom", "/tmp/custom", "../custom",
                          "spec/custom", "C:\\spec\\target.json", "host tuple", "targét",
                          ".", "..", "_custom", "target=host", "--config=other"):
                with self.subTest(option=option, value=value):
                    self.assert_refused(["check", option + "=" + value])
        for args in (
            ["check", "--target"], ["check", "--profile"],
            ["check", "--profile=dev", "--release"],
            ["check", "-r", "--profile=dev"],
            ["check", "--profile=dev", "--profile=release"],
            ["check", "--profile=dev", "--profile=dev"],
        ):
            with self.subTest(args=args):
                self.assert_refused(args)

    def test_selection_limits_include_all_fields_utf8_bytes_and_option_bytes(self):
        exact = ["check"] + [item for _ in range(128) for item in ("-F", "a")]
        self.assertEqual(len(launcher.canonical_local_selection(exact)["features"]), 128)
        self.assert_refused(exact + ["--bin", "one-more"])
        self.assert_refused(["check", "--features", "雪" * 342])
        self.assert_refused(["check"] + [item for _ in range(16) for item in ("-F", "a" * 1024)])

    def test_compilation_targets_and_profile_share_native_value_and_byte_budgets(self):
        exact = ["check"] + [item for _ in range(128) for item in ("--target", "host-tuple")]
        self.assertEqual(len(launcher.canonical_local_selection(exact)["target"]), 128)
        self.assert_refused(exact + ["--profile", "dev"])
        profile = exact[:-2] + ["--profile", "dev"]
        self.assertEqual(len(launcher.canonical_local_selection(profile)["target"]), 127)
        self.assert_refused(profile + ["--features", "one-more"])
        for option in ("--target", "--profile"):
            with self.subTest(option=option):
                field = "target" if option == "--target" else "profile"
                expected = ["a" * 1024] if field == "target" else "a" * 1024
                self.assertEqual(launcher.canonical_local_selection(["check", option, "a" * 1024])[field], expected)
                self.assert_refused(["check", option, "a" * 1025])
        near = ["check"] + [item for _ in range(16) for item in ("--features", "a" * 1000)]
        self.assertEqual(len(launcher.canonical_local_selection(near)["features"]), 16)
        self.assert_refused(near + ["--profile", "a" * 1000])
        self.assert_refused(["check"] + [item for _ in range(16) for item in ("--target", "a" * 1024)])

    def test_strict_profile_refusals_never_create_retained_intent(self):
        original = dict(self.profile)
        for change in (
            {"version": "canonical-cargo-v1"}, {"version": "canonical-check-local-v1"},
            {"env": {"RABS_SOCKET_PATH": "/other"}},
            {"command": "run"}, {"command": "build --config=other"},
            {"command": None}, {"command": True}, {"command": ["build"]},
            {"command": {"build": True}}, {"command": "Build"},
            {"jobs": True}, {"timeout_seconds": 7201}, {"manifest": "../Cargo.toml"},
            {"manifest": "Cargo.lock"}, {"selection": {"args": ["build"]}},
            {"selection": {"lib": "true"}}, {"selection": {"features": "feature"}},
            {"selection": {"features": ["--config=other"]}},
            {"selection": {"exclude": ["package"]}},
            {"selection": {"target": "host-tuple"}},
            {"selection": {"target": None}}, {"selection": {"target": [True]}},
            {"selection": {"target": ["/tmp/custom.json"]}},
            {"selection": {"profile": ["dev"]}}, {"selection": {"profile": True}},
            {"selection": {"profile": {"inherits": "release"}}},
            {"selection": {"profile": "custom.json"}},
            {"selection": {"profile": "dev", "release": True}},
            {"vendor": "vendor", "cargo_home_source": str(self.root)},
        ):
            with self.subTest(change=change):
                self.profile = dict(original, **change)
                self.save()
                self.assert_refused(["check"])
        self.profile = original
        self.save()
        self.profile_path.write_text(self.profile_path.read_text()[:-1] + ',"version":"canonical-compile-local-v1"}')
        self.assert_refused(["check"])

    def test_invalid_saved_test_fields_refuse_before_retaining_native_intent(self):
        original = dict(self.profile)
        for selection in (
            {"doc": "true"}, {"no_run": 1}, {"no_fail_fast": None},
            {"test_filter": ["filter"]}, {"test_filter": True},
            {"test_filter": "invalid\nfilter"}, {"test_filter": "bad\0filter"},
            {"test_args": "--nocapture"}, {"test_args": None}, {"test_args": [True]},
            {"test_args": ["bad\u0085argument"]}, {"test_args": ["bad\0argument"]},
            {"test_args": ["a" * 1025]}, {"test_args": ["--nocapture"] * 129},
            {"test_filter": "filter", "test_args": ["--nocapture"] * 128},
            {"runtime_args": ["--nocapture"]},
        ):
            with self.subTest(selection=selection):
                self.profile = dict(original, command="test", selection=selection)
                self.save()
                self.assert_refused(["test"])
        for command in ("check", "build"):
            for selection in ({"doc": True}, {"no_run": True}, {"no_fail_fast": True},
                              {"test_filter": "filter"}, {"test_args": ["--nocapture"]}):
                with self.subTest(command=command, selection=selection):
                    self.profile = dict(original, command=command, selection=selection)
                    self.save()
                    self.assert_refused(["test"])

    def test_unsafe_storage_overlap_and_symlink_profiles_refuse_before_writes(self):
        self.operations.chmod(0o755)
        self.assert_refused(["check"])
        self.operations.chmod(0o700)
        self.profile["operation_root"] = str(self.source)
        self.save()
        self.assert_refused(["check"])
        self.assertEqual(list(self.source.iterdir()), [])
        self.profile["operation_root"] = str(self.operations)
        self.save()
        alias = self.root / "profile-alias.json"
        alias.symlink_to(self.profile_path)
        self.assert_refused(["check"], prefix=["--rabs-canonical-local", str(alias), "--"])

    def test_mode_mixing_nested_execution_and_root_admission_refuse(self):
        for leading in ("--rabs-remote", "--rabs-no-start", "--rabs-require-daemon"):
            self.assert_refused(prefix=["rabs", leading, "--rabs-canonical-local", str(self.profile_path)])
        for flag in ("CARGO_RABS_CANONICAL_ACTIVE", "CARGO_RABS_REMOTE_ACTIVE", "RCH_RABS_WORKER_ACTIVE"):
            self.assert_refused(["check"], dict(self.env, **{flag: "1"}))
        self.assert_refused(["check"], dict(self.env, CARGO_RABS_ROOT_CAPACITY="4"))
        with patch.object(launcher.sys, "platform", "darwin"):
            with self.assertRaises(launcher.SetupError):
                launcher.canonical_local_invocation(str(self.profile_path), ["check"], self.env)

    def test_native_failure_is_returned_once_without_fallback(self):
        for command in ("check", "build", "test"):
            status, _, stderr, _ = self.invoke([command], dict(self.env, TEST_EXIT="101"))
            self.assertEqual(status, 101, stderr.decode(errors="replace"))
        self.assertEqual(len(self.records()), 3)
        self.assertEqual(len(list(self.operations.iterdir())), 3)
        self.assertEqual([record["profile"]["command"] for record in self.records()], ["check", "build", "test"])

    def test_missing_driver_and_recursive_driver_refuse_before_creating_intent(self):
        self.assert_refused(["check"], dict(self.env, CARGO_RABS_DAEMON=str(self.root / "missing")))
        self.assert_refused(["check"], dict(self.env, CARGO_RABS_DAEMON=str(LAUNCHER)))

    def test_exec_failure_retains_selected_intent_without_running_another_executor(self):
        self.driver.write_text("#!/nonexistent-rabs-fixture-interpreter\n")
        status, stdout, stderr, _ = self.invoke(["check", "--bin", "selected"])
        self.assertEqual(status, 127, stderr.decode(errors="replace"))
        self.assertEqual(stdout, b"")
        self.assertFalse(self.record.exists())
        operation, = self.operations.iterdir()
        retained = json.loads((operation / "profile.json").read_bytes())
        self.assertEqual(retained["selection"], {"bin": ["selected"]})
        self.assertIn(b"cannot execute local canonical driver", stderr)

    def test_help_describes_local_mode_without_starting_anything(self):
        status, stdout, _, _ = self.invoke(prefix=["rabs", "--help"])
        self.assertEqual(status, 0)
        self.assertIn(b"--rabs-canonical-local", stdout)
        self.assertIn(b"canonical-compile-local-v1", stdout)
        self.assertIn(b"build --tests", stdout)
        self.assertIn(b"test --no-run", stdout)
        self.assertIn(b"Test results are never cached", stdout)
        self.assertFalse(self.record.exists())
        self.assertEqual(list(self.operations.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
