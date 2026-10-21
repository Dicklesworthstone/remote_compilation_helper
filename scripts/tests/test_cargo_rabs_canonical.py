#!/usr/bin/env python3
"""Execute the real installed launcher contract with an explicit native-driver double.

No Rust compilation, TLS worker, canonical sandbox or Cargo cache hit is claimed.
The process/exec, filesystem, strict JSON, argv and no-fallback paths are real.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "scripts/cargo-rabs"
loader = importlib.machinery.SourceFileLoader("cargo_rabs_canonical_test", str(LAUNCHER))
spec = importlib.util.spec_from_loader(loader.name, loader)
launcher = importlib.util.module_from_spec(spec)
loader.exec_module(launcher)

DRIVER = r'''
import json, os, pathlib, signal, sys
args = sys.argv[1:]
assert args[0:3] == ["--worker-build-tls", "--replay-diagnostics", "--prepare-from"], args
source, specification, address, worker, pin, bundle, delivery, output = args[3:]
request = json.loads(pathlib.Path(specification).read_text())
operation = pathlib.Path(specification).parent
assert not pathlib.Path(bundle).exists()
assert not pathlib.Path(delivery).exists()
assert not pathlib.Path(output).exists()
assert request["artifacts"]["tree"] == "tree-files-v1"
cargo_args = request["args"][:request["args"].index("--")] if "--" in request["args"] else request["args"]
test_execution = cargo_args[0] == "test" and "--no-run" not in cargo_args
clippy = cargo_args[0] == "clippy"
assert request["program"] == ("/__rabs/toolchain/bin/cargo-clippy" if clippy else "/__rabs/toolchain/bin/cargo")
if clippy:
    assert request["command_context"]["env"]["CARGO"] == "/__rabs/toolchain/bin/cargo"
    assert request["command_context"]["env"]["RUSTC"] == "/__rabs/toolchain/bin/rustc"
assert request["artifacts"]["cargo"] == ("cargo-test-json-v1" if test_execution else "cargo-json-v1")
assert cargo_args.count("--message-format=json") == 1
assert request["toolchain_source"] + "/bin/cargo" == os.environ["CARGO"]
assert request["toolchain_source"] + "/bin/rustc" == os.environ["RUSTC"]
record = {"pid":os.getpid(), "argv":sys.argv, "request":request,
          "cwd":os.getcwd(), "tls":os.environ.get("RABS_COORD_TLS_KEY"),
          "operation":str(operation), "input":sys.stdin.buffer.read().hex()}
fd = os.environ.get("TEST_INHERITED_FD")
if fd:
    record["inherited"] = os.read(int(fd), 1024).hex()
with open(os.environ["TEST_DRIVER_RECORD"], "a") as result:
    result.write(json.dumps(record) + "\n")
print("native-driver-diagnostic", file=sys.stderr, flush=True)
sys.stdout.buffer.write(b"fixture Cargo stdout\x00\xff\n")
sys.stdout.buffer.flush()
print(json.dumps({"kind":"fixture-worker-build", "pid":os.getpid()}), file=sys.stderr, flush=True)
if os.environ.get("TEST_SIGNAL"):
    os.kill(os.getpid(), signal.SIGTERM)
sys.exit(int(os.environ.get("TEST_EXIT", "0")))
'''


class CanonicalCargo(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rabs-canonical-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "approved source 雪"
        self.toolchain = self.root / "compiler"
        self.operations = self.root / "operations"
        for directory in (self.source, self.toolchain / "bin", self.operations):
            directory.mkdir(parents=True, mode=0o700)
        os.chmod(self.operations, 0o700)
        (self.source / "Cargo.toml").write_text('[package]\nname="hello"\nversion="0.1.0"\n')
        self.forbidden = self.root / "forbidden"
        self.driver = self.root / "rabsd"
        self.driver.write_text("#!" + sys.executable + " -S\n" + DRIVER)
        self.driver.chmod(0o700)
        for name in ("cargo", "rustc", "rch"):
            tool = self.toolchain / "bin" / name
            tool.write_text("#!/bin/sh\nprintf unexpected >> '" + str(self.forbidden) + "'\nexit 98\n")
            tool.chmod(0o700)
        self.profile = {
            "version":"canonical-cargo-v1", "listen":"127.0.0.1:45123", "worker":"worker-a",
            "worker_spki_sha256":"ab" * 32, "source_root":str(self.source),
            "toolchain_root":str(self.toolchain), "operation_root":str(self.operations),
        }
        self.profile_path = self.root / "profile.json"
        self.record = self.root / "driver.ndjson"
        self.env = {"PATH":os.defpath, "HOME":str(self.root),
                    "CARGO_RABS_DAEMON":str(self.driver),
                    "CARGO":str(self.toolchain / "bin/cargo"),
                    "CARGO_RABS_RCH":str(self.toolchain / "bin/rch"),
                    "TEST_DRIVER_RECORD":str(self.record)}
        self.save()

    def save(self):
        self.profile_path.write_text(json.dumps(self.profile))

    def install_clippy(self):
        for name in ("cargo-clippy", "clippy-driver"):
            tool = self.toolchain / "bin" / name
            tool.write_text("#!/bin/sh\nprintf unexpected >> '" + str(self.forbidden) + "'\nexit 98\n")
            tool.chmod(0o700)

    def invoke(self, cargo_args=None, env=None, prefix=None, input=b""):
        args = cargo_args if cargo_args is not None else ["build", "--bin", "hello"]
        prefix = prefix if prefix is not None else ["rabs", "--rabs-canonical", str(self.profile_path), "--"]
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", str(LAUNCHER)] + prefix + args, env=env or self.env,
            cwd=self.root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
        status, stdout, _, _ = self.invoke(args, env, prefix)
        self.assertEqual(status, 2)
        self.assertEqual(stdout, b"")
        self.assertFalse(self.record.exists())
        self.assertEqual(list(self.operations.iterdir()), [])

    def test_exec_handoff_keeps_pid_input_exit_status_and_native_output(self):
        env = dict(self.env, TEST_EXIT="37", RABS_COORD_TLS_KEY="/private/never-upload-key")
        status, stdout, stderr, pid = self.invoke(env=env, input=b"\x00\xffstdin")
        self.assertEqual(status, 37)
        record, = self.records()
        self.assertEqual(record["pid"], pid)
        self.assertEqual(record["input"], "00ff737464696e")
        self.assertEqual(record["cwd"], str(self.root))
        self.assertEqual(record["tls"], env["RABS_COORD_TLS_KEY"])
        self.assertNotIn(env["RABS_COORD_TLS_KEY"], json.dumps(record["request"]))
        self.assertEqual(stdout, b"fixture Cargo stdout\x00\xff\n")
        self.assertIn(b'"kind": "fixture-worker-build"', stderr)
        self.assertIn(b"native-driver-diagnostic", stderr)
        self.assertEqual(record["request"]["command_context"]["env"], {"CARGO_INCREMENTAL":"0"})
        self.assertEqual(record["request"]["artifacts"]["files"], [])
        self.assertEqual(record["request"]["artifacts"]["cargo"], "cargo-json-v1")

    def test_binary_release_target_and_feature_intent_is_exact_without_guessing_paths(self):
        args = ["build", "--release", "--bin=one", "--bin", "two", "-p", "app",
                "--target=aarch64-unknown-linux-gnu", "--features", "feature,quoted'雪",
                "--no-default-features", "--color=never", "-vv"]
        self.assertEqual(self.invoke(args)[0], 0)
        request = self.records()[0]["request"]
        self.assertEqual(request["args"][:len(args)], args)
        self.assertEqual(request["args"][len(args):], ["--locked", "--offline", "--message-format=json", "--manifest-path",
            "/__rabs/workspace/Cargo.toml", "--target-dir", "/__rabs/out/cargo"])
        self.assertEqual(request["artifacts"]["files"], [])
        self.assertEqual(request["artifacts"]["cargo"], "cargo-json-v1")

    def test_member_and_explicit_vendor_go_to_shared_source_planner(self):
        self.profile.update(manifest="members/app/Cargo.toml", vendor="third_party/vendor")
        self.save()
        self.assertEqual(self.invoke()[0], 0)
        request = self.records()[0]["request"]
        self.assertEqual(request["cargo_source"], {"manifest":"members/app/Cargo.toml", "vendor":"third_party/vendor"})
        self.assertEqual(request["command_context"]["cwd"], "/__rabs/workspace/members/app")
        self.assertNotIn("source_manifest", request, "launcher must not fabricate input evidence")
        self.assertNotIn("toolchain_identity", request, "native capture owns the identity")

    def test_explicit_registry_cache_is_native_preparation_intent(self):
        cargo_home = self.root / "approved Cargo home 雪"
        cargo_home.mkdir(mode=0o700)
        credentials = cargo_home / "credentials.toml"
        credentials.write_text('[registry]\ntoken="must-not-be-read-by-launcher"\n')
        self.profile.update(manifest="members/app/Cargo.toml", cargo_home_source=str(cargo_home))
        self.save()
        self.assertEqual(self.invoke()[0], 0)
        request = self.records()[0]["request"]
        self.assertEqual(request["cargo_source"], {
            "manifest":"members/app/Cargo.toml", "cargo_home_source":str(cargo_home),
        })
        self.assertNotIn("must-not-be-read-by-launcher", json.dumps(request))
        self.assertNotIn("cargo_home", request, "native capture must derive the transferred projection")
        self.assertNotIn("source_manifest", request, "launcher cannot fabricate source evidence")
        self.assertEqual(credentials.read_text(), '[registry]\ntoken="must-not-be-read-by-launcher"\n')
        self.assertEqual(list(cargo_home.iterdir()), [credentials])

    def test_registry_cache_requires_one_explicit_disjoint_directory(self):
        cargo_home = self.root / "cargo-cache"
        cargo_home.mkdir(mode=0o700)
        alias = self.root / "cache-alias"
        alias.symlink_to(cargo_home, target_is_directory=True)
        nested = self.operations / "nested-cache"
        # An input nested under the output parent must refuse before using it;
        # keep that parent otherwise empty for assert_refused's side-effect check.
        candidates = (None, True, 1, "relative/cache", str(alias), str(self.root / "absent"),
                      str(self.source), str(self.toolchain), str(self.operations), str(self.root))
        for value in candidates:
            with self.subTest(value=value):
                self.profile_path.write_text(json.dumps(dict(self.profile, cargo_home_source=value)))
                self.assert_refused()
        nested.mkdir(mode=0o700)
        self.profile_path.write_text(json.dumps(dict(self.profile, cargo_home_source=str(nested))))
        status, stdout, _, _ = self.invoke()
        self.assertEqual(status, 2)
        self.assertEqual(stdout, b"")
        self.assertFalse(self.record.exists())
        self.assertEqual(list(self.operations.iterdir()), [nested])

    def test_registry_cache_and_vendor_cannot_be_combined(self):
        cargo_home = self.root / "cargo-cache"
        cargo_home.mkdir(mode=0o700)
        self.profile.update(cargo_home_source=str(cargo_home), vendor="vendor")
        self.save()
        self.assert_refused()

    def test_explicit_jobserver_grant_is_request_intent_not_compiler_environment(self):
        for grant in (1, 2, 4096):
            with self.subTest(grant=grant):
                self.profile["jobserver_grant"] = grant
                self.save()
                self.assertEqual(self.invoke()[0], 0)
                request = self.records()[-1]["request"]
                self.assertEqual(request["jobserver_grant"], grant)
                self.assertEqual(request["command_context"]["env"], {"CARGO_INCREMENTAL":"0"})
                self.assertNotIn("-j", request["args"])
                self.assertNotIn("--jobs", request["args"])

    def test_ambiguous_or_unbounded_jobserver_grants_refuse_before_execution(self):
        for grant in (None, True, False, "2", 2.0, 0, -1, 4097, [], {}):
            with self.subTest(grant=grant):
                self.profile_path.write_text(json.dumps(dict(self.profile, jobserver_grant=grant)))
                self.assert_refused()

    def test_locked_offline_and_frozen_are_not_duplicated(self):
        for flags in (["--locked"], ["--offline"], ["--locked", "--offline"], ["--frozen"]):
            self.assertEqual(self.invoke(["build", "--bin=hello"] + flags)[0], 0)
            args = self.records()[-1]["request"]["args"]
            for flag in flags:
                self.assertEqual(args.count(flag), 1)
            if "--frozen" in flags:
                self.assertNotIn("--locked", args)
                self.assertNotIn("--offline", args)
            else:
                self.assertEqual(args.count("--locked"), 1)
                self.assertEqual(args.count("--offline"), 1)

    def test_operation_is_private_durable_intent_not_reused_or_source_mutation(self):
        before = {p.name:p.read_bytes() for p in self.source.iterdir()}
        self.assertEqual(self.invoke()[0], 0)
        first = Path(self.records()[0]["operation"])
        retained = {p.name:p.read_bytes() for p in first.iterdir()}
        self.assertEqual(self.invoke()[0], 0)
        second = Path(self.records()[1]["operation"])
        self.assertNotEqual(first, second)
        self.assertEqual({p.name:p.read_bytes() for p in first.iterdir()}, retained)
        self.assertEqual({p.name:p.read_bytes() for p in self.source.iterdir()}, before)
        for operation in (first, second):
            self.assertEqual(stat.S_IMODE(operation.stat().st_mode), 0o700)
            for file in operation.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            metadata = json.loads((operation / "operation.json").read_text())
            self.assertFalse(metadata["automatic_retry"])
            self.assertFalse(metadata["publication_authorized"])
            self.assertNotIn("--prepare-from", metadata["prepared_build_argv"])
            self.assertEqual(metadata["prepared_build_argv"][2], "--replay-diagnostics")

    def test_native_failure_never_runs_a_second_driver_or_local_compiler(self):
        for status in (1, 2, 101, 125):
            env = dict(self.env, TEST_EXIT=str(status))
            self.assertEqual(self.invoke(env=env)[0], status)
        self.assertEqual(len(self.records()), 4)

    def test_native_signal_is_not_relabelled_as_a_build_or_retried(self):
        status, _, _, _ = self.invoke(env=dict(self.env, TEST_SIGNAL="1"))
        self.assertEqual(status, -signal.SIGTERM)
        self.assertEqual(len(self.records()), 1)

    def test_inherited_descriptor_survives_only_the_launcher_handoff(self):
        read, write = os.pipe()
        try:
            os.write(write, b"jobserver-fixture")
            os.close(write)
            write = None
            env = dict(self.env, TEST_INHERITED_FD=str(read))
            child = subprocess.Popen(
                [sys.executable, "-I", "-S", str(LAUNCHER), "--rabs-canonical", str(self.profile_path), "build", "--bin=hello"],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(read,),
            )
            try:
                child.communicate(timeout=8)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=3)
            self.assertEqual(child.returncode, 0)
            self.assertEqual(bytes.fromhex(self.records()[0]["inherited"]), b"jobserver-fixture")
        finally:
            os.close(read)
            if write is not None:
                os.close(write)

    def test_unknown_and_ambiguous_output_controls_refuse_before_any_operation(self):
        for args in (["run", "--bin=hello"], ["test", "--no-run=false"],
                     ["test", "--no-run", "--no-run"], ["build", "--no-run"],
                     ["check", "--no-run"], ["test", "--no-run", "--", "filter"],
                     ["test", "--no-run", "filter"], ["test", "--doc", "--no-run"],
                     ["test", "one-filter", "another-filter"], ["build", "--no-fail-fast"],
                     ["build", "--exclude=member"], ["build", "--bin=hello", "--target-dir=/other"],
                     ["build", "--bin=hello", "--manifest-path=elsewhere"],
                     ["build", "--bin=hello", "--config", "x=y"],
                     ["build", "--bin=hello", "--profile=custom"],
                     ["build", "--bin=hello", "--message-format=json"],
                     ["build", "--bin=hello", "--", "shell"],
                     ["build", "--bin=../escape"], ["build", "--bin=hello", "--bin=hello"],
                     ["build", "--bin=hello", "--target=x86_64-pc-windows-msvc"],
                     ["build", "--bin=hello", "--features"],
                     ["build", "--bin=hello", "--features=-Zunstable"],
                     ["+nightly", "build", "--bin=hello"]):
            with self.subTest(args=args):
                self.assert_refused(args)

    def test_workspace_library_check_and_test_compilation_use_real_artifact_reports(self):
        cases = (
            ["build"], ["build", "--workspace"], ["build", "--lib"],
            ["build", "--bins"], ["build", "--examples", "--package", "app"],
            ["build", "--workspace", "--exclude", "other", "--all-targets"],
            ["check", "--workspace", "--all-targets"], ["check", "--bin=hello"],
            ["check", "--lib", "--features=one,two"],
            ["test", "--no-run", "--workspace"],
            ["test", "--no-run", "--test", "integration", "--release"],
            ["test", "--no-run", "--bin=hello"],
        )
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(self.invoke(args)[0], 0)
                request = self.records()[-1]["request"]
                self.assertEqual(request["args"][:len(args)], args)
                self.assertEqual(request["artifacts"], {
                    "unit":"cargo", "tree":"tree-files-v1", "files":[], "cargo":"cargo-json-v1",
                })
                self.assertEqual(request["args"].count("--message-format=json"), 1)
                self.assertFalse((Path(self.records()[-1]["operation"]) / "outputs").exists(),
                                 "the launcher must not fabricate compiler outputs")

    def test_canonical_tests_keep_filters_harness_bytes_and_final_native_status(self):
        cases = (
            (["test"], []),
            (["test", "--workspace", "--no-fail-fast"], ["--", "--test-threads=1"]),
            (["test", "--test", "integration", "selected::case"], ["--", "--exact", "--nocapture"]),
            (["test", "--lib", "name=literal雪"], ["--", "--skip", "value with spaces'雪"]),
            (["test", "--doc"], []),
            (["test", "--locked"], ["--", "--offline", "--message-format=json", "--no-run", "--help"]),
        )
        for before, after in cases:
            with self.subTest(before=before, after=after):
                status, stdout, stderr, pid = self.invoke(before + after, env=dict(self.env, TEST_EXIT="101"))
                self.assertEqual(status, 101, "Cargo/test failure must remain observable")
                record = self.records()[-1]
                request = record["request"]
                self.assertEqual(record["pid"], pid)
                self.assertEqual(request["artifacts"]["cargo"], "cargo-test-json-v1")
                self.assertEqual(request["args"][:len(before)], before)
                driver_args = request["args"][:-len(after)] if after else request["args"]
                self.assertEqual(driver_args.count("--locked"), 1)
                self.assertEqual(driver_args.count("--offline"), 1)
                self.assertEqual(driver_args.count("--message-format=json"), 1)
                self.assertEqual(driver_args[-2:], ["--target-dir", "/__rabs/out/cargo"])
                if after:
                    self.assertEqual(request["args"][-len(after):], after)
                self.assertEqual(stdout, b"fixture Cargo stdout\x00\xff\n")
                self.assertIn(b'"kind": "fixture-worker-build"', stderr)
                self.assertIn(b"native-driver-diagnostic", stderr)
                self.assertFalse((Path(record["operation"]) / "outputs").exists())

    def test_canonical_clippy_binds_captured_tools_and_keeps_lint_controls_after_cargo_flags(self):
        self.install_clippy()
        cases = (
            (["clippy"], []),
            (["clippy", "--workspace", "--all-targets", "--all-features"], ["--", "-D", "warnings"]),
            (["clippy", "--no-deps", "-p", "app"],
             ["--", "--warn=clippy::pedantic", "-Aclippy::module-name-repetitions", "--forbid", "unsafe_code"]),
            (["clippy", "--frozen"], ["--", "--force-warn", "unused", "--cap-lints=warn"]),
        )
        for before, after in cases:
            with self.subTest(before=before, after=after):
                env = dict(self.env, TEST_EXIT="101", CLIPPY_ARGS="ambient-not-uploaded",
                           RUSTC_WORKSPACE_WRAPPER="/outside/wrapper")
                status, stdout, stderr, pid = self.invoke(before + after, env=env)
                self.assertEqual(status, 101, "a denied lint must preserve the native failure")
                record = self.records()[-1]
                request = record["request"]
                self.assertEqual(record["pid"], pid)
                self.assertEqual(request["program"], "/__rabs/toolchain/bin/cargo-clippy")
                self.assertEqual(request["artifacts"]["cargo"], "cargo-json-v1")
                self.assertEqual(request["command_context"]["env"], {
                    "CARGO_INCREMENTAL":"0", "CARGO":"/__rabs/toolchain/bin/cargo",
                    "RUSTC":"/__rabs/toolchain/bin/rustc",
                })
                self.assertEqual(request["args"][:len(before)], before)
                controls = request["args"][:-len(after)] if after else request["args"]
                self.assertEqual(controls.count("--message-format=json"), 1)
                self.assertEqual(controls[-2:], ["--target-dir", "/__rabs/out/cargo"])
                if after:
                    self.assertEqual(request["args"][-len(after):], after)
                self.assertEqual(stdout, b"fixture Cargo stdout\x00\xff\n")
                self.assertIn(b'"kind": "fixture-worker-build"', stderr)
                self.assertFalse((Path(record["operation"]) / "outputs").exists())

    def test_clippy_requires_both_ordinary_executable_components_before_operation_creation(self):
        self.assert_refused(["clippy"])
        self.install_clippy()
        driver = self.toolchain / "bin/clippy-driver"
        saved = self.toolchain / "bin/retained-driver"
        driver.rename(saved)
        self.assert_refused(["clippy"])
        saved.rename(driver)
        driver.chmod(0o600)
        self.assert_refused(["clippy"])
        driver.chmod(0o700)
        driver.rename(saved)
        driver.symlink_to(saved)
        self.assert_refused(["clippy"])
        # Other commands need only their existing Cargo/rustc tool set.
        self.assertEqual(self.invoke(["check"])[0], 0)

    def test_clippy_refuses_fix_modes_argument_injection_and_unbounded_lint_controls(self):
        self.install_clippy()
        for args in (
            ["clippy", "--fix"], ["clippy", "--allow-dirty"],
            ["clippy", "--allow-staged"], ["clippy", "--allow-no-vcs"],
            ["clippy", "--explain", "clippy::all"], ["clippy", "--no-run"],
            ["clippy", "filter"], ["clippy", "--", "--fix"],
            ["clippy", "--", "-D"], ["clippy", "--", "-D", "--emit=metadata"],
            ["clippy", "--", "-Dwarnings__CLIPPY_HACKERY__--print"],
            ["clippy", "--", "--warn=clippy:all"],
            ["clippy", "--", "--cap-lints=unknown"],
            ["clippy", "--", "--cfg=other"], ["clippy", "--", "-Copt-level=3"],
            ["clippy", "--", "-Zthreads=4"], ["clippy", "--", "@response"],
            ["clippy", "--", "--sysroot=/outside"], ["clippy", "--", "--out-dir=/outside"],
            ["clippy", "--", "--extern=other=/outside"],
            ["clippy", "--", "--message-format=json", "--target-dir", "/outside"],
            ["clippy", "--"] + ["-Awarnings"] * 129,
            ["clippy", "--", "-A" + "a" * 257],
            ["clippy", "--"] + ["-A" + "a" * 256] * 128,
        ):
            with self.subTest(args=args[:5]):
                self.assert_refused(args)

    def test_launcher_mode_conflicts_cannot_reach_another_executor(self):
        for first in ("--rabs-no-start", "--rabs-require-daemon", "--rabs-remote"):
            self.assert_refused(prefix=[first, "--rabs-canonical", str(self.profile_path)])
            self.assert_refused(prefix=["--rabs-canonical", str(self.profile_path), first])
        self.assert_refused(prefix=["--rabs-canonical"])
        self.assert_refused(prefix=["--rabs-canonical", "--help"])

    def test_profile_rejects_unknown_duplicate_wrong_version_and_malformed_types(self):
        valid = json.dumps(self.profile)
        for data in ("[]", "null", "{", valid.replace("{", '{"version":"canonical-cargo-v1",', 1),
                     json.dumps(dict(self.profile, unknown=True)),
                     json.dumps(dict(self.profile, version=2)),
                     json.dumps(dict(self.profile, worker_spki_sha256=True)),
                     json.dumps(dict(self.profile, source_root=1)), " " * (65536 + 1)):
            with self.subTest(data=data[:80]):
                self.profile_path.write_text(data)
                self.assert_refused()

    def test_profile_refuses_symlink_and_fifo_without_open_rendezvous(self):
        original = self.root / "original-profile"
        self.profile_path.rename(original)
        self.profile_path.symlink_to(original)
        self.assert_refused()
        self.profile_path.rename(self.root / "retained-link")
        os.mkfifo(self.profile_path)
        self.assert_refused()

    def test_profile_network_identity_and_namespace_fail_closed(self):
        for field, value in (
            ("listen", "example.com:1"), ("listen", "127.0.0.1:0"), ("listen", "::1:2"),
            ("listen", "[::1%lo]:2"), ("listen", "127.0.0.1:65536"),
            ("worker", "--arbitrary"), ("worker_spki_sha256", "AB" * 32),
            ("manifest", "../Cargo.toml"), ("manifest", "/Cargo.toml"),
            ("manifest", "Cargo.lock"), ("vendor", "vendor/../outside"),
            ("source_root", str(self.source) + "/../operations"),
        ):
            with self.subTest(field=field, value=value):
                profile = dict(self.profile, **{field:value})
                self.profile_path.write_text(json.dumps(profile))
                self.assert_refused()

    def test_ipv6_literal_requires_no_dns_and_remains_unchanged(self):
        self.profile["listen"] = "[::1]:45123"
        self.save()
        self.assertEqual(self.invoke()[0], 0)
        self.assertEqual(self.records()[0]["argv"][6], "[::1]:45123")

    def test_unsafe_or_input_nested_operation_roots_are_not_chmodded_or_used(self):
        self.operations.chmod(0o770)
        self.assert_refused()
        self.assertEqual(stat.S_IMODE(self.operations.stat().st_mode), 0o770)
        self.operations.chmod(0o700)
        self.profile["operation_root"] = str(self.source)
        self.save()
        self.assert_refused()

    def test_root_and_tool_aliases_refuse_before_operation_creation(self):
        alias = self.root / "source-alias"
        alias.symlink_to(self.source, target_is_directory=True)
        self.profile["source_root"] = str(alias)
        self.save()
        self.assert_refused()
        self.profile["source_root"] = str(self.source)
        self.save()
        cargo = self.toolchain / "bin/cargo"
        cargo.rename(cargo.with_name("cargo-real"))
        cargo.symlink_to(cargo.with_name("cargo-real"))
        self.assert_refused()

    def test_missing_or_recursive_native_driver_has_no_fallback(self):
        for driver in (str(self.root / "absent"), str(LAUNCHER)):
            self.assert_refused(env=dict(self.env, CARGO_RABS_DAEMON=driver))

    def test_exec_failure_preserves_intent_but_never_compiles_locally(self):
        self.driver.write_bytes(b"not an executable image\n")
        status, stdout, _, _ = self.invoke()
        self.assertEqual(status, 127)
        self.assertEqual(stdout, b"")
        self.assertFalse(self.record.exists())
        self.assertEqual(len(list(self.operations.iterdir())), 1)

    def test_nested_dispatch_refuses_even_with_a_valid_profile(self):
        for name in ("CARGO_RABS_CANONICAL_ACTIVE", "CARGO_RABS_REMOTE_ACTIVE", "RCH_RABS_WORKER_ACTIVE"):
            self.assert_refused(env=dict(self.env, **{name:"1"}))

    def test_platform_byte_and_total_size_bounds_have_no_side_effects(self):
        with patch.object(launcher.sys, "platform", "darwin"):
            with self.assertRaises(launcher.SetupError):
                launcher.canonical_invocation(str(self.profile_path), ["build", "--bin=hello"], self.env)
        for args in (["build", "--bin=hello", "--features", "\udcff"],
                     ["build", "--bin=hello", "--features", "a\0b"],
                     ["build", "--bin=hello"] + ["--features=" + "a" * 4000] * 20):
            with self.assertRaises(launcher.SetupError):
                launcher.canonical_invocation(str(self.profile_path), args, self.env)
        self.assertEqual(list(self.operations.iterdir()), [])

    def test_old_parser_and_preparation_import_contract_remain_available(self):
        self.assertEqual(launcher.RCH_WORKER_PREPARATION_API, 1)
        self.assertEqual(launcher.arguments(["rabs"]), (["build"], False, False, False))
        self.assertEqual(launcher.arguments(["rabs", "--rabs-remote", "build", "--bin=x"]),
                         (["build", "--bin=x"], False, False, True))
        self.assertEqual(launcher.arguments(["--rabs-no-start", "--rabs-require-daemon", "--", "test"]),
                         (["test"], True, True, False))
        self.assertFalse(self.record.exists())
        self.assertEqual(list(self.operations.iterdir()), [])

    def test_ordinary_local_fallback_keeps_argv_and_exit_status(self):
        cargo = self.root / "stock-cargo"
        cargo.write_text("#!" + sys.executable + " -S\nimport json,sys\n"
                         "print(json.dumps(sys.argv[1:]))\nsys.exit(19)\n")
        cargo.chmod(0o700)
        env = dict(self.env, CARGO=str(cargo), CARGO_RABS_WRAP=str(self.root / "absent-wrapper"))
        args = ["test", "--features", "spaces quote' 雪"]
        status, stdout, stderr, _ = self.invoke(args, env=env, prefix=["rabs", "--rabs-no-start"])
        self.assertEqual(status, 19)
        self.assertEqual(json.loads(stdout), args)
        self.assertIn(b"running stock Cargo", stderr)
        self.assertEqual(list(self.operations.iterdir()), [])

    def test_ordinary_required_daemon_mode_still_refuses_without_cargo(self):
        env = dict(self.env, CARGO_RABS_WRAP=str(self.root / "absent-wrapper"))
        self.assert_refused(["build"], env=env, prefix=["--rabs-require-daemon"])

    def test_ordinary_remote_mode_still_execs_rch_once(self):
        rch = self.root / "original-rch-route"
        rch.write_text("#!" + sys.executable + " -S\nimport json,os,sys\n"
                       "print(json.dumps({'argv':sys.argv[1:],'required':os.environ['RCH_REQUIRE_REMOTE'],"
                       "'cache':os.environ['RCH_RABS_WORKER_CACHE']}))\nsys.exit(23)\n")
        rch.chmod(0o700)
        status, stdout, _, _ = self.invoke(["build", "--bin=x"],
            env=dict(self.env, CARGO_RABS_RCH=str(rch)), prefix=["--rabs-remote"])
        self.assertEqual(status, 23)
        self.assertEqual(json.loads(stdout), {"argv":["exec", "--source-content-receipt", "--", "cargo", "build", "--bin=x"],
                                             "required":"1", "cache":"1"})
        self.assertEqual(list(self.operations.iterdir()), [])

    def test_every_canonical_mode_delegates_worker_ids_to_native_preparation(self):
        self.install_clippy()
        cases = (["build"], ["check", "--workspace"], ["test", "--no-run"],
                 ["test", "--doc"], ["test", "selected", "--", "--exact"],
                 ["clippy", "--workspace", "--", "-D", "warnings"])
        for args in cases:
            with self.subTest(args=args):
                status, _, _, pid = self.invoke(args)
                self.assertEqual(status, 0)
                record = self.records()[-1]
                self.assertEqual(record["pid"], pid)
                self.assertEqual(record["request"]["request_id"], "allocate")
                operation = Path(record["operation"])
                metadata = json.loads((operation / "operation.json").read_text())
                self.assertEqual(metadata["request_id"], "allocate", "intent is not an assigned ID")
                self.assertEqual(record["argv"][1:4],
                                 ["--worker-build-tls", "--replay-diagnostics", "--prepare-from"])
                # Recovery uses the already prepared bundle, not spec.json or
                # another allocation. No native execution is simulated here.
                self.assertNotIn("--prepare-from", metadata["prepared_build_argv"])
                self.assertEqual(metadata["prepared_build_argv"][-3], str(operation / "bundle"))
                self.assertFalse(metadata["automatic_retry"])
                self.assertFalse(metadata["publication_authorized"])

    def test_random_entropy_is_only_for_private_operation_names_not_worker_ids(self):
        # Even adversarial/decreasing random values must never enter the worker
        # request journal. Do not replace the native allocator with a Python one.
        import secrets
        env = dict(self.env, RABS_STATE_DIR=str(self.root / "shared-admission"))
        before = dict(env)
        operations = []
        with patch.object(secrets, "randbits", side_effect=AssertionError("random worker ID")):
            for _ in range(3):
                _, argv, child_env = launcher.canonical_invocation(
                    str(self.profile_path), ["check"], env)
                specification = Path(argv[5])
                self.assertEqual(json.loads(specification.read_text())["request_id"], "allocate")
                self.assertEqual(child_env["RABS_STATE_DIR"], env["RABS_STATE_DIR"])
                operations.append(specification.parent)
        self.assertEqual(env, before)
        self.assertEqual(len(set(operations)), 3)
        self.assertFalse(Path(env["RABS_STATE_DIR"]).exists(), "only native admission may create its ledger")
        self.assertFalse(self.record.exists(), "preparing intent must not execute or probe the driver")

    def test_allocation_refusal_is_not_retried_with_a_random_or_numeric_id(self):
        # This executable double refuses allocation. It is not a model of the
        # native SQLite allocator, TLS admission, or worker high-water state.
        self.driver.write_text("#!" + sys.executable + " -S\n" + r'''
import json, os, pathlib, sys
specification = pathlib.Path(sys.argv[5])
request = json.loads(specification.read_text())
with open(os.environ["TEST_DRIVER_RECORD"], "a") as record:
    record.write(json.dumps({"request": request, "operation": str(specification.parent)}) + "\n")
if request["request_id"] != "allocate":
    sys.exit(79)
print("fixture: native request allocation unavailable", file=sys.stderr)
sys.exit(78)
''')
        status, stdout, stderr, _ = self.invoke()
        self.assertEqual(status, 78)
        self.assertEqual(stdout, b"")
        self.assertIn(b"native request allocation unavailable", stderr)
        record, = self.records()
        operation = Path(record["operation"])
        self.assertEqual(json.loads((operation / "spec.json").read_text()), record["request"])
        self.assertEqual(sorted(p.name for p in operation.iterdir()), ["operation.json", "spec.json"])
        self.assertEqual(len(list(self.operations.iterdir())), 1)

    def test_concurrent_launchers_keep_allocation_native_and_operation_intent_separate(self):
        children = []
        try:
            for _ in range(8):
                children.append(subprocess.Popen(
                    [sys.executable, "-I", "-S", str(LAUNCHER), "--rabs-canonical",
                     str(self.profile_path), "check"], env=self.env, cwd=self.root,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ))
            for child in children:
                _, stderr = child.communicate(timeout=8)
                self.assertEqual(child.returncode, 0, stderr)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=3)
                for stream in (child.stdout, child.stderr):
                    stream.close()
        records = self.records()
        self.assertEqual(len(records), 8)
        self.assertEqual({r["pid"] for r in records}, {child.pid for child in children})
        self.assertEqual(len({r["operation"] for r in records}), 8)
        for record in records:
            self.assertEqual(record["request"]["request_id"], "allocate")
        self.assertFalse(self.forbidden.exists())

    def test_help_describes_canonical_limits_without_loading_profile(self):
        status, stdout, _, _ = self.invoke(cargo_args=[], prefix=["--help"])
        self.assertEqual(status, 0)
        self.assertIn(b"--rabs-canonical", stdout)
        self.assertIn(b"complete verified delivery", stdout)
        self.assertFalse(self.record.exists())
        self.assertEqual(list(self.operations.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
