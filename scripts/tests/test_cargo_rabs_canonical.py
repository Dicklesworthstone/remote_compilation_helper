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
assert args[0:2] == ["--worker-build-tls", "--prepare-from"], args
source, specification, address, worker, pin, bundle, delivery, output = args[2:]
request = json.loads(pathlib.Path(specification).read_text())
operation = pathlib.Path(specification).parent
assert not pathlib.Path(bundle).exists()
assert not pathlib.Path(delivery).exists()
assert not pathlib.Path(output).exists()
assert request["program"] == "/__rabs/toolchain/bin/cargo"
assert request["artifacts"]["tree"] == "tree-files-v1"
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
print(json.dumps({"kind":"fixture-worker-build", "pid":os.getpid()}), flush=True)
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
        self.assertEqual(json.loads(stdout)["kind"], "fixture-worker-build")
        self.assertIn(b"native-driver-diagnostic", stderr)
        self.assertEqual(record["request"]["command_context"]["env"], {"CARGO_INCREMENTAL":"0"})
        self.assertEqual(record["request"]["artifacts"]["files"], ["debug/hello"])

    def test_required_binaries_release_target_and_features_are_exact(self):
        args = ["build", "--release", "--bin=one", "--bin", "two", "-p", "app",
                "--target=aarch64-unknown-linux-gnu", "--features", "feature,quoted'雪",
                "--no-default-features", "--color=never", "-vv"]
        self.assertEqual(self.invoke(args)[0], 0)
        request = self.records()[0]["request"]
        self.assertEqual(request["args"][:len(args)], args)
        self.assertEqual(request["args"][len(args):], ["--locked", "--offline", "--manifest-path",
            "/__rabs/workspace/Cargo.toml", "--target-dir", "/__rabs/out/cargo"])
        self.assertEqual(request["artifacts"]["files"],
                         ["aarch64-unknown-linux-gnu/release/one", "aarch64-unknown-linux-gnu/release/two"])

    def test_member_and_explicit_vendor_go_to_shared_source_planner(self):
        self.profile.update(manifest="members/app/Cargo.toml", vendor="third_party/vendor")
        self.save()
        self.assertEqual(self.invoke()[0], 0)
        request = self.records()[0]["request"]
        self.assertEqual(request["cargo_source"], {"manifest":"members/app/Cargo.toml", "vendor":"third_party/vendor"})
        self.assertEqual(request["command_context"]["cwd"], "/__rabs/workspace/members/app")
        self.assertNotIn("source_manifest", request, "launcher must not fabricate input evidence")
        self.assertNotIn("toolchain_identity", request, "native capture owns the identity")

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
        for args in (["check", "--bin=hello"], ["build"], ["run", "--bin=hello"],
                     ["build", "--bins"], ["build", "--bin=hello", "--target-dir=/other"],
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
        self.assertEqual(self.records()[0]["argv"][5], "[::1]:45123")

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

    def test_help_describes_canonical_limits_without_loading_profile(self):
        status, stdout, _, _ = self.invoke(cargo_args=[], prefix=["--help"])
        self.assertEqual(status, 0)
        self.assertIn(b"--rabs-canonical", stdout)
        self.assertIn(b"not Cargo JSON", stdout)
        self.assertFalse(self.record.exists())
        self.assertEqual(list(self.operations.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
