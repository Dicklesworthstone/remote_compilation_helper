#!/usr/bin/env python3
"""Native orchestration tests, not Rust compilation or cache-hit evidence."""

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


RUNNER = Path(__file__).resolve().parents[1] / "test_rabs_live.py"
spec = importlib.util.spec_from_file_location("rabs_live_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

FAKE_CARGO = r'''
import hashlib, json, os, pathlib, signal, stat, sys
root = pathlib.Path(os.environ["TEST_ROOT"])
args = sys.argv[1:]
token = None
if "TEST_JOBSERVER_READ" in os.environ:
    read_fd = int(os.environ["TEST_JOBSERVER_READ"])
    write_fd = int(os.environ["TEST_JOBSERVER_WRITE"])
    assert stat.S_ISFIFO(os.fstat(read_fd).st_mode)
    assert stat.S_ISFIFO(os.fstat(write_fd).st_mode)
    token = os.read(read_fd, 1)
    assert token == b"+"
    assert os.write(write_fd, token) == 1
    token = token.hex()
inherited = []
for entry in pathlib.Path("/proc/self/fd").iterdir():
    try:
        inherited.append(os.readlink(entry))
    except FileNotFoundError:
        pass
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps({"argv": args, "cwd": os.getcwd(),
        "manifest": os.environ.get("RABS_TEST_BINARIES"),
        "toolchain": os.environ.get("RUSTUP_TOOLCHAIN"),
        "rustflags": os.environ.get("RUSTFLAGS"),
        "makeflags": os.environ.get("CARGO_MAKEFLAGS"),
        "jobserver_token": token, "inherited": inherited}) + "\n")
mode = os.environ.get("TEST_MODE", "good")
if args[0] == "build":
    target = pathlib.Path(args[args.index("--target-dir") + 1])
    profile = args[args.index("--profile") + 1]
    directory = target / ("debug" if profile == "dev" else profile)
    directory.mkdir(parents=True, exist_ok=True)
    if mode == "malformed":
        print("{broken}")
        sys.exit(0)
    if mode == "oversize":
        print("x" * (5 * 1024 * 1024))
        sys.exit(0)
    if mode == "duplicate-json":
        print('{"reason":"build-finished","success":true,"success":true}')
        sys.exit(0)
    for name in ["rabsd", "rabs-wrap"]:
        binary = directory / name
        binary.write_bytes(b"#!/bin/sh\nprintf fixture\\n\n" + name.encode())
        binary.chmod(0o700)
        if mode == "missing" and name == "rabsd":
            continue  # A sibling exists, but Cargo never identified it.
        if mode == "nonexec" and name == "rabsd":
            binary.chmod(0o600)
        if mode == "symlink" and name == "rabsd":
            real = directory / "real-daemon"
            binary.rename(real)
            binary.symlink_to(real)
        source = str(root / name / "src/main.rs")
        if mode == "wrong-tree" and name == "rabsd":
            source = "/another-checkout/rabsd/src/main.rs"
        kind = ["lib"] if mode == "library-only" and name == "rabsd" else ["bin"]
        record = {"reason": "compiler-artifact", "target": {
            "name": name, "kind": kind, "src_path": source},
            "profile": {"test": False}, "executable": str(binary), "fresh": mode == "fresh"}
        print(json.dumps(record))
        if mode == "ambiguous" and name == "rabsd":
            record["executable"] += "-another"
            print(json.dumps(record))
    print(json.dumps({"reason": "build-finished", "success": mode not in ["nonzero", "failed-finish"]}))
    sys.exit(31 if mode == "nonzero" else 0)
if args[0] == "test":
    record = json.loads(pathlib.Path(os.environ["RABS_TEST_BINARIES"]).read_text())
    assert record["schema"] == "rabs.test-binaries" and record["version"] == 1
    assert record["profile"] == args[args.index("--profile") + 1]
    assert record["workspace_root"] == str(root)
    for name in ["rabs-wrap", "rabsd"]:
        item = record[name]
        data = pathlib.Path(item["path"]).read_bytes()
        assert item["sha256"] == hashlib.sha256(data).hexdigest()
        assert item["size"] == len(data)
    sys.stdout.buffer.write(b"fixture test stdout\x00\xff\n")
    sys.stdout.flush()
    sys.stderr.buffer.write(b"fixture test stderr\n")
    sys.stderr.flush()
    if os.environ.get("TEST_SIGNAL"):
        os.kill(os.getpid(), int(os.environ["TEST_SIGNAL"]))
    sys.exit(int(os.environ.get("TEST_EXIT", "0")))
sys.exit(99)
'''


@unittest.skipUnless(sys.platform == "linux", "Linux live Cargo runner")
class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rabs-runner-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "scripts").mkdir()
        self.program = self.root / "scripts/test_rabs_live.py"
        shutil.copyfile(RUNNER, self.program)
        (self.root / "Cargo.toml").write_text("[workspace]\n")
        for name in runner.NAMES:
            source = self.root / name / "src/main.rs"
            source.parent.mkdir(parents=True)
            source.write_text("fn main() {}\n")
        self.cargo = self.root / "cargo with spaces"
        self.cargo.write_text("#!{} -S\n{}".format(sys.executable, FAKE_CARGO))
        self.cargo.chmod(0o700)
        self.count = 0

    def launch(self, args=(), changes=None, pass_fds=()):
        self.count += 1
        self.output = self.root / ("run-" + str(self.count))
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("CARGO", "RUST", "RABS", "TEST_"))}
        env["TEST_ROOT"] = str(self.root)
        env.update(changes or {})
        result = subprocess.run([sys.executable, "-S", str(self.program), "--cargo", str(self.cargo),
                                 "--output-dir", str(self.output)] + list(args),
                                env=env, cwd=self.root, capture_output=True, timeout=15,
                                pass_fds=pass_fds)
        return result

    def calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def report(self):
        return json.loads((self.output / "run.json").read_text())

    def test_one_profile_matched_build_then_test_with_verified_binary_pair(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        build, test = self.calls()
        self.assertEqual(build["argv"][0], "build")
        self.assertEqual(test["argv"][0], "test")
        for call in [build, test]:
            args = call["argv"]
            self.assertEqual(args[args.index("--profile") + 1], "daemon-release")
            self.assertEqual(args[args.index("--target-dir") + 1], str(self.root / "target"))
            self.assertIn("--locked", args)
            self.assertEqual(call["cwd"], str(self.root))
        self.assertIn("rabsd", build["argv"])
        self.assertIn("rabs-wrap", build["argv"])
        self.assertIn("--bins", build["argv"])
        self.assertIsNone(build["manifest"])
        self.assertEqual(test["manifest"], str(self.output / "binaries.json"))
        self.assertEqual(result.stdout, b"fixture test stdout\x00\xff\n")
        self.assertIn(b"fixture test stderr\n", result.stderr)
        self.assertEqual(self.report()["test_exit"], 0)
        self.assertEqual((self.output / "binaries.json").stat().st_mode & 0o777, 0o600)

    def test_explicit_profile_target_and_libtest_arguments_are_preserved(self):
        args = ["--profile", "dev", "--target-dir", "target with spaces", "--",
                "build_script_reuse", "--test-threads=1", "--exact"]
        result = self.launch(args)
        self.assertEqual(result.returncode, 0, result.stderr)
        build, test = self.calls()
        for call in [build, test]:
            argv = call["argv"]
            self.assertEqual(argv[argv.index("--profile") + 1], "dev")
            self.assertEqual(argv[argv.index("--target-dir") + 1], str(self.root / "target with spaces"))
        self.assertEqual(test["argv"][test["argv"].index("--") + 1:],
                         ["--nocapture", "build_script_reuse", "--test-threads=1", "--exact"])

    def test_toolchain_rustflags_and_jobserver_environment_are_not_rewritten(self):
        changes = {"RUSTUP_TOOLCHAIN": "nightly-fixture", "RUSTFLAGS": "-C debuginfo=1",
                   "CARGO_MAKEFLAGS": "-j --jobserver-auth=3,4", "RABS_TEST_BINARIES": "/stale/manifest"}
        result = self.launch(changes=changes)
        self.assertEqual(result.returncode, 0, result.stderr)
        for call in self.calls():
            self.assertEqual(call["toolchain"], changes["RUSTUP_TOOLCHAIN"])
            self.assertEqual(call["rustflags"], changes["RUSTFLAGS"])
            self.assertEqual(call["makeflags"], changes["CARGO_MAKEFLAGS"])
            self.assertNotEqual(call["manifest"], "/stale/manifest")

    def test_real_jobserver_pipe_survives_both_cargo_process_boundaries(self):
        for spelling in ["--jobserver-auth", "--jobserver-fds"]:
            with self.subTest(spelling=spelling):
                read_fd, write_fd = os.pipe()
                try:
                    os.write(write_fd, b"+")
                    os.set_blocking(read_fd, False)
                    flags = "-j {}={},{}".format(spelling, read_fd, write_fd)
                    mark = len(self.calls())
                    result = self.launch(changes={
                        "CARGO_MAKEFLAGS": flags,
                        "TEST_JOBSERVER_READ": str(read_fd),
                        "TEST_JOBSERVER_WRITE": str(write_fd),
                    }, pass_fds=(read_fd, write_fd))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = self.calls()[mark:]
                    self.assertEqual([call["argv"][0] for call in calls], ["build", "test"])
                    for call in calls:
                        self.assertEqual(call["makeflags"], flags)
                        self.assertEqual(call["jobserver_token"], "2b")
                        self.assertNotIn(str(self.output / "cargo-build.jsonl"), call["inherited"])
                    self.assertEqual(os.read(read_fd, 1), b"+")
                    with self.assertRaises(BlockingIOError):
                        os.read(read_fd, 1)  # The runner must not invent capacity.
                finally:
                    os.close(read_fd)
                    os.close(write_fd)

    def test_jobserver_capacity_survives_build_and_test_failure(self):
        for changes, expected in [({"TEST_MODE": "nonzero"}, 31), ({"TEST_EXIT": "37"}, 37)]:
            with self.subTest(changes=changes):
                read_fd, write_fd = os.pipe()
                try:
                    os.write(write_fd, b"+")
                    os.set_blocking(read_fd, False)
                    result = self.launch(changes={
                        **changes, "CARGO_MAKEFLAGS": "-j --jobserver-auth={},{}".format(read_fd, write_fd),
                        "TEST_JOBSERVER_READ": str(read_fd),
                        "TEST_JOBSERVER_WRITE": str(write_fd),
                    }, pass_fds=(read_fd, write_fd))
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(os.read(read_fd, 1), b"+")
                finally:
                    os.close(read_fd)
                    os.close(write_fd)

    def test_runner_private_log_descriptor_does_not_leak_to_cargo(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        for call in self.calls():
            self.assertNotIn(str(self.output / "cargo-build.jsonl"), call["inherited"])

    def test_build_failure_propagates_and_never_runs_tests(self):
        result = self.launch(changes={"TEST_MODE": "nonzero"})
        self.assertEqual(result.returncode, 31, result.stderr)
        self.assertEqual(len(self.calls()), 1)
        self.assertFalse((self.output / "binaries.json").exists())
        self.assertEqual(self.report()["build_exit"], 31)
        self.assertIsNone(self.report()["test_exit"])

    def test_missing_artifact_never_uses_an_existing_sibling(self):
        result = self.launch(changes={"TEST_MODE": "missing"})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertTrue((self.root / "target/daemon-release/rabsd").exists())
        self.assertEqual(len(self.calls()), 1)
        self.assertIn("both required", self.report()["preparation_error"])

    def test_bad_json_wrong_sources_and_ambiguous_builds_refuse(self):
        for mode in ["malformed", "oversize", "duplicate-json", "wrong-tree",
                     "ambiguous", "library-only", "failed-finish"]:
            with self.subTest(mode=mode):
                mark = len(self.calls())
                result = self.launch(changes={"TEST_MODE": mode})
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(len(self.calls()), mark + 1)
                self.assertFalse((self.output / "binaries.json").exists())
                self.assertIsNone(self.report()["test_exit"])

    def test_nonexecutables_and_symlinks_cannot_be_prepared(self):
        for mode in ["nonexec", "symlink"]:
            with self.subTest(mode=mode):
                mark = len(self.calls())
                result = self.launch(changes={"TEST_MODE": mode})
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(len(self.calls()), mark + 1)
                self.assertFalse((self.output / "binaries.json").exists())

    def test_fresh_cargo_artifact_records_are_accepted(self):
        result = self.launch(changes={"TEST_MODE": "fresh"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls()), 2)

    def test_test_failure_is_not_changed_to_preparation_success(self):
        result = self.launch(changes={"TEST_EXIT": "37"})
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertEqual(self.report()["build_exit"], 0)
        self.assertEqual(self.report()["test_exit"], 37)

    def test_test_signal_remains_a_signal(self):
        result = self.launch(changes={"TEST_SIGNAL": str(signal.SIGTERM)})
        self.assertEqual(result.returncode, -signal.SIGTERM, result.stderr)
        self.assertEqual(self.report()["test_exit"], -signal.SIGTERM)

    def test_explicit_target_beats_ambient_target_and_old_manifest(self):
        result = self.launch(["--target-dir", "selected"], {
            "CARGO_TARGET_DIR": str(self.root / "unrelated"), "RABS_TEST_BINARIES": "/old.json"})
        self.assertEqual(result.returncode, 0, result.stderr)
        for call in self.calls():
            args = call["argv"]
            self.assertEqual(args[args.index("--target-dir") + 1], str(self.root / "selected"))
        self.assertFalse((self.root / "unrelated").exists())

    def test_missing_cargo_does_not_create_a_result_or_run_anything(self):
        result = self.launch(["--cargo", "/does/not/exist"])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.output.exists())

    def test_existing_report_directory_is_not_overwritten(self):
        existing = self.root / "keep"
        existing.mkdir()
        (existing / "binaries.json").write_text("keep these bytes")
        result = self.launch(["--output-dir", str(existing)])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual((existing / "binaries.json").read_text(), "keep these bytes")
        self.assertEqual(self.calls(), [])


class ArtifactTests(unittest.TestCase):
    def test_sha256_matches_binary_multibuffer_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            data = bytes(range(256)) * 1001
            path.write_bytes(data)
            path.chmod(0o700)
            record = runner.fingerprint(path)
            self.assertEqual(record, {"path": str(path), "size": len(data),
                                      "sha256": hashlib.sha256(data).hexdigest()})

    def test_mutation_during_hashing_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(b"x" * 100000)
            path.chmod(0o700)
            original_read = os.read
            changed = False
            def reading(descriptor, count):
                nonlocal changed
                data = original_read(descriptor, count)
                if not changed:
                    changed = True
                    path.write_bytes(b"y" * 100000)
                return data
            with mock.patch.object(runner.os, "read", side_effect=reading):
                with self.assertRaises(runner.PreparationError):
                    runner.fingerprint(path)

    def test_binary_hashing_does_not_open_a_fifo_or_follow_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fifo"
            os.mkfifo(path, 0o700)
            with self.assertRaises(runner.PreparationError):
                runner.fingerprint(path)
            link = Path(directory) / "alias"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                runner.fingerprint(link)

    def test_manifest_records_are_create_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            runner.write_new_json(path, {"original": True})
            with self.assertRaises(FileExistsError):
                runner.write_new_json(path, {"original": False})
            self.assertEqual(json.loads(path.read_text()), {"original": True})

    def test_python39_grammar(self):
        ast.parse(RUNNER.read_text(), feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
