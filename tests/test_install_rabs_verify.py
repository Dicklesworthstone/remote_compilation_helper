"""Read-only recovery of interrupted RABS installs using real files and processes.

Native `true` executables stand in for compiled RABS tools. Only SSH transport
is replaced with a local peer; the actual inspector, lock, hashes, framing and
installer run. These tests do not qualify Rust execution or a live fleet.
"""

import contextlib
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install-rabs"
loader = importlib.machinery.SourceFileLoader("install_rabs_verify", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
installer = importlib.util.module_from_spec(spec)
loader.exec_module(installer)

SSH = r'''#!/usr/bin/env python3
import json, os, pathlib, shlex, subprocess, sys, time
root = pathlib.Path(os.environ["RABS_VERIFY_TEST_ROOT"])
host = sys.argv[-2]
program = shlex.split(sys.argv[-1])
phase = "verify" if "receive_verification" in program[-1] else "install"
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps({"host": host, "phase": phase, "argv": sys.argv[1:]}) + "\n")
if host == "offline":
    sys.exit(255)
if host == "slow":
    time.sleep(20)
    sys.exit(0)
if host == "flood":
    sys.stdout.buffer.write(b"x" * 200000)
    sys.exit(0)
home = root / host
home.mkdir(exist_ok=True)
(home / "tmp").mkdir(exist_ok=True)
env = {**os.environ, "HOME": str(home), "TMPDIR": str(home / "tmp")}
result = subprocess.run(program, stdin=sys.stdin.buffer, capture_output=True,
                        env=env, timeout=15)
sys.stderr.buffer.write(result.stderr)
if host != "drop-ack" or phase == "verify":
    if host == "banner":
        print("unexpected stdout banner", flush=True)
    sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
'''


def snapshot(root):
    """Ignore read access times; retain all names, bytes, links and other metadata."""
    result = {}
    for path in [root] + sorted(root.rglob("*")):
        metadata = path.lstat()
        data = None
        if stat.S_ISLNK(metadata.st_mode):
            data = os.readlink(path)
        elif stat.S_ISREG(metadata.st_mode):
            data = hashlib.sha256(path.read_bytes()).hexdigest()
        result[str(path.relative_to(root))] = (
            metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink, data)
    return result


@unittest.skipUnless(sys.platform == "linux", "real managed Linux installation")
class InstallationVerificationTests(unittest.TestCase):
    def setUp(self):
        # Retained private fixtures; no cleanup can touch a user's installation.
        self.root = Path(tempfile.mkdtemp(prefix="rabs-verify-test-"))
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.bin = self.root / "bin"
        self.marker = self.root / "tool-executed"
        native = shutil.which("true")
        self.assertIsNotNone(native)
        for name in installer.TOOLS[1:]:
            shutil.copyfile(native, self.bundle / name)
            (self.bundle / name).chmod(0o755)
        self.launcher("first")
        client = self.root / "client"
        client.mkdir()
        (client / "ssh").write_text(SSH)
        (client / "ssh").chmod(0o755)
        self.env = {"PATH": str(client) + os.pathsep + os.environ.get("PATH", ""),
                    "RABS_VERIFY_TEST_ROOT": str(self.root)}

    def launcher(self, label):
        (self.bundle / "cargo-rabs").write_text(
            "#!/usr/bin/env python3\nfrom pathlib import Path\n"
            "Path(" + repr(str(self.marker)) + ").write_text(" + repr(label) + ")\n")
        (self.bundle / "cargo-rabs").chmod(0o755)

    def paths(self):
        return installer.source_files(self.bundle, None)

    def expected(self):
        return installer.expected_toolset(self.paths())

    def install(self):
        return installer.install(self.paths(), self.bin, installer.host_machine())

    def run_cli(self, *arguments):
        output = io.StringIO()
        error = io.StringIO()
        with mock.patch.dict(os.environ, self.env), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = installer.main(list(arguments))
        return status, json.loads(output.getvalue()) if output.getvalue() else None, error.getvalue()

    def deploy(self, hosts):
        with mock.patch.dict(os.environ, self.env):
            return installer.deploy(self.paths(), hosts, None, 10, installer.MIN_DEPLOY_RESERVE)

    def calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def corrupt(self, path):
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.chmod(0o755)
        path.write_bytes(data)
        path.chmod(0o555)

    def test_local_cli_verifies_every_current_byte_without_mutation_or_execution(self):
        installed = self.install()
        before = snapshot(self.bin)
        status, receipt, error = self.run_cli(
            "--verify", "--from-bundle", str(self.bundle), "--bin-dir", str(self.bin))
        self.assertEqual(status, 0, (receipt, error))
        self.assertEqual(receipt["state"], "verified")
        self.assertEqual(receipt["generation"], installed["generation"])
        self.assertEqual(receipt["files"], installed["files"])
        self.assertFalse(receipt["installation_changed"])
        self.assertFalse(receipt["services_started"])
        self.assertFalse(receipt["cargo_config_changed"])
        self.assertEqual(snapshot(self.bin), before)
        self.assertFalse(self.marker.exists())

    def test_same_size_corruption_refuses_even_when_manifest_is_unchanged(self):
        self.install()
        self.corrupt(self.bin / installer.CURRENT / "rabsd")
        before = snapshot(self.bin)
        receipt = installer.verification_result(self.expected(), self.bin)
        self.assertEqual(receipt["state"], "unverified", receipt)
        self.assertIn("expected bytes", receipt["error"])
        self.assertEqual(snapshot(self.bin), before)

    def test_self_consistent_modified_manifest_is_not_expected_release_authority(self):
        self.install()
        active = self.bin / installer.CURRENT
        self.corrupt(active / "rabs-wkr")
        manifest = json.loads((active / "manifest.json").read_text())
        manifest["files"]["rabs-wkr"]["sha256"] = hashlib.sha256((active / "rabs-wkr").read_bytes()).hexdigest()
        (active / "manifest.json").write_text(json.dumps(manifest))
        before = snapshot(self.bin)
        receipt = installer.verification_result(self.expected(), self.bin)
        self.assertEqual(receipt["state"], "unverified", receipt)
        self.assertIn("differs from the expected toolset", receipt["error"])
        self.assertEqual(snapshot(self.bin), before)

    def test_newer_generation_is_reported_without_rollback(self):
        first = self.install()
        expected = self.expected()
        self.launcher("second")
        second = self.install()
        before = snapshot(self.bin)
        receipt = installer.verification_result(expected, self.bin)
        self.assertEqual(receipt["state"], "unverified", receipt)
        self.assertIn(second["generation"], receipt["error"])
        self.assertNotEqual(first["generation"], second["generation"])
        self.assertEqual(snapshot(self.bin), before)

    def test_missing_installation_is_not_created(self):
        receipt = installer.verification_result(self.expected(), self.bin)
        self.assertEqual(receipt["state"], "unverified")
        self.assertFalse(self.bin.exists())

    def test_active_installer_lock_refuses_without_waiting_or_modification(self):
        self.install()
        before = snapshot(self.bin)
        with (self.bin / ".rabs-install.lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            receipt = installer.verification_result(self.expected(), self.bin)
        self.assertEqual(receipt["state"], "unverified", receipt)
        self.assertIn("installation is active", receipt["error"])
        self.assertEqual(snapshot(self.bin), before)

    def test_missing_or_unmanaged_public_link_refuses(self):
        self.install()
        public = self.bin / "rabs-wrap"
        public.rename(self.root / "retained-public-link")
        self.assertEqual(installer.verification_result(self.expected(), self.bin)["state"], "unverified")
        public.symlink_to(self.bundle / "rabs-wrap")
        before = snapshot(self.bin)
        receipt = installer.verification_result(self.expected(), self.bin)
        self.assertEqual(receipt["state"], "unverified", receipt)
        self.assertIn("unmanaged symlink", receipt["error"])
        self.assertEqual(snapshot(self.bin), before)

    def test_symlink_tool_and_extra_generation_entry_refuse(self):
        self.install()
        active = self.bin / installer.CURRENT
        tool = active / "rabsd"
        tool.rename(self.root / "retained-rabsd")
        tool.symlink_to(self.root / "retained-rabsd")
        before = snapshot(self.bin)
        self.assertEqual(installer.verification_result(self.expected(), self.bin)["state"], "unverified")
        self.assertEqual(snapshot(self.bin), before)
        (active / "extra").write_text("unexpected")
        receipt = installer.verification_result(self.expected(), self.bin)
        self.assertEqual(receipt["state"], "unverified", receipt)
        self.assertIn("unexpected", receipt["error"])

    def test_manifest_duplicate_fields_and_oversized_data_refuse(self):
        self.install()
        manifest = self.bin / installer.CURRENT / "manifest.json"
        for content in [b'{"schema":1,"schema":1}', b" " * (installer.TRANSFER_HEADER_BYTES + 1)]:
            manifest.write_bytes(content)
            before = snapshot(self.bin)
            self.assertEqual(installer.verification_result(self.expected(), self.bin)["state"], "unverified")
            self.assertEqual(snapshot(self.bin), before)

    def test_late_executable_replacement_is_detected_even_with_equal_bytes(self):
        self.install()
        expected = self.expected()
        actual = installer.inspect_tool_file
        def replace_earlier(name, *args, **kwargs):
            result = actual(name, *args, **kwargs)
            if name == "rabs-cargo-root":
                old = self.bin / installer.CURRENT / "rabsd"
                old.rename(self.root / "replaced-rabsd")
                shutil.copyfile(self.root / "replaced-rabsd", old)
                old.chmod(0o555)
            return result
        with mock.patch.object(installer, "inspect_tool_file", side_effect=replace_earlier):
            receipt = installer.verification_result(expected, self.bin)
        self.assertEqual(receipt["state"], "unverified", receipt)
        self.assertIn("changed during verification", receipt["error"])

    def test_readonly_verification_request_contains_inspector_and_hashes_only(self):
        wire, header, identity = installer.prepare_verification(self.expected(), str(self.bin))
        self.assertEqual(wire.stat().st_size, installer.TRANSFER_HEADER_BYTES + header["inspector"]["bytes"])
        self.assertEqual(identity, installer.signature(wire.lstat()))
        self.assertNotIn(str(self.marker).encode(), wire.read_bytes())
        self.assertEqual(header["expected"], self.expected())

    def test_late_extra_generation_entry_is_detected_and_preserved(self):
        self.install()
        expected = self.expected()
        actual = installer.inspect_tool_file
        extra = self.bin / installer.CURRENT / "extra.py"
        def add_extra(name, *args, **kwargs):
            result = actual(name, *args, **kwargs)
            if name == "rabs-cargo-root":
                extra.write_text("unexpected input")
            return result
        with mock.patch.object(installer, "inspect_tool_file", side_effect=add_extra):
            receipt = installer.verification_result(expected, self.bin)
        self.assertEqual(receipt["state"], "unverified", receipt)
        self.assertIn("unexpected", receipt["error"])
        self.assertEqual(extra.read_text(), "unexpected input")

    def test_late_current_link_replacement_is_not_a_verified_generation(self):
        first = self.install()
        self.launcher("second")
        self.install()
        expected = self.expected()
        actual = installer.inspect_tool_file
        def switch_current(name, *args, **kwargs):
            result = actual(name, *args, **kwargs)
            if name == "rabs-cargo-root":
                pending = self.bin / ".test-change-current"
                pending.symlink_to(installer.VERSIONS + "/" + first["generation"])
                os.replace(pending, self.bin / installer.CURRENT)
            return result
        with mock.patch.object(installer, "inspect_tool_file", side_effect=switch_current):
            receipt = installer.verification_result(expected, self.bin)
        self.assertEqual(receipt["state"], "unverified", receipt)
        self.assertIn("links changed", receipt["error"])
        self.assertEqual((self.bin / installer.CURRENT).resolve().name, first["generation"])

    def test_lost_ack_is_reconciled_by_cli_without_another_install_or_stage(self):
        deployed = self.deploy(["drop-ack"])
        self.assertEqual(deployed["workers"][0]["state"], "unconfirmed", deployed)
        home = self.root / "drop-ack"
        before = snapshot(home)
        status, receipt, error = self.run_cli(
            "--verify", "--from-image", deployed["transfer_image"], "--ssh", "drop-ack")
        self.assertEqual(status, 0, (receipt, error))
        self.assertEqual(receipt["workers"][0]["state"], "verified")
        self.assertEqual(snapshot(home), before)
        self.assertEqual([call["phase"] for call in self.calls()], ["install", "verify"])
        self.assertFalse(self.marker.exists())
        call = self.calls()[-1]["argv"]
        for required in ["-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oForwardAgent=no", "-oClearAllForwardings=yes"]:
            self.assertIn(required, call)
        self.assertNotIn(str(home), call[-1])

    def test_parallel_verification_keeps_order_and_failure_does_not_retry(self):
        self.deploy(["one", "corrupt"])
        corrupt = self.root / "corrupt" / ".local" / "bin"
        self.corrupt(corrupt / installer.CURRENT / "rabsd")
        before = snapshot(corrupt)
        status, receipt, error = self.run_cli(
            "--verify", "--from-bundle", str(self.bundle), "--ssh", "one", "--ssh", "offline",
            "--ssh", "corrupt", "--ssh", "missing", "--ssh-jobs", "2")
        self.assertEqual(status, 1, (receipt, error))
        self.assertEqual([w["host"] for w in receipt["workers"]], ["one", "offline", "corrupt", "missing"])
        self.assertEqual([w["state"] for w in receipt["workers"]], ["verified", "unverified", "unverified", "unverified"])
        self.assertEqual(snapshot(corrupt), before)
        self.assertFalse((self.root / "missing" / ".local" / "bin").exists())
        self.assertCountEqual([c["host"] for c in self.calls() if c["phase"] == "verify"],
                              ["one", "offline", "corrupt", "missing"])

    def test_malformed_reply_and_output_limit_never_prove_installation(self):
        self.deploy(["banner"])
        status, receipt, error = self.run_cli(
            "--verify", "--from-bundle", str(self.bundle), "--ssh", "banner", "--ssh", "flood")
        self.assertEqual(status, 1, (receipt, error))
        self.assertEqual([w["state"] for w in receipt["workers"]], ["unverified", "unverified"])
        self.assertIn("output exceeded", receipt["workers"][1]["error"])

    def test_verification_deadline_is_bounded(self):
        started = time.monotonic()
        status, receipt, error = self.run_cli(
            "--verify", "--from-bundle", str(self.bundle), "--ssh", "slow", "--ssh-timeout", "1")
        self.assertEqual(status, 1, (receipt, error))
        self.assertEqual(receipt["workers"][0]["state"], "unverified")
        self.assertIn("deadline", receipt["workers"][0]["error"])
        self.assertLess(time.monotonic() - started, 5)

    def test_retained_image_corruption_truncation_and_trailing_bytes_fail_before_ssh(self):
        wire, _, _ = installer.prepare_deployment(self.paths(), None, installer.MIN_DEPLOY_RESERVE)
        original = wire.read_bytes()
        corrupt = bytearray(original)
        corrupt[-1] ^= 1
        for index, data in enumerate([bytes(corrupt), original[:-1], original + b"extra"]):
            path = self.root / ("bad-image-" + str(index))
            path.write_bytes(data)
            status, result, error = self.run_cli("--verify", "--from-image", str(path), "--ssh", "one")
            self.assertEqual(status, 1, (result, error))
            self.assertIsNone(result)
        self.assertEqual(self.calls(), [])

    def test_retained_image_does_not_authorize_reinstall_or_another_destination(self):
        wire, _, _ = installer.prepare_deployment(self.paths(), str(self.bin), installer.MIN_DEPLOY_RESERVE)
        status, _, error = self.run_cli("--from-image", str(wire))
        self.assertEqual(status, 1)
        self.assertIn("requires --verify", error)
        status, _, error = self.run_cli(
            "--verify", "--from-image", str(wire), "--bin-dir", str(self.root / "other"), "--ssh", "one")
        self.assertEqual(status, 1)
        self.assertIn("differs from the retained", error)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.bin.exists())

    def test_archive_verification_uses_actual_expected_members(self):
        self.install()
        archive = self.root / "trusted-release.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as writer:
            for name in installer.TOOLS:
                writer.add(self.bundle / name, arcname=name)
        before = snapshot(self.bin)
        status, receipt, error = self.run_cli(
            "--verify", "--from-archive", str(archive), "--bin-dir", str(self.bin))
        self.assertEqual(status, 0, (receipt, error))
        self.assertEqual(snapshot(self.bin), before)

    def test_verification_reply_binds_expected_bytes_and_readonly_semantics(self):
        installed = self.install()
        expected = self.expected()
        _, header, _ = installer.prepare_verification(expected, str(self.bin))
        receipt = installer.verify_installed(expected, self.bin)
        receipt.update(transport="ssh", inspector_sha256=header["inspector"]["sha256"])
        self.assertEqual(installer.verification_reply(json.dumps(receipt).encode(), header)["generation"],
                         installed["generation"])
        for field, value in [("installation_changed", True), ("services_started", True),
                             ("expected_toolset_sha256", "0" * 64), ("generation", "../other"),
                             ("machine", True), ("bin_dir", "/other")]:
            changed = {**receipt, field: value}
            with self.assertRaises(installer.InstallError, msg=field):
                installer.verification_reply(json.dumps(changed).encode(), header)


if __name__ == "__main__":
    unittest.main()
