"""Real deployment framing and installation over a local SSH process substitute.

No fleet host is contacted. Native `true` executables stand in for RABS binaries;
these tests prove transfer/activation behavior, not compilation or cache serving.
Fixtures and generations are retained so no cleanup touches unrelated files.
"""

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install-rabs"
loader = importlib.machinery.SourceFileLoader("install_rabs_ssh", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
installer = importlib.util.module_from_spec(spec)
loader.exec_module(installer)


SSH_SUBSTITUTE = r'''#!/usr/bin/env python3
import json, os, pathlib, shlex, subprocess, sys, time
root = pathlib.Path(os.environ["RABS_SSH_TEST_ROOT"])
host = sys.argv[-2]
with (root / "ssh-calls.jsonl").open("a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
if host == "offline":
    print("test peer unavailable", file=sys.stderr)
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
# SSH concatenates its remote command; execute the exact quoted command here.
result = subprocess.run(shlex.split(sys.argv[-1]), stdin=sys.stdin.buffer,
                        capture_output=True, env=env, timeout=15)
sys.stderr.buffer.write(result.stderr)
if host != "drop-ack":
    if host == "banner":
        print("unexpected stdout banner", flush=True)
    sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
'''


@unittest.skipUnless(sys.platform == "linux", "Linux worker deployment")
class SSHDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rabs-ssh-test-"))
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.ssh_bin = self.root / "client-bin"
        self.ssh_bin.mkdir()
        (self.ssh_bin / "ssh").write_text(SSH_SUBSTITUTE)
        (self.ssh_bin / "ssh").chmod(0o755)
        executable = shutil.which("true")
        self.assertIsNotNone(executable)
        for name in installer.TOOLS[1:]:
            shutil.copyfile(executable, self.bundle / name)
            (self.bundle / name).chmod(0o755)
        self.launcher("first")
        self.env = {"PATH": str(self.ssh_bin) + os.pathsep + os.environ.get("PATH", ""),
                    "RABS_SSH_TEST_ROOT": str(self.root)}
        self.reserve = installer.MIN_DEPLOY_RESERVE

    def launcher(self, label):
        (self.bundle / "cargo-rabs").write_text(
            "#!/usr/bin/env python3\nprint(" + repr(label) + ")\n")
        (self.bundle / "cargo-rabs").chmod(0o755)

    def paths(self):
        return installer.source_files(self.bundle, None)

    def image(self, destination=None):
        return installer.prepare_deployment(self.paths(), destination, self.reserve)

    def deploy(self, hosts, destination=None, timeout=10):
        with mock.patch.dict(os.environ, self.env):
            return installer.deploy(self.paths(), hosts, destination, timeout, self.reserve)

    def calls(self):
        path = self.root / "ssh-calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def receive(self, wire_bytes):
        home = self.root / "receiver-home"
        home.mkdir(exist_ok=True)
        (home / "tmp").mkdir(exist_ok=True)
        process = subprocess.run([sys.executable, "-c", installer.REMOTE_BOOTSTRAP],
                                 input=wire_bytes, capture_output=True, timeout=10,
                                 env={**os.environ, "HOME": str(home), "TMPDIR": str(home / "tmp")})
        return process, home / ".local" / "bin"

    def test_real_bootstrap_installs_exact_native_files_and_uses_remote_home(self):
        wire, header, _ = self.image()
        process, target = self.receive(wire.read_bytes())
        self.assertEqual(process.returncode, 0, process.stderr)
        receipt = installer.deployment_reply(process.stdout, header)
        self.assertEqual(receipt["bin_dir"], str(target))
        self.assertFalse(receipt["services_started"])
        self.assertFalse(receipt["cargo_config_changed"])
        for name in installer.TOOLS:
            self.assertEqual((target / name).read_bytes(), (self.bundle / name).read_bytes())
            self.assertEqual((target / name).resolve().parent.name, receipt["generation"])
        self.assertEqual(subprocess.check_output([str(target / "cargo-rabs")], text=True), "first\n")
        self.assertEqual(subprocess.run([str(target / "rabsd")], timeout=5).returncode, 0)
        self.assertTrue((Path(receipt["staging_dir"]) / "install-rabs").is_file())

    def test_multiple_workers_use_one_snapshot_and_strict_ssh_options(self):
        result = self.deploy(["one", "two"])
        self.assertEqual([worker["state"] for worker in result["workers"]], ["installed"] * 2)
        self.assertEqual(len(self.calls()), 2)
        for host, call in zip(["one", "two"], self.calls()):
            self.assertIn("-oBatchMode=yes", call)
            self.assertIn("-oStrictHostKeyChecking=yes", call)
            self.assertIn("-oForwardAgent=no", call)
            self.assertIn("-oClearAllForwardings=yes", call)
            self.assertEqual(call[-3:-1], ["--", host])
            self.assertNotIn(str(self.bundle), call[-1])
            self.assertTrue((self.root / host / ".local" / "bin" / "rabsd").exists())
        self.assertTrue(Path(result["transfer_image"]).is_file())
        self.assertEqual(result["workers"][0]["receipt"]["files"],
                         result["workers"][1]["receipt"]["files"])

    def test_upgrade_retains_previous_generation_and_public_symlink_inodes(self):
        first = self.deploy(["one"])["workers"][0]["receipt"]
        target = Path(first["bin_dir"])
        old = (target / installer.CURRENT).resolve()
        links = {name: (target / name).lstat().st_ino for name in installer.TOOLS}
        self.launcher("second")
        second = self.deploy(["one"])["workers"][0]["receipt"]
        self.assertNotEqual(first["generation"], second["generation"])
        self.assertEqual(subprocess.check_output([str(old / "cargo-rabs")], text=True), "first\n")
        self.assertEqual(subprocess.check_output([str(target / "cargo-rabs")], text=True), "second\n")
        self.assertEqual(links, {name: (target / name).lstat().st_ino for name in installer.TOOLS})

    def test_failed_peer_does_not_prevent_other_workers_and_is_not_retried(self):
        result = self.deploy(["offline", "one"])
        self.assertEqual([worker["state"] for worker in result["workers"]], ["unconfirmed", "installed"])
        self.assertTrue(result["workers"][0]["activation_may_have_occurred"])
        self.assertEqual([call[-2] for call in self.calls()], ["offline", "one"])

    def test_lost_acknowledgment_reports_unknown_even_when_installation_completed(self):
        result = self.deploy(["drop-ack"])
        self.assertEqual(result["workers"][0]["state"], "unconfirmed")
        self.assertTrue(result["workers"][0]["activation_may_have_occurred"])
        self.assertTrue((self.root / "drop-ack" / ".local" / "bin" / "rabsd").exists())
        self.assertEqual(len(self.calls()), 1)

    def test_stdout_banner_is_not_a_success_receipt(self):
        result = self.deploy(["banner"])
        self.assertEqual(result["workers"][0]["state"], "unconfirmed")

    def test_absolute_timeout_and_output_bound_stop_only_the_owned_client(self):
        started = time.monotonic()
        with mock.patch.object(installer.subprocess, "Popen", wraps=subprocess.Popen) as timed_start:
            result = self.deploy(["slow"], timeout=1)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(result["workers"][0]["state"], "unconfirmed")
        self.assertIn("deadline", result["workers"][0]["error"])
        # Test the byte limit independently of the short deadline. A correct
        # client may time out before a heavily loaded peer even starts Python;
        # that is not evidence that the output bound failed. Neither limit in
        # production changes, and the flood must still hit the byte-limit path.
        with mock.patch.object(installer.subprocess, "Popen", wraps=subprocess.Popen) as flood_start:
            flooded = self.deploy(["flood"], timeout=10)
        self.assertEqual(flooded["workers"][0]["state"], "unconfirmed")
        self.assertIn("output exceeded", flooded["workers"][0]["error"])
        # A client killed before Python starts cannot log from the child.
        # Count actual parent-side launches, including that legitimate case.
        self.assertEqual([call.args[0][-2] for call in timed_start.call_args_list], ["slow"])
        self.assertEqual([call.args[0][-2] for call in flood_start.call_args_list], ["flood"])

    def test_corrupt_truncated_and_extra_payload_never_activate(self):
        wire, header, _ = self.image()
        original = wire.read_bytes()
        offset = installer.TRANSFER_HEADER_BYTES + header["files"][0]["bytes"]
        changed = bytearray(original)
        changed[offset] ^= 1
        for data in [bytes(changed), original[:-1], original + b"extra"]:
            with self.subTest(length=len(data)):
                process, target = self.receive(data)
                self.assertNotEqual(process.returncode, 0)
                self.assertFalse((target / installer.CURRENT).exists())

    def test_installer_corruption_is_rejected_before_executing_it(self):
        wire, _, _ = self.image()
        changed = bytearray(wire.read_bytes())
        changed[installer.TRANSFER_HEADER_BYTES + 10] ^= 1
        process, target = self.receive(bytes(changed))
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"installer digest mismatch", process.stderr)
        self.assertFalse(target.exists())

    def test_wrong_architecture_cannot_replace_an_installed_generation(self):
        first = self.deploy(["one"])["workers"][0]["receipt"]
        current = Path(first["bin_dir"]) / installer.CURRENT
        before = os.readlink(current)
        path = self.bundle / "rabs-wkr"
        data = bytearray(path.read_bytes())
        data[18:20] = (183 if installer.host_machine() == 62 else 62).to_bytes(2, "little")
        path.write_bytes(data)
        result = self.deploy(["one"])
        self.assertEqual(result["workers"][0]["state"], "unconfirmed")
        self.assertIn("native Linux ELF64", result["workers"][0]["error"])
        self.assertEqual(os.readlink(current), before)

    def test_destination_spaces_and_shell_characters_are_data_not_command_text(self):
        destination = str(self.root / "a space;$(touch INJECTED)'quoted" / "bin")
        result = self.deploy(["one"], destination)
        self.assertEqual(result["workers"][0]["state"], "installed")
        self.assertEqual(result["workers"][0]["receipt"]["bin_dir"], destination)
        self.assertNotIn(destination, self.calls()[0][-1])
        self.assertTrue((Path(destination) / "rabsd").exists())
        self.assertFalse((self.root / "INJECTED").exists())

    def test_input_replacement_before_transfer_is_refused_without_connecting(self):
        wire, _, identity = self.image()
        wire.chmod(0o600)
        with wire.open("ab") as writer:
            writer.write(b"unexpected")
        with mock.patch.object(installer.subprocess, "Popen") as start:
            with self.assertRaisesRegex(installer.InstallError, "image changed"):
                installer.ssh_exchange(["ssh"], wire, identity, 1)
            start.assert_not_called()

    def test_mutable_input_is_detected_before_a_transfer_image_can_be_used(self):
        original = installer.copy_transfer_file

        def replace_prior(source, writer, limit, expected, executable):
            result = original(source, writer, limit, expected, executable)
            if Path(source).name == "rabs-wkr":
                self.launcher("changed during capture")
            return result

        with mock.patch.object(installer, "copy_transfer_file", side_effect=replace_prior):
            with self.assertRaisesRegex(installer.InstallError, "input changed"):
                self.deploy(["one"])
        self.assertEqual(self.calls(), [])

    def test_unsafe_hosts_and_options_are_refused_before_snapshot_or_network(self):
        for hosts in [[], ["one", "one"], ["-oProxyCommand=anything"], ["host;bad"],
                      ["a\nb"], [""], ["x" * 256], [str(i) for i in range(33)]]:
            with self.subTest(hosts=hosts):
                with mock.patch.object(installer, "prepare_deployment") as prepare:
                    with self.assertRaises(installer.InstallError):
                        installer.deploy(self.paths(), hosts, None, 10, self.reserve)
                    prepare.assert_not_called()
        for destination, timeout, reserve in [("relative", 10, self.reserve),
                                              (None, 0, self.reserve), (None, 3601, self.reserve),
                                              (None, 10, 0), (None, 10, 65 * 1024**3)]:
            with self.assertRaises(installer.InstallError):
                installer.deploy(self.paths(), ["one"], destination, timeout, reserve)
        self.assertEqual(self.calls(), [])

    def test_receiver_disk_refusal_precedes_installer_activation(self):
        wire, header, _ = self.image()
        data = wire.read_bytes()[installer.TRANSFER_HEADER_BYTES:]
        size = header["files"][0]["bytes"]
        with mock.patch.object(installer, "deployment_space", side_effect=installer.InstallError("no room")):
            with mock.patch.object(installer, "install") as activate:
                with self.assertRaisesRegex(installer.InstallError, "no room"):
                    installer.receive_deployment(header, io.BytesIO(data[size:]), data[:size])
                activate.assert_not_called()

    def test_header_inventory_and_receipt_identity_are_strict(self):
        wire, header, _ = self.image()
        for change in [lambda h: h.update(schema=True),
                       lambda h: h["files"].reverse(),
                       lambda h: h["files"][1].update(name="../escape"),
                       lambda h: h["files"][1].update(bytes=True),
                       lambda h: h["files"][1].update(sha256="0" * 63),
                       lambda h: h.update(reserve_bytes=0)]:
            altered = json.loads(json.dumps(header))
            change(altered)
            with self.assertRaises(installer.InstallError):
                installer.validate_deployment_header(altered)
        process, _ = self.receive(wire.read_bytes())
        self.assertEqual(process.returncode, 0, process.stderr)
        good = json.loads(process.stdout)
        for change in [lambda r: r.update(services_started=True),
                       lambda r: r.update(cargo_config_changed=True),
                       lambda r: r.update(installer_sha256="0" * 64),
                       lambda r: r.update(generation="../bad"),
                       lambda r: r["files"]["rabsd"].update(sha256="0" * 64)]:
            altered = json.loads(json.dumps(good))
            change(altered)
            with self.assertRaises(installer.InstallError):
                installer.deployment_reply(json.dumps(altered).encode(), header)
        duplicated = process.stdout.rstrip()[:-1] + b',"kind":"rabs-installed"}'
        with self.assertRaises(installer.InstallError):
            installer.deployment_reply(duplicated, header)

    def test_cli_reports_aggregate_failure_and_preserves_cargo_config(self):
        one = self.root / "one"
        (one / ".cargo").mkdir(parents=True)
        configuration = one / ".cargo" / "config.toml"
        configuration.write_text('[build]\nrustc-wrapper="keep-this"\n')
        before = configuration.read_bytes()
        process = subprocess.run([sys.executable, str(SCRIPT), "--from-bundle", str(self.bundle),
                                  "--ssh", "one", "--ssh", "offline", "--ssh-reserve-mib", "64"],
                                 env={**os.environ, **self.env}, capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 1, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["kind"], "rabs-deployed")
        self.assertEqual([worker["state"] for worker in result["workers"]], ["installed", "unconfirmed"])
        self.assertEqual(configuration.read_bytes(), before)
        self.assertFalse(result["services_started"])

    def test_cli_deploys_the_release_archive_without_installing_core_rch(self):
        archive_path = self.root / "release.tar.gz"
        with tarfile.open(archive_path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name in installer.TOOLS:
                archive.add(self.bundle / name, arcname=name)
            member = tarfile.TarInfo("rch")
            member.size = 4
            archive.addfile(member, io.BytesIO(b"core"))
        process = subprocess.run([sys.executable, str(SCRIPT), "--from-archive", str(archive_path),
                                  "--ssh", "one", "--ssh-reserve-mib", "64"],
                                 env={**os.environ, **self.env}, capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        receipt = result["workers"][0]["receipt"]
        target = Path(receipt["bin_dir"])
        self.assertFalse((target / "rch").exists())
        self.assertEqual((target / "rabsd").read_bytes(), (self.bundle / "rabsd").read_bytes())

    def test_cli_deploys_split_profiles_without_a_local_native_machine_assumption(self):
        checkout = self.root / "checkout"
        scripts = checkout / "scripts"
        scripts.mkdir(parents=True)
        copied_installer = scripts / "install-rabs"
        shutil.copyfile(SCRIPT, copied_installer)
        shutil.copyfile(self.bundle / "cargo-rabs", scripts / "cargo-rabs")
        (scripts / "cargo-rabs").chmod(0o755)
        target = checkout / "target" / "selected-platform"
        for name, profile in [("rabs-wrap", "wrapper-release"), ("rabsd", "daemon-release"),
                              ("rabs-wkr", "daemon-release")]:
            directory = target / profile
            directory.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.bundle / name, directory / name)
            (directory / name).chmod(0o755)
        process = subprocess.run([sys.executable, str(copied_installer), "--from-build", str(target),
                                  "--ssh", "one", "--ssh-reserve-mib", "64"],
                                 env={**os.environ, **self.env}, capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr)
        receipt = json.loads(process.stdout)["workers"][0]["receipt"]
        self.assertEqual(set(receipt["files"]), set(installer.TOOLS))
        # Host-machine admission belongs to the receiver, not the dispatcher.
        with mock.patch.object(installer, "host_machine", side_effect=AssertionError("local admission")):
            result = self.deploy(["two"])
        self.assertEqual(result["workers"][0]["state"], "installed")

    def test_invalid_remote_options_do_not_extract_an_archive(self):
        for arguments in [["--ssh", "bad;host"], ["--ssh", "one", "--ssh-reserve-mib", "0"],
                          ["--ssh", "one", "--ssh-timeout", "3601"],
                          ["--ssh", "one", "--bin-dir", "relative"]]:
            with mock.patch.object(installer, "unpack_archive") as extract:
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(installer.main(["--from-archive", "never-read.tar.gz"] + arguments), 1)
                extract.assert_not_called()

    def test_existing_local_cli_default_still_uses_the_local_home(self):
        home = self.root / "local-home"
        home.mkdir()
        process = subprocess.run([sys.executable, str(SCRIPT), "--from-bundle", str(self.bundle)],
                                 env={**os.environ, "HOME": str(home)}, capture_output=True,
                                 text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        receipt = json.loads(process.stdout)
        self.assertEqual(receipt["bin_dir"], str(home / ".local" / "bin"))
        self.assertEqual(receipt["kind"], "rabs-installed")
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
