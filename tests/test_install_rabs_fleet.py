"""Target-aware fleet deployment through real local subprocesses and installs.

SSH is replaced by a local process, never a fleet connection. Worker platform
reports are explicit doubles. Native `true` files stand in for x86 RABS tools;
ARM fixtures change only ELF headers and are NEVER executed. This exercises
real archive, framing, hashing, receiver, locking and generation code, not Rust
compilation, remote-host authenticity, ARM execution or cache-hit acceptance.
"""

import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install-rabs"
loader = importlib.machinery.SourceFileLoader("install_rabs_fleet", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
installer = importlib.util.module_from_spec(spec)
loader.exec_module(installer)
X86 = "x86_64-unknown-linux-gnu"
ARM = "aarch64-unknown-linux-gnu"

SSH = r'''#!/usr/bin/env python3
import json, os, pathlib, shlex, subprocess, sys, time
root = pathlib.Path(os.environ["RABS_FLEET_TEST_ROOT"])
host = sys.argv[-2]
command = shlex.split(sys.argv[-1])
assert command[:2] == ["python3", "-c"]
program = command[2]
probe = "rabs-deploy-platform" in program
phase = "probe" if probe else "install"
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps({"host": host, "phase": phase, "argv": sys.argv[1:]}) + "\n")
if host == "offline":
    sys.exit(255)
if host == "slow":
    time.sleep(10)
    sys.exit(0)
if probe and host == "bad-report":
    print('{"kind":"rabs-deploy-platform","kind":"rabs-deploy-platform"}')
    sys.exit(0)
if probe and host == "flood":
    sys.stdout.write("x" * 200000)
    sys.exit(0)
if probe and "gate" in host:
    (root / ("arrived-" + host)).touch()
    deadline = time.monotonic() + 5
    while len(list(root.glob("arrived-*"))) < 2:
        if time.monotonic() >= deadline:
            sys.exit(71)
        time.sleep(0.01)
machine = "aarch64" if host.startswith("arm") or (host == "switch" and not probe) else "x86_64"
if host == "unsupported":
    machine = "armv7l"
home = root / host
home.mkdir(exist_ok=True)
(home / "tmp").mkdir(exist_ok=True)
env = {**os.environ, "HOME": str(home), "TMPDIR": str(home / "tmp")}
# Only the reported/test receiver architecture is replaced. Everything else is
# the actual fixed discovery program or the complete transferred bootstrap.
preamble = "import platform; platform.machine = lambda: " + repr(machine) + "\n"
result = subprocess.run([sys.executable, "-c", preamble + program],
                        stdin=sys.stdin.buffer, capture_output=True, env=env, timeout=15)
sys.stderr.buffer.write(result.stderr)
if host != "drop-ack" or probe:
    sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
'''


@unittest.skipUnless(sys.platform == "linux", "real Linux installer filesystem semantics")
class TargetDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rabs-fleet-test-"))
        client = self.root / "client"
        client.mkdir()
        (client / "ssh").write_text(SSH)
        (client / "ssh").chmod(0o755)
        self.env = {"PATH": str(client) + os.pathsep + os.environ.get("PATH", ""),
                    "RABS_FLEET_TEST_ROOT": str(self.root)}
        self.reserve = installer.MIN_DEPLOY_RESERVE
        self.archives = {}
        self.bundles = {}
        native = Path(shutil.which("true")).read_bytes()
        for target, machine in [(X86, 62), (ARM, 183)]:
            bundle = self.root / target
            bundle.mkdir()
            (bundle / "cargo-rabs").write_text(
                "#!/usr/bin/env python3\nprint(" + repr(target) + ")\n")
            for name in installer.TOOLS[1:]:
                fixture = bytearray(native)
                fixture[18:20] = machine.to_bytes(2, "little")
                (bundle / name).write_bytes(fixture)
            for name in installer.TOOLS:
                (bundle / name).chmod(0o755)
            archive = self.root / ("a space=" + target + ".tar.gz")
            with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as writer:
                for name in installer.TOOLS:
                    writer.add(bundle / name, arcname=name)
            self.archives[target] = archive
            self.bundles[target] = bundle

    def specs(self, targets=(X86, ARM)):
        return [target + "=" + str(self.archives[target]) for target in targets]

    def deploy(self, hosts, targets=(X86, ARM), timeout=10):
        with mock.patch.dict(os.environ, self.env):
            return installer.deploy_targets(self.specs(targets), hosts, None, timeout, self.reserve)

    def calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def current(self, host):
        return self.root / host / ".local" / "bin" / installer.CURRENT

    def assert_no_installer(self, host):
        self.assertFalse(self.current(host).exists())
        self.assertFalse(any(c["host"] == host and c["phase"] == "install" for c in self.calls()))

    def test_mixed_fleet_installs_exact_toolsets_through_real_receiver(self):
        result = self.deploy(["x86-one", "arm-one", "x86-two"])
        self.assertEqual([r["state"] for r in result["workers"]], ["installed"] * 3)
        self.assertEqual([r["target"] for r in result["workers"]], [X86, ARM, X86])
        self.assertEqual(set(result["transfer_images"]), {X86, ARM})
        for worker in result["workers"]:
            target = worker["target"]
            installed = Path(worker["receipt"]["bin_dir"])
            for name in installer.TOOLS:
                expected = (self.bundles[target] / name).read_bytes()
                self.assertEqual((installed / name).read_bytes(), expected)
                self.assertEqual(worker["receipt"]["files"][name]["sha256"],
                                 hashlib.sha256(expected).hexdigest())
            manifest = json.loads((installed / installer.CURRENT / "manifest.json").read_text())
            self.assertEqual(manifest["machine"], installer.TARGET_MACHINES[target])
            self.assertFalse(worker["receipt"]["services_started"])
            self.assertFalse(worker["receipt"]["cargo_config_changed"])
        self.assertEqual(result["workers"][0]["receipt"]["files"],
                         result["workers"][2]["receipt"]["files"])
        # The launcher is real Python. No ARM fixture is ever executed.
        launcher = self.root / "x86-one" / ".local" / "bin" / "cargo-rabs"
        self.assertEqual(subprocess.check_output([str(launcher)], text=True), X86 + "\n")

    def test_dispatcher_architecture_never_selects_worker_images(self):
        with mock.patch.object(installer.platform, "machine", return_value="unsupported-dispatcher"):
            result = self.deploy(["arm-one", "x86-one"])
        self.assertEqual([r["target"] for r in result["workers"]], [ARM, X86])
        self.assertTrue(all(r["state"] == "installed" for r in result["workers"]))

    def test_missing_archive_and_unsupported_host_do_not_receive_installer(self):
        result = self.deploy(["arm-one", "unsupported", "x86-one"], targets=(X86,))
        self.assertEqual([r["state"] for r in result["workers"]],
                         ["not-started", "not-started", "installed"])
        for host, worker in zip(["arm-one", "unsupported"], result["workers"]):
            self.assertFalse(worker["activation_may_have_occurred"])
            self.assert_no_installer(host)
        self.assertIn(ARM, result["workers"][0]["error"])

    def test_failed_discovery_does_not_prevent_healthy_workers(self):
        result = self.deploy(["offline", "bad-report", "flood", "x86-one"], targets=(X86,))
        self.assertEqual([r["state"] for r in result["workers"]],
                         ["not-started"] * 3 + ["installed"])
        for host in ["offline", "bad-report", "flood"]:
            self.assert_no_installer(host)
            self.assertEqual(sum(c["host"] == host for c in self.calls()), 1)
        self.assertIn("output exceeded", result["workers"][2]["error"])

    def test_mislabeled_archive_is_rejected_before_any_network_or_activation(self):
        wrong = [ARM + "=" + str(self.archives[X86])]
        with mock.patch.object(installer, "ssh_exchange") as exchange:
            with self.assertRaisesRegex(installer.InstallError, "native Linux ELF64"):
                installer.deploy_targets(wrong, ["arm-one"], None, 10, self.reserve)
            exchange.assert_not_called()

    def test_incomplete_second_archive_does_not_partially_deploy_first(self):
        with tarfile.open(self.archives[ARM], "w:gz", format=tarfile.USTAR_FORMAT) as writer:
            writer.add(self.bundles[ARM] / "cargo-rabs", arcname="cargo-rabs")
        with mock.patch.object(installer, "ssh_exchange") as exchange:
            with self.assertRaisesRegex(installer.InstallError, "missing RABS tools"):
                installer.deploy_targets(self.specs(), ["x86-one", "arm-one"], None, 10, self.reserve)
            exchange.assert_not_called()

    def test_receiver_rechecks_architecture_after_platform_discovery(self):
        result = self.deploy(["switch"], targets=(X86,))
        worker = result["workers"][0]
        self.assertEqual(worker["state"], "unconfirmed")
        self.assertTrue(worker["activation_may_have_occurred"])
        self.assertIn("native Linux ELF64", worker["error"])
        self.assertFalse(self.current("switch").exists())
        self.assertEqual([c["phase"] for c in self.calls()], ["probe", "install"])

    def test_lost_ack_after_real_install_stays_unconfirmed_and_is_not_retried(self):
        result = self.deploy(["drop-ack"], targets=(X86,))
        self.assertEqual(result["workers"][0]["state"], "unconfirmed")
        self.assertTrue(result["workers"][0]["activation_may_have_occurred"])
        self.assertTrue(self.current("drop-ack").exists())
        self.assertEqual([c["phase"] for c in self.calls()], ["probe", "install"])

    def test_every_probe_and_transfer_keeps_strict_ssh_and_argument_boundaries(self):
        self.deploy(["x86-one"], targets=(X86,))
        for call in self.calls():
            args = call["argv"]
            for flag in ["-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oForwardAgent=no",
                         "-oClearAllForwardings=yes", "-oConnectionAttempts=1"]:
                self.assertIn(flag, args)
            self.assertEqual(args[-3:-1], ["--", "x86-one"])
            self.assertNotIn(str(self.root), args[-1])
        self.assertEqual([c["phase"] for c in self.calls()], ["probe", "install"])

    def test_discovery_spends_the_installation_deadline(self):
        image = (Path("unused"), {}, ())
        with mock.patch.object(installer, "ssh_exchange") as exchange:
            result = installer.deploy_image("worker", image, 10, time.monotonic() - 1)
            self.assertEqual(result["state"], "not-started")
            exchange.assert_not_called()
        started = time.monotonic()
        result = self.deploy(["slow"], targets=(X86,), timeout=1)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(result["workers"][0]["state"], "not-started")
        self.assert_no_installer("slow")

    def test_target_options_are_unambiguous_and_refuse_before_reading_archives(self):
        for specs in [[], ["wrong=x"], [X86], [X86 + "="], [X86 + "=x", X86 + "=y"],
                      [X86 + "=a\0b"], [X86 + "=x", ARM + "=y", X86 + "=z"]]:
            with self.subTest(specs=specs):
                with mock.patch.object(installer, "unpack_archive") as unpack:
                    with self.assertRaises(installer.InstallError):
                        installer.deploy_targets(specs, ["worker"], None, 10, self.reserve)
                    unpack.assert_not_called()
        self.assertEqual(installer.target_archives(self.specs())[X86], self.archives[X86])
        with self.assertRaises(installer.InstallError):
            installer.deploy_targets(self.specs(), [], None, 10, self.reserve)
        self.assertEqual(self.calls(), [])

    def test_platform_parser_refuses_ambiguity_wrong_os_and_old_python(self):
        report = {"kind": "rabs-deploy-platform", "system": "linux",
                  "machine": "x86_64", "python": [3, 9, 0]}
        self.assertEqual(installer.platform_target(json.dumps(report).encode()), X86)
        for field, value in [("system", "darwin"), ("machine", "ARM64"), ("machine", []),
                             ("python", [3, 8, 99]), ("python", [True, 9, 0]),
                             ("python", [3.0, 9, 0]), ("python", [3, 9]),
                             ("python", [3, 9, -1]), ("python", "3.12.0")]:
            changed = {**report, field: value}
            with self.assertRaises(installer.InstallError):
                installer.platform_target(json.dumps(changed).encode())
        for data in [b"null", b"[]", b"{}", b"\xff", b"banner\n" + json.dumps(report).encode(),
                     json.dumps({**report, "extra": 1}).encode(),
                     b'{"kind":"x","kind":"x"}', b"[" * 2000]:
            with self.assertRaises(installer.InstallError):
                installer.platform_target(data)

    def test_cli_exit_status_and_result_distinguish_unstarted_workers(self):
        args = [sys.executable, str(SCRIPT), "--from-target", self.specs((X86,))[0],
                "--ssh", "arm-one", "--ssh", "x86-one", "--ssh-reserve-mib", "64"]
        result = subprocess.run(args, env={**os.environ, **self.env}, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([r["state"] for r in report["workers"]], ["not-started", "installed"])
        self.assert_no_installer("arm-one")

    def test_archives_can_change_after_sealing_without_replacing_installed_bytes(self):
        original = installer.ssh_exchange
        calls = []
        def alter_archive(*args):
            if not calls:
                self.archives[X86].write_bytes(b"changed after all images were sealed")
            calls.append(args)
            return original(*args)
        with mock.patch.object(installer, "ssh_exchange", side_effect=alter_archive):
            result = self.deploy(["x86-one", "x86-two"], targets=(X86,))
        self.assertTrue(all(r["state"] == "installed" for r in result["workers"]))
        self.assertEqual(len(result["transfer_images"]), 1)
        self.assertEqual(result["workers"][0]["receipt"]["files"],
                         result["workers"][1]["receipt"]["files"])

    def test_parallel_mixed_fleet_bounds_clients_and_preserves_host_order(self):
        original = installer.ssh_exchange
        lock = threading.Lock()
        counts = {"active": 0, "peak": 0}
        def observed(*args):
            with lock:
                counts["active"] += 1
                counts["peak"] = max(counts["peak"], counts["active"])
            try:
                return original(*args)
            finally:
                with lock:
                    counts["active"] -= 1
        hosts = ["gate-x86", "arm-gate", "x86-one", "arm-two"]
        with mock.patch.dict(os.environ, self.env):
            with mock.patch.object(installer, "ssh_exchange", side_effect=observed):
                result = installer.deploy_targets(self.specs(), hosts, None, 15, self.reserve, jobs=2)
        self.assertEqual([r["host"] for r in result["workers"]], hosts)
        self.assertEqual([r["target"] for r in result["workers"]], [X86, ARM, X86, ARM])
        self.assertTrue(all(r["state"] == "installed" for r in result["workers"]), result)
        self.assertEqual(counts, {"active": 0, "peak": 2})
        for host in hosts:
            self.assertEqual([c["phase"] for c in self.calls() if c["host"] == host],
                             ["probe", "install"])

    def test_parallel_single_image_deployment_uses_the_existing_receiver(self):
        paths = installer.source_files(self.bundles[X86], None)
        with mock.patch.dict(os.environ, self.env):
            result = installer.deploy(paths, ["x86-one", "offline", "x86-two"],
                                      None, 10, self.reserve, jobs=2)
        self.assertEqual([r["state"] for r in result["workers"]],
                         ["installed", "unconfirmed", "installed"])
        self.assertEqual(len(self.calls()), 3)
        self.assertTrue(Path(result["transfer_image"]).is_file())
        self.assertEqual(result["workers"][0]["receipt"]["files"],
                         result["workers"][2]["receipt"]["files"])

    def test_invalid_parallelism_is_refused_before_snapshot_or_network(self):
        paths = installer.source_files(self.bundles[X86], None)
        for jobs in [0, -1, 9, True, 1.5, "2"]:
            with self.subTest(jobs=jobs):
                with mock.patch.object(installer, "prepare_deployment") as prepare:
                    with mock.patch.object(installer, "unpack_archive") as unpack:
                        with self.assertRaises(installer.InstallError):
                            installer.deploy(paths, ["worker"], None, 10, self.reserve, jobs=jobs)
                        with self.assertRaises(installer.InstallError):
                            installer.deploy_targets(self.specs(), ["worker"], None, 10,
                                                     self.reserve, jobs=jobs)
                        prepare.assert_not_called()
                        unpack.assert_not_called()
        self.assertEqual(self.calls(), [])

    def test_cancelled_exchange_never_starts_an_ssh_client(self):
        wire = self.root / "wire"
        wire.write_bytes(b"")
        cancelled = threading.Event()
        cancelled.set()
        image = (wire, {}, installer.signature(wire.stat()))
        with mock.patch.object(installer.subprocess, "Popen") as start:
            with self.assertRaisesRegex(installer.InstallError, "cancelled"):
                installer.ssh_exchange(["ssh"], wire, image[2], 30, cancelled)
            result = installer.deploy_image("worker", image, 30, cancelled=cancelled)
            self.assertEqual(result["state"], "not-started")
            self.assertFalse(result["activation_may_have_occurred"])
            start.assert_not_called()

    def test_cancellation_reaps_clients_even_after_both_output_pipes_close(self):
        for close_pipes in [False, True]:
            with self.subTest(close_pipes=close_pipes):
                wire = self.root / ("wire-" + str(close_pipes))
                wire.write_bytes(b"unchanged")
                marker = self.root / ("started-" + str(close_pipes))
                program = ("import os, pathlib, sys, time; "
                           + ("os.close(1); os.close(2); " if close_pipes else "")
                           + "pathlib.Path(sys.argv[1]).touch(); time.sleep(30)")
                cancelled = threading.Event()
                failures = []
                processes = []
                original = subprocess.Popen
                def start(*args, **kwargs):
                    process = original(*args, **kwargs)
                    processes.append(process)
                    return process
                def exchange():
                    try:
                        installer.ssh_exchange([sys.executable, "-c", program, str(marker)],
                                               wire, installer.signature(wire.stat()), 30, cancelled)
                    except installer.InstallError as error:
                        failures.append(str(error))
                with mock.patch.object(installer.subprocess, "Popen", side_effect=start):
                    thread = threading.Thread(target=exchange)
                    thread.start()
                    try:
                        deadline = time.monotonic() + 5
                        while not marker.exists() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue(marker.exists(), "native child did not reach the test boundary")
                    finally:
                        cancelled.set()
                        thread.join(5)
                self.assertFalse(thread.is_alive(), "cancelled client owner did not join")
                self.assertEqual(len(processes), 1)
                self.assertIsNotNone(processes[0].poll(), "owned client was not reaped")
                self.assertEqual(len(failures), 1)
                self.assertIn("cancelled", failures[0])
                self.assertEqual(wire.read_bytes(), b"unchanged")

    def test_batch_failure_cancels_and_joins_an_inflight_owner(self):
        started = threading.Event()
        joined = threading.Event()
        def operation(host, cancelled):
            if host == "failing":
                self.assertTrue(started.wait(3))
                raise RuntimeError("injected batch failure")
            started.set()
            self.assertTrue(cancelled.wait(3), "shutdown did not notify the active owner")
            joined.set()
            return installer.not_started(host, "cancelled")
        with self.assertRaisesRegex(RuntimeError, "injected batch failure"):
            installer.run_hosts(["failing", "waiting"], 2, operation)
        self.assertTrue(joined.is_set(), "batch returned before the active owner joined")

    def test_discovery_cannot_reset_the_remaining_transfer_budget(self):
        budgets = []
        def exchange(argv, wire, identity, budget, cancelled):
            budgets.append(budget)
            if "rabs-deploy-platform" in argv[-1]:
                return json.dumps({"kind": "rabs-deploy-platform", "system": "linux",
                                   "machine": "x86_64", "python": [3, 9, 0]}).encode()
            # Explicit receipt double: this case tests clock plumbing only;
            # native receiver integration is covered in the other tests.
            header = json.loads(wire.read_bytes()[:installer.TRANSFER_HEADER_BYTES])
            return json.dumps({"kind": "rabs-installed", "transport": "ssh",
                               "services_started": False, "cargo_config_changed": False,
                               "installer_sha256": header["files"][0]["sha256"],
                               "files": {e["name"]: {"bytes": e["bytes"], "sha256": e["sha256"]}
                                         for e in header["files"][1:]},
                               "generation": "gen-fixture", "bin_dir": "/fixture/bin"}).encode()
        with mock.patch.object(installer, "ssh_exchange", side_effect=exchange):
            with mock.patch.object(installer.time, "monotonic", side_effect=[100.0, 109.25]):
                result = installer.deploy_targets(self.specs((X86,)), ["worker"], None, 10, self.reserve)
        self.assertEqual(budgets, [10, 0.75])
        self.assertEqual(result["workers"][0]["state"], "installed")


if __name__ == "__main__":
    unittest.main()
