#!/usr/bin/env python3
"""Production launcher handoffs using a labeled native-driver executable fixture.

The subprocess, exec, socket inode, signals and retained files are real. The
fixture does not run the Rust daemon, cancel a compiler, or prove TLS behavior.
"""
import copy
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
loader = importlib.machinery.SourceFileLoader("cargo_rabs_controls", str(LAUNCHER))
spec = importlib.util.spec_from_loader(loader.name, loader)
launcher = importlib.util.module_from_spec(spec)
loader.exec_module(launcher)

# Deliberately not the real daemon: it makes the one-exec boundary observable.
DRIVER = r'''
import json, os, signal, sys
args = sys.argv[1:]
assert args[0] in ("--job-status", "--job-cancel", "--job-wait", "--job-resume",
                   "--job-recover-local", "--job-acknowledge", "--worker-build-tls"), args
payload = sys.stdin.buffer.read()
record = {"pid":os.getpid(), "argv":args, "env":dict(os.environ), "stdin":payload.hex()}
fd = os.environ.get("FIXTURE_FD")
if fd is not None:
    record["inherited_fd"] = os.read(int(fd), 128).hex()
with open(os.environ["FIXTURE_LOG"], "a") as target:
    target.write(json.dumps(record) + "\n")
sys.stdout.buffer.write(bytes.fromhex(os.environ.get("FIXTURE_STDOUT", "")))
sys.stderr.buffer.write(bytes.fromhex(os.environ.get("FIXTURE_STDERR", "")))
sys.stdout.buffer.flush()
sys.stderr.buffer.flush()
if os.environ.get("FIXTURE_SIGNAL"):
    os.kill(os.getpid(), int(os.environ["FIXTURE_SIGNAL"]))
raise SystemExit(int(os.environ.get("FIXTURE_EXIT", "0")))
'''


class JobControls(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory(prefix="rabs-controls-")
        self.addCleanup(self.owner.cleanup)
        self.root = Path(self.owner.name)
        self.root.chmod(0o700)
        self.job_id = "ab" * 16
        self.operation = self.root / ("cargo-" + self.job_id)
        self.operation.mkdir(mode=0o700)
        self.endpoint = self.root / "daemon.sock"
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.socket.close)
        self.socket.bind(str(self.endpoint))
        self.endpoint.chmod(0o600)
        self.driver = self.root / "installed-rabsd"
        self.driver.write_text("#!" + sys.executable + "\n" + DRIVER)
        self.driver.chmod(0o700)
        self.log = self.root / "invocations.jsonl"
        saved = str(self.root / "previous-installation-rabsd")
        placement = ["127.0.0.1:6513", "worker-a", "31" * 32]
        placement += [str(self.operation / name) for name in ("bundle", "delivery", "outputs")]
        self.record = {
            "version": "canonical-cargo-v1", "request_id": "allocate",
            "operation_directory": str(self.operation),
            "automatic_retry": False, "publication_authorized": False,
            "job_id": self.job_id, "daemon_socket": str(self.endpoint),
            "job_submit_argv": [saved, "--job-submit-allocated", self.job_id] + placement,
            "job_status_argv": [saved, "--job-status", self.job_id],
            "job_wait_argv": [saved, "--job-wait", self.job_id],
            "job_cancel_argv": [saved, "--job-cancel", self.job_id],
        }
        self.write_record(self.record)
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root),
                    "CARGO_RABS_DAEMON": str(self.driver), "FIXTURE_LOG": str(self.log),
                    "RABS_SOCKET_PATH": str(self.root / "wrong-ambient.sock"),
                    "RABS_STATE_DIR": str(self.root / "original-state"),
                    "RABS_COORD_TLS_KEY": str(self.root / "local-tls.key"),
                    "APP_VERSION": "ambient-do-not-change"}

    def write_record(self, value):
        path = self.operation / "operation.json"
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def logs(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def invoke(self, args=(), *, env=None, pass_fds=(), stdin=b"", operation=None):
        command = [sys.executable, "-I", "-S", str(LAUNCHER), "rabs", "--rabs-recover",
                   str(self.operation if operation is None else operation)] + list(args)
        child = subprocess.Popen(command, env=dict(self.env, **(env or {})), pass_fds=pass_fds,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = child.communicate(stdin, timeout=10)
        except BaseException:
            child.kill()
            child.communicate()
            raise
        return child.returncode, out, err, child.pid

    def refused(self, args, **kwargs):
        before = self.logs()
        code, out, err, _ = self.invoke(args, **kwargs)
        self.assertEqual(code, 2, (args, out, err))
        self.assertEqual(out, b"")
        self.assertNotIn(b"Traceback", err)
        self.assertIn(b"canonical recovery refused", err)
        self.assertEqual(self.logs(), before, "invalid input must not execute a driver")

    def test_status_and_cancel_exec_once_with_saved_job_and_socket(self):
        before = (self.operation / "operation.json").read_bytes()
        for option, action in [("--status", "--job-status"), ("--cancel", "--job-cancel")]:
            with self.subTest(option=option):
                count = len(self.logs())
                code, out, err, pid = self.invoke([option])
                self.assertEqual((code, out, err), (0, b"", b""))
                self.assertEqual(len(self.logs()), count + 1)
                record = self.logs()[-1]
                self.assertEqual(record["pid"], pid, "launcher must exec rather than supervise")
                self.assertEqual(record["argv"], [action, self.job_id])
                self.assertEqual(record["env"]["RABS_SOCKET_PATH"], str(self.endpoint))
                self.assertEqual(record["env"]["CARGO_RABS_CANONICAL_ACTIVE"], "1")
                for name in ("RABS_STATE_DIR", "RABS_COORD_TLS_KEY", "APP_VERSION"):
                    self.assertEqual(record["env"][name], self.env[name])
                self.assertEqual((self.operation / "operation.json").read_bytes(), before)
                self.assertEqual(sorted(p.name for p in self.operation.iterdir()), ["operation.json"])

    def test_status_is_not_a_compiler_result_and_cancel_is_not_completion(self):
        for option, response in [
            ("--status", b'{"state":"running","exit_code":null}\n'),
            ("--status", b'{"state":"completed","exit_code":101}\n'),
            ("--status", b'{"state":"uncertain","execution_may_have_run":true}\n'),
            ("--cancel", b'{"state":"cancelling","execution_may_have_run":true}\n'),
        ]:
            with self.subTest(option=option, response=response):
                code, out, err, _ = self.invoke([option], env={"FIXTURE_STDOUT": response.hex()})
                self.assertEqual((code, out, err), (0, response, b""))
                self.assertEqual(self.logs()[-1]["argv"], ["--job-" + option[2:], self.job_id])

    def test_native_refusal_and_ambiguous_control_failure_never_retry(self):
        for option in ("--status", "--cancel"):
            for status in (1, 2, 75, 101, 127):
                with self.subTest(option=option, status=status):
                    before = len(self.logs())
                    code, out, err, _ = self.invoke([option], env={
                        "FIXTURE_EXIT": str(status), "FIXTURE_STDERR": b"fixture refused\n".hex()})
                    self.assertEqual((code, out, err), (status, b"", b"fixture refused\n"))
                    self.assertEqual(len(self.logs()), before + 1)

    def test_binary_streams_inherited_descriptor_and_signals_survive_handoff(self):
        for option in ("--status", "--cancel"):
            read, write = os.pipe()
            try:
                os.write(write, b"jobserver-like-owned-descriptor")
                os.close(write)
                write = None
                code, out, err, _ = self.invoke([option], pass_fds=(read,), stdin=b"\x00\xffin\n",
                    env={"FIXTURE_FD": str(read), "FIXTURE_STDOUT": b"\x00\xffout\n".hex(),
                         "FIXTURE_STDERR": b"\xfeerr\n".hex()})
                self.assertEqual((code, out, err), (0, b"\x00\xffout\n", b"\xfeerr\n"))
                self.assertEqual(self.logs()[-1]["stdin"], b"\x00\xffin\n".hex())
                self.assertEqual(self.logs()[-1]["inherited_fd"], b"jobserver-like-owned-descriptor".hex())
            finally:
                os.close(read)
                if write is not None:
                    os.close(write)
            code, _, _, _ = self.invoke([option], env={"FIXTURE_SIGNAL": str(signal.SIGTERM)})
            self.assertEqual(code, -signal.SIGTERM)

    def test_control_needs_no_profile_bundle_receipt_or_source_and_never_reads_template(self):
        bundle = self.operation / "bundle"
        bundle.mkdir(mode=0o700)
        # Opening this as a request would block: controls must never consult it.
        os.mkfifo(bundle / "request.json", 0o600)
        (self.operation / "spec.json").write_bytes(b"invalid preparation intent\xff")
        before = sorted(str(p.relative_to(self.operation)) for p in self.operation.rglob("*"))
        for option in ("--status", "--cancel"):
            code, _, err, _ = self.invoke([option])
            self.assertEqual(code, 0, err)
            self.assertEqual(sorted(str(p.relative_to(self.operation)) for p in self.operation.rglob("*")), before)
            self.assertTrue(stat.S_ISFIFO((bundle / "request.json").lstat().st_mode))

    def test_control_options_are_exclusive_valueless_and_do_not_select_submission(self):
        paths = ("--resume-to", "--delivery", "--prefix-from", "--acknowledge")
        for option in ("--status", "--cancel"):
            bad = [[option, option], [option, "--cancel" if option == "--status" else "--status"],
                   [option, "value"], [option + "=true"], [option, "--"], [option, "--job-submit-allocated"]]
            for path in paths:
                bad += [[option, path, str(self.root / "next")],
                        [path, str(self.root / "next"), option]]
            for args in bad:
                with self.subTest(args=args):
                    self.refused(args)
        for args in [["--submit"], ["--execute"], ["--prepare-from", str(self.root)],
                     ["--job-cancel", self.job_id], ["--status", "--wait"]]:
            self.refused(args)

    def test_direct_worker_operations_refuse_job_controls_without_touching_request(self):
        direct = {name: self.record[name] for name in (
            "version", "request_id", "operation_directory", "automatic_retry", "publication_authorized")}
        direct["prepared_build_argv"] = [str(self.driver), "--worker-build-tls", "--replay-diagnostics"]
        direct["prepared_build_argv"] += self.record["job_submit_argv"][3:]
        for identity in ("allocate", 19):
            direct["request_id"] = identity
            self.write_record(direct)
            for option in ("--status", "--cancel"):
                self.refused([option])

    def test_all_saved_job_identities_are_revalidated_for_both_controls(self):
        for field in ("job_status_argv", "job_cancel_argv", "job_wait_argv", "job_submit_argv"):
            for mutation in ("id", "verb", "executable", "extra"):
                changed = copy.deepcopy(self.record)
                if mutation == "id": changed[field][2] = "cd" * 16
                if mutation == "verb": changed[field][1] = "--job-submit-allocated"
                if mutation == "executable": changed[field][0] = "/another/driver"
                if mutation == "extra": changed[field].append("--execute")
                # The submit record already has this verb: use an execution verb instead.
                if mutation == "verb" and field == "job_submit_argv": changed[field][1] = "--worker-exec-tls"
                self.write_record(changed)
                for option in ("--status", "--cancel"):
                    with self.subTest(field=field, mutation=mutation, option=option):
                        self.refused([option])

    def test_record_privacy_authority_and_duplicate_fields_still_refuse(self):
        path = self.operation / "operation.json"
        for option in ("--status", "--cancel"):
            for field, value in [("automatic_retry", True), ("publication_authorized", True),
                                 ("job_id", "cd" * 16), ("request_id", 19),
                                 ("operation_directory", str(self.root / "other"))]:
                changed = copy.deepcopy(self.record); changed[field] = value
                self.write_record(changed); self.refused([option])
            self.write_record(self.record); path.chmod(0o644); self.refused([option])
            self.write_record(self.record); self.operation.chmod(0o755)
            try: self.refused([option])
            finally: self.operation.chmod(0o700)
            self.write_record(self.record)
            text = path.read_text(); path.write_text(text[:-1] + ',"job_id":"' + self.job_id + '"}')
            self.refused([option])

    def test_changed_socket_and_unsafe_endpoint_never_fall_back_to_ambient_daemon(self):
        for target in (self.root / "absent.sock", self.driver):
            changed = copy.deepcopy(self.record); changed["daemon_socket"] = str(target)
            self.write_record(changed)
            for option in ("--status", "--cancel"): self.refused([option])
        alias = self.root / "alias.sock"; alias.symlink_to(self.endpoint)
        changed = copy.deepcopy(self.record); changed["daemon_socket"] = str(alias)
        self.write_record(changed)
        for option in ("--status", "--cancel"): self.refused([option])
        self.write_record(self.record)
        self.root.chmod(0o777)
        try:
            for option in ("--status", "--cancel"): self.refused([option])
        finally: self.root.chmod(0o700)

    def test_changed_driver_is_resolved_and_old_saved_argv_is_not_executed(self):
        historical = Path(self.record["job_cancel_argv"][0])
        historical.write_text("#!/bin/sh\nprintf must-not-run\nexit 99\n")
        historical.chmod(0o700)
        for option in ("--status", "--cancel"):
            code, out, err, _ = self.invoke([option])
            self.assertEqual((code, out, err), (0, b"", b""))
            self.refused([option], env={"CARGO_RABS_DAEMON": str(LAUNCHER)})

    def test_native_exec_failure_keeps_record_and_does_not_start_another_process(self):
        bad = self.root / "invalid-executable"
        bad.write_text("not an executable format\n"); bad.chmod(0o700)
        before = (self.operation / "operation.json").read_bytes()
        for option in ("--status", "--cancel"):
            code, out, err, _ = self.invoke([option], env={"CARGO_RABS_DAEMON": str(bad)})
            self.assertEqual(code, 127, err)
            self.assertEqual(out, b"")
            self.assertIn(b"cannot execute canonical recovery driver", err)
            self.assertEqual((self.operation / "operation.json").read_bytes(), before)
            self.assertEqual(self.logs(), [])

    def test_existing_daemon_recovery_controls_remain_exact(self):
        complete = self.operation / "delivery"; complete.mkdir(mode=0o700)
        prefix = self.root / "prefix"; prefix.mkdir(mode=0o700)
        new = self.root / "new-delivery"
        cases = [([], ["--job-wait", self.job_id]),
                 (["--resume-to", str(new)], ["--job-resume", self.job_id, str(new)]),
                 (["--resume-to", str(new), "--prefix-from", str(prefix)],
                  ["--job-resume", self.job_id, str(new), str(prefix)]),
                 (["--prefix-from", str(prefix), "--resume-to", str(new)],
                  ["--job-resume", self.job_id, str(new), str(prefix)]),
                 (["--delivery", str(complete)], ["--job-recover-local", self.job_id, str(complete)]),
                 (["--acknowledge", str(complete)], ["--job-acknowledge", self.job_id, str(complete)])]
        for args, expected in cases:
            with self.subTest(args=args):
                code, _, err, _ = self.invoke(args)
                self.assertEqual(code, 0, err)
                self.assertEqual(self.logs()[-1]["argv"], expected)
                self.assertFalse(new.exists())

    def test_native_command_mapping_does_not_mutate_the_callers_environment(self):
        original = dict(self.env)
        for option in ("--status", "--cancel"):
            daemon, command, environment = launcher.canonical_recovery_invocation(
                [str(self.operation), option], self.env)
            self.assertEqual(daemon, str(self.driver))
            self.assertEqual(command, [str(self.driver), "--job-" + option[2:], self.job_id])
            self.assertEqual(self.env, original)
            self.assertIsNot(environment, self.env)

    def test_controls_accept_the_record_created_by_the_real_canonical_launcher(self):
        source, toolchain, operations = (self.root / name for name in ("source", "toolchain", "operations"))
        for root in (source, toolchain, operations):
            root.mkdir(mode=0o700)
        (toolchain / "bin").mkdir(mode=0o700)
        for name in ("cargo", "rustc"):
            tool = toolchain / "bin" / name
            tool.write_text("#!/bin/sh\nexit 99\n")
            tool.chmod(0o700)
        (source / "Cargo.toml").write_text("[package]\nname='fixture'\nversion='0.1.0'\n")
        profile = self.root / "profile.json"
        profile.write_text(json.dumps({
            "version": "canonical-cargo-v1", "listen": "127.0.0.1:6513",
            "worker": "worker-a", "worker_spki_sha256": "31" * 32,
            "source_root": str(source), "toolchain_root": str(toolchain),
            "operation_root": str(operations), "daemon_socket": str(self.endpoint),
            "env": {"APP_VERSION": "explicit-worker-value"},
        }))
        # Production preparation of intent, not fixture-generated operation.json.
        # No native preparation or toolchain executable runs in this call.
        _, command, _ = launcher.canonical_invocation(str(profile), ["check"], self.env)
        self.assertEqual(command[1:3], ["--job-build", "--prepare-from"])
        operation = Path(command[4]).parent
        saved = {p.name: p.read_bytes() for p in operation.iterdir()}
        record = json.loads(saved["operation.json"])
        self.assertEqual(record["request_id"], "allocate")
        source.rename(self.root / "retired-source")
        toolchain.rename(self.root / "retired-toolchain")
        profile.rename(self.root / "retired-profile")
        for option in ("--status", "--cancel"):
            code, _, err, _ = self.invoke([option], operation=operation)
            self.assertEqual(code, 0, err)
            result = self.logs()[-1]
            self.assertEqual(result["argv"], ["--job-" + option[2:], record["job_id"]])
            self.assertEqual(result["env"]["APP_VERSION"], "ambient-do-not-change")
            self.assertEqual({p.name: p.read_bytes() for p in operation.iterdir()}, saved)
            self.assertEqual(list(operations.iterdir()), [operation])

    def test_existing_direct_recovery_keeps_worker_request_and_prefix_contract(self):
        direct = {name: self.record[name] for name in (
            "version", "request_id", "operation_directory", "automatic_retry", "publication_authorized")}
        direct["prepared_build_argv"] = [str(self.driver), "--worker-build-tls", "--replay-diagnostics"]
        direct["prepared_build_argv"] += self.record["job_submit_argv"][3:]
        self.write_record(direct)
        bundle, delivery, output = (self.operation / name for name in ("bundle", "delivery", "outputs"))
        bundle.mkdir(mode=0o700)
        request = bundle / "request.json"
        request.write_bytes(b'{"request_id":41,"kind":"canonical-exec"}')
        request.chmod(0o600)
        saved = request.read_bytes()
        prefix = self.root / "old-prefix"; prefix.mkdir(mode=0o700)
        new = self.root / "new-direct"
        complete = self.root / "complete-direct"; complete.mkdir(mode=0o700)
        for args, flags, destination in [
            ([], ["--resume"], delivery),
            (["--resume-to", str(new)], ["--resume"], new),
            (["--delivery", str(complete)], ["--resume"], complete),
            (["--resume-to", str(new), "--prefix-from", str(prefix)], ["--resume-from", str(prefix)], new),
        ]:
            with self.subTest(args=args):
                code, _, err, _ = self.invoke(args)
                self.assertEqual(code, 0, err)
                expected = ["--worker-build-tls", "--replay-diagnostics"] + flags
                expected += self.record["job_submit_argv"][3:6] + [str(bundle), str(destination), str(output)]
                self.assertEqual(self.logs()[-1]["argv"], expected)
                self.assertEqual(request.read_bytes(), saved)
                self.assertFalse(new.exists())


if __name__ == "__main__":
    unittest.main()
