#!/usr/bin/env python3
"""Production Python handoffs and files; the daemon is an explicit executable fixture.

No compiler, TLS handshake, native allocation, or result verification is claimed.
The fixture reads the real sealed descriptor and refuses all execution commands.
"""
import hashlib
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

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/rabs-recover"
LAUNCHER = ROOT / "scripts/cargo-rabs"


def module(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    loader.exec_module(value)
    return value


recover = module("canonical_recovery_tested", SCRIPT)
launcher = module("canonical_launcher_tested", LAUNCHER)
DRIVER = r'''
import fcntl, hashlib, json, os, pathlib, signal, sys
args = sys.argv[1:]
assert args[0] == "--worker-exec-tls", args
assert args[1] in ("--resume", "--resume-from", "--acknowledge"), args
assert not any(arg in ("--prepare-from", "--worker-build-tls", "canonical-exec") for arg in args)
if os.environ.get("REPLACE_REQUEST"):
    pathlib.Path(os.environ["REPLACE_REQUEST"]).write_bytes(b"changed after handoff")
path = args[-2]
assert path.startswith("/proc/self/fd/")
fd = int(path.rsplit("/", 1)[1])
raw = pathlib.Path(path).read_bytes()
required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required == required
try:
    os.write(fd, b"mutate")
except OSError:
    pass
else:
    raise AssertionError("unsealed request")
with open(os.environ["RECOVERY_TEST_LOG"], "a") as log:
    log.write(json.dumps({"argv":args, "request":json.loads(raw),
        "digest":hashlib.sha256(raw).hexdigest(), "state":os.environ["RABS_STATE_DIR"],
        "pid":os.getpid(), "input":sys.stdin.buffer.read().hex()}) + "\n")
if os.environ.get("RECOVERY_TEST_SIGNAL"):
    os.kill(os.getpid(), signal.SIGTERM)
sys.exit(int(os.environ.get("RECOVERY_TEST_EXIT", "0")))
'''


class CanonicalRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="rabs-canonical-recovery-"))
        self.state = self.base / "original-admission"
        self.state.mkdir(mode=0o700)
        self.root = self.base / "operation 雪"
        self.root.mkdir(mode=0o700)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir(mode=0o700)
        self.daemon = self.base / "rabsd-fixture"
        self.daemon.write_text("#!" + sys.executable + " -S\n" + DRIVER)
        self.daemon.chmod(0o700)
        self.log = self.base / "driver.jsonl"
        self.request = {
            "kind":"canonical-exec", "request_id":17, "program":"/__rabs/toolchain/bin/cargo",
            "args":["check", "--message-format=json", "--target-dir", "/__rabs/out/cargo"],
            "source_manifest":{"manifest_sha256":"cd" * 32, "files":[]},
            "artifacts":{"unit":"cargo", "tree":"tree-files-v1", "files":[], "cargo":"cargo-json-v1"},
            "command_context":{"env":{"PRIVATE":"DO_NOT_PRINT_CANONICAL_REQUEST"}},
        }
        self.raw = json.dumps(self.request, ensure_ascii=False, indent=1).encode()
        self.record = {"version":"canonical-cargo-v1", "request_id":"allocate",
            "operation_directory":str(self.root), "automatic_retry":False, "publication_authorized":False,
            "prepared_build_argv":["/stored/program/must/not/run", "--worker-build-tls", "--replay-diagnostics",
                "127.0.0.1:41234", "worker-a", "ab" * 32,
                str(self.bundle), str(self.root / "delivery"), str(self.root / "outputs")]}
        self.put(self.bundle / "request.json", self.raw)
        self.put(self.root / "spec.json", {"request_id":"allocate", "NEVER_EXECUTE_AGAIN":True})
        self.save()
        self.env = {"PATH":os.defpath, "HOME":str(self.base / "wrong-home"),
            "RABS_STATE_DIR":str(self.base / "wrong-state"), "CARGO_RABS_DAEMON":str(self.daemon),
            "RECOVERY_TEST_LOG":str(self.log), "RABS_COORD_TLS_CA":"/fixture/ca.pem",
            "RABS_COORD_TLS_CERT":"/fixture/cert.pem", "RABS_COORD_TLS_KEY":"/fixture/key.pem"}

    def put(self, path, value):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)

    def save(self):
        self.put(self.root / "operation.json", self.record)

    def persisted(self):
        self.record["recovery"] = {
            "schema":"rabs-canonical-cargo-recovery-v1", "transport_state_dir":str(self.state),
            "request_file":"bundle/request.json", "partial_delivery":"delivery",
            "recovery_mode":"resume-or-acknowledge-only", "worker_id":"worker-a",
            "worker_spki_sha256":"ab" * 32, "listen":"127.0.0.1:41234",
            "reexecute":False, "publication_authorized":False,
        }
        self.save()

    def invoke(self, *args, explicit=True, env=None, root=None):
        command = [sys.executable, "-I", "-S", str(SCRIPT), str(root or self.root)]
        if explicit:
            command += ["--canonical-state-dir", str(self.state)]
        child = subprocess.Popen(command + list(map(str, args)), env=env or self.env,
            cwd=self.base, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = child.communicate(b"\0\xfforiginal-input", timeout=5)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
        self.pid = child.pid
        return subprocess.CompletedProcess(command, child.returncode, out, err)

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def refused(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.events(), [])
        self.assertNotIn(b"DO_NOT_PRINT_CANONICAL_REQUEST", result.stdout + result.stderr)

    def partial(self):
        previous = self.root / "delivery"
        previous.mkdir(mode=0o700)
        (previous / "diagnostics").mkdir(mode=0o700)
        self.put(previous / "diagnostics/stdout", b"partial\0\xff")
        return previous

    def test_legacy_canonical_operation_needs_explicit_original_state_not_environment(self):
        self.refused(self.invoke(explicit=False, env=dict(self.env, RABS_STATE_DIR=str(self.state))))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["origin"], "canonical-cargo")
        self.assertIsNone(report["action_key"], "a Cargo request is not a live action-cache key")
        self.assertEqual(report["request_id"], 17)
        self.assertFalse(report["outputs_verified"])
        self.assertFalse(report["reexecute"])
        self.assertFalse(report["publication_authorized"])
        self.assertNotIn(b"DO_NOT_PRINT_CANONICAL_REQUEST", result.stdout + result.stderr)
        self.assertEqual(self.events(), [])

    def test_recorded_state_and_pin_survive_different_home_and_operator_environment(self):
        self.persisted()
        result = self.invoke("--resume-to", self.base / "recovered", explicit=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        event, = self.events()
        self.assertEqual(event["state"], str(self.state))
        self.assertEqual(event["argv"][-5:-2], ["127.0.0.1:41234", "worker-a", "ab" * 32])
        self.assertEqual(event["argv"][:2], ["--worker-exec-tls", "--resume"])
        self.assertEqual(event["request"], self.request)
        self.assertEqual(event["digest"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(event["pid"], self.pid)
        self.assertEqual(bytes.fromhex(event["input"]), b"\0\xfforiginal-input")
        self.assertFalse((self.base / "recovered").exists(), "native receiver owns destination creation")

    def test_prefix_resume_preserves_original_data_spec_and_prepared_request(self):
        previous = self.partial()
        spec = (self.root / "spec.json").read_bytes()
        result = self.invoke("--resume-to", self.base / "new")
        self.assertEqual(result.returncode, 0, result.stderr)
        event, = self.events()
        self.assertEqual(event["argv"][:3], ["--worker-exec-tls", "--resume-from", str(previous)])
        self.assertEqual((previous / "diagnostics/stdout").read_bytes(), b"partial\0\xff")
        self.assertEqual((self.bundle / "request.json").read_bytes(), self.raw)
        self.assertEqual((self.root / "spec.json").read_bytes(), spec)

    def test_later_partial_and_acknowledgment_use_the_same_result_only_driver(self):
        later = self.base / "later"
        later.mkdir(mode=0o700)
        self.put(later / "delivery.json", {"fixture":"native verifier still must check bytes"})
        result = self.invoke("--resume-to", self.base / "new", "--prefix-from", later)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[-1]["argv"][:3], ["--worker-exec-tls", "--resume-from", str(later)])
        result = self.invoke("--acknowledge", later)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[-1]["argv"][1], "--acknowledge")
        self.assertEqual(len(self.events()), 2)

    def test_current_launcher_operation_is_accepted_without_reconstructing_worker_arguments(self):
        source, tools, operations = (self.base / name for name in ("source", "tools", "operations"))
        for path in (source, tools / "bin", operations):
            path.mkdir(parents=True, mode=0o700)
        for name in ("cargo", "rustc"):
            tool = tools / "bin" / name
            tool.write_text("#!/bin/sh\nexit 98\n")
            tool.chmod(0o700)
        profile = self.base / "profile.json"
        self.put(profile, {"version":"canonical-cargo-v1", "listen":"127.0.0.1:41234", "worker":"worker-a",
            "worker_spki_sha256":"ab" * 32, "source_root":str(source), "toolchain_root":str(tools),
            "operation_root":str(operations)})
        _, argv, _ = launcher.canonical_invocation(str(profile), ["check"],
            dict(self.env, RABS_STATE_DIR=str(self.state)))
        root = Path(argv[5]).parent
        bundle = root / "bundle"
        bundle.mkdir(mode=0o700)
        # Stand in only for the native preparation output; no native execution
        # or proof of source/manifest validity is claimed by this fixture.
        self.put(bundle / "request.json", self.raw)
        result = self.invoke("--resume-to", self.base / "result", root=root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[0]["request"], self.request)
        self.assertEqual(json.loads((root / "spec.json").read_text())["request_id"], "allocate")

    def test_partial_preparation_cannot_fall_back_to_specification_or_allocate_an_id(self):
        (self.bundle / "request.json").rename(self.bundle / "retained-request")
        self.refused(self.invoke("--resume-to", self.base / "new"))
        for value in ("allocate", 0, True, -1, 2**64):
            self.put(self.bundle / "request.json", dict(self.request, request_id=value))
            self.refused(self.invoke("--resume-to", self.base / "new"))
        self.assertEqual(json.loads((self.root / "spec.json").read_text())["request_id"], "allocate")

    def test_legacy_numeric_identity_is_preserved_and_mismatch_refuses(self):
        self.record["request_id"] = 18
        self.save()
        self.refused(self.invoke("--resume-to", self.base / "new"))
        self.record["request_id"] = 17
        self.save()
        result = self.invoke("--resume-to", self.base / "new")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[0]["request"]["request_id"], 17)

    def test_missing_admission_state_is_not_recreated(self):
        self.state.rename(self.base / "retained-state")
        self.refused(self.invoke("--resume-to", self.base / "new"))
        self.assertFalse(self.state.exists())

    def test_recorded_state_cannot_be_overridden_or_downgraded_to_legacy(self):
        self.persisted()
        self.record["recovery"]["transport_state_dir"] = str(self.base / "different")
        self.save()
        self.refused(self.invoke("--resume-to", self.base / "new"))
        self.record["recovery"] = None
        self.save()
        self.refused(self.invoke("--resume-to", self.base / "new"))

    def test_invalid_metadata_never_selects_execution_or_a_foreign_request_path(self):
        original = json.loads(json.dumps(self.record))
        cases = [("automatic_retry", True), ("publication_authorized", 0), ("request_id", True),
                 ("version", "v2"), ("operation_directory", str(self.base / "other"))]
        for field, value in cases:
            self.record = dict(original, **{field:value})
            self.save()
            self.refused(self.invoke("--resume-to", self.base / "new"))
        for index, value in ((1, "--worker-build"), (2, "--prepare-from"),
                             (3, "worker.example:1234"), (4, "bad\nworker"), (5, "0" * 64),
                             (6, str(self.base / "foreign")), (7, str(self.base / "foreign"))):
            self.record = json.loads(json.dumps(original))
            self.record["prepared_build_argv"][index] = value
            self.save()
            self.refused(self.invoke("--resume-to", self.base / "new"))

    def test_nested_recovery_fields_are_bound_to_recorded_worker_and_fixed_names(self):
        self.persisted()
        original = dict(self.record["recovery"])
        for field, value in (("schema", "future"), ("request_file", "spec.json"),
                             ("partial_delivery", "../../other"), ("worker_id", "worker-b"),
                             ("worker_spki_sha256", "cd" * 32), ("reexecute", True),
                             ("publication_authorized", True), ("recovery_mode", "execute")):
            self.record["recovery"] = dict(original, **{field:value})
            self.save()
            self.refused(self.invoke("--resume-to", self.base / "new", explicit=False))

    def test_complete_source_and_compiler_trees_are_not_needed_for_result_recovery(self):
        self.assertEqual(sorted(path.name for path in self.bundle.iterdir()), ["request.json"])
        result = self.invoke("--resume-to", self.base / "new")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[0]["argv"][1], "--resume")
        self.assertFalse((self.bundle / "source").exists())
        self.assertFalse((self.bundle / "toolchain").exists())

    def test_request_substitution_after_exec_cannot_change_sealed_handoff(self):
        result = self.invoke("--resume-to", self.base / "new",
            env=dict(self.env, REPLACE_REQUEST=str(self.bundle / "request.json")))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.bundle / "request.json").read_bytes(), b"changed after handoff")
        self.assertEqual(self.events()[0]["digest"], hashlib.sha256(self.raw).hexdigest())

    def test_changed_request_record_or_bundle_is_detected_before_handoff(self):
        for selected in (self.bundle / "request.json", self.root / "operation.json"):
            intent = recover.load_intent(str(self.root), str(self.state))
            original = selected.read_bytes()
            self.put(selected, original + b" ")
            with self.assertRaises(recover.Refused):
                intent.verify_unchanged()
            self.put(selected, original)
        intent = recover.load_intent(str(self.root), str(self.state))
        self.bundle.rename(self.root / "retained-bundle")
        self.bundle.mkdir(mode=0o700)
        self.put(self.bundle / "request.json", self.raw)
        with self.assertRaises(recover.Refused):
            intent.verify_unchanged()

    def test_fifo_links_or_nonprivate_records_refuse_without_rendezvous(self):
        path = self.bundle / "request.json"
        path.chmod(0o640)
        self.refused(self.invoke("--resume-to", self.base / "new"))
        path.chmod(0o600)
        path.rename(self.bundle / "retained")
        os.mkfifo(path, 0o600)
        self.refused(self.invoke("--resume-to", self.base / "new"))
        path.rename(self.bundle / "retained-fifo")
        path.symlink_to(self.bundle / "retained")
        self.refused(self.invoke("--resume-to", self.base / "new"))

    def test_duplicate_records_or_mixed_formats_fail_closed(self):
        raw = (self.root / "operation.json").read_bytes()
        self.put(self.root / "operation.json", raw[:-1] + b',"automatic_retry":false}')
        self.refused(self.invoke("--resume-to", self.base / "new"))
        self.save()
        self.put(self.root / "recovery.json", {})
        self.refused(self.invoke("--resume-to", self.base / "new"))

    def test_native_status_and_signals_are_preserved_without_retry(self):
        result = self.invoke("--resume-to", self.base / "one", env=dict(self.env, RECOVERY_TEST_EXIT="37"))
        self.assertEqual(result.returncode, 37)
        result = self.invoke("--resume-to", self.base / "two", env=dict(self.env, RECOVERY_TEST_SIGNAL="1"))
        self.assertEqual(result.returncode, -signal.SIGTERM)
        self.assertEqual(len(self.events()), 2)

    def test_existing_or_overlapping_destination_remains_untouched(self):
        destination = self.base / "existing"
        destination.mkdir(mode=0o700)
        self.put(destination / "keep", b"unchanged")
        for target in (destination, self.root / "child", self.base):
            self.refused(self.invoke("--resume-to", target))
        self.assertEqual((destination / "keep").read_bytes(), b"unchanged")

    def test_dependency_intent_cannot_take_a_canonical_state_override(self):
        (self.root / "operation.json").rename(self.root / "retained-operation")
        self.put(self.root / "recovery.json", {})
        self.refused(self.invoke("--resume-to", self.base / "new"))

    def test_existing_dependency_record_still_uses_its_own_state_pin_and_digest(self):
        live = self.state / "result-live"
        live.mkdir(mode=0o700)
        self.put(live / "request.json", self.raw)
        record = {"schema":recover.SCHEMA, "action_key":"recorded-action",
            "request_id":17, "request_sha256":hashlib.sha256(self.raw).hexdigest(),
            "request_file":"request.json", "partial_delivery":"delivery",
            "transport_state_dir":str(self.state), "execution_state":"unknown",
            "recovery_mode":"resume-or-acknowledge-only", "publication_authorized":False, "reexecute":False,
            "remote_configuration":{"remote_protocol":1, "listen":"127.0.0.1:41234",
                                    "worker_id":"worker-a", "worker_spki_sha256":"ab" * 32}}
        self.put(live / "recovery.json", record)
        result = self.invoke("--resume-to", self.base / "live-recovered", explicit=False, root=live)
        self.assertEqual(result.returncode, 0, result.stderr)
        event, = self.events()
        self.assertEqual(event["state"], str(self.state))
        self.assertEqual(event["request"], self.request)
        self.assertEqual(event["argv"][1], "--resume")
        self.assertEqual((live / "request.json").read_bytes(), self.raw)

    def test_program_or_artifact_contract_mismatch_refuses_before_native_handoff(self):
        for request in (dict(self.request, program="/bin/sh"), dict(self.request, artifacts=None),
                        dict(self.request, source_manifest=None), dict(self.request, dependency_context={})):
            self.put(self.bundle / "request.json", request)
            self.refused(self.invoke("--resume-to", self.base / "new"))


if __name__ == "__main__":
    unittest.main()
