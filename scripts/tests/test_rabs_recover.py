#!/usr/bin/env python3
"""Native driver/filesystem/exec regressions; rabsd is an explicit fixture.

No TLS handshake or Rust compiler is simulated as a successful real operation.
Fixture directories are retained, including rejected inputs and daemon records.
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


SCRIPT = Path(__file__).resolve().parents[1] / "rabs-recover"
LOADER = importlib.machinery.SourceFileLoader("rabs_recover_tested", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
RECOVER = importlib.util.module_from_spec(SPEC)
sys.modules[LOADER.name] = RECOVER
LOADER.exec_module(RECOVER)

DAEMON = r'''
import fcntl, hashlib, json, os, pathlib, signal, sys
args = sys.argv[1:]
assert args[0] == "--worker-exec-tls"
assert args[1] in ("--resume", "--resume-from", "--acknowledge")
request_path = args[-2]
fd = int(request_path.rsplit("/", 1)[1])
# Mutating the original AFTER handoff must not replace the checked request.
if os.environ.get("FIXTURE_REPLACE_REQUEST"):
    pathlib.Path(os.environ["FIXTURE_REPLACE_REQUEST"]).write_bytes(b"changed after exec")
raw = pathlib.Path(request_path).read_bytes()
seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
try:
    os.write(fd, b"tamper")
except OSError:
    immutable = True
else:
    immutable = False
with open(os.environ["FIXTURE_LOG"], "a", encoding="utf-8") as out:
    out.write(json.dumps({"args":args, "request_sha256":hashlib.sha256(raw).hexdigest(),
        "request":json.loads(raw), "sealed":immutable, "seals":seals,
        "state":os.environ.get("RABS_STATE_DIR"), "pid":os.getpid(),
        "cwd":os.getcwd(), "marker":os.environ.get("FIXTURE_PRESERVED")}) + "\n")
if os.environ.get("FIXTURE_SIGNAL"):
    os.kill(os.getpid(), signal.SIGTERM)
sys.exit(int(os.environ.get("FIXTURE_STATUS", "0")))
'''


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "memfd_create"),
                     "Linux retained-request handoff")
class RecoveryDriverTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="rabs-recover-test-"))
        self.state = self.base / "dependency-workers"
        self.state.mkdir(mode=0o700)
        self.root = self.state / "result-fixture"
        self.root.mkdir(mode=0o700)
        self.log = self.base / "daemon.jsonl"
        self.daemon = self.base / "rabsd-fixture"
        self.daemon.write_text("#!{}\n{}".format(sys.executable, DAEMON), encoding="utf-8")
        self.daemon.chmod(0o700)
        self.request = {"kind":"canonical-exec", "request_id":17,
                        "program":"/toolchain/bin/rustc", "args":["src/lib.rs", "snow 雪; $(no)"],
                        "dependency_context":{"env":[["SECRET", "NEVER_PRINT_SECRET"]]}}
        self.raw = json.dumps(self.request, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":")).encode("utf-8")
        self.record = {"schema":RECOVER.SCHEMA, "action_key":"rabs.action-key.sha256.v1:" + "cd" * 32,
                       "request_id":17, "request_sha256":hashlib.sha256(self.raw).hexdigest(),
                       "request_file":"request.json", "partial_delivery":"delivery",
                       "transport_state_dir":str(self.state), "execution_state":"unknown",
                       "recovery_mode":"resume-or-acknowledge-only",
                       "publication_authorized":False, "reexecute":False,
                       "remote_configuration":{"remote_protocol":1, "dependency_context":"dependency-exec-v5",
                                               "worker_id":"worker 雪", "worker_spki_sha256":"ab" * 32,
                                               "listen":"127.0.0.1:9123"}}
        self.put(self.root / "request.json", self.raw)
        self.save_record()
        self.env = dict(os.environ)
        self.env.update({"CARGO_RABS_DAEMON":str(self.daemon), "FIXTURE_LOG":str(self.log),
                         "FIXTURE_PRESERVED":"opaque value; $not_a_shell",
                         "RABS_STATE_DIR":str(self.base / "wrong-default-state"),
                         "RABS_COORD_TLS_CA":"/explicit/ca.pem", "RABS_COORD_TLS_CERT":"/explicit/cert.pem",
                         "RABS_COORD_TLS_KEY":"/explicit/key.pem"})
        for name in ("FIXTURE_REPLACE_REQUEST", "FIXTURE_SIGNAL", "FIXTURE_STATUS"):
            self.env.pop(name, None)

    def put(self, path, value):
        data = value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

    def save_record(self):
        self.put(self.root / "recovery.json", self.record)

    def launch(self, *args, env=None, root=None):
        child = subprocess.Popen([sys.executable, "-I", "-S", str(SCRIPT), str(root or self.root), *map(str, args)],
                                 env=self.env if env is None else env, cwd=self.base,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = child.communicate(timeout=5)
        self.last_pid = child.pid
        return subprocess.CompletedProcess(child.args, child.returncode, stdout, stderr)

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def partial(self):
        delivery = self.root / "delivery"
        delivery.mkdir(mode=0o700)
        (delivery / "diagnostics").mkdir(mode=0o700)
        self.put(delivery / "diagnostics/stdout", b"partial\0\xff")
        return delivery

    def refused(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])
        self.assertNotIn(b"NEVER_PRINT_SECRET", result.stdout + result.stderr)
        self.assertEqual((self.root / "request.json").read_bytes(), self.raw)

    def test_inspection_needs_no_daemon_or_credentials_and_discloses_no_request(self):
        env = dict(self.env, CARGO_RABS_DAEMON="/absent/rabsd")
        for name in ("RABS_COORD_TLS_CA", "RABS_COORD_TLS_CERT", "RABS_COORD_TLS_KEY"):
            env.pop(name)
        result = self.launch(env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["outputs_verified"])
        self.assertFalse(report["publication_authorized"])
        self.assertFalse(report["reexecute"])
        self.assertEqual(report["request_id"], 17)
        self.assertNotIn(b"NEVER_PRINT_SECRET", result.stdout + result.stderr)
        self.assertNotIn(b"program", result.stdout)
        self.assertEqual(self.events(), [])
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["recovery.json", "request.json"])

    def test_prefix_resume_hands_off_once_with_exact_pin_state_bytes_and_pid(self):
        previous = self.partial()
        destination = self.base / "new delivery 雪"
        result = self.launch("--resume-to", destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        event, = self.events()
        self.assertEqual(event["args"][:3], ["--worker-exec-tls", "--resume-from", str(previous)])
        self.assertEqual(event["args"][-5:-2], ["127.0.0.1:9123", "worker 雪", "ab" * 32])
        self.assertEqual(event["args"][-1], str(destination))
        self.assertEqual(event["request_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(event["request"], self.request)
        self.assertTrue(event["sealed"])
        self.assertEqual(event["state"], str(self.state))
        self.assertEqual(event["pid"], self.last_pid)
        self.assertEqual(event["cwd"], str(self.base))
        self.assertEqual(event["marker"], self.env["FIXTURE_PRESERVED"])
        self.assertFalse(destination.exists(), "only the native receiver creates delivery storage")
        self.assertEqual((previous / "diagnostics/stdout").read_bytes(), b"partial\0\xff")

    def test_no_partial_directory_selects_resume_not_execution(self):
        result = self.launch("--resume-to", self.base / "new")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[0]["args"][:2], ["--worker-exec-tls", "--resume"])

    def test_explicit_no_prefix_preserves_old_bytes_and_never_retries_compiler(self):
        previous = self.partial()
        result = self.launch("--resume-to", self.base / "fresh", "--no-prefix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[0]["args"][1], "--resume")
        self.assertEqual((previous / "diagnostics/stdout").read_bytes(), b"partial\0\xff")

    def test_acknowledgment_only_delegates_existing_byte_verification(self):
        delivery = self.partial()
        self.put(delivery / "delivery.json", {"fixture":"native operator must verify this"})
        result = self.launch("--acknowledge", delivery)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[0]["args"][:2], ["--worker-exec-tls", "--acknowledge"])
        self.assertEqual(self.events()[0]["args"][-1], str(delivery))

    def test_acknowledgment_can_target_a_separately_resumed_delivery(self):
        delivery = self.base / "resumed"
        delivery.mkdir(mode=0o700)
        self.put(delivery / "delivery.json", b"explicit structurally ordinary marker fixture")
        result = self.launch("--acknowledge", delivery)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[0]["args"][-1], str(delivery))

    def test_exit_status_is_not_swallowed_and_failure_never_reexecutes(self):
        result = self.launch("--resume-to", self.base / "new", env=dict(self.env, FIXTURE_STATUS="37"))
        self.assertEqual(result.returncode, 37)
        self.assertEqual(len(self.events()), 1)
        self.assertNotIn("canonical-exec", self.events()[0]["args"])

    def test_native_operator_receives_signals_as_the_same_process(self):
        result = self.launch("--resume-to", self.base / "new", env=dict(self.env, FIXTURE_SIGNAL="1"))
        self.assertEqual(result.returncode, -signal.SIGTERM)
        self.assertEqual(len(self.events()), 1)

    def test_sealed_handoff_cannot_be_replaced_by_mutating_original_request(self):
        env = dict(self.env, FIXTURE_REPLACE_REQUEST=str(self.root / "request.json"))
        result = self.launch("--resume-to", self.base / "new", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "request.json").read_bytes(), b"changed after exec")
        self.assertEqual(self.events()[0]["request_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertTrue(self.events()[0]["sealed"])

    def test_request_digest_mismatch_refuses_before_any_operator(self):
        self.record["request_sha256"] = "00" * 32
        self.save_record()
        self.refused(self.launch("--resume-to", self.base / "new"))

    def test_unsupported_policy_and_request_ids_refuse(self):
        for field, value in [("schema", "future"), ("reexecute", True), ("reexecute", 0),
                             ("publication_authorized", True), ("execution_state", "finished"),
                             ("request_id", True), ("request_id", 18), ("request_id", 2**64),
                             ("request_file", "../other"), ("partial_delivery", "/other")]:
            with self.subTest(field=field, value=value):
                old = self.record[field]
                self.record[field] = value
                self.save_record()
                self.refused(self.launch("--resume-to", self.base / "new"))
                self.record[field] = old
        self.save_record()

    def test_saved_state_cannot_be_rebound_to_an_unfenced_ledger(self):
        self.record["transport_state_dir"] = str(self.base)
        self.save_record()
        self.refused(self.launch("--resume-to", self.base / "new"))

    def test_invalid_pin_listener_or_worker_refuses_without_network(self):
        config = self.record["remote_configuration"]
        for field, value in [("remote_protocol", True), ("worker_spki_sha256", "0" * 64),
                             ("worker_spki_sha256", "AB" * 32), ("worker_id", "x\ncontrol"),
                             ("listen", "attacker.example:9123"), ("listen", "127.0.0.1:0"),
                             ("listen", "127.0.0.1:65536"), ("listen", "::1:9123")]:
            with self.subTest(field=field, value=value):
                old = config[field]
                config[field] = value
                self.save_record()
                self.refused(self.launch("--resume-to", self.base / "new"))
                config[field] = old
        self.save_record()

    def test_ipv6_listener_is_preserved_without_name_resolution(self):
        self.record["remote_configuration"]["listen"] = "[::1]:9123"
        self.save_record()
        result = self.launch("--resume-to", self.base / "new")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[0]["args"][-5], "[::1]:9123")

    def test_duplicate_or_nonfinite_json_is_never_silently_accepted(self):
        original = (self.root / "recovery.json").read_bytes()
        for malformed in (original[:-1] + b',"reexecute":false}',
                          b'{"nested":{"duplicate":1,"duplicate":2}}',
                          b'{"number":NaN}', b'[]', b'\xff'):
            self.put(self.root / "recovery.json", malformed)
            self.refused(self.launch("--resume-to", self.base / "new"))
        self.save_record()

    def test_nonprivate_files_or_root_are_refused(self):
        for path in (self.root, self.root / "request.json", self.root / "recovery.json"):
            with self.subTest(path=path.name):
                old = path.stat().st_mode & 0o777
                path.chmod(old | 0o040)
                self.refused(self.launch("--resume-to", self.base / "new"))
                path.chmod(old)

    def test_request_symlink_and_root_alias_are_not_followed(self):
        original = self.root / "preserved-request"
        (self.root / "request.json").rename(original)
        (self.root / "request.json").symlink_to(original)
        self.refused(self.launch("--resume-to", self.base / "new"))
        alias = self.state / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.refused(self.launch("--resume-to", self.base / "new", root=alias))

    def test_hardlinked_request_refuses(self):
        os.link(self.root / "request.json", self.base / "another-link")
        self.refused(self.launch("--resume-to", self.base / "new"))

    def test_fifo_record_refuses_without_blocking(self):
        (self.root / "recovery.json").rename(self.root / "preserved-record")
        os.mkfifo(self.root / "recovery.json", 0o600)
        self.refused(self.launch("--resume-to", self.base / "new"))

    def test_oversized_record_refuses(self):
        self.put(self.root / "recovery.json", b" " * (RECOVER.MAX_RECORD + 1))
        self.refused(self.launch("--resume-to", self.base / "new"))

    def test_existing_or_overlapping_destinations_are_never_changed(self):
        existing = self.base / "existing"
        existing.mkdir(mode=0o700)
        self.put(existing / "sentinel", b"preserve")
        for destination in (existing, self.root, self.root / "new", self.state,
                            str(self.base) + "/../escape", self.base / "absent/new"):
            self.refused(self.launch("--resume-to", destination))
        self.assertEqual((existing / "sentinel").read_bytes(), b"preserve")

    def test_linked_destination_parent_is_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.state, target_is_directory=True)
        self.refused(self.launch("--resume-to", alias / "new"))

    def test_partial_delivery_cannot_be_acknowledged(self):
        self.refused(self.launch("--acknowledge", self.partial()))

    def test_no_prefix_requires_resume_and_conflicting_modes_refuse(self):
        for args in (("--no-prefix",), ("--execute",),
                     ("--resume-to", self.base / "new", "--acknowledge", self.root),
                     ("--res", self.base / "new")):
            self.refused(self.launch(*args))

    def test_explicit_missing_daemon_or_credentials_cannot_fall_back(self):
        self.refused(self.launch("--resume-to", self.base / "new", "--rabsd", "/absent/rabsd"))
        self.refused(self.launch("--resume-to", self.base / "new", "--rabsd", SCRIPT))
        env = dict(self.env)
        env.pop("RABS_COORD_TLS_KEY")
        self.refused(self.launch("--resume-to", self.base / "new", env=env))
        env["RABS_COORD_TLS_KEY"] = "relative/private-key"
        self.refused(self.launch("--resume-to", self.base / "new", env=env))

    def test_identity_check_detects_same_size_rewrite_before_handoff(self):
        intent = RECOVER.load_intent(str(self.root))
        self.put(self.root / "request.json", self.raw)
        with self.assertRaises(RECOVER.Refused):
            intent.verify_unchanged()

    def test_later_interrupted_recovery_reuses_selected_prefix_without_new_execution_identity(self):
        original = self.partial()
        later = self.base / "second-interrupted"
        later.mkdir(mode=0o700)
        (later / "diagnostics").mkdir(mode=0o700)
        self.put(later / "diagnostics/stdout", b"larger untrusted retained prefix\0\xff")
        result = self.launch("--resume-to", self.base / "third-attempt", "--prefix-from", later)
        self.assertEqual(result.returncode, 0, result.stderr)
        event, = self.events()
        self.assertEqual(event["args"][:3], ["--worker-exec-tls", "--resume-from", str(later)])
        self.assertEqual(event["request_sha256"], self.record["request_sha256"])
        self.assertEqual(event["state"], str(self.state))
        self.assertNotIn("canonical-exec", event["args"])
        self.assertEqual((original / "diagnostics/stdout").read_bytes(), b"partial\0\xff")
        self.assertEqual((later / "diagnostics/stdout").read_bytes(), b"larger untrusted retained prefix\0\xff")

    def test_selected_prefix_cannot_overlap_the_new_destination(self):
        previous = self.base / "second-interrupted"
        previous.mkdir(mode=0o700)
        for destination in (previous, previous / "new", self.base):
            self.refused(self.launch("--resume-to", destination, "--prefix-from", previous))

    def test_missing_linked_and_nonprivate_selected_prefixes_refuse(self):
        self.refused(self.launch("--resume-to", self.base / "new", "--prefix-from", self.base / "missing"))
        previous = self.base / "previous"
        previous.mkdir(mode=0o750)
        self.refused(self.launch("--resume-to", self.base / "new", "--prefix-from", previous))
        previous.chmod(0o700)
        alias = self.base / "prefix-link"
        alias.symlink_to(previous, target_is_directory=True)
        self.refused(self.launch("--resume-to", self.base / "new", "--prefix-from", alias))

    def test_prefix_selection_is_never_an_implicit_operation(self):
        previous = self.partial()
        for args in (("--prefix-from", previous),
                     ("--prefix-from", previous, "--acknowledge", previous),
                     ("--prefix-from", previous, "--no-prefix", "--resume-to", self.base / "new")):
            self.refused(self.launch(*args))

    def test_worker_unicode_and_byte_bounds_refuse_without_a_native_handoff(self):
        for worker in ("bad\u0085control", "bad\udcffsurrogate", "雪" * 400):
            self.record["remote_configuration"]["worker_id"] = worker
            self.save_record()
            self.refused(self.launch("--resume-to", self.base / "new"))

    def test_private_record_can_use_existing_group_accessible_admission_parent_without_chmod(self):
        self.state.chmod(0o775)
        result = self.launch("--resume-to", self.base / "new")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o775)
        self.assertEqual(self.events()[0]["state"], str(self.state))


if __name__ == "__main__":
    unittest.main(verbosity=2)
