#!/usr/bin/env python3
"""Execute the daemon's real storage-health shell helper with fault injection.

    python3 scripts/test_source_registry_health.py -v
    RCH_TEST_SHELL=/bin/bash python3 scripts/test_source_registry_health.py -v

No Rust implementation is re-created here. The exact production shell helper
is executed; only its registry argument and external-command failures vary.
These tests do not claim to simulate a power cut or run the daemon circuit.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "rchd/src/source_registry_health.sh"
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")
SENTINEL = b"health_check\n"
ERROR = b"RCH_SOURCE_REGISTRY_UNWRITABLE"


class SourceRegistryHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rch-registry-health-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry = self.root / "authority" / "claims-v1"
        self.script = SCRIPT.read_text()

    def run_probe(self, prefix: str = "", *, registry: Path | None = None,
                  user: int | None = None) -> subprocess.CompletedProcess[bytes]:
        kwargs = {"user": user, "group": user, "extra_groups": []} if user is not None else {}
        return subprocess.run(
            [SHELL, "-c", prefix + "\n" + self.script +
             '\nrch_source_registry_health "$1"', "rch-registry-health",
             str(self.registry if registry is None else registry)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            cwd=self.root, **kwargs,
        )

    def assert_healthy(self, result: subprocess.CompletedProcess[bytes]) -> None:
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, SENTINEL, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertFalse(list(self.root.rglob(".health-probe.*")))

    def assert_refused(self, result: subprocess.CompletedProcess[bytes],
                       reason: bytes | None = None) -> None:
        self.assertEqual(result.returncode, 74, result.stderr)
        self.assertNotIn(b"health_check", result.stdout)
        self.assertIn(ERROR, result.stderr)
        if reason is not None:
            self.assertIn(reason, result.stderr)

    def seed_registry(self) -> dict[Path, tuple[bytes, int]]:
        for directory in (self.registry, self.registry / "released",
                          self.registry / "cancelled", self.registry / "quarantine"):
            directory.mkdir(parents=True, exist_ok=True)
        records = {
            "aa.bb.claim": b"/a/live/project\n",
            "cc.dd.pending": b"incomplete legacy bytes",
            "ee.ff.cancelling": b"/a/cancelling/project\n",
            "released/11.22.claim": b"/a/released/project\n",
            "cancelled/33.44.claim": b"/a/cancelled/project\n",
            "quarantine/55.66.pending": b"incomplete evidence",
        }
        result = {}
        for name, content in records.items():
            path = self.registry / name
            path.write_bytes(content)
            result[path] = (content, path.stat().st_ino)
        return result

    def assert_records_unchanged(self, records: dict[Path, tuple[bytes, int]]) -> None:
        for path, (content, inode) in records.items():
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(path.stat().st_ino, inode)

    def test_first_probe_creates_private_registry_directories(self) -> None:
        self.assert_healthy(self.run_probe())
        for path in (self.registry.parent, self.registry, self.registry / "released",
                     self.registry / "cancelled", self.registry / "quarantine"):
            self.assertTrue(path.is_dir())
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_existing_records_and_inodes_are_untouched(self) -> None:
        records = self.seed_registry()
        self.assert_healthy(self.run_probe())
        self.assert_records_unchanged(records)

    def test_does_not_repair_existing_directory_permissions(self) -> None:
        self.seed_registry()
        self.registry.chmod(0o750)
        self.assert_healthy(self.run_probe())
        self.assertEqual(self.registry.stat().st_mode & 0o777, 0o750)

    def test_success_is_repeatable_and_leaves_no_probe_files(self) -> None:
        for _ in range(5):
            self.assert_healthy(self.run_probe())

    def test_parallel_initialization_and_probes_do_not_collide(self) -> None:
        with ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(lambda _: self.run_probe(), range(24)))
        for result in results:
            self.assert_healthy(result)

    def test_probe_does_not_wait_for_registry_flock(self) -> None:
        self.seed_registry()
        with (self.registry / ".registry.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_healthy(self.run_probe())

    def test_path_arguments_are_not_evaluated_as_shell(self) -> None:
        authority = self.root / "a ' quoted; $(touch INJECTED) authority"
        self.assert_healthy(self.run_probe(registry=authority / "claims-v1"))
        self.assertFalse((self.root / "INJECTED").exists())

    def test_authority_symlink_is_not_followed(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        self.registry.parent.symlink_to(outside, target_is_directory=True)
        self.assert_refused(self.run_probe(), b"symlink")
        self.assertEqual(list(outside.iterdir()), [])

    def test_registry_symlink_is_not_followed(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        self.registry.parent.mkdir()
        self.registry.symlink_to(outside, target_is_directory=True)
        self.assert_refused(self.run_probe(), b"symlink")
        self.assertEqual(list(outside.iterdir()), [])

    def test_terminal_and_quarantine_symlinks_are_not_followed(self) -> None:
        for name in ("released", "cancelled", "quarantine"):
            with self.subTest(directory=name):
                registry = self.root / name / "claims-v1"
                registry.mkdir(parents=True)
                outside = self.root / (name + "-outside")
                outside.mkdir()
                (registry / name).symlink_to(outside, target_is_directory=True)
                self.assert_refused(self.run_probe(registry=registry), b"symlink")
                self.assertEqual(list(outside.iterdir()), [])

    def test_dangling_directory_symlink_is_rejected(self) -> None:
        self.registry.parent.symlink_to(self.root / "absent", target_is_directory=True)
        self.assert_refused(self.run_probe(), b"symlink")
        self.assertFalse((self.root / "absent").exists())

    def test_non_directory_registry_is_preserved(self) -> None:
        self.registry.parent.mkdir()
        self.registry.write_bytes(b"do not replace")
        self.assert_refused(self.run_probe(), b"mkdir")
        self.assertEqual(self.registry.read_bytes(), b"do not replace")

    def test_non_directory_terminal_storage_is_preserved(self) -> None:
        self.registry.mkdir(parents=True)
        path = self.registry / "released"
        path.write_bytes(b"do not replace")
        self.assert_refused(self.run_probe(), b"mkdir")
        self.assertEqual(path.read_bytes(), b"do not replace")

    def test_registry_fifo_is_rejected_without_opening_it(self) -> None:
        self.registry.parent.mkdir()
        os.mkfifo(self.registry)
        self.assert_refused(self.run_probe(), b"mkdir")
        self.assertTrue(self.registry.exists())

    def test_mkdir_failure_is_not_a_healthy_echo(self) -> None:
        self.assert_refused(self.run_probe("mkdir() { return 1; }"), b"mkdir")

    def test_create_failure_is_not_a_healthy_echo(self) -> None:
        self.assert_refused(self.run_probe("mktemp() { return 1; }"), b"create")

    def test_every_receipt_directory_is_actually_probed(self) -> None:
        for name in ("released", "cancelled", "quarantine"):
            with self.subTest(directory=name):
                prefix = f'''mktemp() {{
                    case "$2" in */{name}/.health-probe.*) return 1 ;; esac
                    command mktemp "$@"
                }}'''
                self.assert_refused(self.run_probe(prefix), b"create")
                self.assertFalse(list(self.root.rglob(".health-probe.*")))

    def test_actual_full_device_write_failure_is_not_a_healthy_echo(self) -> None:
        if not Path("/dev/full").exists():
            self.skipTest("/dev/full is unavailable")
        prefix = '''printf() {
            if [ "${2-}" = RCH_SOURCE_REGISTRY_HEALTH_V1 ]; then
                command printf '%s\\n' "$2" > /dev/full
            else
                command printf "$@"
            fi
        }'''
        self.assert_refused(self.run_probe(prefix), b"write")
        self.assertFalse(list(self.root.rglob(".health-probe.*")))

    def test_partial_write_with_error_is_rejected_and_cleaned(self) -> None:
        prefix = '''printf() {
            if [ "${2-}" = RCH_SOURCE_REGISTRY_HEALTH_V1 ]; then
                command printf partial; return 1
            fi
            command printf "$@"
        }'''
        self.assert_refused(self.run_probe(prefix), b"write")
        self.assertFalse(list(self.root.rglob(".health-probe.*")))

    def test_silent_truncation_is_caught_by_readback(self) -> None:
        prefix = '''printf() {
            if [ "${2-}" = RCH_SOURCE_REGISTRY_HEALTH_V1 ]; then
                command printf partial; return 0
            fi
            command printf "$@"
        }'''
        self.assert_refused(self.run_probe(prefix), b"readback")
        self.assertFalse(list(self.root.rglob(".health-probe.*")))

    def test_rename_failure_is_rejected_and_cleaned(self) -> None:
        self.assert_refused(self.run_probe("mv() { return 1; }"), b"rename")
        self.assertFalse(list(self.root.rglob(".health-probe.*")))

    def test_read_failure_is_rejected_and_cleaned(self) -> None:
        self.assert_refused(self.run_probe("cat() { return 1; }"), b"read")
        self.assertFalse(list(self.root.rglob(".health-probe.*")))

    def test_wrong_readback_is_rejected_and_cleaned(self) -> None:
        self.assert_refused(self.run_probe("cat() { printf wrong; }"), b"readback")
        self.assertFalse(list(self.root.rglob(".health-probe.*")))

    def test_remove_failure_prevents_success(self) -> None:
        self.assert_refused(self.run_probe("rm() { return 1; }"), b"cleanup")

    def test_directory_cleanup_failure_prevents_success(self) -> None:
        self.assert_refused(self.run_probe("rmdir() { return 1; }"), b"cleanup")

    def test_failure_preserves_all_ownership_evidence(self) -> None:
        records = self.seed_registry()
        self.assert_refused(self.run_probe("mv() { return 1; }"), b"rename")
        self.assert_records_unchanged(records)

    def test_storage_recovery_restores_success_without_repairing_claims(self) -> None:
        records = self.seed_registry()
        self.assert_refused(self.run_probe("mv() { return 1; }"), b"rename")
        self.assert_healthy(self.run_probe())
        self.assert_records_unchanged(records)

    def test_real_permission_denial_is_not_a_healthy_echo(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("requires privilege to run the probe as an unprivileged uid")
        self.root.chmod(0o755)
        self.registry.parent.mkdir(mode=0o500)
        self.assert_refused(self.run_probe(user=65534), b"mkdir")


if __name__ == "__main__":
    unittest.main()
