#!/usr/bin/env python3
"""Exercise the production recovery protocol against native Linux process groups.

A retained record's boot UUID is changed only in a private fixture to model a
previous boot. These are NOT actual reboot, SSH, or live systemd tests. Current
boot/namespace reads and PGID collisions are real; negative observation failures
and unavailable cgroups are explicit doubles. No production function is copied.
Fixtures are retained. Only test-owned children are terminated during cleanup.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src" / "remote_process.sh"
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")
BOOT_PATH = "/proc/sys/kernel/random/boot_id"
OLD_BOOT = "13572468-1234-4abc-8def-135724681357"
OTHER_BOOT = "24681357-abcd-4123-8567-246813572468"


def protocol() -> str:
    supplied = os.environ.get("RCH_TEST_PROTOCOL_SCRIPT")
    core = SOURCE.read_text()
    if not supplied:
        return core
    compiled = Path(supplied).read_text()
    if compiled.count(core) != 1:
        raise AssertionError("compiled protocol does not contain the exact production core")
    return compiled


def birth(pid: int) -> int:
    return int(Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19])


@unittest.skipUnless(sys.platform == "linux", "Linux boot-bound recovery protocol")
class RebootRecovery(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="rch-reboot-recovery-"))
        self.boot = Path(BOOT_PATH).read_text().strip()
        self.assertNotIn(self.boot, (OLD_BOOT, OTHER_BOOT))
        self.processes: list[subprocess.Popen] = []
        self.addCleanup(self.stop_owned)
        self.script = protocol()
        self.trace = self.root / "operations"
        # Trace, rather than replace, actual group inspection and signalling.
        # The V2 resource backend is deliberately unavailable; old-boot recovery
        # must not need a currently running manager or a previous cgroup inode.
        # The census runs ps in a separate bounded shell (14aea498): trace it
        # with a real wrapper on PATH, not a function that shell cannot see.
        self.bin = self.root / "bin"
        self.bin.mkdir()
        real_ps = shutil.which("ps")
        assert real_ps, "procps ps is required"
        (self.bin / "ps").write_text(
            "#!/bin/sh\nprintf 'census\\n' >> \"$RCH_REBOOT_TRACE\"\nexec "
            + shlex.quote(real_ps) + ' "$@"\n')
        (self.bin / "ps").chmod(0o700)
        self.observers = r'''
kill() { printf 'signal\n' >> "$RCH_REBOOT_TRACE"; command kill "$@"; }
rch_scope_operation() { printf 'scope:%s\n' "$1" >> "$RCH_REBOOT_TRACE"; return 2; }
'''

    def stop_owned(self) -> None:
        for child in self.processes:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)

    def group(self) -> subprocess.Popen:
        child = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        self.processes.append(child)
        self.assertEqual(os.getpgid(child.pid), child.pid)
        return child

    def record(self, child, *, version=1, boot=None, start=None, build="41", name="record"):
        boot = self.boot if boot is None else boot
        start = birth(child.pid) if start is None else start
        content = f"RCH_REMOTE_PROCESS_V{version}:{build}:{boot}:{child.pid}:{start}"
        if version == 2:
            unit = f"rch-{boot}-{child.pid}-{start}.scope"
            content += f":{os.geteuid()}:user:{'a' * 32}:1:1.1:2.2:/fixture/{unit}"
        path = self.root / name
        path.write_bytes((content + "\n").encode())
        path.chmod(0o600)
        return path

    def run_recovery(self, path, *, extra="", build="41", mode="kill", body=None):
        body = body or 'rch_remote_cancel "$1" "$2" "$3"\n'
        return subprocess.run([SHELL, "-c", self.script + "\n" + self.observers + extra + "\n" + body,
                               "rch-reboot-test", str(path), build, mode],
                              capture_output=True, timeout=10, check=False,
                              env={**os.environ, "LC_ALL": "C", "RCH_REBOOT_TRACE": str(self.trace),
                                   "PATH": f"{self.bin}:{os.environ['PATH']}"})

    def operations(self):
        return self.trace.read_text().splitlines() if self.trace.exists() else []

    def unchanged(self, path):
        metadata = path.lstat()
        return (metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_nlink,
                hashlib.sha256(path.read_bytes()).hexdigest())

    def test_previous_boot_v1_ignores_live_reused_pgid_without_signalling(self):
        child = self.group()
        path = self.record(child, boot=OLD_BOOT)
        before = self.unchanged(path)
        result = self.run_recovery(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((result.stdout, self.operations()), (b"", []))
        self.assertIsNone(child.poll(), "a current-boot PGID is NOT the old execution")
        self.assertEqual(self.unchanged(path), before)

    def test_previous_boot_v2_needs_no_old_cgroup_or_running_manager(self):
        child = self.group()
        path = self.record(child, version=2, boot=OLD_BOOT)
        before = self.unchanged(path)
        result = self.run_recovery(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.operations(), [])
        self.assertIsNone(child.poll())
        self.assertEqual(self.unchanged(path), before)

    def test_same_boot_retains_actual_birth_fenced_group_cancellation(self):
        child = self.group()
        path = self.record(child)
        before = self.unchanged(path)
        result = self.run_recovery(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("signal", self.operations())
        self.assertEqual(child.wait(timeout=3), -9)
        self.assertEqual(self.unchanged(path), before)

    def test_same_boot_wrong_birth_does_not_signal_a_reused_group(self):
        child = self.group()
        path = self.record(child, start=birth(child.pid) + 1)
        result = self.run_recovery(path)
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertNotIn("signal", self.operations())
        self.assertIsNone(child.poll())

    def test_same_boot_unavailable_scope_is_not_retired(self):
        child = self.group()
        result = self.run_recovery(self.record(child, version=2))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(item.startswith("scope:") for item in self.operations()))
        self.assertIsNone(child.poll())

    def test_legacy_pid_does_not_borrow_residual_boot_authority(self):
        child = self.group()
        path = self.root / "legacy"
        path.write_text(str(child.pid) + "\n")
        result = self.run_recovery(path, extra=f"rch_boot={OLD_BOOT}\nrch_identified=1\n")
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertNotIn("signal", self.operations())
        self.assertIsNone(child.poll())

    def test_unknown_or_malformed_current_boot_fails_closed(self):
        child = self.group()
        path = self.record(child, boot=OLD_BOOT)
        for value in ("", "missing", "------------------------------------",
                      "00000000-0000-0000-0000-000000000000", "bad\nboot"):
            with self.subTest(value=value):
                extra = ('cat() { if [ "$1" = ' + shlex.quote(BOOT_PATH) + ' ]; then '
                         + "printf '%s\\n' " + shlex.quote(value)
                         + '; else command cat "$@"; fi; }\n')
                result = self.run_recovery(path, extra=extra)
                self.assertEqual(result.returncode, 44, result.stderr)
                self.assertIsNone(child.poll())
        result = self.run_recovery(path, extra=(
            'cat() { if [ "$1" = ' + shlex.quote(BOOT_PATH)
            + ' ]; then return 1; else command cat "$@"; fi; }\n'))
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assertEqual(self.operations(), [])

    def test_malformed_or_nil_recorded_boot_cannot_prove_a_reboot(self):
        child = self.group()
        for index, value in enumerate(("------------------------------------",
                                      "00000000-0000-0000-0000-000000000000", "invalid")):
            path = self.record(child, boot=value, name=f"bad-{index}")
            result = self.run_recovery(path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(child.poll())
        self.assertEqual(self.operations(), [])

    def test_mismatched_procfs_namespace_cannot_prove_old_execution_dead(self):
        child = self.group()
        path = self.record(child, version=2, boot=OLD_BOOT)
        result = self.run_recovery(path, extra="rch_check_procfs_namespace() { return 1; }\n")
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assertEqual(self.operations(), [])
        self.assertIsNone(child.poll())

    def test_changed_boot_observation_does_not_retire(self):
        child = self.group()
        path = self.record(child, boot=OLD_BOOT)
        marker = shlex.quote(str(self.root / "boot-read"))
        extra = ('cat() { if [ "$1" = ' + shlex.quote(BOOT_PATH) + ' ]; then '
                 + f'if [ -f {marker} ]; then printf "%s\\n" {OTHER_BOOT}; '
                 + f'else printf read > {marker}; command cat "$@"; fi; '
                 + 'else command cat "$@"; fi; }\n')
        result = self.run_recovery(path, extra=extra)
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assertEqual(self.operations(), [])
        self.assertIsNone(child.poll())

    def test_failed_boot_recheck_cannot_authorize_its_valid_looking_output(self):
        child = self.group()
        path = self.record(child, boot=OLD_BOOT)
        marker = shlex.quote(str(self.root / "boot-read"))
        extra = ('cat() { if [ "$1" = ' + shlex.quote(BOOT_PATH) + ' ]; then '
                 + f'if [ -f {marker} ]; then command cat "$@"; return 1; '
                 + f'else printf read > {marker}; command cat "$@"; fi; '
                 + 'else command cat "$@"; fi; }\n')
        result = self.run_recovery(path, extra=extra)
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assertEqual(self.operations(), [])
        self.assertIsNone(child.poll())

    def test_old_boot_still_requires_exact_complete_record_and_build(self):
        child = self.group()
        original = self.record(child, boot=OLD_BOOT).read_bytes()
        for index, content in enumerate((original[:-1], original + b"\n", original + b"noise\n",
                                         original.replace(b":41:", b":42:"), b"broken\n",
                                         original[:-1] + b"\0\n")):
            path = self.root / f"invalid-{index}"
            path.write_bytes(content)
            before = path.read_bytes()
            result = self.run_recovery(path)
            self.assertNotEqual(result.returncode, 0, content)
            self.assertEqual(path.read_bytes(), before)
            self.assertIsNone(child.poll())
        link = self.root / "alias"
        link.symlink_to(self.root / "record")
        self.assertNotEqual(self.run_recovery(link).returncode, 0)
        self.assertTrue(link.is_symlink())
        self.assertEqual(self.operations(), [])

    def test_previous_boot_v2_keeps_private_single_link_receipt_requirement(self):
        child = self.group()
        broad = self.record(child, version=2, boot=OLD_BOOT, name="broad")
        broad.chmod(0o666)
        linked = self.record(child, version=2, boot=OLD_BOOT, name="linked")
        os.link(linked, self.root / "other-link")
        foreign = self.record(child, version=2, boot=OLD_BOOT, name="foreign")
        foreign.write_bytes(foreign.read_bytes().replace(
            f":{os.geteuid()}:user:".encode(), f":{os.geteuid() + 1}:user:".encode()))
        for path in (broad, linked, foreign):
            before = self.unchanged(path)
            result = self.run_recovery(path)
            self.assertEqual(result.returncode, 42, result.stderr)
            self.assertEqual(self.unchanged(path), before)
            self.assertIsNone(child.poll())
        self.assertEqual(self.operations(), [])

    def test_live_supervisor_loaded_path_never_uses_reboot_shortcut(self):
        child = self.group()
        path = self.record(child, boot=OLD_BOOT)
        result = self.run_recovery(path, body=(
            'rch_read_record "$1" "$2" || exit $?\nrch_remote_cancel_loaded "$3"\n'))
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertIn("census", self.operations())
        self.assertNotIn("signal", self.operations())
        self.assertIsNone(child.poll())

    def test_failed_parse_cannot_leak_previous_recovery_authority(self):
        child = self.group()
        old = self.record(child, boot=OLD_BOOT)
        legacy = self.root / "legacy"
        legacy.write_text(str(child.pid) + "\n")
        body = ('rch_remote_cancel "$1" "$2" "$3" || exit $?\n'
                + 'rch_remote_cancel /nonexistent-rch-reboot-fixture 41 kill\n'
                + f'rch_remote_cancel {shlex.quote(str(legacy))} 41 kill\n')
        result = self.run_recovery(old, body=body)
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertNotIn("signal", self.operations())
        self.assertIsNone(child.poll())

    def test_existing_cancel_receipt_reports_only_stopped_execution(self):
        child = self.group()
        path = self.record(child, version=2, boot=OLD_BOOT)
        body = ('rch_remote_cancel "$1" "$2" term || exit $?\n'
                'printf "RCH_REMOTE_CANCELLED_V1:%s\\n" "$2"\n')
        result = self.run_recovery(path, body=body)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, b"RCH_REMOTE_CANCELLED_V1:41\n", b""))
        self.assertEqual(self.operations(), [])
        self.assertIsNone(child.poll())


if __name__ == "__main__":
    unittest.main(verbosity=2)
