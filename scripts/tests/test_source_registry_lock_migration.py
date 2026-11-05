#!/usr/bin/env python3
"""Execute the real migration against isolated files; fixtures are retained.

    TMPDIR=/dev/shm python3 -B scripts/tests/test_source_registry_lock_migration.py -v

This is local filesystem and fault-injection regression coverage, not live
worker/fleet or replacement-binary qualification. No SSH or service is used.
"""

import ast
import contextlib
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "migrate_source_registry_locks.py"
SPEC = importlib.util.spec_from_file_location("registry_lock_migration", SCRIPT)
MIGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATION)
UPLOAD_NAME = "upload." + hashlib.sha256(
    b"rch.source-upload-lock.v1\0/data/tmp/rch/example").hexdigest() + ".lock"


class RegistryLockMigrationTests(unittest.TestCase):
    def setUp(self):
        # Match the repository's retained-fixture policy; never clean up worker
        # state or even test evidence as part of this qualification script.
        self.root = Path(tempfile.mkdtemp(prefix="rch-lock-migration-"))
        self.uid = os.geteuid()
        self.current = self.make_registry("current")
        self.legacy = self.make_registry("legacy")

    def make_registry(self, namespace):
        root = self.root / namespace
        root.mkdir(mode=0o700)
        authority = root / "rch-source-authority-locks"
        authority.mkdir(mode=0o700)
        registry = authority / "claims-v1"
        registry.mkdir(mode=0o700)
        return registry

    def lock(self, name="aa.activity.lock", mode=0o664, registry=None):
        path = (registry or self.current) / name
        path.write_bytes(b"preserve every byte\n")
        path.chmod(mode)
        return path

    def run_cli(self, *args, registries=None, owner_uid=None):
        command = [sys.executable, "-I", "-S", str(SCRIPT), "--owner-uid",
                   str(self.uid if owner_uid is None else owner_uid)]
        for registry in registries or (self.current, self.legacy):
            command.extend(["--registry", str(registry)])
        return subprocess.run(command + list(args), capture_output=True, timeout=5)

    def run_migration(self, apply=True, paths=None, emit=None):
        return MIGRATION.migrate([str(path) for path in paths or (self.current, self.legacy)],
                                 self.uid, apply, emit)

    def chown_fixture(self, path, uid):
        try:
            os.chown(path, uid, uid)
        except OSError as error:
            if error.errno in (errno.EINVAL, errno.EPERM, errno.EACCES):
                self.skipTest("execution environment cannot create foreign-owned fixtures: " + str(error))
            raise

    def assert_refused(self, result, reason=None):
        self.assertEqual(result.returncode, 73, result.stderr)
        event = json.loads(result.stderr)
        self.assertEqual(event["status"], "refused")
        if reason:
            self.assertIn(reason, event["reason"])
        return event

    def test_default_dry_run_has_no_writes(self):
        path = self.lock()
        before = path.stat()
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(events[0]["action"], "would_change")
        self.assertEqual(events[-1]["mode"], "dry-run")
        self.assertEqual(events[-1]["changed"], 0)
        self.assertEqual(events[-1]["would_change"], 1)
        self.assertEqual(path.stat(), before)
        self.assertEqual(path.read_bytes(), b"preserve every byte\n")

    def test_apply_both_registries_preserves_inodes_bytes_and_non_write_bits(self):
        locks = [self.lock("metadata.lock", registry=self.current),
                 self.lock("abc-def.activity.lock", 0o666, registry=self.current),
                 self.lock("metadata.lock", 0o660, registry=self.legacy),
                 self.lock("01.activity.lock", 0o600, registry=self.legacy)]
        before = [(path.stat(), path.read_bytes()) for path in locks]
        result = self.run_cli("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout.splitlines()[-1])
        self.assertEqual(summary["changed"], 3)
        self.assertEqual(summary["unchanged"], 1)
        for path, (info, content) in zip(locks, before):
            self.assertEqual(path.stat().st_ino, info.st_ino)
            self.assertEqual(path.stat().st_uid, info.st_uid)
            self.assertEqual(path.stat().st_gid, info.st_gid)
            self.assertEqual(path.stat().st_mtime_ns, info.st_mtime_ns)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), stat.S_IMODE(info.st_mode) & ~0o022)
            self.assertEqual(path.read_bytes(), content)

    def test_migration_removes_published_settlement_permission_rejection(self):
        settlement = SCRIPT.parents[1] / "rch/src/hook/source_cancel_settlement.py"
        tree = ast.parse(settlement.read_text(), filename=str(settlement))
        # private()/refuse() are unchanged from the published v2.1.35 source.
        # Execute those exact production functions without its main() or the
        # heal_group_writable_lock() helper added by d133ae12. This proves the
        # reported validator rejection is repaired, not cancellation success.
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in {"private", "refuse"}]
        self.assertEqual({node.name for node in functions}, {"private", "refuse"})
        namespace = {"os": os, "stat": stat, "sys": sys}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(settlement), "exec"),
             namespace)
        private = namespace["private"]
        locks = [self.lock(name, registry=registry)
                 for registry in (self.current, self.legacy)
                 for name in ("metadata.lock", "aa.activity.lock")]
        before = [(path.stat(), path.read_bytes()) for path in locks]
        for path in locks:
            with self.subTest(path=path):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as refused:
                    private(path.stat())
                self.assertEqual(refused.exception.code, 73)
                self.assertIn("RCH_SOURCE_CANCELLATION_UNSETTLED unsafe registry ownership or file type",
                              stderr.getvalue())
        result = self.run_cli("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        for path, (info, content) in zip(locks, before):
            with self.subTest(repaired=path):
                self.assertIsNone(private(path.stat()))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
                self.assertEqual((path.stat().st_dev, path.stat().st_ino),
                                 (info.st_dev, info.st_ino))
                self.assertEqual(path.read_bytes(), content)

    def test_idempotent_rerun_and_explicit_dry_run(self):
        path = self.lock()
        self.assertEqual(self.run_migration()["changed"], 1)
        after = path.stat()
        self.assertEqual(self.run_migration()["changed"], 0)
        result = self.run_cli("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.splitlines()[-1])["would_change"], 0)
        self.assertEqual(path.stat(), after)

    def test_production_upload_locks_coexist_without_mutation_or_flock_release(self):
        ssh = SCRIPT.parents[1] / "rch/src/hook/ssh.rs"
        source = ssh.read_text().split('const SOURCE_UPLOAD_ACTIVITY: &str = r#"', 1)[1].split('"#;', 1)[0]
        functions = [node for node in ast.parse(source).body
                     if isinstance(node, ast.FunctionDef) and node.name == "checked_lock"]
        self.assertEqual(len(functions), 1)
        namespace = {"os": os, "fcntl": fcntl, "stat": stat}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(ssh), "exec"), namespace)
        uploads = []
        repairable = [self.lock(name, registry=registry)
                      for registry in (self.current, self.legacy)
                      for name in ("metadata.lock", "aa.activity.lock")]
        with contextlib.ExitStack() as held:
            for registry, kind in ((self.current, fcntl.LOCK_EX), (self.legacy, fcntl.LOCK_SH)):
                directory = os.open(registry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                held.callback(os.close, directory)
                # Execute the production creator and flock operation. The
                # migration must coexist with both an upload and its parents.
                descriptor = namespace["checked_lock"](directory, UPLOAD_NAME, kind)
                held.callback(os.close, descriptor)
                os.write(descriptor, b"preserve upload lock bytes\n")
                path = registry / UPLOAD_NAME
                uploads.append((path, descriptor, path.stat()))
            dry_run = self.run_cli("--dry-run")
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
            summary = json.loads(dry_run.stdout.splitlines()[-1])
            self.assertEqual(summary["would_change"], 4)
            self.assertEqual(summary["untouched"], 2)
            for path in repairable:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o664)
            for args in (("--apply",), ("--apply",)):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                events = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual(events[-1]["untouched"], 2)
                upload_events = [event for event in events[:-1]
                                 if event["path"].endswith("/" + UPLOAD_NAME)]
                self.assertEqual(len(upload_events), 2)
                for event in upload_events:
                    self.assertEqual((event["action"], event["before"], event["after"]),
                                     ("untouched", "0600", "0600"))
                for path, descriptor, before in uploads:
                    self.assertEqual(path.stat(), before)
                    self.assertEqual(os.fstat(descriptor).st_ino, before.st_ino)
                    with path.open("r+") as waiter:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(waiter, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for path in repairable:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            for path, _, _ in uploads:
                self.assertEqual(path.read_bytes(), b"preserve upload lock bytes\n")
        for path, _, _ in uploads:
            with path.open("r+") as waiter:
                fcntl.flock(waiter, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_upload_locks_are_never_chmoded_or_fsynced(self):
        for mode in (0o600, 0o640, 0o604, 0o644):
            with self.subTest(mode=oct(mode)):
                registry = self.make_registry("upload-safe-mode-" + oct(mode))
                path = self.lock(UPLOAD_NAME, mode, registry)
                before = path.stat()
                with mock.patch.object(MIGRATION.os, "fchmod", side_effect=AssertionError("upload chmod")), \
                     mock.patch.object(MIGRATION.os, "fsync", side_effect=AssertionError("upload fsync")):
                    summary = self.run_migration(paths=[registry])
                self.assertEqual(summary["untouched"], 1)
                self.assertEqual(summary["changed"], 0)
                self.assertEqual(summary["unchanged"], 0)
                self.assertEqual(path.stat(), before)
                self.assertEqual(path.read_bytes(), b"preserve every byte\n")

    def test_unsafe_upload_modes_refuse_preflight_without_repair(self):
        for mode in (0o664, 0o660, 0o606, 0o4600, 0o2600, 0o1600, 0o700, 0o400):
            with self.subTest(mode=oct(mode)):
                registry = self.make_registry("upload-unsafe-mode-" + oct(mode))
                repairable = self.lock("metadata.lock", registry=registry)
                upload = self.lock(UPLOAD_NAME, mode, registry)
                before = repairable.stat(), upload.stat()
                self.assert_refused(self.run_cli("--apply", registries=[registry]), "permissions")
                self.assertEqual((repairable.stat(), upload.stat()), before)

    def test_unsafe_upload_objects_refuse_preflight_without_repair(self):
        for kind in ("symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                registry = self.make_registry("upload-object-" + kind)
                repairable = self.lock("metadata.lock", registry=registry)
                upload = registry / UPLOAD_NAME
                target = self.root / ("upload-outside-" + kind)
                target.write_bytes(b"outside the migration scope\n")
                target.chmod(0o600)
                if kind == "symlink":
                    upload.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, upload)
                elif kind == "fifo":
                    os.mkfifo(upload, 0o600)
                else:
                    upload.mkdir(mode=0o700)
                before = repairable.stat(), upload.lstat(), target.stat()
                self.assert_refused(self.run_cli("--apply", registries=[registry]))
                self.assertEqual((repairable.stat(), upload.lstat(), target.stat()), before)
                self.assertEqual(target.read_bytes(), b"outside the migration scope\n")

    def test_malformed_upload_names_refuse_preflight_without_repair(self):
        names = ("upload..lock", "upload." + "a" * 63 + ".lock",
                 "upload." + "a" * 65 + ".lock", "upload." + "A" * 64 + ".lock",
                 "upload." + "a" * 63 + "g.lock", "Upload." + "a" * 64 + ".lock")
        for index, name in enumerate(names):
            with self.subTest(name=name):
                registry = self.make_registry("upload-name-" + str(index))
                repairable = self.lock("metadata.lock", registry=registry)
                malformed = self.lock(name, 0o600, registry)
                before = repairable.stat(), malformed.stat()
                self.assert_refused(self.run_cli("--apply", registries=[registry]), "unrecognized")
                self.assertEqual((repairable.stat(), malformed.stat()), before)

    def test_upload_changes_during_apply_are_refused(self):
        for phase in ("before_upload", "after_upload"):
            for change in ("replacement", "mode", "hardlink", "directory"):
                with self.subTest(phase=phase, change=change):
                    registry = self.make_registry("upload-race-" + phase + "-" + change)
                    repairable = self.lock("metadata.lock", registry=registry)
                    upload = self.lock(UPLOAD_NAME, 0o600, registry)

                    def change_upload(event):
                        trigger = "metadata.lock" if phase == "before_upload" else UPLOAD_NAME
                        if not event["path"].endswith("/" + trigger):
                            return
                        if change == "replacement":
                            upload.rename(upload.with_name("original-upload-saved"))
                            self.lock(UPLOAD_NAME, 0o600, registry)
                        elif change == "mode":
                            # Even a different safe mode must not bypass the
                            # snapshot just because upload locks are untouched.
                            upload.chmod(0o640)
                        elif change == "hardlink":
                            os.link(upload, registry / "upload-hardlink-saved")
                        else:
                            saved = registry.with_name("claims-v1-saved")
                            registry.rename(saved)
                            registry.symlink_to(saved, target_is_directory=True)

                    with self.assertRaises(MIGRATION.Refused):
                        self.run_migration(paths=[registry], emit=change_upload)
                    self.assertEqual(stat.S_IMODE(repairable.stat().st_mode), 0o644)
                    self.assertEqual(stat.S_IMODE(upload.stat().st_mode),
                                     0o640 if change == "mode" else 0o600)

    def test_new_upload_lock_during_migration_requires_a_safe_retry(self):
        repairable = self.lock("metadata.lock")

        def create_upload(event):
            if event["action"] == "changed":
                self.lock(UPLOAD_NAME, 0o600)

        with self.assertRaisesRegex(MIGRATION.Refused, "lock set changed"):
            self.run_migration(emit=create_upload)
        upload = self.current / UPLOAD_NAME
        before = upload.stat()
        summary = self.run_migration()
        self.assertEqual(summary["changed"], 0)
        self.assertEqual(summary["untouched"], 1)
        self.assertEqual(upload.stat(), before)
        self.assertEqual(stat.S_IMODE(repairable.stat().st_mode), 0o644)

    def test_preflight_checks_all_roots_before_any_change(self):
        first = self.lock()
        bad = self.lock("bad-name.activity.lock", registry=self.legacy)
        bad.chmod(0o4664)
        self.assert_refused(self.run_cli("--apply"))
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o664)
        self.assertEqual(stat.S_IMODE(bad.stat().st_mode), 0o4664)

    def test_wrong_invoking_uid_is_refused_even_as_root(self):
        path = self.lock()
        self.assert_refused(self.run_cli("--apply", owner_uid=self.uid + 1), "run as")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o664)

    @unittest.skipUnless(os.geteuid() == 0, "actual foreign ownership requires root fixture setup")
    def test_foreign_file_owner_is_refused(self):
        path = self.lock()
        self.chown_fixture(path, 65534)
        self.assert_refused(self.run_cli("--apply"), "owned by")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o664)

    @unittest.skipUnless(os.geteuid() == 0, "actual foreign ownership requires root fixture setup")
    def test_foreign_directory_owner_is_refused(self):
        self.lock()
        self.chown_fixture(self.current, 65534)
        self.assert_refused(self.run_cli("--apply"), "requested UID")

    @unittest.skipUnless(os.geteuid() == 0, "non-root execution requires root fixture setup")
    def test_registry_owner_can_apply_without_root(self):
        path = self.lock()
        for parent, directories, files in os.walk(self.root):
            self.chown_fixture(parent, 65534)
            for name in files:
                self.chown_fixture(Path(parent) / name, 65534)
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(SCRIPT), "--owner-uid", "65534",
             "--registry", str(self.current), "--apply"],
            user=65534, group=65534, extra_groups=[], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_hardlinked_lock_is_refused(self):
        path = self.lock()
        os.link(path, self.root / "outside")
        self.assert_refused(self.run_cli("--apply"), "multiple links")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o664)

    def test_symlink_lock_is_refused_without_touching_target(self):
        target = self.root / "outside"
        target.write_text("untouched")
        target.chmod(0o666)
        (self.current / "aa.activity.lock").symlink_to(target)
        self.assert_refused(self.run_cli("--apply"), "not a regular file")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o666)

    def test_symlink_registry_authority_or_ancestor_is_refused(self):
        for part in ("registry", "authority", "ancestor"):
            with self.subTest(part=part):
                registry = self.make_registry(part)
                lock = self.lock(registry=registry)
                original = {"registry": registry, "authority": registry.parent,
                            "ancestor": registry.parent.parent}[part]
                saved = original.with_name(original.name + "-saved")
                original.rename(saved)
                original.symlink_to(saved, target_is_directory=True)
                self.assert_refused(self.run_cli("--apply", registries=[registry]))
                self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o664)

    def test_non_private_authority_and_registry_are_refused(self):
        for position in ("authority", "registry"):
            with self.subTest(position=position):
                registry = self.make_registry("public-" + position)
                path = self.lock(registry=registry)
                (registry.parent if position == "authority" else registry).chmod(0o755)
                self.assert_refused(self.run_cli("--apply", registries=[registry]), "0700")
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o664)

    def test_writable_non_sticky_ancestor_is_refused(self):
        self.lock()
        self.current.parent.parent.chmod(0o777)
        self.assert_refused(self.run_cli("--apply"), "ancestor")

    def test_fifo_is_refused_promptly(self):
        os.mkfifo(self.current / "aa.activity.lock", 0o664)
        self.assert_refused(self.run_cli("--apply"), "not a regular file")

    def test_socket_is_refused(self):
        try:
            listener = socket.socket(socket.AF_UNIX)
        except PermissionError as error:
            self.skipTest("execution environment denies Unix socket fixtures: " + str(error))
        with listener:
            listener.bind(str(self.current / "aa.activity.lock"))
            self.assert_refused(self.run_cli("--apply"), "not a regular file")

    def test_foreign_ownership_metadata_is_always_refused(self):
        # These validator checks still execute in single-UID user namespaces,
        # where the actual chown qualification above is explicitly skipped.
        for upload in (False, True):
            with self.subTest(upload=upload):
                with self.assertRaisesRegex(MIGRATION.Refused, "owned by"):
                    MIGRATION.check_lock(SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                                                         st_uid=self.uid + 1, st_nlink=1),
                                         self.uid, upload)
        with self.assertRaisesRegex(MIGRATION.Refused, "requested UID"):
            MIGRATION.check_directory(SimpleNamespace(st_mode=stat.S_IFDIR | 0o700,
                                                       st_uid=self.uid + 1), self.uid, True)

    def test_device_and_socket_metadata_are_always_refused(self):
        for kind in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK):
            for upload in (False, True):
                with self.subTest(kind=kind, upload=upload):
                    with self.assertRaisesRegex(MIGRATION.Refused, "not a regular file"):
                        MIGRATION.check_lock(SimpleNamespace(st_mode=kind | 0o600,
                                                             st_uid=self.uid, st_nlink=1),
                                             self.uid, upload)

    def test_directory_disguised_as_lock_is_refused(self):
        (self.current / "metadata.lock").mkdir(mode=0o700)
        self.assert_refused(self.run_cli("--apply"), "not a regular file")

    def test_special_executable_or_unexpected_owner_modes_are_refused(self):
        for mode in (0o4664, 0o2664, 0o1664, 0o766, 0o464, 0o264):
            with self.subTest(mode=oct(mode)):
                registry = self.make_registry("mode-" + oct(mode))
                path = self.lock(mode=mode, registry=registry)
                self.assert_refused(self.run_cli("--apply", registries=[registry]), "permissions")
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)

    def test_malformed_lock_names_are_refused(self):
        for index, name in enumerate((".activity.lock", "z.activity.lock", "A1.activity.lock",
                                      "a" * 129 + ".activity.lock", "other.lock")):
            with self.subTest(name=name):
                registry = self.make_registry("name-" + str(index))
                self.lock(name, registry=registry)
                self.assert_refused(self.run_cli("--apply", registries=[registry]), "unrecognized")

    def test_claims_and_subdirectories_are_not_migrated(self):
        self.lock()
        claim = self.current / "aa.digest.claim"
        claim.write_bytes(b"claim contents remain owned by registry transaction\n")
        claim.chmod(0o666)
        archive = self.current / "cancelled"
        archive.mkdir(mode=0o700)
        nested = self.lock("metadata.lock", registry=archive)
        before = claim.stat(), nested.stat()
        summary = self.run_migration()
        self.assertEqual(summary["changed"], 1)
        self.assertEqual((claim.stat(), nested.stat()), before)

    def test_missing_registries_are_reported_without_creating_paths(self):
        missing = self.root / "absent/rch-source-authority-locks/claims-v1"
        result = self.run_cli("--apply", registries=[missing])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(missing.parent.exists())
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(events[0]["action"], "absent")
        self.assertEqual(events[-1]["absent"], 1)

    def test_bad_registry_paths_and_duplicate_roots_are_refused(self):
        for paths in ([self.current, self.current], [self.root],
                      [str(self.current) + "/../claims-v1"], ["relative/claims-v1"]):
            with self.subTest(paths=paths):
                self.assert_refused(self.run_cli("--apply", registries=paths))

    def test_active_and_queued_flocks_are_preserved(self):
        path = self.lock()
        with path.open("r+") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_cli("--apply")
            self.assertEqual(result.returncode, 0, result.stderr)
            with path.open("r+") as waiter:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(waiter, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(os.fstat(held.fileno()).st_ino, path.stat().st_ino)
        with path.open("r+") as waiter:
            fcntl.flock(waiter, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_interrupted_apply_is_safe_to_resume(self):
        first = self.lock("aa.activity.lock")
        second = self.lock("bb.activity.lock")

        def interrupt_after_first(event):
            if event["action"] == "changed":
                raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.run_migration(emit=interrupt_after_first)
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(second.stat().st_mode), 0o664)
        summary = self.run_migration()
        self.assertEqual(summary["changed"], 1)
        self.assertEqual(summary["unchanged"], 1)

    def test_directory_replacement_between_files_is_refused(self):
        self.lock("aa.activity.lock")
        self.lock("bb.activity.lock")
        replacement = self.root / "unrelated"
        replacement.mkdir(mode=0o700)
        outside = self.lock("bb.activity.lock", registry=replacement)

        def replace_after_first(event):
            if event["action"] == "changed":
                self.current.rename(self.current.with_name("claims-v1-saved"))
                self.current.symlink_to(replacement, target_is_directory=True)

        with self.assertRaisesRegex(MIGRATION.Refused, "path changed"):
            self.run_migration(emit=replace_after_first)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o664)

    def test_lock_replacement_after_open_cannot_redirect_chmod(self):
        path = self.lock()
        outside = self.root / "outside"
        outside.write_text("untouched")
        outside.chmod(0o666)
        actual_fchmod = os.fchmod

        def replace_then_chmod(descriptor, mode):
            path.rename(path.with_name("original-saved"))
            path.symlink_to(outside)
            actual_fchmod(descriptor, mode)

        with mock.patch.object(MIGRATION.os, "fchmod", side_effect=replace_then_chmod):
            with self.assertRaisesRegex(MIGRATION.Refused, "not a regular file"):
                self.run_migration()
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o666)
        self.assertEqual(stat.S_IMODE(path.with_name("original-saved").stat().st_mode), 0o644)

    def test_permissions_narrowed_while_opening_are_not_widened(self):
        path = self.lock()
        verify_lock = MIGRATION.Registry.verify_lock
        calls = 0

        def narrow_during_apply_open(registry, name, descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:  # Preflight was first; change during the apply open.
                os.fchmod(descriptor, 0o600)
            return verify_lock(registry, name, descriptor)

        with mock.patch.object(MIGRATION.Registry, "verify_lock", new=narrow_during_apply_open):
            with self.assertRaisesRegex(MIGRATION.Refused, "changed while opening"):
                self.run_migration()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_production_healer_commutes_with_migration(self):
        settlement = SCRIPT.parents[1] / "rch/src/hook/source_cancel_settlement.py"
        source = settlement.read_text()
        functions = [node for node in ast.parse(source).body
                     if isinstance(node, ast.FunctionDef)
                     and node.name == "heal_group_writable_lock"]
        self.assertEqual(len(functions), 1)
        # Run the exact d133ae12 production helper in a separate interpreter,
        # interleaved after migration validation and before its final fchmod.
        # This is the supported cooperating writer, not arbitrary admin chmod.
        program = ("import os, stat, sys\n" + ast.get_source_segment(source, functions[0])
                   + "\nheal_group_writable_lock(int(sys.argv[1]))\n")
        actual_fchmod = os.fchmod

        def run_healer(descriptor):
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-c", program, str(descriptor)],
                pass_fds=(descriptor,), capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

        for mode in (0o664, 0o666, 0o660):
            with self.subTest(mode=oct(mode)):
                registry = self.make_registry("healer-" + oct(mode))
                path = self.lock("metadata.lock", mode, registry)
                before = path.stat(), path.read_bytes()

                def heal_before_migration_chmod(descriptor, requested_mode):
                    run_healer(descriptor)
                    self.assertEqual(stat.S_IMODE(os.fstat(descriptor).st_mode), mode & ~0o022)
                    actual_fchmod(descriptor, requested_mode)

                with mock.patch.object(MIGRATION.os, "fchmod", side_effect=heal_before_migration_chmod):
                    self.assertEqual(self.run_migration(paths=[registry])["changed"], 1)
                repaired = path.stat()
                # The opposite order is also safe: a healer after migration
                # observes the already narrowed mode and leaves it untouched.
                with path.open("rb") as held:
                    run_healer(held.fileno())
                self.assertEqual(path.stat(), repaired)
                self.assertEqual(stat.S_IMODE(repaired.st_mode), mode & ~0o022)
                self.assertEqual((repaired.st_dev, repaired.st_ino),
                                 (before[0].st_dev, before[0].st_ino))
                self.assertEqual(path.read_bytes(), before[1])

    def test_new_lock_during_migration_is_reported_for_retry(self):
        self.lock()

        def add_legacy_lock(event):
            self.lock("bb.activity.lock")

        with self.assertRaisesRegex(MIGRATION.Refused, "lock set changed"):
            self.run_migration(emit=add_legacy_lock)
        self.assertEqual(self.run_migration()["changed"], 1)

    def test_same_named_replacement_after_repair_is_refused(self):
        first = self.lock("aa.activity.lock")
        self.lock("bb.activity.lock")

        def replace_earlier_lock(event):
            if event["path"].endswith("bb.activity.lock"):
                first.rename(first.with_name("original-saved"))
                self.lock("aa.activity.lock")

        with self.assertRaisesRegex(MIGRATION.Refused, "changed since inspection"):
            self.run_migration(emit=replace_earlier_lock)
        self.assertEqual(self.run_migration()["changed"], 1)

    def test_group_write_restored_after_repair_is_refused(self):
        first = self.lock("aa.activity.lock")
        self.lock("bb.activity.lock")

        def reopen_earlier_lock(event):
            if event["path"].endswith("bb.activity.lock"):
                first.chmod(0o664)

        with self.assertRaisesRegex(MIGRATION.Refused, "changed since inspection"):
            self.run_migration(emit=reopen_earlier_lock)
        self.assertEqual(self.run_migration()["changed"], 1)

    def test_resumed_apply_fsyncs_already_repaired_file(self):
        self.lock(mode=0o644)
        with mock.patch.object(MIGRATION.os, "fsync", wraps=os.fsync) as fsync:
            self.assertEqual(self.run_migration()["changed"], 0)
        self.assertEqual(fsync.call_count, 1)

    def test_absent_registry_appearing_during_migration_is_refused(self):
        self.lock()
        missing = self.root / "appeared/rch-source-authority-locks/claims-v1"

        def make_missing(event):
            self.make_registry("appeared")

        with self.assertRaisesRegex(MIGRATION.Refused, "appeared"):
            self.run_migration(paths=[self.current, missing], emit=make_missing)

    def test_fchmod_or_fsync_failure_is_reported_and_retry_is_idempotent(self):
        path = self.lock()
        for operation in ("fchmod", "fsync"):
            with self.subTest(operation=operation):
                path.chmod(0o664)
                stderr = io.StringIO()
                with mock.patch.object(MIGRATION.os, operation, side_effect=OSError("injected I/O failure")):
                    with contextlib.redirect_stderr(stderr):
                        status = MIGRATION.main(["--owner-uid", str(self.uid),
                                                 "--registry", str(self.current), "--apply"])
                self.assertEqual(status, 73)
                self.assertIn("injected I/O failure", json.loads(stderr.getvalue())["reason"])
                self.run_migration()
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
