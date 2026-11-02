#!/usr/bin/env python3
"""Direct worker-script checks with real Git TARs, files and rsync.

Fixtures are retained, including interruption/corruption evidence. The
fault-injection wrappers terminate, replace or fail an OS boundary in the actual
helper; they do not replace its cache, digest, copy or filesystem-selection
logic. The read observer records actual offsets and bytes returned by os.read.
No SSH transport or Rust harness execution is claimed here.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[2] / "rch/src/transfer/git_archive_cache.py"
CACHE_DIRECTORY = ".rch-git-archive-cache-v1"
SOURCE_ARCHIVE = ".rch-clean-overlay-base.tar"
SLOT = hashlib.sha256(b"primary logical source root").hexdigest()
OTHER_SLOT = hashlib.sha256(b"sibling logical source root").hexdigest()
PREFIX = b"RCH_GIT_ARCHIVE_CACHE_V1 "


CRASH_PUBLICATION = r"""
import os, runpy, sys
script, when, *arguments = sys.argv[1:]
original = os.replace
def replacement(source, destination, **keywords):
    if str(source).endswith('.pending') and str(destination).endswith('.sealed'):
        if when == 'before':
            os._exit(91)
        original(source, destination, **keywords)
        os._exit(92)
    return original(source, destination, **keywords)
os.replace = replacement
sys.argv = [script, *arguments]
runpy.run_path(script, run_name='__main__')
"""


FAIL_PRIVATE_FSYNC = r"""
import errno, os, runpy, stat, sys
script, failure, *arguments = sys.argv[1:]
original = os.fsync
def fsync(descriptor):
    info = os.fstat(descriptor)
    if stat.S_ISREG(info.st_mode):
        raise OSError(getattr(errno, failure), 'injected private archive fsync failure')
    return original(descriptor)
os.fsync = fsync
sys.argv = [script, *arguments]
runpy.run_path(script, run_name='__main__')
"""


OBSERVE_CACHE_READS = r"""
import atexit, json, os, runpy, sys
script, trace, *arguments = sys.argv[1:]
cache = os.path.join(arguments[2], '.rch-git-archive-cache-v1', arguments[3] + '.sealed')
selected = os.stat(cache, follow_symlinks=False)
original = os.read
reads = []
def read(descriptor, count):
    info = os.fstat(descriptor)
    selected_file = (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino)
    offset = os.lseek(descriptor, 0, os.SEEK_CUR) if selected_file else None
    block = original(descriptor, count)
    if selected_file:
        reads.append([offset, len(block)])
    return block
def record():
    with open(trace, 'x') as output:
        json.dump(reads, output)
atexit.register(record)
os.read = read
sys.argv = [script, *arguments]
runpy.run_path(script, run_name='__main__')
"""


REPLACE_CACHE_AFTER_HEADER = r"""
import os, runpy, sys
script, retained, *arguments = sys.argv[1:]
cache = os.path.join(arguments[2], '.rch-git-archive-cache-v1', arguments[3] + '.sealed')
selected = os.stat(cache, follow_symlinks=False)
original = os.read
replaced = False
def read(descriptor, count):
    global replaced
    info = os.fstat(descriptor)
    block = original(descriptor, count)
    if not replaced and block == b'\n' and (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino):
        replaced = True
        os.rename(cache, retained)
        with open(retained, 'rb') as old, open(cache, 'xb') as new:
            new.write(old.read())
        os.chmod(cache, 0o400)
    return block
os.read = read
sys.argv = [script, *arguments]
runpy.run_path(script, run_name='__main__')
"""


TRUNCATE_CACHE_DURING_COPY = r"""
import os, runpy, sys
script, *arguments = sys.argv[1:]
cache = os.path.join(arguments[2], '.rch-git-archive-cache-v1', arguments[3] + '.sealed')
selected = os.stat(cache, follow_symlinks=False)
with open(cache, 'rb') as stream:
    stream.readline()
    stream.readline()
    header_end = stream.tell()
original = os.read
truncated = False
def read(descriptor, count):
    global truncated
    info = os.fstat(descriptor)
    selected_file = (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino)
    offset = os.lseek(descriptor, 0, os.SEEK_CUR) if selected_file else None
    block = original(descriptor, count)
    if not truncated and selected_file and offset >= header_end and block:
        truncated = True
        os.chmod(cache, 0o600)
        with open(cache, 'r+b') as stream:
            stream.truncate(offset + len(block))
    return block
os.read = read
sys.argv = [script, *arguments]
runpy.run_path(script, run_name='__main__')
"""


class GitArchiveCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.retained = Path(tempfile.mkdtemp(prefix="rch-git-archive-cache-tests-"))
        repo = cls.retained / "git-input"
        repo.mkdir()
        cls.git(repo, "init", "-q")
        (repo / "src").mkdir()
        (repo / "src/lib.rs").write_bytes(b"pub fn pinned_value() -> u32 { 41 }\n")
        (repo / "README.md").write_bytes(b"committed baseline\n")
        (repo / "run.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
        (repo / "run.sh").chmod(0o755)
        (repo / "README_LINK").symlink_to("README.md")
        cls.git(repo, "add", ".")
        cls.git(repo, "-c", "user.name=RCH cache test", "-c", "user.email=rch-cache@example.invalid", "commit", "-qm", "first pin")
        cls.archive = cls.git(repo, "-c", "tar.umask=0022", "archive", "--format=tar", "HEAD")
        (repo / "src/lib.rs").write_bytes(b"pub fn pinned_value() -> u32 { 42 }\n")
        cls.git(repo, "add", ".")
        cls.git(repo, "-c", "user.name=RCH cache test", "-c", "user.email=rch-cache@example.invalid", "commit", "-qm", "second pin")
        cls.changed_archive = cls.git(repo, "-c", "tar.umask=0022", "archive", "--format=tar", "HEAD")
        assert cls.archive != cls.changed_archive
        assert len(cls.archive) == len(cls.changed_archive)
        print("Retained Git archive cache fixtures: " + str(cls.retained), file=sys.stderr)

    @staticmethod
    def git(repo, *arguments):
        return subprocess.run(
            ["/usr/bin/git", "-C", str(repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout

    def setUp(self):
        self.case = self.retained / self._testMethodName
        self.case.mkdir()
        self.source = self.case / "selected source ' quoted"
        self.target = self.case / "target pool"
        self.read_observations = 0

    def arguments(self, operation, archive=None, source=None, target=None, slot=SLOT, minimum=0):
        archive = self.archive if archive is None else archive
        return [
            operation,
            str(self.source if source is None else source),
            str(self.target if target is None else target),
            slot,
            hashlib.sha256(archive).hexdigest(),
            str(len(archive)),
            str(minimum),
        ]

    def invoke(self, operation, **keywords):
        return subprocess.run(
            [sys.executable, "-I", str(HELPER), *self.arguments(operation, **keywords)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def status(self, expected, operation, **keywords):
        output = self.invoke(operation, **keywords)
        self.assertEqual(output.returncode, 0, output)
        self.assertEqual(output.stdout, PREFIX + expected.encode() + b"\n", output)
        self.assertEqual(output.stderr, b"", output)
        return output

    def refused(self, operation, **keywords):
        output = self.invoke(operation, **keywords)
        self.assertNotEqual(output.returncode, 0, output)
        self.assertEqual(output.stdout, b"", output)
        self.assertTrue(output.stderr.startswith(b"RCH_GIT_ARCHIVE_CACHE_ERROR:"), output)
        return output

    def observed_restore(self, expected, payload_bytes, **keywords):
        cache = self.cache_file(keywords.get("slot", SLOT))
        stored = cache.read_bytes()
        header_end = stored.index(b"\n", stored.index(b"\n") + 1) + 1
        trace = self.case / ("cache-reads-" + str(self.read_observations) + ".json")
        self.read_observations += 1
        output = subprocess.run(
            [sys.executable, "-I", "-c", OBSERVE_CACHE_READS, str(HELPER), str(trace), *self.arguments("restore", **keywords)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        self.assertEqual(output.returncode, 0, output)
        self.assertEqual(output.stdout, PREFIX + expected.encode() + b"\n", output)
        self.assertEqual(output.stderr, b"", output)
        reads = json.loads(trace.read_text())
        observed_payload = sum(max(0, offset + count - max(offset, header_end)) for offset, count in reads)
        self.assertEqual(observed_payload, payload_bytes, reads)
        self.assertEqual(sum(count for _, count in reads), header_end + payload_bytes, reads)
        return output

    def stage(self, archive=None, source=None):
        archive = self.archive if archive is None else archive
        source = self.source if source is None else source
        source.mkdir(exist_ok=True)
        path = source / SOURCE_ARCHIVE
        path.write_bytes(archive)
        path.chmod(0o600)
        return path

    def cache_file(self, slot=SLOT):
        return self.target / CACHE_DIRECTORY / (slot + ".sealed")

    def test_cold_publish_warm_restore_is_private_and_exact(self):
        self.status("MISS", "restore")
        self.assertFalse(self.source.exists())
        self.assertFalse(self.target.exists())
        self.stage()
        self.status("PUBLISHED", "publish")
        cache = self.cache_file()
        before = cache.stat()
        old_source = self.case / "retained previous source"
        self.source.rename(old_source)
        (old_source / "generated-by-previous-build").write_bytes(b"must not be restored\n")
        self.observed_restore("HIT", len(self.archive))
        restored = self.source / SOURCE_ARCHIVE
        self.assertEqual(restored.read_bytes(), self.archive)
        self.assertEqual(restored.stat().st_nlink, 1)
        self.assertNotEqual((restored.stat().st_dev, restored.stat().st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(cache.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(list(self.source.iterdir()), [restored])
        with tarfile.open(fileobj=io.BytesIO(restored.read_bytes())) as archive:
            self.assertEqual(archive.extractfile("src/lib.rs").read(), b"pub fn pinned_value() -> u32 { 41 }\n")
            self.assertTrue(archive.getmember("run.sh").mode & 0o111)
            self.assertEqual(archive.getmember("README_LINK").linkname, "README.md")

    def test_alternating_roots_keep_separate_bounded_slots(self):
        sibling = self.case / "sibling source"
        self.stage()
        self.stage(self.changed_archive, sibling)
        self.status("PUBLISHED", "publish")
        self.status("PUBLISHED", "publish", source=sibling, archive=self.changed_archive, slot=OTHER_SLOT)
        self.source.rename(self.case / "retained primary")
        sibling.rename(self.case / "retained sibling")
        self.status("HIT", "restore")
        self.status("HIT", "restore", source=sibling, archive=self.changed_archive, slot=OTHER_SLOT)
        self.status("HIT", "restore")
        self.assertEqual(len(list((self.target / CACHE_DIRECTORY).iterdir())), 2)

    def test_changed_base_misses_then_replaces_one_slot(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        before = self.cache_file().stat()
        self.source.rename(self.case / "retained previous source")
        self.observed_restore("MISS", 0, archive=self.changed_archive)
        self.assertFalse(self.source.exists(), "an unrelated archive cannot create source")
        after = self.cache_file().stat()
        self.assertEqual((after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                         (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns))
        self.stage(self.changed_archive)
        self.status("PUBLISHED", "publish", archive=self.changed_archive)
        self.status("HIT", "restore", archive=self.changed_archive)
        self.status("MISS", "restore")
        self.assertEqual(len(list((self.target / CACHE_DIRECTORY).iterdir())), 1)

    def test_overlay_edits_do_not_change_immutable_cache(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        before = self.cache_file().read_bytes()
        overlay = self.source / "overlay-selected.txt"
        overlay.write_bytes(b"first selected overlay\n")
        self.status("HIT", "restore")
        overlay.write_bytes(b"changed selected overlay\n")
        self.status("HIT", "restore")
        self.assertEqual(overlay.read_bytes(), b"changed selected overlay\n")
        self.assertEqual(self.cache_file().read_bytes(), before)

    def test_corrupt_completed_slot_invalidates_private_copy_and_preserves_cache(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        cache = self.cache_file()
        before = cache.stat()
        data = bytearray(cache.read_bytes())
        data[-1] ^= 1
        cache.chmod(0o600)
        cache.write_bytes(data)
        os.utime(cache, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(cache.stat().st_size, before.st_size)
        self.assertEqual(cache.stat().st_mtime_ns, before.st_mtime_ns)
        source_before = (self.source / SOURCE_ARCHIVE).read_bytes()
        # A different caller pin examines only the declaration. MISS attests
        # neither the unrelated payload nor the existing private source bytes.
        self.observed_restore("MISS", 0, archive=self.changed_archive)
        self.assertEqual((self.source / SOURCE_ARCHIVE).read_bytes(), source_before)
        self.observed_restore("BYPASS_CORRUPT", len(self.archive))
        received = self.source / SOURCE_ARCHIVE
        self.assertEqual(received.stat().st_size, 0, "failed copy must not survive as a full archive")
        self.assertEqual(cache.read_bytes(), data)
        sender = self.stage(source=self.case / "authoritative fallback source")
        output = subprocess.run(
            ["/usr/bin/rsync", "-a", "--no-owner", "--no-group", "--partial", "--checksum", str(sender), str(received)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        self.assertEqual(output.returncode, 0, output)
        self.assertEqual(received.read_bytes(), self.archive)
        self.stage(self.changed_archive)
        self.status("BYPASS_CORRUPT", "publish", archive=self.changed_archive)
        self.assertEqual(cache.read_bytes(), data)
        self.assertEqual(len(list((self.target / CACHE_DIRECTORY).iterdir())), 1)

    def test_header_namespace_replacement_refuses_hit_and_miss_without_source_writes(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        original = (self.source / SOURCE_ARCHIVE).read_bytes()
        for index, selected in enumerate((self.archive, self.changed_archive)):
            retained = self.case / ("replaced sealed entry " + str(index))
            output = subprocess.run(
                [sys.executable, "-I", "-c", REPLACE_CACHE_AFTER_HEADER, str(HELPER), str(retained), *self.arguments("restore", archive=selected)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            )
            self.assertNotEqual(output.returncode, 0, output)
            self.assertEqual(output.stdout, b"", output)
            self.assertIn(b"archive changed during cache operation", output.stderr)
            self.assertEqual((self.source / SOURCE_ARCHIVE).read_bytes(), original)
            self.assertEqual(retained.read_bytes(), self.cache_file().read_bytes())

    def test_noncanonical_or_wrong_slot_headers_bypass_before_source_writes(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        original = (self.source / SOURCE_ARCHIVE).read_bytes()
        magic, header, payload = self.cache_file().read_bytes().split(b"\n", 2)
        for index, changed in enumerate((
            header.replace(SLOT.encode(), OTHER_SLOT.encode()),
            b" " + header,
            b"{\"size\":1," + header[1:],
            b" " * 1025 + header,
        )):
            target = self.case / ("invalid header target " + str(index))
            directory = target / CACHE_DIRECTORY
            directory.mkdir(parents=True, mode=0o700)
            entry = directory / (SLOT + ".sealed")
            contents = magic + b"\n" + changed + b"\n" + payload
            entry.write_bytes(contents)
            entry.chmod(0o400)
            self.status("BYPASS_CORRUPT", "restore", target=target)
            self.assertEqual((self.source / SOURCE_ARCHIVE).read_bytes(), original)
            self.assertEqual(entry.read_bytes(), contents)

    def test_truncation_during_copy_invalidates_partial_private_archive(self):
        repo = self.case / "large Git input"
        repo.mkdir()
        self.git(repo, "init", "-q")
        (repo / "source.bin").write_bytes(bytes(range(256)) * 8193)
        self.git(repo, "add", ".")
        self.git(repo, "-c", "user.name=RCH cache test", "-c", "user.email=rch-cache@example.invalid", "commit", "-qm", "large pinned input")
        archive = self.git(repo, "-c", "tar.umask=0022", "archive", "--format=tar", "HEAD")
        self.assertGreater(len(archive), 2 * 1024**2)
        self.stage(archive)
        self.status("PUBLISHED", "publish", archive=archive)
        cache = self.cache_file()
        original_size = cache.stat().st_size
        output = subprocess.run(
            [sys.executable, "-I", "-c", TRUNCATE_CACHE_DURING_COPY, str(HELPER), *self.arguments("restore", archive=archive)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        self.assertEqual(output.returncode, 0, output)
        self.assertEqual(output.stdout, PREFIX + b"BYPASS_CORRUPT\n", output)
        self.assertEqual(output.stderr, b"", output)
        self.assertLess(cache.stat().st_size, original_size)
        self.assertGreater(cache.stat().st_size, 1024**2)
        self.assertEqual((self.source / SOURCE_ARCHIVE).stat().st_size, 0)

    def test_partial_pending_is_not_a_hit_and_can_be_completed(self):
        self.stage()
        cache = self.target / CACHE_DIRECTORY
        cache.mkdir(parents=True, mode=0o700)
        pending = cache / (SLOT + ".pending")
        pending.write_bytes(b"incomplete previous publication")
        pending.chmod(0o600)
        self.status("MISS", "restore")
        self.assertEqual(pending.read_bytes(), b"incomplete previous publication")
        self.status("PUBLISHED", "publish")
        self.assertFalse(pending.exists())
        self.status("HIT", "restore")

    def test_interruption_before_atomic_publication_preserves_previous_complete_slot(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        previous = self.cache_file().read_bytes()
        self.stage(self.changed_archive)
        output = subprocess.run(
            [sys.executable, "-I", "-c", CRASH_PUBLICATION, str(HELPER), "before", *self.arguments("publish", archive=self.changed_archive)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        self.assertEqual(output.returncode, 91, output)
        self.assertEqual(output.stdout, b"")
        self.assertEqual(output.stderr, b"")
        self.assertEqual(self.cache_file().read_bytes(), previous)
        pending = self.target / CACHE_DIRECTORY / (SLOT + ".pending")
        self.assertTrue(pending.is_file())
        pending_before = pending.read_bytes()
        self.status("HIT", "restore")
        self.assertEqual(pending.read_bytes(), pending_before)
        self.stage(self.changed_archive)
        self.status("PUBLISHED", "publish", archive=self.changed_archive)
        self.status("HIT", "restore", archive=self.changed_archive)

    def test_interruption_after_atomic_publication_exposes_only_verified_archive(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        self.stage(self.changed_archive)
        output = subprocess.run(
            [sys.executable, "-I", "-c", CRASH_PUBLICATION, str(HELPER), "after", *self.arguments("publish", archive=self.changed_archive)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        self.assertEqual(output.returncode, 92, output)
        self.assertEqual(output.stdout, b"")
        self.assertEqual(output.stderr, b"")
        self.status("HIT", "restore", archive=self.changed_archive)
        self.status("MISS", "restore")

    def test_handled_post_copy_fault_leaves_only_empty_reserved_archive(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        for number, (failure, expected) in enumerate([
            ("ENOSPC", "BYPASS_CAPACITY"), ("ENOTSUP", "BYPASS_UNAVAILABLE")
        ]):
            source = self.case / ("fault-source-" + str(number))
            source.mkdir()
            output = subprocess.run(
                [sys.executable, "-I", "-c", FAIL_PRIVATE_FSYNC, str(HELPER), failure, *self.arguments("restore", source=source)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            )
            self.assertEqual(output.returncode, 0, output)
            self.assertEqual(output.stdout, PREFIX + expected.encode() + b"\n", output)
            self.assertEqual(output.stderr, b"", output)
            self.assertEqual(list(source.iterdir()), [source / SOURCE_ARCHIVE])
            self.assertEqual((source / SOURCE_ARCHIVE).stat().st_size, 0)
        self.status("HIT", "restore")

    def test_rsync_integrity_modes_repair_full_length_same_mtime_bad_receivers(self):
        sender = self.stage()
        damaged = bytearray(self.archive)
        damaged[-1] ^= 1
        timestamp = sender.stat().st_mtime_ns
        for integrity in ("--checksum", "--ignore-times"):
            with self.subTest(integrity=integrity):
                destination = self.case / ("fallback source " + integrity)
                destination.mkdir()
                received = destination / SOURCE_ARCHIVE
                received.write_bytes(damaged)
                received.chmod(0o600)
                os.utime(received, ns=(timestamp, timestamp))
                self.assertEqual(sender.stat().st_size, received.stat().st_size)
                self.assertEqual(sender.stat().st_mtime_ns, received.stat().st_mtime_ns)
                output = subprocess.run(
                    ["/usr/bin/rsync", "-a", "--no-owner", "--no-group", "--partial", integrity, str(sender), str(received)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
                )
                self.assertEqual(output.returncode, 0, output)
                self.assertEqual(received.read_bytes(), self.archive)

    def test_free_space_reserve_bypasses_without_replacing_previous_slot(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        previous = self.cache_file().read_bytes()
        self.stage(self.changed_archive)
        self.status("BYPASS_CAPACITY", "publish", archive=self.changed_archive, minimum=2**60)
        self.assertEqual(self.cache_file().read_bytes(), previous)
        self.assertEqual(len(list((self.target / CACHE_DIRECTORY).iterdir())), 1)
        self.status("BYPASS_CAPACITY", "restore", minimum=2**60)
        self.assertEqual((self.source / SOURCE_ARCHIVE).read_bytes(), self.changed_archive)

    def test_slot_count_is_bounded_including_partial_slots(self):
        self.stage()
        cache = self.target / CACHE_DIRECTORY
        cache.mkdir(parents=True, mode=0o700)
        for number in range(64):
            pending = cache / (hashlib.sha256(str(number).encode()).hexdigest() + ".pending")
            pending.write_bytes(b"partial")
            pending.chmod(0o600)
        self.status("BYPASS_CAPACITY", "publish")
        self.assertEqual(len(list(cache.iterdir())), 64)

    def test_aggregate_byte_cap_accounts_for_pending_without_allocating_payload(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        pending = self.target / CACHE_DIRECTORY / (OTHER_SLOT + ".pending")
        # A sparse metadata control exercises the real 1 GiB bound without
        # allocating a large fixture or filling this host's filesystem.
        with pending.open("wb") as stream:
            stream.truncate(1024**3)
        pending.chmod(0o600)
        self.assertLessEqual(pending.stat().st_blocks * 512, 4096)
        self.status("BYPASS_CAPACITY", "restore")
        self.status("BYPASS_CAPACITY", "publish")

    def test_source_and_cache_symlinks_hardlinks_and_fifo_are_refused(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        cache = self.cache_file()
        hardlink = self.case / "retained hardlinked cache"
        os.link(cache, hardlink)
        self.refused("restore")
        self.refused("publish")
        # Separate retained roots keep each negative independent, without
        # deleting evidence or silently repairing an unsafe slot.
        for index, kind in enumerate(("symlink", "fifo")):
            target = self.case / ("bad-target-" + str(index))
            directory = target / CACHE_DIRECTORY
            directory.mkdir(parents=True, mode=0o700)
            entry = directory / (SLOT + ".sealed")
            if kind == "symlink":
                entry.symlink_to(self.case / "outside missing archive")
            else:
                os.mkfifo(entry, 0o600)
            self.refused("restore", target=target)
        source_alias = self.case / "source root alias"
        source_alias.symlink_to(self.source, target_is_directory=True)
        self.refused("publish", source=source_alias)

    def test_source_archive_hardlink_never_changes_other_inode(self):
        original = self.stage()
        self.status("PUBLISHED", "publish")
        os.link(original, self.case / "source archive second link")
        before = original.read_bytes()
        self.refused("restore")
        self.refused("publish")
        self.assertEqual(original.read_bytes(), before)

    def test_private_cache_and_root_entries_cannot_be_symlinks(self):
        self.stage()
        outside = self.case / "outside cache"
        outside.mkdir(mode=0o700)
        self.target.mkdir()
        (self.target / CACHE_DIRECTORY).symlink_to(outside, target_is_directory=True)
        self.refused("restore")
        self.refused("publish")
        self.assertEqual(list(outside.iterdir()), [])
        target_alias = self.case / "target root alias"
        target_alias.symlink_to(self.target, target_is_directory=True)
        self.refused("restore", target=target_alias)

    def test_unsupported_ancestor_alias_bypasses_without_following_or_creating(self):
        self.stage()
        physical = self.case / "physical ancestor"
        physical.mkdir()
        alias = self.case / "ancestor alias"
        alias.symlink_to(physical, target_is_directory=True)
        self.status("BYPASS_UNAVAILABLE", "restore", target=alias / "target")
        self.status("BYPASS_UNAVAILABLE", "publish", target=alias / "target")
        self.assertEqual(list(physical.iterdir()), [])

    def test_missing_parent_outside_target_authority_is_not_created(self):
        self.stage()
        parent = self.case / "ungranted parent"
        self.status("BYPASS_UNAVAILABLE", "publish", target=parent / "target")
        self.assertFalse(parent.exists())

    @unittest.skipUnless(os.geteuid() == 0, "foreign-owner fixture requires chown authority")
    def test_foreign_owned_cache_or_root_is_not_accepted(self):
        self.stage()
        self.status("PUBLISHED", "publish")
        os.chown(self.cache_file(), 65534, 65534)
        self.refused("restore")
        self.refused("publish")
        foreign = self.case / "foreign target"
        foreign.mkdir()
        os.chown(foreign, 65534, 65534)
        self.refused("restore", target=foreign)

    def test_uploaded_source_digest_or_length_mismatch_is_hard_failure(self):
        path = self.stage(self.changed_archive)
        self.refused("publish")
        path.write_bytes(self.archive[:-1])
        self.refused("publish")
        self.assertFalse(self.target.exists())

    def test_invalid_slot_and_escaping_roots_are_hard_failures(self):
        self.stage()
        self.refused("restore", slot="../escape")
        self.refused("restore", target=self.source)
        self.refused("restore", target=self.source / "nested target")
        self.refused("restore", source=self.case / "unselected/../source")

    def test_publication_uses_worker_time_not_future_source_archive_time(self):
        source = self.stage()
        future = 4_000_000_000_000_000_000
        os.utime(source, ns=(future, future))
        self.status("PUBLISHED", "publish")
        self.assertLess(self.cache_file().stat().st_mtime_ns, future)
        self.assertEqual(stat.S_IMODE(self.cache_file().stat().st_mode), 0o400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
