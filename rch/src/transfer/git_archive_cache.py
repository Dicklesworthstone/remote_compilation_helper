#!/usr/bin/env python3
"""Reuse verified Git archive bytes inside an already granted target pool.

The caller must hold its existing source/target authority through this entire
process. This program neither obtains authority nor retires source. Its cache
is only an optimization: the caller's independently generated SHA-256 and size
remain the source authority, and every restore copies into a private archive.

Usage: restore|publish SOURCE_ROOT TARGET_ROOT SLOT SHA256 SIZE MIN_FREE_BYTES
Exit zero has exactly one RCH_GIT_ARCHIVE_CACHE_V1 status line. Unexpected I/O
and unsafe entries fail with stderr, never an invented cache miss.
"""

import contextlib
import errno
import hashlib
import json
import os
import re
import stat
import sys


CACHE_DIRECTORY = ".rch-git-archive-cache-v1"
SOURCE_ARCHIVE = ".rch-clean-overlay-base.tar"
MAGIC = b"RCH-GIT-ARCHIVE-CACHE-V1\n"
SCHEMA = "rch.git_archive_cache.v1"
MAX_HEADER_BYTES = 1024
MAX_CACHE_BYTES = 1024**3
MAX_SLOTS = 64
BLOCK_BYTES = 1024**2
HEX = re.compile(r"[0-9a-f]{64}\Z")
SLOT_FILE = re.compile(r"([0-9a-f]{64})\.(sealed|pending)\Z")
PREFIX = "RCH_GIT_ARCHIVE_CACHE_V1 "
ERROR_PREFIX = "RCH_GIT_ARCHIVE_CACHE_ERROR:"


class UnsafeCache(Exception):
    pass


class CorruptCache(Exception):
    pass


class BypassCache(Exception):
    def __init__(self, status):
        super().__init__(status)
        self.status = status


def require(condition, reason):
    if not condition:
        raise UnsafeCache(reason)


def literal_path(value):
    require(
        value.startswith("/")
        and value != "/"
        and len(value.encode("utf-8")) <= 4096
        and "\\" not in value
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
        and all(part not in ("", ".", "..") for part in value.split("/")[1:]),
        "nonliteral root",
    )
    require(len(value.split("/")) <= 128, "root depth exceeded")
    return value


def snapshot(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def same_inode(first, second):
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def directory_metadata(info, final=False, private=False):
    require(stat.S_ISDIR(info.st_mode), "non-directory root or ancestor")
    require(
        info.st_uid == os.geteuid() if final else info.st_uid in (0, os.geteuid()),
        "foreign directory owner",
    )
    # Root-owned sticky temporary bases are supported, but a writable ordinary
    # ancestor would let another uid substitute the namespace around the grant.
    require(
        not (info.st_mode & 0o022)
        or (info.st_uid == 0 and info.st_mode & stat.S_ISVTX and not final),
        "writable directory namespace",
    )
    if private:
        require(not (info.st_mode & 0o077), "cache directory is not private")


def regular_metadata(info):
    require(stat.S_ISREG(info.st_mode), "nonregular archive entry")
    require(info.st_uid == os.geteuid(), "foreign archive owner")
    require(info.st_nlink == 1, "hardlinked archive entry")
    require(not (info.st_mode & 0o022), "writable archive entry")


class Directory:
    def __init__(self, descriptor, anchors):
        self.fd = descriptor
        self.anchors = anchors

    def check(self):
        for parent, name, descriptor, final, private in self.anchors:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            opened = os.fstat(descriptor)
            directory_metadata(named, final, private)
            require(same_inode(named, opened), "directory changed during cache operation")


def open_directory(path, stack, create=False):
    """Only the exact provided root may be created; ancestors must exist."""
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stack.callback(os.close, current)
    anchors = []
    parts = path.split("/")[1:]
    for index, name in enumerate(parts):
        final = index == len(parts) - 1
        try:
            named = os.stat(name, dir_fd=current, follow_symlinks=False)
        except FileNotFoundError:
            if not create:
                return None
            if not final:
                raise BypassCache("BYPASS_UNAVAILABLE")
            os.mkdir(name, 0o755, dir_fd=current)
            named = os.stat(name, dir_fd=current, follow_symlinks=False)
        if stat.S_ISLNK(named.st_mode) and not final:
            # Existing RCH transports support aliases such as Darwin /tmp.
            # This optimization does not follow them or mutate through them.
            raise BypassCache("BYPASS_UNAVAILABLE")
        directory_metadata(named, final)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
        stack.callback(os.close, child)
        require(same_inode(named, os.fstat(child)), "directory changed while opening")
        anchors.append((current, name, child, final, False))
        current = child
    result = Directory(current, anchors)
    result.check()
    return result


def open_cache(target, stack, create=False):
    try:
        named = os.stat(CACHE_DIRECTORY, dir_fd=target.fd, follow_symlinks=False)
    except FileNotFoundError:
        if not create:
            return None
        target.check()
        os.mkdir(CACHE_DIRECTORY, 0o700, dir_fd=target.fd)
        named = os.stat(CACHE_DIRECTORY, dir_fd=target.fd, follow_symlinks=False)
    directory_metadata(named, final=True, private=True)
    descriptor = os.open(
        CACHE_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=target.fd
    )
    stack.callback(os.close, descriptor)
    require(same_inode(named, os.fstat(descriptor)), "cache directory changed while opening")
    result = Directory(
        descriptor, target.anchors + [(target.fd, CACHE_DIRECTORY, descriptor, True, True)]
    )
    result.check()
    return result


def entry_metadata(directory, name):
    try:
        info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    regular_metadata(info)
    return info


def open_regular(directory, name, stack):
    before = entry_metadata(directory, name)
    if before is None:
        return None
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory.fd)
    stack.callback(os.close, descriptor)
    opened = os.fstat(descriptor)
    regular_metadata(opened)
    require(snapshot(before) == snapshot(opened), "archive changed while opening")
    return descriptor, opened


def unchanged(directory, name, descriptor, before):
    directory.check()
    after = os.fstat(descriptor)
    named = entry_metadata(directory, name)
    require(
        named is not None and snapshot(before) == snapshot(after) == snapshot(named),
        "archive changed during cache operation",
    )


def inventory(cache):
    cache.check()
    slots = set()
    entries = {}
    total = 0
    with os.scandir(cache.fd) as listing:
        for item in listing:
            if len(entries) >= MAX_SLOTS * 2:
                raise BypassCache("BYPASS_CAPACITY")
            match = SLOT_FILE.fullmatch(item.name)
            if match is None:
                raise CorruptCache("unexpected cache entry")
            info = entry_metadata(cache, item.name)
            require(info is not None, "cache inventory changed")
            entries[item.name] = info
            slots.add(match.group(1))
            total += info.st_size
            if len(slots) > MAX_SLOTS or total > MAX_CACHE_BYTES:
                raise BypassCache("BYPASS_CAPACITY")
    cache.check()
    return slots, entries, total


def header_bytes(slot, digest, size):
    header = {"schema": SCHEMA, "slot": slot, "sha256": digest, "size": size}
    return MAGIC + json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def read_header(descriptor, expected_slot, file_size):
    os.lseek(descriptor, 0, os.SEEK_SET)
    prefix = bytearray()
    while len(prefix) < len(MAGIC):
        block = os.read(descriptor, len(MAGIC) - len(prefix))
        if not block:
            raise CorruptCache("truncated cache magic")
        prefix.extend(block)
    if bytes(prefix) != MAGIC:
        raise CorruptCache("invalid cache magic")
    line = bytearray()
    while len(line) <= MAX_HEADER_BYTES:
        char = os.read(descriptor, 1)
        if not char:
            raise CorruptCache("truncated cache header")
        line.extend(char)
        if char == b"\n":
            break
    if len(line) > MAX_HEADER_BYTES:
        raise CorruptCache("oversized cache header")
    try:
        header = json.loads(line)
    except (UnicodeError, ValueError) as error:
        raise CorruptCache("invalid cache header") from error
    if not (
        isinstance(header, dict)
        and set(header) == {"schema", "slot", "sha256", "size"}
        and header["schema"] == SCHEMA
        and header["slot"] == expected_slot
        and isinstance(header["sha256"], str)
        and HEX.fullmatch(header["sha256"])
        and type(header["size"]) is int
        and 0 < header["size"] <= MAX_CACHE_BYTES
    ):
        raise CorruptCache("invalid cache declaration")
    canonical = header_bytes(expected_slot, header["sha256"], header["size"])
    if canonical != MAGIC + bytes(line) or len(canonical) + header["size"] != file_size:
        raise CorruptCache("cache size or framing mismatch")
    return header, len(canonical)


def write_all(descriptor, data):
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        require(written > 0, "archive write made no progress")
        view = view[written:]


def hash_payload(descriptor, size, output=None):
    hasher = hashlib.sha256()
    remaining = size
    while remaining:
        block = os.read(descriptor, min(BLOCK_BYTES, remaining))
        if not block:
            raise CorruptCache("truncated archive payload")
        if output is not None:
            write_all(output, block)
        hasher.update(block)
        remaining -= len(block)
    if os.read(descriptor, 1):
        raise CorruptCache("oversized archive payload")
    return hasher.hexdigest()


def verify_sealed(cache, name, slot, stack):
    opened = open_regular(cache, name, stack)
    if opened is None:
        return None
    descriptor, before = opened
    header, offset = read_header(descriptor, slot, before.st_size)
    digest = hash_payload(descriptor, header["size"])
    unchanged(cache, name, descriptor, before)
    if digest != header["sha256"]:
        raise CorruptCache("completed archive digest mismatch")
    return descriptor, before, header, offset


def free_space(directory, required, minimum):
    info = os.fstatvfs(directory.fd)
    available = info.f_bavail * info.f_frsize
    if available < required + minimum:
        raise BypassCache("BYPASS_CAPACITY")


def open_pending(directory, name, stack):
    before = entry_metadata(directory, name)
    if before is None:
        descriptor = os.open(
            name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory.fd
        )
        stack.callback(os.close, descriptor)
    else:
        opened = open_regular(directory, name, stack)
        require(opened is not None, "pending archive disappeared")
        old_descriptor, old_info = opened
        # An interruption immediately before publication can leave a fully
        # verified read-only pending file. Only this nonauthoritative slot is
        # reset; completed or corrupt evidence is never opened for writing.
        os.fchmod(old_descriptor, 0o600)
        descriptor = os.open(name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory.fd)
        stack.callback(os.close, descriptor)
        require(same_inode(old_info, os.fstat(descriptor)), "pending archive changed")
    regular_metadata(os.fstat(descriptor))
    directory.check()
    os.ftruncate(descriptor, 0)
    return descriptor


def restore(source_path, target_path, slot, digest, size, minimum, stack):
    target = open_directory(target_path, stack)
    if target is None:
        return "MISS"
    cache = open_cache(target, stack)
    if cache is None:
        return "MISS"
    inventory(cache)
    name = slot + ".sealed"
    found = verify_sealed(cache, name, slot, stack)
    if found is None:
        return "MISS"
    descriptor, before, header, offset = found
    if header["sha256"] != digest or header["size"] != size:
        return "MISS"
    source = open_directory(source_path, stack, create=True)
    free_space(source, size, minimum)
    # Source is private to the held grant and cannot execute before HIT. Write
    # only its already reserved transport file: a second staging filename would
    # remain unselected input after an optional cache bypass. Never hardlink it.
    private_archive = open_pending(source, SOURCE_ARCHIVE, stack)

    def invalidate_private_copy():
        source.check()
        named = entry_metadata(source, SOURCE_ARCHIVE)
        opened = os.fstat(private_archive)
        regular_metadata(opened)
        require(named is not None and same_inode(named, opened), "private archive changed before invalidation")
        try:
            os.ftruncate(private_archive, 0)
        except OSError as error:
            raise UnsafeCache("could not invalidate failed private archive") from error
        require(os.fstat(private_archive).st_size == 0, "private archive invalidation failed")

    try:
        os.lseek(descriptor, offset, os.SEEK_SET)
        copied = hash_payload(descriptor, size, private_archive)
        unchanged(cache, name, descriptor, before)
        if copied != digest:
            raise CorruptCache("cache changed during private copy")
        os.fsync(private_archive)
        os.fsync(source.fd)
        source.check()
        completed = entry_metadata(source, SOURCE_ARCHIVE)
        require(
            completed is not None and completed.st_size == size
            and same_inode(completed, os.fstat(private_archive)),
            "restored archive changed",
        )
    except (CorruptCache, BypassCache):
        invalidate_private_copy()
        raise
    except OSError as error:
        if error.errno in (
            errno.ENOSPC, errno.EDQUOT, errno.EROFS, errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP
        ):
            # append-verify can skip a receiver file already as long as the
            # sender. A full-size failed copy must become empty before fallback.
            invalidate_private_copy()
        raise
    return "HIT"


def publish(source_path, target_path, slot, digest, size, minimum, stack):
    source = open_directory(source_path, stack)
    require(source is not None, "uploaded source root is absent")
    opened = open_regular(source, SOURCE_ARCHIVE, stack)
    require(opened is not None, "uploaded archive is absent")
    source_descriptor, source_info = opened
    require(source_info.st_size == size, "uploaded archive size mismatch")
    try:
        observed = hash_payload(source_descriptor, size)
    except CorruptCache as error:
        raise UnsafeCache("uploaded archive changed") from error
    unchanged(source, SOURCE_ARCHIVE, source_descriptor, source_info)
    require(observed == digest, "uploaded archive digest mismatch")

    target = open_directory(target_path, stack, create=True)
    cache = open_cache(target, stack, create=True)
    slots, entries, total = inventory(cache)
    name = slot + ".sealed"
    previous = verify_sealed(cache, name, slot, stack)
    if previous is not None and previous[2]["sha256"] == digest and previous[2]["size"] == size:
        return "PUBLISHED"
    if slot not in slots and len(slots) >= MAX_SLOTS:
        return "BYPASS_CAPACITY"
    header = header_bytes(slot, digest, size)
    candidate_size = len(header) + size
    pending_name = slot + ".pending"
    pending_info = entries.get(pending_name)
    previous_pending_size = pending_info.st_size if pending_info is not None else 0
    if total - previous_pending_size + candidate_size > MAX_CACHE_BYTES:
        return "BYPASS_CAPACITY"
    reclaimed = getattr(pending_info, "st_blocks", 0) * 512 if pending_info is not None else 0
    free_space(cache, max(0, candidate_size - reclaimed), minimum)
    pending = open_pending(cache, pending_name, stack)
    write_all(pending, header)
    os.lseek(source_descriptor, 0, os.SEEK_SET)
    try:
        copied = hash_payload(source_descriptor, size, pending)
    except CorruptCache as error:
        raise UnsafeCache("uploaded archive changed during publication") from error
    unchanged(source, SOURCE_ARCHIVE, source_descriptor, source_info)
    require(copied == digest, "uploaded archive changed during publication")
    # Do not copy caller mtimes: freshness considers every regular pool file.
    os.fchmod(pending, 0o400)
    os.fsync(pending)
    cache.check()
    if previous is not None:
        unchanged(cache, name, previous[0], previous[1])
    else:
        require(entry_metadata(cache, name) is None, "completed cache appeared during publication")
    os.replace(pending_name, name, src_dir_fd=cache.fd, dst_dir_fd=cache.fd)
    os.fsync(cache.fd)
    cache.check()
    completed = entry_metadata(cache, name)
    require(completed is not None and same_inode(completed, os.fstat(pending)), "published archive changed")
    return "PUBLISHED"


def main(arguments):
    require(len(arguments) == 7, "expected operation and six arguments")
    operation, source_path, target_path, slot, digest, raw_size, raw_minimum = arguments
    require(operation in ("restore", "publish"), "invalid cache operation")
    literal_path(source_path)
    literal_path(target_path)
    require(
        source_path != target_path
        and not source_path.startswith(target_path + "/")
        and not target_path.startswith(source_path + "/"),
        "source and target roots overlap",
    )
    require(HEX.fullmatch(slot) is not None and HEX.fullmatch(digest) is not None, "invalid digest or slot")
    require(
        raw_size.isascii() and raw_size.isdecimal() and raw_minimum.isascii() and raw_minimum.isdecimal()
        and len(raw_size) <= 20 and len(raw_minimum) <= 20,
        "invalid cache byte limits",
    )
    size, minimum = int(raw_size), int(raw_minimum)
    require(0 < size < 2**63 and minimum < 2**63, "cache byte limits out of range")
    if size + len(header_bytes(slot, digest, size)) > MAX_CACHE_BYTES:
        return "BYPASS_CAPACITY"
    with contextlib.ExitStack() as stack:
        if operation == "restore":
            return restore(source_path, target_path, slot, digest, size, minimum, stack)
        return publish(source_path, target_path, slot, digest, size, minimum, stack)


if __name__ == "__main__":
    try:
        status = main(sys.argv[1:])
    except CorruptCache:
        status = "BYPASS_CORRUPT"
    except BypassCache as error:
        status = error.status
    except OSError as error:
        if error.errno in (errno.ENOSPC, errno.EDQUOT):
            status = "BYPASS_CAPACITY"
        elif error.errno in (errno.EROFS, errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP):
            status = "BYPASS_UNAVAILABLE"
        else:
            sys.stderr.write(ERROR_PREFIX + "filesystem:" + str(error) + "\n")
            raise SystemExit(74)
    except (UnsafeCache, UnicodeError, ValueError) as error:
        sys.stderr.write(ERROR_PREFIX + str(error) + "\n")
        raise SystemExit(74)
    sys.stdout.write(PREFIX + status + "\n")
