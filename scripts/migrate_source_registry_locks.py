#!/usr/bin/env python3
"""Repair the v2.1.34 lock modes before using published v2.1.35 clients.

Run as the registry owner, first without --apply (or with --dry-run):

    python3 -I -S scripts/migrate_source_registry_locks.py --owner-uid "$(id -u)" \
      --registry /tmp/rch-source-authority-locks/claims-v1 \
      --registry /var/tmp/rch-source-authority-locks/claims-v1

After reviewing the JSON lines, repeat with --apply. Supply physical absolute
paths: symlinks, including Darwin's /tmp alias, are refused; explicitly use
/private/tmp there. Nothing is created, removed, renamed, or read as a claim.
Only group/other write bits on validated top-level metadata/activity locks are
cleared. Production upload.<sha256>.lock files must already have safe modes;
they are validated and reported as untouched, never chmod'ed or fsynced.
Existing flocks stay on the same inode and are neither acquired nor released.

Operational precondition: do not run concurrent administrative chmod/chown/ACL
updates, link operations, or registry directory moves. Normal RCH lock use and
its identical write-bit healer may continue. fchmod sets a complete mode, not
an atomic clear-bits operation: rechecks detect observed changes but cannot
protect against arbitrary same-UID metadata mutations between syscalls.

Every selected registry is checked before the first change. A later race,
failure, or interruption can leave a partially completed migration: rerun the
same command after resolving the refusal. Already repaired locks are unchanged.
This does not prove cancellation, worker health, build drain, or fleet readiness.
Old writers can create more legacy locks; rerun the dry-run after upgrading them.
"""

import argparse
from contextlib import ExitStack, contextmanager
import json
import os
import re
import stat
import sys


LOCK_NAME = re.compile(r"[a-f0-9-]{1,128}\.activity\.lock\Z")
UPLOAD_LOCK_NAME = re.compile(r"upload\.[a-f0-9]{64}\.lock\Z")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class Refused(Exception):
    """The named object cannot safely be migrated."""


def identity(info):
    return info.st_dev, info.st_ino


def lock_state(info):
    return identity(info), info.st_uid, info.st_nlink, stat.S_IMODE(info.st_mode)


def check_directory(info, owner_uid, private):
    if not stat.S_ISDIR(info.st_mode):
        raise Refused("not a directory")
    mode = stat.S_IMODE(info.st_mode)
    if private:
        if info.st_uid != owner_uid or mode != 0o700:
            raise Refused("registry and its authority directory must be owned by the requested UID and mode 0700")
    elif (info.st_uid not in (0, owner_uid) or mode & 0o6000
          or (mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX))):
        raise Refused("untrusted ancestor ownership or write permissions")


def check_lock(info, owner_uid, upload=False):
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode):
        raise Refused("lock is not a regular file (symlinks and special objects are refused)")
    if info.st_uid != owner_uid:
        raise Refused("lock is not owned by the requested UID")
    if info.st_nlink != 1:
        raise Refused("lock has multiple links")
    if mode & 0o7111 or mode & 0o600 != 0o600:
        raise Refused("lock has unexpected special, executable, or owner permissions")
    if upload and mode & 0o022:
        raise Refused("upload lock has unsafe write permissions; only metadata/activity locks may be repaired")


class Registry:
    """Pin every path component and verify its name still refers to that inode."""

    def __init__(self, path, owner_uid, stack):
        if (not os.path.isabs(path) or path != os.path.normpath(path)
                or path.startswith("//")
                or path.split("/")[-2:] != ["rch-source-authority-locks", "claims-v1"]):
            raise Refused("registry must be a physical absolute path ending in /rch-source-authority-locks/claims-v1")
        self.path = path
        self.owner_uid = owner_uid
        self.nodes = []
        self.missing = None
        self.directory = None
        parts = path.split("/")[1:]
        parent = os.open("/", DIRECTORY_FLAGS)
        stack.callback(os.close, parent)
        check_directory(os.fstat(parent), owner_uid, False)
        self.nodes.append((None, "/", parent, identity(os.fstat(parent)), False))
        for index, name in enumerate(parts):
            try:
                descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
            except FileNotFoundError:
                self.missing = (parent, name)
                return
            stack.callback(os.close, descriptor)
            private = index >= len(parts) - 2
            check_directory(os.fstat(descriptor), owner_uid, private)
            self.nodes.append((parent, name, descriptor, identity(os.fstat(descriptor)), private))
            parent = descriptor
        self.directory = parent

    def verify(self):
        for parent, name, descriptor, original, private in self.nodes:
            opened = os.fstat(descriptor)
            check_directory(opened, self.owner_uid, private)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if identity(named) != original or identity(opened) != original:
                raise Refused("registry path changed during migration")
        if self.missing is not None:
            parent, name = self.missing
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise Refused("previously absent registry path appeared during migration")

    def locks(self):
        self.verify()
        if self.directory is None:
            return []
        names = []
        for name in os.listdir(self.directory):
            if name == "metadata.lock" or LOCK_NAME.fullmatch(name) or UPLOAD_LOCK_NAME.fullmatch(name):
                names.append(name)
            elif name.endswith(".lock"):
                raise Refused("unrecognized registry lock name: " + repr(name))
        return sorted(names)

    @contextmanager
    def open_lock(self, name, expected=None):
        self.verify()
        # Check before open as well as afterwards: a FIFO must never block this
        # tool, and a device/socket must not be accepted as a lock.
        upload = bool(UPLOAD_LOCK_NAME.fullmatch(name))
        named = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
        check_lock(named, self.owner_uid, upload)
        descriptor = os.open(name, FILE_FLAGS, dir_fd=self.directory)
        try:
            info = os.fstat(descriptor)
            check_lock(info, self.owner_uid, upload)
            if identity(info) != identity(named) or (expected is not None and lock_state(info) != expected):
                raise Refused("registry lock changed since inspection: " + repr(name))
            checked = self.verify_lock(name, descriptor)
            if lock_state(checked) != lock_state(info):
                raise Refused("registry lock changed while opening: " + repr(name))
            yield descriptor, checked
        finally:
            os.close(descriptor)

    def verify_lock(self, name, descriptor):
        self.verify()
        upload = bool(UPLOAD_LOCK_NAME.fullmatch(name))
        info = os.fstat(descriptor)
        check_lock(info, self.owner_uid, upload)
        named = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
        check_lock(named, self.owner_uid, upload)
        if lock_state(named) != lock_state(info):
            raise Refused("registry lock name or inode changed during migration: " + repr(name))
        return info


def migrate(paths, owner_uid, apply=False, emit=None):
    """Validate all roots, then narrow only the validated file descriptors."""
    if owner_uid < 0 or owner_uid != os.geteuid():
        raise Refused("run as the requested registry owner; root does not authorize changing another UID's files")
    if not paths or len(paths) != len(set(paths)):
        raise Refused("supply one or more distinct registry paths")
    emit = emit or (lambda event: None)
    summary = {"mode": "apply" if apply else "dry-run", "owner_uid": owner_uid,
               "registries": len(paths), "absent": 0, "unchanged": 0, "untouched": 0,
               "would_change": 0, "changed": 0}
    with ExitStack() as stack:
        registries = [Registry(path, owner_uid, stack) for path in paths]
        present = [identity(os.fstat(registry.directory)) for registry in registries
                   if registry.directory is not None]
        if len(present) != len(set(present)):
            raise Refused("selected registries alias the same directory")
        snapshots = [(registry, registry.locks()) for registry in registries]
        planned = []
        for registry, names in snapshots:
            if registry.directory is None:
                summary["absent"] += 1
            for name in names:
                with registry.open_lock(name) as (_, info):
                    planned.append((registry, name, lock_state(info)))
        # A refusal anywhere above leaves all selected registries untouched.
        for registry, name, expected in planned:
            with registry.open_lock(name, expected) as (descriptor, info):
                upload = bool(UPLOAD_LOCK_NAME.fullmatch(name))
                before = stat.S_IMODE(info.st_mode)
                after = before if upload else before & ~0o022
                action = "untouched" if upload else "unchanged"
                if not upload and before != after:
                    action = "would_change"
                    if apply:
                        os.fchmod(descriptor, after)
                        action = "changed"
                if apply and not upload:
                    # Re-fsync an already repaired inode too: a previous run
                    # may have stopped after fchmod but before its fsync.
                    os.fsync(descriptor)
                checked = registry.verify_lock(name, descriptor)
                if stat.S_IMODE(checked.st_mode) != (after if apply else before):
                    raise Refused("registry lock mode changed during migration: " + repr(name))
                summary[action] += 1
                emit({"path": registry.path + "/" + name, "action": action,
                      "before": format(before, "04o"), "after": format(after, "04o")})
        for registry, name, expected in planned:
            original_inode, uid, links, mode = expected
            repair = apply and not UPLOAD_LOCK_NAME.fullmatch(name)
            final_state = (original_inode, uid, links, mode & ~0o022 if repair else mode)
            # Checking just the filename set would miss a concurrent writer
            # replacing an earlier repaired lock under the very same name.
            with registry.open_lock(name, final_state):
                pass
        for registry, names in snapshots:
            if registry.locks() != names:
                raise Refused("registry lock set changed; rerun after inspecting concurrent writers")
            if registry.directory is None:
                emit({"path": registry.path, "action": "absent"})
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registry", action="append", required=True,
                        help="explicit physical registry path; repeat for /tmp and /var/tmp")
    parser.add_argument("--owner-uid", type=int, required=True,
                        help="expected registry UID; must equal the invoking effective UID")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="inspect only (the default)")
    mode.add_argument("--apply", action="store_true", help="clear group/other write bits after validation")
    args = parser.parse_args(argv)
    changed = 0

    def emit(event):
        nonlocal changed
        changed += event["action"] == "changed"
        print(json.dumps(event, sort_keys=True), flush=True)

    try:
        summary = migrate(args.registry, args.owner_uid, args.apply, emit)
        print(json.dumps({"status": "complete", **summary}, sort_keys=True), flush=True)
        return 0
    except (Refused, OSError) as error:
        print(json.dumps({"status": "refused", "confirmed_changes": changed,
                          "changes_may_be_partial": args.apply,
                          "reason": str(error), "next_step": "resolve the refusal and rerun; completed permission changes are safe to retain"}),
              file=sys.stderr, flush=True)
        return 73
    except KeyboardInterrupt:
        print(json.dumps({"status": "interrupted", "confirmed_changes": changed,
                          "changes_may_be_partial": args.apply,
                          "next_step": "rerun the same migration; completed permission changes are safe to retain"}),
              file=sys.stderr, flush=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
