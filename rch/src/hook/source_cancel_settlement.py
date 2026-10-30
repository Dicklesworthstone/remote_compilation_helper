"""Locate exact source ownership or settle a terminal cancellation.

The dispatcher calls this only under its durable recovery journal ownership,
before recording a missing namespace binding, or after validating completed
source/tree/pair retirement. Location grants no source access. Settlement
requires the previously recorded binding. This program never inspects source
trees; the shell transaction remains the sole registry state machine.
"""
import errno
import fcntl
import hashlib
import os
import re
import stat
import subprocess
import sys
import time


def refuse(reason):
    print("RCH_SOURCE_CANCELLATION_UNSETTLED " + reason, file=sys.stderr)
    raise SystemExit(73)


def identity(info):
    return info.st_dev, info.st_ino


def private(info, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        refuse("unsafe registry ownership or file type")
    if not directory and info.st_nlink != 1:
        refuse("registry lock has multiple links")


def main():
    if len(sys.argv) != 8:
        refuse("invalid settlement request")
    current, legacy, token, digest, transaction, operation, expected = sys.argv[1:]
    if ((operation == "locate" and expected != "")
            or (operation == "settle-cancel" and expected not in ("current", "legacy"))
            or operation not in ("locate", "settle-cancel")):
        refuse("invalid source authority namespace request")
    if not re.fullmatch(r"[a-f0-9-]{1,128}", token) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        refuse("invalid settlement identity")
    roots = sys.stdin.buffer.read(32 * 1024 * 1024 + 1)
    if not roots or len(roots) > 32 * 1024 * 1024 or hashlib.sha256(roots).hexdigest() != digest:
        refuse("settlement roots do not match identity digest")
    if current == legacy or not all(os.path.isabs(path) for path in (current, legacy)):
        refuse("invalid registry namespace")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    registries, absent, locks = [], [], []
    for path in (current, legacy):
        # Open the registry's immediate parent too: checking just its leaf
        # would follow a substituted rch-source-authority-locks symlink.
        parent_path, name = os.path.split(path)
        try:
            parent = os.open(parent_path, flags)
        except FileNotFoundError:
            absent.append(path)
            continue
        private(os.fstat(parent), directory=True)
        try:
            directory = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError:
            absent.append(path)
            os.close(parent)
            continue
        private(os.fstat(directory), directory=True)
        registries.append((path, parent, directory))
    if not registries:
        refuse("no worker registry evidence for identity=" + token)
    if len({identity(os.fstat(row[2])) for row in registries}) != len(registries):
        refuse("registry namespaces alias the same directory")

    def verify():
        for path in absent:
            if os.path.lexists(path):
                refuse("registry appeared during settlement")
        for path, parent, directory in registries:
            private(os.fstat(parent), directory=True)
            private(os.fstat(directory), directory=True)
            if identity(os.stat(os.path.dirname(path), follow_symlinks=False)) != identity(os.fstat(parent)):
                refuse("registry parent changed during settlement")
            if identity(os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)) != identity(os.fstat(directory)):
                refuse("registry changed during settlement")
        for directory, name, descriptor in locks:
            private(os.fstat(descriptor))
            if identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != identity(os.fstat(descriptor)):
                refuse("registry lock changed during settlement")

    # All activity locks precede all metadata locks. A cancelled identity has
    # no new normal activity; acquiring these drains any previously admitted
    # operation. Fixed ordering also serializes concurrent recovery clients.
    started = time.monotonic()
    deadline = started + 5
    for name in (token + ".activity.lock", "metadata.lock"):
        for path, _, directory in registries:
            descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 0o600, dir_fd=directory)
            private(os.fstat(descriptor))
            if any(identity(os.fstat(item[2])) == identity(os.fstat(descriptor)) for item in locks):
                refuse("registry locks alias the same inode")
            locks.append((directory, name, descriptor))
            while True:
                verify()
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as error:
                    if error.errno not in (errno.EAGAIN, errno.EACCES):
                        raise
                if time.monotonic() >= deadline:
                    refuse("RCH_SOURCE_SETTLEMENT_LOCK_BUSY identity={} lock={} elapsed_ms={}".format(
                        token, path + "/" + name, int((time.monotonic() - started) * 1000)))
                time.sleep(0.02)
    verify()

    candidates = []
    for path, _, directory in registries:
        found = False
        for subdirectory in ("", "released", "cancelled", "quarantine"):
            scan = directory
            if subdirectory:
                try:
                    scan = os.open(subdirectory, flags, dir_fd=directory)
                except FileNotFoundError:
                    continue
                private(os.fstat(scan), directory=True)
            try:
                for name in os.listdir(scan):
                    if name == token + ".activity.lock" and not subdirectory:
                        continue
                    if name.startswith(token + "."):
                        found = True
                        suffixes = {"": "claim|pending|cancelling", "released": "claim",
                                    "cancelled": "claim", "quarantine": "pending"}[subdirectory]
                        if not re.fullmatch(re.escape(token) + r"\.[a-f0-9]{64}\.(" + suffixes + ")", name):
                            refuse("unrecognized same-identity registry evidence")
            finally:
                if subdirectory:
                    os.close(scan)
        if found:
            candidates.append(path)
    if len(candidates) != 1:
        refuse("{} registries contain identity={}; expected exactly one".format(len(candidates), token))
    selected = "current" if candidates[0] == current else "legacy"
    if operation == "settle-cancel" and selected != expected:
        refuse("source authority namespace changed from recorded binding")
    verify()
    # The caller runs this program inside source_namespace_control's owned
    # process group. Its independent 15-second deadline kills ALL descendants
    # (including helpers inheriting these descriptors) before acknowledging
    # success or failure. A direct-child subprocess timeout would strand them.
    process = subprocess.Popen(
        ["sh", "-c", transaction, "rch-source-settlement", candidates[0], token, digest, operation],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        pass_fds=tuple(item[2] for item in locks),
    )
    process.stdin.write(roots)
    process.stdin.close()
    # One byte beyond the only valid response bounds memory and detects extra
    # output. Stderr is independently bounded by the outer metadata controller.
    reply = process.stdout.read(8)
    if reply != (b"located" if operation == "locate" else b"settled"):
        refuse("invalid worker settlement response identity=" + token)
    status = process.wait()
    verify()
    if status != 0:
        refuse("worker transaction did not confirm exact cancellation identity=" + token)
    if operation == "locate":
        sys.stdout.write("RCH_SOURCE_AUTHORITY_NAMESPACE " + selected + "\n")
    else:
        sys.stdout.write("RCH_SOURCE_CANCELLATION_SETTLED\n")


try:
    main()
except (OSError, subprocess.SubprocessError) as error:
    refuse("worker settlement interrupted: " + str(error))
