"""Discover or locate exact source ownership, or settle a terminal cancellation.

The dispatcher calls this only under its durable recovery journal ownership,
before recording a missing namespace binding, or after validating completed
source/tree/pair retirement. Location grants no source access. Settlement
requires the previously recorded binding. This program never inspects source
trees; the shell transaction remains the sole registry state machine.
Optional discovery can report verified absence, which grants no authority and
does not run a registry transaction. Strict location still requires evidence.
"""
import errno
import fcntl
import hashlib
import math
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


def heal_group_writable_lock(descriptor):
    # A lock file created by a pre-umask-077 wrapper (2.1.34 ran under the
    # worker's umask 002) keeps group/other write bits. The enclosing registry
    # directory is already verified private (0700, our uid), so those bits grant
    # no access, but private() still refuses them and strands the worker on the
    # next settle-cancel. Clear ONLY the group/other write bits in place, on our
    # own just-opened fd: a regular file, our uid, a single link, and no
    # setuid/setgid. Anything else is left for private() to refuse. fchmod binds
    # to the verified inode, and O_NOFOLLOW above already excluded a symlink.
    info = os.fstat(descriptor)
    if (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and info.st_nlink == 1 and (info.st_mode & 0o022)
            and not (info.st_mode & (stat.S_ISUID | stat.S_ISGID))):
        os.fchmod(descriptor, info.st_mode & 0o7777 & ~0o022)


def main():
    if len(sys.argv) != 8:
        refuse("invalid settlement request")
    current, legacy, token, digest, transaction, operation, expected = sys.argv[1:]
    if ((operation in ("locate", "discover") and expected != "")
            or (operation == "settle-cancel" and expected not in ("current", "legacy"))
            or operation not in ("locate", "discover", "settle-cancel")):
        refuse("invalid source authority namespace request")
    if not re.fullmatch(r"[a-f0-9-]{1,128}", token) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        refuse("invalid settlement identity")
    # The daemon and metadata guardian transport the same bounded policy.
    # Honor that scale in this innermost admission window, too. Validate it
    # before opening/healing any registry lock; an invalid value must not
    # create an unbounded lock waiter.
    timing_text = os.environ.get("RCH_TIMING_SCALE", "1")
    if (len(timing_text) > 128 or re.fullmatch(
            r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?",
            timing_text) is None):
        refuse("invalid RCH_TIMING_SCALE (expected finite 1..10)")
    timing_scale = float(timing_text)
    if not math.isfinite(timing_scale) or not 1.0 <= timing_scale <= 10.0:
        refuse("invalid RCH_TIMING_SCALE (expected finite 1..10)")
    started = time.monotonic()
    deadline = started + 5.0 * timing_scale

    def require_admission_time(lock="registry discovery"):
        now = time.monotonic()
        if now >= deadline:
            refuse("RCH_SOURCE_SETTLEMENT_LOCK_BUSY identity={} lock={} elapsed_ms={}".format(
                token, lock, int((now - started) * 1000)))

    roots = sys.stdin.buffer.read(32 * 1024 * 1024 + 1)
    if not roots or len(roots) > 32 * 1024 * 1024 or hashlib.sha256(roots).hexdigest() != digest:
        refuse("settlement roots do not match identity digest")
    if current == legacy or not all(os.path.isabs(path) for path in (current, legacy)):
        refuse("invalid registry namespace")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    registries, absent, locks = [], [], []
    absent_activity, empty_peers, locked_activity = [], [], set()
    for path in (current, legacy):
        # Open the registry's immediate parent too: checking just its leaf
        # would follow a substituted rch-source-authority-locks symlink.
        parent_path, name = os.path.split(path)
        try:
            parent = os.open(parent_path, flags)
        except FileNotFoundError:
            absent.append((path, None))
            continue
        private(os.fstat(parent), directory=True)
        try:
            directory = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError:
            # Keep the parent's identity pinned even when the registry is
            # absent. Replacing it while discovery waits must not turn stale
            # path observations into an acknowledged absence.
            absent.append((path, parent))
            continue
        private(os.fstat(directory), directory=True)
        registries.append((path, parent, directory))
    if not registries and operation != "discover":
        refuse("no worker registry evidence for identity=" + token)
    if len({identity(os.fstat(row[2])) for row in registries}) != len(registries):
        refuse("registry namespaces alias the same directory")

    def identity_evidence(directory):
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
        return found

    def verify():
        for path, parent in absent:
            parent_path = os.path.dirname(path)
            if parent is None:
                if os.path.lexists(parent_path):
                    refuse("absent registry parent appeared during settlement")
            else:
                private(os.fstat(parent), directory=True)
                if identity(os.stat(parent_path, follow_symlinks=False)) != identity(os.fstat(parent)):
                    refuse("absent registry parent changed during settlement")
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
        for directory, name in absent_activity:
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            refuse("registry activity lock appeared during settlement")
        for directory in empty_peers:
            if identity_evidence(directory):
                refuse("source identity appeared in registry without an activity lock")

    # All activity locks precede all metadata locks. A cancelled identity has
    # no new normal activity; acquiring these drains any previously admitted
    # operation. Fixed ordering also serializes concurrent recovery clients.
    # An empty peer namespace needs only its metadata mutex: do not allocate a
    # new token lock there after a worker has filled its disk. Absence is checked
    # again under both metadata locks and after the transaction. Settlement in
    # the selected namespace still requires an EXISTING locked activity inode;
    # creating one cannot prove that a previous activity holder has drained.
    for name in (token + ".activity.lock", "metadata.lock"):
        for path, _, directory in registries:
            lock_path = path + "/" + name
            require_admission_time(lock_path)
            lock_flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            if name == "metadata.lock":
                lock_flags |= os.O_CREAT
            try:
                descriptor = os.open(name, lock_flags, 0o600, dir_fd=directory)
            except FileNotFoundError:
                if name == "metadata.lock":
                    raise
                absent_activity.append((directory, name))
                continue
            heal_group_writable_lock(descriptor)
            private(os.fstat(descriptor))
            if any(identity(os.fstat(item[2])) == identity(os.fstat(descriptor)) for item in locks):
                refuse("registry locks alias the same inode")
            locks.append((directory, name, descriptor))
            while True:
                verify()
                # Expiry wins over a lock released while this waiter was
                # descheduled. All locks consume the original shared window.
                require_admission_time(lock_path)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    require_admission_time(lock_path)
                    if name != "metadata.lock":
                        locked_activity.add(path)
                    break
                except OSError as error:
                    if error.errno not in (errno.EAGAIN, errno.EACCES):
                        raise
                require_admission_time(lock_path)
                time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
    verify()
    require_admission_time()

    candidates = []
    for path, _, directory in registries:
        if identity_evidence(directory):
            candidates.append(path)
        elif path not in locked_activity:
            empty_peers.append(directory)
    if not candidates and operation == "discover":
        # This is an observation only: no source/cleanup access, cancellation
        # receipt, or retirement can be inferred from absent worker evidence.
        verify()
        require_admission_time()
        sys.stdout.write("RCH_SOURCE_AUTHORITY_DISCOVERY absent\n")
        return
    if len(candidates) != 1:
        refuse("{} registries contain identity={}; expected exactly one".format(len(candidates), token))
    selected = "current" if candidates[0] == current else "legacy"
    if operation == "settle-cancel" and selected != expected:
        refuse("source authority namespace changed from recorded binding")
    if operation == "settle-cancel" and candidates[0] not in locked_activity:
        refuse("source cancellation activity lock is absent")
    verify()
    # The caller runs this program inside source_namespace_control's owned
    # process group. Its independent scaled 15-second deadline kills ALL descendants
    # (including helpers inheriting these descriptors) before acknowledging
    # success or failure. A direct-child subprocess timeout would strand them.
    transaction_operation = "locate" if operation == "discover" else operation
    require_admission_time()
    process = subprocess.Popen(
        ["sh", "-c", transaction, "rch-source-settlement", candidates[0], token, digest, transaction_operation],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        pass_fds=tuple(item[2] for item in locks),
    )
    process.stdin.write(roots)
    process.stdin.close()
    # One byte beyond the only valid response bounds memory and detects extra
    # output. Stderr is independently bounded by the outer metadata controller.
    reply = process.stdout.read(8)
    if reply != (b"located" if transaction_operation == "locate" else b"settled"):
        refuse("invalid worker settlement response identity=" + token)
    status = process.wait()
    verify()
    if status != 0:
        refuse("worker transaction did not confirm exact cancellation identity=" + token)
    if operation == "discover":
        sys.stdout.write("RCH_SOURCE_AUTHORITY_DISCOVERY " + selected + "\n")
    elif operation == "locate":
        sys.stdout.write("RCH_SOURCE_AUTHORITY_NAMESPACE " + selected + "\n")
    else:
        sys.stdout.write("RCH_SOURCE_CANCELLATION_SETTLED\n")


try:
    main()
except (OSError, subprocess.SubprocessError) as error:
    refuse("worker settlement interrupted: " + str(error))
