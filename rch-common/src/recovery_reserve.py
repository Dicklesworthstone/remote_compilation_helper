"""Worker-local GC emergency bytes; invoked in memory by recovery_reserve.rs.

This is a byte reserve, not an inode reserve or a quota guarantee. It protects
only the current source registry and the GC scratch directory on that same
filesystem. Cancellation and legacy registries retain their existing protocol.
"""

import errno
import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import uuid
import zlib


CAPACITY = 64 * 1024 * 1024
HEADROOM = 64 * 1024 * 1024
HEADER = 4096
SLOT = HEADER // 2
PRIVATE = ".recovery-v1"
FILE = "reserve.v1"
CLAIM_NAME = re.compile(r"fc-[a-f0-9-]{36}\.([a-f0-9]{64})\.claim\Z")
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class Unsafe(Exception):
    pass


class Pressure(Exception):
    def __init__(self, reason):
        self.reason = reason


def identity(value):
    return [value.st_dev, value.st_ino]


def unpack(argument):
    return zlib.decompress(base64.b64decode(argument, validate=True)).decode()


class Reserve:
    def __init__(self, registry, create=False, capacity=CAPACITY, headroom=HEADROOM):
        if not os.path.isabs(registry) or os.path.normpath(registry) != registry:
            raise Unsafe("noncanonical registry")
        if "\n" in registry or "\r" in registry:
            raise Unsafe("multiline registry")
        self.registry = registry
        self.capacity = capacity
        self.headroom = headroom
        self.uid = os.geteuid()
        self.bindings = []
        self.owned = []
        self.borrowed = False
        self.fd = None
        authority, registry_name = os.path.split(registry)
        ancestor, authority_name = os.path.split(authority)
        if not ancestor or not authority_name or not registry_name:
            raise Unsafe("shallow registry")
        # /tmp and /var can be platform aliases. Only ancestors above the
        # worker-owned authority are resolved; managed leaves never follow links.
        self.original_ancestor = ancestor
        self.ancestor = os.path.realpath(ancestor)
        self.ancestor_fd = os.open(self.ancestor, DIRECTORY)
        self.owned.append(self.ancestor_fd)
        self.ancestor_identity = identity(os.fstat(self.ancestor_fd))
        self.authority_fd = self.directory(self.ancestor_fd, authority_name, create)
        self.registry_fd = self.directory(self.authority_fd, registry_name, create)
        self.private_fd = self.directory(self.registry_fd, PRIVATE, create, private=True)
        self.scratch_fd = self.directory(self.private_fd, "scratch", create, private=True)
        self.creation_locked = False
        if create:
            # Serialize first publication before the reserve file exists. A
            # concurrent first health/admission must not take SH on an empty
            # file and prevent its creator from initializing under EX.
            try:
                fcntl.flock(self.private_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Unsafe("reserve initialization busy") from None
            self.creation_locked = True
        self.scratch = os.path.join(self.ancestor, authority_name, registry_name, PRIVATE, "scratch")
        self.device = os.fstat(self.registry_fd).st_dev
        if any(os.fstat(fd).st_dev != self.device for fd in (self.private_fd, self.scratch_fd)):
            raise Unsafe("reserve filesystem changed")
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        self.created = False
        if create:
            try:
                self.fd = os.open(FILE, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self.private_fd)
                self.created = True
            except FileExistsError:
                pass
        if self.fd is None:
            self.fd = os.open(FILE, flags, dir_fd=self.private_fd)
        self.owned.append(self.fd)
        self.file_identity = identity(os.fstat(self.fd))
        self.immutable = {
            "version": 1, "file": self.file_identity, "uid": self.uid,
            "registry": identity(os.fstat(self.registry_fd)),
            "private": identity(os.fstat(self.private_fd)),
            "scratch": identity(os.fstat(self.scratch_fd)), "capacity": capacity,
        }
        self.validate()

    def directory(self, parent, name, create, private=False):
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        fd = os.open(name, DIRECTORY, dir_fd=parent)
        self.owned.append(fd)
        info = os.fstat(fd)
        if info.st_uid != self.uid or info.st_mode & 0o022:
            raise Unsafe("directory ownership or permissions")
        if private and stat.S_IMODE(info.st_mode) != 0o700:
            raise Unsafe("private directory permissions")
        self.bindings.append((parent, name, fd, identity(info)))
        return fd

    def validate(self):
        if os.path.realpath(self.original_ancestor) != self.ancestor:
            raise Unsafe("ancestor alias changed")
        if identity(os.stat(self.ancestor, follow_symlinks=False)) != self.ancestor_identity:
            raise Unsafe("ancestor replaced")
        for parent, name, fd, expected in self.bindings:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(fd)
            if not stat.S_ISDIR(named.st_mode) or identity(named) != expected or identity(held) != expected:
                raise Unsafe("directory replaced")
            if named.st_uid != self.uid or named.st_mode & 0o022:
                raise Unsafe("directory permissions changed")
            if name in (PRIVATE, "scratch") and stat.S_IMODE(named.st_mode) != 0o700:
                raise Unsafe("private directory permissions changed")
        named = os.stat(FILE, dir_fd=self.private_fd, follow_symlinks=False)
        held = os.fstat(self.fd)
        if (not stat.S_ISREG(named.st_mode) or identity(named) != self.file_identity
                or identity(held) != self.file_identity or held.st_dev != self.device
                or held.st_uid != self.uid or held.st_nlink != 1
                or stat.S_IMODE(held.st_mode) != 0o600):
            raise Unsafe("reserve identity or permissions changed")

    def lock(self, exclusive):
        # No conversion while holding SH: two refillers must never deadlock.
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        try:
            fcntl.flock(self.fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Unsafe("recovery lease busy") from None
        self.validate()

    def load(self):
        self.validate()
        if not HEADER <= os.fstat(self.fd).st_size <= self.capacity:
            raise Unsafe("invalid reserve length")
        valid = []
        for slot in range(2):
            data = os.pread(self.fd, SLOT, slot * SLOT).rstrip(b"\0")
            try:
                envelope = json.loads(data)
                body = envelope["body"]
                raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
                if hashlib.sha256(raw).hexdigest() != envelope["sha256"]:
                    raise Unsafe("reserve header checksum failed")
                if (body["immutable"] != self.immutable or type(body["sequence"]) is not int
                        or body["sequence"] <= 0):
                    raise Unsafe("reserve header identity mismatch")
                epoch, claim = body["epoch"], body["claim"]
                if type(body["provisioned"]) is not bool:
                    raise Unsafe("invalid reserve provisioning state")
                if not body["provisioned"] and (epoch is not None or claim is not None):
                    raise Unsafe("unprovisioned reserve has recovery ownership")
                if epoch is not None and (not isinstance(epoch, str) or re.fullmatch(r"[a-f0-9]{32}", epoch) is None):
                    raise Unsafe("invalid reserve generation")
                if claim is not None and (epoch is None or not isinstance(claim, dict)):
                    raise Unsafe("invalid reserve claim")
                if claim is not None:
                    match = CLAIM_NAME.fullmatch(claim["name"])
                    if (match is None or claim["sha256"] != match.group(1)
                            or not isinstance(claim["file"], list) or len(claim["file"]) != 2
                            or any(type(value) is not int or value < 0 for value in claim["file"])):
                        raise Unsafe("invalid reserve claim binding")
                valid.append((body["sequence"], slot, body))
            except (ValueError, KeyError, TypeError):
                raise Unsafe("reserve header incomplete") from None
        # A torn/zeroed newer slot must not expose an older unbound generation.
        # Both slots must remain valid; ambiguity refuses recovery/admission.
        if len(valid) != 2:
            raise Unsafe("reserve header incomplete")
        valid.sort(key=lambda item: item[0])
        if len(valid) == 2 and valid[0][0] == valid[1][0] and valid[0][2] != valid[1][2]:
            raise Unsafe("conflicting reserve headers")
        self.sequence, self.slot, self.state = valid[-1]
        return self.state

    def write(self, epoch, claim, provisioned=None):
        self.validate()
        if provisioned is None:
            provisioned = self.state["provisioned"]
        body = {"immutable": self.immutable, "sequence": self.sequence + 1,
                "epoch": epoch, "claim": claim, "provisioned": provisioned}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        data = json.dumps({"body": body, "sha256": hashlib.sha256(raw).hexdigest()},
                          sort_keys=True, separators=(",", ":")).encode()
        if len(data) > SLOT:
            raise Unsafe("reserve header too large")
        slot = 1 - self.slot
        data = data.ljust(SLOT, b"\0")
        offset = slot * SLOT
        view = memoryview(data)
        while view:
            count = os.pwrite(self.fd, view, offset)
            if count <= 0:
                raise Unsafe("short reserve header write")
            offset += count
            view = view[count:]
        os.fsync(self.fd)
        if os.pread(self.fd, SLOT, slot * SLOT) != data:
            raise Unsafe("reserve header readback failed")
        self.sequence, self.slot, self.state = body["sequence"], slot, body

    def initialize(self):
        if not self.created:
            self.load()
        else:
            self.sequence, self.slot = 0, 1
            os.ftruncate(self.fd, HEADER)
            self.write(None, None, provisioned=False)
            self.write(None, None)
            os.fsync(self.private_fd)
        if self.creation_locked:
            fcntl.flock(self.private_fd, fcntl.LOCK_UN)
            self.creation_locked = False

    def free_bytes(self):
        info = os.fstatvfs(self.fd)
        return info.f_bavail * info.f_frsize

    def full(self):
        info = os.fstat(self.fd)
        return info.st_size == self.capacity and info.st_blocks * 512 >= self.capacity

    def claim(self, name, released=False):
        match = CLAIM_NAME.fullmatch(name)
        if match is None:
            raise Unsafe("invalid GC claim name")
        directory = self.registry_fd
        extra = None
        if released:
            extra = os.open("released", DIRECTORY, dir_fd=directory)
            directory = extra
            info = os.fstat(directory)
            if info.st_uid != self.uid or info.st_mode & 0o022 or info.st_dev != self.device:
                raise Unsafe("unsafe released directory")
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_nlink != 1
                    or info.st_dev != self.device or info.st_mode & 0o077
                    or not 0 < info.st_size <= 33554432):
                raise Unsafe("unsafe GC claim")
            digest = hashlib.sha256()
            length = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                digest.update(chunk)
                length += len(chunk)
                if length > 33554432:
                    raise Unsafe("GC claim grew")
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (length != info.st_size or digest.hexdigest() != match.group(1)
                    or identity(named) != identity(info) or after.st_size != info.st_size
                    or after.st_mtime_ns != info.st_mtime_ns or after.st_ctime_ns != info.st_ctime_ns):
                raise Unsafe("GC claim changed")
            if released:
                named_directory = os.stat("released", dir_fd=self.registry_fd, follow_symlinks=False)
                held_directory = os.fstat(directory)
                if (not stat.S_ISDIR(named_directory.st_mode)
                        or identity(named_directory) != identity(held_directory)
                        or held_directory.st_uid != self.uid or held_directory.st_mode & 0o022):
                    raise Unsafe("released directory changed")
                os.fsync(fd)
                os.fsync(directory)
                os.fsync(self.registry_fd)
            return {"name": name, "file": identity(info), "sha256": digest.hexdigest()}
        finally:
            if fd is not None:
                os.close(fd)
            if extra is not None:
                os.close(extra)

    def reconcile_receipt(self):
        claim = self.state["claim"]
        if claim is None:
            return True
        try:
            receipt = self.claim(claim["name"], released=True)
        except FileNotFoundError:
            # Only an intact exact active record is a recoverable pending GC.
            # A missing/substituted record cannot become an eligibility hint.
            try:
                active = self.claim(claim["name"])
            except FileNotFoundError:
                raise Unsafe("emergency GC ownership record missing") from None
            if active != claim:
                raise Unsafe("emergency GC ownership record changed")
            return False
        if receipt != claim:
            raise Unsafe("GC retirement receipt changed")
        # Both names existing is not a completed retirement, even with matching
        # contents. The inode-bound receipt is the existing GC protocol's proof.
        try:
            os.stat(claim["name"], dir_fd=self.registry_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Unsafe("active GC claim also has receipt")
        self.write(self.state["epoch"], None)
        return True

    def replenish(self):
        if not self.reconcile_receipt():
            raise Pressure("recovery-pending")
        need = max(0, self.capacity - os.fstat(self.fd).st_blocks * 512)
        if self.free_bytes() < need + self.headroom:
            raise Pressure("insufficient-headroom")
        if not self.full():
            self.validate()
            try:
                os.posix_fallocate(self.fd, 0, self.capacity)
            except (AttributeError, OSError) as error:
                if isinstance(error, OSError) and error.errno not in (errno.EOPNOTSUPP, errno.ENOSYS, errno.EINVAL):
                    raise
                # macOS has no posix_fallocate. Incompressible writes physically
                # allocate bytes; truncate/zero-filled sparse files cannot pass.
                offset = HEADER
                while offset < self.capacity:
                    data = os.urandom(min(262144, self.capacity - offset))
                    view = memoryview(data)
                    while view:
                        count = os.pwrite(self.fd, view, offset)
                        if count <= 0:
                            raise Unsafe("short reserve allocation write")
                        offset += count
                        view = view[count:]
                os.ftruncate(self.fd, self.capacity)
        # This barrier also covers a full file left by an interrupted first
        # allocation before its provisioning bit could be published.
        os.fsync(self.fd)
        self.validate()
        if not self.full():
            raise Unsafe("reserve allocation is sparse")
        if self.state["epoch"] is not None or not self.state["provisioned"]:
            # Publish only after actual allocation and its fsync. An existing
            # full-length file alone is not a durable provisioning receipt.
            self.write(None, None, provisioned=True)

    def spend(self):
        self.validate()
        if not self.state["provisioned"]:
            raise Pressure("insufficient-headroom")
        # This held file was checked before and after taking EX. Never truncate
        # a pathname, unlink a reserve, or replace an unrecognized old header.
        # Release BEFORE overwriting a header: CoW filesystems may need a free
        # block even for that overwrite. If killed here, the durable provisioning
        # bit permits a later EX holder to establish an epoch without refilling.
        os.ftruncate(self.fd, HEADER)
        os.fsync(self.fd)
        self.validate()
        if self.state["epoch"] is None:
            self.write(uuid.uuid4().hex, None)

    def inherit(self, mode):
        lease = fcntl.fcntl(self.fd, fcntl.F_DUPFD, 64)
        os.set_inheritable(lease, True)
        os.environ["RCH_RECOVERY_RESERVE_FD"] = str(lease)
        os.environ["RCH_RECOVERY_RESERVE_REGISTRY"] = self.registry
        os.environ["RCH_RECOVERY_RESERVE_MODE"] = mode
        os.environ["RCH_RECOVERY_RESERVE_EPOCH"] = self.state["epoch"] or ""
        os.environ["RCH_GC_SCRATCH"] = self.scratch

    def borrow(self):
        lease = int(os.environ["RCH_RECOVERY_RESERVE_FD"])
        if identity(os.fstat(lease)) != self.file_identity:
            raise Unsafe("inherited reserve descriptor changed")
        # Use the inherited open-file-description, without changing its flock.
        # Closing this callback's descriptors must not unlock the owning shell.
        os.close(self.fd)
        self.owned.remove(self.fd)
        self.fd = lease
        self.borrowed = True
        self.load()
        if os.environ.get("RCH_RECOVERY_RESERVE_REGISTRY") != self.registry:
            raise Unsafe("inherited registry changed")
        if os.environ.get("RCH_RECOVERY_RESERVE_MODE") == "shared":
            if self.state["epoch"] is not None or not self.state["provisioned"] or not self.full():
                raise Unsafe("shared reserve no longer ready")
            return False
        if (os.environ.get("RCH_RECOVERY_RESERVE_MODE") != "exclusive"
                or not self.state["epoch"]
                or os.environ.get("RCH_RECOVERY_RESERVE_EPOCH") != self.state["epoch"]):
            raise Unsafe("inherited reserve generation changed")
        return True

    def close(self):
        for fd in reversed(self.owned):
            os.close(fd)
        self.owned = []


def callback(reserve, operation, name):
    if not reserve.borrow():
        return
    # The GC shell holds metadata fd8 before publication and through checked
    # retirement. Do not reacquire it via another OFD (that would deadlock).
    held = os.fstat(8)
    named = os.stat("metadata.lock", dir_fd=reserve.registry_fd, follow_symlinks=False)
    if (identity(held) != identity(named) or not stat.S_ISREG(named.st_mode)
            or named.st_uid != reserve.uid or named.st_nlink != 1):
        raise Unsafe("GC metadata descriptor changed")
    if operation == "bind":
        claim = reserve.claim(name)
        if reserve.state["claim"] not in (None, claim):
            raise Unsafe("previous emergency GC claim still bound")
        reserve.write(reserve.state["epoch"], claim)
    elif operation == "settle":
        if reserve.state["claim"] is None or reserve.state["claim"]["name"] != name:
            raise Unsafe("GC retirement does not match reserve")
        if not reserve.reconcile_receipt():
            raise Unsafe("GC retirement receipt missing")
    else:
        raise Unsafe("unknown reserve callback")


def main(arguments):
    if len(arguments) < 2:
        raise Unsafe("missing reserve operation")
    operation, registry = arguments[:2]
    reserve = Reserve(registry, create=operation in ("ready", "admit", "gc"))
    try:
        if operation in ("bind", "settle"):
            callback(reserve, operation, arguments[2])
            return
        reserve.lock(reserve.created)
        reserve.initialize()
        ready = (reserve.full() and reserve.state["provisioned"] and reserve.state["epoch"] is None
                 and reserve.free_bytes() >= reserve.headroom)
        if operation in ("ready", "admit"):
            if not ready:
                reserve.lock(True)
                reserve.load()
                reserve.replenish()
            if operation == "ready":
                return
            # Never rely on a lock conversion. Release EX then take SH and
            # revalidate the state that will protect this short admission.
            reserve.lock(False)
            reserve.load()
            if not reserve.full() or not reserve.state["provisioned"] or reserve.state["epoch"] is not None:
                raise Unsafe("reserve changed before admission")
            reserve.inherit("shared")
            os.execvp("sh", ["sh", "-c", unpack(arguments[2])])
        if operation != "gc":
            raise Unsafe("unknown reserve operation")
        if ready:
            reserve.inherit("shared")
        else:
            reserve.lock(True)
            reserve.load()
            reserve.reconcile_receipt()
            if not reserve.state["provisioned"]:
                # First-use GC may provision on a healthy filesystem. It cannot
                # manufacture emergency bytes after the disk has already filled.
                reserve.replenish()
            if reserve.full() and reserve.state["epoch"] is None and reserve.free_bytes() >= reserve.headroom:
                reserve.lock(False)
                reserve.load()
                if not reserve.full() or not reserve.state["provisioned"] or reserve.state["epoch"] is not None:
                    raise Unsafe("reserve changed before GC")
                reserve.inherit("shared")
            else:
                reserve.spend()
                reserve.inherit("exclusive")
                # Exact bound-claim recovery uses the existing six-hour, intact
                # record, complete handle+argv protocol. Its script is supplied
                # by the GC builder, never by the header or a filename.
                if not reserve.reconcile_receipt():
                    os.environ["RCH_RECOVERY_GC_CLAIM"] = reserve.state["claim"]["name"]
                    import subprocess
                    reconcile = unpack(arguments[3])
                    result = subprocess.run(["sh", "-c", reconcile], close_fds=False, check=False)
                    reserve.validate()
                    reserve.load()
                    if result.returncode or not reserve.reconcile_receipt():
                        raise Unsafe("emergency GC claim still protected")
                    os.environ.pop("RCH_RECOVERY_GC_CLAIM", None)
        reserve.validate()
        os.execvp("sh", ["sh", "-c", unpack(arguments[2])])
    finally:
        reserve.close()


if __name__ == "__main__":
    registry = sys.argv[2] if len(sys.argv) > 2 else "unknown"
    try:
        main(sys.argv[1:])
    except Pressure as error:
        print("RCH_SOURCE_REGISTRY_PRESSURE " + registry + ": " + error.reason, file=sys.stderr)
        sys.exit(75)
    except OSError as error:
        if error.errno in (errno.ENOSPC, errno.EDQUOT):
            reason = "no-space" if error.errno == errno.ENOSPC else "quota-exhausted"
            print("RCH_SOURCE_REGISTRY_PRESSURE " + registry + ": " + reason, file=sys.stderr)
            sys.exit(75)
        print("RCH_RECOVERY_RESERVE_UNSAFE " + registry + ": " + str(error), file=sys.stderr)
        sys.exit(74)
    except (Unsafe, ValueError, KeyError, IndexError, zlib.error) as error:
        print("RCH_RECOVERY_RESERVE_UNSAFE " + registry + ": " + str(error), file=sys.stderr)
        sys.exit(74)
