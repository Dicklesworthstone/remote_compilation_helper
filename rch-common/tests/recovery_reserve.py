#!/usr/bin/env python3
"""Native tests of the production recovery reserve, never a duplicate model.

Real ENOSPC cases mount a small tmpfs inside a new user/mount namespace. No
shared filesystem is filled. All paths mutated by a fixture are newly owned
below its retained temporary directory; no host mount or existing data changes.
"""

import base64
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid
import zlib


HELPER = Path(__file__).resolve().parents[1] / "src/recovery_reserve.py"
SPEC = importlib.util.spec_from_file_location("production_recovery_reserve", HELPER)
PRODUCTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRODUCTION)
GC_SOURCE = (HELPER.parent / "stale_target_reap.rs").read_text()
RESERVE_SOURCE = (HELPER.parent / "recovery_reserve.rs").read_text()
CAPACITY = 2 * 1024 * 1024
HEADROOM = 1024 * 1024
RESERVE_ENV = (
    "RCH_RECOVERY_RESERVE_FD", "RCH_RECOVERY_RESERVE_REGISTRY",
    "RCH_RECOVERY_RESERVE_MODE", "RCH_RECOVERY_RESERVE_EPOCH", "RCH_GC_SCRATCH",
)


def raw_constant(source, name):
    marker = "const " + name + ': &str = r#"'
    if source.count(marker) != 1:
        raise AssertionError("missing or ambiguous production constant " + name)
    return source.split(marker, 1)[1].split('"#;', 1)[0]


GC_SHELL_HELPERS = raw_constant(RESERVE_SOURCE, "GC_SHELL_HELPERS")
GC_GUARD = (
    "__gc_source_registry=__RCH_TEST_REGISTRY__; " + GC_SHELL_HELPERS + "\n"
    + raw_constant(GC_SOURCE, "SOURCE_CLAIM_RECORD_HELPERS") + "\n"
    + raw_constant(GC_SOURCE, "RETAINED_SOURCE_GC_GUARD") + "\n"
    + raw_constant(GC_SOURCE, "GATE")
)
COMPILED_GUARD = os.environ.get("RCH_TEST_GC_RESERVE_GUARD")
if COMPILED_GUARD is not None and COMPILED_GUARD != GC_GUARD:
    raise AssertionError("standalone source guard differs from compiled Rust builder")
BOOTSTRAP, BOOTSTRAP_END = json.JSONDecoder().raw_decode(
    RESERVE_SOURCE.split("const BOOTSTRAP: &str =", 1)[1].lstrip()
)


def gc_guard(registry):
    if GC_GUARD.count("__RCH_TEST_REGISTRY__") != 1:
        raise AssertionError("ambiguous registry placeholder")
    return GC_GUARD.replace("__RCH_TEST_REGISTRY__", shlex.quote(str(registry)), 1)


def abandoned_claims(registry):
    body = GC_SOURCE.split("pub fn abandoned_gc_claims_command_with_registry(", 1)[1]
    template = body.split('r#"', 1)[1].split('"#', 1)[0]
    return template.format(
        scratch=GC_SHELL_HELPERS, capture=raw_constant(GC_SOURCE, "GC_SNAPSHOT_CAPTURE"),
        registry=shlex.quote(str(registry)), min_age_minutes=6 * 60, apply=1,
    )


def fixture_root(prefix):
    root = Path(tempfile.mkdtemp(prefix=prefix))
    root.chmod(0o700)
    return root


def registry_at(root):
    authority = root / "authority"
    authority.mkdir(mode=0o700)
    registry = authority / "claims"
    registry.mkdir(mode=0o700)
    (registry / "released").mkdir(mode=0o700)
    (registry / "metadata.lock").touch(mode=0o600)
    return registry


def reserve_at(registry, provision=True):
    reserve = PRODUCTION.Reserve(str(registry), create=True, capacity=CAPACITY, headroom=HEADROOM)
    reserve.lock(True)
    reserve.initialize()
    if provision:
        reserve.replenish()
    return reserve


def create_claim(registry, candidate, name=None):
    content = (str(candidate) + "\n").encode()
    if name is None:
        name = "fc-" + str(uuid.uuid4()) + "." + hashlib.sha256(content).hexdigest() + ".claim"
    path = registry / name
    with path.open("xb") as output:
        path.chmod(0o600)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return path


def retire_claim(path):
    destination = path.parent / "released" / path.name
    assert not destination.exists(), "fixture must never overwrite an existing receipt"
    path.rename(destination)
    for directory in (path.parent, destination.parent):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return destination


def call_cli(operation, registry, payload=None, reconciler=None, environment=None):
    command = [sys.executable, "-I", "-S", str(HELPER), operation, str(registry)]
    for argument in (payload, reconciler):
        if argument is not None:
            command.append(base64.b64encode(zlib.compress(argument.encode())).decode())
    return subprocess.run(command, env=environment, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=15, check=False)


CALLBACK = r"""
import importlib.util, sys
spec = importlib.util.spec_from_file_location('production_reserve', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
reserve = module.Reserve(sys.argv[2], capacity=2 * 1024 * 1024, headroom=1024 * 1024)
try:
    module.callback(reserve, sys.argv[3], sys.argv[4])
finally:
    reserve.close()
"""


def callback(reserve, operation, name, metadata=None):
    previous = {name: os.environ.get(name) for name in RESERVE_ENV}
    lease = None
    try:
        reserve.inherit("exclusive")
        lease = int(os.environ["RCH_RECOVERY_RESERVE_FD"])
        environment = os.environ.copy()
        metadata = metadata or Path(reserve.registry) / "metadata.lock"
        # The actual callback requires the GC shell's held metadata fd8. The
        # shell keeps this flock while exec transfers it to the real callback.
        result = subprocess.run(
            ["/bin/sh", "-c", 'set -eu; exec 8<> "$1"; flock -x 8; shift; exec "$@"',
             "reserve-callback", str(metadata), sys.executable, "-I", "-S", "-c", CALLBACK,
             str(HELPER), reserve.registry, operation, name],
            pass_fds=(lease,), env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False,
        )
        return result
    finally:
        if lease is not None:
            os.close(lease)
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def require_real_enospc(root, name="enospc-probe"):
    probe = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            os.write(probe, b"x")
        except OSError as error:
            assert error.errno == errno.ENOSPC, error
        else:
            raise AssertionError("fixture did not reach real kernel ENOSPC")
    finally:
        os.close(probe)


def mount_private_tmpfs(root, size):
    subprocess.run(
        ["mount", "-t", "tmpfs", "-o", f"size={size},nr_inodes=1024,mode=0700,nodev,nosuid",
         "tmpfs", str(root)], check=True,
    )


def enospc_child(root):
    mount_private_tmpfs(root, "8m")
    registry = registry_at(root)
    reserve = reserve_at(registry)
    try:
        allocated = os.fstat(reserve.fd).st_blocks * 512
        assert allocated >= CAPACITY
        assert reserve.full() and reserve.state["epoch"] is None
        with (root / "filler").open("xb", buffering=0) as filler:
            os.posix_fallocate(filler.fileno(), 0, reserve.free_bytes())
            require_real_enospc(root)
            before = reserve.free_bytes()
            reserve.spend()
            released = reserve.free_bytes() - before
            assert released >= CAPACITY - PRODUCTION.HEADER, released
            assert os.fstat(reserve.fd).st_size == PRODUCTION.HEADER
            assert reserve.state["epoch"] is not None
            # The freed allocation pays for real durable control data while
            # the former zero-space filler remains fully allocated.
            with (Path(reserve.scratch) / "control-record").open("xb") as output:
                output.write(b"R" * 65536)
                output.flush()
                os.fsync(output.fileno())
            claim = create_claim(registry, root / "owned-candidate")
            bound = callback(reserve, "bind", claim.name)
            assert bound.returncode == 0, bound.stderr
            reserve.load()
            assert reserve.state["claim"]["name"] == claim.name
            receipt = retire_claim(claim)
            settled = callback(reserve, "settle", receipt.name)
            assert settled.returncode == 0, settled.stderr
            reserve.load()
            assert reserve.state["claim"] is None
            try:
                reserve.replenish()
            except PRODUCTION.Pressure as error:
                assert error.reason == "insufficient-headroom", error.reason
            else:
                raise AssertionError("refill consumed emergency bytes without required headroom")
            assert os.fstat(reserve.fd).st_size == PRODUCTION.HEADER
            # Reclaim only this fixture's filler. A new reserve may become
            # ready only after genuinely additional free bytes exist.
            filler.truncate(0)
            os.fsync(filler.fileno())
            reserve.replenish()
            assert reserve.full() and reserve.state["epoch"] is None
            assert reserve.free_bytes() >= HEADROOM
            print(json.dumps({"real_enospc": True, "allocated": allocated,
                              "released": released, "refill_headroom": reserve.free_bytes(),
                              "receipt_inode": receipt.stat().st_ino}))
    finally:
        reserve.close()


def cli_enospc_child(root):
    mount_private_tmpfs(root, "192m")
    registry = registry_at(root)
    result = call_cli("ready", registry)
    assert result.returncode == 0, result.stderr
    path = registry / PRODUCTION.PRIVATE / PRODUCTION.FILE
    initial = path.stat()
    assert initial.st_size == PRODUCTION.CAPACITY
    assert initial.st_blocks * 512 >= PRODUCTION.CAPACITY
    candidate = root / ".rch-target-reserve-fixture"
    candidate.mkdir(mode=0o700)
    (candidate / "artifact").write_bytes(b"owned GC candidate")
    info = os.statvfs(root)
    with (root / "filler").open("xb", buffering=0) as filler:
        os.posix_fallocate(filler.fileno(), 0, info.f_bavail * info.f_frsize)
        require_real_enospc(root)
        blocked = call_cli("admit", registry, "printf MUST-NOT-ADMIT")
        assert blocked.returncode == 75, (blocked.returncode, blocked.stdout, blocked.stderr)
        assert blocked.stdout == b""
        assert blocked.stderr.startswith(b"RCH_SOURCE_REGISTRY_PRESSURE ")
        bound_check = " ".join(shlex.quote(argument) for argument in (
            sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--assert-bound", str(registry),
        ))
        delete_child = " ".join(shlex.quote(argument) for argument in (
            sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--delete-owned", str(root),
        ))
        payload = gc_guard(registry) + "\n" + """set -eu
test -n "$RCH_RECOVERY_RESERVE_FD"
test "$RCH_RECOVERY_RESERVE_MODE" = exclusive
test -n "$RCH_RECOVERY_RESERVE_EPOCH"
printf 'durable recovery control\n' > "$RCH_GC_SCRATCH/control"
test -s "$RCH_GC_SCRATCH/control"
"""
        payload += "\n__gc_source_begin " + shlex.quote(str(candidate)) + "\n"
        payload += bound_check + ' "${__gc_reservation##*/}"\n'
        payload += delete_child + "\n__gc_source_end\nprintf 'recovery-ran\\n'\n"
        environment = os.environ.copy()
        environment["RCH_RECOVERY_RESERVE_PROGRAM"] = base64.b64encode(zlib.compress(HELPER.read_bytes())).decode()
        environment["RCH_RECOVERY_RESERVE_BOOTSTRAP"] = BOOTSTRAP
        recovered = call_cli("gc", registry, payload, "exit 99", environment)
        assert recovered.returncode == 0, (recovered.returncode, recovered.stdout, recovered.stderr)
        assert recovered.stdout == b"recovery-ran\n"
        assert path.stat().st_size == PRODUCTION.HEADER
        assert not candidate.exists()
        assert not list(registry.glob("fc-*.claim"))
        receipts = list((registry / "released").glob("fc-*.claim"))
        assert len(receipts) == 1, receipts
        check = PRODUCTION.Reserve(str(registry))
        try:
            assert check.load()["claim"] is None
        finally:
            check.close()
        still_blocked = call_cli("admit", registry, "printf MUST-NOT-ADMIT")
        assert still_blocked.returncode == 75, still_blocked.stderr
        assert still_blocked.stdout == b""
        filler.truncate(0)
        os.fsync(filler.fileno())
        admitted = call_cli("admit", registry, "printf admitted")
        assert admitted.returncode == 0, admitted.stderr
        assert admitted.stdout == b"admitted"
        assert path.stat().st_blocks * 512 >= PRODUCTION.CAPACITY
        # Kill-equivalent frontier: truncation was durable but the first epoch
        # header write never happened. There is only the released reserve's
        # space, so GC must resume from the prepared bit without first refilling.
        info = os.statvfs(root)
        os.posix_fallocate(filler.fileno(), 0, info.f_bavail * info.f_frsize)
        require_real_enospc(root, "second-enospc-probe")
        interrupted = PRODUCTION.Reserve(str(registry))
        try:
            interrupted.lock(True)
            interrupted.load()
            with mock.patch.object(PRODUCTION.os, "pwrite", side_effect=OSError(errno.ENOSPC, "epoch write interrupted")):
                try:
                    interrupted.spend()
                except OSError as error:
                    assert error.errno == errno.ENOSPC
                else:
                    raise AssertionError("epoch-write interruption was not exercised")
            state = interrupted.load()
            assert state["provisioned"] is True and state["epoch"] is None and state["claim"] is None
            assert path.stat().st_size == PRODUCTION.HEADER
            assert interrupted.free_bytes() < PRODUCTION.CAPACITY + PRODUCTION.HEADROOM
        finally:
            interrupted.close()
        resumed = call_cli("gc", registry, "printf recovered-truncation-frontier", "exit 99", environment)
        assert resumed.returncode == 0, (resumed.stdout, resumed.stderr)
        assert resumed.stdout == b"recovered-truncation-frontier"
        filler.truncate(0)
        os.fsync(filler.fileno())
        refilled = call_cli("ready", registry)
        assert refilled.returncode == 0, refilled.stderr
        print(json.dumps({"real_enospc": True, "default_capacity": initial.st_size,
                          "recovery_stdout": recovered.stdout.decode(), "refilled": True,
                          "truncation_before_epoch_recovered": True,
                          "production_gc_receipt": receipts[0].name}))


def assert_bound_child(registry, name):
    reserve = PRODUCTION.Reserve(str(registry))
    try:
        state = reserve.load()
        assert state["epoch"] is not None
        assert state["claim"] == reserve.claim(name), "deletion started before exact claim binding"
    finally:
        reserve.close()


def delete_owned_child(root):
    candidate = root / ".rch-target-reserve-fixture"
    artifact = candidate / "artifact"
    assert list(candidate.iterdir()) == [artifact]
    assert artifact.read_bytes() == b"owned GC candidate"
    # A real deletion child may close inherited descriptors. Its supervisor
    # must retain the lease and the completed claim must remain bound until
    # the actual production end transaction publishes and checks its receipt.
    os.closerange(3, 65536)
    artifact.unlink()
    candidate.rmdir()


def interrupted_gc_child(root):
    """Run real GC claim/recovery transactions while a deletion outlives GC."""
    import ctypes

    # Adopt only this isolated fixture's orphan, so the test also reaps it.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "fixture subreaper")
    mount_private_tmpfs(root, "192m")
    registry = registry_at(root)
    result = call_cli("ready", registry)
    assert result.returncode == 0, result.stderr
    candidate = root / ".rch-target-surviving-deletion"
    candidate.mkdir(mode=0o700)
    (candidate / "artifact").write_bytes(b"owned interrupted GC candidate")
    ready = root / "survivor.ready"
    environment = os.environ.copy()
    environment["RCH_RECOVERY_RESERVE_PROGRAM"] = base64.b64encode(zlib.compress(HELPER.read_bytes())).decode()
    environment["RCH_RECOVERY_RESERVE_BOOTSTRAP"] = BOOTSTRAP
    reconciler = abandoned_claims(registry)
    survivor_command = " ".join(shlex.quote(argument) for argument in (
        sys.executable, "-I", "-S", str(Path(__file__).resolve()),
        "--surviving-deletion", str(candidate), str(ready),
    ))
    payload = gc_guard(registry) + "\nset -eu\n__gc_source_begin " + shlex.quote(str(candidate))
    payload += "\n" + survivor_command + "\n__gc_source_end\nprintf should-not-complete\n"
    filler = (root / "filler").open("xb", buffering=0)
    owner, survivor_fd, survivor_pid = None, None, None
    try:
        info = os.statvfs(root)
        os.posix_fallocate(filler.fileno(), 0, info.f_bavail * info.f_frsize)
        require_real_enospc(root)
        owner = subprocess.Popen(
            [sys.executable, "-I", "-S", str(HELPER), "gc", str(registry),
             base64.b64encode(zlib.compress(payload.encode())).decode(),
             base64.b64encode(zlib.compress(reconciler.encode())).decode()],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
        )
        deadline = time.monotonic() + 8
        while not ready.exists() and time.monotonic() < deadline and owner.poll() is None:
            time.sleep(0.01)
        assert ready.exists(), (owner.poll(), owner.stderr.read() if owner.poll() is not None else b"no survivor")
        survivor_pid = int(ready.read_text())
        survivor_fd = os.pidfd_open(survivor_pid)
        owner.kill()
        owner.wait(timeout=5)
        # Deletion deliberately closed BOTH metadata and reserve descriptors.
        # The kernel lease can be free while durable ownership still forbids
        # refill. Ample physical space does not turn this into healthy admission.
        filler.truncate(0)
        os.fsync(filler.fileno())
        reserve = PRODUCTION.Reserve(str(registry))
        try:
            reserve.lock(True)
            state = reserve.load()
            claim = registry / state["claim"]["name"]
            assert state["claim"] == reserve.claim(claim.name)
            assert reserve.free_bytes() > PRODUCTION.CAPACITY + PRODUCTION.HEADROOM
        finally:
            reserve.close()
        pending = call_cli("ready", registry)
        assert pending.returncode == 75, pending.stderr
        assert pending.stderr == ("RCH_SOURCE_REGISTRY_PRESSURE " + str(registry) + ": recovery-pending\n").encode()
        assert pending.stdout == b""
        # The production age floor remains six hours. Even a quiet observation
        # cannot bypass it; this retry cannot reach its mutation payload.
        young = call_cli("gc", registry, "printf MUTATION-RAN", reconciler, environment)
        assert young.returncode != 0 and b"MUTATION-RAN" not in young.stdout
        assert b" young " in young.stdout or b"incomplete-" in young.stdout, young.stdout
        old = time.time() - (7 * 60 * 60)
        os.utime(claim, (old, old))
        live = call_cli("gc", registry, "printf MUTATION-RAN", reconciler, environment)
        assert live.returncode != 0 and b"MUTATION-RAN" not in live.stdout
        assert claim.exists() and candidate.exists()
        assert (registry / PRODUCTION.PRIVATE / PRODUCTION.FILE).stat().st_size == PRODUCTION.HEADER
        owner.stdin.write(b"release\n")
        owner.stdin.flush()
        poller = select.poll()
        poller.register(survivor_fd, select.POLLIN)
        assert poller.poll(5000), "owned deletion survivor did not finish"
        assert os.waitpid(survivor_pid, 0)[1] == 0
        survivor_pid = None
        assert not candidate.exists()
        # /proc inventories can legitimately lose a concurrently exiting
        # unrelated task. Retry only that fail-closed result, never a held gate.
        recovered = None
        for _ in range(3):
            recovered = call_cli("gc", registry, "printf recovery-complete", reconciler, environment)
            if recovered.returncode == 0:
                break
            assert b"incomplete-" in recovered.stdout, (recovered.stdout, recovered.stderr)
        assert recovered.returncode == 0, (recovered.stdout, recovered.stderr)
        assert recovered.stdout.endswith(b"recovery-complete")
        assert not claim.exists()
        receipt = registry / "released" / claim.name
        assert receipt.is_file()
        admitted = call_cli("admit", registry, "printf admitted-after-retirement")
        assert admitted.returncode == 0, admitted.stderr
        assert admitted.stdout == b"admitted-after-retirement"
        print(json.dumps({"real_enospc": True, "surviving_deletion_blocked_refill": True,
                          "minimum_age_preserved": True, "checked_automatic_retirement": receipt.name}))
    finally:
        if survivor_fd is not None:
            try:
                signal.pidfd_send_signal(survivor_fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(survivor_fd)
        if owner is not None:
            if owner.poll() is None:
                owner.kill()
            owner.communicate(timeout=5)
        if survivor_pid is not None:
            try:
                os.waitpid(survivor_pid, 0)
            except ChildProcessError:
                pass
        filler.close()


def surviving_deletion_child(candidate, ready):
    artifact = candidate / "artifact"
    assert artifact.read_bytes() == b"owned interrupted GC candidate"
    os.closerange(3, 65536)
    with artifact.open("rb") as handle:
        ready.write_text(str(os.getpid()))
        assert os.read(0, 1), "fixture release pipe closed before survivor finished"
        assert handle.read() == b"owned interrupted GC candidate"
    artifact.unlink()
    candidate.rmdir()


LEASE_OWNER = r"""
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location('production_reserve', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
reserve = module.Reserve(sys.argv[2], create=True, capacity=2 * 1024 * 1024, headroom=1024 * 1024)
reserve.lock(True)
reserve.initialize()
reserve.replenish()
if sys.argv[3] == 'exclusive':
    reserve.spend()
else:
    reserve.lock(False)
reserve.inherit(sys.argv[3])
child = os.fork()
if child == 0:
    with open(sys.argv[4], 'x') as ready:
        ready.write(str(os.getpid()))
    os.read(0, 1)
    os._exit(0)
while True:
    signal.pause()
"""


class RecoveryReserveTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_root("rch-recovery-reserve-")
        self.registry = registry_at(self.root)
        self.reserves = []

    def tearDown(self):
        for reserve in reversed(self.reserves):
            reserve.close()

    def reserve(self, provision=True):
        reserve = reserve_at(self.registry, provision)
        self.reserves.append(reserve)
        return reserve

    def reopen(self):
        reserve = PRODUCTION.Reserve(str(self.registry), capacity=CAPACITY, headroom=HEADROOM)
        self.reserves.append(reserve)
        return reserve

    def test_reserve_is_physically_allocated_and_spending_preserves_its_inode(self):
        reserve = self.reserve()
        before = os.fstat(reserve.fd)
        self.assertEqual(before.st_size, CAPACITY)
        self.assertGreaterEqual(before.st_blocks * 512, CAPACITY)
        self.assertEqual(before.st_nlink, 1)
        self.assertEqual(before.st_mode & 0o777, 0o600)
        reserve.spend()
        spent = os.fstat(reserve.fd)
        self.assertEqual((spent.st_dev, spent.st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(spent.st_size, PRODUCTION.HEADER)
        self.assertIsNotNone(reserve.load()["epoch"])
        reserve.replenish()
        self.assertTrue(reserve.full())
        self.assertIsNone(reserve.load()["epoch"])

    def test_unprovisioned_or_sparse_reserve_cannot_authorize_emergency_gc(self):
        reserve = self.reserve(provision=False)
        with self.assertRaises(PRODUCTION.Pressure) as initial:
            reserve.spend()
        self.assertEqual(initial.exception.reason, "insufficient-headroom")
        os.ftruncate(reserve.fd, CAPACITY)
        self.assertFalse(reserve.full())
        with self.assertRaises(PRODUCTION.Pressure) as sparse:
            reserve.spend()
        self.assertEqual(sparse.exception.reason, "insufficient-headroom")
        self.assertIsNone(reserve.load()["epoch"])
        reserve.replenish()
        self.assertTrue(reserve.full())

    def test_release_frees_payload_before_a_cow_header_overwrite_needs_space(self):
        reserve = self.reserve()
        self.assertIs(reserve.state["provisioned"], True)
        real_pwrite = os.pwrite
        observations = []

        def overwrite_requires_released_bytes(fd, data, offset):
            size = os.fstat(fd).st_size
            observations.append(size)
            # Deterministic write-allocation fault: a full-size reserve's
            # header cannot be overwritten until its payload is truncated.
            if size != PRODUCTION.HEADER:
                raise OSError(errno.ENOSPC, "CoW header allocation needs reserve bytes")
            return real_pwrite(fd, data, offset)

        with mock.patch.object(PRODUCTION.os, "pwrite", side_effect=overwrite_requires_released_bytes):
            reserve.spend()
        self.assertTrue(observations)
        self.assertEqual(observations, [PRODUCTION.HEADER] * len(observations))
        self.assertIsNotNone(reserve.load()["epoch"])

    def test_unprovisioned_full_file_requires_a_durable_allocation_barrier(self):
        reserve = self.reserve(provision=False)
        os.posix_fallocate(reserve.fd, 0, CAPACITY)
        self.assertTrue(reserve.full())
        self.assertIs(reserve.state["provisioned"], False)
        with self.assertRaises(PRODUCTION.Pressure):
            reserve.spend()
        calls = []
        real_fsync, real_pwrite = os.fsync, os.pwrite

        def record_fsync(fd):
            if fd == reserve.fd:
                calls.append("fsync")
            return real_fsync(fd)

        def record_pwrite(fd, data, offset):
            if fd == reserve.fd:
                calls.append("write")
            return real_pwrite(fd, data, offset)

        with mock.patch.object(PRODUCTION.os, "fsync", side_effect=record_fsync), \
                mock.patch.object(PRODUCTION.os, "pwrite", side_effect=record_pwrite):
            reserve.replenish()
        self.assertLess(calls.index("fsync"), calls.index("write"))
        self.assertIs(reserve.load()["provisioned"], True)

    def test_claim_requires_exact_private_file_bytes_and_identity(self):
        reserve = self.reserve()
        path = create_claim(self.registry, self.root / "candidate")
        expected = reserve.claim(path.name)
        self.assertEqual(expected["file"], [path.stat().st_dev, path.stat().st_ino])
        with self.assertRaises(PRODUCTION.Unsafe):
            reserve.claim("fc-not-a-valid-identity.claim")
        path.write_bytes(b"/changed/claim\n")
        with self.assertRaises(PRODUCTION.Unsafe):
            reserve.claim(path.name)
        other = create_claim(self.registry, self.root / "other-candidate")
        other.chmod(0o644)
        with self.assertRaises(PRODUCTION.Unsafe):
            reserve.claim(other.name)

    def test_claim_symlinks_and_multiple_links_cannot_be_bound(self):
        reserve = self.reserve()
        for linked in (False, True):
            with self.subTest(hardlink=linked):
                path = create_claim(self.registry, self.root / ("linked" if linked else "symlinked"))
                saved = self.root / ("saved-" + path.name)
                if linked:
                    os.link(path, saved)
                else:
                    path.rename(saved)
                    path.symlink_to(saved)
                with self.assertRaises((PRODUCTION.Unsafe, OSError)):
                    reserve.claim(path.name)
                self.assertEqual(saved.read_bytes(), (str(self.root / ("linked" if linked else "symlinked")) + "\n").encode())

    def test_bound_claim_blocks_refill_until_its_same_inode_receipt_is_durable(self):
        reserve = self.reserve()
        reserve.spend()
        path = create_claim(self.registry, self.root / "candidate")
        bound = callback(reserve, "bind", path.name)
        self.assertEqual(bound.returncode, 0, bound.stderr)
        reserve.load()
        expected = reserve.state["claim"].copy()
        self.assertFalse(reserve.reconcile_receipt())
        with self.assertRaises(PRODUCTION.Pressure) as pending:
            reserve.replenish()
        self.assertEqual(pending.exception.reason, "recovery-pending")
        receipt = retire_claim(path)
        self.assertEqual(expected["file"], [receipt.stat().st_dev, receipt.stat().st_ino])
        settled = callback(reserve, "settle", receipt.name)
        self.assertEqual(settled.returncode, 0, settled.stderr)
        reserve.load()
        self.assertIsNone(reserve.state["claim"])
        reserve.replenish()
        self.assertTrue(reserve.full())

    def test_substituted_retirement_receipt_cannot_clear_a_bound_claim(self):
        reserve = self.reserve()
        reserve.spend()
        path = create_claim(self.registry, self.root / "candidate")
        reserve.write(reserve.state["epoch"], reserve.claim(path.name))
        expected = reserve.state["claim"].copy()
        content = path.read_bytes()
        path.rename(self.root / "original-claim")
        replacement = self.registry / "released" / path.name
        replacement.write_bytes(content)
        replacement.chmod(0o600)
        with self.assertRaises(PRODUCTION.Unsafe):
            reserve.reconcile_receipt()
        self.assertEqual(reserve.load()["claim"], expected)
        self.assertEqual(os.fstat(reserve.fd).st_size, PRODUCTION.HEADER)

    def test_substituted_active_claim_is_unsafe_not_recoverable_pressure(self):
        reserve = self.reserve()
        reserve.spend()
        path = create_claim(self.registry, self.root / "candidate")
        reserve.write(reserve.state["epoch"], reserve.claim(path.name))
        expected = reserve.state["claim"].copy()
        content = path.read_bytes()
        path.rename(self.root / "retained-original-claim")
        path.write_bytes(content)
        path.chmod(0o600)
        with self.assertRaises(PRODUCTION.Unsafe):
            reserve.replenish()
        self.assertEqual(reserve.load()["claim"], expected)
        self.assertEqual(os.fstat(reserve.fd).st_size, PRODUCTION.HEADER)

    def test_callback_refuses_wrong_metadata_descriptor_and_second_claim(self):
        reserve = self.reserve()
        reserve.spend()
        first = create_claim(self.registry, self.root / "first-candidate")
        second = create_claim(self.registry, self.root / "second-candidate")
        other_metadata = self.root / "other-metadata.lock"
        other_metadata.touch(mode=0o600)
        wrong = callback(reserve, "bind", first.name, other_metadata)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIsNone(reserve.load()["claim"])
        self.assertEqual(callback(reserve, "bind", first.name).returncode, 0)
        wrong = callback(reserve, "bind", second.name)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertEqual(reserve.load()["claim"]["name"], first.name)

    def test_symlink_hardlink_mode_and_replaced_reserve_are_refused(self):
        for mutation in ("symlink", "hardlink", "mode", "replacement"):
            with self.subTest(mutation=mutation):
                root = fixture_root("rch-reserve-invalid-")
                registry = registry_at(root)
                reserve = reserve_at(registry)
                path = registry / PRODUCTION.PRIVATE / PRODUCTION.FILE
                try:
                    if mutation == "symlink":
                        path.rename(root / "retained-reserve")
                        foreign = root / "foreign"
                        foreign.write_bytes(b"must remain untouched")
                        path.symlink_to(foreign)
                    elif mutation == "hardlink":
                        os.link(path, root / "second-reserve-name")
                    elif mutation == "mode":
                        path.chmod(0o640)
                    else:
                        path.rename(root / "retained-reserve")
                        path.write_bytes(b"replacement")
                        path.chmod(0o600)
                    with self.assertRaises((PRODUCTION.Unsafe, OSError)):
                        reserve.validate()
                    with self.assertRaises((PRODUCTION.Unsafe, OSError)):
                        reserve.spend()
                    if mutation == "symlink":
                        self.assertEqual(foreign.read_bytes(), b"must remain untouched")
                finally:
                    reserve.close()

    def test_private_directory_identity_and_noncanonical_registry_are_refused(self):
        reserve = self.reserve()
        scratch = Path(reserve.scratch)
        scratch.rename(scratch.with_name("retained-scratch"))
        scratch.mkdir(mode=0o700)
        with self.assertRaises(PRODUCTION.Unsafe):
            reserve.validate()
        for bad in ("relative", "/", str(self.registry) + "/../claims", str(self.registry) + "\n"):
            with self.subTest(path=bad), self.assertRaises((PRODUCTION.Unsafe, ValueError, OSError)):
                PRODUCTION.Reserve(bad, capacity=CAPACITY, headroom=HEADROOM)

    def test_retargeted_ancestor_alias_cannot_redirect_an_existing_reserve(self):
        physical = self.root / "physical"
        physical.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(physical, target_is_directory=True)
        registry = registry_at(alias)
        reserve = reserve_at(registry)
        self.reserves.append(reserve)
        self.assertTrue(reserve.full())
        alias.rename(self.root / "retained-alias")
        other = self.root / "other"
        other.mkdir(mode=0o700)
        marker = other / "untouched"
        marker.write_bytes(b"foreign directory")
        alias.symlink_to(other, target_is_directory=True)
        with self.assertRaises(PRODUCTION.Unsafe):
            reserve.validate()
        with self.assertRaises(PRODUCTION.Unsafe):
            reserve.spend()
        self.assertEqual(marker.read_bytes(), b"foreign directory")
        self.assertEqual(list(other.iterdir()), [marker])

    def test_corrupt_or_zero_newest_header_never_falls_back_to_unbound_state(self):
        for corruption in ("zero", "invalid", "wrong-identity", "nonboolean-provisioning"):
            with self.subTest(corruption=corruption):
                root = fixture_root("rch-reserve-header-")
                registry = registry_at(root)
                reserve = reserve_at(registry)
                try:
                    reserve.spend()
                    claim = create_claim(registry, root / "candidate")
                    reserve.write(reserve.state["epoch"], reserve.claim(claim.name))
                    offset = reserve.slot * PRODUCTION.SLOT
                    if corruption == "zero":
                        damaged = bytes(PRODUCTION.SLOT)
                    elif corruption == "invalid":
                        damaged = b"not a reserve header".ljust(PRODUCTION.SLOT, b"\0")
                    else:
                        envelope = json.loads(os.pread(reserve.fd, PRODUCTION.SLOT, offset).rstrip(b"\0"))
                        if corruption == "wrong-identity":
                            envelope["body"]["immutable"]["uid"] += 1
                        else:
                            envelope["body"]["provisioned"] = 1
                        encoded = json.dumps(envelope["body"], sort_keys=True, separators=(",", ":")).encode()
                        envelope["sha256"] = hashlib.sha256(encoded).hexdigest()
                        damaged = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode().ljust(PRODUCTION.SLOT, b"\0")
                    os.pwrite(reserve.fd, damaged, offset)
                    os.fsync(reserve.fd)
                    with self.assertRaises(PRODUCTION.Unsafe):
                        reserve.load()
                    self.assertTrue(claim.exists())
                    self.assertEqual(os.fstat(reserve.fd).st_size, PRODUCTION.HEADER)
                finally:
                    reserve.close()

    def test_shared_admissions_coexist_but_cannot_overlap_refill(self):
        first = self.reserve()
        first.lock(False)
        second = self.reopen()
        second.lock(False)
        second.load()
        self.assertTrue(second.full())
        refill = self.reopen()
        with self.assertRaises(PRODUCTION.Unsafe):
            refill.lock(True)
        first.close()
        with self.assertRaises(PRODUCTION.Unsafe):
            refill.lock(True)
        second.close()
        refill.lock(True)
        refill.load()
        refill.replenish()
        self.assertTrue(refill.full())

    def test_first_initializer_cannot_be_stranded_by_a_concurrent_probe(self):
        first = PRODUCTION.Reserve(str(self.registry), create=True, capacity=CAPACITY, headroom=HEADROOM)
        self.reserves.append(first)
        self.assertTrue(first.created)
        self.assertEqual(os.fstat(first.fd).st_size, 0)
        with self.assertRaises(PRODUCTION.Unsafe) as busy:
            PRODUCTION.Reserve(str(self.registry), create=True, capacity=CAPACITY, headroom=HEADROOM)
        self.assertIn("initialization busy", str(busy.exception))
        first.lock(True)
        first.initialize()
        first.replenish()
        first.lock(False)
        second = PRODUCTION.Reserve(str(self.registry), create=True, capacity=CAPACITY, headroom=HEADROOM)
        self.reserves.append(second)
        second.lock(False)
        second.initialize()
        self.assertTrue(second.full())
        self.assertIsNone(second.state["epoch"])

    def test_gc_prunes_only_its_own_released_receipts(self):
        candidate = self.root / "candidate"
        candidate.mkdir(mode=0o700)
        cancelled = self.registry / "cancelled"
        cancelled.mkdir(mode=0o700)
        old = time.time() - 3 * 24 * 60 * 60
        protected = []
        for directory, prefix in ((self.registry / "released", "ca-"),
                                  (self.registry / "released", "a123-"),
                                  (cancelled, "ca-"), (cancelled, "fc-")):
            record = directory / (prefix + str(uuid.uuid4()) + "." + "a" * 64 + ".claim")
            record.write_bytes(b"durable source or cancellation recovery evidence\n")
            record.chmod(0o600)
            os.utime(record, (old, old))
            protected.append(record)
        gc_receipt = self.registry / "released" / ("fc-" + str(uuid.uuid4()) + "." + "b" * 64 + ".claim")
        gc_receipt.write_bytes(b"old GC receipt\n")
        gc_receipt.chmod(0o600)
        os.utime(gc_receipt, (old, old))
        program = gc_guard(self.registry) + "\nset -eu\n__gc_source_begin " + shlex.quote(str(candidate))
        program += "\n__gc_source_end\n"
        result = subprocess.run(["/bin/sh", "-c", program], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(gc_receipt.exists())
        for record in protected:
            self.assertEqual(record.read_bytes(), b"durable source or cancellation recovery evidence\n")
        self.assertEqual(len(list((self.registry / "released").glob("fc-*.claim"))), 1)

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open")
                         and hasattr(signal, "pidfd_send_signal"), "safe Linux pidfd cleanup required")
    def test_killed_parent_does_not_release_a_surviving_childs_shared_or_exclusive_lease(self):
        for mode in ("shared", "exclusive"):
            with self.subTest(mode=mode):
                root = fixture_root("rch-reserve-survivor-")
                registry = registry_at(root)
                ready = root / "survivor.ready"
                owner = subprocess.Popen(
                    [sys.executable, "-I", "-S", "-c", LEASE_OWNER, str(HELPER), str(registry), mode, str(ready)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                survivor = None
                reserve = None
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline and owner.poll() is None:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists(), "lease owner never published its child")
                    survivor = os.pidfd_open(int(ready.read_text()))
                    owner.kill()
                    owner.wait(timeout=5)
                    reserve = PRODUCTION.Reserve(str(registry), capacity=CAPACITY, headroom=HEADROOM)
                    with self.assertRaises(PRODUCTION.Unsafe):
                        reserve.lock(True)
                    owner.stdin.write(b"release\n")
                    owner.stdin.flush()
                    poller = select.poll()
                    poller.register(survivor, select.POLLIN)
                    self.assertTrue(poller.poll(5000), "surviving lease holder failed to exit")
                    reserve.lock(True)
                    reserve.load()
                    reserve.replenish()
                    self.assertTrue(reserve.full())
                finally:
                    if survivor is not None:
                        try:
                            signal.pidfd_send_signal(survivor, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        os.close(survivor)
                    if owner.poll() is None:
                        owner.kill()
                    owner.communicate(timeout=5)
                    if reserve is not None:
                        reserve.close()

    def namespace_fixture(self, mode):
        if sys.platform != "linux" or shutil.which("unshare") is None or shutil.which("mount") is None:
            self.skipTest("real ENOSPC requires isolated Linux user/mount namespaces")
        probe = subprocess.run(
            ["unshare", "--user", "--map-root-user", "--mount", "--fork", "/bin/true"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if probe.returncode:
            self.skipTest("isolated user/mount namespaces unavailable: " + probe.stderr.decode())
        mount = self.root / ("tmpfs-" + mode)
        mount.mkdir(mode=0o700)
        # Full ownership censuses must cover every observed process. Give the
        # interrupted-GC fixture its own real PID namespace/procfs rather than
        # hiding inaccessible unrelated container processes with fake tools.
        process_namespace = ["--pid", "--mount-proc"] if mode == "interrupted-gc-child" else []
        result = subprocess.run(
            ["unshare", "--user", "--map-root-user", "--mount", "--fork", *process_namespace, sys.executable,
             "-I", "-S", str(Path(__file__).resolve()), "--" + mode, str(mount)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40, check=False,
        )
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        evidence = json.loads(result.stdout)
        self.assertTrue(evidence["real_enospc"])
        return evidence

    def test_real_enospc_release_pays_for_bound_receipt_and_refill_requires_new_headroom(self):
        evidence = self.namespace_fixture("enospc-child")
        self.assertGreaterEqual(evidence["allocated"], CAPACITY)
        self.assertGreaterEqual(evidence["released"], CAPACITY - PRODUCTION.HEADER)
        self.assertGreaterEqual(evidence["refill_headroom"], HEADROOM)

    def test_actual_cli_recovers_at_zero_space_and_admission_waits_for_refill(self):
        evidence = self.namespace_fixture("cli-enospc-child")
        self.assertEqual(evidence["default_capacity"], PRODUCTION.CAPACITY)
        self.assertEqual(evidence["recovery_stdout"], "recovery-ran\n")
        self.assertTrue(evidence["refilled"])
        self.assertTrue(evidence["truncation_before_epoch_recovered"])
        self.assertTrue(evidence["production_gc_receipt"].startswith("fc-"))

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open")
                         and hasattr(signal, "pidfd_send_signal"), "safe Linux pidfd cleanup required")
    def test_real_gc_claim_outlives_killed_supervisor_and_recovers_only_after_quiescence(self):
        evidence = self.namespace_fixture("interrupted-gc-child")
        self.assertTrue(evidence["surviving_deletion_blocked_refill"])
        self.assertTrue(evidence["minimum_age_preserved"])
        self.assertTrue(evidence["checked_automatic_retirement"].startswith("fc-"))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--enospc-child":
        enospc_child(Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--cli-enospc-child":
        cli_enospc_child(Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "--interrupted-gc-child":
        interrupted_gc_child(Path(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "--surviving-deletion":
        surviving_deletion_child(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == "--assert-bound":
        assert_bound_child(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "--delete-owned":
        delete_owned_child(Path(sys.argv[2]))
    else:
        unittest.main()
