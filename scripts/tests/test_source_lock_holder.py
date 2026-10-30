#!/usr/bin/env python3
"""Exercise the production holder with real kernel locks and owned processes.

Run directly, or through rch/tests/source_lock_holder.rs. On Linux, the Darwin
bootstrap is selected with a test-owned uname, but the locks are Linux locks:
this does not substitute for running this suite on Darwin. Nothing contacts a
worker or changes a real RCH registry. Fixtures are retained for inspection.
"""
import contextlib
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

REPO = Path(__file__).resolve().parents[2]
HOLDER = (REPO / "rch/src/hook/source_lock_holder.sh").read_text()
SSH_SOURCE = (REPO / "rch/src/hook/ssh.rs").read_text()
RELEASE_WAITER = SSH_SOURCE.split(
    'const SOURCE_AUTHORITY_RELEASE_WAITER: &str = r#"', 1)[1].split('"#;', 1)[0]
CLAIM_REGISTRY = (REPO / "rch/src/hook/source_claim_registry.sh").read_text()
CLAIM_HELPER_SOURCE = (REPO / "rch-common/src/stale_target_reap.rs").read_text()
CLAIM_HELPERS = CLAIM_HELPER_SOURCE.split(
    'pub const SOURCE_CLAIM_RECORD_HELPERS: &str = r#"', 1)[1].split('"#;', 1)[0]
FLOCK = shutil.which("flock")
GNU_FLOCK = bool(FLOCK and b"--no-fork" in subprocess.run(
    [FLOCK, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    timeout=5, check=False,
).stdout)
BASH = shutil.which("bash")
GNU_CANCELLABLE = bool(GNU_FLOCK and BASH and subprocess.run(
    [BASH, "--noprofile", "--norc", "-p", "-c",
     "(( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 1) ))"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False,
).returncode == 0)


def eventually(predicate, detail):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(detail)


def available(path, shared=False):
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            return True
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise
    finally:
        os.close(fd)


def _default_sighup():
    # rch's remote wrapper runs `trap '' HUP`, and an ignored disposition is inherited
    # and cannot be reset by `trap - HUP` in a non-interactive sh. Restore the default
    # so the SIGHUP case really kills the holder when this suite runs under rch.
    signal.signal(signal.SIGHUP, signal.SIG_DFL)


def _ignored_sighup():
    signal.signal(signal.SIGHUP, signal.SIG_IGN)


class Holder:
    def __init__(self, script, args, env, plan, claim="claim input", fd_limit=None,
                 closed_stdin=False, ignore_hup=False, session_idle=None):
        command = "set -eu\n"
        if fd_limit:
            command += "ulimit -n {}\n".format(fd_limit)
        # This is the production transport contract: plan on fd 3, claim on
        # fd 4, release input on stdin, script as both -c program and argv[0].
        if isinstance(plan, Path):
            # Raw bytes (including NUL/truncation) must not pass through argv
            # or a here-document that would repair their framing for the test.
            command += "exec 3<{}\n".format(shlex.quote(str(plan)))
        else:
            command += "exec 3<<'RCH_TEST_PLAN'\n{}RCH_TEST_PLAN\n".format(plan)
        command += "exec 4<<'RCH_TEST_CLAIM'\n{}\nRCH_TEST_CLAIM\n".format(claim)
        command += "exec sh -c {} {} {}".format(
            shlex.quote(script), shlex.quote(script), shlex.join(args))
        if session_idle is not None:
            # Match source_authority_live_session_command: the supervisor
            # receives the whole holder script on fd 3, never through argv.
            command = ("set -eu\nexec 3<<'RCH_SOURCE_LOCK_SESSION_PROGRAM'\n{}\n"
                       "RCH_SOURCE_LOCK_SESSION_PROGRAM\nexec sh -c {} {} --rch-session {}"
                       ).format(command, shlex.quote(script), shlex.quote(script), session_idle)
        self.process = subprocess.Popen(
            ["/bin/sh", "-c", command], env=env,
            stdin=subprocess.DEVNULL if closed_stdin else subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=_ignored_sighup if ignore_hup else _default_sighup,
        )
        self.buffer = b""

    def line(self, timeout=5):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdout, selectors.EVENT_READ)
                if not selector.select(remaining):
                    return None
            data = os.read(self.process.stdout.fileno(), 4096)
            if not data:
                return None
            self.buffer += data
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line

    def send(self, text):
        self.process.stdin.write(text.encode())
        self.process.stdin.flush()

    def finish(self):
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                # Cancellation may close the remote reader while the last
                # heartbeat is buffered. Still inspect its real exit status,
                # output and retained ownership below.
                pass
            finally:
                self.process.stdin = None
        return self.process.communicate(timeout=5)

    def failure(self):
        # A malformed plan or bootstrap must fail with a LIVE requester.
        # Closing stdin first would let disconnect refusal mask the defect.
        self.process.wait(timeout=5)
        return self.finish()

    def close(self):
        if self.process.poll() is None:
            self.process.kill()  # Only the exact child created by this fixture.
        self.process.communicate(timeout=5)


class SourceLockHolderTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-source-holder-"))
        self.holders = []

    def tearDown(self):
        for holder in reversed(self.holders):
            holder.close()

    def environment(self, portable=True, python=True, gnu_flock=True, bash=True):
        name = "native-bin" if portable else "linux-native-bin" if python else "gnu-bin"
        directory = self.root / (name if bash else name + "-legacy")
        directory.mkdir(exist_ok=True)
        uname = directory / "uname"
        # Sibling holders may still be executing this same fixture. Its
        # contents are immutable; replacing it races exec with ETXTBSY.
        if not uname.exists():
            uname.write_text("#!/bin/sh\nprintf 'called\\n' >> {}\nprintf '%s\\n' {}\n".format(
                shlex.quote(str(directory / "uname.calls")), "Darwin" if portable else "Linux"))
            uname.chmod(0o700)
        for name, target in [("sh", "/bin/sh"), ("cat", shutil.which("cat"))]:
            path = directory / name
            if not path.exists():
                path.symlink_to(target)
        if bash and BASH:
            path = directory / "bash"
            if not path.exists():
                path.symlink_to(BASH)
        if python:
            path = directory / "python3"
            if not path.exists():
                path.symlink_to(sys.executable)
        if portable or not gnu_flock:
            # A successful test must never invoke GNU flock on this path.
            flock = directory / "flock"
            self.assertFalse(flock.is_symlink(), "must not overwrite a real tool through a symlink")
            if not flock.exists():
                flock.write_text("#!/bin/sh\nprintf 'unexpected flock invocation\\n' >&2\nexit 97\n")
                flock.chmod(0o700)
        elif FLOCK:
            path = directory / "flock"
            if not path.exists():
                path.symlink_to(FLOCK)
        return {"PATH": str(directory), "LC_ALL": "C"}

    def start(self, specs, portable=True, terminal=None, args=(), **options):
        plan = options.pop("plan", "".join("{} {}\n".format(mode, path) for mode, path in specs))
        count = options.pop("count", len(specs))
        env = options.pop("env", None) or self.environment(portable)
        argv = [str(count), "READY"]
        if terminal is not None:
            argv += [terminal, *args]
        holder = Holder(HOLDER, argv, env, plan, **options)
        self.holders.append(holder)
        return holder

    def session_python_environment(self, setup):
        # Alter platform capabilities or the scheduling boundary before the
        # exact embedded production program runs. Ordinary holder/terminal
        # Python commands still exec the real interpreter unchanged.
        env = self.environment()
        directory = self.root / "session-python-bin"
        directory.mkdir()
        bootstrap = ("import os, signal, sys\n"
                     "if (sys.argv[1:4] == ['-I', '-S', '-c'] and len(sys.argv) == 6\n"
                     "        and 'RCH_SOURCE_LOCK_HEARTBEAT' in sys.argv[4]):\n"
                     + "".join("    " + line + "\n" for line in setup.splitlines())
                     + "    test_program = sys.argv[4]\n"
                     "    sys.argv = ['-c', *sys.argv[5:]]\n"
                     "    exec(compile(test_program, '<production source-lock session>', 'exec'))\n"
                     "else:\n"
                     "    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])\n")
        wrapper = directory / "python3"
        wrapper.write_text("#!/bin/sh\nexec {} -I -S -c {} \"$@\"\n".format(
            shlex.quote(sys.executable), shlex.quote(bootstrap)))
        wrapper.chmod(0o700)
        env["PATH"] = str(directory) + os.pathsep + env["PATH"]
        return env

    def assert_waiting(self, holder, paths, detail):
        # The holder validates and opens the WHOLE plan before taking any
        # lock, then retries the closure non-blocking and releases every
        # acquired lock before each contention wait (53a85a3e, 8b475843). A
        # blocked waiter is recognized by its opened plan and its silence,
        # never by a held prefix: probing a prefix lock only catches a retry
        # in flight.
        eventually(lambda: all(path.exists() for path in paths), detail)
        self.assertIsNone(holder.line(0.2), "readiness while a plan root is contended")
        self.assertIsNone(holder.process.poll(), "waiter exited instead of waiting")

    def assert_prefix_not_monopolized(self, paths):
        # Admission needs the whole closure: a waiter blocked on one busy root
        # must leave the roots before it to other builds.
        eventually(lambda: all(available(path) for path in paths),
                   "waiter monopolized earlier roots while contended")

    def release_registry(self, name="registry"):
        registry = self.root / name
        registry.mkdir()
        for child in ("released", "cancelled", "quarantine"):
            (registry / child).mkdir()
        (registry / "metadata.lock").write_bytes(b"")
        return registry

    def claim_bytes(self, roots):
        return ("\n".join(sorted(set(map(str, roots)))) + "\n").encode()

    def claim_record(self, registry, token, roots, extension="claim", directory=None):
        content = self.claim_bytes(roots)
        digest = hashlib.sha256(content).hexdigest()
        path = (directory or registry) / f"{token}.{digest}.{extension}"
        path.write_bytes(content)
        return path, digest, content

    def registry_transaction(self, registry, token, roots, operation):
        # Run the exact shared helpers and production transaction, including
        # cancellation's activity-before-metadata lock order. Starting with a
        # valid old claim models an admitted invocation, so a full test disk
        # never requires disabling the fresh-admission headroom checks.
        content = self.claim_bytes(roots)
        digest = hashlib.sha256(content).hexdigest()
        command = [FLOCK, "-x", "--", str(registry / "metadata.lock"),
                   "/bin/sh", "-c", CLAIM_HELPERS + "\n" + CLAIM_REGISTRY,
                   "rch-source-registry", str(registry), token, digest, operation]
        if operation in ("cancel", "finish-cancel"):
            command = [FLOCK, "-x", "--", str(registry / f"{token}.activity.lock"),
                       *command]
        return subprocess.run(command, input=content, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=20, check=False,
                              env={**os.environ, "LC_ALL": "C"})

    def start_release_waiter(self, registry, token, binding, mode="source", lock=None,
                             session_idle=None):
        lock = lock or registry / "holder.lock"
        kind = "AUTHORITY" if mode == "source" else "PAIR"
        release = f"RCH_SOURCE_{kind}_RELEASE:{token}"
        # The outer production holder owns real kernel locks. Its terminal
        # execs the production release waiter with those descriptors intact.
        # Success here means only that the exact request was read: no fixture
        # manufactures a durable release receipt or an acknowledgment.
        terminal = ('set -eu; exec 4<&-; printf "%s\\n" "$1"; '
                    'shift; exec python3 -I -S -c "$@"')
        holder = self.start([("x", lock)], terminal=terminal,
                            args=(RELEASE_WAITER, mode, str(registry), token,
                                  str(binding), release), session_idle=session_idle)
        self.assertEqual(holder.line(), b"READY")
        return holder, lock, release

    @contextlib.contextmanager
    def heartbeat_stream(self, holder):
        stopped = threading.Event()

        def send_heartbeats():
            while not stopped.wait(0.1):
                try:
                    holder.send("RCH_SOURCE_LOCK_HEARTBEAT\n")
                except (BrokenPipeError, OSError, ValueError):
                    # Autonomous cancellation closes this exact child's pipe.
                    return

        sender = threading.Thread(target=send_heartbeats, name="rch-test-heartbeats")
        sender.start()
        try:
            yield
        finally:
            stopped.set()
            sender.join(timeout=5)
            self.assertFalse(sender.is_alive(), "fixture heartbeat writer did not stop")

    def assert_heartbeat_session_held(self, holder, lock):
        # Exceed the two-second test lease: without valid heartbeat framing,
        # the supervisor would have killed this holder before cancellation.
        deadline = time.monotonic() + 2.2
        while time.monotonic() < deadline:
            self.assertIsNone(holder.process.poll(), "healthy heartbeat session exited")
            time.sleep(0.1)
        self.assertFalse(available(lock), "healthy session lost its source lock")

    def assert_release_waiting(self, holder, lock):
        self.assertIsNone(holder.line(0.6), "release waiter emitted an acknowledgment")
        self.assertIsNone(holder.process.poll(), "release waiter exited without exact evidence")
        self.assertFalse(available(lock), "release waiter lost its kernel lock")

    def assert_cancelled_waiter(self, holder, lock):
        # Keep stdin OPEN until autonomous exit has been observed. Calling
        # finish() first would let EOF hide the half-open transport defect.
        holder.process.wait(timeout=5)
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (75, b""), stderr)
        self.assertIn(b"cancel", stderr.lower())
        self.assertTrue(available(lock))

    @unittest.skipUnless(FLOCK, "flock required for real cancellation transactions")
    def test_release_waiter_cancellation_drops_kernel_locks_but_preserves_source_exclusion(self):
        registry = self.release_registry()
        roots = [self.root / "project", self.root / "dependency"]
        active, digest, content = self.claim_record(registry, "aa", roots)
        holder, lock, _ = self.start_release_waiter(registry, "aa", digest)
        self.assertFalse(available(lock))
        result = self.registry_transaction(registry, "aa", roots, "cancel")
        self.assertEqual((result.returncode, result.stdout), (0, b"owned"), result.stderr)
        self.assert_cancelled_waiter(holder, lock)
        cancelling = registry / f"aa.{digest}.cancelling"
        self.assertEqual(active.read_bytes(), content)
        self.assertEqual(cancelling.read_bytes(), content)
        # A released transient lock is NOT permission for another invocation
        # to overwrite the still-owned tree, even on a full filesystem.
        overlap = self.registry_transaction(registry, "bb", roots, "try-acquire")
        self.assertEqual((overlap.returncode, overlap.stdout), (75, b""), overlap.stderr)
        self.assertIn(b"unfinished overlapping source owner", overlap.stderr)
        self.assertEqual(active.read_bytes(), content)
        self.assertEqual(cancelling.read_bytes(), content)

    @unittest.skipUnless(FLOCK, "flock required for real cancellation transactions")
    def test_release_waiter_partial_request_does_not_hide_cancellation(self):
        registry = self.release_registry()
        roots = [self.root / "project"]
        active, digest, content = self.claim_record(registry, "aa", roots)
        holder, lock, release = self.start_release_waiter(registry, "aa", digest)
        holder.send(release[:12])  # No newline; the transport remains open.
        self.assert_release_waiting(holder, lock)
        result = self.registry_transaction(registry, "aa", roots, "cancel")
        self.assertEqual((result.returncode, result.stdout), (0, b"owned"), result.stderr)
        self.assert_cancelled_waiter(holder, lock)
        self.assertEqual(active.read_bytes(), content)

    @unittest.skipUnless(FLOCK, "flock required for real cancellation transactions")
    def test_release_waiter_cancellation_exits_healthy_heartbeat_session_before_expiry(self):
        registry = self.release_registry()
        roots = [self.root / "project"]
        active, digest, content = self.claim_record(registry, "aa", roots)
        holder, lock, _ = self.start_release_waiter(registry, "aa", digest, session_idle=2)
        with self.heartbeat_stream(holder):
            self.assert_heartbeat_session_held(holder, lock)
            started = time.monotonic()
            result = self.registry_transaction(registry, "aa", roots, "cancel")
            self.assertEqual((result.returncode, result.stdout), (0, b"owned"), result.stderr)
            holder.process.wait(timeout=1.5)
            self.assertLess(time.monotonic() - started, 1.5)
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (75, b""), stderr)
        self.assertIn(b"cancel", stderr.lower())
        self.assertNotIn(b"HEARTBEAT_EXPIRED", stderr)
        self.assertTrue(available(lock))
        self.assertEqual(active.read_bytes(), content)
        self.assertEqual((registry / f"aa.{digest}.cancelling").read_bytes(), content)

    @unittest.skipUnless(FLOCK, "flock required for real cancellation transactions")
    def test_release_waiter_cleanup_pair_accepts_supervised_explicit_release(self):
        registry = self.release_registry()
        pair_root = self.root / "unmaterialized-pair"
        active, digest, content = self.claim_record(registry, "aa", [pair_root])
        result = self.registry_transaction(registry, "aa", [pair_root], "cancel")
        self.assertEqual((result.returncode, result.stdout), (0, b"owned"), result.stderr)
        holder, lock, release = self.start_release_waiter(
            registry, "aa", pair_root, mode="cleanup-pair", session_idle=2)
        with self.heartbeat_stream(holder):
            self.assert_heartbeat_session_held(holder, lock)
        # Stop the single heartbeat producer before writing the exact release
        # frame, matching production serialization and avoiding interleaving.
        holder.send(release + "\n")
        holder.process.wait(timeout=5)
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
        self.assertTrue(available(lock))
        self.assertEqual(active.read_bytes(), content)
        self.assertEqual((registry / f"aa.{digest}.cancelling").read_bytes(), content)

    @unittest.skipUnless(FLOCK, "flock required for real cancellation transactions")
    def test_release_waiter_pair_cancellation_allows_cleanup_handoff_and_terminal_retry(self):
        registry = self.release_registry()
        pair_root = self.root / "unmaterialized-pair"
        roots = [pair_root, self.root / "dependency"]
        active, digest, content = self.claim_record(registry, "aa", roots)
        original, lock, _ = self.start_release_waiter(registry, "aa", pair_root, mode="pair")
        result = self.registry_transaction(registry, "aa", roots, "cancel")
        self.assertEqual((result.returncode, result.stdout), (0, b"owned"), result.stderr)
        self.assert_cancelled_waiter(original, lock)
        cleanup, _, release = self.start_release_waiter(
            registry, "aa", pair_root, mode="cleanup-pair", lock=lock)
        self.assert_release_waiting(cleanup, lock)
        self.assertEqual(active.read_bytes(), content)
        # Cancellation recovery must keep its newly acquired pair despite the
        # fence that stopped the original holder. Only explicit release ends it.
        cleanup.send(release + "\n")
        cleanup.process.wait(timeout=5)
        stdout, stderr = cleanup.finish()
        self.assertEqual((cleanup.process.returncode, stdout, stderr), (0, b"", b""))
        self.assertTrue(available(lock))
        self.assertFalse(pair_root.exists(), "fixture must have no tree requiring retirement")
        finished = self.registry_transaction(registry, "aa", roots, "finish-cancel")
        self.assertEqual((finished.returncode, finished.stdout), (0, b""), finished.stderr)
        receipt = registry / "cancelled" / f"aa.{digest}.claim"
        cancelling = registry / f"aa.{digest}.cancelling"
        self.assertFalse(active.exists())
        self.assertEqual(receipt.read_bytes(), content)
        self.assertEqual(cancelling.read_bytes(), content)
        for mode, binding in (("source", digest), ("pair", pair_root)):
            with self.subTest(mode=mode):
                retry, _, _ = self.start_release_waiter(registry, "aa", binding, mode, lock)
                self.assert_cancelled_waiter(retry, lock)
                self.assertEqual(receipt.read_bytes(), content)
                self.assertEqual(cancelling.read_bytes(), content)

    @unittest.skipUnless(FLOCK, "flock required for real cancellation transactions")
    def test_release_waiter_pair_observes_unowned_cancellation_without_claim(self):
        registry = self.release_registry()
        pair_root = self.root / "pair-before-source-grant"
        holder, lock, _ = self.start_release_waiter(registry, "aa", pair_root, mode="pair")
        result = self.registry_transaction(registry, "aa", [pair_root], "cancel")
        self.assertEqual((result.returncode, result.stdout), (0, b"unowned"), result.stderr)
        self.assert_cancelled_waiter(holder, lock)
        content = self.claim_bytes([pair_root])
        digest = hashlib.sha256(content).hexdigest()
        self.assertEqual((registry / "cancelled" / f"aa.{digest}.claim").read_bytes(), content)
        self.assertFalse((registry / f"aa.{digest}.claim").exists())

    def test_release_waiter_requires_matching_identity_digest_and_exact_pair_root(self):
        for mode, wrong in (("source", "token"), ("source", "digest"),
                            ("pair", "token"), ("pair", "root")):
            with self.subTest(mode=mode, wrong=wrong):
                registry = self.release_registry(f"registry-{mode}-{wrong}")
                root = self.root / "pair"
                observed_root = self.root / "pair-child" if wrong == "root" else root
                record_token = "bb" if wrong == "token" else "aa"
                active, digest, content = self.claim_record(registry, record_token, [observed_root])
                fence, _, _ = self.claim_record(registry, record_token, [observed_root], "cancelling")
                binding = ("0" * 64 if wrong == "digest" else digest) if mode == "source" else root
                holder, lock, release = self.start_release_waiter(registry, "aa", binding, mode)
                self.assert_release_waiting(holder, lock)
                holder.send(release + "\n")
                holder.process.wait(timeout=5)
                stdout, stderr = holder.finish()
                self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
                self.assertEqual(active.read_bytes(), content)
                self.assertEqual(fence.read_bytes(), content)

    def test_release_waiter_invalid_or_conflicting_records_never_fabricate_cancellation(self):
        for defect in ("bad-content", "symlink", "pending", "active-and-terminal",
                       "released-and-cancelling", "duplicate-digest"):
            with self.subTest(defect=defect):
                registry = self.release_registry("registry-" + defect)
                roots = [self.root / "project"]
                active, digest, content = self.claim_record(registry, "aa", roots)
                fence = registry / f"aa.{digest}.cancelling"
                records = [active]
                if defect == "active-and-terminal":
                    receipt, _, _ = self.claim_record(
                        registry, "aa", roots, directory=registry / "cancelled")
                    records.append(receipt)
                elif defect == "symlink":
                    fence.symlink_to(active)
                else:
                    fence.write_bytes(b"/different-roots\n" if defect == "bad-content" else content)
                    records.append(fence)
                if defect == "pending":
                    records.append(self.claim_record(registry, "aa", roots, "pending")[0])
                elif defect == "released-and-cancelling":
                    records.append(self.claim_record(
                        registry, "aa", roots, directory=registry / "released")[0])
                elif defect == "duplicate-digest":
                    records.append(self.claim_record(
                        registry, "aa", [self.root / "different-project"])[0])
                before = {path: path.read_bytes() for path in records}
                holder, lock, release = self.start_release_waiter(registry, "aa", digest)
                self.assert_release_waiting(holder, lock)
                # The caller's real retirement transaction still validates all
                # records. The waiter recognizes only the request, never an ack.
                holder.send(release + "\n")
                holder.process.wait(timeout=5)
                stdout, stderr = holder.finish()
                self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
                self.assertEqual({path: path.read_bytes() for path in records}, before)
                if defect == "symlink":
                    self.assertTrue(fence.is_symlink())
                    self.assertEqual(fence.readlink(), active)

    def test_release_waiter_observes_metadata_snapshot_without_blocking_input(self):
        registry = self.release_registry()
        roots = [self.root / "project"]
        _, digest, _ = self.claim_record(registry, "aa", roots)
        metadata = os.open(registry / "metadata.lock", os.O_RDWR)
        try:
            fcntl.flock(metadata, fcntl.LOCK_EX)
            self.claim_record(registry, "aa", roots, "cancelling")
            holder, lock, _ = self.start_release_waiter(registry, "aa", digest)
            self.assert_release_waiting(holder, lock)
            # A complete-looking record is not a coherent snapshot while its
            # publishing transaction still owns the metadata mutex.
            fcntl.flock(metadata, fcntl.LOCK_UN)
            self.assert_cancelled_waiter(holder, lock)
        finally:
            os.close(metadata)
        idle_registry = self.release_registry("idle-registry")
        _, idle_digest, _ = self.claim_record(idle_registry, "aa", roots)
        metadata = os.open(idle_registry / "metadata.lock", os.O_RDWR)
        try:
            fcntl.flock(metadata, fcntl.LOCK_EX)
            idle, lock, release = self.start_release_waiter(idle_registry, "aa", idle_digest)
            idle.send(release + "\n")
            idle.process.wait(timeout=5)
            stdout, stderr = idle.finish()
            self.assertEqual((idle.process.returncode, stdout, stderr), (0, b"", b""))
            self.assertTrue(available(lock))
        finally:
            os.close(metadata)

    def test_release_waiter_idle_and_fragmented_exact_request_preserve_protocol(self):
        registry = self.release_registry()
        active, digest, content = self.claim_record(registry, "aa", [self.root / "project"])
        holder, lock, release = self.start_release_waiter(registry, "aa", digest)
        self.assert_release_waiting(holder, lock)
        half = len(release) // 2
        holder.send(release[:half])
        self.assert_release_waiting(holder, lock)
        holder.send(release[half:] + "\n")
        holder.process.wait(timeout=5)
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
        self.assertTrue(available(lock))
        self.assertEqual(active.read_bytes(), content)

    def test_release_waiter_bad_or_oversized_input_never_acknowledges(self):
        registry = self.release_registry()
        active, digest, content = self.claim_record(registry, "aa", [self.root / "project"])
        for defect in ("wrong", "cr", "nul", "oversized"):
            with self.subTest(defect=defect):
                holder, lock, release = self.start_release_waiter(registry, "aa", digest)
                request = {"wrong": "WRONG\n", "cr": release + "\r\n",
                           "nul": release + "\0\n", "oversized": "x" * 4097}[defect]
                holder.send(request)
                holder.process.wait(timeout=5)
                stdout, stderr = holder.finish()
                self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
                self.assertTrue(available(lock))
                self.assertEqual(active.read_bytes(), content)

    def test_release_waiter_eof_without_complete_exact_request_never_acknowledges(self):
        registry = self.release_registry()
        active, digest, content = self.claim_record(registry, "aa", [self.root / "project"])
        for partial in (False, True):
            with self.subTest(partial=partial):
                holder, lock, release = self.start_release_waiter(registry, "aa", digest)
                if partial:
                    holder.send(release)
                stdout, stderr = holder.finish()
                self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
                self.assertTrue(available(lock))
                self.assertEqual(active.read_bytes(), content)

    def test_all_locks_survive_terminal_exec_and_fd4_is_preserved(self):
        paths = [self.root / ("lock-{}".format(i)) for i in range(64)]
        terminal = ('set -eu; claim=$(cat <&4); exec 4<&-; '
                    '[ "$claim" = "claim input" ]; '
                    'if (: <&3) 2>/dev/null; then exit 98; fi; '
                    'printf "%s\\n" "$1" "$$" "$2"; '
                    'IFS= read -r release; [ "$release" = RELEASE ]; printf "RELEASED\\n"')
        holder = self.start([("x", path) for path in paths], terminal=terminal,
                            args=("literal $value; with quotes ' and spaces",))
        self.assertEqual(holder.line(), b"READY")
        self.assertEqual(int(holder.line()), holder.process.pid)
        self.assertEqual(holder.line(), b"literal $value; with quotes ' and spaces")
        self.assertTrue(all(not available(path) for path in paths))
        self.assertTrue(all(not available(path, shared=True) for path in paths))
        holder.send("RELEASE\n")
        self.assertEqual(holder.line(), b"RELEASED")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
        self.assertTrue(all(available(path) for path in paths))

    def session_fixture(self, name="session", idle=1, env=None):
        lock = self.root / (name + ".lock")
        claim = self.root / (name + ".claim")
        receipt = self.root / (name + ".released")
        release = "RCH_SOURCE_AUTHORITY_RELEASE:abc-123"
        terminal = ("set -eu; printf 'durable owner\\n' > {}; printf '%s\\n' \"$1\"; "
                    "IFS= read -r request; [ \"$request\" = {} ]; "
                    "printf '%s\\n' \"$request\" > {}; printf '%s\\n' \"$request\"").format(
                        shlex.quote(str(claim)), shlex.quote(release), shlex.quote(str(receipt)))
        holder = self.start([("x", lock)], terminal=terminal, session_idle=idle, env=env)
        self.assertEqual(holder.line(), b"READY")
        self.assertFalse(available(lock))
        return holder, lock, claim, receipt, release

    def test_session_half_open_requester_expires_without_erasing_durable_owner(self):
        holder, lock, claim, receipt, _ = self.session_fixture()
        # Keep stdin open: this is a half-open/stopped client, not an EOF test.
        holder.process.wait(timeout=4)
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (73, b""))
        self.assertIn(b"RCH_SOURCE_LOCK_HEARTBEAT_EXPIRED", stderr)
        self.assertEqual(claim.read_text(), "durable owner\n")
        self.assertFalse(receipt.exists())
        self.assertTrue(available(lock))

    def test_session_heartbeats_renew_only_liveness_and_release_remains_exact(self):
        holder, lock, claim, receipt, release = self.session_fixture()
        for _ in range(14):
            holder.send("RCH_SOURCE_LOCK_HEARTBEAT\n")
            time.sleep(0.1)
            self.assertIsNone(holder.process.poll())
            self.assertFalse(available(lock))
            self.assertFalse(receipt.exists())
        holder.send(release + "\n")
        # EOF immediately following a complete release must not turn a valid
        # retirement into an unacknowledged cancellation.
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr),
                         (0, (release + "\n").encode(), b""))
        self.assertEqual(receipt.read_text(), release + "\n")
        self.assertEqual(claim.read_text(), "durable owner\n")
        self.assertTrue(available(lock))

    def test_session_partial_heartbeat_never_renews_deadline(self):
        holder, lock, claim, receipt, _ = self.session_fixture()
        started = time.monotonic()
        for fragment in ("RCH_", "SOURCE_", "LOCK_", "HEARTBEAT"):
            holder.send(fragment)
            time.sleep(0.2)
        holder.process.wait(timeout=2)
        _, stderr = holder.finish()
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(holder.process.returncode, 73)
        self.assertIn(b"RCH_SOURCE_LOCK_HEARTBEAT_EXPIRED", stderr)
        self.assertTrue(claim.exists() and available(lock))
        self.assertFalse(receipt.exists())

    def test_session_invalid_and_oversized_frames_never_release_authority(self):
        for index, frame in enumerate(("RCH_SOURCE_LOCK_HEARTBEAT:release\n", "x" * 4096,
                                       "RCH_SOURCE_AUTHORITY_RELEASE:../wrong\n")):
            holder, lock, claim, receipt, _ = self.session_fixture(str(index))
            holder.send(frame)
            holder.process.wait(timeout=3)
            _, stderr = holder.finish()
            self.assertEqual(holder.process.returncode, 73)
            self.assertIn(b"RCH_SOURCE_LOCK_PROTOCOL_ERROR", stderr)
            self.assertTrue(claim.exists() and available(lock))
            self.assertFalse(receipt.exists())

    def test_session_eof_without_release_retains_owner_and_reaps_locks(self):
        holder, lock, claim, receipt, _ = self.session_fixture(idle=90)
        _, stderr = holder.finish()
        self.assertEqual(holder.process.returncode, 73)
        self.assertIn(b"RCH_SOURCE_LOCK_DISCONNECTED", stderr)
        self.assertTrue(claim.exists() and available(lock))
        self.assertFalse(receipt.exists())

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1 required")
    def test_session_expires_queued_metadata_publisher_without_late_work(self):
        root, metadata = self.root / "root.lock", self.root / "metadata.lock"
        published = self.root / "unexpected-publication"
        fd = os.open(metadata, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            terminal = ("printf 'WAITING\\n'; exec flock -x -- {} sh -c {}"
                        ).format(shlex.quote(str(metadata)), shlex.quote(
                            "printf 'late publication\\n' > " + shlex.quote(str(published))))
            holder = self.start([("x", root)], terminal=terminal, session_idle=1,
                                env=self.environment(portable=False))
            self.assertEqual(holder.line(), b"WAITING")
            self.assertFalse(available(root))
            holder.process.wait(timeout=4)
            _, stderr = holder.finish()
            self.assertEqual(holder.process.returncode, 73)
            self.assertIn(b"RCH_SOURCE_LOCK_HEARTBEAT_EXPIRED", stderr)
            self.assertTrue(available(root))
            self.assertFalse(published.exists())
            self.assertFalse(available(metadata), "session killed an unrelated lock holder")
        finally:
            os.close(fd)
        time.sleep(0.1)
        self.assertFalse(published.exists(), "expired queued publisher ran after contention cleared")

    def test_session_reports_external_holder_signal_without_release(self):
        lock = self.root / "killed.lock"
        terminal = 'printf "%s\\n" "$1" "$$"; exec cat >/dev/null'
        holder = self.start([("x", lock)], terminal=terminal, session_idle=90)
        self.assertEqual(holder.line(), b"READY")
        pid = int(holder.line())
        os.kill(pid, signal.SIGKILL)  # Exact child published by this fixture.
        holder.process.wait(timeout=3)
        _, stderr = holder.finish()
        self.assertEqual(holder.process.returncode, 137)
        self.assertIn(b"RCH_SOURCE_LOCK_PROCESS_TERMINATED: signal=9", stderr)
        self.assertTrue(available(lock))

    def test_session_teardown_reaps_descendant_lock_holders_on_normal_exit(self):
        lock = self.root / "descendant.lock"
        terminal = ("python3 -I -S -c {} & printf '%s\\n' \"$1\"; "
                    "IFS= read -r request; exit 0").format(shlex.quote(
                        "import time; time.sleep(120)"))
        holder = self.start([("x", lock)], terminal=terminal, session_idle=90)
        self.assertEqual(holder.line(), b"READY")
        holder.send("RCH_SOURCE_AUTHORITY_RELEASE:abc\n")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
        self.assertTrue(available(lock), "descendant retained source lock after settled exit")

    def test_session_heartbeat_expiry_survives_blocked_stdout(self):
        lock = self.root / "blocked-output.lock"
        terminal = ("printf '%s\\n' \"$1\"; exec python3 -I -S -c {}"
                    ).format(shlex.quote("import os; os.write(1, b\"x\" * (1024 * 1024))"))
        holder = self.start([("x", lock)], terminal=terminal, session_idle=1)
        self.assertEqual(holder.line(), b"READY")
        # Do not drain stdout until the monitor has terminated; this used to
        # leave pipe writers inheriting source-lock descriptors indefinitely.
        holder.process.wait(timeout=4)
        _, stderr = holder.finish()
        self.assertEqual(holder.process.returncode, 73)
        self.assertIn(b"RCH_SOURCE_LOCK_HEARTBEAT_EXPIRED", stderr)
        self.assertTrue(available(lock))

    def test_session_observer_death_cannot_bypass_expiry_group_teardown(self):
        lock = self.root / "orphaned-observer.lock"
        terminal = ("printf '%s\\n' \"$1\"; exec python3 -I -S -c {}"
                    ).format(shlex.quote(
                        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                        "time.sleep(120)"))
        holder = self.start([("x", lock)], terminal=terminal, session_idle=1)
        self.assertEqual(holder.line(), b"READY")
        self.assertFalse(available(lock))
        # Kill only our observer, leaving stdin open and its private holder
        # group alive. The monitor must still kill that group even though its
        # teardown-receipt write now fails with EPIPE.
        holder.process.kill()
        holder.process.wait(timeout=2)
        eventually(lambda: available(lock), "dead observer stranded the holder group")
        _, stderr = holder.finish()
        self.assertEqual(holder.process.returncode, -signal.SIGKILL)
        self.assertIn(b"RCH_SOURCE_LOCK_HEARTBEAT_EXPIRED", stderr)

    def test_session_monitor_death_is_reaped_only_after_its_group_is_killed(self):
        lock = self.root / "killed-monitor.lock"
        terminal = ("printf '%s\\n' \"$1\"; exec python3 -I -S -c {}"
                    ).format(shlex.quote(
                        "import os,signal,time; print(os.getppid(), flush=True); "
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(120)"))
        holder = self.start([("x", lock)], terminal=terminal, session_idle=90)
        self.assertEqual(holder.line(), b"READY")
        monitor = int(holder.line())
        self.assertNotEqual(monitor, holder.process.pid)
        self.assertFalse(available(lock))
        os.kill(monitor, signal.SIGKILL)  # Exact parent reported by our fixture child.
        holder.process.wait(timeout=3)
        _, stderr = holder.finish()
        self.assertEqual(holder.process.returncode, 73)
        self.assertIn(b"RCH_SOURCE_LOCK_SUPERVISOR_TERMINATED", stderr)
        self.assertTrue(available(lock), "externally killed monitor left its child holding locks")

    def test_session_does_not_require_waitid_or_wnowait(self):
        injected = self.root / "old-python-capabilities"
        env = self.session_python_environment(
            "for test_feature in ('waitid', 'WNOWAIT'):\n"
            "    if hasattr(os, test_feature):\n"
            "        delattr(os, test_feature)\n"
            "with open({!r}, 'w') as test_marker:\n"
            "    test_marker.write('unavailable\\n')".format(str(injected)))
        holder, lock, claim, receipt, release = self.session_fixture(idle=90, env=env)
        self.assertEqual(injected.read_text(), "unavailable\n")
        holder.send(release + "\n")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr),
                         (0, (release + "\n").encode(), b""))
        self.assertEqual(receipt.read_text(), release + "\n")
        self.assertEqual(claim.read_text(), "durable owner\n")
        self.assertTrue(available(lock))

    def test_session_inherited_ignored_and_blocked_sigchld_cannot_auto_reap_monitor(self):
        env = self.session_python_environment(
            "signal.signal(signal.SIGCHLD, signal.SIG_IGN)\n"
            "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})")
        holder, lock, claim, receipt, release = self.session_fixture(idle=90, env=env)
        holder.send(release + "\n")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr),
                         (0, (release + "\n").encode(), b""))
        self.assertEqual(receipt.read_text(), release + "\n")
        self.assertEqual(claim.read_text(), "durable owner\n")
        self.assertTrue(available(lock))

    def test_session_descendant_receives_child_exit_after_inherited_blocked_sigchld(self):
        env = self.session_python_environment(
            "signal.signal(signal.SIGCHLD, signal.SIG_IGN)\n"
            "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})")
        lock = self.root / "child-signal.lock"
        release = "RCH_SOURCE_AUTHORITY_RELEASE:abc-123"
        program = (
            "import os,signal,sys,time\n"
            "observed=[]\n"
            "signal.signal(signal.SIGCHLD,lambda *_: observed.append(True))\n"
            "child=os.fork()\n"
            "if child==0: os._exit(0)\n"
            "deadline=time.monotonic()+1\n"
            "while not observed and time.monotonic()<deadline: time.sleep(0.01)\n"
            "os.waitpid(child,0)\n"
            "if not observed: sys.exit('child completion signal remained blocked')\n"
            "print('READY',flush=True)\n"
            "request=sys.stdin.readline()\n"
            "if request!={!r}: sys.exit(9)\n"
            "print(request,end='',flush=True)\n"
        ).format(release + "\n")
        terminal = "exec " + shlex.join([sys.executable, "-I", "-S", "-c", program])
        holder = self.start([("x", lock)], terminal=terminal, session_idle=90, env=env)
        self.assertEqual(holder.line(), b"READY")
        self.assertFalse(available(lock))
        holder.send(release + "\n")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr),
                         (0, (release + "\n").encode(), b""))
        self.assertTrue(available(lock))

    def test_session_monitor_stopped_before_setsid_is_killed_without_admission(self):
        env = self.session_python_environment(
            "test_setsid = os.setsid\n"
            "def test_stop_before_setsid():\n"
            "    print('BEFORE_SETSID', os.getpid(), flush=True)\n"
            "    os.kill(os.getpid(), signal.SIGSTOP)\n"
            "    return test_setsid()\n"
            "os.setsid = test_stop_before_setsid")
        lock = self.root / "pre-session.lock"
        claim = self.root / "pre-session.claim"
        claim.write_text("prior durable ownership\n")
        publication = self.root / "unexpected-publication"
        terminal = "printf 'unexpected admission\\n' > {}".format(
            shlex.quote(str(publication)))
        holder = self.start([("x", lock)], terminal=terminal, session_idle=90, env=env)
        line = holder.line()
        self.assertIsNotNone(line)
        marker, monitor = line.split()
        self.assertEqual(marker, b"BEFORE_SETSID")
        try:
            holder.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            # Failure cleanup: the still-waiting observer has not reaped its
            # stopped direct child, so this fixture identity remains pinned.
            os.kill(int(monitor), signal.SIGKILL)
            raise
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (73, b""))
        self.assertIn(b"RCH_SOURCE_LOCK_SUPERVISOR_TERMINATED", stderr)
        self.assertEqual(claim.read_text(), "prior durable ownership\n")
        self.assertFalse(publication.exists())
        self.assertFalse(lock.exists(), "stopped pre-session monitor reached lock admission")
        with self.assertRaises(ProcessLookupError):
            os.kill(int(monitor), 0)

    def test_session_stopped_monitor_revokes_group_and_retains_durable_owner(self):
        lock = self.root / "stopped-monitor.lock"
        claim = self.root / "stopped-monitor.claim"
        terminal = ("printf 'durable owner\\n' > {}; printf '%s\\n' \"$1\"; "
                    "exec python3 -I -S -c {}").format(shlex.quote(str(claim)), shlex.quote(
                        "import os,signal,time; print(os.getppid(), flush=True); "
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(120)"))
        holder = self.start([("x", lock)], terminal=terminal, session_idle=90)
        self.assertEqual(holder.line(), b"READY")
        monitor = int(holder.line())
        self.assertFalse(available(lock))
        os.kill(monitor, signal.SIGSTOP)
        try:
            holder.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.kill(monitor, signal.SIGKILL)  # Still pinned by our live observer.
            raise
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (73, b""))
        self.assertIn(b"RCH_SOURCE_LOCK_SUPERVISOR_TERMINATED", stderr)
        self.assertEqual(claim.read_text(), "durable owner\n")
        self.assertTrue(available(lock), "stopped monitor stranded inherited source locks")

    def test_session_synthetic_sigchld_revokes_only_its_owned_group(self):
        other_lock = self.root / "unrelated.lock"
        other = self.start([("x", other_lock)])
        self.assertEqual(other.line(), b"READY")
        holder, lock, claim, receipt, _ = self.session_fixture(idle=90)
        os.kill(holder.process.pid, signal.SIGCHLD)
        holder.process.wait(timeout=3)
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (73, b""))
        self.assertIn(b"RCH_SOURCE_LOCK_SUPERVISOR_TERMINATED", stderr)
        self.assertEqual(claim.read_text(), "durable owner\n")
        self.assertFalse(receipt.exists())
        self.assertTrue(available(lock))
        self.assertIsNone(other.process.poll(), "notification killed an unrelated process")
        self.assertFalse(available(other_lock), "notification released an unrelated lock")

    def test_readiness_waits_for_the_complete_ordered_plan(self):
        first, last = self.root / "first", self.root / "last"
        fd = os.open(last, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            holder = self.start([("x", first), ("x", last)])
            self.assert_waiting(holder, [first, last], "holder never opened its ordered plan")
            self.assert_prefix_not_monopolized([first])
        finally:
            os.close(fd)
        self.assertEqual(holder.line(), b"READY")
        holder.finish()
        self.assertEqual(holder.process.returncode, 0)
        self.assertTrue(available(first) and available(last))

    def test_shared_ancestors_allow_siblings_but_exclude_parent_writers(self):
        parent, left, right = (self.root / name for name in ("parent", "left", "right"))
        a = self.start([("s", parent), ("x", left)])
        b = self.start([("s", parent), ("x", right)])
        self.assertEqual(a.line(), b"READY")
        self.assertEqual(b.line(), b"READY")
        self.assertTrue(available(parent, shared=True))
        self.assertFalse(available(parent))
        a.finish()
        self.assertTrue(available(left))
        self.assertFalse(available(parent))
        b.finish()
        self.assertTrue(available(parent) and available(right))

    @unittest.skipUnless(GNU_FLOCK, "GNU flock unavailable for mixed-backend test")
    def test_native_and_existing_gnu_holders_exclude_each_other(self):
        for portable in (False, True):
            path = self.root / str(portable)
            owner = self.start([("x", path)], portable=portable)
            self.assertEqual(owner.line(), b"READY")
            follower = self.start([("x", path)], portable=not portable)
            self.assertIsNone(follower.line(0.1))
            self.assertFalse(available(path))
            owner.finish()
            self.assertEqual(follower.line(), b"READY")
            follower.finish()
            self.assertTrue(available(path))

    def test_disconnect_releases_all_locks_without_a_terminal_program(self):
        paths = [self.root / str(i) for i in range(16)]
        holder = self.start([("x", path) for path in paths])
        self.assertEqual(holder.line(), b"READY")
        self.assertTrue(all(not available(path) for path in paths))
        holder.send("data must not be echoed as a release receipt\n")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
        self.assertTrue(all(available(path) for path in paths))

    def test_process_death_releases_inherited_locks(self):
        for sig in (signal.SIGKILL, signal.SIGHUP):
            path = self.root / str(sig)
            holder = self.start([("x", path)])
            self.assertEqual(holder.line(), b"READY")
            holder.process.send_signal(sig)
            holder.finish()
            self.assertNotEqual(holder.process.returncode, 0)
            self.assertTrue(available(path))

    def test_fd_exhaustion_fails_before_readiness_and_releases_partial_plan(self):
        paths = [self.root / str(i) for i in range(80)]
        holder = self.start([("x", path) for path in paths], fd_limit=32)
        stdout, stderr = holder.failure()
        self.assertEqual(holder.process.returncode, 73, stderr)
        self.assertEqual(stdout, b"")
        self.assertIn(b"native source lock acquisition failed", stderr)
        self.assertTrue(all(available(path) for path in paths))

    def test_invalid_plans_never_announce_readiness_or_leave_locks(self):
        path = self.root / "first"
        valid = "x {}\n".format(path)
        for plan, count in [(valid + "bad\n", 2), (valid, 2),
                            (valid + valid, 2), (valid + "s /extra\n", 1),
                            ("x relative\n", 1), ("x /bad\rpath\n", 1)]:
            holder = self.start([], plan=plan, count=count)
            stdout, stderr = holder.failure()
            self.assertEqual(holder.process.returncode, 73, (plan, stderr))
            self.assertEqual(stdout, b"", plan)
            self.assertTrue(available(path))

    def test_symlinks_and_nonregular_locks_are_refused_without_mutation(self):
        target = self.root / "target"
        target.write_bytes(b"do not truncate")
        link = self.root / "link"
        link.symlink_to(target)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo, self.root):
            holder = self.start([("x", path)])
            stdout, stderr = holder.failure()
            self.assertEqual(holder.process.returncode, 73, stderr)
            self.assertEqual(stdout, b"")
        self.assertEqual(target.read_bytes(), b"do not truncate")
        self.assertTrue(link.is_symlink())

    def test_path_bytes_are_literal_not_shell_programs(self):
        paths = [self.root / name for name in (
            "space name", "single'and\"double", "colon:path", "unicode-λ",
            "$(printf hacked)", "back\\slash", "trailing ",
        )]
        holder = self.start([("x", path) for path in paths])
        self.assertEqual(holder.line(), b"READY")
        self.assertTrue(all(not available(path) for path in paths))
        holder.finish()
        self.assertTrue(all(path.is_file() for path in paths))

    def test_zero_locks_keeps_the_existing_terminal_protocol(self):
        holder = self.start([], terminal='set -eu; [ "$(cat <&4)" = "claim input" ]; '
                            'printf "%s\\n" "$1"; IFS= read -r reply; [ "$reply" = RELEASE ]')
        self.assertEqual(holder.line(), b"READY")
        holder.send("RELEASE\n")
        holder.finish()
        self.assertEqual(holder.process.returncode, 0)

    def test_missing_darwin_prerequisite_is_explicit_and_grants_nothing(self):
        holder = self.start([("x", self.root / "absent")],
                            env=self.environment(python=False))
        stdout, stderr = holder.failure()
        self.assertEqual(holder.process.returncode, 73, stderr)
        self.assertIn(b"Darwin source locking requires python3", stderr)
        self.assertEqual(stdout, b"")
        self.assertFalse((self.root / "absent").exists())

    @unittest.skipUnless(GNU_FLOCK, "GNU flock unavailable")
    def test_linux_still_uses_gnu_without_python_and_probes_platform_once(self):
        paths = [self.root / str(i) for i in range(64)]
        holder = self.start([("x", path) for path in paths], portable=False,
                            env=self.environment(portable=False, python=False))
        self.assertEqual(holder.line(), b"READY")
        self.assertTrue(all(not available(path) for path in paths))
        holder.finish()
        self.assertEqual(holder.process.returncode, 0)
        self.assertEqual((self.root / "gnu-bin/uname.calls").read_text(), "called\n")

    def test_linux_large_plan_uses_native_locks_and_preserves_handoff(self):
        paths = [self.root / str(i) for i in range(96)]
        env = self.environment(portable=False, gnu_flock=False)
        terminal = ('set -eu; [ "$(cat <&4)" = "claim input" ]; exec 4<&-; '
                    'if (: <&3) 2>/dev/null; then exit 98; fi; '
                    'printf "%s\\n" "$1" "$$" "$2"; '
                    'IFS= read -r reply; [ "$reply" = RELEASE ]')
        specs = [("s" if i % 3 == 0 else "x", path) for i, path in enumerate(paths)]
        holder = self.start(specs, portable=False, env=env, terminal=terminal,
                            args=("literal $value; 'quotes'",))
        self.assertEqual(holder.line(), b"READY")
        self.assertEqual(int(holder.line()), holder.process.pid)
        self.assertEqual(holder.line(), b"literal $value; 'quotes'")
        for mode, path in specs:
            self.assertFalse(available(path))
            self.assertEqual(available(path, shared=True), mode == "s")
        holder.send("RELEASE\n")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
        self.assertTrue(all(available(path) for path in paths))
        self.assertEqual((self.root / "linux-native-bin/uname.calls").read_text(), "called\n")

    @unittest.skipUnless(GNU_FLOCK, "GNU flock unavailable")
    def test_linux_native_and_no_python_holders_share_kernel_exclusion(self):
        paths = [self.root / str(i) for i in range(64)]
        specs = [("x", path) for path in paths]
        envs = [self.environment(portable=False, python=False),
                self.environment(portable=False, gnu_flock=False)]
        for first, second in (envs, envs[::-1]):
            owner = self.start(specs, portable=False, env=first)
            self.assertEqual(owner.line(), b"READY")
            follower = self.start(specs, portable=False, env=second)
            self.assertIsNone(follower.line(0.1))
            self.assertTrue(all(not available(path) for path in paths))
            owner.finish()
            self.assertEqual(follower.line(), b"READY")
            follower.finish()
            self.assertTrue(all(available(path) for path in paths))

    @unittest.skipUnless(GNU_FLOCK, "GNU flock unavailable")
    def test_linux_small_plan_avoids_python_and_native_failure_never_falls_back(self):
        directory = self.root / "broken-python"
        directory.mkdir()
        python = directory / "python3"
        python.write_text("#!/bin/sh\nprintf 'native bootstrap failed\\n' >&2\nexit 97\n")
        python.chmod(0o700)
        env = self.environment(portable=False, python=False)
        env["PATH"] = str(directory) + os.pathsep + env["PATH"]
        small = [self.root / ("small-{}".format(i)) for i in range(31)]
        holder = self.start([("x", path) for path in small], portable=False, env=env)
        self.assertEqual(holder.line(), b"READY")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
        large = [self.root / ("large-{}".format(i)) for i in range(32)]
        holder = self.start([("x", path) for path in large], portable=False, env=env)
        stdout, stderr = holder.failure()
        self.assertEqual((holder.process.returncode, stdout), (97, b""))
        self.assertIn(b"native bootstrap failed", stderr)
        self.assertTrue(all(not path.exists() for path in large))

    def test_linux_native_waits_for_last_lock_and_dies_without_orphans(self):
        paths = [self.root / str(i) for i in range(32)]
        env = self.environment(portable=False, gnu_flock=False)
        fd = os.open(paths[-1], os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            holder = self.start([("x", path) for path in paths], portable=False, env=env)
            self.assert_waiting(holder, paths, "native holder did not open its plan")
            self.assert_prefix_not_monopolized(paths[:-1])
            holder.process.kill()
            stdout, stderr = holder.finish()
            self.assertEqual(stdout, b"", stderr)
            self.assertEqual(holder.process.returncode, -signal.SIGKILL)
            self.assertTrue(all(available(path) for path in paths[:-1]))
            self.assertFalse(available(paths[-1]))
        finally:
            os.close(fd)
        follower = self.start([("x", path) for path in paths], portable=False, env=env)
        self.assertEqual(follower.line(), b"READY")
        follower.finish()
        self.assertTrue(all(available(path) for path in paths))

    def test_linux_native_invalid_plan_and_fd_exhaustion_release_partial_locks(self):
        paths = [self.root / str(i) for i in range(64)]
        specs = [("x", path) for path in paths]
        env = self.environment(portable=False, gnu_flock=False)
        for options in ({"fd_limit": 32},
                        {"plan": "".join("x {}\n".format(path) for path in paths[:-1])},
                        {"plan": "".join("x {}\n".format(path) for path in paths) + "s /extra\n"}):
            holder = self.start(specs, portable=False, env=env, **options)
            stdout, stderr = holder.failure()
            self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
            self.assertNotIn(b"requester ended", stderr)
            self.assertTrue(all(available(path) for path in paths))

    def test_linux_native_refuses_symlink_and_fifo_after_partial_acquisition(self):
        paths = [self.root / str(i) for i in range(31)]
        target = self.root / "target"
        target.write_bytes(b"unchanged")
        link = self.root / "link"
        link.symlink_to(target)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        env = self.environment(portable=False, gnu_flock=False)
        for invalid in (link, fifo, self.root):
            holder = self.start([("x", path) for path in paths + [invalid]],
                                portable=False, env=env)
            stdout, stderr = holder.failure()
            self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
            self.assertNotIn(b"requester ended", stderr)
            self.assertTrue(all(available(path) for path in paths))
            self.assertEqual(target.read_bytes(), b"unchanged")
            self.assertTrue(link.is_symlink())


    def terminal_witness(self, witness):
        return ('set -eu; printf entered > {}; '
                'printf "%s\\n" "$1"; exec cat >/dev/null').format(shlex.quote(str(witness)))

    def assert_requester_refused(self, holder, stdout, stderr):
        self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"source lock requester ended or sent input before readiness", stderr)

    def test_native_disconnected_waiter_releases_partial_plan_without_terminal(self):
        for portable in (False, True):
            paths = [self.root / ("{}-{}".format(portable, i)) for i in range(32)]
            paths[-1].write_bytes(b"other owner lock evidence")
            witness = self.root / ("terminal-" + str(portable))
            fd = os.open(paths[-1], os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                holder = self.start([("x", path) for path in paths], portable=portable,
                                    env=self.environment(portable, gnu_flock=False),
                                    terminal=self.terminal_witness(witness))
                self.assert_waiting(holder, paths, "waiter did not open its plan")
                stdout, stderr = holder.finish()  # Requester EOF, NO signal.
                self.assert_requester_refused(holder, stdout, stderr)
                self.assertFalse(witness.exists(), "abandoned acquisition ran the terminal protocol")
                self.assertTrue(all(available(path) for path in paths[:-1]))
                self.assertFalse(available(paths[-1]), "another owner's lock must remain held")
                self.assertEqual(paths[-1].read_bytes(), b"other owner lock evidence")
            finally:
                os.close(fd)
            # No orphaned partial holder may prevent the next real acquisition.
            follower = self.start([("x", path) for path in paths], portable=portable,
                                  env=self.environment(portable, gnu_flock=False))
            self.assertEqual(follower.line(), b"READY")
            follower.finish()
            self.assertEqual(follower.process.returncode, 0)
            self.assertTrue(all(available(path) for path in paths))

    def test_native_initial_eof_creates_no_lock_or_terminal_state(self):
        for portable in (False, True):
            paths = [self.root / ("{}-{}".format(portable, i)) for i in range(32)]
            witness = self.root / ("terminal-" + str(portable))
            holder = self.start([("x", path) for path in paths], portable=portable,
                                env=self.environment(portable, gnu_flock=False),
                                terminal=self.terminal_witness(witness), closed_stdin=True)
            stdout, stderr = holder.failure()
            self.assert_requester_refused(holder, stdout, stderr)
            self.assertFalse(witness.exists())
            self.assertTrue(all(not path.exists() for path in paths))

    def test_native_early_input_refuses_without_consuming_a_terminal_release(self):
        for portable in (False, True):
            paths = [self.root / ("{}-{}".format(portable, i)) for i in range(32)]
            witness = self.root / ("terminal-" + str(portable))
            fd = os.open(paths[-1], os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                holder = self.start([("x", path) for path in paths], portable=portable,
                                    env=self.environment(portable, gnu_flock=False),
                                    terminal=self.terminal_witness(witness))
                self.assert_waiting(holder, paths, "waiter did not open its plan")
                holder.send("RELEASE\n")
                stdout, stderr = holder.failure()  # Stdin stays OPEN until refusal.
                self.assert_requester_refused(holder, stdout, stderr)
                self.assertFalse(witness.exists())
                self.assertTrue(all(available(path) for path in paths[:-1]))
                self.assertFalse(available(paths[-1]))
            finally:
                os.close(fd)

    def test_native_eof_cancels_waiter_even_when_sighup_is_ignored(self):
        paths = [self.root / str(i) for i in range(32)]
        witness = self.root / "terminal"
        fd = os.open(paths[-1], os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            holder = self.start([("x", path) for path in paths], portable=False,
                                env=self.environment(portable=False, gnu_flock=False),
                                terminal=self.terminal_witness(witness), ignore_hup=True)
            self.assert_waiting(holder, paths, "waiter did not open its plan")
            holder.process.send_signal(signal.SIGHUP)
            self.assertIsNone(holder.line(0.05))
            self.assertIsNone(holder.process.poll(), "fixture did not inherit ignored SIGHUP")
            stdout, stderr = holder.finish()
            self.assert_requester_refused(holder, stdout, stderr)
            self.assertFalse(witness.exists())
            self.assertTrue(all(available(path) for path in paths[:-1]))
            self.assertFalse(available(paths[-1]))
        finally:
            os.close(fd)

    def test_native_replaced_earlier_path_cannot_handoff_a_lock_on_an_old_inode(self):
        for portable in (False, True):
            with self.subTest(portable=portable):
                paths = [self.root / f"native-replaced-{portable}-{i}" for i in range(32)]
                old = self.root / f"retained-old-{portable}"
                witness = self.root / f"terminal-replaced-{portable}"
                paths[0].write_bytes(b"original lock evidence")
                final = os.open(paths[-1], os.O_CREAT | os.O_RDWR, 0o600)
                replacement = None
                try:
                    fcntl.flock(final, fcntl.LOCK_EX)
                    holder = self.start([("x", path) for path in paths], portable=portable,
                                        env=self.environment(portable, gnu_flock=False),
                                        terminal=self.terminal_witness(witness))
                    self.assert_waiting(holder, paths, "native waiter did not open its plan")
                    # Keep the old inode and its bytes under a second name, then
                    # swap the pathname atomically: it is never even briefly
                    # absent, so the refusal must be the identity check.
                    os.link(paths[0], old)
                    staged = self.root / f"staged-replacement-{portable}"
                    staged.write_bytes(b"another owner's replacement")
                    os.replace(staged, paths[0])
                    replacement = os.open(paths[0], os.O_RDWR)
                    fcntl.flock(replacement, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(final, fcntl.LOCK_UN)
                    self.assertIsNone(holder.line(), "native holder granted ownership on a replaced inode")
                    stdout, stderr = holder.failure()
                    self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
                    self.assertIn(b"path changed during acquisition", stderr)
                    self.assertNotIn(b"requester ended", stderr)
                    self.assertFalse(witness.exists())
                    self.assertTrue(available(old))
                    self.assertTrue(all(available(path) for path in paths[1:]))
                    self.assertFalse(available(paths[0]), "refusal released another owner's lock")
                    self.assertEqual(old.read_bytes(), b"original lock evidence")
                    self.assertEqual(paths[0].read_bytes(), b"another owner's replacement")
                finally:
                    if replacement is not None:
                        os.close(replacement)
                    os.close(final)

    def test_native_missing_or_symlinked_earlier_path_cannot_reach_terminal(self):
        for portable in (False, True):
            for change in ("missing", "symlink"):
                with self.subTest(portable=portable, change=change):
                    paths = [self.root / f"native-{portable}-{change}-{i}" for i in range(32)]
                    old = self.root / f"retained-{portable}-{change}"
                    witness = self.root / f"terminal-{portable}-{change}"
                    final = os.open(paths[-1], os.O_CREAT | os.O_RDWR, 0o600)
                    try:
                        fcntl.flock(final, fcntl.LOCK_EX)
                        holder = self.start([("x", path) for path in paths], portable=portable,
                                            env=self.environment(portable, gnu_flock=False),
                                            terminal=self.terminal_witness(witness))
                        self.assert_waiting(holder, paths, "native waiter did not open its plan")
                        paths[0].rename(old)
                        if change == "symlink":
                            # Even a link resolving to the SAME held inode is not
                            # the real, regular lock pathname that was acquired.
                            paths[0].symlink_to(old)
                        fcntl.flock(final, fcntl.LOCK_UN)
                        self.assertIsNone(holder.line(), "native holder accepted a missing/symlinked root")
                        stdout, stderr = holder.failure()
                        self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
                        self.assertIn(b"native source lock acquisition failed", stderr)
                        self.assertNotIn(b"requester ended", stderr)
                        self.assertFalse(witness.exists())
                        self.assertTrue(available(old))
                        self.assertTrue(all(available(path) for path in paths[1:]))
                        if change == "symlink":
                            self.assertTrue(paths[0].is_symlink())
                        else:
                            self.assertFalse(paths[0].exists(), "refusal recreated an absent lock pathname")
                    finally:
                        os.close(final)

    def test_native_hardlink_aliases_refuse_instead_of_self_deadlocking_or_granting(self):
        for portable in (False, True):
            for first_mode, second_mode in (("x", "x"), ("s", "x"), ("x", "s"), ("s", "s")):
                with self.subTest(portable=portable, modes=(first_mode, second_mode)):
                    tag = f"{portable}-{first_mode}-{second_mode}"
                    paths = [self.root / f"native-alias-{tag}-{i}" for i in range(32)]
                    paths[0].write_bytes(b"one inode, two names")
                    os.link(paths[0], paths[1])
                    witness = self.root / f"terminal-alias-{tag}"
                    specs = [(first_mode, paths[0]), (second_mode, paths[1])]
                    specs.extend(("x", path) for path in paths[2:])
                    holder = self.start(specs, portable=portable,
                                        env=self.environment(portable, gnu_flock=False),
                                        terminal=self.terminal_witness(witness))
                    self.assertIsNone(holder.line(0.5), "aliased locks granted source authority")
                    # Leave stdin OPEN: an eventual disconnect must not hide
                    # a self-deadlock against another descriptor in this plan.
                    holder.process.wait(timeout=1)
                    stdout, stderr = holder.failure()
                    self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
                    self.assertIn(b"duplicate source lock inode", stderr)
                    self.assertNotIn(b"requester ended", stderr)
                    self.assertFalse(witness.exists())
                    self.assertTrue(available(paths[0]) and available(paths[1]))
                    self.assertTrue(all(not path.exists() for path in paths[2:]))
                    self.assertEqual(paths[0].read_bytes(), b"one inode, two names")
                    self.assertTrue(os.path.samefile(paths[0], paths[1]))

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_disconnected_waiters_release_small_and_no_python_large_plans(self):
        env = self.environment(portable=False, python=False)
        for count, ignore_hup in [(2, False), (2, True), (64, False), (64, True)]:
            paths = [self.root / f"gnu-{count}-{ignore_hup}-{i}" for i in range(count)]
            paths[-1].write_bytes(b"another owner's lock evidence")
            witness = self.root / f"terminal-{count}-{ignore_hup}"
            fd = os.open(paths[-1], os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                holder = self.start([("x", path) for path in paths], env=env,
                                    terminal=self.terminal_witness(witness), ignore_hup=ignore_hup)
                self.assert_waiting(holder, paths, "GNU waiter did not open its plan")
                if ignore_hup:
                    holder.process.send_signal(signal.SIGHUP)
                self.assertIsNone(holder.line(0.05))
                self.assertIsNone(holder.process.poll())
                stdout, stderr = holder.finish()  # Disconnect without signalling.
                self.assert_requester_refused(holder, stdout, stderr)
                self.assertFalse(witness.exists())
                self.assertTrue(all(available(path) for path in paths[:-1]))
                self.assertFalse(available(paths[-1]))
                self.assertEqual(paths[-1].read_bytes(), b"another owner's lock evidence")
            finally:
                os.close(fd)
            follower = self.start([("x", path) for path in paths], env=env)
            self.assertEqual(follower.line(), b"READY")
            stdout, stderr = follower.finish()
            self.assertEqual((follower.process.returncode, stdout, stderr), (0, b"", b""))
            self.assertTrue(all(available(path) for path in paths))

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_initial_eof_and_early_input_grant_no_authority(self):
        env = self.environment(portable=False, python=False)
        witness = self.root / "terminal"
        path = self.root / "absent"
        holder = self.start([("x", path)], env=env, closed_stdin=True,
                            terminal=self.terminal_witness(witness))
        stdout, stderr = holder.failure()
        self.assert_requester_refused(holder, stdout, stderr)
        self.assertFalse(path.exists())
        for index, early in enumerate(("RELEASE\n", "\0", "partial")):
            first, last = self.root / f"first-{index}", self.root / f"last-{index}"
            fd = os.open(last, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                holder = self.start([("x", first), ("x", last)], env=env,
                                    terminal=self.terminal_witness(witness))
                self.assert_waiting(holder, [first, last], "GNU waiter did not open its plan")
                holder.send(early)
                stdout, stderr = holder.failure()
                self.assert_requester_refused(holder, stdout, stderr)
                self.assertTrue(available(first))
                self.assertFalse(available(last))
                self.assertFalse(witness.exists())
            finally:
                os.close(fd)

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_descriptor_handoff_preserves_claim_stdin_pid_modes_and_literal_paths(self):
        names = ["space name", "single'and\"double", "$(printf hacked)", "[x]*?",
                 "back\\slash", "unicode-λ", "trailing ", "a];echo hacked", "byte-" + chr(0xdcff)]
        paths = [self.root / name for name in names] + [self.root / f"root-{i}" for i in range(80)]
        specs = [("s" if i % 3 == 0 else "x", path) for i, path in enumerate(paths)]
        terminal = ('set -eu; [ "$(cat <&4)" = "claim input" ]; exec 4<&-; '
                    'if (: <&3) 2>/dev/null; then exit 98; fi; '
                    '[ "${LC_ALL-unset}" = unset ]; '
                    'printf "%s\\n" "$1" "$$" "$2"; '
                    'IFS= read -r reply; [ "$reply" = RELEASE ]; printf "RELEASED\\n"')
        env = self.environment(portable=False, python=False)
        env.pop("LC_ALL")
        holder = self.start(specs, env=env, terminal=terminal, args=("literal $value; 'quotes'",))
        self.assertEqual(holder.line(), b"READY")
        self.assertEqual(int(holder.line()), holder.process.pid)
        self.assertEqual(holder.line(), b"literal $value; 'quotes'")
        for mode, path in specs:
            self.assertFalse(available(path))
            self.assertEqual(available(path, shared=True), mode == "s")
        holder.send("RELEASE\n")
        self.assertEqual(holder.line(), b"RELEASED")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
        self.assertTrue(all(available(path) for path in paths))
        self.assertEqual((self.root / "gnu-bin/uname.calls").read_text(), "called\n")

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_native_and_legacy_backends_share_the_same_kernel_locks(self):
        envs = [self.environment(portable=False, python=False),
                self.environment(portable=False, python=False, bash=False),
                self.environment(portable=True)]
        paths = [self.root / str(i) for i in range(3)]
        specs = [("s", paths[0]), ("x", paths[1]), ("x", paths[2])]
        for i, first in enumerate(envs):
            for j, second in enumerate(envs):
                if i == j:
                    continue
                owner = self.start(specs, env=first)
                self.assertEqual(owner.line(), b"READY")
                follower = self.start(specs, env=second)
                self.assertIsNone(follower.line(0.1))
                owner.finish()
                self.assertEqual(follower.line(), b"READY")
                self.assertTrue(available(paths[0], shared=True))
                self.assertTrue(all(not available(path) for path in paths))
                follower.finish()
                self.assertTrue(all(available(path) for path in paths))

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_bad_plans_fail_with_a_live_requester_before_any_terminal(self):
        env = self.environment(portable=False, python=False)
        path = self.root / "first"
        valid = f"x {path}\n".encode()
        witness = self.root / "terminal"
        for index, (content, count) in enumerate([
            (valid, 2), (valid + valid, 2), (valid + b"s /extra\n", 1),
            (valid[:-1], 1), (valid + b"x /bad\0path\n", 2),
            (valid + b"s /bad\rpath\n", 2), (b"x relative\n", 1),
            (valid + b"invalid\n", 2), (b"x /" + b"x" * 1048576 + b"\n", 1),
        ]):
            plan = self.root / f"invalid-plan-{index}"
            plan.write_bytes(content)
            holder = self.start([], env=env, plan=plan, count=count,
                                terminal=self.terminal_witness(witness))
            stdout, stderr = holder.failure()
            self.assertEqual((holder.process.returncode, stdout), (73, b""), (index, stderr))
            self.assertIn(b"GNU source lock acquisition failed", stderr)
            self.assertNotIn(b"requester ended", stderr)
            self.assertTrue(available(path))
            self.assertFalse(witness.exists())

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_partial_acquisition_refuses_nonregular_files_and_fd_exhaustion(self):
        env = self.environment(portable=False, python=False)
        paths = [self.root / f"root-{i}" for i in range(64)]
        holder = self.start([("x", path) for path in paths], env=env, fd_limit=32)
        stdout, stderr = holder.failure()
        self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
        self.assertNotIn(b"requester ended", stderr)
        self.assertTrue(all(available(path) for path in paths))
        target, link, fifo = self.root / "target", self.root / "link", self.root / "fifo"
        target.write_bytes(b"do not truncate or lock via symlink")
        link.symlink_to(target)
        os.mkfifo(fifo)
        for invalid in (link, fifo, self.root):
            holder = self.start([("x", paths[0]), ("x", invalid)], env=env)
            stdout, stderr = holder.failure()
            self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
            self.assertIn(b"not a regular file", stderr)
            self.assertTrue(available(paths[0]))
            self.assertEqual(target.read_bytes(), b"do not truncate or lock via symlink")
            self.assertTrue(link.is_symlink())

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_replaced_earlier_inode_is_rejected_before_any_grant(self):
        env = self.environment(portable=False, python=False)
        first, last, old = (self.root / name for name in ("first", "last", "old-first"))
        witness = self.root / "terminal"
        fd = os.open(last, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            holder = self.start([("x", first), ("x", last)], env=env,
                                terminal=self.terminal_witness(witness))
            self.assert_waiting(holder, [first, last], "GNU waiter did not open its plan")
            # Retain the old inode under a second name and swap the pathname
            # atomically; nothing is deleted and the name is never absent.
            os.link(first, old)
            staged = self.root / "staged-first"
            staged.write_bytes(b"replacement lock evidence")
            os.replace(staged, first)
            fcntl.flock(fd, fcntl.LOCK_UN)
            stdout, stderr = holder.failure()
            self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
            self.assertIn(b"path changed during acquisition", stderr)
            self.assertFalse(witness.exists())
            self.assertTrue(available(old) and available(first) and available(last))
            self.assertEqual(first.read_bytes(), b"replacement lock evidence")
        finally:
            os.close(fd)

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_tool_error_is_not_contention_and_never_retries_or_falls_back(self):
        env = self.environment(portable=False, python=False)
        directory = self.root / "broken-flock"
        directory.mkdir()
        counter = self.root / "flock-called"
        tool = directory / "flock"
        tool.write_text("#!/bin/sh\nif [ -e {0} ]; then echo tool-failure >&2; exit 97; fi\n"
                        "printf called > {0}\nexec {1} \"$@\"\n".format(
                            shlex.quote(str(counter)), shlex.quote(FLOCK)))
        tool.chmod(0o700)
        env["PATH"] = str(directory) + os.pathsep + env["PATH"]
        paths = [self.root / str(i) for i in range(3)]
        witness = self.root / "terminal"
        holder = self.start([("x", path) for path in paths], env=env,
                            terminal=self.terminal_witness(witness))
        stdout, stderr = holder.failure()
        self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
        self.assertEqual(stderr.count(b"tool-failure"), 1)
        self.assertIn(b"flock failed without a contention verdict", stderr)
        # The whole plan is opened before any lock is taken; the refusal
        # leaves none of it locked.
        self.assertTrue(all(available(path) for path in paths))
        self.assertFalse(witness.exists())

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_bootstrap_ignores_imported_startup_code_and_functions(self):
        env = self.environment(portable=False, python=False)
        marker = self.root / "unwanted-startup"
        startup = self.root / "bash-env"
        startup.write_text(f"printf bad > {shlex.quote(str(marker))}\nexit 97\n")
        env.update({"BASH_ENV": str(startup), "SHELLOPTS": "verbose",
                    "BASH_FUNC_flock%%": "() { printf bad; return 0; }"})
        path = self.root / "locked"
        holder = self.start([("x", path)], env=env)
        self.assertEqual(holder.line(), b"READY")
        self.assertFalse(available(path), "an imported function fabricated successful flock")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr), (0, b"", b""))
        self.assertFalse(marker.exists())
        self.assertTrue(available(path))

    @unittest.skipUnless(GNU_CANCELLABLE, "GNU flock and Bash 4.1+ are required")
    def test_gnu_holder_death_releases_only_its_locks(self):
        env = self.environment(portable=False, python=False)
        paths = [self.root / str(i) for i in range(16)]
        for sig in (signal.SIGHUP, signal.SIGKILL):
            holder = self.start([("x", path) for path in paths], env=env)
            self.assertEqual(holder.line(), b"READY")
            holder.process.send_signal(sig)
            holder.finish()
            self.assertEqual(holder.process.returncode, -sig)
            self.assertTrue(all(available(path) for path in paths))


if __name__ == "__main__":
    unittest.main(verbosity=2)
