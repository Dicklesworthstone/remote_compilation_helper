#!/usr/bin/env python3
"""Exercise the production holder with real kernel locks and owned processes.

Run directly, or through rch/tests/source_lock_holder.rs. On Linux, the Darwin
bootstrap is selected with a test-owned uname, but the locks are Linux locks:
this does not substitute for running this suite on Darwin. Nothing contacts a
worker or changes a real RCH registry. Fixtures are retained for inspection.
"""
import errno
import fcntl
import os
from pathlib import Path
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[2]
HOLDER = (REPO / "rch/src/hook/source_lock_holder.sh").read_text()
FLOCK = shutil.which("flock")
GNU_FLOCK = bool(FLOCK and b"--no-fork" in subprocess.run(
    [FLOCK, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    timeout=5, check=False,
).stdout)


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


class Holder:
    def __init__(self, script, args, env, plan, claim="claim input", fd_limit=None):
        command = "set -eu\n"
        if fd_limit:
            command += "ulimit -n {}\n".format(fd_limit)
        # This is the production transport contract: plan on fd 3, claim on
        # fd 4, release input on stdin, script as both -c program and argv[0].
        command += "exec 3<<'RCH_TEST_PLAN'\n{}RCH_TEST_PLAN\n".format(plan)
        command += "exec 4<<'RCH_TEST_CLAIM'\n{}\nRCH_TEST_CLAIM\n".format(claim)
        command += "exec sh -c {} {} {}".format(
            shlex.quote(script), shlex.quote(script), shlex.join(args))
        self.process = subprocess.Popen(
            ["/bin/sh", "-c", command], env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
            self.process.stdin.close()
            self.process.stdin = None
        return self.process.communicate(timeout=5)

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

    def environment(self, portable=True, python=True):
        directory = self.root / ("native-bin" if portable else "gnu-bin")
        directory.mkdir(exist_ok=True)
        uname = directory / "uname"
        uname.write_text("#!/bin/sh\nprintf 'called\\n' >> {}\nprintf '%s\\n' {}\n".format(
            shlex.quote(str(directory / "uname.calls")), "Darwin" if portable else "Linux"))
        uname.chmod(0o700)
        for name, target in [("sh", "/bin/sh"), ("cat", shutil.which("cat"))]:
            path = directory / name
            if not path.exists():
                path.symlink_to(target)
        if python:
            path = directory / "python3"
            if not path.exists():
                path.symlink_to(sys.executable)
        if portable:
            # A successful test must never invoke GNU flock on this path.
            flock = directory / "flock"
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

    def test_readiness_waits_for_the_complete_ordered_plan(self):
        first, last = self.root / "first", self.root / "last"
        fd = os.open(last, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            holder = self.start([("x", first), ("x", last)])
            eventually(lambda: not available(first), "holder never acquired first ordered lock")
            self.assertIsNone(holder.line(0.05), "readiness preceded final lock acquisition")
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
        stdout, stderr = holder.finish()
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
            stdout, stderr = holder.finish()
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
            stdout, stderr = holder.finish()
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
        stdout, stderr = holder.finish()
        self.assertEqual(holder.process.returncode, 73, stderr)
        self.assertIn(b"Darwin source locking requires python3", stderr)
        self.assertEqual(stdout, b"")
        self.assertFalse((self.root / "absent").exists())

    @unittest.skipUnless(GNU_FLOCK, "GNU flock unavailable")
    def test_linux_still_uses_gnu_without_python_and_probes_platform_once(self):
        paths = [self.root / str(i) for i in range(16)]
        holder = self.start([("x", path) for path in paths], portable=False,
                            env=self.environment(portable=False, python=False))
        self.assertEqual(holder.line(), b"READY")
        self.assertTrue(all(not available(path) for path in paths))
        holder.finish()
        self.assertEqual(holder.process.returncode, 0)
        self.assertEqual((self.root / "gnu-bin/uname.calls").read_text(), "called\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
