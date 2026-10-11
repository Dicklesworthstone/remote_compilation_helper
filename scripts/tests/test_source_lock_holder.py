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
                 closed_stdin=False, ignore_hup=False):
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
            self.process.stdin.close()
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
            eventually(lambda: not available(paths[-2]), "native holder did not reach final lock")
            self.assertIsNone(holder.line(0.05), "native readiness preceded final lock")
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
                eventually(lambda: not available(paths[-2]), "waiter did not reach final lock")
                self.assertIsNone(holder.line(0.05))
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
                eventually(lambda: not available(paths[-2]), "waiter did not reach final lock")
                self.assertIsNone(holder.line(0.05))
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
            eventually(lambda: not available(paths[-2]), "waiter did not reach final lock")
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
                    eventually(lambda: not available(paths[-2]), "native waiter did not reach last root")
                    self.assertIsNone(holder.line(0.05))
                    paths[0].rename(old)  # Keep the old locked inode and its bytes.
                    paths[0].write_bytes(b"another owner's replacement")
                    replacement = os.open(paths[0], os.O_RDWR)
                    fcntl.flock(replacement, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.assertFalse(available(old))
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
                        eventually(lambda: not available(paths[-2]), "native waiter did not reach last root")
                        self.assertIsNone(holder.line(0.05))
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
                eventually(lambda: not available(paths[-2]), "GNU waiter did not reach final root")
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
                eventually(lambda: not available(first), "GNU waiter did not acquire first root")
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
    def test_gnu_replaced_earlier_inode_is_rejected_after_the_final_wait(self):
        env = self.environment(portable=False, python=False)
        first, last, old = (self.root / name for name in ("first", "last", "old-first"))
        witness = self.root / "terminal"
        fd = os.open(last, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            holder = self.start([("x", first), ("x", last)], env=env,
                                terminal=self.terminal_witness(witness))
            eventually(lambda: not available(first), "GNU waiter did not acquire first root")
            self.assertIsNone(holder.line(0.05))
            first.rename(old)  # Retain the old inode; nothing is deleted.
            first.write_bytes(b"replacement lock evidence")
            self.assertFalse(available(old))
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
        self.assertTrue(all(available(path) for path in paths[:2]))
        self.assertFalse(paths[2].exists())
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
