#!/usr/bin/env python3
"""Qualify source ownership over real, isolated loopback OpenSSH on Linux.

This runs the exact production holder, release waiter, registry transaction
and namespace controller. It uses fixture-owned host/client keys, strict host
verification and a server listening only on 127.0.0.1. Heartbeat fault tests
select a two-second worker lease through the production session argument;
they do not alter the production protocol or kernel-lock implementation.

Run directly as a user permitted to start sshd (normally root on Linux).
Fixtures and logs are retained. This is local SSH qualification, not fleet,
native Darwin, Windows or compiled-Rust end-to-end acceptance.
"""
import contextlib
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import pwd
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

REPO = Path(__file__).resolve().parents[2]
HOLDER = (REPO / "rch/src/hook/source_lock_holder.sh").read_text()
CONTROL = (REPO / "rch/src/hook/source_namespace_control.sh").read_text()
SSH_SOURCE = (REPO / "rch/src/hook/ssh.rs").read_text()
WAITER = SSH_SOURCE.split('const SOURCE_AUTHORITY_RELEASE_WAITER: &str = r#"', 1)[1].split('"#;', 1)[0]
HELPERS_SOURCE = (REPO / "rch-common/src/stale_target_reap.rs").read_text()
HELPERS = HELPERS_SOURCE.split('pub const SOURCE_CLAIM_RECORD_HELPERS: &str = r#"', 1)[1].split('"#;', 1)[0]
TRANSACTION = HELPERS + "\n" + (REPO / "rch/src/hook/source_claim_registry.sh").read_text()
SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").exists() else None)
SSH = shutil.which("ssh")
KEYGEN = shutil.which("ssh-keygen")
FLOCK = shutil.which("flock")
QUOTE = shlex.quote


def available(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise
    finally:
        os.close(fd)


def eventually(predicate, description, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(description)


class SshProcess:
    def __init__(self, argv, command):
        self.process = subprocess.Popen(
            [*argv, command], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.buffer = b""
        self.stopped = False

    def send(self, data):
        self.process.stdin.write(data.encode() if isinstance(data, str) else data)
        self.process.stdin.flush()

    def line(self, seconds=5):
        deadline = time.monotonic() + seconds
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                return None
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                return None
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line

    def close_input(self):
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass
            finally:
                self.process.stdin = None

    def finish(self, seconds=6):
        self.close_input()
        stdout, stderr = self.process.communicate(timeout=seconds)
        output = self.buffer + stdout
        self.buffer = b""
        return output, stderr

    def close(self):
        # Popen retains this exact unreaped child; no process-table search or
        # remembered remote PID authorizes termination here.
        if self.stopped and self.process.poll() is None:
            self.process.send_signal(signal.SIGCONT)
            self.stopped = False
        self.close_input()
        try:
            self.process.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate(timeout=6)


@unittest.skipUnless(sys.platform.startswith("linux") and SSHD and SSH and KEYGEN and FLOCK,
                     "requires native Linux OpenSSH server/client and flock")
class SourceOwnershipSshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # StrictModes also validates every authorized-key ancestor. A shared
        # workspace/TMPDIR may be writable by others; use sshd's private root
        # runtime directory, or an explicitly supplied equally trusted path.
        server_parent = Path(os.environ.get("RCH_SSH_TEST_SERVER_DIR", "/run/sshd"))
        if not server_parent.is_dir() or not os.access(server_parent, os.W_OK):
            raise unittest.SkipTest("a writable private sshd runtime directory is required")
        cls.server_root = Path(tempfile.mkdtemp(prefix="rch-loopback-", dir=server_parent))
        cls.username = pwd.getpwuid(os.getuid()).pw_name
        for name in ("host", "client"):
            subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f",
                            str(cls.server_root / name)], check=True, timeout=10)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        cls.port = port
        (cls.server_root / "known_hosts").write_text(
            "[127.0.0.1]:{} {}\n".format(
                port, " ".join((cls.server_root / "host.pub").read_text().split()[:2])))
        config = cls.server_root / "sshd_config"
        config.write_text(
            "ListenAddress 127.0.0.1\nPort {}\nHostKey {}\nPidFile {}\n"
            "AuthorizedKeysFile {}\nAuthenticationMethods publickey\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "UsePAM no\nPermitRootLogin prohibit-password\nStrictModes yes\n"
            "AllowUsers {}\nLogLevel VERBOSE\nPrintMotd no\nPrintLastLog no\n"
            "X11Forwarding no\nAllowTcpForwarding no\nPermitTunnel no\n"
            "PermitUserEnvironment no\nClientAliveInterval 0\n".format(
                port, cls.server_root / "host", cls.server_root / "sshd.pid",
                cls.server_root / "client.pub", cls.username))
        cls.server_log = (cls.server_root / "sshd.log").open("ab")
        cls.server = subprocess.Popen([SSHD, "-D", "-e", "-f", str(config)],
                                      stdin=subprocess.DEVNULL, stdout=cls.server_log,
                                      stderr=cls.server_log)
        cls.addClassCleanup(cls.stop_server)
        cls.argv = [SSH, "-F", "/dev/null", "-T", "-p", str(port),
                    "-i", str(cls.server_root / "client"),
                    "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                    "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", "UserKnownHostsFile=" + str(cls.server_root / "known_hosts"),
                    "-o", "GlobalKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                    "-o", "ControlMaster=no", "-o", "ControlPath=none",
                    "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=0",
                    cls.username + "@127.0.0.1"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.server.poll() is not None:
                raise AssertionError("fixture sshd failed: " +
                                     (cls.server_root / "sshd.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.02)
        probe = subprocess.run([*cls.argv, "printf RCH_SSH_READY"], capture_output=True,
                               timeout=8)
        if (probe.returncode, probe.stdout) != (0, b"RCH_SSH_READY"):
            raise AssertionError("loopback SSH unavailable: " + probe.stderr.decode(errors="replace")
                                 + (cls.server_root / "sshd.log").read_text())

    @classmethod
    def stop_server(cls):
        if cls.server.poll() is None:
            cls.server.terminate()
        cls.server.wait(timeout=5)
        cls.server_log.close()

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-source-ssh-"))
        self.clients = []
        self.pidfds = []
        self.registry = self.root / "registry"
        self.registry.mkdir(mode=0o700)
        for name in ("cancelled", "released", "quarantine"):
            (self.registry / name).mkdir(mode=0o700)
        (self.registry / "metadata.lock").touch(mode=0o600)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "sentinel").write_text("source remains owned\n")
        self.roots = str(self.source) + "\n"
        self.digest = hashlib.sha256(self.roots.encode()).hexdigest()
        self.token = "aa-111"
        self.release = "RCH_SOURCE_AUTHORITY_RELEASE:" + self.token
        self.active = self.registry / (self.token + "." + self.digest + ".claim")
        self.kernel_lock = self.root / "source.lock"
        self.activity_lock = self.registry / (self.token + ".activity.lock")

    def tearDown(self):
        for client in reversed(self.clients):
            client.close()
        for descriptor in reversed(self.pidfds):
            # A descriptor was pinned while the fixture child was alive.
            # Kill only that process, never a possibly reused numeric PID.
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(descriptor)

    def invocation(self, operation, token=None):
        return shlex.join([FLOCK, "-x", "--", str(self.registry / "metadata.lock"),
                           "sh", "-c", TRANSACTION, "rch-source-registry",
                           str(self.registry), token or self.token, self.digest, operation])

    def transaction(self, operation, token=None):
        command = self.invocation(operation, token)
        if operation in ("cancel", "finish-cancel"):
            command = shlex.join([FLOCK, "-x", "--", str(self.activity_lock)]) + " " + command
        return subprocess.run([*self.argv, command], input=self.roots.encode(),
                              capture_output=True, timeout=8)

    def start(self, program, command="exec sh -s"):
        client = SshProcess(self.argv, command)
        self.clients.append(client)
        client.send("{\n" + program + "\n}\n")
        return client

    def start_holder(self, idle=2, ready=True):
        waiter = shlex.join([sys.executable, "-I", "-S", "-c", WAITER, "source",
                             str(self.registry), self.token, self.digest, self.release])
        retirement = shlex.join([FLOCK, "-x", "--", str(self.activity_lock)]) + " " + self.invocation("release")
        terminal = ("set -eu; ready=$1; roots=$(cat <&4); exec 4<&-; "
                    "printf '%s\\n' \"$roots\" | " + self.invocation("acquire") + "; "
                    "printf '%s\\n' \"$ready\"; " + waiter + "; "
                    "printf '%s\\n' \"$roots\" | " + retirement + "; "
                    "printf '%s\\n' " + QUOTE(self.release))
        program = ("set -eu\nexec 3<<'RCH_SOURCE_LOCK_PATHS'\nx " + str(self.kernel_lock) +
                   "\nRCH_SOURCE_LOCK_PATHS\nexec 4<<'RCH_SOURCE_CLAIM_ROOTS'\n" + self.roots +
                   "RCH_SOURCE_CLAIM_ROOTS\nexec sh -c " + QUOTE(HOLDER) + " " + QUOTE(HOLDER) +
                   " 1 READY " + QUOTE(terminal))
        supervised = ("set -eu\nexec 3<<'RCH_SOURCE_LOCK_SESSION_PROGRAM'\n" + program +
                      "\nRCH_SOURCE_LOCK_SESSION_PROGRAM\nexec sh -c " + QUOTE(HOLDER) +
                      " " + QUOTE(HOLDER) + " --rch-session " + str(idle))
        client = self.start(supervised)
        if ready:
            self.assertEqual(client.line(), b"READY")
            self.assertFalse(available(self.kernel_lock))
            self.assertEqual(self.active.read_text(), self.roots)
        return client

    def start_activity(self):
        # A separate SSH operation models a live compiler retaining the same
        # activity mutex. It is deliberately outside the holder's process tree.
        program = ("import sys\nprint('ACTIVITY_READY',flush=True)\n"
                   "request=sys.stdin.readline()\n"
                   "sys.exit(0 if request=='finish\\n' else 9)\n")
        client = self.start("exec " + shlex.join([
            FLOCK, "-x", "--", str(self.activity_lock),
            sys.executable, "-I", "-S", "-c", program]))
        self.assertEqual(client.line(), b"ACTIVITY_READY")
        self.assertFalse(available(self.activity_lock))
        return client

    @contextlib.contextmanager
    def heartbeat_during_setup(self, holder):
        # Establishing the independent SSH session is not the transport fault.
        # Keep the short test lease alive during that real handshake, just as
        # the dispatcher does, then stop the sole producer before injecting it.
        stopped = threading.Event()
        failures = []

        def renew():
            while not stopped.wait(0.1):
                try:
                    holder.send("RCH_SOURCE_LOCK_HEARTBEAT\n")
                except (OSError, ValueError) as error:
                    failures.append(error)
                    return

        sender = threading.Thread(target=renew, name="rch-ssh-fixture-heartbeat")
        sender.start()
        try:
            yield
        finally:
            stopped.set()
            sender.join(timeout=5)
            self.assertFalse(sender.is_alive(), "fixture heartbeat producer did not stop")
            self.assertFalse(failures, "source holder died before transport fault injection")
        self.assertIsNone(holder.process.poll(), "source holder exited during fixture setup")
        self.assertFalse(available(self.kernel_lock), "source lock was lost before the transport fault")

    def assert_owner_retained(self):
        self.assertEqual(self.active.read_text(), self.roots)
        self.assertFalse((self.registry / "released" / self.active.name).exists())
        self.assertEqual((self.source / "sentinel").read_text(), "source remains owned\n")
        overlap = self.transaction("try-acquire", token="bb-111")
        self.assertEqual((overlap.returncode, overlap.stdout), (75, b""), overlap.stderr)

    def finish_activity(self, activity):
        self.assertIsNone(activity.process.poll(), "holder teardown killed independent activity")
        self.assertFalse(available(self.activity_lock))
        activity.send("finish\n")
        stdout, stderr = activity.finish()
        self.assertEqual((activity.process.returncode, stdout, stderr), (0, b"", b""))

    def test_live_heartbeats_and_explicit_release_publish_exact_retirement(self):
        holder = self.start_holder()
        until = time.monotonic() + 2.3
        while time.monotonic() < until:
            holder.send("RCH_SOURCE_LOCK_HEARTBEAT\n")
            time.sleep(0.1)
            self.assertIsNone(holder.process.poll())
            self.assertFalse(available(self.kernel_lock))
        holder.send(self.release + "\n")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr),
                         (0, (self.release + "\n").encode(), b""))
        self.assertFalse(self.active.exists())
        self.assertEqual((self.registry / "released" / self.active.name).read_text(), self.roots)
        self.assertTrue(available(self.kernel_lock))
        fresh = self.transaction("try-acquire", token="bb-111")
        self.assertEqual((fresh.returncode, fresh.stdout), (0, b""), fresh.stderr)

    def test_ssh_eof_releases_only_transient_locks_and_keeps_independent_activity(self):
        holder = self.start_holder(idle=90)
        with self.heartbeat_during_setup(holder):
            activity = self.start_activity()
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"RCH_SOURCE_LOCK_DISCONNECTED", stderr)
        self.assertTrue(available(self.kernel_lock))
        self.assert_owner_retained()
        self.finish_activity(activity)

    def test_killed_ssh_client_cannot_leave_an_unbounded_source_lock_holder(self):
        holder = self.start_holder()
        with self.heartbeat_during_setup(holder):
            activity = self.start_activity()
        holder.process.kill()
        holder.finish()
        eventually(lambda: available(self.kernel_lock), "killed SSH client stranded source lock")
        self.assert_owner_retained()
        self.finish_activity(activity)

    def test_stopped_ssh_client_expires_while_transport_stays_open(self):
        holder = self.start_holder()
        with self.heartbeat_during_setup(holder):
            activity = self.start_activity()
        holder.send("RCH_SOURCE_LOCK_HEARTBEAT\n")
        holder.process.send_signal(signal.SIGSTOP)
        holder.stopped = True
        eventually(lambda: available(self.kernel_lock), "stopped SSH client stranded source lock")
        self.assertIsNone(holder.process.poll(), "fault must retain the stopped SSH client")
        self.assert_owner_retained()
        self.finish_activity(activity)
        holder.process.send_signal(signal.SIGCONT)
        holder.stopped = False
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"RCH_SOURCE_LOCK_HEARTBEAT_EXPIRED", stderr)

    def test_cancellation_on_another_ssh_session_yields_locks_without_early_release(self):
        holder = self.start_holder(idle=90)
        holder.send("RCH_SOURCE_LOCK_HEARTBEAT\n")
        started = time.monotonic()
        cancelled = self.transaction("cancel")
        self.assertEqual((cancelled.returncode, cancelled.stdout), (0, b"owned"), cancelled.stderr)
        holder.process.wait(timeout=5)  # Keep stdin open through autonomous handoff.
        self.assertLess(time.monotonic() - started, 5)
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (75, b""), stderr)
        self.assertIn(b"yielding kernel locks", stderr)
        self.assertTrue(available(self.kernel_lock))
        self.assertEqual((self.registry / (self.token + "." + self.digest + ".cancelling")).read_text(), self.roots)
        self.assert_owner_retained()

    def test_expired_ssh_waiter_cannot_publish_after_metadata_mutex_is_released(self):
        with (self.registry / "metadata.lock").open("r+") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            holder = self.start_holder(ready=False)
            eventually(lambda: not available(self.kernel_lock), "source holder did not reach metadata wait")
            holder.process.wait(timeout=5)  # No EOF: expire a live queued SSH session.
            stdout, stderr = holder.finish()
            self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
            self.assertIn(b"RCH_SOURCE_LOCK_HEARTBEAT_EXPIRED", stderr)
            self.assertTrue(available(self.kernel_lock))
            self.assertFalse(self.active.exists())
        time.sleep(0.2)
        self.assertFalse(self.active.exists(), "abandoned SSH initializer published after unlock")

    @unittest.skipUnless(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                         "requires Linux pidfds for exact owned-timer fault injection")
    def test_stopped_cancel_client_expires_before_activity_unlock_without_late_publication(self):
        acquire = self.transaction("acquire")
        self.assertEqual((acquire.returncode, acquire.stdout), (0, b""), acquire.stderr)
        before = (self.active.stat().st_ino, self.active.read_bytes())
        cancelling = self.registry / (self.token + "." + self.digest + ".cancelling")
        waiter = self.root / "cancel-waiter.pid"
        command = ("printf '%s\\n' \"$$\" > " + QUOTE(str(waiter)) + "\nexec " +
                   shlex.join([FLOCK, "-x", "--", str(self.activity_lock)]) + " " +
                   self.invocation("cancel") + " <<'RCH_SOURCE_CLAIM_ROOTS'\n" + self.roots +
                   "RCH_SOURCE_CLAIM_ROOTS\n")
        with self.activity_lock.open("a") as activity:
            fcntl.flock(activity, fcntl.LOCK_EX)
            started = time.monotonic()
            client = self.start(command, "set -- RCH_SOURCE_INTENT_CANCEL\n" + CONTROL)
            eventually(lambda: waiter.exists() and waiter.stat().st_size,
                       "queued cancellation did not reach its activity wait")
            waiter_fd = os.pidfd_open(int(waiter.read_text()))
            self.pidfds.append(waiter_fd)
            client.process.send_signal(signal.SIGSTOP)
            client.stopped = True
            ended = select.poll()
            ended.register(waiter_fd, select.POLLIN)
            # Exercise the actual shipped 15s timer and 1s escalation while
            # SSH is stopped, without an accelerated timer or a client EOF.
            self.assertTrue(ended.poll(18000), "worker-side cancellation outlived its deadline")
            self.assertGreaterEqual(time.monotonic() - started, 15)
            self.assertIsNone(client.process.poll(), "fault must keep the SSH client stopped")
            self.assertEqual((self.active.stat().st_ino, self.active.read_bytes()), before)
            self.assertFalse(cancelling.exists())
            self.assertFalse((self.registry / "cancelled" / self.active.name).exists())
        # No detached worker transaction may wake and fence the owner after
        # the real source activity finally releases its mutex.
        time.sleep(0.2)
        self.assertFalse(cancelling.exists(), "timed-out SSH cancellation published after unlock")
        self.assertEqual((self.active.stat().st_ino, self.active.read_bytes()), before)
        client.process.send_signal(signal.SIGCONT)
        client.stopped = False
        stdout, stderr = client.finish()
        self.assertEqual((client.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"RCH_SOURCE_NAMESPACE_CONTROL_UNSETTLED", stderr)
        self.assert_owner_retained()

    @unittest.skipUnless(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                         "requires Linux pidfds for exact owned-timer fault injection")
    def test_killed_namespace_timer_over_ssh_releases_metadata_without_losing_claim(self):
        acquire = self.transaction("acquire")
        self.assertEqual((acquire.returncode, acquire.stdout), (0, b""), acquire.stderr)
        metadata = self.root / "namespace.lock"
        held = self.root / "namespace-held"
        code = ("import fcntl,os,signal,time\n"
                "for s in (signal.SIGHUP,signal.SIGTERM): signal.signal(s,signal.SIG_IGN)\n"
                "fd=open({!r},'a'); fcntl.flock(fd,fcntl.LOCK_EX)\n"
                "open({!r},'w').write(str(os.getpid())+' '+str(os.getpgrp()))\n"
                "os.close(1); os.close(2); time.sleep(60)\n").format(str(metadata), str(held))
        client = self.start("exec " + shlex.join([sys.executable, "-I", "-S", "-c", code]), CONTROL)
        eventually(lambda: held.exists() and held.stat().st_size, "SSH namespace child never held metadata")
        child, timer = map(int, held.read_text().split())
        self.assertEqual(os.getpgid(child), timer)
        for pid in (child, timer):
            self.pidfds.append(os.pidfd_open(pid))
        self.assertFalse(available(metadata))
        signal.pidfd_send_signal(self.pidfds[-1], signal.SIGKILL)
        stdout, stderr = client.finish()
        self.assertEqual((client.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"RCH_SOURCE_NAMESPACE_CONTROL_UNSETTLED", stderr)
        eventually(lambda: available(metadata), "killed SSH timer stranded metadata lock")
        for descriptor in self.pidfds:
            exited = select.poll()
            exited.register(descriptor, select.POLLIN)
            self.assertTrue(exited.poll(1000), "owned namespace descendant survived timer death")
        self.assert_owner_retained()


if __name__ == "__main__":
    unittest.main(verbosity=2)
