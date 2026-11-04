#!/usr/bin/env python3
"""Qualify source ownership over real, isolated loopback OpenSSH on Linux.

This runs the exact production holder, release waiter, pair custody, registry
transaction, cancellation settlement coordinator, activity check, retained-tree
program and namespace controller.
It uses fixture-owned host/client keys, strict host
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
import json
import os
from pathlib import Path
import pwd
import re
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
SETTLEMENT = (REPO / "rch/src/hook/source_cancel_settlement.py").read_text()
SSH_SOURCE = (REPO / "rch/src/hook/ssh.rs").read_text()
WAITER = SSH_SOURCE.split('const SOURCE_AUTHORITY_RELEASE_WAITER: &str = r#"', 1)[1].split('"#;', 1)[0]
PAIR_CUSTODY = SSH_SOURCE.split('const SOURCE_PAIR_CUSTODY: &str = r#"', 1)[1].split('"#;', 1)[0]
# Decode Rust's existing literal, including escaped-newline continuation. The
# shell check itself is not a fixture implementation of the ownership rules.
ACTIVITY_SOURCE = SSH_SOURCE.split('fn source_authority_activity_prefix_for_mode(', 1)[1].split('\n}\n', 1)[0]
ACTIVITY_LITERAL = re.search(r'let check = ("(?:[^"\\]|\\[\s\S])*");', ACTIVITY_SOURCE).group(1)
ACTIVITY_CHECK = json.loads(re.sub(r'\\\n[ \t]*', '', ACTIVITY_LITERAL))
TRANSFER_SOURCE = (REPO / "rch/src/transfer.rs").read_text()
RETENTION = TRANSFER_SOURCE.split("fn remote_tree_retention_program() -> &'static str {", 1)[1].split('r#"', 1)[1].split('"#', 1)[0]
FINITE_ACTIVITY = TRANSFER_SOURCE.split('pub(crate) fn source_activity_finite_script(', 1)[1].split('r#"', 1)[1].split('"#', 1)[0]
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
        # Do not share the config path with worker stdout/stderr sinks. Some
        # constrained qualification containers expose /dev/null as a file.
        empty_config = cls.server_root / "empty_config"
        empty_config.write_text("")
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
                                      stdin=subprocess.PIPE, stdout=cls.server_log,
                                      stderr=cls.server_log)
        cls.server.stdin.close()
        cls.server.stdin = None
        cls.addClassCleanup(cls.stop_server)
        cls.argv = [SSH, "-F", str(empty_config), "-T", "-p", str(port),
                    "-i", str(cls.server_root / "client"),
                    "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                    "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", "UserKnownHostsFile=" + str(cls.server_root / "known_hosts"),
                    "-o", "GlobalKnownHostsFile=" + str(empty_config), "-o", "LogLevel=ERROR",
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

    def invocation(self, operation, token=None, registry=None):
        registry = self.registry if registry is None else registry
        return shlex.join([FLOCK, "-x", "--", str(registry / "metadata.lock"),
                           "sh", "-c", TRANSACTION, "rch-source-registry",
                           str(registry), token or self.token, self.digest, operation])

    def transaction(self, operation, token=None):
        command = self.invocation(operation, token)
        if operation in ("cancel", "finish-cancel", "settle-cancel", "release"):
            activity_lock = self.registry / ((token or self.token) + ".activity.lock")
            command = shlex.join([FLOCK, "-x", "--", str(activity_lock)]) + " " + command
        return subprocess.run([*self.argv, command], input=self.roots.encode(),
                              capture_output=True, timeout=8)

    def cancellation_state(self, token=None, registry=None):
        program = (self.invocation("cancellation-state", token, registry) +
                   " <<'RCH_SOURCE_CLAIM_ROOTS'\n" + self.roots +
                   "RCH_SOURCE_CLAIM_ROOTS\n")
        client = self.start(program, "set -- RCH_SOURCE_INTENT_CANCELLATION_STATE\n" + CONTROL)
        stdout, stderr = client.finish()
        return client.process.returncode, stdout, stderr

    def make_legacy_registry(self):
        self.legacy = self.root / "legacy"
        self.legacy.mkdir(mode=0o700)
        for name in ("cancelled", "released", "quarantine"):
            (self.legacy / name).mkdir(mode=0o700)
        (self.legacy / "metadata.lock").touch(mode=0o600)

    def namespace_command(self, operation, namespace, token=None):
        token = token or self.token
        registry = self.registry if namespace == "current" else self.legacy
        peer = self.legacy if namespace == "current" else self.registry
        command = ["env", "RCH_LEGACY_SOURCE_CLAIM_REGISTRY=" + str(peer)]
        if operation in ("cancel", "finish-cancel", "settle-cancel", "release"):
            command.extend([FLOCK, "-x", "--", str(registry / (token + ".activity.lock"))])
        # Preserve the production activity -> current metadata -> legacy
        # metadata order, including when the identity is bound to legacy.
        for directory in (self.registry, self.legacy):
            command.extend([FLOCK, "-x", "--", str(directory / "metadata.lock")])
        return shlex.join([*command, "sh", "-c", TRANSACTION, "rch-source-registry",
                           str(registry), token, self.digest, operation])

    def namespace_transaction(self, operation, namespace, token=None):
        return subprocess.run([*self.argv, self.namespace_command(operation, namespace, token)],
                              input=self.roots.encode(), capture_output=True, timeout=8)

    def roots_program(self, command):
        return (command + " <<'RCH_SOURCE_CLAIM_ROOTS'\n" + self.roots +
                "RCH_SOURCE_CLAIM_ROOTS\n")

    def settlement_program(self, operation, expected="", token=None):
        return self.roots_program(shlex.join([
            sys.executable, "-I", "-S", "-c", SETTLEMENT, str(self.registry),
            str(self.root / "legacy"), token or self.token, self.digest,
            TRANSACTION, operation, expected]))

    def settlement(self, operation, expected="", token=None):
        contract = {"locate": "RCH_SOURCE_AUTHORITY_NAMESPACE",
                    "discover": "RCH_SOURCE_AUTHORITY_DISCOVERY"}.get(
                        operation, "RCH_SOURCE_CANCELLATION_SETTLED")
        client = self.start(self.settlement_program(operation, expected, token),
                            "set -- " + contract + "\n" + CONTROL)
        stdout, stderr = client.finish(seconds=20)
        return subprocess.CompletedProcess([], client.process.returncode, stdout, stderr)

    def lose_control_reply(self, program, contract, label):
        committed = self.root / (label + ".committed")
        # The real coordinator/registry writes its response into the real
        # controller's capture pipe. Hold the uploaded program before exit so
        # that no response has been delivered, then drop this exact SSH child.
        client = self.start("set -eu\n" + program +
                            "\nprintf committed > " + QUOTE(str(committed)) +
                            "\nread -r lost_reply\n",
                            "set -- " + contract + "\n" + CONTROL)
        eventually(lambda: committed.exists(), "worker did not reach the lost-reply frontier")
        self.assertIsNone(client.line(seconds=0.1), "controller delivered before program completion")
        client.process.kill()
        stdout, _ = client.finish()
        self.assertEqual(stdout, b"", "dropped SSH reply must not be accepted as completion")

    def fail_sync_after_pending_publication(self, pending):
        tools = self.root / "pending-publication-tools"
        tools.mkdir(mode=0o700)
        adapter = tools / "python3"
        # Real file writes and atomic publication run. Fail only the next
        # production fsync adapter call after this exact pending file exists;
        # the record's content has already been written and file-synced.
        adapter.write_text(
            '#!/bin/sh\ncase "${4-}" in *os.fsync*)\n'
            "  if [ -e " + QUOTE(str(pending)) + " ]; then\n"
            "    printf 'injected post-pending publication sync failure\\n' >&2\n"
            "    exit 91\n  fi\nesac\nexec " + QUOTE(sys.executable) + ' "$@"\n')
        adapter.chmod(0o700)
        return "env PATH=" + QUOTE(str(tools)) + ':"$PATH" '

    def authority_records(self):
        return {str(path.relative_to(self.root)): (path.stat().st_ino, path.read_bytes())
                for registry in (self.registry, self.root / "legacy") if registry.exists()
                for path in registry.rglob("*")
                if path.is_file() and not path.name.endswith(".lock")}

    def pair_program(self, operation, source, token=None):
        token = token or self.token
        # The Rust caller supplies the exact per-token receipt name. This
        # fixture exercises that worker program and lock order over real SSH;
        # it does not substitute for compiling Rust's command construction.
        receipt = self.root / ("pair.lock.released-" + token)
        return shlex.join([
            sys.executable, "-I", "-S", "-c", PAIR_CUSTODY, operation,
            str(self.root / "pair.lock.owner"), str(receipt), token, str(source)])

    def pair_command(self, operation, source, token=None, after=""):
        lock = self.root / "pair.lock"
        command = [FLOCK, "-x", "--", str(lock)]
        if operation == "claim":
            command.extend([FLOCK, "-x", "--", str(self.registry / "metadata.lock")])
        program = self.pair_program(operation, source, token)
        if after:
            return shlex.join([*command, "sh", "-c", "set -eu\n" + program + after])
        return shlex.join(command) + " " + program

    def pair_transaction(self, operation, source, token=None):
        return subprocess.run([*self.argv, self.pair_command(operation, source, token)],
                              capture_output=True, timeout=8)

    def start(self, program, command="exec sh -s"):
        command = "export TMPDIR=" + QUOTE(str(self.root)) + "\n" + command
        client = SshProcess(self.argv, command)
        self.clients.append(client)
        client.send("{\n" + program + "\n}\n")
        return client

    def start_holder(self, idle=2, ready=True, acquire_command=None):
        waiter = shlex.join([sys.executable, "-I", "-S", "-c", WAITER, "source",
                             str(self.registry), self.token, self.digest, self.release])
        retirement = shlex.join([FLOCK, "-x", "--", str(self.activity_lock)]) + " " + self.invocation("release")
        terminal = ("set -eu; ready=$1; roots=$(cat <&4); exec 4<&-; "
                    "printf '%s\\n' \"$roots\" | " + (acquire_command or self.invocation("acquire")) + "; "
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

    def prepare_materialized_pair(self, pair_token=None, claim_pair=True, grant_source=True):
        # Keep the default fixture intact; every materialized or retained tree
        # remains available for inspection after this test finishes.
        self.token = "1234567890abcdef1234567890abcdef"
        self.source = self.root / "owned-pair-source"
        self.retained = self.root / (self.source.name + ".retained-" + self.token)
        self.roots = "".join(root + "\n" for root in sorted(map(str, (self.source, self.retained))))
        self.digest = hashlib.sha256(self.roots.encode()).hexdigest()
        self.active = self.registry / (self.token + "." + self.digest + ".claim")
        self.fence = self.registry / (self.token + "." + self.digest + ".cancelling")
        self.activity_lock = self.registry / (self.token + ".activity.lock")
        if claim_pair:
            pair = self.pair_transaction("claim", self.source, pair_token)
            self.assertEqual((pair.returncode, pair.stdout, pair.stderr), (0, b"", b""))
        if grant_source:
            granted = self.transaction("acquire")
            self.assertEqual((granted.returncode, granted.stdout, granted.stderr), (0, b"", b""))
        self.source.mkdir()
        (self.source / "sentinel").write_bytes(b"materialized source evidence\n")

    def activity_prefix(self, mode="cleanup", token=None, registry=None):
        token = token or self.token
        registry = self.registry if registry is None else registry
        return shlex.join([
            "nohup", FLOCK, "-x", "--", str(registry / (token + ".activity.lock")),
            "sh", "-c", ACTIVITY_CHECK, "rch-source-activity", str(registry),
            token, mode])

    def activity_command(self, program, mode="cleanup", token=None, registry=None):
        return self.activity_prefix(mode, token, registry) + " " + shlex.join(["sh", "-c", program])

    def retention_command(self, identity=None, root=None, retained=None):
        return shlex.join([
            sys.executable, "-I", "-c", RETENTION, "retain", str(root or self.source),
            str(retained or self.retained), identity or self.token, "0"])

    def retain_pair_tree(self, **arguments):
        return subprocess.run([*self.argv, self.activity_command(self.retention_command(**arguments))],
                              input=b"", capture_output=True, timeout=8)

    def start_checked_activity(self, mode="active", before=""):
        program = (before + "\n" if before else "") + (
            "exec " + shlex.join([sys.executable, "-I", "-S", "-c",
                                  "import sys\nprint('ACTIVITY_READY',flush=True)\n"
                                  "sys.exit(0 if sys.stdin.readline()=='finish\\n' else 9)\n"]))
        return self.start("exec " + self.activity_command(program, mode))

    def start_cancel_waiter(self, label):
        reached = self.root / (label + ".entered")
        command = ("printf entered > " + QUOTE(str(reached)) + "\nexec " +
                   shlex.join([FLOCK, "-x", "--", str(self.activity_lock)]) + " " +
                   self.invocation("cancel") + " <<'RCH_SOURCE_CLAIM_ROOTS'\n" +
                   self.roots + "RCH_SOURCE_CLAIM_ROOTS\n")
        client = self.start(command, "set -- RCH_SOURCE_INTENT_CANCEL\n" + CONTROL)
        eventually(lambda: reached.exists(), "cancellation did not reach the activity lock")
        return client

    def start_pair_holder(self, mode="cleanup-pair", idle=90, ready=True, label="cleanup", token=None):
        token = token or self.token
        release = "RCH_SOURCE_PAIR_RELEASE:" + token
        ready_marker = "RCH_SOURCE_PAIR_READY:" + token
        waiter = shlex.join([sys.executable, "-I", "-S", "-c", WAITER, mode,
                             str(self.registry), token, str(self.source), release])
        after = ("\nprintf '%s\\n' " + QUOTE(ready_marker) + "\n" + waiter + "\n" +
                 self.pair_program("release", self.source, token) +
                 "\nprintf '%s\\n' " + QUOTE(release) + "\n")
        reached = self.root / (label + ".entered")
        program = ("printf entered > " + QUOTE(str(reached)) + "\nexec " +
                   self.pair_command("recover", self.source, token, after))
        supervised = ("set -eu\nexec 3<<'RCH_SOURCE_LOCK_SESSION_PROGRAM'\n" + program +
                      "\nRCH_SOURCE_LOCK_SESSION_PROGRAM\nexec sh -c " + QUOTE(HOLDER) +
                      " " + QUOTE(HOLDER) + " --rch-session " + str(idle))
        client = self.start(supervised)
        client.pair_release = release
        eventually(lambda: reached.exists(), "pair recovery did not reach its kernel lock")
        if ready:
            self.assertEqual(client.line(), ready_marker.encode())
            if mode == "cleanup-pair":
                self.assertFalse(available(self.root / "pair.lock"))
        return client

    def release_pair_holder(self, holder, queued=False):
        holder.send(holder.pair_release + "\n")
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout, stderr),
                         (0, (holder.pair_release + "\n").encode(), b""))
        if not queued:
            self.assertTrue(available(self.root / "pair.lock"))

    def finish_pair_cancellation(self):
        finished = self.transaction("finish-cancel")
        self.assertEqual((finished.returncode, finished.stdout, finished.stderr), (0, b"", b""))
        self.assertFalse(self.active.exists())
        self.assertEqual(self.fence.read_text(), self.roots)
        self.assertEqual((self.registry / "cancelled" / self.active.name).read_text(), self.roots)
        successor_token = "b" * 32
        successor = self.pair_transaction("claim", self.source, successor_token)
        self.assertEqual((successor.returncode, successor.stdout, successor.stderr), (0, b"", b""))
        admitted = self.transaction("try-acquire", successor_token)
        self.assertEqual((admitted.returncode, admitted.stdout, admitted.stderr), (0, b"", b""))
        self.source.mkdir()
        sentinel = self.source / "successor"
        sentinel.write_bytes(b"live successor source\n")
        owner = self.root / "pair.lock.owner"
        claim = self.registry / (successor_token + "." + self.digest + ".claim")
        before = [(path.stat().st_ino, path.read_bytes()) for path in (owner, claim, sentinel)]
        for _ in range(2):
            settled = self.transaction("settle-cancel")
            self.assertEqual((settled.returncode, settled.stdout, settled.stderr), (0, b"settled", b""))
            released = self.pair_transaction("released", self.source)
            self.assertEqual((released.returncode, released.stdout, released.stderr), (0, b"released", b""))
            self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in (owner, claim, sentinel)], before)
        late = self.retain_pair_tree()
        self.assertEqual(late.returncode, 73, late.stderr)
        self.assertIn(b"source grant is not active", late.stderr)
        self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in (owner, claim, sentinel)], before)
        self.assertEqual((self.retained / "sentinel").read_bytes(), b"materialized source evidence\n")

    @contextlib.contextmanager
    def heartbeat_during_setup(self, holder, lock=None):
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
        self.assertFalse(available(lock or self.kernel_lock), "source lock was lost before the transport fault")

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

    def assert_pending_publication_can_cancel_and_readmit(self, namespace):
        self.make_legacy_registry()
        self.source = self.root / "unmaterialized-source"
        self.roots = str(self.source) + "\n"
        self.digest = hashlib.sha256(self.roots.encode()).hexdigest()
        self.active = self.registry / (self.token + "." + self.digest + ".claim")
        registry = self.registry if namespace == "current" else self.legacy
        pending = registry / (self.token + "." + self.digest + ".pending")
        active = pending.with_suffix(".claim")
        fence = pending.with_suffix(".cancelling")
        receipt = registry / "cancelled" / active.name
        command = (self.fail_sync_after_pending_publication(pending) +
                   self.namespace_command("acquire", namespace))
        holder = self.start_holder(idle=90, ready=False, acquire_command=command)
        holder.process.wait(timeout=10)
        stdout, stderr = holder.finish()
        self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"RCH_SOURCE_REGISTRY_PUBLICATION_UNCONFIRMED", stderr)
        self.assertEqual(pending.read_text(), self.roots)
        pending_identity = pending.stat().st_ino, pending.read_bytes()
        self.assertFalse(active.exists())
        self.assertFalse(self.source.exists(), "unready holder must not materialize source")
        self.assertTrue(available(self.kernel_lock))
        before = self.authority_records()

        blocked = self.namespace_transaction("try-acquire", "current", "bb-111")
        self.assertEqual((blocked.returncode, blocked.stdout), (75, b""), blocked.stderr)
        self.lose_control_reply(self.settlement_program("locate"),
                                "RCH_SOURCE_AUTHORITY_NAMESPACE", "pending-location")
        self.assertEqual(self.authority_records(), before)
        for operation in ("locate", "discover", "locate", "discover"):
            result = self.settlement(operation)
            contract = "NAMESPACE" if operation == "locate" else "DISCOVERY"
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (0, f"RCH_SOURCE_AUTHORITY_{contract} {namespace}\n".encode(), b""))
            self.assertEqual(self.authority_records(), before)
            self.assertFalse(active.exists(), "namespace observation promoted pending ownership")
        # A located pending publication is not cancellation or retirement.
        status, output, error = self.cancellation_state(registry=registry)
        self.assertEqual((status, output), (73, b""), error)
        refused = self.settlement("settle-cancel", namespace)
        self.assertEqual((refused.returncode, refused.stdout), (73, b""), refused.stderr)
        self.assertEqual(self.authority_records(), before)

        self.lose_control_reply(self.roots_program(self.namespace_command("cancel", namespace)),
                                "RCH_SOURCE_INTENT_CANCEL", "pending-cancel")
        self.assertFalse(pending.exists())
        self.assertEqual((active.stat().st_ino, active.read_bytes()), pending_identity)
        self.assertEqual(fence.read_text(), self.roots)
        cancelled_before = self.authority_records()
        for _ in range(2):
            cancelled = self.namespace_transaction("cancel", namespace)
            self.assertEqual((cancelled.returncode, cancelled.stdout, cancelled.stderr),
                             (0, b"owned", b""))
            self.assertEqual(self.authority_records(), cancelled_before)
            blocked = self.namespace_transaction("try-acquire", "current", "bb-111")
            self.assertEqual((blocked.returncode, blocked.stdout), (75, b""), blocked.stderr)

        # This actual holder failed before readiness; no source operation or
        # materialization was ever started. Complete the checked cancellation
        # protocol, preserving its original claim as the retirement receipt.
        self.lose_control_reply(self.roots_program(self.namespace_command("finish-cancel", namespace)),
                                "RCH_SOURCE_INTENT_FINISHED", "pending-finish")
        self.assertFalse(active.exists())
        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), pending_identity)
        finished = self.namespace_transaction("finish-cancel", namespace)
        self.assertEqual((finished.returncode, finished.stdout, finished.stderr), (0, b"", b""))
        admitted = self.namespace_transaction("try-acquire", "current", "bb-111")
        self.assertEqual((admitted.returncode, admitted.stdout, admitted.stderr), (0, b"", b""))
        successor = self.registry / ("bb-111." + self.digest + ".claim")
        self.source.mkdir()
        sentinel = self.source / "successor"
        sentinel.write_bytes(b"new dispatcher source\n")
        protected = (receipt, fence, successor, sentinel)
        protected_before = [(path.stat().st_ino, path.read_bytes()) for path in protected]
        for _ in range(2):
            settled = self.settlement("settle-cancel", namespace)
            self.assertEqual((settled.returncode, settled.stdout, settled.stderr),
                             (0, b"RCH_SOURCE_CANCELLATION_SETTLED\n", b""))
            delayed = self.namespace_transaction("recover", namespace)
            self.assertEqual((delayed.returncode, delayed.stdout), (73, b""), delayed.stderr)
            self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in protected],
                             protected_before)

    def test_interrupted_current_pending_publication_can_cancel_and_readmit_over_ssh(self):
        self.assert_pending_publication_can_cancel_and_readmit("current")

    def test_interrupted_legacy_pending_publication_can_cancel_and_readmit_over_ssh(self):
        self.assert_pending_publication_can_cancel_and_readmit("legacy")

    def test_optional_discovery_absence_preserves_another_dispatchers_live_claim(self):
        acquired = self.transaction("acquire", "bb-111")
        self.assertEqual((acquired.returncode, acquired.stdout, acquired.stderr), (0, b"", b""))
        before = self.authority_records()
        sentinel = self.source / "sentinel"
        source_before = sentinel.stat().st_ino, sentinel.read_bytes()
        for _ in range(2):
            result = self.settlement("discover")
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (0, b"RCH_SOURCE_AUTHORITY_DISCOVERY absent\n", b""))
            strict = self.settlement("locate")
            self.assertEqual((strict.returncode, strict.stdout), (73, b""), strict.stderr)
            self.assertEqual(self.authority_records(), before)
            self.assertFalse((self.root / "legacy").exists())
            self.assertFalse(self.active.exists())
            self.assertEqual((sentinel.stat().st_ino, sentinel.read_bytes()), source_before)
        refused = self.transaction("recover")
        self.assertEqual((refused.returncode, refused.stdout), (73, b""), refused.stderr)
        self.assertEqual(self.authority_records(), before)

    def test_legacy_terminal_cancellation_discovery_survives_a_lost_settlement_reply(self):
        self.make_legacy_registry()
        self.token = "a" * 32
        self.source = self.root / "terminal-source"
        self.retained = self.root / (self.source.name + ".retained-" + self.token)
        self.roots = "".join(root + "\n" for root in sorted(map(str, (self.source, self.retained))))
        self.digest = hashlib.sha256(self.roots.encode()).hexdigest()
        active = self.legacy / (self.token + "." + self.digest + ".claim")
        fence = active.with_suffix(".cancelling")
        receipt = self.legacy / "cancelled" / active.name
        acquired = self.namespace_transaction("acquire", "legacy")
        self.assertEqual((acquired.returncode, acquired.stdout, acquired.stderr), (0, b"", b""))
        active_before = active.stat().st_ino, active.read_bytes()
        self.source.mkdir()
        (self.source / "sentinel").write_bytes(b"retired original source\n")
        cancelled = self.namespace_transaction("cancel", "legacy")
        self.assertEqual((cancelled.returncode, cancelled.stdout, cancelled.stderr), (0, b"owned", b""))
        # Execute actual activity admission and the Linux retained-tree
        # program. This proves the worker's retirement frontier; the separate
        # Rust recovery tests must still qualify durable journal ownership.
        retained = subprocess.run(
            [*self.argv, self.activity_command(self.retention_command(), registry=self.legacy)],
            input=b"", capture_output=True, timeout=8)
        self.assertEqual((retained.returncode, retained.stdout, retained.stderr),
                         (0, b"RCH_SOURCE_RETAINED\n", b""))
        self.assertFalse(self.source.exists())
        before = self.authority_records()
        for _ in range(2):
            located = self.settlement("discover")
            self.assertEqual((located.returncode, located.stdout, located.stderr),
                             (0, b"RCH_SOURCE_AUTHORITY_DISCOVERY legacy\n", b""))
            status, output, error = self.cancellation_state(registry=self.legacy)
            self.assertEqual((status, output, error), (0, b"cancellation", b""))
            self.assertEqual(self.authority_records(), before)
        blocked = self.namespace_transaction("try-acquire", "current", "bb-111")
        self.assertEqual((blocked.returncode, blocked.stdout), (75, b""), blocked.stderr)
        wrong_binding = self.settlement("settle-cancel", "current")
        self.assertEqual((wrong_binding.returncode, wrong_binding.stdout), (73, b""), wrong_binding.stderr)
        self.assertIn(b"namespace changed from recorded binding", wrong_binding.stderr)
        self.assertEqual(self.authority_records(), before)
        self.lose_control_reply(self.settlement_program("settle-cancel", "legacy"),
                                "RCH_SOURCE_CANCELLATION_SETTLED", "terminal-settlement")
        self.assertFalse(active.exists())
        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), active_before)
        self.assertEqual(fence.read_text(), self.roots)
        admitted = self.namespace_transaction("try-acquire", "current", "bb-111")
        self.assertEqual((admitted.returncode, admitted.stdout, admitted.stderr), (0, b"", b""))
        self.source.mkdir()
        successor_source = self.source / "successor"
        successor_source.write_bytes(b"live successor source\n")
        successor = self.registry / ("bb-111." + self.digest + ".claim")
        protected = (receipt, fence, successor, successor_source, self.retained / "sentinel")
        protected_before = [(path.stat().st_ino, path.read_bytes()) for path in protected]
        for _ in range(2):
            restarted = self.settlement("settle-cancel", "legacy")
            self.assertEqual((restarted.returncode, restarted.stdout, restarted.stderr),
                             (0, b"RCH_SOURCE_CANCELLATION_SETTLED\n", b""))
            discovered = self.settlement("discover")
            self.assertEqual((discovered.returncode, discovered.stdout, discovered.stderr),
                             (0, b"RCH_SOURCE_AUTHORITY_DISCOVERY legacy\n", b""))
            self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in protected],
                             protected_before)
        delayed = subprocess.run(
            [*self.argv, self.activity_command(self.retention_command(), registry=self.legacy)],
            input=b"", capture_output=True, timeout=8)
        self.assertEqual(delayed.returncode, 73, delayed.stderr)
        self.assertIn(b"source grant is not active", delayed.stderr)
        self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in protected], protected_before)

    def test_optional_discovery_refuses_malformed_or_conflicting_evidence_over_ssh(self):
        self.make_legacy_registry()
        acquired = self.namespace_transaction("acquire", "current", "bb-111")
        self.assertEqual((acquired.returncode, acquired.stdout, acquired.stderr), (0, b"", b""))
        cases = (("aa-121", "torn-pending"), ("aa-122", "wrong-fence"),
                 ("aa-123", "unknown-record"), ("aa-124", "both-namespaces"))
        for token, case in cases:
            with self.subTest(case=case):
                stem = token + "." + self.digest
                if case == "torn-pending":
                    (self.registry / (stem + ".pending")).write_bytes(b"interrupted")
                elif case == "wrong-fence":
                    (self.registry / (stem + ".cancelling")).write_text(str(self.root / "wrong") + "\n")
                elif case == "unknown-record":
                    (self.registry / (stem + ".unexpected")).write_text(self.roots)
                else:
                    for registry in (self.registry, self.legacy):
                        (registry / (stem + ".cancelling")).write_text(self.roots)
                before = self.authority_records()
                for operation in ("discover", "locate", "settle-cancel"):
                    expected = "current" if operation == "settle-cancel" else ""
                    refused = self.settlement(operation, expected, token)
                    self.assertEqual((refused.returncode, refused.stdout), (73, b""), refused.stderr)
                    self.assertEqual(self.authority_records(), before)
                self.assertFalse(any((self.registry / "quarantine").iterdir()),
                                 "namespace observation moved malformed evidence")
        self.assertEqual((self.source / "sentinel").read_text(), "source remains owned\n")

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

    def test_pair_release_after_lost_ssh_reply_preserves_a_successor_owner(self):
        source = self.root / "pair-source"
        claimed = self.pair_transaction("claim", source)
        self.assertEqual((claimed.returncode, claimed.stdout), (0, b""), claimed.stderr)
        source.mkdir()
        (source / "original").write_bytes(b"old source evidence")
        source.rename(self.root / "pair-retired")

        # Stop the SSH client after the worker committed its release, before
        # the fixture would send a release acknowledgment. The exact child is
        # retained by Popen; no process-table lookup authorizes the kill.
        release = self.start("exec " + self.pair_command(
            "release", source, after="\nprintf 'PAIR_COMMITTED\\n'\nread -r reply\n"))
        self.assertEqual(release.line(), b"PAIR_COMMITTED")
        self.assertFalse(available(self.root / "pair.lock"))
        release.process.kill()
        release.finish()
        eventually(lambda: available(self.root / "pair.lock"),
                   "lost pair reply stranded its mutex")

        successor = self.pair_transaction("claim", source, "bb-111")
        self.assertEqual((successor.returncode, successor.stdout), (0, b""), successor.stderr)
        source.mkdir()
        sentinel = source / "successor"
        sentinel.write_bytes(b"live successor source")
        owner = self.root / "pair.lock.owner"
        before = (owner.stat().st_ino, owner.read_bytes(), sentinel.stat().st_ino,
                  sentinel.read_bytes())
        for _ in range(2):
            confirmed = self.pair_transaction("released", source)
            self.assertEqual((confirmed.returncode, confirmed.stdout),
                             (0, b"released"), confirmed.stderr)
            self.assertEqual((owner.stat().st_ino, owner.read_bytes(), sentinel.stat().st_ino,
                              sentinel.read_bytes()), before)
        delayed = self.pair_transaction("claim", source)
        self.assertNotEqual(delayed.returncode, 0, "retired identity acquired the successor pair")
        self.assertEqual(delayed.stdout, b"")
        self.assertEqual((owner.stat().st_ino, owner.read_bytes(), sentinel.stat().st_ino,
                          sentinel.read_bytes()), before)

    def test_lost_source_release_reply_survives_retention_and_later_dispatchers(self):
        acquired = self.transaction("acquire")
        self.assertEqual((acquired.returncode, acquired.stdout), (0, b""), acquired.stderr)
        release = (shlex.join([FLOCK, "-x", "--", str(self.activity_lock)]) + " " +
                   self.invocation("release"))
        program = ("set -eu\n" + release +
                   " <<'RCH_SOURCE_CLAIM_ROOTS'\n" + self.roots +
                   "RCH_SOURCE_CLAIM_ROOTS\nprintf 'SOURCE_RELEASE_COMMITTED\\n'\nread -r reply\n")
        client = self.start(program)
        ready = client.line()
        if ready is None:
            stdout, stderr = client.finish()
            self.fail("source release did not commit: status={} stdout={!r} stderr={!r}".format(
                client.process.returncode, stdout, stderr))
        self.assertEqual(ready, b"SOURCE_RELEASE_COMMITTED")
        client.process.kill()
        client.finish()
        receipt = self.registry / "released" / self.active.name
        original = (receipt.stat().st_ino, receipt.read_bytes())
        old = time.time() - 3 * 24 * 60 * 60
        os.utime(receipt, (old, old))

        # A later dispatcher must still be admitted, while collection may not
        # erase the only exact retirement proof needed by the old dispatcher.
        for operation in ("acquire", "release"):
            other = self.transaction(operation, token="bb-111")
            self.assertEqual((other.returncode, other.stdout), (0, b""), other.stderr)
        for _ in range(2):
            released = self.transaction("released")
            self.assertEqual((released.returncode, released.stdout),
                             (0, b"released"), released.stderr)
            self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), original)
        delayed = self.transaction("acquire")
        self.assertEqual((delayed.returncode, delayed.stdout), (73, b""), delayed.stderr)
        self.assertIn(b"source grant already released", delayed.stderr)
        self.assertFalse(self.active.exists())
        self.assertEqual((self.source / "sentinel").read_text(), "source remains owned\n")

    def test_pair_cancellation_restart_releases_only_the_exact_old_grant(self):
        self.source = self.root / "cancelled-pair-source"
        self.roots = str(self.source) + "\n"
        self.digest = hashlib.sha256(self.roots.encode()).hexdigest()
        self.active = self.registry / (self.token + "." + self.digest + ".claim")
        pair = self.pair_transaction("claim", self.source)
        self.assertEqual((pair.returncode, pair.stdout), (0, b""), pair.stderr)
        acquired = self.transaction("acquire")
        self.assertEqual((acquired.returncode, acquired.stdout), (0, b""), acquired.stderr)
        self.source.mkdir()
        (self.source / "original").write_bytes(b"cancelled source evidence")
        cancelled = self.transaction("cancel")
        self.assertEqual((cancelled.returncode, cancelled.stdout), (0, b"owned"), cancelled.stderr)
        self.source.rename(self.root / "cancelled-pair-retired")
        released = self.pair_transaction("release", self.source)
        self.assertEqual((released.returncode, released.stdout), (0, b""), released.stderr)

        # Simulate restart after pair retirement but before finish-cancel.
        # Source ownership must still exclude another dispatcher until the
        # exact cancellation completes; free pair locks alone prove nothing.
        blocked = self.transaction("try-acquire", token="bb-111")
        self.assertEqual((blocked.returncode, blocked.stdout), (75, b""), blocked.stderr)
        incomplete = self.transaction("cancelled")
        self.assertEqual((incomplete.returncode, incomplete.stdout),
                         (0, b"pending"), incomplete.stderr)
        status, output, error = self.cancellation_state()
        self.assertEqual((status, output), (0, b"cancellation"), error)
        confirmed = self.pair_transaction("released", self.source)
        self.assertEqual((confirmed.returncode, confirmed.stdout), (0, b"released"), confirmed.stderr)
        finished = self.transaction("finish-cancel")
        self.assertEqual((finished.returncode, finished.stdout), (0, b""), finished.stderr)

        successor = self.pair_transaction("claim", self.source, "bb-111")
        self.assertEqual((successor.returncode, successor.stdout), (0, b""), successor.stderr)
        admitted = self.transaction("try-acquire", token="bb-111")
        self.assertEqual((admitted.returncode, admitted.stdout), (0, b""), admitted.stderr)
        self.source.mkdir()
        sentinel = self.source / "successor"
        sentinel.write_bytes(b"successor owns this source")
        owner = self.root / "pair.lock.owner"
        fresh = self.registry / ("bb-111." + self.digest + ".claim")
        before = [(path.stat().st_ino, path.read_bytes()) for path in (owner, fresh, sentinel)]
        for _ in range(2):
            settled = self.transaction("settle-cancel")
            self.assertEqual((settled.returncode, settled.stdout), (0, b"settled"), settled.stderr)
            pair_receipt = self.pair_transaction("released", self.source)
            self.assertEqual((pair_receipt.returncode, pair_receipt.stdout),
                             (0, b"released"), pair_receipt.stderr)
            self.assertEqual([(path.stat().st_ino, path.read_bytes())
                              for path in (owner, fresh, sentinel)], before)
        self.assertFalse(self.active.exists())
        self.assertEqual((self.registry / "cancelled" / self.active.name).read_text(), self.roots)

    def test_materialized_pair_cancellation_drains_activity_and_excludes_late_recovery(self):
        self.prepare_materialized_pair()
        activity = self.start_checked_activity()
        self.assertEqual(activity.line(), b"ACTIVITY_READY")
        before = (self.active.stat().st_ino, self.active.read_bytes())
        cancelling = self.start_cancel_waiter("initial-cancellation")
        self.assertIsNone(cancelling.line(seconds=0.25), "cancel bypassed live activity")
        self.assertFalse(self.fence.exists())
        self.assertEqual((self.active.stat().st_ino, self.active.read_bytes()), before)
        self.finish_activity(activity)
        stdout, stderr = cancelling.finish()
        self.assertEqual((cancelling.process.returncode, stdout, stderr), (0, b"owned", b""))

        # The legacy normal guard yields to this fence. Recovery must acquire
        # the cleanup-specific guard, not retry the same normal guard forever.
        normal = self.start_pair_holder(mode="pair", label="normal")
        normal.process.wait(timeout=5)
        stdout, stderr = normal.finish()
        self.assertEqual((normal.process.returncode, stdout), (75, b""), stderr)
        self.assertIn(b"yielding kernel locks", stderr)
        owned = self.pair_transaction("cancel-owned", self.source)
        self.assertEqual((owned.returncode, owned.stdout, owned.stderr), (0, b"owned", b""))
        holder = self.start_pair_holder()
        late = self.start_pair_holder(ready=False, label="concurrent-recovery")
        self.assertIsNone(late.line(seconds=0.25), "concurrent recovery bypassed the pair lock")
        blocked = self.transaction("try-acquire", token="b" * 32)
        self.assertEqual((blocked.returncode, blocked.stdout), (75, b""), blocked.stderr)

        inode = self.source.stat().st_ino
        retained = self.retain_pair_tree()
        self.assertEqual((retained.returncode, retained.stdout, retained.stderr),
                         (0, b"RCH_SOURCE_RETAINED\n", b""))
        self.assertFalse(self.source.exists())
        self.assertEqual(self.retained.stat().st_ino, inode)
        self.assertEqual(self.active.read_text(), self.roots)
        self.assertFalse((self.root / ("pair.lock.released-" + self.token)).exists())
        self.release_pair_holder(holder, queued=True)
        late.process.wait(timeout=5)
        stdout, stderr = late.finish()
        self.assertEqual((late.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"RCH_SOURCE_PAIR_OWNERSHIP_UNCONFIRMED", stderr)
        self.assertTrue(available(self.root / "pair.lock"))
        self.finish_pair_cancellation()

    def test_cleanup_pair_ssh_disconnect_before_retirement_keeps_exact_ownership(self):
        self.prepare_materialized_pair()
        cancelled = self.transaction("cancel")
        self.assertEqual((cancelled.returncode, cancelled.stdout, cancelled.stderr), (0, b"owned", b""))
        evidence = (self.active, self.fence, self.root / "pair.lock.owner", self.source / "sentinel")
        before = [(path.stat().st_ino, path.read_bytes()) for path in evidence]
        holder = self.start_pair_holder(idle=2)
        stdout, stderr = holder.finish()  # EOF without an explicit release frame.
        self.assertEqual((holder.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"RCH_SOURCE_LOCK_DISCONNECTED", stderr)
        self.assertTrue(available(self.root / "pair.lock"))
        self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in evidence], before)
        self.assertFalse(self.retained.exists())
        released = self.pair_transaction("released", self.source)
        self.assertEqual((released.returncode, released.stdout, released.stderr), (0, b"pending", b""))
        blocked = self.transaction("try-acquire", token="b" * 32)
        self.assertEqual((blocked.returncode, blocked.stdout), (75, b""), blocked.stderr)

        restarted = self.start_pair_holder(label="restarted-cleanup")
        retained = self.retain_pair_tree()
        self.assertEqual((retained.returncode, retained.stdout, retained.stderr),
                         (0, b"RCH_SOURCE_RETAINED\n", b""))
        self.release_pair_holder(restarted)
        self.finish_pair_cancellation()

    def test_cleanup_pair_transport_loss_after_retention_drains_live_cleanup_before_retry(self):
        self.prepare_materialized_pair()
        cancelled = self.transaction("cancel")
        self.assertEqual((cancelled.returncode, cancelled.stdout, cancelled.stderr), (0, b"owned", b""))
        holder = self.start_pair_holder(idle=2)
        with self.heartbeat_during_setup(holder, lock=self.root / "pair.lock"):
            cleanup = self.start_checked_activity(mode="cleanup", before=self.retention_command())
            self.assertEqual(cleanup.line(), b"RCH_SOURCE_RETAINED")
            self.assertEqual(cleanup.line(), b"ACTIVITY_READY")
        inode = self.retained.stat().st_ino
        marker = os.readlink(self.retained / ".rch-retention-v1")
        evidence = (self.active, self.fence, self.root / "pair.lock.owner", self.retained / "sentinel")
        before = [(path.stat().st_ino, path.read_bytes()) for path in evidence]
        holder.process.kill()
        holder.finish()
        eventually(lambda: available(self.root / "pair.lock"), "lost cleanup SSH retained the pair mutex")
        self.assertFalse(self.source.exists())
        self.assertIsNone(cleanup.process.poll(), "holder loss killed independent cleanup")
        self.assertFalse(available(self.activity_lock))
        retry = self.start_cancel_waiter("restarted-cancellation")
        self.assertIsNone(retry.line(seconds=0.25), "retry cancellation bypassed live cleanup")
        self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in evidence], before)
        blocked = self.transaction("try-acquire", token="b" * 32)
        self.assertEqual((blocked.returncode, blocked.stdout), (75, b""), blocked.stderr)
        self.finish_activity(cleanup)
        stdout, stderr = retry.finish()
        self.assertEqual((retry.process.returncode, stdout, stderr), (0, b"owned", b""))
        released = self.pair_transaction("released", self.source)
        self.assertEqual((released.returncode, released.stdout, released.stderr), (0, b"pending", b""))

        # This is the tree-retired/pair-not-yet-released restart frontier. Only
        # an exact cleanup guard may reconcile it. The retained tree's marker
        # independently binds the old identity and both paths.
        restarted = self.start_pair_holder(label="retired-tree-cleanup")
        wrong_identity = self.retain_pair_tree(identity="c" * 32)
        self.assertEqual(wrong_identity.returncode, 74, wrong_identity.stderr)
        self.assertIn(b"source retention marker does not bind", wrong_identity.stderr)
        wrong_root = self.retain_pair_tree(root=self.root / "another-source")
        self.assertEqual(wrong_root.returncode, 74, wrong_root.stderr)
        self.assertIn(b"source retention marker does not bind", wrong_root.stderr)
        retained = self.retain_pair_tree()
        self.assertEqual((retained.returncode, retained.stdout, retained.stderr),
                         (0, b"RCH_SOURCE_RETAINED\n", b""))
        self.assertEqual(self.retained.stat().st_ino, inode)
        self.assertEqual(os.readlink(self.retained / ".rch-retention-v1"), marker)
        self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in evidence], before)
        self.release_pair_holder(restarted)
        self.finish_pair_cancellation()

    def assert_unowned_pair_refuses_cleanup_guard(self, claim_pair):
        self.prepare_materialized_pair(pair_token="b" * 32, claim_pair=claim_pair)
        cancelled = self.transaction("cancel")
        self.assertEqual((cancelled.returncode, cancelled.stdout, cancelled.stderr), (0, b"owned", b""))
        paths = [self.active, self.fence, self.source / "sentinel"]
        if claim_pair:
            paths.append(self.root / "pair.lock.owner")
        before = [(path.stat().st_ino, path.read_bytes()) for path in paths]
        pair = self.pair_transaction("cancel-owned", self.source)
        self.assertEqual((pair.returncode, pair.stdout, pair.stderr), (0, b"unowned", b""))
        rejected = self.start_pair_holder(ready=False, label="unowned-cleanup")
        rejected.process.wait(timeout=5)
        stdout, stderr = rejected.finish()
        self.assertEqual((rejected.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"RCH_SOURCE_PAIR_OWNERSHIP_UNCONFIRMED", stderr)
        self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in paths], before)
        self.assertFalse(self.retained.exists())
        self.assertFalse((self.source / ".rch-retention-v1").is_symlink())
        self.assertFalse((self.root / ("pair.lock.released-" + self.token)).exists())
        blocked = self.transaction("try-acquire", token="c" * 32)
        self.assertEqual((blocked.returncode, blocked.stdout), (75, b""), blocked.stderr)

    def test_cancelled_source_with_other_pair_owner_cannot_recover_cleanup_guard(self):
        self.assert_unowned_pair_refuses_cleanup_guard(claim_pair=True)

    def test_cancelled_source_with_missing_pair_owner_cannot_recover_cleanup_guard(self):
        self.assert_unowned_pair_refuses_cleanup_guard(claim_pair=False)

    def test_unowned_cancellation_receipt_cannot_authorize_materialized_tree_retirement(self):
        self.prepare_materialized_pair(grant_source=False)
        sentinel = self.source / "sentinel"
        original = (self.source.stat().st_ino, sentinel.stat().st_ino, sentinel.read_bytes())
        cancelled = self.transaction("cancel")
        self.assertEqual((cancelled.returncode, cancelled.stdout, cancelled.stderr), (0, b"unowned", b""))
        pair = self.pair_transaction("cancel-unowned", self.source)
        self.assertEqual((pair.returncode, pair.stdout, pair.stderr), (0, b"unowned", b""))
        refused = self.retain_pair_tree()
        self.assertEqual(refused.returncode, 73, refused.stderr)
        self.assertIn(b"source grant is not active", refused.stderr)
        self.assertFalse(self.retained.exists())
        self.assertFalse((self.source / ".rch-retention-v1").is_symlink())
        self.assertEqual((self.source.stat().st_ino, sentinel.stat().st_ino, sentinel.read_bytes()), original)
        # Pair metadata retirement grants no permission to remove a preexisting
        # tree whose source intent never acquired a grant.
        successor = self.pair_transaction("claim", self.source, "b" * 32)
        self.assertEqual(successor.returncode, 73, successor.stderr)
        self.assertIn(b"source pair has unretired source", successor.stderr)
        self.assertEqual((self.source.stat().st_ino, sentinel.stat().st_ino, sentinel.read_bytes()), original)

    def test_cleanup_activity_refuses_mismatched_cancellation_evidence_without_mutation(self):
        self.prepare_materialized_pair()
        self.fence.write_text(str(self.root / "wrong-root") + "\n")
        evidence = (self.active, self.fence, self.root / "pair.lock.owner", self.source / "sentinel")
        before = [(path.stat().st_ino, path.read_bytes()) for path in evidence]
        retained = self.retain_pair_tree()
        self.assertEqual(retained.returncode, 73, retained.stderr)
        self.assertIn(b"source cleanup authority is absent", retained.stderr)
        cancelled = self.transaction("cancel")
        self.assertEqual((cancelled.returncode, cancelled.stdout), (73, b""), cancelled.stderr)
        self.assertEqual([(path.stat().st_ino, path.read_bytes()) for path in evidence], before)
        self.assertFalse(self.retained.exists())
        self.assertFalse((self.source / ".rch-retention-v1").is_symlink())
        self.assertFalse((self.registry / "cancelled" / self.active.name).exists())

    def test_incomplete_ssh_script_upload_does_not_hold_activity_and_late_completion_observes_cancel(self):
        acquired = self.transaction("acquire")
        self.assertEqual((acquired.returncode, acquired.stdout, acquired.stderr), (0, b"", b""))
        ran = self.root / "late-payload-ran"
        delimiter = "RCH_SOURCE_ACTIVITY_NATIVE_SSH_FIXTURE"
        uploaded = FINITE_ACTIVITY.format(
            prefix=self.activity_prefix(mode="active"),
            script="printf ran > " + QUOTE(str(ran)), delimiter=delimiter)
        # Send the entire payload except its closing heredoc and compound.
        # The first line proves the remote shell reached this incomplete
        # upload, rather than merely observing a slow SSH handshake.
        frontier = uploaded.rindex("\n" + delimiter + "\n")
        client = SshProcess(self.argv, "exec sh -s")
        self.clients.append(client)
        client.send("printf 'UPLOAD_READY\\n'\n" + uploaded[:frontier])
        self.assertEqual(client.line(), b"UPLOAD_READY")
        self.assertTrue(available(self.activity_lock), "partial upload acquired the activity mutex")
        self.assertFalse(ran.exists())
        cancelled = self.transaction("cancel")
        self.assertEqual((cancelled.returncode, cancelled.stdout, cancelled.stderr), (0, b"owned", b""))
        before = (self.active.stat().st_ino, self.active.read_bytes())
        self.assertIsNone(client.process.poll(), "fault must retain the incomplete upload")
        client.send(uploaded[frontier:])
        stdout, stderr = client.finish()
        self.assertEqual((client.process.returncode, stdout), (73, b""), stderr)
        self.assertIn(b"source grant is cancelling", stderr)
        self.assertFalse(ran.exists())
        self.assertTrue(available(self.activity_lock))
        self.assertEqual((self.active.stat().st_ino, self.active.read_bytes()), before)
        self.assert_owner_retained()

    def test_cancellation_probe_does_not_release_a_live_activity_or_its_source_grant(self):
        acquired = self.transaction("acquire")
        self.assertEqual((acquired.returncode, acquired.stdout), (0, b""), acquired.stderr)
        status, output, error = self.cancellation_state()
        self.assertEqual((status, output), (0, b"pending"), error)
        cancelled = self.transaction("cancel")
        self.assertEqual((cancelled.returncode, cancelled.stdout), (0, b"owned"), cancelled.stderr)
        fence = self.registry / (self.token + "." + self.digest + ".cancelling")
        sentinel = self.source / "sentinel"
        before = [(path.stat().st_ino, path.read_bytes()) for path in (self.active, fence, sentinel)]
        activity = self.start_activity()
        # A cancellation marker can coexist with already admitted activity or
        # cancellation cleanup. The read-only probe must report intent without
        # draining or retiring it; a positive answer is never cleanup proof.
        for _ in range(2):
            status, output, error = self.cancellation_state()
            self.assertEqual((status, output), (0, b"cancellation"), error)
            self.assertIsNone(activity.process.poll())
            self.assertFalse(available(self.activity_lock))
            self.assertEqual([(path.stat().st_ino, path.read_bytes())
                              for path in (self.active, fence, sentinel)], before)
            self.assert_owner_retained()
        status, output, error = self.cancellation_state("bb-111")
        self.assertEqual((status, output), (0, b"pending"), error)
        self.finish_activity(activity)
        self.assertEqual([(path.stat().st_ino, path.read_bytes())
                          for path in (self.active, fence, sentinel)], before)

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
