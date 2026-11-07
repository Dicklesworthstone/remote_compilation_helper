#!/usr/bin/env python3
"""Pair two real RCH pipelines over an isolated local OpenSSH worker.

This measures native local sshd/rsync/Cargo execution, not a remote fleet or a
network emulator. --delay-ms adds one fixed delay before each SSH channel or
connection request; it does not model TCP round trips, bandwidth or packet loss.
The same transport instrumentation and delay apply to both binaries. No command,
capability, disk observation, source barrier or recovery result is substituted.

Example (compile the binaries separately before running this script):
    python3 scripts/bench_exec_latency.py \
      --baseline-bin-dir /path/to/baseline-bin \
      --candidate-bin-dir /path/to/candidate-bin \
      --work-dir /path/to/writable/scratch --delay-ms 250 --persist-secs 60

Each bin directory contains rch, rchd and rch-wkr. Fixture files, keys, logs,
source trees, worker outputs and journals are retained in the printed directory.
Only processes started for these fixtures are stopped; no shared service is changed.
The host must support genuine sshd authentication and RCH's native process
identity checks. Unsupported containers fail with retained diagnostics; there
is no simulated transport or weakened process-identity fallback.
"""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time


SCRIPT = Path(__file__).resolve()
CASE_ARGUMENTS = {
    "check": ["check", "--lib", "--locked", "--offline"],
    "clippy": ["clippy", "--lib", "--locked", "--offline", "--", "-D", "warnings"],
    "build": ["build", "--bin", "rch-latency-fixture", "--locked", "--offline"],
}
SOURCE_FILES = {
    "Cargo.toml": '[package]\nname = "rch-latency-fixture"\nversion = "0.1.0"\nedition = "2024"\n',
    "Cargo.lock": 'version = 4\n\n[[package]]\nname = "rch-latency-fixture"\nversion = "0.1.0"\n',
    "src/lib.rs": "pub fn answer() -> u32 { 42 }\n",
    "src/main.rs": 'fn main() { println!("rch latency fixture: {}", rch_latency_fixture::answer()); }\n',
}


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def run(argv, *, env=None, cwd=None, timeout=30):
    result = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            f"{shlex.join(map(str, argv))}: exit {result.returncode}\n"
            f"{result.stdout.decode(errors='replace')}\n{result.stderr.decode(errors='replace')}"
        )
    return result


def stop_owned_child(child, *, interrupt_timeout=30, terminate_timeout=15, kill_timeout=5):
    """Stop/reap only our direct child, then let RCH recover its durable job."""
    for signum, timeout in (
        (signal.SIGINT, interrupt_timeout), (signal.SIGTERM, terminate_timeout),
        (signal.SIGKILL, kill_timeout),
    ):
        if child.poll() is not None:
            return child.returncode
        child.send_signal(signum)
        try:
            return child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
    raise RuntimeError(f"owned child {child.pid} could not be reaped; retain its fixture for recovery")


@contextmanager
def owned_process(argv, **kwargs):
    """Do not orphan a detached launcher when the benchmark is interrupted."""
    child = subprocess.Popen(argv, **kwargs)
    original_error = None
    try:
        yield child
    except BaseException as error:
        original_error = error
        raise
    finally:
        if child.poll() is None:
            try:
                stop_owned_child(child)
            except BaseException as error:
                if original_error is None:
                    raise
                # Keep the original failure authoritative while reporting the
                # additional cleanup failure and retaining the job journals.
                print(f"Launcher cleanup also failed: {error}", file=sys.stderr, flush=True)


def stop_fixtures(fixtures):
    """Attempt every private daemon even when another fixture's cleanup fails."""
    failures = []
    for fixture in reversed(fixtures):
        try:
            fixture.stop()
        except BaseException as error:
            failures.append({"variant": fixture.label, "error": str(error)})
            print(f"{fixture.label} cleanup failed: {error}", file=sys.stderr, flush=True)
    return failures


def write_json(path, value):
    # Each evidence file is a new checkpoint; existing logs/journals are never
    # removed or replaced to hide a failed observation.
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def event(config, **fields):
    fields.update(
        unix_ns=time.time_ns(), monotonic_ns=time.monotonic_ns(), pid=os.getpid(),
        run_id=os.environ.get("RCH_LATENCY_RUN", "setup"),
    )
    descriptor = os.open(config["events"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(descriptor, (json.dumps(fields, sort_keys=True) + "\n").encode())
    finally:
        os.close(descriptor)


def internal_mode(arguments):
    """Transport launchers exec genuine tools, retaining normal PID ownership."""
    mode, config_path, *rest = arguments
    config = json.loads(Path(config_path).read_text())
    if mode == "--worker":
        command = os.environ.get("SSH_ORIGINAL_COMMAND")
        if not command:
            raise RuntimeError("fixture accepts command channels only")
        event(config, tool="worker", operation="command",
              command_sha256=hashlib.sha256(command.encode()).hexdigest(),
              command_bytes=len(command.encode()))
        environment = dict(os.environ)
        environment.update(config["worker_env"])
        # ForceCommand changes only the private worker's environment. The
        # original SSH command and its stdin/stdout/stderr are passed intact.
        os.execve("/bin/sh", ["sh", "-c", command], environment)
    if mode == "--proxy":
        # Launching a proxy proves an attempt, not successful authentication.
        event(config, tool="connection", operation="attempt")
        os.execv(config["sshd_command"][0], config["sshd_command"])
    if mode != "--transport" or not rest:
        raise RuntimeError("invalid internal fixture invocation")
    tool, *argv = rest
    if tool == "ssh":
        # OpenSSH control socket checks/exits are local operations. Do not
        # pretend they cross the network or charge them injected latency.
        local = "-O" in argv or "-G" in argv or "-V" in argv
        operation = "local_control" if local else "request"
        delay_ms = 0.0 if local else float(os.environ.get("RCH_LATENCY_DELAY_MS", "0"))
        event(config, tool=tool, operation=operation, injected_delay_ms=delay_ms,
              argv_sha256=hashlib.sha256(b"\0".join(os.fsencode(x) for x in argv)).hexdigest())
        if delay_ms:
            time.sleep(delay_ms / 1000)
        os.execv(config["ssh"], [config["ssh"], "-F", config["ssh_config"], *argv])
    if tool == "rsync":
        operation = "version" if "--version" in argv or "-V" in argv else "transfer"
        event(config, tool=tool, operation=operation,
              argv_sha256=hashlib.sha256(b"\0".join(os.fsencode(x) for x in argv)).hexdigest())
        os.execv(config["rsync"], [config["rsync"], *argv])
    raise RuntimeError(f"unsupported transport tool: {tool}")


def request(path, line):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(path))
        client.sendall((line + "\n").encode())
        chunks = []
        while chunk := client.recv(65536):
            chunks.append(chunk)
    response = b"".join(chunks)
    if not response.startswith(b"HTTP/1.0 200 OK"):
        raise RuntimeError(f"private daemon response: {response!r}")
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


def wait_until(predicate, seconds, label):
    until = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < until:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, ValueError, RuntimeError) as error:
            last_error = error
        time.sleep(0.05)
    raise RuntimeError(f"{label}: {last_error}")


class Fixture:
    def __init__(self, label, binaries, root, args):
        self.label, self.binaries, self.args = label, binaries, args
        self.root = root / label
        self.root.mkdir(mode=0o700)
        self.socket = self.root / "run/rch.sock"
        if len(os.fsencode(self.socket)) >= 104:
            raise RuntimeError("choose a shorter --work-dir for the Unix socket path")
        self.project = self.root / "local/project"
        self.journals = self.root / "state/job-leases"
        self.process = self.log = None
        for directory in (
            "bin", "config", "state", "data", "cache", "run", "tmp", "local/project/src",
            "worker-home/.local/bin", "worker-home/.cargo/bin", "worker-config", "worker-state",
            "worker-cache", "worker-data", "worker-run", "worker-tmp", "worker-builds",
        ):
            (self.root / directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.root / "local.rch-alias").symlink_to(self.root / "local")
        for name, content in SOURCE_FILES.items():
            (self.project / name).write_text(content)
        (self.root / "worker-home/.local/bin/rch-wkr").symlink_to(binaries / "rch-wkr")
        if args.rustup:
            for name in ("rustup", "cargo", "rustc", "rustdoc", "cargo-clippy", "clippy-driver"):
                (self.root / "worker-home/.cargo/bin" / name).symlink_to(args.rustup)
        worker_path = ":".join([
            str(self.root / "worker-home/.local/bin"),
            str(args.toolchain_bin),
            str(self.root / "worker-home/.cargo/bin"),
            "/usr/local/bin", "/usr/bin", "/bin",
        ])
        user = pwd.getpwuid(os.getuid()).pw_name
        self.worker_id = f"latency-{label}"
        self.host = f"rch-latency-{label}"
        config_path = self.root / "transport.json"
        worker_env = {
            "HOME": str(self.root / "worker-home"), "PATH": worker_path,
            "RUSTUP_HOME": str(args.rustup_home), "CARGO_HOME": str(self.root / "worker-cache/cargo"),
            "RCH_CONFIG_DIR": str(self.root / "worker-config"),
            "RCH_STATE_HOME": str(self.root / "worker-state"),
            "XDG_CACHE_HOME": str(self.root / "worker-cache"),
            "XDG_DATA_HOME": str(self.root / "worker-data"),
            "XDG_STATE_HOME": str(self.root / "worker-state"),
            "XDG_RUNTIME_DIR": str(self.root / "worker-run"),
            "XDG_CONFIG_HOME": str(self.root / "worker-config"),
            "TMPDIR": str(self.root / "worker-tmp"),
            "RCH_WKR_CANONICAL_ROOT": str(self.root / "worker-builds"),
            "RCH_WKR_ALIAS_ROOT": str(self.root / "worker-alias"),
            "RCH_NO_UPDATE_CHECK": "1", "CARGO_NET_OFFLINE": "true",
        }
        server = self.root / "sshd_config"
        ssh_config = self.root / "ssh_config"
        sshd_command = [args.sshd, "-i", "-e", "-f", str(server)]
        if os.geteuid() != 0:
            sshd_command = [shutil.which("sudo") or "sudo", "-n", *sshd_command]
        self.transport_config = {
            "events": str(self.root / "transport.jsonl"), "worker_env": worker_env,
            "sshd_command": sshd_command, "ssh_config": str(ssh_config),
            "ssh": args.ssh, "rsync": args.rsync,
        }
        write_json(config_path, self.transport_config)
        for key in ("host", "client"):
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.root / key)])
        shutil.copyfile(self.root / "client.pub", self.root / "authorized_keys")
        host_key = (self.root / "host.pub").read_text().split()
        (self.root / "known_hosts").write_text(f"{self.host} {' '.join(host_key[:2])}\n")
        worker = shlex.join([sys.executable, str(SCRIPT), "--worker", str(config_path)])
        server.write_text(
            f"HostKey {self.root}/host\nAuthorizedKeysFile {self.root}/authorized_keys\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n"
            "UsePAM yes\nStrictModes no\nPermitRootLogin prohibit-password\n"
            "PrintMotd no\nPrintLastLog no\nLogLevel ERROR\n"
            f"AllowUsers {user}\nPidFile {self.root}/unused-sshd.pid\n"
            f"ForceCommand {worker}\nAcceptEnv RCH_LATENCY_RUN\n"
        )
        proxy = shlex.join([sys.executable, str(SCRIPT), "--proxy", str(config_path)])
        ssh_config.write_text(
            f"Host *\n  ProxyCommand {proxy}\n  User {user}\n"
            f"  UserKnownHostsFile {self.root}/known_hosts\n  GlobalKnownHostsFile /dev/null\n"
            "  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n  LogLevel ERROR\n"
            "  HostKeyAlgorithms ssh-ed25519\n  SendEnv RCH_LATENCY_RUN\n"
        )
        run([*sshd_command[:-4], "-t", "-f", str(server)])
        for tool in ("ssh", "rsync"):
            path = self.root / "bin" / tool
            command = shlex.join([sys.executable, str(SCRIPT), "--transport", str(config_path), tool])
            path.write_text(f'#!/bin/sh\nexec {command} "$@"\n')
            path.chmod(0o700)
        for tool in ("rch", "rchd"):
            (self.root / "bin" / tool).symlink_to(binaries / tool)
        # Only this fixture's process environment changes. The caller's HOME,
        # SSH files, RCH configuration and real daemons remain untouched.
        self.environment = {
            "PATH": str(self.root / "bin") + ":" + str(args.toolchain_bin) + ":"
                    + os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", pwd.getpwuid(os.getuid()).pw_dir),
            "RCH_CONFIG_DIR": str(self.root / "config"), "RCH_STATE_HOME": str(self.root / "state"),
            "XDG_CONFIG_HOME": str(self.root / "config"), "XDG_DATA_HOME": str(self.root / "data"),
            "XDG_STATE_HOME": str(self.root / "state"), "XDG_CACHE_HOME": str(self.root / "cache"),
            "XDG_RUNTIME_DIR": str(self.root / "run"), "TMPDIR": str(self.root / "tmp"),
            "CARGO_HOME": str(self.root / "cache/cargo"), "RUSTUP_HOME": str(args.rustup_home),
            "RCH_SOCKET_PATH": str(self.socket), "RCH_RSYNC_BIN": str(self.root / "bin/rsync"),
            "RCH_REQUIRE_REMOTE": "1", "RCH_FORCE_REMOTE": "1", "RCH_NO_UPDATE_CHECK": "1",
            "RCH_VISIBILITY": "verbose", "NO_COLOR": "1", "RUST_LOG": "info",
            "RCH_LATENCY_RUN": "daemon", "RCH_LATENCY_DELAY_MS": "0", "CARGO_NET_OFFLINE": "true",
        }
        (self.root / "config/workers.toml").write_text(
            f'[[workers]]\nid = "{self.worker_id}"\nhost = "{self.host}"\nuser = "{user}"\n'
            f'identity_file = "{self.root / "client"}"\ntotal_slots = 2\npriority = 100\n'
        )
        (self.root / "config/daemon.toml").write_text(
            "health_check_interval_secs = 30\nworker_timeout_secs = 15\nconnection_pooling = true\n"
            "[cache_cleanup]\nenabled = false\n"
        )
        persist = "" if args.persist_secs is None else f"ssh_control_persist_secs = {args.persist_secs}\n"
        (self.root / "config/config.toml").write_text(
            f'[general]\nsocket_path = "{self.socket}"\nforce_remote = true\n'
            f'[path_topology]\ncanonical_root = "{self.root / "local"}"\n'
            f'alias_root = "{self.root / "local.rch-alias"}"\n'
            f'[transfer]\nremote_base = "{self.root / "worker-builds"}"\n{persist}'
            '[output]\nvisibility = "verbose"\ncolor_mode = "never"\n'
            '[self_test]\nenabled = false\n'
            '[self_healing]\nenabled = false\n'
            '[remediation.pooled_target]\nreaper_enabled = false\n'
        )

    def start(self):
        # sshd -t validates configuration only. Exercise authentication before
        # starting RCH so missing chroot/setuid privileges are an explicit
        # unsupported-host failure, never a timing result or a fake worker.
        # RCH runs its Cargo payload through a login shell. Require that real
        # startup path to preserve the requested toolchain; do not repair the
        # PATH after login or accept a different compiler as equivalent.
        checks = ["set -eu"]
        for tool in ("rustc", "cargo"):
            expected = shlex.quote(str(self.args.toolchain_bin / tool))
            checks.append(
                f'[ "$(command -v {tool})" = {expected} ] || '
                f'{{ printf "%s\\n" "login startup hides requested {tool}" >&2; exit 78; }}'
            )
        checks += ["printf 'RCH_NATIVE_SSH_READY\\n'", "rustc -vV", "cargo -V"]
        command = shlex.join(["sh", "-lc", "; ".join(checks)])
        try:
            preflight = subprocess.run(
                [str(self.root / "bin/ssh"), "-i", str(self.root / "client"), self.host, command],
                env=dict(self.environment, RCH_LATENCY_RUN="preflight"),
                stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
            )
        except subprocess.TimeoutExpired as error:
            (self.root / "preflight.stdout").write_bytes(error.stdout or b"")
            (self.root / "preflight.stderr").write_bytes(error.stderr or b"")
            raise RuntimeError(f"native OpenSSH preflight timed out; diagnostics retained at {self.root}") from error
        (self.root / "preflight.stdout").write_bytes(preflight.stdout)
        (self.root / "preflight.stderr").write_bytes(preflight.stderr)
        expected_output = (
            "RCH_NATIVE_SSH_READY\n" + self.args.toolchain_versions["rustc"]
            + self.args.toolchain_versions["cargo"]
        ).encode()
        if preflight.returncode != 0 or preflight.stdout != expected_output:
            raise RuntimeError(
                f"native OpenSSH/toolchain preflight unavailable for {self.label}: exit {preflight.returncode}; "
                f"{preflight.stderr.decode(errors='replace')}; diagnostics retained at {self.root}"
            )
        self.log = (self.root / "daemon.log").open("xb")
        self.process = subprocess.Popen(
            [str(self.binaries / "rchd"), "--foreground", "--metrics-port", "0", "--no-hot-reload",
             "--socket", str(self.socket), "--workers-config", str(self.root / "config/workers.toml"),
             "--history-file", str(self.root / "history.jsonl")],
            env=self.environment, cwd=self.root, stdin=subprocess.DEVNULL,
            stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True,
        )

        def healthy():
            if self.process.poll() is not None:
                raise RuntimeError(f"{self.label} daemon exited: see {self.root / 'daemon.log'}")
            status = request(self.socket, "GET /status")
            workers = status.get("workers", [])
            worker = next((worker for worker in workers if worker.get("id") == self.worker_id
                           and worker.get("status") == "healthy"), None)
            capabilities = request(self.socket, "GET /workers/capabilities")
            capability = next((item for item in capabilities.get("workers", [])
                               if item.get("id") == self.worker_id
                               and item.get("capabilities", {}).get("rustc_version")), None)
            return {"status": worker, "capabilities": capability} if worker and capability else None

        status = wait_until(healthy, 60, f"{self.label} native worker readiness")
        write_json(self.root / "ready.json", status)

    def _recover_pending_jobs(self):
        # A timed-out launcher is not proof that its durable remote job ended.
        # Use the product's exact-identity cancellation/recovery path before
        # stopping the private daemon; never replay the compiler or guess a PID.
        if self.process is not None and self.process.poll() is None:
            for journal in sorted(self.journals.glob("*.json")):
                lease = json.loads(journal.read_text())
                if lease.get("terminal_acknowledged"):
                    continue
                wrapper_id = lease.get("identity", {}).get("local_wrapper_id")
                if not wrapper_id:
                    continue
                directory = self.root / f"cleanup-{wrapper_id}"
                directory.mkdir()
                outcomes = []
                for action in ("cancel", "recover"):
                    argv = [str(self.binaries / "rch"), "jobs", action, wrapper_id]
                    if action == "recover":
                        argv += ["--timeout-secs", "30"]
                    environment = dict(self.environment, RCH_LATENCY_RUN="cleanup")
                    with (directory / f"{action}.stdout").open("xb") as stdout, \
                            (directory / f"{action}.stderr").open("xb") as stderr:
                        with owned_process(argv, cwd=self.project, env=environment,
                                           stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                           start_new_session=True) as child:
                            try:
                                code = child.wait(timeout=45)
                            except subprocess.TimeoutExpired:
                                code = stop_owned_child(child, interrupt_timeout=5, terminate_timeout=10)
                        outcomes.append({"action": action, "exit_code": code})
                final = json.loads(journal.read_text())
                write_json(directory / "result.json", {"before": lease, "operations": outcomes, "after": final})
                if not final.get("terminal_acknowledged"):
                    print(f"Recovery remains unconfirmed; retain {directory} for same-identity recovery", file=sys.stderr)
        unresolved = [str(path) for path in self.journals.glob("*.json")
                      if not json.loads(path.read_text()).get("terminal_acknowledged")]
        if unresolved:
            raise RuntimeError(f"recovery remains unconfirmed; retained journals: {unresolved}")

    def stop(self):
        try:
            self._recover_pending_jobs()
        finally:
            # A corrupt journal or failed recovery command must not prevent
            # stopping our daemon, nor prevent the other fixture's teardown.
            try:
                if self.process is not None and self.process.poll() is None:
                    try:
                        request(self.socket, "POST /shutdown")
                        self.process.wait(timeout=15)
                    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
                        # The exact owned child is the fallback when its
                        # private control socket cannot acknowledge shutdown.
                        pass
                    finally:
                        if self.process.poll() is None:
                            stop_owned_child(self.process, interrupt_timeout=5)
            finally:
                if self.log is not None:
                    self.log.close()

    def events(self, run_id):
        path = Path(self.transport_config["events"])
        return [item for line in path.read_text().splitlines()
                if (item := json.loads(line)).get("run_id") == run_id] if path.exists() else []

    def sample(self, case, index, warmup=False):
        run_id = f"{case}-{'warmup' if warmup else index}"
        directory = self.root / run_id
        directory.mkdir()
        before = set(self.journals.glob("*.json"))
        source_before = {name: digest(self.project / name) for name in SOURCE_FILES}
        environment = dict(self.environment, RCH_LATENCY_RUN=run_id,
                           RCH_LATENCY_DELAY_MS=str(self.args.delay_ms))
        argv = [str(self.binaries / "rch"), "exec", "--", "cargo", *CASE_ARGUMENTS[case]]
        started = time.monotonic_ns()
        timed_out = False
        with (directory / "stdout").open("xb") as stdout, (directory / "stderr").open("xb") as stderr:
            with owned_process(argv, cwd=self.project, env=environment, stdin=subprocess.DEVNULL,
                               stdout=stdout, stderr=stderr, start_new_session=True) as child:
                try:
                    code = child.wait(timeout=self.args.timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    code = stop_owned_child(child)
        elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
        new_journals = sorted(set(self.journals.glob("*.json")) - before)
        leases = [json.loads(path.read_text()) for path in new_journals]
        history_path = self.root / "history.jsonl"
        history = [json.loads(line) for line in history_path.read_text().splitlines()] if history_path.exists() else []
        identities = {lease.get("identity", {}).get("remote_build_id") for lease in leases}
        records = [record for record in history if record.get("id") in identities]
        for name in ("history.ownership.json", "history.footprints.json"):
            path = self.root / name
            if path.exists():
                shutil.copyfile(path, directory / name)
        events = self.events(run_id)
        counts = {name: sum(item.get("tool") == tool and item.get("operation") == operation
                            for item in events) for name, tool, operation in (
            ("ssh_requests", "ssh", "request"), ("ssh_local_control", "ssh", "local_control"),
            ("connection_attempts", "connection", "attempt"), ("rsync_transfers", "rsync", "transfer"),
            ("worker_commands", "worker", "command"),
        )}
        source_after = {name: digest(self.project / name) for name in SOURCE_FILES}
        result = {
            "variant": self.label, "case": case, "sample": index, "warmup": warmup,
            "exit_code": code, "timed_out": timed_out, "wall_ms": elapsed_ms,
            "transport": counts, "injected_delay_ms": self.args.delay_ms,
            "journals": [str(path) for path in new_journals], "leases": leases, "history": records,
            "source_before": source_before, "source_after": source_after,
        }
        failures = []
        if timed_out or code != 0:
            failures.append("command did not complete successfully before its unchanged deadline")
        if len(leases) != 1 or not all(lease.get("terminal_acknowledged") and lease.get("exit_code") == 0
                                     and lease.get("worker_id") == self.worker_id for lease in leases):
            failures.append("expected one successful remote journal with terminal daemon acknowledgement")
        for lease in leases:
            recipe = lease.get("recovery") or {}
            if not (recipe.get("prepared") and recipe.get("execution_started")
                    and recipe.get("exit_code") == 0 and recipe.get("returned") == 0
                    and recipe.get("sources_released") and recipe.get("retired")):
                failures.append("durable remote completion/source retirement was not verified")
        if len(records) != 1 or any(record.get("location") != "remote" or record.get("exit_code") != 0
                                    for record in records):
            failures.append("expected one successful remote history record")
        if not counts["worker_commands"] or not counts["rsync_transfers"]:
            failures.append("native worker execution/source synchronization was not observed")
        if source_before != source_after:
            failures.append("source/lockfile contents changed")
        if case == "build" and not failures:
            binary = self.project / "target/debug/rch-latency-fixture"
            try:
                output = run([str(binary)], timeout=5)
                result["artifact_sha256"] = digest(binary)
                result["artifact_stdout"] = output.stdout.decode()
                if output.stdout != b"rch latency fixture: 42\n":
                    failures.append("retrieved executable returned incorrect output")
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                failures.append(f"retrieved executable validation failed: {error}")
        result["failures"] = failures
        write_json(directory / "result.json", result)
        print(json.dumps({"variant": self.label, "case": case, "sample": index, "warmup": warmup,
                          "wall_ms": round(elapsed_ms, 3), "transport": counts,
                          "failures": failures, "evidence": str(directory)}), flush=True)
        if failures:
            raise RuntimeError(f"{self.label} {run_id}: {'; '.join(failures)}; see {directory}")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-bin-dir", type=Path, required=True)
    parser.add_argument("--candidate-bin-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--delay-ms", type=float, default=250)
    parser.add_argument("--persist-secs", type=int)
    parser.add_argument("--cases", default="check,clippy,build")
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--toolchain-bin", type=Path, default=Path(shutil.which("rustc") or "/missing/rustc").parent)
    parser.add_argument("--rustup-home", type=Path, default=Path(os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup"))))
    parser.add_argument("--rustup", type=Path, default=Path(shutil.which("rustup")) if shutil.which("rustup") else None)
    args = parser.parse_args()
    cases = args.cases.split(",")
    if not cases or any(case not in CASE_ARGUMENTS for case in cases) or len(set(cases)) != len(cases):
        parser.error("--cases must be a unique comma-separated subset of check,clippy,build")
    if args.samples < 1 or not 0 <= args.delay_ms <= 5000 or args.timeout <= 0:
        parser.error("require samples >= 1, 0 <= delay-ms <= 5000, timeout > 0")
    if args.persist_secs is not None and args.persist_secs < 0:
        parser.error("--persist-secs must be nonnegative")
    for tool in ("ssh", "rsync", "ssh-keygen"):
        if not shutil.which(tool):
            raise RuntimeError(f"required tool unavailable: {tool}")
    args.ssh, args.rsync = shutil.which("ssh"), shutil.which("rsync")
    args.sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    args.toolchain_bin, args.rustup_home = args.toolchain_bin.resolve(), args.rustup_home.resolve()
    if args.rustup:
        args.rustup = args.rustup.resolve()
    for tool in ("rustc", "cargo"):
        executable = args.toolchain_bin / tool
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError(f"requested toolchain executable unavailable: {executable}")
    toolchain_environment = {
        "PATH": str(args.toolchain_bin) + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", pwd.getpwuid(os.getuid()).pw_dir),
        "RUSTUP_HOME": str(args.rustup_home),
    }
    args.toolchain_versions = {
        "rustc": run([str(args.toolchain_bin / "rustc"), "-vV"], env=toolchain_environment).stdout.decode(),
        "cargo": run([str(args.toolchain_bin / "cargo"), "-V"], env=toolchain_environment).stdout.decode(),
    }
    args.work_dir.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="rch-latency-", dir=args.work_dir)).resolve()
    print(f"Retaining all benchmark fixtures and evidence at {root}", flush=True)
    # sshd's privilege-separation directory is infrastructure, not a daemon.
    if not Path("/run/sshd").is_dir():
        if os.geteuid() == 0:
            Path("/run/sshd").mkdir(mode=0o755)
        else:
            run(["sudo", "-n", "mkdir", "-p", "/run/sshd"])
    binaries = {"baseline": args.baseline_bin_dir.resolve(), "candidate": args.candidate_bin_dir.resolve()}
    provenance = {label: {name: {"path": str(directory / name), "sha256": digest(directory / name)}
                          for name in ("rch", "rchd", "rch-wkr")} for label, directory in binaries.items()}
    metadata = {
        "scope": "Native isolated local OpenSSH/rsync/Cargo; fixed per-SSH-request delay, not real network RTT or fleet proof.",
        "denominator": {"samples_per_variant_per_case": args.samples, "cases": cases,
                        "warmup_runs_per_variant_per_case": 1, "measured_workload": "unchanged source after warm-up"},
        "countermetrics": ["remote terminal acknowledgement", "unchanged source", "retrieved build executable output"],
        "delay_ms": args.delay_ms, "persist_secs": args.persist_secs, "timeout_secs": args.timeout,
        "binaries": provenance, "script_sha256": digest(SCRIPT),
        "requested_toolchain_bin": str(args.toolchain_bin), "rustup_home": str(args.rustup_home),
        "connection_counter": "ProxyCommand launches (connection attempts, including failed authentication)",
        "versions": {"ssh": run([args.ssh, "-V"]).stderr.decode(),
                     "rsync": run([args.rsync, "--version"]).stdout.decode(),
                     **args.toolchain_versions},
    }
    write_json(root / "metadata.json", metadata)
    fixtures, results = [], []
    failed = False
    try:
        for label, directory in binaries.items():
            fixture = Fixture(label, directory, root, args)
            fixtures.append(fixture)
            fixture.start()
        for case in cases:
            for fixture in fixtures:
                fixture.sample(case, 0, warmup=True)
            for index in range(args.samples):
                # Balance cache/host order; each side retains its own source
                # mirror, Cargo pool and daemon across the ordinary edit loop.
                order = fixtures if index % 2 == 0 else list(reversed(fixtures))
                for fixture in order:
                    results.append(fixture.sample(case, index + 1))
        summaries = {}
        for case in cases:
            values = {label: [row for row in results if row["variant"] == label and row["case"] == case]
                      for label in binaries}
            medians = {label: statistics.median(row["wall_ms"] for row in rows) for label, rows in values.items()}
            summaries[case] = {"median_wall_ms": medians,
                               "median_reduction_ms": medians["baseline"] - medians["candidate"],
                               "transport_counts": {label: [row["transport"] for row in rows] for label, rows in values.items()}}
        after = {label: {name: digest(directory / name) for name in ("rch", "rchd", "rch-wkr")}
                 for label, directory in binaries.items()}
        if any(after[label][name] != provenance[label][name]["sha256"] for label in binaries for name in after[label]):
            raise RuntimeError("a benchmark binary changed during the paired invocation")
    except BaseException as error:
        failed = True
        write_json(root / "failure.json", {"status": "failed", "error": str(error), "completed_samples": results})
        raise
    finally:
        cleanup_failures = stop_fixtures(fixtures)
        if cleanup_failures:
            write_json(root / "cleanup-failures.json", {"status": "cleanup_unconfirmed", "failures": cleanup_failures})
            if not failed:
                raise RuntimeError(f"private fixture cleanup unconfirmed; see {root / 'cleanup-failures.json'}")
    # Passing includes teardown. A failed cancellation/recovery or daemon stop
    # must never leave a summary that a later reader could mistake for success.
    write_json(root / "summary.json", {"status": "passed", "cases": summaries, "samples": results})
    print(json.dumps({"status": "passed", "cases": summaries, "evidence": str(root)}, indent=2), flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--worker", "--proxy", "--transport"):
        internal_mode(sys.argv[1:])
    else:
        def interrupted(signum, _frame):
            raise KeyboardInterrupt(f"benchmark interrupted by signal {signum}")

        signal.signal(signal.SIGTERM, interrupted)
        main()
