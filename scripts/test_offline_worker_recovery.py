#!/usr/bin/env python3
"""Exercise offline-worker handling through real daemon processes and sockets.

The default transport is an instrumented SSH executable fixture: it implements
the same master/check/command process contract as OpenSSH but never contacts a
host. --openssh instead uses real OpenSSH handshakes and a local inetd sshd,
with deterministic remote command replies and a switchable ProxyCommand. Neither
mode measures actual VPN routing traffic or runs a remote compilation.

Pass --before to measure the unmodified daemon in the same invocation. The
regressions always run against --binary; baseline failures are recorded, never
treated as passing assertions. All fixtures, logs and measurements remain under
--output for diagnosis.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import itertools
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


SCRIPT = Path(__file__).resolve()


def append_event(root, **event):
    fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
    event.update(time=time.monotonic(), pid=os.getpid(), start_ticks=int(fields[19]))
    descriptor = os.open(root / "ssh-events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, (json.dumps(event) + "\n").encode())
    finally:
        os.close(descriptor)


def mode_for(root, worker):
    return json.loads((root / "modes.json").read_text())[worker]


def worker_reply(root, worker, command):
    """Deterministic worker protocol, reached through an actual SSH command."""
    health_probe = "rch_source_registry_health" in command
    append_event(root, event="command", worker=worker, command=command[:160], health_probe=health_probe)
    if health_probe:
        print("health_check")
    elif "capabilities" in command:
        print(json.dumps({
            "rustc_version": "rustc 1.100.0", "num_cpus": 64,
            "load_avg_1": 0.0, "load_avg_5": 0.0, "load_avg_15": 0.0,
            "disk_free_gb": 900.0, "disk_total_gb": 1000.0,
            "build_disk_free_gb": 900.0, "build_disk_total_gb": 1000.0,
            "projects_root_ok": True,
        }))
    elif "telemetry" in command:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        print(json.dumps({
            "version": 1, "worker_id": worker, "timestamp": now,
            "cpu": {"timestamp": now, "overall_percent": 1.0,
                    "per_core_percent": [1.0] * 64, "num_cores": 64,
                    "load_average": {"one_min": 0.0, "five_min": 0.0,
                                     "fifteen_min": 0.0,
                                     "running_processes": 1, "total_processes": 10}},
            "memory": {"timestamp": now, "total_gb": 128.0,
                       "available_gb": 120.0, "used_percent": 6.25,
                       "pressure_score": 1.0, "swap_used_gb": 0.0,
                       "dirty_mb": 0.0},
            "collection_duration_ms": 1,
        }))
    elif "echo ok" in command:
        print("ok")
    elif "rch_canary" in command or "RCH_CANARY" in command:
        print("rch_canary_ok")
    else:
        # Auxiliary inventory/cleanup calls have no side effects in this fixture.
        print("{}")


def run_proxy(root, worker):
    mode = mode_for(root, worker)
    append_event(root, event="dial", worker=worker, mode=mode)
    if mode == "refused":
        print("ssh: connect to fixture port 22: Connection refused", file=sys.stderr)
        return 255
    if mode == "blackhole":
        # Absorb the client banner but never answer. EOF ends the proxy when
        # the daemon cancels/times out its owned SSH child.
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if select.select([sys.stdin.buffer], [], [], 0.1)[0]:
                if not os.read(sys.stdin.fileno(), 65536):
                    return 0
        return 255
    os.execv(str(root / "sshd"), [str(root / "sshd"), "-i", "-e", "-f", str(root / "sshd_config")])


def fake_ssh(root, arguments):
    if "-G" in arguments:
        print("hostname none\nforkafterauthentication no")
        return 0
    control = arguments[arguments.index("-S") + 1] if "-S" in arguments else None
    if "-O" in arguments:
        operation = arguments[arguments.index("-O") + 1]
        return 0 if operation == "check" and control and Path(control).is_file() else 255
    if "-M" in arguments:
        worker = arguments[-1].rsplit("@", 1)[-1]
        mode = mode_for(root, worker)
        append_event(root, event="dial", worker=worker, mode=mode)
        if mode == "refused":
            if "-E" in arguments:
                Path(arguments[arguments.index("-E") + 1]).write_text("Connection refused\n")
            return 255
        if mode == "healthy":
            Path(control).write_text(worker)
        while True:
            time.sleep(0.1)
    if control:
        worker = Path(control).read_text()
        worker_reply(root, worker, " ".join(arguments))
        return 0
    print("fixture refused unexpected SSH invocation", arguments, file=sys.stderr)
    return 255


def request(path, line):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(path))
        client.sendall((line + "\n").encode())
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    response = b"".join(chunks)
    assert response.startswith(b"HTTP/1.0 200 OK"), response
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


def wait_until(predicate, timeout, message):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, ValueError, AssertionError) as error:
            last_error = error
        time.sleep(0.05)
    raise AssertionError(f"{message}; last error: {last_error}")


class DaemonFixture:
    def __init__(self, binary, root, *, openssh=False, recovery=3, cooldown=0,
                 health_interval=1, worker_timeout=1, modes=None, pooling=True):
        self.binary = Path(binary).resolve()
        self.root = root.resolve()
        self.root.mkdir(parents=True)
        self.socket = self.root / "daemon.sock"
        self.process = None
        self.log = None
        self.openssh = openssh
        self.selections = itertools.count()
        self.selection_durations = []
        self.modes = modes or {"offline": "refused", "healthy": "healthy"}
        self.set_modes(**self.modes)
        for directory in ("bin", "config", "state", "data", "cache", "run"):
            (self.root / directory).mkdir()
        self.environment = {
            "PATH": str(self.root / "bin") + ":/usr/bin:/bin",
            "HOME": str(self.root), "RCH_CONFIG_DIR": str(self.root / "config"),
            "RCH_STATE_HOME": str(self.root / "state"),
            "XDG_CONFIG_HOME": str(self.root / "config"),
            "XDG_DATA_HOME": str(self.root / "data"),
            "XDG_STATE_HOME": str(self.root / "state"),
            "XDG_CACHE_HOME": str(self.root / "cache"),
            "XDG_RUNTIME_DIR": str(self.root / "run"),
            "NO_COLOR": "1", "RUST_LOG": "info",
        }
        python = shlex.quote(sys.executable)
        if openssh:
            self.prepare_openssh()
            invocation = f"/usr/bin/ssh -F {shlex.quote(str(self.root / 'ssh_config'))}"
        else:
            invocation = f"{python} {shlex.quote(str(SCRIPT))} --fake-ssh {shlex.quote(str(self.root))}"
        ssh = self.root / "bin/ssh"
        ssh.write_text(f'#!/bin/sh\nexec {invocation} "$@"\n')
        ssh.chmod(0o700)
        user = pwd.getpwuid(os.getuid()).pw_name
        workers = []
        for worker in self.modes:
            workers.append(
                f'[[workers]]\nid = "{worker}"\nhost = "{worker}"\nuser = "{user}"\n'
                f'identity_file = "{self.root / "client"}"\ntotal_slots = 64\npriority = 100\n'
            )
        (self.root / "config/workers.toml").write_text("\n".join(workers))
        (self.root / "config/daemon.toml").write_text(
            f"health_check_interval_secs = {health_interval}\nworker_timeout_secs = {worker_timeout}\n"
            f"connection_pooling = {str(pooling).lower()}\n"
            "[cache_cleanup]\nenabled = false\n"
        )
        (self.root / "config/config.toml").write_text(
            f"[circuit]\nfailure_threshold = 2\nsuccess_threshold = 1\n"
            f"open_cooldown_secs = {cooldown}\nrecovery_probe_interval_secs = {recovery}\n"
            "[self_test]\nenabled = false\n"
        )

    def prepare_openssh(self):
        sshd = shutil.which("sshd") or "/usr/sbin/sshd"
        if not Path(sshd).is_file():
            raise RuntimeError("--openssh requires sshd")
        if os.geteuid() == 0 and not Path("/run/sshd").is_dir():
            raise RuntimeError("root-run OpenSSH tests require /run/sshd to exist")
        (self.root / "sshd").symlink_to(sshd)
        for key in ("host", "client"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.root / key)], check=True)
        shutil.copyfile(self.root / "client.pub", self.root / "authorized_keys")
        user = pwd.getpwuid(os.getuid()).pw_name
        command = shlex.join([sys.executable, str(SCRIPT), "--worker-command", str(self.root)])
        (self.root / "sshd_config").write_text(
            f"HostKey {self.root}/host\nAuthorizedKeysFile {self.root}/authorized_keys\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n"
            "UsePAM yes\nStrictModes no\nPermitRootLogin prohibit-password\n"
            f"AllowUsers {user}\nPidFile {self.root}/sshd.pid\nLogLevel ERROR\n"
            f"ForceCommand {command}\n"
        )
        proxy = shlex.join([sys.executable, str(SCRIPT), "--proxy", str(self.root)])
        (self.root / "ssh_config").write_text(
            f"Host *\n  ProxyCommand {proxy} %h\n  User {user}\n"
            f"  UserKnownHostsFile {self.root}/known_hosts\n  GlobalKnownHostsFile /dev/null\n"
            "  IdentitiesOnly yes\n  LogLevel ERROR\n  HostKeyAlgorithms ssh-ed25519\n"
            "  ControlMaster no\n"
        )
        subprocess.run([sshd, "-t", "-f", str(self.root / "sshd_config")], check=True)

    def set_modes(self, **changes):
        self.modes.update(changes)
        temporary = self.root / "modes.next"
        temporary.write_text(json.dumps(self.modes))
        temporary.replace(self.root / "modes.json")

    def start(self):
        self.log = (self.root / "daemon.log").open("ab")
        self.process = subprocess.Popen(
            [str(self.binary), "--foreground", "--metrics-port", "0", "--no-hot-reload",
             "--socket", str(self.socket), "--workers-config", str(self.root / "config/workers.toml"),
             "--history-file", str(self.root / "history.jsonl")],
            env=self.environment, cwd=self.root, stdin=subprocess.DEVNULL,
            stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True,
        )
        wait_until(lambda: self.request("GET /health"), 20, "daemon startup")

    def stop(self):
        if self.process is not None:
            # Killing this fixture's isolated process group represents abrupt
            # daemon restart. SSH children may have their own process groups;
            # collect those while the daemon's session identity is still live.
            groups = {self.process.pid}
            for dial in self.dials():
                if transport_stats(dial)[1]:
                    try:
                        if os.getsid(dial["pid"]) == self.process.pid:
                            groups.add(os.getpgid(dial["pid"]))
                    except ProcessLookupError:
                        pass
            for group in groups:
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.process.wait(timeout=5)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def request(self, line):
        if self.process.poll() is not None:
            raise AssertionError(f"daemon exited: {(self.root / 'daemon.log').read_text()[-8000:]}")
        return request(self.socket, line)

    def status(self, worker):
        return next(w for w in self.request("GET /status")["workers"] if w["id"] == worker)

    def events(self):
        path = self.root / "ssh-events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def dials(self, worker=None, since=0):
        return [e for e in self.events() if e["event"] == "dial" and e["time"] >= since
                and (worker is None or e["worker"] == worker)]

    def disconnect_worker(self, worker, mode):
        """Break this fixture's established transport and refuse new dials."""
        self.set_modes(**{worker: mode})
        for dial in self.dials(worker):
            if transport_stats(dial)[1]:
                try:
                    os.kill(dial["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def select(self, worker=None):
        query = f"GET /select-worker?project=offline-fixture-{next(self.selections)}&cores=1&runtime=none"
        if worker:
            query += f"&worker={worker}"
        started = time.monotonic()
        response = self.request(query)
        self.selection_durations.append(time.monotonic() - started)
        selected = response.get("worker")
        if selected:
            build_id = response.get("build_id") or selected.get("build_id")
            release = f"POST /release-worker?worker={selected['id']}&slots=1&exit_code=0"
            if build_id:
                release += f"&build_id={build_id}"
            self.request(release)
        return selected

    def observe(self, seconds, worker):
        started = time.monotonic()
        cpu_start = process_stats(self.process.pid)[0]
        log_lines_before = len((self.root / "daemon.log").read_text().splitlines())
        peak_rss = peak_live = 0
        while time.monotonic() - started < seconds:
            _, rss = process_stats(self.process.pid)
            peak_rss = max(peak_rss, rss)
            live = sum(transport_stats(e)[1] > 0 for e in self.dials(worker))
            peak_live = max(peak_live, live)
            time.sleep(0.05)
        cpu_end = process_stats(self.process.pid)[0]
        dials = self.dials(worker, started)
        spacing = [right["time"] - left["time"] for left, right in zip(dials, dials[1:])]
        return {"seconds": time.monotonic() - started, "dial_attempts": len(dials),
                "minimum_dial_spacing_seconds": min(spacing) if spacing else None,
                "sampled_peak_live_transport_processes": peak_live, "daemon_cpu_seconds": cpu_end - cpu_start,
                "peak_daemon_rss_bytes": peak_rss,
                "daemon_log_lines": len((self.root / "daemon.log").read_text().splitlines()) - log_lines_before}


def process_stats(pid, start_ticks=None):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z" or (start_ticks is not None and int(fields[19]) != start_ticks):
            return 0.0, 0
        return ((int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                int(fields[21]) * os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError, IndexError):
        return 0.0, 0


def transport_stats(event):
    # A reaped PID may later name an unrelated process. Measurements and fault
    # injection must retain the identity recorded by this fixture's own child.
    return process_stats(event["pid"], event["start_ticks"])


def binary_identity(path):
    digest = hashlib.sha256()
    with path.open("rb") as executable:
        for chunk in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path.resolve()), "sha256": digest.hexdigest()}


def run_idle_measurement(binary, root, openssh, seconds):
    fixture = DaemonFixture(binary, root, openssh=openssh, recovery=300, cooldown=900,
                            health_interval=30, modes={"offline": "refused"})
    try:
        fixture.start()
        measured = fixture.observe(seconds, "offline")
        measured["total_dial_attempts"] = len(fixture.dials("offline"))
        (root / "measurement.json").write_text(json.dumps(measured, indent=2) + "\n")
        try:
            measured["worker_status"] = fixture.status("offline")
        except (OSError, ValueError, AssertionError) as error:
            measured["status_error"] = str(error)
        try:
            response = fixture.request("POST /workers/offline/disable?reason=fixture")
            assert response.get("status") == "ok", response
        except (OSError, ValueError, AssertionError) as error:
            measured["disable_error"] = str(error)
            return measured
        # Include at least one ordinary health period in the admin-disable
        # observation; current main otherwise hides its bug for 30 seconds.
        measured["disabled"] = fixture.observe(32, "offline")
        (root / "measurement.json").write_text(json.dumps(measured, indent=2) + "\n")
        fixture.stop()
        before_restart = len(fixture.dials("offline"))
        fixture.start()
        measured["disabled_restart"] = fixture.observe(2, "offline")
        measured["disabled_restart"]["all_new_dials"] = len(fixture.dials("offline")) - before_restart
        return measured
    finally:
        fixture.stop()


def run_saturated_fleet(binary, root, openssh):
    blackholes = {f"blackhole-{index:02}": "blackhole" for index in range(14)}
    fixture = DaemonFixture(binary, root, openssh=openssh, worker_timeout=3,
                            modes={**blackholes, "healthy": "healthy"})
    stop_sampling = threading.Event()

    def live_blackholes():
        return sum(transport_stats(event)[1] > 0 for event in fixture.dials()
                   if event["worker"] in blackholes)

    def sample_occupancy():
        peak_blackholes = peak_total = 0
        while not stop_sampling.is_set():
            live = [event for event in fixture.dials() if transport_stats(event)[1]]
            peak_blackholes = max(peak_blackholes, sum(event["worker"] in blackholes for event in live))
            peak_total = max(peak_total, len(live))
            stop_sampling.wait(0.01)
        return peak_blackholes, peak_total

    try:
        fixture.start()
        with ThreadPoolExecutor(max_workers=1) as sampler:
            occupancy = sampler.submit(sample_occupancy)
            try:
                # A 3s deadline keeps saturation observable long enough to
                # exercise concurrent admissions. Other cases retain their
                # stricter 1s deadline; recovery cadence remains 3s here.
                wait_until(lambda: fixture.status("healthy")["total_slots"] > 0,
                           8, "healthy worker behind a saturated recovery queue")
                wait_until(lambda: live_blackholes() == 12, 8, "all 12 recovery permits occupied")
                saturated_before = live_blackholes()
                with ThreadPoolExecutor(max_workers=12) as executor:
                    selected = list(executor.map(lambda _: fixture.select(), range(24)))
                saturated_after = live_blackholes()
                assert saturated_before == saturated_after == 12, (saturated_before, saturated_after)
                assert all(worker and worker["id"] == "healthy" for worker in selected), selected
                heartbeat_start = time.monotonic()
                fixture.observe(2.2, "healthy")
                heartbeats = sum(event.get("health_probe", False) and event["time"] >= heartbeat_start
                                 for event in fixture.events())
                assert heartbeats >= 2, {"healthy_heartbeats": heartbeats}
            finally:
                stop_sampling.set()
            peak_blackholes, peak_total = occupancy.result()
        assert peak_blackholes == 12, {"peak_blackhole_transports": peak_blackholes}
        durations = sorted(fixture.selection_durations)
        return {
            "blackhole_workers": len(blackholes), "probe_deadline_seconds": 3,
            "sampled_peak_blackhole_transports": peak_blackholes,
            # Healthy warm telemetry/capability sessions are separate from
            # the health scheduler's 12 recovery permits.
            "sampled_peak_all_transports": peak_total,
            "blackhole_transports_before_admissions": saturated_before,
            "blackhole_transports_after_admissions": saturated_after,
            "healthy_admissions": len(selected),
            "healthy_heartbeats_in_2_2_seconds": heartbeats,
            "selection_p95_seconds": durations[int((len(durations) - 1) * 0.95)],
        }
    finally:
        stop_sampling.set()
        fixture.stop()


def run_regressions(binary, root, openssh):
    results = {}
    fixture = DaemonFixture(binary, root / "recovery", openssh=openssh)
    try:
        fixture.start()
        wait_until(lambda: fixture.status("offline")["status"].lower() == "unreachable", 12, "mark down")
        wait_until(lambda: fixture.status("healthy")["total_slots"] > 0, 8, "healthy peer capacity")
        settled = time.monotonic()
        baseline = len(fixture.dials("offline"))
        observed = fixture.observe(9.2, "offline")
        assert 2 <= observed["dial_attempts"] <= 4, observed
        assert observed["sampled_peak_live_transport_processes"] <= 1, observed
        assert observed["minimum_dial_spacing_seconds"] >= 3, observed
        results["prolonged_outage"] = observed
        # Force concurrent public admission calls while an offline recovery
        # timer is running; neither jobs nor extra probes may reach it.
        with ThreadPoolExecutor(max_workers=12) as executor:
            selected = list(executor.map(lambda _: fixture.select(), range(24)))
        assert all(worker and worker["id"] == "healthy" for worker in selected), selected
        assert len(fixture.dials("offline", settled)) <= 5, fixture.dials("offline", settled)
        results["mixed_fleet_selected"] = len(selected)
        durations = sorted(fixture.selection_durations)
        results["selection_p95_seconds"] = durations[int((len(durations) - 1) * 0.95)]
        # Operator refresh requests must share the lifecycle gate too. A
        # scheduled recovery probe may fall within this burst; it must retain
        # the same minimum cadence rather than multiply with public requests.
        refresh_started = time.monotonic()
        with ThreadPoolExecutor(max_workers=12) as executor:
            refreshed = list(executor.map(
                lambda _: fixture.request("GET /workers/capabilities?refresh=true"), range(12)))
        refresh_seconds = time.monotonic() - refresh_started
        for response in refreshed:
            offline = next(worker for worker in response["workers"] if worker["id"] == "offline")
            assert not offline["refresh"]["live"], offline
        recovery_dials = fixture.dials("offline", settled)
        spacings = [right["time"] - left["time"]
                    for left, right in zip(recovery_dials, recovery_dials[1:])]
        assert all(spacing >= 3 for spacing in spacings), recovery_dials
        refresh_dials = len(fixture.dials("offline", refresh_started))
        assert refresh_dials <= int(refresh_seconds / 3) + 1, recovery_dials
        results["concurrent_capability_refresh"] = {
            "requests": len(refreshed), "seconds": refresh_seconds,
            "offline_dial_attempts": refresh_dials,
            "minimum_dial_spacing_seconds": min(spacings) if spacings else None,
        }
        fixture.set_modes(offline="healthy")
        recovery_started = time.monotonic()
        wait_until(lambda: fixture.status("offline")["status"].lower() == "healthy"
                   and fixture.status("offline")["total_slots"] > 0, 8, "automatic recovery")
        results["recovery_latency_seconds"] = time.monotonic() - recovery_started
        assert fixture.select("offline")["id"] == "offline"
        assert len(fixture.dials("offline")) > baseline
        response = fixture.request("POST /workers/offline/disable?reason=fixture")
        assert response.get("status") == "ok", response
        disabled_count = len(fixture.dials("offline"))
        wait_until(lambda: not any(transport_stats(e)[1] for e in fixture.dials("offline")),
                   3, "disabled warm SSH sessions close")
        disabled = fixture.observe(4, "offline")
        assert disabled["dial_attempts"] == 0, disabled
        assert fixture.status("offline")["status"].lower() == "disabled"
        fixture.stop()
        fixture.start()
        restarted = fixture.observe(4, "offline")
        assert len(fixture.dials("offline")) == disabled_count, fixture.dials("offline")
        assert fixture.status("offline")["status"].lower() == "disabled"
        assert fixture.select("offline") is None
        results["disabled"] = disabled
        results["disabled_restart"] = restarted
        response = fixture.request("POST /workers/offline/enable")
        assert response.get("status") == "ok", response
        wait_until(lambda: fixture.status("offline")["status"].lower() == "healthy"
                   and fixture.status("offline")["total_slots"] > 0, 8, "explicit enable")
        assert fixture.select("offline")["id"] == "offline"
        # Exercise loss of previously warm pools as well as startup failure,
        # after this worker has been admitted and its reservation released.
        fixture.disconnect_worker("offline", "refused")
        wait_until(lambda: fixture.status("offline")["status"].lower() == "unreachable",
                   10, "established connection loss")
        assert fixture.select()["id"] == "healthy"
        assert fixture.select("offline") is None
        loss = fixture.observe(6.2, "offline")
        assert 1 <= loss["dial_attempts"] <= 3, loss
        if loss["minimum_dial_spacing_seconds"] is not None:
            assert loss["minimum_dial_spacing_seconds"] >= 3, loss
        results["established_connection_loss"] = loss
    finally:
        fixture.stop()

    fixture = DaemonFixture(binary, root / "vpn", openssh=openssh,
                            modes={"offline": "blackhole", "healthy": "healthy"})
    try:
        fixture.start()
        wait_until(lambda: fixture.status("healthy")["total_slots"] > 0, 6, "VPN peer starvation")
        assert fixture.select()["id"] == "healthy"
        wait_until(lambda: fixture.status("offline")["status"].lower() == "unreachable", 12, "VPN down marking")
        vpn = fixture.observe(8, "offline")
        assert 1 <= vpn["dial_attempts"] <= 3, vpn
        assert vpn["sampled_peak_live_transport_processes"] <= 1, vpn
        if vpn["minimum_dial_spacing_seconds"] is not None:
            assert vpn["minimum_dial_spacing_seconds"] >= 3, vpn
        results["vpn_blackhole"] = vpn
        # Disable during an actual blackhole attempt and require its process
        # to disappear, plus no reconnect after its previous deadline.
        wait_until(lambda: any(transport_stats(e)[1] for e in fixture.dials("offline")), 5, "in-flight VPN probe")
        response = fixture.request("POST /workers/offline/disable?reason=fixture")
        assert response.get("status") == "ok", response
        count = len(fixture.dials("offline"))
        wait_until(lambda: not any(transport_stats(e)[1] for e in fixture.dials("offline")), 3, "disabled SSH child cancellation")
        assert fixture.observe(4, "offline")["dial_attempts"] == 0
        assert len(fixture.dials("offline")) == count
    finally:
        fixture.stop()

    fixture = DaemonFixture(binary, root / "unpooled", openssh=openssh,
                            modes={"offline": "refused"}, pooling=False)
    try:
        fixture.start()
        wait_until(lambda: fixture.status("offline")["status"].lower() == "unreachable",
                   10, "unpooled down marking")
        unpooled = fixture.observe(6.2, "offline")
        assert 1 <= unpooled["dial_attempts"] <= 3, unpooled
        assert unpooled["sampled_peak_live_transport_processes"] <= 1, unpooled
        if unpooled["minimum_dial_spacing_seconds"] is not None:
            assert unpooled["minimum_dial_spacing_seconds"] >= 3, unpooled
        response = fixture.request("POST /workers/offline/disable?reason=fixture")
        assert response.get("status") == "ok", response
        assert fixture.observe(4, "offline")["dial_attempts"] == 0
        results["unpooled"] = unpooled
    finally:
        fixture.stop()
    results["saturated_recovery_fleet"] = run_saturated_fleet(binary, root / "saturated", openssh)
    return results


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--fake-ssh":
        return fake_ssh(Path(sys.argv[2]), sys.argv[3:])
    if len(sys.argv) > 1 and sys.argv[1] == "--proxy":
        return run_proxy(Path(sys.argv[2]), sys.argv[3])
    if len(sys.argv) > 1 and sys.argv[1] == "--worker-command":
        root = Path(sys.argv[2])
        # The dedicated sshd is scoped to one logical endpoint. All fixture
        # endpoints share the same protocol; telemetry worker_id is in argv.
        command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
        worker = "healthy"
        for candidate in json.loads((root / "modes.json").read_text()):
            if re.search(r"--worker-id[^a-zA-Z]+" + re.escape(candidate) + r"\b", command):
                worker = candidate
                break
        worker_reply(root, worker, command)
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--openssh", action="store_true")
    parser.add_argument("--measure-seconds", type=float, default=65)
    parser.add_argument("--measure-only", action="store_true")
    args = parser.parse_args()
    # Some execution sandboxes mount an outer namespace's /proc inside an
    # inner PID namespace. Numeric child PIDs would then name OTHER processes,
    # making resource/liveness measurements invalid. Refuse that environment.
    if int(Path("/proc/self/stat").read_text().split(maxsplit=1)[0]) != os.getpid():
        raise RuntimeError("offline-worker fixture needs /proc in the current PID namespace")
    root = args.output or Path(tempfile.mkdtemp(prefix="rch-offline-"))
    root.mkdir(parents=True, exist_ok=True)
    print(f"Fixture logs and measurements: {root}", flush=True)
    result = {
        "transport": "local OpenSSH with deterministic worker protocol" if args.openssh else "SSH subprocess fixture",
        "binary": binary_identity(args.binary),
        "configuration": {
            "failure_threshold": 2,
            "regression_health_interval_secs": 1,
            "regression_recovery_probe_interval_secs": 3,
            "idle_health_interval_secs": 30,
            "idle_recovery_probe_interval_secs": 300,
            "idle_open_cooldown_secs": 900,
        },
    }
    if args.before:
        result["before_binary"] = binary_identity(args.before)
        result["before"] = run_idle_measurement(args.before, root / "before", args.openssh, args.measure_seconds)
        (root / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    if args.before or args.measure_only:
        result["after"] = run_idle_measurement(args.binary, root / "after", args.openssh, args.measure_seconds)
        (root / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    if not args.measure_only:
        result["regressions"] = run_regressions(args.binary, root, args.openssh)
    (root / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    print(f"Fixture logs and measurements: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
