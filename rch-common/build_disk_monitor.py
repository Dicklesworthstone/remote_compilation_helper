"""Worker-local build disk admission and early termination (Python stdlib only).

Embedded by RCH so the SSH execution path cannot depend on an upgraded worker
binary. Polling is not a filesystem quota: fast bursts can overrun an interval,
and process groups do not contain a child deliberately starting another session.
Use the existing cgroup/service scope for that stronger process containment.
No output is removed here. Reservations are retired only after their group is
observed dead, never by TTL, PID reuse, or an incomplete directory scan.
"""

import concurrent.futures
import contextlib
import errno
import fcntl
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

POLL_SECONDS = 0.25
FREE_SAMPLE_DEADLINE = 1.0
SCAN_INTERVAL = 2.0
SCAN_DEADLINE = 30.0
HEARTBEAT_DEADLINE = 3.0
EXIT_BUDGET = 120
MAX_LEDGER_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 8192
DISK_MARKER_SUFFIX = "_DISK_BUDGET:"


class BudgetFailure(Exception):
    def __init__(self, reason, free=0, growth=0, detail=""):
        super().__init__(detail or reason)
        self.reason, self.free, self.growth, self.detail = reason, free, growth, detail


def positive_int(value):
    return type(value) is int and 0 < value <= (1 << 63) - 1


def nonnegative_int(value):
    return type(value) is int and 0 <= value <= (1 << 63) - 1


def boot_identity():
    if sys.platform.startswith("linux"):
        with open("/proc/self/status", encoding="ascii") as stream:
            namespace = [line.split()[1:] for line in stream if line.startswith("NSpid:")]
        # A foreign procfs cannot prove that a recorded process group is gone.
        if namespace != [[str(os.getpid())]]:
            raise BudgetFailure("monitor_unavailable", detail="unverified process namespace")
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as stream:
            boot = stream.read().strip()
    elif sys.platform == "darwin":
        boot = subprocess.check_output(
            ["sysctl", "-n", "kern.bootsessionuuid"], timeout=1, text=True
        ).strip().lower()
    else:
        raise BudgetFailure("monitor_unavailable", detail="unsupported worker process platform")
    if str(uuid.UUID(boot)) != boot:
        raise BudgetFailure("monitor_unavailable", detail="invalid kernel boot identity")
    return boot


def linux_process(path):
    with open(path, encoding="utf-8", errors="strict") as stream:
        data = stream.read(8192)
    prefix, sep, tail = data.rpartition(") ")
    fields = tail.split()
    if not sep or len(fields) < 20:
        raise BudgetFailure("monitor_unavailable", detail="incomplete kernel process record")
    return {
        "pid": int(prefix.split(" ", 1)[0]), "state": fields[0],
        "parent": int(fields[1]), "group": int(fields[2]), "start": fields[19],
    }


def process_snapshot(heartbeat=lambda: None):
    result = {}
    if sys.platform.startswith("linux"):
        with os.scandir("/proc") as entries:
            for entry in entries:
                # A large, progressing census is not a wedged kernel read.
                # Keep the guardian armed between records; any individual
                # scandir/read stall still receives no heartbeat and is fenced.
                heartbeat()
                if not entry.name.isdecimal():
                    continue
                try:
                    record = linux_process(entry.path + "/stat")
                    result[record["pid"]] = record
                    # A dead main thread does not prove that its sibling
                    # threads stopped writing. Linux retains their group.
                    if record["state"] in ("Z", "X"):
                        with os.scandir(entry.path + "/task") as tasks:
                            for task in tasks:
                                heartbeat()
                                try:
                                    thread = linux_process(task.path + "/stat")
                                    result[thread["pid"]] = thread
                                except FileNotFoundError:
                                    pass
                except FileNotFoundError:
                    pass
    elif sys.platform == "darwin":
        output = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,pgid=,stat="], timeout=1, text=True
        )
        for line in output.splitlines():
            heartbeat()
            pid, parent, group, state = line.split()
            result[int(pid)] = {
                "pid": int(pid), "parent": int(parent), "group": int(group),
                "state": state[0], "start": None,
            }
    else:
        raise BudgetFailure("monitor_unavailable", detail="process census is unavailable")
    if os.getpid() not in result:
        raise BudgetFailure("monitor_unavailable", detail="process census omitted supervisor")
    return result


def leader_start(group, snapshot):
    record = snapshot.get(group)
    if record is None or record["state"] in ("Z", "X"):
        raise BudgetFailure("interrupted", detail="build group leader disappeared")
    if sys.platform == "darwin":
        # ps display timestamps are too coarse to fence PID reuse. Reuse the
        # worker's native kernel birth witness, already required for recovery.
        witness = subprocess.check_output(
            ["rch-wkr", "process-identity", str(group)], timeout=1, text=True
        ).split()
        if len(witness) != 3 or witness[0] != boot_identity() or int(witness[2]) != group:
            raise BudgetFailure("monitor_unavailable", detail="unverified Darwin group identity")
        return witness[1]
    return record["start"]


def alive_groups(snapshot):
    return {record["group"] for record in snapshot.values() if record["state"] not in ("Z", "X")}


def reservation_alive(record, boot, groups):
    # A new leader at this numeric PID does not release a reservation while
    # children still occupy the original group. Live group membership wins.
    return record["boot"] == boot and record["group"] in groups


def filesystem_sample(paths):
    samples = {}
    for path in paths:
        # Bind capacity to the same directory as its device identity. Separate
        # path-based stat/statvfs calls can combine different filesystems when
        # a symlink or mount path changes between the two operations.
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            device = os.fstat(descriptor).st_dev
            info = os.fstatvfs(descriptor)
        finally:
            os.close(descriptor)
        available = info.f_bavail * info.f_frsize
        samples[device] = min(samples.get(device, available), available)
    return samples


def output_bindings(paths):
    identities = {}
    for path in paths:
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode):
            raise BudgetFailure("monitor_unavailable", detail="output root is not a physical directory")
        identities[path] = (info.st_dev, info.st_ino)
    return identities


def verify_output_bindings(identities):
    if output_bindings(identities) != identities:
        raise BudgetFailure("monitor_unavailable", detail="output root changed during execution")


def measure_outputs(paths):
    """Allocated bytes, with no symlink traversal and cross-root inode dedup."""
    total, seen = 0, set()
    devices = {identity[0] for identity in output_bindings(paths).values()}

    def visit(name, parent=None):
        nonlocal total
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            identity = (info.st_dev, info.st_ino)
            if identity in seen:
                return
            if info.st_dev not in devices:
                raise BudgetFailure("monitor_unavailable", detail="unmonitored filesystem inside output root")
            seen.add(identity)
            total += info.st_blocks * 512
            if stat.S_ISDIR(info.st_mode):
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    current = os.fstat(descriptor)
                    if (current.st_dev, current.st_ino) != identity:
                        raise BudgetFailure("monitor_unavailable", detail="output directory changed during scan")
                    with os.scandir(descriptor) as entries:
                        for entry in entries:
                            visit(entry.name, descriptor)
                finally:
                    os.close(descriptor)
        except OSError as error:
            # Cargo renames and removes intermediates while compiling. A
            # disappearing managed root is separately rejected by its binding.
            if error.errno not in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
                raise
    for path in paths:
        visit(path)
    return total


def private_regular(descriptor):
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise BudgetFailure("monitor_unavailable", detail="unsafe worker accounting file")


def atomic_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".disk-", dir=os.path.dirname(path))
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class Registry:
    def __init__(self, root=None):
        self.root = root or "/var/tmp/rch-build-disk-" + str(os.getuid())
        try:
            os.mkdir(self.root, 0o700)
        except FileExistsError:
            pass
        info = os.stat(self.root, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BudgetFailure("monitor_unavailable", detail="unsafe worker accounting directory")

    @contextlib.contextmanager
    def locked(self):
        descriptor = os.open(self.root + "/lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            private_regular(descriptor)
            deadline = time.monotonic() + 2
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise BudgetFailure("monitor_unavailable", detail="worker reservation lock deadline")
                    time.sleep(0.025)
            yield
        finally:
            os.close(descriptor)

    def read(self):
        try:
            descriptor = os.open(self.root + "/ledger.json", os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return []
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            private_regular(stream.fileno())
            source = stream.read(MAX_LEDGER_BYTES + 1)
            if len(source) > MAX_LEDGER_BYTES:
                raise BudgetFailure("monitor_unavailable", detail="worker disk ledger exceeded size limit")
            value = json.loads(source)
        if not isinstance(value, dict) or value.get("version") != 1:
            raise BudgetFailure("monitor_unavailable", detail="unrecognized worker disk ledger")
        entries = value.get("entries")
        if not isinstance(entries, list) or len(entries) > 4096:
            raise BudgetFailure("monitor_unavailable", detail="invalid worker disk ledger")
        for entry in entries:
            if (
                not isinstance(entry, dict) or not positive_int(entry.get("group"))
                or entry["group"] <= 1 or not positive_int(entry.get("budget"))
                or not nonnegative_int(entry.get("floor"))
                or not isinstance(entry.get("leader_start"), str)
                or not entry["leader_start"]
                or not isinstance(entry.get("devices"), list) or not entry["devices"]
                or any(type(device) is not int or device < 0 for device in entry["devices"])
                or not isinstance(entry.get("boot"), str)
                or str(uuid.UUID(entry["boot"])) != entry["boot"]
            ):
                raise BudgetFailure("monitor_unavailable", detail="invalid worker disk reservation")
        return entries

    def admit(self, monitor):
        # Recursive scans happen before this lock. Hold it only for a process
        # census, fresh free-space check, and atomic reservation publication.
        with self.locked():
            groups = alive_groups(process_snapshot())
            records = [entry for entry in self.read() if reservation_alive(entry, monitor.boot, groups)]
            free = monitor.sample()
            if set(free) != monitor.devices:
                raise BudgetFailure("monitor_unavailable", detail="filesystem changed before admission")
            floors = {}
            for device, available in free.items():
                same_device = [entry for entry in records if device in entry["devices"]]
                floor = max([monitor.floor] + [entry["floor"] for entry in same_device])
                required = floor + monitor.budget + sum(entry["budget"] for entry in same_device)
                if available < required:
                    raise BudgetFailure("admission", available, detail="free space cannot cover active build reservations and protected floor")
                floors[device] = floor
            records.append({
                "boot": monitor.boot, "group": monitor.group, "leader_start": monitor.start,
                "devices": sorted(monitor.devices), "budget": monitor.budget, "floor": monitor.floor,
            })
            atomic_json(self.root + "/ledger.json", {"version": 1, "entries": records})
            return free, floors


class Monitor:
    def __init__(self, budget, floor, target, paths, outputs=None):
        self.budget, self.floor = budget, floor
        self.outputs = list(dict.fromkeys(outputs if outputs is not None else [target]))
        # Every managed output volume needs both a reservation and ongoing
        # floor protection, even when a caller omitted it from its probe list.
        self.paths = list(dict.fromkeys(paths + [target] + self.outputs))
        self.bindings = output_bindings(self.outputs)
        self.boot, self.group = boot_identity(), os.getpgrp()
        if self.group <= 1:
            raise BudgetFailure("monitor_unavailable", detail="build has no isolated process group")
        snapshot = process_snapshot()
        self.start = leader_start(self.group, snapshot)
        # Keep the command's enclosing shells alive on successful completion.
        self.controls = set()
        parent = os.getpid()
        while parent in snapshot and snapshot[parent]["group"] == self.group:
            self.controls.add(parent)
            parent = snapshot[parent]["parent"]
        self.parent = os.getppid()
        self.devices = set(self.sample())
        self.baseline = self.scan()
        self.peak_output, self.peak_growth = self.baseline, 0
        self.free = {}
        self.floors = {device: floor for device in self.devices}
        self.previous = None

    def sample(self):
        verify_output_bindings(self.bindings)
        samples = filesystem_sample(self.paths)
        verify_output_bindings(self.bindings)
        return samples

    def scan(self):
        verify_output_bindings(self.bindings)
        total = measure_outputs(self.outputs)
        verify_output_bindings(self.bindings)
        return total

    def admit(self):
        self.free, self.floors = Registry().admit(self)
        self.previous = (time.monotonic(), self.free)

    def observe_free(self, samples, now):
        if set(samples) != self.devices:
            raise BudgetFailure("monitor_unavailable", detail="monitored filesystem identity changed")
        for device, free in samples.items():
            base = min(256 * 1024 * 1024, max(1, self.budget // 16))
            margin = base
            if self.previous is not None:
                previous_time, previous_samples = self.previous
                rate = max(0, previous_samples[device] - free) / max(now - previous_time, 0.001)
                margin = max(base, int(rate * 2))
            if free <= self.floors[device] + margin:
                raise BudgetFailure("free_floor", free, self.peak_growth, "protected floor or observed write-rate buffer reached")
        self.free, self.previous = samples, (now, samples)

    def observe_output(self, total):
        self.peak_output = max(self.peak_output, total)
        self.peak_growth = max(self.peak_growth, max(0, total - self.baseline))
        if self.peak_growth > self.budget:
            raise BudgetFailure("growth", min(self.free.values(), default=0), self.peak_growth, "allocated build output exceeded its reservation")

    def check_owner(self):
        if os.getppid() != self.parent:
            raise BudgetFailure("interrupted", detail="disk guardian disappeared")
        if sys.platform.startswith("linux"):
            try:
                snapshot = {self.group: linux_process("/proc/" + str(self.group) + "/stat")}
            except FileNotFoundError:
                snapshot = {}
        else:
            snapshot = process_snapshot()
        if leader_start(self.group, snapshot) != self.start:
            raise BudgetFailure("interrupted", detail="build group leader changed")


def kill_owned_group(group):
    # Our own live membership prevents PGID reuse, even after the leader died
    # or process telemetry failed. Never signal an arbitrary ledger PID/group.
    if group <= 1 or os.getpgrp() != group:
        raise BudgetFailure("monitor_unavailable", detail="lost own build process group")
    os.killpg(group, signal.SIGKILL)


def receipts_for_failure(marker, failure, budget, floor, started, monitor):
    receipt = {
        "reason": failure.reason, "free_bytes": failure.free, "growth_bytes": failure.growth,
        "max_growth_bytes": budget, "min_free_bytes": floor, "started": started,
        "detail": failure.detail[:240],
        "peak_output_bytes": monitor.peak_output if monitor is not None else None,
    }
    receipts = [(marker, receipt)]
    if started and monitor is not None:
        receipts.append(usage_receipt(marker, monitor, False))
    return receipts


def usage_receipt(marker, monitor, complete, exit_code=None):
    return (marker[:-len(DISK_MARKER_SUFFIX)] + "_DISK_USAGE:", {
        "max_growth_bytes": monitor.budget, "min_free_bytes": monitor.floor,
        "peak_output_bytes": monitor.peak_output, "peak_growth_bytes": monitor.peak_growth,
        "complete": complete, "exit_code": exit_code,
    })


def receipt_text(receipts):
    return "".join(marker + (json.dumps(value, separators=(",", ":")) if value is not None else "") + "\n" for marker, value in receipts)


def persist_receipts(path, receipts):
    descriptor, temporary = tempfile.mkstemp(prefix=".disk-receipt-", dir=os.path.dirname(path))
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(receipt_text(receipts))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def emit_receipts(receipts):
    # This is a supplement to the durable receipt. Never wait for a noisy
    # workload's full stderr before stopping its writers; restore fd flags.
    flags = fcntl.fcntl(2, fcntl.F_GETFL)
    try:
        fcntl.fcntl(2, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        with contextlib.suppress(OSError):
            os.write(2, ("\n" + receipt_text(receipts)).encode())
    finally:
        with contextlib.suppress(OSError):
            fcntl.fcntl(2, fcntl.F_SETFL, flags)


def bounded_result(future, deadline, heartbeat):
    while not future.done():
        heartbeat()
        if time.monotonic() >= deadline:
            raise BudgetFailure("monitor_unavailable", detail="disk probe or scan deadline reached")
        time.sleep(0.025)
    return future.result()


def finish_descendants(monitor, heartbeat):
    deadline = time.monotonic() + 2
    while True:
        heartbeat()
        monitor.check_owner()
        snapshot = process_snapshot(heartbeat)
        descendants = [record for record in snapshot.values()
                       if record["group"] == monitor.group and record["pid"] not in monitor.controls
                       and record["state"] not in ("Z", "X")]
        if not descendants:
            return
        for record in descendants:
            # Pin the process on Linux so a recycled numeric PID cannot receive
            # a signal between membership inspection and signal delivery.
            with contextlib.suppress(ProcessLookupError):
                if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
                    descriptor = os.pidfd_open(record["pid"])
                    try:
                        if os.getpgid(record["pid"]) == monitor.group:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    finally:
                        os.close(descriptor)
                elif os.getpgid(record["pid"]) == monitor.group:
                    # Native Unix cancellation already uses an owned group.
                    # Without pidfd, stop that still-owned group rather than
                    # risk signalling a recycled individual PID.
                    raise BudgetFailure("monitor_unavailable", detail="background writer cleanup requires whole-group cancellation")
        if time.monotonic() >= deadline:
            raise BudgetFailure("monitor_unavailable", detail="background build writers did not stop")
        time.sleep(0.025)


def supervise(budget, floor, marker, target, paths, outputs, receipt_path, command, heartbeat, timeout_seconds=0, receipt_initialized=False):
    monitor = child = None
    started = receipt_owned = False
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    try:
        if receipt_path is not None:
            if receipt_initialized:
                descriptor = os.open(receipt_path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                    private_regular(stream.fileno())
                    if stream.read(MAX_RECEIPT_BYTES + 1) != marker + "\n":
                        raise BudgetFailure("monitor_unavailable", detail="disk receipt initialization does not match this attempt")
            else:
                descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(descriptor)
            receipt_owned = True
        monitor = bounded_result(
            executor.submit(Monitor, budget, floor, target, paths, outputs),
            time.monotonic() + SCAN_DEADLINE, heartbeat,
        )
        bounded_result(executor.submit(monitor.admit), time.monotonic() + 5, heartbeat)

        def interrupted(signum, frame):
            raise BudgetFailure("interrupted", detail="supervisor received signal " + str(signum))

        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, interrupted)
        # Signal delivery can interrupt Popen after the OS created its child,
        # before Python returns it. That is possibly started, never a retryable
        # admission refusal. A group kill does not require a returned child PID.
        started = True
        heartbeat(b"S")
        execution_started = time.monotonic()
        child = subprocess.Popen(command, close_fds=True)
        free_future = executor.submit(monitor.sample)
        free_started = time.monotonic()
        scan_future = executor.submit(monitor.scan)
        scan_started = free_started
        next_scan = scan_started + SCAN_INTERVAL
        while child.poll() is None:
            heartbeat()
            monitor.check_owner()
            now = time.monotonic()
            if timeout_seconds and now - execution_started >= timeout_seconds:
                raise BudgetFailure("deadline", detail="remote execution deadline reached")
            if free_future.done():
                monitor.observe_free(free_future.result(), now)
                free_future = executor.submit(monitor.sample)
                free_started = now
            elif now - free_started > FREE_SAMPLE_DEADLINE:
                raise BudgetFailure("monitor_unavailable", detail="free-space telemetry deadline")
            if scan_future is not None:
                if scan_future.done():
                    monitor.observe_output(scan_future.result())
                    scan_future = None
                elif now - scan_started > SCAN_DEADLINE:
                    raise BudgetFailure("monitor_unavailable", detail="output scan deadline")
            if scan_future is None and now >= next_scan:
                scan_future = executor.submit(monitor.scan)
                scan_started, next_scan = now, now + SCAN_INTERVAL
            time.sleep(POLL_SECONDS)
        finish_descendants(monitor, heartbeat)
        monitor.observe_free(bounded_result(free_future, free_started + FREE_SAMPLE_DEADLINE, heartbeat), time.monotonic())
        if scan_future is not None:
            monitor.observe_output(bounded_result(scan_future, scan_started + SCAN_DEADLINE, heartbeat))
        monitor.observe_output(bounded_result(executor.submit(monitor.scan), time.monotonic() + SCAN_DEADLINE, heartbeat))
        # The in-flight free-space sample can predate the command's last writes
        # (or the entire command). A final output scan can also take seconds
        # while unrelated jobs consume this filesystem. Only a NEW probe after
        # writers stop and scanning finishes can attest the completion floor.
        monitor.observe_free(bounded_result(
            executor.submit(monitor.sample), time.monotonic() + FREE_SAMPLE_DEADLINE, heartbeat,
        ), time.monotonic())
        # Completion means the foreground command ended, remaining writers
        # stopped, and final output and free-space checks passed. A nonzero exit
        # remains a complete measurement; callers gate successful learning on
        # that independent command status.
        exit_code = child.returncode if child.returncode >= 0 else 128 - child.returncode
        receipts = [usage_receipt(marker, monitor, True, exit_code)]
        if receipt_owned:
            persist_receipts(receipt_path, receipts)
        emit_receipts(receipts)
        return exit_code
    except BaseException as error:
        try:
            failure = error if isinstance(error, BudgetFailure) else BudgetFailure("monitor_unavailable", detail=str(error))
            if failure.reason == "deadline":
                receipts = [(marker[:-len(DISK_MARKER_SUFFIX)], None)]
                if monitor is not None:
                    receipts.append(usage_receipt(marker, monitor, False))
            else:
                receipts = receipts_for_failure(marker, failure, budget, floor, started, monitor)
            # A failing filesystem can also wedge receipt fsync. Publish the
            # bounded, nonblocking failure diagnostic first so the guardian's
            # subsequent kill does not erase the reason. This is never a
            # completion acknowledgement; durable success still comes first.
            with contextlib.suppress(OSError):
                emit_receipts(receipts)
            if receipt_owned:
                with contextlib.suppress(OSError):
                    persist_receipts(receipt_path, receipts)
        finally:
            # A broken serializer, receipt writer, or diagnostic must never
            # bypass the only cleanup boundary for a possibly started child.
            if started:
                kill_owned_group(os.getpgrp())
        return EXIT_BUDGET
    finally:
        # os._exit below terminates outstanding sampler threads too. Avoid
        # cancel_futures (Python 3.9+) on workers with Python 3.8.
        executor.shutdown(wait=False)


def run_guarded(budget, floor, marker, target, paths, outputs, receipt_path, command, mode, timeout_seconds=0, receipt_initialized=False):
    if mode == "standalone":
        os.setsid()
    elif mode != "tracked":
        raise ValueError("invalid build supervisor mode")
    group, parent = os.getpgrp(), os.getppid()
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    os.set_blocking(write_fd, False)
    supervisor = os.fork()
    if supervisor == 0:
        os.close(read_fd)

        def heartbeat(value=b"H"):
            if os.getppid() != parent_guardian:
                raise BudgetFailure("interrupted", detail="disk guardian disappeared")
            with contextlib.suppress(BlockingIOError):
                os.write(write_fd, value)

        parent_guardian = os.getppid()
        result = supervise(budget, floor, marker, target, paths, outputs, receipt_path, command, heartbeat, timeout_seconds, receipt_initialized)
        os.write(write_fd, b"C")
        os._exit(result)
    os.close(write_fd)
    cancelled, started, completed = False, False, False

    def interrupted(signum, frame):
        nonlocal cancelled
        cancelled = True

    def stop(reason, **detail):
        # Diagnostics must not delay the existing kill fence. This separate
        # marker never attests disk usage or successful command completion.
        try:
            emit_receipts([(marker[:-len(DISK_MARKER_SUFFIX)] + "_DISK_GUARDIAN:", {
                "reason": reason, "started": started, **detail,
            })])
        finally:
            kill_owned_group(group)

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    last_heartbeat = time.monotonic()
    while True:
        try:
            data = os.read(read_fd, 4096)
            if data:
                started = started or b"S" in data
                completed = completed or b"C" in data
                last_heartbeat = time.monotonic()
        except BlockingIOError:
            pass
        pid, status = os.waitpid(supervisor, os.WNOHANG)
        if pid:
            # The exit can race the preceding pipe read. Consume its explicit
            # completion acknowledgement before accepting a normal exit code.
            with contextlib.suppress(BlockingIOError):
                completed = completed or b"C" in os.read(read_fd, 4096)
            if os.WIFEXITED(status) and completed:
                return os.WEXITSTATUS(status)
            stop("supervisor_exit_unconfirmed", wait_status=status)
        deadline = HEARTBEAT_DEADLINE if started else SCAN_DEADLINE + 10
        age = time.monotonic() - last_heartbeat
        if cancelled or os.getppid() != parent or age > deadline:
            # Also fences a wedged fsync/receipt or process-identity probe. A
            # missing receipt is unconfirmed execution, never safe local replay.
            reason = "cancelled" if cancelled else (
                "parent_lost" if os.getppid() != parent else "heartbeat_timeout")
            stop(reason, heartbeat_age_seconds=age)
        time.sleep(0.1)


def main(argv):
    budget, floor = int(argv[0]), int(argv[1])
    marker, target, plan, mode = argv[2], argv[3], json.loads(argv[4]), argv[5]
    if not positive_int(budget) or not nonnegative_int(floor) or not argv[6:]:
        raise ValueError("positive build budget, nonnegative floor, and command required")
    if len(marker) > 160 or not marker.endswith("_DISK_BUDGET:") or any(c.isspace() for c in marker):
        raise ValueError("invalid disk receipt marker")
    paths, outputs = plan["probe"], plan["output"]
    if any(not isinstance(items, list) or not items or len(items) > 64 for items in (paths, outputs)):
        raise ValueError("invalid disk path plan")
    if any(not isinstance(path, str) or not os.path.isabs(path) for path in paths + outputs + [target]):
        raise ValueError("disk paths must be absolute")
    receipt_path = plan.get("receipt")
    if receipt_path is not None and (not isinstance(receipt_path, str) or not os.path.isabs(receipt_path)):
        raise ValueError("disk receipt path must be absolute")
    timeout_seconds = plan.get("timeout_seconds", 0)
    if type(timeout_seconds) is not int or not 0 <= timeout_seconds <= (1 << 63) - 1:
        raise ValueError("invalid execution deadline")
    receipt_initialized = plan.get("receipt_initialized", False)
    if type(receipt_initialized) is not bool:
        raise ValueError("invalid receipt initialization mode")
    return run_guarded(budget, floor, marker, target, paths, outputs, receipt_path, argv[6:], mode, timeout_seconds, receipt_initialized)


if __name__ == "__main__":
    os._exit(main(sys.argv[1:]))
