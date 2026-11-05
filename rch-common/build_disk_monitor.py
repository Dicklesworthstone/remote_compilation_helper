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
import hashlib
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
# Extra learning metadata is bounded independently of the existing output
# scan. Oversized or changing trees still receive the ordinary disk guards;
# they simply cannot attest a smaller, pool-dependent reservation.
MAX_INCREMENTAL_ENTRIES = 100_000
DISK_MARKER_SUFFIX = "_DISK_BUDGET:"


class BudgetFailure(Exception):
    def __init__(self, reason, free=0, growth=0, detail="", required_growth_bytes=None):
        super().__init__(detail or reason)
        self.reason, self.free, self.growth, self.detail = reason, free, growth, detail
        self.required_growth_bytes = required_growth_bytes


def positive_int(value):
    return type(value) is int and 0 < value <= (1 << 63) - 1


def nonnegative_int(value):
    return type(value) is int and 0 <= value <= (1 << 63) - 1


def growth_buffer(budget):
    return min(256 * 1024 * 1024, max(1, budget // 16))


def validate_warm_policy(policy, budget):
    if policy is None:
        return

    def digest(value):
        return (isinstance(value, list) and len(value) == 32
                and all(type(byte) is int and 0 <= byte <= 255 for byte in value)
                and any(value))

    def pool(value):
        return (isinstance(value, dict)
                and set(value) == {"identity", "state", "retained_bytes"}
                and digest(value["identity"]) and digest(value["state"])
                and positive_int(value["retained_bytes"]))

    if (not positive_int(budget)
            or not isinstance(policy, dict)
            or set(policy) != {"cold_growth_bytes", "pools"}
            or not positive_int(policy["cold_growth_bytes"])
            or policy["cold_growth_bytes"] <= budget
            or not isinstance(policy["pools"], list) or len(policy["pools"]) != 8
            or not any(value is not None for value in policy["pools"])
            or any(value is not None and not pool(value) for value in policy["pools"])):
        raise BudgetFailure("monitor_unavailable", detail="invalid warm disk policy")
    identities = [tuple(value["identity"]) for value in policy["pools"] if value is not None]
    if len(identities) != len(set(identities)):
        raise BudgetFailure("monitor_unavailable", detail="duplicate warm disk pool identity")


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
                                except (FileNotFoundError, ProcessLookupError):
                                    pass
                except (FileNotFoundError, ProcessLookupError):
                    # An opened procfs record can return ESRCH when its task
                    # exits before read, rather than ENOENT from open.
                    pass
    elif sys.platform == "darwin":
        census = subprocess.Popen(
            ["ps", "-axo", "pid=,ppid=,pgid=,stat="], stdout=subprocess.PIPE, text=True
        )
        try:
            output, _ = census.communicate(timeout=1)
        except BaseException:
            census.kill()
            census.communicate()
            raise
        if census.returncode:
            raise subprocess.CalledProcessError(census.returncode, census.args, output)
        for line in output.splitlines():
            heartbeat()
            pid, parent, group, state = line.split()
            # This exact child has been reaped above. Its census entry is not
            # an outstanding build writer, even though ps observed itself.
            if int(pid) == census.pid:
                continue
            result[int(pid)] = {
                "pid": int(pid), "parent": int(parent), "group": int(group),
                "state": state[0], "start": None,
            }
    else:
        raise BudgetFailure("monitor_unavailable", detail="process census is unavailable")
    if os.getpid() not in result:
        raise BudgetFailure("monitor_unavailable", detail="process census omitted supervisor")
    return result


def darwin_leader_start(group, boot):
    # Native witness rejects dead/zombie leaders and rechecks birth and group
    # membership. A whole-machine ps census adds no owner identity evidence.
    witness = subprocess.check_output(
        ["rch-wkr", "process-identity", str(group)], timeout=1, text=True
    ).split()
    if len(witness) != 3 or witness[0] != boot or int(witness[2]) != group:
        raise BudgetFailure("monitor_unavailable", detail="unverified Darwin group identity")
    return witness[1]


def leader_start(group, snapshot):
    record = snapshot.get(group)
    if record is None or record["state"] in ("Z", "X"):
        raise BudgetFailure("interrupted", detail="build group leader disappeared")
    if sys.platform == "darwin":
        # ps display timestamps are too coarse to fence PID reuse. Reuse the
        # worker's native kernel birth witness, already required for recovery.
        return darwin_leader_start(group, boot_identity())
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


class OutputScan:
    def __init__(self, total, records=None, pool_state=None, pool_bytes=0, added=None):
        self.total, self.records = total, records
        self.pool_state, self.pool_bytes = pool_state, pool_bytes
        self.added = added


def output_signature(info):
    # A modified/reused inode cannot retain its old allocation credit. Merely
    # subtracting its starting size would miss replacement output after cleanup.
    # Atime is deliberately absent: reading a retained artifact is not a write.
    return (info.st_blocks * 512, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def measure_outputs(paths, target=None, baseline_records=None):
    """Allocated bytes and bounded inode evidence; never follow symlinks.

    Scan the target first so overlapping source/output roots cannot remove
    entries from its fingerprint through cross-root inode deduplication. Pool
    names and signatures are sorted only after collecting a bounded snapshot.
    Runtime additions stream against the immutable baseline even after the
    optional current snapshot exceeds its bound or loses fingerprint evidence.
    """
    total, pool_bytes, seen = 0, 0, set()
    added = 0 if baseline_records is not None else None
    records, pool_entries = {}, []
    devices = {identity[0] for identity in output_bindings(paths).values()}

    def incomplete():
        nonlocal records, pool_entries
        records, pool_entries = None, None

    def visit(name, parent=None, relative=None):
        nonlocal total, pool_bytes, added
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            identity = (info.st_dev, info.st_ino)
            signature = output_signature(info)
            if relative is not None and pool_entries is not None:
                if len(pool_entries) >= MAX_INCREMENTAL_ENTRIES:
                    incomplete()
                else:
                    pool_entries.append((relative, *identity, *signature))
            if identity in seen:
                return
            if info.st_dev not in devices:
                raise BudgetFailure("monitor_unavailable", detail="unmonitored filesystem inside output root")
            seen.add(identity)
            total += signature[0]
            if added is not None and baseline_records.get(identity) != signature:
                added += signature[0]
            if relative is not None:
                pool_bytes += signature[0]
            if records is not None:
                if len(records) >= MAX_INCREMENTAL_ENTRIES:
                    incomplete()
                else:
                    records[identity] = signature
            if stat.S_ISDIR(info.st_mode):
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    current = os.fstat(descriptor)
                    if (current.st_dev, current.st_ino) != identity:
                        raise BudgetFailure("monitor_unavailable", detail="output directory changed during scan")
                    if output_signature(current) != signature:
                        incomplete()
                    with os.scandir(descriptor) as entries:
                        for entry in entries:
                            child = None if relative is None else relative + "/" + entry.name
                            visit(entry.name, descriptor, child)
                    # A tree that changed while enumerated cannot certify an
                    # exact retained-pool proof, even if its byte total fits.
                    if output_signature(os.fstat(descriptor)) != signature:
                        incomplete()
                finally:
                    os.close(descriptor)
        except OSError as error:
            # Cargo renames and removes intermediates while compiling. A
            # disappearing managed root is separately rejected by its binding.
            if error.errno not in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
                raise
            incomplete()
    try:
        ordered = paths if target is None else list(dict.fromkeys([target] + paths))
        for path in ordered:
            visit(path, relative="." if path == target else None)
        pool_state = None
        if target is not None and pool_entries is not None:
            fingerprint = hashlib.sha256(b"rch-pool-state-v1\0")
            for entry in sorted(pool_entries):
                fingerprint.update(json.dumps(entry, separators=(",", ":")).encode("ascii"))
                fingerprint.update(b"\n")
            pool_state = list(fingerprint.digest())
        return OutputScan(total, records, pool_state, pool_bytes, added)
    finally:
        # Recursion captures this function's own cell. Break that cycle on
        # success AND failure so every scan releases its inode table promptly,
        # instead of accumulating entire trees until cyclic GC runs.
        visit = None


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
        # Counting every reservation is conservative and avoids a whole-host
        # process census on the common path. Retire records only when capacity
        # or the ledger limit requires it, using the authoritative census.
        with self.locked():
            records = self.read()
            free = monitor.sample()
            if set(free) != monitor.devices:
                raise BudgetFailure("monitor_unavailable", detail="filesystem changed before admission")

            def fits():
                return all(available >= max([monitor.floor] + [entry["floor"] for entry in records if device in entry["devices"]])
                           + monitor.budget + sum(entry["budget"] for entry in records if device in entry["devices"])
                           for device, available in free.items())

            if len(records) >= 4096 or not fits():
                groups = alive_groups(process_snapshot())
                records = [entry for entry in records if reservation_alive(entry, monitor.boot, groups)]
                free = monitor.sample()
                if set(free) != monitor.devices:
                    raise BudgetFailure("monitor_unavailable", detail="filesystem changed before admission")
            if len(records) >= 4096:
                raise BudgetFailure("monitor_unavailable", detail="worker disk ledger reservation limit")
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
        self.target = target
        self.outputs = list(dict.fromkeys([target] + (outputs or [])))
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
        identity = ["rch-pool-identity-v1", os.path.abspath(target), self.boot,
                    *self.bindings[target]]
        self.pool_identity = list(hashlib.sha256(
            json.dumps(identity, separators=(",", ":")).encode("ascii")
        ).digest())
        initial = self.scan()
        self.baseline, self.baseline_records = initial.total, initial.records
        self.baseline_pool = self.pool_observation(initial)
        self.final_pool, self.admitted_pool = self.baseline_pool, None
        self.incremental_reliable = initial.records is not None and self.baseline_pool is not None
        self.peak_added, self.unproven_baseline, self.strict_tracking = 0, 0, False
        self.peak_output, self.peak_growth = self.baseline, 0
        self.free = {}
        self.free_start, self.free_min = {}, {}
        self.floors = {device: floor for device in self.devices}
        self.previous = None

    def sample(self):
        verify_output_bindings(self.bindings)
        samples = filesystem_sample(self.paths)
        verify_output_bindings(self.bindings)
        return samples

    def scan(self):
        verify_output_bindings(self.bindings)
        result = measure_outputs(self.outputs, self.target, getattr(self, "baseline_records", None))
        verify_output_bindings(self.bindings)
        return result

    def pool_observation(self, scan):
        if scan.pool_state is None:
            return None
        return {"identity": self.pool_identity, "state": scan.pool_state,
                "retained_bytes": scan.pool_bytes}

    def require_runtime_tracking(self, required):
        if type(required) is not bool:
            raise BudgetFailure("monitor_unavailable", detail="invalid required output tracking mode")
        if required and self.baseline_records is None:
            raise BudgetFailure("monitor_unavailable", detail="bounded initial output tracking is unavailable")
        self.strict_tracking = self.strict_tracking or required

    def require_warm_pool(self, policy):
        validate_warm_policy(policy, self.budget)
        if policy is None:
            return
        if self.baseline_pool is None or self.baseline_pool not in policy["pools"]:
            raise BudgetFailure(
                "cold_required", detail="retained output pool no longer matches its warm reservation",
                required_growth_bytes=policy["cold_growth_bytes"],
            )
        # Only the attested target pool has already been funded. Source sync,
        # caches, and other roots cannot borrow its retained-artifact credit.
        # Keep a growth buffer available before installing the reservation;
        # a changed source baseline must request cold admission, not silently
        # consume the whole allowance that was selected for this build.
        unproven = self.baseline - self.baseline_pool["retained_bytes"]
        if unproven + growth_buffer(self.budget) >= self.budget:
            raise BudgetFailure(
                "cold_required",
                detail=f"unproven output baseline ({unproven} bytes) leaves insufficient warm growth allowance",
                required_growth_bytes=policy["cold_growth_bytes"],
            )
        self.unproven_baseline = unproven
        self.strict_tracking = True
        self.peak_growth = max(self.peak_growth, unproven)
        # Admission proof survives a later loss of optional learning metadata.
        # Losing that metadata must not turn confirmed completion into replay.
        self.admitted_pool = self.baseline_pool

    def admit(self):
        self.free, self.floors = Registry().admit(self)
        self.free_start, self.free_min = dict(self.free), dict(self.free)
        self.previous = (time.monotonic(), self.free)

    def observe_free(self, samples, now):
        if set(samples) != self.devices:
            raise BudgetFailure("monitor_unavailable", detail="monitored filesystem identity changed")
        for device, free in samples.items():
            self.free_min[device] = min(self.free_min.get(device, free), free)
            base = growth_buffer(self.budget)
            margin = base
            if self.previous is not None:
                previous_time, previous_samples = self.previous
                rate = max(0, previous_samples[device] - free) / max(now - previous_time, 0.001)
                margin = max(base, int(rate * 2))
            if free <= self.floors[device] + margin:
                raise BudgetFailure("free_floor", free, self.peak_growth, "protected floor or observed write-rate buffer reached")
        self.free, self.previous = samples, (now, samples)

    def observe_output(self, scan):
        self.peak_output = max(self.peak_output, scan.total)
        net_growth = max(0, scan.total - self.baseline)
        self.final_pool = self.pool_observation(scan)
        if scan.records is None or self.final_pool is None:
            self.incremental_reliable = False
        added = scan.added
        if added is None and self.baseline_records is not None and scan.records is not None:
            added = sum(signature[0] for identity, signature in scan.records.items()
                        if self.baseline_records.get(identity) != signature)
        if added is None and self.strict_tracking:
            # Never turn an already-small reservation into net-only tracking.
            # Unknown attribution receives no retained credit. Confirmed
            # completion remains possible if this conservative charge fits.
            self.incremental_reliable = False
            added = scan.total
        if added is not None:
            self.peak_added = max(self.peak_added, added)
            # Old-artifact cleanup cannot erase the new output's reservation
            # charge. Other jobs' overlapping output may be charged too, never
            # divided into unsupported per-writer attribution.
        # Preserve the unproven baseline charge even if a later scan loses
        # bounded evidence. Changed unproven inodes may be charged once at
        # admission and again as new output; that conservative aggregate can
        # exceed the largest simultaneously allocated output snapshot.
        self.peak_growth = max(
            self.peak_growth, self.unproven_baseline + max(net_growth, self.peak_added)
        )
        if self.peak_growth > self.budget:
            raise BudgetFailure("growth", min(self.free.values(), default=0), self.peak_growth, "allocated build output exceeded its reservation")

    def check_owner(self):
        if os.getppid() != self.parent:
            raise BudgetFailure("interrupted", detail="disk guardian disappeared")
        if sys.platform == "darwin":
            if darwin_leader_start(self.group, self.boot) != self.start:
                raise BudgetFailure("interrupted", detail="build group leader changed")
            return
        if sys.platform.startswith("linux"):
            try:
                snapshot = {self.group: linux_process("/proc/" + str(self.group) + "/stat")}
            except (FileNotFoundError, ProcessLookupError):
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
    if failure.reason == "cold_required":
        receipt["required_growth_bytes"] = failure.required_growth_bytes
    receipts = [(marker, receipt)]
    if started and monitor is not None:
        receipts.append(usage_receipt(marker, monitor, False))
    return receipts


def usage_receipt(marker, monitor, complete, exit_code=None):
    incremental = None
    if monitor.incremental_reliable:
        incremental = {
            "version": 1, "baseline_output_bytes": monitor.baseline,
            "peak_added_output_bytes": monitor.peak_added,
            "peak_free_drop_bytes": sum(max(0, start - monitor.free_min[device])
                                        for device, start in monitor.free_start.items()),
            "baseline_pool": monitor.baseline_pool, "final_pool": monitor.final_pool,
        }
    return (marker[:-len(DISK_MARKER_SUFFIX)] + "_DISK_USAGE:", {
        "max_growth_bytes": monitor.budget, "min_free_bytes": monitor.floor,
        "peak_output_bytes": monitor.peak_output, "peak_growth_bytes": monitor.peak_growth,
        "incremental": incremental, "admitted_pool": monitor.admitted_pool,
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
    deadline = None
    while True:
        heartbeat()
        monitor.check_owner()
        snapshot = process_snapshot(heartbeat)
        descendants = [record for record in snapshot.values()
                       if record["group"] == monitor.group and record["pid"] not in monitor.controls
                       and record["state"] not in ("Z", "X")]
        if not descendants:
            return
        # A progressing first census can be slow on a busy worker. Give the
        # writers their bounded exit window after discovering them, rather
        # than expiring it before the first signal. The guardian still fences
        # a stalled census, and completion still requires an empty census.
        if deadline is None:
            deadline = time.monotonic() + 2
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


def supervise(budget, floor, marker, target, paths, outputs, receipt_path, command, heartbeat, timeout_seconds=0, receipt_initialized=False, warm_policy=None, require_incremental_tracking=False):
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
        validate_warm_policy(warm_policy, budget)
        monitor = bounded_result(
            executor.submit(Monitor, budget, floor, target, paths, outputs),
            time.monotonic() + SCAN_DEADLINE, heartbeat,
        )
        monitor.require_warm_pool(warm_policy)
        monitor.require_runtime_tracking(require_incremental_tracking)
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


def run_guarded(budget, floor, marker, target, paths, outputs, receipt_path, command, mode, timeout_seconds=0, receipt_initialized=False, warm_policy=None, require_incremental_tracking=False):
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
        result = supervise(budget, floor, marker, target, paths, outputs, receipt_path, command, heartbeat, timeout_seconds, receipt_initialized, warm_policy, require_incremental_tracking)
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
    require_incremental_tracking = plan.get("require_incremental_tracking", False)
    if type(require_incremental_tracking) is not bool:
        raise ValueError("invalid required output tracking mode")
    return run_guarded(budget, floor, marker, target, paths, outputs, receipt_path, argv[6:], mode, timeout_seconds, receipt_initialized, plan.get("warm_policy"), require_incremental_tracking)


if __name__ == "__main__":
    os._exit(main(sys.argv[1:]))
