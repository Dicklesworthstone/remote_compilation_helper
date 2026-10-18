"""Linux force-stop protocol. Invoked only after explicit CLI force admission.

Bind a pidfd BEFORE consulting the configured socket again. A later PID reuse
cannot redirect TERM. The caller treats absence of the exact terminal receipt
as failure: this helper never removes sockets, signals numeric PIDs, escalates
to KILL, or changes admission. Python 3.9+ and Linux pidfd support are required.
"""

import json
import math
import os
import select
import signal
import socket
import stat
import struct
import sys
import time
import uuid

MAX_REPLY = 1024 * 1024


def endpoint(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError("endpoint is not a socket owned by this user")
    return (info.st_dev, info.st_ino, info.st_uid)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate daemon response field")
        result[key] = value
    return result


def process_record(pid):
    # Procfs can describe another PID namespace. Require its view of this
    # helper to match our kernel PID before consulting a numeric /proc entry.
    with open("/proc/self/stat", encoding="ascii") as source:
        if int(source.read().split("(", 1)[0]) != os.getpid():
            raise ValueError("procfs PID namespace does not match this helper")
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as source:
        boot = source.read().strip()
    if str(uuid.UUID(boot)) != boot:
        raise ValueError("invalid kernel boot identity")
    with open("/proc/{}/stat".format(pid), encoding="utf-8") as source:
        observed = source.read()
    if int(observed.split("(", 1)[0]) != pid:
        raise ValueError("process stat does not match the expected PID")
    fields = observed.rsplit(")", 1)[1].split()
    if len(fields) < 20 or not fields[19].isascii() or not fields[19].isdigit():
        raise ValueError("process birth identity is unavailable")
    return "{}:{}".format(boot, int(fields[19]))


def decode_status(payload, path, pid, incarnation):
    text = payload.decode("utf-8")
    separator = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
    header, body = text.split(separator, 1)
    status_line = header.splitlines()[0].split()
    if status_line[:2] not in (["HTTP/1.1", "200"], ["HTTP/1.0", "200"]):
        raise ValueError("daemon status was not acknowledged")
    response = json.loads(body, object_pairs_hook=unique_object)
    daemon = response["daemon"]
    if (type(daemon["pid"]) is not int or daemon["pid"] != pid
            or daemon["socket_path"] != path):
        raise ValueError("daemon status does not match the bound peer and socket")
    admission = response["admission"]
    if (admission["daemon_incarnation"] != incarnation
            or admission["success"] is not True
            or admission["admission_closed"] is not True
            or admission["shutdown_committed"] is not True):
        raise ValueError("original daemon's terminal shutdown fence is unconfirmed")


def exited(poller):
    events = poller.poll(0)
    if not events:
        return False
    flags = events[0][1]
    if flags & (select.POLLERR | select.POLLNVAL):
        raise OSError("cannot observe the bound daemon process")
    if not flags & (select.POLLIN | select.POLLHUP):
        raise OSError("unrecognized process-handle readiness")
    return True


def stop(path, pid, expected_identity, incarnation, request_timeout=5.0, exit_timeout=10.0):
    if (sys.platform != "linux" or not hasattr(os, "pidfd_open")
            or not hasattr(signal, "pidfd_send_signal")):
        raise ValueError("Linux pidfd support and Python 3.9+ are required; use --drain")
    if type(pid) is not int or pid <= 1 or pid in (os.getpid(), os.getppid()):
        raise ValueError("refusing an unsafe daemon PID")
    if (not os.path.isabs(path) or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or not math.isfinite(request_timeout) or not 0 < request_timeout <= 5
            or not math.isfinite(exit_timeout) or not 0 < exit_timeout <= 10):
        raise ValueError("invalid force-stop path or time budget")
    boot, ticks = expected_identity.split(":")
    if (str(uuid.UUID(boot)) != boot or not ticks.isascii() or not ticks.isdigit()
            or str(uuid.UUID(incarnation)) != incarnation):
        raise ValueError("invalid original daemon identity or incarnation")
    identity = endpoint(path)
    if identity is None:
        raise ValueError("daemon endpoint disappeared before force-stop binding")

    # Opening the handle comes before the fresh status exchange. If the process
    # exits at any later frontier, signalling this fd cannot hit a replacement.
    handle = os.pidfd_open(pid, 0)
    try:
        poller = select.poll()
        poller.register(handle, select.POLLIN)
        if exited(poller):
            raise ValueError("bound daemon already exited; no signal sent")
        if process_record(pid) != expected_identity:
            raise ValueError("daemon PID was recycled; no signal sent")
        deadline = time.monotonic() + request_timeout
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(request_timeout)
            peer.connect(path)
            observed_pid, uid, _gid = struct.unpack(
                "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if observed_pid != pid or uid != os.geteuid():
                raise ValueError("configured endpoint belongs to another process or user")
            if endpoint(path) != identity:
                raise ValueError("endpoint changed during force-stop binding")
            peer.settimeout(max(0.001, deadline - time.monotonic()))
            peer.sendall(b"GET /status\n")
            peer.shutdown(socket.SHUT_WR)
            payload = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("daemon status deadline expired; no signal sent")
                peer.settimeout(remaining)
                chunk = peer.recv(min(65536, MAX_REPLY + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > MAX_REPLY:
                    raise ValueError("oversized daemon status; no signal sent")
            decode_status(payload, path, pid, incarnation)
            if (endpoint(path) != identity or exited(poller)
                    or process_record(pid) != expected_identity):
                raise ValueError("daemon identity changed before TERM; no signal sent")
            # No os.kill, process-group signalling or external kill fallback.
            signal.pidfd_send_signal(handle, signal.SIGTERM, None, 0)

        deadline = time.monotonic() + exit_timeout
        while True:
            current = endpoint(path)
            if current is not None and current != identity:
                raise ValueError("replacement endpoint appeared; retained without modification")
            if exited(poller) and current is None:
                return "RCH_DAEMON_STOPPED_V1:{}\n".format(pid)
            if time.monotonic() >= deadline:
                raise TimeoutError("TERM sent but process exit and socket retirement unconfirmed; retained")
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    finally:
        os.close(handle)


def main():
    try:
        if len(sys.argv) != 5:
            raise ValueError("expected socket path, daemon PID, birth identity and incarnation")
        sys.stdout.write(stop(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        # Never emit arbitrary status bytes or an unbounded exception message.
        sys.stderr.write("RCH force-stop refused: {}\n".format(str(error)[:1024]))
        return 1


if __name__ == "__main__":
    sys.exit(main())
