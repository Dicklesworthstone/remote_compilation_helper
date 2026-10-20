#!/usr/bin/env python3
"""Query rchd's versioned, non-owning HTTP admission endpoint (Python 3.9+).

Input is the exact PreviewRequest JSON, not a shell command to execute. The
selector remains in rchd. No worker reservation, release, execution endpoint,
redirect, retry, subprocess compiler, or local-build fallback exists here.
"""

import argparse
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

ROUTE = "/admission-preview"
PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 65_536
MAX_RESPONSE_BYTES = 1_048_576
MAX_TOKEN_BYTES = 4096
MAX_PACKET_BYTES = 6 * MAX_REQUEST_BYTES + 16_384
RUNTIMES = {"none", "rust", "bun", "node", "nix", "go", "zig"}
ASSIGNED = {"success", "affinity_pinned", "affinity_fallback"}
DENIED = {"no_workers_configured", "all_workers_unreachable", "all_circuits_open",
          "all_workers_busy", "no_workers_passed_health", "all_workers_failed_preflight",
          "all_workers_failed_convergence", "no_matching_workers"}
DETAILED = {"no_admissible_workers", "no_workers_with_runtime", "selection_error"}


class PreviewError(Exception):
    """Stable, non-secret failure category; never include a remote body here."""


def fail(code):
    raise PreviewError(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate_json_field")
        result[key] = value
    return result


def decode(data):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: fail("nonfinite_json_number"))
    except (UnicodeError, ValueError, RecursionError):
        fail("invalid_json")


def encode(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    except (UnicodeError, ValueError, RecursionError):
        fail("invalid_json")


def uint(value, minimum=0):
    return type(value) is int and minimum <= value <= 0xffffffff


def text(value):
    return type(value) is str and bool(value.strip()) and "\0" not in value


def validate_request(request):
    fields = {"protocol_version", "project", "command", "estimated_cores",
              "disk_headroom_gib", "preferred_workers", "toolchain",
              "required_runtime", "job_mode", "required_tools"}
    if type(request) is not dict or request.keys() - fields:
        fail("invalid_request_fields")
    if type(request.get("protocol_version")) is not int or request["protocol_version"] != PROTOCOL_VERSION:
        fail("unsupported_protocol")
    if not text(request.get("project")) or not text(request.get("command")):
        fail("missing_project_or_command")
    if not uint(request.get("estimated_cores"), 1) or not uint(request.get("disk_headroom_gib", 0)):
        fail("invalid_resource_requirement")
    runtime = request.get("required_runtime", "none")
    if type(runtime) is not str or runtime not in RUNTIMES:
        fail("invalid_runtime")
    if type(request.get("job_mode", False)) is not bool:
        fail("invalid_job_mode")
    for field in ("preferred_workers", "required_tools"):
        values = request.get(field, [])
        if type(values) is not list or not all(text(value) for value in values):
            fail("invalid_worker_or_tool_requirement")
    toolchain = request.get("toolchain")
    if toolchain is not None:
        if (type(toolchain) is not dict or toolchain.keys() - {"channel", "date", "full_version"}
                or not text(toolchain.get("channel")) or not text(toolchain.get("full_version"))
                or (toolchain.get("date") is not None and not text(toolchain["date"]))):
            fail("invalid_toolchain")
    body = encode(request)
    if len(body) > MAX_REQUEST_BYTES:
        fail("request_too_large")
    return body


def endpoint_parts(endpoint):
    if (type(endpoint) is not str or len(endpoint) > 2048
            or any(ord(char) <= 32 or ord(char) == 127 for char in endpoint)):
        fail("invalid_endpoint")
    try:
        url = urlsplit(endpoint)
        port = url.port
        host = url.hostname
    except ValueError:
        fail("invalid_endpoint")
    if (url.scheme not in ("http", "https") or not host
            or url.username is not None or url.password is not None
            or url.path not in ("", "/") or url.query or url.fragment
            or "%" in host or "\\" in host or (port is not None and not 1 <= port <= 65535)):
        fail("invalid_endpoint")
    # Never send a bearer credential over arbitrary cleartext HTTP. A literal
    # loopback/tailnet address avoids DNS and proxy reinterpretation. HTTPS
    # permits hostnames, but retains the platform certificate/hostname checks.
    if url.scheme == "http":
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            fail("http_requires_literal_loopback_or_tailnet_address")
        if not (address.is_loopback
                or address in ipaddress.ip_network("100.64.0.0/10")
                or address in ipaddress.ip_network("fd7a:115c:a1e0::/48")):
            fail("http_requires_literal_loopback_or_tailnet_address")
    return url.scheme, host, port


def load_token(path):
    # Credentials enter through a private file, never argv, a request JSON
    # field, or an inherited proxy URL. Reject links/FIFOs before reading.
    if not all(hasattr(os, name) for name in ("O_NONBLOCK", "O_CLOEXEC", "O_NOFOLLOW", "geteuid")):
        fail("private_token_files_require_posix")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid()
                    or meta.st_mode & 0o077 or meta.st_size > MAX_TOKEN_BYTES):
                fail("token_file_not_private_regular_file")
            data = bytearray()
            while len(data) <= MAX_TOKEN_BYTES:
                chunk = os.read(fd, MAX_TOKEN_BYTES + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            os.close(fd)
        token = bytes(data).decode("ascii").strip()
    except (OSError, UnicodeError):
        fail("token_file_unavailable")
    if not token or len(data) > MAX_TOKEN_BYTES or any(not 33 <= ord(c) <= 126 for c in token):
        fail("invalid_token")
    return token


def validate_disk_budget(budget):
    # SelectedWorker carries an optional BuildDiskBudget (two u64 byte
    # counters), NOT two u32 slot counts or a reservation receipt. Retain
    # exact integers: real GiB budgets already exceed the slot field's range.
    # Do not infer a budget when absent or translate it into execution rights.
    if budget is None:
        return
    if (type(budget) is not dict or budget.keys() != {'max_growth_bytes', 'min_free_bytes'}
            or type(budget['max_growth_bytes']) is not int
            or not 1 <= budget['max_growth_bytes'] <= (1 << 64) - 1
            or type(budget['min_free_bytes']) is not int
            or not 0 <= budget['min_free_bytes'] <= (1 << 64) - 1):
        fail('invalid_disk_budget')


def validate_response(response, request):
    if type(response) is not dict or response.keys() != {"protocol_version", "selection"}:
        fail("invalid_preview_envelope")
    if type(response["protocol_version"]) is not int or response["protocol_version"] != PROTOCOL_VERSION:
        fail("unsupported_protocol")
    selection = response["selection"]
    if (type(selection) is not dict or not {"worker", "reason"} <= selection.keys()
            or selection.keys() - {"worker", "reason", "build_id", "diagnostics"}):
        fail("invalid_selection")
    if selection.get("build_id") is not None:
        fail("unexpected_execution_ownership")
    reason = selection["reason"]
    # Preserve daemon denial reasons without inventing a second recommendation
    # taxonomy. Only the three protocol success variants can mean available.
    if not ((type(reason) is str and reason in ASSIGNED | DENIED)
            or (type(reason) is dict and len(reason) == 1 and reason.keys() <= DETAILED
                and all(text(value) for value in reason.values()))):
        fail("invalid_selection_reason")
    assigned = type(reason) is str and reason in ASSIGNED
    worker = selection["worker"]
    if assigned != (worker is not None):
        fail("inconsistent_selection")
    if worker is not None:
        required = {"id", "host", "user", "identity_file", "slots_available", "speed_score"}
        if (type(worker) is not dict or not required <= worker.keys()
                or worker.keys() - required - {"declared_os", "project_lane", "disk_budget"}
                or not all(text(worker[key]) for key in ("id", "host", "user", "identity_file"))
                or not uint(worker["slots_available"])
                or not uint(worker.get("project_lane", 0))
                or type(worker["speed_score"]) not in (int, float)
                or not math.isfinite(worker["speed_score"])
                or (worker.get("declared_os") is not None and not text(worker["declared_os"]))):
            fail("invalid_selected_worker")
        validate_disk_budget(worker.get('disk_budget'))
        allowed = request.get("preferred_workers", [])
        if allowed and worker["id"] not in allowed:
            fail("worker_outside_requested_set")
        # The daemon can deliberately approve an undersized-but-free worker
        # after all hard admission gates pass. estimated_cores is not a second
        # client-side minimum: do not veto that selection or alter the request.
        # Zero free capacity is still inconsistent with an available preview.
        if worker["slots_available"] == 0:
            fail("observed_capacity_changed")
    diagnostics = selection.get("diagnostics")
    if diagnostics is not None:
        if (type(diagnostics) is not dict
                or diagnostics.get("required_runtime") != request.get("required_runtime", "none")
                or type(diagnostics.get("estimated_cores")) is not int
                or diagnostics["estimated_cores"] != request["estimated_cores"]
                or type(diagnostics.get("workers")) is not list):
            fail("inconsistent_diagnostics")
    observation = "available" if assigned else "unavailable"
    if type(reason) is dict and "selection_error" in reason:
        observation = "unknown"
    return {"protocol_version": PROTOCOL_VERSION, "observation": observation,
            "execution_authorized": False, "selection": selection}


def credential_in_response(response, token):
    if token is None:
        return False
    # Inspect decoded strings, including diagnostic object keys. A token with
    # a quote/backslash is escaped by JSON serialization, so searching only the
    # output bytes does not detect its disclosure. An explicit stack avoids
    # adding another recursion limit to the bounded, already-decoded document.
    pending = [response]
    while pending:
        value = pending.pop()
        if type(value) is str:
            if token in value:
                return True
        elif type(value) is dict:
            pending.extend(value.keys())
            pending.extend(value.values())
        elif type(value) is list:
            pending.extend(value)
    # Preserve the previous serialized-byte check too (including literal
    # appearances outside string values); this is not a relaxation of it.
    return token.encode("ascii") in encode(response)


def transport(packet):
    request = packet["request"]
    body = validate_request(request)
    scheme, host, port = endpoint_parts(packet["endpoint"])
    token = packet["token"]
    if token is not None and (not text(token) or any(not 33 <= ord(c) <= 126 for c in token)):
        fail("invalid_token")
    if scheme == "https":
        connection = http.client.HTTPSConnection(host, port, timeout=30,
                                                 context=ssl.create_default_context())
    else:
        connection = http.client.HTTPConnection(host, port, timeout=30)
    try:
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "Accept-Encoding": "identity", "Connection": "close"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        connection.request("POST", ROUTE, body=body, headers=headers)
        reply = connection.getresponse()
        # Do not follow redirects or even read arbitrary error bodies. A 429
        # means the observation is unknown, NOT that the fleet is out of slots.
        if reply.status != 200:
            fail("http_" + str(reply.status))
        for key in ("Content-Type", "Content-Encoding", "Content-Length", "Transfer-Encoding"):
            if len(reply.headers.get_all(key, [])) > 1:
                fail("ambiguous_http_headers")
        if reply.getheader("Content-Encoding", "identity").lower() != "identity":
            fail("unsupported_content_encoding")
        if reply.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            fail("unexpected_content_type")
        length = reply.getheader("Content-Length")
        transfer = reply.getheader("Transfer-Encoding")
        if transfer is not None and (transfer.lower() != "chunked" or length is not None):
            fail("ambiguous_http_framing")
        if length is not None and (not length.isascii() or not length.isdecimal()
                                   or len(length) > 10 or int(length) > MAX_RESPONSE_BYTES):
            fail("response_too_large_or_invalid_length")
        data = reply.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            fail("response_too_large")
        if length is not None and len(data) != int(length):
            fail("incomplete_response")
        response = validate_response(decode(data), request)
        # A reflected credential must never be emitted even by a malformed or
        # misconfigured authenticated peer. Diagnostics remain otherwise intact.
        if credential_in_response(response, token):
            fail("credential_in_response")
        return response
    finally:
        connection.close()


def watch_owner(descriptor):
    # Only the parent owns the write end. EOF also arrives on SIGKILL or an
    # abrupt parent exit, unlike Python exception/finally cleanup. No PID
    # polling or signal to an unrelated process is needed. The helper has no
    # children and owns no build; exiting closes its network connection.
    try:
        while os.read(descriptor, 1):
            pass
    finally:
        os._exit(2)


def transport_main(owner_descriptor):
    threading.Thread(target=watch_owner, args=(owner_descriptor,), daemon=True).start()
    try:
        data = sys.stdin.buffer.read(MAX_PACKET_BYTES + 1)
        if len(data) > MAX_PACKET_BYTES:
            fail("request_too_large")
        result = transport(decode(data))
        data = encode(result)
        if len(data) > MAX_RESPONSE_BYTES:
            fail("response_too_large")
    except PreviewError as error:
        data = encode({"error": str(error)})
    except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException):
        data = encode({"error": "transport_failure"})
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def observe(endpoint, request, token, timeout_seconds):
    validate_request(request)
    endpoint_parts(endpoint)
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0.05 <= timeout_seconds <= 30):
        fail("invalid_timeout")
    packet = encode({"endpoint": endpoint, "request": request, "token": token})
    # A socket timeout restarts on every successful read and does not bound
    # resolver calls. One directly owned helper process gives the parent a
    # deadline over DNS, connect, TLS, headers and trickled response bytes.
    deadline = time.monotonic() + timeout_seconds
    if os.name != "posix":
        fail("unsupported_platform")
    owner_read, owner_write = os.pipe()
    try:
        try:
            # Isolated mode alone still processes environment site-packages
            # and their executable .pth hooks. The helper needs only stdlib;
            # unrelated startup code must not spend its deadline or run here.
            child = subprocess.Popen(
                [sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--_transport", str(owner_read)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=(owner_read,))
        finally:
            os.close(owner_read)
        try:
            remaining = max(0, deadline - time.monotonic())
            data, _ = child.communicate(packet, timeout=remaining)
        except subprocess.TimeoutExpired:
            # Only our direct helper; it never spawns descendants or runs a build.
            child.kill()
            child.communicate()
            fail("observation_timeout")
        except BaseException:
            child.kill()
            child.communicate()
            raise
    finally:
        os.close(owner_write)
    if child.returncode != 0 or len(data) > MAX_RESPONSE_BYTES:
        fail("transport_failure")
    result = decode(data)
    if type(result) is dict and result.keys() == {"error"} and text(result["error"]):
        fail(result["error"])
    # The helper validated the full response. Recheck the IPC envelope without
    # interpreting the daemon's recommendation/denial taxonomy in the parent.
    if (type(result) is not dict or result.get("execution_authorized") is not False
            or result.get("observation") not in ("available", "unavailable", "unknown")):
        fail("invalid_helper_response")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, help="rchd API origin, with no path or query")
    credentials = parser.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--token-file", help="same-user private regular file containing the API token")
    credentials.add_argument("--no-token", action="store_true", help="explicitly use an operator-configured unauthenticated API")
    parser.add_argument("--request", default="-", help="PreviewRequest JSON file; - reads stdin")
    parser.add_argument("--timeout", type=float, default=3.0, help="whole observation deadline in seconds, 0.05..30 (default 3)")
    args = parser.parse_args(argv)
    try:
        endpoint_parts(args.endpoint)
        if args.request == "-":
            data = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        else:
            with open(args.request, "rb") as source:
                data = source.read(MAX_REQUEST_BYTES + 1)
        if len(data) > MAX_REQUEST_BYTES:
            fail("request_too_large")
        request = decode(data)
        validate_request(request)
        token = load_token(args.token_file) if args.token_file is not None else None
        result = observe(args.endpoint, request, token, args.timeout)
        status = {"available": 0, "unavailable": 1, "unknown": 2}[result["observation"]]
    except PreviewError as error:
        result = {"protocol_version": PROTOCOL_VERSION, "observation": "unknown",
                  "execution_authorized": False, "error": str(error)}
        status = 2
    except (OSError, UnicodeError, ValueError):
        result = {"protocol_version": PROTOCOL_VERSION, "observation": "unknown",
                  "execution_authorized": False, "error": "local_input_unavailable"}
        status = 2
    try:
        sys.stdout.buffer.write(encode(result) + b"\n")
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        return 2
    return status


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--_transport":
        descriptor = int(sys.argv[2])
        if descriptor <= 2 or not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
            raise SystemExit(2)
        transport_main(descriptor)
    else:
        raise SystemExit(main())
