#!/usr/bin/env python3
"""Native client checks with real HTTP, TLS, subprocesses and deadlines.

The HTTP peer supplies explicit protocol fixtures; it is not a running rchd
or a substitute for Rust integration/fleet qualification. No worker is used,
no compiler runs, and test-owned temporary directories are retained.
"""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / 'scripts/rch-admission-preview.py'
spec = importlib.util.spec_from_file_location('admission_client', SCRIPT)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def request():
    return {
        'protocol_version': 1, 'project': 'project with spaces',
        'command': "env NOTE='a&b=+%? λ' cargo +nightly check\n",
        'estimated_cores': 3, 'disk_headroom_gib': 21,
        'preferred_workers': ['wanted', 'also-wanted'],
        'toolchain': {'channel': 'nightly', 'date': '2026-09-01', 'full_version': 'rustc exact'},
        'required_runtime': 'rust', 'job_mode': True,
        'required_tools': ['clang', 'llvm-ar'],
    }


def reply(worker='wanted', reason='success'):
    return {'protocol_version': 1, 'selection': {
        'worker': None if worker is None else {
            'id': worker, 'host': 'worker.example', 'user': 'builder',
            'identity_file': '/worker/key', 'slots_available': 4,
            'speed_score': 92.5, 'declared_os': 'linux', 'project_lane': 2,
        },
        'reason': reason,
    }}


class Peer:
    def __init__(self, response=None, status=200, raw=None, headers=None, delay=False, drip=False,
                 tls=None, hold_headers=False, raw_headers=None):
        self.requests = []
        self.connected = threading.Event()
        self.disconnected = threading.Event()
        self.stop = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_args):
                pass

            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length)
                owner.requests.append((self.command, self.path, dict(self.headers), body))
                owner.connected.set()
                if delay:
                    self.connection.settimeout(0.1)
                    while not owner.stop.is_set():
                        try:
                            if not self.connection.recv(1):
                                owner.disconnected.set()
                                return
                        except socket.timeout:
                            continue
                        except OSError:
                            owner.disconnected.set()
                            return
                    return
                data = raw if raw is not None else client.encode(response if response is not None else reply())
                try:
                    if hold_headers:
                        self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Trickle: ')
                        self.wfile.flush()
                        while not owner.stop.wait(0.025):
                            self.wfile.write(b'x')
                            self.wfile.flush()
                        return
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/json')
                    if not raw_headers or not any(k.lower() in ('content-length', 'transfer-encoding') for k, _ in raw_headers):
                        self.send_header('Content-Length', str(len(data)))
                    self.send_header('Connection', 'close')
                    for key, value in (headers or {}).items():
                        self.send_header(key, value)
                    for key, value in (raw_headers or []):
                        self.send_header(key, value)
                    self.end_headers()
                    if drip:
                        for byte in data:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            if owner.stop.wait(0.025):
                                return
                    else:
                        self.wfile.write(data)
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    self.close_connection = True

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        if tls is not None:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.endpoint = '{}://127.0.0.1:{}'.format('https' if tls else 'http', self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.01}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


class PreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix='rch-preview-client-'))
        cls.token = cls.root / 'token'
        cls.secret = 'fixture-S3cret-not-for-output'
        cls.token.write_text(cls.secret + '\n')
        cls.token.chmod(0o600)

    def run_cli(self, endpoint, value=None, raw=None, extra=None, env=None):
        # The fixture itself needs only stdlib. Keep host site-packages out
        # of its startup; deadlines and every protocol assertion are unchanged.
        # The separate real-venv test below verifies the helper's own flags.
        args = [sys.executable, '-I', '-S', str(SCRIPT), '--endpoint', endpoint,
                '--token-file', str(self.token)]
        args += extra or []
        result = subprocess.run(args, input=raw if raw is not None else client.encode(value or request()),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=7, check=False, env=env)
        self.assertNotIn(self.secret.encode(), result.stdout + result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1, result.stderr)
        output = json.loads(result.stdout)
        self.assertIs(output['execution_authorized'], False)
        return result.returncode, output

    def test_cli_preserves_all_inputs_and_returns_lane_without_owning_execution(self):
        with Peer() as peer:
            code, result = self.run_cli(peer.endpoint)
        self.assertEqual(code, 0)
        self.assertEqual(result['observation'], 'available')
        self.assertEqual(result['selection']['worker']['project_lane'], 2)
        self.assertEqual(len(peer.requests), 1)
        method, path, headers, body = peer.requests[0]
        self.assertEqual((method, path), ('POST', '/admission-preview'))
        self.assertEqual(headers['Authorization'], 'Bearer ' + self.secret)
        self.assertEqual(json.loads(body), request())
        self.assertNotIn('local_wrapper_id', json.loads(body))
        self.assertNotIn('hook_pid', json.loads(body))
        self.assertFalse({'queue', 'wait', 'dry_run'} & json.loads(body).keys())

    def test_daemon_denials_are_preserved_not_inferred_as_capacity(self):
        for reason in ['all_workers_busy', 'no_workers_configured',
                       {'selection_error': 'restart_admission_barrier_active'},
                       {'selection_error': 'durable_ownership_uncertain'}]:
            with self.subTest(reason=reason), Peer(reply(None, reason)) as peer:
                code, result = self.run_cli(peer.endpoint)
            is_error = type(reason) is dict and 'selection_error' in reason
            self.assertEqual(code, 2 if is_error else 1)
            self.assertEqual(result['observation'], 'unknown' if is_error else 'unavailable')
            self.assertEqual(result['selection']['reason'], reason)
            self.assertEqual(len(peer.requests), 1)

    def test_budgeted_daemon_approvals_preserve_exact_byte_allowances(self):
        # SelectedWorker.disk_budget is emitted by the production HTTP
        # observer, not an execution grant or a client-selected constraint.
        # These values intentionally exceed the slot field's u32 range.
        for reason, growth, floor in [('success', 40 << 30, 10 << 30),
                                      ('affinity_pinned', (1 << 53) + 1, 0),
                                      ('affinity_fallback', (1 << 64) - 1, (1 << 64) - 1)]:
            with self.subTest(reason=reason):
                response = reply(reason=reason)
                budget = {'max_growth_bytes': growth, 'min_free_bytes': floor}
                response['selection']['worker']['disk_budget'] = budget
                response['selection']['worker']['slots_available'] = 1
                with Peer(response) as peer:
                    code, result = self.run_cli(peer.endpoint)
                self.assertEqual(code, 0, result)
                self.assertEqual(result['observation'], 'available')
                self.assertEqual(result['selection'], response['selection'])
                self.assertEqual(len(peer.requests), 1)
                self.assertEqual(json.loads(peer.requests[0][3]), request())
                self.assertNotIn('disk_budget', json.loads(peer.requests[0][3]))

    def test_absent_and_null_budgets_are_not_synthesized_or_reserved(self):
        for present in [False, True]:
            with self.subTest(present=present):
                response = reply()
                if present:
                    response['selection']['worker']['disk_budget'] = None
                with Peer(response) as peer:
                    code, result = self.run_cli(peer.endpoint)
                self.assertEqual(code, 0, result)
                self.assertEqual(result['selection'], response['selection'])
                self.assertEqual(len(peer.requests), 1)

    def test_malformed_budget_never_turns_into_a_partial_approval(self):
        valid = {'max_growth_bytes': 32 << 30, 'min_free_bytes': 0}
        malformed = [False, 1, 'unlimited', [], {},
                     {'max_growth_bytes': 1}, {'min_free_bytes': 0},
                     dict(valid, reserved=True), dict(valid, extra=0)]
        for key in valid:
            for bad in [True, False, -1, 1.5, '1024', None, 1 << 64]:
                malformed.append(dict(valid, **{key: bad}))
        malformed.append(dict(valid, max_growth_bytes=0))
        for budget in malformed:
            with self.subTest(budget=budget):
                response = reply()
                response['selection']['worker']['disk_budget'] = budget
                with self.assertRaisesRegex(client.PreviewError, '^invalid_disk_budget$'):
                    client.validate_response(response, request())
        # Run representative malformed evidence through the complete native
        # HTTP/helper boundary too, without 24 copies of process startup.
        for budget in [dict(valid, min_free_bytes=True), dict(valid, reserved=True)]:
            response = reply()
            response['selection']['worker']['disk_budget'] = budget
            with Peer(response) as peer:
                code, result = self.run_cli(peer.endpoint)
            self.assertEqual(code, 2)
            self.assertEqual(result['observation'], 'unknown')
            self.assertEqual(result['error'], 'invalid_disk_budget')
            self.assertNotIn('selection', result)
            self.assertEqual(len(peer.requests), 1, 'no retry or release')

    def test_budget_support_does_not_weaken_worker_or_ownership_checks(self):
        valid = reply()
        valid['selection']['worker']['disk_budget'] = {
            'max_growth_bytes': 32 << 30, 'min_free_bytes': 10 << 30}
        cases = []
        for key, value in [('id', 'not-requested'), ('slots_available', 0),
                           ('slots_available', 1 << 32), ('project_lane', -1),
                           ('new_execution_grant', True)]:
            changed = copy.deepcopy(valid)
            changed['selection']['worker'][key] = value
            cases.append(changed)
        for key, value in [('build_id', 1), ('reason', 'all_workers_busy')]:
            changed = copy.deepcopy(valid)
            changed['selection'][key] = value
            cases.append(changed)
        for response in cases:
            with self.subTest(response=response), Peer(response) as peer:
                code, result = self.run_cli(peer.endpoint)
                self.assertEqual(code, 2)
                self.assertEqual(result['observation'], 'unknown')
                self.assertNotIn('selection', result)
                self.assertEqual(len(peer.requests), 1)

    def test_budget_cannot_be_supplied_as_a_new_client_authority_field(self):
        value = request()
        value['disk_budget'] = {'max_growth_bytes': 1, 'min_free_bytes': 0}
        with Peer() as peer:
            code, result = self.run_cli(peer.endpoint, value=value)
            self.assertEqual(code, 2)
            self.assertEqual(result['error'], 'invalid_request_fields')
            self.assertEqual(peer.requests, [])

    def test_duplicate_budget_fields_are_rejected_before_selection_validation(self):
        response = reply()
        response['selection']['worker']['disk_budget'] = {
            'max_growth_bytes': 32 << 30, 'min_free_bytes': 0}
        body = client.encode(response).replace(
            b'"max_growth_bytes":', b'"max_growth_bytes":1,"max_growth_bytes":', 1)
        with Peer(raw=body) as peer:
            code, result = self.run_cli(peer.endpoint)
        self.assertEqual(code, 2)
        self.assertEqual(result['error'], 'duplicate_json_field')
        self.assertNotIn('selection', result)
        self.assertEqual(len(peer.requests), 1)

    def test_worker_pin_and_capacity_contradictions_never_authorize_or_release(self):
        values = [reply('not-requested'), reply(None), reply('wanted', 'all_workers_busy')]
        owned = reply()
        owned['selection']['build_id'] = 19
        values.append(owned)
        depleted = reply()
        depleted['selection']['worker']['slots_available'] = 0
        values.append(depleted)
        for value in values:
            with self.subTest(value=value), Peer(value) as peer:
                code, result = self.run_cli(peer.endpoint)
            self.assertEqual(code, 2)
            self.assertEqual(result['observation'], 'unknown')
            self.assertEqual(len(peer.requests), 1, 'no release or retry is permitted')
            self.assertNotIn('selection', result)

    def test_undersized_worker_approval_preserves_the_daemons_soft_cpu_estimate(self):
        # The production selector can approve an undersized-but-free worker
        # for automatic compilation placement after its hard gates pass.
        # This client must not turn that approval into a new capacity denial.
        value = request()
        value['preferred_workers'] = []
        value['job_mode'] = False
        for reason in sorted(client.ASSIGNED):
            approved = reply(reason=reason)
            approved['selection']['worker']['slots_available'] = 1
            with self.subTest(reason=reason), Peer(approved) as peer:
                code, result = self.run_cli(peer.endpoint, value=value)
            self.assertEqual(code, 0)
            self.assertEqual(result['observation'], 'available')
            self.assertEqual(result['selection'], approved['selection'])
            self.assertEqual(len(peer.requests), 1)
            self.assertEqual(json.loads(peer.requests[0][3]), value)

    def test_soft_estimate_never_changes_denials_or_accepts_an_unusable_worker(self):
        value = request()
        value['preferred_workers'] = []
        value['job_mode'] = False
        for free in [0, -1, True, 1.5, 2 ** 32]:
            approved = reply()
            approved['selection']['worker']['slots_available'] = free
            with self.subTest(free=free), Peer(approved) as peer:
                code, result = self.run_cli(peer.endpoint, value=value)
            self.assertEqual(code, 2)
            self.assertEqual(result['observation'], 'unknown')
            self.assertNotIn('selection', result)
            self.assertEqual(len(peer.requests), 1)
        for reason in ['all_workers_busy', {'no_admissible_workers': 'insufficient_total_slots=1'}]:
            with self.subTest(reason=reason), Peer(reply(None, reason)) as peer:
                code, result = self.run_cli(peer.endpoint, value=value)
            self.assertEqual(code, 1)
            self.assertEqual(result['selection']['reason'], reason)
            self.assertEqual(len(peer.requests), 1)

    def test_json_escaped_reflected_credentials_never_reach_cli_output(self):
        # These printable token bytes are accepted by the existing token-file
        # and header contracts. Searching only serialized JSON misses them.
        for index, secret in enumerate(['quote"token', r'backslash\token', 'both\\"token']):
            token_path = self.root / ('escaped-token-' + str(index))
            token_path.write_text(secret + '\n')
            token_path.chmod(0o600)
            for location in ['reason', 'nested_value', 'nested_key']:
                reflected = reply()
                if location == 'reason':
                    reflected = reply(None, {'selection_error': 'peer echoed ' + secret})
                else:
                    reflected['selection']['diagnostics'] = {
                        'required_runtime': 'rust', 'estimated_cores': 3, 'workers': [],
                        'detail': {secret: 'value'} if location == 'nested_key' else [[secret]],
                    }
                with self.subTest(secret=secret, location=location), Peer(reflected) as peer:
                    completed = subprocess.run(
                        [sys.executable, '-I', '-S', str(SCRIPT), '--endpoint', peer.endpoint,
                         '--token-file', str(token_path)], input=client.encode(request()),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7, check=False,
                    )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(json.loads(completed.stdout), {
                    'protocol_version': 1, 'observation': 'unknown',
                    'execution_authorized': False, 'error': 'credential_in_response',
                })
                self.assertEqual(completed.stderr, b'')
                self.assertEqual(len(peer.requests), 1)
                self.assertEqual(peer.requests[0][2]['Authorization'], 'Bearer ' + secret)

    def test_json_sensitive_token_without_reflection_still_observes_the_worker(self):
        secret = 'quote"and\\slash-private-token'
        token_path = self.root / 'unreflected-escaped-token'
        token_path.write_text(secret + '\n')
        token_path.chmod(0o600)
        with Peer() as peer:
            completed = subprocess.run(
                [sys.executable, '-I', '-S', str(SCRIPT), '--endpoint', peer.endpoint,
                 '--token-file', str(token_path)], input=client.encode(request()),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)['observation'], 'available')
        self.assertIs(json.loads(completed.stdout)['execution_authorized'], False)
        self.assertEqual(len(peer.requests), 1)

    def test_old_protocol_bad_json_duplicate_fields_and_nonfinite_data_refuse(self):
        invalid = [client.encode(reply()['selection']), b'{', b'\xff',
                   b'{"protocol_version":1,"protocol_version":1,"selection":{}}']
        for patch in [{'protocol_version': 2}, {'protocol_version': True}, {'extra': 1}]:
            value = reply()
            value.update(patch)
            invalid.append(client.encode(value))
        value = reply()
        value['selection']['worker']['speed_score'] = float('nan')
        invalid.append(json.dumps(value).encode())
        for data in invalid:
            with self.subTest(data=data[:50]), Peer(raw=data) as peer:
                code, result = self.run_cli(peer.endpoint)
            self.assertEqual(code, 2)
            self.assertEqual(result['observation'], 'unknown')
            self.assertEqual(len(peer.requests), 1)

    def test_unavailable_http_does_not_reuse_a_success_body_or_retry(self):
        for status in [401, 403, 404, 429, 500, 503]:
            with self.subTest(status=status), Peer(status=status, raw=self.secret.encode()) as peer:
                code, result = self.run_cli(peer.endpoint)
            self.assertEqual(code, 2)
            self.assertEqual(result['error'], 'http_' + str(status))
            self.assertEqual(len(peer.requests), 1)

    def test_redirect_cannot_forward_credentials_to_another_peer(self):
        with Peer() as destination:
            for status in [301, 302, 303, 307, 308]:
                with self.subTest(status=status), Peer(status=status,
                        headers={'Location': destination.endpoint + '/select-worker'}) as peer:
                    code, result = self.run_cli(peer.endpoint)
                self.assertEqual(code, 2)
                self.assertEqual(result['error'], 'http_' + str(status))
                self.assertEqual(len(peer.requests), 1)
            self.assertEqual(destination.requests, [])

    def test_proxy_environment_cannot_redirect_admission_or_credentials(self):
        with Peer() as proxy, Peer() as peer:
            env = dict(os.environ, HTTP_PROXY=proxy.endpoint, HTTPS_PROXY=proxy.endpoint,
                       http_proxy=proxy.endpoint, https_proxy=proxy.endpoint, ALL_PROXY=proxy.endpoint,
                       all_proxy=proxy.endpoint, NO_PROXY='', no_proxy='')
            code, result = self.run_cli(peer.endpoint, env=env)
        self.assertEqual(code, 0)
        self.assertEqual(result['observation'], 'available')
        self.assertEqual(len(peer.requests), 1)
        self.assertEqual(proxy.requests, [])

    def test_total_deadline_bounds_stalled_headers_and_trickled_body(self):
        for mode in [{'delay': True}, {'hold_headers': True}, {'drip': True}]:
            with self.subTest(mode=mode), Peer(**mode) as peer:
                before = time.monotonic()
                code, result = self.run_cli(peer.endpoint, extra=['--timeout', '2'])
                elapsed = time.monotonic() - before
            self.assertEqual(code, 2)
            self.assertEqual(result['error'], 'observation_timeout')
            self.assertLess(elapsed, 4.5)
            self.assertEqual(len(peer.requests), 1)

    def test_failed_connection_is_unknown_not_local_or_a_queue_recommendation(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        endpoint = 'http://127.0.0.1:' + str(listener.getsockname()[1])
        # Bound socket with no listener guarantees connection refusal while
        # this fixture owns the port (no race with somebody else's service).
        try:
            code, result = self.run_cli(endpoint)
        finally:
            listener.close()
        self.assertEqual(code, 2)
        self.assertEqual(result['error'], 'transport_failure')
        self.assertEqual(result['observation'], 'unknown')

    def test_size_content_encoding_and_ambiguous_framing_refuse(self):
        data = client.encode(reply())
        cases = [
            {'raw': b'x' * (client.MAX_RESPONSE_BYTES + 1)},
            {'raw': data, 'headers': {'Content-Encoding': 'gzip'}},
            {'raw': data, 'headers': {'Content-Type': 'text/html'}},
            {'raw': data, 'raw_headers': [('Content-Length', str(len(data) + 3))]},
            {'raw': data, 'raw_headers': [('Content-Length', str(len(data))), ('Content-Length', str(len(data)))]},
            {'raw': data, 'raw_headers': [('Content-Length', '-1')]},
            {'raw': data, 'raw_headers': [('Content-Length', str(len(data))), ('Transfer-Encoding', 'chunked')]},
            {'raw': data, 'raw_headers': [('Transfer-Encoding', 'compress')]},
        ]
        for case in cases:
            with self.subTest(case={k: v for k, v in case.items() if k != 'raw'}), Peer(**case) as peer:
                code, result = self.run_cli(peer.endpoint)
            self.assertEqual(code, 2)
            self.assertEqual(result['observation'], 'unknown')
            self.assertEqual(len(peer.requests), 1)

    def test_valid_chunked_reply_is_decoded_with_the_same_bounds(self):
        data = client.encode(reply())
        chunks = b'%X\r\n' % len(data) + data + b'\r\n0\r\n\r\n'
        with Peer(raw=chunks, raw_headers=[('Transfer-Encoding', 'chunked')]) as peer:
            code, result = self.run_cli(peer.endpoint)
        self.assertEqual(code, 0)
        self.assertEqual(result['observation'], 'available')

    def test_reflected_credential_is_not_exposed_in_diagnostics(self):
        value = reply(None, {'selection_error': self.secret})
        with Peer(value) as peer:
            code, result = self.run_cli(peer.endpoint)
        self.assertEqual(code, 2)
        self.assertEqual(result['error'], 'credential_in_response')

    def test_diagnostics_must_describe_the_requested_runtime_and_slots(self):
        value = reply(None, 'all_workers_busy')
        value['selection']['diagnostics'] = {'required_runtime': 'rust', 'estimated_cores': 3, 'workers': []}
        with Peer(value) as peer:
            code, result = self.run_cli(peer.endpoint)
        self.assertEqual(code, 1)
        self.assertEqual(result['selection']['diagnostics'], value['selection']['diagnostics'])
        for key, bad in [('required_runtime', 'none'), ('estimated_cores', 2), ('estimated_cores', True)]:
            broken = copy.deepcopy(value)
            broken['selection']['diagnostics'][key] = bad
            with Peer(broken) as peer:
                code, result = self.run_cli(peer.endpoint)
            self.assertEqual(code, 2)
            self.assertEqual(result['error'], 'inconsistent_diagnostics')

    def test_missing_optional_lane_remains_a_nonowning_legacy_lane_zero(self):
        value = reply()
        del value['selection']['worker']['project_lane']
        with Peer(value) as peer:
            code, result = self.run_cli(peer.endpoint)
        self.assertEqual(code, 0)
        self.assertNotIn('project_lane', result['selection']['worker'])

    def test_unknown_execution_controls_and_invalid_requirements_fail_before_network(self):
        cases = []
        for key in ['wait', 'queue', 'dry_run', 'hook_pid', 'local_wrapper_id', 'future_constraint']:
            value = request()
            value[key] = 1
            cases.append(value)
        for key, bad in [('estimated_cores', 0), ('estimated_cores', True), ('estimated_cores', 2**32),
                         ('disk_headroom_gib', -1), ('job_mode', 'true'), ('required_runtime', 'future'),
                         ('required_tools', ['']), ('preferred_workers', ['']), ('command', '  '),
                         ('toolchain', {'channel': 'nightly'}), ('protocol_version', True)]:
            value = request()
            value[key] = bad
            cases.append(value)
        with Peer() as peer:
            for value in cases:
                code, result = self.run_cli(peer.endpoint, value=value)
                self.assertEqual(code, 2, value)
                self.assertEqual(result['observation'], 'unknown')
            for raw in [b'{}', b'\xff', b'{"protocol_version":1,"protocol_version":1}',
                        b'x' * (client.MAX_REQUEST_BYTES + 1)]:
                code, _ = self.run_cli(peer.endpoint, raw=raw)
                self.assertEqual(code, 2)
            self.assertEqual(peer.requests, [])

    def test_endpoint_has_no_execution_path_userinfo_query_or_cleartext_public_host(self):
        for endpoint in ['http://example.org', 'http://8.8.8.8', 'http://127.0.0.1/select-worker',
                         'http://127.0.0.1?dry_run=0', 'http://u:p@127.0.0.1',
                         'http://127.0.0.1#x', 'http://127.0.0.1:99999', 'ftp://127.0.0.1',
                         'http://localhost', 'http://[::1%25bad]', 'http://127.0.0.1\r\nX:Y']:
            with self.subTest(endpoint=endpoint), self.assertRaises(client.PreviewError):
                client.endpoint_parts(endpoint)
        for endpoint in ['http://127.0.0.1', 'http://[::1]:9101', 'http://100.64.0.1:9101',
                         'http://[fd7a:115c:a1e0::1]:9101', 'https://daemon.example:443']:
            client.endpoint_parts(endpoint)

    def test_private_token_requirement_rejects_symlinks_fifos_empty_and_oversize(self):
        self.assertEqual(client.load_token(self.token), self.secret)
        path = self.root / 'public-token'
        path.write_text(self.secret)
        path.chmod(0o644)
        link = self.root / 'link-token'
        link.symlink_to(self.token)
        fifo = self.root / 'fifo-token'
        os.mkfifo(fifo, 0o600)
        for source in [path, link, fifo, self.root, self.root / 'missing']:
            with self.subTest(source=source), self.assertRaises(client.PreviewError):
                client.load_token(source)
        for index, data in enumerate([b'', b' \n', b'a\nb', b'\xff', b'x' * (client.MAX_TOKEN_BYTES + 1)]):
            source = self.root / ('bad-token-' + str(index))
            source.write_bytes(data)
            source.chmod(0o600)
            with self.assertRaises(client.PreviewError):
                client.load_token(source)

    def test_request_file_and_explicit_no_token_do_not_autoload_credentials(self):
        path = self.root / 'request.json'
        path.write_bytes(client.encode(request()))
        with Peer() as peer:
            result = subprocess.run([sys.executable, '-I', '-S', str(SCRIPT), '--endpoint', peer.endpoint,
                                     '--no-token', '--request', str(path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6,
                                    env=dict(os.environ, RCH_API_TOKEN='ambient-token'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['observation'], 'available')
        self.assertNotIn('Authorization', peer.requests[0][2])

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL needed only to generate the TLS fixture')
    def test_https_keeps_certificate_verification_and_sends_no_credentials_on_failure(self):
        key, cert = self.root / 'tls.key', self.root / 'tls.crt'
        created = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                                  '-keyout', str(key), '-out', str(cert), '-days', '1',
                                  '-subj', '/CN=fixture', '-addext', 'subjectAltName=IP:127.0.0.1'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(created.returncode, 0, created.stderr)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        with Peer(tls=tls) as peer:
            code, result = self.run_cli(peer.endpoint)
        self.assertEqual(code, 2)
        self.assertEqual(result['error'], 'transport_failure')
        self.assertEqual(peer.requests, [], 'HTTP credentials must wait for a verified TLS session')
        with Peer(tls=tls) as trusted_peer:
            code, result = self.run_cli(trusted_peer.endpoint, env=dict(os.environ, SSL_CERT_FILE=str(cert)))
        self.assertEqual(code, 0)
        self.assertEqual(result['observation'], 'available')
        self.assertEqual(len(trusted_peer.requests), 1)

    def test_timeout_values_are_bounded_and_invalid_json_cannot_enter_the_helper(self):
        with Peer() as peer:
            for value in ['0', '-1', '31', 'nan', 'inf']:
                code, result = self.run_cli(peer.endpoint, extra=['--timeout', value])
                self.assertEqual(code, 2)
                self.assertEqual(result['error'], 'invalid_timeout')
            self.assertEqual(peer.requests, [])

    def test_abrupt_cli_owner_death_closes_the_live_helper_connection(self):
        with Peer(delay=True) as peer:
            parent = subprocess.Popen([sys.executable, '-I', '-S', str(SCRIPT), '--endpoint', peer.endpoint,
                                       '--no-token', '--timeout', '30'],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            try:
                parent.stdin.write(client.encode(request()))
                parent.stdin.close()
                parent.stdin = None
                self.assertTrue(peer.connected.wait(5), 'helper never sent the native HTTP request')
                parent.kill()  # Only this test-owned CLI process, never a daemon or worker.
                parent.communicate(timeout=3)
                self.assertTrue(peer.disconnected.wait(3), 'helper outlived its owner connection')
                self.assertEqual(len(peer.requests), 1)
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.communicate(timeout=3)

    def test_cancelled_transport_is_killed_and_reaped_before_return(self):
        children = []
        original = subprocess.Popen

        def capture(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        with Peer(delay=True) as peer, mock.patch.object(client.subprocess, 'Popen', capture):
            with self.assertRaisesRegex(client.PreviewError, '^observation_timeout$'):
                client.observe(peer.endpoint, request(), None, 0.4)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertNotEqual(children[0].returncode, 0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)

    def test_network_helper_never_loads_environment_site_hooks(self):
        import venv

        # A real private interpreter environment, not a mocked Popen/transport.
        # -I alone excludes user site but STILL runs environment .pth and
        # sitecustomize code. Start the parent without site so only its
        # directly owned helper could create the unwanted side effect.
        for hook in ['sitecustomize.py', 'admission_startup.pth']:
            with self.subTest(hook=hook):
                root = Path(tempfile.mkdtemp(prefix='rch-preview-site-'))
                venv.EnvBuilder(with_pip=False).create(root / 'env')
                python = root / 'env' / 'bin' / 'python'
                sites = list((root / 'env' / 'lib').glob('python*/site-packages'))
                self.assertEqual(len(sites), 1)
                witness = root / 'site-hook-ran'
                (sites[0] / hook).write_text(
                    'import pathlib; pathlib.Path({!r}).write_text("site loaded")\n'.format(str(witness)))
                with Peer() as peer:
                    result = subprocess.run(
                        [str(python), '-I', '-S', str(SCRIPT), '--endpoint', peer.endpoint,
                         '--no-token', '--timeout', '2'], input=client.encode(request()),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                output = json.loads(result.stdout)
                self.assertEqual(output['observation'], 'available')
                self.assertIs(output['execution_authorized'], False)
                self.assertEqual(len(peer.requests), 1)
                self.assertEqual(json.loads(peer.requests[0][3]), request())
                self.assertFalse(witness.exists(), 'the network helper loaded unrelated startup code')

    def test_unknown_reason_variants_refuse_instead_of_becoming_denials(self):
        for reason in ['success_v2', 'future_denial', {'future_reason': 'details'},
                       {'selection_error': 7}, {'selection_error': True}]:
            with self.assertRaises(client.PreviewError):
                client.validate_response(reply(None, reason), request())
        for reason in client.DENIED:
            self.assertEqual(client.validate_response(reply(None, reason), request())['observation'],
                             'unavailable')
        for reason in client.ASSIGNED:
            self.assertEqual(client.validate_response(reply(reason=reason), request())['observation'],
                             'available')

    def test_pure_request_roundtrip_keeps_unicode_newlines_and_exact_counts(self):
        value = request()
        self.assertEqual(client.decode(client.validate_request(value)), value)
        for runtime in client.RUNTIMES:
            value['required_runtime'] = runtime
            client.validate_request(value)
        minimal = {'protocol_version': 1, 'project': 'p', 'command': 'make', 'estimated_cores': 1}
        self.assertEqual(client.decode(client.validate_request(minimal)), minimal)


if __name__ == '__main__':
    unittest.main(verbosity=2)
