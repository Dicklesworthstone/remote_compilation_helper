#!/usr/bin/env python3
"""Exercise the exact Linux force-stop helper against owned child/socket fixtures.

No shared daemon or numeric process name is targeted. Cleanup signals only
unreaped Popen children created by this test, never a PID read from a fixture.
"""
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HELPER = Path(__file__).resolve().parents[1] / "rch/src/commands/daemon/force_stop.py"
spec = importlib.util.spec_from_file_location("force_stop", HELPER)
force = importlib.util.module_from_spec(spec)
spec.loader.exec_module(force)
RCH = None
if '--rch' in sys.argv:
    position = sys.argv.index('--rch')
    RCH = str(Path(sys.argv[position + 1]).resolve(strict=True))
    del sys.argv[position:position + 2]

DAEMON = r'''
import json, os, signal, socket, struct, sys, time, uuid
from urllib.parse import parse_qs
path, mode, ready, marker, prepared = sys.argv[1:]
incarnation = str(uuid.uuid4())
maintenance_owner = None
shutdown_committed = prepared == 'true'
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(path)
listener.listen(8)
def admission_snapshot():
    state = 'shutting_down' if shutdown_committed else 'owned' if maintenance_owner else 'open'
    return {'success': True, 'status': state, 'message': None,
        'daemon_incarnation': incarnation, 'admission_closed': maintenance_owner is not None or shutdown_committed,
        'maintenance_closed': maintenance_owner is not None, 'ownership_failed': False,
        'ownership_error': None, 'shutdown_committed': shutdown_committed,
        'maintenance_owner': maintenance_owner, 'last_recovery': None,
        'restart_permitted': False, 'active_build_ids': [41], 'queued_build_ids': [],
        'client_lease_ids': [], 'client_lease_scan_error': None}
def term(_sig, _frame):
    with open(marker, 'a') as output:
        output.write('TERM\n')
    if mode == 'ignore':
        return
    listener.close()
    if mode != 'retain':
        os.unlink(path)
    if mode == 'replace_after_term':
        with open(path, 'w') as output:
            output.write('replacement evidence')
    sys.exit(0)
signal.signal(signal.SIGTERM, term)
with open(ready + '-pending', 'w') as output:
    with open('/proc/sys/kernel/random/boot_id') as source:
        boot = source.read().strip()
    with open('/proc/self/stat') as source:
        ticks = int(source.read().rsplit(')', 1)[1].split()[19])
    json.dump({'pid': os.getpid(), 'identity': '%s:%d' % (boot, ticks),
               'incarnation': incarnation}, output)
os.rename(ready + '-pending', ready)
while True:
    peer, _ = listener.accept()
    try:
        request = bytearray()
        while True:
            chunk = peer.recv(4096)
            if not chunk:
                break
            request.extend(chunk)
        method, target = request.decode().strip().split(' ', 1)
        route, _, query = target.partition('?')
        if route.startswith('/restart-admission') or route == '/shutdown':
            params = parse_qs(query)
            if method == 'POST':
                assert params['daemon_incarnation'] == [incarnation]
                token = params['token'][0]
                peer_pid = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
                if route == '/restart-admission':
                    with open('/proc/sys/kernel/random/boot_id') as source:
                        boot = source.read().strip()
                    with open('/proc/%d/stat' % peer_pid) as source:
                        ticks = int(source.read().rsplit(')', 1)[1].split()[19])
                    assert params['owner_identity'] == ['%s:%d' % (boot, ticks)]
                    maintenance_owner = {'token': token, 'pid': peer_pid, 'purpose': 'stop',
                        'generation': 1, 'acquired_unix_ms': 1, 'deadline_unix_ms': 9999999999999,
                        'remaining_ms': 30000, 'owner_presence': 'live',
                        'process_identity': {'boot_id': boot, 'start': {'platform': 'linux', 'ticks': ticks}}}
                else:
                    assert maintenance_owner['token'] == token and maintenance_owner['pid'] == peer_pid
                    if route == '/restart-admission/release':
                        maintenance_owner = None
                    elif route == '/shutdown':
                        assert params.get('force') == ['true']
                        shutdown_committed = True
            admission = admission_snapshot()
            peer.sendall(b'HTTP/1.1 200 OK\r\n\r\n' + json.dumps(admission).encode())
            continue
        if request != b'GET /status\n':
            raise RuntimeError('unexpected mutating request: ' + repr(request))
        if mode == 'hang':
            time.sleep(10)
            continue
        if mode == 'lost':
            continue
        pid = os.getpid()
        obj = {'daemon': {'pid': pid, 'socket_path': path, 'uptime_secs': 1,
                         'version': 'test', 'started_at': '2026-01-01T00:00:00Z',
                         'workers_total': 0, 'workers_healthy': 0,
                         'slots_total': 0, 'slots_available': 0},
               'workers': [], 'active_builds': [], 'recent_builds': [], 'issues': [],
               'stats': {'total_builds': 0, 'success_count': 0, 'failure_count': 0,
                         'remote_count': 0, 'local_count': 0, 'avg_duration_ms': 0}}
        obj['admission'] = admission_snapshot()
        if mode == 'wrong_pid': obj['daemon']['pid'] = pid + 1
        if mode == 'zero_pid': obj['daemon']['pid'] = 0
        if mode == 'boolean_pid': obj['daemon']['pid'] = True
        if mode == 'wrong_path': obj['daemon']['socket_path'] = path + '-other'
        if mode == 'missing_pid': del obj['daemon']['pid']
        payload = json.dumps(obj).encode()
        if mode == 'malformed': payload = b'{'
        if mode == 'duplicate': payload = ('{"daemon":{"pid":%d,"pid":%d,"socket_path":%s}}' % (pid, pid, json.dumps(path))).encode()
        if mode == 'oversized': payload = b' ' * (1024 * 1024 + 1)
        if mode == 'non_utf8': payload = b'\xff'
        status = b'500 Nope' if mode == 'http_error' else b'200 OK'
        if mode == 'replace_before_term':
            os.rename(path, path + '-original')
            with open(path, 'w') as output:
                output.write('replacement evidence')
        try:
            peer.sendall(b'HTTP/1.1 ' + status + b'\r\n\r\n' + payload)
        except (BrokenPipeError, ConnectionResetError):
            pass
    finally:
        peer.close()
'''


class Fixture:
    def __init__(self, directory, mode='normal', name='daemon.sock', committed=True):
        self.path = Path(directory) / name
        self.ready = Path(directory) / (name + '-ready')
        self.marker = Path(directory) / (name + '-signals')
        self.child = subprocess.Popen(
            [sys.executable, '-I', '-S', '-c', DAEMON, str(self.path), mode,
             str(self.ready), str(self.marker), str(committed).lower()],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while not self.ready.exists():
            if self.child.poll() is not None:
                raise AssertionError(self.child.stderr.read().decode())
            if time.monotonic() > deadline:
                self.close()
                raise AssertionError('fixture startup deadline')
            time.sleep(.005)
        evidence = json.loads(self.ready.read_text())
        self.identity = evidence['identity']
        self.incarnation = evidence['incarnation']

    def close(self):
        if self.child.poll() is None:
            self.child.kill()
        self.child.wait(timeout=5)
        self.child.stderr.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def bounded_stop(fixture):
    return force.stop(str(fixture.path), fixture.child.pid, fixture.identity,
                      fixture.incarnation, .2, .3)


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'pidfd_open'), 'Linux pidfd required')
class NativeForceStop(unittest.TestCase):
    @unittest.skipUnless(RCH, 'supply --rch for the compiled CLI integration')
    def test_compiled_cli_force_stop_uses_the_bound_helper(self):
        for mode in ['normal', 'zero_pid', 'wrong_pid', 'wrong_path']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                config = root / 'config'
                config.mkdir()
                (config / 'workers.toml').write_text('')
                guarded = root / 'bin'
                guarded.mkdir()
                (guarded / 'python3').symlink_to(sys.executable)
                log = root / 'unsafe-command'
                for name in ['kill', 'pkill', 'nohup', 'rchd']:
                    script = guarded / name
                    script.write_text('#!/bin/sh\nprintf attempted >> "$RCH_TEST_GUARD"\nexit 99\n')
                    script.chmod(0o700)
                with Fixture(root, mode, committed=False) as daemon, Fixture(root, name='peer.sock') as peer:
                    env = {'PATH': str(guarded), 'HOME': str(root),
                           'RCH_CONFIG_DIR': str(config), 'RCH_SOCKET_PATH': str(daemon.path),
                           'RCH_TEST_GUARD': str(log), 'XDG_CONFIG_HOME': str(root / 'xdg'),
                           'XDG_DATA_HOME': str(root / 'data'), 'XDG_STATE_HOME': str(root / 'state'),
                           'XDG_RUNTIME_DIR': str(root / 'run')}
                    output = subprocess.run([RCH, '--json', 'daemon', 'stop', '--force', '--yes'],
                                            env=env, cwd=root, capture_output=True, timeout=25)
                    self.assertFalse(log.exists(), (output.stdout, output.stderr))
                    self.assertIsNone(peer.child.poll())
                    self.assertFalse(peer.marker.exists())
                    reply = json.loads(output.stdout)
                    if mode == 'normal':
                        self.assertEqual(output.returncode, 0, output.stderr)
                        self.assertTrue(reply['success'])
                        self.assertFalse(daemon.path.exists())
                        self.assertEqual(daemon.child.wait(timeout=2), 0)
                    else:
                        self.assertNotEqual(output.returncode, 0, (output.stdout, output.stderr))
                        self.assertFalse(reply['success'])
                        self.assertFalse(daemon.marker.exists())
                        self.assertTrue(daemon.path.exists())
                        self.assertIsNone(daemon.child.poll())

    def test_real_term_requires_process_exit_and_natural_socket_retirement(self):
        for name in ['plain.sock', 'p q.sock', 'x:y.sock']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                with Fixture(root, name=name) as daemon, Fixture(root, name='peer.sock') as peer:
                    self.assertEqual(bounded_stop(daemon), f'RCH_DAEMON_STOPPED_V1:{daemon.child.pid}\n')
                    self.assertEqual(daemon.child.wait(timeout=2), 0)
                    self.assertFalse(daemon.path.exists())
                    self.assertEqual(daemon.marker.read_text(), 'TERM\n')
                    self.assertIsNone(peer.child.poll())
                    self.assertTrue(peer.path.exists())
                    self.assertFalse(peer.marker.exists())

    def test_cli_emits_only_the_bound_terminal_receipt(self):
        with tempfile.TemporaryDirectory() as root, Fixture(root) as daemon:
            output = subprocess.run([sys.executable, '-I', '-S', str(HELPER), str(daemon.path),
                                     str(daemon.child.pid), daemon.identity, daemon.incarnation],
                                    capture_output=True, timeout=20)
            self.assertEqual(output.returncode, 0, output.stderr)
            self.assertEqual(output.stderr, b'')
            self.assertEqual(output.stdout, f'RCH_DAEMON_STOPPED_V1:{daemon.child.pid}\n'.encode())

    def test_invalid_or_unbound_status_never_sends_a_signal(self):
        for mode in ['wrong_pid', 'zero_pid', 'boolean_pid', 'wrong_path', 'missing_pid',
                     'malformed', 'duplicate', 'oversized', 'non_utf8', 'http_error', 'lost', 'hang']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root, Fixture(root, mode) as daemon:
                before = force.endpoint(str(daemon.path))
                with self.assertRaises((OSError, ValueError, KeyError, TypeError, IndexError)):
                    bounded_stop(daemon)
                self.assertIsNone(daemon.child.poll())
                self.assertFalse(daemon.marker.exists())
                self.assertEqual(force.endpoint(str(daemon.path)), before)

    def test_pid_is_bound_to_the_actual_socket_peer_before_term(self):
        with tempfile.TemporaryDirectory() as root:
            with Fixture(root) as daemon, Fixture(root, name='other.sock') as other:
                with self.assertRaisesRegex(ValueError, 'another process'):
                    force.stop(str(daemon.path), other.child.pid, other.identity,
                               other.incarnation, .2, .3)
                for process in (daemon, other):
                    self.assertIsNone(process.child.poll())
                    self.assertFalse(process.marker.exists())
                    self.assertTrue(process.path.exists())

    def test_recycled_pid_or_old_boot_identity_cannot_signal_the_live_replacement(self):
        with tempfile.TemporaryDirectory() as root, Fixture(root) as daemon:
            boot, ticks = daemon.identity.split(':')
            previous_boot = ('00000000-0000-0000-0000-000000000001'
                             if boot != '00000000-0000-0000-0000-000000000001'
                             else '00000000-0000-0000-0000-000000000002')
            for abandoned in [f'{boot}:{int(ticks) + 1}', f'{previous_boot}:{ticks}']:
                with self.subTest(identity=abandoned), self.assertRaises(ValueError):
                    force.stop(str(daemon.path), daemon.child.pid, abandoned,
                               daemon.incarnation, .2, .3)
                self.assertIsNone(daemon.child.poll())
                self.assertFalse(daemon.marker.exists())
                self.assertTrue(daemon.path.exists())

    def test_other_incarnation_or_uncommitted_shutdown_never_authorizes_a_signal(self):
        with tempfile.TemporaryDirectory() as root, Fixture(root) as daemon:
            with self.assertRaises(ValueError):
                force.stop(str(daemon.path), daemon.child.pid, daemon.identity,
                           '00000000-0000-0000-0000-000000000001', .2, .3)
            self.assertIsNone(daemon.child.poll())
            self.assertFalse(daemon.marker.exists())
        with tempfile.TemporaryDirectory() as root, Fixture(root, committed=False) as daemon:
            with self.assertRaises(ValueError):
                bounded_stop(daemon)
            self.assertIsNone(daemon.child.poll())
            self.assertFalse(daemon.marker.exists())

    def test_uncertain_birth_identity_never_authorizes_a_signal(self):
        with tempfile.TemporaryDirectory() as root, Fixture(root) as daemon:
            for unknown in ['', 'unknown', '0:1', daemon.identity.split(':')[0] + ':unknown']:
                with self.subTest(identity=unknown), self.assertRaises(ValueError):
                    force.stop(str(daemon.path), daemon.child.pid, unknown,
                               daemon.incarnation, .2, .3)
            self.assertIsNone(daemon.child.poll())
            self.assertFalse(daemon.marker.exists())

    def test_special_pids_cannot_select_a_process_group_or_the_invoker(self):
        with tempfile.TemporaryDirectory() as root, Fixture(root) as daemon:
            for pid in [0, 1, -1, -daemon.child.pid, os.getpid(), os.getppid(), True]:
                with self.subTest(pid=pid), self.assertRaises(ValueError):
                    force.stop(str(daemon.path), pid, daemon.identity, daemon.incarnation, .2, .3)
            self.assertIsNone(daemon.child.poll())
            self.assertFalse(daemon.marker.exists())

    def test_unknown_or_exited_process_handle_is_not_a_stop_acknowledgement(self):
        child = subprocess.Popen([sys.executable, '-I', '-S', '-c', 'pass'])
        pid = child.pid
        handle = os.pidfd_open(pid, 0)
        try:
            child.wait(timeout=5)
            poller = select.poll()
            poller.register(handle, select.POLLIN)
            self.assertTrue(force.exited(poller))
            with tempfile.TemporaryDirectory() as root, Fixture(root) as daemon:
                with self.assertRaises(ProcessLookupError):
                    signal.pidfd_send_signal(handle, signal.SIGTERM, None, 0)
                self.assertIsNone(daemon.child.poll())
                with self.assertRaises(ProcessLookupError):
                    force.stop(str(daemon.path), pid, daemon.identity, daemon.incarnation, .2, .3)
                self.assertFalse(daemon.marker.exists())
        finally:
            os.close(handle)

    def test_existing_socket_cannot_be_a_symlink_or_a_replacement(self):
        with tempfile.TemporaryDirectory() as root, Fixture(root) as daemon:
            link = Path(root) / 'link.sock'
            link.symlink_to(daemon.path)
            with self.assertRaises(ValueError):
                force.stop(str(link), daemon.child.pid, daemon.identity, daemon.incarnation, .2, .3)
            self.assertTrue(link.is_symlink())
            self.assertFalse(daemon.marker.exists())
        with tempfile.TemporaryDirectory() as root, Fixture(root, 'replace_before_term') as daemon:
            with self.assertRaises(ValueError):
                bounded_stop(daemon)
            self.assertEqual(daemon.path.read_text(), 'replacement evidence')
            self.assertFalse(daemon.marker.exists())
            self.assertIsNone(daemon.child.poll())

    def test_no_escalation_or_socket_removal_when_term_is_not_terminal(self):
        with tempfile.TemporaryDirectory() as root, Fixture(root, 'ignore') as daemon:
            before = force.endpoint(str(daemon.path))
            with self.assertRaises(TimeoutError):
                bounded_stop(daemon)
            self.assertIsNone(daemon.child.poll())
            self.assertEqual(daemon.marker.read_text(), 'TERM\n')
            self.assertEqual(force.endpoint(str(daemon.path)), before)
        with tempfile.TemporaryDirectory() as root, Fixture(root, 'retain') as daemon:
            before = force.endpoint(str(daemon.path))
            with self.assertRaises(TimeoutError):
                bounded_stop(daemon)
            self.assertEqual(daemon.child.wait(timeout=2), 0)
            self.assertEqual(force.endpoint(str(daemon.path)), before)

    def test_endpoint_replacement_after_term_is_never_unlinked(self):
        with tempfile.TemporaryDirectory() as root, Fixture(root, 'replace_after_term') as daemon:
            with self.assertRaises(ValueError):
                bounded_stop(daemon)
            self.assertEqual(daemon.child.wait(timeout=2), 0)
            self.assertEqual(daemon.path.read_text(), 'replacement evidence')

    def test_missing_capability_and_invalid_inputs_never_signal(self):
        with tempfile.TemporaryDirectory() as root, Fixture(root) as daemon:
            for path, request, wait in [('relative', .2, .3), (str(daemon.path), 0, .3),
                                        (str(daemon.path), .2, float('nan')),
                                        (str(daemon.path) + '\n', .2, .3)]:
                with self.assertRaises(ValueError):
                    force.stop(path, daemon.child.pid, daemon.identity, daemon.incarnation,
                               request, wait)
            saved = force.os.pidfd_open
            del force.os.pidfd_open
            try:
                with self.assertRaisesRegex(ValueError, 'pidfd support'):
                    bounded_stop(daemon)
            finally:
                force.os.pidfd_open = saved
            self.assertIsNone(daemon.child.poll())
            self.assertFalse(daemon.marker.exists())


if __name__ == '__main__':
    if (sys.platform != 'linux' or not hasattr(os, 'pidfd_open')
            or not hasattr(signal, 'pidfd_send_signal')):
        raise SystemExit('This mandatory native gate requires Linux pidfds and Python 3.9+')
    unittest.main(verbosity=2)
