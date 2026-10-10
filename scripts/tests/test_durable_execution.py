#!/usr/bin/env python3
"""Exercise the durable-execution program embedded in transfer.rs.

--native compiles the actual Rust formatter in isolation with its production
shell-escape dependency; CI always uses this mode. Without it the ordinary Rust
strings are decoded for shell-only local checks. Neither mode qualifies the
whole TransferPipeline, SSH transport, or recovery journal integration.
"""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(os.environ.get(
    "RCH_DURABLE_TEST_SOURCE",
    str(Path(__file__).resolve().parents[2] / "rch/src/transfer.rs"),
))
NATIVE_RENDERER: Path | None = None


def build_native_renderer(directory: Path) -> Path:
    """Compile an unchanged copy of the production method, not another builder."""
    source = SOURCE.read_text()
    start = source.index('    fn durable_execution_command_with_stall(')
    end = source.index('\n    }\n', start) + len('\n    }\n')
    method = source[start:end]
    (directory / 'src').mkdir()
    (directory / 'Cargo.toml').write_text(
        '[package]\nname = "durable-renderer"\nversion = "0.0.0"\nedition = "2024"\n'
        '[workspace]\n[dependencies]\nshell-escape = "=0.1.5"\n'
    )
    (directory / 'src/main.rs').write_text(
        'use std::borrow::Cow;\nuse std::path::Path;\nuse shell_escape::escape;\n'
        'struct TransferPipeline { recovery_completion: Option<(String, String)> }\n'
        'impl TransferPipeline {\n' + method + '\n}\n'
        'fn main() {\n'
        '    let args: Vec<String> = std::env::args().collect();\n'
        '    let [_, path, identity, stall, command] = args.as_slice() else { panic!("arguments") };\n'
        '    let pipeline = TransferPipeline { recovery_completion: Some((path.clone(), identity.clone())) };\n'
        '    print!("{}", pipeline.durable_execution_command_with_stall(command.clone(), stall.parse().unwrap()));\n'
        '}\n'
    )
    environment = os.environ.copy()
    for name in ['RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_ENCODED_RUSTFLAGS']:
        environment.pop(name, None)
    environment['RUSTFLAGS'] = '-D warnings'
    subprocess.run(
        ['cargo', '+stable', 'build', '--manifest-path', str(directory / 'Cargo.toml'),
         '--target-dir', str(directory / 'target')],
        check=True, env=environment, timeout=180,
    )
    return directory / 'target/debug/durable-renderer'


def rust_string(source: str, at: int) -> str:
    """Decode a Rust ordinary string, including whitespace line continuations."""
    if source[at] != '"':
        raise ValueError("expected a Rust string")
    at += 1
    result: list[str] = []
    escapes = {'n': '\n', 'r': '\r', 't': '\t', '0': '\0', '"': '"', '\\': '\\'}
    while at < len(source):
        character = source[at]
        at += 1
        if character == '"':
            return ''.join(result)
        if character != '\\':
            result.append(character)
            continue
        character = source[at]
        at += 1
        if character == '\n':
            while at < len(source) and source[at] in ' \t\r\n':
                at += 1
        elif character in escapes:
            result.append(escapes[character])
        else:
            raise ValueError(f"unsupported Rust escape: {character!r}")
    raise ValueError("unterminated Rust string")


def script(path: Path, command: str, stall_seconds: int = 1) -> str:
    if NATIVE_RENDERER is not None:
        return subprocess.check_output(
            [str(NATIVE_RENDERER), str(path), 'abc123', str(stall_seconds), command],
            timeout=5, text=True,
        )
    source = SOURCE.read_text()
    start = source.index('fn durable_execution_command_with_stall(')
    source = source[start:]
    supervisor_at = source.index('let supervisor = format!(')
    supervisor = rust_string(source, source.index('"', supervisor_at))
    outer = rust_string(source, source.index('"set -e; rch_umask='))
    # These bindings mirror the production formatter, not a substitute shell
    # program. Changing its binding expressions requires updating this harness.
    for binding in [
        'supervisor = quote(&supervisor)', 'done = quote(path)',
        'identity = quote(identity)', 'stall_ticks = stall_secs * 5',
        'out_progress = quote(&format!("{path}.stdout.progress"))',
        'err_progress = quote(&format!("{path}.stderr.progress"))',
    ]:
        if binding not in source:
            raise ValueError(f"production formatter changed: {binding}")
    bindings = {
        'identity': shlex.quote('abc123'), 'done': shlex.quote(str(path)),
        'directory': shlex.quote(str(path.parent)),
        'pending': shlex.quote(str(path) + '.pending'),
        'claim': shlex.quote(str(path) + '.started'),
        'out': shlex.quote(str(path) + '.stdout'),
        'err': shlex.quote(str(path) + '.stderr'),
        'out_progress': shlex.quote(str(path) + '.stdout.progress'),
        'err_progress': shlex.quote(str(path) + '.stderr.progress'),
        'stall_ticks': stall_seconds * 5,
    }
    bindings['supervisor'] = shlex.quote(supervisor.format(command=command, **bindings))
    return outer.format(**bindings)


class DurableExecution(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix='rch-durable-')
        self.root = Path(self.temporary.name)
        self.receipt = self.root / "result : with ' quotes"
        self.activity = self.root / 'activity.lock'
        self.processes: list[subprocess.Popen] = []
        self.handles: list = []

    def tearDown(self) -> None:
        for process in self.processes:
            # Every process here starts its own group. Only signal it while the
            # unreaped group leader is still our direct child, never by name.
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
        for handle in self.handles:
            handle.close()
        self.temporary.cleanup()

    def start(self, command: str, blocked_reader: bool = False) -> subprocess.Popen:
        stdout = subprocess.PIPE if blocked_reader else open(self.root / 'client.stdout', 'wb')
        stderr = open(self.root / 'client.stderr', 'wb')
        self.handles.append(stderr)
        if not blocked_reader:
            self.handles.append(stdout)
        process = subprocess.Popen(
            ['flock', '-x', str(self.activity), 'sh', '-c', script(self.receipt, command)],
            cwd=self.root, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            start_new_session=True,
        )
        self.processes.append(process)
        return process

    def lock_is_free(self) -> bool:
        return subprocess.run(
            ['flock', '-n', str(self.activity), 'true'], timeout=2, check=False,
        ).returncode == 0

    def wait_free(self) -> None:
        until = time.monotonic() + 3
        while not self.lock_is_free():
            self.assertLess(time.monotonic(), until, 'follower retained the activity lock')
            time.sleep(0.02)

    def assert_unconfirmed(self, process: subprocess.Popen) -> None:
        self.assertEqual(process.wait(timeout=5), 255)
        self.assertFalse(self.receipt.exists(), 'must not fabricate a completion receipt')
        self.assertTrue(Path(str(self.receipt) + '.started').is_dir())
        self.assertIn(b'execution outcome remains unconfirmed',
                      (self.root / 'client.stderr').read_bytes())

    def test_supervisor_death_does_not_wait_forever_or_release_unrelated_jobs(self) -> None:
        witness = subprocess.Popen(['sleep', '30'], start_new_session=True)
        self.processes.append(witness)
        process = self.start('printf before > evidence; kill -KILL "$$"')
        self.assert_unconfirmed(process)
        self.wait_free()
        self.assertEqual((self.root / 'evidence').read_bytes(), b'before')
        self.assertIsNone(witness.poll(), 'an unrelated process must never be signalled')

    def test_failed_receipt_write_terminates_without_claiming_success(self) -> None:
        Path(str(self.receipt) + '.pending').mkdir()
        process = self.start('printf run > executed; exit 0')
        self.assert_unconfirmed(process)
        self.wait_free()
        self.assertEqual((self.root / 'executed').read_bytes(), b'run')
        self.assertTrue(Path(str(self.receipt) + '.pending').is_dir())

    def test_a_surviving_workload_keeps_activity_authority_after_supervisor_loss(self) -> None:
        process = self.start(
            '(sleep 2; printf finished > descendant-finished) & '
            'printf started > descendant-started; kill -KILL "$$"'
        )
        self.assert_unconfirmed(process)
        self.assertTrue((self.root / 'descendant-started').exists())
        self.assertFalse((self.root / 'descendant-finished').exists())
        self.assertFalse(self.lock_is_free(), 'surviving workload must keep source fencing')
        until = time.monotonic() + 4
        while not (self.root / 'descendant-finished').exists():
            self.assertLess(time.monotonic(), until, 'owned descendant did not finish')
            time.sleep(0.02)
        self.wait_free()
        self.assertFalse(self.receipt.exists(), 'descendant exit is not a completion receipt')

    def test_missing_receipt_stops_followers_blocked_on_an_unread_client_pipe(self) -> None:
        command = shlex.quote(sys.executable) + " -c 'import os; os.write(1, b\"x\" * 4194304)'"
        process = self.start(command + '; sleep 0.4; kill -KILL "$$"', blocked_reader=True)
        self.assert_unconfirmed(process)
        self.wait_free()
        self.assertEqual(Path(str(self.receipt) + '.stdout').stat().st_size, 4194304)

    def test_normal_nonzero_completion_preserves_exact_streams_status_and_umask(self) -> None:
        process = self.start("printf 'out\\000\\377'; printf 'err\\000\\376' >&2; umask > workload.umask; exit 7")
        self.assertEqual(process.wait(timeout=5), 7)
        self.wait_free()
        self.assertEqual(self.receipt.read_bytes(), b'abc123 7\n')
        self.assertEqual((self.root / 'client.stdout').read_bytes(), b'out\0\xff')
        self.assertEqual((self.root / 'client.stderr').read_bytes(), b'err\0\xfe')
        current_umask = os.umask(0)
        os.umask(current_umask)
        self.assertEqual(int((self.root / 'workload.umask').read_text().strip(), 8), current_umask)

    def test_live_reader_drains_both_large_transcripts(self) -> None:
        program = 'import os; os.write(1, b"o" * 2097152); os.write(2, b"e" * 2097152)'
        process = self.start(shlex.quote(sys.executable) + ' -c ' + shlex.quote(program))
        self.assertEqual(process.wait(timeout=10), 0)
        self.wait_free()
        self.assertEqual((self.root / 'client.stdout').read_bytes(), b'o' * 2097152)
        self.assertEqual((self.root / 'client.stderr').read_bytes(), b'e' * 2097152)

    def test_same_execution_claim_never_replays_an_unconfirmed_command(self) -> None:
        first = self.start('printf run >> execution-count; kill -KILL "$$"')
        self.assert_unconfirmed(first)
        self.wait_free()
        second = self.start('printf replay >> execution-count')
        self.assertNotEqual(second.wait(timeout=5), 0)
        self.assertEqual((self.root / 'execution-count').read_bytes(), b'run')
        self.assertFalse(self.receipt.exists())


if __name__ == '__main__':
    if '--native' in sys.argv:
        sys.argv.remove('--native')
        with tempfile.TemporaryDirectory(prefix='rch-durable-renderer-') as build:
            NATIVE_RENDERER = build_native_renderer(Path(build))
            result = unittest.main(verbosity=2, exit=False).result
        sys.exit(not result.wasSuccessful())
    unittest.main(verbosity=2)
