"""Drive the actual worker CLI; no Rust relay behavior is reimplemented here.

The forked fixture can retain stdout/stderr after its foreground process exits.
Every descendant has a natural deadline and an explicit release file. Cleanup
signals only the Popen-owned worker, never a PID read from fixture metadata.
Run with <rch-wkr binary>, or --fixture-controls for kernel/fixture checks only.
"""

import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest

WORKER = None
OUT = b"foreground-out\x00\xff\n"
ERR = b"foreground-err\x00\xfe\n"
TAIL = b"tail\x00\xfd\n"
PAYLOAD = bytes(range(256)) * 4096

FIXTURE = r'''
import os
from pathlib import Path
import signal
import sys
import time

root = Path(sys.argv[1])
mode = sys.argv[2]
code = int(sys.argv[3])

def write(fd, data):
    while data:
        data = data[os.write(fd, data):]

if mode == "bulk":
    data = bytes(range(256)) * 4096
    # Alternate streams with payloads larger than an ordinary pipe buffer.
    for offset in range(0, len(data), 16384):
        write(1, data[offset:offset + 16384])
        write(2, data[offset:offset + 16384])
    os._exit(code)
if mode == "signal":
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGTERM)
    os._exit(99)
if mode != "complete":
    ready_read, ready_write = os.pipe()
    if os.fork() == 0:
        os.close(ready_read)
        if mode == "stdout":
            os.close(2)
        elif mode == "stderr":
            os.close(1)
        write(ready_write, b"R")
        os.close(ready_write)
        deadline = time.monotonic() + 25
        while not (root / "release").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        try:
            if mode == "tail":
                write(1, b"tail\x00\xfd\n")
                write(2, b"tail\x00\xfd\n")
        except BrokenPipeError:
            pass
        (root / "descendant-done").write_text("done")
        os._exit(0)
    os.close(ready_write)
    assert os.read(ready_read, 1) == b"R"
    os.close(ready_read)
write(1, b"foreground-out\x00\xff\n")
write(2, b"foreground-err\x00\xfe\n")
(root / "foreground-exiting").write_text("ready")
os._exit(code)
'''


def until(predicate, detail, seconds=8):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(detail)
        time.sleep(0.01)


class Fixture:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-output-completion-"))
        self.program = self.root / "fixture.py"
        self.program.write_text(FIXTURE)
        self.worker = None
        self.descendant = False

    def command(self, mode, code):
        self.descendant = mode not in ("bulk", "signal", "complete")
        # Do not inherit site customization or instrumentation threads into
        # the deliberately forked process fixture.
        return [sys.executable, "-I", "-S", str(self.program), str(self.root), mode, str(code)]

    def start(self, mode, code=0, direct=False):
        command = self.command(mode, code)
        if not direct:
            command = [str(WORKER), "execute", "--workdir", str(self.root),
                       "--command", "exec " + shlex.join(command)]
        # Retain loader/library paths needed by Cargo-built binaries, but do
        # not let a caller's RCH log-file setting write outside this fixture.
        env = {key: value for key, value in os.environ.items() if not key.startswith("RCH_")}
        env.update({"HOME": str(self.root), "XDG_CACHE_HOME": str(self.root / "cache"),
                    "XDG_CONFIG_HOME": str(self.root / "config"), "RUST_LOG": "off",
                    "TOKIO_WORKER_THREADS": "2"})
        self.worker = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        return self.worker

    def release(self):
        (self.root / "release").write_text("release")

    def close(self):
        self.release()
        if self.worker is not None:
            try:
                self.worker.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.worker.kill()
                self.worker.communicate(timeout=5)
        if self.descendant and (self.root / "foreground-exiting").exists():
            until(lambda: (self.root / "descendant-done").exists(),
                  "fixture descendant did not acknowledge release")


class WorkerOutputTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def tearDown(self):
        self.fixture.close()

    def collect(self):
        out, err = self.fixture.worker.communicate(timeout=12)
        return self.fixture.worker.returncode, out, err

    def retained(self, mode, foreground, expected):
        self.fixture.start(mode, foreground)
        until(lambda: (self.fixture.root / "foreground-exiting").exists(),
              "foreground did not reach exit")
        code, out, err = self.collect()
        self.assertEqual(code, expected, (code, out, err))
        self.assertEqual(out, OUT)
        self.assertIn(ERR, err)
        self.assertFalse((self.fixture.root / "release").exists())
        self.assertFalse((self.fixture.root / "descendant-done").exists(),
                         "the test did not keep the pipe holder alive")
        if foreground == 0:
            self.assertIn(b"output stream to the client was truncated", err)

    def test_retained_stdout_cannot_hang_a_successful_command(self):
        self.retained("stdout", 0, 122)

    def test_retained_stderr_cannot_hang_a_successful_command(self):
        self.retained("stderr", 0, 122)

    def test_retained_both_pipes_cannot_hide_a_compiler_failure(self):
        self.retained("both", 42, 42)

    def test_tail_within_the_drain_window_is_not_discarded(self):
        self.fixture.start("tail")
        until(lambda: (self.fixture.root / "foreground-exiting").exists(),
              "foreground did not reach exit")
        self.fixture.release()
        code, out, err = self.collect()
        self.assertEqual((code, out, err), (0, OUT + TAIL, ERR + TAIL))

    def test_large_binary_stdout_and_stderr_are_conserved(self):
        self.fixture.start("bulk")
        code, out, err = self.collect()
        self.assertEqual(code, 0, err[:4096])
        self.assertEqual(out, PAYLOAD)
        self.assertEqual(err, PAYLOAD)

    def test_ordinary_exit_is_preserved(self):
        self.fixture.start("complete", 42)
        code, out, err = self.collect()
        self.assertEqual((code, out, err), (42, OUT, ERR))

    def test_signal_exit_is_preserved(self):
        self.fixture.start("signal")
        code, out, err = self.collect()
        self.assertEqual((code, out, err), (128 + signal.SIGTERM, b"", b""))


def fixture_controls():
    # Actual kernel behavior that triggers the defect: wait returns, but the
    # output read cannot finish until the separately gated descendant exits.
    # This is NOT execution or validation of the changed Rust implementation.
    for mode in ("stdout", "stderr", "both", "tail"):
        fixture = Fixture()
        try:
            child = fixture.start(mode, direct=True)
            assert child.wait(timeout=5) == 0
            try:
                child.communicate(timeout=0.1)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise AssertionError("fixture did not retain an output pipe")
            fixture.release()
            out, err = child.communicate(timeout=5)
            tail = TAIL if mode == "tail" else b""
            assert (out, err) == (OUT + tail, ERR + tail), (mode, out, err)
            print(mode + ": foreground exited; pipe held until explicit release", flush=True)
        finally:
            fixture.close()
    for mode, code in (("bulk", 0), ("complete", 42), ("signal", 0)):
        fixture = Fixture()
        try:
            child = fixture.start(mode, code, direct=True)
            out, err = child.communicate(timeout=8)
            expected = (0, PAYLOAD, PAYLOAD) if mode == "bulk" else (
                (42, OUT, ERR) if mode == "complete" else (-signal.SIGTERM, b"", b""))
            assert (child.returncode, out, err) == expected
            print(mode + ": fixture bytes and terminal status verified", flush=True)
        finally:
            fixture.close()
    print("PASS: seven fixture controls; Rust worker was not run", flush=True)


if __name__ == "__main__":
    assert os.name == "posix", "requires POSIX process and pipe semantics"
    assert len(sys.argv) == 2, "usage: output_completion.py <rch-wkr>|--fixture-controls"
    if sys.argv[1] == "--fixture-controls":
        fixture_controls()
    else:
        WORKER = Path(sys.argv[1]).resolve(strict=True)
        unittest.main(argv=[sys.argv[0]], verbosity=2)
