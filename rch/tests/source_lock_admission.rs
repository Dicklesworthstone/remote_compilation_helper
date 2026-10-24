//! Real-process source-lock admission tests. The Python driver coordinates
//! native flock descriptors and the actual shipped holder; it does not model
//! the locking algorithm. No SSH server or worker fleet is needed.
#![cfg(target_os = "linux")]

use std::process::Command;

fn check(backend: &str, scenario: &str) {
    let directory = tempfile::tempdir().expect("source lock fixture");
    let script = directory.path().join("holder.sh");
    std::fs::write(&script, include_str!("../src/hook/source_lock_holder.sh"))
        .expect("write production holder");
    let output = Command::new("python3")
        .args(["-I", "-c", DRIVER])
        .arg(script)
        .arg(directory.path())
        .args([backend, scenario])
        .output()
        .expect("run Linux source lock regression (requires python3)");
    assert!(
        output.status.success(),
        "{backend}/{scenario}: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn native_waiter_does_not_reserve_unavailable_source_closure() {
    for scenario in ["convoy_exclusive", "convoy_shared", "cancelled_waiter"] {
        check("native", scenario);
    }
}

#[test]
fn native_retry_preserves_identity_and_complete_grant() {
    for scenario in [
        "path_replacement",
        "inode_alias",
        "terminal_handoff",
        "mutual_exclusion",
        "malformed_plan",
    ] {
        check("native", scenario);
    }
}

#[test]
fn gnu_waiter_does_not_reserve_unavailable_source_closure() {
    for backend in ["gnu", "gnu_large"] {
        for scenario in ["convoy_exclusive", "convoy_shared", "cancelled_waiter"] {
            check(backend, scenario);
        }
    }
}

#[test]
fn gnu_retry_preserves_identity_and_complete_grant() {
    for backend in ["gnu", "gnu_large"] {
        for scenario in [
            "path_replacement",
            "inode_alias",
            "terminal_handoff",
            "mutual_exclusion",
            "malformed_plan",
        ] {
            check(backend, scenario);
        }
    }
}

const DRIVER: &str = r#"
import fcntl
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time

script_path, root_path, backend, scenario = sys.argv[1:]
script = Path(script_path).read_text()
root = Path(root_path)
count = {"native": 32, "gnu": 2, "gnu_large": 64}[backend]
environment = os.environ.copy()
if backend == "gnu_large":
    # Exercise large GNU plans on workers without Python in PATH. The driver
    # itself still uses Python; the actual holder gets only its existing tools.
    binary_dir = root / "gnu-bin"
    binary_dir.mkdir()
    for name in ["sh", "bash", "flock", "cat", "uname"]:
        executable = shutil.which(name)
        assert executable is not None, "required fixture tool missing: " + name
        (binary_dir / name).symlink_to(executable)
    environment["PATH"] = str(binary_dir)
holders = []
blockers = []

class Holder:
    def __init__(self, paths, modes=None, terminal=None, malformed=False):
        modes = modes or ["x"] * len(paths)
        plan = root / ("plan-" + str(len(holders)))
        text = "".join(mode + " " + str(path) + "\n" for mode, path in zip(modes, paths))
        if malformed:
            text += "unexpected trailing record\n"
        plan.write_text(text)
        claim = root / ("claim-" + str(len(holders)))
        claim.write_bytes(b"durable-claim-sentinel\n")
        args = ["sh", "-c",
                'plan=$1; claim=$2; shift 2; exec 3<"$plan"; exec 4<"$claim"; exec sh -c "$@"',
                "source-lock-test", str(plan), str(claim), script, script, str(len(paths)), "READY"]
        if terminal is not None:
            args += [terminal]
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=environment)
        self.buffer = b""
        holders.append(self)

    def line(self, seconds=3):
        deadline = time.monotonic() + seconds
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise AssertionError("holder did not make progress before the observation deadline")
            data = os.read(self.process.stdout.fileno(), 4096)
            if not data:
                raise AssertionError("holder exited before readiness: " + self.process.stderr.read().decode())
            self.buffer += data
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line

    def not_ready(self):
        assert not self.buffer, self.buffer
        if select.select([self.process.stdout], [], [], 0.1)[0]:
            data = os.read(self.process.stdout.fileno(), 4096)
            assert not data, "partial source ownership was announced as ready: " + repr(data)
            assert self.process.poll() is None, "holder exited while expected to wait"

    def opened(self, path):
        # Wait for the real holder to reach the contested inode, rather than
        # letting a probe win before acquisition has even started. All execs
        # preserve the Popen PID. This observation grants no lock authority.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                files = Path("/proc/" + str(self.process.pid) + "/fd").iterdir()
                if any(os.readlink(entry) == str(path) for entry in files):
                    return
            except FileNotFoundError:
                pass
            if self.process.poll() is not None:
                raise AssertionError("holder exited during acquisition: " + self.process.stderr.read().decode())
            time.sleep(0.005)
        raise AssertionError("holder never opened the contended source root")

    def close(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()

    def finished(self, code):
        actual = self.process.wait(timeout=4)
        error = self.process.stderr.read().decode()
        assert actual == code, (actual, code, error)
        return error


def paths():
    result = [root / ("source root " + str(i) + ".lock") for i in range(count)]
    for path in result:
        path.touch()
    return result


def block(path):
    descriptor = path.open("r+b")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    blockers.append(descriptor)
    return descriptor


def available(path, mode=fcntl.LOCK_EX):
    with path.open("r+b") as descriptor:
        try:
            fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True


def complete_grant(items, shared_first=False):
    assert all(not available(path) for path in items), "an announced grant omitted a source root"
    if shared_first:
        assert available(items[0], fcntl.LOCK_SH), "shared intent was upgraded to exclusive ownership"


def convoy(shared_first):
    items = paths()
    busy = block(items[-1])
    modes = ["s" if shared_first and i == 0 else "x" for i in range(count)]
    waiting = Holder(items, modes)
    waiting.opened(items[-1])
    waiting.not_ready()
    # A real second build requiring only the free prefix must progress while
    # the first build's last dependency REMAINS owned by the external blocker.
    independent = Holder([items[0]])
    assert independent.line() == b"READY"
    assert not available(items[-1]), "fixture released the busy dependency too early"
    waiting.not_ready()
    independent.close()
    independent.finished(0)
    busy.close()
    assert waiting.line() == b"READY"
    complete_grant(items, shared_first)
    waiting.close()
    waiting.finished(0)
    assert all(available(path) for path in items), "completed holder leaked a source lock"


def cancelled_waiter():
    items = paths()
    busy = block(items[-1])
    waiting = Holder(items)
    waiting.opened(items[-1])
    waiting.close()
    error = waiting.finished(73)
    assert "requester" in error, error
    assert waiting.process.stdout.read() == b"", "cancelled waiter announced a grant"
    busy.close()
    assert all(available(path) for path in items), "cancelled waiter leaked a source lock"


def path_replacement():
    items = paths()
    busy = block(items[-1])
    waiting = Holder(items)
    waiting.opened(items[-1])
    retained = items[0].with_suffix(".retained")
    items[0].rename(retained)
    items[0].touch()
    busy.close()
    error = waiting.finished(73)
    assert "source lock path changed" in error, error
    assert waiting.process.stdout.read() == b"", "replaced inode granted source ownership"
    assert available(retained), "replaced lock inode remained held"
    assert all(available(path) for path in items)


def inode_alias():
    items = paths()
    alias = root / "physical alias.lock"
    os.link(items[0], alias)
    items[1] = alias
    items[0].write_bytes(b"retained original lock bytes")
    for first, second in [("x", "x"), ("x", "s"), ("s", "x"), ("s", "s")]:
        modes = [first, second] + ["x"] * (count - 2)
        waiting = Holder(items, modes)
        error = waiting.finished(73)
        assert "duplicate source lock inode" in error, error
        assert waiting.process.stdout.read() == b""
        assert all(available(path) for path in items)
        assert items[0].read_bytes() == alias.read_bytes() == b"retained original lock bytes"


def terminal_handoff():
    items = paths()
    busy = block(items[-1])
    terminal = ('printf "%s\\n" "$1"; IFS= read -r claim <&4 || exit 91; '
                'printf "CLAIM:%s\\n" "$claim"; IFS= read -r reply || exit 92; '
                '[ "$reply" = release ] || exit 93')
    waiting = Holder(items, terminal=terminal)
    waiting.opened(items[-1])
    waiting.not_ready()
    busy.close()
    assert waiting.line() == b"READY"
    assert waiting.line() == b"CLAIM:durable-claim-sentinel"
    complete_grant(items)
    waiting.process.stdin.write(b"release\n")
    waiting.process.stdin.flush()
    waiting.close()
    waiting.finished(0)
    assert all(available(path) for path in items), "terminal handoff leaked a source lock"


def mutual_exclusion():
    items = paths()
    first = Holder(items)
    assert first.line() == b"READY"
    second = Holder(items)
    second.opened(items[0])
    second.not_ready()
    complete_grant(items)
    first.close()
    first.finished(0)
    assert second.line() == b"READY"
    complete_grant(items)
    second.close()
    second.finished(0)
    assert all(available(path) for path in items)


def malformed_plan():
    items = paths()
    # Validation cannot sit behind contention and keep reserving a prefix for
    # a request that will never be eligible for a grant in the first place.
    busy = block(items[-1])
    waiting = Holder(items, malformed=True)
    error = waiting.finished(73)
    assert "count does not match" in error, error
    assert waiting.process.stdout.read() == b""
    busy.close()
    assert all(available(path) for path in items)


try:
    if scenario == "convoy_exclusive":
        convoy(False)
    elif scenario == "convoy_shared":
        convoy(True)
    else:
        {"cancelled_waiter": cancelled_waiter, "path_replacement": path_replacement,
         "inode_alias": inode_alias, "terminal_handoff": terminal_handoff,
         "mutual_exclusion": mutual_exclusion, "malformed_plan": malformed_plan}[scenario]()
    print(backend + "/" + scenario + ": passed")
finally:
    # Stop only children this test created, via their still-owned Popen handles.
    # Close requester streams first, exercising the real disconnect boundary.
    for holder in holders:
        holder.close()
    for holder in holders:
        try:
            holder.process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            holder.process.kill()
            holder.process.wait(timeout=4)
    for blocker in blockers:
        blocker.close()
"#;
