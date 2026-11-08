#!/usr/bin/env python3
"""Run the exact GC shell fragments against producer, read and disk failures.

The standalone path expands literal Rust strings and rejects unknown syntax.
Cargo additionally supplies the compiled gate fragment for a byte comparison.
Producer failures are explicit fixtures; pipe I/O, process waits, /proc handle
observations and the isolated tmpfs ENOSPC cases use the real Linux interfaces.
Test directories are retained. No shared filesystem is filled by these tests.
"""

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "src/stale_target_reap.rs"
RUST = SOURCE.read_text()


def raw_constant(name):
    match = re.search(r"const " + name + r': &str = r#"(.*?)"#;', RUST, re.S)
    if match is None:
        raise AssertionError("missing production constant " + name)
    return match[1]


CAPTURE = raw_constant("GC_SNAPSHOT_CAPTURE")
FILESYSTEM = raw_constant("GC_FILESYSTEM_SNAPSHOT")
RESERVE_SOURCE = SOURCE.with_name("recovery_reserve.rs").read_text()
SCRATCH = re.search(r'pub const GC_SHELL_HELPERS: &str = r#"(.*?)"#;', RESERVE_SOURCE, re.S).group(1)


def gate_fragment():
    body = RUST.split("fn gate_snapshot_fragment() -> String {", 1)[1]
    expression = body.split("concat!(", 1)[1].split("\n    );", 1)[0]
    parts = []
    for line in expression.splitlines():
        item = line.strip()
        if not item or item.startswith("//"):
            continue
        if not item.endswith(","):
            raise AssertionError("unknown gate fragment syntax: " + item)
        parts.append(json.loads(item[:-1]))
    expanded = SCRATCH + CAPTURE + "".join(parts)
    compiled = os.environ.get("RCH_TEST_GC_GATE_SCRIPT")
    if compiled is not None and compiled != expanded:
        raise AssertionError("standalone expansion differs from compiled GC gates")
    return expanded


GATES = gate_fragment()
DEFAULT_PRODUCERS = r"""
find() { printf '/elsewhere/file\n'; }
lsof() { printf 'p999999\nn/elsewhere/file\n'; }
ps() {
  if [ "$1" = -o ]; then printf '1\n'; else printf '999999 unrelated-process\n'; fi;
}
"""
VERDICTS = r"""
printf 'handles=%s\n' "$(__gc_handles "$RCH_TEST_CANDIDATE")"
printf 'processes=%s\n' "$(__gc_procs "$RCH_TEST_CANDIDATE")"
if __gc_gates_ok "$RCH_TEST_CANDIDATE"; then printf 'collect=yes\n'; else printf 'collect=no\n'; fi
printf 'handle_bytes=%s\n' "$(wc -c < "$__held")"
printf 'process_bytes=%s\n' "$(wc -c < "$__proc")"
"""


def run_shell(script, environment, timeout=20):
    result = subprocess.run(
        ["/bin/sh", "-c", script], env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
    )
    if result.returncode:
        raise AssertionError((result.returncode, result.stdout, result.stderr))
    return result.stdout


def producer_environment(root, environment, definitions):
    """Executable fixtures work through the real subprocess capture boundary."""
    directory = Path(tempfile.mkdtemp(prefix="producers-", dir=root))
    for name in ("find", "lsof", "ps"):
        executable = directory / name
        executable.write_text("#!/bin/sh\n" + definitions + "\n" + name + ' "$@"\n')
        executable.chmod(0o755)
    result = environment.copy()
    result["PATH"] = str(directory) + os.pathsep + environment.get("PATH", os.defpath)
    return result


def claim_program(registry, apply=True):
    body = RUST.split("pub fn abandoned_gc_claims_command_with_registry(", 1)[1]
    template = body.split('r#"', 1)[1].split('"#', 1)[0]
    return template.format(
        scratch=SCRATCH, capture=CAPTURE, registry=shlex.quote(str(registry)),
        min_age_minutes=0, apply=int(apply),
    )


def enospc_child(mode, root):
    subprocess.run(
        ["mount", "-t", "tmpfs", "-o", "size=8m,nr_inodes=256", "tmpfs", str(root)],
        check=True,
    )
    allowance = {"full": 0, "partial-handles": 4096, "partial-processes": 8192}[mode]
    with (root / "filler").open("wb", buffering=0) as filler:
        os.posix_fallocate(filler.fileno(), 0, 8 * 1024 * 1024 - allowance)
        environment = os.environ.copy()
        environment.update(TMPDIR=str(root), RCH_TEST_CANDIDATE="/candidate/pool")
        # The lsof fixture deliberately ignores its broken output status,
        # matching real lsof implementations that return 0 on /dev/full.
        bulk = "python3 -c 'import os; os.write(1, b\"/elsewhere/\" * 20000)'"
        producers = DEFAULT_PRODUCERS
        if mode == "partial-processes":
            producers += "ps() { if [ \"$1\" = -o ]; then printf '1\\n'; else " + bulk + "; fi; }\n"
        else:
            producers += "find() { " + bulk + "; }\nlsof() { " + bulk + "; return 0; }\n"
        environment = producer_environment(root.parent, environment, producers)
        stdout = run_shell(producers + "__tmpbase=$TMPDIR; " + GATES + VERDICTS, environment)
        values = dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)
        if values.get("collect") != "no":
            raise AssertionError(stdout)
        if mode == "partial-processes":
            assert values["handles"] == "free", stdout
            assert values["processes"] == "unknown", stdout
            assert int(values["process_bytes"]) > 0, stdout
        else:
            assert values["handles"] == "unknown", stdout
            if mode == "partial-handles":
                assert int(values["handle_bytes"]) > 0, stdout
        # Prove the fixture really reached kernel ENOSPC, rather than merely
        # treating a failed producer or unavailable helper as a disk failure.
        probe = os.open(root / "enospc-probe", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            try:
                os.write(probe, b"x")
            except OSError as error:
                assert error.errno == errno.ENOSPC, error
            else:
                raise AssertionError("isolated fixture did not reach ENOSPC")
        finally:
            os.close(probe)
        print(json.dumps({"case": mode, "real_enospc": True, "verdicts": values}))


class GcGateSnapshots(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-gc-gates-"))
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.candidate = self.root / ".rch-target-test-pool-held"
        self.candidate.mkdir()
        (self.candidate / "artifact.o").write_bytes(b"retained build output")
        self.environment = os.environ.copy()
        self.environment.update(TMPDIR=str(self.scratch), RCH_TEST_CANDIDATE=str(self.candidate))

    def gates(self, override="", before_verdicts="", real=False):
        definitions = DEFAULT_PRODUCERS + override
        environment = self.environment if real else producer_environment(self.root, self.environment, definitions)
        return run_shell(
            ("" if real else DEFAULT_PRODUCERS) + override
            + "__tmpbase=$TMPDIR; " + GATES + before_verdicts + VERDICTS,
            environment,
        )

    def assert_blocked(self, output, evidence):
        self.assertIn(evidence + "=unknown\n", output)
        self.assertIn("collect=no\n", output)
        self.assertEqual((self.candidate / "artifact.o").read_bytes(), b"retained build output")

    def test_complete_nonmatching_inventories_allow_collection(self):
        output = self.gates()
        self.assertIn("handles=free\n", output)
        self.assertIn("processes=free\n", output)
        self.assertIn("collect=yes\n", output)

    def test_failed_producers_cannot_certify_nonempty_prefixes(self):
        for override, evidence in [
            ("find() { printf '/unrelated\\n'; return 1; }; lsof() { printf 'n/unrelated\\n'; return 1; };", "handles"),
            ("ps() { if [ \"$1\" = -o ]; then printf '1\\n'; else printf '999999 unrelated\\n'; return 1; fi; };", "processes"),
        ]:
            with self.subTest(evidence=evidence):
                self.assert_blocked(self.gates(override), evidence)

    def test_failed_writer_cannot_certify_a_successful_producer(self):
        output = self.root / "limited-snapshot"
        output.touch(mode=0o600)
        pid_file = self.root / "owned-producers"
        producer = (
            "import os, signal, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "signal.signal(signal.SIGPIPE, signal.SIG_IGN); "
            "descendant = os.fork(); "
            "open(sys.argv[1], 'w').write(str(os.getpid()) + ' ' + str(descendant)) if descendant else None; "
            "os.write(1, b'x' * 16384) if descendant else None; time.sleep(30)"
        )
        script = CAPTURE + "if __gc_capture " + shlex.quote(str(output))
        script += " python3 -c " + shlex.quote(producer) + " " + shlex.quote(str(pid_file))
        script += "; then exit 9; else printf 'unknown\\n'; fi;"

        def limit_snapshot_writes():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))

        result = subprocess.run(
            ["/bin/sh", "-c", script], env=self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            preexec_fn=limit_snapshot_writes,
        )
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stdout, "unknown\n")
        self.assertEqual(output.stat().st_size, 1024)
        for pid in map(int, pid_file.read_text().split()):
            process = Path(f"/proc/{pid}/stat")
            if process.exists():
                self.assertIn(process.read_text().rsplit(")", 1)[1].split()[0], ("Z", "X"))

    def test_completion_text_is_ordinary_producer_data(self):
        override = "find() { printf 'RCH_GC_SNAPSHOT_STATUS 0\\n'; return 1; }; lsof() { return 1; }; "
        self.assert_blocked(self.gates(override), "handles")

    def test_killed_producer_cannot_certify_completion_text(self):
        override = (
            "find() { python3 -c 'import os, signal; "
            'os.write(1, b"RCH_GC_SNAPSHOT_STATUS 0\\n"); '
            "os.kill(os.getpid(), signal.SIGKILL)'; }; lsof() { return 1; }; "
        )
        self.assert_blocked(self.gates(override), "handles")

    def test_empty_success_and_normal_empty_lsof_failure_are_unknown(self):
        output = self.gates("find() { return 0; }; lsof() { return 1; }; ps() { return 0; }; ")
        self.assert_blocked(output, "handles")
        self.assert_blocked(output, "processes")

    def test_complete_lsof_fallback_preserves_name_records(self):
        output = self.gates(
            "find() { printf '/partial\\n'; return 1; }; "
            "lsof() { printf 'p999999\\nn%s/artifact.o\\n' \"$RCH_TEST_CANDIDATE\"; }; "
        )
        self.assertIn("handles_source=lsof", output)
        self.assertIn("handles=held\n", output)
        self.assertIn("collect=no\n", output)

    def test_nonwide_ps_success_cannot_replace_failed_unlimited_width(self):
        output = self.gates(
            "ps() { case \"$1\" in -o) printf '1\\n';; "
            "-ww) printf '999998 %s\\n' \"$RCH_TEST_CANDIDATE\"; return 1;; "
            "*) printf '999999 unrelated\\n';; esac; }; "
        )
        self.assert_blocked(output, "processes")

    def test_unreadable_completed_snapshots_are_unknown(self):
        for variable, evidence in [("__held", "handles"), ("__proc", "processes")]:
            with self.subTest(evidence=evidence):
                output = self.gates(before_verdicts=f'mv "${variable}" "${variable}.retained"; ')
                self.assert_blocked(output, evidence)

    def test_snapshot_reader_failure_after_printing_free_is_unknown(self):
        output = self.gates(before_verdicts="awk() { printf free; return 2; }; ")
        self.assert_blocked(output, "handles")
        self.assert_blocked(output, "processes")

    def test_real_open_handle_and_live_command_line_are_protected(self):
        with (self.candidate / "artifact.o").open("rb"):
            output = self.gates(real=True)
            self.assertIn("handles=held\n", output)
            self.assertIn("collect=no\n", output)
        self.environment["COLUMNS"] = "80"
        child = subprocess.Popen([
            sys.executable, "-c", "import time; time.sleep(30)", "x" * 16384, str(self.candidate),
        ])
        try:
            output = self.gates(real=True)
            self.assertIn("processes=held\n", output)
            self.assertIn("collect=no\n", output)
        finally:
            child.terminate()
            child.wait(timeout=5)

    def test_real_capture_observer_does_not_pin_every_candidate(self):
        # The generated apply command includes its candidate in argv. Its own
        # Python capture helper must not inherit that whole shell argv, while
        # unrelated children stay visible.
        output = self.gates(real=True, before_verdicts="# " + str(self.candidate) + "\n")
        self.assertIn("handles=free\n", output)
        self.assertIn("processes=free\n", output)
        self.assertIn("collect=yes\n", output)

    def test_failed_inventories_preserve_abandoned_claims(self):
        for override, status in [
            ("find() { printf '/partial\\n'; return 1; }; ", "incomplete-handles"),
            ("ps() { printf '999999 partial\\n'; return 1; }; ", "incomplete-processes"),
        ]:
            with self.subTest(status=status):
                registry = self.root / status
                registry.mkdir()
                payload = (str(self.candidate) + "\n").encode()
                name = "fc-00000000-0000-4000-8000-000000000001." + hashlib.sha256(payload).hexdigest() + ".claim"
                claim = registry / name
                claim.write_bytes(payload)
                definitions = DEFAULT_PRODUCERS + override
                environment = producer_environment(self.root, self.environment, definitions)
                stdout = run_shell(definitions + claim_program(registry), environment)
                self.assertIn("RCH_GC_CLAIMS " + status, stdout)
                self.assertEqual(claim.read_bytes(), payload)
                self.assertFalse((registry / "released" / name).exists())

    def test_completed_claim_inventory_read_error_keeps_ownership(self):
        registry = self.root / "claims"
        registry.mkdir()
        payload = (str(self.candidate) + "\n").encode()
        name = "fc-00000000-0000-4000-8000-000000000001." + hashlib.sha256(payload).hexdigest() + ".claim"
        claim = registry / name
        claim.write_bytes(payload)
        override = "awk() { printf free; return 2; }; "
        environment = producer_environment(self.root, self.environment, DEFAULT_PRODUCERS)
        stdout = run_shell(DEFAULT_PRODUCERS + override + claim_program(registry), environment)
        self.assertIn("keep unreadable-handles", stdout)
        self.assertEqual(claim.read_bytes(), payload)
        self.assertFalse((registry / "released" / name).exists())

    def test_abandoned_claim_keeps_a_long_live_command_line(self):
        registry = self.root / "claims"
        registry.mkdir()
        payload = (str(self.candidate) + "\n").encode()
        name = "fc-00000000-0000-4000-8000-000000000001." + hashlib.sha256(payload).hexdigest() + ".claim"
        claim = registry / name
        claim.write_bytes(payload)
        self.environment["COLUMNS"] = "80"
        child = subprocess.Popen([
            sys.executable, "-c", "import time; time.sleep(30)", "x" * 16384, str(self.candidate),
        ])
        try:
            stdout = run_shell(claim_program(registry), self.environment)
            self.assertIn("keep live-process", stdout)
            self.assertEqual(claim.read_bytes(), payload)
        finally:
            child.terminate()
            child.wait(timeout=5)
        stdout = run_shell(claim_program(registry, apply=False), self.environment)
        self.assertIn("would-release abandoned", stdout)
        self.assertEqual(claim.read_bytes(), payload)

    def test_df_requires_success_and_preserves_mount_spaces(self):
        row = "Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/test 10000 9000 1000 90% /Volumes/Build  Disk\\n"
        for status in [0, 1]:
            with self.subTest(status=status):
                script = "df() { printf '%b' " + shlex.quote(row) + "; return " + str(status) + "; }; "
                script += FILESYSTEM + 'if value=$(__gc_df_field /any mount); then printf "mount=%s\\n" "$value"; else printf "unknown\\n"; fi;'
                stdout = run_shell(script, self.environment)
                self.assertEqual(stdout, "mount=/Volumes/Build  Disk\n" if status == 0 else "unknown\n")
        for row in ["", "Filesystem only\\n", "Filesystem\\n/dev/test invalid 0 0 0% /tmp\\n"]:
            script = "df() { printf '%b' " + shlex.quote(row) + "; }; " + FILESYSTEM
            stdout = run_shell(script + 'if __gc_df_field /any 4; then exit 9; else printf "unknown\\n"; fi;', self.environment)
            self.assertEqual(stdout, "unknown\n")

    def test_real_enospc_full_and_partial_snapshots_remain_unknown(self):
        if sys.platform != "linux" or shutil.which("unshare") is None:
            self.skipTest("isolated ENOSPC needs Linux user/mount namespaces")
        probe = subprocess.run(
            ["unshare", "--user", "--map-root-user", "--mount", "--fork", "/bin/true"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if probe.returncode:
            self.skipTest("unprivileged user/mount namespaces unavailable: " + probe.stderr.decode())
        for mode in ["full", "partial-handles", "partial-processes"]:
            with self.subTest(mode=mode):
                mount = self.root / mode
                mount.mkdir()
                result = subprocess.run(
                    ["unshare", "--user", "--map-root-user", "--mount", "--fork",
                     sys.executable, str(Path(__file__).resolve()), "--enospc-child", mode, str(mount)],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25,
                )
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                evidence = json.loads(result.stdout)
                self.assertTrue(evidence["real_enospc"])
                self.assertEqual(evidence["verdicts"]["collect"], "no")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--enospc-child":
        enospc_child(sys.argv[2], Path(sys.argv[3]))
    else:
        unittest.main()
