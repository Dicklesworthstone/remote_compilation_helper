#!/usr/bin/env python3
"""Exercise dependency preparation wrapper with controlled fixtures."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = (REPO / "rch/src/transfer/node_prepare.sh").read_text()

WORKER = """#!/bin/sh
set -eu
[ "$1" = prepare ] && [ "$2" = --project ] && [ "$3" = . ] &&
[ "$4" = --runtime ] && [ "$5" = "$RUNTIME" ] || exit 91
printf 'prepare:%s\n' "$5" >> "$ROOT/events"
if IFS= read -r ignored; then exit 92; fi
exit "$PREPARE_STATUS"
"""

COMPILER = """#!/bin/sh
set -eu
printf 'compiler\n' >> "$ROOT/events"
printf '%s\n' "$@"
exit "$COMPILER_STATUS"
"""

PROOF_WORKER = """#!/bin/sh
set -eu
[ "$#" = 11 ] && [ "$1" = prepare-proof ] && [ "$2" = --mode ] &&
[ "$3" = verify ] && [ "$4" = --project ] && [ "$5" = . ] &&
[ "$6" = --runtime ] && [ "$7" = "$RUNTIME" ] &&
[ "$8" = --expected-request-digest ] && [ "$9" = request-digest ] &&
[ "${10}" = --expected-attestation-digest ] &&
[ "${11}" = attestation-digest ] || exit 91
printf 'verify:%s\n' "$7" >> "$ROOT/events"
if IFS= read -r ignored; then exit 92; fi
printf 'verified preparation metadata\n'
exit "$PREPARE_STATUS"
"""

def executable(path, body):
    path.write_text(body)
    path.chmod(0o700)

class Fixture:
    def __init__(self, shell, runtime="node", package=True):
        self.root = Path(tempfile.mkdtemp(prefix="rch-node-prepare-"))
        self.project = self.root / "project"
        self.tools = self.root / "tools"
        self.project.mkdir()
        self.tools.mkdir()
        for name in ("sh", "bash"):
            found = shutil.which(name)
            if found:
                (self.tools / name).symlink_to(found)
        executable(self.tools / "rch-wkr", WORKER)
        executable(self.tools / "compiler", COMPILER)
        if package:
            (self.project / "package.json").write_text("{}\n")
        self.shell = shell
        self.runtime = runtime
        self.env = {
            "PATH": str(self.tools),
            "HOME": str(self.root),
            "LC_ALL": "C",
            "ROOT": str(self.root),
            "RUNTIME": runtime,
            "PREPARE_STATUS": "0",
            "COMPILER_STATUS": "0",
        }

    def run(self, args=None):
        args = args or ["compiler", "--noEmit", "quoted argument"]
        return subprocess.run(
            [self.shell, "-c", SCRIPT, "rch-prepare", self.runtime, *args],
            cwd=self.project,
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )

    def events(self):
        path = self.root / "events"
        return path.read_text().splitlines() if path.exists() else []

class Tests(unittest.TestCase):
    def test_accepted_proof_verifies_without_installing_again(self):
        for shell in ("sh", "bash"):
            for runtime in ("node", "bun"):
                f = Fixture(shell, runtime)
                executable(f.tools / "rch-wkr", PROOF_WORKER)
                f.env["COMPILER_STATUS"] = "23"
                result = f.run(args=[
                    "--source-proof", "request-digest", "attestation-digest",
                    "compiler", "literal $value; not shell code",
                ])
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(f.events(), [f"verify:{runtime}", "compiler"])
                self.assertEqual(result.stdout, b"literal $value; not shell code\n")
                self.assertEqual(result.stderr, b"verified preparation metadata\n")

    def test_failed_or_incomplete_proof_never_starts_the_workload(self):
        for shell in ("sh", "bash"):
            for package in (False, True):
                f = Fixture(shell, "bun", package=package)
                executable(f.tools / "rch-wkr", PROOF_WORKER)
                f.env["PREPARE_STATUS"] = "73"
                result = f.run(args=[
                    "--source-proof", "request-digest", "attestation-digest", "compiler",
                ])
                self.assertEqual(result.returncode, 121, result.stderr)
                self.assertEqual(f.events(), ["verify:bun"])
                self.assertIn(b"the command was not run", result.stderr)
                self.assertEqual(result.stdout, b"")
                invalid = f.run(args=["--source-proof", "request-digest"])
                self.assertEqual(invalid.returncode, 121, invalid.stderr)
                self.assertEqual(f.events(), ["verify:bun"])

    def test_proof_rejects_a_worker_without_the_qualified_protocol(self):
        for shell in ("sh", "bash"):
            f = Fixture(shell)
            result = f.run(args=[
                "--source-proof", "request-digest", "attestation-digest", "compiler",
            ])
            self.assertEqual(result.returncode, 121, result.stderr)
            self.assertEqual(f.events(), [])

    def test_cold_and_warm_always_prepare(self):
        for shell in ("sh", "bash"):
            for runtime in ("node", "bun"):
                for warm in (False, True):
                    f = Fixture(shell, runtime)
                    if warm:
                        (f.project / "node_modules").mkdir()
                    result = f.run()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(f.events(), [f"prepare:{runtime}", "compiler"])

    def test_prepare_failure_stops_workload(self):
        for shell in ("sh", "bash"):
            for runtime in ("node", "bun"):
                f = Fixture(shell, runtime)
                f.env["PREPARE_STATUS"] = "73"
                result = f.run(args=["sh", "-c", "compiler --noEmit || true"])
                self.assertEqual(result.returncode, 121, result.stderr)
                self.assertEqual(f.events(), [f"prepare:{runtime}"])
                self.assertIn(b"the command was not run", result.stderr)

    def test_project_local_tool_wins_after_prepare(self):
        for shell in ("sh", "bash"):
            for runtime, tool in (("node", "tsc"), ("bun", "bun")):
                f = Fixture(shell, runtime)
                local = f.project / "node_modules/.bin"
                local.mkdir(parents=True)
                executable(local / tool, COMPILER)
                executable(f.tools / tool, "#!/bin/sh\nexit 96\n")
                result = f.run(args=["sh", "-c", f"{tool} test 'literal ; argument'"])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(f.events(), [f"prepare:{runtime}", "compiler"])

    def test_terminal_status_is_preserved(self):
        for shell in ("sh", "bash"):
            f = Fixture(shell)
            f.env["COMPILER_STATUS"] = "23"
            result = f.run()
            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertEqual(f.events(), ["prepare:node", "compiler"])

    def test_manifest_free_workload_does_not_require_worker(self):
        for shell in ("sh", "bash"):
            f = Fixture(shell, package=False)
            (f.tools / "rch-wkr").rename(f.root / "retained-worker")
            result = f.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.events(), ["compiler"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
