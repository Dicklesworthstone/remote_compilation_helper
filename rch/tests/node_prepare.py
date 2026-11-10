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
[ "$4" = --runtime ] && [ "$5" = "$RUNTIME" ] &&
[ "$6" = --execution-layout ] && [ "$#" = 6 ] || exit 91
printf 'prepare:%s\n' "$5" >> "$ROOT/events"
if IFS= read -r ignored; then exit 92; fi
printf '%s\n' "$LAYOUT_TOKEN"
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
printf 'verified preparation metadata\n' >&2
printf '%s\n' "$PROOF_LAYOUT_TOKEN"
exit "$PREPARE_STATUS"
"""

ANCESTOR_PROOF_WORKER = """#!/bin/sh
set -eu
[ "$#" = 13 ] && [ "$1" = prepare-proof ] && [ "$2" = --mode ] &&
[ "$3" = verify ] && [ "$4" = --project ] && [ "$5" = "$PREPARATION_ROOT" ] &&
[ "$6" = --runtime ] && [ "$7" = "$RUNTIME" ] &&
[ "$8" = --expected-request-digest ] && [ "$9" = request-digest ] &&
[ "${10}" = --expected-attestation-digest ] && [ "${11}" = attestation-digest ] &&
[ "${12}" = --invocation-project ] && [ "${13}" = . ] &&
[ "$PWD" = "$INVOCATION_DIR" ] || exit 91
printf 'verify:%s\n' "$7" >> "$ROOT/events"
printf '%s\n' "$PROOF_LAYOUT_TOKEN"
exit "$PREPARE_STATUS"
"""

YARN = """#!/bin/sh
set -eu
[ "$1" = run ] && [ "$2" = --binaries-only ] && [ "$3" = tsc ] || exit 93
shift 3
printf 'yarn:%s\n' "$PWD" >> "$ROOT/events"
exec compiler "$@"
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
        for name in ("sh", "bash", "head", "od", "cat"):
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
            "LAYOUT_TOKEN": "RCH_PREPARED_NODE_MODULES",
            "PROOF_LAYOUT_TOKEN": "RCH_PREPARED_DEPENDENCIES_VERIFIED",
        }

    def run(self, args=None, input=None, cwd=None):
        args = args or ["compiler", "--noEmit", "quoted argument"]
        return subprocess.run(
            [self.shell, "-c", SCRIPT, "rch-prepare", self.runtime, *args],
            cwd=cwd or self.project,
            env=self.env,
            stdin=subprocess.DEVNULL if input is None else None,
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )

    def events(self):
        path = self.root / "events"
        return path.read_text().splitlines() if path.exists() else []

class Tests(unittest.TestCase):
    def test_subdirectory_uses_nearest_prepared_tools_without_changing_cwd(self):
        for shell in ("sh", "bash"):
            for runtime in ("node", "bun"):
                for member_tool in (False, True):
                    f = Fixture(shell, runtime)
                    member = f.project / "packages/member"
                    invocation = member / "src/deep"
                    invocation.mkdir(parents=True)
                    (member / "package.json").write_text('{"name":"member"}\n')
                    for package, label in [(f.project, "root"), (member, "member")]:
                        if label == "member" and not member_tool:
                            continue
                        bin_dir = package / "node_modules/.bin"
                        bin_dir.mkdir(parents=True)
                        executable(bin_dir / "compiler", "#!/bin/sh\n"
                                   f"printf '{label}\\n' >> \"$ROOT/events\"\n"
                                   "printf '[%s]\\n' \"$PWD\" \"$@\"\ncat\nexit 23\n")
                    executable(f.tools / "rch-wkr", ANCESTOR_PROOF_WORKER)
                    f.env.update(PREPARATION_ROOT=str(f.project), INVOCATION_DIR=str(invocation))
                    args = ["--source-proof", "request-digest", "attestation-digest",
                            "--preparation-root", str(f.project), "compiler", "literal $value; argument"]
                    data = b"binary\x00stdin\xff\n"
                    result = f.run(args=args, input=data, cwd=invocation)
                    self.assertEqual(result.returncode, 23, result.stderr)
                    self.assertEqual(f.events(), [f"verify:{runtime}", "member" if member_tool else "root"])
                    self.assertEqual(result.stdout,
                                     f"[{invocation}]\n[literal $value; argument]\n".encode() + data)

    def test_subdirectory_search_stops_at_the_verified_preparation_root(self):
        for shell in ("sh", "bash"):
            f = Fixture(shell)
            invocation = f.project / "src"
            invocation.mkdir()
            outside = f.root / "node_modules/.bin"
            outside.mkdir(parents=True)
            executable(outside / "outside-only", COMPILER)
            executable(f.tools / "rch-wkr", ANCESTOR_PROOF_WORKER)
            f.env.update(PREPARATION_ROOT=str(f.project), INVOCATION_DIR=str(invocation))
            result = f.run(args=["--source-proof", "request-digest", "attestation-digest",
                                 "--preparation-root", str(f.project), "outside-only"], cwd=invocation)
            self.assertEqual(result.returncode, 127, result.stderr)
            self.assertEqual(f.events(), ["verify:node"])

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

    def test_yarn_pnp_launcher_preserves_cwd_arguments_stdin_and_status(self):
        for shell in ("sh", "bash"):
            for proved in (False, True):
                for relative in ("", "packages/member", "packages/member/src"):
                    f = Fixture(shell)
                    cwd = f.project / relative
                    cwd.mkdir(parents=True, exist_ok=True)
                    (cwd / "package.json").write_text("{}\n")
                    executable(f.tools / "yarn", YARN)
                    executable(f.tools / "compiler", """#!/bin/sh
printf 'compiler\n' >> "$ROOT/events"
printf '[%s]\n' "$@"
cat
exit 23
""")
                    f.env["LAYOUT_TOKEN"] = "RCH_PREPARED_YARN_PNP"
                    f.env["PROOF_LAYOUT_TOKEN"] = "RCH_PREPARED_DEPENDENCIES_VERIFIED_YARN_PNP"
                    compiler_args = ["--noEmit", "--incremental", "false", "--composite", "false", "--project",
                                     "literal $value; config.json"]
                    args = ["--pnp-tsc", str(len(compiler_args)), *compiler_args,
                            "sh", "-c", "printf original-shell-was-run"]
                    if proved:
                        executable(f.tools / "rch-wkr", PROOF_WORKER)
                        args = ["--source-proof", "request-digest", "attestation-digest", *args]
                    data = b"binary\x00stdin\xff\n"
                    result = f.run(args=args, input=data, cwd=cwd)
                    self.assertEqual(result.returncode, 23, result.stderr)
                    phase = "verify" if proved else "prepare"
                    self.assertEqual(f.events(), [f"{phase}:node", f"yarn:{cwd}", "compiler"])
                    expected = b"".join(f"[{argument}]\n".encode() for argument in compiler_args)
                    self.assertEqual(result.stdout, expected + data)
                    self.assertEqual(result.stderr, b"verified preparation metadata\n" if proved else b"")

    def test_bun_does_not_execute_a_yarn_pnp_layout(self):
        for shell in ("sh", "bash"):
            for proved in (False, True):
                f = Fixture(shell, "bun")
                executable(f.tools / "yarn", YARN)
                f.env["LAYOUT_TOKEN"] = "RCH_PREPARED_YARN_PNP"
                f.env["PROOF_LAYOUT_TOKEN"] = "RCH_PREPARED_DEPENDENCIES_VERIFIED_YARN_PNP"
                args = ["compiler"]
                if proved:
                    executable(f.tools / "rch-wkr", PROOF_WORKER)
                    args = ["--source-proof", "request-digest", "attestation-digest", *args]
                result = f.run(args=args)
                self.assertEqual(result.returncode, 121, result.stderr)
                self.assertEqual(f.events(), ["verify:bun" if proved else "prepare:bun"])
                self.assertIn(b"requires the Node runtime", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_layout_requires_exact_bounded_success_response(self):
        for shell in ("sh", "bash"):
            for proved in (False, True):
                token = (b"RCH_PREPARED_DEPENDENCIES_VERIFIED" if proved
                         else b"RCH_PREPARED_NODE_MODULES")
                for malformed in [
                    b"", b"unknown\n", token, token + b"\n\n",
                    token + b"\x00\n", b"\x00" + token + b"\n",
                    token + b"\nextra\n", b"x" * 4096,
                    token + b"\nRCH_PREPARE_STATUS:0" + b"x" * 4096,
                ]:
                    f = Fixture(shell)
                    (f.root / "selector").write_bytes(malformed)
                    executable(f.tools / "rch-wkr", """#!/bin/sh
printf 'prepare\n' >> "$ROOT/events"
cat "$ROOT/selector"
""")
                    args = ["compiler"]
                    if proved:
                        args = ["--source-proof", "request-digest", "attestation-digest", *args]
                    result = f.run(args=args)
                    self.assertEqual(result.returncode, 121, (malformed[:80], result.stderr))
                    self.assertEqual(f.events(), ["prepare"])
                    self.assertEqual(result.stdout, b"")

    def test_pnp_file_presence_cannot_select_the_launcher(self):
        for shell in ("sh", "bash"):
            f = Fixture(shell)
            (f.project / ".pnp.cjs").write_text("unverified loader\n")
            executable(f.tools / "yarn", YARN)
            result = f.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.events(), ["prepare:node", "compiler"])

    def test_pnp_without_literal_compiler_arguments_never_runs_original_shell(self):
        for shell in ("sh", "bash"):
            f = Fixture(shell)
            f.env["LAYOUT_TOKEN"] = "RCH_PREPARED_YARN_PNP"
            executable(f.tools / "yarn", YARN)
            result = f.run(args=["sh", "-c", "compiler --noEmit || true"])
            self.assertEqual(result.returncode, 121, result.stderr)
            self.assertEqual(f.events(), ["prepare:node"])
            self.assertIn(b"literal tsc --noEmit --incremental false --composite false", result.stderr)
            self.assertEqual(result.stdout, b"")

    def test_node_modules_keeps_original_payload_when_pnp_arguments_are_available(self):
        for shell in ("sh", "bash"):
            f = Fixture(shell)
            result = f.run(args=["--pnp-tsc", "5", "--noEmit", "--incremental", "false", "--composite", "false",
                                 "compiler", "original literal argument"])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"original literal argument\n")
            self.assertEqual(f.events(), ["prepare:node", "compiler"])

    def test_pnp_argument_count_is_bounded_and_keeps_a_real_workload(self):
        for shell in ("sh", "bash"):
            for count in ("0", "01", "-1", "abc", "257", "1000000000000000000000", "5"):
                f = Fixture(shell)
                result = f.run(args=["--pnp-tsc", count, "--noEmit", "compiler"])
                self.assertEqual(result.returncode, 121, (count, result.stderr))
                self.assertEqual(f.events(), [])
                self.assertEqual(result.stdout, b"")

    def test_manifest_free_workload_does_not_require_worker(self):
        for shell in ("sh", "bash"):
            f = Fixture(shell, package=False)
            (f.tools / "rch-wkr").rename(f.root / "retained-worker")
            result = f.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(f.events(), ["compiler"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
