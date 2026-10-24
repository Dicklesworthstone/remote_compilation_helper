#!/usr/bin/env python3
"""GH #105: real registry/topology transactions, including namespace races.

Uses the production registry, record helpers and retry loop with local files,
hashes and flocks. Topology commands and fault-injected tools are explicit test
inputs, not a claim of Cargo, SSH-fleet or native-Darwin qualification.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import select
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[2]
REGISTRY = Path(os.environ.get("RCH_TEST_SOURCE_TOPOLOGY_SCRIPT",
                              REPO / "rch/src/hook/source_claim_registry.sh"))
RETRY = Path(os.environ.get("RCH_TEST_SOURCE_TOPOLOGY_RETRY",
                           REPO / "rch/src/hook/source_claim_admission.sh"))
SHELL = os.environ.get("RCH_TEST_SOURCE_TOPOLOGY_SHELL", "sh")


def production_helpers() -> str:
    supplied = os.environ.get("RCH_TEST_SOURCE_TOPOLOGY_HELPERS")
    if supplied:
        return Path(supplied).read_text(encoding="utf-8")
    source = (REPO / "rch-common/src/stale_target_reap.rs").read_text(encoding="utf-8")
    marker = 'pub const SOURCE_CLAIM_RECORD_HELPERS: &str = r#"'
    if source.count(marker) != 1:
        raise RuntimeError("cannot locate production claim helpers")
    helpers, end, _ = source.split(marker, 1)[1].partition('"#;')
    if not end:
        raise RuntimeError("unterminated production claim helpers")
    return helpers


@unittest.skipUnless(shutil.which("flock") and shutil.which(SHELL), "POSIX flock/shell required")
class SourceTopologyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rch-topology-105-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.registry = self.base / "registry"
        for directory in ("", "released", "cancelled", "quarantine"):
            (self.registry / directory).mkdir(parents=True, exist_ok=True)
        (self.registry / "metadata.lock").touch()
        self.canonical = self.base / "projects with spaces"
        self.alias = self.base / "dp"
        self.scope = [self.canonical, self.alias]
        self.script = production_helpers() + "\n" + REGISTRY.read_text(encoding="utf-8")
        self.env = {**os.environ, "LC_ALL": "C"}

    @staticmethod
    def root_bytes(roots):
        return ("\n".join(sorted(set(map(str, roots)))) + "\n").encode()

    def command(self, operation, token, roots, *arguments):
        data = self.root_bytes(roots)
        digest = hashlib.sha256(data).hexdigest()
        return ["flock", "-x", str(self.registry / "metadata.lock"), SHELL,
                "-c", self.script, "rch-source-registry", str(self.registry),
                token, digest, operation, *arguments], data

    def run_op(self, operation, token, roots, *arguments, env=None):
        command, data = self.command(operation, token, roots, *arguments)
        return subprocess.run(command, input=data, capture_output=True, timeout=10,
                              env=self.env if env is None else env)

    def topology_commands(self):
        canonical, alias = map(lambda p: shlex.quote(str(p)), self.scope)
        check = (f'[ -d {canonical} ] && [ -L {alias} ] && '
                 f'[ "$(readlink -f -- {alias})" = "$(readlink -f -- {canonical})" ]')
        # Like the production builder, ln runs in a command substitution after
        # testing alias absence. The registry must guard this check/create gap.
        create = (f'set -eu; mkdir -p -- {canonical}; '
                  f'if [ ! -e {alias} ] && [ ! -L {alias} ]; then '
                  f'created=$(ln -s -- {canonical} {alias} 2>&1) || exit 44; fi; '
                  'printf "RCH_TOPOLOGY_OK\\n"')
        return check, create

    def topology(self, token="cc", create=None, env=None):
        check, default_create = self.topology_commands()
        return self.run_op("topology", token, self.scope, check,
                           default_create if create is None else create, env=env)

    def accepted(self, result, stdout=b""):
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, stdout)
        self.assertEqual(result.stderr, b"")

    def initialize(self):
        self.accepted(self.topology(), b"RCH_TOPOLOGY_OK\n")
        self.assertEqual(self.alias.resolve(), self.canonical.resolve())

    def inventory(self):
        return {str(p.relative_to(self.registry)): (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
                for p in self.registry.rglob("*") if p.is_file()}

    def fault_tools(self, tools):
        directory = self.base / ("tools-" + str(len(list(self.base.glob("tools-*")))))
        directory.mkdir()
        for name, body in tools.items():
            tool = directory / name
            tool.write_text("#!/bin/sh\n" + body + "\n")
            tool.chmod(0o700)
        return {**self.env, "PATH": str(directory) + os.pathsep + self.env["PATH"]}

    def test_namespace_never_becomes_a_durable_build_claim(self):
        before = self.inventory()
        self.initialize()
        self.assertEqual(before, self.inventory())
        self.assertEqual(list(self.canonical.iterdir()), [])

    def test_unrelated_repositories_coexist_through_the_shared_alias(self):
        self.initialize()
        a = [self.canonical / "a", self.canonical / "a/.rch-target"]
        b = [self.alias / "b", self.alias / "b/.rch-target"]
        self.accepted(self.run_op("try-acquire", "a1", a))
        self.accepted(self.run_op("try-acquire", "b1", b))
        records = list(self.registry.glob("*.claim"))
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertNotIn(str(self.canonical), record.read_text().splitlines())
            self.assertNotIn(str(self.alias), record.read_text().splitlines())

    def test_sequential_repository_jobs_require_exact_release(self):
        self.initialize()
        roots = [self.canonical / "repo", self.canonical / "repo/.rch-target"]
        for token in ("01", "02", "03"):
            self.accepted(self.run_op("try-acquire", token, roots))
            self.assertEqual(self.run_op("try-acquire", "ffff", roots).returncode, 75)
            self.accepted(self.run_op("release", token, roots))
        self.assertEqual(len(list((self.registry / "released").glob("*.claim"))), 3)

    def test_parent_child_alias_pool_and_dependency_overlaps_remain_exclusive(self):
        self.initialize()
        roots = [self.canonical / "repo/nested", self.base / "pools/shared",
                 self.canonical / "dependency"]
        self.accepted(self.run_op("try-acquire", "a1", roots))
        before = self.inventory()
        for candidate in (self.canonical / "repo", self.canonical / "repo/nested/child",
                          self.alias / "repo/nested", *roots[1:]):
            with self.subTest(candidate=candidate):
                self.assertEqual(self.run_op("try-acquire", "b1", [candidate]).returncode, 75)
                self.assertEqual(self.run_op("acquire", "b1", [candidate]).returncode, 73)
        self.assertEqual(before, self.inventory())

    def test_missing_namespace_cannot_bypass_a_physical_owner(self):
        physical = self.base / "physical"
        physical.mkdir()
        self.canonical.symlink_to(physical, target_is_directory=True)
        roots = [physical / "repo"]
        self.accepted(self.run_op("acquire", "a1", roots))
        before = self.inventory()
        self.assertEqual(self.topology().returncode, 75)
        self.assertFalse(self.alias.exists())
        self.assertEqual(before, self.inventory())
        self.accepted(self.run_op("release", "a1", roots))
        self.initialize()

    def test_healthy_namespace_does_not_need_parent_authority(self):
        self.initialize()
        self.accepted(self.run_op("acquire", "a1", [self.canonical / "a"]))
        before = self.inventory()
        self.accepted(self.topology(create="exit 97"), b"RCH_TOPOLOGY_OK\n")
        self.assertEqual(before, self.inventory())

    def test_legacy_broad_claim_is_not_rewritten_or_expired(self):
        self.initialize()
        self.accepted(self.run_op("acquire", "a1", self.scope))
        before = self.inventory()
        self.accepted(self.topology(), b"RCH_TOPOLOGY_OK\n")
        self.assertEqual(self.run_op("try-acquire", "b1", [self.alias / "unrelated"]).returncode, 75)
        self.assertEqual(before, self.inventory())
        self.accepted(self.run_op("release", "a1", self.scope))
        self.accepted(self.run_op("try-acquire", "b1", [self.alias / "unrelated"]))

    def test_successful_noop_mutator_cannot_acknowledge_missing_topology(self):
        result = self.topology(create='printf "RCH_TOPOLOGY_OK\\n"')
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertFalse(self.canonical.exists())
        self.assertEqual(set(self.inventory()), {"metadata.lock"})

    def test_mutator_stdout_is_not_a_success_acknowledgement(self):
        result = self.topology(create='printf "RCH_TOPOLOGY_OK\\n"; exit 75')
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(set(self.inventory()), {"metadata.lock"})

    def test_durability_failure_refuses_then_additive_setup_can_resume(self):
        result = self.topology(env=self.fault_tools({"sync": "exit 1"}))
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertTrue(self.alias.is_symlink(), "failed barriers must preserve additive setup")
        self.assertEqual(set(self.inventory()), {"metadata.lock"})
        self.initialize()

    def test_already_present_fast_path_reestablishes_durability(self):
        self.initialize()
        result = self.topology(env=self.fault_tools({"sync": "exit 1"}))
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(self.alias.resolve(), self.canonical.resolve())

    def race_alias(self, symlink):
        other = self.base / "unrelated live tree"
        other.mkdir()
        real_ln = shlex.quote(shutil.which("ln"))
        destination = shlex.quote(str(self.alias))
        create_race = (real_ln + " -s -- " + shlex.quote(str(other)) + " " + destination
                       if symlink else "mkdir -- " + destination)
        body = create_race + "\nexec " + real_ln + ' "$@"'
        # The wrapper also exercises Darwin's g-prefixed selection on Linux.
        result = self.topology(env=self.fault_tools({"ln": body, "gln": body}))
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(list(other.iterdir()), [])
        self.assertEqual(list(self.alias.iterdir()), [])
        self.assertEqual(set(self.inventory()), {"metadata.lock"})

    def test_raced_directory_never_receives_a_nested_symlink(self):
        self.race_alias(False)

    def test_raced_symlink_never_writes_into_another_tree(self):
        self.race_alias(True)

    def test_ready_and_new_claim_wait_for_complete_namespace_confirmation(self):
        entered, gate = self.base / "entered", self.base / "continue"
        real_sync = shlex.quote(shutil.which("sync"))
        env = self.fault_tools({"sync": (
            "touch " + shlex.quote(str(entered)) + "\n"
            + "while [ ! -e " + shlex.quote(str(gate)) + " ]; do sleep 0.01; done\n"
            + "exec " + real_sync + ' "$@"'
        )})
        command, data = self.command("topology", "a1", self.scope, *self.topology_commands())
        initializer = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=env)
        contender = None
        try:
            initializer.stdin.write(data)
            initializer.stdin.close()
            initializer.stdin = None
            deadline = time.monotonic() + 5
            while not entered.exists() and initializer.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(entered.exists(), "initialization skipped its durability barrier")
            self.assertEqual(select.select([initializer.stdout], [], [], 0.05)[0], [],
                             "readiness escaped before namespace confirmation")
            command, data = self.command("try-acquire", "b1", [self.alias / "repo"])
            contender = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, env=self.env)
            contender.stdin.write(data)
            contender.stdin.close()
            contender.stdin = None
            time.sleep(0.05)
            self.assertIsNone(contender.poll(), "admission crossed an unfinished namespace change")
            self.assertEqual(list(self.registry.glob("*.claim")), [])
            gate.touch()
            stdout, stderr = initializer.communicate(timeout=5)
            self.assertEqual((initializer.returncode, stdout, stderr), (0, b"RCH_TOPOLOGY_OK\n", b""))
            stdout, stderr = contender.communicate(timeout=5)
            self.assertEqual((contender.returncode, stdout, stderr), (0, b"", b""))
            self.assertEqual(len(list(self.registry.glob("*.claim"))), 1)
        finally:
            gate.touch()
            for child in (initializer, contender):
                if child is not None:
                    if child.poll() is None:
                        child.terminate()
                    child.communicate(timeout=5)

    def start_retry(self, attempts):
        roots = [self.canonical / "repo"]
        self.accepted(self.run_op("acquire", "a1", roots))
        command, data = self.command("try-acquire", "b1", roots)
        lock, counter = self.base / "source.lock", self.base / "attempts"
        script = ("rch_source_attempt() { (\nset -eu\n"
                  + 'exec 9<>' + shlex.quote(str(lock)) + '\nflock -x 9\n'
                  + "printf 'attempt\\n' >> " + shlex.quote(str(counter)) + "\n"
                  + "exec " + shlex.join(command) + " <<'RCH_RETRY_ROOTS'\n"
                  + data.decode() + "RCH_RETRY_ROOTS\n); }\n"
                  + f"rch_admission_attempts={attempts}\n" + RETRY.read_text())
        child = subprocess.Popen([SHELL, "-c", script], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=self.env)
        self.addCleanup(self.reap, child)
        deadline = time.monotonic() + 5
        while not counter.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(counter.exists(), "retry attempt did not start")
        return child, roots, lock, counter

    @staticmethod
    def reap(child):
        if child.poll() is None:
            child.terminate()
        child.communicate(timeout=5)

    def test_delayed_release_can_take_source_locks_between_retry_attempts(self):
        self.initialize()
        child, roots, lock, counter = self.start_retry(3)
        command, data = self.command("release", "a1", roots)
        release = subprocess.run(["flock", "-x", str(lock), *command], input=data,
                                 capture_output=True, timeout=5, env=self.env)
        self.accepted(release)
        stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(stdout, b"")
        self.assertGreaterEqual(len(counter.read_text().splitlines()), 2)
        self.assertEqual(len(list(self.registry.glob("*.claim"))), 1)
        self.assertEqual(len(list((self.registry / "released").glob("*.claim"))), 1)

    def test_persistent_active_owner_exhausts_retry_without_stealing_it(self):
        self.initialize()
        child, roots, _, counter = self.start_retry(2)
        before = self.inventory()
        stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 75, stderr)
        self.assertEqual(stdout, b"")
        self.assertEqual(len(counter.read_text().splitlines()), 2)
        self.assertEqual(before, self.inventory())


if __name__ == "__main__":
    unittest.main(verbosity=2)
