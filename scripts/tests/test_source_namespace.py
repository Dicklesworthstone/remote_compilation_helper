#!/usr/bin/env python3
"""Run #105 topology regressions with the production path-translation program.

This covers local native protocol transactions, not Rust compilation or a live
SSH fleet. Rust's source_namespace unit test additionally executes its actual
command builder; the Cargo integration target supplies compiled shell bytes.
"""
from pathlib import Path
import json
import os
import shlex
import subprocess
import time
import unittest

import test_source_topology as base

PATHS = Path(os.environ.get("RCH_TEST_SOURCE_NAMESPACE_PATHS",
                           base.REPO / "rch/src/hook/source_namespace_paths.sh"))


class ProductionNamespaceTests(base.SourceTopologyTests):
    def topology_commands(self):
        arguments = " ".join(shlex.quote(str(p)) for p in self.scope)
        program = PATHS.read_text(encoding="utf-8")
        return (f"set -- check {arguments}\n{program}",
                f"set -- create {arguments}\n{program}")

    def test_isolated_staging_needs_no_distinct_alias(self):
        self.alias = self.canonical
        self.scope = [self.canonical, self.canonical]
        self.initialize()
        self.assertFalse(self.canonical.is_symlink())
        self.assertEqual(set(self.inventory()), {"metadata.lock"})

    def test_existing_correct_dangling_alias_can_be_initialized(self):
        self.alias.symlink_to(self.canonical, target_is_directory=True)
        before = self.alias.lstat().st_ino
        self.initialize()
        self.assertEqual(self.alias.lstat().st_ino, before)

    def test_relative_alias_is_preserved(self):
        self.canonical.mkdir()
        self.alias.symlink_to(self.canonical.name, target_is_directory=True)
        before = self.alias.lstat().st_ino
        self.initialize()
        self.assertEqual(self.alias.lstat().st_ino, before)
        self.assertEqual(os.readlink(self.alias), self.canonical.name)

    def test_conflicting_alias_directory_is_never_replaced_or_used_as_target(self):
        self.alias.mkdir()
        evidence = self.alias / "keep"
        evidence.write_bytes(b"unfinished source evidence")
        result = self.topology()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertFalse(self.canonical.exists())
        self.assertEqual(evidence.read_bytes(), b"unfinished source evidence")
        self.assertEqual(list(self.alias.iterdir()), [evidence])
        self.assertEqual(set(self.inventory()), {"metadata.lock"})

    def test_conflicting_worker_symlink_identifies_both_physical_roots_without_source_contents(self):
        # Issue #130: the dispatcher's canonical root is a real, separate
        # directory while /dp already names the worker's own project root.
        physical = self.base / "data/projects"
        physical.mkdir(parents=True)
        self.canonical.mkdir()
        self.alias.symlink_to(physical, target_is_directory=True)
        canonical_data = self.canonical / "keep"
        worker_data = physical / "keep"
        canonical_data.write_bytes(b"private canonical source contents")
        worker_data.write_bytes(b"private worker source contents")
        before = self.inventory()
        alias_inode = self.alias.lstat().st_ino
        result = self.topology()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base\n", result.stderr)
        mappings = [line.removeprefix("RCH_SOURCE_TOPOLOGY_PATHS ")
                    for line in result.stderr.decode().splitlines()
                    if line.startswith("RCH_SOURCE_TOPOLOGY_PATHS ")]
        self.assertEqual(len(mappings), 1)
        self.assertEqual(json.loads(mappings[0]), {
            "canonical": str(self.canonical),
            "canonical_physical": str(self.canonical.resolve()),
            "alias": str(self.alias),
            "alias_physical": str(physical.resolve()),
        })
        self.assertNotIn(b"private", result.stderr)
        self.assertEqual(canonical_data.read_bytes(), b"private canonical source contents")
        self.assertEqual(worker_data.read_bytes(), b"private worker source contents")
        self.assertEqual(self.alias.lstat().st_ino, alias_inode)
        self.assertEqual(os.readlink(self.alias), str(physical))
        self.assertEqual(before, self.inventory())

    def test_two_compatible_aliases_to_one_physical_root_are_preserved(self):
        physical = self.base / "data/projects"
        physical.mkdir(parents=True)
        self.canonical.symlink_to(physical, target_is_directory=True)
        self.alias.symlink_to(physical, target_is_directory=True)
        original_inodes = [path.lstat().st_ino for path in self.scope]
        self.initialize()
        self.assertEqual([path.lstat().st_ino for path in self.scope], original_inodes)
        self.assertEqual(list(physical.iterdir()), [])

    def test_physical_mapping_diagnostic_quotes_control_and_shell_characters(self):
        physical = self.base / "other\t\x1b[31m' $(touch BAD)"
        physical.mkdir()
        self.canonical.mkdir()
        self.alias.symlink_to(physical, target_is_directory=True)
        result = self.topology()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertNotIn(b"\x1b", result.stderr)
        self.assertNotIn(b"\t", result.stderr)
        self.assertFalse((self.base / "BAD").exists())
        mapping_line = next(line for line in result.stderr.decode().splitlines()
                            if line.startswith("RCH_SOURCE_TOPOLOGY_PATHS "))
        mapping = json.loads(mapping_line.removeprefix("RCH_SOURCE_TOPOLOGY_PATHS "))
        self.assertEqual(mapping["alias_physical"], str(physical))

    def test_non_directory_canonical_is_permanent_and_never_replaced(self):
        self.canonical.write_bytes(b"keep canonical file")
        result = self.topology()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertIn(b"RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: canonical_not_directory\n", result.stderr)
        self.assertEqual(self.canonical.read_bytes(), b"keep canonical file")
        self.assertFalse(self.alias.exists())

    def test_conflicting_topology_never_retries_the_same_worker(self):
        physical = self.base / "other/projects"
        physical.mkdir(parents=True)
        self.canonical.mkdir()
        self.alias.symlink_to(physical, target_is_directory=True)
        command, data = self.command("topology", "b1", self.scope, *self.topology_commands())
        counter = self.base / "conflict-attempts"
        script = (
            "rch_source_attempt() { (\nset -eu\n"
            + "printf 'attempt\\n' >> " + shlex.quote(str(counter)) + "\n"
            + "exec " + shlex.join(command) + " <<'RCH_NAMESPACE_SCOPE'\n"
            + data.decode() + "RCH_NAMESPACE_SCOPE\n); }\n"
            + "rch_admission_attempts=6\n" + base.RETRY.read_text()
        )
        result = subprocess.run([base.SHELL, "-c", script], capture_output=True,
                                timeout=5, env=self.env)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(counter.read_text().splitlines(), ["attempt"])
        self.assertEqual(self.alias.resolve(), physical)
        self.assertEqual(list(self.registry.glob("*.claim")), [])

    def test_conflicting_dangling_alias_does_not_create_either_target(self):
        elsewhere = self.base / "elsewhere"
        self.alias.symlink_to(elsewhere, target_is_directory=True)
        result = self.topology()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertFalse(self.canonical.exists())
        self.assertFalse(elsewhere.exists())
        self.assertEqual(os.readlink(self.alias), str(elsewhere))

    def test_shell_metacharacters_in_translation_paths_are_literal_data(self):
        self.canonical = self.base / "projects ' $(touch BAD); with spaces"
        self.alias = self.base / "alias ' ; echo BAD"
        self.scope = [self.canonical, self.alias]
        self.initialize()
        self.assertEqual(list(self.canonical.iterdir()), [])
        self.assertFalse((self.base / "BAD").exists())

    def test_ambiguous_newline_in_physical_alias_is_not_stripped_into_authority(self):
        physical = self.base / "physical\n"
        physical.mkdir()
        self.canonical.symlink_to(physical, target_is_directory=True)
        result = self.topology()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertFalse(self.alias.is_symlink())
        self.assertEqual(list(physical.iterdir()), [])

    def test_delayed_legacy_release_allows_bounded_namespace_retry(self):
        self.accepted(self.run_op("acquire", "a1", self.scope))
        command, data = self.command("topology", "b1", self.scope, *self.topology_commands())
        counter = self.base / "namespace-attempts"
        script = (
            "rch_source_attempt() { (\nset -eu\n"
            + "printf 'attempt\\n' >> " + shlex.quote(str(counter)) + "\n"
            + "exec " + shlex.join(command) + " <<'RCH_NAMESPACE_SCOPE'\n"
            + data.decode() + "RCH_NAMESPACE_SCOPE\n); }\n"
            + "rch_admission_attempts=3\n" + base.RETRY.read_text()
        )
        child = subprocess.Popen([base.SHELL, "-c", script], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=self.env)
        self.addCleanup(self.reap, child)
        deadline = time.monotonic() + 5
        while not counter.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(counter.exists())
        self.accepted(self.run_op("release", "a1", self.scope))
        stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(stdout, b"RCH_TOPOLOGY_OK\n")
        self.assertGreaterEqual(len(counter.read_text().splitlines()), 2)
        self.assertEqual(list(self.registry.glob("*.claim")), [])
        self.assertEqual(len(list((self.registry / "released").glob("*.claim"))), 1)
        self.assertEqual(self.alias.resolve(), self.canonical.resolve())


class NamespaceOrchestrationWiringTests(unittest.TestCase):
    def test_namespace_is_initialized_before_journaling_and_source_locks(self):
        # A source-level guard for the producer boundary, not a Rust type check.
        source = (base.REPO / "rch/src/hook/transfer_orchestration.rs").read_text()
        body = source.split("async fn execute_remote_compilation_inner(", 1)[1]
        initialize = body.index("source_namespace::initialize_worker_namespace(")
        plan = body.index("source_namespace::build_source_roots(")
        journal = body.index("recovery::RecoverySession::begin(")
        pair = body.index("acquire_clean_overlay_source_pair(")
        # 0f5694ce (#105) acquires through the bounded same-worker retry.
        acquire = body.index("source_namespace::acquire_source_authority_with_retry(")
        self.assertLess(initialize, plan)
        self.assertLess(plan, journal)
        self.assertLess(journal, pair)
        self.assertLess(pair, acquire)
        self.assertNotIn("canonical_root()", body[plan:journal])
        self.assertNotIn("alias_root()", body[plan:journal])
        # rustfmt may split these chains across lines; compare without whitespace.
        planned = "".join(body[plan:journal].split())
        self.assertIn("source_pair_pool.as_ref().and(overlay_remote_root.as_deref())", planned)
        self.assertIn("retained_source_root.as_deref()", planned)
        self.assertIn("source_freshness_control.as_deref()", planned)
        self.assertIn("source_target_root.as_deref()", planned)
        repair = body.split("    ensure_worker_projects_topology(", 1)[1].split(")\n", 1)[0]
        self.assertIn("false,", repair, "repair must not recreate shared bases under a build claim")


if __name__ == "__main__":
    unittest.main(verbosity=2)
