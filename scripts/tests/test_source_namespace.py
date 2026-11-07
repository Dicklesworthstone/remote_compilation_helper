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
import tempfile
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
            + "rch_admission_retry_seconds=5\n" + base.RETRY.read_text()
        )
        result = subprocess.run([base.SHELL, "-c", script], capture_output=True,
                                timeout=5, env={**self.env, "RCH_TIMING_SCALE": "1"})
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
            + "rch_admission_retry_seconds=3\n" + base.RETRY.read_text()
        )
        child = subprocess.Popen([base.SHELL, "-c", script], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env={**self.env, "RCH_TIMING_SCALE": "1"})
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


class NamespaceCheckReportTests(unittest.TestCase):
    """Execute the production read-only report with real directory layouts."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rch-namespace-probe-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.canonical = self.root / "dispatcher/projects"
        self.alias = self.root / "alias"
        self.physical = self.root / "worker/projects"

    def run_check(self, canonical=None, alias=None, *, report=True, env=None):
        arguments = ["check", str(canonical or self.canonical), str(alias or self.alias)]
        if report:
            arguments.append("--report-json")
        result = subprocess.run(
            [base.SHELL, "-c", PATHS.read_text(), "rch-namespace-probe", *arguments],
            capture_output=True, timeout=5, env=env,
        )
        if report:
            self.assertEqual(result.stderr, b"")
            prefix = b"RCH_SOURCE_TOPOLOGY_CHECK_V1 "
            self.assertTrue(result.stdout.startswith(prefix), result)
            self.assertEqual(result.stdout.count(b"\n"), 1)
            self.assertLessEqual(len(result.stdout), 65536)
            return result, json.loads(result.stdout.removeprefix(prefix))
        return result

    def snapshot(self):
        return {
            str(path.relative_to(self.root)): (
                path.lstat().st_ino, path.lstat().st_mode, path.lstat().st_size,
                path.lstat().st_mtime_ns,
                os.readlink(path) if path.is_symlink() else None,
            )
            for path in self.root.rglob("*")
        }

    def test_worker_defaults_cannot_hide_dispatcher_conflicting_alias(self):
        self.physical.mkdir(parents=True)
        self.canonical.mkdir(parents=True)
        self.alias.symlink_to(self.physical, target_is_directory=True)
        (self.physical / "keep").write_bytes(b"private worker source")
        (self.canonical / "keep").write_bytes(b"private dispatcher source")
        before = self.snapshot()
        defaults, defaults_report = self.run_check(canonical=self.physical)
        self.assertEqual(defaults.returncode, 0)
        self.assertEqual(defaults_report["outcome"], "compatible")
        result, report = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report, {
            "canonical": str(self.canonical),
            "alias": str(self.alias),
            "canonical_physical": str(self.canonical.resolve()),
            "alias_physical": str(self.physical.resolve()),
            "outcome": "conflicting_alias_base",
        })
        self.assertNotIn(b"private", result.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_missing_dispatcher_canonical_is_reported_without_initialization(self):
        self.physical.mkdir(parents=True)
        self.alias.symlink_to(self.physical, target_is_directory=True)
        before = self.snapshot()
        result, report = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["outcome"], "canonical_missing")
        self.assertEqual(report["canonical"], str(self.canonical))
        self.assertEqual(report["alias_physical"], str(self.physical.resolve()))
        self.assertFalse(self.canonical.parent.exists())
        self.assertEqual(self.snapshot(), before)

    def test_matching_canonical_and_alias_symlinks_are_preserved(self):
        self.physical.mkdir(parents=True)
        self.canonical.parent.mkdir()
        self.canonical.symlink_to(self.physical, target_is_directory=True)
        self.alias.symlink_to(self.physical, target_is_directory=True)
        before = self.snapshot()
        result, report = self.run_check()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["outcome"], "compatible")
        self.assertEqual(report["canonical_physical"], report["alias_physical"])
        self.assertEqual(self.snapshot(), before)

    def test_single_staging_root_needs_no_alias(self):
        self.physical.mkdir(parents=True)
        result, report = self.run_check(canonical=self.physical, alias=self.physical)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["outcome"], "compatible")
        self.assertFalse(self.alias.exists())

    def test_missing_alias_is_not_created(self):
        self.canonical.mkdir(parents=True)
        before = self.snapshot()
        result, report = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["outcome"], "alias_missing")
        self.assertFalse(self.alias.exists())
        self.assertEqual(self.snapshot(), before)

    def test_dangling_alias_target_is_not_created(self):
        self.canonical.mkdir(parents=True)
        self.alias.symlink_to(self.physical, target_is_directory=True)
        before = self.snapshot()
        result, report = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["outcome"], "alias_missing")
        self.assertEqual(report["alias_physical"], str(self.physical.resolve()))
        self.assertFalse(self.physical.parent.exists())
        self.assertEqual(self.snapshot(), before)

    def test_canonical_file_is_not_replaced(self):
        self.canonical.parent.mkdir()
        self.canonical.write_bytes(b"keep canonical file")
        before = self.snapshot()
        result, report = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["outcome"], "canonical_not_directory")
        self.assertEqual(self.canonical.read_bytes(), b"keep canonical file")
        self.assertEqual(self.snapshot(), before)

    def test_alias_file_is_not_replaced(self):
        self.canonical.mkdir(parents=True)
        self.alias.write_bytes(b"keep alias file")
        before = self.snapshot()
        result, report = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["outcome"], "alias_not_directory")
        self.assertEqual(self.alias.read_bytes(), b"keep alias file")
        self.assertEqual(self.snapshot(), before)

    def test_ordinary_check_retains_silent_admission_contract(self):
        missing = self.run_check(report=False)
        self.assertNotEqual(missing.returncode, 0)
        self.assertEqual(missing.stdout, b"")
        self.canonical.mkdir(parents=True)
        self.alias.symlink_to(self.canonical, target_is_directory=True)
        matching = self.run_check(report=False)
        self.assertEqual(matching.returncode, 0)
        self.assertEqual(matching.stdout, b"")
        self.assertEqual(matching.stderr, b"")

    def test_report_option_cannot_invoke_create_mode(self):
        result = subprocess.run(
            [base.SHELL, "-c", PATHS.read_text(), "rch-namespace-probe", "create",
             str(self.canonical), str(self.alias), "--report-json"],
            capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 73)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_resolver_failure_is_unavailable_not_a_matching_namespace(self):
        self.canonical.mkdir(parents=True)
        self.alias.symlink_to(self.canonical, target_is_directory=True)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        resolver = binary_dir / "grealpath"
        resolver.write_text("#!/bin/sh\nexit 1\n")
        resolver.chmod(0o755)
        env = {**os.environ, "PATH": f"{binary_dir}:{os.environ['PATH']}"}
        before = self.snapshot()
        result, report = self.run_check(env=env)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["outcome"], "unavailable")
        self.assertIsNone(report["canonical_physical"])
        self.assertIsNone(report["alias_physical"])
        self.assertEqual(self.snapshot(), before)

    def test_physical_mapping_controls_are_escaped_in_report(self):
        physical = self.root / "physical\t\x1b[31m' $(touch BAD)"
        physical.mkdir()
        self.canonical.mkdir(parents=True)
        self.alias.symlink_to(physical, target_is_directory=True)
        result, report = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["alias_physical"], str(physical.resolve()))
        self.assertNotIn(b"\x1b", result.stdout)
        self.assertNotIn(b"\t", result.stdout)
        self.assertFalse((self.root / "BAD").exists())


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
