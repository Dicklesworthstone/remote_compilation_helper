#!/usr/bin/env python3
"""Run the production source-claim transaction against isolated local registries.

No daemon, SSH connection, configured worker, or Rust build is used. The record
helpers are extracted from the same Rust constant that production prepends to
source_claim_registry.sh; no alternate implementation substitutes for them.

Run: python3 scripts/test_source_claim_registry.py
Measure: python3 scripts/test_source_claim_registry.py --benchmark
Compare an older transaction with RCH_TEST_SOURCE_REGISTRY_SCRIPT=/path/to/old.sh.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import unittest

if sys.platform.startswith("linux"):
    import fcntl

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get(
    "RCH_TEST_SOURCE_REGISTRY_SCRIPT",
    str(ROOT / "rch/src/hook/source_claim_registry.sh"),
))
HELPER_SOURCE = ROOT / "rch-common/src/stale_target_reap.rs"


def production_script() -> str:
    source = HELPER_SOURCE.read_text(encoding="utf-8")
    marker = 'pub const SOURCE_CLAIM_RECORD_HELPERS: &str = r#"'
    if source.count(marker) != 1:
        raise RuntimeError("cannot locate the production source-claim helpers")
    helpers, end, _ = source.split(marker, 1)[1].partition('"#;')
    if not end:
        raise RuntimeError("unterminated production source-claim helper constant")
    return helpers + "\n" + SCRIPT.read_text(encoding="utf-8")


def root_bytes(roots: list[str]) -> bytes:
    return ("\n".join(sorted(set(roots))) + "\n").encode("utf-8")


class Registry:
    """A private registry using the real metadata flock and durable writer."""

    def __init__(self, root: Path):
        self.root = root
        self.registry = root / "registry"
        self.registry.mkdir()
        for name in ("released", "cancelled", "quarantine"):
            (self.registry / name).mkdir()
        self.script = production_script()
        self.env = os.environ.copy()
        self.env["LC_ALL"] = "C"
        self.calls = root / "realpath-calls"
        self.env["RCH_TEST_REALPATH_CALLS"] = str(self.calls)
        realpath = shutil.which("realpath")
        if realpath is None:
            raise RuntimeError("GNU realpath is required")
        tools = root / "tools"
        tools.mkdir()
        shim = tools / "realpath"
        # Record both argc and argument bytes. Fault injection is confined to
        # this private subprocess PATH and never replaces a system utility.
        shim.write_text(
            "#!/bin/sh\nset -eu\nbytes=0\n"
            'for arg do bytes=$((bytes + ${#arg} + 1)); done\n'
            'printf "%s %s\\n" "$#" "$bytes" >> "$RCH_TEST_REALPATH_CALLS"\n'
            'for arg do case "$arg" in */resolver-failure) exit 19;; esac; done\n'
            f"exec {shlex.quote(realpath)} \"$@\"\n",
            encoding="utf-8",
        )
        shim.chmod(0o700)
        self.env["PATH"] = str(tools) + os.pathsep + self.env.get("PATH", os.defpath)

    def path(self, token: str, roots: list[str], extension: str = "claim") -> Path:
        digest = hashlib.sha256(root_bytes(roots)).hexdigest()
        return self.registry / f"{token}.{digest}.{extension}"

    def seed(self, token: str, roots: list[str], extension: str = "claim") -> Path:
        path = self.path(token, roots, extension)
        path.write_bytes(root_bytes(roots))
        return path

    def command(self, token: str, roots: list[str], operation: str = "acquire", *arguments: str) -> list[str]:
        body = root_bytes(roots)
        digest = hashlib.sha256(body).hexdigest()
        return ["flock", "-x", "--", str(self.registry / "metadata.lock"),
                "sh", "-c", self.script, "rch-source-registry", str(self.registry),
                token, digest, operation, *arguments]

    def run(self, token: str, roots: list[str], operation: str = "acquire", *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.command(token, roots, operation, *arguments),
            input=root_bytes(roots), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.env, timeout=45, check=False,
        )

    def resolutions(self) -> list[tuple[int, int]]:
        if not self.calls.exists():
            return []
        return [tuple(map(int, line.split())) for line in self.calls.read_text().splitlines()]


@unittest.skipUnless(sys.platform.startswith("linux"), "requires the GNU worker toolchain")
class SourceClaimRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rch-registry-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = Registry(self.root)
        self.source = str(self.root / "sources")

    def accepted(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def refused(self, result, roots, reason=None):
        self.assertEqual(result.returncode, 73, result.stderr.decode(errors="replace"))
        if reason:
            self.assertIn(reason.encode(), result.stderr)
        self.assertFalse(self.fixture.path("bb", roots).exists(), "refusal must not publish a grant")
        self.assertFalse(self.fixture.path("bb", roots, "pending").exists())

    def test_claim_keeps_exact_lexical_identity_and_release_receipt(self):
        target = self.root / "target"
        target.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        roots = [str(alias / "dep"), str(alias / "other")]
        self.accepted(self.fixture.run("aa", roots))
        self.assertEqual(self.fixture.path("aa", roots).read_bytes(), root_bytes(roots))
        self.accepted(self.fixture.run("aa", roots, "recover"))
        self.accepted(self.fixture.run("aa", roots, "release"))
        result = self.fixture.run("aa", roots, "released")
        self.accepted(result)
        self.assertEqual(result.stdout, b"released")
        self.assertNotEqual(self.fixture.run("aa", roots, "recover").returncode, 0)

    def test_disjoint_siblings_and_component_prefixes_are_admitted(self):
        self.fixture.seed("aa", [self.source + "/dep", self.source + "/sibling/left"])
        self.accepted(self.fixture.run("bb", [self.source + "/dependency", self.source + "/sibling/right"]))

    def test_lexical_parent_child_equal_and_root_conflicts(self):
        for old, wanted in [
            ("/tree", "/tree/child"), ("/tree/child", "/tree"),
            ("/tree", "/tree"), ("/", "/tree"), ("/tree", "/"),
        ]:
            with self.subTest(old=old, wanted=wanted), tempfile.TemporaryDirectory() as tmp:
                fixture = Registry(Path(tmp))
                fixture.seed("aa", [old])
                result = fixture.run("bb", [wanted])
                self.assertEqual(result.returncode, 73, result.stderr)
                self.assertIn(b"unfinished overlapping source owner", result.stderr)
                self.assertFalse(fixture.path("bb", [wanted]).exists())

    def test_physical_alias_conflicts_in_both_directions(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                fixture = Registry(root)
                physical = root / "physical"
                physical.mkdir()
                alias = root / "alias"
                alias.symlink_to(physical, target_is_directory=True)
                old, wanted = str(physical / "dep"), str(alias / "dep/child")
                if reverse:
                    old, wanted = wanted, old
                fixture.seed("aa", [old])
                result = fixture.run("bb", [wanted])
                self.assertEqual(result.returncode, 73, result.stderr)
                self.assertIn(b"unfinished overlapping physical source owner", result.stderr)

    def test_ambiguous_symlink_targets_fail_closed_in_either_set(self):
        for suffix in ("\n", "\r", "\n/second-root"):
            for held in (False, True):
                with self.subTest(suffix=repr(suffix), held=held), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    fixture = Registry(root)
                    alias = root / "ambiguous-alias"
                    alias.symlink_to(str(root / "physical") + suffix)
                    if held:
                        fixture.seed("aa", [str(alias)])
                        roots = [str(root / "unrelated")]
                    else:
                        roots = [str(alias)]
                    result = fixture.run("bb", roots)
                    self.assertEqual(result.returncode, 73, result.stderr)
                    self.assertFalse(fixture.path("bb", roots).exists())

    def test_literal_path_bytes_are_not_split_or_interpreted(self):
        names = ["space name", "tab\tname", "back\\slash", "[glob]*?", "dollar$HOME", "quote'\"", "café"]
        roots = [self.source + "/" + name for name in names]
        self.fixture.seed("aa", [root + "-neighbor" for root in roots])
        self.accepted(self.fixture.run("bb", roots))
        self.assertEqual(self.fixture.path("bb", roots).read_bytes(), root_bytes(roots))

    def test_complete_pending_owner_still_excludes_writers(self):
        roots = [self.source + "/owner"]
        self.fixture.seed("aa", roots, "pending")
        self.refused(self.fixture.run("bb", roots), roots, "unfinished overlapping")
        self.accepted(self.fixture.run("aa", roots, "recover"))
        self.assertTrue(self.fixture.path("aa", roots).exists())

    def test_incomplete_pending_is_quarantined_without_reviving_identity(self):
        roots = [self.source + "/old"]
        pending = self.fixture.path("aa", roots, "pending")
        pending.write_bytes(b"incomplete")
        other = [self.source + "/other"]
        self.accepted(self.fixture.run("bb", other))
        self.assertTrue((self.fixture.registry / "quarantine" / pending.name).exists())
        self.assertNotEqual(self.fixture.run("aa", roots, "recover").returncode, 0)
        self.assertNotEqual(self.fixture.run("aa", roots).returncode, 0)

    def test_corrupt_active_owner_is_not_ignored(self):
        old = [self.source + "/owner"]
        self.fixture.seed("aa", old).write_bytes(b"bad")
        roots = [self.source + "/other"]
        self.refused(self.fixture.run("bb", roots), roots, "invalid claim record")

    def test_absent_cancel_fences_late_acquisition(self):
        roots = [self.source + "/never-started"]
        result = self.fixture.run("bb", roots, "cancel")
        self.accepted(result)
        self.assertEqual(result.stdout, b"unowned")
        self.refused(self.fixture.run("bb", roots), roots, "cancelled")

    def test_active_cancellation_keeps_exclusion_until_cleanup_finishes(self):
        roots = [self.source + "/owner"]
        self.accepted(self.fixture.run("aa", roots))
        result = self.fixture.run("aa", roots, "cancel")
        self.accepted(result)
        self.assertEqual(result.stdout, b"owned")
        self.refused(self.fixture.run("bb", roots), roots, "unfinished overlapping")
        self.accepted(self.fixture.run("aa", roots, "finish-cancel"))
        self.accepted(self.fixture.run("bb", roots))

    def test_failed_later_resolution_cannot_publish_partial_closure(self):
        roots = [self.source + f"/a-{i:04d}" for i in range(130)]
        roots.append(self.source + "/resolver-failure")
        self.refused(self.fixture.run("bb", roots), roots, "cannot resolve physical")

    def test_realpath_process_count_is_bounded_by_batches(self):
        self.fixture.seed("aa", [self.source + f"/held-{i:04d}" for i in range(130)])
        roots = [self.source + f"/wanted-{i:04d}" for i in range(130)]
        self.accepted(self.fixture.run("bb", roots))
        calls = self.fixture.resolutions()
        self.assertLessEqual(len(calls), 6, "root resolution must not fork once per dependency")
        self.assertTrue(all(argc <= 66 for argc, _ in calls), calls)

    def test_large_closures_use_bounded_argv_not_one_giant_command(self):
        # More than Linux's per-argument limit overall, without ever passing
        # the closure through argv. Each path remains below PATH_MAX.
        prefix = self.source + "/" + "/".join(["component-" + "x" * 190] * 8)
        roots = [prefix + f"/dep-{i:04d}" for i in range(160)]
        self.assertGreater(len(root_bytes(roots)), 128 * 1024)
        self.accepted(self.fixture.run("bb", roots))
        calls = self.fixture.resolutions()
        self.assertTrue(all(size <= 64 * 1024 for _, size in calls), calls)
        self.assertEqual(self.fixture.path("bb", roots).read_bytes(), root_bytes(roots))


@unittest.skipUnless(sys.platform.startswith("linux"), "requires the GNU worker toolchain")
class SourceAdmission105Tests(unittest.TestCase):
    """Actual worker registry/retry programs, with local subprocess transports.

    The representative source lock and topology commands isolate the protocol;
    Rust tests cover production command construction. This is not fleet E2E.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rch-105-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fixture = Registry(self.root)
        self.canonical = self.root / "projects"
        self.alias = self.root / "dp"
        self.scope = [str(self.canonical), str(self.alias)]
        self.roots = [str(self.canonical / "repo"), str(self.canonical / "repo/.rch-target")]
        self.source_lock = self.root / "source.lock"
        self.attempts = self.root / "attempts"

    def accepted(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def topology_commands(self):
        canonical, alias = map(shlex.quote, self.scope)
        check = f'[ -d {canonical} ] && [ -L {alias} ] && [ "$(readlink -- {alias})" = {canonical} ]'
        create = (f'set -eu; mkdir -p -- {canonical}; '
                  f'ln -s -- {canonical} {alias}; printf "RCH_TOPOLOGY_OK\n"')
        return check, create

    def topology(self, token="cc"):
        return self.fixture.run(token, self.scope, "topology", *self.topology_commands())

    def wait_for(self, predicate, message):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail(message)

    def start_retry(self, attempts=3):
        # Production retry loop, not a Python retry substitute. Its source-lock
        # descriptor is opened INSIDE the fresh attempt subshell, as in ssh.rs.
        command = shlex.join(self.fixture.command("bb", self.roots, "try-acquire"))
        payload = root_bytes(self.roots).decode()
        retry = (ROOT / "rch/src/hook/source_claim_admission.sh").read_text()
        script = (
            "rch_source_attempt() { (\nset -eu\n"
            f"exec 9<>{shlex.quote(str(self.source_lock))}\nflock -x 9\n"
            f"printf 'attempt\n' >> {shlex.quote(str(self.attempts))}\n"
            f"exec {command} <<'RCH_TEST_ROOTS'\n{payload}RCH_TEST_ROOTS\n"
            "); }\n"
            f"rch_admission_attempts={attempts}\n{retry}"
        )
        child = subprocess.Popen(["sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=self.fixture.env)
        child.stdin.write(script.encode())
        child.stdin.close()
        child.stdin = None
        self.addCleanup(self.reap, child)
        self.wait_for(lambda: self.attempts.exists(), "first source attempt never started")
        return child

    @staticmethod
    def reap(child):
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)

    def finish(self, child, expected):
        stdout, stderr = child.communicate(timeout=10)
        self.assertEqual(child.returncode, expected, stderr.decode(errors="replace"))
        self.assertEqual(stdout, b"", "admission must not synthesize build output")

    def test_topology_does_not_own_shared_bases_and_unrelated_repos_coexist(self):
        self.accepted(self.topology())
        self.assertFalse(list(self.fixture.registry.glob("cc.*")))
        self.accepted(self.fixture.run("aa", self.roots, "try-acquire"))
        other = [str(self.alias / "different"), str(self.alias / "different/.rch-target")]
        self.accepted(self.fixture.run("bb", other, "try-acquire"))
        self.assertEqual(len(list(self.fixture.registry.glob("*.claim"))), 2)
        self.assertEqual(self.fixture.path("aa", self.roots).read_bytes(), root_bytes(self.roots))
        self.assertEqual(self.fixture.path("bb", other).read_bytes(), root_bytes(other))

    def test_topology_rechecks_after_another_initializer_finished(self):
        self.accepted(self.topology())
        self.accepted(self.fixture.run("aa", self.roots))
        check, _ = self.topology_commands()
        result = self.fixture.run("cc", self.scope, "topology", check, "exit 97")
        self.accepted(result)
        self.assertEqual(result.stdout, b"RCH_TOPOLOGY_OK\n")
        self.assertFalse(list(self.fixture.registry.glob("cc.*")))

    def test_missing_alias_cannot_be_initialized_over_an_unfinished_owner(self):
        self.fixture.seed("aa", self.roots)
        result = self.topology()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertFalse(self.canonical.exists())
        self.assertFalse(self.alias.is_symlink())
        self.assertEqual(self.fixture.path("aa", self.roots).read_bytes(), root_bytes(self.roots))

    def test_topology_physical_alias_owner_is_not_ignored(self):
        physical = self.root / "physical"
        physical.mkdir()
        self.canonical.symlink_to(physical, target_is_directory=True)
        held = [str(physical / "repo")]
        self.fixture.seed("aa", held)
        result = self.topology()
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertIn(b"physical source owner", result.stderr)
        self.assertFalse(self.alias.is_symlink())

    def test_topology_corruption_and_invalid_scopes_refuse_before_mutation(self):
        self.fixture.seed("aa", self.roots).write_bytes(b"corrupt")
        self.assertEqual(self.topology().returncode, 73)
        self.assertFalse(self.canonical.exists())
        for scope in [[], ["relative"], ["/a/../b"]]:
            result = self.fixture.run("cc", scope, "topology", "false", "exit 97")
            self.assertEqual(result.returncode, 73, result.stderr)

    def test_topology_retains_metadata_exclusion_through_mutation(self):
        entered = self.root / "entered"
        proceed = self.root / "proceed"
        check, create = self.topology_commands()
        paused = (f'touch {shlex.quote(str(entered))}; '
                  f'while [ ! -f {shlex.quote(str(proceed))} ]; do sleep 0.01; done; {create}')
        initializer = subprocess.Popen(
            ["nohup", *self.fixture.command("cc", self.scope, "topology", check, paused)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.fixture.env,
        )
        initializer.stdin.write(root_bytes(self.scope))
        initializer.stdin.close()
        initializer.stdin = None
        self.addCleanup(self.reap, initializer)
        try:
            self.wait_for(entered.exists, "topology mutation never started")
            # Production keeps the metadata supervisor HUP-resistant. Losing
            # control transport must not drop exclusion beneath its mutator.
            os.kill(initializer.pid, signal.SIGHUP)
            with (self.fixture.registry / "metadata.lock").open("a") as lock:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertFalse(list(self.fixture.registry.glob("*.claim")))
        finally:
            proceed.touch()
        stdout, stderr = initializer.communicate(timeout=10)
        self.assertEqual(initializer.returncode, 0, stderr)
        self.assertEqual(stdout, b"RCH_TOPOLOGY_OK\n")
        self.accepted(self.fixture.run("aa", self.roots))

    def test_partial_topology_creation_is_idempotently_retryable_without_a_lease(self):
        check, _ = self.topology_commands()
        failed = self.fixture.run("cc", self.scope, "topology", check,
                                  f'mkdir -p {shlex.quote(str(self.canonical))}; exit 75')
        self.assertEqual(failed.returncode, 73, "mutator failure is not admission contention")
        self.assertFalse(list(self.fixture.registry.glob("cc.*")))
        self.accepted(self.topology("dd"))

    def test_try_acquire_distinguishes_real_conflict_from_corruption(self):
        self.fixture.seed("aa", self.roots)
        self.assertEqual(self.fixture.run("bb", self.roots, "try-acquire").returncode, 75)
        self.assertEqual(self.fixture.run("bb", self.roots, "recover").returncode, 73)
        self.assertFalse(self.fixture.path("bb", self.roots).exists())
        self.fixture.path("aa", self.roots).write_bytes(b"corrupt")
        self.assertEqual(self.fixture.run("bb", self.roots, "try-acquire").returncode, 73)

    def test_unrelated_primary_roots_still_conflict_on_a_shared_dependency_or_pool(self):
        for shared in ("dependency", "target-pool"):
            with self.subTest(shared=shared), tempfile.TemporaryDirectory() as tmp:
                fixture = Registry(Path(tmp))
                common = str(Path(tmp) / shared)
                first = [str(Path(tmp) / "first"), common]
                second = [str(Path(tmp) / "second"), common]
                self.accepted(fixture.run("aa", first, "try-acquire"))
                result = fixture.run("bb", second, "try-acquire")
                self.assertEqual(result.returncode, 75, result.stderr)
                self.assertFalse(fixture.path("bb", second).exists())
                self.assertEqual(fixture.path("aa", first).read_bytes(), root_bytes(first))

    def test_legacy_broad_grants_require_exact_recovery_and_release(self):
        self.accepted(self.topology())
        legacy = self.scope + self.roots
        self.accepted(self.fixture.run("aa", legacy))
        other = [str(self.alias / "other")]
        self.assertEqual(self.fixture.run("bb", other, "try-acquire").returncode, 75)
        self.assertEqual(self.fixture.run("aa", self.roots, "recover").returncode, 73)
        self.accepted(self.fixture.run("aa", legacy, "recover"))
        self.accepted(self.fixture.run("aa", legacy, "release"))
        self.accepted(self.fixture.run("bb", other, "try-acquire"))
        receipt = self.fixture.registry / "released" / self.fixture.path("aa", legacy).name
        self.assertEqual(receipt.read_bytes(), root_bytes(legacy))

    def test_late_release_acknowledgment_cannot_release_the_next_owner(self):
        self.accepted(self.fixture.run("aa", self.roots, "try-acquire"))
        self.accepted(self.fixture.run("aa", self.roots, "release"))
        self.accepted(self.fixture.run("bb", self.roots, "try-acquire"))
        self.accepted(self.fixture.run("aa", self.roots, "release"))
        self.assertEqual(self.fixture.path("bb", self.roots).read_bytes(), root_bytes(self.roots))
        self.assertEqual(self.fixture.run("cc", self.roots, "try-acquire").returncode, 75)
        self.assertEqual(self.fixture.run("aa", self.roots, "cancel").returncode, 73)

    def test_pending_sync_error_cannot_be_mistaken_for_retryable_contention(self):
        sync = shutil.which("sync")
        self.assertIsNotNone(sync)
        shim = self.root / "tools/sync"
        shim.write_text(
            '#!/bin/sh\ncase "${2-}" in *.pending) exit 75;; esac\n'
            f'exec {shlex.quote(sync)} "$@"\n', encoding="utf-8",
        )
        shim.chmod(0o700)
        result = self.fixture.run("bb", self.roots, "try-acquire")
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertFalse(self.fixture.path("bb", self.roots).exists())
        self.assertEqual(self.fixture.path("bb", self.roots, "pending").read_bytes(),
                         root_bytes(self.roots))

    def test_sequential_commands_on_one_worker_wait_for_exact_release(self):
        # The first command is complete, but its ownership release is delayed.
        # There is exactly ONE source lock and ONE registry: no worker failover.
        self.accepted(self.fixture.run("aa", self.roots))
        child = self.start_retry()
        self.assertIsNone(child.poll())
        self.assertFalse(self.fixture.path("bb", self.roots).exists())
        # Recovery must be able to acquire that SAME lock between attempts.
        with self.source_lock.open("a") as lock:
            def recovery_can_lock():
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return True
                except BlockingIOError:
                    return False
            self.wait_for(recovery_can_lock, "waiting admission monopolized the recovery lock")
            self.accepted(self.fixture.run("aa", self.roots, "recover"))
            self.accepted(self.fixture.run("aa", self.roots, "release"))
        self.finish(child, 0)
        self.assertGreaterEqual(len(self.attempts.read_text().splitlines()), 2)
        self.assertEqual(self.fixture.path("bb", self.roots).read_bytes(), root_bytes(self.roots))
        self.assertTrue((self.fixture.registry / "released" / self.fixture.path("aa", self.roots).name).exists())

    def test_live_owner_exhausts_bounded_attempts_without_losing_ownership(self):
        self.accepted(self.fixture.run("aa", self.roots))
        child = self.start_retry(attempts=2)
        self.finish(child, 75)
        self.assertEqual(len(self.attempts.read_text().splitlines()), 2)
        self.assertFalse(self.fixture.path("bb", self.roots).exists())
        self.assertEqual(self.fixture.path("aa", self.roots).read_bytes(), root_bytes(self.roots))

    def test_cancellation_during_wait_fences_late_admission(self):
        self.accepted(self.fixture.run("aa", self.roots))
        child = self.start_retry()
        self.accepted(self.fixture.run("bb", self.roots, "cancel"))
        self.accepted(self.fixture.run("aa", self.roots, "release"))
        self.finish(child, 73)
        self.assertFalse(self.fixture.path("bb", self.roots).exists())
        self.assertFalse(self.fixture.path("bb", self.roots, "pending").exists())

    def test_unknown_ownership_is_not_retried(self):
        self.fixture.seed("aa", self.roots).write_bytes(b"bad")
        child = self.start_retry()
        self.finish(child, 73)
        self.assertEqual(len(self.attempts.read_text().splitlines()), 1)

    def test_retry_does_not_disable_errexit_in_attempt_setup(self):
        retry = (ROOT / "rch/src/hook/source_claim_admission.sh").read_text()
        result = subprocess.run(
            ["sh"], input=(
                "rch_source_attempt() { ( set -eu; false; echo UNSAFE; ); }\n"
                f"rch_admission_attempts=2\n{retry}"
            ).encode(), capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"", "failed setup must never reach admission")


def benchmark():
    measurements = []
    for _ in range(3):
        with tempfile.TemporaryDirectory(prefix="rch-registry-benchmark-") as tmp:
            root = Path(tmp)
            fixture = Registry(root)
            source = str(root / "sources")
            fixture.seed("aa", [source + f"/held-{i:04d}" for i in range(256)])
            wanted = [source + f"/wanted-{i:04d}" for i in range(256)]
            started = time.perf_counter()
            result = fixture.run("bb", wanted)
            seconds = time.perf_counter() - started
            if result.returncode:
                raise RuntimeError(result.stderr.decode(errors="replace"))
            measurements.append({"seconds": seconds, "realpath_processes": len(fixture.resolutions())})
    print(json.dumps({"script": str(SCRIPT), "held_roots": 256, "requested_roots": 256,
                      "median_seconds": statistics.median(row["seconds"] for row in measurements),
                      "runs": measurements}, indent=2))


if __name__ == "__main__":
    if sys.argv[1:] == ["--benchmark"]:
        benchmark()
    else:
        unittest.main()
