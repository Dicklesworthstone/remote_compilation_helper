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
import statistics
import subprocess
import sys
import tempfile
import time
import unittest

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

    def run(self, token: str, roots: list[str], operation: str = "acquire") -> subprocess.CompletedProcess:
        body = root_bytes(roots)
        digest = hashlib.sha256(body).hexdigest()
        return subprocess.run(
            ["flock", "-x", "--", str(self.registry / "metadata.lock"),
             "sh", "-c", self.script, "rch-source-registry", str(self.registry),
             token, digest, operation],
            input=body, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
