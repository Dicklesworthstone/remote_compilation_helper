#!/usr/bin/env python3
"""Exercise the shipped claim transaction with real locks, hashes and aliases.

No SSH, worker or production registry is used. The record helpers are the same
Rust literal prepended by production; the Rust harness supplies compiled bytes.
Fault-injected tools are identified in each test and delegate to the real tool
otherwise. All test directories are retained. --benchmark BASELINE compares the
baseline and candidate against the same native registry in alternating order.
"""
import hashlib
import json
import os
from pathlib import Path
import random
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get("RCH_TEST_SOURCE_CLAIM_SCRIPT",
                             ROOT / "rch/src/hook/source_claim_registry.sh"))
HELPER_FILE = os.environ.get("RCH_TEST_SOURCE_CLAIM_HELPERS")
if HELPER_FILE:
    HELPERS = Path(HELPER_FILE).read_text()
else:
    HELPERS = (ROOT / "rch-common/src/stale_target_reap.rs").read_text().split(
        'pub const SOURCE_CLAIM_RECORD_HELPERS: &str = r#"', 1)[1].split('"#;', 1)[0]
SCRIPT = SOURCE.read_text()
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")
FLOCK = shutil.which("flock")
AWK = shutil.which("awk")
REALPATH = shutil.which("realpath")
TR = shutil.which("tr")
SYNC = shutil.which("sync")


def body(roots):
    return ("\n".join(map(str, roots)) + "\n").encode()


def digest(roots):
    return hashlib.sha256(body(roots)).hexdigest()


def reference(wanted, held):
    return any(a == "/" or b == "/" or a == b or a.startswith(b + "/")
               or b.startswith(a + "/") for a in wanted for b in held)


class Fixture:
    def __init__(self, script=SCRIPT):
        self.root = Path(tempfile.mkdtemp(prefix="rch-claim-inventory-"))
        self.registry = self.root / "registry with ' quotes"
        self.registry.mkdir()
        for name in ("released", "cancelled", "quarantine"):
            (self.registry / name).mkdir()
        self.script = self.root / "transaction.sh"
        self.script.write_text("set -eu\n" + HELPERS + "\n" + script)
        self.env = {**os.environ, "LC_ALL": "C"}

    def record(self, token, roots, extension="claim", raw=None):
        content = body(roots) if raw is None else raw
        name = token + "." + hashlib.sha256(content).hexdigest() + "." + extension
        path = self.registry / name
        path.write_bytes(content)
        return path

    def command(self, token, roots, operation="acquire", extra=(), script=None):
        return [FLOCK, "--exclusive", "--", str(self.registry / ".lock"),
                SHELL, str(script or self.script), str(self.registry), token,
                digest(roots), operation, *extra]

    def transact(self, token, roots, operation="acquire", extra=(), script=None):
        return subprocess.run(self.command(token, roots, operation, extra, script),
                              input=body(roots), capture_output=True, env=self.env,
                              timeout=30, check=False)

    def tools(self, name, source):
        directory = Path(tempfile.mkdtemp(prefix="tools-", dir=self.root))
        tool = directory / name
        tool.write_text("#!/bin/sh\n" + source + "\n")
        tool.chmod(0o700)
        self.env["PATH"] = str(directory) + os.pathsep + self.env["PATH"]
        return tool

    def unpublished(self, token):
        return not (list(self.registry.glob(token + ".*.claim"))
                    or list(self.registry.glob(token + ".*.pending")))


@unittest.skipUnless(sys.platform == "linux" and FLOCK and AWK and REALPATH and TR and SYNC,
                     "requires native Linux flock and GNU filesystem tools")
class InventoryTests(unittest.TestCase):
    def assert_status(self, result, status):
        self.assertEqual(result.returncode, status, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, b"")

    def test_many_disjoint_owners_reuse_comparisons_in_bounded_batches(self):
        f = Fixture()
        records = [f.record(format(i, "x"), [f.root / "held" / str(i)]) for i in range(24)]
        before = [(p.stat().st_ino, p.read_bytes()) for p in records]
        calls = f.root / "comparisons"
        f.tools("awk", 'case "$1" in -v) ;; *) printf "comparison\\n" >> ' +
                shlex.quote(str(calls)) + ';; esac\nexec ' + shlex.quote(AWK) + ' "$@"')
        self.assert_status(f.transact("ffff", [f.root / "wanted"]), 0)
        # 24 records use five batches (1, 2, 4, 8, 9), not 24 independently
        # rebuilt indexes. Both lexical and physical comparisons are required.
        self.assertEqual(calls.read_text().splitlines(), ["comparison"] * 10)
        self.assertEqual([(p.stat().st_ino, p.read_bytes()) for p in records], before)

    def test_empty_inventory_self_recovery_and_duplicate_identity(self):
        f = Fixture()
        roots = [f.root / "wanted"]
        self.assert_status(f.transact("aa", roots), 0)
        record = next(f.registry.glob("aa.*.claim"))
        before = (record.stat().st_ino, record.read_bytes())
        self.assert_status(f.transact("aa", roots, "recover"), 0)
        self.assert_status(f.transact("aa", roots), 73)
        self.assertEqual((record.stat().st_ino, record.read_bytes()), before)
        self.assert_status(f.transact("aa", [f.root / "different"], "recover"), 73)

    def test_inventory_larger_than_the_batch_cap_checks_every_owner(self):
        f = Fixture()
        for i in range(160):
            f.record(format(i, "04x"), [f.root / "held" / str(i)])
        calls = f.root / "comparisons"
        f.tools("awk", 'case "$1" in -v) ;; *) printf "comparison\\n" >> ' +
                shlex.quote(str(calls)) + ';; esac\nexec ' + shlex.quote(AWK) + ' "$@"')
        self.assert_status(f.transact("ffff", [f.root / "wanted"]), 0)
        # Seven full growing batches cover 127 owners, then a final batch of
        # 33. The cap is not an inventory truncation or permission to omit roots.
        self.assertEqual(calls.read_text().splitlines(), ["comparison"] * 16)
        self.assert_status(f.transact("eeee", [f.root / "held" / "159" / "child"],
                                      "try-acquire"), 75)
        self.assertTrue(f.unpublished("eeee"))

    def test_first_and_last_lexical_conflicts_preserve_retry_policy(self):
        for position in (0, 15):
            for suffix in ("", "/child", "/child/deeper"):
                for operation, status in (("acquire", 73), ("try-acquire", 75), ("recover", 73)):
                    with self.subTest(position=position, suffix=suffix, operation=operation):
                        f = Fixture()
                        held = []
                        for i in range(16):
                            held.append(f.record(format(i, "x"), [f.root / "held" / str(i)]))
                        roots = [str(f.root / "held" / str(position)) + suffix]
                        result = f.transact("ffff", roots, operation)
                        self.assert_status(result, status)
                        self.assertIn(b"overlapping source owner", result.stderr)
                        self.assertTrue(f.unpublished("ffff"))
                        self.assertEqual(len(list(f.registry.glob("*.claim"))), len(held))

    def test_physical_aliases_and_retargeted_aliases_remain_fenced(self):
        for parent_first in (False, True):
            f = Fixture()
            real = f.root / "real"
            real.mkdir()
            alias = f.root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            for i in range(12):
                f.record(format(i, "x"), [f.root / "other" / str(i)])
            roots = [real if parent_first else real / "child"]
            f.record("ee", roots)
            requested = [alias / "child" if parent_first else alias]
            result = f.transact("ffff", requested, "try-acquire")
            self.assert_status(result, 75)
            self.assertIn(b"overlapping physical source owner", result.stderr)
            self.assertTrue(f.unpublished("ffff"))
            replacement = f.root / "other-real"
            replacement.mkdir()
            alias.rename(f.root / "retained-alias")
            alias.symlink_to(replacement, target_is_directory=True)
            self.assert_status(f.transact("ffff", requested), 0)

    def test_lexical_claim_survives_alias_retargeting(self):
        f = Fixture()
        for name in ("real-a", "real-b"):
            (f.root / name).mkdir()
        alias = f.root / "alias"
        alias.symlink_to(f.root / "real-a", target_is_directory=True)
        f.record("aa", [alias])
        alias.rename(f.root / "retained-alias")
        alias.symlink_to(f.root / "real-b", target_is_directory=True)
        self.assert_status(f.transact("bb", [alias / "child"], "try-acquire"), 75)
        self.assert_status(f.transact("cc", [f.root / "real-b"], "try-acquire"), 75)

    def test_complete_pending_blocks_and_incomplete_pending_remains_quarantined(self):
        f = Fixture()
        roots = [f.root / "held"]
        pending = f.record("aa", roots, "pending")
        self.assert_status(f.transact("bb", roots, "try-acquire"), 75)
        self.assert_status(f.transact("aa", roots, "recover"), 0)
        self.assertTrue(pending.with_suffix(".claim").exists())
        broken = f.record("cc", [f.root / "broken"], "pending")
        broken.write_bytes(b"incomplete")
        self.assert_status(f.transact("dd", [f.root / "unrelated"]), 0)
        self.assertEqual((f.registry / "quarantine" / broken.name).read_bytes(), b"incomplete")
        self.assert_status(f.transact("cc", [f.root / "broken"]), 73)
        self.assert_status(f.transact("cc", [f.root / "broken"], "recover"), 73)
        self.assertTrue(f.unpublished("cc"))

    def test_late_corruption_and_symlink_records_do_not_admit(self):
        for corrupt in ("hash", "symlink"):
            f = Fixture()
            for i in range(12):
                f.record(format(i, "x"), [f.root / "held" / str(i)])
            record = f.record("ee", [f.root / "last"])
            if corrupt == "hash":
                record.write_bytes(b"/different\n")
            else:
                retained = f.root / "retained-record"
                record.rename(retained)
                record.symlink_to(retained)
            self.assert_status(f.transact("ffff", [f.root / "wanted"], "try-acquire"), 73)
            self.assertTrue(f.unpublished("ffff"))

    def test_record_boundaries_cannot_hide_empty_unterminated_or_control_bytes(self):
        for raw in (b"", b"/held", b"/held\0suffix\n", b"/held\rname\n"):
            for position in ("aa", "ee"):
                f = Fixture()
                f.record("cc", [f.root / "ordinary"])
                # A matching digest is intentional: structural/framing checks,
                # not a hash mismatch, must reject these files before a grant.
                f.record(position, [], raw=raw)
                self.assert_status(f.transact("ffff", [f.root / "wanted"]), 73)
                self.assertTrue(f.unpublished("ffff"))

    def test_partial_record_reader_cannot_publish_a_shortened_inventory(self):
        f = Fixture()
        for i in range(8):
            f.record(format(i, "x"), [f.root / "held" / str(i)])
        calls = f.root / "reads"
        f.tools("tr", 'printf "read\\n" >> ' + shlex.quote(str(calls)) + '\n'
                '[ "$(wc -l < ' + shlex.quote(str(calls)) + ')" -ne 7 ] || '
                '{ printf "/apparently-disjoint\\n"; exit 91; }\n'
                'exec ' + shlex.quote(TR) + ' "$@"')
        self.assert_status(f.transact("ffff", [f.root / "wanted"]), 73)
        self.assertTrue(f.unpublished("ffff"))

    def test_late_physical_resolution_failure_never_publishes(self):
        f = Fixture()
        for i in range(8):
            f.record(format(i, "x"), [f.root / "held" / str(i)])
        f.tools("realpath", 'for root do case "$root" in */held/7) '
                'printf "/apparently-disjoint\\n"; exit 91;; esac; done\n'
                'exec ' + shlex.quote(REALPATH) + ' "$@"')
        self.assert_status(f.transact("ffff", [f.root / "wanted"]), 73)
        self.assertTrue(f.unpublished("ffff"))

    def test_failed_comparator_cannot_turn_partial_input_into_success(self):
        for program in ("exit 0", "printf disjoint; exit 91", "kill -KILL $$"):
            f = Fixture()
            f.record("aa", [f.root / "held"])
            f.tools("awk", 'case "$1" in -v) exec ' + shlex.quote(AWK) +
                    ' "$@";; esac\n' + program)
            self.assert_status(f.transact("bb", [f.root / "wanted"]), 73)
            self.assertTrue(f.unpublished("bb"))

    def test_large_roots_stay_off_exec_argv_and_last_root_is_checked(self):
        f = Fixture()
        roots = [str(f.root / "wanted" / str(i)) + "/" + "x" * 100 for i in range(1400)]
        self.assertGreater(len(body(roots)), 131072)
        for i in range(5):
            f.record(format(i, "x"), [f.root / "held" / str(i)])
        self.assert_status(f.transact("aa", roots), 0)
        self.assert_status(f.transact("aa", roots, "release"), 0)
        f.record("ee", [roots[-1] + "/child"], "pending")
        self.assert_status(f.transact("bb", roots, "try-acquire"), 75)
        self.assertTrue(f.unpublished("bb"))

    def test_concurrent_overlapping_transactions_have_one_grant(self):
        f = Fixture()
        for i in range(12):
            f.record(format(i, "x"), [f.root / "other" / str(i)])
        roots = [f.root / "wanted"]
        processes = [subprocess.Popen(f.command(token, roots, "try-acquire"),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=f.env)
                     for token in ("aa", "bb", "cc", "dd")]
        try:
            for process in processes:
                process.stdin.write(body(roots))
                process.stdin.close()
                process.stdin = None
            outputs = [process.communicate(timeout=30) for process in processes]
            self.assertEqual(sorted(p.returncode for p in processes), [0, 75, 75, 75], outputs)
            self.assertEqual(len(list(f.registry.glob("*.claim"))), 13)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_cancellation_release_receipts_and_durability_failures_are_unchanged(self):
        f = Fixture()
        roots = [f.root / "wanted"]
        self.assert_status(f.transact("aa", roots), 0)
        self.assertEqual(f.transact("aa", roots, "cancel").stdout, b"owned")
        self.assert_status(f.transact("bb", roots, "try-acquire"), 75)
        self.assert_status(f.transact("aa", roots, "finish-cancel"), 0)
        self.assertEqual(f.transact("aa", roots, "cancelled").stdout, b"cancelled")
        self.assert_status(f.transact("bb", roots), 0)
        self.assert_status(f.transact("bb", roots, "release"), 0)
        receipt = next((f.registry / "released").glob("bb.*.claim"))
        before = (receipt.stat().st_ino, receipt.read_bytes())
        f.tools("sync", "exit 91")
        result = f.transact("bb", roots, "released")
        self.assert_status(result, 73)
        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)

    def test_topology_overlap_does_not_run_the_mutator(self):
        f = Fixture()
        roots = [f.root / "namespace"]
        f.record("aa", [roots[0] / "held"])
        mutation = f.root / "must-not-exist"
        result = f.transact("bb", roots, "topology",
                            ("false", "touch " + shlex.quote(str(mutation))))
        self.assert_status(result, 75)
        self.assertFalse(mutation.exists())
        self.assertTrue(f.unpublished("bb"))

    def test_seeded_inventory_comparisons_match_cartesian_reference(self):
        rng = random.Random(104105)
        components = ["a", "aa", "b", "space name", "quote'\"", "[glob]*?", "back\\slash", "λ", "1\x1c2"]
        functions = SCRIPT.split("# An identity is bound", 1)[0]
        functions = functions[functions.index("refuse() {"):]
        for iteration in range(120):
            f = Fixture()
            groups = []
            for _ in range(rng.randint(2, 6)):
                groups.append(["/" + "/".join(rng.choice(components)
                                              for _ in range(rng.randint(1, 5)))
                               for _ in range(rng.randint(1, 7))])
            wanted = groups.pop()
            if iteration % 3 == 0:
                groups[-1].append(wanted[-1] + "/child")
            if iteration % 11 == 0:
                wanted.append("/")
            names = [f.record(format(i, "x"), roots).name for i, roots in enumerate(groups)]
            program = ("set -eu\n" + functions + '\nregistry=$1\nheld_claim_names=$2\n'
                       'requested=$(cat)\nif closures_overlap "$requested" inventory lexical; then\n'
                       'printf "overlap\\n"\nelse\nprintf "disjoint\\n"\nfi\n')
            result = subprocess.run([SHELL, "-c", program, "comparison", str(f.registry), "\n".join(names)],
                                    input=body(wanted), capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = b"overlap\n" if reference(wanted, [p for group in groups for p in group]) else b"disjoint\n"
            self.assertEqual(result.stdout, expected, (wanted, groups))

    def test_single_record_comparator_retains_its_original_contract(self):
        functions = SCRIPT.split("# An identity is bound", 1)[0]
        functions = functions[functions.index("refuse() {"):]
        for content, expected in ((b"/aa\n/b/cc\n", b"disjoint\n"),
                                  (b"/aa\n/b/c/child\n", b"overlap\n"),
                                  (b"/\n", b"overlap\n"), (b"/bad", None),
                                  (b"/a\0b\n", None), (b"RCH_HELD_RECORD_BEGIN\n", None)):
            f = Fixture()
            held = f.root / "held.roots"
            held.write_bytes(content)
            program = ("set -eu\n" + functions + '\nrequested=$(cat)\n'
                       'if closures_overlap "$requested" file "$1"; then\n'
                       'printf "overlap\\n"\nelse\nprintf "disjoint\\n"\nfi\n')
            result = subprocess.run([SHELL, "-c", program, "comparison", str(held)],
                                    input=body(["/a", "/b/c"]), capture_output=True, timeout=5)
            if expected is None:
                self.assert_status(result, 73)
            else:
                self.assertEqual((result.returncode, result.stdout), (0, expected), result.stderr)


def benchmark(baseline):
    original = Path(baseline).read_text()
    reports = []
    for owners, requested_count, conflict in ((1, 1, False), (32, 1, False),
                                               (32, 2048, False), (32, 2048, True)):
        f = Fixture()
        wanted = [f.root / "wanted" / str(i) for i in range(requested_count)]
        for i in range(owners):
            f.record(format(i, "x"), [wanted[0] if conflict and i == 0 else f.root / "held" / str(i)])
        f.record("ffff", wanted)
        baseline_file = f.root / "baseline.sh"
        baseline_file.write_text("set -eu\n" + HELPERS + "\n" + original)
        scripts = {"baseline": baseline_file, "candidate": f.script}
        expected = 73 if conflict else 0
        measurements = {key: [] for key in scripts}
        for repetition in range(4):
            order = list(scripts) if repetition % 2 == 0 else list(reversed(scripts))
            for key in order:
                start = time.perf_counter()
                result = f.transact("ffff", wanted, "recover", script=scripts[key])
                elapsed = time.perf_counter() - start
                if result.returncode != expected or result.stdout:
                    raise RuntimeError((key, result.returncode, result.stderr))
                if repetition:
                    measurements[key].append(elapsed)
        medians = {key: statistics.median(values) for key, values in measurements.items()}
        reports.append({"owners": owners, "requested_roots": requested_count,
                        "first_owner_conflicts": conflict, "seconds": measurements,
                        "median_seconds": medians,
                        "baseline_over_candidate": medians["baseline"] / medians["candidate"]})
    print(json.dumps({"shell": SHELL,
                      "baseline_sha256": hashlib.sha256(original.encode()).hexdigest(),
                      "candidate_sha256": hashlib.sha256(SCRIPT.encode()).hexdigest(),
                      "paired_native_registry_results": reports}, indent=2))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--benchmark":
        benchmark(sys.argv[2])
    else:
        unittest.main(verbosity=2)
