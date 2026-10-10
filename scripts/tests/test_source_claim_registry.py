#!/usr/bin/env python3
"""Real, isolated source-admission transactions and exact overlap regressions.

The production shell and shared record helpers run with actual flock, hashing,
realpath and durable writes. No worker or installed RCH state is touched. Owned
fixtures are retained; neither a passing test nor this suite claims fleet or
native-Darwin qualification. Run directly or through the Rust integration test.
"""
import hashlib
import os
from pathlib import Path
import random
import shlex
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = (REPO / "rch/src/hook/source_claim_registry.sh").read_text()
HELPER_SOURCE = (REPO / "rch-common/src/stale_target_reap.rs").read_text()
HELPERS = HELPER_SOURCE.split('pub const SOURCE_CLAIM_RECORD_HELPERS: &str = r#"', 1)[1].split('"#;', 1)[0]
FLOCK = shutil.which("flock")
AWK = shutil.which("awk")
CAT = shutil.which("cat")
REALPATH = shutil.which("realpath")


def body(roots):
    return ("\n".join(map(str, roots)) + "\n").encode()


def digest(roots):
    return hashlib.sha256(body(roots)).hexdigest()


def reference_overlap(wanted, held):
    """Independent Cartesian reference, deliberately not a trie."""
    return any(a == "/" or b == "/" or a == b
               or a.startswith(b + "/") or b.startswith(a + "/")
               for a in wanted for b in held)


class SourceClaimRegistryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-source-registry-"))
        self.registry = self.root / "registry"
        self.registry.mkdir()
        for name in ("released", "cancelled", "quarantine"):
            (self.registry / name).mkdir()
        self.env = {**os.environ, "LC_ALL": "C"}
        self.script = self.root / "transaction.sh"
        self.script.write_text("set -eu\n" + HELPERS + "\n" + SCRIPT)

    def record(self, token, roots, extension="claim"):
        path = self.registry / (token + "." + digest(roots) + "." + extension)
        path.write_bytes(body(roots))
        return path

    def command(self, token, roots, operation="acquire"):
        return [FLOCK, "--exclusive", "--no-fork", "--", str(self.registry / ".lock"),
                "/bin/sh", str(self.script), str(self.registry), token,
                digest(roots), operation]

    def transact(self, token, roots, operation="acquire", env=None):
        return subprocess.run(self.command(token, roots, operation),
                              input=body(roots), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env or self.env,
                              timeout=20, check=False)

    def assert_granted(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def assert_refused(self, result):
        self.assertEqual(result.returncode, 73, result.stderr.decode(errors="replace"))

    def comparison(self, wanted, held, env=None, held_file=None):
        # Execute the production function, not an algorithm copied into a test.
        functions = SCRIPT.split("# An identity is bound", 1)[0]
        functions = functions[functions.index("refuse() {"):]
        held_file = held_file or self.root / "held.roots"
        if held is not None:
            held_file.write_bytes(body(held))
        script = ("set -eu\n" + functions + "\nrequested=$(cat)\n"
                  'if closures_overlap "$requested" file "$1"; then\n'
                  '  printf "overlap\\n"\nelse\n  printf "disjoint\\n"\nfi\n')
        return subprocess.run(["/bin/sh", "-c", script, "comparison", str(held_file)],
                              input=body(wanted), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env or self.env,
                              timeout=10, check=False)

    def tool_env(self, name, program):
        directory = self.root / ("tools-" + str(len(list(self.root.glob("tools-*")))))
        directory.mkdir()
        tool = directory / name
        tool.write_text("#!/bin/sh\n" + program + "\n")
        tool.chmod(0o700)
        return {**self.env, "PATH": str(directory) + os.pathsep + self.env["PATH"]}

    def test_cartesian_reference_matches_component_index(self):
        rng = random.Random(67031)
        components = ["a", "aa", "b", "a-b", "a_b", "a.b", "space name",
                      "quote'\"", "[glob]*?", "back\\slash", "λ", "1\x1c2", "123"]
        for iteration in range(180):
            wanted, held = [], []
            for roots in (wanted, held):
                for _ in range(rng.randint(1, 10)):
                    roots.append("/" + "/".join(rng.choice(components)
                                              for _ in range(rng.randint(1, 5))))
            if iteration % 7 == 0:
                held.append(rng.choice(wanted))
            if iteration % 11 == 0:
                wanted.append("/")
            result = self.comparison(wanted, held)
            self.assert_granted(result)
            expected = b"overlap\n" if reference_overlap(wanted, held) else b"disjoint\n"
            self.assertEqual(result.stdout, expected, (wanted, held))

    def test_component_boundaries_and_both_ancestor_directions(self):
        for wanted, held, overlaps in [
            (["/"], ["/a/b"], True), (["/a/b"], ["/"], True),
            (["/a/b/c"], ["/a/b"], True), (["/a/b"], ["/a/b/c"], True),
            (["/a", "/b/c"], ["/aa", "/b/cc"], False),
            (["/a/b", "/a/b", "/x"], ["/a/c"], False),
        ]:
            result = self.comparison(wanted, held)
            self.assert_granted(result)
            self.assertEqual(result.stdout, b"overlap\n" if overlaps else b"disjoint\n")

    def test_failed_or_incomplete_comparison_never_proves_disjointness(self):
        for program in ("exit 1", "exit 0", "printf disjoint; exit 1",
                        "printf 'disjoint\\noverlap\\n'", "kill -KILL $$"):
            with self.subTest(program=program):
                result = self.comparison(["/a"], ["/b"], env=self.tool_env("awk", program))
                self.assert_refused(result)
                self.assertEqual(result.stdout, b"")
        result = self.comparison(["/a"], None, held_file=self.root / "absent")
        self.assert_refused(result)
        # A failed producer that emitted apparently valid but partial roots
        # cannot be rescued by awk returning success for the shortened set.
        env = self.tool_env("cat", 'if [ "$#" -gt 0 ]; then printf "/b\\n"; exit 1; fi\n'
                            "exec " + shlex.quote(CAT))
        self.assert_refused(self.comparison(["/a"], ["/b", "/a"], env=env))

    def test_malformed_and_unterminated_records_are_refused(self):
        for roots in (["relative"], ["/a/../b"], ["/a//b"], ["/a/"],
                      ["/a/./b"], ["/a\rb"], ["/a\x00b"], [""]):
            self.assert_refused(self.comparison(["/wanted"], roots))
        path = self.root / "unterminated"
        path.write_bytes(b"/b")
        self.assert_refused(self.comparison(["/a"], None, held_file=path))

    def test_large_closures_are_not_passed_through_exec_argv(self):
        wanted = ["/wanted/" + str(i) + "/" + "w" * 100 for i in range(1600)]
        held = ["/held/" + str(i) + "/" + "h" * 100 for i in range(1600)]
        self.assertGreater(len(body(wanted)), 131072)
        result = self.comparison(wanted, held)
        self.assert_granted(result)
        self.assertEqual(result.stdout, b"disjoint\n")
        held[-1] = wanted[-1] + "/child"
        result = self.comparison(wanted, held)
        self.assert_granted(result)
        self.assertEqual(result.stdout, b"overlap\n")

    def test_real_acquire_recover_release_and_reacquire(self):
        roots = [self.root / "project", self.root / "dependency"]
        self.assert_granted(self.transact("aa", roots))
        original = self.registry / ("aa." + digest(roots) + ".claim")
        original_bytes = original.read_bytes()
        self.assert_granted(self.transact("aa", roots, "recover"))
        self.assert_refused(self.transact("aa", roots))
        self.assert_refused(self.transact("bb", [roots[0] / "child"]))
        self.assert_granted(self.transact("bb", [self.root / "project-other"]))
        self.assert_granted(self.transact("aa", roots, "release"))
        receipt = self.registry / "released" / original.name
        self.assertEqual(receipt.read_bytes(), original_bytes)
        self.assert_refused(self.transact("aa", roots, "recover"))
        self.assert_granted(self.transact("cc", [roots[0] / "child"]))
        self.assertEqual(receipt.read_bytes(), original_bytes)

    def test_cancellation_remains_a_fence_until_finish_cancel(self):
        roots = [self.root / "project"]
        self.assert_granted(self.transact("aa", roots))
        cancel = self.transact("aa", roots, "cancel")
        self.assert_granted(cancel)
        self.assertEqual(cancel.stdout, b"owned")
        self.assert_refused(self.transact("aa", roots, "recover"))
        self.assert_refused(self.transact("bb", roots))
        self.assert_granted(self.transact("aa", roots, "finish-cancel"))
        self.assert_granted(self.transact("bb", roots))
        self.assert_refused(self.transact("aa", roots))

    def test_physical_aliases_exclude_both_parent_and_child_writers(self):
        real = self.root / "real"
        real.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(real, target_is_directory=True)
        self.assert_granted(self.transact("aa", [real]))
        for path in (alias, alias / "child"):
            result = self.transact("bb", [path])
            self.assert_refused(result)
            self.assertIn(b"physical source owner", result.stderr)
        self.assert_granted(self.transact("aa", [real], "release"))
        self.assert_granted(self.transact("cc", [real / "child"]))
        self.assert_refused(self.transact("dd", [alias]))

    def test_lexical_alias_claim_is_not_forgotten_after_symlink_moves(self):
        real_a, real_b = self.root / "a", self.root / "b"
        real_a.mkdir()
        real_b.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(real_a, target_is_directory=True)
        self.assert_granted(self.transact("aa", [alias]))
        replacement = self.root / "replacement"
        replacement.symlink_to(real_b, target_is_directory=True)
        alias.rename(self.root / "retained-original-alias")
        replacement.rename(alias)
        result = self.transact("bb", [alias / "child"])
        self.assert_refused(result)
        self.assertIn(b"overlapping source owner", result.stderr)
        self.assert_refused(self.transact("cc", [real_b]))

    def test_corrupt_active_and_complete_pending_records_never_grant_overlap(self):
        roots = [self.root / "project"]
        pending = self.record("aa", roots, "pending")
        self.assert_refused(self.transact("bb", [roots[0] / "child"]))
        self.assertEqual(pending.read_bytes(), body(roots))
        self.assert_granted(self.transact("aa", roots, "recover"))
        active = pending.with_suffix(".claim")
        active.write_bytes(b"truncated")
        result = self.transact("cc", [self.root / "unrelated"])
        self.assert_refused(result)
        self.assertEqual(active.read_bytes(), b"truncated")
        self.assertFalse(list(self.registry.glob("cc.*.claim")))

    def test_quarantined_incomplete_pending_cannot_become_a_new_grant(self):
        roots = [self.root / "project"]
        pending = self.record("aa", roots, "pending")
        pending.write_bytes(b"truncated")
        self.assert_granted(self.transact("bb", [self.root / "unrelated"]))
        self.assertEqual((self.registry / "quarantine" / pending.name).read_bytes(), b"truncated")
        self.assert_refused(self.transact("aa", roots))
        self.assert_refused(self.transact("aa", roots, "recover"))
        self.assertFalse(list(self.registry.glob("aa.*.claim")))

    def test_real_large_registry_checks_last_root_before_publication(self):
        held = [self.root / "held" / str(i) for i in range(384)]
        wanted = [self.root / "wanted" / str(i) for i in range(384)]
        original = self.record("aa", held)
        self.assert_granted(self.transact("bb", wanted))
        wanted[-1] = held[-1] / "child"
        self.assert_refused(self.transact("cc", wanted))
        self.assertEqual(original.read_bytes(), body(held))
        self.assertFalse(list(self.registry.glob("cc.*.claim")))
        self.assertFalse(list(self.registry.glob("cc.*.pending")))

    def test_resolver_failure_in_later_batch_does_not_publish(self):
        roots = [self.root / "wanted" / str(i) for i in range(130)]
        env = self.tool_env("realpath", 'for root do\n'
                            '  case "$root" in */wanted/129) exit 1;; esac\ndone\n'
                            "exec " + shlex.quote(REALPATH) + ' "$@"')
        self.assert_refused(self.transact("aa", roots, env=env))
        self.assertFalse(list(self.registry.glob("aa.*.claim")))
        self.assertFalse(list(self.registry.glob("aa.*.pending")))

    def test_comparison_failure_in_transaction_preserves_both_owners(self):
        held, wanted = [self.root / "held"], [self.root / "wanted"]
        original = self.record("aa", held)
        # Physical-batch validation still uses real awk. Fail only the actual
        # new comparison, after a genuine claim was validated and resolved.
        env = self.tool_env("awk", 'case "$1" in -v) exec ' + shlex.quote(AWK)
                            + ' "$@";; *) exit 1;; esac')
        self.assert_refused(self.transact("bb", wanted, env=env))
        self.assertEqual(original.read_bytes(), body(held))
        self.assertFalse(list(self.registry.glob("bb.*.claim")))
        self.assertFalse(list(self.registry.glob("bb.*.pending")))

    def test_concurrent_overlapping_acquires_grant_exactly_one_owner(self):
        roots = [self.root / "project"]
        processes = [subprocess.Popen(self.command(token, roots), stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=self.env) for token in ("aa", "bb")]
        try:
            for process in processes:
                process.stdin.write(body(roots))
                process.stdin.close()
                process.stdin = None
            outputs = [process.communicate(timeout=20) for process in processes]
            self.assertEqual(sorted(process.returncode for process in processes), [0, 73], outputs)
            records = list(self.registry.glob("*.claim"))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].read_bytes(), body(roots))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()  # Only the fixture child, never a worker.
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
