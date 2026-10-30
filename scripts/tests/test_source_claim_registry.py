#!/usr/bin/env python3
"""Real, isolated source-admission transactions and exact overlap regressions.

The production shell and shared record helpers run with actual flock, hashing,
realpath and durable writes. No worker or installed RCH state is touched. Owned
fixtures are retained; neither a passing test nor this suite claims fleet or
native-Darwin qualification. Run directly or through the Rust integration test.
"""
import hashlib
import fcntl
import os
from pathlib import Path
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = (REPO / "rch/src/hook/source_claim_registry.sh").read_text()
HELPER_SOURCE = (REPO / "rch-common/src/stale_target_reap.rs").read_text()
HELPERS = HELPER_SOURCE.split('pub const SOURCE_CLAIM_RECORD_HELPERS: &str = r#"', 1)[1].split('"#;', 1)[0]
FLOCK = shutil.which("flock")
# util-linux flock can exec the command in place; the BSD port Homebrew ships
# on macOS has no --no-fork and always runs it as a child.
FLOCK_NO_FORK = ["--no-fork"] if FLOCK and b"util-linux" in subprocess.run(
    [FLOCK, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    check=False).stdout else []
AWK = shutil.which("awk")
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
    shell = "/bin/sh"

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
        return [FLOCK, "--exclusive", *FLOCK_NO_FORK, "--", str(self.registry / ".lock"),
                self.shell, str(self.script), str(self.registry), token,
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
        return subprocess.run([self.shell, "-c", script, "comparison", str(held_file)],
                              input=body(wanted), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env or self.env,
                              timeout=10, check=False)

    def tool_env(self, name, program):
        return self.tools_env({name: program})

    def tools_env(self, tools):
        directory = self.root / ("tools-" + str(len(list(self.root.glob("tools-*")))))
        directory.mkdir()
        for name, program in tools.items():
            tool = directory / name
            tool.write_text("#!/bin/sh\n" + program + "\n")
            tool.chmod(0o700)
        return {**self.env, "PATH": str(directory) + os.pathsep + self.env["PATH"]}

    def barrier_env(self, program):
        # The registry fsyncs each record and directory itself through a
        # `python3 -c` adapter, never the sync utility (GNU syncfs and uutils'
        # global sync wait on unrelated builds under the registry lock). Fake
        # that adapter: `program` sees the barrier path as $1 and fails the
        # barrier by exiting nonzero; otherwise the real fsync runs. A call to
        # the utility itself leaves a marker (see assert_no_sync_utility).
        return self.tools_env({
            "python3": ('case "${4-}" in *os.fsync*)\n'
                        "  barrier() {\n" + program + "\n  }\n"
                        '  barrier "$5" || exit\n'
                        "esac\nexec " + shlex.quote(sys.executable) + ' "$@"'),
            "sync": "touch " + shlex.quote(str(self.root / "sync-utility-called")) + "\nexit 97",
        })

    def assert_no_sync_utility(self):
        self.assertFalse((self.root / "sync-utility-called").exists(),
                         "no whole-filesystem sync under the registry lock")

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
        # Held record files are read through tr (NUL -> CR for BSD awk).
        held_file = self.root / "held-partial.roots"
        held_file.write_bytes(body(["/b", "/a"]))
        env = self.tool_env("tr", 'printf "/b\\n"; exit 1')
        self.assert_refused(self.comparison(["/a"], None, env=env, held_file=held_file))
        self.assert_granted(self.comparison(["/a"], None, held_file=held_file))

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
        conflict = self.transact("bb", roots)
        self.assert_refused(conflict)
        self.assertIn(b"RCH_SOURCE_CANCELLATION_FENCE identity=aa", conflict.stderr)
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
        program = ('for root do\n'
                   '  case "$root" in */wanted/129) exit 1;; esac\ndone\n'
                   'exec {} "$@"')
        env = self.tool_env("realpath", program.format(shlex.quote(REALPATH)))
        # rch_realpath_m prefers Homebrew's grealpath (macOS) when present.
        grealpath = shutil.which("grealpath")
        if grealpath:
            tool = Path(env["PATH"].split(os.pathsep)[0]) / "grealpath"
            tool.write_text("#!/bin/sh\n" + program.format(shlex.quote(grealpath)) + "\n")
            tool.chmod(0o700)
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

    def fail_sync_after_move(self, destination):
        # Real writes and renames run. Only the fsync barrier reports an injected
        # failure after the destination appears: the lost-durability-ack frontier.
        return self.barrier_env('if [ -e {} ]; then\n'
                                '  printf "injected post-rename sync failure\\n" >&2\n'
                                '  exit 91\nfi'.format(shlex.quote(str(destination))))

    def assert_unconfirmed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, b"", "no success/ownership verdict on failure")

    def test_recovery_completes_failed_acquire_and_pending_promotion_sync(self):
        for from_pending, token in [(False, "aa"), (True, "ab")]:
            with self.subTest(from_pending=from_pending):
                roots = [self.root / token]
                active = self.registry / (token + "." + digest(roots) + ".claim")
                operation = "acquire"
                if from_pending:
                    self.record(token, roots, "pending")
                    operation = "recover"
                env = self.fail_sync_after_move(active)
                self.assert_unconfirmed(self.transact(token, roots, operation, env))
                before = (active.stat().st_ino, active.read_bytes())
                self.assertEqual(before[1], body(roots))
                self.assert_unconfirmed(self.transact(token, roots, "recover", env))
                self.assert_refused(self.transact("bb", roots))
                self.assert_granted(self.transact(token, roots, "recover"))
                self.assertEqual((active.stat().st_ino, active.read_bytes()), before)
                self.assertFalse(active.with_suffix(".pending").exists())

    def test_release_replay_finishes_durability_without_releasing_a_new_owner(self):
        roots = [self.root / "project"]
        self.assert_granted(self.transact("aa", roots))
        active = self.registry / ("aa." + digest(roots) + ".claim")
        before = (active.stat().st_ino, active.read_bytes())
        receipt = self.registry / "released" / active.name
        env = self.fail_sync_after_move(receipt)
        self.assert_unconfirmed(self.transact("aa", roots, "release", env))
        self.assertFalse(active.exists())
        for operation in ("release", "released"):
            self.assert_unconfirmed(self.transact("aa", roots, operation, env))
        self.assert_granted(self.transact("aa", roots, "release"))
        query = self.transact("aa", roots, "released")
        self.assert_granted(query)
        self.assertEqual(query.stdout, b"released")
        # Normal completion cannot be relabelled as an unexecuted cancellation.
        self.assert_refused(self.transact("aa", roots, "cancel"))
        self.assert_refused(self.transact("aa", roots, "recover"))
        self.assert_granted(self.transact("bb", roots))
        next_owner = self.registry / ("bb." + digest(roots) + ".claim")
        self.assert_granted(self.transact("aa", roots, "release"))
        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)
        self.assertEqual(next_owner.read_bytes(), body(roots))
        self.assert_refused(self.transact("cc", roots))

    def test_lost_release_ack_keeps_aged_restart_proof_and_fences_same_token(self):
        roots = [self.root / "project"]
        roots[0].mkdir()
        source = roots[0] / "source"
        source.write_bytes(b"preserved source for the next owner")
        source_before = source.stat().st_ino, source.read_bytes()
        self.assert_granted(self.transact("aa", roots))
        receipt = self.registry / "released" / ("aa." + digest(roots) + ".claim")
        self.assert_unconfirmed(self.transact("aa", roots, "release",
                                             self.fail_sync_after_move(receipt)))
        before = receipt.stat().st_ino, receipt.read_bytes()
        # The dispatcher cannot checkpoint an unsuccessful release. Age the
        # worker's exact proof past retention before unrelated admissions run.
        os.utime(receipt, (1_000_000, 1_000_000))
        for token in ("ba", "bb", "bc"):
            self.assert_granted(self.transact(token, [self.root / token]))
        query = self.transact("aa", roots, "released")
        self.assert_granted(query)
        self.assertEqual(query.stdout, b"released", "restart must still prove the exact release")
        self.assert_granted(self.transact("aa", roots, "release"))
        for operation in ("acquire", "try-acquire", "recover", "cancel"):
            self.assert_refused(self.transact("aa", roots, operation))
        self.assert_granted(self.transact("cc", roots))
        successor = self.registry / ("cc." + digest(roots) + ".claim")
        successor_before = successor.stat().st_ino, successor.read_bytes()
        self.assert_granted(self.transact("aa", roots, "release"))
        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)
        self.assertEqual((successor.stat().st_ino, successor.read_bytes()), successor_before)
        self.assertEqual((source.stat().st_ino, source.read_bytes()), source_before)

    def test_cancel_replay_rechecks_post_rename_durability_for_every_frontier(self):
        for frontier, token in [("active", "aa"), ("absent", "ab"), ("quarantine", "ac")]:
            with self.subTest(frontier=frontier):
                roots = [self.root / token]
                receipt = self.registry / "cancelled" / (token + "." + digest(roots) + ".claim")
                operation = "cancel"
                if frontier == "active":
                    self.assert_granted(self.transact(token, roots))
                    self.assertEqual(self.transact(token, roots, "cancel").stdout, b"owned")
                    operation = "finish-cancel"
                elif frontier == "quarantine":
                    pending = self.record(token, roots, "pending")
                    pending.write_bytes(b"incomplete legacy write")
                    self.assert_granted(self.transact("bb", [self.root / "other"]))
                env = self.fail_sync_after_move(receipt)
                self.assert_unconfirmed(self.transact(token, roots, operation, env))
                before = (receipt.stat().st_ino, receipt.read_bytes())
                self.assertEqual(before[1], body(roots))
                for retry in ("cancel", "finish-cancel", "cancelled"):
                    self.assert_unconfirmed(self.transact(token, roots, retry, env))
                    result = self.transact(token, roots, retry)
                    self.assert_granted(result)
                    self.assertEqual(result.stdout, {
                        "cancel": b"unowned", "finish-cancel": b"", "cancelled": b"cancelled",
                    }[retry])
                self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)
                self.assert_refused(self.transact(token, roots))
                self.assert_refused(self.transact(token, roots, "recover"))
                self.assertFalse((self.registry / receipt.name).exists())
                if frontier == "quarantine":
                    self.assertEqual((self.registry / "quarantine" / pending.name).read_bytes(),
                                     b"incomplete legacy write")

    def test_every_terminal_replay_sync_barrier_is_required_before_success(self):
        roots = [self.root / "project"]
        for state, token, operations in [("released", "aa", ("released", "release")),
                                         ("cancelled", "ab", ("cancel", "finish-cancel", "cancelled"))]:
            self.assert_granted(self.transact(token, roots))
            if state == "released":
                self.assert_granted(self.transact(token, roots, "release"))
            else:
                self.assert_granted(self.transact(token, roots, "cancel"))
                self.assert_granted(self.transact(token, roots, "finish-cancel"))
            receipt = self.registry / state / (token + "." + digest(roots) + ".claim")
            before = (receipt.stat().st_ino, receipt.read_bytes())
            for path in (receipt, receipt.parent, self.registry):
                env = self.barrier_env('if [ "$1" = {} ]; then exit 91; fi'.format(
                    shlex.quote(str(path))))
                for operation in operations:
                    with self.subTest(state=state, path=path, operation=operation):
                        self.assert_unconfirmed(self.transact(token, roots, operation, env))
                        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)
                        self.assert_granted(self.transact(token, roots, operation))

    def test_release_replay_rejects_conflicting_records_without_mutation(self):
        for index, state in enumerate(("claim", "pending", "cancelling", "cancelled", "quarantine")):
            with self.subTest(state=state):
                token = "a" + format(index, "x")
                roots = [self.root / token]
                self.assert_granted(self.transact(token, roots))
                self.assert_granted(self.transact(token, roots, "release"))
                receipt = self.registry / "released" / (token + "." + digest(roots) + ".claim")
                if state in ("cancelled", "quarantine"):
                    extension = "pending" if state == "quarantine" else "claim"
                    conflict = self.registry / state / (token + "." + digest(roots) + "." + extension)
                    conflict.write_bytes(body(roots))
                else:
                    conflict = self.record(token, roots, state)
                before = [(p.stat().st_ino, p.read_bytes()) for p in (receipt, conflict)]
                self.assert_refused(self.transact(token, roots, "release"))
                self.assertEqual([(p.stat().st_ino, p.read_bytes()) for p in (receipt, conflict)], before)

    def test_concurrent_release_retries_preserve_one_receipt_and_later_grant(self):
        roots = [self.root / "project"]
        self.assert_granted(self.transact("aa", roots))
        active = self.registry / ("aa." + digest(roots) + ".claim")
        before = (active.stat().st_ino, active.read_bytes())
        processes = [subprocess.Popen(self.command("aa", roots, "release"), stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=self.env) for _ in range(4)]
        try:
            for process in processes:
                process.stdin.write(body(roots))
                process.stdin.close()
                process.stdin = None
            outputs = [process.communicate(timeout=20) for process in processes]
            self.assertEqual([p.returncode for p in processes], [0] * 4, outputs)
            self.assertTrue(all(stdout == b"" for stdout, _ in outputs))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
        receipt = self.registry / "released" / active.name
        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)
        self.assertFalse(active.exists())
        self.assert_granted(self.transact("bb", roots))
        self.assert_refused(self.transact("aa", roots, "recover"))

    def test_terminal_verdicts_refuse_conflicting_identity_states_before_mutation(self):
        pairs = [("released", state) for state in
                 ("claim", "pending", "cancelling", "cancelled", "quarantine")]
        pairs += [("cancelled", "claim"), ("cancelled", "pending")]
        operations = ("acquire", "recover", "release", "released", "cancel", "finish-cancel", "cancelled")
        for index, states in enumerate(pairs):
            for operation in operations:
                with self.subTest(states=states, operation=operation):
                    # Every case has independent state so a buggy operation's
                    # mutation cannot manufacture the next case's outcome.
                    self.registry = self.root / (str(index) + "-" + operation)
                    self.registry.mkdir()
                    for directory in ("released", "cancelled", "quarantine"):
                        (self.registry / directory).mkdir()
                    (self.registry / ".lock").touch()
                    roots = [self.root / "project"]
                    for state in states:
                        if state in ("released", "cancelled", "quarantine"):
                            extension = "pending" if state == "quarantine" else "claim"
                            path = self.registry / state / ("aa." + digest(roots) + "." + extension)
                            path.write_bytes(body(roots))
                        else:
                            self.record("aa", roots, state)
                    def snapshot():
                        return {str(path.relative_to(self.registry)):
                                (path.stat().st_ino, path.read_bytes())
                                for path in self.registry.rglob("*") if path.is_file()}
                    before = snapshot()
                    result = self.transact("aa", roots, operation)
                    self.assert_refused(result)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(snapshot(), before, "conflicting evidence must be retained")

    def test_terminal_checks_preserve_real_completed_and_quarantined_cancellations(self):
        for quarantined, token in [(False, "aa"), (True, "ab")]:
            roots = [self.root / token]
            if quarantined:
                pending = self.record(token, roots, "pending")
                pending.write_bytes(b"partial write")
                self.assert_granted(self.transact("bb", [self.root / "other"]))
                result = self.transact(token, roots, "cancel")
                self.assert_granted(result)
                self.assertEqual(result.stdout, b"unowned")
            else:
                self.assert_granted(self.transact(token, roots))
                result = self.transact(token, roots, "cancel")
                self.assert_granted(result)
                self.assertEqual(result.stdout, b"owned")
                self.assert_granted(self.transact(token, roots, "finish-cancel"))
            # Cancellation deliberately keeps its marker. The hard-linked
            # quarantine fence can contain incomplete bytes, not a valid claim.
            fence = self.registry / (token + "." + digest(roots) + ".cancelling")
            before = (fence.stat().st_ino, fence.read_bytes())
            for operation in ("cancel", "finish-cancel", "cancelled"):
                result = self.transact(token, roots, operation)
                self.assert_granted(result)
                self.assertEqual(result.stdout, {
                    "cancel": b"unowned", "finish-cancel": b"", "cancelled": b"cancelled",
                }[operation])
            self.assertEqual((fence.stat().st_ino, fence.read_bytes()), before)
            self.assert_granted(self.transact("cc" if quarantined else "cd", roots))
            self.assert_refused(self.transact(token, roots, "recover"))
            self.assert_refused(self.transact(token, roots, "release"))

    def test_cancellation_query_never_grants_or_retires_source_ownership(self):
        roots = [self.root / "project"]
        receipt = self.registry / "cancelled" / ("aa." + digest(roots) + ".claim")
        for transition in (None, "acquire", "cancel"):
            if transition:
                self.assert_granted(self.transact("aa", roots, transition))
            before = {str(path): (path.stat().st_ino, path.read_bytes())
                      for path in self.registry.rglob("*") if path.is_file()}
            query = self.transact("aa", roots, "cancelled")
            self.assert_granted(query)
            self.assertEqual(query.stdout, b"pending")
            self.assertFalse(receipt.exists())
            after = {str(path): (path.stat().st_ino, path.read_bytes())
                     for path in self.registry.rglob("*") if path.is_file()}
            # The first query may create only the flock inode, not any record.
            self.assertEqual({p: v for p, v in after.items() if not p.endswith("/.lock")},
                             {p: v for p, v in before.items() if not p.endswith("/.lock")})

        self.assert_granted(self.transact("aa", roots, "finish-cancel"))
        self.assert_granted(self.transact("bb", roots))
        next_owner = self.registry / ("bb." + digest(roots) + ".claim")
        before = [(path.stat().st_ino, path.read_bytes()) for path in (receipt, next_owner)]
        query = self.transact("aa", roots, "cancelled")
        self.assert_granted(query)
        self.assertEqual(query.stdout, b"cancelled")
        self.assertEqual([(path.stat().st_ino, path.read_bytes())
                          for path in (receipt, next_owner)], before)
        self.assert_refused(self.transact("aa", [roots[0] / "different"], "cancelled"))
        self.assert_refused(self.transact("cc", roots))

    def test_cancellation_state_observes_interrupted_and_collected_cancellation(self):
        for index, state in enumerate(("absent", "active", "active-fence", "marker-only",
                                       "receipt-only", "released")):
            with self.subTest(state=state):
                token = "a" + format(index, "x")
                roots = [self.root / token]
                roots[0].mkdir()
                source = roots[0] / "source"
                source.write_bytes(b"source is not cancellation evidence")
                source_before = source.stat().st_ino, source.read_bytes()
                receipt = self.registry / "cancelled" / (token + "." + digest(roots) + ".claim")
                if state in ("active", "active-fence", "released"):
                    self.assert_granted(self.transact(token, roots))
                if state == "active-fence":
                    self.assertEqual(self.transact(token, roots, "cancel").stdout, b"owned")
                elif state == "marker-only":
                    self.assertEqual(self.transact(token, roots, "cancel").stdout, b"unowned")
                    os.utime(receipt, (1_000_000, 1_000_000))
                    self.assert_granted(self.transact("bb", [self.root / "receipt-gc-trigger"]))
                    self.assertFalse(receipt.exists(), "exercise actual cancelled receipt collection")
                elif state == "receipt-only":
                    receipt.write_bytes(body(roots))  # An older unowned cancellation frontier.
                elif state == "released":
                    self.assert_granted(self.transact(token, roots, "release"))
                before = {str(path): (path.stat().st_ino, path.read_bytes())
                          for path in self.registry.rglob("*") if path.is_file() and path.name != ".lock"}
                for _ in range(2):
                    query = self.transact(token, roots, "cancellation-state")
                    self.assert_granted(query)
                    self.assertEqual(query.stdout, b"cancellation" if state in
                                     ("active-fence", "marker-only", "receipt-only") else b"pending")
                after = {str(path): (path.stat().st_ino, path.read_bytes())
                         for path in self.registry.rglob("*") if path.is_file() and path.name != ".lock"}
                self.assertEqual(after, before, "discovery cannot publish or retire ownership")
                self.assertEqual((source.stat().st_ino, source.read_bytes()), source_before)
                if state in ("active-fence", "marker-only"):
                    completed = self.transact(token, roots, "cancelled")
                    self.assert_granted(completed)
                    self.assertEqual(completed.stdout, b"pending", "intent is not completed cancellation")
                    for operation in ("acquire", "recover"):
                        self.assert_refused(self.transact(token, roots, operation))

    def test_cancellation_state_preserves_incomplete_conflicting_and_unknown_evidence(self):
        states = ("pending", "torn-pending", "quarantine", "torn-marker", "changed-roots",
                  "active-and-cancelled", "released-and-marker", "symlink-marker",
                  "unknown", "unknown-released", "unknown-cancelled", "unknown-quarantine")
        for index, state in enumerate(states):
            with self.subTest(state=state):
                token = "a" + format(index, "x")
                roots = [self.root / token]
                fence = self.record(token, roots, "cancelling")
                if state in ("pending", "torn-pending"):
                    pending = self.record(token, roots, "pending")
                    if state == "torn-pending":
                        pending.write_bytes(b"partial publication")
                elif state == "quarantine":
                    pending = self.registry / "quarantine" / fence.with_suffix(".pending").name
                    pending.write_bytes(b"partial quarantined publication")
                elif state == "torn-marker":
                    fence.write_bytes(b"")
                elif state == "changed-roots":
                    self.record(token, [self.root / (token + "-different")], "cancelling")
                elif state == "active-and-cancelled":
                    self.record(token, roots)
                    (self.registry / "cancelled" / fence.with_suffix(".claim").name).write_bytes(body(roots))
                elif state == "released-and-marker":
                    (self.registry / "released" / fence.with_suffix(".claim").name).write_bytes(body(roots))
                elif state == "symlink-marker":
                    saved = self.root / (token + "-original-marker")
                    fence.rename(saved)
                    fence.symlink_to(saved)
                else:
                    directory = self.registry if state == "unknown" else self.registry / state[8:]
                    (directory / (token + ".unknown")).write_bytes(b"unrecognized same-identity state")

                def inventory():
                    return {str(path): (path.lstat().st_ino,
                                        os.readlink(path) if path.is_symlink() else path.read_bytes())
                            for path in self.registry.rglob("*")
                            if (path.is_file() or path.is_symlink()) and path.name != ".lock"}

                before = inventory()
                query = self.transact(token, roots, "cancellation-state")
                self.assert_refused(query)
                self.assertEqual(query.stdout, b"")
                self.assertEqual(inventory(), before, "read-only discovery cannot repair ambiguous state")

    def test_cancellation_state_requires_exact_durability_before_reply(self):
        roots = [self.root / "project"]
        self.assert_granted(self.transact("aa", roots))
        self.assert_granted(self.transact("aa", roots, "cancel"))
        fence = self.registry / ("aa." + digest(roots) + ".cancelling")
        receipt = self.registry / "cancelled" / fence.with_suffix(".claim").name
        for completed in (False, True):
            if completed:
                self.assert_granted(self.transact("aa", roots, "finish-cancel"))
            paths = (fence, self.registry, receipt, receipt.parent) if completed else (fence, self.registry)
            before = {str(path): (path.stat().st_ino, path.read_bytes())
                      for path in self.registry.rglob("*") if path.is_file()}
            for path in paths:
                with self.subTest(completed=completed, path=path):
                    env = self.barrier_env('if [ "$1" = {} ]; then exit 91; fi'.format(shlex.quote(str(path))))
                    self.assert_unconfirmed(self.transact("aa", roots, "cancellation-state", env))
                    query = self.transact("aa", roots, "cancellation-state")
                    self.assert_granted(query)
                    self.assertEqual(query.stdout, b"cancellation")
                    self.assertEqual({str(path): (path.stat().st_ino, path.read_bytes())
                                      for path in self.registry.rglob("*") if path.is_file()}, before)
        self.assert_refused(self.transact("aa", [roots[0] / "different"], "cancellation-state"))

    def test_registry_durability_syncs_records_and_directories_not_filesystems(self):
        trace = self.root / "barrier-paths"
        env = self.barrier_env('printf "%s\\000" "$1" >> {}'.format(shlex.quote(str(trace))))
        cancelled_roots = [self.root / "cancelled-project"]
        for operation in ("acquire", "recover", "cancel", "finish-cancel", "cancelled"):
            self.assert_granted(self.transact("aa", cancelled_roots, operation, env))
        released_roots = [self.root / "released-project"]
        for operation in ("acquire", "release", "released"):
            self.assert_granted(self.transact("bb", released_roots, operation, env))
        self.assert_granted(self.transact("cc", [self.root / "absent-project"], "cancel", env))

        quarantined_roots = [self.root / "quarantined-project"]
        pending = self.record("dd", quarantined_roots, "pending")
        pending.write_bytes(b"partial write")
        self.assert_granted(self.transact("ee", [self.root / "other-project"], "acquire", env))
        self.assert_granted(self.transact("dd", quarantined_roots, "cancel", env))

        # Observe each path the real fsync then receives: one record or
        # directory, data and metadata, never a filesystem-wide flush. This
        # includes calls originating in the shared record helpers.
        self.assert_no_sync_utility()
        arguments = trace.read_bytes().split(b"\0")
        self.assertEqual(arguments.pop(), b"")
        paths = set()
        for path in arguments:
            path = Path(os.fsdecode(path))
            self.assertTrue(path == self.registry or self.registry in path.parents)
            paths.add(path)
        for directory in (self.registry, self.registry / "released",
                          self.registry / "cancelled", self.registry / "quarantine"):
            self.assertIn(directory, paths, "directory-entry durability is still required")
        for token, roots, directory in (("aa", cancelled_roots, "cancelled"),
                                         ("bb", released_roots, "released")):
            self.assertIn(self.registry / directory / (token + "." + digest(roots) + ".claim"), paths)
        self.assertTrue(any(path.name.startswith(".record-write.") for path in paths),
                        "private record bytes must be synced before publication")

    def test_failed_file_sync_never_falls_back_to_a_global_flush_or_grants(self):
        env = self.barrier_env("exit 91")
        result = self.transact("aa", [self.root / "project"], env=env)
        self.assert_unconfirmed(result)
        self.assert_no_sync_utility()
        self.assertFalse(list(self.registry.glob("aa.*.claim")))
        self.assertFalse(list(self.registry.glob("aa.*.pending")))

    def test_legacy_registry_compatibility_window_and_unwritable_tmp_isolation(self):
        legacy = self.root / "legacy-tmp-registry"
        legacy.mkdir()
        legacy_roots = [self.root / "legacy-held"]
        legacy_claim = legacy / ("99." + digest(legacy_roots) + ".claim")
        legacy_claim.write_bytes(body(legacy_roots))
        # Simulate a quota-exhausted / unwritable /tmp registry directory.
        legacy.chmod(0o500)
        self.addCleanup(lambda: legacy.chmod(0o700))
        env = {**self.env, "RCH_LEGACY_SOURCE_CLAIM_REGISTRY": str(legacy)}

        overlap = self.transact("aa", [self.root / "legacy-held/sub"], "try-acquire", env=env)
        self.assertEqual(overlap.returncode, 75, overlap.stderr.decode(errors="replace"))
        self.assertIn(b"unfinished overlapping source owner", overlap.stderr)

        disjoint = [self.root / "var-tmp-project"]
        self.assert_granted(self.transact("bb", disjoint, "acquire", env=env))
        self.assert_granted(self.transact("bb", disjoint, "release", env=env))

    def test_terminal_retention_preserves_release_proof_and_headroom_reserves_release(self):
        old_roots = [self.root / "old-project"]
        old_released = self.registry / "released" / ("01." + digest(old_roots) + ".claim")
        old_cancelled = self.registry / "cancelled" / ("02." + digest(old_roots) + ".claim")
        fresh_released = self.registry / "released" / ("03." + digest(old_roots) + ".claim")
        for path in (old_released, old_cancelled, fresh_released):
            path.write_bytes(body(old_roots))
        self.record("02", old_roots, "cancelling")
        two_days_ago = 1_000_000
        os.utime(old_released, (two_days_ago, two_days_ago))
        os.utime(old_cancelled, (two_days_ago, two_days_ago))

        active_roots = [self.root / "active-project"]
        self.assert_granted(self.transact("aa", active_roots, "acquire"))
        self.assertTrue(old_released.exists(), "age does not prove the dispatcher acknowledged release")
        self.assertFalse(old_cancelled.exists())
        self.assertTrue(fresh_released.exists())

        low_headroom_env = {**self.env, "RCH_REGISTRY_MIN_FREE_KB": "999999999999"}
        refused = self.transact("bb", [self.root / "new-project"], "acquire", env=low_headroom_env)
        self.assert_refused(refused)
        self.assertIn(b"RCH_SOURCE_CLAIM_WRITE_FAILED", refused.stderr)
        self.assertIn(b"below reserved headroom", refused.stderr)
        # In-flight claims can still release using the reserved headroom.
        self.assert_granted(self.transact("aa", active_roots, "release", env=low_headroom_env))

    def test_unowned_cancellation_fence_survives_gc_before_dispatcher_settlement(self):
        for index, interrupted in enumerate((False, True)):
            with self.subTest(interrupted=interrupted):
                token = "a" + format(index, "x")
                roots = [self.root / token]
                roots[0].mkdir()
                source = roots[0] / "keep-source"
                source.write_bytes(b"source owned by a later job")
                receipt = self.registry / "cancelled" / (token + "." + digest(roots) + ".claim")
                env = self.fail_sync_after_move(receipt) if interrupted else self.env
                result = self.transact(token, roots, "cancel", env=env)
                if interrupted:
                    self.assert_unconfirmed(result)
                else:
                    self.assert_granted(result)
                    self.assertEqual(result.stdout, b"unowned")
                fence = self.registry / receipt.with_suffix(".cancelling").name
                before = fence.stat().st_ino, fence.read_bytes()
                self.assertEqual(before[1], body(roots))
                os.utime(receipt, (1_000_000, 1_000_000))

                # The dispatcher never reaches settle-cancel. Another real
                # admission runs receipt retention after its interrupted start.
                other = "b" + format(index, "x")
                self.assert_granted(self.transact(other, [self.root / (other + "-other")]))
                self.assertFalse(receipt.exists())
                self.assertEqual((fence.stat().st_ino, fence.read_bytes()), before)
                for operation in ("acquire", "try-acquire", "recover"):
                    self.assert_refused(self.transact(token, roots, operation))
                replacement = "c" + format(index, "x")
                self.assert_granted(self.transact(replacement, roots))
                self.assert_refused(self.transact(token, roots))
                self.assertEqual(source.read_bytes(), b"source owned by a later job")
                settled = self.transact(token, roots, "settle-cancel")
                self.assert_granted(settled)
                self.assertEqual(settled.stdout, b"settled")
                replacement_claim = self.registry / (replacement + "." + digest(roots) + ".claim")
                self.assertEqual(replacement_claim.read_bytes(), body(roots))

    def test_legacy_cancellation_replay_requires_durable_fence_and_gc_retains_failed_barrier(self):
        for index, operation in enumerate(("cancel", "finish-cancel")):
            with self.subTest(operation=operation):
                token = "a" + format(index, "x")
                roots = [self.root / token]
                receipt = self.registry / "cancelled" / (token + "." + digest(roots) + ".claim")
                receipt.write_bytes(body(roots))
                os.utime(receipt, (1_000_000, 1_000_000))
                before = receipt.stat().st_ino, receipt.read_bytes()
                fence = self.registry / receipt.with_suffix(".cancelling").name
                env = self.barrier_env('if [ "$1" = {} ]; then\n'
                                       '  printf "injected fence fsync failure\\n" >&2\n'
                                       '  exit 91\nfi'.format(shlex.quote(str(fence))))
                # An old receipt-only cancellation must reconstruct its exact
                # fence before either terminal replay can acknowledge success.
                self.assert_unconfirmed(self.transact(token, roots, operation, env=env))
                fence_before = fence.stat().st_ino, fence.read_bytes()
                self.assertEqual(fence_before[1], body(roots))
                other = "b" + format(index, "x")
                other_roots = [self.root / (other + "-other")]
                result = self.transact(other, other_roots, env=env)
                self.assert_granted(result)
                self.assertIn(b"injected fence fsync failure", result.stderr)
                self.assertIn(b"RCH_SOURCE_CLAIM_RETENTION_DEFERRED", result.stderr)
                self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)
                self.assertEqual((fence.stat().st_ino, fence.read_bytes()), fence_before)
                result = self.transact(token, roots, operation)
                self.assert_granted(result)
                self.assertEqual(result.stdout, b"unowned" if operation == "cancel" else b"")
                self.assert_granted(self.transact(other, other_roots, "release"))
                self.assertFalse(receipt.exists())
                self.assertEqual((fence.stat().st_ino, fence.read_bytes()), fence_before)
                self.assert_refused(self.transact(token, roots))
                self.assert_granted(self.transact("c" + format(index, "x"), roots))

    def test_cancelled_receipt_gc_preserves_incomplete_and_conflicting_evidence(self):
        cases = ("missing", "incomplete", "changed", "symlink", "quarantine",
                 "active", "pending", "released", "other-closure", "unknown")
        for index, state in enumerate(cases):
            with self.subTest(state=state):
                token = "a" + format(index, "x")
                roots = [self.root / token]
                receipt = self.registry / "cancelled" / (token + "." + digest(roots) + ".claim")
                receipt.write_bytes(body(roots))
                os.utime(receipt, (1_000_000, 1_000_000))
                fence = self.registry / receipt.with_suffix(".cancelling").name
                if state == "incomplete":
                    fence.write_bytes(b"interrupted marker")
                elif state == "changed":
                    fence.write_bytes(body([self.root / "different-roots"]))
                elif state == "symlink":
                    preserved = self.root / "preserved-fence"
                    preserved.write_bytes(body(roots))
                    fence.symlink_to(preserved)
                elif state == "quarantine":
                    pending = self.registry / "quarantine" / receipt.with_suffix(".pending").name
                    pending.write_bytes(b"interrupted source publication")
                    os.link(pending, fence)
                elif state != "missing":
                    fence.write_bytes(body(roots))
                    if state in ("active", "pending"):
                        self.record(token, roots, "claim" if state == "active" else "pending")
                    elif state == "released":
                        (self.registry / "released" / receipt.name).write_bytes(body(roots))
                    elif state == "other-closure":
                        self.record(token, [self.root / "other-closure"], "cancelling")
                    else:
                        (self.registry / (token + ".unknown")).write_bytes(b"unknown history")
                records = [path for path in self.registry.rglob(token + ".*")
                           if path.is_file() or path.is_symlink()]
                before = {path: (path.lstat().st_ino, path.read_bytes(), path.is_symlink())
                          for path in records}
                self.assert_granted(self.transact("f" + format(index, "x"),
                                                 [self.root / ("gc-trigger-" + token)]))
                self.assertEqual({path: (path.lstat().st_ino, path.read_bytes(), path.is_symlink())
                                  for path in records}, before)
                if state == "quarantine":
                    result = self.transact(token, roots, "settle-cancel")
                    self.assert_granted(result)
                    self.assertEqual(result.stdout, b"settled")
                    self.assert_granted(self.transact("bb", roots))
                    self.assert_refused(self.transact(token, roots))

    def test_cancelled_receipt_gc_bounds_confirmation_work_and_makes_progress(self):
        receipts = []
        fences = {}
        for index in range(40):
            token = format(index, "02x")
            roots = [self.root / token]
            fence = self.record(token, roots, "cancelling")
            fences[fence] = fence.stat().st_ino, fence.read_bytes()
            receipt = self.registry / "cancelled" / fence.with_suffix(".claim").name
            receipt.write_bytes(body(roots))
            os.utime(receipt, (1_000_000, 1_000_000))
            receipts.append(receipt)
        self.assert_granted(self.transact("ff", [self.root / "gc-first"]))
        remaining = [path for path in receipts if path.exists()]
        self.assertGreater(len(remaining), 0, "one admission must not confirm the entire backlog")
        self.assertLess(len(remaining), len(receipts), "verified old receipts should make progress")
        for index in range(len(receipts)):
            if not any(path.exists() for path in receipts):
                break
            token = "fa" + format(index, "x")
            self.assert_granted(self.transact(token, [self.root / ("gc-next-" + token)]))
        self.assertFalse(any(path.exists() for path in receipts))
        self.assertEqual({path: (path.stat().st_ino, path.read_bytes()) for path in fences}, fences)
        self.assert_refused(self.transact("00", [self.root / "00"]))

    def test_released_receipt_gc_preserves_aged_cancellation_contradiction(self):
        token = "aa"
        roots = [self.root / "project"]
        name = token + "." + digest(roots) + ".claim"
        released = self.registry / "released" / name
        cancelled = self.registry / "cancelled" / name
        fence = self.record(token, roots, "cancelling")
        for receipt in (released, cancelled):
            receipt.write_bytes(body(roots))
            os.utime(receipt, (1_000_000, 1_000_000))
        before = {path: (path.stat().st_ino, path.read_bytes())
                  for path in (released, cancelled, fence)}

        # Collection for another job must not erase the released contradiction
        # before the cancellation collector validates this same identity.
        for attempt in range(3):
            self.assert_granted(self.transact("b" + format(attempt, "x"),
                                             [self.root / ("other-project-" + str(attempt))]))
            for path, evidence in before.items():
                self.assertTrue(path.exists(), "contradictory terminal evidence must survive GC")
                self.assertEqual((path.stat().st_ino, path.read_bytes()), evidence)
        for operation in ("acquire", "recover", "cancel", "finish-cancel", "settle-cancel"):
            self.assert_refused(self.transact(token, roots, operation))

    def test_released_receipt_gc_preserves_active_and_unknown_same_identity_evidence(self):
        for index, state in enumerate(("active", "pending", "cancelling", "cancelled",
                                       "quarantine", "released", "unknown",
                                       "unknown-released", "unknown-cancelled", "unknown-quarantine")):
            with self.subTest(state=state):
                token = "a" + format(index, "x")
                roots = [self.root / token]
                receipt = self.registry / "released" / (token + "." + digest(roots) + ".claim")
                receipt.write_bytes(body(roots))
                os.utime(receipt, (1_000_000, 1_000_000))
                if state in ("active", "pending", "cancelling"):
                    conflict = self.record(token, roots, "claim" if state == "active" else state)
                elif state in ("cancelled", "quarantine"):
                    extension = "pending" if state == "quarantine" else "claim"
                    conflict = self.registry / state / (token + "." + digest(roots) + "." + extension)
                    conflict.write_bytes(body(roots))
                elif state == "released":
                    other_roots = [self.root / (token + "-changed")]
                    conflict = self.registry / "released" / (token + "." + digest(other_roots) + ".claim")
                    conflict.write_bytes(body(other_roots))
                else:
                    directory = self.registry if state == "unknown" else self.registry / state[8:]
                    conflict = directory / (token + ".unknown")
                    conflict.write_bytes(b"unknown same-identity evidence")
                before = {path: (path.stat().st_ino, path.read_bytes())
                          for path in (receipt, conflict)}
                for attempt in range(3):
                    self.assert_granted(self.transact("f" + format(index, "x") + str(attempt),
                                                     [self.root / ("gc-trigger-" + token + "-" + str(attempt))]))
                    for path, evidence in before.items():
                        self.assertTrue(path.exists(), "same-identity evidence must survive GC")
                        self.assertEqual((path.stat().st_ino, path.read_bytes()), evidence)

    def test_released_receipts_survive_retention_without_rewriting_evidence(self):
        receipts = []
        activity_locks = {}
        for index in range(40):
            token = format(index, "02x")
            roots = [self.root / token]
            receipt = self.registry / "released" / (token + "." + digest(roots) + ".claim")
            receipt.write_bytes(body(roots))
            os.utime(receipt, (1_000_000, 1_000_000))
            receipts.append(receipt)
            activity = self.registry / (token + ".activity.lock")
            activity.write_bytes(b"retained activity lock inode")
            activity_locks[activity] = activity.stat().st_ino, activity.read_bytes()
        before = {path: (path.stat().st_ino, path.read_bytes()) for path in receipts}
        for token in ("ff", "fa", "fb"):
            self.assert_granted(self.transact(token, [self.root / ("gc-trigger-" + token)]))
        self.assertEqual({path: (path.stat().st_ino, path.read_bytes()) for path in receipts}, before)
        query = self.transact("00", [self.root / "00"], "released")
        self.assert_granted(query)
        self.assertEqual(query.stdout, b"released")
        self.assert_refused(self.transact("00", [self.root / "00"]))
        self.assertEqual({path: (path.stat().st_ino, path.read_bytes())
                          for path in activity_locks}, activity_locks)


@unittest.skipUnless(shutil.which("bash"), "bash is unavailable")
class SourceClaimRegistryBashTests(SourceClaimRegistryTests):
    shell = shutil.which("bash")


@unittest.skipUnless(sys.platform.startswith("linux"), "requires native Linux worker processes")
class TerminalCancellationSettlementTests(unittest.TestCase):
    shell = "/bin/sh"
    record = SourceClaimRegistryTests.record
    transact = SourceClaimRegistryTests.transact
    command = SourceClaimRegistryTests.command
    assert_granted = SourceClaimRegistryTests.assert_granted
    assert_refused = SourceClaimRegistryTests.assert_refused
    tools_env = SourceClaimRegistryTests.tools_env
    barrier_env = SourceClaimRegistryTests.barrier_env
    fail_sync_after_move = SourceClaimRegistryTests.fail_sync_after_move

    def setUp(self):
        SourceClaimRegistryTests.setUp(self)
        self.legacy = self.root / "legacy"
        self.roots = [self.root / "project", self.root / "project/.rch-target"]
        self.coordinator = (REPO / "rch/src/hook/source_cancel_settlement.py").read_text()
        self.control = (REPO / "rch/src/hook/source_namespace_control.sh").read_text()
        self.tmp = self.root / "control"
        self.tmp.mkdir()
        self.env["TMPDIR"] = str(self.tmp)

    def start_settlement(self, token="aa", roots=None, env=None, transaction=None,
                         operation="settle-cancel", expected="current"):
        roots = self.roots if roots is None else roots
        invocation = [sys.executable, "-I", "-S", "-c", self.coordinator,
                      str(self.registry), str(self.legacy), token, digest(roots),
                      transaction or self.script.read_text(), operation, expected]
        program = ("exec " + shlex.join(invocation) + " <<'RCH_SOURCE_CLAIM_ROOTS'\n"
                   + body(roots).decode() + "RCH_SOURCE_CLAIM_ROOTS\n")
        contract = ("RCH_SOURCE_AUTHORITY_NAMESPACE" if operation == "locate"
                    else "RCH_SOURCE_CANCELLATION_SETTLED")
        process = subprocess.Popen([self.shell, "-c", "set -- " + contract + "\n" + self.control],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env or self.env)
        process.stdin.write(program.encode())
        process.stdin.close()
        process.stdin = None
        return process

    def settle(self, **arguments):
        process = self.start_settlement(**arguments)
        stdout, stderr = process.communicate(timeout=25)
        return subprocess.CompletedProcess([], process.returncode, stdout, stderr)

    def locate(self, **arguments):
        return self.settle(operation="locate", expected="", **arguments)

    def make_legacy(self):
        self.legacy.mkdir()
        for name in ("released", "cancelled", "quarantine"):
            (self.legacy / name).mkdir()

    def legacy_transaction(self, operation, token="aa", roots=None):
        roots = self.roots if roots is None else roots
        command = [FLOCK, "--exclusive", *FLOCK_NO_FORK, "--",
                   str(self.legacy / (token + ".activity.lock")),
                   FLOCK, "--exclusive", *FLOCK_NO_FORK, "--",
                   str(self.registry / "metadata.lock"),
                   FLOCK, "--exclusive", *FLOCK_NO_FORK, "--",
                   str(self.legacy / "metadata.lock"), self.shell, str(self.script),
                   str(self.legacy), token, digest(roots), operation]
        return subprocess.run(command, input=body(roots), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              env={**self.env, "RCH_LEGACY_SOURCE_CLAIM_REGISTRY": str(self.registry)},
                              timeout=20, check=False)

    def assert_settled(self, result):
        self.assert_granted(result)
        self.assertEqual(result.stdout, b"RCH_SOURCE_CANCELLATION_SETTLED\n")

    def records(self):
        return {str(path.relative_to(self.root)): (path.stat().st_ino, path.read_bytes())
                for directory in (self.registry, self.legacy) if directory.exists()
                for path in directory.rglob("*")
                if path.is_file() and not path.name.endswith(".lock")}

    def test_active_fenced_claim_settles_and_new_owner_can_enter(self):
        self.assert_granted(self.transact("aa", self.roots))
        self.assertEqual(self.transact("aa", self.roots, "cancel").stdout, b"owned")
        active = self.registry / ("aa." + digest(self.roots) + ".claim")
        before = active.stat().st_ino, active.read_bytes()
        fence = active.with_suffix(".cancelling")
        self.assert_settled(self.settle())
        receipt = self.registry / "cancelled" / active.name
        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)
        self.assertFalse(active.exists())
        self.assertEqual(fence.read_bytes(), body(self.roots))
        self.assert_granted(self.transact("bb", self.roots))
        next_owner = self.registry / ("bb." + digest(self.roots) + ".claim")
        new_bytes = next_owner.read_bytes()
        self.assert_settled(self.settle())
        self.assertEqual(next_owner.read_bytes(), new_bytes)
        self.assert_refused(self.transact("aa", self.roots, "recover"))
        self.assert_refused(self.transact("aa", self.roots, "acquire"))

    def test_marker_only_recovery_never_touches_source_and_keeps_delayed_request_fence(self):
        self.roots[0].mkdir()
        source = self.roots[0] / "keep-source"
        source.write_bytes(b"another owner's source")
        fence = self.record("aa", self.roots, "cancelling")
        before = fence.stat().st_ino, fence.read_bytes()
        self.assert_settled(self.settle())
        self.assertEqual((fence.stat().st_ino, fence.read_bytes()), before)
        self.assertEqual(source.read_bytes(), b"another owner's source")
        self.assert_granted(self.transact("bb", self.roots))
        self.assert_refused(self.transact("aa", self.roots))

    def test_receipt_only_creates_permanent_fence_before_acknowledgement(self):
        receipt = self.registry / "cancelled" / ("aa." + digest(self.roots) + ".claim")
        # Preserve the historical receipt-only frontier: new unowned
        # cancellations now retain their fence before replying.
        receipt.write_bytes(body(self.roots))
        before = receipt.stat().st_ino, receipt.read_bytes()
        self.assert_settled(self.settle())
        self.assertEqual((receipt.stat().st_ino, receipt.read_bytes()), before)
        fence = self.registry / receipt.with_suffix(".cancelling").name
        self.assertEqual(fence.read_bytes(), body(self.roots))
        os.utime(receipt, (1_000_000, 1_000_000))
        self.assert_granted(self.transact("bb", [self.root / "different"]))
        self.assertFalse(receipt.exists(), "exercise real existing receipt retention GC")
        self.assert_refused(self.transact("aa", self.roots))
        self.assert_settled(self.settle())

    def test_missing_or_conflicting_evidence_is_preserved(self):
        for state in ("absent", "active", "pending", "torn-pending", "released",
                      "active-and-cancelled", "quarantine", "wrong-roots", "bad-marker"):
            with self.subTest(state=state):
                self.setUp()
                if state in ("active", "active-and-cancelled"):
                    self.record("aa", self.roots)
                if state in ("pending", "torn-pending"):
                    path = self.record("aa", self.roots, "pending")
                    if state == "torn-pending":
                        path.write_bytes(b"interrupted")
                if state not in ("absent", "active"):
                    marker = self.record("aa", self.roots, "cancelling")
                    if state == "bad-marker":
                        marker.write_bytes(b"incomplete")
                if state in ("released", "active-and-cancelled", "quarantine"):
                    folder = "cancelled" if state == "active-and-cancelled" else state
                    suffix = "pending" if state == "quarantine" else "claim"
                    (self.registry / folder / ("aa." + digest(self.roots) + "." + suffix)).write_bytes(body(self.roots))
                before = self.records()
                result = self.settle(roots=[self.root / "other"] if state == "wrong-roots" else None)
                self.assert_refused(result)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(self.records(), before)

    def test_legacy_registry_settles_exact_owner_but_duplicate_namespaces_refuse(self):
        self.make_legacy()
        marker = self.legacy / ("aa." + digest(self.roots) + ".cancelling")
        marker.write_bytes(body(self.roots))
        self.assert_settled(self.settle(expected="legacy"))
        self.assertTrue((self.legacy / "cancelled" / marker.with_suffix(".claim").name).exists())
        self.assertFalse(list(self.registry.glob("*.claim")))
        self.record("aa", self.roots, "cancelling")
        before = self.records()
        result = self.settle(expected="legacy")
        self.assert_refused(result)
        self.assertIn(b"2 registries contain identity", result.stderr)
        self.assertEqual(self.records(), before)

    def test_legacy_binding_retries_cleanup_in_existing_namespace_without_second_receipt(self):
        self.make_legacy()
        active = self.legacy / ("aa." + digest(self.roots) + ".claim")
        active.write_bytes(body(self.roots))
        before = self.records()
        for _ in range(2):
            result = self.locate()
            self.assert_granted(result)
            self.assertEqual(result.stdout, b"RCH_SOURCE_AUTHORITY_NAMESPACE legacy\n")
            self.assertEqual(self.records(), before, "location grants no cleanup authority")
        result = self.legacy_transaction("cancel")
        self.assert_granted(result)
        self.assertEqual(result.stdout, b"owned")
        self.assertEqual(active.read_bytes(), body(self.roots))
        self.assert_granted(self.legacy_transaction("finish-cancel"))
        self.assert_settled(self.settle(expected="legacy"))
        self.assertFalse(list((self.registry / "cancelled").glob("*")))
        self.assert_refused(self.legacy_transaction("recover"))
        self.assert_granted(self.transact("bb", self.roots,
                           env={**self.env, "RCH_LEGACY_SOURCE_CLAIM_REGISTRY": str(self.legacy)}))

    def test_recorded_namespace_binding_cannot_follow_relocated_evidence(self):
        self.make_legacy()
        (self.legacy / ("aa." + digest(self.roots) + ".cancelling")).write_bytes(body(self.roots))
        before = self.records()
        result = self.settle(expected="current")
        self.assert_refused(result)
        self.assertIn(b"namespace changed from recorded binding", result.stderr)
        self.assertEqual(self.records(), before)

    def test_namespace_locator_preserves_missing_incomplete_and_conflicting_evidence(self):
        for state in ("absent", "pending", "torn", "wrong-roots", "active-and-cancelled",
                      "quarantine", "duplicate", "misplaced", "corrupt-active"):
            with self.subTest(state=state):
                self.setUp()
                if state in ("pending", "torn"):
                    path = self.record("aa", self.roots, "pending")
                    if state == "torn":
                        path.write_bytes(b"interrupted")
                elif state != "absent":
                    path = self.record("aa", self.roots)
                    if state == "corrupt-active":
                        path.write_bytes(b"invalid")
                if state == "active-and-cancelled":
                    (self.registry / "cancelled" / path.name).write_bytes(body(self.roots))
                if state == "quarantine":
                    (self.registry / "quarantine" / path.with_suffix(".pending").name).write_bytes(b"torn")
                if state == "misplaced":
                    (self.registry / "released" / path.with_suffix(".pending").name).write_bytes(body(self.roots))
                if state == "duplicate":
                    self.make_legacy()
                    (self.legacy / path.name).write_bytes(body(self.roots))
                before = self.records()
                result = self.locate(roots=[self.root / "wrong"] if state == "wrong-roots" else None)
                self.assert_refused(result)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(self.records(), before)

    def test_legacy_cleanup_refuses_current_lexical_and_physical_owner(self):
        for physical in (False, True):
            with self.subTest(physical=physical):
                self.setUp()
                self.make_legacy()
                self.roots[0].mkdir()
                other_roots = self.roots
                if physical:
                    alias = self.root / "alias"
                    alias.symlink_to(self.roots[0])
                    other_roots = [alias]
                active = self.legacy / ("aa." + digest(self.roots) + ".claim")
                active.write_bytes(body(self.roots))
                other = self.record("bb", other_roots)
                before = self.records()
                self.assert_granted(self.locate())
                self.assert_refused(self.legacy_transaction("cancel"))
                self.assertEqual(self.records(), before)
                # Terminal metadata reconciliation may coexist with a newer
                # owner only after the caller proves retirement independently.
                active.rename(self.legacy / "cancelled" / active.name)
                self.assert_settled(self.settle(expected="legacy"))
                self.assertEqual(other.read_bytes(), body(other_roots))

    def test_legacy_cleanup_refuses_incomplete_current_publication_without_quarantine(self):
        self.make_legacy()
        (self.legacy / ("aa." + digest(self.roots) + ".claim")).write_bytes(body(self.roots))
        pending = self.record("bb", self.roots, "pending")
        pending.write_bytes(b"interrupted")
        before = self.records()
        self.assert_refused(self.legacy_transaction("cancel"))
        self.assertEqual(self.records(), before)

    def test_misplaced_same_identity_record_is_not_ignored(self):
        for folder, suffix in (("cancelled", "pending"), ("released", "cancelling"),
                               ("quarantine", "claim")):
            with self.subTest(folder=folder):
                self.setUp()
                self.record("aa", self.roots, "cancelling")
                (self.registry / folder / ("aa." + digest(self.roots) + "." + suffix)).write_bytes(body(self.roots))
                before = self.records()
                result = self.settle()
                self.assert_refused(result)
                self.assertIn(b"unrecognized same-identity", result.stderr)
                self.assertEqual(self.records(), before)

    def test_publication_interruption_is_not_acknowledged_and_restart_rechecks_durability(self):
        self.assert_granted(self.transact("aa", self.roots))
        self.assert_granted(self.transact("aa", self.roots, "cancel"))
        receipt = self.registry / "cancelled" / ("aa." + digest(self.roots) + ".claim")
        env = self.fail_sync_after_move(receipt)
        result = self.settle(env=env)
        self.assert_refused(result)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"RCH_SOURCE_REGISTRY_PUBLICATION_UNCONFIRMED", result.stderr)
        before = self.records()
        self.assert_refused(self.settle(env=env))
        self.assertEqual(self.records(), before)
        self.assert_settled(self.settle())
        self.assertEqual(self.records(), before)

    def test_live_activity_refuses_with_bounded_distinct_lock_diagnostic(self):
        self.record("aa", self.roots, "cancelling")
        before = self.records()
        with (self.registry / "aa.activity.lock").open("a") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            started = time.monotonic()
            result = self.settle()
            self.assert_refused(result)
            self.assertIn(b"RCH_SOURCE_SETTLEMENT_LOCK_BUSY", result.stderr)
            self.assertIn(b"elapsed_ms=", result.stderr)
            self.assertLess(time.monotonic() - started, 12)
            self.assertEqual(self.records(), before)
        self.assert_settled(self.settle())

    def test_concurrent_dispatchers_converge_to_one_receipt(self):
        self.record("aa", self.roots, "cancelling")
        processes = [self.start_settlement() for _ in range(3)]
        for process in processes:
            stdout, stderr = process.communicate(timeout=25)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stdout, b"RCH_SOURCE_CANCELLATION_SETTLED\n")
        self.assertEqual(len(list((self.registry / "cancelled").glob("*.claim"))), 1)
        self.assert_refused(self.transact("aa", self.roots))
        self.assert_granted(self.transact("bb", self.roots))

    def test_replaced_or_symlinked_lock_never_creates_split_ownership(self):
        self.record("aa", self.roots, "cancelling")
        lock = self.registry / "metadata.lock"
        with lock.open("a") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            process = self.start_settlement()
            deadline = time.monotonic() + 3
            while not (self.registry / "aa.activity.lock").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            # The old inode remains held; no numeric PID or pathname deletion
            # is used to reclaim it. Replacement must cause refusal, not reuse.
            time.sleep(0.1)
            lock.rename(self.registry / "saved-metadata.lock")
            lock.write_bytes(b"")
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 73, stderr)
            self.assertEqual(stdout, b"")
            self.assertIn(b"lock changed", stderr)
        lock.rename(self.registry / "replacement-metadata.lock")
        lock.symlink_to(self.root / "unrelated")
        result = self.settle()
        self.assert_refused(result)
        self.assertFalse((self.root / "unrelated").exists())
        self.assertFalse(list((self.registry / "cancelled").glob("*.claim")))


@unittest.skipUnless(FLOCK and REALPATH, "native flock and realpath required")
class LegacyGcGuardTests(unittest.TestCase):
    """Exercise the production GC admission gate without removing a tree."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-legacy-gc-"))
        self.current = self.root / "current"
        self.legacy = self.root / "legacy"
        for registry in (self.current, self.legacy):
            registry.mkdir()
            for name in ("released", "cancelled", "quarantine"):
                (registry / name).mkdir()
        self.candidate = self.root / "source-tree"
        self.candidate.mkdir()
        self.sentinel = self.candidate / "source.rs"
        self.sentinel.write_bytes(b"owned source bytes\n")
        retained = HELPER_SOURCE.split(
            'pub const RETAINED_SOURCE_GC_GUARD: &str = r#"', 1)[1].split('"#;', 1)[0]
        gate = HELPER_SOURCE.split(
            'fn source_claim_gate_fragment(registry: &str) -> String {', 1)[1]
        gate = gate.split('const GATE: &str = r#"', 1)[1].split('"#;', 1)[0]
        self.script = "set -u\n" + HELPERS + retained + gate + '''
__gc_source_registry=$1
if __gc_source_begin "$2"; then
    printf 'admitted\n'
    # Keep the fixture's GC claim as evidence. No removal or retirement is
    # needed to determine whether the production gate would allow mutation.
    exit 0
else
    exit "$?"
fi
'''

    def record(self, roots, suffix="claim", folder=None):
        path = (folder or self.legacy) / ("aa." + digest(roots) + "." + suffix)
        path.write_bytes(body(roots))
        return path

    def snapshot(self):
        return {str(path.relative_to(self.legacy)):
                ("link", str(path.readlink())) if path.is_symlink()
                else ("file", path.read_bytes())
                for path in self.legacy.rglob("*")
                if path.is_symlink() or path.is_file()}

    def admit(self):
        before = self.snapshot()
        result = subprocess.run(
            ["/bin/sh", "-c", self.script, "legacy-gc", str(self.current),
             str(self.candidate)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C",
                 "RCH_LEGACY_SOURCE_CLAIM_REGISTRY": str(self.legacy)},
            timeout=20, check=False)
        self.assertEqual(self.snapshot(), before, "legacy evidence must remain read-only")
        self.assertEqual(self.sentinel.read_bytes(), b"owned source bytes\n")
        return result

    def test_malformed_legacy_active_claim_refuses_without_discarding_evidence(self):
        for defect in ("empty", "truncated", "invalid-bytes", "symlink"):
            with self.subTest(defect=defect):
                self.setUp()
                roots = [self.candidate]
                if defect == "symlink":
                    target = self.root / "saved-active-record"
                    target.write_bytes(body(roots))
                    record = self.legacy / ("aa." + digest(roots) + ".claim")
                    record.symlink_to(target)
                else:
                    record = self.record(roots)
                    record.write_bytes({"empty": b"", "truncated": body(roots)[:-1],
                                        "invalid-bytes": b"\xff\x00\n"}[defect])
                result = self.admit()
                self.assertEqual(result.returncode, 2, (defect, result.stdout, result.stderr))
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"RCH_GC_LEGACY_SOURCE_OWNERSHIP_UNKNOWN", result.stderr)
                self.assertIn(os.fsencode(record), result.stderr)

    def test_live_legacy_claim_and_activity_hold_candidate(self):
        self.record([self.candidate])
        with (self.legacy / "aa.activity.lock").open("a") as activity:
            fcntl.flock(activity, fcntl.LOCK_EX)
            result = self.admit()
            self.assertEqual((result.returncode, result.stdout), (1, b""), result.stderr)

    def test_complete_legacy_pending_record_holds_candidate(self):
        self.record([self.candidate], "pending")
        result = self.admit()
        self.assertEqual((result.returncode, result.stdout), (1, b""), result.stderr)

    def test_valid_disjoint_legacy_claim_allows_candidate(self):
        self.record([self.root / "other-project"])
        result = self.admit()
        self.assertEqual((result.returncode, result.stdout), (0, b"admitted\n"), result.stderr)

    def test_terminal_fences_and_incomplete_pending_do_not_grant_legacy_activity(self):
        roots = [self.candidate]
        self.record(roots, "cancelling")
        self.record(roots, folder=self.legacy / "cancelled")
        self.record(roots, "pending").write_bytes(b"interrupted publication")
        result = self.admit()
        self.assertEqual((result.returncode, result.stdout), (0, b"admitted\n"), result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
