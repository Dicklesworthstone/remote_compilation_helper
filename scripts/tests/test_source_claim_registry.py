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
# util-linux flock can exec the command in place; the BSD port Homebrew ships
# on macOS has no --no-fork and always runs it as a child.
FLOCK_NO_FORK = ["--no-fork"] if FLOCK and b"util-linux" in subprocess.run(
    [FLOCK, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    check=False).stdout else []
AWK = shutil.which("awk")
REALPATH = shutil.which("realpath")
SYNC = shutil.which("sync")


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
        # Real writes and renames run. Only sync reports an injected failure
        # after the destination appears: the lost-durability-ack frontier.
        return self.tool_env("sync", 'if [ -e {} ]; then\n'
                             '  printf "injected post-rename sync failure\\n" >&2\n'
                             '  exit 91\nfi\nexec {} "$@"'.format(
                                 shlex.quote(str(destination)), shlex.quote(SYNC)))

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
                env = self.tool_env("sync", 'if [ "$2" = {} ]; then exit 91; fi\n'
                                    'exec {} "$@"'.format(shlex.quote(str(path)), shlex.quote(SYNC)))
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


@unittest.skipUnless(shutil.which("bash"), "bash is unavailable")
class SourceClaimRegistryBashTests(SourceClaimRegistryTests):
    shell = shutil.which("bash")


if __name__ == "__main__":
    unittest.main(verbosity=2)
