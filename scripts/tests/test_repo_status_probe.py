#!/usr/bin/env python3
"""Exercise the production shell census with real Git and retained fixtures.

No SSH, installed worker, daemon, compiler or user repository is contacted.
The reference path invokes the former per-root Git status in the same test.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "rch/src/hook/repo_updater/status_probe.sh"
GIT = shutil.which("git")


def request(roots):
    encoded = [b"".join(("\\0%03o" % byte).encode() for byte in os.fsencode(root))
               for root in roots]
    return b"RCH_REPO_STATUS_REQUEST_V1\n" + b"".join(line + b"\n" for line in encoded) + b"RCH_REPO_STATUS_REQUEST_END\n"


def response(result, count):
    if result.returncode:
        raise AssertionError((result.returncode, result.stdout, result.stderr))
    lines = result.stdout.decode("ascii").splitlines()
    assert lines[0] == "RCH_REPO_STATUS_V1", lines
    assert lines[-1] == "RCH_REPO_STATUS_END %d" % count, lines
    assert len(lines) == count + 2, lines
    states = []
    for index, line in enumerate(lines[1:-1]):
        number, state = line.split(" ")
        assert number == str(index) and state in ("clean", "dirty", "unavailable"), line
        states.append(state)
    return states


class RepoStatusProbeTests(unittest.TestCase):
    shell = "/bin/sh"

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-status-census-"))
        self.home = self.root / "home"
        self.home.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("GIT_")}
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home), LC_ALL="C")
        self.trace = self.root / "status-calls"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        wrapper = self.tools / "git"
        wrapper.write_text("#!/bin/sh\nfor arg do\n"
                           " case \"$arg\" in status) printf 'status\\n' >> \"$STATUS_TRACE\";; esac\n"
                           "done\nexec " + shlex.quote(GIT) + ' "$@"\n')
        wrapper.chmod(0o700)
        self.env.update(PATH=str(self.tools) + os.pathsep + self.env["PATH"],
                        STATUS_TRACE=str(self.trace))

    def git(self, root, *args):
        return subprocess.run([GIT, "-C", os.fspath(root), *args], env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=True, timeout=10)

    def repository(self, name="repo"):
        root = self.root / name
        root.mkdir()
        self.git(root, "init", "-q")
        self.git(root, "config", "user.name", "RCH fixture")
        self.git(root, "config", "user.email", "fixture@invalid")
        (root / "tracked").write_bytes(b"original\n")
        (root / ".gitignore").write_text("ignored*\n")
        self.git(root, "add", "--all")
        self.git(root, "commit", "-qm", "fixture")
        return root

    def probe(self, roots=(), payload=None, env=None):
        return subprocess.run([self.shell, str(SCRIPT)], input=request(roots) if payload is None else payload,
                              env=env or self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=10, check=False)

    def reference(self, roots, env=None):
        results = []
        for root in roots:
            run = subprocess.run(["git", "-C", os.fspath(root), "status", "--porcelain"],
                                 env={**(env or self.env), "GIT_OPTIONAL_LOCKS": "0"},
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=10, check=False)
            results.append("unavailable" if run.returncode else "dirty" if run.stdout.strip() else "clean")
        return results

    def calls(self):
        return len(self.trace.read_text().splitlines()) if self.trace.exists() else 0

    def test_nested_worktree_scans_once_with_same_live_reference_results(self):
        root = self.repository()
        roots = [root / ("member-%d" % index) for index in range(17)]
        for path in roots:
            path.mkdir()
        expected = self.reference(roots)
        baseline_calls = self.calls()
        actual = response(self.probe(roots), len(roots))
        self.assertEqual(expected, ["clean"] * 17)
        self.assertEqual(actual, expected)
        self.assertEqual(baseline_calls, 17)
        self.assertEqual(self.calls() - baseline_calls, 1)

    def test_dirt_anywhere_in_worktree_is_reported_for_all_members(self):
        root = self.repository()
        roots = [root / "a", root / "b"]
        for path in roots:
            path.mkdir()
        for name, stage in [("untracked", False), ("tracked", False), ("tracked", True)]:
            with self.subTest(name=name, stage=stage):
                (root / name).write_bytes(b"changed\n")
                if stage:
                    self.git(root, "add", "tracked")
                expected = self.reference(roots)
                before = self.calls()
                self.assertEqual(response(self.probe(roots), 2), expected)
                self.assertEqual(expected, ["dirty", "dirty"])
                self.assertEqual(self.calls() - before, 1)

    def test_ignored_paths_do_not_make_worktree_dirty(self):
        root = self.repository()
        (root / "ignored-output").write_text("not a source change")
        self.assertEqual(response(self.probe([root]), 1), self.reference([root]))
        self.assertEqual(self.reference([root]), ["clean"])

    def test_separate_repositories_and_linked_worktrees_stay_independent(self):
        root = self.repository()
        other = self.repository("other")
        linked = self.root / "linked"
        self.git(root, "worktree", "add", "--detach", str(linked), "HEAD")
        (linked / "tracked").write_bytes(b"linked only\n")
        roots = [root, other, linked, root, linked]
        expected = self.reference(roots)
        before = self.calls()
        self.assertEqual(response(self.probe(roots), len(roots)), expected)
        self.assertEqual(expected, ["clean", "clean", "dirty", "clean", "dirty"])
        self.assertEqual(self.calls() - before, 3)

    def test_missing_bare_and_nonrepositories_are_never_clean(self):
        root = self.repository()
        empty = self.root / "empty"
        empty.mkdir()
        bare = self.root / "bare"
        bare.mkdir()
        self.git(bare, "init", "--bare", "-q")
        roots = [empty, self.root / "missing", bare, root]
        self.assertEqual(response(self.probe(roots), len(roots)), self.reference(roots))
        self.assertEqual(self.reference(roots), ["unavailable"] * 3 + ["clean"])

    def test_opaque_paths_quotes_globs_and_trailing_newlines_roundtrip(self):
        root = self.repository("repo quote' [*]\\\n\n")
        odd = os.fsencode(root) + b"/member-\xff-\n"
        os.mkdir(odd)
        roots = [root, odd]
        expected = self.reference(roots)
        before = self.calls()
        self.assertEqual(response(self.probe(roots), 2), expected)
        self.assertEqual(expected, ["clean", "clean"])
        self.assertEqual(self.calls() - before, 1)
        with open(odd + b"/changed\nRCH_GIT_STATUS_SUCCESS", "wb") as stream:
            stream.write(b"source")
        self.assertEqual(response(self.probe(roots), 2), ["dirty", "dirty"])

    def test_symbolic_aliases_share_the_same_worktree_scan(self):
        root = self.repository()
        alias = self.root / "alias"
        alias.symlink_to(root, target_is_directory=True)
        before = self.calls()
        self.assertEqual(response(self.probe([alias, root]), 2), ["clean", "clean"])
        self.assertEqual(self.calls() - before, 1)

    def test_memo_never_survives_a_request(self):
        root = self.repository()
        self.assertEqual(response(self.probe([root, root]), 2), ["clean", "clean"])
        (root / "tracked").write_bytes(b"next request changed\n")
        self.assertEqual(response(self.probe([root, root]), 2), ["dirty", "dirty"])
        self.assertEqual(self.calls(), 2)

    def test_git_environment_overrides_disable_cross_root_memoization(self):
        root = self.repository()
        sub = root / "member"
        sub.mkdir()
        env = {**self.env, "GIT_INDEX_FILE": str(root / ".git/index")}
        before = self.calls()
        self.assertEqual(response(self.probe([root, sub], env=env), 2), self.reference([root, sub], env))
        self.assertEqual(self.calls() - before, 4)

    def test_request_framing_and_encoding_errors_never_acknowledge_completion(self):
        root = self.repository()
        valid = request([root])
        for payload in [b"", valid.replace(b"REQUEST_V1", b"REQUEST_V2"),
                        valid[:valid.index(b"RCH_REPO_STATUS_REQUEST_END")],
                        valid + b"suffix", valid + b"\n", request([root] * 65),
                        request(["relative"]), request([b"/nul\x00path"]),
                        b"RCH_REPO_STATUS_REQUEST_V1\n\\c\nRCH_REPO_STATUS_REQUEST_END\n"]:
            with self.subTest(payload=payload[:90]):
                result = self.probe(payload=payload)
                self.assertEqual(result.returncode, 73, (result.stdout, result.stderr))
                self.assertNotIn(b"RCH_REPO_STATUS_END", result.stdout)

    def test_empty_and_maximum_batches_have_exact_denominators(self):
        self.assertEqual(response(self.probe(), 0), [])
        root = self.repository()
        self.assertEqual(response(self.probe([root] * 64), 64), ["clean"] * 64)
        self.assertEqual(self.calls(), 1)

    def test_failed_status_is_not_memoized_or_misreported_as_clean(self):
        root = self.repository()
        wrapper = self.tools / "git"
        wrapper.write_text("#!/bin/sh\nfor arg do\n"
                           " case \"$arg\" in status) printf 'call\\n' >> \"$STATUS_TRACE\"; "
                           "printf ' M tracked\\n'; exit 1;; esac\ndone\n"
                           "exec " + shlex.quote(GIT) + ' "$@"\n')
        self.assertEqual(response(self.probe([root, root]), 2), ["unavailable", "unavailable"])
        self.assertEqual(self.calls(), 2)

    def test_incomplete_or_failed_octet_encoder_refuses_before_reuse(self):
        root = self.repository()
        for program in ["exit 1", "exit 0", "printf '2f 61'; exit 1", "printf '2f 61'", "printf '*' "]:
            tool = self.tools / "od"
            tool.write_text("#!/bin/sh\n" + program + "\n")
            tool.chmod(0o700)
            result = self.probe([root, root])
            self.assertEqual(result.returncode, 73)
            self.assertNotIn(b"RCH_REPO_STATUS_END", result.stdout)

    def test_read_only_census_preserves_source_and_git_index_bytes(self):
        root = self.repository()
        (root / "tracked").write_bytes(b"uncommitted content\n")
        self.git(root, "add", "tracked")
        before = {path.relative_to(root): path.read_bytes()
                  for path in root.rglob("*") if path.is_file()}
        self.assertEqual(response(self.probe([root] * 17), 17), ["dirty"] * 17)
        after = {path.relative_to(root): path.read_bytes()
                 for path in root.rglob("*") if path.is_file()}
        self.assertEqual(after, before)

    def test_failed_status_reducer_never_acknowledges_a_partial_census(self):
        root = self.repository()
        real_awk = shutil.which("awk")
        for program in ["exit 1", "exit 0", "printf clean; exit 1", "printf 'clean\\ndirty\\n'"]:
            tool = self.tools / "awk"
            tool.write_text("#!/bin/sh\ncase \"$1\" in *RCH_GIT_STATUS_SUCCESS*) "
                            + program + ";; *) exec " + shlex.quote(real_awk) + ' "$@";; esac\n')
            tool.chmod(0o700)
            result = self.probe([root])
            self.assertEqual(result.returncode, 73, (result.stdout, result.stderr))
            self.assertNotIn(b"RCH_REPO_STATUS_END", result.stdout)


@unittest.skipUnless(shutil.which("bash"), "Bash unavailable")
class RepoStatusProbeBashTests(RepoStatusProbeTests):
    shell = shutil.which("bash")


if __name__ == "__main__":
    unittest.main(verbosity=2)
