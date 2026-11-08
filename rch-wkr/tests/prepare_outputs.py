#!/usr/bin/env python3
"""Exact output provenance through the compiled worker's proof CLI.

The isolated package managers are deterministic lifecycle fixtures, not a
claim of fleet or registry acceptance. All transaction, inventory, hashing,
publication and installer-descendant logic is the actual worker binary.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location(
    "rch_prepare_fixture", Path(__file__).with_name("prepare_transactions.py")
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

EXTRA_OUTPUTS = r'''
mkdir -p node_modules/pkg/empty node_modules/.bin
printf 'module.exports = 1;\n' > node_modules/pkg/index.js
ln -s ../pkg/index.js node_modules/.bin/fixture-tool
if [ "${RCH_PROOF_WORKSPACE-}" = 1 ]; then
    mkdir -p packages/a/node_modules/member
    printf 'workspace dependency\n' > packages/a/node_modules/member/index.js
fi
if [ "${RCH_PROOF_MUTATE_SELECTED-}" = 1 ]; then
    printf 'changed selected bytes\n' > node_modules/pinned.txt
fi
if [ "${RCH_PROOF_ESCAPE-}" = 1 ]; then
    ln -s "$RCH_PROOF_OUTSIDE" node_modules/escaped
fi
'''


class PreparedOutputs(fixture.PrepareTransactions):
    def setUp(self):
        super().setUp()
        (self.bin / "ln").symlink_to(shutil.which("ln"))
        for name in ("npm", "bun", "pnpm", "yarn"):
            (self.bin / name).write_text(fixture.NPM + EXTRA_OUTPUTS)

    def request(self, project, paths=None, *, source=None, attempt="attempt-1"):
        source = project if source is None else source
        if paths is None:
            paths = ["package.json", "package-lock.json"]
        files = []
        directories = set()
        prefix = project.relative_to(source).as_posix()
        if prefix == ".":
            prefix = ""
        for project_path in paths:
            path = project / project_path
            relative = path.relative_to(source).as_posix()
            metadata = path.lstat()
            target = os.readlink(path) if path.is_symlink() else None
            data = target.encode() if target is not None else path.read_bytes()
            files.append({
                "path": relative,
                "kind": "symlink" if target is not None else "regular",
                "sha256": hashlib.sha256(data).hexdigest(),
                "byte_count": len(data),
                "executable": bool(metadata.st_mode & 0o111) if target is None else False,
                "symlink_target": target,
            })
            parent = Path(relative).parent
            while parent != Path("."):
                directories.add(parent.as_posix())
                parent = parent.parent
        return {
            "schema_version": 1, "attempt_id": attempt,
            "source_owner": "12345678-1234-1234-1234-123456789abc",
            "build_id": "12345", "command_sha256": "a" * 64,
            "source_content_root": "b" * 64, "source_root": str(source),
            "project_relative": prefix, "files": sorted(files, key=lambda item: item["path"]),
            "directories": sorted(directories),
        }

    def proof(self, project, state, request, *, mode="install", manager="npm",
              runtime="node", install_mode="immediate", extra_env=None):
        env = {
            "PATH": str(self.bin), "HOME": str(self.home), "LC_ALL": "C",
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_STATE_HOME": str(self.home / ".local/state"),
            "TOKIO_WORKER_THREADS": "2", "RCH_PREPARE_INSTALL_TIMEOUT_SECS": "20",
            "RCH_PREPARE_TEST_STATE": str(state), "RCH_PREPARE_TEST_MODE": install_mode,
            "RCH_PREPARE_EXPECT_MANAGER": manager,
            "RCH_PREPARE_EXPECT_PLAN": "ci" if manager == "npm" else "frozen",
            "RCH_PREPARE_TEST_NEW_LOCK": "",
        }
        if extra_env:
            env.update(extra_env)
        child = subprocess.Popen(
            [fixture.WORKER, "prepare-proof", "--mode", mode,
             "--project", str(project), "--runtime", runtime],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.children.append(child)
        child.stdin.write(json.dumps(request).encode())
        child.stdin.close()
        child.stdin = None
        return child

    def completed_records(self):
        return sorted((self.home / ".cache/rch/prepare-transactions").glob("*.outputs-v1.json"))

    def accepted(self, child):
        output, error = child.communicate(timeout=8)
        self.assertEqual(child.returncode, 0, (output, error))
        return json.loads(output)

    def refused(self, child, reason=None):
        output, error = child.communicate(timeout=8)
        self.assertNotEqual(child.returncode, 0, (output, error))
        self.assertEqual(output, b"", "refusal must not publish partial success JSON")
        if reason is not None:
            self.assertIn(reason, error.decode(), error)
        return error

    def test_fresh_and_retained_inventory_covers_files_links_and_empty_directories(self):
        project, state = self.project("fresh")
        request = self.request(project)
        self.assertIsNone(self.accepted(self.proof(project, state, request, mode="inspect")))
        first = self.accepted(self.proof(project, state, request))
        self.assertEqual(first["disposition"], "fresh")
        inventory = first["state"]["inventory"]
        self.assertIn("node_modules/pkg/empty", inventory["directories"])
        link, = [entry for entry in inventory["files"] if entry["kind"] == "symlink"]
        self.assertEqual(link["path"], "node_modules/.bin/fixture-tool")
        self.assertEqual(link["symlink_target"], "../pkg/index.js")
        self.assertEqual(self.accepted(self.proof(project, state, request, mode="inspect")), first["state"])
        second_request = copy.deepcopy(request)
        second_request["attempt_id"] = "attempt-2"
        second = self.accepted(self.proof(project, state, second_request))
        self.assertEqual(second["disposition"], "retained")
        self.assertEqual(first["state"], second["state"])
        self.assertNotEqual(first["request_digest"], second["request_digest"])
        self.assertEqual(self.events(state), ["install"])
        self.assertEqual(self.journals()[0].read_bytes(), fixture.IDLE)
        completed = json.loads(self.completed_records()[0].read_bytes())
        self.assertEqual(completed, {"request": second_request, "attestation": second})

    def test_fresh_selected_node_modules_are_preserved_and_never_owned_as_outputs(self):
        project, state = self.project("selected", lock="bun.lock")
        (project / "node_modules").mkdir()
        selected = project / "node_modules/pinned.txt"
        selected.write_text("selected archive bytes\n")
        request = self.request(project, ["package.json", "bun.lock", "node_modules/pinned.txt"])
        original = selected.read_bytes()
        first = self.accepted(self.proof(project, state, request, manager="bun", runtime="bun"))
        self.assertEqual(selected.read_bytes(), original)
        self.assertNotIn("node_modules/pinned.txt", [entry["path"] for entry in first["state"]["inventory"]["files"]])
        self.assertNotIn("node_modules", first["state"]["inventory"]["directories"])
        self.assertEqual(self.invocations(state), ["bun", "2", "install", "--frozen-lockfile"])
        selected.write_text("planted archive bytes\n")
        self.refused(self.proof(project, state, request, mode="inspect"), "selected source changed")
        self.assertEqual(self.events(state), ["install"])

    def test_legacy_fingerprint_and_idle_journal_cannot_adopt_retained_additions(self):
        project, state = self.project("legacy")
        request = self.request(project)
        self.assertEqual(self.report(self.start(project, state), 0)["action"], "Installed")
        for mode in ("inspect", "install"):
            self.refused(self.proof(project, state, request, mode=mode), "no completed ownership record")
        self.assertEqual(self.events(state), ["install"])
        self.assertFalse(self.completed_records())
        self.assertEqual(self.journals()[0].read_bytes(), fixture.IDLE)

    def test_selected_only_baseline_with_legacy_stamp_still_runs_a_fresh_installer(self):
        project, state = self.project("selected-legacy")
        self.assertEqual(self.report(self.start(project, state), 0)["action"], "Installed")
        # This new request independently selects every existing dependency
        # entry; the legacy stamp still cannot authorize a Skipped attestation.
        paths = ["package.json", "package-lock.json", "node_modules/fixture-dependency",
                 "node_modules/pkg/index.js", "node_modules/.bin/fixture-tool"]
        request = self.request(project, paths)
        request["directories"].append("node_modules/pkg/empty")
        request["directories"].sort()
        # The fixture manager recreates its symlink, so use a manager that
        # preserves selected source while producing a different new output.
        (self.bin / "npm").write_text("#!/bin/sh\nset -eu\n[ \"$#\" = 1 ] && [ \"$1\" = ci ]\nprintf 'install\\n' >> \"$RCH_PREPARE_TEST_STATE/events\"\nprintf 'new output\\n' > node_modules/new-output\n")
        accepted = self.accepted(self.proof(project, state, request))
        self.assertEqual(accepted["disposition"], "fresh")
        self.assertEqual([entry["path"] for entry in accepted["state"]["inventory"]["files"]], ["node_modules/new-output"])
        self.assertEqual(self.events(state), ["install", "install"])

    def test_registered_content_mode_missing_entry_and_new_empty_directory_are_checked(self):
        for kind in ("bytes", "mode", "missing", "extra", "empty-directory"):
            with self.subTest(kind=kind):
                project, state = self.project("tamper-" + kind)
                request = self.request(project)
                self.accepted(self.proof(project, state, request))
                path = project / "node_modules/fixture-dependency"
                if kind == "bytes":
                    path.write_bytes(b"tampered\n")
                elif kind == "mode":
                    path.chmod(0o700)
                elif kind == "missing":
                    path.rename(self.root / ("retained-" + kind))
                elif kind == "extra":
                    (project / "node_modules/unregistered.js").write_text("planted\n")
                else:
                    (project / "node_modules/unregistered-empty").mkdir()
                self.refused(self.proof(project, state, request, mode="inspect"), "inventory changed")
                self.refused(self.proof(project, state, request), "inventory changed")
                self.assertEqual(self.events(state), ["install"])

    def test_installer_selected_mutation_and_escape_links_keep_running_fence(self):
        for kind in ("selected", "escape"):
            with self.subTest(kind=kind):
                project, state = self.project("unsafe-" + kind)
                paths = ["package.json", "package-lock.json"]
                extra = {}
                if kind == "selected":
                    (project / "node_modules").mkdir()
                    (project / "node_modules/pinned.txt").write_text("selected\n")
                    paths.append("node_modules/pinned.txt")
                    extra["RCH_PROOF_MUTATE_SELECTED"] = "1"
                else:
                    outside = self.root / "outside"
                    outside.write_text("retain outside bytes\n")
                    extra.update(RCH_PROOF_ESCAPE="1", RCH_PROOF_OUTSIDE=str(outside))
                request = self.request(project, paths)
                self.refused(self.proof(project, state, request, extra_env=extra))
                self.refused(self.proof(project, state, request), "interrupted or invalid transaction")
                self.assertFalse(self.completed_records())
                self.assertEqual(self.events(state), ["install"])
        self.assertTrue(all(path.read_bytes() == fixture.RUNNING for path in self.journals()))

    def test_subproject_and_workspace_outputs_use_exact_selected_root_paths(self):
        source = self.root / "source"
        source.mkdir()
        project = source / "vittles"
        project.mkdir()
        state = self.root / "nested-state"
        state.mkdir()
        self.states.append(state)
        (project / "package.json").write_text('{"workspaces":["packages/*"]}')
        (project / "package-lock.json").write_text('{"lockfileVersion":3}')
        member = project / "packages/a"
        member.mkdir(parents=True)
        (member / "package.json").write_text('{"name":"member"}')
        request = self.request(project, ["package.json", "package-lock.json", "packages/a/package.json"], source=source)
        accepted = self.accepted(self.proof(project, state, request, extra_env={"RCH_PROOF_WORKSPACE": "1"}))
        files = [entry["path"] for entry in accepted["state"]["inventory"]["files"]]
        self.assertIn("vittles/packages/a/node_modules/member/index.js", files)
        self.assertTrue(all(path.startswith("vittles/") for path in files))
        self.assertEqual(self.accepted(self.proof(project, state, request, mode="inspect")), accepted["state"])

    def test_input_change_requires_a_new_frozen_install_but_inspect_preserves_ownership(self):
        project, state = self.project("new-input")
        request = self.request(project)
        first = self.accepted(self.proof(project, state, request))
        (project / "package.json").write_text('{"name":"changed","version":"2.0.0"}')
        current_request = self.request(project, attempt="new-input-attempt")
        self.assertEqual(self.accepted(self.proof(project, state, current_request, mode="inspect")), first["state"])
        # Permit deterministic replacement of an already owned .bin symlink.
        (self.bin / "npm").write_text(fixture.NPM)
        second = self.accepted(self.proof(project, state, current_request))
        self.assertEqual(second["disposition"], "fresh")
        self.assertNotEqual(second["state"]["input_fingerprint"], first["state"]["input_fingerprint"])
        self.assertEqual(self.events(state), ["install", "install"])

    def test_interrupted_install_cannot_publish_or_reuse_completed_state(self):
        project, state = self.project("interrupted")
        request = self.request(project)
        child = self.proof(project, state, request, install_mode="blocked")
        fixture.eventually(lambda: (state / "started").exists(), "installer did not start")
        self.assertEqual(self.journals()[0].read_bytes(), fixture.RUNNING)
        self.assertFalse(self.completed_records())
        child.kill()
        child.communicate(timeout=5)
        (state / "release").write_text("release\n")
        self.refused(self.proof(project, state, request, mode="inspect"), "interrupted or invalid transaction")
        self.refused(self.proof(project, state, request), "interrupted or invalid transaction")
        self.assertFalse(self.completed_records())
        self.assertEqual(self.events(state), ["install"])

    def test_success_receipt_waits_for_lifecycle_descendant_output(self):
        project, state = self.project("descendant-proof")
        request = self.request(project)
        child = self.proof(project, state, request, install_mode="descendants",
                           extra_env={"RCH_PREPARE_TEST_LEADER_EXIT": "0"})
        self.release_installer_leader(child, state)
        with self.assertRaises(subprocess.TimeoutExpired):
            child.communicate(timeout=0.2)
        self.assertFalse(self.completed_records())
        self.assertEqual(self.journals()[0].read_bytes(), fixture.RUNNING)
        (state / "release").write_text("release\n")
        accepted = self.accepted(child)
        output, = accepted["state"]["inventory"]["files"]
        self.assertEqual(output["sha256"], hashlib.sha256(b"descendant output\n").hexdigest())
        self.assertTrue((state / "descendant-finished").exists())

    def test_corrupt_linked_or_public_completed_record_is_not_reconstructed(self):
        for kind in ("corrupt", "linked", "public", "symlink"):
            with self.subTest(kind=kind):
                project, state = self.project("record-" + kind)
                request = self.request(project)
                before = set(self.completed_records())
                self.accepted(self.proof(project, state, request))
                record, = set(self.completed_records()) - before
                if kind == "corrupt":
                    record.write_text('{"request":')
                elif kind == "linked":
                    os.link(record, self.root / (kind + "-receipt"))
                elif kind == "public":
                    record.chmod(0o644)
                else:
                    retained = self.root / (kind + "-receipt")
                    record.rename(retained)
                    record.symlink_to(retained)
                self.refused(self.proof(project, state, request, mode="inspect"))
                self.refused(self.proof(project, state, request))
                self.assertEqual(self.events(state), ["install"])

    def test_replaced_project_inode_cannot_reuse_identical_retained_bytes(self):
        project, state = self.project("replacement")
        request = self.request(project)
        self.accepted(self.proof(project, state, request))
        retained = self.root / "original-project"
        project.rename(retained)
        shutil.copytree(retained, project, symlinks=True)
        self.refused(self.proof(project, state, request, mode="inspect"), "project inode changed")
        self.assertEqual(self.events(state), ["install"])

    def test_unlocked_proof_request_refuses_before_starting_an_installer(self):
        project, state = self.project("unlocked", lock=None)
        request = self.request(project, ["package.json"])
        self.refused(self.proof(project, state, request), "requires a selected frozen lockfile")
        self.assertEqual(self.events(state), [])
        self.assertFalse(self.completed_records())
        self.assertEqual(self.journals()[0].read_bytes(), b"")


if __name__ == "__main__":
    if fixture.WORKER is None or not Path(fixture.WORKER).is_file():
        raise SystemExit("usage: prepare_outputs.py /absolute/path/to/rch-wkr")
    names = sorted(name for name in PreparedOutputs.__dict__ if name.startswith("test_"))
    suite = unittest.TestSuite(PreparedOutputs(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
