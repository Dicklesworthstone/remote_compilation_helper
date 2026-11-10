#!/usr/bin/env python3
"""Exact output provenance through the compiled worker's proof CLI.

The isolated package managers are deterministic lifecycle fixtures, not a
claim of fleet or registry acceptance. All transaction, inventory, hashing,
publication and installer-descendant logic is the actual worker binary.

Pass the compiled worker as the only argument. Verification uses real BLAKE3:
set RCH_TEST_BLAKE3 to a stdin-to-hex executable, install b3sum, or retain the
worker's Cargo dependency artifacts and a matching rustc (optionally RUSTC).
The last option compiles a small hasher against the already-built blake3 crate;
it neither downloads dependencies nor substitutes a Python hash implementation.
RCH_TEST_REAL_NPM=1 additionally requires npm and Node for an offline workspace
install and consumer run with only local dependencies.
"""

import copy
import functools
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "rch_prepare_fixture", Path(__file__).with_name("prepare_transactions.py")
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

BLAKE3_HELPER = r'''
use std::io::Read;
fn main() -> std::io::Result<()> {
    let mut input = std::io::stdin().lock();
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    println!("{}", hasher.finalize().to_hex());
    Ok(())
}
'''


@functools.cache
def blake3_command():
    explicit = os.environ.get("RCH_TEST_BLAKE3") or shutil.which("b3sum")
    if explicit:
        return [explicit]
    profile = Path(fixture.WORKER).parent
    if profile.name == "deps":
        profile = profile.parent
    artifacts = sorted(
        [*profile.glob("deps/libblake3-*.rlib"),
         *profile.glob("build/blake3/*/out/libblake3-*.rlib")],
        key=lambda path: path.stat().st_mtime_ns, reverse=True,
    )
    rustc = os.environ.get("RUSTC") or shutil.which("rustc")
    if not rustc or not artifacts:
        raise RuntimeError("verification needs RCH_TEST_BLAKE3, b3sum, or matching "
                           "rustc and the candidate worker's built blake3 artifact")
    helper = Path(tempfile.mkdtemp(prefix="rch-proof-blake3-")) / "hasher"
    directories = [profile / "deps", *sorted(profile.glob("build/*/*/out"))]
    search = [argument for path in directories if path.is_dir()
              for argument in ("-L", "dependency=" + str(path))]
    diagnostic = b""
    # A target may contain a few artifacts from previous build flags. Try at
    # most four, newest first; mismatched compiler/dependency sets fail clearly.
    for artifact in artifacts[:4]:
        extern = ["--extern", "blake3=" + str(artifact)]
        metadata = artifact.with_suffix(".rmeta")
        if metadata.is_file():
            # Cargo can emit the archive and its metadata separately.
            extern.extend(["--extern", "blake3=" + str(metadata)])
        result = subprocess.run(
            [rustc, "--edition=2024", "--crate-name=rch_proof_blake3", "-C", "debuginfo=0",
             *search, *extern, "-o", str(helper), "-"],
            input=BLAKE3_HELPER.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30,
        )
        if result.returncode == 0:
            return [str(helper)]
        diagnostic = result.stderr
    raise RuntimeError("cannot build the verification BLAKE3 helper; set RCH_TEST_BLAKE3: "
                       + diagnostic.decode(errors="replace")[-2000:])


def blake3_digest(data):
    result = subprocess.run(blake3_command(), input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=8, check=True)
    words = result.stdout.decode("ascii").split()
    if not words or len(words[0]) != 64 or any(c not in "0123456789abcdef" for c in words[0]):
        raise RuntimeError("BLAKE3 helper did not return a 64-character lowercase hex digest")
    return words[0]


EXTRA_OUTPUTS = r'''
pwd > "$RCH_PREPARE_TEST_STATE/install-cwd"
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

    def request(self, project, paths=None, *, source=None, preparation=None, attempt="attempt-1"):
        inputs = project if preparation is None else preparation
        source = inputs if source is None else source
        if paths is None:
            paths = ["package.json", "package-lock.json"]
        files = []
        directories = set()
        prefix = project.relative_to(source).as_posix()
        if prefix == ".":
            prefix = ""
        for project_path in paths:
            path = inputs / project_path
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
        invocation = Path(prefix)
        while invocation != Path("."):
            directories.add(invocation.as_posix())
            invocation = invocation.parent
        request = {
            "schema_version": 1, "attempt_id": attempt,
            "source_owner": "12345678-1234-1234-1234-123456789abc",
            "build_id": "12345", "command_sha256": "a" * 64,
            "source_content_root": "b" * 64, "source_root": str(source),
            "project_relative": prefix, "files": sorted(files, key=lambda item: item["path"]),
            "directories": sorted(directories),
        }
        if preparation is not None:
            relative = preparation.relative_to(source).as_posix()
            request["preparation_relative"] = "" if relative == "." else relative
        return request

    def proof_environment(self, state, *, manager="npm", install_mode="immediate", extra_env=None):
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
        return env

    def proof(self, project, state, request, *, mode="install", manager="npm",
              runtime="node", install_mode="immediate", extra_env=None):
        child = subprocess.Popen(
            [fixture.WORKER, "prepare-proof", "--mode", mode,
             "--project", str(project), "--runtime", runtime],
            env=self.proof_environment(state, manager=manager, install_mode=install_mode,
                                       extra_env=extra_env),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.children.append(child)
        child.stdin.write(json.dumps(request).encode())
        child.stdin.close()
        child.stdin = None
        return child

    def verify(self, project, state, attestation, *, invocation=None, cwd=None, runtime="node",
               extra_env=None):
        # Preserve the field order returned by the worker. Its canonical digest
        # is the compact UTF-8 JSON envelope, with no trailing newline.
        digest = blake3_digest(json.dumps(
            attestation, ensure_ascii=False, separators=(",", ":")
        ).encode())
        argv = [fixture.WORKER, "prepare-proof", "--mode", "verify",
                "--project", str(project), "--runtime", runtime,
                "--expected-request-digest", attestation["request_digest"],
                "--expected-attestation-digest", digest]
        if invocation is not None:
            argv.extend(["--invocation-project", str(invocation)])
        child = subprocess.Popen(
            argv, cwd=cwd, env=self.proof_environment(state, extra_env=extra_env), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.children.append(child)
        return child

    def assert_verified(self, child):
        output, error = child.communicate(timeout=8)
        self.assertEqual(child.returncode, 0, (output, error))
        self.assertEqual(output, b"RCH_PREPARED_DEPENDENCIES_VERIFIED\n")

    def workspace(self, name, lock="package-lock.json", declaration=None):
        project, state = self.project(name, lock=lock)
        (project / "package.json").write_text(json.dumps({
            "name": "root", "private": True,
            "workspaces": ["packages/*"] if declaration is None else declaration,
        }))
        paths = ["package.json", lock]
        if lock == "pnpm-lock.yaml":
            (project / "pnpm-workspace.yaml").write_text("packages:\n  - 'packages/*'\n")
            paths.append("pnpm-workspace.yaml")
        for name in ("a", "b"):
            member = project / "packages" / name
            member.mkdir(parents=True)
            (member / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
            (member / "index.js").write_text("selected member " + name + "\n")
            paths.extend([f"packages/{name}/package.json", f"packages/{name}/index.js"])
        return project, state, paths

    def completed_records(self):
        return sorted((self.home / ".cache/rch/prepare-transactions").glob("*.outputs-v1.json"))

    def accepted(self, child):
        output, error = child.communicate(timeout=8)
        self.assertEqual(child.returncode, 0, (output, error))
        value = json.loads(output)
        # The worker emits serde_json::to_string in declaration field order.
        # Prove our bytes match that exact canonical framing before hashing an
        # accepted envelope, including UTF-8, decimal inode strings and escapes.
        self.assertEqual(output, json.dumps(value, ensure_ascii=False,
                                           separators=(",", ":")).encode() + b"\n")
        return value

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
        request = self.request(member, ["package.json", "package-lock.json", "packages/a/package.json"],
                               source=source, preparation=project)
        accepted = self.accepted(self.proof(project, state, request, extra_env={"RCH_PROOF_WORKSPACE": "1"}))
        self.assertEqual(accepted["state"]["project"], str(project))
        files = [entry["path"] for entry in accepted["state"]["inventory"]["files"]]
        self.assertIn("vittles/packages/a/node_modules/member/index.js", files)
        self.assertTrue(all(path.startswith("vittles/") for path in files))
        self.assertEqual(self.accepted(self.proof(project, state, request, mode="inspect")), accepted["state"])

    def test_workspace_members_share_frozen_root_install_and_retained_outputs(self):
        for lock, manager in (("package-lock.json", "npm"), ("bun.lock", "bun"),
                              ("pnpm-lock.yaml", "pnpm")):
            for runtime in ("node", "bun"):
                with self.subTest(manager=manager, runtime=runtime):
                    project, state, paths = self.workspace(manager + "-" + runtime, lock=lock)
                    before_journals = set(self.journals())
                    before_records = set(self.completed_records())
                    original_lock = (project / lock).read_bytes()
                    member_a = project / "packages/a"
                    first_request = self.request(member_a, paths, preparation=project)
                    options = dict(manager=manager, runtime=runtime)
                    self.assertIsNone(self.accepted(
                        self.proof(project, state, first_request, mode="inspect", **options)))
                    first = self.accepted(self.proof(
                        project, state, first_request, extra_env={"RCH_PROOF_WORKSPACE": "1"}, **options))
                    self.assertEqual(first["disposition"], "fresh")
                    self.assertEqual(first["state"]["package_manager"], manager)
                    self.assertEqual(first["state"]["project"], str(project))
                    self.assertEqual(first["state"]["root_inode"], str(project.stat().st_ino))
                    self.assertEqual((state / "install-cwd").read_text(), str(project) + "\n")
                    inventory = {entry["path"] for entry in first["state"]["inventory"]["files"]}
                    self.assertIn("node_modules/pkg/index.js", inventory)
                    self.assertIn("packages/a/node_modules/member/index.js", inventory)

                    member_b = project / "packages/b"
                    second_request = self.request(member_b, paths, preparation=project,
                                                  attempt="other-member-attempt")
                    self.assertEqual(first_request["files"], second_request["files"])
                    self.assertEqual(first_request["directories"], second_request["directories"])
                    second = self.accepted(self.proof(project, state, second_request, **options))
                    self.assertEqual(second["disposition"], "retained")
                    self.assertEqual(second["state"], first["state"])
                    self.assertNotEqual(second["request_digest"], first["request_digest"])
                    self.assertEqual(self.events(state), ["install"])
                    expected = [manager, "1", "ci"] if manager == "npm" else [
                        manager, "2", "install", "--frozen-lockfile"]
                    self.assertEqual(self.invocations(state), expected)
                    self.assertEqual((project / lock).read_bytes(), original_lock)
                    self.assertFalse((member_a / lock).exists())
                    self.assertFalse((member_b / lock).exists())
                    self.assertEqual(len(set(self.journals()) - before_journals), 1)
                    self.assertEqual(len(set(self.completed_records()) - before_records), 1)
                    self.assert_verified(self.verify(project, state, second, invocation=".",
                                                     cwd=member_b, runtime=runtime))

    def test_workspace_verify_binds_actual_member_cwd_and_latest_attempt(self):
        project, state, paths = self.workspace("verify-member")
        member_a, member_b = project / "packages/a", project / "packages/b"
        request = self.request(member_a, paths, preparation=project)
        first = self.accepted(self.proof(project, state, request))
        self.refused(self.verify(project, state, first, cwd=member_a), "requires --invocation-project")
        for wrong in (project, member_b):
            with self.subTest(cwd=wrong):
                self.refused(self.verify(project, state, first, invocation=".", cwd=wrong),
                             "invocation directory")
        self.assert_verified(self.verify(project, state, first, invocation=".", cwd=member_a))
        next_request = self.request(member_b, paths, preparation=project, attempt="next-member")
        second = self.accepted(self.proof(project, state, next_request))
        self.assertEqual(second["disposition"], "retained")
        self.refused(self.verify(project, state, first, invocation=".", cwd=member_a), "does not match")
        self.assert_verified(self.verify(project, state, second, invocation=".", cwd=member_b))
        self.assertEqual(self.events(state), ["install"])

    def test_workspace_exclusions_and_unmatched_prefixes_refuse_forged_root(self):
        for label, declaration in (("excluded", ["packages/*", "!packages/a"]),
                                   ("unmatched", ["packages/b*"]),
                                   ("negative-only", ["!packages/b"])):
            with self.subTest(declaration=declaration):
                project, state, paths = self.workspace(label, declaration=declaration)
                before = set(self.journals())
                request = self.request(project / "packages/a", paths, preparation=project)
                self.refused(self.proof(project, state, request))
                self.assertEqual(self.events(state), [])
                journal, = set(self.journals()) - before
                self.assertEqual(journal.read_bytes(), b"", "membership must be checked before RUNNING")
        self.assertFalse(self.completed_records())

    def test_workspace_install_requires_selected_root_lock_and_declarations(self):
        for omitted in ("package-lock.json", "package.json", "pnpm-workspace.yaml"):
            with self.subTest(omitted=omitted):
                pnpm = omitted == "pnpm-workspace.yaml"
                project, state, paths = self.workspace(
                    "unselected-" + omitted,
                    lock="pnpm-lock.yaml" if pnpm else "package-lock.json",
                )
                paths.remove(omitted)
                request = self.request(project / "packages/a", paths, preparation=project)
                self.refused(self.proof(project, state, request, manager="pnpm" if pnpm else "npm"))
                self.assertEqual(self.events(state), [])
        self.assertFalse(self.completed_records())
        self.assertTrue(all(path.read_bytes() == b"" for path in self.journals()))

    def test_nearer_locked_package_prevents_forged_outer_workspace_root(self):
        for boundary in ("own", "independent", "excluded", "conflicting"):
            with self.subTest(boundary=boundary):
                project, state, paths = self.workspace("boundary-" + boundary,
                                                       declaration=["packages/**"])
                before = set(self.journals())
                if boundary in ("own", "conflicting"):
                    member = project / "packages/a"
                    (member / "bun.lock").write_text("member-owned frozen resolution\n")
                    paths.append("packages/a/bun.lock")
                    if boundary == "conflicting":
                        (member / "package-lock.json").write_text("another manager\n")
                        paths.append("packages/a/package-lock.json")
                else:
                    group = project / "packages/group"
                    member = group / "app"
                    member.mkdir(parents=True)
                    declaration = {"name": "independent-root"}
                    if boundary == "excluded":
                        declaration["workspaces"] = ["other/*"]
                    (group / "package.json").write_text(json.dumps(declaration))
                    (group / "package-lock.json").write_text("nearest frozen resolution\n")
                    (member / "package.json").write_text('{"name":"app"}')
                    paths.extend(["packages/group/package.json", "packages/group/package-lock.json",
                                  "packages/group/app/package.json"])
                request = self.request(member, paths, preparation=project)
                self.refused(self.proof(project, state, request))
                self.assertEqual(self.events(state), [])
                journal, = set(self.journals()) - before
                self.assertEqual(journal.read_bytes(), b"")
        self.assertFalse(self.completed_records())

    def test_pnpm_workspace_ascent_requires_explicit_positive_yaml_membership(self):
        for label, yaml in (("omitted", "linkWorkspacePackages: true\n"),
                            ("null", "packages: null\n"),
                            ("empty", "packages: []\n"),
                            ("excluded", "packages:\n  - 'packages/*'\n  - '!packages/a'\n")):
            with self.subTest(declaration=label):
                project, state, paths = self.workspace("pnpm-" + label, lock="pnpm-lock.yaml")
                (project / "pnpm-workspace.yaml").write_text(yaml)
                before = set(self.journals())
                # The JSON manifest still lists packages/*; pnpm's own YAML
                # declarations must decide whether the root owns this member.
                request = self.request(project / "packages/a", paths, preparation=project)
                self.refused(self.proof(project, state, request, manager="pnpm"))
                self.assertEqual(self.events(state), [])
                journal, = set(self.journals()) - before
                self.assertEqual(journal.read_bytes(), b"")
        self.assertFalse(self.completed_records())

    def test_workspace_selected_source_change_refreshes_root_lifecycle_outputs(self):
        project, state, paths = self.workspace("member-source-change")
        (self.bin / "npm").write_text(fixture.NPM + r'''
IFS= read -r selected < packages/a/index.js
printf '%s\n' "$selected" > node_modules/member-source
''')
        member = project / "packages/a"
        request = self.request(member, paths, preparation=project)
        first = self.accepted(self.proof(project, state, request))
        lock = (project / "package-lock.json").read_bytes()
        (member / "index.js").write_text("new selected member input\n")
        self.refused(self.verify(project, state, first, invocation=".", cwd=member), "selected source changed")
        current = self.request(member, paths, preparation=project, attempt="changed-member-source")
        current["source_content_root"] = "c" * 64
        second = self.accepted(self.proof(project, state, current))
        self.assertEqual(second["disposition"], "fresh")
        self.assertEqual(second["state"]["input_fingerprint"], first["state"]["input_fingerprint"])
        self.assertNotEqual(second["state"]["inventory_digest"], first["state"]["inventory_digest"])
        self.assertEqual((project / "node_modules/member-source").read_text(), "new selected member input\n")
        self.assertEqual((project / "package-lock.json").read_bytes(), lock)
        self.assertEqual(self.events(state), ["install", "install"])

    def test_workspace_declaration_change_during_install_fences_every_member(self):
        project, state, paths = self.workspace("declaration-during-install")
        first_request = self.request(project / "packages/a", paths, preparation=project)
        child = self.proof(project, state, first_request, install_mode="blocked")
        fixture.eventually(lambda: (state / "started").exists(), "root installer did not start")
        (project / "package.json").write_text('{"workspaces":["packages/b"]}')
        (state / "release").write_text("release\n")
        self.refused(child)
        second_request = self.request(project / "packages/b", paths, preparation=project,
                                      attempt="other-member-after-mutation")
        self.refused(self.proof(project, state, second_request), "interrupted or invalid transaction")
        self.assertEqual(self.events(state), ["install"])
        self.assertFalse(self.completed_records())
        journal, = self.journals()
        self.assertEqual(journal.read_bytes(), fixture.RUNNING)

    @unittest.skipUnless(os.environ.get("RCH_TEST_REAL_NPM") == "1",
                         "opt-in offline proof test requires actual npm and node")
    def test_real_npm_root_proof_serves_hoisted_member_dependencies_and_reuses_them(self):
        npm, node = shutil.which("npm"), shutil.which("node")
        self.assertIsNotNone(npm, "RCH_TEST_REAL_NPM=1 requires npm")
        self.assertIsNotNone(node, "RCH_TEST_REAL_NPM=1 requires node")
        project, state = self.project("real-npm-proof", lock=None)
        consumer, provider = project / "packages/consumer", project / "packages/provider"
        consumer.mkdir(parents=True)
        provider.mkdir()
        (project / "package.json").write_text(json.dumps({
            "name": "rch-offline-root", "private": True, "workspaces": ["packages/*"],
        }))
        (consumer / "package.json").write_text(json.dumps({
            "name": "rch-offline-consumer", "version": "1.0.0",
            "dependencies": {"rch-offline-provider": "1.0.0"},
        }))
        (provider / "package.json").write_text(json.dumps({
            "name": "rch-offline-provider", "version": "1.0.0", "main": "index.js",
        }))
        (provider / "index.js").write_text("module.exports = 73;\n")
        for name in ("npmrc", "npm-globalrc"):
            (self.root / name).write_text("")
        manager_bin = self.root / "real-manager-bin"
        manager_bin.mkdir()
        manager = manager_bin / "npm"
        # This launcher only records argv and execs the actual installed npm.
        # No installation, lockfile, workspace link, or package layout is faked.
        manager.write_text("#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> "
                           + shlex.quote(str(state / "real-npm-argv"))
                           + "\nexec " + shlex.quote(npm) + ' "$@"\n')
        manager.chmod(0o700)
        environment = {
            "PATH": os.pathsep.join([str(manager_bin), str(Path(node).parent),
                                     str(Path(npm).parent), "/usr/bin", "/bin"]),
            "npm_config_offline": "true", "npm_config_audit": "false", "npm_config_fund": "false",
            "npm_config_update_notifier": "false", "npm_config_cache": str(self.root / "npm-cache"),
            "npm_config_userconfig": str(self.root / "npmrc"),
            "npm_config_globalconfig": str(self.root / "npm-globalrc"),
        }
        actual_environment = self.proof_environment(state, extra_env=environment)
        result = subprocess.run([npm, "install", "--package-lock-only"], cwd=project,
                                env=actual_environment, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=25, check=False)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertFalse((project / "node_modules").exists())
        lock = (project / "package-lock.json").read_bytes()
        paths = ["package.json", "package-lock.json", "packages/consumer/package.json",
                 "packages/provider/package.json", "packages/provider/index.js"]
        request = self.request(consumer, paths, preparation=project)
        first = self.accepted(self.proof(project, state, request, extra_env=environment))
        self.assertEqual(first["disposition"], "fresh")
        self.assertEqual(first["state"]["project"], str(project))
        links = {entry["path"]: entry["symlink_target"]
                 for entry in first["state"]["inventory"]["files"] if entry["kind"] == "symlink"}
        self.assertEqual(links["node_modules/rch-offline-provider"], "../packages/provider")
        self.assertFalse((consumer / "node_modules").exists())
        self.assert_verified(self.verify(project, state, first, invocation=".", cwd=consumer,
                                         extra_env=environment))
        result = subprocess.run(
            [node, "-e", "if(require('rch-offline-provider')!==73)process.exit(1)"],
            cwd=consumer, env=actual_environment, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=25, check=False,
        )
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))

        other = self.request(provider, paths, preparation=project, attempt="real-provider-member")
        second = self.accepted(self.proof(project, state, other, extra_env=environment))
        self.assertEqual(second["disposition"], "retained")
        self.assertEqual(second["state"], first["state"])
        self.assert_verified(self.verify(project, state, second, invocation=".", cwd=provider,
                                         extra_env=environment))
        self.assertEqual((state / "real-npm-argv").read_text(), "ci\n")
        self.assertEqual((project / "package-lock.json").read_bytes(), lock)
        self.assertEqual(len(self.journals()), 1)
        self.assertEqual(len(self.completed_records()), 1)

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

    def test_runtime_replacement_invalidates_attestation_and_refreshes_frozen_dependencies(self):
        project, state = self.project("runtime-generation")
        # These are controlled installer/runtime executables. Their generations,
        # worker reuse decisions and frozen install invocations are real; this
        # test does not claim to exercise a Node ABI or an actual registry.
        (self.bin / "npm").write_text(fixture.NPM)
        runtime = self.bin / "node"
        runtime.write_text("#!/bin/sh\nexit 0\n")
        runtime.chmod(0o700)
        request = self.request(project)
        initial = self.accepted(self.proof(project, state, request))
        retained_request = self.request(project, attempt="same-runtime-generation")
        retained = self.accepted(self.proof(project, state, retained_request))
        self.assertEqual(retained["disposition"], "retained")
        self.assertEqual(self.events(state), ["install"])
        self.assert_verified(self.verify(project, state, retained))

        metadata = runtime.stat()
        runtime.rename(self.bin / "retained-node")
        runtime.write_text("#!/bin/sh\nexit 0\n")
        runtime.chmod(0o700)
        os.utime(runtime, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        self.refused(self.verify(project, state, retained), "prepared execution inputs changed")
        current = self.request(project, attempt="new-runtime-generation")
        self.assertEqual(
            self.accepted(self.proof(project, state, current, mode="inspect")),
            initial["state"],
            "old output ownership must survive toolchain invalidation",
        )
        refreshed = self.accepted(self.proof(project, state, current))
        self.assertEqual(refreshed["disposition"], "fresh")
        self.assertNotEqual(refreshed["state"]["input_fingerprint"], initial["state"]["input_fingerprint"])
        self.assertEqual(refreshed["state"]["inventory_digest"], initial["state"]["inventory_digest"])
        self.assertEqual(self.events(state), ["install", "install"])
        self.assertEqual(self.invocations(state), ["npm", "1", "ci", "npm", "1", "ci"])
        self.assert_verified(self.verify(project, state, refreshed))
        warm = self.accepted(self.proof(project, state,
                                      self.request(project, attempt="stable-new-runtime")))
        self.assertEqual(warm["disposition"], "retained")
        self.assertEqual(self.events(state), ["install", "install"])

    def test_runtime_mutation_during_install_keeps_the_transaction_fenced(self):
        project, state = self.project("runtime-during-install")
        runtime = self.bin / "node"
        runtime.write_text("#!/bin/sh\nexit 0\n")
        runtime.chmod(0o700)
        request = self.request(project)
        child = self.proof(project, state, request, install_mode="blocked")
        fixture.eventually(lambda: (state / "started").exists(), "installer did not start")
        runtime.write_text("#!/bin/sh\nexit 1\n")
        (state / "release").write_text("release\n")
        self.refused(child, "package-manager environment changed")
        self.assertFalse(self.completed_records())
        self.assertEqual(self.journals()[0].read_bytes(), fixture.RUNNING)
        self.refused(self.proof(project, state, request), "interrupted or invalid transaction")
        self.assertEqual(self.events(state), ["install"])

    def test_selected_lifecycle_input_change_reinstalls_before_new_attestation(self):
        project, state = self.project("lifecycle-input")
        (project / "package.json").write_text(
            '{"name":"fixture","scripts":{"postinstall":"sh prepare-dependency.sh"}}'
        )
        script = project / "prepare-dependency.sh"
        script.write_text("printf 'first generation\\n' > node_modules/lifecycle-output\n")
        # The manager is a deterministic fixture. Its lifecycle script, file
        # writes, worker transaction and output attestation are real execution.
        # No registry or package-manager implementation is being qualified.
        (self.bin / "npm").write_text(fixture.NPM + "\nsh ./prepare-dependency.sh\n")
        paths = ["package.json", "package-lock.json", "prepare-dependency.sh"]
        request = self.request(project, paths)
        first = self.accepted(self.proof(project, state, request))
        output = project / "node_modules/lifecycle-output"
        self.assertEqual(output.read_bytes(), b"first generation\n")
        self.assertEqual(first["disposition"], "fresh")

        # A new attempt with identical selected inputs still reuses the
        # completed inventory without executing the installer twice.
        unchanged = self.request(project, paths, attempt="unchanged-input-attempt")
        retained = self.accepted(self.proof(project, state, unchanged))
        self.assertEqual(retained["disposition"], "retained")
        self.assertEqual(self.events(state), ["install"])

        # The lockfile and manifests are unchanged. The old fingerprint alone
        # cannot prove the lifecycle script will produce the same dependencies.
        script.write_text("printf 'second generation\\n' > node_modules/lifecycle-output\n")
        current = self.request(project, paths, attempt="changed-script-attempt")
        current["source_content_root"] = "c" * 64
        self.assertEqual(
            self.accepted(self.proof(project, state, current, mode="inspect")),
            retained["state"],
            "old output ownership must remain usable for a fresh frozen install",
        )
        refreshed = self.accepted(self.proof(project, state, current))
        self.assertEqual(refreshed["disposition"], "fresh")
        self.assertEqual(output.read_bytes(), b"second generation\n")
        self.assertEqual(self.events(state), ["install", "install"])
        self.assertEqual(
            refreshed["state"]["input_fingerprint"], first["state"]["input_fingerprint"],
            "this regression must keep the old manifest/lock fingerprint unchanged",
        )
        self.assertNotEqual(
            refreshed["state"]["inventory_digest"], first["state"]["inventory_digest"]
        )
        completed = json.loads(self.completed_records()[0].read_bytes())
        self.assertEqual(completed["request"], current)
        self.assertEqual(completed["attestation"], refreshed)
        self.assertEqual(self.journals()[0].read_bytes(), fixture.IDLE)

    def test_selected_directory_change_refreshes_lifecycle_outputs(self):
        project, state = self.project("lifecycle-directory")
        (project / "package.json").write_text(
            '{"name":"fixture","scripts":{"postinstall":"sh prepare-dependency.sh"}}'
        )
        script = project / "prepare-dependency.sh"
        script.write_text(
            "if [ -d optional-input ]; then\n"
            "    printf 'directory present\\n' > node_modules/lifecycle-output\n"
            "else\n"
            "    printf 'directory absent\\n' > node_modules/lifecycle-output\n"
            "fi\n"
        )
        (self.bin / "npm").write_text(fixture.NPM + "\nsh ./prepare-dependency.sh\n")
        paths = ["package.json", "package-lock.json", "prepare-dependency.sh"]
        request = self.request(project, paths)
        initial = self.accepted(self.proof(project, state, request))
        output = project / "node_modules/lifecycle-output"
        self.assertEqual(output.read_bytes(), b"directory absent\n")

        (project / "optional-input").mkdir()
        current = self.request(project, paths, attempt="changed-directory-attempt")
        current["directories"] = ["optional-input"]
        current["source_content_root"] = "d" * 64
        self.assertEqual(request["files"], current["files"])
        self.assertEqual(
            self.accepted(self.proof(project, state, current, mode="inspect")),
            initial["state"],
        )
        refreshed = self.accepted(self.proof(project, state, current))
        self.assertEqual(refreshed["disposition"], "fresh")
        self.assertEqual(output.read_bytes(), b"directory present\n")
        self.assertEqual(self.events(state), ["install", "install"])
        self.assertEqual(
            refreshed["state"]["input_fingerprint"], initial["state"]["input_fingerprint"]
        )

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
