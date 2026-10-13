#!/usr/bin/env python3
"""Workspace invalidation through the compiled worker's public commands.

Reuse the existing isolated installer/process fixture; the normal cases never
run a real package manager or access a registry. Set RCH_TEST_REAL_NPM=1 to
also run the explicitly offline npm workspace-only test. No test substitutes
an implementation for the worker's cache, fingerprint or transaction logic.
"""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

# -I removes the script directory from sys.path. Resolve only the explicit
# neighboring fixture, not a module from user site-packages or PYTHONPATH.
spec = importlib.util.spec_from_file_location(
    "rch_prepare_fixture", Path(__file__).with_name("prepare_transactions.py")
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)  # consumes the compiled-worker argv


class WorkspaceTransactions(fixture.PrepareTransactions):
    def workspace(self, name, lock="package-lock.json", declaration=None):
        project, state = self.project(name, lock=lock)
        (project / "package.json").write_text(json.dumps({
            "name": "rch-workspace-root", "version": "1.0.0", "private": True,
            "workspaces": ["packages/*"] if declaration is None else declaration,
        }))
        self.member(project, "a")
        return project, state

    def member(self, project, name, revision="1.0.0"):
        directory = project / "packages" / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "package.json").write_text(json.dumps({
            "name": "rch-workspace-" + name, "version": revision, "main": "index.js",
        }))
        (directory / "index.js").write_text("module.exports=" + json.dumps(name) + ";\n")

    def test_workspace_cold_install_and_warm_hit_preserve_locked_manager(self):
        for lock, manager, plan in [("package-lock.json", "npm", "ci"),
                                    ("bun.lock", "bun", "frozen")]:
            for runtime in ("node", "bun"):
                with self.subTest(manager=manager, runtime=runtime):
                    project, state = self.workspace(manager + runtime, lock)
                    args = dict(runtime=runtime, manager=manager, plan=plan)
                    first = self.report(self.start(project, state, **args), 0)
                    self.assertEqual(first["action"], "Installed")
                    self.assertIn("packages/a/package.json", first["fingerprint"]["sources"])
                    second = self.report(self.start(project, state, **args), 0)
                    self.assertEqual(second["action"], "Skipped")
                    self.assertEqual(first["fingerprint"], second["fingerprint"])
                    self.assertEqual(self.events(state), ["install"])
                    expected = (["npm", "1", "ci"] if plan == "ci" else
                                ["bun", "2", "install", "--frozen-lockfile"])
                    self.assertEqual(self.invocations(state), expected)

    def test_workspace_edit_addition_and_removal_reinstall_with_unchanged_root_inputs(self):
        project, state = self.workspace("mutations")
        roots = {name: (project / name).read_bytes()
                 for name in ("package.json", "package-lock.json")}
        previous = self.report(self.start(project, state), 0)["fingerprint"]
        for operation in ("edit", "add", "remove"):
            with self.subTest(operation=operation):
                if operation == "edit":
                    self.member(project, "a", "2.0.0")
                elif operation == "add":
                    self.member(project, "b")
                else:
                    (project / "packages/b").rename(self.root / "retained-workspace-b")
                self.assertEqual(roots, {name: (project / name).read_bytes() for name in roots})
                current = self.report(self.start(project, state), 0)
                self.assertEqual(current["action"], "Installed")
                self.assertNotEqual(current["fingerprint"]["hash"], previous["hash"])
                self.assertEqual(current["fingerprint_changed_from"], previous["hash"])
                self.assertEqual(self.report(self.start(project, state), 0)["action"], "Skipped")
                previous = current["fingerprint"]
        self.assertEqual(self.events(state), ["install"] * 4)
        self.assertEqual(self.invocations(state), ["npm", "1", "ci"] * 4)

    def test_workspace_generated_dependencies_do_not_force_another_install(self):
        project, state = self.workspace("generated", declaration={"packages": ["packages/*"]})
        first = self.report(self.start(project, state), 0)
        for relative in ("node_modules/pkg", "packages/a/node_modules/pkg", "unrelated"):
            directory = project / relative
            directory.mkdir(parents=True)
            (directory / "package.json").write_text('{"name":"generated"}')
        current = self.report(self.start(project, state), 0)
        self.assertEqual(current["action"], "Skipped")
        self.assertEqual(first["fingerprint"], current["fingerprint"])
        self.assertEqual(self.events(state), ["install"])

    def test_workspace_mutation_during_install_keeps_the_uncertainty_fence(self):
        for operation in ("edit", "add", "remove"):
            with self.subTest(operation=operation):
                project, state = self.workspace("during-" + operation)
                child = self.start(project, state, "blocked")
                fixture.eventually(lambda: (state / "started").exists(), "installer did not start")
                if operation == "edit":
                    self.member(project, "a", "2.0.0")
                elif operation == "add":
                    self.member(project, "b")
                else:
                    (project / "packages/a").rename(self.root / "retained-during-a")
                (state / "release").write_text("release\n")
                self.assertEqual(self.report(child, 1)["action"], "Failed")
                self.assertEqual(self.report(self.start(project, state), 1)["action"], "Failed")
                self.assertEqual(self.events(state), ["install"], "no second installer on uncertain state")
                self.assertTrue(all(path.read_bytes() == fixture.RUNNING for path in self.journals()))

    def test_workspace_stale_cache_cannot_bypass_failed_preparation_and_run_user_code(self):
        for runtime in ("node", "bun"):
            with self.subTest(runtime=runtime):
                project, state = self.workspace("execute-" + runtime)
                self.assertEqual(self.report(self.start(project, state), 0)["action"], "Installed")
                self.member(project, "b")
                child = self.start(project, state, "failure", execute=True, runtime=runtime)
                stdout, stderr = child.communicate(timeout=8)
                self.assertEqual(child.returncode, 121, (stdout, stderr))
                self.assertEqual(self.events(state), ["install", "install"])
                self.assertFalse((state / "user-command").exists())

    def test_workspace_escape_refuses_before_install_and_does_not_poison_repair(self):
        project, state = self.workspace("escape", declaration=["../retained"])
        outside = self.root / "retained"
        outside.mkdir()
        (outside / "package.json").write_text('{"name":"outside"}')
        self.assertEqual(self.report(self.start(project, state), 1)["action"], "Failed")
        self.assertEqual(self.events(state), [])
        journal, = self.journals()
        self.assertEqual(journal.read_bytes(), b"", "refused discovery never starts an installer")
        (project / "package.json").write_text('{"workspaces":["packages/*"]}')
        self.assertEqual(self.report(self.start(project, state), 0)["action"], "Installed")
        self.assertEqual((outside / "package.json").read_text(), '{"name":"outside"}')

    @unittest.skipUnless(os.environ.get("RCH_TEST_REAL_NPM") == "1",
                         "opt-in offline test requires actual npm and node")
    def test_workspace_real_npm_rejects_a_stale_lock_then_serves_the_repaired_workspace(self):
        npm = shutil.which("npm")
        node = shutil.which("node")
        self.assertIsNotNone(npm, "RCH_TEST_REAL_NPM=1 requires npm")
        self.assertIsNotNone(node, "RCH_TEST_REAL_NPM=1 requires node")
        project, _ = self.workspace("real-npm", lock=None)
        env = {
            "PATH": os.pathsep.join([str(Path(npm).parent), str(Path(node).parent), "/usr/bin", "/bin"]),
            "HOME": str(self.home), "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_CONFIG_HOME": str(self.home / ".config"), "LC_ALL": "C",
            "npm_config_cache": str(self.root / "npm-cache"), "npm_config_offline": "true",
            "npm_config_ignore_scripts": "true", "npm_config_audit": "false",
            "npm_config_fund": "false", "npm_config_update_notifier": "false",
            "TOKIO_WORKER_THREADS": "2", "RCH_PREPARE_INSTALL_TIMEOUT_SECS": "15",
        }

        def run(argv, expected=0):
            result = subprocess.run(argv, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=25, check=False)
            self.assertEqual(result.returncode, expected, (argv, result.stdout, result.stderr))
            return result

        def prepare(expected=0):
            return json.loads(run([fixture.WORKER, "prepare", "--project", str(project),
                                   "--runtime", "node"], expected).stdout)

        run([npm, "install", "--package-lock-only"])
        self.assertEqual(prepare()["action"], "Installed")
        self.assertEqual(prepare()["action"], "Skipped")
        roots = [(project / name).read_bytes() for name in ("package.json", "package-lock.json")]
        self.member(project, "b")
        self.assertEqual(roots, [(project / name).read_bytes() for name in ("package.json", "package-lock.json")])
        self.assertEqual(prepare(1)["action"], "Failed", "npm ci must see the new unpinned workspace")
        run([npm, "install", "--package-lock-only"])
        self.assertEqual(prepare()["action"], "Installed")
        self.assertEqual(prepare()["action"], "Skipped")
        run([node, "-e", "if(require('rch-workspace-a')!=='a'||require('rch-workspace-b')!=='b')process.exit(1)"])


if __name__ == "__main__":
    if fixture.WORKER is None or not Path(fixture.WORKER).is_file():
        raise SystemExit("usage: prepare_workspaces.py /absolute/path/to/rch-wkr")
    # The unchanged transaction suite is run separately by the Cargo target.
    # Reuse its helpers without accidentally executing inherited cases twice.
    names = sorted(name for name in WorkspaceTransactions.__dict__ if name.startswith("test_"))
    suite = unittest.TestSuite(WorkspaceTransactions(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
