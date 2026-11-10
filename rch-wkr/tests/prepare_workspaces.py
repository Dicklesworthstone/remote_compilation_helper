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

    def test_member_invocation_prepares_the_root_with_its_frozen_manager(self):
        for lock, manager, plan in [("package-lock.json", "npm", "ci"),
                                    ("bun.lock", "bun", "frozen"),
                                    ("pnpm-lock.yaml", "pnpm", "frozen")]:
            for runtime in ("node", "bun"):
                with self.subTest(manager=manager, runtime=runtime):
                    project, state = self.workspace("member-" + manager + runtime, lock)
                    if manager == "pnpm":
                        (project / "pnpm-workspace.yaml").write_text("packages: ['packages/*']\n")
                    member = project / "packages/a"
                    args = dict(runtime=runtime, manager=manager, plan=plan)
                    first = self.report(self.start(member, state, **args), 0)
                    self.assertEqual(first["action"], "Installed")
                    self.assertIn(lock, first["fingerprint"]["sources"])
                    self.assertIn("packages/a/package.json", first["fingerprint"]["sources"])
                    self.assertTrue((project / "node_modules/fixture-dependency").is_file())
                    self.assertTrue((project / ".rch_dep_fingerprint.json").is_file())
                    self.assertFalse((member / "node_modules").exists())
                    self.assertFalse((member / ".rch_dep_fingerprint.json").exists())
                    second = self.report(self.start(member, state, **args), 0)
                    self.assertEqual(second["action"], "Skipped")
                    self.assertEqual(first["fingerprint"], second["fingerprint"])
                    self.assertEqual(self.events(state), ["install"])
                    expected = (["npm", "1", "ci"] if plan == "ci" else
                                [manager, "2", "install", "--frozen-lockfile"])
                    self.assertEqual(self.invocations(state), expected)
                    if manager == "npm":
                        self.assertEqual((state / "npm-preparation-root").read_text(), str(project))

    def test_concurrent_members_share_one_root_transaction_and_cache(self):
        project, state = self.workspace("concurrent-members")
        self.member(project, "b")
        first = self.start(project / "packages/a", state, "blocked")
        fixture.eventually(lambda: (state / "started").exists(), "installer did not start")
        second = self.start(project / "packages/b", state)
        with self.assertRaises(subprocess.TimeoutExpired):
            second.communicate(timeout=0.2)
        self.assertEqual(self.events(state), ["install"])
        (state / "release").write_text("release\n")
        self.assertEqual(self.report(first, 0)["action"], "Installed")
        self.assertEqual(self.report(second, 0)["action"], "Skipped")
        self.assertEqual(self.events(state), ["install"])
        journal, = self.journals()
        self.assertEqual(journal.read_bytes(), fixture.IDLE)

    def test_member_local_lock_remains_independent_and_conflicting_managers_refuse(self):
        project, state = self.workspace("independent-member", "bun.lock")
        member = project / "packages/a"
        (member / "package-lock.json").write_text('{"lockfileVersion":3}\n')
        report = self.report(self.start(member, state, runtime="bun"), 0)
        self.assertEqual(report["action"], "Installed")
        self.assertEqual(self.invocations(state), ["npm", "1", "ci"])
        self.assertTrue((member / "node_modules/fixture-dependency").is_file())
        self.assertFalse((project / "node_modules").exists())
        (member / "pnpm-lock.yaml").write_text("conflicting manager\n")
        self.assertEqual(self.report(self.start(member, state), 1)["action"], "Failed")
        self.assertEqual(self.events(state), ["install"])

    def test_admission_root_and_source_boundary_mismatch_stop_before_installer(self):
        project, state = self.workspace("wrong-admission")
        member = project / "packages/a"
        for option in ("--expected-preparation-root", "--preparation-boundary"):
            with self.subTest(option=option):
                report = self.report(self.start(member, state, prepare_options=[option, str(member)]), 1)
                self.assertEqual(report["action"], "Failed")
                self.assertEqual(self.events(state), [])
                self.assertEqual(self.journals(), [])
                self.assertFalse((project / "node_modules").exists())
                self.assertFalse((member / "node_modules").exists())
        self.assertEqual(self.report(self.start(member, state, prepare_options=[
            "--expected-preparation-root", str(project), "--preparation-boundary", str(project)
        ]), 0)["action"], "Installed")

    def test_root_declaration_change_during_member_install_keeps_uncertainty_fence(self):
        project, state = self.workspace("changed-owner")
        member = project / "packages/a"
        manifest = (project / "package.json").read_bytes()
        child = self.start(member, state, "blocked")
        fixture.eventually(lambda: (state / "started").exists(), "installer did not start")
        (project / "package.json").write_text('{"workspaces":["other/*"]}\n')
        (state / "release").write_text("release\n")
        self.assertEqual(self.report(child, 1)["action"], "Failed")
        journal, = self.journals()
        self.assertEqual(journal.read_bytes(), fixture.RUNNING)
        (project / "package.json").write_bytes(manifest)
        self.assertEqual(self.report(self.start(member, state), 1)["action"], "Failed")
        self.assertEqual(self.events(state), ["install"])

    def test_bun_and_classic_yarn_cannot_redirect_independent_install_into_ancestor(self):
        for manager, lock in (("bun", "bun.lock"), ("yarn", "yarn.lock")):
            with self.subTest(manager=manager):
                project, state = self.workspace("native-ascent-" + manager, lock=None)
                member = project / "packages/a"
                (member / lock).write_text("independent lock\n")
                report = self.report(self.start(member, state, manager=manager, plan="frozen"), 1)
                self.assertEqual(report["action"], "Failed")
                self.assertEqual(self.events(state), [])
                self.assertFalse((project / "node_modules").exists())
                self.assertFalse((member / "node_modules").exists())
                self.assertTrue(all(path.read_bytes() != fixture.RUNNING for path in self.journals()))

    def test_member_execution_uses_hoisted_then_member_tools_in_both_budget_modes(self):
        project, state = self.workspace("execution-tools")
        member = project / "packages/a"
        nested = member / "src"
        nested.mkdir()
        self.assertEqual(self.report(self.start(member, state), 0)["action"], "Installed")

        def compiler(root, origin):
            directory = root / "node_modules/.bin"
            directory.mkdir(parents=True)
            path = directory / "tsc"
            path.write_text('#!/bin/sh\nprintf "%s" "' + origin + '" > "$RCH_PREPARE_TEST_STATE/user-command"\n'
                            'pwd > "$RCH_PREPARE_TEST_STATE/workload-cwd"\nexit 23\n')
            path.chmod(0o700)

        compiler(project, "root")
        for origin in ("root", "member"):
            if origin == "member":
                compiler(member, "member")
            for location in (member, nested):
                for guarded in (False, True):
                    with self.subTest(origin=origin, location=location, guarded=guarded):
                        # npm test has no automatic compiler disk budget and
                        # exercises the actual plain executor path. Its real
                        # shell fixture execs the same PATH-selected compiler.
                        child = self.start(location, state, execute=True, guarded=guarded,
                                           command=None if guarded else "npm test",
                                           extra_env={"RCH_PREPARE_TEST_EXEC_TSC": "1"})
                        stdout, stderr = child.communicate(timeout=8)
                        self.assertEqual(child.returncode, 23, (stdout, stderr))
                        self.assertEqual((state / "user-command").read_text(), origin)
                        self.assertEqual((state / "workload-cwd").read_text().strip(), str(location))
        self.assertEqual(self.events(state), ["install"])

    def test_execution_selector_preserves_legacy_marker_and_reports_member_distance(self):
        project, state = self.workspace("selector")
        member = project / "packages/a"
        for options, token in [(["--execution-layout"], b"RCH_PREPARED_NODE_MODULES\n"),
                               (["--execution-layout", "--workspace-root"],
                                b"RCH_PREPARED_NODE_MODULES:2\n")]:
            child = self.start(member, state, prepare_options=options)
            stdout, stderr = child.communicate(timeout=8)
            self.assertEqual(child.returncode, 0, (stdout, stderr))
            self.assertEqual(stdout, token)
            reports = [json.loads(line) for line in stderr.splitlines() if line.startswith(b'{')]
            self.assertEqual([report["dependency_layout"] for report in reports if "action" in report],
                             ["node_modules"])
        self.assertEqual(self.events(state), ["install"])

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

    def real_independent_member(self, manager):
        executable, node = shutil.which(manager), shutil.which("node")
        self.assertIsNotNone(executable, "real-manager opt-in requires " + manager)
        self.assertIsNotNone(node, "real-manager opt-in requires Node")
        root, _ = self.workspace("real-independent-" + manager, lock=None)
        invocation = root / "packages/a"
        local = invocation / "vendor/local"
        local.mkdir(parents=True)
        (local / "package.json").write_text('{"name":"rch-local","version":"1.0.0","main":"index.js"}')
        (local / "index.js").write_text("module.exports=73;\n")
        (invocation / "package.json").write_text(json.dumps({
            "name": "rch-independent", "version": "1.0.0",
            "dependencies": {"rch-local": "file:vendor/local"},
        }))
        lock = "package-lock.json" if manager == "npm" else "pnpm-lock.yaml"
        # This deliberately unusable ancestor lock detects accidental manager
        # ascent even if the resolver itself chose the member correctly.
        (root / lock).write_text("invalid ancestor lock\n")
        if manager == "pnpm":
            (root / "pnpm-workspace.yaml").write_text("packages: ['packages/*']\n")
        environment = {
            "PATH": os.pathsep.join([str(Path(executable).parent), str(Path(node).parent), "/usr/bin", "/bin"]),
            "HOME": str(self.home), "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_CONFIG_HOME": str(self.home / ".config"), "LC_ALL": "C", "CI": "1",
            "npm_config_cache": str(self.root / "npm-cache"), "npm_config_offline": "true",
            "npm_config_ignore_scripts": "true", "npm_config_audit": "false",
            "npm_config_fund": "false", "npm_config_update_notifier": "false",
            "PNPM_CONFIG_STORE_DIR": str(self.root / "pnpm-store"), "PNPM_CONFIG_CHECK_UPDATE": "false",
            "TOKIO_WORKER_THREADS": "2", "RCH_PREPARE_INSTALL_TIMEOUT_SECS": "25",
        }

        def run(argv):
            result = subprocess.run(argv, cwd=invocation, env=environment, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=35, check=False)
            self.assertEqual(result.returncode, 0, (argv, result.stdout, result.stderr))
            return result

        generate = (["--prefix", str(invocation), "install", "--package-lock-only"] if manager == "npm" else
                    ["install", "--lockfile-only", "--offline", "--ignore-scripts", "--ignore-workspace"])
        run([executable, *generate])
        self.assertTrue((invocation / lock).is_file())
        for action in ("Installed", "Skipped"):
            result = run([fixture.WORKER, "prepare", "--project", str(invocation), "--runtime", "node",
                          "--preparation-boundary", str(invocation)])
            self.assertEqual(json.loads(result.stdout)["action"], action)
            self.assertFalse((root / "node_modules").exists())
            self.assertEqual((root / lock).read_text(), "invalid ancestor lock\n")
            self.assertTrue((invocation / "node_modules/rch-local").exists())
        run([node, "-e", "if(require('rch-local')!==73)process.exit(1)"])

    @unittest.skipUnless(os.environ.get("RCH_TEST_REAL_NPM") == "1", "opt-in offline test requires npm")
    def test_real_npm_independent_lock_cannot_install_into_ancestor_workspace(self):
        self.real_independent_member("npm")

    @unittest.skipUnless(os.environ.get("RCH_TEST_REAL_PNPM") == "1", "opt-in offline test requires pnpm")
    def test_real_pnpm_independent_lock_cannot_install_into_ancestor_workspace(self):
        self.real_independent_member("pnpm")

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

        def run(argv, expected=0, cwd=project):
            result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=25, check=False)
            self.assertEqual(result.returncode, expected, (argv, result.stdout, result.stderr))
            return result

        def prepare(expected=0):
            return json.loads(run([fixture.WORKER, "prepare", "--project", str(project / "packages/a"),
                                   "--runtime", "node"], expected).stdout)

        run([npm, "install", "--package-lock-only"])
        self.assertEqual(prepare()["action"], "Installed")
        self.assertTrue((project / "node_modules/rch-workspace-a").exists())
        self.assertFalse((project / "packages/a/node_modules").exists())
        self.assertEqual(prepare()["action"], "Skipped")
        roots = [(project / name).read_bytes() for name in ("package.json", "package-lock.json")]
        self.member(project, "b")
        self.assertEqual(roots, [(project / name).read_bytes() for name in ("package.json", "package-lock.json")])
        self.assertEqual(prepare(1)["action"], "Failed", "npm ci must see the new unpinned workspace")
        run([npm, "install", "--package-lock-only"])
        self.assertEqual(prepare()["action"], "Installed")
        self.assertEqual(prepare()["action"], "Skipped")
        run([node, "-e", "if(require('rch-workspace-a')!=='a'||require('rch-workspace-b')!=='b')process.exit(1)"],
            cwd=project / "packages/a")


if __name__ == "__main__":
    if fixture.WORKER is None or not Path(fixture.WORKER).is_file():
        raise SystemExit("usage: prepare_workspaces.py /absolute/path/to/rch-wkr")
    # The unchanged transaction suite is run separately by the Cargo target.
    # Reuse its helpers without accidentally executing inherited cases twice.
    names = sorted(name for name in WorkspaceTransactions.__dict__ if name.startswith("test_"))
    suite = unittest.TestSuite(WorkspaceTransactions(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
