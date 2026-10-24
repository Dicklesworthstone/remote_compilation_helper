#!/usr/bin/env python3
"""pnpm-only workspace preparation through the compiled worker.

Normal cases use the existing isolated manager fixtures, never a substituted
worker/cache implementation. RCH_TEST_REAL_PNPM=1 additionally requires an
installed pnpm and Node for a local-only, offline frozen-lockfile scenario.
"""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

spec = importlib.util.spec_from_file_location(
    "rch_pnpm_fixture", Path(__file__).with_name("prepare_transactions.py")
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class PnpmWorkspaces(fixture.PrepareTransactions):
    def workspace(self, name, yaml="packages: ['packages/*']\n"):
        project, state = self.project(name, lock="pnpm-lock.yaml")
        (project / "package.json").write_text('{"name":"root","private":true}')
        (project / "pnpm-workspace.yaml").write_text(yaml)
        self.member(project, "a")
        return project, state

    def member(self, project, name, revision="1.0.0"):
        directory = project / "packages" / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "package.json").write_text(json.dumps({
            "name": "rch-pnpm-" + name, "version": revision, "main": "index.js",
        }))
        (directory / "index.js").write_text("module.exports=" + json.dumps(name) + ";\n")
        return directory

    def launch(self, project, state, **kwargs):
        return self.start(project, state, manager="pnpm", plan="frozen", **kwargs)

    def test_pnpm_only_cold_and_warm_paths_preserve_the_selected_manager(self):
        for runtime in ("node", "bun"):
            with self.subTest(runtime=runtime):
                project, state = self.workspace(runtime)
                self.assertNotIn("workspaces", json.loads((project / "package.json").read_text()))
                first = self.report(self.launch(project, state, runtime=runtime), 0)
                self.assertEqual(first["action"], "Installed")
                self.assertIn("pnpm-workspace.yaml", first["fingerprint"]["sources"])
                self.assertIn("packages/a/package.json", first["fingerprint"]["sources"])
                self.assertEqual(self.report(self.launch(project, state), 0)["action"], "Skipped")
                self.assertEqual(self.invocations(state), ["pnpm", "2", "install", "--frozen-lockfile"])
                self.assertEqual(self.events(state), ["install"])

    def test_member_edit_addition_and_removal_cannot_reuse_root_only_stamps(self):
        project, state = self.workspace("members")
        roots = {name: (project / name).read_bytes() for name in
                 ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml")}
        previous = self.report(self.launch(project, state), 0)["fingerprint"]
        for operation in ("edit", "add", "remove"):
            with self.subTest(operation=operation):
                if operation == "edit":
                    self.member(project, "a", "2.0.0")
                elif operation == "add":
                    self.member(project, "b")
                else:
                    (project / "packages/b").rename(self.root / "retained-b")
                self.assertEqual(roots, {name: (project / name).read_bytes() for name in roots})
                report = self.report(self.launch(project, state), 0)
                self.assertEqual(report["action"], "Installed")
                self.assertNotEqual(report["fingerprint"]["hash"], previous["hash"])
                self.assertEqual(report["fingerprint_changed_from"], previous["hash"])
                self.assertEqual(self.report(self.launch(project, state), 0)["action"], "Skipped")
                previous = report["fingerprint"]
        self.assertEqual(self.events(state), ["install"] * 4)

    def test_yaml_catalogs_and_member_specific_configuration_invalidate(self):
        for name in ("pnpm-workspace.yaml", "packages/a/pnpm-lock.yaml", "packages/a/.npmrc"):
            with self.subTest(input=name):
                project, state = self.workspace("config-" + name.replace("/", "-"))
                path = project / name
                if name != "pnpm-workspace.yaml":
                    path.write_text("initial member settings\n")
                first = self.report(self.launch(project, state), 0)
                self.assertEqual(self.report(self.launch(project, state), 0)["action"], "Skipped")
                path.write_text("packages: ['packages/*']\ncatalog:\n chalk: '^5.0.0'\n"
                                if name == "pnpm-workspace.yaml" else "changed member settings\n")
                second = self.report(self.launch(project, state), 0)
                self.assertEqual(second["action"], "Installed")
                self.assertIn(name, second["fingerprint"]["sources"])
                self.assertNotEqual(first["fingerprint"]["hash"], second["fingerprint"]["hash"])
                self.assertEqual(self.events(state), ["install", "install"])

    def test_inflight_yaml_or_member_change_keeps_the_uncertainty_fence(self):
        for operation in ("yaml", "member", "member-lock", "add", "remove-yaml"):
            with self.subTest(operation=operation):
                project, state = self.workspace("inflight-" + operation)
                child = self.launch(project, state, mode="blocked")
                fixture.eventually(lambda: (state / "started").exists(), "installer did not start")
                if operation == "yaml":
                    (project / "pnpm-workspace.yaml").write_text("packages: ['packages/*']\nhoist: false\n")
                elif operation == "member":
                    self.member(project, "a", "2.0.0")
                elif operation == "member-lock":
                    (project / "packages/a/pnpm-lock.yaml").write_text("changed lock\n")
                elif operation == "add":
                    self.member(project, "b")
                else:
                    (project / "pnpm-workspace.yaml").rename(project / "retained.yaml")
                (state / "release").write_text("release\n")
                self.assertEqual(self.report(child, 1)["action"], "Failed")
                self.assertEqual(self.report(self.launch(project, state), 1)["action"], "Failed")
                self.assertEqual(self.events(state), ["install"])
                self.assertTrue(all(path.read_bytes() == fixture.RUNNING for path in self.journals()))

    def test_stale_workspace_failure_never_runs_the_users_command(self):
        for runtime in ("node", "bun"):
            with self.subTest(runtime=runtime):
                project, state = self.workspace("execution-" + runtime)
                self.report(self.launch(project, state), 0)
                self.member(project, "b")
                child = self.launch(project, state, mode="failure", execute=True, runtime=runtime)
                stdout, stderr = child.communicate(timeout=8)
                self.assertEqual(child.returncode, 121, (stdout, stderr))
                self.assertEqual(self.events(state), ["install", "install"])
                self.assertFalse((state / "user-command").exists())

    def test_invalid_yaml_refuses_before_install_and_allows_explicit_repair(self):
        cases = ("packages: [false]", "packages: []\npackages: ['other/*']",
                 "packages: ['../outside']", "defaults: &x {packages: ['other/*']}\n<<: *x")
        for index, yaml in enumerate(cases):
            with self.subTest(yaml=yaml):
                project, state = self.workspace("invalid-" + str(index), yaml)
                existing_journals = set(self.journals())
                self.assertEqual(self.report(self.launch(project, state), 1)["action"], "Failed")
                self.assertEqual(self.events(state), [])
                journal, = set(self.journals()) - existing_journals
                self.assertEqual(journal.read_bytes(), b"", "preflight must not write RUNNING")
                (project / "pnpm-workspace.yaml").write_text("packages: ['packages/*']\n")
                self.assertEqual(self.report(self.launch(project, state), 0)["action"], "Installed")
                self.assertEqual(self.events(state), ["install"])

    def test_pnpm_without_a_lock_is_not_bootstrapped_by_another_manager(self):
        project, state = self.workspace("no-lock")
        (project / "pnpm-lock.yaml").rename(project / "retained-lock.yaml")
        self.assertEqual(self.report(self.launch(project, state), 1)["action"], "Failed")
        self.assertEqual(self.invocations(state), [])
        journal, = self.journals()
        self.assertEqual(journal.read_bytes(), b"")
        (project / "retained-lock.yaml").rename(project / "pnpm-lock.yaml")
        self.assertEqual(self.report(self.launch(project, state), 0)["action"], "Installed")
        self.assertEqual(self.invocations(state), ["pnpm", "2", "install", "--frozen-lockfile"])

    @unittest.skipUnless(os.environ.get("RCH_TEST_REAL_PNPM") == "1",
                         "opt-in offline test requires installed pnpm, Node and compiled worker")
    def test_real_offline_pnpm_refuses_stale_workspace_lock_then_installs_repaired_graph(self):
        pnpm = shutil.which("pnpm")
        node = shutil.which("node")
        self.assertIsNotNone(pnpm, "RCH_TEST_REAL_PNPM=1 requires installed pnpm")
        self.assertIsNotNone(node, "RCH_TEST_REAL_PNPM=1 requires Node")
        project, _ = self.workspace("real")
        # Only local workspace edges; no registry dependency or lifecycle script.
        (project / "pnpm-lock.yaml").rename(project / "retained-synthetic-lock.yaml")
        (project / "package.json").write_text(json.dumps({
            "name": "root", "private": True, "dependencies": {"rch-pnpm-a": "workspace:*"},
        }))
        (project / "pnpm-workspace.yaml").write_text(
            "packages: ['packages/*']\nstoreDir: " + json.dumps(str(self.root / "store")) + "\n"
        )
        env = {
            "PATH": os.pathsep.join([str(Path(pnpm).parent), str(Path(node).parent), "/usr/bin", "/bin"]),
            "HOME": str(self.home), "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_CONFIG_HOME": str(self.home / ".config"), "LC_ALL": "C", "CI": "true",
            "COREPACK_ENABLE_NETWORK": "0", "npm_config_offline": "true",
            "npm_config_ignore_scripts": "true", "npm_config_update_notifier": "false",
            "TOKIO_WORKER_THREADS": "2", "RCH_PREPARE_INSTALL_TIMEOUT_SECS": "20",
        }

        def run(args, expected=0):
            result = subprocess.run(args, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=30, check=False)
            self.assertEqual(result.returncode, expected, (args, result.stdout, result.stderr))
            return result

        def prepare(expected=0):
            return json.loads(run([fixture.WORKER, "prepare", "--project", str(project),
                                   "--runtime", "node"], expected).stdout)

        run([pnpm, "install", "--lockfile-only", "--offline", "--ignore-scripts"])
        self.assertEqual(prepare()["action"], "Installed")
        self.assertEqual(prepare()["action"], "Skipped")
        run([node, "-e", "if(require('rch-pnpm-a')!=='a')process.exit(1)"])
        roots = {name: (project / name).read_bytes() for name in
                 ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml")}
        self.member(project, "b")
        member = project / "packages/a/package.json"
        metadata = json.loads(member.read_text())
        metadata["dependencies"] = {"rch-pnpm-b": "workspace:*"}
        member.write_text(json.dumps(metadata))
        (project / "packages/a/index.js").write_text("module.exports='a'+require('rch-pnpm-b');\n")
        self.assertEqual(roots, {name: (project / name).read_bytes() for name in roots})
        self.assertEqual(prepare(1)["action"], "Failed")
        run([pnpm, "install", "--lockfile-only", "--offline", "--ignore-scripts"])
        self.assertEqual(prepare()["action"], "Installed")
        self.assertEqual(prepare()["action"], "Skipped")
        run([node, "-e", "if(require('rch-pnpm-a')!=='ab')process.exit(1)"])


if __name__ == "__main__":
    if fixture.WORKER is None or not Path(fixture.WORKER).is_file():
        raise SystemExit("usage: prepare_pnpm_workspaces.py /absolute/path/to/rch-wkr")
    names = sorted(name for name in PnpmWorkspaces.__dict__ if name.startswith("test_"))
    suite = unittest.TestSuite(PnpmWorkspaces(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
