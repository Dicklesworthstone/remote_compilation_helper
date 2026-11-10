#!/usr/bin/env python3
"""Real-worker/npm install-environment/config changes and stamp migration.

Usage: prepare_environment.py WORKER PREVIOUS_WORKER NPM NODE
PREVIOUS_WORKER must reproduce environment-insensitive reuse (for example v4).
NPM is its installed JavaScript CLI entry point, not a package-download shim.
Only one local file devDependency is used, with isolated configuration and
offline installation. All tools are explicit, fixtures are retained, and no
skipped test can pass. Explicit npm user/global configuration is exercised with
real offline installs, including a change made by a lifecycle script. This does
not qualify arbitrary lifecycle variables, runtime replacements, unselected
configuration locations, or other managers.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest


SELECTED = (
    "package.json", "package-lock.json", "prepare.cjs",
    "packages/dev-only/package.json", "packages/dev-only/index.js",
)
SCRIPT = """const fs = require('fs');
fs.mkdirSync('node_modules', {recursive: true});
fs.writeFileSync('node_modules/lifecycle-env', process.env.NODE_ENV || 'unset');
"""


def load_suite(worker, previous_worker, npm, node):
    path = Path(__file__).with_name("prepare_outputs.py")
    saved_argv = sys.argv
    try:
        sys.argv = [str(path), str(worker)]
        spec = importlib.util.spec_from_file_location("rch_environment_outputs", path)
        outputs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(outputs)
    finally:
        sys.argv = saved_argv

    class InstallEnvironment(outputs.PreparedOutputs):
        def setUp(self):
            super().setUp()
            (self.bin / "node").symlink_to(node)
            for name in ("npm-user.conf", "npm-global.conf"):
                (self.home / name).write_text("")
            self.install_env = {
                "CI": "1", "COREPACK_ENABLE_NETWORK": "0",
                "npm_config_userconfig": str(self.home / "npm-user.conf"),
                "npm_config_globalconfig": str(self.home / "npm-global.conf"),
                "npm_config_offline": "true", "npm_config_audit": "false",
                "npm_config_fund": "false", "npm_config_update_notifier": "false",
                "npm_config_registry": "http://127.0.0.1:9/",
            }
            (self.bin / "npm").write_text(
                '#!/bin/sh\nset -eu\n'
                # Keep the historical-worker comparison's plan log comparable,
                # while checking and preserving the new exact-root argv.
                'if [ "${1-}" = --prefix ]; then\n'
                '  [ "$#" -ge 3 ] && [ "$2" = "$PWD" ] || exit 97\n'
                '  root=$2; shift 2\n'
                '  printf "%s\\n" "$#" "$@" >> "$RCH_PREPARE_TEST_STATE/real-npm-argv"\n'
                f'  exec {shlex.quote(str(node))} {shlex.quote(str(npm))} --prefix "$root" "$@"\n'
                'fi\n'
                'printf "%s\\n" "$#" "$@" >> "$RCH_PREPARE_TEST_STATE/real-npm-argv"\n'
                f'exec {shlex.quote(str(node))} {shlex.quote(str(npm))} "$@"\n'
            )
            print(f"Retained environment fixture: {self.root}", file=sys.stderr)

        def environment(self, settings):
            return {
                "PATH": str(self.bin), "HOME": str(self.home), "LC_ALL": "C",
                "XDG_CACHE_HOME": str(self.home / ".cache"),
                "XDG_CONFIG_HOME": str(self.home / ".config"),
                "XDG_STATE_HOME": str(self.home / ".local/state"),
                **self.install_env, **settings,
            }

        def local_command(self, project, settings, args, log):
            child = subprocess.Popen(args, cwd=project, env=self.environment(settings),
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.children.append(child)
            stdout, stderr = child.communicate(timeout=30)
            (self.root / log).write_bytes(stdout + stderr)
            return child.returncode, stdout, stderr

        def prepared_project(self, suffix=""):
            seed = self.root / ("seed" + suffix)
            (seed / "packages/dev-only").mkdir(parents=True)
            (seed / "package.json").write_text(json.dumps({
                "name": "rch-env-fixture", "version": "1.0.0", "private": True,
                "scripts": {"postinstall": "node prepare.cjs"},
                "devDependencies": {"rch-fixture-dev": "file:packages/dev-only"},
            }))
            (seed / "prepare.cjs").write_text(SCRIPT)
            (seed / "packages/dev-only/package.json").write_text(
                '{"name":"rch-fixture-dev","version":"1.0.0","main":"index.js"}'
            )
            (seed / "packages/dev-only/index.js").write_text("module.exports='dev available';\n")
            code, stdout, stderr = self.local_command(seed, {}, [str(node), str(npm), "--version"], "npm-version.log")
            self.assertEqual(code, 0, (stdout, stderr))
            print(f"Real npm version: {stdout.decode().strip()}", file=sys.stderr)
            code, stdout, stderr = self.local_command(seed, {}, [
                str(node), str(npm), "install", "--package-lock-only", "--ignore-scripts",
            ], "seed-lock.log")
            self.assertEqual(code, 0, (stdout, stderr))
            # Do not adopt any node_modules or metadata generated by the seed.
            project, state = self.project("environment" + suffix, lock=None)
            for name in SELECTED:
                target = project / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((seed / name).read_bytes())
            return project, state, {name: (project / name).read_bytes() for name in SELECTED}

        def install(self, project, state, request, settings, *, previous=False):
            current = outputs.fixture.WORKER
            try:
                if previous:
                    outputs.fixture.WORKER = str(previous_worker)
                child = self.proof(project, state, request, extra_env=self.install_env | settings)
            finally:
                outputs.fixture.WORKER = current
            return self.accepted(child)

        def inspect(self, project, state, request, settings):
            return self.accepted(self.proof(project, state, request, mode="inspect",
                                           extra_env=self.install_env | settings))

        def check_state(self, project, state, request, attestation, selected, settings):
            self.assertEqual(selected, {name: (project / name).read_bytes() for name in SELECTED})
            self.assertEqual(attestation["state"]["package_manager"], "npm")
            self.assertTrue(attestation["state"]["frozen"])
            record, = self.completed_records()
            self.assertEqual(json.loads(record.read_bytes()), {"request": request, "attestation": attestation})
            journal, = self.journals()
            self.assertEqual(journal.read_bytes(), outputs.fixture.IDLE)
            self.assertEqual(self.inspect(project, state, request, settings), attestation["state"])

        def check_module(self, project, settings, present, log):
            code, stdout, stderr = self.local_command(project, settings, [
                str(node), "-e", "process.stdout.write(require('rch-fixture-dev'))",
            ], log)
            if present:
                self.assertEqual(code, 0, (stdout, stderr))
                self.assertEqual(stdout, b"dev available")
            else:
                self.assertNotEqual(code, 0)
                self.assertIn(b"MODULE_NOT_FOUND", stderr)

        def test_environment_transitions_refresh_dependencies_and_unchanged_attempts_reuse(self):
            project, state, selected = self.prepared_project()
            previous = None
            cases = [({"NODE_ENV": "production"}, False),
                     ({"NODE_ENV": "development"}, True),
                     ({"NODE_ENV": "development", "npm_config_omit": "dev"}, False)]
            for index, (settings, present) in enumerate(cases):
                with self.subTest(settings=settings):
                    request = self.request(project, list(SELECTED), attempt=f"env-{index}-fresh")
                    self.assertEqual(self.inspect(project, state, request, settings),
                                     None if previous is None else previous["state"])
                    current = self.install(project, state, request, settings)
                    self.assertEqual(current["disposition"], "fresh")
                    if previous is not None:
                        self.assertNotEqual(current["state"]["input_fingerprint"], previous["state"]["input_fingerprint"])
                    self.check_module(project, settings, present, f"module-{index}.log")
                    self.check_state(project, state, request, current, selected, settings)
                    warm_request = self.request(project, list(SELECTED), attempt=f"env-{index}-warm")
                    warm = self.install(project, state, warm_request,
                                        settings | {"RCH_BUILD_ID": f"unrelated-attempt-{index}"})
                    self.assertEqual(warm["disposition"], "retained")
                    self.assertEqual(warm["state"], current["state"])
                    self.assertNotEqual(warm["request_digest"], current["request_digest"])
                    self.check_state(project, state, warm_request, warm, selected, settings)
                    self.assertEqual((state / "real-npm-argv").read_text().splitlines(), ["1", "ci"] * (index + 1))
                    previous = warm

        def test_upgrade_rejects_a_previous_workers_underbound_environment_stamp(self):
            project, state, selected = self.prepared_project()
            production = {"NODE_ENV": "production"}
            development = {"NODE_ENV": "development"}
            first_request = self.request(project, list(SELECTED), attempt="old-production")
            first = self.install(project, state, first_request, production, previous=True)
            self.assertEqual(first["disposition"], "fresh")
            self.check_module(project, production, False, "old-production.log")
            stale_request = self.request(project, list(SELECTED), attempt="old-development")
            stale = self.install(project, state, stale_request, development, previous=True)
            self.assertEqual(stale["disposition"], "retained",
                             "PREVIOUS_WORKER must reproduce environment-insensitive reuse")
            self.assertEqual(stale["state"], first["state"])
            self.assertEqual(stale_request["files"], first_request["files"])
            self.check_module(project, development, False, "old-development.log")
            self.check_state(project, state, stale_request, stale, selected, development)

            request = self.request(project, list(SELECTED), attempt="new-development")
            refreshed = self.install(project, state, request, development)
            self.assertEqual(refreshed["disposition"], "fresh")
            self.assertNotEqual(refreshed["state"]["input_fingerprint"], stale["state"]["input_fingerprint"])
            self.check_module(project, development, True, "new-development.log")
            self.assertEqual((project / "node_modules/lifecycle-env").read_text(), "development")
            self.check_state(project, state, request, refreshed, selected, development)
            warm_request = self.request(project, list(SELECTED), attempt="new-development-warm")
            warm = self.install(project, state, warm_request, development)
            self.assertEqual(warm["disposition"], "retained")
            self.assertEqual(warm["state"], refreshed["state"])
            self.check_state(project, state, warm_request, warm, selected, development)
            self.assertEqual((state / "real-npm-argv").read_text().splitlines(), ["1", "ci"] * 2)

        def test_configuration_bytes_refresh_dependencies_and_unchanged_attempts_reuse(self):
            for config_name in ("npm-user.conf", "npm-global.conf"):
                with self.subTest(config=config_name):
                    # Each configuration file is exercised independently; the
                    # other stays empty so npm's precedence cannot mask it.
                    for other in ("npm-user.conf", "npm-global.conf"):
                        if other != config_name:
                            (self.home / other).write_text("")
                    project, state, selected = self.prepared_project("-" + config_name)
                    config = self.home / config_name
                    config.rename(self.home / (config_name + ".original"))
                    previous = None
                    cases = [("", True, True, None), ("omit=dev\n", False, True, None),
                             ("ignore-scripts=true\n", True, False, None),
                             ("omit=${RCH_PREPARE_CONFIG_OMIT}\n", False, True, "dev"),
                             ("omit=${RCH_PREPARE_CONFIG_OMIT}\n", True, True, "optional"),
                             (None, True, True, None),
                             ("", True, True, None)]
                    for index, (content, present, lifecycle, omit) in enumerate(cases):
                        settings = {"NODE_ENV": "development"}
                        if omit is not None:
                            settings["RCH_PREPARE_CONFIG_OMIT"] = omit
                        if content is not None:
                            config.write_text(content)
                        else:
                            config.rename(self.home / f"{config_name}.removed-{index}")
                        attempt = f"{config_name}-{index}"
                        request = self.request(project, list(SELECTED), attempt=attempt)
                        current = self.install(project, state, request, settings)
                        self.check_module(project, settings, present, attempt + ".log")
                        self.assertEqual(current["disposition"], "fresh")
                        if previous is not None:
                            self.assertNotEqual(current["state"]["input_fingerprint"],
                                                previous["state"]["input_fingerprint"])
                        lifecycle_output = project / "node_modules/lifecycle-env"
                        self.assertEqual(lifecycle_output.exists(), lifecycle)
                        if lifecycle:
                            # npm sets NODE_ENV=production for lifecycle scripts
                            # when the effective omit list includes dev.
                            expected_environment = "development" if present else "production"
                            self.assertEqual(lifecycle_output.read_text(), expected_environment)
                        self.assertEqual(selected, {name: (project / name).read_bytes() for name in SELECTED})
                        self.assertEqual(self.inspect(project, state, request, settings), current["state"])
                        warm_request = self.request(project, list(SELECTED), attempt=attempt + "-warm")
                        warm = self.install(project, state, warm_request, settings)
                        self.assertEqual(warm["disposition"], "retained")
                        self.assertEqual(warm["state"], current["state"])
                        self.assertEqual((state / "real-npm-argv").read_text().splitlines(),
                                         ["1", "ci"] * (index + 1))
                        previous = warm

        def test_configuration_change_during_install_retains_unconfirmed_fence(self):
            project, state, _selected = self.prepared_project()
            # npm consumes this configuration before the selected lifecycle
            # runs. A later changed config must not bless those earlier outputs.
            script = project / "prepare.cjs"
            script.write_text(SCRIPT + "fs.writeFileSync(process.env.npm_config_userconfig, 'omit=dev\\n');\n")
            request = self.request(project, list(SELECTED), attempt="config-mutated-by-installer")
            child = self.proof(project, state, request,
                               extra_env=self.install_env | {"NODE_ENV": "development"})
            self.refused(child, "package-manager")
            self.assertEqual((self.home / "npm-user.conf").read_text(), "omit=dev\n")
            self.assertEqual((state / "real-npm-argv").read_text().splitlines(), ["1", "ci"])
            self.assertFalse(self.completed_records())
            journal, = self.journals()
            self.assertEqual(journal.read_bytes(), outputs.fixture.RUNNING)
            retry = self.proof(project, state, request,
                               extra_env=self.install_env | {"NODE_ENV": "development"})
            self.refused(retry, "interrupted or invalid transaction")
            self.assertEqual((state / "real-npm-argv").read_text().splitlines(), ["1", "ci"])

    names = sorted(name for name in InstallEnvironment.__dict__ if name.startswith("test_"))
    return unittest.TestSuite(InstallEnvironment(name) for name in names)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path)
    parser.add_argument("previous_worker", type=Path)
    parser.add_argument("npm", type=Path, help="installed npm JavaScript CLI entry point")
    parser.add_argument("node", type=Path)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("this process regression requires Linux")
    paths = [path.resolve() for path in (args.worker, args.previous_worker, args.npm, args.node)]
    if not all(path.is_file() for path in paths):
        parser.error("all four tool paths must be existing files")
    if not all(os.access(path, os.X_OK) for path in (paths[0], paths[1], paths[3])):
        parser.error("both workers and Node must be executable")
    if paths[2].suffix not in (".js", ".cjs", ".mjs"):
        parser.error("NPM must be its installed JavaScript CLI entry point")
    result = unittest.TextTestRunner(verbosity=2).run(load_suite(*paths))
    return int(not result.wasSuccessful() or result.testsRun != 4 or bool(result.skipped))


if __name__ == "__main__":
    raise SystemExit(main())
