#!/usr/bin/env python3
"""Real-worker, real-pnpm lifecycle refresh on Linux without registry packages.

Usage: prepare_pnpm_lifecycle.py WORKER PNPM NODE
PNPM is an installed JavaScript CLI entry point, such as pnpm/bin/pnpm.cjs,
not a Corepack or shell launcher. All three paths are required; unavailable
tools fail instead of producing a skipped success. Fixtures and logs remain
available after the test. This qualifies the supplied manager version's root
and workspace scripts, not third-party dependency rebuilds or fleet rollout.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest


SCRIPT = """const fs = require('fs');
fs.mkdirSync('node_modules', {recursive: true});
fs.writeFileSync('node_modules/lifecycle-output', GENERATION);
fs.appendFileSync('node_modules/lifecycle-events', GENERATION + '\\n');
"""
SCRIPTS = ("prepare-dependency.cjs", "packages/member/prepare-dependency.cjs")
INPUTS = ("package.json", "packages/member/package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml")


def load_suite(worker, pnpm, node):
    path = Path(__file__).with_name("prepare_outputs.py")
    saved_argv = sys.argv
    try:
        # The imported transaction fixture consumes its worker from argv.
        sys.argv = [str(path), str(worker)]
        spec = importlib.util.spec_from_file_location("rch_real_pnpm_outputs", path)
        outputs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(outputs)
    finally:
        sys.argv = saved_argv

    class RealPnpmLifecycle(outputs.PreparedOutputs):
        def setUp(self):
            super().setUp()
            (self.bin / "node").symlink_to(node)
            self.manager_env = {
                "CI": "1", "COREPACK_ENABLE_NETWORK": "0",
                "XDG_DATA_HOME": str(self.home / ".local/share"),
                "npm_config_offline": "true", "PNPM_CONFIG_OFFLINE": "true",
                "npm_config_audit": "false", "npm_config_fund": "false",
                "npm_config_update_notifier": "false", "PNPM_CONFIG_UPDATE_NOTIFIER": "false",
                "npm_config_registry": "http://127.0.0.1:9/",
                "PNPM_CONFIG_REGISTRY": "http://127.0.0.1:9/",
                "PNPM_CONFIG_FETCH_RETRIES": "0", "PNPM_CONFIG_PM_ON_FAIL": "ignore",
                # The worker must remove this conflicting inherited setting.
                "pnpm_config_optimistic_repeat_install": "true",
            }
            # This records and forwards exact worker argv/environment to real
            # pnpm. It neither implements nor simulates installation behavior.
            (self.bin / "pnpm").write_text(
                '#!/bin/sh\nset -eu\n'
                'printf "%s\\n" "$#" "$@" >> "$RCH_PREPARE_TEST_STATE/real-pnpm-argv"\n'
                'printf "%s\\n" "${pnpm_config_optimistic_repeat_install-unset}" '
                '"${PNPM_CONFIG_OPTIMISTIC_REPEAT_INSTALL-unset}" '
                '>> "$RCH_PREPARE_TEST_STATE/real-pnpm-env"\n'
                f'exec {shlex.quote(str(node))} {shlex.quote(str(pnpm))} "$@"\n'
            )
            print(f"Retained real-pnpm fixture: {self.root}", file=sys.stderr)

        def seed_command(self, seed, *args):
            env = {
                "PATH": str(self.bin), "HOME": str(self.home), "LC_ALL": "C",
                "XDG_CACHE_HOME": str(self.home / ".cache"),
                "XDG_CONFIG_HOME": str(self.home / ".config"),
                "XDG_STATE_HOME": str(self.home / ".local/state"),
                **self.manager_env,
            }
            child = subprocess.Popen(
                [str(node), str(pnpm), *args], cwd=seed, env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.children.append(child)
            stdout, stderr = child.communicate(timeout=30)
            (self.root / ("pnpm-version.log" if args == ("--version",) else "seed-install.log")).write_bytes(stdout + stderr)
            self.assertEqual(child.returncode, 0, (stdout, stderr))
            return stdout.decode().strip()

        def check_completed(self, project, state, request, attestation, selected):
            self.assertEqual({name: (project / name).read_bytes() for name in selected}, selected)
            self.assertEqual(attestation["state"]["package_manager"], "pnpm")
            self.assertTrue(attestation["state"]["frozen"])
            record, = self.completed_records()
            self.assertEqual(json.loads(record.read_bytes()),
                             {"request": request, "attestation": attestation})
            journal, = self.journals()
            self.assertEqual(journal.read_bytes(), outputs.fixture.IDLE)
            # Inspect revalidates the exact source and output inventory through
            # the actual worker; it must not execute another installer.
            self.assertEqual(self.accepted(self.proof(
                project, state, request, mode="inspect", manager="pnpm",
                extra_env=self.manager_env)), attestation["state"])

        def check_lifecycle(self, project, attestation, generation, events):
            inventory = {entry["path"]: entry for entry in attestation["state"]["inventory"]["files"]}
            for prefix in ("", "packages/member/"):
                for name, expected in (("lifecycle-output", generation), ("lifecycle-events", events)):
                    path = prefix + "node_modules/" + name
                    data = expected.encode()
                    self.assertEqual((project / path).read_bytes(), data)
                    self.assertEqual(inventory[path]["sha256"], hashlib.sha256(data).hexdigest())
                    self.assertEqual(inventory[path]["byte_count"], len(data))

        def test_real_pnpm_refreshes_selected_root_and_workspace_scripts(self):
            seed = self.root / "lock-seed"
            (seed / "packages/member").mkdir(parents=True)
            for relative, name in (("", "rch-fixture-root"), ("packages/member", "rch-fixture-member")):
                manifest = {"name": name, "version": "1.0.0", "private": True,
                            "scripts": {"postinstall": "node prepare-dependency.cjs"}}
                if not relative:
                    manifest["workspaces"] = ["packages/*"]
                (seed / relative / "package.json").write_text(json.dumps(manifest))
            (seed / "pnpm-workspace.yaml").write_text(
                "packages:\n  - 'packages/*'\noptimisticRepeatInstall: true\n"
            )
            for name in SCRIPTS:
                (seed / name).write_text(SCRIPT.replace("GENERATION", "'first'"))
            print(f"Real pnpm version: {self.seed_command(seed, '--version')}", file=sys.stderr)
            self.seed_command(seed, "install", "--lockfile-only", "--ignore-scripts")

            # Lockfile generation may leave manager metadata. Copy only the
            # selected source closure, never its node_modules or install state.
            project, state = self.project("real-pnpm", lock=None)
            paths = [*INPUTS, *SCRIPTS]
            for name in paths:
                target = project / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((seed / name).read_bytes())
            selected = {name: (project / name).read_bytes() for name in paths}
            request = self.request(project, paths, attempt="real-pnpm-first")
            first = self.accepted(self.proof(project, state, request, manager="pnpm", extra_env=self.manager_env))
            self.assertEqual(first["disposition"], "fresh")
            self.check_lifecycle(project, first, "first", "first\n")
            self.check_completed(project, state, request, first, selected)

            warm_request = self.request(project, paths, attempt="real-pnpm-warm")
            warm = self.accepted(self.proof(project, state, warm_request, manager="pnpm", extra_env=self.manager_env))
            self.assertEqual(warm["disposition"], "retained")
            self.assertEqual(warm["state"], first["state"])
            self.assertNotEqual(warm["request_digest"], first["request_digest"])
            self.check_lifecycle(project, warm, "first", "first\n")
            self.check_completed(project, state, warm_request, warm, selected)
            self.assertEqual((state / "real-pnpm-argv").read_text().splitlines(),
                             ["2", "install", "--frozen-lockfile"])

            for name in SCRIPTS:
                (project / name).write_text(SCRIPT.replace("GENERATION", "'second'"))
            current = self.request(project, paths, attempt="real-pnpm-edited")
            current["source_content_root"] = "c" * 64
            selected = {name: (project / name).read_bytes() for name in paths}
            self.assertEqual(self.accepted(self.proof(
                project, state, current, mode="inspect", manager="pnpm",
                extra_env=self.manager_env)), warm["state"])
            refreshed = self.accepted(self.proof(project, state, current, manager="pnpm", extra_env=self.manager_env))
            self.assertEqual(refreshed["disposition"], "fresh")
            self.assertEqual(refreshed["state"]["input_fingerprint"], first["state"]["input_fingerprint"])
            self.assertNotEqual(refreshed["state"]["inventory_digest"], first["state"]["inventory_digest"])
            self.check_lifecycle(project, refreshed, "second", "first\nsecond\n")
            self.check_completed(project, state, current, refreshed, selected)
            self.assertEqual({name: (project / name).read_bytes() for name in INPUTS},
                             {name: (seed / name).read_bytes() for name in INPUTS})
            self.assertEqual((state / "real-pnpm-argv").read_text().splitlines(),
                             ["2", "install", "--frozen-lockfile"] * 2)
            self.assertEqual((state / "real-pnpm-env").read_text().splitlines(),
                             ["unset", "false"] * 2)

    return unittest.TestSuite([RealPnpmLifecycle(
        "test_real_pnpm_refreshes_selected_root_and_workspace_scripts"
    )])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path, help="compiled rch-wkr executable")
    parser.add_argument("pnpm", type=Path, help="installed pnpm JavaScript CLI entry point (.cjs/.mjs/.js)")
    parser.add_argument("node", type=Path, help="installed Node executable")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("this process regression requires Linux")
    paths = [path.resolve() for path in (args.worker, args.pnpm, args.node)]
    for path in paths:
        if not path.is_file():
            parser.error(f"required tool is not a file: {path}")
    if not all(os.access(path, os.X_OK) for path in (paths[0], paths[2])):
        parser.error("worker and Node must be executable")
    if paths[1].suffix not in (".cjs", ".mjs", ".js"):
        parser.error("PNPM must be its installed JavaScript entry point, not a launcher")
    result = unittest.TextTestRunner(verbosity=2).run(load_suite(*paths))
    return int(not result.wasSuccessful() or result.testsRun != 1 or bool(result.skipped))


if __name__ == "__main__":
    raise SystemExit(main())
