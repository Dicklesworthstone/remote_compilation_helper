#!/usr/bin/env python3
"""Exercise dependency-stamp migration with actual current and previous workers.

Usage: prepare_input_upgrade.py WORKER PREVIOUS_WORKER
The previous worker must exhibit the manifest-only retained-output bug. It
creates the stale completed record itself; this test never forges fingerprints
or attestations. Package installation uses the existing deterministic npm
fixture. This proves worker migration behavior, not real-manager rebuilding.
Both binaries are required, fixtures are retained, and skips cannot pass.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest


def load_suite(worker, previous_worker):
    path = Path(__file__).with_name("prepare_outputs.py")
    saved_argv = sys.argv
    try:
        sys.argv = [str(path), str(worker)]
        spec = importlib.util.spec_from_file_location("rch_upgrade_outputs", path)
        outputs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(outputs)
    finally:
        sys.argv = saved_argv

    class InputUpgrade(outputs.PreparedOutputs):
        def previous(self, project, state, request):
            current_worker = outputs.fixture.WORKER
            try:
                # proof() captures the executable at spawn; restore the
                # current worker before any subsequent operation.
                outputs.fixture.WORKER = str(previous_worker)
                child = self.proof(project, state, request)
            finally:
                outputs.fixture.WORKER = current_worker
            return self.accepted(child)

        def assert_completed(self, request, attestation):
            record, = self.completed_records()
            self.assertEqual(json.loads(record.read_bytes()),
                             {"request": request, "attestation": attestation})
            journal, = self.journals()
            self.assertEqual(journal.read_bytes(), outputs.fixture.IDLE)

        def test_upgrade_refreshes_previously_miscertified_current_selection(self):
            print(f"Retained upgrade fixture: {self.root}", file=sys.stderr)
            project, state = self.project("upgrade")
            (project / "package.json").write_text(
                '{"name":"fixture","scripts":{"postinstall":"sh prepare-dependency.sh"}}'
            )
            script = project / "prepare-dependency.sh"
            script.write_text("printf 'first\\n' > node_modules/lifecycle-output\n")
            (self.bin / "npm").write_text(outputs.fixture.NPM + "\nsh ./prepare-dependency.sh\n")
            paths = ["package.json", "package-lock.json", "prepare-dependency.sh"]
            initial_request = self.request(project, paths, attempt="old-first")
            first = self.previous(project, state, initial_request)
            self.assertEqual(first["disposition"], "fresh")
            output = project / "node_modules/lifecycle-output"
            self.assertEqual(output.read_bytes(), b"first\n")

            # Reproduce the old bug: the completed request now describes the
            # new source, even though its dependency outputs are still old.
            script.write_text("printf 'second\\n' > node_modules/lifecycle-output\n")
            stale_request = self.request(project, paths, attempt="old-stale")
            stale_request["source_content_root"] = "c" * 64
            stale = self.previous(project, state, stale_request)
            self.assertEqual(stale["disposition"], "retained",
                             "PREVIOUS_WORKER must reproduce the historical reuse bug")
            self.assertEqual(stale["state"], first["state"])
            self.assertEqual(output.read_bytes(), b"first\n")
            self.assertEqual(self.events(state), ["install"])
            self.assert_completed(stale_request, stale)

            current_request = self.request(project, paths, attempt="new-refresh")
            current_request["source_content_root"] = "c" * 64
            self.assertEqual(current_request["files"], stale_request["files"])
            self.assertEqual(current_request["directories"], stale_request["directories"])
            selected = {name: (project / name).read_bytes() for name in paths}
            self.assertEqual(self.accepted(self.proof(project, state, current_request, mode="inspect")),
                             stale["state"], "migration must preserve exact old output ownership")
            refreshed = self.accepted(self.proof(project, state, current_request))
            self.assertEqual(refreshed["disposition"], "fresh",
                             "the previous semantic stamp must not authorize retained reuse")
            self.assertEqual(output.read_bytes(), b"second\n")
            self.assertEqual(self.events(state), ["install", "install"])
            self.assertNotEqual(refreshed["state"]["input_fingerprint"], stale["state"]["input_fingerprint"])
            self.assertNotEqual(refreshed["state"]["inventory_digest"], stale["state"]["inventory_digest"])
            self.assert_completed(current_request, refreshed)
            self.assertEqual(self.accepted(self.proof(project, state, current_request, mode="inspect")),
                             refreshed["state"])

            warm_request = self.request(project, paths, attempt="new-warm")
            warm_request["source_content_root"] = "c" * 64
            warm = self.accepted(self.proof(project, state, warm_request))
            self.assertEqual(warm["disposition"], "retained")
            self.assertEqual(warm["state"], refreshed["state"])
            self.assertNotEqual(warm["request_digest"], refreshed["request_digest"])
            self.assertEqual(output.read_bytes(), b"second\n")
            self.assertEqual(self.events(state), ["install", "install"])
            self.assertEqual({name: (project / name).read_bytes() for name in paths}, selected)
            self.assert_completed(warm_request, warm)

    return unittest.TestSuite([InputUpgrade(
        "test_upgrade_refreshes_previously_miscertified_current_selection"
    )])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path, help="current rch-wkr executable")
    parser.add_argument("previous_worker", type=Path, help="previous worker with manifest-only reuse")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("this process regression requires Linux")
    paths = [path.resolve() for path in (args.worker, args.previous_worker)]
    for path in paths:
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(f"required worker is not an executable file: {path}")
    print(f"Current worker: {paths[0]}\nPrevious worker: {paths[1]}", file=sys.stderr)
    result = unittest.TextTestRunner(verbosity=2).run(load_suite(*paths))
    return int(not result.wasSuccessful() or result.testsRun != 1 or bool(result.skipped))


if __name__ == "__main__":
    raise SystemExit(main())
