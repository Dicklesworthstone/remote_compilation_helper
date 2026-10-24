#!/usr/bin/env python3
"""Native tests of the candidate worker probe, not executions of the Rust hook."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parents[1] / "src/transfer/artifact_header_probe.py"
SPEC = importlib.util.spec_from_file_location("artifact_header_probe", HELPER)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class HeaderProbeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.worker = self.root / "worker"
        self.worker.mkdir()
        self.nonce = "0123456789abcdef" * 2

    def request(self, paths, target=None, root=None):
        return {"version": 1, "nonce": self.nonce, "root": str(root or self.worker),
                "cargo_target_root": str(target) if target else None, "paths": paths}

    def artifact(self, relative, prefix=b"\x7fELF", length=64):
        path = self.worker / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as stream:
            stream.write(prefix)
            stream.truncate(length)
        return path

    def run_probe(self, request=None, raw=None, env=None):
        if raw is None:
            raw = json.dumps(request, ensure_ascii=True).encode()
        return subprocess.run([sys.executable, str(HELPER)], input=raw,
                              capture_output=True, timeout=10, env=env)

    def checked(self, request):
        result = self.run_probe(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        answer = json.loads(result.stdout)
        self.assertEqual(answer["nonce"], self.nonce)
        self.assertEqual([row["path"] for row in answer["headers"]], request["paths"])
        return answer["headers"]

    def refused(self, request=None, raw=None):
        result = self.run_probe(request, raw)
        self.assertEqual(result.returncode, 74, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"RCH_ARTIFACT_HEADER_PROBE_REFUSED", result.stderr)

    def test_format_evidence_is_platform_independent(self):
        for name, prefix in [("linux", b"\x7fELF"), ("darwin", b"\xcf\xfa\xed\xfe"),
                             ("windows", b"MZ\0\0"), ("wasm", b"\0asm")]:
            self.artifact("debug/deps/" + name, prefix)
        paths = ["debug/deps/" + name for name in ("linux", "darwin", "windows", "wasm")]
        rows = self.checked(self.request(paths))
        self.assertEqual([bytes.fromhex(row["prefix_hex"])[:4] for row in rows],
                         [b"\x7fELF", b"\xcf\xfa\xed\xfe", b"MZ\0\0", b"\0asm"])

    def test_large_suite_reads_only_64_bytes_per_selected_file(self):
        total = 53_830_688_947
        count = 1040
        quotient, remainder = divmod(total, count)
        paths = [f"debug/deps/test_{number:04d}-0123456789abcdef" for number in range(count)]
        for index, path in enumerate(paths):
            self.artifact(path, length=quotient + (index < remainder))
        actual_read = os.read
        requests = []
        def counted_read(fd, length):
            requests.append(length)
            return actual_read(fd, length)
        with patch.object(probe.os, "read", counted_read):
            response = probe.collect(self.request(paths))
        rows = json.loads(response)["headers"]
        self.assertEqual(sum(row["length"] for row in rows), total)
        self.assertEqual(sum(len(row["prefix_hex"]) // 2 for row in rows), 66_560)
        self.assertEqual(len(requests), count)
        self.assertEqual(max(requests), 64)
        self.assertEqual(sum(requests), 66_560)
        self.assertLess(len(response), 300_000)
        self.assertEqual(list(self.root.iterdir()), [self.worker])

    def test_explicit_cross_target_path_is_not_rewritten_to_worker_host(self):
        path = "aarch64-apple-darwin/release/deps/cross-0123456789abcdef"
        self.artifact(path, b"\xcf\xfa\xed\xfe")
        row = self.checked(self.request([path]))[0]
        self.assertEqual(row["path"], path)
        self.assertEqual(bytes.fromhex(row["prefix_hex"])[:4], b"\xcf\xfa\xed\xfe")

    def test_custom_target_root_with_spaces_and_unicode(self):
        custom = self.root / "custom target ü"
        custom.mkdir()
        (custom / "test binary").write_bytes(b"\x7fELF" + bytes(60))
        rows = self.checked(self.request(["test binary"], root=custom))
        self.assertEqual(rows[0]["length"], 64)

    def test_authorized_managed_target_alias(self):
        target = self.root / "owned target pool"
        (target / "debug/deps").mkdir(parents=True)
        (target / "debug/deps/test").write_bytes(b"\x7fELF" + bytes(60))
        (self.worker / "target").symlink_to(target, target_is_directory=True)
        rows = self.checked(self.request(["target/debug/deps/test"], target=target))
        self.assertEqual(rows[0]["length"], 64)
        self.refused(self.request(["target/debug/deps/test"]))

    def test_alias_cannot_read_another_owned_target_pool(self):
        wanted = self.root / "wanted"
        other = self.root / "other"
        wanted.mkdir()
        other.mkdir()
        (other / "private-output").write_bytes(b"do not return this")
        (self.worker / "target").symlink_to(other, target_is_directory=True)
        self.refused(self.request(["target/private-output"], target=wanted))

    def test_root_alias_is_supported(self):
        self.artifact("test")
        alias = self.root / "root alias"
        alias.symlink_to(self.worker, target_is_directory=True)
        self.checked(self.request(["test"], root=alias))

    def test_recovery_probe_retains_existing_artifacts_and_journal(self):
        selected = self.artifact("debug/deps/test", length=8192)
        stage = self.root / "stage"
        stage.mkdir()
        retained = stage / "partial-output"
        retained.write_bytes(b"previous partial output")
        journal = self.root / "journal.json"
        journal.write_text('{"execution_started":true,"exit_code":0,"sources_released":false}')
        before = [(p, p.stat().st_ino, p.read_bytes()) for p in (selected, retained, journal)]
        request = self.request(["debug/deps/test"])
        raw = json.dumps(request).encode()
        first = self.run_probe(raw=raw)
        environment = dict(os.environ, RCH_ALLOW_FOREIGN_ARTIFACTS="1")
        second = self.run_probe(raw=raw, env=environment)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.stdout, first.stdout)
        self.assertEqual(second.returncode, 0, second.stderr)
        for path, inode, contents in before:
            self.assertEqual(path.stat().st_ino, inode)
            self.assertEqual(path.read_bytes(), contents)

    def test_missing_file_produces_no_partial_success_frame(self):
        self.artifact("present")
        self.refused(self.request(["present", "missing"]))

    def test_non_regular_and_symlink_files_are_refused(self):
        self.artifact("real")
        (self.worker / "link").symlink_to("real")
        os.mkfifo(self.worker / "fifo")
        (self.worker / "directory").mkdir()
        for path in ("link", "fifo", "directory"):
            with self.subTest(path=path):
                self.refused(self.request([path]))

    def test_symlink_ancestor_is_refused(self):
        self.artifact("real/test")
        (self.worker / "alias").symlink_to("real", target_is_directory=True)
        self.refused(self.request(["alias/test"]))

    def test_invalid_paths_are_refused_before_open(self):
        for path in ("../other", "/absolute", "a//b", "a/./b", "a/../b", "a\\b", "C:foo",
                     "bad\nname", "bad\x7fname", "a/" * 65 + "test"):
            with self.subTest(path=path):
                self.refused(self.request([path]))

    def test_duplicate_keys_paths_and_excessive_counts_are_refused(self):
        self.refused(self.request(["test", "test"]))
        self.refused(self.request([f"test_{i}" for i in range(probe.MAX_FILES + 1)]))
        raw = json.dumps(self.request([])).encode()
        self.refused(raw=b'{"version":1,' + raw[1:])
        self.refused(raw=b" " * (probe.MAX_REQUEST_BYTES + 1))

    def test_unknown_fields_versions_and_boolean_version_are_refused(self):
        for alteration in ({"version": 2}, {"version": True}, {"allow_foreign": True},
                           {"nonce": "0" * 31}, {"root": "relative"}):
            with self.subTest(alteration=alteration):
                request = self.request([])
                request.update(alteration)
                self.refused(request)

    def test_empty_and_short_files_produce_exact_bounded_evidence(self):
        for size in (0, 1, 4, 63, 64, 65):
            self.artifact(f"f{size}", b"x" * min(size, 64), size)
        rows = self.checked(self.request([f"f{size}" for size in (0, 1, 4, 63, 64, 65)]))
        self.assertEqual([len(row["prefix_hex"]) // 2 for row in rows], [0, 1, 4, 63, 64, 64])

    def test_modified_file_is_refused(self):
        artifact = self.artifact("test")
        original_read = os.read
        def mutate(fd, length):
            result = original_read(fd, length)
            with artifact.open("ab") as stream:
                stream.write(b"changed")
            return result
        with patch.object(probe.os, "read", mutate):
            with self.assertRaisesRegex(probe.Refused, "changed"):
                probe.collect(self.request(["test"]))

    def test_replaced_ancestor_is_refused(self):
        self.artifact("debug/test")
        original_read = os.read
        def replace(fd, length):
            result = original_read(fd, length)
            (self.worker / "debug").rename(self.worker / "old-debug")
            (self.worker / "debug").mkdir()
            return result
        with patch.object(probe.os, "read", replace):
            with self.assertRaisesRegex(probe.Refused, "directory changed"):
                probe.collect(self.request(["debug/test"]))

    def test_no_file_descriptor_leaks_on_success_or_refusal(self):
        if not Path("/proc/self/fd").exists():
            self.skipTest("descriptor accounting requires Linux procfs")
        self.artifact("debug/test")
        before = len(list(Path("/proc/self/fd").iterdir()))
        for _ in range(20):
            probe.collect(self.request(["debug/test"]))
            with self.assertRaises(OSError):
                probe.collect(self.request(["debug/missing"]))
        after = len(list(Path("/proc/self/fd").iterdir()))
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
