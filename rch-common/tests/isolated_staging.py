#!/usr/bin/env python3
"""Filesystem/rsync integration contract for the isolated staging backend.

Runs the production shell, real rsync sender/receiver, and native C builds in
owned temporary trees. A local rsh transport substitutes for SSH; no ordinary
RCH orchestration, Cargo build, or real SSH disconnect is claimed by this test.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src" / "isolated_staging.sh"
SCRIPT = SOURCE.read_text()
ID = "0123456789abcdef0123456789abcdef"
SECOND = "fedcba9876543210fedcba9876543210"


@unittest.skipUnless(sys.platform == "linux", "Linux isolated receiver backend")
class IsolatedStaging(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="rch-isolated-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root / "stage"
        self.developer = self.root / "developer"
        self.developer.mkdir()
        self.sentinel = self.developer / "active-editor.txt"
        self.sentinel.write_text("do not change\n")
        self.rsh = self.root / "local-rsh"
        self.rsh.write_text('''#!/bin/sh
[ "$1" = rch-local-fixture ] || exit 99
shift
exec /bin/sh -c "$*"
''')
        self.rsh.chmod(0o700)

    def shell(self, function: str, *args: object, extra: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", "-c", SCRIPT + extra + f'\n{function} "$@"\n', "rch-stage-test", *map(str, args)],
            text=True, capture_output=True, timeout=10, check=False,
        )

    def job(self, identity: str = ID) -> Path:
        return self.base / "invocations" / identity

    def destination(self, identity: str = ID, logical: str = "/data/app") -> Path:
        return self.job(identity) / "source" / logical.lstrip("/")

    def prepare(self, identity: str = ID) -> None:
        result = self.shell("rch_stage_prepare", self.base, identity)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.rstrip("\n"), str(self.job(identity)))

    def verify(self, destination: Path | str | None = None, identity: str = ID) -> subprocess.CompletedProcess[str]:
        return self.shell("rch_stage_verify", self.base, identity,
                          self.destination(identity) if destination is None else destination)

    def assert_protected(self) -> None:
        self.assertEqual(self.sentinel.read_text(), "do not change\n")

    def receiver(self, identity: str, destination: Path) -> str:
        script = SCRIPT + '\nrch_stage_receive "$@"\n'
        return " ".join(map(shlex.quote, ["sh", "-c", script, "rch-isolated-stage",
                                         str(self.base), identity, str(destination)]))

    def upload(self, source: Path, identity: str = ID, logical: str = "/data/app",
               options: tuple[str, ...] = ()) -> subprocess.CompletedProcess[str]:
        destination = self.destination(identity, logical)
        result = subprocess.run(
            ["rsync", "-az", "--delete", "--partial", "--partial-dir=.rch-partial",
             "--stats", "--rsh", str(self.rsh), "--rsync-path", self.receiver(identity, destination),
             *options, "--", str(source) + "/", f"rch-local-fixture:{destination}"],
            text=True, capture_output=True, timeout=20, check=False,
        )
        return result

    def test_prepare_creates_private_owned_invocation(self) -> None:
        self.prepare()
        self.assertEqual(self.job().stat().st_mode & 0o777, 0o700)
        marker = self.job() / ".rch-stage-owner"
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(marker.read_text(), f"RCH_ISOLATED_STAGE_V1:{ID}\n")
        self.assertEqual(self.verify().returncode, 0)

    def test_existing_invocation_is_never_adopted_or_reset(self) -> None:
        self.prepare()
        receipt = self.job() / "completion"
        receipt.write_text("original build completed\n")
        result = self.shell("rch_stage_prepare", self.base, ID)
        self.assertEqual(result.returncode, 125)
        self.assertIn("invocation_exists", result.stderr)
        self.assertEqual(receipt.read_text(), "original build completed\n")
        self.assertEqual(self.verify().returncode, 0)

    def test_concurrent_claims_have_exactly_one_winner(self) -> None:
        # Pre-create safe parents so the race under test is the atomic claim.
        (self.base / "invocations").mkdir(parents=True, mode=0o700)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.shell("rch_stage_prepare", self.base, ID), range(4)))
        self.assertEqual(sum(result.returncode == 0 for result in results), 1)
        self.assertTrue(all(result.returncode in (0, 125) for result in results))
        self.assertEqual(self.verify().returncode, 0)

    def test_invalid_identity_and_noncanonical_base_refused(self) -> None:
        for identity in ("", "1", "A" * 32, "g" * 32, "a" * 31, "a" * 33, "../" + ID):
            with self.subTest(identity=identity):
                self.assertEqual(self.shell("rch_stage_prepare", self.base, identity).returncode, 125)
        for base in ("/", "relative", str(self.base) + "/", str(self.base) + "/../other",
                     str(self.base) + "//other", str(self.base) + "/./other", str(self.base) + "\n"):
            with self.subTest(base=base):
                self.assertEqual(self.shell("rch_stage_prepare", base, ID).returncode, 125)
        self.assertFalse(self.base.exists())

    def test_every_ascii_control_is_rejected_in_paths(self) -> None:
        # NUL cannot be present in an OS argv in the first place.
        for code in (*range(1, 32), 127):
            with self.subTest(code=code):
                path = str(self.base) + chr(code) + "tail"
                self.assertNotEqual(self.shell("rch_stage_valid_path", path).returncode, 0)

    def test_developer_checkout_ancestor_is_protected(self) -> None:
        git = self.developer / ".git"
        git.mkdir()
        result = self.shell("rch_stage_prepare", self.developer / "new-stage", ID)
        self.assertEqual(result.returncode, 125)
        self.assertFalse((self.developer / "new-stage").exists())
        self.assert_protected()

    def test_worktree_git_file_and_dangling_marker_are_protected(self) -> None:
        git = self.developer / ".git"
        git.write_text("gitdir: /elsewhere/worktrees/active\n")
        self.assertEqual(self.shell("rch_stage_prepare", self.developer / "cache", ID).returncode, 125)
        git.unlink()
        git.symlink_to(self.root / "missing-git")
        self.assertEqual(self.shell("rch_stage_prepare", self.developer / "cache", ID).returncode, 125)
        self.assert_protected()

    def test_symlink_base_and_intermediate_alias_are_protected(self) -> None:
        alias = self.root / "alias"
        alias.symlink_to(self.developer, target_is_directory=True)
        self.assertEqual(self.shell("rch_stage_prepare", alias, ID).returncode, 125)
        self.assertEqual(self.shell("rch_stage_prepare", alias / "cache", ID).returncode, 125)
        self.assertFalse((self.developer / "cache").exists())
        self.assert_protected()

    def test_dangling_base_and_invocations_alias_are_refused(self) -> None:
        self.base.symlink_to(self.root / "missing")
        self.assertEqual(self.shell("rch_stage_prepare", self.base, ID).returncode, 125)
        self.base.unlink()
        self.base.mkdir(mode=0o700)
        (self.base / "invocations").symlink_to(self.developer, target_is_directory=True)
        self.assertEqual(self.shell("rch_stage_prepare", self.base, ID).returncode, 125)
        self.assertFalse((self.developer / ID).exists())
        self.assert_protected()

    def test_shared_writable_parents_are_refused(self) -> None:
        self.base.mkdir(mode=0o777)
        self.base.chmod(0o777)
        result = self.shell("rch_stage_prepare", self.base, ID)
        self.assertEqual(result.returncode, 125)
        self.assertIn("shared_parent", result.stderr)
        self.assertFalse(self.job().exists())

    def test_wrong_owner_record_permissions_and_tampering_refused(self) -> None:
        self.prepare()
        self.job().chmod(0o755)
        self.assertEqual(self.verify().returncode, 125)
        self.job().chmod(0o700)
        marker = self.job() / ".rch-stage-owner"
        original = marker.read_bytes()
        for content in (b"", original + b"\n", original.replace(ID.encode(), SECOND.encode()), original + b"\0"):
            with self.subTest(content=content):
                marker.write_bytes(content)
                self.assertEqual(self.verify().returncode, 125)
        marker.write_bytes(original)
        marker.chmod(0o644)
        self.assertEqual(self.verify().returncode, 125)

    def test_owner_marker_hardlink_is_refused(self) -> None:
        self.prepare()
        os.link(self.job() / ".rch-stage-owner", self.root / "linked-owner")
        self.assertEqual(self.verify().returncode, 125)

    def test_destination_escape_and_neighbor_invocation_refused(self) -> None:
        self.prepare()
        for destination in (self.developer, self.job() / "source-other/data/app",
                            self.job(SECOND) / "source/data/app", str(self.destination()) + "/../other",
                            self.job() / ".rch-stage-owner"):
            with self.subTest(destination=destination):
                self.assertEqual(self.verify(destination).returncode, 125)
        self.assert_protected()

    def test_destination_alias_inserted_after_prepare_is_refused(self) -> None:
        self.prepare()
        self.destination().parent.mkdir(parents=True)
        self.destination().symlink_to(self.developer, target_is_directory=True)
        self.assertEqual(self.verify().returncode, 125)
        self.assert_protected()

    def test_nested_checkout_created_after_prepare_is_protected(self) -> None:
        self.prepare()
        nested = self.destination() / "vendor/new-checkout"
        nested.mkdir(parents=True)
        (nested / ".git").write_text("gitdir: /active\n")
        (nested / "editor.txt").write_text("unsaved work\n")
        result = self.verify()
        self.assertEqual(result.returncode, 125)
        self.assertIn("protected_entry", result.stderr)
        self.assertEqual((nested / "editor.txt").read_text(), "unsaved work\n")

    def test_hardlinked_source_file_and_partial_dir_alias_are_protected(self) -> None:
        self.prepare()
        self.destination().mkdir(parents=True)
        linked = self.destination() / "source.c"
        os.link(self.sentinel, linked)
        self.assertEqual(self.verify().returncode, 125)
        linked.unlink()
        (self.destination() / ".rch-partial").symlink_to(self.developer, target_is_directory=True)
        self.assertEqual(self.verify().returncode, 125)
        self.assert_protected()

    def test_receiver_rejects_escaping_options_before_creation(self) -> None:
        self.prepare()
        for option in ("--sender", "--inplace", "--append-verify", "--keep-dirlinks", "-K",
                       "-lKogDtpr", "--link-dest=/outside", "--backup-dir=/outside",
                       "--temp-dir=/outside", "--log-file=/outside", "--partial-dir=/outside",
                       "--partial-dir=../outside"):
            with self.subTest(option=option):
                result = self.shell("rch_stage_receive", self.base, ID, self.destination(),
                                    "--server", option, ".", self.destination())
                self.assertEqual(result.returncode, 125)
                self.assertFalse(self.destination().exists())
        self.assert_protected()

    def test_receiver_binds_exact_destination(self) -> None:
        self.prepare()
        result = self.shell("rch_stage_receive", self.base, ID, self.destination(),
                            "--server", "-logDtpr", ".", self.developer)
        self.assertEqual(result.returncode, 125)
        self.assertIn("destination_mismatch", result.stderr)
        self.assertFalse(self.destination().exists())
        self.assert_protected()

    @unittest.skipUnless(shutil.which("rsync"), "real rsync required")
    def test_real_rsync_updates_only_owned_tree_and_preserves_owner(self) -> None:
        self.prepare()
        source = self.root / "source"
        source.mkdir()
        (source / "main.c").write_text("int main(void) { return 0; }\n")
        self.destination().mkdir(parents=True)
        (self.destination() / "stale.c").write_text("old revision\n")
        result = self.upload(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.destination() / "main.c").read_bytes(), (source / "main.c").read_bytes())
        self.assertFalse((self.destination() / "stale.c").exists())
        self.assertEqual(self.verify().returncode, 0)
        self.assert_protected()

    @unittest.skipUnless(shutil.which("rsync"), "real rsync required")
    def test_rsync_replaces_directory_link_instead_of_following_it(self) -> None:
        self.prepare()
        source = self.root / "source"
        (source / "nested").mkdir(parents=True)
        (source / "nested/active-editor.txt").write_text("new staged source\n")
        self.destination().mkdir(parents=True)
        (self.destination() / "nested").symlink_to(self.developer, target_is_directory=True)
        result = self.upload(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.destination() / "nested").is_symlink())
        self.assertEqual((self.destination() / "nested/active-editor.txt").read_text(), "new staged source\n")
        self.assert_protected()

    @unittest.skipUnless(shutil.which("rsync"), "real rsync required")
    def test_quoted_paths_are_values_not_shell_programs(self) -> None:
        self.base = self.root / "stage with 'quotes' $(false); literal"
        self.prepare()
        source = self.root / "source with spaces"
        source.mkdir()
        (source / "literal.txt").write_text("ok\n")
        result = self.upload(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.destination() / "literal.txt").read_text(), "ok\n")

    def make_fixture(self, name: str, value: int) -> Path:
        root = self.root / name
        app = root / "app"
        for path in (app / "src", app / "vendor/nested", app / "tools/client", root / "deps/shared"):
            path.mkdir(parents=True)
        (app / "src/main.c").write_text(
            '#include <stdio.h>\n#include "tweak.h"\nint value(void);\n'
            'int main(void) { printf("%d\\n", value() + TWEAK); return 0; }\n'
        )
        (app / "vendor/nested/tweak.h").write_text("#define TWEAK 2\n")
        (root / "deps/shared/value.c").write_text(f"int value(void) {{ return {value}; }}\n")
        (app / "tools/client/Makefile").write_text(
            "all: ../../target/answer\n"
            "../../target/answer: ../../src/main.c ../../../deps/shared/value.c ../../vendor/nested/tweak.h\n"
            "\tmkdir -p ../../target\n"
            "\tcc -I../../vendor/nested ../../src/main.c ../../../deps/shared/value.c -o $@\n"
        )
        return root

    def compile_fixture(self, identity: str, source: Path) -> str:
        for local, logical in ((source / "app", "/data/app"), (source / "deps/shared", "/data/deps/shared"),
                               (source / "app/vendor/nested", "/data/app/vendor/nested")):
            result = self.upload(local, identity, logical)
            self.assertEqual(result.returncode, 0, result.stderr)
        cwd = self.destination(identity) / "tools/client"
        result = subprocess.run(["make"], cwd=cwd, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        binary = self.destination(identity) / "target/answer"
        stamp = binary.stat().st_mtime_ns
        self.assertEqual(subprocess.run(["make", "-q"], cwd=cwd).returncode, 0)
        self.assertEqual(binary.stat().st_mtime_ns, stamp, "within-invocation build cache stays hot")
        return subprocess.check_output([str(binary)], text=True).strip()

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("rsync", "cc", "make")), "rsync and native C toolchain required")
    def test_concurrent_nested_builds_artifacts_and_readonly_recovery(self) -> None:
        self.prepare(ID)
        self.prepare(SECOND)
        first = self.make_fixture("snapshot-a", 9)
        second = self.make_fixture("snapshot-b", 20)
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(self.compile_fixture, ID, first)
            b = pool.submit(self.compile_fixture, SECOND, second)
            self.assertEqual(a.result(), "11")
            self.assertEqual(b.result(), "22")
        marker = (self.job() / ".rch-stage-owner").read_bytes()
        binary = self.destination() / "target/answer"
        stamp = binary.stat().st_mtime_ns
        # A new shell/process recovers the existing capability. It neither
        # prepares a replacement invocation nor runs the build again.
        self.assertEqual(self.verify().returncode, 0)
        recovered = self.root / "recovered-artifacts"
        recovered.mkdir()
        result = subprocess.run(["rsync", "-a", "--safe-links", str(binary), str(recovered) + "/"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(subprocess.check_output([str(recovered / "answer")], text=True).strip(), "11")
        self.assertEqual(binary.stat().st_mtime_ns, stamp)
        self.assertEqual((self.job() / ".rch-stage-owner").read_bytes(), marker)
        self.assertFalse((first / "app/target").exists(), "local developer source was not built in place")
        self.assert_protected()


if __name__ == "__main__":
    unittest.main(verbosity=2)
