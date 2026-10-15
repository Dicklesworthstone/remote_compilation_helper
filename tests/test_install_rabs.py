"""Real filesystem/process tests of RABS installation, not compiler-cache proofs."""

import contextlib
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install-rabs"
loader = importlib.machinery.SourceFileLoader("install_rabs", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
installer = importlib.util.module_from_spec(spec)
loader.exec_module(installer)


@unittest.skipUnless(sys.platform == "linux", "Linux installation contract")
class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rabs-install-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.bin = self.root / "bin"
        # A real native ELF fixture, not a claimed rabsd/rustc build.
        executable = shutil.which("true")
        self.assertIsNotNone(executable)
        for name in installer.TOOLS[1:]:
            shutil.copyfile(executable, self.bundle / name)
            (self.bundle / name).chmod(0o755)
        self.launcher("first")

    def launcher(self, label):
        (self.bundle / "cargo-rabs").write_text(
            "#!/usr/bin/env python3\nfrom pathlib import Path\n"
            "print(" + repr(label) + ")\n"
            "print(Path(__file__).resolve().parent)\n", encoding="utf-8")
        (self.bundle / "cargo-rabs").chmod(0o755)

    def run_install(self):
        return installer.install(
            installer.source_files(self.bundle, None), self.bin, installer.host_machine())

    def current(self):
        return os.readlink(self.bin / installer.CURRENT)

    def test_complete_install_activates_native_executables_and_launcher_together(self):
        result = self.run_install()
        self.assertFalse(result["services_started"])
        self.assertFalse(result["cargo_config_changed"])
        generation = self.bin / self.current()
        self.assertEqual(generation.name, result["generation"])
        manifest = json.loads((generation / "manifest.json").read_text())
        self.assertEqual(set(manifest["files"]), set(installer.TOOLS))
        for name in installer.TOOLS:
            self.assertEqual(os.readlink(self.bin / name), ".rabs-current/" + name)
            self.assertEqual((self.bin / name).resolve().parent, generation)
            self.assertEqual((self.bin / name).read_bytes(), (self.bundle / name).read_bytes())
            self.assertEqual(manifest["files"][name]["sha256"],
                             hashlib.sha256((generation / name).read_bytes()).hexdigest())
            self.assertEqual((generation / name).stat().st_mode & 0o777, 0o555)
        output = subprocess.check_output([str(self.bin / "cargo-rabs")], text=True)
        self.assertEqual(output.splitlines(), ["first", str(generation)])

    def test_upgrade_retains_old_generation_and_existing_public_links(self):
        self.run_install()
        old = self.current()
        old_launcher = (self.bin / old / "cargo-rabs").read_bytes()
        links = {name: (self.bin / name).lstat().st_ino for name in installer.TOOLS}
        self.launcher("second")
        self.run_install()
        self.assertNotEqual(old, self.current())
        self.assertEqual((self.bin / old / "cargo-rabs").read_bytes(), old_launcher)
        self.assertEqual(links, {name: (self.bin / name).lstat().st_ino for name in installer.TOOLS})
        self.assertIn("second", subprocess.check_output([str(self.bin / "cargo-rabs")], text=True))

    def test_missing_member_fails_before_creating_install_directory(self):
        (self.bundle / "rabs-wkr").rename(self.bundle / "not-rabs-wkr")
        with self.assertRaises(FileNotFoundError):
            self.run_install()
        self.assertFalse(self.bin.exists())

    def test_failed_upgrade_never_switches_the_active_generation(self):
        self.run_install()
        old = self.current()
        bad = bytearray((self.bundle / "rabs-wkr").read_bytes())
        bad[18:20] = (0).to_bytes(2, "little")
        (self.bundle / "rabs-wkr").write_bytes(bad)
        self.launcher("must-not-activate")
        with self.assertRaisesRegex(installer.InstallError, "native Linux ELF64"):
            self.run_install()
        self.assertEqual(self.current(), old)
        self.assertTrue(subprocess.check_output([str(self.bin / "cargo-rabs")], text=True)
                        .startswith("first\n"))

    def test_late_copy_failure_does_not_replace_any_old_tool(self):
        self.run_install()
        old = self.current()
        original = installer.copy_tool

        def fail_last(name, *args):
            if name == "rabs-wkr":
                raise OSError("simulated full filesystem")
            return original(name, *args)

        with mock.patch.object(installer, "copy_tool", side_effect=fail_last):
            with self.assertRaisesRegex(OSError, "full filesystem"):
                self.run_install()
        self.assertEqual(self.current(), old)
        self.assertTrue(all((self.bin / name).resolve().parent == self.bin / old
                            for name in installer.TOOLS))

    def test_wrong_elf_class_endianness_type_and_architecture_are_refused(self):
        original = (self.bundle / "rabs-wrap").read_bytes()
        for offset, replacement in [(0, b"MZ"), (4, b"\x01"), (5, b"\x02"),
                                    (16, b"\x01\x00"), (18, b"\x00\x00")]:
            with self.subTest(offset=offset):
                changed = bytearray(original)
                changed[offset:offset + len(replacement)] = replacement
                (self.bundle / "rabs-wrap").write_bytes(changed)
                with self.assertRaises(installer.InstallError):
                    self.run_install()
                self.assertFalse((self.bin / installer.CURRENT).exists())

    def test_malformed_launcher_refuses_before_activation(self):
        (self.bundle / "cargo-rabs").write_text("#!/usr/bin/env python3\nthis is (\n")
        with self.assertRaises(SyntaxError):
            self.run_install()
        self.assertFalse((self.bin / installer.CURRENT).exists())

    def test_source_symlink_is_never_followed(self):
        path = self.bundle / "rabsd"
        path.rename(self.bundle / "real-rabsd")
        path.symlink_to("real-rabsd")
        with self.assertRaisesRegex(installer.InstallError, "regular executable"):
            self.run_install()
        self.assertFalse(self.bin.exists())

    def test_unmanaged_existing_binary_is_not_overwritten(self):
        self.bin.mkdir()
        old = self.bin / "rabsd"
        old.write_bytes(b"existing operator installation")
        with self.assertRaisesRegex(installer.InstallError, "unmanaged entry"):
            self.run_install()
        self.assertEqual(old.read_bytes(), b"existing operator installation")
        self.assertFalse((self.bin / installer.VERSIONS).exists())

    def test_unmanaged_symlinks_are_not_retargeted(self):
        self.bin.mkdir()
        for name, target in [("rabsd", "../other-rabsd"),
                             (installer.CURRENT, "../other-generation")]:
            with self.subTest(name=name):
                link = self.bin / name
                link.symlink_to(target)
                with self.assertRaisesRegex(installer.InstallError, "unmanaged symlink"):
                    self.run_install()
                self.assertEqual(os.readlink(link), target)
                link.rename(self.root / (name + "-saved"))

    def test_unsafe_directory_and_lock_are_refused(self):
        self.bin.mkdir()
        self.bin.chmod(0o777)
        with self.assertRaisesRegex(installer.InstallError, "unsafe ownership"):
            self.run_install()
        self.bin.chmod(0o755)
        target = self.root / "unrelated"
        target.write_bytes(b"leave alone")
        (self.bin / ".rabs-install.lock").symlink_to(target)
        with self.assertRaises(OSError):
            self.run_install()
        self.assertEqual(target.read_bytes(), b"leave alone")

    def test_competing_installer_cannot_activate(self):
        self.run_install()
        current = self.current()
        with (self.bin / ".rabs-install.lock").open("r+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(installer.InstallError, "another RABS installation"):
                self.run_install()
        self.assertEqual(self.current(), current)

    def test_split_profiles_are_explicit_and_missing_daemon_is_not_best_effort(self):
        scripts = self.root / "checkout" / "scripts"
        scripts.mkdir(parents=True)
        shutil.copyfile(self.bundle / "cargo-rabs", scripts / "cargo-rabs")
        (scripts / "cargo-rabs").chmod(0o755)
        build = self.root / "custom-target" / "x86_64-unknown-linux-gnu"
        for name, profile in [("rabs-wrap", "wrapper-release"), ("rabsd", "daemon-release"),
                              ("rabs-wkr", "daemon-release")]:
            directory = build / profile
            directory.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.bundle / name, directory / name)
            (directory / name).chmod(0o755)
        with mock.patch.object(installer, "__file__", str(scripts / "install-rabs")):
            paths = installer.source_files(None, build)
            result = installer.install(paths, self.bin, installer.host_machine())
            self.assertEqual(set(result["files"]), set(installer.TOOLS))
            (build / "daemon-release" / "rabsd").rename(build / "daemon-release" / "absent")
            with self.assertRaises(FileNotFoundError):
                installer.source_files(None, build)

    def test_cli_reports_complete_install_and_preserves_cargo_configuration(self):
        home = self.root / "home"
        cargo = home / ".cargo"
        cargo.mkdir(parents=True)
        config = cargo / "config.toml"
        config.write_text('[build]\nrustc-wrapper = "existing-wrapper"\n')
        before = config.read_bytes()
        process = subprocess.run([sys.executable, str(SCRIPT), "--from-bundle", str(self.bundle),
                                  "--bin-dir", str(self.bin)], env={**os.environ, "HOME": str(home)},
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["kind"], "rabs-installed")
        self.assertFalse(result["services_started"])
        self.assertEqual(config.read_bytes(), before)

    def test_unsupported_platform_does_not_create_installation_state(self):
        for target in ["darwin", "win32"]:
            with mock.patch.object(installer.sys, "platform", target):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(installer.main(["--from-bundle", str(self.bundle),
                                                     "--bin-dir", str(self.bin)]), 1)
            self.assertFalse(self.bin.exists())

    def archive(self, extra=None, omit=()):
        path = self.root / "release.tar.gz"
        with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name in installer.TOOLS:
                if name not in omit:
                    archive.add(self.bundle / name, arcname=name)
            if extra is not None:
                member, data = extra
                archive.addfile(member, io.BytesIO(data))
        return path

    def test_archive_install_and_upgrade_keep_core_files_untouched(self):
        member = tarfile.TarInfo("rch")
        member.size = 4
        path = self.archive(extra=(member, b"core"))
        self.bin.mkdir()
        core = self.bin / "rch"
        core.write_bytes(b"existing core")
        args = ["--from-archive", str(path), "--bin-dir", str(self.bin)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(installer.main(args), 0)
            first = self.current()
            self.assertEqual(installer.main(args), 0)
        self.assertNotEqual(first, self.current())
        self.assertEqual(core.read_bytes(), b"existing core")
        self.assertTrue((self.bin / first / "rabsd").is_file())

    def test_archive_missing_tool_is_not_a_best_effort_install(self):
        path = self.archive(omit=("rabs-wkr",))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(installer.main(["--from-archive", str(path),
                                             "--bin-dir", str(self.bin)]), 1)
        self.assertFalse(self.bin.exists())

    def test_archive_traversal_duplicates_links_and_special_files_are_refused(self):
        bad_members = []
        for name in ("../escaped", "/absolute", "./rabsd", "rabsd", "unexpected"):
            member = tarfile.TarInfo(name)
            member.size = 1
            bad_members.append((member, b"x"))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE):
            member = tarfile.TarInfo("rch")
            member.type = kind
            member.linkname = "../escaped"
            bad_members.append((member, b""))
        for member, data in bad_members:
            with self.subTest(name=member.name, kind=member.type):
                path = self.archive(extra=(member, data))
                with tempfile.TemporaryDirectory(dir=self.root) as destination:
                    with self.assertRaises(installer.InstallError):
                        installer.unpack_archive(path, Path(destination))
                self.assertFalse((self.root / "escaped").exists())
                self.assertFalse(self.bin.exists())

    def test_expanded_archive_budget_is_enforced_before_activation(self):
        path = self.archive()
        # The compressed archive fits while its real ELF payload does not.
        limit = path.stat().st_size + 1
        with mock.patch.object(installer, "MAX_ARCHIVE_BYTES", limit):
            with tempfile.TemporaryDirectory(dir=self.root) as destination:
                with self.assertRaisesRegex(installer.InstallError, "expanded byte limit"):
                    installer.unpack_archive(path, Path(destination))

    def test_truncated_archive_cannot_switch_an_existing_installation(self):
        self.run_install()
        before = self.current()
        path = self.archive()
        path.write_bytes(path.read_bytes()[:100])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(installer.main(["--from-archive", str(path),
                                             "--bin-dir", str(self.bin)]), 1)
        self.assertEqual(before, self.current())

    def test_archive_symlink_is_not_followed(self):
        path = self.archive()
        alias = self.root / "archive-link"
        alias.symlink_to(path)
        with tempfile.TemporaryDirectory(dir=self.root) as destination:
            with self.assertRaises(OSError):
                installer.unpack_archive(alias, Path(destination))

    def test_extension_headers_are_refused_before_payload_decoding(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                     tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind):
                member = tarfile.TarInfo("rch")
                member.type = kind
                member.size = 1
                path = self.archive(extra=(member, b"x"))
                with tempfile.TemporaryDirectory(dir=self.root) as destination:
                    with self.assertRaisesRegex(installer.InstallError, "unsupported release archive header"):
                        installer.unpack_archive(path, Path(destination))


if __name__ == "__main__":
    unittest.main()
