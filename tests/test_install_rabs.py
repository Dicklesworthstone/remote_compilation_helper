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
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install-rabs"
MAIN_INSTALLER = SCRIPT.parents[1] / "install.sh"
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


@unittest.skipUnless(sys.platform == "linux", "Linux installation contract")
class MainInstallerTests(unittest.TestCase):
    """Run the actual main installer with real archive/generation operations.

    Native `true` binaries stand in for compiled programs. Cargo, SSH and
    package downloads are fixtures: these prove installation and build-command
    wiring, not a Rust compilation, worker deployment or cache acceleration.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rabs-main-install-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.bin = self.root / "bin"
        self.commands = self.root / "commands"
        self.commands.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.native = shutil.which("true")
        self.assertIsNotNone(self.native)
        for name in ("rch", "rchd", "rch-wkr", "rabs-wrap", "rabsd", "rabs-wkr"):
            shutil.copyfile(self.native, self.bundle / name)
            (self.bundle / name).chmod(0o755)
        for name in ("install-rabs", "cargo-rabs"):
            shutil.copyfile(SCRIPT.with_name(name), self.bundle / name)
            (self.bundle / name).chmod(0o755)
        for name in ("rustup", "rsync", "zstd"):
            self.command(name, "printf '%s\\n' 'installer fixture'\n")
        self.command("curl", "echo 'unexpected network access' >&2\nexit 90\n")
        self.command("ssh", "echo 'unexpected SSH access' >&2\nexit 91\n")
        self.environment = dict(os.environ, HOME=str(self.home),
                                PATH=str(self.commands) + os.pathsep + os.environ["PATH"],
                                RCH_INSTALL_DIR=str(self.bin),
                                RCH_CONFIG_DIR=str(self.root / "config"),
                                RCH_RUNTIME_DIR=str(self.root / "runtime"),
                                RCH_INSTALLER_LIB="1", RCH_NO_RC="1", RCH_NO_HOOK="1",
                                RCH_SKIP_FLEET_SYNC="1", RCH_SKIP_DAEMON_RESTART="1",
                                RCH_SKIP_DOCTOR="1", NO_GUM="1", RCH_NO_COLOR="1",
                                VERSION="2.9.0", TMPDIR=str(self.root))
        self.environment.pop("RCH_RABS_INSTALL_DIR", None)
        self.environment.pop("CARGO_TARGET_DIR", None)
        self.environment.pop("CARGO_BUILD_TARGET", None)

    def command(self, name, body):
        path = self.commands / name
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def archive(self, exclude=()):
        path = self.root / "rch-v2.9.0-x86_64-unknown-linux-gnu.tar.gz"
        with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for item in sorted(self.bundle.iterdir()):
                if item.name not in exclude:
                    archive.add(item, arcname=item.name)
        return path

    def shell(self, body, arguments=(), environment=None, cwd=None):
        return subprocess.run(
            ["bash", "-c", 'source "$1"\nLOCK_FILE="$2"\nshift 2\n' + body,
             "installer-test", str(MAIN_INSTALLER), str(self.root / "install.lock"), *arguments],
            cwd=cwd or self.root, env=environment or self.environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)

    def main(self, *arguments):
        return self.shell('main "$@"',
                          ["--worker", "--no-service", "--yes", *arguments])

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_complete_generation(self, bin_dir=None):
        bin_dir = bin_dir or self.bin
        generation = (bin_dir / installer.CURRENT).resolve(strict=True)
        manifest = json.loads((generation / "manifest.json").read_text())
        self.assertEqual(set(manifest["files"]), set(installer.TOOLS))
        for name in installer.TOOLS:
            self.assertEqual((bin_dir / name).resolve(strict=True).parent, generation)
            self.assertEqual((bin_dir / name).read_bytes(), (self.bundle / name).read_bytes())
        self.assertEqual(subprocess.run([str(bin_dir / "cargo-rabs"), "--help"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode, 0)
        return generation

    def test_offline_opt_in_installs_launcher_and_all_binaries_and_upgrades_atomically(self):
        archive = self.archive()
        first = self.main("--with-rabs", "--offline", str(archive))
        self.assert_success(first)
        before = self.assert_complete_generation()
        self.assertIn('"services_started": false', first.stdout)
        self.assertIn('"cargo_config_changed": false', first.stdout)
        self.assertTrue((self.bin / "rch-wkr").is_file())
        second = self.main("--with-rabs", "--offline", str(archive))
        self.assert_success(second)
        after = self.assert_complete_generation()
        self.assertNotEqual(before, after)
        self.assertTrue((before / "rabsd").is_file())
        self.assertFalse((self.home / ".cargo").exists())
        self.assertFalse((self.home / ".config" / "systemd").exists())

    def test_core_only_offline_install_does_not_install_any_rabs_tools(self):
        result = self.main("--offline", str(self.archive()))
        self.assert_success(result)
        self.assertTrue((self.bin / "rch-wkr").is_file())
        self.assertTrue(all(not (self.bin / name).exists() for name in installer.TOOLS))
        self.assertFalse((self.bin / installer.CURRENT).exists())

    def test_local_mode_also_installs_a_complete_rabs_generation(self):
        result = self.shell('main "$@"',
                            ["--local", "--with-rabs", "--offline", str(self.archive()),
                             "--no-service", "--yes"])
        self.assert_success(result)
        self.assert_complete_generation()
        self.assertTrue((self.bin / "rch").is_file())
        self.assertTrue((self.bin / "rchd").is_file())

    def test_incomplete_requested_release_fails_and_keeps_the_previous_generation(self):
        self.assert_success(self.main("--with-rabs", "--offline", str(self.archive())))
        before = self.assert_complete_generation()
        for missing in ("rabsd", "cargo-rabs", "install-rabs"):
            with self.subTest(missing=missing):
                result = self.main("--with-rabs", "--offline", str(self.archive(exclude={missing})))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("RABS", result.stderr)
                self.assertNotIn("Installation Complete!", result.stdout)
                self.assertEqual((self.bin / installer.CURRENT).resolve(), before)

    def test_unmanaged_tool_is_preserved_and_separate_directory_is_supported(self):
        self.bin.mkdir()
        previous = self.bin / "rabsd"
        previous.write_bytes(b"previous unmanaged daemon")
        archive = self.archive()
        result = self.main("--with-rabs", "--offline", str(archive))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(previous.read_bytes(), b"previous unmanaged daemon")
        self.assertIn("RCH_RABS_INSTALL_DIR", result.stderr)
        self.environment["RCH_RABS_INSTALL_DIR"] = str(self.root / "separate bin")
        self.assert_success(self.main("--with-rabs", "--offline", str(archive)))
        self.assert_complete_generation(self.root / "separate bin")
        self.assertEqual(previous.read_bytes(), b"previous unmanaged daemon")

    def test_opt_in_selects_gnu_release_and_runs_download_install_path(self):
        archive = self.archive()
        requests = self.root / "downloads"
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.command("curl", """
url= destination=
while [ "$#" -gt 0 ]; do
  case "$1" in
    https://*) url=$1; shift ;;
    -o) destination=$2; shift 2 ;;
    --proxy) shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\\n' "$url" >> """ + shlex.quote(str(requests)) + """
case "$url" in
  *-unknown-linux-gnu.tar.gz) cp """ + shlex.quote(str(archive)) + """ "$destination" ;;
  *-unknown-linux-gnu.tar.gz.sha256) printf '%s\\n' """ + shlex.quote(checksum) + """ > "$destination" ;;
  *) exit 92 ;;
esac
""")
        result = self.main("--with-rabs")
        self.assert_success(result)
        self.assert_complete_generation()
        downloads = requests.read_text().splitlines()
        self.assertEqual(len(downloads), 2)
        self.assertTrue(all("-unknown-linux-gnu.tar.gz" in url for url in downloads))
        self.assertTrue(all("musl" not in url for url in downloads))

    def source_tree(self):
        project = self.root / "source"
        project.mkdir()
        (project / "Cargo.toml").write_text(
            '# remote_compilation_helper fixture\n[workspace]\n[workspace.package]\nversion = "2.9.0"\n')
        (project / "scripts").mkdir()
        for name in ("install-rabs", "cargo-rabs"):
            shutil.copyfile(self.bundle / name, project / "scripts" / name)
            (project / "scripts" / name).chmod(0o755)
        target = self.root / "custom target"
        (target / "wrapper-release").mkdir(parents=True)
        (target / "daemon-release").mkdir()
        for name in ("rch", "rabs-wrap"):
            shutil.copyfile(self.bundle / name, target / "wrapper-release" / name)
            (target / "wrapper-release" / name).chmod(0o755)
        for name in ("rchd", "rch-wkr", "rabsd", "rabs-wkr"):
            shutil.copyfile(self.bundle / name, target / "daemon-release" / name)
            (target / "daemon-release" / name).chmod(0o755)
        self.environment["CARGO_TARGET_DIR"] = str(target)
        return project

    def run_source(self, project, with_rabs=True, failing_package=""):
        builds = self.root / "build-commands"
        self.command("cargo", "printf '%s\\n' \"$*\" >> " + shlex.quote(str(builds)) + "\n"
                     + ("case \" $* \" in *' -p " + failing_package + " '*) exit 23;; esac\n"
                        if failing_package else ""))
        body = ("MODE=worker\nVERSION_EXPLICIT=false\nWITH_RABS="
                + ("true" if with_rabs else "false")
                + '\nmkdir -p "$INSTALL_DIR"\nbuild_from_source\n')
        return self.shell(body, cwd=project), builds

    def test_source_opt_in_installs_from_both_profiles_with_the_launcher(self):
        result, builds = self.run_source(self.source_tree())
        self.assert_success(result)
        self.assert_complete_generation()
        self.assertEqual(builds.read_text().splitlines(), [
            "build --locked --profile wrapper-release -p rch",
            "build --locked --profile daemon-release -p rchd -p rch-wkr",
            "build --locked --profile wrapper-release -p rabs-wrap",
            "build --locked --profile daemon-release -p rabsd -p rabs-wkr",
        ])

    def test_release_source_fallback_clones_the_tag_and_installs_all_rabs_tools(self):
        project = self.source_tree()
        for arguments in (["init", "-b", "main"], ["add", "Cargo.toml", "scripts"],
                          ["-c", "user.name=RABS installer test", "-c", "user.email=rabs-test@localhost",
                           "-c", "commit.gpgsign=false", "commit", "-m", "Source installation fixture"],
                          ["tag", "v2.9.0"]):
            result = subprocess.run(["git", *arguments], cwd=project, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assert_success(result)
        builds = self.root / "cloned-build-commands"
        self.command("cargo", "printf '%s\\n' \"$*\" >> " + shlex.quote(str(builds)) + "\n")
        result = self.shell('MODE=worker\nWITH_RABS=true\nREPO_URL="$1"\n'
                            'mkdir -p "$INSTALL_DIR"\nclone_and_build_from_source\n',
                            [project.as_uri()])
        self.assert_success(result)
        self.assert_complete_generation()
        self.assertIn("--profile wrapper-release -p rabs-wrap", builds.read_text())
        self.assertIn("--profile daemon-release -p rabsd -p rabs-wkr", builds.read_text())
        self.assertTrue((self.bin / "rch-wkr").is_file())

    def test_source_failure_never_installs_stale_rabs_build_outputs(self):
        result, _ = self.run_source(self.source_tree(), failing_package="rabsd")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RABS daemon/worker build failed", result.stderr)
        self.assertFalse((self.bin / installer.CURRENT).exists())
        self.assertFalse((self.bin / "rch-wkr").exists())

    def test_core_only_source_skips_rabs_builds_and_leftover_outputs(self):
        result, builds = self.run_source(self.source_tree(), with_rabs=False)
        self.assert_success(result)
        self.assertNotIn("rabs", builds.read_text())
        self.assertFalse((self.bin / installer.CURRENT).exists())
        self.assertFalse((self.bin / "rabs-wkr").exists())

    def test_unsupported_platform_refuses_before_installing_tools(self):
        self.command("uname", 'case "$1" in -s) echo Darwin;; -m) echo arm64;; esac\n')
        result = self.main("--with-rabs", "--offline", str(self.archive()))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Linux GNU", result.stderr)
        self.assertFalse(self.bin.exists())

    def test_musl_host_refuses_before_installing_gnu_binaries(self):
        self.command("getconf", "exit 1\n")
        result = self.main("--with-rabs", "--offline", str(self.archive()))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GNU libc", result.stderr)
        self.assertFalse(self.bin.exists())

    def test_verify_only_checks_the_requested_launcher(self):
        self.assert_success(self.main("--offline", str(self.archive())))
        result = self.main("--with-rabs", "--verify-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cargo-rabs", result.stderr)

    def test_unrunnable_native_elf_cannot_report_installation_success(self):
        self.assert_success(self.main("--with-rabs", "--offline", str(self.archive())))
        previous = self.assert_complete_generation()
        before = (self.bin / "rabsd").read_bytes()
        daemon = self.bundle / "rabsd"
        # A complete native ELF header passes the distribution identity check,
        # but its missing program segments make the actual OS launch fail.
        daemon.write_bytes(daemon.read_bytes()[:64])
        result = self.main("--with-rabs", "--offline", str(self.archive()))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rabsd cannot execute on this host", result.stderr)
        self.assertNotIn("Installation Complete!", result.stdout)
        self.assertEqual((self.bin / installer.CURRENT).resolve(), previous)
        self.assertEqual((self.bin / "rabsd").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
