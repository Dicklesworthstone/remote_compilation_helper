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
import time
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
        self.bin.mkdir(mode=0o755)
        old = self.bin / "rabsd"
        old.write_bytes(b"existing operator installation")
        with self.assertRaisesRegex(installer.InstallError, "unmanaged entry"):
            self.run_install()
        self.assertEqual(old.read_bytes(), b"existing operator installation")
        self.assertFalse((self.bin / installer.VERSIONS).exists())

    def test_unmanaged_symlinks_are_not_retargeted(self):
        self.bin.mkdir(mode=0o755)
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
                              ("rabs-wkr", "daemon-release"), ("rabs-cargo-root", "daemon-release")]:
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
        self.bin.mkdir(mode=0o755)
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
        for name in ("rch", "rchd", "rch-wkr", "rabs-wrap", "rabsd", "rabs-wkr", "rabs-cargo-root"):
            shutil.copyfile(self.native, self.bundle / name)
            (self.bundle / name).chmod(0o755)
        for name in ("install-rabs", "cargo-rabs"):
            shutil.copyfile(SCRIPT.with_name(name), self.bundle / name)
            (self.bundle / name).chmod(0o755)
        for name in ("rustup", "rsync", "zstd"):
            self.command(name, "printf '%s\\n' 'installer fixture'\n")
        self.source_host = next(target for target, machine in installer.TARGET_MACHINES.items()
                                if machine == installer.host_machine())
        self.command("rustc", '[ "$*" = -vV ] || exit 97\nprintf \'%s\\n\' '
                     + shlex.quote("rustc fixture") + " "
                     + shlex.quote("host: " + self.source_host) + "\n")
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
        self.bin.mkdir(mode=0o755)
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
        target_base = self.root / "custom target"
        target = target_base / self.source_host
        (target / "wrapper-release").mkdir(parents=True)
        (target / "daemon-release").mkdir()
        # Retained executable outputs must not stand in for this invocation's
        # artifacts. The Cargo double below overwrites only its selected paths.
        stale_marker = b"\nretained source build output\n"
        for name in ("rch", "rabs-wrap"):
            (target / "wrapper-release" / name).write_bytes(
                (self.bundle / name).read_bytes() + stale_marker)
            (target / "wrapper-release" / name).chmod(0o755)
        for name in ("rchd", "rch-wkr", "rabsd", "rabs-wkr", "rabs-cargo-root"):
            (target / "daemon-release" / name).write_bytes(
                (self.bundle / name).read_bytes() + stale_marker)
            (target / "daemon-release" / name).chmod(0o755)
        self.environment["CARGO_TARGET_DIR"] = str(target_base)
        return project

    def source_cargo(self, builds, failing_package=""):
        # An explicit compiler double emits real native ELF fixtures into the
        # requested Cargo layout; it does not claim to compile Rust sources.
        self.command("cargo", "printf '%s\\n' \"$*\" >> " + shlex.quote(str(builds)) + "\n"
                     + ("case \" $* \" in *' -p " + failing_package + " '*) exit 23;; esac\n"
                        if failing_package else "") + r'''
target_dir=${CARGO_TARGET_DIR:-target}
target=${CARGO_BUILD_TARGET:-}
profile= packages=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --target-dir) target_dir=$2; shift 2 ;;
        --target) target=$2; shift 2 ;;
        --profile) profile=$2; shift 2 ;;
        -p) packages="$packages $2"; shift 2 ;;
        --bin) shift 2 ;;
        *) shift ;;
    esac
done
output="$target_dir${target:+/$target}/$profile"
mkdir -p "$output"
for package in $packages; do
    case "$package" in
        rabs-wkr) names='rabs-wkr rabs-cargo-root' ;;
        *) names=$package ;;
    esac
    for name in $names; do
        cp ''' + shlex.quote(str(self.bundle)) + r'''/"$name" "$output/$name"
        chmod 755 "$output/$name"
    done
done
''')

    def run_source(self, project, with_rabs=True, failing_package=""):
        builds = self.root / "build-commands"
        self.source_cargo(builds, failing_package)
        body = ("MODE=worker\nVERSION_EXPLICIT=false\nWITH_RABS="
                + ("true" if with_rabs else "false")
                + '\nmkdir -m 0755 -p "$INSTALL_DIR"\nbuild_from_source\n')
        return self.shell(body, cwd=project), builds

    def test_source_opt_in_installs_from_both_profiles_with_the_launcher(self):
        result, builds = self.run_source(self.source_tree())
        self.assert_success(result)
        self.assert_complete_generation()
        layout = (f" --target-dir {self.environment['CARGO_TARGET_DIR']}"
                  f" --target {self.source_host}")
        self.assertEqual(builds.read_text().splitlines(), [
            "build --locked --profile wrapper-release -p rch --bin rch" + layout,
            "build --locked --profile daemon-release -p rchd -p rch-wkr"
            " --bin rchd --bin rch-wkr" + layout,
            "build --locked --profile wrapper-release -p rabs-wrap --bin rabs-wrap" + layout,
            "build --locked --profile daemon-release -p rabsd -p rabs-wkr"
            " --bin rabsd --bin rabs-wkr --bin rabs-cargo-root" + layout,
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
        self.source_cargo(builds)
        result = self.shell('MODE=worker\nWITH_RABS=true\nREPO_URL="$1"\n'
                            'mkdir -m 0755 -p "$INSTALL_DIR"\nclone_and_build_from_source\n',
                            [project.as_uri()])
        self.assert_success(result)
        self.assert_complete_generation()
        self.assertIn("--profile wrapper-release -p rabs-wrap", builds.read_text())
        self.assertIn("--profile daemon-release -p rabsd -p rabs-wkr", builds.read_text())
        for invocation in builds.read_text().splitlines():
            self.assertIn(f"--target-dir {self.environment['CARGO_TARGET_DIR']}"
                          f" --target {self.source_host}", invocation)
        self.assertEqual((self.bin / "rch-wkr").read_bytes(),
                         (self.bundle / "rch-wkr").read_bytes())

    def test_source_failure_never_installs_stale_rabs_build_outputs(self):
        result, _ = self.run_source(self.source_tree(), failing_package="rabsd")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RABS daemon/worker build failed", result.stderr)
        self.assertFalse((self.bin / installer.CURRENT).exists())
        self.assertFalse((self.bin / "rch-wkr").exists())

    def test_core_only_source_skips_rabs_builds_and_leftover_outputs(self):
        result, builds = self.run_source(self.source_tree(), with_rabs=False)
        self.assert_success(result)
        self.assertNotIn(" -p rabs", builds.read_text())
        self.assertNotIn(" --bin rabs", builds.read_text())
        self.assertEqual((self.bin / "rch-wkr").read_bytes(),
                         (self.bundle / "rch-wkr").read_bytes())
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


@unittest.skipUnless(sys.platform == "linux", "Linux archive/install contract")
class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rabs-package-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.bin = self.root / "bin"
        self.output = self.root / "release.tar.gz"
        self.target = next(target for target, machine in installer.TARGET_MACHINES.items()
                           if machine == installer.host_machine())
        executable = shutil.which("true")
        self.assertIsNotNone(executable)
        # Real ELF fixtures test distribution, not source identity or RABS execution.
        for name in installer.TOOLS[1:]:
            shutil.copyfile(executable, self.bundle / name)
            (self.bundle / name).chmod(0o755)
        (self.bundle / "cargo-rabs").write_text(
            "#!/usr/bin/env python3\nprint('packaged launcher')\n", encoding="utf-8")
        (self.bundle / "cargo-rabs").chmod(0o755)

    def package(self, output=None, target=None):
        return installer.package_archive(installer.source_files(self.bundle, None),
                                         output or self.output, target or self.target)

    def main(self, *arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = installer.main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_exact_flat_archive_installs_and_verifies_without_executing_tools(self):
        expected = installer.expected_toolset(installer.source_files(self.bundle, None))
        with mock.patch.object(installer.subprocess, "Popen", side_effect=AssertionError("executed tool")):
            result = self.package()
            self.assertFalse(self.bin.exists())
            code, _, error = self.main("--from-archive", str(self.output), "--bin-dir", str(self.bin))
            self.assertEqual(code, 0, error)
            code, stdout, error = self.main("--verify", "--from-archive", str(self.output),
                                           "--bin-dir", str(self.bin))
            self.assertEqual(code, 0, error)
            self.assertEqual(json.loads(stdout)["state"], "verified")
        self.assertEqual(result["toolset"], expected)
        self.assertEqual(result["bytes"], self.output.stat().st_size)
        self.assertEqual(result["sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertFalse(result["services_started"])
        self.assertFalse(result["cargo_config_changed"])
        self.assertTrue(Path(result["staging_directory"]).is_dir())
        with tarfile.open(self.output, "r:gz") as archive:
            members = archive.getmembers()
            self.assertEqual([member.name for member in members],
                             list(installer.TOOLS) + ["install-rabs"])
            for member in members:
                self.assertTrue(member.isreg())
                self.assertEqual(member.mode, 0o755)
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual(member.pax_headers, {})
                source = SCRIPT if member.name == "install-rabs" else self.bundle / member.name
                self.assertEqual(archive.extractfile(member).read(), source.read_bytes())

    def test_identical_inputs_produce_identical_archive_bytes(self):
        first = self.package()
        second_path = self.root / "different-filename.tar.gz"
        second = self.package(output=second_path)
        self.assertEqual(self.output.read_bytes(), second_path.read_bytes())
        self.assertEqual(first["sha256"], second["sha256"])

    def test_cross_architecture_packaging_does_not_execute_supplied_binaries(self):
        target, machine = next((target, machine) for target, machine in installer.TARGET_MACHINES.items()
                               if target != self.target)
        for name in installer.TOOLS[1:]:
            data = bytearray((self.bundle / name).read_bytes())
            data[18:20] = machine.to_bytes(2, "little")
            (self.bundle / name).write_bytes(data)
        with mock.patch.object(installer.subprocess, "Popen", side_effect=AssertionError("executed tool")):
            result = self.package(target=target)
        self.assertEqual(result["toolset"]["machine"], machine)
        self.assertEqual(result["target"], target)

    def test_split_profiles_use_the_checkout_launcher_and_explicit_target(self):
        build = self.root / "target"
        for profile in ("wrapper-release", "daemon-release"):
            (build / profile).mkdir(parents=True)
        for name in installer.TOOLS[1:]:
            profile = "wrapper-release" if name == "rabs-wrap" else "daemon-release"
            shutil.copy2(self.bundle / name, build / profile / name)
        code, stdout, error = self.main("--from-build", str(build), "--package", str(self.output),
                                       "--target", self.target)
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(stdout)["kind"], "rabs-packaged")
        with tarfile.open(self.output, "r:gz") as archive:
            self.assertEqual(archive.extractfile("cargo-rabs").read(),
                             SCRIPT.with_name("cargo-rabs").read_bytes())
        self.assertFalse(self.bin.exists())

    def test_wrong_target_missing_or_mixed_tools_never_publish(self):
        other = next(target for target in installer.TARGET_MACHINES if target != self.target)
        with self.assertRaisesRegex(installer.InstallError, "match --target"):
            self.package(target=other)
        with self.assertRaisesRegex(installer.InstallError, "supported Linux GNU"):
            installer.package_archive(installer.source_files(self.bundle, None), self.output, None)
        (self.bundle / "rabsd").rename(self.bundle / "saved-rabsd")
        with self.assertRaises(FileNotFoundError):
            self.package()
        (self.bundle / "saved-rabsd").rename(self.bundle / "rabsd")
        data = bytearray((self.bundle / "rabsd").read_bytes())
        data[18:20] = installer.TARGET_MACHINES[other].to_bytes(2, "little")
        (self.bundle / "rabsd").write_bytes(data)
        with self.assertRaisesRegex(installer.InstallError, "mixes executable architectures"):
            self.package()
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".rabs-package-*")))

    def test_symlink_and_invalid_launcher_inputs_are_refused(self):
        saved = self.bundle / "saved-rabsd"
        (self.bundle / "rabsd").rename(saved)
        (self.bundle / "rabsd").symlink_to(saved)
        with self.assertRaisesRegex(installer.InstallError, "regular executable"):
            self.package()
        (self.bundle / "rabsd").rename(self.bundle / "saved-link")
        saved.rename(self.bundle / "rabsd")
        (self.bundle / "cargo-rabs").write_text("#!/usr/bin/env python3\ninvalid (\n")
        with self.assertRaises(SyntaxError):
            self.package()
        self.assertFalse(self.output.exists())

    def test_late_input_change_is_detected_before_archive_publication(self):
        original = installer.copy_transfer_file

        def change_earlier_source(source, *args, **kwargs):
            result = original(source, *args, **kwargs)
            if Path(source).name == "rabs-cargo-root":
                with (self.bundle / "rabs-wrap").open("ab") as writer:
                    writer.write(b"changed after capture")
            return result

        with mock.patch.object(installer, "copy_transfer_file", side_effect=change_earlier_source):
            with self.assertRaisesRegex(installer.InstallError, "changed during capture"):
                self.package()
        self.assertFalse(self.output.exists())
        self.assertEqual(len(list(self.root.glob(".rabs-package-*"))), 1)

    def test_consumer_rejection_prevents_publication(self):
        with mock.patch.object(installer, "unpack_archive",
                               side_effect=installer.InstallError("consumer rejected archive")):
            with self.assertRaisesRegex(installer.InstallError, "consumer rejected archive"):
                self.package()
        self.assertFalse(self.output.exists())

    def test_existing_files_and_dangling_symlinks_are_never_replaced(self):
        self.output.write_bytes(b"existing release")
        with self.assertRaisesRegex(installer.InstallError, "replace an existing archive"):
            self.package()
        self.assertEqual(self.output.read_bytes(), b"existing release")
        link = self.root / "dangling.tar.gz"
        link.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(installer.InstallError, "replace an existing archive"):
            self.package(output=link)
        self.assertEqual(os.readlink(link), str(self.root / "absent"))
        self.assertFalse(list(self.root.glob(".rabs-package-*")))

    def test_archive_changed_after_consumer_verification_is_not_published(self):
        original = installer.unpack_archive

        def replace_verified_archive(path, *args, **kwargs):
            original(path, *args, **kwargs)
            path.chmod(0o600)
            path.write_bytes(b"not a gzip archive")

        with mock.patch.object(installer, "unpack_archive", side_effect=replace_verified_archive):
            with self.assertRaisesRegex(installer.InstallError, "archive changed"):
                self.package()
        self.assertFalse(self.output.exists())

    def test_bundled_installer_bytes_are_verified_too(self):
        original = installer.tarfile.TarFile.addfile

        def corrupt_installer(archive, member, reader=None):
            if member.name == "install-rabs":
                data = reader.read()
                reader = io.BytesIO(b"x" + data[1:])
            return original(archive, member, reader)

        with mock.patch.object(installer.tarfile.TarFile, "addfile", new=corrupt_installer):
            with self.assertRaisesRegex(installer.InstallError, "installer digest differs"):
                self.package()
        self.assertFalse(self.output.exists())

    def test_output_created_during_packaging_is_not_overwritten(self):
        original = installer.os.link

        def raced_publication(source, destination, **kwargs):
            self.output.write_bytes(b"concurrent release")
            return original(source, destination, **kwargs)

        with mock.patch.object(installer.os, "link", side_effect=raced_publication):
            with self.assertRaises(installer.InstallError):
                self.package()
        self.assertEqual(self.output.read_bytes(), b"concurrent release")

    def test_compressed_output_limit_is_enforced_during_writes(self):
        output = io.BytesIO()
        writer = installer.ArchiveWriter(output)
        with mock.patch.object(installer, "MAX_ARCHIVE_BYTES", 10):
            writer.write(b"1234567890")
            with self.assertRaisesRegex(installer.InstallError, "compressed byte limit"):
                writer.write(b"x")
        self.assertEqual(output.getvalue(), b"1234567890")

    def test_package_cli_rejects_install_deploy_and_verification_options(self):
        for extra in (["--verify"], ["--ssh", "worker.example"], ["--bin-dir", str(self.bin)],
                      ["--ssh-jobs", "2"], ["--ssh-timeout", "42"],
                      ["--from-archive", str(self.output)], ["--from-image", str(self.output)]):
            with self.subTest(extra=extra):
                code, _, error = self.main("--package", str(self.output), "--target", self.target, *extra)
                self.assertEqual(code, 1)
                self.assertIn("--package accepts only", error)
        code, _, error = self.main("--target", self.target)
        self.assertEqual(code, 1)
        self.assertIn("--target requires --package", error)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.bin.exists())

    def test_empty_output_or_missing_target_cannot_fall_through_to_installation(self):
        for arguments in (["--package", ""], ["--package", "", "--target", self.target],
                          ["--package", str(self.output)]):
            with self.subTest(arguments=arguments):
                with mock.patch.object(installer, "install", side_effect=AssertionError("installed")), \
                        mock.patch.object(installer, "source_files", side_effect=AssertionError("read inputs")):
                    code, _, error = self.main(*arguments)
                self.assertEqual(code, 1)
                self.assertIn("nonempty output path and --target", error)
        self.assertFalse(self.output.exists())


@unittest.skipUnless(sys.platform == "linux", "native source-probe process contract")
class PackageSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rabs-package-source-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir()
        self.repo = self.root / "source"
        (self.repo / "scripts").mkdir(parents=True)
        executable = shutil.which("true")
        self.assertIsNotNone(executable)
        for name in installer.TOOLS[1:]:
            shutil.copyfile(executable, self.snapshot / name)
            (self.snapshot / name).chmod(0o755)
        for name in ("cargo-rabs", "install-rabs"):
            data = ("#!/usr/bin/env python3\nprint(" + repr(name + " fixture") + ")\n").encode()
            (self.snapshot / name).write_bytes(data)
            (self.snapshot / name).chmod(0o755)
            (self.repo / "scripts" / name).write_bytes(data)
        self.git("init", "-q", "-b", "main", "--object-format=sha1")
        self.git("add", "scripts")
        self.git("commit", "-qm", "source fixture")
        self.source = self.git("rev-parse", "HEAD").decode().strip()
        self.refresh_expected()
        self.reports = {name: {"schema": 1, "kind": "rabs-build-info", "tool": name,
                               "version": "2.1.34", "compiled_source": self.source,
                               "build_identity": "rabs-2.1.34+" + self.source}
                        for name in installer.TOOLS[1:]}
        self.raw_reports = {}
        self.seen = []
        self.run_probe = installer.package_probe_output

    def git(self, *arguments):
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", str(self.repo),
             "-c", "user.name=RABS Fixture", "-c", "user.email=rabs@example.invalid",
             "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", *arguments],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def refresh_expected(self):
        self.expected = installer.expected_toolset(installer.source_files(self.snapshot, None))
        self.entries = {name: {"bytes": (self.snapshot / name).stat().st_size,
                               "sha256": hashlib.sha256((self.snapshot / name).read_bytes()).hexdigest()}
                        for name in installer.TOOLS + ("install-rabs",)}

    def dispatch_probe(self, argv, limit, deadline):
        if argv[0] == "git":
            self.assertIn("--no-replace-objects", argv)
            return self.run_probe(argv, limit, deadline)
        name = Path(argv[0]).name
        self.assertEqual(argv, [str(self.snapshot / name), "--rabs-build-info"])
        self.seen.append(name)
        data = self.raw_reports.get(name, json.dumps(self.reports[name]).encode())
        # Explicit report producer double: real ELF files are hashed, while
        # these Python children exercise process framing, not compiled Rust.
        return self.run_probe(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))",
             data.hex()], limit, deadline)

    def verify(self, source=None):
        with mock.patch.object(installer, "package_probe_output", side_effect=self.dispatch_probe):
            return installer.verify_package_source(self.snapshot, self.expected, self.entries,
                                                   self.source if source is None else source, self.repo)

    def test_four_exact_snapshot_probes_and_git_blobs_bind_the_receipt(self):
        self.assertEqual(self.verify(), {"commit": self.source, "version": "2.1.34",
                                         "build_identity": "rabs-2.1.34+" + self.source})
        self.assertEqual(self.seen, list(installer.TOOLS[1:]))

    def test_strict_package_cli_binds_captured_tools_and_refuses_mixed_source(self):
        # The producer ships its own installer. Pin those actual bytes in the
        # fixture repository so the complete CLI exercises both script checks.
        (self.repo / "scripts" / "install-rabs").write_bytes(SCRIPT.read_bytes())
        self.git("add", "scripts")
        self.git("commit", "-qm", "pin the actual archive producer")
        self.source = self.git("rev-parse", "HEAD").decode().strip()
        for report in self.reports.values():
            report.update(compiled_source=self.source, build_identity="rabs-2.1.34+" + self.source)
        target = next(target for target, machine in installer.TARGET_MACHINES.items()
                      if machine == installer.host_machine())
        captured_paths = []

        def captured_probe(argv, limit, deadline):
            if argv[0] == "git":
                return self.run_probe(argv, limit, deadline)
            path = Path(argv[0])
            self.assertEqual(argv[1:], ["--rabs-build-info"])
            self.assertEqual(path.parent.name, "inputs")
            self.assertNotEqual(path.parent, self.snapshot)
            self.assertEqual(path.read_bytes(), (self.snapshot / path.name).read_bytes())
            captured_paths.append(path)
            data = json.dumps(self.reports[path.name]).encode()
            return self.run_probe(
                [sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))",
                 data.hex()], limit, deadline)

        for mixed in (False, True):
            with self.subTest(mixed=mixed):
                self.reports["rabsd"]["compiled_source"] = "f" * 40 if mixed else self.source
                output = self.root / ("mixed.tar.gz" if mixed else "matched.tar.gz")
                stdout, stderr = io.StringIO(), io.StringIO()
                with mock.patch.object(installer, "package_probe_output", side_effect=captured_probe), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = installer.main(["--from-bundle", str(self.snapshot), "--package", str(output),
                                           "--target", target, "--require-source", self.source,
                                           "--source-repository", str(self.repo)])
                self.assertEqual(code, int(mixed), stderr.getvalue())
                self.assertEqual(output.exists(), not mixed)
                if mixed:
                    self.assertIn("identity differs from required source", stderr.getvalue())
                else:
                    receipt = json.loads(stdout.getvalue())
                    self.assertEqual(receipt["source_identity"], {
                        "commit": self.source, "version": "2.1.34",
                        "build_identity": "rabs-2.1.34+" + self.source})
                    with tarfile.open(output, "r:gz") as archive:
                        self.assertEqual(archive.extractfile("install-rabs").read(), SCRIPT.read_bytes())
        self.assertGreaterEqual(len(captured_paths), 6)

    def test_requested_commit_is_used_despite_dirty_worktree_and_new_head(self):
        (self.repo / "scripts" / "cargo-rabs").write_bytes(b"dirty checkout bytes")
        self.assertEqual(self.verify()["commit"], self.source)
        self.git("add", "scripts")
        self.git("commit", "-qm", "later source")
        self.assertNotEqual(self.git("rev-parse", "HEAD").decode().strip(), self.source)
        self.assertEqual(self.verify()["commit"], self.source)

    def test_invalid_source_and_non_native_toolset_refuse_before_probing(self):
        for source in ("", self.source[:12], self.source.upper(), self.source + "-dirty",
                       self.source + "+overlay-123", "main"):
            with self.subTest(source=source):
                with mock.patch.object(installer, "package_probe_output", side_effect=AssertionError("probed")):
                    with self.assertRaisesRegex(installer.InstallError, "full, clean, lowercase"):
                        installer.verify_package_source(self.snapshot, self.expected, self.entries, source, self.repo)
        self.expected["machine"] = next(machine for machine in installer.TARGET_MACHINES.values()
                                         if machine != installer.host_machine())
        with mock.patch.object(installer, "package_probe_output", side_effect=AssertionError("probed")):
            with self.assertRaisesRegex(installer.InstallError, "native executable"):
                installer.verify_package_source(self.snapshot, self.expected, self.entries, self.source, self.repo)

    def test_missing_commit_and_tree_object_are_not_commits(self):
        with self.assertRaisesRegex(installer.InstallError, "probe exit"):
            self.verify("0" * 40)
        tree = self.git("rev-parse", self.source + "^{tree}").decode().strip()
        with self.assertRaisesRegex(installer.InstallError, "not a Git commit object"):
            self.verify(tree)
        self.assertEqual(self.seen, [])

    def test_both_scripts_must_match_the_requested_git_blobs(self):
        for name in ("cargo-rabs", "install-rabs"):
            with self.subTest(name=name):
                path = self.snapshot / name
                original = path.read_bytes()
                path.write_bytes(original + b"# wrong source\n")
                self.refresh_expected()
                with self.assertRaisesRegex(installer.InstallError, "script differs from required source"):
                    self.verify()
                path.write_bytes(original)
                self.refresh_expected()
        self.assertEqual(self.seen, [])

    def test_wrong_missing_or_mixed_build_reports_are_refused(self):
        name = "rabs-wrap"
        valid = self.reports[name].copy()
        for changes in ({"schema": True}, {"kind": "other"}, {"tool": "rabsd"},
                        {"version": "invalid"}, {"version": "3.0.0"}, {"extra": True},
                        {"build_identity": "rabs-2.1.34"},
                        {"build_identity": "rabs-2.1.34+" + "f" * 40},
                        {"build_identity": "rabs-2.1.34+" + self.source + "-dirty"},
                        {"compiled_source": None}, {"compiled_source": self.source[:12]},
                        {"compiled_source": self.source + "-dirty"},
                        {"compiled_source": self.source + "+overlay-123"}):
            with self.subTest(changes=changes):
                self.reports[name] = {**valid, **changes}
                with self.assertRaises(installer.InstallError):
                    self.verify()
        self.reports[name] = valid
        self.reports["rabsd"].update(version="3.0.0", build_identity="rabs-3.0.0+" + self.source)
        with self.assertRaisesRegex(installer.InstallError, "versions differ"):
            self.verify()

    def test_malformed_empty_duplicate_and_incomplete_reports_are_refused(self):
        valid = json.dumps(self.reports["rabs-wrap"]).encode()
        for data in (b"", b"not JSON", b"\xff", b"[]", b'{}',
                     b'{"schema":1,' + valid[1:],
                     json.dumps({key: value for key, value in self.reports["rabs-wrap"].items()
                                 if key != "compiled_source"}).encode()):
            with self.subTest(data=data[:40]):
                self.raw_reports["rabs-wrap"] = data
                with self.assertRaises(installer.InstallError):
                    self.verify()

    def test_snapshot_replacement_after_a_probe_is_refused(self):
        dispatch = self.dispatch_probe

        def change_snapshot(argv, limit, deadline):
            output = dispatch(argv, limit, deadline)
            if Path(argv[0]).name == "rabs-cargo-root":
                with (self.snapshot / "install-rabs").open("ab") as writer:
                    writer.write(b"# changed during probe\n")
            return output

        with mock.patch.object(installer, "package_probe_output", side_effect=change_snapshot):
            with self.assertRaisesRegex(installer.InstallError, "snapshot changed"):
                installer.verify_package_source(self.snapshot, self.expected, self.entries, self.source, self.repo)

    def test_real_child_output_is_bounded_across_stdout_and_stderr(self):
        command = [sys.executable, "-c", "import os; os.write(1,b'a'*80); os.write(2,b'b'*80)"]
        with self.assertRaisesRegex(installer.InstallError, "output exceeded"):
            self.run_probe(command, 128, time.monotonic() + 2)
        command = [sys.executable, "-c", "import sys; sys.stderr.write('fixture failure'); sys.exit(23)"]
        with self.assertRaisesRegex(installer.InstallError, "probe exit 23: fixture failure"):
            self.run_probe(command, 128, time.monotonic() + 2)

    def test_closed_output_does_not_remove_the_process_deadline(self):
        command = [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(30)"]
        started = time.monotonic()
        with self.assertRaisesRegex(installer.InstallError, "deadline expired"):
            self.run_probe(command, 128, started + 0.2)
        self.assertLess(time.monotonic() - started, 3)

    def test_process_group_is_retired_before_reaping_releases_its_identity(self):
        original_signal = installer.os.killpg
        original_wait = installer.subprocess.Popen.wait
        events = []

        def signal_group(pid, sig):
            events.append("signal")
            return original_signal(pid, sig)

        def reap(child, timeout=None):
            self.assertIn("signal", events, "reaping permits the process-group ID to be recycled")
            events.append("reap")
            return original_wait(child, timeout=timeout)

        with mock.patch.object(installer.os, "killpg", side_effect=signal_group), \
                mock.patch.object(installer.subprocess.Popen, "wait", new=reap):
            output = self.run_probe([sys.executable, "-c", "print('complete')"],
                                    128, time.monotonic() + 2)
        self.assertEqual(output, b"complete\n")
        self.assertEqual(events, ["signal", "reap"])

    def test_reap_timeout_is_a_bounded_install_error(self):
        original_wait = installer.subprocess.Popen.wait
        children = []

        def unreapable(child, timeout=None):
            children.append(child)
            raise subprocess.TimeoutExpired(child.args, timeout)

        try:
            with mock.patch.object(installer.subprocess.Popen, "wait", new=unreapable):
                with self.assertRaisesRegex(installer.InstallError, "could not be reaped"):
                    self.run_probe([sys.executable, "-c", "pass"], 128, time.monotonic() + 2)
        finally:
            for child in children:
                original_wait(child, timeout=2)

    def test_timeout_kills_descendants_that_keep_output_open(self):
        pid_file = self.root / "descendant.pid"
        descendant = ("import os,sys,time; from pathlib import Path; "
                      "Path(sys.argv[1]).write_text(os.readlink('/proc/self')); time.sleep(30)")
        script = ("import subprocess,sys; subprocess.Popen([sys.executable,'-c',"
                  + repr(descendant) + ",sys.argv[1]])")
        with self.assertRaisesRegex(installer.InstallError, "deadline expired"):
            self.run_probe([sys.executable, "-c", script, str(pid_file)], 128, time.monotonic() + 0.3)
        # /proc can expose the outer PID namespace in a build sandbox. The
        # descendant records its own mounted-proc identity, not Popen's PID.
        pid = int(pid_file.read_text())
        for _ in range(20):
            try:
                state = Path("/proc/{}/stat".format(pid)).read_text().split(")", 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            time.sleep(0.01)
        else:
            self.fail("probe descendant is still running")


if __name__ == "__main__":
    unittest.main()
