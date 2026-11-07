#!/usr/bin/env python3
"""Execute install.sh's upgrade paths with an explicit fake CLI and supervisors.

These are installer control-flow regressions, not live daemon/fleet qualification.
All fixtures and subprocess transcripts are retained for inspection. No service
manager, worker, download, installed binary, or user home is modified.
"""

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]

PROLOGUE = r'''
set -euo pipefail
export RCH_INSTALLER_LIB=1
source "$RCH_TEST_INSTALLER"
USE_GUM=false
USE_COLOR=false
MODE=local
NO_SERVICE=false
ENABLE_SERVICE=true
trace() { printf '%s\n' "$*" >> "$RCH_TEST_TRACE"; }
systemctl() {
    trace "systemctl $*"
    if [[ "$*" == "is-active --quiet rchd.service" ]]; then
        [[ "${RCH_TEST_SYSTEM_ACTIVE:-0}" == 1 ]]
        return
    fi
    # A destructive fallback would succeed, making a regression observable.
    return 0
}
launchctl() {
    trace "launchctl $*"
    if [[ "$*" == list ]]; then
        printf '%s\n' "$RCH_TEST_LAUNCHD_LIST"
        return "${RCH_TEST_LAUNCHD_RESULT:-0}"
    fi
    return 0
}
uname() { printf '%s\n' "${RCH_TEST_OS:-Linux}"; }
# Service-preservation tests must return before creating/writing a definition.
mkdir() { trace "UNEXPECTED mkdir $*"; return 99; }
'''

MAIN_STUBS = r'''
# Keep main's real sequencing, refusal handling, restart, and launchd setup.
# Replace unrelated installation/network/configuration work with trace markers.
for helper in setup_ui detect_target_version show_header acquire_lock \
    enforce_no_downgrade check_existing_install setup_proxy detect_platform \
    check_prerequisites create_directories generate_default_config \
    configure_claude_hook install_skill setup_systemd_service \
    setup_path configure_dispatcher_shim install_dispatcher_shim_watchdog \
    setup_shell_completions verify_installation detect_agents \
    harmonize_workers run_doctor print_summary cleanup_lock; do
    eval "$helper() { trace '$helper'; }"
done
install_binaries() {
    trace install_binaries
    return "${RCH_TEST_INSTALL_RESULT:-0}"
}
maybe_prompt_service() { ENABLE_SERVICE=true; }
'''

FAKE_CLIENT = r'''#!/usr/bin/env bash
set -euo pipefail
printf 'rch %s\n' "$*" >> "$RCH_TEST_TRACE"
if [[ "$*" != 'daemon restart --drain --drain-timeout 300' ]]; then
    printf 'unexpected maintenance command: %s\n' "$*" >&2
    exit 97
fi
if [[ "${RCH_TEST_CLIENT_RESULT:-0}" != 0 ]]; then
    printf 'fixture client refusal: %s\n' "$RCH_TEST_CLIENT_REASON" >&2
    exit "$RCH_TEST_CLIENT_RESULT"
fi
printf 'fixture: original daemon retired; replacement readiness confirmed\n'
'''

UPGRADE_CLIENT = r'''
set -euo pipefail
printf '%s rch %s\n' "$generation" "$*" >> "$RCH_TEST_TRACE"
if [[ "$*" != 'daemon restart --drain --drain-timeout 300' ]]; then
    printf 'unexpected maintenance command: %s\n' "$*" >&2
    exit 97
fi
if [[ "$generation" == legacy ]]; then
    if [[ -n "${RCH_TEST_UPGRADE_REFUSAL:-}" ]]; then
        printf '%s\n' "$RCH_TEST_UPGRADE_REFUSAL" >&2
        exit 23
    fi
    if [[ "${RCH_TEST_UPGRADE_INTERRUPT:-0}" == 1 ]]; then
        kill -INT "$$"
    fi
    [[ "$(cat "$RCH_TEST_DAEMON_GENERATION")" == legacy ]] || exit 96
    # Exercise sibling lookup with a real executable, as the installed client
    # does for an unmanaged daemon. This is a protocol stand-in, not rchd.
    "$(dirname "$0")/rchd" --fixture-restart
else
    if [[ "$(cat "$RCH_TEST_DAEMON_GENERATION")" != current ]]; then
        printf 'legacy admission response malformed: missing success\n' >&2
        exit 24
    fi
fi
'''

UPGRADE_DAEMON = r'''#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == --fixture-restart ]] || exit 97
[[ -x "$(dirname "$0")/rch-wkr" ]] || exit 95
printf 'current rchd launched\n' >> "$RCH_TEST_TRACE"
if [[ "${RCH_TEST_DAEMON_REMAINS_LEGACY:-0}" != 1 ]]; then
    printf 'current\n' > "$RCH_TEST_DAEMON_GENERATION"
fi
'''

REAL_INSTALL_HELPERS = r'''
EASY_MODE=true
WITH_RABS=false
cleanup_lock() { :; }
# Keep extraction and failed-hook staging files after either outcome. The
# production installer retains its ordinary extraction-directory cleanup.
mktemp() { printf '%s\n' "$RCH_TEST_EXTRACT"; }
rm() { trace "retained cleanup $*"; }
'''


class InstallerDaemonUpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(tempfile.mkdtemp(prefix="rch-installer-upgrade-"))
        print(f"Retaining installer fixtures: {cls.fixtures}", flush=True)

    def setUp(self):
        self.case = self.fixtures / self.id().rsplit(".", 1)[-1]
        self.case.mkdir()
        self.client = self.case / "rch"
        self.client.write_text(FAKE_CLIENT)
        self.client.chmod(0o755)
        self.trace = self.case / "trace.txt"
        self.env = dict(os.environ)
        for key in ("RCH_SKIP_DAEMON_RESTART", "RCH_SKIP_FLEET_SYNC"):
            self.env.pop(key, None)
        self.env.update(
            RCH_TEST_INSTALLER=str(REPO / "install.sh"),
            RCH_INSTALL_DIR=str(self.case),
            RCH_CONFIG_DIR=str(self.case / "config"),
            RCH_TEST_TRACE=str(self.trace),
            RCH_TEST_LAUNCHD_LIST="PID\tStatus\tLabel\n42\t0\tcom.rch.daemon",
        )
        self.invocations = 0

    def run_installer(self, script, **env):
        self.invocations += 1
        result = subprocess.run(
            ["bash", "-c", PROLOGUE + "\n" + script],
            cwd=REPO,
            env={**self.env, **env},
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        (self.case / f"run-{self.invocations}.stdout").write_text(result.stdout)
        (self.case / f"run-{self.invocations}.stderr").write_text(result.stderr)
        (self.case / f"run-{self.invocations}.status").write_text(str(result.returncode))
        return result

    def events(self):
        return self.trace.read_text().splitlines() if self.trace.exists() else []

    def assert_no_supervisor_mutation(self):
        for event in self.events():
            if event.startswith("systemctl "):
                self.assertEqual(event, "systemctl is-active --quiet rchd.service")
            if event.startswith("launchctl "):
                self.assertEqual(event, "launchctl list")
            self.assertNotIn("UNEXPECTED", event)

    def prepare_upgrade(self):
        self.bundle = self.case / "bundle"
        self.bundle.mkdir(exist_ok=True)
        self.extract = self.case / "extracted"
        self.extract.mkdir(exist_ok=True)
        self.generation = self.case / "daemon-generation"
        self.generation.write_text("legacy\n")
        self.client.write_text("#!/usr/bin/env bash\ngeneration=legacy\n" + UPGRADE_CLIENT)
        self.old_client = self.client.read_bytes()
        for name, contents in (
            ("rch", "#!/usr/bin/env bash\ngeneration=current\n" + UPGRADE_CLIENT),
            ("rchd", UPGRADE_DAEMON),
            ("rch-wkr", "#!/usr/bin/env bash\nexit 0\n"),
        ):
            path = self.bundle / name
            path.write_text(contents)
            path.chmod(0o755)
        self.tarball = self.case / "release.tar.gz"
        with tarfile.open(self.tarball, "w:gz") as archive:
            for path in self.bundle.iterdir():
                archive.add(path, arcname=path.name)
        self.env.update(
            RCH_TEST_ARCHIVE=str(self.tarball),
            RCH_TEST_BUNDLE=str(self.bundle),
            RCH_TEST_EXTRACT=str(self.extract),
            RCH_TEST_DAEMON_GENERATION=str(self.generation),
        )

    def assert_installed_client(self):
        self.assertEqual(self.client.read_bytes(), (self.bundle / "rch").read_bytes())
        self.assertEqual(self.generation.read_text(), "current\n")
        events = self.events()
        self.assertLess(events.index("legacy rch daemon restart --drain --drain-timeout 300"),
                        events.index("current rchd launched"))
        self.assertLess(events.index("current rchd launched"),
                        events.index("current rch daemon restart --drain --drain-timeout 300"))
        self.assert_no_supervisor_mutation()

    def prepare_split_build(self):
        target = self.case / "target"
        for profile, names in (("wrapper-release", ("rch",)),
                               ("daemon-release", ("rchd", "rch-wkr"))):
            directory = target / profile
            directory.mkdir(parents=True)
            for name in names:
                destination = directory / name
                destination.write_bytes((self.bundle / name).read_bytes())
                destination.chmod(0o755)
        self.env["CARGO_TARGET_DIR"] = str(target)

    def preserve_installed_binaries(self):
        for name in ("rchd", "rch-wkr"):
            path = self.case / name
            path.write_bytes(f"existing {name}\n".encode())
            path.chmod(0o755)
        return {name: ((self.case / name).stat().st_ino,
                       (self.case / name).read_bytes())
                for name in ("rch", "rchd", "rch-wkr")}

    def assert_installed_binaries_preserved(self, original):
        for name, identity in original.items():
            self.assertEqual(((self.case / name).stat().st_ino,
                              (self.case / name).read_bytes()), identity, name)
        self.assertEqual(self.generation.read_text(), "legacy\n")
        self.assertFalse(any("rch daemon " in event for event in self.events()))
        self.assert_no_supervisor_mutation()

    def archive_case(self, label, omit=(), replacement=None):
        # Every case gets a fresh extraction directory. Retaining the prior
        # case must not accidentally supply a member absent from this archive.
        extract = self.case / f"extracted-{label}"
        extract.mkdir()
        self.env["RCH_TEST_EXTRACT"] = str(extract)
        archive = self.case / f"release-{label}.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for path in self.bundle.iterdir():
                if (path.name not in omit
                        and (replacement is None or path.name != replacement[0].name)):
                    output.add(path, arcname=path.name)
            if replacement is not None:
                member, payload = replacement
                output.addfile(member, io.BytesIO(payload))
        return archive

    def test_incomplete_offline_archive_preserves_every_installed_binary(self):
        self.prepare_upgrade()
        original = self.preserve_installed_binaries()
        for name in ("rch", "rchd", "rch-wkr"):
            with self.subTest(missing=name):
                archive = self.archive_case(f"missing-{name}", omit=(name,))
                result = self.run_installer(
                    REAL_INSTALL_HELPERS + '\n'
                    'install_rabs_toolset() { trace UNEXPECTED-rabs-install; }\n'
                    'install_from_tarball "$RCH_TEST_ARCHIVE"\n',
                    RCH_TEST_ARCHIVE=str(archive),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assertNotIn("Offline installation complete", result.stdout)
                self.assert_installed_binaries_preserved(original)

    def test_unusable_archive_member_is_refused_before_any_binary_replacement(self):
        self.prepare_upgrade()
        original = self.preserve_installed_binaries()
        outside = self.case / "outside-executable"
        outside.write_bytes(b"outside archive; must remain unchanged\n")
        outside.chmod(0o755)
        for kind in ("symlink", "directory", "fifo", "empty", "not-executable"):
            with self.subTest(kind=kind):
                member = tarfile.TarInfo("rch")
                member.mode = 0o755
                payload = b""
                if kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = str(outside)
                elif kind == "directory":
                    member.type = tarfile.DIRTYPE
                elif kind == "fifo":
                    member.type = tarfile.FIFOTYPE
                elif kind == "not-executable":
                    payload = (self.bundle / "rch").read_bytes()
                    member.size = len(payload)
                    member.mode = 0o644
                archive = self.archive_case(kind, replacement=(member, payload))
                result = self.run_installer(
                    REAL_INSTALL_HELPERS + '\n'
                    'install_rabs_toolset() { trace UNEXPECTED-rabs-install; }\n'
                    'install_from_tarball "$RCH_TEST_ARCHIVE"\n',
                    RCH_TEST_ARCHIVE=str(archive),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("rch", result.stderr)
                self.assert_installed_binaries_preserved(original)
                self.assertEqual(outside.read_bytes(), b"outside archive; must remain unchanged\n")

    def test_failed_extraction_cannot_install_when_caller_checks_the_result(self):
        self.prepare_upgrade()
        original = self.preserve_installed_binaries()
        corrupt = self.case / "truncated.tar.gz"
        # Lose the gzip trailer after all members, so extraction can leave a
        # complete-looking directory while still reporting a real read error.
        corrupt.write_bytes(self.tarball.read_bytes()[:-8])
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\n'
            'install_rabs_toolset() { trace UNEXPECTED-rabs-install; }\n'
            'if install_from_tarball "$RCH_TEST_ARCHIVE"; then\n'
            '  trace UNEXPECTED-install-success\n'
            'else\n'
            '  trace extraction-refused\n'
            'fi\n',
            RCH_TEST_ARCHIVE=str(corrupt),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("extraction-refused", self.events())
        self.assert_installed_binaries_preserved(original)

    def test_offline_local_install_allows_absent_worker_only_with_fleet_skip(self):
        self.prepare_upgrade()
        worker = self.case / "rch-wkr"
        worker.write_bytes(b"existing worker must remain available\n")
        worker.chmod(0o755)
        archive = self.archive_case("no-worker", omit=("rch-wkr",))
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\ninstall_from_tarball "$RCH_TEST_ARCHIVE"\n'
            'restart_daemon_if_needed\n',
            RCH_TEST_ARCHIVE=str(archive), RCH_SKIP_FLEET_SYNC="1",
        )
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_installed_client()
        self.assertEqual(worker.read_bytes(), b"existing worker must remain available\n")

    def test_worker_install_still_requires_worker_when_fleet_sync_is_disabled(self):
        self.prepare_upgrade()
        original = self.preserve_installed_binaries()
        archive = self.archive_case("worker-missing", omit=("rch-wkr",))
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\nMODE=worker\n'
            'install_rabs_toolset() { trace UNEXPECTED-rabs-install; }\n'
            'install_from_tarball "$RCH_TEST_ARCHIVE"\n',
            RCH_TEST_ARCHIVE=str(archive), RCH_SKIP_FLEET_SYNC="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rch-wkr", result.stderr)
        self.assert_installed_binaries_preserved(original)

    def test_fleet_skip_does_not_admit_an_invalid_worker_member(self):
        self.prepare_upgrade()
        original = self.preserve_installed_binaries()
        member = tarfile.TarInfo("rch-wkr")
        member.type = tarfile.SYMTYPE
        member.linkname = "missing-worker-target"
        archive = self.archive_case("dangling-worker", replacement=(member, b""))
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\ninstall_from_tarball "$RCH_TEST_ARCHIVE"\n',
            RCH_TEST_ARCHIVE=str(archive), RCH_SKIP_FLEET_SYNC="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rch-wkr", result.stderr)
        self.assert_installed_binaries_preserved(original)

    def test_worker_only_archive_does_not_require_or_replace_dispatcher_binaries(self):
        self.prepare_upgrade()
        original = self.preserve_installed_binaries()
        archive = self.archive_case("worker-only", omit=("rch", "rchd"))
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\nMODE=worker\n'
            'install_from_tarball "$RCH_TEST_ARCHIVE"\n',
            RCH_TEST_ARCHIVE=str(archive),
        )
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual((self.case / "rch-wkr").read_bytes(),
                         (self.bundle / "rch-wkr").read_bytes())
        self.assert_installed_binaries_preserved(
            {name: identity for name, identity in original.items() if name != "rch-wkr"})

    def test_incomplete_download_refuses_before_replacement_or_source_fallback(self):
        self.prepare_upgrade()
        original = self.preserve_installed_binaries()
        archive = self.archive_case("download-no-hook", omit=("rch",))
        result = self.run_installer(
            REAL_INSTALL_HELPERS + r'''
VERSION=2.1.35
RELEASE_ARCHIVE_EXT=tar.gz
RELEASE_TARGETS=(fixture-linux)
TARGET=fixture-linux
install_rabs_toolset() { trace UNEXPECTED-rabs-install; }
clone_and_build_from_source() { trace UNEXPECTED-source-fallback; return 1; }
curl() {
    [[ $# == 4 && "$1" == -fsSL && "$3" == -o ]] || return 97
    case "$2" in
        */rch-v2.1.35-fixture-linux.tar.gz)
            cp "$RCH_TEST_ARCHIVE" "$4" ;;
        */rch-v2.1.35-fixture-linux.tar.gz.sha256)
            printf '%s  %s\n' "$RCH_TEST_CHECKSUM" rch-v2.1.35-fixture-linux.tar.gz > "$4" ;;
        *) return 96 ;;
    esac
}
download_binaries
''',
            RCH_TEST_ARCHIVE=str(archive),
            RCH_TEST_CHECKSUM=hashlib.sha256(archive.read_bytes()).hexdigest(),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rch", result.stderr)
        self.assert_installed_binaries_preserved(original)

    def test_offline_upgrade_uses_existing_client_before_replacing_it(self):
        self.prepare_upgrade()
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\ninstall_from_tarball "$RCH_TEST_ARCHIVE"\n'
            'restart_daemon_if_needed\n'
        )
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_installed_client()

    def test_source_upgrade_uses_existing_client_and_installs_split_profiles(self):
        self.prepare_upgrade()
        self.prepare_split_build()
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\ncargo() { trace "cargo $*"; }\n'
            'build_from_source\nrestart_daemon_if_needed\n'
        )
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_installed_client()
        self.assertEqual((self.case / "rch-wkr").read_bytes(),
                         (self.bundle / "rch-wkr").read_bytes())

    def test_download_upgrade_verifies_archive_and_drains_before_client_swap(self):
        self.prepare_upgrade()
        result = self.run_installer(
            REAL_INSTALL_HELPERS + r'''
VERSION=2.1.35
RELEASE_ARCHIVE_EXT=tar.gz
RELEASE_TARGETS=(fixture-linux)
TARGET=fixture-linux
curl() {
    [[ $# == 4 && "$1" == -fsSL && "$3" == -o ]] || return 97
    trace "download $2"
    case "$2" in
        */rch-v2.1.35-fixture-linux.tar.gz)
            cp "$RCH_TEST_ARCHIVE" "$4" ;;
        */rch-v2.1.35-fixture-linux.tar.gz.sha256)
            printf '%s  %s\n' "$RCH_TEST_CHECKSUM" rch-v2.1.35-fixture-linux.tar.gz > "$4" ;;
        *) return 96 ;;
    esac
}
download_binaries
restart_daemon_if_needed
''',
            RCH_TEST_CHECKSUM=hashlib.sha256(self.tarball.read_bytes()).hexdigest(),
        )
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_installed_client()
        self.assertEqual(len([e for e in self.events() if e.startswith("download ")]), 2)

    def test_cloned_source_upgrade_keeps_existing_client_until_daemon_drain(self):
        self.prepare_upgrade()
        self.prepare_split_build()
        # Source acquisition and compilation are explicit stand-ins. The
        # clone install path still reads actual profile files and executes the
        # installed client and its sibling daemon. Release binding has its own
        # real Git tests in test_install_rabs.py.
        project = self.case / "source"
        project.mkdir()
        (project / "Cargo.toml").write_text("# installer source fixture\n")
        result = self.run_installer(
            REAL_INSTALL_HELPERS + r'''
VERSION=2.1.35
cargo() { trace "cargo $*"; }
git() {
    trace "git $*"
    if [[ "$1" == clone ]]; then
        cp -R "$RCH_TEST_SOURCE" "$TEMP_DIR/rch"
    elif [[ "$1" == -C && "$3" == rev-parse ]]; then
        printf 'fixture-release\n'
    elif [[ "$1" != -C || "$3" != status ]]; then
        return 97
    fi
}
clone_and_build_from_source
restart_daemon_if_needed
''',
            RCH_TEST_SOURCE=str(project),
        )
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_installed_client()
        self.assertTrue(any(e.startswith("git clone --depth 1 --branch v2.1.35 -- ")
                            for e in self.events()))

    def test_retry_after_old_client_drain_refusal_completes_the_upgrade(self):
        self.prepare_upgrade()
        first = self.run_installer(
            REAL_INSTALL_HELPERS + '\ninstall_from_tarball "$RCH_TEST_ARCHIVE"\n',
            RCH_TEST_UPGRADE_REFUSAL="legacy builds still running",
        )
        self.assertNotEqual(first.returncode, 0)
        self.assertEqual(self.client.read_bytes(), self.old_client)
        second = self.run_installer(
            REAL_INSTALL_HELPERS + '\ninstall_from_tarball "$RCH_TEST_ARCHIVE"\n'
            'restart_daemon_if_needed\n'
        )
        self.assertEqual(second.returncode, 0, (second.stdout, second.stderr))
        self.assert_installed_client()
        self.assertEqual(self.events().count(
            "legacy rch daemon restart --drain --drain-timeout 300"), 2)

    def test_failed_old_client_drain_keeps_it_available_and_new_hook_staged(self):
        self.prepare_upgrade()
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\ninstall_from_tarball "$RCH_TEST_ARCHIVE"\n'
            'trace UNEXPECTED-completed-upgrade\n',
            RCH_TEST_UPGRADE_REFUSAL="active legacy builds did not drain",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("active legacy builds did not drain", result.stdout)
        self.assertEqual(self.client.read_bytes(), self.old_client)
        self.assertEqual((self.case / "rchd").read_bytes(),
                         (self.bundle / "rchd").read_bytes())
        staged = list(self.case.glob("rch.tmp.*"))
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0].read_bytes(), (self.bundle / "rch").read_bytes())
        self.assertEqual(self.generation.read_text(), "legacy\n")
        self.assert_no_supervisor_mutation()

    def test_interrupt_during_old_client_drain_keeps_the_old_hook(self):
        self.prepare_upgrade()
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\ninstall_from_tarball "$RCH_TEST_ARCHIVE"\n'
            'trace UNEXPECTED-completed-upgrade\n',
            RCH_TEST_UPGRADE_INTERRUPT="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.client.read_bytes(), self.old_client)
        self.assertEqual(self.generation.read_text(), "legacy\n")
        self.assert_no_supervisor_mutation()

    def test_missing_hook_source_fails_before_old_client_drain(self):
        self.prepare_upgrade()
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\nDAEMON_BINARY_INSTALLED=true\n'
            'install_binary_file "$RCH_TEST_BUNDLE/missing-rch" "$INSTALL_DIR/rch"\n'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.client.read_bytes(), self.old_client)
        self.assertEqual(self.events(), [])

    def test_hook_upgrade_requires_daemon_to_be_installed_first(self):
        self.prepare_upgrade()
        result = self.run_installer(
            REAL_INSTALL_HELPERS + '\n'
            'install_binary_file "$RCH_TEST_BUNDLE/rch" "$INSTALL_DIR/rch"\n'
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.client.read_bytes(), self.old_client)
        self.assertEqual(self.generation.read_text(), "legacy\n")
        self.assertFalse(any(" rch daemon " in event for event in self.events()))
        self.assert_no_supervisor_mutation()

    def test_no_restart_upgrade_preserves_existing_daemon_behavior(self):
        for mode in ("default", "skip", "system"):
            with self.subTest(mode=mode):
                self.prepare_upgrade()
                script = REAL_INSTALL_HELPERS
                env = {}
                if mode == "default":
                    script += "\nEASY_MODE=false\n"
                elif mode == "skip":
                    env["RCH_SKIP_DAEMON_RESTART"] = "1"
                else:
                    env["RCH_TEST_SYSTEM_ACTIVE"] = "1"
                result = self.run_installer(
                    script + '\ninstall_from_tarball "$RCH_TEST_ARCHIVE"\n', **env
                )
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                self.assertEqual(self.client.read_bytes(), (self.bundle / "rch").read_bytes())
                self.assertEqual(self.generation.read_text(), "legacy\n")
                self.assertFalse(any(" rch daemon " in event for event in self.events()))
                self.assert_no_supervisor_mutation()

    def test_new_client_must_confirm_readiness_before_fleet_sync(self):
        self.prepare_upgrade()
        result = self.run_installer(
            REAL_INSTALL_HELPERS + MAIN_STUBS + '\n'
            'install_binaries() { install_from_tarball "$RCH_TEST_ARCHIVE"; }\n'
            'main --easy-mode --yes\n',
            RCH_TEST_DAEMON_REMAINS_LEGACY="1",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("current rchd launched", self.events())
        self.assertIn("legacy admission response malformed", result.stdout)
        self.assertIn("installation stopped before worker sync", result.stderr)
        for step in ("harmonize_workers", "run_doctor", "print_summary"):
            self.assertNotIn(step, self.events())
        self.assert_no_supervisor_mutation()

    def test_success_requests_bounded_drain_without_force(self):
        result = self.run_installer("restart_daemon_if_needed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [event for event in self.events() if event.startswith("rch ")],
            ["rch daemon restart --drain --drain-timeout 300"],
        )
        self.assert_no_supervisor_mutation()

    def test_client_refusals_never_become_service_manager_restarts(self):
        for reason in (
            "active builds did not drain",
            "queued work did not drain",
            "client leases remain",
            "client lease scan failed",
            "daemon ownership is uncertain",
            "daemon incarnation changed",
            "legacy admission response malformed",
            "drain timed out",
            "shutdown acknowledgement lost",
        ):
            with self.subTest(reason=reason):
                result = self.run_installer(
                    "restart_daemon_if_needed",
                    RCH_TEST_CLIENT_RESULT="1",
                    RCH_TEST_CLIENT_REASON=reason,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(reason, result.stdout)
                self.assertIn("Daemon upgrade is unconfirmed", result.stderr)
                self.assertIn("Binaries may already be installed", result.stderr)
                self.assert_no_supervisor_mutation()

    def test_interrupt_during_drain_is_a_failure_without_fallback(self):
        result = self.run_installer(
            "restart_daemon_if_needed",
            RCH_TEST_CLIENT_RESULT="130",
            RCH_TEST_CLIENT_REASON="maintenance cancelled by SIGINT",
        )
        self.assertEqual(result.returncode, 1)
        self.assert_no_supervisor_mutation()

    def test_missing_client_does_not_claim_upgrade_success(self):
        result = self.run_installer("HOOK_BIN=missing-rch; restart_daemon_if_needed")
        self.assertEqual(result.returncode, 1)
        self.assertIn("rch binary not found", result.stderr)
        self.assert_no_supervisor_mutation()

    def test_retry_after_interruption_reenters_client_drain(self):
        first = self.run_installer(
            "restart_daemon_if_needed",
            RCH_TEST_CLIENT_RESULT="130",
            RCH_TEST_CLIENT_REASON="maintenance interrupted",
        )
        second = self.run_installer("restart_daemon_if_needed")
        self.assertEqual(first.returncode, 1)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(
            self.events().count("rch daemon restart --drain --drain-timeout 300"), 2
        )
        self.assert_no_supervisor_mutation()

    def test_explicit_skip_preserves_the_daemon(self):
        result = self.run_installer("restart_daemon_if_needed", RCH_SKIP_DAEMON_RESTART="1")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])

    def test_worker_install_does_not_restart_a_daemon(self):
        result = self.run_installer("MODE=worker; restart_daemon_if_needed")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])

    def test_system_daemon_keeps_existing_explicit_skip_behavior(self):
        result = self.run_installer("restart_daemon_if_needed", RCH_TEST_SYSTEM_ACTIVE="1")
        self.assertEqual(result.returncode, 0)
        self.assertIn("System-level rchd.service is active", result.stdout)
        self.assertEqual(self.events(), ["systemctl is-active --quiet rchd.service"])

    def test_launchd_preserves_loaded_and_pending_respawn_jobs(self):
        for pid in ("42", "-"):
            with self.subTest(pid=pid):
                result = self.run_installer(
                    "setup_launchd_service",
                    RCH_TEST_OS="Darwin",
                    RCH_TEST_LAUNCHD_LIST=f"PID\tStatus\tLabel\n{pid}\t0\tcom.rch.daemon",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Existing launchd daemon retained", result.stdout)
                self.assert_no_supervisor_mutation()

    def test_launchd_inspection_failure_never_means_no_owner(self):
        result = self.run_installer(
            "setup_launchd_service",
            RCH_TEST_OS="Darwin",
            RCH_TEST_LAUNCHD_LIST="permission denied",
            RCH_TEST_LAUNCHD_RESULT="1",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Cannot inspect launchd jobs", result.stderr)
        self.assert_no_supervisor_mutation()

    def test_launchd_malformed_listing_refuses_service_setup(self):
        for listing in ("", "unrecognized response", "PID Status Label\nunknown 0 com.rch.daemon"):
            with self.subTest(listing=listing):
                result = self.run_installer(
                    "setup_launchd_service",
                    RCH_TEST_OS="Darwin",
                    RCH_TEST_LAUNCHD_LIST=listing,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("Cannot interpret launchd job ownership", result.stderr)
                self.assert_no_supervisor_mutation()

    def test_easy_mode_failure_stops_before_worker_deploy_and_success_summary(self):
        result = self.run_installer(
            MAIN_STUBS + "\nmain --easy-mode --yes",
            RCH_TEST_CLIENT_RESULT="1",
            RCH_TEST_CLIENT_REASON="queued work remains",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("installation stopped before worker sync", result.stderr)
        self.assertIn("install_binaries", self.events())
        for step in ("harmonize_workers", "run_doctor", "print_summary"):
            self.assertNotIn(step, self.events())
        self.assert_no_supervisor_mutation()

    def test_interrupted_binary_install_never_reaches_daemon_or_workers(self):
        result = self.run_installer(
            MAIN_STUBS + "\nmain --easy-mode --yes", RCH_TEST_INSTALL_RESULT="130"
        )
        self.assertEqual(result.returncode, 130)
        self.assertEqual(self.events()[-1], "install_binaries")
        self.assert_no_supervisor_mutation()

    def test_easy_mode_launchd_ownership_uncertainty_stops_the_install(self):
        result = self.run_installer(
            MAIN_STUBS + "\nmain --easy-mode --yes",
            RCH_TEST_OS="Darwin",
            RCH_TEST_LAUNCHD_LIST="launchd unavailable",
            RCH_TEST_LAUNCHD_RESULT="1",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("installation stopped before daemon restart or worker sync", result.stderr)
        self.assertNotIn("harmonize_workers", self.events())
        self.assertFalse(any(event.startswith("rch ") for event in self.events()))
        self.assert_no_supervisor_mutation()

    def test_default_install_cannot_unload_launchd_before_drain(self):
        result = self.run_installer(MAIN_STUBS + "\nmain --yes", RCH_TEST_OS="Darwin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("print_summary", self.events())
        self.assertFalse(any(event.startswith("rch ") for event in self.events()))
        self.assert_no_supervisor_mutation()

    def test_successful_retry_resumes_main_after_client_confirms_restart(self):
        first = self.run_installer(
            MAIN_STUBS + "\nmain --easy-mode --yes",
            RCH_TEST_CLIENT_RESULT="130",
            RCH_TEST_CLIENT_REASON="interrupted upgrade",
        )
        second = self.run_installer(MAIN_STUBS + "\nmain --easy-mode --yes")
        self.assertEqual(first.returncode, 1)
        self.assertEqual(second.returncode, 0, second.stderr)
        events = self.events()
        self.assertEqual(events.count("harmonize_workers"), 1)
        self.assertEqual(events.count("print_summary"), 1)
        self.assertLess(events.index("rch daemon restart --drain --drain-timeout 300"), events.index("harmonize_workers"))
        self.assert_no_supervisor_mutation()


if __name__ == "__main__":
    unittest.main(verbosity=2)
