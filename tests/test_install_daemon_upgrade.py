#!/usr/bin/env python3
"""Execute install.sh's upgrade paths with an explicit fake CLI and supervisors.

These are installer control-flow regressions, not live daemon/fleet qualification.
All fixtures and subprocess transcripts are retained for inspection. No service
manager, worker, download, installed binary, or user home is modified.
"""

import os
from pathlib import Path
import subprocess
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
