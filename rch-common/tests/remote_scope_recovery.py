#!/usr/bin/env python3
"""Exercise the production scope receipt/recovery protocol.

The fast cases use real files, descriptors and process observations, with
explicit doubles for systemd and cgroupfs. They do NOT qualify kernel cgroup
semantics. RCH_TEST_SYSTEMD_SLICE enables the separately named live Linux test,
which launches a setsid descendant, disconnects its leader, and recovers through
an unchanged durable receipt. No SSH server or daemon reservation is simulated.
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = (Path(__file__).resolve().parents[1] / "src" / "remote_process.sh").read_text()
BOOT = Path("/proc/sys/kernel/random/boot_id").read_text().strip() if sys.platform == "linux" else ""
INVOCATION = "1234567890abcdef1234567890abcdef"
TEST_SHELL = os.environ.get("RCH_SCOPE_TEST_SHELL", "/bin/sh")
PRELUDE = r'''
rch_scope_root() { printf '%s\n' "$RCH_SCOPE_TEST_ROOT/cgroups"; }
'''


def inode(path: Path) -> str:
    info = path.stat()
    return f"{info.st_dev}.{info.st_ino}"


@unittest.skipUnless(sys.platform == "linux", "Linux scope backend")
class ScopeProtocol(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="rch-scope-recovery-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for directory in ("cgroups/jobs.slice", "manager", "bin"):
            (self.root / directory).mkdir(parents=True)
        self.env = {**os.environ, "RCH_SCOPE_TEST_ROOT": str(self.root),
                    "PATH": f"{self.root}/bin:/usr/bin:/bin"}
        # Only filesystem TYPE is doubled. Device/inode and FD behavior are real.
        self.executable("stat", r'''
case "$1" in -fc|-fLc) printf '%s\n' cgroup2fs;; *) exec /usr/bin/stat "$@";; esac
''')
        self.executable("systemctl", r'''
[ ! -e "$RCH_SCOPE_TEST_ROOT/manager-down" ] || exit 1
for unit do :; done
file="$RCH_SCOPE_TEST_ROOT/manager/$unit"
[ -f "$file" ] || exit 1
# A path swap after the caller pinned fd 8. The fake manager deliberately
# retains the same generation to isolate the kernel-descriptor fence.
if [ -e "$RCH_SCOPE_TEST_ROOT/swap-when-pinned" ] && [ -e /proc/self/fd/8/cgroup.events ]; then
    old="$RCH_SCOPE_TEST_ROOT/cgroups/jobs.slice/$unit"
    mv "$old" "$old.retired" || exit 1
    mkdir "$old" || exit 1
    printf 'populated 1\nfrozen 0\n' > "$old/cgroup.events"
    printf 'domain\n' > "$old/cgroup.type"
    : > "$old/cgroup.kill"
    mv "$RCH_SCOPE_TEST_ROOT/swap-when-pinned" "$RCH_SCOPE_TEST_ROOT/swapped"
fi
case " $* " in
    *' --value '* )
        for arg do
            case "$arg" in --property=*) key=${arg#--property=};; esac
        done
        sed -n "s/^$key=//p" "$file";;
    *) cat "$file";;
esac
''')
        ended = subprocess.Popen(["/bin/sh", "-c", "exit 0"], start_new_session=True)
        ended.wait(timeout=5)
        self.pgid = ended.pid
        self.scope = self.make_scope(self.pgid)

    def executable(self, name: str, text: str) -> None:
        path = self.root / "bin" / name
        path.write_text("#!/bin/sh\n" + text)
        path.chmod(0o700)

    def make_scope(self, pgid: int, start: str = "1") -> dict[str, object]:
        unit = f"rch-{BOOT}-{pgid}-{start}.scope"
        cgroup = f"/jobs.slice/{unit}"
        directory = self.root / "cgroups" / cgroup.lstrip("/")
        directory.mkdir()
        (directory / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        (directory / "cgroup.type").write_text("domain\n")
        (directory / "cgroup.kill").write_text("")
        snapshot = self.root / "manager" / unit
        snapshot.write_text(f"LoadState=loaded\nActiveState=active\nInvocationID={INVOCATION}\nControlGroup={cgroup}\n")
        fields = ["RCH_REMOTE_PROCESS_V2", "42", BOOT, str(pgid), start, str(os.getuid()),
                  "user", INVOCATION, str(Path("/proc/self/ns/cgroup").stat().st_ino),
                  inode(self.root / "cgroups"), inode(directory), cgroup]
        record = self.root / f"{pgid}-{start}.pgid"
        record.write_text(":".join(fields) + "\n")
        record.chmod(0o600)
        return {"unit": unit, "directory": directory, "snapshot": snapshot,
                "fields": fields, "record": record}

    def run_shell(self, body: str, *args: object, shell: str = TEST_SHELL) -> subprocess.CompletedProcess[str]:
        return subprocess.run([shell, "-c", SCRIPT + PRELUDE + body, "scope-test", *map(str, args)],
                              env=self.env, capture_output=True, text=True, timeout=12,
                              start_new_session=True)

    def operation(self, operation: str, scope: dict[str, object] | None = None) -> subprocess.CompletedProcess[str]:
        scope = self.scope if scope is None else scope
        return self.run_shell('rch_read_record "$1" 42 || exit $?\nrch_scope_operation "$2"',
                              scope["record"], operation)

    def test_receipt_roundtrip_and_empty_original_group_does_not_mean_empty_scope(self) -> None:
        for shell in ("/bin/sh", "/bin/bash"):
            result = self.run_shell('rch_read_record "$1" 42 || exit $?\nrch_group_state',
                                    self.scope["record"], shell=shell)
            self.assertEqual(result.returncode, 1, result.stderr)
        (self.scope["directory"] / "cgroup.events").write_text("populated 0\nfrozen 0\n")
        result = self.run_shell('rch_read_record "$1" 42 || exit $?\nrch_group_state', self.scope["record"])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_probe_opens_but_does_not_fire_kill(self) -> None:
        result = self.operation("probe")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "")

    def launch_with_scope_fixture(self, omit_kill: bool) -> subprocess.CompletedProcess[str]:
        # Model ONLY systemd's creation/move. The binding, cleanup admission,
        # atomic receipt publication and payload gate are production functions.
        return self.run_shell(r'''
rch_apply_configured_worker_policy() {
    rch_policy_manager=user
    rch_policy_scope="rch-$rch_boot-$rch_pgid-$rch_start.scope"
    rch_policy_expected_cgroup="/jobs.slice/$rch_policy_scope"
    directory="$RCH_SCOPE_TEST_ROOT/cgroups$rch_policy_expected_cgroup"
    mkdir "$directory" || return 1
    printf 'populated 1\nfrozen 0\n' > "$directory/cgroup.events"
    printf 'domain\n' > "$directory/cgroup.type"
    if [ "$omit" = no ]; then : > "$directory/cgroup.kill"; fi
    printf 'LoadState=loaded\nActiveState=active\nInvocationID=1234567890abcdef1234567890abcdef\nControlGroup=%s\n' \
        "$rch_policy_expected_cgroup" > "$RCH_SCOPE_TEST_ROOT/manager/$rch_policy_scope"
    rch_scope_bind_created
}
omit=$3
rch_remote_record "$1" 42 || exit $?
printf 'payload\n' > "$2"
rch_read_record "$1" 42 || exit $?
[ "$rch_scope_bound" = 1 ] && [ "$rch_identified" = 1 ]
''', self.root / "launched.pgid", self.root / "payload", "yes" if omit_kill else "no")

    def test_publisher_binds_scope_in_one_atomic_required_record(self) -> None:
        result = self.launch_with_scope_fixture(False)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.root / "launched.pgid"
        self.assertTrue(record.read_text().startswith("RCH_REMOTE_PROCESS_V2:42:"))
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "payload").read_text(), "payload\n")
        self.assertEqual(list(self.root.glob("launched.pgid.*")), [], "no partial publication")

    def test_scope_without_cleanup_capability_starts_no_payload(self) -> None:
        result = self.launch_with_scope_fixture(True)
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertFalse((self.root / "launched.pgid").exists())
        self.assertFalse((self.root / "payload").exists())

    def test_kill_targets_the_bound_subtree_not_a_pid_or_unit_name(self) -> None:
        result = self.operation("kill")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "1\n")
        # Merely accepting the kill request does not authorize cleanup success.
        result = self.run_shell('rch_remote_cancel "$1" 42 kill', self.scope["record"])
        self.assertEqual(result.returncode, 45, result.stderr)

    def test_descriptor_pin_survives_path_replacement(self) -> None:
        (self.root / "swap-when-pinned").touch()
        result = self.operation("kill")
        self.assertEqual(result.returncode, 0, result.stderr)
        original = Path(str(self.scope["directory"]) + ".retired")
        self.assertEqual((original / "cgroup.kill").read_text(), "1\n")
        self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "")
        # A later channel must not adopt the replacement at the old name.
        self.assertEqual(self.operation("kill").returncode, 3)

    def test_reused_systemd_generation_is_never_signalled(self) -> None:
        snapshot = self.scope["snapshot"]
        snapshot.write_text(snapshot.read_text().replace(INVOCATION, "f" * 32))
        self.assertEqual(self.operation("kill").returncode, 3)
        self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "")

    def test_missing_manager_cannot_downgrade_to_posix_cleanup(self) -> None:
        (self.root / "manager-down").touch()
        result = self.run_shell('rch_remote_cancel "$1" 42 kill', self.scope["record"])
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "")

    def test_failed_census_still_stops_authenticated_scope_then_rechecks_both_views(self) -> None:
        kill = self.scope["directory"] / "cgroup.kill"
        events = self.scope["directory"] / "cgroup.events"
        self.env.update(RCH_SCOPE_TEST_KILL=str(kill), RCH_SCOPE_TEST_EVENTS=str(events))
        # Fault only the process census before kill. Afterwards use real ps,
        # and let the cgroupfs double report the simulated kernel's empty tree.
        self.executable("ps", r'''
if [ ! -s "$RCH_SCOPE_TEST_KILL" ]; then
    case "$RCH_SCOPE_TEST_CENSUS_FAULT" in
        failed) exit 1;;
        malformed) printf 'incomplete census\n'; exit 0;;
    esac
fi
printf 'populated 0\nfrozen 0\n' > "$RCH_SCOPE_TEST_EVENTS"
exec /usr/bin/ps "$@"
''')
        receipt = self.scope["record"].read_bytes()
        for fault in ("failed", "malformed"):
            self.env["RCH_SCOPE_TEST_CENSUS_FAULT"] = fault
            for mode in ("kill", "term"):
                with self.subTest(fault=fault, mode=mode):
                    kill.write_text("")
                    events.write_text("populated 1\nfrozen 0\n")
                    result = self.run_shell('rch_remote_cancel "$1" 42 "$2"', self.scope["record"], mode)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(kill.read_text(), "1\n")
                    self.assertEqual(self.scope["record"].read_bytes(), receipt)

    def test_persistent_failed_census_stops_scope_without_claiming_completion(self) -> None:
        self.executable("ps", "exit 1\n")
        kill = self.scope["directory"] / "cgroup.kill"
        for populated in (0, 1):
            (self.scope["directory"] / "cgroup.events").write_text(f"populated {populated}\n")
            for mode in ("kill", "term"):
                with self.subTest(populated=populated, mode=mode):
                    kill.write_text("")
                    result = self.run_shell('rch_remote_cancel "$1" 42 "$2"', self.scope["record"], mode)
                    self.assertEqual(result.returncode, 44, result.stderr)
                    self.assertEqual(kill.read_text(), "1\n", "unknown census must not suppress scoped stop")

    def test_failed_census_does_not_borrow_foreign_or_unavailable_scope_authority(self) -> None:
        self.executable("ps", "exit 1\n")
        snapshot = self.scope["snapshot"]
        original_snapshot = snapshot.read_text()
        snapshot.write_text(original_snapshot.replace(INVOCATION, "f" * 32))
        result = self.run_shell('rch_remote_cancel "$1" 42 kill', self.scope["record"])
        self.assertEqual(result.returncode, 43, result.stderr)
        self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "")
        snapshot.write_text(original_snapshot)
        original = self.scope["record"].read_text()
        # A changed boot also contradicts the unit name encoded in the same
        # receipt, so it is rejected during parsing, before scope observation.
        for index, value, expected in ((2, "00000000-0000-0000-0000-000000000000", 42),
                                       (8, "1", 43), (9, "1.1", 43), (10, "1.1", 43)):
            with self.subTest(field=index):
                fields = list(self.scope["fields"])
                fields[index] = value
                self.scope["record"].write_text(":".join(fields) + "\n")
                result = self.run_shell('rch_remote_cancel "$1" 42 kill', self.scope["record"])
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "")
        self.scope["record"].write_text(original)
        (self.root / "manager-down").touch()
        result = self.run_shell('rch_remote_cancel "$1" 42 kill', self.scope["record"])
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "")

    def test_failed_census_never_authorizes_legacy_group_signals(self) -> None:
        self.executable("ps", "exit 1\n")
        legacy = self.root / "legacy.pgid"
        legacy.write_text(f"RCH_REMOTE_PROCESS_V1:42:{BOOT}:{self.pgid}:1\n")
        signal_log = self.root / "unexpected-signal"
        for mode in ("kill", "term"):
            result = self.run_shell(r'''
kill() { printf '%s\n' "$*" >> "$RCH_SCOPE_TEST_ROOT/unexpected-signal"; return 0; }
rch_remote_cancel "$1" 42 "$2"
''', legacy, mode)
            self.assertEqual(result.returncode, 44, result.stderr)
            self.assertFalse(signal_log.exists())
            self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "")

    def test_census_failure_after_graceful_term_cannot_prevent_scoped_escalation(self) -> None:
        kill = self.scope["directory"] / "cgroup.kill"
        events = self.scope["directory"] / "cgroup.events"
        self.env.update(RCH_SCOPE_TEST_KILL=str(kill), RCH_SCOPE_TEST_EVENTS=str(events))
        self.executable("ps", r'''
count_file="$RCH_SCOPE_TEST_ROOT/census-count"
count=0
if [ -f "$count_file" ]; then read -r count < "$count_file"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
[ "$count" != 2 ] || exit 1
if [ -s "$RCH_SCOPE_TEST_KILL" ]; then
    printf 'populated 0\nfrozen 0\n' > "$RCH_SCOPE_TEST_EVENTS"
fi
exec /usr/bin/ps "$@"
''')
        result = self.run_shell('rch_remote_cancel "$1" 42 term', self.scope["record"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(kill.read_text(), "1\n")
        self.assertGreaterEqual(int((self.root / "census-count").read_text()), 3)

    def test_changed_boot_uid_namespace_mount_and_inode_refuse(self) -> None:
        original = list(self.scope["fields"])
        for index, value in ((2, "00000000-0000-0000-0000-000000000000"),
                             (5, str(os.getuid() + 1)), (8, "1"), (9, "1.1"), (10, "1.1")):
            with self.subTest(field=index):
                fields = list(original)
                fields[index] = value
                self.scope["record"].write_text(":".join(fields) + "\n")
                self.assertNotEqual(self.operation("kill").returncode, 0)
                self.assertEqual((self.scope["directory"] / "cgroup.kill").read_text(), "")
        self.scope["record"].write_text(":".join(original) + "\n")

    def test_invalid_or_incomplete_binding_is_not_a_legacy_record(self) -> None:
        original = list(self.scope["fields"])
        for index, value in ((6, "auto"), (7, "0" * 32), (7, "g" * 32), (8, "01"),
                             (9, "1.2.3"), (11, "/"), (11, "/jobs.slice/../other"),
                             (11, "/jobs.slice/not-the-recorded-unit.scope"),
                             (11, "/jobs.slice/$(touch nope)")):
            with self.subTest(field=index, value=value):
                fields = list(original)
                fields[index] = value
                self.scope["record"].write_text(":".join(fields) + "\n")
                self.assertEqual(self.operation("kill").returncode, 42)
        for raw in (":".join(original[:-1]) + "\n", ":".join(original),
                    ":".join(original) + "\n\n", ":".join(original) + "\x00\n"):
            self.scope["record"].write_text(raw)
            self.assertEqual(self.operation("kill").returncode, 42)

    def test_wrong_build_and_unsafe_record_are_refused(self) -> None:
        result = self.run_shell('rch_read_record "$1" 43', self.scope["record"])
        self.assertEqual(result.returncode, 43)
        self.scope["record"].chmod(0o666)
        self.assertEqual(self.operation("kill").returncode, 42)
        self.scope["record"].chmod(0o600)
        os.link(self.scope["record"], self.root / "alias.pgid")
        self.assertEqual(self.operation("kill").returncode, 42)

    def test_failed_or_legacy_read_clears_scope_authority(self) -> None:
        legacy = self.root / "legacy.pgid"
        legacy.write_text(f"RCH_REMOTE_PROCESS_V1:42:{BOOT}:{self.pgid}:1\n")
        result = self.run_shell(r'''
rch_read_record "$1" 42 || exit 80
rch_read_record "$2" 42 || exit 81
[ "$rch_scope_bound" = 0 ] || exit 82
rch_read_record "$1" 42 || exit 83
rch_read_record "$3" 42
[ "$?" = 42 ] && [ "$rch_identified" = 0 ] && [ "$rch_scope_bound" = 0 ] || exit 84
rch_signal_group KILL
[ "$?" = 43 ]
''', self.scope["record"], legacy, self.root / "absent.pgid")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_kill_primitive_or_wrong_cgroup_type_refuses_admission(self) -> None:
        kill = self.scope["directory"] / "cgroup.kill"
        kill.rename(kill.with_name("retained.kill"))
        self.assertEqual(self.operation("probe").returncode, 2)
        kill.with_name("retained.kill").rename(kill)
        (self.scope["directory"] / "cgroup.type").write_text("threaded\n")
        self.assertEqual(self.operation("probe").returncode, 2)
        self.assertEqual(self.operation("kill").returncode, 2)
        self.assertEqual(kill.read_text(), "")

    def test_incomplete_populated_evidence_is_unknown(self) -> None:
        events = self.scope["directory"] / "cgroup.events"
        for text in ("", "frozen 0\n", "populated 2\n", "populated 0 junk\n",
                     "populated 0\npopulated 0\n"):
            with self.subTest(events=text):
                events.write_text(text)
                self.assertEqual(self.operation("state").returncode, 2)

    def test_incomplete_or_contradictory_manager_snapshot_is_unknown(self) -> None:
        snapshot = self.scope["snapshot"]
        original = snapshot.read_text()
        for text in ("", original.replace("LoadState=loaded\n", ""),
                     original + "ActiveState=active\n", original.replace("active", "activating"),
                     original.replace("LoadState=loaded", "LoadState=not-found")):
            snapshot.write_text(text)
            self.assertNotEqual(self.operation("state").returncode, 0)
        snapshot.write_text(original)

    def test_gc_requires_terminal_manager_and_physical_absence(self) -> None:
        directory = self.scope["directory"]
        (directory / "cgroup.events").write_text("populated 0\n")
        directory.rename(Path(str(directory) + ".retained"))
        self.assertEqual(self.operation("state").returncode, 2, "active manager contradicts absence")
        self.scope["snapshot"].write_text("LoadState=not-found\nActiveState=inactive\nInvocationID=\nControlGroup=\n")
        self.assertEqual(self.operation("state").returncode, 0)
        self.assertEqual(self.operation("kill").returncode, 0, "already-gone cleanup is idempotent")
        self.assertEqual(self.operation("probe").returncode, 2, "absence cannot admit a workload")

    def test_symlinked_scope_does_not_authorize_kill_or_absence(self) -> None:
        directory = self.scope["directory"]
        original = Path(str(directory) + ".retained")
        directory.rename(original)
        directory.symlink_to(original, target_is_directory=True)
        self.assertEqual(self.operation("kill").returncode, 2)
        self.assertEqual((original / "cgroup.kill").read_text(), "")

    def test_concurrent_scopes_keep_distinct_cleanup_authority(self) -> None:
        other = self.make_scope(self.pgid, "2")
        processes = []
        for scope in (self.scope, other):
            body = SCRIPT + PRELUDE + 'rch_read_record "$1" 42 || exit $?\nrch_scope_operation kill'
            processes.append(subprocess.Popen([TEST_SHELL, "-c", body, "scope-test", str(scope["record"])],
                                               env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        for process in processes:
            out, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, (out, err))
        for scope in (self.scope, other):
            self.assertEqual((scope["directory"] / "cgroup.kill").read_text(), "1\n")
        original = self.scope["record"].read_text()
        self.scope["record"].write_text(original.replace(str(self.scope["fields"][-1]), str(other["fields"][-1])))
        self.assertEqual(self.operation("kill").returncode, 42)

    def test_new_channel_observes_terminal_evidence_without_policy_file(self) -> None:
        # A previous channel issued the kill; the simulated kernel later
        # reports the complete subtree empty. Recovery must not replay a job.
        self.assertEqual(self.operation("kill").returncode, 0)
        (self.scope["directory"] / "cgroup.events").write_text("populated 0\n")
        result = self.run_shell(r'''
rch_policy_select_file() { echo should-not-load-policy >&2; return 125; }
rch_remote_cancel "$1" 42 kill
''', self.scope["record"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("should-not-load-policy", result.stderr)


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("RCH_TEST_SYSTEMD_SLICE"),
                     "requires an explicitly selected active systemd user slice")
class LiveSystemdScope(unittest.TestCase):
    def test_setsid_descendant_is_reaped_after_leader_disconnect(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rch-live-scope-") as tmp:
            root = Path(tmp)
            policy, record, ready = (root / name for name in ("policy", "42.pgid", "child"))
            policy.write_text(f"version=1\nsystemd_slice={os.environ['RCH_TEST_SYSTEMD_SLICE']}\n")
            policy.chmod(0o600)
            # Select only the test-owned policy; enforcement and observations
            # below are the unchanged production implementation, without doubles.
            body = r'''
rch_policy_select_file() { rch_policy_file=$RCH_LIVE_POLICY; rch_policy_owner=$(id -u); }
rch_remote_record "$1" 42 || exit $?
"$3" -c 'import os,signal,sys,time; os.setsid(); signal.signal(signal.SIGTERM,signal.SIG_IGN); open(sys.argv[1],"w").write(str(os.getpid())); time.sleep(60)' "$2" >/dev/null 2>&1 &
wait
'''
            environment = {**os.environ, "RCH_LIVE_POLICY": str(policy)}
            process = subprocess.Popen(["/bin/sh", "-c", SCRIPT + body, "live-scope", str(record),
                                        str(ready), sys.executable], env=environment, start_new_session=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            child_fd = None
            try:
                deadline = time.monotonic() + 12
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not ready.exists():
                    if process.poll() is None:
                        process.kill()
                    out, err = process.communicate(timeout=5)
                    self.fail(f"live scope admission failed: {out!r} {err!r}")
                child_pid = int(ready.read_text())
                child_fd = os.pidfd_open(child_pid)
                self.assertNotEqual(os.getpgid(child_pid), process.pid)
                self.assertTrue(record.read_text().startswith("RCH_REMOTE_PROCESS_V2:42:"))
                fields = record.read_text().strip().split(":")
                self.assertIn("0::" + fields[-1], Path(f"/proc/{child_pid}/cgroup").read_text())
                process.kill()  # transport/leader loss must not erase scope authority
                process.communicate(timeout=5)
                policy.rename(root / "policy.retained")
                result = subprocess.run(["/bin/sh", "-c", SCRIPT + '\nrch_remote_cancel "$1" 42 kill',
                                         "live-recovery", str(record)], capture_output=True, text=True, timeout=40)
                self.assertEqual(result.returncode, 0, result.stderr)
                import select
                poll = select.poll()
                poll.register(child_fd, select.POLLIN)
                self.assertTrue(poll.poll(1000), "detached descendant is still alive")
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
                if child_fd is not None:
                    try:
                        signal.pidfd_send_signal(child_fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.close(child_fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
