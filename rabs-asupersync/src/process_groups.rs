//! Managed process groups under attempt ownership (bead G006; plan §189).
//!
//! Every external action runs as the **leader of its own POSIX process
//! group**: the spawn pins `process_group(0)` so the leader becomes a
//! group whose pgid equals the leader pid, and every descendant the
//! action forks joins that group automatically (inherited pgid). This is
//! what makes cancellation and cleanup *complete*: signaling the group
//! reaches build scripts, compilers, and grandchildren that a
//! leader-only kill would orphan.
//!
//! Ownership shape (plan §10.7, invariant I7): the group carries the
//! [`Attribution`] of its owning attempt, so any leaked effect found by
//! the leak scanner attributes along region → coordinator authority →
//! operation → generation → action → attempt exactly like every other
//! runtime resource in this crate.
//!
//! The controlled bounded wait mounts G008's TERM → drain → KILL → reap
//! ordering. The caller owns cancellation/deadline classification; this
//! module returns the real process status and never publishes a result.
//! Supervision/restart budgets remain in G010 (`supervision.rs`).
//!
//! Safety posture: the workspace forbids `unsafe`. Group formation uses
//! the stable `std::os::unix::process::CommandExt::process_group` (no
//! `pre_exec`), and group signaling shells out to `kill(1)` with a
//! negative pid — the standard dependency-free way to reach a whole
//! group from safe Rust.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};

use crate::region_tree::Attribution;

/// Signal delivered to a whole process group via `kill(1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSignal {
    /// Graceful request (`TERM`).
    Term,
    /// Unconditional (`KILL`).
    Kill,
    /// Hangup (`HUP`) — used when draining session leaders.
    Hup,
}

impl GroupSignal {
    fn name(self) -> &'static str {
        match self {
            Self::Term => "TERM",
            Self::Kill => "KILL",
            Self::Hup => "HUP",
        }
    }
}

/// One descendant observed in the action's process group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    /// Thread-group id (the pid as `kill(1)` sees it).
    pub pid: i32,
    /// Parent pid within or outside the group.
    pub ppid: i32,
    /// Process state letter (`R`, `S`, `D`, …). `Z` (zombie) members are
    /// filtered out during scanning — they hold no execution resource
    /// and are reaped by their surviving parent or pid 1.
    pub state: char,
    /// Executable name from `/proc/<pid>/stat` (parenthesized, may contain
    /// spaces — parsed defensively).
    pub comm: String,
}

/// Specification for one managed external action launch.
#[derive(Debug, Clone)]
pub struct ProcessGroupSpec {
    /// Program argv[0].
    pub program: String,
    /// Remaining arguments.
    pub args: Vec<String>,
    /// Working directory for the leader (action cwd).
    pub working_dir: Option<String>,
    /// Attempt ownership rendered for tracing/crashpacks (I7 chain).
    pub attribution: Attribution,
}

impl ProcessGroupSpec {
    /// A minimal spec with empty attribution (tests, ad-hoc tools).
    #[must_use]
    pub fn new(program: impl Into<String>, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().collect(),
            working_dir: None,
            attribution: Attribution::default(),
        }
    }
}

/// A running external action pinned to its own process group.
///
/// Drop does **not** kill the group: lifecycle policy belongs to the
/// supervisor/supersync region that owns the attempt (G008/G010). The
/// struct exists to make membership observable and group-wide signaling
/// possible — never to hide an exit decision.
#[derive(Debug)]
pub struct ManagedProcessGroup {
    /// Leader pid == pgid (pinned by `process_group(0)`).
    pgid: u32,
    leader: Child,
    /// Last observed group membership (call [`Self::refresh_members`]).
    pub members: Vec<GroupMember>,
    /// Attempt ownership for attribution chains (never mutated).
    pub attribution: Attribution,
}

impl ManagedProcessGroup {
    /// Spawn `spec` as a process-group leader.
    ///
    /// Stdio defaults to null so an action cannot accidentally hold the
    /// coordinator's terminal; callers needing pipes pass a configurator
    /// to [`spawn_with`]. The leader's pgid is asserted against `/proc`
    /// immediately after spawn so a platform that silently ignored the
    /// grouping request fails loudly here instead of corrupting cleanup
    /// later.
    pub fn spawn(spec: &ProcessGroupSpec) -> io::Result<Self> {
        Self::spawn_with(spec, |cmd| {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
        })
    }

    /// Spawn with caller-controlled `Command` configuration (stdio,
    /// environment, jobserver auth injection — see `jobserver.rs`).
    pub fn spawn_with(
        spec: &ProcessGroupSpec,
        configure: impl FnOnce(&mut Command),
    ) -> io::Result<Self> {
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args).process_group(0);
        if let Some(dir) = &spec.working_dir {
            cmd.current_dir(dir);
        }
        configure(&mut cmd);
        let leader = cmd.spawn()?;
        Self::verify_group_formation(leader, spec.attribution.clone())
    }

    /// Shared construction tail: verify the leader actually leads a
    /// fresh group before handing the handle out.
    #[allow(unused_mut)]
    fn verify_group_formation(mut leader: Child, attribution: Attribution) -> io::Result<Self> {
        let pgid = leader.id();
        // Fail loudly if the grouping request was not honored: a group we
        // cannot trust would make every later group-signal wrong. A leader
        // that already exited before the probe is fine — wait() surfaces
        // its status; a LIVE leader absent from every /proc pgrp means the
        // platform ignored process_group(0) and cleanup would be a lie.
        #[cfg(target_os = "linux")]
        let members = {
            let probe = members_from_proc(pgid);
            match leader.try_wait()? {
                Some(_) => {}
                None => {
                    if !probe
                        .iter()
                        .any(|m| m.pid == i32::try_from(pgid).unwrap_or(-1))
                        // Re-check exit before condemning: a leader that
                        // exited between try_wait and the scan above is a
                        // zombie our membership filter hides — the group WAS
                        // honored, and wait_with_output will surface the
                        // status. Only a STILL-RUNNING leader absent from
                        // every pgrp means the platform ignored the request.
                        && leader.try_wait()?.is_none()
                    {
                        return Err(io::Error::other(format!(
                            "process_group(0) not honored: live leader pid {pgid} not found in any /proc pgrp"
                        )));
                    }
                }
            }
            probe
        };
        #[cfg(not(target_os = "linux"))]
        let members = members_from_proc(pgid);

        Ok(Self {
            pgid,
            leader,
            members,
            attribution,
        })
    }
    /// Group id (== leader pid by construction).
    #[must_use]
    pub fn pgid(&self) -> u32 {
        self.pgid
    }

    /// Re-scan `/proc` for current group membership.
    ///
    /// Returns the number of members now registered (including the
    /// leader while it lives). Descendants that forked since the last
    /// refresh appear here; nothing else can add members, because group
    /// membership is inherited, not joined.
    pub fn refresh_members(&mut self) -> io::Result<usize> {
        self.members = members_from_proc(self.pgid);
        Ok(self.members.len())
    }

    /// Non-blocking leader status poll (does not reap descendants).
    pub fn leader_try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.leader.try_wait()
    }

    /// Block on the leader. Descendants are NOT waited: they die or
    /// reparent per the caller's group policy (G008).
    pub fn wait_leader(&mut self) -> io::Result<ExitStatus> {
        self.leader.wait()
    }

    /// Deliver `sig` to the entire group (negative pid targets pgid).
    ///
    /// Uses `kill(1)` because sending signals from safe std Rust is not
    /// otherwise expressible under `forbid(unsafe_code)`. Failure means
    /// the group outlived this call — callers decide escalation (G008).
    pub fn signal_group(&self, sig: GroupSignal) -> io::Result<()> {
        // `--` is required: without it kill(1) parses the negative pgid
        // as another option-like token instead of an operand.
        let status = Command::new("kill")
            .arg(format!("-{}", sig.name()))
            .arg("--")
            .arg(format!("-{}", self.pgid))
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "kill -{} -- -{} failed: {status}",
                sig.name(),
                self.pgid
            )))
        }
    }

    /// Spawn a caller-built `Command` as a process-group leader.
    ///
    /// For integrations that already own command construction (stdio
    /// wiring, environment, namespace argv — e.g. the worker's bwrap
    /// launcher), this pins ONLY the group formation and attribution;
    /// stdio is whatever the caller set. The same live-leader probe as
    /// [`Self::spawn`] applies: a grouping request the platform ignored
    /// is a typed error, never a silently unmanaged tree.
    ///
    /// # Errors
    /// Typed [`io::Error`] from the spawn, or when `process_group(0)`
    /// was not honored for a still-running leader.
    pub fn spawn_command(mut command: Command, attribution: Attribution) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // New session-less group: pgid := child pid. Safe std API;
            // this workspace forbids unsafe, so no pre_exec/setsid here.
            command.process_group(0);
        }
        let leader = command.spawn()?;
        Self::verify_group_formation(leader, attribution)
    }

    /// Drain both captured streams to EOF, then reap the leader. EOF
    /// happens when EVERY writer holding the pipes closes them —
    /// including orphaned group members — so output is complete before
    /// the exit status is decided (G007's bounded drain builds on this
    /// ordering). Capture [`Self::pgid`] first for post-exit
    /// [`reap_residuals`].
    ///
    /// # Errors
    /// Typed [`io::Error`] from stream drains or the wait itself.
    pub fn wait_with_output(self) -> io::Result<std::process::Output> {
        self.leader.wait_with_output()
    }

    /// Drain both streams with G007 resident bounds and reap the group.
    /// Callers without cancellation retain the same output/cleanup contract.
    pub fn wait_with_bounded_drain(
        self,
        limits: &crate::stream_drain::DrainLimits,
    ) -> io::Result<crate::stream_drain::DrainedOutput> {
        self.wait_with_bounded_drain_controlled(limits, || false)
    }

    /// Drain stdout/stderr while observing a caller-owned stop condition.
    ///
    /// This is blocking process supervision and MUST run off an async reactor.
    /// `stop_requested` is polled while the leader is alive. The first stop
    /// sends TERM to the owned group; after 250 ms, KILL is sent regardless of
    /// whether TERM succeeded. No timer thread keeps a raw PID after this
    /// ownership ends. The returned status is the REAL leader status: callers
    /// must retain their stop reason even when a TERM handler exits with zero.
    ///
    /// Group cleanup precedes BOTH lane joins, including wait errors. A failed
    /// stdout archive must not cause the stderr thread to be silently detached.
    /// The containment limit remains POSIX process-group membership; descendants
    /// that deliberately escape require the sandbox's namespace/cgroup fence.
    ///
    /// # Errors
    /// Wait, pipe-drain, or spill errors, after attempting group cleanup and
    /// joining both output lanes. The default aggregate stdout/stderr budget is
    /// [`crate::stream_drain::DEFAULT_MAX_CAPTURE_BYTES`]. Drain I/O failure,
    /// budget exhaustion or a lane startup failure stops the process immediately
    /// through the same TERM/KILL policy. No partial capture becomes success.
    /// The stop predicate must not panic.
    pub fn wait_with_bounded_drain_controlled(
        self,
        limits: &crate::stream_drain::DrainLimits,
        stop_requested: impl FnMut() -> bool,
    ) -> io::Result<crate::stream_drain::DrainedOutput> {
        self.wait_with_bounded_drain_budget(
            limits,
            crate::stream_drain::DEFAULT_MAX_CAPTURE_BYTES,
            stop_requested,
        )
    }

    /// Managed capture with an explicit aggregate byte budget. Zero permits
    /// empty streams only; resident bytes consume the same budget as spill bytes.
    /// The limit is execution-resource policy, not a compiler-success condition.
    /// On failure the process is stopped, residuals are closed, both lanes are
    /// joined, and an error is returned even if a TERM handler exits with zero.
    pub fn wait_with_bounded_drain_budget(
        mut self,
        limits: &crate::stream_drain::DrainLimits,
        maximum: u64,
        mut stop_requested: impl FnMut() -> bool,
    ) -> io::Result<crate::stream_drain::DrainedOutput> {
        use crate::stream_drain::MonitoredLanes;
        use std::time::{Duration, Instant};

        let lanes = MonitoredLanes::spawn(&mut self.leader, limits, maximum);
        let mut stopping_at = None;
        let mut killed = false;
        let status = loop {
            match self.leader.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(error) => {
                    // Never return while the failed wait still owns live work.
                    let _ = self.signal_group(GroupSignal::Kill);
                    let _ = self.leader.kill();
                    let _ = self.leader.wait();
                    break Err(error);
                }
            }
            if stopping_at.is_none() && (lanes.failed() || stop_requested()) {
                stopping_at = Some(Instant::now());
                let _ = self.signal_group(GroupSignal::Term);
            }
            if !killed
                && stopping_at.is_some_and(|at: Instant| at.elapsed() >= Duration::from_millis(250))
            {
                if self.signal_group(GroupSignal::Kill).is_err() {
                    // A missing/failing kill utility must not leave the leader
                    // running. Residual cleanup below still reports descendants.
                    let _ = self.leader.kill();
                }
                killed = true;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let residual_group_members = reap_residuals(self.pgid);
        // Join both lanes even when waiting for the process itself failed.
        let streams = lanes.join();
        let status = status?;
        let (stdout, stderr) = streams?;
        Ok(crate::stream_drain::DrainedOutput {
            status,
            stdout,
            stderr,
            residual_group_members,
        })
    }

    /// Post-leader-exit closer: guarantee NO live member survives
    /// management. Polls briefly for natural exit (orphans reparent to
    /// pid 1 and are reaped), escalates to a group KILL at half grace,
    /// then verifies empty. Returns the residual LIVE-member count — 0
    /// means fully resolved; anything else is an honest incident record
    /// for the receipt/crashpack.
    #[must_use]
    pub fn reap_residuals(&self) -> u32 {
        reap_residuals(self.pgid)
    }
}

/// Free-function closer for pgids whose handle is already consumed
/// (`wait_with_output` takes ownership). Same contract as
/// [`ManagedProcessGroup::reap_residuals`].
#[must_use]
pub fn reap_residuals(pgid: u32) -> u32 {
    const POLLS: usize = 20;
    const POLL_MILLIS: u64 = 10;

    let mut escalated = false;
    for poll in 0..=POLLS {
        if members_from_proc(pgid).is_empty() {
            return 0;
        }
        if poll == POLLS / 2 && !escalated {
            // Half the grace spent: force. KILL needs no cooperation, so
            // one pass suffices; remaining polls VERIFY emptiness.
            escalated = true;
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg("--")
                .arg(format!("-{pgid}"))
                .status();
        }
        std::thread::sleep(std::time::Duration::from_millis(POLL_MILLIS));
    }
    members_from_proc(pgid).len() as u32
}

/// Snapshot every process whose pgid equals `pgid`, from `/proc`.
///
/// Parses `/proc/<pid>/stat` defensively: `comm` is parenthesized and may
/// contain spaces *and* parentheses, so fields are taken relative to the
/// LAST `)`. Layout after it: `state ppid pgrp …`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn members_from_proc(pgid: u32) -> Vec<GroupMember> {
    let mut members = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return members;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue; // not a pid directory
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue; // raced exit or permission
        };
        let Some((comm, rest)) = split_stat_fields(&stat) else {
            continue;
        };
        // rest: state(0) ppid(1) pgrp(2) …
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let Ok(member_pgrp) = fields[2].parse::<u32>() else {
            continue;
        };
        if member_pgrp == pgid {
            let state = fields[0].chars().next().unwrap_or('?');
            if state != 'Z' {
                members.push(GroupMember {
                    pid,
                    ppid: fields[1].parse().unwrap_or(-1),
                    state,
                    comm,
                });
            }
        }
    }
    members.sort_by_key(|m| m.pid);
    members
}

/// Non-Linux stub: no `/proc`, membership stays empty (fixture tests are
/// Linux-only; CI workers are Linux per README Limitations).
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn members_from_proc(_pgid: u32) -> Vec<GroupMember> {
    Vec::new()
}

/// Split `/proc/<pid>/stat` into `(comm, fields_after_comm)`.
#[cfg(any(target_os = "linux", test))]
fn split_stat_fields(stat: &str) -> Option<(String, &str)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close < open {
        return None;
    }
    Some((stat[open + 1..close].to_owned(), &stat[close + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn capture_budget_exact_boundary_keeps_both_binary_streams() {
        let dir = tempfile::tempdir().unwrap();
        let group = ManagedProcessGroup::spawn_with(
            &spec("sh", "printf 'A\\000B'; printf 'C\\377DE' >&2"),
            |cmd| { cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()); },
        ).unwrap();
        let output = group.wait_with_bounded_drain_budget(
            &crate::stream_drain::DrainLimits { resident_bound: 0, spill_dir: dir.path().join("spill") },
            7, || false,
        ).unwrap();
        assert!(output.status.success());
        assert_eq!(std::fs::read(&output.stdout.spill().unwrap().path).unwrap(), b"A\0B");
        assert_eq!(std::fs::read(&output.stderr.spill().unwrap().path).unwrap(), b"C\xffDE");
        assert_eq!(output.stdout.total_bytes() + output.stderr.total_bytes(), 7);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capture_budget_terminates_long_lived_writers_without_waiting_for_caller_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let group = ManagedProcessGroup::spawn_with(
            &spec("sh", "trap '' TERM; printf abcd; printf efgh >&2; sleep 30 & wait"),
            |cmd| { cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()); },
        ).unwrap();
        let pgid = group.pgid();
        let start = Instant::now();
        let mut external_stop = false;
        let error = group.wait_with_bounded_drain_budget(
            &crate::stream_drain::DrainLimits { resident_bound: 0, spill_dir: dir.path().join("spill") },
            7,
            || { external_stop = start.elapsed() >= Duration::from_secs(3); external_stop },
        ).unwrap_err();
        assert!(!external_stop, "only the caller's timeout stopped the failed capture");
        assert!(matches!(error.get_ref().and_then(|e| e.downcast_ref::<crate::stream_drain::DrainFailure>()),
            Some(crate::stream_drain::DrainFailure::OutputLimitExceeded { maximum: 7 })));
        assert!(members_from_proc(pgid).is_empty());
        let retained: u64 = ["stdout.spill", "stderr.spill"].iter().map(|name| {
            std::fs::metadata(dir.path().join("spill").join(name)).map_or(0, |m| m.len())
        }).sum();
        assert!(retained <= 7, "quota was enforced only after writing");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spill_io_failure_stops_execution_and_joins_the_other_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("not-a-directory");
        std::fs::write(&blocked, b"preserve").unwrap();
        let group = ManagedProcessGroup::spawn_with(
            &spec("sh", "printf failed-spill; sleep 30 & wait"),
            |cmd| { cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()); },
        ).unwrap();
        let pgid = group.pgid();
        let start = Instant::now();
        let mut external_stop = false;
        let error = group.wait_with_bounded_drain_controlled(
            &crate::stream_drain::DrainLimits { resident_bound: 0, spill_dir: blocked.clone() },
            || { external_stop = start.elapsed() >= Duration::from_secs(3); external_stop },
        ).unwrap_err();
        assert!(!external_stop, "drain failure did not reach the process owner");
        assert!(error.to_string().contains("stdout.spill"));
        assert!(members_from_proc(pgid).is_empty());
        assert_eq!(std::fs::read(blocked).unwrap(), b"preserve");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_zero_exit_term_handler_cannot_turn_truncated_output_into_success() {
        let dir = tempfile::tempdir().unwrap();
        let group = ManagedProcessGroup::spawn_with(
            &spec("sh", "trap 'exit 0' TERM; printf too-long; while :; do sleep 1; done"),
            |cmd| { cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()); },
        ).unwrap();
        let pgid = group.pgid();
        let start = Instant::now();
        let outcome = group.wait_with_bounded_drain_budget(
            &crate::stream_drain::DrainLimits { resident_bound: 64, spill_dir: dir.path().join("spill") },
            1, || start.elapsed() >= Duration::from_secs(3),
        );
        assert!(outcome.is_err());
        assert!(members_from_proc(pgid).is_empty());
    }

    fn spec(program: &str, script: &str) -> ProcessGroupSpec {
        let mut s = ProcessGroupSpec::new(program, ["-c".to_owned(), script.to_owned()]);
        s.attribution.attempt = Some("attempt-G006-test".to_owned());
        s
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn group_membership_covers_descendants() {
        // Fixture: leader shells out and forks two background children;
        // all four pids (sh + 2 sleeps + subshell) must share one pgid.
        let mut group =
            ManagedProcessGroup::spawn(&spec("sh", "sleep 30 & sleep 30 & wait")).expect("spawn");
        assert_eq!(group.pgid(), group.leader.id());

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            group.refresh_members().expect("scan");
            if group.members.len() >= 3 || Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            group.members.len() >= 3,
            "expected leader + descendants, got {:?}",
            group.members
        );
        // The leader itself must be registered, and membership is exactly
        // the set of pids sharing the group id — members_from_proc already
        // filters on pgrp, so assert the leader is present and pids are
        // unique.
        let leader_pid = i32::try_from(group.pgid()).expect("pid fits i32");
        assert!(
            group.members.iter().any(|m| m.pid == leader_pid),
            "leader missing from its own group: {:?}",
            group.members
        );
        let mut seen: Vec<i32> = group.members.iter().map(|m| m.pid).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), group.members.len(), "duplicate member pids");

        group.signal_group(GroupSignal::Kill).expect("kill group");
        let status = group.wait_leader().expect("reap");
        assert!(!status.success(), "killed leader reported success");

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = members_from_proc(group.pgid());
            if remaining.is_empty() || Instant::now() > deadline {
                assert!(remaining.is_empty(), "group survived KILL: {remaining:?}");
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn attribution_flows_into_group() {
        let mut group = ManagedProcessGroup::spawn(&spec("sh", "exit 0")).expect("spawn");
        assert_eq!(
            group.attribution.attempt.as_deref(),
            Some("attempt-G006-test")
        );
        let _ = group.wait_leader();
    }

    #[test]
    fn split_stat_handles_parens_and_spaces_in_comm() {
        let line = "123 ((weird) name) S 1 123 0 0 -1 4194560 …";
        let (comm, rest) = split_stat_fields(line).expect("parse");
        assert_eq!(comm, "(weird) name");
        let fields: Vec<&str> = rest.split_whitespace().collect();
        assert_eq!(fields[0], "S");
        assert_eq!(fields[1], "1"); // ppid
        assert_eq!(fields[2], "123"); // pgrp == pid (group leader)
    }

    #[test]
    fn signaling_dead_group_reports_error() {
        // After the leader is reaped and its (empty) group is gone, a
        // group-signal must surface the failure instead of pretending.
        let mut group = ManagedProcessGroup::spawn(&spec("sh", "exit 0")).expect("spawn");
        let status = group.wait_leader().expect("reap");
        assert!(status.success());

        // Wait for /proc to drop every trace of the group.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !members_from_proc(group.pgid()).is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            group.signal_group(GroupSignal::Term).is_err(),
            "signaling a dead group unexpectedly succeeded"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn controlled_wait_escalates_and_drains_both_streams() {
        let dir = tempfile::tempdir().unwrap();
        let group = ManagedProcessGroup::spawn_with(
            &spec("sh", "trap '' TERM; printf stdout-ready; printf stderr-ready >&2; sleep 30 & wait"),
            |cmd| {
                cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            },
        )
        .unwrap();
        let pgid = group.pgid();
        let start = Instant::now();
        let output = group
            .wait_with_bounded_drain_controlled(
                &crate::stream_drain::DrainLimits {
                    resident_bound: 1024,
                    spill_dir: dir.path().join("spill"),
                },
                || start.elapsed() >= Duration::from_millis(100),
            )
            .unwrap();
        assert!(!output.status.success());
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(output.stdout.resident(), b"stdout-ready");
        assert_eq!(output.stderr.resident(), b"stderr-ready");
        assert_eq!(output.residual_group_members, 0);
        assert!(members_from_proc(pgid).is_empty());
    }

    #[test]
    fn controlled_wait_preserves_natural_failure_and_output() {
        let dir = tempfile::tempdir().unwrap();
        let group = ManagedProcessGroup::spawn_with(
            &spec("sh", "printf ordinary-out; printf ordinary-error >&2; exit 7"),
            |cmd| {
                cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            },
        )
        .unwrap();
        let output = group
            .wait_with_bounded_drain_controlled(
                &crate::stream_drain::DrainLimits {
                    resident_bound: 1024,
                    spill_dir: dir.path().join("spill"),
                },
                || false,
            )
            .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout.resident(), b"ordinary-out");
        assert_eq!(output.stderr.resident(), b"ordinary-error");
    }
}
