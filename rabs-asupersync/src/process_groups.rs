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
//! Deliberately OUT of scope here (neighboring beads):
//! - graceful TERM → drain → escalate → reap policy (G008) — this module
//!   provides only the primitive `ManagedProcessGroup::signal_group`;
//! - termination classification for publication eligibility (G009);
//! - supervision/restart budgets (G010, `supervision.rs`).
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
    /// Graceful request (`TERM`) — escalation to [`GroupSignal::Kill`] is
    /// G008 policy, not this primitive.
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
    fn verify_group_formation(leader: Child, attribution: Attribution) -> io::Result<Self> {
        let pgid = leader.id();
        let mut group = Self {
            pgid,
            leader,
            members: Vec::new(),
            attribution,
        };
        // Fail loudly if the grouping request was not honored: a group we
        // cannot trust would make every later group-signal wrong. A leader
        // that already exited before the probe is fine — wait() surfaces
        // its status; a LIVE leader absent from every /proc pgrp means the
        // platform ignored process_group(0) and cleanup would be a lie.
        let probe = members_from_proc(pgid);
        match group.leader.try_wait()? {
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
                    && group.leader.try_wait()?.is_none()
                {
                    return Err(io::Error::other(format!(
                        "process_group(0) not honored: live leader pid {pgid} not found in any /proc pgrp"
                    )));
                }
            }
        }
        group.members = probe;
        Ok(group)
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

    fn spec(program: &str, script: &str) -> ProcessGroupSpec {
        let mut s = ProcessGroupSpec::new(program, ["-c".to_owned(), script.to_owned()]);
        s.attribution.attempt = Some("attempt-G006-test".to_owned());
        s
    }

    #[test]
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
}
