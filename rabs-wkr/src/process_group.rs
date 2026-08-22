//! Managed process groups under attempt ownership (bead G006; M2
//! deliverable "managed process groups for current whole-command remote
//! actions"; invariants I7 region-owned external effects, I16 no cache
//! poisoning by abnormal termination).
//!
//! Every external action is spawned as the LEADER of its own fresh POSIX
//! process group (`pgid == leader pid`, via the safe std API
//! [`std::os::unix::process::CommandExt::process_group`]). Cancellation
//! therefore addresses the whole tree with ONE group signal
//! (`kill -TERM -- -PGID`, escalation `kill -KILL -- -PGID`) instead of
//! racing individual pids — the primitive G008's graceful TERM → drain →
//! escalate → reap policy composes, and the shape that retires RCH's ad
//! hoc remote-PGID-file + SSH-kill logic.
//!
//! Membership is DISCOVERED, not assumed: `/proc/<pid>/stat` field 5
//! (pgrp) enumerates every live group member, including descendants that
//! daemonized away from the leader's children. Zombies are dead (their
//! parent or pid 1 reaps them) and are never counted as residuals.
//!
//! Signaling shells out to the external `kill` binary because this crate
//! forbids `unsafe` and std exposes no safe killpg — same house style as
//! `df -Pk` in [`crate::session`]. Verified against procps kill:
//! `kill -TERM -- -<pgid>` signals exactly the group.
//!
//! On non-unix hosts there are no process groups; callers must refuse
//! execution there first (the canonical-namespace probe already does).

use std::io;
use std::process::{Child, Command, ExitStatus, Stdio};

/// One live (non-zombie) process discovered in a managed group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    /// PID from `/proc/<pid>/stat`.
    pub pid: u32,
    /// Process state letter (`R`, `S`, `D`, …). `Z` (zombie) members are
    /// filtered out of membership entirely — they cannot run again.
    pub state: char,
}

/// A spawned action leading its own process group.
///
/// The group is the unit of cancellation: drop the handle AFTER
/// [`ManagedProcessGroup::wait_with_output`] plus
/// [`reap_residuals`] so no member can outlive management.
#[derive(Debug)]
pub struct ManagedProcessGroup {
    /// The fresh group id (== leader pid).
    pub pgid: u32,
    leader: Child,
}

impl ManagedProcessGroup {
    /// Spawn `command` with stdout/stderr captured, as leader of a NEW
    /// process group. The caller owns reading the captured streams via
    /// [`Self::wait_with_output`].
    ///
    /// # Errors
    /// Typed [`io::Error`] when the child cannot be spawned.
    pub fn spawn(mut command: Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // New session-less group: pgid := child pid. Safe std API;
            // this crate forbids unsafe, so no pre_exec/setsid here.
            command.process_group(0);
        }
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let leader = command.spawn()?;
        Ok(Self {
            pgid: leader.id(),
            leader,
        })
    }

    /// Consume the group: drain both captured streams to EOF, then reap
    /// the leader. EOF happens when EVERY writer holding the pipes
    /// closes them, which includes orphaned group members — so output is
    /// complete before exit status is decided (G007 builds its bounded
    /// drain on this ordering). Ownership passes to std, matching
    /// [`std::process::Child::wait_with_output`]; capture `pgid` first
    /// for post-exit [`reap_residuals`].
    ///
    /// # Errors
    /// Typed [`io::Error`] from stream drains or the wait itself.
    pub fn wait_with_output(self) -> io::Result<std::process::Output> {
        self.leader.wait_with_output()
    }

    /// Reap the leader alone (status without stream capture); used by
    /// cancellation paths where G007-style draining already happened.
    ///
    /// # Errors
    /// Typed [`io::Error`] from the wait itself.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.leader.wait()
    }
}

/// Parse one `/proc/<pid>/stat` line into `(state, pgrp)`.
///
/// Layout: `pid (comm) state ppid pgrp …`. `comm` may contain spaces and
/// parentheses, so parsing starts after the LAST `)`. Malformed lines
/// yield `None` (a torn read mid-proc-refresh is benign, never a crash).
#[must_use]
fn parse_stat_fields(stat: &str) -> Option<(char, u32)> {
    let close = stat.rfind(')')?;
    let fields = stat[close + 1..].split_whitespace();
    let mut iter = fields;
    let state = iter.next()?.chars().next()?;
    let _ppid = iter.next()?;
    let pgrp = iter.next()?.parse::<u32>().ok()?;
    Some((state, pgrp))
}

/// Enumerate LIVE members of `pgid` from `/proc`.
///
/// An unreadable `/proc` yields an empty list (honest "unknown"), never
/// a fabricated clean bill.
#[must_use]
pub fn group_members(pgid: u32) -> Vec<GroupMember> {
    let mut members = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return members;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue; // /proc also carries non-numeric entries
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue; // raced exit: fine
        };
        if let Some((state, pgrp)) = parse_stat_fields(&stat) {
            // 'Z' zombies hold no execution resource and are reaped by
            // their surviving parent or pid 1 — they never count as a
            // live member needing a signal.
            if pgrp == pgid && state != 'Z' {
                members.push(GroupMember { pid, state });
            }
        }
    }
    members.sort_unstable_by_key(|m| m.pid);
    members
}

/// One group-directed signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSignal {
    /// Cooperative stop (`SIGTERM`) — the graceful first step.
    GracefulTerm,
    /// Unstoppable teardown (`SIGKILL`) — escalation only.
    ForceKill,
}

impl GroupSignal {
    fn name(self) -> &'static str {
        match self {
            Self::GracefulTerm => "TERM",
            Self::ForceKill => "KILL",
        }
    }
}

/// Signal every member of `pgid` at once (`kill -<SIG> -- -<pgid>`).
///
/// # Errors
/// Typed [`io::Error`] when the external `kill` binary is missing or
/// reports failure (e.g. the whole group already exited — treat as done).
pub fn signal_group(pgid: u32, signal: GroupSignal) -> io::Result<()> {
    let status = Command::new("kill")
        .args([
            format!("-{}", signal.name()),
            "--".to_string(),
            format!("-{pgid}"),
        ])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "kill -{} -- -{pgid} failed: {status}",
            signal.name()
        )))
    }
}

/// Post-leader-exit closer: guarantee NO live member survives management.
///
/// Polls briefly for natural exit (orphans reparent to pid 1 and get
/// reaped), then escalates to a group KILL, then verifies empty. Returns
/// the residual LIVE-member count — 0 means the group is fully resolved;
/// anything else is an honest incident record for the receipt/crashpack.
#[must_use]
pub fn reap_residuals(pgid: u32) -> u32 {
    const POLLS: usize = 20;
    const POLL_MILLIS: u64 = 10;

    let mut escalated = false;
    for poll in 0..=POLLS {
        if group_members(pgid).is_empty() {
            return 0;
        }
        if poll == POLLS / 2 && !escalated {
            // Half the grace spent: force. KILL needs no cooperation, so
            // one pass suffices; remaining polls VERIFY emptiness.
            escalated = true;
            let _ = signal_group(pgid, GroupSignal::ForceKill);
        }
        std::thread::sleep(std::time::Duration::from_millis(POLL_MILLIS));
    }
    group_members(pgid).len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parsing_handles_comm_with_spaces_and_parens() {
        // pid=1234, comm contains spaces AND parens, state=S, ppid=1,
        // pgrp=999 — the parser must skip comm by the LAST ')'.
        let line = "1234 (weird (comm) name) S 1 999 55 0 0 0\n";
        assert_eq!(parse_stat_fields(line), Some(('S', 999)));
    }

    #[test]
    fn stat_parsing_reads_standard_layout() {
        // pid (sh) state ppid pgrp
        let line = "1602058 (sh) Ss 1601000 1602058 0 0\n";
        assert_eq!(parse_stat_fields(line), Some(('S', 1602058)));
    }

    #[test]
    fn malformed_stat_lines_yield_none_not_crash() {
        assert_eq!(parse_stat_fields(""), None);
        assert_eq!(parse_stat_fields("12 (unterminated"), None);
        assert_eq!(parse_stat_fields("12 (x) R notanumber"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unknown_pgid_has_no_members() {
        // Practically unclaimable pgid; /proc readable or not, empty.
        assert!(group_members(u32::MAX - 1).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_spawn_leads_fresh_group_and_term_resolves_it() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("sleep 30 & sleep 30 & wait");
        let mut group = ManagedProcessGroup::spawn(cmd).expect("spawn");
        assert_ne!(group.pgid, std::process::id(), "fresh group, not ours");

        // Wait for the two background sleeps to exist.
        let mut saw_children = false;
        for _ in 0..50 {
            if group_members(group.pgid).len() >= 3 {
                saw_children = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(saw_children, "leader + 2 sleeps share the managed pgid");

        signal_group(group.pgid, GroupSignal::GracefulTerm).expect("group TERM");
        let status = group.wait().expect("reap leader");
        // A signal-killed process has NO exit code; the signal itself is
        // the truth (SIGTERM = 15). The 128+15 ENCODING happens where
        // ExecResult is built, not in std's ExitStatus.
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(15), "leader died by group SIGTERM");
        assert_eq!(reap_residuals(group.pgid), 0, "no survivors after TERM");
    }
}
