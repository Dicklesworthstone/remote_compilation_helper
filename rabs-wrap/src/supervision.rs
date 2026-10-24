//! Linux process ownership for admitted local compiles (bd-k52xe).
//!
//! The wrapper remains Cargo's child. A separate invocation of THIS executable
//! supervises rustc in its own process group, outside Cargo's foreground group.
//! Losing the wrapper (including SIGKILL) OR its original caller stops that
//! compiler group. Both birth identities and the parent relation are captured
//! before the daemon consult: reparenting cannot adopt an orphaned request.
//! The guard retains its unreaped child until the group is observed quiescent,
//! so a recycled PID can never become the target of cleanup. Signal delivery is
//! not completion: normal compiler exit also waits for remaining group members
//! and threads to stop before returning the compiler's status for output capture.
//!
//! No runtime, unsafe code, signal-handler thread, PATH-resolved kill utility,
//! shell interpolation, or compiler environment additions. This is process-group
//! ownership on Linux, NOT containment of a hostile process that calls setsid.
//! The system kill utility and a matching procfs PID namespace exposing the
//! supervised group's members are prerequisites.

use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const GUARD_ARGUMENT: &str = "--rabs-internal-compiler-guard-v1";
const POLL: Duration = Duration::from_millis(20);
const KILL_BUDGET: Duration = Duration::from_secs(2);
const MAX_SCAN_ENTRIES: usize = 262_144;

#[derive(Debug, Clone, Copy)]
struct Stat {
    pid: u32,
    parent: u32,
    group: u32,
    start: u64,
    state: u8,
}

impl Stat {
    fn exited(self) -> bool {
        matches!(self.state, b'Z' | b'X' | b'x')
    }
}

fn number<T: std::str::FromStr>(bytes: &[u8]) -> Option<T> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// comm can contain spaces, newlines, parentheses, and non-UTF-8 bytes. The
/// numeric fields begin AFTER its final closing parenthesis, not at word 3.
fn parse_stat(bytes: &[u8]) -> Option<Stat> {
    let space = bytes.iter().position(|byte| *byte == b' ')?;
    if bytes.get(space + 1) != Some(&b'(') {
        return None;
    }
    let end = bytes.iter().rposition(|byte| *byte == b')')?;
    let mut fields = bytes
        .get(end + 1..)?
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty());
    let state = fields.next()?;
    if state.len() != 1 || !b"RSDZTtXxKWPI".contains(&state[0]) {
        return None;
    }
    Some(Stat {
        pid: number(&bytes[..space])?,
        parent: number(fields.next()?)?,
        group: number(fields.next()?)?,
        start: number(fields.nth(16)?)?,
        state: state[0],
    })
}

fn read_stat_path(path: &Path, pid: u32) -> io::Result<Stat> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(8193)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(io::Error::other("oversized process identity"));
    }
    parse_stat(&bytes)
        .filter(|stat| stat.pid == pid)
        .ok_or_else(|| io::Error::other("invalid process identity"))
}

fn read_stat(pid: u32) -> io::Result<Stat> {
    read_stat_path(Path::new(&format!("/proc/{pid}/stat")), pid)
}

fn process_disappeared(error: &io::Error) -> bool {
    // An already-open procfs descriptor can return ESRCH after its task exits.
    error.kind() == io::ErrorKind::NotFound
        || (cfg!(target_os = "linux") && error.raw_os_error() == Some(3))
}

fn scan_budget(entries: &mut usize, deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "compiler group quiescence was not confirmed before the deadline",
        ));
    }
    if *entries >= MAX_SCAN_ENTRIES {
        return Err(io::Error::other(
            "compiler group scan exceeded its entry bound",
        ));
    }
    *entries += 1;
    Ok(())
}

/// Observe every visible process in the pinned compiler group, including the
/// threads of zombie process leaders. A leader's Z state alone does not prove
/// that all of its threads have exited. Only disappearance is benign during
/// enumeration; malformed or inaccessible identities leave cleanup unknown.
///
/// None means at least one member can still execute. Some records the birth
/// identities of all terminal members, for a second independent sweep before
/// reaping the leader. This is not a substitute for cgroup containment of a
/// process that deliberately escapes its group or changes its credentials.
fn quiescent_group_snapshot(
    proc_root: &Path,
    leader: u32,
    parent: u32,
    deadline: Instant,
) -> io::Result<Option<Vec<(u32, u64)>>> {
    let mut entries = 0;
    scan_budget(&mut entries, deadline)?;
    let leader_path = proc_root.join(leader.to_string()).join("stat");
    let pinned = read_stat_path(&leader_path, leader)?;
    if pinned.parent != parent || pinned.group != leader {
        return Err(io::Error::other(
            "compiler group lost its unreaped leader fence",
        ));
    }
    if !pinned.exited() {
        return Ok(None);
    }
    let mut terminal = Vec::new();
    for entry in std::fs::read_dir(proc_root)? {
        scan_budget(&mut entries, deadline)?;
        let entry = entry?;
        let Some(pid) = number::<u32>(entry.file_name().as_bytes()) else {
            continue;
        };
        let process_path = entry.path();
        let stat = match read_stat_path(&process_path.join("stat"), pid) {
            Ok(stat) => stat,
            Err(error) if process_disappeared(&error) => continue,
            Err(error) => return Err(error),
        };
        if stat.group != leader {
            continue;
        }
        if !stat.exited() {
            return Ok(None);
        }
        terminal.push((stat.pid, stat.start));
        let tasks = match std::fs::read_dir(process_path.join("task")) {
            Ok(tasks) => tasks,
            Err(error) if process_disappeared(&error) => {
                // The task directory of a known group member is not optional.
                // In particular, a terminated main thread can leave live tasks.
                // Ignore only a process that has itself disappeared as well.
                match read_stat_path(&process_path.join("stat"), pid) {
                    Err(gone) if process_disappeared(&gone) && pid != leader => {
                        continue;
                    }
                    _ => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        for task in tasks {
            scan_budget(&mut entries, deadline)?;
            let task = task?;
            let tid = number::<u32>(task.file_name().as_bytes())
                .ok_or_else(|| io::Error::other("invalid compiler task directory"))?;
            let stat = match read_stat_path(&task.path().join("stat"), tid) {
                Ok(stat) => stat,
                Err(error) if process_disappeared(&error) => continue,
                Err(error) => return Err(error),
            };
            if stat.group != leader {
                return Err(io::Error::other("compiler task changed its process group"));
            }
            if !stat.exited() {
                return Ok(None);
            }
            terminal.push((stat.pid, stat.start));
        }
    }
    scan_budget(&mut entries, deadline)?;
    let after = read_stat_path(&leader_path, leader)?;
    if after.start != pinned.start
        || after.parent != parent
        || after.group != leader
        || !after.exited()
    {
        return Err(io::Error::other(
            "compiler leader changed during group observation",
        ));
    }
    terminal.sort_unstable();
    terminal.dedup();
    if !terminal.contains(&(leader, pinned.start)) {
        return Err(io::Error::other(
            "compiler leader was absent from the group scan",
        ));
    }
    Ok(Some(terminal))
}

/// Captured before the daemon consult, never reconstructed from an orphan's
/// new parent. Birth identities prevent another process borrowing either PID.
#[derive(Debug, Clone, Copy)]
pub(super) struct Owner {
    pid: u32,
    start: u64,
    caller_pid: u32,
    caller_start: u64,
}

impl Owner {
    pub(super) fn capture() -> io::Result<Self> {
        if !cfg!(target_os = "linux") {
            // Preserve the existing non-Linux lane; no Linux supervision claim.
            return Ok(Self {
                pid: std::process::id(),
                start: 0,
                caller_pid: 0,
                caller_start: 0,
            });
        }
        if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unqualified supervisor architecture",
            ));
        }
        // A detached process group must not change terminal input semantics.
        // Interactive callers retain the original direct-exec path instead.
        if io::stdin().is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "interactive compiler input",
            ));
        }
        // /proc/self must agree with the process-visible namespace too. Reading
        // /proc/<pid> alone can observe an unrelated host process in a container.
        let bytes = std::fs::read("/proc/self/stat")?;
        let stat = parse_stat(&bytes)
            .filter(|stat| stat.pid == std::process::id())
            .ok_or_else(|| io::Error::other("procfs PID namespace mismatch"))?;
        // An already-lost caller is cancellation, NOT a setup failure granting
        // direct-exec fallback. Retain an invalid binding so spawn refuses to
        // execute even if the wrapper has acquired a new parent meanwhile.
        let caller = read_stat(stat.parent)
            .ok()
            .filter(|caller| !caller.exited());
        Ok(Self {
            pid: stat.pid,
            start: stat.start,
            caller_pid: caller.map_or(0, |caller| caller.pid),
            caller_start: caller.map_or(0, |caller| caller.start),
        })
    }

    /// Recheck the original caller after output capture as well as before
    /// execution. Caller death cannot turn a late capture into publication.
    pub(super) fn can_acknowledge_capture(self) -> bool {
        self.pid == std::process::id() && (!cfg!(target_os = "linux") || self.alive())
    }

    fn alive(self) -> bool {
        self.caller_pid != 0
            && read_stat(self.pid).is_ok_and(|stat| {
                stat.start == self.start && stat.parent == self.caller_pid && !stat.exited()
            })
            && read_stat(self.caller_pid)
                .is_ok_and(|stat| stat.start == self.caller_start && !stat.exited())
    }
}

fn spawn_with_etxtbsy_retry(command: &mut Command) -> io::Result<Child> {
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match command.spawn() {
            Err(error)
                if (error.kind() == io::ErrorKind::ExecutableFileBusy
                    || error.raw_os_error() == Some(26))
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

/// No compiler has started when this returns Err. The caller may abandon the
/// admission and exec the original chain, without publishing an observed run.
/// A lost caller instead terminates the wrapper: cancellation must never pass
/// through that ordinary fail-open error path and start an orphaned compiler.
pub(super) fn spawn(
    compiler: &OsStr,
    args: &[OsString],
    env: &[(String, String)],
    owner: Owner,
) -> io::Result<Child> {
    if !cfg!(target_os = "linux") {
        return spawn_with_etxtbsy_retry(
            Command::new(compiler)
                .args(args)
                .env_clear()
                .envs(env.iter().map(|(key, value)| (key, value)))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        );
    }
    if owner.pid != std::process::id() || !owner.alive() {
        eprintln!("rabs-wrap: compiler caller disappeared before execution");
        std::process::exit(1);
    }
    kill_program()?;
    spawn_with_etxtbsy_retry(
        Command::new("/proc/self/exe")
            .arg(GUARD_ARGUMENT)
            .arg(owner.pid.to_string())
            .arg(owner.start.to_string())
            .arg(owner.caller_pid.to_string())
            .arg(owner.caller_start.to_string())
            .arg("--")
            .arg(compiler)
            .args(args)
            .env_clear()
            .envs(env.iter().map(|(key, value)| (key, value)))
            .process_group(0)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
}

fn kill_program() -> io::Result<&'static str> {
    use std::os::unix::fs::PermissionsExt;
    ["/bin/kill", "/usr/bin/kill"]
        .into_iter()
        .find(|path| {
            std::fs::metadata(path)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "system kill utility unavailable"))
}

/// Called before the public wrapper argument decoder. All arguments after --
/// are opaque OsStrings; they are never interpreted as shell source.
pub(super) fn run_if_guard() {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(OsStr::new(GUARD_ARGUMENT)) {
        return;
    }
    let result = (|| -> io::Result<ExitStatus> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid compiler guard request",
            )
        };
        let owner = Owner {
            pid: args
                .next()
                .and_then(|s| s.to_str()?.parse().ok())
                .ok_or_else(invalid)?,
            start: args
                .next()
                .and_then(|s| s.to_str()?.parse().ok())
                .ok_or_else(invalid)?,
            caller_pid: args
                .next()
                .and_then(|s| s.to_str()?.parse().ok())
                .ok_or_else(invalid)?,
            caller_start: args
                .next()
                .and_then(|s| s.to_str()?.parse().ok())
                .ok_or_else(invalid)?,
        };
        if args.next().as_deref() != Some(OsStr::new("--")) {
            return Err(invalid());
        }
        let compiler = args.next().ok_or_else(invalid)?;
        let own = Owner::capture()?;
        let stat = read_stat(own.pid)?;
        if stat.parent != owner.pid || stat.group != own.pid || !owner.alive() {
            return Err(io::Error::other(
                "compiler guard is not owned by the requesting wrapper and caller",
            ));
        }
        // An inherited ignored SIGCHLD would auto-reap children and remove our
        // PID-reuse fence. Linux's supported dependency hosts use signal 17.
        let status = std::fs::read_to_string("/proc/self/status")?;
        let ignored = status
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .ok_or_else(invalid)?;
        if ignored & (1 << 16) != 0 {
            return Err(io::Error::other(
                "ignored SIGCHLD prevents compiler ownership",
            ));
        }
        let kill = kill_program()?;
        let child = spawn_with_etxtbsy_retry(Command::new(compiler).args(args).process_group(0))?;
        let mut owned = OwnedCompiler {
            child,
            kill,
            reaped: false,
        };
        loop {
            let stat = read_stat(owned.child.id())?;
            if stat.parent != own.pid || stat.group != owned.child.id() {
                return Err(io::Error::other("compiler escaped its owned process group"));
            }
            if !owner.alive() {
                owned.finish()?;
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "compiler wrapper or original caller disappeared",
                ));
            }
            if stat.exited() {
                return owned.finish();
            }
            std::thread::sleep(POLL);
        }
    })();
    match result {
        Ok(status) => super::exit_like(status),
        Err(error) => {
            eprintln!("rabs-wrap: compiler supervision: {error}");
            std::process::exit(if error.kind() == io::ErrorKind::NotFound {
                127
            } else {
                1
            });
        }
    }
}

struct OwnedCompiler {
    child: Child,
    kill: &'static str,
    reaped: bool,
}

impl OwnedCompiler {
    fn kill_group(&self) -> io::Result<()> {
        // child was spawned with PGID=PID; it has NEVER been waited/reaped.
        // Do not add try_wait here: even a successful poll would lose that fence.
        if self.child.id() <= 1 || self.child.id() == std::process::id() {
            return Err(io::Error::other("invalid owned compiler process group"));
        }
        let mut kill = Command::new(self.kill)
            .args(["-KILL", "--", &format!("-{}", self.child.id())])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + KILL_BUDGET;
        loop {
            if let Some(status) = kill.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(
                        "compiler group termination was not confirmed",
                    ))
                };
            }
            if Instant::now() >= deadline {
                let _ = kill.kill();
                let _ = kill.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "compiler group termination timed out",
                ));
            }
            std::thread::sleep(POLL);
        }
    }

    fn finish(&mut self) -> io::Result<ExitStatus> {
        self.kill_group()?;
        let deadline = Instant::now() + KILL_BUDGET;
        let mut previous = None;
        loop {
            let current = quiescent_group_snapshot(
                Path::new("/proc"),
                self.child.id(),
                std::process::id(),
                deadline,
            )?;
            if current.is_some() && current == previous {
                // Keep the PID fence through two independent terminal sweeps.
                // Never expose a successful compiler status on signal delivery
                // alone, while descendants could still change captured outputs.
                let status = self.child.wait()?;
                self.reaped = true;
                return Ok(status);
            }
            previous = current;
            std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

impl Drop for OwnedCompiler {
    fn drop(&mut self) {
        if !self.reaped {
            // Covers ordinary errors and unwind. Direct child kill is a last
            // resort after group failure, never evidence of complete cleanup.
            let _ = self.kill_group();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(comm: &[u8], state: &str, start: &str) -> Vec<u8> {
        let mut out = b"123 (".to_vec();
        out.extend_from_slice(comm);
        out.extend_from_slice(
            format!(") {state} 99 123 {} {start} 0\n", ["0"; 16].join(" ")).as_bytes(),
        );
        out
    }

    #[test]
    fn identity_parser_handles_real_comm_grammar_without_pid_aliasing() {
        for comm in [b"rustc".as_slice(), b"a ) ( b\n", b"name-\xff"] {
            let parsed = parse_stat(&stat(comm, "Z", "456")).unwrap();
            assert_eq!(
                (parsed.pid, parsed.parent, parsed.group, parsed.start),
                (123, 99, 123, 456)
            );
            assert!(parsed.exited());
        }
        for input in [
            stat(b"x", "?", "456"),
            stat(b"x", "S", "-1"),
            stat(b"x", "S", "18446744073709551616"),
            b"123 (truncated) S 99".to_vec(),
        ] {
            assert!(parse_stat(&input).is_none());
        }
    }

    #[cfg(target_os = "linux")]
    fn current_owner() -> Owner {
        let stat = read_stat(std::process::id()).unwrap();
        let caller = read_stat(stat.parent).unwrap();
        Owner {
            pid: stat.pid,
            start: stat.start,
            caller_pid: caller.pid,
            caller_start: caller.start,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_pid_with_a_different_birth_identity_is_not_the_owner() {
        let owner = current_owner();
        assert!(owner.alive());
        let reused = Owner {
            start: owner.start.wrapping_add(1),
            ..owner
        };
        assert!(!reused.alive());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn caller_birth_and_parent_relation_cannot_be_substituted() {
        let owner = current_owner();
        assert!(owner.alive());
        for changed in [
            Owner {
                caller_start: owner.caller_start.wrapping_add(1),
                ..owner
            },
            Owner {
                caller_pid: owner.pid,
                caller_start: owner.start,
                ..owner
            },
            Owner {
                caller_pid: 0,
                caller_start: 0,
                ..owner
            },
        ] {
            assert!(!changed.alive(), "invalid owner accepted: {changed:?}");
        }
    }

    fn fake_stat(path: &Path, pid: u32, parent: u32, group: u32, state: char) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            format!(
                "{pid} (compiler ) worker) {state} {parent} {group} {} 456 0\n",
                ["0"; 16].join(" ")
            ),
        )
        .unwrap();
    }

    fn fake_process(root: &Path, pid: u32, group: u32, state: char) {
        let process = root.join(pid.to_string());
        fake_stat(&process.join("stat"), pid, 99, group, state);
        fake_stat(
            &process.join(format!("task/{pid}/stat")),
            pid,
            99,
            group,
            state,
        );
    }

    fn snapshot(root: &Path) -> io::Result<Option<Vec<(u32, u64)>>> {
        quiescent_group_snapshot(root, 123, 99, Instant::now() + Duration::from_secs(2))
    }

    #[test]
    fn group_completion_requires_every_member_to_be_terminal() {
        let dir = tempfile::tempdir().unwrap();
        fake_process(dir.path(), 123, 123, 'Z');
        // An unrelated process does not block this group's completion.
        fake_process(dir.path(), 200, 200, 'R');
        assert_eq!(snapshot(dir.path()).unwrap(), Some(vec![(123, 456)]));
        for state in ['R', 'S', 'D', 'T', 't', 'I'] {
            fake_process(dir.path(), 456, 123, state);
            assert!(snapshot(dir.path()).unwrap().is_none(), "{state}");
        }
        fake_process(dir.path(), 456, 123, 'Z');
        assert_eq!(
            snapshot(dir.path()).unwrap(),
            Some(vec![(123, 456), (456, 456)])
        );
    }

    #[test]
    fn zombie_process_leader_does_not_hide_a_live_thread() {
        let dir = tempfile::tempdir().unwrap();
        fake_process(dir.path(), 123, 123, 'Z');
        fake_stat(&dir.path().join("123/task/124/stat"), 124, 99, 123, 'D');
        assert!(snapshot(dir.path()).unwrap().is_none());
        fake_stat(&dir.path().join("123/task/124/stat"), 124, 99, 123, 'Z');
        assert_eq!(
            snapshot(dir.path()).unwrap(),
            Some(vec![(123, 456), (124, 456)])
        );
    }

    #[test]
    fn incomplete_process_observation_cannot_confirm_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        assert!(snapshot(dir.path()).is_err());
        fake_process(dir.path(), 123, 123, 'Z');
        fake_process(dir.path(), 456, 123, 'Z');
        std::fs::write(dir.path().join("456/stat"), b"truncated").unwrap();
        assert!(snapshot(dir.path()).is_err());
        fake_process(dir.path(), 456, 123, 'Z');
        // A known member with an unavailable task directory is uncertain,
        // not evidence that it has no live threads.
        std::fs::rename(dir.path().join("456/task"), dir.path().join("saved-task")).unwrap();
        assert!(snapshot(dir.path()).is_err());
    }

    #[test]
    fn group_observation_requires_the_original_parent_and_a_live_deadline() {
        let dir = tempfile::tempdir().unwrap();
        fake_process(dir.path(), 123, 123, 'Z');
        assert!(
            quiescent_group_snapshot(
                dir.path(),
                123,
                100,
                Instant::now() + Duration::from_secs(2)
            )
            .is_err()
        );
        let error = quiescent_group_snapshot(dir.path(), 123, 99, Instant::now()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let mut entries = MAX_SCAN_ENTRIES;
        assert!(scan_budget(&mut entries, Instant::now() + Duration::from_secs(2)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_signal_helper_cannot_authorize_live_group_completion() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut owned = OwnedCompiler {
            child,
            kill: "/bin/true",
            reaped: false,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !read_stat(owned.child.id()).unwrap().exited() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(POLL);
        }
        // Keep a second child in the same group while the unreaped leader
        // already has exit 0. /bin/true simulates a successful signal send
        // that has not actually stopped this member (e.g. pending fatal I/O).
        let mut member = Command::new("/bin/sleep")
            .arg("30")
            .process_group(i32::try_from(owned.child.id()).expect("compiler PID fits pid_t"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let result = owned.finish();
        let retained_fence = !owned.reaped;
        // Clean up before assertions, including when run against the old
        // implementation, which incorrectly returned the leader's exit 0.
        let _ = member.kill();
        member.wait().unwrap();
        owned.kill = kill_program().unwrap();
        if !owned.reaped {
            assert!(owned.finish().unwrap().success());
        }
        assert!(
            retained_fence,
            "unconfirmed group cleanup reaped the PID fence"
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
