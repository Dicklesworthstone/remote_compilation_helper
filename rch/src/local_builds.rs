//! Loud local-build detection on dispatcher boxes (bd-sb836).
//!
//! The recurring dispatcher failure mode: interception silently stops
//! covering builds — the cargo shim dies, or someone invokes
//! `~/.rustup/.../bin/cargo` by absolute path — and the box burns local
//! cores with zero signal (the 2026-07-16 meltdown, the 2026-07-23 trj
//! incident). This module makes that state observable.
//!
//! A running compiler process counts as a LOCAL build when it is NOT
//! rch-managed:
//!
//! - its environment carries `RCH_CARGO_WRAPPER_BYPASS=1` (rch sets this
//!   on its own local-fallback execs — see `crate::commands::shim`), OR
//! - its ancestry contains an `rch` process (an `rch exec` spawn);
//!
//! otherwise — no bypass env AND no rch ancestor — it is an unmanaged
//! local build that interception missed.
//!
//! Reads only `/proc` surfaces world-readable on Linux; environ is
//! same-user only, so for foreign-user processes classification falls
//! back to ancestry alone. Non-Linux platforms report no local builds
//! rather than guessing.

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

/// One unmanaged compiler process found running locally.
#[derive(Debug, Clone)]
pub struct LocalBuild {
    pub pid: i32,
    /// Kernel command name (`/proc/<pid>/comm`, ≤15 chars).
    pub comm: String,
    /// Resolved executable path when readable.
    pub exe: Option<PathBuf>,
}

/// Env var rch sets on its own local-fallback execs.
pub const MANAGED_BYPASS_ENV: &str = "RCH_CARGO_WRAPPER_BYPASS";

/// Bounded PPID walk: /proc ancestry cycles would hang the scan.
#[cfg(target_os = "linux")]
const MAX_ANCESTRY_DEPTH: usize = 16;

/// Scan the live process table for unmanaged compiler processes.
/// Empty on non-Linux platforms.
#[must_use]
pub fn scan_local_builds() -> Vec<LocalBuild> {
    #[cfg(target_os = "linux")]
    {
        scan_local_builds_in(Path::new("/proc"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn scan_local_builds_in(proc_root: &Path) -> Vec<LocalBuild> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return found;
    };
    let self_pid = std::process::id() as i32;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let proc_dir = entry.path();
        let Some(comm) = read_comm(&proc_dir) else {
            // Kernel threads and exiting processes have no comm.
            continue;
        };
        if !is_compiler_comm(&comm) {
            continue;
        }
        if is_zombie(&proc_dir) {
            continue;
        }
        if is_rch_managed(proc_root, pid) {
            continue;
        }
        let exe = std::fs::read_link(proc_dir.join("exe")).ok();
        found.push(LocalBuild { pid, comm, exe });
    }
    found.sort_unstable_by_key(|b| b.pid);
    found
}

/// Compilers we care about catching. `comm` is truncated to 15 bytes by
/// the kernel, so prefix matching covers suffixed names (`rustc-lld`,
/// versioned cargo wrappers).
#[must_use]
#[cfg(target_os = "linux")]
fn is_compiler_comm(comm: &str) -> bool {
    comm == "cargo" || comm.starts_with("rustc")
}

#[cfg(target_os = "linux")]
fn read_comm(proc_dir: &Path) -> Option<String> {
    std::fs::read_to_string(proc_dir.join("comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn is_zombie(proc_dir: &Path) -> bool {
    stat_fields(proc_dir)
        .map(|(_, state, _)| state == 'Z')
        .unwrap_or(false)
}

/// Is this pid rch-managed: bypass env present, or an `rch` ancestor?
#[cfg(target_os = "linux")]
fn is_rch_managed(proc_root: &Path, pid: i32) -> bool {
    if environ_has_bypass(&proc_root.join(format!("{pid}/environ"))) {
        return true;
    }
    ancestry_has_rch(proc_root, pid)
}

/// NUL-separated environ contains `RCH_CARGO_WRAPPER_BYPASS=`.
#[must_use]
#[cfg(target_os = "linux")]
fn environ_has_bypass(environ_path: &Path) -> bool {
    std::fs::read(environ_path)
        .map(|env| {
            env.split(|&b| b == 0)
                .any(|entry| entry.starts_with(format!("{MANAGED_BYPASS_ENV}=").as_bytes()))
        })
        .unwrap_or(false)
}

/// Walk the PPID chain looking for a process whose comm is exactly
/// `rch` (the hook CLI — an `rch exec` parent). `rchd` does NOT count:
/// the daemon legitimately coexists with unrelated local tooling.
#[cfg(target_os = "linux")]
fn ancestry_has_rch(proc_root: &Path, start_pid: i32) -> bool {
    let mut visited = HashSet::new();
    let mut current = start_pid;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        if !visited.insert(current) {
            return false; // cycle guard
        }
        let Some((_, _, ppid)) = stat_fields(&proc_root.join(current.to_string())) else {
            return false; // process exited mid-walk
        };
        if ppid <= 1 {
            return false;
        }
        match read_comm(&proc_root.join(ppid.to_string())) {
            Some(comm) if comm == "rch" => return true,
            Some(_) => current = ppid,
            None => return false,
        }
    }
    false
}

/// `(pid_after_paren, state_char, ppid)` from `/proc/<pid>/stat`.
///
/// `comm` may contain spaces and parentheses, so everything through the
/// LAST `)` is the comm field.
#[cfg(target_os = "linux")]
#[must_use]
fn stat_fields(proc_dir: &Path) -> Option<(i32, char, i32)> {
    let raw = std::fs::read_to_string(proc_dir.join("stat")).ok()?;
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    let pid: i32 = raw[..open].trim().parse().ok()?;
    let rest = raw[close + 1..].split_whitespace();
    let mut fields = rest.map(str::to_string);
    let state = fields.next()?.chars().next()?;
    let ppid: i32 = fields.next()?.parse().ok()?;
    Some((pid, state, ppid))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn compiler_comms_match_and_non_compilers_do_not() {
        assert!(is_compiler_comm("cargo"));
        assert!(is_compiler_comm("rustc"));
        assert!(is_compiler_comm("rustc-lld"));
        assert!(is_compiler_comm("rustc-1.99"));
        assert!(!is_compiler_comm("rustup"));
        assert!(!is_compiler_comm("bash"));
        assert!(!is_compiler_comm("rch"));
        assert!(!is_compiler_comm("rchd"));
        assert!(!is_compiler_comm(""));
    }

    #[test]
    fn bypass_env_detected_in_synthetic_environ() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("environ");
        std::fs::write(
            &path,
            b"PATH=/usr/bin\0RCH_CARGO_WRAPPER_BYPASS=1\0HOME=/home/u\0",
        )
        .expect("write");
        assert!(environ_has_bypass(&path));

        std::fs::write(&path, b"PATH=/usr/bin\0HOME=/home/u\0").expect("rewrite");
        assert!(!environ_has_bypass(&path));

        // Prefix collisions must not match (different var entirely).
        std::fs::write(&path, b"RCH_CARGO_WRAPPER_BYPASSX=1\0").expect("rewrite2");
        assert!(!environ_has_bypass(&path));
    }

    #[test]
    fn missing_environ_is_not_bypassed() {
        assert!(
            !environ_has_bypass(Path::new("/definitely/not/here/environ")),
            "unreadable environ must classify as NOT bypassed so the \
             ancestry check still gets a chance"
        );
    }

    #[test]
    fn own_ancestry_has_no_rch_process() {
        // The test harness binary is not named `rch`; walking up from
        // here exercises the real parser without ever finding `rch`.
        #[cfg(target_os = "linux")]
        assert!(!ancestry_has_rch(
            Path::new("/proc"),
            std::process::id() as i32
        ));
    }

    #[test]
    fn stat_parser_handles_spaces_and_parens_in_comm() {
        let dir = tempfile::tempdir().expect("dir");
        let proc_dir = dir.path().join("4242");
        std::fs::create_dir_all(&proc_dir).expect("proc dir");
        std::fs::write(
            proc_dir.join("stat"),
            "4242 (weird (cargo) name) S 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        )
        .expect("stat");
        let (pid, state, ppid) = stat_fields(&proc_dir).expect("parsed");
        assert_eq!(pid, 4242);
        assert_eq!(state, 'S');
        assert_eq!(ppid, 17);
    }

    #[test]
    fn zombie_detection_works_on_real_self() {
        // The test process itself is alive, not a zombie.
        #[cfg(target_os = "linux")]
        {
            let self_dir = Path::new("/proc").join(std::process::id().to_string());
            assert!(!is_zombie(&self_dir));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_scan_finds_real_cargo_and_respects_bypass_env() {
        // Spawn the REAL cargo binary (`--version` exits in tens of
        // millis) with the bypass marker stripped: an unmanaged cargo
        // process the detector must catch. NOTE: copies of binaries are
        // not usable here — this box refuses to exec untrusted copies
        // (exit 1 before main) — so we use the genuine toolchain cargo.
        let real_cargo = std::env::var("CARGO")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("cargo"));
        let spawn = |managed: bool| {
            let mut cmd = std::process::Command::new(&real_cargo);
            cmd.arg("--version");
            if managed {
                cmd.env(MANAGED_BYPASS_ENV, "1");
            } else {
                // The harness itself may carry rch's local-fallback
                // bypass marker; children inherit it and would read as
                // managed. Strip it for the unmanaged case.
                cmd.env_remove(MANAGED_BYPASS_ENV);
            }
            cmd.spawn().expect("spawn real cargo")
        };

        // Unmanaged: poll-scan until seen (--version exits quickly, so
        // retry within a bounded window instead of a fixed sleep).
        let mut child = spawn(false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut seen = false;
        while std::time::Instant::now() < deadline {
            if scan_local_builds()
                .iter()
                .any(|b| b.pid == child.id() as i32)
            {
                seen = true;
                break;
            }
            if child
                .try_wait()
                .expect("poll child")
                .is_some_and(|status| !status.success())
            {
                break; // exited with failure — no point retrying
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(seen, "unmanaged real cargo must be detected while alive");
        let _ = child.kill();
        let _ = child.wait();

        // Managed via bypass env → excluded. Absence is stable even
        // after exit, so a single scan after a settle delay suffices.
        let mut managed = spawn(true);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let found = scan_local_builds();
        assert!(
            !found.iter().any(|b| b.pid == managed.id() as i32),
            "bypass-env process must NOT be flagged: {found:?}"
        );
        let _ = managed.kill();
        let _ = managed.wait();
    }
}
