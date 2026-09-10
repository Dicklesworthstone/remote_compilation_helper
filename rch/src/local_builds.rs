//! Loud local-build detection on dispatcher boxes (bd-sb836).
//!
//! The recurring dispatcher failure mode: interception silently stops
//! covering builds — the cargo shim dies, or someone invokes
//! `~/.rustup/.../bin/cargo` by absolute path — and the box burns local
//! cores with zero signal (the 2026-07-16 meltdown, the 2026-07-23 trj
//! incident). This module makes that state observable.
//!
//! A running compiler process is rch-managed when either:
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
//! back to ancestry alone. Non-Linux platforms report detection unavailable.

#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rch_common::BoxRole;

/// One unmanaged compiler process found running locally.
#[derive(Debug, Clone)]
pub struct LocalBuild {
    pub pid: i32,
    /// Kernel command name (`/proc/<pid>/comm`, ≤15 chars).
    pub comm: String,
    /// Resolved executable path when readable.
    pub exe: Option<PathBuf>,
}

/// A persisted change in the current local-build episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmTransition {
    Started,
    Recovered,
}

/// Current observation; a failed scan is never represented as a clean machine.
#[derive(Debug)]
pub struct LocalBuildObservation {
    pub builds: Vec<LocalBuild>,
    pub scan_error: Option<String>,
    pub state_error: Option<String>,
    pub transition: Option<AlarmTransition>,
}

impl LocalBuildObservation {
    /// Current warning remains visible on every report, independently of the
    /// edge-triggered log event and any failure to persist its latch.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        if !self.builds.is_empty() {
            Some(format!(
                "{} local builds on a dispatcher — interception not covering them \
                 (check PATH order / absolute-path .rustup/.../bin/cargo invocations)",
                self.builds.len()
            ))
        } else if let Some(error) = &self.scan_error {
            Some(format!("Local build detection unavailable: {error}"))
        } else {
            self.state_error
                .as_ref()
                .map(|error| format!("Local build alarm state unavailable: {error}"))
        }
    }
}

/// Observe dispatcher processes, persisting a shared latch across status and
/// doctor invocations. Worker/hybrid roles neither scan nor change that latch.
#[must_use]
pub fn observe(role: BoxRole) -> Option<LocalBuildObservation> {
    let state_path = dirs::cache_dir().map(|dir| dir.join("rch/local-build-alarm"));
    let observation = observe_with_scan(role, state_path.as_deref(), scan_local_builds)?;
    match observation.transition {
        Some(AlarmTransition::Started) => {
            if let Some(message) = observation.warning() {
                tracing::warn!(
                    local_build_count = observation.builds.len(),
                    "RCH LOCAL BUILD ALARM: {message}"
                );
            }
        }
        Some(AlarmTransition::Recovered) => tracing::info!(
            "RCH local build interception recovered: no unmanaged compiler processes remain"
        ),
        None => {}
    }
    Some(observation)
}

fn observe_with_scan(
    role: BoxRole,
    state_path: Option<&Path>,
    scan: impl FnOnce() -> io::Result<Vec<LocalBuild>>,
) -> Option<LocalBuildObservation> {
    if role != BoxRole::Dispatcher {
        return None;
    }

    // Lock before scanning: simultaneous CLI polls cannot commit observations
    // in the opposite order. A lock failure still allows a current warning.
    let state = state_path
        .ok_or_else(|| io::Error::other("cannot determine the cache directory"))
        .and_then(lock_alarm_state);
    let mut observation = LocalBuildObservation {
        builds: Vec::new(),
        scan_error: None,
        state_error: None,
        transition: None,
    };
    match scan() {
        Ok(builds) => observation.builds = builds,
        Err(error) => observation.scan_error = Some(error.to_string()),
    }
    match state {
        Ok(mut state) if observation.scan_error.is_none() => {
            match update_alarm_state(&mut state, !observation.builds.is_empty()) {
                Ok(transition) => observation.transition = transition,
                Err(error) => observation.state_error = Some(error.to_string()),
            }
        }
        Ok(_) => {} // Unknown scan must not clear an active episode.
        Err(error) => observation.state_error = Some(error.to_string()),
    }
    Some(observation)
}

fn lock_alarm_state(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "another status/doctor poll holds the local build alarm lock",
                ));
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }
}

fn update_alarm_state(file: &mut File, active: bool) -> io::Result<Option<AlarmTransition>> {
    // Keep a single locked inode and a one-byte latch. Never rename it while
    // another invocation may already have this same inode open for locking.
    let mut contents = Vec::new();
    file.seek(SeekFrom::Start(0))?;
    (&mut *file).take(2).read_to_end(&mut contents)?;
    let was_active = match contents.as_slice() {
        [] | [b'0'] => false,
        [b'1'] => true,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid local build alarm state; episode transition was not recorded",
            ));
        }
    };
    if was_active == active {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(0))?;
    file.write_all(if active { b"1" } else { b"0" })?;
    file.sync_data()?;
    Ok(Some(if active {
        AlarmTransition::Started
    } else {
        AlarmTransition::Recovered
    }))
}

/// Env var rch sets on its own local-fallback execs.
pub const MANAGED_BYPASS_ENV: &str = "RCH_CARGO_WRAPPER_BYPASS";

/// Bounded PPID walk: /proc ancestry cycles would hang the scan.
#[cfg(target_os = "linux")]
const MAX_ANCESTRY_DEPTH: usize = 16;

/// Scan the live process table for unmanaged compiler processes.
/// Errors on unavailable process tables, including non-Linux platforms.
pub fn scan_local_builds() -> io::Result<Vec<LocalBuild>> {
    #[cfg(target_os = "linux")]
    {
        scan_local_builds_in(Path::new("/proc"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local build detection requires Linux /proc",
        ))
    }
}

#[cfg(target_os = "linux")]
fn scan_local_builds_in(proc_root: &Path) -> io::Result<Vec<LocalBuild>> {
    let mut found = Vec::new();
    let entries = std::fs::read_dir(proc_root)?;
    let self_pid = std::process::id() as i32;
    for entry in entries {
        let entry = entry?;
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
        let Some(comm) = read_comm(&proc_dir)? else {
            // The process exited after the directory listing.
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
    Ok(found)
}

/// Compilers we care about catching. Cargo may use the shim's preserved
/// `cargo-rch-real` executable name. `comm` is truncated to 15 bytes by the
/// kernel, so prefix matching covers suffixed rustc names (`rustc-lld`).
#[cfg(any(target_os = "linux", test))]
#[must_use]
fn is_compiler_comm(comm: &str) -> bool {
    comm == "cargo" || comm == "cargo-rch-real" || comm.starts_with("rustc")
}

#[cfg(target_os = "linux")]
fn read_comm(proc_dir: &Path) -> io::Result<Option<String>> {
    let raw = match std::fs::read_to_string(proc_dir.join("comm")) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let comm = raw.trim();
    if comm.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty process command name; local build scan is incomplete",
        ));
    }
    Ok(Some(comm.to_string()))
}

#[cfg(target_os = "linux")]
fn is_zombie(proc_dir: &Path) -> bool {
    stat_fields(proc_dir)
        .map(|(_, state, _)| state == 'Z')
        .unwrap_or(false)
}

/// Is this pid rch-managed: bypass env enabled, or an `rch` ancestor?
#[cfg(target_os = "linux")]
fn is_rch_managed(proc_root: &Path, pid: i32) -> bool {
    if environ_has_bypass(&proc_root.join(format!("{pid}/environ"))) {
        return true;
    }
    ancestry_has_rch(proc_root, pid)
}

/// NUL-separated environ contains the same enabled value as the cargo shim.
#[cfg(any(target_os = "linux", test))]
#[must_use]
fn environ_has_bypass(environ_path: &Path) -> bool {
    std::fs::read(environ_path)
        .map(|env| {
            env.split(|&b| b == 0)
                .any(|entry| entry == b"RCH_CARGO_WRAPPER_BYPASS=1")
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
            Ok(Some(comm)) if comm == "rch" => return true,
            Ok(Some(_)) => current = ppid,
            Ok(None) | Err(_) => return false,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn one_build() -> Vec<LocalBuild> {
        vec![LocalBuild {
            pid: 4242,
            comm: "cargo".to_string(),
            exe: None,
        }]
    }

    #[test]
    fn local_build_alarm_persists_enter_repeat_clear_and_reentry() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("alarm");
        for (active, expected) in [
            (false, None),
            (true, Some(AlarmTransition::Started)),
            (true, None),
            (false, Some(AlarmTransition::Recovered)),
            (false, None),
            (true, Some(AlarmTransition::Started)),
        ] {
            // Each observation opens its own file handle, just like separate
            // status and doctor processes sharing the same cache directory.
            let observation = observe_with_scan(BoxRole::Dispatcher, Some(&state_path), || {
                Ok(if active { one_build() } else { Vec::new() })
            })
            .unwrap();
            assert_eq!(observation.transition, expected);
            assert!(observation.scan_error.is_none());
            assert!(observation.state_error.is_none());
            assert_eq!(observation.warning().is_some(), active);
        }
        assert_eq!(std::fs::read(state_path).unwrap(), b"1");
    }

    #[test]
    fn local_build_alarm_other_roles_do_not_scan_or_change_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("alarm");
        for role in [BoxRole::Worker, BoxRole::Hybrid] {
            let mut scanned = false;
            assert!(
                observe_with_scan(role, Some(&state_path), || {
                    scanned = true;
                    Ok(one_build())
                })
                .is_none()
            );
            assert!(!scanned);
            assert!(!state_path.exists());
        }
    }

    #[test]
    fn local_build_alarm_unknown_scan_preserves_active_episode() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("alarm");
        std::fs::write(&state_path, b"1").unwrap();
        let observation = observe_with_scan(BoxRole::Dispatcher, Some(&state_path), || {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "proc unreadable",
            ))
        })
        .unwrap();
        assert!(observation.scan_error.is_some());
        assert!(observation.warning().unwrap().contains("unavailable"));
        assert_eq!(observation.transition, None);
        assert_eq!(std::fs::read(state_path).unwrap(), b"1");
    }

    #[test]
    fn local_build_alarm_persistence_errors_do_not_hide_live_builds() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("alarm");
        std::fs::write(&state_path, b"corrupt").unwrap();
        for path in [None, Some(dir.path()), Some(state_path.as_path())] {
            let observation =
                observe_with_scan(BoxRole::Dispatcher, path, || Ok(one_build())).unwrap();
            assert!(observation.state_error.is_some());
            assert!(observation.scan_error.is_none());
            assert_eq!(observation.transition, None);
            assert!(observation.warning().unwrap().contains("1 local builds"));
        }
        assert_eq!(std::fs::read(state_path).unwrap(), b"corrupt");
    }

    #[test]
    fn local_build_alarm_concurrent_callers_emit_one_transition() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("alarm");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                let state_path = state_path.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    observe_with_scan(BoxRole::Dispatcher, Some(&state_path), || Ok(one_build()))
                        .unwrap()
                })
            })
            .collect();
        let observations: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(
            observations
                .iter()
                .all(|observation| observation.state_error.is_none())
        );
        assert!(
            observations
                .iter()
                .all(|observation| observation.builds.len() == 1)
        );
        assert_eq!(
            observations
                .iter()
                .filter(|observation| observation.transition == Some(AlarmTransition::Started))
                .count(),
            1
        );
    }

    #[test]
    fn local_build_alarm_serializes_scans_before_recording_recovery() {
        use std::sync::mpsc;

        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("alarm");
        let (first_entered, first_scan) = mpsc::channel();
        let (release_first, release) = mpsc::channel();
        let first_path = state_path.clone();
        let first = std::thread::spawn(move || {
            observe_with_scan(BoxRole::Dispatcher, Some(&first_path), || {
                first_entered.send(()).unwrap();
                release.recv().unwrap();
                Ok(one_build())
            })
            .unwrap()
        });
        first_scan.recv().unwrap();
        let (second_ready, ready) = mpsc::channel();
        let (second_entered, second_scan) = mpsc::channel();
        let second = std::thread::spawn(move || {
            second_ready.send(()).unwrap();
            observe_with_scan(BoxRole::Dispatcher, Some(&state_path), || {
                second_entered.send(()).unwrap();
                Ok(Vec::new())
            })
            .unwrap()
        });
        ready.recv().unwrap();
        let scanned_before_unlock = second_scan.recv_timeout(Duration::from_millis(50)).is_ok();
        // Release and join before asserting, including on a regression.
        release_first.send(()).unwrap();
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert!(!scanned_before_unlock);
        assert_eq!(first.transition, Some(AlarmTransition::Started));
        assert_eq!(second.transition, Some(AlarmTransition::Recovered));
        assert!(first.state_error.is_none());
        assert!(second.state_error.is_none());
    }

    #[test]
    fn local_build_alarm_busy_lock_is_bounded_and_does_not_hide_builds() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("alarm");
        let _held = lock_alarm_state(&state_path).unwrap();
        let observation =
            observe_with_scan(BoxRole::Dispatcher, Some(&state_path), || Ok(one_build())).unwrap();
        assert!(
            observation
                .state_error
                .unwrap()
                .contains("holds the local build alarm lock")
        );
        assert_eq!(observation.builds.len(), 1);
        assert_eq!(observation.transition, None);
        assert!(std::fs::read(state_path).unwrap().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_build_scan_distinguishes_managed_ancestry_zombies_and_missing_proc() {
        let dir = tempfile::tempdir().unwrap();
        for (pid, comm, state, parent) in [
            (10_000_001, "cargo", "S", 1),
            (10_000_002, "rch", "S", 1),
            (10_000_003, "rustc", "S", 10_000_002),
            (10_000_004, "rchd", "S", 1),
            (10_000_005, "rustc", "S", 10_000_004),
            (10_000_006, "cargo", "Z", 1),
        ] {
            let path = dir.path().join(pid.to_string());
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("comm"), comm).unwrap();
            std::fs::write(
                path.join("stat"),
                format!("{pid} ({comm}) {state} {parent} 0 0\n"),
            )
            .unwrap();
        }
        let found = scan_local_builds_in(dir.path()).unwrap();
        assert_eq!(
            found.iter().map(|build| build.pid).collect::<Vec<_>>(),
            [10_000_001, 10_000_005]
        );
        assert!(scan_local_builds_in(&dir.path().join("missing")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_build_scan_unreadable_comm_does_not_report_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        // EISDIR is deterministic even when tests run with elevated privileges.
        std::fs::create_dir_all(proc_root.join("10000001/comm")).unwrap();
        let state_path = dir.path().join("alarm");
        std::fs::write(&state_path, b"1").unwrap();
        let observation = observe_with_scan(BoxRole::Dispatcher, Some(&state_path), || {
            scan_local_builds_in(&proc_root)
        })
        .unwrap();
        assert!(observation.scan_error.is_some());
        assert_eq!(observation.transition, None);
        assert_eq!(std::fs::read(state_path).unwrap(), b"1");
    }

    #[test]
    fn compiler_comms_match_and_non_compilers_do_not() {
        assert!(is_compiler_comm("cargo"));
        assert!(is_compiler_comm("cargo-rch-real"));
        assert!(is_compiler_comm("rustc"));
        assert!(is_compiler_comm("rustc-lld"));
        assert!(is_compiler_comm("rustc-1.99"));
        assert!(!is_compiler_comm("rustup"));
        assert!(!is_compiler_comm("cargo-rch-fake"));
        assert!(!is_compiler_comm("cargo-rch-realx"));
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

        for value in ["0", "", "10", "true"] {
            std::fs::write(&path, format!("RCH_CARGO_WRAPPER_BYPASS={value}\0")).unwrap();
            assert!(
                !environ_has_bypass(&path),
                "disabled bypass value {value:?}"
            );
        }
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

    #[cfg(target_os = "linux")]
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
        // Spawn the REAL cargo binary and hold it ALIVE across the scan.
        // `--version` exits in tens of millis, so polling for it raced a
        // process that was usually already gone — that lost ~2 of every 3
        // runs on a loaded worker. `login` instead blocks reading a token
        // from an open, never-written stdin pipe, so the process is
        // deterministically observable. CARGO_HOME points at a throwaway
        // dir, so no token could reach the real one. NOTE: copies of
        // binaries are not usable here — this box refuses to exec
        // untrusted copies (exit 1 before main) — so we use the genuine
        // toolchain cargo.
        let real_cargo = std::env::var("CARGO")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("cargo"));
        let cargo_home = std::env::temp_dir().join(format!("rch-livescan-{}", std::process::id()));
        std::fs::create_dir_all(&cargo_home).expect("throwaway CARGO_HOME");

        let spawn = |managed: bool| {
            let mut cmd = std::process::Command::new(&real_cargo);
            cmd.arg("login")
                .env("CARGO_HOME", &cargo_home)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
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

        // Wait for the child to be visible in /proc as a cargo process, so
        // the assertions exercise the detector rather than process startup.
        let await_observable = |pid: i32| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                if read_comm(&Path::new("/proc").join(pid.to_string()))
                    .ok()
                    .flatten()
                    .is_some_and(|comm| is_compiler_comm(&comm))
                {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            false
        };

        // Unmanaged → must be caught. Reap before asserting so a failure
        // cannot leak the blocked child.
        let mut child = spawn(false);
        let pid = child.id() as i32;
        let observable = await_observable(pid);
        let found = scan_local_builds();
        let seen = observable
            && found
                .as_ref()
                .is_ok_and(|builds| builds.iter().any(|b| b.pid == pid));
        let _ = child.kill();
        let _ = child.wait();
        assert!(observable, "real cargo never became observable in /proc");
        assert!(seen, "unmanaged real cargo must be detected while alive");

        // Managed via bypass env → excluded, though it is equally alive.
        let mut managed = spawn(true);
        let managed_pid = managed.id() as i32;
        let managed_observable = await_observable(managed_pid);
        let found = scan_local_builds();
        let excluded = found
            .as_ref()
            .is_ok_and(|builds| !builds.iter().any(|b| b.pid == managed_pid));
        let _ = managed.kill();
        let _ = managed.wait();
        assert!(
            managed_observable,
            "managed cargo never became observable in /proc"
        );
        assert!(
            excluded,
            "bypass-env process must NOT be flagged: {found:?}"
        );

        let _ = std::fs::remove_dir_all(&cargo_home);
    }
}
