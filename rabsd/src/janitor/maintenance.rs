//! Recurring, single-owner CAS maintenance outside the control reactor.
//!
//! One joined OS thread owns all sweeps and usage scans. Ticks never overlap,
//! queue catch-up work, or start nested runtimes. Region cancellation drops the
//! owner, wakes its delay and joins any admitted filesystem operation before
//! releasing the CAS mount. Kernel filesystem calls are not claimed cancellable.

use super::reclaim::Reclaimer;
use super::store::LiveCas;
use rabs_asupersync::daemon_runtime::SubsystemWork;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

const MAX_USAGE_ENTRIES: usize = 1_000_000;

#[cfg(target_os = "linux")]
static EVENT_OUTPUT: Mutex<()> = Mutex::new(());

/// Maintenance observations do not own the caller's output consumer. Keep the
/// existing stdout NDJSON contract without letting pipe/socket backpressure
/// strand the control reactor or a joined janitor that still owns the CAS.
/// Never wait on the process-wide stdio lock or queue behind another notice.
pub(super) fn report_event(line: &str, stopped: &AtomicBool) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(_writer) = EVENT_OUTPUT.try_lock() else {
            return false;
        };
        let Ok(mut output) = crate::controlled_output::ControlledOutput::new(
            &std::io::stdout(),
            stopped,
            std::time::Instant::now() + Duration::from_millis(100),
        ) else {
            return false;
        };
        output.write_all(format!("{line}\n").as_bytes()).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        !stopped.load(Ordering::Acquire) && writeln!(std::io::stdout().lock(), "{line}").is_ok()
    }
}

#[derive(Debug, Clone, Copy)]
struct Config {
    reclaim: bool,
    interval: Duration,
    grace: Duration,
    limit: usize,
}

impl Config {
    fn from_environment() -> Result<Self, String> {
        let read = |key: &str| match std::env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(format!("{key} is not UTF-8")),
        };
        Self::from_values(
            read("RABS_GC_RECLAIM")?.as_deref(),
            read("RABS_GC_INTERVAL_SECS")?.as_deref(),
            read("RABS_GC_GRACE_SECS")?.as_deref(),
            read("RABS_GC_MAX_LOCATIONS")?.as_deref(),
        )
    }

    fn from_values(
        reclaim: Option<&str>,
        interval: Option<&str>,
        grace: Option<&str>,
        limit: Option<&str>,
    ) -> Result<Self, String> {
        let reclaim = match reclaim.map(str::trim) {
            None | Some("0" | "false" | "off") => false,
            Some("1" | "true" | "on") => true,
            _ => return Err("RABS_GC_RECLAIM requires 0/1, false/true, or off/on".into()),
        };
        Ok(Self {
            reclaim,
            interval: Duration::from_secs(number(interval, 60, 86_400, "RABS_GC_INTERVAL_SECS")?),
            grace: Duration::from_secs(number(grace, 300, 86_400, "RABS_GC_GRACE_SECS")?),
            limit: number(limit, 64, 1024, "RABS_GC_MAX_LOCATIONS")? as usize,
        })
    }
}

fn number(value: Option<&str>, default: u64, maximum: u64, key: &str) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let value = value.trim();
    let parsed = (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u64>().ok())
        .flatten()
        .filter(|value| (1..=maximum).contains(value));
    parsed.ok_or_else(|| format!("{key} must be an integer in 1..={maximum}"))
}

struct Worker {
    cancelled: Arc<AtomicBool>,
    wake: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    fn start(cas: Arc<LiveCas>, quota: Option<u64>, config: Config) -> Result<Self, String> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancelled);
        let (wake, receiver) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("rabs-cas-janitor".into())
            .spawn(move || {
                let mut collector = Reclaimer::default();
                let mut first = true;
                while !stop.load(Ordering::Acquire) {
                    if config.reclaim {
                        match collector.sweep(&cas, config.grace, config.limit) {
                            Ok(report) => {
                                report_event(
                                    &serde_json::json!({
                                        "v":1, "kind":"janitor-physical-gc", "state":report.state,
                                        "observed":report.observed,
                                        "unlinked_files":report.unlinked_files,
                                        "unlinked_bytes":report.unlinked_bytes,
                                        "recovered_locations":report.recovered_locations,
                                        "retained":report.retained,
                                    })
                                    .to_string(),
                                    &stop,
                                );
                            }
                            Err(reason) => {
                                event_error("janitor-physical-gc-failed", &reason, &stop);
                            }
                        }
                    } else if first {
                        // Preserve the existing non-deleting startup audit when
                        // physical reclamation has not been explicitly enabled.
                        match cas.gc_sweep(rabs_cas::gc::GcMode::Normal) {
                            Ok(report) => {
                                report_event(
                                    &format!(
                                        "{{\"v\":1,\"kind\":\"janitor-gc-sweep\",\"planned\":{},\"reclaimed\":{},\"skipped\":{}}}",
                                        report.planned, report.reclaimed, report.skipped,
                                    ),
                                    &stop,
                                );
                            }
                            Err(reason) => {
                                event_error("janitor-gc-sweep-failed", &reason, &stop);
                            }
                        }
                    }
                    first = false;
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    match measure_usage(cas.cas_root(), &stop) {
                        Ok(bytes) => {
                            if let Some(quota) = quota
                                && bytes > quota
                            {
                                report_event(
                                    &format!(
                                        "{{\"v\":1,\"kind\":\"janitor-quota-exceeded\",\"bytes\":{bytes},\"quota_bytes\":{quota}}}"
                                    ),
                                    &stop,
                                );
                            }
                            // Keep this event's numeric bytes field last for the
                            // existing CLI consumer; failures emit no bogus zero.
                            report_event(
                                &format!(
                                    "{{\"v\":1,\"kind\":\"janitor-store-usage\",\"bytes\":{bytes}}}"
                                ),
                                &stop,
                            );
                        }
                        Err(reason) if !stop.load(Ordering::Acquire) => {
                            event_error("janitor-store-usage-unavailable", &reason, &stop);
                        }
                        Err(_) => break,
                    }
                    // Delay AFTER a completed pass, not a catch-up interval. A slow
                    // scan cannot queue a second scan or buy another deletion budget.
                    match receiver.recv_timeout(config.interval) {
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .map_err(|error| format!("start CAS maintenance: {error}"))?;
        Ok(Self {
            cancelled,
            wake,
            thread: Some(thread),
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.wake.send(());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            event_error(
                "janitor-maintenance-panicked",
                "joined worker panicked; no worker remains",
                &self.cancelled,
            );
        }
    }
}

fn event_error(kind: &str, reason: &str, stopped: &AtomicBool) {
    let line = serde_json::json!({"v":1,"kind":kind,"reason":reason}).to_string();
    if !report_event(&line, stopped) {
        // Preserve operational failures on the independent diagnostic stream
        // when stdout is unavailable. That writer has its own bounded budget.
        crate::edge::server::report_log_line(&line);
    }
}

/// Count regular-file bytes once per inode, plus link bytes WITHOUT following
/// symlinks. This is an observational usage sample, not a coherent filesystem
/// snapshot or free-block measurement. Any incomplete traversal is an error.
fn measure_usage(root: &Path, cancelled: &AtomicBool) -> Result<u64, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = HashSet::new();
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        if cancelled.load(Ordering::Acquire) {
            return Err("usage scan cancelled".into());
        }
        let metadata = fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_dir() {
            return Err("usage directory changed type".into());
        }
        for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
            if cancelled.load(Ordering::Acquire) {
                return Err("usage scan cancelled".into());
            }
            entries = entries.checked_add(1).ok_or("usage entry count overflow")?;
            if entries > MAX_USAGE_ENTRIES {
                return Err("usage inventory limit exceeded".into());
            }
            let path = entry.map_err(|e| e.to_string())?.path();
            let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if metadata.file_type().is_dir() {
                pending.push(path);
            } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                if files.insert((metadata.dev(), metadata.ino())) {
                    bytes = bytes
                        .checked_add(metadata.len())
                        .ok_or("usage byte count overflow")?;
                }
            } else {
                return Err("unsupported node in usage inventory".into());
            }
        }
    }
    Ok(bytes)
}

pub(super) fn work(mounted: Result<Arc<LiveCas>, String>, quota: Option<u64>) -> SubsystemWork {
    Box::new(move |cx, mut shutdown| {
        Box::pin(async move {
            let cas = mounted?;
            let stopped = AtomicBool::new(false);
            let config = Config::from_environment().inspect_err(|reason| {
                event_error("janitor-gc-config-refused", reason, &stopped);
            })?;
            report_event(
                &serde_json::json!({
                    "v":1, "kind":"janitor-cas-mounted", "root":cas.cas_root().display().to_string(),
                    "serving_refused":cas.serving_refused, "repaired":cas.repaired, "reported":cas.reported,
                })
                .to_string(),
                &stopped,
            );
            report_event(
                &serde_json::json!({
                    "v":1,"kind":"janitor-maintenance-config", "physical_reclaim":config.reclaim,
                    "interval_seconds":config.interval.as_secs(), "grace_seconds":config.grace.as_secs(),
                    "max_locations":config.limit, "quota_advisory":true,
                })
                .to_string(),
                &stopped,
            );
            let owner = Worker::start(cas, quota, config)?;
            cx.trace("janitor region up: recurring joined maintenance outside control reactor");
            shutdown.wait().await;
            drop(owner);
            Ok(())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::janitor::store::mount_and_reconcile;
    use crate::test_util::private_tempdir;
    use std::os::unix::fs::symlink;

    /// The child enters the test body before stdout becomes unavailable, so
    /// test-harness announcements cannot mask a blocked production writer.
    /// Completion is a separate file, and the exact child is killed/reaped if
    /// a regression prevents region shutdown. No test mocks the sink or CAS.
    #[cfg(target_os = "linux")]
    fn with_unavailable_stdout(test_name: &str, close_reader: bool, case: impl FnOnce()) {
        use rustix::fs::{Mode, OFlags, fcntl_getfl, open};
        use std::fs::File;
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::process::{Child, Command, Stdio};
        use std::time::Instant;

        const CHILD_TEST: &str = "RABS_JANITOR_STDOUT_TEST";
        const CHILD_ROOT: &str = "RABS_JANITOR_STDOUT_TEST_ROOT";
        let test_name = test_name.strip_prefix("rabsd::").unwrap_or(test_name);
        if std::env::var(CHILD_TEST).as_deref() == Ok(test_name) {
            let root = std::path::PathBuf::from(std::env::var_os(CHILD_ROOT).unwrap());
            fs::write(root.join("ready"), b"test body ready").unwrap();
            std::io::stdin().read_exact(&mut [0_u8]).unwrap();
            case();
            fs::write(root.join("completed"), b"region drained and mount released").unwrap();
            // All case-owned resources have dropped. Avoid asking the test
            // harness to print its verdict to the deliberately unusable pipe.
            std::process::exit(0);
        }

        struct ChildOwner(Child);
        impl Drop for ChildOwner {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }

        let root = private_tempdir();
        let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let mut reader = Some(reader);
        let flags = fcntl_getfl(&writer).unwrap();
        assert!(!flags.contains(OFlags::NONBLOCK));
        let log = root.path().join("stderr.log");
        let mut child = ChildOwner(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--nocapture"])
                .env(CHILD_TEST, test_name)
                .env(CHILD_ROOT, root.path())
                .env("RABS_GC_RECLAIM", "0")
                .env("RABS_GC_INTERVAL_SECS", "60")
                .env("RABS_GC_GRACE_SECS", "1")
                .env("RABS_GC_MAX_LOCATIONS", "1")
                .stdin(Stdio::piped())
                .stdout(File::from(writer.try_clone().unwrap()))
                .stderr(File::create(&log).unwrap())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.path().join("ready").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
                "janitor child did not enter {test_name}: {}",
                fs::read_to_string(&log).unwrap(),
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        if close_reader {
            drop(reader.take());
        } else {
            // A distinct nonblocking description fills the real pipe without
            // changing the blocking flags inherited by the daemon region.
            let filler = open(
                format!("/proc/self/fd/{}", writer.as_raw_fd()),
                OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            loop {
                match rustix::io::write(&filler, &[0x5a; 4096]) {
                    Ok(count) => assert!(count > 0),
                    Err(rustix::io::Errno::AGAIN) => break,
                    result => panic!("unexpected stdout pipe fill: {result:?}"),
                }
            }
            assert_eq!(
                rustix::io::write(&filler, b"x"),
                Err(rustix::io::Errno::AGAIN)
            );
        }
        child.0.stdin.take().unwrap().write_all(b"x").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "{test_name} retained its CAS behind unavailable stdout: {}",
                fs::read_to_string(&log).unwrap(),
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let diagnostics = fs::read_to_string(&log).unwrap();
        assert!(status.success(), "{test_name} failed: {diagnostics}");
        assert!(root.path().join("completed").is_file(), "{diagnostics}");
        assert!(!diagnostics.contains("panicked"), "{diagnostics}");
        assert!(
            diagnostics.contains("janitor-test-failure"),
            "{diagnostics}"
        );
        assert_eq!(fcntl_getfl(&writer).unwrap(), flags);
    }

    #[cfg(target_os = "linux")]
    fn run_janitor_behind_unavailable_stdout() {
        use rabs_asupersync::daemon_runtime::{DaemonRunOptions, run_daemon};
        use rabs_cas::metadata_store::RabsMetadataStore;

        // Exercise both production mount owners. Only recurring maintenance
        // executes a sweep; neither may block shutdown while reporting startup.
        for recurring in [true, false] {
            let root = private_tempdir();
            let cas = Arc::new(mount_and_reconcile(root.path()).unwrap());
            let weak = Arc::downgrade(&cas);
            let janitor = if recurring {
                work(Ok(cas), Some(1))
            } else {
                crate::janitor::store::janitor_work_holding(Ok(cas))
            };
            let receipt = run_daemon(DaemonRunOptions {
                run_for: Some(Duration::from_secs(1)),
                janitor_work: Some(janitor),
                ..DaemonRunOptions::default()
            })
            .unwrap();
            assert!(receipt.clean(), "{}", receipt.to_json_line());
            assert!(
                weak.upgrade().is_none(),
                "joined janitor retained the mount"
            );
            let reopened = mount_and_reconcile(root.path()).unwrap();
            let rows = reopened
                .store()
                .lock()
                .unwrap()
                .query("SELECT seq FROM gc_receipts", &[])
                .unwrap();
            assert_eq!(
                rows.len(),
                usize::from(recurring),
                "the actual janitor sweep did not execute"
            );
        }
        // Operational errors retain an independent, bounded stderr fallback.
        event_error(
            "janitor-test-failure",
            "retained failure",
            &AtomicBool::new(false),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_stdout_cannot_block_region_startup_or_retain_the_cas_mount() {
        with_unavailable_stdout(
            concat!(
                module_path!(),
                "::stalled_stdout_cannot_block_region_startup_or_retain_the_cas_mount"
            ),
            false,
            run_janitor_behind_unavailable_stdout,
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn broken_stdout_cannot_panic_maintenance_or_lose_failure_diagnostics() {
        with_unavailable_stdout(
            concat!(
                module_path!(),
                "::broken_stdout_cannot_panic_maintenance_or_lose_failure_diagnostics"
            ),
            true,
            run_janitor_behind_unavailable_stdout,
        );
    }

    #[test]
    fn config_is_opt_in_bounded_and_never_silently_repairs_invalid_values() {
        let default = Config::from_values(None, None, None, None).unwrap();
        assert!(!default.reclaim);
        assert_eq!(default.interval, Duration::from_secs(60));
        assert_eq!(default.grace, Duration::from_secs(300));
        assert_eq!(default.limit, 64);
        for value in ["1", "true", "on"] {
            assert!(
                Config::from_values(Some(value), Some("1"), Some("1"), Some("1024"))
                    .unwrap()
                    .reclaim
            );
        }
        for value in ["", "yes", "garbage"] {
            assert!(Config::from_values(Some(value), None, None, None).is_err());
        }
        for value in ["0", "-1", "+1", "1.5", "18446744073709551616", "86401"] {
            assert!(Config::from_values(None, Some(value), None, None).is_err());
            assert!(Config::from_values(None, None, Some(value), None).is_err());
        }
        assert!(Config::from_values(None, None, None, Some("1025")).is_err());
    }

    #[test]
    fn usage_never_follows_directory_links_or_double_counts_hardlinks() {
        let root = private_tempdir();
        let outside = private_tempdir();
        fs::write(root.path().join("file"), b"abc").unwrap();
        fs::hard_link(root.path().join("file"), root.path().join("hardlink")).unwrap();
        fs::write(outside.path().join("large"), vec![0_u8; 1024 * 1024]).unwrap();
        symlink(outside.path(), root.path().join("outside")).unwrap();
        symlink(root.path(), root.path().join("cycle")).unwrap();
        let links = fs::symlink_metadata(root.path().join("outside"))
            .unwrap()
            .len()
            + fs::symlink_metadata(root.path().join("cycle"))
                .unwrap()
                .len();
        assert_eq!(
            measure_usage(root.path(), &AtomicBool::new(false)).unwrap(),
            3 + links
        );
    }

    #[test]
    fn unavailable_cancelled_or_linked_root_never_becomes_zero_usage() {
        let root = private_tempdir();
        assert!(measure_usage(&root.path().join("absent"), &AtomicBool::new(false)).is_err());
        assert!(measure_usage(root.path(), &AtomicBool::new(true)).is_err());
        symlink(root.path(), root.path().join("alias")).unwrap();
        assert!(measure_usage(&root.path().join("alias"), &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn maintenance_owner_keeps_mount_until_cancelled_thread_has_joined() {
        let root = private_tempdir();
        let cas = Arc::new(mount_and_reconcile(root.path()).unwrap());
        let weak = Arc::downgrade(&cas);
        let owner = Worker::start(
            Arc::clone(&cas),
            None,
            Config::from_values(None, None, None, None).unwrap(),
        )
        .unwrap();
        drop(cas);
        assert!(weak.upgrade().is_some());
        assert!(mount_and_reconcile(root.path()).is_err());
        drop(owner);
        assert!(weak.upgrade().is_none());
        assert!(mount_and_reconcile(root.path()).is_ok());
    }
}
