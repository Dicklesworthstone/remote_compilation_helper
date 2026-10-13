//! Bounded local-execution speed gate (bd-2spi4).
//!
//! `compilation.remote_speedup_threshold` and `compilation.min_local_time_ms`
//! were parsed, merged and displayed but never consulted (the gate that read
//! them was removed in ef0f90b7). That cost real time on a dispatcher faster
//! than its workers: on mac-studio (M5 Ultra) a cold `cargo check -p
//! rch-common --lib` took 12.4 s locally and 143.1 s on hz4.
//!
//! The decision uses this machine's own measured build history (the
//! `timing_history` store), not SpeedScore. Every host scores cpu ≈ 70, and
//! compilation and disk sit at their caps, so the benchmark cannot rank a
//! dispatcher against its workers (mac-studio scored 75.3 against workers'
//! 67–77.5).
//!
//! Opt-in: `compilation.local_slots > 0`. With the default 0, nothing changes.
//! When enabled, the gate:
//! - learns each side once per project and command kind (local first, then
//!   remote), and re-measures a side whose newest sample is older than a week;
//! - runs locally when the local median is below `min_local_time_ms`, or when
//!   remote is less than `remote_speedup_threshold` times faster;
//! - bounds local runs to `local_slots` concurrent builds through crash-safe
//!   lock files, and to machines with at least
//!   [`LOCAL_MIN_FREE_MEMORY_PCT`] free memory. macOS additionally needs known
//!   compressor-segment headroom and bounded CPU-normalized load. Unknown or
//!   invalid pressure metrics never admit a local build.
use super::timing_history::{ProjectTimingData, TimingRecord, timing_cache};
use rch_common::CompilationKind;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Path, PathBuf};

/// A side whose newest sample is older than this is measured again, so a
/// decision cannot outlive the fleet or project it was measured on.
pub(super) const RESAMPLE_AFTER_SECS: u64 = 7 * 24 * 3600;

/// Free memory alone is not a compressor-segment exhaustion guard (issue #103).
pub(super) const LOCAL_MIN_FREE_MEMORY_PCT: u8 = 25;

/// Keep at least half the compressor's segment capacity in reserve. This is
/// an admission policy, not a prediction of the kernel's panic threshold.
const LOCAL_MAX_COMPRESSOR_SEGMENT_PCT: u8 = 50;
/// Refuse at or above two runnable tasks per logical CPU, on either the one-
/// or five-minute window. A quiet short window cannot hide sustained pressure.
const LOCAL_MAX_LOAD_PER_CPU: f64 = 2.0;

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub(crate) struct MacOsPressure {
    pub compressor_segments: u64,
    pub compressor_segment_limit: u64,
    pub load_average: [f64; 3],
    pub logical_cpus: u32,
}

/// Parse the four outputs of the fixed, ordered sysctl query below. Do not
/// substitute compressed-page utilization for segment utilization: they can
/// diverge dramatically. Reject partial, extra, malformed and non-finite data.
#[cfg(any(target_os = "macos", test))]
fn parse_macos_pressure(output: &str) -> Option<MacOsPressure> {
    let mut lines = output.lines();
    let compressor_segments = lines.next()?.trim().parse().ok()?;
    let compressor_segment_limit = lines.next()?.trim().parse().ok()?;
    let load = lines.next()?.trim().strip_prefix('{')?.strip_suffix('}')?;
    let mut values = load.split_whitespace();
    let load_average = [
        values.next()?.parse::<f64>().ok()?,
        values.next()?.parse::<f64>().ok()?,
        values.next()?.parse::<f64>().ok()?,
    ];
    let logical_cpus = lines.next()?.trim().parse().ok()?;
    if values.next().is_some()
        || lines.next().is_some()
        || compressor_segment_limit == 0
        || compressor_segments > compressor_segment_limit
        || logical_cpus == 0
        || load_average
            .iter()
            .any(|load| !load.is_finite() || *load < 0.0)
    {
        return None;
    }
    Some(MacOsPressure {
        compressor_segments,
        compressor_segment_limit,
        load_average,
        logical_cpus,
    })
}

/// A sysctl reply is a handful of numbers, never an unbounded output stream.
#[cfg(all(unix, any(target_os = "macos", test)))]
const MAX_PROBE_OUTPUT_BYTES: usize = 4096;

/// Bound both process completion AND output collection. Waiting for exit and
/// then calling `wait_with_output` loses the deadline if another process still
/// holds stdout. A nonblocking socket also lets us reject oversized replies
/// without allowing the probe to block on a full pipe.
#[cfg(all(unix, any(target_os = "macos", test)))]
fn bounded_probe(
    command: &mut std::process::Command,
    deadline: std::time::Duration,
) -> Option<String> {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    if deadline.is_zero() {
        return None;
    }
    let started = std::time::Instant::now();
    let (reader, writer) = UnixStream::pair().ok()?;
    reader.set_nonblocking(true).ok()?;
    let spawned = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::null())
        .spawn();
    // Command retains caller-supplied descriptors after spawn. Close its copy
    // on success AND failure; otherwise even a healthy probe never reaches EOF.
    command.stdout(Stdio::null());
    let mut child = spawned.ok()?;
    let output = collect_probe_output(&mut child, reader, started, deadline);
    if output.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    output
}

#[cfg(all(unix, any(target_os = "macos", test)))]
fn collect_probe_output(
    child: &mut std::process::Child,
    mut reader: std::os::unix::net::UnixStream,
    started: std::time::Instant,
    deadline: std::time::Duration,
) -> Option<String> {
    use std::io::{ErrorKind, Read};

    let mut output = Vec::new();
    let mut buffer = [0; 512];
    let mut eof = false;
    loop {
        if started.elapsed() >= deadline {
            return None;
        }
        if !eof {
            match reader.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if count > MAX_PROBE_OUTPUT_BYTES - output.len() {
                        return None;
                    }
                    output.extend_from_slice(&buffer[..count]);
                    // Check the deadline between reads, including continuous
                    // output. Never return a valid-looking truncated prefix.
                    continue;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(_) => return None,
            }
        }
        match child.try_wait().ok()? {
            Some(status) if !status.success() => return None,
            Some(_) if eof => {
                if started.elapsed() >= deadline {
                    return None;
                }
                return String::from_utf8(output).ok();
            }
            _ => {
                std::thread::sleep(
                    std::time::Duration::from_millis(5)
                        .min(deadline.saturating_sub(started.elapsed())),
                );
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_sysctl(names: &[&str]) -> Option<String> {
    bounded_probe(
        std::process::Command::new("/usr/sbin/sysctl")
            .env("LC_ALL", "C")
            .arg("-n")
            .args(names),
        std::time::Duration::from_millis(250),
    )
}

fn macos_pressure() -> Option<MacOsPressure> {
    #[cfg(target_os = "macos")]
    {
        parse_macos_pressure(&macos_sysctl(&[
            "vm.compressor.segment.total",
            "vm.compressor.segment.limit",
            "vm.loadavg",
            "hw.logicalcpu",
        ])?)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

fn resources_allow_local(
    free_pct: Option<u8>,
    require_macos_pressure: bool,
    pressure: Option<&MacOsPressure>,
) -> bool {
    if !memory_allows_local(free_pct) {
        return false;
    }
    if !require_macos_pressure {
        return true;
    }
    let Some(pressure) = pressure else {
        return false;
    };
    // Compare without truncating percentages or overflowing u64 counters.
    pressure.compressor_segment_limit > 0
        && u128::from(pressure.compressor_segments) * 100
            < u128::from(pressure.compressor_segment_limit)
                * u128::from(LOCAL_MAX_COMPRESSOR_SEGMENT_PCT)
        && pressure.logical_cpus > 0
        && pressure
            .load_average
            .iter()
            .all(|load| load.is_finite() && *load >= 0.0)
        && pressure.load_average[..2]
            .iter()
            .all(|load| *load < f64::from(pressure.logical_cpus) * LOCAL_MAX_LOAD_PER_CPU)
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum SpeedGateDecision {
    /// Run locally. The reason is shown to the caller and recorded.
    Local(String),
    /// Offload as usual.
    Remote(String),
}

/// Which builds the gate may consider at all.
#[derive(Debug, Clone, Copy)]
pub(super) struct SpeedGateInputs {
    pub local_slots: u32,
    pub kind: Option<CompilationKind>,
    /// `rch exec --job`: an explicit request for the remote job rail.
    pub job: bool,
    /// A mode a local run cannot satisfy: clean overlay, source-content
    /// receipt, retained Cargo JSON stdout, an exact worker, required tools.
    pub strict_remote_mode: bool,
    /// Additional force-remote policy resolved by the caller. The gate also
    /// checks operator environment directly before considering local history.
    pub caller_force_remote: bool,
}

/// Snapshot placement variables without modifying the process environment.
#[derive(Debug, Default)]
struct PlacementEnvironment {
    require_remote: Option<OsString>,
    shim_pid: Option<OsString>,
    force_remote: Option<OsString>,
    worker: Option<OsString>,
}

impl PlacementEnvironment {
    fn read() -> Self {
        Self {
            require_remote: std::env::var_os("RCH_REQUIRE_REMOTE"),
            shim_pid: std::env::var_os("RCH_SPEED_GATE_SHIM_PID"),
            force_remote: std::env::var_os("RCH_FORCE_REMOTE"),
            worker: std::env::var_os("RCH_WORKER"),
        }
    }

    fn allows_local(&self, pid: u32) -> bool {
        // Only the canonical shim's *default injection* may be relaxed. It
        // clears stale markers and sets this PID immediately before exec, so
        // an inherited marker cannot authorize a later child invocation. An
        // explicit value is never overwritten or marked by either shim.
        let expected_pid = pid.to_string();
        let shim_default = self.require_remote.as_deref() == Some(OsStr::new("1"))
            && self.shim_pid.as_deref() == Some(OsStr::new(&expected_pid));
        !remote_flag_requested(self.force_remote.as_deref())
            && !self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_empty())
            && (!remote_flag_requested(self.require_remote.as_deref()) || shim_default)
    }
}

/// Only a recognized false value relaxes placement. Malformed/non-UTF-8
/// operator settings must not accidentally authorize a local measurement.
fn remote_flag_requested(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| {
        value.to_str().is_none_or(|value| {
            !matches!(
                value.to_ascii_lowercase().as_str(),
                "" | "0" | "false" | "no" | "off"
            )
        })
    })
}

/// Explicit remote-only requests always bypass the speed gate. Only a shim
/// default bound to this exact exec process permits deliberate local placement;
/// it still forbids local fallback after remote failure in the normal exec path.
pub(super) fn gate_applies(inputs: SpeedGateInputs) -> bool {
    gate_applies_with_environment(inputs, &PlacementEnvironment::read(), std::process::id())
}

fn gate_applies_with_environment(
    inputs: SpeedGateInputs,
    placement: &PlacementEnvironment,
    pid: u32,
) -> bool {
    inputs.local_slots > 0
        && !inputs.job
        && !inputs.strict_remote_mode
        && !inputs.caller_force_remote
        && placement.allows_local(pid)
        && matches!(inputs.kind, Some(kind) if kind != CompilationKind::Job)
}

fn newest(samples: &[TimingRecord]) -> Option<u64> {
    samples.iter().map(|record| record.timestamp).max()
}

fn stale(samples: &[TimingRecord], now_secs: u64) -> bool {
    newest(samples).is_none_or(|newest| now_secs.saturating_sub(newest) > RESAMPLE_AFTER_SECS)
}

/// Pure decision over measured history.
pub(super) fn decide(
    data: Option<&ProjectTimingData>,
    threshold: f64,
    min_local_ms: u64,
    now_secs: u64,
) -> SpeedGateDecision {
    // TOML can represent NaN/infinity. The diagnostic validator rejects them,
    // but ordinary loading must not turn an invalid threshold into permission
    // for a local measurement (comparisons against NaN are always false).
    if !threshold.is_finite() || threshold <= 0.0 {
        return SpeedGateDecision::Remote(
            "speed gate: invalid remote_speedup_threshold; offloading".into(),
        );
    }
    let Some(data) = data else {
        return SpeedGateDecision::Local("speed gate: measuring this build locally".into());
    };
    let Some(local_ms) = data.median_duration(false) else {
        return SpeedGateDecision::Local("speed gate: measuring this build locally".into());
    };
    if local_ms < min_local_ms {
        return SpeedGateDecision::Local(format!(
            "speed gate: local median {local_ms} ms < min_local_time_ms {min_local_ms}"
        ));
    }
    let Some(remote_ms) = data.median_duration(true) else {
        return SpeedGateDecision::Remote("speed gate: measuring this build remotely".into());
    };
    // > 1.0 means remote is faster.
    let speedup = local_ms as f64 / remote_ms.max(1) as f64;
    if speedup >= threshold {
        if stale(&data.local_samples, now_secs) {
            return SpeedGateDecision::Local(
                "speed gate: re-measuring locally (local timing is over a week old)".into(),
            );
        }
        SpeedGateDecision::Remote(format!(
            "speed gate: remote {speedup:.2}x faster (local {local_ms} ms, remote {remote_ms} ms, threshold {threshold})"
        ))
    } else {
        if stale(&data.remote_samples, now_secs) {
            return SpeedGateDecision::Remote(
                "speed gate: re-measuring remotely (remote timing is over a week old)".into(),
            );
        }
        SpeedGateDecision::Local(format!(
            "speed gate: remote only {speedup:.2}x faster (local {local_ms} ms, remote {remote_ms} ms, threshold {threshold})"
        ))
    }
}

/// Free memory as a percentage of physical memory, or `None` if unknown.
fn memory_free_pct() -> Option<u8> {
    #[cfg(target_os = "macos")]
    {
        macos_sysctl(&["kern.memorystatus_level"])?
            .trim()
            .parse()
            .ok()
    }
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        meminfo_free_pct(&meminfo)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// `MemAvailable` as a percentage of `MemTotal`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn meminfo_free_pct(meminfo: &str) -> Option<u8> {
    let field = |name: &str| {
        let mut matches = meminfo
            .lines()
            .filter_map(|line| line.strip_prefix(name)?.strip_prefix(':'));
        let mut fields = matches.next()?.split_whitespace();
        let value = fields.next()?.parse::<u64>().ok()?;
        if fields.next() != Some("kB") || fields.next().is_some() || matches.next().is_some() {
            return None;
        }
        Some(value)
    };
    let total = field("MemTotal").filter(|total| *total > 0)?;
    // An inconsistent snapshot is unknown, not 100% available memory.
    let available = field("MemAvailable").filter(|available| *available <= total)?;
    u8::try_from((u128::from(available) * 100) / u128::from(total)).ok()
}

/// Unknown memory counts as short: the gate only adds load when it can see room.
fn memory_allows_local(free_pct: Option<u8>) -> bool {
    free_pct.is_some_and(|pct| (LOCAL_MIN_FREE_MEMORY_PCT..=100).contains(&pct))
}

fn local_slot_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("rch").join("local-slots"))
}

/// Take one of `slots` exclusive lock files without waiting. The kernel
/// releases the lock when this process exits, so a killed build never leaks
/// its slot. Rust opens files close-on-exec, so the compiler child does not
/// inherit it.
pub(super) fn try_acquire_local_slot(dir: &Path, slots: u32) -> Option<File> {
    std::fs::create_dir_all(dir).ok()?;
    (0..slots).find_map(|index| {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join(format!("slot-{index}.lock")))
            .ok()?;
        file.try_lock().ok().map(|()| file)
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Measured history for `project` and `kind` (the same key timing records use).
fn history_for(project: &str, kind: Option<CompilationKind>) -> Option<ProjectTimingData> {
    let history = timing_cache().read().ok()?;
    history.get(project, kind).cloned()
}

/// Decide whether this build runs locally. `Some` carries the reason to report
/// and the held local slot, which must stay alive until the build finishes.
pub(super) fn evaluate(
    config: &rch_common::RchConfig,
    project: &str,
    inputs: SpeedGateInputs,
) -> Option<(String, File)> {
    if !gate_applies(inputs) {
        return None;
    }
    let data = history_for(project, inputs.kind);
    let reason = match decide(
        data.as_ref(),
        config.compilation.remote_speedup_threshold,
        config.compilation.min_local_time_ms,
        now_secs(),
    ) {
        SpeedGateDecision::Remote(reason) => {
            tracing::debug!(target: "rch::hook::speed_gate", %reason, "offloading");
            return None;
        }
        SpeedGateDecision::Local(reason) => reason,
    };
    let Some(slot) =
        local_slot_dir().and_then(|dir| try_acquire_local_slot(&dir, inputs.local_slots))
    else {
        tracing::info!(
            target: "rch::hook::speed_gate",
            local_slots = inputs.local_slots,
            "speed gate prefers local, but every local slot is busy; offloading"
        );
        return None;
    };
    // Sample after acquiring the slot, as close to local admission as possible.
    // A refused admission drops the slot; it cannot consume local capacity.
    let free_pct = memory_free_pct();
    let pressure = macos_pressure();
    if !resources_allow_local(free_pct, cfg!(target_os = "macos"), pressure.as_ref()) {
        tracing::info!(
            target: "rch::hook::speed_gate",
            free_pct = ?free_pct,
            macos_pressure = ?pressure,
            min_free_memory_pct = LOCAL_MIN_FREE_MEMORY_PCT,
            max_compressor_segment_pct = LOCAL_MAX_COMPRESSOR_SEGMENT_PCT,
            max_load_per_cpu = LOCAL_MAX_LOAD_PER_CPU,
            "speed gate prefers local, but resource pressure is unsafe or unknown; offloading"
        );
        return None;
    }
    Some((reason, slot))
}

/// What `rch diagnose` reports about the gate for this project and kind.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub(crate) struct SpeedGateDiagnosis {
    pub enabled: bool,
    pub local_slots: u32,
    pub remote_speedup_threshold: f64,
    pub min_local_time_ms: u64,
    pub local_samples: usize,
    pub remote_samples: usize,
    pub local_median_ms: Option<u64>,
    pub remote_median_ms: Option<u64>,
    /// `local` or `remote`, before the placement, slot and resource checks.
    pub decision: Option<String>,
    pub reason: Option<String>,
    pub free_memory_pct: Option<u8>,
    pub min_free_memory_pct: u8,
    pub macos_pressure: Option<MacOsPressure>,
    pub max_compressor_segment_pct: u8,
    pub max_load_per_cpu: f64,
    /// Resource admission only; this does not grant a slot or override placement.
    pub resources_allow_local: bool,
}

pub(crate) fn diagnose(
    config: &rch_common::RchConfig,
    project: &str,
    kind: Option<CompilationKind>,
) -> SpeedGateDiagnosis {
    let enabled = config.compilation.local_slots > 0;
    let data = history_for(project, kind);
    let decision = enabled.then(|| {
        decide(
            data.as_ref(),
            config.compilation.remote_speedup_threshold,
            config.compilation.min_local_time_ms,
            now_secs(),
        )
    });
    let (decision, reason) = match decision {
        Some(SpeedGateDecision::Local(reason)) => (Some("local".to_string()), Some(reason)),
        Some(SpeedGateDecision::Remote(reason)) => (Some("remote".to_string()), Some(reason)),
        None => (None, None),
    };
    let free_memory_pct = enabled.then(memory_free_pct).flatten();
    let pressure = enabled.then(macos_pressure).flatten();
    let resources_allow_local = enabled
        && resources_allow_local(
            free_memory_pct,
            cfg!(target_os = "macos"),
            pressure.as_ref(),
        );
    SpeedGateDiagnosis {
        enabled,
        local_slots: config.compilation.local_slots,
        remote_speedup_threshold: config.compilation.remote_speedup_threshold,
        min_local_time_ms: config.compilation.min_local_time_ms,
        local_samples: data.as_ref().map_or(0, |data| data.local_samples.len()),
        remote_samples: data.as_ref().map_or(0, |data| data.remote_samples.len()),
        local_median_ms: data.as_ref().and_then(|data| data.median_duration(false)),
        remote_median_ms: data.as_ref().and_then(|data| data.median_duration(true)),
        decision,
        reason,
        free_memory_pct,
        min_free_memory_pct: LOCAL_MIN_FREE_MEMORY_PCT,
        macos_pressure: pressure,
        max_compressor_segment_pct: LOCAL_MAX_COMPRESSOR_SEGMENT_PCT,
        max_load_per_cpu: LOCAL_MAX_LOAD_PER_CPU,
        resources_allow_local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn data(local: &[u64], remote: &[u64], age_secs: u64) -> ProjectTimingData {
        let record = |duration_ms: u64, remote: bool| TimingRecord {
            timestamp: NOW - age_secs,
            duration_ms,
            remote,
        };
        ProjectTimingData {
            local_samples: local.iter().map(|ms| record(*ms, false)).collect(),
            remote_samples: remote.iter().map(|ms| record(*ms, true)).collect(),
        }
    }

    fn inputs() -> SpeedGateInputs {
        SpeedGateInputs {
            local_slots: 2,
            kind: Some(CompilationKind::CargoCheck),
            job: false,
            strict_remote_mode: false,
            caller_force_remote: false,
        }
    }

    fn is_local(decision: &SpeedGateDecision) -> bool {
        matches!(decision, SpeedGateDecision::Local(_))
    }

    #[test]
    fn fast_local_history_runs_locally_and_fast_remote_history_offloads() {
        // mac-studio shape: 12.4 s local, 143 s remote.
        let fast_local = data(&[12_400], &[143_100], 60);
        assert!(is_local(&decide(Some(&fast_local), 1.2, 2000, NOW)));
        // A slow dispatcher: 100 s local, 20 s remote (5x).
        let fast_remote = data(&[100_000], &[20_000], 60);
        assert!(!is_local(&decide(Some(&fast_remote), 1.2, 2000, NOW)));
        // The threshold is a strict bar for offloading: 1.1x < 1.2 runs locally.
        let marginal = data(&[11_000], &[10_000], 60);
        assert!(is_local(&decide(Some(&marginal), 1.2, 2000, NOW)));
        assert!(!is_local(&decide(Some(&marginal), 1.0, 2000, NOW)));
    }

    #[test]
    fn invalid_speedup_threshold_never_authorizes_a_local_measurement() {
        let fast_local = data(&[100], &[100_000], 0);
        let fast_remote = data(&[100_000], &[100], 0);
        let empty = data(&[], &[], 0);
        for threshold in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0, -1.0] {
            for history in [None, Some(&empty), Some(&fast_local), Some(&fast_remote)] {
                assert!(matches!(
                    decide(history, threshold, 2000, NOW),
                    SpeedGateDecision::Remote(reason)
                        if reason.contains("invalid remote_speedup_threshold")
                ));
            }
        }
    }

    #[test]
    fn short_local_builds_stay_local_even_when_remote_is_faster() {
        let tiny = data(&[1_500], &[300], 60);
        assert!(is_local(&decide(Some(&tiny), 1.2, 2000, NOW)));
        assert!(!is_local(&decide(Some(&tiny), 1.2, 1000, NOW)));
    }

    #[test]
    fn missing_or_stale_history_is_measured_once_on_each_side() {
        assert!(is_local(&decide(None, 1.2, 2000, NOW)));
        let local_only = data(&[30_000], &[], 60);
        assert!(!is_local(&decide(Some(&local_only), 1.2, 2000, NOW)));
        let week = RESAMPLE_AFTER_SECS + 1;
        // Remote won long ago: re-measure local once.
        let old_remote_win = data(&[100_000], &[20_000], week);
        assert!(is_local(&decide(Some(&old_remote_win), 1.2, 2000, NOW)));
        // Local won long ago: re-measure remote once.
        let old_local_win = data(&[10_000], &[100_000], week);
        assert!(!is_local(&decide(Some(&old_local_win), 1.2, 2000, NOW)));
    }

    #[test]
    fn exhausted_local_slots_overflow_to_remote_and_free_on_release() {
        let dir = tempfile::tempdir().unwrap();
        let first = try_acquire_local_slot(dir.path(), 2).expect("slot 0");
        let second = try_acquire_local_slot(dir.path(), 2).expect("slot 1");
        assert!(try_acquire_local_slot(dir.path(), 2).is_none());
        drop(first);
        // A sibling test that forks while slot 0 was open shares its lock until
        // that child execs (bd-p7auy's mechanism), so allow a short window.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let third = loop {
            if let Some(slot) = try_acquire_local_slot(dir.path(), 2) {
                break slot;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "released slot never freed"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        drop((second, third));
        assert!(try_acquire_local_slot(dir.path(), 0).is_none());
    }

    #[test]
    fn caller_force_remote_and_strict_modes_override_even_a_verified_shim() {
        let placement = PlacementEnvironment {
            require_remote: Some("1".into()),
            shim_pid: Some("42".into()),
            ..PlacementEnvironment::default()
        };
        let applies = |inputs| gate_applies_with_environment(inputs, &placement, 42);
        assert!(applies(inputs()));
        assert!(!applies(SpeedGateInputs {
            local_slots: 0,
            ..inputs()
        }));
        assert!(!applies(SpeedGateInputs {
            caller_force_remote: true,
            ..inputs()
        }));
        assert!(!applies(SpeedGateInputs {
            strict_remote_mode: true,
            ..inputs()
        }));
        assert!(!applies(SpeedGateInputs {
            job: true,
            ..inputs()
        }));
        assert!(!applies(SpeedGateInputs {
            kind: Some(CompilationKind::Job),
            ..inputs()
        }));
        assert!(!applies(SpeedGateInputs {
            kind: None,
            ..inputs()
        }));
    }

    #[test]
    fn explicit_remote_requests_and_unrecognized_provenance_never_run_locally() {
        for required in ["1", "true", "TRUE", "yes", "ON", "invalid"] {
            for marker in [None, Some(""), Some("41"), Some("042"), Some("bad-pid")] {
                let placement = PlacementEnvironment {
                    require_remote: Some(required.into()),
                    shim_pid: marker.map(Into::into),
                    ..PlacementEnvironment::default()
                };
                assert!(!gate_applies_with_environment(inputs(), &placement, 42));
            }
        }
        let mut placement = PlacementEnvironment {
            require_remote: Some("1".into()),
            shim_pid: Some("42".into()),
            ..PlacementEnvironment::default()
        };
        assert!(gate_applies_with_environment(inputs(), &placement, 42));
        // A child inherits the environment but not permission for a local run.
        assert!(!gate_applies_with_environment(inputs(), &placement, 43));
        // The marker identifies exactly the injected value, not every truthy one.
        placement.require_remote = Some("true".into());
        assert!(!gate_applies_with_environment(inputs(), &placement, 42));
    }

    #[test]
    fn worker_and_force_remote_environment_override_shim_local_permission() {
        let mut placement = PlacementEnvironment {
            require_remote: Some("1".into()),
            shim_pid: Some("42".into()),
            ..PlacementEnvironment::default()
        };
        for force in ["1", "true", "YES", "on", "malformed"] {
            placement.force_remote = Some(force.into());
            assert!(!gate_applies_with_environment(inputs(), &placement, 42));
        }
        placement.force_remote = None;
        for worker in ["vmi1153651", "another-worker", " "] {
            placement.worker = Some(worker.into());
            assert!(!gate_applies_with_environment(inputs(), &placement, 42));
        }
        placement.worker = Some("".into());
        assert!(gate_applies_with_environment(inputs(), &placement, 42));
    }

    #[test]
    fn absent_and_explicit_false_remote_policy_preserve_intentional_speed_gate() {
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("NO"),
            Some("off"),
        ] {
            let placement = PlacementEnvironment {
                require_remote: value.map(Into::into),
                force_remote: value.map(Into::into),
                ..PlacementEnvironment::default()
            };
            assert!(gate_applies_with_environment(inputs(), &placement, 42));
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_placement_cannot_authorize_local_measurement() {
        use std::os::unix::ffi::OsStringExt;
        let mut placement = PlacementEnvironment {
            require_remote: Some(std::ffi::OsString::from_vec(vec![0xff])),
            shim_pid: Some("42".into()),
            ..PlacementEnvironment::default()
        };
        assert!(!gate_applies_with_environment(inputs(), &placement, 42));
        placement.force_remote = placement.require_remote.take();
        assert!(!gate_applies_with_environment(inputs(), &placement, 42));
    }

    #[test]
    fn local_runs_need_known_free_memory_above_the_floor() {
        assert!(memory_allows_local(Some(LOCAL_MIN_FREE_MEMORY_PCT)));
        assert!(!memory_allows_local(Some(LOCAL_MIN_FREE_MEMORY_PCT - 1)));
        assert!(!memory_allows_local(None));
        let meminfo =
            "MemTotal:       100000 kB\nMemFree:        1000 kB\nMemAvailable:   40000 kB\n";
        assert_eq!(meminfo_free_pct(meminfo), Some(40));
        assert_eq!(meminfo_free_pct("MemFree: 1 kB\n"), None);
    }

    fn healthy_macos() -> MacOsPressure {
        parse_macos_pressure("49\n100\n{ 1.0 2.0 3.0 }\n8\n").unwrap()
    }

    #[test]
    fn macos_segment_admission_is_strict_and_does_not_round_or_overflow() {
        let mut pressure = healthy_macos();
        assert!(resources_allow_local(Some(25), true, Some(&pressure)));
        for used in [50, 51, 100, 101, u64::MAX] {
            pressure.compressor_segments = used;
            assert!(!resources_allow_local(Some(100), true, Some(&pressure)));
        }
        pressure.compressor_segments = 0;
        pressure.compressor_segment_limit = 0;
        assert!(!resources_allow_local(Some(100), true, Some(&pressure)));
        pressure.compressor_segment_limit = u64::MAX;
        pressure.compressor_segments = u64::MAX / 2;
        assert!(resources_allow_local(Some(25), true, Some(&pressure)));
        pressure.compressor_segments += 1;
        assert!(!resources_allow_local(Some(25), true, Some(&pressure)));
        // No integer percentage truncation at a non-integral half-limit.
        pressure.compressor_segment_limit = 101;
        pressure.compressor_segments = 50;
        assert!(resources_allow_local(Some(25), true, Some(&pressure)));
        pressure.compressor_segments = 51;
        assert!(!resources_allow_local(Some(25), true, Some(&pressure)));
    }

    #[test]
    fn macos_both_load_windows_must_be_below_the_cpu_normalized_limit() {
        for cpus in [1, 8, 32] {
            for window in [0, 1] {
                let mut pressure = healthy_macos();
                pressure.logical_cpus = cpus;
                pressure.load_average = [0.0; 3];
                pressure.load_average[window] = f64::from(cpus) * 2.0 - 0.01;
                assert!(resources_allow_local(Some(100), true, Some(&pressure)));
                pressure.load_average[window] = f64::from(cpus) * 2.0;
                assert!(!resources_allow_local(Some(100), true, Some(&pressure)));
                pressure.load_average[window] = 140.0;
                assert!(!resources_allow_local(Some(100), true, Some(&pressure)));
            }
        }
        let mut pressure = healthy_macos();
        pressure.logical_cpus = 0;
        assert!(!resources_allow_local(Some(100), true, Some(&pressure)));
        pressure.logical_cpus = 8;
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            for window in 0..3 {
                pressure.load_average = [0.0; 3];
                pressure.load_average[window] = value;
                assert!(!resources_allow_local(Some(100), true, Some(&pressure)));
            }
        }
    }

    #[test]
    fn all_required_metrics_must_be_known_and_free_memory_must_be_valid() {
        let pressure = healthy_macos();
        for free in [None, Some(0), Some(24), Some(101), Some(u8::MAX)] {
            assert!(!resources_allow_local(free, true, Some(&pressure)));
            assert!(!resources_allow_local(free, false, None));
        }
        for free in [25, 26, 100] {
            assert!(resources_allow_local(Some(free), true, Some(&pressure)));
            assert!(!resources_allow_local(Some(free), true, None));
            // Linux needs its own known memory reading, not macOS-only sysctls.
            assert!(resources_allow_local(Some(free), false, None));
        }
        assert_eq!(
            meminfo_free_pct(&format!(
                "MemTotal: {} kB\nMemAvailable: {} kB\n",
                u64::MAX,
                u64::MAX
            )),
            Some(100)
        );
        assert_eq!(
            meminfo_free_pct("MemTotal: 0 kB\nMemAvailable: 1 kB\n"),
            None
        );
    }

    #[test]
    fn ambiguous_or_inconsistent_meminfo_never_admits_a_local_build() {
        for meminfo in [
            "MemTotal: 100 kB\nMemAvailable: 101 kB\n",
            "MemTotal: 100 kB\nMemAvailable: 40 MB\n",
            "MemTotal: 100 MB\nMemAvailable: 40 kB\n",
            "MemTotal: 100 kB\nMemAvailable: 40\n",
            "MemTotal: 100\nMemAvailable: 40 kB\n",
            "MemTotal: 100 kB\nMemAvailable: 40 kB junk\n",
            "MemTotal: 100 kB junk\nMemAvailable: 40 kB\n",
            "MemTotal: 100 kB\nMemAvailable: 1 kB\nMemAvailable: 40 kB\n",
            "MemTotal: 100 kB\nMemAvailable: bad\nMemAvailable: 40 kB\n",
            "MemTotal: 100 kB\nMemTotal: 100 kB\nMemAvailable: 40 kB\n",
            "MemTotal: 100 kB\nMemAvailable: -1 kB\n",
            "MemTotal: 100 kB\nMemAvailable: 18446744073709551616 kB\n",
        ] {
            assert_eq!(meminfo_free_pct(meminfo), None, "{meminfo}");
            assert!(!resources_allow_local(
                meminfo_free_pct(meminfo),
                false,
                None
            ));
        }
        for (available, admitted) in [(0, false), (24, false), (25, true), (100, true)] {
            let meminfo = format!("MemTotal: 100 kB\nMemAvailable: {available} kB\n");
            assert_eq!(
                resources_allow_local(meminfo_free_pct(&meminfo), false, None),
                admitted,
            );
        }
    }

    #[test]
    fn macos_sysctl_parser_rejects_missing_malformed_and_nonfinite_metrics() {
        for output in [
            "",
            "49\n100\n{ 1 2 3 }\n",
            "49\n100\n{ 1 2 3 }\n8\nunexpected\n",
            "unknown oid\n100\n{ 1 2 3 }\n8\n",
            "-1\n100\n{ 1 2 3 }\n8\n",
            "49\n0\n{ 1 2 3 }\n8\n",
            "101\n100\n{ 1 2 3 }\n8\n",
            "49\n100\n{ 1 2 }\n8\n",
            "49\n100\n{ 1 2 3 4 }\n8\n",
            "49\n100\n1 2 3\n8\n",
            "49\n100\n{ NaN 2 3 }\n8\n",
            "49\n100\n{ 1 inf 3 }\n8\n",
            "49\n100\n{ 1 2 -1 }\n8\n",
            "49\n100\n{ 1 2 3 }\n0\n",
            "49\n100\n{ 1 2 3 }\n-8\n",
            "18446744073709551616\n100\n{ 1 2 3 }\n8\n",
        ] {
            assert!(parse_macos_pressure(output).is_none(), "{output:?}");
        }
        assert!(parse_macos_pressure(" 0\n100 \n{ 0.0 0.0 0.0 }\n8").is_some());
    }

    #[cfg(unix)]
    #[test]
    fn exited_pressure_probe_cannot_turn_late_stdout_into_a_healthy_reply() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let (reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.write_all(b"49\n100\n{ 1 2 3 }\n8\n").unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(child.wait().unwrap().success());
        let started = Instant::now();
        // Model a second stdout owner without orphaning a child process.
        // Eventually close it so a regression fails instead of hanging tests.
        let holder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(writer);
        });
        let output = collect_probe_output(&mut child, reader, started, Duration::from_millis(10));
        holder.join().unwrap();
        assert!(output.is_none(), "late EOF authorized a healthy reply");
    }

    #[cfg(unix)]
    #[test]
    fn pressure_probes_bound_output_and_require_utf8_complete_success() {
        use std::process::Command;
        use std::time::Duration;

        for bytes in [MAX_PROBE_OUTPUT_BYTES, MAX_PROBE_OUTPUT_BYTES + 1, 65_536] {
            let output = bounded_probe(
                Command::new("/bin/sh").args(["-c", &format!("printf '%{bytes}s' ''")]),
                Duration::from_secs(1),
            );
            if bytes == MAX_PROBE_OUTPUT_BYTES {
                assert_eq!(output.unwrap(), " ".repeat(bytes));
            } else {
                assert!(output.is_none(), "oversized probe output was accepted");
            }
        }
        for script in [
            "printf '\\377'",
            "printf '25'; exit 1",
            "exec 1>&-; exec sleep 10",
        ] {
            assert!(
                bounded_probe(
                    Command::new("/bin/sh").args(["-c", script]),
                    Duration::from_millis(20),
                )
                .is_none(),
                "accepted incomplete or invalid probe: {script}",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn pressure_probe_closes_parent_writer_and_can_reuse_command() {
        use std::process::Command;
        use std::time::Duration;

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf '25'"]);
        for _ in 0..3 {
            assert_eq!(
                bounded_probe(&mut command, Duration::from_secs(1)),
                Some("25".to_string()),
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn zero_probe_budget_does_not_execute_the_command() {
        use std::process::Command;
        use std::time::Duration;

        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("executed");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf executed > \"$1\"", "probe-test"]);
        command.arg(&marker);
        assert!(bounded_probe(&mut command, Duration::ZERO).is_none());
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pressure_probes_fail_closed_on_spawn_failure_exit_failure_and_timeout() {
        use std::process::Command;
        use std::time::Duration;
        let missing = tempfile::tempdir().unwrap();
        assert!(
            bounded_probe(
                &mut Command::new(missing.path().join("missing")),
                Duration::from_secs(1),
            )
            .is_none()
        );
        assert!(
            bounded_probe(
                Command::new("/bin/sh")
                    .args(["-c", "printf '49\\n100\\n{ 1 2 3 }\\n8\\n'; exit 1"]),
                Duration::from_secs(1),
            )
            .is_none()
        );
        assert!(
            bounded_probe(
                Command::new("/bin/sh").args(["-c", "exec sleep 10"]),
                Duration::from_millis(10),
            )
            .is_none()
        );
        let output = bounded_probe(
            Command::new("/bin/sh").args(["-c", "printf '49\\n100\\n{ 1 2 3 }\\n8\\n'"]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(resources_allow_local(
            Some(25),
            true,
            parse_macos_pressure(&output).as_ref(),
        ));
    }
}
