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
//!   [`LOCAL_MIN_FREE_MEMORY_PCT`] free memory. Otherwise the build is
//!   offloaded exactly as before.
use super::timing_history::{ProjectTimingData, TimingRecord, timing_cache};
use rch_common::CompilationKind;
use std::fs::File;
use std::path::{Path, PathBuf};

/// A side whose newest sample is older than this is measured again, so a
/// decision cannot outlive the fleet or project it was measured on.
pub(super) const RESAMPLE_AFTER_SECS: u64 = 7 * 24 * 3600;

/// Local runs need at least this much free memory. On 2026-10-12 mac-studio
/// panicked when its VM compressor ran out of segments under swarm load, so
/// the gate refuses to add local builds to a machine that is already short.
pub(super) const LOCAL_MIN_FREE_MEMORY_PCT: u8 = 25;

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
    /// The caller explicitly forced remote (`RCH_FORCE_REMOTE`, or
    /// `general.force_remote` not explained by the shim's blanket
    /// `RCH_REQUIRE_REMOTE=1`).
    pub caller_force_remote: bool,
}

/// Like `general.force_local`, the gate is a deliberate placement rather than
/// a fallback, so the shim's blanket `RCH_REQUIRE_REMOTE=1` does not disable
/// it. An explicit caller force-remote and every strict mode do.
pub(super) fn gate_applies(inputs: SpeedGateInputs) -> bool {
    inputs.local_slots > 0
        && !inputs.job
        && !inputs.strict_remote_mode
        && !inputs.caller_force_remote
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
        let output = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "kern.memorystatus_level"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8_lossy(&output.stdout).trim().parse().ok()
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
        meminfo.lines().find_map(|line| {
            let rest = line.strip_prefix(name)?.strip_prefix(':')?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
    };
    let total = field("MemTotal").filter(|total| *total > 0)?;
    let available = field("MemAvailable")?;
    u8::try_from((available.min(total) * 100) / total).ok()
}

/// Unknown memory counts as short: the gate only adds load when it can see room.
fn memory_allows_local(free_pct: Option<u8>) -> bool {
    free_pct.is_some_and(|pct| pct >= LOCAL_MIN_FREE_MEMORY_PCT)
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
    let free_pct = memory_free_pct();
    if !memory_allows_local(free_pct) {
        tracing::info!(
            target: "rch::hook::speed_gate",
            free_pct = ?free_pct,
            "speed gate prefers local, but free memory is below {LOCAL_MIN_FREE_MEMORY_PCT}%; offloading"
        );
        return None;
    }
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
    /// `local` or `remote`, before the slot and memory checks.
    pub decision: Option<String>,
    pub reason: Option<String>,
    pub free_memory_pct: Option<u8>,
    pub min_free_memory_pct: u8,
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
        free_memory_pct: enabled.then(memory_free_pct).flatten(),
        min_free_memory_pct: LOCAL_MIN_FREE_MEMORY_PCT,
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
    fn caller_force_remote_and_strict_modes_disable_the_gate_but_the_shim_does_not() {
        // The shim's blanket RCH_REQUIRE_REMOTE=1 is not a caller force-remote,
        // so a shim-routed build with the gate enabled is still gated.
        assert!(gate_applies(inputs()));
        assert!(!gate_applies(SpeedGateInputs {
            local_slots: 0,
            ..inputs()
        }));
        assert!(!gate_applies(SpeedGateInputs {
            caller_force_remote: true,
            ..inputs()
        }));
        assert!(!gate_applies(SpeedGateInputs {
            strict_remote_mode: true,
            ..inputs()
        }));
        assert!(!gate_applies(SpeedGateInputs {
            job: true,
            ..inputs()
        }));
        assert!(!gate_applies(SpeedGateInputs {
            kind: Some(CompilationKind::Job),
            ..inputs()
        }));
        assert!(!gate_applies(SpeedGateInputs {
            kind: None,
            ..inputs()
        }));
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
}
