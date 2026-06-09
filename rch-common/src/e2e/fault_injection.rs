//! Reusable fault-injection fixtures for RCH remediation scenarios
//! (bd-session-history-remediation-ocv9i.16.2).
//!
//! Each [`FaultFixture`] sets up the filesystem / mock state needed to drive a
//! single remediation failure class through the real code paths, **without any
//! real destructive operation**: everything lives under a private
//! [`tempfile::TempDir`], so cleanup (on `Drop`) is bounded to that root and can
//! never touch files outside it. Setup and teardown emit structured `tracing`
//! events on `target: "rch::e2e::fault"` so a test or E2E script can prove the
//! fixture was installed and torn down.
//!
//! Fixtures are usable from unit tests, integration tests, and E2E scripts, and
//! need no real Contabo/VMI worker — runtime-behavioral faults (worker
//! unreachable, daemon socket refusal) are expressed as mock SSH config / dead
//! socket paths that the production code treats identically to the real fault.
//!
//! Each scenario maps to a stable [`IncidentReasonCode`] so fixtures and the
//! incident vocabulary stay in lockstep.

use std::path::{Path, PathBuf};

use crate::incident::IncidentReasonCode;
use crate::types::{WorkerConfig, WorkerId};

/// A fault class this module can inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultScenario {
    /// Daemon Unix socket is absent — connections are refused.
    DaemonSocketRefused,
    /// A stale socket file exists but no live listener is behind it.
    StaleSocket,
    /// A worker host is unreachable over SSH.
    WorkerUnreachable,
    /// The deployed `rch-wkr` is the wrong architecture / at the wrong path.
    WrongWorkerBinaryPath,
    /// `rustup` is absent from the resolved PATH.
    MissingRustup,
    /// The wasm target is not installed in the toolchain.
    MissingWasmTarget,
    /// Disk byte capacity is exhausted.
    DiskBytesExhausted,
    /// Disk inode capacity is exhausted.
    DiskInodesExhausted,
    /// Worker telemetry has gone stale / is missing.
    TelemetryGap,
    /// The active project root is excluded from offload.
    ActiveProjectExclusion,
    /// A source file vanishes mid-transfer (rsync vanished-file race).
    RsyncVanishedFile,
    /// An expected artifact is missing under a rewritten target dir.
    ArtifactMissingRewrittenTarget,
    /// A queued job's owning process is gone (orphan).
    QueuedJobOrphan,
    /// The source changes while a proof intent is queued.
    SourceChangedWhileProofQueued,
}

impl FaultScenario {
    /// Stable snake_case identifier (for logs and scenario selection).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DaemonSocketRefused => "daemon_socket_refused",
            Self::StaleSocket => "stale_socket",
            Self::WorkerUnreachable => "worker_unreachable",
            Self::WrongWorkerBinaryPath => "wrong_worker_binary_path",
            Self::MissingRustup => "missing_rustup",
            Self::MissingWasmTarget => "missing_wasm_target",
            Self::DiskBytesExhausted => "disk_bytes_exhausted",
            Self::DiskInodesExhausted => "disk_inodes_exhausted",
            Self::TelemetryGap => "telemetry_gap",
            Self::ActiveProjectExclusion => "active_project_exclusion",
            Self::RsyncVanishedFile => "rsync_vanished_file",
            Self::ArtifactMissingRewrittenTarget => "artifact_missing_rewritten_target",
            Self::QueuedJobOrphan => "queued_job_orphan",
            Self::SourceChangedWhileProofQueued => "source_changed_while_proof_queued",
        }
    }

    /// The incident reason this scenario reproduces (links fixtures to the
    /// stable reason-code registry).
    #[must_use]
    pub const fn reason_code(self) -> IncidentReasonCode {
        match self {
            Self::DaemonSocketRefused | Self::StaleSocket => {
                IncidentReasonCode::DaemonSocketRefused
            }
            Self::WorkerUnreachable => IncidentReasonCode::NoAdmissibleWorkers,
            Self::WrongWorkerBinaryPath => IncidentReasonCode::WrongUserPathWorkerBinary,
            Self::MissingRustup | Self::MissingWasmTarget => {
                IncidentReasonCode::MissingRuntimeToolchainTarget
            }
            Self::DiskBytesExhausted | Self::DiskInodesExhausted => IncidentReasonCode::DiskFull,
            Self::TelemetryGap => IncidentReasonCode::TelemetryStale,
            Self::ActiveProjectExclusion => IncidentReasonCode::ActiveProjectExclusion,
            Self::RsyncVanishedFile => IncidentReasonCode::RsyncVanishedFile,
            Self::ArtifactMissingRewrittenTarget => IncidentReasonCode::ArtifactMiss,
            Self::QueuedJobOrphan => IncidentReasonCode::QueueAmbiguity,
            Self::SourceChangedWhileProofQueued => IncidentReasonCode::ProofRefusal,
        }
    }
}

/// Simulated `statvfs`-style disk capacity, so a disk-pressure check can be
/// exercised without actually filling a real filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimulatedDiskStats {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub total_inodes: u64,
    pub available_inodes: u64,
}

impl SimulatedDiskStats {
    const BIG_BYTES: u64 = 1 << 40; // 1 TiB
    const BIG_INODES: u64 = 10_000_000;

    /// Plenty of headroom (the no-fault baseline).
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            total_bytes: Self::BIG_BYTES,
            available_bytes: Self::BIG_BYTES / 2,
            total_inodes: Self::BIG_INODES,
            available_inodes: Self::BIG_INODES / 2,
        }
    }

    /// Byte capacity exhausted (inodes fine).
    #[must_use]
    pub fn bytes_exhausted() -> Self {
        Self {
            available_bytes: 0,
            ..Self::healthy()
        }
    }

    /// Inode capacity exhausted (bytes fine).
    #[must_use]
    pub fn inodes_exhausted() -> Self {
        Self {
            available_inodes: 0,
            ..Self::healthy()
        }
    }

    #[must_use]
    pub fn is_bytes_exhausted(&self) -> bool {
        self.available_bytes == 0
    }

    #[must_use]
    pub fn is_inodes_exhausted(&self) -> bool {
        self.available_inodes == 0
    }
}

/// Mach-O 64-bit magic — a deployed darwin binary on a linux worker path is the
/// canonical "wrong arch" fault. A fixture writes this header so a sanity check
/// can detect the mismatch.
pub const MACH_O_64_MAGIC: [u8; 4] = [0xCF, 0xFA, 0xED, 0xFE];
/// ELF magic — the *correct* header a linux worker binary should carry.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// A single installed fault scenario. Owns a private temp root; all state lives
/// under it and is removed on `Drop`.
pub struct FaultFixture {
    scenario: FaultScenario,
    dir: tempfile::TempDir,
    disk_stats: Option<SimulatedDiskStats>,
    worker: Option<WorkerConfig>,
}

impl FaultFixture {
    /// Install `scenario`. Returns an error only on a genuine temp-dir / I/O
    /// failure (never on the simulated fault itself).
    pub fn inject(scenario: FaultScenario) -> std::io::Result<Self> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().to_path_buf();
        let mut disk_stats = None;
        let mut worker = None;

        match scenario {
            FaultScenario::DaemonSocketRefused => {
                // Intentionally do NOT create the socket: a connect() refuses.
            }
            FaultScenario::StaleSocket => {
                // A regular file at the socket path: exists, but not a listener.
                std::fs::write(root.join("rch.sock"), b"stale")?;
            }
            FaultScenario::WorkerUnreachable => {
                worker = Some(unreachable_worker());
            }
            FaultScenario::WrongWorkerBinaryPath => {
                // Write a darwin (Mach-O) binary where a linux ELF is expected.
                std::fs::create_dir_all(root.join("bin"))?;
                std::fs::write(root.join("bin/rch-wkr"), MACH_O_64_MAGIC)?;
            }
            FaultScenario::MissingRustup => {
                // A PATH dir with no `rustup` in it.
                std::fs::create_dir_all(root.join("bin"))?;
            }
            FaultScenario::MissingWasmTarget => {
                // A toolchain lib dir with no wasm32 target subdir.
                std::fs::create_dir_all(root.join("toolchain/lib/rustlib"))?;
                std::fs::create_dir_all(
                    root.join("toolchain/lib/rustlib/x86_64-unknown-linux-gnu"),
                )?;
            }
            FaultScenario::DiskBytesExhausted => {
                disk_stats = Some(SimulatedDiskStats::bytes_exhausted());
            }
            FaultScenario::DiskInodesExhausted => {
                disk_stats = Some(SimulatedDiskStats::inodes_exhausted());
            }
            FaultScenario::TelemetryGap => {
                // No state on disk; the gap is expressed via telemetry_signals().
            }
            FaultScenario::ActiveProjectExclusion => {
                // A project root that the exclusion policy will mark excluded.
                std::fs::create_dir_all(root.join("project"))?;
                std::fs::write(root.join("project/.rch-exclude"), b"excluded")?;
            }
            FaultScenario::RsyncVanishedFile => {
                std::fs::create_dir_all(root.join("src"))?;
                std::fs::write(root.join("src/vanishing.rs"), b"// will vanish\n")?;
            }
            FaultScenario::ArtifactMissingRewrittenTarget => {
                // The rewritten target dir exists but the expected artifact is
                // absent.
                std::fs::create_dir_all(root.join(".rch-target-rewritten/debug"))?;
            }
            FaultScenario::QueuedJobOrphan => {
                // A job record whose owning pid does not exist.
                std::fs::write(root.join("job.record"), b"job_id=orphan-1 pid=0\n")?;
            }
            FaultScenario::SourceChangedWhileProofQueued => {
                std::fs::create_dir_all(root.join("src"))?;
                std::fs::write(root.join("src/lib.rs"), b"pub fn v() -> u32 { 1 }\n")?;
            }
        }

        tracing::info!(
            target: "rch::e2e::fault",
            scenario = scenario.as_str(),
            reason_code = scenario.reason_code().code(),
            root = %root.display(),
            "fault.fixture.setup",
        );

        Ok(Self {
            scenario,
            dir,
            disk_stats,
            worker,
        })
    }

    /// The scenario this fixture injects.
    #[must_use]
    pub fn scenario(&self) -> FaultScenario {
        self.scenario
    }

    /// The private temp root. All fixture state lives under here.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Path to the (absent or stale) daemon socket for socket-fault scenarios.
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.root().join("rch.sock")
    }

    /// Path to the deployed worker binary (Mach-O wrong-arch fixture).
    #[must_use]
    pub fn worker_binary_path(&self) -> PathBuf {
        self.root().join("bin/rch-wkr")
    }

    /// PATH directory to point a toolchain lookup at (missing-rustup fixture).
    #[must_use]
    pub fn path_dir(&self) -> PathBuf {
        self.root().join("bin")
    }

    /// The simulated disk stats for disk-exhaustion scenarios.
    #[must_use]
    pub fn disk_stats(&self) -> Option<SimulatedDiskStats> {
        self.disk_stats
    }

    /// A mock-unreachable worker config (worker-unreachable scenario).
    #[must_use]
    pub fn worker(&self) -> Option<&WorkerConfig> {
        self.worker.as_ref()
    }

    /// Telemetry signals describing the gap (telemetry-gap scenario).
    #[must_use]
    pub fn telemetry_signals(&self) -> crate::telemetry_explain::TelemetrySignals {
        crate::telemetry_explain::TelemetrySignals {
            ever_received_sample: false,
            poller_behind: false,
            ..crate::telemetry_explain::TelemetrySignals::default()
        }
    }

    /// The source file used by vanished-file / proof-changed scenarios.
    #[must_use]
    pub fn source_file(&self) -> PathBuf {
        match self.scenario {
            FaultScenario::RsyncVanishedFile => self.root().join("src/vanishing.rs"),
            _ => self.root().join("src/lib.rs"),
        }
    }

    /// Trigger the vanished-file race: remove the source file (bounded to the
    /// temp root) to simulate rsync observing a file disappear mid-transfer.
    pub fn vanish_source(&self) -> std::io::Result<()> {
        let path = self.source_file();
        debug_assert!(
            path.starts_with(self.root()),
            "vanish must stay in temp root"
        );
        std::fs::remove_file(&path)?;
        tracing::info!(
            target: "rch::e2e::fault",
            scenario = self.scenario.as_str(),
            path = %path.display(),
            "fault.fixture.source_vanished",
        );
        Ok(())
    }

    /// Mutate the source after a proof intent would have been queued (changes
    /// content so a proof re-validation sees drift).
    pub fn mutate_source(&self) -> std::io::Result<()> {
        let path = self.source_file();
        debug_assert!(
            path.starts_with(self.root()),
            "mutate must stay in temp root"
        );
        std::fs::write(&path, b"pub fn v() -> u32 { 2 }\n")?;
        tracing::info!(
            target: "rch::e2e::fault",
            scenario = self.scenario.as_str(),
            path = %path.display(),
            "fault.fixture.source_mutated",
        );
        Ok(())
    }
}

impl Drop for FaultFixture {
    fn drop(&mut self) {
        // The TempDir removes the (bounded) root; we just journal teardown.
        tracing::info!(
            target: "rch::e2e::fault",
            scenario = self.scenario.as_str(),
            root = %self.dir.path().display(),
            "fault.fixture.teardown",
        );
    }
}

/// A worker config that mock SSH treats as unreachable (RFC 5737 TEST-NET host
/// that never resolves to a real machine).
fn unreachable_worker() -> WorkerConfig {
    WorkerConfig {
        id: WorkerId("unreachable".to_string()),
        host: "192.0.2.1".to_string(),
        user: "rch".to_string(),
        ..WorkerConfig::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[FaultScenario] = &[
        FaultScenario::DaemonSocketRefused,
        FaultScenario::StaleSocket,
        FaultScenario::WorkerUnreachable,
        FaultScenario::WrongWorkerBinaryPath,
        FaultScenario::MissingRustup,
        FaultScenario::MissingWasmTarget,
        FaultScenario::DiskBytesExhausted,
        FaultScenario::DiskInodesExhausted,
        FaultScenario::TelemetryGap,
        FaultScenario::ActiveProjectExclusion,
        FaultScenario::RsyncVanishedFile,
        FaultScenario::ArtifactMissingRewrittenTarget,
        FaultScenario::QueuedJobOrphan,
        FaultScenario::SourceChangedWhileProofQueued,
    ];

    #[test]
    fn every_scenario_injects_and_cleans_up_within_temp_root() {
        for &scenario in ALL {
            let root: PathBuf;
            {
                let fx = FaultFixture::inject(scenario).expect("inject");
                root = fx.root().to_path_buf();
                assert!(root.exists(), "{}: root exists", scenario.as_str());
                // Everything the fixture creates is under its own root.
                assert!(root.starts_with(std::env::temp_dir()));
            }
            // Dropped -> bounded cleanup removed the whole root, nothing else.
            assert!(
                !root.exists(),
                "{}: root cleaned on drop",
                scenario.as_str()
            );
        }
    }

    #[test]
    fn scenario_ids_and_reason_codes_are_distinct_and_mapped() {
        let mut ids: Vec<&str> = ALL.iter().map(|s| s.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(n, ids.len(), "scenario ids must be unique");
        // Every scenario maps to a real incident reason code.
        for &s in ALL {
            assert!(!s.reason_code().code().is_empty());
        }
    }

    #[test]
    fn daemon_socket_refused_has_no_socket() {
        let fx = FaultFixture::inject(FaultScenario::DaemonSocketRefused).unwrap();
        assert!(
            !fx.socket_path().exists(),
            "socket must be absent (refused)"
        );
    }

    #[test]
    fn stale_socket_is_a_file_not_a_listener() {
        let fx = FaultFixture::inject(FaultScenario::StaleSocket).unwrap();
        assert!(fx.socket_path().is_file());
    }

    #[test]
    fn wrong_worker_binary_is_mach_o_not_elf() {
        let fx = FaultFixture::inject(FaultScenario::WrongWorkerBinaryPath).unwrap();
        let bytes = std::fs::read(fx.worker_binary_path()).unwrap();
        assert_eq!(&bytes[..4], &MACH_O_64_MAGIC);
        assert_ne!(&bytes[..4], &ELF_MAGIC);
    }

    #[test]
    fn missing_rustup_path_dir_has_no_rustup() {
        let fx = FaultFixture::inject(FaultScenario::MissingRustup).unwrap();
        assert!(fx.path_dir().is_dir());
        assert!(!fx.path_dir().join("rustup").exists());
    }

    #[test]
    fn disk_exhaustion_stats_are_distinct() {
        let bytes = FaultFixture::inject(FaultScenario::DiskBytesExhausted).unwrap();
        let s = bytes.disk_stats().unwrap();
        assert!(s.is_bytes_exhausted() && !s.is_inodes_exhausted());

        let inodes = FaultFixture::inject(FaultScenario::DiskInodesExhausted).unwrap();
        let s = inodes.disk_stats().unwrap();
        assert!(s.is_inodes_exhausted() && !s.is_bytes_exhausted());

        assert!(!SimulatedDiskStats::healthy().is_bytes_exhausted());
    }

    #[test]
    fn worker_unreachable_provides_test_net_worker() {
        let fx = FaultFixture::inject(FaultScenario::WorkerUnreachable).unwrap();
        let w = fx.worker().expect("worker present");
        assert_eq!(w.host, "192.0.2.1");
    }

    #[test]
    fn telemetry_gap_signals_never_received() {
        let fx = FaultFixture::inject(FaultScenario::TelemetryGap).unwrap();
        let signals = fx.telemetry_signals();
        assert!(!signals.ever_received_sample);
    }

    #[test]
    fn rsync_vanished_file_removes_only_its_own_source() {
        let fx = FaultFixture::inject(FaultScenario::RsyncVanishedFile).unwrap();
        let src = fx.source_file();
        assert!(src.exists());
        fx.vanish_source().unwrap();
        assert!(!src.exists());
        // The temp root itself survives the vanish (only the file went).
        assert!(fx.root().exists());
    }

    #[test]
    fn source_changed_while_proof_queued_mutates_content() {
        let fx = FaultFixture::inject(FaultScenario::SourceChangedWhileProofQueued).unwrap();
        let before = std::fs::read_to_string(fx.source_file()).unwrap();
        fx.mutate_source().unwrap();
        let after = std::fs::read_to_string(fx.source_file()).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn artifact_missing_rewritten_target_has_dir_but_no_artifact() {
        let fx = FaultFixture::inject(FaultScenario::ArtifactMissingRewrittenTarget).unwrap();
        assert!(fx.root().join(".rch-target-rewritten/debug").is_dir());
        assert!(
            !fx.root()
                .join(".rch-target-rewritten/debug/libfixture.rlib")
                .exists()
        );
    }
}
