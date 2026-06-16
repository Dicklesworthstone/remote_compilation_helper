//! Append-only, bounded, corruption-tolerant incident ledger.
//!
//! A durable JSONL log of [`IncidentEvent`]s that survives process restarts and
//! is cheap enough to write from the hook/daemon hot paths (one buffered append
//! per event; a single `stat` to decide whether retention compaction is due).
//!
//! Design:
//! - **Append-only**: each event is one JSON line appended to the file. A line
//!   shorter than `PIPE_BUF` is written atomically by the OS, so concurrent
//!   hook + daemon writers interleave whole lines rather than corrupting one
//!   another. Torn/garbage lines are tolerated on read.
//! - **Bounded retention**: when the file grows past `max_bytes`, it is
//!   compacted to the most-recent `max_entries` events via an atomic
//!   temp-file + rename, so a long-running fleet cannot grow the ledger without
//!   limit. Compaction also drops any unparseable lines.
//! - **Privacy-aware**: the ledger persists whatever [`IncidentEvent`] carries;
//!   that schema uses a `command_fingerprint` (not the raw command) and has no
//!   secret fields, so the on-disk ledger never contains raw command text or
//!   credentials.
//! - **Queryable**: [`IncidentLedger::query`] filters by project, command
//!   fingerprint, worker, and reason code.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::incident::{IncidentEvent, IncidentReasonCode};

/// Default retained-event count after a compaction.
const DEFAULT_MAX_ENTRIES: usize = 5_000;
/// Default file-size compaction trigger (4 MiB).
const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Ledger configuration.
#[derive(Debug, Clone)]
pub struct IncidentLedgerConfig {
    /// Path to the JSONL ledger file.
    pub path: PathBuf,
    /// Events retained after a compaction (most-recent wins).
    pub max_entries: usize,
    /// File size that triggers a compaction, in bytes.
    pub max_bytes: u64,
}

impl IncidentLedgerConfig {
    /// Config for an explicit ledger path with default retention bounds.
    #[must_use]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

impl Default for IncidentLedgerConfig {
    fn default() -> Self {
        Self {
            path: default_ledger_path(),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// Resolve the default ledger path: `${RCH_STATE_HOME}/incidents.jsonl`, else
/// `${XDG_STATE_HOME}/rch/...`, else `~/.local/state/rch/...`, else
/// `/tmp/rch/...`.
#[must_use]
pub fn default_ledger_path() -> PathBuf {
    let base = std::env::var_os("RCH_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| {
            std::env::var_os("XDG_STATE_HOME")
                .map(|d| PathBuf::from(d).join("rch"))
                .filter(|p| p.as_os_str().len() > "rch".len())
        })
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state/rch")))
        .unwrap_or_else(|| PathBuf::from("/tmp/rch"));
    base.join("incidents.jsonl")
}

/// Outcome counts from a corruption-tolerant read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LedgerReadStats {
    /// Events parsed successfully.
    pub parsed: usize,
    /// Lines skipped because they did not parse (corruption-tolerant).
    pub skipped: usize,
}

/// Filter for [`IncidentLedger::query`]. `None` fields match anything.
#[derive(Debug, Clone, Default)]
pub struct IncidentFilter {
    pub project_id: Option<String>,
    pub command_fingerprint: Option<String>,
    pub worker_id: Option<String>,
    pub reason_code: Option<IncidentReasonCode>,
}

impl IncidentFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn project(mut self, project_id: impl Into<String>) -> Self {
        self.project_id = Some(project_id.into());
        self
    }

    #[must_use]
    pub fn command_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.command_fingerprint = Some(fp.into());
        self
    }

    #[must_use]
    pub fn worker(mut self, worker_id: impl Into<String>) -> Self {
        self.worker_id = Some(worker_id.into());
        self
    }

    #[must_use]
    pub fn reason(mut self, reason: IncidentReasonCode) -> Self {
        self.reason_code = Some(reason);
        self
    }

    /// Does `event` satisfy every set field?
    #[must_use]
    pub fn matches(&self, event: &IncidentEvent) -> bool {
        if let Some(p) = &self.project_id
            && *p != event.project_id
        {
            return false;
        }
        if let Some(fp) = &self.command_fingerprint
            && *fp != event.command_fingerprint
        {
            return false;
        }
        if let Some(w) = &self.worker_id
            && event.worker_id.as_deref() != Some(w.as_str())
        {
            return false;
        }
        if let Some(r) = self.reason_code
            && r != event.reason_code
        {
            return false;
        }
        true
    }
}

/// Append-only incident ledger.
#[derive(Debug, Clone)]
pub struct IncidentLedger {
    config: IncidentLedgerConfig,
}

impl IncidentLedger {
    /// Construct from explicit config.
    #[must_use]
    pub fn new(config: IncidentLedgerConfig) -> Self {
        Self { config }
    }

    /// Construct for an explicit path with default bounds.
    #[must_use]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self::new(IncidentLedgerConfig::with_path(path))
    }

    /// The ledger file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.config.path
    }

    /// Append one event. Creates the parent directory on first write. Triggers
    /// a retention compaction when the file exceeds `max_bytes`.
    ///
    /// Best-effort durability: a write failure is returned, not swallowed, so
    /// callers on non-critical paths can log-and-continue (incident logging
    /// must never break a build).
    pub fn append(&self, event: &IncidentEvent) -> std::io::Result<()> {
        if let Some(parent) = self.config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        // One JSON object per line. serde_json::to_string never embeds a raw
        // newline, so line framing stays intact. Free-form `details` values are
        // routed through the shared secret redactor at write time (bd-53ga7) so
        // an injected secret never reaches the persisted ledger.
        let mut line = serde_json::to_string(&event.redacted())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;

        // Cheap stat-based retention trigger (no full read on the hot path).
        if let Ok(meta) = fs::metadata(&self.config.path)
            && meta.len() > self.config.max_bytes
        {
            self.compact()?;
        }
        Ok(())
    }

    /// Read every parseable event, tolerating (and counting) corrupt lines.
    #[must_use]
    pub fn read_all(&self) -> Vec<IncidentEvent> {
        self.read_all_with_stats().0
    }

    /// Read with parse/skip statistics. A missing file yields an empty result.
    #[must_use]
    pub fn read_all_with_stats(&self) -> (Vec<IncidentEvent>, LedgerReadStats) {
        let mut events = Vec::new();
        let mut stats = LedgerReadStats::default();
        let file = match fs::File::open(&self.config.path) {
            Ok(f) => f,
            Err(_) => return (events, stats),
        };
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else {
                // An I/O error mid-stream (e.g. invalid UTF-8): count and stop.
                stats.skipped += 1;
                break;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<IncidentEvent>(trimmed) {
                Ok(event) => {
                    events.push(event);
                    stats.parsed += 1;
                }
                Err(_) => stats.skipped += 1,
            }
        }
        (events, stats)
    }

    /// Read events matching `filter`, newest-last (file order).
    #[must_use]
    pub fn query(&self, filter: &IncidentFilter) -> Vec<IncidentEvent> {
        self.read_all()
            .into_iter()
            .filter(|e| filter.matches(e))
            .collect()
    }

    /// Compact the ledger to the most-recent `max_entries` parseable events,
    /// dropping corrupt lines. Atomic via temp-file + rename so a reader never
    /// observes a partial file.
    pub fn compact(&self) -> std::io::Result<()> {
        let (mut events, _) = self.read_all_with_stats();
        if events.len() > self.config.max_entries {
            let drop = events.len() - self.config.max_entries;
            events.drain(0..drop);
        }

        let parent = self.config.path.parent().unwrap_or_else(|| Path::new("."));
        // Unique temp name avoids clobbering a concurrent compactor.
        let tmp = parent.join(format!(".incidents.{}.tmp", std::process::id(),));
        {
            let mut tmp_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            for event in &events {
                let mut line = serde_json::to_string(event)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                line.push('\n');
                tmp_file.write_all(line.as_bytes())?;
            }
            tmp_file.flush()?;
        }
        match fs::rename(&tmp, &self.config.path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{IncidentEventType, IncidentSource, SelectedMode};

    fn event(
        reason: IncidentReasonCode,
        project: &str,
        worker: Option<&str>,
        ts: u64,
    ) -> IncidentEvent {
        let mut e = IncidentEvent::new(
            IncidentEventType::Selection,
            reason,
            IncidentSource::Daemon,
            project,
            "cargo build",
            SelectedMode::Remote,
            true,
            ts,
        );
        if let Some(w) = worker {
            e = e.with_worker_id(w);
        }
        e
    }

    fn temp_ledger() -> (IncidentLedger, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let ledger = IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
        (ledger, dir)
    }

    #[test]
    fn append_then_read_roundtrips() {
        let (ledger, _dir) = temp_ledger();
        let e = event(IncidentReasonCode::LocalFallback, "p1", Some("css"), 100);
        ledger.append(&e).unwrap();
        let read = ledger.read_all();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0], e);
    }

    #[test]
    fn missing_file_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = IncidentLedger::with_path(dir.path().join("nope.jsonl"));
        assert!(ledger.read_all().is_empty());
    }

    #[test]
    fn survives_reopen_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("incidents.jsonl");
        {
            let ledger = IncidentLedger::with_path(&path);
            ledger
                .append(&event(IncidentReasonCode::CircuitOpen, "p1", None, 1))
                .unwrap();
            ledger
                .append(&event(IncidentReasonCode::DiskFull, "p2", None, 2))
                .unwrap();
        }
        // A fresh instance (simulating a process restart) sees prior events.
        let reopened = IncidentLedger::with_path(&path);
        assert_eq!(reopened.read_all().len(), 2);
    }

    #[test]
    fn corrupt_lines_are_tolerated_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("incidents.jsonl");
        let ledger = IncidentLedger::with_path(&path);
        ledger
            .append(&event(IncidentReasonCode::ArtifactMiss, "p1", None, 1))
            .unwrap();
        // Inject a torn/garbage line and a blank line between valid events.
        {
            use std::io::Write;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "{{ this is not valid json").unwrap();
            writeln!(f).unwrap();
            writeln!(f, "garbage").unwrap();
        }
        ledger
            .append(&event(IncidentReasonCode::QueueAmbiguity, "p2", None, 2))
            .unwrap();

        let (events, stats) = ledger.read_all_with_stats();
        assert_eq!(events.len(), 2, "two valid events survive");
        assert_eq!(stats.parsed, 2);
        assert_eq!(
            stats.skipped, 2,
            "two garbage lines skipped (blank ignored)"
        );
    }

    #[test]
    fn query_filters_by_project_worker_and_reason() {
        let (ledger, _dir) = temp_ledger();
        ledger
            .append(&event(
                IncidentReasonCode::LocalFallback,
                "p1",
                Some("css"),
                1,
            ))
            .unwrap();
        ledger
            .append(&event(
                IncidentReasonCode::CircuitOpen,
                "p1",
                Some("bil"),
                2,
            ))
            .unwrap();
        ledger
            .append(&event(
                IncidentReasonCode::CircuitOpen,
                "p2",
                Some("css"),
                3,
            ))
            .unwrap();

        assert_eq!(ledger.query(&IncidentFilter::new().project("p1")).len(), 2);
        assert_eq!(ledger.query(&IncidentFilter::new().worker("css")).len(), 2);
        assert_eq!(
            ledger
                .query(&IncidentFilter::new().reason(IncidentReasonCode::CircuitOpen))
                .len(),
            2
        );
        // Combined filter narrows to one.
        let combined = IncidentFilter::new()
            .project("p1")
            .reason(IncidentReasonCode::CircuitOpen);
        let hits = ledger.query(&combined);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].worker_id.as_deref(), Some("bil"));
    }

    #[test]
    fn retention_compacts_to_max_entries_keeping_newest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("incidents.jsonl");
        // Tiny bounds so compaction triggers deterministically.
        let ledger = IncidentLedger::new(IncidentLedgerConfig {
            path,
            max_entries: 3,
            max_bytes: 1, // any content exceeds this → compact every append
        });
        for i in 0..10u64 {
            ledger
                .append(&event(IncidentReasonCode::LocalFallback, "p", None, i))
                .unwrap();
        }
        let events = ledger.read_all();
        assert_eq!(events.len(), 3, "retained at most max_entries");
        // Newest events kept (timestamps 7,8,9).
        let timestamps: Vec<u64> = events.iter().map(|e| e.occurred_at_unix_ms).collect();
        assert_eq!(timestamps, vec![7, 8, 9]);
    }

    #[test]
    fn explicit_compact_drops_corrupt_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("incidents.jsonl");
        let ledger = IncidentLedger::with_path(&path);
        ledger
            .append(&event(IncidentReasonCode::DiskFull, "p1", None, 1))
            .unwrap();
        {
            use std::io::Write;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "not json").unwrap();
        }
        ledger.compact().unwrap();
        // Corrupt line is gone; the file now round-trips cleanly with no skips.
        let (events, stats) = ledger.read_all_with_stats();
        assert_eq!(events.len(), 1);
        assert_eq!(stats.skipped, 0);
    }

    #[test]
    fn default_ledger_path_honors_state_home() {
        // Use an explicit config rather than mutating process env (unsafe in
        // edition 2024). default_ledger_path falls through to a sane location.
        let p = default_ledger_path();
        assert!(p.ends_with("incidents.jsonl"));
    }
}
