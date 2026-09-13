//! Filesystem edit watcher with stable-write debounce (bead Q001;
//! plan §104; feeds the Q-series speculation snapshotter).
//!
//! Speculative snapshots must start from a STABLE edit boundary —
//! half a save is worse than no save. The watcher folds raw fs
//! events into per-file states using editor write semantics:
//!
//! - RENAME-INTO-PLACE (VSCode-style atomic save: write `.tmp`, then
//!   rename over the target) is stable IMMEDIATELY — the rename is
//!   atomic, there is nothing to wait for;
//! - plain in-place writes are stable only after `debounce_ms` of
//!   quiet, and every new write RESETS the clock;
//! - editor droppings (`.swp`, `~` backups, vim's `4913` probe,
//!   `.tmp` staging files) are never changed outputs themselves —
//!   a temp path either maps to its rename target or is ignored;
//! - time is a caller-supplied monotonic millisecond counter — the
//!   watcher never reads a clock.

use crate::snapshot_capture::{CaptureError, SealedSourceSnapshot, capture_sealed_source};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Default quiet period for in-place writes (ms).
pub const DEFAULT_DEBOUNCE_MS: u64 = 200;

/// One raw filesystem event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEvent {
    /// File created.
    Create(String),
    /// File written in place.
    Write(String),
    /// Rename `from` → `to`.
    Rename {
        /// Source path.
        from: String,
        /// Destination path.
        to: String,
    },
    /// File removed.
    Remove(String),
}

/// Whether a path is an editor dropping, never a real output.
fn is_editor_temp(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.ends_with(".swp")
        || name.ends_with(".swx")
        || name.ends_with('~')
        || name.ends_with(".tmp")
        || name == "4913" // vim's write-permission probe
        || name.starts_with(".#") // emacs lock
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileState {
    last_event_ms: u64,
    /// Stable immediately (arrived by rename-into-place).
    renamed_into_place: bool,
}

/// The boundary decision at a moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryDecision {
    /// The edit boundary is stable: snapshot these changed files.
    Stable {
        /// Changed real files (sorted; no editor droppings).
        files: Vec<String>,
    },
    /// Still unstable: the file still inside its quiet period.
    Unstable {
        /// The path holding the boundary open.
        settling: String,
    },
}

/// The watcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditWatcher {
    debounce_ms: u64,
    changed: BTreeMap<String, FileState>,
    generation: u64,
    generation_exhausted: bool,
}

impl EditWatcher {
    /// New watcher with a quiet period.
    #[must_use]
    pub const fn new(debounce_ms: u64) -> Self {
        Self {
            debounce_ms,
            changed: BTreeMap::new(),
            generation: 0,
            generation_exhausted: false,
        }
    }

    /// Observe one event at `now_ms` (caller's monotonic counter).
    pub fn observe(&mut self, event: &FsEvent, now_ms: u64) {
        // Capture membership is broader than editor debounce membership: a
        // legitimate build input may be named input.tmp. Every delivered event
        // invalidates snapshot freshness, even when it does not start work or
        // hold the debounce boundary open. This can abandon extra speculative
        // work during editor noise; it cannot authorize stale captured inputs.
        if let Some(next) = self.generation.checked_add(1) {
            self.generation = next;
        } else {
            // Never let a wrapped generation validate an old capture ticket.
            self.generation_exhausted = true;
        }
        match event {
            FsEvent::Create(path) | FsEvent::Write(path) => {
                if is_editor_temp(path) {
                    return; // droppings never become outputs
                }
                let state = self.changed.entry(path.clone()).or_insert(FileState {
                    last_event_ms: now_ms,
                    renamed_into_place: false,
                });
                state.last_event_ms = now_ms;
                state.renamed_into_place = false; // a new write re-opens
            }
            FsEvent::Rename { from, to } => {
                if is_editor_temp(from) && is_editor_temp(to) {
                    return;
                }
                // Both visible endpoints changed atomically. Moving a real
                // source to an editor backup also invalidates a capture, even
                // before the editor writes the replacement source.
                for path in [from, to] {
                    if !is_editor_temp(path) {
                        self.changed.insert(
                            path.clone(),
                            FileState {
                                last_event_ms: now_ms,
                                renamed_into_place: from != to,
                            },
                        );
                    }
                }
            }
            FsEvent::Remove(path) => {
                // A removed temp is noise; a removed real file is a
                // change that settles like a write.
                if is_editor_temp(path) {
                    return;
                }
                self.changed.insert(
                    path.clone(),
                    FileState {
                        last_event_ms: now_ms,
                        renamed_into_place: false,
                    },
                );
            }
        }
    }

    /// Decide the boundary at `now_ms`.
    #[must_use]
    pub fn boundary(&self, now_ms: u64) -> BoundaryDecision {
        for (path, state) in &self.changed {
            let settled = state.renamed_into_place
                || now_ms.saturating_sub(state.last_event_ms) >= self.debounce_ms;
            if !settled {
                return BoundaryDecision::Unstable {
                    settling: path.clone(),
                };
            }
        }
        BoundaryDecision::Stable {
            files: self.changed.keys().cloned().collect(),
        }
    }

    /// Consume the settled change set (after a snapshot was taken).
    pub fn drain(&mut self) {
        self.changed.clear();
    }
}

/// A capture started at one stable edit boundary. Its identity is private so
/// another watcher or a late completion cannot publish into this watcher.
#[derive(Debug, Clone)]
pub struct SnapshotTicket {
    origin: Arc<()>,
    generation: u64,
    serial: u64,
}

impl SnapshotTicket {
    /// Capture fresh bytes for this ticket. Keeping the image and ticket
    /// together prevents publication of an image captured before the ticket.
    pub fn capture(
        self,
        roots: &[(String, PathBuf)],
        declared_git_state: bool,
        max_attempts: u32,
        max_bytes: u64,
    ) -> Result<CapturedSpeculation, CaptureError> {
        let source = capture_sealed_source(roots, declared_git_state, max_attempts, max_bytes)?;
        Ok(CapturedSpeculation {
            ticket: self,
            source,
        })
    }
}

/// Fresh captured bytes bound to the ticket that requested their capture.
/// Only [`SnapshotTicket::capture`] constructs this publication candidate.
#[derive(Debug)]
pub struct CapturedSpeculation {
    ticket: SnapshotTicket,
    source: SealedSourceSnapshot,
}

/// Why a speculative capture cannot begin yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotStartRefusal {
    /// No unacknowledged source changes remain.
    NoChanges,
    /// An in-place write has not settled.
    Unstable { settling: String },
    /// A monotonic identity counter cannot advance without wrapping.
    CounterExhausted,
}

/// Why captured bytes must not become the current speculative source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotAbandonReason {
    /// An observed source edit invalidated the capture boundary.
    Edited,
    /// A newer capture began, or this ticket already completed.
    Superseded,
    /// This ticket belongs to a different watcher.
    ForeignWatcher,
}

impl SnapshotAbandonReason {
    /// Existing protocol reason for edit-driven abandonment.
    #[must_use]
    pub const fn reason_code(self) -> Option<&'static str> {
        match self {
            Self::Edited => Some("SPECULATION_SUPERSEDED_BY_EDIT"),
            Self::Superseded | Self::ForeignWatcher => None,
        }
    }
}

/// Completion of a speculative capture. Only `Published` acknowledges edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotPublication {
    /// The image became current; earlier handles still own their sealed bytes.
    Published { superseded_previous: bool },
    /// The image was discarded and pending edits were left intact.
    Abandoned(SnapshotAbandonReason),
}

#[derive(Debug)]
struct PublishedSnapshot {
    generation: u64,
    source: Arc<SealedSourceSnapshot>,
}

/// Couples stable edit boundaries to actual sealed source images (Q003).
///
/// The caller starts a ticket, calls [`SnapshotTicket::capture`], then finishes
/// the captured candidate.
/// Filesystem events may continue arriving between those steps. A newer edit
/// invalidates the ticket without draining that edit, and a late completion
/// cannot replace a newer image. Capturing bytes still performs its own coherent
/// filesystem scans; watcher events alone are not snapshot proof.
///
/// Explicit user commands call `capture_sealed_source` afresh, independently of
/// this speculative state and its debounce. This component does not run a
/// filesystem event service or substitute cached speculation for that boundary.
#[derive(Debug)]
pub struct SpeculativeSnapshotter {
    watcher: EditWatcher,
    identity: Arc<()>,
    last_serial: u64,
    active_serial: Option<u64>,
    latest: Option<PublishedSnapshot>,
}

impl SpeculativeSnapshotter {
    /// Create an empty snapshotter with the requested write debounce.
    #[must_use]
    pub fn new(debounce_ms: u64) -> Self {
        Self {
            watcher: EditWatcher::new(debounce_ms),
            identity: Arc::new(()),
            last_serial: 0,
            active_serial: None,
            latest: None,
        }
    }

    /// Observe an edit; previously returned image handles retain their bytes.
    pub fn observe(&mut self, event: &FsEvent, now_ms: u64) {
        self.watcher.observe(event, now_ms);
    }

    /// Inspect pending edits without acknowledging them.
    #[must_use]
    pub fn boundary(&self, now_ms: u64) -> BoundaryDecision {
        self.watcher.boundary(now_ms)
    }

    /// Start a capture only after a nonempty change set has settled.
    /// Starting a newer capture supersedes any older unfinished ticket.
    pub fn begin_snapshot(&mut self, now_ms: u64) -> Result<SnapshotTicket, SnapshotStartRefusal> {
        if self.watcher.generation_exhausted {
            return Err(SnapshotStartRefusal::CounterExhausted);
        }
        match self.watcher.boundary(now_ms) {
            BoundaryDecision::Unstable { settling } => {
                return Err(SnapshotStartRefusal::Unstable { settling });
            }
            BoundaryDecision::Stable { files } if files.is_empty() => {
                return Err(SnapshotStartRefusal::NoChanges);
            }
            BoundaryDecision::Stable { .. } => {}
        }
        let serial = self
            .last_serial
            .checked_add(1)
            .ok_or(SnapshotStartRefusal::CounterExhausted)?;
        self.last_serial = serial;
        self.active_serial = Some(serial);
        Ok(SnapshotTicket {
            origin: Arc::clone(&self.identity),
            generation: self.watcher.generation,
            serial,
        })
    }

    /// Publish captured bytes only if this ticket still owns the edit boundary.
    /// On capture error callers simply omit this step; the edits remain pending.
    pub fn finish_snapshot(&mut self, captured: CapturedSpeculation) -> SnapshotPublication {
        let CapturedSpeculation { ticket, source } = captured;
        let abandoned = if !Arc::ptr_eq(&ticket.origin, &self.identity) {
            Some(SnapshotAbandonReason::ForeignWatcher)
        } else if self.watcher.generation_exhausted || ticket.generation != self.watcher.generation
        {
            Some(SnapshotAbandonReason::Edited)
        } else if self.active_serial != Some(ticket.serial) {
            Some(SnapshotAbandonReason::Superseded)
        } else {
            None
        };
        if let Some(reason) = abandoned {
            return SnapshotPublication::Abandoned(reason);
        }
        let superseded_previous = self.latest.is_some();
        self.latest = Some(PublishedSnapshot {
            generation: ticket.generation,
            source: Arc::new(source),
        });
        self.active_serial = None;
        self.watcher.drain();
        SnapshotPublication::Published {
            superseded_previous,
        }
    }

    /// The published image, only while no later source edit has been observed.
    /// Clone its `Arc` to retain old bytes across later edits and supersession.
    #[must_use]
    pub fn current(&self) -> Option<&Arc<SealedSourceSnapshot>> {
        self.latest
            .as_ref()
            .filter(|image| {
                !self.watcher.generation_exhausted && image.generation == self.watcher.generation
            })
            .map(|image| &image.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watcher() -> EditWatcher {
        EditWatcher::new(DEFAULT_DEBOUNCE_MS)
    }

    #[test]
    fn vscode_atomic_save_is_stable_immediately() {
        // THE VSCode fixture: write the staging file, rename it over
        // the target — stable at once, and the .tmp never appears.
        let mut w = watcher();
        w.observe(&FsEvent::Create("src/lib.rs.tmp".into()), 1_000);
        w.observe(&FsEvent::Write("src/lib.rs.tmp".into()), 1_001);
        w.observe(
            &FsEvent::Rename {
                from: "src/lib.rs.tmp".into(),
                to: "src/lib.rs".into(),
            },
            1_002,
        );
        assert_eq!(
            w.boundary(1_002),
            BoundaryDecision::Stable {
                files: vec!["src/lib.rs".into()],
            },
            "rename-into-place needs no quiet period"
        );
    }

    #[test]
    fn vim_save_sequence_produces_one_clean_boundary() {
        // THE vim fixture: probe 4913, backup to ~, write the real
        // file, remove the backup — the boundary settles to exactly
        // the real file after the quiet period.
        let mut w = watcher();
        w.observe(&FsEvent::Create("src/4913".into()), 2_000);
        w.observe(&FsEvent::Remove("src/4913".into()), 2_001);
        w.observe(
            &FsEvent::Rename {
                from: "src/main.rs".into(),
                to: "src/main.rs~".into(),
            },
            2_002,
        );
        w.observe(&FsEvent::Create("src/main.rs".into()), 2_003);
        w.observe(&FsEvent::Write("src/main.rs".into()), 2_004);
        w.observe(&FsEvent::Remove("src/main.rs~".into()), 2_005);
        // Mid-sequence: unstable (main.rs still settling).
        assert_eq!(
            w.boundary(2_010),
            BoundaryDecision::Unstable {
                settling: "src/main.rs".into(),
            }
        );
        // After the quiet period: exactly the real file, no probe, no
        // backup.
        assert_eq!(
            w.boundary(2_004 + DEFAULT_DEBOUNCE_MS),
            BoundaryDecision::Stable {
                files: vec!["src/main.rs".into()],
            }
        );
    }

    #[test]
    fn plain_writes_debounce_and_each_write_resets_the_clock() {
        let mut w = watcher();
        w.observe(&FsEvent::Write("a.rs".into()), 0);
        w.observe(&FsEvent::Write("a.rs".into()), 50);
        w.observe(&FsEvent::Write("a.rs".into()), 100);
        // One ms short of quiet: unstable.
        assert!(matches!(
            w.boundary(100 + DEFAULT_DEBOUNCE_MS - 1),
            BoundaryDecision::Unstable { .. }
        ));
        // Quiet reached — measured from the LAST write, not the first.
        assert_eq!(
            w.boundary(100 + DEFAULT_DEBOUNCE_MS),
            BoundaryDecision::Stable {
                files: vec!["a.rs".into()],
            }
        );
        // A later write re-opens the boundary.
        w.observe(&FsEvent::Write("a.rs".into()), 400);
        assert!(matches!(w.boundary(410), BoundaryDecision::Unstable { .. }));
    }

    #[test]
    fn editor_droppings_never_hold_or_join_the_boundary() {
        // A .swp churn session: no real files changed, so the
        // boundary is trivially stable and EMPTY.
        let mut w = watcher();
        w.observe(&FsEvent::Create("src/.main.rs.swp".into()), 0);
        w.observe(&FsEvent::Write("src/.main.rs.swp".into()), 10);
        w.observe(&FsEvent::Write("src/.main.rs.swp".into()), 20);
        assert_eq!(
            w.boundary(21),
            BoundaryDecision::Stable { files: vec![] },
            "swap-file churn is not an edit"
        );
        // Emacs lock + backup: same.
        w.observe(&FsEvent::Create("src/.#main.rs".into()), 30);
        w.observe(&FsEvent::Write("src/main.rs~".into()), 31);
        assert_eq!(w.boundary(32), BoundaryDecision::Stable { files: vec![] });
    }

    #[test]
    fn drain_consumes_the_boundary_for_the_snapshotter() {
        let mut w = watcher();
        w.observe(&FsEvent::Write("a.rs".into()), 0);
        assert!(matches!(
            w.boundary(DEFAULT_DEBOUNCE_MS),
            BoundaryDecision::Stable { .. }
        ));
        w.drain();
        assert_eq!(
            w.boundary(DEFAULT_DEBOUNCE_MS + 1),
            BoundaryDecision::Stable { files: vec![] },
            "the snapshot took the change set"
        );
    }

    fn source_tree() -> tempfile::TempDir {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("main.rs"), "fn main() { /* old */ }\n").unwrap();
        source
    }

    fn roots(source: &tempfile::TempDir) -> Vec<(String, PathBuf)> {
        vec![("workspace".to_string(), source.path().to_path_buf())]
    }

    #[test]
    fn edit_before_publication_abandons_capture_without_consuming_new_edits() {
        let source = source_tree();
        let roots = roots(&source);
        let mut snapshots = SpeculativeSnapshotter::new(DEFAULT_DEBOUNCE_MS);
        snapshots.observe(&FsEvent::Write("main.rs".into()), 0);
        let captured = snapshots
            .begin_snapshot(DEFAULT_DEBOUNCE_MS)
            .unwrap()
            .capture(&roots, false, 3, 4096)
            .unwrap();
        // A real edit lands after the bytes were sealed but before publication.
        std::fs::write(source.path().join("main.rs"), "fn main() { /* new */ }\n").unwrap();
        snapshots.observe(&FsEvent::Write("main.rs".into()), 201);
        assert_eq!(
            snapshots.finish_snapshot(captured),
            SnapshotPublication::Abandoned(SnapshotAbandonReason::Edited)
        );
        assert!(snapshots.current().is_none());
        assert!(matches!(
            snapshots.begin_snapshot(202),
            Err(SnapshotStartRefusal::Unstable { .. })
        ));
        assert_eq!(
            snapshots.boundary(401),
            BoundaryDecision::Stable {
                files: vec!["main.rs".into()]
            }
        );

        // An explicit command does not wait for speculation's debounce and
        // cannot reuse the discarded image: it captures the current filesystem.
        let authoritative = capture_sealed_source(&roots, false, 3, 4096).unwrap();
        assert_eq!(
            authoritative.file_bytes("workspace", "main.rs"),
            Some(b"fn main() { /* new */ }\n".as_slice())
        );
        assert!(matches!(
            snapshots.boundary(202),
            BoundaryDecision::Unstable { .. }
        ));
        let code = SnapshotAbandonReason::Edited.reason_code().unwrap();
        assert!(rabs_protocol::reason_codes::lookup(code).is_some());
    }

    #[test]
    fn supersession_preserves_old_bytes_and_rejects_late_completion() {
        let source = source_tree();
        let roots = roots(&source);
        let mut snapshots = SpeculativeSnapshotter::new(0);
        snapshots.observe(&FsEvent::Write("main.rs".into()), 0);
        let first_ticket = snapshots.begin_snapshot(0).unwrap();
        let late = first_ticket
            .clone()
            .capture(&roots, false, 3, 4096)
            .unwrap();
        let first = first_ticket.capture(&roots, false, 3, 4096).unwrap();
        assert_eq!(
            snapshots.finish_snapshot(first),
            SnapshotPublication::Published {
                superseded_previous: false
            }
        );
        let old = Arc::clone(snapshots.current().unwrap());
        assert!(matches!(
            snapshots.begin_snapshot(1),
            Err(SnapshotStartRefusal::NoChanges)
        ));

        std::fs::write(source.path().join("main.rs"), "fn main() { /* new */ }\n").unwrap();
        snapshots.observe(&FsEvent::Write("main.rs".into()), 1);
        assert!(
            snapshots.current().is_none(),
            "old image is no longer current"
        );
        let next = snapshots
            .begin_snapshot(1)
            .unwrap()
            .capture(&roots, false, 3, 4096)
            .unwrap();
        assert_eq!(
            snapshots.finish_snapshot(next),
            SnapshotPublication::Published {
                superseded_previous: true
            }
        );
        let current = Arc::clone(snapshots.current().unwrap());
        assert_ne!(old.closure_digest(), current.closure_digest());
        assert_eq!(
            old.file_bytes("workspace", "main.rs"),
            Some(b"fn main() { /* old */ }\n".as_slice())
        );
        assert_eq!(
            current.file_bytes("workspace", "main.rs"),
            Some(b"fn main() { /* new */ }\n".as_slice())
        );
        assert_eq!(
            snapshots.finish_snapshot(late),
            SnapshotPublication::Abandoned(SnapshotAbandonReason::Edited)
        );
        assert!(Arc::ptr_eq(snapshots.current().unwrap(), &current));
    }

    #[test]
    fn newer_ticket_supersedes_an_unfinished_capture_at_the_same_generation() {
        let source = source_tree();
        let roots = roots(&source);
        let mut snapshots = SpeculativeSnapshotter::new(0);
        snapshots.observe(&FsEvent::Write("main.rs".into()), 0);
        let old = snapshots
            .begin_snapshot(0)
            .unwrap()
            .capture(&roots, false, 3, 4096)
            .unwrap();
        let newest = snapshots.begin_snapshot(0).unwrap();
        let duplicate = newest.clone().capture(&roots, false, 3, 4096).unwrap();
        let captured = newest.capture(&roots, false, 3, 4096).unwrap();
        assert_eq!(
            snapshots.finish_snapshot(old),
            SnapshotPublication::Abandoned(SnapshotAbandonReason::Superseded)
        );
        assert!(snapshots.current().is_none());
        assert_eq!(
            snapshots.boundary(0),
            BoundaryDecision::Stable {
                files: vec!["main.rs".into()]
            }
        );
        assert!(matches!(
            snapshots.finish_snapshot(captured),
            SnapshotPublication::Published { .. }
        ));
        let current = Arc::clone(snapshots.current().unwrap());
        assert_eq!(
            snapshots.finish_snapshot(duplicate),
            SnapshotPublication::Abandoned(SnapshotAbandonReason::Superseded)
        );
        assert!(Arc::ptr_eq(snapshots.current().unwrap(), &current));
    }

    #[test]
    fn foreign_ticket_and_capture_errors_never_acknowledge_changes() {
        let source = source_tree();
        let roots = roots(&source);
        let mut first = SpeculativeSnapshotter::new(0);
        let mut second = SpeculativeSnapshotter::new(0);
        first.observe(&FsEvent::Write("main.rs".into()), 0);
        second.observe(&FsEvent::Write("main.rs".into()), 0);
        let foreign = first
            .begin_snapshot(0)
            .unwrap()
            .capture(&roots, false, 3, 4096)
            .unwrap();
        let own = second.begin_snapshot(0).unwrap();
        assert_eq!(
            second.finish_snapshot(foreign),
            SnapshotPublication::Abandoned(SnapshotAbandonReason::ForeignWatcher)
        );
        assert!(second.current().is_none());
        let missing = vec![("workspace".to_string(), source.path().join("missing"))];
        assert!(own.capture(&missing, false, 3, 4096).is_err());
        assert_eq!(
            second.boundary(0),
            BoundaryDecision::Stable {
                files: vec!["main.rs".into()]
            }
        );
        let retry = second
            .begin_snapshot(0)
            .unwrap()
            .capture(&roots, false, 3, 4096)
            .unwrap();
        assert!(matches!(
            second.finish_snapshot(retry),
            SnapshotPublication::Published { .. }
        ));
    }

    #[test]
    fn visible_rename_endpoints_invalidate_capture_including_editor_backups() {
        let mut watcher = watcher();
        watcher.observe(
            &FsEvent::Rename {
                from: "a.rs".into(),
                to: "b.rs".into(),
            },
            0,
        );
        assert_eq!(
            watcher.boundary(0),
            BoundaryDecision::Stable {
                files: vec!["a.rs".into(), "b.rs".into()]
            }
        );
        watcher.drain();
        watcher.observe(
            &FsEvent::Rename {
                from: "b.rs".into(),
                to: "b.rs~".into(),
            },
            1,
        );
        assert_eq!(
            watcher.boundary(1),
            BoundaryDecision::Stable {
                files: vec!["b.rs".into()]
            }
        );
        watcher.drain();
        watcher.observe(
            &FsEvent::Rename {
                from: "b.rs".into(),
                to: "b.rs".into(),
            },
            2,
        );
        assert!(matches!(
            watcher.boundary(2),
            BoundaryDecision::Unstable { .. }
        ));
        assert_eq!(
            watcher.boundary(202),
            BoundaryDecision::Stable {
                files: vec!["b.rs".into()]
            }
        );

        let source = source_tree();
        let mut snapshots = SpeculativeSnapshotter::new(0);
        snapshots.observe(&FsEvent::Write("main.rs".into()), 0);
        let captured = snapshots
            .begin_snapshot(0)
            .unwrap()
            .capture(&roots(&source), false, 3, 4096)
            .unwrap();
        std::fs::rename(
            source.path().join("main.rs"),
            source.path().join("main.rs~"),
        )
        .unwrap();
        snapshots.observe(
            &FsEvent::Rename {
                from: "main.rs".into(),
                to: "main.rs~".into(),
            },
            1,
        );
        assert_eq!(
            snapshots.finish_snapshot(captured),
            SnapshotPublication::Abandoned(SnapshotAbandonReason::Edited)
        );
    }

    #[test]
    fn captured_temp_named_inputs_invalidate_snapshots_without_starting_new_work() {
        let source = source_tree();
        std::fs::write(source.path().join("input.tmp"), "old input").unwrap();
        let mut snapshots = SpeculativeSnapshotter::new(0);
        snapshots.observe(&FsEvent::Write("main.rs".into()), 0);
        let captured = snapshots
            .begin_snapshot(0)
            .unwrap()
            .capture(&roots(&source), false, 3, 4096)
            .unwrap();
        assert!(matches!(
            snapshots.finish_snapshot(captured),
            SnapshotPublication::Published { .. }
        ));
        let old = Arc::clone(snapshots.current().unwrap());
        assert_eq!(
            old.file_bytes("workspace", "input.tmp"),
            Some(b"old input".as_slice())
        );

        std::fs::write(source.path().join("input.tmp"), "new input").unwrap();
        snapshots.observe(&FsEvent::Write("input.tmp".into()), 1);
        assert!(snapshots.current().is_none());
        assert_eq!(
            snapshots.boundary(1),
            BoundaryDecision::Stable { files: vec![] }
        );
        assert!(matches!(
            snapshots.begin_snapshot(1),
            Err(SnapshotStartRefusal::NoChanges)
        ));
        assert_eq!(
            old.file_bytes("workspace", "input.tmp"),
            Some(b"old input".as_slice())
        );
        let authoritative = capture_sealed_source(&roots(&source), false, 3, 4096).unwrap();
        assert_eq!(
            authoritative.file_bytes("workspace", "input.tmp"),
            Some(b"new input".as_slice())
        );

        snapshots.observe(&FsEvent::Write("main.rs".into()), 2);
        let captured = snapshots
            .begin_snapshot(2)
            .unwrap()
            .capture(&roots(&source), false, 3, 4096)
            .unwrap();
        std::fs::write(source.path().join("input.tmp"), "third input").unwrap();
        snapshots.observe(&FsEvent::Write("input.tmp".into()), 3);
        assert_eq!(
            snapshots.finish_snapshot(captured),
            SnapshotPublication::Abandoned(SnapshotAbandonReason::Edited)
        );
        assert_eq!(
            snapshots.boundary(3),
            BoundaryDecision::Stable {
                files: vec!["main.rs".into()]
            }
        );
    }

    #[test]
    fn exhausted_counters_refuse_instead_of_revalidating_old_tickets() {
        let source = source_tree();
        let mut snapshots = SpeculativeSnapshotter::new(0);
        snapshots.observe(&FsEvent::Write("main.rs".into()), 0);
        let captured = snapshots
            .begin_snapshot(0)
            .unwrap()
            .capture(&roots(&source), false, 3, 4096)
            .unwrap();
        snapshots.watcher.generation = u64::MAX;
        snapshots.observe(&FsEvent::Write("main.rs".into()), 1);
        assert_eq!(
            snapshots.finish_snapshot(captured),
            SnapshotPublication::Abandoned(SnapshotAbandonReason::Edited)
        );
        assert!(matches!(
            snapshots.begin_snapshot(1),
            Err(SnapshotStartRefusal::CounterExhausted)
        ));

        let mut snapshots = SpeculativeSnapshotter::new(0);
        snapshots.observe(&FsEvent::Write("main.rs".into()), 0);
        snapshots.last_serial = u64::MAX;
        assert!(matches!(
            snapshots.begin_snapshot(0),
            Err(SnapshotStartRefusal::CounterExhausted)
        ));
        assert_eq!(
            snapshots.boundary(0),
            BoundaryDecision::Stable {
                files: vec!["main.rs".into()]
            }
        );
    }
}
