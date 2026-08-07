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

use std::collections::BTreeMap;

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
}

impl EditWatcher {
    /// New watcher with a quiet period.
    #[must_use]
    pub const fn new(debounce_ms: u64) -> Self {
        Self {
            debounce_ms,
            changed: BTreeMap::new(),
        }
    }

    /// Observe one event at `now_ms` (caller's monotonic counter).
    pub fn observe(&mut self, event: &FsEvent, now_ms: u64) {
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
                if is_editor_temp(to) {
                    return;
                }
                // Rename-into-place: the temp staging file becomes the
                // target atomically — stable NOW.
                let atomic = is_editor_temp(from) || from != to;
                self.changed.insert(
                    to.clone(),
                    FileState {
                        last_event_ms: now_ms,
                        renamed_into_place: atomic,
                    },
                );
                self.changed.remove(from);
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
}
