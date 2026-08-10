//! Build-script OUT_DIR pre/post-state replacement semantics (bead
//! D025; risk R66; plan §28).
//!
//! A build script's OUT_DIR is STATE, not a scratch pile: the run's
//! captured post-state — including what the script DELETED — is the
//! result. Replay therefore installs the complete post-state into a
//! clean private staging directory and atomically swaps it into place.
//! Merging into a stale OUT_DIR is the R66 bug class: a "ghost" file
//! from an earlier run survives the merge, `include!`s resolve to it,
//! and the replayed build silently differs from the clean run it
//! claims to equal. The swap-never-merge rule makes ghosts and missed
//! deletions structurally impossible: the old directory is moved aside
//! whole, never edited.
//!
//! The Cargo-generated OUT_DIR path stays authoritative (D006): this
//! module operates on the hidden backing directory that path maps to.

use std::collections::BTreeMap;

/// A complete OUT_DIR state: relative path → content bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutDirState {
    /// Every file the state contains (paths `/`-separated, relative).
    pub files: BTreeMap<String, Vec<u8>>,
}

impl OutDirState {
    /// Capture a directory's current state (regular files only).
    pub fn capture(root: &std::path::Path) -> std::io::Result<Self> {
        let mut state = Self::default();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    pending.push(entry.path());
                } else {
                    let rel = entry
                        .path()
                        .strip_prefix(root)
                        .expect("walk stays under root")
                        .to_string_lossy()
                        .replace(std::path::MAIN_SEPARATOR, "/");
                    state.files.insert(rel, std::fs::read(entry.path())?);
                }
            }
        }
        Ok(state)
    }
}

/// One build-script run: the observable pre-state (None when the run
/// started from a fresh OUT_DIR) and the authoritative post-state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildScriptRun {
    /// OUT_DIR state before the run, where observable.
    pub pre_state: Option<OutDirState>,
    /// The complete captured result — deletions are expressed by
    /// ABSENCE from this state.
    pub post_state: OutDirState,
}

/// Replay a captured post-state into `out_dir`: stage privately, then
/// swap atomically. Whatever `out_dir` held before — ghosts, files the
/// run deleted, half-states — is moved aside WHOLE (returned as the
/// displaced path for the caller's disposal policy) and never merged.
pub fn replay_post_state(
    out_dir: &std::path::Path,
    post_state: &OutDirState,
) -> std::io::Result<Option<std::path::PathBuf>> {
    let parent = out_dir
        .parent()
        .ok_or_else(|| std::io::Error::other("OUT_DIR must have a parent"))?;
    std::fs::create_dir_all(parent)?;

    // Stage the COMPLETE post-state in a private sibling.
    let staging = parent.join(format!(
        ".rabs-staging-{}",
        std::process::id() // private per-process; contents are the full state
    ));
    if staging.exists() {
        return Err(std::io::Error::other("staging path already in use"));
    }
    std::fs::create_dir(&staging)?;
    for (rel, content) in &post_state.files {
        let path = staging.join(rel);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, content)?;
    }

    // Swap: displace the old directory whole, then rename staging in.
    let displaced = if out_dir.exists() {
        let graveyard = parent.join(format!(".rabs-displaced-{}", std::process::id()));
        std::fs::rename(out_dir, &graveyard)?;
        Some(graveyard)
    } else {
        None
    };
    std::fs::rename(&staging, out_dir)?;
    Ok(displaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(entries: &[(&str, &str)]) -> OutDirState {
        let mut s = OutDirState::default();
        for (path, content) in entries {
            s.files
                .insert((*path).to_string(), content.as_bytes().to_vec());
        }
        s
    }

    fn write(root: &std::path::Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn ghost_file_fixture_replay_equals_a_clean_run() {
        // THE R66 acceptance: a stale OUT_DIR carries a ghost from an
        // earlier run. Replay into the stale dir and a clean install
        // into a fresh dir must observe IDENTICAL state — the ghost
        // cannot survive.
        let post = state(&[("generated.rs", "pub const X: u32 = 2;"), ("marker", "v2")]);

        let stale_root = tempfile::tempdir().unwrap();
        let stale_out = stale_root.path().join("out");
        write(&stale_out, "generated.rs", "pub const X: u32 = 1;"); // outdated
        write(&stale_out, "ghost.rs", "pub const GHOST: bool = true;"); // ghost

        let clean_root = tempfile::tempdir().unwrap();
        let clean_out = clean_root.path().join("out");

        replay_post_state(&stale_out, &post).unwrap();
        replay_post_state(&clean_out, &post).unwrap();

        let replayed = OutDirState::capture(&stale_out).unwrap();
        let clean = OutDirState::capture(&clean_out).unwrap();
        assert_eq!(replayed, clean, "replay must equal a clean run");
        assert!(
            !replayed.files.contains_key("ghost.rs"),
            "the ghost survived: {:?}",
            replayed.files.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            replayed.files["generated.rs"],
            b"pub const X: u32 = 2;".to_vec()
        );
    }

    #[test]
    fn deletion_fixture_absence_in_post_state_deletes_on_replay() {
        // The run DELETED cached.bin (pre had it, post does not).
        let run = BuildScriptRun {
            pre_state: Some(state(&[("cached.bin", "old"), ("keep.rs", "k")])),
            post_state: state(&[("keep.rs", "k")]),
        };
        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("out");
        // The target dir currently holds the PRE state (stale).
        write(&out, "cached.bin", "old");
        write(&out, "keep.rs", "k");

        replay_post_state(&out, &run.post_state).unwrap();
        let observed = OutDirState::capture(&out).unwrap();
        assert!(!observed.files.contains_key("cached.bin"), "deletion lost");
        assert_eq!(observed, run.post_state);
    }

    #[test]
    fn swap_displaces_the_old_state_whole_never_merges() {
        let post = state(&[("new.rs", "n")]);
        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("out");
        write(&out, "old.rs", "o");

        let displaced = replay_post_state(&out, &post).unwrap().unwrap();
        // The old directory still exists, WHOLE, at the displaced path
        // (disposal is the caller's policy — nothing was edited).
        assert_eq!(
            OutDirState::capture(&displaced).unwrap(),
            state(&[("old.rs", "o")])
        );
        assert_eq!(OutDirState::capture(&out).unwrap(), post);
    }

    #[test]
    fn fresh_out_dir_replay_installs_without_displacement() {
        let post = state(&[("a/b/nested.rs", "n")]);
        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("out");
        let displaced = replay_post_state(&out, &post).unwrap();
        assert!(displaced.is_none());
        assert_eq!(OutDirState::capture(&out).unwrap(), post);
    }
}
