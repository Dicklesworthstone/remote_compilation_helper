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

/// The `/`-separated byte key for a relative path inside an OUT_DIR.
///
/// Byte-exact: a path component is an arbitrary byte string on Unix,
/// and this key is what decides whether two captured files are the same
/// file. On Windows `MAIN_SEPARATOR` is `\`, so the separator is
/// normalized to `/` for a stable cross-platform key; on Unix that
/// substitution cannot fire, because `/` is already the separator and
/// no other byte is.
fn relative_key(rel: &std::path::Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        rel.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        rel.to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/")
            .into_bytes()
    }
}

/// A complete OUT_DIR state: relative path → content bytes.
///
/// Relative paths are BYTES. They were `String` via `to_string_lossy`,
/// which maps every invalid UTF-8 byte to U+FFFD — so two files whose
/// names differed only in invalid bytes collapsed to one map key, and
/// the `insert` in [`Self::capture`] silently kept whichever
/// `read_dir` happened to yield last.
///
/// That defeats the premise this module is built on. The captured
/// post-state is supposed to be COMPLETE, with deletions expressed by
/// absence; a collapse makes a file the script actually wrote absent
/// from the state, so the replay omits it and the replayed build
/// silently differs from the clean run it claims to equal. That is the
/// R66 ghost class arriving through capture instead of through a merge,
/// and the swap-never-merge rule cannot prevent it.
///
/// Worse, `read_dir` order is unspecified, so WHICH of the two
/// survived varied run to run — a nondeterministic capture underneath
/// a cache whose whole value is determinism.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutDirState {
    /// Every file the state contains (paths `/`-separated, relative).
    pub files: BTreeMap<Vec<u8>, Vec<u8>>,
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
                    let rel = relative_key(
                        entry
                            .path()
                            .strip_prefix(root)
                            .expect("walk stays under root"),
                    );
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
        // The key is bytes and the filesystem takes bytes, with no
        // decode in between — the same path that was captured is the
        // path that gets written back.
        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStrExt;
            staging.join(std::ffi::OsStr::from_bytes(rel))
        };
        #[cfg(not(unix))]
        let path = staging.join(String::from_utf8_lossy(rel).as_ref());
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
                .insert(path.as_bytes().to_vec(), content.as_bytes().to_vec());
        }
        s
    }

    /// The byte key for a path literal, matching what `capture` records.
    fn k(path: &str) -> Vec<u8> {
        path.as_bytes().to_vec()
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
            !replayed.files.contains_key(&k("ghost.rs")),
            "the ghost survived: {:?}",
            replayed.files.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            replayed.files[&k("generated.rs")],
            b"pub const X: u32 = 2;".to_vec()
        );
    }

    #[cfg(unix)]
    #[test]
    fn two_out_dir_files_differing_only_in_invalid_utf8_both_survive_capture() {
        // The completeness premise, against the one input that used to
        // break it. These are two different files; under the previous
        // `to_string_lossy` key they became one, and whichever
        // `read_dir` yielded last silently won — so the "complete"
        // post-state was missing a file the script had really written,
        // and replay produced a build differing from the clean run.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let first = OsStr::from_bytes(b"gen-\xff.rs");
        let second = OsStr::from_bytes(b"gen-\xfe.rs");
        assert_eq!(
            first.to_string_lossy(),
            second.to_string_lossy(),
            "the fixture must be indistinguishable under the decode this replaced, \
             or it is not exercising the collapse"
        );
        std::fs::write(out.join(first), b"first").unwrap();
        std::fs::write(out.join(second), b"second").unwrap();

        let captured = OutDirState::capture(&out).unwrap();
        assert_eq!(
            captured.files.len(),
            2,
            "both files must be in the state: {:?}",
            captured.files.keys().collect::<Vec<_>>()
        );
        assert_eq!(captured.files[&b"gen-\xff.rs".to_vec()], b"first".to_vec());
        assert_eq!(captured.files[&b"gen-\xfe.rs".to_vec()], b"second".to_vec());

        // And the round trip holds: replaying the captured state into a
        // clean directory reproduces it exactly, which is the property
        // the whole module exists to provide.
        let clean = root.path().join("clean");
        replay_post_state(&clean, &captured).unwrap();
        assert_eq!(
            OutDirState::capture(&clean).unwrap(),
            captured,
            "replay of a non-UTF-8 state must equal the state"
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
        assert!(
            !observed.files.contains_key(&k("cached.bin")),
            "deletion lost"
        );
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
