//! Full-snapshot vs minimal-closure invalidation scope (bead T014;
//! risk R41; the empirical basis M015's rmeta experiment extends).
//!
//! Two keying schemes over one fixture workspace:
//!
//! - MINIMAL CLOSURE: each action keys exactly its own consumed
//!   files plus the artifact identities of its dependencies (the
//!   F010 projection discipline) — an edit invalidates only the
//!   transitive dependents of the edited file;
//! - FULL SNAPSHOT: each action keys the whole workspace snapshot
//!   root — ANY edit invalidates EVERY action.
//!
//! The fixtures pin the invalidation scope of one-file edits under
//! both schemes and the exact waste factor full-snapshot keying
//! would impose.

use rabs_key::canonical::CanonicalEncoder;
use rabs_key::typed_digest::compute;
use rabs_protocol::result_identity::TypedDigest;

/// The fixture workspace: five files, five actions.
///
/// dep-a(f1) → lib(f2,f3) → {bin(f4), test} ; leaf(f5) independent.
#[derive(Clone)]
struct Workspace {
    /// Content of files f1..f5.
    files: [Vec<u8>; 5],
}

impl Workspace {
    fn base() -> Self {
        Self {
            files: [
                b"fn dep_a() {}".to_vec(),
                b"fn lib_core() {}".to_vec(),
                b"fn lib_util() {}".to_vec(),
                b"fn main() {}".to_vec(),
                b"fn leaf() {}".to_vec(),
            ],
        }
    }

    fn edit(&self, file: usize) -> Self {
        let mut next = self.clone();
        next.files[file].extend_from_slice(b" // edited");
        next
    }

    fn file_digest(&self, file: usize) -> TypedDigest {
        compute("rabs.t014.file", &self.files[file])
    }

    /// The whole-workspace snapshot root (every file folded in).
    fn snapshot_root(&self) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        for f in &self.files {
            enc.bytes(f);
        }
        compute("rabs.t014.snapshot-root", &enc.finish())
    }

    /// MINIMAL-CLOSURE key for action `idx` (0=dep-a, 1=lib, 2=bin,
    /// 3=test, 4=leaf): own files + dependency ARTIFACT identities.
    fn minimal_key(&self, idx: usize) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        match idx {
            0 => {
                enc.bytes(&self.file_digest(0).bytes);
            }
            1 => {
                enc.bytes(&self.file_digest(1).bytes)
                    .bytes(&self.file_digest(2).bytes)
                    .bytes(&self.minimal_key(0).bytes); // dep-a artifact
            }
            2 => {
                enc.bytes(&self.file_digest(3).bytes)
                    .bytes(&self.minimal_key(1).bytes); // lib artifact
            }
            3 => {
                enc.bytes(&self.minimal_key(1).bytes); // test consumes lib
            }
            4 => {
                enc.bytes(&self.file_digest(4).bytes);
            }
            _ => unreachable!("five actions"),
        }
        compute("rabs.t014.minimal-key", &enc.finish())
    }

    /// FULL-SNAPSHOT key for action `idx`: the action name plus the
    /// whole snapshot root.
    fn full_snapshot_key(&self, idx: usize) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        enc.u32(u32::try_from(idx).expect("small"))
            .bytes(&self.snapshot_root().bytes);
        compute("rabs.t014.full-key", &enc.finish())
    }
}

/// Which of the five actions changed keys between two workspaces.
fn invalidated(before: &Workspace, after: &Workspace, minimal: bool) -> Vec<usize> {
    (0..5)
        .filter(|&i| {
            if minimal {
                before.minimal_key(i) != after.minimal_key(i)
            } else {
                before.full_snapshot_key(i) != after.full_snapshot_key(i)
            }
        })
        .collect()
}

#[test]
fn minimal_closures_scope_invalidation_to_dependents() {
    // THE acceptance: one-file edits invalidate exactly the
    // transitive dependents under minimal closures.
    let base = Workspace::base();
    // Edit f1 (dep-a source): dep-a, lib, bin, test — NOT leaf.
    assert_eq!(invalidated(&base, &base.edit(0), true), vec![0, 1, 2, 3]);
    // Edit f3 (a lib source): lib, bin, test.
    assert_eq!(invalidated(&base, &base.edit(2), true), vec![1, 2, 3]);
    // Edit f4 (bin main): bin only.
    assert_eq!(invalidated(&base, &base.edit(3), true), vec![2]);
    // Edit f5 (the independent leaf): leaf only.
    assert_eq!(invalidated(&base, &base.edit(4), true), vec![4]);
    // No edit: nothing invalidates (determinism control).
    assert!(invalidated(&base, &base.clone(), true).is_empty());
}

#[test]
fn full_snapshot_keys_invalidate_everything_on_any_edit() {
    // The R41 waste, pinned: EVERY one-file edit — even the
    // independent leaf — invalidates all five actions.
    let base = Workspace::base();
    for file in 0..5 {
        assert_eq!(
            invalidated(&base, &base.edit(file), false),
            vec![0, 1, 2, 3, 4],
            "full-snapshot keying cannot scope file {file}"
        );
    }
}

#[test]
fn the_waste_factor_is_the_argument_for_minimal_closures() {
    // Quantified on the leaf edit: minimal invalidates 1 action,
    // full-snapshot invalidates 5 — a 5x rebuild waste on this tiny
    // fixture (and unbounded on a real workspace).
    let base = Workspace::base();
    let edited = base.edit(4);
    let minimal_count = invalidated(&base, &edited, true).len();
    let full_count = invalidated(&base, &edited, false).len();
    assert_eq!((minimal_count, full_count), (1, 5));
    // And minimal closures never MISS an invalidation full-snapshot
    // catches for genuinely-dependent actions: the minimal set for
    // every edit is a subset of the full set.
    for file in 0..5 {
        let m = invalidated(&base, &base.edit(file), true);
        let f = invalidated(&base, &base.edit(file), false);
        assert!(m.iter().all(|a| f.contains(a)), "soundness: subset holds");
        assert!(
            !m.is_empty(),
            "the edited file's own action always invalidates"
        );
    }
}
