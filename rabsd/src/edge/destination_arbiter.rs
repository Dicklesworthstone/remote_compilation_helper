//! Per-build destination-path reservations + disjoint-bundle
//! materialization concurrency (bead D031; invariant I45; risk R98).
//!
//! Materialization writes into a subscriber's real target tree, and two
//! bundles installing into overlapping paths — or one replacing the
//! parent directory of another's files — corrupt silently. The
//! destination arbiter makes ownership explicit BEFORE any byte lands:
//!
//! - a bundle reserves EVERY declared output path all-or-nothing;
//! - reservations conflict on equality OR ancestry (a parent-directory
//!   replacement is an overlap, not a technicality);
//! - disjoint bundles install fully concurrently;
//! - conflicting bundles serialize behind the holder (or the caller
//!   bypasses) — and an install to a path the bundle never declared is
//!   a typed refusal, not a write;
//! - atomic swaps are authorized per OWNED file/subtree only — swapping
//!   an unrelated shared target root is unrepresentable because
//!   authorization only ever names a reserved path.
//!
//! Names are compared in one lexical Unix path namespace: repeated
//! separators and `.` do not create independent destinations. Parent
//! traversal is NEVER collapsed through a possible symlink and cannot
//! authorize an install. Unresolved claims conservatively overlap, rather
//! than manufacturing concurrency from an ambiguous spelling. Callers still
//! own filesystem containment, symlink/case-alias policy, and directory
//! mutation fencing; this arbiter is not a filesystem sandbox.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Identity of one materialization bundle (per-operation).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BundleId(pub String);

/// Typed reservation refusal.
///
/// Paths are BYTES, not `String`. A destination on Unix is an arbitrary
/// byte sequence, and the reservation identity has to be exactly as
/// discriminating as the filesystem is: keying on a lossy UTF-8 decode
/// collapsed every destination that differed only in invalid bytes onto
/// one key, so two concurrent serves writing genuinely different files
/// conflicted with each other (bd-1rofg). The direction was safe — a
/// false refusal, never a false authorization — but the refusal named a
/// path that was not the path anyone asked for, because the U+FFFD
/// substitution is what had made them look identical.
///
/// It also contradicted T026/R89, whose fixtures assert byte equality
/// with no lossy decode anywhere in the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationConflict {
    /// The requested path that overlapped.
    pub path: Vec<u8>,
    /// The path already reserved that it overlaps with.
    pub reserved: Vec<u8>,
    /// Who holds it.
    pub holder: BundleId,
}

/// Typed install refusal: the bundle never declared this destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndeclaredWrite {
    /// The offending destination, as bytes (see [`ReservationConflict`]).
    pub path: Vec<u8>,
}

/// What an authorized install may atomically replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// Exactly the owned file.
    OwnedFile,
    /// The owned subtree (e.g. one build script's OUT_DIR) — may swap
    /// whole via the D025 replacement semantics.
    OwnedSubtree,
}

/// Lock the shared arbiter, recovering from poisoning.
///
/// A panic anywhere can poison this mutex, but what it guards is a map
/// of path strings — there is no invariant a panic could have left
/// half-applied. Treating poison as a hard failure turned one unrelated
/// panic into a permanent, whole-daemon serving outage, reported to the
/// caller as a STORE error, which is both fatal and misleading.
fn lock(arbiter: &Mutex<DestinationArbiter>) -> MutexGuard<'_, DestinationArbiter> {
    arbiter.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A held reservation that releases when it drops.
///
/// Reservations have no owner liveness, no expiry and no reclaim: one
/// lives until someone calls [`DestinationArbiter::release`] with the
/// same [`BundleId`], and the ids are minted from a counter that only
/// advances. So an exit between reserving and releasing that skipped the
/// release — an unwind, a `?` added later on the wrong side of it —
/// stranded those paths for the process's lifetime, held by a bundle
/// that no longer exists, and every later serve into them (or any
/// overlapping path, since conflicts include ancestry) was refused
/// naming a phantom holder.
///
/// Making the release a `Drop` moves that from a property of one
/// function's control flow to a property of the type: unwinding
/// reclaims the paths for free.
#[derive(Debug)]
pub struct ReservationGuard<'a> {
    arbiter: &'a Mutex<DestinationArbiter>,
    bundle: BundleId,
}

impl ReservationGuard<'_> {
    /// The bundle whose reservation this guard holds.
    #[must_use]
    pub const fn bundle(&self) -> &BundleId {
        &self.bundle
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        lock(self.arbiter).release(&self.bundle);
    }
}

/// Reserve every declared destination for `bundle`, all-or-nothing, and
/// hold the reservation until the returned guard drops.
///
/// This is the only reservation path callers should use; it cannot leak
/// the way a manual reserve/release pair can.
///
/// # Errors
/// [`ReservationConflict`] when any path overlaps another bundle's
/// reservation. A refused reservation holds nothing.
pub fn reserve_scoped<'a>(
    arbiter: &'a Mutex<DestinationArbiter>,
    bundle: BundleId,
    paths: &[Vec<u8>],
) -> Result<ReservationGuard<'a>, ReservationConflict> {
    lock(arbiter).reserve(&bundle, paths)?;
    Ok(ReservationGuard { arbiter, bundle })
}

/// A lexical identity, without filesystem access or lossy path rewriting.
/// An empty component list names `/` or the relative root `.`; those are
/// real subtree claims, not prefixes that happen to contain no characters.
struct Destination<'a> {
    absolute: bool,
    components: Vec<&'a [u8]>,
}

fn destination(path: &[u8]) -> Option<Destination<'_>> {
    if path.is_empty() || path.contains(&0) {
        return None;
    }
    let mut components = Vec::new();
    for component in path.split(|b| *b == b'/') {
        match component {
            b"" | b"." => {}
            b".." => return None,
            component => components.push(component),
        }
    }
    Some(Destination {
        absolute: path.first() == Some(&b'/'),
        components,
    })
}

/// Whether two claims can overlap. Unknown identities and mixed
/// absolute/relative namespaces are conservative conflicts: resolving the
/// latter requires the caller's working-directory identity, which this
/// operation-independent arbiter must not guess from the daemon's cwd.
fn overlaps(a: &[u8], b: &[u8]) -> bool {
    let (Some(a), Some(b)) = (destination(a), destination(b)) else {
        return true;
    };
    a.absolute != b.absolute
        || a.components.starts_with(&b.components)
        || b.components.starts_with(&a.components)
}

/// The per-operation destination arbiter.
#[derive(Debug, Default)]
pub struct DestinationArbiter {
    reserved: BTreeMap<Vec<u8>, BundleId>,
}

impl DestinationArbiter {
    /// New empty arbiter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve every declared destination for `bundle`, all-or-nothing:
    /// one overlap refuses the WHOLE reservation (the caller serializes
    /// behind the named holder or bypasses).
    ///
    /// An unresolved name claims conservatively against every other bundle
    /// until released, but can NEVER authorize an install. Reserving is not
    /// validation or permission to write: use `authorize_install` before
    /// installing, in addition to the caller's filesystem containment checks.
    pub fn reserve(
        &mut self,
        bundle: &BundleId,
        paths: &[Vec<u8>],
    ) -> Result<(), ReservationConflict> {
        for path in paths {
            for (reserved, holder) in &self.reserved {
                if holder != bundle && overlaps(path, reserved) {
                    return Err(ReservationConflict {
                        path: path.clone(),
                        reserved: reserved.clone(),
                        holder: holder.clone(),
                    });
                }
            }
        }
        for path in paths {
            self.reserved.insert(path.clone(), bundle.clone());
        }
        Ok(())
    }

    /// Release every reservation held by `bundle`.
    pub fn release(&mut self, bundle: &BundleId) {
        self.reserved.retain(|_, holder| holder != bundle);
    }

    /// Authorize one install destination for `bundle`: the path must be
    /// (inside) a reservation the bundle holds. The returned scope is
    /// what may be atomically replaced — always an OWNED path, so a
    /// shared-root swap cannot be expressed.
    pub fn authorize_install(
        &self,
        bundle: &BundleId,
        path: impl AsRef<[u8]>,
    ) -> Result<InstallScope, UndeclaredWrite> {
        let path = path.as_ref();
        let denied = || UndeclaredWrite {
            path: path.to_vec(),
        };
        let requested = destination(path).ok_or_else(denied)?;
        let mut inside_owned_subtree = false;
        for (reserved, holder) in &self.reserved {
            if holder != bundle {
                continue;
            }
            let Some(reserved) = destination(reserved) else {
                continue;
            };
            if requested.absolute != reserved.absolute {
                continue;
            }
            if requested.components == reserved.components {
                return Ok(InstallScope::OwnedSubtree);
            }
            if requested.components.starts_with(&reserved.components) {
                // Keep looking: an explicitly owned child subtree must not
                // be downgraded just because its ancestor sorts first.
                inside_owned_subtree = true;
            }
        }
        if inside_owned_subtree {
            Ok(InstallScope::OwnedFile)
        } else {
            Err(denied())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(name: &str) -> BundleId {
        BundleId(name.to_string())
    }
    fn paths(list: &[&str]) -> Vec<Vec<u8>> {
        list.iter().map(|s| s.as_bytes().to_vec()).collect()
    }
    /// The byte form of a path literal, for comparing against the
    /// `Vec<u8>` a refusal carries. Named `pb` rather than `b` because
    /// several tests bind a `BundleId` called `b`.
    fn pb(path: &str) -> Vec<u8> {
        path.as_bytes().to_vec()
    }

    #[test]
    fn equivalent_spellings_share_ownership_and_conflict_identity() {
        let spellings = [
            "target/debug/build/x/out",
            "./target//debug/build/x/out/",
            "target/./debug/build/x/./out",
        ];
        for owned in spellings {
            let mut arbiter = DestinationArbiter::new();
            let owner = bundle("owner");
            arbiter.reserve(&owner, &paths(&[owned])).unwrap();
            for alias in spellings {
                let error = arbiter
                    .reserve(&bundle("other"), &paths(&[alias]))
                    .unwrap_err();
                assert_eq!(error.path, pb(alias));
                assert_eq!(
                    error.reserved,
                    pb(owned),
                    "retain caller spelling for diagnostics"
                );
                assert_eq!(error.holder, owner);
                assert_eq!(
                    arbiter.authorize_install(&owner, alias),
                    Ok(InstallScope::OwnedSubtree)
                );
                assert_eq!(
                    arbiter.authorize_install(&owner, format!("{alias}/gen.rs")),
                    Ok(InstallScope::OwnedFile)
                );
            }
        }
    }

    #[test]
    fn parent_traversal_and_invalid_names_never_authorize_writes() {
        let mut arbiter = DestinationArbiter::new();
        let owner = bundle("owner");
        arbiter.reserve(&owner, &paths(&["target/out"])).unwrap();
        for path in [
            "target/out/../unowned.rs",
            "target/out/sub/../../unowned.rs",
            "target/out/sub/../within.rs",
            "target/out/..",
            "target/out/\0injected",
            "",
            "target/output/file.rs",
            "/target/out/file.rs",
        ] {
            assert_eq!(
                arbiter.authorize_install(&owner, path),
                Err(UndeclaredWrite { path: pb(path) }),
                "{path:?}"
            );
        }
        // Dot-prefixed ordinary names are not traversal.
        assert_eq!(
            arbiter.authorize_install(&owner, "target/out/.cache/.../file"),
            Ok(InstallScope::OwnedFile)
        );
    }

    #[test]
    fn ambiguous_claims_cannot_authorize_or_manufacture_disjointness() {
        for bad in ["", "target/out/..", "target/\0out"] {
            let mut arbiter = DestinationArbiter::new();
            let owner = bundle("owner");
            let other = bundle("other");
            arbiter.reserve(&owner, &paths(&[bad])).unwrap();
            assert!(arbiter.authorize_install(&owner, bad).is_err());
            assert!(arbiter.authorize_install(&owner, "target/file").is_err());
            assert!(
                arbiter
                    .reserve(&other, &paths(&["elsewhere/file"]))
                    .is_err()
            );
            arbiter.release(&owner);
            arbiter
                .reserve(&other, &paths(&["elsewhere/file"]))
                .unwrap();
            assert!(arbiter.reserve(&owner, &paths(&[bad])).is_err());
        }
    }

    #[test]
    fn destinations_differing_only_in_invalid_utf8_are_distinct_reservations() {
        // bd-1rofg. These two paths are different files. Under a lossy
        // decode they were the SAME reservation key, because
        // `to_string_lossy` maps every invalid byte to U+FFFD — so
        // "target/out/\xff" and "target/out/\xfe" both became
        // "target/out/\u{FFFD}" and the second serve was refused,
        // naming a path neither caller had asked for.
        let first = b"target/out/\xff".to_vec();
        let second = b"target/out/\xfe".to_vec();
        assert_ne!(first, second, "the fixture must be two different files");
        assert_eq!(
            String::from_utf8_lossy(&first),
            String::from_utf8_lossy(&second),
            "and they must be indistinguishable under the decode this replaced, \
             or the test is not exercising the bug"
        );

        let mut arbiter = DestinationArbiter::new();
        let (a, b) = (bundle("a"), bundle("b"));
        arbiter.reserve(&a, std::slice::from_ref(&first)).unwrap();
        arbiter
            .reserve(&b, std::slice::from_ref(&second))
            .expect("two genuinely different files must not conflict");

        // And each bundle owns exactly its own, so the byte identity
        // reaches authorization too and not just the conflict check.
        assert_eq!(
            arbiter.authorize_install(&a, &first),
            Ok(InstallScope::OwnedSubtree)
        );
        assert_eq!(
            arbiter.authorize_install(&b, &second),
            Ok(InstallScope::OwnedSubtree)
        );
        assert_eq!(
            arbiter.authorize_install(&a, &second),
            Err(UndeclaredWrite {
                path: second.clone()
            }),
            "a bundle must not gain a neighbour's path by sharing a lossy spelling"
        );

        // The genuine overlap still refuses: identical bytes conflict.
        let conflict = arbiter
            .reserve(&bundle("c"), std::slice::from_ref(&first))
            .unwrap_err();
        assert_eq!(conflict.path, first);
        assert_eq!(conflict.holder, a);
    }

    #[test]
    fn root_claims_cover_descendants_in_both_reservation_orders() {
        for (root, child) in [("/", "/target/out"), (".", "target/out")] {
            assert!(overlaps(root.as_bytes(), child.as_bytes()));
            assert!(overlaps(child.as_bytes(), root.as_bytes()));
            let mut arbiter = DestinationArbiter::new();
            let owner = bundle("owner");
            arbiter.reserve(&owner, &paths(&[root])).unwrap();
            assert!(arbiter.reserve(&bundle("other"), &paths(&[child])).is_err());
            assert_eq!(
                arbiter.authorize_install(&owner, child),
                Ok(InstallScope::OwnedFile)
            );
            assert_eq!(
                arbiter.authorize_install(&owner, root),
                Ok(InstallScope::OwnedSubtree)
            );
        }
    }

    #[test]
    fn aliases_refuse_the_whole_bundle_without_stealing_free_paths() {
        let mut arbiter = DestinationArbiter::new();
        let owner = bundle("owner");
        let other = bundle("other");
        arbiter.reserve(&owner, &paths(&["/target/out"])).unwrap();
        let requested = paths(&["/target/free", "/target/./out//file"]);
        assert!(arbiter.reserve(&other, &requested).is_err());
        assert!(arbiter.authorize_install(&other, "/target/free").is_err());
        // Do not invent a relationship between relative names and the
        // edge daemon's cwd; ambiguity is a conflict, not a disjoint grant.
        assert!(
            arbiter
                .reserve(&other, &paths(&["target/out/file"]))
                .is_err()
        );
        arbiter.release(&owner);
        arbiter.reserve(&other, &requested).unwrap();
        assert!(arbiter.authorize_install(&other, "/target/free").is_ok());
    }

    #[test]
    fn exact_child_reservation_keeps_subtree_scope_beneath_owned_parent() {
        let mut arbiter = DestinationArbiter::new();
        let owner = bundle("owner");
        arbiter
            .reserve(&owner, &paths(&["target/out", "target/out/nested"]))
            .unwrap();
        assert_eq!(
            arbiter.authorize_install(&owner, "./target/out/nested/"),
            Ok(InstallScope::OwnedSubtree)
        );
        assert_eq!(
            arbiter.authorize_install(&owner, "target/out/nested/file"),
            Ok(InstallScope::OwnedFile)
        );
    }

    #[test]
    fn two_bundle_overlap_fixture_serializes() {
        // THE T031 overlap acceptance: bundle B overlaps bundle A on
        // one path — B's WHOLE reservation refuses (all-or-nothing),
        // naming the holder to serialize behind; after A releases, B
        // reserves cleanly.
        let mut arbiter = DestinationArbiter::new();
        let a = bundle("op-a");
        let b = bundle("op-b");
        arbiter
            .reserve(
                &a,
                &paths(&["target/debug/deps/libx.rmeta", "target/debug/build/x/out"]),
            )
            .unwrap();
        let conflict = arbiter
            .reserve(
                &b,
                &paths(&[
                    "target/debug/deps/liby.rmeta",
                    "target/debug/build/x/out/gen.rs",
                ]),
            )
            .unwrap_err();
        assert_eq!(conflict.holder, a);
        assert_eq!(conflict.reserved, pb("target/debug/build/x/out"));
        // All-or-nothing: B's NON-overlapping path was not reserved.
        assert!(matches!(
            arbiter.authorize_install(&b, "target/debug/deps/liby.rmeta"),
            Err(UndeclaredWrite { .. })
        ));
        arbiter.release(&a);
        arbiter
            .reserve(
                &b,
                &paths(&[
                    "target/debug/deps/liby.rmeta",
                    "target/debug/build/x/out/gen.rs",
                ]),
            )
            .unwrap();
    }

    #[test]
    fn parent_directory_replacement_is_an_overlap() {
        let mut arbiter = DestinationArbiter::new();
        arbiter
            .reserve(&bundle("a"), &paths(&["target/debug/build/x/out/gen.rs"]))
            .unwrap();
        // Reserving the PARENT (to replace it) overlaps the child.
        let err = arbiter
            .reserve(&bundle("b"), &paths(&["target/debug/build/x/out"]))
            .unwrap_err();
        assert_eq!(err.reserved, pb("target/debug/build/x/out/gen.rs"));
        // Sibling with a shared name PREFIX (not ancestry) is fine.
        arbiter
            .reserve(&bundle("b"), &paths(&["target/debug/build/x/output"]))
            .unwrap();
    }

    #[test]
    fn undeclared_writes_are_typed_refusals_and_scopes_are_owned_only() {
        let mut arbiter = DestinationArbiter::new();
        let a = bundle("a");
        arbiter
            .reserve(&a, &paths(&["target/debug/build/x/out"]))
            .unwrap();
        // The owned subtree root may swap whole (D025 semantics)…
        assert_eq!(
            arbiter.authorize_install(&a, "target/debug/build/x/out"),
            Ok(InstallScope::OwnedSubtree)
        );
        // …files inside it install as owned files…
        assert_eq!(
            arbiter.authorize_install(&a, "target/debug/build/x/out/gen.rs"),
            Ok(InstallScope::OwnedFile)
        );
        // …and anything undeclared — including the shared target root
        // ABOVE the reservation — refuses. A shared-root swap cannot be
        // authorized because authorization only names reserved paths.
        for undeclared in ["target/debug", "target", "target/debug/deps/libz.rlib"] {
            assert!(
                matches!(
                    arbiter.authorize_install(&a, undeclared),
                    Err(UndeclaredWrite { .. })
                ),
                "{undeclared}"
            );
        }
    }

    #[test]
    fn disjoint_bundles_install_concurrently() {
        // THE T031 disjoint acceptance: 8 real threads, disjoint
        // reservations, all reserve WITHOUT conflict and install
        // concurrently; a barrier proves they were in-flight together
        // rather than serialized.
        use std::sync::{Arc, Barrier, Mutex};
        let arbiter = Arc::new(Mutex::new(DestinationArbiter::new()));
        let root = Arc::new(tempfile::tempdir().unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let arbiter = Arc::clone(&arbiter);
                let root = Arc::clone(&root);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let me = bundle(&format!("op-{i}"));
                    let mine = format!("target/debug/build/crate-{i}/out").into_bytes();
                    arbiter
                        .lock()
                        .unwrap()
                        .reserve(&me, std::slice::from_ref(&mine))
                        .expect("disjoint bundles must not conflict");
                    // Everyone holds a reservation at the same moment.
                    barrier.wait();
                    let scope = arbiter.lock().unwrap().authorize_install(&me, &mine);
                    assert_eq!(scope, Ok(InstallScope::OwnedSubtree));
                    // The reservation key is bytes; the real filesystem
                    // takes those same bytes, with no decode in between.
                    use std::os::unix::ffi::OsStrExt;
                    let dir = root.path().join(std::ffi::OsStr::from_bytes(&mine));
                    std::fs::create_dir_all(&dir).unwrap();
                    std::fs::write(dir.join("gen.rs"), b"x").unwrap();
                    arbiter.lock().unwrap().release(&me);
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        for i in 0..8 {
            assert!(
                root.path()
                    .join(format!("target/debug/build/crate-{i}/out/gen.rs"))
                    .exists()
            );
        }
    }

    #[test]
    fn a_panic_holding_a_reservation_releases_it_instead_of_stranding_the_path() {
        // bd-v9ho1. Reservations have no owner liveness, no expiry and
        // no reclaim, and bundle ids only ever advance — so before the
        // guard, an unwind between reserving and releasing left the path
        // held forever by a bundle that no longer existed, and every
        // later serve into it was refused naming a phantom.
        let arbiter = Mutex::new(DestinationArbiter::new());
        let path = paths(&["target/debug/build/crate-0/out"]);

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = reserve_scoped(&arbiter, bundle("doomed"), &path).expect("reserved");
            assert!(
                !lock(&arbiter).reserved.is_empty(),
                "precondition: the reservation is actually held here"
            );
            panic!("the holder dies mid-install");
        }));
        assert!(panicked.is_err(), "the fixture must really have unwound");

        // The path is free: a later bundle takes it without conflict.
        assert!(
            lock(&arbiter).reserved.is_empty(),
            "an unwind must reclaim the reservation, not strand it"
        );
        reserve_scoped(&arbiter, bundle("next"), &path)
            .expect("a path freed by unwinding must be reservable again");
    }

    #[test]
    fn a_poisoned_arbiter_still_serves_rather_than_failing_every_reservation() {
        // The other half. A panic while the lock was held poisoned the
        // mutex, after which every reserve failed and every release was
        // silently skipped — one unrelated panic took serving out
        // permanently. What the lock guards is a map of path strings,
        // with no invariant a panic can leave half-applied, so poison is
        // recovered rather than treated as corruption.
        let arbiter = Mutex::new(DestinationArbiter::new());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = arbiter.lock().unwrap();
            panic!("poison it");
        }));
        assert!(
            arbiter.is_poisoned(),
            "the fixture must really have poisoned"
        );

        let path = paths(&["target/debug/build/crate-1/out"]);
        let held = reserve_scoped(&arbiter, bundle("after-poison"), &path)
            .expect("a poisoned arbiter must still reserve");
        drop(held);
        assert!(
            lock(&arbiter).reserved.is_empty(),
            "release must work through poisoning too"
        );
    }
}
