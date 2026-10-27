//! One capture per exact package observation, shared by foreground and warm callers.
//!
//! The source walk remains fresh on every request. Only the subsequent sealed
//! capture and hashing are singleflight: a changed source/generated tree gets a
//! different reservation, never the previous generation's failure or pending
//! state. Reservations are local observation ownership, NOT action authority.
//! Byte and entry pressure evict cold completed observations, not the entire
//! ready cache. Recency is process-local policy, never input or key evidence.
//! A large cold request reserves shared warm capacity BEFORE entry eviction;
//! a saturated warmer cannot consume useful cache state without doing work.

use super::{
    DependencySourceKind, FactsMiss, FileSig, GeneratedObservation, LiveFacts, MAX_PACKAGE_BYTES,
    MAX_PACKAGE_FILES, MAX_RETAINED_PACKAGE_BYTES, MAX_WARMING, MemberSig, PROBE_RETRY,
    PackageFacts, PackageKey, SYNCHRONOUS_PACKAGE_BYTES, WarmPermit, capture_package,
    observe_generated, walk_package,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

/// Bound pending, ready AND failed observations, including superseded generations.
const MAX_PACKAGE_MEMOS: usize = 128;

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct Observation {
    key: PackageKey,
    root_identity: (u64, u64),
    members: Vec<(String, MemberSig)>,
    generated: Option<GeneratedObservation>,
    bytes: u64,
}

fn root_identity(root: &Path) -> Result<(u64, u64), String> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if !metadata.is_dir() {
        return Err("package root is not a real directory".into());
    }
    let signature = FileSig::of(&metadata);
    Ok((signature.dev, signature.ino))
}

impl Observation {
    fn read(
        root: &Path,
        source_kind: DependencySourceKind,
        generated_root: Option<&Path>,
    ) -> Result<Self, String> {
        let identity = root_identity(root)?;
        let (members, source_bytes) = walk_package(root, source_kind)?;
        let (generated, generated_bytes) = match generated_root {
            Some(root) => {
                let (observation, bytes) = observe_generated(root)?;
                (Some(observation), bytes)
            }
            None => (None, 0),
        };
        let bytes = source_bytes
            .checked_add(generated_bytes)
            .ok_or("package observation byte count overflow")?;
        if bytes > MAX_PACKAGE_BYTES
            || members.len() + generated.as_ref().map_or(0, |tree| tree.members.len())
                > MAX_PACKAGE_FILES
        {
            return Err("combined source and generated inputs exceed capture bounds".into());
        }
        if root_identity(root)? != identity {
            return Err("package root changed during observation".into());
        }
        Ok(Self {
            key: (
                root.to_path_buf(),
                source_kind,
                generated_root.map(Path::to_path_buf),
            ),
            root_identity: identity,
            members,
            generated,
            bytes,
        })
    }

    fn capture(&self) -> Result<PackageFacts, String> {
        capture_package(&self.key.0, self.key.1, self.key.2.as_deref())
    }

    fn matches_capture(&self, captured: &PackageFacts) -> Result<(), String> {
        if captured.source_kind != self.key.1
            || captured.members != self.members
            || captured.generated != self.generated
            || captured.bytes != self.bytes
            || root_identity(&self.key.0)? != self.root_identity
        {
            return Err("package capture does not match its admitted observation".into());
        }
        captured.verify_unchanged(&self.key.0)
    }
}

#[derive(Debug)]
pub(super) enum PackageSlot {
    Warming(Arc<()>),
    Ready {
        captured: Arc<PackageFacts>,
        last_used: Instant,
    },
    Failed {
        reason: String,
        at: Instant,
    },
}

impl PackageSlot {
    /// Called only after a fresh complete Observation matched this memo key.
    /// Touching retention policy cannot extend a file-generation witness.
    fn reuse(&mut self, now: Instant) -> Option<Result<Arc<PackageFacts>, FactsMiss>> {
        match self {
            Self::Ready {
                captured,
                last_used,
            } => {
                *last_used = (*last_used).max(now);
                Some(Ok(Arc::clone(captured)))
            }
            Self::Warming(_) => Some(Err(FactsMiss::Pending)),
            Self::Failed { reason, at } if now.saturating_duration_since(*at) < PROBE_RETRY => {
                Some(Err(FactsMiss::Refused(reason.clone())))
            }
            Self::Failed { .. } => None,
        }
    }

    fn eviction_rank(&self, now: Instant) -> Option<(u8, Instant)> {
        match self {
            // Expired negative observations no longer provide backoff value.
            Self::Failed { at, .. } if now.saturating_duration_since(*at) >= PROBE_RETRY => {
                Some((0, *at))
            }
            Self::Ready { last_used, .. } => Some((1, *last_used)),
            // Preserve a live backoff while there is an ordinary cache victim.
            // With only failures left, evict the oldest rather than preventing
            // unrelated packages from entering the bounded observation cache.
            Self::Failed { at, .. } => Some((2, *at)),
            Self::Warming(_) => None,
        }
    }
}

pub(super) type PackageMemos = HashMap<Arc<Observation>, PackageSlot>;

/// A token fences even a retry of the identical observation after eviction.
struct Reservation {
    facts: Arc<LiveFacts>,
    observation: Arc<Observation>,
    token: Arc<()>,
}

impl Reservation {
    fn insert(
        facts: &Arc<LiveFacts>,
        memos: &mut PackageMemos,
        observation: Arc<Observation>,
    ) -> Self {
        let token = Arc::new(());
        memos.insert(
            Arc::clone(&observation),
            PackageSlot::Warming(Arc::clone(&token)),
        );
        Self {
            facts: Arc::clone(facts),
            observation,
            token,
        }
    }

    fn owns(&self, memos: &PackageMemos) -> bool {
        matches!(memos.get(&self.observation),
            Some(PackageSlot::Warming(token)) if Arc::ptr_eq(token, &self.token))
    }

    fn finish(
        self,
        captured: Result<PackageFacts, String>,
        retain_failure: bool,
    ) -> Result<Arc<PackageFacts>, FactsMiss> {
        // All filesystem validation stays OUTSIDE the memo mutex.
        let captured = captured
            .and_then(|captured| {
                self.observation.matches_capture(&captured)?;
                Ok(Arc::new(captured))
            })
            .map_err(FactsMiss::Refused);
        {
            let mut memos = self
                .facts
                .packages
                .lock()
                .map_err(|_| FactsMiss::Refused("package memo poisoned".into()))?;
            if !self.owns(&memos) {
                return Err(FactsMiss::Pending);
            }
            match &captured {
                Ok(captured) => {
                    if make_byte_room(&mut memos, captured.bytes, MAX_RETAINED_PACKAGE_BYTES) {
                        memos.insert(
                            Arc::clone(&self.observation),
                            PackageSlot::Ready {
                                captured: Arc::clone(captured),
                                last_used: Instant::now(),
                            },
                        );
                    }
                    // An unretainable result is still returned to its caller.
                    // Drop removes our reservation, not a successor's entry.
                }
                Err(FactsMiss::Refused(reason)) if retain_failure => {
                    memos.insert(
                        Arc::clone(&self.observation),
                        PackageSlot::Failed {
                            reason: reason.clone(),
                            at: Instant::now(),
                        },
                    );
                }
                Err(_) => {}
            }
        }
        captured
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut memos) = self.facts.packages.lock()
            && self.owns(&memos)
        {
            memos.remove(&self.observation);
        }
    }
}

/// Bound memo-held snapshot bytes BEFORE insertion. Evicted snapshots held by
/// subscribers remain alive; this is not a global process-memory bound. Active
/// captures are never evicted and therefore never lose their singleflight owner.
fn make_byte_room(memos: &mut PackageMemos, incoming: u64, limit: u64) -> bool {
    let Some(available) = limit.checked_sub(incoming) else {
        return false;
    };
    let Some(mut retained) = memos.values().try_fold(0_u64, |total, slot| match slot {
        PackageSlot::Ready { captured, .. } => total.checked_add(captured.bytes),
        _ => Some(total),
    }) else {
        return false;
    };
    if retained <= available {
        return true;
    }
    // The map has at most MAX_PACKAGE_MEMOS entries. Sort once only under
    // pressure and evict oldest-first until this insertion actually fits.
    let mut victims: Vec<_> = memos
        .iter()
        .filter_map(|(observation, slot)| match slot {
            PackageSlot::Ready {
                captured,
                last_used,
            } if captured.bytes != 0 => Some((*last_used, Arc::clone(observation))),
            _ => None,
        })
        .collect();
    victims.sort_unstable_by_key(|(last_used, _)| *last_used);
    for (_, observation) in victims {
        if retained <= available {
            break;
        }
        if let Some(PackageSlot::Ready { captured, .. }) = memos.remove(&observation) {
            retained -= captured.bytes;
        }
    }
    retained <= available
}

/// Reserve an entry without flushing all completed observations. Retrying an
/// expired failure for this SAME key replaces its slot and needs no eviction.
/// Pending captures remain unevictable even if they are the oldest entries.
fn make_entry_room(memos: &mut PackageMemos, incoming: &Arc<Observation>, now: Instant) -> bool {
    if memos.contains_key(incoming) {
        return true;
    }
    while memos.len() >= MAX_PACKAGE_MEMOS {
        let victim = memos
            .iter()
            .filter_map(|(observation, slot)| {
                slot.eviction_rank(now)
                    .map(|rank| (rank, Arc::clone(observation)))
            })
            .min_by_key(|(rank, _)| *rank);
        let Some((_, victim)) = victim else {
            return false;
        };
        memos.remove(&victim);
    }
    true
}

/// Reuse LiveFacts' ONE warm counter and its existing affine release owner.
/// The package memo lock precedes this short counter lock; neither is held
/// during capture, thread creation, or filesystem validation. Other warm
/// producers release the counter lock before entering any observation work.
fn reserve_warm(facts: &Arc<LiveFacts>) -> Option<WarmPermit> {
    let mut warming = facts.warming.lock().ok()?;
    if *warming >= MAX_WARMING {
        return None;
    }
    *warming += 1;
    Some(WarmPermit {
        facts: Arc::clone(facts),
    })
}

pub(super) fn observe(
    facts: &Arc<LiveFacts>,
    root: &Path,
    source_kind: DependencySourceKind,
    generated_root: Option<&Path>,
) -> Result<Arc<PackageFacts>, FactsMiss> {
    observe_with(
        facts,
        root,
        source_kind,
        generated_root,
        Observation::capture,
    )
}

fn observe_with(
    facts: &Arc<LiveFacts>,
    root: &Path,
    source_kind: DependencySourceKind,
    generated_root: Option<&Path>,
    capture: impl FnOnce(&Observation) -> Result<PackageFacts, String> + Send + 'static,
) -> Result<Arc<PackageFacts>, FactsMiss> {
    let observation =
        Arc::new(Observation::read(root, source_kind, generated_root).map_err(FactsMiss::Refused)?);
    let (reservation, warm) = {
        let mut memos = facts
            .packages
            .lock()
            .map_err(|_| FactsMiss::Refused("package memo poisoned".into()))?;
        let now = Instant::now();
        if let Some(result) = memos.get_mut(&observation).and_then(|slot| slot.reuse(now)) {
            return result;
        }
        // Ready hits and existing flights never need another warm permit.
        // For a new large capture, refusal must precede cache mutation, not
        // evict a ready snapshot then discover the shared warmer is full.
        let warm = if observation.bytes > SYNCHRONOUS_PACKAGE_BYTES {
            let Some(permit) = reserve_warm(facts) else {
                return Err(FactsMiss::Pending);
            };
            Some(permit)
        } else {
            None
        };
        // Check and insert are one critical section for BOTH capture paths.
        if !make_entry_room(&mut memos, &observation, now) {
            return Err(FactsMiss::Pending);
        }
        (
            Reservation::insert(facts, &mut memos, Arc::clone(&observation)),
            warm,
        )
    };
    let Some(permit) = warm else {
        return reservation.finish(capture(&observation), false);
    };
    // Do not reacquire capacity after evicting. The existing WarmPermit owns
    // accounting until capture/finish unwinds or returns. A failed thread
    // start drops this unstarted closure and both exact reservation owners.
    let _ = std::thread::Builder::new()
        .name("rabs-facts-warm".to_owned())
        .spawn(move || {
            let _permit = permit;
            let _ = reservation.finish(capture(&observation), true);
        });
    Err(FactsMiss::Pending)
}

#[cfg(test)]
mod tests;
