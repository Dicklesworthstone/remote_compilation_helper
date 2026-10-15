//! One capture per exact package observation, shared by foreground and warm callers.
//!
//! The source walk remains fresh on every request. Only the subsequent sealed
//! capture and hashing are singleflight: a changed source/generated tree gets a
//! different reservation, never the previous generation's failure or pending
//! state. Reservations are local observation ownership, NOT action authority.

use super::{
    DependencySourceKind, FactsMiss, FileSig, GeneratedObservation, LiveFacts, MAX_PACKAGE_BYTES,
    MAX_PACKAGE_FILES, MAX_RETAINED_PACKAGE_BYTES, MemberSig, PROBE_RETRY, PackageFacts, PackageKey,
    SYNCHRONOUS_PACKAGE_BYTES, capture_package, observe_generated, walk_package,
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
    Ready(Arc<PackageFacts>),
    Failed { reason: String, at: Instant },
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
                    make_byte_room(&mut memos, captured.bytes, MAX_RETAINED_PACKAGE_BYTES);
                    memos.insert(
                        Arc::clone(&self.observation),
                        PackageSlot::Ready(Arc::clone(captured)),
                    );
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
fn make_byte_room(memos: &mut PackageMemos, incoming: u64, limit: u64) {
    let retained = memos.values().fold(0_u64, |total, slot| match slot {
        PackageSlot::Ready(facts) => total.saturating_add(facts.bytes),
        _ => total,
    });
    if retained.saturating_add(incoming) > limit {
        memos.retain(|_, slot| !matches!(slot, PackageSlot::Ready(_)));
    }
}

pub(super) fn observe(
    facts: &Arc<LiveFacts>,
    root: &Path,
    source_kind: DependencySourceKind,
    generated_root: Option<&Path>,
) -> Result<Arc<PackageFacts>, FactsMiss> {
    observe_with(facts, root, source_kind, generated_root, Observation::capture)
}

fn observe_with(
    facts: &Arc<LiveFacts>,
    root: &Path,
    source_kind: DependencySourceKind,
    generated_root: Option<&Path>,
    capture: impl FnOnce(&Observation) -> Result<PackageFacts, String> + Send + 'static,
) -> Result<Arc<PackageFacts>, FactsMiss> {
    let observation = Arc::new(
        Observation::read(root, source_kind, generated_root).map_err(FactsMiss::Refused)?,
    );
    let reservation = {
        let mut memos = facts
            .packages
            .lock()
            .map_err(|_| FactsMiss::Refused("package memo poisoned".into()))?;
        match memos.get(&observation) {
            Some(PackageSlot::Ready(captured)) => return Ok(Arc::clone(captured)),
            Some(PackageSlot::Warming(_)) => return Err(FactsMiss::Pending),
            Some(PackageSlot::Failed { reason, at }) if at.elapsed() < PROBE_RETRY => {
                return Err(FactsMiss::Refused(reason.clone()));
            }
            _ => {}
        }
        // Check and insert are one critical section for BOTH capture paths.
        if memos.len() >= MAX_PACKAGE_MEMOS {
            memos.retain(|_, slot| matches!(slot, PackageSlot::Warming(_)));
        }
        if memos.len() >= MAX_PACKAGE_MEMOS {
            return Err(FactsMiss::Pending);
        }
        Reservation::insert(facts, &mut memos, Arc::clone(&observation))
    };
    if observation.bytes <= SYNCHRONOUS_PACKAGE_BYTES {
        return reservation.finish(capture(&observation), false);
    }
    // Reuse the existing bounded warm pool. If spawn/admission fails, dropping
    // this unstarted closure releases only its own exact reservation token.
    facts.start_warm(move |_| {
        let _ = reservation.finish(capture(&observation), true);
    });
    Err(FactsMiss::Pending)
}

#[cfg(test)]
mod tests;
