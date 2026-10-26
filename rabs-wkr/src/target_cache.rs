//! Optional worker-local Cargo target state, never an action/result cache.
//!
//! Verified inputs may seed a NEW private target directory. Cargo still
//! executes and owns every freshness decision, including build-script tracking.
//! Unchanged inputs retain prior timestamps; eligible source and data edits are
//! made newer than every retained fingerprint before Cargo runs. Output
//! timestamps are preserved, never advanced to manufacture freshness. No seed
//! is mounted writable or linked into an execution. Verified internal aliases
//! are reconstructed only between files of the SAME fresh private clone.
//! The process owns the pool across reconnects. Explicit persistent mode also
//! retains completed generations across restarts under an exclusive disk owner;
//! its operator-supplied runtime epoch must change when host tools/libraries do.

use crate::artifacts::{ArtifactPlan, CapturedArtifacts, MAX_ARTIFACT_BYTES, PreparedArtifacts};
use crate::result_spool::ResultRecipient;
use crate::session::CanonicalExecRequest;
use rabs_sandbox::canonical_namespace::{CanonicalNamespaceSpec, HostIsolationSupport};
use rabs_sandbox::cargo_home::CargoHomeProjection;
use rabs_sandbox::source_transfer::{MAX_SOURCE_BYTES, SourceManifest};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[cfg(target_os = "linux")]
mod persistence;
mod source_edits;

/// Independent count and byte limits bound retained seeds and in-flight staging.
pub const MAX_TARGET_CACHE_ENTRIES: usize = 8;
pub const MAX_TARGET_CACHE_BYTES: u64 = rabs_sandbox::artifact_tree::MAX_PRIVATE_TREE_BYTES;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "target state interrupted",
        ))
    } else {
        Ok(())
    }
}

/// Privacy scope comes from the authenticated connection, not request metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetCacheScope([u8; 32]);

impl TargetCacheScope {
    #[must_use]
    pub fn new(worker: &str, endpoint: &str, recipient: &ResultRecipient) -> Self {
        let recipient = match recipient {
            ResultRecipient::TlsSpki(digest) => {
                format!("tls-spki:{}", crate::source_transfer::hex(digest))
            }
            ResultRecipient::LoopbackFixture => "explicit-loopback-fixture".to_owned(),
        };
        let encoded = serde_json::to_vec(&(worker, endpoint, recipient)).expect("string encoding");
        Self(Sha256::digest(encoded).into())
    }
}

/// Only SourceOwner constructs production inputs after its sealed handoff.
#[derive(Debug, Clone)]
pub(crate) struct WorkspaceInputs {
    pub root: PathBuf,
    pub manifest: SourceManifest,
    pub full_source_digest: [u8; 32],
    // Retain the validated partition, not a caller-supplied cache digest hint.
    // Its original transport and workspace identities are checked before any
    // source-edit normalization; the cache partition always remains exact.
    pub projection: Option<Arc<CargoHomeProjection>>,
    pub runtime_owner: Option<Arc<tempfile::TempDir>>,
}

impl WorkspaceInputs {
    /// SourceReceiver's seal and any Cargo-home projection remain untouched.
    /// Timestamp restoration is permitted only on this independent, verified
    /// runtime copy, whose owner stays live even if optional caching is refused.
    #[cfg(target_os = "linux")]
    pub(crate) fn private_runtime_clone(self, stopped: &impl Fn() -> bool) -> io::Result<Self> {
        self.clone_into(private_directory("rabs-target-workspace-")?, stopped)
    }

    #[cfg(target_os = "linux")]
    fn clone_into(
        self,
        directory: tempfile::TempDir,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        let before = SourceTimes::capture(&self, stopped)?;
        let required = self
            .manifest
            .files()
            .iter()
            .map(|file| file.path.clone())
            .collect();
        let tree = TreeInventory::scan(&self.root, &required, MAX_SOURCE_BYTES, stopped)?;
        copy_tree(&tree, directory.path(), stopped)?;
        let cloned = Self {
            root: directory.path().to_path_buf(),
            runtime_owner: Some(Arc::new(directory)),
            ..self
        };
        if SourceTimes::capture(&cloned, stopped)? != before {
            return Err(invalid(
                "runtime source clone differs from the sealed workspace",
            ));
        }
        Ok(cloned)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn private_runtime_clone(self, _stopped: &impl Fn() -> bool) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TargetKey([u8; 32]);

/// Bind the actual final environment, including the worker-authored grant and
/// private HOME's stable FIFO path. Hidden temporary backing paths are excluded:
/// the compiler sees only these canonical mount destinations.
pub(crate) fn target_key(
    scope: TargetCacheScope,
    request: &CanonicalExecRequest,
    inputs: &WorkspaceInputs,
    spec: &CanonicalNamespaceSpec,
    support: &HostIsolationSupport,
    plan: &ArtifactPlan,
    grant: u32,
) -> io::Result<TargetKey> {
    let value = target_key_description(scope, request, inputs, spec, support, plan, grant)?;
    Ok(TargetKey(
        Sha256::digest(serde_json::to_vec(&value)?).into(),
    ))
}

/// Ordinary Cargo can reuse one private target across build, check and test,
/// including different package and target selections. Clippy uses a separate
/// family and retains every selection and lint control while sharing its own
/// prior targets across source edits.
/// This secondary key never changes action identity or permits result replay:
/// the current command executes with its original argv and artifact contract.
/// Unknown argument forms retain exact-key reuse only.
pub(crate) fn target_compatibility_key(
    scope: TargetCacheScope,
    request: &CanonicalExecRequest,
    inputs: &WorkspaceInputs,
    spec: &CanonicalNamespaceSpec,
    support: &HostIsolationSupport,
    plan: &ArtifactPlan,
    grant: u32,
) -> io::Result<Option<TargetKey>> {
    let Some(args) = compatible_cargo_arguments(request, plan) else {
        return Ok(None);
    };
    let mut value = target_key_description(scope, request, inputs, spec, support, plan, grant)?;
    let clippy = request.program == "/__rabs/toolchain/bin/cargo-clippy";
    value["version"] = serde_json::json!(if clippy {
        "rabs.private-clippy-commands.v1"
    } else {
        "rabs.private-cargo-selections.v1"
    });
    value["args"] = serde_json::json!(args);
    value["cargo_mode"] = serde_json::json!("current-cargo-contract-required-v1");
    if let Some(source) = source_edits::identity(inputs) {
        // This is only a private Cargo seed family, never an action key.
        // Actual changed bytes remain in the exact key and current manifest.
        value["version"] = serde_json::json!(if clippy {
            "rabs.private-clippy-source-edits.v1"
        } else {
            "rabs.private-cargo-selection-source-edits.v1"
        });
        value["source"] = serde_json::json!(source);
        value["workspace"] = serde_json::json!(source);
    }
    Ok(Some(TargetKey(
        Sha256::digest(serde_json::to_vec(&value)?).into(),
    )))
}

fn target_key_description(
    scope: TargetCacheScope,
    request: &CanonicalExecRequest,
    inputs: &WorkspaceInputs,
    spec: &CanonicalNamespaceSpec,
    support: &HostIsolationSupport,
    plan: &ArtifactPlan,
    grant: u32,
) -> io::Result<serde_json::Value> {
    if spec.allows_network() {
        return Err(invalid(
            "target state requires the network-denied canonical namespace",
        ));
    }
    let toolchain = request
        .toolchain_identity
        .ok_or_else(|| invalid("target state requires a pinned toolchain"))?;
    let mut ro: Vec<_> = spec.ro_binds.iter().map(|bind| &bind.visible).collect();
    let mut rw: Vec<_> = spec.rw_binds.iter().map(|bind| &bind.visible).collect();
    ro.sort();
    rw.sort();
    let mut value = serde_json::json!({
        "version":"rabs.private-cargo-target.v1",
        "scope":scope.0,
        "source":inputs.full_source_digest,
        "workspace":inputs.manifest.digest(),
        "projection":inputs.projection.as_ref().map(|home| (home.version(), home.prefix())),
        "toolchain":[crate::source_transfer::hex(&toolchain.sha256), toolchain.files.to_string(), toolchain.bytes.to_string()],
        "program":request.program, "args":request.args,
        "cwd":spec.cwd, "env":spec.env, "hostname":spec.hostname,
        "network":spec.allows_network(), "ro":ro, "rw":rw,
        "bubblewrap":support.bubblewrap, "userns":support.unprivileged_userns,
        "grant":grant, "output":plan.virtual_root(),
        "required":plan.files().collect::<Vec<_>>(),
        "cargo_mode":format!("{:?}", plan.cargo_mode()),
        "runtime":"fresh-home+captured-or-empty-cargo-home+private-fifo-v1",
    });
    if let Some(roots) = plan.private_incremental_roots() {
        // The private tree and the delivered tree have different contracts.
        // Preserve exact identity for existing full-tree requests, and bind
        // the explicitly selected projection for private incremental runs.
        value["cargo_private_incremental_roots"] = serde_json::json!(roots);
    }
    Ok(value)
}

fn compatible_cargo_arguments(
    request: &CanonicalExecRequest,
    plan: &ArtifactPlan,
) -> Option<Vec<String>> {
    rabs_sandbox::cargo_target::compatible_arguments(
        &request.program,
        &request.args,
        plan.cargo_mode()?,
    )
}

#[derive(Debug, Default)]
struct PoolState {
    // Every generation stays charged while a restore holds its shared owner.
    // A replacement may coexist with an in-use predecessor, within both caps.
    entries: VecDeque<Arc<Seed>>,
    retained_bytes: u64,
    reserved_bytes: u64,
    reservations: usize,
}

/// Explicitly configured, process-owned, bounded private Cargo hot state.
#[derive(Debug)]
pub struct TargetCache {
    max_bytes: u64,
    state: Mutex<PoolState>,
    #[cfg(target_os = "linux")]
    storage: Option<Arc<persistence::Storage>>,
}

impl TargetCache {
    /// A zero CLI limit disables the pool before this constructor is called.
    pub fn new(max_bytes: u64) -> io::Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Cargo target state requires Linux",
            ));
        }
        if max_bytes == 0 || max_bytes > MAX_TARGET_CACHE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target cache bytes must be between 1 and 8589934592",
            ));
        }
        Ok(Self {
            max_bytes,
            state: Mutex::new(PoolState::default()),
            #[cfg(target_os = "linux")]
            storage: None,
        })
    }

    /// Retain completed private targets across worker restarts. The epoch is an
    /// explicit operator assertion that the host runtime remains unchanged;
    /// rotate it before changing tools, libraries, headers or other host inputs.
    /// A changed epoch retires old generations within this SAME bounded root.
    /// This never enables action-result reuse or skips the current Cargo command.
    pub fn open_persistent(max_bytes: u64, root: &Path, runtime_epoch: &str) -> io::Result<Self> {
        let cache = Self::new(max_bytes)?;
        #[cfg(target_os = "linux")]
        {
            let (storage, entries) = persistence::Storage::open(root, max_bytes, runtime_epoch)?;
            let retained_bytes = entries.iter().map(|seed| seed.tree.bytes).sum();
            Ok(Self {
                storage: Some(storage),
                state: Mutex::new(PoolState {
                    entries,
                    retained_bytes,
                    ..PoolState::default()
                }),
                ..cache
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (cache, root, runtime_epoch);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "target state requires Linux",
            ))
        }
    }

    /// Take an exact-generation read lease under the pool lock, then copy and
    /// validate outside it. Independent restores never share writable inodes.
    /// A contended lookup remains cold; a large copy no longer holds that lock.
    /// Cold attempts keep the caller-owned sealed workspace read-only. Only a
    /// matching seed needs a private source copy for timestamp restoration;
    /// the returned attempt owns that copy through execution and capture.
    pub(crate) fn acquire(
        self: &Arc<Self>,
        key: TargetKey,
        compatible: Option<TargetKey>,
        mut inputs: WorkspaceInputs,
        new_output: impl FnOnce() -> io::Result<PreparedArtifacts>,
        request_id: u64,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<(TargetAttempt, Option<PreparedArtifacts>)> {
        checkpoint(stopped)?;
        if inputs
            .runtime_owner
            .as_ref()
            .is_some_and(|owner| owner.path() != inputs.root)
        {
            return Err(invalid(
                "target state runtime owner differs from its workspace",
            ));
        }
        let mut times = SourceTimes::capture(&inputs, stopped)?;
        let mut restored = None;
        let mut disposition = "cold";
        let seed = match self.state.try_lock() {
            Ok(state) => state
                .entries
                .iter()
                .rev()
                .find(|seed| seed.key == key && !seed.invalidated.load(Ordering::Acquire))
                .or_else(|| {
                    compatible.and_then(|compatible| {
                        state.entries.iter().rev().find(|seed| {
                            seed.compatible == Some(compatible)
                                && !seed.invalidated.load(Ordering::Acquire)
                        })
                    })
                })
                .cloned(),
            Err(_) => {
                disposition = "cold-pool-busy";
                None
            }
        };
        if let Some(seed) = seed {
            let mut restore_started = false;
            let reuse = (|| {
                // Refuse incompatible edits or an unorderable clock BEFORE
                // copying or invalidating an otherwise usable old generation.
                let restored_times =
                    source_edits::timestamps(&seed, &inputs, SystemTime::now(), stopped)?;
                let output = new_output()?;
                checkpoint(stopped)?;
                // The original SourceReceiver seal must never receive old
                // Cargo timestamps. A miss needs no second source tree;
                // a hit copies and verifies it before changing any times.
                // The exact seed lease stays live throughout this copy.
                let runtime = if inputs.runtime_owner.is_some() {
                    inputs.clone()
                } else {
                    inputs.clone().private_runtime_clone(stopped)?
                };
                restore_started = true;
                seed.tree.restore(output.backing(), stopped)?;
                restored_times.restore(&runtime, stopped)?;
                if seed.invalidated.load(Ordering::Acquire) {
                    return Err(invalid("target seed invalidated during restoration"));
                }
                Ok::<_, io::Error>((output, runtime, restored_times))
            })();
            match reuse {
                Ok((output, runtime, restored_times)) => {
                    times = restored_times;
                    inputs = runtime;
                    restored = Some(output);
                    disposition = if seed.key == key {
                        "restored"
                    } else if seed.source_manifest.digest() != inputs.manifest.digest() {
                        "restored-edited"
                    } else {
                        "restored-compatible"
                    };
                    self.finish_seed_use(seed, true);
                }
                Err(error) => {
                    // Keep the old error policy, but invalidate THIS generation
                    // only. Other readers retain its backing and quota charge;
                    // they cannot make a replacement generation disappear.
                    if restore_started
                        && !matches!(
                            error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
                        )
                    {
                        seed.invalidated.store(true, Ordering::Release);
                    }
                    self.finish_seed_use(seed, false);
                    eprintln!(
                        "{}",
                        serde_json::json!({"kind":"worker-target-state-refused", "request_id":request_id, "error":error.to_string()})
                    );
                    // A stop is terminal, not a reason to prepare a cold
                    // attempt. Release the seed lease above, then preserve the
                    // target-state interruption before shared artifact scans
                    // can replace it with their timeout classification.
                    checkpoint(stopped)?;
                    // No partial target or newly cloned source escapes. A
                    // refused private preparation preserves a valid seed, but
                    // cold execution must still revalidate the original source.
                    times = SourceTimes::capture(&inputs, stopped)?;
                    disposition = "cold-after-refusal";
                }
            }
        }
        eprintln!(
            "{}",
            serde_json::json!({"kind":"worker-target-state", "request_id":request_id, "disposition":disposition, "key_sha256":crate::source_transfer::hex(&key.0)})
        );
        Ok((
            TargetAttempt {
                cache: Arc::clone(self),
                key,
                compatible,
                inputs,
                times,
                request_id,
            },
            restored,
        ))
    }

    fn finish_seed_use(&self, seed: Arc<Seed>, promote: bool) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Some(index) = state
            .entries
            .iter()
            .position(|entry| Arc::ptr_eq(entry, &seed))
        else {
            return;
        };
        let retired =
            seed.invalidated.load(Ordering::Acquire)
                || state.entries.iter().skip(index + 1).any(|newer| {
                    newer.key == seed.key && !newer.invalidated.load(Ordering::Acquire)
                });
        // Drop this reader under the lock before the exclusive ownership test.
        // Removing a leased entry would leave unaccounted live disk backing.
        drop(seed);
        if retired {
            if Arc::get_mut(&mut state.entries[index]).is_some() {
                if state.entries[index].tree.directory.retire().is_err() {
                    // Failed reclamation stays charged; durable storage refuses
                    // further reservations until a successful recovery/reopen.
                    state.entries[index]
                        .invalidated
                        .store(true, Ordering::Release);
                    return;
                }
                let retired = state.entries.remove(index).expect("located generation");
                state.retained_bytes -= retired.tree.bytes;
                drop(retired);
            }
        } else if promote {
            let seed = state.entries.remove(index).expect("located generation");
            state.entries.push_back(seed);
        }
    }

    fn reserve(self: &Arc<Self>, bytes: u64) -> Option<Reservation> {
        if bytes > self.max_bytes {
            return None;
        }
        #[cfg(target_os = "linux")]
        if self
            .storage
            .as_ref()
            .is_some_and(|storage| !storage.healthy())
        {
            return None;
        }
        let mut state = self.state.try_lock().ok()?;
        // Pending copies AND leased generations are non-evictable. Preflight
        // both limits before changing the LRU, so an impossible request cannot
        // destroy unrelated warm entries. Exclusivity checks include Weak refs.
        let mut protected_bytes = state.reserved_bytes;
        let mut protected_entries = state.reservations;
        for seed in &mut state.entries {
            if Arc::get_mut(seed).is_none() {
                protected_bytes = protected_bytes.checked_add(seed.tree.bytes)?;
                protected_entries += 1;
            }
        }
        let available_bytes = self.max_bytes.checked_sub(protected_bytes)?;
        if bytes > available_bytes || protected_entries >= MAX_TARGET_CACHE_ENTRIES {
            return None;
        }
        while state.retained_bytes + state.reserved_bytes + bytes > self.max_bytes
            || state.entries.len() + state.reservations >= MAX_TARGET_CACHE_ENTRIES
        {
            let index = state
                .entries
                .iter_mut()
                .position(|seed| Arc::get_mut(seed).is_some())?;
            if state.entries[index].tree.directory.retire().is_err() {
                state.entries[index]
                    .invalidated
                    .store(true, Ordering::Release);
                return None;
            }
            let seed = state.entries.remove(index)?;
            state.retained_bytes -= seed.tree.bytes;
        }
        state.reserved_bytes += bytes;
        state.reservations += 1;
        Some(Reservation {
            cache: Arc::clone(self),
            bytes,
            active: true,
        })
    }
}

#[derive(Debug)]
struct Reservation {
    cache: Arc<TargetCache>,
    bytes: u64,
    active: bool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.active {
            let mut state = self
                .cache
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.reserved_bytes -= self.bytes;
            state.reservations -= 1;
        }
    }
}

#[derive(Debug)]
struct Seed {
    key: TargetKey,
    compatible: Option<TargetKey>,
    source: SourceTimes,
    source_manifest: SourceManifest,
    edit_family: Option<[u8; 32]>,
    tree: TreeSnapshot,
    invalidated: AtomicBool,
}

/// Staging is not publication. ExecutionControl owns this until its FINAL
/// completed execution frontier, after cancellation, drains and diagnostic
/// checks. Successful commands also require their validated artifact offer.
/// An ordinary Cargo failure may retain private target state, never a result
/// cache hit or successful artifact offer. The observed native exit binds the
/// candidate to that exact completion rather than an interruption or refusal.
#[derive(Debug)]
pub(crate) struct PendingTargetSeed {
    // Drop the owned tree BEFORE releasing its byte/entry reservation, so a
    // cancelled candidate's filesystem cleanup remains inside the pool bound.
    seed: Option<Seed>,
    reservation: Reservation,
    request_id: u64,
    exit_code: i32,
}

impl PendingTargetSeed {
    pub(crate) fn matches_completion(
        &self,
        request_id: u64,
        exit_code: i32,
        artifacts: bool,
    ) -> bool {
        self.request_id == request_id
            && self.exit_code == exit_code
            && (exit_code != 0 || artifacts)
    }

    pub(crate) fn publish(mut self) {
        // The execution's final completion frontier is the ONLY operation that
        // makes a staged disk generation discoverable after restart. Do this
        // before taking the pool mutex: a failed commit drops the reservation,
        // whose destructor takes that same mutex to release its charge.
        if let Err(error) = self
            .seed
            .as_mut()
            .expect("pending snapshot")
            .tree
            .directory
            .publish()
        {
            eprintln!(
                "{}",
                serde_json::json!({
                    "kind":"worker-target-state-persistence-refused",
                    "request_id":self.request_id, "error":error.to_string(),
                })
            );
            return;
        }
        let mut state = self
            .reservation
            .cache
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let seed = self.seed.take().expect("pending seed owns its snapshot");
        // Keep in-use predecessor generations owned and charged. New lookups
        // select the newest non-invalidated generation; its late predecessor
        // is reclaimed only after that predecessor's final reader returns.
        while let Some(index) = state
            .entries
            .iter_mut()
            .position(|prior| prior.key == seed.key && Arc::get_mut(prior).is_some())
        {
            if state.entries[index].tree.directory.retire().is_err() {
                state.entries[index]
                    .invalidated
                    .store(true, Ordering::Release);
                break;
            }
            let prior = state.entries.remove(index).expect("located seed");
            state.retained_bytes -= prior.tree.bytes;
        }
        state.reserved_bytes -= self.reservation.bytes;
        state.reservations -= 1;
        self.reservation.active = false;
        state.retained_bytes += seed.tree.bytes;
        state.entries.push_back(Arc::new(seed));
        eprintln!(
            "{}",
            serde_json::json!({"kind":"worker-target-state-published", "request_id":self.request_id, "seed_bytes":self.reservation.bytes, "retained_bytes":state.retained_bytes, "entries":state.entries.len()})
        );
    }
}

#[derive(Debug)]
pub(crate) struct TargetAttempt {
    cache: Arc<TargetCache>,
    key: TargetKey,
    compatible: Option<TargetKey>,
    inputs: WorkspaceInputs,
    times: SourceTimes,
    request_id: u64,
}

impl TargetAttempt {
    /// Bind the verified private source and target together, never timestamps
    /// from one source view with another target. The caller must retain this
    /// attempt through process cleanup and revalidate the resulting namespace.
    pub(crate) fn bind_restored(
        &self,
        spec: &mut CanonicalNamespaceSpec,
        original: &WorkspaceInputs,
        current: &PreparedArtifacts,
        restored: &PreparedArtifacts,
        plan: &ArtifactPlan,
    ) -> io::Result<()> {
        let owner = self
            .inputs
            .runtime_owner
            .as_ref()
            .filter(|owner| owner.path() == self.inputs.root)
            .ok_or_else(|| invalid("restored Cargo target lacks a private workspace owner"))?;
        if self.inputs.manifest.digest() != original.manifest.digest()
            || self.inputs.full_source_digest != original.full_source_digest
            || self.inputs.projection != original.projection
        {
            return Err(invalid(
                "restored Cargo workspace differs from the admitted source",
            ));
        }
        let visible = PathBuf::from(plan.virtual_root());
        let output_index = spec
            .rw_binds
            .iter()
            .position(|bind| bind.visible == visible && bind.backing == current.backing());
        let workspace_index = spec.ro_binds.iter().position(|bind| {
            bind.visible == Path::new(rabs_sandbox::layout::WORKSPACE)
                && bind.backing == original.root
        });
        let (Some(output_index), Some(workspace_index)) = (output_index, workspace_index) else {
            return Err(invalid(
                "Cargo target or sealed source mount ownership changed",
            ));
        };
        // Both identities must match BEFORE changing either binding. A failed
        // optional restore leaves the original sealed-source/fresh-target view.
        spec.ro_binds[workspace_index].backing = owner.path().to_path_buf();
        spec.rw_binds[output_index].backing = restored.backing().to_path_buf();
        Ok(())
    }

    pub(crate) fn stage(
        self,
        artifacts: &PreparedArtifacts,
        captured: &CapturedArtifacts,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Option<PendingTargetSeed>> {
        if SourceTimes::capture(&self.inputs, stopped)? != self.times {
            return Err(invalid("source changed while Cargo was executing"));
        }
        let Some((reservation, tree)) = TreeSnapshot::capture(
            &self.cache,
            artifacts.backing(),
            artifacts.plan(),
            captured,
            stopped,
        )?
        else {
            return Ok(None);
        };
        if SourceTimes::capture(&self.inputs, stopped)? != self.times {
            return Err(invalid("source changed while capturing Cargo target state"));
        }
        let seed = Seed {
            key: self.key,
            compatible: self.compatible,
            source: self.times,
            edit_family: source_edits::identity(&self.inputs),
            source_manifest: self.inputs.manifest,
            tree,
            invalidated: AtomicBool::new(false),
        };
        seed.tree.directory.prepare(&seed, stopped)?;
        Ok(Some(PendingTargetSeed {
            reservation,
            seed: Some(seed),
            request_id: self.request_id,
            exit_code: 0,
        }))
    }

    /// Preserve a normally exited Cargo command's complete private target even
    /// when a compile or test failed. Cargo's own fingerprints decide reuse on
    /// the next execution. Missing final outputs remain missing; no successful
    /// artifact report or transport offer is constructed for this state.
    /// Bubblewrap may report an inner signal as an ordinary 128+signal exit.
    /// Exclude that entire range as well as direct signal statuses; Cargo's
    /// ordinary compile/test failure (101) remains eligible.
    #[cfg(target_os = "linux")]
    pub(crate) fn stage_failed(
        self,
        artifacts: &PreparedArtifacts,
        status: std::process::ExitStatus,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Option<PendingTargetSeed>> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        let exit_code = status
            .code()
            .filter(|code| (1..128).contains(code))
            .ok_or_else(|| invalid("target state requires a nonzero Cargo exit below 128"))?;
        if artifacts.plan().cargo_mode().is_none() {
            return Err(invalid(
                "failed target state requires a Cargo output contract",
            ));
        }
        if SourceTimes::capture(&self.inputs, stopped)? != self.times {
            return Err(invalid("source changed while Cargo was executing"));
        }
        let inventory = if artifacts.plan().private_incremental_roots().is_some() {
            TreeInventory::scan_complete_private(
                artifacts.backing(),
                MAX_TARGET_CACHE_BYTES,
                stopped,
            )?
        } else {
            TreeInventory::scan_complete(artifacts.backing(), MAX_ARTIFACT_BYTES, stopped)?
        };
        let Some(reservation) = self.cache.reserve(inventory.total_bytes()) else {
            return Ok(None);
        };
        let tree = TreeSnapshot::capture_inventory(&self.cache, &inventory, stopped)?;
        if SourceTimes::capture(&self.inputs, stopped)? != self.times {
            return Err(invalid(
                "source changed while capturing failed Cargo target state",
            ));
        }
        let seed = Seed {
            key: self.key,
            compatible: self.compatible,
            source: self.times,
            edit_family: source_edits::identity(&self.inputs),
            source_manifest: self.inputs.manifest,
            tree,
            invalidated: AtomicBool::new(false),
        };
        seed.tree.directory.prepare(&seed, stopped)?;
        Ok(Some(PendingTargetSeed {
            reservation,
            seed: Some(seed),
            request_id: self.request_id,
            exit_code,
        }))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn stage_failed(
        self,
        _: &PreparedArtifacts,
        _: std::process::ExitStatus,
        _: &impl Fn() -> bool,
    ) -> io::Result<Option<PendingTargetSeed>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceTimes {
    files: BTreeMap<String, SystemTime>,
    directories: BTreeMap<String, StoredDirectory>,
}

#[cfg(target_os = "linux")]
impl SourceTimes {
    fn capture(inputs: &WorkspaceInputs, stopped: &impl Fn() -> bool) -> io::Result<Self> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        use std::os::unix::fs::PermissionsExt;
        let required = inputs
            .manifest
            .files()
            .iter()
            .map(|file| file.path.clone())
            .collect();
        let tree = TreeInventory::scan(&inputs.root, &required, MAX_SOURCE_BYTES, stopped)?;
        if tree.names().ne(inputs
            .manifest
            .files()
            .iter()
            .map(|file| file.path.as_str()))
        {
            return Err(invalid(
                "target state workspace differs from its sealed manifest",
            ));
        }
        let mut files = BTreeMap::new();
        for expected in inputs.manifest.files() {
            checkpoint(stopped)?;
            let mut file = tree.open_file(&expected.path)?;
            let metadata = file.metadata()?;
            if metadata.len() != expected.len
                || (metadata.permissions().mode() & 0o111 != 0) != expected.executable
                || hash_copy(&mut file, &mut io::sink(), expected.len, stopped)? != expected.sha256
            {
                return Err(invalid("target state source content verification failed"));
            }
            tree.verify_file(&expected.path, &file)?;
            files.insert(expected.path.clone(), metadata.modified()?);
        }
        let directories = directory_times(&tree)?;
        tree.verify(stopped)?;
        Ok(Self { files, directories })
    }

    fn restore(&self, inputs: &WorkspaceInputs, stopped: &impl Fn() -> bool) -> io::Result<()> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        if inputs
            .runtime_owner
            .as_ref()
            .is_none_or(|owner| owner.path() != inputs.root)
        {
            return Err(invalid(
                "source timestamps require a private runtime workspace owner",
            ));
        }
        let current = Self::capture(inputs, stopped)?;
        if current.files.keys().ne(self.files.keys())
            || current.directories.keys().ne(self.directories.keys())
            || current
                .directories
                .iter()
                .any(|(name, value)| self.directories[name].mode != value.mode)
        {
            return Err(invalid("target state source layout changed"));
        }
        let required = self.files.keys().cloned().collect();
        let tree = TreeInventory::scan(&inputs.root, &required, MAX_SOURCE_BYTES, stopped)?;
        for (name, modified) in &self.files {
            checkpoint(stopped)?;
            tree.open_file(name)?
                .set_times(FileTimes::new().set_modified(*modified))?;
        }
        // Updating a child timestamp does not alter its parent. Deepest-first
        // restoration also leaves the original root timestamp intact.
        for (name, directory) in self.directories.iter().rev() {
            checkpoint(stopped)?;
            tree.open_directory(name)?
                .set_times(FileTimes::new().set_modified(directory.modified))?;
        }
        if Self::capture(inputs, stopped)? != *self {
            return Err(invalid(
                "source filesystem cannot preserve Cargo timestamps",
            ));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
impl SourceTimes {
    fn capture(_: &WorkspaceInputs, _: &impl Fn() -> bool) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
    fn restore(&self, _: &WorkspaceInputs, _: &impl Fn() -> bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredFile {
    len: u64,
    digest: [u8; 32],
    mode: u32,
    modified: SystemTime,
    /// First relative path of an internal alias group; never a host inode ID.
    link_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredDirectory {
    mode: u32,
    modified: SystemTime,
}

#[derive(Debug)]
struct TreeSnapshot {
    directory: SnapshotDirectory,
    files: BTreeMap<String, StoredFile>,
    directories: BTreeMap<String, StoredDirectory>,
    bytes: u64,
}

#[derive(Debug)]
enum SnapshotDirectory {
    Temporary(tempfile::TempDir),
    #[cfg(target_os = "linux")]
    Durable(persistence::Generation),
}

impl SnapshotDirectory {
    fn path(&self) -> &Path {
        match self {
            Self::Temporary(directory) => directory.path(),
            #[cfg(target_os = "linux")]
            Self::Durable(generation) => generation.path(),
        }
    }

    fn prepare(&self, seed: &Seed, stopped: &impl Fn() -> bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Self::Durable(generation) = self {
            return generation.prepare(seed, stopped);
        }
        let _ = seed;
        checkpoint(stopped)
    }

    fn publish(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Self::Durable(generation) = self {
            return generation.publish();
        }
        Ok(())
    }

    fn retire(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Self::Durable(generation) = self {
            return generation.retire();
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn directory_times(
    tree: &rabs_sandbox::artifact_tree::TreeInventory,
) -> io::Result<BTreeMap<String, StoredDirectory>> {
    use std::os::unix::fs::PermissionsExt;
    tree.directory_names()
        .map(|name| {
            let metadata = tree.open_directory(name)?.metadata()?;
            let mode = metadata.permissions().mode();
            if mode & 0o7000 != 0 {
                return Err(invalid(
                    "target state refuses special directory permission bits",
                ));
            }
            if mode & 0o700 != 0o700 {
                // Retained TempDir cleanup must not require privilege or leave
                // unaccounted read-only trees after eviction/cancellation.
                return Err(invalid(
                    "target state requires owner-readable writable directories",
                ));
            }
            Ok((
                name.to_owned(),
                StoredDirectory {
                    mode: mode & 0o777,
                    modified: metadata.modified()?,
                },
            ))
        })
        .collect()
}

#[cfg(target_os = "linux")]
impl TreeSnapshot {
    fn capture_inventory(
        cache: &TargetCache,
        tree: &rabs_sandbox::artifact_tree::TreeInventory,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        let directory = match &cache.storage {
            Some(storage) => SnapshotDirectory::Durable(storage.allocate()?),
            None => SnapshotDirectory::Temporary(private_directory("rabs-target-seed-")?),
        };
        let (files, directories) = copy_tree(tree, directory.path(), stopped)?;
        Ok(Self {
            directory,
            files,
            directories,
            bytes: tree.total_bytes(),
        })
    }

    fn capture(
        cache: &Arc<TargetCache>,
        root: &Path,
        plan: &ArtifactPlan,
        captured: &CapturedArtifacts,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Option<(Reservation, Self)>> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        let required = captured.file_names().map(str::to_owned).collect();
        let tree = if plan.private_incremental_roots().is_some() {
            TreeInventory::scan_private(root, &required, MAX_TARGET_CACHE_BYTES, stopped)?
        } else {
            TreeInventory::scan(root, &required, MAX_ARTIFACT_BYTES, stopped)?
        };
        // Every ordinary output still belongs to the validated offer. Only
        // the explicit Cargo private-state projection may retain extra files;
        // generic and older Cargo contracts continue to require exact equality.
        if tree
            .names()
            .filter(|name| !plan.is_private_incremental_file(name))
            .ne(captured.file_names())
        {
            return Err(invalid("target seed differs from validated artifact set"));
        }
        // Reserve the COMPLETE target before copying, including compiler state
        // omitted from transport. An output-only reservation would undercount
        // incremental generations and let them bypass the worker pool quota.
        let Some(reservation) = cache.reserve(tree.total_bytes()) else {
            return Ok(None);
        };
        let snapshot = Self::capture_inventory(cache, &tree, stopped)?;
        for name in captured.file_names() {
            let file = snapshot
                .files
                .get(name)
                .ok_or_else(|| invalid("target seed is missing a validated artifact"))?;
            if captured.file_identity(name)
                != Some((
                    file.len,
                    crate::source_transfer::hex(&file.digest).as_str(),
                    file.mode & 0o111 != 0,
                ))
            {
                return Err(invalid("target seed differs from validated artifact bytes"));
            }
        }
        if snapshot.bytes != reservation.bytes {
            return Err(invalid(
                "target state differs from its complete reservation",
            ));
        }
        Ok(Some((reservation, snapshot)))
    }

    fn restore(&self, destination: &Path, stopped: &impl Fn() -> bool) -> io::Result<()> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        let required = self.files.keys().cloned().collect();
        let tree =
            TreeInventory::scan_private(self.directory.path(), &required, self.bytes, stopped)?;
        let (files, directories) = copy_tree(&tree, destination, stopped)?;
        if files != self.files
            || directories != self.directories
            || tree.total_bytes() != self.bytes
        {
            return Err(invalid("private target seed was corrupted"));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
impl TreeSnapshot {
    fn capture(
        _: &Arc<TargetCache>,
        _: &Path,
        _: &ArtifactPlan,
        _: &CapturedArtifacts,
        _: &impl Fn() -> bool,
    ) -> io::Result<Option<(Reservation, Self)>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
    fn restore(&self, _: &Path, _: &impl Fn() -> bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
}

fn private_directory(prefix: &str) -> io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder.tempdir()
}

#[cfg(target_os = "linux")]
fn copy_tree(
    tree: &rabs_sandbox::artifact_tree::TreeInventory,
    destination: &Path,
    stopped: &impl Fn() -> bool,
) -> io::Result<(
    BTreeMap<String, StoredFile>,
    BTreeMap<String, StoredDirectory>,
)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let directories = directory_times(tree)?;
    for name in directories.keys().filter(|name| !name.is_empty()) {
        checkpoint(stopped)?;
        // PreparedArtifacts may already have declared parent directories. Only
        // this execution owns destination, which is never sourced from a peer.
        let path = destination.join(name);
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists
                    && fs::symlink_metadata(&path)?.is_dir() => {}
            Err(error) => return Err(error),
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let mut files = BTreeMap::new();
    let mut aliases: BTreeMap<(u64, u64), String> = BTreeMap::new();
    for name in tree.names() {
        checkpoint(stopped)?;
        let mut input = tree.open_file(name)?;
        let metadata = input.metadata()?;
        if metadata.permissions().mode() & 0o7000 != 0 {
            return Err(invalid("target state refuses special permission bits"));
        }
        let mode = metadata.permissions().mode() & 0o777;
        let modified = metadata.modified()?;
        let inode = (metadata.dev(), metadata.ino());
        let link_to = aliases.get(&inode).cloned();
        let digest = if let Some(first) = &link_to {
            let digest = hash_copy(&mut input, &mut io::sink(), metadata.len(), stopped)?;
            let prior: &StoredFile = files
                .get(first)
                .ok_or_else(|| invalid("missing internal target alias"))?;
            if prior.len != metadata.len()
                || prior.digest != digest
                || prior.mode != mode
                || prior.modified != modified
            {
                return Err(invalid("internal target alias changed during copy"));
            }
            // TreeInventory has already proved the entire link group closed.
            // Both endpoints are newly created under this one private owner;
            // the original tree, the seed and other attempts share NO inode.
            fs::hard_link(destination.join(first), destination.join(name))?;
            digest
        } else {
            let mut output = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(destination.join(name))?;
            let digest = clone_or_copy_private(
                &mut input,
                &mut output,
                destination,
                metadata.len(),
                stopped,
            )?;
            output.set_permissions(fs::Permissions::from_mode(mode))?;
            output.set_times(FileTimes::new().set_modified(modified))?;
            aliases.insert(inode, name.to_owned());
            digest
        };
        tree.verify_file(name, &input)?;
        files.insert(
            name.to_owned(),
            StoredFile {
                len: metadata.len(),
                digest,
                mode,
                modified,
                link_to,
            },
        );
    }
    for (name, directory) in directories.iter().rev() {
        checkpoint(stopped)?;
        let output = File::open(destination.join(name))?;
        output.set_permissions(fs::Permissions::from_mode(directory.mode))?;
        output.set_times(FileTimes::new().set_modified(directory.modified))?;
    }
    tree.verify(stopped)?;
    Ok((files, directories))
}

/// Retained target state and each restored attempt must own different writable
/// inodes. Reuse the CAS materializer's verified CoW primitive to avoid writing
/// the entire target twice per build. Hash the actual clone, not the source, and
/// keep copy_tree's source inventory and expected seed-digest checks unchanged.
/// Logical bytes remain fully charged to the pool even when extents are shared.
#[cfg(target_os = "linux")]
fn clone_or_copy_private(
    input: &mut File,
    output: &mut File,
    parent: &Path,
    length: u64,
    stopped: &impl Fn() -> bool,
) -> io::Result<[u8; 32]> {
    clone_or_copy_private_with_cloner(
        input,
        output,
        parent,
        length,
        stopped,
        rabs_cas::materialization::try_verified_reflink,
    )
}

#[cfg(target_os = "linux")]
fn clone_or_copy_private_with_cloner(
    input: &mut File,
    output: &mut File,
    parent: &Path,
    length: u64,
    stopped: &impl Fn() -> bool,
    cloner: impl FnOnce(&File, &File, &Path) -> bool,
) -> io::Result<[u8; 32]> {
    use std::io::Seek;

    checkpoint(stopped)?;
    // Fingerprint and dep-info files fit in a single copy buffer. Avoid the
    // isolation probe's extra file creations and writes for those tiny inputs,
    // including on filesystems without clone support.
    if length > 64 * 1024 && cloner(input, output, parent) {
        output.rewind()?;
        hash_copy(output, &mut io::sink(), length, stopped)
    } else {
        // Unsupported or failed clones may have partially changed the fresh
        // output. Never retain a suffix, including for an empty source file.
        output.set_len(0)?;
        output.rewind()?;
        input.rewind()?;
        hash_copy(input, output, length, stopped)
    }
}

fn hash_copy(
    input: &mut File,
    output: &mut impl Write,
    length: u64,
    stopped: &impl Fn() -> bool,
) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut remaining = length;
    let mut buffer = [0; 64 * 1024];
    loop {
        checkpoint(stopped)?;
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        remaining = remaining
            .checked_sub(count as u64)
            .ok_or_else(|| invalid("target state file grew during copy"))?;
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    if remaining != 0 {
        return Err(invalid("target state file shrank during copy"));
    }
    Ok(hash.finalize().into())
}

#[cfg(all(test, target_os = "linux"))]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "target_cache/concurrent_tests.rs"]
mod concurrent_tests;
