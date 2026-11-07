//! Verified source-byte reuse for the authenticated remote Cargo frontend.
//!
//! The cache owns only disposable byte objects. Each operation imports selected
//! hits into its fresh receiver, advertises a bounded missing-file plan, and
//! seals the complete manifest before execution. A hit never grants source-tree
//! or publication authority, and no shared file is mounted writable.

use super::private_directory;
use super::wire::{SourcePlan, invalid, require};
use rabs_sandbox::source_cache::{RememberError, SourceCache, SourceCheckpoints};
use rabs_sandbox::source_transfer::SourceReceiver;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

/// One service-wide budget and private parent. Scoped sessions clone the same
/// writer/inventory state; enrolled peers do not receive independent quotas.
pub(super) struct RemoteSourceCache {
    cache: SourceCache,
    owner: Arc<tempfile::TempDir>,
}

impl RemoteSourceCache {
    pub(super) fn new(parent: &Path, max_bytes: u64) -> io::Result<Self> {
        private_directory(parent)?;
        let owner = Arc::new(
            tempfile::Builder::new()
                .prefix("canonical-remote-source-cache-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(parent)?,
        );
        let cache = SourceCache::open_byte_only(owner.path(), max_bytes)?;
        Ok(Self { cache, owner })
    }

    /// The caller supplies the identity actually authenticated by TLS. Logical
    /// Cargo settings and the source manifest cannot choose this namespace.
    pub(super) fn for_peer(
        &self,
        peer: [u8; 32],
        stopped: Arc<AtomicBool>,
        deadline: Instant,
    ) -> io::Result<SourceCacheLease> {
        Ok(SourceCacheLease {
            cache: self
                .cache
                .clone()
                .for_peer(peer)?
                .with_cancellation(stopped)
                .before(deadline),
            _owner: Arc::clone(&self.owner),
        })
    }
}

/// Keep cache storage alive through any anonymous hit snapshot or checkpoint
/// writer, even if the service's original pool handle has already been dropped.
pub(super) struct SourceCacheLease {
    cache: SourceCache,
    _owner: Arc<tempfile::TempDir>,
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> io::Result<()> {
    if cancelled() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "remote source preparation or transfer cancelled",
        ))
    } else {
        Ok(())
    }
}

fn cache_warning(stage: &str, error: &io::Error) {
    eprintln!(
        "{}",
        serde_json::json!({
            "kind":"canonical-remote-source-cache-warning",
            "stage":stage,
            "message":error.to_string().chars().take(1024).collect::<String>(),
        })
    );
}

/// Exact missing-file decision and the original fresh source receiver. Writer
/// handles close before cache ownership. An uncertain write or source error
/// makes this wrapper terminal even when the underlying receiver was sealed.
pub(super) struct SourceInput {
    receiver: SourceReceiver,
    checkpoints: Option<SourceCheckpoints>,
    cache: Option<SourceCacheLease>,
    plan: SourcePlan,
    checkpoint_attempted: bool,
    transfer_started: bool,
    failed: bool,
    sealed: bool,
}

impl SourceInput {
    pub(super) fn uncached(receiver: SourceReceiver) -> io::Result<Self> {
        require(
            receiver.sealed_root().is_none(),
            "remote source admission requires a fresh receiver",
        )?;
        let plan = SourcePlan::all(receiver.manifest())?;
        Ok(Self {
            receiver,
            checkpoints: None,
            cache: None,
            plan,
            checkpoint_attempted: false,
            transfer_started: false,
            failed: false,
            sealed: false,
        })
    }

    pub(super) fn prepare(
        receiver: SourceReceiver,
        cache: Option<SourceCacheLease>,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<Self> {
        checkpoint(&cancelled)?;
        let mut input = Self::uncached(receiver)?;
        input.cache = cache;
        if let Some(cache) = &input.cache {
            let files = input.receiver.manifest().files().to_vec();
            let mut missing = Vec::with_capacity(files.len());
            for (index, file) in files.iter().enumerate() {
                checkpoint(&cancelled)?;
                if file.len == 0 {
                    continue;
                }
                let snapshot = cache.cache.load(file);
                // load intentionally treats unavailable/corrupt objects as
                // misses, including a spent cache control budget. Recheck the
                // operation budget before interpreting absence as upload work.
                checkpoint(&cancelled)?;
                if let Some(snapshot) = snapshot {
                    snapshot.install_with_cloner(
                        &mut input.receiver,
                        rabs_cas::materialization::try_verified_reflink,
                    )?;
                    // Import failure poisons the receiver: never request an
                    // upload to repair a partly populated operation in place.
                    checkpoint(&cancelled)?;
                } else {
                    missing.push(
                        u16::try_from(index)
                            .map_err(|_| invalid("remote source index exceeds its bound"))?,
                    );
                }
            }
            input.plan = SourcePlan::new(input.receiver.manifest(), missing)?;
        }
        checkpoint(&cancelled)?;
        Ok(input)
    }

    pub(super) fn plan(&self) -> &SourcePlan {
        &self.plan
    }

    /// Readiness grants one new input budget. No frame, checkpoint or retry can
    /// renew it again, and preparation must already have finished successfully.
    pub(super) fn begin_transfer(&mut self, deadline: Instant) -> io::Result<()> {
        require(
            !self.transfer_started && !self.failed && !self.sealed,
            "remote source transfer was already started or refused",
        )?;
        self.plan.validate(self.receiver.manifest())?;
        if let Some(cache) = &mut self.cache {
            cache.cache = cache.cache.clone().before(deadline);
        }
        self.transfer_started = true;
        Ok(())
    }

    pub(super) fn write_chunk(
        &mut self,
        path: &str,
        offset: u64,
        bytes: &[u8],
        sha256: [u8; 32],
        cancelled: impl Fn() -> bool,
    ) -> io::Result<()> {
        require(
            self.transfer_started && !self.failed && !self.sealed,
            "remote source transfer is unavailable or already sealed",
        )?;
        self.failed = true;
        checkpoint(&cancelled)?;
        let files = self.receiver.manifest().files();
        let index = files
            .binary_search_by(|file| file.path.as_str().cmp(path))
            .map_err(|_| invalid("remote source chunk names an undeclared file"))?;
        let index_u16 = u16::try_from(index)
            .map_err(|_| invalid("remote source index exceeds its bound"))?;
        require(
            self.plan.missing_files.binary_search(&index_u16).is_ok(),
            "remote source chunk was not requested by the admitted missing-file plan",
        )?;
        let expected_len = files[index].len;
        let received = self.receiver.write_chunk(path, offset, bytes, sha256)?;
        if received == expected_len {
            self.remember_completed_file(path)?;
        }
        checkpoint(&cancelled)?;
        self.failed = false;
        Ok(())
    }

    fn remember_completed_file(&mut self, path: &str) -> io::Result<()> {
        let Some(cache) = &self.cache else {
            return Ok(());
        };
        if !self.checkpoint_attempted {
            self.checkpoint_attempted = true;
            match cache.cache.checkpoints(self.receiver.manifest()) {
                Ok(writer) => self.checkpoints = writer,
                Err(RememberError::Cache(error)) => cache_warning("checkpoint", &error),
                Err(RememberError::Source(error)) => return Err(error),
            }
        }
        if let Some(writer) = &mut self.checkpoints {
            match writer.remember_file(&mut self.receiver, path) {
                Ok(()) => {}
                Err(RememberError::Cache(error)) => {
                    cache_warning("checkpoint", &error);
                    self.checkpoints = None;
                }
                Err(RememberError::Source(error)) => return Err(error),
            }
        }
        Ok(())
    }

    pub(super) fn seal(&mut self, cancelled: impl Fn() -> bool) -> io::Result<()> {
        require(
            self.transfer_started && !self.failed,
            "remote source transfer was not started or has failed",
        )?;
        checkpoint(&cancelled)?;
        if self.sealed {
            return Ok(());
        }
        self.failed = true;
        // Do not hold a shared writer while the receiver performs its mandatory
        // complete-tree verification. Remember can retry optional admission.
        self.checkpoints = None;
        self.receiver.seal_cancellable(&cancelled)?;
        if let Some(cache) = &self.cache {
            match cache.cache.remember(&self.receiver) {
                Ok(_) => {}
                Err(RememberError::Cache(error)) => cache_warning("retain", &error),
                Err(RememberError::Source(error)) => return Err(error),
            }
        }
        checkpoint(&cancelled)?;
        self.sealed = true;
        self.failed = false;
        Ok(())
    }

    pub(super) fn finish(mut self, cancelled: impl Fn() -> bool) -> io::Result<SourceReceiver> {
        self.seal(cancelled)?;
        Ok(self.receiver)
    }
}
