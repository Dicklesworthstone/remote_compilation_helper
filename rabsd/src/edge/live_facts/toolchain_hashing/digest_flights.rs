//! Share an in-flight verified read of one exact toolchain file generation.
//!
//! This table is not another digest cache: the owner removes its entry when
//! work ends. All followers validate THEIR path, and populate THEIR existing
//! memo, after receiving the result. No pathname, mtime alone, or pending read
//! grants authority. The existing warm/scoped-helper threads own all work and
//! waits; no request queue, executor, detached reader, or new thread is created.

use super::{DigestMemo, FileSig, verify_files};
use rabs_protocol::result_identity::TypedDigest;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::thread::{self, ThreadId};

const MAX_FLIGHTS: usize = 64;
static FLIGHTS: LazyLock<Flights> = LazyLock::new(Flights::default);

#[derive(Clone)]
struct Failure {
    kind: io::ErrorKind,
    raw: Option<i32>,
    message: String,
}

impl Failure {
    fn capture(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw: error.raw_os_error(),
            message: error.to_string(),
        }
    }

    fn error(&self) -> io::Error {
        self.raw.map_or_else(
            || io::Error::new(self.kind, self.message.clone()),
            io::Error::from_raw_os_error,
        )
    }
}

struct Flight {
    owner: ThreadId,
    result: Mutex<Option<Result<TypedDigest, Failure>>>,
    changed: Condvar,
}

impl Flight {
    fn wait(&self) -> io::Result<TypedDigest> {
        let mut result = self.result.lock().map_err(|_| poisoned())?;
        loop {
            if let Some(result) = &*result {
                return result.clone().map_err(|failure| failure.error());
            }
            if self.owner == thread::current().id() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "recursive toolchain digest observation",
                ));
            }
            // A production reader owns one flight at a time: its work is one
            // direct descriptor read plus memo recording, not nested hashing.
            // Unwind/drop wakes us; slow kernel I/O remains slow, not cancellable.
            result = self.changed.wait(result).map_err(|_| poisoned())?;
        }
    }
}

fn poisoned() -> io::Error {
    io::Error::other("toolchain digest flight result poisoned")
}

#[derive(Default)]
struct Flights {
    active: Mutex<HashMap<FileSig, Arc<Flight>>>,
}

enum Admission<'a> {
    Owner(Owner<'a>),
    Follower(Arc<Flight>),
    Direct,
}

impl Flights {
    fn acquire(&self, signature: FileSig) -> Admission<'_> {
        let Ok(mut active) = self.active.lock() else {
            // Advisory state failure cannot turn a verified read into a hit.
            return Admission::Direct;
        };
        if let Some(flight) = active.get(&signature) {
            return Admission::Follower(Arc::clone(flight));
        }
        if active.len() >= MAX_FLIGHTS {
            // Keep all admitted owners. Existing warm-thread capacity bounds
            // the direct read; do not queue behind an unrelated file identity.
            return Admission::Direct;
        }
        let flight = Arc::new(Flight {
            owner: thread::current().id(),
            result: Mutex::new(None),
            changed: Condvar::new(),
        });
        active.insert(signature, Arc::clone(&flight));
        Admission::Owner(Owner {
            table: self,
            signature,
            flight,
        })
    }

    fn run(
        &self,
        signature: FileSig,
        work: impl FnOnce() -> io::Result<TypedDigest>,
    ) -> io::Result<TypedDigest> {
        match self.acquire(signature) {
            Admission::Direct => work(),
            Admission::Follower(flight) => flight.wait(),
            Admission::Owner(owner) => {
                // Neither table nor result mutex covers hashing, persistence,
                // user-supplied test callbacks, or result destruction.
                let result = work();
                *owner.flight.result.lock().map_err(|_| poisoned())? =
                    Some(result.as_ref().cloned().map_err(Failure::capture));
                // Drop publishes abandonment on unwind; on success it retires
                // this exact entry and wakes all already admitted followers.
                drop(owner);
                result
            }
        }
    }
}

struct Owner<'a> {
    table: &'a Flights,
    signature: FileSig,
    flight: Arc<Flight>,
}

impl Drop for Owner<'_> {
    fn drop(&mut self) {
        {
            let mut result = self
                .flight
                .result
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if result.is_none() {
                *result = Some(Err(Failure::capture(&io::Error::other(
                    "toolchain digest owner abandoned its read",
                ))));
            }
        }
        if let Ok(mut active) = self.table.active.lock()
            && active
                .get(&self.signature)
                .is_some_and(|current| Arc::ptr_eq(current, &self.flight))
        {
            active.remove(&self.signature);
        }
        self.flight.changed.notify_all();
    }
}

pub(super) fn read(
    memo: &DigestMemo,
    path: &Path,
    signature: FileSig,
    hash: &(impl Fn(&Path, FileSig) -> io::Result<TypedDigest> + Sync),
) -> io::Result<TypedDigest> {
    read_with(&FLIGHTS, memo, path, signature, hash)
}

fn read_with(
    flights: &Flights,
    memo: &DigestMemo,
    path: &Path,
    signature: FileSig,
    hash: &(impl Fn(&Path, FileSig) -> io::Result<TypedDigest> + Sync),
) -> io::Result<TypedDigest> {
    verify_files(&[(path, signature)])?;
    if let Some(digest) = memo.get(&signature) {
        return Ok(digest);
    }
    let digest = flights.run(signature, || {
        verify_files(&[(path, signature)])?;
        // A preceding leader may have finished between lookup and admission.
        if let Some(digest) = memo.get(&signature) {
            return Ok(digest);
        }
        let digest = hash(path, signature)?;
        verify_files(&[(path, signature)])?;
        // Record before retiring the flight, closing the lookup/admission race.
        // No incomplete batch is promoted, but individually verified work stays.
        memo.remember(signature, &digest)?;
        Ok(digest)
    })?;
    // Same inode/version can be reached by different names. The leader's name
    // cannot prove that a follower's alias still resolves to that generation.
    verify_files(&[(path, signature)])?;
    // Normal callers share the same memo. An independent memo still needs its
    // own conflict check; a shared read never imports another memo's authority.
    memo.remember(signature, &digest)?;
    Ok(digest)
}

#[cfg(test)]
mod tests;
