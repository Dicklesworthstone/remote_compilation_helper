//! Operation cancellation and process-root ownership during source preparation.

use sha2::{Digest, Sha256};
use std::any::Any;
use std::io::{self, Read, Write};
use std::time::Duration;

/// Keeps the caller's root admission alive without coupling preparation to the
/// service broker. The owner is released only after the managed group drains.
pub(crate) struct PreparationRootGuard {
    _owner: Box<dyn Any>,
}

impl PreparationRootGuard {
    pub(crate) fn new<T: 'static>(owner: T) -> Self {
        Self {
            _owner: Box::new(owner),
        }
    }
}

type AcquireRoot<'a> = dyn Fn(Duration) -> io::Result<PreparationRootGuard> + 'a;

pub(crate) struct PreparationControl<'a> {
    stopped: &'a dyn Fn() -> bool,
    acquire: Option<&'a AcquireRoot<'a>>,
}

impl<'a> PreparationControl<'a> {
    pub(crate) fn new(stopped: &'a dyn Fn() -> bool, acquire: Option<&'a AcquireRoot<'a>>) -> Self {
        Self { stopped, acquire }
    }

    pub(crate) fn uncontrolled() -> Self {
        Self::new(&|| false, None)
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        (self.stopped)()
    }

    pub(crate) fn checkpoint(&self) -> io::Result<()> {
        if self.is_cancelled() {
            Err(Self::cancelled())
        } else {
            Ok(())
        }
    }

    pub(crate) fn cancelled() -> io::Error {
        io::Error::new(io::ErrorKind::Interrupted, "source preparation cancelled")
    }

    pub(crate) fn acquire_root(&self, timeout: Duration) -> io::Result<PreparationRootGuard> {
        self.checkpoint()?;
        let guard = match self.acquire {
            Some(acquire) => acquire(timeout)?,
            None => PreparationRootGuard::new(()),
        };
        // Cancellation may arrive while the broker waits for a root slot.
        self.checkpoint()?;
        Ok(guard)
    }

    /// Bound every read and observe cancellation between chunks. The caller
    /// retains responsibility for its exact-size/content verification.
    pub(crate) fn read_bounded(&self, reader: impl Read, limit: u64) -> io::Result<Vec<u8>> {
        let mut reader = reader.take(limit);
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            self.checkpoint()?;
            let count = reader.read(&mut buffer)?;
            self.checkpoint()?;
            if count == 0 {
                return Ok(bytes);
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
    }

    pub(crate) fn write_all(&self, mut writer: impl Write, bytes: &[u8]) -> io::Result<()> {
        for chunk in bytes.chunks(64 * 1024) {
            self.checkpoint()?;
            writer.write_all(chunk)?;
        }
        self.checkpoint()
    }

    pub(crate) fn sha256(&self, bytes: &[u8]) -> io::Result<[u8; 32]> {
        let mut hash = Sha256::new();
        for chunk in bytes.chunks(64 * 1024) {
            self.checkpoint()?;
            hash.update(chunk);
        }
        self.checkpoint()?;
        Ok(hash.finalize().into())
    }
}
