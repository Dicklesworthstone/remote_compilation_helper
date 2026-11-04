//! One owner for endpoint locking, stale takeover and final socket retirement.
//!
//! Asupersync's bind() normally retires the path when its listener drops. The
//! from_std() constructor deliberately leaves pathname ownership with us: an
//! admitted connection may still be joining an output writer after the acceptor
//! stops. Its Arc keeps the endpoint fenced until that work has actually ended.

use asupersync::net::unix::{UnixListener, UnixStream};
use rabs_sandbox::socket_endpoint::EndpointLease;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub(super) struct EndpointOwner(EndpointLease);

impl Drop for EndpointOwner {
    fn drop(&mut self) {
        let path = self.0.path().display().to_string();
        let line = match self.0.retire_bound() {
            Ok(true) => super::render_log_line("rabsd-edge-socket-retired", &[("socket", &path)]),
            Ok(false) => super::render_log_line(
                "rabsd-edge-socket-retirement-skipped",
                &[
                    ("socket", &path),
                    ("reason", "absent or changed generation"),
                ],
            ),
            Err(error) => super::render_log_line(
                "rabsd-edge-socket-retirement-refused",
                &[("socket", &path), ("reason", &error.to_string())],
            ),
        };
        // Teardown still releases ownership when stderr is closed. Do not
        // let an eprintln! I/O panic interrupt an already-unwinding owner.
        let _ = writeln!(io::stderr().lock(), "{line}");
        // EndpointLease explicitly unlocks only after the retirement attempt.
    }
}

pub(super) struct ListenerOwner {
    // Field order matters: close listener BEFORE dropping its endpoint owner.
    pub(super) listener: UnixListener,
    pub(super) owner: Arc<EndpointOwner>,
}

impl ListenerOwner {
    pub(super) fn owner_uid(&self) -> u32 {
        self.owner.0.owner_uid()
    }
}

pub(super) async fn bind(path: &Path, budget: Duration) -> Result<ListenerOwner, String> {
    bind_inner(path, budget)
        .await
        .map_err(|error| format!("endpoint {}: {error}", path.display()))
}

async fn bind_inner(path: &Path, budget: Duration) -> io::Result<ListenerOwner> {
    // Different state stores must not race over one shared socket. The CAS
    // mount lock alone cannot provide this endpoint-specific fence.
    let mut lease = EndpointLease::acquire(path)?;
    if let Some(observed) = lease.observe()? {
        let probe = asupersync::time::timeout(
            asupersync::time::wall_now(),
            budget,
            UnixStream::connect(lease.path()),
        )
        .await;
        match probe {
            Ok(Ok(_stream)) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another daemon is listening",
                ));
            }
            Ok(Err(error)) => {
                // This method accepts ONLY ConnectionRefused plus the exact
                // pre-probe generation. EACCES, reset, ENOENT, etc. retain it.
                lease.retire_refused(observed, &error)?;
                super::log_line(
                    "rabsd-socket-takeover",
                    &[("stale", &lease.path().display().to_string())],
                );
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "endpoint liveness is uncertain",
                ));
            }
        }
    }
    lease.verify()?;
    // Same native bind as Asupersync uses, but without its shorter-lived
    // automatic pathname cleanup. No second runtime or worker thread.
    let listener = std::os::unix::net::UnixListener::bind(lease.path())?;
    lease.claim_bound()?;
    let owner = Arc::new(EndpointOwner(lease));
    let listener = UnixListener::from_std(listener)?;
    Ok(ListenerOwner { listener, owner })
}

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;
