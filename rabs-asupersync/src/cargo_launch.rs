//! Permit-gated Cargo launch + valid jobserver injection (bead I002;
//! Epic I scheduler/jobserver; risk R48's enforcement half).
//!
//! Composes the two landed halves into THE single admission point every
//! managed Cargo process must pass:
//!
//! 1. **Root permit** ([`crate::root_permits`]): acquired BEFORE spawn,
//!    held for the FULL process lifetime, released exactly once —
//!    either explicitly through [`ManagedCargoLaunch::finish`] (which
//!    also resolves the paired `CargoRootPermit` obligation) or, on
//!    unwind/early-drop paths, by RAII so the root always returns to
//!    the pool while the OPEN obligation makes the leak visible at
//!    region close.
//! 2. **Valid local jobserver** (GNU make protocol): a fresh
//!    **named-pipe** jobserver (`--jobserver-auth=fifo:PATH`, the POSIX
//!    variant GNU make ≥4.3 documents and cargo's jobserver client
//!    understands), preloaded with the caller-supplied transferable
//!    token budget and handed over purely by PATH.
//!
//! WHY FIFO BY PATH (recorded decision): passing arbitrary fd numbers
//! into children requires `dup2` pre-exec (`unsafe`, forbidden) or
//! non-CLOEXEC descriptors (unreachable from safe std — extra fds
//! cannot cross `Command` spawn at all, and `std::io::pipe` ends are
//! CLOEXEC by design). The fifo form moves the handshake into the
//! filesystem namespace, which nested make/cargo open THEMSELVES —
//! validity is therefore provable by ordinary fixtures instead of
//! asserted.

use std::process::Command;
use std::time::Duration;

use crate::obligations::ObligationSet;
use crate::process_groups::{ManagedProcessGroup, ProcessGroupSpec};
use crate::root_permits::{RootPermit, RootPermitBroker};

/// Env keys nested make/cargo consult for jobserver auth.
pub const MAKEFLAGS_ENV: &str = "MAKEFLAGS";
/// Cargo's dialect of the same variable (what cargo sets for build
/// scripts and what some wrappers consult).
pub const CARGO_MAKEFLAGS_ENV: &str = "CARGO_MAKEFLAGS";

/// Why a gated launch could not start.
#[derive(Debug)]
pub enum LaunchError {
    /// No root permit within the waited budget.
    PermitTimeout(crate::root_permits::PermitError),
    /// The fifo could not be created or seeded.
    Jobserver(std::io::Error),
    /// The process group failed to spawn.
    Spawn(std::io::Error),
}

/// One admitted Cargo process: the live group, the held root permit,
/// and the fifo jobserver it was granted.
///
/// Drop semantics mirror [`RootPermit`]: dropping without [`Self::finish`]
/// still returns the ROOT to the pool (RAII) and unlinks the fifo, but
/// leaves the `CargoRootPermit` obligation OPEN so `may_close_region`
/// names the leak — plain `Drop` is the crash path, `finish` is the
/// happy path.
#[derive(Debug)]
pub struct ManagedCargoLaunch {
    group: ManagedProcessGroup,
    permit: Option<RootPermit>,
    fifo_path: std::path::PathBuf,
    /// Held-open write end: tokens are bytes. Never READ — its value
    /// is the open descriptor itself (EOF reaches readers exactly when
    /// this handle drops).
    #[allow(dead_code)]
    fifo_writer: std::fs::File,
}

impl ManagedCargoLaunch {
    /// Leader pid == pgid of the managed group.
    #[must_use]
    pub fn pgid(&self) -> u32 {
        self.group.pgid()
    }

    /// Block on the leader (streams per the caller's configurator).
    ///
    /// # Errors
    /// Typed [`std::io::Error`] from the wait itself.
    pub fn wait_leader(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.group.wait_leader()
    }

    /// Happy-path completion: root released exactly once INTO `set`
    /// (resolving the paired obligation), fifo unlinked, writer closed.
    ///
    /// # Errors
    /// The obligation resolution result (typed).
    pub fn finish(
        mut self,
        set: &mut ObligationSet,
    ) -> Result<(), crate::obligations::ObligationError> {
        if let Some(permit) = self.permit.take() {
            permit.release_into(set)?;
        }
        Ok(())
    }
}

impl Drop for ManagedCargoLaunch {
    fn drop(&mut self) {
        // RootPermit's own Drop returns the root; the fifo goes away.
        // The obligation intentionally stays open (crash-path ledger).
        let _ = std::fs::remove_file(&self.fifo_path);
        // fifo_writer closes here: nested readers observe EOF after the
        // final tokens, ending their jobserver wait cleanly.
    }
}

/// The admission point for managed Cargo processes.
#[derive(Debug)]
pub struct CargoLaunchGate {
    broker: std::sync::Arc<RootPermitBroker>,
}

impl CargoLaunchGate {
    /// Gate over one broker.
    #[must_use]
    pub fn new(broker: std::sync::Arc<RootPermitBroker>) -> Self {
        Self { broker }
    }

    /// Admit ONE Cargo process: take a root permit, mint a fresh fifo
    /// jobserver preloaded with `transferable_tokens`, inject the auth
    /// environment, and spawn the group.
    ///
    /// `configure` runs last (stdio etc.) AFTER the auth environment is
    /// installed, so callers cannot accidentally shadow it.
    ///
    /// # Errors
    /// Typed [`LaunchError`]: permit timeout, fifo setup, or spawn
    /// failure — never a silently ungated Cargo run.
    pub fn launch(
        &self,
        spec: &ProcessGroupSpec,
        set: &mut ObligationSet,
        transferable_tokens: usize,
        permit_timeout: Duration,
        configure: impl FnOnce(&mut Command),
    ) -> Result<ManagedCargoLaunch, LaunchError> {
        // 1. Root permit FIRST (R48: before every Cargo process).
        let permit = Some(
            self.broker
                .acquire_timeout(set, permit_timeout)
                .map_err(LaunchError::PermitTimeout)?,
        );

        // 2. Fresh fifo jobserver, preloaded to the transferable budget.
        //    On failure the permit returns via RAII while the OPEN
        //    obligation names the aborted attempt for the ledger.
        let (fifo_path, fifo_writer, auth) =
            crate::jobserver::mint_fifo_jobserver(transferable_tokens, &std::env::temp_dir())
                .map_err(LaunchError::Jobserver)?;

        // 3. Spawn under a managed group with the auth installed BEFORE
        //    any caller configuration (callers cannot shadow it).
        let auth_env = auth;
        let inner = |cmd: &mut Command| {
            cmd.env(MAKEFLAGS_ENV, &auth_env);
            cmd.env(CARGO_MAKEFLAGS_ENV, &auth_env);
            configure(cmd);
        };
        match ManagedProcessGroup::spawn_with(spec, inner) {
            Ok(group) => Ok(ManagedCargoLaunch {
                group,
                permit,
                fifo_path,
                fifo_writer,
            }),
            Err(e) => {
                // ManagedCargoLaunch was never constructed, so its Drop
                // will not run — unlink eagerly here.
                let _ = std::fs::remove_file(&fifo_path);
                Err(LaunchError::Spawn(e))
            }
        }
    }
}
