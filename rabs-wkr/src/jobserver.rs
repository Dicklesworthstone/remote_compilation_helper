//! Worker-local jobserver authority (bead G006; risk R48's worker side;
//! feeds I002 "valid jobserver injection" and I004 "worker-local
//! jobserver bridge").
//!
//! The edge's local jobserver pipe can NEVER cross into the canonical
//! namespace: bubblewrap closes unrecognized descriptors before exec,
//! and an inherited coordination channel would couple worker parallelism
//! to a dead remote pipe even if it survived. The WORKER therefore owns
//! the action's concurrency budget outright.
//!
//! At the environment layer a "local jobserver handle" is the make-style
//! coordination variables (`MAKEFLAGS`, `MFLAGS`, `CARGO_MAKEFLAGS`):
//! they carry `-j` budgets and `--jobserver-auth` descriptors. Under I21
//! the presented env is EXACTLY `spec.env`, and `extra_env` may smuggle
//! any non-canonical key in — so [`replace_with_worker_local`] runs on
//! the FINAL spec: client-supplied coordination vars are stripped, then
//! one worker-authored `MAKEFLAGS=-j<slots>` is installed, making this
//! worker — not some inherited descriptor — the authority for how many
//! parallel jobs the action believes it may run.
//!
//! Descriptor-level injection is impossible (bwrap offers no fd
//! passthrough), but a bare `MAKEFLAGS=-jN` lets every PLAIN `make`
//! invoked in a recipe mint its OWN full-size pool — tree-depth
//! multiplication. [`JobserverBridge`] closes that with a real fifo
//! jobserver carried through the canonical HOME bind by PATH: one budget,
//! shared by every descendant, sized from the execution grant.

/// Env var names that carry make/cargo coordination state — including
/// descriptor/auth material that is NEVER valid from a client (bead
/// I003, risk R7: a leaked host-local descriptor hangs or oversubscribes
/// the remote action).
pub const COORDINATION_ENV_VARS: &[&str] = &["CARGO_MAKEFLAGS", "MAKEFLAGS", "MFLAGS"];

/// Client-supplied LOGICAL capacity claims (bead I003): never trusted.
/// The child-visible capacity value is the WORKER-authored canonical
/// `NUM_JOBS`, derived from the execution grant — a client's claim says
/// nothing about THIS host's budget.
pub const CAPACITY_ENV_VARS: &[&str] = &["NUM_JOBS"];

const BRIDGE_PREFIX: &str = ".rabs-jobserver-";

// The Linux bridge preloads before any client can consume tokens. Keep
// that write within PIPE_BUF rather than allocating or blocking on an
// arbitrarily large caller-provided grant.
const MAX_BRIDGE_TOKENS: u32 = 4096;

/// Whether `name` is a coordination variable (exact, case-sensitive:
/// canonical env keys are uppercase by construction and I21 forbids
/// fuzzy matching).
#[must_use]
pub fn is_coordination_var(name: &str) -> bool {
    COORDINATION_ENV_VARS.contains(&name)
}

/// Whether `name` is a client capacity claim replaced by the canonical
/// value.
#[must_use]
pub fn is_local_capacity_var(name: &str) -> bool {
    CAPACITY_ENV_VARS.contains(&name)
}

/// Remove every client-supplied coordination variable in place.
pub fn strip_client_coordination(env: &mut Vec<(String, String)>) {
    env.retain(|(k, _)| !is_coordination_var(k));
}

/// Remove every client-supplied capacity claim in place.
pub fn strip_client_capacity(env: &mut Vec<(String, String)>) {
    env.retain(|(k, _)| !is_local_capacity_var(k));
}

/// The worker-authored parallelism budget. Floors at 1 slot: an action
/// must never see `-j0` (make treats 0 as "unbounded" in some code
/// paths, which would silently defeat the budget).
#[must_use]
pub fn worker_makeflags(slots: u32) -> String {
    format!("-j{}", slots.max(1))
}

/// The worker-authored canonical logical capacity (bead I003): tools
/// that consult `NUM_JOBS` directly get the SAME grant the MAKEFLAGS
/// budget carries — one number, one source of truth.
#[must_use]
pub fn worker_num_jobs(slots: u32) -> String {
    slots.max(1).to_string()
}

/// Replace any client authority state with the worker-local canon:
/// strip [`COORDINATION_ENV_VARS`] and [`CAPACITY_ENV_VARS`], then
/// author exactly one `MAKEFLAGS=-j<slots>` and one `NUM_JOBS=<slots>`.
/// Output stays name-sorted (I21 presentation).
pub fn replace_with_worker_local(env: &mut Vec<(String, String)>, slots: u32) {
    strip_client_coordination(env);
    strip_client_capacity(env);
    env.push(("MAKEFLAGS".to_string(), worker_makeflags(slots)));
    env.push(("NUM_JOBS".to_string(), worker_num_jobs(slots)));
    env.sort_by(|a, b| a.0.cmp(&b.0));
    env.dedup_by(|a, b| a.0 == b.0);
}

/// One attempt's SANDBOX-VISIBLE jobserver (bead I004): a real
/// named-pipe jobserver minted under the worker-owned HOME backing so nested
/// make/cargo/ninja inside the canonical namespace cooperate on ONE
/// budget instead of each plain `make` in a recipe minting its own
/// full-size pool (parallelism multiplying by tree depth).
///
/// Mechanism: the fifo node lives in a fresh private directory under HOME,
/// which the canonical namespace bind-mounts at
/// `rabs_sandbox::layout::HOME` — both views address the same
/// in-kernel pipe, so the worker-held writer feeds token bytes that
/// sandboxed descendants consume by PATH. No fd passthrough required.
///
/// Drop unlinks the fifo and closes the writer: stranded readers see
/// EOF after the final tokens, and no per-attempt node outlives the
/// attempt. Source is never consulted or modified to establish coordination;
/// `.rabs-jobserver` remains an ordinary, usable source-file name.
#[derive(Debug)]
pub struct JobserverBridge {
    /// Host-side path (unlinked on Drop).
    host_path: std::path::PathBuf,
    /// Held write end: keeps the fifo open for late readers; its bytes
    /// ARE the free-slot budget.
    _writer: std::fs::File,
    /// Private runtime backing, dropped after the holding writer closes.
    _directory: tempfile::TempDir,
    /// Total admitted slots, including the command's implicit slot.
    slots: u32,
    /// The full MAKEFLAGS value to install (budget + fifo auth with the
    /// IN-SANDBOX path).
    makeflags: String,
}

impl JobserverBridge {
    /// Mint a bridge with `grant_slots` TOTAL slots and exactly one
    /// implicit slot already owned by the command. Its remaining C-1
    /// transferable tokens live in a new private directory under
    /// `home_backing`. HOME is bound at `rabs_sandbox::layout::HOME`, so both fifo paths
    /// are derived from the same relative location.
    ///
    /// # Errors
    /// Typed [`std::io::Error`] from directory creation or the mint.
    /// Callers must refuse execution if the shared budget is unavailable.
    pub fn mint(grant_slots: u32, home_backing: &std::path::Path) -> std::io::Result<Self> {
        let slots = grant_slots.max(1);
        if slots > MAX_BRIDGE_TOKENS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "jobserver grant exceeds the bounded fifo preload",
            ));
        }
        // Never use a fixed child selected by source contents or a previous
        // action. A failed mint drops only this attempt's private directory.
        let directory = tempfile::Builder::new().prefix(BRIDGE_PREFIX).tempdir_in(home_backing)?;
        let (host_path, writer, _edge_auth_unused) =
            rabs_asupersync::jobserver::mint_fifo_jobserver((slots - 1) as usize, directory.path())?;
        let component = |path: &std::path::Path| -> std::io::Result<String> {
            path.file_name().and_then(|name| name.to_str()).map(str::to_owned)
                .ok_or_else(|| std::io::Error::other("jobserver runtime name is not UTF-8"))
        };
        let dir_name = component(directory.path())?;
        let name = component(&host_path)?;
        let makeflags = format!(
            "-j{slots} --jobserver-auth=fifo:{}/{dir_name}/{}",
            rabs_sandbox::layout::HOME,
            name
        );
        Ok(Self {
            host_path,
            _writer: writer,
            _directory: directory,
            slots,
            makeflags,
        })
    }

    /// The full MAKEFLAGS value carrying the in-sandbox auth.
    #[must_use]
    pub fn makeflags(&self) -> &str {
        &self.makeflags
    }

    /// Install one authority for Cargo and make on the FINAL environment.
    /// Stale descriptors, duplicate coordination keys and capacity claims are
    /// replaced together, so CARGO_MAKEFLAGS cannot shadow the valid MAKEFLAGS.
    pub fn apply(env: &mut Vec<(String, String)>, bridge: &Self) {
        replace_with_worker_local(env, bridge.slots);
        for (k, v) in env.iter_mut() {
            if k == "MAKEFLAGS" {
                *v = bridge.makeflags.clone();
            }
        }
        env.push(("CARGO_MAKEFLAGS".to_string(), bridge.makeflags.clone()));
        env.sort_by(|a, b| a.0.cmp(&b.0));
    }
}

impl Drop for JobserverBridge {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.host_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn coordination_detection_is_exact() {
        assert!(is_coordination_var("MAKEFLAGS"));
        assert!(is_coordination_var("CARGO_MAKEFLAGS"));
        assert!(is_coordination_var("MFLAGS"));
        // Case-sensitivity + prefix isolation: none of these coordinate.
        assert!(!is_coordination_var("makeflags"));
        assert!(!is_coordination_var("MAKEFLAGS_EXTRA"));
        assert!(!is_coordination_var("PATH"));
    }

    #[test]
    fn strip_removes_every_coordination_var() {
        let mut env = env_of(&[
            ("PATH", "/bin"),
            ("MAKEFLAGS", "-j64 --jobserver-auth=9,10"),
            ("CARGO_MAKEFLAGS", "-j2"),
            ("HOME", "/home/w"),
            ("MFLAGS", "-j8"),
        ]);
        strip_client_coordination(&mut env);
        assert_eq!(env.len(), 2);
        assert!(!env.iter().any(|(k, _)| is_coordination_var(k)));
    }

    #[test]
    fn worker_budget_floors_at_one_slot() {
        assert_eq!(worker_makeflags(32), "-j32");
        assert_eq!(worker_makeflags(1), "-j1");
        assert_eq!(worker_makeflags(0), "-j1");
        assert_eq!(worker_num_jobs(32), "32");
        assert_eq!(worker_num_jobs(0), "1");
    }

    #[test]
    fn bridge_rejects_oversized_grant_before_creating_fifo() {
        let workspace = tempfile::tempdir().expect("workspace");
        let error = JobserverBridge::mint(u32::MAX, workspace.path())
            .expect_err("unbounded grant must be refused before allocation");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read_dir(workspace.path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bridge_kernel_credit_plus_implicit_slot_equals_the_grant() {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        for grant in [0, 1, 2, 8, MAX_BRIDGE_TOKENS] {
            let workspace = tempfile::tempdir().unwrap();
            let bridge = JobserverBridge::mint(grant, workspace.path()).unwrap();
            let slots = grant.max(1);
            assert!(bridge.makeflags().starts_with(&format!("-j{slots} --jobserver-auth=fifo:")));
            let mut reader = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(0o4000) // Linux O_NONBLOCK; independent of client descriptors.
                .open(&bridge.host_path)
                .unwrap();
            let mut tokens = vec![0; (slots - 1) as usize];
            reader.read_exact(&mut tokens).unwrap();
            assert_eq!(tokens, vec![b'|'; (slots - 1) as usize]);
            assert_eq!(
                reader.read(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "the implicit slot must never become an extra readable token"
            );
            let path = bridge.host_path.clone();
            drop(bridge);
            assert!(!path.exists());
            assert_eq!(reader.read(&mut [0]).unwrap(), 0);
            assert_eq!(std::fs::read_dir(workspace.path()).unwrap().count(), 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bridge_runtime_is_private_and_independent_for_each_attempt() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let first = JobserverBridge::mint(2, home.path()).unwrap();
        let second = JobserverBridge::mint(3, home.path()).unwrap();
        assert_ne!(first.host_path, second.host_path);
        assert_ne!(first._directory.path(), second._directory.path());
        assert!(first.makeflags().contains("fifo:/__rabs/home/.rabs-jobserver-"));
        assert!(!first.makeflags().contains("/__rabs/workspace"));
        assert_eq!(
            std::fs::metadata(first._directory.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let first_dir = first._directory.path().to_path_buf();
        drop(first);
        assert!(!first_dir.exists());
        assert!(second.host_path.exists(), "retiring one attempt must not unlink another FIFO");
        drop(second);
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bridge_replaces_both_auth_channels_and_capacity_without_duplicates() {
        let home = tempfile::tempdir().unwrap();
        let bridge = JobserverBridge::mint(2, home.path()).unwrap();
        let mut env = env_of(&[
            ("MAKEFLAGS", "-j999 --jobserver-auth=3,4"),
            ("MAKEFLAGS", "duplicate"),
            ("CARGO_MAKEFLAGS", "--jobserver-auth=fifo:/other-worker"),
            ("MFLAGS", "-j999"),
            ("NUM_JOBS", "999"),
            ("PATH", "/bin"),
        ]);
        JobserverBridge::apply(&mut env, &bridge);
        let once = env.clone();
        JobserverBridge::apply(&mut env, &bridge);
        assert_eq!(env, once);
        assert_eq!(env.len(), 4);
        let map: std::collections::BTreeMap<_, _> = env.into_iter().collect();
        assert_eq!(map["MAKEFLAGS"], bridge.makeflags());
        assert_eq!(map["CARGO_MAKEFLAGS"], bridge.makeflags());
        assert_eq!(map["NUM_JOBS"], "2");
        assert_eq!(map["PATH"], "/bin");
    }

    #[test]
    fn replace_installs_single_sorted_worker_budget() {
        let mut env = env_of(&[
            ("RUST_LOG", "debug"),
            ("MAKEFLAGS", "-j999 --jobserver-auth=3,4"),
            ("PATH", "/bin"),
            ("MFLAGS", "smuggled"),
            ("NUM_JOBS", "999"),
        ]);
        replace_with_worker_local(&mut env, 12);
        assert_eq!(
            env,
            vec![
                ("MAKEFLAGS".to_string(), "-j12".to_string()),
                ("NUM_JOBS".to_string(), "12".to_string()),
                ("PATH".to_string(), "/bin".to_string()),
                ("RUST_LOG".to_string(), "debug".to_string()),
            ]
        );
    }

    #[test]
    fn replace_is_idempotent() {
        let mut env = env_of(&[("PATH", "/bin")]);
        replace_with_worker_local(&mut env, 4);
        let once = env.clone();
        replace_with_worker_local(&mut env, 4);
        assert_eq!(once, env, "re-running the replacement changes nothing");
    }

    #[test]
    fn i003_client_capacity_claims_are_replaced_by_canonical_value() {
        let mut env = env_of(&[("NUM_JOBS", "999"), ("PATH", "/bin")]);
        assert!(is_local_capacity_var("NUM_JOBS"));
        assert!(!is_local_capacity_var("NUM_JOBS_V2"));
        replace_with_worker_local(&mut env, 3);
        let map: std::collections::BTreeMap<_, _> = env.into_iter().collect();
        assert_eq!(map.get("NUM_JOBS").unwrap(), "3", "canonical capacity wins");
        assert_eq!(
            map.get("MAKEFLAGS").unwrap(),
            "-j3",
            "budget and capacity agree"
        );
    }
}
