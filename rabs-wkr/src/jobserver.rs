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
//! Descriptor-level injection (passing real jobserver FDs to processes
//! inside the namespace) is deliberately NOT here: bwrap offers no fd
//! passthrough primitive, and that bridge is exactly beads I002/I004.

/// Env var names that carry make/cargo coordination state.
pub const COORDINATION_ENV_VARS: &[&str] = &["CARGO_MAKEFLAGS", "MAKEFLAGS", "MFLAGS"];

/// Whether `name` is a coordination variable (exact, case-sensitive:
/// canonical env keys are uppercase by construction and I21 forbids
/// fuzzy matching).
#[must_use]
pub fn is_coordination_var(name: &str) -> bool {
    COORDINATION_ENV_VARS.contains(&name)
}

/// Remove every client-supplied coordination variable in place.
pub fn strip_client_coordination(env: &mut Vec<(String, String)>) {
    env.retain(|(k, _)| !is_coordination_var(k));
}

/// The worker-authored parallelism budget. Floors at 1 slot: an action
/// must never see `-j0` (make treats 0 as "unbounded" in some code
/// paths, which would silently defeat the budget).
#[must_use]
pub fn worker_makeflags(slots: u32) -> String {
    format!("-j{}", slots.max(1))
}

/// Replace any client coordination state with the worker-local budget:
/// strip [`COORDINATION_ENV_VARS`], then author exactly one
/// `MAKEFLAGS=-j<slots>`. Output stays name-sorted (I21 presentation).
pub fn replace_with_worker_local(env: &mut Vec<(String, String)>, slots: u32) {
    strip_client_coordination(env);
    env.push(("MAKEFLAGS".to_string(), worker_makeflags(slots)));
    env.sort_by(|a, b| a.0.cmp(&b.0));
    env.dedup_by(|a, b| a.0 == b.0);
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
    }

    #[test]
    fn replace_installs_single_sorted_worker_budget() {
        let mut env = env_of(&[
            ("RUST_LOG", "debug"),
            ("MAKEFLAGS", "-j999 --jobserver-auth=3,4"),
            ("PATH", "/bin"),
            ("MFLAGS", "smuggled"),
        ]);
        replace_with_worker_local(&mut env, 12);
        assert_eq!(
            env,
            vec![
                ("MAKEFLAGS".to_string(), "-j12".to_string()),
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
}
