//! RCH is a Rust-only project (JE, 2026-11-10: "this is supposed to be an
//! exclusively RUST project, no python!!!!"). No rch, rchd, rch-wkr or shim
//! code path may start a Python interpreter on any host: not directly, not as
//! a `python3 -c` program inside a shell snippet sent over SSH, not through a
//! generated `#!/usr/bin/env python3` script, and not from a test.
//!
//! Worker-side logic belongs in `rch-wkr` subcommands (Rust) or plain POSIX sh.
//!
//! This guard counts every line that mentions Python in every Rust source and
//! shell script of the workspace (shell scripts are embedded into the binaries
//! with `include_str!`), and counts `.py` files. `NAMED_ONLY` lists the few
//! places that merely NAME Python as a foreign command, tag or value and never
//! run it. `PORT_DEBT` and `PY_FILES_DEBT` record what remains from before the
//! rule. They may only go DOWN: a port lowers or removes its entry in the same
//! commit, and no entry is ever added or raised. See AGENTS.md
//! "RULE 0.75 - RUST ONLY: NO PYTHON, EVER".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Mentions that never execute Python (classifier fixtures, tags, values).
const NAMED_ONLY: &[(&str, usize)] = &[
    ("rch-common/src/config/env.rs", 1),
    ("rch-common/src/patterns.rs", 1),
    ("rch-common/src/types.rs", 1),
    ("rch/src/config.rs", 1),
    ("rch/src/hook/cargo_target_dir.rs", 1),
    ("rchd/src/config.rs", 1),
    ("rchd/src/process_triage.rs", 1),
];

/// `.py` files left in the workspace. Shrink only.
const PY_FILES_DEBT: usize = 91;

/// Sources that still run Python. Shrink only; never add or raise an entry.
const PORT_DEBT: &[(&str, usize)] = &[
    ("install.sh", 4),
    ("rabs-key/src/bin/layer0_render.rs", 5),
    ("rch-common/src/ssh.rs", 6),
    ("rch-common/src/stale_target_reap.rs", 5),
    ("rch-common/src/toolchain/worker_cache.rs", 7),
    ("rch-common/tests/control_deadlines.rs", 2),
    ("rch-common/tests/isolated_staging.rs", 2),
    ("rch-common/tests/process_identity_threads.rs", 3),
    ("rch-common/tests/process_triage_e2e.rs", 4),
    ("rch-common/tests/remote_launch_once.rs", 1),
    ("rch-common/tests/remote_process_threads.rs", 2),
    ("rch-common/tests/remote_reboot_recovery.rs", 1),
    ("rch-common/tests/remote_scope_recovery.rs", 2),
    ("rch-common/tests/remote_scoped_backpressure.rs", 1),
    ("rch-common/tests/remote_scoped_launch.rs", 2),
    ("rch-common/tests/remote_scoped_stdin.rs", 1),
    ("rch-common/tests/worker_execution_policy.rs", 2),
    ("rch-wkr/src/executor.rs", 1),
    ("rch-wkr/tests/output_completion.rs", 2),
    ("rch-wkr/tests/prepare_transactions.rs", 2),
    ("rch-wkr/tests/toolchain_execution.rs", 11),
    ("rch/src/cache_gc.rs", 2),
    ("rch/src/hook/repo_updater/status_probe.rs", 2),
    ("rch/src/hook/source_fidelity.rs", 1),
    ("rch/src/hook/source_namespace_control.sh", 18),
    ("rch/src/hook/ssh.rs", 5),
    ("rch/src/hook/tests.rs", 5),
    ("rch/src/hook/transfer_orchestration.rs", 3),
    ("rch/src/main.rs", 1),
    ("rch/src/transfer.rs", 14),
    ("rch/src/transfer/node_prepare_tests.rs", 2),
    ("rch/src/update/install/daemon_shutdown.rs", 2),
    ("rch/tests/git_archive_cache.rs", 2),
    ("rch/tests/integration/command_tests.rs", 1),
    ("rch/tests/node_prepare_paths.rs", 1),
    ("rch/tests/source_claim_inventory.rs", 1),
    ("rch/tests/source_lock_holder.rs", 5),
    ("rch/tests/source_namespace_control.rs", 1),
    ("rch/tests/source_topology_protocol.rs", 2),
    ("rchd/tests/daemon_lifecycle.rs", 4),
    ("rchd/tests/source_registry_health.rs", 2),
    ("scripts/ci_validation_gate.sh", 6),
    ("scripts/e2e_bd-ceewf.sh", 4),
    ("scripts/e2e_bd-zbtgb.sh", 2),
    ("scripts/e2e_bun_prepare.sh", 5),
    ("scripts/e2e_config_rollout_logs.sh", 5),
    ("scripts/e2e_config_rollout.sh", 5),
    ("scripts/e2e_discovery_surfaces.sh", 8),
    ("scripts/e2e_fleet_reconciliation.sh", 5),
    ("scripts/e2e_l0_pack.sh", 3),
    ("scripts/e2e_perf_budgets.sh", 5),
    ("scripts/e2e_placement_controls.sh", 6),
    ("scripts/e2e_real_fleet_smoke.sh", 5),
    ("scripts/e2e_remediation_views.sh", 7),
    ("scripts/e2e_self_test_full.sh", 1),
    ("scripts/e2e_storm_control.sh", 5),
    ("scripts/rabs_layer0_bench.sh", 1),
    ("scripts/test_dependabot_automerge_workflow.sh", 6),
    ("scripts/test_update_signature_verification.sh", 2),
    ("scripts/test_verbose_flag.sh", 1),
];

const THIS_FILE: &str = "rch-common/tests/no_python_guard.rs";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rch-common lives inside the workspace")
        .to_path_buf()
}

#[derive(Default)]
struct Scan {
    /// `.rs` and `.sh` files, relative to the workspace root.
    sources: Vec<PathBuf>,
    py_files: Vec<PathBuf>,
}

fn scan(dir: &Path, root: &Path, found: &mut Scan) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let relative = || path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        if kind.is_dir() {
            // Build output and VCS/agent state are not sources.
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            scan(&path, root, found);
        } else if kind.is_file() {
            if name.ends_with(".rs") || name.ends_with(".sh") {
                found.sources.push(relative());
            } else if name.ends_with(".py") {
                found.py_files.push(relative());
            }
        }
    }
}

fn workspace_scan() -> (PathBuf, Scan) {
    let root = workspace_root();
    let mut found = Scan::default();
    scan(&root, &root, &mut found);
    (root, found)
}

fn python_mentions(root: &Path, sources: &[PathBuf]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for relative in sources {
        let key = relative.to_string_lossy().replace('\\', "/");
        if key == THIS_FILE {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(root.join(relative)) else {
            continue;
        };
        let count = text
            .lines()
            .filter(|line| line.to_ascii_lowercase().contains("python"))
            .count();
        if count > 0 {
            counts.insert(key, count);
        }
    }
    counts
}

#[test]
fn rust_sources_never_gain_python() {
    let (root, found) = workspace_scan();
    let actual = python_mentions(&root, &found.sources);
    let allowed: BTreeMap<&str, usize> = NAMED_ONLY.iter().chain(PORT_DEBT).copied().collect();
    assert_eq!(
        allowed.len(),
        NAMED_ONLY.len() + PORT_DEBT.len(),
        "a file is listed twice"
    );

    let mut violations = Vec::new();
    for (file, &count) in &actual {
        match allowed.get(file.as_str()) {
            None => violations.push(format!(
                "{file}: {count} new line(s) mention Python. RCH is Rust-only: port it to \
                 Rust (an rch-wkr subcommand for worker-side logic) or POSIX sh."
            )),
            Some(&limit) if count > limit => violations.push(format!(
                "{file}: {count} Python lines, limit {limit}. PORT_DEBT may only shrink."
            )),
            Some(&limit) if count < limit => violations.push(format!(
                "{file}: {count} Python lines, limit {limit}. Ratchet: lower its entry in \
                 tests/no_python_guard.rs to {count} (remove it at 0)."
            )),
            Some(_) => {}
        }
    }
    for (file, limit) in &allowed {
        if !actual.contains_key(*file) {
            violations.push(format!(
                "{file}: no Python left (limit {limit}). Ratchet: remove its entry."
            ));
        }
    }
    let py_files = found.py_files.len();
    if py_files > PY_FILES_DEBT {
        let mut names: Vec<String> = found
            .py_files
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        names.sort();
        violations.push(format!(
            "{py_files} .py files, limit {PY_FILES_DEBT}. Never add Python files: {}",
            names.join(", ")
        ));
    } else if py_files < PY_FILES_DEBT {
        violations.push(format!(
            "{py_files} .py files, limit {PY_FILES_DEBT}. Ratchet: lower PY_FILES_DEBT to {py_files}."
        ));
    }
    assert!(
        violations.is_empty(),
        "Rust-only guard failed:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn guard_sees_the_workspace() {
    // A guard that silently scans nothing would pass forever.
    let (_, found) = workspace_scan();
    assert!(
        found
            .sources
            .iter()
            .any(|path| path.ends_with("rch-common/src/lib.rs")),
        "the workspace scan did not find rch-common/src/lib.rs"
    );
    assert!(
        found
            .sources
            .iter()
            .any(|path| path.ends_with("rch-common/src/remote_process.sh")),
        "the workspace scan did not find the embedded shell scripts"
    );
    assert!(
        found.sources.len() > 100,
        "only {} sources found",
        found.sources.len()
    );
}
