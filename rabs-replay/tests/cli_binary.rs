//! End-to-end integration tests for the `rabs-replay` CLI binary (W2/B013).

#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;

fn replay_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rabs-replay")
}

#[test]
fn binary_inspect_stratify_and_pair_emit_valid_json() {
    let base = std::env::temp_dir().join(format!("rabs-replay-bin-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();

    let corpus = base.join("invocations.ndjsonl");
    let lines = [
        serde_json::json!({
            "schema": "rabs.invocation-record",
            "schema_version": 1,
            "tool": "CargoWholeCommand",
            "argv_correlation": 11_u64,
            "argv_redacted": ["cargo check --workspace"],
            "env_correlation": 1_u64,
            "env_redacted": ["RUSTUP_TOOLCHAIN=nightly-2026-08-31"],
            "cwd_redacted": "/work/proj_alpha",
            "outcome_kind": "exited",
            "outcome_value": 0,
            "duration_ms": 1200_u64,
            "recorded_at_unix_ms": 10_000_u64,
            "ci_env": false,
        })
        .to_string(),
        serde_json::json!({
            "schema": "rabs.invocation-record",
            "schema_version": 1,
            "tool": "Nextest",
            "argv_correlation": 22_u64,
            "argv_redacted": ["cargo nextest run"],
            "env_correlation": 2_u64,
            "env_redacted": [],
            "cwd_redacted": "/work/proj_beta",
            "outcome_kind": "exited",
            "outcome_value": 101,
            "duration_ms": 4500_u64,
            "recorded_at_unix_ms": 10_500_u64,
            "ci_env": true,
        })
        .to_string(),
        "corrupt line".to_owned(),
    ];
    fs::write(&corpus, lines.join("\n")).unwrap();

    let inspect_out = Command::new(replay_bin())
        .args(["inspect", corpus.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        inspect_out.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&inspect_out.stderr)
    );
    let inspect_json: serde_json::Value = serde_json::from_slice(&inspect_out.stdout).unwrap();
    assert_eq!(inspect_json["schema"], "rabs.replay-inspect.v1");
    assert_eq!(inspect_json["parsed_records"], 2);
    assert_eq!(inspect_json["malformed_lines"], 1);
    assert_eq!(inspect_json["concurrency"]["peak_overlap"], 2);

    let stratify_out = Command::new(replay_bin())
        .args([
            "stratify",
            corpus.to_str().unwrap(),
            "--per-stratum",
            "2",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        stratify_out.status.success(),
        "stratify failed: {}",
        String::from_utf8_lossy(&stratify_out.stderr)
    );
    let stratify_json: serde_json::Value = serde_json::from_slice(&stratify_out.stdout).unwrap();
    assert_eq!(stratify_json["schema"], "rabs.replay-stratify.v1");
    assert_eq!(stratify_json["selected_count"], 2);
    assert_eq!(stratify_json["skipped_malformed"], 1);

    let pair_out = Command::new(replay_bin())
        .args([
            "pair",
            "--workdir",
            base.to_str().unwrap(),
            "--iterations",
            "2",
            "--aa-check",
            "--json",
            "--",
            "sh",
            "-c",
            "printf ok",
        ])
        .output()
        .unwrap();
    assert!(
        pair_out.status.success(),
        "pair failed: {}",
        String::from_utf8_lossy(&pair_out.stderr)
    );
    let pair_json: serde_json::Value = serde_json::from_slice(&pair_out.stdout).unwrap();
    assert_eq!(pair_json["schema"], "rabs.replay-pair.v1");
    assert_eq!(pair_json["divergences"], 0);
    assert_eq!(pair_json["aa_mode"], true);

    let bad = Command::new(replay_bin())
        .arg("unknown-cmd")
        .output()
        .unwrap();
    assert!(!bad.status.success());

    let _ = fs::remove_dir_all(&base);
}
