//! Redacted RABS invocation recorder in the live hook path (bead B002).
//!
//! Every offloaded invocation that completes through the hook emits one
//! B001 [`InvocationRecord`] (rabs-protocol's schema — redaction applied
//! at construction, digests over raw bytes, signal-vs-exit preserved) as
//! an NDJSON line under `~/.cache/rch/rabs-corpus/invocations.ndjsonl`.
//! Real agent traces from the live RCH fleet are the highest-value RABS
//! corpus, so recording starts here, before any RABS daemons exist.
//!
//! Discipline:
//!
//! - **Off the SLO path**: callers invoke this from `spawn_blocking`
//!   AFTER the build completed, alongside `record_build_timing` — the
//!   hook's decision latency never pays for it.
//! - **Fail-open**: every error is a `debug!` log and a dropped record;
//!   recording can never affect a build.
//! - **No source bytes, no secrets**: the only payload fields are the
//!   B001 record's — redacted presentation forms and correlation
//!   digests. The env capture is a bounded, build-relevant subset
//!   (`CARGO*`/`RUST*` names), and redaction still applies to it.
//! - **Bounded disk**: one rotation at [`MAX_SPOOL_BYTES`]
//!   (`.ndjsonl` → `.ndjsonl.1`, previous `.1` dropped) keeps the
//!   spool ≤ 2× the cap.
//! - **Honest coverage boundary**: only tools in B001's `ToolKind`
//!   vocabulary are recorded (the Rust-path corpus). Build-system and
//!   Bun/Nix commands map to no kind and are skipped with a debug log,
//!   never mislabeled. Local-fallback commands are executed by the
//!   AGENT after the hook allows them — the hook never observes their
//!   outcome, so they cannot be recorded here.

use std::path::{Path, PathBuf};

use rabs_protocol::invocation_record::{
    INVOCATION_RECORD_VERSION, InvocationRecord, NormalizedOutcome, ToolKind,
};
use rabs_protocol::raw_bytes::RawBytes;

use super::*;

/// Spool rotation threshold (bytes).
pub(super) const MAX_SPOOL_BYTES: u64 = 64 * 1024 * 1024;

/// Map RCH's classification to B001's tool vocabulary. `None` = outside
/// the corpus schema (skipped honestly, never mislabeled).
pub(super) const fn tool_kind_for(kind: CompilationKind) -> Option<ToolKind> {
    match kind {
        CompilationKind::CargoBuild
        | CompilationKind::CargoTest
        | CompilationKind::CargoCheck
        | CompilationKind::CargoClippy
        | CompilationKind::CargoDoc
        | CompilationKind::CargoBench
        | CompilationKind::CargoZigbuild => Some(ToolKind::CargoWholeCommand),
        CompilationKind::CargoNextest => Some(ToolKind::Nextest),
        CompilationKind::Rustc => Some(ToolKind::Rustc),
        CompilationKind::Gcc | CompilationKind::Clang => Some(ToolKind::NativeCc),
        CompilationKind::Gpp | CompilationKind::Clangpp => Some(ToolKind::NativeCxx),
        _ => None,
    }
}

/// Decode the hook's exit-code convention back into the B001 outcome:
/// `128 + N` means the remote tool died by signal N (the transfer layer
/// forwards wait statuses in that convention), everything else is a
/// plain exit. Signal-vs-exit is thereby PRESERVED in the record (R94).
pub(super) fn normalized_outcome(exit_code: i32) -> NormalizedOutcome {
    is_signal_killed(exit_code).map_or(NormalizedOutcome::Exited(exit_code), |signal| {
        NormalizedOutcome::Signaled(signal)
    })
}

/// The bounded, build-relevant environment subset: `CARGO*`/`RUST*`
/// names, as raw bytes (A019). Redaction of VALUES happens inside
/// `InvocationRecord::capture`; this filter only bounds the capture.
fn relevant_env() -> Vec<(RawBytes, RawBytes)> {
    #[cfg(unix)]
    fn to_raw(s: std::ffi::OsString) -> RawBytes {
        use std::os::unix::ffi::OsStrExt;
        RawBytes::new(s.as_os_str().as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    fn to_raw(s: std::ffi::OsString) -> RawBytes {
        RawBytes::new(s.to_string_lossy().into_owned().into_bytes())
    }
    let mut pairs: Vec<(RawBytes, RawBytes)> = std::env::vars_os()
        .filter(|(k, _)| {
            let name = k.to_string_lossy();
            name.starts_with("CARGO") || name.starts_with("RUST")
        })
        .map(|(k, v)| (to_raw(k), to_raw(v)))
        .collect();
    pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    pairs
}

/// Serialize one record as its NDJSON line. The encoding is owned HERE
/// (rabs-protocol stays serde-free); field names mirror the B001 struct
/// so the replay tooling reads them stably.
pub(super) fn record_to_ndjson(record: &InvocationRecord) -> String {
    let (outcome_kind, outcome_value) = match record.outcome {
        NormalizedOutcome::Exited(code) => ("exited", code),
        NormalizedOutcome::Signaled(signal) => ("signaled", signal),
    };
    serde_json::json!({
        "schema": "rabs.invocation-record",
        "schema_version": record.schema_version,
        "tool": format!("{:?}", record.tool),
        "argv_correlation": record.argv_correlation,
        "argv_redacted": record.argv_redacted,
        "env_correlation": record.env_correlation,
        "env_redacted": record.env_redacted,
        "cwd_redacted": record.cwd_redacted,
        "outcome_kind": outcome_kind,
        "outcome_value": outcome_value,
        "duration_ms": record.duration_ms,
    })
    .to_string()
}

/// Spool file path.
fn spool_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| {
        dir.join("rch")
            .join("rabs-corpus")
            .join("invocations.ndjsonl")
    })
}

/// Append one line with single-file rotation at `max_bytes`. Fail-open:
/// all errors return `Err` for the caller to `debug!`-log and drop.
pub(super) fn append_line(path: &Path, line: &str, max_bytes: u64) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(meta) = std::fs::metadata(path)
        && meta.len() >= max_bytes
    {
        let rotated = path.with_extension("ndjsonl.1");
        // The previous rotation is dropped: spool stays <= 2x cap.
        let _ = std::fs::remove_file(&rotated);
        std::fs::rename(path, &rotated)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")
}

/// Record one completed offloaded invocation. Called from
/// `spawn_blocking` after the build finished — never on the decision
/// path. Every failure mode is fail-open.
pub(super) fn record_invocation(
    command: &str,
    cwd: &Path,
    kind: Option<CompilationKind>,
    exit_code: i32,
    duration_ms: u64,
) {
    let Some(kind) = kind else {
        debug!("rabs-recorder: unclassified command, skipping");
        return;
    };
    let Some(tool) = tool_kind_for(kind) else {
        debug!("rabs-recorder: {kind:?} outside the B001 tool vocabulary, skipping");
        return;
    };
    let home = dirs::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();
    // The hook intercepts one SHELL COMMAND; that string is the argv
    // evidence we actually have (element boundaries inside it are the
    // shell's business). One element keeps the correlation byte-exact.
    let argv = [RawBytes::new(command.as_bytes().to_vec())];
    let cwd_raw = RawBytes::new(cwd.to_string_lossy().into_owned().into_bytes());
    let record = InvocationRecord::capture(
        tool,
        &argv,
        &relevant_env(),
        &cwd_raw,
        &home,
        normalized_outcome(exit_code),
        duration_ms,
    );
    debug_assert_eq!(record.schema_version, INVOCATION_RECORD_VERSION);
    let Some(path) = spool_path() else {
        debug!("rabs-recorder: no cache dir, dropping record");
        return;
    };
    let line = record_to_ndjson(&record);
    if let Err(e) = append_line(&path, &line, MAX_SPOOL_BYTES) {
        debug!("rabs-recorder: append failed (fail-open): {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b002_tool_mapping_covers_rust_path_and_skips_the_rest() {
        // Rust-path kinds map into the B001 vocabulary…
        assert_eq!(
            tool_kind_for(CompilationKind::CargoBuild),
            Some(ToolKind::CargoWholeCommand)
        );
        assert_eq!(
            tool_kind_for(CompilationKind::CargoNextest),
            Some(ToolKind::Nextest)
        );
        assert_eq!(tool_kind_for(CompilationKind::Rustc), Some(ToolKind::Rustc));
        assert_eq!(
            tool_kind_for(CompilationKind::Gcc),
            Some(ToolKind::NativeCc)
        );
        assert_eq!(
            tool_kind_for(CompilationKind::Clangpp),
            Some(ToolKind::NativeCxx)
        );
        // …and build-system kinds are honestly OUTSIDE it (skipped,
        // never mislabeled as a cargo command).
        assert_eq!(tool_kind_for(CompilationKind::Make), None);
    }

    #[test]
    fn b002_signal_vs_exit_is_preserved_through_the_hook_convention() {
        assert_eq!(normalized_outcome(0), NormalizedOutcome::Exited(0));
        assert_eq!(normalized_outcome(101), NormalizedOutcome::Exited(101));
        // 128+N decodes back to the SIGNAL, never flattened (R94).
        assert_eq!(normalized_outcome(137), NormalizedOutcome::Signaled(9));
        assert_eq!(normalized_outcome(139), NormalizedOutcome::Signaled(11));
    }

    #[test]
    fn b002_ndjson_lines_validate_against_the_schema_and_carry_no_secrets() {
        let argv = [RawBytes::from("cargo publish --token=tok_live_supersecret")];
        let env = [(
            RawBytes::from("CARGO_REGISTRY_TOKEN"),
            RawBytes::from("tok_live_supersecret"),
        )];
        let record = InvocationRecord::capture(
            ToolKind::CargoWholeCommand,
            &argv,
            &env,
            &RawBytes::from("/Users/alice/work/repo"),
            "/Users/alice",
            NormalizedOutcome::Exited(0),
            2500,
        );
        let line = record_to_ndjson(&record);
        // Validates as one JSON object with the schema fields.
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["schema"], "rabs.invocation-record");
        assert_eq!(
            parsed["schema_version"],
            u64::from(INVOCATION_RECORD_VERSION)
        );
        assert_eq!(parsed["tool"], "CargoWholeCommand");
        assert_eq!(parsed["outcome_kind"], "exited");
        assert_eq!(parsed["outcome_value"], 0);
        assert_eq!(parsed["duration_ms"], 2500);
        assert_eq!(parsed["cwd_redacted"], "~/work/repo");
        assert!(parsed["argv_correlation"].is_u64());
        // The secret never appears anywhere in the line.
        assert!(
            !line.contains("tok_live_supersecret"),
            "secret leaked into the spool line: {line}"
        );
        // The B004 raw-content audit stays empty through this path.
        assert!(record.raw_content_fields().is_empty());
    }

    #[test]
    fn b002_spool_appends_and_rotates_boundedly() {
        let dir = std::env::temp_dir().join(format!(
            "rabs-recorder-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("invocations.ndjsonl");
        // Two appends land in order.
        append_line(&path, "{\"a\":1}", 1024).unwrap();
        append_line(&path, "{\"b\":2}", 1024).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "{\"a\":1}\n{\"b\":2}\n");
        // Crossing the cap rotates: current file starts fresh, previous
        // generation is preserved at .1, and a SECOND rotation drops the
        // oldest — total disk stays bounded at <= 2x the cap.
        let cap = content.len() as u64; // already at cap
        append_line(&path, "{\"c\":3}", cap).unwrap();
        let rotated = path.with_extension("ndjsonl.1");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"c\":3}\n",
            "fresh spool after rotation"
        );
        assert_eq!(
            std::fs::read_to_string(&rotated).unwrap(),
            "{\"a\":1}\n{\"b\":2}\n"
        );
        append_line(&path, "{\"d\":4}", 1).unwrap();
        assert_eq!(std::fs::read_to_string(&rotated).unwrap(), "{\"c\":3}\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"d\":4}\n");
    }
}
