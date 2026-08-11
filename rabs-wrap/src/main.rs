//! `rabs-wrap` — the RABS tiny `RUSTC_WRAPPER` binary (bead S2 /
//! bridge plan Phase S).
//!
//! Invocation contract (Cargo): `rabs-wrap <real-rustc> <rustc args…>`.
//! The wrapper's whole job fits the p95 <10ms budget:
//!
//! 1. classify — version/target-info probes (`-vV`, `--crate-name ___`)
//!    exec the real chain instantly, zero consult;
//! 2. read the breaker-state file → `wrapper_breaker::decide` (the
//!    C-epic state machine, live);
//! 3. on `Attempt`/`Probe`: UDS connect + C001-shaped hello + consult
//!    frame under the breaker's OWN budgets (read/write timeouts);
//!    shadow decisions are always pass-through;
//! 4. `on_outcome` update persisted (probe starts persisted WRITE-AHEAD
//!    per the breaker contract);
//! 5. `exec` the real rustc — the wrapper process BECOMES the compiler,
//!    so exit codes, signals, and stdio streaming are preserved by
//!    construction (no buffering exists to get wrong).
//!
//! Failure philosophy: every wrapper-side problem — no daemon, timeout,
//! malformed reply, unreadable state file — degrades to local exec.
//! A build must never fail because RABS had a bad day (fail-open).

use rabs_protocol::wrapper_breaker::{
    AttemptOutcome, BreakerPolicy, BreakerState, ConnectDecision, decide, decode_state,
    encode_state, on_outcome,
};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::time::Duration;

/// Minimal JSON string encoder (quotes + escapes; no serde by design).
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn default_under_home(rel: &str) -> String {
    std::env::var("HOME").map_or_else(|_| format!("/tmp/{rel}"), |h| format!("{h}/{rel}"))
}

fn breaker_path() -> String {
    std::env::var("RABS_BREAKER_FILE")
        .unwrap_or_else(|_| default_under_home(".cache/rch/rabs-breaker"))
}

fn socket_path() -> String {
    std::env::var("RABS_SOCKET_PATH")
        .unwrap_or_else(|_| default_under_home(".cache/rch/rabsd.sock"))
}

/// Probes never consult: they are sub-millisecond cargo internals.
fn is_probe(args: &[String]) -> bool {
    args.iter().any(|a| a == "-vV" || a == "-V")
        || args
            .windows(2)
            .any(|w| w[0] == "--crate-name" && w[1] == "___")
}

fn load_state(path: &str) -> BreakerState {
    // Missing/corrupt state fails OPEN to a fresh closed breaker (the
    // module contract: broken bookkeeping never blocks a build).
    std::fs::read(path)
        .ok()
        .and_then(|bytes| decode_state(&bytes))
        .unwrap_or_else(BreakerState::fresh)
}

fn store_state(path: &str, state: &BreakerState) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, encode_state(state));
}

const HELLO: &str = "{\"kind\":\"hello\",\
    \"transport\":{\"minimum_compatible\":1,\"current\":1},\
    \"application\":{\"minimum_compatible\":1,\"current\":1}}";

/// One consult attempt under the breaker budgets. Ok(()) = decision
/// received (shadow: always pass-through).
fn consult(
    socket: &str,
    connect_timeout_ms: u32,
    decision_timeout_ms: u32,
    args: &[String],
) -> Result<(), ()> {
    // std UDS has no connect timeout: connect on a helper thread and
    // bound the wait. A short-lived process reaps stragglers at exit.
    let (sender, receiver) = std::sync::mpsc::channel();
    let socket_owned = socket.to_string();
    std::thread::spawn(move || {
        let _ = sender.send(std::os::unix::net::UnixStream::connect(socket_owned));
    });
    let stream = receiver
        .recv_timeout(Duration::from_millis(u64::from(connect_timeout_ms)))
        .map_err(|_| ())?
        .map_err(|_| ())?;
    let budget = Duration::from_millis(u64::from(decision_timeout_ms));
    stream.set_read_timeout(Some(budget)).map_err(|_| ())?;
    stream.set_write_timeout(Some(budget)).map_err(|_| ())?;

    let mut writer = stream.try_clone().map_err(|_| ())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    writer.write_all(HELLO.as_bytes()).map_err(|_| ())?;
    writer.write_all(b"\n").map_err(|_| ())?;
    reader.read_line(&mut line).map_err(|_| ())?;
    if !line.contains("hello-ok") {
        return Err(());
    }

    // The full S4 observation: real argv, cwd, CARGO_*/RUSTC_* env
    // NAMES (values never leave the process in shadow tier). The
    // daemon computes the Epic F key and redacts before persisting.
    let argv_json: Vec<String> = args.iter().map(|a| json_string(a)).collect();
    let env_names: Vec<String> = std::env::vars()
        .filter(|(name, _)| name.starts_with("CARGO") || name.starts_with("RUSTC"))
        .map(|(name, _)| json_string(&name))
        .collect();
    let cwd = std::env::current_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    let consult_frame = format!(
        "{{\"kind\":\"consult\",\"argv\":[{}],\"cwd\":{},\"env_names\":[{}]}}",
        argv_json.join(","),
        json_string(&cwd),
        env_names.join(","),
    );
    writer.write_all(consult_frame.as_bytes()).map_err(|_| ())?;
    writer.write_all(b"\n").map_err(|_| ())?;
    line.clear();
    reader.read_line(&mut line).map_err(|_| ())?;
    if line.contains("\"decision\"") {
        Ok(())
    } else {
        Err(())
    }
}

fn main() {
    let mut argv = std::env::args().skip(1);
    let Some(real_rustc) = argv.next() else {
        eprintln!("rabs-wrap: usage: rabs-wrap <real-rustc> <args…>");
        std::process::exit(2);
    };
    let args: Vec<String> = argv.collect();

    // Probes: exec instantly, no state, no socket, no consult.
    if !is_probe(&args) {
        // The consult argv is the FULL command the compiler runs:
        // argv[0] is the real tool (the daemon stats it for the
        // toolchain-identity key component and records it as argv0),
        // followed by every rustc argument. Sending only the args would
        // leave the daemon statting `--crate-name` and mislabeling
        // receipts.
        let consult_argv: Vec<String> = std::iter::once(real_rustc.clone())
            .chain(args.iter().cloned())
            .collect();
        let path = breaker_path();
        let policy = BreakerPolicy::default();
        let state = load_state(&path);
        let now = now_ms();
        match decide(&policy, &state, now) {
            ConnectDecision::SkipToLocal => {}
            ConnectDecision::Attempt {
                connect_timeout_ms,
                decision_timeout_ms,
            } => {
                let outcome = consult(
                    &socket_path(),
                    connect_timeout_ms,
                    decision_timeout_ms,
                    &consult_argv,
                );
                let attempt = if outcome.is_ok() {
                    AttemptOutcome::Succeeded
                } else {
                    AttemptOutcome::Failed
                };
                store_state(&path, &on_outcome(&policy, &state, attempt, now));
            }
            ConnectDecision::Probe {
                connect_timeout_ms,
                decision_timeout_ms,
            } => {
                // WRITE-AHEAD: persist the probe start BEFORE attempting
                // (a crash mid-probe must not permit a same-window retry).
                let probing = state.probe_started(now);
                store_state(&path, &probing);
                let outcome = consult(
                    &socket_path(),
                    connect_timeout_ms,
                    decision_timeout_ms,
                    &consult_argv,
                );
                let attempt = if outcome.is_ok() {
                    AttemptOutcome::Succeeded
                } else {
                    AttemptOutcome::Failed
                };
                store_state(&path, &on_outcome(&policy, &probing, attempt, now));
            }
        }
    }

    // Become the compiler. On success this never returns; exit codes,
    // signals, and stdio semantics are the real chain's, exactly.
    let error = std::process::Command::new(&real_rustc).args(&args).exec();
    eprintln!("rabs-wrap: exec {real_rustc}: {error}");
    std::process::exit(127);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_are_classified_and_never_consult() {
        let vv = vec!["-vV".to_string()];
        assert!(is_probe(&vv));
        let cap_v = vec!["-V".to_string()];
        assert!(is_probe(&cap_v));
        let target_info = vec![
            "--crate-name".to_string(),
            "___".to_string(),
            "--print=file-names".to_string(),
        ];
        assert!(is_probe(&target_info));
        let real = vec![
            "--crate-name".to_string(),
            "serde".to_string(),
            "--edition=2021".to_string(),
        ];
        assert!(!is_probe(&real));
    }

    #[test]
    fn state_file_roundtrip_and_corrupt_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("breaker");
        let path_str = path.to_str().unwrap();
        // Missing: fresh closed.
        assert_eq!(load_state(path_str), BreakerState::fresh());
        // Roundtrip.
        let open = BreakerState::Open {
            opened_at_ms: 123,
            last_probe_started_at_ms: None,
        };
        store_state(path_str, &open);
        assert_eq!(load_state(path_str), open);
        // Corrupt: fresh closed, never an error.
        std::fs::write(&path, b"\xff\xfe garbage").unwrap();
        assert_eq!(load_state(path_str), BreakerState::fresh());
    }

    #[test]
    fn consult_against_nothing_fails_within_budget() {
        let start = std::time::Instant::now();
        let result = consult("/nonexistent/rabsd.sock", 25, 50, &[]);
        assert!(result.is_err());
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "daemon-dead consult must fail fast: {:?}",
            start.elapsed()
        );
    }
}
