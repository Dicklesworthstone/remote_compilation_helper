//! E004 acceptance: the resource envelope is ENFORCED in a fixture, and
//! an OOM inside the cgroup is classified `OomKilled` — never a
//! deterministic failure (I16).
//!
//! slice distributes `memory`/`cpu`; hardened uid-1000 hosts skip
//! honestly). The OOM proof spawns a self-staged memory hog attached to a
//! 32 MiB envelope with swap pinned to 0 (so the kernel cannot quietly
//! swap instead of enforcing), waits for the kernel's SIGKILL, reads the
//! advanced `oom_kill` counter, and classifies. A hog that SURVIVES means
//! the envelope did not enforce — loud failure, never a pass.

#![cfg(target_os = "linux")]
use rabs_sandbox::cgroup_envelope::{
    Delegation, ResourceEnvelope, Termination, attach, classify_termination, cleanup_best_effort,
    create_envelope, oom_kill_count, probe_delegation,
};
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;

fn supported() -> Option<Delegation> {
    match probe_delegation() {
        Ok(delegation) => Some(delegation),
        Err(refusal) => {
            eprintln!("skipping E004 live fixtures: {refusal} (measured, not assumed)");
            None
        }
    }
}

fn unique_name(tag: &str) -> String {
    format!(
        "rabs-e004-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    )
}

/// In-hog body. On the host (env unset) this test is a no-op so ordinary
/// runs pass; the fixture sets the marker and attaches THIS binary to a
/// 32 MiB envelope before re-executing it here.
#[test]
fn e004_memory_hog() {
    if std::env::var("RABS_E004_HOG").as_deref() != Ok("1") {
        return;
    }
    // Deterministic handshake: block on stdin until the parent has
    // ATTACHED us to the envelope and writes one byte. No fixed sleep —
    // allocation cannot begin outside the cgroup no matter how loaded
    // the host is.
    let mut go = [0u8; 1];
    std::io::stdin()
        .read_exact(&mut go)
        .expect("parent handshake byte");
    let mut hog = vec![0u8; 256 * 1024 * 1024];
    for page in hog.chunks_mut(4096) {
        page[0] = 1;
    }
    // Surviving to here means the kernel never enforced memory.max.
    println!("E004 hog: allocated and touched 256MiB without being killed");
}

#[test]
fn envelope_bounds_round_trip_and_clean_up() {
    let Some(delegation) = supported() else {
        return;
    };
    let name = unique_name("roundtrip");
    let envelope = ResourceEnvelope {
        memory_max_bytes: Some(64 * 1024 * 1024),
        memory_swap_max_bytes: Some(0),
        cpu_weight: Some(42),
        io_max: Vec::new(),
    };

    let applied = create_envelope(&delegation, &name, &envelope)
        .expect("envelope creation on delegated host");

    // Read-back facts: what the kernel reports AFTER our writes.
    let mem = applied
        .enforced
        .iter()
        .find(|b| b.file == "memory.max")
        .expect("memory.max enforced");
    assert_eq!(mem.value, (64 * 1024 * 1024).to_string());
    let weight = applied
        .enforced
        .iter()
        .find(|b| b.file == "cpu.weight")
        .expect("cpu.weight enforced");
    assert_eq!(weight.value, "42");
    assert!(applied.memory_enforced());

    // Empty subgroup removes cleanly; no janitorial surprises.
    let notes = cleanup_best_effort(&applied);
    assert!(
        notes.is_empty(),
        "cleanup of an empty envelope must be silent: {notes:?}"
    );
}

#[test]
fn oom_inside_cgroup_classified_oom_killed() {
    let Some(delegation) = supported() else {
        return;
    };
    let name = unique_name("oom");
    let envelope = ResourceEnvelope {
        memory_max_bytes: Some(32 * 1024 * 1024),
        // Pin swap to zero: otherwise the kernel may satisfy the hog from
        // swap and the proof becomes a swapping benchmark, not an OOM.
        memory_swap_max_bytes: Some(0),
        cpu_weight: None,
        io_max: Vec::new(),
    };
    let applied = create_envelope(&delegation, &name, &envelope)
        .expect("envelope creation on delegated host");
    assert!(applied.memory_enforced());
    // The proof is only valid when the swap pin is a VERIFIED fact — on
    // hosts without swap accounting the kernel could satisfy the hog from
    // unpinned swap and we would misattribute that to the envelope.
    assert!(
        !applied.skipped.iter().any(|s| s.facet == "memory.swap.max"),
        "swap accounting unavailable; the no-swap-escape precondition of \
         this OOM proof cannot be established — skipping honestly"
    );

    let before = oom_kill_count(&applied).expect("memory.events readable");

    // Stage the probe binary INSIDE nothing special — plain host spawn,
    // then attach its pid to the envelope.
    let exe = std::env::current_exe().expect("test binary path");
    let staging = tempfile::tempdir().expect("staging tempdir");
    let staged = staging.path().join("e004-self");
    std::fs::copy(&exe, &staged).expect("stage hog binary");

    let mut child = std::process::Command::new(&staged)
        .args([
            "--exact".to_string(),
            "e004_memory_hog".to_string(),
            "--nocapture".to_string(),
        ])
        .env("RABS_E004_HOG", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn hog");

    // Deterministic ordering: attach FIRST, then release the hog. The
    // child blocks reading one stdin byte, so allocation cannot begin
    // outside the cgroup regardless of host load (no sleep race).
    attach(&applied, child.id()).expect("attach hog pid to envelope");
    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(b"go")
        .expect("release hog handshake");
    drop(child.stdin.take());

    let output = child.wait().expect("wait hog");
    let signal = output.signal();
    let code = output.code();
    let after = oom_kill_count(&applied).expect("memory.events readable after run");
    let delta = after.saturating_sub(before);

    // Survived: the envelope did NOT enforce — acceptance fails loudly.
    if code == Some(0) {
        let janitor = cleanup_best_effort(&applied);
        panic!(
            "ENVELOPE NOT ENFORCED: memory hog survived a 32MiB memory.max \
             (oom_kill delta={delta}, cleanup={janitor:?})"
        );
    }

    assert!(
        delta >= 1,
        "expected the cgroup oom_kill counter to advance"
    );
    assert_eq!(
        classify_termination(code, signal, delta),
        Termination::OomKilled,
        "SIGKILL under an advancing oom_kill counter must classify OomKilled \
         (never a deterministic failure, I16)"
    );

    // Process is gone; teardown must be silent.
    let notes = cleanup_best_effort(&applied);
    assert!(notes.is_empty(), "cleanup after OOM: {notes:?}");
}
