//! I002 acceptance: root-permit gating + jobserver validity for managed
//! Cargo processes, against REAL processes and REAL nested make.
//!
//! 1. Permit lifecycle: a second launch cannot start while the first
//!    holds the only root (bounded wait times out); finishing A admits B.
//! 2. Crash-release: a panicking holder releases the root via RAII while
//!    the OPEN obligation names the leak at region close.
//! 3. Jobserver protocol validity: the action consumes EXACTLY the
//!    preloaded token bytes through the fifo BY PATH (the identical
//!    handshake nested make performs).
//! 4. Nested make builds successfully under the injected auth env.

#![cfg(target_os = "linux")]

use std::time::Duration;

use rabs_asupersync::cargo_launch::{CargoLaunchGate, LaunchError};
use rabs_asupersync::obligations::ObligationSet;
use rabs_asupersync::process_groups::ProcessGroupSpec;
use rabs_asupersync::root_permits::RootPermitBroker;

fn gate_with_roots(n: usize) -> CargoLaunchGate {
    // RootPermitBroker::new already returns Arc<Self>.
    CargoLaunchGate::new(RootPermitBroker::new(n))
}

fn spec(script: &str) -> ProcessGroupSpec {
    ProcessGroupSpec::new("sh", ["-c".to_owned(), script.to_owned()])
}

#[test]
fn permit_gate_bounds_concurrent_launches() {
    let gate = gate_with_roots(1);
    // An ObligationSet scopes ONE region/attempt: each managed launch
    // carries its own set — a second permit's release must never fold
    // into an already-resolved ledger.
    let mut set_a = ObligationSet::default();

    let mut first = gate
        .launch(
            &spec("sleep 30"),
            &mut set_a,
            2,
            Duration::from_millis(100),
            |_| {},
        )
        .expect("first launch admitted");
    let mut set_b = ObligationSet::default();
    match gate.launch(
        &spec("true"),
        &mut set_b,
        2,
        Duration::from_millis(80),
        |_| {},
    ) {
        Err(LaunchError::PermitTimeout(_)) => {}
        other => panic!("expected PermitTimeout, got {other:?}"),
    }

    // Finishing A returns the root exactly once; B is admitted after.
    let status = first.wait_leader().expect("wait A");
    assert_eq!(status.code(), Some(0));
    first.finish(&mut set_a).expect("A releases cleanly");

    let mut second = gate
        .launch(
            &spec("true"),
            &mut set_b,
            2,
            Duration::from_millis(500),
            |_| {},
        )
        .expect("second launch admitted after release");
    let status = second.wait_leader().expect("wait B");
    assert_eq!(status.code(), Some(0));
    second.finish(&mut set_b).expect("B releases cleanly");
}

#[test]
fn panicking_holder_releases_root_but_names_the_leak() {
    let gate = gate_with_roots(1);

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut set = ObligationSet::default();
        let launched = gate
            .launch(
                &spec("sleep 30"),
                &mut set,
                2,
                Duration::from_millis(100),
                |_| {},
            )
            .expect("admitted");
        // Holder "crashes" mid-flight without finishing.
        drop(launched);
        set
    }));
    let leaked_set = outcome.expect("unwind caught");

    // The root returned to A pool via RAII: a fresh broker-backed gate
    // admits immediately (pool accounting was never over-granted).
    let fresh_gate = gate_with_roots(1);
    let mut fresh_set = ObligationSet::default();
    let relaunch = fresh_gate
        .launch(
            &spec("true"),
            &mut fresh_set,
            2,
            Duration::from_millis(200),
            |_| {},
        )
        .expect("RAII returned the root");
    relaunch.finish(&mut fresh_set).expect("clean finish");

    // …while the CRASHED holder's set still names the unresolved
    // obligation — may_close_region refuses until someone owns it.
    assert!(
        leaked_set.may_close_region().is_err(),
        "crashed holder's leak must be named by the ledger"
    );
}

#[test]
fn action_consumes_exactly_the_preloaded_token_bytes() {
    let gate = gate_with_roots(2);
    const TOKENS: usize = 4;

    let out_path = std::env::temp_dir().join(format!("rabs-i002-count-{}", std::process::id()));
    let _ = std::fs::remove_file(&out_path);

    let mut set = ObligationSet::default();
    let mut launch = gate
        .launch(
            // Extract the fifo path from the INJECTED auth (the exact
            // handshake nested make performs) and consume EXACTLY the
            // preloaded count — the writer stays open parent-side, so
            // an unbounded read would wait for EOF forever. POSIX sh
            // ONLY: fleet /bin/sh is dash, whose read has no `-n`, so
            // per-byte consumption uses `dd bs=1 count=1` per fresh
            // fifo open (each token = one byte, one open).
            &spec(
                r#"p=${MAKEFLAGS#*fifo:}; n=0; while [ "$n" -lt 4 ]; do if dd bs=1 count=1 <"$p" >/dev/null 2>&1; then n=$((n+1)); else break; fi; done; echo "$n" > "$COUNT_OUT""#,
            ),
            &mut set,
            TOKENS,
            Duration::from_millis(300),
            |cmd| {
                cmd.env("COUNT_OUT", &out_path);
            },
        )
        .expect("admitted");

    let status = launch.wait_leader().expect("wait");
    assert_eq!(status.code(), Some(0), "token-consumption loop succeeded");
    let observed = std::fs::read_to_string(&out_path).expect("count written");
    assert_eq!(
        observed.trim(),
        TOKENS.to_string(),
        "exactly the preloaded bytes"
    );
    launch.finish(&mut set).expect("clean finish");
    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn nested_make_builds_under_injected_auth() {
    let gate = gate_with_roots(2);

    // Real workspace: three parallel targets; make drives them through
    // OUR fifo jobserver (auth arrives via the injected MAKEFLAGS).
    let ws = tempfile::tempdir().expect("workspace");
    let mk = ws.path().join("Makefile");
    std::fs::write(&mk, "all: t1 t2 t3\nt%:\n\t@echo building $@ > $@\n").expect("makefile");
    let build_flag = ws.path().join("built.flag");

    let mut set = ObligationSet::default();
    let script = format!(
        "cd {} && make -f Makefile -j2 all && touch {}",
        ws.path().display(),
        build_flag.display()
    );
    let mut launch = gate
        .launch(
            &spec(&script),
            &mut set,
            2,
            Duration::from_millis(500),
            |_| {},
        )
        .expect("admitted");

    let status = launch.wait_leader().expect("wait");
    assert!(status.success(), "nested make must succeed");
    assert!(build_flag.exists(), "all targets built");
    launch.finish(&mut set).expect("clean finish");
}
