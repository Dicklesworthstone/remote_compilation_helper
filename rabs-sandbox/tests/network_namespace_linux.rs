//! E002 acceptance: a network attempt inside a hermetic canonical action
//! FAILS and is RECORDED as a `NetworkSensitive` observation.
//!
//! The probe re-executes THIS test binary inside the real D003 namespace
//! (bubblewrap, `--unshare-net`): the child makes a genuine TCP connect
//! attempt to TEST-NET-1 and asserts it fails — under default-deny there
//! is no route, so any success means the sandbox leaked and the parent
//! fails loudly. The parent then derives the isolation-evidence record
//! from the launch boundary (enforcement facts) and classifies the denied
//! attempt observation — closing the acceptance chain:
//! attempt → fails → recorded as NetworkSensitive.
//!
//! Skips honestly (with a note) on hosts without bubblewrap + unprivileged
//! user namespaces; everything else in this file runs everywhere.

#![cfg(target_os = "linux")]

use rabs_protocol::input_evidence::EnforcementState;
use rabs_protocol::volatility::{EffectClass, classify};
use rabs_sandbox::canonical_namespace::{
    Bind, CanonicalNamespaceSpec, HostIsolationSupport, build_canonical_argv, command_for,
};
use rabs_sandbox::layout;
use rabs_sandbox::network_isolation::{boundary_isolation_evidence, denied_attempt_observation};

fn supported() -> Option<HostIsolationSupport> {
    let support = HostIsolationSupport::probe();
    if support.missing_for_canonical().is_empty() {
        Some(support)
    } else {
        None
    }
}

/// The in-namespace probe. On the host (env unset) it is a no-op so the
/// ordinary test run passes; inside the namespace the spec's complete
/// environment sets the marker and this body IS the acceptance assertion.
#[test]
fn e002_in_namespace_probe() {
    if std::env::var("RABS_E002_PROBE").as_deref() != Ok("1") {
        return; // Host side: nothing to prove here.
    }
    // Inside the namespace: genuinely attempt network I/O. TEST-NET-1
    // (RFC 5737) must never route anywhere; under --unshare-net even a
    // routable address would fail, so this target keeps the failure
    // deterministic on any host.
    let attempt = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([192, 0, 2, 1], 80)),
        std::time::Duration::from_secs(3),
    );
    match attempt {
        Err(err) => {
            // Causation matters: a REAL netns deny fails FAST (no route /
            // unreachable / permission). A slow timeout is what a connect
            // from the HOST netns to a blackhole looks like — i.e. the
            // signature of enforcement silently regressing. Refuse it.
            if matches!(
                err.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                panic!(
                    "NETWORK LEAK SUSPECTED: connect failed SLOWLY ({:?}, {err}) — \
                     that is host-netns behavior, not netns denial",
                    err.kind()
                );
            }
            eprintln!(
                "E002 probe: connect failed as required (kind={:?}, err={err})",
                err.kind()
            );
        }
        Ok(_stream) => {
            panic!("NETWORK LEAK: TCP connect SUCCEEDED inside the default-deny namespace");
        }
    }
}

#[test]
fn network_attempt_inside_canonical_namespace_fails_and_is_recorded() {
    let Some(support) = supported() else {
        eprintln!(
            "skipping E002 live probe: host lacks bubblewrap/unprivileged userns \
             (measured, not assumed)"
        );
        return;
    };

    let exe = std::env::current_exe().expect("test binary path");
    let ws = tempfile::tempdir().expect("workspace backing tempdir");

    let mut spec = CanonicalNamespaceSpec::new();
    spec.rw_binds.push(Bind::new(ws.path(), layout::WORKSPACE));
    // The complete presented environment (I21): exactly the marker.
    spec.env = vec![("RABS_E002_PROBE".to_string(), "1".to_string())];
    // Re-enter THIS binary through the closed view: stage a copy INSIDE
    // the workspace backing so it becomes visible via the existing rw
    // bind at /__rabs/workspace/e002-self. A separate ro-bind under
    // /__rabs/workspace would be shadowed by the later workspace mount
    // (the builder emits ro binds before rw binds).
    let staged = ws.path().join("e002-self");
    std::fs::copy(&exe, &staged)
        .expect("stage probe binary into workspace backing (fs::copy keeps the exec bit)");
    eprintln!("E002 live probe: launching real namespace on this host");

    let launch = build_canonical_argv(
        &spec,
        &support,
        "/__rabs/workspace/e002-self",
        &[
            "--exact".to_string(),
            "e002_in_namespace_probe".to_string(),
            "--nocapture".to_string(),
        ],
    )
    .expect("spec compiles against measured support");

    // Enforcement claim of THIS argv, before running: netns deny present.
    assert!(launch.boundary.net_isolated);
    assert!(launch.boundary.satisfies_strict_hermetic_linux());

    let output = command_for(&launch)
        .output()
        .expect("bwrap spawnable on a supported host");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "in-namespace probe failed (child exit={:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(
        stderr.contains("connect failed as required"),
        "probe must show the attempted-and-denied connect\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // RECORD (E010): the enforcement facts of exactly this launch.
    let record = boundary_isolation_evidence(&launch.boundary);
    assert!(record.fully_enforced());
    let network = record
        .controls
        .iter()
        .find(|(name, _)| name.as_utf8() == Some("network-deny"))
        .expect("network control present");
    assert_eq!(network.1, EnforcementState::Enforced { mechanism: "netns" });

    // OBSERVATION: the attempt the probe made is classified
    // NetworkSensitive — the acceptance recording half.
    assert_eq!(
        EffectClass::NetworkSensitive,
        classify(&denied_attempt_observation())
    );
}
