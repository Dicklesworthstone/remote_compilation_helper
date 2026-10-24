//! Exercise the production completion handoff against real coordinator/CAS
//! state and Unix sockets. Only toolchain probes and compiled artifact bytes
//! are fixtures; these are not executions of Cargo or rustc.

use super::super::rustc_request::{Decided, LiveEdge, complete_on_lane, decide};
use super::super::{
    EdgeLimits, EdgeServices, EdgeStream, FRAME_READ_BUFFER_BYTES, LIVE_DECISION_WORKERS,
    MATERIALIZATION_WORKERS, handle_connection,
};
use super::{Limit, OwnedWork};
use crate::coord::live::CoordLive;
use crate::coord::live_dependency::{
    CompletionOutcome, CompletionReport, LiveDependencyLane, LocalAttempt,
};
use crate::janitor::store::{LiveCas, mount_and_reconcile};
use asupersync::net::unix::UnixListener;
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::daemon_runtime::block_on_top_level;
use rabs_cas::metadata_store::RabsMetadataStore;
use rabs_protocol::socket_admission::{AdmissionPolicy, SocketMetadata};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const ARTIFACT: &[u8] = b"original captured metadata fixture";

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    package: PathBuf,
    out: PathBuf,
    request: Value,
    live: Arc<LiveEdge>,
    coord: Arc<CoordLive>,
    cas: Arc<LiveCas>,
}

impl Fixture {
    fn new() -> Self {
        let dir = crate::test_util::private_tempdir();
        let root = dir.path().canonicalize().unwrap();
        let cargo = root.join("cargo");
        let package = cargo.join("registry/src/fixture-index/foo-1.0.0");
        let out = root.join("target/debug/deps");
        let toolchain = root.join("toolchain");
        for directory in [
            package.clone(),
            out.clone(),
            toolchain.join("bin"),
            toolchain.join("lib/rustlib/x86_64-unknown-linux-gnu/lib"),
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        std::fs::write(package.join("lib.rs"), b"pub fn value() -> u32 { 42 }\n").unwrap();
        std::fs::write(
            package.join("Cargo.toml"),
            "[package]\nname = \"foo\"\nversion = \"1.0.0\"\nedition = \"2021\"\n[lib]\npath = \"lib.rs\"\n",
        ).unwrap();
        std::fs::write(toolchain.join("lib/libdriver.so"), b"runtime fixture").unwrap();
        std::fs::write(
            toolchain.join("lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore.rlib"),
            b"sysroot fixture",
        )
        .unwrap();
        let compiler = toolchain.join("bin/rustc");
        std::fs::write(&compiler, concat!(
            "#!/bin/sh\ncase \"$*\" in\n",
            "'-vV') printf 'rustc fixture\\nhost: x86_64-unknown-linux-gnu\\nLLVM version: fixture\\n';;\n",
            "'--print sysroot') printf '%s\\n' \"${0%/bin/rustc}\";;\n",
            "*) exit 64;;\nesac\n",
        )).unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o700)).unwrap();
        let request = json!({
            "kind":"rustc-request", "wait_for_inflight":true,
            "argv":[compiler.to_str().unwrap(), "--crate-name=foo", "--crate-type=lib",
                "--emit=metadata,dep-info", "--cap-lints=allow", "--error-format=json",
                "-Cextra-filename=-123", "--out-dir", out.to_str().unwrap(),
                package.join("lib.rs").to_str().unwrap()],
            "cwd":package.to_str().unwrap(),
            "env":[["CARGO_HOME", cargo.to_str().unwrap()],
                ["CARGO_MANIFEST_DIR", package.to_str().unwrap()], ["CARGO_PKG_NAME", "foo"]],
        });
        let cas = Arc::new(mount_and_reconcile(&root.join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
        coord
            .acquire_boot_authority("completion-reservation-fixture")
            .unwrap();
        coord.mark_up();
        let live = Arc::new(LiveEdge::new(LiveDependencyLane::new(Arc::clone(&coord))));
        Self {
            _dir: dir,
            root,
            package,
            out,
            request,
            live,
            coord,
            cas,
        }
    }

    fn begin(&self) -> (Box<LocalAttempt>, String) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match decide(&self.live, &self.request) {
                Decided::Execute { reply, attempt } => {
                    let reply: Value = serde_json::from_str(&reply).unwrap();
                    assert_eq!(reply["compiler_skip_authorized"], false);
                    return (attempt, reply["action_key"].as_str().unwrap().to_owned());
                }
                Decided::Reply(reply) => {
                    let reply: Value = serde_json::from_str(&reply).unwrap();
                    assert_eq!(reply["decision"], "preparing", "{reply}");
                    assert!(Instant::now() < deadline, "fixture facts did not warm");
                    std::thread::sleep(Duration::from_millis(5));
                }
                _ => panic!("fixture must enter the real local execution lane"),
            }
        }
    }

    fn outputs(&self) {
        std::fs::write(self.out.join("libfoo-123.rmeta"), ARTIFACT).unwrap();
        std::fs::write(
            self.out.join("foo-123.d"),
            format!(
                "{}/libfoo-123.rmeta: {}/lib.rs\n\n{}/lib.rs:\n",
                self.out.display(),
                self.package.display(),
                self.package.display(),
            ),
        )
        .unwrap();
    }

    fn report(attempt: &LocalAttempt) -> Vec<u8> {
        json!({
            "kind":"rustc-complete", "capture_protocol":1, "attempt":attempt.attempt_hex(),
            "exit_code":0, "signal":null, "stdout_hex":"", "stderr_hex":"",
        })
        .to_string()
        .into_bytes()
    }

    fn warm_replay(&self) -> String {
        let mut action_key = None;
        for expected in [
            CompletionOutcome::Committed,
            CompletionOutcome::Verified,
            CompletionOutcome::Verified,
        ] {
            let (attempt, action) = self.begin();
            if let Some(previous) = &action_key {
                assert_eq!(previous, &action);
            } else {
                action_key = Some(action);
            }
            self.outputs();
            let report = CompletionReport {
                exit_code: Some(0),
                signal: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
            };
            assert_eq!((*attempt).complete(&report).0, expected);
        }
        action_key.unwrap()
    }

    fn locations(&self) -> Vec<(String, String)> {
        let mut locations: Vec<_> = self
            .cas
            .store()
            .lock()
            .unwrap()
            .reconciliation_scan()
            .unwrap()
            .into_iter()
            .map(|row| (row.object_key, row.store_path))
            .collect();
        locations.sort();
        locations
    }
}

#[derive(Clone, Copy)]
enum Ack {
    Matching,
    WrongCapture,
    Disconnect,
}

/// Occupy every OTHER completion slot precisely after the real capture receipt.
/// Keep those slots occupied until complete_on_lane has returned; the final
/// publication or cleanup therefore cannot depend on another caller releasing.
fn handoff(ack: Ack) {
    let fixture = Fixture::new();
    let (attempt, action) = fixture.begin();
    fixture.outputs();
    let report = Fixture::report(&attempt);
    let capacity = Limit::new(8);
    let peer_capacity = capacity.clone();
    let cas = Arc::clone(&fixture.cas);
    let path = fixture.root.join("capture.sock");
    let (finished, finish) = mpsc::channel();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let result = block_on_top_level(&runtime, async {
        let listener = UnixListener::bind(&path).await.unwrap();
        let peer = std::thread::spawn(move || {
            let socket = std::os::unix::net::UnixStream::connect(path).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            socket.read_line(&mut line).unwrap();
            let receipt: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(receipt["kind"], "rustc-captured");
            assert_eq!(receipt["publication_authorized"], false);
            // Captured bytes are durable, but there is no publication before
            // consent and no metadata mutex held by the acknowledgment waiter.
            assert!(
                cas.store()
                    .try_lock()
                    .unwrap()
                    .list_publications()
                    .unwrap()
                    .is_empty()
            );
            let mut occupied = Vec::new();
            while let Some(permit) = peer_capacity.acquire() {
                occupied.push(permit);
            }
            assert_eq!(
                occupied.len(),
                7,
                "the capture reservation must survive its joined stage"
            );
            match ack {
                Ack::Matching | Ack::WrongCapture => {
                    let capture = match ack {
                        Ack::Matching => receipt["capture"].clone(),
                        _ => json!("wrong-capture"),
                    };
                    let answer = json!({"kind":"rustc-capture-ack",
                        "attempt":receipt["attempt"], "capture":capture});
                    writeln!(socket.get_mut(), "{answer}").unwrap();
                }
                Ack::Disconnect => {
                    socket.get_mut().shutdown(std::net::Shutdown::Both).unwrap();
                }
            }
            finish.recv_timeout(Duration::from_secs(10)).unwrap();
            drop(occupied);
        });
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = EdgeStream::with_capacity(FRAME_READ_BUFFER_BYTES, socket);
        let result = complete_on_lane(
            &capacity,
            Arc::clone(&fixture.live),
            attempt,
            report,
            &mut socket,
        )
        .await;
        let _ = finished.send(());
        peer.join().unwrap();
        serde_json::from_str::<Value>(&result).unwrap()
    });
    let publications = fixture
        .cas
        .store()
        .lock()
        .unwrap()
        .list_publications()
        .unwrap();
    match ack {
        Ack::Matching => {
            assert_eq!(result["outcome"], "committed", "{result}");
            assert_eq!(publications.len(), 1);
            assert_eq!(publications[0].0, action);
        }
        Ack::WrongCapture | Ack::Disconnect => {
            assert_eq!(result["outcome"], "not-published", "{result}");
            assert_eq!(result["detail"], "output capture was not acknowledged");
            assert!(publications.is_empty());
            // The old attempt has settled; it must not strand singleflight.
            drop(fixture.begin());
        }
    }
    let recovered: Vec<_> = (0..8).map(|_| capacity.acquire().unwrap()).collect();
    assert!(capacity.acquire().is_none());
    drop(recovered);
    assert_eq!(
        std::fs::read(fixture.out.join("libfoo-123.rmeta")).unwrap(),
        ARTIFACT
    );
}

#[test]
fn acknowledged_capture_publishes_while_all_other_completion_slots_are_occupied() {
    handoff(Ack::Matching);
}

#[test]
fn wrong_ack_still_refuses_publication_and_cleans_up_under_saturation() {
    handoff(Ack::WrongCapture);
}

#[test]
fn disconnected_owner_still_refuses_publication_and_cleans_up_under_saturation() {
    handoff(Ack::Disconnect);
}

#[test]
fn initial_saturation_never_acknowledges_or_copies_outputs() {
    let fixture = Fixture::new();
    let (attempt, _) = fixture.begin();
    fixture.outputs();
    let report = Fixture::report(&attempt);
    let locations_before = fixture.locations();
    let path = fixture.root.join("refused.sock");
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let result = block_on_top_level(&runtime, async {
        let listener = UnixListener::bind(&path).await.unwrap();
        let peer = std::thread::spawn(move || {
            let socket = std::os::unix::net::UnixStream::connect(path).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            assert_eq!(
                socket.read_line(&mut line).unwrap(),
                0,
                "no custody receipt on refusal"
            );
        });
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = EdgeStream::with_capacity(FRAME_READ_BUFFER_BYTES, socket);
        let result = complete_on_lane(
            &Limit::new(0),
            Arc::clone(&fixture.live),
            attempt,
            report,
            &mut socket,
        )
        .await;
        drop(socket);
        peer.join().unwrap();
        serde_json::from_str::<Value>(&result).unwrap()
    });
    assert_eq!(result["outcome"], "not-published");
    assert_eq!(result["publication_authorized"], false);
    assert!(
        fixture
            .cas
            .store()
            .lock()
            .unwrap()
            .list_publications()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture.locations(),
        locations_before,
        "no additional captured blob locations"
    );
    drop(fixture.begin());
    assert_eq!(
        std::fs::read(fixture.out.join("libfoo-123.rmeta")).unwrap(),
        ARTIFACT
    );
}

fn read_reply(socket: &mut BufReader<std::os::unix::net::UnixStream>) -> Value {
    let mut line = String::new();
    assert!(
        socket.read_line(&mut line).unwrap() > 0,
        "missing daemon reply"
    );
    serde_json::from_str(&line).unwrap()
}

/// Run the production admitted connection handler with a real Unix peer.
/// The client owns its socket until its protocol assertions are complete.
fn run_connection(
    fixture: &Fixture,
    limits: EdgeLimits,
    peer: impl FnOnce(BufReader<std::os::unix::net::UnixStream>) + Send + 'static,
) {
    let path = fixture.root.join("hit.sock");
    let services = EdgeServices {
        shadow: Arc::new(std::sync::Mutex::new(
            crate::edge::shadow::ShadowPlane::open(&fixture.root.join("shadow")).unwrap(),
        )),
        coord: fixture.coord.edge_subscriber(),
        prepared_operations: None,
        live: Some(Arc::clone(&fixture.live)),
    };
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    block_on_top_level(&runtime, async {
        let listener = UnixListener::bind(&path).await.unwrap();
        let client = std::thread::spawn(move || {
            let socket = std::os::unix::net::UnixStream::connect(path).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut socket = BufReader::new(socket);
            let hello = json!({
                "kind":"hello",
                "transport":{"minimum_compatible":1, "current":1},
                "application":{"minimum_compatible":1, "current":1},
            });
            writeln!(socket.get_mut(), "{hello}").unwrap();
            assert_eq!(read_reply(&mut socket)["kind"], "hello-ok");
            peer(socket);
        });
        let (socket, _) = listener.accept().await.unwrap();
        let owner_uid = socket.peer_cred().unwrap().uid;
        handle_connection(
            1,
            socket,
            AdmissionPolicy {
                expected_uid: owner_uid,
                require_token_on_unix: false,
                tcp_enabled: false,
            },
            SocketMetadata {
                owner_uid,
                mode: 0o600,
            },
            services,
            limits,
        )
        .await;
        client.join().unwrap();
    });
}

/// Actual decision workers remain blocked until the peer has its install
/// result. Tuple drop order also releases the sender before joining its worker
/// if a client assertion panics, so a failing test cannot strand a thread.
fn occupy_decisions(lane: &Limit) -> Vec<(mpsc::Sender<()>, OwnedWork<()>)> {
    let (started, ready) = mpsc::channel();
    let mut occupied = Vec::new();
    for _ in 0..LIVE_DECISION_WORKERS {
        let started = started.clone();
        let (release, released) = mpsc::channel();
        let work = lane
            .spawn(move || {
                started.send(()).unwrap();
                let _ = released.recv_timeout(Duration::from_secs(10));
            })
            .unwrap();
        occupied.push((release, work));
    }
    for _ in 0..LIVE_DECISION_WORKERS {
        ready.recv_timeout(Duration::from_secs(10)).unwrap();
    }
    assert!(lane.acquire().is_none());
    occupied
}

fn assert_capacity_returned(lane: &Limit, maximum: usize) {
    let recovered: Vec<_> = (0..maximum).map(|_| lane.acquire().unwrap()).collect();
    assert!(lane.acquire().is_none());
    drop(recovered);
}

#[derive(Clone, Copy)]
enum InstallAck {
    Matching,
    WrongKind,
    Disconnect,
}

fn hit_handoff(ack: InstallAck) {
    let fixture = Fixture::new();
    let action = fixture.warm_replay();
    let metadata = fixture.out.join("libfoo-123.rmeta");
    let dep_info = fixture.out.join("foo-123.d");
    let expected_dep_info = std::fs::read(&dep_info).unwrap();
    let prior_metadata = b"subscriber metadata before acceptance";
    let prior_dep_info = b"subscriber dep-info before acceptance";
    std::fs::write(&metadata, prior_metadata).unwrap();
    std::fs::write(&dep_info, prior_dep_info).unwrap();
    let request = fixture.request.clone();
    let limits = EdgeLimits::new(0);
    let peer_limits = limits.clone();
    let peer_metadata = metadata.clone();
    let peer_dep_info = dep_info.clone();
    let peer_expected_dep_info = expected_dep_info.clone();
    run_connection(&fixture, limits.clone(), move |mut socket| {
        writeln!(socket.get_mut(), "{request}").unwrap();
        let hit = read_reply(&mut socket);
        assert_eq!(hit["decision"], "hit", "{hit}");
        assert_eq!(hit["action_key"], action);
        assert_eq!(hit["compiler_skip_authorized"], false);
        // Offering a hit reserves exactly one installation slot, but it is
        // not consent to write either output.
        assert_eq!(std::fs::read(&peer_metadata).unwrap(), prior_metadata);
        assert_eq!(std::fs::read(&peer_dep_info).unwrap(), prior_dep_info);
        let other_installation = peer_limits.materialization.acquire().unwrap();
        assert!(peer_limits.materialization.acquire().is_none());
        let occupied = occupy_decisions(&peer_limits.live);
        match ack {
            InstallAck::Matching => {
                let accepted = json!({"kind":"rustc-accept"});
                writeln!(socket.get_mut(), "{accepted}").unwrap();
                let served = read_reply(&mut socket);
                assert_eq!(served["decision"], "served", "{served}");
                assert_eq!(served["action_key"], action);
                assert_eq!(served["compiler_skip_authorized"], true);
                assert_eq!(std::fs::read(&peer_metadata).unwrap(), ARTIFACT);
                assert_eq!(
                    std::fs::read(&peer_dep_info).unwrap(),
                    peer_expected_dep_info
                );
                // No decision worker was released to make the hit succeed.
                assert!(peer_limits.live.acquire().is_none());
                let returned = peer_limits.materialization.acquire().unwrap();
                assert!(peer_limits.materialization.acquire().is_none());
                drop(returned);
            }
            InstallAck::WrongKind => {
                let rejected = json!({"kind":"not-rustc-accept"});
                writeln!(socket.get_mut(), "{rejected}").unwrap();
            }
            InstallAck::Disconnect => {}
        }
        drop(socket);
        drop(other_installation);
        for (release, work) in occupied {
            let _ = release.send(());
            drop(work);
        }
    });
    assert_capacity_returned(&limits.materialization, MATERIALIZATION_WORKERS);
    assert_capacity_returned(&limits.live, LIVE_DECISION_WORKERS);
    match ack {
        InstallAck::Matching => {
            assert_eq!(std::fs::read(&metadata).unwrap(), ARTIFACT);
            assert_eq!(std::fs::read(&dep_info).unwrap(), expected_dep_info);
        }
        InstallAck::WrongKind | InstallAck::Disconnect => {
            assert_eq!(std::fs::read(&metadata).unwrap(), prior_metadata);
            assert_eq!(std::fs::read(&dep_info).unwrap(), prior_dep_info);
        }
    }
}

#[test]
fn accepted_hit_installs_while_every_decision_worker_is_busy() {
    hit_handoff(InstallAck::Matching);
}

#[test]
fn rejected_hit_returns_its_reservation_without_writing_any_output() {
    hit_handoff(InstallAck::WrongKind);
}

#[test]
fn disconnected_hit_returns_its_reservation_without_writing_any_output() {
    hit_handoff(InstallAck::Disconnect);
}

#[test]
fn saturated_installation_retries_before_consent_then_serves_the_same_request() {
    let fixture = Fixture::new();
    let action = fixture.warm_replay();
    let metadata = fixture.out.join("libfoo-123.rmeta");
    let dep_info = fixture.out.join("foo-123.d");
    let expected_dep_info = std::fs::read(&dep_info).unwrap();
    let prior = b"subscriber outputs before acceptance";
    std::fs::write(&metadata, prior).unwrap();
    std::fs::write(&dep_info, prior).unwrap();
    let limits = EdgeLimits::new(0);
    let occupied: Vec<_> = (0..MATERIALIZATION_WORKERS)
        .map(|_| limits.materialization.acquire().unwrap())
        .collect();
    let request = fixture.request.clone();
    let peer_metadata = metadata.clone();
    let peer_dep_info = dep_info.clone();
    run_connection(&fixture, limits.clone(), move |mut socket| {
        writeln!(socket.get_mut(), "{request}").unwrap();
        let retry = read_reply(&mut socket);
        assert_eq!(retry["kind"], "rustc-decision");
        assert_eq!(retry["decision"], "pass-through");
        assert_eq!(retry["reason"], "edge-capacity");
        assert_eq!(retry["retry"], "decision-capacity-v1");
        assert_eq!(retry["compiler_skip_authorized"], false);
        assert_eq!(retry["materialization_started"], false);
        for authority in ["action_key", "attempt", "env"] {
            assert!(retry.get(authority).is_none());
        }
        assert_eq!(std::fs::read(&peer_metadata).unwrap(), prior);
        assert_eq!(std::fs::read(&peer_dep_info).unwrap(), prior);
        drop(occupied);
        // Retry the identical request over the same admitted session. Its
        // original action still has a hit; saturation granted no attempt.
        writeln!(socket.get_mut(), "{request}").unwrap();
        let hit = read_reply(&mut socket);
        assert_eq!(hit["decision"], "hit", "{hit}");
        assert_eq!(hit["action_key"], action);
        assert_eq!(hit["compiler_skip_authorized"], false);
        assert_eq!(std::fs::read(&peer_metadata).unwrap(), prior);
        assert_eq!(std::fs::read(&peer_dep_info).unwrap(), prior);
        let accepted = json!({"kind":"rustc-accept"});
        writeln!(socket.get_mut(), "{accepted}").unwrap();
        let served = read_reply(&mut socket);
        assert_eq!(served["decision"], "served", "{served}");
        assert_eq!(served["action_key"], action);
        assert_eq!(served["compiler_skip_authorized"], true);
    });
    assert_capacity_returned(&limits.materialization, MATERIALIZATION_WORKERS);
    assert_capacity_returned(&limits.live, LIVE_DECISION_WORKERS);
    assert_eq!(std::fs::read(&metadata).unwrap(), ARTIFACT);
    assert_eq!(std::fs::read(&dep_info).unwrap(), expected_dep_info);
}
