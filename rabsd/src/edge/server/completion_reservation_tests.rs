//! Exercise the production completion handoff against real coordinator/CAS
//! state and Unix sockets. Only toolchain probes and compiled artifact bytes
//! are fixtures; these are not executions of Cargo or rustc.

use super::super::rustc_request::{Decided, LiveEdge, complete_on_lane, decide};
use super::super::{EdgeStream, FRAME_READ_BUFFER_BYTES};
use super::Limit;
use asupersync::net::unix::UnixListener;
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::daemon_runtime::block_on_top_level;
use rabs_cas::metadata_store::RabsMetadataStore;
use crate::coord::live::CoordLive;
use crate::coord::live_dependency::{LiveDependencyLane, LocalAttempt};
use crate::janitor::store::{LiveCas, mount_and_reconcile};
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
        ).unwrap();
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
        coord.acquire_boot_authority("completion-reservation-fixture").unwrap();
        coord.mark_up();
        let live = Arc::new(LiveEdge::new(LiveDependencyLane::new(coord)));
        Self { _dir: dir, root, package, out, request, live, cas }
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
        std::fs::write(self.out.join("foo-123.d"), format!(
            "{}/libfoo-123.rmeta: {}/lib.rs\n\n{}/lib.rs:\n",
            self.out.display(), self.package.display(), self.package.display(),
        )).unwrap();
    }

    fn report(attempt: &LocalAttempt) -> Vec<u8> {
        json!({
            "kind":"rustc-complete", "capture_protocol":1, "attempt":attempt.attempt_hex(),
            "exit_code":0, "signal":null, "stdout_hex":"", "stderr_hex":"",
        }).to_string().into_bytes()
    }

    fn locations(&self) -> Vec<(String, String)> {
        let mut locations: Vec<_> = self.cas.store().lock().unwrap()
            .reconciliation_scan().unwrap().into_iter()
            .map(|row| (row.object_key, row.store_path)).collect();
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
            socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            socket.read_line(&mut line).unwrap();
            let receipt: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(receipt["kind"], "rustc-captured");
            assert_eq!(receipt["publication_authorized"], false);
            // Captured bytes are durable, but there is no publication before
            // consent and no metadata mutex held by the acknowledgment waiter.
            assert!(cas.store().try_lock().unwrap().list_publications().unwrap().is_empty());
            let mut occupied = Vec::new();
            while let Some(permit) = peer_capacity.acquire() {
                occupied.push(permit);
            }
            assert_eq!(occupied.len(), 7, "the capture reservation must survive its joined stage");
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
            &capacity, Arc::clone(&fixture.live), attempt, report, &mut socket,
        ).await;
        let _ = finished.send(());
        peer.join().unwrap();
        serde_json::from_str::<Value>(&result).unwrap()
    });
    let publications = fixture.cas.store().lock().unwrap().list_publications().unwrap();
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
    assert_eq!(std::fs::read(fixture.out.join("libfoo-123.rmeta")).unwrap(), ARTIFACT);
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
            socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            assert_eq!(socket.read_line(&mut line).unwrap(), 0, "no custody receipt on refusal");
        });
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = EdgeStream::with_capacity(FRAME_READ_BUFFER_BYTES, socket);
        let result = complete_on_lane(
            &Limit::new(0), Arc::clone(&fixture.live), attempt, report, &mut socket,
        ).await;
        drop(socket);
        peer.join().unwrap();
        serde_json::from_str::<Value>(&result).unwrap()
    });
    assert_eq!(result["outcome"], "not-published");
    assert_eq!(result["publication_authorized"], false);
    assert!(fixture.cas.store().lock().unwrap().list_publications().unwrap().is_empty());
    assert_eq!(fixture.locations(), locations_before, "no additional captured blob locations");
    drop(fixture.begin());
    assert_eq!(std::fs::read(fixture.out.join("libfoo-123.rmeta")).unwrap(), ARTIFACT);
}
