//! Metadata-first committed-result protocol over real Unix sockets and the real
//! wrapper subprocess. The daemon, artifacts and compiler marker are explicit
//! protocol fixtures; these tests do not claim real Cargo compilation success.
//! They prove what Cargo's stderr pipe sees, when it sees it, and whether the
//! wrapper ever starts a second compiler after irreversible output exposure.
#![cfg(unix)]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const ACTION: &str = "accepted-action";
const MANIFEST: &str = "committed-manifest";
const PREFIX: &[u8] = b"{\"$message_type\":\"artifact\",\"artifact\":\"/fixture/libdemo.rmeta\"}\n";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn notice(bytes: &[u8]) -> Value {
    json!({
        "kind": "rustc-metadata", "metadata_protocol": 1,
        "action_key": ACTION, "manifest_key": MANIFEST,
        "sequence": 1, "stderr_hex": hex(bytes),
    })
}

fn served(bytes: &[u8], exposed: bool) -> Value {
    json!({
        "kind": "rustc-decision", "decision": "served", "metadata_protocol": 1,
        "action_key": ACTION, "manifest_key": MANIFEST,
        "compiler_skip_authorized": true, "stderr_hex": hex(bytes),
        "metadata_exposed": exposed,
    })
}

fn failed(exposed: bool) -> Value {
    json!({
        "kind": "rustc-decision", "decision": "serve-failed", "metadata_protocol": 1,
        "action_key": ACTION, "manifest_key": MANIFEST,
        "compiler_skip_authorized": false, "writer_returned": true,
        "metadata_exposed": exposed,
    })
}

#[derive(Clone, Copy, Debug)]
enum Lane {
    Cached,
    PublishedRemote,
}

impl Lane {
    fn bind(self, mut frame: Value) -> Value {
        if matches!(self, Self::PublishedRemote) {
            frame["remote_protocol"] = json!(1);
            frame["capture"] = json!(MANIFEST);
        }
        frame
    }

    fn notice(self, bytes: &[u8]) -> Value {
        self.bind(notice(bytes))
    }

    fn served(self, bytes: &[u8], exposed: bool) -> Value {
        let mut frame = self.bind(served(bytes, exposed));
        if matches!(self, Self::PublishedRemote) {
            frame["decision"] = json!("remote-complete");
            frame["writer_returned"] = json!(true);
        }
        frame
    }

    fn failed(self, exposed: bool) -> Value {
        let mut frame = self.bind(failed(exposed));
        if matches!(self, Self::PublishedRemote) {
            frame["decision"] = json!("remote-failed");
            frame["execution_finished"] = json!(true);
        }
        frame
    }

    fn accept(self, peer: &mut Peer) {
        if matches!(self, Self::Cached) {
            peer.accept();
            return;
        }
        peer.accept_remote_execution();
        peer.send(&Peer::remote_ready(true));
        assert_eq!(
            peer.read().unwrap(),
            json!({
                "kind": "rustc-accept", "capture": MANIFEST,
                "remote_protocol": 1, "metadata_protocol": 1,
                "action_key": ACTION, "manifest_key": MANIFEST,
            }),
            "remote installation requires separate consent for this published capture"
        );
    }

    fn ack(self, peer: &mut Peer) {
        assert_eq!(
            peer.read().unwrap(),
            self.bind(json!({
                "kind": "rustc-metadata-ack", "metadata_protocol": 1,
                "action_key": ACTION, "manifest_key": MANIFEST, "sequence": 1,
            })),
            "the daemon receives one exact prefix acknowledgment for {self:?}"
        );
    }
}

struct Peer {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Peer {
    fn send(&mut self, frame: &Value) {
        self.raw(&frame.to_string());
    }

    fn raw(&mut self, frame: &str) {
        self.writer.write_all(frame.as_bytes()).unwrap();
        self.writer.write_all(b"\n").unwrap();
    }

    fn read(&mut self) -> Option<Value> {
        let mut line = String::new();
        (self.reader.read_line(&mut line).unwrap() > 0)
            .then(|| serde_json::from_str(&line).unwrap())
    }

    fn offer() -> Value {
        json!({
            "kind": "rustc-decision", "decision": "hit", "capture_protocol": 1,
            "compiler_skip_authorized": false, "metadata_protocol": 1,
            "action_key": ACTION, "manifest_key": MANIFEST,
        })
    }

    fn accept(&mut self) {
        self.send(&Self::offer());
        assert_eq!(
            self.read().unwrap(),
            json!({
                "kind": "rustc-accept", "metadata_protocol": 1,
                "action_key": ACTION, "manifest_key": MANIFEST,
            }),
            "consent must bind the exact negotiated committed result"
        );
    }

    fn accept_remote_execution(&mut self) {
        self.send(&json!({
            "kind": "rustc-decision", "decision": "remote",
            "remote_protocol": 1, "capture_protocol": 1, "action_key": ACTION,
        }));
        assert_eq!(
            self.read().unwrap(),
            json!({
                "kind": "rustc-remote-accept", "remote_protocol": 1,
                "action_key": ACTION,
            }),
            "execution consent cannot authorize later writes into Cargo's target tree"
        );
    }

    fn remote_ready(metadata: bool) -> Value {
        let mut frame = json!({
            "kind": "rustc-decision", "decision": "remote-ready",
            "remote_protocol": 1, "action_key": ACTION, "capture": MANIFEST,
            "capture_protocol": 1, "compiler_skip_authorized": false,
        });
        if metadata {
            frame["metadata_protocol"] = json!(1);
            frame["manifest_key"] = json!(MANIFEST);
        }
        frame
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    socket: PathBuf,
    compiler: PathBuf,
    marker: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("d.sock");
        let compiler = dir.path().join("protocol-compiler-marker");
        let marker = dir.path().join("compiler-ran");
        std::fs::write(
            &compiler,
            format!(
                "#!/bin/sh\ntouch '{}'\nprintf 'local-compiler-must-not-run\\n' >&2\nexit 3\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            dir,
            socket,
            compiler,
            marker,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabs-wrap"));
        command
            .arg(&self.compiler)
            .args(["--crate-name", "demo", "src/lib.rs"])
            .current_dir(self.dir.path())
            .env("RABS_SOCKET_PATH", &self.socket)
            .env("RABS_BREAKER_FILE", self.dir.path().join("breaker"))
            .env("RABS_INSTALL_WAIT_MS", "5000")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn daemon(
        &self,
        exchange: impl FnOnce(&mut Peer) + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(&self.socket).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut peer = Peer {
                writer: stream.try_clone().unwrap(),
                reader: BufReader::new(stream),
            };
            assert_eq!(peer.read().unwrap()["kind"], "hello");
            peer.send(&json!({"kind": "hello-ok", "transport": 1, "application": 1}));
            let request = peer.read().unwrap();
            assert_eq!(request["kind"], "rustc-request");
            assert_eq!(request["metadata_protocol"], 1);
            exchange(&mut peer);
        })
    }
}

/// Reap only this test's subprocess on assertion failure as well as success.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn metadata_is_observed_before_tail_installation_and_replayed_exactly_once() {
    for lane in [Lane::Cached, Lane::PublishedRemote] {
        observe_metadata_before_tail(lane);
    }
}

fn observe_metadata_before_tail(lane: Lane) {
    let fixture = Fixture::new();
    let dep_info = fixture.dir.path().join("demo.d");
    let metadata = fixture.dir.path().join("libdemo.rmeta");
    let complete = fixture.dir.path().join("libdemo.rlib");
    let prefix = format!(
        "warning fixture before metadata\n{{\"$message_type\":\"artifact\",\"artifact\":{},\"emit\":\"dep-info\"}}\n{{\"$message_type\":\"artifact\",\"artifact\":{},\"emit\":\"metadata\"}}\n",
        serde_json::to_string(&dep_info).unwrap(),
        serde_json::to_string(&metadata).unwrap()
    )
    .into_bytes();
    let tail = b"warning fixture after metadata\n\xff\0unterminated";
    let (acknowledged, ack_seen) = mpsc::channel();
    let (finish, may_finish) = mpsc::channel();
    let prefix_for_daemon = prefix.clone();
    let dep_info_for_daemon = dep_info.clone();
    let metadata_for_daemon = metadata.clone();
    let complete_for_daemon = complete.clone();
    let daemon = fixture.daemon(move |peer| {
        lane.accept(peer);
        std::fs::write(dep_info_for_daemon, b"protocol dep-info fixture").unwrap();
        std::fs::write(metadata_for_daemon, b"protocol metadata fixture").unwrap();
        peer.send(&lane.notice(&prefix_for_daemon));
        lane.ack(peer);
        acknowledged.send(()).unwrap();
        may_finish.recv_timeout(Duration::from_secs(5)).unwrap();
        std::fs::write(complete_for_daemon, b"protocol tail fixture").unwrap();
        peer.send(&lane.served(tail, true));
    });
    let mut child = ChildGuard(fixture.command().spawn().unwrap());
    let mut stderr = child.0.stderr.take().unwrap();
    let prefix_len = prefix.len();
    let (observed, observation) = mpsc::channel();
    let read_stderr = std::thread::spawn(move || {
        let mut prefix = vec![0; prefix_len];
        stderr.read_exact(&mut prefix).unwrap();
        observed.send(prefix.clone()).unwrap();
        stderr.read_to_end(&mut prefix).unwrap();
        prefix
    });
    assert_eq!(
        observation.recv_timeout(Duration::from_secs(5)).unwrap(),
        prefix,
        "Cargo receives the continuous prefix while the tail is still held"
    );
    ack_seen.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        std::fs::read(&dep_info).unwrap(),
        b"protocol dep-info fixture"
    );
    assert_eq!(
        std::fs::read(&metadata).unwrap(),
        b"protocol metadata fixture"
    );
    assert!(!complete.exists());
    assert!(child.0.try_wait().unwrap().is_none());
    assert!(!fixture.marker.exists());
    finish.send(()).unwrap();
    assert_eq!(child.0.wait().unwrap().code(), Some(0));
    let mut stdout = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert!(stdout.is_empty());
    let mut transcript = prefix;
    transcript.extend_from_slice(tail);
    assert_eq!(read_stderr.join().unwrap(), transcript);
    assert!(complete.exists());
    assert!(!fixture.marker.exists());
    daemon.join().unwrap();
}

#[test]
fn negotiated_result_can_finish_without_an_early_metadata_frame() {
    for lane in [Lane::Cached, Lane::PublishedRemote] {
        finish_without_metadata(lane);
    }
}

fn finish_without_metadata(lane: Lane) {
    for success in [true, false] {
        let fixture = Fixture::new();
        let daemon = fixture.daemon(move |peer| {
            lane.accept(peer);
            peer.send(&if success {
                lane.served(b"whole transcript\n", false)
            } else {
                lane.failed(false)
            });
        });
        let output = fixture.command().output().unwrap();
        daemon.join().unwrap();
        assert_eq!(output.status.code(), Some(if success { 0 } else { 3 }));
        assert_eq!(fixture.marker.exists(), !success);
        assert_eq!(
            output.stderr,
            if success {
                b"whole transcript\n".as_slice()
            } else {
                b"local-compiler-must-not-run\n".as_slice()
            }
        );
    }
}

#[test]
fn every_uncertain_or_failed_tail_stays_closed_after_the_prefix() {
    for lane in [Lane::Cached, Lane::PublishedRemote] {
        refuse_every_uncertain_tail(lane);
    }
}

fn refuse_every_uncertain_tail(lane: Lane) {
    let mut false_exposure = lane.failed(false);
    false_exposure
        .as_object_mut()
        .unwrap()
        .remove("metadata_exposed");
    let mut wrong_action = lane.served(b"tail", true);
    wrong_action["action_key"] = json!("another-action");
    let mut wrong_manifest = lane.served(b"tail", true);
    wrong_manifest["manifest_key"] = json!("another-manifest");
    let mut cases = vec![
        None,
        Some(lane.failed(true).to_string()),
        Some(lane.failed(false).to_string()),
        Some(false_exposure.to_string()),
        Some(wrong_action.to_string()),
        Some(wrong_manifest.to_string()),
        Some(lane.notice(PREFIX).to_string()),
        Some("{truncated".into()),
        Some(json!({"kind": "unexpected"}).to_string()),
        Some(lane.served(b"tail", false).to_string()),
    ];
    if matches!(lane, Lane::PublishedRemote) {
        let mut wrong_capture = lane.served(b"tail", true);
        wrong_capture["capture"] = json!("another-capture");
        cases.push(Some(wrong_capture.to_string()));
        cases.push(Some(served(b"tail", true).to_string()));
        let mut wrong_protocol = lane.failed(false);
        wrong_protocol["remote_protocol"] = json!(2);
        cases.push(Some(wrong_protocol.to_string()));
    }
    for tail in cases {
        let fixture = Fixture::new();
        let description = tail.clone();
        let daemon = fixture.daemon(move |peer| {
            lane.accept(peer);
            peer.send(&lane.notice(PREFIX));
            lane.ack(peer);
            if let Some(tail) = tail {
                peer.raw(&tail);
                assert!(
                    peer.read().is_none(),
                    "no duplicate ACK or fallback request"
                );
            }
        });
        let output = fixture.command().output().unwrap();
        daemon.join().unwrap();
        assert_eq!(output.status.code(), Some(1), "tail: {description:?}");
        assert!(!fixture.marker.exists(), "tail: {description:?}");
        assert_eq!(output.stderr, PREFIX, "tail: {description:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn metadata_notice_requires_one_exact_negotiated_identity_and_bounded_bytes() {
    for lane in [Lane::Cached, Lane::PublishedRemote] {
        refuse_invalid_notices(lane);
    }
}

fn refuse_invalid_notices(lane: Lane) {
    let mut cases = Vec::new();
    for (field, value) in [
        ("action_key", json!("another-action")),
        ("manifest_key", json!("another-manifest")),
        ("metadata_protocol", json!(2)),
        ("metadata_protocol", json!("1")),
        ("sequence", json!(2)),
        ("sequence", json!("1")),
        ("stderr_hex", json!("zz")),
        ("stderr_hex", json!("a")),
        ("stderr_hex", json!("")),
        ("unexpected", json!(true)),
    ] {
        let mut frame = lane.notice(PREFIX);
        frame[field] = value;
        cases.push(frame.to_string());
    }
    for field in [
        "action_key",
        "manifest_key",
        "metadata_protocol",
        "sequence",
        "stderr_hex",
    ] {
        let mut frame = lane.notice(PREFIX);
        frame.as_object_mut().unwrap().remove(field);
        cases.push(frame.to_string());
    }
    cases.push(format!(
        "{{\"sequence\":1,{}",
        &lane.notice(PREFIX).to_string()[1..]
    ));
    cases.push(lane.notice(&vec![b'x'; 1024 * 1024 + 1]).to_string());
    if matches!(lane, Lane::PublishedRemote) {
        for (field, value) in [
            ("capture", json!("another-capture")),
            ("remote_protocol", json!(2)),
            ("remote_protocol", json!("1")),
        ] {
            let mut frame = lane.notice(PREFIX);
            frame[field] = value;
            cases.push(frame.to_string());
        }
        for field in ["capture", "remote_protocol"] {
            let mut frame = lane.notice(PREFIX);
            frame.as_object_mut().unwrap().remove(field);
            cases.push(frame.to_string());
            cases.push(format!(
                "{{{}:{},{}",
                serde_json::to_string(field).unwrap(),
                lane.notice(PREFIX)[field],
                &lane.notice(PREFIX).to_string()[1..]
            ));
        }
        cases.push(notice(PREFIX).to_string());
    }
    for (index, frame) in cases.into_iter().enumerate() {
        let fixture = Fixture::new();
        let daemon = fixture.daemon(move |peer| {
            lane.accept(peer);
            peer.raw(&frame);
            assert!(peer.read().is_none(), "invalid prefix must never be ACKed");
        });
        let output = fixture.command().output().unwrap();
        daemon.join().unwrap();
        assert_eq!(output.status.code(), Some(1), "case {index}");
        assert!(!fixture.marker.exists(), "case {index}");
        assert!(!output.stderr.starts_with(PREFIX), "case {index}");
    }
}

#[test]
fn a_legacy_hit_cannot_spontaneously_expose_metadata() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon(|peer| {
        let mut offer = Peer::offer();
        offer.as_object_mut().unwrap().remove("metadata_protocol");
        offer.as_object_mut().unwrap().remove("manifest_key");
        peer.send(&offer);
        assert_eq!(peer.read().unwrap(), json!({"kind": "rustc-accept"}));
        peer.send(&notice(PREFIX));
        assert!(peer.read().is_none());
    });
    let output = fixture.command().output().unwrap();
    daemon.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!fixture.marker.exists());
    assert!(!output.stderr.starts_with(PREFIX));
}

#[test]
fn malformed_metadata_offers_are_declined_before_consent() {
    let mut cases = Vec::new();
    for (field, value) in [
        ("metadata_protocol", json!(2)),
        ("metadata_protocol", json!("1")),
        ("action_key", json!("")),
        ("manifest_key", json!("")),
        ("manifest_key", json!(null)),
        ("manifest_key", json!("x".repeat(257))),
    ] {
        let mut offer = Peer::offer();
        offer[field] = value;
        cases.push(offer.to_string());
    }
    cases.push(format!(
        "{{\"metadata_protocol\":1,{}",
        &Peer::offer().to_string()[1..]
    ));
    for offer in cases {
        let fixture = Fixture::new();
        let daemon = fixture.daemon(move |peer| {
            peer.raw(&offer);
            assert!(
                peer.read().is_none(),
                "malformed negotiation grants no consent"
            );
        });
        let output = fixture.command().output().unwrap();
        daemon.join().unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(fixture.marker.exists());
    }
}

#[test]
fn malformed_remote_negotiation_cannot_grant_install_consent_or_local_retry() {
    let mut cases = Vec::new();
    for (field, value) in [
        ("metadata_protocol", json!(2)),
        ("metadata_protocol", json!("1")),
        ("manifest_key", json!("another-capture")),
        ("manifest_key", json!("")),
        ("manifest_key", json!(null)),
        ("manifest_key", json!("x".repeat(513))),
        ("capture", json!("another-capture")),
        ("action_key", json!("another-action")),
    ] {
        let mut ready = Peer::remote_ready(true);
        ready[field] = value;
        cases.push(ready.to_string());
    }
    for field in ["metadata_protocol", "manifest_key", "capture"] {
        let mut ready = Peer::remote_ready(true);
        ready.as_object_mut().unwrap().remove(field);
        cases.push(ready.to_string());
        cases.push(format!(
            "{{{}:{},{}",
            serde_json::to_string(field).unwrap(),
            Peer::remote_ready(true)[field],
            &Peer::remote_ready(true).to_string()[1..]
        ));
    }
    for (index, ready) in cases.into_iter().enumerate() {
        let fixture = Fixture::new();
        let daemon = fixture.daemon(move |peer| {
            peer.accept_remote_execution();
            peer.raw(&ready);
            assert!(
                peer.read().is_none(),
                "malformed ready grants no install consent"
            );
        });
        let output = fixture.command().output().unwrap();
        daemon.join().unwrap();
        assert_eq!(output.status.code(), Some(1), "case {index}");
        assert!(!fixture.marker.exists(), "case {index}");
    }
}

#[test]
fn request_owned_remote_results_keep_full_installation_and_settled_fallback() {
    for success in [true, false] {
        let fixture = Fixture::new();
        let daemon = fixture.daemon(move |peer| {
            peer.accept_remote_execution();
            peer.send(&Peer::remote_ready(false));
            assert_eq!(
                peer.read().unwrap(),
                json!({"kind": "rustc-accept", "capture": MANIFEST})
            );
            let mut terminal = if success {
                Lane::PublishedRemote.served(b"whole remote transcript\n", false)
            } else {
                Lane::PublishedRemote.failed(false)
            };
            for field in [
                "metadata_protocol",
                "manifest_key",
                "metadata_exposed",
                "capture",
            ] {
                terminal.as_object_mut().unwrap().remove(field);
            }
            peer.send(&terminal);
        });
        let output = fixture.command().output().unwrap();
        daemon.join().unwrap();
        assert_eq!(output.status.code(), Some(if success { 0 } else { 3 }));
        assert_eq!(fixture.marker.exists(), !success);
        assert_eq!(
            output.stderr,
            if success {
                b"whole remote transcript\n".as_slice()
            } else {
                b"local-compiler-must-not-run\n".as_slice()
            }
        );
    }
}

#[test]
fn legacy_remote_installation_cannot_enable_metadata_after_consent() {
    for frame in [
        Lane::PublishedRemote.notice(PREFIX),
        Lane::PublishedRemote.served(b"unexpected suffix", true),
        Lane::PublishedRemote.failed(false),
    ] {
        let fixture = Fixture::new();
        let daemon = fixture.daemon(move |peer| {
            peer.accept_remote_execution();
            peer.send(&Peer::remote_ready(false));
            assert_eq!(
                peer.read().unwrap(),
                json!({"kind": "rustc-accept", "capture": MANIFEST})
            );
            peer.send(&frame);
            assert!(
                peer.read().is_none(),
                "unnegotiated metadata cannot be ACKed"
            );
        });
        let output = fixture.command().output().unwrap();
        daemon.join().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(!fixture.marker.exists());
        assert!(!output.stderr.starts_with(PREFIX));
    }
}

#[test]
fn a_reported_exposure_forbids_fallback_even_without_a_received_prefix() {
    for lane in [Lane::Cached, Lane::PublishedRemote] {
        refuse_reported_exposure(lane);
    }
}

fn refuse_reported_exposure(lane: Lane) {
    let fixture = Fixture::new();
    let daemon = fixture.daemon(move |peer| {
        lane.accept(peer);
        peer.send(&lane.failed(true));
    });
    let output = fixture.command().output().unwrap();
    daemon.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!fixture.marker.exists());
}

#[test]
fn prefix_and_tail_share_the_original_install_deadline() {
    for lane in [Lane::Cached, Lane::PublishedRemote] {
        share_original_deadline(lane);
    }
}

fn share_original_deadline(lane: Lane) {
    let fixture = Fixture::new();
    let daemon = fixture.daemon(move |peer| {
        lane.accept(peer);
        std::thread::sleep(Duration::from_millis(900));
        peer.send(&lane.notice(PREFIX));
        lane.ack(peer);
        let acknowledged_at = Instant::now();
        assert!(peer.read().is_none(), "expired wrapper closes its session");
        assert!(
            acknowledged_at.elapsed() < Duration::from_millis(1100),
            "ACK must not grant a fresh 1500ms install budget"
        );
    });
    let output = fixture
        .command()
        .env("RABS_INSTALL_WAIT_MS", "1500")
        .output()
        .unwrap();
    daemon.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stderr, PREFIX);
    assert!(!fixture.marker.exists());
}

#[test]
fn a_blocked_cargo_stderr_pipe_cannot_ack_or_extend_the_install_deadline() {
    for lane in [Lane::Cached, Lane::PublishedRemote] {
        refuse_blocked_prefix(lane);
    }
}

fn refuse_blocked_prefix(lane: Lane) {
    let fixture = Fixture::new();
    let daemon = fixture.daemon(move |peer| {
        lane.accept(peer);
        peer.send(&lane.notice(&vec![b'x'; 1024 * 1024]));
        assert!(peer.read().is_none(), "an unflushed prefix cannot be ACKed");
    });
    let mut child = ChildGuard(
        fixture
            .command()
            .env("RABS_INSTALL_WAIT_MS", "500")
            .spawn()
            .unwrap(),
    );
    // Keep stderr's read end open but deliberately do not drain it. A 1MiB
    // prefix fills the pipe and leaves the worker thread in write_all.
    let limit = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < limit,
            "blocked stderr escaped the install deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(1));
    let mut partial = Vec::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut partial)
        .unwrap();
    assert!(!partial.is_empty());
    assert!(partial.len() < 1024 * 1024);
    assert!(partial.iter().all(|byte| *byte == b'x'));
    assert!(!fixture.marker.exists());
    daemon.join().unwrap();
}

#[test]
fn a_closed_cargo_stderr_pipe_cannot_ack_or_run_the_compiler() {
    for lane in [Lane::Cached, Lane::PublishedRemote] {
        refuse_closed_prefix(lane);
    }
}

fn refuse_closed_prefix(lane: Lane) {
    let fixture = Fixture::new();
    let (release, may_send) = mpsc::channel();
    let daemon = fixture.daemon(move |peer| {
        lane.accept(peer);
        may_send.recv_timeout(Duration::from_secs(5)).unwrap();
        peer.send(&lane.notice(PREFIX));
        assert!(peer.read().is_none());
    });
    let mut child = ChildGuard(fixture.command().spawn().unwrap());
    drop(child.0.stderr.take().unwrap());
    release.send(()).unwrap();
    assert_eq!(child.0.wait().unwrap().code(), Some(1));
    assert!(!fixture.marker.exists());
    daemon.join().unwrap();
}
