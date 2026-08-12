//! bd-1vf05 acceptance: a committed action served THROUGH THE SOCKET by
//! the shipped `rabsd` binary.
//!
//! Everything before this vertebra could only be reached in-process. Here
//! the store is prepared and committed into first, the real daemon is
//! then booted over that state directory, and a client asks it — over the
//! real UDS, after the real handshake — to materialize the hit into a
//! worktree. The bytes that appear are the committed bytes.
//!
//! NOT proven here: no wrapper skips a compile on the strength of this
//! answer. That half of bd-1vf05 is blocked and stays blocked until a
//! manifest's virtual paths are derived from the real rustc invocation
//! (the D-epic work under bd-14t4j) — serving into a cargo target dir
//! before then would be guessing at destinations, and a wrong guess is a
//! wrong build, not a slow one.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::publication::{OfferPreparedActionResult, PublicationOutcome};
use rabs_cas::test_support::{
    install_admission_world, install_offer_closure, offer_serving_object, sample_action_key,
    sample_expected_descriptor,
};
use rabs_protocol::result_identity::ObjectId;
use rabsd::coord::live::{CoordLive, cluster_id};
use rabsd::janitor::store::mount_and_reconcile;

const HELLO: &str = "{\"kind\":\"hello\",\
    \"transport\":{\"minimum_compatible\":1,\"current\":1},\
    \"application\":{\"minimum_compatible\":1,\"current\":1}}";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Commit one action whose materializable output really is `artifact`,
/// into the store under `state_dir`. Returns when the store handle is
/// released, so the daemon can mount it.
fn commit_one_action(state_dir: &std::path::Path, artifact: &[u8]) {
    let cas = Arc::new(mount_and_reconcile(&state_dir.join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");

    let object = {
        let mut store = cas.store().lock().expect("store lock");
        let declared = digest_set(artifact, DigestRequest::default(), None)
            .expect("digest")
            .atp_content_id;
        let mut reader = artifact;
        put_if_absent(
            cas.layout(),
            &mut *store,
            &declared,
            &mut reader,
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .expect("put artifact");
        ObjectId(declared)
    };
    let (offer, manifest_bytes) = offer_serving_object(&authority, &object);
    put_manifest(&cas, &offer, &manifest_bytes);
    {
        let mut store = cas.store().lock().expect("store lock");
        install_admission_world(&mut *store, &authority);
        install_offer_closure(&mut *store, &offer);
    }
    let outcome = coord
        .commit_offer(&offer, &sample_expected_descriptor())
        .expect("commit");
    assert!(
        matches!(outcome, PublicationOutcome::Committed(_)),
        "expected a commit, got {outcome:?}"
    );
}

fn put_manifest(
    cas: &rabsd::janitor::store::LiveCas,
    offer: &OfferPreparedActionResult,
    bytes: &[u8],
) {
    let mut store = cas.store().lock().expect("store lock");
    let mut reader = bytes;
    put_if_absent(
        cas.layout(),
        &mut *store,
        &offer.manifest_id.0,
        &mut reader,
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .expect("put manifest bytes");
}

fn spawn_daemon(state_dir: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .env("RABS_SOCKET_PATH", state_dir.join("rabsd.sock"))
        .env("RABS_BOOT_MARKER", state_dir.join("rabsd.boot"))
        .env("RABS_STATE_DIR", state_dir)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rabsd")
}

fn connect(socket: &std::path::Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                return stream;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("connect: {error}"),
        }
    }
}

fn round_trip(stream: &mut UnixStream, line: &str) -> String {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    stream.write_all(line.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    reply.trim_end().to_string()
}

#[test]
fn the_running_daemon_serves_a_committed_hit_over_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().to_path_buf();
    let artifact = b"the committed rlib, served over the wire".repeat(32);
    commit_one_action(&state_dir, &artifact);

    let mut daemon = spawn_daemon(&state_dir);
    let mut stream = connect(&state_dir.join("rabsd.sock"));
    let hello = round_trip(&mut stream, HELLO);
    assert!(hello.contains("hello-ok"), "{hello}");

    // The hit.
    let worktree = dir.path().join("worktree");
    let key = hex(&sample_action_key().bytes);
    let reply = round_trip(
        &mut stream,
        &format!(
            "{{\"kind\":\"serve\",\"action_key\":\"{key}\",\"destination_root\":\"{}\"}}",
            worktree.display()
        ),
    );
    assert!(
        reply.contains("\"outcome\":\"served\""),
        "expected a served hit, got {reply}"
    );
    let served = worktree.join("out").join("lib.rlib");
    assert!(reply.contains(&served.display().to_string()), "{reply}");
    assert_eq!(
        std::fs::read(&served).expect("the served artifact"),
        artifact,
        "the daemon must materialize the committed bytes"
    );

    // A key nobody committed is a typed MISS, distinguishable from a hit
    // and from a fault — the distinction a caller that may skip work
    // depends on.
    let miss = round_trip(
        &mut stream,
        &format!(
            "{{\"kind\":\"serve\",\"action_key\":\"{}\",\"destination_root\":\"{}\"}}",
            "aa".repeat(32),
            dir.path().join("elsewhere").display()
        ),
    );
    assert!(
        miss.contains("\"outcome\":\"not-servable\"") && miss.contains("NoRecord"),
        "expected a typed miss, got {miss}"
    );
    assert!(!dir.path().join("elsewhere").exists());

    // Malformed requests are refusals, not writes.
    let bad_key = round_trip(
        &mut stream,
        "{\"kind\":\"serve\",\"action_key\":\"nope\",\"destination_root\":\"/tmp\"}",
    );
    assert!(bad_key.contains("bad-action-key"), "{bad_key}");
    let relative = round_trip(
        &mut stream,
        &format!(
            "{{\"kind\":\"serve\",\"action_key\":\"{key}\",\"destination_root\":\"relative/dir\"}}"
        ),
    );
    assert!(relative.contains("relative-destination"), "{relative}");

    // The daemon is unharmed and still exits clean.
    drop(stream);
    Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .expect("SIGTERM");
    let status = daemon.wait().expect("daemon exit");
    assert_eq!(
        status.code(),
        Some(0),
        "daemon must exit clean after serving"
    );
}
