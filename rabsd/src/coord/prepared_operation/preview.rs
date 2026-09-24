//! Ephemeral, bounded observations for one running execution attempt.
//!
//! These bytes are lossy diagnostics, never a complete transcript or completion
//! evidence. Independent readers supply their own cursors. Neither the transport
//! callback nor readers take the durable operation mutex or perform filesystem I/O.

use rabs_asupersync::stream_drain::preview::{MAX_PREVIEW_BYTES, OutputPreview, PreviewStream};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Tail {
    start: u64,
    end: u64,
    bytes: Vec<u8>,
}

impl Default for Tail {
    fn default() -> Self {
        Self {
            start: 0,
            end: 0,
            bytes: Vec::with_capacity(MAX_PREVIEW_BYTES),
        }
    }
}

impl Tail {
    fn append(&mut self, segment: &OutputPreview) {
        let end = segment.offset + segment.bytes.len() as u64;
        if self.end != segment.offset {
            self.bytes.clear();
            self.start = segment.offset;
        }
        let discard = (self.bytes.len() + segment.bytes.len()).saturating_sub(MAX_PREVIEW_BYTES);
        if discard != 0 {
            self.bytes.drain(..discard);
            self.start += discard as u64;
        }
        self.bytes.extend_from_slice(&segment.bytes);
        self.end = end;
    }

    fn read(
        &self,
        stream: PreviewStream,
        cursor: u64,
        delivered: u64,
        observed: u64,
    ) -> OutputPreview {
        if cursor < self.end {
            let offset = cursor.max(self.start);
            OutputPreview {
                stream,
                offset,
                bytes: self.bytes[(offset - self.start) as usize..].to_vec(),
                skipped_bytes: offset - cursor,
                observed_bytes: observed,
            }
        } else {
            // Only the delivered frontier proves a preview gap. observed_bytes
            // may describe bytes which the worker has not sent to us yet.
            let offset = cursor.max(delivered);
            OutputPreview {
                stream,
                offset,
                bytes: Vec::new(),
                skipped_bytes: offset - cursor,
                observed_bytes: observed,
            }
        }
    }
}

#[derive(Debug, Default)]
struct Frontier {
    delivered: AtomicU64,
    observed: AtomicU64,
}

#[derive(Debug)]
struct Inner {
    operation_id: String,
    request_sha256: String,
    attempt: u64,
    enabled: Arc<AtomicBool>,
    open: AtomicBool,
    available: AtomicBool,
    active: AtomicBool,
    stdout: Frontier,
    stderr: Frontier,
    tails: Mutex<[Tail; 2]>,
}

/// A callback capability bound to one saved request and one linear claim.
#[derive(Debug, Clone)]
pub struct PreviewObserver(Arc<Inner>);

impl PreviewObserver {
    #[cfg(test)]
    pub(crate) fn new(id: &str, fingerprint: &str, attempt: u64) -> Self {
        PreviewRegistry::default()
            .register(id, fingerprint, attempt)
            .unwrap()
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self, stdout_offset: u64, stderr_offset: u64) -> io::Result<Value> {
        self.read(stdout_offset, stderr_offset)
    }

    fn is_open(&self) -> bool {
        self.0.open.load(Ordering::Acquire) && self.0.enabled.load(Ordering::Acquire)
    }

    pub(super) fn close(&self) {
        self.0.open.store(false, Ordering::Release);
    }

    /// Record an already validated worker preview reply without waiting for a
    /// reader. A false return loses only diagnostics; it never affects execution.
    /// Empty valid replies make support observable before the first output byte.
    pub fn observe(&self, active: bool, segments: &[OutputPreview]) -> bool {
        if !self.is_open() || segments.len() > 2 {
            return false;
        }
        let mut seen = [false; 2];
        for segment in segments {
            let index = index(segment.stream);
            if seen[index]
                || segment.bytes.len() > MAX_PREVIEW_BYTES
                || segment.skipped_bytes > segment.offset
                || segment
                    .offset
                    .checked_add(segment.bytes.len() as u64)
                    .is_none_or(|end| end > segment.observed_bytes)
            {
                return false;
            }
            seen[index] = true;
        }
        // Remember bytes discarded because of contention as an explicit gap.
        // The worker protocol validates monotonic cursors before this callback.
        for segment in segments {
            let frontier = self.frontier(segment.stream);
            frontier
                .observed
                .fetch_max(segment.observed_bytes, Ordering::AcqRel);
            frontier.delivered.fetch_max(
                segment.offset + segment.bytes.len() as u64,
                Ordering::AcqRel,
            );
        }
        self.0.active.store(active, Ordering::Release);
        self.0.available.store(true, Ordering::Release);
        let Ok(mut tails) = self.0.tails.try_lock() else {
            return false;
        };
        if !self.is_open()
            || segments
                .iter()
                .any(|segment| segment.offset < tails[index(segment.stream)].end)
        {
            return false;
        }
        for segment in segments {
            tails[index(segment.stream)].append(segment);
        }
        true
    }

    fn frontier(&self, stream: PreviewStream) -> &Frontier {
        match stream {
            PreviewStream::Stdout => &self.0.stdout,
            PreviewStream::Stderr => &self.0.stderr,
        }
    }

    fn read(&self, stdout_offset: u64, stderr_offset: u64) -> io::Result<Value> {
        let unavailable = || {
            reply(
                &self.0.operation_id,
                &self.0.request_sha256,
                self.0.attempt,
                Some("unavailable"),
                false,
                Vec::new(),
            )
        };
        if !self.is_open() || !self.0.available.load(Ordering::Acquire) {
            return Ok(unavailable());
        }
        let Ok(tails) = self.0.tails.try_lock() else {
            return Ok(reply(
                &self.0.operation_id,
                &self.0.request_sha256,
                self.0.attempt,
                Some("busy"),
                false,
                Vec::new(),
            ));
        };
        let mut segments = Vec::with_capacity(2);
        for (stream, cursor) in [
            (PreviewStream::Stdout, stdout_offset),
            (PreviewStream::Stderr, stderr_offset),
        ] {
            let frontier = self.frontier(stream);
            let delivered = frontier.delivered.load(Ordering::Acquire);
            let observed = frontier.observed.load(Ordering::Acquire);
            if cursor > delivered {
                return Err(super::invalid(
                    "preview cursor exceeds the delivered stream",
                ));
            }
            segments.push(tails[index(stream)].read(stream, cursor, delivered, observed));
        }
        drop(tails);
        if !self.is_open() {
            return Ok(unavailable());
        }
        Ok(reply(
            &self.0.operation_id,
            &self.0.request_sha256,
            self.0.attempt,
            None,
            self.0.active.load(Ordering::Acquire),
            segments,
        ))
    }
}

fn index(stream: PreviewStream) -> usize {
    match stream {
        PreviewStream::Stdout => 0,
        PreviewStream::Stderr => 1,
    }
}

fn reply(
    id: &str,
    fingerprint: &str,
    attempt: u64,
    reason: Option<&str>,
    active: bool,
    segments: Vec<OutputPreview>,
) -> Value {
    let segments: Vec<_> = segments.into_iter().map(|segment| json!({
        "stream":segment.stream.name(), "offset":segment.offset,
        "next_offset":segment.offset + segment.bytes.len() as u64,
        "data_hex":segment.bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "skipped_bytes":segment.skipped_bytes, "observed_bytes":segment.observed_bytes,
    })).collect();
    json!({
        "kind":"prepared-preview", "operation_id":id, "request_sha256":fingerprint,
        "attempt":attempt, "available":reason.is_none(), "active":active, "reason":reason,
        "segments":segments, "complete":false, "publication_authorized":false,
    })
}

/// A separate bounded registry keeps optional preview traffic off the durable
/// state lock. Closed entries are pruned on admission; none survive a restart.
#[derive(Debug)]
pub(super) struct PreviewRegistry {
    enabled: Arc<AtomicBool>,
    entries: Mutex<BTreeMap<String, PreviewObserver>>,
}

impl Default for PreviewRegistry {
    fn default() -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(true)),
            entries: Mutex::default(),
        }
    }
}

impl PreviewRegistry {
    pub(super) fn register(
        &self,
        id: &str,
        fingerprint: &str,
        attempt: u64,
    ) -> Option<PreviewObserver> {
        let mut entries = self.entries.try_lock().ok()?;
        entries.retain(|_, observer| observer.is_open());
        if !self.enabled.load(Ordering::Acquire)
            || entries.len() >= super::MAX_RUNNING
            || entries.contains_key(id)
        {
            return None;
        }
        let observer = PreviewObserver(Arc::new(Inner {
            operation_id: id.to_owned(),
            request_sha256: fingerprint.to_owned(),
            attempt,
            enabled: Arc::clone(&self.enabled),
            open: AtomicBool::new(true),
            available: AtomicBool::new(false),
            active: AtomicBool::new(false),
            stdout: Frontier::default(),
            stderr: Frontier::default(),
            tails: Mutex::new([Tail::default(), Tail::default()]),
        }));
        entries.insert(id.to_owned(), observer.clone());
        Some(observer)
    }

    pub(super) fn stop(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    fn read(
        &self,
        id: &str,
        fingerprint: &str,
        attempt: u64,
        stdout_offset: u64,
        stderr_offset: u64,
    ) -> io::Result<Value> {
        super::require(
            super::valid_id(id)
                && fingerprint.len() == 64
                && fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid preview operation identity",
        )?;
        let unavailable = |reason| reply(id, fingerprint, attempt, Some(reason), false, Vec::new());
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(unavailable("unavailable"));
        }
        let Ok(entries) = self.entries.try_lock() else {
            return Ok(unavailable("busy"));
        };
        let observer = entries.get(id).cloned();
        drop(entries);
        let Some(observer) = observer.filter(PreviewObserver::is_open) else {
            return Ok(unavailable("unavailable"));
        };
        super::require(
            observer.0.request_sha256 == fingerprint && observer.0.attempt == attempt,
            "preview belongs to a different request or execution attempt",
        )?;
        observer.read(stdout_offset, stderr_offset)
    }
}

impl super::PreparedOperationStore {
    /// Read only ephemeral diagnostics. This never verifies delivery bytes or
    /// authorizes completion, installation, publication, or execution fallback.
    pub fn preview(
        &self,
        id: &str,
        request_sha256: &str,
        attempt: u64,
        stdout_offset: u64,
        stderr_offset: u64,
    ) -> io::Result<Value> {
        self.previews
            .read(id, request_sha256, attempt, stdout_offset, stderr_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "00000000000000000000000000000001";
    const HASH: &str = "abababababababababababababababababababababababababababababababab";

    fn segment(stream: PreviewStream, offset: u64, bytes: &[u8], observed: u64) -> OutputPreview {
        OutputPreview {
            stream,
            offset,
            bytes: bytes.to_vec(),
            skipped_bytes: 0,
            observed_bytes: observed,
        }
    }

    #[test]
    fn independent_clients_read_identical_binary_bytes_without_consuming_the_tail() {
        let observer = PreviewObserver::new(ID, HASH, 1);
        assert!(observer.observe(
            true,
            &[
                segment(PreviewStream::Stdout, 0, b"a\0\xff", 3),
                segment(PreviewStream::Stderr, 0, b"error\n", 6),
            ]
        ));
        let first = observer.snapshot(0, 0).unwrap();
        assert_eq!(first, observer.snapshot(0, 0).unwrap());
        assert_eq!(first["segments"][0]["data_hex"], "6100ff");
        assert_eq!(first["segments"][1]["data_hex"], "6572726f720a");
        assert_eq!(first["complete"], false);
        assert_eq!(first["publication_authorized"], false);
        assert_eq!(
            observer.snapshot(1, 6).unwrap()["segments"][0]["data_hex"],
            "00ff"
        );
    }

    #[test]
    fn bounded_tail_reports_a_gap_per_client_and_stays_below_the_edge_frame_limit() {
        let observer = PreviewObserver::new(ID, HASH, 1);
        let bytes = vec![b'x'; MAX_PREVIEW_BYTES];
        for stream in [PreviewStream::Stdout, PreviewStream::Stderr] {
            assert!(observer.observe(true, &[segment(stream, 0, &bytes, 8192)]));
            assert!(observer.observe(true, &[segment(stream, 8192, b"yz", 8194)]));
        }
        let snapshot = observer.snapshot(0, 2).unwrap();
        assert_eq!(snapshot["segments"][0]["offset"], 2);
        assert_eq!(snapshot["segments"][0]["skipped_bytes"], 2);
        assert_eq!(snapshot["segments"][1]["skipped_bytes"], 0);
        assert_eq!(snapshot["segments"][0]["next_offset"], 8194);
        assert_eq!(
            snapshot["segments"][0]["data_hex"].as_str().unwrap().len(),
            16384
        );
        assert!(serde_json::to_vec(&snapshot).unwrap().len() < 64 * 1024);
        assert_eq!(
            observer.0.tails.lock().unwrap()[0].bytes.len(),
            MAX_PREVIEW_BYTES
        );
        assert_eq!(
            observer.0.tails.lock().unwrap()[0].bytes.capacity(),
            MAX_PREVIEW_BYTES
        );
    }

    #[test]
    fn uneven_appends_keep_the_allocation_fixed_at_eight_kib_per_lane() {
        let observer = PreviewObserver::new(ID, HASH, 1);
        let mut offset = 0;
        for count in [5000, 2000, 999, 301, 8192, 7] {
            assert!(observer.observe(
                true,
                &[segment(
                    PreviewStream::Stdout,
                    offset,
                    &vec![b'x'; count],
                    offset + count as u64
                )]
            ));
            offset += count as u64;
            let tails = observer.0.tails.lock().unwrap();
            assert!(tails[0].bytes.len() <= MAX_PREVIEW_BYTES);
            assert_eq!(tails[0].bytes.capacity(), MAX_PREVIEW_BYTES);
        }
    }

    #[test]
    fn producer_observed_highwater_never_skips_bytes_not_yet_delivered() {
        let observer = PreviewObserver::new(ID, HASH, 1);
        assert!(observer.observe(true, &[segment(PreviewStream::Stdout, 0, b"first", 11)]));
        let first = observer.snapshot(0, 0).unwrap();
        assert_eq!(first["segments"][0]["next_offset"], 5);
        assert_eq!(first["segments"][0]["observed_bytes"], 11);
        assert_eq!(
            observer.snapshot(5, 0).unwrap()["segments"][0]["next_offset"],
            5
        );
        assert!(observer.observe(true, &[segment(PreviewStream::Stdout, 5, b"second", 11)]));
        let next = observer.snapshot(5, 0).unwrap();
        assert_eq!(next["segments"][0]["data_hex"], "7365636f6e64");
        assert_eq!(next["segments"][0]["skipped_bytes"], 0);
        assert_eq!(next["segments"][0]["next_offset"], 11);
    }

    #[test]
    fn contention_is_nonblocking_and_dropped_bytes_become_an_explicit_gap() {
        let observer = PreviewObserver::new(ID, HASH, 1);
        assert!(observer.observe(true, &[segment(PreviewStream::Stdout, 0, b"old", 3)]));
        let guard = observer.0.tails.lock().unwrap();
        // Both calls execute on the lock holder: a blocking lock would deadlock.
        assert!(!observer.observe(true, &[segment(PreviewStream::Stdout, 3, b"lost", 7)]));
        assert_eq!(observer.snapshot(0, 0).unwrap()["reason"], "busy");
        drop(guard);
        let old = observer.snapshot(0, 0).unwrap();
        assert_eq!(old["segments"][0]["data_hex"], "6f6c64");
        assert_eq!(old["segments"][0]["next_offset"], 3);
        let gap = observer.snapshot(3, 0).unwrap();
        assert_eq!(gap["segments"][0]["offset"], 7);
        assert_eq!(gap["segments"][0]["skipped_bytes"], 4);
        assert_eq!(gap["segments"][0]["data_hex"], "");
        assert!(observer.observe(true, &[segment(PreviewStream::Stdout, 7, b"new", 10)]));
        assert_eq!(
            observer.snapshot(3, 0).unwrap()["segments"][0]["skipped_bytes"],
            4
        );
        assert_eq!(
            observer.snapshot(7, 0).unwrap()["segments"][0]["data_hex"],
            "6e6577"
        );
    }

    #[test]
    fn validation_rejects_overflow_duplicates_and_future_cursors() {
        let observer = PreviewObserver::new(ID, HASH, 1);
        let valid = segment(PreviewStream::Stdout, 0, b"ok", 2);
        assert!(!observer.observe(true, &[valid.clone(), valid.clone()]));
        assert!(!observer.observe(
            true,
            &[segment(PreviewStream::Stderr, u64::MAX, b"x", u64::MAX)]
        ));
        assert!(!observer.observe(
            true,
            &[segment(PreviewStream::Stderr, 0, &vec![0; 8193], 8193)]
        ));
        assert_eq!(observer.snapshot(0, 0).unwrap()["available"], false);
        assert!(observer.observe(true, &[valid]));
        assert!(observer.snapshot(3, 0).is_err());
    }

    #[test]
    fn empty_support_reply_is_available_but_closed_observers_cannot_reopen() {
        let observer = PreviewObserver::new(ID, HASH, 1);
        assert_eq!(observer.snapshot(0, 0).unwrap()["reason"], "unavailable");
        assert!(observer.observe(true, &[]));
        assert_eq!(observer.snapshot(0, 0).unwrap()["available"], true);
        let guard = observer.0.tails.lock().unwrap();
        observer.close();
        assert!(!observer.observe(true, &[segment(PreviewStream::Stdout, 0, b"late", 4)]));
        assert_eq!(observer.snapshot(0, 0).unwrap()["reason"], "unavailable");
        drop(guard);
        assert_eq!(observer.snapshot(0, 0).unwrap()["segments"], json!([]));
    }

    #[test]
    fn registry_binds_request_attempt_and_bounds_live_entries_without_waiting() {
        let registry = PreviewRegistry::default();
        let observer = registry.register(ID, HASH, 1).unwrap();
        observer.observe(true, &[]);
        assert!(registry.read(ID, &"cd".repeat(32), 1, 0, 0).is_err());
        assert!(registry.read(ID, HASH, 2, 0, 0).is_err());
        assert!(registry.read("bad", HASH, 1, 0, 0).is_err());
        for index in 2..=super::super::MAX_RUNNING {
            registry
                .register(&format!("{index:032x}"), HASH, 1)
                .unwrap();
        }
        assert!(
            registry
                .register(&format!("{:032x}", 99), HASH, 1)
                .is_none()
        );
        let guard = registry.entries.lock().unwrap();
        assert_eq!(registry.read(ID, HASH, 1, 0, 0).unwrap()["reason"], "busy");
        assert!(
            registry
                .register(&format!("{:032x}", 99), HASH, 1)
                .is_none()
        );
        drop(guard);
        observer.close();
        let next = registry.register(ID, HASH, 2).unwrap();
        assert_eq!(
            registry.entries.lock().unwrap().len(),
            super::super::MAX_RUNNING
        );
        assert!(!observer.observe(true, &[]));
        assert!(registry.read(ID, HASH, 1, 0, 0).is_err());
        assert!(next.observe(true, &[]));
        registry.stop();
        assert!(!next.observe(true, &[]));
        assert_eq!(
            registry.read(ID, HASH, 2, 0, 0).unwrap()["reason"],
            "unavailable"
        );
    }

    struct Fixture {
        _temporary: tempfile::TempDir,
        root: std::path::PathBuf,
        store: Arc<super::super::PreparedOperationStore>,
        spec: super::super::PreparedOperationSpec,
        fingerprint: String,
    }

    impl Fixture {
        fn new() -> Self {
            use crate::coord::source_delivery::prepare_source_bundle;
            use std::fs;
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().canonicalize().unwrap();
            let checkout = root.join("checkout");
            let bundle = root.join("bundle");
            fs::create_dir(&checkout).unwrap();
            fs::write(checkout.join("lib.rs"), b"pub fn answer() -> u32 { 42 }\n").unwrap();
            // A valid preparation fixture, not a claim of an executed compiler.
            prepare_source_bundle(
                &checkout,
                &json!({
                    "kind":"canonical-exec", "request_id":1,
                    "program":"/__rabs/toolchain/bin/rustc",
                    "toolchain_backing":"/opt/preview-test-toolchain",
                    "toolchain_identity":{
                        "version":"toolchain-dataset-v1", "sha256":HASH, "files":1, "bytes":4,
                    },
                    "source_files":["lib.rs"],
                    "args":["lib.rs", "--crate-type", "lib", "--emit", "metadata",
                        "-o", "/__rabs/out/compile/libfixture.rmeta"],
                    "artifacts":{"unit":"compile", "files":["libfixture.rmeta"]},
                    "timeout_ms":10000,
                }),
                &bundle,
            )
            .unwrap();
            let spec = super::super::PreparedOperationSpec {
                id: ID.to_owned(),
                address: "127.0.0.1:31001".into(),
                worker: "preview-worker".into(),
                worker_spki_sha256: HASH.to_owned(),
                bundle,
                delivery: root.join("delivery"),
                output: root.join("output"),
            };
            let store =
                super::super::PreparedOperationStore::open(&root.join("operations")).unwrap();
            let status = store.submit(spec.clone()).unwrap();
            assert_eq!(status.attempt, 0);
            Self {
                _temporary: temporary,
                root,
                store,
                spec,
                fingerprint: status.request_sha256,
            }
        }

        fn preview(&self, attempt: u64) -> Value {
            self.store
                .preview(ID, &self.fingerprint, attempt, 0, 0)
                .unwrap()
        }
    }

    #[test]
    fn actual_claim_previews_bypass_the_durable_mutex_and_close_before_finish() {
        let fixture = Fixture::new();
        assert_eq!(fixture.preview(0)["available"], false);
        let claim = fixture.store.claim_next().unwrap().unwrap();
        assert_eq!(fixture.store.status(ID).unwrap().unwrap().attempt, 1);
        let observer = claim.preview_observer().unwrap();
        let before =
            std::fs::read(fixture.root.join("operations").join(format!("{ID}.json"))).unwrap();
        let state = fixture.store.state.lock().unwrap();
        assert!(observer.observe(
            true,
            &[segment(PreviewStream::Stderr, 0, b"diagnostic", 10)]
        ));
        assert_eq!(
            fixture.preview(1)["segments"][1]["data_hex"],
            "646961676e6f73746963"
        );
        drop(state);
        assert_eq!(
            before,
            std::fs::read(fixture.root.join("operations").join(format!("{ID}.json"))).unwrap()
        );
        claim
            .finish(super::super::OperationOutcome::Failed {
                detail: "fixture stopped before sending execution".into(),
                execution_may_have_run: false,
            })
            .unwrap();
        assert_eq!(fixture.preview(1)["available"], false);
        assert!(!observer.observe(true, &[]));
        assert!(!fixture.spec.delivery.exists());
        assert!(!fixture.spec.output.exists());
    }

    #[test]
    fn dropped_claim_resume_and_reopen_never_expose_a_previous_attempt_tail() {
        let fixture = Fixture::new();
        let claim = fixture.store.claim_next().unwrap().unwrap();
        let observer = claim.preview_observer().unwrap();
        observer.observe(true, &[segment(PreviewStream::Stdout, 0, b"old", 3)]);
        drop(claim);
        assert_eq!(fixture.preview(1)["available"], false);
        fixture
            .store
            .resume(ID, fixture.root.join("resume"), None)
            .unwrap();
        let resumed = fixture.store.claim_next().unwrap().unwrap();
        assert_eq!(fixture.store.status(ID).unwrap().unwrap().attempt, 2);
        assert!(resumed.preview_observer().is_none());
        assert!(!observer.observe(true, &[segment(PreviewStream::Stdout, 3, b"late", 7)]));
        assert_eq!(fixture.preview(2)["available"], false);
        drop(resumed);
        let Fixture {
            _temporary,
            root,
            store,
            spec: _,
            fingerprint,
        } = fixture;
        drop(store);
        let reopened =
            super::super::PreparedOperationStore::open(&root.join("operations")).unwrap();
        assert_eq!(reopened.status(ID).unwrap().unwrap().attempt, 2);
        assert_eq!(
            reopened.preview(ID, &fingerprint, 2, 0, 0).unwrap()["available"],
            false
        );
    }

    #[test]
    fn preview_registry_contention_never_prevents_the_real_execution_claim() {
        let fixture = Fixture::new();
        let entries = fixture.store.previews.entries.lock().unwrap();
        let claim = fixture.store.claim_next().unwrap().unwrap();
        assert!(claim.preview_observer().is_none());
        drop(entries);
        assert_eq!(fixture.store.status(ID).unwrap().unwrap().attempt, 1);
        assert_eq!(fixture.preview(1)["available"], false);
        drop(claim);
    }

    #[test]
    fn shutdown_and_uncertain_persistence_close_observers_without_taking_their_mutex() {
        for poison in [false, true] {
            let fixture = Fixture::new();
            let claim = fixture.store.claim_next().unwrap().unwrap();
            let observer = claim.preview_observer().unwrap();
            observer.observe(true, &[]);
            let tails = observer.0.tails.lock().unwrap();
            if poison {
                fixture
                    .store
                    .fail_after_rename
                    .store(true, Ordering::SeqCst);
                assert!(claim.listening("127.0.0.1:31001".parse().unwrap()).is_err());
            } else {
                fixture.store.stop().unwrap();
            }
            assert_eq!(fixture.preview(1)["available"], false);
            assert!(!observer.observe(true, &[]));
            drop(tails);
            drop(claim);
        }
    }
}
