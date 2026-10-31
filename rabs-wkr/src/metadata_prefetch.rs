//! Private, bounded metadata bytes available while the original process runs.
//!
//! The execution owner observes complete rustc artifact notifications through
//! an independent lossy cursor, then copies the named declared file. A missed
//! notification or failed capture merely disables this optimization. Neither
//! the pipe drains nor the async session perform filesystem capture. The final
//! ordinary artifact manifest remains the only selector of reusable bytes.

use rabs_protocol::metadata_prefetch::{CHUNK_BYTES, VERSION};
use serde_json::{Value, json};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

#[derive(Debug)]
struct FrozenMetadata {
    name: String,
    bytes: Vec<u8>,
    sha256: String,
}

#[derive(Debug, Default)]
struct State {
    file: Option<FrozenMetadata>,
    offset: usize,
    #[cfg(target_os = "linux")]
    offered: bool,
    waker: Option<Waker>,
}

/// One selected execution owns at most one immutable bounded candidate.
#[derive(Debug, Default)]
pub(crate) struct MetadataPrefetch {
    selected: AtomicBool,
    state: Mutex<State>,
}

impl MetadataPrefetch {
    pub(crate) fn select(&self) {
        self.selected.store(true, Ordering::Release);
    }

    #[cfg(target_os = "linux")]
    fn offer(&self, file: FrozenMetadata) {
        let wake = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            if state.offered || !self.selected.load(Ordering::Acquire) {
                return;
            }
            state.offered = true;
            state.file = Some(file);
            state.waker.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    pub(crate) fn poll_chunk(&self, request: u64, cx: &mut Context<'_>) -> Poll<Value> {
        let Ok(mut state) = self.state.lock() else {
            return Poll::Pending;
        };
        // The session can poll immediately after thread creation, before its
        // executor has selected this optional lane. Register the wake even then
        // so the first offer cannot wait silently for terminal completion.
        if !self.selected.load(Ordering::Acquire) || state.file.is_none() {
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let file = state.file.as_ref().expect("selected metadata candidate");
        let end = (state.offset + CHUNK_BYTES).min(file.bytes.len());
        let bytes = &file.bytes[state.offset..end];
        let done = end == file.bytes.len();
        // Keep one small allocation per scheduling quantum; formatting every
        // individual byte would add thousands of allocations on the reactor.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            encoded.push(HEX[usize::from(byte >> 4)] as char);
            encoded.push(HEX[usize::from(byte & 15)] as char);
        }
        let frame = json!({
            "kind":"metadata-prefetch", "version":VERSION, "request_id":request,
            "name":file.name, "total_bytes":file.bytes.len(), "sha256":file.sha256,
            "executable":false, "offset":state.offset, "next_offset":end,
            "data_hex":encoded,
            "chunk_sha256":crate::session::sha256_hex(bytes), "eof":done,
            "publication_authorized":false,
        });
        // Burn this quantum before the possibly partial socket write. A lost
        // connection cannot turn it into a second execution or result offer.
        state.offset = end;
        if done {
            state.file = None;
        }
        Poll::Ready(frame)
    }
}

#[cfg(target_os = "linux")]
mod capture {
    use super::*;
    use crate::artifacts::PreparedArtifacts;
    use crate::execution::ExecutionControl;
    use rabs_asupersync::stream_drain::preview::{LiveOutputPreview, PreviewStream};
    use rabs_protocol::metadata_prefetch::{MAX_BYTES, candidate};
    use rustix::fs::{Mode, OFlags, open, openat};
    use sha2::{Digest, Sha256};
    use std::fs::{File, Metadata};
    use std::io::{self, Read};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const MAX_LINE_BYTES: usize = 4096;

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Signature {
        device: u64,
        inode: u64,
        size: u64,
        mode: u32,
        links: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    fn signature(metadata: &Metadata) -> io::Result<Signature> {
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o111 != 0
            || metadata.len() == 0
            || metadata.len() > MAX_BYTES as u64
        {
            return Err(io::Error::other("ineligible metadata prefetch file"));
        }
        Ok(Signature {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    fn directory_identity(path: &Path) -> io::Result<(u64, u64)> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() {
            return Err(io::Error::other("metadata output root is not a directory"));
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    /// Runs only on the existing blocking process owner between wait polls.
    /// The root descriptor names its original private output directory; no
    /// event field becomes a host pathname or a new artifact declaration.
    pub(crate) struct MetadataObserver {
        root: File,
        root_path: PathBuf,
        root_identity: (u64, u64),
        name: String,
        visible: String,
        preview: Arc<LiveOutputPreview>,
        cursor: u64,
        line: Vec<u8>,
        discard_line: bool,
        done: bool,
    }

    impl MetadataObserver {
        pub(crate) fn new(
            artifacts: &PreparedArtifacts,
            visible_root: &str,
            control: &ExecutionControl,
        ) -> Option<Self> {
            if !control.metadata_prefetch.selected.load(Ordering::Acquire)
                || !artifacts.plan().is_exact()
            {
                return None;
            }
            let name = candidate(artifacts.plan().files())?.to_owned();
            let root = File::from(
                open(
                    artifacts.backing(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .ok()?,
            );
            let metadata = root.metadata().ok()?;
            let root_identity = (metadata.dev(), metadata.ino());
            if directory_identity(artifacts.backing()).ok()? != root_identity {
                return None;
            }
            Some(Self {
                root,
                root_path: artifacts.backing().to_path_buf(),
                root_identity,
                visible: format!("{visible_root}/{name}"),
                name,
                preview: control.output_observer(),
                cursor: 0,
                line: Vec::with_capacity(MAX_LINE_BYTES),
                discard_line: false,
                done: false,
            })
        }

        pub(crate) fn poll(&mut self, control: &ExecutionControl) {
            if self.done || control.reason().is_some() {
                return;
            }
            let Some(segment) = self.preview.read_since(PreviewStream::Stderr, self.cursor) else {
                return;
            };
            self.cursor = segment.offset + segment.bytes.len() as u64;
            if segment.skipped_bytes != 0 {
                self.line.clear();
                // The first retained byte after a gap may be inside a record.
                // Only a following complete newline-delimited record can match.
                self.discard_line = true;
            }
            for byte in segment.bytes {
                if byte == b'\n' {
                    let notification = !self.discard_line && self.matches_notification();
                    self.line.clear();
                    self.discard_line = false;
                    if notification {
                        self.done = true;
                        if let Ok(file) = self.freeze(|| control.reason().is_some()) {
                            control.metadata_prefetch.offer(file);
                        }
                        return;
                    }
                } else if !self.discard_line {
                    if self.line.len() == MAX_LINE_BYTES {
                        self.line.clear();
                        self.discard_line = true;
                    } else {
                        self.line.push(byte);
                    }
                }
            }
        }

        fn matches_notification(&self) -> bool {
            let Ok(Value::Object(fields)) = serde_json::from_slice(&self.line) else {
                return false;
            };
            let exact_fields = fields.len() == 2
                || (fields.len() == 3
                    && fields.get("$message_type").and_then(Value::as_str) == Some("artifact"));
            exact_fields
                && fields.get("artifact").and_then(Value::as_str) == Some(self.visible.as_str())
                && fields.get("emit").and_then(Value::as_str) == Some("metadata")
        }

        fn freeze(&self, stopped: impl Fn() -> bool) -> io::Result<FrozenMetadata> {
            let checkpoint = || {
                if stopped() {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "metadata prefetch cancelled",
                    ))
                } else {
                    Ok(())
                }
            };
            checkpoint()?;
            if directory_identity(&self.root_path)? != self.root_identity {
                return Err(io::Error::other("metadata output root changed"));
            }
            let mut input = File::from(openat(
                &self.root,
                self.name.as_str(),
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let before = signature(&input.metadata()?)?;
            let path = self.root_path.join(&self.name);
            if signature(&std::fs::symlink_metadata(&path)?)? != before {
                return Err(io::Error::other("metadata pathname changed before capture"));
            }
            let mut bytes = vec![0; before.size as usize];
            let mut hasher = Sha256::new();
            for chunk in bytes.chunks_mut(CHUNK_BYTES) {
                checkpoint()?;
                input.read_exact(chunk)?;
                hasher.update(chunk);
            }
            checkpoint()?;
            let mut extra = [0];
            if input.read(&mut extra)? != 0
                || signature(&input.metadata()?)? != before
                || signature(&std::fs::symlink_metadata(path)?)? != before
                || directory_identity(&self.root_path)? != self.root_identity
            {
                return Err(io::Error::other("metadata changed during prefetch"));
            }
            Ok(FrozenMetadata {
                name: self.name.clone(),
                bytes,
                sha256: hasher
                    .finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::artifacts::ArtifactPlan;
        use crate::execution::{ExecutionCompletion, ExecutionTask, StopReason};
        use crate::output::CapturedOutputs;
        use rabs_asupersync::process_groups::ManagedProcessGroup;
        use rabs_asupersync::region_tree::Attribution;
        use rabs_asupersync::stream_drain::DrainLimits;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        fn fixture() -> (PreparedArtifacts, ExecutionControl, MetadataObserver) {
            let artifacts = PreparedArtifacts::new(
                ArtifactPlan::new(
                    "dep".into(),
                    vec!["libdep.rmeta".into(), "libdep.rlib".into()],
                )
                .unwrap(),
            )
            .unwrap();
            let control = ExecutionControl::new(Duration::from_secs(10)).unwrap();
            control.request_metadata_prefetch();
            let observer = MetadataObserver::new(&artifacts, "/__rabs/out/dep", &control).unwrap();
            (artifacts, control, observer)
        }

        fn notify(control: &ExecutionControl, offset: u64, bytes: &[u8]) {
            control
                .output_observer()
                .record(PreviewStream::Stderr, offset, bytes);
        }

        const NOTICE: &[u8] =
            b"{\"artifact\":\"/__rabs/out/dep/libdep.rmeta\",\"emit\":\"metadata\"}\n";

        #[test]
        fn complete_exact_notice_freezes_private_bytes_without_consuming_diagnostics() {
            let (artifacts, control, mut observer) = fixture();
            std::fs::write(artifacts.backing().join("libdep.rmeta"), b"metadata").unwrap();
            notify(&control, 0, &NOTICE[..12]);
            observer.poll(&control);
            assert!(!observer.done);
            notify(&control, 12, &NOTICE[12..]);
            observer.poll(&control);
            assert!(observer.done);
            std::fs::write(artifacts.backing().join("libdep.rmeta"), b"different").unwrap();
            let Poll::Ready(frame) = control
                .metadata_prefetch
                .poll_chunk(7, &mut Context::from_waker(Waker::noop()))
            else {
                panic!("no prefetched file")
            };
            assert_eq!(frame["data_hex"], "6d65746164617461");
            assert_eq!(frame["publication_authorized"], false);
            assert_eq!(
                control
                    .output_observer()
                    .take(PreviewStream::Stderr)
                    .unwrap()
                    .bytes,
                NOTICE
            );
        }

        #[test]
        fn gaps_unfinished_records_and_foreign_paths_never_open_files() {
            let (artifacts, control, mut observer) = fixture();
            std::fs::write(artifacts.backing().join("libdep.rmeta"), b"metadata").unwrap();
            notify(&control, 9, NOTICE);
            observer.poll(&control);
            assert!(!observer.done);
            let wrong =
                b"{\"artifact\":\"/__rabs/out/dep/../libdep.rmeta\",\"emit\":\"metadata\"}\n";
            let next = 9 + NOTICE.len() as u64;
            notify(&control, next, wrong);
            observer.poll(&control);
            assert!(!observer.done);
            notify(&control, next + wrong.len() as u64, NOTICE);
            observer.poll(&control);
            assert!(observer.done);
        }

        #[test]
        fn hostile_or_large_files_and_cancellation_are_optional_misses() {
            for kind in [
                "link",
                "hardlink",
                "empty",
                "large",
                "executable",
                "cancelled",
            ] {
                let (artifacts, control, mut observer) = fixture();
                let path = artifacts.backing().join("libdep.rmeta");
                match kind {
                    "link" => std::os::unix::fs::symlink("missing", &path).unwrap(),
                    "hardlink" => {
                        std::fs::write(artifacts.backing().join("original"), b"metadata").unwrap();
                        std::fs::hard_link(artifacts.backing().join("original"), &path).unwrap();
                    }
                    "empty" => {
                        File::create(&path).unwrap();
                    }
                    "large" => {
                        File::create(&path)
                            .unwrap()
                            .set_len(MAX_BYTES as u64 + 1)
                            .unwrap();
                    }
                    "executable" => {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::write(&path, b"metadata").unwrap();
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                            .unwrap();
                    }
                    _ => {
                        std::fs::write(&path, b"metadata").unwrap();
                        control.cancel(crate::execution::StopReason::Cancelled);
                    }
                }
                notify(&control, 0, NOTICE);
                observer.poll(&control);
                assert!(
                    control
                        .metadata_prefetch
                        .poll_chunk(7, &mut Context::from_waker(Waker::noop()))
                        .is_pending(),
                    "{kind}"
                );
            }
        }

        /// This is a real managed producer and real pipe drain, with an explicit
        /// artifact-notification fixture. It does not stand in for a native
        /// rustc/namespace qualification or claim compiler lineage authority.
        fn live_producer(root: &Path, bytes: &[u8]) -> (ExecutionTask, Arc<AtomicBool>) {
            let root = root.to_path_buf();
            std::fs::write(root.join("payload"), bytes).unwrap();
            let running = Arc::new(AtomicBool::new(false));
            let child_running = Arc::clone(&running);
            let plan = ArtifactPlan::new("dep".into(), vec!["libdep.rmeta".into()]).unwrap();
            let task = ExecutionTask::spawn_with_artifacts(
                7,
                Duration::from_secs(10),
                plan,
                move |control| {
                    control.request_metadata_prefetch();
                    control.request_output_capture();
                    let artifacts = PreparedArtifacts::new(control.artifact_plan().unwrap()).unwrap();
                    let mut observer = MetadataObserver::new(&artifacts, "/__rabs/out/dep", &control).unwrap();
                    let mut command = Command::new("/bin/sh");
                    command
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin")
                        .env("PAYLOAD", root.join("payload"))
                        .env("METADATA", artifacts.backing().join("libdep.rmeta"))
                        .env("NOTICE", std::str::from_utf8(NOTICE).unwrap().trim_end())
                        .env("GATE", root.join("continue"))
                        .args(["-c", r#"cat "$PAYLOAD" > "$METADATA"; printf '%s\n' "$NOTICE" >&2; while [ ! -e "$GATE" ]; do sleep 0.01; done"#])
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());
                    let group = ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
                    child_running.store(true, Ordering::Release);
                    let drained = group.wait_with_bounded_drain_preview(
                        &DrainLimits { resident_bound: 8, spill_dir: root.join("spills") },
                        4096,
                        Some(control.output_observer()),
                        || { observer.poll(&control); control.reason().is_some() },
                    ).unwrap();
                    child_running.store(false, Ordering::Release);
                    let outputs = CapturedOutputs::from_lanes(&drained.stdout, &drained.stderr).unwrap();
                    let result = crate::session::ExecResult {
                        request_id: 7,
                        exit_code: drained.status.code().unwrap_or(125),
                        stdout_sha256: outputs.stdout.sha256().to_owned(),
                        stderr_sha256: outputs.stderr.sha256().to_owned(),
                        executed: true,
                        residual_group_members: drained.residual_group_members,
                        stdout_spill_bytes: drained.stdout.spilled_bytes(),
                        stderr_spill_bytes: drained.stderr.spilled_bytes(),
                        stdout_spill_path: drained.stdout.spill().map(|spill| spill.path.display().to_string()),
                        stderr_spill_path: drained.stderr.spill().map(|spill| spill.path.display().to_string()),
                    };
                    control.retain_outputs(Ok(outputs)).unwrap();
                    if drained.status.success() && control.reason().is_none() {
                        control.retain_artifacts(artifacts.capture(|| control.reason().is_some()).map_err(|error| error.to_string())).unwrap();
                    }
                    result
                },
            ).unwrap();
            (task, running)
        }

        fn wait_for_completion(task: &mut ExecutionTask) -> ExecutionCompletion {
            let deadline = Instant::now() + Duration::from_secs(6);
            loop {
                if let Poll::Ready(result) =
                    task.poll_completion(&mut Context::from_waker(Waker::noop()))
                {
                    return result.unwrap();
                }
                assert!(
                    Instant::now() < deadline,
                    "real metadata producer did not resolve"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        #[test]
        fn real_live_producer_prefetches_before_exit_and_stops_at_cancel_or_completion() {
            for variant in ["complete", "cancelled", "terminal"] {
                let root = tempfile::tempdir().unwrap();
                let bytes = vec![0xa5; CHUNK_BYTES + 23];
                let (mut task, running) = live_producer(root.path(), &bytes);
                let deadline = Instant::now() + Duration::from_secs(6);
                let first = loop {
                    let mut cx = Context::from_waker(Waker::noop());
                    assert!(
                        task.poll_completion(&mut cx).is_pending(),
                        "producer exited before metadata"
                    );
                    if let Poll::Ready(frame) = task.poll_metadata_prefetch(&mut cx) {
                        break frame;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "real pipe notification did not freeze metadata"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                };
                assert!(running.load(Ordering::Acquire));
                assert_eq!(first["offset"], 0);
                assert_eq!(first["next_offset"], CHUNK_BYTES);
                assert_eq!(first["eof"], false);
                assert_eq!(first["sha256"], crate::session::sha256_hex(&bytes));
                assert_eq!(first["publication_authorized"], false);
                match variant {
                    "cancelled" => {
                        assert!(task.cancel(StopReason::Cancelled));
                        assert!(
                            task.poll_metadata_prefetch(&mut Context::from_waker(Waker::noop()))
                                .is_pending()
                        );
                    }
                    "complete" => {
                        let Poll::Ready(last) =
                            task.poll_metadata_prefetch(&mut Context::from_waker(Waker::noop()))
                        else {
                            panic!("metadata tail missing")
                        };
                        assert_eq!(last["offset"], CHUNK_BYTES);
                        assert_eq!(last["eof"], true);
                        assert_eq!(last["data_hex"], "a5".repeat(23));
                        std::fs::write(root.path().join("continue"), b"go").unwrap();
                    }
                    _ => {
                        std::fs::write(root.path().join("continue"), b"go").unwrap();
                    }
                }
                let mut completion = wait_for_completion(&mut task);
                assert!(!running.load(Ordering::Acquire));
                assert_eq!(completion.result.residual_group_members, 0);
                assert!(
                    task.poll_metadata_prefetch(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                assert_eq!(
                    completion
                        .outputs
                        .as_mut()
                        .unwrap()
                        .stderr
                        .read_chunk(0, 4096)
                        .unwrap(),
                    NOTICE
                );
                if variant == "cancelled" {
                    assert_eq!(completion.stop_reason, Some(StopReason::Cancelled));
                    assert!(completion.artifacts.is_none());
                } else {
                    assert_eq!(completion.result.exit_code, 0);
                    assert!(completion.stop_reason.is_none());
                    let (len, digest, mode) = completion
                        .artifacts
                        .as_ref()
                        .unwrap()
                        .file_identity("libdep.rmeta")
                        .unwrap();
                    assert_eq!(len, bytes.len() as u64);
                    assert_eq!(digest, crate::session::sha256_hex(&bytes));
                    assert!(!mode);
                }
            }
        }

        #[test]
        fn cancellation_is_checked_between_bounded_file_copy_quanta() {
            let (artifacts, _control, observer) = fixture();
            std::fs::write(
                artifacts.backing().join("libdep.rmeta"),
                vec![0x33; CHUNK_BYTES * 3],
            )
            .unwrap();
            let checkpoints = std::cell::Cell::new(0);
            let failure = observer
                .freeze(|| {
                    let next = checkpoints.get() + 1;
                    checkpoints.set(next);
                    next == 3
                })
                .unwrap_err();
            assert_eq!(failure.kind(), io::ErrorKind::Interrupted);
            assert_eq!(checkpoints.get(), 3);
        }

        #[test]
        fn offer_wakes_a_session_that_polled_before_executor_selection() {
            use std::task::Wake;

            struct WakeCount(std::sync::atomic::AtomicUsize);
            impl Wake for WakeCount {
                fn wake(self: Arc<Self>) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }
            let count = Arc::new(WakeCount(std::sync::atomic::AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&count));
            let mut cx = Context::from_waker(&waker);
            let prefetch = MetadataPrefetch::default();
            assert!(prefetch.poll_chunk(7, &mut cx).is_pending());
            prefetch.select();
            prefetch.offer(FrozenMetadata {
                name: "libdep.rmeta".into(),
                bytes: b"metadata".to_vec(),
                sha256: crate::session::sha256_hex(b"metadata"),
            });
            assert_eq!(count.0.load(Ordering::SeqCst), 1);
            assert!(prefetch.poll_chunk(7, &mut cx).is_ready());
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use capture::MetadataObserver;
