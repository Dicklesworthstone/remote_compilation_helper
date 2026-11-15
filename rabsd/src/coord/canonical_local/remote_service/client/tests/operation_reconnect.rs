use super::*;
use std::collections::VecDeque;

/// Script only transport records and explicit disconnections. Every test uses
/// the production client controller, Wire, receiver and publication receipt;
/// these peers do not qualify TLS or prove coordinator Cargo execution.
struct RecoveryPeer {
    inner: AdmissionStream,
    fail_write: Option<&'static str>,
}

impl RecoveryPeer {
    fn new(messages: &[Message]) -> Self {
        let mut inner = AdmissionStream::new(messages, false);
        inner.quantum = MAX_JSON_RECORD;
        Self {
            inner,
            fail_write: None,
        }
    }

    fn output(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.inner.output)
    }
}

impl AsyncRead for RecoveryPeer {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, output)
    }
}

impl AsyncWrite for RecoveryPeer {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let peer = self.get_mut();
        if peer.fail_write.is_some_and(|kind| {
            serde_json::from_slice::<Value>(bytes).is_ok_and(|message| message["kind"] == kind)
        }) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "scripted connection loss while sending a record",
            )));
        }
        Pin::new(&mut peer.inner).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

fn finished(exit_code: i32, target: Option<&ArtifactManifest>) -> Message {
    Message::BuildFinished {
        exit_code,
        stdout_bytes: 0,
        stderr_bytes: 0,
        target: target.map(ArtifactDeclaration::from_native),
    }
}

fn diagnostic(offset: u64, bytes: &[u8]) -> Output {
    Output {
        offset,
        bytes: encode_hex(bytes),
    }
}

fn client<'a>(config: &'a ClientProfile, stopped: &'a AtomicBool) -> ResumableClient<'a> {
    ResumableClient::new(
        config,
        stopped,
        "fixture-build",
        true,
        operation_token(),
        Instant::now() + Duration::from_secs(15),
    )
}

fn kinds(output: &Mutex<Vec<u8>>) -> Vec<String> {
    admission_messages(output)
        .iter()
        .map(|message| message["kind"].as_str().unwrap().into())
        .collect()
}

fn assert_resume(output: &Mutex<Vec<u8>>, stdout_offset: u64, stderr_offset: u64) {
    let messages = admission_messages(output);
    let resume = &messages[0];
    assert_eq!(resume["kind"], "resume");
    assert_eq!(resume["version"], WIRE_VERSION);
    assert_eq!(resume["build_identity"], "fixture-build");
    assert_eq!(resume["require_release"], true);
    assert_eq!(
        resume["token"],
        serde_json::to_value(operation_token()).unwrap()
    );
    assert_eq!(resume["stdout_offset"], stdout_offset);
    assert_eq!(resume["stderr_offset"], stderr_offset);
    assert!(messages.iter().all(|message| !matches!(
        message["kind"].as_str(),
        Some("hello" | "inputs-done" | "source-chunk" | "toolchain-entry")
    )));
}

#[test]
fn lost_input_acknowledgment_only_resumes_the_original_token() {
    for lost_send in [false, true] {
        let directory = private();
        let config = delivery_config(&directory.path().join("completed"));
        let stopped = AtomicBool::new(false);
        let mut client = client(&config, &stopped);
        let mut initial = RecoveryPeer::new(&[]);
        initial.fail_write = lost_send.then_some("inputs-done");
        let initial_output = initial.output();
        let pending = RecoveryPeer::new(&[Message::ResumePending {}]);
        let pending_output = pending.output();
        let resumed = RecoveryPeer::new(&[
            Message::Accepted {},
            finished(7, None),
            Message::Complete { exit_code: 7 },
        ]);
        let resumed_output = resumed.output();
        let mut peers = VecDeque::from([pending, resumed]);
        let result = native(client.complete(
            Wire::new(initial),
            || std::future::ready(Ok(peers.pop_front().expect("unexpected reconnect"))),
            &mut Vec::new(),
            &mut Vec::new(),
        ));
        assert_eq!(result.unwrap(), 7);
        assert_eq!(
            kinds(&initial_output),
            if lost_send {
                vec![]
            } else {
                vec!["inputs-done"]
            }
        );
        assert_resume(&pending_output, 0, 0);
        assert_resume(&resumed_output, 0, 0);
        assert_eq!(kinds(&pending_output), ["resume"]);
        assert_eq!(
            kinds(&resumed_output),
            ["resume", "poll", "close", "delivered"]
        );
        assert!(peers.is_empty());
    }
}

#[derive(Default)]
struct ObservedOutput {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for ObservedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn reconnect_retains_raw_stdout_privately_and_publishes_it_once() {
    let directory = private();
    let config = delivery_config(&directory.path().join("completed"));
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let first_stdout = b"first-out\x00\xff";
    let next_stdout = b"-next\n";
    let mut initial = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, first_stdout),
            stderr: diagnostic(0, b"first-err"),
        },
    ]);
    // A partial next record is never retained or continued on another stream.
    initial
        .inner
        .input
        .extend_from_slice(b"{\"kind\":\"progress\",\"stdout\":");
    let resumed = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(first_stdout.len() as u64, next_stdout),
            stderr: diagnostic(9, b""),
        },
        Message::BuildFinished {
            exit_code: 0,
            stdout_bytes: (first_stdout.len() + next_stdout.len()) as u64,
            stderr_bytes: 9,
            target: None,
        },
        Message::Complete { exit_code: 0 },
    ]);
    let resumed_output = resumed.output();
    let mut peers = VecDeque::from([resumed]);
    let mut stdout = ObservedOutput::default();
    let visible = Arc::clone(&stdout.bytes);
    let mut stderr = Vec::new();
    assert_eq!(
        native(client.complete(
            Wire::new(initial),
            || {
                assert!(visible.lock().unwrap().is_empty());
                std::future::ready(Ok(peers.pop_front().expect("unexpected reconnect")))
            },
            &mut stdout,
            &mut stderr,
        ))
        .unwrap(),
        0
    );
    assert_eq!(
        visible.lock().unwrap().as_slice(),
        b"first-out\x00\xff-next\n"
    );
    assert_eq!(stderr, b"first-err");
    assert_resume(&resumed_output, first_stdout.len() as u64, 9);
    assert_eq!(
        (client.delivery.stdout_offset, client.delivery.stderr_offset),
        ((first_stdout.len() + next_stdout.len()) as u64, 9)
    );
    assert!(client.delivery.stdout_published);
    assert!(client.delivery.stdout_spool.is_none());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

struct FailedOutput;

impl Write for FailedOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "local output disappeared",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn local_stderr_failure_cancels_without_publishing_retained_stdout() {
    let directory = private();
    let config = delivery_config(&directory.path().join("completed"));
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let initial = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, b"retained"),
            stderr: diagnostic(0, b"failed"),
        },
    ]);
    let output = initial.output();
    let mut connects = 0;
    let mut stdout = Vec::new();
    let error = native(client.complete(
        Wire::new(initial),
        || {
            connects += 1;
            std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                "must not reconnect",
            )))
        },
        &mut stdout,
        &mut FailedOutput,
    ))
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(stdout.is_empty());
    assert!(!client.delivery.stdout_published);
    assert_eq!(
        (client.delivery.stdout_offset, client.delivery.stderr_offset),
        (0, 0)
    );
    assert_eq!(connects, 0);
    assert_eq!(kinds(&output), ["inputs-done", "poll", "cancel"]);
}

#[test]
fn blocked_real_output_cancels_the_original_operation_without_reconnect() {
    struct BlockedOutput<'a> {
        inner: ControlledOutput<'a>,
        started: std::sync::mpsc::Sender<()>,
    }
    impl Write for BlockedOutput<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.inner.write(bytes)
        }

        fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            if !bytes.is_empty() {
                self.started.send(()).unwrap();
            }
            self.inner.write_all(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    // Stderr is live; stdout can block only after its verified terminal
    // receipt. Neither kind of local backpressure may retry the remote work.
    for block_stdout in [false, true] {
        let directory = private();
        let config = delivery_config(&directory.path().join("completed"));
        let stopped = AtomicBool::new(false);
        let mut client = client(&config, &stopped);
        let initial = RecoveryPeer::new(&[
            Message::Accepted {},
            Message::Progress {
                stdout: diagnostic(0, b"retained"),
                stderr: diagnostic(0, if block_stdout { b"" } else { b"blocked" }),
            },
            Message::BuildFinished {
                exit_code: 0,
                stdout_bytes: 8,
                stderr_bytes: if block_stdout { 0 } else { 7 },
                target: None,
            },
            Message::Complete { exit_code: 0 },
        ]);
        let commands = initial.output();
        let (_reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::NONBLOCK).unwrap();
        loop {
            match rustix::io::write(&writer, &[0; 4096]) {
                Ok(_) => {}
                Err(rustix::io::Errno::AGAIN) => break,
                result => panic!("unexpected real pipe fill result: {result:?}"),
            }
        }
        let (started, observed) = std::sync::mpsc::channel();
        let mut blocked = BlockedOutput {
            inner: ControlledOutput::with_deadline(
                &writer,
                &stopped,
                client.delivery.output_deadline.clone(),
            )
            .unwrap(),
            started,
        };
        let mut connects = 0;
        let error = std::thread::scope(|scope| {
            let stopped = &stopped;
            scope.spawn(move || {
                observed.recv_timeout(Duration::from_secs(3)).unwrap();
                stopped.store(true, Ordering::Release);
            });
            let connect = || {
                connects += 1;
                std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                    "blocked local output must not reconnect",
                )))
            };
            if block_stdout {
                native(client.complete(Wire::new(initial), connect, &mut blocked, &mut Vec::new()))
            } else {
                native(client.complete(Wire::new(initial), connect, &mut Vec::new(), &mut blocked))
            }
            .unwrap_err()
        });
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(connects, 0);
        assert_eq!(client.delivery.stdout_published, block_stdout);
        assert_eq!(
            (client.delivery.stdout_offset, client.delivery.stderr_offset),
            if block_stdout { (8, 0) } else { (0, 0) }
        );
        assert_eq!(
            kinds(&commands),
            if block_stdout {
                vec!["inputs-done", "poll", "poll", "close", "cancel"]
            } else {
                vec!["inputs-done", "poll", "cancel"]
            }
        );
    }
}

#[test]
fn terminal_receipt_controls_stdout_including_failed_build_diagnostics() {
    let retained = b"failed compiler output\x00\xff\n";
    for terminal_exit in [None, Some(0), Some(7)] {
        let directory = private();
        let config = delivery_config(&directory.path().join("completed"));
        let stopped = AtomicBool::new(false);
        let mut delivery = ClientDelivery::new(Instant::now() + Duration::from_secs(15));
        let mut messages = vec![
            Message::Progress {
                stdout: diagnostic(0, retained),
                stderr: diagnostic(0, b"live diagnostic"),
            },
            Message::BuildFinished {
                exit_code: 7,
                stdout_bytes: retained.len() as u64,
                stderr_bytes: 15,
                target: None,
            },
        ];
        if let Some(exit_code) = terminal_exit {
            messages.push(Message::Complete { exit_code });
        }
        let mut wire = Wire::new(RecoveryPeer::new(&messages));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = native(receive_operation(
            &mut wire,
            &config,
            &stopped,
            &mut delivery,
            &mut stdout,
            &mut stderr,
        ));
        assert_eq!(stderr, b"live diagnostic");
        assert_eq!(delivery.stdout_offset, retained.len() as u64);
        if terminal_exit == Some(7) {
            assert_eq!(result.unwrap(), 7);
            assert_eq!(stdout, retained);
            assert!(delivery.stdout_published);
            assert!(delivery.stdout_spool.is_none());
        } else {
            assert!(result.is_err());
            assert!(stdout.is_empty());
            assert!(!delivery.stdout_published);
            assert_eq!(
                delivery
                    .stdout_spool
                    .as_ref()
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .len(),
                retained.len() as u64
            );
        }
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}

#[test]
fn interrupted_target_delivery_keeps_cargo_stdout_private() {
    let directory = private();
    let destination = directory.path().join("completed");
    let config = delivery_config(&destination);
    let stopped = AtomicBool::new(false);
    let mut delivery = ClientDelivery::new(Instant::now() + Duration::from_secs(15));
    let (manifest, bytes) = artifact_fixture();
    let retained = b"{\"reason\":\"compiler-artifact\",\"filenames\":[\"/rabs/target/program\"]}\n";
    let mut messages = vec![
        Message::Progress {
            stdout: diagnostic(0, retained),
            stderr: diagnostic(0, b"live diagnostic"),
        },
        Message::BuildFinished {
            exit_code: 0,
            stdout_bytes: retained.len() as u64,
            stderr_bytes: 15,
            target: Some(ArtifactDeclaration::from_native(&manifest)),
        },
    ];
    messages.extend(artifact_manifest_messages(&manifest));
    messages.push(Message::ArtifactChunk {
        chunk: Chunk::new("program", 0, &bytes[..MAX_SOURCE_CHUNK]).unwrap(),
    });
    let mut wire = Wire::new(RecoveryPeer::new(&messages));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let error = native(receive_operation(
        &mut wire,
        &config,
        &stopped,
        &mut delivery,
        &mut stdout,
        &mut stderr,
    ))
    .unwrap_err();
    assert!(wire.can_resume_after(&error));
    assert!(stdout.is_empty());
    assert_eq!(stderr, b"live diagnostic");
    assert!(!destination.exists());
    assert!(!delivery.stdout_published);
    assert_eq!(delivery.stdout_offset, retained.len() as u64);
    assert_eq!(
        delivery
            .stdout_spool
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .len(),
        retained.len() as u64
    );
}

#[test]
fn stdout_first_write_observes_the_verified_installed_target() {
    struct ArtifactReadyOutput<'a> {
        destination: &'a Path,
        expected: &'a [u8],
        bytes: Vec<u8>,
        checked: bool,
    }

    impl Write for ArtifactReadyOutput<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.checked {
                assert_eq!(
                    fs::read(self.destination.join("program")).unwrap(),
                    self.expected,
                    "Cargo stdout cannot announce an unavailable artifact"
                );
                self.checked = true;
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let directory = private();
    let destination = directory.path().join("completed");
    let config = delivery_config(&destination);
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let (manifest, bytes) = artifact_fixture();
    let retained = b"{\"reason\":\"compiler-artifact\",\"filenames\":[\"/rabs/target/program\"]}\n";
    let mut messages = vec![
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, retained),
            stderr: diagnostic(0, b""),
        },
        Message::BuildFinished {
            exit_code: 0,
            stdout_bytes: retained.len() as u64,
            stderr_bytes: 0,
            target: Some(ArtifactDeclaration::from_native(&manifest)),
        },
    ];
    messages.extend(artifact_manifest_messages(&manifest));
    for (index, part) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
        messages.push(Message::ArtifactChunk {
            chunk: Chunk::new("program", (index * MAX_SOURCE_CHUNK) as u64, part).unwrap(),
        });
    }
    messages.push(Message::WindowEnd { count: 2 });
    messages.push(Message::ArtifactEnd {});
    messages.push(Message::Commit {
        manifest_sha256: encode_hex(&manifest.digest()),
    });
    messages.push(Message::Complete { exit_code: 0 });
    let mut stdout = ArtifactReadyOutput {
        destination: &destination,
        expected: &bytes,
        bytes: Vec::new(),
        checked: false,
    };
    assert_eq!(
        native(client.complete(
            Wire::new(RecoveryPeer::new(&messages)),
            || {
                std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                    "successful delivery must not reconnect",
                )))
            },
            &mut stdout,
            &mut Vec::new(),
        ))
        .unwrap(),
        0
    );
    assert!(stdout.checked);
    assert_eq!(stdout.bytes, retained);
    assert!(client.delivery.target.installed.is_some());
    assert!(client.delivery.stdout_published);
    assert!(client.delivery.stdout_spool.is_none());
}

fn cargo_artifact_record() -> Value {
    json!({
        "reason":"compiler-artifact",
        "package_id":"path+file:///__rabs/workspace#fixture@0.1.0",
        "manifest_path":"/__rabs/workspace/Cargo.toml",
        "target":{"src_path":"/__rabs/workspace/src/main.rs", "kind":["bin"]},
        "profile":{"test":false}, "fresh":false,
        "filenames":["/__rabs/out/cargo/program"],
        "executable":"/__rabs/out/cargo/program"
    })
}

fn cargo_error_record() -> Value {
    json!({
        "reason":"compiler-message",
        "package_id":"path+file:///__rabs/workspace#fixture@0.1.0",
        "manifest_path":"/__rabs/workspace/Cargo.toml",
        "target":{"src_path":"/__rabs/workspace/src/main.rs", "kind":["bin"]},
        "message":{
            "message":"keep /__rabs/workspace/literal", "level":"error", "children":[],
            "spans":[{"file_name":"/__rabs/workspace/src/main.rs", "line_start":3, "column_start":1,
                "text":[{"text":"let literal = \"/__rabs/workspace/source\";"}]}],
            "rendered":"error: keep /__rabs/workspace/literal\n --> /__rabs/workspace/src/main.rs:3:1\n3 | let literal = \"/__rabs/workspace/source\";\n"
        }
    })
}

fn cargo_json_line(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn subscriber_artifact_first_write_names_the_actual_verified_file() {
    struct ReturnedArtifact<'a> {
        expected_path: &'a Path,
        expected_bytes: &'a [u8],
        bytes: Vec<u8>,
        checked: bool,
    }
    impl Write for ReturnedArtifact<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.checked {
                let record: Value = serde_json::from_slice(bytes).unwrap();
                let named = Path::new(record["executable"].as_str().unwrap());
                assert_eq!(named, self.expected_path);
                assert_eq!(
                    fs::read(named).unwrap(),
                    self.expected_bytes,
                    "the first returned Cargo artifact path must already open the verified bytes"
                );
                self.checked = true;
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let directory = private();
    let destination = directory.path().join("completed");
    let mut config = delivery_config(&destination);
    config.stdout_presentation = StdoutPresentation::CargoJsonSubscriber;
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let (manifest, bytes) = artifact_fixture();
    let mut retained = cargo_json_line(&cargo_artifact_record());
    retained.extend(cargo_json_line(
        &json!({"reason":"build-finished", "success":true}),
    ));
    let runtime =
        b"\xff\0{\"reason\":\"compiler-artifact\",\"executable\":\"/__rabs/out/cargo/fake\"}";
    retained.extend_from_slice(runtime);
    let mut messages = vec![
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, &retained),
            stderr: diagnostic(0, b""),
        },
        Message::BuildFinished {
            exit_code: 0,
            stdout_bytes: retained.len() as u64,
            stderr_bytes: 0,
            target: Some(ArtifactDeclaration::from_native(&manifest)),
        },
    ];
    messages.extend(artifact_manifest_messages(&manifest));
    for (index, part) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
        messages.push(Message::ArtifactChunk {
            chunk: Chunk::new("program", (index * MAX_SOURCE_CHUNK) as u64, part).unwrap(),
        });
    }
    messages.extend([
        Message::WindowEnd { count: 2 },
        Message::ArtifactEnd {},
        Message::Commit {
            manifest_sha256: encode_hex(&manifest.digest()),
        },
        Message::Complete { exit_code: 0 },
    ]);
    let expected_path = destination.join("program");
    let mut output = ReturnedArtifact {
        expected_path: &expected_path,
        expected_bytes: &bytes,
        bytes: Vec::new(),
        checked: false,
    };
    let mut stderr = Vec::new();
    assert_eq!(
        native(client.complete(
            Wire::new(RecoveryPeer::new(&messages)),
            || std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                "presentation must not reconnect"
            ))),
            &mut output,
            &mut stderr,
        ))
        .unwrap(),
        0
    );
    assert!(output.checked);
    assert!(output.bytes.ends_with(runtime));
    assert!(stderr.is_empty());
    assert_eq!(client.delivery.stdout_offset, retained.len() as u64);
    assert!(client.delivery.stdout_spool.is_none());
}

#[test]
fn source_error_presentation_survives_reconnect_with_raw_wire_frontiers() {
    let directory = private();
    let destination = directory.path().join("completed");
    let mut config = delivery_config(&destination);
    config.stdout_presentation = StdoutPresentation::CargoJsonSourcePaths;
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let mut retained = cargo_json_line(&cargo_artifact_record());
    retained.extend(cargo_json_line(&cargo_error_record()));
    retained.extend(cargo_json_line(
        &json!({"reason":"build-finished", "success":false}),
    ));
    let split = 31;
    let initial = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, &retained[..split]),
            stderr: diagnostic(0, b"live\n"),
        },
    ]);
    let resumed = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(split as u64, &retained[split..]),
            stderr: diagnostic(5, b""),
        },
        Message::BuildFinished {
            exit_code: 101,
            stdout_bytes: retained.len() as u64,
            stderr_bytes: 5,
            target: None,
        },
        Message::Complete { exit_code: 101 },
    ]);
    let commands = resumed.output();
    let mut peers = VecDeque::from([resumed]);
    let mut output = ObservedOutput::default();
    let visible = Arc::clone(&output.bytes);
    let mut stderr = Vec::new();
    assert_eq!(
        native(client.complete(
            Wire::new(initial),
            || {
                assert!(visible.lock().unwrap().is_empty());
                std::future::ready(Ok(peers.pop_front().expect("one reconnect")))
            },
            &mut output,
            &mut stderr
        ))
        .unwrap(),
        101
    );
    assert_resume(&commands, split as u64, 5);
    assert_eq!(stderr, b"live\n");
    let output = visible.lock().unwrap();
    let records: Vec<Value> = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[0]["executable"],
        cargo_artifact_record()["executable"]
    );
    assert_eq!(records[0]["manifest_path"], "/fixture/source/Cargo.toml");
    assert_eq!(
        records[1]["message"]["spans"][0]["file_name"],
        "/fixture/source/src/main.rs"
    );
    assert_eq!(
        records[1]["message"]["message"],
        cargo_error_record()["message"]["message"]
    );
    assert_eq!(client.delivery.stdout_offset, retained.len() as u64);
    assert_ne!(
        output.len(),
        retained.len(),
        "wire offsets must not become presentation offsets"
    );
    assert!(!destination.exists());
    assert!(client.delivery.stdout_published);
}

#[test]
fn incomplete_presentation_discards_its_private_prefix_and_replays_raw_once() {
    let directory = private();
    let destination = directory.path().join("completed");
    let mut config = delivery_config(&destination);
    config.stdout_presentation = StdoutPresentation::CargoJsonSubscriber;
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let mut retained = cargo_json_line(&cargo_error_record());
    retained.extend(cargo_json_line(&cargo_artifact_record()));
    let peer = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, &retained),
            stderr: diagnostic(0, b""),
        },
        Message::BuildFinished {
            exit_code: 101,
            stdout_bytes: retained.len() as u64,
            stderr_bytes: 0,
            target: None,
        },
        Message::Complete { exit_code: 101 },
    ]);
    let commands = peer.output();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        native(client.complete(
            Wire::new(peer),
            || {
                std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                    "a presentation bypass must not reconnect",
                )))
            },
            &mut stdout,
            &mut stderr
        ))
        .unwrap(),
        101
    );
    assert_eq!(
        stdout, retained,
        "no translated private prefix may escape before a late bypass"
    );
    let status: Value = serde_json::from_slice(&stderr).unwrap();
    assert_eq!(status["kind"], "canonical-remote-presentation-bypassed");
    assert_eq!(status["reason"], "output-path-not-installed");
    assert_eq!(status["using"], "raw");
    assert_eq!(
        client.delivery.stderr_offset, 0,
        "local presentation status is not remote output"
    );
    assert_eq!(
        kinds(&commands)
            .iter()
            .filter(|kind| *kind == "delivered")
            .count(),
        1
    );
}

#[test]
fn cumulative_presentation_limit_discards_private_translation_before_raw_replay() {
    let directory = private();
    let mut config = delivery_config(&directory.path().join("completed"));
    config.stdout_presentation = StdoutPresentation::CargoJsonSourcePaths;
    let stopped = AtomicBool::new(false);
    let first = cargo_json_line(&cargo_error_record());
    let limit = first.len() as u64;
    let mut retained = first;
    retained.extend_from_slice(&[b'x'; 128]);
    retained.push(b'\n');
    let mut delivery = ClientDelivery::new(Instant::now() + Duration::from_secs(15));
    delivery
        .retain_stdout(&config.staging_root, &retained)
        .unwrap();
    delivery.stdout_offset = retained.len() as u64;
    delivery
        .completed(BuildCompletion {
            exit_code: 101,
            stdout_bytes: retained.len() as u64,
            stderr_bytes: 0,
            target: None,
        })
        .unwrap();
    let mut stderr = Vec::new();
    let selected = delivery
        .prepare_stdout_presentation(&config, &stopped, &mut stderr, limit)
        .unwrap();
    assert!(
        selected.is_none(),
        "the complete presentation exceeds the injected byte budget"
    );
    assert!(!delivery.stdout_published);
    let status: Value = serde_json::from_slice(&stderr).unwrap();
    assert_eq!(status["reason"], "translated-cargo-output-limit");
    assert_eq!(status["using"], "raw");
    let mut stdout = Vec::new();
    delivery
        .publish_stdout(&stopped, &mut stdout, selected.as_ref())
        .unwrap();
    assert_eq!(
        stdout, retained,
        "no earlier translated record may escape or be duplicated"
    );
    assert_eq!(delivery.stdout_offset, retained.len() as u64);
    assert_eq!(delivery.stderr_offset, 0);
    assert!(delivery.stdout_published);
    assert!(delivery.stdout_spool.is_none());
}

#[test]
fn unavailable_presentation_status_sink_is_a_local_failure_without_stdout_or_retry() {
    let directory = private();
    let mut config = delivery_config(&directory.path().join("completed"));
    config.stdout_presentation = StdoutPresentation::CargoJsonSubscriber;
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let retained = cargo_json_line(&cargo_artifact_record());
    let peer = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, &retained),
            stderr: diagnostic(0, b""),
        },
        Message::BuildFinished {
            exit_code: 101,
            stdout_bytes: retained.len() as u64,
            stderr_bytes: 0,
            target: None,
        },
        Message::Complete { exit_code: 101 },
    ]);
    let commands = peer.output();
    let mut stdout = Vec::new();
    let mut connections = 0;
    let result = native(client.complete(
        Wire::new(peer),
        || {
            connections += 1;
            std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                "local status failure must not reconnect",
            )))
        },
        &mut stdout,
        &mut FailedOutput,
    ));
    assert!(result.is_err());
    assert!(stdout.is_empty());
    assert_eq!(connections, 0);
    assert!(!kinds(&commands).iter().any(|kind| kind == "delivered"));
}

#[test]
fn retained_stdout_bound_is_checked_before_creating_a_spool() {
    let directory = private();
    let mut delivery = ClientDelivery::new(Instant::now() + Duration::from_secs(15));
    delivery.stdout_offset = OUTPUT_TOTAL_BYTES - 1;
    let error = delivery.retain_stdout(directory.path(), b"xx").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(delivery.stdout_offset, OUTPUT_TOTAL_BYTES - 1);
    assert!(delivery.stdout_spool.is_none());
    assert!(!delivery.stdout_published);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn local_stdout_failure_after_complete_never_reconnects_or_replays() {
    let directory = private();
    let config = delivery_config(&directory.path().join("completed"));
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let retained = b"completed stdout\x00\xff\n";
    let initial = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, retained),
            stderr: diagnostic(0, b""),
        },
        Message::BuildFinished {
            exit_code: 0,
            stdout_bytes: retained.len() as u64,
            stderr_bytes: 0,
            target: None,
        },
        Message::Complete { exit_code: 0 },
    ]);
    let output = initial.output();
    let mut connects = 0;
    let error = native(client.complete(
        Wire::new(initial),
        || {
            connects += 1;
            std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                "must not reconnect",
            )))
        },
        &mut FailedOutput,
        &mut Vec::new(),
    ))
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(connects, 0);
    assert!(client.delivery.stdout_published);
    assert!(client.delivery.stdout_spool.is_none());
    assert_eq!(client.delivery.stdout_offset, retained.len() as u64);
    assert_eq!(
        kinds(&output),
        ["inputs-done", "poll", "poll", "close", "cancel"]
    );
    let mut replay = Vec::new();
    assert!(
        client
            .delivery
            .publish_stdout(&stopped, &mut replay, None)
            .is_err()
    );
    assert!(replay.is_empty());
}

#[test]
fn local_stdout_spool_failure_never_becomes_transport_recovery() {
    let directory = private();
    let mut config = delivery_config(&directory.path().join("completed"));
    config.staging_root = directory.path().join("missing-staging");
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let initial = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, b"retained"),
            stderr: diagnostic(0, b"not exposed"),
        },
    ]);
    let output = initial.output();
    let mut connects = 0;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let error = native(client.complete(
        Wire::new(initial),
        || {
            connects += 1;
            std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                "must not reconnect",
            )))
        },
        &mut stdout,
        &mut stderr,
    ))
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(connects, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(
        (client.delivery.stdout_offset, client.delivery.stderr_offset),
        (0, 0)
    );
    assert!(!client.delivery.stdout_published);
    assert_eq!(kinds(&output), ["inputs-done", "poll", "cancel"]);
}

#[test]
fn interrupted_wire_uses_fresh_authenticated_token_cancellation_without_resume() {
    let directory = private();
    let config = delivery_config(&directory.path().join("completed"));
    let stopped = AtomicBool::new(true);
    let mut client = client(&config, &stopped);
    let initial = RecoveryPeer::new(&[]);
    let initial_output = initial.output();
    let cleanup = RecoveryPeer::new(&[Message::Cancelled {}]);
    let cleanup_output = cleanup.output();
    let mut cleanup = Some(cleanup);
    let error = native(client.complete(
        Wire::new(initial),
        || std::future::ready(Ok(cleanup.take().expect("cleanup is attempted only once"))),
        &mut Vec::new(),
        &mut Vec::new(),
    ))
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(kinds(&initial_output).is_empty());
    assert_eq!(kinds(&cleanup_output), ["cancel-operation"]);
    let messages = admission_messages(&cleanup_output);
    assert_eq!(
        messages[0]["token"],
        serde_json::to_value(operation_token()).unwrap()
    );
    assert_eq!(messages[0]["build_identity"], "fixture-build");
    assert_eq!(messages[0]["require_release"], true);
    assert!(
        stopped.load(Ordering::Acquire),
        "cleanup cannot clear cancellation"
    );
}

#[test]
fn artifact_tail_and_sealed_receiver_resume_without_redownloading_completed_bytes() {
    for after_seal in [false, true] {
        let directory = private();
        let destination = directory.path().join("completed");
        let config = delivery_config(&destination);
        let stopped = AtomicBool::new(false);
        let mut client = client(&config, &stopped);
        let (manifest, bytes) = artifact_fixture();
        let program = manifest
            .files()
            .iter()
            .position(|file| file.path == "program")
            .unwrap();
        let mut first = vec![Message::Accepted {}, finished(0, Some(&manifest))];
        first.extend(artifact_manifest_messages(&manifest));
        first.push(Message::ArtifactChunk {
            chunk: Chunk::new("program", 0, &bytes[..MAX_SOURCE_CHUNK]).unwrap(),
        });
        if after_seal {
            first.push(Message::ArtifactChunk {
                chunk: Chunk::new(
                    "program",
                    MAX_SOURCE_CHUNK as u64,
                    &bytes[MAX_SOURCE_CHUNK..],
                )
                .unwrap(),
            });
            first.push(Message::WindowEnd { count: 2 });
            first.push(Message::ArtifactEnd {});
        }
        let initial = RecoveryPeer::new(&first);
        let initial_output = initial.output();
        let mut second = vec![Message::Accepted {}, finished(0, Some(&manifest))];
        second.extend(artifact_manifest_messages(&manifest));
        if !after_seal {
            second.push(Message::ArtifactChunk {
                chunk: Chunk::new(
                    "program",
                    MAX_SOURCE_CHUNK as u64,
                    &bytes[MAX_SOURCE_CHUNK..],
                )
                .unwrap(),
            });
            second.push(Message::WindowEnd { count: 1 });
        }
        second.push(Message::ArtifactEnd {});
        second.push(Message::Commit {
            manifest_sha256: encode_hex(&manifest.digest()),
        });
        second.push(Message::Complete { exit_code: 0 });
        let resumed = RecoveryPeer::new(&second);
        let resumed_output = resumed.output();
        let mut resumed = Some(resumed);
        assert_eq!(
            native(client.complete(
                Wire::new(initial),
                || std::future::ready(Ok(resumed.take().expect("one artifact reconnect"))),
                &mut Vec::new(),
                &mut Vec::new(),
            ))
            .unwrap(),
            0
        );
        assert_eq!(fs::read(destination.join("program")).unwrap(), bytes);
        assert!(client.delivery.target.receiving.is_none());
        client
            .delivery
            .target
            .installed
            .as_ref()
            .unwrap()
            .verify(&|| false)
            .unwrap();
        assert_resume(&resumed_output, 0, 0);
        let original = admission_messages(&initial_output);
        let resumed = admission_messages(&resumed_output);
        let initial_plan = original
            .iter()
            .find(|message| message["kind"] == "receive-artifacts")
            .unwrap();
        let resumed_plan = resumed
            .iter()
            .find(|message| message["kind"] == "receive-artifacts")
            .unwrap();
        assert_eq!(initial_plan["file_index"], program);
        assert_eq!(initial_plan["offset"], 0);
        assert_eq!(resumed_plan["missing_files"], initial_plan["missing_files"]);
        assert_eq!(
            resumed_plan["file_index"],
            if after_seal {
                manifest.files().len()
            } else {
                program
            }
        );
        assert_eq!(
            resumed_plan["offset"],
            if after_seal { 0 } else { MAX_SOURCE_CHUNK }
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}

#[test]
fn publication_and_completion_loss_resend_receipt_without_reinstalling_target() {
    for lost_published in [false, true] {
        let directory = private();
        let destination = directory.path().join("completed");
        let config = delivery_config(&destination);
        let stopped = AtomicBool::new(false);
        let mut client = client(&config, &stopped);
        let (manifest, bytes) = artifact_fixture();
        let mut first = vec![Message::Accepted {}, finished(0, Some(&manifest))];
        first.extend(artifact_manifest_messages(&manifest));
        for (index, part) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            first.push(Message::ArtifactChunk {
                chunk: Chunk::new("program", (index * MAX_SOURCE_CHUNK) as u64, part).unwrap(),
            });
        }
        first.push(Message::WindowEnd { count: 2 });
        first.push(Message::ArtifactEnd {});
        first.push(Message::Commit {
            manifest_sha256: encode_hex(&manifest.digest()),
        });
        let mut initial = RecoveryPeer::new(&first);
        initial.fail_write = lost_published.then_some("published");
        let resumed = RecoveryPeer::new(&[
            Message::Accepted {},
            finished(0, Some(&manifest)),
            Message::Complete { exit_code: 0 },
        ]);
        let resumed_output = resumed.output();
        let mut resumed = Some(resumed);
        let mut installed_inode = None;
        assert_eq!(
            native(client.complete(
                Wire::new(initial),
                || {
                    installed_inode = Some(fs::metadata(&destination).unwrap().ino());
                    std::future::ready(Ok(resumed.take().expect("one receipt reconnect")))
                },
                &mut Vec::new(),
                &mut Vec::new(),
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            installed_inode,
            Some(fs::metadata(&destination).unwrap().ino())
        );
        assert_eq!(fs::read(destination.join("program")).unwrap(), bytes);
        assert_resume(&resumed_output, 0, 0);
        assert_eq!(
            kinds(&resumed_output),
            ["resume", "poll", "published", "delivered"]
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}

#[test]
fn reattachment_refuses_changed_result_identity_and_mutated_installed_bytes() {
    for changed_result in [false, true] {
        let directory = private();
        let destination = directory.path().join("completed");
        let config = delivery_config(&destination);
        let stopped = AtomicBool::new(false);
        let mut client = client(&config, &stopped);
        let manifest = ArtifactManifest::new(vec![SourceFile {
            path: "program".into(),
            len: 4,
            sha256: Sha256::digest(b"good").into(),
            executable: true,
        }])
        .unwrap();
        let mut messages = vec![Message::Accepted {}, finished(0, Some(&manifest))];
        messages.extend(artifact_manifest_messages(&manifest));
        messages.push(Message::ArtifactChunk {
            chunk: Chunk::new("program", 0, b"good").unwrap(),
        });
        messages.push(Message::WindowEnd { count: 1 });
        messages.push(Message::ArtifactEnd {});
        messages.push(Message::Commit {
            manifest_sha256: encode_hex(&manifest.digest()),
        });
        let initial = RecoveryPeer::new(&messages);
        let resumed = RecoveryPeer::new(&[
            Message::Accepted {},
            if changed_result {
                finished(1, None)
            } else {
                finished(0, Some(&manifest))
            },
        ]);
        let resumed_output = resumed.output();
        let mut resumed = Some(resumed);
        let error = native(client.complete(
            Wire::new(initial),
            || {
                if !changed_result {
                    fs::set_permissions(
                        destination.join("program"),
                        fs::Permissions::from_mode(0o755),
                    )
                    .unwrap();
                    fs::write(destination.join("program"), b"evil").unwrap();
                    fs::set_permissions(
                        destination.join("program"),
                        fs::Permissions::from_mode(0o555),
                    )
                    .unwrap();
                }
                std::future::ready(Ok(resumed
                    .take()
                    .expect("no recovery from changed local data")))
            },
            &mut Vec::new(),
            &mut Vec::new(),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(kinds(&resumed_output), ["resume", "poll", "cancel"]);
        assert!(client.delivery.target.installed.is_some());
        assert_eq!(
            fs::read(destination.join("program")).unwrap(),
            if changed_result { b"good" } else { b"evil" }
        );
    }
}

#[test]
fn reconnect_preserves_original_reuse_plan_and_never_reimports_mutated_hints() {
    let directory = private();
    let prior = directory.path().join("prior");
    fs::DirBuilder::new().mode(0o700).create(&prior).unwrap();
    fs::write(prior.join("a-cached"), b"one").unwrap();
    fs::write(prior.join("c-cached"), b"two").unwrap();
    let changed = vec![0x63; MAX_SOURCE_CHUNK + 7];
    let manifest = ArtifactManifest::new(
        [
            ("a-cached", b"one".as_slice()),
            ("b-changed", changed.as_slice()),
            ("c-cached", b"two".as_slice()),
        ]
        .into_iter()
        .map(|(path, bytes)| SourceFile {
            path: path.into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        })
        .collect(),
    )
    .unwrap();
    let destination = directory.path().join("completed");
    let mut config = delivery_config(&destination);
    config.artifact_reuse_root = Some(prior.clone());
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let mut first = vec![Message::Accepted {}, finished(0, Some(&manifest))];
    first.extend(artifact_manifest_messages(&manifest));
    first.push(Message::ArtifactChunk {
        chunk: Chunk::new("b-changed", 0, &changed[..MAX_SOURCE_CHUNK]).unwrap(),
    });
    let initial = RecoveryPeer::new(&first);
    let mut second = vec![Message::Accepted {}, finished(0, Some(&manifest))];
    second.extend(artifact_manifest_messages(&manifest));
    second.push(Message::ArtifactChunk {
        chunk: Chunk::new(
            "b-changed",
            MAX_SOURCE_CHUNK as u64,
            &changed[MAX_SOURCE_CHUNK..],
        )
        .unwrap(),
    });
    second.push(Message::WindowEnd { count: 1 });
    second.push(Message::ArtifactEnd {});
    second.push(Message::Commit {
        manifest_sha256: encode_hex(&manifest.digest()),
    });
    second.push(Message::Complete { exit_code: 0 });
    let resumed = RecoveryPeer::new(&second);
    let resumed_output = resumed.output();
    let mut resumed = Some(resumed);
    assert_eq!(
        native(client.complete(
            Wire::new(initial),
            || {
                fs::write(prior.join("a-cached"), b"bad").unwrap();
                fs::write(prior.join("c-cached"), b"bad").unwrap();
                std::future::ready(Ok(resumed.take().expect("one tail reconnect")))
            },
            &mut Vec::new(),
            &mut Vec::new(),
        ))
        .unwrap(),
        0
    );
    assert_eq!(fs::read(destination.join("a-cached")).unwrap(), b"one");
    assert_eq!(fs::read(destination.join("b-changed")).unwrap(), changed);
    assert_eq!(fs::read(destination.join("c-cached")).unwrap(), b"two");
    let messages = admission_messages(&resumed_output);
    let plan = messages
        .iter()
        .find(|message| message["kind"] == "receive-artifacts")
        .unwrap();
    assert_eq!(plan["missing_files"], json!([1]));
    assert_eq!(plan["file_index"], 1);
    assert_eq!(plan["offset"], MAX_SOURCE_CHUNK);
}

#[test]
fn reconnect_keeps_frozen_prefix_selection_and_continues_only_the_unreceived_tail() {
    for matching_prefix in [false, true] {
        let directory = private();
        let prior = directory.path().join("prior");
        fs::DirBuilder::new().mode(0o700).create(&prior).unwrap();
        let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 2 + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        let later = vec![0x71; 127];
        let retained = 43;
        let later_retained = 7;
        let mut prefix = bytes[..retained].to_vec();
        if !matching_prefix {
            prefix[0] ^= 0xff;
        }
        fs::write(prior.join("a-cached"), b"same").unwrap();
        fs::write(prior.join("b-program"), &prefix).unwrap();
        fs::write(prior.join("c-program"), &later[..later_retained]).unwrap();
        let manifest = ArtifactManifest::new(
            [
                ("a-cached", b"same".as_slice()),
                ("b-program", bytes.as_slice()),
                ("c-program", later.as_slice()),
            ]
            .into_iter()
            .map(|(path, bytes)| SourceFile {
                path: path.into(),
                len: bytes.len() as u64,
                sha256: Sha256::digest(bytes).into(),
                executable: false,
            })
            .collect(),
        )
        .unwrap();
        let destination = directory.path().join("completed");
        let mut config = delivery_config(&destination);
        config.artifact_reuse_root = Some(prior.clone());
        let stopped = AtomicBool::new(false);
        let mut client = client(&config, &stopped);
        let selected = if matching_prefix { retained } else { 0 };
        let received = selected + MAX_SOURCE_CHUNK;
        let mut first = vec![Message::Accepted {}, finished(0, Some(&manifest))];
        first.extend(artifact_manifest_messages(&manifest));
        first.push(Message::ArtifactChunk {
            chunk: Chunk::new("b-program", selected as u64, &bytes[selected..received]).unwrap(),
        });
        let initial = RecoveryPeer::new(&first);
        let initial_output = initial.output();
        let mut second = vec![Message::Accepted {}, finished(0, Some(&manifest))];
        second.extend(artifact_manifest_messages(&manifest));
        let mut count = 0;
        for (index, part) in bytes[received..].chunks(MAX_SOURCE_CHUNK).enumerate() {
            second.push(Message::ArtifactChunk {
                chunk: Chunk::new(
                    "b-program",
                    (received + index * MAX_SOURCE_CHUNK) as u64,
                    part,
                )
                .unwrap(),
            });
            count += 1;
        }
        // This untouched member may select its original frozen prefix even
        // while the earlier file uses its retained network-receive cursor.
        second.push(Message::ArtifactChunk {
            chunk: Chunk::new("c-program", later_retained as u64, &later[later_retained..])
                .unwrap(),
        });
        second.push(Message::WindowEnd { count: count + 1 });
        second.push(Message::ArtifactEnd {});
        second.push(Message::Commit {
            manifest_sha256: encode_hex(&manifest.digest()),
        });
        second.push(Message::Complete { exit_code: 0 });
        let resumed = RecoveryPeer::new(&second);
        let resumed_output = resumed.output();
        let mut resumed = Some(resumed);
        assert_eq!(
            native(client.complete(
                Wire::new(initial),
                || {
                    for name in ["a-cached", "b-program", "c-program"] {
                        fs::write(prior.join(name), b"changed untrusted hints").unwrap();
                    }
                    std::future::ready(Ok(resumed.take().expect("one frozen-prefix reconnect")))
                },
                &mut Vec::new(),
                &mut Vec::new(),
            ))
            .unwrap(),
            0
        );
        assert_eq!(fs::read(destination.join("a-cached")).unwrap(), b"same");
        assert_eq!(fs::read(destination.join("b-program")).unwrap(), bytes);
        assert_eq!(fs::read(destination.join("c-program")).unwrap(), later);
        let first = admission_messages(&initial_output);
        let second = admission_messages(&resumed_output);
        let initial_plan = first
            .iter()
            .find(|message| message["kind"] == "receive-artifacts")
            .unwrap();
        let resumed_plan = second
            .iter()
            .find(|message| message["kind"] == "receive-artifacts")
            .unwrap();
        assert_eq!(initial_plan["missing_files"], json!([1, 2]));
        assert_eq!(initial_plan["file_index"], 1);
        assert_eq!(initial_plan["offset"], 0);
        assert_eq!(
            initial_plan["prefixes"],
            json!([
                {"index":1,"offset":retained,"sha256":encode_hex(&Sha256::digest(&prefix))},
                {"index":2,"offset":later_retained,"sha256":encode_hex(&Sha256::digest(&later[..later_retained]))},
            ])
        );
        assert_eq!(resumed_plan["prefixes"], initial_plan["prefixes"]);
        assert_eq!(resumed_plan["missing_files"], initial_plan["missing_files"]);
        assert_eq!(resumed_plan["file_index"], 1);
        assert_eq!(resumed_plan["offset"], received);
        assert_eq!(client.delivery.target.started_files.len(), 2);
        assert_eq!(
            client.delivery.target.resumed_files,
            if matching_prefix { 2 } else { 1 }
        );
        assert_eq!(
            client.delivery.target.resumed_bytes,
            (selected + later_retained) as u64
        );
        assert_eq!(
            client.delivery.target.transferred_bytes,
            (bytes.len() + later.len() - selected - later_retained) as u64
        );
        assert!(client.delivery.target.reported_reuse);
    }
}

#[test]
fn lost_delivered_ack_does_not_repeat_an_already_verified_completion() {
    let directory = private();
    let config = delivery_config(&directory.path().join("completed"));
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let retained = b"completed output";
    let mut initial = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, retained),
            stderr: diagnostic(0, b""),
        },
        Message::BuildFinished {
            exit_code: 0,
            stdout_bytes: retained.len() as u64,
            stderr_bytes: 0,
            target: None,
        },
        Message::Complete { exit_code: 0 },
    ]);
    initial.fail_write = Some("delivered");
    let output = initial.output();
    let mut connects = 0;
    let mut stdout = Vec::new();
    assert_eq!(
        native(client.complete(
            Wire::new(initial),
            || {
                connects += 1;
                std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                    "must not reconnect",
                )))
            },
            &mut stdout,
            &mut Vec::new(),
        ))
        .unwrap(),
        0
    );
    assert_eq!(stdout, retained);
    assert!(client.delivery.stdout_published);
    assert!(client.delivery.stdout_spool.is_none());
    assert_eq!(connects, 0);
    assert_eq!(kinds(&output), ["inputs-done", "poll", "poll", "close"]);
}

#[test]
fn result_identity_and_original_delivery_deadline_cannot_change_on_reattachment() {
    let original = Instant::now() + Duration::from_secs(15);
    let mut delivery = ClientDelivery::new(original);
    let result = BuildCompletion {
        exit_code: 0,
        stdout_bytes: 0,
        stderr_bytes: 0,
        target: None,
    };
    delivery.completed(result.clone()).unwrap();
    assert_eq!(delivery.deadline(), original);
    assert_eq!(delivery.output_deadline.get(), original);
    delivery.completed(result).unwrap();
    assert_eq!(delivery.deadline(), original);
    assert_eq!(delivery.output_deadline.get(), original);
    assert!(
        delivery
            .completed(BuildCompletion {
                exit_code: 1,
                stdout_bytes: 0,
                stderr_bytes: 0,
                target: None,
            })
            .is_err()
    );
    assert_eq!(delivery.deadline(), original);
    assert_eq!(delivery.output_deadline.get(), original);
}

#[test]
fn completed_build_shortens_the_deadline_held_by_caller_output() {
    let original = Instant::now() + DELIVERY_BUDGET * 2;
    let mut delivery = ClientDelivery::new(original);
    let output = delivery.output_deadline.clone();
    let result = BuildCompletion {
        exit_code: 0,
        stdout_bytes: 0,
        stderr_bytes: 0,
        target: None,
    };
    delivery.completed(result.clone()).unwrap();
    let deadline = delivery.deadline();
    assert!(deadline < original);
    assert_eq!(output.get(), deadline);
    // Reattachment cannot move either the network or blocked sink's bound.
    delivery.completed(result).unwrap();
    assert_eq!(delivery.deadline(), deadline);
    assert_eq!(output.get(), deadline);
}

#[test]
fn exhausted_original_deadline_allows_only_bounded_token_cancellation() {
    let directory = private();
    let config = delivery_config(&directory.path().join("completed"));
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    client.delivery.operation_deadline = Instant::now();
    let initial = RecoveryPeer::new(&[]);
    let initial_output = initial.output();
    let cleanup = RecoveryPeer::new(&[Message::Cancelled {}]);
    let cleanup_output = cleanup.output();
    let mut cleanup = Some(cleanup);
    let error = native(client.complete(
        Wire::new(initial),
        || {
            std::future::ready(Ok(cleanup
                .take()
                .expect("expired operations never reconnect")))
        },
        &mut Vec::new(),
        &mut Vec::new(),
    ))
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(kinds(&initial_output).is_empty());
    assert_eq!(kinds(&cleanup_output), ["cancel-operation"]);
}
