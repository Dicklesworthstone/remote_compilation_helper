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

#[test]
fn reconnect_retains_only_fully_exposed_diagnostic_pairs() {
    let directory = private();
    let config = delivery_config(&directory.path().join("completed"));
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let mut initial = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, b"first-out"),
            stderr: diagnostic(0, b"first-err"),
        },
    ]);
    // A partial next record is never exposed or continued on another stream.
    initial
        .inner
        .input
        .extend_from_slice(b"{\"kind\":\"progress\",\"stdout\":");
    let resumed = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(9, b"-next"),
            stderr: diagnostic(9, b""),
        },
        Message::BuildFinished {
            exit_code: 0,
            stdout_bytes: 14,
            stderr_bytes: 9,
            target: None,
        },
        Message::Complete { exit_code: 0 },
    ]);
    let resumed_output = resumed.output();
    let mut peers = VecDeque::from([resumed]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        native(client.complete(
            Wire::new(initial),
            || std::future::ready(Ok(peers.pop_front().expect("unexpected reconnect"))),
            &mut stdout,
            &mut stderr,
        ))
        .unwrap(),
        0
    );
    assert_eq!(stdout, b"first-out-next");
    assert_eq!(stderr, b"first-err");
    assert_resume(&resumed_output, 9, 9);
    assert_eq!(
        (client.delivery.stdout_offset, client.delivery.stderr_offset),
        (14, 9)
    );
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
fn local_diagnostic_failure_cancels_without_replaying_an_exposed_half_pair() {
    let directory = private();
    let config = delivery_config(&directory.path().join("completed"));
    let stopped = AtomicBool::new(false);
    let mut client = client(&config, &stopped);
    let initial = RecoveryPeer::new(&[
        Message::Accepted {},
        Message::Progress {
            stdout: diagnostic(0, b"visible"),
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
    assert_eq!(stdout, b"visible");
    assert_eq!(
        (client.delivery.stdout_offset, client.delivery.stderr_offset),
        (0, 0)
    );
    assert_eq!(connects, 0);
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
    let mut initial = RecoveryPeer::new(&[
        Message::Accepted {},
        finished(0, None),
        Message::Complete { exit_code: 0 },
    ]);
    initial.fail_write = Some("delivered");
    let output = initial.output();
    let mut connects = 0;
    assert_eq!(
        native(client.complete(
            Wire::new(initial),
            || {
                connects += 1;
                std::future::ready(Err::<RecoveryPeer, _>(io::Error::other(
                    "must not reconnect",
                )))
            },
            &mut Vec::new(),
            &mut Vec::new(),
        ))
        .unwrap(),
        0
    );
    assert_eq!(connects, 0);
    assert_eq!(kinds(&output), ["inputs-done", "poll", "close"]);
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
    delivery.completed(result).unwrap();
    assert_eq!(delivery.deadline(), original);
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
