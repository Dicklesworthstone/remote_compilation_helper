use super::*;

fn window_replies(replies: &mut Vec<Message>, mut frames: u64, cumulative: &mut u64) {
    while frames != 0 {
        let count = frames.min(wire::WINDOW);
        *cumulative += count;
        replies.push(Message::Window { count: *cumulative });
        frames -= count;
    }
}

fn file_plan(fixture: &InputFixture, mode: &str) -> wire::ToolchainFilePlan {
    let toolchain = fixture.bundle.toolchain.as_ref().unwrap();
    let files = toolchain.files().unwrap();
    let index = files
        .iter()
        .position(|file| file.path == "lib/runtime")
        .unwrap() as u32;
    wire::ToolchainFilePlan {
        first: 0,
        missing_files: if mode == "complete" {
            vec![]
        } else {
            vec![index]
        },
        prefixes: match mode {
            "prefix" | "corrupt-prefix" => vec![ToolchainPrefixOffer {
                index,
                offset: (MAX_SOURCE_CHUNK + 13) as u64,
                sha256: encode_hex(&Sha256::digest(if mode == "prefix" {
                    &fixture.runtime_bytes[..MAX_SOURCE_CHUNK + 13]
                } else {
                    b"different bytes retained by the coordinator"
                })),
            }],
            _ => vec![],
        },
    }
}

#[test]
fn sdk_file_plans_skip_only_verified_bytes_and_preserve_the_entire_namespace() {
    // The production sender consumes bounded wire replies; real receivers
    // independently seal both trees. Cached SDK bytes are an explicit fixture,
    // not a claim about TLS, worker execution or retained-cache performance.
    for mode in ["missing", "prefix", "corrupt-prefix", "complete"] {
        let mut fixture = InputFixture::new();
        let toolchain = Arc::clone(fixture.bundle.toolchain.as_ref().unwrap());
        let expected_sdk = *toolchain.identity();
        let files = toolchain.files().unwrap();
        let plan = file_plan(&fixture, mode);
        let selected_offset = match mode {
            "prefix" => (MAX_SOURCE_CHUNK + 13) as u64,
            "complete" => fixture.runtime_bytes.len() as u64,
            _ => 0,
        };
        // One source frame is pending before the SDK phase. It must be
        // acknowledged before the first file-plan reply is consumed.
        let source_plan =
            SourcePlan::with_prefixes(fixture.bundle.source.manifest(), vec![2], vec![]).unwrap();
        let mut replies = Vec::new();
        let mut cumulative = 0;
        window_replies(&mut replies, 1, &mut cumulative);
        replies.push(Message::ToolchainFilePlan { plan });
        replies.push(Message::ToolchainFilesReady {
            files: expected_sdk.files,
            bytes: expected_sdk.bytes,
        });
        let sdk_frames = toolchain.entries().unwrap().len() as u64
            + (fixture.runtime_bytes.len() as u64 - selected_offset)
                .div_ceil(MAX_SOURCE_CHUNK as u64);
        window_replies(&mut replies, sdk_frames, &mut cumulative);
        let mut stream = AdmissionStream::new(&replies, false);
        stream.quantum = MAX_JSON_RECORD;
        let output = Arc::clone(&stream.output);
        let mut wire = Wire::new(stream);
        native(async {
            let stopped = AtomicBool::new(false);
            let deadline = Instant::now() + Duration::from_secs(5);
            upload_inputs(
                &mut wire,
                &mut fixture.bundle,
                &fixture.owner.path().join("scratch"),
                ToolchainDisposition::UploadFiles,
                &source_plan,
                &stopped,
                deadline,
            )
            .await
            .unwrap();
            wire.send(&Message::InputsDone {}, &stopped, deadline)
                .await
                .unwrap();
        });

        let destination = private();
        let sdk_destination = private();
        let (mut source, mut sdk) = fixture.receivers(destination.path(), sdk_destination.path());
        for (index, bytes) in fixture.source_bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            source
                .write_chunk(
                    "a-binary",
                    (index * MAX_SOURCE_CHUNK) as u64,
                    bytes,
                    Sha256::digest(bytes).into(),
                )
                .unwrap();
        }
        let mut pending = 0;
        let mut cumulative = 0;
        let mut negotiation = 0;
        let mut sdk_entries = 0;
        let mut sent_sdk_bytes = 0;
        let mut first_runtime_offset = None;
        let mut complete = false;
        for record in admission_messages(&output) {
            assert!(!complete, "nothing may follow InputsDone");
            match serde_json::from_value::<Message>(record).unwrap() {
                Message::SourceChunk { chunk } => {
                    assert_eq!(negotiation, 0);
                    assert_eq!(chunk.path, "c-executable");
                    let (bytes, sha256) = chunk.verified_bytes().unwrap();
                    source
                        .write_chunk(&chunk.path, chunk.offset, &bytes, sha256)
                        .unwrap();
                    pending += 1;
                }
                Message::WindowEnd { count } => {
                    assert!((1..=wire::WINDOW).contains(&pending));
                    cumulative += pending;
                    assert_eq!(count, cumulative);
                    pending = 0;
                }
                Message::ToolchainFilePage { page } => {
                    assert_eq!(
                        pending, 0,
                        "source window is flushed before file negotiation"
                    );
                    assert_eq!(negotiation, 0);
                    assert_eq!(page.first, 0);
                    assert_eq!(page.native().unwrap(), files);
                    negotiation = 1;
                }
                Message::ToolchainFilesEnd {} => {
                    assert_eq!(negotiation, 1);
                    negotiation = 2;
                }
                Message::ToolchainResumedEntry { entry, resume } => {
                    assert_eq!(negotiation, 2);
                    let entry = entry.native();
                    sdk.entry(entry.clone()).unwrap();
                    if let ToolchainEntryKind::File { bytes, .. } = entry.kind {
                        let file = files.iter().find(|file| file.path == entry.path).unwrap();
                        let resume = resume.expect("every negotiated regular file selects a range");
                        let expected_offset = if entry.path == "lib/runtime" {
                            selected_offset
                        } else {
                            bytes
                        };
                        assert_eq!(resume.offset, expected_offset);
                        let mut digest = Sha256::new();
                        let mut offset = 0;
                        while offset < resume.offset {
                            let count =
                                (resume.offset - offset).min(MAX_SOURCE_CHUNK as u64) as usize;
                            let bytes = toolchain
                                .read_chunk(&entry.path, offset, count, || false)
                                .unwrap();
                            digest.update(&bytes);
                            sdk.write_chunk(
                                &entry.path,
                                offset,
                                &bytes,
                                Sha256::digest(&bytes).into(),
                            )
                            .unwrap();
                            offset += bytes.len() as u64;
                        }
                        assert_eq!(resume.sha256, encode_hex(&digest.finalize()));
                        if resume.offset == file.bytes {
                            assert_eq!(resume.sha256, encode_hex(&file.sha256));
                        }
                    } else {
                        assert!(
                            resume.is_none(),
                            "directories and links cannot skip payload bytes"
                        );
                    }
                    sdk_entries += 1;
                    pending += 1;
                }
                Message::ToolchainChunk { chunk } => {
                    assert_eq!(negotiation, 2);
                    assert_eq!(chunk.path, "lib/runtime");
                    first_runtime_offset.get_or_insert(chunk.offset);
                    let (bytes, sha256) = chunk.verified_bytes().unwrap();
                    sdk.write_chunk(&chunk.path, chunk.offset, &bytes, sha256)
                        .unwrap();
                    sent_sdk_bytes += bytes.len() as u64;
                    pending += 1;
                }
                Message::InputsDone {} => {
                    assert_eq!(pending, 0);
                    complete = true;
                }
                message => panic!("unexpected SDK file upload message: {message:?}"),
            }
            assert!(pending <= wire::WINDOW);
        }
        assert!(complete);
        assert_eq!(sdk_entries, toolchain.entries().unwrap().len());
        assert_eq!(
            sent_sdk_bytes,
            fixture.runtime_bytes.len() as u64 - selected_offset
        );
        assert_eq!(
            first_runtime_offset,
            (selected_offset < fixture.runtime_bytes.len() as u64).then_some(selected_offset),
        );
        source.seal().unwrap();
        let received = sdk.seal(|| false).unwrap();
        assert_eq!(*received.identity(), expected_sdk);
        assert_eq!(
            fs::read(received.root().join("lib/runtime")).unwrap(),
            fixture.runtime_bytes
        );
        assert_eq!(
            fs::read_link(received.root().join("bin/runtime")).unwrap(),
            Path::new("../lib/runtime")
        );
        assert_eq!(
            fs::metadata(received.root().join("bin/compiler"))
                .unwrap()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(
            fs::read(source.sealed_root().unwrap().join("a-binary")).unwrap(),
            fixture.source_bytes
        );
    }
}

#[test]
fn malformed_sdk_plans_refuse_before_any_namespace_or_file_payload() {
    let fixture = InputFixture::new();
    let valid = file_plan(&fixture, "prefix");
    let index = valid.missing_files[0];
    let file_bytes = fixture.runtime_bytes.len() as u64;
    let mut invalid = Vec::new();
    for first in [1, u32::MAX] {
        invalid.push(wire::ToolchainFilePlan {
            first,
            ..valid.clone()
        });
    }
    for missing_files in [
        vec![index, index],
        vec![index, 0],
        vec![1],
        vec![u32::MAX],
        vec![],
    ] {
        invalid.push(wire::ToolchainFilePlan {
            missing_files,
            ..valid.clone()
        });
    }
    for offset in [0, file_bytes, u64::MAX] {
        let mut plan = valid.clone();
        plan.prefixes[0].offset = offset;
        invalid.push(plan);
    }
    for sha256 in ["AB".repeat(32), "00".repeat(31), "zz".repeat(32)] {
        let mut plan = valid.clone();
        plan.prefixes[0].sha256 = sha256;
        invalid.push(plan);
    }
    let mut duplicate = valid.clone();
    duplicate.prefixes.push(duplicate.prefixes[0].clone());
    invalid.push(duplicate);
    for plan in invalid {
        let stream = AdmissionStream::new(&[Message::ToolchainFilePlan { plan }], false);
        let output = Arc::clone(&stream.output);
        let mut wire = Wire::new(stream);
        let result = native(negotiate_toolchain_files(
            &mut wire,
            fixture.bundle.toolchain.as_ref().unwrap(),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        ));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let sent = admission_messages(&output);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["kind"], "toolchain-file-page");
    }
}

#[test]
fn sdk_file_negotiation_refuses_wrong_totals_disconnect_and_phase_changes_without_retry() {
    let fixture = InputFixture::new();
    let toolchain = fixture.bundle.toolchain.as_ref().unwrap();
    let identity = toolchain.identity();
    for (reply, expected) in [
        (
            Some(Message::ToolchainFilesReady {
                files: identity.files + 1,
                bytes: identity.bytes,
            }),
            io::ErrorKind::InvalidData,
        ),
        (
            Some(Message::ToolchainFilesReady {
                files: identity.files,
                bytes: identity.bytes + 1,
            }),
            io::ErrorKind::InvalidData,
        ),
        (
            Some(Message::ToolchainFilesDeclined {}),
            io::ErrorKind::InvalidData,
        ),
        (Some(Message::Cancel {}), io::ErrorKind::Interrupted),
        (
            Some(Message::Failure {
                message: "SDK became unavailable".into(),
            }),
            io::ErrorKind::InvalidData,
        ),
        (None, io::ErrorKind::UnexpectedEof),
    ] {
        let mut replies = vec![Message::ToolchainFilePlan {
            plan: file_plan(&fixture, "complete"),
        }];
        replies.extend(reply);
        let stream = AdmissionStream::new(&replies, false);
        let output = Arc::clone(&stream.output);
        let mut wire = Wire::new(stream);
        let result = native(negotiate_toolchain_files(
            &mut wire,
            toolchain,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        ));
        assert_eq!(result.unwrap_err().kind(), expected);
        let sent = admission_messages(&output);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0]["kind"], "toolchain-file-page");
        assert_eq!(sent[1], json!({"kind":"toolchain-files-end"}));
    }
}

#[test]
fn sdk_prefix_selection_checks_deadlines_and_refuses_changed_retained_bytes() {
    let fixture = InputFixture::new();
    let toolchain = fixture.bundle.toolchain.as_ref().unwrap();
    let file = toolchain
        .files()
        .unwrap()
        .into_iter()
        .find(|file| file.path == "lib/runtime")
        .unwrap();
    let offer = file_plan(&fixture, "prefix").prefixes.remove(0);
    for (cancelled, deadline, expected) in [
        (
            true,
            Instant::now() + Duration::from_secs(5),
            io::ErrorKind::Interrupted,
        ),
        (false, Instant::now(), io::ErrorKind::TimedOut),
    ] {
        let error = toolchain_prefix_resume(
            toolchain,
            &file,
            &offer,
            &AtomicBool::new(cancelled),
            deadline,
        )
        .unwrap_err();
        assert_eq!(error.kind(), expected);
    }
    let path = toolchain.root().join(&file.path);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, b"changed retained compiler input").unwrap();
    assert!(
        toolchain_prefix_resume(
            toolchain,
            &file,
            &offer,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .is_err(),
        "an invalid retained SDK cannot silently choose a cold upload"
    );
    let stream = AdmissionStream::new(&[], false);
    let output = Arc::clone(&stream.output);
    let mut wire = Wire::new(stream);
    assert!(
        native(negotiate_toolchain_files(
            &mut wire,
            toolchain,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        ))
        .is_err()
    );
    assert!(
        output.lock().unwrap().is_empty(),
        "changed custody refuses before negotiation"
    );
}

#[test]
fn sdk_file_pages_bound_quoted_paths_and_optional_manifest_metadata() {
    let files: Vec<_> = (0..TOOLCHAIN_PAGE_FILES + 11)
        .map(|index| ToolchainFile {
            path: format!("{}/{index:06}", vec!["\"".repeat(250); 15].join("/")),
            bytes: 1,
            executable: false,
            sha256: [7; 32],
        })
        .collect();
    let mut first = 0;
    let mut pages = 0;
    while first < files.len() {
        let next = toolchain_file_page_end(&files, first).unwrap();
        assert!(
            next - first < TOOLCHAIN_PAGE_FILES,
            "worst-case quoted names need smaller pages"
        );
        let page = ToolchainFilePage::from_native(first, &files[first..next]).unwrap();
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_TOOLCHAIN_FILE_PAGE_BYTES);
        assert_eq!(page.native().unwrap(), files[first..next]);
        first = next;
        pages += 1;
    }
    assert!(pages > 1);
    assert!(toolchain_file_manifest_fits(&files));
    let count = MAX_TOOLCHAIN_METADATA_BYTES / (256 + 2 * files[0].path.len());
    let mut excessive = vec![files[0].clone(); count];
    assert!(toolchain_file_manifest_fits(&excessive));
    excessive.push(files[0].clone());
    assert!(
        !toolchain_file_manifest_fits(&excessive),
        "extra metadata must choose the cold path"
    );
}

struct ObservedUpload<S> {
    inner: S,
    output: Arc<Mutex<Vec<u8>>>,
    stop_before_runtime_offset: Option<u64>,
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedUpload<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedUpload<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = self.get_mut();
        if let Some(offset) = stream.stop_before_runtime_offset
            && let Ok(Message::ToolchainChunk { chunk }) = serde_json::from_slice(bytes)
            && chunk.path == "lib/runtime"
            && chunk.offset >= offset
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "fixture disconnect before the next SDK chunk",
            )));
        }
        let result = Pin::new(&mut stream.inner).poll_write(context, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            stream
                .output
                .lock()
                .unwrap()
                .extend_from_slice(&bytes[..*count]);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[test]
fn native_atp_resumes_interrupted_sdk_upload_then_reuses_files_only_for_the_same_peer() {
    use super::super::super::toolchain_inputs::RemoteToolchainFileCache;

    // Real loopback ATP, source/SDK receivers and byte cache; the compiler
    // dataset and authenticated peer IDs are explicit fixtures. This test
    // exercises transfer recovery, not real Cargo or TLS authentication.
    let mut fixture = InputFixture::new();
    let expected = *fixture.bundle.toolchain.as_ref().unwrap().identity();
    let cache_parent = private();
    let cache = RemoteToolchainFileCache::new(cache_parent.path(), expected.bytes * 4).unwrap();
    let retained_prefix = (MAX_SOURCE_CHUNK * 2) as u64;
    for (round, peer, disconnect) in [
        (0, [19; 32], Some(retained_prefix)),
        (1, [19; 32], None),
        (2, [19; 32], None),
        (3, [23; 32], None),
    ] {
        let destination = private();
        let sdk_destination = Arc::new(private());
        let (source, receiver) = fixture.receivers(destination.path(), sdk_destination.path());
        let files = cache.for_peer(peer, expected, &|| false).unwrap();
        let source_plan = SourcePlan::all(fixture.bundle.source.manifest()).unwrap();
        let scratch = fixture.owner.path().join("scratch");
        let expected_runtime = fixture.runtime_bytes.clone();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let output = Arc::clone(&observed);
        let (sent, received) = std::thread::scope(|scope| {
            let (addresses, address) = mpsc::sync_channel(1);
            let server = scope.spawn(move || {
                native(async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    addresses.send(listener.local_addr()?.to_string()).unwrap();
                    let (stream, _) = listener.accept().await?;
                    let mut wire = Wire::new(JsonAtpStream::new(stream));
                    let stopped = AtomicBool::new(false);
                    let deadline = Instant::now() + Duration::from_secs(25);
                    let (_, toolchain) = super::super::super::receive_inputs(
                        &mut wire,
                        SourceInput::uncached(source)?,
                        ToolchainInput::Upload {
                            receiver: Box::new(receiver),
                            owner: sdk_destination,
                            files: Some(Box::new(files)),
                        },
                        &stopped,
                        deadline,
                    )
                    .await?;
                    assert_eq!(*toolchain.identity(), expected);
                    assert_eq!(
                        fs::read(toolchain.root().join("lib/runtime"))?,
                        expected_runtime
                    );
                    wire.send(&Message::Accepted {}, &stopped, deadline).await?;
                    Ok::<_, io::Error>(())
                })
            });
            let address = address.recv_timeout(Duration::from_secs(10)).unwrap();
            let sent = native(async {
                let stream = TcpStream::connect(address).await?;
                let mut wire = Wire::new(ObservedUpload {
                    inner: JsonAtpStream::new(stream),
                    output,
                    stop_before_runtime_offset: disconnect,
                });
                let stopped = AtomicBool::new(false);
                let deadline = Instant::now() + Duration::from_secs(25);
                upload_inputs(
                    &mut wire,
                    &mut fixture.bundle,
                    &scratch,
                    ToolchainDisposition::UploadFiles,
                    &source_plan,
                    &stopped,
                    deadline,
                )
                .await?;
                wire.send(&Message::InputsDone {}, &stopped, deadline)
                    .await?;
                require(
                    matches!(
                        wire.receive_until(&stopped, deadline).await?,
                        Message::Accepted {}
                    ),
                    "native SDK file receiver did not seal the exact dataset",
                )
            });
            (sent, server.join().unwrap())
        });
        let messages = admission_messages(&observed);
        let chunks: Vec<Chunk> = messages
            .iter()
            .filter_map(|message| {
                if message["kind"] == "toolchain-chunk" {
                    let Message::ToolchainChunk { chunk } =
                        serde_json::from_value(message.clone()).unwrap()
                    else {
                        unreachable!()
                    };
                    Some(chunk)
                } else {
                    None
                }
            })
            .collect();
        let bytes: u64 = chunks
            .iter()
            .map(|chunk| chunk.verified_bytes().unwrap().0.len() as u64)
            .sum();
        let runtime_offset = chunks
            .iter()
            .find(|chunk| chunk.path == "lib/runtime")
            .map(|chunk| chunk.offset);
        if round == 0 {
            assert_eq!(sent.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
            assert!(
                received.is_err(),
                "interrupted SDK cannot become an accepted execution input"
            );
            assert!(
                messages
                    .iter()
                    .all(|message| message["kind"] != "inputs-done")
            );
            assert_eq!(runtime_offset, Some(0));
            assert_eq!(bytes, retained_prefix + b"#!/bin/sh\nexit 0\n".len() as u64);
        } else {
            sent.unwrap();
            received.unwrap();
            assert_eq!(messages.last().unwrap()["kind"], "inputs-done");
            match round {
                1 => {
                    assert_eq!(runtime_offset, Some(retained_prefix));
                    assert_eq!(bytes, fixture.runtime_bytes.len() as u64 - retained_prefix);
                }
                2 => {
                    assert_eq!(runtime_offset, None);
                    assert_eq!(
                        bytes, 0,
                        "all SDK files are independently verified retained hits"
                    );
                }
                3 => {
                    assert_eq!(runtime_offset, Some(0));
                    assert_eq!(
                        bytes, expected.bytes,
                        "another peer cannot reuse the first peer's bytes"
                    );
                }
                _ => unreachable!(),
            }
        }
    }
}
