use super::*;

fn prefix_plan(fixture: &InputFixture, offset: usize, matching: bool) -> SourcePlan {
    let bytes = if matching {
        &fixture.source_bytes[..offset]
    } else {
        b"different bytes retained by the peer".as_slice()
    };
    SourcePlan::with_prefixes(
        fixture.bundle.source.manifest(),
        vec![0, 2],
        vec![SourcePrefixOffer {
            index: 0,
            offset: offset as u64,
            sha256: encode_hex(&Sha256::digest(bytes)),
        }],
    )
    .unwrap()
}

fn prefix_peer(
    fixture: &InputFixture,
    plan: SourcePlan,
    disposition: ToolchainDisposition,
    expected_offset: u64,
) -> AdmissionStream {
    let mut frames: u64 = plan
        .missing_files
        .iter()
        .map(|index| {
            let file = &fixture.bundle.source.manifest().files()[usize::from(*index)];
            let offset = if *index == 0 { expected_offset } else { 0 };
            (file.len - offset).div_ceil(MAX_SOURCE_CHUNK as u64)
        })
        .sum();
    if disposition == ToolchainDisposition::Upload {
        for entry in fixture
            .bundle
            .toolchain
            .as_ref()
            .unwrap()
            .entries()
            .unwrap()
        {
            frames += 1;
            if let ToolchainEntryKind::File { bytes, .. } = entry.kind {
                frames += bytes.div_ceil(MAX_SOURCE_CHUNK as u64);
            }
        }
    }
    let mut replies = vec![Message::Ready {
        toolchain: disposition,
        source: plan,
    }];
    let mut cumulative = 0;
    while frames != 0 {
        let count = frames.min(wire::WINDOW);
        cumulative += count;
        replies.push(Message::Window { count: cumulative });
        frames -= count;
    }
    let mut peer = AdmissionStream::new(&replies, false);
    peer.quantum = MAX_JSON_RECORD;
    peer
}

#[test]
fn client_selects_only_matching_prefixes_and_seals_the_complete_source_and_sdk() {
    // This runs the actual sender and wire against bounded in-memory responses,
    // then reconstructs both complete trees using real filesystem receivers.
    for disposition in [ToolchainDisposition::Upload, ToolchainDisposition::Reuse] {
        for matching in [true, false] {
            let mut fixture = InputFixture::new();
            let offered_offset = MAX_SOURCE_CHUNK + 13;
            let selected_offset = if matching { offered_offset } else { 0 };
            let plan = prefix_plan(&fixture, offered_offset, matching);
            let peer = prefix_peer(&fixture, plan.clone(), disposition, selected_offset as u64);
            let output = Arc::clone(&peer.output);
            let mut wire = Wire::new(peer);
            let stopped = AtomicBool::new(false);
            native(async {
                let (deadline, selected, admitted) = await_input_admission(
                    &mut wire,
                    fixture.bundle.source.manifest(),
                    &stopped,
                    "prefix-fixture",
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .unwrap();
                assert_eq!(admitted, plan);
                upload_inputs(
                    &mut wire,
                    &mut fixture.bundle,
                    &fixture.owner.path().join("scratch"),
                    selected,
                    &admitted,
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
            let (mut source, mut sdk) =
                fixture.receivers(destination.path(), sdk_destination.path());
            for (index, bytes) in fixture.source_bytes[..selected_offset]
                .chunks(MAX_SOURCE_CHUNK)
                .enumerate()
            {
                source
                    .write_chunk(
                        "a-binary",
                        (index * MAX_SOURCE_CHUNK) as u64,
                        bytes,
                        Sha256::digest(bytes).into(),
                    )
                    .unwrap();
            }
            let mut first_binary = None;
            let mut first_executable = None;
            let mut sent_source_bytes = 0;
            let mut sent_sdk_bytes = 0;
            let mut pending = 0;
            let mut cumulative = 0;
            let mut completed = false;
            for record in admission_messages(&output) {
                assert!(!completed, "nothing may follow the complete input seal");
                match serde_json::from_value::<Message>(record).unwrap() {
                    Message::SourceChunk { chunk } => {
                        match chunk.path.as_str() {
                            "a-binary" => {
                                first_binary.get_or_insert(chunk.offset);
                            }
                            "c-executable" => {
                                first_executable.get_or_insert(chunk.offset);
                            }
                            other => panic!("unexpected requested source member: {other}"),
                        }
                        let (bytes, sha256) = chunk.verified_bytes().unwrap();
                        assert!(bytes.len() <= MAX_SOURCE_CHUNK);
                        source
                            .write_chunk(&chunk.path, chunk.offset, &bytes, sha256)
                            .unwrap();
                        sent_source_bytes += bytes.len();
                        pending += 1;
                    }
                    Message::ToolchainEntry { entry } => {
                        assert_eq!(disposition, ToolchainDisposition::Upload);
                        sdk.entry(entry.native()).unwrap();
                        pending += 1;
                    }
                    Message::ToolchainChunk { chunk } => {
                        assert_eq!(disposition, ToolchainDisposition::Upload);
                        let (bytes, sha256) = chunk.verified_bytes().unwrap();
                        sdk.write_chunk(&chunk.path, chunk.offset, &bytes, sha256)
                            .unwrap();
                        sent_sdk_bytes += bytes.len() as u64;
                        pending += 1;
                    }
                    Message::WindowEnd { count } => {
                        assert!((1..=wire::WINDOW).contains(&pending));
                        cumulative += pending;
                        assert_eq!(count, cumulative);
                        pending = 0;
                    }
                    Message::InputsDone {} => {
                        assert_eq!(pending, 0);
                        completed = true;
                    }
                    message => panic!("unexpected resumed upload message: {message:?}"),
                }
                assert!(pending <= wire::WINDOW);
            }
            assert!(completed);
            assert_eq!(first_binary, Some(selected_offset as u64));
            assert_eq!(first_executable, Some(0));
            assert_eq!(
                sent_source_bytes,
                fixture.source_bytes.len() - selected_offset + b"#!/bin/sh\nexit 0\n".len(),
            );
            source.seal().unwrap();
            let root = source.sealed_root().unwrap();
            assert_eq!(
                fs::read(root.join("a-binary")).unwrap(),
                fixture.source_bytes
            );
            assert!(fs::read(root.join("b-empty")).unwrap().is_empty());
            assert_eq!(
                fs::read(root.join("c-executable")).unwrap(),
                b"#!/bin/sh\nexit 0\n"
            );
            assert_eq!(
                fs::metadata(root.join("c-executable")).unwrap().mode() & 0o7777,
                0o555
            );
            if disposition == ToolchainDisposition::Upload {
                let received_sdk = sdk.seal(|| false).unwrap();
                assert_eq!(
                    received_sdk.identity(),
                    fixture.bundle.toolchain.as_ref().unwrap().identity()
                );
                assert_eq!(sent_sdk_bytes, received_sdk.identity().bytes);
                assert_eq!(
                    fs::read(received_sdk.root().join("lib/runtime")).unwrap(),
                    fixture.runtime_bytes
                );
            } else {
                assert_eq!(sent_sdk_bytes, 0);
                assert_eq!(sdk.entry_count(), 0);
            }
            assert_eq!(
                fs::read_dir(fixture.owner.path().join("scratch"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }
}

#[test]
fn resumed_source_upload_refuses_a_wrong_window_ack_before_sending_more_tail_or_sealing() {
    let mut fixture = InputFixture::new();
    let offset = MAX_SOURCE_CHUNK + 13;
    let plan = prefix_plan(&fixture, offset, true);
    let mut peer = AdmissionStream::new(
        &[
            Message::Ready {
                toolchain: ToolchainDisposition::Reuse,
                source: plan,
            },
            Message::Window {
                count: wire::WINDOW - 1,
            },
        ],
        false,
    );
    peer.quantum = MAX_JSON_RECORD;
    let output = Arc::clone(&peer.output);
    let stopped = AtomicBool::new(false);
    let mut wire = Wire::new(peer);
    let error = native(async {
        let (deadline, selected, source_plan) = await_input_admission(
            &mut wire,
            fixture.bundle.source.manifest(),
            &stopped,
            "prefix-fixture",
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
        upload_inputs(
            &mut wire,
            &mut fixture.bundle,
            &fixture.owner.path().join("scratch"),
            selected,
            &source_plan,
            &stopped,
            deadline,
        )
        .await
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    let records = admission_messages(&output);
    assert_eq!(records.len(), wire::WINDOW as usize + 1);
    assert_eq!(records[0]["chunk"]["offset"], offset as u64);
    for record in &records[..wire::WINDOW as usize] {
        assert_eq!(record["kind"], "source-chunk");
    }
    assert_eq!(records.last().unwrap()["kind"], "window-end");
    assert_eq!(records.last().unwrap()["count"], wire::WINDOW);
}

#[test]
fn matching_prefix_does_not_skip_full_retained_source_verification() {
    let mut fixture = InputFixture::new();
    let plan = prefix_plan(&fixture, MAX_SOURCE_CHUNK + 13, true);
    let source_path = fixture
        .bundle
        .source
        .sealed_root()
        .unwrap()
        .join("a-binary");
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut damaged = fixture.source_bytes.clone();
    *damaged.last_mut().unwrap() ^= 0xff;
    fs::write(source_path, damaged).unwrap();
    let peer = AdmissionStream::new(&[], false);
    let output = Arc::clone(&peer.output);
    let result = native(upload_inputs(
        &mut Wire::new(peer),
        &mut fixture.bundle,
        &fixture.owner.path().join("scratch"),
        ToolchainDisposition::Reuse,
        &plan,
        &AtomicBool::new(false),
        Instant::now() + IO_BUDGET,
    ));
    assert!(result.is_err());
    assert!(output.lock().unwrap().is_empty());
}
