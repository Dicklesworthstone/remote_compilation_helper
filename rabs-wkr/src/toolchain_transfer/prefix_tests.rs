//! Interrupted-file recovery through the real owned transfer task and cache.
//! Prefix agreement skips bytes only; every success below still obtains the
//! ordinary complete SDK seal, and legacy file-reuse behavior is retained.

use super::*;

fn prefix_task(cache: ToolchainFileCache) -> ToolchainTransferTask {
    ToolchainTransferTask::with_prefix_configuration(false, Some(cache), true)
}

fn negotiate_prefixes(
    task: &mut ToolchainTransferTask,
    sdk: &PreparedToolchain,
) -> BTreeMap<String, (u64, [u8; 32])> {
    let files = sdk.files().unwrap();
    let accepted = exchange(task, page(sdk, 0, &files)).unwrap();
    assert_eq!(accepted.as_object().unwrap().len(), 6);
    let missing: BTreeSet<_> = accepted["missing"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect();
    let mut selected = BTreeMap::new();
    for file in &files {
        if !missing.contains(file.path.as_str()) {
            selected.insert(file.path.clone(), (file.bytes, file.sha256));
        } else {
            selected.insert(file.path.clone(), (0, Sha256::digest([]).into()));
        }
    }
    for offered in accepted["prefixes"].as_array().unwrap() {
        let path = offered["path"].as_str().unwrap();
        assert!(missing.contains(path));
        let offset = offered["offset"].as_u64().unwrap();
        let sha256 = digest(&offered["sha256"]).unwrap();
        let expected = files.iter().find(|file| file.path == path).unwrap();
        assert!(offset > 0 && offset < expected.bytes);
        // Exercise the actual retained sender byte view; an object name and a
        // worker-computed hash alone cannot authenticate the claimed prefix.
        let mut hash = Sha256::new();
        let mut checked = 0;
        while checked < offset {
            let bytes = sdk
                .read_chunk(
                    path,
                    checked,
                    (offset - checked).min(MAX_TOOLCHAIN_CHUNK as u64) as usize,
                    || false,
                )
                .unwrap();
            hash.update(&bytes);
            checked += bytes.len() as u64;
        }
        if <[u8; 32]>::from(hash.finalize()) == sha256 {
            selected.insert(path.to_owned(), (offset, sha256));
        }
    }
    let ready = exchange(task, operation(sdk, "toolchain-file-manifest-seal")).unwrap();
    assert_eq!(ready["kind"], "toolchain-file-manifest-ready");
    assert!(task.prepared_path(&request(sdk), true).is_err());
    selected
}

fn prefix_entry(
    sdk: &PreparedToolchain,
    entry: &ToolchainEntry,
    selected: &BTreeMap<String, (u64, [u8; 32])>,
) -> Value {
    let mut frame = entry_frame(sdk, entry);
    if matches!(entry.kind, ToolchainEntryKind::File { .. }) {
        let (offset, sha256) = selected[&entry.path];
        frame["resume"] = json!({"offset":offset, "sha256":hex(&sha256)});
    }
    frame
}

fn upload_prefixes(
    task: &mut ToolchainTransferTask,
    sdk: &PreparedToolchain,
    selected: &BTreeMap<String, (u64, [u8; 32])>,
) -> u64 {
    let mut transmitted = 0;
    for entry in sdk.entries().unwrap() {
        let reply = exchange(task, prefix_entry(sdk, &entry, selected)).unwrap();
        if let ToolchainEntryKind::File { bytes, .. } = entry.kind {
            let mut offset = selected[&entry.path].0;
            assert_eq!(reply["next_offset"], offset);
            while offset < bytes {
                let chunk = sdk
                    .read_chunk(&entry.path, offset, MAX_TOOLCHAIN_CHUNK, || false)
                    .unwrap();
                let reply = exchange(task, chunk_frame(sdk, &entry.path, offset, &chunk)).unwrap();
                offset += chunk.len() as u64;
                transmitted += chunk.len() as u64;
                assert_eq!(reply["next_offset"], offset);
            }
        } else {
            assert!(reply.get("next_offset").is_none());
        }
    }
    assert!(task.prepared_path(&request(sdk), true).is_err());
    let ready = exchange(task, operation(sdk, "toolchain-seal")).unwrap();
    assert_eq!(ready["sealed"], true);
    let root = task.prepared_path(&request(sdk), true).unwrap().unwrap();
    let verified = rabs_sandbox::toolchain_dataset::open_toolchain(
        Path::new(&root),
        sdk.identity(),
        &ToolchainLimits::default(),
        || false,
    )
    .unwrap();
    assert_eq!(verified.identity(), sdk.identity());
    transmitted
}

fn stop_with_prefix(root: &Path, sdk: &PreparedToolchain, budget: u64, prefix_bytes: usize) {
    let cache = ToolchainFileCache::open(root, budget).unwrap();
    let mut task = prefix_task(cache);
    begin(&mut task, sdk);
    let selected = negotiate_prefixes(&mut task, sdk);
    for entry in sdk.entries().unwrap() {
        exchange(&mut task, prefix_entry(sdk, &entry, &selected)).unwrap();
        if matches!(entry.kind, ToolchainEntryKind::File { .. }) {
            assert_eq!(selected[&entry.path].0, 0);
            let mut offset = 0;
            while offset < prefix_bytes as u64 {
                let bytes = sdk
                    .read_chunk(
                        &entry.path,
                        offset,
                        (prefix_bytes as u64 - offset).min(MAX_TOOLCHAIN_CHUNK as u64) as usize,
                        || false,
                    )
                    .unwrap();
                exchange(&mut task, chunk_frame(sdk, &entry.path, offset, &bytes)).unwrap();
                offset += bytes.len() as u64;
            }
            break;
        }
    }
    assert!(task.prepared_path(&request(sdk), true).is_err());
    // Disconnect drops the owned upload and lock. No complete SDK existed.
    drop(task);
}

#[test]
fn toolchain_prefix_recovery_reopens_half_file_and_transfers_only_tail_before_full_seal() {
    let bytes: Vec<_> = (0..MAX_TOOLCHAIN_CHUNK * 5 + 123)
        .map(|value| (value % 251) as u8)
        .collect();
    let (_owner, sdk) = fixture(&[("bin/compiler", &bytes, true)]);
    let root = private();
    let prefix = MAX_TOOLCHAIN_CHUNK * 2 + 17;
    stop_with_prefix(root.path(), &sdk, bytes.len() as u64, prefix);
    let file = &sdk.files().unwrap()[0];
    let retained = object(root.path(), file);
    assert_eq!(fs::read(&retained).unwrap(), bytes[..prefix]);
    assert_eq!(fs::metadata(&retained).unwrap().mode() & 0o222, 0);

    let mut resumed =
        prefix_task(ToolchainFileCache::open(root.path(), bytes.len() as u64).unwrap());
    begin(&mut resumed, &sdk);
    let selected = negotiate_prefixes(&mut resumed, &sdk);
    assert_eq!(selected["bin/compiler"].0, prefix as u64);
    assert_eq!(
        upload_prefixes(&mut resumed, &sdk, &selected),
        (bytes.len() - prefix) as u64
    );
    let uploaded = resumed
        .prepared_path(&request(&sdk), true)
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::read(Path::new(&uploaded).join("bin/compiler")).unwrap(),
        bytes
    );
    assert_ne!(
        fs::metadata(Path::new(&uploaded).join("bin/compiler"))
            .unwrap()
            .ino(),
        fs::metadata(&retained).unwrap().ino()
    );
    drop(resumed);

    let mut complete =
        prefix_task(ToolchainFileCache::open(root.path(), bytes.len() as u64).unwrap());
    begin(&mut complete, &sdk);
    let selected = negotiate_prefixes(&mut complete, &sdk);
    assert_eq!(selected["bin/compiler"].0, bytes.len() as u64);
    assert_eq!(upload_prefixes(&mut complete, &sdk, &selected), 0);
}

#[test]
fn toolchain_prefix_corruption_is_sender_rejected_and_legacy_peer_uploads_from_zero() {
    let bytes = vec![0x6b; MAX_TOOLCHAIN_CHUNK * 2 + 19];
    let (_owner, sdk) = fixture(&[("a", &bytes, false)]);
    let root = private();
    stop_with_prefix(root.path(), &sdk, bytes.len() as u64, MAX_TOOLCHAIN_CHUNK);
    let file = &sdk.files().unwrap()[0];
    corrupt(&object(root.path(), file), MAX_TOOLCHAIN_CHUNK as u64);
    let mut resumed =
        prefix_task(ToolchainFileCache::open(root.path(), bytes.len() as u64).unwrap());
    begin(&mut resumed, &sdk);
    let selected = negotiate_prefixes(&mut resumed, &sdk);
    assert_eq!(
        selected["a"].0, 0,
        "hash disagreement cannot skip any bytes"
    );
    assert_eq!(
        upload_prefixes(&mut resumed, &sdk, &selected),
        bytes.len() as u64
    );
    drop(resumed);

    // An older completed-file-only session sees the same ordinary object name,
    // but treats an interrupted short length as missing and retains v1 shape.
    fs::set_permissions(object(root.path(), file), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(object(root.path(), file), &bytes[..37]).unwrap();
    fs::set_permissions(object(root.path(), file), fs::Permissions::from_mode(0o400)).unwrap();
    let mut legacy = ToolchainTransferTask::with_configuration(
        false,
        Some(ToolchainFileCache::open(root.path(), bytes.len() as u64).unwrap()),
    );
    begin(&mut legacy, &sdk);
    let missing = negotiate(&mut legacy, &sdk);
    assert_eq!(missing, BTreeSet::from(["a".to_owned()]));
    assert_eq!(
        upload(&mut legacy, &sdk, &missing, None),
        bytes.len() as u64
    );
}

#[test]
fn toolchain_prefix_hint_snapshot_survives_retained_object_mutation_and_writer_contention() {
    let bytes = vec![0x47; MAX_TOOLCHAIN_CHUNK * 2 + 3];
    let (_owner, sdk) = fixture(&[("a", &bytes, false)]);
    let root = private();
    stop_with_prefix(root.path(), &sdk, bytes.len() as u64, MAX_TOOLCHAIN_CHUNK);
    let cache = ToolchainFileCache::open(root.path(), bytes.len() as u64).unwrap();
    let writer = cache.writer(&|| false).unwrap().unwrap();
    let mut resumed = prefix_task(cache);
    begin(&mut resumed, &sdk);
    let selected = negotiate_prefixes(&mut resumed, &sdk);
    assert_eq!(selected["a"].0, MAX_TOOLCHAIN_CHUNK as u64);
    corrupt(
        &object(root.path(), &sdk.files().unwrap()[0]),
        MAX_TOOLCHAIN_CHUNK as u64,
    );
    assert_eq!(
        upload_prefixes(&mut resumed, &sdk, &selected),
        (bytes.len() - MAX_TOOLCHAIN_CHUNK) as u64
    );
    drop(writer);
}

#[test]
fn toolchain_prefix_wrong_or_unoffered_selection_never_acknowledges_or_seals() {
    let bytes = vec![0x55; MAX_TOOLCHAIN_CHUNK * 2];
    let (_owner, sdk) = fixture(&[("a", &bytes, false)]);
    for fault in [
        "offset",
        "digest",
        "zero-digest",
        "full-unoffered",
        "missing-resume",
    ] {
        let root = private();
        stop_with_prefix(root.path(), &sdk, bytes.len() as u64, MAX_TOOLCHAIN_CHUNK);
        let mut resumed =
            prefix_task(ToolchainFileCache::open(root.path(), bytes.len() as u64).unwrap());
        begin(&mut resumed, &sdk);
        let selected = negotiate_prefixes(&mut resumed, &sdk);
        for entry in sdk.entries().unwrap() {
            let mut frame = prefix_entry(&sdk, &entry, &selected);
            if matches!(entry.kind, ToolchainEntryKind::File { .. }) {
                match fault {
                    "offset" => frame["resume"]["offset"] = json!(1),
                    "digest" => frame["resume"]["sha256"] = json!("ab".repeat(32)),
                    "zero-digest" => frame["resume"]["offset"] = json!(0),
                    "full-unoffered" => {
                        frame["resume"]["offset"] = json!(bytes.len());
                        frame["resume"]["sha256"] = json!(hex(&sdk.files().unwrap()[0].sha256));
                    }
                    "missing-resume" => {
                        frame.as_object_mut().unwrap().remove("resume");
                    }
                    _ => unreachable!(),
                }
                assert!(exchange(&mut resumed, frame).is_err(), "{fault}");
                break;
            }
            exchange(&mut resumed, frame).unwrap();
        }
        assert!(resumed.prepared_path(&request(&sdk), true).is_err());
        assert!(exchange(&mut resumed, operation(&sdk, "toolchain-seal")).is_err());
    }
}

#[test]
fn toolchain_prefix_capacity_preserves_largest_prefix_without_exceeding_existing_budget() {
    let bytes = vec![0x28; MAX_TOOLCHAIN_CHUNK * 3 + 11];
    let (_owner, sdk) = fixture(&[("a", &bytes, false)]);
    let root = private();
    let budget = MAX_TOOLCHAIN_CHUNK as u64;
    stop_with_prefix(root.path(), &sdk, budget, MAX_TOOLCHAIN_CHUNK * 2);
    let file = &sdk.files().unwrap()[0];
    assert_eq!(
        fs::metadata(object(root.path(), file)).unwrap().len(),
        budget
    );
    let mut resumed = prefix_task(ToolchainFileCache::open(root.path(), budget).unwrap());
    begin(&mut resumed, &sdk);
    let selected = negotiate_prefixes(&mut resumed, &sdk);
    assert_eq!(selected["a"].0, budget);
    assert_eq!(
        upload_prefixes(&mut resumed, &sdk, &selected),
        bytes.len() as u64 - budget
    );
    assert_eq!(
        fs::metadata(object(root.path(), file)).unwrap().len(),
        budget
    );
    let retained: u64 = fs::read_dir(root.path().join("toolchain-files-v1"))
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum();
    assert!(retained <= budget);
}

#[test]
fn toolchain_prefix_restart_uses_actual_short_write_length_without_a_stale_cursor() {
    let bytes: Vec<_> = (0..MAX_TOOLCHAIN_CHUNK * 2)
        .map(|value| (value % 239) as u8)
        .collect();
    let (_owner, sdk) = fixture(&[("a", &bytes, false)]);
    let root = private();
    stop_with_prefix(root.path(), &sdk, bytes.len() as u64, MAX_TOOLCHAIN_CHUNK);
    let path = object(root.path(), &sdk.files().unwrap()[0]);
    // Model the filesystem image left by an interrupted append: it contains
    // fewer actual bytes than the prior transfer's acknowledged chunk cursor.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let shortened = MAX_TOOLCHAIN_CHUNK as u64 - 23;
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(shortened)
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let mut resumed =
        prefix_task(ToolchainFileCache::open(root.path(), bytes.len() as u64).unwrap());
    begin(&mut resumed, &sdk);
    let selected = negotiate_prefixes(&mut resumed, &sdk);
    assert_eq!(selected["a"].0, shortened);
    assert_eq!(
        upload_prefixes(&mut resumed, &sdk, &selected),
        bytes.len() as u64 - shortened
    );
}

#[test]
fn toolchain_prefix_manifest_reply_is_bounded_and_omitted_hints_cannot_be_selected() {
    let directory = format!(
        "{}/{}/{}",
        "d".repeat(230),
        "e".repeat(230),
        "f".repeat(230)
    );
    let names: Vec<_> = (0..180)
        .map(|index| format!("{directory}/{index:04}{}", "x".repeat(220)))
        .collect();
    let bodies: Vec<_> = (0..names.len())
        .map(|index| format!("prefix-{index:04}-tail").into_bytes())
        .collect();
    let inputs: Vec<_> = names
        .iter()
        .zip(&bodies)
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice(), false))
        .collect();
    let (_owner, sdk) = fixture(&inputs);
    let root = private();
    let cache = ToolchainFileCache::open(root.path(), sdk.identity().bytes).unwrap();
    let files = sdk.files().unwrap();
    for file in &files {
        let path = object(root.path(), file);
        fs::write(&path, b"prefix").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    let mut task = prefix_task(cache);
    begin(&mut task, &sdk);
    let manifest = page(&sdk, 0, &files);
    assert!(serde_json::to_vec(&manifest).unwrap().len() <= MAX_TOOLCHAIN_FILE_PAGE_BYTES);
    let reply = exchange(&mut task, manifest).unwrap();
    assert!(serde_json::to_vec(&reply).unwrap().len() <= MAX_TOOLCHAIN_FILE_PAGE_BYTES);
    assert_eq!(reply["missing"].as_array().unwrap().len(), files.len());
    let offers = reply["prefixes"].as_array().unwrap();
    assert!(!offers.is_empty() && offers.len() < files.len());
    let omitted = files
        .iter()
        .find(|file| !offers.iter().any(|offer| offer["path"] == file.path))
        .unwrap();
    exchange(&mut task, operation(&sdk, "toolchain-file-manifest-seal")).unwrap();
    for entry in sdk.entries().unwrap() {
        if matches!(entry.kind, ToolchainEntryKind::Directory) {
            exchange(&mut task, entry_frame(&sdk, &entry)).unwrap();
        } else if entry.path == omitted.path {
            let mut frame = entry_frame(&sdk, &entry);
            frame["resume"] = json!({"offset":6,"sha256":hex(&Sha256::digest(b"prefix"))});
            assert!(
                exchange(&mut task, frame)
                    .unwrap_err()
                    .contains("owned offer")
            );
            break;
        }
    }
    assert!(task.prepared_path(&request(&sdk), true).is_err());
}

#[test]
fn toolchain_prefix_owned_snapshot_mutation_and_cancel_revoke_the_transfer() {
    let bytes = vec![0x74; MAX_TOOLCHAIN_CHUNK * 2];
    let (_owner, sdk) = fixture(&[("a", &bytes, false)]);
    for cancelled in [false, true] {
        let root = private();
        stop_with_prefix(root.path(), &sdk, bytes.len() as u64, MAX_TOOLCHAIN_CHUNK);
        let mut resumed =
            prefix_task(ToolchainFileCache::open(root.path(), bytes.len() as u64).unwrap());
        begin(&mut resumed, &sdk);
        let selected = negotiate_prefixes(&mut resumed, &sdk);
        if cancelled {
            resumed.cancelled.store(true, Ordering::Release);
        } else {
            let ToolchainBacking::Uploaded(upload) = &mut resumed
                .state
                .as_mut()
                .unwrap()
                .owner
                .as_mut()
                .unwrap()
                .backing
            else {
                panic!("owned upload");
            };
            let snapshots = upload
                .file_reuse
                .as_mut()
                .unwrap()
                .snapshots
                .as_mut()
                .unwrap();
            // The private spool descriptor is never public production state.
            // Test corruption after its advertised hash must fail, not become
            // an offset-zero fallback after the sender has already skipped it.
            snapshots.corrupt_owned_snapshot_for_test();
        }
        for entry in sdk.entries().unwrap() {
            let result = exchange(&mut resumed, prefix_entry(&sdk, &entry, &selected));
            if cancelled || matches!(entry.kind, ToolchainEntryKind::File { .. }) {
                assert!(result.is_err());
                break;
            }
            result.unwrap();
        }
        assert!(resumed.prepared_path(&request(&sdk), true).is_err());
    }
}

#[test]
fn toolchain_prefix_agreement_and_valid_chunk_hashes_never_replace_the_full_sdk_seal() {
    let bytes = b"agreed prefix but exact complete SDK is mandatory";
    let (_owner, sdk) = fixture(&[("a", bytes, false)]);
    let root = private();
    stop_with_prefix(root.path(), &sdk, bytes.len() as u64, 6);
    let cache = ToolchainFileCache::open(root.path(), bytes.len() as u64).unwrap();
    // Contention disables optional complete-file checkpoints, so this reaches
    // the ordinary final tree seal rather than relying on an earlier cache check.
    let writer = cache.writer(&|| false).unwrap().unwrap();
    let mut task = prefix_task(cache);
    begin(&mut task, &sdk);
    let selected = negotiate_prefixes(&mut task, &sdk);
    assert_eq!(selected["a"].0, 6);
    for entry in sdk.entries().unwrap() {
        exchange(&mut task, prefix_entry(&sdk, &entry, &selected)).unwrap();
    }
    let wrong_tail = vec![0x31; bytes.len() - 6];
    let accepted = exchange(&mut task, chunk_frame(&sdk, "a", 6, &wrong_tail)).unwrap();
    assert_eq!(accepted["next_offset"], bytes.len());
    assert!(task.prepared_path(&request(&sdk), true).is_err());
    assert!(exchange(&mut task, operation(&sdk, "toolchain-seal")).is_err());
    assert!(task.prepared_path(&request(&sdk), true).is_err());
    drop(writer);
}

#[test]
fn toolchain_prefix_selection_requires_explicit_version_authenticated_file_reuse() {
    let ack = json!({"kind":"session-ok", "toolchain_prefix_reuse":TOOLCHAIN_PREFIX_REUSE_VERSION})
        .to_string();
    assert!(selected_prefix_reuse(&ack, true, true).unwrap());
    assert!(selected_prefix_reuse(&ack, false, true).is_err());
    assert!(selected_prefix_reuse(&ack, true, false).is_err());
    assert!(!selected_prefix_reuse(r#"{"kind":"session-ok"}"#, true, true).unwrap());
    for value in [
        Value::Null,
        json!(true),
        json!(7),
        json!("toolchain-file-prefix-v2"),
    ] {
        assert!(
            selected_prefix_reuse(
                &json!({"toolchain_prefix_reuse":value}).to_string(),
                true,
                true
            )
            .is_err()
        );
    }
}
