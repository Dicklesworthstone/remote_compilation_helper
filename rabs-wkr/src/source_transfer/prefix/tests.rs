use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn private() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn manifest(bytes: &[u8]) -> Value {
    let file = SourceFile {
        path: "dependencies/library.rlib".to_owned(),
        len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
        executable: false,
    };
    let manifest = SourceManifest::new(vec![file.clone()]).unwrap();
    json!({"manifest_sha256":hex(&manifest.digest()), "files":[{
        "path":file.path, "bytes":file.len, "sha256":hex(&file.sha256), "executable":false,
    }]})
}

fn state(root: &Path, budget: u64) -> SourceTransferState {
    SourceTransferState::default()
        .with_cache(Some(SourceCache::open_byte_only(root, budget).unwrap()))
}

fn begin(state: &mut SourceTransferState, manifest: &Value, prefixes: bool) -> Value {
    let mut frame = json!({"kind":"source-begin", "request_id":17, "manifest":manifest,
        "allow_cached_files":true});
    if prefixes {
        frame["source_prefix_reuse"] = json!(SOURCE_PREFIX_REUSE_VERSION);
    }
    state.handle(&frame, true, false).unwrap()
}

fn zero() -> SourcePrefix {
    SourcePrefix {
        offset: 0,
        sha256: Sha256::digest([]).into(),
    }
}

fn chunk(manifest: &Value, offset: u64, bytes: &[u8], selected: Option<SourcePrefix>) -> Value {
    let mut frame = json!({"kind":"source-chunk", "request_id":17,
        "manifest_sha256":manifest["manifest_sha256"], "path":"dependencies/library.rlib",
        "offset":offset, "data_hex":hex(bytes), "chunk_sha256":hex(&Sha256::digest(bytes))});
    if let Some(selected) = selected {
        frame["resume"] = json!({"offset":selected.offset, "sha256":hex(&selected.sha256)});
    }
    frame
}

fn offer(ready: &Value) -> SourcePrefix {
    assert_eq!(ready["source_prefix_reuse"], SOURCE_PREFIX_REUSE_VERSION);
    let rows = ready["prefixes"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["path"], "dependencies/library.rlib");
    SourcePrefix {
        offset: rows[0]["offset"].as_u64().unwrap(),
        sha256: digest(&rows[0]["sha256"]).unwrap(),
    }
}

fn seal(state: &mut SourceTransferState, manifest: &Value) -> Result<Value, String> {
    state.handle(
        &json!({"kind":"source-seal", "request_id":17,
        "manifest_sha256":manifest["manifest_sha256"]}),
        true,
        false,
    )
}

fn finish(
    state: &mut SourceTransferState,
    manifest: &Value,
    bytes: &[u8],
    selected: SourcePrefix,
) -> u64 {
    let mut offset = selected.offset;
    let mut first = true;
    while offset < bytes.len() as u64 {
        let end = (offset as usize + MAX_SOURCE_CHUNK).min(bytes.len());
        let reply = state
            .handle(
                &chunk(
                    manifest,
                    offset,
                    &bytes[offset as usize..end],
                    first.then_some(selected),
                ),
                true,
                false,
            )
            .unwrap();
        assert_eq!(reply["next_offset"], end);
        offset = end as u64;
        first = false;
    }
    assert!(
        state
            .prepared_path(
                &json!({"kind":"canonical-exec", "request_id":17,
        "source_manifest":manifest}),
                true
            )
            .is_err()
    );
    let sealed = seal(state, manifest).unwrap();
    assert_eq!(sealed["sealed"], true);
    assert_eq!(sealed["source_reused_bytes"], selected.offset);
    let path = state
        .prepared_path(
            &json!({"kind":"canonical-exec", "request_id":17,
        "source_manifest":manifest}),
            true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::read(Path::new(&path).join("dependencies/library.rlib")).unwrap(),
        bytes
    );
    offset - selected.offset
}

fn interrupted(root: &Path, bytes: &[u8], prefix_bytes: usize) -> Value {
    let manifest = manifest(bytes);
    let mut upload = state(root, bytes.len() as u64);
    let ready = begin(&mut upload, &manifest, true);
    assert_eq!(ready["prefixes"], json!([]));
    for (index, bytes) in bytes[..prefix_bytes].chunks(MAX_SOURCE_CHUNK).enumerate() {
        let offset = (index * MAX_SOURCE_CHUNK) as u64;
        let reply = upload
            .handle(
                &chunk(&manifest, offset, bytes, (index == 0).then_some(zero())),
                true,
                false,
            )
            .unwrap();
        assert_eq!(reply["next_offset"], offset + bytes.len() as u64);
    }
    assert!(
        upload
            .prepared_path(
                &json!({"kind":"canonical-exec", "request_id":17,
                "source_manifest":manifest}),
                true,
            )
            .is_err()
    );
    // Disconnect drops the incomplete source tree without a source seal. Its
    // independently retained input prefix may still help a fresh request.
    drop(upload);
    manifest
}

fn object(root: &Path, bytes: &[u8]) -> PathBuf {
    root.join("source-files-v1")
        .join(format!("{}.src", hex(&Sha256::digest(bytes))))
}

#[test]
fn source_prefix_reconnect_sends_only_unaligned_tail_and_still_requires_complete_seal() {
    let root = private();
    let bytes: Vec<_> = (0..MAX_SOURCE_CHUNK * 3 + 37)
        .map(|index| (index % 251) as u8)
        .collect();
    let prefix = MAX_SOURCE_CHUNK + 13;
    let manifest = interrupted(root.path(), &bytes, prefix);
    let mut resumed = state(root.path(), bytes.len() as u64);
    let selected = offer(&begin(&mut resumed, &manifest, true));
    assert_eq!(selected.offset, prefix as u64);
    assert_eq!(
        selected.sha256,
        <[u8; 32]>::from(Sha256::digest(&bytes[..prefix]))
    );
    assert_eq!(
        finish(&mut resumed, &manifest, &bytes, selected),
        (bytes.len() - prefix) as u64
    );
    drop(resumed);

    let mut warm = state(root.path(), bytes.len() as u64);
    let ready = begin(&mut warm, &manifest, true);
    assert_eq!(ready["missing_files"], json!([]));
    assert_eq!(ready["prefixes"], json!([]));
    assert_eq!(ready["source_reused_bytes"], bytes.len());
    assert_eq!(ready["sealed"], false);
    assert_eq!(seal(&mut warm, &manifest).unwrap()["sealed"], true);
}

#[test]
fn source_prefix_corruption_can_select_zero_and_named_changes_cannot_mutate_owned_offers() {
    for mutate_before_offer in [false, true] {
        let root = private();
        let bytes = vec![0x49; MAX_SOURCE_CHUNK * 2 + 29];
        let prefix = MAX_SOURCE_CHUNK + 7;
        let manifest = interrupted(root.path(), &bytes, prefix);
        let path = object(root.path(), &bytes);
        let corrupt = || {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&path, vec![0x91; prefix]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        };
        if mutate_before_offer {
            corrupt();
        }
        let mut resumed = state(root.path(), bytes.len() as u64);
        let offered = offer(&begin(&mut resumed, &manifest, true));
        let selected = if mutate_before_offer {
            assert_ne!(
                offered.sha256,
                <[u8; 32]>::from(Sha256::digest(&bytes[..prefix]))
            );
            zero()
        } else {
            corrupt();
            offered
        };
        assert_eq!(
            finish(&mut resumed, &manifest, &bytes, selected),
            bytes.len() as u64 - selected.offset
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn source_prefix_reselection_forgery_and_missing_selection_never_publish_a_source() {
    for fault in 0..6 {
        let root = private();
        let bytes = vec![0x64; MAX_SOURCE_CHUNK * 3 + 31];
        let manifest = interrupted(root.path(), &bytes, MAX_SOURCE_CHUNK);
        let mut resumed = state(root.path(), bytes.len() as u64);
        let selected = offer(&begin(&mut resumed, &manifest, true));
        let tail = &bytes[selected.offset as usize..selected.offset as usize + MAX_SOURCE_CHUNK];
        let valid = chunk(&manifest, selected.offset, tail, Some(selected));
        let mut invalid = valid.clone();
        match fault {
            0 => {
                invalid.as_object_mut().unwrap().remove("resume");
            }
            1 => {
                invalid["resume"]["sha256"] = json!("00".repeat(32));
            }
            2 => {
                invalid["resume"]["offset"] = json!(bytes.len());
            }
            3 => {
                invalid["offset"] = json!(0);
            }
            4 => {
                resumed.handle(&valid, true, false).unwrap();
                invalid["resume"] = json!({"offset":0,"sha256":hex(&zero().sha256)});
                invalid["offset"] = json!(0);
            }
            _ => {
                resumed.handle(&valid, true, false).unwrap();
                invalid = chunk(&manifest, selected.offset, &tail[..17], Some(selected));
            }
        }
        assert!(
            resumed.handle(&invalid, true, false).is_err(),
            "fault {fault}"
        );
        assert!(seal(&mut resumed, &manifest).is_err(), "fault {fault}");
        assert!(
            resumed.handle(&valid, true, false).is_err(),
            "a failed owner cannot reselect"
        );
    }
}

#[test]
fn source_prefix_exact_first_chunk_retry_does_not_import_or_charge_twice() {
    let root = private();
    let bytes = vec![0x72; MAX_SOURCE_CHUNK * 3 + 17];
    let manifest = interrupted(root.path(), &bytes, MAX_SOURCE_CHUNK + 3);
    let mut resumed = state(root.path(), bytes.len() as u64);
    let selected = offer(&begin(&mut resumed, &manifest, true));
    let next = selected.offset as usize + MAX_SOURCE_CHUNK;
    let first = chunk(
        &manifest,
        selected.offset,
        &bytes[selected.offset as usize..next],
        Some(selected),
    );
    assert_eq!(
        resumed.handle(&first, true, false).unwrap()["next_offset"],
        next
    );
    let retained = fs::metadata(object(root.path(), &bytes)).unwrap().len();
    assert_eq!(
        resumed.handle(&first, true, false).unwrap()["next_offset"],
        next
    );
    assert_eq!(
        fs::metadata(object(root.path(), &bytes)).unwrap().len(),
        retained
    );
    for (index, part) in bytes[next..].chunks(MAX_SOURCE_CHUNK).enumerate() {
        let offset = (next + index * MAX_SOURCE_CHUNK) as u64;
        resumed
            .handle(&chunk(&manifest, offset, part, None), true, false)
            .unwrap();
    }
    let sealed = seal(&mut resumed, &manifest).unwrap();
    assert_eq!(sealed["sealed"], true);
    assert_eq!(sealed["source_reused_bytes"], selected.offset);
}

#[test]
fn source_prefix_negotiation_preserves_legacy_and_explicit_cache_opt_out() {
    let root = private();
    let bytes = vec![0x38; MAX_SOURCE_CHUNK + 5];
    let manifest = manifest(&bytes);
    let mut legacy = state(root.path(), bytes.len() as u64);
    let ready = begin(&mut legacy, &manifest, false);
    assert!(ready.get("source_prefix_reuse").is_none());
    assert!(ready.get("prefixes").is_none());
    legacy
        .handle(
            &chunk(&manifest, 0, &bytes[..MAX_SOURCE_CHUNK], None),
            true,
            false,
        )
        .unwrap();
    drop(legacy);
    assert!(
        !object(root.path(), &bytes).exists(),
        "legacy incomplete files stay cold"
    );

    let mut disabled = state(root.path(), bytes.len() as u64);
    let request = json!({"kind":"source-begin", "request_id":17, "manifest":manifest,
        "allow_cached_files":false, "source_prefix_reuse":SOURCE_PREFIX_REUSE_VERSION});
    assert!(disabled.handle(&request, true, false).is_err());
    let mut unknown = request.clone();
    unknown["allow_cached_files"] = json!(true);
    unknown["source_prefix_reuse"] = json!("source-file-prefix-v999");
    assert!(disabled.handle(&unknown, true, false).is_err());
    begin(&mut disabled, &manifest, false);
    assert!(
        disabled
            .handle(
                &chunk(&manifest, 0, &bytes[..MAX_SOURCE_CHUNK], Some(zero())),
                true,
                false
            )
            .is_err()
    );
    assert!(!object(root.path(), &bytes).exists());
}

#[test]
fn agreed_source_prefix_and_chunk_hashes_cannot_replace_the_full_file_digest() {
    let root = private();
    let bytes = vec![0x18; MAX_SOURCE_CHUNK + 19];
    let manifest = interrupted(root.path(), &bytes, MAX_SOURCE_CHUNK);
    let mut resumed = state(root.path(), bytes.len() as u64);
    let selected = offer(&begin(&mut resumed, &manifest, true));
    let corrupt_tail = vec![0x87; 19];
    assert!(
        resumed
            .handle(
                &chunk(&manifest, selected.offset, &corrupt_tail, Some(selected)),
                true,
                false
            )
            .is_err()
    );
    assert!(seal(&mut resumed, &manifest).is_err());
    assert!(
        resumed
            .prepared_path(
                &json!({"kind":"canonical-exec", "request_id":17,
        "source_manifest":manifest}),
                true
            )
            .is_err()
    );
}

#[test]
fn source_prefix_empty_files_need_no_selection_and_cancellation_never_acknowledges_tail() {
    let root = private();
    let empty = manifest(&[]);
    let mut upload = state(root.path(), 1024);
    let ready = begin(&mut upload, &empty, true);
    assert_eq!(ready["missing_files"], json!([]));
    assert_eq!(ready["prefixes"], json!([]));
    assert_eq!(seal(&mut upload, &empty).unwrap()["sealed"], true);
    drop(upload);

    let bytes = vec![0x14; MAX_SOURCE_CHUNK + 11];
    let manifest = interrupted(root.path(), &bytes, MAX_SOURCE_CHUNK);
    let mut resumed = state(root.path(), bytes.len() as u64);
    let selected = offer(&begin(&mut resumed, &manifest, true));
    resumed.cancellation_flag().store(true, Ordering::Release);
    assert!(
        resumed
            .handle(
                &chunk(
                    &manifest,
                    selected.offset,
                    &bytes[MAX_SOURCE_CHUNK..],
                    Some(selected)
                ),
                true,
                false
            )
            .is_err()
    );
    assert!(seal(&mut resumed, &manifest).is_err());
    assert_eq!(
        fs::metadata(object(root.path(), &bytes)).unwrap().len(),
        selected.offset
    );
}

#[test]
fn interleaved_source_files_preserve_one_writer_and_finish_under_a_one_file_budget() {
    let root = private();
    let files = [("a", b"aaaa"), ("b", b"bbbb")];
    let declared = SourceManifest::new(
        files
            .iter()
            .map(|(path, bytes)| SourceFile {
                path: (*path).to_owned(),
                len: bytes.len() as u64,
                sha256: Sha256::digest(bytes).into(),
                executable: false,
            })
            .collect(),
    )
    .unwrap();
    let manifest = json!({"manifest_sha256":hex(&declared.digest()), "files":
        declared.files().iter().map(|file| json!({"path":file.path,
            "bytes":file.len,"sha256":hex(&file.sha256),"executable":false})).collect::<Vec<_>>()});
    let mut upload = state(root.path(), 4);
    let ready = begin(&mut upload, &manifest, true);
    assert_eq!(ready["missing_files"], json!(["a", "b"]));
    for (path, offset, bytes) in [
        ("a", 0, b"aa"),
        ("b", 0, b"bb"),
        ("a", 2, b"aa"),
        ("b", 2, b"bb"),
    ] {
        let mut frame = chunk(&manifest, offset, bytes, (offset == 0).then_some(zero()));
        frame["path"] = json!(path);
        assert_eq!(
            upload.handle(&frame, true, false).unwrap()["next_offset"],
            offset + 2
        );
        assert!(!root.path().join("source-files-v1/incoming").exists());
        let retained: u64 = fs::read_dir(root.path().join("source-files-v1"))
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum();
        assert!(retained <= 4);
    }
    let sealed = seal(&mut upload, &manifest).unwrap();
    assert_eq!(sealed["sealed"], true);
    assert!(sealed["cache_write_error"].is_null());
    let source = upload
        .prepared_path(
            &json!({"kind":"canonical-exec", "request_id":17,
        "source_manifest":manifest}),
            true,
        )
        .unwrap()
        .unwrap();
    for (path, bytes) in files {
        assert_eq!(fs::read(Path::new(&source).join(path)).unwrap(), bytes);
    }
}
