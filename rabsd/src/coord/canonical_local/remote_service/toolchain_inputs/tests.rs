//! Real captured SDKs, receiver files and retained byte objects. No simulated hits.

use super::*;
use rabs_sandbox::toolchain_dataset::{PreparedToolchain, ToolchainLimits, capture_toolchain};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

const ALICE: [u8; 32] = [0x11; 32];
const BOB: [u8; 32] = [0x22; 32];

fn private() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn fixture(
    files: &[(&str, &[u8], bool)],
    link: Option<(&str, &str)>,
) -> (tempfile::TempDir, PreparedToolchain) {
    let owner = private();
    let source = owner.path().join("source");
    fs::create_dir(&source).unwrap();
    for (name, bytes, executable) in files {
        let path = source.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if *executable { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
    if let Some((name, target)) = link {
        symlink(target, source.join(name)).unwrap();
    }
    let sdk = capture_toolchain(
        &source,
        &owner.path().join("retained"),
        None,
        &ToolchainLimits::default(),
        || false,
    )
    .unwrap();
    (owner, sdk)
}

fn receiver(identity: ToolchainIdentity) -> (tempfile::TempDir, ToolchainReceiver) {
    let owner = private();
    let receiver = ToolchainReceiver::create(
        &owner.path().join("received"),
        identity,
        ToolchainLimits::default(),
    )
    .unwrap();
    (owner, receiver)
}

fn prefix_digest(sdk: &PreparedToolchain, path: &str, bytes: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < bytes {
        let chunk = sdk
            .read_chunk(
                path,
                offset,
                (bytes - offset).min(MAX_TOOLCHAIN_CHUNK as u64) as usize,
                || false,
            )
            .unwrap();
        assert!(!chunk.is_empty());
        hash.update(&chunk);
        offset += chunk.len() as u64;
    }
    hash.finalize().into()
}

fn empty_selection() -> ToolchainResume {
    ToolchainResume {
        offset: 0,
        sha256: encode_hex(&Sha256::digest([])),
    }
}

fn negotiate(
    input: &mut ToolchainFileInput,
    sdk: &PreparedToolchain,
) -> (BTreeMap<String, ToolchainResume>, Vec<ToolchainFilePlan>) {
    let mut selections = BTreeMap::new();
    let mut plans = Vec::new();
    // One file per page also exercises ordering and counters across pages.
    for (index, file) in sdk.files().unwrap().iter().enumerate() {
        let page = ToolchainFilePage::from_native(index, std::slice::from_ref(file)).unwrap();
        let plan = input.page(&page, &|| false).unwrap();
        plan.validate(&page).unwrap();
        let selection = if !plan.missing_files.contains(&(index as u32)) {
            ToolchainResume {
                offset: file.bytes,
                sha256: encode_hex(&file.sha256),
            }
        } else if let Some(offer) = plan.prefixes.first()
            && digest(&offer.sha256).unwrap() == prefix_digest(sdk, &file.path, offer.offset)
        {
            ToolchainResume {
                offset: offer.offset,
                sha256: offer.sha256.clone(),
            }
        } else {
            empty_selection()
        };
        selections.insert(file.path.clone(), selection);
        plans.push(plan);
    }
    assert_eq!(
        input.seal_manifest(&|| false).unwrap(),
        (sdk.identity().files, sdk.identity().bytes)
    );
    (selections, plans)
}

fn transfer(
    input: &mut ToolchainFileInput,
    receiver: &mut ToolchainReceiver,
    sdk: &PreparedToolchain,
    selections: &BTreeMap<String, ToolchainResume>,
) -> u64 {
    let mut uploaded = 0;
    for entry in sdk.entries().unwrap() {
        let resume = match entry.kind {
            ToolchainEntryKind::File { .. } => Some(selections[&entry.path].clone()),
            _ => None,
        };
        let path = entry.path.clone();
        let count = match entry.kind {
            ToolchainEntryKind::File { bytes, .. } => Some(bytes),
            _ => None,
        };
        let mut offset = resume.as_ref().map_or(0, |resume| resume.offset);
        input.entry(receiver, entry, resume, &|| false).unwrap();
        if let Some(count) = count {
            while offset < count {
                let chunk = sdk
                    .read_chunk(&path, offset, MAX_TOOLCHAIN_CHUNK, || false)
                    .unwrap();
                assert!(!chunk.is_empty());
                input
                    .write_chunk(
                        receiver,
                        &path,
                        offset,
                        &chunk,
                        Sha256::digest(&chunk).into(),
                        &|| false,
                    )
                    .unwrap();
                offset += chunk.len() as u64;
                uploaded += chunk.len() as u64;
            }
        }
    }
    uploaded
}

fn complete(
    cache: &RemoteToolchainFileCache,
    peer: [u8; 32],
    sdk: &PreparedToolchain,
) -> (u64, Vec<ToolchainFilePlan>) {
    let mut input = cache.for_peer(peer, *sdk.identity(), &|| false).unwrap();
    let (_owner, mut received) = receiver(*sdk.identity());
    let (selections, plans) = negotiate(&mut input, sdk);
    let uploaded = transfer(&mut input, &mut received, sdk, &selections);
    input.finish(&|| false).unwrap();
    let sealed = received.seal(|| false).unwrap();
    sealed.verify(|| false).unwrap();
    assert_eq!(sealed.identity(), sdk.identity());
    (uploaded, plans)
}

fn interrupt_with_prefix(
    cache: &RemoteToolchainFileCache,
    sdk: &PreparedToolchain,
    bytes: u64,
    cancelled: bool,
) {
    let mut input = cache.for_peer(ALICE, *sdk.identity(), &|| false).unwrap();
    let (_owner, mut received) = receiver(*sdk.identity());
    let (selections, _) = negotiate(&mut input, sdk);
    let files = sdk.files().unwrap();
    assert_eq!(files.len(), 1);
    let file = &files[0];
    assert!(bytes != 0 && bytes < file.bytes);
    for entry in sdk.entries().unwrap() {
        let selected = matches!(entry.kind, ToolchainEntryKind::File { .. });
        input
            .entry(
                &mut received,
                entry,
                selected.then(|| selections[&file.path].clone()),
                &|| false,
            )
            .unwrap();
    }
    let mut offset = 0;
    while offset < bytes {
        let chunk = sdk
            .read_chunk(
                &file.path,
                offset,
                (bytes - offset).min(MAX_TOOLCHAIN_CHUNK as u64) as usize,
                || false,
            )
            .unwrap();
        input
            .write_chunk(
                &mut received,
                &file.path,
                offset,
                &chunk,
                Sha256::digest(&chunk).into(),
                &|| false,
            )
            .unwrap();
        offset += chunk.len() as u64;
    }
    if cancelled {
        assert_eq!(
            input.finish(&|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(
            input.finish(&|| false).is_err(),
            "a cancelled input remains poisoned"
        );
    }
    // An interrupted network owner drops both objects without a complete SDK seal.
}

fn cached_objects(cache: &RemoteToolchainFileCache) -> Vec<PathBuf> {
    fs::read_dir(cache.owner.path().join("toolchain-files-v1"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sdk"))
        .collect()
}

fn durable_cache(parent: &Path, max_bytes: u64) -> RemoteToolchainFileCache {
    RemoteToolchainFileCache::with_storage(
        Arc::new(InputCacheStorage::persistent(parent).unwrap()),
        max_bytes,
    )
    .unwrap()
}

#[test]
fn service_restart_reuses_sdk_files_and_prefixes_but_seals_a_fresh_image() {
    let bytes = vec![0x37; MAX_TOOLCHAIN_CHUNK * 2 + 29];
    let (_owner, sdk) = fixture(&[("bin/compiler", &bytes, true)], None);
    let parent = private();
    let cache = durable_cache(parent.path(), sdk.identity().bytes * 2);
    let prefix = MAX_TOOLCHAIN_CHUNK as u64 + 17;
    interrupt_with_prefix(&cache, &sdk, prefix, false);
    drop(cache);

    let reopened = durable_cache(parent.path(), sdk.identity().bytes * 2);
    let (uploaded, plans) = complete(&reopened, ALICE, &sdk);
    assert_eq!(uploaded, sdk.identity().bytes - prefix);
    assert_eq!(plans[0].prefixes[0].offset, prefix);
    drop(reopened);

    let reopened = durable_cache(parent.path(), sdk.identity().bytes * 2);
    let (uploaded, plans) = complete(&reopened, ALICE, &sdk);
    assert_eq!(uploaded, 0);
    assert!(plans.iter().all(|plan| plan.missing_files.is_empty()));
    let (_linked_owner, linked) = fixture(
        &[("bin/compiler", &bytes, true)],
        Some(("compiler", "bin/compiler")),
    );
    assert_ne!(linked.identity(), sdk.identity());
    assert_eq!(complete(&reopened, ALICE, &linked).0, 0);
    let (foreign, plans) = complete(&reopened, BOB, &sdk);
    assert_eq!(foreign, sdk.identity().bytes);
    assert!(plans.iter().all(|plan| plan.prefixes.is_empty()));
}

#[test]
fn restarted_sdk_storage_reuses_unchanged_members_across_images_and_rejects_corruption() {
    let compiler = b"retained compiler bytes";
    let (_owner, sdk) = fixture(&[("bin/compiler", compiler, true)], None);
    let parent = private();
    let cache = durable_cache(parent.path(), 1024);
    assert_eq!(complete(&cache, ALICE, &sdk).0, compiler.len() as u64);
    drop(cache);

    let (_changed_owner, changed) = fixture(
        &[
            ("bin/compiler", compiler, true),
            ("lib/new", b"new library", false),
        ],
        None,
    );
    let reopened = durable_cache(parent.path(), 1024);
    assert_ne!(sdk.identity(), changed.identity());
    assert_eq!(complete(&reopened, ALICE, &changed).0, 11);
    let objects = cached_objects(&reopened);
    drop(reopened);
    for object in objects {
        fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
        let mut bytes = fs::read(&object).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&object, bytes).unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o400)).unwrap();
    }
    let reopened = durable_cache(parent.path(), 1024);
    assert_eq!(
        complete(&reopened, ALICE, &changed).0,
        changed.identity().bytes
    );
}

fn corrupt_retained_prefix(cache: &RemoteToolchainFileCache) {
    let objects = cached_objects(cache);
    assert_eq!(objects.len(), 1);
    let path = &objects[0];
    let mut bytes = fs::read(path).unwrap();
    assert!(!bytes.is_empty());
    bytes[0] ^= 0xff;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, &bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

#[test]
fn interrupted_sdk_upload_resumes_a_verified_multi_chunk_prefix() {
    let bytes = vec![0x37; MAX_TOOLCHAIN_CHUNK * 3 + 29];
    let (_owner, sdk) = fixture(&[("bin/compiler", &bytes, true)], None);
    let prefix = MAX_TOOLCHAIN_CHUNK as u64 + 17;
    for cancelled in [false, true] {
        let root = private();
        let cache = RemoteToolchainFileCache::new(root.path(), sdk.identity().bytes).unwrap();
        interrupt_with_prefix(&cache, &sdk, prefix, cancelled);
        let objects = cached_objects(&cache);
        assert_eq!(objects.len(), 1);
        assert_eq!(fs::read(&objects[0]).unwrap(), bytes[..prefix as usize]);
        let (uploaded, plans) = complete(&cache, ALICE, &sdk);
        assert_eq!(uploaded, sdk.identity().bytes - prefix);
        assert_eq!(plans[0].missing_files, vec![0]);
        assert_eq!(plans[0].prefixes.len(), 1);
        assert_eq!(plans[0].prefixes[0].offset, prefix);
        assert_eq!(
            plans[0].prefixes[0].sha256,
            encode_hex(&Sha256::digest(&bytes[..prefix as usize]))
        );
        let (again, plans) = complete(&cache, ALICE, &sdk);
        assert_eq!(again, 0);
        assert!(plans[0].missing_files.is_empty());
        assert!(plans[0].prefixes.is_empty());
    }
}

#[test]
fn completed_files_reuse_across_sdk_identities_and_paths_only_for_the_same_peer() {
    let compiler = vec![0x67; MAX_TOOLCHAIN_CHUNK + 31];
    let (_first_owner, first) = fixture(
        &[
            ("bin/compiler", &compiler, true),
            ("lib/version", b"first", false),
        ],
        None,
    );
    let (_second_owner, second) = fixture(
        &[
            ("bin/compiler-new", &compiler, true),
            ("lib/version", b"second", false),
            ("marker", b"", false),
        ],
        None,
    );
    assert_ne!(first.identity(), second.identity());
    let root = private();
    let cache = RemoteToolchainFileCache::new(root.path(), second.identity().bytes * 3).unwrap();
    assert_eq!(complete(&cache, ALICE, &first).0, first.identity().bytes);
    let (uploaded, plans) = complete(&cache, ALICE, &second);
    assert_eq!(uploaded, second.identity().bytes - compiler.len() as u64);
    assert!(plans[0].missing_files.is_empty());
    assert_eq!(plans[1].missing_files, vec![1]);
    assert!(
        plans[2].missing_files.is_empty(),
        "empty files still require ordinary image validation"
    );
    let (other_peer_uploaded, plans) = complete(&cache, BOB, &second);
    assert_eq!(other_peer_uploaded, second.identity().bytes);
    assert_eq!(plans[0].missing_files, vec![0]);
    assert_eq!(plans[1].missing_files, vec![1]);
    assert!(plans.iter().all(|plan| plan.prefixes.is_empty()));
}

#[test]
fn corrupt_prefix_retransfers_and_advertised_snapshots_remain_independent() {
    let bytes = vec![0x56; MAX_TOOLCHAIN_CHUNK * 2 + 41];
    let (_owner, sdk) = fixture(&[("bin/compiler", &bytes, true)], None);
    let prefix = MAX_TOOLCHAIN_CHUNK as u64 + 9;
    for before_negotiation in [true, false] {
        let root = private();
        let cache = RemoteToolchainFileCache::new(root.path(), sdk.identity().bytes).unwrap();
        interrupt_with_prefix(&cache, &sdk, prefix, false);
        if before_negotiation {
            corrupt_retained_prefix(&cache);
        }
        let mut input = cache.for_peer(ALICE, *sdk.identity(), &|| false).unwrap();
        let (_received_owner, mut received) = receiver(*sdk.identity());
        let (selections, plans) = negotiate(&mut input, &sdk);
        assert_eq!(plans[0].prefixes[0].offset, prefix);
        if before_negotiation {
            assert_ne!(
                plans[0].prefixes[0].sha256,
                encode_hex(&prefix_digest(&sdk, "bin/compiler", prefix))
            );
            assert_eq!(selections["bin/compiler"].offset, 0);
        } else {
            assert_eq!(selections["bin/compiler"].offset, prefix);
            corrupt_retained_prefix(&cache);
        }
        let uploaded = transfer(&mut input, &mut received, &sdk, &selections);
        assert_eq!(
            uploaded,
            if before_negotiation {
                sdk.identity().bytes
            } else {
                sdk.identity().bytes - prefix
            }
        );
        input.finish(&|| false).unwrap();
        received.seal(|| false).unwrap().verify(|| false).unwrap();
    }
}

#[test]
fn unoffered_offsets_hashes_modes_and_missing_selections_poison_the_input() {
    let bytes = vec![0x29; MAX_TOOLCHAIN_CHUNK * 2 + 37];
    let (_owner, sdk) = fixture(&[("bin/compiler", &bytes, true)], None);
    let root = private();
    let cache = RemoteToolchainFileCache::new(root.path(), sdk.identity().bytes).unwrap();
    interrupt_with_prefix(&cache, &sdk, MAX_TOOLCHAIN_CHUNK as u64 + 9, false);
    for fault in 0..5 {
        let mut input = cache.for_peer(ALICE, *sdk.identity(), &|| false).unwrap();
        let (_received_owner, mut received) = receiver(*sdk.identity());
        let (selections, _) = negotiate(&mut input, &sdk);
        let mut refused = false;
        for mut entry in sdk.entries().unwrap() {
            if fault == 4 && matches!(entry.kind, ToolchainEntryKind::Directory) {
                assert!(
                    input
                        .entry(&mut received, entry, Some(empty_selection()), &|| false)
                        .is_err()
                );
                refused = true;
                break;
            }
            if let ToolchainEntryKind::File { executable, .. } = &mut entry.kind {
                let mut resume = Some(selections[&entry.path].clone());
                match fault {
                    0 => resume.as_mut().unwrap().offset += 1,
                    1 => resume.as_mut().unwrap().sha256 = encode_hex(&[0x91; 32]),
                    2 => *executable = !*executable,
                    3 => resume = None,
                    _ => unreachable!(),
                }
                assert!(
                    input
                        .entry(&mut received, entry.clone(), resume, &|| false)
                        .is_err()
                );
                assert!(
                    input
                        .entry(
                            &mut received,
                            entry,
                            Some(selections["bin/compiler"].clone()),
                            &|| false
                        )
                        .is_err()
                );
                refused = true;
                break;
            }
            input.entry(&mut received, entry, None, &|| false).unwrap();
        }
        assert!(refused);
        assert!(
            !input.can_decline(),
            "failed negotiation cannot downgrade to an ordinary upload"
        );
        assert!(input.finish(&|| false).is_err());
        assert!(received.seal(|| false).is_err());
    }
}

#[test]
fn cached_file_bytes_cannot_replace_the_final_complete_sdk_namespace_identity() {
    let compiler = b"same compiler bytes, different SDK link topology";
    let files = [
        ("bin/compiler", compiler.as_slice(), true),
        ("bin/other", compiler.as_slice(), true),
    ];
    let (_first_owner, first) = fixture(&files, Some(("current", "bin/compiler")));
    let (_second_owner, second) = fixture(&files, Some(("current", "bin/other")));
    assert_ne!(first.identity().sha256, second.identity().sha256);
    assert_eq!(first.identity().files, second.identity().files);
    assert_eq!(first.identity().bytes, second.identity().bytes);
    let root = private();
    let cache = RemoteToolchainFileCache::new(root.path(), first.identity().bytes * 2).unwrap();
    complete(&cache, ALICE, &first);

    let mut input = cache.for_peer(ALICE, *first.identity(), &|| false).unwrap();
    let (_received_owner, mut received) = receiver(*first.identity());
    let (selections, plans) = negotiate(&mut input, &second);
    assert!(plans.iter().all(|plan| plan.missing_files.is_empty()));
    assert_eq!(transfer(&mut input, &mut received, &second, &selections), 0);
    input.finish(&|| false).unwrap();
    assert!(
        received.seal(|| false).is_err(),
        "matching file hints cannot authorize a different symlink namespace"
    );
}

#[test]
fn stalled_cache_notice_preserves_verified_sdk_handoff_and_invalid_inventory_refusal() {
    crate::controlled_output::with_stalled_stderr(
        concat!(
            module_path!(),
            "::stalled_cache_notice_preserves_verified_sdk_handoff_and_invalid_inventory_refusal"
        ),
        || {
            let (_owner, sdk) =
                fixture(&[("bin/compiler", b"verified compiler bytes", true)], None);
            let root = private();
            let cache = RemoteToolchainFileCache::new(root.path(), sdk.identity().bytes).unwrap();
            let unexpected = cache.owner.path().join("toolchain-files-v1/foreign-entry");
            fs::write(&unexpected, b"unrecognized optional storage").unwrap();

            // Real inventory refusal disables the optional writer, while the
            // ordinary receiver still seals and verifies the complete SDK.
            // Its warning must not hold the operation behind the log sink.
            let (uploaded, plans) = complete(&cache, ALICE, &sdk);
            assert_eq!(uploaded, sdk.identity().bytes);
            assert_eq!(plans[0].missing_files, vec![0]);
            assert!(plans[0].prefixes.is_empty());
            assert_eq!(
                fs::read(&unexpected).unwrap(),
                b"unrecognized optional storage"
            );
            assert!(cached_objects(&cache).is_empty());

            // The same cache failure grants no relaxation to the required
            // input contract. A file count/length mismatch remains terminal.
            let mut input = cache.for_peer(ALICE, *sdk.identity(), &|| false).unwrap();
            let mut files = sdk.files().unwrap();
            files[0].bytes += 1;
            let page = ToolchainFilePage::from_native(0, &files).unwrap();
            assert!(input.page(&page, &|| false).is_err());
            assert!(!input.can_decline());
            assert!(input.finish(&|| false).is_err());
        },
    );
}

#[test]
fn one_global_cache_budget_bounds_peer_churn_without_reducing_sdk_validation() {
    let bytes = vec![0x48; MAX_TOOLCHAIN_CHUNK * 3 + 19];
    let (_owner, sdk) = fixture(&[("bin/compiler", &bytes, true)], None);
    let root = private();
    let budget = MAX_TOOLCHAIN_CHUNK as u64 + 7;
    let cache = RemoteToolchainFileCache::new(root.path(), budget).unwrap();
    for peer in [ALICE, BOB, [0x33; 32]] {
        let (uploaded, plans) = complete(&cache, peer, &sdk);
        assert_eq!(uploaded, sdk.identity().bytes);
        assert_eq!(plans[0].missing_files, vec![0]);
        assert!(plans[0].prefixes.is_empty());
        let objects = cached_objects(&cache);
        let retained: u64 = objects
            .iter()
            .map(|path| fs::metadata(path).unwrap().len())
            .sum();
        assert_eq!(objects.len(), 1);
        assert_eq!(retained, MAX_TOOLCHAIN_CHUNK as u64);
        assert!(retained <= budget);
    }
    let mut evicted = cache.for_peer(ALICE, *sdk.identity(), &|| false).unwrap();
    let (_, plans) = negotiate(&mut evicted, &sdk);
    assert_eq!(plans[0].missing_files, vec![0]);
    assert!(plans[0].prefixes.is_empty());
}

#[test]
fn inventory_count_byte_totals_order_and_cancellation_remain_mandatory() {
    let (_owner, sdk) = fixture(&[("compiler", b"compiler bytes", true)], None);
    let root = private();
    let cache = RemoteToolchainFileCache::new(root.path(), sdk.identity().bytes).unwrap();
    let files = sdk.files().unwrap();
    for fault in 0..5 {
        let mut input = cache.for_peer(ALICE, *sdk.identity(), &|| false).unwrap();
        let page = ToolchainFilePage::from_native(0, &files).unwrap();
        match fault {
            0 => assert!(input.seal_manifest(&|| false).is_err()),
            1 => {
                let mut changed = files.clone();
                changed[0].bytes += 1;
                let oversized = ToolchainFilePage::from_native(0, &changed).unwrap();
                assert!(input.page(&oversized, &|| false).is_err());
            }
            2 => {
                let skipped = ToolchainFilePage::from_native(1, &files).unwrap();
                assert!(input.page(&skipped, &|| false).is_err());
            }
            3 => {
                input.page(&page, &|| false).unwrap();
                assert!(input.page(&page, &|| false).is_err());
            }
            _ => assert_eq!(
                input.page(&page, &|| true).unwrap_err().kind(),
                io::ErrorKind::Interrupted
            ),
        }
        assert!(input.page(&page, &|| false).is_err());
        assert!(input.seal_manifest(&|| false).is_err());
        assert!(!input.can_decline());
    }
}
