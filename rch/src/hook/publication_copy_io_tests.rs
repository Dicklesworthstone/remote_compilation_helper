//! Faults at the real preparation durability boundary, not a model publisher.
use super::*;
use std::path::PathBuf;

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    temporary: PathBuf,
    destination: PathBuf,
    bytes: Vec<u8>,
    hash: String,
}

impl Fixture {
    fn new(length: usize, mode: u32) -> Self {
        let root = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap()
            .keep();
        let source = root.join("stage");
        let temporary = root.join(".rch-return-io-test");
        let destination = root.join("output");
        let bytes: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        std::fs::write(&source, &bytes).unwrap();
        std::fs::set_permissions(&source, Permissions::from_mode(mode)).unwrap();
        std::fs::write(&destination, b"prior caller output").unwrap();
        Self {
            root,
            source,
            temporary,
            destination,
            bytes,
            hash,
        }
    }

    fn retain(&self, length: usize) {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(COPY_MODE)
            .open(&self.temporary)
            .unwrap();
        file.set_permissions(Permissions::from_mode(COPY_MODE))
            .unwrap();
        file.write_all_at(&self.bytes[..length], 0).unwrap();
        file.sync_all().unwrap();
        File::open(&self.root).unwrap().sync_all().unwrap();
    }

    fn caller_unchanged(&self) {
        assert_eq!(
            std::fs::read(&self.destination).unwrap(),
            b"prior caller output"
        );
        assert_eq!(std::fs::read(&self.source).unwrap(), self.bytes);
    }

    fn publish(&self, prepared: PreparedOutput) {
        // Same ordering as RecoverySession: sync the directory before pending
        // may be journaled. This helper never claims to exercise the journal.
        prepared.directory.sync_all().unwrap();
        prepared.publish(&self.destination).unwrap();
        assert_eq!(std::fs::read(&self.destination).unwrap(), self.bytes);
    }
}

#[test]
fn preparation_syncs_complete_data_before_chmod_without_syncing_empty_creation() {
    for length in [0, 1, 65_537] {
        for mode in [0o444, COPY_MODE, 0o755] {
            for resumed in [false, true] {
                let fixture = Fixture::new(length, mode);
                if resumed {
                    fixture.retain(length / 2);
                }
                let mut syncs = 0;
                let prepared = prepare_with_io(
                    &fixture.source,
                    &fixture.temporary,
                    &fixture.hash,
                    |file, bytes, offset| file.write_at(bytes, offset),
                    |file| {
                        syncs += 1;
                        let metadata = file.metadata()?;
                        assert!(metadata.is_file(), "empty-entry directory sync returned");
                        assert_eq!(metadata.len(), length as u64);
                        assert_eq!(
                            metadata.mode() & 0o7777,
                            if syncs == 1 { COPY_MODE } else { mode }
                        );
                        assert_eq!(std::fs::read(&fixture.temporary).unwrap(), fixture.bytes);
                        file.sync_all()
                    },
                )
                .unwrap();
                assert_eq!(syncs, if mode == COPY_MODE { 1 } else { 2 });
                fixture.caller_unchanged();
                fixture.publish(prepared);
                assert_eq!(
                    std::fs::metadata(&fixture.destination).unwrap().mode() & 0o7777,
                    mode
                );
            }
        }
    }
}

#[test]
fn data_and_mode_sync_failures_retain_complete_copies_and_retry_without_writes() {
    for length in [0, 65_537] {
        for mode in [0o444, COPY_MODE, 0o755] {
            let boundaries = if mode == COPY_MODE { 1 } else { 2 };
            for fail_on in 1..=boundaries {
                let fixture = Fixture::new(length, mode);
                fixture.retain(length / 2);
                let mut syncs = 0;
                let result = prepare_with_io(
                    &fixture.source,
                    &fixture.temporary,
                    &fixture.hash,
                    |file, bytes, offset| file.write_at(bytes, offset),
                    |file| {
                        syncs += 1;
                        if syncs == fail_on {
                            Err(io::Error::from_raw_os_error(
                                rustix::io::Errno::IO.raw_os_error(),
                            ))
                        } else {
                            file.sync_all()
                        }
                    },
                );
                assert!(result.is_err(), "sync failure returned a prepared output");
                assert_eq!(syncs, fail_on);
                fixture.caller_unchanged();
                let metadata = std::fs::metadata(&fixture.temporary).unwrap();
                assert_eq!(
                    metadata.mode() & 0o7777,
                    if fail_on == 1 { COPY_MODE } else { mode }
                );
                assert_eq!(std::fs::read(&fixture.temporary).unwrap(), fixture.bytes);
                let prepared = prepare_with_write(
                    &fixture.source,
                    &fixture.temporary,
                    &fixture.hash,
                    |_, _, _| panic!("complete retained copy reached a payload write"),
                )
                .unwrap();
                assert_eq!(prepared.file.metadata().unwrap().ino(), metadata.ino());
                fixture.publish(prepared);
                assert_eq!(
                    std::fs::metadata(&fixture.destination).unwrap().ino(),
                    metadata.ino()
                );
            }
        }
    }
}

#[test]
fn write_error_remains_primary_when_both_salvage_syncs_fail() {
    let fixture = Fixture::new(65_539, 0o755);
    let mut sync_types = Vec::new();
    let error = prepare_with_io(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |file, bytes, offset| {
            if offset == 0 {
                file.write_at(&bytes[..17], offset)
            } else {
                Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::NOSPC.raw_os_error(),
                ))
            }
        },
        |file| {
            sync_types.push(file.metadata()?.is_dir());
            Err(io::Error::from_raw_os_error(
                rustix::io::Errno::IO.raw_os_error(),
            ))
        },
    )
    .err()
    .expect("injected write fault must fail");
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(rustix::io::Errno::NOSPC.raw_os_error())
    );
    assert_eq!(sync_types, [false, true]);
    assert_eq!(
        std::fs::read(&fixture.temporary).unwrap(),
        fixture.bytes[..17]
    );
    fixture.caller_unchanged();
    let inode = std::fs::metadata(&fixture.temporary).unwrap().ino();
    let prepared = prepare_with_write(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |file, bytes, offset| {
            assert!(offset >= 17, "retained prefix was overwritten");
            file.write_at(bytes, offset)
        },
    )
    .unwrap();
    fixture.publish(prepared);
    assert_eq!(
        std::fs::metadata(&fixture.destination).unwrap().ino(),
        inode
    );
}

#[test]
fn changed_copy_after_failed_sync_is_not_reused_or_discarded() {
    for hardlink in [false, true] {
        let fixture = Fixture::new(65_537, 0o755);
        let result = prepare_with_io(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            |file, bytes, offset| file.write_at(bytes, offset),
            |file| {
                if hardlink {
                    std::fs::hard_link(&fixture.temporary, fixture.root.join("other-owner"))?;
                } else {
                    file.write_all_at(b"X", 0)?;
                }
                Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::IO.raw_os_error(),
                ))
            },
        );
        assert!(result.is_err());
        let before = std::fs::read(&fixture.temporary).unwrap();
        let inode = std::fs::metadata(&fixture.temporary).unwrap().ino();
        assert!(
            prepare_with_write(
                &fixture.source,
                &fixture.temporary,
                &fixture.hash,
                |_, _, _| panic!("conflicting retained evidence reached a write"),
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&fixture.temporary).unwrap(), before);
        assert_eq!(std::fs::metadata(&fixture.temporary).unwrap().ino(), inode);
        fixture.caller_unchanged();
    }
}

#[test]
fn verified_source_cache_is_bounded_and_never_accepts_a_matching_prefix_alone() {
    for length in [0, 65_537, 1_048_576, 1_048_577] {
        let fixture = Fixture::new(length, 0o755);
        let prefix = length / 2;
        fixture.retain(prefix);
        let source = File::open(&fixture.source).unwrap();
        let copy = File::open(&fixture.temporary).unwrap();
        let verified =
            verify_prefix(&source, length as u64, &copy, prefix as u64, &fixture.hash).unwrap();
        if (length as u64) <= VERIFIED_SOURCE_CACHE_BYTES {
            assert_eq!(verified.as_deref(), Some(fixture.bytes.as_slice()));
        } else {
            assert!(
                verified.is_none(),
                "large artifacts must not be buffered whole"
            );
        }
        let wrong = blake3::hash(b"different unverified artifact")
            .to_hex()
            .to_string();
        assert!(verify_prefix(&source, length as u64, &copy, prefix as u64, &wrong).is_err());
        assert_eq!(
            std::fs::read(&fixture.temporary).unwrap(),
            fixture.bytes[..prefix]
        );
        fixture.caller_unchanged();
        let prepared = prepare_with_write(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            |file, bytes, offset| {
                assert!(offset >= prefix as u64);
                file.write_at(bytes, offset)
            },
        )
        .unwrap();
        fixture.publish(prepared);
    }
}

#[test]
fn cached_copy_still_refuses_source_replacement_between_chunks() {
    let fixture = Fixture::new(2 * BUFFER_BYTES + 1, 0o755);
    let retained_source = fixture.root.join("original-source");
    let mut writes = 0;
    let result = prepare_with_write(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |file, bytes, offset| {
            writes += 1;
            let count = file.write_at(bytes, offset)?;
            if writes == 1 {
                std::fs::rename(&fixture.source, &retained_source)?;
                std::fs::write(&fixture.source, b"new source owner")?;
            }
            Ok(count)
        },
    );
    assert!(result.is_err());
    assert_eq!(writes, 1, "cached bytes bypassed the source identity check");
    assert_eq!(std::fs::read(&retained_source).unwrap(), fixture.bytes);
    assert_eq!(std::fs::read(&fixture.source).unwrap(), b"new source owner");
    assert_eq!(
        std::fs::read(&fixture.destination).unwrap(),
        b"prior caller output"
    );
    assert_eq!(
        std::fs::read(&fixture.temporary).unwrap(),
        fixture.bytes[..BUFFER_BYTES]
    );
}

// This backend writes real bytes to exercise preparation's clone-result path.
// It is deliberately not evidence that the filesystem supports native CoW.
fn injected_clone(source: &File, destination: &File) -> io::Result<bool> {
    let length = source.metadata()?.len();
    let mut bytes = [0; BUFFER_BYTES];
    let mut offset = 0;
    while offset < length {
        let count = (length - offset).min(bytes.len() as u64) as usize;
        source.read_exact_at(&mut bytes[..count], offset)?;
        destination.write_all_at(&bytes[..count], offset)?;
        offset += count as u64;
    }
    Ok(true)
}

#[test]
fn verified_clone_finishes_without_reserving_a_second_payload() {
    for retained_empty in [false, true] {
        let fixture = Fixture::new(65_539, 0o755);
        if retained_empty {
            fixture.retain(0);
        }
        let source_before = std::fs::metadata(&fixture.source).unwrap();
        let mut clones = 0;
        let mut modes_at_sync = Vec::new();
        let prepared = prepare_with_backend(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            CopyBackend {
                write: |_: &File, _: &[u8], _: u64| panic!("clone reached buffered copying"),
                sync: |file: &File| {
                    assert_eq!(file.metadata()?.len(), fixture.bytes.len() as u64);
                    modes_at_sync.push(file.metadata()?.mode() & 0o7777);
                    file.sync_all()
                },
                copy_range: |_: &File, _: &File, _: u64, _: usize| {
                    panic!("clone reached suffix copying")
                },
                clone_file: |source: &File, destination: &File| {
                    clones += 1;
                    assert_eq!(destination.metadata()?.len(), 0);
                    injected_clone(source, destination)
                },
                check_space: |_: &File, _: u64| anyhow::bail!("no room for a second full payload"),
            },
        )
        .unwrap();
        assert_eq!(clones, 1);
        assert_eq!(modes_at_sync, [COPY_MODE, 0o755]);
        assert_ne!(prepared.file.metadata().unwrap().ino(), source_before.ino());
        fixture.caller_unchanged();
        fixture.publish(prepared);
        let source_after = std::fs::metadata(&fixture.source).unwrap();
        assert!(same_version(&source_before, &source_after));
        assert_eq!(
            std::fs::metadata(&fixture.destination).unwrap().mode() & 0o7777,
            0o755
        );
    }
}

#[test]
fn unsupported_clone_and_retained_prefix_keep_copy_capacity_admission() {
    for prefix in [0, 17, 65_539] {
        let fixture = Fixture::new(65_539, 0o755);
        fixture.retain(prefix);
        let inode = std::fs::metadata(&fixture.temporary).unwrap().ino();
        let mut clones = 0;
        let mut reserved = Vec::new();
        let prepared = prepare_with_backend(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            CopyBackend {
                write: |file: &File, bytes: &[u8], offset: u64| {
                    assert!(offset >= prefix as u64, "retained bytes were overwritten");
                    file.write_at(bytes, offset)
                },
                sync: File::sync_all,
                copy_range: |_: &File, _: &File, _: u64, _: usize| Ok(None),
                clone_file: |_: &File, destination: &File| {
                    clones += 1;
                    assert_eq!(prefix, 0, "whole clone reached a retained prefix");
                    assert_eq!(destination.metadata()?.len(), 0);
                    Ok(false)
                },
                check_space: |directory: &File, bytes: u64| {
                    if bytes > 0 {
                        reserved.push(bytes);
                    }
                    check_copy_space(directory, bytes)
                },
            },
        )
        .unwrap();
        assert_eq!(clones, usize::from(prefix == 0));
        assert_eq!(
            reserved,
            if prefix == fixture.bytes.len() {
                vec![]
            } else {
                vec![(fixture.bytes.len() - prefix) as u64]
            }
        );
        assert_eq!(prepared.file.metadata().unwrap().ino(), inode);
        fixture.caller_unchanged();
        fixture.publish(prepared);
    }

    let fixture = Fixture::new(65_539, 0o755);
    let result = prepare_with_backend(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        CopyBackend {
            write: |_: &File, _: &[u8], _: u64| panic!("capacity refusal reached a write"),
            sync: File::sync_all,
            copy_range: |_: &File, _: &File, _: u64, _: usize| {
                panic!("capacity refusal reached suffix copying")
            },
            clone_file: |_: &File, _: &File| Ok(false),
            check_space: |_: &File, bytes: u64| {
                assert_eq!(bytes, fixture.bytes.len() as u64);
                anyhow::bail!("injected full-copy capacity refusal")
            },
        },
    );
    assert!(result.is_err());
    assert_eq!(std::fs::metadata(&fixture.temporary).unwrap().len(), 0);
    fixture.caller_unchanged();
}

#[test]
fn unsuccessful_clone_never_overwrites_its_changed_temporary() {
    for reported_success in [false, true] {
        let fixture = Fixture::new(65_539, 0o755);
        let result = prepare_with_backend(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            CopyBackend {
                write: |_: &File, _: &[u8], _: u64| panic!("changed clone was overwritten"),
                sync: File::sync_all,
                copy_range: |_: &File, _: &File, _: u64, _: usize| {
                    panic!("changed clone reached suffix copying")
                },
                clone_file: |source: &File, destination: &File| {
                    if reported_success {
                        injected_clone(source, destination)?;
                        destination.write_all_at(b"X", 0)?;
                    } else {
                        destination.write_all_at(&fixture.bytes[..17], 0)?;
                    }
                    Ok(reported_success)
                },
                check_space: |_: &File, _: u64| {
                    panic!("changed clone was admitted as an ordinary copy")
                },
            },
        );
        assert!(result.is_err(), "unverified clone became a prepared output");
        let retained = std::fs::read(&fixture.temporary).unwrap();
        if reported_success {
            assert_eq!(retained.len(), fixture.bytes.len());
            assert_eq!(retained[0], b'X');
            assert_eq!(&retained[1..], &fixture.bytes[1..]);
        } else {
            assert_eq!(retained, fixture.bytes[..17]);
        }
        fixture.caller_unchanged();
    }
}

#[test]
fn clone_io_failure_retains_progress_and_original_error_for_append_only_retry() {
    for failure in [
        rustix::io::Errno::NOSPC,
        rustix::io::Errno::IO,
        rustix::io::Errno::INTR,
    ] {
        let fixture = Fixture::new(65_539, 0o755);
        let mut salvaged = Vec::new();
        let error = prepare_with_backend(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            CopyBackend {
                write: |_: &File, _: &[u8], _: u64| panic!("clone failure retried a write"),
                sync: |file: &File| {
                    salvaged.push(file.metadata()?.is_dir());
                    Err(io::Error::from_raw_os_error(
                        rustix::io::Errno::IO.raw_os_error(),
                    ))
                },
                copy_range: |_: &File, _: &File, _: u64, _: usize| {
                    panic!("clone failure retried a kernel operation")
                },
                clone_file: |_: &File, destination: &File| {
                    destination.write_all_at(&fixture.bytes[..17], 0)?;
                    Err(io::Error::from_raw_os_error(failure.raw_os_error()))
                },
                check_space: |_: &File, _: u64| panic!("clone error became a fallback"),
            },
        )
        .err()
        .expect("injected clone error must fail preparation");
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(failure.raw_os_error())
        );
        assert_eq!(salvaged, [false, true]);
        assert_eq!(
            std::fs::read(&fixture.temporary).unwrap(),
            fixture.bytes[..17]
        );
        let inode = std::fs::metadata(&fixture.temporary).unwrap().ino();
        fixture.caller_unchanged();
        let prepared = prepare_with_write(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            |file, bytes, offset| {
                assert!(offset >= 17, "retry overwrote clone-failure evidence");
                file.write_at(bytes, offset)
            },
        )
        .unwrap();
        assert_eq!(prepared.file.metadata().unwrap().ino(), inode);
        fixture.publish(prepared);
    }
}

#[test]
fn clone_sync_failure_leaves_complete_bytes_reusable_without_copying() {
    let fixture = Fixture::new(65_539, 0o755);
    let result = prepare_with_backend(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        CopyBackend {
            write: |_: &File, _: &[u8], _: u64| panic!("clone was redundantly copied"),
            sync: |_: &File| {
                Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::IO.raw_os_error(),
                ))
            },
            copy_range: |_: &File, _: &File, _: u64, _: usize| panic!("unexpected suffix copy"),
            clone_file: injected_clone,
            check_space: |_: &File, _: u64| anyhow::bail!("no duplicate payload budget"),
        },
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(&fixture.temporary).unwrap(), fixture.bytes);
    let before = std::fs::metadata(&fixture.temporary).unwrap();
    assert_eq!(before.mode() & 0o7777, COPY_MODE);
    fixture.caller_unchanged();
    let prepared = prepare_with_backend(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        CopyBackend {
            write: |_: &File, _: &[u8], _: u64| panic!("complete clone was recopied"),
            sync: File::sync_all,
            copy_range: |_: &File, _: &File, _: u64, _: usize| {
                panic!("complete clone was recopied")
            },
            clone_file: |_: &File, _: &File| panic!("complete clone was replaced"),
            check_space: |_: &File, remaining: u64| {
                anyhow::ensure!(remaining == 0, "complete clone requires no payload space");
                Ok(())
            },
        },
    )
    .unwrap();
    assert_eq!(prepared.file.metadata().unwrap().ino(), before.ino());
    fixture.publish(prepared);
}
