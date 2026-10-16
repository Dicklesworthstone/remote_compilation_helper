//! Exercise the actual publisher with partial kernel results and real files.
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
    fn new() -> Self {
        Self::with_length(VERIFIED_SOURCE_CACHE_BYTES as usize + 129)
    }

    fn with_length(length: usize) -> Self {
        let root = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap()
            .keep();
        let source = root.join("stage");
        let temporary = root.join(".rch-return-range");
        let destination = root.join("output");
        let bytes: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        std::fs::write(&source, &bytes).unwrap();
        std::fs::set_permissions(&source, Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&destination, b"old output").unwrap();
        Self {
            root,
            source,
            temporary,
            destination,
            bytes,
            hash,
        }
    }

    fn unchanged(&self) {
        assert_eq!(std::fs::read(&self.source).unwrap(), self.bytes);
        assert_eq!(std::fs::read(&self.destination).unwrap(), b"old output");
    }

    fn delivered(&self, prepared: PreparedOutput) {
        prepared.directory.sync_all().unwrap();
        prepared.publish(&self.destination).unwrap();
        assert_eq!(std::fs::read(&self.destination).unwrap(), self.bytes);
    }
}

// Fault-injection backend: copies real bytes with explicit offsets, but is
// deliberately NOT evidence of a kernel copy_file_range invocation.
fn positioned_copy(source: &File, dest: &File, offset: u64, length: usize) -> io::Result<usize> {
    let mut bytes = vec![0; length];
    source.read_exact_at(&mut bytes, offset)?;
    dest.write_all_at(&bytes, offset)?;
    Ok(length)
}

#[test]
fn partial_kernel_result_then_unsupported_falls_back_at_exact_retained_offset() {
    let fixture = Fixture::new();
    let mut calls = 0;
    let mut written = 17;
    let prepared = prepare_with_copier(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |file, bytes, offset| {
            assert_eq!(offset, written);
            let count = file.write_at(&bytes[..bytes.len().min(10_003)], offset)?;
            written += count as u64;
            Ok(count)
        },
        File::sync_all,
        |source, dest, offset, _| {
            calls += 1;
            match calls {
                1 => positioned_copy(source, dest, offset, 17).map(Some),
                2 => {
                    assert_eq!(offset, 17);
                    Ok(None)
                }
                _ => panic!("unsupported backend was retried for every chunk"),
            }
        },
    )
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(written, fixture.bytes.len() as u64);
    fixture.unchanged();
    fixture.delivered(prepared);
}

#[test]
fn interrupted_kernel_call_retries_without_skipping_or_replaying_bytes() {
    let fixture = Fixture::new();
    let mut calls = 0;
    let mut copied = 0;
    let prepared = prepare_with_copier(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |_, _, _| panic!("successful range copy used buffered writes"),
        File::sync_all,
        |source, dest, offset, count| {
            calls += 1;
            assert_eq!(offset, copied);
            if calls == 2 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let count = if calls == 1 { 17 } else { count };
            let written = positioned_copy(source, dest, offset, count)?;
            copied += written as u64;
            Ok(Some(written))
        },
    )
    .unwrap();
    assert_eq!(copied, fixture.bytes.len() as u64);
    fixture.delivered(prepared);
}

#[test]
fn range_storage_failure_retains_prefix_for_production_retry() {
    let fixture = Fixture::new();
    let mut calls = 0;
    let mut salvaged = Vec::new();
    let result = prepare_with_copier(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |_, _, _| panic!("storage failure was hidden by buffered fallback"),
        |file| {
            salvaged.push(file.metadata()?.is_dir());
            file.sync_all()
        },
        |source, dest, offset, count| {
            calls += 1;
            if calls == 2 {
                return Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::NOSPC.raw_os_error(),
                ));
            }
            positioned_copy(source, dest, offset, count).map(Some)
        },
    );
    let error = result.err().expect("range ENOSPC must not succeed");
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(rustix::io::Errno::NOSPC.raw_os_error())
    );
    assert_eq!(salvaged, [false, true]);
    assert_eq!(
        std::fs::read(&fixture.temporary).unwrap(),
        fixture.bytes[..BUFFER_BYTES]
    );
    let inode = std::fs::metadata(&fixture.temporary).unwrap().ino();
    fixture.unchanged();
    let prepared =
        prepare_output_temporary(&fixture.source, &fixture.temporary, &fixture.hash).unwrap();
    assert_eq!(prepared.file.metadata().unwrap().ino(), inode);
    fixture.delivered(prepared);
    assert_eq!(
        std::fs::metadata(&fixture.destination).unwrap().ino(),
        inode
    );
}

#[test]
fn copier_zero_progress_without_fallback_is_not_a_completed_artifact() {
    let fixture = Fixture::new();
    let result = prepare_with_copier(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |_, _, _| panic!("unexpected EOF fell back to another transport"),
        File::sync_all,
        |_, _, _, _| Ok(Some(0)),
    );
    let error = result.err().expect("zero range result must fail");
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(std::fs::metadata(&fixture.temporary).unwrap().len(), 0);
    fixture.unchanged();
}

#[test]
fn kernel_copy_cannot_hide_same_length_output_corruption() {
    let fixture = Fixture::new();
    let result = prepare_with_copier(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |_, _, _| panic!("unexpected fallback"),
        File::sync_all,
        |source, dest, offset, count| {
            let copied = positioned_copy(source, dest, offset, count)?;
            dest.write_all_at(b"X", 0)?;
            Ok(Some(copied))
        },
    );
    assert!(
        result.is_err(),
        "kernel byte count replaced content verification"
    );
    fixture.unchanged();
    assert_eq!(std::fs::read(&fixture.temporary).unwrap()[0], b'X');
    assert_eq!(
        std::fs::metadata(&fixture.temporary).unwrap().mode() & 0o7777,
        COPY_MODE
    );
}

#[test]
fn range_copy_refuses_replaced_temporary_without_touching_its_new_owner() {
    let fixture = Fixture::new();
    let retained = fixture.root.join("retained-copy");
    let mut calls = 0;
    let result = prepare_with_copier(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |_, _, _| panic!("replaced name reached fallback"),
        File::sync_all,
        |source, dest, offset, count| {
            calls += 1;
            let copied = positioned_copy(source, dest, offset, count)?;
            std::fs::rename(&fixture.temporary, &retained)?;
            std::fs::write(&fixture.temporary, b"other owner's output")?;
            Ok(Some(copied))
        },
    );
    assert!(result.is_err());
    assert_eq!(calls, 1);
    assert_eq!(
        std::fs::read(&fixture.temporary).unwrap(),
        b"other owner's output"
    );
    assert_eq!(
        std::fs::read(&retained).unwrap(),
        fixture.bytes[..BUFFER_BYTES]
    );
    fixture.unchanged();
}

#[test]
fn public_entrypoint_delivers_large_artifacts_with_real_backend_or_safe_fallback() {
    let fixture = Fixture::new();
    let prepared =
        prepare_output_temporary(&fixture.source, &fixture.temporary, &fixture.hash).unwrap();
    fixture.unchanged();
    fixture.delivered(prepared);
}

#[test]
fn small_verified_sources_do_not_invoke_the_kernel_backend() {
    let fixture = Fixture::with_length(65_537);
    let prepared = prepare_with_copier(
        &fixture.source,
        &fixture.temporary,
        &fixture.hash,
        |file, bytes, offset| file.write_at(bytes, offset),
        File::sync_all,
        |_, _, _, _| panic!("small verified snapshot was needlessly copied again"),
    )
    .unwrap();
    fixture.unchanged();
    fixture.delivered(prepared);
}
