//! Resume an interrupted, not-yet-journaled publication copy without losing it.
//!
//! The caller holds the output-root lock and resolves any journaled pending
//! rename before entering here. A private 0600 temporary may be an interrupted
//! copy, not corrupt output. Verify the entire staged source and every retained
//! prefix byte before appending; never truncate, overwrite that prefix, unlink
//! evidence, or advance the journal. PreparedOutput still verifies the complete
//! bytes, inode and mode before the ordinary pending/rename/published boundary.

use super::{File, Path, PreparedOutput};
use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};
use std::fs::{Metadata, Permissions};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

const COPY_MODE: u32 = 0o600;
const BUFFER_BYTES: usize = 64 * 1024;
// Reuse the bytes we must read to validate the source and retained prefix.
// Bounded per artifact, never per inventory; large outputs still stream.
const VERIFIED_SOURCE_CACHE_BYTES: u64 = 1024 * 1024;

#[path = "publication_kernel_copy.rs"]
mod kernel_copy;
#[path = "staged_inventory.rs"]
mod staged_inventory;

#[cfg(test)]
#[path = "publication_copy_io_tests.rs"]
mod io_tests;
#[cfg(test)]
#[path = "publication_copy_range_tests.rs"]
mod range_tests;

/// A missing stage is not an empty successful Make output set. The generic
/// file enumerator also serves pre-build baselines, where absent output roots
/// are normal; publication must first require a real, still-named directory.
/// Completed phases bypass collection in the caller and need no stage readback.
pub(super) fn staged_regular_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    staged_inventory::regular_files(root)
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY
}

fn same_version(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
        && left.mode() == right.mode()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn verify_source(source: &File, path: &Path, original: &Metadata) -> Result<()> {
    let named = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        same_version(original, &source.metadata()?) && same_version(original, &named),
        "staged publication source changed; retained copy was not published"
    );
    Ok(())
}

/// Bind both names to held descriptors. Opening the leaf is nonblocking and
/// nofollow: a FIFO or substituted symlink cannot redirect a read or append.
fn verify_temporary(
    directory: &File,
    temporary: &Path,
    file: &File,
    original: &Metadata,
    length: u64,
    mode: u32,
) -> Result<()> {
    let parent = temporary
        .parent()
        .context("output temporary has no parent")?;
    let held_directory = directory.metadata()?;
    // The caller may choose a symlinked output ROOT. Its referent must still
    // be the same held directory; descendant checks remain in the publisher.
    let named_directory = std::fs::metadata(parent)?;
    anyhow::ensure!(
        held_directory.is_dir()
            && named_directory.is_dir()
            && held_directory.dev() == named_directory.dev()
            && held_directory.ino() == named_directory.ino(),
        "publication copy directory changed; evidence retained"
    );
    let name = temporary
        .file_name()
        .context("output temporary has no name")?;
    let named = File::from(rustix::fs::openat(
        directory.as_fd(),
        name,
        read_flags(),
        Mode::empty(),
    )?);
    let safe = |metadata: &Metadata| {
        metadata.is_file()
            && metadata.dev() == original.dev()
            && metadata.ino() == original.ino()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.nlink() == 1
            && metadata.len() == length
            && metadata.mode() & 0o7777 == mode
    };
    anyhow::ensure!(
        safe(&file.metadata()?) && safe(&named.metadata()?),
        "publication copy identity, length, permissions or links changed; evidence retained"
    );
    Ok(())
}

fn required_copy_bytes(remaining: u64, block_bytes: u64) -> Result<u64> {
    if remaining == 0 {
        return Ok(0);
    }
    anyhow::ensure!(
        block_bytes > 0,
        "publication filesystem has no allocation size"
    );
    remaining
        .div_ceil(block_bytes)
        .checked_mul(block_bytes)
        .context("publication copy capacity overflow")
}

fn check_copy_space(directory: &File, remaining: u64) -> Result<()> {
    if remaining == 0 {
        // A complete retained copy needs no second payload allocation, even
        // when space has since become scarce. Sync/rename can still fail.
        return Ok(());
    }
    let stats = rustix::fs::fstatvfs(directory.as_fd())?;
    let required = required_copy_bytes(remaining, stats.f_frsize)?;
    let available = stats.f_bavail.saturating_mul(stats.f_frsize);
    anyhow::ensure!(
        available >= required,
        "insufficient controller publication storage: need {required} additional bytes, \
         available {available}; staged output and retained copy remain retryable"
    );
    Ok(())
}

/// Read the full source, not just the missing suffix. A matching prefix cannot
/// legitimize a different output or a source that changed after fingerprinting.
fn verify_prefix(
    source: &File,
    source_length: u64,
    copy: &File,
    prefix_length: u64,
    expected: &str,
) -> Result<Option<Vec<u8>>> {
    let mut source_bytes = vec![0; BUFFER_BYTES];
    let mut prefix_bytes = vec![0; BUFFER_BYTES];
    let mut verified = (source_length <= VERIFIED_SOURCE_CACHE_BYTES)
        .then(|| Vec::with_capacity(source_length as usize));
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0;
    while offset < source_length {
        super::publication_runtime::checkpoint()?;
        let count = (source_length - offset).min(BUFFER_BYTES as u64) as usize;
        source.read_exact_at(&mut source_bytes[..count], offset)?;
        hasher.update(&source_bytes[..count]);
        if let Some(verified) = &mut verified {
            verified.extend_from_slice(&source_bytes[..count]);
        }
        let retained = prefix_length.saturating_sub(offset).min(count as u64) as usize;
        if retained > 0 {
            copy.read_exact_at(&mut prefix_bytes[..retained], offset)?;
            anyhow::ensure!(
                prefix_bytes[..retained] == source_bytes[..retained],
                "retained publication copy is not the exact staged prefix; evidence unchanged"
            );
        }
        offset += count as u64;
    }
    anyhow::ensure!(
        hasher.finalize().to_hex().as_str() == expected,
        "staged publication source does not match its fingerprint; evidence unchanged"
    );
    Ok(verified)
}

pub(super) fn prepare_output_temporary(
    source: &Path,
    temporary: &Path,
    expected: &str,
) -> Result<PreparedOutput> {
    prepare_with_copier(
        source,
        temporary,
        expected,
        |file, bytes, offset| file.write_at(bytes, offset),
        File::sync_all,
        kernel_copy::copy_range,
    )
}

/// The writer seam injects real partial-write boundaries in tests. Production
/// uses positional writes on the same descriptor, never seek/truncate/replace.
#[cfg(test)]
pub(super) fn prepare_with_write(
    source_path: &Path,
    temporary: &Path,
    expected: &str,
    write: impl FnMut(&File, &[u8], u64) -> io::Result<usize>,
) -> Result<PreparedOutput> {
    prepare_with_io(source_path, temporary, expected, write, File::sync_all)
}

/// No journal checkpoint exists during preparation. Empty-file creation needs
/// no durability barrier: the complete data is still synced BEFORE chmod, and
/// changed permissions are synced before returning to the publisher. The caller
/// syncs the held directory BEFORE recording pending ownership; rename and the
/// published checkpoint retain their own durability barriers.
/// The sync seam lets tests fail this boundary without weakening production I/O.
#[cfg(test)]
fn prepare_with_io(
    source_path: &Path,
    temporary: &Path,
    expected: &str,
    write: impl FnMut(&File, &[u8], u64) -> io::Result<usize>,
    sync: impl FnMut(&File) -> io::Result<()>,
) -> Result<PreparedOutput> {
    prepare_with_copier(
        source_path,
        temporary,
        expected,
        write,
        sync,
        |_, _, _, _| Ok(None),
    )
}

// Retain cancellation prefixes just like interrupted writes. Storage errors
// during salvage never replace the cancellation that stopped this attempt.
fn copy_checkpoint(
    file: &File,
    directory: &File,
    sync: &mut impl FnMut(&File) -> io::Result<()>,
) -> Result<()> {
    if let Err(error) = super::publication_runtime::checkpoint() {
        let _ = sync(file);
        let _ = sync(directory);
        return Err(error);
    }
    Ok(())
}

// A kernel copier reports None ONLY when no bytes were consumed and ordinary
// positioned I/O should take over. Every positive partial result advances the
// retained prefix; no fallback ever starts again from zero.
fn prepare_with_copier(
    source_path: &Path,
    temporary: &Path,
    expected: &str,
    mut write: impl FnMut(&File, &[u8], u64) -> io::Result<usize>,
    mut sync: impl FnMut(&File) -> io::Result<()>,
    mut copy_range: impl FnMut(&File, &File, u64, usize) -> io::Result<Option<usize>>,
) -> Result<PreparedOutput> {
    super::publication_runtime::checkpoint()?;
    let parent = temporary
        .parent()
        .context("output temporary has no parent")?;
    std::fs::create_dir_all(parent)?;
    let directory = File::open(parent)?;
    anyhow::ensure!(
        directory.metadata()?.is_dir(),
        "output parent is not a directory"
    );
    let source = File::from(rustix::fs::open(source_path, read_flags(), Mode::empty())?);
    let source_metadata = source.metadata()?;
    anyhow::ensure!(
        source_metadata.is_file(),
        "staged output is not a regular file"
    );
    let name = temporary
        .file_name()
        .context("output temporary has no name")?;
    let file = match rustix::fs::openat(directory.as_fd(), name, read_flags(), Mode::empty()) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => {
            check_copy_space(&directory, source_metadata.len())?;
            let file = File::from(rustix::fs::openat(
                directory.as_fd(),
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )?);
            // Only this exclusively created descriptor may normalize a more
            // restrictive umask. Never chmod pre-existing evidence here.
            file.set_permissions(Permissions::from_mode(COPY_MODE))?;
            // Persisting an empty temporary adds no recoverable payload. The
            // stage remains authoritative until the caller's durable pending
            // checkpoint; interruptions can resume or recreate this copy.
            file
        }
        Err(error) => return Err(error.into()),
    };
    let initial = file.metadata()?;
    let prefix_length = initial.len();
    let mode = initial.mode() & 0o7777;
    let final_mode = source_metadata.mode() & 0o7777;
    anyhow::ensure!(
        initial.is_file()
            && initial.nlink() == 1
            && initial.uid() == rustix::process::geteuid().as_raw()
            && prefix_length <= source_metadata.len()
            && (initial.dev() != source_metadata.dev() || initial.ino() != source_metadata.ino())
            && (mode == COPY_MODE
                || (prefix_length == source_metadata.len() && mode == final_mode)),
        "retained output is not a private partial copy or a complete correctly-permissioned copy"
    );
    verify_temporary(&directory, temporary, &file, &initial, prefix_length, mode)?;
    verify_source(&source, source_path, &source_metadata)?;
    let verified_source = verify_prefix(
        &source,
        source_metadata.len(),
        &file,
        prefix_length,
        expected,
    )?;
    verify_source(&source, source_path, &source_metadata)?;
    anyhow::ensure!(
        same_version(&initial, &file.metadata()?),
        "retained publication prefix changed during validation"
    );
    verify_temporary(&directory, temporary, &file, &initial, prefix_length, mode)?;
    let remaining = source_metadata.len() - prefix_length;
    check_copy_space(&directory, remaining)?;
    let file = if remaining > 0 {
        let writable = File::from(rustix::fs::openat(
            directory.as_fd(),
            name,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )?);
        anyhow::ensure!(
            same_version(&initial, &writable.metadata()?),
            "publication copy changed before writable open; evidence retained"
        );
        writable
    } else {
        file
    };
    let mut offset = prefix_length;
    let mut buffer = Vec::new();
    let mut try_kernel = verified_source.is_none();
    while offset < source_metadata.len() {
        copy_checkpoint(&file, &directory, &mut sync)?;
        verify_source(&source, source_path, &source_metadata)?;
        let count = (source_metadata.len() - offset).min(BUFFER_BYTES as u64) as usize;
        if try_kernel {
            verify_temporary(&directory, temporary, &file, &initial, offset, mode)?;
            match copy_range(&source, &file, offset, count) {
                Ok(Some(0)) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(Some(copied)) => {
                    anyhow::ensure!(copied <= count, "invalid publication range length");
                    offset += copied as u64;
                    continue;
                }
                Ok(None) => try_kernel = false,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    let _ = sync(&file);
                    let _ = sync(&directory);
                    return Err(error).with_context(|| {
                        format!(
                            "publication range copy interrupted at {}; prefix retained for recovery",
                            temporary.display()
                        )
                    });
                }
            }
        }
        // Only the fully hash-checked snapshot may bypass this second source
        // read. Name/version checks still run for every chunk, and the held
        // temporary is independently hashed before chmod and publication.
        let bytes = if let Some(verified) = &verified_source {
            &verified[offset as usize..offset as usize + count]
        } else {
            if buffer.is_empty() {
                buffer.resize(BUFFER_BYTES, 0);
            }
            source.read_exact_at(&mut buffer[..count], offset)?;
            &buffer[..count]
        };
        let mut written = 0;
        while written < count {
            copy_checkpoint(&file, &directory, &mut sync)?;
            // The next write starts exactly at EOF. Another writer's growth
            // or truncation is not permission to overwrite retained bytes.
            verify_temporary(&directory, temporary, &file, &initial, offset, mode)?;
            match write(&file, &bytes[written..count], offset) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(bytes) => {
                    anyhow::ensure!(bytes <= count - written, "invalid publication write length");
                    offset += bytes as u64;
                    written += bytes;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    // Best effort only: a full or failed device can also
                    // refuse fsync. Never hide the original write failure.
                    let _ = sync(&file);
                    let _ = sync(&directory);
                    return Err(error).with_context(|| {
                        format!(
                            "publication copy interrupted at {}; prefix retained for recovery",
                            temporary.display()
                        )
                    });
                }
            }
        }
    }
    copy_checkpoint(&file, &directory, &mut sync)?;
    verify_source(&source, source_path, &source_metadata)?;
    verify_temporary(&directory, temporary, &file, &initial, offset, mode)?;
    // Full-byte validation precedes chmod too. A complete 0600 copy left by a
    // crash between data sync and permission installation can finish safely.
    let prepared = PreparedOutput::hold(file, directory, temporary, expected)?;
    sync(&prepared.file)?;
    if mode == final_mode {
        return Ok(prepared);
    }
    prepared.verify_name(temporary)?;
    prepared.verify_content()?;
    prepared
        .file
        .set_permissions(source_metadata.permissions())?;
    sync(&prepared.file)?;
    PreparedOutput::hold(prepared.file, prepared.directory, temporary, expected)
}

#[cfg(test)]
mod tests {
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
        fn new(length: usize) -> Self {
            let root = tempfile::Builder::new()
                .disable_cleanup(true)
                .tempdir()
                .unwrap()
                .keep();
            let source = root.join("staged-output");
            let temporary = root.join(".rch-return-copy-fixture");
            let destination = root.join("caller-output");
            let bytes: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
            let hash = blake3::hash(&bytes).to_hex().to_string();
            std::fs::write(&source, &bytes).unwrap();
            std::fs::set_permissions(&source, Permissions::from_mode(0o755)).unwrap();
            std::fs::write(&destination, b"previous caller output").unwrap();
            Self {
                root,
                source,
                temporary,
                destination,
                bytes,
                hash,
            }
        }

        fn private_prefix(&self, length: usize) {
            let file = File::from(
                rustix::fs::open(
                    &self.temporary,
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::CLOEXEC
                        | OFlags::NOFOLLOW,
                    Mode::RUSR | Mode::WUSR,
                )
                .unwrap(),
            );
            file.write_all_at(&self.bytes[..length], 0).unwrap();
            file.set_permissions(Permissions::from_mode(COPY_MODE))
                .unwrap();
            file.sync_all().unwrap();
        }

        fn check_originals(&self) {
            assert_eq!(std::fs::read(&self.source).unwrap(), self.bytes);
            assert_eq!(
                std::fs::read(&self.destination).unwrap(),
                b"previous caller output"
            );
        }
    }

    fn fail_at(fixture: &Fixture, stop: u64) -> anyhow::Error {
        prepare_with_write(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            |file, bytes, offset| {
                if offset >= stop {
                    return Err(io::Error::from_raw_os_error(
                        rustix::io::Errno::NOSPC.raw_os_error(),
                    ));
                }
                let count = bytes.len().min((stop - offset) as usize);
                file.write_at(&bytes[..count], offset)
            },
        )
        .err()
        .expect("fault injection must interrupt the copy")
    }

    #[test]
    fn partial_enospc_retries_append_only_the_missing_suffix_and_keep_the_inode() {
        for stop in [0, 1, 65_535, 65_536, 65_537, 131_079] {
            let fixture = Fixture::new(196_739);
            let destination_inode = std::fs::metadata(&fixture.destination).unwrap().ino();
            let error = fail_at(&fixture, stop);
            assert!(
                error.chain().any(|cause| cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.raw_os_error()
                        == Some(rustix::io::Errno::NOSPC.raw_os_error())))
            );
            let initial = std::fs::metadata(&fixture.temporary).unwrap();
            assert_eq!(initial.len(), stop);
            assert_eq!(initial.mode() & 0o7777, COPY_MODE);
            assert_eq!(
                std::fs::read(&fixture.temporary).unwrap(),
                fixture.bytes[..stop as usize]
            );
            fixture.check_originals();
            assert_eq!(
                std::fs::metadata(&fixture.destination).unwrap().ino(),
                destination_inode
            );
            let mut appended = 0;
            let prepared = prepare_with_write(
                &fixture.source,
                &fixture.temporary,
                &fixture.hash,
                |file, bytes, offset| {
                    assert_eq!(offset, stop + appended);
                    assert!(offset >= stop, "retained prefix was rewritten");
                    let written = file.write_at(bytes, offset)?;
                    appended += written as u64;
                    Ok(written)
                },
            )
            .unwrap();
            assert_eq!(appended, fixture.bytes.len() as u64 - stop);
            assert_eq!(prepared.file.metadata().unwrap().ino(), initial.ino());
            assert_eq!(std::fs::read(&fixture.temporary).unwrap(), fixture.bytes);
            assert_eq!(prepared.mode, 0o755);
            fixture.check_originals();
            prepared.publish(&fixture.destination).unwrap();
            assert_eq!(std::fs::read(&fixture.destination).unwrap(), fixture.bytes);
            assert_eq!(
                std::fs::metadata(&fixture.destination).unwrap().ino(),
                initial.ino()
            );
            assert_eq!(std::fs::read(&fixture.source).unwrap(), fixture.bytes);
        }
    }

    #[test]
    fn repeated_storage_failures_keep_a_longer_verified_prefix_on_each_attempt() {
        let fixture = Fixture::new(131_083);
        let _ = fail_at(&fixture, 13);
        let inode = std::fs::metadata(&fixture.temporary).unwrap().ino();
        for stop in [100, 65_535, 65_537] {
            let _ = fail_at(&fixture, stop);
            assert_eq!(std::fs::metadata(&fixture.temporary).unwrap().ino(), inode);
            assert_eq!(
                std::fs::read(&fixture.temporary).unwrap(),
                fixture.bytes[..stop as usize]
            );
            fixture.check_originals();
        }
        let prepared =
            prepare_output_temporary(&fixture.source, &fixture.temporary, &fixture.hash).unwrap();
        assert_eq!(prepared.file.metadata().unwrap().ino(), inode);
        prepared.verify_content().unwrap();
    }

    #[test]
    fn complete_private_copies_finish_permissions_and_empty_or_readonly_outputs_reuse() {
        for length in [0, 1, 65_537] {
            for mode in [0o444, 0o600, 0o755] {
                let fixture = Fixture::new(length);
                std::fs::set_permissions(&fixture.source, Permissions::from_mode(mode)).unwrap();
                fixture.private_prefix(length);
                let inode = std::fs::metadata(&fixture.temporary).unwrap().ino();
                for _ in 0..2 {
                    let prepared = prepare_with_write(
                        &fixture.source,
                        &fixture.temporary,
                        &fixture.hash,
                        |_, _, _| panic!("complete copy must not allocate or rewrite payload"),
                    )
                    .unwrap();
                    assert_eq!(prepared.mode, mode);
                    assert_eq!(prepared.file.metadata().unwrap().ino(), inode);
                    prepared.verify_content().unwrap();
                }
                fixture.check_originals();
            }
        }
    }

    #[test]
    fn conflicting_prefix_hash_length_and_mode_are_refused_without_writing() {
        for case in [
            "prefix",
            "suffix-hash",
            "oversized",
            "mode",
            "complete-mode",
            "hardlink",
        ] {
            let fixture = Fixture::new(131_073);
            let complete = case == "complete-mode";
            fixture.private_prefix(if complete {
                fixture.bytes.len()
            } else {
                65_537
            });
            let mut expected = fixture.hash.clone();
            match case {
                "prefix" => {
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&fixture.temporary)
                        .unwrap();
                    file.write_all_at(b"X", 65_536).unwrap();
                }
                "suffix-hash" => {
                    let mut other = fixture.bytes.clone();
                    *other.last_mut().unwrap() ^= 1;
                    expected = blake3::hash(&other).to_hex().to_string();
                }
                "oversized" => {
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&fixture.temporary)
                        .unwrap();
                    file.write_all_at(b"X", fixture.bytes.len() as u64).unwrap();
                }
                "mode" | "complete-mode" => {
                    std::fs::set_permissions(&fixture.temporary, Permissions::from_mode(0o644))
                        .unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&fixture.temporary, fixture.root.join("retained-alias"))
                        .unwrap()
                }
                _ => unreachable!(),
            }
            let before = std::fs::read(&fixture.temporary).unwrap();
            let metadata = std::fs::metadata(&fixture.temporary).unwrap();
            assert!(
                prepare_with_write(
                    &fixture.source,
                    &fixture.temporary,
                    &expected,
                    |_, _, _| panic!("rejected evidence reached a write: {case}"),
                )
                .is_err(),
                "{case}"
            );
            assert_eq!(std::fs::read(&fixture.temporary).unwrap(), before);
            let after = std::fs::metadata(&fixture.temporary).unwrap();
            assert_eq!(after.ino(), metadata.ino());
            assert_eq!(after.mode(), metadata.mode());
            assert_eq!(after.nlink(), metadata.nlink());
            fixture.check_originals();
        }
    }

    #[test]
    fn symlinks_and_fifo_temporaries_never_become_copy_targets() {
        for kind in ["symlink", "fifo", "directory", "source-symlink"] {
            let fixture = Fixture::new(99);
            let mut source = fixture.source.clone();
            match kind {
                "symlink" => {
                    std::os::unix::fs::symlink(&fixture.destination, &fixture.temporary).unwrap()
                }
                "fifo" => {
                    assert!(
                        std::process::Command::new("mkfifo")
                            .arg(&fixture.temporary)
                            .status()
                            .unwrap()
                            .success()
                    );
                }
                "directory" => std::fs::create_dir(&fixture.temporary).unwrap(),
                "source-symlink" => {
                    source = fixture.root.join("source-alias");
                    std::os::unix::fs::symlink(&fixture.source, &source).unwrap();
                    fixture.private_prefix(9);
                }
                _ => unreachable!(),
            }
            assert!(
                prepare_with_write(
                    &source,
                    &fixture.temporary,
                    &fixture.hash,
                    |_, _, _| panic!("unsafe entry reached write")
                )
                .is_err()
            );
            fixture.check_originals();
            assert!(std::fs::symlink_metadata(&fixture.temporary).is_ok());
        }
    }

    #[test]
    fn complete_byte_verification_detects_in_place_mutation_after_prefix_validation() {
        let fixture = Fixture::new(131_077);
        fixture.private_prefix(101);
        let result = prepare_with_write(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            |file, bytes, offset| {
                let count = file.write_at(bytes, offset)?;
                // Same inode and size, but a test-owned prefix byte changed.
                file.write_all_at(b"X", 0)?;
                Ok(count)
            },
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(&fixture.temporary).unwrap()[0], b'X');
        assert_eq!(
            std::fs::metadata(&fixture.temporary).unwrap().mode() & 0o7777,
            COPY_MODE
        );
        fixture.check_originals();
    }

    #[test]
    fn replacement_during_append_preserves_both_names_and_never_publishes() {
        for replace_directory in [false, true] {
            let fixture = Fixture::new(131_089);
            fixture.private_prefix(31);
            let original_inode = std::fs::metadata(&fixture.temporary).unwrap().ino();
            let retained = if replace_directory {
                fixture.root.with_extension("retained-directory")
            } else {
                fixture.root.join("retained-prefix")
            };
            let mut first = true;
            let result = prepare_with_write(
                &fixture.source,
                &fixture.temporary,
                &fixture.hash,
                |file, bytes, offset| {
                    let count = file.write_at(bytes, offset)?;
                    if first {
                        first = false;
                        if replace_directory {
                            std::fs::rename(&fixture.root, &retained)?;
                            std::fs::create_dir(&fixture.root)?;
                        } else {
                            std::fs::rename(&fixture.temporary, &retained)?;
                        }
                        std::fs::write(&fixture.temporary, b"replacement must not be touched")?;
                    }
                    Ok(count)
                },
            );
            assert!(result.is_err());
            assert_eq!(
                std::fs::read(&fixture.temporary).unwrap(),
                b"replacement must not be touched"
            );
            let original = if replace_directory {
                assert_eq!(
                    std::fs::read(retained.join("caller-output")).unwrap(),
                    b"previous caller output"
                );
                retained.join(".rch-return-copy-fixture")
            } else {
                fixture.check_originals();
                retained
            };
            assert_eq!(std::fs::metadata(&original).unwrap().ino(), original_inode);
            assert_eq!(
                std::fs::read(&original).unwrap(),
                fixture.bytes[..31 + BUFFER_BYTES]
            );
        }
    }

    #[test]
    fn interrupted_short_and_zero_writes_never_skip_bytes() {
        let fixture = Fixture::new(1031);
        fixture.private_prefix(31);
        let before = std::fs::read(&fixture.temporary).unwrap();
        let error = prepare_with_write(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            |_, _, _| Ok(0),
        )
        .err()
        .unwrap();
        assert!(
            error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::WriteZero)
        );
        assert_eq!(std::fs::read(&fixture.temporary).unwrap(), before);
        let mut interrupted = false;
        let prepared = prepare_with_write(
            &fixture.source,
            &fixture.temporary,
            &fixture.hash,
            |file, bytes, offset| {
                if !interrupted {
                    interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                file.write_at(&bytes[..bytes.len().min(17)], offset)
            },
        )
        .unwrap();
        prepared.verify_content().unwrap();
        assert_eq!(std::fs::read(&fixture.temporary).unwrap(), fixture.bytes);
        fixture.check_originals();
    }

    #[test]
    fn capacity_check_budgets_the_missing_suffix_not_another_complete_copy() {
        assert_eq!(required_copy_bytes(0, 0).unwrap(), 0);
        assert_eq!(required_copy_bytes(1, 4096).unwrap(), 4096);
        assert_eq!(required_copy_bytes(4096, 4096).unwrap(), 4096);
        assert_eq!(required_copy_bytes(4097, 4096).unwrap(), 8192);
        assert!(required_copy_bytes(1, 0).is_err());
        assert!(required_copy_bytes(u64::MAX, 4096).is_err());
        let fixture = Fixture::new(19);
        fixture.private_prefix(9);
        let directory = File::open(&fixture.root).unwrap();
        assert!(check_copy_space(&directory, u64::MAX).is_err());
        assert_eq!(
            std::fs::read(&fixture.temporary).unwrap(),
            fixture.bytes[..9]
        );
        fixture.check_originals();
    }

    #[test]
    fn publication_requires_a_present_real_stage_but_allows_an_empty_one() {
        let fixture = Fixture::new(19);
        let stage = fixture.root.join("stage");
        assert!(staged_regular_files(&stage).is_err());
        std::fs::create_dir(&stage).unwrap();
        assert!(staged_regular_files(&stage).unwrap().is_empty());
        std::fs::write(stage.join("output.o"), b"retained output").unwrap();
        assert_eq!(
            staged_regular_files(&stage).unwrap(),
            [PathBuf::from("output.o")]
        );

        let retained = fixture.root.join("original-stage");
        std::fs::rename(&stage, &retained).unwrap();
        assert!(staged_regular_files(&stage).is_err());
        std::os::unix::fs::symlink(&retained, &stage).unwrap();
        assert!(staged_regular_files(&stage).is_err());
        assert_eq!(std::fs::read_link(&stage).unwrap(), retained);
        assert_eq!(
            std::fs::read(retained.join("output.o")).unwrap(),
            b"retained output"
        );
        assert!(staged_regular_files(&fixture.source).is_err());
        fixture.check_originals();
    }

    #[tokio::test]
    async fn make_output_publication_resumes_after_enospc_without_replay_or_acknowledgment() {
        use super::super::{RecoverySession, lock_output_root};
        use crate::hook::{DurableLeaseWriter, EXIT_ARTIFACT_TRANSFER_FAILED};
        use crate::transfer::TransferPipeline;
        use rch_common::{CompilationKind, TransferConfig, WorkerConfig, WorkerId};
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        async fn run(command: &mut Command) -> std::process::Output {
            command.stdin(Stdio::null()).kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(30), command.output())
                .await
                .expect("owned Make/publication fixture exceeded its deadline")
                .expect("make, a C compiler and rsync are required for this fixture");
            assert!(output.status.success(), "{output:?}");
            output
        }

        let root = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap()
            .keep()
            .canonicalize()
            .unwrap();
        let local = root.join("caller");
        let remote = root.join("worker");
        std::fs::create_dir_all(local.join("build")).unwrap();
        std::fs::create_dir_all(remote.join("build")).unwrap();
        std::fs::write(local.join("build/app"), b"previous caller executable").unwrap();
        std::fs::write(local.join("source.c"), b"caller source sentinel").unwrap();
        std::fs::write(local.join("Makefile"), b"caller Makefile sentinel").unwrap();
        std::fs::write(
            remote.join("source.c"),
            b"#include <stdio.h>\nint main(void) { puts(\"publication recovered\"); return 0; }\n",
        )
        .unwrap();
        std::fs::write(
            remote.join("Makefile"),
            concat!(
                ".PHONY: all\nall:\n",
                "\t$(CC) source.c -o build/app\n",
                "\tprintf 'once\\n' >> build/invocations\n",
            ),
        )
        .unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("publication-copy-fixture"),
            host: "unreachable.invalid".into(),
            user: "worker".into(),
            identity_file: "/unused/test-key".into(),
            total_slots: 1,
            priority: 100,
            tags: Vec::new(),
            tools: Vec::new(),
        };
        let writer =
            DurableLeaseWriter::create_in(&root.join("journals"), "make all", true, false).unwrap();
        writer.admit(41, &worker.id).unwrap();
        let identity = uuid::Uuid::new_v4().simple().to_string();
        let remote_name = remote.to_str().unwrap().to_owned();
        let retained = format!("{remote_name}.retained-{identity}");
        let source_roots = vec![remote_name.clone(), retained.clone()];
        let pair = Some((remote_name.clone(), identity.clone()));
        let transfer = TransferConfig {
            retrieval_staging_dir: Some(root.join("durable-stage")),
            ..Default::default()
        };
        let pipeline = TransferPipeline::new(
            local.clone(),
            "publication-fixture".into(),
            identity.clone(),
            transfer.clone(),
        )
        .with_remote_path_override(remote_name.clone());
        // Source-grant metadata is fixture input. The actual local Make,
        // transport and publisher run; no worker SSH or daemon is contacted.
        RecoverySession::begin(
            &writer,
            &worker,
            source_roots.clone(),
            pair.clone(),
            Some(remote_name.clone()),
            Some(retained.clone()),
            transfer.clone(),
            local.clone(),
            identity.clone(),
        )
        .unwrap();
        let mut session = RecoverySession::prepare(
            &writer,
            &worker,
            &pipeline,
            source_roots,
            pair,
            Some(remote_name),
            Some(retained),
            transfer,
            local.clone(),
            None,
            Some(CompilationKind::Make),
            "make all",
            &[],
            identity.clone(),
        )
        .unwrap();
        session.starting_execution().unwrap();
        let output = run(Command::new("make").arg("all").current_dir(&remote)).await;
        session.completed(output.status.code().unwrap()).unwrap();
        let stage = session.stage(0);
        let staged = session.staging_pipeline("project", &pipeline).unwrap();
        let mut rsync = staged.local_artifact_retrieval_for_test(
            &worker,
            &remote,
            &session.recipe.phases[0].patterns,
        );
        run(&mut rsync).await;
        let source = stage.join("build/app");
        let bytes = std::fs::read(&source).unwrap();
        assert!(bytes.len() > 127);
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let temporary = local.join("build").join(format!(".rch-return-{identity}"));
        let before = std::fs::read(&writer.path).unwrap();
        {
            let _publication = lock_output_root(&local).await.unwrap();
            let result = prepare_with_write(&source, &temporary, &hash, |file, bytes, offset| {
                if offset >= 127 {
                    return Err(io::Error::from_raw_os_error(
                        rustix::io::Errno::NOSPC.raw_os_error(),
                    ));
                }
                file.write_at(&bytes[..bytes.len().min((127 - offset) as usize)], offset)
            });
            assert!(result.is_err());
        }
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        assert!(session.recipe.phases[0].pending.is_none());
        assert!(session.recipe.phases[0].published.is_empty());
        assert!(!session.recipe.phases[0].complete);
        assert_eq!(std::fs::read(&temporary).unwrap(), bytes[..127]);
        assert_eq!(
            std::fs::read(local.join("build/app")).unwrap(),
            b"previous caller executable"
        );
        let inode = std::fs::metadata(&temporary).unwrap().ino();
        writer.record_exit(EXIT_ARTIFACT_TRANSFER_FAILED).unwrap();
        let disk = DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id()).unwrap();
        assert!(!disk.terminal_acknowledged);
        let mut recovered = RecoverySession {
            recipe: serde_json::from_value(disk.recovery.unwrap()).unwrap(),
            writer: writer.clone(),
        };
        // Losing the stage after collection must not turn a successful Make
        // invocation into a falsely successful zero-output publication. Move
        // and restore only the owned fixture; no bytes or journals are edited.
        let retained_stage = root.join("stage-loss-evidence");
        std::fs::rename(&stage, &retained_stage).unwrap();
        let before_missing_stage = std::fs::read(&writer.path).unwrap();
        assert!(recovered.publish("project").await.is_err());
        assert_eq!(std::fs::read(&writer.path).unwrap(), before_missing_stage);
        assert!(!recovered.recipe.phases[0].complete);
        assert!(!writer.snapshot().terminal_acknowledged);
        assert_eq!(std::fs::read(&temporary).unwrap(), bytes[..127]);
        assert_eq!(
            std::fs::read(local.join("build/app")).unwrap(),
            b"previous caller executable"
        );
        assert_eq!(
            std::fs::read(retained_stage.join("build/app")).unwrap(),
            bytes
        );
        std::fs::rename(&retained_stage, &stage).unwrap();
        // This invokes the normal publisher, stage checks and pending/rename
        // checkpoints. It must reach the copy helper through the production
        // import, not call the test's fault-injection seam a second time.
        recovered.publish("project").await.unwrap();
        recovered.returned(0).unwrap();
        assert_eq!(
            std::fs::metadata(local.join("build/app")).unwrap().ino(),
            inode
        );
        assert_eq!(std::fs::read(local.join("build/app")).unwrap(), bytes);
        assert_eq!(
            run(&mut Command::new(local.join("build/app"))).await.stdout,
            b"publication recovered\n"
        );
        assert_eq!(
            std::fs::read(remote.join("build/invocations")).unwrap(),
            b"once\n"
        );
        assert_eq!(
            std::fs::read(&source).unwrap(),
            bytes,
            "retained stage changed"
        );
        assert_eq!(
            std::fs::read(local.join("source.c")).unwrap(),
            b"caller source sentinel"
        );
        let disk = DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id()).unwrap();
        assert_eq!(disk.exit_code, Some(EXIT_ARTIFACT_TRANSFER_FAILED));
        assert!(!disk.terminal_acknowledged);
        assert!(
            disk.recovery.as_ref().unwrap()["phases"][0]["complete"]
                .as_bool()
                .unwrap()
        );
        assert!(disk.recovery.as_ref().unwrap()["phases"][0]["pending"].is_null());
        assert!(!recovered.recipe.sources_released);
        assert!(writer.acknowledge_terminal().is_err());
    }
}
