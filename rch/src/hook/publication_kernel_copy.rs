//! Kernel-assisted suffix copies; neither an ownership check nor a publication.
//!
//! The parent validates the complete source/prefix before the first call,
//! checks held identities before each bounded chunk, and hashes/syncs the
//! complete temporary afterward. Successful kernel transfer is never proof
//! of artifact content, and never advances the durable recovery journal.

use std::fs::File;
use std::io;

#[cfg(target_os = "linux")]
fn permits_fallback(error: rustix::io::Errno) -> bool {
    use rustix::io::Errno;
    matches!(
        error,
        Errno::NOSYS | Errno::XDEV | Errno::OPNOTSUPP | Errno::INVAL | Errno::PERM
    )
}

#[cfg(target_os = "linux")]
pub(super) fn copy_range(
    source: &File,
    destination: &File,
    offset: u64,
    length: usize,
) -> io::Result<Option<usize>> {
    let mut input = offset;
    let mut output = offset;
    match rustix::fs::copy_file_range(
        source,
        Some(&mut input),
        destination,
        Some(&mut output),
        length,
    ) {
        // Some kernels/filesystems return zero for an unsupported operation.
        // Buffered read_exact_at will still reject a genuinely missing suffix;
        // zero must never be interpreted as successful end-of-artifact here.
        Ok(0) if input == offset && output == offset => Ok(None),
        Ok(copied) => {
            let end = offset.checked_add(copied as u64).ok_or_else(|| {
                io::Error::other("publication range offset overflow; evidence retained")
            })?;
            if copied > length || input != end || output != end {
                return Err(io::Error::other(
                    "publication range offsets disagree; evidence retained",
                ));
            }
            Ok(Some(copied))
        }
        Err(error) if permits_fallback(error) && input == offset && output == offset => Ok(None),
        // EPERM may mean seccomp disables this optimization; ordinary writes
        // must still pass all existing checks and their own permission checks.
        // Storage, access and unexpected errors are real failures, not
        // reasons to replay a range through another mechanism. The parent
        // salvages the observed prefix and returns the original I/O error.
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn copy_range(
    _source: &File,
    _destination: &File,
    _offset: u64,
    _length: usize,
) -> io::Result<Option<usize>> {
    Ok(None)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::{FileExt, MetadataExt};

    #[test]
    fn only_unsupported_range_operations_allow_fallback() {
        use rustix::io::Errno;
        for error in [
            Errno::NOSYS,
            Errno::XDEV,
            Errno::OPNOTSUPP,
            Errno::INVAL,
            Errno::PERM,
        ] {
            assert!(permits_fallback(error));
        }
        for error in [Errno::NOSPC, Errno::IO, Errno::ACCESS, Errno::INTR] {
            assert!(!permits_fallback(error));
        }
    }

    #[test]
    fn native_range_copy_preserves_offsets_or_reports_unsupported_without_writing() {
        let root = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let bytes = vec![42; 131_077];
        let path = root.path().join("source");
        std::fs::write(&path, &bytes).unwrap();
        let mut source = File::open(&path).unwrap();
        let destination_path = root.path().join("destination");
        let mut destination = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&destination_path)
            .unwrap();
        destination.write_all_at(b"retained-prefix", 0).unwrap();
        let inode = destination.metadata().unwrap().ino();
        let prefix = b"retained-prefix".len() as u64;
        source.seek(SeekFrom::Start(3)).unwrap();
        destination.seek(SeekFrom::Start(5)).unwrap();
        let mut offset = prefix;
        while offset < bytes.len() as u64 {
            let length = (bytes.len() as u64 - offset).min(65_536) as usize;
            match copy_range(&source, &destination, offset, length).unwrap() {
                Some(copied) => {
                    assert!(copied > 0 && copied <= length);
                    offset += copied as u64;
                }
                None => {
                    // Unsupported filesystems are legitimate. Assert the
                    // contract here; the parent tests exercise fallback after
                    // actual copied bytes with an injected unsupported result.
                    assert_eq!(destination.metadata().unwrap().len(), offset);
                    break;
                }
            }
        }
        assert_eq!(source.stream_position().unwrap(), 3);
        assert_eq!(destination.stream_position().unwrap(), 5);
        assert_eq!(std::fs::metadata(&destination_path).unwrap().ino(), inode);
        let content = std::fs::read(&destination_path).unwrap();
        assert_eq!(&content[..prefix as usize], b"retained-prefix");
        assert_eq!(
            &content[prefix as usize..],
            &bytes[prefix as usize..offset as usize]
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}
