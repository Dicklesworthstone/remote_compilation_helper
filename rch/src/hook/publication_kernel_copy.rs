//! Kernel-assisted copies; neither an ownership check nor a publication.
//!
//! The parent validates the complete source/prefix before the first call,
//! checks held identities before each bounded chunk, and hashes/syncs the
//! complete temporary afterward. Successful kernel transfer is never proof
//! of artifact content, and never advances the durable recovery journal.
//! Whole-file clones require an already verified empty private destination;
//! an unsupported result still requires the caller to prove it stayed empty.

use std::fs::File;
use std::io;

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "sparc", target_arch = "sparc64"))
))]
fn clone_permits_fallback(error: rustix::io::Errno) -> bool {
    use rustix::io::Errno;
    matches!(
        error,
        Errno::NOSYS | Errno::NOTTY | Errno::XDEV | Errno::OPNOTSUPP | Errno::INVAL | Errno::PERM
    )
}

/// Attempt an independent CoW inode without requiring a second payload's free
/// capacity. `false` means unsupported or denied by policy, not proof that the
/// destination is still empty. Neither errors nor fallback results authorize
/// truncation; the caller retains and revalidates the exact destination.
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "sparc", target_arch = "sparc64"))
))]
pub(super) fn clone_file(source: &File, destination: &File) -> io::Result<bool> {
    match rustix::fs::ioctl_ficlone(destination, source) {
        Ok(()) => Ok(true),
        Err(error) if clone_permits_fallback(error) => Ok(false),
        // Seccomp may deny this optional ioctl with EPERM while permitting
        // ordinary copies. The caller proves the destination stayed empty;
        // fallback writes still enforce immutable-inode and access rules.
        // EBADF can describe descriptor permissions and remains an error.
        // EINTR may leave a modified destination, so do not retry implicitly.
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(all(
    target_os = "linux",
    not(any(target_arch = "sparc", target_arch = "sparc64"))
)))]
pub(super) fn clone_file(_source: &File, _destination: &File) -> io::Result<bool> {
    Ok(false)
}

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

    #[cfg(not(any(target_arch = "sparc", target_arch = "sparc64")))]
    #[test]
    fn unsupported_or_policy_denied_whole_file_clones_allow_checked_fallback() {
        use rustix::io::Errno;
        for error in [
            Errno::NOSYS,
            Errno::NOTTY,
            Errno::XDEV,
            Errno::OPNOTSUPP,
            Errno::INVAL,
            Errno::PERM,
        ] {
            assert!(clone_permits_fallback(error));
        }
        for error in [
            Errno::NOSPC,
            Errno::IO,
            Errno::ACCESS,
            Errno::BADF,
            Errno::INTR,
        ] {
            assert!(!clone_permits_fallback(error));
        }
    }

    #[test]
    fn native_whole_clone_preserves_offsets_and_independent_inode_or_is_unsupported() {
        use std::os::unix::fs::PermissionsExt;

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
        destination
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let before = destination.metadata().unwrap();
        source.seek(SeekFrom::Start(3)).unwrap();
        destination.seek(SeekFrom::Start(5)).unwrap();
        let cloned = clone_file(&source, &destination).unwrap();
        assert_eq!(source.stream_position().unwrap(), 3);
        assert_eq!(destination.stream_position().unwrap(), 5);
        let after = destination.metadata().unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(after.nlink(), 1);
        assert_eq!(after.mode() & 0o7777, 0o600);
        assert_ne!(source.metadata().unwrap().ino(), after.ino());
        if cloned {
            assert_eq!(std::fs::read(&destination_path).unwrap(), bytes);
            destination.write_all_at(b"private change", 0).unwrap();
            assert_ne!(std::fs::read(&destination_path).unwrap(), bytes);
        } else {
            assert!(super::super::same_version(&before, &after));
            assert!(std::fs::read(&destination_path).unwrap().is_empty());
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    #[ignore = "requires RCH_REFLINK_TEST_ROOT on a real reflink-capable filesystem"]
    fn real_whole_clone_is_required_and_mutations_remain_private() {
        use std::os::unix::fs::PermissionsExt;

        let root_path = std::env::var_os("RCH_REFLINK_TEST_ROOT")
            .expect("set RCH_REFLINK_TEST_ROOT to a real reflink-capable filesystem");
        let root = tempfile::Builder::new()
            .prefix("rch-publication-reflink-")
            .disable_cleanup(true)
            .tempdir_in(root_path)
            .unwrap();
        let bytes: Vec<u8> = (0..2_097_169).map(|index| (index % 251) as u8).collect();
        let source_path = root.path().join("source");
        std::fs::write(&source_path, &bytes).unwrap();
        std::fs::set_permissions(&source_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let source = File::open(&source_path).unwrap();
        let before = source.metadata().unwrap();
        let destination_path = root.path().join("destination");
        let destination = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&destination_path)
            .unwrap();
        destination
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(
            clone_file(&source, &destination).unwrap(),
            "copy fallback cannot satisfy the native reflink gate"
        );
        assert!(super::super::same_version(
            &before,
            &source.metadata().unwrap()
        ));
        assert_ne!(before.ino(), destination.metadata().unwrap().ino());
        assert_eq!(destination.metadata().unwrap().nlink(), 1);
        assert_eq!(std::fs::read(&destination_path).unwrap(), bytes);
        destination.write_all_at(b"private change", 17).unwrap();
        destination.set_len(bytes.len() as u64 - 13).unwrap();
        destination
            .set_permissions(std::fs::Permissions::from_mode(0o640))
            .unwrap();
        destination.sync_all().unwrap();
        assert!(super::super::same_version(
            &before,
            &source.metadata().unwrap()
        ));
        assert_eq!(std::fs::read(&source_path).unwrap(), bytes);
        assert_eq!(destination.metadata().unwrap().mode() & 0o7777, 0o640);
    }

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
