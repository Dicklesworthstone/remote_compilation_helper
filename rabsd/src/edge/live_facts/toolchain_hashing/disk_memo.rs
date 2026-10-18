//! Restart reuse of verified toolchain file digests, never toolchain authority.
//!
//! This owner-private, bounded journal is valid only in the SAME Linux boot,
//! mount namespace and user identity. Records bind the complete FileSig to the
//! existing typed CAS digest. The caller still enumerates the entire toolchain,
//! probes rustc, and checks every file and directory generation before and after
//! hashing. A reboot, namespace change, damaged journal, or unavailable lock
//! degrades to verified reads. No source bytes, action keys, or serving grants
//! are persisted here. Checksums detect damage, not a malicious same-user writer;
//! like the process-local memo, this assumes a trusted local filesystem whose
//! ctime changes on writes. Filesystem rollback is outside that contract.

use super::{FileSig, MAX_TOOLCHAIN_DIGESTS};
use rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN;
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const NAME: &str = "toolchain-digests.v1";
const MAGIC: &[u8; 8] = b"RABSTC01";
const HEADER_BYTES: usize = 96;
const RECORD_BYTES: usize = 120;

type Entries = HashMap<FileSig, TypedDigest>;

#[derive(Clone)]
struct Scope {
    boot: [u8; 36],
    mount_dev: u64,
    mount_ino: u64,
    uid: u32,
}

impl Scope {
    fn current() -> io::Result<Self> {
        // Do not treat a different procfs PID namespace as our own identity.
        let pid = std::fs::read_link("/proc/self")?;
        if pid.to_str().and_then(|pid| pid.parse::<u32>().ok()) != Some(std::process::id()) {
            return Err(invalid("procfs PID namespace mismatch"));
        }
        let mut boot = Vec::new();
        File::open("/proc/sys/kernel/random/boot_id")?
            .take(38)
            .read_to_end(&mut boot)?;
        if boot.last() == Some(&b'\n') {
            boot.pop();
        }
        if boot.len() != 36
            || !boot.iter().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
        {
            return Err(invalid("invalid kernel boot identity"));
        }
        let mount = std::fs::metadata("/proc/self/ns/mnt")?;
        Ok(Self {
            boot: boot
                .try_into()
                .map_err(|_| invalid("boot identity length"))?,
            mount_dev: mount.dev(),
            mount_ino: mount.ino(),
            uid: std::fs::metadata("/proc/self")?.uid(),
        })
    }

    fn header(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..44].copy_from_slice(&self.boot);
        bytes[44..52].copy_from_slice(&self.mount_dev.to_le_bytes());
        bytes[52..60].copy_from_slice(&self.mount_ino.to_le_bytes());
        bytes[60..64].copy_from_slice(&self.uid.to_le_bytes());
        // Include the digest contract, not just the boot identity: a future
        // object domain must never silently re-type old persisted digest bytes.
        let mut checksum = Sha256::new();
        checksum.update(b"rabs.toolchain-digest-journal.header.v1\0sha256-v1\0");
        checksum.update(ATP_OBJECT_CONTENT_DOMAIN.as_bytes());
        checksum.update([0]);
        checksum.update(&bytes[..64]);
        bytes[64..].copy_from_slice(&checksum.finalize());
        bytes
    }
}

fn invalid(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

fn private_root(root: &Path, uid: u32) -> io::Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "toolchain digest directory is not owner-controlled",
        ));
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn private_file(metadata: &std::fs::Metadata, uid: u32) -> io::Result<FileSig> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "toolchain digest journal is not a private regular file",
        ));
    }
    Ok(FileSig::of(metadata))
}

/// The file lock has one owner and never waits. An unavailable optimization
/// must not serialize unrelated daemons or hold up a compiler. The stable
/// journal inode is not renamed/unlinked; drop explicitly unlocks it, including
/// when another thread has forked but its child has not reached exec yet.
#[derive(Debug)]
pub(super) struct DiskMemo {
    file: File,
    root: PathBuf,
    root_identity: (u64, u64),
    path: PathBuf,
    uid: u32,
    header: [u8; HEADER_BYTES],
    expected: FileSig,
    records: usize,
    capacity: usize,
}

impl Drop for DiskMemo {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl DiskMemo {
    /// The live Cargo launcher supplies RABS_STATE_DIR. A missing/relative
    /// state directory never creates an alternate cache in the current cwd.
    /// RABS_TOOLCHAIN_DIGEST_CACHE=0 disables only this optimization.
    pub(super) fn configured() -> io::Result<Option<(Self, Entries)>> {
        if !cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )) || matches!(
            std::env::var("RABS_TOOLCHAIN_DIGEST_CACHE").as_deref(),
            Ok("0" | "off")
        ) {
            return Ok(None);
        }
        let Some(root) = std::env::var_os("RABS_STATE_DIR").map(PathBuf::from) else {
            return Ok(None);
        };
        if !root.is_absolute() {
            return Ok(None);
        }
        Self::open(&root, &Scope::current()?, MAX_TOOLCHAIN_DIGESTS).map(Some)
    }

    fn open(root: &Path, scope: &Scope, capacity: usize) -> io::Result<(Self, Entries)> {
        let root_identity = private_root(root, scope.uid)?;
        let path = root.join(NAME);
        let mut options = OpenOptions::new();
        options.read(true).write(true).mode(0o600);
        // Linux flags only on the qualified architectures. O_NOFOLLOW rejects
        // a final-component symlink race; O_NONBLOCK prevents a substituted
        // FIFO/device from turning an advisory open into an unbounded wait.
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        options.custom_flags(0o400000 | 0o4000);
        if !cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unqualified journal platform",
            ));
        }
        let file = match options.create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                private_file(&std::fs::symlink_metadata(&path)?, scope.uid)?;
                options.create_new(false).open(&path)?
            }
            Err(error) => return Err(error),
        };
        file.try_lock()
            .map_err(|error| io::Error::other(error.to_string()))?;
        // Install the unlocking guard before any fallible post-lock operation.
        let mut memo = Self {
            file,
            root: root.to_path_buf(),
            root_identity,
            path,
            uid: scope.uid,
            header: scope.header(),
            expected: FileSig {
                dev: 0,
                ino: 0,
                size: 0,
                mtime_ns: 0,
                ctime_ns: 0,
            },
            records: 0,
            capacity: capacity.min(MAX_TOOLCHAIN_DIGESTS),
        };
        memo.expected = memo.identity()?;
        let maximum = HEADER_BYTES + memo.capacity * RECORD_BYTES;
        if memo.expected.size() > maximum as u64 {
            return Err(invalid("toolchain digest journal exceeds its byte bound"));
        }
        let mut bytes = Vec::with_capacity(memo.expected.size() as usize);
        (&mut memo.file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        if memo.identity()? != memo.expected || bytes.len() as u64 != memo.expected.size() {
            return Err(invalid("toolchain digest journal changed while loading"));
        }
        if bytes.is_empty() {
            memo.reset()?;
            return Ok((memo, Entries::new()));
        }
        // Unknown/future formats are left untouched. A torn known header or
        // damaged current-scope record discards ALL hints, never just a failed
        // validation. The next warm must read the actual compiler bytes.
        if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
            return Err(invalid("unknown toolchain digest journal format"));
        }
        if bytes.len() < HEADER_BYTES || bytes[..HEADER_BYTES] != memo.header {
            memo.reset()?;
            return Ok((memo, Entries::new()));
        }
        let mut entries = Entries::new();
        for record in bytes[HEADER_BYTES..].as_chunks::<RECORD_BYTES>().0 {
            let Some((sig, digest)) = decode_record(&memo.header, record) else {
                memo.reset()?;
                return Ok((memo, Entries::new()));
            };
            if let Some(previous) = entries.insert(sig, digest.clone())
                && previous != digest
            {
                memo.reset()?;
                return Ok((memo, Entries::new()));
            }
            memo.records += 1;
        }
        // A crash can leave an incomplete FINAL append. Its bytes supply no
        // hint; retain the complete checked prefix and restore append alignment.
        let complete = HEADER_BYTES + memo.records * RECORD_BYTES;
        if bytes.len() != complete {
            memo.file.set_len(complete as u64)?;
        }
        memo.file.seek(SeekFrom::End(0))?;
        memo.expected = memo.identity()?;
        Ok((memo, entries))
    }

    fn identity(&self) -> io::Result<FileSig> {
        if private_root(&self.root, self.uid)? != self.root_identity {
            return Err(invalid("toolchain digest directory was replaced"));
        }
        let opened = private_file(&self.file.metadata()?, self.uid)?;
        let named = private_file(&std::fs::symlink_metadata(&self.path)?, self.uid)?;
        if opened != named {
            return Err(invalid("toolchain digest journal was replaced"));
        }
        Ok(opened)
    }

    fn reset(&mut self) -> io::Result<()> {
        if self.identity()? != self.expected {
            return Err(invalid("toolchain digest journal changed before reset"));
        }
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.header)?;
        self.records = 0;
        self.expected = self.identity()?;
        Ok(())
    }

    /// Called only after a descriptor-verified real read and a fresh pathname
    /// check. A full journal simply stops retaining new hints; memory reuse and
    /// real reads remain available. No fsync is needed for non-authoritative,
    /// same-boot hints: incomplete writes are detected on the next open.
    pub(super) fn remember(&mut self, sig: FileSig, digest: &TypedDigest) -> io::Result<()> {
        if self.records >= self.capacity {
            return Ok(());
        }
        if self.identity()? != self.expected {
            return Err(invalid("toolchain digest journal changed before append"));
        }
        let record = encode_record(&self.header, sig, digest)?;
        self.file.write_all(&record)?;
        self.records += 1;
        self.expected = self.identity()?;
        if self.expected.size() != (HEADER_BYTES + self.records * RECORD_BYTES) as u64 {
            return Err(invalid("toolchain digest journal append length mismatch"));
        }
        Ok(())
    }
}

fn encode_record(
    header: &[u8; HEADER_BYTES],
    sig: FileSig,
    digest: &TypedDigest,
) -> io::Result<[u8; RECORD_BYTES]> {
    if digest.algorithm != DigestAlgorithm::Sha256V1 || digest.domain != ATP_OBJECT_CONTENT_DOMAIN {
        return Err(invalid("unsupported persisted toolchain digest domain"));
    }
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(&sig.dev.to_le_bytes());
    bytes[8..16].copy_from_slice(&sig.ino.to_le_bytes());
    bytes[16..24].copy_from_slice(&sig.size.to_le_bytes());
    bytes[24..40].copy_from_slice(&sig.mtime_ns.to_le_bytes());
    bytes[40..56].copy_from_slice(&sig.ctime_ns.to_le_bytes());
    bytes[56..88].copy_from_slice(&digest.bytes);
    let mut checksum = Sha256::new();
    checksum.update(header);
    checksum.update(&bytes[..88]);
    bytes[88..].copy_from_slice(&checksum.finalize());
    Ok(bytes)
}

fn decode_record(header: &[u8; HEADER_BYTES], bytes: &[u8]) -> Option<(FileSig, TypedDigest)> {
    if bytes.len() != RECORD_BYTES {
        return None;
    }
    let mut checksum = Sha256::new();
    checksum.update(header);
    checksum.update(&bytes[..88]);
    let expected: [u8; 32] = checksum.finalize().into();
    if expected[..] != bytes[88..] {
        return None;
    }
    Some((
        FileSig {
            dev: u64::from_le_bytes(bytes[..8].try_into().ok()?),
            ino: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            size: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
            mtime_ns: i128::from_le_bytes(bytes[24..40].try_into().ok()?),
            ctime_ns: i128::from_le_bytes(bytes[40..56].try_into().ok()?),
        },
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: ATP_OBJECT_CONTENT_DOMAIN,
            bytes: bytes[56..88].try_into().ok()?,
        },
    ))
}

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::super::{DigestMemo, digest_stable_at, hash_files, lstat_regular};
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn fixture() -> (tempfile::TempDir, Scope, PathBuf, FileSig, TypedDigest) {
        let dir = crate::test_util::private_tempdir();
        let scope = Scope::current().unwrap();
        let path = dir.path().join("compiler-input");
        std::fs::write(&path, b"compiler bytes\0\xff").unwrap();
        let sig = lstat_regular(&path).unwrap();
        let digest = digest_stable_at(&path, sig).unwrap().1;
        (dir, scope, path, sig, digest)
    }

    fn restored(root: &Path, scope: &Scope) -> DigestMemo {
        let (disk, entries) = DiskMemo::open(root, scope, MAX_TOOLCHAIN_DIGESTS).unwrap();
        DigestMemo {
            entries: Mutex::new(entries),
            disk: Mutex::new(Some(disk)),
        }
    }

    #[test]
    fn restart_reuses_verified_digests_through_the_actual_hashing_pipeline() {
        let (dir, scope, path, sig, expected) = fixture();
        let files = [(path.as_path(), sig)];
        let busy = AtomicBool::new(false);
        let memo = restored(dir.path(), &scope);
        let reads = AtomicUsize::new(0);
        assert_eq!(
            hash_files(&files, &busy, &memo, |path, sig| {
                reads.fetch_add(1, Ordering::Relaxed);
                digest_stable_at(path, sig).map(|(_, digest)| digest)
            })
            .unwrap()
            .as_slice(),
            std::slice::from_ref(&expected)
        );
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        drop(memo);

        let restarted = restored(dir.path(), &scope);
        assert_eq!(restarted.entries.lock().unwrap().len(), 1);
        assert_eq!(
            hash_files(&files, &busy, &restarted, |_, _| {
                panic!("unchanged file bytes were reread after restarting the memo")
            })
            .unwrap(),
            [expected]
        );
    }

    #[test]
    fn restart_does_not_reuse_a_changed_file_or_adopt_a_stale_observation() {
        let (dir, scope, path, sig, expected) = fixture();
        let (mut disk, _) = DiskMemo::open(dir.path(), &scope, 8).unwrap();
        disk.remember(sig, &expected).unwrap();
        drop(disk);
        std::fs::write(&path, b"different compiler bytes").unwrap();
        let refreshed = lstat_regular(&path).unwrap();
        assert_ne!(sig, refreshed);
        let restarted = restored(dir.path(), &scope);
        let busy = AtomicBool::new(false);
        assert!(
            hash_files(&[(path.as_path(), sig)], &busy, &restarted, |_, _| {
                panic!("stale file observation reached a read")
            })
            .is_err()
        );
        let reads = AtomicUsize::new(0);
        let actual = hash_files(
            &[(path.as_path(), refreshed)],
            &busy,
            &restarted,
            |path, sig| {
                reads.fetch_add(1, Ordering::Relaxed);
                digest_stable_at(path, sig).map(|(_, digest)| digest)
            },
        )
        .unwrap();
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        assert_ne!(actual, [expected]);
    }

    #[test]
    fn a_new_boot_or_mount_namespace_discards_all_old_hints() {
        for boot_change in [true, false] {
            let (dir, scope, _, sig, digest) = fixture();
            let (mut disk, _) = DiskMemo::open(dir.path(), &scope, 8).unwrap();
            disk.remember(sig, &digest).unwrap();
            drop(disk);
            let mut other = scope.clone();
            if boot_change {
                other.boot[0] = if other.boot[0] == b'0' { b'1' } else { b'0' };
            } else {
                other.mount_ino = other.mount_ino.wrapping_add(1);
            }
            let (mut disk, entries) = DiskMemo::open(dir.path(), &other, 8).unwrap();
            assert!(entries.is_empty());
            assert_eq!(disk.file.metadata().unwrap().len(), HEADER_BYTES as u64);
            disk.remember(sig, &digest).unwrap();
            drop(disk);
            assert_eq!(
                DiskMemo::open(dir.path(), &other, 8).unwrap().1.get(&sig),
                Some(&digest)
            );
        }
    }

    #[test]
    fn damaged_record_or_conflicting_identity_discards_the_entire_journal() {
        for conflicting in [false, true] {
            let (dir, scope, _, sig, digest) = fixture();
            let (mut disk, _) = DiskMemo::open(dir.path(), &scope, 8).unwrap();
            disk.remember(sig, &digest).unwrap();
            let path = disk.path.clone();
            if conflicting {
                let mut other = digest.clone();
                other.bytes[0] ^= 1;
                // Exercise the decoder's contradiction defense, independent of
                // the enclosing memory memo, which refuses this before append.
                disk.remember(sig, &other).unwrap();
                drop(disk);
            } else {
                drop(disk);
                let mut bytes = std::fs::read(&path).unwrap();
                bytes[HEADER_BYTES + 56] ^= 1;
                std::fs::write(&path, bytes).unwrap();
            }
            let (mut recovered, entries) = DiskMemo::open(dir.path(), &scope, 8).unwrap();
            assert!(
                entries.is_empty(),
                "damage must not preserve a partial set of hints"
            );
            assert_eq!(std::fs::metadata(&path).unwrap().len(), HEADER_BYTES as u64);
            recovered.remember(sig, &digest).unwrap();
            drop(recovered);
            assert_eq!(
                DiskMemo::open(dir.path(), &scope, 8).unwrap().1.get(&sig),
                Some(&digest)
            );
        }
    }

    #[test]
    fn a_torn_final_append_preserves_only_complete_checked_records() {
        let (dir, scope, _, sig, digest) = fixture();
        let (mut disk, _) = DiskMemo::open(dir.path(), &scope, 8).unwrap();
        disk.remember(sig, &digest).unwrap();
        let path = disk.path.clone();
        drop(disk);
        let mut next = sig;
        next.ino = next.ino.wrapping_add(1);
        let record = encode_record(&scope.header(), next, &digest).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&record[..57])
            .unwrap();
        let (mut disk, entries) = DiskMemo::open(dir.path(), &scope, 8).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries.get(&sig), Some(&digest));
        assert_eq!(
            disk.file.metadata().unwrap().len(),
            (HEADER_BYTES + RECORD_BYTES) as u64
        );
        disk.remember(next, &digest).unwrap();
        drop(disk);
        let (_, entries) = DiskMemo::open(dir.path(), &scope, 8).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.get(&next), Some(&digest));
    }

    #[test]
    fn private_identity_checks_reject_links_and_permissive_files_without_repair() {
        for mode in ["symlink", "hardlink", "permissions"] {
            let (dir, scope, _, _, _) = fixture();
            let path = dir.path().join(NAME);
            let target = dir.path().join("foreign-file");
            std::fs::write(&target, b"leave untouched").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
            match mode {
                "symlink" => std::os::unix::fs::symlink(&target, &path).unwrap(),
                "hardlink" => std::fs::hard_link(&target, &path).unwrap(),
                _ => {
                    std::fs::write(&path, b"not private").unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
            }
            assert!(DiskMemo::open(dir.path(), &scope, 8).is_err());
            assert_eq!(std::fs::read(&target).unwrap(), b"leave untouched");
            if mode == "permissions" {
                assert_eq!(std::fs::read(&path).unwrap(), b"not private");
            }
        }
    }

    #[test]
    fn journal_ownership_is_exclusive_and_drop_releases_it() {
        let (dir, scope, _, sig, digest) = fixture();
        let (mut first, _) = DiskMemo::open(dir.path(), &scope, 8).unwrap();
        first.remember(sig, &digest).unwrap();
        assert!(DiskMemo::open(dir.path(), &scope, 8).is_err());
        first.remember(sig, &digest).unwrap();
        drop(first);
        assert_eq!(
            DiskMemo::open(dir.path(), &scope, 8).unwrap().1.get(&sig),
            Some(&digest)
        );
    }

    #[test]
    fn full_journal_is_bounded_and_does_not_prevent_later_real_reads() {
        let (dir, scope, _, sig, digest) = fixture();
        let (mut disk, _) = DiskMemo::open(dir.path(), &scope, 2).unwrap();
        for index in 0..100 {
            let mut sig = sig;
            sig.ino = index;
            disk.remember(sig, &digest).unwrap();
        }
        assert_eq!(
            disk.file.metadata().unwrap().len(),
            (HEADER_BYTES + 2 * RECORD_BYTES) as u64
        );
        drop(disk);
        assert_eq!(DiskMemo::open(dir.path(), &scope, 2).unwrap().1.len(), 2);
    }

    #[test]
    fn unknown_formats_and_oversized_files_are_left_untouched() {
        for bytes in [
            b"future-format-v2".to_vec(),
            vec![0; HEADER_BYTES + 2 * RECORD_BYTES + 1],
        ] {
            let (dir, scope, _, _, _) = fixture();
            let path = dir.path().join(NAME);
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap()
                .write_all(&bytes)
                .unwrap();
            assert!(DiskMemo::open(dir.path(), &scope, 2).is_err());
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn signed_nanosecond_generations_and_typed_domain_round_trip_exactly() {
        let (_, scope, _, mut sig, digest) = fixture();
        sig.dev = u64::MAX;
        sig.ino = u64::MAX;
        sig.size = u64::MAX;
        sig.mtime_ns = i128::MIN;
        sig.ctime_ns = i128::MAX;
        let header = scope.header();
        let encoded = encode_record(&header, sig, &digest).unwrap();
        assert_eq!(
            decode_record(&header, &encoded),
            Some((sig, digest.clone()))
        );
        let mut other_scope = scope;
        other_scope.mount_dev ^= 1;
        assert!(decode_record(&other_scope.header(), &encoded).is_none());
        let mut foreign = digest;
        foreign.domain = "not-a-toolchain-content-domain";
        assert!(encode_record(&header, sig, &foreign).is_err());
    }
}
