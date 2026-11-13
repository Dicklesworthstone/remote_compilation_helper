//! Read-only cancellation observation and exact source/pair release framing.
//!
//! The surrounding terminal owns the kernel locks and durable retirement.
//! A valid cancellation snapshot yields only those transient locks (75); it
//! neither acknowledges release nor changes a claim. Ambiguous snapshots keep
//! waiting for explicit release or a later coherent cancellation fence.

use std::ffi::OsString;

/// Run before the async runtime or optional logging initialization.
pub fn main(arguments: &[OsString]) -> i32 {
    #[cfg(unix)]
    {
        unix::main(arguments)
    }
    #[cfg(not(unix))]
    {
        let _ = arguments;
        eprintln!("RCH: source release wait failed: native cancellation observation requires Unix");
        73
    }
}

#[cfg(unix)]
mod unix {
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::PathBuf;

    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::fs::{AtFlags, CWD, Dir, FileType, FlockOperation, Mode, OFlags, Stat};
    use rustix::io::Errno;
    use sha2::{Digest, Sha256};

    const LIMIT: usize = 32 * 1024 * 1024;
    const PROBE_REPLY: &[u8] = b"rch-wkr source-release v1\n";
    const REFUSED: i32 = 73;
    const CANCELLED: i32 = 75;
    const CHILD_NAMES: [&str; 3] = ["cancelled", "released", "quarantine"];
    type Result<T> = std::result::Result<T, io::Error>;

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn diagnostic(message: &str) {
        let stderr = rustix::stdio::stderr();
        if let Ok(flags) = rustix::fs::fcntl_getfl(stderr)
            && rustix::fs::fcntl_setfl(stderr, flags | OFlags::NONBLOCK).is_ok()
        {
            let mut bytes = message.as_bytes().to_vec();
            bytes.truncate(4095);
            bytes.push(b'\n');
            let _ = rustix::io::write(stderr, &bytes);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReleaseMode {
        Source,
        Pair,
        CleanupPair,
    }

    struct Request {
        mode: ReleaseMode,
        registry: PathBuf,
        token: String,
        selector: OsString,
        expected: Vec<u8>,
    }

    impl Request {
        fn parse(arguments: &[OsString]) -> Result<Self> {
            if arguments.len() != 6 || arguments[0] != "wait" {
                return Err(invalid("invalid source release arguments"));
            }
            let mode = match arguments[1].as_bytes() {
                b"source" => ReleaseMode::Source,
                b"pair" => ReleaseMode::Pair,
                b"cleanup-pair" => ReleaseMode::CleanupPair,
                _ => return Err(invalid("invalid source release identity or mode")),
            };
            let token = arguments[3].as_bytes();
            if !(1..=128).contains(&token.len())
                || !token.iter().all(|byte| lower_hex(*byte) || *byte == b'-')
            {
                return Err(invalid("invalid source release identity or mode"));
            }
            let selector = arguments[4].as_bytes();
            let prefix = if mode == ReleaseMode::Source {
                if selector.len() != 64 || !selector.iter().all(|byte| lower_hex(*byte)) {
                    return Err(invalid("invalid source release digest"));
                }
                "RCH_SOURCE_AUTHORITY_RELEASE:"
            } else {
                if !canonical_root(selector) {
                    return Err(invalid("invalid source pair root"));
                }
                "RCH_SOURCE_PAIR_RELEASE:"
            };
            let token = std::str::from_utf8(token)
                .map_err(|_| invalid("invalid source release identity"))?
                .to_owned();
            let release = format!("{prefix}{token}");
            if arguments[5].as_bytes() != release.as_bytes() {
                return Err(invalid("invalid source release request"));
            }
            Ok(Self {
                mode,
                registry: PathBuf::from(&arguments[2]),
                token,
                selector: arguments[4].clone(),
                expected: format!("{release}\n").into_bytes(),
            })
        }
    }

    fn lower_hex(byte: u8) -> bool {
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
    }

    fn canonical_root(root: &[u8]) -> bool {
        if !root.starts_with(b"/") || root.iter().any(|byte| matches!(*byte, 0 | b'\n' | b'\r')) {
            return false;
        }
        root == b"/"
            || root[1..]
                .split(|byte| *byte == b'/')
                .all(|part| !part.is_empty() && part != b"." && part != b"..")
    }

    pub(super) fn main(arguments: &[OsString]) -> i32 {
        if arguments.len() == 1 && arguments[0] == "probe" {
            return match rustix::io::write(rustix::stdio::stdout(), PROBE_REPLY) {
                Ok(length) if length == PROBE_REPLY.len() => 0,
                _ => REFUSED,
            };
        }
        match Request::parse(arguments).and_then(|request| wait(&request)) {
            Ok(status) => status,
            Err(error) => {
                diagnostic(&format!("RCH: source release wait failed: {error}"));
                REFUSED
            }
        }
    }

    fn wait(request: &Request) -> Result<i32> {
        let mut incoming = Vec::new();
        let mut descriptors = [PollFd::from_borrowed_fd(
            rustix::stdio::stdin(),
            PollFlags::IN,
        )];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 250_000_000,
        };
        loop {
            // Cleanup pairs deliberately ignore cancellation. They retain the
            // overlap lock until their explicit retirement protocol completes.
            if request.mode != ReleaseMode::CleanupPair
                && snapshot(request, |_| Ok(())).unwrap_or(false)
            {
                diagnostic(
                    "RCH: source invocation cancelled; yielding kernel locks without retiring ownership",
                );
                return Ok(CANCELLED);
            }
            match poll(&mut descriptors, Some(&timeout)) {
                Ok(0) | Err(Errno::INTR) => continue,
                Ok(_) => {}
                Err(error) => return Err(error.into()),
            }
            let mut bytes = [0_u8; 4096];
            let length = match rustix::io::read(rustix::stdio::stdin(), &mut bytes) {
                Ok(length) => length,
                Err(Errno::AGAIN | Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            };
            if length == 0 {
                return Err(invalid(
                    "source release requester disconnected before retirement",
                ));
            }
            incoming.extend_from_slice(&bytes[..length]);
            if !request.expected.starts_with(&incoming) {
                return Err(invalid("unexpected source release input"));
            }
            if incoming == request.expected {
                // No EOF requirement: the terminal must resume and retire its
                // durable owner while the source control connection is open.
                return Ok(0);
            }
        }
    }

    fn directory_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
    }

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    fn same_generation(left: &Stat, right: &Stat) -> bool {
        same_inode(left, right)
            && left.st_mode == right.st_mode
            && left.st_uid == right.st_uid
            && left.st_gid == right.st_gid
            && left.st_nlink == right.st_nlink
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }

    struct Directory {
        descriptor: OwnedFd,
        identity: Stat,
    }

    impl Directory {
        fn new(descriptor: OwnedFd) -> Result<Self> {
            let identity = rustix::fs::fstat(&descriptor)?;
            if FileType::from_raw_mode(identity.st_mode) != FileType::Directory {
                return Err(invalid("invalid cancellation directory"));
            }
            Ok(Self {
                descriptor,
                identity,
            })
        }

        fn verify(&self, parent: impl AsFd, name: impl rustix::path::Arg) -> Result<()> {
            let retained = rustix::fs::fstat(&self.descriptor)?;
            let named = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(named.st_mode) != FileType::Directory
                || !same_inode(&self.identity, &retained)
                || !same_inode(&retained, &named)
            {
                return Err(invalid("changed cancellation directory binding"));
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum Kind {
        Claim,
        Pending,
        Cancelling,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Observation {
        BeforeInventory,
        AfterRecordRead,
        BeforeFinalCheck,
    }

    fn listing(directory: &Directory, prefix: &[u8]) -> Result<Vec<OsString>> {
        let mut names = Vec::new();
        for entry in Dir::read_from(&directory.descriptor)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name.starts_with(prefix)
                && [b".claim".as_slice(), b".pending", b".cancelling"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
            {
                names.push(OsString::from_vec(name.to_vec()));
            }
        }
        Ok(names)
    }

    fn record_name<'a>(name: &'a OsStr, prefix: &[u8]) -> Result<(&'a [u8], Kind)> {
        let suffix = name
            .as_bytes()
            .strip_prefix(prefix)
            .ok_or_else(|| invalid("invalid cancellation record identity"))?;
        if suffix.len() < 65
            || suffix[64] != b'.'
            || !suffix[..64].iter().all(|byte| lower_hex(*byte))
        {
            return Err(invalid("invalid cancellation record name"));
        }
        let kind = match &suffix[65..] {
            b"claim" => Kind::Claim,
            b"pending" => Kind::Pending,
            b"cancelling" => Kind::Cancelling,
            _ => return Err(invalid("invalid cancellation record extension")),
        };
        Ok((&suffix[..64], kind))
    }

    fn candidate(directory: &Directory, name: &str) -> Result<bool> {
        match rustix::fs::statat(&directory.descriptor, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    struct Record {
        file: File,
        identity: Stat,
        directory: usize,
        name: OsString,
    }

    impl Record {
        fn verify(&self, directories: &[Directory]) -> Result<()> {
            let current = rustix::fs::fstat(&self.file)?;
            let named = rustix::fs::statat(
                &directories[self.directory].descriptor,
                &self.name,
                AtFlags::SYMLINK_NOFOLLOW,
            )?;
            if !same_generation(&self.identity, &current) || !same_generation(&current, &named) {
                return Err(invalid("changed cancellation record"));
            }
            Ok(())
        }
    }

    fn read_record(
        directories: &[Directory],
        directory: usize,
        name: OsString,
        digest: &[u8],
        observe: &mut impl FnMut(Observation) -> Result<()>,
    ) -> Result<(Record, Vec<u8>)> {
        let fd = rustix::fs::openat(
            &directories[directory].descriptor,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let identity = rustix::fs::fstat(&fd)?;
        if FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
            || identity.st_size <= 0
            || identity.st_size > LIMIT as _
        {
            return Err(invalid("invalid cancellation record"));
        }
        let mut file = File::from(fd);
        let mut content = Vec::with_capacity(identity.st_size as usize);
        file.by_ref()
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut content)?;
        observe(Observation::AfterRecordRead)?;
        let record = Record {
            file,
            identity,
            directory,
            name,
        };
        record.verify(directories)?;
        if content.len() != identity.st_size as usize || !content.ends_with(b"\n") {
            return Err(invalid("changed cancellation record"));
        }
        let actual: String = Sha256::digest(&content)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if actual.as_bytes() != digest
            || std::str::from_utf8(&content).is_err()
            || !content[..content.len() - 1]
                .split(|byte| *byte == b'\n')
                .all(canonical_root)
        {
            return Err(invalid("invalid cancellation roots or digest"));
        }
        Ok((record, content))
    }

    fn snapshot(
        request: &Request,
        mut observe: impl FnMut(Observation) -> Result<()>,
    ) -> Result<bool> {
        let root = Directory::new(rustix::fs::open(
            &request.registry,
            directory_flags(),
            Mode::empty(),
        )?)?;
        let mutex = rustix::fs::openat(
            &root.descriptor,
            "metadata.lock",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        // Never wait for an activity mutex while retaining source locks.
        rustix::fs::flock(&mutex, FlockOperation::NonBlockingLockShared)?;
        let mutex_identity = rustix::fs::fstat(&mutex)?;
        let named =
            rustix::fs::statat(&root.descriptor, "metadata.lock", AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(mutex_identity.st_mode) != FileType::RegularFile
            || !same_inode(&mutex_identity, &named)
        {
            return Err(invalid("invalid cancellation metadata mutex"));
        }
        let cancelled = Directory::new(rustix::fs::openat(
            &root.descriptor,
            "cancelled",
            directory_flags(),
            Mode::empty(),
        )?)?;
        let mut directories = vec![root, cancelled];
        let prefix = format!("{}.", request.token).into_bytes();
        let mut names = Vec::new();
        if request.mode == ReleaseMode::Source {
            let digest = request
                .selector
                .to_str()
                .ok_or_else(|| invalid("invalid source digest"))?;
            // Two constant-cost name probes for a healthy source holder. Do not
            // inventory retained receipts unless this invocation has a fence.
            let active = candidate(
                &directories[0],
                &format!("{}.{digest}.cancelling", request.token),
            )?;
            let terminal = candidate(
                &directories[1],
                &format!("{}.{digest}.claim", request.token),
            )?;
            if !active && !terminal {
                return Ok(false);
            }
            observe(Observation::BeforeInventory)?;
            names.push(listing(&directories[0], &prefix)?);
            names.push(listing(&directories[1], &prefix)?);
        } else {
            observe(Observation::BeforeInventory)?;
            names.push(listing(&directories[0], &prefix)?);
            names.push(listing(&directories[1], &prefix)?);
            if !names[0]
                .iter()
                .any(|name| name.as_bytes().ends_with(b".cancelling"))
                && !names[1]
                    .iter()
                    .any(|name| name.as_bytes().ends_with(b".claim"))
            {
                return Ok(false);
            }
        }
        for name in &CHILD_NAMES[1..] {
            let directory = Directory::new(rustix::fs::openat(
                &directories[0].descriptor,
                *name,
                directory_flags(),
                Mode::empty(),
            )?)?;
            names.push(listing(&directory, &prefix)?);
            directories.push(directory);
        }
        let mut records = BTreeMap::new();
        let mut one_digest: Option<Vec<u8>> = None;
        for (directory, names) in names.into_iter().enumerate() {
            for name in names {
                let (digest, kind) = record_name(&name, &prefix)?;
                if one_digest
                    .as_deref()
                    .is_some_and(|existing| existing != digest)
                {
                    return Ok(false);
                }
                one_digest = Some(digest.to_vec());
                if records.insert((directory, kind), name).is_some() {
                    return Ok(false);
                }
            }
        }
        let Some(digest) = one_digest else {
            return Ok(false);
        };
        if request.mode == ReleaseMode::Source && digest != request.selector.as_bytes() {
            return Ok(false);
        }
        let active = records.contains_key(&(0, Kind::Claim));
        let cancelling = records.contains_key(&(0, Kind::Cancelling));
        let cancelled = records.contains_key(&(1, Kind::Claim));
        let coherent = (records.len() == 1 && cancelled)
            || (records.len() == 2 && cancelling && (active || cancelled));
        if !coherent {
            return Ok(false);
        }
        let mut expected: Option<Vec<u8>> = None;
        let mut retained = Vec::new();
        for ((directory, _), name) in records {
            let (record, content) =
                read_record(&directories, directory, name, &digest, &mut observe)?;
            if expected
                .as_deref()
                .is_some_and(|previous| previous != content)
                || (request.mode == ReleaseMode::Pair
                    && !content[..content.len() - 1]
                        .split(|byte| *byte == b'\n')
                        .any(|root| root == request.selector.as_bytes()))
            {
                return Ok(false);
            }
            expected = Some(content);
            retained.push(record);
        }
        observe(Observation::BeforeFinalCheck)?;
        // The shared mutex excludes cooperating writers. Also refuse a new
        // conflicting record for this identity if an out-of-protocol writer
        // changed the observed set while its bytes were being checked. Ignore
        // unrelated directory churn, including other identities/activity locks.
        for (index, directory) in directories.iter().enumerate() {
            let mut current = listing(directory, &prefix)?;
            let mut expected: Vec<_> = retained
                .iter()
                .filter(|record| record.directory == index)
                .map(|record| record.name.clone())
                .collect();
            current.sort();
            expected.sort();
            if current != expected {
                return Ok(false);
            }
        }
        for record in &retained {
            record.verify(&directories)?;
        }
        for (directory, name) in directories[1..].iter().zip(CHILD_NAMES) {
            directory.verify(&directories[0].descriptor, name)?;
        }
        directories[0].verify(CWD, &request.registry)?;
        let current = rustix::fs::fstat(&mutex)?;
        let named = rustix::fs::statat(
            &directories[0].descriptor,
            "metadata.lock",
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        Ok(same_inode(&mutex_identity, &current) && same_inode(&current, &named))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::symlink;

        struct Registry {
            owner: tempfile::TempDir,
            root: PathBuf,
            content: Vec<u8>,
            digest: String,
        }

        impl Registry {
            fn new(content: &[u8]) -> Self {
                let owner = tempfile::Builder::new()
                    .disable_cleanup(true)
                    .tempdir()
                    .unwrap();
                let root = owner.path().join("registry");
                std::fs::create_dir(&root).unwrap();
                std::fs::write(root.join("metadata.lock"), b"").unwrap();
                for child in CHILD_NAMES {
                    std::fs::create_dir(root.join(child)).unwrap();
                }
                let digest = Sha256::digest(content)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                Self {
                    owner,
                    root,
                    content: content.to_vec(),
                    digest,
                }
            }

            fn record(&self, place: &str, extension: &str) -> PathBuf {
                let path = self
                    .root
                    .join(place)
                    .join(format!("abc-123.{}.{extension}", self.digest));
                std::fs::write(&path, &self.content).unwrap();
                path
            }

            fn request(&self, mode: &str, selector: &str) -> Request {
                let prefix = if mode == "source" {
                    "RCH_SOURCE_AUTHORITY_RELEASE"
                } else {
                    "RCH_SOURCE_PAIR_RELEASE"
                };
                Request::parse(&[
                    "wait".into(),
                    mode.into(),
                    self.root.clone().into_os_string(),
                    "abc-123".into(),
                    selector.into(),
                    format!("{prefix}:abc-123").into(),
                ])
                .unwrap()
            }

            fn observed(&self) -> bool {
                snapshot(&self.request("source", &self.digest), |_| Ok(())).unwrap_or(false)
            }
        }

        #[test]
        fn validates_canonical_roots_and_identity_before_waiting() {
            for root in [b"/".as_slice(), b"/literal ' root", b"/a/b"] {
                assert!(canonical_root(root));
            }
            for root in [
                b"".as_slice(),
                b"relative",
                b"//a",
                b"/a/",
                b"/a/../b",
                b"/./a",
                b"/a\n",
                b"/a\0",
            ] {
                assert!(!canonical_root(root));
            }
            let registry = Registry::new(b"/root\n");
            for token in ["", "UPPER", "x", "abc\n"] {
                assert!(
                    Request::parse(&[
                        "wait".into(),
                        "source".into(),
                        registry.root.clone().into_os_string(),
                        token.into(),
                        registry.digest.clone().into(),
                        format!("RCH_SOURCE_AUTHORITY_RELEASE:{token}").into()
                    ])
                    .is_err()
                );
            }
        }

        #[test]
        fn accepts_only_the_three_cancellation_state_sets() {
            for state in 0..3 {
                let registry = Registry::new(b"/root\n/dependency\n");
                if state == 0 {
                    registry.record("", "claim");
                } else {
                    registry.record("cancelled", "claim");
                }
                if state != 1 {
                    registry.record("", "cancelling");
                }
                assert!(registry.observed(), "state {state}");
            }
            for extension in ["claim", "cancelling", "pending"] {
                let registry = Registry::new(b"/root\n");
                registry.record("", extension);
                assert!(!registry.observed(), "lone {extension}");
            }
        }

        #[test]
        fn healthy_source_uses_candidate_probes_without_directory_inventory() {
            let registry = Registry::new(b"/root\n");
            registry.record("", "claim");
            assert!(
                !snapshot(&registry.request("source", &registry.digest), |stage| {
                    assert_ne!(stage, Observation::BeforeInventory);
                    Ok(())
                })
                .unwrap()
            );
        }

        #[test]
        fn ignores_other_invocations_but_refuses_conflicting_own_states() {
            for (place, extension) in [
                ("", "pending"),
                ("released", "claim"),
                ("quarantine", "claim"),
            ] {
                let registry = Registry::new(b"/root\n");
                registry.record("", "claim");
                registry.record("", "cancelling");
                std::fs::write(
                    registry
                        .root
                        .join(format!("def-456.{}.pending", registry.digest)),
                    b"unrelated",
                )
                .unwrap();
                assert!(registry.observed());
                registry.record(place, extension);
                assert!(!registry.observed(), "conflicting {place}/{extension}");
            }
        }

        #[test]
        fn requires_one_digest_and_exact_hash_bound_utf8_root_bytes() {
            let registry = Registry::new(b"/root\n");
            registry.record("", "claim");
            registry.record("", "cancelling");
            std::fs::write(
                registry
                    .root
                    .join(format!("abc-123.{}.claim", "0".repeat(64))),
                &registry.content,
            )
            .unwrap();
            assert!(!registry.observed());
            for content in [
                b"relative\n".as_slice(),
                b"/a/../b\n",
                b"/a\n\n",
                b"/a\xff\n",
                b"/a",
            ] {
                let invalid = Registry::new(content);
                invalid.record("cancelled", "claim");
                assert!(!invalid.observed(), "invalid root bytes {content:?}");
            }
            let corrupt = Registry::new(b"/root\n");
            let record = corrupt.record("cancelled", "claim");
            std::fs::write(record, b"/different\n").unwrap();
            assert!(!corrupt.observed());
        }

        #[test]
        fn pair_handoff_requires_literal_membership_in_every_record() {
            let registry = Registry::new(b"/root\n/dependency with spaces\n");
            registry.record("", "claim");
            registry.record("", "cancelling");
            assert!(
                snapshot(
                    &registry.request("pair", "/dependency with spaces"),
                    |_| Ok(())
                )
                .unwrap()
            );
            assert!(!snapshot(&registry.request("pair", "/different"), |_| Ok(())).unwrap());
        }

        #[test]
        fn busy_metadata_mutex_refuses_snapshot_without_waiting() {
            let registry = Registry::new(b"/root\n");
            registry.record("cancelled", "claim");
            let mutex = File::open(registry.root.join("metadata.lock")).unwrap();
            rustix::fs::flock(&mutex, FlockOperation::NonBlockingLockExclusive).unwrap();
            assert!(!registry.observed());
            drop(mutex);
            assert!(registry.observed());
        }

        #[test]
        fn rejects_special_or_oversized_cancellation_records_without_blocking() {
            let registry = Registry::new(b"/root\n");
            let target = registry.owner.path().join("outside");
            std::fs::write(&target, &registry.content).unwrap();
            let name = registry
                .root
                .join("cancelled")
                .join(format!("abc-123.{}.claim", registry.digest));
            symlink(&target, &name).unwrap();
            assert!(!registry.observed());
            let fifo = Registry::new(b"/root\n");
            let name = fifo
                .root
                .join("cancelled")
                .join(format!("abc-123.{}.claim", fifo.digest));
            #[cfg(not(target_vendor = "apple"))]
            rustix::fs::mknodat(CWD, &name, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
            // rustix does not expose mknodat on Apple; match the native
            // verifier's platform fixture without omitting the FIFO assertion.
            #[cfg(target_vendor = "apple")]
            assert!(
                std::process::Command::new("/usr/bin/mkfifo")
                    .arg(&name)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(!fifo.observed());
            let large = Registry::new(b"/root\n");
            let record = large.record("cancelled", "claim");
            File::options()
                .write(true)
                .open(record)
                .unwrap()
                .set_len((LIMIT + 1) as u64)
                .unwrap();
            assert!(!large.observed());
        }

        #[test]
        fn rechecks_record_identity_and_generation_at_snapshot_completion() {
            for replacement in [false, true] {
                let registry = Registry::new(b"/root\n");
                let record = registry.record("cancelled", "claim");
                let result = snapshot(&registry.request("source", &registry.digest), |stage| {
                    if stage == Observation::BeforeFinalCheck {
                        if replacement {
                            std::fs::rename(
                                &record,
                                registry.owner.path().join("retained-record"),
                            )?;
                        }
                        std::fs::write(&record, b"/modified\n")?;
                    }
                    Ok(())
                });
                assert!(result.is_err());
            }
        }

        #[test]
        fn late_own_record_conflicts_refuse_but_unrelated_activity_does_not() {
            for own in [false, true] {
                let registry = Registry::new(b"/root\n");
                registry.record("cancelled", "claim");
                let result = snapshot(&registry.request("source", &registry.digest), |stage| {
                    if stage == Observation::BeforeFinalCheck {
                        let name = if own {
                            format!("abc-123.{}.pending", registry.digest)
                        } else {
                            "unrelated.activity.lock".to_owned()
                        };
                        std::fs::write(registry.root.join(name), &registry.content)?;
                    }
                    Ok(())
                });
                assert_eq!(result.unwrap_or(false), !own);
            }
        }

        #[test]
        fn rechecks_every_directory_and_mutex_binding_before_yielding() {
            for name in [
                "cancelled",
                "released",
                "quarantine",
                "metadata.lock",
                "registry",
            ] {
                let registry = Registry::new(b"/root\n");
                registry.record("cancelled", "claim");
                let result = snapshot(&registry.request("source", &registry.digest), |stage| {
                    if stage == Observation::BeforeFinalCheck {
                        let original = if name == "registry" {
                            registry.root.clone()
                        } else {
                            registry.root.join(name)
                        };
                        std::fs::rename(
                            &original,
                            registry.owner.path().join(format!("retained-{name}")),
                        )?;
                        if name == "metadata.lock" {
                            std::fs::write(&original, b"")?;
                        } else {
                            std::fs::create_dir(&original)?;
                        }
                    }
                    Ok(())
                });
                assert!(!result.unwrap_or(false), "rebound {name}");
            }
        }
    }
}
