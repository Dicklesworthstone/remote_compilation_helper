//! Publish immutable cancellation evidence without copying its record bytes.
//!
//! The caller owns source activity and the registry metadata lock. This helper
//! admits only the three cancellation transitions, links an existing verified
//! record without replacing any name, and confirms its durability and binding.
//! A failed or interrupted operation leaves every visible name for recovery.

use anyhow::{Result, bail};
use std::io::{Read, Write};

const PROBE_REPLY: &str = "rch-wkr source-claim-link v1";

/// This control operation runs before the async runtime or logging sinks.
pub fn main(arguments: &[String]) -> i32 {
    match run(arguments, std::io::stdin().lock(), std::io::stdout().lock()) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "RCH_SOURCE_CLAIM_LINK_FAILED {error:#}"
            );
            1
        }
    }
}

fn run(arguments: &[String], input: impl Read, mut output: impl Write) -> Result<()> {
    require_supported()?;
    match arguments {
        [operation] if operation == "probe" => {
            writeln!(output, "{PROBE_REPLY}")?;
            Ok(())
        }
        [operation, registry, source, destination, token, digest] if operation == "link" => {
            link_record(registry, source, destination, token, digest, input)
        }
        _ => bail!("expected probe or link <registry> <source> <destination> <token> <digest>"),
    }
}

#[cfg(unix)]
fn require_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn require_supported() -> Result<()> {
    bail!("descriptor-bound cancellation links require a Unix worker")
}

#[cfg(unix)]
fn link_record(
    registry: &str,
    source: &str,
    destination: &str,
    token: &str,
    digest: &str,
    input: impl Read,
) -> Result<()> {
    unix::link_with(registry, source, destination, token, digest, input, |_| {
        Ok(())
    })
}

#[cfg(not(unix))]
fn link_record(
    _registry: &str,
    _source: &str,
    _destination: &str,
    _token: &str,
    _digest: &str,
    _input: impl Read,
) -> Result<()> {
    require_supported()
}

#[cfg(unix)]
mod unix {
    use super::*;
    use anyhow::{Context as _, ensure};
    use rustix::fd::{AsFd, OwnedFd};
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
    use sha2::{Digest as _, Sha256};
    use std::fs::File;
    use std::io::{Seek as _, SeekFrom};
    use std::path::Path;

    const MAX_CLOSURE_BYTES: u64 = 32 * 1024 * 1024;
    const FILE_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY)
        .union(OFlags::CLOEXEC);
    const DIRECTORY_FLAGS: OFlags = FILE_FLAGS.union(OFlags::DIRECTORY);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Observation {
        DirectoriesOpened,
        BeforeSourceRead,
        AfterSourceRead,
        BeforeInitialFileSync,
        BeforeLink,
        Linked,
        TargetOpened,
        BeforeLinkedFileSync,
        BeforeTargetDirectorySync,
        BeforeRegistryDirectorySync,
        BeforeConfirmation,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Directory {
        Registry,
        Cancelled,
    }

    struct Record {
        directory: Directory,
        name: String,
    }

    struct Request<'a> {
        parent: &'a str,
        registry_name: &'a str,
        source: Record,
        destination: Record,
        digest: &'a str,
    }

    impl<'a> Request<'a> {
        fn new(
            registry: &'a str,
            source: &str,
            destination: &str,
            token: &str,
            digest: &'a str,
        ) -> Result<Self> {
            ensure!(
                !token.is_empty()
                    && token.len() <= 128
                    && token.bytes().all(|byte| byte.is_ascii_digit()
                        || (b'a'..=b'f').contains(&byte)
                        || byte == b'-'),
                "invalid cancellation record token"
            );
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "invalid cancellation record digest"
            );
            ensure!(
                Path::new(registry).is_absolute(),
                "invalid cancellation registry"
            );
            let (parent, registry_name) = registry
                .rsplit_once('/')
                .context("invalid cancellation registry")?;
            ensure!(!registry_name.is_empty(), "invalid cancellation registry");
            let parent = if parent.is_empty() { "/" } else { parent };
            let base = format!("{token}.{digest}");
            let claim = format!("{base}.claim");
            let fence = format!("{base}.cancelling");
            let receipt = format!("cancelled/{claim}");
            let (left, right) = [
                (claim.as_str(), fence.as_str()),
                (receipt.as_str(), fence.as_str()),
                (fence.as_str(), receipt.as_str()),
            ]
            .into_iter()
            .find(|(left, right)| {
                source == format!("{registry}/{left}")
                    && destination == format!("{registry}/{right}")
            })
            .context("invalid cancellation record link")?;
            let record = |relative: &str| match relative.strip_prefix("cancelled/") {
                Some(name) => Record {
                    directory: Directory::Cancelled,
                    name: name.to_owned(),
                },
                None => Record {
                    directory: Directory::Registry,
                    name: relative.to_owned(),
                },
            };
            Ok(Self {
                parent,
                registry_name,
                source: record(left),
                destination: record(right),
                digest,
            })
        }
    }

    fn identity(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    // Linking may change ctime and nlink; every other source attribute remains
    // fixed across publication. Ordinary reads must preserve the full stamp.
    fn stable_content(left: &Stat, right: &Stat) -> bool {
        identity(left, right)
            && left.st_mode == right.st_mode
            && left.st_uid == right.st_uid
            && left.st_gid == right.st_gid
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
    }

    fn stamp(left: &Stat, right: &Stat) -> bool {
        stable_content(left, right)
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
            && left.st_nlink == right.st_nlink
    }

    fn private(info: &Stat, directory: bool) -> Result<()> {
        let kind = if directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        ensure!(
            FileType::from_raw_mode(info.st_mode) == kind
                && info.st_uid == rustix::process::geteuid().as_raw()
                && info.st_mode & 0o022 == 0,
            "unsafe cancellation record ownership or type"
        );
        Ok(())
    }

    struct Directories {
        parent: OwnedFd,
        registry: OwnedFd,
        cancelled: Option<OwnedFd>,
    }

    impl Directories {
        fn open(request: &Request<'_>) -> Result<Self> {
            // Only the immediate parent and the registry's own directories are
            // private bindings. Earlier aliases such as Darwin's /var remain
            // permitted, matching the registry's existing directory contract.
            let parent = rustix::fs::open(request.parent, DIRECTORY_FLAGS, Mode::empty())
                .context("open cancellation registry parent")?;
            let registry = rustix::fs::openat(
                &parent,
                request.registry_name,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .context("open cancellation registry")?;
            let cancelled = if request.source.directory == Directory::Cancelled
                || request.destination.directory == Directory::Cancelled
            {
                Some(
                    rustix::fs::openat(&registry, "cancelled", DIRECTORY_FLAGS, Mode::empty())
                        .context("open cancellation receipt directory")?,
                )
            } else {
                None
            };
            Ok(Self {
                parent,
                registry,
                cancelled,
            })
        }

        fn selected(&self, directory: Directory) -> Result<&OwnedFd> {
            match directory {
                Directory::Registry => Ok(&self.registry),
                Directory::Cancelled => self
                    .cancelled
                    .as_ref()
                    .context("missing cancellation receipt directory"),
            }
        }

        fn verify(&self, request: &Request<'_>) -> Result<()> {
            let verify = |owner: rustix::fd::BorrowedFd<'_>, name: &str, descriptor: &OwnedFd| {
                let opened = rustix::fs::fstat(descriptor)?;
                private(&opened, true)?;
                let named = rustix::fs::statat(owner, name, AtFlags::SYMLINK_NOFOLLOW)?;
                ensure!(
                    identity(&named, &opened),
                    "cancellation record directory changed"
                );
                Ok::<_, anyhow::Error>(())
            };
            verify(rustix::fs::CWD.as_fd(), request.parent, &self.parent)?;
            verify(self.parent.as_fd(), request.registry_name, &self.registry)?;
            if let Some(cancelled) = &self.cancelled {
                verify(self.registry.as_fd(), "cancelled", cancelled)?;
            }
            Ok(())
        }
    }

    fn verify_record(
        source: &mut File,
        directory: &OwnedFd,
        name: &str,
        expected: &[u8],
        observe: &mut impl FnMut(Observation) -> Result<()>,
    ) -> Result<Stat> {
        let before = rustix::fs::fstat(&*source)?;
        private(&before, false)?;
        ensure!(
            u64::try_from(before.st_size).ok() == Some(expected.len() as u64)
                && before.st_nlink >= 1,
            "cancellation source record changed"
        );
        observe(Observation::BeforeSourceRead)?;
        source.seek(SeekFrom::Start(0))?;
        let mut buffer = [0_u8; 64 * 1024];
        let mut position = 0;
        loop {
            let bound = (expected.len() - position + 1).min(buffer.len());
            let read = match source.read(&mut buffer[..bound]) {
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if read == 0 {
                break;
            }
            let end = position + read;
            ensure!(
                end <= expected.len() && buffer[..read] == expected[position..end],
                "cancellation source identity or bytes changed"
            );
            position = end;
        }
        observe(Observation::AfterSourceRead)?;
        let after = rustix::fs::fstat(&*source)?;
        let named = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            position == expected.len() && stamp(&before, &after) && stamp(&named, &after),
            "cancellation source identity or bytes changed"
        );
        Ok(after)
    }

    pub(super) fn link_with(
        registry: &str,
        source: &str,
        destination: &str,
        token: &str,
        digest: &str,
        input: impl Read,
        mut observe: impl FnMut(Observation) -> Result<()>,
    ) -> Result<()> {
        let request = Request::new(registry, source, destination, token, digest)?;
        let mut expected = Vec::new();
        input
            .take(MAX_CLOSURE_BYTES + 1)
            .read_to_end(&mut expected)?;
        ensure!(
            !expected.is_empty() && expected.len() as u64 <= MAX_CLOSURE_BYTES,
            "cancellation closure changed"
        );
        let actual = Sha256::digest(&expected)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        ensure!(actual == request.digest, "cancellation closure changed");
        let directories = Directories::open(&request)?;
        observe(Observation::DirectoriesOpened)?;
        directories.verify(&request)?;
        let source_directory = directories.selected(request.source.directory)?;
        let target_directory = directories.selected(request.destination.directory)?;
        let descriptor = rustix::fs::openat(
            source_directory,
            request.source.name.as_str(),
            FILE_FLAGS,
            Mode::empty(),
        )
        .context("open cancellation source record")?;
        let mut source = File::from(descriptor);
        let before = verify_record(
            &mut source,
            source_directory,
            &request.source.name,
            &expected,
            &mut observe,
        )?;
        observe(Observation::BeforeInitialFileSync)?;
        rustix::fs::fsync(&source).context("sync cancellation source before link")?;
        directories.verify(&request)?;
        let named = rustix::fs::statat(
            source_directory,
            request.source.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        ensure!(
            stamp(&named, &before),
            "cancellation source changed before link"
        );
        observe(Observation::BeforeLink)?;
        rustix::fs::linkat(
            source_directory,
            request.source.name.as_str(),
            target_directory,
            request.destination.name.as_str(),
            AtFlags::empty(),
        )
        .context("link cancellation record without replacement")?;
        observe(Observation::Linked)?;
        let target = rustix::fs::openat(
            target_directory,
            request.destination.name.as_str(),
            FILE_FLAGS,
            Mode::empty(),
        )
        .context("open linked cancellation record")?;
        ensure!(
            identity(&rustix::fs::fstat(&target)?, &before),
            "cancellation destination does not name the verified source"
        );
        observe(Observation::TargetOpened)?;
        observe(Observation::BeforeLinkedFileSync)?;
        rustix::fs::fsync(&source).context("sync linked cancellation source")?;
        observe(Observation::BeforeTargetDirectorySync)?;
        rustix::fs::fsync(target_directory).context("sync cancellation destination directory")?;
        if request.destination.directory == Directory::Cancelled {
            observe(Observation::BeforeRegistryDirectorySync)?;
            rustix::fs::fsync(&directories.registry).context("sync cancellation registry")?;
        }
        observe(Observation::BeforeConfirmation)?;
        directories.verify(&request)?;
        let after = verify_record(
            &mut source,
            source_directory,
            &request.source.name,
            &expected,
            &mut observe,
        )?;
        let named = rustix::fs::statat(
            target_directory,
            request.destination.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        ensure!(
            stable_content(&after, &before)
                && before.st_nlink.checked_add(1) == Some(after.st_nlink)
                && stamp(&rustix::fs::fstat(&target)?, &after)
                && stamp(&named, &after),
            "cancellation record changed after link"
        );
        directories.verify(&request)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
        use std::path::PathBuf;

        struct Fixture {
            root: tempfile::TempDir,
            parent: PathBuf,
            registry: PathBuf,
            source: PathBuf,
            destination: PathBuf,
            token: String,
            digest: String,
            bytes: Vec<u8>,
        }

        impl Fixture {
            fn new(route: usize) -> Self {
                let root = tempfile::Builder::new()
                    .prefix("source-claim-link-")
                    .disable_cleanup(true)
                    .tempdir()
                    .unwrap();
                let parent = root.path().join("private ' café parent");
                let registry = parent.join("claims");
                fs::create_dir_all(registry.join("cancelled")).unwrap();
                for directory in [&parent, &registry, &registry.join("cancelled")] {
                    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
                }
                let token = "a1-b2".to_owned();
                let bytes = b"/work/project\n/work/shared\n".to_vec();
                let digest = Sha256::digest(&bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let claim = registry.join(format!("{token}.{digest}.claim"));
                let fence = registry.join(format!("{token}.{digest}.cancelling"));
                let receipt = registry.join("cancelled").join(claim.file_name().unwrap());
                let (source, destination) = match route {
                    0 => (claim, fence),
                    1 => (receipt, fence),
                    2 => (fence, receipt),
                    _ => unreachable!(),
                };
                fs::write(&source, &bytes).unwrap();
                fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
                Self {
                    root,
                    parent,
                    registry,
                    source,
                    destination,
                    token,
                    digest,
                    bytes,
                }
            }

            fn arguments(&self) -> Vec<String> {
                vec![
                    "link".into(),
                    self.registry.to_str().unwrap().into(),
                    self.source.to_str().unwrap().into(),
                    self.destination.to_str().unwrap().into(),
                    self.token.clone(),
                    self.digest.clone(),
                ]
            }

            fn call(&self, observe: impl FnMut(Observation) -> Result<()>) -> Result<()> {
                link_with(
                    self.registry.to_str().unwrap(),
                    self.source.to_str().unwrap(),
                    self.destination.to_str().unwrap(),
                    &self.token,
                    &self.digest,
                    self.bytes.as_slice(),
                    observe,
                )
            }

            fn assert_linked(&self) {
                let source = fs::metadata(&self.source).unwrap();
                let destination = fs::metadata(&self.destination).unwrap();
                assert_eq!(
                    (source.dev(), source.ino()),
                    (destination.dev(), destination.ino())
                );
                assert_eq!(source.nlink(), 2);
                assert_eq!(fs::read(&self.source).unwrap(), self.bytes);
                assert_eq!(fs::read(&self.destination).unwrap(), self.bytes);
                assert_eq!(source.mode() & 0o777, 0o600);
            }
        }

        #[test]
        fn publishes_all_three_routes_silently_without_copying_or_overwriting() {
            for route in 0..3 {
                let fixture = Fixture::new(route);
                let before = fs::metadata(&fixture.source).unwrap();
                let mut output = Vec::new();
                run(&fixture.arguments(), fixture.bytes.as_slice(), &mut output).unwrap();
                assert!(output.is_empty());
                fixture.assert_linked();
                assert_eq!(fs::metadata(&fixture.source).unwrap().ino(), before.ino());
                assert!(
                    fixture.call(|_| Ok(())).is_err(),
                    "the caller owns retry confirmation"
                );
                fixture.assert_linked();
            }
            let fixture = Fixture::new(0);
            fs::hard_link(&fixture.source, fixture.registry.join("existing-evidence")).unwrap();
            fixture.call(|_| Ok(())).unwrap();
            assert_eq!(fs::metadata(&fixture.source).unwrap().nlink(), 3);
            assert_eq!(
                fs::metadata(&fixture.source).unwrap().ino(),
                fs::metadata(&fixture.destination).unwrap().ino()
            );
        }

        #[test]
        fn rejects_unadmitted_routes_identities_and_unbound_closures() {
            let fixture = Fixture::new(0);
            for (index, replacement) in [
                (0, "unknown".into()),
                (1, "relative/registry".into()),
                (
                    2,
                    fixture
                        .registry
                        .join("unrelated.claim")
                        .to_str()
                        .unwrap()
                        .into(),
                ),
                (
                    3,
                    fixture
                        .registry
                        .join("cancelled")
                        .join(fixture.source.file_name().unwrap())
                        .to_str()
                        .unwrap()
                        .into(),
                ),
                (4, "../a1".into()),
                (4, "a".repeat(129)),
                (5, "A".repeat(64)),
            ] {
                let mut arguments = fixture.arguments();
                arguments[index] = replacement;
                let mut output = Vec::new();
                assert!(run(&arguments, fixture.bytes.as_slice(), &mut output).is_err());
                assert!(output.is_empty());
                assert!(!fixture.destination.exists());
            }
            for payload in [b"".as_slice(), b"/other/source\n".as_slice()] {
                assert!(run(&fixture.arguments(), payload, Vec::new()).is_err());
                assert!(!fixture.destination.exists());
            }
            assert!(
                run(
                    &fixture.arguments(),
                    std::io::repeat(b'x').take(MAX_CLOSURE_BYTES + 1),
                    Vec::new(),
                )
                .is_err()
            );
            assert!(!fixture.destination.exists());
            assert_eq!(fs::read(&fixture.source).unwrap(), fixture.bytes);
            assert_eq!(fs::metadata(&fixture.source).unwrap().nlink(), 1);
        }

        #[test]
        fn rejects_record_corruption_writable_bindings_and_special_files() {
            for damaged in [
                "source-bytes",
                "source-mode",
                "parent",
                "registry",
                "cancelled",
            ] {
                let fixture = Fixture::new(2);
                match damaged {
                    "source-bytes" => fs::write(&fixture.source, b"/changed\n").unwrap(),
                    "source-mode" => {
                        fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o620))
                            .unwrap()
                    }
                    _ => {
                        let path = match damaged {
                            "parent" => fixture.parent.clone(),
                            "registry" => fixture.registry.clone(),
                            _ => fixture.registry.join("cancelled"),
                        };
                        fs::set_permissions(path, fs::Permissions::from_mode(0o720)).unwrap();
                    }
                }
                let before = fs::read(&fixture.source).unwrap();
                assert!(fixture.call(|_| Ok(())).is_err(), "{damaged}");
                assert!(!fixture.destination.exists());
                assert_eq!(fs::read(&fixture.source).unwrap(), before);
            }
            for kind in ["link", "directory", "fifo"] {
                let fixture = Fixture::new(0);
                let retained = fixture.registry.join("original-source");
                fs::rename(&fixture.source, &retained).unwrap();
                match kind {
                    "link" => symlink(&retained, &fixture.source).unwrap(),
                    "directory" => fs::create_dir(&fixture.source).unwrap(),
                    "fifo" => {
                        #[cfg(not(target_vendor = "apple"))]
                        rustix::fs::mkfifoat(
                            rustix::fs::CWD,
                            &fixture.source,
                            Mode::RUSR | Mode::WUSR,
                        )
                        .unwrap();
                        #[cfg(target_vendor = "apple")]
                        assert!(
                            std::process::Command::new("/usr/bin/mkfifo")
                                .arg(&fixture.source)
                                .status()
                                .unwrap()
                                .success()
                        );
                    }
                    _ => unreachable!(),
                }
                assert!(fixture.call(|_| Ok(())).is_err(), "{kind}");
                assert!(!fixture.destination.exists());
                assert_eq!(fs::read(retained).unwrap(), fixture.bytes);
            }
        }

        #[test]
        fn never_overwrites_a_destination_appearing_at_the_link_boundary() {
            for kind in ["regular", "symlink", "directory"] {
                let fixture = Fixture::new(0);
                let mut injected = false;
                let result = fixture.call(|point| {
                    if point == Observation::BeforeLink {
                        match kind {
                            "regular" => fs::write(&fixture.destination, b"keep existing").unwrap(),
                            "symlink" => symlink("keep-target", &fixture.destination).unwrap(),
                            "directory" => fs::create_dir(&fixture.destination).unwrap(),
                            _ => unreachable!(),
                        }
                        injected = true;
                    }
                    Ok(())
                });
                assert!(injected && result.is_err(), "{kind}");
                match kind {
                    "regular" => {
                        assert_eq!(fs::read(&fixture.destination).unwrap(), b"keep existing")
                    }
                    "symlink" => assert_eq!(
                        fs::read_link(&fixture.destination).unwrap(),
                        Path::new("keep-target")
                    ),
                    "directory" => {
                        assert!(fs::read_dir(&fixture.destination).unwrap().next().is_none())
                    }
                    _ => unreachable!(),
                }
                assert_eq!(fs::read(&fixture.source).unwrap(), fixture.bytes);
                assert_eq!(fs::metadata(&fixture.source).unwrap().nlink(), 1);
            }
        }

        #[test]
        fn refuses_source_replacement_after_the_final_named_check() {
            let fixture = Fixture::new(0);
            let retained = fixture.registry.join("verified-source");
            let mut injected = false;
            let error = fixture
                .call(|point| {
                    if point == Observation::BeforeLink {
                        fs::rename(&fixture.source, &retained).unwrap();
                        fs::write(&fixture.source, &fixture.bytes).unwrap();
                        fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o600))
                            .unwrap();
                        injected = true;
                    }
                    Ok(())
                })
                .unwrap_err();
            assert!(injected);
            assert!(
                error
                    .to_string()
                    .contains("does not name the verified source")
            );
            assert_eq!(fs::read(&retained).unwrap(), fixture.bytes);
            assert_eq!(fs::metadata(&retained).unwrap().nlink(), 1);
            // The uncertain new link is evidence for the caller, never rolled back.
            assert!(fixture.destination.exists());
            assert_ne!(
                fs::metadata(&retained).unwrap().ino(),
                fs::metadata(&fixture.destination).unwrap().ino()
            );
        }

        #[test]
        fn refuses_rebound_directories_before_acknowledgement_and_keeps_evidence() {
            for binding in ["parent", "registry", "cancelled"] {
                let fixture = Fixture::new(2);
                let original = match binding {
                    "parent" => fixture.parent.clone(),
                    "registry" => fixture.registry.clone(),
                    _ => fixture.registry.join("cancelled"),
                };
                let retained = fixture.root.path().join("retained-binding");
                let mut injected = false;
                let error = fixture
                    .call(|point| {
                        if point == Observation::BeforeLink {
                            fs::rename(&original, &retained).unwrap();
                            fs::create_dir(&original).unwrap();
                            fs::set_permissions(&original, fs::Permissions::from_mode(0o700))
                                .unwrap();
                            injected = true;
                        }
                        Ok(())
                    })
                    .unwrap_err();
                assert!(injected);
                assert!(
                    error.to_string().contains("directory changed"),
                    "{binding}: {error:#}"
                );
                let linked = retained.join(fixture.destination.strip_prefix(&original).unwrap());
                assert_eq!(fs::read(linked).unwrap(), fixture.bytes);
                assert!(!fixture.destination.exists());
            }
        }

        #[test]
        fn refuses_destination_substitution_before_or_after_its_descriptor_opens() {
            for point in [Observation::Linked, Observation::TargetOpened] {
                for kind in ["regular", "symlink", "directory"] {
                    let fixture = Fixture::new(2);
                    let retained = fixture.registry.join("original-destination");
                    let mut injected = false;
                    let result = fixture.call(|observed| {
                        if observed == point {
                            fs::rename(&fixture.destination, &retained).unwrap();
                            match kind {
                                "regular" => {
                                    fs::write(&fixture.destination, b"keep replacement").unwrap()
                                }
                                "symlink" => symlink("keep-target", &fixture.destination).unwrap(),
                                "directory" => fs::create_dir(&fixture.destination).unwrap(),
                                _ => unreachable!(),
                            }
                            injected = true;
                        }
                        Ok(())
                    });
                    assert!(injected && result.is_err(), "{point:?}/{kind}");
                    assert_eq!(fs::read(&retained).unwrap(), fixture.bytes);
                    assert_eq!(
                        fs::metadata(&retained).unwrap().ino(),
                        fs::metadata(&fixture.source).unwrap().ino()
                    );
                    match kind {
                        "regular" => {
                            assert_eq!(fs::read(&fixture.destination).unwrap(), b"keep replacement")
                        }
                        "symlink" => assert_eq!(
                            fs::read_link(&fixture.destination).unwrap(),
                            Path::new("keep-target")
                        ),
                        "directory" => {
                            assert!(fs::read_dir(&fixture.destination).unwrap().next().is_none())
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }

        #[test]
        fn injected_link_and_barrier_failures_never_confirm_or_rollback() {
            for point in [
                Observation::BeforeInitialFileSync,
                Observation::BeforeLink,
                Observation::BeforeLinkedFileSync,
                Observation::BeforeTargetDirectorySync,
                Observation::BeforeRegistryDirectorySync,
                Observation::BeforeConfirmation,
            ] {
                let fixture = Fixture::new(2);
                let mut injected = false;
                let result = fixture.call(|observed| {
                    if observed == point {
                        injected = true;
                        return Err(std::io::Error::from_raw_os_error(
                            rustix::io::Errno::NOSPC.raw_os_error(),
                        )
                        .into());
                    }
                    Ok(())
                });
                assert!(injected && result.is_err(), "{point:?}");
                assert_eq!(fs::read(&fixture.source).unwrap(), fixture.bytes);
                if matches!(
                    point,
                    Observation::BeforeInitialFileSync | Observation::BeforeLink
                ) {
                    assert!(!fixture.destination.exists());
                    fixture.call(|_| Ok(())).unwrap();
                } else {
                    fixture.assert_linked();
                    assert!(fixture.call(|_| Ok(())).is_err());
                }
                fixture.assert_linked();
            }
        }

        #[test]
        fn detects_record_generation_changes_and_unexpected_extra_links() {
            for (point, mutation) in [
                (Observation::AfterSourceRead, "mode"),
                (Observation::BeforeConfirmation, "bytes"),
                (Observation::BeforeConfirmation, "extra-link"),
            ] {
                let fixture = Fixture::new(2);
                let mut injected = false;
                let result = fixture.call(|observed| {
                    if observed == point && !injected {
                        match mutation {
                            "mode" => fs::set_permissions(
                                &fixture.source,
                                fs::Permissions::from_mode(0o400),
                            )
                            .unwrap(),
                            "bytes" => fs::write(&fixture.source, b"/different\n").unwrap(),
                            "extra-link" => {
                                fs::hard_link(&fixture.source, fixture.registry.join("third-name"))
                                    .unwrap()
                            }
                            _ => unreachable!(),
                        }
                        injected = true;
                    }
                    Ok(())
                });
                assert!(injected && result.is_err(), "{mutation}");
                if mutation == "bytes" {
                    assert_eq!(fs::read(&fixture.source).unwrap(), b"/different\n");
                    assert_eq!(fs::read(&fixture.destination).unwrap(), b"/different\n");
                }
            }
        }

        #[test]
        fn allows_earlier_aliases_but_refuses_links_at_bound_directory_names() {
            let fixture = Fixture::new(0);
            let alias = fixture.root.path().join("earlier-alias");
            symlink(fixture.root.path(), &alias).unwrap();
            let registry = alias.join(fixture.registry.strip_prefix(fixture.root.path()).unwrap());
            let source = registry.join(fixture.source.file_name().unwrap());
            let destination = registry.join(fixture.destination.file_name().unwrap());
            link_with(
                registry.to_str().unwrap(),
                source.to_str().unwrap(),
                destination.to_str().unwrap(),
                &fixture.token,
                &fixture.digest,
                fixture.bytes.as_slice(),
                |_| Ok(()),
            )
            .unwrap();
            fixture.assert_linked();

            for binding in ["parent", "registry", "cancelled"] {
                let fixture = Fixture::new(2);
                let original = match binding {
                    "parent" => fixture.parent.clone(),
                    "registry" => fixture.registry.clone(),
                    _ => fixture.registry.join("cancelled"),
                };
                let retained = fixture.root.path().join("real-binding");
                fs::rename(&original, &retained).unwrap();
                symlink(&retained, &original).unwrap();
                assert!(fixture.call(|_| Ok(())).is_err(), "{binding}");
                assert!(!fixture.destination.exists());
            }
        }
    }
}
