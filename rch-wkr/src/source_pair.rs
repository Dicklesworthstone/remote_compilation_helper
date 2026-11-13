//! Durable custody of a clean-overlay source pair, independent of source access.
//!
//! Callers hold the pair flock; claim also holds the source-registry metadata
//! mutex after checking cancellation fences. Every read is descriptor-bound,
//! and every replacement publishes a complete private record before confirming
//! its file and directory barriers. Failed publications remain for recovery.

use std::io::Write;

use anyhow::Result;

const REFUSED: i32 = 73;

#[derive(Clone, Copy, Default)]
enum Stage {
    #[default]
    Validation,
    Publication,
    Confirmation,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::Publication => "publication",
            Self::Confirmation => "confirmation",
        }
    }

    fn marker(self) -> &'static str {
        match self {
            Self::Validation => "RCH_SOURCE_PAIR_OWNERSHIP_UNCONFIRMED",
            Self::Publication | Self::Confirmation => "RCH_SOURCE_PAIR_PUBLICATION_UNCONFIRMED",
        }
    }
}

/// Execute before the runtime and optional logging sinks are initialized.
pub fn main(arguments: &[String]) -> i32 {
    let mut stage = Stage::default();
    match run(arguments, std::io::stdout().lock(), &mut stage) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "{} stage={}: {error:#}",
                stage.marker(),
                stage.label(),
            );
            REFUSED
        }
    }
}

fn run(arguments: &[String], mut output: impl Write, stage: &mut Stage) -> Result<()> {
    #[cfg(unix)]
    {
        if arguments == ["probe"] {
            writeln!(output, "rch-wkr source-pair v1")?;
            return Ok(());
        }
        unix::run(arguments, output, stage)
    }
    #[cfg(not(unix))]
    {
        let _ = (arguments, &mut output, stage);
        anyhow::bail!("descriptor-bound source pair custody requires a Unix worker")
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use anyhow::{Context as _, bail, ensure};
    use rustix::fd::OwnedFd;
    use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, Stat};
    use rustix::io::Errno;
    use std::fs::File;
    use std::io::{Read as _, Seek as _};
    use std::path::Path;

    const RECORD_LIMIT: u64 = 130;
    const READ_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::CLOEXEC);
    const DIRECTORY_FLAGS: OFlags = READ_FLAGS.union(OFlags::DIRECTORY);
    const RELEASED: &[u8] = b"released\n";

    fn identity(bytes: &[u8]) -> bool {
        (1..=128).contains(&bytes.len())
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte) || *byte == b'-')
    }

    fn safe(info: &Stat, directory: bool) -> Result<()> {
        let kind = if directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        ensure!(
            FileType::from_raw_mode(info.st_mode) == kind
                && info.st_uid == rustix::process::geteuid().as_raw()
                && info.st_mode & 0o022 == 0
                && (directory || info.st_nlink == 1),
            "unsafe source pair record ownership, type or links"
        );
        Ok(())
    }

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    fn same_stamp(left: &Stat, right: &Stat) -> bool {
        same_inode(left, right)
            && left.st_uid == right.st_uid
            && left.st_gid == right.st_gid
            && left.st_mode == right.st_mode
            && left.st_nlink == right.st_nlink
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }

    struct Record {
        name: String,
        file: File,
        content: Vec<u8>,
        before: Stat,
    }

    struct Custody<'a> {
        directory: OwnedFd,
        parent: &'a str,
        token: Vec<u8>,
        stage: &'a mut Stage,
    }

    impl<'a> Custody<'a> {
        fn open(parent: &'a str, token: &str, stage: &'a mut Stage) -> Result<Self> {
            let directory = rustix::fs::open(parent, DIRECTORY_FLAGS, Mode::empty())
                .context("open source pair parent")?;
            let custody = Self {
                directory,
                parent,
                token: format!("{token}\n").into_bytes(),
                stage,
            };
            custody.verify_parent()?;
            Ok(custody)
        }

        fn verify_parent(&self) -> Result<()> {
            let current = rustix::fs::fstat(&self.directory)?;
            safe(&current, true)?;
            let named = rustix::fs::statat(CWD, self.parent, AtFlags::SYMLINK_NOFOLLOW)?;
            ensure!(
                same_inode(&current, &named),
                "source pair parent changed during publication"
            );
            Ok(())
        }

        fn verify(&self, record: &Record) -> Result<()> {
            let current = rustix::fs::fstat(&record.file)?;
            safe(&current, false)?;
            let named =
                rustix::fs::statat(&self.directory, &record.name, AtFlags::SYMLINK_NOFOLLOW)?;
            ensure!(
                same_stamp(&current, &record.before) && same_stamp(&named, &record.before),
                "source pair record identity or exact bytes changed"
            );
            let mut file = &record.file;
            file.rewind()?;
            let mut content = Vec::new();
            file.take(RECORD_LIMIT).read_to_end(&mut content)?;
            ensure!(
                content == record.content
                    && same_stamp(&rustix::fs::fstat(&record.file)?, &record.before),
                "source pair record identity or exact bytes changed"
            );
            self.verify_parent()
        }

        fn read_record(&self, name: &str, receipt: bool) -> Result<Option<Record>> {
            let descriptor =
                match rustix::fs::openat(&self.directory, name, READ_FLAGS, Mode::empty()) {
                    Ok(descriptor) => descriptor,
                    Err(Errno::NOENT) => return Ok(None),
                    Err(error) => return Err(error).context("open source pair record"),
                };
            let before = rustix::fs::fstat(&descriptor)?;
            safe(&before, false)?;
            let file = File::from(descriptor);
            let mut content = Vec::new();
            (&file).take(RECORD_LIMIT).read_to_end(&mut content)?;
            ensure!(
                content.strip_suffix(b"\n").is_some_and(identity)
                    || (!receipt && content == RELEASED),
                "source pair has an unfinished owner or malformed release receipt"
            );
            let record = Record {
                name: name.to_owned(),
                file,
                content,
                before,
            };
            self.verify(&record)?;
            ensure!(
                !receipt || record.content == self.token,
                "source pair release receipt belongs to another identity"
            );
            Ok(Some(record))
        }

        fn confirm(&mut self, record: &Record) -> Result<()> {
            *self.stage = Stage::Confirmation;
            self.verify(record)?;
            rustix::fs::fsync(&record.file).context("sync source pair record")?;
            rustix::fs::fsync(&self.directory).context("sync source pair parent")?;
            self.verify(record)
        }

        fn publish(
            &mut self,
            name: &str,
            content: &[u8],
            previous: Option<&Record>,
        ) -> Result<Record> {
            *self.stage = Stage::Publication;
            self.verify_parent()?;
            let mut nonce = [0u8; 16];
            File::open("/dev/urandom")?.read_exact(&mut nonce)?;
            let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            let temporary = format!(".pair-write.{suffix}");
            let descriptor = rustix::fs::openat(
                &self.directory,
                &temporary,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .context("create private source pair record")?;
            // No TempDir/NamedTempFile cleanup: a partial write or failed barrier
            // must retain its private evidence, never remove an ambiguous name.
            let mut file = File::from(descriptor);
            file.write_all(content)?;
            rustix::fs::fsync(&file).context("sync private source pair record")?;
            let mut record = Record {
                name: temporary.clone(),
                before: rustix::fs::fstat(&file)?,
                file,
                content: content.to_vec(),
            };
            self.verify(&record)?;
            if let Some(previous) = previous {
                self.verify(previous)?;
            } else {
                match rustix::fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Err(Errno::NOENT) => {}
                    Ok(_) => bail!("source pair publication destination appeared"),
                    Err(error) => return Err(error).context("inspect source pair destination"),
                }
            }
            // Legitimate publishers retain the same pair flock. The exact
            // previous destination was checked immediately before replacement;
            // immutable receipts only use the absent-destination arm.
            rustix::fs::renameat(&self.directory, &temporary, &self.directory, name)
                .context("publish complete source pair record")?;
            record.name = name.to_owned();
            record.before = rustix::fs::fstat(&record.file)?;
            self.confirm(&record)?;
            Ok(record)
        }

        fn receipt_or_publish(&mut self, name: &str, receipt: Option<&Record>) -> Result<()> {
            if let Some(receipt) = receipt {
                self.confirm(receipt)
            } else {
                self.publish(name, &self.token.clone(), None).map(|_| ())
            }
        }
    }

    fn require_root_absent(root: &str) -> Result<()> {
        match rustix::fs::statat(CWD, root, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Ok(()),
            Ok(_) => bail!("source pair has unretired source; refusing release or reuse"),
            Err(error) => Err(error).context("inspect source pair root"),
        }
    }

    fn record_path(path: &str) -> Result<(&str, &str)> {
        let (parent, name) = path
            .rsplit_once('/')
            .context("invalid source pair custody paths")?;
        let parent = if parent.is_empty() { "/" } else { parent };
        ensure!(
            Path::new(path).is_absolute()
                && !name.is_empty()
                && name != "."
                && name != ".."
                && !path.contains('\0'),
            "invalid source pair custody paths"
        );
        Ok((parent, name))
    }

    pub(super) fn run(
        arguments: &[String],
        mut output: impl Write,
        stage: &mut Stage,
    ) -> Result<()> {
        let [operation, owner, receipt, token, root] = arguments else {
            bail!("invalid source pair custody arguments");
        };
        ensure!(
            matches!(
                operation.as_str(),
                "claim" | "recover" | "release" | "cancel-owned" | "cancel-unowned" | "released"
            ),
            "invalid source pair custody operation"
        );
        ensure!(
            identity(token.as_bytes()),
            "invalid source pair custody identity"
        );
        let (parent, owner_name) = record_path(owner)?;
        let (receipt_parent, receipt_name) = record_path(receipt)?;
        ensure!(
            parent == receipt_parent
                && owner_name != receipt_name
                && Path::new(root).is_absolute()
                && !root.contains('\0'),
            "invalid source pair custody paths"
        );
        let mut custody = Custody::open(parent, token, stage)?;
        let receipt = custody.read_record(receipt_name, true)?;
        if operation == "released" && receipt.is_none() {
            output.write_all(b"pending")?;
            output.flush()?;
            return Ok(());
        }
        let owner = custody.read_record(owner_name, false)?;
        let owner_bytes = owner.as_ref().map(|record| record.content.as_slice());
        ensure!(
            receipt.is_none() || owner.is_some(),
            "source pair release receipt has no owner record"
        );
        match operation.as_str() {
            "claim" => {
                ensure!(receipt.is_none(), "source pair identity already released");
                ensure!(
                    owner_bytes.is_none() || owner_bytes == Some(RELEASED),
                    "source pair has an unfinished owner; refusing reuse"
                );
                require_root_absent(root)?;
                custody.publish(owner_name, &custody.token.clone(), owner.as_ref())?;
            }
            "recover" => {
                ensure!(
                    owner_bytes == Some(custody.token.as_slice()) && receipt.is_none(),
                    "source pair has an unfinished owner or a completed release"
                );
                custody.confirm(owner.as_ref().expect("matching owner was required"))?;
            }
            "release" => {
                if owner_bytes == Some(RELEASED)
                    && let Some(receipt) = receipt.as_ref()
                {
                    custody.confirm(receipt)?;
                    custody.confirm(owner.as_ref().expect("released owner was required"))?;
                } else {
                    ensure!(
                        owner_bytes == Some(custody.token.as_slice()),
                        "source pair owner changed before release"
                    );
                    require_root_absent(root)?;
                    custody.receipt_or_publish(receipt_name, receipt.as_ref())?;
                    custody.publish(owner_name, RELEASED, owner.as_ref())?;
                }
            }
            "released" => {
                custody.confirm(
                    receipt
                        .as_ref()
                        .expect("receipt checked before reading owner"),
                )?;
                if owner_bytes == Some(custody.token.as_slice()) {
                    require_root_absent(root)?;
                    custody.publish(owner_name, RELEASED, owner.as_ref())?;
                } else {
                    custody.confirm(owner.as_ref().expect("receipt requires an owner record"))?;
                }
                output.write_all(b"released")?;
            }
            "cancel-owned" => {
                if owner_bytes == Some(custody.token.as_slice()) {
                    if let Some(receipt) = receipt.as_ref() {
                        require_root_absent(root)?;
                        custody.confirm(receipt)?;
                        custody.publish(owner_name, RELEASED, owner.as_ref())?;
                        output.write_all(b"unowned")?;
                    } else {
                        custody.confirm(owner.as_ref().expect("matching owner was required"))?;
                        output.write_all(b"owned")?;
                    }
                } else {
                    if let Some(receipt) = receipt.as_ref() {
                        custody.confirm(receipt)?;
                    }
                    if let Some(owner) = owner.as_ref() {
                        custody.confirm(owner)?;
                    }
                    output.write_all(b"unowned")?;
                }
            }
            "cancel-unowned" => {
                // The caller has independently proved the source intent
                // unowned. This operation never reads or grants source access.
                if owner_bytes == Some(custody.token.as_slice()) {
                    custody.receipt_or_publish(receipt_name, receipt.as_ref())?;
                    custody.publish(owner_name, RELEASED, owner.as_ref())?;
                } else {
                    if let Some(receipt) = receipt.as_ref() {
                        custody.confirm(receipt)?;
                    }
                    if let Some(owner) = owner.as_ref() {
                        custody.confirm(owner)?;
                    }
                }
                output.write_all(b"unowned")?;
            }
            _ => unreachable!("validated custody operation"),
        }
        output.flush()?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
        use std::path::PathBuf;

        struct Fixture {
            directory: PathBuf,
            root: PathBuf,
            owner: PathBuf,
        }

        impl Fixture {
            fn new() -> Self {
                let directory = tempfile::tempdir().unwrap().keep();
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                Self {
                    root: directory.join("source with ' quotes"),
                    owner: directory.join("pair.lock.owner"),
                    directory,
                }
            }

            fn receipt(&self, token: &str) -> PathBuf {
                self.directory.join(format!("pair.lock.released-{token}"))
            }

            fn write(&self, path: &Path, bytes: &[u8]) {
                std::fs::write(path, bytes).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }

            fn execute(&self, operation: &str, token: &str) -> Result<Vec<u8>> {
                let arguments = vec![
                    operation.to_owned(),
                    self.owner.to_str().unwrap().to_owned(),
                    self.receipt(token).to_str().unwrap().to_owned(),
                    token.to_owned(),
                    self.root.to_str().unwrap().to_owned(),
                ];
                let mut output = Vec::new();
                super::super::run(&arguments, &mut output, &mut Stage::Validation)?;
                Ok(output)
            }
        }

        #[test]
        fn durable_claim_release_and_successor_preserve_source_custody() {
            let fixture = Fixture::new();
            assert_eq!(fixture.execute("released", "aaa").unwrap(), b"pending");
            fixture.execute("claim", "aaa").unwrap();
            assert!(!fixture.root.exists(), "claim grants no source access");
            let original = std::fs::metadata(&fixture.owner).unwrap();
            assert_eq!(original.permissions().mode() & 0o777, 0o600);
            std::fs::create_dir(&fixture.root).unwrap();
            std::fs::write(fixture.root.join("source.rs"), b"original source").unwrap();
            fixture.execute("recover", "aaa").unwrap();
            assert_eq!(fixture.execute("cancel-owned", "aaa").unwrap(), b"owned");
            assert!(fixture.execute("claim", "bbb").is_err());
            assert!(fixture.execute("release", "aaa").is_err());
            assert!(!fixture.receipt("aaa").exists());
            assert_eq!(std::fs::read(&fixture.owner).unwrap(), b"aaa\n");

            let retired = fixture.directory.join("retired-source");
            std::fs::rename(&fixture.root, &retired).unwrap();
            fixture.execute("release", "aaa").unwrap();
            assert_eq!(std::fs::read(&fixture.owner).unwrap(), RELEASED);
            assert_eq!(std::fs::read(fixture.receipt("aaa")).unwrap(), b"aaa\n");
            assert_ne!(
                original.ino(),
                std::fs::metadata(&fixture.owner).unwrap().ino()
            );
            fixture.execute("release", "aaa").unwrap();
            assert!(fixture.execute("recover", "aaa").is_err());
            assert!(fixture.execute("claim", "aaa").is_err());

            fixture.execute("claim", "bbb").unwrap();
            std::fs::create_dir(&fixture.root).unwrap();
            std::fs::write(fixture.root.join("successor.rs"), b"successor source").unwrap();
            let successor = std::fs::metadata(&fixture.owner).unwrap();
            assert_eq!(fixture.execute("released", "aaa").unwrap(), b"released");
            assert_eq!(fixture.execute("cancel-owned", "aaa").unwrap(), b"unowned");
            assert_eq!(
                fixture.execute("cancel-unowned", "aaa").unwrap(),
                b"unowned"
            );
            assert_eq!(std::fs::read(&fixture.owner).unwrap(), b"bbb\n");
            assert_eq!(
                successor.ino(),
                std::fs::metadata(&fixture.owner).unwrap().ino()
            );
            assert_eq!(
                std::fs::read(retired.join("source.rs")).unwrap(),
                b"original source"
            );
            assert_eq!(
                std::fs::read(fixture.root.join("successor.rs")).unwrap(),
                b"successor source"
            );
        }

        #[test]
        fn only_a_complete_receipt_can_finish_an_interrupted_release() {
            for operation in ["release", "released", "cancel-owned"] {
                let fixture = Fixture::new();
                fixture.execute("claim", "aaa").unwrap();
                fixture.write(&fixture.receipt("aaa"), b"aaa\n");
                std::fs::create_dir(&fixture.root).unwrap();
                assert!(fixture.execute(operation, "aaa").is_err());
                assert_eq!(std::fs::read(&fixture.owner).unwrap(), b"aaa\n");
                std::fs::rename(&fixture.root, fixture.directory.join("retired")).unwrap();
                fixture.execute(operation, "aaa").unwrap();
                assert_eq!(std::fs::read(&fixture.owner).unwrap(), RELEASED);
                assert_eq!(fixture.execute("released", "aaa").unwrap(), b"released");
            }
        }

        #[test]
        fn cancellation_of_an_unowned_intent_never_touches_source() {
            let fixture = Fixture::new();
            assert_eq!(fixture.execute("cancel-owned", "aaa").unwrap(), b"unowned");
            assert!(!fixture.owner.exists());
            fixture.execute("claim", "aaa").unwrap();
            std::fs::create_dir(&fixture.root).unwrap();
            std::fs::write(fixture.root.join("unrelated"), b"preserve").unwrap();
            assert_eq!(
                fixture.execute("cancel-unowned", "aaa").unwrap(),
                b"unowned"
            );
            assert_eq!(std::fs::read(&fixture.owner).unwrap(), RELEASED);
            assert_eq!(
                std::fs::read(fixture.root.join("unrelated")).unwrap(),
                b"preserve"
            );
            assert!(fixture.execute("claim", "bbb").is_err());
        }

        #[test]
        fn malformed_owners_and_receipts_are_never_repaired() {
            for content in [
                Vec::new(),
                b"aaa".to_vec(),
                b"released\nextra".to_vec(),
                b"aaa\n\n".to_vec(),
                b"AAA\n".to_vec(),
                b"\0\n".to_vec(),
                [vec![b'a'; 129], b"\n".to_vec()].concat(),
            ] {
                let fixture = Fixture::new();
                fixture.write(&fixture.owner, &content);
                for operation in [
                    "claim",
                    "recover",
                    "release",
                    "cancel-owned",
                    "cancel-unowned",
                ] {
                    assert!(
                        fixture.execute(operation, "aaa").is_err(),
                        "{operation}: {content:?}"
                    );
                    assert_eq!(std::fs::read(&fixture.owner).unwrap(), content);
                }
                assert!(!fixture.receipt("aaa").exists());
            }
            for content in [b"released\n".as_slice(), b"bbb\n", b"aaa", b""] {
                let fixture = Fixture::new();
                fixture.execute("claim", "aaa").unwrap();
                fixture.write(&fixture.receipt("aaa"), content);
                for operation in [
                    "released",
                    "recover",
                    "release",
                    "cancel-owned",
                    "cancel-unowned",
                ] {
                    assert!(fixture.execute(operation, "aaa").is_err(), "{operation}");
                    assert_eq!(std::fs::read(&fixture.owner).unwrap(), b"aaa\n");
                    assert_eq!(std::fs::read(fixture.receipt("aaa")).unwrap(), content);
                }
            }
            let fixture = Fixture::new();
            fixture.write(&fixture.receipt("aaa"), b"aaa\n");
            assert!(fixture.execute("released", "aaa").is_err());
            assert!(!fixture.owner.exists());
        }

        #[test]
        fn maximum_identity_and_dangling_source_are_checked() {
            let fixture = Fixture::new();
            let maximum = "a".repeat(128);
            fixture.execute("claim", &maximum).unwrap();
            fixture.execute("recover", &maximum).unwrap();
            symlink(fixture.directory.join("missing"), &fixture.root).unwrap();
            assert!(fixture.execute("release", &maximum).is_err());
            assert!(!fixture.receipt(&maximum).exists());
            for token in [String::new(), "A".into(), "a\nb".into(), "a".repeat(129)] {
                assert!(fixture.execute("cancel-unowned", &token).is_err());
            }
        }

        #[test]
        fn unsafe_types_links_and_permissions_cannot_grant_custody() {
            for kind in ["symlink", "hardlink", "writable", "directory", "fifo"] {
                let fixture = Fixture::new();
                let original = fixture.directory.join("original");
                fixture.write(&original, RELEASED);
                match kind {
                    "symlink" => symlink(&original, &fixture.owner).unwrap(),
                    "hardlink" => std::fs::hard_link(&original, &fixture.owner).unwrap(),
                    "writable" => {
                        fixture.write(&fixture.owner, RELEASED);
                        std::fs::set_permissions(
                            &fixture.owner,
                            std::fs::Permissions::from_mode(0o620),
                        )
                        .unwrap();
                    }
                    "directory" => std::fs::create_dir(&fixture.owner).unwrap(),
                    "fifo" => rustix::fs::mknodat(
                        CWD,
                        &fixture.owner,
                        FileType::Fifo,
                        Mode::from_raw_mode(0o600),
                        0,
                    )
                    .unwrap(),
                    _ => unreachable!(),
                }
                assert!(fixture.execute("claim", "aaa").is_err(), "{kind}");
                assert!(!fixture.root.exists());
                assert_eq!(std::fs::read(&original).unwrap(), RELEASED);
            }
            let fixture = Fixture::new();
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o770))
                .unwrap();
            assert!(fixture.execute("claim", "aaa").is_err());
            assert!(!fixture.owner.exists());
        }

        #[test]
        fn descriptor_checks_reject_replaced_records_and_parents() {
            let fixture = Fixture::new();
            fixture.execute("claim", "aaa").unwrap();
            let mut stage = Stage::Validation;
            let custody =
                Custody::open(fixture.directory.to_str().unwrap(), "aaa", &mut stage).unwrap();
            let record = custody
                .read_record("pair.lock.owner", false)
                .unwrap()
                .unwrap();
            std::fs::rename(&fixture.owner, fixture.directory.join("old-owner")).unwrap();
            fixture.write(&fixture.owner, b"aaa\n");
            assert!(custody.verify(&record).is_err());
            let record = custody
                .read_record("pair.lock.owner", false)
                .unwrap()
                .unwrap();
            fixture.write(&fixture.owner, b"bbb\n");
            assert!(custody.verify(&record).is_err());

            let moved = fixture.directory.with_extension("retained");
            std::fs::rename(&fixture.directory, &moved).unwrap();
            std::fs::create_dir(&fixture.directory).unwrap();
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            assert!(custody.verify_parent().is_err());
            assert_eq!(
                std::fs::read(moved.join("pair.lock.owner")).unwrap(),
                b"bbb\n"
            );
            assert!(!fixture.owner.exists());
        }

        #[test]
        fn failed_publication_preserves_existing_owner_and_private_evidence() {
            let fixture = Fixture::new();
            fixture.execute("claim", "aaa").unwrap();
            let mut stage = Stage::Validation;
            let mut custody =
                Custody::open(fixture.directory.to_str().unwrap(), "bbb", &mut stage).unwrap();
            let error = custody
                .publish("pair.lock.owner", b"bbb\n", None)
                .err()
                .unwrap();
            assert!(error.to_string().contains("destination appeared"));
            assert_eq!(std::fs::read(&fixture.owner).unwrap(), b"aaa\n");
            let private: Vec<_> = std::fs::read_dir(&fixture.directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".pair-write.")
                })
                .collect();
            assert_eq!(private.len(), 1);
            assert_eq!(std::fs::read(&private[0]).unwrap(), b"bbb\n");
        }
    }
}
