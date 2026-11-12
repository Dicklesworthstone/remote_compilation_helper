//! Discover exact source ownership or settle an already authorized cancellation.
//!
//! This coordinator holds both registries' activity and metadata locks while
//! the existing shell transaction checks immutable records. It grants no source
//! access, never creates a missing activity lock, and leaves process teardown to
//! the surrounding namespace controller's independently owned deadline.

use std::io::{Read, Write};

#[cfg(unix)]
use anyhow::Context as _;
use anyhow::Result;

const REFUSED: i32 = 73;

/// Run before the async runtime and optional logging or disk-backed sinks.
pub fn main(arguments: &[String]) -> i32 {
    let result = run(arguments, std::io::stdin().lock(), std::io::stdout().lock());
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "RCH_SOURCE_CANCELLATION_UNSETTLED {error:#}"
            );
            REFUSED
        }
    }
}

fn run(arguments: &[String], input: impl Read, mut output: impl Write) -> Result<()> {
    #[cfg(unix)]
    {
        if arguments == ["probe"] {
            output.write_all(b"rch-wkr source-settlement v1\n")?;
            return Ok(());
        }
        let request = unix::Request::parse(arguments)?;
        let scale = match std::env::var(rch_common::timing::TIMING_SCALE_ENV) {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => "1".to_owned(),
            Err(error) => return Err(error).context("invalid RCH_TIMING_SCALE"),
        };
        let scale = crate::control_clock::timing_scale(&scale)
            .context("invalid RCH_TIMING_SCALE (expected finite 1..10)")?;
        unix::settle(&request, input, output, scale)
    }
    #[cfg(not(unix))]
    {
        let _ = (arguments, input, &mut output);
        anyhow::bail!("native source settlement requires a Unix worker")
    }
}

#[cfg(unix)]
mod unix {
    use anyhow::{Context as _, Result, bail, ensure};
    use rustix::fd::{AsFd, OwnedFd};
    use rustix::fs::{AtFlags, CWD, Dir, FileType, FlockOperation, Mode, OFlags, Stat};
    use rustix::io::{Errno, FdFlags};
    use sha2::{Digest as _, Sha256};
    use std::io::{Read, Write};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const MAX_ROOTS_BYTES: u64 = 32 * 1024 * 1024;
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::CLOEXEC);
    const LOCK_FLAGS: OFlags = OFlags::RDWR
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::CLOEXEC);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Operation {
        Discover,
        Locate,
        Settle,
    }

    pub(super) struct Request<'a> {
        current: &'a str,
        legacy: &'a str,
        token: &'a str,
        digest: &'a str,
        transaction: &'a str,
        operation: Operation,
        expected: &'a str,
    }

    fn lower_hex(byte: u8) -> bool {
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
    }

    fn registry_parts(path: &str) -> Result<(&str, &str)> {
        ensure!(Path::new(path).is_absolute(), "invalid registry namespace");
        let (parent, name) = path
            .rsplit_once('/')
            .context("invalid registry namespace")?;
        ensure!(
            !name.is_empty() && name != "." && name != ".." && !path.contains('\0'),
            "invalid registry namespace"
        );
        Ok((if parent.is_empty() { "/" } else { parent }, name))
    }

    impl<'a> Request<'a> {
        pub(super) fn parse(arguments: &'a [String]) -> Result<Self> {
            let [
                current,
                legacy,
                token,
                digest,
                transaction,
                operation,
                expected,
            ] = arguments
            else {
                bail!("invalid settlement request");
            };
            let operation = match (operation.as_str(), expected.as_str()) {
                ("discover", "") => Operation::Discover,
                ("locate", "") => Operation::Locate,
                ("settle-cancel", "current" | "legacy") => Operation::Settle,
                _ => bail!("invalid source authority namespace request"),
            };
            ensure!(
                (1..=128).contains(&token.len())
                    && token.bytes().all(|byte| lower_hex(byte) || byte == b'-')
                    && digest.len() == 64
                    && digest.bytes().all(lower_hex),
                "invalid settlement identity"
            );
            ensure!(current != legacy, "invalid registry namespace");
            registry_parts(current)?;
            registry_parts(legacy)?;
            Ok(Self {
                current,
                legacy,
                token,
                digest,
                transaction,
                operation,
                expected,
            })
        }
    }

    struct Admission<'a> {
        token: &'a str,
        started: Instant,
        deadline: Instant,
    }

    impl<'a> Admission<'a> {
        fn new(token: &'a str, duration: Duration) -> Self {
            let started = Instant::now();
            Self {
                token,
                started,
                deadline: started + duration,
            }
        }

        fn check(&self, lock: &str) -> Result<()> {
            let now = Instant::now();
            ensure!(
                now < self.deadline,
                "RCH_SOURCE_SETTLEMENT_LOCK_BUSY identity={} lock={} elapsed_ms={}",
                self.token,
                lock,
                now.duration_since(self.started).as_millis(),
            );
            Ok(())
        }

        fn pause(&self) {
            std::thread::sleep(
                self.deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(20)),
            );
        }
    }

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
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
            "unsafe registry ownership or file type"
        );
        ensure!(
            directory || info.st_nlink == 1,
            "registry lock has multiple links"
        );
        Ok(())
    }

    fn heal_group_writable_lock(descriptor: &OwnedFd) -> Result<()> {
        let info = rustix::fs::fstat(descriptor)?;
        if FileType::from_raw_mode(info.st_mode) == FileType::RegularFile
            && info.st_uid == rustix::process::geteuid().as_raw()
            && info.st_nlink == 1
            && info.st_mode & 0o022 != 0
            && info.st_mode & 0o6000 == 0
        {
            // Only a legacy same-owner single-link inode inside an already
            // verified private directory can lose these two write bits.
            rustix::fs::fchmod(descriptor, Mode::from_raw_mode(info.st_mode & 0o7755))?;
        }
        Ok(())
    }

    fn absent_at(directory: impl AsFd, name: &str) -> Result<bool> {
        match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(false),
            Err(Errno::NOENT) => Ok(true),
            Err(error) => Err(error.into()),
        }
    }

    struct Registry<'a> {
        path: &'a str,
        parent_path: &'a str,
        name: &'a str,
        parent: OwnedFd,
        directory: OwnedFd,
        activity_locked: bool,
    }

    struct Absent<'a> {
        path: &'a str,
        parent_path: &'a str,
        name: &'a str,
        parent: Option<OwnedFd>,
    }

    struct Lock {
        registry: usize,
        name: String,
        descriptor: OwnedFd,
    }

    struct State<'a> {
        token: &'a str,
        registries: Vec<Registry<'a>>,
        absent: Vec<Absent<'a>>,
        locks: Vec<Lock>,
        absent_activity: Vec<usize>,
        empty_peers: Vec<usize>,
    }

    fn identity_evidence(directory: &OwnedFd, token: &str) -> Result<bool> {
        let prefix = format!("{token}.");
        let activity = format!("{token}.activity.lock");
        let mut found = false;
        for child in ["", "released", "cancelled", "quarantine"] {
            let opened;
            let scan = if child.is_empty() {
                directory
            } else {
                opened = match rustix::fs::openat(directory, child, DIRECTORY_FLAGS, Mode::empty())
                {
                    Ok(descriptor) => descriptor,
                    Err(Errno::NOENT) => continue,
                    Err(error) => return Err(error.into()),
                };
                private(&rustix::fs::fstat(&opened)?, true)?;
                &opened
            };
            for entry in Dir::read_from(scan)? {
                let entry = entry?;
                let name = entry.file_name().to_bytes();
                if child.is_empty() && name == activity.as_bytes() {
                    continue;
                }
                let Some(record) = name.strip_prefix(prefix.as_bytes()) else {
                    continue;
                };
                found = true;
                ensure!(
                    record.len() > 65
                        && record[64] == b'.'
                        && record[..64].iter().copied().all(lower_hex),
                    "unrecognized same-identity registry evidence"
                );
                let allowed = match child {
                    "" => matches!(&record[65..], b"claim" | b"pending" | b"cancelling"),
                    "released" | "cancelled" => &record[65..] == b"claim",
                    "quarantine" => &record[65..] == b"pending",
                    _ => unreachable!(),
                };
                ensure!(allowed, "unrecognized same-identity registry evidence");
            }
            if !child.is_empty() {
                let held = rustix::fs::fstat(scan)?;
                private(&held, true)?;
                ensure!(
                    same_inode(
                        &held,
                        &rustix::fs::statat(directory, child, AtFlags::SYMLINK_NOFOLLOW)?,
                    ),
                    "registry evidence directory changed during settlement"
                );
            }
        }
        Ok(found)
    }

    impl<'a> State<'a> {
        fn open(request: &Request<'a>) -> Result<Self> {
            let mut state = Self {
                token: request.token,
                registries: Vec::new(),
                absent: Vec::new(),
                locks: Vec::new(),
                absent_activity: Vec::new(),
                empty_peers: Vec::new(),
            };
            for path in [request.current, request.legacy] {
                let (parent_path, name) = registry_parts(path)?;
                let parent = match rustix::fs::open(parent_path, DIRECTORY_FLAGS, Mode::empty()) {
                    Ok(parent) => parent,
                    Err(Errno::NOENT) => {
                        state.absent.push(Absent {
                            path,
                            parent_path,
                            name,
                            parent: None,
                        });
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                private(&rustix::fs::fstat(&parent)?, true)?;
                let directory =
                    match rustix::fs::openat(&parent, name, DIRECTORY_FLAGS, Mode::empty()) {
                        Ok(directory) => directory,
                        Err(Errno::NOENT) => {
                            state.absent.push(Absent {
                                path,
                                parent_path,
                                name,
                                parent: Some(parent),
                            });
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };
                let identity = rustix::fs::fstat(&directory)?;
                private(&identity, true)?;
                for existing in &state.registries {
                    ensure!(
                        !same_inode(&identity, &rustix::fs::fstat(&existing.directory)?),
                        "registry namespaces alias the same directory"
                    );
                }
                state.registries.push(Registry {
                    path,
                    parent_path,
                    name,
                    parent,
                    directory,
                    activity_locked: false,
                });
            }
            ensure!(
                !state.registries.is_empty() || request.operation == Operation::Discover,
                "no worker registry evidence for identity={}",
                request.token
            );
            Ok(state)
        }

        fn verify(&self) -> Result<()> {
            for missing in &self.absent {
                if let Some(parent) = &missing.parent {
                    let held = rustix::fs::fstat(parent)?;
                    private(&held, true)?;
                    ensure!(
                        same_inode(
                            &held,
                            &rustix::fs::statat(
                                CWD,
                                missing.parent_path,
                                AtFlags::SYMLINK_NOFOLLOW
                            )?,
                        ),
                        "absent registry parent changed during settlement"
                    );
                    ensure!(
                        absent_at(parent, missing.name)?,
                        "registry appeared during settlement"
                    );
                } else {
                    ensure!(
                        absent_at(CWD, missing.parent_path)?,
                        "absent registry parent appeared during settlement"
                    );
                }
                // Recheck the complete spelling too, after the pinned-parent
                // checks, so a concurrently appearing parent cannot hide a
                // newly published registry behind an earlier absent result.
                ensure!(
                    absent_at(CWD, missing.path)?,
                    "registry appeared during settlement"
                );
            }
            for registry in &self.registries {
                let parent = rustix::fs::fstat(&registry.parent)?;
                let directory = rustix::fs::fstat(&registry.directory)?;
                private(&parent, true)?;
                private(&directory, true)?;
                ensure!(
                    same_inode(
                        &parent,
                        &rustix::fs::statat(CWD, registry.parent_path, AtFlags::SYMLINK_NOFOLLOW)?,
                    ),
                    "registry parent changed during settlement"
                );
                ensure!(
                    same_inode(
                        &directory,
                        &rustix::fs::statat(
                            &registry.parent,
                            registry.name,
                            AtFlags::SYMLINK_NOFOLLOW
                        )?,
                    ),
                    "registry changed during settlement"
                );
            }
            for lock in &self.locks {
                let held = rustix::fs::fstat(&lock.descriptor)?;
                private(&held, false)?;
                ensure!(
                    same_inode(
                        &held,
                        &rustix::fs::statat(
                            &self.registries[lock.registry].directory,
                            &lock.name,
                            AtFlags::SYMLINK_NOFOLLOW,
                        )?,
                    ),
                    "registry lock changed during settlement"
                );
            }
            let activity = format!("{}.activity.lock", self.token);
            for index in &self.absent_activity {
                ensure!(
                    absent_at(&self.registries[*index].directory, &activity)?,
                    "registry activity lock appeared during settlement"
                );
            }
            for index in &self.empty_peers {
                ensure!(
                    !identity_evidence(&self.registries[*index].directory, self.token)?,
                    "source identity appeared in registry without an activity lock"
                );
            }
            Ok(())
        }

        fn acquire(&mut self, admission: &Admission<'_>) -> Result<()> {
            // Drain all activity before taking either metadata mutex, always
            // in current/legacy order. An empty peer gets no new token lock.
            for name in [
                format!("{}.activity.lock", self.token),
                "metadata.lock".to_owned(),
            ] {
                let metadata = name == "metadata.lock";
                for index in 0..self.registries.len() {
                    let lock_path = format!("{}/{name}", self.registries[index].path);
                    admission.check(&lock_path)?;
                    let flags = if metadata {
                        LOCK_FLAGS | OFlags::CREATE
                    } else {
                        LOCK_FLAGS
                    };
                    let descriptor = match rustix::fs::openat(
                        &self.registries[index].directory,
                        &name,
                        flags,
                        Mode::RUSR | Mode::WUSR,
                    ) {
                        Ok(descriptor) => descriptor,
                        Err(Errno::NOENT) if !metadata => {
                            self.absent_activity.push(index);
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };
                    heal_group_writable_lock(&descriptor)?;
                    let held = rustix::fs::fstat(&descriptor)?;
                    private(&held, false)?;
                    for lock in &self.locks {
                        ensure!(
                            !same_inode(&held, &rustix::fs::fstat(&lock.descriptor)?),
                            "registry locks alias the same inode"
                        );
                    }
                    self.locks.push(Lock {
                        registry: index,
                        name: name.clone(),
                        descriptor,
                    });
                    loop {
                        self.verify()?;
                        // A descheduled waiter cannot acquire a lock after the
                        // original shared window expires, even if it is free.
                        admission.check(&lock_path)?;
                        match rustix::fs::flock(
                            &self.locks.last().expect("just opened lock").descriptor,
                            FlockOperation::NonBlockingLockExclusive,
                        ) {
                            Ok(()) => {
                                admission.check(&lock_path)?;
                                if !metadata {
                                    self.registries[index].activity_locked = true;
                                }
                                break;
                            }
                            Err(Errno::AGAIN | Errno::ACCESS) => {}
                            Err(error) => return Err(error.into()),
                        }
                        admission.check(&lock_path)?;
                        admission.pause();
                    }
                }
            }
            self.verify()?;
            admission.check("registry discovery")
        }

        fn select(
            &mut self,
            request: &Request<'_>,
            admission: &Admission<'_>,
        ) -> Result<Option<usize>> {
            let mut candidates = Vec::new();
            for (index, registry) in self.registries.iter().enumerate() {
                if identity_evidence(&registry.directory, self.token)? {
                    candidates.push(index);
                } else if !registry.activity_locked {
                    self.empty_peers.push(index);
                }
            }
            self.verify()?;
            admission.check("registry discovery")?;
            if candidates.is_empty() && request.operation == Operation::Discover {
                return Ok(None);
            }
            ensure!(
                candidates.len() == 1,
                "{} registries contain identity={}; expected exactly one",
                candidates.len(),
                self.token
            );
            let selected = candidates[0];
            if request.operation == Operation::Settle {
                ensure!(
                    self.namespace(selected, request) == request.expected,
                    "source authority namespace changed from recorded binding"
                );
                ensure!(
                    self.registries[selected].activity_locked,
                    "source cancellation activity lock is absent"
                );
            }
            Ok(Some(selected))
        }

        fn namespace(&self, selected: usize, request: &Request<'_>) -> &'static str {
            if self.registries[selected].path == request.current {
                "current"
            } else {
                "legacy"
            }
        }

        fn transaction(&self, selected: usize, request: &Request<'_>, roots: &[u8]) -> Result<()> {
            // The synchronous entry point has no other threads. Our directory
            // descriptors stay CLOEXEC; these locks and any enclosing reserve
            // lease survive exec. If this coordinator dies, the transaction
            // pins them until the outer controller settles the entire group.
            for lock in &self.locks {
                rustix::io::fcntl_setfd(&lock.descriptor, FdFlags::empty())?;
            }
            let operation = if request.operation == Operation::Settle {
                "settle-cancel"
            } else {
                "locate"
            };
            let mut child = Command::new("sh")
                .args([
                    "-c",
                    request.transaction,
                    "rch-source-settlement",
                    self.registries[selected].path,
                    request.token,
                    request.digest,
                    operation,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .context("cannot start worker settlement transaction")?;
            for lock in &self.locks {
                rustix::io::fcntl_setfd(&lock.descriptor, FdFlags::CLOEXEC)?;
            }
            child
                .stdin
                .take()
                .context("missing transaction input")?
                .write_all(roots)?;
            let mut reply = Vec::new();
            child
                .stdout
                .take()
                .context("missing transaction output")?
                .take(8)
                .read_to_end(&mut reply)?;
            let expected = if request.operation == Operation::Settle {
                b"settled"
            } else {
                b"located"
            };
            ensure!(
                reply == expected,
                "invalid worker settlement response identity={}",
                request.token
            );
            let status = child.wait()?;
            self.verify()?;
            ensure!(
                status.success(),
                "worker transaction did not confirm exact cancellation identity={}",
                request.token
            );
            Ok(())
        }
    }

    pub(super) fn settle(
        request: &Request<'_>,
        input: impl Read,
        mut output: impl Write,
        scale: f64,
    ) -> Result<()> {
        let admission = Admission::new(request.token, Duration::from_secs_f64(5.0 * scale));
        let mut roots = Vec::new();
        input.take(MAX_ROOTS_BYTES + 1).read_to_end(&mut roots)?;
        ensure!(
            !roots.is_empty()
                && roots.len() as u64 <= MAX_ROOTS_BYTES
                && format!("{:x}", Sha256::digest(&roots)) == request.digest,
            "settlement roots do not match identity digest"
        );
        let mut state = State::open(request)?;
        state.acquire(&admission)?;
        let Some(selected) = state.select(request, &admission)? else {
            output.write_all(b"RCH_SOURCE_AUTHORITY_DISCOVERY absent\n")?;
            return Ok(());
        };
        state.verify()?;
        admission.check("registry discovery")?;
        state.transaction(selected, request, &roots)?;
        match request.operation {
            Operation::Discover => writeln!(
                output,
                "RCH_SOURCE_AUTHORITY_DISCOVERY {}",
                state.namespace(selected, request)
            )?,
            Operation::Locate => writeln!(
                output,
                "RCH_SOURCE_AUTHORITY_NAMESPACE {}",
                state.namespace(selected, request)
            )?,
            Operation::Settle => output.write_all(b"RCH_SOURCE_CANCELLATION_SETTLED\n")?,
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
        use std::path::PathBuf;

        const ROOTS: &[u8] = b"/owned/source\n";
        const TOKEN: &str = "aa01";

        struct Fixture {
            _directory: tempfile::TempDir,
            current: PathBuf,
            legacy: PathBuf,
            arguments: Vec<String>,
        }

        fn directory(path: &Path) {
            fs::create_dir_all(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }

        fn record(path: &Path) {
            fs::write(path, ROOTS).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        impl Fixture {
            fn new(evidence: bool, activity: bool) -> Self {
                let temporary = tempfile::Builder::new()
                    .disable_cleanup(true)
                    .tempdir()
                    .unwrap();
                directory(temporary.path());
                let current = temporary.path().join("current/claims-v1");
                let legacy = temporary.path().join("legacy/claims-v1");
                for path in [&current, &legacy] {
                    directory(path.parent().unwrap());
                    directory(path);
                    record(&path.join("metadata.lock"));
                }
                let digest = format!("{:x}", Sha256::digest(ROOTS));
                if evidence {
                    record(&current.join(format!("{TOKEN}.{digest}.claim")));
                }
                if activity {
                    record(&current.join(format!("{TOKEN}.activity.lock")));
                }
                let arguments = vec![
                    current.to_string_lossy().into_owned(),
                    legacy.to_string_lossy().into_owned(),
                    TOKEN.to_owned(),
                    digest,
                    "exit 99".to_owned(),
                    "discover".to_owned(),
                    String::new(),
                ];
                Self {
                    _directory: temporary,
                    current,
                    legacy,
                    arguments,
                }
            }

            fn admission(&self) -> Admission<'_> {
                Admission::new(TOKEN, Duration::from_secs(5))
            }

            fn activity(&self) -> PathBuf {
                self.current.join(format!("{TOKEN}.activity.lock"))
            }
        }

        #[test]
        fn requests_reject_ambiguous_identity_namespace_and_operation() {
            let fixture = Fixture::new(true, true);
            for (index, bad) in [
                (0, "relative"),
                (0, "/"),
                (0, "/registry/"),
                (0, "/registry/.."),
                (2, ""),
                (2, "a/b"),
                (2, "AA"),
                (3, "a"),
                (5, "claim"),
                (6, "current"),
            ] {
                let mut arguments = fixture.arguments.clone();
                arguments[index] = bad.into();
                assert!(Request::parse(&arguments).is_err(), "{index}: {bad:?}");
            }
            let mut arguments = fixture.arguments.clone();
            arguments[1] = arguments[0].clone();
            assert!(Request::parse(&arguments).is_err());
            arguments = fixture.arguments.clone();
            arguments[2] = "a".repeat(129);
            assert!(Request::parse(&arguments).is_err());
            arguments = fixture.arguments.clone();
            arguments[5] = "settle-cancel".into();
            assert!(Request::parse(&arguments).is_err());
            arguments[6] = "legacy".into();
            assert!(Request::parse(&arguments).is_ok());
        }

        #[test]
        fn discovery_locks_exact_namespace_without_allocating_peer_activity() {
            let fixture = Fixture::new(true, true);
            let request = Request::parse(&fixture.arguments).unwrap();
            let original = fs::metadata(fixture.activity()).unwrap().ino();
            let mut state = State::open(&request).unwrap();
            let admission = fixture.admission();
            state.acquire(&admission).unwrap();
            let selected = state.select(&request, &admission).unwrap().unwrap();
            assert_eq!(state.namespace(selected, &request), "current");
            assert_eq!(fs::metadata(fixture.activity()).unwrap().ino(), original);
            assert!(
                !fixture
                    .legacy
                    .join(format!("{TOKEN}.activity.lock"))
                    .exists()
            );
            for lock in &state.locks {
                let other = rustix::fs::openat(
                    &state.registries[lock.registry].directory,
                    &lock.name,
                    LOCK_FLAGS,
                    Mode::empty(),
                )
                .unwrap();
                assert!(matches!(
                    rustix::fs::flock(&other, FlockOperation::NonBlockingLockExclusive),
                    Err(Errno::AGAIN | Errno::ACCESS)
                ));
            }
        }

        #[test]
        fn optional_discovery_confirms_absence_without_running_a_transaction() {
            let mut fixture = Fixture::new(false, false);
            let mut output = Vec::new();
            settle(
                &Request::parse(&fixture.arguments).unwrap(),
                ROOTS,
                &mut output,
                1.0,
            )
            .unwrap();
            assert_eq!(output, b"RCH_SOURCE_AUTHORITY_DISCOVERY absent\n");
            assert!(!fixture.activity().exists());
            assert!(
                !fixture
                    .legacy
                    .join(format!("{TOKEN}.activity.lock"))
                    .exists()
            );
            fixture.arguments[5] = "locate".into();
            output.clear();
            assert!(
                settle(
                    &Request::parse(&fixture.arguments).unwrap(),
                    ROOTS,
                    &mut output,
                    1.0
                )
                .is_err()
            );
            assert!(output.is_empty());
        }

        #[test]
        fn settlement_requires_existing_activity_and_recorded_namespace() {
            for (activity, expected, detail) in [
                (false, "current", "activity lock is absent"),
                (true, "legacy", "changed from recorded binding"),
            ] {
                let mut fixture = Fixture::new(true, activity);
                fixture.arguments[5] = "settle-cancel".into();
                fixture.arguments[6] = expected.into();
                let request = Request::parse(&fixture.arguments).unwrap();
                let mut state = State::open(&request).unwrap();
                let admission = fixture.admission();
                state.acquire(&admission).unwrap();
                assert!(
                    state
                        .select(&request, &admission)
                        .unwrap_err()
                        .to_string()
                        .contains(detail)
                );
                assert_eq!(fixture.activity().exists(), activity);
            }
        }

        #[test]
        fn identity_in_both_namespaces_or_unknown_same_token_names_refuses() {
            let fixture = Fixture::new(true, true);
            record(
                &fixture
                    .legacy
                    .join(format!("{TOKEN}.{}.claim", fixture.arguments[3])),
            );
            let request = Request::parse(&fixture.arguments).unwrap();
            let mut state = State::open(&request).unwrap();
            let admission = fixture.admission();
            state.acquire(&admission).unwrap();
            assert!(
                state
                    .select(&request, &admission)
                    .unwrap_err()
                    .to_string()
                    .contains("2 registries")
            );

            for (child, suffix, allowed) in [
                ("", "claim", true),
                ("", "pending", true),
                ("", "cancelling", true),
                ("released", "claim", true),
                ("cancelled", "claim", true),
                ("quarantine", "pending", true),
                ("released", "pending", false),
                ("cancelled", "cancelling", false),
                ("quarantine", "claim", false),
                ("", "claim.extra", false),
            ] {
                let fixture = Fixture::new(false, false);
                let path = fixture.current.join(child);
                directory(&path);
                record(&path.join(format!("{TOKEN}.{}.{}", fixture.arguments[3], suffix)));
                let fd =
                    rustix::fs::open(&fixture.current, DIRECTORY_FLAGS, Mode::empty()).unwrap();
                let result = identity_evidence(&fd, TOKEN);
                assert_eq!(result.is_ok(), allowed, "{child}/{suffix}: {result:?}");
                if allowed {
                    assert!(result.unwrap());
                }
            }
        }

        #[test]
        fn expired_admission_never_takes_even_an_uncontended_lock() {
            let fixture = Fixture::new(true, true);
            let request = Request::parse(&fixture.arguments).unwrap();
            let mut state = State::open(&request).unwrap();
            let admission = Admission::new(TOKEN, Duration::ZERO);
            let error = state.acquire(&admission).unwrap_err().to_string();
            assert!(error.contains("RCH_SOURCE_SETTLEMENT_LOCK_BUSY"));
            assert!(state.locks.is_empty());
        }

        #[test]
        fn contended_peer_metadata_consumes_the_original_shared_window() {
            let fixture = Fixture::new(true, true);
            let blocker = rustix::fs::open(
                fixture.legacy.join("metadata.lock"),
                LOCK_FLAGS,
                Mode::empty(),
            )
            .unwrap();
            rustix::fs::flock(&blocker, FlockOperation::NonBlockingLockExclusive).unwrap();
            let request = Request::parse(&fixture.arguments).unwrap();
            let mut state = State::open(&request).unwrap();
            let admission = Admission::new(TOKEN, Duration::from_millis(30));
            let error = state.acquire(&admission).unwrap_err().to_string();
            assert!(error.contains("RCH_SOURCE_SETTLEMENT_LOCK_BUSY"));
            assert!(error.contains(fixture.legacy.to_str().unwrap()));
            assert!(admission.started.elapsed() >= Duration::from_millis(30));
            assert!(state.registries[0].activity_locked);
            assert!(
                !fixture
                    .legacy
                    .join(format!("{TOKEN}.activity.lock"))
                    .exists()
            );
        }

        #[test]
        fn lock_replacement_never_becomes_a_new_owned_inode() {
            let fixture = Fixture::new(true, true);
            let request = Request::parse(&fixture.arguments).unwrap();
            let mut state = State::open(&request).unwrap();
            state.acquire(&fixture.admission()).unwrap();
            fs::rename(
                fixture.activity(),
                fixture.current.join("retained-activity"),
            )
            .unwrap();
            record(&fixture.activity());
            assert!(
                state
                    .verify()
                    .unwrap_err()
                    .to_string()
                    .contains("registry lock changed")
            );
        }

        #[test]
        fn registry_and_parent_replacement_are_not_acknowledged() {
            for replace_parent in [false, true] {
                let fixture = Fixture::new(true, true);
                let request = Request::parse(&fixture.arguments).unwrap();
                let state = State::open(&request).unwrap();
                let path = if replace_parent {
                    fixture.current.parent().unwrap()
                } else {
                    &fixture.current
                };
                fs::rename(path, path.with_extension("retained")).unwrap();
                directory(path);
                assert!(state.verify().is_err());
            }
        }

        #[test]
        fn absent_parent_registry_and_activity_must_stay_absent() {
            for stage in ["parent", "registry", "activity"] {
                let mut fixture = Fixture::new(true, true);
                let appearing = match stage {
                    "parent" => fixture._directory.path().join("missing"),
                    "registry" => fixture._directory.path().join("missing-registry"),
                    _ => fixture.legacy.join(format!("{TOKEN}.activity.lock")),
                };
                if stage == "parent" {
                    fixture.arguments[1] =
                        appearing.join("claims-v1").to_string_lossy().into_owned();
                } else if stage == "registry" {
                    fixture.arguments[1] = appearing.to_string_lossy().into_owned();
                }
                let request = Request::parse(&fixture.arguments).unwrap();
                let mut state = State::open(&request).unwrap();
                state.acquire(&fixture.admission()).unwrap();
                if stage == "activity" {
                    record(&appearing);
                } else {
                    directory(&appearing);
                }
                assert!(state.verify().is_err(), "{stage}");
            }
        }

        #[test]
        fn empty_peer_cannot_gain_identity_during_the_transaction() {
            let fixture = Fixture::new(true, true);
            let request = Request::parse(&fixture.arguments).unwrap();
            let mut state = State::open(&request).unwrap();
            let admission = fixture.admission();
            state.acquire(&admission).unwrap();
            state.select(&request, &admission).unwrap();
            record(
                &fixture
                    .legacy
                    .join(format!("{TOKEN}.{}.pending", fixture.arguments[3])),
            );
            assert!(
                state
                    .verify()
                    .unwrap_err()
                    .to_string()
                    .contains("identity appeared")
            );
        }

        #[test]
        fn legacy_writable_mutex_heals_only_owned_single_link_regular_files() {
            for kind in ["regular", "multiple-links", "set-id", "symlink"] {
                let fixture = Fixture::new(true, true);
                let activity = fixture.activity();
                fs::set_permissions(&activity, fs::Permissions::from_mode(0o666)).unwrap();
                let original = fs::metadata(&activity).unwrap();
                match kind {
                    "multiple-links" => {
                        fs::hard_link(&activity, fixture.current.join("linked-lock")).unwrap()
                    }
                    "set-id" => {
                        fs::set_permissions(&activity, fs::Permissions::from_mode(0o6666)).unwrap()
                    }
                    "symlink" => {
                        let retained = fixture.current.join("retained-lock");
                        fs::rename(&activity, &retained).unwrap();
                        symlink(retained, &activity).unwrap();
                    }
                    _ => {}
                }
                let request = Request::parse(&fixture.arguments).unwrap();
                let mut state = State::open(&request).unwrap();
                let result = state.acquire(&fixture.admission());
                if kind == "regular" {
                    result.unwrap();
                    let after = fs::metadata(&activity).unwrap();
                    assert_eq!(after.ino(), original.ino());
                    assert_eq!(after.mode() & 0o7777, 0o644);
                } else {
                    assert!(result.is_err(), "{kind}");
                    assert_ne!(fs::metadata(&activity).unwrap().mode() & 0o022, 0, "{kind}");
                }
            }
        }

        #[test]
        fn aliased_registry_names_and_untrusted_directory_modes_refuse() {
            let mut fixture = Fixture::new(true, true);
            fixture.arguments[1] = fixture
                .current
                .parent()
                .unwrap()
                .join("./claims-v1")
                .to_string_lossy()
                .into_owned();
            let request = Request::parse(&fixture.arguments).unwrap();
            assert!(
                State::open(&request)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("alias")
            );
            for parent in [false, true] {
                let fixture = Fixture::new(true, true);
                let path = if parent {
                    fixture.current.parent().unwrap()
                } else {
                    &fixture.current
                };
                fs::set_permissions(path, fs::Permissions::from_mode(0o777)).unwrap();
                assert!(State::open(&Request::parse(&fixture.arguments).unwrap()).is_err());
            }
        }

        #[test]
        fn roots_are_bounded_and_digest_checked_before_opening_registries() {
            let fixture = Fixture::new(true, true);
            let request = Request::parse(&fixture.arguments).unwrap();
            for roots in [
                Vec::new(),
                b"/different\n".to_vec(),
                vec![b'a'; MAX_ROOTS_BYTES as usize + 1],
            ] {
                let mut output = Vec::new();
                let error = settle(&request, roots.as_slice(), &mut output, 1.0).unwrap_err();
                assert!(error.to_string().contains("roots do not match"));
                assert!(output.is_empty());
                assert!(
                    !fixture
                        .legacy
                        .join(format!("{TOKEN}.activity.lock"))
                        .exists()
                );
            }
        }
    }
}
