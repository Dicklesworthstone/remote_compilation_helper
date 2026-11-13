//! Source-grant admission and lock ownership for concurrent source receivers.
//!
//! Disjoint destinations share the invocation activity lock, with shared
//! ancestor locks and an exclusive destination lock. Aliased directories use
//! exclusive activity instead. This foreground supervisor retains every lock
//! while the receiver runs, even if the receiver closes inherited descriptors.
//! No receiver input is consumed before or during admission.

use std::ffi::OsString;

/// Run before the worker starts an async runtime or background threads.
pub fn main(arguments: &[OsString]) -> i32 {
    #[cfg(unix)]
    {
        unix::main(arguments)
    }
    #[cfg(not(unix))]
    {
        let _ = arguments;
        eprintln!("RCH: source upload authority: native upload locks require a Unix worker");
        73
    }
}

#[cfg(unix)]
mod unix {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use rustix::fs::{AtFlags, CWD, Dir, FileType, FlockOperation, Mode, OFlags, Stat};
    use rustix::io::{Errno, FdFlags};
    use sha2::{Digest as _, Sha256};

    const LIMIT: usize = 32 * 1024 * 1024;
    const REFUSED: i32 = 73;
    const PROBE_REPLY: &[u8] = b"rch-wkr source-upload v1\n";
    type Result<T> = std::result::Result<T, io::Error>;

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn lower_hex(byte: u8) -> bool {
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
    }

    fn canonical(path: &str) -> bool {
        path.starts_with('/')
            && !path.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
            && (path == "/"
                || path[1..]
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."))
    }

    fn ancestors(path: &str) -> Vec<String> {
        let mut result = vec![path.to_owned()];
        let mut path = path;
        while path != "/" {
            path = path.rsplit_once('/').map_or(
                "/",
                |(parent, _)| {
                    if parent.is_empty() { "/" } else { parent }
                },
            );
            result.push(path.to_owned());
        }
        result
    }

    fn sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn upload_lock_name(path: &str) -> String {
        let mut bytes = b"rch.source-upload-lock.v1\0".to_vec();
        bytes.extend_from_slice(path.as_bytes());
        format!("upload.{}.lock", sha256(&bytes))
    }

    struct Request<'a> {
        registry: PathBuf,
        token: &'a str,
        root: &'a str,
        command: &'a [OsString],
    }

    impl<'a> Request<'a> {
        fn parse(arguments: &'a [OsString]) -> Result<Self> {
            if arguments.len() < 5 || arguments[0] != "run" {
                return Err(invalid(
                    "expected run <registry> <token> <root> <command> [arguments...]",
                ));
            }
            let registry = PathBuf::from(&arguments[1]);
            let token = arguments[2]
                .to_str()
                .ok_or_else(|| invalid("invalid source identity"))?;
            let root = arguments[3]
                .to_str()
                .ok_or_else(|| invalid("invalid upload destination"))?;
            if !registry.is_absolute()
                || !(1..=128).contains(&token.len())
                || !token.bytes().all(|byte| lower_hex(byte) || byte == b'-')
                || !canonical(root)
                || root == "/"
                || arguments[4].is_empty()
            {
                return Err(invalid(
                    "invalid upload destination, source identity or command",
                ));
            }
            Ok(Self {
                registry,
                token,
                root,
                command: &arguments[4..],
            })
        }
    }

    pub(super) fn main(arguments: &[OsString]) -> i32 {
        if arguments.len() == 1 && arguments[0] == "probe" {
            return match io::stdout().lock().write_all(PROBE_REPLY) {
                Ok(()) => 0,
                Err(_) => REFUSED,
            };
        }
        match Request::parse(arguments).and_then(|request| run(&request)) {
            Ok(status) => status,
            Err(error) => {
                let _ = writeln!(io::stderr().lock(), "RCH: source upload authority: {error}");
                REFUSED
            }
        }
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

    #[derive(Debug)]
    struct Lock {
        descriptor: OwnedFd,
        name: String,
    }

    impl Lock {
        fn acquire(directory: impl AsFd, name: String, operation: FlockOperation) -> Result<Self> {
            let descriptor = rustix::fs::openat(
                &directory,
                name.as_str(),
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?;
            if FileType::from_raw_mode(rustix::fs::fstat(&descriptor)?.st_mode)
                != FileType::RegularFile
            {
                return Err(invalid("upload lock is not a regular file"));
            }
            rustix::fs::flock(&descriptor, operation)?;
            let lock = Self { descriptor, name };
            lock.verify(directory)?;
            Ok(lock)
        }

        fn verify(&self, directory: impl AsFd) -> Result<()> {
            let opened = rustix::fs::fstat(&self.descriptor)?;
            let named =
                rustix::fs::statat(directory, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
                || !same_inode(&opened, &named)
            {
                return Err(invalid("upload lock changed"));
            }
            Ok(())
        }

        fn inherit(&self) -> Result<()> {
            rustix::io::fcntl_setfd(&self.descriptor, FdFlags::empty())?;
            Ok(())
        }
    }

    fn checked_namespace(directory: impl AsFd, registry: &Path, activity: &Lock) -> Result<()> {
        let opened = rustix::fs::fstat(&directory)?;
        let named = rustix::fs::statat(CWD, registry, AtFlags::SYMLINK_NOFOLLOW)?;
        if !same_inode(&opened, &named) {
            return Err(invalid("source registry changed"));
        }
        activity.verify(directory)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Observation {
        LocksAcquired,
        ClaimRead,
        BeforeExclusiveRecheck,
        BeforeFinalCheck,
    }

    fn active_roots(
        directory: impl AsFd,
        token: &str,
        root: &str,
        observe: &mut impl FnMut(Observation) -> Result<()>,
    ) -> Result<Vec<String>> {
        let prefix = format!("{token}.");
        let mut names = Vec::new();
        for entry in Dir::read_from(&directory)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name.starts_with(prefix.as_bytes()) && name.ends_with(b".claim") {
                names.push(OsString::from_vec(name.to_vec()));
            }
        }
        if names.len() != 1 {
            return Err(invalid("source grant is absent or duplicated"));
        }
        let name = &names[0];
        // Prefix and suffix can overlap, for example in `c001.claim`.
        // Check the entire byte shape before taking a bounded digest slice.
        if name.len() != prefix.len() + 64 + b".claim".len() {
            return Err(invalid("invalid source grant identity"));
        }
        let digest = &name.as_bytes()[prefix.len()..prefix.len() + 64];
        if !digest.iter().all(|byte| lower_hex(*byte)) {
            return Err(invalid("invalid source grant identity"));
        }
        let descriptor = rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let before = rustix::fs::fstat(&descriptor)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_size <= 0
            || before.st_size > LIMIT as _
        {
            return Err(invalid("invalid source grant record"));
        }
        let mut file = File::from(descriptor);
        let mut content = Vec::with_capacity(before.st_size as usize);
        Read::by_ref(&mut file)
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut content)?;
        observe(Observation::ClaimRead)?;
        let after = rustix::fs::fstat(&file)?;
        let named = rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if !same_generation(&before, &after)
            || !same_generation(&after, &named)
            || content.len() != before.st_size as usize
            || !content.ends_with(b"\n")
            || sha256(&content).as_bytes() != digest
        {
            return Err(invalid("source grant content changed"));
        }
        let digest =
            std::str::from_utf8(digest).map_err(|_| invalid("invalid source grant identity"))?;
        match rustix::fs::statat(
            &directory,
            format!("{token}.{digest}.cancelling"),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => return Err(invalid("source grant is cancelling")),
            Err(Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        let roots = std::str::from_utf8(&content[..content.len() - 1])
            .map_err(|_| invalid("invalid source grant roots"))?
            .split('\n')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !roots.iter().all(|candidate| canonical(candidate)) {
            return Err(invalid("invalid source grant roots"));
        }
        if !roots.iter().any(|candidate| {
            candidate == "/" || root == candidate || root.starts_with(&format!("{candidate}/"))
        }) {
            return Err(invalid("upload destination is outside its source grant"));
        }
        Ok(roots)
    }

    #[derive(Clone, Copy)]
    struct TopologyEntry {
        kind: FileType,
        device: i128,
        inode: i128,
    }

    fn inspect_topology(path: &str) -> Result<Option<TopologyEntry>> {
        match rustix::fs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => Ok(Some(TopologyEntry {
                kind: FileType::from_raw_mode(metadata.st_mode),
                device: i128::from(metadata.st_dev),
                inode: i128::from(metadata.st_ino),
            })),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn direct_topology(
        roots: &[String],
        root: &str,
        mut inspect: impl FnMut(&str) -> Result<Option<TopologyEntry>>,
    ) -> Result<bool> {
        // Inspect directory prefixes only. The identity map also detects
        // static bind-mount aliases below destinations that do not yet exist.
        let mut selected_roots = roots.iter().map(String::as_str).collect::<BTreeSet<_>>();
        selected_roots.insert(root);
        let mut paths = selected_roots
            .iter()
            .flat_map(|selected| ancestors(selected))
            .collect::<BTreeSet<_>>();
        let mut stamps = BTreeSet::new();
        for selected in &selected_roots {
            if !inspect(selected)?.is_some_and(|metadata| metadata.kind == FileType::RegularFile) {
                let scratch = Path::new(selected).join(".rch-tmp");
                let stamp = scratch.join(".rch-prune-stamp");
                // Every input is a valid UTF-8 root and these suffixes are ASCII.
                let scratch = scratch
                    .to_str()
                    .ok_or_else(|| invalid("invalid scratch path"))?;
                let stamp = stamp
                    .to_str()
                    .ok_or_else(|| invalid("invalid scratch stamp"))?;
                paths.insert(scratch.to_owned());
                paths.insert(stamp.to_owned());
                stamps.insert(stamp.to_owned());
            }
        }
        let mut identities = BTreeMap::new();
        for path in paths {
            let Some(metadata) = inspect(&path)? else {
                continue;
            };
            if metadata.kind == FileType::Symlink {
                return Ok(false);
            }
            if metadata.kind != FileType::Directory {
                // A grant may own a freshness-control file. Only a declared
                // root or scratch stamp may be a regular file, never the
                // destination itself or one of its intermediate components.
                if path == root
                    || (!roots.contains(&path) && !stamps.contains(&path))
                    || metadata.kind != FileType::RegularFile
                {
                    return Err(invalid("source topology is not a directory"));
                }
                continue;
            }
            if identities
                .insert((metadata.device, metadata.inode), path)
                .is_some()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    #[derive(Debug)]
    struct UploadLease {
        locks: Vec<Lock>,
        activity: Lock,
        _directory: OwnedFd,
    }

    impl UploadLease {
        fn acquire(
            request: &Request<'_>,
            mut observe: impl FnMut(Observation) -> Result<()>,
        ) -> Result<Self> {
            let directory = rustix::fs::open(
                &request.registry,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let activity = Lock::acquire(
                &directory,
                format!("{}.activity.lock", request.token),
                FlockOperation::LockShared,
            )?;
            let mut locks = Vec::new();
            let mut paths = ancestors(request.root);
            paths.sort();
            for path in paths {
                locks.push(Lock::acquire(
                    &directory,
                    upload_lock_name(&path),
                    if path == request.root {
                        FlockOperation::LockExclusive
                    } else {
                        FlockOperation::LockShared
                    },
                )?);
            }
            observe(Observation::LocksAcquired)?;
            checked_namespace(&directory, &request.registry, &activity)?;
            let roots = active_roots(&directory, request.token, request.root, &mut observe)?;
            if !direct_topology(&roots, request.root, inspect_topology)? {
                // Release shared/ancestor locks before waiting for exclusive
                // activity. Upgrading in place would deadlock two aliased
                // uploads. A cancellation may win this gap; always recheck.
                while locks.pop().is_some() {}
                rustix::fs::flock(&activity.descriptor, FlockOperation::Unlock)?;
                rustix::fs::flock(&activity.descriptor, FlockOperation::LockExclusive)?;
                observe(Observation::BeforeExclusiveRecheck)?;
                checked_namespace(&directory, &request.registry, &activity)?;
                active_roots(&directory, request.token, request.root, &mut observe)?;
            }
            observe(Observation::BeforeFinalCheck)?;
            checked_namespace(&directory, &request.registry, &activity)?;
            // A later queued ancestor must not hide replacement of an earlier
            // lock name while its old descriptor is still held.
            for lock in &locks {
                lock.verify(&directory)?;
            }
            Ok(Self {
                _directory: directory,
                activity,
                locks,
            })
        }

        fn supervise(&self, command: &[OsString]) -> Result<i32> {
            self.activity.inherit()?;
            for lock in &self.locks {
                lock.inherit()?;
            }
            let status = Command::new(&command[0]).args(&command[1..]).status()?;
            Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
        }
    }

    fn run(request: &Request<'_>) -> Result<i32> {
        let lease = UploadLease::acquire(request, |_| Ok(()))?;
        lease.supervise(request.command)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::symlink;
        use std::sync::mpsc;
        use std::time::Duration;

        struct Fixture {
            base: PathBuf,
            registry: PathBuf,
            roots: Vec<PathBuf>,
            claim: PathBuf,
            digest: String,
            contents: Vec<u8>,
        }

        impl Fixture {
            fn new(names: &[&str]) -> Self {
                let base = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
                let registry = base.join("registry");
                std::fs::create_dir(&registry).unwrap();
                let roots = names.iter().map(|name| base.join(name)).collect::<Vec<_>>();
                for root in &roots {
                    std::fs::create_dir_all(root).unwrap();
                }
                let contents = roots
                    .iter()
                    .map(|path| format!("{}\n", path.display()))
                    .collect::<String>()
                    .into_bytes();
                let digest = sha256(&contents);
                let claim = registry.join(format!("c001.{digest}.claim"));
                std::fs::write(&claim, &contents).unwrap();
                Self {
                    base,
                    registry,
                    roots,
                    claim,
                    digest,
                    contents,
                }
            }

            fn arguments(&self, root: &Path) -> Vec<OsString> {
                vec![
                    "run".into(),
                    self.registry.as_os_str().to_owned(),
                    "c001".into(),
                    root.as_os_str().to_owned(),
                    "true".into(),
                ]
            }

            fn acquire(&self, root: &Path) -> Result<UploadLease> {
                let arguments = self.arguments(root);
                UploadLease::acquire(&Request::parse(&arguments)?, |_| Ok(()))
            }

            fn replace_claim(&mut self, contents: &[u8]) {
                std::fs::rename(&self.claim, self.base.join("retained-claim")).unwrap();
                self.contents = contents.to_vec();
                self.digest = sha256(contents);
                self.claim = self.registry.join(format!("c001.{}.claim", self.digest));
                std::fs::write(&self.claim, contents).unwrap();
            }

            fn cancel(&self) {
                std::fs::write(
                    self.registry
                        .join(format!("c001.{}.cancelling", self.digest)),
                    &self.contents,
                )
                .unwrap();
            }
        }

        #[test]
        fn upload_request_preserves_literal_argv_and_rejects_unsafe_roots() {
            let fixture = Fixture::new(&["literal ' $ source"]);
            let mut arguments = fixture.arguments(&fixture.roots[0]);
            arguments.extend(["--", "-i", "literal $data"].map(OsString::from));
            let request = Request::parse(&arguments).unwrap();
            assert_eq!(request.command, &arguments[4..]);
            assert_eq!(request.root, fixture.roots[0].to_str().unwrap());
            for root in ["/", "relative", "/a/..", "/a/", "/a//b", "/a\nb", "/a\0b"] {
                let mut invalid = arguments.clone();
                invalid[3] = root.into();
                assert!(Request::parse(&invalid).is_err(), "{root:?}");
            }
            for token in ["", "c001/other", "UPPER", "x"] {
                let mut invalid = arguments.clone();
                invalid[2] = token.into();
                assert!(Request::parse(&invalid).is_err(), "{token:?}");
            }
            let mut invalid = arguments.clone();
            invalid[3] = OsString::from_vec(b"/non-utf8-\xff".to_vec());
            assert!(Request::parse(&invalid).is_err());
            assert!(Request::parse(&arguments[..4]).is_err());
            arguments[4].clear();
            assert!(Request::parse(&arguments).is_err());
        }

        #[test]
        fn upload_grants_reject_missing_duplicate_corrupt_and_nonregular_records() {
            for case in [
                "absent",
                "duplicate",
                "digest",
                "overlap",
                "content",
                "symlink",
                "oversized",
                "empty",
            ] {
                let fixture = Fixture::new(&["source"]);
                match case {
                    "absent" => {
                        std::fs::rename(&fixture.claim, fixture.base.join("retained")).unwrap()
                    }
                    "duplicate" => {
                        std::fs::write(
                            fixture
                                .registry
                                .join(format!("c001.{}.claim", "0".repeat(64))),
                            &fixture.contents,
                        )
                        .unwrap();
                    }
                    "digest" => {
                        std::fs::rename(&fixture.claim, fixture.registry.join("c001.invalid.claim"))
                            .unwrap()
                    }
                    "overlap" => {
                        std::fs::rename(&fixture.claim, fixture.registry.join("c001.claim"))
                            .unwrap()
                    }
                    "content" => std::fs::write(&fixture.claim, b"/different\n").unwrap(),
                    "symlink" => {
                        let saved = fixture.base.join("retained");
                        std::fs::rename(&fixture.claim, &saved).unwrap();
                        symlink(saved, &fixture.claim).unwrap();
                    }
                    "oversized" => std::fs::OpenOptions::new()
                        .write(true)
                        .open(&fixture.claim)
                        .unwrap()
                        .set_len((LIMIT + 1) as u64)
                        .unwrap(),
                    "empty" => std::fs::write(&fixture.claim, []).unwrap(),
                    _ => unreachable!(),
                }
                assert!(fixture.acquire(&fixture.roots[0]).is_err(), "{case}");
            }
        }

        #[test]
        fn upload_grants_enforce_canonical_coverage_and_cancellation() {
            for contents in [
                b"/source/../other\n".as_slice(),
                b"/source\n\n",
                b"/source",
                b"/raw-\xff\n",
            ] {
                let mut fixture = Fixture::new(&["source"]);
                fixture.replace_claim(contents);
                assert!(fixture.acquire(&fixture.roots[0]).is_err(), "{contents:?}");
            }
            let fixture = Fixture::new(&["source"]);
            assert!(fixture.acquire(&fixture.roots[0]).is_ok());
            assert!(
                fixture
                    .acquire(&fixture.roots[0].join("new/subdir"))
                    .is_ok()
            );
            assert!(fixture.acquire(&fixture.base.join("source-other")).is_err());
            fixture.cancel();
            assert!(
                fixture
                    .acquire(&fixture.roots[0])
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("cancelling")
            );

            let fixture = Fixture::new(&["source"]);
            symlink(
                fixture.base.join("absent"),
                fixture
                    .registry
                    .join(format!("c001.{}.cancelling", fixture.digest)),
            )
            .unwrap();
            assert!(
                fixture
                    .acquire(&fixture.roots[0])
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("cancelling")
            );
        }

        #[test]
        fn upload_refuses_descriptor_name_changes_before_starting_receiver() {
            for case in ["registry", "activity", "ancestor", "claim"] {
                let fixture = Fixture::new(&["source"]);
                let arguments = fixture.arguments(&fixture.roots[0]);
                let request = Request::parse(&arguments).unwrap();
                let mut changed = false;
                let result = UploadLease::acquire(&request, |point| {
                    if changed
                        || point
                            != if case == "claim" {
                                Observation::ClaimRead
                            } else {
                                Observation::BeforeFinalCheck
                            }
                    {
                        return Ok(());
                    }
                    changed = true;
                    match case {
                        "registry" => {
                            std::fs::rename(&fixture.registry, fixture.base.join("old-registry"))?;
                            std::fs::create_dir(&fixture.registry)?;
                        }
                        "activity" | "ancestor" => {
                            let name = if case == "activity" {
                                "c001.activity.lock".into()
                            } else {
                                upload_lock_name("/")
                            };
                            let path = fixture.registry.join(name);
                            std::fs::rename(&path, fixture.base.join("old-lock"))?;
                            std::fs::write(path, [])?;
                        }
                        "claim" => {
                            std::fs::rename(&fixture.claim, fixture.base.join("old-claim"))?;
                            std::fs::write(&fixture.claim, &fixture.contents)?;
                        }
                        _ => unreachable!(),
                    }
                    Ok(())
                });
                assert!(changed);
                assert!(result.is_err(), "{case}");
            }
        }

        #[test]
        fn topology_detects_directory_identity_aliases_below_missing_destinations() {
            // A deterministic topology oracle, not a privileged mount test.
            // Real symlink aliases and activity fallback are checked below.
            let mut identities = BTreeMap::from([("/", 1), ("/first", 2), ("/alias", 2)]);
            let inspect = |identities: &BTreeMap<&str, i128>, path: &str| {
                Ok(identities.get(path).map(|inode| TopologyEntry {
                    kind: FileType::Directory,
                    device: 3,
                    inode: *inode,
                }))
            };
            assert!(
                !direct_topology(
                    &["/first/missing".into(), "/alias/other".into()],
                    "/first/missing",
                    |path| inspect(&identities, path),
                )
                .unwrap()
            );
            assert!(
                direct_topology(
                    &["/first/missing".into(), "/first/other".into()],
                    "/first/missing",
                    |path| inspect(&identities, path),
                )
                .unwrap()
            );
            identities.extend([
                ("/alias", 3),
                ("/first/.rch-tmp", 4),
                ("/alias/.rch-tmp", 4),
            ]);
            assert!(
                !direct_topology(&["/first".into(), "/alias".into()], "/first", |path| {
                    inspect(&identities, path)
                },)
                .unwrap()
            );
        }

        #[test]
        fn upload_alias_fallback_retains_exclusive_activity_and_rechecks_cancel() {
            for alias in ["root", "scratch", "stamp"] {
                let fixture = Fixture::new(&["source", "other"]);
                let root = &fixture.roots[0];
                let selected = if alias == "root" {
                    let selected = root.join("alias");
                    symlink(&fixture.roots[1], &selected).unwrap();
                    selected
                } else {
                    if alias == "scratch" {
                        symlink(&fixture.roots[1], root.join(".rch-tmp")).unwrap();
                    } else {
                        std::fs::create_dir(root.join(".rch-tmp")).unwrap();
                        symlink(
                            fixture.base.join("absent"),
                            root.join(".rch-tmp/.rch-prune-stamp"),
                        )
                        .unwrap();
                    }
                    root.clone()
                };
                let lease = fixture.acquire(&selected).unwrap();
                assert!(lease.locks.is_empty(), "{alias}");
                let activity = File::open(fixture.registry.join("c001.activity.lock")).unwrap();
                assert_eq!(
                    rustix::fs::flock(&activity, FlockOperation::NonBlockingLockShared),
                    Err(Errno::AGAIN),
                    "{alias}"
                );
                drop(lease);
                let arguments = fixture.arguments(&selected);
                let request = Request::parse(&arguments).unwrap();
                let result = UploadLease::acquire(&request, |point| {
                    if point == Observation::BeforeExclusiveRecheck {
                        fixture.cancel();
                    }
                    Ok(())
                });
                assert!(
                    result.err().unwrap().to_string().contains("cancelling"),
                    "{alias}"
                );
            }
        }

        #[test]
        fn upload_locks_allow_disjoint_roots_and_serialize_nested_destinations() {
            let fixture = Fixture::new(&["first", "second"]);
            let first = fixture.acquire(&fixture.roots[0]).unwrap();
            let (ready_tx, ready_rx) = mpsc::channel();
            let second_arguments = fixture.arguments(&fixture.roots[1]);
            let second_thread = std::thread::spawn(move || {
                let request = Request::parse(&second_arguments).unwrap();
                ready_tx
                    .send(UploadLease::acquire(&request, |_| Ok(())))
                    .unwrap();
            });
            let second = ready_rx
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .unwrap();
            second_thread.join().unwrap();
            let activity = File::open(fixture.registry.join("c001.activity.lock")).unwrap();
            assert_eq!(
                rustix::fs::flock(&activity, FlockOperation::NonBlockingLockExclusive),
                Err(Errno::AGAIN)
            );
            drop(first);
            assert_eq!(
                rustix::fs::flock(&activity, FlockOperation::NonBlockingLockExclusive),
                Err(Errno::AGAIN)
            );
            drop(second);
            rustix::fs::flock(&activity, FlockOperation::NonBlockingLockExclusive).unwrap();
            rustix::fs::flock(&activity, FlockOperation::Unlock).unwrap();

            for suffix in ["", "nested/leaf"] {
                let first = fixture.acquire(&fixture.roots[0]).unwrap();
                let nested = if suffix.is_empty() {
                    fixture.roots[0].clone()
                } else {
                    fixture.roots[0].join(suffix)
                };
                let arguments = fixture.arguments(&nested);
                let (ready_tx, ready_rx) = mpsc::channel();
                let thread = std::thread::spawn(move || {
                    ready_tx
                        .send(UploadLease::acquire(
                            &Request::parse(&arguments).unwrap(),
                            |_| Ok(()),
                        ))
                        .unwrap();
                });
                assert!(
                    matches!(
                        ready_rx.recv_timeout(Duration::from_millis(100)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ),
                    "{suffix}"
                );
                drop(first);
                let nested = ready_rx
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap()
                    .unwrap();
                thread.join().unwrap();
                drop(nested);
            }
        }

        #[test]
        fn queued_upload_rechecks_cancellation_after_acquiring_activity() {
            let fixture = Fixture::new(&["source"]);
            let directory = rustix::fs::open(
                &fixture.registry,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let activity = Lock::acquire(
                &directory,
                "c001.activity.lock".into(),
                FlockOperation::LockExclusive,
            )
            .unwrap();
            let arguments = fixture.arguments(&fixture.roots[0]);
            let (ready_tx, ready_rx) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                ready_tx
                    .send(UploadLease::acquire(
                        &Request::parse(&arguments).unwrap(),
                        |_| Ok(()),
                    ))
                    .unwrap();
            });
            assert!(matches!(
                ready_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            fixture.cancel();
            drop(activity);
            let result = ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            thread.join().unwrap();
            assert!(result.err().unwrap().to_string().contains("cancelling"));
        }
    }
}
