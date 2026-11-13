//! Durable, non-replacing retirement of an owned source tree into its sibling.
//!
//! The dispatcher owns the source activity grant. This helper seals the exact
//! identity and both literal paths before an atomic Linux no-replace rename;
//! retries accept only that sealed directory. It never copies or removes data.

use anyhow::Result;
use std::io::Write;

const REFUSED_EXIT: i32 = 74;

/// Run before the async runtime and optional logging sinks are initialized.
pub fn main(arguments: &[String]) -> i32 {
    let result = run(arguments).and_then(|reply| {
        writeln!(std::io::stdout().lock(), "{reply}")?;
        Ok(())
    });
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("RCH_SOURCE_RETENTION_REFUSED: {error:#}");
            REFUSED_EXIT
        }
    }
}

#[cfg(target_os = "linux")]
fn run(arguments: &[String]) -> Result<&'static str> {
    linux::run(arguments)
}

#[cfg(not(target_os = "linux"))]
fn run(_arguments: &[String]) -> Result<&'static str> {
    anyhow::bail!("Linux source retention required")
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::{Context, ensure};
    use rustix::fd::{AsFd, OwnedFd};
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags, Stat};
    use rustix::io::Errno;
    use sha2::{Digest, Sha256};

    const PROBE_REPLY: &str = "rch-wkr source-retain v1";
    const RETAINED_REPLY: &str = "RCH_SOURCE_RETAINED";
    const ABSENT_REPLY: &str = "RCH_SOURCE_ABSENT_BEFORE_MATERIALIZATION";
    const MARKER_NAME: &str = ".rch-retention-v1";
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    pub(super) fn run(arguments: &[String]) -> Result<&'static str> {
        capability()?;
        match arguments {
            [operation] if operation == "probe" => Ok(PROBE_REPLY),
            [operation, root, retained, identity, allow_absent] if operation == "retain" => {
                let request = Request::new(root, retained, identity, allow_absent)?;
                retain(&request, |_| Ok(()))
            }
            _ => anyhow::bail!("invalid retention arguments"),
        }
    }

    fn capability() -> Result<()> {
        // Empty names cannot select or mutate any entry. ENOENT proves the
        // actual no-replace syscall is available; ENOSYS/EPERM never do.
        ensure!(
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                "",
                rustix::fs::CWD,
                "",
                RenameFlags::NOREPLACE,
            ) == Err(Errno::NOENT),
            "Linux no-replace rename syscall unavailable"
        );
        Ok(())
    }

    struct Request<'a> {
        root: &'a str,
        retained: &'a str,
        identity: &'a str,
        parent: &'a str,
        source_name: &'a str,
        retained_name: &'a str,
        allow_absent: bool,
    }

    impl<'a> Request<'a> {
        fn new(
            root: &'a str,
            retained: &'a str,
            identity: &'a str,
            allow_absent: &str,
        ) -> Result<Self> {
            let literal = |path: &str| {
                path.starts_with('/')
                    && !path.ends_with('/')
                    && !path.contains('\\')
                    && !path.chars().any(char::is_control)
                    && path[1..]
                        .split('/')
                        .all(|part| !matches!(part, "" | "." | ".."))
            };
            ensure!(
                literal(root) && literal(retained) && root != retained,
                "invalid retained siblings"
            );
            let (parent, source_name) = root.rsplit_once('/').context("invalid source path")?;
            let (retained_parent, retained_name) =
                retained.rsplit_once('/').context("invalid retained path")?;
            ensure!(parent == retained_parent, "invalid retained siblings");
            ensure!(
                identity.len() == 32
                    && identity
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "invalid source identity"
            );
            ensure!(matches!(allow_absent, "0" | "1"), "invalid absence policy");
            Ok(Self {
                root,
                retained,
                identity,
                parent,
                source_name,
                retained_name,
                allow_absent: allow_absent == "1",
            })
        }
    }

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    fn metadata(directory: impl AsFd, name: &str) -> Result<Option<Stat>> {
        match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) => Ok(Some(info)),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    struct Parent<'a> {
        directories: Vec<OwnedFd>,
        names: Vec<&'a str>,
    }

    impl<'a> Parent<'a> {
        fn open(path: &'a str, allow_absent: bool) -> Result<Option<Self>> {
            let mut parent = Self {
                directories: vec![rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty())?],
                names: Vec::new(),
            };
            for component in path.split('/').filter(|component| !component.is_empty()) {
                let next = match rustix::fs::openat(
                    parent.descriptor(),
                    component,
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                ) {
                    Ok(next) => next,
                    Err(Errno::NOENT) if allow_absent => {
                        parent.verify()?;
                        ensure!(
                            metadata(parent.descriptor(), component)?.is_none(),
                            "source parent appeared during absence observation"
                        );
                        return Ok(None);
                    }
                    Err(error) => {
                        return Err(error).context("open materialized source parent");
                    }
                };
                parent.directories.push(next);
                parent.names.push(component);
            }
            parent.verify()?;
            Ok(Some(parent))
        }

        fn descriptor(&self) -> &OwnedFd {
            self.directories.last().expect("root descriptor retained")
        }

        fn verify(&self) -> Result<()> {
            // Retain every ancestor until the final acknowledgement. A rename
            // in a detached/replaced parent is not retention at the bound path.
            for (edge, name) in self.directories.windows(2).zip(&self.names).rev() {
                ensure!(
                    same_inode(
                        &rustix::fs::statat(&edge[0], *name, AtFlags::SYMLINK_NOFOLLOW)?,
                        &rustix::fs::fstat(&edge[1])?,
                    ),
                    "source parent changed during retention"
                );
            }
            Ok(())
        }
    }

    fn owned_directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd> {
        let directory = rustix::fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
            .context("open owned source directory")?;
        ensure!(
            rustix::fs::fstat(&directory)?.st_uid == rustix::process::geteuid().as_raw(),
            "source directory has a foreign owner"
        );
        Ok(directory)
    }

    fn marker_value(request: &Request<'_>) -> String {
        use std::fmt::Write as _;

        // Preserve the existing marker's exact ASCII JSON preimage. In
        // particular non-ASCII paths use lowercase UTF-16 escape sequences,
        // including surrogate pairs, rather than serde_json's UTF-8 spelling.
        let mut preimage = String::from("[");
        for (index, value) in [
            "rch.source_retention.v1",
            request.identity,
            request.root,
            request.retained,
        ]
        .into_iter()
        .enumerate()
        {
            if index != 0 {
                preimage.push(',');
            }
            preimage.push('"');
            for character in value.chars() {
                match character {
                    '"' => preimage.push_str("\\\""),
                    '\\' => preimage.push_str("\\\\"),
                    ' '..='~' => preimage.push(character),
                    other => {
                        let mut units = [0u16; 2];
                        for unit in other.encode_utf16(&mut units) {
                            let _ = write!(preimage, "\\u{unit:04x}");
                        }
                    }
                }
            }
            preimage.push('"');
        }
        preimage.push(']');
        let hash = Sha256::digest(preimage.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("rch-retention-v1:{}:{hash}", request.identity)
    }

    fn marker(directory: &OwnedFd, value: &str, create: bool) -> Result<()> {
        if create {
            match rustix::fs::symlinkat(value, directory, MARKER_NAME) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(error).context("seal source retention identity"),
            }
        }
        let entry = rustix::fs::statat(directory, MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            FileType::from_raw_mode(entry.st_mode) == FileType::Symlink
                && entry.st_uid == rustix::process::geteuid().as_raw()
                && rustix::fs::readlinkat(directory, MARKER_NAME, Vec::new())?.as_bytes()
                    == value.as_bytes(),
            "source retention marker does not bind this identity and both paths"
        );
        ensure!(
            same_inode(
                &entry,
                &rustix::fs::statat(directory, MARKER_NAME, AtFlags::SYMLINK_NOFOLLOW)?,
            ),
            "source retention marker changed during observation"
        );
        rustix::fs::fsync(directory).context("sync source retention marker")?;
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Observation {
        ParentOpened,
        MarkerSealed,
        BeforeRename,
        Renamed,
        Reconcile,
    }

    fn retain(
        request: &Request<'_>,
        mut observe: impl FnMut(Observation) -> Result<()>,
    ) -> Result<&'static str> {
        let Some(parent) = Parent::open(request.parent, request.allow_absent)? else {
            return Ok(ABSENT_REPLY);
        };
        observe(Observation::ParentOpened)?;
        let directory = parent.descriptor();
        let source = metadata(directory, request.source_name)?;
        let destination = metadata(directory, request.retained_name)?;
        let value = marker_value(request);
        let Some(source) = source else {
            if destination.is_none() {
                ensure!(
                    request.allow_absent,
                    "materialized source and retained snapshot are both missing"
                );
                parent.verify()?;
                ensure!(
                    metadata(directory, request.source_name)?.is_none()
                        && metadata(directory, request.retained_name)?.is_none(),
                    "source appeared during absence observation"
                );
                return Ok(ABSENT_REPLY);
            }
            let retained = owned_directory(directory, request.retained_name)?;
            marker(&retained, &value, false)?;
            rustix::fs::fsync(directory).context("sync retained source parent")?;
            observe(Observation::Reconcile)?;
            ensure!(
                metadata(directory, request.source_name)?.is_none(),
                "source appeared during retention reconciliation"
            );
            let current = metadata(directory, request.retained_name)?;
            let held = rustix::fs::fstat(&retained)?;
            ensure!(
                current
                    .as_ref()
                    .is_some_and(|current| same_inode(current, &held)),
                "retained source changed during reconciliation"
            );
            parent.verify()?;
            return Ok(RETAINED_REPLY);
        };
        ensure!(
            FileType::from_raw_mode(source.st_mode) == FileType::Directory,
            "source root is not a real directory"
        );
        ensure!(
            destination.is_none(),
            "retained destination already exists while source is present"
        );
        let source_directory = owned_directory(directory, request.source_name)?;
        let held = rustix::fs::fstat(&source_directory)?;
        ensure!(
            same_inode(&source, &held),
            "source changed before retention"
        );
        marker(&source_directory, &value, true)?;
        observe(Observation::MarkerSealed)?;
        let current = metadata(directory, request.source_name)?;
        ensure!(
            current
                .as_ref()
                .is_some_and(|current| same_inode(current, &held)),
            "source changed before no-replace rename"
        );
        parent.verify()?;
        observe(Observation::BeforeRename)?;
        rustix::fs::renameat_with(
            directory,
            request.source_name,
            directory,
            request.retained_name,
            RenameFlags::NOREPLACE,
        )
        .context("source no-replace rename refused")?;
        rustix::fs::fsync(directory).context("sync source retirement rename")?;
        observe(Observation::Renamed)?;
        let current = metadata(directory, request.retained_name)?;
        ensure!(
            metadata(directory, request.source_name)?.is_none()
                && current
                    .as_ref()
                    .is_some_and(|current| same_inode(current, &held)),
            "source retention did not preserve the exact directory"
        );
        marker(&source_directory, &value, false)?;
        parent.verify()?;
        Ok(RETAINED_REPLY)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::path::{Path, PathBuf};

        const IDENTITY: &str = "1234567890abcdef1234567890abcdef";

        struct Fixture {
            _owner: tempfile::TempDir,
            parent: PathBuf,
            source: PathBuf,
            retained: PathBuf,
        }

        impl Fixture {
            fn new() -> Self {
                let owner = tempfile::tempdir().unwrap();
                let parent = owner.path().join("parent");
                std::fs::create_dir(&parent).unwrap();
                Self {
                    _owner: owner,
                    source: parent.join("source ' \" α 😀"),
                    retained: parent.join("retained ' \" α 😀"),
                    parent,
                }
            }

            fn request(&self, allow_absent: bool) -> Request<'_> {
                Request::new(
                    self.source.to_str().unwrap(),
                    self.retained.to_str().unwrap(),
                    IDENTITY,
                    if allow_absent { "1" } else { "0" },
                )
                .unwrap()
            }

            fn create_source(&self) {
                std::fs::create_dir(&self.source).unwrap();
                std::fs::write(self.source.join("input"), b"\0source bytes\xff\n").unwrap();
            }
        }

        #[test]
        fn capability_checks_the_real_no_replace_syscall_and_exact_arguments() {
            assert_eq!(run(&["probe".into()]).unwrap(), PROBE_REPLY);
            for arguments in [
                vec![],
                vec!["probe".into(), "extra".into()],
                vec!["retain".into()],
            ] {
                assert!(run(&arguments).is_err());
            }
        }

        #[test]
        fn paths_identity_and_absence_policy_are_literal() {
            for source in [
                "/",
                "relative",
                "/x/",
                "/a/./x",
                "/a/../x",
                "/a//x",
                "/a/x\n",
                "/a/x\u{0085}",
                "/a/x\\y",
                "/other/x",
                "/a/retained",
            ] {
                assert!(Request::new(source, "/a/retained", IDENTITY, "0").is_err());
            }
            for identity in [
                "",
                "short",
                "1234567890ABCDEF1234567890ABCDEF",
                "g234567890abcdef1234567890abcdef",
            ] {
                assert!(Request::new("/a/source", "/a/retained", identity, "0").is_err());
            }
            for policy in ["", "true", "2", "01"] {
                assert!(Request::new("/a/source", "/a/retained", IDENTITY, policy).is_err());
            }
        }

        #[test]
        fn marker_hash_preserves_ascii_json_and_surrogate_pair_encoding() {
            let request =
                Request::new("/a/source α 😀 \"", "/a/retained α 😀 \"", IDENTITY, "0").unwrap();
            let preimage = r#"["rch.source_retention.v1","1234567890abcdef1234567890abcdef","/a/source \u03b1 \ud83d\ude00 \"","/a/retained \u03b1 \ud83d\ude00 \""]"#;
            let hash = Sha256::digest(preimage.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(
                marker_value(&request),
                format!("rch-retention-v1:{IDENTITY}:{hash}"),
            );
        }

        #[test]
        fn retention_moves_the_exact_tree_preserves_bytes_and_reconciles_retries() {
            capability().unwrap();
            let fixture = Fixture::new();
            fixture.create_source();
            let file = fixture.source.join("input");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o751)).unwrap();
            std::fs::hard_link(&file, fixture.source.join("hardlink")).unwrap();
            symlink("input", fixture.source.join("link")).unwrap();
            symlink("../missing", fixture.source.join("dangling")).unwrap();
            let before = std::fs::metadata(&file).unwrap();
            let source_inode = std::fs::metadata(&fixture.source).unwrap().ino();
            for _ in 0..2 {
                assert_eq!(
                    retain(&fixture.request(false), |_| Ok(())).unwrap(),
                    RETAINED_REPLY
                );
                assert!(!fixture.source.exists());
                assert_eq!(
                    std::fs::metadata(&fixture.retained).unwrap().ino(),
                    source_inode
                );
                assert_eq!(
                    std::fs::read(fixture.retained.join("input")).unwrap(),
                    b"\0source bytes\xff\n"
                );
                let after = std::fs::metadata(fixture.retained.join("input")).unwrap();
                assert_eq!(
                    (
                        after.dev(),
                        after.ino(),
                        after.mode(),
                        after.nlink(),
                        after.mtime(),
                        after.mtime_nsec()
                    ),
                    (
                        before.dev(),
                        before.ino(),
                        before.mode(),
                        before.nlink(),
                        before.mtime(),
                        before.mtime_nsec()
                    ),
                );
                assert_eq!(
                    std::fs::metadata(fixture.retained.join("hardlink"))
                        .unwrap()
                        .ino(),
                    before.ino()
                );
                assert_eq!(
                    std::fs::read_link(fixture.retained.join("link")).unwrap(),
                    Path::new("input")
                );
                assert_eq!(
                    std::fs::read_link(fixture.retained.join("dangling")).unwrap(),
                    Path::new("../missing")
                );
            }
            std::fs::rename(&fixture.retained, &fixture.source).unwrap();
            assert_eq!(
                retain(&fixture.request(false), |_| Ok(())).unwrap(),
                RETAINED_REPLY
            );
            let foreign = Request::new(
                fixture.source.to_str().unwrap(),
                fixture.retained.to_str().unwrap(),
                "abcdef1234567890abcdef1234567890",
                "0",
            )
            .unwrap();
            assert!(retain(&foreign, |_| Ok(())).is_err());
            assert_eq!(
                std::fs::metadata(&fixture.retained).unwrap().ino(),
                source_inode
            );
        }

        #[test]
        fn absence_requires_explicit_policy_and_never_follows_parent_or_leaf_links() {
            let fixture = Fixture::new();
            assert!(retain(&fixture.request(false), |_| Ok(())).is_err());
            assert_eq!(
                retain(&fixture.request(true), |_| Ok(())).unwrap(),
                ABSENT_REPLY
            );
            let missing = fixture.parent.join("missing");
            let source = missing.join("source");
            let retained = missing.join("retained");
            let absent = Request::new(
                source.to_str().unwrap(),
                retained.to_str().unwrap(),
                IDENTITY,
                "1",
            )
            .unwrap();
            assert_eq!(retain(&absent, |_| Ok(())).unwrap(), ABSENT_REPLY);
            assert!(!missing.exists());
            symlink(&fixture.parent, &missing).unwrap();
            assert!(retain(&absent, |_| Ok(())).is_err());
            symlink("nonexistent", &fixture.source).unwrap();
            assert!(retain(&fixture.request(true), |_| Ok(())).is_err());
            assert!(fixture.source.is_symlink());
        }

        #[test]
        fn conflicting_destinations_and_markers_are_preserved() {
            for kind in ["directory", "file", "symlink"] {
                let fixture = Fixture::new();
                fixture.create_source();
                match kind {
                    "directory" => std::fs::create_dir(&fixture.retained).unwrap(),
                    "file" => std::fs::write(&fixture.retained, b"foreign retained").unwrap(),
                    _ => symlink("nonexistent", &fixture.retained).unwrap(),
                }
                assert!(retain(&fixture.request(false), |_| Ok(())).is_err());
                assert_eq!(
                    std::fs::read(fixture.source.join("input")).unwrap(),
                    b"\0source bytes\xff\n"
                );
                assert!(std::fs::symlink_metadata(fixture.source.join(MARKER_NAME)).is_err());
                assert!(std::fs::symlink_metadata(&fixture.retained).is_ok());
            }
            for link in [false, true] {
                let fixture = Fixture::new();
                fixture.create_source();
                let marker = fixture.source.join(MARKER_NAME);
                if link {
                    symlink("foreign marker", &marker).unwrap();
                } else {
                    std::fs::write(&marker, b"foreign marker").unwrap();
                }
                assert!(retain(&fixture.request(false), |_| Ok(())).is_err());
                assert!(fixture.source.is_dir());
                assert!(!fixture.retained.exists());
                if link {
                    assert_eq!(
                        std::fs::read_link(marker).unwrap(),
                        Path::new("foreign marker")
                    );
                } else {
                    assert_eq!(std::fs::read(marker).unwrap(), b"foreign marker");
                }
            }
        }

        #[test]
        fn destination_created_at_rename_boundary_is_never_replaced() {
            capability().unwrap();
            let fixture = Fixture::new();
            fixture.create_source();
            let error = retain(&fixture.request(false), |event| {
                if event == Observation::BeforeRename {
                    std::fs::create_dir(&fixture.retained)?;
                    std::fs::write(fixture.retained.join("peer"), b"peer tree")?;
                }
                Ok(())
            })
            .unwrap_err();
            assert!(
                error.to_string().contains("no-replace rename refused"),
                "{error:#}"
            );
            assert_eq!(
                std::fs::read(fixture.retained.join("peer")).unwrap(),
                b"peer tree"
            );
            assert_eq!(
                std::fs::read(fixture.source.join("input")).unwrap(),
                b"\0source bytes\xff\n"
            );
        }

        #[test]
        fn substituted_sources_parents_and_completed_names_never_acknowledge() {
            for stage in [
                Observation::MarkerSealed,
                Observation::BeforeRename,
                Observation::Renamed,
            ] {
                let fixture = Fixture::new();
                fixture.create_source();
                let moved = fixture._owner.path().join("retained-evidence");
                assert!(
                    retain(&fixture.request(false), |event| {
                        if event == stage {
                            let name = match stage {
                                Observation::MarkerSealed => &fixture.source,
                                Observation::BeforeRename => &fixture.parent,
                                Observation::Renamed => &fixture.retained,
                                _ => unreachable!(),
                            };
                            std::fs::rename(name, &moved)?;
                            std::fs::create_dir(name)?;
                        }
                        Ok(())
                    })
                    .is_err(),
                    "{stage:?}"
                );
                assert!(moved.is_dir());
            }
            let fixture = Fixture::new();
            fixture.create_source();
            assert_eq!(
                retain(&fixture.request(false), |_| Ok(())).unwrap(),
                RETAINED_REPLY
            );
            assert!(
                retain(&fixture.request(false), |event| {
                    if event == Observation::Reconcile {
                        std::fs::create_dir(&fixture.source)?;
                    }
                    Ok(())
                })
                .is_err()
            );
            assert!(fixture.retained.join("input").is_file());
        }
    }
}
