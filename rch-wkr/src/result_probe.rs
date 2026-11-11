//! Descriptor-relative result-directory observations for recovery.
//!
//! An unavailable declared output is terminal only after the source root and
//! every traversed parent still name the inspected directories. The caller's
//! source grant excludes cooperating writers; descriptor identity checks also
//! refuse replacements by writers outside that protocol. No output is read,
//! created, removed or followed through a link below the selected root.

use anyhow::Result;
#[cfg(unix)]
use anyhow::ensure;
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
const PROBE_REPLY: &str = "rch-wkr result-directory v1";
const UNSAFE_EXIT: i32 = 73;

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Presence {
    Present,
    Absent,
    NotDirectory,
    Symlink,
}

#[cfg(unix)]
impl Presence {
    fn receipt(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::NotDirectory => "not-directory",
            Self::Symlink => "symlink",
        }
    }
}

/// This small recovery operation runs before Tokio or optional log sinks.
/// A failed observation never emits a receipt that could release ownership.
pub fn main(arguments: &[String]) -> i32 {
    match run(arguments) {
        Ok(receipt) => {
            println!("{receipt}");
            0
        }
        Err(error) => {
            eprintln!("RCH_RESULT_DIRECTORY_UNSAFE {error:#}");
            UNSAFE_EXIT
        }
    }
}

#[cfg(not(unix))]
fn run(_arguments: &[String]) -> Result<String> {
    anyhow::bail!("descriptor-relative result probes require Unix")
}

#[cfg(unix)]
fn run(arguments: &[String]) -> Result<String> {
    if arguments == ["probe"] {
        return Ok(PROBE_REPLY.to_owned());
    }
    ensure!(
        arguments.len() == 3,
        "expected source root, result path and token"
    );
    let root = &arguments[0];
    let relative = &arguments[1];
    let token = &arguments[2];
    validate(root, relative, token)?;
    let presence = probe(Path::new(root), relative)?;
    Ok(format!("{token}:{}", presence.receipt()))
}

#[cfg(unix)]
fn validate(root: &str, relative: &str, token: &str) -> Result<()> {
    ensure!(
        root.starts_with('/') && !root.chars().any(char::is_control),
        "result probe requires an absolute Unix source root"
    );
    ensure!(
        !relative.is_empty()
            && !relative.contains('\\')
            && !relative.chars().any(char::is_control)
            && relative
                .split('/')
                .all(|part| !matches!(part, "" | "." | "..")),
        "invalid admitted result path"
    );
    ensure!(
        !token.is_empty() && token.len() <= 256 && !token.chars().any(char::is_control),
        "invalid result receipt token"
    );
    Ok(())
}

#[cfg(unix)]
fn probe(root: &Path, relative: &str) -> Result<Presence> {
    unix::probe_with(root, relative, |_, _| Ok(()))
}

#[cfg(unix)]
mod unix {
    use super::*;
    use anyhow::Context;
    use rustix::fd::OwnedFd;
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
    use rustix::io::Errno;

    /// A private observation seam lets tests arrange real filesystem races at
    /// the same syscall boundaries as production. The production closure is
    /// empty and is eliminated by monomorphization; no runtime hook exists.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Observation {
        BeforeLookup,
        BeforeOpen,
        Missing,
        Terminal,
    }

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    fn is_directory(info: &Stat) -> bool {
        FileType::from_raw_mode(info.st_mode) == FileType::Directory
    }

    fn unchanged_chain(
        root: &Path,
        root_identity: &Stat,
        held: &[OwnedFd],
        edges: &[(&str, Stat)],
    ) -> Result<()> {
        let current = rustix::fs::stat(root).context("recheck result source root")?;
        ensure!(
            is_directory(&current) && same_inode(&current, root_identity),
            "result source root changed during probe"
        );
        for ((name, expected), parent) in edges.iter().zip(held) {
            let current = rustix::fs::statat(parent, *name, AtFlags::SYMLINK_NOFOLLOW)
                .context("recheck result parent")?;
            ensure!(
                is_directory(&current) && same_inode(&current, expected),
                "result parent changed during probe"
            );
        }
        Ok(())
    }

    pub(super) fn probe_with(
        root: &Path,
        relative: &str,
        mut observe: impl FnMut(Observation, &str) -> Result<()>,
    ) -> Result<Presence> {
        let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        // The configured source root may itself be a system alias (/tmp on
        // Darwin). Every component beneath it is opened without following links.
        let first = rustix::fs::open(root, directory_flags, Mode::empty())
            .context("open result source root")?;
        let root_identity = rustix::fs::fstat(&first).context("inspect result source root")?;
        let mut held = vec![first];
        let mut edges = Vec::new();
        let mut parts = relative.split('/').peekable();
        while let Some(part) = parts.next() {
            let parent = held.last().context("missing result parent descriptor")?;
            observe(Observation::BeforeLookup, part)?;
            let metadata = match rustix::fs::statat(parent, part, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(metadata) => metadata,
                Err(Errno::NOENT) => {
                    observe(Observation::Missing, part)?;
                    unchanged_chain(root, &root_identity, &held, &edges)?;
                    // Recheck the same name after its ancestors. A directory
                    // appearing during revalidation invalidates the first miss.
                    match rustix::fs::statat(parent, part, AtFlags::SYMLINK_NOFOLLOW) {
                        Err(Errno::NOENT) => return Ok(Presence::Absent),
                        Err(error) => return Err(error).context("recheck missing result path"),
                        Ok(_) => anyhow::bail!("result path appeared during absence probe"),
                    }
                }
                Err(error) => return Err(error).context("inspect result path"),
            };
            if !is_directory(&metadata) || parts.peek().is_none() {
                observe(Observation::Terminal, part)?;
                unchanged_chain(root, &root_identity, &held, &edges)?;
                let current = rustix::fs::statat(parent, part, AtFlags::SYMLINK_NOFOLLOW)
                    .context("recheck result entry")?;
                let kind = FileType::from_raw_mode(current.st_mode);
                ensure!(
                    same_inode(&current, &metadata)
                        && kind == FileType::from_raw_mode(metadata.st_mode),
                    "result entry changed during type probe"
                );
                return Ok(match kind {
                    FileType::Symlink => Presence::Symlink,
                    FileType::Directory => Presence::Present,
                    _ => Presence::NotDirectory,
                });
            }
            observe(Observation::BeforeOpen, part)?;
            let child = rustix::fs::openat(
                parent,
                part,
                directory_flags | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .context("open result parent")?;
            let opened = rustix::fs::fstat(&child).context("inspect opened result parent")?;
            ensure!(
                is_directory(&opened) && same_inode(&opened, &metadata),
                "result parent replaced between inspection and open"
            );
            edges.push((part, opened));
            held.push(child);
        }
        anyhow::bail!("empty admitted result path")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::unix::{Observation, probe_with};
    use super::*;

    fn inspect(root: &Path, relative: &str) -> Presence {
        validate(root.to_str().unwrap(), relative, "test-receipt").unwrap();
        probe(root, relative).unwrap()
    }

    #[test]
    fn descriptor_probe_distinguishes_absence_from_links_and_wrong_types() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source : with ' quotes");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("reports")).unwrap();
        std::fs::write(root.join("reports/file"), b"retained").unwrap();
        std::os::unix::fs::symlink(root.join("nowhere"), root.join("dangling")).unwrap();
        std::os::unix::fs::symlink(root.join("reports"), root.join("alias")).unwrap();
        for path in ["missing", "reports/missing", "missing/deep/result"] {
            assert_eq!(inspect(&root, path), Presence::Absent, "{path}");
        }
        for (path, expected) in [
            ("reports", Presence::Present),
            ("reports/file", Presence::NotDirectory),
            ("reports/file/child", Presence::NotDirectory),
            ("dangling", Presence::Symlink),
            ("alias/missing", Presence::Symlink),
        ] {
            assert_eq!(inspect(&root, path), expected, "{path}");
        }
        assert!(probe(&directory.path().join("missing-root"), "reports").is_err());
        assert!(probe(&root.join("dangling"), "reports").is_err());
        let alias = directory.path().join("source-alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert_eq!(inspect(&alias, "reports/missing"), Presence::Absent);
    }

    #[test]
    fn descriptor_probe_never_traverses_links_or_opens_special_entries() {
        for name in ["plain", "with space", "with:colon"] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join(name);
            let outside = directory.path().join("outside");
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("evidence"), b"not an admitted output").unwrap();
            std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
            let socket = std::os::unix::net::UnixListener::bind(root.join("socket")).unwrap();
            for path in ["link", "link/evidence"] {
                assert_eq!(inspect(&root, path), Presence::Symlink);
            }
            for path in ["socket", "socket/child"] {
                assert_eq!(inspect(&root, path), Presence::NotDirectory);
            }
            assert_eq!(
                std::fs::read(outside.join("evidence")).unwrap(),
                b"not an admitted output"
            );
            assert_eq!(std::fs::read_link(root.join("link")).unwrap(), outside);
            drop(socket);
        }
    }

    #[test]
    fn descriptor_probe_refuses_replacement_between_inspection_and_open() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source : with ' quotes");
        std::fs::create_dir_all(root.join("reports/export")).unwrap();
        std::fs::write(root.join("reports/export/evidence"), b"retained").unwrap();
        let mut raced = false;
        let result = probe_with(&root, "reports/export", |point, name| {
            if point == Observation::BeforeOpen && name == "reports" {
                std::fs::rename(root.join("reports"), root.join("retained-reports"))?;
                std::fs::create_dir(root.join("reports"))?;
                raced = true;
            }
            Ok(())
        });
        assert!(raced);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("between inspection and open")
        );
        assert_eq!(
            std::fs::read(root.join("retained-reports/export/evidence")).unwrap(),
            b"retained"
        );
        assert!(root.join("reports").is_dir());
    }

    #[test]
    fn descriptor_probe_rechecks_parent_and_root_names_before_absence() {
        for replace_root in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("source");
            std::fs::create_dir_all(root.join("reports")).unwrap();
            let mut raced = false;
            let result = probe_with(&root, "reports/export", |point, name| {
                if point == Observation::BeforeLookup && name == "export" {
                    if replace_root {
                        std::fs::rename(&root, directory.path().join("retained-source"))?;
                    } else {
                        std::fs::rename(root.join("reports"), root.join("retained-reports"))?;
                    }
                    std::fs::create_dir_all(root.join("reports/export"))?;
                    raced = true;
                }
                Ok(())
            });
            assert!(raced);
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("changed during probe")
            );
            assert!(root.join("reports/export").is_dir());
        }
    }

    #[test]
    fn descriptor_probe_refuses_creation_after_a_negative_lookup() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("reports")).unwrap();
        let mut raced = false;
        let result = probe_with(directory.path(), "reports/export", |point, name| {
            if point == Observation::Missing && name == "export" {
                std::fs::create_dir(directory.path().join("reports/export"))?;
                raced = true;
            }
            Ok(())
        });
        assert!(raced);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("appeared during absence probe")
        );
        assert!(directory.path().join("reports/export").is_dir());
    }

    #[test]
    fn descriptor_probe_revalidates_wrong_type_before_terminal_failure() {
        for link in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let reports = directory.path().join("reports");
            std::fs::create_dir(&reports).unwrap();
            if link {
                std::os::unix::fs::symlink("missing", reports.join("export")).unwrap();
            } else {
                std::fs::write(reports.join("export"), b"retained file").unwrap();
            }
            let mut raced = false;
            let result = probe_with(directory.path(), "reports/export", |point, name| {
                if point == Observation::Terminal && name == "export" {
                    std::fs::rename(reports.join("export"), reports.join("retained-export"))?;
                    std::fs::create_dir(reports.join("export"))?;
                    raced = true;
                }
                Ok(())
            });
            assert!(raced);
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("changed during type probe")
            );
            assert!(reports.join("export").is_dir());
            assert!(std::fs::symlink_metadata(reports.join("retained-export")).is_ok());
        }
    }

    #[test]
    fn worker_contract_rejects_unadmitted_paths_and_tokens() {
        for path in [
            "",
            "/reports",
            "../reports",
            "reports/../out",
            "reports//out",
            "./reports",
            "reports/",
            "reports\n",
            "reports\\out",
        ] {
            assert!(validate("/source", path, "token").is_err(), "{path:?}");
        }
        for root in ["relative", "", "/source\n"] {
            assert!(validate(root, "reports", "token").is_err());
        }
        for token in ["", "token\n", "token\0"] {
            assert!(validate("/source", "reports", token).is_err());
        }
        assert!(validate("/source", "reports", &"t".repeat(257)).is_err());
        assert_eq!(run(&["probe".to_owned()]).unwrap(), PROBE_REPLY);
        assert!(run(&["probe".to_owned(), "extra".to_owned()]).is_err());
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            run(&[
                root.path().to_str().unwrap().to_owned(),
                "missing".to_owned(),
                "bound:token".to_owned()
            ])
            .unwrap(),
            "bound:token:absent"
        );
    }
}
