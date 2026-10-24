//! Inventory a quiescent retrieval stage without turning lost subtrees into
//! successful empty Make output. Baseline discovery deliberately permits
//! missing directories; publication must not reuse that permissive walker.
//!
//! Every descendant lookup is relative to its held parent descriptor. No
//! symlink or special file is opened, and missing/replaced entries fail the
//! whole inventory before the publisher writes a baseline or a checkpoint.
//! This is not a new artifact policy or a substitute for transfer completion,
//! content verification, publication ownership or source-release evidence.

use anyhow::{Context, Result};
use rustix::fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags, Stat, fstat, open, openat, statat};
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

fn directory_flags() -> OFlags {
    OFlags::RDONLY
        | OFlags::DIRECTORY
        | OFlags::CLOEXEC
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::NOCTTY
}

/// Ignore access time: enumerating a directory may itself update it. Identity,
/// type, permissions, ownership, size and change/modify times must stay put.
fn same_entry(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
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

fn require_same(expected: &Stat, actual: &Stat, relative: &Path) -> Result<()> {
    anyhow::ensure!(
        same_entry(expected, actual),
        "retrieval staging entry changed at {}; delivery remains pending",
        relative.display()
    );
    Ok(())
}

pub(super) fn regular_files(root: &Path) -> Result<Vec<PathBuf>> {
    scan(root, &mut |_| Ok(()))
}

/// The observer runs after a name's initial stat, before descending into it.
/// Tests inject namespace interruptions here; production never mutates a name.
fn scan(root: &Path, observed: &mut impl FnMut(&Path) -> Result<()>) -> Result<Vec<PathBuf>> {
    let before = statat(CWD, root, AtFlags::SYMLINK_NOFOLLOW)
        .context("retrieval staging directory is missing or invalid; delivery remains pending")?;
    anyhow::ensure!(
        FileType::from_raw_mode(before.st_mode) == FileType::Directory,
        "retrieval staging root is not a real directory; delivery remains pending"
    );
    let held = File::from(open(root, directory_flags(), Mode::empty())?);
    require_same(&before, &fstat(&held)?, root)?;
    let mut files = Vec::new();
    visit(&held, Path::new(""), &mut files, observed)?;
    require_same(&before, &fstat(&held)?, root)?;
    require_same(
        &before,
        &statat(CWD, root, AtFlags::SYMLINK_NOFOLLOW)?,
        root,
    )?;
    files.sort();
    Ok(files)
}

fn visit(
    directory: &File,
    relative: &Path,
    files: &mut Vec<PathBuf>,
    observed: &mut impl FnMut(&Path) -> Result<()>,
) -> Result<()> {
    let before = fstat(directory)?;
    let mut entries = Dir::read_from(directory)?;
    while let Some(entry) = entries.read() {
        super::super::publication_runtime::checkpoint()?;
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = OsStr::from_bytes(name);
        let path = relative.join(name);
        // Do not trust dirent.d_type: some filesystems report Unknown. A
        // nofollow stat also notices an entry lost since the directory read.
        let initial = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).with_context(|| {
            format!(
                "inspect staged output {}; delivery remains pending",
                path.display()
            )
        })?;
        let kind = FileType::from_raw_mode(initial.st_mode);
        anyhow::ensure!(
            kind != FileType::Symlink,
            "symlink in recovery output: {}; delivery remains pending",
            path.display()
        );
        anyhow::ensure!(
            matches!(kind, FileType::Directory | FileType::RegularFile),
            "non-regular recovery output: {}; delivery remains pending",
            path.display()
        );
        observed(&path)?;
        if kind == FileType::Directory {
            let child = File::from(
                openat(directory, name, directory_flags(), Mode::empty()).with_context(|| {
                    format!(
                        "open staged directory {}; delivery remains pending",
                        path.display()
                    )
                })?,
            );
            require_same(&initial, &fstat(&child)?, &path)?;
            visit(&child, &path, files, observed)?;
            require_same(&initial, &fstat(&child)?, &path)?;
        } else {
            files.push(path.clone());
        }
        require_same(
            &initial,
            &statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?,
            &path,
        )?;
    }
    // Adding/removing/replacing an entry must not silently change the set
    // during traversal, even if readdir did not return the changed name.
    require_same(&before, &fstat(directory)?, relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    #[cfg(not(target_vendor = "apple"))]
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    #[cfg(not(target_vendor = "apple"))]
    fn make_fifo(path: &Path) -> std::io::Result<()> {
        Ok(rustix::fs::mkfifoat(CWD, path, Mode::RUSR | Mode::WUSR)?)
    }

    // rustix has no mkfifoat on Apple targets and this crate forbids unsafe code.
    #[cfg(target_vendor = "apple")]
    fn make_fifo(path: &Path) -> std::io::Result<()> {
        let status = std::process::Command::new("/usr/bin/mkfifo")
            .args(["-m", "600"])
            .arg(path)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "mkfifo {}: {status}",
                path.display()
            )))
        }
    }

    struct Fixture {
        root: PathBuf,
        stage: PathBuf,
        retained: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::Builder::new()
                .disable_cleanup(true)
                .tempdir()
                .unwrap()
                .keep();
            let stage = root.join("stage");
            let retained = root.join("retained");
            std::fs::create_dir_all(stage.join("build/deep")).unwrap();
            std::fs::write(stage.join("build/deep/app"), b"original executable").unwrap();
            std::fs::write(root.join("caller-output"), b"previous caller output").unwrap();
            Self {
                root,
                stage,
                retained,
            }
        }

        fn caller_unchanged(&self) {
            assert_eq!(
                std::fs::read(self.root.join("caller-output")).unwrap(),
                b"previous caller output"
            );
        }
    }

    #[test]
    fn nested_inventory_preserves_literal_names_archives_and_empty_directories() {
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.stage.join("empty/nested")).unwrap();
        let mut expected = vec![PathBuf::from("build/deep/app")];
        #[cfg_attr(target_vendor = "apple", allow(unused_mut))]
        let mut names = vec![
            OsString::from("library.a"),
            OsString::from("distribution.tar"),
            OsString::from("report with spaces.txt"),
            OsString::from(".rch-clean-overlay-base.tar"),
        ];
        // APFS refuses names that are not UTF-8 (EILSEQ).
        #[cfg(not(target_vendor = "apple"))]
        names.push(OsString::from_vec(b"object-\xff.o".to_vec()));
        for name in names {
            let path = PathBuf::from("build").join(name);
            std::fs::write(fixture.stage.join(&path), b"retained bytes").unwrap();
            expected.push(path);
        }
        expected.sort();
        // Selection remains the publisher's responsibility; this inventory
        // neither invents exclusions nor removes the retained source archive.
        for _ in 0..2 {
            assert_eq!(regular_files(&fixture.stage).unwrap(), expected);
        }
        fixture.caller_unchanged();
    }

    #[test]
    fn disappearing_descendant_is_an_error_not_an_empty_success_and_can_retry() {
        let fixture = Fixture::new();
        let original = fixture.stage.join("build/deep");
        let inode = std::fs::metadata(original.join("app")).unwrap().ino();
        let mut injected = false;
        let result = scan(&fixture.stage, &mut |path| {
            if path == Path::new("build/deep") {
                injected = true;
                std::fs::rename(&original, &fixture.retained)?;
            }
            Ok(())
        });
        assert!(injected);
        assert!(result.is_err(), "lost subtree was accepted as empty");
        assert_eq!(
            std::fs::read(fixture.retained.join("app")).unwrap(),
            b"original executable"
        );
        assert_eq!(
            std::fs::metadata(fixture.retained.join("app"))
                .unwrap()
                .ino(),
            inode
        );
        fixture.caller_unchanged();
        // Restore the same test-owned tree, not regenerated build output.
        std::fs::rename(&fixture.retained, &original).unwrap();
        assert_eq!(
            regular_files(&fixture.stage).unwrap(),
            [PathBuf::from("build/deep/app")]
        );
        assert_eq!(
            std::fs::metadata(original.join("app")).unwrap().ino(),
            inode
        );
    }

    #[test]
    fn replacement_descendants_are_not_adopted_or_followed() {
        for replacement in ["empty-directory", "symlink", "fifo"] {
            let fixture = Fixture::new();
            let original = fixture.stage.join("build/deep");
            let mut injected = false;
            let result = scan(&fixture.stage, &mut |path| {
                if path == Path::new("build/deep") {
                    injected = true;
                    std::fs::rename(&original, &fixture.retained)?;
                    match replacement {
                        "empty-directory" => std::fs::create_dir(&original)?,
                        "symlink" => symlink(&fixture.retained, &original)?,
                        "fifo" => make_fifo(&original)?,
                        _ => unreachable!(),
                    }
                }
                Ok(())
            });
            assert!(injected);
            assert!(result.is_err(), "{replacement}");
            assert_eq!(
                std::fs::read(fixture.retained.join("app")).unwrap(),
                b"original executable"
            );
            assert!(std::fs::symlink_metadata(&original).is_ok());
            if replacement == "symlink" {
                assert_eq!(std::fs::read_link(&original).unwrap(), fixture.retained);
            }
            fixture.caller_unchanged();
        }
    }

    #[test]
    fn root_replacement_during_descent_keeps_both_trees_and_refuses_delivery() {
        let fixture = Fixture::new();
        let mut injected = false;
        let result = scan(&fixture.stage, &mut |path| {
            if path == Path::new("build/deep") {
                injected = true;
                std::fs::rename(&fixture.stage, &fixture.retained)?;
                std::fs::create_dir(&fixture.stage)?;
                std::fs::write(fixture.stage.join("replacement"), b"do not publish")?;
            }
            Ok(())
        });
        assert!(injected);
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(fixture.retained.join("build/deep/app")).unwrap(),
            b"original executable"
        );
        assert_eq!(
            std::fs::read(fixture.stage.join("replacement")).unwrap(),
            b"do not publish"
        );
        fixture.caller_unchanged();
    }

    #[test]
    fn changed_regular_entries_cannot_complete_an_inventory() {
        for replacement in [false, true] {
            let fixture = Fixture::new();
            let original = fixture.stage.join("build/deep/app");
            let mut injected = false;
            let result = scan(&fixture.stage, &mut |path| {
                if path == Path::new("build/deep/app") {
                    injected = true;
                    if replacement {
                        std::fs::rename(&original, &fixture.retained)?;
                        std::fs::write(&original, b"different executable")?;
                    } else {
                        // Deterministic metadata change, without rewriting or
                        // deleting even one retained output byte.
                        let metadata = std::fs::metadata(&original)?;
                        let mode = metadata.mode() ^ 0o100;
                        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(mode))?;
                    }
                }
                Ok(())
            });
            assert!(injected);
            assert!(result.is_err());
            let retained = if replacement {
                &fixture.retained
            } else {
                &original
            };
            assert_eq!(std::fs::read(retained).unwrap(), b"original executable");
            fixture.caller_unchanged();
        }
    }

    #[test]
    fn preexisting_symlinks_and_special_files_are_rejected_without_opening_them() {
        for special in ["symlink", "dangling-symlink", "fifo"] {
            let fixture = Fixture::new();
            let name = fixture.stage.join("build/special");
            match special {
                "symlink" => symlink(fixture.stage.join("build/deep"), &name).unwrap(),
                "dangling-symlink" => symlink(&fixture.retained, &name).unwrap(),
                "fifo" => make_fifo(&name).unwrap(),
                _ => unreachable!(),
            }
            assert!(regular_files(&fixture.stage).is_err(), "{special}");
            assert!(std::fs::symlink_metadata(&name).is_ok());
            assert_eq!(
                std::fs::read(fixture.stage.join("build/deep/app")).unwrap(),
                b"original executable"
            );
            fixture.caller_unchanged();
        }
    }

    #[test]
    fn parent_namespace_changes_are_not_a_smaller_successful_set() {
        let fixture = Fixture::new();
        let directory = fixture.stage.join("build/deep");
        let mut injected = false;
        let result = scan(&fixture.stage, &mut |path| {
            if path == Path::new("build/deep/app") {
                injected = true;
                std::fs::write(directory.join("late-output.o"), b"late output")?;
                // Ensure this fault is observable even on a coarse-clock
                // filesystem: mode belongs to the directory version too.
                let mode = std::fs::metadata(&directory)?.mode() ^ 0o010;
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode))?;
            }
            Ok(())
        });
        assert!(injected);
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(directory.join("app")).unwrap(),
            b"original executable"
        );
        assert_eq!(
            std::fs::read(directory.join("late-output.o")).unwrap(),
            b"late output"
        );
        fixture.caller_unchanged();
    }
}
