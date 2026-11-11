//! Exact-file durability barriers for remote completion and source records.
//!
//! A barrier flushes only the named files/directories. It must never fall back
//! to a filesystem-wide sync, and a failed flush must leave ownership held.

const PROBE_REPLY: &str = "rch-wkr file-sync v1";
const REFUSAL_EXIT: i32 = 74;

pub fn main(arguments: &[String]) -> i32 {
    match run(arguments) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("RCH_FILE_SYNC_UNCONFIRMED {error}");
            REFUSAL_EXIT
        }
    }
}

fn run(arguments: &[String]) -> std::io::Result<()> {
    match arguments.split_first() {
        Some((operation, [])) if operation == "probe" => {
            require_supported()?;
            println!("{PROBE_REPLY}");
            Ok(())
        }
        Some((operation, paths)) if operation == "sync" => {
            require_supported()?;
            for path in paths {
                sync_path(std::path::Path::new(path)).map_err(|error| {
                    std::io::Error::new(error.kind(), format!("{path:?}: {error}"))
                })?;
            }
            Ok(())
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected probe or sync <path>...",
        )),
    }
}

#[cfg(unix)]
fn require_supported() -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn require_supported() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "descriptor-based file and directory sync requires a Unix worker",
    ))
}

#[cfg(unix)]
fn sync_path(path: &std::path::Path) -> std::io::Result<()> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, fsync, open};

    // NONBLOCK keeps a substituted FIFO from wedging recovery; NOCTTY avoids
    // acquiring a terminal if a record was replaced with a device. The final
    // component must never be a symlink. Parent aliases (e.g. Darwin /tmp) are
    // permitted, as they are for the writers of these owned records.
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )?;
    let metadata = fstat(&descriptor)?;
    if !matches!(
        FileType::from_raw_mode(metadata.st_mode),
        FileType::RegularFile | FileType::Directory
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "durability barrier requires a regular file or directory",
        ));
    }
    fsync(&descriptor)?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_path(_path: &std::path::Path) -> std::io::Result<()> {
    require_supported()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn flushes_named_file_and_directory_without_changing_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let record = directory.path().join("completion.pending");
        std::fs::write(&record, b"owned-build 7\n").unwrap();
        sync_path(&record).unwrap();
        sync_path(directory.path()).unwrap();
        assert_eq!(std::fs::read(&record).unwrap(), b"owned-build 7\n");
    }

    #[test]
    fn refuses_missing_files_and_final_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let record = directory.path().join("completion");
        assert_eq!(
            sync_path(&record).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        symlink(directory.path(), &record).unwrap();
        assert!(sync_path(&record).is_err());
    }

    #[test]
    fn accepts_parent_aliases_but_not_special_entries() {
        let directory = tempfile::tempdir().unwrap();
        let owned = directory.path().join("owned");
        std::fs::create_dir(&owned).unwrap();
        let alias = directory.path().join("alias");
        symlink(&owned, &alias).unwrap();
        std::fs::write(owned.join("record"), b"receipt").unwrap();
        sync_path(&alias.join("record")).unwrap();

        let fifo = owned.join("fifo");
        #[cfg(not(target_vendor = "apple"))]
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        #[cfg(target_vendor = "apple")]
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            sync_path(&fifo).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn does_not_skip_a_failed_barrier() {
        let directory = tempfile::tempdir().unwrap();
        let existing = directory.path().join("record");
        std::fs::write(&existing, b"receipt").unwrap();
        assert!(
            run(&[
                "sync".into(),
                directory.path().join("absent").display().to_string(),
                existing.display().to_string(),
            ])
            .is_err()
        );
        assert!(run(&["sync".into()]).is_ok());
        assert!(run(&[]).is_err());
        assert!(run(&["probe".into(), "unexpected".into()]).is_err());
        assert!(run(&["other".into()]).is_err());
    }
}
