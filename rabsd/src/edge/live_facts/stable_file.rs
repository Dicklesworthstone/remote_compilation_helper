//! Acquisition and completion fences shared by the live input readers.
//!
//! An earlier lstat does not make a subsequent blocking open safe: a path
//! can become a FIFO while a fact warmer is acquiring it. Open without
//! following a final symlink or waiting for a FIFO peer, then check both the
//! actual descriptor and the path BEFORE any read or allocation. Recheck
//! both after consuming the observed byte length, before publishing a fact.
//!
//! This is same-host mutation detection, not a sandbox or a cryptographic
//! seal. O_NONBLOCK does not bound regular-file filesystem latency, and
//! parent-component policy remains the responsibility of source admission.

use super::{FileSig, lstat_regular};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub(super) fn open(path: &Path, before: FileSig) -> io::Result<File> {
    let file = rabs_sandbox::regular_input::open(path)?;
    verify(&file, path, before)?;
    Ok(file)
}

pub(super) fn verify(file: &File, path: &Path, before: FileSig) -> io::Result<()> {
    let held = file.metadata()?;
    if !held.is_file() || FileSig::of(&held) != before || lstat_regular(path)? != before {
        return Err(io::Error::other(
            "input descriptor or path changed during observation",
        ));
    }
    Ok(())
}

/// Consume only the generation observed by the caller. Retain the descriptor
/// through the completion fence; a pathname recheck is not its substitute.
pub(super) fn read_at(
    path: &Path,
    before: FileSig,
    max_bytes: u64,
) -> io::Result<(FileSig, Vec<u8>)> {
    if before.size() > max_bytes {
        return Err(io::Error::other("file exceeds the byte bound"));
    }
    let mut file = open(path, before)?;
    let capacity = usize::try_from(before.size()).map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(io::Error::other)?;
    // Do not read up to max_bytes + 1: it can overflow, and a growing file
    // must not make us consume more than its already observed length.
    (&mut file).take(before.size()).read_to_end(&mut bytes)?;
    if bytes.len() != capacity {
        return Err(io::Error::other("file shrank while it was read"));
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(io::Error::other("file grew while it was read"));
    }
    verify(&file, path, before)?;
    Ok((before, bytes))
}

#[cfg(test)]
mod tests {
    use super::super::{digest_stable, digest_stable_at, read_stable};
    use super::*;
    use rabs_cas::digest_set::{DigestRequest, digest_set};
    use std::fs::{self, FileTimes};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    #[test]
    fn both_live_readers_preserve_exact_bytes_and_cas_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.rlib");
        for size in [0, 1, 255, 262_145] {
            let bytes: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
            fs::write(&path, &bytes).unwrap();
            let before = lstat_regular(&path).unwrap();
            let (read_sig, read) = read_stable(&path, size as u64).unwrap();
            let (hash_sig, hash) = digest_stable(&path).unwrap();
            let expected = digest_set(&bytes, DigestRequest::default(), None)
                .unwrap()
                .atp_content_id;
            assert_eq!(read_sig, before);
            assert_eq!(hash_sig, before);
            assert_eq!(read, bytes);
            assert_eq!(hash, expected);
        }
    }

    #[test]
    fn maximum_limit_does_not_overflow_or_change_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        for bytes in [b"".as_slice(), b"ordinary input".as_slice()] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(read_stable(&path, u64::MAX).unwrap().1, bytes);
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn over_limit_input_is_refused_without_touching_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        fs::write(&path, b"unchanged").unwrap();
        let before = lstat_regular(&path).unwrap();
        assert!(read_stable(&path, 3).is_err());
        assert_eq!(lstat_regular(&path).unwrap(), before);
        assert_eq!(fs::read(&path).unwrap(), b"unchanged");
    }

    #[test]
    fn replacements_cannot_inherit_an_observed_regular_file_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        fs::write(&path, b"original").unwrap();
        let before = lstat_regular(&path).unwrap();
        fs::rename(&path, dir.path().join("retained-original")).unwrap();
        fs::write(&path, b"replaced").unwrap();
        assert!(read_at(&path, before, 8).is_err());
        assert!(digest_stable_at(&path, before).is_err());
        // A fresh observation can read the new generation normally.
        assert_eq!(read_stable(&path, 8).unwrap().1, b"replaced");
    }

    #[test]
    fn changed_size_is_refused_before_allocating_or_reading_the_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        fs::write(&path, b"old").unwrap();
        let before = lstat_regular(&path).unwrap();
        fs::write(&path, b"now much larger").unwrap();
        assert!(read_at(&path, before, u64::MAX).is_err());
        assert!(digest_stable_at(&path, before).is_err());
    }

    #[test]
    fn final_symlink_is_never_followed_after_regular_file_observation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        let retained = dir.path().join("retained-original");
        fs::write(&path, b"original").unwrap();
        let before = lstat_regular(&path).unwrap();
        fs::rename(&path, &retained).unwrap();
        symlink(&retained, &path).unwrap();
        assert!(open(&path, before).is_err());
        assert!(read_at(&path, before, 8).is_err());
        assert!(digest_stable_at(&path, before).is_err());
        assert!(read_stable(&path, 8).is_err());
        assert_eq!(fs::read(retained).unwrap(), b"original");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replacement_fifo_does_not_occupy_a_fact_warmer_waiting_for_a_writer() {
        // This exercises BOTH real production readers with a deterministic
        // observation/open cut. A rescue endpoint bounds even a regression
        // to blocking open, so a failing test does not strand its test thread.
        let readers: [fn(&Path, FileSig) -> bool; 2] = [
            |path, before| read_at(path, before, 8).is_err(),
            |path, before| digest_stable_at(path, before).is_err(),
        ];
        for read in readers {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("input");
            fs::write(&path, b"original").unwrap();
            let before = lstat_regular(&path).unwrap();
            fs::rename(&path, dir.path().join("retained-original")).unwrap();
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
            let (sender, receiver) = std::sync::mpsc::channel();
            let source = path.clone();
            let thread = std::thread::spawn(move || {
                sender.send(read(&source, before)).unwrap();
            });
            let first = receiver.recv_timeout(Duration::from_secs(1));
            if first.is_err() {
                // Linux permits O_RDWR on a FIFO without another endpoint.
                let rescue = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .unwrap();
                drop(rescue);
                let _ = receiver.recv_timeout(Duration::from_secs(2));
            }
            // A successful result is the refusal, not merely fast return.
            thread.join().unwrap();
            assert_eq!(first, Ok(true), "reader waited on a replacement FIFO");
        }
    }

    #[test]
    fn directories_sockets_and_devices_are_not_regular_input_replacements() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input");
        fs::write(&source, b"original").unwrap();
        let before = lstat_regular(&source).unwrap();
        let directory = dir.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let socket = dir.path().join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        for path in [
            directory.as_path(),
            socket.as_path(),
            Path::new("/dev/null"),
        ] {
            assert!(open(path, before).is_err(), "{path:?}");
            assert!(read_stable(path, 8).is_err(), "{path:?}");
        }
    }

    #[test]
    fn held_descriptor_is_checked_even_when_the_named_path_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        let other = dir.path().join("other");
        fs::write(&path, b"original").unwrap();
        fs::write(&other, b"different").unwrap();
        let before = lstat_regular(&path).unwrap();
        let unrelated = File::open(&other).unwrap();
        assert_eq!(lstat_regular(&path).unwrap(), before);
        assert!(verify(&unrelated, &path, before).is_err());
        let held = open(&path, before).unwrap();
        assert!(verify(&held, &path, before).is_ok());
    }

    #[test]
    fn restoring_mtime_cannot_hide_a_same_length_descriptor_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        fs::write(&path, b"original").unwrap();
        let before = lstat_regular(&path).unwrap();
        let held = open(&path, before).unwrap();
        let modified = held.metadata().unwrap().modified().unwrap();
        // Avoid depending on two metadata changes sharing one clock tick.
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&path, b"replaced").unwrap();
        held.set_times(FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(held.metadata().unwrap().modified().unwrap(), modified);
        assert_eq!(held.metadata().unwrap().len(), before.size());
        assert!(verify(&held, &path, before).is_err());
        assert!(read_at(&path, before, 8).is_err());
        assert!(digest_stable_at(&path, before).is_err());
    }

    #[test]
    fn non_utf8_input_paths_keep_their_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(std::ffi::OsString::from_vec(b"input-\xff".to_vec()));
        fs::write(&path, b"bytes").unwrap();
        assert_eq!(read_stable(&path, 5).unwrap().1, b"bytes");
        assert!(digest_stable(&path).is_ok());
    }

    #[test]
    fn completion_refuses_a_path_replaced_after_acquisition() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        fs::write(&path, b"original").unwrap();
        let before = lstat_regular(&path).unwrap();
        let mut held = open(&path, before).unwrap();
        fs::rename(&path, dir.path().join("retained-original")).unwrap();
        fs::write(&path, b"replaced").unwrap();
        let mut bytes = Vec::new();
        held.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert!(verify(&held, &path, before).is_err());
    }
}
