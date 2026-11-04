//! Acquire a regular input without waiting for a replacement FIFO writer.
//!
//! A caller's preceding pathname observation cannot make a blocking open
//! safe. Reject a final symlink, acquire without FIFO rendezvous or terminal
//! ownership, and check the held descriptor before exposing it to a reader.
//! This is acquisition only: callers must still validate the observed file
//! generation, parent-component policy and content before accepting a fact.
//! Nonblocking acquisition does not bound regular-file or kernel I/O latency.

use rustix::fs::{Mode, OFlags};
use std::fs::File;
use std::io;
use std::path::Path;

/// Open an input without following its final symlink or waiting for a FIFO.
///
/// # Errors
/// Acquisition or metadata failures, and descriptors that are not regular
/// files. A successful return grants no content or cache-serving authority.
pub fn open(path: &Path) -> io::Result<File> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )?;
    let file = File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("input descriptor is not a regular file"));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn regular_inputs_keep_their_bytes_and_raw_names() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join(std::ffi::OsString::from_vec(b"input-\xff".to_vec()));
        for bytes in [b"".as_slice(), b"\0binary\xff".as_slice()] {
            std::fs::write(&path, bytes).unwrap();
            let mut held = open(&path).unwrap();
            let mut observed = Vec::new();
            held.read_to_end(&mut observed).unwrap();
            assert_eq!(observed, bytes);
        }
    }

    #[test]
    fn final_symlinks_and_nonregular_descriptors_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        std::fs::write(&input, b"unchanged").unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&input, &link).unwrap();
        let socket = directory.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        for path in [
            link.as_path(),
            directory.path(),
            socket.as_path(),
            Path::new("/dev/null"),
        ] {
            assert!(open(path).is_err(), "{path:?}");
        }
        assert_eq!(std::fs::read(input).unwrap(), b"unchanged");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fifo_acquisition_does_not_wait_for_a_writer() {
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fifo");
        rustix::fs::mkfifoat(rustix::fs::CWD, &path, Mode::RUSR | Mode::WUSR).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let input = path.clone();
        let thread = std::thread::spawn(move || sender.send(open(&input).is_err()).unwrap());
        let first = receiver.recv_timeout(Duration::from_secs(1));
        if first.is_err() {
            let rescue = rustix::fs::open(
                &path,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .unwrap();
            drop(rescue);
        }
        thread.join().unwrap();
        assert_eq!(
            first,
            Ok(true),
            "regular input acquisition waited on a FIFO"
        );
    }
}
