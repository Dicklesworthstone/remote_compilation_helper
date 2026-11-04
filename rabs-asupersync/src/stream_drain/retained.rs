//! Descriptor-owned spill reads. Pathnames are diagnostic labels, not custody.
//!
//! The drain transfers its existing file into this owner after flushing. No
//! reader reopens a pathname or shares another reader's logical cursor. Metadata
//! changes refuse capture; this is not a cryptographic seal against a malicious
//! process with the worker's credentials. Read errors never certify completeness.

use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    length: u64,
    modified: SystemTime,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64, u64, u32),
}

impl Version {
    fn of(metadata: &Metadata) -> io::Result<Self> {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retained spill is not a regular file",
            ));
        }
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            unix: {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                    metadata.nlink(),
                    metadata.mode(),
                )
            },
        })
    }
}

#[derive(Debug, Clone)]
pub(super) struct RetainedSpill {
    file: Arc<Mutex<File>>,
    version: Version,
}

// Cloning one completed drain retains the same custody. A separately opened
// descriptor is not considered equal merely because its pathname was equal.
impl PartialEq for RetainedSpill {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.file, &other.file) && self.version == other.version
    }
}
impl Eq for RetainedSpill {}

impl RetainedSpill {
    pub(super) fn new(file: File, length: u64) -> io::Result<Self> {
        let version = Version::of(&file.metadata()?)?;
        if version.length != length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "spill length disagrees with the completed drain",
            ));
        }
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            version,
        })
    }

    fn verify(&self, file: &File) -> io::Result<()> {
        if Version::of(&file.metadata()?)? != self.version {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retained spill changed after drain completion",
            ));
        }
        Ok(())
    }

    pub(super) fn reader(&self, length: u64) -> io::Result<SpillReader> {
        if length != self.version.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "spill receipt does not match its retained descriptor",
            ));
        }
        let file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("retained spill ownership is poisoned"))?;
        self.verify(&file)?;
        Ok(SpillReader {
            source: Some(self.clone()),
            position: 0,
        })
    }
}

pub(super) struct SpillReader {
    source: Option<RetainedSpill>,
    position: u64,
}

impl SpillReader {
    pub(super) fn empty() -> Self {
        Self {
            source: None,
            position: 0,
        }
    }
}

impl Read for SpillReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let Some(source) = &self.source else {
            return Ok(0);
        };
        let mut file = source
            .file
            .lock()
            .map_err(|_| io::Error::other("retained spill ownership is poisoned"))?;
        source.verify(&file)?;
        let remaining = source
            .version
            .length
            .checked_sub(self.position)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "retained spill cursor overflow")
            })?;
        if remaining == 0 {
            return Ok(0);
        }
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("retained spill range does not fit memory"))?;
        // Seek and read share a short lock. Each reader owns its position, so
        // alternating or concurrent readers cannot steal one another's bytes.
        file.seek(SeekFrom::Start(self.position))?;
        let read = file.read(&mut buffer[..count])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "retained spill ended before its recorded length",
            ));
        }
        source.verify(&file)?;
        self.position += read as u64; // read <= remaining, checked above
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn capture(bytes: &[u8]) -> (tempfile::NamedTempFile, RetainedSpill) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
        let retained =
            RetainedSpill::new(file.as_file().try_clone().unwrap(), bytes.len() as u64).unwrap();
        (file, retained)
    }

    #[test]
    fn retained_empty_binary_and_multibuffer_streams_round_trip() {
        for bytes in [Vec::new(), vec![0, 255, 128, 10], vec![37; 196_615]] {
            let (_file, retained) = capture(&bytes);
            let mut result = Vec::new();
            retained
                .reader(bytes.len() as u64)
                .unwrap()
                .read_to_end(&mut result)
                .unwrap();
            assert_eq!(result, bytes);
        }
    }

    #[test]
    fn interleaved_readers_never_share_their_logical_cursor() {
        let (_file, retained) = capture(b"0123456789");
        let mut a = retained.reader(10).unwrap();
        let mut b = retained.reader(10).unwrap();
        let mut first = [0; 3];
        a.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"012");
        let mut all = Vec::new();
        b.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"0123456789");
        let mut rest = Vec::new();
        a.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"3456789");
    }

    #[test]
    fn concurrent_readers_each_receive_the_complete_original() {
        let bytes: Vec<u8> = (0..131_079).map(|n| (n % 251) as u8).collect();
        let (_file, retained) = capture(&bytes);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let mut reader = retained.reader(bytes.len() as u64).unwrap();
                std::thread::spawn(move || {
                    let mut result = Vec::new();
                    let mut chunk = [0; 997];
                    loop {
                        let n = reader.read(&mut chunk).unwrap();
                        if n == 0 {
                            break;
                        }
                        result.extend_from_slice(&chunk[..n]);
                    }
                    result
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), bytes);
        }
    }

    #[test]
    fn descriptor_retains_custody_after_the_original_owner_drops() {
        let (file, retained) = capture(b"owned bytes");
        // Drop only the first descriptor, not the name: unlink changes ctime
        // and is allowed to trigger a conservative refusal on Unix.
        let (descriptor, path) = file.into_parts();
        drop(descriptor);
        let mut reader = retained.reader(11).unwrap();
        drop(retained);
        let mut result = Vec::new();
        reader.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"owned bytes");
        drop(path);
    }

    #[test]
    fn length_mismatch_refuses_before_reading() {
        let (file, retained) = capture(b"abc");
        for length in [0, 2, 4, u64::MAX] {
            assert!(retained.reader(length).is_err());
            assert!(RetainedSpill::new(file.as_file().try_clone().unwrap(), length).is_err());
        }
    }

    #[test]
    fn truncation_and_growth_are_not_reported_as_successful_eof() {
        for length in [0, 2, 4] {
            let (file, retained) = capture(b"abc");
            let mut reader = retained.reader(3).unwrap();
            file.as_file().set_len(length).unwrap();
            assert!(reader.read(&mut [0; 8]).is_err());
            assert!(retained.reader(3).is_err());
        }
    }

    #[test]
    fn mutation_after_the_final_byte_is_checked_on_eof() {
        let (mut file, retained) = capture(b"abc");
        let mut reader = retained.reader(3).unwrap();
        reader.read_exact(&mut [0; 3]).unwrap();
        file.as_file_mut().set_len(4).unwrap();
        assert!(reader.read(&mut [0]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn same_size_rewrite_with_restored_mtime_still_refuses() {
        let (mut file, retained) = capture(b"original");
        let modified = file.as_file().metadata().unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"tampered").unwrap();
        file.flush().unwrap();
        file.as_file()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert!(retained.reader(8).is_err());
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn read_errors_and_poisoned_ownership_cannot_become_empty_success() {
        let (_file, retained) = capture(b"payload");
        let other = retained.clone();
        let _ = std::thread::spawn(move || {
            let _guard = other.file.lock().unwrap();
            panic!("injected reader failure");
        })
        .join();
        assert!(retained.reader(7).is_err());
    }
}
