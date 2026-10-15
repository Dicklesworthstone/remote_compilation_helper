//! Bounded-memory capture of native compiler outputs into the existing CAS.
//!
//! Copy and hash before taking the metadata mutex. The private staging file
//! owns the captured bytes; close its writable descriptor before publication.
//! The existing CAS publisher supplies fsync, no-clobber installation and
//! collision handling. The attempt's capture pin is installed under the same
//! mutex as the durable location. None of this publishes an action result.

use super::{CapturePins, KnownOutput};
use crate::edge::live_facts::FileSig;
use crate::janitor::store::LiveCas;
use rabs_cas::blob_store::{
    DurabilityPolicy, RawTargetObservation, publish_staged_with_observation,
};
use rabs_cas::digest_set::{DigestRequest, StreamingObjectWriter};
use rabs_protocol::result_identity::TypedDigest;
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const COPY_BUFFER_BYTES: usize = 64 * 1024;

fn regular_signature(metadata: &Metadata) -> io::Result<FileSig> {
    if !metadata.is_file() {
        return Err(io::Error::other("compiler output is not a regular file"));
    }
    Ok(FileSig::of(metadata))
}

fn signature(path: &Path) -> io::Result<FileSig> {
    regular_signature(&std::fs::symlink_metadata(path)?)
}

/// Hash exactly the observed payload, with one extra byte to detect growth.
/// The buffer size and read bound do not depend on the artifact's byte length.
fn copy_exact(
    reader: &mut impl Read,
    writer: &mut impl Write,
    expected: u64,
) -> io::Result<TypedDigest> {
    let mut digest = StreamingObjectWriter::new(DigestRequest::default(), Some(expected));
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut remaining = expected;
    loop {
        // At EOF this asks for one byte, even for an empty artifact. Never
        // truncate an oversized source into a valid expected-size object.
        let limit = usize::try_from(remaining.saturating_add(1).min(buffer.len() as u64))
            .map_err(io::Error::other)?;
        let count = match reader.read(&mut buffer[..limit]) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if count == 0 {
            if remaining != 0 {
                return Err(io::Error::other("compiler output shrank during capture"));
            }
            break;
        }
        if count as u64 > remaining {
            return Err(io::Error::other("compiler output grew during capture"));
        }
        writer.write_all(&buffer[..count])?;
        digest
            .write(&buffer[..count])
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        remaining -= count as u64;
    }
    Ok(digest
        .finish()
        .map_err(|error| io::Error::other(format!("{error:?}")))?
        .atp_content_id)
}

/// An unpublished private copy; no open writable descriptor survives capture.
/// The source signature describes the exact bytes copied, not a fresh lstat
/// paired with an older digest. TempPath owns only the private staging name.
struct StagedOutput {
    stage: tempfile::TempPath,
    stage_sig: FileSig,
    source: PathBuf,
    source_sig: FileSig,
    digest: TypedDigest,
}

impl StagedOutput {
    fn capture(staging: &Path, source: &Path, maximum: u64) -> io::Result<Self> {
        let before = signature(source)?;
        if before.size() > maximum {
            return Err(io::Error::other("compiler output exceeds the byte bound"));
        }
        let mut input = File::open(source)?;
        if regular_signature(&input.metadata()?)? != before || signature(source)? != before {
            return Err(io::Error::other("compiler output changed before capture"));
        }
        let mut temporary = tempfile::Builder::new()
            .prefix("live-output-")
            .tempfile_in(staging)?;
        let digest = copy_exact(&mut input, temporary.as_file_mut(), before.size())?;
        if regular_signature(&input.metadata()?)? != before || signature(source)? != before {
            return Err(io::Error::other("compiler output changed during capture"));
        }
        // Never hardlink the caller's output into CAS. Even the private copy
        // loses its writable handle before the publisher can link it there.
        let mut permissions = temporary.as_file().metadata()?.permissions();
        permissions.set_readonly(true);
        temporary.as_file().set_permissions(permissions)?;
        let stage_sig = regular_signature(&temporary.as_file().metadata()?)?;
        let stage = temporary.into_temp_path();
        let captured = Self {
            stage,
            stage_sig,
            source: source.to_path_buf(),
            source_sig: before,
            digest,
        };
        captured.verify()?;
        Ok(captured)
    }

    fn verify(&self) -> io::Result<()> {
        if signature(&self.source)? != self.source_sig {
            return Err(io::Error::other("compiler output changed after capture"));
        }
        if signature(&self.stage)? != self.stage_sig {
            return Err(io::Error::other("private compiler capture changed"));
        }
        Ok(())
    }
}

/// Stage one native output without retaining its bytes in memory or holding
/// the metadata mutex during source I/O. The pin and durable location become
/// visible together. Later inputs/output failures still drop the capture owner
/// without publishing an action pointer or acknowledging compiler completion.
pub(super) fn put_output(
    cas: &LiveCas,
    source: &Path,
    maximum: u64,
    pins: &mut CapturePins,
) -> Result<KnownOutput, String> {
    let staged = StagedOutput::capture(&cas.layout().root().join("staging"), source, maximum)
        .map_err(|error| format!("output capture {}: {error}", source.display()))?;
    // Verification repeats commonly ingest the same large rlib/rmeta. Hash
    // that possible duplicate before taking the ONE shared metadata lock.
    // Retry at most twice if another publisher/GC changed the destination;
    // keep the same captured stage and custody pin, never recopy the compiler.
    let mut retries = 0;
    loop {
        let observation = RawTargetObservation::observe(cas.layout(), &staged.digest, maximum)
            .map_err(|error| format!("observe output target: {error:?}"))?;
        let result = {
            let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
            staged.verify().map_err(|error| error.to_string())?;
            pins.protect(&mut *store, &staged.digest)?;
            publish_staged_with_observation(
                cas.layout(),
                &mut *store,
                &staged.digest,
                &staged.stage,
                DurabilityPolicy::FULL,
                &observation,
            )
        };
        match result {
            Ok(_) => break,
            Err(error) if RawTargetObservation::changed(&error) && retries < 2 => {
                retries += 1;
            }
            Err(error) => return Err(format!("publish output capture: {error:?}")),
        }
    }
    // publish_staged consumes/removes the private staging name, not the
    // compiler output. Never manufacture a newer source identity here.
    if signature(source).map_err(|error| error.to_string())? != staged.source_sig {
        return Err("compiler output changed while its capture was stored".into());
    }
    Ok(KnownOutput {
        path: staged.source.clone(),
        sig: staged.source_sig,
        digest: staged.digest.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_cas::digest_set::digest_set;
    use std::io::Cursor;

    #[test]
    fn streaming_capture_preserves_empty_binary_and_multibuffer_identity() {
        for bytes in [
            Vec::new(),
            vec![0, 255, 128, 10],
            vec![37; COPY_BUFFER_BYTES * 3 + 7],
        ] {
            let mut copied = Vec::new();
            let observed =
                copy_exact(&mut Cursor::new(&bytes), &mut copied, bytes.len() as u64).unwrap();
            assert_eq!(copied, bytes);
            assert_eq!(
                observed,
                digest_set(&bytes, DigestRequest::default(), None)
                    .unwrap()
                    .atp_content_id
            );
        }
    }

    #[test]
    fn stream_growth_and_shrinkage_refuse_instead_of_truncating() {
        for (input, expected) in [
            (b"extra".as_slice(), 4),
            (b"short".as_slice(), 6),
            (b"x", 0),
        ] {
            assert!(copy_exact(&mut Cursor::new(input), &mut Vec::new(), expected).is_err());
        }
    }

    #[test]
    fn large_stream_uses_bounded_reads_and_only_one_eof_probe() {
        struct Generated {
            remaining: u64,
            requested: usize,
            reads: usize,
        }
        impl Read for Generated {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.requested = self.requested.max(buffer.len());
                self.reads += 1;
                let count = usize::try_from(self.remaining.min(buffer.len() as u64)).unwrap();
                buffer[..count].fill(19);
                self.remaining -= count as u64;
                Ok(count)
            }
        }
        let length = COPY_BUFFER_BYTES as u64 * 17 + 3;
        let mut input = Generated {
            remaining: length,
            requested: 0,
            reads: 0,
        };
        copy_exact(&mut input, &mut io::sink(), length).unwrap();
        assert_eq!(input.requested, COPY_BUFFER_BYTES);
        assert_eq!(input.reads, 19);
        assert_eq!(input.remaining, 0);
        // An effectively unending input is stopped after the observed bytes
        // plus ONE byte, not drained to EOF and not truncated into success.
        let mut growing = Generated {
            remaining: u64::MAX,
            requested: 0,
            reads: 0,
        };
        assert!(copy_exact(&mut growing, &mut io::sink(), 7).is_err());
        assert_eq!(growing.remaining, u64::MAX - 8);
        assert_eq!(growing.reads, 1);
    }

    #[test]
    fn interrupted_reads_retry_but_failed_writes_never_produce_an_identity() {
        struct InterruptedOnce(bool);
        impl Read for InterruptedOnce {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    Err(io::Error::from(io::ErrorKind::Interrupted))
                } else {
                    Ok(0)
                }
            }
        }
        copy_exact(&mut InterruptedOnce(true), &mut io::sink(), 0).unwrap();
        struct FullDisk;
        impl Write for FullDisk {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("fixture disk exhausted"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let error = copy_exact(&mut Cursor::new(b"artifact"), &mut FullDisk, 8).unwrap_err();
        assert!(error.to_string().contains("disk exhausted"));
    }

    #[test]
    fn staged_output_is_a_private_readonly_copy_and_replacement_refuses() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::test_util::private_tempdir();
        let source = dir.path().join("libfoo.rlib");
        let staging = dir.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(&source, b"original").unwrap();
        let captured = StagedOutput::capture(&staging, &source, 8).unwrap();
        assert_eq!(std::fs::read(&captured.stage).unwrap(), b"original");
        assert_ne!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&captured.stage).unwrap().ino()
        );
        assert!(
            std::fs::metadata(&captured.stage)
                .unwrap()
                .permissions()
                .readonly()
        );
        std::fs::rename(&source, dir.path().join("retained-original")).unwrap();
        std::fs::write(&source, b"original").unwrap();
        assert!(
            captured.verify().is_err(),
            "equal bytes do not adopt a new source inode"
        );
        assert_eq!(std::fs::read(&captured.stage).unwrap(), b"original");
    }

    #[test]
    fn oversized_and_nonregular_sources_never_create_staging_objects() {
        let dir = crate::test_util::private_tempdir();
        let staging = dir.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        let source = dir.path().join("large.rlib");
        File::create(&source).unwrap().set_len(1000).unwrap();
        assert!(StagedOutput::capture(&staging, &source, 999).is_err());
        assert!(StagedOutput::capture(&staging, dir.path(), 1000).is_err());
        assert!(StagedOutput::capture(&staging, &dir.path().join("absent"), 1000).is_err());
        let alias = dir.path().join("alias.rlib");
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(StagedOutput::capture(&staging, &alias, 1000).is_err());
        assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
    }
}
