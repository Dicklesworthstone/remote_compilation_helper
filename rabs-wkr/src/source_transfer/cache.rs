//! Worker integration for the shared verified source-byte cache.
//!
//! Storage, bounds, checkpointing and eviction live in rabs-sandbox. The worker
//! supplies the CAS layer's verified clone callback at installation and retains
//! the real-filesystem integration test for that dependency boundary here.

pub use rabs_sandbox::source_cache::{
    DEFAULT_SOURCE_CACHE_BYTES, MAX_SOURCE_CACHE_BYTES, SourceCache,
};
pub(super) use rabs_sandbox::source_cache::{RememberError, SourceCheckpoints};

#[cfg(all(
    test,
    target_os = "linux",
    not(any(target_arch = "sparc", target_arch = "sparc64"))
))]
mod tests {
    use super::*;
    use rabs_sandbox::source_transfer::{
        MAX_SOURCE_CHUNK, SourceFile, SourceManifest, SourceReceiver,
    };
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{Seek, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    fn private_in(parent: impl AsRef<Path>) -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
            .unwrap()
    }

    fn staged(parent: &Path, files: &[(&str, &[u8])]) -> SourceReceiver {
        let manifest = SourceManifest::new(
            files
                .iter()
                .map(|(path, bytes)| SourceFile {
                    path: (*path).into(),
                    len: bytes.len() as u64,
                    sha256: Sha256::digest(bytes).into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap();
        let mut receiver = SourceReceiver::create(&parent.join("workspace"), manifest).unwrap();
        for (path, bytes) in files {
            for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                receiver
                    .write_chunk(
                        path,
                        (index * MAX_SOURCE_CHUNK) as u64,
                        chunk,
                        Sha256::digest(chunk).into(),
                    )
                    .unwrap();
            }
        }
        receiver.seal().unwrap();
        receiver
    }

    #[test]
    #[ignore = "requires RABS_REFLINK_TEST_ROOT on a real reflink-capable filesystem"]
    fn cached_snapshot_import_requires_real_verified_reflink_and_independent_seal() {
        let root = std::env::var_os("RABS_REFLINK_TEST_ROOT").expect("explicit capable filesystem");
        let parent = private_in(root);
        let input = private_in(parent.path());
        let bytes = vec![0x29; MAX_SOURCE_CHUNK * 4 + 3];
        let source = staged(input.path(), &[("lib.rlib", &bytes)]);
        let cache = SourceCache::open(parent.path(), DEFAULT_SOURCE_CACHE_BYTES).unwrap();
        cache.remember(&source).unwrap();
        let expected = &source.manifest().files()[0];
        let snapshot = cache.load(expected).unwrap();
        let next = private_in(parent.path());
        let mut receiver =
            SourceReceiver::create(&next.path().join("workspace"), source.manifest().clone())
                .unwrap();
        let mut retained_snapshot = None;
        assert!(
            snapshot
                .install_with_cloner(&mut receiver, |input, output, parent| {
                    retained_snapshot = Some(input.try_clone().unwrap());
                    rabs_cas::materialization::try_verified_reflink(input, output, parent)
                })
                .unwrap(),
            "a private-copy fallback does not satisfy this real CoW fixture"
        );
        assert!(receiver.sealed_root().is_none());
        let mut retained_snapshot = retained_snapshot.expect("clone callback retained its input");
        retained_snapshot.rewind().unwrap();
        retained_snapshot
            .write_all(b"changed private spool")
            .unwrap();
        let installed = receiver.seal().unwrap().join("lib.rlib");
        assert_eq!(fs::read(&installed).unwrap(), bytes);
        assert_ne!(
            retained_snapshot.metadata().unwrap().ino(),
            fs::metadata(&installed).unwrap().ino()
        );
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&installed, b"changed private receiver").unwrap();
        let confirm = private_in(parent.path());
        let mut confirmed =
            SourceReceiver::create(&confirm.path().join("workspace"), source.manifest().clone())
                .unwrap();
        cache
            .load(expected)
            .unwrap()
            .install(&mut confirmed)
            .unwrap();
        assert_eq!(
            fs::read(confirmed.seal().unwrap().join("lib.rlib")).unwrap(),
            bytes
        );
    }
}
