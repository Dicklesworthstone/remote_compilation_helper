//! Discover exact source roots recorded by the worker's ownership protocol.
//!
//! A successful inventory is only a set of scan hints. It grants no collection
//! authority: the existing target-name, source-claim, idle, process and handle
//! checks still decide whether any individual target can be collected. In
//! particular, never infer a parent directory or replace a recorded alias with
//! its current physical destination here.

use anyhow::{Result, bail};
use std::io::Write;

#[cfg(unix)]
const PROBE_REPLY: &str = "rch-wkr source-claim-roots v1";

/// Run without a logging sink or async runtime; inventory itself is read-only.
pub fn main(arguments: &[String]) -> i32 {
    match run(arguments, std::io::stdout().lock()) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "RCH_SOURCE_CLAIM_ROOTS_UNAVAILABLE {error:#}"
            );
            1
        }
    }
}

fn run(arguments: &[String], output: impl Write) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (arguments, output);
        bail!("source-claim root inventory requires a Unix worker");
    }
    #[cfg(unix)]
    {
        let mut output = output;
        let registries = match arguments {
            [operation] if operation == "probe" => {
                writeln!(output, "{PROBE_REPLY}")?;
                return Ok(());
            }
            [operation] if operation == "inventory" => vec![
                rch_common::stale_target_reap::SOURCE_CLAIM_REGISTRY,
                "/tmp/rch-source-authority-locks/claims-v1",
            ],
            [operation, registry] if operation == "inventory" => vec![registry.as_str()],
            _ => bail!("expected probe or inventory [registry]"),
        };
        let inventory = unix::inventory(&registries)?;
        // Do not emit any partial roots when a later record or directory fails.
        let bytes = serde_json::to_vec(&inventory)?;
        anyhow::ensure!(
            bytes.len() < rch_common::gc_roots::SOURCE_CLAIM_ROOTS_MAX_BYTES,
            "source-claim root inventory exceeds its output byte bound"
        );
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
        Ok(())
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use anyhow::{Context as _, ensure};
    use rch_common::gc_roots::{
        SOURCE_CLAIM_ROOTS_MAX_BYTES, SOURCE_CLAIM_ROOTS_MAX_ROOTS,
        SOURCE_CLAIM_ROOTS_SCHEMA_VERSION, SourceClaimRootsInventory, is_safe_source_claim_root,
    };
    use rustix::fd::{AsFd as _, OwnedFd};
    use rustix::fs::{AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, Stat};
    use rustix::io::Errno;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;
    use std::ffi::CStr;
    use std::fs::File;
    use std::io::Read as _;
    use std::path::Path;

    const MAX_ENTRIES: usize = 65_536;
    const MAX_ROOT_PROBES: usize = 65_536;
    const MAX_RECORD_BYTES: u64 = 32 * 1024 * 1024;
    const MAX_TOTAL_RECORD_BYTES: u64 = 64 * 1024 * 1024;
    const FILE_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY)
        .union(OFlags::CLOEXEC);
    const DIRECTORY_FLAGS: OFlags = FILE_FLAGS.union(OFlags::DIRECTORY);

    struct Budget {
        entries: usize,
        record_bytes: u64,
        root_bytes: usize,
        root_probes: usize,
        seen_roots: BTreeSet<String>,
    }

    impl Default for Budget {
        fn default() -> Self {
            Self {
                entries: MAX_ENTRIES,
                record_bytes: MAX_TOTAL_RECORD_BYTES,
                root_bytes: 0,
                root_probes: MAX_ROOT_PROBES,
                seen_roots: BTreeSet::new(),
            }
        }
    }

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    fn same_record(left: &Stat, right: &Stat) -> bool {
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

    fn private(info: &Stat, directory: bool) -> Result<()> {
        let expected = if directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        ensure!(
            FileType::from_raw_mode(info.st_mode) == expected
                && info.st_uid == rustix::process::geteuid().as_raw()
                && info.st_mode & 0o022 == 0,
            "unsafe source-claim inventory ownership, permissions or type"
        );
        Ok(())
    }

    fn optional_directory(parent: &OwnedFd, name: &str) -> Result<Option<OwnedFd>> {
        match rustix::fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(descriptor) => {
                private(&rustix::fs::fstat(&descriptor)?, true)?;
                Ok(Some(descriptor))
            }
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(error).context("open source-claim inventory directory"),
        }
    }

    fn verify_directory(parent: &OwnedFd, name: &str, directory: &OwnedFd) -> Result<()> {
        let opened = rustix::fs::fstat(directory)?;
        let named = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
        private(&opened, true)?;
        ensure!(
            same_inode(&opened, &named),
            "source-claim inventory directory changed"
        );
        Ok(())
    }

    fn claim_digest(name: &str) -> Result<&str> {
        let name = name
            .strip_suffix(".claim")
            .context("invalid source-claim name")?;
        let (token, digest) = name.split_once('.').context("invalid source-claim name")?;
        ensure!(
            !token.is_empty()
                && token.len() <= 128
                && token.bytes().all(|byte| byte.is_ascii_digit()
                    || (b'a'..=b'f').contains(&byte)
                    || byte == b'-')
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid source-claim name"
        );
        Ok(digest)
    }

    fn add_roots(bytes: &[u8], roots: &mut BTreeSet<String>, budget: &mut Budget) -> Result<()> {
        let text = std::str::from_utf8(bytes).context("source-claim roots are not UTF-8")?;
        ensure!(
            !text.is_empty() && text.ends_with('\n'),
            "incomplete source-claim roots"
        );
        for root in text[..text.len() - 1].split('\n') {
            ensure!(
                is_safe_source_claim_root(root),
                "unsafe source-claim inventory root: {root:?}"
            );
            // Historical receipts repeatedly name the same roots. Remember
            // missing paths too, so neither repetition nor retired roots can
            // cause unbounded filesystem probes under the registry lock.
            // The aggregate record-byte limit also bounds retained key bytes.
            if budget.seen_roots.contains(root) {
                continue;
            }
            budget.root_probes = budget
                .root_probes
                .checked_sub(1)
                .context("source-claim inventory exceeds its root probe bound")?;
            budget.seen_roots.insert(root.to_owned());
            // Preserve the authenticated lexical spelling, including legitimate
            // /dp and Darwin /tmp aliases. The ordinary scan resolves it and
            // rechecks current ownership before considering individual targets.
            match std::fs::metadata(root) {
                Ok(metadata) => ensure!(
                    metadata.is_dir(),
                    "source-claim root is not a directory: {root}"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect source-claim root {root}"));
                }
            }
            if roots.insert(root.to_owned()) {
                budget.root_bytes = budget
                    .root_bytes
                    .checked_add(root.len() + 3)
                    .context("source-claim inventory size overflow")?;
                ensure!(
                    roots.len() <= SOURCE_CLAIM_ROOTS_MAX_ROOTS
                        && budget.root_bytes < SOURCE_CLAIM_ROOTS_MAX_BYTES,
                    "source-claim root inventory exceeds its root or byte bound"
                );
            }
        }
        Ok(())
    }

    fn read_claim(
        directory: &OwnedFd,
        path: &Path,
        name: &CStr,
        roots: &mut BTreeSet<String>,
        budget: &mut Budget,
        after_read: &mut impl FnMut(&Path),
    ) -> Result<()> {
        let digest = claim_digest(name.to_str().context("non-UTF-8 source-claim name")?)?;
        let descriptor = rustix::fs::openat(directory, name, FILE_FLAGS, Mode::empty())
            .context("open source-claim inventory record")?;
        let mut file = File::from(descriptor);
        let before = rustix::fs::fstat(&file)?;
        private(&before, false)?;
        let length = u64::try_from(before.st_size).context("invalid source-claim record size")?;
        ensure!(
            length > 0 && length <= MAX_RECORD_BYTES,
            "source-claim record exceeds its byte bound"
        );
        budget.record_bytes = budget
            .record_bytes
            .checked_sub(length)
            .context("source-claim inventory exceeds its total record byte bound")?;
        let mut bytes = Vec::new();
        (&mut file).take(length + 1).read_to_end(&mut bytes)?;
        after_read(path);
        let after = rustix::fs::fstat(&file)?;
        let named = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            bytes.len() as u64 == length
                && same_record(&before, &after)
                && same_record(&named, &after),
            "source-claim inventory record changed"
        );
        let actual = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        ensure!(
            actual == digest,
            "source-claim inventory record digest mismatch"
        );
        add_roots(&bytes, roots, budget)
    }

    fn scan_directory(
        directory: &OwnedFd,
        path: &Path,
        roots: &mut BTreeSet<String>,
        budget: &mut Budget,
        after_read: &mut impl FnMut(&Path),
    ) -> Result<()> {
        let before = rustix::fs::fstat(directory)?;
        for entry in Dir::read_from(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            budget.entries = budget
                .entries
                .checked_sub(1)
                .context("source-claim inventory exceeds its directory-entry bound")?;
            if name.to_bytes().ends_with(b".claim") {
                let filename = name.to_str().context("non-UTF-8 source-claim name")?;
                read_claim(
                    directory,
                    &path.join(filename),
                    name,
                    roots,
                    budget,
                    after_read,
                )?;
            }
        }
        ensure!(
            same_record(&before, &rustix::fs::fstat(directory)?),
            "source-claim inventory directory changed during enumeration"
        );
        Ok(())
    }

    fn scan_registry(
        path: &str,
        roots: &mut BTreeSet<String>,
        budget: &mut Budget,
        after_read: &mut impl FnMut(&Path),
    ) -> Result<()> {
        ensure!(
            Path::new(path).is_absolute(),
            "source-claim registry must be absolute"
        );
        let (parent_path, name) = path.rsplit_once('/').context("invalid source-claim registry")?;
        ensure!(
            !parent_path.is_empty() && !name.is_empty(),
            "invalid source-claim registry"
        );
        // Match the existing cancellation-record contract: earlier OS aliases
        // are permitted, but the immediate parent and registry are no-follow.
        let parent = match rustix::fs::open(parent_path, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(parent) => parent,
            Err(Errno::NOENT) => return Ok(()),
            Err(error) => return Err(error).context("open source-claim inventory parent"),
        };
        private(&rustix::fs::fstat(&parent)?, true)?;
        let Some(registry) = optional_directory(&parent, name)? else {
            return Ok(());
        };
        let lock = rustix::fs::openat(&registry, "metadata.lock", FILE_FLAGS, Mode::empty())
            .context("open source-claim inventory metadata lock")?;
        let lock_before = rustix::fs::fstat(&lock)?;
        private(&lock_before, false)?;
        ensure!(
            lock_before.st_nlink == 1,
            "source-claim metadata lock has aliases"
        );
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockShared)
            .context("source-claim inventory metadata lock is busy")?;
        verify_directory(&parent, name, &registry)?;
        scan_directory(&registry, Path::new(path), roots, budget, after_read)?;
        for child in ["released", "cancelled"] {
            if let Some(directory) = optional_directory(&registry, child)? {
                scan_directory(
                    &directory,
                    &Path::new(path).join(child),
                    roots,
                    budget,
                    after_read,
                )?;
                verify_directory(&registry, child, &directory)?;
            }
        }
        verify_directory(&parent, name, &registry)?;
        let named_parent = rustix::fs::statat(
            rustix::fs::CWD.as_fd(),
            parent_path,
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        ensure!(
            same_inode(&named_parent, &rustix::fs::fstat(&parent)?),
            "source-claim inventory parent changed"
        );
        let named_lock =
            rustix::fs::statat(&registry, "metadata.lock", AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            same_record(&lock_before, &named_lock),
            "source-claim inventory metadata lock changed"
        );
        Ok(())
    }

    pub(super) fn inventory(registries: &[&str]) -> Result<SourceClaimRootsInventory> {
        inventory_with(registries, Budget::default(), |_| {})
    }

    fn inventory_with(
        registries: &[&str],
        mut budget: Budget,
        mut after_read: impl FnMut(&Path),
    ) -> Result<SourceClaimRootsInventory> {
        let mut roots = BTreeSet::new();
        for registry in registries {
            scan_registry(registry, &mut roots, &mut budget, &mut after_read)
                .with_context(|| format!("inventory registry {registry}"))?;
        }
        Ok(SourceClaimRootsInventory {
            schema_version: SOURCE_CLAIM_ROOTS_SCHEMA_VERSION,
            roots: roots.into_iter().collect(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::path::PathBuf;

        struct Fixture {
            _owner: tempfile::TempDir,
            registry: PathBuf,
            source: PathBuf,
        }

        impl Fixture {
            fn new() -> Self {
                let owner = tempfile::tempdir().unwrap();
                fs::set_permissions(owner.path(), fs::Permissions::from_mode(0o700)).unwrap();
                let registry = owner.path().join("claims-v1");
                fs::create_dir(&registry).unwrap();
                fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
                let lock = registry.join("metadata.lock");
                fs::write(&lock, []).unwrap();
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
                let source = owner.path().join("offroot-project");
                fs::create_dir(&source).unwrap();
                Self {
                    _owner: owner,
                    registry,
                    source,
                }
            }

            fn claim(&self, directory: &str, token: &str, roots: &[&Path]) -> PathBuf {
                let directory = self.registry.join(directory);
                fs::create_dir_all(&directory).unwrap();
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
                let content = format!(
                    "{}\n",
                    roots
                        .iter()
                        .map(|root| root.to_str().unwrap())
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                let digest = Sha256::digest(content.as_bytes())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let record = directory.join(format!("{token}.{digest}.claim"));
                fs::write(&record, content).unwrap();
                fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
                record
            }

            fn inventory(&self) -> Result<SourceClaimRootsInventory> {
                inventory(&[self.registry.to_str().unwrap()])
            }
        }

        #[test]
        fn published_records_discover_exact_roots_and_preserve_alias_spellings() {
            let fixture = Fixture::new();
            let alias = fixture.source.with_file_name("alias-project");
            symlink(&fixture.source, &alias).unwrap();
            let missing = fixture.source.with_file_name("retired-project");
            fixture.claim("", "ab01", &[&fixture.source]);
            fixture.claim("released", "ab02", &[&alias, &fixture.source, &missing]);
            fixture.claim("cancelled", "ab03", &[&fixture.source]);
            let pending = fixture.registry.join("unfinished.pending");
            fs::write(pending, "not a published claim").unwrap();
            let result = fixture.inventory().unwrap();
            assert_eq!(result.schema_version, SOURCE_CLAIM_ROOTS_SCHEMA_VERSION);
            let mut expected = vec![
                alias.to_str().unwrap().to_owned(),
                fixture.source.to_str().unwrap().to_owned(),
            ];
            expected.sort();
            assert_eq!(result.roots, expected);
            assert!(!result.roots.contains(
                &fixture
                    .source
                    .parent()
                    .unwrap()
                    .display()
                    .to_string()
            ));
        }

        #[test]
        fn repeated_existing_and_retired_roots_share_a_bounded_probe_budget() {
            let fixture = Fixture::new();
            let missing = fixture.source.with_file_name("retired-project");
            fixture.claim("", "ab01", &[&fixture.source, &missing, &missing]);
            fixture.claim("released", "ab02", &[&missing, &fixture.source]);
            fixture.claim("cancelled", "ab03", &[&fixture.source, &missing]);
            let result = inventory_with(
                &[fixture.registry.to_str().unwrap()],
                Budget {
                    root_probes: 2,
                    ..Budget::default()
                },
                |_| {},
            )
            .unwrap();
            assert_eq!(result.roots, vec![fixture.source.display().to_string()]);

            // A new missing path must still consume the bound even though it
            // would not increase the successful output's root count.
            let another_missing = fixture.source.with_file_name("another-retired-project");
            fixture.claim("released", "ab04", &[&another_missing]);
            let error = inventory_with(
                &[fixture.registry.to_str().unwrap()],
                Budget {
                    root_probes: 2,
                    ..Budget::default()
                },
                |_| {},
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("root probe bound"));
        }

        #[test]
        fn corrupt_record_never_emits_a_partial_inventory() {
            let fixture = Fixture::new();
            fixture.claim("", "ab01", &[&fixture.source]);
            let invalid = fixture.claim("released", "ab02", &[&fixture.source]);
            fs::write(invalid, "/a/different/root\n").unwrap();
            let mut output = Vec::new();
            let error = run(
                &["inventory".into(), fixture.registry.display().to_string()],
                &mut output,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("digest mismatch"));
            assert!(output.is_empty());
        }

        #[test]
        fn ownership_and_symlink_record_guards_remain_fail_closed() {
            let fixture = Fixture::new();
            let record = fixture.claim("released", "ab01", &[&fixture.source]);
            fs::set_permissions(&record, fs::Permissions::from_mode(0o666)).unwrap();
            assert!(fixture.inventory().is_err());
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
            let retained = record.with_extension("retained");
            fs::rename(&record, &retained).unwrap();
            symlink(&retained, &record).unwrap();
            assert!(fixture.inventory().is_err());
        }

        #[test]
        fn directory_binding_and_busy_registry_do_not_produce_roots() {
            let fixture = Fixture::new();
            fixture.claim("released", "ab01", &[&fixture.source]);
            let lock = fs::File::open(fixture.registry.join("metadata.lock")).unwrap();
            rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
            assert!(
                format!("{:#}", fixture.inventory().unwrap_err()).contains("lock is busy")
            );
            drop(lock);
            let old = fixture.registry.join("released-old");
            fs::rename(fixture.registry.join("released"), &old).unwrap();
            symlink(&old, fixture.registry.join("released")).unwrap();
            assert!(fixture.inventory().is_err());
        }

        #[test]
        fn changed_record_and_resource_limits_refuse_the_complete_scan() {
            let fixture = Fixture::new();
            fixture.claim("", "ab01", &[&fixture.source]);
            for budget in [
                Budget {
                    entries: 0,
                    ..Budget::default()
                },
                Budget {
                    record_bytes: 1,
                    ..Budget::default()
                },
                Budget {
                    root_bytes: SOURCE_CLAIM_ROOTS_MAX_BYTES,
                    ..Budget::default()
                },
            ] {
                assert!(
                    inventory_with(
                        &[fixture.registry.to_str().unwrap()],
                        budget,
                        |_| {}
                    )
                    .is_err()
                );
            }
            let error = inventory_with(
                &[fixture.registry.to_str().unwrap()],
                Budget::default(),
                |path| {
                    fs::write(path, "/changed/record\n").unwrap();
                },
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("record changed"));
        }

        #[test]
        fn replaced_registry_cannot_turn_an_old_descriptor_into_new_root_authority() {
            let fixture = Fixture::new();
            fixture.claim("", "ab01", &[&fixture.source]);
            let retained = fixture.registry.with_file_name("retained-registry");
            let error = inventory_with(
                &[fixture.registry.to_str().unwrap()],
                Budget::default(),
                |_| {
                    fs::rename(&fixture.registry, &retained).unwrap();
                    fs::create_dir(&fixture.registry).unwrap();
                    fs::set_permissions(
                        &fixture.registry,
                        fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                },
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("directory changed"));
            assert!(retained.join("metadata.lock").is_file());
            assert!(fixture.source.is_dir());
        }

        #[test]
        fn ambiguous_roots_are_not_normalized_into_scan_authority() {
            for path in [
                "/",
                "/tmp/../etc",
                "/tmp/./root",
                "/tmp//root",
                "/tmp/root/",
                "/tmp/a b",
                "/tmp/$HOME",
                "relative",
            ] {
                assert!(!is_safe_source_claim_root(path), "{path}");
            }
            let fixture = Fixture::new();
            fixture.claim("released", "ab01", &[Path::new("/")]);
            assert!(
                format!("{:#}", fixture.inventory().unwrap_err())
                    .contains("unsafe source-claim inventory root")
            );
        }

        #[test]
        fn missing_registry_is_an_empty_read_only_inventory() {
            let fixture = Fixture::new();
            let missing = fixture.registry.with_file_name("not-created");
            assert!(
                inventory(&[missing.to_str().unwrap()])
                    .unwrap()
                    .roots
                    .is_empty()
            );
            assert!(!missing.exists());
        }
    }
}
