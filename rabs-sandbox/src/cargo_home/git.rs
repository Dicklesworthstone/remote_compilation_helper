//! The transport shape of reconstructed, revision-only Cargo Git databases.
//!
//! The preparer verifies Git object closure before creating the source bundle.
//! This projection admits only that bounded shape and checks control bytes from
//! the retained, hash-verified source image before creating a writable home.
//! It never accepts user hooks, remotes, alternates, checkouts or loose refs.

use super::{SealedSourceSnapshot, SourceManifest, invalid, require};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

/// This is generated configuration, never configuration copied from a user.
pub const CAPTURED_GIT_CONFIG: &[u8] =
    b"[core]\n\tbare = true\n\trepositoryformatversion = 0\n\tfilemode = true\n";

const MAX_DATABASES: usize = 64;
const MAX_REVISIONS: usize = 64;
type Databases<'a> = BTreeMap<&'a str, BTreeSet<&'a str>>;

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn namespace(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && value
            .rsplit_once('-')
            .is_some_and(|(name, suffix)| !name.is_empty() && lower_hex(suffix, 16))
}

fn databases(manifest: &SourceManifest) -> io::Result<Databases<'_>> {
    let mut databases = BTreeMap::<&str, BTreeSet<&str>>::new();
    for file in manifest.files() {
        let Some(path) = file.path.strip_prefix("git/db/") else {
            continue;
        };
        let (database, member) = path
            .split_once('/')
            .ok_or_else(|| invalid("captured Git database member is missing"))?;
        require(
            namespace(database),
            "invalid captured Git database namespace",
        )?;
        require(
            !file.executable,
            "captured Git database files cannot execute",
        )?;
        let valid = match member {
            "config" => file.len == CAPTURED_GIT_CONFIG.len() as u64,
            "HEAD" | "refs/heads/rabs-captured" => file.len == 41,
            "shallow" => {
                file.len > 0
                    && file.len <= (41 * MAX_REVISIONS) as u64
                    && file.len.is_multiple_of(41)
            }
            _ => member
                .strip_prefix("objects/pack/pack-")
                .is_some_and(|name| {
                    if let Some(hash) = name.strip_suffix(".pack") {
                        lower_hex(hash, 40) && file.len >= 32
                    } else if let Some(hash) = name.strip_suffix(".idx") {
                        lower_hex(hash, 40) && file.len >= 1072
                    } else {
                        false
                    }
                }),
        };
        require(valid, "unsupported captured Git database member")?;
        databases.entry(database).or_default().insert(member);
        require(
            databases.len() <= MAX_DATABASES,
            "captured Git database count exceeds its bound",
        )?;
    }
    require(!databases.is_empty(), "Git projection has no Git database")?;
    for members in databases.values() {
        require(
            members.len() == 6
                && ["config", "HEAD", "shallow", "refs/heads/rabs-captured"]
                    .iter()
                    .all(|member| members.contains(member)),
            "captured Git database requires its exact control files and pack pair",
        )?;
        let pack = members
            .iter()
            .find_map(|member| member.strip_suffix(".pack"))
            .ok_or_else(|| invalid("captured Git database pack missing"))?;
        require(
            members.contains(format!("{pack}.idx").as_str()),
            "captured Git pack and index names differ",
        )?;
    }
    Ok(databases)
}

pub(super) fn validate_manifest(manifest: &SourceManifest) -> io::Result<()> {
    databases(manifest).map(|_| ())
}

pub(super) fn verify_contents(
    image: &SealedSourceSnapshot,
    manifest: &SourceManifest,
    prefix: &str,
) -> io::Result<()> {
    for (database, members) in databases(manifest)? {
        let bytes = |member: &str| {
            image
                .file_bytes(
                    "cargo-home",
                    &format!("{prefix}/git/db/{database}/{member}"),
                )
                .ok_or_else(|| invalid("retained Git database member missing"))
        };
        require(
            bytes("config")? == CAPTURED_GIT_CONFIG,
            "captured Git configuration differs from the fixed contract",
        )?;
        let head = std::str::from_utf8(bytes("HEAD")?)
            .map_err(|_| invalid("captured Git HEAD is not UTF-8"))?;
        let revision = head
            .strip_suffix('\n')
            .filter(|revision| lower_hex(revision, 40))
            .ok_or_else(|| invalid("captured Git HEAD must be a detached full revision"))?;
        require(
            bytes("refs/heads/rabs-captured")? == head.as_bytes(),
            "captured Git fixed ref differs from HEAD",
        )?;
        let shallow = std::str::from_utf8(bytes("shallow")?)
            .map_err(|_| invalid("captured Git shallow roots are not UTF-8"))?;
        let mut previous = None;
        let mut contains_head = false;
        for line in shallow.split_inclusive('\n') {
            let commit = line
                .strip_suffix('\n')
                .filter(|commit| lower_hex(commit, 40))
                .ok_or_else(|| invalid("captured Git shallow root is not a full revision"))?;
            require(
                previous.is_none_or(|previous| previous < commit),
                "captured Git shallow roots must be sorted and unique",
            )?;
            contains_head |= commit == revision;
            previous = Some(commit);
        }
        require(
            contains_head,
            "captured Git shallow roots do not include HEAD",
        )?;
        let pack_name = members
            .iter()
            .find(|member| member.ends_with(".pack"))
            .ok_or_else(|| invalid("captured Git database pack missing"))?;
        let stem = pack_name
            .strip_suffix(".pack")
            .ok_or_else(|| invalid("captured Git database pack suffix missing"))?;
        let pack = bytes(pack_name)?;
        let index = bytes(&format!("{stem}.idx"))?;
        require(
            pack.starts_with(b"PACK") && matches!(&pack[4..8], [0, 0, 0, 2] | [0, 0, 0, 3]),
            "captured Git pack envelope is invalid",
        )?;
        let trailer = &pack[pack.len() - 20..];
        let hash: String = trailer.iter().map(|byte| format!("{byte:02x}")).collect();
        require(
            *pack_name == format!("objects/pack/pack-{hash}.pack")
                && index.starts_with(b"\xfftOc\0\0\0\x02")
                && &index[index.len() - 40..index.len() - 20] == trailer,
            "captured Git pack and index envelopes do not match",
        )?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::canonical_namespace::{Bind, CanonicalNamespaceSpec};
    use crate::cargo_home::{
        CARGO_HOME_SOURCE_VERSION, CargoHomeProjection, ISOLATED_CARGO_HOME_SOURCE_VERSION,
        ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
    };
    use crate::source_transfer::{SourceFile, SourceReceiver};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    const PREFIX: &str = "cache";
    const DATABASE: &str = "dependency-0123456789abcdef";
    const REVISION: &str = "1111111111111111111111111111111111111111";
    const OTHER_REVISION: &str = "2222222222222222222222222222222222222222";
    const PACK: &str = "objects/pack/pack-7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a.pack";
    const INDEX: &str = "objects/pack/pack-7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a.idx";
    type Payload = BTreeMap<String, Vec<u8>>;

    fn path(member: &str) -> String {
        format!("{PREFIX}/git/db/{DATABASE}/{member}")
    }

    // Intentionally synthetic pack/index envelopes: these fixtures exercise
    // projection shape, byte checks and custody, not Git object validity.
    // Native Git and Cargo resolution are covered by preparer integration tests.
    fn shape_payload() -> Payload {
        let mut pack = vec![0_u8; 32];
        pack[..8].copy_from_slice(b"PACK\0\0\0\x02");
        pack[12..].fill(0x7a);
        let mut index = vec![0_u8; 1072];
        index[..8].copy_from_slice(b"\xfftOc\0\0\0\x02");
        index[1032..1052].fill(0x7a);
        BTreeMap::from([
            (path("config"), CAPTURED_GIT_CONFIG.to_vec()),
            (path("HEAD"), format!("{REVISION}\n").into_bytes()),
            (
                path("refs/heads/rabs-captured"),
                format!("{REVISION}\n").into_bytes(),
            ),
            (
                path("shallow"),
                format!("{REVISION}\n{OTHER_REVISION}\n").into_bytes(),
            ),
            (path(PACK), pack),
            (path(INDEX), index),
            (
                "cache/registry/cache/example/pkg-1.crate".into(),
                b"registry bytes\0\xff".to_vec(),
            ),
            (
                "Cargo.toml".into(),
                b"[package]\nname='fixture'\nversion='0.1.0'\n".to_vec(),
            ),
            (
                "src/lib.rs".into(),
                b"pub fn value() -> u8 { 7 }\n".to_vec(),
            ),
        ])
    }

    fn manifest(payload: &Payload) -> SourceManifest {
        SourceManifest::new(
            payload
                .iter()
                .map(|(path, bytes)| SourceFile {
                    path: path.clone(),
                    len: bytes.len() as u64,
                    sha256: Sha256::digest(bytes).into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap()
    }

    fn projection(payload: &Payload) -> io::Result<CargoHomeProjection> {
        CargoHomeProjection::for_version(
            ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
            PREFIX,
            &manifest(payload),
        )
    }

    fn private() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn sealed(parent: &Path, payload: &Payload) -> SourceReceiver {
        let mut source =
            SourceReceiver::create(&parent.join("transfer"), manifest(payload)).unwrap();
        for (path, bytes) in payload {
            if !bytes.is_empty() {
                source
                    .write_chunk(path, 0, bytes, Sha256::digest(bytes).into())
                    .unwrap();
            }
        }
        source.seal().unwrap();
        source
    }

    #[test]
    fn git_projection_shape_requires_new_version_and_exact_six_file_database() {
        let payload = shape_payload();
        let source = manifest(&payload);
        assert_eq!(
            projection(&payload).unwrap().version(),
            ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
        );
        for version in [
            CARGO_HOME_SOURCE_VERSION,
            ISOLATED_CARGO_HOME_SOURCE_VERSION,
        ] {
            assert!(CargoHomeProjection::for_version(version, PREFIX, &source).is_err());
        }
        for member in [
            "config",
            "HEAD",
            "shallow",
            "refs/heads/rabs-captured",
            PACK,
            INDEX,
        ] {
            let mut incomplete = payload.clone();
            incomplete.remove(&path(member));
            assert!(projection(&incomplete).is_err(), "missing {member}");
        }
        let mut extra_pack = payload.clone();
        extra_pack.insert(
            path(&PACK.replace("7a", "8b")),
            payload[&path(PACK)].clone(),
        );
        assert!(projection(&extra_pack).is_err());
        let mut mismatched = payload.clone();
        let index = mismatched.remove(&path(INDEX)).unwrap();
        mismatched.insert(path(&INDEX.replace("7a", "8b")), index);
        assert!(projection(&mismatched).is_err());
        let registry_only = payload
            .into_iter()
            .filter(|(path, _)| !path.starts_with("cache/git/"))
            .collect();
        assert!(projection(&registry_only).is_err());
    }

    #[test]
    fn git_projection_shape_refuses_executables_and_untrusted_git_state() {
        let payload = shape_payload();
        let source = manifest(&payload);
        for (index, file) in source.files().iter().enumerate() {
            if file.path.starts_with("cache/git/") {
                let mut files = source.files().to_vec();
                files[index].executable = true;
                let executable = SourceManifest::new(files).unwrap();
                assert!(
                    CargoHomeProjection::for_version(
                        ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
                        PREFIX,
                        &executable,
                    )
                    .is_err(),
                    "{}",
                    file.path
                );
            }
        }
        for member in [
            "hooks/post-checkout",
            "objects/info/alternates",
            "objects/info/http-alternates",
            "refs/heads/main",
            "packed-refs",
            "config.worktree",
            "objects/11/11111111111111111111111111111111111111",
        ] {
            let mut unexpected = payload.clone();
            unexpected.insert(path(member), b"untrusted".to_vec());
            assert!(projection(&unexpected).is_err(), "{member}");
        }
        for member in [
            "cache/git/checkouts/dependency/src/lib.rs",
            "cache/config.toml",
            "cache/credentials.toml",
            "cache/bin/git",
        ] {
            let mut unexpected = payload.clone();
            unexpected.insert(member.into(), b"untrusted".to_vec());
            assert!(projection(&unexpected).is_err(), "{member}");
        }
    }

    #[test]
    fn git_projection_shape_bounds_database_names_counts_and_control_lengths() {
        let payload = shape_payload();
        for name in [
            "dependency-not-a-cargo-hash",
            "-0123456789abcdef",
            "dependency.name-0123456789abcdef",
        ] {
            let renamed = payload
                .iter()
                .map(|(path, bytes)| (path.replace(DATABASE, name), bytes.clone()))
                .collect();
            assert!(projection(&renamed).is_err(), "{name}");
        }
        for (member, bytes) in [
            ("config", vec![b'x'; CAPTURED_GIT_CONFIG.len() + 1]),
            ("HEAD", vec![b'1'; 40]),
            ("shallow", Vec::new()),
            (
                "shallow",
                format!("{REVISION}\n")
                    .repeat(MAX_REVISIONS + 1)
                    .into_bytes(),
            ),
            (PACK, vec![0; 31]),
            (INDEX, vec![0; 1071]),
        ] {
            let mut malformed = payload.clone();
            malformed.insert(path(member), bytes);
            assert!(projection(&malformed).is_err(), "{member}");
        }
        let mut databases: Payload = payload
            .iter()
            .filter(|(path, _)| !path.starts_with("cache/git/"))
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect();
        for index in 0..=MAX_DATABASES {
            let name = format!("dependency-{index:016x}");
            for (path, bytes) in payload
                .iter()
                .filter(|(path, _)| path.starts_with("cache/git/"))
            {
                databases.insert(path.replace(DATABASE, &name), bytes.clone());
            }
        }
        assert!(projection(&databases).is_err());
    }

    #[test]
    fn invalid_git_control_bytes_and_envelopes_refuse_before_destination_creation() {
        let payload = shape_payload();
        let mut config = CAPTURED_GIT_CONFIG.to_vec();
        config[1..5].copy_from_slice(b"http");
        let mut symbolic_head = b"ref: refs/heads/main".to_vec();
        symbolic_head.resize(40, b' ');
        symbolic_head.push(b'\n');
        let mut non_utf8_head = vec![0xff; 41];
        non_utf8_head[40] = b'\n';
        let mut cases = vec![
            ("configuration", "config", config),
            ("symbolic HEAD", "HEAD", symbolic_head),
            ("non-UTF-8 HEAD", "HEAD", non_utf8_head),
            (
                "unterminated HEAD",
                "HEAD",
                format!("{REVISION}x").into_bytes(),
            ),
            (
                "foreign fixed ref",
                "refs/heads/rabs-captured",
                format!("{OTHER_REVISION}\n").into_bytes(),
            ),
            (
                "missing shallow HEAD",
                "shallow",
                format!("{OTHER_REVISION}\n").into_bytes(),
            ),
            (
                "duplicate shallow roots",
                "shallow",
                format!("{REVISION}\n{REVISION}\n").into_bytes(),
            ),
            (
                "unsorted shallow roots",
                "shallow",
                format!("{OTHER_REVISION}\n{REVISION}\n").into_bytes(),
            ),
            (
                "unterminated shallow root",
                "shallow",
                format!("{REVISION}x").into_bytes(),
            ),
        ];
        for (label, member, offset, value) in [
            ("pack magic", PACK, 0, b'X'),
            ("pack version", PACK, 7, 4),
            ("pack trailer/name", PACK, 31, 0),
            ("index magic", INDEX, 0, 0),
            ("index version", INDEX, 7, 3),
            ("index/pack trailer", INDEX, 1032, 0),
        ] {
            let mut bytes = payload[&path(member)].clone();
            bytes[offset] = value;
            cases.push((label, member, bytes));
        }
        for (label, member, bytes) in cases {
            let mut malformed = payload.clone();
            malformed.insert(path(member), bytes);
            // These bytes have a valid shape and their own correct transport
            // hashes: rejection must come from retained control-byte checks.
            let projection = projection(&malformed).unwrap();
            let parent = private();
            let source = sealed(parent.path(), &malformed);
            let destination = parent.path().join("must-not-exist");
            let error = projection
                .prepare(&source, &destination, || false)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{label}: {error}");
            assert!(
                !destination.exists(),
                "{label} created a partial destination"
            );
        }
    }

    #[test]
    fn git_projection_shape_copies_mixed_cache_into_independent_isolated_roots() {
        let payload = shape_payload();
        let projection = projection(&payload).unwrap();
        let parent = private();
        let source = sealed(parent.path(), &payload);
        let source_root = source.sealed_root().unwrap();
        let original_manifest = source.manifest().clone();
        let prepared = projection
            .prepare(&source, &parent.path().join("isolated"), || false)
            .unwrap();
        let workspace = prepared.projected_workspace().unwrap();
        assert!(!workspace.join(PREFIX).exists());
        assert_eq!(
            fs::read(workspace.join("src/lib.rs")).unwrap(),
            payload["src/lib.rs"]
        );
        assert_eq!(
            fs::metadata(workspace.join("src/lib.rs")).unwrap().mode() & 0o777,
            0o444
        );
        for (path, bytes) in &payload {
            let Some(relative) = path.strip_prefix("cache/") else {
                continue;
            };
            let copied = prepared.root().join(relative);
            let original = source_root.join(path);
            assert_eq!(fs::read(&copied).unwrap(), *bytes);
            assert_ne!(
                fs::metadata(&copied).unwrap().ino(),
                fs::metadata(&original).unwrap().ino()
            );
            assert_eq!(fs::metadata(&copied).unwrap().mode() & 0o777, 0o600);
        }
        let operator_home = parent.path().join("operator-home");
        fs::create_dir(&operator_home).unwrap();
        fs::write(operator_home.join("credentials.toml"), b"keep private").unwrap();
        let mut namespace = CanonicalNamespaceSpec::new();
        namespace
            .rw_binds
            .push(Bind::new(&operator_home, crate::layout::CARGO_HOME));
        namespace
            .rw_binds
            .push(Bind::new(source_root, crate::layout::WORKSPACE));
        prepared.apply_to(&mut namespace).unwrap();
        assert!(
            namespace
                .ro_binds
                .iter()
                .any(|bind| bind.visible == Path::new(crate::layout::WORKSPACE)
                    && bind.backing == workspace)
        );
        assert!(
            namespace
                .rw_binds
                .iter()
                .any(|bind| bind.visible == Path::new(crate::layout::CARGO_HOME)
                    && bind.backing == prepared.root())
        );
        assert!(!namespace.allows_network());
        let copied_config = prepared.root().join("git/db").join(DATABASE).join("config");
        fs::write(copied_config, b"private runtime mutation").unwrap();
        assert_eq!(
            fs::read(source_root.join(path("config"))).unwrap(),
            CAPTURED_GIT_CONFIG
        );
        assert_eq!(source.manifest(), &original_manifest);
        assert_eq!(
            fs::read(operator_home.join("credentials.toml")).unwrap(),
            b"keep private"
        );
    }
}
