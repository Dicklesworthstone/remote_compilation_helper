use super::*;
use flate2::{Compression, write::GzEncoder};
use std::io::Cursor;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

struct Fixture {
    temporary: tempfile::TempDir,
    bundle: PathBuf,
    root: PathBuf,
    native: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let bundle = temporary.path().join("bundle");
        fs::create_dir(&bundle).unwrap();
        let native = fs::read(external_true().unwrap()).unwrap();
        for name in TOOLS {
            write_executable(&bundle.join(name), &native);
        }
        let root = temporary.path().join("bin");
        Self {
            temporary,
            bundle,
            root,
            native,
        }
    }

    fn sources(&self) -> Sources {
        Source::Bundle(self.bundle.clone()).capture().unwrap()
    }

    fn install(&self) -> Value {
        install(&mut self.sources(), &self.root, false).unwrap()
    }

    fn active(&self) -> PathBuf {
        self.root
            .join(fs::read_link(self.root.join(CURRENT)).unwrap())
    }
}

fn write_executable(path: &Path, bytes: &[u8]) {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[derive(Debug, PartialEq, Eq)]
struct EntrySnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    links: u64,
    data: Vec<u8>,
}

fn snapshot(path: &Path) -> BTreeMap<PathBuf, EntrySnapshot> {
    fn visit(path: &Path, entries: &mut BTreeMap<PathBuf, EntrySnapshot>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let data = if metadata.is_file() {
            Sha256::digest(fs::read(path).unwrap()).to_vec()
        } else if metadata.file_type().is_symlink() {
            fs::read_link(path)
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else {
            Vec::new()
        };
        entries.insert(
            path.to_owned(),
            EntrySnapshot {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                size: metadata.size(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                links: metadata.nlink(),
                data,
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(&entry.unwrap().path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    visit(path, &mut entries);
    entries
}

#[test]
fn atomic_upgrade_keeps_old_generations_and_public_link_inodes() {
    let fixture = Fixture::new();
    let first = fixture.install();
    let previous = fixture.active();
    let inodes: Vec<_> = TOOLS
        .iter()
        .map(|name| fs::symlink_metadata(fixture.root.join(name)).unwrap().ino())
        .collect();
    let mut bytes = fixture.native.clone();
    bytes.extend_from_slice(b"second trusted source revision");
    write_executable(&fixture.bundle.join("rabsd"), &bytes);
    let second = fixture.install();
    assert_ne!(first["generation"], second["generation"]);
    assert!(previous.join("rabsd").is_file());
    assert_eq!(fs::read(previous.join("rabsd")).unwrap(), fixture.native);
    assert_eq!(fs::read(fixture.root.join("rabsd")).unwrap(), bytes);
    for (name, inode) in TOOLS.iter().zip(inodes) {
        assert_eq!(
            fs::symlink_metadata(fixture.root.join(name)).unwrap().ino(),
            inode
        );
        assert_eq!(
            fs::read_link(fixture.root.join(name)).unwrap(),
            Path::new(CURRENT).join(name)
        );
        assert_eq!(
            fs::metadata(fixture.active().join(name)).unwrap().mode() & 0o777,
            0o555
        );
    }
    assert_eq!(
        fs::metadata(fixture.active().join(MANIFEST))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(second["files"].as_object().unwrap().len(), TOOLS.len());
    assert_eq!(second["services_started"], false);
    assert_eq!(second["cargo_config_changed"], false);
}

#[test]
fn verification_is_read_only_and_requires_independent_expected_bytes() {
    let fixture = Fixture::new();
    fixture.install();
    let expected = fixture.sources().expected;
    let before = snapshot(&fixture.root);
    assert_eq!(
        verify_installed(&expected, &fixture.root).unwrap()["state"],
        "verified"
    );
    assert_eq!(snapshot(&fixture.root), before);

    // A self-consistent edited manifest is not authority for --verify.
    let active = fixture.active();
    let mut changed = fixture.native.clone();
    changed.extend_from_slice(b"unrequested executable");
    write_executable(&active.join("rabsd"), &changed);
    fs::set_permissions(active.join("rabsd"), fs::Permissions::from_mode(0o555)).unwrap();
    let mut manifest = expected.clone();
    manifest.files.insert(
        "rabsd".to_owned(),
        ToolIdentity {
            bytes: changed.len() as u64,
            sha256: digest_hex(&Sha256::digest(&changed)),
        },
    );
    fs::write(
        active.join(MANIFEST),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let before = snapshot(&fixture.root);
    assert!(verify_installed(&expected, &fixture.root).is_err());
    assert_eq!(snapshot(&fixture.root), before);
}

#[test]
fn verification_of_missing_installation_does_not_create_it() {
    let fixture = Fixture::new();
    assert!(verify_installed(&fixture.sources().expected, &fixture.root).is_err());
    assert!(!fixture.root.exists());
}

#[test]
fn installation_and_verification_compete_for_the_same_persistent_lock() {
    let fixture = Fixture::new();
    fixture.install();
    let lock = File::open(fixture.root.join(LOCK)).unwrap();
    rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    let before = snapshot(&fixture.root);
    let mut sources = fixture.sources();
    assert!(install(&mut sources, &fixture.root, false).is_err());
    assert!(verify_installed(&sources.expected, &fixture.root).is_err());
    assert_eq!(snapshot(&fixture.root), before);
    // Other process tests can fork while this fixture owns the lock. Explicit
    // unlock fences those transient pre-exec descriptor copies as well.
    rustix::fs::flock(&lock, FlockOperation::Unlock).unwrap();
    drop(lock);
    verify_installed(&sources.expected, &fixture.root).unwrap();
}

#[test]
fn sources_are_complete_split_profile_snapshots() {
    let fixture = Fixture::new();
    let build = fixture.temporary.path().join("target");
    for (name, path) in source_paths(&build, true) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::copy(fixture.bundle.join(&name), path).unwrap();
    }
    let mut sources = Source::Build(build.clone()).capture().unwrap();
    install(&mut sources, &fixture.root, false).unwrap();
    verify_installed(&sources.expected, &fixture.root).unwrap();
    fs::rename(
        build.join("daemon-release/rabsd"),
        build.join("rabsd-loose"),
    )
    .unwrap();
    assert!(Source::Build(build).capture().is_err());
}

#[test]
fn source_replacement_after_capture_never_activates() {
    let fixture = Fixture::new();
    let mut sources = fixture.sources();
    let saved = fixture.bundle.join("saved-rabsd");
    fs::rename(fixture.bundle.join("rabsd"), &saved).unwrap();
    fs::copy(&saved, fixture.bundle.join("rabsd")).unwrap();
    assert!(install(&mut sources, &fixture.root, false).is_err());
    assert!(!fixture.root.exists());
}

#[test]
fn incomplete_non_native_and_symlink_sources_are_refused_before_destination_creation() {
    for corruption in [
        "missing",
        "symlink",
        "script",
        "machine",
        "class",
        "endian",
        "type",
        "oversized",
    ] {
        let fixture = Fixture::new();
        let target = fixture.bundle.join("rabsd");
        match corruption {
            "missing" => {
                fs::rename(&target, fixture.bundle.join("saved")).unwrap();
            }
            "symlink" => {
                fs::rename(&target, fixture.bundle.join("saved")).unwrap();
                symlink("saved", &target).unwrap();
            }
            "script" => {
                write_executable(&target, b"#!/bin/sh\nexit 0\n");
            }
            "oversized" => {
                File::options()
                    .write(true)
                    .open(&target)
                    .unwrap()
                    .set_len(MAX_FILE_BYTES + 1)
                    .unwrap();
            }
            _ => {
                let mut bytes = fixture.native.clone();
                match corruption {
                    "machine" => bytes[18..20].copy_from_slice(&0xffff_u16.to_le_bytes()),
                    "class" => bytes[4] = 1,
                    "endian" => bytes[5] = 2,
                    "type" => bytes[16..18].copy_from_slice(&1_u16.to_le_bytes()),
                    _ => unreachable!(),
                }
                write_executable(&target, &bytes);
            }
        }
        assert!(
            Source::Bundle(fixture.bundle.clone()).capture().is_err(),
            "{corruption}"
        );
        assert!(!fixture.root.exists(), "{corruption}");
    }
}

#[test]
fn unmanaged_destinations_and_unsafe_locks_are_preserved() {
    for condition in [
        "file",
        "symlink",
        "directory-mode",
        "lock-symlink",
        "lock-mode",
        "lock-hardlink",
    ] {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.root).unwrap();
        match condition {
            "file" => fs::write(fixture.root.join("rabsd"), b"operator-owned").unwrap(),
            "symlink" => symlink("operator-owned", fixture.root.join("rabsd")).unwrap(),
            "directory-mode" => {
                fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o777)).unwrap()
            }
            "lock-symlink" => symlink("operator-owned", fixture.root.join(LOCK)).unwrap(),
            "lock-mode" => {
                fs::write(fixture.root.join(LOCK), b"").unwrap();
                fs::set_permissions(fixture.root.join(LOCK), fs::Permissions::from_mode(0o666))
                    .unwrap();
            }
            "lock-hardlink" => {
                fs::write(fixture.root.join(LOCK), b"").unwrap();
                fs::set_permissions(fixture.root.join(LOCK), fs::Permissions::from_mode(0o600))
                    .unwrap();
                fs::hard_link(
                    fixture.root.join(LOCK),
                    fixture.root.join("second-lock-name"),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            install(&mut fixture.sources(), &fixture.root, false).is_err(),
            "{condition}"
        );
        assert!(!fixture.root.join(CURRENT).exists(), "{condition}");
        if condition == "file" {
            assert_eq!(
                fs::read(fixture.root.join("rabsd")).unwrap(),
                b"operator-owned"
            );
        }
        if condition == "symlink" {
            assert_eq!(
                fs::read_link(fixture.root.join("rabsd")).unwrap(),
                Path::new("operator-owned")
            );
        }
    }
}

#[test]
fn installed_inventory_modes_manifest_duplicates_and_symlinks_are_rejected() {
    for corruption in [
        "extra",
        "tool-symlink",
        "tool-mode",
        "tool-hardlink",
        "manifest-mode",
        "manifest-duplicate",
        "manifest-oversized",
    ] {
        let fixture = Fixture::new();
        fixture.install();
        let expected = fixture.sources().expected;
        let active = fixture.active();
        match corruption {
            "extra" => fs::write(active.join("foreign"), b"extra").unwrap(),
            "tool-symlink" => {
                fs::rename(
                    active.join("rabsd"),
                    fixture.temporary.path().join("saved-rabsd"),
                )
                .unwrap();
                symlink(
                    fixture.temporary.path().join("saved-rabsd"),
                    active.join("rabsd"),
                )
                .unwrap();
            }
            "tool-mode" => {
                fs::set_permissions(active.join("rabsd"), fs::Permissions::from_mode(0o755))
                    .unwrap()
            }
            "tool-hardlink" => fs::hard_link(
                active.join("rabsd"),
                fixture.temporary.path().join("other-name"),
            )
            .unwrap(),
            "manifest-mode" => {
                fs::set_permissions(active.join(MANIFEST), fs::Permissions::from_mode(0o660))
                    .unwrap()
            }
            "manifest-duplicate" => {
                let bytes = serde_json::to_string(&expected).unwrap();
                fs::write(
                    active.join(MANIFEST),
                    bytes.replacen("{", "{\"schema\":1,", 1),
                )
                .unwrap();
            }
            "manifest-oversized" => File::options()
                .write(true)
                .open(active.join(MANIFEST))
                .unwrap()
                .set_len(MAX_MANIFEST_BYTES + 1)
                .unwrap(),
            _ => unreachable!(),
        }
        let before = snapshot(&fixture.root);
        assert!(
            verify_installed(&expected, &fixture.root).is_err(),
            "{corruption}"
        );
        assert_eq!(snapshot(&fixture.root), before, "{corruption}");
    }
}

#[test]
fn duplicate_manifest_tool_keys_are_not_silently_overwritten() {
    let fixture = Fixture::new();
    let expected = fixture.sources().expected;
    let json = serde_json::to_string(&expected).unwrap();
    let entry = serde_json::to_string(&expected.files["rabsd"]).unwrap();
    let duplicate = json.replacen("\"files\":{", &format!("\"files\":{{\"rabsd\":{entry},"), 1);
    assert!(serde_json::from_str::<Manifest>(&duplicate).is_err());
}

#[test]
fn replaced_current_or_root_namespace_is_not_verified() {
    for replacement in ["current", "root"] {
        let fixture = Fixture::new();
        fixture.install();
        let expected = fixture.sources().expected;
        let active = ActiveGeneration::open(&fixture.root).unwrap();
        if replacement == "current" {
            // Even identical target bytes cannot hide replacement of the link.
            let target = fs::read_link(fixture.root.join(CURRENT)).unwrap();
            symlink(target, fixture.root.join("pending-test")).unwrap();
            fs::rename(
                fixture.root.join("pending-test"),
                fixture.root.join(CURRENT),
            )
            .unwrap();
        } else {
            fs::rename(&fixture.root, fixture.temporary.path().join("moved-bin")).unwrap();
            fs::create_dir(&fixture.root).unwrap();
        }
        assert!(active.verify(Some(&expected)).is_err(), "{replacement}");
    }
}

fn archive(path: &Path, entries: &[(&str, u8, &[u8])]) {
    let gzip = GzEncoder::new(File::create(path).unwrap(), Compression::fast());
    let mut builder = tar::Builder::new(gzip);
    for (name, kind, bytes) in entries {
        let mut header = tar::Header::new_ustar();
        assert!(name.len() < 100);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::new(*kind));
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder.append(&header, Cursor::new(bytes)).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap();
}

#[test]
fn native_archive_install_preserves_core_tools_and_supports_read_only_verification() {
    let fixture = Fixture::new();
    let path = fixture.temporary.path().join("release.tar.gz");
    let mut entries: Vec<_> = TOOLS
        .iter()
        .map(|name| (*name, b'0', fixture.native.as_slice()))
        .collect();
    entries.push(("rch", b'0', b"core bytes are not installed by RABS"));
    entries.push(("install-rabs", b'0', b"ignored legacy helper data"));
    archive(&path, &entries);
    fs::create_dir(&fixture.root).unwrap();
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(fixture.root.join("rch"), b"existing core").unwrap();
    let mut sources = Source::Archive(path).capture().unwrap();
    install(&mut sources, &fixture.root, false).unwrap();
    assert_eq!(
        fs::read(fixture.root.join("rch")).unwrap(),
        b"existing core"
    );
    let before = snapshot(&fixture.root);
    verify_installed(&sources.expected, &fixture.root).unwrap();
    assert_eq!(snapshot(&fixture.root), before);
}

#[test]
fn raw_archives_reject_foreign_paths_duplicates_and_extension_headers() {
    let fixture = Fixture::new();
    for (name, kind) in [
        ("../rabsd", b'0'),
        ("/rabsd", b'0'),
        ("./rabsd", b'0'),
        ("foreign", b'0'),
        ("rabsd", b'1'),
        ("rabsd", b'2'),
        ("rabsd", b'3'),
        ("rabsd", b'5'),
        ("rabsd", b'x'),
        ("rabsd", b'g'),
        ("rabsd", b'L'),
        ("rabsd", b'K'),
        ("rabsd", b'S'),
    ] {
        let archive_path = fixture.temporary.path().join("bad.tar.gz");
        archive(&archive_path, &[(name, kind, &fixture.native)]);
        let destination = tempfile::tempdir().unwrap();
        assert!(
            unpack_archive(&archive_path, destination.path(), MAX_ARCHIVE_BYTES).is_err(),
            "{name}/{kind}"
        );
    }
    let path = fixture.temporary.path().join("duplicate.tar.gz");
    archive(
        &path,
        &[
            ("rabsd", b'0', &fixture.native),
            ("rabsd", b'0', &fixture.native),
        ],
    );
    let destination = tempfile::tempdir().unwrap();
    assert!(unpack_archive(&path, destination.path(), MAX_ARCHIVE_BYTES).is_err());
}

#[test]
fn truncated_overexpanded_and_symlink_archives_leave_current_generation_unchanged() {
    let fixture = Fixture::new();
    fixture.install();
    let before = snapshot(&fixture.root);
    let path = fixture.temporary.path().join("release.tar.gz");
    let entries: Vec<_> = TOOLS
        .iter()
        .map(|name| (*name, b'0', fixture.native.as_slice()))
        .collect();
    archive(&path, &entries);
    let compressed = fs::metadata(&path).unwrap().len();
    assert!(compressed < fixture.native.len() as u64 * TOOLS.len() as u64);
    let destination = tempfile::tempdir().unwrap();
    assert!(unpack_archive(&path, destination.path(), compressed + 1).is_err());
    let link = fixture.temporary.path().join("archive-link");
    symlink(&path, &link).unwrap();
    assert!(Source::Archive(link).capture().is_err());
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(compressed - 5)
        .unwrap();
    assert!(Source::Archive(path).capture().is_err());
    assert_eq!(snapshot(&fixture.root), before);
}

#[test]
fn failed_native_launch_check_retains_stage_without_activating_it() {
    let fixture = Fixture::new();
    fixture.install();
    let previous = fs::read_link(fixture.root.join(CURRENT)).unwrap();
    // A header is sufficient for architecture inspection, but cannot execute.
    write_executable(&fixture.bundle.join("rabsd"), &fixture.native[..64]);
    let mut sources = fixture.sources();
    assert!(install(&mut sources, &fixture.root, true).is_err());
    assert_eq!(fs::read_link(fixture.root.join(CURRENT)).unwrap(), previous);
    assert_eq!(
        fs::read_dir(fixture.root.join(VERSIONS)).unwrap().count(),
        2
    );
    verify_installed(
        &Source::Bundle(fixture.root.join(previous))
            .capture()
            .unwrap()
            .expected,
        &fixture.root,
    )
    .unwrap();
}

#[test]
fn successful_staged_and_installed_probes_do_not_start_services_or_change_configuration() {
    let fixture = Fixture::new();
    let result = install(&mut fixture.sources(), &fixture.root, true).unwrap();
    assert_eq!(result["services_started"], false);
    let before = snapshot(&fixture.root);
    let receipt = probe_installed(&fixture.root).unwrap();
    assert_eq!(receipt["kind"], "rabs-launch-check");
    assert_eq!(receipt["state"], "passed");
    assert_eq!(snapshot(&fixture.root), before);
}

#[test]
fn byte_verification_does_not_execute_an_unlaunchable_native_image() {
    let fixture = Fixture::new();
    write_executable(&fixture.bundle.join("rabsd"), &fixture.native[..64]);
    let mut sources = fixture.sources();
    install(&mut sources, &fixture.root, false).unwrap();
    let before = snapshot(&fixture.root);
    assert_eq!(
        verify_installed(&sources.expected, &fixture.root).unwrap()["state"],
        "verified"
    );
    assert_eq!(snapshot(&fixture.root), before);
    assert!(probe_installed(&fixture.root).is_err());
}

#[test]
fn launcher_deadline_kills_and_reaps_its_child() {
    let start = Instant::now();
    let mut command = Command::new("/bin/sleep");
    command.arg("30");
    let error = probe_command(&mut command, Duration::from_millis(30)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
#[allow(clippy::zombie_processes)] // The parent probe must kill this deliberate descendant.
fn probe_descendant_fixture() {
    let Some(path) = std::env::var_os("RABS_TEST_PROBE_DESCENDANT") else {
        return;
    };
    let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    fs::write(path, child.id().to_string()).unwrap();
    std::process::exit(0);
}

#[test]
fn successful_probe_reaps_leader_after_signaling_surviving_descendants() {
    let temporary = tempfile::tempdir().unwrap();
    let pid_file = temporary.path().join("descendant");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "installer::tests::probe_descendant_fixture",
            "--nocapture",
        ])
        .env("RABS_TEST_PROBE_DESCENDANT", &pid_file);
    probe_command(&mut command, Duration::from_secs(3)).unwrap();
    let pid = fs::read_to_string(pid_file).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let state = fs::read_to_string(format!("/proc/{}/stat", pid.trim()));
        if state
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            || state.as_ref().is_ok_and(|stat| {
                stat.rsplit_once(") ")
                    .is_some_and(|(_, tail)| tail.starts_with('Z'))
            })
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "probe descendant remains live: {state:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn unsupported_or_conflicting_cli_options_fail_before_creating_an_installation() {
    let fixture = Fixture::new();
    for extra in [
        vec!["--ssh", "worker"],
        vec!["--package", "release.tar.gz"],
        vec!["--verify", "--probe"],
        vec!["--probe-installed"],
        vec!["--verify", "--verify"],
    ] {
        let mut arguments = vec![
            OsString::from("--from-bundle"),
            fixture.bundle.as_os_str().to_owned(),
            OsString::from("--bin-dir"),
            fixture.root.as_os_str().to_owned(),
        ];
        arguments.extend(extra.into_iter().map(OsString::from));
        assert!(run(&arguments).is_err());
        assert!(!fixture.root.exists());
    }
}

fn host_target_triple() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        other => panic!("unsupported test arch: {other}"),
    }
}

fn other_target_triple() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "aarch64-unknown-linux-gnu",
        "aarch64" => "x86_64-unknown-linux-gnu",
        other => panic!("unsupported test arch: {other}"),
    }
}

#[test]
fn package_archive_is_deterministic_and_round_trips_through_install_and_verify() {
    let fixture = Fixture::new();
    let archive_a = fixture.temporary.path().join("release-a.tar.gz");
    let archive_b = fixture.temporary.path().join("release-b.tar.gz");
    let target = host_target_triple();

    let (receipt_a, ok_a) = run(&[
        OsString::from("--from-bundle"),
        fixture.bundle.as_os_str().to_owned(),
        OsString::from("--package"),
        archive_a.as_os_str().to_owned(),
        OsString::from("--target"),
        OsString::from(target),
    ])
    .unwrap();
    assert!(ok_a);
    assert_eq!(receipt_a["kind"], "rabs-packaged");
    assert_eq!(receipt_a["target"], target);
    assert_eq!(receipt_a["source_identity"], Value::Null);
    assert_eq!(receipt_a["services_started"], false);
    assert_eq!(receipt_a["cargo_config_changed"], false);
    assert_eq!(
        receipt_a["toolset"]["files"].as_object().unwrap().len(),
        TOOLS.len()
    );

    let (receipt_b, ok_b) = run(&[
        OsString::from("--from-bundle"),
        fixture.bundle.as_os_str().to_owned(),
        OsString::from("--package"),
        archive_b.as_os_str().to_owned(),
        OsString::from("--target"),
        OsString::from(target),
    ])
    .unwrap();
    assert!(ok_b);
    // Deterministic USTAR + mtime=0 gzip produces byte-identical archives.
    assert_eq!(receipt_a["sha256"], receipt_b["sha256"]);
    assert_eq!(receipt_a["bytes"], receipt_b["bytes"]);
    assert_eq!(fs::read(&archive_a).unwrap(), fs::read(&archive_b).unwrap());
    assert_eq!(
        digest_hex(&Sha256::digest(fs::read(&archive_a).unwrap())),
        receipt_a["sha256"].as_str().unwrap()
    );

    // Produced archive installs and verifies cleanly via --from-archive.
    let (installed, ok_inst) = run(&[
        OsString::from("--from-archive"),
        archive_a.as_os_str().to_owned(),
        OsString::from("--bin-dir"),
        fixture.root.as_os_str().to_owned(),
    ])
    .unwrap();
    assert!(ok_inst);
    assert_eq!(installed["kind"], "rabs-installed");

    let (verified, ok_ver) = run(&[
        OsString::from("--from-archive"),
        archive_a.as_os_str().to_owned(),
        OsString::from("--bin-dir"),
        fixture.root.as_os_str().to_owned(),
        OsString::from("--verify"),
    ])
    .unwrap();
    assert!(ok_ver);
    assert_eq!(verified["state"], "verified");
}

#[test]
fn package_archive_refuses_target_mismatch_existing_file_and_dangling_symlink() {
    let fixture = Fixture::new();
    let out = fixture.temporary.path().join("mismatch.tar.gz");

    // Wrong --target must refuse before publishing.
    assert!(
        run(&[
            OsString::from("--from-bundle"),
            fixture.bundle.as_os_str().to_owned(),
            OsString::from("--package"),
            out.as_os_str().to_owned(),
            OsString::from("--target"),
            OsString::from(other_target_triple()),
        ])
        .is_err()
    );
    assert!(!out.exists());

    // Existing file must never be clobbered.
    let existing = fixture.temporary.path().join("existing.tar.gz");
    fs::write(&existing, b"keep-existing").unwrap();
    assert!(
        run(&[
            OsString::from("--from-bundle"),
            fixture.bundle.as_os_str().to_owned(),
            OsString::from("--package"),
            existing.as_os_str().to_owned(),
            OsString::from("--target"),
            OsString::from(host_target_triple()),
        ])
        .is_err()
    );
    assert_eq!(fs::read(&existing).unwrap(), b"keep-existing");

    // Dangling symlink must never be followed or replaced.
    let dangling = fixture.temporary.path().join("dangling.tar.gz");
    symlink(fixture.temporary.path().join("nowhere"), &dangling).unwrap();
    assert!(
        run(&[
            OsString::from("--from-bundle"),
            fixture.bundle.as_os_str().to_owned(),
            OsString::from("--package"),
            dangling.as_os_str().to_owned(),
            OsString::from("--target"),
            OsString::from(host_target_triple()),
        ])
        .is_err()
    );
    assert!(!fixture.temporary.path().join("nowhere").exists());

    // --target / --require-source without --package must refuse.
    assert!(
        run(&[
            OsString::from("--from-bundle"),
            fixture.bundle.as_os_str().to_owned(),
            OsString::from("--bin-dir"),
            fixture.root.as_os_str().to_owned(),
            OsString::from("--target"),
            OsString::from(host_target_triple()),
        ])
        .is_err()
    );
    assert!(
        run(&[
            OsString::from("--from-bundle"),
            fixture.bundle.as_os_str().to_owned(),
            OsString::from("--package"),
            out.as_os_str().to_owned(),
            OsString::from("--target"),
            OsString::from(host_target_triple()),
            OsString::from("--require-source"),
            OsString::from("not-a-40-hex-commit"),
        ])
        .is_err()
    );
}
