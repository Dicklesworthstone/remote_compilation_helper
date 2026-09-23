//! Real filesystem capture and mutation tests. The explicit installed-rustc test
//! additionally compiles from retained bytes; it is not sandbox/ATP proof.
#![cfg(target_os = "linux")]

use rabs_sandbox::toolchain_dataset::{ToolchainLimits, capture_toolchain, fingerprint_toolchain};
use std::cell::Cell;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

fn private() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn write(root: &Path, name: &str, bytes: &[u8], mode: u32) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn fixture(root: &Path) {
    write(root, "bin/rustc", b"fixture compiler bytes", 0o755);
    write(root, "lib/runtime.so", b"fixture runtime\0\xff", 0o644);
    write(
        root,
        "lib/rustlib/target/lib/std.rlib",
        b"fixture sysroot",
        0o644,
    );
    fs::create_dir(root.join("empty")).unwrap();
    symlink("../lib/runtime.so", root.join("bin/runtime")).unwrap();
    symlink("runtime", root.join("bin/chained")).unwrap();
    symlink("rustlib/target", root.join("lib/target")).unwrap();
    symlink(
        "lib/target/lib/std.rlib",
        root.join("through-directory-link"),
    )
    .unwrap();
}

#[test]
fn copied_dataset_is_complete_and_independent_of_source_inodes() {
    let source = private();
    fixture(source.path());
    fs::hard_link(
        source.path().join("bin/rustc"),
        source.path().join("bin/rustc-alias"),
    )
    .unwrap();
    let parent = private();
    let expected =
        fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false).unwrap();
    let retained = capture_toolchain(
        source.path(),
        &parent.path().join("retained"),
        Some(&expected),
        &ToolchainLimits::default(),
        || false,
    )
    .unwrap();
    assert_eq!(*retained.identity(), expected);
    assert_eq!(expected.files, 4);
    assert_eq!(
        fs::read(retained.root().join("through-directory-link")).unwrap(),
        b"fixture sysroot"
    );
    assert!(retained.root().join("empty").is_dir());
    assert_eq!(
        fs::read_link(retained.root().join("bin/runtime")).unwrap(),
        Path::new("../lib/runtime.so")
    );
    assert_eq!(
        fs::metadata(retained.root().join("bin/rustc"))
            .unwrap()
            .mode()
            & 0o777,
        0o555
    );
    assert_eq!(
        fs::metadata(retained.root().join("lib/runtime.so"))
            .unwrap()
            .mode()
            & 0o777,
        0o444
    );
    assert_ne!(
        fs::metadata(source.path().join("bin/rustc")).unwrap().ino(),
        fs::metadata(retained.root().join("bin/rustc"))
            .unwrap()
            .ino()
    );
    assert_ne!(
        fs::metadata(retained.root().join("bin/rustc"))
            .unwrap()
            .ino(),
        fs::metadata(retained.root().join("bin/rustc-alias"))
            .unwrap()
            .ino()
    );
    fs::write(source.path().join("bin/rustc"), b"mutated source compiler").unwrap();
    assert_eq!(
        fs::read(retained.root().join("bin/rustc")).unwrap(),
        b"fixture compiler bytes"
    );
    retained.verify(|| false).unwrap();
    assert_ne!(
        fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false).unwrap(),
        expected
    );
    assert_eq!(
        fingerprint_toolchain(retained.root(), &ToolchainLimits::default(), || false).unwrap(),
        expected
    );
}

#[test]
fn external_source_hardlinks_are_copied_without_sharing_mutable_storage() {
    let source = private();
    let other = private();
    write(source.path(), "compiler", b"original", 0o755);
    fs::hard_link(
        source.path().join("compiler"),
        other.path().join("outside-alias"),
    )
    .unwrap();
    let parent = private();
    let retained = capture_toolchain(
        source.path(),
        &parent.path().join("copy"),
        None,
        &ToolchainLimits::default(),
        || false,
    )
    .unwrap();
    fs::write(
        other.path().join("outside-alias"),
        b"changed through outside hardlink",
    )
    .unwrap();
    assert_eq!(
        fs::read(retained.root().join("compiler")).unwrap(),
        b"original"
    );
    assert_eq!(
        fs::metadata(retained.root().join("compiler"))
            .unwrap()
            .nlink(),
        1
    );
    retained.verify(|| false).unwrap();
}

#[test]
fn identity_changes_for_executable_content_links_and_empty_directories() {
    let root = private();
    write(root.path(), "compiler", b"abc", 0o644);
    let identity =
        || fingerprint_toolchain(root.path(), &ToolchainLimits::default(), || false).unwrap();
    let original = identity();
    fs::set_permissions(
        root.path().join("compiler"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let executable = identity();
    assert_ne!(original, executable);
    fs::write(root.path().join("compiler"), b"abd").unwrap();
    let changed = identity();
    assert_ne!(changed, executable);
    fs::create_dir(root.path().join("empty")).unwrap();
    let directory = identity();
    assert_ne!(changed, directory);
    symlink("compiler", root.path().join("alias")).unwrap();
    assert_ne!(identity(), directory);
    assert_eq!(identity().files, 1);
    assert_eq!(identity().bytes, 3);
}

#[test]
fn source_mutation_during_streaming_cannot_produce_an_owner() {
    let source = private();
    write(source.path(), "compiler", &vec![42; 512 * 1024], 0o755);
    let parent = private();
    let destination = parent.path().join("copy");
    let changed = Cell::new(false);
    let result = capture_toolchain(
        source.path(),
        &destination,
        None,
        &ToolchainLimits::default(),
        || {
            if !changed.get()
                && fs::metadata(destination.join("compiler"))
                    .is_ok_and(|metadata| metadata.len() >= 64 * 1024)
            {
                fs::write(source.path().join("compiler"), vec![43; 512 * 1024]).unwrap();
                changed.set(true);
            }
            false
        },
    );
    assert!(
        changed.get(),
        "mutation must occur during the actual streaming copy"
    );
    assert!(
        result.is_err(),
        "mixed source bytes must not become a prepared toolchain"
    );
}

#[test]
fn retained_content_namespace_and_inode_mutations_are_detected() {
    for change in 0..4 {
        let source = private();
        write(source.path(), "compiler", b"original", 0o755);
        let parent = private();
        let retained = capture_toolchain(
            source.path(),
            &parent.path().join("copy"),
            None,
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        match change {
            0 => {
                fs::set_permissions(
                    retained.root().join("compiler"),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
                fs::write(retained.root().join("compiler"), b"modified").unwrap();
            }
            1 => {
                fs::write(retained.root().join("added"), b"new").unwrap();
            }
            2 => {
                fs::rename(
                    retained.root().join("compiler"),
                    retained.root().join("old"),
                )
                .unwrap();
                write(retained.root(), "compiler", b"original", 0o555);
            }
            _ => {
                fs::rename(retained.root(), parent.path().join("previous-root")).unwrap();
                fs::create_dir(retained.root()).unwrap();
                write(retained.root(), "compiler", b"original", 0o555);
            }
        }
        assert!(
            retained.verify(|| false).is_err(),
            "mutation {change} was not rejected"
        );
    }
}

#[test]
fn symlink_escape_dangling_cycle_and_special_nodes_are_refused() {
    for target in [
        "../outside",
        "/etc/passwd",
        "missing",
        "alias",
        "compiler/child",
    ] {
        let source = private();
        write(source.path(), "compiler", b"bytes", 0o755);
        symlink(target, source.path().join("alias")).unwrap();
        assert!(
            fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false).is_err(),
            "{target}"
        );
    }
    let source = private();
    write(source.path(), "compiler", b"bytes", 0o755);
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        source.path().join("fifo"),
        rustix::fs::Mode::RUSR,
    )
    .unwrap();
    assert!(fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false).is_err());
}

#[test]
fn bounds_wrong_identity_cancellation_and_destination_ownership_are_enforced() {
    let source = private();
    write(source.path(), "bin/compiler", b"12345678", 0o755);
    let limits = ToolchainLimits {
        max_bytes: 8,
        max_entries: 3,
        max_depth: 2,
    };
    let identity = fingerprint_toolchain(source.path(), &limits, || false).unwrap();
    for rejected in [
        ToolchainLimits {
            max_bytes: 7,
            ..limits
        },
        ToolchainLimits {
            max_entries: 2,
            ..limits
        },
        ToolchainLimits {
            max_depth: 1,
            ..limits
        },
    ] {
        assert!(fingerprint_toolchain(source.path(), &rejected, || false).is_err());
    }
    assert_eq!(
        fingerprint_toolchain(source.path(), &limits, || true)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    let parent = private();
    let mut wrong = identity;
    wrong.sha256[0] ^= 1;
    assert!(
        capture_toolchain(
            source.path(),
            &parent.path().join("wrong"),
            Some(&wrong),
            &limits,
            || false
        )
        .is_err()
    );
    assert!(capture_toolchain(source.path(), source.path(), None, &limits, || false).is_err());
    assert!(
        capture_toolchain(
            source.path(),
            &source.path().join("nested"),
            None,
            &limits,
            || false
        )
        .is_err()
    );
    fs::create_dir(parent.path().join("exists")).unwrap();
    fs::write(parent.path().join("exists/keep"), b"keep").unwrap();
    assert!(
        capture_toolchain(
            source.path(),
            &parent.path().join("exists"),
            None,
            &limits,
            || false
        )
        .is_err()
    );
    assert_eq!(
        fs::read(parent.path().join("exists/keep")).unwrap(),
        b"keep"
    );
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        capture_toolchain(
            source.path(),
            &parent.path().join("public"),
            None,
            &limits,
            || false
        )
        .is_err()
    );
    symlink(source.path(), parent.path().join("alias")).unwrap();
    assert!(fingerprint_toolchain(&parent.path().join("alias"), &limits, || false).is_err());
}

#[test]
fn empty_dataset_is_valid_without_claiming_a_compiler_exists() {
    let source = private();
    let identity =
        fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false).unwrap();
    assert_eq!(identity.files, 0);
    assert_eq!(identity.bytes, 0);
    let parent = private();
    let owner = capture_toolchain(
        source.path(),
        &parent.path().join("empty"),
        Some(&identity),
        &ToolchainLimits::default(),
        || false,
    )
    .unwrap();
    owner.verify(|| false).unwrap();
}

struct OwnedProcess {
    child: Child,
    reaped: bool,
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", self.child.id())])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn run(command: &mut Command, root: &Path) -> (ExitStatus, Vec<u8>, Vec<u8>) {
    let logs = tempfile::tempdir_in(root).unwrap();
    let stdout = logs.path().join("out");
    let stderr = logs.path().join("err");
    let mut owned = OwnedProcess {
        child: command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .unwrap(),
        reaped: false,
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = owned.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "real compiler probe timed out");
        assert!(
            fs::metadata(&stdout).unwrap().len() <= 1024 * 1024
                && fs::metadata(&stderr).unwrap().len() <= 1024 * 1024
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    owned.reaped = true;
    let read = |path: &Path| {
        let mut bytes = Vec::new();
        File::open(path)
            .unwrap()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= 1024 * 1024);
        bytes
    };
    (status, read(&stdout), read(&stderr))
}

#[test]
#[ignore = "copies an installed Rust toolchain; run explicitly with RABS_TEST_TOOLCHAIN_ROOT"]
fn installed_rustc_executes_and_compiles_from_retained_toolchain() {
    let root = std::env::var_os("RABS_TEST_TOOLCHAIN_ROOT")
        .expect("set RABS_TEST_TOOLCHAIN_ROOT to an actual installed Rust toolchain");
    let parent = private();
    let retained = capture_toolchain(
        Path::new(&root),
        &parent.path().join("toolchain"),
        None,
        &ToolchainLimits::default(),
        || false,
    )
    .unwrap();
    let compiler = retained.root().join("bin/rustc");
    let (status, output, error) = run(
        Command::new(&compiler).args(["--print", "sysroot"]),
        parent.path(),
    );
    assert!(status.success(), "{}", String::from_utf8_lossy(&error));
    assert_eq!(
        Path::new(String::from_utf8(output).unwrap().trim()),
        retained.root()
    );
    let source = parent.path().join("fixture.rs");
    fs::write(
        &source,
        "pub fn captured_toolchain_value() -> usize { 42 }\n",
    )
    .unwrap();
    let output = parent.path().join("fixture.rmeta");
    let (status, _, error) = run(
        Command::new(compiler)
            .arg(&source)
            .args(["--crate-type=lib", "--emit=metadata"])
            .arg("-o")
            .arg(&output),
        parent.path(),
    );
    assert!(status.success(), "{}", String::from_utf8_lossy(&error));
    assert!(fs::metadata(output).unwrap().len() > 0);
    retained.verify(|| false).unwrap();
}
