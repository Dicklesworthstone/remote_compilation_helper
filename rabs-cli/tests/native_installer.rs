#![cfg(all(target_os = "linux", feature = "installer"))]

//! Real native CLI and live shell source-install integration. The tool fixtures
//! are host ELF executables; PATH contains only native true and lock-cleanup rm.

use flate2::{Compression, write::GzEncoder};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TOOLS: [&str; 9] = [
    "cargo-rabs",
    "rabs-wrap",
    "rabsd",
    "rabs-wkr",
    "rabs-cargo-root",
    "rabs-delivery-cas",
    "rabs-recover",
    "rabs-cargo",
    "rabs-install",
];

struct Fixture {
    temporary: tempfile::TempDir,
    build: PathBuf,
    root: PathBuf,
    native_only_path: PathBuf,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let build = temporary.path().join("target");
        let root = temporary.path().join("bin");
        let native_only_path = temporary.path().join("native-path");
        fs::create_dir(&native_only_path).unwrap();
        let true_program = ["/usr/bin/true", "/bin/true"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .unwrap();
        symlink(&true_program, native_only_path.join("true")).unwrap();
        let remove_program = ["/usr/bin/rm", "/bin/rm"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .unwrap();
        symlink(remove_program, native_only_path.join("rm")).unwrap();
        let bytes = fs::read(true_program).unwrap();
        for name in TOOLS {
            let path = Self::tool(&build, name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            if name == "rabs-install" {
                fs::copy(env!("CARGO_BIN_EXE_rabs-install"), &path).unwrap();
            } else {
                fs::write(&path, &bytes).unwrap();
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir(temporary.path().join(".cargo")).unwrap();
        fs::write(
            temporary.path().join(".cargo/config.toml"),
            b"# existing user configuration\n",
        )
        .unwrap();
        Self {
            temporary,
            build,
            root,
            native_only_path,
            bytes,
        }
    }

    fn tool(build: &Path, name: &str) -> PathBuf {
        build
            .join(
                if matches!(
                    name,
                    "cargo-rabs" | "rabs-cargo" | "rabs-recover" | "rabs-wrap" | "rabs-install"
                ) {
                    "wrapper-release"
                } else {
                    "daemon-release"
                },
            )
            .join(name)
    }

    fn native(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabs-install"));
        command
            .env("PATH", &self.native_only_path)
            .env("HOME", self.temporary.path());
        command
    }

    fn archive(&self) -> PathBuf {
        let path = self.temporary.path().join("native-release.tar.gz");
        let encoder = GzEncoder::new(fs::File::create(&path).unwrap(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for name in TOOLS {
            archive
                .append_path_with_name(Self::tool(&self.build, name), name)
                .unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
        path
    }

    fn shell(&self, program: &str) -> Command {
        let mut command = Command::new("/bin/bash");
        command
            .arg("-c")
            .arg(program)
            .arg("native-install-test")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join("install.sh"),
            )
            .arg(env!("CARGO_BIN_EXE_rabs-install"))
            .arg(&self.build)
            .arg(&self.root)
            .arg(self.temporary.path().join("unexpected-command"))
            .env("RCH_INSTALLER_LIB", "1")
            .env("RCH_INSTALL_DIR", &self.root)
            .env("PATH", &self.native_only_path)
            .env("HOME", self.temporary.path());
        command
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn live_source_install_and_final_checks_use_the_native_helper_with_minimal_path() {
    let fixture = Fixture::new();
    let output = fixture
        .shell(
            r#"
        source "$1"
        WITH_RABS=true
        FROM_SOURCE=true
        LOCK_FILE="$5.lock"
        unexpected="$5"
        command_not_found_handle() { printf '%s\n' "$*" > "$unexpected"; return 127; }
        install_rabs_toolset "$2" --from-build "$3"
        [[ "$RABS_NATIVE_INSTALLER" == "$2" ]]
        check_rabs_launchers "" --installed "$4"
    "#,
        )
        .output()
        .unwrap();
    success(&output);
    let receipts: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0]["kind"], "rabs-installed");
    assert_eq!(receipts[1]["kind"], "rabs-launch-check");
    assert!(!fixture.temporary.path().join("unexpected-command").exists());
    assert_eq!(
        fs::read(fixture.temporary.path().join(".cargo/config.toml")).unwrap(),
        b"# existing user configuration\n"
    );
    for name in TOOLS {
        assert_eq!(
            fs::read(fixture.root.join(name)).unwrap(),
            fs::read(Fixture::tool(&fixture.build, name)).unwrap()
        );
    }
}

#[test]
fn live_archive_install_and_standalone_final_probe_use_the_native_generation() {
    let fixture = Fixture::new();
    let archive = fixture.archive();
    let output = fixture
        .shell(
            r#"
        source "$1"
        WITH_RABS=true
        FROM_SOURCE=false
        LOCK_FILE="$5.lock"
        unexpected="$5"
        command_not_found_handle() { printf '%s\n' "$*" > "$unexpected"; return 127; }
        install_rabs_toolset "$2" --from-archive "$6"
        [[ "$RABS_NATIVE_INSTALLER" == "$2" ]]
        unset RABS_NATIVE_INSTALLER
        check_rabs_launchers "" --installed "$4"
        "#,
        )
        .arg(&archive)
        .output()
        .unwrap();
    success(&output);
    let receipts: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0]["kind"], "rabs-installed");
    assert_eq!(receipts[1]["kind"], "rabs-launch-check");
    assert_eq!(receipts[0]["generation"], receipts[1]["generation"]);
    assert_eq!(receipts[0]["files"].as_object().unwrap().len(), 9);
    assert!(!fixture.temporary.path().join("unexpected-command").exists());
    assert_eq!(
        fs::read_link(fixture.root.join("rabs-install")).unwrap(),
        Path::new(".rabs-current/rabs-install")
    );
    assert_eq!(
        fs::read(fixture.temporary.path().join(".cargo/config.toml")).unwrap(),
        b"# existing user configuration\n"
    );
}

#[test]
fn archive_launch_failure_preserves_the_active_generation() {
    let fixture = Fixture::new();
    let output = fixture
        .native()
        .arg("--from-build")
        .arg(&fixture.build)
        .arg("--bin-dir")
        .arg(&fixture.root)
        .arg("--probe")
        .output()
        .unwrap();
    success(&output);
    let previous = fs::read_link(fixture.root.join(".rabs-current")).unwrap();
    fs::write(Fixture::tool(&fixture.build, "rabsd"), &fixture.bytes[..64]).unwrap();
    let archive = fixture.archive();
    let output = fixture
        .shell(
            r#"
        source "$1"
        WITH_RABS=true
        FROM_SOURCE=false
        LOCK_FILE="$5.lock"
        unexpected="$5"
        command_not_found_handle() { printf '%s\n' "$*" > "$unexpected"; return 127; }
        install_rabs_toolset "$2" --from-archive "$6"
        "#,
        )
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read_link(fixture.root.join(".rabs-current")).unwrap(),
        previous
    );
    assert!(!fixture.temporary.path().join("unexpected-command").exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("launch check failed"));
}

#[test]
fn source_helper_launch_failure_preserves_generation_without_legacy_fallback() {
    let fixture = Fixture::new();
    success(
        &fixture
            .native()
            .arg("--from-build")
            .arg(&fixture.build)
            .arg("--bin-dir")
            .arg(&fixture.root)
            .arg("--probe")
            .output()
            .unwrap(),
    );
    let previous = fs::read_link(fixture.root.join(".rabs-current")).unwrap();
    fs::write(Fixture::tool(&fixture.build, "rabsd"), &fixture.bytes[..64]).unwrap();
    let output = fixture
        .shell(
            r#"
        source "$1"
        WITH_RABS=true
        FROM_SOURCE=true
        LOCK_FILE="$5.lock"
        unexpected="$5"
        command_not_found_handle() { printf '%s\n' "$*" > "$unexpected"; return 127; }
        install_rabs_toolset "$2" --from-build "$3"
    "#,
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read_link(fixture.root.join(".rabs-current")).unwrap(),
        previous
    );
    assert!(!fixture.temporary.path().join("unexpected-command").exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("launch check failed"));
}

#[test]
fn native_cli_verifies_exact_bytes_and_creates_private_manifest_under_umask_002() {
    let fixture = Fixture::new();
    let output = fixture
        .shell(
            r#"
        umask 002
        exec "$2" --from-build "$3" --bin-dir "$4" --probe
    "#,
        )
        .output()
        .unwrap();
    success(&output);
    let installed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(installed["kind"], "rabs-installed");
    let manifest = fixture
        .root
        .join(fs::read_link(fixture.root.join(".rabs-current")).unwrap())
        .join("manifest.json");
    assert_eq!(fs::metadata(&manifest).unwrap().mode() & 0o777, 0o600);
    let before = fs::metadata(&manifest).unwrap();
    let output = fixture
        .native()
        .arg("--from-build")
        .arg(&fixture.build)
        .arg("--bin-dir")
        .arg(&fixture.root)
        .arg("--verify")
        .output()
        .unwrap();
    success(&output);
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["state"], "verified");
    assert_eq!(receipt["installation_changed"], false);
    let after = fs::metadata(&manifest).unwrap();
    assert_eq!(
        (before.ino(), before.mtime_nsec(), before.ctime_nsec()),
        (after.ino(), after.mtime_nsec(), after.ctime_nsec())
    );

    fs::write(
        Fixture::tool(&fixture.build, "rabsd"),
        [fixture.bytes.as_slice(), b"another release"].concat(),
    )
    .unwrap();
    let output = fixture
        .native()
        .arg("--from-build")
        .arg(&fixture.build)
        .arg("--bin-dir")
        .arg(&fixture.root)
        .arg("--verify")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["state"], "unverified");
    assert_eq!(receipt["installation_changed"], false);
}

#[test]
fn unsupported_fleet_operations_are_explicit_refusals_without_mutation() {
    let fixture = Fixture::new();
    let output = fixture
        .native()
        .arg("--from-build")
        .arg(&fixture.build)
        .arg("--bin-dir")
        .arg(&fixture.root)
        .args(["--ssh", "worker"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!fixture.root.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported local installer option"));
}
