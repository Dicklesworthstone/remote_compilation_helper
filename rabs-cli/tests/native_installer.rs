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
        let temporary = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
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
fn unsupported_options_are_explicit_refusals_without_mutation() {
    let fixture = Fixture::new();
    let output = fixture
        .native()
        .arg("--from-build")
        .arg(&fixture.build)
        .arg("--bin-dir")
        .arg(&fixture.root)
        .args(["--unsupported-flag", "value"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!fixture.root.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported installer option"));
}

#[test]
fn native_cli_packages_archive_then_installs_probes_and_verifies_end_to_end() {
    let fixture = Fixture::new();
    let archive = fixture.temporary.path().join("rabs-packaged.tar.gz");
    let target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        other => panic!("unsupported arch: {other}"),
    };
    let packaged = fixture
        .native()
        .arg("--from-build")
        .arg(&fixture.build)
        .arg("--package")
        .arg(&archive)
        .arg("--target")
        .arg(target)
        .output()
        .unwrap();
    success(&packaged);
    let receipt: Value = serde_json::from_slice(&packaged.stdout).unwrap();
    assert_eq!(receipt["kind"], "rabs-packaged");
    assert_eq!(receipt["target"], target);
    assert_eq!(receipt["bytes"], fs::metadata(&archive).unwrap().len());
    assert_eq!(receipt["services_started"], false);
    assert_eq!(receipt["cargo_config_changed"], false);

    // Refuses to clobber the archive on repeat invocation.
    let clobber = fixture
        .native()
        .arg("--from-build")
        .arg(&fixture.build)
        .arg("--package")
        .arg(&archive)
        .arg("--target")
        .arg(target)
        .output()
        .unwrap();
    assert!(!clobber.status.success());
    assert!(
        String::from_utf8_lossy(&clobber.stderr)
            .contains("refusing to replace an existing archive")
    );

    // Install and verify straight from the freshly packaged native archive.
    let installed = fixture
        .native()
        .arg("--from-archive")
        .arg(&archive)
        .arg("--bin-dir")
        .arg(&fixture.root)
        .arg("--probe")
        .output()
        .unwrap();
    success(&installed);
    let inst_receipt: Value = serde_json::from_slice(&installed.stdout).unwrap();
    assert_eq!(inst_receipt["kind"], "rabs-installed");

    let verified = fixture
        .native()
        .arg("--from-archive")
        .arg(&archive)
        .arg("--bin-dir")
        .arg(&fixture.root)
        .arg("--verify")
        .output()
        .unwrap();
    success(&verified);
    let ver_receipt: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(ver_receipt["state"], "verified");
}

fn host_target_triple() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        other => panic!("unsupported arch: {other}"),
    }
}

fn other_target_triple() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "aarch64-unknown-linux-gnu",
        "aarch64" => "x86_64-unknown-linux-gnu",
        other => panic!("unsupported arch: {other}"),
    }
}

fn other_uname_machine() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "aarch64",
        "aarch64" => "x86_64",
        other => panic!("unsupported arch: {other}"),
    }
}

fn install_fake_ssh(fixture: &Fixture) -> (PathBuf, PathBuf, PathBuf) {
    let ssh_dir = fixture.temporary.path().join("fake-ssh-bin");
    let hosts_root = fixture.temporary.path().join("fake-ssh-hosts");
    let log_file = fixture.temporary.path().join("fake-ssh.log");
    fs::create_dir_all(&ssh_dir).unwrap();
    fs::create_dir_all(&hosts_root).unwrap();
    let ssh_script = ssh_dir.join("ssh");
    fs::write(
        &ssh_script,
        r#"#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--" ]; then
        shift
        break
    fi
    shift
done
host="$1"
script="$2"
if [ -n "${FAKE_SSH_LOG:-}" ]; then
    printf '%s\n' "$host" >> "$FAKE_SSH_LOG"
fi
host_dir="$FAKE_SSH_HOSTS/$host"
host_home="$host_dir/home"
host_tmp="$host_dir/tmp"
mkdir -p -m 700 "$host_home" "$host_tmp"
path_prefix=""
if [ -d "$host_dir/shim" ]; then
    path_prefix="$host_dir/shim:"
fi
exec env HOME="$host_home" TMPDIR="$host_tmp" PATH="${path_prefix}/usr/bin:/bin" /bin/sh -c "$script"
"#,
    )
    .unwrap();
    fs::set_permissions(&ssh_script, fs::Permissions::from_mode(0o755)).unwrap();
    (ssh_dir, hosts_root, log_file)
}

#[test]
fn native_cli_ssh_deploys_probes_retains_image_and_verifies_lost_ack_end_to_end() {
    let fixture = Fixture::new();
    let (ssh_dir, hosts_root, log_file) = install_fake_ssh(&fixture);
    let host_bin = hosts_root.join("host-a/custom-bin");
    let ssh_path = format!(
        "{}:{}",
        ssh_dir.display(),
        fixture.native_only_path.display()
    );

    let deployed = Command::new(env!("CARGO_BIN_EXE_rabs-install"))
        .env("PATH", &ssh_path)
        .env("HOME", fixture.temporary.path())
        .env("TMPDIR", fixture.temporary.path())
        .env("FAKE_SSH_HOSTS", &hosts_root)
        .env("FAKE_SSH_LOG", &log_file)
        .arg("--from-build")
        .arg(&fixture.build)
        .arg("--bin-dir")
        .arg(&host_bin)
        .arg("--probe")
        .args(["--ssh", "host-a", "--ssh-reserve-mib", "64"])
        .output()
        .unwrap();
    success(&deployed);
    let receipt: Value = serde_json::from_slice(&deployed.stdout).unwrap();
    assert_eq!(receipt["kind"], "rabs-deployed");
    assert_eq!(receipt["services_started"], false);
    assert_eq!(receipt["cargo_config_changed"], false);
    assert_eq!(receipt["workers"].as_array().unwrap().len(), 1);
    assert_eq!(receipt["workers"][0]["host"], "host-a");
    assert_eq!(receipt["workers"][0]["state"], "installed");
    assert_eq!(
        receipt["workers"][0]["receipt"]["bin_dir"],
        host_bin.to_str().unwrap()
    );

    // Retained transfer image exists at mode 0400 inside a private 0700 dir.
    let image_path = PathBuf::from(receipt["transfer_image"].as_str().unwrap());
    assert_eq!(fs::metadata(&image_path).unwrap().mode() & 0o777, 0o400);
    assert_eq!(
        fs::metadata(image_path.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );

    // Capture manifest inode/timestamps to prove --verify is strictly read-only.
    let manifest_path = host_bin
        .join(fs::read_link(host_bin.join(".rabs-current")).unwrap())
        .join("manifest.json");
    let before_manifest = fs::metadata(&manifest_path).unwrap();

    // Lost-ACK recovery over SSH using --from-image --verify WITHOUT re-passing --bin-dir.
    let verified_ssh = Command::new(env!("CARGO_BIN_EXE_rabs-install"))
        .env("PATH", &ssh_path)
        .env("HOME", fixture.temporary.path())
        .env("FAKE_SSH_HOSTS", &hosts_root)
        .arg("--from-image")
        .arg(&image_path)
        .arg("--verify")
        .args(["--ssh", "host-a"])
        .output()
        .unwrap();
    success(&verified_ssh);
    let ver_receipt: Value = serde_json::from_slice(&verified_ssh.stdout).unwrap();
    assert_eq!(ver_receipt["kind"], "rabs-verified");
    assert_eq!(ver_receipt["installation_changed"], false);
    assert_eq!(ver_receipt["workers"][0]["state"], "verified");
    let after_manifest = fs::metadata(&manifest_path).unwrap();
    assert_eq!(
        (
            before_manifest.ino(),
            before_manifest.mtime_nsec(),
            before_manifest.ctime_nsec()
        ),
        (
            after_manifest.ino(),
            after_manifest.mtime_nsec(),
            after_manifest.ctime_nsec()
        )
    );

    // Local lost-ACK verification against the same retained transfer image also succeeds.
    let verified_local = fixture
        .native()
        .arg("--from-image")
        .arg(&image_path)
        .arg("--verify")
        .output()
        .unwrap();
    success(&verified_local);
    let local_receipt: Value = serde_json::from_slice(&verified_local.stdout).unwrap();
    assert_eq!(local_receipt["state"], "verified");
    assert_eq!(local_receipt["installation_changed"], false);

    // Disagreeing --bin-dir with --from-image refuses BEFORE contacting any SSH host.
    let unused_log = fixture.temporary.path().join("must-not-touch.log");
    let bad_dir = Command::new(env!("CARGO_BIN_EXE_rabs-install"))
        .env("PATH", &ssh_path)
        .env("HOME", fixture.temporary.path())
        .env("FAKE_SSH_HOSTS", &hosts_root)
        .env("FAKE_SSH_LOG", &unused_log)
        .arg("--from-image")
        .arg(&image_path)
        .arg("--verify")
        .args(["--bin-dir", "/tmp/different-bin-dir", "--ssh", "host-a"])
        .output()
        .unwrap();
    assert!(!bad_dir.status.success());
    assert!(!unused_log.exists());
    assert!(
        String::from_utf8_lossy(&bad_dir.stderr)
            .contains("--bin-dir disagrees with retained transfer image")
    );

    // Corrupt an installed executable -> --from-image --verify --ssh reports unverified.
    let rabsd_path = host_bin
        .join(fs::read_link(host_bin.join(".rabs-current")).unwrap())
        .join("rabsd");
    fs::set_permissions(&rabsd_path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&rabsd_path, b"corrupted").unwrap();
    fs::set_permissions(&rabsd_path, fs::Permissions::from_mode(0o555)).unwrap();
    let tampered = Command::new(env!("CARGO_BIN_EXE_rabs-install"))
        .env("PATH", &ssh_path)
        .env("HOME", fixture.temporary.path())
        .env("FAKE_SSH_HOSTS", &hosts_root)
        .arg("--from-image")
        .arg(&image_path)
        .arg("--verify")
        .args(["--ssh", "host-a"])
        .output()
        .unwrap();
    assert!(!tampered.status.success());
    let tampered_receipt: Value = serde_json::from_slice(&tampered.stdout).unwrap();
    assert_eq!(tampered_receipt["workers"][0]["state"], "unverified");
    assert_eq!(tampered_receipt["installation_changed"], false);
}

#[test]
fn native_cli_ssh_from_target_deploys_parallel_workers_and_refuses_bad_arch_before_ssh() {
    let fixture = Fixture::new();
    let (ssh_dir, hosts_root, _) = install_fake_ssh(&fixture);
    let ssh_path = format!(
        "{}:{}",
        ssh_dir.display(),
        fixture.native_only_path.display()
    );
    let host_archive = fixture.temporary.path().join("host-target.tar.gz");
    let pkg = fixture
        .native()
        .arg("--from-build")
        .arg(&fixture.build)
        .arg("--package")
        .arg(&host_archive)
        .arg("--target")
        .arg(host_target_triple())
        .output()
        .unwrap();
    success(&pkg);

    // Wrong declared target for an archive must fail BEFORE invoking ssh.
    let preflight_log = fixture.temporary.path().join("preflight-ssh.log");
    let mismatch = Command::new(env!("CARGO_BIN_EXE_rabs-install"))
        .env("PATH", &ssh_path)
        .env("HOME", fixture.temporary.path())
        .env("FAKE_SSH_HOSTS", &hosts_root)
        .env("FAKE_SSH_LOG", &preflight_log)
        .arg("--from-target")
        .arg(format!(
            "{}={}",
            other_target_triple(),
            host_archive.display()
        ))
        .args(["--ssh", "host-1", "--ssh-reserve-mib", "64"])
        .output()
        .unwrap();
    assert!(!mismatch.status.success());
    assert!(!preflight_log.exists());

    // Simulate host-other reporting the opposite Linux architecture via a uname shim.
    let shim_dir = hosts_root.join("host-other/shim");
    fs::create_dir_all(&shim_dir).unwrap();
    let uname_shim = shim_dir.join("uname");
    fs::write(
        &uname_shim,
        format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = \"-m\" ]; then printf '%s\\n' '{}'; else exec /usr/bin/uname \"$@\"; fi\n",
            other_uname_machine()
        ),
    )
    .unwrap();
    fs::set_permissions(&uname_shim, fs::Permissions::from_mode(0o755)).unwrap();

    // Deploy in parallel to two matching hosts + one mismatched-arch host.
    let fleet = Command::new(env!("CARGO_BIN_EXE_rabs-install"))
        .env("PATH", &ssh_path)
        .env("HOME", fixture.temporary.path())
        .env("TMPDIR", fixture.temporary.path())
        .env("FAKE_SSH_HOSTS", &hosts_root)
        .arg("--from-target")
        .arg(format!(
            "{}={}",
            host_target_triple(),
            host_archive.display()
        ))
        .args([
            "--ssh",
            "host-1",
            "--ssh",
            "host-2",
            "--ssh",
            "host-other",
            "--ssh-jobs",
            "2",
            "--ssh-reserve-mib",
            "64",
        ])
        .output()
        .unwrap();
    // Overall exit fails because host-other had no supplied archive, while host-1 & host-2 succeed!
    assert!(!fleet.status.success());
    let receipt: Value = serde_json::from_slice(&fleet.stdout).unwrap();
    assert_eq!(receipt["kind"], "rabs-deployed");
    let workers = receipt["workers"].as_array().unwrap();
    assert_eq!(workers.len(), 3);
    assert_eq!(workers[0]["host"], "host-1");
    assert_eq!(workers[0]["state"], "installed");
    assert_eq!(workers[1]["host"], "host-2");
    assert_eq!(workers[1]["state"], "installed");
    assert_eq!(workers[2]["host"], "host-other");
    assert_eq!(workers[2]["state"], "failed");
    assert!(
        workers[2]["error"]
            .as_str()
            .unwrap()
            .contains("no authenticated archive supplied")
    );
    // Verify both successful workers in parallel from the retained transfer image.
    let retained = PathBuf::from(
        receipt["transfer_images"][host_target_triple()]
            .as_str()
            .unwrap(),
    );
    let verified = Command::new(env!("CARGO_BIN_EXE_rabs-install"))
        .env("PATH", &ssh_path)
        .env("HOME", fixture.temporary.path())
        .env("FAKE_SSH_HOSTS", &hosts_root)
        .arg("--from-image")
        .arg(&retained)
        .arg("--verify")
        .args(["--ssh", "host-1", "--ssh", "host-2", "--ssh-jobs", "2"])
        .output()
        .unwrap();
    success(&verified);
    let ver: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(ver["workers"][0]["state"], "verified");
    assert_eq!(ver["workers"][1]["state"], "verified");
}

#[test]
fn check_release_assets_validates_unwind_wrappers_and_rejects_abort_or_wrong_arch() {
    let fixture = Fixture::new();
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("scripts/check_release_assets.sh");

    // Populate all 9 tools with the real panic=unwind native rabs-install binary
    // and package it through native rabs-install --package.
    let unwind_bundle = fixture.temporary.path().join("unwind-bundle");
    fs::create_dir(&unwind_bundle).unwrap();
    for name in TOOLS {
        let dest = unwind_bundle.join(name);
        fs::copy(env!("CARGO_BIN_EXE_rabs-install"), &dest).unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let valid_archive = fixture.temporary.path().join("valid-rabs.tar.gz");
    let pkg = fixture
        .native()
        .arg("--from-bundle")
        .arg(&unwind_bundle)
        .arg("--package")
        .arg(&valid_archive)
        .arg("--target")
        .arg(host_target_triple())
        .output()
        .unwrap();
    success(&pkg);

    // Complete unwind archive passes full check (including A021 unwind verification).
    let ok = Command::new("bash")
        .arg(&script)
        .arg("--check-rabs-archive")
        .arg(&valid_archive)
        .arg("--target")
        .arg(host_target_triple())
        .output()
        .unwrap();
    success(&ok);

    // Wrong declared target must fail closed.
    let wrong_arch = Command::new("bash")
        .arg(&script)
        .arg("--check-rabs-archive")
        .arg(&valid_archive)
        .arg("--target")
        .arg(other_target_triple())
        .output()
        .unwrap();
    assert!(!wrong_arch.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_arch.stderr).contains("ELF machine mismatch"),
        "stderr: {}",
        String::from_utf8_lossy(&wrong_arch.stderr)
    );

    // Replace rabs-wrap with /usr/bin/true (no unwind symbols, matching panic=abort)
    // and verify the release gate refuses it.
    let abort_archive = fixture.temporary.path().join("abort-rabs.tar.gz");
    fs::write(unwind_bundle.join("rabs-wrap"), &fixture.bytes).unwrap();
    fs::set_permissions(
        unwind_bundle.join("rabs-wrap"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let pkg_abort = fixture
        .native()
        .arg("--from-bundle")
        .arg(&unwind_bundle)
        .arg("--package")
        .arg(&abort_archive)
        .arg("--target")
        .arg(host_target_triple())
        .output()
        .unwrap();
    success(&pkg_abort);
    let abort_check = Command::new("bash")
        .arg(&script)
        .arg("--check-rabs-archive")
        .arg(&abort_archive)
        .arg("--target")
        .arg(host_target_triple())
        .output()
        .unwrap();
    assert!(!abort_check.status.success());
    assert!(
        String::from_utf8_lossy(&abort_check.stderr).contains("lacks panic=unwind symbols"),
        "stderr: {}",
        String::from_utf8_lossy(&abort_check.stderr)
    );
}
