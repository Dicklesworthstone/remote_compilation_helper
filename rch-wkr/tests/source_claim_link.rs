//! Exercise cancellation evidence links through the actual native worker CLI.

#![cfg(unix)]

use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

struct Fixture {
    directory: tempfile::TempDir,
    registry: PathBuf,
    source: PathBuf,
    destination: PathBuf,
    digest: String,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new(route: usize, bytes: Vec<u8>) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("source-claim-link-cli-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        fs::write(directory.path().join("blocked-log"), b"keep").unwrap();
        let registry = directory.path().join("registry ' ; café");
        fs::create_dir_all(registry.join("cancelled")).unwrap();
        for path in [&registry, &registry.join("cancelled")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let digest = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let claim = registry.join(format!("b1.{digest}.claim"));
        let fence = registry.join(format!("b1.{digest}.cancelling"));
        let receipt = registry.join("cancelled").join(claim.file_name().unwrap());
        let (source, destination) = match route {
            0 => (claim, fence),
            1 => (receipt, fence),
            2 => (fence, receipt),
            _ => unreachable!(),
        };
        fs::write(&source, &bytes).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            directory,
            registry,
            source,
            destination,
            digest,
            bytes,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rch-wkr"));
        command
            .arg("source-claim-link")
            .env_clear()
            .env("PATH", "")
            .env("TOKIO_WORKER_THREADS", "0")
            .env(
                "RCH_LOG_FILE",
                self.directory.path().join("blocked-log/worker.log"),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn link(&self, input: &[u8]) -> Output {
        let mut child = self
            .command()
            .arg("link")
            .arg(&self.registry)
            .arg(&self.source)
            .arg(&self.destination)
            .args(["b1", &self.digest])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        if let Err(error) = child.stdin.take().unwrap().write_all(input) {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        child.wait_with_output().unwrap()
    }
}

fn refused(output: &Output) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        output.stderr.starts_with(b"RCH_SOURCE_CLAIM_LINK_FAILED "),
        "{output:?}"
    );
}

#[test]
fn probe_and_argument_refusals_need_no_runtime_logging_or_host_utilities() {
    let fixture = Fixture::new(0, b"/work/project\n".to_vec());
    let output = fixture
        .command()
        .arg("probe")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"rch-wkr source-claim-link v1\n");
    assert!(output.stderr.is_empty());
    refused(
        &fixture
            .command()
            .args(["probe", "extra"])
            .stdin(Stdio::null())
            .output()
            .unwrap(),
    );
    refused(
        &fixture
            .command()
            .arg("link")
            .stdin(Stdio::null())
            .output()
            .unwrap(),
    );
    assert!(!fixture.destination.exists());
    assert_eq!(fs::read(&fixture.source).unwrap(), fixture.bytes);
}

#[test]
fn all_three_routes_link_exact_multibuffer_bytes_without_allocating_a_new_record() {
    let bytes = (0..10_000)
        .map(|index| format!("/work/source-{index}\n"))
        .collect::<String>()
        .into_bytes();
    for route in 0..3 {
        let fixture = Fixture::new(route, bytes.clone());
        let before = fs::metadata(&fixture.source).unwrap();
        let output = fixture.link(&fixture.bytes);
        assert!(output.status.success(), "{output:?}");
        assert!(
            output.stdout.is_empty() && output.stderr.is_empty(),
            "{output:?}"
        );
        let source = fs::metadata(&fixture.source).unwrap();
        let destination = fs::metadata(&fixture.destination).unwrap();
        assert_eq!((source.dev(), source.ino()), (before.dev(), before.ino()));
        assert_eq!(
            (source.dev(), source.ino()),
            (destination.dev(), destination.ino())
        );
        assert_eq!(source.nlink(), before.nlink() + 1);
        assert_eq!(fs::read(&fixture.destination).unwrap(), fixture.bytes);
        refused(&fixture.link(&fixture.bytes));
        assert_eq!(
            fs::metadata(&fixture.source).unwrap().nlink(),
            source.nlink()
        );
    }
}

#[test]
fn invalid_records_and_appeared_destinations_remain_unconfirmed_and_untouched() {
    for scenario in [
        "closure",
        "corrupt",
        "source-link",
        "writable",
        "target-file",
        "target-link",
        "target-directory",
    ] {
        let fixture = Fixture::new(2, b"/work/project\n".to_vec());
        match scenario {
            "corrupt" => fs::write(&fixture.source, b"/changed/root\n").unwrap(),
            "source-link" => {
                let retained = fixture.registry.join("original");
                fs::rename(&fixture.source, &retained).unwrap();
                symlink(retained, &fixture.source).unwrap();
            }
            "writable" => {
                fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o620)).unwrap()
            }
            "target-file" => fs::write(&fixture.destination, b"keep existing").unwrap(),
            "target-link" => symlink("keep-target", &fixture.destination).unwrap(),
            "target-directory" => fs::create_dir(&fixture.destination).unwrap(),
            _ => {}
        }
        let before = fs::read(&fixture.source).unwrap();
        let input = if scenario == "closure" {
            b"/different/input\n".as_slice()
        } else {
            fixture.bytes.as_slice()
        };
        refused(&fixture.link(input));
        assert_eq!(fs::read(&fixture.source).unwrap(), before);
        match scenario {
            "target-file" => assert_eq!(fs::read(&fixture.destination).unwrap(), b"keep existing"),
            "target-link" => assert_eq!(
                fs::read_link(&fixture.destination).unwrap(),
                PathBuf::from("keep-target")
            ),
            "target-directory" => {
                assert!(fs::read_dir(&fixture.destination).unwrap().next().is_none())
            }
            _ => assert!(fs::symlink_metadata(&fixture.destination).is_err()),
        }
    }
}
