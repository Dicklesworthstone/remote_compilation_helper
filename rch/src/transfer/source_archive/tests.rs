use super::*;
use crate::transfer::{TransferPipeline, WorkerPlatform};
use rch_common::TransferConfig;
use std::collections::BTreeSet;
use std::fs;
use std::time::Duration;

const STATE: &[&str] = &[
    ".ntm/session.json",
    ".beads-recovery/checkpoint.json",
    ".beads/.br_recovery/checkpoint.json",
    "nested/.ntm/session.json",
    "nested/deep/.beads-recovery/checkpoint.json",
];
const INPUTS: &[&str] = &[
    "src/lib.rs",
    "src/name with spaces.rs",
    "src/literal[1].rs",
    "src/雪.rs",
    "src/-C",
    "scratch/generated.rs",
    "data/input.bin",
    "artifacts/fixture.txt",
    ".cargo/config.toml",
    ".claude/settings.json",
    ".ntm-fixtures/input.txt",
    ".beads-recovery-tools/input.txt",
    "fixtures/.ntm",
    "fixtures/.beads-recovery",
];

fn write(root: &Path, name: &str, bytes: &[u8]) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn fixture() -> (PathBuf, TransferPipeline) {
    let retained = tempfile::tempdir().unwrap().keep();
    let root = retained.join("source");
    for path in STATE.iter().chain(INPUTS) {
        write(&root, path, b"original source");
    }
    let pipeline = TransferPipeline::new(
        root,
        "source-archive-test".to_owned(),
        "abcdef0123456789".to_owned(),
        TransferConfig::default(),
    );
    (retained, pipeline)
}

async fn members(pipeline: &TransferPipeline) -> Vec<Member> {
    tokio::time::timeout(
        Duration::from_secs(10),
        pipeline.enumerate_source_upload_members(&pipeline.get_effective_excludes()),
    )
    .await
    .expect("local rsync selection timed out")
    .expect("local rsync selection requires installed rsync")
}

async fn upload(pipeline: &TransferPipeline, destination: &Path) -> (u64, u32) {
    let selected = members(pipeline).await;
    let (list, count) = manifest(&selected).await.unwrap();
    fs::create_dir_all(destination).unwrap();
    let mut receiver = Command::new("tar");
    receiver
        .args(["--extract", "--gzip", "--file=-", "--directory"])
        .arg(destination)
        .env_remove("TAR_OPTIONS");
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        stream(tar_command(&pipeline.project_root, list.path()), receiver),
    )
    .await
    .expect("local archive stream timed out")
    .unwrap();
    (bytes, count)
}

#[test]
fn names_are_decoded_once_before_validation() {
    assert_eq!(decode_name(r"literal\#134#012.rs").unwrap(), r"literal\#012.rs");
    assert_eq!(decode_name(r"literal\#134012.rs").unwrap(), r"literal\012.rs");
    assert_eq!(decode_name(r"\#351\#233\#252.rs").unwrap(), "雪.rs");
    assert!(decode_name(r"\#377").is_err(), "invalid UTF-8 must not panic or be replaced");
    let members = parse_members(b">f+++++++++\tsrc/literal\\#134#012.rs\n").unwrap();
    assert_eq!(members[0].path, PathBuf::from(r"src/literal\#012.rs"));
    assert_eq!(regular_paths(members).unwrap(), [PathBuf::from(r"src/literal\#012.rs")]);
}

#[test]
fn incomplete_duplicate_unsupported_and_unsafe_members_refuse() {
    for output in [
        ">f+++++++++\tsrc/lib.rs",
        ">f+++++++++\tx\n>f+++++++++\tx\n",
        ">f+++++++++\tx\ncd+++++++++\tx/\n",
        "cS+++++++++\tsocket\n",
        "*deleting  \tx\n",
        ">f?????????\tx\n",
        ">f+++++++++\t../outside\n",
        ">f+++++++++\t/absolute\n",
        ">f+++++++++\tx//y\n",
        ">f+++++++++\tx/./y\n",
        ">f+++++++++\tx\\#012y\n",
        ">f+++++++++\tx\\#011y\n",
        ">f+++++++++\tx\\#000y\n",
    ] {
        assert!(parse_members(output.as_bytes()).is_err(), "accepted {output:?}");
    }
}

#[test]
fn receipt_gate_stays_stricter_than_ordinary_archives() {
    let listing = b"created directory /tmp/unused\ncd+++++++++\t./\ncd+++++++++\tsrc/\n>f+++++++++\tsrc/lib.rs\ncL+++++++++\tsrc/link.rs\n";
    let selected = parse_members(listing).unwrap();
    assert_eq!(selected.len(), 3);
    assert!(selected.iter().any(|member| member.kind == Kind::Symlink));
    assert!(regular_paths(selected).unwrap_err().to_string().contains("non-regular"));
    assert!(parse_members(b".d..t.......\t./\n>f++++++++++\tx\n").is_ok());
}

#[tokio::test]
async fn native_archive_and_receipt_selection_share_nested_exclusions() {
    let (retained, pipeline) = fixture();
    let receipt: BTreeSet<_> = pipeline
        .enumerate_source_content_files()
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(receipt, INPUTS.iter().map(PathBuf::from).collect());
    let destination = retained.join("worker");
    for path in STATE {
        write(&destination, path, b"retained worker state");
    }
    let (bytes, count) = upload(&pipeline, &destination).await;
    assert!(bytes > 0);
    assert_eq!(count as usize, INPUTS.len());
    for path in INPUTS {
        assert_eq!(fs::read(destination.join(path)).unwrap(), b"original source");
    }
    for path in STATE {
        assert_eq!(fs::read(destination.join(path)).unwrap(), b"retained worker state");
        assert_eq!(fs::read(pipeline.project_root.join(path)).unwrap(), b"original source");
    }
}

#[tokio::test]
async fn project_ignores_add_to_custom_configuration_without_erasing_exceptions() {
    let (retained, mut pipeline) = fixture();
    pipeline.transfer_config.exclude_patterns = vec!["target/".to_owned()];
    write(&pipeline.project_root, ".rchignore", b"/scratch/\n");
    let destination = retained.join("custom-worker");
    upload(&pipeline, &destination).await;
    for path in STATE {
        assert_eq!(fs::read(destination.join(path)).unwrap(), b"original source");
    }
    assert!(!destination.join("scratch/generated.rs").exists());
    assert_eq!(fs::read(destination.join("data/input.bin")).unwrap(), b"original source");
}

#[tokio::test]
async fn archive_preserves_links_and_empty_directories_without_recursion() {
    let (retained, pipeline) = fixture();
    fs::create_dir(pipeline.project_root.join("empty-input")).unwrap();
    std::os::unix::fs::symlink("lib.rs", pipeline.project_root.join("src/link.rs")).unwrap();
    let selected = members(&pipeline).await;
    assert!(regular_paths(selected.clone()).is_err());
    let (list, count) = manifest(&selected).await.unwrap();
    assert_eq!(count as usize, INPUTS.len());
    // These additions happen after selection. Including directory entries in
    // tar must not recursively reintroduce excluded or unselected children.
    write(&pipeline.project_root, "empty-input/late.txt", b"not selected");
    write(&pipeline.project_root, "nested/.ntm/late.txt", b"private state");
    let destination = retained.join("worker");
    fs::create_dir(&destination).unwrap();
    let mut receiver = Command::new("tar");
    receiver.args(["-xzf", "-", "-C"]).arg(&destination);
    tokio::time::timeout(
        Duration::from_secs(10),
        stream(tar_command(&pipeline.project_root, list.path()), receiver),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(destination.join("empty-input").is_dir());
    assert!(!destination.join("empty-input/late.txt").exists());
    assert!(!destination.join("nested/.ntm").exists());
    assert_eq!(fs::read_link(destination.join("src/link.rs")).unwrap(), PathBuf::from("lib.rs"));
    assert_eq!(fs::read(destination.join("src/link.rs")).unwrap(), b"original source");
}

#[tokio::test]
async fn tracked_cargo_packages_keep_the_production_build_directory_exception() {
    let (retained, pipeline) = fixture();
    write(&pipeline.project_root, "Cargo.toml", b"[workspace]\nmembers=['crates/build']\n");
    write(&pipeline.project_root, "crates/build/Cargo.toml", b"[package]\nname='build'\nversion='0.1.0'\n");
    write(&pipeline.project_root, "crates/build/src/lib.rs", b"pub fn input() {}\n");
    write(&pipeline.project_root, "crates/build/.ntm/state.json", b"private state");
    write(&pipeline.project_root, "build/generated.bin", b"build output");
    for args in [
        vec!["-c", "init.defaultBranch=main", "init", "-q"],
        vec!["add", "Cargo.toml", "crates/build/Cargo.toml"],
    ] {
        assert!(std::process::Command::new("git")
            .args(args)
            .current_dir(&pipeline.project_root)
            .status()
            .unwrap()
            .success());
    }
    let destination = retained.join("worker");
    upload(&pipeline, &destination).await;
    assert_eq!(fs::read(destination.join("crates/build/src/lib.rs")).unwrap(), b"pub fn input() {}\n");
    assert!(!destination.join("crates/build/.ntm").exists());
    assert!(!destination.join("build/generated.bin").exists());
}

#[tokio::test]
async fn explicit_windows_overlays_still_select_only_the_declared_files() {
    let (_, mut pipeline) = fixture();
    pipeline.worker_platform = WorkerPlatform::Windows;
    pipeline.sync_include_patterns = Some(vec![
        "/.ntm/".to_owned(),
        "/.ntm/session.json".to_owned(),
    ]);
    let (archive, count) = pipeline.selected_source_archive().await.unwrap();
    assert_eq!(count, 1);
    let mut archive = tar::Archive::new(archive.reopen().unwrap());
    let paths: Vec<_> = archive
        .entries()
        .unwrap()
        .map(|entry| entry.unwrap().path().unwrap().into_owned())
        .collect();
    assert_eq!(paths, [PathBuf::from(".ntm/session.json")]);
    assert!(pipeline.enumerate_source_content_files().await.is_err());
}

#[tokio::test]
async fn tracked_non_cargo_inputs_under_output_names_survive_archive_selection() {
    let (retained, pipeline) = fixture();
    let tracked = [
        "formal/lean/coverage/inventory.json",
        "fixtures/npm/dist/fixture.js",
        "src/build/mod.rs",
    ];
    let excluded = [
        "formal/lean/coverage/.ntm/session.json",
        "fixtures/npm/dist/.beads-recovery/state.json",
        "src/build/target/generated.o",
        "src/build/.env",
        "untracked/coverage/report.json",
        "untracked/dist/bundle.js",
    ];
    for path in tracked.iter().chain(excluded.iter()) {
        write(&pipeline.project_root, path, b"fixture bytes");
    }
    assert!(std::process::Command::new("git")
        .args(["-c", "init.defaultBranch=main", "init", "-q"])
        .current_dir(&pipeline.project_root)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("git")
        .arg("add")
        .args(tracked)
        .current_dir(&pipeline.project_root)
        .status()
        .unwrap()
        .success());
    let receipt = pipeline.enumerate_source_content_files().await.unwrap();
    let destination = retained.join("tracked-worker");
    upload(&pipeline, &destination).await;
    for path in tracked {
        assert!(receipt.contains(&PathBuf::from(path)), "receipt lost {path}");
        assert_eq!(fs::read(destination.join(path)).unwrap(), b"fixture bytes");
    }
    for path in excluded {
        assert!(!receipt.contains(&PathBuf::from(path)), "receipt included {path}");
        assert!(!destination.join(path).exists(), "archive included {path}");
        assert_eq!(fs::read(pipeline.project_root.join(path)).unwrap(), b"fixture bytes");
    }
}

#[tokio::test]
async fn manifest_refuses_windows_path_aliases_and_tar_ignores_ambient_options() {
    for name in [r"src/literal\name", "src/a:stream", "../outside", "a\nb"] {
        assert!(manifest(&[Member { path: PathBuf::from(name), kind: Kind::File }]).await.is_err());
    }
    let command = tar_command(Path::new("/source"), Path::new("/manifest"));
    assert!(command.as_std().get_envs().any(|(name, value)| name == "TAR_OPTIONS" && value.is_none()));
    let args: Vec<_> = command.as_std().get_args().collect();
    assert!(args.contains(&std::ffi::OsStr::new("--no-recursion")));
    assert!(args.contains(&std::ffi::OsStr::new("--null")));
}

#[tokio::test]
async fn producer_receiver_and_diagnostic_failures_cannot_report_success() {
    for (producer, receiver) in [
        ("printf x; exit 7", "cat >/dev/null"),
        ("printf x", "cat >/dev/null; exit 9"),
        ("printf x; printf warning >&2", "cat >/dev/null"),
        ("head -c 70000 /dev/zero >&2", "cat >/dev/null"),
        ("head -c 1048576 /dev/zero", "exit 9"),
    ] {
        let mut tar = Command::new("sh");
        tar.args(["-c", producer]);
        let mut ssh = Command::new("sh");
        ssh.args(["-c", receiver]);
        assert!(tokio::time::timeout(Duration::from_secs(10), stream(tar, ssh))
            .await
            .expect("failed producer/receiver stalled")
            .is_err());
    }
}

#[tokio::test]
async fn successful_ssh_notices_are_not_source_receipt_failures() {
    let mut tar = Command::new("sh");
    tar.args(["-c", "printf source-bytes"]);
    let mut ssh = Command::new("sh");
    ssh.args([
        "-c",
        "cat >/dev/null; printf 'Warning: Permanently added test host.\\n' >&2",
    ]);
    let copied = tokio::time::timeout(Duration::from_secs(10), stream(tar, ssh))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(copied, 12);
}
