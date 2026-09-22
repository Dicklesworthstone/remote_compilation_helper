//! Real Cargo local-registry acceptance through the actual worker. The registry
//! package is generated locally, not downloaded, and no result spool is seeded.
//! Cargo must unpack the transferred archive into its private writable home.
//! The negative case transfers hash-valid bytes with a wrong Cargo checksum.

use super::*;
use rabs_sandbox::cargo_home::CARGO_HOME_SOURCE_VERSION;

const ARCHIVE_PATH: &str = "cache/registry/index/local/registry_dep-1.0.0.crate";

fn registry_files(root: &Path, corrupt_archive: bool) -> BTreeMap<String, Vec<u8>> {
    let package = root.join("registry_dep-1.0.0");
    fs::create_dir_all(package.join("src")).unwrap();
    fs::write(package.join("Cargo.toml"),
        "[package]\nname=\"registry_dep\"\nversion=\"1.0.0\"\nedition=\"2021\"\n").unwrap();
    fs::write(package.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
    let archive_path = root.join("registry_dep-1.0.0.crate");
    // .crate files are gzip-compressed tar archives. All paths are controlled
    // fixture names, not peer input; no shell expansion or registry access runs.
    let child = Command::new("tar").arg("-czf").arg(&archive_path)
        .arg("-C").arg(root).arg("registry_dep-1.0.0")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit())
        .spawn().expect("tar and gzip are required by the registry acceptance fixture");
    let mut archiver = Worker(child);
    archiver.wait_success();
    assert!(fs::metadata(&archive_path).unwrap().len() < 64 * 1024);
    let mut archive = fs::read(archive_path).unwrap();
    let checksum = sha256_hex(&archive);
    let index = json!({"name":"registry_dep", "vers":"1.0.0", "deps":[],
        "cksum":checksum, "features":{}, "yanked":false});
    let lock = format!("version = 4\n\n[[package]]\nname = \"closure_app\"\nversion = \"0.1.0\"\ndependencies = [\"registry_dep\"]\n\n[[package]]\nname = \"registry_dep\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n");
    let config = format!("[source.crates-io]\nreplace-with=\"fixture\"\n[source.fixture]\nlocal-registry=\"{}/registry/index/local\"\n",
        rabs_sandbox::layout::CARGO_HOME);
    if corrupt_archive {
        // The transport manifest hashes these actual bytes, so source transfer
        // must succeed. Cargo's independently recorded index/lock checksum must
        // refuse them. This is not merely another bad transfer-chunk test.
        archive.push(0);
    }
    BTreeMap::from([
        ("app/Cargo.toml".to_owned(), b"[package]\nname=\"closure_app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[workspace]\n[dependencies]\nregistry_dep=\"=1.0.0\"\n".to_vec()),
        ("app/Cargo.lock".to_owned(), lock.into_bytes()),
        ("app/.cargo/config.toml".to_owned(), config.into_bytes()),
        ("app/src/main.rs".to_owned(), b"fn main() { println!(\"{}:{}\", registry_dep::answer(), env!(\"BUILD_LABEL\")); }\n".to_vec()),
        (ARCHIVE_PATH.to_owned(), archive),
        ("cache/registry/index/local/index/re/gi/registry_dep".to_owned(), format!("{index}\n").into_bytes()),
    ])
}

#[test]
#[ignore = "requires canonical-capable Linux, Rust, linker, tar and gzip; run explicitly"]
fn offline_registry_replay_builds_recovers_and_rejects_wrong_package_checksum() {
    let missing = rabs_sandbox::canonical_namespace::HostIsolationSupport::probe().missing_for_canonical();
    assert!(missing.is_empty(), "canonical isolation is required, missing {missing:?}");
    for corrupt in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut files = registry_files(root.path(), corrupt);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let state = root.path().join("state");
        let mut worker = Worker::start(&address, &state);
        let mut peer = Peer::accept(&listener, &mut worker);
        let first_hello = peer.admit(true);
        let home = json!({"version":CARGO_HOME_SOURCE_VERSION, "prefix":"cache"});
        let source = upload(&mut peer, &files, Some(&home));
        files.insert(ARCHIVE_PATH.into(), b"edited after upload".to_vec());
        let request = json!({"kind":"canonical-exec", "request_id":REQUEST_ID, "timeout_ms":60000,
            "program":"/__rabs/toolchain/bin/cargo", "args":["build", "--frozen", "--jobs=1"],
            "toolchain_backing":toolchain(), "source_manifest":source, "cargo_home":home,
            "jobserver_grant":1,
            "command_context":{"version":"env-cwd-v1", "cwd":"/__rabs/workspace/app",
                "env":{"CARGO_TARGET_DIR":"/__rabs/out/build", "CARGO_INCREMENTAL":"0", "BUILD_LABEL":"registry-replay"}},
            "artifacts":{"unit":"build", "files":["debug/closure_app"], "tree":TREE_FILES_VERSION}});
        peer.send(&request);
        let first = peer.receive();
        assert_eq!(first["kind"], "exec-result", "{first}");
        assert_eq!(first["executed"], true);
        assert_eq!(first["residual_group_members"], 0);
        assert!(first["stop_reason"].is_null());
        assert_eq!(first["result_retention"], "durable-result-v1");
        assert_eq!(peer.sent_execution, 1);
        let mut result = first.clone();
        if !corrupt {
            assert_eq!(first["exit_code"], 0, "{first}");
            verify_manifest(&first["artifact_manifest"]);
            // Destroy the original worker's source/cache ownership after the
            // complete result exists, before ACK. Resume must need neither a
            // cache reupload nor reconstruction of a new Cargo execution home.
            worker.crash_after_completed_result();
            drop(peer);
            worker = Worker::start(&address, &state);
            peer = Peer::accept(&listener, &mut worker);
            let hello = peer.admit(false);
            assert!(hello["boot_generation"].as_u64().unwrap() > first_hello["boot_generation"].as_u64().unwrap());
            peer.send(&json!({"kind":"result-resume", "request_id":REQUEST_ID, "request":request}));
            result = peer.receive();
            assert_eq!(result["kind"], "exec-result", "{result}");
            assert_eq!(result["resumed"], true);
            for field in ["exit_code", "stop_reason", "artifact_manifest", "retained_result_sha256",
                "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256"] {
                assert_eq!(result[field], first[field], "registry recovery changed {field}");
            }
            assert_eq!(peer.sent_execution, 0);
        } else {
            assert_ne!(first["exit_code"], 0, "Cargo accepted a package with the wrong checksum");
            assert!(first["artifact_manifest"].is_null());
            assert_eq!(first["artifact_ack_required"], false);
        }
        for stream in ["stdout", "stderr"] {
            let bytes = download(&mut peer, stream, result[format!("{stream}_bytes")].as_u64().unwrap(),
                result[format!("{stream}_sha256")].as_str().unwrap(), None);
            if corrupt && stream == "stderr" {
                assert!(String::from_utf8_lossy(&bytes).to_ascii_lowercase().contains("checksum"),
                    "failure was not Cargo checksum validation: {}", String::from_utf8_lossy(&bytes));
            }
        }
        if !corrupt {
            let destination = root.path().join("downloaded");
            fs::create_dir(&destination).unwrap();
            let manifest = &result["artifact_manifest"];
            for file in manifest["files"].as_array().unwrap() {
                let name = file["name"].as_str().unwrap();
                let executable = file["executable"].as_bool().unwrap();
                let bytes = download(&mut peer, name, file["bytes"].as_u64().unwrap(),
                    file["sha256"].as_str().unwrap(), Some((manifest, executable)));
                let path = destination.join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                let mut output = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
                output.write_all(&bytes).unwrap();
                output.set_permissions(fs::Permissions::from_mode(if executable {0o700} else {0o600})).unwrap();
                output.sync_all().unwrap();
            }
            let report = root.path().join("program-output");
            let child = Command::new(destination.join("debug/closure_app"))
                .stdin(Stdio::null()).stdout(File::create(&report).unwrap()).stderr(Stdio::inherit()).spawn().unwrap();
            let mut binary = Worker(child);
            binary.wait_success();
            assert_eq!(fs::read(report).unwrap(), b"42:registry-replay\n");
        }
        peer.send(&json!({"kind":"output-ack", "request_id":REQUEST_ID,
            "stdout_bytes":result["stdout_bytes"], "stdout_sha256":result["stdout_sha256"],
            "stderr_bytes":result["stderr_bytes"], "stderr_sha256":result["stderr_sha256"]}));
        assert_eq!(peer.receive()["kind"], "output-acknowledged");
        if !corrupt {
            peer.send(&json!({"kind":"artifact-ack", "request_id":REQUEST_ID,
                "manifest_sha256":result["artifact_manifest"]["manifest_sha256"],
                "total_bytes":result["artifact_manifest"]["total_bytes"]}));
            assert_eq!(peer.receive()["kind"], "artifact-acknowledged");
        }
        worker.wait_success();
        assert!(!state.join("retained-result").exists());
        assert_eq!(peer.sent_execution, if corrupt {1} else {0});
    }
}
