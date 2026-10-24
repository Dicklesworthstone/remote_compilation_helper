//! Resolve the companion daemon from Cargo artifacts, never a guessed sibling.
//!
//! `scripts/test_rabs_live.py` builds both binaries once and supplies a private
//! artifact manifest. Direct `cargo test` remains supported: one profile-matched
//! build is performed per test process, rooted at THIS workspace and target
//! directory rather than the test's ambient cwd/CARGO_TARGET_DIR. A failed or
//! ambiguous build never falls back to a stale installed daemon.

use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

const MANIFEST_ENV: &str = "RABS_TEST_BINARIES";
const MAX_MANIFEST_BYTES: u64 = 32 * 1024;
const MAX_CARGO_FRAME_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn identity(path: &Path) -> Result<Identity, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(format!("{} is not a regular executable", path.display()));
    }
    Ok(identity_of(&metadata))
}

fn identity_of(metadata: &std::fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        mode: metadata.mode(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug)]
struct Artifact {
    path: PathBuf,
    identity: Identity,
}

impl Artifact {
    fn read(path: PathBuf, expected: Option<(&str, u64)>) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("artifact path is not absolute".into());
        }
        let before = identity(&path)?;
        if let Some((expected_hash, size)) = expected {
            if size != before.size {
                return Err(format!("{} changed size after preparation", path.display()));
            }
            let mut file = std::fs::File::open(&path).map_err(|error| error.to_string())?;
            if identity_of(&file.metadata().map_err(|error| error.to_string())?) != before {
                return Err("artifact changed while opening".into());
            }
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut remaining = size;
            while remaining != 0 {
                let limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
                let read = file
                    .read(&mut buffer[..limit])
                    .map_err(|error| error.to_string())?;
                if read == 0 {
                    return Err("artifact was truncated during verification".into());
                }
                hash.update(&buffer[..read]);
                remaining -= read as u64;
            }
            if file
                .read(&mut buffer[..1])
                .map_err(|error| error.to_string())?
                != 0
                || identity_of(&file.metadata().map_err(|error| error.to_string())?) != before
            {
                return Err("artifact changed during verification".into());
            }
            if hex(&hash.finalize()) != expected_hash {
                return Err(format!(
                    "{} does not match its prepared SHA-256",
                    path.display()
                ));
            }
        }
        let artifact = Self {
            path,
            identity: before,
        };
        artifact.verify()?;
        Ok(artifact)
    }

    fn verify(&self) -> Result<(), String> {
        if identity(&self.path)? != self.identity {
            return Err(format!(
                "{} was replaced after preparation",
                self.path.display()
            ));
        }
        Ok(())
    }
}

struct Binaries {
    daemon: Artifact,
    wrapper: Artifact,
}

fn text<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("missing string field {key}"))
}

fn artifact(value: &serde_json::Value) -> Result<Artifact, String> {
    let path = PathBuf::from(text(value, "path")?);
    let hash = text(value, "sha256")?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid artifact SHA-256".into());
    }
    let size = value
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing artifact size")?;
    Artifact::read(path, Some((hash, size)))
}

fn prepared(path: &Path, workspace: &Path, wrapper: &Path) -> Result<Binaries, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("prepared binary manifest is too large".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if text(&value, "schema")? != "rabs.test-binaries"
        || value.get("version").and_then(serde_json::Value::as_u64) != Some(1)
    {
        return Err("unsupported prepared binary manifest".into());
    }
    let recorded_workspace = PathBuf::from(text(&value, "workspace_root")?);
    if !recorded_workspace.is_absolute()
        || recorded_workspace
            .canonicalize()
            .map_err(|error| error.to_string())?
            != workspace
    {
        return Err("prepared binaries belong to another workspace".into());
    }
    // Verify the wrapper BEFORE trusting a daemon selected by the manifest.
    // Cargo may have rebuilt it with different features/profile/source while
    // compiling this test; a matching filename is not evidence of a match.
    let supplied_wrapper = artifact(value.get("rabs-wrap").ok_or("missing rabs-wrap artifact")?)?;
    if supplied_wrapper
        .path
        .canonicalize()
        .map_err(|error| error.to_string())?
        != wrapper.canonicalize().map_err(|error| error.to_string())?
    {
        return Err("manifest does not name this test's Cargo-built wrapper".into());
    }
    Ok(Binaries {
        daemon: artifact(value.get("rabsd").ok_or("missing rabsd artifact")?)?,
        wrapper: supplied_wrapper,
    })
}

fn build_layout(wrapper: &Path) -> Result<(&Path, &str), String> {
    let profile_dir = wrapper.parent().ok_or("wrapper has no profile directory")?;
    let target_dir = profile_dir
        .parent()
        .ok_or("wrapper has no target directory")?;
    let profile = profile_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("wrapper profile directory is not UTF-8")?;
    if !wrapper.is_absolute() || profile.is_empty() || profile == "deps" {
        return Err(
            "wrapper has an unsupported Cargo artifact layout; use scripts/test_rabs_live.py"
                .into(),
        );
    }
    Ok((target_dir, if profile == "debug" { "dev" } else { profile }))
}

fn cargo_artifact(value: &serde_json::Value, workspace: &Path) -> Result<Option<PathBuf>, String> {
    if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact")
        || value["target"]["name"] != "rabsd"
        || value["target"]["kind"] != serde_json::json!(["bin"])
        || value["profile"]["test"] != false
    {
        return Ok(None);
    }
    if Path::new(text(&value["target"], "src_path")?) != workspace.join("rabsd/src/main.rs") {
        return Err("Cargo reported rabsd from another source tree".into());
    }
    let executable = PathBuf::from(text(value, "executable")?);
    if !executable.is_absolute() {
        return Err("Cargo reported a relative daemon executable".into());
    }
    Ok(Some(executable))
}

fn build(workspace: &Path, wrapper: &Path) -> Result<Binaries, String> {
    let (target_dir, profile) = build_layout(wrapper)?;
    let mut child = Command::new(env!("CARGO"))
        .current_dir(workspace)
        .args([
            "build",
            "--locked",
            "-p",
            "rabsd",
            "--bin",
            "rabsd",
            "--message-format=json-render-diagnostics",
            "--profile",
            profile,
        ])
        .arg("--manifest-path")
        .arg(workspace.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(target_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("build rabsd: {error}"))?;
    let mut stdout = BufReader::new(child.stdout.take().ok_or("missing Cargo output")?);
    let mut selected = None;
    let mut failure = None;
    loop {
        let mut frame = Vec::new();
        let read = stdout
            .by_ref()
            .take(MAX_CARGO_FRAME_BYTES + 1)
            .read_until(b'\n', &mut frame);
        match read {
            Ok(0) => break,
            Ok(_) if frame.len() as u64 <= MAX_CARGO_FRAME_BYTES => {
                let parsed = serde_json::from_slice(&frame)
                    .map_err(|error| error.to_string())
                    .and_then(|value| cargo_artifact(&value, workspace));
                match parsed {
                    Ok(Some(path)) if selected.as_ref().is_some_and(|old| old != &path) => {
                        failure.get_or_insert_with(|| {
                            "Cargo reported multiple daemon executables".into()
                        });
                    }
                    Ok(Some(path)) => selected = Some(path),
                    Ok(None) => {}
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
            Ok(_) => {
                failure.get_or_insert_with(|| "Cargo JSON frame exceeded its bound".into());
                // Keep draining so a verbose child cannot deadlock behind a
                // full pipe. No overlong frame is retained or accepted.
                let _ = std::io::copy(&mut stdout, &mut std::io::sink());
                break;
            }
            Err(error) => {
                failure.get_or_insert_with(|| format!("read Cargo output: {error}"));
                let _ = child.kill();
                break;
            }
        }
    }
    let status = child.wait().map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("rabsd build failed: {status}"));
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(Binaries {
        daemon: Artifact::read(
            selected.ok_or("Cargo succeeded without a rabsd executable artifact")?,
            None,
        )?,
        wrapper: Artifact::read(wrapper.to_path_buf(), None)?,
    })
}

pub fn binary(wrapper: &str) -> PathBuf {
    static BINARIES: OnceLock<Binaries> = OnceLock::new();
    let binaries = BINARIES.get_or_init(|| {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .canonicalize()
            .expect("resolve RABS workspace");
        let wrapper = Path::new(wrapper);
        let result = match std::env::var_os(MANIFEST_ENV) {
            Some(path) => prepared(Path::new(&path), &workspace, wrapper),
            None => build(&workspace, wrapper),
        };
        result.unwrap_or_else(|error| panic!("prepare real rabsd: {error}"))
    });
    binaries
        .wrapper
        .verify()
        .expect("prepared wrapper identity");
    binaries.daemon.verify().expect("prepared daemon identity");
    binaries.daemon.path.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn executable(root: &Path, name: &str, bytes: &[u8]) -> serde_json::Value {
        let path = root.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        serde_json::json!({"path": path, "sha256": hex(&Sha256::digest(bytes)), "size": bytes.len()})
    }

    #[test]
    fn companion_build_uses_the_wrapper_profile_and_target_root() {
        for (path, target, profile) in [
            ("/repo/target/debug/rabs-wrap", "/repo/target", "dev"),
            (
                "/shared/build/release/rabs-wrap",
                "/shared/build",
                "release",
            ),
            (
                "/shared/build/daemon-release/rabs-wrap",
                "/shared/build",
                "daemon-release",
            ),
        ] {
            assert_eq!(
                build_layout(Path::new(path)).unwrap(),
                (Path::new(target), profile)
            );
        }
        assert!(build_layout(Path::new("target/debug/rabs-wrap")).is_err());
        assert!(build_layout(Path::new("/target/debug/deps/test")).is_err());
    }

    #[test]
    fn only_the_real_workspace_binary_artifact_is_accepted() {
        let mut value = serde_json::json!({"reason": "compiler-artifact", "target": {
            "name": "rabsd", "kind": ["bin"], "src_path": "/repo/rabsd/src/main.rs"
        }, "profile": {"test": false}, "executable": "/target/daemon-release/rabsd"});
        assert_eq!(
            cargo_artifact(&value, Path::new("/repo")).unwrap(),
            Some(PathBuf::from("/target/daemon-release/rabsd"))
        );
        value["profile"]["test"] = serde_json::json!(true);
        assert_eq!(cargo_artifact(&value, Path::new("/repo")).unwrap(), None);
        value["profile"]["test"] = serde_json::json!(false);
        value["target"]["src_path"] = serde_json::json!("/other/rabsd/src/main.rs");
        assert!(cargo_artifact(&value, Path::new("/repo")).is_err());
        value["target"]["src_path"] = serde_json::json!("/repo/rabsd/src/main.rs");
        value["executable"] = serde_json::json!(null);
        assert!(cargo_artifact(&value, Path::new("/repo")).is_err());
    }

    #[test]
    fn prepared_pair_binds_both_actual_binary_contents_and_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let wrapper = executable(&root, "rabs-wrap", b"wrapper\0bytes");
        let daemon = executable(&root, "rabsd", b"daemon\xffbytes");
        let manifest = root.join("binaries.json");
        let record = serde_json::json!({"schema": "rabs.test-binaries", "version": 1,
            "workspace_root": root, "rabs-wrap": wrapper, "rabsd": daemon});
        std::fs::write(&manifest, record.to_string()).unwrap();
        let pair = prepared(&manifest, &root, &root.join("rabs-wrap")).unwrap();
        assert_eq!(pair.daemon.path, root.join("rabsd"));
        assert!(prepared(&manifest, &root.join("other"), &root.join("rabs-wrap")).is_err());
        std::fs::write(root.join("rabsd"), b"changedbytes").unwrap();
        assert!(pair.daemon.verify().is_err());
        assert!(prepared(&manifest, &root, &root.join("rabs-wrap")).is_err());
    }

    #[test]
    fn prepared_artifacts_refuse_bad_hashes_symlinks_and_nonexecutables() {
        let dir = tempfile::tempdir().unwrap();
        let mut item = executable(dir.path(), "binary", b"abc");
        item["sha256"] = serde_json::json!("0".repeat(64));
        assert!(artifact(&item).is_err());
        item["sha256"] = serde_json::json!(hex(&Sha256::digest(b"abc")));
        std::fs::set_permissions(
            dir.path().join("binary"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(artifact(&item).is_err());
        let other = executable(dir.path(), "other", b"abc");
        std::os::unix::fs::symlink(dir.path().join("other"), dir.path().join("alias")).unwrap();
        let mut alias = other;
        alias["path"] = serde_json::json!(dir.path().join("alias"));
        assert!(artifact(&alias).is_err());
    }
}
