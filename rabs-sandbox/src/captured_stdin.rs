//! Byte-exact runtime input selected from an already sealed source projection.
//!
//! This is a whole-Cargo execution input, never compiler-cache or test-result
//! authority. The request retains the source-relative selection and the source
//! manifest retains its bytes. Linux execution copies those verified bytes to
//! a sealed anonymous descriptor that is not mounted into the workload.

use crate::source_transfer::{SourceFile, SourceManifest, SourceReceiver};
use serde_json::Value;
use std::fs::File;
use std::io;
use std::process::Stdio;

/// Required worker capability when a request changes the default EOF input.
pub const CAPTURED_STDIN_VERSION: &str = "source-file-stdin-v1";
/// Per-operation anonymous input storage, separately bounded from source trees.
/// Larger inputs refuse before worker admission; they are never truncated.
pub const MAX_CAPTURED_STDIN_BYTES: u64 = 16 * 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

/// Parse only the logical selection, before source preparation opens a checkout.
/// Missing means EOF; malformed or unknown selections never silently mean EOF.
pub fn selected_path(request: &Value) -> io::Result<Option<&str>> {
    let Some(selection) = request.get("captured_stdin") else {
        return Ok(None);
    };
    require(
        selection.as_object().is_some_and(|fields| {
            fields.len() == 2 && fields.contains_key("version") && fields.contains_key("path")
        }) && selection["version"] == CAPTURED_STDIN_VERSION,
        "captured stdin requires the exact source-file-stdin-v1 selection",
    )?;
    let path = selection["path"]
        .as_str()
        .ok_or_else(|| invalid("captured stdin path must be a string"))?;
    require(
        !path.is_empty()
            && path.len() <= 1024
            && !path.contains(['\\', ':'])
            && !path.chars().any(char::is_control)
            && path.split('/').all(|part| !matches!(part, "" | "." | "..")),
        "captured stdin must be an ordinary source-root-relative file",
    )?;
    require(
        crate::cargo_artifacts::requested(request)?
            .is_some_and(crate::cargo_artifacts::CargoArtifactMode::is_execution),
        "captured stdin requires an executing Cargo run, test or bench contract",
    )?;
    Ok(Some(path))
}

/// Bind the selection to the exact immutable request's source inventory.
pub fn validate_request(
    request: &Value,
    manifest: Option<&SourceManifest>,
) -> io::Result<Option<SourceFile>> {
    let Some(path) = selected_path(request)? else {
        return Ok(None);
    };
    let expected = manifest
        .and_then(|manifest| manifest.files().iter().find(|file| file.path == path))
        .ok_or_else(|| invalid("captured stdin is not a declared source file"))?;
    require(
        expected.len <= MAX_CAPTURED_STDIN_BYTES,
        "captured worker stdin exceeds the 16 MiB byte bound",
    )?;
    Ok(Some(expected.clone()))
}

fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "captured stdin cancelled",
        ))
    } else {
        Ok(())
    }
}

/// An independently sealed copy. It owns no writable filesystem pathname and
/// can be handed to one child only; verification never advances the read offset.
#[derive(Debug)]
pub struct CapturedStdin {
    file: File,
    len: u64,
    handed_off: bool,
}

impl CapturedStdin {
    /// Acquire only a member of a sealed receiver, and compare the copy with its
    /// existing digest. Opening is descriptor-relative and refuses all symlinks,
    /// nonregular files and mount crossings. Reads/copies have a finite bound.
    #[cfg(target_os = "linux")]
    pub fn capture(
        source: &SourceReceiver,
        expected: &SourceFile,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        use crate::source_transfer::MAX_SOURCE_CHUNK;
        use rustix::fs::{MemfdFlags, Mode, OFlags, ResolveFlags, SealFlags};
        use sha2::{Digest, Sha256};
        use std::io::{Seek, Write};
        use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

        checkpoint(stopped)?;
        require(
            source
                .manifest()
                .files()
                .iter()
                .any(|file| file == expected)
                && expected.len <= MAX_CAPTURED_STDIN_BYTES,
            "captured stdin differs from its sealed source declaration",
        )?;
        let root = source
            .sealed_root()
            .ok_or_else(|| invalid("captured stdin requires a completely sealed source"))?;
        let root = File::from(rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let input = File::from(rustix::fs::openat2(
            &root,
            expected.path.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )?);
        let before = input.metadata()?;
        require(
            before.is_file() && before.len() == expected.len && before.nlink() == 1,
            "captured stdin source type, length or link count changed",
        )?;
        let mut file = File::from(rustix::fs::memfd_create(
            "rabs-captured-stdin",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?);
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
        let mut offset = 0;
        while offset < expected.len {
            checkpoint(stopped)?;
            let count = (expected.len - offset).min(buffer.len() as u64) as usize;
            input.read_exact_at(&mut buffer[..count], offset)?;
            hash.update(&buffer[..count]);
            file.write_all(&buffer[..count])?;
            offset += count as u64;
        }
        let after = input.metadata()?;
        require(
            input.read_at(&mut buffer[..1], offset)? == 0
                && <[u8; 32]>::from(hash.finalize()) == expected.sha256
                && before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.len() == after.len()
                && before.mode() == after.mode()
                && before.nlink() == after.nlink()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec(),
            "captured stdin source bytes or generation changed",
        )?;
        checkpoint(stopped)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        file.rewind()?;
        rustix::fs::fcntl_add_seals(
            &file,
            SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
        )?;
        let captured = Self {
            file,
            len: expected.len,
            handed_off: false,
        };
        captured.verify(stopped)?;
        Ok(captured)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn capture(
        _source: &SourceReceiver,
        _expected: &SourceFile,
        _stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sealed worker stdin requires Linux",
        ))
    }

    /// Kernel seals cannot be removed and prevent writes through every alias.
    /// Keeping this owner through cleanup also keeps the bytes alive.
    pub fn verify(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(stopped)?;
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::SealFlags;
            require(
                rustix::fs::fcntl_get_seals(&self.file)?.contains(
                    SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
                ) && self.file.metadata()?.len() == self.len,
                "captured stdin lost its immutable byte binding",
            )?;
            checkpoint(stopped)
        }
        #[cfg(not(target_os = "linux"))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sealed worker stdin requires Linux",
        ))
    }

    /// Transfer a clone of the descriptor once. A partial read, EOF or a failed
    /// launch cannot reset input and authorize a second execution.
    pub fn take_stdio(&mut self, stopped: &impl Fn() -> bool) -> io::Result<Stdio> {
        require(
            !self.handed_off,
            "captured stdin was already handed to the workload",
        )?;
        self.verify(stopped)?;
        let descriptor = self.file.try_clone()?;
        self.handed_off = true;
        Ok(Stdio::from(descriptor))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::source_transfer::MAX_SOURCE_CHUNK;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::unix::fs::FileExt;
    use std::os::unix::fs::PermissionsExt;

    fn sealed(bytes: &[u8]) -> (tempfile::TempDir, SourceReceiver, SourceFile) {
        let parent = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let expected = SourceFile {
            path: "inputs/request.bin".into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        };
        let mut source = SourceReceiver::create(
            &parent.path().join("source"),
            SourceManifest::new(vec![expected.clone()]).unwrap(),
        )
        .unwrap();
        for (index, bytes) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            source
                .write_chunk(
                    &expected.path,
                    (index * MAX_SOURCE_CHUNK) as u64,
                    bytes,
                    Sha256::digest(bytes).into(),
                )
                .unwrap();
        }
        source.seal().unwrap();
        (parent, source, expected)
    }

    fn request(command: &str) -> Value {
        json!({
            "program":"/__rabs/toolchain/bin/cargo",
            "args":[command, "--message-format=json", "--target-dir=/__rabs/out/cargo"],
            "artifacts":{"unit":"cargo", "tree":"tree-files-v1", "files":[],
                "cargo":format!("cargo-{command}-json-v1")},
            "captured_stdin":{"version":CAPTURED_STDIN_VERSION,"path":"inputs/request.bin"},
        })
    }

    #[test]
    fn captured_stdin_request_requires_exact_runtime_contract_and_source_membership() {
        let (_parent, source, expected) = sealed(b"input");
        for command in ["run", "test", "bench"] {
            let request = request(command);
            assert_eq!(
                validate_request(&request, Some(source.manifest())).unwrap(),
                Some(expected.clone())
            );
            assert!(validate_request(&request, None).is_err());
            for bad in [
                Value::Null,
                json!("inputs/request.bin"),
                json!({"version":"source-file-stdin-v2","path":"inputs/request.bin"}),
                json!({"version":CAPTURED_STDIN_VERSION,"path":"inputs/request.bin","extra":true}),
            ] {
                let mut refused = request.clone();
                refused["captured_stdin"] = bad;
                assert!(validate_request(&refused, Some(source.manifest())).is_err());
            }
            for path in [
                "",
                "/dev/stdin",
                "../outside",
                "inputs/../request.bin",
                "inputs//request.bin",
                "inputs\\request.bin",
                "inputs/request.bin\n",
                "inputs/absent",
            ] {
                let mut refused = request.clone();
                refused["captured_stdin"]["path"] = json!(path);
                assert!(
                    validate_request(&refused, Some(source.manifest())).is_err(),
                    "{path:?}"
                );
            }
        }
        for command in ["build", "check", "clippy", "doc", "test", "bench"] {
            let mut refused = request(command);
            refused["artifacts"]["cargo"] = json!("cargo-json-v1");
            if matches!(command, "test" | "bench") {
                refused["args"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("--no-run"));
            }
            assert!(
                validate_request(&refused, Some(source.manifest())).is_err(),
                "{command}"
            );
        }
        let mut closed = request("run");
        closed.as_object_mut().unwrap().remove("captured_stdin");
        assert_eq!(validate_request(&closed, None).unwrap(), None);
        for (length, accepted) in [
            (MAX_CAPTURED_STDIN_BYTES, true),
            (MAX_CAPTURED_STDIN_BYTES + 1, false),
        ] {
            let mut bounded = expected.clone();
            bounded.len = length;
            let manifest = SourceManifest::new(vec![bounded]).unwrap();
            assert_eq!(
                validate_request(&request("run"), Some(&manifest)).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn captured_stdin_keeps_empty_binary_and_multichunk_bytes_immutable() {
        for bytes in [
            Vec::new(),
            b"\0binary\xff\n".to_vec(),
            vec![0xa5; MAX_SOURCE_CHUNK * 3 + 7],
        ] {
            let (_parent, source, expected) = sealed(&bytes);
            let mut captured = CapturedStdin::capture(&source, &expected, &|| false).unwrap();
            assert!(captured.file.write_at(b"changed", 0).is_err());
            assert!(captured.file.set_len(expected.len + 1).is_err());
            if expected.len != 0 {
                assert!(captured.file.set_len(0).is_err());
            }
            // A later source edit cannot replace the independently sealed input.
            let original = source.sealed_root().unwrap().join(&expected.path);
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(original, b"other").unwrap();
            let mut reader = captured.file.try_clone().unwrap();
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, bytes);
            captured.verify(&|| false).unwrap();
            captured.take_stdio(&|| false).unwrap();
            assert!(captured.take_stdio(&|| false).is_err());
        }
    }

    #[test]
    fn captured_stdin_refuses_unsealed_changed_and_symlinked_source() {
        let (_parent, mut source, expected) = sealed(b"original");
        let mut wrong = expected.clone();
        wrong.sha256 = Sha256::digest(b"different").into();
        assert!(CapturedStdin::capture(&source, &wrong, &|| false).is_err());
        let input = source.sealed_root().unwrap().join(&expected.path);
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&input, b"mutated!").unwrap();
        assert!(CapturedStdin::capture(&source, &expected, &|| false).is_err());
        assert!(
            source
                .verify_completed_file(&expected.path, || false)
                .is_err()
        );
        assert!(CapturedStdin::capture(&source, &expected, &|| false).is_err());

        let (parent, source, expected) = sealed(b"original");
        let root = source.sealed_root().unwrap();
        std::fs::rename(root.join("inputs"), parent.path().join("moved")).unwrap();
        std::os::unix::fs::symlink(parent.path().join("moved"), root.join("inputs")).unwrap();
        assert!(CapturedStdin::capture(&source, &expected, &|| false).is_err());
    }

    #[test]
    fn captured_stdin_cancellation_prevents_capture_and_handoff() {
        let (_parent, source, expected) = sealed(&vec![7; MAX_SOURCE_CHUNK * 3]);
        let calls = std::cell::Cell::new(0);
        let stopped = || {
            calls.set(calls.get() + 1);
            calls.get() >= 3
        };
        assert_eq!(
            CapturedStdin::capture(&source, &expected, &stopped)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        let mut captured = CapturedStdin::capture(&source, &expected, &|| false).unwrap();
        assert_eq!(
            captured.take_stdio(&|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(!captured.handed_off);
    }

    #[test]
    fn captured_stdin_real_cargo_run_preserves_bytes_eof_and_partial_reads() {
        // Real Cargo/rustc and child standard input. This does not claim a TLS
        // session or kernel namespace qualification on the test host.
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("src")).unwrap();
        std::fs::write(
            project.path().join("Cargo.toml"),
            "[package]\nname='captured-stdin-test'\nversion='0.1.0'\nedition='2024'\n[workspace]\n",
        )
        .unwrap();
        std::fs::write(
            project.path().join("src/main.rs"),
            r#"
use std::io::{Read, Write};
fn main() {
    let mut bytes = Vec::new();
    if std::env::args().any(|arg| arg == "prefix") {
        std::io::stdin().take(3).read_to_end(&mut bytes).unwrap();
    } else {
        std::io::stdin().read_to_end(&mut bytes).unwrap();
    }
    std::io::stdout().write_all(&bytes).unwrap();
}
"#,
        )
        .unwrap();
        let cargo = std::env::var_os("RABS_TEST_CARGO")
            .or_else(|| std::env::var_os("CARGO"))
            .unwrap_or_else(|| "cargo".into());
        for (bytes, partial) in [
            (Vec::new(), false),
            (b"\0exact\xff\n".to_vec(), false),
            (vec![0xad; MAX_SOURCE_CHUNK * 2 + 11], false),
            (vec![0x92; MAX_SOURCE_CHUNK * 2 + 11], true),
        ] {
            let (_parent, source, expected) = sealed(&bytes);
            let mut captured = CapturedStdin::capture(&source, &expected, &|| false).unwrap();
            let mut process = std::process::Command::new(&cargo);
            process
                .current_dir(project.path())
                .args(["run", "--quiet", "--offline", "--target-dir"])
                .arg(project.path().join("target"))
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("CARGO_MAKEFLAGS")
                .env_remove("MAKEFLAGS")
                .stdin(captured.take_stdio(&|| false).unwrap());
            if partial {
                process.args(["--", "prefix"]);
            }
            let result = process.output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                result.stdout,
                if partial {
                    &bytes[..3]
                } else {
                    bytes.as_slice()
                }
            );
            captured.verify(&|| false).unwrap();
            assert!(captured.take_stdio(&|| false).is_err());
        }
    }
}
