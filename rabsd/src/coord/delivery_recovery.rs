//! Read-only recovery AFTER the worker-delivery durability frontier.
//!
//! A retained directory is never permission to execute again. Only a complete
//! delivery.json bound to the exact request, worker and transport policy can
//! restore a result. Every byte is reverified before returning it. An incomplete
//! or corrupt directory is an uncertain execution, not a cache miss. This runs
//! on the operator thread, never on the daemon's asynchronous control reactor.

use super::worker_delivery::{
    Delivery, DeliveryFailure, MAX_DELIVERY_BYTES, MAX_FRAME_BYTES, validate_request,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Required provenance of the ORIGINAL delivery; recovery performs no handshake
/// and cannot upgrade an unauthenticated receipt into an authenticated one.
#[derive(Debug, Clone, Copy)]
pub enum DeliveryTrust {
    Loopback,
    PinnedWorker([u8; 32]),
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}

fn text<'a>(value: &'a Value, field: &str) -> io::Result<&'a str> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing string {field}"),
        )
    })
}

fn number(value: &Value, field: &str) -> io::Result<u64> {
    value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing integer {field}"),
        )
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical_hex(value: &str, digits: usize) -> bool {
    value.len() == digits
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(value: &Value, field: &str) -> io::Result<String> {
    let value = text(value, field)?;
    require(canonical_hex(value, 64), "non-canonical SHA-256")?;
    Ok(value.to_owned())
}

fn read_receipt(path: &Path) -> io::Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    require(metadata.is_file(), "delivery receipt is not a regular file")?;
    require(
        metadata.len() <= MAX_FRAME_BYTES as u64,
        "oversized delivery receipt",
    )?;
    let file = File::open(path)?;
    require(file.metadata()?.is_file(), "delivery receipt changed type")?;
    let mut bytes = Vec::new();
    file.take(MAX_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(bytes.len() <= MAX_FRAME_BYTES, "oversized delivery receipt")?;
    Ok(serde_json::from_slice(&bytes)?)
}

struct ExpectedFile {
    len: u64,
    sha256: String,
    executable: bool,
}

fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn expected_files(
    request: &Value,
    receipt: &Value,
    successful: bool,
) -> io::Result<BTreeMap<PathBuf, ExpectedFile>> {
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for stream in ["stdout", "stderr"] {
        let len = number(receipt, &format!("{stream}_bytes"))?;
        total = total.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "diagnostic length overflow")
        })?;
        files.insert(
            Path::new("diagnostics").join(stream),
            ExpectedFile {
                len,
                sha256: digest(receipt, &format!("{stream}_sha256"))?,
                executable: false,
            },
        );
    }
    match (successful, request.get("artifacts")) {
        (true, Some(declaration)) => {
            // validate_request already checked names, duplicates, traversal,
            // depth, and file/directory collisions. Read paths from THAT set,
            // never from an untrusted retained manifest.
            let names: BTreeSet<_> = declaration["files"]
                .as_array()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact declaration"))?
                .iter()
                .map(|name| {
                    name.as_str()
                        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact name"))
                })
                .collect::<io::Result<_>>()?;
            let manifest = &receipt["artifact_manifest"];
            let unit = text(declaration, "unit")?;
            require(text(manifest, "unit")? == unit, "artifact unit mismatch")?;
            let rows = manifest["files"].as_array().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing artifact manifest")
            })?;
            require(rows.len() == names.len(), "artifact set mismatch")?;
            let mut manifest_hash = Sha256::new();
            field(&mut manifest_hash, b"rabs.worker-artifact-manifest.v1");
            field(&mut manifest_hash, unit.as_bytes());
            manifest_hash.update((rows.len() as u64).to_be_bytes());
            let mut artifact_total = 0_u64;
            for (row, name) in rows.iter().zip(names) {
                require(text(row, "name")? == name, "artifact set/order mismatch")?;
                let len = number(row, "bytes")?;
                let sha256 = digest(row, "sha256")?;
                let executable = row["executable"].as_bool().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing artifact mode")
                })?;
                artifact_total = artifact_total.checked_add(len).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "artifact length overflow")
                })?;
                field(&mut manifest_hash, name.as_bytes());
                manifest_hash.update([u8::from(executable)]);
                manifest_hash.update(len.to_be_bytes());
                field(&mut manifest_hash, sha256.as_bytes());
                files.insert(
                    Path::new("artifacts").join(name),
                    ExpectedFile {
                        len,
                        sha256,
                        executable,
                    },
                );
            }
            require(
                artifact_total == number(manifest, "total_bytes")?
                    && hex(&manifest_hash.finalize()) == digest(manifest, "manifest_sha256")?,
                "artifact manifest identity mismatch",
            )?;
            total = total.checked_add(artifact_total).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "delivery length overflow")
            })?;
        }
        _ => require(
            receipt.get("artifact_manifest") == Some(&Value::Null),
            "unexpected artifacts for unsuccessful or undeclared execution",
        )?,
    }
    require(
        total <= MAX_DELIVERY_BYTES && total == number(receipt, "total_bytes")?,
        "delivery byte budget or total mismatch",
    )?;
    Ok(files)
}

fn verify_tree(root: &Path, files: &BTreeMap<PathBuf, ExpectedFile>) -> io::Result<()> {
    let mut directories = BTreeSet::from([
        PathBuf::new(),
        PathBuf::from("diagnostics"),
        PathBuf::from("artifacts"),
    ]);
    for path in files.keys() {
        for parent in path.ancestors().skip(1) {
            directories.insert(parent.to_path_buf());
        }
    }
    // Iterate only the bounded set derived from the validated request. Unknown
    // files, links, devices and directories fail without recursively exploring
    // attacker-controlled subtrees. Empty artifact sets still need both roots.
    for relative in &directories {
        let directory = root.join(relative);
        require(
            fs::symlink_metadata(&directory)?.is_dir(),
            "delivery directory is missing or a link",
        )?;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = relative.join(entry.file_name());
            let kind = entry.file_type()?;
            require(
                if directories.contains(&path) {
                    kind.is_dir()
                } else if files.contains_key(&path) || path == Path::new("delivery.json") {
                    kind.is_file()
                } else {
                    false
                },
                "unexpected file, symlink or special file in retained delivery",
            )?;
        }
    }
    Ok(())
}

fn verify_file(path: &Path, expected: &ExpectedFile) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && metadata.len() == expected.len,
        "delivery file type/length mismatch",
    )?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    require(
        metadata.is_file() && metadata.len() == expected.len,
        "delivery file changed type/length",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if expected.executable { 0o700 } else { 0o600 };
        require(
            metadata.permissions().mode() & 0o7777 == mode,
            "delivery file mode mismatch",
        )?;
    }
    #[cfg(not(unix))]
    let _ = expected.executable;
    let mut reader = file.take(expected.len + 1); // aggregate budget bounds this addition
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut read = 0_u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        hasher.update(&buffer[..count]);
    }
    require(
        read == expected.len && hex(&hasher.finalize()) == expected.sha256,
        "retained delivery content digest mismatch",
    )
}

/// Return None ONLY for an absent destination. Existing but incomplete, corrupt,
/// mismatched or inaccessible deliveries always refuse; callers must not use
/// those errors to dispatch again. No files or remote acknowledgments are changed.
///
/// The private local directory is the trust boundary, as in receive_execution.
/// Recovery revalidates content and historical provenance, not a new signature or
/// handshake. Callers must not concurrently modify the directory during recovery.
pub fn recover_existing_delivery(
    request: &Value,
    expected_worker: &str,
    destination: &Path,
    trust: DeliveryTrust,
) -> Result<Option<Delivery>, DeliveryFailure> {
    let outcome = (|| -> io::Result<Option<Delivery>> {
        validate_request(request)?;
        require(!expected_worker.is_empty(), "empty expected worker")?;
        require(
            destination.is_absolute()
                && destination
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "delivery destination must be absolute without traversal",
        )?;
        let metadata = match fs::symlink_metadata(destination) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        require(
            metadata.is_dir(),
            "retained delivery is not an ordinary directory",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            require(
                metadata.permissions().mode() & 0o077 == 0,
                "retained delivery is not private",
            )?;
        }
        let receipt = read_receipt(&destination.join("delivery.json"))?;
        require(
            number(&receipt, "version")? == 1
                && text(&receipt, "kind")? == "verified-worker-delivery"
                && number(&receipt, "request_id")? == number(request, "request_id")?
                && text(&receipt, "worker_id")? == expected_worker
                && digest(&receipt, "request_sha256")?
                    == hex(&Sha256::digest(serde_json::to_vec(request)?))
                && receipt
                    .get("publication_authorized")
                    .and_then(Value::as_bool)
                    == Some(false)
                && receipt.get("reexecute").and_then(Value::as_bool) == Some(false),
            "delivery receipt does not match this request or authority policy",
        )?;
        let incarnation = text(&receipt, "incarnation")?;
        require(
            number(&receipt, "boot_generation")? > 0
                && canonical_hex(incarnation, 32)
                && incarnation.bytes().any(|byte| byte != b'0'),
            "invalid retained worker incarnation",
        )?;
        match trust {
            DeliveryTrust::Loopback => require(
                receipt
                    .get("transport_authenticated")
                    .and_then(Value::as_bool)
                    == Some(false)
                    && [
                        "worker_spki_sha256",
                        "authenticated_session_id",
                        "identity_generation",
                    ]
                    .iter()
                    .all(|field| receipt.get(*field) == Some(&Value::Null)),
                "retained delivery transport does not match loopback mode",
            )?,
            DeliveryTrust::PinnedWorker(pin) => require(
                pin != [0; 32]
                    && receipt
                        .get("transport_authenticated")
                        .and_then(Value::as_bool)
                        == Some(true)
                    && digest(&receipt, "worker_spki_sha256")? == hex(&pin)
                    && number(&receipt, "authenticated_session_id")? > 0
                    && number(&receipt, "identity_generation")? > 0,
                "retained delivery is not authenticated by the pinned worker",
            )?,
        }
        let exit = receipt.get("exit_code").and_then(Value::as_i64);
        require(
            exit.is_some_and(|code| (0..=255).contains(&code)),
            "invalid retained exit code",
        )?;
        let stop = receipt.get("stop_reason").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing retained stop reason")
        })?;
        require(
            stop.is_null()
                || (matches!(
                    stop.as_str(),
                    Some("cancelled" | "deadline-exceeded" | "session-lost")
                ) && exit != Some(0)),
            "invalid retained interruption or interrupted success",
        )?;
        let files = expected_files(request, &receipt, exit == Some(0) && stop.is_null())?;
        verify_tree(destination, &files)?;
        for (relative, file) in files {
            verify_file(&destination.join(relative), &file)?;
        }
        // A process may have died after marker rename but before directory
        // fsync. Re-establish that barrier before reporting a durable result.
        File::open(destination.join("delivery.json"))?.sync_all()?;
        File::open(destination)?.sync_all()?;
        Ok(Some(Delivery {
            directory: destination.to_path_buf(),
            receipt,
            acknowledgments_confirmed: false,
            acknowledgment_error: Some(
                "restored durable delivery; remote acknowledgments were not rechecked".to_owned(),
            ),
        }))
    })();
    outcome.map_err(|error| DeliveryFailure {
        directory: destination.to_path_buf(),
        execution_may_have_run: true,
        detail: format!("retained delivery cannot be replayed; do not reexecute: {error}"),
    })
}
