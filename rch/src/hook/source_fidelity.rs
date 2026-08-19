//! Exact source-content manifests and worker-side verification for proof runs.
//!
//! This is deliberately a transfer-boundary proof. The file universe comes
//! from the configured `TransferPipeline`'s own rsync filters, uploads use
//! checksum mode, a no-delta rsync barrier reopens the synchronized tree, and a
//! worker-side verifier re-hashes every selected regular file before Cargo.

use super::dependency_closure::{SyncClosureMode, SyncClosurePlanEntry};
use super::ssh::run_offload_ssh_command_with_stdin;
use super::*;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::fs::File;

const ROOT_SCHEMA: &str = "rch.source_content_root.v1";
const RECEIPT_SCHEMA: &str = "rch.source_content_receipt.v1";
const MAX_SOURCE_CONTENT_FILES: usize = 50_000;
const MAX_SOURCE_CONTENT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_REMOTE_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOURCE_CONTENT_RECEIPT_BYTES: usize = 8 * 1024 * 1024;
const REMOTE_VERIFY_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SourceContentFilterPolicy {
    schema: &'static str,
    include_patterns: Option<Vec<String>>,
    exclude_patterns: Vec<String>,
    delete_extraneous: bool,
    checksum_transfer: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SourceContentFile {
    path: String,
    sha256: String,
    byte_count: u64,
    executable: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SourceContentRootManifest {
    schema: &'static str,
    ordinal: usize,
    project_id: String,
    local_root: String,
    remote_root: String,
    root_hash: String,
    is_primary: bool,
    mode: SyncClosureMode,
    filter_policy: SourceContentFilterPolicy,
    file_count: usize,
    byte_count: u64,
    files: Vec<SourceContentFile>,
    content_root: String,
}

#[derive(Debug, Serialize)]
struct SourceContentRootPreimage<'a> {
    schema: &'static str,
    ordinal: usize,
    project_id: &'a str,
    local_root: &'a str,
    remote_root: &'a str,
    root_hash: &'a str,
    is_primary: bool,
    mode: SyncClosureMode,
    filter_policy: &'a SourceContentFilterPolicy,
    file_count: usize,
    byte_count: u64,
    files: &'a [SourceContentFile],
}

#[derive(Clone)]
pub(super) struct PreparedSourceContentRoot {
    pipeline: TransferPipeline,
    manifest: SourceContentRootManifest,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct SourceContentReceipt {
    schema: &'static str,
    worker_id: String,
    /// Decimal string because daemon build IDs exceed JavaScript's exact
    /// integer range and receipts are consumed by Node validators.
    build_id: String,
    command_sha256: String,
    command_exit_code: i32,
    root_count: usize,
    roots: Vec<SourceContentRootManifest>,
    receipt_root: String,
}

impl SourceContentReceipt {
    pub(super) fn canonical_json(&self) -> anyhow::Result<String> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_SOURCE_CONTENT_RECEIPT_BYTES {
            anyhow::bail!(
                "source-content receipt cap exceeded: {} > {}",
                bytes.len(),
                MAX_SOURCE_CONTENT_RECEIPT_BYTES
            );
        }
        String::from_utf8(bytes).context("source-content receipt JSON was not UTF-8")
    }
}

#[derive(Debug, Serialize)]
struct SourceContentReceiptPreimage<'a> {
    schema: &'static str,
    worker_id: &'a str,
    build_id: &'a str,
    command_sha256: &'a str,
    command_exit_code: i32,
    root_count: usize,
    roots: &'a [SourceContentRootManifest],
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hash_file(path: &Path) -> anyhow::Result<(String, u64, bool)> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat source-content file {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        anyhow::bail!(
            "source-content proof requires a regular non-symlink file: {}",
            path.display()
        );
    }
    let byte_count = metadata.len();
    let mut file =
        File::open(path).with_context(|| format!("open source-content file {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)
            .with_context(|| format!("read source-content file {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    #[cfg(unix)]
    let executable = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o111 != 0;
    #[cfg(not(unix))]
    let executable = false;
    Ok((hex_lower(&hasher.finalize()), byte_count, executable))
}

fn canonical_root_path(path: &Path) -> anyhow::Result<String> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize source-content root {}", path.display()))?;
    let value = canonical
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("source-content root is not UTF-8: {}", path.display()))?;
    if value.chars().any(char::is_control) {
        anyhow::bail!("source-content root contains control characters");
    }
    Ok(value.to_string())
}

async fn capture_manifest(
    ordinal: usize,
    entry: &SyncClosurePlanEntry,
    pipeline: &TransferPipeline,
) -> anyhow::Result<SourceContentRootManifest> {
    let paths = pipeline.enumerate_source_content_files().await?;
    if paths.is_empty() {
        anyhow::bail!(
            "source-content transfer universe is empty for {}",
            entry.local_root.display()
        );
    }
    if paths.len() > MAX_SOURCE_CONTENT_FILES {
        anyhow::bail!(
            "source-content file cap exceeded for {}: {} > {}",
            entry.local_root.display(),
            paths.len(),
            MAX_SOURCE_CONTENT_FILES
        );
    }

    let local_root = canonical_root_path(&entry.local_root)?;
    let hash_root = PathBuf::from(&local_root);
    let files = tokio::task::spawn_blocking(move || {
        let mut files = Vec::with_capacity(paths.len());
        let mut total_bytes = 0_u64;
        for relative in paths {
            let path = relative.to_str().ok_or_else(|| {
                anyhow::anyhow!("source-content relative path is not UTF-8: {relative:?}")
            })?;
            if path.chars().any(char::is_control) {
                anyhow::bail!("source-content relative path contains control characters");
            }
            let (sha256, byte_count, executable) = hash_file(&hash_root.join(&relative))?;
            total_bytes = total_bytes
                .checked_add(byte_count)
                .ok_or_else(|| anyhow::anyhow!("source-content byte count overflow"))?;
            if total_bytes > MAX_SOURCE_CONTENT_BYTES {
                anyhow::bail!(
                    "source-content byte cap exceeded: {} > {}",
                    total_bytes,
                    MAX_SOURCE_CONTENT_BYTES
                );
            }
            files.push(SourceContentFile {
                path: path.to_string(),
                sha256,
                byte_count,
                executable,
            });
        }
        Ok::<_, anyhow::Error>((files, total_bytes))
    })
    .await
    .context("join source-content hashing task")??;
    let (files, byte_count) = files;

    let (include_patterns, exclude_patterns, delete_extraneous, checksum_transfer) =
        pipeline.source_content_filter_policy();
    if !checksum_transfer {
        anyhow::bail!("source-content proof requires checksum transfer mode");
    }
    let filter_policy = SourceContentFilterPolicy {
        schema: "rch.source_content_filter.v1",
        include_patterns,
        exclude_patterns,
        delete_extraneous,
        checksum_transfer,
    };
    let preimage = SourceContentRootPreimage {
        schema: ROOT_SCHEMA,
        ordinal,
        project_id: &entry.project_id,
        local_root: &local_root,
        remote_root: &entry.remote_root,
        root_hash: &entry.root_hash,
        is_primary: entry.is_primary,
        mode: entry.mode,
        filter_policy: &filter_policy,
        file_count: files.len(),
        byte_count,
        files: &files,
    };
    let content_root = sha256_hex(&serde_json::to_vec(&preimage)?);
    Ok(SourceContentRootManifest {
        schema: ROOT_SCHEMA,
        ordinal,
        project_id: entry.project_id.clone(),
        local_root,
        remote_root: entry.remote_root.clone(),
        root_hash: entry.root_hash.clone(),
        is_primary: entry.is_primary,
        mode: entry.mode,
        filter_policy,
        file_count: files.len(),
        byte_count,
        files,
        content_root,
    })
}

pub(super) async fn prepare_source_content_root(
    ordinal: usize,
    entry: &SyncClosurePlanEntry,
    pipeline: &TransferPipeline,
) -> anyhow::Result<PreparedSourceContentRoot> {
    Ok(PreparedSourceContentRoot {
        pipeline: pipeline.clone(),
        manifest: capture_manifest(ordinal, entry, pipeline).await?,
    })
}

fn remote_manifest_payload(manifest: &SourceContentRootManifest) -> anyhow::Result<Vec<u8>> {
    let mut payload = Vec::new();
    for file in &manifest.files {
        if file.path.chars().any(|ch| matches!(ch, '\t' | '\n' | '\r')) {
            anyhow::bail!("unsafe source-content manifest path: {:?}", file.path);
        }
        use std::io::Write as _;
        writeln!(
            payload,
            "{}\t{}\t{}\t{}",
            file.sha256,
            file.byte_count,
            u8::from(file.executable),
            file.path
        )?;
        if payload.len() > MAX_REMOTE_MANIFEST_BYTES {
            anyhow::bail!(
                "source-content remote manifest cap exceeded: {} > {}",
                payload.len(),
                MAX_REMOTE_MANIFEST_BYTES
            );
        }
    }
    Ok(payload)
}

fn remote_verify_command(manifest: &SourceContentRootManifest) -> String {
    let root = shell_escape::escape(manifest.remote_root.clone().into());
    format!(
        "set -eu; root={root}; tab=$(printf '\\t'); count=0; total=0; \
         if command -v sha256sum >/dev/null 2>&1; then hash_file() {{ sha256sum -- \"$1\" | awk '{{print $1}}'; }}; \
         elif command -v shasum >/dev/null 2>&1; then hash_file() {{ shasum -a 256 -- \"$1\" | awk '{{print $1}}'; }}; \
         else printf 'RCH_SOURCE_CONTENT_ERROR:sha256_tool_missing\\n' >&2; exit 61; fi; \
         while IFS=\"$tab\" read -r expected_hash expected_bytes expected_exec relative; do \
           [ -n \"$relative\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:empty_path\\n' >&2; exit 62; }}; \
           file=\"$root/$relative\"; \
           [ -f \"$file\" ] && [ ! -L \"$file\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:not_regular:%s\\n' \"$relative\" >&2; exit 63; }}; \
           actual_bytes=$(wc -c < \"$file\" | tr -d '[:space:]'); \
           [ \"$actual_bytes\" = \"$expected_bytes\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:size:%s\\n' \"$relative\" >&2; exit 64; }}; \
           actual_hash=$(hash_file \"$file\"); \
           [ \"$actual_hash\" = \"$expected_hash\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:sha256:%s\\n' \"$relative\" >&2; exit 65; }}; \
           actual_exec=0; [ -x \"$file\" ] && actual_exec=1; \
           [ \"$actual_exec\" = \"$expected_exec\" ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:mode:%s\\n' \"$relative\" >&2; exit 66; }}; \
           count=$((count + 1)); total=$((total + actual_bytes)); \
         done; \
         [ \"$count\" -eq {file_count} ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:count:%s\\n' \"$count\" >&2; exit 67; }}; \
         [ \"$total\" -eq {byte_count} ] || {{ printf 'RCH_SOURCE_CONTENT_ERROR:bytes:%s\\n' \"$total\" >&2; exit 68; }}; \
         printf 'RCH_SOURCE_CONTENT_VERIFIED\\t%s\\t%s\\n' \"$count\" \"$total\"",
        file_count = manifest.file_count,
        byte_count = manifest.byte_count,
    )
}

async fn verify_remote_root(
    worker: &WorkerConfig,
    root: &PreparedSourceContentRoot,
) -> anyhow::Result<()> {
    root.pipeline
        .verify_source_content_rsync_barrier(worker)
        .await?;
    let payload = remote_manifest_payload(&root.manifest)?;
    let output = run_offload_ssh_command_with_stdin(
        worker,
        &remote_verify_command(&root.manifest),
        &payload,
        REMOTE_VERIFY_TIMEOUT,
    )
    .await?;
    if !output.status.success() {
        anyhow::bail!(
            "remote source-content verification failed on {} for {} (exit {:?}): {}",
            worker.id,
            root.manifest.project_id,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if !output.stderr.is_empty() {
        anyhow::bail!(
            "remote source-content verification produced stderr on {} for {}: {}",
            worker.id,
            root.manifest.project_id,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let expected = format!(
        "RCH_SOURCE_CONTENT_VERIFIED\t{}\t{}\n",
        root.manifest.file_count, root.manifest.byte_count
    );
    if output.stdout != expected.as_bytes() {
        anyhow::bail!(
            "remote source-content verification envelope mismatch on {} for {}: {:?}",
            worker.id,
            root.manifest.project_id,
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Ok(())
}

pub(super) async fn verify_source_content_roots(
    worker: &WorkerConfig,
    prepared: &[PreparedSourceContentRoot],
) -> anyhow::Result<()> {
    if prepared.is_empty() {
        anyhow::bail!("source-content proof has no synchronized roots");
    }
    for root in prepared {
        verify_remote_root(worker, root).await?;
    }

    // Re-enumerate and re-hash after every remote verification. A lasting local
    // edit, added file, deletion, mode change, or filter drift therefore refuses
    // the receipt. The caller's recursive watcher supplies ABA/overflow proof.
    for root in prepared {
        let recaptured = capture_manifest(
            root.manifest.ordinal,
            &SyncClosurePlanEntry {
                local_root: PathBuf::from(&root.manifest.local_root),
                remote_root: root.manifest.remote_root.clone(),
                project_id: root.manifest.project_id.clone(),
                root_hash: root.manifest.root_hash.clone(),
                is_primary: root.manifest.is_primary,
                mode: root.manifest.mode,
            },
            &root.pipeline,
        )
        .await?;
        if recaptured != root.manifest {
            anyhow::bail!(
                "local source-content changed during transfer proof for {}",
                root.manifest.project_id
            );
        }
    }
    Ok(())
}

pub(super) async fn finalize_source_content_receipt(
    worker: &WorkerConfig,
    build_id: u64,
    command: &str,
    command_exit_code: i32,
    prepared: &[PreparedSourceContentRoot],
) -> anyhow::Result<SourceContentReceipt> {
    verify_source_content_roots(worker, prepared).await?;

    let roots = prepared
        .iter()
        .map(|root| root.manifest.clone())
        .collect::<Vec<_>>();
    let command_sha256 = sha256_hex(command.as_bytes());
    let build_id = build_id.to_string();
    let preimage = SourceContentReceiptPreimage {
        schema: RECEIPT_SCHEMA,
        worker_id: worker.id.as_str(),
        build_id: &build_id,
        command_sha256: &command_sha256,
        command_exit_code,
        root_count: roots.len(),
        roots: &roots,
    };
    let receipt_root = sha256_hex(&serde_json::to_vec(&preimage)?);
    Ok(SourceContentReceipt {
        schema: RECEIPT_SCHEMA,
        worker_id: worker.id.as_str().to_string(),
        build_id,
        command_sha256,
        command_exit_code,
        root_count: roots.len(),
        roots,
        receipt_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_root_changes_with_worker_command_exit_and_file_identity() {
        let filter_policy = SourceContentFilterPolicy {
            schema: "rch.source_content_filter.v1",
            include_patterns: None,
            exclude_patterns: vec!["target/".to_string()],
            delete_extraneous: true,
            checksum_transfer: true,
        };
        let file = SourceContentFile {
            path: "src/lib.rs".to_string(),
            sha256: "a".repeat(64),
            byte_count: 7,
            executable: false,
        };
        let root = SourceContentRootManifest {
            schema: ROOT_SCHEMA,
            ordinal: 0,
            project_id: "fixture".to_string(),
            local_root: "/data/projects/fixture".to_string(),
            remote_root: "/data/tmp/rch/fixture/proof".to_string(),
            root_hash: "b".repeat(64),
            is_primary: true,
            mode: SyncClosureMode::Full,
            filter_policy,
            file_count: 1,
            byte_count: 7,
            files: vec![file],
            content_root: "c".repeat(64),
        };
        let roots = vec![root.clone()];
        let root_for =
            |worker: &str, command: &str, exit_code: i32, roots: &[SourceContentRootManifest]| {
                let command_sha256 = sha256_hex(command.as_bytes());
                sha256_hex(
                    &serde_json::to_vec(&SourceContentReceiptPreimage {
                        schema: RECEIPT_SCHEMA,
                        worker_id: worker,
                        build_id: "42",
                        command_sha256: &command_sha256,
                        command_exit_code: exit_code,
                        root_count: roots.len(),
                        roots,
                    })
                    .unwrap(),
                )
            };
        let baseline = root_for("worker-a", "cargo check", 0, &roots);
        assert_ne!(baseline, root_for("worker-b", "cargo check", 0, &roots));
        assert_ne!(baseline, root_for("worker-a", "cargo test", 0, &roots));
        assert_ne!(baseline, root_for("worker-a", "cargo check", 1, &roots));
        let mut mutated = roots;
        mutated[0].files[0].sha256 = "d".repeat(64);
        assert_ne!(baseline, root_for("worker-a", "cargo check", 0, &mutated));

        let receipt = SourceContentReceipt {
            schema: RECEIPT_SCHEMA,
            worker_id: "worker-a".to_string(),
            build_id: "9007199254740993".to_string(),
            command_sha256: sha256_hex(b"cargo check"),
            command_exit_code: 0,
            root_count: 1,
            roots: vec![root],
            receipt_root: baseline,
        };
        let wire: serde_json::Value = serde_json::from_str(&receipt.canonical_json().unwrap())
            .expect("receipt JSON should parse");
        assert_eq!(wire["build_id"], "9007199254740993");
    }

    #[test]
    fn remote_manifest_payload_is_bounded_and_unambiguous() {
        let manifest = SourceContentRootManifest {
            schema: ROOT_SCHEMA,
            ordinal: 0,
            project_id: "fixture".to_string(),
            local_root: "/local".to_string(),
            remote_root: "/remote".to_string(),
            root_hash: "a".repeat(64),
            is_primary: true,
            mode: SyncClosureMode::Full,
            filter_policy: SourceContentFilterPolicy {
                schema: "rch.source_content_filter.v1",
                include_patterns: None,
                exclude_patterns: vec![],
                delete_extraneous: true,
                checksum_transfer: true,
            },
            file_count: 1,
            byte_count: 3,
            files: vec![SourceContentFile {
                path: "src/lib.rs".to_string(),
                sha256: "f".repeat(64),
                byte_count: 3,
                executable: false,
            }],
            content_root: "b".repeat(64),
        };
        assert_eq!(
            String::from_utf8(remote_manifest_payload(&manifest).unwrap()).unwrap(),
            format!("{}\t3\t0\tsrc/lib.rs\n", "f".repeat(64))
        );
        let mut invalid = manifest;
        invalid.files[0].path = "src\tlib.rs".to_string();
        assert!(remote_manifest_payload(&invalid).is_err());
    }
}
