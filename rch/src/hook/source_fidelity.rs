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
// Large tracked conformance corpora are legitimate source inputs.  The
// FrankenNetworkX dependency currently contributes about 74k selected files,
// so keep a finite one-over boundary without rejecting that authentic tree.
const MAX_SOURCE_CONTENT_FILES: usize = 100_000;
const MAX_SOURCE_CONTENT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_REMOTE_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
// The receipt repeats each selected path and SHA-256 for independently synced
// workspace and crate roots.  A 32 MiB cap closes the current ~100k-entry
// dependency closure while remaining equal to the bounded rsync/remote-manifest
// capture budget.
const MAX_SOURCE_CONTENT_RECEIPT_BYTES: usize = 32 * 1024 * 1024;
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

fn stamp_commit_hash(value: &str) -> bool {
    (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn build_source_commit_env<F>(mut lookup: F) -> std::collections::HashMap<String, String>
where
    F: FnMut(&str) -> Option<String>,
{
    rch_common::BUILD_COMMIT_ENV_VARS
        .iter()
        .map(|&key| {
            let value = lookup(key)
                .map(|value| value.trim().to_owned())
                .filter(|value| stamp_commit_hash(value))
                .unwrap_or_default();
            (key.to_owned(), value)
        })
        .collect()
}

async fn build_source_git_output(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let mut command = Command::new("git");
    configure_clean_git_command(&mut command);
    command
        .arg("--no-optional-locks")
        .args(["-c", "core.fsmonitor=false"])
        .current_dir(root)
        .args(args)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(5), command.output())
        .await
        .ok()?
        .ok()?;
    output.status.success().then_some(output.stdout)
}

fn clean_overlay_build_source_stamp(spec: &CleanOverlaySpec) -> String {
    if spec.is_base_only() && spec.dependencies.is_empty() {
        return spec.base_commit().to_owned();
    }
    if spec.dependencies.is_empty() {
        return format!(
            "{}-overlay-{}",
            spec.base_commit(),
            spec.overlay_fingerprint()
        );
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"rch-build-source-selection-v1\0");
    hasher.update(spec.base_commit().as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.tree_object.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.overlay_fingerprint().as_bytes());
    let mut dependencies = spec.dependencies.iter().collect::<Vec<_>>();
    dependencies.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (root, dependency) in dependencies {
        hasher.update(b"\0dependency\0");
        hasher.update(root.file_name().unwrap_or_default().as_encoded_bytes());
        hasher.update(b"\0");
        hasher.update(clean_overlay_build_source_stamp(dependency).as_bytes());
        hasher.update(b"\0");
        hasher.update(dependency.tree_object.as_bytes());
    }
    format!(
        "{}-overlay-{}",
        spec.base_commit(),
        hasher.finalize().to_hex()
    )
}

pub(super) async fn capture_build_source_stamp(
    root: &Path,
    overlay: Option<&CleanOverlaySpec>,
) -> String {
    if let Some(spec) = overlay {
        return clean_overlay_build_source_stamp(spec);
    }
    let Some(head) = build_source_git_output(root, &["rev-parse", "--verify", "HEAD"])
        .await
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| stamp_commit_hash(value))
    else {
        return "unknown".to_owned();
    };
    if build_source_git_output(root, &["ls-files", "--error-unmatch", "--", "Cargo.toml"])
        .await
        .is_none()
    {
        return "unknown".to_owned();
    }
    match build_source_git_output(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
            "--ignore-submodules=none",
        ],
    )
    .await
    {
        Some(status) if status.is_empty() => head,
        Some(_) => format!("{head}-dirty"),
        None => "unknown".to_owned(),
    }
}

pub(super) fn reconcile_build_source_stamps(before: &str, after: &str) -> String {
    if before == after {
        before.to_owned()
    } else {
        "unknown".to_owned()
    }
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

    fn build_source_stamp_git(root: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("git fixture command runs");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn build_source_stamp_git_commit(root: &Path, message: &str) {
        build_source_stamp_git(
            root,
            &[
                "-c",
                "user.name=RCH-Test",
                "-c",
                "user.email=rch-test@example.invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                message,
            ],
        );
    }

    fn build_source_stamp_fixture_repo() -> (PathBuf, String) {
        let root = tempfile::tempdir().unwrap().keep();
        build_source_stamp_git(&root, &["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='stamp-fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn baseline() {}\n").unwrap();
        build_source_stamp_git(&root, &["add", "Cargo.toml", "src/lib.rs"]);
        build_source_stamp_git_commit(&root, "initial");
        let head = build_source_stamp_git(&root, &["rev-parse", "HEAD"]);
        assert!(stamp_commit_hash(&head));
        (root, head)
    }

    fn build_source_stamp_overlay_spec(
        base_commit: &str,
        tree_object: &str,
        overlay_fingerprint: &str,
        overlay_paths: Vec<PathBuf>,
        dependencies: Vec<(PathBuf, CleanOverlaySpec)>,
    ) -> CleanOverlaySpec {
        CleanOverlaySpec {
            base_commit: base_commit.to_owned(),
            tree_object: tree_object.to_owned(),
            overlay_paths,
            overlay_fingerprint: overlay_fingerprint.to_owned(),
            dependencies,
            primary_directory: None,
        }
    }

    #[tokio::test]
    async fn build_source_stamp_clean_repo_is_head() {
        let (root, head) = build_source_stamp_fixture_repo();
        assert_eq!(capture_build_source_stamp(&root, None).await, head);
        eprintln!(
            "build-source clean-repo fixture retained at {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn build_source_stamp_tracked_edit_is_dirty() {
        let (root, head) = build_source_stamp_fixture_repo();
        std::fs::write(root.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
        assert_eq!(
            capture_build_source_stamp(&root, None).await,
            format!("{head}-dirty")
        );
        eprintln!("build-source dirty fixture retained at {}", root.display());
    }

    #[tokio::test]
    async fn build_source_stamp_untracked_source_is_dirty() {
        let (root, first) = build_source_stamp_fixture_repo();
        std::fs::write(root.join("src/lib.rs"), "pub fn second() {}\n").unwrap();
        build_source_stamp_git(&root, &["add", "src/lib.rs"]);
        build_source_stamp_git_commit(&root, "second");
        let second = build_source_stamp_git(&root, &["rev-parse", "HEAD"]);
        assert_ne!(first, second);
        assert_eq!(capture_build_source_stamp(&root, None).await, second);
        std::fs::write(root.join("src/extra.rs"), "pub fn extra() {}\n").unwrap();
        assert_eq!(
            capture_build_source_stamp(&root, None).await,
            format!("{second}-dirty")
        );
        eprintln!(
            "build-source untracked fixture retained at {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn build_source_stamp_non_git_root_is_unknown() {
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='not-git'\nversion='0.1.0'\n",
        )
        .unwrap();
        assert_eq!(capture_build_source_stamp(&root, None).await, "unknown");
        eprintln!(
            "build-source non-git fixture retained at {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn build_source_stamp_ignored_nested_package_is_unknown() {
        let (root, _head) = build_source_stamp_fixture_repo();
        std::fs::write(root.join(".gitignore"), "generated/\n").unwrap();
        build_source_stamp_git(&root, &["add", ".gitignore"]);
        build_source_stamp_git_commit(&root, "ignore generated");
        let nested = root.join("generated");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("Cargo.toml"),
            "[package]\nname='generated'\nversion='0.1.0'\n",
        )
        .unwrap();
        assert_eq!(capture_build_source_stamp(&nested, None).await, "unknown");
        eprintln!(
            "build-source ignored-package fixture retained at {}",
            root.display()
        );
    }

    #[tokio::test]
    async fn build_source_stamp_missing_root_is_unknown() {
        let root = tempfile::tempdir().unwrap().keep();
        let missing = root.join("absent");
        assert_eq!(capture_build_source_stamp(&missing, None).await, "unknown");
        eprintln!(
            "build-source missing-root fixture retained at {}",
            root.display()
        );
    }

    #[test]
    fn build_source_stamp_reconcile_downgrades_on_mutation() {
        let head = "a".repeat(40);
        let other = "b".repeat(40);
        assert_eq!(reconcile_build_source_stamps(&head, &head), head);
        assert_eq!(
            reconcile_build_source_stamps(&head, &format!("{head}-dirty")),
            "unknown"
        );
        assert_eq!(reconcile_build_source_stamps(&head, &other), "unknown");
        let dirty = format!("{head}-dirty");
        assert_eq!(reconcile_build_source_stamps(&dirty, &dirty), dirty);
        assert_eq!(
            reconcile_build_source_stamps("unknown", "unknown"),
            "unknown"
        );
    }

    #[tokio::test]
    async fn build_source_stamp_overlay_base_only_ignores_ambient_worktree() {
        let (root, _head) = build_source_stamp_fixture_repo();
        std::fs::write(root.join("src/lib.rs"), "pub fn ambient_dirt() {}\n").unwrap();
        let spec = build_source_stamp_overlay_spec(
            &"a".repeat(40),
            &"c".repeat(40),
            &"d".repeat(64),
            vec![],
            vec![],
        );
        assert_eq!(
            capture_build_source_stamp(&root, Some(&spec)).await,
            "a".repeat(40)
        );
        eprintln!(
            "build-source base-only fixture retained at {}",
            root.display()
        );
    }

    #[test]
    fn build_source_stamp_overlay_stamp_tracks_selection() {
        let base = "a".repeat(40);
        let tree = "c".repeat(40);
        let fingerprint = "d".repeat(64);
        let selected = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &fingerprint,
            vec![PathBuf::from("src/lib.rs")],
            vec![],
        );
        let stamp = clean_overlay_build_source_stamp(&selected);
        assert_eq!(stamp, format!("{base}-overlay-{fingerprint}"));

        let changed_fingerprint = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &"e".repeat(64),
            vec![PathBuf::from("src/lib.rs")],
            vec![],
        );
        assert_ne!(
            stamp,
            clean_overlay_build_source_stamp(&changed_fingerprint)
        );

        let dep_root_a = PathBuf::from("/data/projects/dep-a");
        let dep_root_b = PathBuf::from("/data/projects/dep-b");
        let dep_a = build_source_stamp_overlay_spec(
            &"1".repeat(40),
            &"2".repeat(40),
            &"3".repeat(64),
            vec![],
            vec![],
        );
        let dep_b = build_source_stamp_overlay_spec(
            &"4".repeat(40),
            &"5".repeat(40),
            &"6".repeat(64),
            vec![],
            vec![],
        );
        let with_deps = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &fingerprint,
            vec![PathBuf::from("src/lib.rs")],
            vec![
                (dep_root_a.clone(), dep_a.clone()),
                (dep_root_b.clone(), dep_b.clone()),
            ],
        );
        let stamp_with_deps = clean_overlay_build_source_stamp(&with_deps);
        assert!(stamp_with_deps.starts_with(&format!("{base}-overlay-")));
        assert_ne!(stamp_with_deps, stamp);

        let reordered = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &fingerprint,
            vec![PathBuf::from("src/lib.rs")],
            vec![
                (dep_root_b.clone(), dep_b.clone()),
                (dep_root_a.clone(), dep_a.clone()),
            ],
        );
        assert_eq!(
            stamp_with_deps,
            clean_overlay_build_source_stamp(&reordered)
        );

        let dep_a_changed = build_source_stamp_overlay_spec(
            &"7".repeat(40),
            &dep_a.tree_object,
            &dep_a.overlay_fingerprint,
            vec![],
            vec![],
        );
        let changed_dep = build_source_stamp_overlay_spec(
            &base,
            &tree,
            &fingerprint,
            vec![PathBuf::from("src/lib.rs")],
            vec![(dep_root_a, dep_a_changed), (dep_root_b, dep_b)],
        );
        assert_ne!(
            stamp_with_deps,
            clean_overlay_build_source_stamp(&changed_dep)
        );
    }

    #[test]
    fn build_source_stamp_commit_env_filters_and_preserves_aliases() {
        let valid_a = "a".repeat(40);
        let valid_b = "b".repeat(7);
        let values: std::collections::HashMap<String, String> = [
            ("RCH_GIT_COMMIT", format!("  {valid_a}  ")),
            ("VERGEN_GIT_SHA", valid_b.clone()),
            ("GIT_COMMIT", "not-a-hash\n".to_owned()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        let env = build_source_commit_env(|key| values.get(key).cloned());
        assert_eq!(env.len(), rch_common::BUILD_COMMIT_ENV_VARS.len());
        assert_eq!(env["RCH_GIT_COMMIT"], valid_a);
        assert_eq!(env["VERGEN_GIT_SHA"], valid_b);
        assert_eq!(env["GIT_COMMIT"], "");
        assert_eq!(env["GITHUB_SHA"], "");
        assert_ne!(env["RCH_GIT_COMMIT"], env["VERGEN_GIT_SHA"]);
    }
}
