//! Zero-dependency, native SSH fleet deployment and read-only verification for
//! `rabs-install` (bead `rabs-root-4pidu.40`, Rule 0.75).
//!
//! Sealed transfer images are built once before contacting any host, retained
//! at mode `0400` for lost-acknowledgment recovery (`--from-image --verify`),
//! and streamed over authenticated `ssh` to a minimal POSIX `sh` receiver that
//! checks disk headroom and SHA-256 before executing the freshly verified
//! native `rabs-install` executable from the archive. Read-only verification
//! (`--verify --ssh`) never executes any installed binary on the remote host.

use super::{
    CURRENT, MAX_ARCHIVE_BYTES, MAX_MANIFEST_BYTES, Manifest, ProbeChild, Sources, Stamp, TOOLS,
    VERSIONS, check_directory, copy_staged_tools, digest_hex, directory_flags, generation_name,
    hash_regular_file, invalid, parse_unique_json, read_flags, require, require_child_ownership,
    source_paths, target_machine, unpack_archive,
};
use flate2::{Compression, GzBuilder};
use rustix::fs::{FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub(super) const TRANSFER_HEADER_BYTES: usize = 4096;
pub(super) const MIN_DEPLOY_RESERVE_MIB: u64 = 64;
pub(super) const MAX_DEPLOY_RESERVE_MIB: u64 = 64 * 1024;
pub(super) const DEFAULT_DEPLOY_RESERVE_MIB: u64 = 1024;
pub(super) const DEFAULT_SSH_TIMEOUT_SECS: u64 = 600;
pub(super) const MAX_SSH_TIMEOUT_SECS: u64 = 3600;
pub(super) const MAX_SSH_JOBS: usize = 8;
const MAX_SSH_REPLY_BYTES: usize = 256 * 1024;
const PROBE_DEADLINE_CAP_SECS: u64 = 30;
const TRANSFER_IMAGE_KIND: &str = "rabs-native-transfer-image";

#[derive(Debug, Clone)]
pub(super) struct SshOptions {
    pub(super) hosts: Vec<String>,
    pub(super) timeout_secs: u64,
    pub(super) jobs: usize,
    pub(super) reserve_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransferImageHeader {
    pub(super) schema: u8,
    pub(super) kind: String,
    pub(super) target: String,
    pub(super) bin_dir: Option<String>,
    pub(super) reserve_bytes: u64,
    pub(super) archive_bytes: u64,
    pub(super) archive_sha256: String,
    pub(super) toolset: Manifest,
}

#[derive(Debug)]
pub(super) struct SealedTransferImage {
    pub(super) path: PathBuf,
    pub(super) stamp: Stamp,
    pub(super) header: TransferImageHeader,
}

pub(super) fn target_for_machine(machine: u16) -> io::Result<&'static str> {
    match machine {
        62 => Ok("x86_64-unknown-linux-gnu"),
        183 => Ok("aarch64-unknown-linux-gnu"),
        _ => Err(invalid("unsupported Linux ELF machine for SSH deployment")),
    }
}

pub(super) fn validate_host(host: &str) -> io::Result<()> {
    require(
        !host.is_empty()
            && host.len() <= 255
            && !host.starts_with('-')
            && host.bytes().all(|b| {
                b.is_ascii_graphic()
                    && !matches!(
                        b,
                        b'\''
                            | b'"'
                            | b'\\'
                            | b';'
                            | b'|'
                            | b'&'
                            | b'$'
                            | b'`'
                            | b'('
                            | b')'
                            | b'<'
                            | b'>'
                    )
            }),
        format!("invalid SSH host specification: {host:?}"),
    )
}

pub(super) fn parse_target_spec(spec: &str) -> io::Result<(String, PathBuf)> {
    let (target, raw_path) = spec.split_once('=').ok_or_else(|| {
        invalid("--from-target requires TARGET=TAR_GZ with a supported Linux GNU target")
    })?;
    target_machine(target)?;
    require(
        !raw_path.is_empty() && !raw_path.contains('\0'),
        "--from-target requires a nonempty archive path",
    )?;
    Ok((target.to_owned(), std::path::absolute(raw_path)?))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn external_ssh() -> io::Result<PathBuf> {
    let search = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&search) {
        let path = std::path::absolute(directory.join("ssh"))?;
        if fs::metadata(&path).is_ok_and(|metadata| metadata.is_file())
            && rustix::fs::accessat(
                rustix::fs::CWD,
                &path,
                rustix::fs::Access::EXEC_OK,
                rustix::fs::AtFlags::EACCESS,
            )
            .is_ok()
        {
            return Ok(path);
        }
    }
    Err(invalid("SSH deployment requires an ssh executable on PATH"))
}

fn write_deterministic_archive(
    inputs_dir: &File,
    expected: &Manifest,
    target_file: &mut File,
) -> io::Result<()> {
    let encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(3)
        .write(&mut *target_file, Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for name in TOOLS {
        let mut reader = File::from(rustix::fs::openat(
            inputs_dir,
            name,
            read_flags(),
            Mode::empty(),
        )?);
        let stat = rustix::fs::fstat(&reader)?;
        let size = u64::try_from(stat.st_size)
            .map_err(|_| invalid("negative staged tool size during SSH seal"))?;
        require(
            size == expected.files[name].bytes,
            format!("staged tool size changed before SSH seal: {name}"),
        )?;
        let mut header = tar::Header::new_ustar();
        header.set_path(name)?;
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(size);
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append(&header, &mut reader)?;
    }
    let encoder = archive.into_inner()?;
    encoder.finish()?;
    target_file.flush()
}

/// Seal a verified toolset into one immutable, `0400` self-verifying
/// `transfer.bin` file (4 KiB JSON header + deterministic flat `.tar.gz` body)
/// before contacting any worker.
pub(super) fn seal_transfer_image(
    sources: &mut Sources,
    expected_target: Option<&str>,
    bin_dir: Option<&Path>,
    reserve_bytes: u64,
) -> io::Result<SealedTransferImage> {
    let target = target_for_machine(sources.expected.machine)?;
    if let Some(required_target) = expected_target {
        require(
            target == required_target,
            format!("archive ELF machine does not match declared target {required_target}"),
        )?;
    }
    let bin_dir_str = match bin_dir {
        Some(path) => {
            require(
                path.is_absolute() && !path.to_string_lossy().contains('\0'),
                "remote --bin-dir must be an absolute UTF-8 path",
            )?;
            let text = path
                .to_str()
                .ok_or_else(|| invalid("remote --bin-dir must be valid UTF-8"))?;
            Some(text.to_owned())
        }
        None => None,
    };
    require(
        (MIN_DEPLOY_RESERVE_MIB * 1024 * 1024..=MAX_DEPLOY_RESERVE_MIB * 1024 * 1024)
            .contains(&reserve_bytes),
        "deployment reserve must be between 64 MiB and 65536 MiB",
    )?;

    // Build inputs/ and release.tar.gz in a scoped private temporary directory
    // so only the single 0400 transfer.bin image is retained for lost-ACK recovery.
    let work = tempfile::Builder::new()
        .prefix("rabs-deploy-seal-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    fs::set_permissions(work.path(), fs::Permissions::from_mode(0o700))?;
    let work_dir = File::from(rustix::fs::open(
        work.path(),
        directory_flags(),
        Mode::empty(),
    )?);
    check_directory(&work_dir, true)?;

    rustix::fs::mkdirat(&work_dir, "inputs", Mode::from_raw_mode(0o700))?;
    let inputs_dir = super::open_directory_at(&work_dir, "inputs", true)?;
    copy_staged_tools(sources, &inputs_dir)?;

    let mut archive_file = File::from(rustix::fs::openat(
        &work_dir,
        "release.tar.gz",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    write_deterministic_archive(&inputs_dir, &sources.expected, &mut archive_file)?;
    archive_file.sync_all()?;
    let archive_stamp = Stamp::of(&rustix::fs::fstat(&archive_file)?);
    let (archive_bytes, archive_sha256) = hash_regular_file(&mut archive_file, &archive_stamp)?;

    let header = TransferImageHeader {
        schema: 1,
        kind: TRANSFER_IMAGE_KIND.to_owned(),
        target: target.to_owned(),
        bin_dir: bin_dir_str,
        reserve_bytes,
        archive_bytes,
        archive_sha256,
        toolset: sources.expected.clone(),
    };
    let mut header_bytes = serde_json::to_vec(&header)?;
    require(
        header_bytes.len() < TRANSFER_HEADER_BYTES,
        "transfer image header exceeds its fixed 4 KiB frame",
    )?;
    header_bytes.resize(TRANSFER_HEADER_BYTES - 1, b' ');
    header_bytes.push(b'\n');

    let stage_path = tempfile::Builder::new()
        .prefix("rabs-deploy-send-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?
        .keep();
    fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o700))?;
    let stage_dir = File::from(rustix::fs::open(
        &stage_path,
        directory_flags(),
        Mode::empty(),
    )?);
    check_directory(&stage_dir, true)?;

    let mut wire = File::from(rustix::fs::openat(
        &stage_dir,
        "transfer.bin",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    wire.write_all(&header_bytes)?;
    archive_file.seek(SeekFrom::Start(0))?;
    let copied = io::copy(&mut (&mut archive_file).take(archive_bytes + 1), &mut wire)?;
    require(
        copied == archive_bytes,
        "archive changed size while sealing transfer image",
    )?;
    wire.flush()?;
    rustix::fs::fchmod(&wire, Mode::from_raw_mode(0o400))?;
    wire.sync_all()?;
    stage_dir.sync_all()?;
    drop(archive_file);
    drop(inputs_dir);
    drop(work_dir);
    drop(work);

    let stamp = Stamp::of(&rustix::fs::fstat(&wire)?);
    let path = stage_path.join("transfer.bin");
    // Independently verify the sealed image through the same reader used by --from-image.
    let loaded = load_transfer_image(&path)?;
    require(
        loaded.archive_sha256 == header.archive_sha256
            && loaded.archive_bytes == header.archive_bytes
            && loaded.toolset == header.toolset,
        "sealed transfer image failed self-verification",
    )?;
    Ok(SealedTransferImage {
        path,
        stamp,
        header,
    })
}

/// Read and cryptographically verify a retained `transfer.bin` image for
/// read-only lost-acknowledgment verification (`--from-image --verify`).
pub(super) fn load_transfer_image(path: &Path) -> io::Result<TransferImageHeader> {
    let mut file = File::from(rustix::fs::open(path, read_flags(), Mode::empty())?);
    let before_stat = rustix::fs::fstat(&file)?;
    let before = Stamp::of(&before_stat);
    require(
        FileType::from_raw_mode(before_stat.st_mode) == FileType::RegularFile,
        "retained transfer image must be a regular file",
    )?;
    let total_size =
        u64::try_from(before_stat.st_size).map_err(|_| invalid("invalid transfer image size"))?;
    let header_len = TRANSFER_HEADER_BYTES as u64;
    require(
        total_size > header_len && total_size <= header_len + MAX_ARCHIVE_BYTES,
        "retained transfer image has invalid byte length",
    )?;

    let mut header_buf = [0_u8; TRANSFER_HEADER_BYTES];
    file.read_exact(&mut header_buf)?;
    let parsed_map = parse_unique_json(&header_buf)?;
    let header: TransferImageHeader =
        serde_json::from_value(Value::Object(parsed_map.into_iter().collect()))
            .map_err(|err| invalid(format!("invalid retained transfer image header: {err}")))?;
    require(
        header.schema == 1 && header.kind == TRANSFER_IMAGE_KIND,
        "unsupported retained transfer image schema or kind",
    )?;
    header.toolset.validate()?;
    require(
        target_machine(&header.target)? == header.toolset.machine,
        "transfer image target disagrees with its toolset ELF machine",
    )?;
    require(
        is_sha256_hex(&header.archive_sha256) && header.archive_bytes == total_size - header_len,
        "transfer image archive digest or length header is invalid",
    )?;
    if let Some(ref dir) = header.bin_dir {
        require(
            Path::new(dir).is_absolute() && !dir.contains('\0'),
            "transfer image carries an invalid bin_dir",
        )?;
    }

    let mut hasher = Sha256::new();
    let mut remaining = header.archive_bytes;
    let mut buf = [0_u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..want])?;
        require(n > 0, "retained transfer image was truncated")?;
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    require(
        file.read(&mut buf[..1])? == 0,
        "retained transfer image grew during verification",
    )?;
    require(
        Stamp::of(&rustix::fs::fstat(&file)?) == before,
        "retained transfer image changed during verification",
    )?;
    require(
        digest_hex(&hasher.finalize()) == header.archive_sha256,
        "retained transfer image payload digest mismatch",
    )?;
    Ok(header)
}

struct SshReply {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum StdinPayload<'a> {
    Empty,
    SealedImageBody(&'a SealedTransferImage),
}

fn run_ssh(
    ssh_bin: &Path,
    host: &str,
    remote_script: &str,
    payload: StdinPayload<'_>,
    deadline: Instant,
) -> io::Result<SshReply> {
    require_child_ownership()?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "SSH deployment deadline expired before starting",
        ));
    }
    let connect_timeout = remaining.as_secs().clamp(1, PROBE_DEADLINE_CAP_SECS);
    let mut cmd = Command::new(ssh_bin);
    cmd.arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg(format!("ConnectTimeout={connect_timeout}"))
        .arg("-o")
        .arg("ServerAliveInterval=15")
        .arg("-o")
        .arg("ServerAliveCountMax=3")
        .arg("--")
        .arg(host)
        .arg(remote_script)
        .stdin(match payload {
            StdinPayload::Empty => Stdio::null(),
            StdinPayload::SealedImageBody(_) => Stdio::piped(),
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);

    let mut child = cmd.spawn()?;
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| invalid("ssh stdout pipe unavailable"))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| invalid("ssh stderr pipe unavailable"))?;

    let writer_handle = match payload {
        StdinPayload::Empty => None,
        StdinPayload::SealedImageBody(image) => {
            let mut stdin_pipe = child
                .stdin
                .take()
                .ok_or_else(|| invalid("ssh stdin pipe unavailable"))?;
            let path = image.path.clone();
            let expected_stamp = image.stamp.clone();
            let expected_bytes = image.header.archive_bytes;
            Some(std::thread::spawn(move || -> io::Result<()> {
                let mut reader = File::from(rustix::fs::open(&path, read_flags(), Mode::empty())?);
                require(
                    Stamp::of(&rustix::fs::fstat(&reader)?) == expected_stamp,
                    "sealed transfer image changed before streaming",
                )?;
                reader.seek(SeekFrom::Start(TRANSFER_HEADER_BYTES as u64))?;
                let mut remaining = expected_bytes;
                let mut buf = [0_u8; 64 * 1024];
                while remaining > 0 {
                    let want = remaining.min(buf.len() as u64) as usize;
                    let n = reader.read(&mut buf[..want])?;
                    require(n > 0, "sealed transfer image truncated while streaming")?;
                    if let Err(err) = stdin_pipe.write_all(&buf[..n]) {
                        // Remote may exit early (e.g., headroom preflight failed);
                        // surface remote stderr rather than masking with EPIPE.
                        if err.kind() == io::ErrorKind::BrokenPipe {
                            break;
                        }
                        return Err(err);
                    }
                    remaining -= n as u64;
                }
                let _ = stdin_pipe.flush();
                drop(stdin_pipe);
                require(
                    Stamp::of(&rustix::fs::fstat(&reader)?) == expected_stamp,
                    "sealed transfer image changed during streaming",
                )?;
                Ok(())
            }))
        }
    };

    let stdout_reader = std::thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        (&mut stdout_pipe)
            .take((MAX_SSH_REPLY_BYTES as u64) + 1)
            .read_to_end(&mut buf)?;
        Ok(buf)
    });
    let stderr_reader = std::thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        (&mut stderr_pipe)
            .take((MAX_SSH_REPLY_BYTES as u64) + 1)
            .read_to_end(&mut buf)?;
        Ok(buf)
    });

    let mut probe = ProbeChild { child, owned: true };
    let status = loop {
        if probe.waitable()? {
            break probe.finish()?;
        }
        if Instant::now() >= deadline {
            let _ = probe.finish();
            if let Some(handle) = writer_handle {
                let _ = handle.join();
            }
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SSH operation exceeded its per-worker deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    if let Some(handle) = writer_handle {
        handle
            .join()
            .map_err(|_| invalid("SSH stdin writer thread panicked"))??;
    }
    let stdout = stdout_reader
        .join()
        .map_err(|_| invalid("SSH stdout reader thread panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| invalid("SSH stderr reader thread panicked"))??;
    require(
        stdout.len() <= MAX_SSH_REPLY_BYTES && stderr.len() <= MAX_SSH_REPLY_BYTES,
        "SSH reply exceeded bounded byte limit",
    )?;
    Ok(SshReply {
        status,
        stdout,
        stderr,
    })
}

fn format_ssh_failure(context: &str, reply: &SshReply) -> io::Error {
    let stderr = String::from_utf8_lossy(&reply.stderr).trim().to_owned();
    let snippet: String = stderr.chars().take(1024).collect();
    if snippet.is_empty() {
        invalid(format!("{context}: ssh exited with {}", reply.status))
    } else {
        invalid(format!("{context}: {snippet}"))
    }
}

fn probe_remote_platform(ssh_bin: &Path, host: &str, deadline: Instant) -> io::Result<String> {
    let probe_deadline =
        deadline.min(Instant::now() + Duration::from_secs(PROBE_DEADLINE_CAP_SECS));
    let script = "set -eu\nprintf 'RABS_PROBE\\t%s\\t%s\\t%s\\n' \"$(uname -s)\" \"$(uname -m)\" \"${HOME:-}\"";
    let reply = run_ssh(ssh_bin, host, script, StdinPayload::Empty, probe_deadline)?;
    if !reply.status.success() {
        return Err(format_ssh_failure("remote platform probe failed", &reply));
    }
    let text = std::str::from_utf8(&reply.stdout)
        .map_err(|_| invalid("remote platform probe emitted non-UTF-8"))?;
    let mut lines = text.lines();
    let line = lines
        .next()
        .ok_or_else(|| invalid("empty remote platform probe reply"))?;
    require(
        lines.next().is_none(),
        "unexpected multi-line remote platform probe reply",
    )?;
    let parts: Vec<&str> = line.split('\t').collect();
    require(
        parts.len() == 4 && parts[0] == "RABS_PROBE",
        "malformed remote platform probe reply",
    )?;
    require(
        parts[1] == "Linux",
        format!("remote host is not Linux (got {:?})", parts[1]),
    )?;
    match parts[2] {
        "x86_64" => Ok("x86_64-unknown-linux-gnu".to_owned()),
        "aarch64" => Ok("aarch64-unknown-linux-gnu".to_owned()),
        other => Err(invalid(format!(
            "unsupported remote Linux architecture: {other}"
        ))),
    }
}

fn build_remote_deploy_script(image: &SealedTransferImage, probe: bool) -> String {
    let bin_dir_expr = match &image.header.bin_dir {
        Some(dir) => shell_quote(dir),
        None => "\"${HOME:?HOME is unavailable}/.local/bin\"".to_owned(),
    };
    let required_bytes = image
        .header
        .archive_bytes
        .saturating_mul(2)
        .saturating_add(image.header.reserve_bytes);
    let required_kib = required_bytes.div_ceil(1024);
    let probe_arg = if probe { " --probe" } else { "" };
    format!(
        "set -eu\n\
         umask 077\n\
         bin_dir={bin_dir_expr}\n\
         stage=\"$(mktemp -d \"${{TMPDIR:-/tmp}}/rabs-deploy-recv-XXXXXX\")\"\n\
         check_dir=\"$bin_dir\"\n\
         while [ ! -d \"$check_dir\" ] && [ \"$check_dir\" != \"/\" ]; do check_dir=\"$(dirname \"$check_dir\")\"; done\n\
         avail_kib=\"$(df -Pk \"$stage\" | awk 'NR==2 {{print $4}}')\"\n\
         [ \"$avail_kib\" -ge {required_kib} ] || {{ printf 'insufficient deployment headroom on %s\\n' \"$stage\" >&2; exit 1; }}\n\
         avail_bin_kib=\"$(df -Pk \"$check_dir\" | awk 'NR==2 {{print $4}}')\"\n\
         [ \"$avail_bin_kib\" -ge {required_kib} ] || {{ printf 'insufficient deployment headroom on %s\\n' \"$check_dir\" >&2; exit 1; }}\n\
         cat > \"$stage/release.tar.gz\"\n\
         actual_bytes=\"$(wc -c < \"$stage/release.tar.gz\" | tr -d '[:space:]')\"\n\
         [ \"$actual_bytes\" = \"{archive_bytes}\" ] || {{ printf 'truncated or oversized deployment stream\\n' >&2; exit 1; }}\n\
         actual_sha=\"$(sha256sum \"$stage/release.tar.gz\" | awk '{{print $1}}')\"\n\
         [ \"$actual_sha\" = \"{archive_sha256}\" ] || {{ printf 'deployment archive digest mismatch\\n' >&2; exit 1; }}\n\
         mkdir -m 700 \"$stage/boot\"\n\
         tar -xzf \"$stage/release.tar.gz\" -C \"$stage/boot\" rabs-install\n\
         chmod 500 \"$stage/boot/rabs-install\"\n\
         exec \"$stage/boot/rabs-install\" --from-archive \"$stage/release.tar.gz\" --bin-dir \"$bin_dir\"{probe_arg}\n",
        archive_bytes = image.header.archive_bytes,
        archive_sha256 = image.header.archive_sha256,
    )
}

fn validate_remote_install_receipt(
    raw: &[u8],
    expected: &TransferImageHeader,
) -> io::Result<Value> {
    let map = parse_unique_json(raw)?;
    let value = Value::Object(map.into_iter().collect());
    require(
        value.get("kind").and_then(Value::as_str) == Some("rabs-installed"),
        "remote installer did not return a rabs-installed receipt",
    )?;
    let generation = value
        .get("generation")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("remote installer receipt missing generation"))?;
    generation_name(&format!("{VERSIONS}/{generation}"))?;
    require(
        value.get("services_started").and_then(Value::as_bool) == Some(false)
            && value.get("cargo_config_changed").and_then(Value::as_bool) == Some(false),
        "remote installer receipt reported unexpected side effects",
    )?;
    require(
        value.get("machine").and_then(Value::as_u64) == Some(u64::from(expected.toolset.machine)),
        "remote installer machine disagrees with transferred toolset",
    )?;
    if let Some(ref requested_dir) = expected.bin_dir {
        require(
            value.get("bin_dir").and_then(Value::as_str) == Some(requested_dir.as_str()),
            "remote installer activated a different bin_dir than requested",
        )?;
    }
    let files = value
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("remote installer receipt missing files table"))?;
    require(
        files.len() == TOOLS.len(),
        "remote installer receipt reported wrong tool count",
    )?;
    for (name, identity) in &expected.toolset.files {
        let reported = files
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| invalid(format!("remote installer receipt missing tool {name}")))?;
        require(
            reported.get("bytes").and_then(Value::as_u64) == Some(identity.bytes)
                && reported.get("sha256").and_then(Value::as_str) == Some(identity.sha256.as_str()),
            format!("remote installer receipt disagrees on {name}"),
        )?;
    }
    Ok(value)
}

fn deploy_one_host(
    ssh_bin: &Path,
    host: &str,
    images: &BTreeMap<String, SealedTransferImage>,
    timeout: Duration,
    probe: bool,
) -> Value {
    let deadline = Instant::now() + timeout;
    let target = match probe_remote_platform(ssh_bin, host, deadline) {
        Ok(target) => target,
        Err(error) => {
            return json!({
                "host": host,
                "state": "failed",
                "error": error.to_string(),
            });
        }
    };
    let Some(image) = images.get(&target) else {
        return json!({
            "host": host,
            "target": target,
            "state": "failed",
            "error": format!("no authenticated archive supplied for {target}"),
        });
    };
    let script = build_remote_deploy_script(image, probe);
    let reply = match run_ssh(
        ssh_bin,
        host,
        &script,
        StdinPayload::SealedImageBody(image),
        deadline,
    ) {
        Ok(reply) => reply,
        Err(error) => {
            return json!({
                "host": host,
                "target": target,
                "state": "failed",
                "error": error.to_string(),
            });
        }
    };
    if !reply.status.success() {
        return json!({
            "host": host,
            "target": target,
            "state": "failed",
            "error": format_ssh_failure("remote installation failed", &reply).to_string(),
        });
    }
    match validate_remote_install_receipt(&reply.stdout, &image.header) {
        Ok(receipt) => json!({
            "host": host,
            "target": target,
            "state": "installed",
            "receipt": receipt,
        }),
        Err(error) => json!({
            "host": host,
            "target": target,
            "state": "failed",
            "error": error.to_string(),
        }),
    }
}

fn run_parallel_hosts<F>(hosts: &[String], jobs: usize, work: F) -> Vec<Value>
where
    F: Fn(&str) -> Value + Sync,
{
    let worker_count = jobs.clamp(1, MAX_SSH_JOBS).min(hosts.len().max(1));
    let next_index = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Value>>> = (0..hosts.len()).map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let next_index = &next_index;
            let slots = &slots;
            let work = &work;
            scope.spawn(move || {
                loop {
                    let idx = next_index.fetch_add(1, Ordering::Relaxed);
                    if idx >= hosts.len() {
                        break;
                    }
                    let outcome = work(&hosts[idx]);
                    if let Ok(mut guard) = slots[idx].lock() {
                        *guard = Some(outcome);
                    }
                }
            });
        }
    });
    slots
        .into_iter()
        .enumerate()
        .map(|(idx, slot)| {
            slot.into_inner().ok().flatten().unwrap_or_else(
                || json!({"host": hosts[idx], "state": "failed", "error": "worker slot abandoned"}),
            )
        })
        .collect()
}

pub(super) fn deploy_single(
    sources: &mut Sources,
    bin_dir: Option<&Path>,
    ssh: &SshOptions,
    probe: bool,
) -> io::Result<(Value, bool)> {
    let ssh_bin = external_ssh()?;
    let image = seal_transfer_image(sources, None, bin_dir, ssh.reserve_bytes)?;
    let image_path = image.path.clone();
    let target = image.header.target.clone();
    let mut images = BTreeMap::new();
    images.insert(target, image);
    let timeout = Duration::from_secs(ssh.timeout_secs);
    let workers = run_parallel_hosts(&ssh.hosts, ssh.jobs, |host| {
        deploy_one_host(&ssh_bin, host, &images, timeout, probe)
    });
    let all_ok = workers.iter().all(|w| w["state"] == "installed");
    Ok((
        json!({
            "kind": "rabs-deployed",
            "workers": workers,
            "transfer_image": image_path,
            "services_started": false,
            "cargo_config_changed": false,
        }),
        all_ok,
    ))
}

pub(super) fn deploy_targets(
    specs: &[(String, PathBuf)],
    bin_dir: Option<&Path>,
    ssh: &SshOptions,
    probe: bool,
) -> io::Result<(Value, bool)> {
    let ssh_bin = external_ssh()?;
    // Validate, unpack, ELF-check, and seal EVERY archive BEFORE contacting any worker.
    let mut images = BTreeMap::new();
    let mut image_paths = BTreeMap::new();
    for (target, archive_path) in specs {
        let stage = tempfile::Builder::new()
            .prefix("rabs-deploy-bundle-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700))?;
        unpack_archive(archive_path, stage.path(), MAX_ARCHIVE_BYTES)?;
        let mut sources = Sources::capture(source_paths(stage.path(), false))?;
        let sealed = seal_transfer_image(&mut sources, Some(target), bin_dir, ssh.reserve_bytes)?;
        image_paths.insert(target.clone(), sealed.path.clone());
        images.insert(target.clone(), sealed);
    }
    let timeout = Duration::from_secs(ssh.timeout_secs);
    let workers = run_parallel_hosts(&ssh.hosts, ssh.jobs, |host| {
        deploy_one_host(&ssh_bin, host, &images, timeout, probe)
    });
    let all_ok = workers.iter().all(|w| w["state"] == "installed");
    Ok((
        json!({
            "kind": "rabs-deployed",
            "workers": workers,
            "transfer_images": image_paths,
            "services_started": false,
            "cargo_config_changed": false,
        }),
        all_ok,
    ))
}

fn build_remote_verify_script(bin_dir: Option<&Path>) -> String {
    let bin_dir_expr = match bin_dir {
        Some(dir) => shell_quote(&dir.to_string_lossy()),
        None => "\"${HOME:?HOME is unavailable}/.local/bin\"".to_owned(),
    };
    let tools_list = TOOLS.join(" ");
    format!(
        "set -eu\n\
         bin_dir={bin_dir_expr}\n\
         uid=\"$(id -u)\"\n\
         printf 'UID\\t%s\\n' \"$uid\"\n\
         printf 'UNAME\\t%s\\t%s\\n' \"$(uname -s)\" \"$(uname -m)\"\n\
         printf 'BIN_DIR\\t%s\\n' \"$bin_dir\"\n\
         printf 'DIR_STAT\\t%s\\n' \"$(stat -c '%u %a %F' \"$bin_dir\")\"\n\
         printf 'VER_STAT\\t%s\\n' \"$(stat -c '%u %a %F' \"$bin_dir/{VERSIONS}\")\"\n\
         cur=\"$(readlink \"$bin_dir/{CURRENT}\")\"\n\
         case \"$cur\" in .rabs-versions/*) : ;; *) printf 'invalid .rabs-current target\\n' >&2; exit 1 ;; esac\n\
         case \"${{cur#.rabs-versions/}}\" in ''|*/*|.|..) printf 'invalid generation name\\n' >&2; exit 1 ;; esac\n\
         printf 'CURRENT\\t%s\\n' \"$cur\"\n\
         gen=\"$bin_dir/$cur\"\n\
         printf 'GEN_STAT\\t%s\\n' \"$(stat -c '%u %a %F' \"$gen\")\"\n\
         ls -A \"$gen\" | LC_ALL=C sort | while IFS= read -r entry; do printf 'GEN_ENTRY\\t%s\\n' \"$entry\"; done\n\
         for t in {tools_list}; do\n\
             lnk=\"$(readlink \"$bin_dir/$t\")\"\n\
             st=\"$(stat -c '%u %a %h %s %F' \"$gen/$t\")\"\n\
             sh=\"$(sha256sum \"$gen/$t\" | awk '{{print $1}}')\"\n\
             printf 'TOOL\\t%s\\t%s\\t%s\\t%s\\n' \"$t\" \"$lnk\" \"$st\" \"$sh\"\n\
         done\n\
         printf 'MANIFEST_STAT\\t%s\\n' \"$(stat -c '%u %a %h %s %F' \"$gen/manifest.json\")\"\n\
         printf 'MANIFEST_BEGIN\\n'\n\
         head -c {max_manifest} \"$gen/manifest.json\"\n\
         printf '\\nMANIFEST_END\\n'\n",
        max_manifest = MAX_MANIFEST_BYTES + 1,
    )
}

fn parse_octal_mode(text: &str) -> io::Result<u32> {
    u32::from_str_radix(text, 8).map_err(|_| invalid(format!("invalid octal mode: {text}")))
}

fn check_stat_dir(stat_line: &str, expected_uid: &str, private: bool) -> io::Result<()> {
    let mut parts = stat_line.splitn(3, ' ');
    let uid = parts.next().unwrap_or("");
    let mode_str = parts.next().unwrap_or("");
    let kind = parts.next().unwrap_or("");
    let mode = parse_octal_mode(mode_str)?;
    let mask = if private { 0o077 } else { 0o022 };
    require(
        uid == expected_uid && kind == "directory" && mode & mask == 0,
        format!("remote directory has unsafe ownership or permissions ({stat_line})"),
    )
}

fn verify_remote_output(
    stdout: &[u8],
    expected: &Manifest,
    expected_bin_dir: Option<&Path>,
) -> io::Result<Value> {
    let text = std::str::from_utf8(stdout)
        .map_err(|_| invalid("remote verification emitted non-UTF-8"))?;
    let (header_part, manifest_tail) = text
        .split_once("\nMANIFEST_BEGIN\n")
        .ok_or_else(|| invalid("remote verification reply missing manifest block"))?;
    let manifest_raw = manifest_tail
        .strip_suffix("\nMANIFEST_END\n")
        .ok_or_else(|| invalid("remote verification reply truncated manifest block"))?;
    require(
        manifest_raw.len() as u64 <= MAX_MANIFEST_BYTES,
        "remote manifest exceeds byte limit",
    )?;

    let mut uid = None;
    let mut bin_dir = None;
    let mut current = None;
    let mut dir_stat = None;
    let mut ver_stat = None;
    let mut gen_stat = None;
    let mut actual_entries = BTreeSet::new();
    let mut manifest_stat = None;
    let mut remote_machine = None;
    let mut tools = BTreeMap::new();

    for line in header_part.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["UID", val] => uid = Some(*val),
            ["UNAME", sys, mach] => {
                require(*sys == "Linux", "remote verification target is not Linux")?;
                remote_machine = Some(match *mach {
                    "x86_64" => 62_u16,
                    "aarch64" => 183_u16,
                    _ => return Err(invalid("unsupported remote architecture")),
                });
            }
            ["BIN_DIR", val] => bin_dir = Some(*val),
            ["DIR_STAT", val] => dir_stat = Some(*val),
            ["VER_STAT", val] => ver_stat = Some(*val),
            ["CURRENT", val] => current = Some(*val),
            ["GEN_STAT", val] => gen_stat = Some(*val),
            ["GEN_ENTRY", val] => {
                require(
                    !val.is_empty() && actual_entries.insert(*val),
                    "duplicate or empty remote generation entry",
                )?;
            }
            ["MANIFEST_STAT", val] => manifest_stat = Some(*val),
            ["TOOL", name, link_target, stat_str, sha] => {
                require(
                    tools
                        .insert((*name).to_owned(), (*link_target, *stat_str, *sha))
                        .is_none(),
                    format!("duplicate remote verification tool entry: {name}"),
                )?;
            }
            _ => return Err(invalid("unexpected remote verification output line")),
        }
    }

    let uid = uid.ok_or_else(|| invalid("missing remote uid"))?;
    let bin_dir = bin_dir.ok_or_else(|| invalid("missing remote bin_dir"))?;
    if let Some(req) = expected_bin_dir {
        require(
            Path::new(bin_dir) == req,
            "remote verification reported a different bin_dir than requested",
        )?;
    }
    let current = current.ok_or_else(|| invalid("missing remote active generation link"))?;
    let machine = remote_machine.ok_or_else(|| invalid("missing remote architecture"))?;
    require(
        machine == expected.machine,
        "expected toolset is not native to remote host",
    )?;
    check_stat_dir(
        dir_stat.ok_or_else(|| invalid("missing remote bin_dir stat"))?,
        uid,
        false,
    )?;
    check_stat_dir(
        ver_stat.ok_or_else(|| invalid("missing remote .rabs-versions stat"))?,
        uid,
        true,
    )?;
    check_stat_dir(
        gen_stat.ok_or_else(|| invalid("missing remote generation stat"))?,
        uid,
        true,
    )?;
    let generation = generation_name(current)?;

    let mut expected_entries: BTreeSet<&str> = TOOLS.into_iter().collect();
    expected_entries.insert("manifest.json");
    require(
        actual_entries == expected_entries,
        "remote generation directory contains unexpected or missing entries",
    )?;

    // Validate manifest.json metadata and parsed content.
    let mstat = manifest_stat.ok_or_else(|| invalid("missing remote manifest stat"))?;
    let mut mparts = mstat.splitn(5, ' ');
    let m_uid = mparts.next().unwrap_or("");
    let m_mode = parse_octal_mode(mparts.next().unwrap_or(""))?;
    let m_links: u64 = mparts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| invalid("invalid remote manifest link count"))?;
    let m_size: u64 = mparts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| invalid("invalid remote manifest size"))?;
    let m_kind = mparts.next().unwrap_or("");
    require(
        m_uid == uid
            && m_mode == 0o600
            && m_links == 1
            && (1..=MAX_MANIFEST_BYTES).contains(&m_size)
            && m_size == manifest_raw.len() as u64
            && m_kind == "regular file",
        "remote manifest has unsafe ownership, permissions, link count, size, or type",
    )?;
    let _ = parse_unique_json(manifest_raw.as_bytes())?;
    let parsed_manifest: Manifest = serde_json::from_str(manifest_raw)
        .map_err(|err| invalid(format!("invalid remote manifest JSON: {err}")))?;
    parsed_manifest.validate()?;
    require(
        parsed_manifest == *expected,
        "remote manifest disagrees with expected toolset",
    )?;

    // Validate every tool symlink, metadata, byte size, and SHA-256.
    require(tools.len() == TOOLS.len(), "incomplete remote tool list")?;
    for name in TOOLS {
        let (link_target, stat_str, sha) = tools
            .get(name)
            .ok_or_else(|| invalid(format!("missing remote tool report: {name}")))?;
        require(
            *link_target == format!("{CURRENT}/{name}"),
            format!("remote public symlink {name} does not target active generation"),
        )?;
        let mut parts = stat_str.splitn(5, ' ');
        let t_uid = parts.next().unwrap_or("");
        let t_mode = parse_octal_mode(parts.next().unwrap_or(""))?;
        let t_links: u64 = parts
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| invalid("invalid remote tool link count"))?;
        let t_size: u64 = parts
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| invalid("invalid remote tool size"))?;
        let t_kind = parts.next().unwrap_or("");
        let expected_tool = &expected.files[name];
        require(
            t_uid == uid
                && t_mode == 0o555
                && t_links == 1
                && t_kind == "regular file"
                && t_size == expected_tool.bytes
                && *sha == expected_tool.sha256,
            format!("remote installed executable failed verification: {name}"),
        )?;
    }

    Ok(json!({
        "kind": "rabs-install-verification",
        "state": "verified",
        "transport": "ssh",
        "bin_dir": bin_dir,
        "generation": generation,
        "machine": expected.machine,
        "files": expected.files,
        "expected_toolset_sha256": expected.digest()?,
        "installation_changed": false,
        "services_started": false,
        "cargo_config_changed": false,
    }))
}

pub(super) fn verify_hosts(
    expected: &Manifest,
    bin_dir: Option<&Path>,
    ssh: &SshOptions,
) -> io::Result<(Value, bool)> {
    expected.validate()?;
    let ssh_bin = external_ssh()?;
    let expected_digest = expected.digest()?;
    let script = build_remote_verify_script(bin_dir);
    let timeout = Duration::from_secs(ssh.timeout_secs);
    let workers = run_parallel_hosts(&ssh.hosts, ssh.jobs, |host| {
        let deadline = Instant::now() + timeout;
        match run_ssh(&ssh_bin, host, &script, StdinPayload::Empty, deadline) {
            Ok(reply) if reply.status.success() => {
                match verify_remote_output(&reply.stdout, expected, bin_dir) {
                    Ok(receipt) => json!({
                        "host": host,
                        "state": "verified",
                        "receipt": receipt,
                    }),
                    Err(error) => json!({
                        "host": host,
                        "state": "unverified",
                        "error": error.to_string(),
                    }),
                }
            }
            Ok(reply) => json!({
                "host": host,
                "state": "unverified",
                "error": format_ssh_failure("remote verification failed", &reply).to_string(),
            }),
            Err(error) => json!({
                "host": host,
                "state": "unverified",
                "error": error.to_string(),
            }),
        }
    });
    let all_ok = workers.iter().all(|w| w["state"] == "verified");
    Ok((
        json!({
            "kind": "rabs-verified",
            "workers": workers,
            "expected_toolset_sha256": expected_digest,
            "installation_changed": false,
            "services_started": false,
            "cargo_config_changed": false,
        }),
        all_ok,
    ))
}
