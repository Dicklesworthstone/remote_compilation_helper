//! Rsync selects source members; tar only transports their literal names.
//!
//! Do not translate rsync globs into tar globs: directory-only exclusions and
//! first-match-wins includes have different meanings in the two tools (#109).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

mod windows_paths;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Member {
    pub path: PathBuf,
    pub kind: Kind,
}

/// Rsync quotes unsafe bytes, and a backslash before an escape-looking name,
/// as `\#ooo`. Decode ONCE: a literal `\#012` must not turn into a newline.
fn decode_name(name: &str) -> Result<String> {
    let input = name.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index..].starts_with(b"\\#")
            && input.len() - index >= 5
            && matches!(input[index + 2], b'0'..=b'3')
            && input[index + 3..index + 5]
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'7'))
        {
            output.push(
                (input[index + 2] - b'0') * 64
                    + (input[index + 3] - b'0') * 8
                    + (input[index + 4] - b'0'),
            );
            index += 5;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
    String::from_utf8(output).context("source filename is not UTF-8 after rsync decoding")
}

pub(super) fn parse_members(output: &[u8]) -> Result<Vec<Member>> {
    let output = std::str::from_utf8(output).context("source enumeration is not UTF-8")?;
    anyhow::ensure!(
        output.is_empty() || output.ends_with('\n'),
        "source enumeration ended in an incomplete record"
    );
    let mut members = Vec::new();
    for line in output.split_terminator('\n') {
        if line.is_empty() || line.starts_with("created directory ") {
            continue;
        }
        let (itemized, name) = line
            .split_once('\t')
            .context("source enumeration record lacks its tab separator")?;
        let item = itemized.as_bytes();
        anyhow::ensure!(
            matches!(item.len(), 11 | 12)
                && matches!(item[0], b'<' | b'>' | b'c' | b'.' | b'h')
                && item[2..]
                    .iter()
                    .all(|byte| b".+ cstpoguaxfnTb".contains(byte)),
            "unexpected source enumeration item {itemized:?}"
        );
        let kind = match item[1] {
            b'f' => Kind::File,
            b'd' => Kind::Directory,
            b'L' => Kind::Symlink,
            _ => anyhow::bail!("unsupported source enumeration item {itemized:?}"),
        };
        let name = decode_name(name)?;
        if kind == Kind::Directory && name == "./" {
            continue;
        }
        let relative = name.strip_prefix("./").unwrap_or(&name);
        let relative = if kind == Kind::Directory {
            relative.strip_suffix('/').unwrap_or(relative)
        } else {
            relative
        };
        anyhow::ensure!(
            !relative.is_empty()
                && !relative.chars().any(char::is_control)
                && relative.split('/').all(|part| !matches!(part, "" | "." | ".."))
                && !Path::new(relative).is_absolute(),
            "unsafe source path emitted by rsync: {name:?}"
        );
        members.push(Member {
            path: PathBuf::from(relative),
            kind,
        });
    }
    members.sort_by(|left, right| left.path.cmp(&right.path));
    anyhow::ensure!(
        !members.windows(2).any(|pair| pair[0].path == pair[1].path),
        "source enumeration emitted duplicate paths"
    );
    Ok(members)
}

/// Receipts and explicit clean overlays retain their regular-file-only gate.
/// Ordinary archives may carry symlinks without following them; a proof may not.
pub(super) fn regular_paths(members: Vec<Member>) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for member in members {
        match member.kind {
            Kind::File => paths.push(member.path),
            Kind::Directory => {}
            Kind::Symlink => anyhow::bail!(
                "source-content proof refuses non-regular rsync item at {:?}",
                member.path
            ),
        }
    }
    Ok(paths)
}

/// Explicit regular-file overlays need the same Windows namespace admission
/// as ordinary archives, without changing the POSIX receipt path contract.
pub(super) fn validate_windows_paths(paths: &[PathBuf]) -> Result<()> {
    let members = paths
        .iter()
        .map(|path| Member {
            path: path.clone(),
            kind: Kind::File,
        })
        .collect::<Vec<_>>();
    windows_paths::validate(&members)
}

/// NUL-delimited names are data, never tar options, globs or recursive roots.
/// Keep the tempfile alive until the producer exits or is cancelled.
pub(super) async fn manifest(members: &[Member]) -> Result<(tempfile::NamedTempFile, u32)> {
    // Reject the whole selected namespace before creating a manifest or
    // contacting the receiver. A per-file check cannot detect parent aliases.
    windows_paths::validate(members)?;
    let manifest = tempfile::Builder::new()
        .prefix("rch-source-members-")
        .tempfile()
        .context("create source archive manifest")?;
    let mut writer = tokio::fs::File::from_std(manifest.reopen()?);
    let mut count = 0_u32;
    for member in members {
        let path = member.path.to_str().context("non-UTF-8 archive member")?;
        writer.write_all(b"./").await?;
        writer.write_all(path.as_bytes()).await?;
        writer.write_all(&[0]).await?;
        if member.kind == Kind::File {
            count = count.checked_add(1).context("source file-count limit exceeded")?;
        }
    }
    writer.flush().await.context("flush source archive manifest")?;
    drop(writer);
    Ok((manifest, count))
}

pub(super) fn tar_command(root: &Path, manifest: &Path) -> Command {
    let mut command = Command::new("tar");
    command
        .args(["--create", "--gzip", "--file=-", "--directory"])
        .arg(root)
        .args(["--no-recursion", "--null", "--files-from"])
        .arg(manifest)
        // An inherited --dereference/--transform/--exclude would select a
        // different source universe than the manifest. Do not consult it.
        .env_remove("TAR_OPTIONS");
    command
}

/// Scope both children and every pipe to the caller's source-sync timeout.
/// Never detach a pump that can continue sending after cancellation; never
/// turn a failed copy, producer, consumer or diagnostic capture into success.
pub(super) async fn stream(mut tar: Command, mut receiver: Command) -> Result<u64> {
    const DIAGNOSTIC_LIMIT: usize = 64 * 1024;
    tar.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    receiver
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut producer = tar.spawn().context("spawn source archive producer")?;
    let mut consumer = receiver.spawn().context("spawn source archive receiver")?;
    let mut input = producer.stdout.take().context("source archive stdout")?;
    let producer_error = producer.stderr.take().context("source archive stderr")?;
    let mut output = consumer.stdin.take().context("source receiver stdin")?;
    let consumer_output = consumer.stdout.take().context("source receiver stdout")?;
    let consumer_error = consumer.stderr.take().context("source receiver stderr")?;

    let (copied, (), ()) = tokio::try_join!(
        async {
            let copied = tokio::io::copy(&mut input, &mut output)
                .await
                .context("stream source archive")?;
            output.shutdown().await.context("close source archive stream")?;
            drop(output);
            Ok::<_, anyhow::Error>(copied)
        },
        async {
            let stderr = super::read_bounded_output_stream(producer_error, DIAGNOSTIC_LIMIT)
                .await
                .context("capture source archive diagnostics")?;
            let status = producer.wait().await.context("wait for source archive producer")?;
            anyhow::ensure!(
                status.success() && stderr.is_empty(),
                "source archive producer failed ({status}): {}",
                String::from_utf8_lossy(&stderr).trim()
            );
            Ok::<_, anyhow::Error>(())
        },
        async {
            let (_stdout, stderr) = tokio::try_join!(
                super::read_bounded_output_stream(consumer_output, DIAGNOSTIC_LIMIT),
                super::read_bounded_output_stream(consumer_error, DIAGNOSTIC_LIMIT),
            )
            .context("capture source archive receiver diagnostics")?;
            let status = consumer.wait().await.context("wait for source archive receiver")?;
            anyhow::ensure!(
                status.success(),
                "source archive receiver failed ({status}): {}",
                String::from_utf8_lossy(&stderr).trim()
            );
            // A successful SSH client can announce a newly accepted host key
            // on stderr. This is an upload, not the strict receipt barrier:
            // retain the existing success-status contract for these notices.
            if !stderr.is_empty() {
                tracing::debug!(
                    "source archive receiver diagnostics: {}",
                    String::from_utf8_lossy(&stderr).trim()
                );
            }
            Ok::<_, anyhow::Error>(())
        },
    )?;
    Ok(copied)
}

#[cfg(all(test, unix))]
mod tests;
