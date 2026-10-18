//! One framed, read-only status census per bounded group of source roots.
//!
//! The embedded shell memoizes only within a request and only by worktree,
//! never by origin URL (linked worktrees can have different dirty states).
//! Root bytes travel on stdin, outside the shell/SSH argument-size limit.

use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use rch_common::WorkerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::super::ssh::{run_offload_ssh_command_with_stdin, wrap_remote_source_activity};

const SCRIPT: &str = include_str!("status_probe.sh");
const MAX_ROOTS: usize = 64;
const MAX_PATH_BYTES: usize = 16_384;
const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Clean,
    Dirty,
    Unavailable,
}

fn request(roots: &[PathBuf]) -> Result<Vec<u8>> {
    ensure!(roots.len() <= MAX_ROOTS, "too many repository status roots");
    let mut payload = String::from("RCH_REPO_STATUS_REQUEST_V1\n");
    for root in roots {
        let bytes = root.as_os_str().as_bytes();
        ensure!(
            bytes.first() == Some(&b'/')
                && bytes.len() <= MAX_PATH_BYTES
                && !bytes.contains(&0),
            "repository status requires a bounded, absolute non-NUL path"
        );
        for byte in bytes {
            // POSIX printf %b accepts this exact five-byte octal form. It is
            // data, never source text or eval; non-UTF-8 and final LF survive.
            write!(&mut payload, "\\0{byte:03o}")?;
        }
        payload.push('\n');
    }
    payload.push_str("RCH_REPO_STATUS_REQUEST_END\n");
    Ok(payload.into_bytes())
}

fn response(bytes: &[u8], expected: usize) -> Result<Vec<Status>> {
    ensure!(
        expected <= MAX_ROOTS && bytes.len() <= MAX_RESPONSE_BYTES,
        "repository status response exceeded its bound"
    );
    let text = std::str::from_utf8(bytes).context("invalid repository status response encoding")?;
    let text = text
        .strip_suffix('\n')
        .context("unterminated repository status response")?;
    let mut lines = text.split('\n');
    ensure!(
        lines.next() == Some("RCH_REPO_STATUS_V1"),
        "invalid repository status header"
    );
    let mut states = Vec::with_capacity(expected);
    for index in 0..expected {
        let prefix = format!("{index} ");
        let value = lines
            .next()
            .and_then(|line| line.strip_prefix(&prefix))
            .context("missing or misordered repository status root")?;
        states.push(match value {
            "clean" => Status::Clean,
            "dirty" => Status::Dirty,
            "unavailable" => Status::Unavailable,
            _ => anyhow::bail!("unknown repository status verdict"),
        });
    }
    let footer = format!("RCH_REPO_STATUS_END {expected}");
    ensure!(
        lines.next() == Some(footer.as_str()) && lines.next().is_none(),
        "incomplete or contradictory repository status census"
    );
    Ok(states)
}

fn command() -> String {
    format!("sh -c {}", shell_escape::escape(SCRIPT.into()))
}

fn budget(count: usize) -> Duration {
    // Preserve the old aggregate allowance of ten seconds per root; merging
    // transport must not turn a large, valid closure into a ten-second job.
    Duration::from_secs(10 * u64::try_from(count.min(MAX_ROOTS)).unwrap_or(64))
}

fn unsuitable(roots: &[PathBuf], states: Vec<Status>) -> Vec<(PathBuf, String)> {
    roots
        .iter()
        .zip(states)
        .filter_map(|(root, state)| match state {
            Status::Clean => None,
            Status::Dirty => Some((root.clone(), "dirty".to_string())),
            Status::Unavailable => Some((
                root.clone(),
                "git status unavailable (not a worktree or status failed)".to_string(),
            )),
        })
        .collect()
}

fn local_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("sh");
    command.arg("-c").arg(SCRIPT);
    command
}

async fn bounded_stream(reader: impl AsyncRead + Unpin, maximum: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take((maximum + 1) as u64).read_to_end(&mut bytes).await?;
    if bytes.len() > maximum {
        return Err(std::io::Error::other("repository status stream exceeded its bound"));
    }
    Ok(bytes)
}

async fn local_batch(
    mut command: tokio::process::Command,
    roots: &[PathBuf],
    allowance: Duration,
) -> Result<Vec<Status>> {
    let payload = request(roots)?;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start local repository status census")?;
    let mut input = child.stdin.take().context("missing census stdin")?;
    let output = child.stdout.take().context("missing census stdout")?;
    let diagnostic = child.stderr.take().context("missing census stderr")?;
    // Feed and drain concurrently: a large closure cannot deadlock with a
    // full output pipe. One deadline includes write, both reads and process
    // completion. Dropping the future kills its directly owned shell child;
    // this does not claim process-tree cancellation of arbitrary Git helpers.
    let exchange = async {
        let write = async {
            input.write_all(&payload).await?;
            input.shutdown().await?;
            drop(input);
            Ok::<_, std::io::Error>(())
        };
        let ((), bytes, _) = tokio::try_join!(
            write,
            bounded_stream(output, MAX_RESPONSE_BYTES),
            bounded_stream(diagnostic, MAX_RESPONSE_BYTES),
        )?;
        let status = child.wait().await?;
        ensure!(status.success(), "local repository status census failed: {status}");
        response(&bytes, roots.len())
    };
    tokio::time::timeout(allowance, exchange)
        .await
        .context("local repository status census timed out")?
}

pub(super) async fn local(roots: &[PathBuf]) -> Result<Vec<(PathBuf, String)>> {
    let mut rejected = Vec::new();
    for batch in roots.chunks(MAX_ROOTS) {
        let states = local_batch(local_command(), batch, budget(batch.len())).await?;
        rejected.extend(unsuitable(batch, states));
    }
    Ok(rejected)
}

pub(super) async fn remote(
    worker: &WorkerConfig,
    roots: &[PathBuf],
    source_identity: Option<&str>,
) -> Result<Vec<(PathBuf, String)>> {
    let mut rejected = Vec::new();
    for batch in roots.chunks(MAX_ROOTS) {
        let payload = request(batch)?;
        let command = match source_identity {
            Some(identity) => wrap_remote_source_activity(&command(), identity)?,
            None => command(),
        };
        let observed = async {
            let output =
                run_offload_ssh_command_with_stdin(worker, &command, &payload, budget(batch.len()))
                    .await?;
            ensure!(
                output.status.success(),
                "repository status census did not complete: {:?}",
                output.status.code()
            );
            response(&output.stdout, batch.len())
        }
        .await;
        match observed {
            Ok(states) => rejected.extend(unsuitable(batch, states)),
            // The complete activity remains owned on an uncertain transport or
            // malformed completion. Never continue into the mutating adapter.
            Err(error) if source_identity.is_some() => {
                return Err(error.context(
                    "remote repository census unconfirmed; source cancellation required",
                ));
            }
            Err(error) => {
                // The legacy unowned diagnostic path may skip repo_updater and
                // use direct synchronization, but cannot label partial data clean.
                rejected.extend(batch.iter().map(|root| {
                    (root.clone(), format!("repository status unavailable: {error}"))
                }));
            }
        }
    }
    Ok(rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn request_preserves_opaque_roots_without_shell_interpretation() {
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/a'\xff\n".to_vec()));
        let encoded = request(&[path]).unwrap();
        assert_eq!(
            encoded,
            b"RCH_REPO_STATUS_REQUEST_V1\n\\0057\\0141\\0047\\0377\\0012\nRCH_REPO_STATUS_REQUEST_END\n"
        );
        assert!(request(&[PathBuf::from("relative")]).is_err());
        assert!(request(&[PathBuf::from("/a\0b")]).is_err());
        assert!(request(&vec![PathBuf::from("/root"); MAX_ROOTS + 1]).is_err());
        assert!(request(&[PathBuf::from(format!("/{}", "a".repeat(MAX_PATH_BYTES)))]).is_err());
    }

    #[test]
    fn complete_response_preserves_every_input_in_order() {
        assert_eq!(
            response(b"RCH_REPO_STATUS_V1\n0 clean\n1 dirty\n2 unavailable\nRCH_REPO_STATUS_END 3\n", 3).unwrap(),
            [Status::Clean, Status::Dirty, Status::Unavailable]
        );
        assert!(response(b"RCH_REPO_STATUS_V1\nRCH_REPO_STATUS_END 0\n", 0).unwrap().is_empty());
    }

    #[test]
    fn no_partial_extra_or_forged_response_can_prove_cleanliness() {
        for bytes in [
            b"".as_slice(),
            b"RCH_REPO_STATUS_V1\n0 clean\n",
            b"RCH_REPO_STATUS_V1\n1 clean\nRCH_REPO_STATUS_END 1\n",
            b"RCH_REPO_STATUS_V1\n0 clean\n0 clean\nRCH_REPO_STATUS_END 1\n",
            b"RCH_REPO_STATUS_V1\n0 clean\nRCH_REPO_STATUS_END 2\n",
            b"RCH_REPO_STATUS_V1\n0 clean\nRCH_REPO_STATUS_END 1",
            b"RCH_REPO_STATUS_V1\n0 clean\nRCH_REPO_STATUS_END 1\nextra\n",
            b"RCH_REPO_STATUS_V1\n0 clean\r\nRCH_REPO_STATUS_END 1\n",
            b"RCH_REPO_STATUS_V1\n0 clean\0\nRCH_REPO_STATUS_END 1\n",
            b"RCH_REPO_STATUS_V1\n0 unknown\nRCH_REPO_STATUS_END 1\n",
        ] {
            assert!(response(bytes, 1).is_err(), "{bytes:?}");
        }
        assert!(response(&vec![b'x'; MAX_RESPONSE_BYTES + 1], 1).is_err());
    }

    #[test]
    fn unavailable_rows_block_the_adapter_just_like_dirty_rows() {
        let roots = ["/a", "/b", "/c"].map(PathBuf::from);
        let rejected = unsuitable(&roots, vec![Status::Clean, Status::Unavailable, Status::Dirty]);
        assert_eq!(rejected.len(), 2);
        assert_eq!(rejected[0].0, roots[1]);
        assert_eq!(rejected[1], (roots[2].clone(), "dirty".to_string()));
        assert_eq!(budget(17), Duration::from_secs(170));
    }

    #[test]
    fn production_shell_matches_the_live_git_reference() {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../scripts/tests/test_repo_status_probe.py");
        let output = std::process::Command::new("python3")
            .arg(script)
            .output()
            .expect("Python 3 is required by the native repository status regressions");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    }

    #[tokio::test]
    async fn local_pipeline_observes_real_git_without_losing_unknown_roots() {
        let retained = tempfile::tempdir().unwrap().keep();
        let home = retained.join("home");
        std::fs::create_dir(&home).unwrap();
        let root = retained.join(std::ffi::OsString::from_vec(b"repo-'\xff\n".to_vec()));
        std::fs::create_dir(&root).unwrap();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let init = tokio::process::Command::new("git")
            .arg("init").arg("-q").arg(&root)
            .env_clear().env("PATH", &path).env("HOME", &home)
            .kill_on_drop(true).status().await.unwrap();
        assert!(init.success());
        let member = root.join("member");
        std::fs::create_dir(&member).unwrap();
        let roots = [root.clone(), member, retained.join("missing")];
        for dirty in [false, true] {
            if dirty {
                std::fs::write(root.join("untracked"), b"new source\n").unwrap();
            }
            let mut command = local_command();
            command.env_clear().env("PATH", &path).env("HOME", &home);
            let states = local_batch(command, &roots, Duration::from_secs(5)).await.unwrap();
            let state = if dirty { Status::Dirty } else { Status::Clean };
            assert_eq!(states, [state, state, Status::Unavailable]);
            let rejected = unsuitable(&roots, states);
            assert_eq!(rejected.len(), if dirty { 3 } else { 1 });
            assert_eq!(rejected.last().unwrap().0, roots[2]);
        }
        assert!(local(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn local_pipeline_requires_successful_exit_and_bounded_complete_streams() {
        for script in [
            "cat >/dev/null; printf 'RCH_REPO_STATUS_V1\\n0 clean\\n'",
            "cat >/dev/null; printf 'RCH_REPO_STATUS_V1\\n0 clean\\nRCH_REPO_STATUS_END 1\\n'; exit 1",
            "cat >/dev/null; printf '%4097s' ''",
            "cat >/dev/null; printf '%4097s' '' >&2",
        ] {
            let mut command = tokio::process::Command::new("sh");
            command.arg("-c").arg(script);
            let result = local_batch(command, &[PathBuf::from("/fixture")], Duration::from_secs(2)).await;
            assert!(result.is_err(), "{script}");
        }
    }

    #[tokio::test]
    async fn local_pipeline_deadline_drops_the_owned_stalled_process() {
        let mut command = tokio::process::Command::new("sh");
        // exec keeps the directly owned process as the stalled child, rather
        // than claiming an unqualified descendant/process-group kill policy.
        command.arg("-c").arg("exec sleep 30");
        let roots = [PathBuf::from("/fixture")];
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            local_batch(command, &roots, Duration::from_millis(50)),
        ).await.expect("local census escaped its deadline");
        assert!(format!("{:#}", result.unwrap_err()).contains("timed out"));
    }

    #[tokio::test]
    async fn local_pipeline_refuses_invalid_roots_before_spawning() {
        let command = tokio::process::Command::new("/no-such-rch-status-fixture");
        let result = local_batch(command, &[PathBuf::from("relative")], Duration::from_secs(1)).await;
        assert!(format!("{:#}", result.unwrap_err()).contains("absolute"));
    }
}
