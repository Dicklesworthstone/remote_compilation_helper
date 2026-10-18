//! One framed, read-only status census per bounded group of source roots.
//!
//! The embedded shell memoizes only within a request and only by worktree,
//! never by origin URL (linked worktrees can have different dirty states).
//! Root bytes travel on stdin, outside the shell/SSH argument-size limit.

use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use rch_common::WorkerConfig;

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
}
