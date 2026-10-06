//! The no-delta receipt barrier's transport and output policy.
//!
//! SSH informational logging must not be confused with rsync evidence (#84).
//! Suppress it at the SSH client, never by accepting arbitrary stderr here.

use std::process::{Command, Output};

const SSH_LOG_LEVEL: &str = "LogLevel=ERROR";

/// Machine-readable receipt operations need a silent successful SSH connection.
/// Keep authentication, host-key policy, identity quoting and multiplexing intact.
/// OpenSSH logs new-known-host notices at INFO, but changed/revoked host keys
/// at ERROR. Unlike `-q`, this retains authentication and transport errors.
pub(super) fn ssh_command(transport: &str) -> String {
    format!("{transport} -o {SSH_LOG_LEVEL}")
}

/// Apply the same policy to the direct control-plane SSH transport, including
/// the per-file hash verifier after the rsync barrier. Call before the SSH
/// destination: these are local client options, never remote command arguments.
pub(crate) fn configure_ssh_command(command: &mut Command) {
    command.arg("-o").arg(SSH_LOG_LEVEL);
}

/// Recognize only a complete directory-attribute record in rsync's
/// `YXcstpoguax<TAB>path` format. Checking byte 1 alone is unsound: the
/// message `*deleting` ALSO has `d` there, for both files and directories.
/// Creation, deletion, unknown flags and malformed records are not metadata.
fn directory_metadata_only(line: &str) -> bool {
    let Some((itemized, path)) = line.split_once('\t') else {
        return false;
    };
    let bytes = itemized.as_bytes();
    if bytes.len() != 11 || !bytes.starts_with(b".d") {
        return false;
    }
    if path.is_empty()
        || path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.split('/').any(|component| component == "..")
    {
        return false;
    }
    // Spaces mean all attributes are unchanged. Otherwise each position must
    // contain its documented attribute letter or '.', never '+' or '?'.
    if bytes[2..].iter().all(|byte| *byte == b' ') {
        return true;
    }
    bytes[2..]
        .iter()
        .zip(b"cstpoguax")
        .all(|(&actual, &attribute)| {
            actual == b'.'
                || actual == attribute
                || (attribute == b't' && actual == b'T')
                || (attribute == b'u' && matches!(actual, b'n' | b'b'))
        })
}

/// Interpret the bounded, completed rsync capture. No stderr is whitelisted,
/// including text that resembles SSH's known-host notice: a remote process
/// can print that same text. Only the SSH client's log level is adjusted.
/// Per-file type/mode/length/hash proofs and before/after receipt validation
/// remain separate requirements enforced by the caller's receipt pipeline.
pub(super) fn verify_output(output: &Output) -> Result<(), String> {
    if !output.status.success() {
        return Err(format!(
            "source-content rsync barrier failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if !output.stderr.is_empty() {
        return Err(format!(
            "source-content rsync barrier produced stderr: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| "source-content rsync barrier output was not UTF-8".to_owned())?;
    if !stdout.is_empty() && !stdout.ends_with('\n') {
        return Err("source-content rsync barrier output ended in an incomplete record".to_owned());
    }
    // Only recognized directory metadata can be ignored. Every file change,
    // deletion, creation or unexpected output is a delta, never a no-op proof.
    let changed = stdout
        .split_terminator('\n')
        .filter(|line| !line.is_empty())
        .filter(|line| !directory_metadata_only(line))
        .collect::<Vec<_>>();
    if !changed.is_empty() {
        let preview = changed
            .iter()
            .take(8)
            .copied()
            .collect::<Vec<_>>()
            .join(" | ");
        return Err(format!(
            "source-content rsync barrier detected {} remote delta(s): {}",
            changed.len(),
            preview
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(code: i32, stdout: &[u8], stderr: &[u8]) -> Output {
        #[cfg(unix)]
        let status = {
            use std::os::unix::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(code << 8)
        };
        #[cfg(windows)]
        let status = {
            use std::os::windows::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(code as u32)
        };
        Output {
            status,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn ssh_logging_changes_without_changing_authentication_or_quoting() {
        let original = "ssh -i '/keys/p q' -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ControlMaster=auto";
        assert_eq!(
            ssh_command(original),
            format!("{original} -o LogLevel=ERROR")
        );
        assert!(!ssh_command(original).contains(" -q"));
        assert!(!ssh_command(original).contains("UserKnownHostsFile"));
    }

    #[test]
    fn direct_ssh_policy_keeps_options_and_payload_as_distinct_arguments() {
        let original = [
            "-i",
            "/keys/p q",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=180",
        ];
        let mut command = Command::new("ssh");
        command.args(original);
        configure_ssh_command(&mut command);
        command.arg("builder@host").arg("sh -s");
        let expected: Vec<_> = original
            .into_iter()
            .chain(["-o", "LogLevel=ERROR", "builder@host", "sh -s"])
            .map(std::ffi::OsString::from)
            .collect();
        assert_eq!(command.get_args().collect::<Vec<_>>(), expected);
        assert_eq!(command.get_program(), "ssh");
    }

    #[test]
    fn empty_success_and_directory_metadata_are_not_file_deltas() {
        assert!(verify_output(&output(0, b"", b"")).is_ok());
        for line in [
            ".d..t......\t./\n",
            ".d...p.....\tsrc/\n",
            ".d..tp.....\tp q/x:y/\n",
            ".d         \tsrc/\n",
        ] {
            assert!(verify_output(&output(0, line.as_bytes(), b"")).is_ok());
        }
    }

    #[test]
    fn nonzero_and_signal_exits_fail_even_without_stderr_or_deltas() {
        for code in [1, 12, 23, 24, 30, 255] {
            assert!(verify_output(&output(code, b"", b"")).is_err());
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            let mut killed = output(0, b"", b"");
            killed.status = std::process::ExitStatus::from_raw(15);
            assert!(verify_output(&killed).is_err());
        }
    }

    #[test]
    fn every_stderr_byte_still_refuses_including_spoofed_ssh_notices() {
        for stderr in [
            &b"Warning: Permanently added 'worker' (ED25519) to the list of known hosts.\r\n"[..],
            &b"rsync: some files vanished\n"[..],
            &b"Host key verification failed.\n"[..],
            &b"Permission denied (publickey).\n"[..],
            &b"\n"[..],
            &b"\xff"[..],
        ] {
            assert!(verify_output(&output(0, b"", stderr)).is_err());
        }
    }

    #[test]
    fn file_content_metadata_creation_and_deletion_deltas_refuse() {
        for line in [
            ">fc........\tsrc/lib.rs\n",
            ">f+++++++++\tsrc/new.rs\n",
            ".f...p.....\tsrc/lib.rs\n",
            "*deleting  \tsrc/old.rs\n",
            "*deleting  \told-directory/\n",
            "*deleting\tsrc/old.rs\n",
            "cd+++++++++\tnew-directory/\n",
        ] {
            let stdout = format!(".d..t......\t./\n{line}");
            let error = verify_output(&output(0, stdout.as_bytes(), b"")).unwrap_err();
            assert!(error.contains("1 remote delta(s)"), "{error}");
        }
    }

    #[test]
    fn directory_type_byte_alone_never_proves_a_metadata_only_record() {
        for line in [
            "ad\tsrc/\n",
            ".d\tsrc/\n",
            ".d........\tsrc/\n",
            ".d..........\tsrc/\n",
            ".d..t.....?\tsrc/\n",
            ".d..t.....q\tsrc/\n",
            ".d..t......\t\n",
            ".d..t......\t../outside/\n",
            ".d..t......\t/absolute/\n",
            ".d..t......\tsrc/\tforged\n",
            ".d..t......\tsrc/\0\n",
            ".d..t......\tsrc/\r\n",
            ".d..t......\tsrc/",
        ] {
            assert!(
                verify_output(&output(0, line.as_bytes(), b"")).is_err(),
                "malformed directory record passed: {line:?}"
            );
        }
    }

    #[test]
    fn malformed_or_non_utf8_output_does_not_prove_no_delta() {
        for stdout in [&b"unparseable\n"[..], &b".f........?\n"[..], &b"\xff"[..]] {
            assert!(verify_output(&output(0, stdout, b"")).is_err());
        }
    }

    #[test]
    fn delta_preview_is_bounded_but_all_changes_are_counted() {
        let stdout = (0..20)
            .map(|index| format!(">fc........\tsrc/file-{index}.rs\n"))
            .collect::<String>();
        let error = verify_output(&output(0, stdout.as_bytes(), b"")).unwrap_err();
        assert!(error.contains("20 remote delta(s)"));
        assert!(error.contains("src/file-7.rs"));
        assert!(!error.contains("src/file-8.rs"));
    }
}
