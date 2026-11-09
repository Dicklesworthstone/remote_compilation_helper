//! Linux and Darwin share the `rch-build` owned-group supervisor.
//! Configured scopes add cgroup containment without changing the receipt ABI.
//! Other protocol users (cancellation, recovery, GC) only load functions.
//!
//! A scoped child needs the same identity/policy implementation as its parent.
//! A quoted assignment passes these exact sources as data, without installing
//! a launcher or requiring temporary-file space on a full worker. Load that
//! single literal copy for the supervisor and pass the same bytes to the child.
//! Duplicating it inline exhausts Linux's per-argument limit after the surrounding
//! execution/ownership/SSH layers quote the launch program.

// Keep these inputs literal: the native Python suites reconstruct their exact
// expansion and compare it with the compiled constant when Cargo supplies it.
const LAUNCH_SOURCE: &str = concat!(
    include_str!("remote_process.sh"),
    "\n",
    include_str!("remote_scoped_launch.sh"),
);
const BOOTSTRAP_PREFIX: &str = "rch_literal_bang=\"!\"\nrch_launch_source=\"";
const BANG_EXPANSION: &str = "${rch_literal_bang}";
const BOOTSTRAP_SUFFIX: &str = concat!(
    "\"\n",
    "unset rch_literal_bang\n",
    "command eval \"$rch_launch_source\" || exit 125\n",
    "\nif [ \"$0\" = rch-build ]; then\n",
    "    rch_launch_platform=$(uname -s) || { printf '\\n%s_IDENTITY_UNAVAILABLE\\n' \"$3\" >&2; exit 125; }\n",
    "    case \"$rch_launch_platform\" in Linux|Darwin) ;; *) rch_scope_launch_message \"$3\" setup >&2; exit 125;; esac\n",
    "    rch_scope_launch_supervise \"$@\"\n",
    "    exit $?\n",
    "fi\n",
);

const fn protocol_length() -> usize {
    let source = LAUNCH_SOURCE.as_bytes();
    let mut length = BOOTSTRAP_PREFIX.len() + source.len() + BOOTSTRAP_SUFFIX.len();
    let mut index = 0;
    while index < source.len() {
        if source[index] == b'!' {
            length += BANG_EXPANSION.len() - 1;
        } else if matches!(source[index], b'\\' | b'"' | b'$' | b'`') {
            length += 1;
        }
        index += 1;
    }
    length
}

const PROTOCOL_LENGTH: usize = protocol_length();

const fn compile_protocol() -> [u8; PROTOCOL_LENGTH] {
    let source = LAUNCH_SOURCE.as_bytes();
    let mut output = [0; PROTOCOL_LENGTH];
    let mut written = 0;
    let mut index = 0;
    while index < BOOTSTRAP_PREFIX.len() {
        output[written] = BOOTSTRAP_PREFIX.as_bytes()[index];
        written += 1;
        index += 1;
    }
    index = 0;
    while index < source.len() {
        let byte = source[index];
        if byte == b'!' {
            let mut bang_index = 0;
            while bang_index < BANG_EXPANSION.len() {
                output[written] = BANG_EXPANSION.as_bytes()[bang_index];
                written += 1;
                bang_index += 1;
            }
        } else {
            if matches!(byte, b'\\' | b'"' | b'$' | b'`') {
                output[written] = b'\\';
                written += 1;
            }
            output[written] = byte;
            written += 1;
        }
        index += 1;
    }
    index = 0;
    while index < BOOTSTRAP_SUFFIX.len() {
        output[written] = BOOTSTRAP_SUFFIX.as_bytes()[index];
        written += 1;
        index += 1;
    }
    output
}

static PROTOCOL_BYTES: [u8; PROTOCOL_LENGTH] = compile_protocol();

/// Bootstrap from literal bytes without a disk-backed heredoc. Bash can spill
/// even a quoted heredoc to /tmp, regardless of an unavailable TMPDIR, so the
/// old bootstrap prevented cancellation before its diskless census could run.
/// Double quoting keeps nested transport below the existing argument budget;
/// escaping every expansion character prevents any source from running early.
/// A fixed internal variable supplies `!` bytes, whose shell-escape transport
/// encoding would otherwise amplify beyond that budget after four layers.
/// Only the compile-time literal is evaluated. Policy, environment, arguments
/// and stdin never supply program text to the bootstrap.
pub const REMOTE_PROCESS_IDENTITY_SCRIPT: &str = match std::str::from_utf8(&PROTOCOL_BYTES) {
    Ok(protocol) => protocol,
    Err(_) => panic!("quoted worker protocol must remain UTF-8"),
};

#[cfg(test)]
mod tests {
    use super::{LAUNCH_SOURCE, REMOTE_PROCESS_IDENTITY_SCRIPT};

    /// Workers run this under their own `sh`: dash on Linux, bash 3.2 on
    /// macOS. A parse error here breaks every remote launch, cancellation,
    /// recovery and cleanup script on that worker.
    #[test]
    fn protocol_parses_under_the_system_sh() {
        let output = std::process::Command::new("/bin/sh")
            .args(["-n", "-c", REMOTE_PROCESS_IDENTITY_SCRIPT])
            .output()
            .expect("run /bin/sh -n");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn quoted_protocol_fits_linux_single_argument_limit() {
        // TransferPipeline shell-quotes this script and adds its legacy tail.
        // Keep space for that tail, the payload, and enclosing launch wrappers.
        let quoted = shell_escape::escape(REMOTE_PROCESS_IDENTITY_SCRIPT.into());
        assert!(quoted.len() < 110_000);
    }

    #[test]
    fn bootstrap_preserves_the_complete_literal_source() {
        let output = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                &format!("{REMOTE_PROCESS_IDENTITY_SCRIPT}\nprintf '%s' \"$rch_launch_source\""),
            ])
            .output()
            .expect("read the quoted protocol source");
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(output.stdout, LAUNCH_SOURCE.as_bytes());
    }

    #[test]
    fn nested_transport_quoting_keeps_room_for_the_payload() {
        // The tracked command is nested under durable execution, source
        // activity and the login shell. A one-quote check misses amplification
        // of quotes and backslashes before exec reaches the worker protocol.
        let mut script = REMOTE_PROCESS_IDENTITY_SCRIPT.to_owned();
        for _ in 0..4 {
            script = format!(
                "exec /bin/sh -c {} rch-transport",
                shell_escape::unix::escape(script.into())
            );
        }
        assert!(
            script.len() < 110_000,
            "nested script is {} bytes",
            script.len()
        );
    }
}
