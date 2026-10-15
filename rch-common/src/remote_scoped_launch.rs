//! Linux and Darwin share the `rch-build` owned-group supervisor.
//! Configured scopes add cgroup containment without changing the receipt ABI.
//! Other protocol users (cancellation, recovery, GC) only load functions.
//!
//! A scoped child needs the same identity/policy implementation as its parent.
//! The quoted heredoc passes these exact sources as data, without installing a
//! launcher on the worker or resolving a mutable script from a source checkout.
//! Load that single literal copy for the supervisor and pass the same bytes to
//! the child. Duplicating it inline exhausts Linux's per-argument limit after
//! the surrounding execution/ownership/SSH layers quote the launch program.

/// The heredoc lives in a function body, not inside `$(...)`: bash 3.2 (macOS
/// `/bin/sh`) scans a substitution's heredoc for the closing paren and fails on
/// the first `pattern)` arm, which made every script that embeds this protocol
/// a syntax error on macOS workers. Keep this `concat!` to string literals and
/// `include_str!` lines only: `tests/remote_scoped_launch.py` re-assembles it.
/// Only the compile-time literal is evaluated. Policy, environment, arguments
/// and stdin never supply program text to the bootstrap.
pub const REMOTE_PROCESS_IDENTITY_SCRIPT: &str = concat!(
    "rch_scope_launch_source() { command cat <<'RCH_SCOPED_LAUNCH_SOURCE_104'\n",
    include_str!("remote_process.sh"),
    "\n",
    include_str!("remote_scoped_launch.sh"),
    "\nRCH_SCOPED_LAUNCH_SOURCE_104\n",
    "}\n",
    "rch_launch_source=$(rch_scope_launch_source) || exit 125\n",
    "command eval \"$rch_launch_source\" || exit 125\n",
    "\nif [ \"$0\" = rch-build ]; then\n",
    "    rch_launch_platform=$(uname -s) || { printf '\\n%s_IDENTITY_UNAVAILABLE\\n' \"$3\" >&2; exit 125; }\n",
    "    case \"$rch_launch_platform\" in Linux|Darwin) ;; *) rch_scope_launch_message \"$3\" setup >&2; exit 125;; esac\n",
    "    rch_scope_launch_supervise \"$@\"\n",
    "    exit $?\n",
    "fi\n",
);

#[cfg(test)]
mod tests {
    use super::REMOTE_PROCESS_IDENTITY_SCRIPT;

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
        for source in [
            include_str!("remote_process.sh"),
            include_str!("remote_scoped_launch.sh"),
        ] {
            assert!(
                !source
                    .lines()
                    .any(|line| line == "RCH_SCOPED_LAUNCH_SOURCE_104")
            );
        }
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
