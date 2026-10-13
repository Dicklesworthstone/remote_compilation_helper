//! The existing `rch-build` shell ABI gains a scope-aware supervisor. Other
//! users of the shared protocol (cancellation, recovery, GC) only load functions.
//! No policy and nice-only launches continue into the caller's legacy watchdog.
//!
//! A scoped child needs the same identity/policy implementation as its parent.
//! The quoted heredoc passes these exact sources as data, without installing a
//! launcher on the worker or resolving a mutable script from a source checkout.

pub const REMOTE_PROCESS_IDENTITY_SCRIPT: &str = concat!(
    include_str!("remote_process.sh"),
    "\n",
    include_str!("remote_scoped_launch.sh"),
    "\nif [ \"$0\" = rch-build ]; then\n",
    "    rch_scope_launch_select || { printf '\\n%s_IDENTITY_UNAVAILABLE\\n' \"$3\" >&2; exit 125; }\n",
    "    if [ -n \"$rch_launch_slice\" ]; then\n",
    "        rch_launch_source=$(cat <<'RCH_SCOPED_LAUNCH_SOURCE_104'\n",
    include_str!("remote_process.sh"),
    "\n",
    include_str!("remote_scoped_launch.sh"),
    "\nRCH_SCOPED_LAUNCH_SOURCE_104\n",
    "        ) || { printf '\\n%s_IDENTITY_UNAVAILABLE\\n' \"$3\" >&2; exit 125; }\n",
    "        rch_scope_launch_supervise \"$@\"\n",
    "        exit $?\n",
    "    fi\n",
    "fi\n",
);

#[cfg(test)]
mod tests {
    use super::REMOTE_PROCESS_IDENTITY_SCRIPT;

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
}
