//! Opt-in RCH-dispatched Cargo with worker-local RABS (plan §3.7).
//!
//! This extends the existing remote-command builder, not the scheduler or
//! artifact transport. The worker's installed cargo-rabs owns daemon startup
//! and environment preparation; rabs-wrap/rabsd retain all cache authority.

use std::borrow::Cow;

const WORKER_PREPARE: &str = include_str!("worker_cache.py");

// RCH's Windows worker also runs Git's sh. Refuse the Linux-only accelerator
// before importing Python or the launcher on other platforms. Missing Python
// likewise preserves the original executable and argv. No eval or retry.
const PLATFORM_RUNNER: &str = r#"program=$1; shift
if [ "$(uname -s 2>/dev/null)" = Linux ] && command -v python3 >/dev/null 2>&1; then
    exec python3 -c "$program" "$@"
fi
exec "$@""#;

pub(super) fn enabled() -> bool {
    std::env::var_os("RCH_RABS_WORKER_CACHE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

pub(super) fn runner_for(command: &str) -> Option<String> {
    let offset = super::toolchain_runner_insert_index(command);
    let (start, end) = super::next_shell_token_span(command, offset)?;
    // Do not guess shell aliases, quoted/expanded executable names, nested
    // shells, or absolute dispatcher tool paths. Existing behavior wins for
    // everything outside the ordinary Cargo command that RCH normalizes.
    if command.get(start..end)? != "cargo" {
        return None;
    }
    Some(format!(
        "sh -c {} rch-rabs-worker {}",
        shell_escape::escape(Cow::Borrowed(PLATFORM_RUNNER)),
        shell_escape::escape(Cow::Borrowed(WORKER_PREPARE)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toolchain::{ToolchainInfo, wrap_command_with_toolchain_policy};

    #[test]
    fn activation_preserves_rustup_cargo_selection_after_environment_controls() {
        let tc = ToolchainInfo::new("nightly", Some("2026-08-31".into()), "");
        let suffix = "cargo +nightly build --manifest-path 'a b/Cargo.toml'";
        let prefix = "env -u RUSTC_WRAPPER RUSTFLAGS='-C debuginfo=0' ";
        let command = format!("{prefix}{suffix}");
        let result = wrap_command_with_toolchain_policy(&command, Some(&tc), true);
        assert_eq!(
            result,
            format!(
                "{prefix}{} rustup run nightly-2026-08-31 {suffix}",
                runner_for(&command).unwrap()
            )
        );
    }

    #[test]
    fn toolchain_free_cargo_keeps_its_own_selector_and_shell_suffix() {
        let command = "CARGO_TARGET_DIR='target private' cargo +stable test -- ';' && echo done";
        let result = wrap_command_with_toolchain_policy(command, None, true);
        assert_eq!(
            result,
            format!(
                "CARGO_TARGET_DIR='target private' {} cargo +stable test -- ';' && echo done",
                runner_for(command).unwrap()
            )
        );
    }

    #[test]
    fn disabled_policy_is_byte_identical_to_the_existing_command_builder() {
        let tc = ToolchainInfo::new("stable", None, "");
        for command in ["cargo build", "", "env -u RUSTFLAGS cargo check"] {
            assert_eq!(
                wrap_command_with_toolchain_policy(command, None, false),
                command
            );
            assert_eq!(
                wrap_command_with_toolchain_policy(command, Some(&tc), false),
                super::super::insert_toolchain_runner(command, "rustup run stable")
            );
        }
    }

    #[test]
    fn unsupported_executables_never_gain_an_acceleration_runner() {
        let tc = ToolchainInfo::new("stable", None, "");
        for command in [
            "rustc input.rs",
            "gcc main.c",
            "sh -c 'cargo build'",
            "'cargo' build",
            "$CARGO build",
            "/dispatcher/bin/cargo build",
            "cargo-rabs build",
            "env -S 'cargo build'",
            "",
        ] {
            assert!(runner_for(command).is_none(), "{command}");
            assert_eq!(
                wrap_command_with_toolchain_policy(command, Some(&tc), true),
                wrap_command_with_toolchain_policy(command, Some(&tc), false)
            );
        }
    }

    #[test]
    fn opaque_arguments_and_toolchain_names_remain_shell_quoted() {
        let tc = ToolchainInfo::new("nightly; echo injected", None, "");
        let command = "cargo build --features 'x y' > 'output file'";
        let wrapped = wrap_command_with_toolchain_policy(command, Some(&tc), true);
        assert!(wrapped.starts_with("sh -c "));
        assert!(wrapped.ends_with(&format!("rustup run 'nightly; echo injected' {command}")));
        assert_eq!(wrapped.matches("rch-rabs-worker").count(), 1);
    }
}
