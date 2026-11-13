//! Opt-in RCH-dispatched Cargo with worker-local RABS (plan §3.7).
//!
//! This extends the existing remote-command builder, not the scheduler or
//! artifact transport. The deployed native worker owns bounded daemon startup
//! and environment preparation; rabs-wrap/rabsd retain all cache authority.

use std::borrow::Cow;

// The accelerator is Linux-only; other worker platforms preserve stock Cargo.
const PLATFORM_RUNNER: &str = r#"if [ "$(uname -s 2>/dev/null)" != Linux ]; then
    exec "$@"
fi
if ! rch_wkr_locate; then
    printf '%s\n' 'RCH_RABS_WORKER_UNAVAILABLE: install the matching native rch-wkr' >&2
    exit 73
fi
exec "$RCH_WKR" worker-cache --protocol v1 -- "$@""#;

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
    let program = format!("{}\n{PLATFORM_RUNNER}", crate::wkr_locate::WKR_LOCATE_SHELL);
    Some(format!(
        "sh -c {} rch-rabs-worker",
        shell_escape::escape(Cow::Borrowed(&program)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toolchain::{ToolchainInfo, wrap_command_with_toolchain_policy};

    #[test]
    fn activation_consumes_the_cargo_selector_before_direct_rustup_handoff() {
        let tc = ToolchainInfo::new("nightly", Some("2026-08-31".into()), "");
        let suffix = "cargo +nightly build --manifest-path 'a b/Cargo.toml'";
        let prefix = "env -u RUSTC_WRAPPER RUSTFLAGS='-C debuginfo=0' ";
        let command = format!("{prefix}{suffix}");
        let result = wrap_command_with_toolchain_policy(&command, Some(&tc), true);
        assert_eq!(
            result,
            format!(
                "{prefix}{} rustup run nightly cargo build --manifest-path 'a b/Cargo.toml'",
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
        let tc = ToolchainInfo::new("nightly;echo_injected", None, "");
        let command = "cargo build --features 'x y' > 'output file'";
        let wrapped = wrap_command_with_toolchain_policy(command, Some(&tc), true);
        assert!(wrapped.starts_with("sh -c "));
        assert!(wrapped.ends_with(&format!("rustup run 'nightly;echo_injected' {command}")));
        assert_eq!(wrapped.matches("rch-rabs-worker").count(), 1);
    }

    #[test]
    fn worker_bootstrap_uses_the_deployed_native_protocol() {
        assert!(PLATFORM_RUNNER.contains("worker-cache --protocol v1 -- \"$@\""));
        assert!(PLATFORM_RUNNER.contains("RCH_RABS_WORKER_UNAVAILABLE"));
        let runner = runner_for("cargo check").unwrap();
        assert!(runner.contains("rch_wkr_locate"));
        assert!(runner.ends_with("rch-rabs-worker"));
    }
}
