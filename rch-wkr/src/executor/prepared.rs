//! Launch the workload in the layout proven by dependency preparation.
//!
//! The plain path already has a report. The disk path must prepare inside the
//! existing monitor, so its private selector reads the worker's bounded layout
//! protocol before choosing between the original shell and literal PnP argv.

use super::{CommandFailed, EXIT_PREPARE_FAILED, eprintln_best_effort, managed_command};
use crate::prepare::DependencyLayout;
use anyhow::{Context, Result, ensure};
use rch_common::types::RequiredRuntime;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use tokio::process::Command;

const DISK_PREPARE_SELECTOR: &str = include_str!("prepared.sh");

/// Member-local tools precede hoisted tools. Resolve both before launching a
/// shell which may change cwd; join_paths rejects an unrepresentable separator
/// instead of silently searching an unrelated directory.
pub(super) fn node_modules_path(
    invocation: &Path,
    preparation: &Path,
    existing: Option<&OsStr>,
) -> Result<OsString> {
    let invocation = invocation.canonicalize()?;
    let preparation = preparation.canonicalize()?;
    ensure!(
        invocation.starts_with(&preparation),
        "invocation is outside its prepared root"
    );
    let mut paths = Vec::new();
    for (distance, root) in invocation.ancestors().enumerate() {
        ensure!(
            distance <= rch_common::node_workspace_fs::MAX_ROOT_PARENTS,
            "prepared tool ancestry exceeds its bound"
        );
        let bin = root.join("node_modules/.bin");
        if bin.is_dir() {
            let absolute = bin
                .canonicalize()
                .context("resolve prepared tool directory")?;
            if !paths.contains(&absolute) {
                paths.push(absolute);
            }
        }
        if root == preparation {
            break;
        }
    }
    if let Some(existing) = existing {
        paths.extend(std::env::split_paths(existing));
    }
    std::env::join_paths(paths).context("prepared tool directory contains a PATH separator")
}

fn yarn_arguments(command: &str) -> Option<Vec<String>> {
    let compiler = rch_common::patterns::tsc_invocation(command)?;
    let mut arguments = ["run", "--binaries-only", "tsc"]
        .map(str::to_owned)
        .to_vec();
    arguments.extend(compiler);
    Some(arguments)
}

pub(super) fn workload_command(layout: DependencyLayout, command: &str) -> Result<Command> {
    match layout {
        DependencyLayout::NodeModules => {
            let mut shell = managed_command("sh");
            shell.args(["-c", command]);
            Ok(shell)
        }
        DependencyLayout::YarnPnp => {
            let Some(arguments) = yarn_arguments(command) else {
                eprintln_best_effort(
                    "rch-wkr: Yarn PnP requires literal tsc --noEmit --incremental false --composite false arguments; the command was not run",
                );
                return Err(CommandFailed {
                    exit_code: EXIT_PREPARE_FAILED,
                }
                .into());
            };
            let mut yarn = managed_command("yarn");
            yarn.args(arguments);
            Ok(yarn)
        }
    }
}

pub(super) fn disk_guard_command(
    project: &Path,
    preparation: &Path,
    runtime: RequiredRuntime,
    command: &str,
) -> Result<Command> {
    let runtime = match runtime {
        RequiredRuntime::Node => "node",
        RequiredRuntime::Bun => "bun",
        _ => anyhow::bail!("dependency preparation requires Node or Bun"),
    };
    let mut selector = managed_command("sh");
    selector
        .args(["-c", DISK_PREPARE_SELECTOR, "rch-worker-prepare"])
        .arg(std::env::current_exe()?)
        .arg(project)
        .arg(preparation)
        .arg(runtime)
        .arg(command);
    if let Some(arguments) = yarn_arguments(command) {
        selector.args(arguments);
    }
    Ok(selector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn pnp_launch_preserves_literal_compiler_arguments_without_a_shell() {
        let command = workload_command(
            DependencyLayout::YarnPnp,
            "tsc --noEmit --incremental false --composite false --project 'config with spaces.json'",
        )
        .unwrap();
        assert_eq!(command.as_std().get_program(), OsStr::new("yarn"));
        assert_eq!(
            command.as_std().get_args().collect::<Vec<_>>(),
            [
                "run",
                "--binaries-only",
                "tsc",
                "--noEmit",
                "--incremental",
                "false",
                "--composite",
                "false",
                "--project",
                "config with spaces.json",
            ]
            .map(OsStr::new)
        );
        assert!(
            command
                .as_std()
                .get_envs()
                .all(|(key, _)| key != OsStr::new("PATH"))
        );
    }

    #[test]
    fn pnp_launch_refuses_unproven_wrappers_and_output_settings() {
        for command in [
            "tsc --noEmit",
            "tsc --noEmit --incremental false",
            "tsc --noEmit --incremental false --composite true",
            "npx tsc --noEmit --incremental false --composite false",
            "NODE_OPTIONS='' tsc --noEmit --incremental false --composite false",
            "tsc --noEmit --incremental false --composite false; printf unowned",
            "npm run typecheck",
        ] {
            let error = workload_command(DependencyLayout::YarnPnp, command).unwrap_err();
            assert_eq!(
                error.downcast_ref::<CommandFailed>().unwrap().exit_code,
                EXIT_PREPARE_FAILED,
                "{command}"
            );
        }
    }

    #[test]
    fn node_modules_launch_preserves_the_original_shell() {
        let source = "VALUE='literal value' npm run typecheck && printf done";
        let command = workload_command(DependencyLayout::NodeModules, source).unwrap();
        assert_eq!(command.as_std().get_program(), OsStr::new("sh"));
        assert_eq!(
            command.as_std().get_args().collect::<Vec<_>>(),
            [OsStr::new("-c"), OsStr::new(source)]
        );
    }

    #[cfg(unix)]
    #[test]
    fn disk_selector_keeps_verified_manager_path_stdin_and_status() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Stdio;

        // Explicit protocol fixtures, not substitute Yarn semantics. An
        // authentic PnP install can remove a planted node_modules directory;
        // this isolates the selector's independent PATH obligation.
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path().join("project");
        let bin = fixture.path().join("bin");
        std::fs::create_dir_all(project.join("node_modules/.bin")).unwrap();
        std::fs::create_dir(&bin).unwrap();
        let worker = bin.join("worker");
        for (path, source) in [
            (
                worker.clone(),
                "#!/bin/sh\nprintf '%s\\n' RCH_PREPARED_YARN_PNP:0\n",
            ),
            (
                bin.join("yarn"),
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RCH_TEST_ARGV\"\ncat > \"$RCH_TEST_STDIN\"\nexit 27\n",
            ),
            (
                project.join("node_modules/.bin/yarn"),
                "#!/bin/sh\nexit 97\n",
            ),
        ] {
            std::fs::write(&path, source).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let original = "tsc --noEmit --incremental false --composite false --project 'config with spaces.json'";
        let arguments = yarn_arguments(original).unwrap();
        let argument_output = fixture.path().join("arguments");
        let stdin_output = fixture.path().join("stdin");
        let mut child = std::process::Command::new("sh")
            .args(["-c", DISK_PREPARE_SELECTOR, "rch-worker-prepare"])
            .arg(&worker)
            .arg(&project)
            .arg(&project)
            .arg("node")
            .arg(original)
            .args(&arguments)
            .current_dir(&project)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("RCH_TEST_ARGV", &argument_output)
            .env("RCH_TEST_STDIN", &stdin_output)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"compiler input\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(27), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            std::fs::read_to_string(argument_output).unwrap(),
            arguments.join("\n") + "\n"
        );
        assert_eq!(std::fs::read(stdin_output).unwrap(), b"compiler input\n");
    }
}
