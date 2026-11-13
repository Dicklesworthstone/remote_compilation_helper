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

#[derive(Debug)]
pub(super) struct Invocation<'a> {
    pub prefix: &'a str,
    pub command: &'a str,
    pub runtime: RequiredRuntime,
    directories: Vec<String>,
    disk_scope_conflict: bool,
}

/// Read one literal shell word without evaluating expansions. Keep its tail
/// as a slice of the original command so environment prefixes remain exact.
pub(super) fn literal_word(input: &str) -> Option<(String, &str)> {
    let input = input.trim_start_matches([' ', '\t']);
    if input.is_empty() || input.starts_with(['\0', '\r', '\n']) {
        return None;
    }
    let mut value = String::new();
    let mut quote = None;
    let mut chars = input.char_indices();
    while let Some((offset, ch)) = chars.next() {
        if offset > 65_536 || matches!(ch, '\0' | '\r') {
            return None;
        }
        if ch == '\n' {
            return (quote.is_none() && !value.is_empty()).then_some((value, &input[offset..]));
        }
        if quote == Some('\'') {
            if ch == '\'' {
                quote = None;
            } else {
                value.push(ch);
            }
            continue;
        }
        if ch == '\\' {
            let (_, escaped) = chars.next()?;
            if matches!(escaped, '\0' | '\r' | '\n') {
                return None;
            }
            if quote == Some('"') && !matches!(escaped, '$' | '\u{60}' | '"' | '\\') {
                value.push('\\');
            }
            value.push(escaped);
            continue;
        }
        if quote == Some('"') {
            match ch {
                '"' => quote = None,
                '$' | '\u{60}' => return None,
                _ => value.push(ch),
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            ' ' | '\t' => return Some((value, &input[offset..])),
            '$' | '\u{60}' | '|' | '&' | ';' | '<' | '>' | '(' | ')' | '*' | '?' | '['
            | ']' | '{' | '}' | '#' | '~' => return None,
            _ => value.push(ch),
        }
    }
    quote.is_none().then_some((value, ""))
}

impl<'a> Invocation<'a> {
    pub fn parse(command: &'a str) -> Option<Self> {
        let mut remaining = command.trim_start_matches([' ', '\t']);
        let mut directories = Vec::new();
        let mut disk_scope_conflict = false;
        // Only an unquoted NAME= prefix is a shell assignment. A fully quoted
        // 'NAME=value' in command position names an executable instead.
        while remaining
            .split_once('=')
            .is_some_and(|(key, _)| rch_common::ssh_utils::is_valid_env_key(key))
        {
            let (assignment, tail) = literal_word(remaining)?;
            disk_scope_conflict |= assignment
                .split_once('=')
                .is_some_and(|(key, _)| managed_disk_key(key));
            remaining = tail.trim_start_matches([' ', '\t']);
        }
        for _ in 0..32 {
            let (program, tail) = literal_word(remaining)?;
            if Path::new(&program).file_name()?.to_str()? != "env" {
                let runtime = super::runtime_for_head(remaining);
                let prefix = &command[..command.len() - remaining.len()];
                return (runtime != RequiredRuntime::None).then_some(Self {
                    prefix,
                    command: remaining,
                    runtime,
                    directories,
                    disk_scope_conflict,
                });
            }
            remaining = tail.trim_start_matches([' ', '\t']);
            let mut options = true;
            let mut directory = None;
            loop {
                let (word, tail) = literal_word(remaining)?;
                let mut tail = tail.trim_start_matches([' ', '\t']);
                if options && word == "--" {
                    options = false;
                } else if options && matches!(word.as_str(), "-" | "-i" | "--ignore-environment") {
                    disk_scope_conflict = true;
                } else if options && matches!(word.as_str(), "-u" | "--unset" | "-C" | "--chdir") {
                    let (value, rest) = literal_word(tail)?;
                    if matches!(word.as_str(), "-u" | "--unset") {
                        disk_scope_conflict |= managed_disk_key(&value);
                    }
                    if matches!(word.as_str(), "-C" | "--chdir") {
                        if value.is_empty() {
                            return None;
                        }
                        directory = Some(value);
                    }
                    tail = rest.trim_start_matches([' ', '\t']);
                } else if options
                    && (word.starts_with("--unset=") || word.starts_with("-u") && word.len() > 2)
                {
                    let key = word.strip_prefix("--unset=").unwrap_or(&word[2..]);
                    disk_scope_conflict |= managed_disk_key(key);
                } else if options
                    && (word.starts_with("--chdir=") || word.starts_with("-C") && word.len() > 2)
                {
                    let value = word.strip_prefix("--chdir=").unwrap_or(&word[2..]);
                    if value.is_empty() {
                        return None;
                    }
                    directory = Some(value.to_owned());
                } else {
                    if options && word.starts_with('-') {
                        // env -S reparses shell text; it is not an unchanged
                        // executable suffix whose dependencies we can prepare.
                        return None;
                    }
                    options = false;
                    let Some((key, _)) = word
                        .split_once('=')
                        .filter(|(key, _)| rch_common::ssh_utils::is_valid_env_key(key))
                    else {
                        break;
                    };
                    disk_scope_conflict |= managed_disk_key(key);
                }
                remaining = tail;
            }
            // env applies its last -C once; a nested env resolves relative to
            // the directory selected by its outer env.
            if let Some(directory) = directory {
                directories.push(directory);
            }
        }
        None
    }

    pub fn is_prefixed(&self) -> bool {
        !self.prefix.trim().is_empty()
    }

    pub fn is_relocatable(&self) -> bool {
        !self.is_prefixed() || literal_suffix(self.command)
    }

    pub fn preserves_disk_scope(&self) -> bool {
        !self.disk_scope_conflict
    }

    pub fn working_directory(&self, workdir: &Path) -> Result<std::path::PathBuf> {
        ensure!(
            !self.is_prefixed() || literal_suffix(self.command),
            "dependency preparation requires a literal command after an environment prefix"
        );
        let mut directory = workdir.canonicalize()?;
        for next in &self.directories {
            directory = directory.join(next).canonicalize()?;
        }
        Ok(directory)
    }

    pub fn prepared_command(
        &self,
        workdir: &Path,
        project: &Path,
        preparation: &Path,
    ) -> Result<Command> {
        let selector = selector_command(
            &crate::native_worker_executable()?,
            workdir,
            project,
            preparation,
            self.runtime,
            self.command,
        )?;
        self.wrap_selector(selector)
    }

    fn wrap_selector(&self, selector: Command) -> Result<Command> {
        ensure!(
            !self.is_prefixed() || literal_suffix(self.command),
            "dependency preparation requires a literal command after an environment prefix"
        );
        if !self.is_prefixed() {
            return Ok(selector);
        }
        let arguments = std::iter::once(selector.as_std().get_program())
            .chain(selector.as_std().get_args())
            .map(|value| {
                value
                    .to_str()
                    .context("prepared invocation is not UTF-8")
                    .map(super::quote_shell_argument)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut wrapped = managed_command(selector.as_std().get_program());
        wrapped.args(["-c", &format!("{}{}", self.prefix, arguments.join(" "))]);
        Ok(wrapped)
    }
}

fn managed_disk_key(key: &str) -> bool {
    matches!(key, "CARGO_TARGET_DIR" | "TMPDIR" | "TMP" | "TEMP")
}

/// Relocating a prefix across shell expansion or a compound command would
/// change its scope. Only literal suffixes may enter the contextual selector.
fn literal_suffix(mut command: &str) -> bool {
    for _ in 0..4096 {
        if command.trim_start_matches([' ', '\t']).is_empty() {
            return true;
        }
        let Some((_, tail)) = literal_word(command) else {
            return false;
        };
        command = tail;
    }
    false
}

fn control_tool(name: &str, workdir: &Path) -> Result<std::path::PathBuf> {
    control_tool_in(name, std::env::var_os("PATH").as_deref(), workdir)
}

fn control_tool_in(name: &str, path: Option<&OsStr>, workdir: &Path) -> Result<std::path::PathBuf> {
    let path = path.unwrap_or_else(|| OsStr::new("/usr/bin:/bin"));
    for directory in std::env::split_paths(path) {
        // Command::current_dir applies before executable lookup. Relative
        // PATH entries (including an empty entry) belong to the requested
        // workdir, before any env -C in the invocation changes that directory.
        let directory = workdir.join(directory);
        for leaf in [name.to_owned(), format!("{name}{}", std::env::consts::EXE_SUFFIX)] {
            let candidate = directory.join(&leaf);
            let Ok(metadata) = candidate.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            // Preserve applet argv[0] on BusyBox. Resolve the directory, not
            // the executable symlink, before an env prefix can change cwd.
            let parent = candidate
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            return Ok(parent.canonicalize()?.join(leaf));
        }
    }
    anyhow::bail!("dependency preparation requires executable {name} on the worker PATH")
}

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
    selector_command(
        &crate::native_worker_executable()?,
        project,
        project,
        preparation,
        runtime,
        command,
    )
}

fn selector_command(
    worker: &Path,
    workdir: &Path,
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
    let shell = control_tool("sh", workdir)?;
    let head = control_tool("head", workdir)?;
    let od = control_tool("od", workdir)?;
    let mut selector = managed_command(&shell);
    selector
        .args(["-c", DISK_PREPARE_SELECTOR, "rch-worker-prepare"])
        .arg(worker)
        .arg(project)
        .arg(preparation)
        .arg(runtime)
        .arg(command)
        .arg(head)
        .arg(od)
        .arg(shell);
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
    fn literal_prefix_keeps_quotes_and_last_chdir_per_env() {
        let fixture = tempfile::tempdir().unwrap();
        for directory in ["first", "last", "first/child"] {
            std::fs::create_dir_all(fixture.path().join(directory)).unwrap();
        }
        let source = "CI='agent job' env -C first -C last npm run 'test:ci'";
        let invocation = Invocation::parse(source).unwrap();
        assert_eq!(invocation.prefix, "CI='agent job' env -C first -C last ");
        assert_eq!(invocation.command, "npm run 'test:ci'");
        assert!(invocation.is_relocatable());
        assert!(invocation.preserves_disk_scope());
        assert_eq!(
            invocation.working_directory(fixture.path()).unwrap(),
            fixture.path().join("last").canonicalize().unwrap()
        );
        let nested = Invocation::parse("env -C first env --chdir=child bun test").unwrap();
        assert_eq!(
            nested.working_directory(fixture.path()).unwrap(),
            fixture.path().join("first/child").canonicalize().unwrap()
        );
        for command in [
            "CI=1 npm test && printf after",
            "env -C first npm test ; pwd",
            "env VALUE=new npm test \"$VALUE\"",
            "env -C first npm test *.test.js",
            "env CI=1 npm test > result",
            "env CI=1 npm test\nprintf after",
        ] {
            let invocation = Invocation::parse(command).unwrap();
            assert!(!invocation.is_relocatable(), "{command}");
            assert!(invocation.working_directory(fixture.path()).is_err());
        }
        assert!(Invocation::parse("env -C first\\\nchild npm test").is_none());
        assert!(Invocation::parse("'CI=job' npm test").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn control_tools_skip_nonexecutables_and_keep_applet_names() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let fixture = tempfile::tempdir().unwrap();
        let denied = fixture.path().join("denied");
        let allowed = fixture.path().join("allowed");
        std::fs::create_dir(&denied).unwrap();
        std::fs::create_dir(&allowed).unwrap();
        std::fs::write(denied.join("head"), b"not executable").unwrap();
        let applet = allowed.join("fixture-app");
        std::fs::write(&applet, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&applet, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink("fixture-app", allowed.join("head")).unwrap();
        let path = std::env::join_paths([&denied, &allowed]).unwrap();
        let expected = allowed.canonicalize().unwrap().join("head");
        assert_eq!(
            control_tool_in("head", Some(&path), fixture.path()).unwrap(),
            expected
        );
        assert!(control_tool_in("head", Some(denied.as_os_str()), fixture.path()).is_err());

        // Relative PATH is anchored to the original workdir, not the worker
        // process cwd or the different project selected by an env -C prefix.
        let project = fixture.path().join("nested-project");
        std::fs::create_dir(&project).unwrap();
        let relative = OsStr::new("denied:allowed");
        assert_eq!(
            control_tool_in("head", Some(relative), fixture.path()).unwrap(),
            expected
        );
        assert!(control_tool_in("head", Some(relative), &project).is_err());
        assert_eq!(
            control_tool_in("head", Some(OsStr::new("")), &allowed).unwrap(),
            expected
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn contextual_selector_preserves_env_cwd_stdin_and_status_with_restricted_path() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Stdio;

        // Protocol fixtures isolate the selector from package-manager behavior.
        // The actual installer/transaction contracts have their own tests.
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path().join("nested project");
        let restricted = fixture.path().join("restricted");
        std::fs::create_dir_all(project.join("node_modules/.bin")).unwrap();
        std::fs::create_dir(&restricted).unwrap();
        let project = project.canonicalize().unwrap();
        let prepared_log = fixture.path().join("prepared");
        let workload_log = fixture.path().join("workload");
        let stdin_log = fixture.path().join("stdin");
        let worker = fixture.path().join("worker");
        let fields = [
            "$PWD",
            "${KEEP-unset}",
            "${REMOVE-unset}",
            "${PRESERVED-unset}",
            "$RCH_CARGO_WRAPPER_BYPASS",
            "$RCH_CARGO_WRAPPER_ORIGIN",
        ]
        .map(|value| format!("\"{value}\""))
        .join(" ");
        let worker_script = format!(
            "#!/bin/sh\nprintf '%s\\n' {fields} > {}\nif read -r unexpected; then exit 96; fi\nprintf '%s\\n' RCH_PREPARED_NODE_MODULES:0\n",
            super::super::quote_shell_argument(prepared_log.to_str().unwrap()),
        );
        let workload_script = format!(
            "#!/bin/sh\nprintf '%s\\n' {fields} \"$@\" > {}\n/bin/cat > {}\nexit 27\n",
            super::super::quote_shell_argument(workload_log.to_str().unwrap()),
            super::super::quote_shell_argument(stdin_log.to_str().unwrap()),
        );
        for (path, script) in [
            (worker.clone(), worker_script),
            (project.join("node_modules/.bin/npm"), workload_script),
            (restricted.join("npm"), "#!/bin/sh\nexit 97\n".to_owned()),
        ] {
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (reset, expected_preserved) in [("-i", "unset"), ("-u REMOVE", "inherited")] {
            let source = format!(
                "env {reset} -C {} PATH={} KEEP='literal value' npm test 'literal argument'",
                super::super::quote_shell_argument(project.to_str().unwrap()),
                super::super::quote_shell_argument(restricted.to_str().unwrap()),
            );
            let invocation = Invocation::parse(&source).unwrap();
            assert_eq!(invocation.working_directory(fixture.path()).unwrap(), project);
            let selector = selector_command(
                &worker,
                fixture.path(),
                &project,
                &project,
                RequiredRuntime::Node,
                invocation.command,
            )
            .unwrap();
            let mut command = invocation.wrap_selector(selector).unwrap();
            let mut child = command
                .current_dir(fixture.path())
                .env("REMOVE", "removed")
                .env("PRESERVED", "inherited")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .as_std_mut()
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(b"workload input\n").unwrap();
            let output = child.wait_with_output().unwrap();
            assert_eq!(output.status.code(), Some(27), "{output:?}");
            assert!(output.stdout.is_empty(), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            let expected = format!(
                "{}\nliteral value\nunset\n{expected_preserved}\n1\nrch\n",
                project.display()
            );
            assert_eq!(std::fs::read_to_string(&prepared_log).unwrap(), expected);
            assert_eq!(
                std::fs::read_to_string(&workload_log).unwrap(),
                format!("{expected}test\nliteral argument\n")
            );
            assert_eq!(std::fs::read(&stdin_log).unwrap(), b"workload input\n");
        }
    }

    #[cfg(unix)]
    #[test]
    fn selector_refuses_changed_cwd_before_preparation_or_workload() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Stdio;

        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path().join("expected");
        std::fs::create_dir(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let worker = fixture.path().join("worker");
        let marker = fixture.path().join("prepared");
        let output = fixture.path().join("workload");
        std::fs::write(
            &worker,
            format!(
                "#!/bin/sh\nprintf touched > {}\nprintf '%s\\n' RCH_PREPARED_NODE_MODULES:0\n",
                super::super::quote_shell_argument(marker.to_str().unwrap())
            ),
        )
        .unwrap();
        std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut selector = selector_command(
            &worker,
            fixture.path(),
            &project,
            &project,
            RequiredRuntime::Node,
            &format!(
                "printf started > {}",
                super::super::quote_shell_argument(output.to_str().unwrap())
            ),
        )
        .unwrap();
        let result = selector
            .current_dir(fixture.path())
            .stdin(Stdio::null())
            .as_std_mut()
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(121));
        assert!(!marker.exists(), "preparation ran in an unbound directory");
        assert!(!output.exists(), "workload ran after a cwd mismatch");
    }

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
        let project = project.canonicalize().unwrap();
        let mut selector = selector_command(
            &worker,
            &project,
            &project,
            &project,
            RequiredRuntime::Node,
            original,
        )
        .unwrap();
        let mut child = selector
            .current_dir(&project)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("RCH_TEST_ARGV", &argument_output)
            .env("RCH_TEST_STDIN", &stdin_output)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .as_std_mut()
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
