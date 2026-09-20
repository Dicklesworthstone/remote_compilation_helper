//! Explicit direct-compiler outputs, relative to the project sync root.
//!
//! Cargo's target-directory convention does not apply to `rustc -o file`.
//! Resolve primary outputs only when the command names every emission. Never
//! infer crate names from source filenames or transfer an arbitrary --out-dir
//! tree: crate attributes and target specifications can change implicit names.
//! Unsupported commands retain the caller's existing selection policy. This is
//! retrieval selection, not a cache-publication or output-completeness proof.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub(super) fn patterns(
    kind: Option<rch_common::CompilationKind>,
    command: Option<&str>,
) -> Option<Vec<String>> {
    match (kind, command) {
        (Some(rch_common::CompilationKind::Rustc), Some(command)) => rustc_patterns(command),
        _ => None,
    }
}

/// Shell-words is a tokenizer, not an expansion engine. Admit only a literal
/// argv before dropping quoting information. In particular, a quoted `*` is a
/// filename while an unquoted one can expand to several shell arguments.
fn literal_words(command: &str) -> Option<Vec<String>> {
    if command.len() > 65_536 {
        return None;
    }
    let mut quote = None;
    let mut escaped = false;
    for ch in command.chars() {
        if matches!(ch, '\0' | '\r' | '\n') {
            return None;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                }
            }
            Some('"') => match ch {
                '"' => quote = None,
                '\\' => escaped = true,
                '$' | '`' => return None,
                _ => {}
            },
            _ => match ch {
                '\'' | '"' => quote = Some(ch),
                '\\' => escaped = true,
                '$' | '`' | '|' | '&' | ';' | '<' | '>' | '(' | ')' | '*' | '?'
                | '[' | '{' | '}' | '~' | '#' => return None,
                _ => {}
            },
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    let words = shell_words::split(command).ok()?;
    (words.len() <= 4096).then_some(words)
}

/// Skip only wrappers whose argv and working directory are unchanged. Do not
/// search arbitrary option values for a compiler name. env -C/-S, shells and
/// unknown wrapper options require a different execution/root contract.
fn compiler_arguments(command: &str, compiler: &str) -> Option<Vec<String>> {
    let words = literal_words(command)?;
    let assignment = |word: &str| {
        word.split_once('=')
            .is_some_and(|(key, _)| rch_common::ssh_utils::is_valid_env_key(key))
    };
    let mut index = 0;
    loop {
        while words.get(index).is_some_and(|word| assignment(word)) {
            index += 1;
        }
        let executable = Path::new(words.get(index)?).file_name()?.to_str()?;
        if executable == compiler || executable.strip_suffix(".exe") == Some(compiler) {
            return Some(words[index + 1..].to_vec());
        }
        match executable {
            "env" => {
                index += 1;
                while let Some(word) = words.get(index) {
                    match word.as_str() {
                        "--" => {
                            index += 1;
                            break;
                        }
                        "-i" | "--ignore-environment" => index += 1,
                        "-u" | "--unset" => {
                            words.get(index + 1)?;
                            index += 2;
                        }
                        _ if word.starts_with("--unset=")
                            || word.starts_with("-u") && word.len() > 2 => index += 1,
                        _ if word.starts_with('-') => return None,
                        _ => break,
                    }
                }
            }
            "rustup" => {
                if words.get(index + 1)?.as_str() != "run" {
                    return None;
                }
                index += 2;
                if words.get(index).is_some_and(|word| word == "--install") {
                    index += 1;
                }
                if words.get(index).is_some_and(|word| word == "--") {
                    index += 1;
                }
                let channel = words.get(index)?;
                if channel.is_empty() || channel.starts_with('-') {
                    return None;
                }
                index += 1;
            }
            "time" => {
                index += 1;
                while let Some(word) = words.get(index) {
                    match word.as_str() {
                        "--" => {
                            index += 1;
                            break;
                        }
                        "-f" | "--format" => {
                            words.get(index + 1)?;
                            index += 2;
                        }
                        "-p" | "--portability" | "-v" | "--verbose" | "-q" | "--quiet" => {
                            index += 1;
                        }
                        _ if word.starts_with("--format=")
                            || word.starts_with("-f") && word.len() > 2 => index += 1,
                        // time -o has its own file output; do not mistake that
                        // path for the compiler's output or drop its contract.
                        _ if word.starts_with('-') => return None,
                        _ => break,
                    }
                }
            }
            "ccache" | "sccache" => index += 1,
            _ => return None,
        }
    }
}

/// A literal filename, not a caller-controlled rsync filter. Bracket quoting
/// also forces rsync's wildcard parser for literal backslashes. Protect a
/// leading '-' from the pipeline's special '- ' exclusion-rule convention.
fn literal_file_pattern(path: &str) -> Option<String> {
    if path.is_empty() || path.ends_with('/') || path.chars().any(char::is_control) {
        return None;
    }
    let mut components = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(name) => components.push(name.to_str()?),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if components.is_empty() {
        return None;
    }
    let normalized = components.join("/");
    let mut pattern = String::new();
    for (index, ch) in normalized.chars().enumerate() {
        match ch {
            '*' => pattern.push_str("[*]"),
            '?' => pattern.push_str("[?]"),
            '[' => pattern.push_str("[[]"),
            ']' => pattern.push_str("[]]"),
            '\\' => pattern.push_str(r"[\\]"),
            '-' if index == 0 => pattern.push_str("[-]"),
            _ => pattern.push(ch),
        }
    }
    Some(pattern)
}

fn rustc_value_option(option: &str) -> bool {
    matches!(
        option,
        "--out-dir" | "--crate-name" | "--crate-type" | "--edition" | "--target"
            | "--extern" | "--cfg" | "--check-cfg" | "--sysroot" | "--error-format"
            | "--json" | "--color" | "--cap-lints" | "--diagnostic-width"
            | "--remap-path-prefix" | "--remap-path-scope" | "--codegen"
            | "--allow" | "--warn" | "--force-warn" | "--deny" | "--forbid"
            | "-A" | "-W" | "-D" | "-F" | "-L" | "-l" | "-C" | "-Z"
    )
}

fn add_emissions(value: &str, emits: &mut BTreeMap<String, Option<String>>) -> Option<()> {
    for item in value.split(',') {
        let (kind, path) = match item.split_once('=') {
            Some((kind, path)) if !path.is_empty() => (kind, Some(path.to_owned())),
            Some(_) => return None,
            None => (item, None),
        };
        if !matches!(kind, "asm" | "dep-info" | "link" | "llvm-bc" | "llvm-ir" | "metadata" | "mir" | "obj") {
            return None;
        }
        // rustc's OutputTypes map retains the last value for a repeated kind.
        emits.insert(kind.to_owned(), path);
    }
    Some(())
}

/// Resolve named primary rustc emissions. KIND=PATH outranks -o; rustc adapts
/// -o into inferred filenames only when MORE THAN ONE emission is unnamed.
/// Refuse that inference rather than copying a stale file at the original -o.
/// No crate/source/target naming guesses or recursive --out-dir includes occur.
/// `Some([])` is an explicitly stdout-only invocation, not an unknown layout.
pub(super) fn rustc_patterns(command: &str) -> Option<Vec<String>> {
    let args = compiler_arguments(command, "rustc")?;
    let mut iter = args.iter().peekable();
    if iter.peek().is_some_and(|arg| arg.starts_with('+')) {
        let _ = iter.next();
    }
    let mut output: Option<String> = None;
    let mut emits = BTreeMap::new();
    let mut sources = 0;
    while let Some(arg) = iter.next() {
        if arg == "--" {
            sources += iter.count();
            break;
        }
        if arg == "-o" {
            if output.replace(iter.next()?.to_string()).is_some() {
                return None;
            }
        } else if let Some(path) = arg.strip_prefix("-o") {
            if output.replace(path.to_owned()).is_some() {
                return None;
            }
        } else if arg == "--emit" {
            add_emissions(iter.next()?, &mut emits)?;
        } else if let Some(value) = arg.strip_prefix("--emit=") {
            add_emissions(value, &mut emits)?;
        } else if rustc_value_option(arg) {
            iter.next()?;
        } else if arg.split_once('=').is_some_and(|(key, _)| rustc_value_option(key))
            || ["-A", "-W", "-D", "-F", "-L", "-l", "-C", "-Z"]
                .iter().any(|prefix| arg.starts_with(*prefix) && arg.len() > prefix.len())
            || matches!(arg.as_str(), "-O" | "-g" | "--test" | "-v" | "--verbose")
        {
            // Opaque option values are never rescanned for output flags.
        } else if arg.starts_with('-') || arg.starts_with('@') || arg.is_empty() {
            return None;
        } else {
            sources += 1;
        }
    }
    if sources != 1 {
        return None;
    }
    if emits.is_empty() {
        emits.insert("link".to_owned(), None);
    }
    let unnamed = emits.values().filter(|path| path.is_none()).count();
    if unnamed > 1 || unnamed == 1 && output.is_none() {
        return None;
    }
    let mut patterns = BTreeSet::new();
    for path in emits.values() {
        let path = path.as_ref().or(output.as_ref())?;
        if path != "-" {
            patterns.insert(literal_file_pattern(path)?);
        }
    }
    Some(patterns.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected(command: &str) -> Vec<String> {
        rustc_patterns(command).unwrap_or_else(|| panic!("missing explicit plan: {command}"))
    }

    #[test]
    fn rustc_named_binary_is_not_a_cargo_target_tree() {
        for command in [
            "rustc main.rs -o app",
            "/opt/rust/bin/rustc -O main.rs -o ./dist/app",
            "env -- RUST_BACKTRACE=1 rustup run nightly rustc +nightly main.rs -odist/app",
            "/usr/bin/time -f '-o decoy' -- rustc main.rs -o dist/app",
            "sccache rustc main.rs -o dist/app",
        ] {
            let patterns = selected(command);
            assert_eq!(patterns, if command == "rustc main.rs -o app" { vec!["app"] } else { vec!["dist/app"] });
        }
    }

    #[test]
    fn rustc_named_emissions_override_output_and_ignore_out_dir() {
        assert_eq!(
            selected("rustc lib.rs --emit=link,dep-info=reports/inputs.d --out-dir ignored -o dist/libcustom.rlib"),
            vec!["dist/libcustom.rlib", "reports/inputs.d"]
        );
        assert_eq!(
            selected("rustc lib.rs --emit=metadata=old --emit=metadata=out/new.rmeta,mir=out/code.mir -o ignored"),
            vec!["out/code.mir", "out/new.rmeta"]
        );
        assert_eq!(selected("rustc lib.rs --emit=asm=-,metadata=out/lib.rmeta"), vec!["out/lib.rmeta"]);
        assert!(selected("rustc lib.rs --emit=asm -o -").is_empty());
        assert_eq!(selected("rustc lib.rs --emit=asm -o ./-"), vec!["[-]"]);
    }

    #[test]
    fn opaque_rustc_values_cannot_invent_outputs() {
        for command in [
            "rustc lib.rs --cfg '-odecoy' -o real",
            "rustc lib.rs --remap-path-prefix '-o=decoy' -o real",
            "rustc lib.rs -L '-odecoy' -o real",
            "rustc lib.rs --extern '-odecoy' -o real",
            "rustc lib.rs -C 'link-arg=-odecoy' -o real",
        ] {
            assert_eq!(selected(command), vec!["real"]);
        }
    }

    #[test]
    fn unresolved_output_names_and_reparsed_commands_keep_legacy_policy() {
        for command in [
            "rustc main.rs",
            "rustc main.rs --out-dir dist",
            "rustc lib.rs --emit=link,metadata -o dist/base",
            "rustc @args -o dist/base",
            "rustc main.rs -o first -o second",
            "rustc main.rs --future-option -o decoy",
            "rustc --version -o decoy",
            "env -C subdir rustc main.rs -o app",
            "env -S 'rustc main.rs -o app'",
            "sh -c 'rustc main.rs -o app'",
            "time -o timing rustc main.rs -o app",
            "rustc main.rs -o $OUT",
            "rustc main.rs -o $(pwd)/app",
            "rustc main.rs -o app; touch elsewhere",
            "rustc main.rs -o app && echo complete",
            "rustc main.rs -o out/*",
            "rustc main.rs -o out/{a,b}",
            "rustc main.rs -o 'unterminated",
            "rustc main.rs -o /outside/app",
            "rustc main.rs -o ../app",
            "rustc main.rs -o safe/../app",
            "rustc main.rs -o dir/",
        ] {
            assert!(rustc_patterns(command).is_none(), "{command}");
        }
    }

    #[test]
    fn quoted_filenames_are_literal_rsync_patterns_not_filters() {
        assert_eq!(selected("rustc main.rs -o 'dist/app[dev]*?'"), vec!["dist/app[[]dev[]][*][?]"]);
        assert_eq!(selected("rustc main.rs -o '- output'"), vec!["[-] output"]);
        assert_eq!(selected(r"rustc main.rs -o 'dist/back\slash'"), vec![r"dist/back[\\]slash"]);
        assert_eq!(selected("rustc main.rs -o 'dist/$literal'"), vec!["dist/$literal"]);
    }

    #[test]
    fn explicit_project_outputs_survive_unrelated_cargo_target_forwarding() {
        use super::super::{get_artifact_patterns, get_custom_target_artifact_patterns, get_project_artifact_patterns};
        let kind = Some(rch_common::CompilationKind::Rustc);
        let command = Some("rustc main.rs -o target/direct/app");
        assert_eq!(get_artifact_patterns(kind, command), vec!["target/direct/app"]);
        assert_eq!(get_project_artifact_patterns(kind, command, true), vec!["target/direct/app"]);
        assert!(get_custom_target_artifact_patterns(kind, command).is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_rsync_returns_named_rustc_outputs_without_source_or_wildcard_decoys() {
        use super::super::get_project_artifact_patterns;
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        let root = tempfile::tempdir().unwrap().keep();
        let source = root.join("worker");
        let local = root.join("local");
        for base in [&source, &local] {
            std::fs::create_dir_all(base.join("dist")).unwrap();
        }
        let binary = "dist/app[dev]*?";
        std::fs::write(source.join(binary), b"new compiled artifact\0\xff").unwrap();
        std::fs::write(local.join(binary), b"old local artifact").unwrap();
        std::fs::write(source.join("dist/inputs.d"), b"artifact: main.rs\n").unwrap();
        std::fs::write(source.join("dist/appdOTHER1"), b"wildcard decoy").unwrap();
        std::fs::write(source.join("dist/main.rs"), b"foreign source").unwrap();
        std::fs::write(local.join("dist/main.rs"), b"local source sentinel").unwrap();
        let patterns = get_project_artifact_patterns(
            Some(rch_common::CompilationKind::Rustc),
            Some("rustc main.rs --emit=link,dep-info=dist/inputs.d -o 'dist/app[dev]*?'"),
            true,
        );
        let mut command = Command::new("rsync");
        command.args(["-a", "--checksum", "--no-owner", "--no-group", "--safe-links", "--prune-empty-dirs", "--include=*/"]);
        for pattern in &patterns {
            assert!(!pattern.starts_with("- "));
            command.arg(format!("--include=/{pattern}"));
        }
        command.arg("--exclude=*")
            .arg(format!("{}/", source.display())).arg(format!("{}/", local.display()))
            .stdin(Stdio::null()).kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(10), command.output()).await
            .expect("rsync deadline").expect("rsync is required for artifact delivery tests");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(std::fs::read(local.join(binary)).unwrap(), b"new compiled artifact\0\xff");
        assert_eq!(std::fs::read(local.join("dist/inputs.d")).unwrap(), b"artifact: main.rs\n");
        assert_eq!(std::fs::read(local.join("dist/main.rs")).unwrap(), b"local source sentinel");
        assert!(!local.join("dist/appdOTHER1").exists());
        assert!(!local.join("target").exists());
    }
}
