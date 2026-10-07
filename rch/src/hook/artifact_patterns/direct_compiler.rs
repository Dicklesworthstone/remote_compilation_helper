//! Direct-compiler outputs, relative to the project sync root.
//!
//! Cargo's target-directory convention does not apply to direct compilers.
//! Explicit Rustc selections require names for every emission. Native GCC/Clang
//! contracts also cover ordinary POSIX a.out/object/assembly defaults, while
//! named selections include depfiles and Clang -MJ fragments. Never
//! infer crate names from source filenames or transfer an arbitrary --out-dir
//! tree: crate attributes and target specifications can change implicit names.
//! Unsupported commands retain the caller's existing selection policy. Native
//! contracts are persisted and checked before publication; Rustc's explicit
//! selection alone is not an output-completeness or cache-publication proof.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

/// Every file a supported native command promises to its caller. Persist this
/// before execution: neither a stale destination nor one returned object can
/// stand in for another required object or dependency sidecar.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NativeOutputContract {
    pub(crate) required_files: BTreeSet<PathBuf>,
}

impl NativeOutputContract {
    fn from_paths(paths: impl IntoIterator<Item = String>) -> Option<Self> {
        let mut required_files = BTreeSet::new();
        for path in paths {
            literal_file_pattern(&path)?;
            let normalized: PathBuf = Path::new(&path)
                .components()
                .filter(|part| *part != Component::CurDir)
                .collect();
            required_files.insert(normalized);
        }
        (!required_files.is_empty()).then_some(Self { required_files })
    }

    pub(crate) fn patterns(&self) -> anyhow::Result<Vec<String>> {
        anyhow::ensure!(
            !self.required_files.is_empty(),
            "empty native output contract"
        );
        self.required_files
            .iter()
            .map(|path| {
                let text = path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF-8 native output"))?;
                anyhow::ensure!(
                    path.components()
                        .all(|part| matches!(part, Component::Normal(_))),
                    "native output must be a normalized relative path: {}",
                    path.display()
                );
                literal_file_pattern(text)
                    .ok_or_else(|| anyhow::anyhow!("invalid native output path: {text}"))
            })
            .collect()
    }

    /// Require regular files below real directories in the owned stage. Never
    /// follow an output symlink or accept the pre-existing local destination.
    pub(crate) fn verify_staged(&self, stage: &Path) -> anyhow::Result<()> {
        use anyhow::Context;
        self.patterns()?;
        let root = std::fs::symlink_metadata(stage).context("native output stage is missing")?;
        anyhow::ensure!(
            root.is_dir() && !root.file_type().is_symlink(),
            "invalid native output stage"
        );
        for relative in &self.required_files {
            let mut path = stage.to_owned();
            let mut components = relative.components().peekable();
            while let Some(component) = components.next() {
                path.push(component.as_os_str());
                let metadata = std::fs::symlink_metadata(&path).with_context(|| {
                    format!("required native output is missing: {}", path.display())
                })?;
                anyhow::ensure!(
                    !metadata.file_type().is_symlink()
                        && if components.peek().is_some() {
                            metadata.is_dir()
                        } else {
                            metadata.is_file()
                        },
                    "required native output is not a regular file below directories: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }
}

/// Implicit filenames are a property of the selected worker's compiler, not
/// the dispatcher. Callers enable defaults only on a POSIX worker; explicit
/// target/architecture options still decline implicit filename inference.
pub(crate) fn native_output_contract(
    kind: Option<rch_common::CompilationKind>,
    command: &str,
    posix_defaults: bool,
) -> Option<NativeOutputContract> {
    match kind? {
        rch_common::CompilationKind::Gcc => {
            c_family_outputs(command, &["gcc", "cc"], false, posix_defaults)
        }
        rch_common::CompilationKind::Gpp => {
            c_family_outputs(command, &["g++", "c++"], false, posix_defaults)
        }
        rch_common::CompilationKind::Clang => {
            c_family_outputs(command, &["clang"], true, posix_defaults)
        }
        rch_common::CompilationKind::Clangpp => {
            c_family_outputs(command, &["clang++"], true, posix_defaults)
        }
        rch_common::CompilationKind::GoBuild if posix_defaults => go_output_contract(command),
        _ => None,
    }
}

pub(super) fn patterns(
    kind: Option<rch_common::CompilationKind>,
    command: Option<&str>,
) -> Option<Vec<String>> {
    match (kind, command) {
        (Some(rch_common::CompilationKind::Rustc), Some(command)) => rustc_patterns(command),
        (Some(rch_common::CompilationKind::Gcc), Some(command)) => {
            c_family_patterns(command, &["gcc", "cc"], false)
        }
        (Some(rch_common::CompilationKind::Gpp), Some(command)) => {
            c_family_patterns(command, &["g++", "c++"], false)
        }
        (Some(rch_common::CompilationKind::Clang), Some(command)) => {
            c_family_patterns(command, &["clang"], true)
        }
        (Some(rch_common::CompilationKind::Clangpp), Some(command)) => {
            c_family_patterns(command, &["clang++"], true)
        }
        (Some(rch_common::CompilationKind::GoBuild), Some(command)) => {
            go_output_contract(command)?.patterns().ok()
        }
        _ => None,
    }
}

fn go_output_selection(command: &str) -> Option<rch_common::patterns::GoBuildOutput> {
    let args = compiler_arguments(command, &["go"])?;
    let plain = shell_words::join(std::iter::once("go").chain(args.iter().map(String::as_str)));
    rch_common::patterns::go_build_output(&plain)
}

fn go_output_contract(command: &str) -> Option<NativeOutputContract> {
    NativeOutputContract::from_paths([go_output_selection(command)?.path])
}

// Query names explicitly: older Go versions return an empty string for newer
// settings, so a worker gaining a new default cannot silently skip comparison.
const GO_BUILD_ENVIRONMENT: &[&str] = &[
    "GOFLAGS",
    "GOOS",
    "GOARCH",
    "GOVERSION",
    "CGO_ENABLED",
    "GOEXPERIMENT",
    "GODEBUG",
    "GO386",
    "GOAMD64",
    "GOARM",
    "GOARM64",
    "GOMIPS",
    "GOMIPS64",
    "GOPPC64",
    "GORISCV64",
    "GOWASM",
    "GOFIPS140",
    "CC",
    "CXX",
    "FC",
    "AR",
    "PKG_CONFIG",
    "CGO_CFLAGS",
    "CGO_CPPFLAGS",
    "CGO_CXXFLAGS",
    "CGO_FFLAGS",
    "CGO_LDFLAGS",
];

/// The caller's effective compiler and code-generation settings at admission.
/// Kept until the remote execution guard is built; recovery only collects the
/// completed output and never needs to run the compiler or its probe again.
#[derive(Clone, Debug)]
pub(in crate::hook) struct GoBuildEnvironment {
    settings: String,
}

/// Check the caller's effective Go configuration and output path before any
/// upload or compiler execution. A worker-only default must not silently turn
/// a native binary into another platform's binary, or a GOFLAGS dry run into a
/// successful delivery of an old file.
pub(in crate::hook) async fn validate_go_build_output(
    command: &str,
    project_root: &Path,
) -> anyhow::Result<GoBuildEnvironment> {
    use anyhow::Context;
    let probe = guarded_go_command(command, None)
        .context("Go build has no supported explicit file output contract")?;
    let mut go = tokio::process::Command::new("sh");
    go.args(["-c", &probe])
        .current_dir(project_root)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), go.output())
        .await
        .context("local Go output preflight timed out")?
        .context("local Go output preflight could not run")?;
    anyhow::ensure!(
        output.status.success(),
        "local Go output preflight refused remote execution: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    anyhow::ensure!(
        output.stdout.len() <= 65_536,
        "oversized Go build environment"
    );
    let settings = String::from_utf8(output.stdout).context("non-UTF-8 Go build environment")?;
    let values: BTreeMap<String, String> =
        serde_json::from_str(&settings).context("invalid Go build environment")?;
    anyhow::ensure!(
        values.len() == GO_BUILD_ENVIRONMENT.len()
            && GO_BUILD_ENVIRONMENT
                .iter()
                .all(|name| values.contains_key(*name)),
        "incomplete Go build environment"
    );
    let (goos, goarch) = native_go_target().context("unsupported native Go target")?;
    anyhow::ensure!(
        values["GOFLAGS"].is_empty() && values["GOOS"] == goos && values["GOARCH"] == goarch,
        "Go output delivery requires empty GOFLAGS and the dispatcher native GOOS/GOARCH"
    );
    Ok(GoBuildEnvironment {
        settings: settings.trim_end_matches('\n').to_owned(),
    })
}

/// Preserve the original wrappers and argv while validating the worker's Go
/// configuration. The compiler writes outside its source root, then stages a
/// fresh private file beside the destination for atomic replacement. Creating
/// output parents or a staging directory before package loading would change
/// wildcard go:embed inputs, including introducing empty-directory errors.
/// A zero exit without that fresh file cannot validate stale files uploaded
/// from the caller or left by an earlier remote build.
pub(in crate::hook) fn go_build_execution_command(
    command: &str,
    environment: &GoBuildEnvironment,
) -> Option<String> {
    guarded_go_command(command, Some(environment))
}

fn native_go_target() -> Option<(&'static str, &'static str)> {
    let goos = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "freebsd" => "freebsd",
        "openbsd" => "openbsd",
        "netbsd" => "netbsd",
        "dragonfly" => "dragonfly",
        _ => return None,
    };
    let goarch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        "arm" => "arm",
        "riscv64" => "riscv64",
        "s390x" => "s390x",
        _ => return None,
    };
    Some((goos, goarch))
}

fn guarded_go_command(command: &str, environment: Option<&GoBuildEnvironment>) -> Option<String> {
    let selection = go_output_selection(command)?;
    let contract = NativeOutputContract::from_paths([selection.path])?;
    let output = contract.required_files.first()?;
    let mut words = literal_words(command)?;
    let mut args = compiler_arguments(command, &["go"])?;
    let go_index = words.len().checked_sub(args.len() + 1)?;
    let go = words.get(go_index)?.clone();
    let query = shell_words::join(GO_BUILD_ENVIRONMENT);
    let output_text = shell_escape::escape(format!("./{}", output.to_str()?).into());
    let mut path_checks = String::new();
    for parent in output
        .ancestors()
        .skip(1)
        .filter(|path| !path.as_os_str().is_empty())
    {
        let parent = shell_escape::escape(format!("./{}", parent.to_str()?).into());
        path_checks.push_str(&format!(
            "if [ -L {parent} ] || {{ [ -e {parent} ] && [ ! -d {parent} ]; }}; then \
             printf '%s\\n' 'RCH: Go output parents must be real directories' >&2; return 113; fi; "
        ));
    }
    path_checks.push_str(&format!(
        "if [ -L {output_text} ] || {{ [ -e {output_text} ] && [ ! -f {output_text} ]; }}; then \
         printf '%s\\n' 'RCH: Go -o must name a regular file, not a directory or symlink' >&2; return 113; fi; "
    ));
    let terminal = if let Some(environment) = environment {
        // The shared parser supplies the actual option's position. Opaque
        // values such as `-tags -o` must not be rewritten as output options.
        let output_index = selection.option_index.checked_sub(1)?;
        let count = if args.get(output_index)? == "-o" {
            2
        } else {
            1
        };
        args.drain(output_index..output_index + count);
        args.remove(0); // build is supplied before the private -o below.
        let parent = shell_escape::escape(format!("./{}", output.parent()?.to_str()?).into());
        let expected = shell_escape::escape(environment.settings.as_str().into());
        format!(
            "rch_go_settings=$(\"$rch_go\" env -json {query}) || exit 113; \
             if [ \"$rch_go_settings\" != {expected} ]; then \
               printf '%s\\n' 'RCH: worker Go compiler/code-generation settings differ from the dispatcher' >&2; exit 113; fi; \
             rch_go_root=$(pwd -P) || exit 113; \
             rch_go_build=$(mktemp -d \"${{TMPDIR:-/tmp}}/rch-go-build.XXXXXXXXXX\") || exit 113; \
             rch_go_stage=; \
             trap 'rm -f \"$rch_go_build/output\"; rmdir \"$rch_go_build\"; \
               if [ -n \"$rch_go_stage\" ]; then rm -f \"$rch_go_stage/output\"; rmdir \"$rch_go_stage\"; fi' EXIT; \
             trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
             rch_go_build_root=$(cd \"$rch_go_build\" && pwd -P) || exit 113; \
             case \"$rch_go_build_root/\" in \"${{rch_go_root%/}}/\"*) \
               printf '%s\\n' 'RCH: Go build temporary directory must be outside the source root' >&2; exit 113;; esac; \
             \"$rch_go\" build -o \"$rch_go_build/output\" \"$@\"; \
             rch_go_status=$?; \
             if [ \"$rch_go_status\" -ne 0 ]; then exit \"$rch_go_status\"; fi; \
             if [ -L \"$rch_go_build/output\" ] || [ ! -f \"$rch_go_build/output\" ]; then \
               printf '%s\\n' 'RCH: Go build succeeded without its required output file' >&2; exit 113; fi; \
             rch_go_parent={parent}; \
             rch_go_check_output || exit 113; \
             mkdir -p \"$rch_go_parent\" || exit 113; \
             rch_go_check_output || exit 113; \
             rch_go_stage=$(mktemp -d \"$rch_go_parent/.rch-go-output.XXXXXXXXXX\") || exit 113; \
             cp -p \"$rch_go_build/output\" \"$rch_go_stage/output\" || exit 113; \
             rch_go_check_output || exit 113; \
             mv -f \"$rch_go_stage/output\" {output_text} || exit 113"
        )
    } else {
        format!("\"$rch_go\" env -json {query}")
    };
    let script = format!(
        "rch_go=$1; shift; \
         rch_go_check_output() {{ {path_checks} return 0; }}; \
         rch_go_check_output || exit 113; \
         {terminal}"
    );
    words.truncate(go_index);
    words.extend([
        "sh".to_owned(),
        "-c".to_owned(),
        script,
        "rch-go-output".to_owned(),
        go,
    ]);
    words.extend(args);
    Some(super::super::join_exec_command(&words))
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
                '$' | '`' | '|' | '&' | ';' | '<' | '>' | '(' | ')' | '*' | '?' | '[' | '{'
                | '}' | '~' | '#' => return None,
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
fn compiler_arguments(command: &str, compilers: &[&str]) -> Option<Vec<String>> {
    let words = literal_words(command)?;
    let assignment = |word: &str| {
        word.split_once('=')
            .is_some_and(|(key, _)| rch_common::ssh_utils::is_valid_env_key(key))
    };
    let mut index = 0;
    loop {
        while words.get(index).is_some_and(|word| assignment(word)) {
            let key = words[index].split_once('=')?.0;
            if matches!(key, "DEPENDENCIES_OUTPUT" | "SUNPRO_DEPENDENCIES") {
                return None;
            }
            index += 1;
        }
        let executable = Path::new(words.get(index)?).file_name()?.to_str()?;
        let executable = executable.strip_suffix(".exe").unwrap_or(executable);
        if compilers.iter().any(|compiler| {
            executable == *compiler
                || executable
                    .strip_prefix(*compiler)
                    .and_then(|suffix| suffix.strip_prefix('-'))
                    .is_some_and(|version| {
                        !version.is_empty()
                            && version
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || byte == b'.')
                    })
        }) {
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
                            || word.starts_with("-u") && word.len() > 2 =>
                        {
                            index += 1
                        }
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
                            || word.starts_with("-f") && word.len() > 2 =>
                        {
                            index += 1
                        }
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
        "--out-dir"
            | "--crate-name"
            | "--crate-type"
            | "--edition"
            | "--target"
            | "--extern"
            | "--cfg"
            | "--check-cfg"
            | "--sysroot"
            | "--error-format"
            | "--json"
            | "--color"
            | "--cap-lints"
            | "--diagnostic-width"
            | "--remap-path-prefix"
            | "--remap-path-scope"
            | "--codegen"
            | "--allow"
            | "--warn"
            | "--force-warn"
            | "--deny"
            | "--forbid"
            | "-A"
            | "-W"
            | "-D"
            | "-F"
            | "-L"
            | "-l"
    )
}

/// Raw linker/LLVM options and debug/temporary-output switches can add files
/// or even override the linker destination. Keep those on the legacy policy
/// rather than dropping their unnamed sidecars from an explicit selection.
fn named_output_codegen(value: &str) -> bool {
    let key = value.split_once('=').map_or(value, |(key, _)| key);
    matches!(
        key,
        "opt-level"
            | "target-cpu"
            | "target-feature"
            | "panic"
            | "overflow-checks"
            | "debug-assertions"
            | "embed-bitcode"
            | "lto"
            | "prefer-dynamic"
            | "relocation-model"
            | "code-model"
            | "no-redzone"
            | "force-frame-pointers"
            | "metadata"
            | "extra-filename"
            | "strip"
            | "symbol-mangling-version"
    ) || matches!(
        value,
        "debuginfo=0" | "split-debuginfo=off" | "codegen-units=1"
    )
}

fn add_emissions(value: &str, emits: &mut BTreeMap<String, Option<String>>) -> Option<()> {
    for item in value.split(',') {
        let (kind, path) = match item.split_once('=') {
            Some((kind, path)) if !path.is_empty() => (kind, Some(path.to_owned())),
            Some(_) => return None,
            None => (item, None),
        };
        if !matches!(
            kind,
            "asm" | "dep-info" | "link" | "llvm-bc" | "llvm-ir" | "metadata" | "mir" | "obj"
        ) {
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
    let args = compiler_arguments(command, &["rustc"])?;
    // Response-file expansion precedes ordinary option parsing, including --.
    if args.iter().any(|arg| arg.starts_with('@')) {
        return None;
    }
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
        } else if arg == "-C" || arg == "--codegen" {
            if !named_output_codegen(iter.next()?) {
                return None;
            }
        } else if let Some(value) = arg
            .strip_prefix("-C")
            .or_else(|| arg.strip_prefix("--codegen="))
        {
            if !named_output_codegen(value) {
                return None;
            }
        } else if rustc_value_option(arg) {
            iter.next()?;
        } else if arg
            .split_once('=')
            .is_some_and(|(key, _)| rustc_value_option(key))
            || ["-A", "-W", "-D", "-F", "-L", "-l"]
                .iter()
                .any(|prefix| arg.starts_with(*prefix) && arg.len() > prefix.len())
            || matches!(arg.as_str(), "-O" | "--test" | "-v" | "--verbose")
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

fn c_value_option(option: &str) -> bool {
    matches!(
        option,
        "-I" | "-L"
            | "-l"
            | "-D"
            | "-U"
            | "-x"
            | "-B"
            | "-isystem"
            | "-iquote"
            | "-idirafter"
            | "-include"
            | "-imacros"
            | "-isysroot"
            | "--sysroot"
            | "-target"
            | "--target"
            | "-arch"
            | "-MT"
            | "-MQ"
            | "-std"
    )
}

fn c_plain_option(option: &str) -> bool {
    matches!(
        option,
        "-c" | "-S"
            | "-shared"
            | "-static"
            | "-pie"
            | "-pthread"
            | "-pipe"
            | "-pedantic"
            | "-pedantic-errors"
            | "-ansi"
            | "-nostdinc"
            | "-nostdinc++"
            | "-nostdlib"
            | "-nodefaultlibs"
            | "-nostartfiles"
            | "-fPIC"
            | "-fpic"
            | "-fPIE"
            | "-fpie"
            | "-fno-exceptions"
            | "-fexceptions"
            | "-fno-rtti"
            | "-frtti"
            | "-fomit-frame-pointer"
            | "-fno-omit-frame-pointer"
            | "-fno-strict-aliasing"
            | "-fstrict-aliasing"
            | "-ffunction-sections"
            | "-fdata-sections"
            | "-m32"
            | "-m64"
            | "-g0"
            | "-O"
            | "-O0"
            | "-O1"
            | "-O2"
            | "-O3"
            | "-Os"
            | "-Oz"
            | "-Og"
            | "-Ofast"
            | "-emit-llvm"
            | "-MP"
    ) || option.starts_with("-W")
        && !option.starts_with("-Wl,")
        && !option.starts_with("-Wa,")
        && !option.starts_with("-Wp,")
        || [
            "-std=",
            "--std=",
            "-march=",
            "-mtune=",
            "-mcpu=",
            "-mabi=",
            "-fvisibility=",
        ]
        .iter()
        .any(|prefix| option.starts_with(*prefix))
}

/// Native driver outputs with an explicit -o and their dependency sidecars.
/// Without -MF, -MD/-MMD derives the depfile from -o for one ordinary C/C++
/// source. Multi-input or language-overridden inference, preprocessing-only
/// modes, raw subtool options, debug sidecars and response files retain the
/// previous policy; they are not an exact selection.
fn c_family_patterns(command: &str, compilers: &[&str], clang: bool) -> Option<Vec<String>> {
    c_family_outputs(command, compilers, clang, false)?
        .patterns()
        .ok()
}

fn c_family_outputs(
    command: &str,
    compilers: &[&str],
    clang: bool,
    posix_defaults: bool,
) -> Option<NativeOutputContract> {
    let args = compiler_arguments(command, compilers)?;
    if args.iter().any(|arg| arg.starts_with('@')) {
        return None;
    }
    let mut iter = args.iter();
    let mut output: Option<String> = None;
    let mut depfile: Option<String> = None;
    let mut database: Option<String> = None;
    let mut dependencies = false;
    let mut sources = Vec::new();
    let mut language_override = false;
    let mut target_override = false;
    let mut compile_only = false;
    let mut assembly_only = false;
    let mut llvm_emission = false;
    while let Some(arg) = iter.next() {
        if arg == "--" {
            for input in iter {
                sources.push(input.as_str());
            }
            break;
        }
        // These Clang options overlap the spelling of joined -o. They can
        // rewrite source or change compiler output semantics, so do not parse
        // them as requests for files named bjc..., bject..., or penmp....
        if arg.starts_with("-objc") || arg.starts_with("-object") || arg.starts_with("-openmp") {
            return None;
        }
        if arg == "-o" || arg == "--output" {
            if output.replace(iter.next()?.to_string()).is_some() {
                return None;
            }
        } else if let Some(path) = arg
            .strip_prefix("--output=")
            .or_else(|| arg.strip_prefix("-o"))
        {
            if output.replace(path.to_owned()).is_some() {
                return None;
            }
        } else if arg == "-MF" {
            if depfile.replace(iter.next()?.to_string()).is_some() {
                return None;
            }
        } else if let Some(path) = arg.strip_prefix("-MF") {
            if depfile.replace(path.to_owned()).is_some() {
                return None;
            }
        } else if arg == "-MJ" && clang {
            if database.replace(iter.next()?.to_string()).is_some() {
                return None;
            }
        } else if clang && arg.starts_with("-MJ") {
            if database.replace(arg[3..].to_owned()).is_some() {
                return None;
            }
        } else if matches!(arg.as_str(), "-MD" | "-MMD") {
            dependencies = true;
        } else if arg == "-c" {
            compile_only = true;
        } else if arg == "-S" {
            assembly_only = true;
        } else if arg == "-emit-llvm" {
            llvm_emission = true;
        } else if c_value_option(arg) {
            language_override |= arg == "-x";
            target_override |= matches!(arg.as_str(), "-target" | "--target" | "-arch");
            iter.next()?;
        } else if c_plain_option(arg)
            || ["-I", "-L", "-l", "-D", "-U", "-B", "-MT", "-MQ"]
                .iter()
                .any(|prefix| arg.starts_with(*prefix) && arg.len() > prefix.len())
            || arg
                .split_once('=')
                .is_some_and(|(key, _)| c_value_option(key))
        {
            // A flag's operand is opaque even when it looks like -o or -MF.
            language_override |= arg.starts_with("-x=");
            target_override |= arg.starts_with("-target=")
                || arg.starts_with("--target=")
                || arg.starts_with("-arch=")
                || arg.starts_with("-march=")
                || arg.starts_with("-mtune=")
                || arg.starts_with("-mcpu=")
                || arg.starts_with("-mabi=")
                || matches!(arg.as_str(), "-m32" | "-m64");
        } else if arg.starts_with('-') || arg.starts_with('@') || arg.is_empty() {
            return None;
        } else {
            sources.push(arg.as_str());
        }
    }
    let inputs = sources.len();
    if output.is_none() {
        if !posix_defaults
            || inputs == 0
            || language_override
            || target_override
            || llvm_emission
            || dependencies
            || depfile.is_some()
            || database.is_some()
            || compile_only && assembly_only
        {
            return None;
        }
        let ordinary_source = |source: &str| {
            Path::new(source)
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| {
                    matches!(
                        ext,
                        "c" | "C" | "cc" | "cp" | "cpp" | "CPP" | "cxx" | "c++" | "m" | "M" | "mm"
                    )
                })
        };
        if compile_only || assembly_only {
            let extension = if compile_only { "o" } else { "s" };
            let mut outputs = BTreeSet::new();
            for source in sources {
                if !ordinary_source(source) {
                    return None;
                }
                let name = Path::new(source).file_name()?.to_str()?;
                let (stem, _) = name.rsplit_once('.')?;
                let output = format!("{stem}.{extension}");
                if !outputs.insert(output) {
                    return None;
                }
            }
            return NativeOutputContract::from_paths(outputs);
        }
        if !sources.iter().all(|source| {
            ordinary_source(source)
                || Path::new(source)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| matches!(ext, "o" | "a" | "so" | "dylib"))
        }) {
            return None;
        }
        return NativeOutputContract::from_paths(["a.out".to_owned()]);
    }
    let output = output?;
    // '-' is mode-specific in native drivers (stdout in some modes, a real
    // linker filename in others), unlike rustc's uniform stdout convention.
    if inputs == 0 || output == "-" || !dependencies && depfile.is_some() {
        return None;
    }
    let mut paths = BTreeSet::from([output.clone()]);
    if dependencies && depfile.is_none() {
        if inputs != 1 || language_override {
            return None;
        }
        let extension = Path::new(sources[0]).extension()?.to_str()?;
        if !matches!(
            extension,
            "c" | "C" | "cc" | "cp" | "cpp" | "CPP" | "cxx" | "c++" | "m" | "M" | "mm"
        ) {
            return None;
        }
        // The drivers replace the last dot suffix INCLUDING a leading dot:
        // -o products/.hidden yields products/.d, not .hidden.d. Rust's
        // Path::with_extension treats dotfiles differently and is wrong here.
        let (parent, name) = output
            .rsplit_once('/')
            .map_or(("", output.as_str()), |(parent, name)| {
                (&output[..parent.len() + 1], name)
            });
        let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
        depfile = Some(format!("{parent}{stem}.d"));
    }
    if let Some(depfile) = depfile
        && depfile != "-"
    {
        paths.insert(depfile);
    }
    if let Some(database) = database
        && database != "-"
    {
        // Clang -MJ - emits a database fragment on stdout, not a file '-'.
        paths.insert(database);
    }
    NativeOutputContract::from_paths(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_outputs_are_exact_required_project_files() {
        use rch_common::CompilationKind;
        let kind = Some(CompilationKind::GoBuild);
        for (command, path, pattern) in [
            ("go build -o app main.go", "app", "app"),
            (
                "env GOFLAGS= /usr/bin/time -p go build -o './products/app [dev]*?' .",
                "products/app [dev]*?",
                "products/app [[]dev[]][*][?]",
            ),
            ("go build -o=target/app .", "target/app", "target/app"),
        ] {
            let contract = native_output_contract(kind, command, true).unwrap();
            assert_eq!(
                contract.required_files,
                BTreeSet::from([PathBuf::from(path)])
            );
            assert_eq!(contract.patterns().unwrap(), vec![pattern]);
            assert_eq!(
                super::super::get_artifact_patterns(kind, Some(command)),
                vec![pattern]
            );
            assert_eq!(
                super::super::get_project_artifact_patterns(kind, Some(command), true),
                vec![pattern],
                "forwarded Cargo target must not suppress Go outputs"
            );
            assert!(
                super::super::get_custom_target_artifact_patterns(kind, Some(command)).is_empty()
            );
            assert!(super::super::kind_produces_transferable_artifacts(kind));
            assert!(native_output_contract(kind, command, false).is_none());
        }
        for command in [
            "go build .",
            "go build -o app -n .",
            "go build -o app -buildmode=c-shared .",
            "env -C other go build -o app .",
            "time -o timing.txt go build -o app .",
            "sh -c 'go build -o app .'",
        ] {
            assert!(
                native_output_contract(kind, command, true).is_none(),
                "{command}"
            );
            assert!(guarded_go_command(command, None).is_none(), "{command}");
        }
    }

    #[test]
    fn native_implicit_outputs_are_enumerated_per_source_and_selected_worker() {
        use rch_common::CompilationKind;
        for (kind, driver) in [
            (CompilationKind::Gcc, "gcc"),
            (CompilationKind::Gpp, "g++"),
            (CompilationKind::Clang, "clang"),
            (CompilationKind::Clangpp, "clang++"),
        ] {
            for (args, expected) in [
                ("main.c support.o", vec!["a.out"]),
                ("-O2 -c main.c src/helper.cpp", vec!["helper.o", "main.o"]),
                ("-S main.c src/helper.cpp", vec!["helper.s", "main.s"]),
                ("-c 'src/odd[1]*?.c'", vec!["odd[[]1[]][*][?].o"]),
            ] {
                let command = format!("{driver} {args}");
                let contract = native_output_contract(Some(kind), &command, true).unwrap();
                assert_eq!(contract.patterns().unwrap(), expected, "{command}");
                assert!(
                    native_output_contract(Some(kind), &command, false).is_none(),
                    "implicit filenames must not be inferred for another worker platform"
                );
            }
            for args in [
                "-c src/same.c other/same.c",
                "-S -c main.c",
                "-E main.c",
                "-fsyntax-only main.c",
                "-x c main.c",
                "--target=x86_64-pc-windows-gnu main.c",
                "-target x86_64-apple-darwin main.c",
                "-arch arm64 main.c",
                "-m32 main.c",
                "-march=native main.c",
                "-mtune=generic main.c",
                "-mcpu=power9 main.c",
                "-mabi=ms main.c",
                "-emit-llvm -c main.c",
                "-MMD main.c",
                "-MD -MF named.d main.c",
                "-MJ fragment.json main.c",
                "-c objects.o",
                "header.h",
                "@arguments",
                "*.c",
                "-save-temps main.c",
                "-gsplit-dwarf main.c",
                "-Wl,-o,other main.c",
            ] {
                let command = format!("{driver} {args}");
                assert!(
                    native_output_contract(Some(kind), &command, true).is_none(),
                    "{command}"
                );
            }
        }
    }

    #[test]
    fn native_explicit_contract_keeps_raw_paths_and_all_sidecars() {
        use rch_common::CompilationKind;
        let contract = native_output_contract(Some(CompilationKind::Clang),
            "clang -c main.c -o './products/item[1]*?.o' -MMD -MF reports/input.d -MJ reports/compile.json", false).unwrap();
        assert_eq!(
            contract.required_files,
            BTreeSet::from([
                PathBuf::from("products/item[1]*?.o"),
                PathBuf::from("reports/input.d"),
                PathBuf::from("reports/compile.json"),
            ])
        );
        assert_eq!(
            contract.patterns().unwrap(),
            vec![
                "products/item[[]1[]][*][?].o",
                "reports/compile.json",
                "reports/input.d"
            ]
        );
        let restored: NativeOutputContract =
            serde_json::from_slice(&serde_json::to_vec(&contract).unwrap()).unwrap();
        assert_eq!(restored, contract);
        for path in ["../outside", "/absolute", "", "bad\npath"] {
            let invalid = NativeOutputContract {
                required_files: BTreeSet::from([PathBuf::from(path)]),
            };
            assert!(invalid.patterns().is_err(), "{path:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_required_output_symlinks_and_directories_cannot_satisfy_delivery() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let contract = NativeOutputContract::from_paths(["products/output.o".into()]).unwrap();
        let stage = root.path().join("stage");
        let outside = root.path().join("outside");
        std::fs::create_dir(&stage).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("output.o"), b"not owned by stage").unwrap();
        symlink(&outside, stage.join("products")).unwrap();
        assert!(contract.verify_staged(&stage).is_err());
        let stage = root.path().join("regular");
        std::fs::create_dir_all(stage.join("products/output.o")).unwrap();
        assert!(contract.verify_staged(&stage).is_err());
        let stage = root.path().join("file-link");
        std::fs::create_dir_all(stage.join("products")).unwrap();
        symlink(outside.join("output.o"), stage.join("products/output.o")).unwrap();
        assert!(contract.verify_staged(&stage).is_err());
    }

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
            assert_eq!(
                patterns,
                if command == "rustc main.rs -o app" {
                    vec!["app"]
                } else {
                    vec!["dist/app"]
                }
            );
        }
    }

    #[test]
    fn rustc_named_emissions_override_output_and_ignore_out_dir() {
        assert_eq!(
            selected(
                "rustc lib.rs --emit=link,dep-info=reports/inputs.d --out-dir ignored -o dist/libcustom.rlib"
            ),
            vec!["dist/libcustom.rlib", "reports/inputs.d"]
        );
        assert_eq!(
            selected(
                "rustc lib.rs --emit=metadata=old --emit=metadata=out/new.rmeta,mir=out/code.mir -o ignored"
            ),
            vec!["out/code.mir", "out/new.rmeta"]
        );
        assert_eq!(
            selected("rustc lib.rs --emit=asm=-,metadata=out/lib.rmeta"),
            vec!["out/lib.rmeta"]
        );
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
            "rustc lib.rs -C 'opt-level=3' -o real",
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
            "rustc -o app -- @args",
            "rustc main.rs -o first -o second",
            "rustc main.rs --future-option -o decoy",
            "rustc main.rs -g -o app",
            "rustc main.rs -Clink-arg=-oelsewhere -o app",
            "rustc main.rs -Csave-temps -o app",
            "rustc main.rs --codegen=debuginfo=2 -o app",
            "rustc main.rs -Zunstable-options -o app",
            "rustc --version -o decoy",
            "env -C subdir rustc main.rs -o app",
            "env -S 'rustc main.rs -o app'",
            "sh -c 'rustc main.rs -o app'",
            "time -o timing rustc main.rs -o app'",
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
        assert_eq!(
            selected("rustc main.rs -o 'dist/app[dev]*?'"),
            vec!["dist/app[[]dev[]][*][?]"]
        );
        assert_eq!(selected("rustc main.rs -o '- output'"), vec!["[-] output"]);
        assert_eq!(
            selected(r"rustc main.rs -o 'dist/back\slash'"),
            vec![r"dist/back[\\]slash"]
        );
        assert_eq!(
            selected("rustc main.rs -o 'dist/$literal'"),
            vec!["dist/$literal"]
        );
    }

    #[test]
    fn explicit_project_outputs_survive_unrelated_cargo_target_forwarding() {
        use super::super::{
            get_artifact_patterns, get_custom_target_artifact_patterns,
            get_project_artifact_patterns,
        };
        let kind = Some(rch_common::CompilationKind::Rustc);
        let command = Some("rustc main.rs -o target/direct/app");
        assert_eq!(
            get_artifact_patterns(kind, command),
            vec!["target/direct/app"]
        );
        assert_eq!(
            get_project_artifact_patterns(kind, command, true),
            vec!["target/direct/app"]
        );
        assert!(get_custom_target_artifact_patterns(kind, command).is_empty());
    }

    #[test]
    fn native_drivers_return_explicit_primary_outputs_instead_of_broad_build_globs() {
        use rch_common::CompilationKind;
        for (kind, command) in [
            (CompilationKind::Gcc, "gcc -O2 main.c -o products/app"),
            (
                CompilationKind::Gcc,
                "env -- cc -std=c11 main.c -oproducts/app",
            ),
            (
                CompilationKind::Gcc,
                "/usr/bin/time -f '-o decoy' -- gcc-14 main.c -o products/app",
            ),
            (
                CompilationKind::Gpp,
                "ccache g++-14.2 main.cpp --output=products/app",
            ),
            (CompilationKind::Gpp, "c++ main.cpp -o ./products/app"),
            (CompilationKind::Clang, "clang -O3 main.c -o products/app"),
            (
                CompilationKind::Clangpp,
                "sccache /usr/bin/clang++ main.cpp -o products/app",
            ),
        ] {
            assert_eq!(
                patterns(Some(kind), Some(command)),
                Some(vec!["products/app".into()]),
                "{command}"
            );
        }
        assert!(patterns(Some(CompilationKind::Gcc), Some("echo gcc main.c -o app")).is_none());
        assert!(patterns(Some(CompilationKind::Make), Some("make -o Makefile")).is_none());
    }

    #[test]
    fn native_named_depfiles_and_clang_database_fragments_are_part_of_selection() {
        let native = |command| c_family_patterns(command, &["gcc", "cc"], false).unwrap();
        assert_eq!(
            native("gcc -c main.c -o products/main.o -MMD -MF products/main.d -MP"),
            vec!["products/main.d", "products/main.o"]
        );
        assert_eq!(
            native("gcc main.c -o products/app -MD -MFproducts/all.d"),
            vec!["products/all.d", "products/app"]
        );
        assert_eq!(
            native("gcc main.c -o products/app -MMD -MF -"),
            vec!["products/app"]
        );
        assert_eq!(
            native("gcc main.c -o products/app -MMD -MF ./-"),
            vec!["[-]", "products/app"]
        );
        assert_eq!(
            c_family_patterns(
                "clang main.c -o products/app -MMD -MF products/app.d -MJ products/compile.json",
                &["clang"],
                true
            )
            .unwrap(),
            vec!["products/app", "products/app.d", "products/compile.json"]
        );
        assert_eq!(
            c_family_patterns("clang main.c -o products/app -MJ-", &["clang"], true).unwrap(),
            vec!["products/app"]
        );
        assert_eq!(
            c_family_patterns("clang main.c -o products/app -MJ./-", &["clang"], true).unwrap(),
            vec!["[-]", "products/app"]
        );
    }

    #[test]
    fn native_single_source_default_depfiles_follow_driver_suffix_rules() {
        for driver in ["gcc", "clang"] {
            for mode in ["", "-c", "-S"] {
                for (output, dependency) in [
                    ("products/app", "products/app.d"),
                    ("products/app.bin", "products/app.d"),
                    ("products/archive.part.exe", "products/archive.part.d"),
                    ("products/.hidden", "products/.d"),
                    ("products.v1/app", "products.v1/app.d"),
                ] {
                    let command = format!("{driver} {mode} main.c -MMD -o {output}");
                    let mut expected = vec![output.to_owned(), dependency.to_owned()];
                    expected.sort();
                    assert_eq!(
                        c_family_patterns(&command, &[driver], driver == "clang").unwrap(),
                        expected,
                        "{command}"
                    );
                }
            }
        }
        assert_eq!(
            c_family_patterns("gcc main.c -MD -o 'products/app[dev]*?'", &["gcc"], false).unwrap(),
            vec![
                "products/app[[]dev[]][*][?]",
                "products/app[[]dev[]][*][?].d"
            ]
        );
    }

    #[test]
    fn native_option_values_are_opaque_and_filename_filters_are_literal() {
        for option in ["-D", "-I", "-L", "-include", "-imacros", "-MT", "-MQ"] {
            let command = format!("gcc main.c {option} '-odecoy' -o real");
            assert_eq!(
                c_family_patterns(&command, &["gcc"], false).unwrap(),
                vec!["real"]
            );
        }
        assert_eq!(
            c_family_patterns("gcc main.c -o 'products/app[dev]*?'", &["gcc"], false).unwrap(),
            vec!["products/app[[]dev[]][*][?]"]
        );
        assert_eq!(
            c_family_patterns(
                "clang main.c -o '- output' -MMD -MF 'products/dep[1].d'",
                &["clang"],
                true
            )
            .unwrap(),
            vec!["[-] output", "products/dep[[]1[]].d"]
        );
    }

    #[test]
    fn native_implicit_sidecars_forwarded_options_and_reparsing_do_not_narrow_selection() {
        for command in [
            "gcc main.c",
            "gcc main.c extra.c -o app -MMD",
            "gcc main.o -o app -MMD",
            "gcc main.i -o app -MMD",
            "gcc main.c -x c-header -o app -MMD",
            "gcc main.c -o app -MF unused.d",
            "gcc main.c -o app -MJ clang-only.json",
            "gcc main.c -o first -o second",
            "gcc main.c -o app -MMD -MF first.d -MF second.d",
            "gcc main.c -o app -g",
            "gcc main.c -o app -gsplit-dwarf",
            "gcc main.c -o app --coverage",
            "gcc main.c -o app -save-temps",
            "gcc main.c -o app -Wl,-o,other",
            "gcc main.c -o app -Wa,--MD,other.d",
            "gcc main.c -o app -Wp,-MMD,other.d",
            "gcc main.c -o app -Xlinker -oother",
            "gcc main.c -o app -E",
            "gcc main.c -o app -M",
            "gcc main.c -o app -fsyntax-only",
            "gcc main.c -o -",
            "gcc @args -o app",
            "gcc -o app -- @args",
            "env DEPENDENCIES_OUTPUT=hidden.d gcc main.c -o app",
            "SUNPRO_DEPENDENCIES=hidden.d gcc main.c -o app",
            "env -C elsewhere gcc main.c -o app",
            "gcc main.c -o $OUT",
            "gcc main.c -o products/*",
            "gcc main.c -o ../app",
            "gcc main.c -o /tmp/app",
        ] {
            assert!(
                c_family_patterns(command, &["gcc"], false).is_none(),
                "{command}"
            );
        }
        for command in [
            "clang main.c -o app -object-file-name=other",
            "clang main.c -o app -objcmt-migrate-all",
            "clang main.c -o app -Xclang -emit-pch",
            "clang main.c -o app -MJ first.json -MJ second.json",
        ] {
            assert!(
                c_family_patterns(command, &["clang"], true).is_none(),
                "{command}"
            );
        }
    }

    #[test]
    fn native_artifacts_and_depfiles_remain_project_rooted_under_custom_target_sync() {
        use super::super::{get_custom_target_artifact_patterns, get_project_artifact_patterns};
        use rch_common::CompilationKind;
        for (kind, driver) in [
            (CompilationKind::Gcc, "gcc"),
            (CompilationKind::Gpp, "g++"),
            (CompilationKind::Clang, "clang"),
            (CompilationKind::Clangpp, "clang++"),
        ] {
            let command =
                format!("{driver} main.c -o target/native/app -MMD -MF target/native/app.d");
            assert_eq!(
                get_project_artifact_patterns(Some(kind), Some(&command), true),
                vec!["target/native/app", "target/native/app.d"]
            );
            assert!(get_custom_target_artifact_patterns(Some(kind), Some(&command)).is_empty());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_native_builds_return_runnable_outputs_and_named_sidecars_without_decoys() {
        use super::super::get_project_artifact_patterns;
        use rch_common::CompilationKind;
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        async fn run(command: &mut Command) -> std::process::Output {
            command.stdin(Stdio::null()).kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(20), command.output())
                .await
                .expect("owned native artifact fixture exceeded its deadline")
                .expect("gcc, clang and rsync are required for the native artifact regression");
            assert!(output.status.success(), "{output:?}");
            output
        }

        let root = tempfile::tempdir().unwrap().keep();
        for (driver, kind, named_dependency) in [
            ("gcc", CompilationKind::Gcc, true),
            ("gcc", CompilationKind::Gcc, false),
            ("clang", CompilationKind::Clang, true),
            ("clang", CompilationKind::Clang, false),
        ] {
            let mode = if named_dependency { "named" } else { "default" };
            let source = root.join(driver).join(mode).join("worker");
            let local = root.join(driver).join(mode).join("local");
            for base in [&source, &local] {
                std::fs::create_dir_all(base.join("products")).unwrap();
            }
            std::fs::write(source.join("main.c"),
                b"#include <stdio.h>\n#include \"message.h\"\nint main(void) { puts(MESSAGE); return 0; }\n").unwrap();
            std::fs::write(
                source.join("message.h"),
                b"#define MESSAGE \"remote-artifact-ok\"\n",
            )
            .unwrap();
            std::fs::write(local.join("main.c"), b"local source sentinel\n").unwrap();
            let binary = "products/app[dev]*?";
            let depfile = if named_dependency {
                "products/app.d"
            } else {
                "products/app[dev]*?.d"
            };
            let fragment = "products/app.compile.json";
            let mut argv = vec!["main.c", "-O2", "-MMD", "-o", binary];
            if named_dependency {
                argv.extend(["-MF", depfile]);
            }
            let mut files = vec![binary, depfile];
            if driver == "clang" {
                argv.extend(["-MJ", fragment]);
                files.push(fragment);
            }
            let mut compiler = Command::new(driver);
            compiler
                .args(&argv)
                .current_dir(&source)
                .env_remove("DEPENDENCIES_OUTPUT")
                .env_remove("SUNPRO_DEPENDENCIES");
            run(&mut compiler).await;
            std::fs::write(local.join(binary), b"stale local output").unwrap();
            std::fs::write(source.join("products/appdOTHER1"), b"wildcard decoy").unwrap();
            std::fs::write(source.join("products/foreign.o"), b"unrelated object").unwrap();
            let command = shell_words::join(std::iter::once(driver).chain(argv.iter().copied()));
            let patterns = get_project_artifact_patterns(Some(kind), Some(&command), true);
            assert_eq!(patterns.len(), files.len());
            for _ in 0..2 {
                // Repeated transfer must also preserve the no-op/current case.
                let mut rsync = Command::new("rsync");
                rsync.args([
                    "-a",
                    "--checksum",
                    "--no-owner",
                    "--no-group",
                    "--safe-links",
                    "--prune-empty-dirs",
                    "--include=*/",
                ]);
                for pattern in &patterns {
                    assert!(!pattern.starts_with("- "));
                    rsync.arg(format!("--include=/{pattern}"));
                }
                rsync
                    .arg("--exclude=*")
                    .arg(format!("{}/", source.display()))
                    .arg(format!("{}/", local.display()));
                run(&mut rsync).await;
                for path in &files {
                    assert_eq!(
                        std::fs::read(local.join(path)).unwrap(),
                        std::fs::read(source.join(path)).unwrap()
                    );
                }
                assert!(
                    std::fs::read_to_string(local.join(depfile))
                        .unwrap()
                        .contains("message.h")
                );
                assert_eq!(
                    std::fs::read(local.join("main.c")).unwrap(),
                    b"local source sentinel\n"
                );
                assert!(!local.join("products/appdOTHER1").exists());
                assert!(!local.join("products/foreign.o").exists());
                let mut executable = Command::new(local.join(binary));
                assert_eq!(run(&mut executable).await.stdout, b"remote-artifact-ok\n");
            }
            if driver == "clang" {
                // -MJ is a comma-terminated fragment, not a complete database.
                let fragment = std::fs::read_to_string(local.join(fragment)).unwrap();
                let database = format!("[{}]", fragment.trim().trim_end_matches(','));
                let records: serde_json::Value = serde_json::from_str(&database).unwrap();
                assert_eq!(records[0]["file"], "main.c");
            }
        }
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
        std::fs::write(local.join("dist/main.rs"), b"local source sentinel\n").unwrap();
        let patterns = get_project_artifact_patterns(
            Some(rch_common::CompilationKind::Rustc),
            Some("rustc main.rs --emit=link,dep-info=dist/inputs.d -o 'dist/app[dev]*?'"),
            true,
        );
        let mut command = Command::new("rsync");
        command.args([
            "-a",
            "--checksum",
            "--no-owner",
            "--no-group",
            "--safe-links",
            "--prune-empty-dirs",
            "--include=*/",
        ]);
        for pattern in &patterns {
            assert!(!pattern.starts_with("- "));
            command.arg(format!("--include=/{pattern}"));
        }
        command
            .arg("--exclude=*")
            .arg(format!("{}/", source.display()))
            .arg(format!("{}/", local.display()))
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(10), command.output())
            .await
            .expect("rsync deadline")
            .expect("rsync is required for artifact delivery tests");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            std::fs::read(local.join(binary)).unwrap(),
            b"new compiled artifact\0\xff"
        );
        assert_eq!(
            std::fs::read(local.join("dist/inputs.d")).unwrap(),
            b"artifact: main.rs\n"
        );
        assert_eq!(
            std::fs::read(local.join("dist/main.rs")).unwrap(),
            b"local source sentinel\n"
        );
        assert!(!local.join("dist/appdOTHER1").exists());
        assert!(!local.join("target").exists());
    }
}
