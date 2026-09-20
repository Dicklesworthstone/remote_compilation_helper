//! Explicit direct-compiler outputs, relative to the project sync root.
//!
//! Cargo's target-directory convention does not apply to direct compilers.
//! Resolve primary outputs only when the command names every emission. Native
//! GCC/Clang selections include explicit depfiles and Clang -MJ fragments. Never
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
            executable == *compiler || executable.strip_prefix(*compiler)
                .and_then(|suffix| suffix.strip_prefix('-'))
                .is_some_and(|version| !version.is_empty()
                    && version.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.'))
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
            | "-A" | "-W" | "-D" | "-F" | "-L" | "-l"
    )
}

/// Raw linker/LLVM options and debug/temporary-output switches can add files
/// or even override the linker destination. Keep those on the legacy policy
/// rather than dropping their unnamed sidecars from an explicit selection.
fn named_output_codegen(value: &str) -> bool {
    let key = value.split_once('=').map_or(value, |(key, _)| key);
    matches!(key, "opt-level" | "target-cpu" | "target-feature" | "panic"
        | "overflow-checks" | "debug-assertions" | "embed-bitcode" | "lto"
        | "prefer-dynamic" | "relocation-model" | "code-model" | "no-redzone"
        | "force-frame-pointers" | "metadata" | "extra-filename" | "strip"
        | "symbol-mangling-version")
        || matches!(value, "debuginfo=0" | "split-debuginfo=off" | "codegen-units=1")
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
        } else if let Some(value) = arg.strip_prefix("-C")
            .or_else(|| arg.strip_prefix("--codegen="))
        {
            if !named_output_codegen(value) {
                return None;
            }
        } else if rustc_value_option(arg) {
            iter.next()?;
        } else if arg.split_once('=').is_some_and(|(key, _)| rustc_value_option(key))
            || ["-A", "-W", "-D", "-F", "-L", "-l"]
                .iter().any(|prefix| arg.starts_with(*prefix) && arg.len() > prefix.len())
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
    matches!(option, "-I" | "-L" | "-l" | "-D" | "-U" | "-x" | "-B"
        | "-isystem" | "-iquote" | "-idirafter" | "-include" | "-imacros"
        | "-isysroot" | "--sysroot" | "-target" | "--target" | "-arch"
        | "-MT" | "-MQ" | "-std")
}

fn c_plain_option(option: &str) -> bool {
    matches!(option, "-c" | "-S" | "-shared" | "-static" | "-pie" | "-pthread"
        | "-pipe" | "-pedantic" | "-pedantic-errors" | "-ansi" | "-nostdinc"
        | "-nostdinc++" | "-nostdlib" | "-nodefaultlibs" | "-nostartfiles"
        | "-fPIC" | "-fpic" | "-fPIE" | "-fpie" | "-fno-exceptions"
        | "-fexceptions" | "-fno-rtti" | "-frtti" | "-fomit-frame-pointer"
        | "-fno-omit-frame-pointer" | "-fno-strict-aliasing" | "-fstrict-aliasing"
        | "-ffunction-sections" | "-fdata-sections" | "-m32" | "-m64" | "-g0"
        | "-O" | "-O0" | "-O1" | "-O2" | "-O3" | "-Os" | "-Oz" | "-Og" | "-Ofast"
        | "-emit-llvm" | "-MP")
        || option.starts_with("-W") && !option.starts_with("-Wl,")
            && !option.starts_with("-Wa,") && !option.starts_with("-Wp,")
        || ["-std=", "--std=", "-march=", "-mtune=", "-mcpu=", "-mabi=", "-fvisibility="]
            .iter().any(|prefix| option.starts_with(*prefix))
}

/// Native driver outputs with an explicit -o, and optional explicitly named
/// depfiles / Clang compilation-database fragments. Inferred depfile names,
/// preprocessing-only modes, raw subtool options, debug sidecars and response
/// files retain the previous policy; they are not an exact named selection.
fn c_family_patterns(command: &str, compilers: &[&str], clang: bool) -> Option<Vec<String>> {
    let args = compiler_arguments(command, compilers)?;
    if args.iter().any(|arg| arg.starts_with('@')) {
        return None;
    }
    let mut iter = args.iter();
    let mut output: Option<String> = None;
    let mut depfile: Option<String> = None;
    let mut database: Option<String> = None;
    let mut dependencies = false;
    let mut inputs = 0;
    while let Some(arg) = iter.next() {
        if arg == "--" {
            inputs += iter.count();
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
        } else if let Some(path) = arg.strip_prefix("--output=").or_else(|| arg.strip_prefix("-o")) {
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
        } else if c_value_option(arg) {
            iter.next()?;
        } else if c_plain_option(arg)
            || ["-I", "-L", "-l", "-D", "-U", "-B", "-MT", "-MQ"]
                .iter().any(|prefix| arg.starts_with(*prefix) && arg.len() > prefix.len())
            || arg.split_once('=').is_some_and(|(key, _)| c_value_option(key))
        {
            // A flag's operand is opaque even when it looks like -o or -MF.
        } else if arg.starts_with('-') || arg.starts_with('@') || arg.is_empty() {
            return None;
        } else {
            inputs += 1;
        }
    }
    let output = output?;
    // '-' is mode-specific in native drivers (stdout in some modes, a real
    // linker filename in others), unlike rustc's uniform stdout convention.
    if inputs == 0 || output == "-" || dependencies != depfile.is_some() {
        return None;
    }
    let mut patterns = BTreeSet::from([literal_file_pattern(&output)?]);
    if let Some(depfile) = depfile && depfile != "-" {
        patterns.insert(literal_file_pattern(&depfile)?);
    }
    if let Some(database) = database && database != "-" {
        // Clang -MJ - emits a database fragment on stdout, not a file '-'.
        patterns.insert(literal_file_pattern(&database)?);
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

    #[test]
    fn native_drivers_return_explicit_primary_outputs_instead_of_broad_build_globs() {
        use rch_common::CompilationKind;
        for (kind, command) in [
            (CompilationKind::Gcc, "gcc -O2 main.c -o products/app"),
            (CompilationKind::Gcc, "env -- cc -std=c11 main.c -oproducts/app"),
            (CompilationKind::Gcc, "/usr/bin/time -f '-o decoy' -- gcc-14 main.c -o products/app"),
            (CompilationKind::Gpp, "ccache g++-14.2 main.cpp --output=products/app"),
            (CompilationKind::Gpp, "c++ main.cpp -o ./products/app"),
            (CompilationKind::Clang, "clang -O3 main.c -o products/app"),
            (CompilationKind::Clangpp, "sccache /usr/bin/clang++ main.cpp -o products/app"),
        ] {
            assert_eq!(patterns(Some(kind), Some(command)), Some(vec!["products/app".into()]), "{command}");
        }
        assert!(patterns(Some(CompilationKind::Gcc), Some("echo gcc main.c -o app")).is_none());
        assert!(patterns(Some(CompilationKind::Make), Some("make -o Makefile")).is_none());
    }

    #[test]
    fn native_named_depfiles_and_clang_database_fragments_are_part_of_selection() {
        let native = |command| c_family_patterns(command, &["gcc", "cc"], false).unwrap();
        assert_eq!(native("gcc -c main.c -o products/main.o -MMD -MF products/main.d -MP"),
            vec!["products/main.d", "products/main.o"]);
        assert_eq!(native("gcc main.c -o products/app -MD -MFproducts/all.d"),
            vec!["products/all.d", "products/app"]);
        assert_eq!(native("gcc main.c -o products/app -MMD -MF -"), vec!["products/app"]);
        assert_eq!(native("gcc main.c -o products/app -MMD -MF ./-"), vec!["[-]", "products/app"]);
        assert_eq!(c_family_patterns("clang main.c -o products/app -MMD -MF products/app.d -MJ products/compile.json", &["clang"], true).unwrap(),
            vec!["products/app", "products/app.d", "products/compile.json"]);
        assert_eq!(c_family_patterns("clang main.c -o products/app -MJ-", &["clang"], true).unwrap(),
            vec!["products/app"]);
        assert_eq!(c_family_patterns("clang main.c -o products/app -MJ./-", &["clang"], true).unwrap(),
            vec!["[-]", "products/app"]);
    }

    #[test]
    fn native_option_values_are_opaque_and_filename_filters_are_literal() {
        for option in ["-D", "-I", "-L", "-include", "-imacros", "-MT", "-MQ"] {
            let command = format!("gcc main.c {option} '-odecoy' -o real");
            assert_eq!(c_family_patterns(&command, &["gcc"], false).unwrap(), vec!["real"]);
        }
        assert_eq!(c_family_patterns("gcc main.c -o 'products/app[dev]*?'", &["gcc"], false).unwrap(),
            vec!["products/app[[]dev[]][*][?]"]);
        assert_eq!(c_family_patterns("clang main.c -o '- output' -MMD -MF 'products/dep[1].d'", &["clang"], true).unwrap(),
            vec!["[-] output", "products/dep[[]1[]].d"]);
    }

    #[test]
    fn native_implicit_sidecars_forwarded_options_and_reparsing_do_not_narrow_selection() {
        for command in [
            "gcc main.c",
            "gcc main.c -o app -MMD",
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
            assert!(c_family_patterns(command, &["gcc"], false).is_none(), "{command}");
        }
        for command in [
            "clang main.c -o app -object-file-name=other",
            "clang main.c -o app -objcmt-migrate-all",
            "clang main.c -o app -Xclang -emit-pch",
            "clang main.c -o app -MJ first.json -MJ second.json",
        ] {
            assert!(c_family_patterns(command, &["clang"], true).is_none(), "{command}");
        }
    }

    #[test]
    fn native_artifacts_and_depfiles_remain_project_rooted_under_custom_target_sync() {
        use super::super::{get_custom_target_artifact_patterns, get_project_artifact_patterns};
        use rch_common::CompilationKind;
        for (kind, driver) in [(CompilationKind::Gcc, "gcc"), (CompilationKind::Gpp, "g++"),
            (CompilationKind::Clang, "clang"), (CompilationKind::Clangpp, "clang++")]
        {
            let command = format!("{driver} main.c -o target/native/app -MMD -MF target/native/app.d");
            assert_eq!(get_project_artifact_patterns(Some(kind), Some(&command), true),
                vec!["target/native/app", "target/native/app.d"]);
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
            let output = tokio::time::timeout(Duration::from_secs(20), command.output()).await
                .expect("owned native artifact fixture exceeded its deadline")
                .expect("gcc, clang and rsync are required for the native artifact regression");
            assert!(output.status.success(), "{output:?}");
            output
        }

        let root = tempfile::tempdir().unwrap().keep();
        for (driver, kind) in [("gcc", CompilationKind::Gcc), ("clang", CompilationKind::Clang)] {
            let source = root.join(driver).join("worker");
            let local = root.join(driver).join("local");
            for base in [&source, &local] {
                std::fs::create_dir_all(base.join("products")).unwrap();
            }
            std::fs::write(source.join("main.c"),
                b"#include <stdio.h>\n#include \"message.h\"\nint main(void) { puts(MESSAGE); return 0; }\n").unwrap();
            std::fs::write(source.join("message.h"), b"#define MESSAGE \"remote-artifact-ok\"\n").unwrap();
            std::fs::write(local.join("main.c"), b"local source sentinel\n").unwrap();
            let binary = "products/app[dev]*?";
            let depfile = "products/app.d";
            let fragment = "products/app.compile.json";
            let mut argv = vec!["main.c", "-O2", "-MMD", "-MF", depfile, "-o", binary];
            let mut files = vec![binary, depfile];
            if driver == "clang" {
                argv.extend(["-MJ", fragment]);
                files.push(fragment);
            }
            let mut compiler = Command::new(driver);
            compiler.args(&argv).current_dir(&source)
                .env_remove("DEPENDENCIES_OUTPUT").env_remove("SUNPRO_DEPENDENCIES");
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
                rsync.args(["-a", "--checksum", "--no-owner", "--no-group", "--safe-links",
                    "--prune-empty-dirs", "--include=*/"]);
                for pattern in &patterns {
                    assert!(!pattern.starts_with("- "));
                    rsync.arg(format!("--include=/{pattern}"));
                }
                rsync.arg("--exclude=*")
                    .arg(format!("{}/", source.display())).arg(format!("{}/", local.display()));
                run(&mut rsync).await;
                for path in &files {
                    assert_eq!(std::fs::read(local.join(path)).unwrap(), std::fs::read(source.join(path)).unwrap());
                }
                assert!(std::fs::read_to_string(local.join(depfile)).unwrap().contains("message.h"));
                assert_eq!(std::fs::read(local.join("main.c")).unwrap(), b"local source sentinel\n");
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
        assert_eq!(std::fs::read(local.join("dist/main.rs")).unwrap(), b"local source sentinel\n");
        assert!(!local.join("dist/appdOTHER1").exists());
        assert!(!local.join("target").exists());
    }
}
