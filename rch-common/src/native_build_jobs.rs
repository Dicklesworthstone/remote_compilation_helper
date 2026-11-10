//! One scheduling interpretation for native-build admission and execution.
//!
//! The plan retains the original shell bytes and changes only understood job
//! options. It accepts a single literal command, including transparent process
//! wrappers, and declines expansion, shell composition, jobserver controls and
//! opaque backend arguments. Callers must keep a declined native build local;
//! using a guessed reservation with its unchanged command would be unbounded.
//!
//! These limits govern the build tool's scheduler. Recipes that start their own
//! independent parallel work still need to participate in that tool's jobserver.
//! In particular, do not export a replacement MAKEFLAGS: an explicit top-level
//! `make -j N` creates and propagates its own valid worker-side jobserver.

use crate::CompilationKind;
use std::ops::Range;

/// A literal native build whose scheduling controls can be bounded together.
#[derive(Debug, Clone)]
pub struct NativeBuildJobs {
    command: String,
    insertion: usize,
    job_options: Vec<Range<usize>>,
    flag: &'static str,
    ninja_target_separator: bool,
    requested: Option<u32>,
}

impl NativeBuildJobs {
    /// The effective finite request, or `None` for a backend default/unlimited
    /// request. Plain Make is serial and therefore returns `Some(1)`.
    #[must_use]
    pub fn requested_jobs(&self) -> Option<u32> {
        self.requested
    }

    /// Preserve a smaller finite request and cap everything else to the actual
    /// reservation. A zero reservation cannot authorize an executable command.
    #[must_use]
    pub fn bounded_command(&self, slots: u32) -> Option<String> {
        if slots == 0 {
            return None;
        }
        let jobs = self.requested.unwrap_or(slots).min(slots);
        let mut command = self.command.clone();
        // All controls follow the insertion point, and the parser records
        // nonoverlapping ranges in command order. Keep every other byte intact,
        // including quoting, wrapper arguments, assignments and target names.
        for range in self.job_options.iter().rev() {
            command.replace_range(range.clone(), "");
        }
        // Meson resolves requested target names into output filenames before
        // appending them to Ninja's argv. A harmless target name can resolve
        // to an output such as -j64, so preserve the argument boundary in the
        // backend too. Other Meson backends ignore this Ninja-only option.
        let separator = if self.ninja_target_separator {
            " --ninja-args=--"
        } else {
            ""
        };
        command.insert_str(self.insertion, &format!(" {} {jobs}{separator}", self.flag));
        Some(command)
    }
}

/// The command classes which require native scheduler admission.
#[must_use]
pub const fn is_native_build_kind(kind: CompilationKind) -> bool {
    matches!(
        kind,
        CompilationKind::Make
            | CompilationKind::Ninja
            | CompilationKind::CmakeBuild
            | CompilationKind::Meson
    )
}

/// Parse the same controls used both to reserve slots and to execute the build.
/// Unknown options are deliberately declined: an abbreviation, wrapper or
/// backend escape hatch must not silently override the injected scheduler cap.
#[must_use]
pub fn native_build_jobs(kind: CompilationKind, command: &str) -> Option<NativeBuildJobs> {
    if !is_native_build_kind(kind) {
        return None;
    }
    let words = literal_words(command)?;
    let (program, environment_jobs) = native_program(kind, command, &words)?;
    let mut plan = NativeBuildJobs {
        command: command.to_owned(),
        insertion: words[program].end,
        job_options: Vec::new(),
        flag: "-j",
        ninja_target_separator: kind == CompilationKind::Meson,
        requested: None,
    };
    let jobs = match kind {
        CompilationKind::Make => {
            make_jobs(&words, program + 1, &mut plan.job_options)?.or(Some(Jobs::Finite(1)))
        }
        CompilationKind::Ninja => ninja_jobs(&words, program + 1, &mut plan.job_options)?,
        CompilationKind::CmakeBuild => {
            let build = words.get(program + 1)?;
            let directory = words.get(program + 2)?;
            if build.value != "--build"
                || directory.value.is_empty()
                || directory.value.starts_with('-')
            {
                return None;
            }
            plan.insertion = directory.end;
            plan.flag = "--parallel";
            cmake_jobs(&words, program + 3, &mut plan.job_options)?.or(environment_jobs)
        }
        CompilationKind::Meson => {
            let verb = words.get(program + 1)?;
            if verb.value != "compile" {
                return None;
            }
            plan.insertion = verb.end;
            meson_jobs(&words, program + 2, &mut plan.job_options)?
        }
        _ => return None,
    };
    plan.requested = jobs.and_then(|jobs| match jobs {
        Jobs::Finite(jobs) => Some(jobs),
        Jobs::Automatic => None,
    });
    Some(plan)
}

#[derive(Debug, Clone, Copy)]
enum Jobs {
    Finite(u32),
    Automatic,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Syntax {
    Make,
    Ninja,
    Cmake,
    Meson,
    CmakeBackend,
}

impl Syntax {
    fn long(self) -> Option<&'static str> {
        match self {
            Self::Make | Self::Meson => Some("--jobs"),
            Self::Cmake => Some("--parallel"),
            Self::Ninja | Self::CmakeBackend => None,
        }
    }

    fn is_jobs(self, word: &str) -> bool {
        word.starts_with("-j")
            || self
                .long()
                .is_some_and(|long| word == long || word.starts_with(&format!("{long}=")))
    }
}

fn count(value: &str, syntax: Syntax) -> Option<Jobs> {
    if syntax == Syntax::Meson
        && value
            .strip_prefix('-')
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
    {
        return Some(Jobs::Automatic);
    }
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match value.parse::<u32>().ok()? {
        0 if matches!(syntax, Syntax::Ninja | Syntax::Meson) => Some(Jobs::Automatic),
        0 => None,
        jobs => Some(Jobs::Finite(jobs)),
    }
}

fn take_jobs(
    words: &[Word],
    index: &mut usize,
    syntax: Syntax,
    ranges: &mut Vec<Range<usize>>,
) -> Option<Jobs> {
    let start = *index;
    let word = words.get(start)?.value.as_str();
    let separate = word == "-j" || syntax.long() == Some(word);
    let jobs = if separate {
        let next = words.get(start + 1).map(|word| word.value.as_str());
        let numeric = next.is_some_and(|value| {
            value.bytes().all(|b| b.is_ascii_digit()) && !value.is_empty()
                || syntax == Syntax::Meson
                    && value.strip_prefix('-').is_some_and(|digits| {
                        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
                    })
        });
        if numeric {
            *index += 2;
            count(next?, syntax)?
        } else if syntax == Syntax::Make
            || syntax == Syntax::Cmake && next.is_none_or(|value| value.starts_with('-'))
        {
            *index += 1;
            Jobs::Automatic
        } else {
            return None;
        }
    } else {
        let value = if let Some(long) = syntax.long()
            && let Some(value) = word
                .strip_prefix(long)
                .and_then(|tail| tail.strip_prefix('='))
        {
            value
        } else {
            word.strip_prefix("-j")?
        };
        *index += 1;
        count(value, syntax)?
    };
    ranges.push(words[start].start..words[*index - 1].end);
    Some(jobs)
}

fn make_jobs(
    words: &[Word],
    mut index: usize,
    ranges: &mut Vec<Range<usize>>,
) -> Option<Option<Jobs>> {
    // Make still interprets command-line variable assignments after `--`.
    // Replacing its scheduler environment or recursive make command is not a
    // literal top-level -j request and may invalidate a live jobserver.
    if words[index..].iter().any(|word| {
        make_assignment_key(&word.value)
            .is_some_and(|key| scheduling_variable(key) || key.contains('$'))
    }) {
        return None;
    }
    let mut jobs = None;
    while let Some(word) = words.get(index).map(|word| word.value.as_str()) {
        if word == "--" {
            break;
        }
        if Syntax::Make.is_jobs(word) {
            jobs = Some(take_jobs(words, &mut index, Syntax::Make, ranges)?);
        } else if takes_value(
            word,
            &["-C", "-f", "-I", "-o", "-W"],
            &[
                "--directory",
                "--file",
                "--makefile",
                "--include-dir",
                "--old-file",
                "--assume-old",
                "--what-if",
                "--new-file",
                "--assume-new",
            ],
        ) {
            skip_value(words, &mut index)?;
        } else if attached_value(
            word,
            &["-C", "-f", "-I", "-o", "-W"],
            &[
                "--directory",
                "--file",
                "--makefile",
                "--include-dir",
                "--old-file",
                "--assume-old",
                "--what-if",
                "--new-file",
                "--assume-new",
            ],
        ) || make_switch(word)
            || !word.starts_with('-')
        {
            index += 1;
        } else if matches!(word, "-l" | "--load-average" | "--max-load") {
            index += 1;
            if words.get(index).is_some_and(|word| number(&word.value)) {
                index += 1;
            }
        } else if word.strip_prefix("-l").is_some_and(number)
            || ["--load-average=", "--max-load="]
                .iter()
                .any(|prefix| word.strip_prefix(prefix).is_some_and(number))
        {
            index += 1;
        } else {
            return None;
        }
    }
    Some(jobs)
}

fn make_switch(word: &str) -> bool {
    matches!(
        word,
        "--always-make"
            | "--environment-overrides"
            | "--ignore-errors"
            | "--keep-going"
            | "--check-symlink-times"
            | "--just-print"
            | "--dry-run"
            | "--recon"
            | "--print-data-base"
            | "--question"
            | "--no-builtin-rules"
            | "--no-builtin-variables"
            | "--silent"
            | "--quiet"
            | "--no-silent"
            | "--no-keep-going"
            | "--stop"
            | "--touch"
            | "--trace"
            | "--print-directory"
            | "--no-print-directory"
            | "--warn-undefined-variables"
            | "--output-sync"
            | "--debug"
    ) || ["--output-sync=", "--debug=", "--shuffle="]
        .iter()
        .any(|prefix| word.starts_with(prefix))
        || word == "-O"
        || word
            .strip_prefix("-O")
            .is_some_and(|mode| matches!(mode, "none" | "line" | "target" | "recurse"))
        || word.strip_prefix('-').is_some_and(|flags| {
            !flags.is_empty() && flags.chars().all(|flag| "bmBdeikLnpqrRsStw".contains(flag))
        })
}

fn ninja_jobs(
    words: &[Word],
    mut index: usize,
    ranges: &mut Vec<Range<usize>>,
) -> Option<Option<Jobs>> {
    let mut jobs = None;
    while let Some(word) = words.get(index).map(|word| word.value.as_str()) {
        if word == "--" {
            break;
        }
        if Syntax::Ninja.is_jobs(word) {
            jobs = Some(take_jobs(words, &mut index, Syntax::Ninja, ranges)?);
        } else if takes_value(word, &["-C", "-f", "-k", "-l", "-d", "-w"], &[]) {
            skip_value(words, &mut index)?;
        } else if attached_value(word, &["-C", "-f", "-k", "-l", "-d", "-w"], &[])
            || matches!(word, "-v" | "--verbose" | "--quiet")
            || !word.starts_with('-')
        {
            index += 1;
        } else {
            // In particular, -t terminates Ninja's own option parser; the
            // following -j could belong to a completely different tool.
            return None;
        }
    }
    Some(jobs)
}

fn cmake_jobs(
    words: &[Word],
    mut index: usize,
    ranges: &mut Vec<Range<usize>>,
) -> Option<Option<Jobs>> {
    let mut jobs = None;
    let mut targets = false;
    while let Some(word) = words.get(index).map(|word| word.value.as_str()) {
        if word == "--" {
            return Some(cmake_backend_jobs(words, index + 1, ranges)?.or(jobs));
        }
        if Syntax::Cmake.is_jobs(word) {
            jobs = Some(take_jobs(words, &mut index, Syntax::Cmake, ranges)?);
            targets = false;
        } else if matches!(word, "--target" | "-t") {
            targets = true;
            index += 1;
            let target = words.get(index)?;
            if target.value.is_empty() || target.value.starts_with('-') {
                return None;
            }
        } else if takes_value(word, &[], &["--config", "--resolve-package-references"]) {
            skip_value(words, &mut index)?;
            targets = false;
        } else if attached_value(word, &[], &["--config", "--resolve-package-references"])
            || matches!(word, "--clean-first" | "-v" | "--verbose")
        {
            targets = false;
            index += 1;
        } else if targets && !word.starts_with('-') {
            // CMake forwards target operands to Make as well as Ninja. A
            // "target" such as MAKEFLAGS:=-j64 is then a Make assignment,
            // replacing the jobserver which --parallel just established.
            if make_assignment_key(word)
                .is_some_and(|key| scheduling_variable(key) || key.contains('$'))
            {
                return None;
            }
            index += 1;
        } else {
            return None;
        }
    }
    Some(jobs)
}

fn cmake_backend_jobs(
    words: &[Word],
    mut index: usize,
    ranges: &mut Vec<Range<usize>>,
) -> Option<Option<Jobs>> {
    let mut jobs = None;
    while let Some(word) = words.get(index).map(|word| word.value.as_str()) {
        if Syntax::CmakeBackend.is_jobs(word) {
            // Positive -j N is shared by Ninja and GNU Make. Bare -j and -j0
            // differ between them; a pure command parser cannot infer CMake's
            // generator. Other backend schedulers (/m, response files, etc.)
            // must stay local until their own grammar can be bounded.
            jobs = Some(take_jobs(words, &mut index, Syntax::CmakeBackend, ranges)?);
        } else if word == "-l" {
            let value = words.get(index + 1)?;
            if !number(&value.value) {
                return None;
            }
            index += 2;
        } else if word.strip_prefix("-l").is_some_and(number)
            || matches!(word, "-v" | "--verbose" | "-s" | "--silent")
        {
            index += 1;
        } else {
            return None;
        }
    }
    Some(jobs)
}

fn meson_jobs(
    words: &[Word],
    mut index: usize,
    ranges: &mut Vec<Range<usize>>,
) -> Option<Option<Jobs>> {
    let mut jobs = None;
    while let Some(word) = words.get(index).map(|word| word.value.as_str()) {
        if word == "--" {
            break;
        }
        if Syntax::Meson.is_jobs(word) {
            jobs = Some(take_jobs(words, &mut index, Syntax::Meson, ranges)?);
        } else if word == "--ninja-args=--" {
            // This is the one backend argument whose scheduling effect is
            // known: it terminates options before Meson's resolved targets.
            // Re-emit exactly one marker together with the bounded -j flag.
            // Any other --ninja-args value, even after this marker, is refused.
            ranges.push(words[index].start..words[index].end);
            index += 1;
        } else if takes_value(word, &["-C", "-l"], &["--load-average"]) {
            skip_value(words, &mut index)?;
        } else if attached_value(word, &["-C", "-l"], &["--load-average"])
            || matches!(word, "--clean" | "-v" | "--verbose")
            || !word.starts_with('-')
        {
            index += 1;
        } else {
            // Opaque --ninja-args, --vs-args and --xcode-args are nested
            // grammars which could replace the frontend's parallel limit.
            return None;
        }
    }
    Some(jobs)
}

fn takes_value(word: &str, short: &[&str], long: &[&str]) -> bool {
    short.contains(&word) || long.contains(&word)
}

fn attached_value(word: &str, short: &[&str], long: &[&str]) -> bool {
    short.iter().any(|flag| {
        word.strip_prefix(flag)
            .is_some_and(|value| !value.is_empty())
    }) || long.iter().any(|flag| {
        word.strip_prefix(flag)
            .and_then(|tail| tail.strip_prefix('='))
            .is_some_and(|value| !value.is_empty())
    })
}

fn skip_value(words: &[Word], index: &mut usize) -> Option<()> {
    words.get(*index + 1)?;
    *index += 2;
    Some(())
}

fn number(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && value.parse::<f64>().is_ok_and(|number| number.is_finite())
}

fn scheduling_variable(key: &str) -> bool {
    matches!(
        key,
        "MAKEFLAGS" | "MFLAGS" | "GNUMAKEFLAGS" | "MAKELEVEL" | "MAKEOVERRIDES" | "MAKE"
    )
}

/// GNU Make's command-line assignments have their own grammar, independent of
/// the shell's leading ENV=value assignments. All of these operators can name a
/// scheduling variable. A name containing a Make expansion is opaque: it could
/// resolve to MAKEFLAGS even when the literal token does not mention it.
fn make_assignment_key(word: &str) -> Option<&str> {
    let (prefix, _) = word.split_once('=')?;
    let prefix = prefix.trim();
    let name = [":::", "::", ":", "+", "?", "!"]
        .iter()
        .find_map(|operator| prefix.strip_suffix(operator))
        .unwrap_or(prefix)
        .trim();
    (!name.is_empty()).then_some(name)
}

fn assignment(value: &str) -> Option<(&str, &str)> {
    let (key, value) = value.split_once('=')?;
    let mut bytes = key.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((key, value))
}

fn assigned_jobs(key: &str, value: &str, jobs: &mut Option<Jobs>) -> Option<()> {
    if scheduling_variable(key) {
        return None;
    }
    if key == "CMAKE_BUILD_PARALLEL_LEVEL" {
        *jobs = Some(if value.is_empty() {
            Jobs::Automatic
        } else {
            count(value, Syntax::Cmake)?
        });
    }
    Some(())
}

fn native_program(
    kind: CompilationKind,
    command: &str,
    words: &[Word],
) -> Option<(usize, Option<Jobs>)> {
    let mut index = 0;
    let mut jobs = None;
    while let Some(word) = words.get(index)
        && let Some((key, value)) = assignment(&word.value)
    {
        // A quoted whole word "KEY=value" is an executable name to the
        // shell, whereas KEY="value" is an assignment. Preserve that role.
        if !command[word.start..word.end].starts_with(&format!("{key}=")) {
            return None;
        }
        assigned_jobs(key, value, &mut jobs)?;
        index += 1;
    }
    loop {
        let program = words.get(index)?.value.rsplit('/').next()?;
        let program = program.strip_suffix(".exe").unwrap_or(program);
        if matches!(
            (kind, program),
            (CompilationKind::Make, "make" | "gmake")
                | (CompilationKind::Ninja, "ninja" | "ninja-build")
                | (CompilationKind::CmakeBuild, "cmake")
                | (CompilationKind::Meson, "meson")
        ) {
            return Some((index, jobs));
        }
        index += 1;
        match program {
            "env" => {
                while let Some(word) = words.get(index).map(|word| word.value.as_str()) {
                    match word {
                        "--" => {
                            index += 1;
                            break;
                        }
                        "-i" | "--ignore-environment" => jobs = None,
                        "-u" | "--unset" => {
                            index += 1;
                            if words.get(index)?.value == "CMAKE_BUILD_PARALLEL_LEVEL" {
                                jobs = None;
                            }
                        }
                        _ if word.starts_with("--unset=") || word.starts_with("-u") => {
                            let name = word
                                .strip_prefix("--unset=")
                                .or_else(|| word.strip_prefix("-u"))?;
                            if name.is_empty() {
                                return None;
                            }
                            if name == "CMAKE_BUILD_PARALLEL_LEVEL" {
                                jobs = None;
                            }
                        }
                        _ if word.starts_with('-') => return None,
                        _ => break,
                    }
                    index += 1;
                }
                while let Some(word) = words.get(index)
                    && let Some((key, value)) = assignment(&word.value)
                {
                    assigned_jobs(key, value, &mut jobs)?;
                    index += 1;
                }
            }
            "command" => {
                if words.get(index).is_some_and(|word| word.value == "-p") {
                    index += 1;
                }
                if words.get(index).is_some_and(|word| word.value == "--") {
                    index += 1;
                }
            }
            "nice" => {
                if let Some(word) = words.get(index).map(|word| word.value.as_str()) {
                    if matches!(word, "-n" | "--adjustment") {
                        skip_value(words, &mut index)?;
                    } else if word.starts_with("--adjustment=")
                        || word.strip_prefix('-').is_some_and(|value| {
                            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                        })
                    {
                        index += 1;
                    }
                }
                if words.get(index).is_some_and(|word| word.value == "--") {
                    index += 1;
                }
            }
            "time" => {
                while let Some(word) = words.get(index).map(|word| word.value.as_str()) {
                    if word == "--" {
                        index += 1;
                        break;
                    } else if takes_value(word, &["-f", "-o"], &["--format", "--output"]) {
                        skip_value(words, &mut index)?;
                    } else if attached_value(word, &["-f", "-o"], &["--format", "--output"])
                        || matches!(
                            word,
                            "-p" | "--portability"
                                | "-v"
                                | "--verbose"
                                | "-q"
                                | "--quiet"
                                | "-a"
                                | "--append"
                        )
                    {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "timeout" => {
                while let Some(word) = words.get(index).map(|word| word.value.as_str()) {
                    if word == "--" {
                        index += 1;
                        break;
                    } else if takes_value(word, &["-s", "-k"], &["--signal", "--kill-after"]) {
                        skip_value(words, &mut index)?;
                    } else if attached_value(word, &["-s", "-k"], &["--signal", "--kill-after"])
                        || matches!(
                            word,
                            "--preserve-status" | "--foreground" | "-v" | "--verbose"
                        )
                    {
                        index += 1;
                    } else {
                        break;
                    }
                }
                let duration = words.get(index)?.value.as_str();
                let duration = duration
                    .strip_suffix(['s', 'm', 'h', 'd'])
                    .unwrap_or(duration);
                if !number(duration) {
                    return None;
                }
                index += 1;
            }
            _ => return None,
        }
    }
}

#[derive(Debug)]
struct Word {
    value: String,
    start: usize,
    end: usize,
}

/// Decode literal POSIX shell words while keeping their exact original spans.
/// Backslashes inside double quotes only escape the POSIX special characters;
/// treating every backslash as an escape would silently change option values.
fn literal_words(command: &str) -> Option<Vec<Word>> {
    if command.len() > 65_536 || command.chars().any(|ch| ch.is_control() && ch != '\t') {
        return None;
    }
    let mut chars = command.char_indices().peekable();
    let mut words = Vec::new();
    while let Some(&(start, ch)) = chars.peek() {
        if matches!(ch, ' ' | '\t') {
            chars.next();
            continue;
        }
        if words.len() >= 4096 {
            return None;
        }
        let mut quote = None;
        let mut value = String::new();
        let mut end = start;
        while let Some(&(offset, ch)) = chars.peek() {
            if quote.is_none() && matches!(ch, ' ' | '\t') {
                break;
            }
            chars.next();
            end = offset + ch.len_utf8();
            match (quote, ch) {
                (Some('\''), '\'') | (Some('"'), '"') => quote = None,
                (Some('\''), _) => value.push(ch),
                (None, '\'' | '"') => quote = Some(ch),
                (None | Some('"'), '\\') => {
                    let (offset, escaped) = chars.next()?;
                    end = offset + escaped.len_utf8();
                    if quote == Some('"') && !matches!(escaped, '$' | '`' | '"' | '\\') {
                        value.push('\\');
                    }
                    value.push(escaped);
                }
                (None | Some('"'), '$' | '`') => return None,
                (
                    None,
                    '|' | '&' | ';' | '<' | '>' | '(' | ')' | '*' | '?' | '[' | '{' | '}' | '~'
                    | '#',
                ) => {
                    return None;
                }
                _ => value.push(ch),
            }
        }
        if quote.is_some() {
            return None;
        }
        words.push(Word { value, start, end });
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounded(kind: CompilationKind, command: &str, slots: u32) -> (Option<u32>, Vec<String>) {
        let plan = native_build_jobs(kind, command).expect(command);
        let bounded = plan.bounded_command(slots).expect("nonzero reservation");
        let words = literal_words(&bounded)
            .expect("rewritten command stays literal")
            .into_iter()
            .map(|word| word.value)
            .collect();
        (plan.requested_jobs(), words)
    }

    #[test]
    fn defaults_and_unlimited_parallelism_are_bounded() {
        for (kind, command, requested, expected) in [
            (CompilationKind::Make, "make all", Some(1), "make -j 1 all"),
            (CompilationKind::Make, "make -j all", None, "make -j 3  all"),
            (
                CompilationKind::Make,
                "make --jobs all",
                None,
                "make -j 3  all",
            ),
            (CompilationKind::Ninja, "ninja all", None, "ninja -j 3 all"),
            (CompilationKind::Ninja, "ninja -j0", None, "ninja -j 3 "),
            (
                CompilationKind::CmakeBuild,
                "cmake --build out",
                None,
                "cmake --build out --parallel 3",
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build out --parallel",
                None,
                "cmake --build out --parallel 3 ",
            ),
            (
                CompilationKind::Meson,
                "meson compile -C out",
                None,
                "meson compile -j 3 --ninja-args=-- -C out",
            ),
            (
                CompilationKind::Meson,
                "meson compile -j 0",
                None,
                "meson compile -j 3 --ninja-args=-- ",
            ),
            (
                CompilationKind::Meson,
                "meson compile --jobs=-1",
                None,
                "meson compile -j 3 --ninja-args=-- ",
            ),
        ] {
            let plan = native_build_jobs(kind, command).expect(command);
            assert_eq!(plan.requested_jobs(), requested, "{command}");
            assert_eq!(
                plan.bounded_command(3).as_deref(),
                Some(expected),
                "{command}"
            );
            assert!(plan.bounded_command(0).is_none());
        }
    }

    #[test]
    fn finite_counts_preserve_smaller_requests_and_cap_larger_ones() {
        for (kind, command) in [
            (CompilationKind::Make, "make -j16"),
            (CompilationKind::Make, "make --jobs=16"),
            (CompilationKind::Make, "make --jobs 16"),
            (CompilationKind::Ninja, "ninja -j 16"),
            (CompilationKind::CmakeBuild, "cmake --build out -j16"),
            (
                CompilationKind::CmakeBuild,
                "cmake --build out --parallel=16",
            ),
            (CompilationKind::Meson, "meson compile --jobs 16"),
        ] {
            let (request, words) = bounded(kind, command, 2);
            assert_eq!(request, Some(16), "{command}");
            assert!(words.iter().any(|word| word == "2"), "{command}");
            assert!(!words.iter().any(|word| word.contains("16")), "{command}");
            let (request, words) = bounded(kind, &command.replace("16", "1"), 2);
            assert_eq!(request, Some(1));
            assert!(words.iter().any(|word| word == "1"));
        }
    }

    #[test]
    fn later_controls_and_cmake_backend_controls_determine_actual_parallelism() {
        for (kind, command, requested) in [
            (CompilationKind::Make, "make -j64 --jobs=2", Some(2)),
            (CompilationKind::Make, "make -j2 -j", None),
            (CompilationKind::Ninja, "ninja -j0 -j2", Some(2)),
            (
                CompilationKind::Meson,
                "meson compile -j20 --jobs=2",
                Some(2),
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build out -j2 -- -j16",
                Some(16),
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build out --parallel 16 -- -j2",
                Some(2),
            ),
            (
                CompilationKind::CmakeBuild,
                "cmake --build out --parallel -- -j2 -l4",
                Some(2),
            ),
        ] {
            let (request, words) = bounded(kind, command, 3);
            assert_eq!(request, requested, "{command}");
            assert_eq!(
                words
                    .iter()
                    .filter(|word| word.starts_with("-j") || word.starts_with("--parallel"))
                    .count(),
                1,
                "{command}"
            );
            let plan = native_build_jobs(kind, command).unwrap();
            let rewritten = plan.bounded_command(3).unwrap();
            let reparsed = native_build_jobs(kind, &rewritten).unwrap();
            assert_eq!(
                reparsed.requested_jobs(),
                Some(requested.unwrap_or(3).min(3)),
                "{command}"
            );
        }
    }

    #[test]
    fn wrappers_and_literal_shell_bytes_are_preserved() {
        let command = "  LABEL='two words; $literal' env -u UNUSED nice -n 5 timeout -k 2s 30s /usr/bin/time -f '%E -j99' /usr/bin/ninja -C 'build tree' -j64 'a[*].o'  ";
        let plan = native_build_jobs(CompilationKind::Ninja, command).unwrap();
        assert_eq!(plan.requested_jobs(), Some(64));
        let expected = command
            .replace("/usr/bin/ninja", "/usr/bin/ninja -j 2")
            .replace("-j64", "");
        assert_eq!(plan.bounded_command(2).unwrap(), expected);
        let command = r#"LABEL='-j99' command -- ninja -f "name\q.ninja" -j 8 -- '-j40'"#;
        let (request, words) = bounded(CompilationKind::Ninja, command, 2);
        assert_eq!(request, Some(8));
        assert!(words.contains(&r"name\q.ninja".to_owned()));
        assert_eq!(words.last().unwrap(), "-j40");
    }

    #[test]
    fn option_values_and_target_terminators_are_not_job_options() {
        let (_, words) = bounded(
            CompilationKind::Make,
            "make -f '-j99' -j4 VALUE=-j55 -- -j22",
            2,
        );
        assert_eq!(
            words,
            ["make", "-j", "2", "-f", "-j99", "VALUE=-j55", "--", "-j22"]
        );
        let (_, words) = bounded(
            CompilationKind::CmakeBuild,
            "cmake --build 'a b' --config '-j99' --target first second --parallel 4 -- -j8",
            2,
        );
        assert_eq!(
            words,
            [
                "cmake",
                "--build",
                "a b",
                "--parallel",
                "2",
                "--config",
                "-j99",
                "--target",
                "first",
                "second",
                "--"
            ]
        );
    }

    #[test]
    fn meson_resolved_targets_cannot_become_ninja_scheduler_options() {
        for command in [
            "meson compile -C out -j64 flagged",
            "meson compile -C out -j64 -- -j32",
            "meson compile -C out -j64 ./-j32:custom",
            "meson compile --ninja-args=-- -C out -j64 flagged",
            "meson compile --ninja-args=-- -C out -j64 --ninja-args=-- flagged",
        ] {
            let plan = native_build_jobs(CompilationKind::Meson, command).unwrap();
            let rewritten = plan.bounded_command(2).unwrap();
            let (_, words) = bounded(CompilationKind::Meson, command, 2);
            assert_eq!(
                words
                    .iter()
                    .filter(|word| *word == "--ninja-args=--")
                    .count(),
                1,
                "{command}"
            );
            assert_eq!(
                native_build_jobs(CompilationKind::Meson, &rewritten)
                    .unwrap()
                    .requested_jobs(),
                Some(2),
                "{command}",
            );
        }
        for command in [
            "meson compile --ninja-args=-- --ninja-args=-j64",
            "meson compile --ninja-args=-j64 --ninja-args=--",
            "meson compile --ninja-args=-- --ninja-args='-- -j64'",
            "meson compile --ninja-args=-- --ninja-args='[]'",
            "meson compile --ninja-args --",
        ] {
            assert!(
                native_build_jobs(CompilationKind::Meson, command).is_none(),
                "{command}"
            );
        }
    }

    #[test]
    fn inline_cmake_defaults_follow_environment_wrapper_precedence() {
        for (command, expected) in [
            ("CMAKE_BUILD_PARALLEL_LEVEL=2 cmake --build out", Some(2)),
            (
                "CMAKE_BUILD_PARALLEL_LEVEL=2 cmake --build out --parallel 4",
                Some(4),
            ),
            (
                "env CMAKE_BUILD_PARALLEL_LEVEL=2 cmake --build out --parallel",
                None,
            ),
            (
                "CMAKE_BUILD_PARALLEL_LEVEL=2 env -i cmake --build out",
                None,
            ),
            (
                "CMAKE_BUILD_PARALLEL_LEVEL=2 env -u CMAKE_BUILD_PARALLEL_LEVEL cmake --build out",
                None,
            ),
            (
                "CMAKE_BUILD_PARALLEL_LEVEL=2 env --unset=CMAKE_BUILD_PARALLEL_LEVEL cmake --build out",
                None,
            ),
            ("env CMAKE_BUILD_PARALLEL_LEVEL= cmake --build out", None),
        ] {
            assert_eq!(
                native_build_jobs(CompilationKind::CmakeBuild, command)
                    .unwrap()
                    .requested_jobs(),
                expected,
                "{command}"
            );
        }
    }

    #[test]
    fn ambiguous_or_opaque_scheduling_stays_local() {
        for (kind, command) in [
            (CompilationKind::Make, "make -j0"),
            (CompilationKind::Make, "make -j=2"),
            (CompilationKind::Make, "make -kj8"),
            (CompilationKind::Make, "make --jobserver-auth=3,4"),
            (CompilationKind::Make, "make MAKEFLAGS=-j8"),
            (CompilationKind::Make, "make -- MAKEFLAGS=-j8"),
            (
                CompilationKind::Make,
                "MAKEFLAGS='-j8 --jobserver-auth=3,4' make",
            ),
            (CompilationKind::Make, "make --eval 'MAKEFLAGS += -j99'"),
            (CompilationKind::Ninja, "ninja -j"),
            (CompilationKind::Ninja, "ninja --jobs=2"),
            (CompilationKind::Ninja, "ninja -t commands -j8"),
            (CompilationKind::Ninja, "ninja -j $JOBS"),
            (CompilationKind::Ninja, "ninja -j$(nproc)"),
            (CompilationKind::Ninja, "ninja -j2 && ninja -j8"),
            (CompilationKind::Ninja, "ninja -j2 > output"),
            (CompilationKind::Ninja, "ninja *.o"),
            (CompilationKind::Ninja, "'VAR=value' ninja"),
            (CompilationKind::Ninja, "env -S 'ninja -j8'"),
            (CompilationKind::Ninja, "sh -c 'ninja -j8'"),
            (
                CompilationKind::CmakeBuild,
                "cmake --build out --parallel=0",
            ),
            (CompilationKind::CmakeBuild, "cmake --build out -- -j0"),
            (CompilationKind::CmakeBuild, "cmake --build out -- --jobs=4"),
            (CompilationKind::CmakeBuild, "cmake --build out -- /m:99"),
            (CompilationKind::CmakeBuild, "cmake --build out -- @flags"),
            (CompilationKind::Meson, "meson compile --ninja-args=-j99"),
            (CompilationKind::Meson, "meson compile --vs-args /m:99"),
            (
                CompilationKind::Meson,
                "meson compile --xcode-args '-jobs 99'",
            ),
            (CompilationKind::Meson, "meson setup out"),
        ] {
            assert!(native_build_jobs(kind, command).is_none(), "{command}");
        }
    }

    #[test]
    fn make_assignment_operators_cannot_replace_the_jobserver() {
        for key in [
            "MAKEFLAGS",
            "MFLAGS",
            "GNUMAKEFLAGS",
            "MAKELEVEL",
            "MAKEOVERRIDES",
            "MAKE",
        ] {
            for operator in ["=", ":=", "::=", ":::=", "+=", "?=", "!="] {
                for assignment in [
                    format!("{key}{operator}-j64"),
                    format!("'{key} {operator} -j64'"),
                ] {
                    for separator in ["", "-- "] {
                        let command = format!("make -j2 {separator}{assignment}");
                        assert!(
                            native_build_jobs(CompilationKind::Make, &command).is_none(),
                            "{command}"
                        );
                    }
                }
            }
        }
        for command in [
            "make -j2 '$(SCHEDULER)=-j64'",
            "make -j2 'MA$(EMPTY)KEFLAGS:=-j64'",
        ] {
            assert!(
                native_build_jobs(CompilationKind::Make, command).is_none(),
                "{command}"
            );
        }
        let (_, words) = bounded(CompilationKind::Make, "make -j8 'CFLAGS += -DVALUE=4'", 2);
        assert_eq!(words, ["make", "-j", "2", "CFLAGS += -DVALUE=4"]);
    }

    #[test]
    fn cmake_targets_cannot_replace_backend_job_controls() {
        for key in [
            "MAKEFLAGS",
            "MFLAGS",
            "GNUMAKEFLAGS",
            "MAKELEVEL",
            "MAKEOVERRIDES",
            "MAKE",
        ] {
            for operator in ["=", ":=", "::=", ":::=", "+=", "?=", "!="] {
                for preceding in ["", "all "] {
                    let command = format!(
                        "cmake --build out --parallel 2 --target {preceding}'{key} {operator} -j64'"
                    );
                    assert!(
                        native_build_jobs(CompilationKind::CmakeBuild, &command).is_none(),
                        "{command}"
                    );
                }
            }
        }
        for command in [
            "cmake --build out --parallel 2 --target MAKEFLAGS=-j64 show",
            "cmake --build out --parallel 2 --target '$(SCHEDULER)=-j64'",
            "cmake --build out --parallel 2 --target=-j64",
            "cmake --build out --parallel 2 --target -j64",
            "cmake --build out --parallel 2 -t '-j64'",
        ] {
            assert!(
                native_build_jobs(CompilationKind::CmakeBuild, command).is_none(),
                "{command}"
            );
        }
        let (_, words) = bounded(
            CompilationKind::CmakeBuild,
            "cmake --build out --parallel 8 --target ./-j64",
            2,
        );
        assert_eq!(
            words,
            [
                "cmake",
                "--build",
                "out",
                "--parallel",
                "2",
                "--target",
                "./-j64"
            ]
        );
    }

    #[test]
    fn malformed_or_mismatched_commands_never_produce_a_plan() {
        for command in [
            "",
            " ",
            "ninja 'unterminated",
            "ninja trailing\\",
            "ninja\n-j4",
            "ninja -j4294967296",
            "ninja -j-1",
            "ninja -f",
        ] {
            assert!(
                native_build_jobs(CompilationKind::Ninja, command).is_none(),
                "{command}"
            );
        }
        assert!(native_build_jobs(CompilationKind::Make, "ninja -j4").is_none());
        assert!(native_build_jobs(CompilationKind::CargoBuild, "cargo build -j4").is_none());
    }
}
