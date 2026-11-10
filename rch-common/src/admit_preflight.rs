//! `rch admit` preflight core (bd-session-history-remediation-ocv9i.6.1).
//!
//! `rch admit -- <command>` is a fast, read-only preflight an agent runs before
//! expensive work: it classifies the command, determines its family and the
//! capabilities a worker must have to run it, and — given the daemon's
//! candidate/rejection data — returns a decisive Offload / Local / Queue / Defer
//! answer. This module is the **pure** heart of that: classification and
//! capability derivation ([`preflight`]) plus the decision rule that folds in
//! aggregated candidate rejections ([`refine_recommendation`]).
//!
//! It reuses the existing classifier ([`crate::patterns`]), the capability
//! requirement contract ([`crate::capability_probe::CapabilityRequirement`]),
//! and the admission-rejection vocabulary ([`crate::admission_rejection`]) rather
//! than inventing a parallel path. The clap `rch admit` subcommand and the
//! optional daemon candidate query are the CLI/daemon surface over this contract.

use serde::{Deserialize, Serialize};

use crate::admission_rejection::{AdmissionRejectionSummary, RejectionClass};
use crate::capability_probe::CapabilityRequirement;
use crate::patterns::{
    CompilationKind, cargo_xwin_compilation_kind, classify_command, classify_command_detailed,
    normalize_command, split_shell_commands, split_wrapper_word,
};

/// The decisive recommendation `rch admit` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmitRecommendation {
    /// Offload to a remote worker.
    Offload,
    /// Run locally (not a compilation, or nothing to gain from offload).
    Local,
    /// Offload-eligible but the fleet is transiently busy/unhealthy — queue.
    Queue,
    /// No worker can run this command (structural capability gap) — defer until
    /// the fleet gains the capability rather than waiting on a slot.
    Defer,
}

impl AdmitRecommendation {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AdmitRecommendation::Offload => "offload",
            AdmitRecommendation::Local => "local",
            AdmitRecommendation::Queue => "queue",
            AdmitRecommendation::Defer => "defer",
        }
    }
}

/// The capabilities a command needs from a worker, as a serializable summary.
/// Mirrors (and converts to) [`CapabilityRequirement`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredCapabilities {
    pub needs_cargo: bool,
    pub needs_bun: bool,
    /// Whether the command requires nix (binary + populated `/nix/store`).
    pub needs_nix: bool,
    /// Whether the command requires the Go toolchain.
    pub needs_go: bool,
    /// Whether the command requires Node.js (e.g. `tsc` / `npx tsc`).
    pub needs_node: bool,
    /// Whether the command requires `zig` + `cargo-zigbuild` (a zig cross-build).
    /// This is on TOP of `needs_cargo` and the requested `needs_targets`.
    pub needs_zig: bool,
    /// rustup targets the command explicitly requests (`--target <triple>`).
    pub needs_targets: Vec<String>,
    /// Explicit toolchain overrides (`cargo +nightly-…`).
    pub needs_toolchains: Vec<String>,
    /// Host OS the worker must run, when a native tool or requested `--target`
    /// triple implies one (e.g. `xcodebuild` → `darwin`). `None` for the ordinary
    /// native build, which stays schedulable on any worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs_os: Option<String>,
    /// Operator-declared named tools the caller required (`--require-tool`).
    ///
    /// Job mode only, and never derived from the command: RCH cannot know that
    /// `./run_shards.sh` shells out to clang, so the requirement is something
    /// the caller states, not something a classifier guesses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs_tools: Vec<String>,
}

impl RequiredCapabilities {
    /// Convert to the admission-gate [`CapabilityRequirement`] for a given wire
    /// protocol.
    #[must_use]
    pub fn to_requirement(&self, min_protocol: u32) -> CapabilityRequirement {
        CapabilityRequirement {
            needs_targets: self.needs_targets.clone(),
            min_protocol,
            needs_cargo: self.needs_cargo,
            needs_bun: self.needs_bun,
            needs_nix: self.needs_nix,
            needs_go: self.needs_go,
            needs_node: self.needs_node,
            needs_zig: self.needs_zig,
            needs_toolchains: self.needs_toolchains.clone(),
            needs_os: self.needs_os.clone(),
            needs_tools: self.needs_tools.clone(),
            ..CapabilityRequirement::default()
        }
    }
}

/// The result of a read-only admit preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmitPreflight {
    /// The command as given.
    pub command: String,
    /// Sub-commands when the input is a compound shell form (`a && b`); a single
    /// command yields one element.
    pub compound: Vec<String>,
    /// Whether the (whole) command is a compilation worth offloading.
    pub is_compilation: bool,
    /// The compilation family, when classified (e.g. `cargo_build`, `bun_test`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Capabilities a worker must have to run it.
    pub required: RequiredCapabilities,
    /// Whether proof/strict-remote policy is in force (caller-supplied).
    pub proof_policy: bool,
    /// Whether this was preflighted as a job-mode admission (`--job`), where
    /// the compilation classifier is bypassed rather than consulted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub job_mode: bool,
    /// The decision before daemon candidate data is folded in.
    pub base_recommendation: AdmitRecommendation,
    /// Operator-facing explanation.
    pub detail: String,
}

/// Snake_case family token for a compilation kind.
fn family_token(kind: CompilationKind) -> &'static str {
    match kind {
        CompilationKind::CargoBuild => "cargo_build",
        CompilationKind::CargoTest => "cargo_test",
        CompilationKind::CargoCheck => "cargo_check",
        CompilationKind::CargoClippy => "cargo_clippy",
        CompilationKind::CargoDoc => "cargo_doc",
        CompilationKind::CargoNextest => "cargo_nextest",
        CompilationKind::CargoBench => "cargo_bench",
        CompilationKind::CargoZigbuild => "cargo_zigbuild",
        CompilationKind::Rustc => "rustc",
        CompilationKind::Gcc => "gcc",
        CompilationKind::Gpp => "gpp",
        CompilationKind::Clang => "clang",
        CompilationKind::Clangpp => "clangpp",
        CompilationKind::Make => "make",
        CompilationKind::CmakeBuild => "cmake",
        CompilationKind::Ninja => "ninja",
        CompilationKind::Meson => "meson",
        CompilationKind::BunTest => "bun_test",
        CompilationKind::BunTypecheck => "bun_typecheck",
        CompilationKind::NixBuild => "nix_build",
        CompilationKind::GoBuild => "go_build",
        CompilationKind::GoTest => "go_test",
        CompilationKind::GoVet => "go_vet",
        CompilationKind::Tsc => "tsc",
        CompilationKind::Job => "job",
    }
}

/// Whether a kind is part of the Rust/cargo family (needs cargo).
fn is_rust_kind(kind: CompilationKind) -> bool {
    matches!(
        kind,
        CompilationKind::CargoBuild
            | CompilationKind::CargoTest
            | CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::CargoDoc
            | CompilationKind::CargoNextest
            | CompilationKind::CargoBench
            // A zig cross-build runs through cargo, so it needs the cargo toolchain
            // too (plus zig — see `needs_zig` in derive_capabilities).
            | CompilationKind::CargoZigbuild
            | CompilationKind::Rustc
    )
}

struct DerivedCapabilities {
    required: RequiredCapabilities,
    // Native compiler targets can constrain the host without requiring a
    // rustup standard library. Keep this evidence out of needs_targets.
    host_targets: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum AdmissionArgument {
    Literal(String),
    // The literal prefix before a quoted parameter expansion. This still
    // occupies exactly one argv slot, but its complete value is unknown.
    Opaque(String),
    // The remaining shell text can add an unknown number of arguments. It
    // cannot establish option arity, but a preceding compiler -- still applies.
    Unbounded,
}

impl AdmissionArgument {
    fn literal(&self) -> Option<&str> {
        match self {
            Self::Literal(value) => Some(value),
            Self::Opaque(_) | Self::Unbounded => None,
        }
    }
}

/// Consume only simple, single-word parameter expansions inside double quotes.
/// `$@`, substitutions and parameter operators need a full shell grammar and
/// cannot establish a bounded argv slot here.
fn quoted_parameter(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<()> {
    let first = chars.next()?;
    if first == '{' {
        let first = chars.next()?;
        if !(first == '_' || first.is_ascii_alphabetic()) {
            return None;
        }
        while chars
            .peek()
            .is_some_and(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        {
            chars.next();
        }
        return (chars.next()? == '}').then_some(());
    }
    if first == '_' || first.is_ascii_alphabetic() {
        while chars
            .peek()
            .is_some_and(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        {
            chars.next();
        }
        return Some(());
    }
    matches!(first, '0'..='9' | '?' | '$' | '!' | '#' | '*' | '-').then_some(())
}

/// Read argv without executing expansions or treating quoted option operands as
/// additional arguments. A quoted variable can hide an operand without hiding
/// other literal options; unquoted expansion can manufacture argv and is opaque.
fn admission_arguments(command: &str) -> Option<Vec<AdmissionArgument>> {
    if command.len() > 65_536 {
        return None;
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut opaque_prefix = None;
    let mut started = false;
    let mut quote = None;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        if matches!(ch, '\0' | '\r' | '\n') {
            return None;
        }
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => word.push(ch),
            (None, '\'' | '"') => {
                started = true;
                quote = Some(ch);
            }
            (None, '$') | (None | Some('"'), '`') => {
                words.push(AdmissionArgument::Unbounded);
                return Some(words);
            }
            (Some('"'), '$') => {
                if quoted_parameter(&mut chars).is_none() {
                    words.push(AdmissionArgument::Unbounded);
                    return Some(words);
                }
                if opaque_prefix.is_none() {
                    opaque_prefix = Some(word.clone());
                }
            }
            (None, '\\') => {
                let escaped = chars.next()?;
                if matches!(escaped, '\0' | '\r' | '\n') {
                    return None;
                }
                started = true;
                word.push(escaped);
            }
            (Some('"'), '\\') => {
                let escaped = chars.next()?;
                if matches!(escaped, '\0' | '\r' | '\n') {
                    return None;
                }
                if !matches!(escaped, '$' | '`' | '"' | '\\') {
                    word.push('\\');
                }
                word.push(escaped);
            }
            (None, ' ' | '\t') => {
                if started {
                    let value = std::mem::take(&mut word);
                    words.push(match opaque_prefix.take() {
                        Some(prefix) => AdmissionArgument::Opaque(prefix),
                        None => AdmissionArgument::Literal(value),
                    });
                    started = false;
                }
            }
            (None, ';' | '&' | '|' | '<' | '>') => break,
            (None, '#') if !started => break,
            (None, '(' | ')' | '*' | '?' | '[' | ']' | '{' | '}' | '~') => {
                words.push(AdmissionArgument::Unbounded);
                return Some(words);
            }
            _ => {
                started = true;
                word.push(ch);
            }
        }
        if words.len() > 4096 {
            return None;
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        words.push(match opaque_prefix {
            Some(prefix) => AdmissionArgument::Opaque(prefix),
            None => AdmissionArgument::Literal(word),
        });
    }
    (!words.is_empty() && words.len() <= 4096).then_some(words)
}

fn target_value_is_literal(value: &str) -> bool {
    // A custom Rust target JSON file is not an installed rustup target, and a
    // filename containing "-apple-" does not establish its target platform.
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with(".json")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn option_takes_value(option: &str, program: &str) -> bool {
    if matches!(program, "clang" | "clang++") {
        matches!(
            option,
            "-o" | "--output"
                | "-x"
                | "-I"
                | "-D"
                | "-U"
                | "-L"
                | "-l"
                | "-B"
                | "-isystem"
                | "-iquote"
                | "-idirafter"
                | "-include"
                | "-include-pch"
                | "-imacros"
                | "-isysroot"
                | "--sysroot"
                | "-arch"
                | "-std"
                | "-MF"
                | "-MJ"
                | "-MT"
                | "-MQ"
                | "-Xclang"
                | "-Xlinker"
                | "-Xassembler"
                | "-Xpreprocessor"
                | "-mllvm"
                | "--gcc-toolchain"
        ) || option.starts_with("-Xarch_")
    } else if program == "rustc" {
        matches!(
            option,
            "-o" | "--out-dir"
                | "--crate-name"
                | "--crate-type"
                | "--edition"
                | "--extern"
                | "--cfg"
                | "--check-cfg"
                | "--sysroot"
                | "--emit"
                | "--print"
                | "--error-format"
                | "--json"
                | "--color"
                | "--cap-lints"
                | "--diagnostic-width"
                | "--remap-path-prefix"
                | "--remap-path-scope"
                | "-C"
                | "--codegen"
                | "-Z"
                | "-L"
                | "-l"
                | "-A"
                | "--allow"
                | "-W"
                | "--warn"
                | "--force-warn"
                | "-D"
                | "--deny"
                | "-F"
                | "--forbid"
        )
    } else {
        matches!(
            option,
            "--color"
                | "--config"
                | "-Z"
                | "-C"
                | "--manifest-path"
                | "--target-dir"
                | "--build-dir"
                | "--message-format"
                | "--profile"
                | "-p"
                | "--package"
                | "--exclude"
                | "-F"
                | "--features"
                | "--bin"
                | "--example"
                | "--test"
                | "--bench"
                | "-j"
                | "--jobs"
                | "--out-dir"
                | "--artifact-dir"
                | "--crate-type"
                | "--filter-expr"
                | "-E"
                | "--filterset"
                | "-P"
                | "--partition"
                | "--status-level"
                | "--final-status-level"
                | "--failure-output"
                | "--success-output"
                | "--archive-file"
                | "--workspace-remap"
                | "--test-threads"
        )
    }
}

fn opaque_argument_is_value(prefix: &str, program: &str) -> bool {
    // A fixed non-option prefix cannot become --target. Known --flag=value
    // spellings retain their arity even when the attached value expands empty.
    if !prefix.is_empty() && !prefix.starts_with(['-', '+']) {
        return true;
    }
    if prefix
        .split_once('=')
        .is_some_and(|(flag, _)| option_takes_value(flag, program))
    {
        return true;
    }
    let short: &[&str] = if matches!(program, "clang" | "clang++") {
        &[
            "-o", "-x", "-I", "-D", "-U", "-L", "-l", "-B", "-MF", "-MJ", "-MT", "-MQ",
        ]
    } else if program == "rustc" {
        &["-C", "-Z", "-L", "-l", "-A", "-W", "-D", "-F"]
    } else {
        &["-j", "-p", "-F", "-Z", "-C"]
    };
    // Require a fixed, nonempty operand: -D"$NAME" could expand to bare -D
    // and consume the next token, but -DNAME="$VALUE" cannot change its arity.
    short.iter().any(|flag| {
        prefix
            .strip_prefix(flag)
            .is_some_and(|value| !value.is_empty())
    })
}

fn compiler_target_options(words: &[AdmissionArgument]) -> Vec<String> {
    let Some(program) = words[0].literal().and_then(|word| word.rsplit('/').next()) else {
        return Vec::new();
    };
    let native = matches!(program, "clang" | "clang++");
    let mut targets = Vec::new();
    let mut args = words[1..].iter();
    while let Some(word) = args.next() {
        let argument = match word {
            AdmissionArgument::Literal(value) => value.as_str(),
            AdmissionArgument::Opaque(prefix) if opaque_argument_is_value(prefix, program) => {
                continue;
            }
            AdmissionArgument::Opaque(_) | AdmissionArgument::Unbounded => return Vec::new(),
        };
        if argument == "--" {
            break;
        }
        let target = if argument == "--target" || native && argument == "-target" {
            match args.next() {
                Some(AdmissionArgument::Literal(value)) => Some(value.as_str()),
                Some(AdmissionArgument::Opaque(_) | AdmissionArgument::Unbounded) => {
                    return Vec::new();
                }
                None => None,
            }
        } else {
            argument
                .strip_prefix("--target=")
                .or_else(|| native.then(|| argument.strip_prefix("-target=")).flatten())
        };
        if let Some(target) = target {
            // Clang's final driver target wins. Cargo can build several
            // explicitly selected targets and requires all of their stds.
            if native {
                targets.clear();
            }
            if target_value_is_literal(target) {
                targets.push(target.to_owned());
            }
        } else if option_takes_value(argument, program)
            && matches!(args.next(), Some(AdmissionArgument::Unbounded))
        {
            return Vec::new();
        }
    }
    targets
}

/// Derive language capabilities and separate host-target evidence from the
/// invoked compiler's own options. CMake build targets, TypeScript targets,
/// and test-program arguments are never Rust standard-library requirements.
fn derive_capabilities(command: &str, kind: Option<CompilationKind>) -> DerivedCapabilities {
    let mut req = RequiredCapabilities::default();
    if let Some(kind) = kind {
        req.needs_cargo = is_rust_kind(kind);
        req.needs_bun = matches!(
            kind,
            CompilationKind::BunTest | CompilationKind::BunTypecheck
        );
        req.needs_nix = matches!(kind, CompilationKind::NixBuild);
        req.needs_go = matches!(
            kind,
            CompilationKind::GoBuild | CompilationKind::GoTest | CompilationKind::GoVet
        );
        req.needs_node = matches!(kind, CompilationKind::Tsc);
        // A zig cross-build additionally needs zig + cargo-zigbuild on the worker.
        // The requested `--target` std is captured by the needs_targets scan below,
        // exactly as for a plain `cargo build --target ...`.
        req.needs_zig = matches!(kind, CompilationKind::CargoZigbuild);
    }
    let normalized = normalize_command(command);
    let words = admission_arguments(&normalized).filter(|words| {
        let Some(program) = words[0].literal().and_then(|word| word.rsplit('/').next()) else {
            return false;
        };
        req.needs_cargo && matches!(program, "cargo" | "rustc" | "cargo-xwin" | "cargo-zigbuild")
            || matches!(
                kind,
                Some(CompilationKind::Clang | CompilationKind::Clangpp)
            ) && matches!(program, "clang" | "clang++")
    });
    let targets = words
        .as_deref()
        .map(compiler_target_options)
        .unwrap_or_default();
    if req.needs_cargo {
        req.needs_targets = targets.clone();
        let selector = words.as_ref().and_then(|words| {
            let program = words[0].literal()?.rsplit('/').next()?;
            matches!(program, "cargo" | "rustc")
                .then(|| words.get(1)?.literal()?.strip_prefix('+'))
                .flatten()
        });
        let toolchain = selector
            .map(str::to_owned)
            .or_else(|| crate::rustup_toolchain_from_command(command).ok().flatten());
        if let Some(toolchain) = toolchain.filter(|name| {
            !name.is_empty()
                && !name.starts_with('-')
                && !name.chars().any(|ch| ch.is_whitespace() || ch.is_control())
        }) {
            req.needs_toolchains.push(toolchain);
        }
    }
    req.needs_targets.sort();
    req.needs_targets.dedup();
    req.needs_toolchains.sort();
    req.needs_toolchains.dedup();
    let host_targets = host_bound_targets(command, &targets);
    req.needs_os = os_from_target_triples(&host_targets);
    DerivedCapabilities {
        required: req,
        host_targets,
    }
}

/// Explicit cross-build tools supply their linker on the build host. Darwin
/// zigbuild still needs the Apple SDK, Zig, and the requested Rust target, but
/// the SDK can reside on Linux. Keep native constraints for ordinary Cargo and
/// for targets the selected cross-build tool does not support here.
fn host_bound_targets(command: &str, targets: &[String]) -> Vec<String> {
    let cross_msvc = cargo_xwin_compilation_kind(command).is_some();
    let cross_darwin = classify_command(command).kind == Some(CompilationKind::CargoZigbuild);
    targets
        .iter()
        .filter(|target| {
            let target = target.to_ascii_lowercase();
            !(cross_msvc && target.contains("-windows-msvc")
                || cross_darwin && target.ends_with("-apple-darwin"))
        })
        .cloned()
        .collect()
}

/// The host OS a command demands of a worker, if any.
///
/// Exposed for the daemon's selection path, which gates on the command string it
/// already carries rather than on a new wire field — keeping this usable across
/// a fleet whose `rch` and `rchd` binaries are at mixed versions.
#[must_use]
pub fn required_os_for_command(command: &str) -> Option<String> {
    let mut triples: Vec<String> = Vec::new();
    for part in split_shell_commands(command) {
        let detail = classify_command_detailed(part);
        if detail.classification.is_compilation {
            triples.extend(derive_capabilities(part, detail.classification.kind).host_targets);
        }
    }
    os_from_command_and_targets(command, &triples)
}

/// Native Apple tools need a Darwin host even in explicit job mode, where the
/// compilation classifier deliberately does not recognize them. Only inspect
/// the invoked command word, never an argument mentioning a tool. Opaque shell
/// scripts are not inferred: callers must invoke the Apple tool directly.
fn os_from_command_and_targets(command: &str, triples: &[String]) -> Option<String> {
    let native_hosts = split_shell_commands(command)
        .into_iter()
        .filter_map(|part| {
            let normalized = normalize_command(part);
            let (word, _) = split_wrapper_word(&normalized)?;
            match word.rsplit('/').next()? {
                "xcodebuild" | "xcrun" => Some("darwin"),
                _ => None,
            }
        });
    unique_host_os(
        triples
            .iter()
            .filter_map(|triple| target_host_os(triple))
            .chain(native_hosts),
    )
}

/// The host OS a set of `--target` triples demands, when they agree on one.
///
/// Only a triple naming an OS the worker must *be* counts. `x86_64-pc-windows-msvc`
/// ordinarily links against the native MSVC toolchain, so it yields `windows`;
/// explicit cargo-xwin compilations remove their MSVC targets before this step.
/// Every `*-apple-*` target (darwin, ios, tvos, watchos, visionos)
/// needs the macOS SDK, so it yields `darwin`. `x86_64-pc-windows-gnu` and
/// `wasm32-unknown-unknown` cross-compile happily from Linux and yield nothing.
///
/// Mixed or absent requirements yield `None`, leaving the command schedulable
/// anywhere — the historical behaviour. A compound command spanning two host
/// OSes cannot succeed on any single worker regardless, and returning `None`
/// keeps that no worse than it is today rather than inventing a new refusal.
fn os_from_target_triples(triples: &[String]) -> Option<String> {
    unique_host_os(triples.iter().filter_map(|triple| target_host_os(triple)))
}

fn target_host_os(triple: &str) -> Option<&'static str> {
    let lower = triple.to_ascii_lowercase();
    if lower.contains("-windows-msvc") {
        Some("windows")
    } else if lower.contains("-apple-") {
        Some("darwin")
    } else {
        None
    }
}

fn unique_host_os(hosts: impl IntoIterator<Item = &'static str>) -> Option<String> {
    let mut required: Option<String> = None;
    for os in hosts {
        match &required {
            Some(existing) if existing != os => return None,
            Some(_) => {}
            None => required = Some(os.to_string()),
        }
    }
    required
}

/// Run the read-only preflight for a command. `proof_policy` reflects the
/// caller's strict/proof-remote setting (from env/flags). Pure.
#[must_use]
pub fn preflight(command: &str, proof_policy: bool) -> AdmitPreflight {
    let compound: Vec<String> = split_shell_commands(command)
        .into_iter()
        .map(Into::into)
        .collect();
    let compound = if compound.is_empty() {
        vec![command.to_string()]
    } else {
        compound
    };

    // The whole command is a compilation if any sub-command classifies as one;
    // capabilities are the union across compilation sub-commands.
    let mut is_compilation = false;
    let mut family: Option<String> = None;
    let mut required = RequiredCapabilities::default();
    let mut host_targets = Vec::new();
    for part in &compound {
        let detail = classify_command_detailed(part);
        let c = &detail.classification;
        if c.is_compilation {
            is_compilation = true;
            if let Some(kind) = c.kind
                && family.is_none()
            {
                family = Some(family_token(kind).to_string());
            }
            let derived = derive_capabilities(part, c.kind);
            host_targets.extend(derived.host_targets);
            let part_req = derived.required;
            required.needs_cargo |= part_req.needs_cargo;
            required.needs_zig |= part_req.needs_zig;
            required.needs_bun |= part_req.needs_bun;
            required.needs_nix |= part_req.needs_nix;
            required.needs_go |= part_req.needs_go;
            required.needs_node |= part_req.needs_node;
            required.needs_targets.extend(part_req.needs_targets);
            required.needs_toolchains.extend(part_req.needs_toolchains);
        }
    }
    required.needs_targets.sort();
    required.needs_targets.dedup();
    required.needs_toolchains.sort();
    required.needs_toolchains.dedup();
    // Recomputed over the merged target set: a compound command whose parts
    // disagree on the required OS must not inherit one part's answer.
    required.needs_os = os_from_command_and_targets(command, &host_targets);

    let base_recommendation = if is_compilation {
        AdmitRecommendation::Offload
    } else {
        AdmitRecommendation::Local
    };

    let detail = if !is_compilation {
        "not a compilation command; run locally".to_string()
    } else if compound.len() > 1 {
        format!(
            "compound command with {} parts; offload-eligible (family={})",
            compound.len(),
            family.as_deref().unwrap_or("unknown")
        )
    } else {
        format!(
            "offload-eligible (family={})",
            family.as_deref().unwrap_or("unknown")
        )
    };

    AdmitPreflight {
        command: command.to_string(),
        compound,
        is_compilation,
        family,
        required,
        proof_policy,
        job_mode: false,
        base_recommendation,
        detail,
    }
}

impl AdmitPreflight {
    /// Add explicit compiler capabilities without bypassing classification or
    /// replacing the command's existing Rust/target/toolchain requirements.
    #[must_use]
    pub fn with_required_tools(mut self, required_tools: Vec<String>) -> Self {
        self.required.needs_tools.extend(required_tools);
        self.required.needs_tools.sort();
        self.required.needs_tools.dedup();
        self
    }

    /// Re-frame a preflight as a JOB-mode admission (`rch exec --job`).
    ///
    /// Job mode bypasses the compilation classifier rather than consulting it,
    /// so a job is offload-eligible whatever the classifier thought: `./fuzz.sh`
    /// is not a compilation and must still preflight as `offload`, otherwise
    /// this command would answer `local` for every workload job mode exists to
    /// serve.
    ///
    /// The classification facts are KEPT rather than cleared. A caller that
    /// passes `cargo test` to `--job` should still be able to see that it would
    /// have classified as a compilation — that is usually a mistake worth
    /// noticing, and erasing the evidence would hide it.
    ///
    /// Required tools are caller-stated, never derived: RCH cannot know that a
    /// shell script shells out to clang.
    #[must_use]
    pub fn as_job(mut self, required_tools: Vec<String>) -> Self {
        self.job_mode = true;
        self.required.needs_tools = required_tools;
        self.required.needs_tools.sort();
        self.required.needs_tools.dedup();
        self.base_recommendation = AdmitRecommendation::Offload;
        let tools = if self.required.needs_tools.is_empty() {
            String::new()
        } else {
            format!(
                "; requires verified tool(s) {}",
                self.required.needs_tools.join(", ")
            )
        };
        self.detail = format!(
            "job-mode admission: classifier bypassed, offload-eligible (classified as {}{})",
            if self.is_compilation {
                self.family.as_deref().unwrap_or("a compilation")
            } else {
                "non-compilation"
            },
            tools
        );
        self
    }
}

/// Fold aggregated candidate-rejection data into a final recommendation.
///
/// A non-offload base stays as-is. For an offload-eligible command: if every
/// candidate was rejected, distinguish a *structural* gap (command-admissibility
/// rejections dominate — no worker can run it, so `Defer`) from a *transient*
/// one (worker-health rejections dominate — busy/unhealthy, so `Queue`). If some
/// candidate remained admissible, `Offload`.
#[must_use]
pub fn refine_recommendation(
    base: AdmitRecommendation,
    summary: &AdmissionRejectionSummary,
) -> AdmitRecommendation {
    if base != AdmitRecommendation::Offload {
        return base;
    }
    if !summary.all_rejected() {
        return AdmitRecommendation::Offload;
    }
    let command_specific = summary.class_count(RejectionClass::CommandAdmissibility)
        + summary.class_count(RejectionClass::ProjectPolicy);
    let health = summary.class_count(RejectionClass::WorkerHealth);
    if command_specific >= health {
        AdmitRecommendation::Defer
    } else {
        AdmitRecommendation::Queue
    }
}

/// Convenience: whether `command` would offload at all (cheap classification).
#[must_use]
pub fn is_offloadable(command: &str) -> bool {
    classify_command(command).is_compilation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_rejection::{
        AdmissionRejectionCategory, CandidateRejection, aggregate_rejections,
    };

    #[test]
    fn compiler_tool_requirements_preserve_rust_target_and_classification() {
        let original = preflight(
            "cargo build --target x86_64-pc-windows-msvc --release",
            true,
        );
        let observed = original.clone().with_required_tools(vec![
            "cargo-xwin".into(),
            "llvm-ar".into(),
            "cargo-xwin".into(),
        ]);
        assert_eq!(observed.is_compilation, original.is_compilation);
        assert_eq!(observed.family, original.family);
        assert_eq!(observed.base_recommendation, original.base_recommendation);
        assert_eq!(
            observed.required.needs_targets,
            original.required.needs_targets
        );
        assert_eq!(
            observed.required.needs_toolchains,
            original.required.needs_toolchains
        );
        assert!(observed.required.needs_cargo);
        assert!(!observed.job_mode);
        assert!(observed.proof_policy);
        assert_eq!(observed.required.needs_tools, vec!["cargo-xwin", "llvm-ar"]);
    }

    #[test]
    fn job_mode_preflight_is_offload_eligible_whatever_the_classifier_said() {
        // THE point of the job-mode preflight: `exec --job` bypasses the
        // classifier, so a preflight that consulted it would answer `local`
        // for every workload job mode exists to serve.
        let script = preflight("./run_shards.sh --shard 3", false);
        assert!(!script.is_compilation);
        assert_eq!(script.base_recommendation, AdmitRecommendation::Local);

        let job = script.clone().as_job(Vec::new());
        assert!(job.job_mode);
        assert_eq!(job.base_recommendation, AdmitRecommendation::Offload);
        assert!(job.detail.contains("classifier bypassed"), "{}", job.detail);
        // The classification facts are KEPT, not cleared — they are still the
        // truth about the command, and erasing them would hide a mistake.
        assert!(!job.is_compilation);
        assert_eq!(job.command, script.command);
        assert_eq!(job.compound, script.compound);

        // A compilation passed to --job keeps its family visible, precisely so
        // a caller can notice they probably did not mean `--job`.
        let compile = preflight("cargo test --workspace", false).as_job(Vec::new());
        assert!(compile.is_compilation);
        assert_eq!(compile.family.as_deref(), Some("cargo_test"));
        assert_eq!(compile.base_recommendation, AdmitRecommendation::Offload);
        assert!(compile.detail.contains("cargo_test"), "{}", compile.detail);
    }

    #[test]
    fn job_mode_required_tools_are_caller_stated_normalized_and_gate_ready() {
        // Never derived: nothing can know that a shell script shells out to
        // clang, so the requirement only ever comes from the caller.
        assert!(
            preflight("./fuzz.sh", false)
                .as_job(Vec::new())
                .required
                .needs_tools
                .is_empty()
        );

        let job = preflight("./fuzz.sh", false).as_job(vec![
            "clang".to_string(),
            "ld.lld".to_string(),
            "clang".to_string(),
        ]);
        assert_eq!(
            job.required.needs_tools,
            vec!["clang".to_string(), "ld.lld".to_string()],
            "sorted and deduped so the same request preflights identically"
        );
        assert!(job.detail.contains("clang, ld.lld"), "{}", job.detail);

        // And it converts into the SAME requirement the selection gate uses,
        // so the preflight cannot drift from the admission it predicts.
        let requirement = job.required.to_requirement(1);
        assert_eq!(
            requirement.needs_tools,
            vec!["clang".to_string(), "ld.lld".to_string()]
        );
    }

    #[test]
    fn msvc_target_requires_a_windows_host() {
        // Ordinary Cargo builds use the native Microsoft toolchain. Only an
        // explicit cross-build entry point can supply that SDK on another OS.
        assert_eq!(
            required_os_for_command("cargo build --target x86_64-pc-windows-msvc"),
            Some("windows".to_string())
        );
        assert_eq!(
            required_os_for_command("cargo build --target=aarch64-pc-windows-msvc --release"),
            Some("windows".to_string())
        );
    }

    #[test]
    fn cargo_xwin_keeps_rust_requirements_without_a_native_windows_gate() {
        for (subcommand, family) in [
            ("build", "cargo_build"),
            ("check", "cargo_check"),
            ("clippy", "cargo_clippy"),
        ] {
            for (prefix, toolchain) in [
                ("cargo xwin", None),
                ("cargo +nightly-2026-08-31 xwin", Some("nightly-2026-08-31")),
                ("cargo-xwin", None),
                ("cargo-xwin xwin", None),
            ] {
                for (target_argument, target) in [
                    ("--target x86_64-pc-windows-msvc", "x86_64-pc-windows-msvc"),
                    (
                        "--target=aarch64-pc-windows-msvc",
                        "aarch64-pc-windows-msvc",
                    ),
                ] {
                    let passthrough = if subcommand == "clippy" {
                        " -- -D warnings"
                    } else {
                        ""
                    };
                    let command = format!(
                        "{prefix} {subcommand} --locked --all-targets {target_argument}{passthrough}"
                    );
                    let result = preflight(&command, true);
                    let expected_toolchains: Vec<String> = toolchain
                        .into_iter()
                        .map(|value| value.to_string())
                        .collect();
                    assert!(result.is_compilation, "{command}");
                    assert!(result.required.needs_cargo, "{command}");
                    assert_eq!(result.family.as_deref(), Some(family), "{command}");
                    assert_eq!(
                        result.required.needs_targets,
                        vec![target.to_string()],
                        "{command}"
                    );
                    assert_eq!(
                        result.required.needs_toolchains, expected_toolchains,
                        "{command}"
                    );
                    assert_eq!(result.required.needs_os, None, "{command}");
                    assert_eq!(required_os_for_command(&command), None, "{command}");
                    let requirement = result.required.to_requirement(1);
                    assert!(requirement.needs_cargo, "{command}");
                    assert_eq!(requirement.min_protocol, 1, "{command}");
                    assert_eq!(
                        requirement.needs_targets, result.required.needs_targets,
                        "{command}"
                    );
                    assert_eq!(
                        requirement.needs_toolchains, result.required.needs_toolchains,
                        "{command}"
                    );
                    assert_eq!(requirement.needs_os, None, "{command}");
                }
            }
        }
    }

    #[test]
    fn cargo_xwin_does_not_relax_other_commands_or_apple_targets() {
        for command in [
            "cargo check --target x86_64-pc-windows-msvc",
            "cargo clippy --target x86_64-pc-windows-msvc -- -D warnings",
            "cargo xwin build --target x86_64-pc-windows-msvc && cargo build --target x86_64-pc-windows-msvc",
            "cargo xwin check --target x86_64-pc-windows-msvc && cargo check --target x86_64-pc-windows-msvc",
            "cargo xwin clippy --target x86_64-pc-windows-msvc && cargo clippy --target x86_64-pc-windows-msvc",
            "cargo --config xwin build --target x86_64-pc-windows-msvc",
            "cargo --config xwin check --target x86_64-pc-windows-msvc",
            "cargo --config xwin clippy --target x86_64-pc-windows-msvc",
            "cargo build --manifest-path cargo-xwin --target x86_64-pc-windows-msvc",
            "cargo check --manifest-path 'cargo xwin check' --target x86_64-pc-windows-msvc",
            "cargo clippy --config 'alias.cross=xwin' --target x86_64-pc-windows-msvc",
        ] {
            assert_eq!(
                required_os_for_command(command).as_deref(),
                Some("windows"),
                "{command}"
            );
            assert_eq!(
                preflight(command, true).required.needs_os.as_deref(),
                Some("windows"),
                "{command}"
            );
        }
        for command in [
            "cargo xwin build --target aarch64-apple-darwin",
            "cargo xwin check --target aarch64-apple-darwin",
            "cargo xwin clippy --target aarch64-apple-darwin",
            "cargo-xwin check --target aarch64-apple-darwin",
            "cargo-xwin xwin clippy --target aarch64-apple-darwin",
            "cargo xwin build --target x86_64-pc-windows-msvc && cargo build --target aarch64-apple-darwin",
            "cargo xwin check --target x86_64-pc-windows-msvc && cargo check --target aarch64-apple-darwin",
        ] {
            assert_eq!(
                required_os_for_command(command).as_deref(),
                Some("darwin"),
                "{command}"
            );
            assert_eq!(
                preflight(command, true).required.needs_os.as_deref(),
                Some("darwin"),
                "{command}"
            );
        }
    }

    #[test]
    fn darwin_zigbuild_keeps_linker_and_target_requirements_without_native_host_gate() {
        for command in [
            "cargo zigbuild --target aarch64-apple-darwin",
            "cargo +nightly zigbuild --target=x86_64-apple-darwin",
            "cargo-zigbuild zigbuild --target aarch64-apple-darwin",
            "env SDKROOT=/opt/MacOSX.sdk cargo zigbuild --target aarch64-apple-darwin",
        ] {
            let result = preflight(command, true);
            assert!(result.is_compilation, "{command}");
            assert!(result.required.needs_cargo, "{command}");
            assert!(result.required.needs_zig, "{command}");
            assert_eq!(result.family.as_deref(), Some("cargo_zigbuild"));
            assert_eq!(result.required.needs_targets.len(), 1);
            assert!(result.required.needs_targets[0].ends_with("-apple-darwin"));
            assert_eq!(result.required.needs_os, None);
            assert_eq!(required_os_for_command(command), None);
        }
    }

    #[test]
    fn darwin_zigbuild_does_not_relax_native_commands_or_other_apple_targets() {
        for command in [
            "cargo build --target aarch64-apple-darwin",
            "cargo build --manifest-path cargo-zigbuild --target aarch64-apple-darwin",
            "cargo --config zigbuild build --target aarch64-apple-darwin",
            "cargo zigbuild --target aarch64-apple-ios",
            "cargo zigbuild --target aarch64-apple-darwin && cargo build --target aarch64-apple-darwin",
        ] {
            assert_eq!(
                required_os_for_command(command).as_deref(),
                Some("darwin"),
                "{command}"
            );
            assert_eq!(
                preflight(command, true).required.needs_os.as_deref(),
                Some("darwin"),
                "{command}"
            );
        }
        let command = "cargo zigbuild --target x86_64-pc-windows-msvc";
        assert_eq!(required_os_for_command(command).as_deref(), Some("windows"));
        assert_eq!(
            preflight(command, true).required.needs_os.as_deref(),
            Some("windows")
        );
    }

    #[test]
    fn cross_compilable_targets_stay_unconstrained() {
        // mingw and wasm cross-compile from Linux, so constraining them would
        // strand work that the existing fleet handles today.
        assert_eq!(
            required_os_for_command("cargo build --target x86_64-pc-windows-gnu"),
            None
        );
        assert_eq!(
            required_os_for_command("cargo build --target wasm32-unknown-unknown"),
            None
        );
        assert_eq!(required_os_for_command("cargo check --workspace"), None);
        assert_eq!(required_os_for_command("cargo test"), None);
    }

    #[test]
    fn apple_target_requires_a_darwin_host() {
        // Every Apple target needs the macOS SDK, not just apple-darwin.
        for triple in [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "aarch64-apple-ios",
            "aarch64-apple-tvos",
            "arm64_32-apple-watchos",
        ] {
            assert_eq!(
                required_os_for_command(&format!("cargo build --target {triple}")),
                Some("darwin".to_string()),
                "triple={triple}"
            );
        }
    }

    #[test]
    fn native_apple_jobs_require_darwin_without_rust_target_flags() {
        for command in [
            "xcodebuild -version",
            "/usr/bin/xcodebuild -project ios/App.xcodeproj -scheme App build",
            "'xcodebuild' -scheme App test",
            "'/Applications/Xcode Beta.app/Contents/Developer/usr/bin/xcodebuild' -version",
            "env DEVELOPER_DIR='/Applications/Xcode Beta.app' xcodebuild -jobs 1 test",
            "timeout 1200 xcodebuild -destination 'platform=macOS,variant=Mac Catalyst' test",
            "xcrun --sdk iphoneos xcodebuild -scheme App build",
            "/usr/bin/xcrun --find swift",
            "cd ios && xcodebuild -scheme App build",
        ] {
            assert_eq!(
                required_os_for_command(command).as_deref(),
                Some("darwin"),
                "{command}"
            );
            let job = preflight(command, true).as_job(Vec::new());
            assert_eq!(
                job.required.needs_os.as_deref(),
                Some("darwin"),
                "{command}"
            );
            assert!(
                job.required.needs_targets.is_empty(),
                "not a Rust target: {command}"
            );
            assert!(!job.required.needs_cargo, "not a Cargo job: {command}");
        }
    }

    #[test]
    fn native_apple_job_inference_does_not_claim_mentions_or_opaque_scripts() {
        for command in [
            "echo xcodebuild -version",
            "printf '%s' 'xcrun --sdk macosx'",
            "br comments add bd-example 'xcodebuild -scheme App build'",
            "env NOTE=xcodebuild bun test",
            "env -u xcodebuild bun test",
            "xcodebuild-wrapper -scheme App build",
            "./check.sh --target aarch64-apple-darwin",
            "bash -c 'echo xcodebuild'",
            "bash -c 'xcodebuild -version'",
            "'xcodebuild -version'",
            "\"${TOOL}/xcodebuild\" -version",
            "'unterminated/xcodebuild -version",
        ] {
            assert_eq!(required_os_for_command(command), None, "{command}");
            assert_eq!(
                preflight(command, true)
                    .as_job(Vec::new())
                    .required
                    .needs_os,
                None,
                "{command}"
            );
        }
        assert_eq!(
            required_os_for_command(
                "xcodebuild build && cargo build --target x86_64-pc-windows-msvc"
            ),
            None,
            "mixed native host requirements must not inherit just the Rust half"
        );
    }

    #[test]
    fn conflicting_targets_constrain_nothing() {
        // A compound command spanning two host OSes has no single answer; it must
        // stay schedulable rather than inherit one half's requirement.
        assert_eq!(
            required_os_for_command(
                "cargo build --target x86_64-pc-windows-msvc && cargo build --target aarch64-apple-darwin"
            ),
            None
        );
    }

    #[test]
    fn preflight_surfaces_the_required_os() {
        let p = preflight("cargo build --target x86_64-pc-windows-msvc", false);
        assert_eq!(p.required.needs_os.as_deref(), Some("windows"));
        assert_eq!(
            p.required.to_requirement(0).needs_os.as_deref(),
            Some("windows")
        );

        let plain = preflight("cargo build --release", false);
        assert_eq!(plain.required.needs_os, None);
        assert_eq!(plain.required.to_requirement(0).needs_os, None);
    }

    #[test]
    fn common_cargo_build_offloads_needing_cargo() {
        let p = preflight("cargo build --release", false);
        assert!(p.is_compilation);
        assert_eq!(p.family.as_deref(), Some("cargo_build"));
        assert!(p.required.needs_cargo);
        assert!(!p.required.needs_bun);
        assert_eq!(p.base_recommendation, AdmitRecommendation::Offload);
    }

    #[test]
    fn wasm_target_is_captured_as_required_capability() {
        let p = preflight("cargo build --target wasm32-unknown-unknown", false);
        assert!(p.required.needs_cargo);
        assert_eq!(p.required.needs_targets, vec!["wasm32-unknown-unknown"]);
        // `--target=triple` form too.
        let p2 = preflight("cargo test --target=aarch64-apple-darwin", false);
        assert_eq!(p2.required.needs_targets, vec!["aarch64-apple-darwin"]);
    }

    #[test]
    fn explicit_toolchain_override_is_captured() {
        let p = preflight("cargo +nightly-2025-11-01 build", false);
        assert_eq!(p.required.needs_toolchains, vec!["nightly-2025-11-01"]);
    }

    #[test]
    fn non_rust_targets_never_require_rustup_or_select_a_host_os() {
        for command in [
            "cmake --build obj/debug --target app",
            "cmake --build obj/debug --target aarch64-apple-darwin",
            "cmake --build obj/debug --target x86_64-pc-windows-msvc",
            "cmake --build obj/debug --target +nightly",
            "env RUSTUP_TOOLCHAIN=nightly cmake --build obj --target app",
            "ninja -C obj +nightly",
            "make +nightly",
            "gcc -c main.c -o main.o -D 'TEXT= --target aarch64-apple-darwin +nightly'",
            "tsc --noEmit --target ES2022",
            "bun test -- --target x86_64-pc-windows-msvc +nightly",
        ] {
            let result = preflight(command, true);
            assert!(result.is_compilation, "{command}");
            assert!(!result.required.needs_cargo, "{command}");
            assert!(result.required.needs_targets.is_empty(), "{command}");
            assert!(result.required.needs_toolchains.is_empty(), "{command}");
            assert!(result.required.needs_tools.is_empty(), "{command}");
            assert_eq!(result.required.needs_os, None, "{command}");
            assert_eq!(required_os_for_command(command), None, "{command}");
        }
    }

    #[test]
    fn rust_requirements_follow_literal_compiler_options_and_wrappers() {
        for (command, toolchain, targets, host) in [
            (
                "env NOTE='--target x86_64-pc-windows-msvc +decoy' cargo +nightly build --target 'wasm32-unknown-unknown'",
                Some("nightly"),
                vec!["wasm32-unknown-unknown"],
                None,
            ),
            (
                "timeout 30 cargo +nightly build '--target=aarch64-apple-darwin'",
                Some("nightly"),
                vec!["aarch64-apple-darwin"],
                Some("darwin"),
            ),
            (
                "time -f '--target x86_64-pc-windows-msvc +decoy' cargo build --target='wasm32-unknown-unknown'",
                None,
                vec!["wasm32-unknown-unknown"],
                None,
            ),
            (
                "RUSTUP_TOOLCHAIN=nightly-2026-01-01 cargo build --target x86_64-pc-windows-msvc",
                Some("nightly-2026-01-01"),
                vec!["x86_64-pc-windows-msvc"],
                Some("windows"),
            ),
            (
                "env RUSTUP_TOOLCHAIN=nightly cargo +stable build --target wasm32-unknown-unknown",
                Some("stable"),
                vec!["wasm32-unknown-unknown"],
                None,
            ),
            (
                "rustc +nightly main.rs --cfg 'feature=\"--target x86_64-pc-windows-msvc\"' --target wasm32-unknown-unknown",
                Some("nightly"),
                vec!["wasm32-unknown-unknown"],
                None,
            ),
            (
                "cargo build --target wasm32-unknown-unknown --target aarch64-apple-darwin",
                None,
                vec!["aarch64-apple-darwin", "wasm32-unknown-unknown"],
                Some("darwin"),
            ),
        ] {
            let result = preflight(command, true);
            assert!(result.is_compilation, "{command}");
            assert!(result.required.needs_cargo, "{command}");
            assert_eq!(result.required.needs_targets, targets, "{command}");
            assert_eq!(
                result.required.needs_toolchains,
                toolchain.into_iter().collect::<Vec<_>>(),
                "{command}"
            );
            assert_eq!(result.required.needs_os.as_deref(), host, "{command}");
            assert_eq!(
                required_os_for_command(command).as_deref(),
                host,
                "{command}"
            );
        }
    }

    #[test]
    fn rust_argument_payloads_and_separators_do_not_become_requirements() {
        for command in [
            "cargo test +test_name -- --target x86_64-pc-windows-msvc +nightly",
            "cargo clippy -- -W '--target=aarch64-apple-darwin'",
            "cargo build --config '--target=x86_64-pc-windows-msvc'",
            "cargo test --test +nightly",
            "cargo build --target ./targets/x86_64-apple-custom.json",
            "cargo build --target x86_64-apple-custom.json",
            "rustc main.rs -- --target=x86_64-pc-windows-msvc",
            "rustc main.rs --cfg '--target=x86_64-pc-windows-msvc'",
            "rustc main.rs --crate-name +nightly",
        ] {
            let result = preflight(command, true);
            assert!(result.is_compilation, "{command}");
            assert!(result.required.needs_cargo, "{command}");
            assert!(result.required.needs_targets.is_empty(), "{command}");
            assert!(result.required.needs_toolchains.is_empty(), "{command}");
            assert_eq!(result.required.needs_os, None, "{command}");
            assert_eq!(required_os_for_command(command), None, "{command}");
        }
    }

    #[test]
    fn clang_targets_constrain_hosts_without_requiring_rust_std() {
        for (command, host) in [
            (
                "clang --target=x86_64-pc-windows-msvc -c main.c -o main.o",
                Some("windows"),
            ),
            (
                "clang++ -target aarch64-apple-darwin -c main.cpp -o main.o",
                Some("darwin"),
            ),
            (
                "env NOTE='--target=x86_64-pc-windows-msvc' clang -target 'aarch64-apple-darwin' -c main.c",
                Some("darwin"),
            ),
            (
                "clang --target=aarch64-apple-darwin --target=x86_64-unknown-linux-gnu -c main.c",
                None,
            ),
            (
                "clang --target=x86_64-pc-windows-msvc -target aarch64-apple-darwin -c main.c",
                Some("darwin"),
            ),
            ("clang -c main.c -D '--target=x86_64-pc-windows-msvc'", None),
            (
                "clang -c main.c -Xclang --target=aarch64-apple-darwin",
                None,
            ),
            ("clang -c main.c -- --target=x86_64-pc-windows-msvc", None),
            (
                "clang -c main.c -o main.o -D 'TEXT= --target x86_64-pc-windows-msvc +nightly'",
                None,
            ),
        ] {
            let result = preflight(command, true);
            assert!(result.is_compilation, "{command}");
            assert!(!result.required.needs_cargo, "{command}");
            assert!(result.required.needs_targets.is_empty(), "{command}");
            assert!(result.required.needs_toolchains.is_empty(), "{command}");
            assert_eq!(result.required.needs_os.as_deref(), host, "{command}");
            assert_eq!(
                required_os_for_command(command).as_deref(),
                host,
                "{command}"
            );
        }
    }

    #[test]
    fn compound_host_requirements_ignore_non_compiler_target_names() {
        for (command, host) in [
            (
                "cmake --build obj --target x86_64-pc-windows-msvc && cargo build --target aarch64-apple-darwin",
                Some("darwin"),
            ),
            (
                "clang -c main.c --target=x86_64-pc-windows-msvc && cargo build --target aarch64-apple-darwin",
                None,
            ),
        ] {
            let result = preflight(command, true);
            assert!(result.is_compilation, "{command}");
            assert_eq!(result.required.needs_targets, vec!["aarch64-apple-darwin"]);
            assert_eq!(result.required.needs_os.as_deref(), host, "{command}");
            assert_eq!(
                required_os_for_command(command).as_deref(),
                host,
                "{command}"
            );
        }
    }

    #[test]
    fn admission_arguments_do_not_evaluate_opaque_shell_words() {
        for command in [
            "cargo build --target=$TARGET",
            "cargo build --target `target-name`",
            "cargo build --features \"$@\"",
            "cargo build --features \"${FEATURES:-default}\"",
        ] {
            let arguments = admission_arguments(command).expect("literal prefix remains available");
            assert_eq!(
                arguments.last(),
                Some(&AdmissionArgument::Unbounded),
                "{command}"
            );
            assert!(compiler_target_options(&arguments).is_empty(), "{command}");
        }
        assert!(admission_arguments("cargo build --target 'unterminated").is_none());
        for command in [
            "cargo build '--target=wasm32-unknown-unknown' > output.log",
            "cargo build --target=\"wasm32-unknown-unknown\"",
        ] {
            assert_eq!(
                admission_arguments(command),
                Some(
                    ["cargo", "build", "--target=wasm32-unknown-unknown"]
                        .into_iter()
                        .map(|word| AdmissionArgument::Literal(word.to_owned()))
                        .collect()
                ),
                "{command}"
            );
        }
    }

    #[test]
    fn quoted_unrelated_operands_preserve_explicit_compiler_targets() {
        for command in [
            "cargo build --target aarch64-apple-darwin --features=\"$FEATURES\"",
            "cargo build --features=\"${FEATURES}\" --target aarch64-apple-darwin",
            "cargo build --target aarch64-apple-darwin --features \"$FEATURES\"",
            "rustc main.rs --cfg \"$CFG\" --target aarch64-apple-darwin",
            "clang --target=aarch64-apple-darwin -DNAME=\"$NAME\" -c main.c",
            "clang -DNAME=\"${NAME}\" -c main.c --target=aarch64-apple-darwin",
            "clang --target=aarch64-apple-darwin -D \"$NAME\" -c main.c",
            "clang --sysroot \"$SDK\" --target=aarch64-apple-darwin -c main.c",
        ] {
            let result = preflight(command, true);
            assert!(result.is_compilation, "{command}");
            assert_eq!(
                result.required.needs_os.as_deref(),
                Some("darwin"),
                "{command}"
            );
            assert_eq!(
                required_os_for_command(command).as_deref(),
                Some("darwin"),
                "{command}"
            );
            if result.required.needs_cargo {
                assert_eq!(
                    result.required.needs_targets,
                    vec!["aarch64-apple-darwin"],
                    "{command}"
                );
            } else {
                assert!(result.required.needs_targets.is_empty(), "{command}");
            }
        }
    }

    #[test]
    fn opaque_arguments_cannot_manufacture_compiler_target_evidence() {
        for command in [
            "cargo build --target \"${TARGET}\"",
            "cargo build \"--target=$TARGET\"",
            "cargo build --target aarch64-apple-darwin \"$EXTRA\"",
            "cargo build --features=$FEATURES --target aarch64-apple-darwin",
            "clang --target=aarch64-apple-darwin \"$EXTRA\" -c main.c",
            "clang -D\"$NAME\" --target=aarch64-apple-darwin -c main.c",
        ] {
            let result = preflight(command, true);
            assert_eq!(result.required.needs_os, None, "{command}");
            assert_eq!(required_os_for_command(command), None, "{command}");
            assert!(result.required.needs_targets.is_empty(), "{command}");
        }
    }

    #[test]
    fn compiler_terminators_keep_program_expansion_out_of_requirements() {
        for command in [
            "cargo test --target aarch64-apple-darwin -- --filter=$FILTER",
            "cargo test --target aarch64-apple-darwin -- \"$@\"",
            "rustc main.rs --target aarch64-apple-darwin -- $INPUTS",
            "clang --target=aarch64-apple-darwin -c main.c -- $INPUTS",
        ] {
            let result = preflight(command, true);
            assert!(result.is_compilation, "{command}");
            assert_eq!(
                result.required.needs_os.as_deref(),
                Some("darwin"),
                "{command}"
            );
            assert_eq!(
                required_os_for_command(command).as_deref(),
                Some("darwin"),
                "{command}"
            );
            if result.required.needs_cargo {
                assert_eq!(
                    result.required.needs_targets,
                    vec!["aarch64-apple-darwin"],
                    "{command}"
                );
            } else {
                assert!(result.required.needs_targets.is_empty(), "{command}");
            }
        }
        for command in [
            "cargo test $ARGS --target aarch64-apple-darwin --",
            "cargo test --target aarch64-apple-darwin $ARGS --",
            "cargo test --target aarch64-apple-darwin --features $FEATURES --",
            "clang $ARGS --target=aarch64-apple-darwin -c main.c --",
        ] {
            let result = preflight(command, true);
            assert!(result.required.needs_targets.is_empty(), "{command}");
            assert_eq!(result.required.needs_os, None, "{command}");
            assert_eq!(required_os_for_command(command), None, "{command}");
        }
    }

    #[test]
    fn immediate_toolchain_selectors_survive_opaque_argument_tails() {
        for command in [
            "cargo +nightly test --features=$FEATURES",
            "timeout 30 cargo +nightly test --features=$FEATURES",
            "rustc +nightly main.rs --cfg=$CFG",
            "timeout 30 rustc +nightly main.rs --cfg=$CFG",
            "cargo +nightly test -- --filter=$FILTER",
        ] {
            let result = preflight(command, true);
            assert!(result.is_compilation, "{command}");
            assert_eq!(
                result.required.needs_toolchains,
                vec!["nightly"],
                "{command}"
            );
        }
    }

    #[test]
    fn bun_command_needs_bun() {
        let p = preflight("bun test", false);
        if p.is_compilation {
            assert!(p.required.needs_bun);
            assert!(!p.required.needs_cargo);
            assert_eq!(p.base_recommendation, AdmitRecommendation::Offload);
        } else {
            // If the classifier doesn't treat this bun form as compilation, the
            // preflight must still be decisive (local), never ambiguous.
            assert_eq!(p.base_recommendation, AdmitRecommendation::Local);
        }
    }

    #[test]
    fn non_compilation_runs_local() {
        let p = preflight("ls -la", false);
        assert!(!p.is_compilation);
        assert_eq!(p.base_recommendation, AdmitRecommendation::Local);
        assert!(!p.required.needs_cargo && !p.required.needs_bun);
        assert!(p.detail.contains("locally"));
    }

    #[test]
    fn quoted_exec_form_is_classified_decisively() {
        // A quoted exec wrapper around a build still resolves to a definite
        // recommendation (never ambiguous).
        let p = preflight("sh -c 'cargo build'", false);
        assert!(matches!(
            p.base_recommendation,
            AdmitRecommendation::Offload | AdmitRecommendation::Local
        ));
    }

    #[test]
    fn compound_shell_form_is_split_and_unioned() {
        let p = preflight("cargo build && bun test", false);
        assert!(
            p.compound.len() >= 2,
            "compound must be split: {:?}",
            p.compound
        );
        // It is compilation if either part is, and capabilities union.
        if p.is_compilation {
            assert!(p.required.needs_cargo || p.required.needs_bun);
        }
    }

    #[test]
    fn refine_offload_when_some_candidate_admissible() {
        // 1 of 3 rejected => others admissible => Offload.
        let summary = aggregate_rejections(
            3,
            &[CandidateRejection {
                worker_id: "a".into(),
                category: AdmissionRejectionCategory::InsufficientSlots,
            }],
        );
        assert_eq!(
            refine_recommendation(AdmitRecommendation::Offload, &summary),
            AdmitRecommendation::Offload
        );
    }

    #[test]
    fn refine_queue_when_all_rejected_for_health() {
        // All rejected, dominated by worker-health (busy/unhealthy) => Queue.
        let summary = aggregate_rejections(
            2,
            &[
                CandidateRejection {
                    worker_id: "a".into(),
                    category: AdmissionRejectionCategory::InsufficientSlots,
                },
                CandidateRejection {
                    worker_id: "b".into(),
                    category: AdmissionRejectionCategory::CircuitOpen,
                },
            ],
        );
        assert_eq!(
            refine_recommendation(AdmitRecommendation::Offload, &summary),
            AdmitRecommendation::Queue
        );
    }

    #[test]
    fn refine_defer_when_all_rejected_for_capability() {
        // All rejected for command-specific capability => no worker can ever run
        // it => Defer (waiting on a slot is pointless).
        let summary = aggregate_rejections(
            2,
            &[
                CandidateRejection {
                    worker_id: "a".into(),
                    category: AdmissionRejectionCategory::MissingRustTarget,
                },
                CandidateRejection {
                    worker_id: "b".into(),
                    category: AdmissionRejectionCategory::OsArchMismatch,
                },
            ],
        );
        assert_eq!(
            refine_recommendation(AdmitRecommendation::Offload, &summary),
            AdmitRecommendation::Defer
        );
    }

    #[test]
    fn refine_keeps_local_recommendation() {
        let summary = aggregate_rejections(0, &[]);
        assert_eq!(
            refine_recommendation(AdmitRecommendation::Local, &summary),
            AdmitRecommendation::Local
        );
    }

    #[test]
    fn required_capabilities_convert_to_requirement() {
        let p = preflight("cargo build --target wasm32-unknown-unknown", false);
        let req = p.required.to_requirement(3);
        assert!(req.needs_cargo);
        assert_eq!(req.min_protocol, 3);
        assert_eq!(
            req.needs_targets,
            vec!["wasm32-unknown-unknown".to_string()]
        );
    }

    #[test]
    fn preflight_serializes_with_stable_tokens() {
        let p = preflight("cargo build", false);
        let value = serde_json::to_value(&p).unwrap();
        assert_eq!(value["base_recommendation"], "offload");
        assert_eq!(value["is_compilation"], true);
        let back: AdmitPreflight = serde_json::from_value(value).unwrap();
        assert_eq!(back, p);
    }
}
