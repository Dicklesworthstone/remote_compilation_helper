//! Derive the DECLARED output set of a rustc invocation (the missing
//! producer for F011's [`OutputDeclarationSet`]).
//!
//! [`crate::output_declarations`] defines what an action is expected to
//! produce and digests it into the action key, but nothing built one
//! from an actual invocation — so no component could answer "what files
//! will this compile produce?". Everything downstream needs that answer:
//! a worker must know what to harvest, the coordinator must know what a
//! manifest should contain, and a wrapper can only skip a compile if it
//! knows every file the compile would have produced.
//!
//! That last one is why this module is fail-closed everywhere. A missed
//! output means a rebuild; a WRONG output name means a build that
//! silently lacks a file it was promised. So: no defaulting a missing
//! `--crate-type`, no guessing at an unknown emit kind, no inventing
//! naming for a target family we have not encoded, and no accepting
//! `--emit=kind=path` (an explicit destination changes placement
//! semantics, which this declaration type deliberately cannot express).
//! Every one of those is a typed refusal, and a caller that gets one
//! must fall back to compiling.
//!
//! Paths here are FILENAMES, relative to the invocation's output
//! directory — never absolute. That is not a simplification: an output
//! declaration is keyed, and "where the bytes are staged" must stay
//! unrepresentable in it (F011). The directory is the caller's to supply
//! when it materializes.
//!
//! The naming rules are verified by conformance test against real rustc:
//! `tests/output_derivation_conformance.rs` runs each invocation shape
//! for real and compares the produced file set to the derived one.

use crate::invocation::{NormalizedRustcInvocation, SourceInput};
use crate::output_declarations::{OutputClass, OutputDeclaration, OutputDeclarationSet};

/// Why an invocation's outputs could not be derived. Each one means
/// "compile it; do not pretend to know what it produces".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationRefusal {
    /// No `--crate-name`.
    NoCrateName,
    /// Link output requested with no `--crate-type`. rustc has a default
    /// here; we do not guess it, because the default differs by rustc
    /// version and driver.
    NoCrateType,
    /// A `--crate-type` this module has no naming rule for.
    UnknownCrateType(String),
    /// An `--emit` kind this module has no naming rule for.
    UnknownEmitKind(String),
    /// `--emit=kind=path`: an explicit destination, which a keyed
    /// declaration cannot express.
    ExplicitEmitPath(String),
    /// A target triple whose file-naming family is not encoded here.
    UnknownTargetFamily(String),
    /// The invocation is outside the first file-only dependency serving lane.
    UnsupportedDependencyInvocation(&'static str),
    /// An option may add outputs, redirect them, or suppress compilation.
    UnsupportedOutputOption(String),
    /// A generated name is not a bounded, portable single path component.
    UnsafeOutputName(String),
}

impl std::fmt::Display for DerivationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCrateName => write!(f, "no --crate-name"),
            Self::NoCrateType => write!(f, "link output with no --crate-type"),
            Self::UnknownCrateType(t) => write!(f, "unknown --crate-type {t:?}"),
            Self::UnknownEmitKind(e) => write!(f, "unknown --emit kind {e:?}"),
            Self::ExplicitEmitPath(e) => write!(f, "--emit with an explicit path: {e:?}"),
            Self::UnknownTargetFamily(t) => write!(f, "no naming rules for target {t:?}"),
            Self::UnsupportedDependencyInvocation(reason) => write!(f, "{reason}"),
            Self::UnsupportedOutputOption(option) => {
                write!(f, "output effects are not modeled for {option:?}")
            }
            Self::UnsafeOutputName(name) => write!(f, "unsafe output filename {name:?}"),
        }
    }
}

/// Platform file-naming rules for linked artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetNaming {
    /// Prefix for dynamic libraries (`lib` on unix, empty on windows).
    pub dll_prefix: &'static str,
    /// Suffix for dynamic libraries.
    pub dll_suffix: &'static str,
    /// Suffix for executables.
    pub exe_suffix: &'static str,
    /// Prefix for static libraries.
    pub staticlib_prefix: &'static str,
    /// Suffix for static libraries.
    pub staticlib_suffix: &'static str,
}

/// Naming rules for a target triple, or `None` for a family this module
/// does not encode (wasm, uefi, bare-metal…). Unknown means REFUSE, not
/// "assume unix".
#[must_use]
pub fn naming_for(target: &str) -> Option<TargetNaming> {
    if target.contains("-apple-") || target.ends_with("darwin") {
        return Some(TargetNaming {
            dll_prefix: "lib",
            dll_suffix: ".dylib",
            exe_suffix: "",
            staticlib_prefix: "lib",
            staticlib_suffix: ".a",
        });
    }
    if target.contains("windows-msvc") {
        return Some(TargetNaming {
            dll_prefix: "",
            dll_suffix: ".dll",
            exe_suffix: ".exe",
            staticlib_prefix: "",
            staticlib_suffix: ".lib",
        });
    }
    if target.contains("windows-gnu") {
        return Some(TargetNaming {
            dll_prefix: "",
            dll_suffix: ".dll",
            exe_suffix: ".exe",
            staticlib_prefix: "lib",
            staticlib_suffix: ".a",
        });
    }
    // ELF unixes: linux (gnu/musl), the BSDs, illumos, redox.
    if target.contains("-linux-")
        || target.contains("-freebsd")
        || target.contains("-netbsd")
        || target.contains("-openbsd")
        || target.contains("-dragonfly")
        || target.contains("-illumos")
        || target.contains("-solaris")
        || target.contains("-redox")
    {
        return Some(TargetNaming {
            dll_prefix: "lib",
            dll_suffix: ".so",
            exe_suffix: "",
            staticlib_prefix: "lib",
            staticlib_suffix: ".a",
        });
    }
    None
}

/// The `-C extra-filename=` value, or empty.
fn extra_filename(invocation: &NormalizedRustcInvocation) -> &str {
    invocation
        .codegen
        .iter()
        .rev() // last wins, as rustc does
        .find(|(name, _)| name == "extra-filename")
        .and_then(|(_, value)| value.as_deref())
        .unwrap_or("")
}

/// The emit kinds, defaulting to `link` when `--emit` is absent (rustc's
/// own default). An `--emit=kind=path` form refuses.
fn emit_kinds(invocation: &NormalizedRustcInvocation) -> Result<Vec<String>, DerivationRefusal> {
    if invocation.emit.is_empty() {
        return Ok(vec!["link".to_owned()]);
    }
    let mut kinds = Vec::with_capacity(invocation.emit.len());
    for entry in &invocation.emit {
        if entry.contains('=') {
            return Err(DerivationRefusal::ExplicitEmitPath(entry.clone()));
        }
        kinds.push(entry.clone());
    }
    Ok(kinds)
}

/// The filename(s) one crate type produces when linked.
fn link_filename(
    crate_type: &str,
    stem: &str,
    naming: TargetNaming,
) -> Result<(String, OutputClass), DerivationRefusal> {
    match crate_type {
        // `lib` is rustc's "whatever the default library format is",
        // which for every target this module encodes is rlib.
        "lib" | "rlib" => Ok((format!("lib{stem}.rlib"), OutputClass::File)),
        "dylib" | "cdylib" | "proc-macro" => Ok((
            format!("{}{stem}{}", naming.dll_prefix, naming.dll_suffix),
            OutputClass::File,
        )),
        "staticlib" => Ok((
            format!(
                "{}{stem}{}",
                naming.staticlib_prefix, naming.staticlib_suffix
            ),
            OutputClass::File,
        )),
        "bin" => Ok((
            format!("{stem}{}", naming.exe_suffix),
            OutputClass::Executable,
        )),
        other => Err(DerivationRefusal::UnknownCrateType(other.to_owned())),
    }
}

/// Derive every file `invocation` is expected to produce, as filenames
/// relative to its output directory.
///
/// `host_target` is used when the invocation carries no `--target`.
///
/// # Errors
/// A typed [`DerivationRefusal`]. A caller that receives one has learned
/// "I do not know what this produces" — which must mean "compile it",
/// never "produce nothing".
pub fn derive_output_declarations(
    invocation: &NormalizedRustcInvocation,
    host_target: &str,
) -> Result<OutputDeclarationSet, DerivationRefusal> {
    let crate_name = invocation
        .crate_name
        .as_deref()
        .ok_or(DerivationRefusal::NoCrateName)?;
    let target = invocation.target.as_deref().unwrap_or(host_target);
    let naming = naming_for(target)
        .ok_or_else(|| DerivationRefusal::UnknownTargetFamily(target.to_owned()))?;
    let stem = format!("{crate_name}{}", extra_filename(invocation));

    let mut declarations: Vec<OutputDeclaration> = Vec::new();
    let mut push = |virtual_path: String, class: OutputClass| {
        if !declarations
            .iter()
            .any(|d: &OutputDeclaration| d.virtual_path == virtual_path)
        {
            declarations.push(OutputDeclaration {
                virtual_path,
                class,
                optional: false,
            });
        }
    };

    for kind in emit_kinds(invocation)? {
        match kind.as_str() {
            "link" => {
                if invocation.crate_types.is_empty() {
                    return Err(DerivationRefusal::NoCrateType);
                }
                for crate_type in &invocation.crate_types {
                    let (name, class) = link_filename(crate_type, &stem, naming)?;
                    push(name, class);
                }
            }
            "metadata" => push(format!("lib{stem}.rmeta"), OutputClass::ProvisionalMetadata),
            "dep-info" => push(format!("{stem}.d"), OutputClass::DepInfo),
            "obj" => push(format!("{stem}.o"), OutputClass::File),
            "asm" => push(format!("{stem}.s"), OutputClass::File),
            "llvm-ir" => push(format!("{stem}.ll"), OutputClass::File),
            "llvm-bc" => push(format!("{stem}.bc"), OutputClass::File),
            "mir" => push(format!("{stem}.mir"), OutputClass::File),
            other => return Err(DerivationRefusal::UnknownEmitKind(other.to_owned())),
        }
    }
    Ok(OutputDeclarationSet { declarations })
}

/// Derive the complete file set for the first Cargo dependency serving lane
/// (bd-14t4j), rather than treating a naming table as an output-closure proof.
///
/// Supported here: ordinary Linux `lib`/`rlib` invocations producing link,
/// metadata and/or dep-info files. Unknown flags are safe to retain in a key,
/// but NOT safe to ignore when predicting the complete set of writes. In
/// particular `--test`, `-o`, response files, incremental state, save-temps,
/// split-debug sidecars and unmodeled unstable output modes cannot use this
/// adapter. Cargo's `-Z embed-metadata=no` is modeled only with explicit
/// separate metadata emission, so the required `.rmeta` remains declared.
/// The general naming helper remains available for non-serving consumers.
///
/// This derives outputs only. It does not establish immutable inputs, validate
/// successful execution, bind a toolchain identity, or authorize compiler skip
/// or local fallback after delivery. Those remain separate serving gates.
pub fn derive_dependency_output_declarations(
    invocation: &NormalizedRustcInvocation,
    host_target: &str,
) -> Result<OutputDeclarationSet, DerivationRefusal> {
    let unsupported = DerivationRefusal::UnsupportedDependencyInvocation;
    let compiler = invocation.compiler_argv0.rsplit(['/', '\\']).next();
    if !matches!(compiler, Some("rustc" | "rustc.exe"))
        || !invocation.wrapper_chain.is_empty()
        || !invocation.stripped_wrapper_flags.is_empty()
    {
        return Err(unsupported(
            "dependency outputs require an unwrapped rustc invocation",
        ));
    }
    if !matches!(&invocation.source, Some(SourceInput::Path(path)) if !path.starts_with('@')) {
        return Err(unsupported(
            "dependency outputs require an explicit source file",
        ));
    }
    if invocation.out_dir.as_deref().is_none_or(str::is_empty) {
        return Err(unsupported("dependency outputs require --out-dir"));
    }
    if invocation.crate_types.is_empty()
        || invocation
            .crate_types
            .iter()
            .any(|kind| !matches!(kind.as_str(), "lib" | "rlib"))
    {
        return Err(unsupported(
            "dependency outputs require --crate-type lib or rlib",
        ));
    }
    let target = invocation.target.as_deref().unwrap_or(host_target);
    if !matches!(
        target,
        "x86_64-unknown-linux-gnu"
            | "x86_64-unknown-linux-musl"
            | "aarch64-unknown-linux-gnu"
            | "aarch64-unknown-linux-musl"
    ) {
        return Err(DerivationRefusal::UnknownTargetFamily(target.to_owned()));
    }
    let name = invocation
        .crate_name
        .as_deref()
        .ok_or(DerivationRefusal::NoCrateName)?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(DerivationRefusal::UnsafeOutputName(name.to_owned()));
    }
    for kind in emit_kinds(invocation)? {
        if !matches!(kind.as_str(), "link" | "metadata" | "dep-info") {
            return Err(DerivationRefusal::UnsupportedOutputOption(format!(
                "--emit={kind}"
            )));
        }
    }
    check_dependency_output_options(invocation)?;
    let declarations = derive_output_declarations(invocation, host_target)?;
    for output in &declarations.declarations {
        let name = &output.virtual_path;
        if name.len() > 255
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(DerivationRefusal::UnsafeOutputName(name.clone()));
        }
    }
    Ok(declarations)
}

fn check_dependency_output_options(
    invocation: &NormalizedRustcInvocation,
) -> Result<(), DerivationRefusal> {
    for (name, value) in &invocation.unstable {
        // Current Cargo can omit metadata from the rlib while requesting
        // a separate rmeta. This changes artifact bytes, already bound by
        // the normalized invocation, but not the declared file set. Never
        // admit this mode without the explicit metadata output, and do not
        // infer output neutrality for any other unstable control.
        if name != "embed-metadata"
            || value.as_deref() != Some("no")
            || !invocation.emit.iter().any(|kind| kind == "metadata")
        {
            return Err(DerivationRefusal::UnsupportedOutputOption(format!(
                "-Z {name}"
            )));
        }
    }
    for (name, value) in &invocation.codegen {
        // This is an allowlist of output-neutral controls for an rlib, not a
        // denylist that would silently admit a future rustc output option.
        let modeled = matches!(
            name.as_str(),
            "opt-level"
                | "debuginfo"
                | "debug-assertions"
                | "overflow-checks"
                | "panic"
                | "metadata"
                | "extra-filename"
                | "embed-bitcode"
                | "codegen-units"
                | "strip"
                | "target-cpu"
                | "target-feature"
                | "relocation-model"
                | "code-model"
                | "force-frame-pointers"
                | "force-unwind-tables"
                | "lto"
        ) || (name == "split-debuginfo" && value.as_deref() == Some("off"));
        if !modeled {
            return Err(DerivationRefusal::UnsupportedOutputOption(format!(
                "-C {name}"
            )));
        }
    }
    let mut passthrough = invocation.passthrough.iter();
    while let Some(arg) = passthrough.next() {
        let (name, inline) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(name, value)| (name, Some(value)));
        if !matches!(
            name,
            "--error-format" | "--json" | "--check-cfg" | "--remap-path-prefix" | "--sysroot"
        ) || inline
            .or_else(|| passthrough.next().map(String::as_str))
            .is_none_or(str::is_empty)
        {
            return Err(DerivationRefusal::UnsupportedOutputOption(arg.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invocation::parse;

    fn invocation(args: &[&str]) -> NormalizedRustcInvocation {
        let argv: Vec<String> = std::iter::once("rustc".to_owned())
            .chain(args.iter().map(|a| (*a).to_owned()))
            .collect();
        parse(&argv, None).expect("parse")
    }

    fn names(set: &OutputDeclarationSet) -> Vec<String> {
        let mut out: Vec<String> = set
            .declarations
            .iter()
            .map(|d| d.virtual_path.clone())
            .collect();
        out.sort();
        out
    }

    #[test]
    fn an_rlib_with_metadata_and_dep_info() {
        let inv = invocation(&[
            "--crate-name",
            "foo",
            "--crate-type",
            "rlib",
            "--emit=link,metadata,dep-info",
            "-C",
            "extra-filename=-abc123",
            "src/lib.rs",
        ]);
        let set = derive_output_declarations(&inv, "x86_64-unknown-linux-gnu").expect("derive");
        assert_eq!(
            names(&set),
            vec!["foo-abc123.d", "libfoo-abc123.rlib", "libfoo-abc123.rmeta"]
        );
    }

    #[test]
    fn naming_follows_the_target_not_the_host() {
        let inv = invocation(&[
            "--crate-name",
            "foo",
            "--crate-type",
            "cdylib",
            "--target",
            "x86_64-pc-windows-msvc",
            "src/lib.rs",
        ]);
        let set = derive_output_declarations(&inv, "aarch64-apple-darwin").expect("derive");
        assert_eq!(names(&set), vec!["foo.dll"]);

        let inv = invocation(&[
            "--crate-name",
            "foo",
            "--crate-type",
            "cdylib",
            "src/lib.rs",
        ]);
        assert_eq!(
            names(&derive_output_declarations(&inv, "aarch64-apple-darwin").expect("derive")),
            vec!["libfoo.dylib"]
        );
        assert_eq!(
            names(&derive_output_declarations(&inv, "x86_64-unknown-linux-gnu").expect("derive")),
            vec!["libfoo.so"]
        );
    }

    #[test]
    fn several_crate_types_declare_several_artifacts() {
        let inv = invocation(&[
            "--crate-name",
            "foo",
            "--crate-type",
            "bin",
            "--crate-type",
            "staticlib",
            "src/main.rs",
        ]);
        let set = derive_output_declarations(&inv, "x86_64-unknown-linux-gnu").expect("derive");
        assert_eq!(names(&set), vec!["foo", "libfoo.a"]);
        // The binary is an Executable, not a File — the class is part of
        // the declaration, not decoration.
        let bin = set
            .declarations
            .iter()
            .find(|d| d.virtual_path == "foo")
            .expect("bin declared");
        assert_eq!(bin.class, OutputClass::Executable);
    }

    #[test]
    fn a_metadata_only_check_build_declares_no_link_output() {
        // `cargo check`: no link, so no crate-type requirement either.
        let inv = invocation(&[
            "--crate-name",
            "foo",
            "--emit=metadata,dep-info",
            "-C",
            "extra-filename=-9f",
            "src/lib.rs",
        ]);
        let set = derive_output_declarations(&inv, "x86_64-unknown-linux-gnu").expect("derive");
        assert_eq!(names(&set), vec!["foo-9f.d", "libfoo-9f.rmeta"]);
    }

    #[test]
    fn everything_unknown_is_a_typed_refusal_never_a_guess() {
        let no_name = invocation(&["--crate-type", "rlib", "src/lib.rs"]);
        assert_eq!(
            derive_output_declarations(&no_name, "x86_64-unknown-linux-gnu"),
            Err(DerivationRefusal::NoCrateName)
        );

        // Link with no crate type: rustc has a default, we refuse to
        // guess which one this rustc uses.
        let no_type = invocation(&["--crate-name", "foo", "src/lib.rs"]);
        assert_eq!(
            derive_output_declarations(&no_type, "x86_64-unknown-linux-gnu"),
            Err(DerivationRefusal::NoCrateType)
        );

        let odd_type = invocation(&[
            "--crate-name",
            "foo",
            "--crate-type",
            "sharedobject",
            "src/lib.rs",
        ]);
        assert_eq!(
            derive_output_declarations(&odd_type, "x86_64-unknown-linux-gnu"),
            Err(DerivationRefusal::UnknownCrateType("sharedobject".into()))
        );

        let odd_emit = invocation(&["--crate-name", "foo", "--emit=thir-tree", "src/lib.rs"]);
        assert_eq!(
            derive_output_declarations(&odd_emit, "x86_64-unknown-linux-gnu"),
            Err(DerivationRefusal::UnknownEmitKind("thir-tree".into()))
        );

        let emit_path = invocation(&[
            "--crate-name",
            "foo",
            "--emit=dep-info=/tmp/out.d",
            "src/lib.rs",
        ]);
        assert_eq!(
            derive_output_declarations(&emit_path, "x86_64-unknown-linux-gnu"),
            Err(DerivationRefusal::ExplicitEmitPath(
                "dep-info=/tmp/out.d".into()
            ))
        );

        let odd_target = invocation(&[
            "--crate-name",
            "foo",
            "--crate-type",
            "cdylib",
            "--target",
            "wasm32-unknown-unknown",
            "src/lib.rs",
        ]);
        assert_eq!(
            derive_output_declarations(&odd_target, "x86_64-unknown-linux-gnu"),
            Err(DerivationRefusal::UnknownTargetFamily(
                "wasm32-unknown-unknown".into()
            ))
        );
    }

    #[test]
    fn the_derived_set_digests_as_a_declaration_set() {
        // The point of deriving: the result is keyable (F011).
        let inv = invocation(&[
            "--crate-name",
            "foo",
            "--crate-type",
            "rlib",
            "--emit=link,metadata",
            "src/lib.rs",
        ]);
        let set = derive_output_declarations(&inv, "x86_64-unknown-linux-gnu").expect("derive");
        let digest = set.declaration_digest().expect("digest");
        // A different emit set is a different action.
        let other = invocation(&[
            "--crate-name",
            "foo",
            "--crate-type",
            "rlib",
            "--emit=link",
            "src/lib.rs",
        ]);
        let other = derive_output_declarations(&other, "x86_64-unknown-linux-gnu")
            .expect("derive")
            .declaration_digest()
            .expect("digest");
        assert_ne!(digest, other);
    }

    fn dependency(extra: &[&str]) -> NormalizedRustcInvocation {
        let mut args = vec![
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--emit=dep-info,metadata,link",
            "--out-dir",
            "/work/target/debug/deps",
            "-C",
            "extra-filename=-123",
            "src/lib.rs",
        ];
        args.extend_from_slice(extra);
        invocation(&args)
    }

    #[test]
    fn dependency_serving_derives_cargo_build_and_check_outputs() {
        let mut inv = dependency(&[
            "--error-format=json",
            "--json=diagnostic-rendered-ansi,artifacts",
            "--check-cfg",
            "cfg(docsrs,test)",
            "--cap-lints",
            "allow",
            "-C",
            "debuginfo=2",
            "-C",
            "embed-bitcode=no",
        ]);
        let derive = |inv: &NormalizedRustcInvocation| {
            derive_dependency_output_declarations(inv, "x86_64-unknown-linux-gnu").unwrap()
        };
        assert_eq!(
            names(&derive(&inv)),
            vec!["foo-123.d", "libfoo-123.rlib", "libfoo-123.rmeta"]
        );
        inv.emit = vec!["dep-info".into(), "metadata".into()];
        assert_eq!(names(&derive(&inv)), vec!["foo-123.d", "libfoo-123.rmeta"]);
        inv.out_dir = Some("/another/worktree/target/debug/deps".into());
        assert_eq!(names(&derive(&inv)), vec!["foo-123.d", "libfoo-123.rmeta"]);
    }

    #[test]
    fn dependency_serving_models_only_separately_emitted_metadata() {
        for args in [vec!["-Z", "embed-metadata=no"], vec!["-Zembed-metadata=no"]] {
            let mut inv = dependency(&args);
            assert_eq!(
                names(
                    &derive_dependency_output_declarations(&inv, "x86_64-unknown-linux-gnu")
                        .unwrap()
                ),
                vec!["foo-123.d", "libfoo-123.rlib", "libfoo-123.rmeta"]
            );
            inv.emit = vec!["dep-info".into(), "metadata".into()];
            assert_eq!(
                names(
                    &derive_dependency_output_declarations(&inv, "x86_64-unknown-linux-gnu")
                        .unwrap()
                ),
                vec!["foo-123.d", "libfoo-123.rmeta"]
            );
            for emit in [vec![], vec!["link"], vec!["dep-info", "link"]] {
                inv.emit = emit.into_iter().map(str::to_owned).collect();
                assert!(
                    derive_dependency_output_declarations(&inv, "x86_64-unknown-linux-gnu")
                        .is_err(),
                    "embed-metadata=no requires an explicit metadata output"
                );
            }
        }
        for args in [
            vec!["-Z", "embed-metadata"],
            vec!["-Z", "embed-metadata=yes"],
            vec!["-Z", "embed-metadata=false"],
            vec!["-Z", "embed-metadata=unknown"],
            vec!["-Z", "embed-metadata=no", "-Z", "no-codegen"],
            vec!["-Z", "no-codegen", "-Z", "embed-metadata=no"],
            vec!["-Z", "embed-metadata=yes", "-Z", "embed-metadata=no"],
            vec!["-Z", "embed-metadata=no", "-Z", "embed-metadata=yes"],
        ] {
            assert!(
                derive_dependency_output_declarations(
                    &dependency(&args),
                    "x86_64-unknown-linux-gnu"
                )
                .is_err(),
                "unmodeled unstable options remain refused: {args:?}"
            );
        }
    }

    #[test]
    fn dependency_serving_refuses_unmodeled_writes_and_non_compiles() {
        for args in [
            vec!["--test"],
            vec!["-o", "/elsewhere/result"],
            vec!["-oelsewhere"],
            vec!["@args"],
            vec!["--print=file-names"],
            vec!["--help"],
            vec!["-C", "incremental=/elsewhere/state"],
            vec!["-C", "save-temps=yes"],
            vec!["-C", "split-debuginfo=unpacked"],
            vec!["-Z", "no-codegen"],
            vec!["-C", "future-output-option=yes"],
            vec!["--future-output-option"],
            vec!["--json"],
        ] {
            assert!(
                derive_dependency_output_declarations(
                    &dependency(&args),
                    "x86_64-unknown-linux-gnu"
                )
                .is_err(),
                "unmodeled output effects must refuse: {args:?}"
            );
        }
        for emit in ["obj", "asm", "llvm-ir", "link=elsewhere", "metadata=-"] {
            let mut inv = dependency(&[]);
            inv.emit = vec![emit.into()];
            assert!(
                derive_dependency_output_declarations(&inv, "x86_64-unknown-linux-gnu").is_err()
            );
        }
    }

    #[test]
    fn dependency_serving_requires_source_driver_directory_and_library_shape() {
        let base = dependency(&[]);
        let mut variants = Vec::new();
        let mut inv = base.clone();
        inv.source = None;
        variants.push(inv);
        let mut inv = base.clone();
        inv.out_dir = None;
        variants.push(inv);
        let mut inv = base.clone();
        inv.compiler_argv0 = "clippy-driver".into();
        variants.push(inv);
        let mut inv = base.clone();
        inv.wrapper_chain.push("sccache".into());
        variants.push(inv);
        let mut inv = base.clone();
        inv.crate_types = vec!["proc-macro".into()];
        variants.push(inv);
        let mut inv = base.clone();
        inv.crate_types.clear();
        variants.push(inv);
        let mut inv = base;
        inv.target = Some("/tmp/x86_64-unknown-linux-gnu.json".into());
        variants.push(inv);
        for inv in variants {
            assert!(
                derive_dependency_output_declarations(&inv, "x86_64-unknown-linux-gnu").is_err()
            );
        }
    }

    #[test]
    fn dependency_serving_never_derives_a_path_from_extra_filename() {
        for suffix in [
            "../../escape",
            "/absolute",
            "\\windows",
            "\0",
            "\n",
            " space",
        ] {
            let mut inv = dependency(&[]);
            inv.codegen
                .push(("extra-filename".into(), Some(suffix.into())));
            assert!(matches!(
                derive_dependency_output_declarations(&inv, "x86_64-unknown-linux-gnu"),
                Err(DerivationRefusal::UnsafeOutputName(_))
            ));
        }
        let mut inv = dependency(&[]);
        inv.codegen
            .push(("extra-filename".into(), Some("x".repeat(256))));
        assert!(matches!(
            derive_dependency_output_declarations(&inv, "x86_64-unknown-linux-gnu"),
            Err(DerivationRefusal::UnsafeOutputName(_))
        ));
    }
}
