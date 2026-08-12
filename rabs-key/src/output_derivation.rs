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

use crate::invocation::NormalizedRustcInvocation;
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
}
