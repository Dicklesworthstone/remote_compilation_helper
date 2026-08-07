//! Exact link invocation parser/key (bead L001; plan §97; risks
//! R11/R84; the F003 sibling for the link step).
//!
//! Link actions key on EXACTLY what the linker consumes:
//!
//! - the linker's content identity (F007-style, never a path
//!   spelling) plus its driver style — a cc-driver invocation
//!   (`cc -o out a.o -lz`) and a direct-linker invocation
//!   (`ld.lld -o out a.o -lz`) are parsed to one normalized model;
//! - ORDERED object/archive/shared-library inputs by content identity
//!   (link order is semantics — F009's rule applied at parse level);
//! - linker scripts (`-T script`) and `@response` files by CONTENT
//!   (the F005 machinery), never by filename;
//! - flags in normalized order; output class from the flag shape
//!   (shared/pie/static/relocatable/executable);
//! - environment, target/platform, and sysroot/runtime objects enter
//!   via the F006/F008/F007 slots — this parser fills the invocation
//!   and inputs slots.

use rabs_protocol::result_identity::{ObjectId, TypedDigest};

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the link invocation.
pub const DOMAIN_LINK_INVOCATION: &str = "rabs.link-invocation.v1";

/// The driver style the argv arrived in (normalized away — both
/// styles produce one model; the style rides for diagnostics only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum DriverStyle {
    CcDriver,
    DirectLinker,
}

/// Output class from the flag shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum LinkOutputClass {
    Executable,
    SharedLibrary,
    PieExecutable,
    StaticArchive,
    Relocatable,
}

/// One ordered link input, content-identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkInput {
    /// An object/archive/dylib file's content identity.
    File(ObjectId),
    /// A named library resolved later (`-lz`): keys by the request;
    /// the RESOLVED artifact enters via F009 dependency inputs.
    NamedLibrary(String),
    /// A linker script by CONTENT digest (never filename).
    LinkerScript(TypedDigest),
}

/// The normalized link invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedLinkInvocation {
    /// Driver style (diagnostic; not keyed).
    pub style: DriverStyle,
    /// Linker content identity (from the F007 toolchain contract).
    pub linker_identity: TypedDigest,
    /// Output class.
    pub output_class: LinkOutputClass,
    /// Ordered inputs.
    pub inputs: Vec<LinkInput>,
    /// Normalized semantic flags in order.
    pub flags: Vec<String>,
}

/// Parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkParseError {
    /// A file input could not be content-identified.
    UnidentifiableInput(String),
    /// A linker script could not be read/identified.
    UnidentifiableScript(String),
}

/// Flags that are output-path/diagnostic plumbing, not link semantics.
fn is_plumbing(flag: &str) -> bool {
    flag == "-o" || flag.starts_with("--error-limit") || flag == "-v" || flag == "--version"
}

/// Parse a link argv (either driver style) with content lookups.
///
/// # Errors
/// [`LinkParseError`] on any unidentifiable file/script.
pub fn parse_link(
    style: DriverStyle,
    linker_identity: TypedDigest,
    argv: &[String],
    identify_file: impl Fn(&str) -> Option<ObjectId>,
    identify_script: impl Fn(&str) -> Option<TypedDigest>,
) -> Result<NormalizedLinkInvocation, LinkParseError> {
    let mut inputs = Vec::new();
    let mut flags = Vec::new();
    let mut output_class = LinkOutputClass::Executable;
    let mut iter = argv.iter().peekable();
    while let Some(arg) = iter.next() {
        let a = arg.as_str();
        match a {
            "-shared" => {
                output_class = LinkOutputClass::SharedLibrary;
                flags.push(a.to_owned());
            }
            "-pie" => {
                output_class = LinkOutputClass::PieExecutable;
                flags.push(a.to_owned());
            }
            "-r" | "--relocatable" => {
                output_class = LinkOutputClass::Relocatable;
                flags.push(a.to_owned());
            }
            "-static" => {
                output_class = LinkOutputClass::StaticArchive;
                flags.push(a.to_owned());
            }
            "-o" => {
                let _ = iter.next(); // output path: placement, not key
            }
            "-T" => {
                let script = iter.next().map(String::as_str).unwrap_or("");
                let digest = identify_script(script)
                    .ok_or_else(|| LinkParseError::UnidentifiableScript(script.to_owned()))?;
                inputs.push(LinkInput::LinkerScript(digest));
            }
            _ if a.starts_with("-l") => {
                inputs.push(LinkInput::NamedLibrary(a[2..].to_owned()));
            }
            _ if a.starts_with('-') => {
                if !is_plumbing(a) {
                    flags.push(a.to_owned());
                }
            }
            _ => {
                let object = identify_file(a)
                    .ok_or_else(|| LinkParseError::UnidentifiableInput(a.to_owned()))?;
                inputs.push(LinkInput::File(object));
            }
        }
    }
    Ok(NormalizedLinkInvocation {
        style,
        linker_identity,
        output_class,
        inputs,
        flags,
    })
}

impl NormalizedLinkInvocation {
    /// The keyed digest (style excluded — one semantic model for both
    /// driver spellings).
    #[must_use]
    pub fn invocation_digest(&self) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        enc.str(self.linker_identity.domain)
            .bytes(&self.linker_identity.bytes);
        enc.u32(match self.output_class {
            LinkOutputClass::Executable => 1,
            LinkOutputClass::SharedLibrary => 2,
            LinkOutputClass::PieExecutable => 3,
            LinkOutputClass::StaticArchive => 4,
            LinkOutputClass::Relocatable => 5,
        });
        enc.u64(self.inputs.len() as u64);
        for input in &self.inputs {
            match input {
                LinkInput::File(object) => {
                    enc.u32(1).str(object.0.domain).bytes(&object.0.bytes);
                }
                LinkInput::NamedLibrary(name) => {
                    enc.u32(2).str(name);
                }
                LinkInput::LinkerScript(digest) => {
                    enc.u32(3).str(digest.domain).bytes(&digest.bytes);
                }
            }
        }
        enc.u64(self.flags.len() as u64);
        for flag in &self.flags {
            enc.str(flag);
        }
        compute(DOMAIN_LINK_INVOCATION, &enc.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn identify_file(path: &str) -> Option<ObjectId> {
        match path {
            "main.o" | "/w/main.o" => Some(ObjectId(d("rabs.object.v1", 1))),
            "libdep.rlib" => Some(ObjectId(d("rabs.object.v1", 2))),
            _ => None,
        }
    }

    fn identify_script(path: &str) -> Option<TypedDigest> {
        (path == "layout.ld").then(|| d("rabs.linker-script.v1", 3))
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn cc_driver_and_direct_linker_styles_key_identically() {
        // THE acceptance: the same semantic link through cc-driver and
        // direct-linker argv shapes (lld/Wild/system all reduce here).
        let via_cc = parse_link(
            DriverStyle::CcDriver,
            d("rabs.tool-binary.v1", 9),
            &args(&["-o", "app", "main.o", "libdep.rlib", "-lz", "--gc-sections"]),
            identify_file,
            identify_script,
        )
        .unwrap();
        let via_direct = parse_link(
            DriverStyle::DirectLinker,
            d("rabs.tool-binary.v1", 9),
            &args(&["main.o", "libdep.rlib", "-lz", "--gc-sections", "-o", "app"]),
            identify_file,
            identify_script,
        )
        .unwrap();
        assert_eq!(via_cc.invocation_digest(), via_direct.invocation_digest());
        // The output PATH is placement and never keys.
        let elsewhere = parse_link(
            DriverStyle::CcDriver,
            d("rabs.tool-binary.v1", 9),
            &args(&[
                "-o",
                "/tmp/other",
                "main.o",
                "libdep.rlib",
                "-lz",
                "--gc-sections",
            ]),
            identify_file,
            identify_script,
        )
        .unwrap();
        assert_eq!(via_cc.invocation_digest(), elsewhere.invocation_digest());
    }

    #[test]
    fn link_order_and_output_class_are_semantics() {
        let forward = parse_link(
            DriverStyle::DirectLinker,
            d("rabs.tool-binary.v1", 9),
            &args(&["main.o", "libdep.rlib"]),
            identify_file,
            identify_script,
        )
        .unwrap();
        let reversed = parse_link(
            DriverStyle::DirectLinker,
            d("rabs.tool-binary.v1", 9),
            &args(&["libdep.rlib", "main.o"]),
            identify_file,
            identify_script,
        )
        .unwrap();
        assert_ne!(forward.invocation_digest(), reversed.invocation_digest());
        // -shared flips the output class AND the key.
        let shared = parse_link(
            DriverStyle::DirectLinker,
            d("rabs.tool-binary.v1", 9),
            &args(&["-shared", "main.o", "libdep.rlib"]),
            identify_file,
            identify_script,
        )
        .unwrap();
        assert_eq!(shared.output_class, LinkOutputClass::SharedLibrary);
        assert_ne!(forward.invocation_digest(), shared.invocation_digest());
    }

    #[test]
    fn linker_scripts_key_by_content_and_missing_inputs_are_hard_errors() {
        let scripted = parse_link(
            DriverStyle::DirectLinker,
            d("rabs.tool-binary.v1", 9),
            &args(&["-T", "layout.ld", "main.o"]),
            identify_file,
            identify_script,
        )
        .unwrap();
        assert!(matches!(scripted.inputs[0], LinkInput::LinkerScript(_)));
        // An unidentifiable object/script is a typed hard error.
        assert_eq!(
            parse_link(
                DriverStyle::DirectLinker,
                d("rabs.tool-binary.v1", 9),
                &args(&["ghost.o"]),
                identify_file,
                identify_script,
            ),
            Err(LinkParseError::UnidentifiableInput("ghost.o".into()))
        );
        assert_eq!(
            parse_link(
                DriverStyle::DirectLinker,
                d("rabs.tool-binary.v1", 9),
                &args(&["-T", "ghost.ld"]),
                identify_file,
                identify_script,
            ),
            Err(LinkParseError::UnidentifiableScript("ghost.ld".into()))
        );
    }

    #[test]
    fn linker_identity_keys_and_path_spelling_of_inputs_does_not() {
        let lld = parse_link(
            DriverStyle::DirectLinker,
            d("rabs.tool-binary.v1", 9),
            &args(&["main.o"]),
            identify_file,
            identify_script,
        )
        .unwrap();
        let wild = parse_link(
            DriverStyle::DirectLinker,
            d("rabs.tool-binary.v1", 10), // a different linker binary
            &args(&["main.o"]),
            identify_file,
            identify_script,
        )
        .unwrap();
        assert_ne!(lld.invocation_digest(), wild.invocation_digest());
        // Input path spelling never keys — content identity does.
        let spelled = parse_link(
            DriverStyle::DirectLinker,
            d("rabs.tool-binary.v1", 9),
            &args(&["/w/main.o"]), // same content, different spelling
            identify_file,
            identify_script,
        )
        .unwrap();
        assert_eq!(lld.invocation_digest(), spelled.invocation_digest());
    }
}
