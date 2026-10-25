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

/// Digest domain for the linker implicit search closure (`L011`, risk `R123`).
pub const DOMAIN_LINKER_IMPLICIT_CLOSURE: &str = "rabs.linker-implicit-closure.v1";

/// One resolved `-l<name>` or framework search hit (`L011`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLinkerSearchItem {
    /// Requested logical name (`"-lz"`, `"framework:CoreFoundation"`).
    pub requested_name: String,
    /// Selected canonical virtual path inside the closed view.
    pub selected_virtual_path: String,
    /// Content identity of the selected library/framework/object.
    pub object: ObjectId,
    /// Earlier `-L` / framework / sysroot search directories probed and found NOT
    /// containing a matching candidate before `selected_virtual_path` won.
    pub earlier_missed_paths: Vec<String>,
}

/// Discovered implicit linker search closure (`L011`, risk `R123`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkerImplicitSearchClosure {
    /// Ordered `-l` / framework resolutions in link order.
    pub resolved_libraries: Vec<ResolvedLinkerSearchItem>,
    /// Ordered CRT / startup objects (`crt1.o`, `crti.o`, `crtbegin.o`, `crtend.o`, `crtn.o`).
    pub crt_startup_objects: Vec<(String, ObjectId)>,
    /// Default or implicit linker scripts read (e.g. GNU `libc.so` linker script + `GROUP` members).
    pub implicit_linker_scripts: Vec<(String, TypedDigest)>,
    /// Linker plugins loaded (`-plugin` / `liblto_plugin.so`).
    pub linker_plugins: Vec<(String, ObjectId)>,
    /// Included `@response` files by content digest.
    pub response_files: Vec<(String, TypedDigest)>,
    /// Search directories from `-L`, `LIBRARY_PATH`, `rustc-link-search`, or built-in linker defaults.
    pub search_directories: Vec<String>,
}

/// Shareability and enforcement decision for a link action's implicit search closure (`L011`, `R123`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkerClosureShareability {
    /// All search paths and observed linker reads lie strictly inside the closed
    /// RABS view; returns the positive closure digest and negative-lookup digest.
    ShareableClosedView {
        /// Digest of all selected libraries, CRT objects, scripts, plugins, and response files.
        closure_digest: TypedDigest,
        /// Digest of the [`rabs_protocol::input_evidence::NegativeDependencySet`] for missed earlier search candidates.
        negative_dependencies_digest: TypedDigest,
    },
    /// Linker search path includes an uncontrolled host system directory outside
    /// the closed RABS view (`R122`/`R123`); link must stay local/nonshareable.
    LocalOnlyUncontrolledSearchPath {
        /// Offending search directories outside the closed view.
        uncontrolled_paths: Vec<String>,
    },
    /// Linker read a file not declared in its closure during closed-view execution (`E021`/`L011`).
    AbortUndeclaredLinkerRead {
        /// The undeclared path read by the linker.
        path: String,
    },
}

impl LinkerImplicitSearchClosure {
    /// Construct the [`rabs_protocol::input_evidence::NegativeDependencySet`]
    /// recording all failed earlier candidate paths probed before each selected library (`L011`).
    #[must_use]
    pub fn to_negative_dependency_set(
        &self,
    ) -> rabs_protocol::input_evidence::NegativeDependencySet {
        use rabs_protocol::input_evidence::{
            INPUT_EVIDENCE_SCHEMA_VERSION, NegativeDependency, NegativeDependencySet,
        };
        use rabs_protocol::raw_bytes::RawBytes;

        let mut entries = Vec::new();
        for item in &self.resolved_libraries {
            for missed in &item.earlier_missed_paths {
                entries.push(NegativeDependency::FailedOpen {
                    virtual_path: RawBytes::new(missed.as_bytes().to_vec()),
                });
            }
        }
        NegativeDependencySet {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            entries,
        }
    }

    /// Canonical digest of the positive implicit linker closure (`L011`).
    #[must_use]
    pub fn closure_digest(&self) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        enc.seq(&self.resolved_libraries, |enc, item| {
            enc.str(&item.requested_name)
                .str(&item.selected_virtual_path)
                .str(item.object.0.domain)
                .bytes(&item.object.0.bytes);
        });
        enc.seq(&self.crt_startup_objects, |enc, (path, obj)| {
            enc.str(path).str(obj.0.domain).bytes(&obj.0.bytes);
        });
        enc.seq(&self.implicit_linker_scripts, |enc, (path, dig)| {
            enc.str(path).str(dig.domain).bytes(&dig.bytes);
        });
        enc.seq(&self.linker_plugins, |enc, (path, obj)| {
            enc.str(path).str(obj.0.domain).bytes(&obj.0.bytes);
        });
        enc.seq(&self.response_files, |enc, (path, dig)| {
            enc.str(path).str(dig.domain).bytes(&dig.bytes);
        });
        compute(DOMAIN_LINKER_IMPLICIT_CLOSURE, &enc.finish())
    }
}

fn path_within_allowed_prefixes(path: &str, allowed_prefixes: &[&str]) -> bool {
    if path.split('/').any(|seg| seg == "..") {
        return false;
    }
    allowed_prefixes
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

/// Evaluate and enforce a [`LinkerImplicitSearchClosure`] under the closed linker
/// filesystem view (`L011`, risks `R122`/`R123`).
#[must_use]
pub fn evaluate_linker_implicit_closure(
    closure: &LinkerImplicitSearchClosure,
    closed_view_allowed_prefixes: &[&str],
    observed_linker_reads: &[String],
) -> LinkerClosureShareability {
    let mut uncontrolled_paths = Vec::new();
    for dir in &closure.search_directories {
        if !path_within_allowed_prefixes(dir, closed_view_allowed_prefixes) {
            uncontrolled_paths.push(dir.clone());
        }
    }
    if !uncontrolled_paths.is_empty() {
        return LinkerClosureShareability::LocalOnlyUncontrolledSearchPath { uncontrolled_paths };
    }

    let mut declared_reads: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for item in &closure.resolved_libraries {
        declared_reads.insert(item.selected_virtual_path.as_str());
    }
    for (path, _) in &closure.crt_startup_objects {
        declared_reads.insert(path.as_str());
    }
    for (path, _) in &closure.implicit_linker_scripts {
        declared_reads.insert(path.as_str());
    }
    for (path, _) in &closure.linker_plugins {
        declared_reads.insert(path.as_str());
    }
    for (path, _) in &closure.response_files {
        declared_reads.insert(path.as_str());
    }

    for read in observed_linker_reads {
        if !path_within_allowed_prefixes(read, closed_view_allowed_prefixes)
            || !declared_reads.contains(read.as_str())
        {
            return LinkerClosureShareability::AbortUndeclaredLinkerRead { path: read.clone() };
        }
    }

    let negdeps = closure.to_negative_dependency_set();
    let negative_dependencies_digest =
        crate::action_key::negative_dependency_set_digest(&negdeps).expect("valid schema version");

    LinkerClosureShareability::ShareableClosedView {
        closure_digest: closure.closure_digest(),
        negative_dependencies_digest,
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

    #[test]
    fn t045_directive_path_closure_and_linker_implicit_search_differential_scenarios() {
        let allowed = &[
            "/__rabs/workspace",
            "/__rabs/out",
            "/__rabs/toolchain",
            "/__rabs/sysroot",
        ];

        let base_closure = LinkerImplicitSearchClosure {
            resolved_libraries: vec![ResolvedLinkerSearchItem {
                requested_name: "-lz".into(),
                selected_virtual_path: "/__rabs/sysroot/usr/lib/libz.a".into(),
                object: ObjectId(d("rabs.object.v1", 0x20)),
                earlier_missed_paths: vec![
                    "/__rabs/out/build-z/lib/libz.so".into(),
                    "/__rabs/out/build-z/lib/libz.a".into(),
                ],
            }],
            crt_startup_objects: vec![
                (
                    "/__rabs/sysroot/usr/lib/crt1.o".into(),
                    ObjectId(d("rabs.object.v1", 0x21)),
                ),
                (
                    "/__rabs/sysroot/usr/lib/crti.o".into(),
                    ObjectId(d("rabs.object.v1", 0x22)),
                ),
            ],
            implicit_linker_scripts: vec![(
                "/__rabs/sysroot/usr/lib/libc.so".into(),
                d("rabs.linker-script.v1", 0x23),
            )],
            linker_plugins: vec![(
                "/__rabs/toolchain/lib/liblto_plugin.so".into(),
                ObjectId(d("rabs.object.v1", 0x24)),
            )],
            response_files: vec![(
                "/__rabs/out/link.rsp".into(),
                d("rabs.response-file.v1", 0x25),
            )],
            search_directories: vec![
                "/__rabs/out/build-z/lib".into(),
                "/__rabs/sysroot/usr/lib".into(),
            ],
        };

        let observed_reads = vec![
            "/__rabs/sysroot/usr/lib/libz.a".to_string(),
            "/__rabs/sysroot/usr/lib/crt1.o".to_string(),
            "/__rabs/sysroot/usr/lib/crti.o".to_string(),
            "/__rabs/sysroot/usr/lib/libc.so".to_string(),
            "/__rabs/toolchain/lib/liblto_plugin.so".to_string(),
            "/__rabs/out/link.rsp".to_string(),
        ];

        let LinkerClosureShareability::ShareableClosedView {
            closure_digest: base_closure_digest,
            negative_dependencies_digest: base_neg_digest,
        } = evaluate_linker_implicit_closure(&base_closure, allowed, &observed_reads)
        else {
            panic!("expected ShareableClosedView");
        };

        // Differential 1 (R123): Mutating the selected system library content (`libz.a`) changes closure_digest.
        let mut mutated_syslib = base_closure.clone();
        mutated_syslib.resolved_libraries[0].object = ObjectId(d("rabs.object.v1", 0x99));
        let LinkerClosureShareability::ShareableClosedView {
            closure_digest: syslib_digest,
            ..
        } = evaluate_linker_implicit_closure(&mutated_syslib, allowed, &observed_reads)
        else {
            panic!("expected ShareableClosedView");
        };
        assert_ne!(syslib_digest, base_closure_digest);

        // Differential 2 (R123): Earlier `-L` directory (`/__rabs/out/build-z/lib`) gains a shadowing `libz.a`:
        // negative_dependencies_digest and closure_digest both change!
        let mut shadowed = base_closure.clone();
        shadowed.resolved_libraries[0].selected_virtual_path =
            "/__rabs/out/build-z/lib/libz.a".into();
        shadowed.resolved_libraries[0].object = ObjectId(d("rabs.object.v1", 0x77));
        shadowed.resolved_libraries[0].earlier_missed_paths =
            vec!["/__rabs/out/build-z/lib/libz.so".into()];
        let shadowed_reads = vec![
            "/__rabs/out/build-z/lib/libz.a".to_string(),
            "/__rabs/sysroot/usr/lib/crt1.o".to_string(),
            "/__rabs/sysroot/usr/lib/crti.o".to_string(),
            "/__rabs/sysroot/usr/lib/libc.so".to_string(),
            "/__rabs/toolchain/lib/liblto_plugin.so".to_string(),
            "/__rabs/out/link.rsp".to_string(),
        ];
        let LinkerClosureShareability::ShareableClosedView {
            closure_digest: shadowed_closure_digest,
            negative_dependencies_digest: shadowed_neg_digest,
        } = evaluate_linker_implicit_closure(&shadowed, allowed, &shadowed_reads)
        else {
            panic!("expected ShareableClosedView");
        };
        assert_ne!(shadowed_closure_digest, base_closure_digest);
        assert_ne!(shadowed_neg_digest, base_neg_digest);

        // Differential 3 (R122/N014/L011): `rustc-link-search` or linker default search path
        // resolving outside the closed view (`/usr/local/lib`) forces LocalOnlyUncontrolledSearchPath!
        let mut uncontrolled = base_closure.clone();
        uncontrolled
            .search_directories
            .push("/usr/local/lib".into());
        assert_eq!(
            evaluate_linker_implicit_closure(&uncontrolled, allowed, &observed_reads),
            LinkerClosureShareability::LocalOnlyUncontrolledSearchPath {
                uncontrolled_paths: vec!["/usr/local/lib".into()],
            }
        );

        // Differential 4 (E021/L011): Undeclared linker read during closed-view execution aborts!
        let mut escaping_reads = observed_reads.clone();
        escaping_reads.push("/__rabs/sysroot/usr/lib/libundeclared.a".into());
        assert_eq!(
            evaluate_linker_implicit_closure(&base_closure, allowed, &escaping_reads),
            LinkerClosureShareability::AbortUndeclaredLinkerRead {
                path: "/__rabs/sysroot/usr/lib/libundeclared.a".into(),
            }
        );
    }
}
