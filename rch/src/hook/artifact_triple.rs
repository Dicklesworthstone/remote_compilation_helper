//! Host-vs-artifact executable typing for retrieved build outputs (GitHub #65).
//!
//! A worker is selected for capacity, not for platform: an unpinned `cargo
//! build` dispatched from a macOS/aarch64 caller can land on a Linux/x86_64
//! worker, compile cleanly, and rsync an ELF executable straight over the
//! caller's `target/<profile>/` tree. Existence and executable-bit checks stay
//! green, so the poisoned artifact is only discovered when something tries to
//! run it (`exec format error`) — possibly hours and several gates later.
//!
//! This module is the typing gate that closes that window. It is deliberately
//! **evidence-only**, mirroring the fail-open philosophy of the sibling
//! zero-output gate (`artifact_patterns::sync_back_verified_zero_build_outputs`):
//! it fires solely when a retrieved file's own leading bytes prove it is an
//! executable container or CPU architecture different from the requested target,
//! and declines whenever the evidence is partial (unrecognized triple, unreadable file,
//! unknown magic).
//!
//! # Scope: requested target outputs only
//!
//! When the command carries an explicit `--target <triple>`, cargo writes the
//! cross output under `target/<triple>/<profile>/` while *host* tooling —
//! build-script binaries and proc-macro dylibs — is still emitted under the
//! plain `target/<profile>/`. On a cross build that host is the WORKER's host,
//! so foreign-format files under `target/<profile>/` are expected and correct.
//! The gate therefore inspects:
//!
//! - pinned build (`--target T`): only `target/T/<profile>/…`, expecting `T`;
//! - unpinned build: only the plain `target/<profile>/…` (never a
//!   `target/<triple>/…` subtree), expecting the local host triple.
//!
//! Cargo cache trees (`build/`, `incremental/`, `.fingerprint/`) are skipped in
//! both shapes — they mirror the exclude set the retrieval patterns emit and
//! legitimately hold worker-host binaries.

use std::fs::File;
use std::io::Read;
use std::path::Path;

// File-format decoding stays separate from retrieval scope and failure policy.
#[path = "artifact_identity.rs"]
mod artifact_identity;

/// How many retrieved files the gate is willing to open. A `target/debug/deps`
/// tree can hold thousands of files; the mismatch this gate exists to catch is
/// a whole-directory property, so a bounded sample is sufficient evidence and
/// keeps the post-build path off the critical latency budget.
pub(super) const MAX_FILES_INSPECTED: usize = 256;

/// How many distinct mismatches to report before stopping. The message is for a
/// human; the first few paths already identify the tree.
pub(super) const MAX_FINDINGS_REPORTED: usize = 8;

/// Executable container formats identifiable from a file's leading bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BinaryFormat {
    /// Linux, Android, the BSDs, illumos, Fuchsia, Redox.
    Elf,
    /// macOS / iOS, thin or universal ("fat").
    MachO,
    /// Windows PE/COFF.
    Pe,
    /// WebAssembly module.
    Wasm,
}

impl BinaryFormat {
    /// Human label used in the operator-facing failure message.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::Pe => "PE",
            Self::Wasm => "WebAssembly",
        }
    }
}

/// Bytes of leading header the classifier needs.
const MAGIC_LEN: usize = 4;

/// Enough for an ELF64 header. Never read a whole executable into memory.
const HEADER_LEN: usize = 64;

/// CPU families for which the target and header encodings are unambiguous.
/// This is not an ISA-extension, OS ABI, or dynamic-loader compatibility check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpuArchitecture {
    X86,
    X86_64,
    X86_64X32,
    Arm,
    ArmBe,
    Aarch64,
    Aarch64Be,
}

impl CpuArchitecture {
    const fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::X86_64X32 => "x86_64 (x32 ABI)",
            Self::Arm => "arm",
            Self::ArmBe => "arm (big-endian)",
            Self::Aarch64 => "aarch64",
            Self::Aarch64Be => "aarch64 (big-endian)",
        }
    }
}

fn expected_cpu_architecture(triple: &str) -> Option<CpuArchitecture> {
    let triple = triple.to_ascii_lowercase();
    match triple.split('-').next()? {
        "x86_64" if triple.ends_with("-gnux32") => Some(CpuArchitecture::X86_64X32),
        "x86_64" | "x86_64h" => Some(CpuArchitecture::X86_64),
        "i386" | "i486" | "i586" | "i686" => Some(CpuArchitecture::X86),
        "aarch64" | "arm64e" => Some(CpuArchitecture::Aarch64),
        "aarch64_be" => Some(CpuArchitecture::Aarch64Be),
        "arm" | "armv4t" | "armv5te" | "armv6" | "armv7" | "armv7a" | "thumbv7neon" => {
            Some(CpuArchitecture::Arm)
        }
        "armeb" | "armebv7r" => Some(CpuArchitecture::ArmBe),
        _ => None,
    }
}

fn header_u16(bytes: &[u8], little_endian: bool) -> Option<u16> {
    let bytes = bytes.get(..2)?.try_into().ok()?;
    Some(if little_endian {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

fn header_u32(bytes: &[u8], little_endian: bool) -> Option<u32> {
    let bytes = bytes.get(..4)?.try_into().ok()?;
    Some(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

/// Decode only complete executable/shared-object ELF headers with known CPU,
/// class, and byte order. A truncated or inconsistent header is not positive
/// evidence of an architecture mismatch. ELF magic alone still proves format.
fn elf_cpu_architecture(header: &[u8]) -> Option<CpuArchitecture> {
    if classify_binary_format(header)? != BinaryFormat::Elf {
        return None;
    }
    let (size, size_offset) = match header.get(4)? {
        1 => (52, 40),
        2 => (64, 52),
        _ => return None,
    };
    let header = header.get(..size)?;
    let little_endian = match header[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    if header[6] != 1
        || header_u32(&header[20..], little_endian)? != 1
        || usize::from(header_u16(&header[size_offset..], little_endian)?) != size
        || !matches!(header_u16(&header[16..], little_endian)?, 2 | 3)
    {
        return None;
    }
    let machine = header_u16(&header[18..], little_endian)?;
    match (machine, header[4], little_endian) {
        (3, 1, true) => Some(CpuArchitecture::X86),
        (62, 2, true) => Some(CpuArchitecture::X86_64),
        (62, 1, true) => Some(CpuArchitecture::X86_64X32),
        (40, 1, true) => Some(CpuArchitecture::Arm),
        (40, 1, false) => Some(CpuArchitecture::ArmBe),
        (183, 2, true) => Some(CpuArchitecture::Aarch64),
        (183, 2, false) => Some(CpuArchitecture::Aarch64Be),
        _ => None,
    }
}

struct BinaryIdentity {
    format: BinaryFormat,
    /// None means architecture evidence is unavailable, not an empty CPU set.
    architectures: Option<Vec<CpuArchitecture>>,
}

/// Identify an executable container from its leading bytes.
///
/// Returns `None` for anything not positively recognized — a short read, a text
/// file, an `ar` archive (`.rlib`/`.a`), or any format not in the table. `None`
/// never fires the gate.
///
/// Note on `0xCAFEBABE`: it is both a Mach-O universal-binary header and a Java
/// class file. Only extension-shaped executable candidates reach this function
/// (see [`inspectable_executable_path`]), and `.class` is not among them.
pub(super) fn classify_binary_format(header: &[u8]) -> Option<BinaryFormat> {
    let magic: [u8; MAGIC_LEN] = header.get(..MAGIC_LEN)?.try_into().ok()?;
    match magic {
        [0x7F, b'E', b'L', b'F'] => Some(BinaryFormat::Elf),
        // Mach-O thin: 32/64-bit, both byte orders.
        [0xFE, 0xED, 0xFA, 0xCE]
        | [0xCE, 0xFA, 0xED, 0xFE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xCF, 0xFA, 0xED, 0xFE] => Some(BinaryFormat::MachO),
        // Mach-O universal ("fat"): 32/64-bit offsets, both byte orders.
        [0xCA, 0xFE, 0xBA, 0xBE]
        | [0xBE, 0xBA, 0xFE, 0xCA]
        | [0xCA, 0xFE, 0xBA, 0xBF]
        | [0xBF, 0xBA, 0xFE, 0xCA] => Some(BinaryFormat::MachO),
        [0x00, 0x61, 0x73, 0x6D] => Some(BinaryFormat::Wasm),
        [b'M', b'Z', ..] => Some(BinaryFormat::Pe),
        _ => None,
    }
}

/// The executable container a Rust target triple produces, or `None` when the
/// triple is not recognized (an unknown triple must never fire the gate).
pub(super) fn expected_binary_format(triple: &str) -> Option<BinaryFormat> {
    let t = triple.to_ascii_lowercase();
    // Apple first: `aarch64-apple-darwin` also contains no other marker, but
    // `*-apple-ios-sim` etc. must not fall through to a substring match below.
    if t.contains("-apple-") || t.contains("darwin") || t.contains("-ios") || t.contains("-tvos") {
        return Some(BinaryFormat::MachO);
    }
    if t.contains("windows") {
        return Some(BinaryFormat::Pe);
    }
    // `wasm32-unknown-emscripten` emits a `.js`/`.wasm` pair rather than a bare
    // module, so only the plain wasm targets get a positive expectation.
    if t.starts_with("wasm") && !t.contains("emscripten") {
        return Some(BinaryFormat::Wasm);
    }
    if t.contains("linux")
        || t.contains("android")
        || t.contains("freebsd")
        || t.contains("netbsd")
        || t.contains("openbsd")
        || t.contains("dragonfly")
        || t.contains("illumos")
        || t.contains("solaris")
        || t.contains("fuchsia")
        || t.contains("redox")
        || t.contains("haiku")
    {
        return Some(BinaryFormat::Elf);
    }
    None
}

/// Whether a path component looks like a Rust target triple directory
/// (`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, …) rather than a cargo
/// profile directory (`debug`, `release`, `my-profile`).
///
/// Cargo profile names may contain a single dash; every real triple has at
/// least two, so "two or more dashes AND a known arch prefix" separates them
/// without a hardcoded triple list.
fn looks_like_target_triple_dir(component: &str) -> bool {
    if component.matches('-').count() < 2 {
        return false;
    }
    let arch = component.split('-').next().unwrap_or_default();
    matches!(
        arch,
        "x86_64"
            | "i686"
            | "i586"
            | "aarch64"
            | "arm"
            | "armv7"
            | "armv7a"
            | "armebv7r"
            | "thumbv7neon"
            | "riscv32imac"
            | "riscv64gc"
            | "powerpc"
            | "powerpc64"
            | "powerpc64le"
            | "s390x"
            | "mips"
            | "mips64"
            | "mipsel"
            | "loongarch64"
            | "sparc64"
            | "wasm32"
            | "wasm64"
    )
}

/// Whether the file name is shaped like something that could be an executable
/// container the host will try to load.
///
/// Extension-less files are cargo's bin/example/test executables; the shared
/// library extensions cover cdylib/proc-macro outputs. Everything else
/// (`.rlib`, `.rmeta`, `.d`, `.json`, `.o`, `.a`, …) is either an archive the
/// host never execs or metadata, and is not worth an open.
fn inspectable_executable_path(file_name: &str) -> bool {
    match file_name.rsplit_once('.') {
        None => true,
        Some((stem, ext)) => {
            if stem.is_empty() {
                // A dotfile such as `.gitignore`, not `name.ext`.
                return false;
            }
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "exe" | "so" | "dylib" | "dll"
            )
        }
    }
}

/// Reduce one manifest path to the part below the profile directory that this
/// gate is allowed to inspect, or `None` when the path is out of scope.
///
/// `path` is relative to the retrieval sync root: the project root for the
/// default-root phase (so it starts with `target/`) or the target directory
/// itself for a forwarded `CARGO_TARGET_DIR` phase (`custom_target_sync`).
///
/// `pinned_triple` is the command's explicit `--target <triple>`, if any; see
/// the module docs for why it selects a different subtree.
fn in_scope_output_path<'a>(
    path: &'a str,
    custom_target_sync: bool,
    pinned_triple: Option<&str>,
) -> Option<&'a str> {
    let rel = if custom_target_sync {
        path
    } else {
        path.strip_prefix("target/")?
    };
    let mut components = rel.split('/').filter(|c| !c.is_empty());
    let first = components.next()?;
    let _profile = match pinned_triple {
        // Pinned cross build: only the `<triple>/<profile>/…` subtree is the
        // artifact the caller asked for; `target/<profile>/…` holds worker-host
        // build scripts and proc macros by design.
        Some(triple) => {
            if !first.eq_ignore_ascii_case(triple) {
                return None;
            }
            components.next()?
        }
        // Unpinned build: the plain `<profile>/…` tree. A `<triple>/…` subtree
        // here came from some other, explicitly-targeted build and is not this
        // command's host artifact.
        None => {
            if looks_like_target_triple_dir(first) {
                return None;
            }
            first
        }
    };
    // Cargo per-job cache trees mirror the retrieval excludes and legitimately
    // hold worker-host binaries even for a host build.
    let rest: Vec<&str> = components.collect();
    if rest.is_empty() {
        return None;
    }
    if rest
        .iter()
        .any(|c| matches!(*c, "build" | "incremental" | ".fingerprint"))
    {
        return None;
    }
    let file_name = *rest.last()?;
    if !inspectable_executable_path(file_name) {
        return None;
    }
    Some(rel)
}

/// One retrieved file whose format or CPU differs from the requested target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ForeignArtifact {
    /// Path as it appeared in the retrieval manifest (relative to the sync root).
    pub(super) path: String,
    /// The container format actually found in the file.
    pub(super) found: BinaryFormat,
    /// Present only for a proven same-format CPU mismatch.
    architecture: Option<String>,
}

/// Inspect a successful retrieval's manifest and report every file that is
/// provably an executable for the wrong platform.
///
/// `local_base` is the local directory the manifest paths are relative to (the
/// project root, or the forwarded `CARGO_TARGET_DIR`). `expected_triple` is the
/// triple the caller's build was for — the command's `--target` when pinned,
/// otherwise the local host triple.
///
/// Returns an empty vector whenever the evidence is not conclusive: unknown
/// expected triple, unreadable files, or unrecognized magic.
pub(super) fn foreign_target_artifacts(
    local_base: &Path,
    manifest: &[String],
    custom_target_sync: bool,
    expected_triple: &str,
    pinned_triple: Option<&str>,
) -> Vec<ForeignArtifact> {
    let Some(expected) = expected_binary_format(expected_triple) else {
        return Vec::new();
    };
    let expected_cpu = expected_cpu_architecture(expected_triple);
    let mut findings = Vec::new();
    let mut inspected = 0usize;
    for path in manifest {
        if inspected >= MAX_FILES_INSPECTED || findings.len() >= MAX_FINDINGS_REPORTED {
            break;
        }
        if in_scope_output_path(path, custom_target_sync, pinned_triple).is_none() {
            continue;
        }
        inspected += 1;
        // The manifest path is relative to the retrieval sync root, which is
        // exactly what `local_base` names — the project root for the
        // default-root phase (so the path keeps its `target/` prefix) or the
        // local target dir for a forwarded `CARGO_TARGET_DIR`.
        let full = local_base.join(path);
        let Some(identity) = read_binary_identity(&full) else {
            continue;
        };
        let found = identity.format;
        if found != expected {
            findings.push(ForeignArtifact {
                path: path.clone(),
                found,
                architecture: None,
            });
        } else if let (Some(expected_cpu), Some(cpus)) = (expected_cpu, identity.architectures)
            && !cpus.is_empty()
            && !cpus.contains(&expected_cpu)
        {
            findings.push(ForeignArtifact {
                path: path.clone(),
                found,
                architecture: Some(
                    cpus.iter()
                        .map(|cpu| cpu.label())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            });
        }
    }
    findings
}

/// Read just enough of a file to classify it. Any I/O error is "no evidence".
fn read_binary_identity(path: &Path) -> Option<BinaryIdentity> {
    let mut file = File::open(path).ok()?;
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0usize;
    while filled < header.len() {
        match file.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    let header = &header[..filled];
    let format = classify_binary_format(header)?;
    let architectures = elf_cpu_architecture(header).map(|cpu| vec![cpu]).or_else(|| {
        let len = file.metadata().ok()?.len();
        artifact_identity::architectures(&mut file, format, header, len)
    });
    Some(BinaryIdentity {
        format,
        architectures,
    })
}

/// Render the operator-facing detail for a set of findings.
pub(super) fn describe_findings(findings: &[ForeignArtifact]) -> String {
    findings
        .iter()
        .map(|f| match &f.architecture {
            Some(cpu) => format!("{} ({}; CPU {cpu})", f.path, f.found.label()),
            None => format!("{} ({})", f.path, f.found.label()),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn classifies_known_magics() {
        assert_eq!(
            classify_binary_format(b"\x7FELF\x02\x01"),
            Some(BinaryFormat::Elf)
        );
        assert_eq!(
            classify_binary_format(&[0xCF, 0xFA, 0xED, 0xFE, 0x0C]),
            Some(BinaryFormat::MachO)
        );
        assert_eq!(
            classify_binary_format(&[0xCA, 0xFE, 0xBA, 0xBE]),
            Some(BinaryFormat::MachO)
        );
        assert_eq!(
            classify_binary_format(b"MZ\x90\x00"),
            Some(BinaryFormat::Pe)
        );
        assert_eq!(
            classify_binary_format(&[0x00, 0x61, 0x73, 0x6D]),
            Some(BinaryFormat::Wasm)
        );
    }

    #[test]
    fn declines_unknown_and_short_magics() {
        assert_eq!(classify_binary_format(b"#!/b"), None);
        assert_eq!(classify_binary_format(b"!<ar"), None);
        assert_eq!(classify_binary_format(b"\x7FEL"), None);
        assert_eq!(classify_binary_format(b""), None);
    }

    #[test]
    fn maps_triples_to_formats() {
        assert_eq!(
            expected_binary_format("aarch64-apple-darwin"),
            Some(BinaryFormat::MachO)
        );
        assert_eq!(
            expected_binary_format("x86_64-unknown-linux-gnu"),
            Some(BinaryFormat::Elf)
        );
        assert_eq!(
            expected_binary_format("x86_64-unknown-linux-musl"),
            Some(BinaryFormat::Elf)
        );
        assert_eq!(
            expected_binary_format("x86_64-pc-windows-msvc"),
            Some(BinaryFormat::Pe)
        );
        assert_eq!(
            expected_binary_format("wasm32-unknown-unknown"),
            Some(BinaryFormat::Wasm)
        );
        // Unknown triples must never fire the gate.
        assert_eq!(expected_binary_format("x86_64-unknown-none"), None);
        assert_eq!(expected_binary_format(""), None);
    }

    #[test]
    fn triple_dirs_are_distinguished_from_profile_dirs() {
        assert!(looks_like_target_triple_dir("x86_64-unknown-linux-gnu"));
        assert!(looks_like_target_triple_dir("aarch64-apple-darwin"));
        assert!(!looks_like_target_triple_dir("debug"));
        assert!(!looks_like_target_triple_dir("release"));
        assert!(!looks_like_target_triple_dir("fast-dev"));
        // A two-dash profile name that is not an arch prefix stays a profile.
        assert!(!looks_like_target_triple_dir("my-fast-profile"));
    }

    #[test]
    fn executable_candidates_are_extension_filtered() {
        assert!(inspectable_executable_path("arch-repro"));
        assert!(inspectable_executable_path("tool.exe"));
        assert!(inspectable_executable_path("libfoo.so"));
        assert!(inspectable_executable_path("libfoo.dylib"));
        assert!(!inspectable_executable_path("libfoo.rlib"));
        assert!(!inspectable_executable_path("foo.rmeta"));
        assert!(!inspectable_executable_path("foo.d"));
        assert!(!inspectable_executable_path(".gitignore"));
    }

    #[test]
    fn scope_selects_the_unpinned_profile_tree() {
        assert_eq!(
            in_scope_output_path("target/release/arch-repro", false, None),
            Some("release/arch-repro")
        );
        assert_eq!(
            in_scope_output_path("target/debug/deps/libfoo.dylib", false, None),
            Some("debug/deps/libfoo.dylib")
        );
        // Cache trees are never inspected.
        assert_eq!(
            in_scope_output_path("target/debug/build/foo-abc/build-script-build", false, None),
            None
        );
        assert_eq!(
            in_scope_output_path("target/debug/.fingerprint/foo/lib-foo", false, None),
            None
        );
        // A cross-compiled subtree is not this unpinned command's host output.
        assert_eq!(
            in_scope_output_path("target/x86_64-unknown-linux-gnu/release/tool", false, None),
            None
        );
        // Loose target-root metadata.
        assert_eq!(
            in_scope_output_path("target/.rustc_info.json", false, None),
            None
        );
        // Files outside target/ never reach the gate.
        assert_eq!(in_scope_output_path("src/main.rs", false, None), None);
    }

    #[test]
    fn scope_selects_the_pinned_triple_tree() {
        let pinned = Some("x86_64-unknown-linux-musl");
        assert_eq!(
            in_scope_output_path(
                "target/x86_64-unknown-linux-musl/release/tool",
                false,
                pinned
            ),
            Some("x86_64-unknown-linux-musl/release/tool")
        );
        // Host build scripts / proc macros of a cross build are the WORKER's
        // host format by design and must not be flagged.
        assert_eq!(
            in_scope_output_path("target/release/deps/libmacro.so", false, pinned),
            None
        );
    }

    #[test]
    fn custom_target_basis_has_no_target_prefix() {
        assert_eq!(
            in_scope_output_path("release/arch-repro", true, None),
            Some("release/arch-repro")
        );
        assert_eq!(
            in_scope_output_path("release/deps/libfoo.so", true, None),
            Some("release/deps/libfoo.so")
        );
    }

    fn write_file(root: &Path, rel: &str, bytes: &[u8]) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    const ELF: &[u8] = b"\x7FELF\x02\x01\x01\x00";
    const MACHO: &[u8] = &[0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01];

    #[test]
    fn flags_an_elf_returned_to_a_macos_target_dir() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "target/release/arch-repro", ELF);
        let findings = foreign_target_artifacts(
            dir.path(),
            &["target/release/arch-repro".to_string()],
            false,
            "aarch64-apple-darwin",
            None,
        );
        assert_eq!(
            findings,
            vec![ForeignArtifact {
                path: "target/release/arch-repro".to_string(),
                found: BinaryFormat::Elf,
                architecture: None,
            }]
        );
        assert_eq!(
            describe_findings(&findings),
            "target/release/arch-repro (ELF)"
        );
    }

    #[test]
    fn accepts_a_native_artifact() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "target/release/arch-repro", MACHO);
        assert!(
            foreign_target_artifacts(
                dir.path(),
                &["target/release/arch-repro".to_string()],
                false,
                "aarch64-apple-darwin",
                None,
            )
            .is_empty()
        );
    }

    #[test]
    fn accepts_a_pinned_cross_build_with_worker_host_build_scripts() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "target/x86_64-unknown-linux-musl/release/tool",
            ELF,
        );
        // Worker-host proc macro beside it: correct for a cross build, and
        // outside the pinned subtree the gate inspects.
        write_file(dir.path(), "target/release/deps/libmacro.so", ELF);
        assert!(
            foreign_target_artifacts(
                dir.path(),
                &[
                    "target/x86_64-unknown-linux-musl/release/tool".to_string(),
                    "target/release/deps/libmacro.so".to_string(),
                ],
                false,
                "x86_64-unknown-linux-musl",
                Some("x86_64-unknown-linux-musl"),
            )
            .is_empty()
        );
    }

    #[test]
    fn flags_a_pinned_cross_build_that_returned_the_wrong_triple() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "target/x86_64-pc-windows-msvc/release/tool.exe",
            ELF,
        );
        let findings = foreign_target_artifacts(
            dir.path(),
            &["target/x86_64-pc-windows-msvc/release/tool.exe".to_string()],
            false,
            "x86_64-pc-windows-msvc",
            Some("x86_64-pc-windows-msvc"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].found, BinaryFormat::Elf);
    }

    #[test]
    fn unknown_expected_triple_never_fires() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "target/release/arch-repro", ELF);
        assert!(
            foreign_target_artifacts(
                dir.path(),
                &["target/release/arch-repro".to_string()],
                false,
                "x86_64-unknown-none",
                None,
            )
            .is_empty()
        );
    }

    #[test]
    fn non_executable_and_missing_files_are_not_evidence() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "target/release/libfoo.rlib", b"!<arch>\n");
        write_file(dir.path(), "target/release/build-info.json", b"{}");
        assert!(
            foreign_target_artifacts(
                dir.path(),
                &[
                    "target/release/libfoo.rlib".to_string(),
                    "target/release/build-info.json".to_string(),
                    "target/release/never-transferred".to_string(),
                ],
                false,
                "aarch64-apple-darwin",
                None,
            )
            .is_empty()
        );
    }

    #[test]
    fn reporting_is_bounded() {
        let dir = TempDir::new().unwrap();
        let mut manifest = Vec::new();
        for i in 0..(MAX_FINDINGS_REPORTED + 5) {
            let rel = format!("target/release/bin-{i}");
            write_file(dir.path(), &rel, ELF);
            manifest.push(rel);
        }
        let findings =
            foreign_target_artifacts(dir.path(), &manifest, false, "aarch64-apple-darwin", None);
        assert_eq!(findings.len(), MAX_FINDINGS_REPORTED);
    }

    fn elf_header(machine: u16, class: u8, little_endian: bool) -> Vec<u8> {
        let (size, size_offset) = if class == 1 {
            (52, 40)
        } else {
            (64, 52)
        };
        let mut header = vec![0; size];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = class;
        header[5] = if little_endian { 1 } else { 2 };
        header[6] = 1;
        for (offset, value) in [(16, 2_u16), (18, machine), (size_offset, size as u16)] {
            let bytes = if little_endian {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            };
            header[offset..offset + 2].copy_from_slice(&bytes);
        }
        header[if little_endian { 20 } else { 23 }] = 1;
        header
    }

    #[test]
    fn elf_cpu_decodes_complete_headers_and_refuses_inconclusive_evidence() {
        for (machine, class, little_endian, expected) in [
            (3, 1, true, CpuArchitecture::X86),
            (62, 2, true, CpuArchitecture::X86_64),
            (62, 1, true, CpuArchitecture::X86_64X32),
            (40, 1, true, CpuArchitecture::Arm),
            (40, 1, false, CpuArchitecture::ArmBe),
            (183, 2, true, CpuArchitecture::Aarch64),
            (183, 2, false, CpuArchitecture::Aarch64Be),
        ] {
            let header = elf_header(machine, class, little_endian);
            assert_eq!(elf_cpu_architecture(&header), Some(expected));
            for length in 0..header.len() {
                assert_eq!(
                    elf_cpu_architecture(&header[..length]),
                    None,
                    "length {length}"
                );
            }
        }
        for (machine, class, little_endian) in [
            (0, 2, true),
            (65535, 2, true),
            (3, 2, true),
            (62, 2, false),
        ] {
            assert_eq!(
                elf_cpu_architecture(&elf_header(machine, class, little_endian)),
                None
            );
        }
        for (offset, value) in [(4, 0), (5, 0), (6, 0), (16, 1), (20, 0), (52, 0)] {
            let mut header = elf_header(62, 2, true);
            header[offset] = value;
            assert_eq!(
                elf_cpu_architecture(&header),
                None,
                "invalid field at {offset}"
            );
        }
    }

    #[test]
    fn same_format_cpu_mismatch_is_reported_in_both_retrieval_bases() {
        let dir = TempDir::new().unwrap();
        for (custom, path) in [(false, "target/release/app"), (true, "release/app")] {
            for (machine, expected, found) in [
                (62, "aarch64-unknown-linux-gnu", "x86_64"),
                (183, "x86_64-unknown-linux-gnu", "aarch64"),
            ] {
                let header = elf_header(machine, 2, true);
                // Negative control: the previous four-byte-only gate accepts
                // this incompatible executable because both sides are ELF.
                assert_eq!(
                    classify_binary_format(&header),
                    expected_binary_format(expected)
                );
                write_file(dir.path(), path, &header);
                let findings =
                    foreign_target_artifacts(dir.path(), &[path.into()], custom, expected, None);
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].architecture.as_deref(), Some(found));
                assert_eq!(
                    describe_findings(&findings),
                    format!("{path} (ELF; CPU {found})")
                );
            }
        }
    }

    #[test]
    fn cpu_gate_preserves_pinned_cross_build_scope_and_native_outputs() {
        let dir = TempDir::new().unwrap();
        let triple = "aarch64-unknown-linux-gnu";
        let requested = format!("target/{triple}/release/app");
        let host_macro = "target/release/deps/libmacro.so";
        let cache = format!("target/{triple}/release/build/worker-helper");
        write_file(dir.path(), &requested, &elf_header(183, 2, true));
        write_file(dir.path(), host_macro, &elf_header(62, 2, true));
        write_file(dir.path(), &cache, &elf_header(62, 2, true));
        let manifest = vec![requested.clone(), host_macro.into(), cache];
        assert!(
            foreign_target_artifacts(dir.path(), &manifest, false, triple, Some(triple)).is_empty()
        );
        write_file(dir.path(), &requested, &elf_header(62, 2, true));
        let findings = foreign_target_artifacts(dir.path(), &manifest, false, triple, Some(triple));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, requested);
        // An unpinned host build must not inspect residue from a cross build.
        assert!(
            foreign_target_artifacts(
                dir.path(),
                &manifest,
                false,
                "x86_64-unknown-linux-gnu",
                None,
            )
            .is_empty()
        );
    }

    #[test]
    fn cpu_gate_keeps_unknown_architectures_and_short_headers_fail_open() {
        let dir = TempDir::new().unwrap();
        let path = "release/app";
        for bytes in [ELF.to_vec(), elf_header(0, 2, true)] {
            write_file(dir.path(), path, &bytes);
            assert!(
                foreign_target_artifacts(
                    dir.path(),
                    &[path.into()],
                    true,
                    "aarch64-unknown-linux-gnu",
                    None,
                )
                .is_empty()
            );
        }
        write_file(dir.path(), path, &elf_header(62, 2, true));
        assert!(
            foreign_target_artifacts(
                dir.path(),
                &[path.into()],
                true,
                "unknown-unknown-linux-gnu",
                None,
            )
            .is_empty()
        );
        assert_eq!(
            expected_cpu_architecture("x86_64-unknown-linux-gnux32"),
            Some(CpuArchitecture::X86_64X32)
        );
        assert_eq!(
            expected_cpu_architecture("aarch64_be-unknown-linux-gnu"),
            Some(CpuArchitecture::Aarch64Be)
        );
        assert_eq!(expected_cpu_architecture("aarch64_32-apple-watchos"), None);
    }
}
