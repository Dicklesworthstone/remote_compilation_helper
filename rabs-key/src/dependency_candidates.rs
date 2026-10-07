//! Locator-exact dependency candidates for the live dependency class
//! (bd-k52xe): which files in a dependency search directory rustc's crate
//! locator can examine for one compile, and what identity the action key
//! binds for each.
//!
//! ## Why not the whole directory
//!
//! Cargo compiles every library of a build into one `target/<profile>/deps`
//! directory and passes it to each rustc as both `--out-dir` and
//! `-L dependency=`. Keying every member of that directory makes the key a
//! function of build scheduling (which units finished first under `-jN`)
//! and of everything else the target directory ever held (workspace crates,
//! other versions, test executables, proc-macro dylibs, rustc's `*.rcgu.o`
//! temporaries). Two worktrees then never share a key, and a compile is
//! unpublishable whenever a sibling compile finishes while it runs.
//!
//! ## What rustc actually examines
//!
//! A direct `--extern name=path` is loaded from exactly that path. Every
//! other crate in the graph is located through the search directories by
//! the `(name, extra-filename)` pair its dependent's metadata records: the
//! locator examines only files whose names start with `lib{name}{extra}`
//! and end in `.rlib`, `.rmeta` or the dylib suffix, and keeps the one whose
//! crate hash matches. Cargo names every library unit
//! `lib{crate}-{16 hex}.{rlib,rmeta,so}` and records that `-{16 hex}` extra
//! filename verbatim in the metadata of every crate whose graph contains it
//! (pinned against real rustc in this module's tests' companion
//! conformance test). So a Cargo-named file can be examined only when its
//! `-{16 hex}` token occurs in the metadata of a crate the compile loads;
//! the closure starts at the direct externs. Files that are not
//! locator-visible at all (no `lib` prefix or crate suffix) are never
//! opened. Locator-visible files that do not follow Cargo's naming could
//! only be reached through an extra filename Cargo does not produce for
//! dependencies; they are keyed unconditionally whenever they carry Rust
//! metadata (a file without metadata is rejected by the locator and can
//! only change an error, never a successful result).
//!
//! ## Identity is the metadata, not the container
//!
//! A compile that emits a library reads nothing from a transitive
//! dependency but its metadata, and an `.rlib` carries the byte-identical
//! metadata of its `.rmeta` as the `.rmeta` section of its `lib.rmeta`
//! archive member. A group (`lib{crate}-{hash}` in one directory) whose
//! present members all carry one metadata digest is keyed by that digest,
//! so the key does not depend on whether pipelining has written the
//! `.rlib` yet. Under `-Z embed-metadata=no` (the pinned Cargo's default)
//! an `.rlib` carries object code only; it adds nothing to the group.
//! Members that disagree, or whose metadata cannot be extracted, are keyed
//! by their exact bytes instead.
//!
//! A referenced Cargo-named dylib is a proc-macro (or a dylib crate): its
//! code may run inside the compile, so the closure refuses it — the class
//! still never consumes proc-macros, but no longer refuses compiles merely
//! because some unrelated proc-macro sits in the same directory.
//!
//! Like the rest of this crate: zero filesystem effects. The caller reads;
//! this module parses, closes and hashes.

use std::collections::{BTreeMap, BTreeSet};

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Domain of a crate-metadata identity.
pub const DOMAIN_CRATE_METADATA: &str = "rabs.live-dependency.crate-metadata.v1";

/// Length of the hexadecimal part of a Cargo extra filename.
pub const EXTRA_FILENAME_HEX_DIGITS: usize = 16;

/// Most groups one compile may reference before the closure refuses.
pub const MAX_REFERENCED_FILES: usize = 4096;

/// Magic prefix of serialized Rust crate metadata.
const METADATA_MAGIC: &[u8] = b"rust\0\0\0";
/// The archive member that carries an `.rlib`'s metadata.
const RLIB_METADATA_MEMBER: &str = "lib.rmeta";
/// The object section that carries the metadata inside that member.
const RLIB_METADATA_SECTION: &str = ".rmeta";
/// The object section a Rust dylib (or proc-macro) carries its metadata in.
const DYLIB_METADATA_SECTION: &str = ".rustc";

/// The container kinds the crate locator examines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CrateFlavor {
    /// `.rlib`
    Rlib,
    /// `.rmeta`
    Rmeta,
    /// `.so` / `.dylib`: a proc-macro or a Rust dylib.
    Dylib,
}

impl CrateFlavor {
    const fn tag(self) -> u32 {
        match self {
            Self::Rlib => 0,
            Self::Rmeta => 1,
            Self::Dylib => 2,
        }
    }
}

/// How the crate locator sees one directory member, by name alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateClass {
    /// `lib{crate}-{16 hex}.{rlib,rmeta,so}`.
    Cargo {
        /// `lib{crate}-{16 hex}`: the group this member belongs to.
        stem: String,
        /// `{16 hex}` (without the leading `-`).
        hash: String,
        /// Container kind.
        flavor: CrateFlavor,
    },
    /// Locator-visible (`lib` prefix and crate suffix) but not Cargo-named.
    Unpatterned {
        /// Container kind.
        flavor: CrateFlavor,
    },
    /// Never examined by the crate locator.
    Inert,
}

fn is_crate_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_lower_hex(text: &[u8]) -> bool {
    text.iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// Classify one directory member by name.
#[must_use]
pub fn classify_candidate(file_name: &str) -> CandidateClass {
    let Some(rest) = file_name.strip_prefix("lib") else {
        return CandidateClass::Inert;
    };
    let (stem_tail, flavor) = if let Some(stem) = rest.strip_suffix(".rlib") {
        (stem, CrateFlavor::Rlib)
    } else if let Some(stem) = rest.strip_suffix(".rmeta") {
        (stem, CrateFlavor::Rmeta)
    } else if let Some(stem) = rest
        .strip_suffix(".so")
        .or_else(|| rest.strip_suffix(".dylib"))
    {
        (stem, CrateFlavor::Dylib)
    } else {
        return CandidateClass::Inert;
    };
    if let Some((name, hash)) = stem_tail.rsplit_once('-')
        && is_crate_name(name)
        && hash.len() == EXTRA_FILENAME_HEX_DIGITS
        && is_lower_hex(hash.as_bytes())
    {
        return CandidateClass::Cargo {
            stem: format!("lib{stem_tail}"),
            hash: hash.to_owned(),
            flavor,
        };
    }
    CandidateClass::Unpatterned { flavor }
}

/// Every Cargo extra-filename token (`-` followed by exactly 16 lowercase
/// hex digits) occurring anywhere in `bytes`, as the 16 digits. A digit run
/// longer than 16 still yields its first 16: metadata strings are length
/// prefixed, so the byte after the token is arbitrary.
#[must_use]
pub fn extra_filename_tokens(bytes: &[u8]) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    let mut index = 0;
    while let Some(offset) = bytes[index..].iter().position(|byte| *byte == b'-') {
        let start = index + offset + 1;
        if let Some(candidate) = bytes.get(start..start + EXTRA_FILENAME_HEX_DIGITS)
            && is_lower_hex(candidate)
        {
            // Hex digits are ASCII.
            tokens.insert(String::from_utf8_lossy(candidate).into_owned());
        }
        index = start;
    }
    tokens
}

/// Whether `bytes` begin like serialized crate metadata.
#[must_use]
pub fn is_crate_metadata(bytes: &[u8]) -> bool {
    bytes.starts_with(METADATA_MAGIC)
}

/// Largest metadata blob ever classified as a stub. The stub rustc writes
/// into an `.rlib` under `-Z embed-metadata=no` is ~120 bytes (header,
/// compiler version, target, crate hash); real metadata of even an empty
/// crate is kilobytes and records extra filenames.
const MAX_METADATA_STUB_BYTES: usize = 1024;

/// Whether an rlib's metadata is only the stub that defers to the sibling
/// `.rmeta`: tiny, terminated, and referencing no crate at all (real
/// metadata records the extra filename of every crate in its graph,
/// including its own). Anything else is treated as real metadata, so a
/// misclassification can only make a key more conservative.
#[must_use]
pub fn is_metadata_stub(metadata: &[u8]) -> bool {
    metadata.len() <= MAX_METADATA_STUB_BYTES
        && metadata.ends_with(b"rust-end-file")
        && extra_filename_tokens(metadata).is_empty()
}

fn parse_decimal(field: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(field).ok()?.trim_end_matches(' ');
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Locate one member of a System V / GNU `ar` archive by its short name.
/// Long-name references (`/123`, `#1/…`) are skipped: rustc stores the
/// metadata member under its short name.
#[must_use]
pub fn ar_member<'a>(archive: &'a [u8], wanted: &str) -> Option<&'a [u8]> {
    let mut offset = archive.strip_prefix(b"!<arch>\n").map(|_| 8)?;
    while offset + 60 <= archive.len() {
        let header = &archive[offset..offset + 60];
        if &header[58..60] != b"`\n" {
            return None;
        }
        let size = parse_decimal(&header[48..58])?;
        let start = offset + 60;
        let end = start.checked_add(size)?;
        if end > archive.len() {
            return None;
        }
        let name = std::str::from_utf8(&header[..16])
            .ok()?
            .trim_end_matches(' ');
        if name.strip_suffix('/').unwrap_or(name) == wanted {
            return Some(&archive[start..end]);
        }
        offset = end + (size & 1);
    }
    None
}

/// Whether every member header of an `ar` archive parses to the end.
fn ar_is_well_formed(archive: &[u8]) -> bool {
    let Some(mut offset) = archive.strip_prefix(b"!<arch>\n").map(|_| 8_usize) else {
        return false;
    };
    while offset < archive.len() {
        let Some(header) = archive.get(offset..offset + 60) else {
            return false;
        };
        let Some(size) = (&header[58..60] == b"`\n")
            .then(|| parse_decimal(&header[48..58]))
            .flatten()
        else {
            return false;
        };
        let Some(end) = (offset + 60)
            .checked_add(size)
            .filter(|end| *end <= archive.len())
        else {
            return false;
        };
        offset = end + (size & 1);
    }
    offset == archive.len() || offset == archive.len() + 1
}

fn read_u16(bytes: &[u8], at: usize, little: bool) -> Option<u64> {
    let raw: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
    Some(u64::from(if little {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    }))
}

fn read_u32(bytes: &[u8], at: usize, little: bool) -> Option<u64> {
    let raw: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(u64::from(if little {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    }))
}

fn read_u64(bytes: &[u8], at: usize, little: bool) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(at..at + 8)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(raw)
    } else {
        u64::from_be_bytes(raw)
    })
}

/// The contents of the named section of an ELF object (32- or 64-bit,
/// either byte order). `None` for anything that is not a well-formed ELF
/// object containing exactly one such section.
#[must_use]
pub fn elf_section<'a>(object: &'a [u8], wanted: &str) -> Option<&'a [u8]> {
    if object.get(..4)? != b"\x7fELF" {
        return None;
    }
    let wide = match object.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match object.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let to_usize = |value: u64| usize::try_from(value).ok();
    let (section_offset, entry_size, count, names_index) = if wide {
        (
            to_usize(read_u64(object, 0x28, little)?)?,
            to_usize(read_u16(object, 0x3a, little)?)?,
            to_usize(read_u16(object, 0x3c, little)?)?,
            to_usize(read_u16(object, 0x3e, little)?)?,
        )
    } else {
        (
            to_usize(read_u32(object, 0x20, little)?)?,
            to_usize(read_u16(object, 0x2e, little)?)?,
            to_usize(read_u16(object, 0x30, little)?)?,
            to_usize(read_u16(object, 0x32, little)?)?,
        )
    };
    if entry_size < if wide { 0x40 } else { 0x28 } || names_index >= count {
        return None;
    }
    // (name offset, file offset, size) of section `index`.
    let header = |index: usize| -> Option<(usize, usize, usize)> {
        let base = section_offset.checked_add(index.checked_mul(entry_size)?)?;
        let name = to_usize(read_u32(object, base, little)?)?;
        let (offset, size) = if wide {
            (
                read_u64(object, base + 0x18, little)?,
                read_u64(object, base + 0x20, little)?,
            )
        } else {
            (
                read_u32(object, base + 0x10, little)?,
                read_u32(object, base + 0x14, little)?,
            )
        };
        Some((name, to_usize(offset)?, to_usize(size)?))
    };
    let (_, names_offset, names_size) = header(names_index)?;
    let names = object.get(names_offset..names_offset.checked_add(names_size)?)?;
    let mut found = None;
    for index in 0..count {
        let (name, offset, size) = header(index)?;
        let name_bytes = names.get(name..)?;
        let name_end = name_bytes.iter().position(|byte| *byte == 0)?;
        if &name_bytes[..name_end] == wanted.as_bytes() {
            if found.is_some() {
                return None;
            }
            found = Some(object.get(offset..offset.checked_add(size)?)?);
        }
    }
    found
}

/// The serialized crate metadata a crate file carries, if it can be
/// extracted exactly: a `.rmeta` file is its metadata; an `.rlib` carries
/// it as the `.rmeta` section of its `lib.rmeta` member (or, for targets
/// that store it raw, as that member's bytes); a dylib carries it in its
/// `.rustc` section, possibly compressed (identity only — callers that need
/// references scan the whole dylib).
#[must_use]
pub fn crate_metadata(flavor: CrateFlavor, bytes: &[u8]) -> Option<&[u8]> {
    let metadata = match flavor {
        CrateFlavor::Rmeta => bytes,
        CrateFlavor::Rlib => {
            let member = ar_member(bytes, RLIB_METADATA_MEMBER)?;
            if is_crate_metadata(member) {
                member
            } else {
                elf_section(member, RLIB_METADATA_SECTION)?
            }
        }
        CrateFlavor::Dylib => return elf_section(bytes, DYLIB_METADATA_SECTION),
    };
    is_crate_metadata(metadata).then_some(metadata)
}

/// The identity one locator-visible file contributes to a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateIdentity {
    /// The digest of its crate metadata ([`DOMAIN_CRATE_METADATA`]).
    Metadata(TypedDigest),
    /// The caller's content identity of its exact bytes (no extractable
    /// metadata container, or a dylib).
    Bytes(TypedDigest),
    /// A well-formed `.rlib` whose metadata member is absent or only a stub
    /// (`-Z embed-metadata=no`, the pinned Cargo's default): rustc reads the
    /// crate's metadata from the group's `.rmeta`, and a compile that emits
    /// a library never reads the archive's object code. Its exact identity
    /// is kept for groups that have nothing else to key.
    ObjectsOnly(TypedDigest),
    /// Carries no Rust metadata at all: the locator rejects it.
    NotRust,
}

/// What reading one file established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRead {
    /// Identity bound by the key.
    pub identity: CandidateIdentity,
    /// Extra-filename tokens it references (from its metadata when that
    /// was extracted, otherwise from all of its bytes).
    pub tokens: BTreeSet<String>,
}

/// Interpret the bytes of one crate file. `exact` is the caller's content
/// identity of `bytes` (used when metadata cannot be extracted).
#[must_use]
pub fn read_candidate(flavor: CrateFlavor, bytes: &[u8], exact: TypedDigest) -> CandidateRead {
    match crate_metadata(flavor, bytes) {
        Some(metadata) if flavor == CrateFlavor::Rlib && is_metadata_stub(metadata) => {
            CandidateRead {
                identity: CandidateIdentity::ObjectsOnly(exact),
                tokens: BTreeSet::new(),
            }
        }
        Some(metadata) if flavor != CrateFlavor::Dylib => CandidateRead {
            identity: CandidateIdentity::Metadata(compute(DOMAIN_CRATE_METADATA, metadata)),
            tokens: extra_filename_tokens(metadata),
        },
        Some(_) => CandidateRead {
            identity: CandidateIdentity::Bytes(exact),
            tokens: extra_filename_tokens(bytes),
        },
        None if flavor == CrateFlavor::Dylib => CandidateRead {
            identity: CandidateIdentity::NotRust,
            tokens: BTreeSet::new(),
        },
        // No metadata member: nothing in it is a compile input or a crate
        // reference (the group's `.rmeta` is read and scanned instead).
        None if flavor == CrateFlavor::Rlib
            && bytes.starts_with(b"!<arch>\n")
            && ar_member(bytes, RLIB_METADATA_MEMBER).is_none()
            && ar_is_well_formed(bytes) =>
        {
            CandidateRead {
                identity: CandidateIdentity::ObjectsOnly(exact),
                tokens: BTreeSet::new(),
            }
        }
        None if !looks_like_container(flavor, bytes) => CandidateRead {
            identity: CandidateIdentity::NotRust,
            tokens: BTreeSet::new(),
        },
        None => CandidateRead {
            identity: CandidateIdentity::Bytes(exact),
            tokens: extra_filename_tokens(bytes),
        },
    }
}

/// An archive or object whose metadata could not be extracted is still
/// keyed by its bytes; only content that is plainly not a crate container
/// is classified as not Rust.
fn looks_like_container(flavor: CrateFlavor, bytes: &[u8]) -> bool {
    match flavor {
        CrateFlavor::Rlib => bytes.starts_with(b"!<arch>\n"),
        CrateFlavor::Rmeta => is_crate_metadata(bytes),
        CrateFlavor::Dylib => false,
    }
}

/// One member of a group: file name, container kind, identity.
pub type GroupMember = (String, CrateFlavor, CandidateIdentity);

/// How a group is bound in the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupIdentity {
    /// Every present member carries this metadata.
    Metadata(TypedDigest),
    /// Members disagree or carry no extractable metadata: each member's
    /// file name, flavor and identity, sorted by file name.
    Members(Vec<GroupMember>),
}

/// One referenced group (or unpatterned file) in one directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateGroupFact {
    /// `lib{crate}-{hash}` for Cargo groups; the file name otherwise.
    pub stem: String,
    /// What the key binds.
    pub identity: GroupIdentity,
}

/// The locator-reachable candidates of one dependency directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDirectoryFact {
    /// Real absolute directory, in the plan's first-use order.
    pub path: String,
    /// Referenced groups and keyed unpatterned files, sorted by stem.
    pub groups: Vec<CandidateGroupFact>,
}

/// Why the closure cannot key this compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosureRefusal {
    /// A proc-macro or dylib crate is reachable from the crate graph.
    Dylib(String),
    /// The caller could not read a file the closure needs.
    Read(String),
    /// The closure exceeds [`MAX_REFERENCED_FILES`].
    TooLarge,
}

impl std::fmt::Display for ClosureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dylib(path) => write!(f, "reachable dylib or proc-macro {path}"),
            Self::Read(detail) => write!(f, "unreadable candidate: {detail}"),
            Self::TooLarge => f.write_str("referenced candidate closure exceeds class bound"),
        }
    }
}

/// Close the referenced candidates of one compile.
///
/// - `listings[d]`: the locator-visible member names of dependency
///   directory `d` (callers may pass every member; inert names are
///   ignored), excluding the compile's own declared outputs;
/// - `seeds`: the direct externs as `(directory index, file name)`;
/// - `read(d, name, flavor)`: the caller's observation of one file.
///
/// # Errors
/// A [`ClosureRefusal`]: the compile runs unkeyed.
pub fn referenced_candidates(
    paths: &[String],
    listings: &[Vec<String>],
    seeds: &[(usize, String)],
    mut read: impl FnMut(usize, &str, CrateFlavor) -> Result<CandidateRead, String>,
) -> Result<Vec<DependencyDirectoryFact>, ClosureRefusal> {
    // token -> members carrying it, in (directory, name) order.
    let mut by_token: BTreeMap<String, Vec<(usize, String, String, CrateFlavor)>> = BTreeMap::new();
    let mut unpatterned = Vec::new();
    for (directory, names) in listings.iter().enumerate() {
        for name in names {
            match classify_candidate(name) {
                CandidateClass::Cargo { stem, hash, flavor } => {
                    by_token
                        .entry(hash)
                        .or_default()
                        .push((directory, name.clone(), stem, flavor));
                }
                CandidateClass::Unpatterned { flavor } => {
                    unpatterned.push((directory, name.clone(), flavor));
                }
                CandidateClass::Inert => {}
            }
        }
    }
    let mut pending: Vec<String> = Vec::new();
    let mut groups: BTreeMap<(usize, String), Vec<GroupMember>> = BTreeMap::new();
    let mut files = 0_usize;
    for (directory, name) in seeds {
        let flavor = match classify_candidate(name) {
            CandidateClass::Cargo { flavor, .. } | CandidateClass::Unpatterned { flavor } => flavor,
            CandidateClass::Inert => {
                return Err(ClosureRefusal::Read(format!("{name} is not a crate file")));
            }
        };
        count(&mut files)?;
        let seen = read(*directory, name, flavor).map_err(ClosureRefusal::Read)?;
        pending.extend(seen.tokens);
    }
    for (directory, name, flavor) in unpatterned {
        count(&mut files)?;
        let seen = read(directory, &name, flavor).map_err(ClosureRefusal::Read)?;
        if seen.identity == CandidateIdentity::NotRust {
            continue;
        }
        // An unpatterned Rust dylib is keyed by its bytes but not refused:
        // Cargo names every proc-macro, so it can only be a dylib crate.
        pending.extend(seen.tokens);
        groups
            .entry((directory, name.clone()))
            .or_default()
            .push((name, flavor, seen.identity));
    }
    let mut closed = BTreeSet::new();
    while let Some(token) = pending.pop() {
        if !closed.insert(token.clone()) {
            continue;
        }
        let Some(members) = by_token.get(&token) else {
            continue;
        };
        for (directory, name, stem, flavor) in members {
            if *flavor == CrateFlavor::Dylib {
                return Err(ClosureRefusal::Dylib(format!(
                    "{}/{name}",
                    paths[*directory]
                )));
            }
            count(&mut files)?;
            let seen = read(*directory, name, *flavor).map_err(ClosureRefusal::Read)?;
            pending.extend(seen.tokens);
            groups.entry((*directory, stem.clone())).or_default().push((
                name.clone(),
                *flavor,
                seen.identity,
            ));
        }
    }
    let mut facts: Vec<DependencyDirectoryFact> = paths
        .iter()
        .map(|path| DependencyDirectoryFact {
            path: path.clone(),
            groups: Vec::new(),
        })
        .collect();
    for ((directory, stem), mut members) in groups {
        members.sort_by(|a, b| a.0.cmp(&b.0));
        // One metadata identity across every member that carries metadata;
        // members without any (objects-only rlibs) add no compile input.
        let mut metadata = members
            .iter()
            .filter_map(|(_, _, identity)| match identity {
                CandidateIdentity::Metadata(digest) => Some(digest),
                _ => None,
            });
        let first = metadata.next().cloned();
        let agreeing = first.as_ref().is_some_and(|first| {
            metadata.all(|digest| digest == first)
                && members.iter().all(|(_, _, identity)| {
                    matches!(
                        identity,
                        CandidateIdentity::Metadata(_) | CandidateIdentity::ObjectsOnly(_)
                    )
                })
        });
        let identity = match first {
            Some(digest) if agreeing => GroupIdentity::Metadata(digest),
            _ => GroupIdentity::Members(members),
        };
        facts[directory]
            .groups
            .push(CandidateGroupFact { stem, identity });
    }
    Ok(facts)
}

fn count(files: &mut usize) -> Result<(), ClosureRefusal> {
    *files += 1;
    if *files > MAX_REFERENCED_FILES {
        Err(ClosureRefusal::TooLarge)
    } else {
        Ok(())
    }
}

fn encode_identity(enc: &mut CanonicalEncoder, identity: &CandidateIdentity) {
    match identity {
        CandidateIdentity::Metadata(digest) => {
            enc.u32(0).str(digest.domain).bytes(&digest.bytes);
        }
        CandidateIdentity::Bytes(digest) => {
            enc.u32(1).str(digest.domain).bytes(&digest.bytes);
        }
        CandidateIdentity::NotRust => {
            enc.u32(2);
        }
        CandidateIdentity::ObjectsOnly(digest) => {
            enc.u32(3).str(digest.domain).bytes(&digest.bytes);
        }
    }
}

/// Canonical encoding of the candidate facts with each directory replaced
/// by its virtual placement (`virtual_path(real)`).
#[must_use]
pub fn encode_candidates(
    directories: &[DependencyDirectoryFact],
    virtual_path: impl Fn(&str) -> String,
) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new();
    enc.str("referenced-dependency-candidates-v1")
        .u64(directories.len() as u64);
    for directory in directories {
        enc.str(&virtual_path(&directory.path))
            .u64(directory.groups.len() as u64);
        for group in &directory.groups {
            enc.str(&group.stem);
            match &group.identity {
                GroupIdentity::Metadata(digest) => {
                    enc.u32(0).str(digest.domain).bytes(&digest.bytes);
                }
                GroupIdentity::Members(members) => {
                    enc.u32(1).u64(members.len() as u64);
                    for (name, flavor, identity) in members {
                        enc.str(name).u32(flavor.tag());
                        encode_identity(&mut enc, identity);
                    }
                }
            }
        }
    }
    enc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(tag: &str) -> TypedDigest {
        compute("test.exact", tag.as_bytes())
    }

    fn metadata(references: &[&str]) -> Vec<u8> {
        let mut bytes = METADATA_MAGIC.to_vec();
        bytes.extend_from_slice(b"\x0a\x00");
        for reference in references {
            bytes.push(17);
            bytes.extend_from_slice(format!("-{reference}").as_bytes());
            bytes.push(0x01);
        }
        bytes
    }

    fn ar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, data) in members {
            let mut header = format!("{:<16}", format!("{name}/"));
            header.push_str(&format!(
                "{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                0,
                0,
                0,
                644,
                data.len()
            ));
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    /// A minimal little-endian ELF64 object with the given sections.
    fn elf64(sections: &[(&str, &[u8])]) -> Vec<u8> {
        let mut names = vec![0_u8];
        let mut name_offsets = Vec::new();
        for (name, _) in sections {
            name_offsets.push(names.len() as u32);
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        let shstrtab_name = names.len() as u32;
        names.extend_from_slice(b".shstrtab\0");
        let mut data = Vec::new();
        let mut placed = Vec::new();
        let base = 0x40;
        for (_, contents) in sections {
            placed.push((base + data.len(), contents.len()));
            data.extend_from_slice(contents);
        }
        let names_at = base + data.len();
        data.extend_from_slice(&names);
        let section_offset = base + data.len();
        let count = sections.len() + 2;
        let mut out = vec![0_u8; 0x40];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[0x28..0x30].copy_from_slice(&(section_offset as u64).to_le_bytes());
        out[0x3a..0x3c].copy_from_slice(&0x40_u16.to_le_bytes());
        out[0x3c..0x3e].copy_from_slice(&(count as u16).to_le_bytes());
        out[0x3e..0x40].copy_from_slice(&((count - 1) as u16).to_le_bytes());
        out.extend_from_slice(&data);
        let entry = |name: u32, offset: usize, size: usize| {
            let mut header = vec![0_u8; 0x40];
            header[..4].copy_from_slice(&name.to_le_bytes());
            header[0x18..0x20].copy_from_slice(&(offset as u64).to_le_bytes());
            header[0x20..0x28].copy_from_slice(&(size as u64).to_le_bytes());
            header
        };
        out.extend_from_slice(&entry(0, 0, 0));
        for (index, (offset, size)) in placed.iter().enumerate() {
            out.extend_from_slice(&entry(name_offsets[index], *offset, *size));
        }
        out.extend_from_slice(&entry(shstrtab_name, names_at, names.len()));
        out
    }

    #[test]
    fn names_classify_exactly_like_the_locator_sees_them() {
        let cargo = |name: &str| match classify_candidate(name) {
            CandidateClass::Cargo { stem, hash, flavor } => Some((stem, hash, flavor)),
            _ => None,
        };
        assert_eq!(
            cargo("libserde_json-0123456789abcdef.rmeta"),
            Some((
                "libserde_json-0123456789abcdef".into(),
                "0123456789abcdef".into(),
                CrateFlavor::Rmeta
            ))
        );
        assert_eq!(
            cargo("libserde_derive-0123456789abcdef.so").map(|c| c.2),
            Some(CrateFlavor::Dylib)
        );
        for unpatterned in [
            "libfoo.rlib",
            "libfoo.so",
            "libfoo-0123456789ABCDEF.rlib",
            "libfoo-0123456789abcde.rmeta",
            "libfoo-0123456789abcdef0.rlib",
            "libfoo-bar-0123456789abcdef.rlib",
            "lib-0123456789abcdef.rlib",
        ] {
            assert!(
                matches!(
                    classify_candidate(unpatterned),
                    CandidateClass::Unpatterned { .. }
                ),
                "{unpatterned}"
            );
        }
        for inert in [
            "foo-0123456789abcdef.d",
            "foo-0123456789abcdef",
            "foo-0123456789abcdef.foo.1a2b-cgu.0.rcgu.o",
            "rmetaXyZ123",
            "libfoo-0123456789abcdef.d",
            "libfoo-0123456789abcdef.a",
            "foo.rlib",
        ] {
            assert_eq!(classify_candidate(inert), CandidateClass::Inert, "{inert}");
        }
    }

    #[test]
    fn tokens_are_dash_prefixed_sixteen_lower_hex_runs() {
        let tokens = extra_filename_tokens(
            b"x-0123456789abcdef\x01-fedcba9876543210ff-0123456789ABCDEF-short-abc\x00-aaaaaaaaaaaaaaaa",
        );
        assert_eq!(
            tokens.into_iter().collect::<Vec<_>>(),
            vec!["0123456789abcdef", "aaaaaaaaaaaaaaaa", "fedcba9876543210"]
        );
        assert!(extra_filename_tokens(b"").is_empty());
        assert!(extra_filename_tokens(b"---------").is_empty());
        assert!(extra_filename_tokens(b"-0123456789abcde").is_empty());
    }

    #[test]
    fn rlib_metadata_is_the_rmeta_section_of_its_metadata_member() {
        let meta = metadata(&["aaaaaaaaaaaaaaaa"]);
        let member = elf64(&[(".text", b"code"), (".rmeta", &meta)]);
        let rlib = ar(&[
            ("lib.rmeta", &member),
            ("lib.rmeta-link", b"other"),
            ("x.o", b"obj"),
        ]);
        assert_eq!(
            crate_metadata(CrateFlavor::Rlib, &rlib),
            Some(meta.as_slice())
        );
        // Targets that store raw metadata in the member.
        let raw = ar(&[("lib.rmeta", &meta)]);
        assert_eq!(
            crate_metadata(CrateFlavor::Rlib, &raw),
            Some(meta.as_slice())
        );
        assert_eq!(
            crate_metadata(CrateFlavor::Rmeta, &meta),
            Some(meta.as_slice())
        );
        // The metadata identity is the same for both containers.
        let exact = digest("x");
        assert_eq!(
            read_candidate(CrateFlavor::Rlib, &rlib, exact.clone()).identity,
            read_candidate(CrateFlavor::Rmeta, &meta, exact).identity
        );
    }

    #[test]
    fn metadata_stubs_defer_to_the_rmeta_and_real_metadata_never_does() {
        let exact = digest("bytes");
        let mut stub = METADATA_MAGIC.to_vec();
        stub.extend_from_slice(b"\x0a>\0\0\0\0\0\0\0,rustc 1.100.0-nightly\xc1\x00\x18x86_64-unknown-linux-gnu\x01rust-end-file");
        assert!(is_metadata_stub(&stub));
        let rlib = ar(&[
            ("lib.rmeta", &elf64(&[(".rmeta", &stub)])),
            ("x.o", b"objects"),
        ]);
        let read = read_candidate(CrateFlavor::Rlib, &rlib, exact.clone());
        assert_eq!(read.identity, CandidateIdentity::ObjectsOnly(exact.clone()));
        assert!(read.tokens.is_empty());
        // Any crate reference, an unterminated blob, or a large one is real.
        let mut referencing = stub[..stub.len() - 13].to_vec();
        referencing.extend_from_slice(b"\x11-aaaaaaaaaaaaaaaarust-end-file");
        assert!(!is_metadata_stub(&referencing));
        assert!(!is_metadata_stub(&stub[..stub.len() - 1]));
        let mut large = stub[..stub.len() - 13].to_vec();
        large.resize(MAX_METADATA_STUB_BYTES, b'x');
        large.extend_from_slice(b"rust-end-file");
        assert!(!is_metadata_stub(&large));
        // A stub is never read for an `.rmeta` file itself.
        assert!(matches!(
            read_candidate(CrateFlavor::Rmeta, &stub, exact).identity,
            CandidateIdentity::Metadata(_)
        ));
    }

    #[test]
    fn malformed_containers_fall_back_to_exact_bytes_or_not_rust() {
        let exact = digest("bytes");
        // A well-formed archive without a metadata member (embed-metadata=no)
        // carries only object code: no compile input, no crate references.
        let archive = ar(&[("x.o", b"-bbbbbbbbbbbbbbbb")]);
        let read = read_candidate(CrateFlavor::Rlib, &archive, exact.clone());
        assert_eq!(read.identity, CandidateIdentity::ObjectsOnly(exact.clone()));
        assert!(read.tokens.is_empty());
        // A metadata member that cannot be decoded is keyed by its bytes,
        // and its references are scanned from every byte.
        let opaque = ar(&[("lib.rmeta", b"neither ELF nor -bbbbbbbbbbbbbbbb raw")]);
        let read = read_candidate(CrateFlavor::Rlib, &opaque, exact.clone());
        assert_eq!(read.identity, CandidateIdentity::Bytes(exact.clone()));
        assert!(read.tokens.contains("bbbbbbbbbbbbbbbb"));
        // A truncated archive is not well formed: keyed by its bytes.
        let mut truncated = ar(&[("x.o", b"objects")]);
        truncated.truncate(truncated.len() - 3);
        assert_eq!(
            read_candidate(CrateFlavor::Rlib, &truncated, exact.clone()).identity,
            CandidateIdentity::Bytes(exact.clone())
        );
        // Truncated archives, bad headers and out-of-range sizes.
        assert!(ar_member(b"!<arch>\nshort", "lib.rmeta").is_none());
        let mut bad = ar(&[("lib.rmeta", b"x")]);
        let len = bad.len();
        bad[len - 3] = b'?';
        assert!(ar_member(&bad, "lib.rmeta").is_none());
        // Not a container at all: rejected by the locator.
        assert_eq!(
            read_candidate(CrateFlavor::Rlib, b"junk", exact.clone()).identity,
            CandidateIdentity::NotRust
        );
        assert_eq!(
            read_candidate(CrateFlavor::Rmeta, b"junk", exact.clone()).identity,
            CandidateIdentity::NotRust
        );
        // A cdylib has no `.rustc` section; a Rust dylib does.
        let cdylib = elf64(&[(".text", b"code")]);
        assert_eq!(
            read_candidate(CrateFlavor::Dylib, &cdylib, exact.clone()).identity,
            CandidateIdentity::NotRust
        );
        let dylib = elf64(&[(".rustc", &metadata(&[]))]);
        assert_eq!(
            read_candidate(CrateFlavor::Dylib, &dylib, exact.clone()).identity,
            CandidateIdentity::Bytes(exact)
        );
        // Duplicate sections are ambiguous.
        assert!(elf_section(&elf64(&[(".rmeta", b"a"), (".rmeta", b"b")]), ".rmeta").is_none());
        assert!(elf_section(b"\x7fELF", ".rmeta").is_none());
    }

    struct Fixture {
        paths: Vec<String>,
        listings: Vec<Vec<String>>,
        files: BTreeMap<(usize, String), Vec<u8>>,
    }

    impl Fixture {
        fn new(directories: usize) -> Self {
            Self {
                paths: (0..directories).map(|d| format!("/t/{d}")).collect(),
                listings: vec![Vec::new(); directories],
                files: BTreeMap::new(),
            }
        }
        fn add(&mut self, directory: usize, name: &str, bytes: Vec<u8>) {
            self.listings[directory].push(name.into());
            self.files.insert((directory, name.into()), bytes);
        }
        fn close(
            &self,
            seeds: &[(usize, &str)],
        ) -> Result<Vec<DependencyDirectoryFact>, ClosureRefusal> {
            let seeds: Vec<(usize, String)> =
                seeds.iter().map(|(d, n)| (*d, (*n).to_owned())).collect();
            referenced_candidates(&self.paths, &self.listings, &seeds, |d, name, flavor| {
                let bytes = self
                    .files
                    .get(&(d, name.to_owned()))
                    .ok_or_else(|| format!("missing {name}"))?;
                Ok(read_candidate(flavor, bytes, compute("test.exact", bytes)))
            })
        }
    }

    const A: &str = "aaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccc";
    const P: &str = "dddddddddddddddd";

    fn stems(facts: &[DependencyDirectoryFact]) -> Vec<Vec<String>> {
        facts
            .iter()
            .map(|d| d.groups.iter().map(|g| g.stem.clone()).collect())
            .collect()
    }

    #[test]
    fn only_referenced_groups_enter_the_closure_and_churn_is_ignored() {
        let mut fx = Fixture::new(1);
        // b depends on a; the compile's direct extern is b.
        fx.add(0, &format!("liba-{A}.rmeta"), metadata(&[]));
        fx.add(0, &format!("libb-{B}.rmeta"), metadata(&[A]));
        let baseline = fx.close(&[(0, &format!("libb-{B}.rmeta"))]).unwrap();
        assert_eq!(stems(&baseline), vec![vec![format!("liba-{A}")]]);
        // Unrelated crates, executables, temporaries, dep-info and an
        // unrelated proc-macro: the closure and its encoding are unchanged.
        fx.add(0, &format!("libc-{C}.rmeta"), metadata(&[A]));
        fx.add(0, &format!("libmacro-{P}.so"), b"\x7fELF junk".to_vec());
        fx.add(0, "proj-0123456789abcdef", b"bin".to_vec());
        fx.add(0, "a-aaaaaaaaaaaaaaaa.a.1234-cgu.0.rcgu.o", b"o".to_vec());
        fx.add(0, &format!("a-{A}.d"), b"d".to_vec());
        let churned = fx.close(&[(0, &format!("libb-{B}.rmeta"))]).unwrap();
        assert_eq!(churned, baseline);
        // The .rlib arriving later with the same metadata keeps the key.
        let meta = metadata(&[]);
        fx.add(
            0,
            &format!("liba-{A}.rlib"),
            ar(&[("lib.rmeta", &elf64(&[(".rmeta", &meta)]))]),
        );
        let with_rlib = fx.close(&[(0, &format!("libb-{B}.rmeta"))]).unwrap();
        let encode = |facts: &[DependencyDirectoryFact]| encode_candidates(facts, |p| p.to_owned());
        assert_eq!(encode(&with_rlib), encode(&baseline));
        // An objects-only rlib (embed-metadata=no) keeps the key too.
        fx.files.insert(
            (0, format!("liba-{A}.rlib")),
            ar(&[("liba.o", b"object code")]),
        );
        let objects_only = fx.close(&[(0, &format!("libb-{B}.rmeta"))]).unwrap();
        assert_eq!(encode(&objects_only), encode(&baseline));
    }

    #[test]
    fn referenced_content_changes_and_disagreeing_members_change_the_key() {
        let encode = |facts: &[DependencyDirectoryFact]| encode_candidates(facts, |p| p.to_owned());
        let mut fx = Fixture::new(1);
        fx.add(0, &format!("liba-{A}.rmeta"), metadata(&[]));
        fx.add(0, &format!("libb-{B}.rmeta"), metadata(&[A]));
        let seed = [(0, format!("libb-{B}.rmeta"))];
        let seeds: Vec<(usize, &str)> = seed.iter().map(|(d, n)| (*d, n.as_str())).collect();
        let before = encode(&fx.close(&seeds).unwrap());
        fx.files.insert(
            (0, format!("liba-{A}.rmeta")),
            metadata(&["0000000000000000"]),
        );
        assert_ne!(encode(&fx.close(&seeds).unwrap()), before);
        // An rlib whose metadata disagrees with the rmeta: both are keyed.
        let mut fx = Fixture::new(1);
        fx.add(0, &format!("liba-{A}.rmeta"), metadata(&[]));
        fx.add(
            0,
            &format!("liba-{A}.rlib"),
            ar(&[("lib.rmeta", &metadata(&[C]))]),
        );
        fx.add(0, &format!("libb-{B}.rmeta"), metadata(&[A]));
        let facts = fx.close(&seeds).unwrap();
        assert!(matches!(
            &facts[0].groups[0].identity,
            GroupIdentity::Members(members) if members.len() == 2
        ));
    }

    #[test]
    fn transitive_references_close_across_directories() {
        let mut fx = Fixture::new(2);
        fx.add(1, &format!("liba-{A}.rmeta"), metadata(&[]));
        fx.add(
            1,
            &format!("libc-{C}.rlib"),
            ar(&[("lib.rmeta", &metadata(&[A]))]),
        );
        fx.add(0, &format!("libb-{B}.rmeta"), metadata(&[C]));
        let facts = fx.close(&[(0, &format!("libb-{B}.rmeta"))]).unwrap();
        assert_eq!(
            stems(&facts),
            vec![
                Vec::<String>::new(),
                vec![format!("liba-{A}"), format!("libc-{C}")]
            ]
        );
    }

    #[test]
    fn a_reachable_proc_macro_refuses_but_an_unreachable_one_does_not() {
        let mut fx = Fixture::new(1);
        fx.add(0, &format!("libmacro-{P}.so"), b"\x7fELF".to_vec());
        fx.add(0, &format!("libb-{B}.rmeta"), metadata(&[P]));
        fx.add(0, &format!("libc-{C}.rmeta"), metadata(&[]));
        assert!(matches!(
            fx.close(&[(0, &format!("libb-{B}.rmeta"))]),
            Err(ClosureRefusal::Dylib(path)) if path.ends_with(".so")
        ));
        assert!(fx.close(&[(0, &format!("libc-{C}.rmeta"))]).is_ok());
    }

    #[test]
    fn unpatterned_rust_files_are_keyed_and_non_rust_ones_are_not() {
        let mut fx = Fixture::new(1);
        fx.add(0, &format!("libc-{C}.rmeta"), metadata(&[]));
        fx.add(0, "libplain.rlib", ar(&[("lib.rmeta", &metadata(&[]))]));
        fx.add(0, "libcdy.so", elf64(&[(".text", b"code")]));
        let facts = fx.close(&[(0, &format!("libc-{C}.rmeta"))]).unwrap();
        assert_eq!(stems(&facts), vec![vec!["libplain.rlib".to_owned()]]);
        // An unreadable needed file refuses rather than guessing.
        fx.listings[0].push(format!("liba-{A}.rmeta"));
        fx.files
            .insert((0, format!("libc-{C}.rmeta")), metadata(&[A]));
        assert!(matches!(
            fx.close(&[(0, &format!("libc-{C}.rmeta"))]),
            Err(ClosureRefusal::Read(_))
        ));
    }
}
