//! Validate the native input closure carried by a produced Rust archive.
//!
//! Rust can copy a native library unchanged into an object section named
//! `.bundled_lib`, including for source-level `#[link]` attributes. Successful
//! compilation in a namespace does not prove that this payload is closed: a
//! thin archive or a linker script may first read its inputs in a later link.
//! Inspect the output, independently of command-line flags and member names,
//! before granting it cache or replay authority.
//!
//! The supported packed-native profile is deliberately narrower than the
//! object reader: regular GNU/BSD archives of ELF relocatable objects, without
//! nested bundles, native LTO, or dependent-library sections. Top-level Rust
//! metadata/codegen objects are inspected as ELF, COFF, or Mach-O; existing
//! top-level LLVM bitcode is checked for a bounded container envelope. This is
//! not a general linker or a validator of LLVM IR semantics.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::ops::Range;

use object::read::archive::{ArchiveFile, ArchiveKind};
use object::read::macho::MachHeader;
use object::read::{ReadCache, ReadCacheOps, ReadRef};
use object::{FileKind, Object, ObjectKind, ObjectSection, SectionFlags};

const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_READ_SIZE: u64 = 16 * 1024 * 1024;
const MAX_READ_CALLS: u64 = 262_144;
const MAX_MEMBERS: u64 = 65_536;
const MAX_SECTIONS: u64 = 262_144;
const MAX_SYMBOLS: u64 = 1_048_576;
const MAX_NAME: u64 = 4096;

/// Versioned acceptance semantics for digest-bound closure receipts.
pub const NATIVE_ARCHIVE_CLOSURE_CONTRACT: &str = "rabs.native-archive-closure.v1";

/// A produced archive cannot receive native-closure authority.
#[derive(Debug)]
pub enum NativeArchiveError {
    /// The exact file supplied by the caller could not be read.
    Io(std::io::Error),
    /// A container header, name, index, or range is invalid.
    Malformed(&'static str),
    /// Thin archives retain external member paths.
    ThinArchive,
    /// This object/container format has no admitted closure model.
    Unsupported(&'static str),
    /// Native LTO, nested bundles, or linker directives defer additional reads.
    DeferredNativeInput(&'static str),
    /// Inspection exceeded a fixed memory or work budget.
    ResourceLimit(&'static str),
}

impl fmt::Display for NativeArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "native archive input could not be read: {error}"),
            Self::Malformed(reason) => write!(f, "malformed native archive closure: {reason}"),
            Self::ThinArchive => {
                f.write_str("native archive retains external thin-archive members")
            }
            Self::Unsupported(reason) => write!(f, "unsupported native archive closure: {reason}"),
            Self::DeferredNativeInput(reason) => {
                write!(f, "native archive defers additional input reads: {reason}")
            }
            Self::ResourceLimit(reason) => {
                write!(f, "native archive inspection exceeded its {reason} budget")
            }
        }
    }
}

impl std::error::Error for NativeArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

type Result<T> = std::result::Result<T, NativeArchiveError>;

/// Validate an already resident `.rlib` without copying its payloads.
///
/// Prefer [`validate_rlib_native_closure_file`] for production artifacts. Both
/// entry points enforce the same parsing, member, section, and read budgets.
pub fn validate_rlib_native_closure(bytes: &[u8]) -> Result<()> {
    validate_read(bytes, bytes.len() as u64)
}

/// Validate the exact immutable staging/CAS file before exposing its outputs.
///
/// The caller owns immutability and retention of this file for the entire
/// validation and subsequent publication/install. Reads are positional: this
/// does not reopen a path or alter the caller's shared seek cursor. Code/data
/// sections are range-checked rather than copied. At most 64 MiB of requested
/// parsing data is cached, with at most 16 MiB in any individual request;
/// malformed or unusually complex artifacts fail closed at those limits.
pub fn validate_rlib_native_closure_file(file: &File) -> Result<()> {
    let metadata = file.metadata().map_err(NativeArchiveError::Io)?;
    if !metadata.is_file() {
        return Err(NativeArchiveError::Malformed(
            "artifact is not a regular file",
        ));
    }
    let len = metadata.len();
    let cache = ReadCache::new(PositionalFile {
        file,
        len,
        position: 0,
    });
    validate_read(&cache, len)
}

struct PositionalFile<'a> {
    file: &'a File,
    len: u64,
    position: u64,
}

impl ReadCacheOps for PositionalFile<'_> {
    fn len(&mut self) -> std::result::Result<u64, ()> {
        Ok(self.len)
    }

    fn seek(&mut self, position: u64) -> std::result::Result<u64, ()> {
        self.position = position;
        Ok(position)
    }

    fn read(&mut self, bytes: &mut [u8]) -> std::result::Result<usize, ()> {
        #[cfg(unix)]
        let result = std::os::unix::fs::FileExt::read_at(self.file, bytes, self.position);
        #[cfg(windows)]
        let result = std::os::windows::fs::FileExt::seek_read(self.file, bytes, self.position);
        #[cfg(not(any(unix, windows)))]
        let result: std::io::Result<usize> = Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "positional file reads are unavailable",
        ));
        let count = result.map_err(|_| ())?;
        self.position = self.position.checked_add(count as u64).ok_or(())?;
        Ok(count)
    }

    fn read_exact(&mut self, mut bytes: &mut [u8]) -> std::result::Result<(), ()> {
        while !bytes.is_empty() {
            let count = self.read(bytes)?;
            if count == 0 {
                return Err(());
            }
            bytes = &mut bytes[count..];
        }
        Ok(())
    }
}

#[derive(Default)]
struct Budget {
    bytes: Cell<u64>,
    reads: Cell<u64>,
    members: Cell<u64>,
    sections: Cell<u64>,
    symbols: Cell<u64>,
    exhausted: Cell<Option<&'static str>>,
}

impl Budget {
    fn charge(&self, counter: &Cell<u64>, amount: u64, max: u64, name: &'static str) -> Result<()> {
        let Some(next) = counter
            .get()
            .checked_add(amount)
            .filter(|next| *next <= max)
        else {
            self.exhausted.set(Some(name));
            return Err(NativeArchiveError::ResourceLimit(name));
        };
        counter.set(next);
        Ok(())
    }

    fn read(&self, size: u64) -> std::result::Result<(), ()> {
        if size > MAX_READ_SIZE {
            self.exhausted.set(Some("individual read"));
            return Err(());
        }
        self.charge(&self.reads, 1, MAX_READ_CALLS, "read count")
            .map_err(|_| ())?;
        self.charge(&self.bytes, size, MAX_READ_BYTES, "parsing bytes")
            .map_err(|_| ())
    }
}

/// A checked subrange sharing a budget and an underlying immutable reader.
#[derive(Clone, Copy)]
struct View<'a, R> {
    read: R,
    budget: &'a Budget,
    offset: u64,
    len: u64,
}

impl<R: Copy> View<'_, R> {
    fn range(self, offset: u64, len: u64) -> Result<Self> {
        let end = offset
            .checked_add(len)
            .ok_or(NativeArchiveError::Malformed("range overflow"))?;
        if end > self.len {
            return Err(NativeArchiveError::Malformed(
                "range exceeds its containing member",
            ));
        }
        Ok(Self {
            read: self.read,
            budget: self.budget,
            offset: self
                .offset
                .checked_add(offset)
                .ok_or(NativeArchiveError::Malformed("range overflow"))?,
            len,
        })
    }

    fn bytes<'data>(self, offset: u64, size: u64) -> Result<&'data [u8]>
    where
        R: ReadRef<'data>,
    {
        self.read_bytes_at(offset, size)
            .map_err(|()| NativeArchiveError::Malformed("unreadable or out-of-bounds data"))
    }
}

impl<'data, R: ReadRef<'data>> ReadRef<'data> for View<'_, R> {
    fn len(self) -> std::result::Result<u64, ()> {
        Ok(self.len)
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> std::result::Result<&'data [u8], ()> {
        let end = offset.checked_add(size).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        self.budget.read(size)?;
        self.read
            .read_bytes_at(self.offset.checked_add(offset).ok_or(())?, size)
    }

    fn read_bytes_at_until(
        self,
        range: Range<u64>,
        delimiter: u8,
    ) -> std::result::Result<&'data [u8], ()> {
        if range.start > range.end || range.end > self.len {
            return Err(());
        }
        // Object string tables can be enormous; a single name cannot consume
        // them. ReadCache applies the same 4096-byte cap internally.
        let end = range.end.min(range.start.saturating_add(MAX_NAME));
        self.budget.read(0)?;
        if self.budget.bytes.get().saturating_add(MAX_NAME) > MAX_READ_BYTES {
            self.budget.exhausted.set(Some("parsing bytes"));
            return Err(());
        }
        let start = self.offset.checked_add(range.start).ok_or(())?;
        let end = self.offset.checked_add(end).ok_or(())?;
        let result = self.read.read_bytes_at_until(start..end, delimiter);
        // ReadCache fills strings in blocks of up to 256 bytes, including
        // reads that fail to find a delimiter. Charge that work too.
        let charge = match &result {
            Ok(bytes) => (bytes.len() as u64 + 256).min(end - start),
            Err(()) => end - start,
        };
        self.budget
            .charge(&self.budget.bytes, charge, MAX_READ_BYTES, "parsing bytes")
            .map_err(|_| ())?;
        let bytes = result?;
        // ReadCache keys cached strings by start/delimiter, without their
        // original end. Re-check a cache hit against this narrower view.
        if bytes.len() as u64 >= end - start {
            return Err(());
        }
        Ok(bytes)
    }
}

fn validate_read<'a, R: ReadRef<'a>>(read: R, len: u64) -> Result<()> {
    let budget = Budget::default();
    let result = validate_archive(
        View {
            read,
            budget: &budget,
            offset: 0,
            len,
        },
        false,
    );
    // A parser may map a failed bounded read into its own format error. Keep
    // resource refusal distinguishable from malformed bytes for the caller.
    match budget.exhausted.get() {
        Some(reason) => Err(NativeArchiveError::ResourceLimit(reason)),
        None => result,
    }
}

struct MemberRange {
    header: u64,
    data: u64,
    end: u64,
}

fn decimal(bytes: &[u8]) -> Result<u64> {
    let mut value = 0u64;
    let mut digits = 0;
    let mut padding = false;
    for &byte in bytes {
        if byte == b' ' {
            padding = true;
        } else if byte.is_ascii_digit() && !padding {
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(byte - b'0')))
                .ok_or(NativeArchiveError::Malformed("archive decimal overflow"))?;
            digits += 1;
        } else {
            return Err(NativeArchiveError::Malformed("invalid archive decimal"));
        }
    }
    if digits == 0 {
        return Err(NativeArchiveError::Malformed("empty archive decimal"));
    }
    Ok(value)
}

fn archive_layout<'data, R: ReadRef<'data>>(view: View<'_, R>) -> Result<Vec<MemberRange>> {
    match view.bytes(0, 8)? {
        b"!<thin>\n" => return Err(NativeArchiveError::ThinArchive),
        b"!<arch>\n" => {}
        _ => {
            return Err(NativeArchiveError::Unsupported(
                "payload is not a regular archive",
            ));
        }
    }
    let mut offset = 8;
    let mut members = Vec::new();
    while offset < view.len {
        view.budget
            .charge(&view.budget.members, 1, MAX_MEMBERS, "archive members")?;
        let header = view.bytes(offset, 60)?;
        if &header[58..60] != b"`\n" {
            return Err(NativeArchiveError::Malformed(
                "invalid archive header terminator",
            ));
        }
        let size = decimal(&header[48..58])?;
        let data = offset
            .checked_add(60)
            .ok_or(NativeArchiveError::Malformed("archive offset overflow"))?;
        let range = view.range(data, size)?;
        let end = data + range.len;
        members.push(MemberRange {
            header: offset,
            data,
            end,
        });
        offset = end;
        if size & 1 != 0 {
            if !matches!(view.bytes(offset, 1)?, [b'\n'] | [0]) {
                return Err(NativeArchiveError::Malformed(
                    "invalid archive member padding",
                ));
            }
            offset += 1;
        }
    }
    Ok(members)
}

fn validate_archive<'data, R: ReadRef<'data>>(view: View<'_, R>, native: bool) -> Result<()> {
    let layout = archive_layout(view)?;
    let archive = ArchiveFile::parse(view)
        .map_err(|_| NativeArchiveError::Malformed("archive header or names table"))?;
    match archive.kind() {
        ArchiveKind::Unknown
        | ArchiveKind::Gnu
        | ArchiveKind::Gnu64
        | ArchiveKind::Bsd
        | ArchiveKind::Bsd64 => {}
        // COFF has two independently consumed linker tables. Do not treat a
        // successful parse of just its second index as closure authority.
        _ => {
            return Err(NativeArchiveError::Unsupported(
                "archive linker-table format",
            ));
        }
    }
    let mut headers = BTreeSet::new();
    for member in archive.members() {
        let member = member.map_err(|_| NativeArchiveError::Malformed("archive member"))?;
        let name = member.name();
        if name.is_empty()
            || name.len() as u64 > MAX_NAME
            || name == b"."
            || name == b".."
            || name
                .iter()
                .any(|byte| matches!(byte, b'/' | b'\\' | b':' | 0))
        {
            return Err(NativeArchiveError::Malformed(
                "archive member name is not a plain filename",
            ));
        }
        let (offset, size) = member.file_range();
        let body = view.range(offset, size)?;
        let index = layout.partition_point(|range| range.data <= offset);
        let Some(range) = index.checked_sub(1).and_then(|index| layout.get(index)) else {
            return Err(NativeArchiveError::Malformed(
                "archive member has no header",
            ));
        };
        if offset.checked_add(size) != Some(range.end) {
            return Err(NativeArchiveError::Malformed(
                "archive member disagrees with its header",
            ));
        }
        headers.insert(range.header);
        validate_object(body, native)?;
    }
    if let Some(symbols) = archive
        .symbols()
        .map_err(|_| NativeArchiveError::Malformed("archive symbol table"))?
    {
        for symbol in symbols {
            view.budget
                .charge(&view.budget.symbols, 1, MAX_SYMBOLS, "archive symbols")?;
            let symbol = symbol.map_err(|_| NativeArchiveError::Malformed("archive symbol"))?;
            if !headers.contains(&symbol.offset().0) {
                return Err(NativeArchiveError::Malformed(
                    "symbol points outside a real archive member",
                ));
            }
        }
    }
    Ok(())
}

fn validate_object<'data, R: ReadRef<'data>>(view: View<'_, R>, native: bool) -> Result<()> {
    let magic = view.bytes(0, 4)?;
    if magic == b"BC\xc0\xde" || magic == b"\xde\xc0\x17\x0b" {
        if native {
            return Err(NativeArchiveError::DeferredNativeInput(
                "packed native LLVM bitcode",
            ));
        }
        return validate_bitcode_envelope(view);
    }
    let kind = FileKind::parse(view)
        .map_err(|_| NativeArchiveError::Unsupported("opaque archive member"))?;
    match kind {
        FileKind::Elf32 | FileKind::Elf64 => {}
        FileKind::Coff | FileKind::CoffBig | FileKind::MachO32 | FileKind::MachO64 if !native => {}
        _ => {
            return Err(NativeArchiveError::Unsupported(
                "member is not an admitted relocatable object",
            ));
        }
    }
    let file = object::File::parse(view)
        .map_err(|_| NativeArchiveError::Malformed("object headers or tables"))?;
    if file.kind() != ObjectKind::Relocatable {
        return Err(NativeArchiveError::Unsupported(
            "non-relocatable archive member",
        ));
    }
    match &file {
        object::File::MachO32(file) => validate_macho_commands(file.macho_header(), view)?,
        object::File::MachO64(file) => validate_macho_commands(file.macho_header(), view)?,
        _ => {}
    }
    let mut packed = false;
    for section in file.sections() {
        view.budget
            .charge(&view.budget.sections, 1, MAX_SECTIONS, "object sections")?;
        let name = section
            .name_bytes()
            .map_err(|_| NativeArchiveError::Malformed("object section name"))?;
        let range = section
            .file_range()
            .map(|(offset, len)| view.range(offset, len))
            .transpose()?;
        if native
            && matches!(
                section.flags(),
                SectionFlags::Elf { sh_type, .. }
                    if matches!(sh_type,
                        object::elf::SHT_LLVM_DEPENDENT_LIBRARIES
                            | object::elf::SHT_GNU_LIBLIST
                            | object::elf::SHT_DYNAMIC)
            )
        {
            return Err(NativeArchiveError::DeferredNativeInput(
                "native dependent-library section type",
            ));
        }
        if native
            && (name.starts_with(b".gnu.lto_")
                || matches!(
                    name,
                    b".llvmbc"
                        | b".llvm.lto"
                        | b".llvmcmd"
                        | b".deplibs"
                        | b".llvm.dependent-libraries"
                        | b".llvm.offloading"
                ))
        {
            return Err(NativeArchiveError::DeferredNativeInput(
                "native LTO or dependent-library section",
            ));
        }
        if name != b".bundled_lib" {
            continue;
        }
        if native {
            return Err(NativeArchiveError::DeferredNativeInput(
                "nested packed native archive",
            ));
        }
        if packed {
            return Err(NativeArchiveError::Malformed(
                "duplicate packed native section",
            ));
        }
        packed = true;
        if matches!(section.flags(), SectionFlags::Elf { sh_flags, .. } if sh_flags.contains(object::elf::SHF_COMPRESSED))
        {
            return Err(NativeArchiveError::Unsupported(
                "compressed packed native section",
            ));
        }
        let payload = range.ok_or(NativeArchiveError::Malformed(
            "packed native section has no file data",
        ))?;
        // Only this transition can nest an archive. Native members cannot
        // contain another bundle, so recursion is bounded to two archives.
        validate_archive(payload, true)?;
    }
    Ok(())
}

fn validate_macho_commands<'a, Mach: MachHeader, R: ReadRef<'a>>(
    header: &Mach,
    view: View<'_, R>,
) -> Result<()> {
    let endian = header
        .endian()
        .map_err(|_| NativeArchiveError::Malformed("Mach-O byte order"))?;
    let mut commands = header
        .load_commands(endian, view, 0)
        .map_err(|_| NativeArchiveError::Malformed("Mach-O load commands"))?;
    let mut size = 0u64;
    while let Some(command) = commands
        .next()
        .map_err(|_| NativeArchiveError::Malformed("Mach-O load command"))?
    {
        view.budget
            .charge(&view.budget.sections, 1, MAX_SECTIONS, "object sections")?;
        size =
            size.checked_add(u64::from(command.cmdsize()))
                .ok_or(NativeArchiveError::Malformed(
                    "Mach-O command size overflow",
                ))?;
    }
    if size != u64::from(header.sizeofcmds(endian)) {
        return Err(NativeArchiveError::Malformed(
            "Mach-O command table has unparsed bytes",
        ));
    }
    Ok(())
}

/// Validate framing, not LLVM instructions. Native bitcode never reaches here.
fn validate_bitcode_envelope<'data, R: ReadRef<'data>>(mut view: View<'_, R>) -> Result<()> {
    if view.bytes(0, 4)? == b"\xde\xc0\x17\x0b" {
        let header = view.bytes(0, 20)?;
        let word = |offset| {
            u32::from_le_bytes(
                header[offset..offset + 4]
                    .try_into()
                    .expect("fixed header range"),
            )
        };
        if word(4) != 0 || word(8) < 20 {
            return Err(NativeArchiveError::Malformed("LLVM bitcode wrapper"));
        }
        view = view.range(u64::from(word(8)), u64::from(word(12)))?;
    }
    if view.len < 12 || view.len & 3 != 0 || view.bytes(0, 4)? != b"BC\xc0\xde" {
        return Err(NativeArchiveError::Malformed("LLVM bitcode envelope"));
    }
    let end = view
        .len
        .checked_mul(8)
        .ok_or(NativeArchiveError::Malformed("LLVM bit length overflow"))?;
    let mut bits = BitCursor { view, bit: 32 };
    let mut module = false;
    while bits.bit < end {
        view.budget
            .charge(&view.budget.sections, 1, MAX_SECTIONS, "object sections")?;
        if bits.bits(2)? != 1 {
            return Err(NativeArchiveError::Malformed("LLVM top-level block marker"));
        }
        let id = bits.vbr(8)?;
        let width = bits.vbr(4)?;
        if !(2..=32).contains(&width) {
            return Err(NativeArchiveError::Malformed(
                "LLVM block abbreviation width",
            ));
        }
        bits.bit = bits
            .bit
            .checked_add(31)
            .ok_or(NativeArchiveError::Malformed("LLVM bit offset overflow"))?
            & !31;
        let words = bits.bits(32)?;
        let len = words
            .checked_mul(4)
            .ok_or(NativeArchiveError::Malformed("LLVM block size overflow"))?;
        if len == 0 {
            return Err(NativeArchiveError::Malformed("empty LLVM block"));
        }
        let block = view.range(bits.bit / 8, len)?;
        bits.bit = bits
            .bit
            .checked_add(
                block
                    .len
                    .checked_mul(8)
                    .ok_or(NativeArchiveError::Malformed("LLVM bit length overflow"))?,
            )
            .ok_or(NativeArchiveError::Malformed("LLVM bit offset overflow"))?;
        module |= id == 8;
    }
    if !module {
        return Err(NativeArchiveError::Malformed("LLVM module block is absent"));
    }
    Ok(())
}

struct BitCursor<'a, R> {
    view: View<'a, R>,
    bit: u64,
}

impl<R: Copy> BitCursor<'_, R> {
    fn bits<'data>(&mut self, count: u32) -> Result<u64>
    where
        R: ReadRef<'data>,
    {
        let shift = self.bit % 8;
        let size = (shift + u64::from(count)).div_ceil(8);
        let bytes = self.view.bytes(self.bit / 8, size)?;
        let mut word = 0u64;
        for (index, byte) in bytes.iter().enumerate() {
            word |= u64::from(*byte) << (index * 8);
        }
        self.bit = self
            .bit
            .checked_add(u64::from(count))
            .ok_or(NativeArchiveError::Malformed("LLVM bit offset overflow"))?;
        Ok((word >> shift) & ((1u64 << count) - 1))
    }

    fn vbr<'data>(&mut self, width: u32) -> Result<u64>
    where
        R: ReadRef<'data>,
    {
        let mut value = 0u64;
        for shift in (0..32).step_by(width as usize - 1) {
            let bits = self.bits(width)?;
            value |= (bits & ((1 << (width - 1)) - 1)) << shift;
            if bits & (1 << (width - 1)) == 0 {
                return Ok(value);
            }
        }
        Err(NativeArchiveError::Malformed(
            "LLVM variable-width integer overflow",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    fn put16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn ar_header(name: &[u8], size: u64) -> Vec<u8> {
        let mut header = vec![b' '; 60];
        header[..name.len()].copy_from_slice(name);
        for (at, value) in [(16, "0"), (28, "0"), (34, "0"), (40, "644")] {
            header[at..at + value.len()].copy_from_slice(value.as_bytes());
        }
        let size = size.to_string();
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58..].copy_from_slice(b"`\n");
        header
    }

    fn archive(members: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = b"!<arch>\n".to_vec();
        for (name, data) in members {
            // BSD extended names also let negative cases retain the exact
            // path/name bytes that a short SysV name would truncate.
            let size = name.len() + data.len();
            bytes.extend(ar_header(
                format!("#1/{}", name.len()).as_bytes(),
                size as u64,
            ));
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(data);
            if size & 1 != 0 {
                bytes.push(b'\n');
            }
        }
        bytes
    }

    fn elf(sections: &[(&[u8], &[u8], u32, u64)]) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, 1);
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 58, 64);
        put16(&mut bytes, 60, (sections.len() + 2) as u16);
        put16(&mut bytes, 62, (sections.len() + 1) as u16);
        let mut names = vec![0];
        let mut entries = Vec::new();
        for (name, data, kind, flags) in sections {
            let name_offset = names.len();
            names.extend_from_slice(name);
            names.push(0);
            let offset = bytes.len();
            bytes.extend_from_slice(data);
            entries.push((name_offset, offset, data.len(), *kind, *flags));
        }
        let string_name = names.len();
        names.extend_from_slice(b".shstrtab\0");
        entries.push((string_name, bytes.len(), names.len(), 3, 0));
        bytes.extend(names);
        bytes.resize(bytes.len().next_multiple_of(8), 0);
        let table = bytes.len();
        put64(&mut bytes, 40, table as u64);
        bytes.resize(bytes.len() + 64, 0);
        for (name, offset, len, kind, flags) in entries {
            let start = bytes.len();
            bytes.resize(start + 64, 0);
            put32(&mut bytes, start, name as u32);
            put32(&mut bytes, start + 4, kind);
            put64(&mut bytes, start + 8, flags);
            put64(&mut bytes, start + 24, offset as u64);
            put64(&mut bytes, start + 32, len as u64);
            put64(&mut bytes, start + 48, 1);
        }
        bytes
    }

    fn code() -> Vec<u8> {
        elf(&[(b".text", b"\xc3", 1, 6)])
    }

    fn bundle(payload: &[u8]) -> Vec<u8> {
        elf(&[(b".bundled_lib", payload, 1, 0x8000_0000)])
    }

    fn coff_bundle(payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 60];
        put16(&mut bytes, 0, 0x8664);
        put16(&mut bytes, 2, 1);
        put32(&mut bytes, 8, (60 + payload.len()) as u32);
        bytes[20..22].copy_from_slice(b"/4");
        put32(&mut bytes, 36, payload.len() as u32);
        put32(&mut bytes, 40, 60);
        put32(&mut bytes, 56, 0x4000_0840);
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&17u32.to_le_bytes());
        bytes.extend_from_slice(b".bundled_lib\0");
        bytes
    }

    fn macho_bundle(payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 184];
        put32(&mut bytes, 0, 0xfeed_facf);
        put32(&mut bytes, 4, 0x0100_0007);
        put32(&mut bytes, 8, 3);
        put32(&mut bytes, 12, 1);
        put32(&mut bytes, 16, 1);
        put32(&mut bytes, 20, 152);
        put32(&mut bytes, 32, 0x19);
        put32(&mut bytes, 36, 152);
        bytes[40..47].copy_from_slice(b"__DWARF");
        put64(&mut bytes, 64, payload.len() as u64);
        put64(&mut bytes, 72, 184);
        put64(&mut bytes, 80, payload.len() as u64);
        put32(&mut bytes, 88, 7);
        put32(&mut bytes, 92, 7);
        put32(&mut bytes, 96, 1);
        bytes[104..116].copy_from_slice(b".bundled_lib");
        bytes[120..127].copy_from_slice(b"__DWARF");
        put64(&mut bytes, 144, payload.len() as u64);
        put32(&mut bytes, 152, 184);
        put32(&mut bytes, 168, 0x0200_0000);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn bitcode_envelope() -> Vec<u8> {
        // One top-level MODULE_BLOCK (id 8, abbreviation width 2) whose
        // framing is complete. This is a framing fixture, not executable IR.
        b"BC\xc0\xde\x21\x08\0\0\x01\0\0\0\0\0\0\0".to_vec()
    }

    #[test]
    fn regular_native_archive_and_rust_metadata_objects_are_accepted() {
        let native = archive(&[(b"answer.o", &code())]);
        let packed = bundle(&native);
        let metadata = elf(&[(b".rmeta", b"rust\0\0\0\x0a", 1, 0x8000_0000)]);
        let link_metadata = elf(&[(b".rmeta-link", b"metadata", 1, 0x8000_0000)]);
        let bytes = archive(&[
            (b"lib.rmeta", &metadata),
            (b"lib.rmeta-link", &link_metadata),
            (b"crate.rcgu.o", &code()),
            (b"custom-name.a", &packed),
        ]);
        validate_rlib_native_closure(&bytes).unwrap();
    }

    #[test]
    fn sectionless_elf_fixture_has_no_uninspected_bundle_authority() {
        let mut object = vec![0; 64];
        object[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut object, 16, 1);
        put16(&mut object, 18, 62);
        put32(&mut object, 20, 1);
        put16(&mut object, 52, 64);
        put16(&mut object, 58, 64);
        object.extend_from_slice(b"model marker");
        validate_rlib_native_closure(&archive(&[(b"fixture.o", &object)])).unwrap();
    }

    #[test]
    fn hidden_packed_thin_and_linker_script_payloads_never_gain_authority() {
        for payload in [
            &b"!<thin>\n"[..],
            &b"INPUT (/private/outside.o)\n"[..],
            &b"GROUP (../outside.a)\n"[..],
        ] {
            for name in [
                &b"ordinary.rcgu.o"[..],
                &b"lib.rmeta"[..],
                &b"native.custom.a"[..],
            ] {
                for wrapper in [bundle(payload), coff_bundle(payload), macho_bundle(payload)] {
                    let result = validate_rlib_native_closure(&archive(&[(name, &wrapper)]));
                    if payload.starts_with(b"!<thin>") {
                        assert!(
                            matches!(result, Err(NativeArchiveError::ThinArchive)),
                            "{result:?}"
                        );
                    } else {
                        assert!(result.is_err(), "packed script accepted as {name:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn supported_wrapper_formats_inspect_regular_native_payloads() {
        let payload = archive(&[(b"answer.o", &code())]);
        for wrapper in [
            bundle(&payload),
            coff_bundle(&payload),
            macho_bundle(&payload),
        ] {
            validate_rlib_native_closure(&archive(&[(b"misleading.o", &wrapper)])).unwrap();
        }
    }

    #[test]
    fn packed_native_lto_and_dependent_libraries_are_refused() {
        for name in [
            &b".llvmbc"[..],
            &b".llvm.lto"[..],
            &b".gnu.lto_answer.123"[..],
            &b".deplibs"[..],
            &b".llvm.dependent-libraries"[..],
        ] {
            let object = elf(&[(name, b"opaque", 1, 0)]);
            let bytes = archive(&[(b"native.a", &bundle(&archive(&[(b"answer.o", &object)])))]);
            assert!(matches!(
                validate_rlib_native_closure(&bytes),
                Err(NativeArchiveError::DeferredNativeInput(_))
            ));
        }
        // LLVM uses a section type for dependent libraries; a misleading
        // section name must not bypass the same decision.
        let object = elf(&[(b".harmless", b"outside", 0x6fff_4c04, 0)]);
        let bytes = archive(&[(b"native.a", &bundle(&archive(&[(b"answer.o", &object)])))]);
        assert!(matches!(
            validate_rlib_native_closure(&bytes),
            Err(NativeArchiveError::DeferredNativeInput(_))
        ));
        let bitcode = bitcode_envelope();
        let bytes = archive(&[(b"native.a", &bundle(&archive(&[(b"answer.o", &bitcode)])))]);
        assert!(matches!(
            validate_rlib_native_closure(&bytes),
            Err(NativeArchiveError::DeferredNativeInput(_))
        ));
    }

    #[test]
    fn unmodeled_native_formats_and_nested_archives_are_refused() {
        for native_member in [
            archive(&[(b"answer.o", &code())]),
            coff_bundle(b"!<arch>\n"),
            macho_bundle(b"!<arch>\n"),
            b"INPUT (/private/object.o)".to_vec(),
        ] {
            let packed = bundle(&archive(&[(b"not-really-an-object.o", &native_member)]));
            assert!(validate_rlib_native_closure(&archive(&[(b"native.a", &packed)])).is_err());
        }
        let nested = bundle(&archive(&[(b"native.o", &bundle(b"!<arch>\n"))]));
        assert!(matches!(
            validate_rlib_native_closure(&archive(&[(b"native.a", &nested)])),
            Err(NativeArchiveError::DeferredNativeInput(_))
        ));
    }

    #[test]
    fn malformed_ranges_tables_names_and_opaque_metadata_are_refused() {
        let object = code();
        for name in [
            &b"../answer.o"[..],
            &b"/absolute.o"[..],
            &b"C:\\answer.o"[..],
        ] {
            assert!(validate_rlib_native_closure(&archive(&[(name, &object)])).is_err());
        }
        assert!(
            validate_rlib_native_closure(&archive(&[(b"lib.rmeta", b"opaque metadata")])).is_err()
        );
        let mut truncated = b"!<arch>\n".to_vec();
        truncated.extend(ar_header(b"/", 100));
        // Even the symbol table skipped by ArchiveFile must be in bounds.
        assert!(validate_rlib_native_closure(&truncated).is_err());
        let mut trailing = archive(&[(b"answer.o", &object)]);
        trailing.push(0);
        assert!(validate_rlib_native_closure(&trailing).is_err());
        let mut bad_section = object;
        let table = u64::from_le_bytes(bad_section[40..48].try_into().unwrap()) as usize;
        put64(&mut bad_section, table + 64 + 24, u64::MAX - 1);
        put64(&mut bad_section, table + 64 + 32, 16);
        assert!(validate_rlib_native_closure(&archive(&[(b"answer.o", &bad_section)])).is_err());
        let mut truncated_macho = macho_bundle(b"!<arch>\n");
        put32(&mut truncated_macho, 16, 2);
        assert!(
            validate_rlib_native_closure(&archive(&[(b"answer.o", &truncated_macho)])).is_err()
        );
    }

    #[test]
    fn archive_symbol_offsets_must_name_validated_member_headers() {
        for valid in [true, false] {
            let mut symbols = Vec::new();
            symbols.extend_from_slice(&1u32.to_be_bytes());
            symbols.extend_from_slice(&(if valid { 84u32 } else { 68u32 }).to_be_bytes());
            symbols.extend_from_slice(b"answer\0");
            let mut bytes = b"!<arch>\n".to_vec();
            bytes.extend(ar_header(b"/", symbols.len() as u64));
            bytes.extend(symbols);
            bytes.push(b'\n');
            bytes.extend_from_slice(&archive(&[(b"answer.o", &code())])[8..]);
            assert_eq!(validate_rlib_native_closure(&bytes).is_ok(), valid);
        }
    }

    #[test]
    fn duplicate_and_compressed_bundle_sections_are_refused() {
        let native = archive(&[(b"answer.o", &code())]);
        for object in [
            elf(&[
                (b".bundled_lib", &native, 1, 0),
                (b".bundled_lib", &native, 1, 0),
            ]),
            elf(&[(b".bundled_lib", &native, 1, 1 << 11)]),
        ] {
            assert!(validate_rlib_native_closure(&archive(&[(b"native.a", &object)])).is_err());
        }
    }

    #[test]
    fn top_level_bitcode_retains_its_existing_bounded_envelope_profile() {
        let bitcode = bitcode_envelope();
        validate_rlib_native_closure(&archive(&[(b"crate.rcgu.o", &bitcode)])).unwrap();
        let mut wrapped = b"\xde\xc0\x17\x0b".to_vec();
        for word in [0, 20, bitcode.len() as u32, 0] {
            wrapped.extend_from_slice(&word.to_le_bytes());
        }
        wrapped.extend_from_slice(&bitcode);
        validate_rlib_native_closure(&archive(&[(b"crate.rcgu.o", &wrapped)])).unwrap();
        for broken in [
            b"BC\xc0\xde".to_vec(),
            {
                let mut broken = bitcode;
                put32(&mut broken, 8, u32::MAX);
                broken
            },
            {
                put32(&mut wrapped, 8, u32::MAX);
                wrapped
            },
        ] {
            assert!(validate_rlib_native_closure(&archive(&[(b"crate.rcgu.o", &broken)])).is_err());
        }
    }

    #[test]
    fn archive_member_count_is_bounded_before_member_inspection() {
        let mut bytes = b"!<arch>\n".to_vec();
        let header = ar_header(b"empty.o/", 0);
        for _ in 0..=MAX_MEMBERS {
            bytes.extend_from_slice(&header);
        }
        assert!(matches!(
            validate_rlib_native_closure(&bytes),
            Err(NativeArchiveError::ResourceLimit("archive members"))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn file_validation_is_positional_and_does_not_read_large_code_sections() {
        let mut object = code();
        let table = u64::from_le_bytes(object[40..48].try_into().unwrap()) as usize;
        let object_size = 1024 * 1024 * 1024;
        put64(&mut object, table + 64 + 24, 4096);
        put64(&mut object, table + 64 + 32, object_size - 4096);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"!<arch>\n").unwrap();
        file.write_all(&ar_header(b"large.rcgu.o/", object_size))
            .unwrap();
        file.write_all(&object).unwrap();
        file.set_len(68 + object_size).unwrap();
        Seek::seek(&mut file, SeekFrom::Start(17)).unwrap();
        validate_rlib_native_closure_file(&file).unwrap();
        assert_eq!(file.stream_position().unwrap(), 17);

        let cache = ReadCache::new(PositionalFile {
            file: &file,
            len: 68 + object_size,
            position: 0,
        });
        let budget = Budget::default();
        validate_archive(
            View {
                read: &cache,
                budget: &budget,
                offset: 0,
                len: 68 + object_size,
            },
            false,
        )
        .unwrap();
        assert!(
            budget.bytes.get() < 4096,
            "read {} bytes of parsing data",
            budget.bytes.get()
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn oversized_names_table_is_refused_before_readcache_allocates_it() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"!<arch>\n").unwrap();
        let size = MAX_READ_SIZE + 2;
        file.write_all(&ar_header(b"//", size)).unwrap();
        file.set_len(68 + size).unwrap();
        assert!(matches!(
            validate_rlib_native_closure_file(&file),
            Err(NativeArchiveError::ResourceLimit("individual read"))
        ));
    }

    #[test]
    fn cached_string_cannot_cross_a_narrower_member_boundary() {
        let cache = ReadCache::new(std::io::Cursor::new(b".bundled_lib\0"));
        let budget = Budget::default();
        let view = View {
            read: &cache,
            budget: &budget,
            offset: 0,
            len: 13,
        };
        assert_eq!(view.read_bytes_at_until(0..13, 0).unwrap(), b".bundled_lib");
        assert!(
            view.range(0, 4)
                .unwrap()
                .read_bytes_at_until(0..4, 0)
                .is_err()
        );
    }
}
