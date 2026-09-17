//! Bounded CPU evidence from executable formats with indirect headers.
//!
//! The caller owns retrieval scope, reporting and fail-open policy. This
//! decoder only returns a CPU set when every relevant header is understood.
//! Universal images require checking the actual slices, not just trusting
//! their directory's CPU claims. No executable code is loaded or run.

use super::{BinaryFormat, CpuArchitecture, header_u32};
use std::io::{Read, Seek, SeekFrom};

const MAX_FAT_SLICES: usize = 64;

/// None is unavailable evidence, never proof that the requested CPU is absent.
pub(super) fn architectures<R: Read + Seek>(
    reader: &mut R,
    format: BinaryFormat,
    prefix: &[u8],
    file_len: u64,
) -> Option<Vec<CpuArchitecture>> {
    if format != BinaryFormat::MachO {
        return None;
    }
    if macho_layout(prefix).is_some() {
        return thin_macho_cpu(prefix, file_len).map(|(_, cpu)| vec![cpu]);
    }
    fat_macho_cpus(reader, prefix, file_len)
}

fn read_at<const N: usize, R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    end: u64,
) -> Option<[u8; N]> {
    if offset.checked_add(u64::try_from(N).ok()?)? > end {
        return None;
    }
    let mut bytes = [0; N];
    reader.seek(SeekFrom::Start(offset)).ok()?;
    reader.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

fn header_u64(bytes: &[u8], little_endian: bool) -> Option<u64> {
    let bytes = bytes.get(..8)?.try_into().ok()?;
    Some(if little_endian {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn macho_layout(prefix: &[u8]) -> Option<(bool, usize)> {
    match prefix.get(..4)? {
        [0xce, 0xfa, 0xed, 0xfe] => Some((true, 28)),
        [0xcf, 0xfa, 0xed, 0xfe] => Some((true, 32)),
        [0xfe, 0xed, 0xfa, 0xce] => Some((false, 28)),
        [0xfe, 0xed, 0xfa, 0xcf] => Some((false, 32)),
        _ => None,
    }
}

fn thin_macho_cpu(prefix: &[u8], image_len: u64) -> Option<(u32, CpuArchitecture)> {
    let (little_endian, header_len) = macho_layout(prefix)?;
    let header = prefix.get(..header_len)?;
    let file_type = header_u32(&header[12..], little_endian)?;
    // Executables, dylibs and bundles; an object/debug file is not evidence
    // about a runnable output. Current x86/Arm Mach-O targets are little-endian;
    // unsupported historical big-endian CPU types remain inconclusive.
    if !little_endian || !matches!(file_type, 2 | 6 | 8) {
        return None;
    }
    let commands = u64::from(header_u32(&header[16..], little_endian)?);
    let command_bytes = u64::from(header_u32(&header[20..], little_endian)?);
    if commands.checked_mul(8)? > command_bytes
        || u64::try_from(header_len).ok()?.checked_add(command_bytes)? > image_len
    {
        return None;
    }
    let cpu_type = header_u32(&header[4..], little_endian)?;
    let cpu = match (cpu_type, header_len) {
        (7, 28) => CpuArchitecture::X86,
        (0x0100_0007, 32) => CpuArchitecture::X86_64,
        (12, 28) => CpuArchitecture::Arm,
        (0x0100_000c, 32) => CpuArchitecture::Aarch64,
        // Do not collapse ARM64_32 or unknown ABI flags into ordinary arm64.
        _ => return None,
    };
    Some((cpu_type, cpu))
}

fn fat_macho_cpus<R: Read + Seek>(
    reader: &mut R,
    prefix: &[u8],
    file_len: u64,
) -> Option<Vec<CpuArchitecture>> {
    let (little_endian, entry_len) = match prefix.get(..4)? {
        [0xca, 0xfe, 0xba, 0xbe] => (false, 20),
        [0xbe, 0xba, 0xfe, 0xca] => (true, 20),
        [0xca, 0xfe, 0xba, 0xbf] => (false, 32),
        [0xbf, 0xba, 0xfe, 0xca] => (true, 32),
        _ => return None,
    };
    let count = usize::try_from(header_u32(prefix.get(4..)?, little_endian)?).ok()?;
    if !(1..=MAX_FAT_SLICES).contains(&count) {
        return None;
    }
    // At most 2 KiB of directory plus 32 bytes per slice (another 2 KiB).
    // Counts, offsets and lengths from the file never drive unbounded reads.
    let table_len = count.checked_mul(entry_len)?;
    let table_end = 8_u64.checked_add(u64::try_from(table_len).ok()?)?;
    if table_end > file_len {
        return None;
    }
    let mut table = vec![0; table_len];
    reader.seek(SeekFrom::Start(8)).ok()?;
    reader.read_exact(&mut table).ok()?;
    let mut ranges = Vec::with_capacity(count);
    let mut cpus = Vec::new();
    for entry in table.chunks_exact(entry_len) {
        let claimed_cpu = header_u32(entry, little_endian)?;
        let (offset, size, alignment) = if entry_len == 20 {
            (
                u64::from(header_u32(&entry[8..], little_endian)?),
                u64::from(header_u32(&entry[12..], little_endian)?),
                header_u32(&entry[16..], little_endian)?,
            )
        } else {
            if header_u32(&entry[28..], little_endian)? != 0 {
                return None;
            }
            (
                header_u64(&entry[8..], little_endian)?,
                header_u64(&entry[16..], little_endian)?,
                header_u32(&entry[24..], little_endian)?,
            )
        };
        let end = offset.checked_add(size)?;
        let alignment_bytes = 1_u64.checked_shl(alignment)?;
        if offset < table_end
            || end > file_len
            || size < 28
            || offset % alignment_bytes != 0
            || ranges.iter().any(|&(start, stop)| offset < stop && start < end)
        {
            return None;
        }
        ranges.push((offset, end));
        let mut header = [0; 32];
        header[..28].copy_from_slice(&read_at::<28, _>(reader, offset, end)?);
        let (_, header_len) = macho_layout(&header)?;
        if header_len == 32 {
            header[28..].copy_from_slice(&read_at::<4, _>(reader, offset.checked_add(28)?, end)?);
        }
        let (actual_cpu, cpu) = thin_macho_cpu(&header[..header_len], size)?;
        if actual_cpu != claimed_cpu {
            return None;
        }
        // An unrecognized slice aborts the whole proof: it might be the CPU
        // the caller requested. A universal binary with a native slice passes.
        if !cpus.contains(&cpu) {
            cpus.push(cpu);
        }
    }
    Some(cpus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn thin(cpu: u32) -> Vec<u8> {
        let wide = cpu & 0x0100_0000 != 0;
        let mut image = vec![0; if wide { 32 } else { 28 }];
        image[..4].copy_from_slice(&if wide {
            [0xcf, 0xfa, 0xed, 0xfe]
        } else {
            [0xce, 0xfa, 0xed, 0xfe]
        });
        image[4..8].copy_from_slice(&cpu.to_le_bytes());
        image[12..16].copy_from_slice(&2_u32.to_le_bytes());
        image
    }

    fn fat(cpus: &[u32], wide: bool, little: bool) -> Vec<u8> {
        let entry_len = if wide { 32 } else { 20 };
        let table_end = 8 + cpus.len() * entry_len;
        let mut image = vec![0; table_end];
        let magic: u32 = if wide { 0xcafe_babf } else { 0xcafe_babe };
        let u32_bytes = |value: u32| {
            if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            }
        };
        let u64_bytes = |value: u64| {
            if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            }
        };
        image[..4].copy_from_slice(&u32_bytes(magic));
        image[4..8].copy_from_slice(&u32_bytes(u32::try_from(cpus.len()).unwrap()));
        for (index, cpu) in cpus.iter().copied().enumerate() {
            let slice = thin(cpu);
            let offset = image.len();
            let entry = &mut image[8 + index * entry_len..8 + (index + 1) * entry_len];
            entry[..4].copy_from_slice(&u32_bytes(cpu));
            if wide {
                entry[8..16].copy_from_slice(&u64_bytes(u64::try_from(offset).unwrap()));
                entry[16..24].copy_from_slice(&u64_bytes(u64::try_from(slice.len()).unwrap()));
            } else {
                entry[8..12].copy_from_slice(&u32_bytes(u32::try_from(offset).unwrap()));
                entry[12..16].copy_from_slice(&u32_bytes(u32::try_from(slice.len()).unwrap()));
            }
            image.extend_from_slice(&slice);
        }
        image
    }

    fn decode(image: &[u8]) -> Option<Vec<CpuArchitecture>> {
        architectures(
            &mut Cursor::new(image),
            BinaryFormat::MachO,
            &image[..image.len().min(64)],
            u64::try_from(image.len()).unwrap(),
        )
    }

    #[test]
    fn macho_cpu_complete_thin_headers_and_truncation() {
        for (raw, cpu) in [
            (7, CpuArchitecture::X86),
            (0x0100_0007, CpuArchitecture::X86_64),
            (12, CpuArchitecture::Arm),
            (0x0100_000c, CpuArchitecture::Aarch64),
        ] {
            let image = thin(raw);
            assert_eq!(decode(&image), Some(vec![cpu]));
            for len in 0..image.len() {
                assert_eq!(decode(&image[..len]), None, "{raw:x}, {len}");
            }
        }
        for (offset, value) in [(4, 0_u32), (12, 1), (16, 1), (20, 100)] {
            let mut image = thin(0x0100_0007);
            image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(decode(&image), None, "invalid field at {offset}");
        }
        let mut wrong_class = thin(0x0100_0007);
        wrong_class[..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]);
        assert_eq!(decode(&wrong_class), None);
    }

    #[test]
    fn macho_cpu_universal_requires_all_slices_and_preserves_native_membership() {
        for wide in [false, true] {
            for little in [false, true] {
                let image = fat(&[0x0100_0007, 0x0100_000c], wide, little);
                assert_eq!(
                    decode(&image),
                    Some(vec![CpuArchitecture::X86_64, CpuArchitecture::Aarch64])
                );
                for len in 0..image.len() {
                    assert_eq!(decode(&image[..len]), None, "{wide}, {little}, {len}");
                }
                // A partly understood CPU directory cannot prove absence.
                assert_eq!(
                    decode(&fat(&[0x0100_0007, 0x0200_000c], wide, little)),
                    None
                );
                assert_eq!(decode(&fat(&[], wide, little)), None);
                assert_eq!(
                    decode(&fat(&[7, 12], wide, little)),
                    Some(vec![CpuArchitecture::X86, CpuArchitecture::Arm])
                );
            }
        }
    }

    #[test]
    fn macho_cpu_universal_rejects_bad_ranges_counts_and_directory_claims() {
        let original = fat(&[0x0100_0007, 0x0100_000c], true, false);
        for (offset, value) in [
            (4, u32::MAX),    // count cannot drive an allocation
            (8, 0x0100_000c), // table CPU disagrees with its actual slice
            (32, 64),        // invalid alignment exponent
            (36, 1),         // reserved fat_arch_64 field
        ] {
            let mut image = original.clone();
            image[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert_eq!(decode(&image), None, "invalid field at {offset}");
        }
        for (offset, value) in [(16, 0), (16, u64::MAX), (24, u64::MAX), (48, 72)] {
            let mut image = original.clone();
            image[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            assert_eq!(decode(&image), None, "invalid range at {offset}");
        }
        assert_eq!(
            decode(&fat(&vec![7; MAX_FAT_SLICES + 1], false, false)),
            None
        );
        let image = fat(&vec![7; MAX_FAT_SLICES], true, false);
        assert_eq!(decode(&image), Some(vec![CpuArchitecture::X86]));
    }

    #[test]
    fn macho_cpu_indirect_reads_are_bounded_and_io_errors_are_inconclusive() {
        struct Meter {
            input: Cursor<Vec<u8>>,
            bytes_read: usize,
            fail_read: bool,
            fail_seek: bool,
        }
        impl Read for Meter {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.fail_read {
                    return Err(std::io::Error::other("injected read failure"));
                }
                let count = self.input.read(buffer)?;
                self.bytes_read += count;
                Ok(count)
            }
        }
        impl Seek for Meter {
            fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
                if self.fail_seek {
                    return Err(std::io::Error::other("injected seek failure"));
                }
                self.input.seek(position)
            }
        }
        let image = fat(&vec![0x0100_000c; MAX_FAT_SLICES], true, false);
        for (fail_read, fail_seek) in [(false, false), (true, false), (false, true)] {
            let mut reader = Meter {
                input: Cursor::new(image.clone()),
                bytes_read: 0,
                fail_read,
                fail_seek,
            };
            let result = architectures(
                &mut reader,
                BinaryFormat::MachO,
                &image[..64],
                u64::try_from(image.len()).unwrap(),
            );
            if fail_read || fail_seek {
                assert_eq!(result, None);
            } else {
                assert_eq!(result, Some(vec![CpuArchitecture::Aarch64]));
                assert_eq!(reader.bytes_read, 4096);
            }
            assert!(reader.bytes_read <= 4096);
            let mut oversized = image[..64].to_vec();
            oversized[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
            let before = reader.bytes_read;
            assert_eq!(
                architectures(&mut reader, BinaryFormat::MachO, &oversized, u64::MAX),
                None
            );
            assert_eq!(reader.bytes_read, before);
        }
    }

    #[test]
    fn macho_cpu_production_guard_checks_both_bases_and_pinned_scope() {
        use super::super::{describe_findings, foreign_target_artifacts};

        let root = tempfile::tempdir().unwrap().keep();
        for (custom, relative) in [(false, "target/release/app"), (true, "release/app")] {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            for image in [thin(0x0100_0007), fat(&[0x0100_0007], false, false)] {
                std::fs::write(&path, image).unwrap();
                let findings = foreign_target_artifacts(
                    &root, &[relative.into()], custom, "aarch64-apple-darwin", None,
                );
                assert_eq!(findings.len(), 1);
                assert!(describe_findings(&findings).contains("Mach-O; CPU x86_64"));
            }
            std::fs::write(&path, fat(&[0x0100_0007, 0x0100_000c], true, false)).unwrap();
            assert!(foreign_target_artifacts(
                &root, &[relative.into()], custom, "aarch64-apple-darwin", None,
            ).is_empty());
        }
        let triple = "aarch64-apple-darwin";
        let requested = format!("target/{triple}/release/app");
        let host_macro = "target/release/deps/libmacro.dylib";
        for (relative, cpu) in [(&requested[..], 0x0100_000c), (host_macro, 0x0100_0007)] {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, thin(cpu)).unwrap();
        }
        let manifest = vec![requested.clone(), host_macro.into()];
        assert!(foreign_target_artifacts(&root, &manifest, false, triple, Some(triple)).is_empty());
        std::fs::write(root.join(&requested), thin(0x0100_0007)).unwrap();
        let findings = foreign_target_artifacts(&root, &manifest, false, triple, Some(triple));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, requested);
    }
}