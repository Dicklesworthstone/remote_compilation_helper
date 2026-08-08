//! zstd compression policy + metrics (bead H005; plan §62's transfer
//! economics; composes with H030's encoded representations).
//!
//! Compression is an ECONOMIC decision, made per object from cheap
//! evidence, never a reflex:
//!
//! - tiny objects skip (the frame + CPU overhead exceeds any saving);
//! - already-compressed payloads skip, detected from leading magic
//!   bytes (zstd/gzip/xz/zip/png/jpeg re-compression burns CPU for
//!   ~nothing);
//! - everything else compresses under a profile chosen by object
//!   class and CPU pressure — pressure degrades the LEVEL before it
//!   degrades the decision, and only critical pressure skips
//!   less-valuable classes outright;
//! - every zstd profile here verifies content over the UNCOMPRESSED
//!   logical bytes: publishing goes through H030's
//!   `put_encoded_representation`, whose decoder-verification against
//!   the declared logical identity IS that check (the
//!   [`VerificationBasis`] on the profile makes the contract explicit
//!   and testable rather than implied);
//! - outcomes are METERED: logical/encoded byte totals, caller-
//!   supplied CPU time, and per-decision counts, with the derived
//!   CPU-per-GiB and savings figures naming their denominators
//!   (compressed logical bytes) and carrying the countermetric
//!   (skipped bytes) so a policy that "saves" by skipping everything
//!   is visible, not celebrated.
//!
//! An optional worker-local UNCOMPRESSED hot cache rounds out the
//! economics: repeat consumers of a hot object skip both decode and
//! transfer, bounded by bytes and evicted least-recently-used.

use std::collections::VecDeque;

/// Storage classes with distinct compression economics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectClass {
    /// Compiler artifacts (`.rlib`/`.rmeta`/objects): large, highly
    /// compressible, transferred often — the primary payer.
    CompilerArtifact,
    /// Dep-info / small metadata: compressible but small-ish.
    DepInfo,
    /// Source/text blobs.
    Source,
    /// Toolchain blobs (often shipped compressed already).
    ToolchainBlob,
    /// No class evidence.
    Unknown,
}

/// Coarse CPU pressure at decision time (the worker's own signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPressure {
    /// Normal operation.
    Low,
    /// Contended: spend less CPU per byte.
    Elevated,
    /// Critical: compression only where it pays most.
    Critical,
}

/// What the profile's content verification is computed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationBasis {
    /// Decode-verify against the UNCOMPRESSED logical identity — the
    /// H030 `put_encoded_representation` contract, and the default
    /// for every zstd profile.
    UncompressedLogical,
    /// Verify the encoded bytes only (reserved for profiles whose
    /// definition says so; no current profile does).
    EncodedBytes,
}

/// A named compression profile (the string names match H030
/// representation profiles / H010 location encodings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionProfile {
    /// Profile name recorded in location/representation metadata.
    pub name: &'static str,
    /// zstd compression level.
    pub level: i32,
    /// What content verification covers.
    pub verify: VerificationBasis,
}

/// Standard-throughput profile (default).
pub const ZSTD_BALANCED: CompressionProfile = CompressionProfile {
    name: "zstd-3",
    level: 3,
    verify: VerificationBasis::UncompressedLogical,
};

/// Cheap profile under CPU pressure.
pub const ZSTD_FAST: CompressionProfile = CompressionProfile {
    name: "zstd-1",
    level: 1,
    verify: VerificationBasis::UncompressedLogical,
};

/// Objects at or below this size skip compression outright.
pub const MIN_COMPRESS_BYTES: u64 = 4096;

/// Why an object was not compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// At or below [`MIN_COMPRESS_BYTES`].
    Tiny,
    /// Leading bytes identify an already-compressed container.
    AlreadyCompressed,
    /// Critical CPU pressure and a class that does not pay enough.
    CpuPressure,
}

/// The per-object decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionDecision {
    /// Store raw, for the stated reason.
    Skip(SkipReason),
    /// Compress under the profile.
    Compress(CompressionProfile),
}

/// Leading-byte signatures of already-compressed containers.
const MAGIC_PREFIXES: &[&[u8]] = &[
    &[0x28, 0xB5, 0x2F, 0xFD],             // zstd frame
    &[0x1F, 0x8B],                         // gzip
    &[0xFD, b'7', b'z', b'X', b'Z', 0x00], // xz
    &[b'P', b'K', 0x03, 0x04],             // zip/jar
    &[0x89, b'P', b'N', b'G'],             // png
    &[0xFF, 0xD8, 0xFF],                   // jpeg
];

/// Whether the leading bytes identify an already-compressed payload.
#[must_use]
pub fn looks_precompressed(leading: &[u8]) -> bool {
    MAGIC_PREFIXES
        .iter()
        .any(|magic| leading.len() >= magic.len() && &leading[..magic.len()] == *magic)
}

/// THE H005 policy: decide from size, leading bytes, class, and CPU
/// pressure. Total and pure — same evidence, same decision.
#[must_use]
pub fn decide(
    class: ObjectClass,
    logical_size: u64,
    leading: &[u8],
    pressure: CpuPressure,
) -> CompressionDecision {
    if logical_size <= MIN_COMPRESS_BYTES {
        return CompressionDecision::Skip(SkipReason::Tiny);
    }
    if looks_precompressed(leading) {
        return CompressionDecision::Skip(SkipReason::AlreadyCompressed);
    }
    match pressure {
        CpuPressure::Low => CompressionDecision::Compress(ZSTD_BALANCED),
        // Pressure degrades the LEVEL first…
        CpuPressure::Elevated => CompressionDecision::Compress(ZSTD_FAST),
        // …and only critical pressure skips the classes that pay the
        // least; artifacts still compress (cheapest level) because
        // they dominate transfer volume.
        CpuPressure::Critical => match class {
            ObjectClass::CompilerArtifact => CompressionDecision::Compress(ZSTD_FAST),
            ObjectClass::DepInfo
            | ObjectClass::Source
            | ObjectClass::ToolchainBlob
            | ObjectClass::Unknown => CompressionDecision::Skip(SkipReason::CpuPressure),
        },
    }
}

/// Accumulated compression metrics. CPU time is CALLER-supplied (the
/// policy core has no clock); denominators are predeclared in the
/// emitted report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompressionMetrics {
    /// Logical bytes that went through a compressor.
    pub compressed_logical_bytes: u64,
    /// Encoded bytes those produced.
    pub compressed_encoded_bytes: u64,
    /// CPU micros spent compressing (caller-measured).
    pub compress_cpu_micros: u64,
    /// Logical bytes stored raw, by skip reason.
    pub skipped_tiny_bytes: u64,
    /// Bytes skipped as already-compressed.
    pub skipped_precompressed_bytes: u64,
    /// Bytes skipped under CPU pressure.
    pub skipped_pressure_bytes: u64,
    /// Objects per decision arm.
    pub compressed_objects: u64,
    /// Skipped object count.
    pub skipped_objects: u64,
}

impl CompressionMetrics {
    /// Record one decided-and-executed object.
    pub const fn record(
        &mut self,
        decision: CompressionDecision,
        logical_bytes: u64,
        encoded_bytes: u64,
        cpu_micros: u64,
    ) {
        match decision {
            CompressionDecision::Compress(_) => {
                self.compressed_objects += 1;
                self.compressed_logical_bytes += logical_bytes;
                self.compressed_encoded_bytes += encoded_bytes;
                self.compress_cpu_micros += cpu_micros;
            }
            CompressionDecision::Skip(reason) => {
                self.skipped_objects += 1;
                match reason {
                    SkipReason::Tiny => self.skipped_tiny_bytes += logical_bytes,
                    SkipReason::AlreadyCompressed => {
                        self.skipped_precompressed_bytes += logical_bytes;
                    }
                    SkipReason::CpuPressure => self.skipped_pressure_bytes += logical_bytes,
                }
            }
        }
    }

    /// Emit the derived report.
    #[must_use]
    pub const fn emit(&self) -> CompressionReport {
        let saved = self
            .compressed_logical_bytes
            .saturating_sub(self.compressed_encoded_bytes);
        const GIB: u128 = 1024 * 1024 * 1024;
        let cpu_micros_per_gib = if self.compressed_logical_bytes == 0 {
            0
        } else {
            // micros * GiB / bytes, widened against overflow.
            ((self.compress_cpu_micros as u128 * GIB) / self.compressed_logical_bytes as u128)
                as u64
        };
        let savings_permille = if self.compressed_logical_bytes == 0 {
            0
        } else {
            ((saved as u128 * 1000) / self.compressed_logical_bytes as u128) as u64
        };
        CompressionReport {
            cpu_micros_per_gib,
            transfer_bytes_saved: saved,
            savings_permille,
            skipped_bytes_total: self.skipped_tiny_bytes
                + self.skipped_precompressed_bytes
                + self.skipped_pressure_bytes,
            compressed_objects: self.compressed_objects,
            skipped_objects: self.skipped_objects,
        }
    }
}

/// The emitted H005 report. Denominator for `cpu_micros_per_gib` and
/// `savings_permille` is COMPRESSED LOGICAL BYTES (bytes that actually
/// went through a compressor); `skipped_bytes_total` is the
/// countermetric — a run that skips everything shows zero savings and
/// a large skipped total, never an inflated ratio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionReport {
    /// CPU micros per GiB of compressed logical input.
    pub cpu_micros_per_gib: u64,
    /// Logical minus encoded bytes across compressed objects.
    pub transfer_bytes_saved: u64,
    /// Saved permille of compressed logical bytes.
    pub savings_permille: u64,
    /// Countermetric: logical bytes that never entered a compressor.
    pub skipped_bytes_total: u64,
    /// Compressed object count.
    pub compressed_objects: u64,
    /// Skipped object count.
    pub skipped_objects: u64,
}

/// Optional worker-local UNCOMPRESSED hot cache: repeat consumers skip
/// decode + transfer. Bounded by bytes; least-recently-used evicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotCache {
    budget_bytes: u64,
    used_bytes: u64,
    /// (digest key, size), most recent at the BACK.
    entries: VecDeque<(String, u64)>,
    /// Hit/miss counters (the cache's own economics).
    pub hits: u64,
    /// Miss counter.
    pub misses: u64,
}

impl HotCache {
    /// A cache bounded to `budget_bytes` of uncompressed content.
    #[must_use]
    pub const fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            used_bytes: 0,
            entries: VecDeque::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// Resident uncompressed bytes.
    #[must_use]
    pub const fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// Look up a digest key; a hit refreshes recency.
    pub fn lookup(&mut self, key: &str) -> bool {
        if let Some(index) = self.entries.iter().position(|(k, _)| k == key) {
            let entry = self.entries.remove(index).expect("index valid");
            self.entries.push_back(entry);
            self.hits += 1;
            true
        } else {
            self.misses += 1;
            false
        }
    }

    /// Insert an uncompressed object; oldest entries evict until it
    /// fits. Objects larger than the whole budget are refused (never
    /// evict the world for one object). Returns evicted keys.
    pub fn insert(&mut self, key: &str, size: u64) -> Vec<String> {
        let mut evicted = Vec::new();
        if size > self.budget_bytes {
            return evicted;
        }
        if self.entries.iter().any(|(k, _)| k == key) {
            return evicted;
        }
        while self.used_bytes + size > self.budget_bytes {
            let (old_key, old_size) = self.entries.pop_front().expect("used > 0 implies entries");
            self.used_bytes -= old_size;
            evicted.push(old_key);
        }
        self.used_bytes += size;
        self.entries.push_back((key.to_owned(), size));
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h005_tiny_and_precompressed_objects_skip() {
        // Tiny skips regardless of class or pressure.
        for class in [
            ObjectClass::CompilerArtifact,
            ObjectClass::DepInfo,
            ObjectClass::Unknown,
        ] {
            assert_eq!(
                decide(class, MIN_COMPRESS_BYTES, b"plain text", CpuPressure::Low),
                CompressionDecision::Skip(SkipReason::Tiny)
            );
        }
        // Each already-compressed magic skips.
        let magics: [&[u8]; 6] = [
            &[0x28, 0xB5, 0x2F, 0xFD, 0x00],
            &[0x1F, 0x8B, 0x08],
            &[0xFD, b'7', b'z', b'X', b'Z', 0x00, 0x00],
            b"PK\x03\x04rest",
            &[0x89, b'P', b'N', b'G', 0x0D],
            &[0xFF, 0xD8, 0xFF, 0xE0],
        ];
        for magic in magics {
            assert_eq!(
                decide(ObjectClass::ToolchainBlob, 1 << 20, magic, CpuPressure::Low),
                CompressionDecision::Skip(SkipReason::AlreadyCompressed),
                "magic {magic:02x?}"
            );
        }
        // A plain payload one byte over the floor compresses.
        assert_eq!(
            decide(
                ObjectClass::Source,
                MIN_COMPRESS_BYTES + 1,
                b"fn main() {}",
                CpuPressure::Low
            ),
            CompressionDecision::Compress(ZSTD_BALANCED)
        );
    }

    #[test]
    fn h005_pressure_degrades_level_before_decision() {
        let big = 1 << 20;
        // Low → balanced; elevated → fast level, SAME decision.
        assert_eq!(
            decide(ObjectClass::DepInfo, big, b"text", CpuPressure::Low),
            CompressionDecision::Compress(ZSTD_BALANCED)
        );
        assert_eq!(
            decide(ObjectClass::DepInfo, big, b"text", CpuPressure::Elevated),
            CompressionDecision::Compress(ZSTD_FAST)
        );
        // Critical: artifacts still compress (cheap level); the
        // lesser-paying classes skip with the reason named.
        assert_eq!(
            decide(
                ObjectClass::CompilerArtifact,
                big,
                b"elf",
                CpuPressure::Critical
            ),
            CompressionDecision::Compress(ZSTD_FAST)
        );
        for class in [
            ObjectClass::DepInfo,
            ObjectClass::Source,
            ObjectClass::ToolchainBlob,
            ObjectClass::Unknown,
        ] {
            assert_eq!(
                decide(class, big, b"text", CpuPressure::Critical),
                CompressionDecision::Skip(SkipReason::CpuPressure)
            );
        }
    }

    #[test]
    fn h005_zstd_profiles_verify_over_uncompressed_logical_bytes() {
        // The H030 linkage, explicit: every zstd profile's content
        // verification basis is the UNCOMPRESSED logical identity —
        // publishing runs put_encoded_representation, whose decoder
        // verification against the declared logical digest IS this
        // check. No profile opts out.
        for profile in [ZSTD_BALANCED, ZSTD_FAST] {
            assert_eq!(profile.verify, VerificationBasis::UncompressedLogical);
        }
        assert_eq!(ZSTD_BALANCED.name, "zstd-3");
        assert_eq!(ZSTD_FAST.name, "zstd-1");
        assert!(ZSTD_FAST.level < ZSTD_BALANCED.level);
    }

    #[test]
    fn h005_metrics_emit_with_predeclared_denominator_and_countermetric() {
        let mut metrics = CompressionMetrics::default();
        // Two compressed objects: 3 GiB logical → 1 GiB encoded, at
        // 1500 micros per GiB of logical input.
        const GIB: u64 = 1024 * 1024 * 1024;
        metrics.record(
            CompressionDecision::Compress(ZSTD_BALANCED),
            2 * GIB,
            GIB / 2,
            3000,
        );
        metrics.record(CompressionDecision::Compress(ZSTD_FAST), GIB, GIB / 2, 1500);
        // Skips accumulate the countermetric, never the ratio.
        metrics.record(CompressionDecision::Skip(SkipReason::Tiny), 1000, 1000, 0);
        metrics.record(
            CompressionDecision::Skip(SkipReason::AlreadyCompressed),
            5 * GIB,
            5 * GIB,
            0,
        );
        let report = metrics.emit();
        assert_eq!(report.cpu_micros_per_gib, 1500, "4500 micros / 3 GiB");
        assert_eq!(report.transfer_bytes_saved, 2 * GIB);
        assert_eq!(
            report.savings_permille, 666,
            "2/3 saved of COMPRESSED bytes"
        );
        assert_eq!(report.skipped_bytes_total, 5 * GIB + 1000);
        assert_eq!(report.compressed_objects, 2);
        assert_eq!(report.skipped_objects, 2);

        // The skip-everything pathology is visible: zero savings,
        // large countermetric — never a divide-by-zero or a flattering
        // ratio.
        let mut lazy = CompressionMetrics::default();
        lazy.record(
            CompressionDecision::Skip(SkipReason::CpuPressure),
            10 * GIB,
            10 * GIB,
            0,
        );
        let lazy_report = lazy.emit();
        assert_eq!(lazy_report.savings_permille, 0);
        assert_eq!(lazy_report.cpu_micros_per_gib, 0);
        assert_eq!(lazy_report.skipped_bytes_total, 10 * GIB);
    }

    #[test]
    fn h005_hot_cache_is_bounded_lru_with_honest_hit_accounting() {
        let mut cache = HotCache::new(100);
        assert!(cache.insert("a", 40).is_empty());
        assert!(cache.insert("b", 40).is_empty());
        // Miss then hit accounting.
        assert!(!cache.lookup("c"));
        assert!(cache.lookup("a"), "a is resident");
        assert_eq!((cache.hits, cache.misses), (1, 1));
        // Inserting 40 more evicts the LRU — which is now "b" (the
        // lookup refreshed "a").
        let evicted = cache.insert("c", 40);
        assert_eq!(evicted, vec!["b".to_owned()]);
        assert!(cache.lookup("a"));
        assert!(!cache.lookup("b"));
        assert!(cache.lookup("c"));
        assert_eq!(cache.used_bytes(), 80);
        // An object bigger than the whole budget is refused, evicting
        // nothing.
        assert!(cache.insert("huge", 101).is_empty());
        assert_eq!(cache.used_bytes(), 80);
        // Duplicate insert is a no-op.
        assert!(cache.insert("a", 40).is_empty());
        assert_eq!(cache.used_bytes(), 80);
    }
}
