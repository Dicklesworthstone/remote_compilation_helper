//! Writable-hardlink aliasing + malicious-manifest fuzz corpus (bead
//! T021; risks R65/R75; drives H027 validation, D023 materialization,
//! and H004 coverage validation).
//!
//! A deterministic splitmix64 fuzzer builds benign manifests, injects
//! one attack from each R75 class at random, and asserts:
//!
//! - every manifest with an injected attack REJECTS;
//! - every clean manifest PASSES (no false positives — a validator
//!   that rejects everything would also pass a naive suite);
//! - every attack class actually appeared in the corpus (coverage is
//!   asserted, not hoped);
//! - overlapping/gapped/truncated pack ranges reject at coverage
//!   validation while the true cut passes;
//! - the R65 aliasing attempt (a writable hardlink onto CAS bytes)
//!   is UNREPRESENTABLE in the materialization mode enum.

use rabs_cas::chunking::{PROFILE_V1, chunk, validate_coverage};
use rabs_cas::manifest_validation::{ManifestMember, ManifestMemberKind, validate_manifest};
use rabs_cas::materialization::{MaterializationMode, decide_materialization};

/// splitmix64 (the same generator J025 uses; deterministic).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn file(path: &str) -> ManifestMember {
    ManifestMember {
        path: path.to_owned(),
        kind: ManifestMemberKind::File,
    }
}

/// A benign manifest: nested dirs, files, a safe symlink, a declared
/// hardlink.
fn benign(rng: &mut Rng) -> Vec<ManifestMember> {
    let stem = rng.below(1_000_000);
    vec![
        ManifestMember {
            path: format!("dir{stem}"),
            kind: ManifestMemberKind::Directory,
        },
        file(&format!("dir{stem}/lib.rlib")),
        file(&format!("dir{stem}/data-{}.bin", rng.below(1_000))),
        ManifestMember {
            path: format!("dir{stem}/link"),
            kind: ManifestMemberKind::Symlink {
                target: "lib.rlib".into(), // stays inside
            },
        },
        ManifestMember {
            path: format!("dir{stem}/alias"),
            kind: ManifestMemberKind::Hardlink {
                to: format!("dir{stem}/lib.rlib"), // declared earlier
            },
        },
    ]
}

/// The R75 attack classes (count pinned in the corpus assertion).
const ATTACK_CLASSES: u64 = 10;

/// Inject attack `class` into a benign manifest.
fn inject(members: &mut Vec<ManifestMember>, class: u64, rng: &mut Rng) {
    let attack = match class {
        0 => file("/etc/cron.d/backdoor"),          // absolute
        1 => file("../../.bashrc"),                 // traversal
        2 => file("evil\0hidden"),                  // NUL byte
        3 => members[1].clone(),                    // duplicate
        4 => file(&members[1].path.to_uppercase()), // case twin
        5 => {
            // Unicode twin of a fresh café member.
            members.push(file("caf\u{e9}.rs")); // NFC
            file("cafe\u{301}.rs") // NFD spelling of the same name
        }
        6 => ManifestMember {
            path: "escape-link".into(),
            kind: ManifestMemberKind::Symlink {
                target: "../".repeat(usize::try_from(rng.below(4)).expect("small") + 1) + "outside",
            },
        },
        7 => ManifestMember {
            path: "abs-link".into(),
            kind: ManifestMemberKind::Symlink {
                target: "/etc/passwd".into(),
            },
        },
        8 => ManifestMember {
            path: "dev-node".into(),
            kind: ManifestMemberKind::SpecialNode,
        },
        9 => ManifestMember {
            path: "wild-alias".into(),
            kind: ManifestMemberKind::Hardlink {
                to: "never-declared".into(), // undeclared target
            },
        },
        _ => unreachable!("class count pinned"),
    };
    let pos = usize::try_from(rng.below(members.len() as u64 + 1)).expect("small");
    members.insert(pos.min(members.len()), attack);
}

#[test]
fn the_fuzz_corpus_rejects_every_attack_and_admits_every_clean_manifest() {
    // THE acceptance: 1000 deterministic corpus entries, roughly half
    // attacked; attacked ⇒ reject, clean ⇒ pass, and every attack
    // class must have fired at least once.
    let mut rng = Rng(0x7042_2021);
    let mut class_hits = [0u32; ATTACK_CLASSES as usize];
    let mut clean_count = 0u32;
    for _ in 0..1_000 {
        let mut members = benign(&mut rng);
        let attacked = rng.below(2) == 1;
        if attacked {
            let class = rng.below(ATTACK_CLASSES);
            inject(&mut members, class, &mut rng);
            assert!(
                validate_manifest(&members).is_err(),
                "attack class {class} slipped through: {members:?}"
            );
            class_hits[usize::try_from(class).expect("small")] += 1;
        } else {
            assert_eq!(
                validate_manifest(&members),
                Ok(()),
                "false positive on a clean manifest: {members:?}"
            );
            clean_count += 1;
        }
    }
    // Corpus coverage is asserted, not hoped.
    for (class, hits) in class_hits.iter().enumerate() {
        assert!(*hits > 0, "attack class {class} never exercised");
    }
    assert!(clean_count > 300, "the clean half really ran");
}

#[test]
fn overlapping_and_gapped_pack_ranges_reject() {
    // R75's pack-range arm: cut a real object, then fuzz the span
    // list — overlap, gap, zero-length, truncation, padding — every
    // mutation rejects while the true cut passes.
    let mut rng = Rng(0x7042_2022);
    // Larger than the profile's max chunk size, so the cut MUST
    // produce several spans.
    let data: Vec<u8> = (0..600 * 1024).map(|_| (rng.next() & 0xFF) as u8).collect();
    let manifest = chunk(&data, &PROFILE_V1);
    assert_eq!(validate_coverage(&manifest, data.len()), Ok(()));
    assert!(manifest.spans.len() >= 2, "fixture must have several spans");
    // Overlap: second span starts one byte early.
    let mut overlap = manifest.clone();
    overlap.spans[1].offset -= 1;
    assert!(validate_coverage(&overlap, data.len()).is_err());
    // Gap: second span starts one byte late.
    let mut gap = manifest.clone();
    gap.spans[1].offset += 1;
    assert!(validate_coverage(&gap, data.len()).is_err());
    // Zero-length span injected.
    let mut zero = manifest.clone();
    let tail_offset = zero.spans[1].offset;
    zero.spans.insert(
        1,
        rabs_cas::chunking::ChunkSpan {
            offset: tail_offset,
            length: 0,
        },
    );
    assert!(validate_coverage(&zero, data.len()).is_err());
    // Truncation: last span dropped.
    let mut truncated = manifest.clone();
    truncated.spans.pop();
    assert!(validate_coverage(&truncated, data.len()).is_err());
    // Padding: claimed length larger than the object.
    assert!(validate_coverage(&manifest, data.len() + 1).is_err());
}

#[test]
fn writable_hardlink_aliasing_is_unrepresentable() {
    // R65: sweep every (mutable, reflink, verified) combination —
    // no decision ever yields a mode that both aliases CAS bytes and
    // permits mutation, because no such variant EXISTS.
    for mutable in [false, true] {
        for reflink in [false, true] {
            for verified in [false, true] {
                let mode = decide_materialization(mutable, reflink, verified);
                match mode {
                    // The only mutation-permitting modes are private
                    // forms (copy or verified-isolated CoW).
                    MaterializationMode::PrivateCopy | MaterializationMode::VerifiedCowReflink => {
                        assert!(mutable, "immutable destinations get binds");
                    }
                    MaterializationMode::ReadOnlyBind => {
                        assert!(!mode.mutation_permitted());
                    }
                }
            }
        }
    }
    // An UNVERIFIED reflink falls back to copy, never to aliasing.
    assert_eq!(
        decide_materialization(true, true, false),
        MaterializationMode::PrivateCopy
    );
}
