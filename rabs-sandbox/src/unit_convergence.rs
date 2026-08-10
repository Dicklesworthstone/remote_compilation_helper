//! Cross-worktree Cargo unit-identity convergence verification (bead
//! D019; risk R43; plan §55/§57).
//!
//! R43 is the risk this module exists to falsify: Cargo running outside
//! the canonical namespace derives `-C metadata` seeds, unit hashes,
//! `-C extra-filename` suffixes, output names, and child rustc argv
//! from ABSOLUTE PATHS — so two worktrees of identical source produce
//! divergent unit identity before any wrapper downstream can repair it.
//! Under the canonical driver (D003) both worktrees ARE
//! `/__rabs/workspace`, so every one of those surfaces must converge
//! byte-for-byte. This module is the comparator that PROVES it, from
//! evidence: a logging `RUSTC_WRAPPER` records every child rustc argv,
//! and two records converge only if their normalized invocation sets
//! are identical.
//!
//! The convergence digest deliberately binds the toolchain's verbose
//! version: unit hashes are only comparable within one toolchain, so a
//! cross-machine digest match asserts "same platform class, same
//! toolchain, same unit identity" — and a differing toolchain can
//! never accidentally alias as convergence.
//!
//! Wrapper log format (one line per invocation, written with a single
//! appending `printf`): argv fields joined by the ASCII unit separator
//! `\x1f`. Version probes (`rustc -vV` runs through the wrapper too)
//! carry no `--crate-name` and are skipped.

use sha2::{Digest, Sha256};

/// One recorded child rustc invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustcInvocation {
    /// `--crate-name` value.
    pub crate_name: String,
    /// Every `-C metadata=…` value, in argv order.
    pub metadata: Vec<String>,
    /// Every `-C extra-filename=…` value, in argv order.
    pub extra_filename: Vec<String>,
    /// The full argv (wrapper's view: argv[0] is the real rustc).
    pub argv: Vec<String>,
}

/// Parse a wrapper log into invocations, skipping version probes.
#[must_use]
pub fn parse_wrapper_log(log: &str) -> Vec<RustcInvocation> {
    let mut invocations = Vec::new();
    for line in log.lines() {
        let argv: Vec<String> = line
            .split('\u{1f}')
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect();
        let Some(crate_name) = value_after(&argv, "--crate-name") else {
            continue; // -vV / --print probes carry no crate name
        };
        let mut metadata = Vec::new();
        let mut extra_filename = Vec::new();
        let mut iter = argv.iter().peekable();
        while let Some(arg) = iter.next() {
            let codegen = if arg == "-C" {
                iter.peek().map(|next| next.as_str())
            } else {
                arg.strip_prefix("-C")
            };
            if let Some(codegen) = codegen {
                if let Some(value) = codegen.strip_prefix("metadata=") {
                    metadata.push(value.to_string());
                } else if let Some(value) = codegen.strip_prefix("extra-filename=") {
                    extra_filename.push(value.to_string());
                }
            }
        }
        invocations.push(RustcInvocation {
            crate_name,
            metadata,
            extra_filename,
            argv,
        });
    }
    invocations
}

fn value_after(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .cloned()
}

/// Sort invocations into normalized order (by crate name, then full
/// argv) — Cargo's parallel scheduling makes LOG order meaningless, and
/// normalization must not hide real differences, so the full argv is
/// the tiebreaker.
#[must_use]
pub fn normalize(mut invocations: Vec<RustcInvocation>) -> Vec<RustcInvocation> {
    invocations.sort_by(|a, b| {
        a.crate_name
            .cmp(&b.crate_name)
            .then_with(|| a.argv.cmp(&b.argv))
    });
    invocations
}

/// One divergence between two normalized invocation records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitDivergence {
    /// Different invocation counts.
    InvocationCountMismatch {
        /// Count in record A.
        a: usize,
        /// Count in record B.
        b: usize,
    },
    /// Same position, different crate.
    CrateSetMismatch {
        /// Crate in record A.
        a: String,
        /// Crate in record B.
        b: String,
    },
    /// `-C metadata` seeds differ — THE R43 signature.
    MetadataMismatch {
        /// The crate whose unit identity diverged.
        crate_name: String,
        /// Metadata values in record A.
        a: Vec<String>,
        /// Metadata values in record B.
        b: Vec<String>,
    },
    /// `-C extra-filename` (the unit-hash-bearing output suffix) differs.
    ExtraFilenameMismatch {
        /// The crate whose output naming diverged.
        crate_name: String,
        /// Values in record A.
        a: Vec<String>,
        /// Values in record B.
        b: Vec<String>,
    },
    /// Any other argv difference (first differing index reported).
    ArgvMismatch {
        /// The crate whose argv diverged.
        crate_name: String,
        /// First differing argv index.
        index: usize,
        /// Value in record A at that index (empty if absent).
        a: String,
        /// Value in record B at that index (empty if absent).
        b: String,
    },
}

/// Compare two normalized records; empty result = converged.
#[must_use]
pub fn compare(a: &[RustcInvocation], b: &[RustcInvocation]) -> Vec<UnitDivergence> {
    let mut divergences = Vec::new();
    if a.len() != b.len() {
        divergences.push(UnitDivergence::InvocationCountMismatch {
            a: a.len(),
            b: b.len(),
        });
        return divergences;
    }
    for (inv_a, inv_b) in a.iter().zip(b) {
        if inv_a.crate_name != inv_b.crate_name {
            divergences.push(UnitDivergence::CrateSetMismatch {
                a: inv_a.crate_name.clone(),
                b: inv_b.crate_name.clone(),
            });
            continue;
        }
        if inv_a.metadata != inv_b.metadata {
            divergences.push(UnitDivergence::MetadataMismatch {
                crate_name: inv_a.crate_name.clone(),
                a: inv_a.metadata.clone(),
                b: inv_b.metadata.clone(),
            });
        }
        if inv_a.extra_filename != inv_b.extra_filename {
            divergences.push(UnitDivergence::ExtraFilenameMismatch {
                crate_name: inv_a.crate_name.clone(),
                a: inv_a.extra_filename.clone(),
                b: inv_b.extra_filename.clone(),
            });
        }
        if inv_a.argv != inv_b.argv {
            let index = inv_a
                .argv
                .iter()
                .zip(&inv_b.argv)
                .position(|(x, y)| x != y)
                .unwrap_or_else(|| inv_a.argv.len().min(inv_b.argv.len()));
            divergences.push(UnitDivergence::ArgvMismatch {
                crate_name: inv_a.crate_name.clone(),
                index,
                a: inv_a.argv.get(index).cloned().unwrap_or_default(),
                b: inv_b.argv.get(index).cloned().unwrap_or_default(),
            });
        }
    }
    divergences
}

/// The convergence digest: SHA-256 over the toolchain's verbose version
/// plus every normalized invocation. Equal digests across machines of
/// one platform class assert converged unit identity; a different
/// toolchain yields a different digest by construction.
#[must_use]
pub fn convergence_digest(
    toolchain_verbose_version: &str,
    normalized: &[RustcInvocation],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(toolchain_verbose_version.as_bytes());
    for invocation in normalized {
        hasher.update([0u8]);
        for arg in &invocation.argv {
            hasher.update(arg.as_bytes());
            hasher.update([0x1f]);
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(args: &[&str]) -> String {
        args.join("\u{1f}")
    }

    fn sample_log(metadata: &str, order_swapped: bool) -> String {
        let probe = line(&["/tc/bin/rustc", "-vV"]);
        let build_script = line(&[
            "/tc/bin/rustc",
            "--crate-name",
            "build_script_build",
            "--edition=2021",
            "/__rabs/workspace/build.rs",
            "-C",
            &format!("metadata={metadata}bs"),
            "-C",
            &format!("extra-filename=-{metadata}bs"),
        ]);
        let main = line(&[
            "/tc/bin/rustc",
            "--crate-name",
            "fx",
            "--edition=2021",
            "/__rabs/workspace/src/main.rs",
            &format!("-Cmetadata={metadata}"),
            &format!("-Cextra-filename=-{metadata}"),
        ]);
        if order_swapped {
            format!("{probe}\n{main}\n{build_script}\n")
        } else {
            format!("{probe}\n{build_script}\n{main}\n")
        }
    }

    #[test]
    fn parser_extracts_units_and_skips_version_probes() {
        let invocations = parse_wrapper_log(&sample_log("abc123", false));
        assert_eq!(invocations.len(), 2, "the -vV probe must be skipped");
        assert_eq!(invocations[0].crate_name, "build_script_build");
        assert_eq!(invocations[0].metadata, vec!["abc123bs"]);
        assert_eq!(invocations[1].crate_name, "fx");
        assert_eq!(invocations[1].metadata, vec!["abc123"]);
        assert_eq!(invocations[1].extra_filename, vec!["-abc123"]);
    }

    #[test]
    fn identical_builds_converge_regardless_of_scheduling_order() {
        let a = normalize(parse_wrapper_log(&sample_log("abc123", false)));
        let b = normalize(parse_wrapper_log(&sample_log("abc123", true)));
        assert_eq!(compare(&a, &b), Vec::new(), "converged");
        assert_eq!(
            convergence_digest("rustc 1.99.0-nightly", &a),
            convergence_digest("rustc 1.99.0-nightly", &b)
        );
    }

    #[test]
    fn metadata_divergence_is_named_as_the_r43_signature() {
        let a = normalize(parse_wrapper_log(&sample_log("abc123", false)));
        let b = normalize(parse_wrapper_log(&sample_log("ffe999", false)));
        let divergences = compare(&a, &b);
        assert!(
            divergences
                .iter()
                .any(|d| matches!(d, UnitDivergence::MetadataMismatch { crate_name, .. } if crate_name == "fx")),
            "{divergences:?}"
        );
        assert!(
            divergences
                .iter()
                .any(|d| matches!(d, UnitDivergence::ExtraFilenameMismatch { .. })),
            "{divergences:?}"
        );
    }

    #[test]
    fn missing_invocation_and_crate_set_changes_are_caught() {
        let a = normalize(parse_wrapper_log(&sample_log("abc123", false)));
        let mut b = a.clone();
        b.pop();
        assert!(matches!(
            compare(&a, &b)[0],
            UnitDivergence::InvocationCountMismatch { a: 2, b: 1 }
        ));
        let mut c = a.clone();
        c[1].crate_name = "other".into();
        c.sort_by(|x, y| x.crate_name.cmp(&y.crate_name));
        assert!(
            compare(&a, &c)
                .iter()
                .any(|d| matches!(d, UnitDivergence::CrateSetMismatch { .. }))
        );
    }

    #[test]
    fn digest_binds_the_toolchain_so_cross_toolchain_never_aliases() {
        let a = normalize(parse_wrapper_log(&sample_log("abc123", false)));
        assert_ne!(
            convergence_digest("rustc 1.99.0-nightly (09ee43b2d)", &a),
            convergence_digest("rustc 1.98.0-nightly (11aa22b3c)", &a)
        );
    }
}
