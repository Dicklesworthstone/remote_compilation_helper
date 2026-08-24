//! Canonical process-context capture: stat/umask/CPU-topology/inherited-
//! FD mutation differentials (bead T024; invariant D026; risk R78).
//!
//! R78's hazard: a build tool observes system context — file `stat`
//! metadata, the process umask, CPU count/affinity, rlimits, `argv0`,
//! the working directory, inherited descriptors — and that observation
//! either (a) AFFECTS outputs, in which case it MUST enter the action
//! key, or (b) is noise, in which case capture must CANONICALIZE it so
//! two hosts with different noise still share a key. The failure modes
//! are symmetric and both named by the plan:
//!
//! - omitted key input → wrong-result serving;
//! - uncanonicalized input → whole-graph invalidation on host noise.
//!
//! This module is the D026 capture contract as PURE classification: each
//! dimension takes its OBSERVED value and returns a disposition from the
//! same taxonomy family the environment layer uses — keyed, normalized
//! to a canonical form, or volatile-refused. The differential matrix
//! tests mutate every dimension and assert digest behavior matches the
//! declared rule; "differential matrix green" = mutations either enter
//! the key or are canonicalized, never silently dropped, never leaking
//! host noise into keys.
//!
//! Capture is pure over observed values on purpose: the worker probes
//! the live system elsewhere; here we own the LAW for what an
//! observation does to identity.
//!
//! # Dependency rules
//!
//! Same as the crate: no Tokio, no Asupersync; digests via the reviewed
//! sha2 path (`typed_digest::compute`).

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;
use rabs_protocol::result_identity::TypedDigest;

/// Digest domain for the captured system-context component.
pub const DOMAIN_SYSTEM_CONTEXT: &str = "rabs.system-context.sha256.v1";

/// One observed system-context field, pre-classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemContextField {
    /// File size in bytes (`stat::st_size`) — affects most consumers.
    FileSize(u64),
    /// Permission bits (`st_mode` low bits) — affect exec/read semantics.
    Permissions(u32),
    /// Executable bit — keyed independently: scripts behave differently.
    ExecBit(bool),
    /// Modification time nanoseconds — timestamps are explicitly NON-
    /// semantic for build inputs (object model `MetadataRule`); captured,
    /// then canonicalized away.
    MtimeNs(u128),
    /// Process umask at spawn — gates created-file modes.
    Umask(u32),
    /// Logical CPU count — codegen backends read it (rayon/LLVM).
    CpuCount(u32),
    /// CPU affinity mask bytes — scheduling noise in the default posture.
    CpuAffinity(Vec<u8>),
    /// Inherited descriptors beyond stdin/stdout/stderr — jobserver fds
    /// and socket paths are transport, never semantics (I003 posture).
    InheritedFds(u32),
    /// `argv[0]` as invoked — some tools embed it in outputs.
    Argv0(Vec<u8>),
    /// Working directory — keys ONLY in its canonical spelling under the
    /// canonical prefix; a noncanonical spelling refuses (fail-closed).
    WorkingDir {
        /// Observed absolute cwd bytes.
        observed: Vec<u8>,
        /// Canonical prefix configured for this workspace plane.
        canonical_prefix: Vec<u8>,
    },
    /// rlimit (resource, current, max) — stack limits can change
    /// codegen; captured via named normalization.
    Rlimit {
        /// Resource identifier (e.g. RLIMIT_STACK).
        resource: u32,
        /// Current limit.
        current: u64,
        /// Ceiling.
        max: u64,
    },
}

/// What the capture law says about one classified field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextDisposition {
    /// Full value enters the digest verbatim (framed).
    Keyed { value: Vec<u8> },
    /// The canonical form enters the digest under a versioned normalizer
    /// name; raw observations that normalize identically share a key.
    Normalized {
        normalizer: &'static str,
        canonical: Vec<u8>,
    },
    /// Excluded from the digest entirely. The refusal reason is
    /// deterministic bookkeeping, NOT key input.
    VolatileRefused { reason: &'static str },
}

impl ContextDisposition {
    /// Whether this disposition contributes bytes to the digest.
    #[must_use]
    pub const fn keys(&self) -> bool {
        !matches!(self, Self::VolatileRefused { .. })
    }
}

/// Classification failure (only the working-directory rule can fail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemContextError {
    /// The observed cwd does not live under the canonical prefix: the
    /// action ran OUTSIDE the canonical namespace and its context cannot
    /// be canonicalized honestly.
    NonCanonicalWorkingDir { observed: String },
}

fn keyed(tag: &[u8], value: &[u8]) -> ContextDisposition {
    let mut enc = CanonicalEncoder::new();
    enc.bytes(tag).bytes(value);
    ContextDisposition::Keyed {
        value: enc.finish(),
    }
}

fn normalize_cwd(observed: &[u8]) -> Vec<u8> {
    if observed.starts_with(b"./") {
        observed[2..].to_vec()
    } else {
        observed.to_vec()
    }
}

/// Classify one observed field per the D026 law.
///
/// # Errors
/// [`SystemContextError::NonCanonicalWorkingDir`] when the observed cwd
/// escapes the configured canonical prefix.
pub fn classify(field: &SystemContextField) -> Result<ContextDisposition, SystemContextError> {
    Ok(match field {
        // Size / permissions / exec bit: identity facts.
        SystemContextField::FileSize(v) => keyed(b"file-size", &v.to_be_bytes()),
        SystemContextField::Permissions(v) => keyed(b"permissions", &v.to_be_bytes()),
        SystemContextField::ExecBit(v) => keyed(b"exec-bit", &[*v as u8]),
        // Timestamps: captured, then canonicalized away — two checkouts
        // hours apart MUST share the key.
        SystemContextField::MtimeNs(_) => ContextDisposition::Normalized {
            normalizer: "d026.mtime.v1",
            canonical: b"dropped-nonsemantic".to_vec(),
        },
        // Umask: keys through a versioned octal normalizer (it changes
        // created-file modes); equal masks normalize identically.
        SystemContextField::Umask(mode) => ContextDisposition::Normalized {
            normalizer: "d026.umask.v1",
            canonical: format!("{mode:o}").into_bytes(),
        },
        // Logical CPU count: keys via decimal normalization — codegen
        // backends branch on it, but a re-spelled 8 still means 8.
        SystemContextField::CpuCount(n) => ContextDisposition::Normalized {
            normalizer: "d026.cpu-count.v1",
            canonical: n.to_string().into_bytes(),
        },
        // Affinity masks are scheduling noise in the default posture:
        // refusing them keeps host pinning out of keys (R78 second arm).
        SystemContextField::CpuAffinity(_) => ContextDisposition::VolatileRefused {
            reason: "d026.cpu-affinity.scheduling-noise",
        },
        // Inherited descriptors beyond std streams: jobserver/socket
        // transport (I003). Count is noise; presence refuses.
        SystemContextField::InheritedFds(_) => ContextDisposition::VolatileRefused {
            reason: "d026.inherited-fds.transport",
        },
        // argv0: some tools embed their invocation name in outputs.
        SystemContextField::Argv0(v) => keyed(b"argv0", v),
        // cwd: canonical-spelling-or-refuse. A noncanonical cwd means the
        // action did not plan in the canonical namespace — exactly what
        // M014's gate refuses upstream; here it cannot be canonicalized
        // honestly, so it errors rather than keying host-local bytes.
        SystemContextField::WorkingDir {
            observed,
            canonical_prefix,
        } => {
            let norm = normalize_cwd(observed);
            if norm.starts_with(canonical_prefix.as_slice()) {
                ContextDisposition::Normalized {
                    normalizer: "d026.cwd.v1",
                    canonical: norm,
                }
            } else {
                return Err(SystemContextError::NonCanonicalWorkingDir {
                    observed: String::from_utf8_lossy(observed).into_owned(),
                });
            }
        }
        // rlimits: (resource, cur, max) keys through the named
        // normalizer — stack exhaustion changes some codegen paths.
        SystemContextField::Rlimit {
            resource,
            current,
            max,
        } => ContextDisposition::Normalized {
            normalizer: "d026.rlimit.v1",
            canonical: {
                let mut enc = CanonicalEncoder::new();
                enc.u32(*resource).u64(*current).u64(*max);
                enc.finish()
            },
        },
    })
}

/// The D026 component digest: only KEYED/NORMALIZED contributions enter,
/// each framed through [`CanonicalEncoder`] rules (tag + payload), over
/// the domain-prefixed buffer. Deterministic across hosts/processes.
///
/// Volatile-refused fields contribute NOTHING — not even a marker — so
/// adding/removing noise descriptors cannot perturb the key.
///
/// # Errors
/// Propagates the working-directory rule.
pub fn system_context_digest(
    fields: &[SystemContextField],
) -> Result<TypedDigest, SystemContextError> {
    // The length prefix counts ONLY key-participating fields: a
    // volatile-refused entry contributes NOTHING — not even to the
    // count — so adding/removing noise cannot perturb the digest
    // (T024: "noise cannot leak in OR out").
    let mut participating = 0u64;
    for field in fields {
        if classify(field)?.keys() {
            participating += 1;
        }
    }
    let mut enc = CanonicalEncoder::new();
    enc.u64(participating);
    for field in fields {
        match classify(field)? {
            ContextDisposition::Keyed { value } => {
                enc.bytes(b"keyed").bytes(&value);
            }
            ContextDisposition::Normalized {
                normalizer,
                canonical,
            } => {
                enc.bytes(b"norm").str(normalizer).bytes(&canonical);
            }
            ContextDisposition::VolatileRefused { .. } => {}
        }
    }
    Ok(compute(DOMAIN_SYSTEM_CONTEXT, &enc.finish()))
}

// ---------------------------------------------------------------------
// Tests — the T024 acceptance matrix: every mutation lands on the
// declared side of the key/canonicalize line.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn base_fields() -> Vec<SystemContextField> {
        vec![
            SystemContextField::FileSize(4096),
            SystemContextField::Permissions(0o644),
            SystemContextField::ExecBit(false),
            SystemContextField::MtimeNs(1_700_000_000_000_000_000),
            SystemContextField::Umask(0o022),
            SystemContextField::CpuCount(16),
            SystemContextField::CpuAffinity(vec![0xFF, 0x00]),
            SystemContextField::InheritedFds(3),
            SystemContextField::Argv0(b"rustc".to_vec()),
            SystemContextField::WorkingDir {
                observed: b"/data/projects/acme".to_vec(),
                canonical_prefix: b"/data/projects".to_vec(),
            },
            SystemContextField::Rlimit {
                resource: 3,
                current: 8 << 20,
                max: u64::MAX,
            },
        ]
    }

    fn base_digest() -> TypedDigest {
        system_context_digest(&base_fields()).unwrap()
    }

    fn mutated(index: usize, field: SystemContextField) -> TypedDigest {
        let mut fields = base_fields();
        fields[index] = field;
        system_context_digest(&fields).unwrap()
    }

    #[test]
    fn t024_identity_dimensions_enter_the_key() {
        let base = base_digest();
        assert_ne!(mutated(0, SystemContextField::FileSize(8192)), base);
        assert_ne!(mutated(1, SystemContextField::Permissions(0o600)), base);
        assert_ne!(mutated(2, SystemContextField::ExecBit(true)), base);
        assert_ne!(
            mutated(8, SystemContextField::Argv0(b"rustc.exe".to_vec())),
            base
        );
    }

    #[test]
    fn t024_timestamps_and_noise_are_canonicalized_away() {
        let base = base_digest();
        // Timestamps: two checkouts hours apart share the key.
        assert_eq!(
            mutated(3, SystemContextField::MtimeNs(1_900_000_000_000_000_000)),
            base
        );
        // Affinity mask churn: scheduling noise never keys.
        assert_eq!(
            mutated(6, SystemContextField::CpuAffinity(vec![0x0F, 0xF0])),
            base
        );
        // Inherited descriptor count: transport, never semantics.
        assert_eq!(mutated(7, SystemContextField::InheritedFds(9)), base);
    }

    #[test]
    fn t024_normalized_dimensions_key_on_canonical_form_only() {
        let base = base_digest();
        // umask 0o002 differs from 0o022 semantically → keys…
        assert_ne!(mutated(4, SystemContextField::Umask(0o002)), base);
        // …and the SAME mask re-observed does not.
        assert_eq!(mutated(4, SystemContextField::Umask(0o022)), base);

        // CPU count 32 vs 16 keys (codegen branches on it).
        assert_ne!(mutated(5, SystemContextField::CpuCount(32)), base);
        // rlimit change keys (stack exhaustion changes codegen paths).
        assert_ne!(
            mutated(
                10,
                SystemContextField::Rlimit {
                    resource: 3,
                    current: 16 << 20,
                    max: u64::MAX
                }
            ),
            base
        );
    }

    #[test]
    fn t024_noncanonical_working_dir_refuses_instead_of_keying() {
        let mut fields = base_fields();
        fields[9] = SystemContextField::WorkingDir {
            observed: b"/home/me/code".to_vec(),
            canonical_prefix: b"/data/projects".to_vec(),
        };
        assert_eq!(
            system_context_digest(&fields).unwrap_err(),
            SystemContextError::NonCanonicalWorkingDir {
                observed: "/home/me/code".to_owned()
            }
        );
    }

    #[test]
    fn t024_canonical_cwd_is_deterministic_and_workspace_sensitive() {
        let mut fields = base_fields();
        fields[9] = SystemContextField::WorkingDir {
            observed: b"/data/projects/acme".to_vec(),
            canonical_prefix: b"/data/projects".to_vec(),
        };
        let d1 = system_context_digest(&fields).unwrap();
        let d2 = system_context_digest(&fields).unwrap();
        assert_eq!(d1, d2);

        // A different workspace under the same canonical prefix keys
        // differently (the normalized spelling differs).
        fields[9] = SystemContextField::WorkingDir {
            observed: b"/data/projects/beta".to_vec(),
            canonical_prefix: b"/data/projects".to_vec(),
        };
        assert_ne!(system_context_digest(&fields).unwrap(), d1);
    }

    #[test]
    fn t024_volatile_field_presence_never_perturbs_the_matrix() {
        // Removing ALL volatile dimensions leaves the digest untouched:
        // noise cannot leak in OR out.
        let with_noise = base_digest();
        let mut without = base_fields();
        without.retain(|f| {
            !matches!(
                f,
                SystemContextField::CpuAffinity(_) | SystemContextField::InheritedFds(_)
            )
        });
        assert_eq!(system_context_digest(&without).unwrap(), with_noise);
    }
}
