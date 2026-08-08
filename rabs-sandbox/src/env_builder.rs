//! Scrubbed/fixed environment builder (bead E003; invariant I21; risk
//! R45).
//!
//! Constructs the COMPLETE environment presented to an action: an exact
//! allowlist for declared variables, a policy-fixed base (canonical
//! `PATH`, locale, `TZ`, hostname, user, home), and a set of names whose
//! ABSENCE is semantic and hashed. The built list is a full replacement
//! handed to exec — nothing inherits — so an ambient mutation outside
//! the allowlist cannot reach the sandbox **by construction**: this
//! module never reads the process environment at all, and a source
//! tripwire test keeps it that way. Environment soundness therefore
//! never depends on discovering `getenv` calls (env reads happen from
//! process memory; tracers cannot see them — R45).
//!
//! The presented-env digest covers every presented key/value pair AND
//! the hashed absences, canonically sorted and length-delimited: it
//! changes exactly when a semantic variable (or required absence)
//! changes, and never with declaration order.

use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use sha2::{Digest, Sha256};

/// Domain separator for the presented-environment digest.
pub const PRESENTED_ENV_DOMAIN: &str = "rabs.presented-env.sha256.v1";

/// The environment policy: what an action's env is MADE of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvPolicy {
    /// Policy-fixed pairs present in every action env (canonical PATH,
    /// locale, TZ, hostname, user, home). Declaring one is a refusal.
    pub fixed: Vec<(String, String)>,
    /// Names an action MAY declare (with per-action values).
    pub allowed_declared: Vec<String>,
    /// Names that MUST be absent; each absence is part of the digest.
    /// Declaring one is a refusal.
    pub hashed_absences: Vec<String>,
}

impl EnvPolicy {
    /// The strict default: canonical tool path, C.UTF-8 locale, UTC,
    /// fixed sandbox identity, dumb terminal; nothing declarable; the
    /// dynamic-linker and toolchain-wrapper injection vectors required
    /// absent.
    #[must_use]
    pub fn strict_default() -> Self {
        let fixed = [
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C.UTF-8"),
            ("TZ", "UTC"),
            ("HOME", "/__rabs/home"),
            ("USER", "rabs"),
            ("LOGNAME", "rabs"),
            ("HOSTNAME", "rabs-sandbox"),
            ("TERM", "dumb"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
        let hashed_absences = [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        Self {
            fixed,
            allowed_declared: Vec::new(),
            hashed_absences,
        }
    }
}

/// Typed refusals: nothing is built, nothing is partially presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvRefusal {
    /// A name is empty or contains `=`/NUL.
    InvalidName {
        /// The offending name.
        name: String,
    },
    /// A value contains NUL.
    InvalidValue {
        /// The variable whose value is invalid.
        name: String,
    },
    /// The policy's fixed/allowed/absent sets overlap or repeat a name;
    /// an ambiguous policy never builds an env.
    PolicyOverlap {
        /// The name appearing in more than one role.
        name: String,
    },
    /// The same name declared twice.
    DuplicateDeclaration {
        /// The duplicated name.
        name: String,
    },
    /// A declared name is not in the allowlist.
    UndeclaredVariable {
        /// The refused name.
        name: String,
    },
    /// A declared name is policy-fixed (fixed values are not
    /// per-action inputs).
    FixedOverride {
        /// The refused name.
        name: String,
    },
    /// A declared name is required ABSENT by policy.
    ForbiddenVariable {
        /// The refused name.
        name: String,
    },
}

/// The complete presented environment plus its canonical digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedEnv {
    /// The FULL environment, sorted by name — exec receives exactly
    /// this, never an inherited superset.
    pub pairs: Vec<(String, String)>,
    /// Names whose absence is enforced and hashed, sorted.
    pub hashed_absent: Vec<String>,
    /// Canonical digest over pairs and absences.
    pub digest: TypedDigest,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('=') && !name.contains('\0')
}

/// Length-delimited canonical framing (the F034 pattern): every field is
/// `len(u64 be) || bytes`, so no concatenation ambiguity exists.
struct Framing(Sha256);

impl Framing {
    fn new(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain.as_bytes());
        Self(hasher)
    }

    fn field(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
        self
    }

    fn u64(&mut self, v: u64) -> &mut Self {
        self.field(&v.to_be_bytes())
    }

    fn finish(self, domain: &'static str) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: self.0.finalize().into(),
        }
    }
}

fn check_policy(policy: &EnvPolicy) -> Result<(), EnvRefusal> {
    let mut seen: Vec<&str> = Vec::new();
    let roles = policy
        .fixed
        .iter()
        .map(|(name, _)| name.as_str())
        .chain(policy.allowed_declared.iter().map(String::as_str))
        .chain(policy.hashed_absences.iter().map(String::as_str));
    for name in roles {
        if !valid_name(name) {
            return Err(EnvRefusal::InvalidName {
                name: name.to_owned(),
            });
        }
        if seen.contains(&name) {
            return Err(EnvRefusal::PolicyOverlap {
                name: name.to_owned(),
            });
        }
        seen.push(name);
    }
    for (name, value) in &policy.fixed {
        if value.contains('\0') {
            return Err(EnvRefusal::InvalidValue { name: name.clone() });
        }
    }
    Ok(())
}

/// Build the complete presented environment from a policy and the
/// action's declared variables. Takes NO ambient input — the process
/// environment is never consulted (I21/R45).
pub fn build_presented_env(
    policy: &EnvPolicy,
    declared: &[(String, String)],
) -> Result<PresentedEnv, EnvRefusal> {
    check_policy(policy)?;
    let mut declared_names: Vec<&str> = Vec::new();
    for (name, value) in declared {
        if !valid_name(name) {
            return Err(EnvRefusal::InvalidName { name: name.clone() });
        }
        if value.contains('\0') {
            return Err(EnvRefusal::InvalidValue { name: name.clone() });
        }
        if declared_names.contains(&name.as_str()) {
            return Err(EnvRefusal::DuplicateDeclaration { name: name.clone() });
        }
        declared_names.push(name);
        if policy.fixed.iter().any(|(fixed, _)| fixed == name) {
            return Err(EnvRefusal::FixedOverride { name: name.clone() });
        }
        if policy.hashed_absences.contains(name) {
            return Err(EnvRefusal::ForbiddenVariable { name: name.clone() });
        }
        if !policy.allowed_declared.contains(name) {
            return Err(EnvRefusal::UndeclaredVariable { name: name.clone() });
        }
    }
    let mut pairs: Vec<(String, String)> = policy
        .fixed
        .iter()
        .chain(declared.iter())
        .cloned()
        .collect();
    pairs.sort();
    let mut hashed_absent = policy.hashed_absences.clone();
    hashed_absent.sort();

    let mut framing = Framing::new(PRESENTED_ENV_DOMAIN);
    framing.u64(pairs.len() as u64);
    for (name, value) in &pairs {
        framing.field(name.as_bytes()).field(value.as_bytes());
    }
    framing.u64(hashed_absent.len() as u64);
    for name in &hashed_absent {
        framing.field(name.as_bytes());
    }
    let digest = framing.finish(PRESENTED_ENV_DOMAIN);
    Ok(PresentedEnv {
        pairs,
        hashed_absent,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn permissive_policy() -> EnvPolicy {
        let mut policy = EnvPolicy::strict_default();
        policy.allowed_declared = vec!["RUSTFLAGS".to_owned(), "CARGO_HOME".to_owned()];
        policy
    }

    #[test]
    fn presented_env_is_complete_and_exact() {
        let policy = permissive_policy();
        let env =
            build_presented_env(&policy, &declared(&[("RUSTFLAGS", "-Copt-level=2")])).unwrap();
        // Exactly fixed ∪ declared, sorted; nothing inherited, nothing
        // extra.
        assert_eq!(env.pairs.len(), policy.fixed.len() + 1);
        assert!(env.pairs.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(
            env.pairs
                .iter()
                .any(|(n, v)| n == "RUSTFLAGS" && v == "-Copt-level=2")
        );
        assert!(
            env.pairs
                .iter()
                .any(|(n, v)| n == "PATH" && v == "/usr/local/bin:/usr/bin:/bin")
        );
        assert!(env.hashed_absent.contains(&"LD_PRELOAD".to_owned()));
    }

    #[test]
    fn allowlist_is_exact_and_typed() {
        let policy = permissive_policy();
        assert_eq!(
            build_presented_env(&policy, &declared(&[("SNEAKY", "1")])),
            Err(EnvRefusal::UndeclaredVariable {
                name: "SNEAKY".to_owned()
            })
        );
        assert_eq!(
            build_presented_env(&policy, &declared(&[("PATH", "/tmp/evil")])),
            Err(EnvRefusal::FixedOverride {
                name: "PATH".to_owned()
            })
        );
        assert_eq!(
            build_presented_env(&policy, &declared(&[("LD_PRELOAD", "/tmp/evil.so")])),
            Err(EnvRefusal::ForbiddenVariable {
                name: "LD_PRELOAD".to_owned()
            })
        );
        assert_eq!(
            build_presented_env(
                &policy,
                &declared(&[
                    ("RUSTFLAGS", "-Copt-level=2"),
                    ("RUSTFLAGS", "-Copt-level=3")
                ])
            ),
            Err(EnvRefusal::DuplicateDeclaration {
                name: "RUSTFLAGS".to_owned()
            })
        );
        assert_eq!(
            build_presented_env(&policy, &declared(&[("BAD=NAME", "x")])),
            Err(EnvRefusal::InvalidName {
                name: "BAD=NAME".to_owned()
            })
        );
        assert_eq!(
            build_presented_env(&policy, &[("RUSTFLAGS".to_owned(), "a\0b".to_owned())]),
            Err(EnvRefusal::InvalidValue {
                name: "RUSTFLAGS".to_owned()
            })
        );
        // An ambiguous policy never builds an env.
        let mut overlapping = permissive_policy();
        overlapping.allowed_declared.push("PATH".to_owned());
        assert_eq!(
            build_presented_env(&overlapping, &[]),
            Err(EnvRefusal::PolicyOverlap {
                name: "PATH".to_owned()
            })
        );
    }

    #[test]
    fn digest_changes_iff_a_semantic_variable_changes() {
        let policy = permissive_policy();
        let base = build_presented_env(
            &policy,
            &declared(&[
                ("RUSTFLAGS", "-Copt-level=2"),
                ("CARGO_HOME", "/__rabs/cargo"),
            ]),
        )
        .unwrap();
        // Declaration order is not semantic.
        let reordered = build_presented_env(
            &policy,
            &declared(&[
                ("CARGO_HOME", "/__rabs/cargo"),
                ("RUSTFLAGS", "-Copt-level=2"),
            ]),
        )
        .unwrap();
        assert_eq!(base.digest, reordered.digest);
        assert_eq!(base, reordered);
        // A changed value is semantic.
        let changed = build_presented_env(
            &policy,
            &declared(&[
                ("RUSTFLAGS", "-Copt-level=3"),
                ("CARGO_HOME", "/__rabs/cargo"),
            ]),
        )
        .unwrap();
        assert_ne!(base.digest, changed.digest);
        // An added allowed variable is semantic.
        let smaller =
            build_presented_env(&policy, &declared(&[("RUSTFLAGS", "-Copt-level=2")])).unwrap();
        assert_ne!(base.digest, smaller.digest);
        // A changed fixed value is semantic.
        let mut warsaw = permissive_policy();
        for (name, value) in &mut warsaw.fixed {
            if name == "TZ" {
                "Europe/Warsaw".clone_into(value);
            }
        }
        let moved = build_presented_env(
            &warsaw,
            &declared(&[
                ("RUSTFLAGS", "-Copt-level=2"),
                ("CARGO_HOME", "/__rabs/cargo"),
            ]),
        )
        .unwrap();
        assert_ne!(base.digest, moved.digest);
        // A required ABSENCE is semantic: dropping it from policy
        // changes the digest even though the pairs are identical.
        let mut lax = permissive_policy();
        lax.hashed_absences.retain(|name| name != "LD_PRELOAD");
        let relaxed = build_presented_env(
            &lax,
            &declared(&[
                ("RUSTFLAGS", "-Copt-level=2"),
                ("CARGO_HOME", "/__rabs/cargo"),
            ]),
        )
        .unwrap();
        assert_eq!(base.pairs, relaxed.pairs);
        assert_ne!(base.digest, relaxed.digest);
        // Field framing: name/value boundaries cannot be shifted.
        let mut policy_ab = EnvPolicy::strict_default();
        policy_ab.fixed = vec![("A".to_owned(), "BC".to_owned())];
        policy_ab.hashed_absences.clear();
        let mut policy_abc = EnvPolicy::strict_default();
        policy_abc.fixed = vec![("AB".to_owned(), "C".to_owned())];
        policy_abc.hashed_absences.clear();
        assert_ne!(
            build_presented_env(&policy_ab, &[]).unwrap().digest,
            build_presented_env(&policy_abc, &[]).unwrap().digest
        );
    }

    #[test]
    fn builder_reads_no_ambient_environment() {
        // The R45 soundness claim is BY CONSTRUCTION: this module never
        // consults the process environment. This tripwire fails the
        // build if anyone adds an ambient read to the non-test code
        // above (env reads happen from process memory; a tracer-based
        // check could never prove their absence).
        let source = include_str!("env_builder.rs");
        let non_test = source
            .split("#[cfg(test)]")
            .next()
            .expect("split always yields a first segment");
        // Comments may TALK about getenv; code may not touch it.
        let code_only: String = non_test
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code_only.contains(&format!("std::{}", "env")) && !code_only.contains("getenv"),
            "env_builder must never read the ambient environment"
        );
        // And determinism holds across repeated builds.
        let policy = EnvPolicy::strict_default();
        assert_eq!(
            build_presented_env(&policy, &[]).unwrap(),
            build_presented_env(&policy, &[]).unwrap()
        );
    }
}
