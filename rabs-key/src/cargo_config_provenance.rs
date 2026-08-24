//! Effective Cargo configuration provenance capture (bead K015;
//! EffectiveCargoConfigContract).
//!
//! Cargo's effective configuration is an ORIGIN-SENSITIVE merge: the
//! nearest `.cargo/config.toml` wins over ancestors, which win over
//! `$CARGO_HOME/config.toml`, with `--config` CLI arguments and
//! `CARGO_*` environment overrides layered on top. Two hosts whose
//! configs differ only in WHERE a value came from behave identically
//! byte-for-byte today yet are different deployment facts: K019 needs
//! origin-relative path semantics, and the plan forbids HOST-GLOBAL
//! config (`CARGO_HOME`) from influencing an authoritative action
//! INVISIBLY.
//!
//! This module owns the LAW for what an observed config tuple
//! (origin, kind, value) does to identity — pure classification over
//! observations exactly like [`crate::system_context`] and
//! [`crate::environment`]; the worker resolves the live merge elsewhere.
//!
//! The law, per the bead text:
//!
//! - every applicable source class (workspace/ancestor `.cargo/config*`,
//!   `CARGO_HOME` config, `--config` CLI, env override, toolchain
//!   selection input) is representable as an [`ConfigOrigin`];
//! - each value carries its ORIGIN into every digest — influence is
//!   always VISIBLE (never silently folded away);
//! - SECRETS stay capabilities: a registry token enters only as an
//!   authority-computed opaque digest (R56 family) — the plaintext has
//!   no representation anywhere in this module;
//! - host-global config participates ONLY when the action plane
//!   explicitly declares host-global influence ([`GlobalInfluencePolicy`]);
//!   otherwise every `CARGO_HOME`-origin entry is refused as a named
//!   policy outcome that appears in the audit record but contributes
//!   NOTHING to the provenance (key) digest;
//! - UNRECOGNIZED tables key verbatim (fail-closed): future Cargo
//!   versions may grant them semantics we cannot predict.
//!
//! Entry ORDER is preserved everywhere: Cargo's merge precedence IS the
//! semantics being captured (later entries shadow earlier ones), so the
//! digests are order-sensitive by design.
//!
//! # Dependency rules
//!
//! Same as the crate: no Tokio, no Asupersync; digests via the reviewed
//! sha2 path ([`crate::typed_digest::compute`]).

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;
use rabs_protocol::result_identity::TypedDigest;

/// Digest domain for the provenance (key-side) view of the contract.
pub const DOMAIN_CARGO_CONFIG_PROVENANCE: &str = "rabs.cargo-config-provenance.v1";

/// Digest domain for the full audit RECORD (refusals included).
///
/// Distinct from the provenance domain so a refusal-policy change can
/// never masquerade as a build-input change (and vice versa).
pub const DOMAIN_CARGO_CONFIG_RECORD: &str = "rabs.cargo-config-record.v1";

/// Digest domain for authority-computed secret capabilities (R56
/// family): computed over `(kind, registry, value, scope)` by the
/// authority that observed the plaintext; this module only ever sees
/// the resulting [`TypedDigest`].
pub const DOMAIN_CARGO_CONFIG_SECRET: &str = "rabs.cargo-config-secret.v1";

/// Scope bound mixed into [`secret_capability_digest`] so a token
/// captured for one plane cannot be replayed as another plane's
/// capability.
pub const SECRET_SCOPE_ACTION_CONFIG: &[u8] = b"action-config/v1";

/// Authority-side derivation of the opaque secret capability for a
/// registry token. Lives here so callers cannot hand-roll divergent
/// derivations; the plaintext argument exists ONLY inside this call.
#[must_use]
pub fn secret_capability_digest(registry: &[u8], value: &[u8]) -> TypedDigest {
    let mut enc = CanonicalEncoder::new();
    enc.bytes(b"registry-token")
        .bytes(registry)
        .bytes(value)
        .bytes(SECRET_SCOPE_ACTION_CONFIG);
    compute(DOMAIN_CARGO_CONFIG_SECRET, &enc.finish())
}

/// Where one observed configuration value came from. Every variant is
/// explicit — there is no "ambient" origin, because invisible influence
/// is precisely what this contract exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigOrigin {
    /// `.cargo/config.toml` at the workspace root.
    Workspace {
        /// Canonical absolute path of the config file.
        path: Vec<u8>,
    },
    /// `.cargo/config.toml` in a directory between the workspace root
    /// and `/` (exclusive). Nearest ancestor wins Cargo's merge.
    Ancestor {
        /// Canonical absolute path of the config file.
        path: Vec<u8>,
    },
    /// `$CARGO_HOME/config.toml` (or legacy `~/.cargo/config.toml`) —
    /// HOST-GLOBAL: participates only under
    /// [`GlobalInfluencePolicy::DeclaredHostGlobal`].
    CargoHome,
    /// A `--config KEY=VALUE|path` CLI occurrence, index-preserving
    /// (later flags override earlier ones).
    CliConfig {
        /// Zero-based position among the invocation's `--config` flags.
        index: u32,
    },
    /// A process-environment override feeding Cargo's config system
    /// (`CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET`,
    /// `CARGO_REGISTRIES_*_TOKEN`, ...).
    EnvOverride {
        /// Variable name bytes.
        name: Vec<u8>,
    },
    /// Toolchain-selection input: `rust-toolchain.toml` /
    /// `rust-toolchain` driving the channel the action runs under.
    ToolchainFile {
        /// Canonical absolute path of the toolchain file.
        path: Vec<u8>,
    },
}

/// One observed configuration fact, pre-classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigEntryKind {
    /// `build.target-dir` — output location; origin-relative resolution
    /// is K019's concern, captured here verbatim modulo path spelling.
    TargetDir(Vec<u8>),
    /// `build.jobs` — logical parallelism fed to codegen backends.
    BuildJobs(u32),
    /// `[alias.NAME]` — command expansion; argv ORDER is semantics.
    Alias {
        /// Alias name.
        name: Vec<u8>,
        /// Expanded program + arguments, in order.
        argv: Vec<Vec<u8>>,
    },
    /// `[source.NAME]` source replacement — `source` is replaced by
    /// the registry identified by `replace_with`.
    SourceReplacement {
        /// Replaced source name (e.g. `crates-io`).
        source: Vec<u8>,
        /// Replacement registry name/URL.
        replace_with: Vec<u8>,
    },
    /// `[registries.NAME] index` — alternate registry URL binding.
    RegistryIndex {
        /// Registry name.
        registry: Vec<u8>,
        /// Index URL.
        url: Vec<u8>,
    },
    /// `[registry] default` / `index` — the default registry binding.
    RegistryDefault(Vec<u8>),
    /// `[target.TRIPLE] runner` — CARGO_TARGET_..._RUNNER argv.
    TargetRunner {
        /// Target triple.
        triple: Vec<u8>,
        /// Runner program + arguments, in order.
        runner: Vec<Vec<u8>>,
    },
    /// `[target.TRIPLE] linker` — linker executable path/basename.
    TargetLinker {
        /// Target triple.
        triple: Vec<u8>,
        /// Linker path as written.
        linker: Vec<u8>,
    },
    /// `build.rustflags` or `[target.TRIPLE] rustflags` — flag ORDER
    /// is semantics (first-wins conflicts on some flags).
    Rustflags {
        /// `Some(triple)` when target-scoped, `None` for global.
        scoped_to_triple: Option<Vec<u8>>,
        /// Flags in written order.
        flags: Vec<Vec<u8>>,
    },
    /// `credential-helper` / `[registries.NAME] credential-provider` —
    /// the helper REFERENCE is semantic (which program mints
    /// credentials) and keys; its OUTPUTS stay secrets.
    CredentialHelper(Vec<u8>),
    /// A registry auth token: the plaintext was observed by the
    /// AUTHORITY and reduced to `capability` via
    /// [`secret_capability_digest`]. The plaintext has no representation
    /// in this module.
    RegistryToken {
        /// Registry the token authenticates.
        registry: Vec<u8>,
        /// Opaque capability over the plaintext (R56 family).
        capability: TypedDigest,
    },
    /// Toolchain selection value (channel or full toolchain spec).
    ToolchainChannel(Vec<u8>),
    /// Anything this version of the contract does not model. Captured
    /// VERBATIM and keyed (fail-closed): unknown config may acquire
    /// semantics in future Cargo releases.
    Unrecognized {
        /// Dotted table path (e.g. `future.table.key`).
        table_path: Vec<u8>,
        /// Raw TOML value bytes as written.
        raw_value_toml: Vec<u8>,
    },
}

/// Whether the action plane admits host-global (`CARGO_HOME`)
/// configuration influence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalInfluencePolicy {
    /// The plane DECLARED host-global inputs: `CargoHome`-origin
    /// entries classify normally (still visibly origin-tagged).
    DeclaredHostGlobal,
    /// The plane FORBIDS host-global influence: every `CargoHome`-
    /// origin entry is refused as a named policy outcome.
    ForbidHostGlobal,
}

/// Why an observed entry got its disposition payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigDisposition {
    /// Origin + kind + value frame verbatim into the digest.
    Keyed,
    /// A versioned normalization of the value frames instead of the
    /// raw bytes (raw spellings that normalize identically share a
    /// key). The origin still frames — normalization never erases
    /// provenance.
    Normalized {
        /// Which normalizer ran (versioned name).
        normalizer: &'static str,
        /// Post-normalization bytes.
        canonical: Vec<u8>,
    },
    /// Secret-bearing entry: only the authority-computed opaque
    /// capability digest participates (R56 family).
    SecretOpaqueDigest(TypedDigest),
    /// Refused by the host-global policy: recorded for audit, contributes
    /// NOTHING to the provenance digest.
    GlobalRefused,
}

impl ConfigDisposition {
    /// Whether this disposition contributes bytes to the PROVENANCE
    /// (key) digest.
    #[must_use]
    pub const fn keys(&self) -> bool {
        !matches!(self, Self::GlobalRefused)
    }
}

/// Classification failure modes (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigProvenanceError {
    /// A path-bearing origin carried a non-canonical path spelling:
    /// relative, `.`/`..` components, empty or duplicated segments.
    /// Provenance of a config we cannot spell canonically cannot be
    /// captured honestly.
    NonCanonicalConfigPath {
        /// Raw offending bytes.
        raw: String,
    },
    /// An alias (or runner) expanded to zero argv entries: meaningless
    /// expansion, ambiguous between "unset" and "set-but-empty".
    EmptyExpansion {
        /// The dotted key concerned.
        key: Vec<u8>,
    },
}

/// An observation awaiting classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedConfigEntry {
    /// Where the value came from.
    pub origin: ConfigOrigin,
    /// What was set.
    pub kind: ConfigEntryKind,
}

/// One classified entry in precedence order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedEntry {
    /// Origin (always framed — provenance is never erased).
    pub origin: ConfigOrigin,
    /// Kind (always framed — categories never alias).
    pub kind: ConfigEntryKind,
    /// Disposition payload for this entry.
    pub disposition: ConfigDisposition,
}

/// The EffectiveCargoConfigContract: every applicable observed entry,
/// classified, in precedence order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveCargoConfigContract {
    /// Classified entries, caller-supplied precedence order preserved.
    pub entries: Vec<ClassifiedEntry>,
}

/// Classify one observed entry per the K015 law.
///
/// # Errors
/// [`ConfigProvenanceError::NonCanonicalConfigPath`] when a path-bearing
/// origin is not canonically spelled;
/// [`ConfigProvenanceError::EmptyExpansion`] when an alias expands to
/// zero argv entries.
pub fn classify(
    entry: &ObservedConfigEntry,
    policy: GlobalInfluencePolicy,
) -> Result<ConfigDisposition, ConfigProvenanceError> {
    // Host-global gate FIRST: under ForbidHostGlobal nothing from
    // CARGO_HOME reaches the key, whatever it is.
    if entry.origin == ConfigOrigin::CargoHome && policy == GlobalInfluencePolicy::ForbidHostGlobal
    {
        return Ok(ConfigDisposition::GlobalRefused);
    }
    // Path-bearing origins must be canonically spelled.
    match &entry.origin {
        ConfigOrigin::Workspace { path }
        | ConfigOrigin::Ancestor { path }
        | ConfigOrigin::ToolchainFile { path } => {
            if !is_canonical_path(path) {
                return Err(ConfigProvenanceError::NonCanonicalConfigPath {
                    raw: String::from_utf8_lossy(path).into_owned(),
                });
            }
        }
        ConfigOrigin::CargoHome
        | ConfigOrigin::CliConfig { .. }
        | ConfigOrigin::EnvOverride { .. } => {}
    }
    Ok(match &entry.kind {
        ConfigEntryKind::TargetDir(dir) => ConfigDisposition::Normalized {
            normalizer: "k015.target-dir.v1",
            canonical: normalize_path(dir),
        },
        ConfigEntryKind::BuildJobs(jobs) => ConfigDisposition::Normalized {
            normalizer: "k015.jobs.v1",
            canonical: jobs.to_string().into_bytes(),
        },
        ConfigEntryKind::Alias { name, argv } => {
            if argv.is_empty() {
                return Err(ConfigProvenanceError::EmptyExpansion { key: name.clone() });
            }
            ConfigDisposition::Keyed
        }
        ConfigEntryKind::SourceReplacement { .. }
        | ConfigEntryKind::RegistryIndex { .. }
        | ConfigEntryKind::RegistryDefault(_)
        | ConfigEntryKind::TargetRunner { .. }
        | ConfigEntryKind::TargetLinker { .. }
        | ConfigEntryKind::Rustflags { .. }
        | ConfigEntryKind::CredentialHelper(_)
        | ConfigEntryKind::ToolchainChannel(_)
        | ConfigEntryKind::Unrecognized { .. } => ConfigDisposition::Keyed,
        ConfigEntryKind::RegistryToken { capability, .. } => {
            ConfigDisposition::SecretOpaqueDigest(capability.clone())
        }
    })
}

/// Build the contract: classify every observation, preserving order.
///
/// # Errors
/// Propagates [`classify`] failures.
pub fn classify_contract(
    entries: &[ObservedConfigEntry],
    policy: GlobalInfluencePolicy,
) -> Result<EffectiveCargoConfigContract, ConfigProvenanceError> {
    let mut classified = Vec::with_capacity(entries.len());
    for entry in entries {
        let disposition = classify(entry, policy)?;
        classified.push(ClassifiedEntry {
            origin: entry.origin.clone(),
            kind: entry.kind.clone(),
            disposition,
        });
    }
    Ok(EffectiveCargoConfigContract {
        entries: classified,
    })
}

impl EffectiveCargoConfigContract {
    /// The PROVENANCE (key-side) digest: only key-participating
    /// dispositions frame, each as (origin, kind, disposition payload),
    /// in precedence order. Host-global refusals contribute nothing —
    /// adding/removing forbidden global config cannot perturb the key.
    #[must_use]
    pub fn provenance_digest(&self) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        let participating: Vec<&ClassifiedEntry> = self
            .entries
            .iter()
            .filter(|e| e.disposition.keys())
            .collect();
        enc.u64(participating.len() as u64);
        for e in participating {
            Self::frame_entry(&mut enc, e);
        }
        compute(DOMAIN_CARGO_CONFIG_PROVENANCE, &enc.finish())
    }

    /// The full audit RECORD digest: every entry including host-global
    /// refusals (with their refusal marker). Answers "what config was
    /// observed, and what did policy do with it" without ever feeding
    /// refusals into build identity.
    #[must_use]
    pub fn record_digest(&self) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        enc.u64(self.entries.len() as u64);
        for e in &self.entries {
            enc.bool(e.disposition.keys());
            Self::frame_entry(&mut enc, e);
        }
        compute(DOMAIN_CARGO_CONFIG_RECORD, &enc.finish())
    }

    fn frame_entry(enc: &mut CanonicalEncoder, e: &ClassifiedEntry) {
        // Origin discriminants.
        match &e.origin {
            ConfigOrigin::Workspace { path } => enc.u32(1).bytes(path),
            ConfigOrigin::Ancestor { path } => enc.u32(2).bytes(path),
            ConfigOrigin::CargoHome => enc.u32(3),
            ConfigOrigin::CliConfig { index } => enc.u32(4).u32(*index),
            ConfigOrigin::EnvOverride { name } => enc.u32(5).bytes(name),
            ConfigOrigin::ToolchainFile { path } => enc.u32(6).bytes(path),
        };
        // Kind discriminants + payloads. A NORMALIZED disposition
        // carries the value (its canonical form) in the disposition
        // payload below, so the raw spelling must NOT also frame here —
        // otherwise spellings that normalize identically would still
        // diverge. Refused entries frame fully: the audit record shows
        // exactly what policy declined. The RegistryToken capability is
        // framed once, by its disposition — never duplicated here.
        let normalized = matches!(e.disposition, ConfigDisposition::Normalized { .. });
        match &e.kind {
            ConfigEntryKind::TargetDir(d) => {
                enc.u32(1);
                if !normalized {
                    enc.bytes(d);
                }
            }
            ConfigEntryKind::BuildJobs(j) => {
                enc.u32(2);
                if !normalized {
                    enc.u32(*j);
                }
            }
            ConfigEntryKind::Alias { name, argv } => {
                enc.u32(3).bytes(name);
                enc.seq(argv, |enc, a| {
                    enc.bytes(a);
                });
            }
            ConfigEntryKind::SourceReplacement {
                source,
                replace_with,
            } => {
                enc.u32(4).bytes(source).bytes(replace_with);
            }
            ConfigEntryKind::RegistryIndex { registry, url } => {
                enc.u32(5).bytes(registry).bytes(url);
            }
            ConfigEntryKind::RegistryDefault(url) => {
                enc.u32(6).bytes(url);
            }
            ConfigEntryKind::TargetRunner { triple, runner } => {
                enc.u32(7).bytes(triple);
                enc.seq(runner, |enc, r| {
                    enc.bytes(r);
                });
            }
            ConfigEntryKind::TargetLinker { triple, linker } => {
                enc.u32(8).bytes(triple).bytes(linker);
            }
            ConfigEntryKind::Rustflags {
                scoped_to_triple,
                flags,
            } => {
                enc.u32(9);
                enc.option(scoped_to_triple.as_ref(), |enc, t| {
                    enc.bytes(t);
                });
                enc.seq(flags, |enc, f| {
                    enc.bytes(f);
                });
            }
            ConfigEntryKind::CredentialHelper(reference) => {
                enc.u32(10).bytes(reference);
            }
            ConfigEntryKind::RegistryToken { registry, .. } => {
                enc.u32(11).bytes(registry);
            }
            ConfigEntryKind::ToolchainChannel(channel) => {
                enc.u32(12).bytes(channel);
            }
            ConfigEntryKind::Unrecognized {
                table_path,
                raw_value_toml,
            } => {
                enc.u32(13).bytes(table_path).bytes(raw_value_toml);
            }
        };
        // Disposition payload.
        match &e.disposition {
            ConfigDisposition::Keyed => {
                enc.u32(1);
            }
            ConfigDisposition::Normalized {
                normalizer,
                canonical,
            } => {
                enc.u32(2).str(normalizer).bytes(canonical);
            }
            ConfigDisposition::SecretOpaqueDigest(capability) => {
                enc.u32(3).str(capability.domain).bytes(&capability.bytes);
            }
            ConfigDisposition::GlobalRefused => {
                enc.u32(4);
            }
        };
    }
}

/// Canonical path check: absolute, no `.`/`..` components, no empty
/// segments, no trailing slash.
fn is_canonical_path(path: &[u8]) -> bool {
    if path.first() != Some(&b'/') || path.last() == Some(&b'/') {
        return false;
    }
    path.split(|&b| b == b'/')
        .skip(1)
        .all(|seg| !seg.is_empty() && seg != b"." && seg != b"..")
}

/// Path-spelling normalizer: collapse duplicate separators, drop a
/// trailing separator. Relative target-dir spellings are MEANINGFUL
/// (resolved against the config file's directory — K019), so no other
/// rewriting happens here.
fn normalize_path(path: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len());
    for &b in path {
        if b == b'/' && out.last() == Some(&b'/') {
            continue;
        }
        out.push(b);
    }
    while out.len() > 1 && out.last() == Some(&b'/') {
        out.pop();
    }
    out
}

// ---------------------------------------------------------------------
// Tests — the K015 acceptance matrix: origin visibility, host-global
// gating, secrets-as-capabilities, source replacement + alias fixtures.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ws_entry(kind: ConfigEntryKind) -> ObservedConfigEntry {
        ObservedConfigEntry {
            origin: ConfigOrigin::Workspace {
                path: b"/data/projects/rch/.cargo/config.toml".to_vec(),
            },
            kind,
        }
    }

    fn home_entry(kind: ConfigEntryKind) -> ObservedConfigEntry {
        ObservedConfigEntry {
            origin: ConfigOrigin::CargoHome,
            kind,
        }
    }

    #[test]
    fn source_replacement_fixtures_key_by_replacement_target() {
        let a = classify_contract(
            &[ws_entry(ConfigEntryKind::SourceReplacement {
                source: b"crates-io".to_vec(),
                replace_with: b"internal-mirror".to_vec(),
            })],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        let b = classify_contract(
            &[ws_entry(ConfigEntryKind::SourceReplacement {
                source: b"crates-io".to_vec(),
                replace_with: b"public-crates-io".to_vec(),
            })],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        assert_ne!(a.provenance_digest(), b.provenance_digest());
        let again = classify_contract(
            &[ws_entry(ConfigEntryKind::SourceReplacement {
                source: b"crates-io".to_vec(),
                replace_with: b"internal-mirror".to_vec(),
            })],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        assert_eq!(a.provenance_digest(), again.provenance_digest());
    }

    #[test]
    fn alias_fixture_keys_name_and_argv_order() {
        let mk = |argv: Vec<Vec<u8>>| {
            classify_contract(
                &[ws_entry(ConfigEntryKind::Alias {
                    name: b"checkall".to_vec(),
                    argv,
                })],
                GlobalInfluencePolicy::DeclaredHostGlobal,
            )
            .expect("classify")
        };
        let base = mk(vec![b"check".to_vec(), b"--workspace".to_vec()]);
        let reordered = mk(vec![b"--workspace".to_vec(), b"check".to_vec()]);
        assert_ne!(base.provenance_digest(), reordered.provenance_digest());
        assert_eq!(base.provenance_digest(), base.provenance_digest());
        // Empty expansion is a classification failure, not a key.
        assert!(matches!(
            classify(
                &ws_entry(ConfigEntryKind::Alias {
                    name: b"empty".to_vec(),
                    argv: vec![],
                }),
                GlobalInfluencePolicy::DeclaredHostGlobal,
            ),
            Err(ConfigProvenanceError::EmptyExpansion { .. })
        ));
    }

    #[test]
    fn origin_is_always_visible_same_value_different_origin_different_key() {
        let kind = ConfigEntryKind::BuildJobs(4);
        let from_ws = classify_contract(
            &[ws_entry(kind.clone())],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        let from_home = classify_contract(
            &[home_entry(kind)],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        // Influence is never INVISIBLE: identical values from different
        // origins produce different provenance.
        assert_ne!(from_ws.provenance_digest(), from_home.provenance_digest());
    }

    #[test]
    fn host_global_forbidden_entries_refuse_but_stay_in_record() {
        let entries = vec![
            home_entry(ConfigEntryKind::BuildJobs(16)),
            ws_entry(ConfigEntryKind::BuildJobs(4)),
        ];
        let forbidden =
            classify_contract(&entries, GlobalInfluencePolicy::ForbidHostGlobal).expect("classify");
        let declared = classify_contract(&entries, GlobalInfluencePolicy::DeclaredHostGlobal)
            .expect("classify");
        // Forbidden: global entry contributes nothing to provenance…
        assert!(!forbidden.entries[0].disposition.keys());
        // …so the workspace-only value fully determines the key side…
        let ws_only = classify_contract(
            std::slice::from_ref(&entries[1]),
            GlobalInfluencePolicy::ForbidHostGlobal,
        )
        .expect("classify");
        assert_eq!(forbidden.provenance_digest(), ws_only.provenance_digest());
        // …while the audit record still shows the refusal.
        assert_ne!(forbidden.record_digest(), ws_only.record_digest());
        // Declared: the same global entry visibly participates.
        assert!(declared.entries[0].disposition.keys());
        assert_ne!(declared.provenance_digest(), forbidden.provenance_digest());
    }

    #[test]
    fn registry_token_is_capability_only_and_never_affects_key_via_plaintext() {
        let token_cap = secret_capability_digest(b"internal-registry", b"super-secret-token");
        let entry = ObservedConfigEntry {
            origin: ConfigOrigin::EnvOverride {
                name: b"CARGO_REGISTRIES_INTERNAL_REGISTRY_TOKEN".to_vec(),
            },
            kind: ConfigEntryKind::RegistryToken {
                registry: b"internal-registry".to_vec(),
                capability: token_cap.clone(),
            },
        };
        let contract = classify_contract(&[entry], GlobalInfluencePolicy::DeclaredHostGlobal)
            .expect("classify");
        match &contract.entries[0].disposition {
            ConfigDisposition::SecretOpaqueDigest(d) => assert_eq!(d, &token_cap),
            other => panic!("expected secret capability, got {other:?}"),
        }
        // Different plaintext → different capability → different key.
        let other_cap = secret_capability_digest(b"internal-registry", b"rotated-token");
        let rotated = classify_contract(
            &[ObservedConfigEntry {
                origin: ConfigOrigin::EnvOverride {
                    name: b"CARGO_REGISTRIES_INTERNAL_REGISTRY_TOKEN".to_vec(),
                },
                kind: ConfigEntryKind::RegistryToken {
                    registry: b"internal-registry".to_vec(),
                    capability: other_cap,
                },
            }],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        assert_ne!(contract.provenance_digest(), rotated.provenance_digest());
    }

    #[test]
    fn precedence_order_is_semantic() {
        let jobs = ws_entry(ConfigEntryKind::BuildJobs(4));
        let target_dir = ws_entry(ConfigEntryKind::TargetDir(b"/tmp/target".to_vec()));
        let ab = classify_contract(
            &[jobs.clone(), target_dir.clone()],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        let ba = classify_contract(
            &[target_dir, jobs],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        assert_ne!(ab.provenance_digest(), ba.provenance_digest());
    }

    #[test]
    fn non_canonical_paths_fail_closed() {
        for bad in [
            &b"relative/config.toml"[..],
            b"/a/../b/config.toml".as_slice(),
            b"/double//slash.toml".as_slice(),
            b"/trailing/".as_slice(),
        ] {
            assert!(
                matches!(
                    classify(
                        &ObservedConfigEntry {
                            origin: ConfigOrigin::Workspace { path: bad.to_vec() },
                            kind: ConfigEntryKind::RegistryDefault(b"https://example.io".to_vec()),
                        },
                        GlobalInfluencePolicy::DeclaredHostGlobal,
                    ),
                    Err(ConfigProvenanceError::NonCanonicalConfigPath { .. })
                ),
                "expected refusal for {bad:?}"
            );
        }
    }

    #[test]
    fn unrecognized_tables_key_verbatim_fail_closed() {
        let a = classify_contract(
            &[ws_entry(ConfigEntryKind::Unrecognized {
                table_path: b"future.experimental-flag".to_vec(),
                raw_value_toml: b"true".to_vec(),
            })],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        let b = classify_contract(
            &[ws_entry(ConfigEntryKind::Unrecognized {
                table_path: b"future.experimental-flag".to_vec(),
                raw_value_toml: b"false".to_vec(),
            })],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        assert_ne!(a.provenance_digest(), b.provenance_digest());
    }

    #[test]
    fn toolchain_selection_inputs_capture_channel_and_file_origin() {
        let file = ObservedConfigEntry {
            origin: ConfigOrigin::ToolchainFile {
                path: b"/data/projects/rch/rust-toolchain.toml".to_vec(),
            },
            kind: ConfigEntryKind::ToolchainChannel(b"nightly-2026-08-01".to_vec()),
        };
        let env = ObservedConfigEntry {
            origin: ConfigOrigin::EnvOverride {
                name: b"RUSTUP_TOOLCHAIN".to_vec(),
            },
            kind: ConfigEntryKind::ToolchainChannel(b"nightly-2026-08-01".to_vec()),
        };
        let a = classify_contract(&[file], GlobalInfluencePolicy::DeclaredHostGlobal).expect("ok");
        let b = classify_contract(&[env], GlobalInfluencePolicy::DeclaredHostGlobal).expect("ok");
        // Same channel, different selection mechanism → visible difference.
        assert_ne!(a.provenance_digest(), b.provenance_digest());
    }

    #[test]
    fn target_dir_normalizes_spelling_not_location() {
        let mk = |dir: &[u8]| {
            classify_contract(
                &[ws_entry(ConfigEntryKind::TargetDir(dir.to_vec()))],
                GlobalInfluencePolicy::DeclaredHostGlobal,
            )
            .expect("classify")
        };
        assert_eq!(
            mk(b"target//").provenance_digest(),
            mk(b"target").provenance_digest()
        );
        assert_ne!(
            mk(b"target").provenance_digest(),
            mk(b"target-release").provenance_digest()
        );
    }

    #[test]
    fn credential_helper_reference_keys_without_secret_material() {
        let a = classify_contract(
            &[home_entry(ConfigEntryKind::CredentialHelper(
                b"!/usr/local/bin/arch-vault-helper".to_vec(),
            ))],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        let b = classify_contract(
            &[home_entry(ConfigEntryKind::CredentialHelper(
                b"/usr/bin/cargo-credential-1password".to_vec(),
            ))],
            GlobalInfluencePolicy::DeclaredHostGlobal,
        )
        .expect("classify");
        assert_ne!(a.provenance_digest(), b.provenance_digest());
        // And under a forbid policy the helper reference refuses too:
        // host-global means host-global, even for references.
        let refused = classify(
            &home_entry(ConfigEntryKind::CredentialHelper(b"x".to_vec())),
            GlobalInfluencePolicy::ForbidHostGlobal,
        )
        .expect("classify");
        assert_eq!(refused, ConfigDisposition::GlobalRefused);
    }

    #[test]
    fn rustflags_frame_scope_and_flag_order() {
        let mk = |scoped: Option<Vec<u8>>, flags: Vec<Vec<u8>>| {
            classify_contract(
                &[ws_entry(ConfigEntryKind::Rustflags {
                    scoped_to_triple: scoped,
                    flags,
                })],
                GlobalInfluencePolicy::DeclaredHostGlobal,
            )
            .expect("classify")
        };
        let global_ab = mk(None, vec![b"-A".to_vec(), b"-B".to_vec()]);
        let global_ba = mk(None, vec![b"-B".to_vec(), b"-A".to_vec()]);
        assert_ne!(global_ab.provenance_digest(), global_ba.provenance_digest());
        let scoped = mk(
            Some(b"aarch64-unknown-linux-gnu".to_vec()),
            vec![b"-A".to_vec(), b"-B".to_vec()],
        );
        assert_ne!(global_ab.provenance_digest(), scoped.provenance_digest());
    }
}
