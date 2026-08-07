//! The five RABS schema version registries (bead A005).
//!
//! Every canonical serialization in RABS carries explicit schema identity,
//! and this module is the single authoritative catalog of those identities
//! across the five domains: **key**, **protocol**, **database**,
//! **object-manifest**, and **sandbox**.
//!
//! ## Epoch doctrine (binding)
//!
//! A version bump creates a **cold namespace**: old entries are never
//! reinterpreted under new semantics. Bumps are required for adding a
//! previously omitted semantic or negative input, changing path or
//! environment normalization, changing dependency projection, changing
//! sandbox-visible state, changing canonical serialization, or changing
//! logical output interpretation (plan §17.1).
//!
//! ## Change discipline
//!
//! The registry is guarded by a fingerprint change-detector test: any edit
//! to entries fails the test until the recorded golden fingerprint is
//! updated in the same change, forcing registry edits to be deliberate and
//! reviewable. Struct-level enforcement (a schema type changing without its
//! registry entry bumping) extends as the concrete types land and is wired
//! into dependency-direction/schema CI by bead A002.

/// The five schema domains. Identifiers from different domains are never
/// interchangeable, mirroring the typed digest-domain rule (risk R121).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaDomain {
    /// Action-key construction: keys, families, breakdowns, epochs,
    /// projections (Epic F).
    Key,
    /// Wire protocols: the local wrapper protocol, the RABS application
    /// protocol, and the ATP transport it rides on (Epics C and J).
    Protocol,
    /// Durable metadata-store schemas (Epic H).
    Database,
    /// Object/manifest formats in the CAS (Epic H).
    ObjectManifest,
    /// Sandbox, isolation, and capture policies (Epics D and E).
    Sandbox,
}

impl SchemaDomain {
    /// Stable lowercase identifier used in serialized schema references.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Protocol => "protocol",
            Self::Database => "database",
            Self::ObjectManifest => "object-manifest",
            Self::Sandbox => "sandbox",
        }
    }
}

/// One registered schema: a versioned, domain-scoped canonical identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaEntry {
    /// Domain this schema belongs to.
    pub domain: SchemaDomain,
    /// Stable dotted name, unique within the whole registry.
    pub name: &'static str,
    /// Current version. A bump is a cold namespace, never a reinterpretation.
    pub version: u32,
    /// What the schema covers and which beads populate it.
    pub notes: &'static str,
}

/// The authoritative registry. Append entries as schemas land; never delete
/// or renumber an entry that shipped (retire by note instead).
pub const REGISTRY: &[SchemaEntry] = &[
    // ---- Key domain -----------------------------------------------------
    SchemaEntry {
        domain: SchemaDomain::Key,
        name: "rabs.action-key",
        version: 1,
        notes: "SHA-256 over length-delimited canonical descriptor bytes, \
                digest domain \"rabs.action-key.sha256.v1\" (beads F001/F034).",
    },
    SchemaEntry {
        domain: SchemaDomain::Key,
        name: "rabs.action-family-key",
        version: 1,
        notes: "Stable source-independent unit/invocation-shape identity for \
                discovery singleflight and recipes (bead F016).",
    },
    SchemaEntry {
        domain: SchemaDomain::Key,
        name: "rabs.action-key-breakdown",
        version: 1,
        notes: "Redaction-safe component tree returned with every key; powers \
                rch why miss diffs (beads F012/F013).",
    },
    SchemaEntry {
        domain: SchemaDomain::Key,
        name: "rabs.dependency-projection",
        version: 1,
        notes: "Versioned dependency-artifact projection epoch; v1 is the \
                conservative exact-artifact identity only (beads F009/F010).",
    },
    SchemaEntry {
        domain: SchemaDomain::Key,
        name: "rabs.observed-input-recipe",
        version: 1,
        notes: "ActionFamilyKey-scoped discovery recipe (optimization hint, \
                never a trust anchor; beads E011/E012).",
    },
    // ---- Protocol domain ------------------------------------------------
    SchemaEntry {
        domain: SchemaDomain::Protocol,
        name: "rabs.local-wrapper",
        version: 1,
        notes: "Wrapper<->edge Unix-socket protocol: length-bounded canonical \
                frames, resumable subscriber tokens, two-frontier delivery \
                (Epic C; beads C001/C002).",
    },
    SchemaEntry {
        domain: SchemaDomain::Protocol,
        name: "rabs.application",
        version: 1,
        notes: "\"RABS/1\": the typed action/CAS/health/reconciliation \
                application protocol; negotiated explicitly, never implied \
                (bead J002).",
    },
    SchemaEntry {
        domain: SchemaDomain::Protocol,
        name: "atp.transport",
        version: 0,
        notes: "\"ATP/0\": the transport RABS/1 rides on. Transport and \
                application versions evolve independently; no \"ATP/0+\" \
                ambiguity (plan Part I sec 2).",
    },
    SchemaEntry {
        domain: SchemaDomain::Protocol,
        name: "rabs.reason-codes",
        version: 1,
        notes: "Stable machine-readable reason-code registry; append-only \
                within a protocol major version (bead A006).",
    },
    // ---- Database domain ------------------------------------------------
    SchemaEntry {
        domain: SchemaDomain::Database,
        name: "rabs.metadata-store",
        version: 1,
        notes: "RabsMetadataStore logical tables: authorities, high-water \
                marks, incarnation fences, generations+tombstones, immutable \
                publications, mutable serving states, evidence/trust, pins, \
                leases, quarantine (beads H009/H038). Transactional, \
                versioned migrations only.",
    },
    // ---- Object-manifest domain ------------------------------------------
    SchemaEntry {
        domain: SchemaDomain::ObjectManifest,
        name: "rabs.object-manifest",
        version: 1,
        notes: "Logical object/tree manifests: acyclic, depth/fan-out \
                bounded, path/type validated before storage and \
                materialization (beads H001/H027/H031).",
    },
    SchemaEntry {
        domain: SchemaDomain::ObjectManifest,
        name: "rabs.artifact-bundle",
        version: 1,
        notes: "Complete action-result output set, deterministically derived \
                from the single role-tagged logical-output map (bead F035).",
    },
    SchemaEntry {
        domain: SchemaDomain::ObjectManifest,
        name: "rabs.chunking-profile",
        version: 1,
        notes: "Content-defined chunking parameters; old manifests are never \
                reinterpreted under new settings (bead H004).",
    },
    SchemaEntry {
        domain: SchemaDomain::ObjectManifest,
        name: "rabs.pack-format",
        version: 1,
        notes: "Deterministic small-object packs with bounded member \
                indexes; storage optimization, never a semantic key input \
                (bead H021).",
    },
    // ---- Sandbox domain --------------------------------------------------
    SchemaEntry {
        domain: SchemaDomain::Sandbox,
        name: "rabs.sandbox-semantic-policy",
        version: 1,
        notes: "Keyed sandbox semantics per ActionClass (bead E001); \
                scheduler-only implementation details excluded (I23).",
    },
    SchemaEntry {
        domain: SchemaDomain::Sandbox,
        name: "rabs.isolation-profile",
        version: 1,
        notes: "StrictHermeticLinux / StrictHermeticVm / HostSandboxAudit / \
                DependencyImmutableFastPath / VolatileLocal, recording what \
                was ACTUALLY enforced (I25/I28; bead E010).",
    },
    SchemaEntry {
        domain: SchemaDomain::Sandbox,
        name: "rabs.source-capture-policy",
        version: 1,
        notes: "BuildInputAllowed/LocalOnly/SecretCapability/Denied/\
                ExplicitOperatorApproval path classes; .gitignore is never a \
                security boundary (I38; bead E027).",
    },
    SchemaEntry {
        domain: SchemaDomain::Sandbox,
        name: "rabs.build-path-semantic-policy",
        version: 1,
        notes: "CanonicalPortablePath / PathOpaqueVerified / \
                ProjectRelativeRemapped / SubscriberPathPreserving (I41; \
                bead D030).",
    },
];

/// Look up a schema entry by domain and name.
#[must_use]
pub fn lookup(domain: SchemaDomain, name: &str) -> Option<&'static SchemaEntry> {
    REGISTRY
        .iter()
        .find(|e| e.domain == domain && e.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FNV-1a over the registry's identity-bearing fields. Deliberately
    /// simple and dependency-free: this is a change detector, not a
    /// cryptographic commitment (authoritative digests are typed SHA-256
    /// per bead F034).
    fn registry_fingerprint() -> u64 {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = FNV_OFFSET;
        let mut eat = |bytes: &[u8]| {
            for &b in bytes {
                h ^= u64::from(b);
                h = h.wrapping_mul(FNV_PRIME);
            }
            h ^= 0xff;
            h = h.wrapping_mul(FNV_PRIME);
        };
        for e in REGISTRY {
            eat(e.domain.as_str().as_bytes());
            eat(e.name.as_bytes());
            eat(&e.version.to_le_bytes());
        }
        h
    }

    /// Any edit to registry entries (add/remove/rename/renumber) must be
    /// deliberate: update this golden in the SAME change, with review.
    #[test]
    fn registry_change_is_deliberate() {
        let fp = registry_fingerprint();
        assert_eq!(
            fp, 0x7314_db1a_cae6_5ee3,
            "schema registry changed (fingerprint {fp:#x}); if intentional, \
             bump the affected schema versions per the epoch doctrine and \
             update this golden in the same commit"
        );
    }

    #[test]
    fn names_are_globally_unique() {
        for (i, a) in REGISTRY.iter().enumerate() {
            for b in &REGISTRY[i + 1..] {
                assert_ne!(
                    a.name, b.name,
                    "duplicate schema name across the registry: {}",
                    a.name
                );
            }
        }
    }

    #[test]
    fn every_domain_has_at_least_one_entry() {
        for d in [
            SchemaDomain::Key,
            SchemaDomain::Protocol,
            SchemaDomain::Database,
            SchemaDomain::ObjectManifest,
            SchemaDomain::Sandbox,
        ] {
            assert!(
                REGISTRY.iter().any(|e| e.domain == d),
                "schema domain {:?} has no registered entries",
                d
            );
        }
    }

    #[test]
    fn lookup_finds_registered_and_rejects_cross_domain() {
        let hit = lookup(SchemaDomain::Key, "rabs.action-key");
        assert!(hit.is_some(), "rabs.action-key must be registered");
        assert_eq!(hit.map(|e| e.version), Some(1));
        // Domain scoping: the same name under another domain is a miss —
        // identifiers from different domains are never interchangeable.
        assert!(lookup(SchemaDomain::Sandbox, "rabs.action-key").is_none());
        assert!(lookup(SchemaDomain::Key, "no.such.schema").is_none());
    }

    #[test]
    fn notes_and_names_are_nonempty() {
        for e in REGISTRY {
            assert!(!e.name.is_empty(), "empty schema name");
            assert!(
                !e.notes.trim().is_empty(),
                "schema {} has empty notes",
                e.name
            );
        }
    }
}
