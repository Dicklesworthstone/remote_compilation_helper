//! Explicit external-input capabilities (bead E030; risk R129;
//! fixture family T051).
//!
//! Everything an action reads outside the workspace/path-dependency
//! closure must be one of:
//!
//! - a declared immutable toolchain/SDK/native DATASET (the D-series
//!   mounts under `/__rabs/toolchain` etc.), or
//! - an [`ExternalInputCapability`]: a declared external tree with a
//!   stable virtual mount, object identity, metadata/filesystem
//!   class, privacy scope, and a revocation/version identity.
//!
//! A raw host absolute path can never become a portable input by
//! accident: the resolver either maps a read to a declared mount (the
//! CANONICAL path + keyed identity), or the action goes
//! local-only/volatile with an explanation — an undeclared `/opt`
//! read is the acceptance fixture, and "too broad/mutable to
//! snapshot" is a declared refusal, not a silent best-effort.

use rabs_protocol::result_identity::ObjectId;

/// One declared external-input capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalInputCapability {
    /// Capability name (project-unique).
    pub name: String,
    /// The real host root this capability covers.
    pub host_root: String,
    /// The stable virtual mount it maps to (`/__rabs/external/<name>`).
    pub virtual_mount: String,
    /// Snapshot object identity of the tree contents.
    pub object: ObjectId,
    /// D022 filesystem semantic class keying string.
    pub filesystem_class: String,
    /// Privacy scope identifier.
    pub privacy_scope: String,
    /// Revocation/version identity (bumped when the tree changes).
    pub version: u32,
}

/// Resolution of one external read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalReadResolution {
    /// Mapped through a declared capability: the canonical virtual
    /// path plus the keyed identity (object + version).
    Declared {
        /// Canonical virtual path.
        virtual_path: String,
        /// The snapshot object identity (keyed).
        object: ObjectId,
        /// The capability version (keyed — revocation forks keys).
        version: u32,
    },
    /// Undeclared external read: the action becomes local-only /
    /// volatile, with the explanation `rch why` renders.
    LocalOnly {
        /// The offending path.
        path: String,
        /// Why.
        explanation: String,
    },
}

/// Resolve one external read against the declared capabilities.
#[must_use]
pub fn resolve_external_read(
    host_path: &str,
    declared: &[ExternalInputCapability],
) -> ExternalReadResolution {
    for capability in declared {
        let root = &capability.host_root;
        if host_path == root || host_path.starts_with(&format!("{root}/")) {
            let suffix = &host_path[root.len()..];
            return ExternalReadResolution::Declared {
                virtual_path: format!("{}{suffix}", capability.virtual_mount),
                object: capability.object.clone(),
                version: capability.version,
            };
        }
    }
    ExternalReadResolution::LocalOnly {
        path: host_path.to_owned(),
        explanation: format!(
            "read outside the workspace closure at `{host_path}` matches no \
             declared ExternalInputCapability; declare one (with a snapshot \
             identity and version) to restore remote/cache eligibility"
        ),
    }
}

/// Why a capability declaration itself is refused at configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityRefusal {
    /// The root is too broad to snapshot and reproduce.
    TooBroad(&'static str),
    /// The mount is not under the canonical external prefix.
    NonCanonicalMount,
}

/// Validate one capability declaration. Roots that cannot be
/// snapshotted reproducibly are refused AT DECLARATION — a declared
/// refusal, never a silent best-effort at discovery time.
///
/// # Errors
/// [`CapabilityRefusal`] naming the rule.
pub fn validate_capability(capability: &ExternalInputCapability) -> Result<(), CapabilityRefusal> {
    const UNSNAPSHOTTABLE_ROOTS: [&str; 6] = ["/", "/proc", "/sys", "/dev", "/tmp", "/var"];
    if UNSNAPSHOTTABLE_ROOTS.contains(&capability.host_root.as_str()) {
        return Err(CapabilityRefusal::TooBroad(
            "root is too broad/mutable to snapshot and reproduce",
        ));
    }
    if !capability.virtual_mount.starts_with("/__rabs/external/") {
        return Err(CapabilityRefusal::NonCanonicalMount);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

    fn object(tag: u8) -> ObjectId {
        ObjectId(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        })
    }

    fn capability() -> ExternalInputCapability {
        ExternalInputCapability {
            name: "vendor-sdk".into(),
            host_root: "/opt/vendor-sdk-3.1".into(),
            virtual_mount: "/__rabs/external/vendor-sdk".into(),
            object: object(1),
            filesystem_class:
                "case-sensitive.unicode-bytes.symlink-posix.hardlink-posix.perm-execbit.xattr-hidden"
                    .into(),
            privacy_scope: "org-internal".into(),
            version: 3,
        }
    }

    #[test]
    fn undeclared_opt_read_goes_local_only_with_explanation() {
        // THE T051 acceptance fixture.
        let resolution = resolve_external_read("/opt/mystery-lib/include/x.h", &[capability()]);
        let ExternalReadResolution::LocalOnly { path, explanation } = resolution else {
            panic!("undeclared external read must go local-only");
        };
        assert_eq!(path, "/opt/mystery-lib/include/x.h");
        assert!(explanation.contains("no declared ExternalInputCapability"));
        assert!(explanation.contains("declare one"));
    }

    #[test]
    fn declared_capability_produces_canonical_mount_and_keyed_identity() {
        // THE T051 acceptance's second half.
        let resolution =
            resolve_external_read("/opt/vendor-sdk-3.1/include/api.h", &[capability()]);
        assert_eq!(
            resolution,
            ExternalReadResolution::Declared {
                virtual_path: "/__rabs/external/vendor-sdk/include/api.h".into(),
                object: object(1),
                version: 3,
            }
        );
        // Version participates: a revoked/rotated tree is a different
        // keyed identity.
        let mut rotated = capability();
        rotated.version = 4;
        rotated.object = object(2);
        let after = resolve_external_read("/opt/vendor-sdk-3.1/include/api.h", &[rotated]);
        assert_ne!(resolution, after);
    }

    #[test]
    fn raw_prefix_lookalikes_do_not_resolve() {
        // /opt/vendor-sdk-3.1-evil must NOT map through the capability
        // (prefix match is path-component aware).
        let resolution = resolve_external_read("/opt/vendor-sdk-3.1-evil/x", &[capability()]);
        assert!(matches!(
            resolution,
            ExternalReadResolution::LocalOnly { .. }
        ));
    }

    #[test]
    fn too_broad_or_mutable_roots_refuse_at_declaration() {
        for root in ["/", "/proc", "/tmp", "/var"] {
            let mut broad = capability();
            broad.host_root = root.into();
            assert!(
                matches!(
                    validate_capability(&broad),
                    Err(CapabilityRefusal::TooBroad(_))
                ),
                "{root} must refuse"
            );
        }
        // Non-canonical mount prefix refuses too.
        let mut wrong_mount = capability();
        wrong_mount.virtual_mount = "/mnt/sdk".into();
        assert_eq!(
            validate_capability(&wrong_mount),
            Err(CapabilityRefusal::NonCanonicalMount)
        );
        assert_eq!(validate_capability(&capability()), Ok(()));
    }
}
