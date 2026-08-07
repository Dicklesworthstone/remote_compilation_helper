//! Undeclared-read / capability-version / broad-tree / cross-host
//! mount differential scenarios (bead T051; risk R129; drives the
//! E030 capability machinery end to end).
//!
//! The four scenario families the bead names:
//!
//! 1. an undeclared absolute host read forces LOCAL/VOLATILE with an
//!    explanation — and declaring the capability restores canonical
//!    eligibility for the very same read;
//! 2. a capability VERSION bump (revocation) invalidates: the keyed
//!    identity (object, version) forks, so results cached under the
//!    old version can never serve the new one;
//! 3. over-broad/mutable trees are refused AT DECLARATION, typed —
//!    never a silent best-effort snapshot;
//! 4. canonical external mounts behave IDENTICALLY across hosts:
//!    two hosts with different host-root spellings resolve the same
//!    logical read to byte-identical canonical views.

use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};
use rabs_sandbox::external_inputs::{
    CapabilityRefusal, ExternalInputCapability, ExternalReadResolution, resolve_external_read,
    validate_capability,
};

fn object(tag: u8) -> ObjectId {
    ObjectId(TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: "rabs.object.v1",
        bytes: [tag; 32],
    })
}

fn sdk_capability(host_root: &str, version: u32) -> ExternalInputCapability {
    ExternalInputCapability {
        name: "vendor-sdk".into(),
        host_root: host_root.to_owned(),
        virtual_mount: "/__rabs/external/vendor-sdk".into(),
        object: object(1),
        filesystem_class:
            "case-sensitive.unicode-bytes.symlink-posix.hardlink-posix.perm-execbit.xattr-hidden"
                .into(),
        privacy_scope: "org-shared".into(),
        version,
    }
}

#[test]
fn undeclared_reads_force_local_volatile_and_declaration_restores() {
    // SCENARIO 1: the acceptance fixture — an undeclared /opt read.
    let undeclared = resolve_external_read("/opt/obscure-sdk/include/api.h", &[]);
    match undeclared {
        ExternalReadResolution::LocalOnly { path, explanation } => {
            assert_eq!(path, "/opt/obscure-sdk/include/api.h");
            assert!(
                explanation.contains("ExternalInputCapability"),
                "the explanation tells the user the fix"
            );
        }
        ExternalReadResolution::Declared { .. } => panic!("undeclared read must not map"),
    }
    // Declaring the capability restores canonical eligibility for
    // the SAME read.
    let mut cap = sdk_capability("/opt/obscure-sdk", 1);
    cap.name = "obscure-sdk".into();
    cap.virtual_mount = "/__rabs/external/obscure-sdk".into();
    assert_eq!(validate_capability(&cap), Ok(()));
    assert_eq!(
        resolve_external_read("/opt/obscure-sdk/include/api.h", &[cap]),
        ExternalReadResolution::Declared {
            virtual_path: "/__rabs/external/obscure-sdk/include/api.h".into(),
            object: object(1),
            version: 1,
        }
    );
}

#[test]
fn capability_version_changes_invalidate() {
    // SCENARIO 2: the SDK tree changed on disk; the operator bumps
    // the version (revocation of the old snapshot). The keyed
    // identity forks — a result cached under v1 cannot match v2.
    let read = "/opt/vendor-sdk-3.1/lib/libvendor.a";
    let v1 = resolve_external_read(read, &[sdk_capability("/opt/vendor-sdk-3.1", 1)]);
    let mut updated = sdk_capability("/opt/vendor-sdk-3.1", 2);
    updated.object = object(9); // the re-snapshot has new content
    let v2 = resolve_external_read(read, &[updated]);
    let (
        ExternalReadResolution::Declared {
            virtual_path: p1,
            object: o1,
            version: s1,
        },
        ExternalReadResolution::Declared {
            virtual_path: p2,
            object: o2,
            version: s2,
        },
    ) = (v1, v2)
    else {
        panic!("both resolutions are declared");
    };
    assert_eq!(p1, p2, "the canonical path is stable across versions");
    assert_ne!(
        (o1, s1),
        (o2, s2),
        "the KEYED identity forks — old hits die"
    );
    assert_eq!((s1, s2), (1, 2));
}

#[test]
fn over_broad_and_mutable_trees_refuse_at_declaration() {
    // SCENARIO 3: each unsnapshottable root refuses TYPED, at
    // declaration time — never a silent best-effort later.
    for root in ["/", "/proc", "/sys", "/dev", "/tmp", "/var"] {
        let cap = sdk_capability(root, 1);
        assert!(
            matches!(
                validate_capability(&cap),
                Err(CapabilityRefusal::TooBroad(_))
            ),
            "{root} must refuse as too broad/mutable"
        );
    }
    // A non-canonical mount refuses on its own rule.
    let mut rogue = sdk_capability("/opt/vendor-sdk-3.1", 1);
    rogue.virtual_mount = "/mnt/sdk".into();
    assert_eq!(
        validate_capability(&rogue),
        Err(CapabilityRefusal::NonCanonicalMount)
    );
    // The well-formed declaration is the control.
    assert_eq!(
        validate_capability(&sdk_capability("/opt/vendor-sdk-3.1", 1)),
        Ok(())
    );
}

#[test]
fn canonical_mounts_behave_identically_across_hosts() {
    // SCENARIO 4 (the differential): host A keeps the SDK at
    // /opt/vendor-sdk-3.1, host B at /usr/local/sdk/vendor. Same
    // logical capability (name/object/version). The SAME logical
    // read resolves to BYTE-IDENTICAL canonical views on both hosts
    // — host spelling is gone from the keyed identity entirely.
    let host_a = sdk_capability("/opt/vendor-sdk-3.1", 3);
    let host_b = sdk_capability("/usr/local/sdk/vendor", 3);
    let read_a = resolve_external_read("/opt/vendor-sdk-3.1/include/vendor.h", &[host_a]);
    let read_b = resolve_external_read("/usr/local/sdk/vendor/include/vendor.h", &[host_b]);
    assert_eq!(read_a, read_b, "identical canonical view on both hosts");
    let ExternalReadResolution::Declared { virtual_path, .. } = read_a else {
        panic!("declared");
    };
    assert_eq!(virtual_path, "/__rabs/external/vendor-sdk/include/vendor.h");
}

#[test]
fn prefix_matching_is_exact_component_boundaries() {
    // Negative space for scenario 1: a SIBLING path sharing a string
    // prefix (`/opt/vendor-sdk-3.1-beta`) is NOT covered by the
    // declared root — it stays local/volatile rather than riding a
    // capability it does not belong to.
    let cap = sdk_capability("/opt/vendor-sdk-3.1", 1);
    let sibling = resolve_external_read("/opt/vendor-sdk-3.1-beta/lib/x.a", &[cap]);
    assert!(
        matches!(sibling, ExternalReadResolution::LocalOnly { .. }),
        "string-prefix siblings must not map through the capability"
    );
}
