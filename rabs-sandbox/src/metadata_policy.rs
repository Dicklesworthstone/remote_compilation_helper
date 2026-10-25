//! Symlink / xattr / permission metadata policy (bead D016; plan §28;
//! risks R47/R82).
//!
//! Filesystem metadata is a SEMANTIC channel, not decoration: an
//! executable bit decides whether a build script runs, a symlink target
//! decides what bytes an include resolves to, and platform xattrs carry
//! code signatures (macOS `com.apple.cs.*`) and SDK attributes that
//! make a toolchain binary loadable at all. Materialization therefore
//! follows an explicit **object profile** that says which metadata is
//! retained — and everything outside the profile is DROPPED, because
//! smuggling un-declared metadata across hosts is exactly how "same
//! object" becomes two different objects:
//!
//! - executable bits: retained where the profile says so;
//! - symlink targets: byte-preserved, always (a rewritten target is a
//!   different object — there is no profile that "fixes" symlinks);
//! - xattrs/ACLs: retained ONLY via an explicit profile allowlist
//!   (prefix match, e.g. `com.apple.cs.` for signature preservation);
//!   no profile ⇒ none travel;
//! - verification is a typed refusal list, not a boolean: each
//!   violation names the path, the channel, and both sides.

use std::collections::BTreeMap;

/// Which metadata one object class retains through materialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectProfile {
    /// Human-stable profile name (bound into receipts).
    pub name: &'static str,
    /// Retain the executable permission bit.
    pub executable_bits: bool,
    /// Xattr NAME PREFIXES retained (empty = no xattrs travel).
    pub xattr_allowlist: Vec<&'static str>,
    /// Whether POSIX ACLs may travel (explicit opt-in; default no).
    pub acls: bool,
}

impl ObjectProfile {
    /// Source trees: exec bits matter (scripts), no xattrs, no ACLs.
    #[must_use]
    pub fn source() -> Self {
        Self {
            name: "source",
            executable_bits: true,
            xattr_allowlist: Vec::new(),
            acls: false,
        }
    }

    /// Toolchains: exec bits plus platform-critical xattrs — macOS
    /// code-signature (`com.apple.cs.`), quarantine-free provenance
    /// (`com.apple.provenance`), and SDK attributes.
    #[must_use]
    pub fn toolchain() -> Self {
        Self {
            name: "toolchain",
            executable_bits: true,
            xattr_allowlist: vec!["com.apple.cs.", "com.apple.provenance", "user.rabs.sdk."],
            acls: false,
        }
    }

    /// Build outputs: exec bits (produced binaries), nothing else.
    #[must_use]
    pub fn output() -> Self {
        Self {
            name: "output",
            executable_bits: true,
            xattr_allowlist: Vec::new(),
            acls: false,
        }
    }

    /// Whether an xattr NAME is inside this profile's allowlist.
    #[must_use]
    pub fn retains_xattr(&self, name: &str) -> bool {
        self.xattr_allowlist
            .iter()
            .any(|prefix| name.starts_with(prefix))
    }
}

/// Observed metadata for one materialized object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetadataObservation {
    /// Executable bit observed (any of ugo+x).
    pub executable: bool,
    /// Symlink target bytes (None for non-symlinks).
    pub symlink_target: Option<Vec<u8>>,
    /// Extended attributes by name.
    pub xattrs: BTreeMap<String, Vec<u8>>,
    /// Whether a POSIX ACL beyond the mode bits is present.
    pub has_acl: bool,
}

/// One typed violation found by materialization verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataViolation {
    /// Executable bit lost (profile retains it) or gained (never OK).
    ExecutableBitChanged {
        /// The affected path.
        path: String,
        /// Source had the bit.
        source: bool,
        /// Materialized has the bit.
        materialized: bool,
    },
    /// Symlink target bytes differ — always a violation.
    SymlinkTargetRewritten {
        /// The affected path.
        path: String,
        /// Source target bytes.
        source: Vec<u8>,
        /// Materialized target bytes.
        materialized: Vec<u8>,
    },
    /// Symlink became a regular file or vice versa.
    SymlinkKindChanged {
        /// The affected path.
        path: String,
    },
    /// A profile-critical xattr was lost or its value changed.
    CriticalXattrLost {
        /// The affected path.
        path: String,
        /// The xattr name.
        name: String,
    },
    /// An xattr OUTSIDE the profile travelled anyway.
    UndeclaredXattrRetained {
        /// The affected path.
        path: String,
        /// The xattr name.
        name: String,
    },
    /// An ACL travelled without the profile's explicit opt-in.
    UndeclaredAclRetained {
        /// The affected path.
        path: String,
    },
}

/// Verify one materialized object against its source under a profile.
/// Empty result = faithful materialization.
#[must_use]
pub fn verify_materialization(
    profile: &ObjectProfile,
    path: &str,
    source: &MetadataObservation,
    materialized: &MetadataObservation,
) -> Vec<MetadataViolation> {
    let mut violations = Vec::new();

    // Symlinks first: kind and target are invariant under EVERY profile.
    match (&source.symlink_target, &materialized.symlink_target) {
        (Some(a), Some(b)) => {
            if a != b {
                violations.push(MetadataViolation::SymlinkTargetRewritten {
                    path: path.to_string(),
                    source: a.clone(),
                    materialized: b.clone(),
                });
            }
            return violations; // symlinks carry no exec/xattr semantics of their own
        }
        (None, None) => {}
        _ => {
            violations.push(MetadataViolation::SymlinkKindChanged {
                path: path.to_string(),
            });
            return violations;
        }
    }

    if profile.executable_bits && source.executable != materialized.executable
        || !source.executable && materialized.executable
    {
        violations.push(MetadataViolation::ExecutableBitChanged {
            path: path.to_string(),
            source: source.executable,
            materialized: materialized.executable,
        });
    }

    for (name, value) in &source.xattrs {
        if profile.retains_xattr(name) && materialized.xattrs.get(name) != Some(value) {
            violations.push(MetadataViolation::CriticalXattrLost {
                path: path.to_string(),
                name: name.clone(),
            });
        }
    }
    for name in materialized.xattrs.keys() {
        if !profile.retains_xattr(name) {
            violations.push(MetadataViolation::UndeclaredXattrRetained {
                path: path.to_string(),
                name: name.clone(),
            });
        }
    }

    if materialized.has_acl && !profile.acls {
        violations.push(MetadataViolation::UndeclaredAclRetained {
            path: path.to_string(),
        });
    }

    violations
}

/// Observe a real filesystem path (exec bit + symlink target; xattrs
/// and ACLs need platform APIs outside std and are supplied by the
/// caller's platform layer — this observer reports none).
pub fn observe_path(path: &std::path::Path) -> std::io::Result<MetadataObservation> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(path)?;
        return Ok(MetadataObservation {
            symlink_target: Some(target.as_os_str().as_encoded_bytes().to_vec()),
            ..Default::default()
        });
    }
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    Ok(MetadataObservation {
        executable,
        ..Default::default()
    })
}

/// One directory enumeration observed during action execution (`E028`, risk `R93`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedDirectoryReaddir {
    /// Canonical virtual directory path enumerated.
    pub directory_path: String,
    /// Exact sequence of entry names returned by `getdents64`/`readdir`.
    pub raw_readdir_order: Vec<Vec<u8>>,
    /// Whether the action consumed the raw `readdir` order without sorting
    /// (e.g. passing `readdir` stream directly into archive/codegen/link order).
    pub action_consumed_unsorted_order: bool,
    /// Host-local stat/dirent metadata fields observed by the action beyond
    /// portable content/type/exec-bit (e.g. `"st_ino"`, `"st_dev"`, `"st_mtime"`).
    pub observed_volatile_metadata_fields: Vec<String>,
}

/// Materializer/filesystem capability for reproducing `readdir` order (`E028`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializerReaddirClass {
    /// Virtual/FUSE/canonical overlay that always serves lexicographically
    /// sorted directory entries regardless of backing filesystem.
    CanonicalSortedOverlay,
    /// Pinned materializer + filesystem image class proven to reproduce the
    /// recorded raw `readdir` sequence.
    PinnedFilesystemClass {
        /// Stable identifier for the materializer/filesystem class.
        class_tag: String,
    },
    /// Unpinned native host filesystem (`ext4` HTree, `xfs`, `apfs`, `tmpfs`)
    /// whose raw `readdir` order is host/inode-allocation dependent.
    NativeHostFilesystem,
}

/// Authority and portability decision for directory order & metadata (`E028`, `R93`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryOrderDisposition {
    /// Action only depends on set membership (sorted `DirectoryEnumeration`)
    /// and portable metadata (`ObjectProfile`), or runs under `CanonicalSortedOverlay`
    /// with no volatile stat fields.
    PortableDeterministic,
    /// Action depends on raw `readdir` order, which is recorded in the closure
    /// and restricted to the proven materializer/filesystem class.
    RestrictedToMaterializerClass {
        /// The materializer/filesystem class required to replay or serve.
        required_class_tag: String,
        /// Recorded `(directory_path, raw_readdir_order)` closure entries.
        recorded_raw_order: Vec<(String, Vec<Vec<u8>>)>,
    },
    /// Action depends on unvirtualized volatile metadata (`st_ino`, `st_mtime`, …)
    /// or raw `readdir` order on an unpinned native filesystem; classified
    /// nonportable/volatile and denied shared cache authority.
    ClassifiedVolatile {
        /// Explicit diagnostic reason naming the directory and field/order sensitivity.
        reason: String,
        /// Resulting volatility effect class.
        effect_class: rabs_protocol::volatility::EffectClass,
    },
}

/// Classify observable directory order and metadata fields (`E028`, risk `R93`).
#[must_use]
pub fn classify_directory_order_and_metadata(
    observations: &[ObservedDirectoryReaddir],
    materializer: &MaterializerReaddirClass,
) -> DirectoryOrderDisposition {
    for obs in observations {
        if let Some(field) = obs.observed_volatile_metadata_fields.first() {
            return DirectoryOrderDisposition::ClassifiedVolatile {
                reason: format!(
                    "directory '{}' observed nonportable metadata field '{field}' (R93)",
                    obs.directory_path
                ),
                effect_class: rabs_protocol::volatility::EffectClass::HostIdentitySensitive,
            };
        }
    }

    let mut order_sensitive: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
    for obs in observations {
        let mut sorted = obs.raw_readdir_order.clone();
        sorted.sort_unstable();
        let raw_differs_from_sorted = obs.raw_readdir_order != sorted;
        if obs.action_consumed_unsorted_order && raw_differs_from_sorted {
            order_sensitive.push((obs.directory_path.clone(), obs.raw_readdir_order.clone()));
        } else if obs.action_consumed_unsorted_order
            && matches!(materializer, MaterializerReaddirClass::NativeHostFilesystem)
        {
            // Even if a particular run happened to yield sorted entries on a
            // native filesystem, an action that consumes unsorted readdir
            // order without a deterministic overlay or pinned class is
            // sensitive to native readdir drift.
            order_sensitive.push((obs.directory_path.clone(), obs.raw_readdir_order.clone()));
        }
    }

    if order_sensitive.is_empty() {
        return DirectoryOrderDisposition::PortableDeterministic;
    }

    match materializer {
        MaterializerReaddirClass::CanonicalSortedOverlay => {
            // CanonicalSortedOverlay enforces sorted readdir order; if the raw
            // observation already came from the canonical sorted overlay, it is
            // portable across all CanonicalSortedOverlay workers.
            if order_sensitive.iter().all(|(_, raw)| {
                let mut s = raw.clone();
                s.sort_unstable();
                *raw == s
            }) {
                DirectoryOrderDisposition::PortableDeterministic
            } else {
                DirectoryOrderDisposition::RestrictedToMaterializerClass {
                    required_class_tag: "canonical-sorted-overlay.v1".to_string(),
                    recorded_raw_order: order_sensitive,
                }
            }
        }
        MaterializerReaddirClass::PinnedFilesystemClass { class_tag } => {
            DirectoryOrderDisposition::RestrictedToMaterializerClass {
                required_class_tag: class_tag.clone(),
                recorded_raw_order: order_sensitive,
            }
        }
        MaterializerReaddirClass::NativeHostFilesystem => {
            let first_dir = &order_sensitive[0].0;
            DirectoryOrderDisposition::ClassifiedVolatile {
                reason: format!(
                    "directory '{first_dir}' raw readdir order is observable on unpinned native filesystem (R93)"
                ),
                effect_class: rabs_protocol::volatility::EffectClass::Nondeterministic,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(executable: bool) -> MetadataObservation {
        MetadataObservation {
            executable,
            ..Default::default()
        }
    }

    #[test]
    fn symlinked_source_fixture_targets_are_byte_preserved() {
        // THE symlink fixture: byte-weird target preserved exactly, a
        // rewritten target (e.g. absolute-ized by a naive copier) is a
        // named violation under EVERY profile.
        let target = b"../weird \xc3\xa9 target".to_vec();
        let source = MetadataObservation {
            symlink_target: Some(target.clone()),
            ..Default::default()
        };
        for profile in [
            ObjectProfile::source(),
            ObjectProfile::toolchain(),
            ObjectProfile::output(),
        ] {
            assert!(
                verify_materialization(&profile, "link.rs", &source, &source.clone()).is_empty()
            );
            let rewritten = MetadataObservation {
                symlink_target: Some(b"/abs/weird target".to_vec()),
                ..Default::default()
            };
            assert!(matches!(
                verify_materialization(&profile, "link.rs", &source, &rewritten)[0],
                MetadataViolation::SymlinkTargetRewritten { .. }
            ));
        }
        // Kind change (symlink flattened to a file) is caught too.
        assert!(matches!(
            verify_materialization(&ObjectProfile::source(), "link.rs", &source, &plain(false))[0],
            MetadataViolation::SymlinkKindChanged { .. }
        ));
    }

    #[test]
    fn executable_output_fixture_keeps_its_bit_and_never_gains_one() {
        let profile = ObjectProfile::output();
        // Retained: fine.
        assert!(verify_materialization(&profile, "bin/fx", &plain(true), &plain(true)).is_empty());
        // Lost: violation.
        assert!(matches!(
            verify_materialization(&profile, "bin/fx", &plain(true), &plain(false))[0],
            MetadataViolation::ExecutableBitChanged {
                source: true,
                materialized: false,
                ..
            }
        ));
        // GAINED exec is a violation even for a profile that does not
        // track exec bits — materialization must never mint authority.
        let no_exec_profile = ObjectProfile {
            name: "no-exec",
            executable_bits: false,
            xattr_allowlist: Vec::new(),
            acls: false,
        };
        assert!(matches!(
            verify_materialization(&no_exec_profile, "data", &plain(false), &plain(true))[0],
            MetadataViolation::ExecutableBitChanged { .. }
        ));
    }

    #[test]
    fn xattr_carrying_toolchain_fixture_keeps_signatures_drops_the_rest() {
        let profile = ObjectProfile::toolchain();
        let mut source = plain(true);
        source
            .xattrs
            .insert("com.apple.cs.CodeDirectory".into(), b"sig-bytes".to_vec());
        source
            .xattrs
            .insert("com.apple.quarantine".into(), b"0083;origin".to_vec());

        // Faithful: signature retained, quarantine dropped.
        let mut faithful = plain(true);
        faithful
            .xattrs
            .insert("com.apple.cs.CodeDirectory".into(), b"sig-bytes".to_vec());
        assert_eq!(
            verify_materialization(&profile, "bin/rustc", &source, &faithful),
            Vec::new()
        );

        // Signature lost: named violation.
        assert!(matches!(
            verify_materialization(&profile, "bin/rustc", &source, &plain(true))[0],
            MetadataViolation::CriticalXattrLost { ref name, .. }
                if name == "com.apple.cs.CodeDirectory"
        ));

        // Quarantine smuggled through anyway: named violation.
        let mut smuggled = faithful.clone();
        smuggled
            .xattrs
            .insert("com.apple.quarantine".into(), b"0083;origin".to_vec());
        assert!(matches!(
            verify_materialization(&profile, "bin/rustc", &source, &smuggled)[0],
            MetadataViolation::UndeclaredXattrRetained { ref name, .. }
                if name == "com.apple.quarantine"
        ));

        // Under the SOURCE profile the same signature xattr must NOT
        // travel: retention is profile-scoped, not global.
        assert!(matches!(
            verify_materialization(&ObjectProfile::source(), "bin/rustc", &source, &faithful)[0],
            MetadataViolation::UndeclaredXattrRetained { ref name, .. }
                if name == "com.apple.cs.CodeDirectory"
        ));
    }

    #[test]
    fn acls_travel_only_via_explicit_profile_opt_in() {
        let mut materialized = plain(false);
        materialized.has_acl = true;
        assert!(matches!(
            verify_materialization(
                &ObjectProfile::source(),
                "src/lib.rs",
                &plain(false),
                &materialized
            )[0],
            MetadataViolation::UndeclaredAclRetained { .. }
        ));
        let acl_profile = ObjectProfile {
            name: "acl-opt-in",
            executable_bits: false,
            xattr_allowlist: Vec::new(),
            acls: true,
        };
        assert!(
            verify_materialization(&acl_profile, "src/lib.rs", &plain(false), &materialized)
                .is_empty()
        );
    }

    #[test]
    fn real_fs_observer_reports_exec_bits_and_symlink_targets() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("script.sh");
        std::fs::write(&file, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
            let observed = observe_path(&file).unwrap();
            assert!(observed.executable);
            assert!(observed.symlink_target.is_none());

            std::os::unix::fs::symlink("script.sh", dir.path().join("link")).unwrap();
            let link = observe_path(&dir.path().join("link")).unwrap();
            assert_eq!(link.symlink_target, Some(b"script.sh".to_vec()));

            // Round-trip through the verifier: observe source, observe
            // a faithful copy, expect zero violations.
            let copy = dir.path().join("copy.sh");
            std::fs::copy(&file, &copy).unwrap();
            let violations = verify_materialization(
                &ObjectProfile::source(),
                "script.sh",
                &observe_path(&file).unwrap(),
                &observe_path(&copy).unwrap(),
            );
            assert_eq!(violations, Vec::new());
        }
    }

    #[test]
    fn e028_order_sensitive_and_volatile_metadata_fixtures_are_detected_and_restricted() {
        let sorted_consumer = ObservedDirectoryReaddir {
            directory_path: "/__rabs/workspace/src".into(),
            raw_readdir_order: vec![b"z.rs".to_vec(), b"a.rs".to_vec()],
            action_consumed_unsorted_order: false,
            observed_volatile_metadata_fields: Vec::new(),
        };
        assert_eq!(
            classify_directory_order_and_metadata(
                std::slice::from_ref(&sorted_consumer),
                &MaterializerReaddirClass::NativeHostFilesystem,
            ),
            DirectoryOrderDisposition::PortableDeterministic
        );

        // Order-sensitive consumer on an unpinned native filesystem -> ClassifiedVolatile.
        let unsorted_consumer = ObservedDirectoryReaddir {
            directory_path: "/__rabs/workspace/c_sources".into(),
            raw_readdir_order: vec![b"z.c".to_vec(), b"a.c".to_vec()],
            action_consumed_unsorted_order: true,
            observed_volatile_metadata_fields: Vec::new(),
        };
        assert!(matches!(
            classify_directory_order_and_metadata(
                std::slice::from_ref(&unsorted_consumer),
                &MaterializerReaddirClass::NativeHostFilesystem,
            ),
            DirectoryOrderDisposition::ClassifiedVolatile {
                effect_class: rabs_protocol::volatility::EffectClass::Nondeterministic,
                ..
            }
        ));

        // Order-sensitive consumer under a pinned filesystem class -> RestrictedToMaterializerClass.
        assert_eq!(
            classify_directory_order_and_metadata(
                std::slice::from_ref(&unsorted_consumer),
                &MaterializerReaddirClass::PinnedFilesystemClass {
                    class_tag: "erofs-deterministic.v1".into(),
                },
            ),
            DirectoryOrderDisposition::RestrictedToMaterializerClass {
                required_class_tag: "erofs-deterministic.v1".into(),
                recorded_raw_order: vec![(
                    "/__rabs/workspace/c_sources".into(),
                    vec![b"z.c".to_vec(), b"a.c".to_vec()],
                )],
            }
        );

        // Volatile metadata observation (e.g., st_ino / st_mtime) -> ClassifiedVolatile even under CanonicalSortedOverlay.
        let ino_consumer = ObservedDirectoryReaddir {
            directory_path: "/__rabs/workspace/src".into(),
            raw_readdir_order: vec![b"a.rs".to_vec(), b"z.rs".to_vec()],
            action_consumed_unsorted_order: false,
            observed_volatile_metadata_fields: vec!["st_ino".into()],
        };
        assert!(matches!(
            classify_directory_order_and_metadata(
                &[ino_consumer],
                &MaterializerReaddirClass::CanonicalSortedOverlay,
            ),
            DirectoryOrderDisposition::ClassifiedVolatile {
                effect_class: rabs_protocol::volatility::EffectClass::HostIdentitySensitive,
                ..
            }
        ));
    }
}
