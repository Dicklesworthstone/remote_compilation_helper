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
}
