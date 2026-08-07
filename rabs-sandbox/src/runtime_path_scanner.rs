//! Runtime-visible canonical-path portability scanner (bead D027;
//! risk R84; the D012 scanner's canonical-path blind spot).
//!
//! D012 hunts HIDDEN paths; this scanner hunts CANONICAL ones —
//! because an embedded `/__rabs/...` string is not automatically safe.
//! A canonical path in loadable bytes is SEMANTIC when the program
//! later OPENS it at runtime (`include_path!`-style resource lookup,
//! `env!("CARGO_MANIFEST_DIR")` + `File::open`, an `OUT_DIR` asset
//! read): on the user's machine, `/__rabs/workspace` does not exist —
//! the shared artifact would run differently than a local build.
//! Classification:
//!
//! - `PackagedResource` — the project declared the resource packaged
//!   (bundled into the artifact/bundle): portable, no path opened;
//! - `GuaranteedRuntimeMount` — the deployment guarantees the
//!   canonical mount exists at runtime: portable by declaration;
//! - `RuntimePathSensitive` — neither declaration covers it: route to
//!   the local-only lane (the artifact must be built with the user's
//!   real paths).

use crate::layout::VISIBLE_ROOTS;

/// Project declarations covering embedded canonical paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortabilityDeclarations {
    /// Canonical path prefixes whose resources ship inside the
    /// artifact bundle.
    pub packaged_resources: Vec<String>,
    /// Canonical path prefixes the deployment guarantees mounted at
    /// runtime.
    pub guaranteed_runtime_mounts: Vec<String>,
}

/// Classification of one embedded canonical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimePathClass {
    /// Resource packaged with the artifact: portable.
    PackagedResource(String),
    /// Deployment guarantees the mount: portable by declaration.
    GuaranteedRuntimeMount(String),
    /// Neither: the action is runtime-path-sensitive — local-only.
    RuntimePathSensitive(String),
}

/// One finding from a loadable surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePathFinding {
    /// The embedded canonical path.
    pub path: String,
    /// Its classification.
    pub class: RuntimePathClass,
}

/// Extract embedded canonical-path strings from loadable bytes (any
/// `/__rabs/...` or `/run/rabs-secrets/...` run of path characters).
fn embedded_canonical_paths(bytes: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    for root in VISIBLE_ROOTS {
        let root_bytes = root.as_bytes();
        let mut search_from = 0;
        while let Some(pos) = bytes[search_from..]
            .windows(root_bytes.len())
            .position(|w| w == root_bytes)
        {
            let start = search_from + pos;
            let mut end = start + root_bytes.len();
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric()
                    || matches!(bytes[end], b'/' | b'.' | b'-' | b'_'))
            {
                end += 1;
            }
            let path = String::from_utf8_lossy(&bytes[start..end]).into_owned();
            if !found.contains(&path) {
                found.push(path);
            }
            search_from = end;
        }
    }
    found
}

/// Scan loadable bytes and classify every embedded canonical path.
#[must_use]
pub fn scan_runtime_paths(
    loadable_bytes: &[u8],
    declarations: &PortabilityDeclarations,
) -> Vec<RuntimePathFinding> {
    embedded_canonical_paths(loadable_bytes)
        .into_iter()
        .map(|path| {
            let class = if declarations
                .packaged_resources
                .iter()
                .any(|p| path.starts_with(p.as_str()))
            {
                RuntimePathClass::PackagedResource(path.clone())
            } else if declarations
                .guaranteed_runtime_mounts
                .iter()
                .any(|p| path.starts_with(p.as_str()))
            {
                RuntimePathClass::GuaranteedRuntimeMount(path.clone())
            } else {
                RuntimePathClass::RuntimePathSensitive(path.clone())
            };
            RuntimePathFinding { path, class }
        })
        .collect()
}

/// Whether the findings force the local-only lane.
#[must_use]
pub fn forces_local_only(findings: &[RuntimePathFinding]) -> bool {
    findings
        .iter()
        .any(|f| matches!(f.class, RuntimePathClass::RuntimePathSensitive(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_binary_opening_a_canonical_path_is_detected_and_classified() {
        // THE acceptance fixture: a "binary" embedding a canonical
        // manifest-dir path it will open at runtime.
        let binary =
            b"\x7fELF...const DATA: &str = \"/__rabs/workspace/assets/schema.json\"...open()...";
        let findings = scan_runtime_paths(binary, &PortabilityDeclarations::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].class,
            RuntimePathClass::RuntimePathSensitive("/__rabs/workspace/assets/schema.json".into()),
            "undeclared runtime canonical path is SENSITIVE"
        );
        assert!(forces_local_only(&findings), "routes to local-only");
    }

    #[test]
    fn declarations_make_embedded_canonical_paths_portable() {
        let binary =
            b"a=\"/__rabs/workspace/assets/schema.json\" b=\"/__rabs/toolchain/lib/librt.so\"";
        let declarations = PortabilityDeclarations {
            packaged_resources: vec!["/__rabs/workspace/assets".into()],
            guaranteed_runtime_mounts: vec!["/__rabs/toolchain".into()],
        };
        let findings = scan_runtime_paths(binary, &declarations);
        assert_eq!(findings.len(), 2);
        assert!(matches!(
            findings[0].class,
            RuntimePathClass::PackagedResource(_)
        ));
        assert!(matches!(
            findings[1].class,
            RuntimePathClass::GuaranteedRuntimeMount(_)
        ));
        assert!(!forces_local_only(&findings), "both declared: portable");
    }

    #[test]
    fn one_sensitive_path_among_declared_ones_still_forces_local_only() {
        let binary = b"\"/__rabs/workspace/assets/a.png\" and \"/__rabs/home/.config/tool.toml\"";
        let declarations = PortabilityDeclarations {
            packaged_resources: vec!["/__rabs/workspace/assets".into()],
            guaranteed_runtime_mounts: vec![],
        };
        let findings = scan_runtime_paths(binary, &declarations);
        assert!(forces_local_only(&findings));
    }

    #[test]
    fn clean_binaries_and_duplicates_scan_sanely() {
        // No canonical strings: no findings.
        assert!(
            scan_runtime_paths(
                b"ordinary bytes /usr/lib",
                &PortabilityDeclarations::default()
            )
            .is_empty()
        );
        // The same path embedded twice reports once.
        let twice = b"\"/__rabs/tmp/x\" ... \"/__rabs/tmp/x\"";
        let findings = scan_runtime_paths(twice, &PortabilityDeclarations::default());
        assert_eq!(findings.len(), 1);
    }
}
