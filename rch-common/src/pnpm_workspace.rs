//! Bounded declaration decoding for pnpm-workspace.yaml.
//!
//! This reads configuration only; it never runs a package manager or expands
//! environment variables. The worker owns path validation and filesystem
//! discovery, and hashes the entire original document (including catalogs).

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

pub const FILE_NAME: &str = "pnpm-workspace.yaml";
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_PATTERNS: usize = 128;
const MAX_PATTERN_BYTES: usize = 4096;

/// Decode package patterns without allocating arbitrary configuration trees.
///
/// Missing, null, empty, or exclusion-only packages conservatively includes
/// `**`: older pnpm releases discover subdirectories by default, while newer
/// releases include only the root. A superset can cause extra cache misses but
/// cannot certify a root-only stamp for an older pnpm workspace.
///
/// # Errors
/// Rejects malformed/multiple YAML documents, duplicate package declarations,
/// non-string patterns, size/count limits and YAML merge keys. Merge keys must
/// never hide a package list behind an ignored configuration field.
pub fn package_patterns(bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut patterns = declared_package_patterns(bytes)?.unwrap_or_default();
    if !patterns.iter().any(|pattern| !pattern.starts_with('!')) {
        patterns.push("**".to_owned());
    }
    Ok(patterns)
}

/// Decode only the explicitly authored package list, without adding members.
///
/// Workspace-root authority must not reuse [`package_patterns`]' conservative
/// cross-version fallback: an omitted or exclusion-only list does not prove
/// that any particular descendant belongs to this workspace.
pub fn declared_package_patterns(bytes: &[u8]) -> Result<Option<Vec<String>>, String> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err("pnpm-workspace.yaml exceeds document byte limit".to_owned());
    }
    let document: Option<Workspace> = serde_yaml_ng::from_slice(bytes)
        .map_err(|error| format!("invalid pnpm-workspace.yaml: {error}"))?;
    Ok(document.and_then(|document| document.patterns))
}

struct Workspace {
    patterns: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for Workspace {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct WorkspaceVisitor;
        impl<'de> Visitor<'de> for WorkspaceVisitor {
            type Value = Workspace;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a pnpm workspace configuration mapping")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut seen_packages = false;
                let mut patterns = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "packages" => {
                            if seen_packages {
                                return Err(de::Error::duplicate_field("packages"));
                            }
                            seen_packages = true;
                            patterns = map
                                .next_value::<Option<Patterns>>()?
                                .map(|patterns| patterns.0);
                        }
                        "<<" => {
                            return Err(de::Error::custom(
                                "workspace YAML merge keys are unsupported; declare packages explicitly",
                            ));
                        }
                        _ => {
                            // Raw bytes still participate in the fingerprint.
                            // Avoid constructing catalogs or other unused trees.
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(Workspace { patterns })
            }
        }
        deserializer.deserialize_map(WorkspaceVisitor)
    }
}

struct Patterns(Vec<String>);

impl<'de> Deserialize<'de> for Patterns {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PatternsVisitor;
        impl<'de> Visitor<'de> for PatternsVisitor {
            type Value = Patterns;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an array of workspace paths")
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Patterns, S::Error> {
                let mut patterns = Vec::new();
                while let Some(pattern) = sequence.next_element::<Pattern>()? {
                    if patterns.len() == MAX_PATTERNS {
                        return Err(de::Error::custom("too many workspace declarations"));
                    }
                    patterns.push(pattern.0);
                }
                Ok(Patterns(patterns))
            }
        }
        deserializer.deserialize_seq(PatternsVisitor)
    }
}

struct Pattern(String);

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PatternVisitor;
        impl Visitor<'_> for PatternVisitor {
            type Value = Pattern;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a nonempty workspace path string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Pattern, E> {
                if value.is_empty() || value.len() > MAX_PATTERN_BYTES {
                    return Err(E::custom("workspace path is empty or exceeds byte limit"));
                }
                if value.chars().any(char::is_control) {
                    return Err(E::custom("workspace path contains control characters"));
                }
                Ok(Pattern(value.to_owned()))
            }
        }
        // deserialize_any avoids YAML's String coercion of booleans/numbers.
        deserializer.deserialize_any(PatternVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_flow_and_alias_patterns_are_identical() {
        for bytes in [
            b"packages:\n - 'packages/*'\n - \"components/**\"\n - '!**/test/**'\n".as_slice(),
            b"packages: ['packages/*', 'components/**', '!**/test/**']\n",
            b"defaults: &paths ['packages/*', 'components/**', '!**/test/**']\npackages: *paths\n",
        ] {
            assert_eq!(
                package_patterns(bytes).unwrap(),
                ["packages/*", "components/**", "!**/test/**"]
            );
        }
    }

    #[test]
    fn unspecified_membership_is_a_cross_version_conservative_superset() {
        for bytes in [
            b"".as_slice(),
            b"# empty\n",
            b"{}",
            b"packages: null",
            b"packages: []",
            b"catalog:\n chalk: ^4.0.0",
        ] {
            assert_eq!(package_patterns(bytes).unwrap(), ["**"]);
        }
        assert_eq!(
            package_patterns(b"packages: ['!fixtures/**']").unwrap(),
            ["!fixtures/**", "**"]
        );
    }

    #[test]
    fn explicit_membership_never_invents_the_conservative_fallback() {
        for bytes in [b"".as_slice(), b"{}", b"packages: null", b"catalog: {}"] {
            assert_eq!(declared_package_patterns(bytes).unwrap(), None);
        }
        assert_eq!(
            declared_package_patterns(b"packages: []").unwrap(),
            Some(Vec::new())
        );
        assert_eq!(
            declared_package_patterns(b"packages: ['!fixtures/**']").unwrap(),
            Some(vec!["!fixtures/**".to_owned()])
        );
        assert_eq!(
            declared_package_patterns(b"packages: ['packages/*', '!packages/old']").unwrap(),
            Some(vec!["packages/*".to_owned(), "!packages/old".to_owned()])
        );
    }

    #[test]
    fn invalid_shapes_duplicates_merges_and_extra_documents_are_rejected() {
        for bytes in [
            b"packages: false".as_slice(),
            b"packages: packages/*",
            b"packages: [42]",
            b"packages: [true]",
            b"packages: [null]",
            b"packages: [{path: packages/*}]",
            b"packages: ['']",
            b"packages: []\npackages: ['outside/*']",
            b"defaults: &d {packages: ['outside/*']}\n<<: *d",
            b"packages: ['packages/*']\n---\npackages: ['outside/*']",
            b"- packages/*",
            b"packages: [*missing]",
            b"packages: ['unterminated]",
        ] {
            assert!(package_patterns(bytes).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn pattern_and_document_limits_do_not_return_partial_lists() {
        let document = |count| format!("packages: [{}]", vec!["'packages/*'"; count].join(","));
        assert_eq!(
            package_patterns(document(MAX_PATTERNS).as_bytes())
                .unwrap()
                .len(),
            MAX_PATTERNS
        );
        assert!(package_patterns(document(MAX_PATTERNS + 1).as_bytes()).is_err());
        assert!(
            package_patterns(
                format!("packages: ['{}']", "a".repeat(MAX_PATTERN_BYTES + 1)).as_bytes()
            )
            .is_err()
        );
        assert!(package_patterns(&vec![b' '; MAX_DOCUMENT_BYTES + 1]).is_err());
    }
}
