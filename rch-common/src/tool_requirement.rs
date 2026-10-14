//! Exact Node/Bun admission requirements carried on the existing verified-tool
//! wire. Named operator probes keep their original meaning. An `@` is not legal
//! in an operator probe name, so older daemons refuse these requirements rather
//! than silently admitting an unconstrained worker.
//!
//! These are eligibility checks against reported capabilities, not runtime
//! installation, version-manager overrides, or an execution-time attestation.
//! In particular, a worker's default rustc is not proof of the compiler selected
//! by a job's rustup configuration; Rust constraints are deliberately rejected.

const MAX_VERSION_BYTES: usize = 128;

/// Validate one `--require-tool` value without changing its wire identity.
///
/// Ordinary names retain the existing ASCII letters/digits/`-_.+` grammar.
/// Exact constraints use `node@MAJOR.MINOR.PATCH` or `bun@MAJOR.MINOR.PATCH`,
/// optionally with a complete prerelease/build suffix. Partial versions,
/// ranges, aliases, and implicit version-manager selection are not supported.
///
/// # Errors
/// Returns an explanation for an invalid name, unsupported runtime, or version.
pub fn validate(value: &str) -> Result<(), String> {
    if value.contains('@') {
        parse_exact(value).map(|_| ()).map_err(str::to_owned)
    } else if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
    {
        Ok(())
    } else {
        Err("require a declared tool name using letters, digits, - _ . +, or node@VERSION/bun@VERSION".to_owned())
    }
}

/// Check a versioned requirement against the actual runtime capability fields.
///
/// `None` means this is an ordinary named-tool requirement: the caller must run
/// its existing named-probe gate. `Some(Ok(()))` is an exact match; every other
/// `Some` is a refusal. A forged named-tool fact can never satisfy an exact
/// runtime constraint. Callers must not fall back to named facts on an error.
///
/// Only Node's conventional leading `v` and surrounding probe whitespace are
/// normalized. Prerelease and build suffixes are compared byte for byte, even
/// though build metadata does not affect semantic-version precedence.
#[must_use]
pub fn check_exact_runtime(
    requirement: &str,
    node_version: Option<&str>,
    bun_version: Option<&str>,
) -> Option<Result<(), String>> {
    if !requirement.contains('@') {
        return None;
    }
    Some((|| {
        let (runtime, expected) = parse_exact(requirement)
            .map_err(|reason| format!("capability_invalid:runtime_requirement:{reason}"))?;
        let observed = match runtime {
            "node" => node_version.map(|value| {
                let value = value.trim();
                value.strip_prefix('v').unwrap_or(value)
            }),
            "bun" => bun_version.map(str::trim),
            _ => unreachable!("parse_exact accepts only Node and Bun"),
        };
        let observed = match observed {
            Some(value) if exact_version(value) => value,
            Some(_) => "<invalid>",
            None => "<unknown>",
        };
        if observed == expected {
            Ok(())
        } else {
            // Both versions are validated/bounded before display; malformed
            // probe output cannot inject control characters into diagnostics.
            Err(format!(
                "capability_missing:runtime_version:{runtime}:required={expected}:observed={observed}"
            ))
        }
    })())
}

fn parse_exact(value: &str) -> Result<(&str, &str), &'static str> {
    let (runtime, version) = value
        .split_once('@')
        .ok_or("exact runtime requirement must contain @")?;
    if !matches!(runtime, "node" | "bun") {
        return Err("supported exact runtime requirements are node@VERSION and bun@VERSION");
    }
    if !exact_version(version) {
        return Err(
            "VERSION must be a full MAJOR.MINOR.PATCH with optional prerelease/build suffix, not a range or alias",
        );
    }
    Ok((runtime, version))
}

/// A bounded lexical check, not a range resolver or a precedence comparator.
/// Keeping numeric components as strings avoids integer-overflow ambiguities.
fn exact_version(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_VERSION_BYTES || !value.is_ascii() {
        return false;
    }
    let (version, build) = match value.split_once('+') {
        Some((version, build)) => (version, Some(build)),
        None => (value, None),
    };
    if build.is_some_and(|build| !identifiers(build, false)) {
        return false;
    }
    let (core, prerelease) = match version.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (version, None),
    };
    if prerelease.is_some_and(|prerelease| !identifiers(prerelease, true)) {
        return false;
    }
    let mut components = core.split('.');
    (0..3).all(|_| components.next().is_some_and(numeric_component)) && components.next().is_none()
}

fn numeric_component(value: &str) -> bool {
    !value.is_empty()
        && (value.len() == 1 || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    value.split('.').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && (!reject_numeric_leading_zero
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || numeric_component(part))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_tools_keep_their_original_grammar_and_gate() {
        for name in ["clang", "g++", "clang-20", "my_tool.1", "node", "bun"] {
            validate(name).unwrap();
            assert_eq!(
                check_exact_runtime(name, Some("v26.7.0"), Some("1.3.0")),
                None
            );
        }
        for name in ["", "clang -v", "tool/path", "x=y", "x\n", "naïve"] {
            assert!(validate(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn exact_node_and_bun_versions_match_only_their_own_capabilities() {
        for node in ["v26.7.0", "26.7.0", "v26.7.0\n", " v26.7.0\r\n"] {
            assert_eq!(
                check_exact_runtime("node@26.7.0", Some(node), None),
                Some(Ok(()))
            );
        }
        assert_eq!(
            check_exact_runtime("bun@1.3.0", None, Some("1.3.0\n")),
            Some(Ok(()))
        );
        assert!(
            check_exact_runtime("node@26.7.0", None, Some("26.7.0"))
                .unwrap()
                .is_err()
        );
        assert!(
            check_exact_runtime("bun@1.3.0", Some("v1.3.0"), None)
                .unwrap()
                .is_err()
        );
        assert!(
            check_exact_runtime("bun@1.3.0", None, Some("v1.3.0"))
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn full_versions_are_not_prefixes_or_ranges() {
        for version in [
            "26",
            "26.7",
            "26.7.0.1",
            "26.7.00",
            "026.7.0",
            "26.07.0",
            "v26.7.0",
            "^26.7.0",
            "~26.7.0",
            ">=26.7.0",
            "26.*",
            "*",
            "latest",
            "lts",
            " 26.7.0",
            "26.7.0 ",
            "26.7.0\n",
            "26.7.0 || 22.0.0",
            "26.7.0@other",
            "26.7.0-",
            "26.7.0+",
            "26.7.0-rc..1",
            "26.7.0-01",
            "26.7.0+one+two",
            "26.7.0+one..two",
            "２６.7.0",
        ] {
            let requirement = format!("node@{version}");
            assert!(validate(&requirement).is_err(), "{requirement:?}");
            assert!(
                check_exact_runtime(&requirement, Some(version), None)
                    .unwrap()
                    .is_err()
            );
        }
        for observed in [
            "v26.7.1",
            "v26.7.00",
            "v26.7.01",
            "v26.7.0.1",
            "v26.7.0-rc.1",
        ] {
            assert!(
                check_exact_runtime("node@26.7.0", Some(observed), None)
                    .unwrap()
                    .is_err()
            );
        }
    }

    #[test]
    fn prerelease_and_build_metadata_are_part_of_exact_identity() {
        let versions = [
            "26.7.0",
            "26.7.0-rc.1",
            "26.7.0-rc.2",
            "26.7.0+one",
            "26.7.0+two",
            "26.7.0-rc.1+0001",
        ];
        for expected in versions {
            let requirement = format!("node@{expected}");
            validate(&requirement).unwrap();
            for observed in versions {
                let actual = format!("v{observed}");
                assert_eq!(
                    check_exact_runtime(&requirement, Some(&actual), None)
                        .unwrap()
                        .is_ok(),
                    expected == observed
                );
            }
        }
    }

    #[test]
    fn unsupported_runtimes_never_become_named_tool_fallbacks() {
        for requirement in [
            "rust@1.90.0",
            "npm@11.0.0",
            "Node@26.7.0",
            "@26.7.0",
            "clang@20.0.0",
        ] {
            assert!(validate(requirement).is_err());
            assert!(
                check_exact_runtime(requirement, Some("v26.7.0"), Some("1.90.0"))
                    .unwrap()
                    .is_err()
            );
        }
    }

    #[test]
    fn missing_malformed_and_multiline_observations_are_not_evidence() {
        let unknown = check_exact_runtime("node@26.7.0", None, None)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            unknown,
            "capability_missing:runtime_version:node:required=26.7.0:observed=<unknown>"
        );
        for observed in [
            "",
            "node v26.7.0",
            "vv26.7.0",
            "v26.7.0\nother",
            "v26.7.0\0",
            "v26.7.0\x1b[0m",
        ] {
            let detail = check_exact_runtime("node@26.7.0", Some(observed), None)
                .unwrap()
                .unwrap_err();
            assert!(detail.ends_with("observed=<invalid>"), "{detail}");
            assert!(!detail.chars().any(char::is_control));
        }
    }

    #[test]
    fn version_bounds_do_not_overflow_or_truncate_into_matches() {
        let bounded = format!("1.2.3+{}", "a".repeat(MAX_VERSION_BYTES - 6));
        assert_eq!(bounded.len(), MAX_VERSION_BYTES);
        assert!(exact_version(&bounded));
        assert!(!exact_version(&format!("{bounded}a")));
        assert!(exact_version("184467440737095516160.2.3"));
        assert!(!exact_version("1.2.3-000"));
        assert!(exact_version("1.2.3+000"));
    }

    #[test]
    fn conflicting_exact_requirements_cannot_both_match() {
        for observed in ["v22.0.0", "v26.7.0", "v26.7.1"] {
            assert!(!["node@26.7.0", "node@26.7.1"].iter().all(|required| {
                check_exact_runtime(required, Some(observed), None)
                    .unwrap()
                    .is_ok()
            }));
        }
    }
}
