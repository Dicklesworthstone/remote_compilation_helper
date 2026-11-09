//! Known package-manager environment inputs to dependency preparation.
//!
//! Keep raw values (including registry credentials) out of records and logs.
//! This binds configuration and lookup values, not the contents of referenced
//! global config files or replacement executables at unchanged paths. Custom
//! lifecycle scripts may read other variables; this is not a hermetic sandbox.

use anyhow::{Result, ensure};
use std::ffi::{OsStr, OsString};

const MAX_ENVIRONMENT_BYTES: usize = 32 * 1024 * 1024;

fn relevant(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    [b"npm_config_".as_slice(), b"pnpm_", b"yarn_", b"bun_"]
        .iter()
        .any(|prefix| {
            bytes
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        })
        || [
            "NODE_ENV",
            "NODE_OPTIONS",
            "NODE_PATH",
            "CI",
            "PATH",
            "PATHEXT",
            "HOME",
            "USERPROFILE",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "APPDATA",
            "LOCALAPPDATA",
        ]
        .iter()
        .any(|key| bytes.eq_ignore_ascii_case(key.as_bytes()))
}

fn fingerprint(values: impl IntoIterator<Item = (OsString, OsString)>) -> Result<blake3::Hash> {
    let mut values: Vec<_> = values
        .into_iter()
        .filter(|(name, _)| relevant(name))
        .collect();
    // Preserve exact key case and OS value bytes. Stable sorting also retains
    // the original order of any duplicate environment names.
    values.sort_by(|left, right| left.0.as_encoded_bytes().cmp(right.0.as_encoded_bytes()));
    let mut digest = blake3::Hasher::new();
    digest.update(b"rch-dependency-install-environment-v1\0");
    let mut budget = MAX_ENVIRONMENT_BYTES;
    for (name, value) in values {
        for bytes in [name.as_encoded_bytes(), value.as_encoded_bytes()] {
            ensure!(
                bytes.len() <= budget,
                "package-manager environment exceeds byte limit"
            );
            budget -= bytes.len();
            digest.update(&(bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
        }
    }
    Ok(digest.finalize())
}

pub(super) fn capture() -> Result<blake3::Hash> {
    fingerprint(std::env::vars_os())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(values: &[(&str, &str)]) -> blake3::Hash {
        fingerprint(
            values
                .iter()
                .map(|(key, value)| (OsString::from(*key), OsString::from(*value))),
        )
        .unwrap()
    }

    #[test]
    fn configuration_values_presence_and_exact_key_case_affect_identity() {
        for key in [
            "NODE_ENV",
            "NODE_OPTIONS",
            "NODE_PATH",
            "CI",
            "PATH",
            "HOME",
            "XDG_CONFIG_HOME",
            "npm_config_omit",
            "NPM_CONFIG_IGNORE_SCRIPTS",
            "PNPM_CONFIG_PRODUCTION",
            "YARN_ENABLE_SCRIPTS",
            "BUN_INSTALL",
        ] {
            assert_ne!(digest(&[]), digest(&[(key, "")]), "{key}");
            assert_ne!(
                digest(&[(key, "first")]),
                digest(&[(key, "second")]),
                "{key}"
            );
        }
        assert_ne!(
            digest(&[("NODE_ENV", "production")]),
            digest(&[("node_env", "production")])
        );
        assert_ne!(
            digest(&[("npm_config_omit", "dev")]),
            digest(&[("NPM_CONFIG_OMIT", "dev")])
        );
    }

    #[test]
    fn order_and_unrelated_attempt_environment_do_not_force_reinstalls() {
        let expected = digest(&[("NODE_ENV", "development"), ("npm_config_omit", "optional")]);
        assert_eq!(
            expected,
            digest(&[("npm_config_omit", "optional"), ("NODE_ENV", "development")])
        );
        assert_eq!(
            expected,
            digest(&[
                ("RCH_BUILD_ID", "new-attempt"),
                ("TMPDIR", "/another/temporary/root"),
                ("NODE_ENV", "development"),
                ("npm_config_omit", "optional"),
            ])
        );
        // Length framing separates a changed key from a changed value.
        assert_ne!(
            digest(&[("npm_config_a", "bc")]),
            digest(&[("npm_config_ab", "c")])
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_values_remain_distinct() {
        use std::os::unix::ffi::OsStringExt;
        let first = fingerprint([(
            OsString::from("npm_config_cache"),
            OsString::from_vec(vec![0xff]),
        )])
        .unwrap();
        let second = fingerprint([(
            OsString::from("npm_config_cache"),
            OsString::from_vec(vec![0xfe]),
        )])
        .unwrap();
        assert_ne!(first, second);
    }
}
