//! Worker capability fact schema — exact host/user/path inventory.
//!
//! [`WorkerFacts`] is the authoritative, exhaustive description of what a worker
//! actually is and can do: its OS/arch/libc, the remote user and its home/temp/
//! build roots, the exact `rch-wkr` path + version/protocol, the Rust
//! toolchains/targets and cargo path, the JS runtimes, the disk roots, and the
//! artifact platforms it can execute. Unlike the lightweight routing hints in
//! [`crate::types::WorkerCapabilities`], facts are *exact* and path-scoped, so
//! capability refresh, selection, fleet update, admission, status, and incident
//! events can all reason from one schema instead of re-probing ad hoc.
//!
//! The schema is versioned via [`SchemaComponent::WorkerFacts`] and exports a
//! JSON Schema through [`worker_facts_schema`].

use schemars::schema::RootSchema;
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};

use crate::schema_versions::{SchemaComponent, current_version};

/// Host-level facts (OS, arch, libc, target triple, runnable platforms).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HostFacts {
    /// OS family: `linux`, `macos`, `windows`, …
    pub os: String,
    /// CPU arch: `x86_64`, `aarch64`, …
    pub arch: String,
    /// libc flavor where it matters: `gnu`, `musl` (`None` on non-linux).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libc: Option<String>,
    /// Login shell, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// The worker's own Rust target triple (e.g. `x86_64-unknown-linux-gnu`).
    pub target_triple: String,
    /// Target triples whose artifacts this worker can *execute* (its own triple
    /// plus any it is binary-compatible with). Drives fleet-update artifact
    /// selection and wrong-arch refusal.
    #[serde(default)]
    pub artifact_platforms: Vec<String>,
}

/// Remote-user and filesystem-root facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UserFacts {
    /// The SSH login user the facts were collected as.
    pub remote_user: String,
    /// That user's home directory.
    pub home: String,
    /// Resolved temp root (`$TMPDIR` → `/data/tmp` → `/tmp`).
    pub temp_root: String,
    /// Build roots this user offloads into (e.g. pooled target dirs).
    #[serde(default)]
    pub build_roots: Vec<String>,
}

/// Facts about the deployed `rch-wkr` binary at its exact path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkerBinaryFacts {
    /// Exact path to the `rch-wkr` binary that answered.
    pub rch_wkr_path: String,
    /// `rch-wkr --version` string.
    pub version: String,
    /// Wire protocol version the worker speaks.
    pub protocol_version: u32,
}

/// Rust toolchain facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RustFacts {
    /// Exact `cargo` path, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_path: Option<String>,
    /// `rustc --version`, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rustc_version: Option<String>,
    /// Installed toolchains (`rustup toolchain list`), e.g. `stable`,
    /// `nightly-2026-05-22`.
    #[serde(default)]
    pub toolchains: Vec<String>,
    /// Installed rustup targets, e.g. `wasm32-unknown-unknown`.
    #[serde(default)]
    pub targets: Vec<String>,
}

/// JS-runtime facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RuntimeFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bun_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_version: Option<String>,
}

/// One filesystem root's capacity (exact, path-scoped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiskRootFacts {
    pub path: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub available_inodes: u64,
}

/// All exact disk roots a worker reports (temp root, build roots, cargo home).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct DiskFacts {
    #[serde(default)]
    pub roots: Vec<DiskRootFacts>,
}

/// The exhaustive worker capability fact record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkerFacts {
    /// Schema version (`SchemaComponent::WorkerFacts`).
    pub schema_version: String,
    /// Worker id these facts describe.
    pub worker_id: String,
    /// Collection time as Unix epoch milliseconds. Caller-supplied so the
    /// schema is deterministic in tests / golden artifacts.
    pub collected_at_unix_ms: u64,
    pub host: HostFacts,
    pub user: UserFacts,
    pub worker: WorkerBinaryFacts,
    #[serde(default)]
    pub rust: RustFacts,
    #[serde(default)]
    pub runtimes: RuntimeFacts,
    #[serde(default)]
    pub disk: DiskFacts,
}

impl WorkerFacts {
    /// Construct facts with the current schema version stamped in.
    #[must_use]
    pub fn new(
        worker_id: impl Into<String>,
        collected_at_unix_ms: u64,
        host: HostFacts,
        user: UserFacts,
        worker: WorkerBinaryFacts,
    ) -> Self {
        Self {
            schema_version: worker_facts_schema_version().to_string(),
            worker_id: worker_id.into(),
            collected_at_unix_ms,
            host,
            user,
            worker,
            rust: RustFacts::default(),
            runtimes: RuntimeFacts::default(),
            disk: DiskFacts::default(),
        }
    }

    /// Whether this worker can *execute* artifacts for `triple` (its own triple
    /// or a declared compatible platform). Used by fleet update / admission /
    /// wrong-arch refusal.
    #[must_use]
    pub fn supports_target(&self, triple: &str) -> bool {
        self.host.target_triple == triple
            || self.host.artifact_platforms.iter().any(|p| p == triple)
    }

    /// Whether a named rustup toolchain is installed.
    ///
    /// Matches the exact channel/pinned name OR a `-`-suffixed host-triple form
    /// (so `nightly` matches `nightly-2026-05-22` and `nightly-x86_64-...`). The
    /// `-` boundary is required so `nightly` does NOT match a hypothetical
    /// `nightlyfoo`, and `nightly-2025-11` does not match `nightly-2025-110`
    /// (bd-review-toolchain-prefix).
    #[must_use]
    pub fn has_toolchain(&self, name: &str) -> bool {
        self.rust
            .toolchains
            .iter()
            .any(|t| t == name || t.starts_with(&format!("{name}-")))
    }

    /// Whether a rustup target is installed (e.g. `wasm32-unknown-unknown`).
    #[must_use]
    pub fn has_target(&self, target: &str) -> bool {
        self.rust.targets.iter().any(|t| t == target)
    }
}

/// The current worker-facts schema version string.
#[must_use]
pub fn worker_facts_schema_version() -> &'static str {
    current_version(SchemaComponent::WorkerFacts)
}

/// Export the JSON Schema for [`WorkerFacts`] (for `--schema` surfaces and
/// contract drift tests).
#[must_use]
pub fn worker_facts_schema() -> RootSchema {
    schema_for!(WorkerFacts)
}

/// Derive a Rust target triple from coarse host facts. Helper for facts
/// collectors and the fleet-update artifact resolver.
#[must_use]
pub fn derive_target_triple(os: &str, arch: &str, libc: Option<&str>) -> String {
    match os {
        "linux" => {
            let env = libc.unwrap_or("gnu");
            format!("{arch}-unknown-linux-{env}")
        }
        "macos" => format!("{arch}-apple-darwin"),
        "windows" => format!("{arch}-pc-windows-msvc"),
        other => format!("{arch}-unknown-{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WorkerFacts {
        WorkerFacts::new(
            "css",
            1_700_000_000_000,
            HostFacts {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                libc: Some("gnu".to_string()),
                shell: Some("/bin/bash".to_string()),
                target_triple: "x86_64-unknown-linux-gnu".to_string(),
                artifact_platforms: vec!["x86_64-unknown-linux-gnu".to_string()],
            },
            UserFacts {
                remote_user: "rch".to_string(),
                home: "/home/rch".to_string(),
                temp_root: "/data/tmp".to_string(),
                build_roots: vec!["/data/tmp/rch-targets".to_string()],
            },
            WorkerBinaryFacts {
                rch_wkr_path: "/home/rch/.local/bin/rch-wkr".to_string(),
                version: "1.0.41".to_string(),
                protocol_version: 3,
            },
        )
    }

    #[test]
    fn new_stamps_current_schema_version() {
        assert_eq!(sample().schema_version, "1.0.0");
        assert_eq!(worker_facts_schema_version(), "1.0.0");
    }

    #[test]
    fn serde_roundtrips() {
        let f = sample();
        let json = serde_json::to_string(&f).unwrap();
        let back: WorkerFacts = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn top_level_field_names_are_stable() {
        let v = serde_json::to_value(sample()).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "collected_at_unix_ms",
                "disk",
                "host",
                "runtimes",
                "rust",
                "schema_version",
                "user",
                "worker",
                "worker_id",
            ]
        );
    }

    #[test]
    fn host_facts_omit_optional_fields_when_absent() {
        let v = serde_json::to_value(HostFacts {
            os: "linux".to_string(),
            arch: "aarch64".to_string(),
            libc: None,
            shell: None,
            target_triple: "aarch64-unknown-linux-musl".to_string(),
            artifact_platforms: vec![],
        })
        .unwrap();
        assert!(v.get("libc").is_none());
        assert!(v.get("shell").is_none());
        // Required fields are always present.
        assert_eq!(v["os"], "linux");
        assert_eq!(v["target_triple"], "aarch64-unknown-linux-musl");
    }

    #[test]
    fn supports_target_matches_own_triple_and_platforms() {
        let mut f = sample();
        assert!(f.supports_target("x86_64-unknown-linux-gnu"));
        assert!(!f.supports_target("aarch64-apple-darwin"));
        f.host
            .artifact_platforms
            .push("x86_64-unknown-linux-musl".to_string());
        assert!(f.supports_target("x86_64-unknown-linux-musl"));
    }

    #[test]
    fn has_toolchain_prefix_and_target_exact() {
        let mut f = sample();
        f.rust.toolchains = vec!["stable".to_string(), "nightly-2026-05-22".to_string()];
        f.rust.targets = vec!["wasm32-unknown-unknown".to_string()];
        assert!(f.has_toolchain("stable"));
        assert!(f.has_toolchain("nightly")); // prefix
        assert!(!f.has_toolchain("beta"));
        assert!(f.has_target("wasm32-unknown-unknown"));
        assert!(!f.has_target("wasm32-wasi"));
    }

    #[test]
    fn derive_target_triple_covers_platforms() {
        assert_eq!(
            derive_target_triple("linux", "x86_64", Some("gnu")),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            derive_target_triple("linux", "aarch64", Some("musl")),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            derive_target_triple("linux", "x86_64", None),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            derive_target_triple("macos", "aarch64", None),
            "aarch64-apple-darwin"
        );
    }

    #[test]
    fn json_schema_is_generatable_and_describes_the_record() {
        // "Tests must validate JSON schema" — the schema must generate and
        // mention WorkerFacts' fields. Assert on the serialized schema text so
        // the check is robust to schemars' inline-vs-definitions layout.
        let schema = worker_facts_schema();
        let text = serde_json::to_string(&schema).expect("schema serializes");
        assert!(text.contains("WorkerFacts"));
        for field in [
            "schema_version",
            "worker_id",
            "collected_at_unix_ms",
            "target_triple",
            "artifact_platforms",
            "rch_wkr_path",
            "protocol_version",
        ] {
            assert!(text.contains(field), "schema omits field {field}");
        }
    }
}
