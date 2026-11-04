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

use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, Schema};
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
    /// Installed rustup components, qualified by the toolchain that owns them:
    /// `"<toolchain>:<component>"`, e.g.
    /// `"nightly-2026-07-05-x86_64-unknown-linux-gnu:clippy"`.
    ///
    /// Qualified rather than bare because components are installed against a
    /// specific toolchain: a worker holding `clippy` for `stable` still cannot
    /// run `cargo clippy` under a project's pinned nightly (bd-vc61a).
    #[serde(default)]
    pub components: Vec<String>,
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
    /// Nix version (from `nix --version`, gated on a populated `/nix/store`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nix_version: Option<String>,
    /// Go toolchain version (from `go version`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub go_version: Option<String>,
    /// Zig version (from `zig version`). Gates `cargo zigbuild` routing together
    /// with `cargo_zigbuild_version` — both must be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zig_version: Option<String>,
    /// cargo-zigbuild version (from `cargo-zigbuild --version`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_zigbuild_version: Option<String>,
}

/// One filesystem root's capacity (exact, path-scoped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiskRootFacts {
    pub path: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub available_inodes: u64,
    /// Size of the filesystem's inode pool (statvfs `f_files`, the `df -Pi`
    /// `Inodes` column). `Some(0)` means the filesystem reports no fixed pool:
    /// btrfs allocates inodes dynamically and reports zero for every inode
    /// count, and GNU `df` prints `-` (also recorded as zero) when there is no
    /// inode information at all. `None` means the total was not measured, so
    /// the free count is still treated as a fixed pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_inodes: Option<u64>,
}

impl DiskRootFacts {
    /// Whether the filesystem has a fixed inode pool that can run out. Without
    /// one, its zero free-inode count does not mean exhaustion, and free bytes
    /// are the only capacity limit.
    #[must_use]
    pub fn has_inode_pool(&self) -> bool {
        self.total_inodes != Some(0)
    }

    /// Free inodes as a capacity measurement, or `None` when the filesystem has
    /// no fixed inode pool (see [`DiskRootFacts::has_inode_pool`]).
    #[must_use]
    pub fn free_inodes(&self) -> Option<u64> {
        self.has_inode_pool().then_some(self.available_inodes)
    }

    /// Whether this root clears a free-inode floor. A filesystem without a
    /// fixed inode pool always does; one with a pool must have at least
    /// `floor` free inodes, so real exhaustion (an ext4 root with
    /// `f_files > 0` and `f_ffree` below the floor) still fails.
    #[must_use]
    pub fn meets_inode_floor(&self, floor: u64) -> bool {
        self.free_inodes().is_none_or(|free| free >= floor)
    }
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

    /// Whether `component` is installed for `toolchain` (e.g. `clippy` for
    /// `nightly`).
    ///
    /// The toolchain half is matched with the same `-` boundary rule as
    /// [`WorkerFacts::has_toolchain`], so `nightly` matches a pinned
    /// `nightly-2026-07-05-x86_64-unknown-linux-gnu` but never a hypothetical
    /// `nightlyfoo`. The component half must match exactly: `clippy` must not be
    /// satisfied by `clippy-preview`, because the two are not interchangeable at
    /// the `cargo clippy` call site.
    ///
    /// Absence means "not known to be installed", never "known to be absent".
    /// A worker whose component listing could not be read reports nothing here,
    /// so callers must treat `false` as a reason to avoid routing, not as
    /// evidence about the host (bd-vc61a).
    #[must_use]
    pub fn has_component(&self, toolchain: &str, component: &str) -> bool {
        let prefix = format!("{toolchain}-");
        self.rust.components.iter().any(|entry| {
            let Some((owner, name)) = entry.split_once(':') else {
                return false;
            };
            name == component && (owner == toolchain || owner.starts_with(&prefix))
        })
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
pub fn worker_facts_schema() -> Schema {
    SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<WorkerFacts>()
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

    /// A root built from synthetic statvfs values: `f_files` (pool size, if
    /// measured) and `f_ffree` (free inodes).
    fn statvfs_root(f_files: Option<u64>, f_ffree: u64) -> DiskRootFacts {
        DiskRootFacts {
            path: "/data/tmp".to_string(),
            total_bytes: 2_000_000_000_000,
            available_bytes: 1_600_000_000_000,
            available_inodes: f_ffree,
            total_inodes: f_files,
        }
    }

    #[test]
    fn inode_floor_ignores_filesystems_without_an_inode_pool() {
        // btrfs: f_files == f_ffree == 0. Nothing to exhaust, whatever the floor.
        let btrfs = statvfs_root(Some(0), 0);
        assert!(!btrfs.has_inode_pool());
        assert_eq!(btrfs.free_inodes(), None);
        for floor in [0, 1, 10_000, u64::MAX] {
            assert!(btrfs.meets_inode_floor(floor), "floor={floor}");
        }
        // A zero pool with a nonsensical free count is still no pool.
        assert!(statvfs_root(Some(0), 7).meets_inode_floor(10_000));
    }

    #[test]
    fn inode_floor_detects_exhaustion_of_a_fixed_pool() {
        // ext4-style pools: the floor applies to the free count.
        let cases = [
            (6_553_600, 5_000_000, true),
            (6_553_600, 10_000, true),
            (6_553_600, 9_999, false),
            (6_553_600, 12, false),
            (6_553_600, 0, false),
            (1, 0, false),
        ];
        for (f_files, f_ffree, expected) in cases {
            let root = statvfs_root(Some(f_files), f_ffree);
            assert!(root.has_inode_pool());
            assert_eq!(root.free_inodes(), Some(f_ffree));
            assert_eq!(
                root.meets_inode_floor(10_000),
                expected,
                "f_files={f_files}, f_ffree={f_ffree}"
            );
        }
        // A zero floor disables the check even for an exhausted pool.
        assert!(statvfs_root(Some(6_553_600), 0).meets_inode_floor(0));
    }

    #[test]
    fn inode_floor_without_a_measured_total_keeps_the_free_count_binding() {
        // Facts that never measured f_files keep the historical behavior: the
        // free count is trusted, so a reported zero is exhaustion.
        let unmeasured = statvfs_root(None, 0);
        assert!(unmeasured.has_inode_pool());
        assert!(!unmeasured.meets_inode_floor(10_000));
        assert!(statvfs_root(None, 900_000).meets_inode_floor(10_000));
    }

    #[test]
    fn disk_root_total_inodes_is_optional_on_the_wire() {
        let legacy = r#"{"path":"/tmp","total_bytes":1,"available_bytes":1,"available_inodes":5}"#;
        let parsed: DiskRootFacts = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.total_inodes, None);
        let value = serde_json::to_value(&parsed).unwrap();
        assert!(value.get("total_inodes").is_none());

        let btrfs = statvfs_root(Some(0), 0);
        let value = serde_json::to_value(&btrfs).unwrap();
        assert_eq!(value["total_inodes"], 0);
        assert_eq!(
            serde_json::from_value::<DiskRootFacts>(value).unwrap(),
            btrfs
        );
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
    fn has_component_is_toolchain_scoped_and_component_exact() {
        let mut f = sample();
        f.rust.components = vec![
            "stable:clippy".to_string(),
            "nightly-2026-07-05-x86_64-unknown-linux-gnu:rustfmt".to_string(),
            "nightlyfoo:clippy".to_string(),
            "beta:clippy-preview".to_string(),
        ];

        // Exact toolchain, and the `-` boundary form a pinned nightly takes.
        assert!(f.has_component("stable", "clippy"));
        assert!(f.has_component("nightly", "rustfmt"));
        assert!(f.has_component("nightly-2026-07-05-x86_64-unknown-linux-gnu", "rustfmt"));

        // The exact failure this fact exists to catch: clippy installed for
        // SOME toolchain must not answer for a different pinned one. This is the
        // state that let workers report healthy while voiding a lint gate.
        assert!(!f.has_component("nightly", "clippy"));

        // Same `-` boundary discipline as `has_toolchain`: `nightly` must not be
        // satisfied by a toolchain merely starting with those letters.
        assert!(!f.has_component("nightl", "clippy"));

        // Component half is exact: `clippy-preview` is not `clippy` at the
        // `cargo clippy` call site.
        assert!(!f.has_component("beta", "clippy"));

        // Unknown toolchain/component answers false rather than panicking.
        assert!(!f.has_component("stable", "rust-analyzer"));
        assert!(!f.has_component("does-not-exist", "clippy"));
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
