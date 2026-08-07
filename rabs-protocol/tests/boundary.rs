//! Stable-boundary tests: no Asupersync types in public CLI/wire/
//! persistence surfaces (bead A008; invariant I14).
//!
//! Three layers of enforcement, strongest first:
//!
//! 1. **Structural**: `rabs-protocol` (the sole owner of wire/durable/CLI
//!    schemas) has ZERO dependencies — it cannot even name an Asupersync
//!    type. Re-asserted here as the boundary's foundation (with A002/A012).
//! 2. **Public-surface scan**: the daemon crates (`rabsd`, `rabs-wkr`) own
//!    the CLI/protocol endpoints; their sources must never declare a `pub`
//!    item mentioning `asupersync::` nor re-export the crate. The adapter
//!    (`rabs-asupersync`) may use Asupersync types internally — that is
//!    its job — but must not `pub use` (re-export) them either, so no
//!    downstream crate can reach Asupersync types THROUGH it.
//! 3. **Honest boundary**: this is a source-text heuristic. Exhaustive
//!    signature-level verification (cargo-public-api / schema-dump against
//!    an allowlist) joins the rabs CI job when concrete serializers exist;
//!    until then this scan + the dependency gates bound the exposure.

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Lines that begin a public item and mention asupersync are boundary
/// violations. Comments and private items are exempt.
fn public_asupersync_violations(src: &str, path: &Path) -> Vec<String> {
    let mut hits = Vec::new();
    for (n, raw) in src.lines().enumerate() {
        let line = raw.trim_start();
        if line.starts_with("//") || line.starts_with("//!") || line.starts_with('#') {
            continue;
        }
        let is_pub_item = line.starts_with("pub ") || line.starts_with("pub(");
        if is_pub_item && line.contains("asupersync") {
            hits.push(format!("{}:{}: {}", path.display(), n + 1, raw.trim()));
        }
    }
    hits
}

#[test]
fn protocol_crate_has_zero_dependencies() {
    let manifest = fs::read_to_string(workspace_root().join("rabs-protocol/Cargo.toml"))
        .expect("read rabs-protocol manifest");
    let mut in_deps = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_deps = line == "[dependencies]";
            continue;
        }
        if in_deps && !line.is_empty() && !line.starts_with('#') {
            panic!(
                "rabs-protocol declared a dependency (`{line}`); the schema \
                 crate must stay dependency-free so Asupersync/Tokio types \
                 are unnameable in wire/durable/CLI schemas (I14)"
            );
        }
    }
}

#[test]
fn daemon_and_adapter_surfaces_never_expose_asupersync() {
    // rabsd + rabs-wkr: no pub item may mention asupersync at all.
    // rabs-asupersync: uses it internally, but may not re-export it
    // (`pub use asupersync…`) nor alias it publicly.
    let mut violations = Vec::new();
    for krate in ["rabsd", "rabs-wkr"] {
        let mut files = Vec::new();
        rust_sources(&workspace_root().join(krate).join("src"), &mut files);
        assert!(!files.is_empty(), "no sources found for {krate}");
        for f in files {
            let src = fs::read_to_string(&f).expect("read source");
            violations.extend(public_asupersync_violations(&src, &f));
        }
    }
    let mut adapter_files = Vec::new();
    rust_sources(
        &workspace_root().join("rabs-asupersync").join("src"),
        &mut adapter_files,
    );
    for f in adapter_files {
        let src = fs::read_to_string(&f).expect("read source");
        for (n, raw) in src.lines().enumerate() {
            let line = raw.trim_start();
            if line.starts_with("pub use asupersync") || line.starts_with("pub use ::asupersync") {
                violations.push(format!(
                    "{}:{}: adapter re-exports asupersync: {}",
                    f.display(),
                    n + 1,
                    raw.trim()
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Asupersync types reached a public surface (I14). Convert through \
         rabs-protocol owned types instead:\n{}",
        violations.join("\n")
    );
}
