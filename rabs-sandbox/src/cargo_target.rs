//! Shared compatibility policy for PRIVATE Cargo target state and placement.
//!
//! These families are hints for selecting a worker or a private target seed.
//! They never identify an action result, authorize a cache hit, or replace the
//! exact captured request. Cargo still executes its original command. A worker
//! must independently verify the retained inputs, restore only private copies,
//! and make changed source inputs newer than every retained fingerprint.
//!
//! Sharing this policy prevents coordinator placement from disagreeing with the
//! worker's source-edit and command-selection reuse. Its v3 source encoding is
//! unchanged from the worker implementation, including durable seed identity.

use crate::cargo_artifacts::CargoArtifactMode;
use crate::cargo_home::CargoHomeProjection;
use crate::source_transfer::{SourceFile, SourceManifest};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

/// Which local source/data files Cargo may recheck after a private seed restore.
/// Directory sources are immutable as a whole: Cargo does not track their
/// ordinary source mtimes as it tracks local/path packages.
pub struct SourceEditPolicy<'a> {
    protected: BTreeSet<&'a Path>,
}

impl<'a> SourceEditPolicy<'a> {
    #[must_use]
    pub fn new(manifest: &'a SourceManifest) -> Self {
        Self {
            protected: manifest
                .files()
                .iter()
                .filter_map(|file| {
                    let path = Path::new(&file.path);
                    if path.file_name()?.to_str()? == ".cargo-checksum.json" {
                        path.parent()
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }

    /// This classifies source membership only. Returning true never permits
    /// serving or reuse without the worker's full timestamp/content validation.
    #[must_use]
    pub fn is_editable(&self, file: &SourceFile) -> bool {
        let path = Path::new(&file.path);
        // Resolution, tool/lint configuration and executable inputs remain
        // exact. Git rules affect Cargo's default build-script package scan.
        if file.executable
            || path.file_name().is_some_and(|name| {
                matches!(
                    name.to_str(),
                    Some(
                        "Cargo.toml"
                            | "Cargo.lock"
                            | "rust-toolchain"
                            | "rust-toolchain.toml"
                            | "clippy.toml"
                            | ".clippy.toml"
                            | ".gitignore"
                            | ".gitattributes"
                            | ".gitmodules"
                    )
                )
            })
            || path
                .components()
                .any(|part| part.as_os_str() == ".cargo" || part.as_os_str() == ".git")
        {
            return false;
        }
        !path
            .ancestors()
            .skip(1)
            .any(|parent| self.protected.contains(parent))
    }
}

/// Length-framed private target family, preserving non-editable names, modes
/// and bytes. The coherent manifest remains exact and unchanged. Isolated
/// Cargo-home cache partitions remain byte-for-byte inputs; the legacy visible
/// cache prefix and mismatched transport/workspace bindings cannot normalize.
#[must_use]
pub fn source_edit_identity(
    workspace: &SourceManifest,
    full_source_digest: [u8; 32],
    projection: Option<&CargoHomeProjection>,
) -> Option<[u8; 32]> {
    let mut hash = Sha256::new();
    if let Some(home) = projection {
        let projected_workspace = home.workspace_manifest()?;
        if home.source_digest() != full_source_digest
            || projected_workspace.digest() != workspace.digest()
        {
            return None;
        }
        hash.update(b"rabs.private-cargo-projected-source-edits.v3\0");
        for value in [home.version(), home.prefix()] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update(home.cache_manifest().digest());
    } else {
        if full_source_digest != workspace.digest() {
            return None;
        }
        hash.update(b"rabs.private-cargo-source-edits.v3\0");
    }
    let policy = SourceEditPolicy::new(workspace);
    let immutable = workspace
        .files()
        .iter()
        .filter(|file| !policy.is_editable(file))
        .count();
    hash.update((immutable as u64).to_be_bytes());
    for file in workspace.files() {
        if policy.is_editable(file) {
            continue;
        }
        hash.update((file.path.len() as u64).to_be_bytes());
        hash.update(file.path.as_bytes());
        hash.update([u8::from(file.executable)]);
        hash.update(file.len.to_be_bytes());
        hash.update(file.sha256);
    }
    (immutable < workspace.files().len()).then(|| hash.finalize().into())
}

/// Normalize only the command/selection differences supported by Cargo's
/// ordinary private target reuse. Callers must first validate the complete
/// Cargo artifact contract. Unknown arguments retain exact-key reuse only.
/// Cargo fingerprints feature-selected units and build-script environments;
/// unchanged dependencies can therefore survive feature-selection changes.
/// Clippy keeps every selection, feature and lint control in a separate family.
#[must_use]
pub fn compatible_arguments(
    program: &str,
    args: &[String],
    mode: CargoArtifactMode,
) -> Option<Vec<String>> {
    let command = args.first()?.as_str();
    let clippy = match (program, command, mode) {
        ("/__rabs/toolchain/bin/cargo", "build" | "check" | "test" | "run" | "bench", _) => false,
        ("/__rabs/toolchain/bin/cargo-clippy", "clippy", CargoArtifactMode::Compilation) => true,
        _ => return None,
    };
    let mut normalized = vec![
        if clippy {
            "cargo-clippy"
        } else {
            "cargo-compilation"
        }
        .to_owned(),
    ];
    let mut no_run = false;
    let mut filter = false;
    let mut profile = None;
    let mut at = 1;
    while at < args.len() {
        let argument = &args[at];
        if argument == "--" {
            if clippy {
                // The admitted artifact contract validates a lint-only tail.
                // Unlike runtime arguments, lints change compilation.
                normalized.extend(args[at..].iter().cloned());
                break;
            }
            if !matches!(command, "test" | "run" | "bench") || no_run {
                return None;
            }
            break;
        }
        let (option, inline) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(option, value)| {
                (option, Some(value))
            });
        match option {
            "--no-run" if inline.is_none() && matches!(command, "test" | "bench") && !no_run => {
                no_run = true;
            }
            "--no-fail-fast" if inline.is_none() && matches!(command, "test" | "bench") => {}
            "--bin" | "--example" | "--test" | "--bench" | "--package" | "-p" | "--exclude"
            | "--features" | "-F" => {
                // Cargo rechecks each selected unit. Clippy must keep selection:
                // a --no-deps dependency otherwise might stay fresh when made
                // primary and escape the requested lints. Features also stay
                // exact for Clippy; ordinary Cargo keys them in each unit's
                // own fingerprint, including feature-dependent build scripts.
                if clippy {
                    normalized.push(argument.clone());
                }
                let value = if let Some(value) = inline {
                    value
                } else {
                    at += 1;
                    let value = args.get(at)?;
                    if clippy {
                        normalized.push(value.clone());
                    }
                    value
                };
                if value.is_empty() || value.starts_with('-') {
                    return None;
                }
            }
            "--workspace"
            | "--all"
            | "--lib"
            | "--bins"
            | "--examples"
            | "--tests"
            | "--benches"
            | "--all-targets"
            | "--all-features"
            | "--no-default-features"
                if inline.is_none() =>
            {
                if clippy {
                    normalized.push(argument.clone());
                }
            }
            "--target" | "--color" | "--message-format" | "--manifest-path" | "--target-dir"
            | "--jobs" | "-j" => {
                normalized.push(argument.clone());
                let value = if let Some(value) = inline {
                    value
                } else {
                    at += 1;
                    let value = args.get(at)?;
                    normalized.push(value.clone());
                    value
                };
                if value.is_empty() || value.starts_with('-') {
                    return None;
                }
            }
            "--profile" => {
                let value = match inline {
                    Some(value) => value,
                    None => {
                        at += 1;
                        args.get(at)?.as_str()
                    }
                };
                if profile.is_some() || value.is_empty() || value.starts_with('-') {
                    return None;
                }
                profile = Some(value);
            }
            "--release" | "-r" if inline.is_none() && profile.is_none() && command != "bench" => {
                profile = Some("release");
            }
            "--locked" | "--offline" | "--frozen" | "--verbose" | "-v" | "-vv" | "--quiet"
            | "-q"
                if inline.is_none() =>
            {
                normalized.push(argument.clone());
            }
            "--doc" if inline.is_none() && command == "test" => {
                normalized.push(argument.clone());
            }
            "--no-deps" if inline.is_none() && clippy => {
                normalized.push(argument.clone());
            }
            _ if matches!(command, "test" | "bench") && !argument.starts_with('-') && !filter => {
                filter = true;
            }
            _ => return None,
        }
        at += 1;
    }
    if no_run && filter {
        return None;
    }
    // This is private Cargo state only: Cargo still runs and checks every
    // fingerprint. Keep debug/release/custom output families separate, while
    // equivalent profile spellings can seed builds, runs, tests and benchmarks.
    // Clippy retains its exact profile because lint freshness is distinct.
    let profile = match profile {
        Some("dev" | "test") if !clippy => "debug",
        Some("release" | "bench") if !clippy => "release",
        Some(profile) => profile,
        None if command == "bench" => "release",
        None => "debug",
    };
    normalized.push(format!("private-target-profile={profile}"));
    match mode {
        CargoArtifactMode::Compilation
            if command != "run" && (!matches!(command, "test" | "bench") || no_run) =>
        {
            Some(normalized)
        }
        CargoArtifactMode::TestExecution if command == "test" && !no_run => Some(normalized),
        CargoArtifactMode::RunExecution if command == "run" && !no_run => Some(normalized),
        CargoArtifactMode::BenchExecution if command == "bench" && !no_run => Some(normalized),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cargo_home::{
        CARGO_HOME_SOURCE_VERSION, ISOLATED_CARGO_HOME_SOURCE_VERSION,
        ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
    };

    fn file(path: &str, bytes: &[u8], executable: bool) -> SourceFile {
        SourceFile {
            path: path.to_owned(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable,
        }
    }

    fn workspace() -> SourceManifest {
        SourceManifest::new(vec![
            file(
                "Cargo.toml",
                b"[package]\nname=\"sample\"\nversion=\"0.1.0\"\n",
                false,
            ),
            file(".cargo/config.toml", b"[build]\njobs=2\n", false),
            file("tools/helper", b"#!/bin/sh\nexit 0\n", true),
            file("vendor/dep/.cargo-checksum.json", b"{}", false),
            file("vendor/dep/src/lib.rs", b"pub fn dependency() {}\n", false),
            file("src/lib.rs", b"pub fn answer()->u32{1}\n", false),
            file("assets/λ.txt", b"data\n", false),
        ])
        .unwrap()
    }

    fn cache_files() -> Vec<SourceFile> {
        vec![
            file(
                "registry/cache/index/dep-1.0.crate",
                b"captured archive\n",
                false,
            ),
            file(
                "registry/index/index/config.json",
                b"{\"dl\":\"https://example.invalid\"}\n",
                false,
            ),
        ]
    }

    fn projection(
        workspace: &SourceManifest,
        cache: &[SourceFile],
        version: &str,
        prefix: &str,
    ) -> (SourceManifest, CargoHomeProjection) {
        let mut files = workspace.files().to_vec();
        files.extend(cache.iter().cloned().map(|mut file| {
            file.path = format!("{prefix}/{}", file.path);
            file
        }));
        let transport = SourceManifest::new(files).unwrap();
        let projection = CargoHomeProjection::for_version(version, prefix, &transport).unwrap();
        (transport, projection)
    }

    fn family(manifest: &SourceManifest) -> [u8; 32] {
        source_edit_identity(manifest, manifest.digest(), None).unwrap()
    }

    fn hex(digest: [u8; 32]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn source_family_preserves_existing_v3_persistent_seed_encoding() {
        // Independently encoded from the worker policy at 7ed61b9, before
        // extraction: v3 domains, big-endian length framing, and the five
        // immutable fixture members. These constants are not recalculated
        // from SourceEditPolicy or source_edit_identity in this test.
        let workspace = workspace();
        assert_eq!(
            hex(family(&workspace)),
            "718d95bfe0a65192c19d31e9d0f3e538a235ecb325190066273f88feb6a4afbe"
        );
        let (transport, home) = projection(
            &workspace,
            &cache_files(),
            ISOLATED_CARGO_HOME_SOURCE_VERSION,
            "transport/cache",
        );
        assert_eq!(
            hex(source_edit_identity(&workspace, transport.digest(), Some(&home)).unwrap()),
            "6913fa5936dc226583d7950aab0e89ce4b47303b57b29bc2572af69e7287dec5"
        );
    }

    #[test]
    fn source_and_data_edits_share_family_without_changing_exact_manifests() {
        let original = workspace();
        let original_digest = original.digest();
        let expected = family(&original);
        let mut files = original.files().to_vec();
        for file in &mut files {
            if file.path == "src/lib.rs" {
                *file = self::file("src/lib.rs", b"mod added; pub fn answer()->u32{2}\n", false);
            }
        }
        files.retain(|file| file.path != "assets/λ.txt");
        files.push(file("assets/renamed.txt", b"new data\n", false));
        files.push(file("src/added.rs", b"pub fn new_module() {}\n", false));
        files.push(file("build.rs", b"fn main() {}\n", false));
        let edited = SourceManifest::new(files).unwrap();
        assert_ne!(edited.digest(), original_digest);
        assert_eq!(family(&edited), expected);
        assert_eq!(original.digest(), original_digest);

        for (index, member) in edited.files().iter().enumerate() {
            if !SourceEditPolicy::new(&edited).is_editable(member) {
                continue;
            }
            let mut executable = edited.files().to_vec();
            executable[index].executable = true;
            assert_ne!(family(&SourceManifest::new(executable).unwrap()), expected);
        }
    }

    #[test]
    fn configuration_executables_and_complete_vendor_packages_stay_exact() {
        let original = workspace();
        let expected = family(&original);
        for path in [
            "Cargo.toml",
            ".cargo/config.toml",
            "tools/helper",
            "vendor/dep/.cargo-checksum.json",
            "vendor/dep/src/lib.rs",
        ] {
            let mut changed = original.files().to_vec();
            let member = changed.iter_mut().find(|file| file.path == path).unwrap();
            *member = file(path, b"changed bytes", member.executable);
            assert_ne!(
                family(&SourceManifest::new(changed).unwrap()),
                expected,
                "{path}"
            );
        }
        let mut vendor_added = original.files().to_vec();
        vendor_added.push(file("vendor/dep/data.txt", b"new", false));
        assert_ne!(
            family(&SourceManifest::new(vendor_added).unwrap()),
            expected
        );
        let mut vendor_removed = original.files().to_vec();
        vendor_removed.retain(|file| file.path != "vendor/dep/src/lib.rs");
        assert_ne!(
            family(&SourceManifest::new(vendor_removed).unwrap()),
            expected
        );

        for path in [
            "nested/Cargo.toml",
            "nested/Cargo.lock",
            "rust-toolchain",
            "rust-toolchain.toml",
            "clippy.toml",
            ".clippy.toml",
            ".gitignore",
            ".gitattributes",
            ".gitmodules",
            "nested/.cargo/config.toml",
            "nested/.git/HEAD",
        ] {
            let manifest = SourceManifest::new(vec![
                file(path, b"control", false),
                file("src/lib.rs", b"source", false),
            ])
            .unwrap();
            let policy = SourceEditPolicy::new(&manifest);
            assert!(
                !policy.is_editable(
                    manifest
                        .files()
                        .iter()
                        .find(|file| file.path == path)
                        .unwrap()
                ),
                "{path}"
            );
        }
        // Directory-component boundaries matter: a nearby local path does not
        // become immutable merely because its name starts with a vendor root.
        let policy = SourceEditPolicy::new(&original);
        assert!(policy.is_editable(&file("vendor/dep-local/lib.rs", b"local", false)));
    }

    #[test]
    fn isolated_source_edits_bind_cache_bytes_membership_modes_and_projection() {
        let original = workspace();
        let cache = cache_files();
        let (transport, home) = projection(
            &original,
            &cache,
            ISOLATED_CARGO_HOME_SOURCE_VERSION,
            "cache",
        );
        let expected = source_edit_identity(&original, transport.digest(), Some(&home)).unwrap();
        let mut files = original.files().to_vec();
        let member = files
            .iter_mut()
            .find(|file| file.path == "src/lib.rs")
            .unwrap();
        *member = file("src/lib.rs", b"pub fn answer()->u32{2}\n", false);
        let edited = SourceManifest::new(files).unwrap();
        let (new_transport, new_home) =
            projection(&edited, &cache, ISOLATED_CARGO_HOME_SOURCE_VERSION, "cache");
        assert_eq!(
            source_edit_identity(&edited, new_transport.digest(), Some(&new_home)),
            Some(expected)
        );

        for change in 0..4 {
            let mut changed = cache.clone();
            match change {
                0 => changed[0] = file(&changed[0].path, b"changed archive", false),
                1 => changed[0].executable = true,
                2 => changed.push(file("registry/src/index/dep-1.0/new.rs", b"new", false)),
                3 => {
                    changed.pop();
                }
                _ => unreachable!(),
            }
            let (transport, home) = projection(
                &edited,
                &changed,
                ISOLATED_CARGO_HOME_SOURCE_VERSION,
                "cache",
            );
            assert_ne!(
                source_edit_identity(&edited, transport.digest(), Some(&home)),
                Some(expected)
            );
        }
        let (other_transport, other_home) = projection(
            &edited,
            &cache,
            ISOLATED_CARGO_HOME_SOURCE_VERSION,
            "other/cache",
        );
        assert_ne!(
            source_edit_identity(&edited, other_transport.digest(), Some(&other_home)),
            Some(expected)
        );
        // A registry-only snapshot cannot masquerade as the Git projection:
        // that version requires its complete reconstructed Git database.
        assert!(
            CargoHomeProjection::for_version(
                ISOLATED_GIT_CARGO_HOME_SOURCE_VERSION,
                "cache",
                &new_transport,
            )
            .is_err()
        );
        assert_eq!(
            source_edit_identity(&edited, transport.digest(), Some(&home)),
            None
        );
        assert_eq!(source_edit_identity(&original, [0; 32], Some(&home)), None);
    }

    #[test]
    fn legacy_or_unbound_inputs_do_not_gain_source_edit_compatibility() {
        let original = workspace();
        let (transport, legacy) = projection(
            &original,
            &cache_files(),
            CARGO_HOME_SOURCE_VERSION,
            "cache",
        );
        assert_eq!(
            source_edit_identity(&transport, transport.digest(), Some(&legacy)),
            None
        );
        assert_eq!(source_edit_identity(&original, [0; 32], None), None);
        let immutable_only =
            SourceManifest::new(vec![file("Cargo.toml", b"manifest", false)]).unwrap();
        assert_eq!(
            source_edit_identity(&immutable_only, immutable_only.digest(), None),
            None
        );
    }

    fn invocation(command: &str, tail: &[&str]) -> Vec<String> {
        std::iter::once(command)
            .chain([
                "--offline",
                "--message-format=json",
                "--target-dir=/__rabs/out/cargo",
            ])
            .chain(tail.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn ordinary_selections_and_test_execution_share_only_supported_compile_controls() {
        let cargo = "/__rabs/toolchain/bin/cargo";
        let expected = compatible_arguments(
            cargo,
            &invocation("build", &[]),
            CargoArtifactMode::Compilation,
        )
        .unwrap();
        for (command, tail, mode) in [
            (
                "build",
                &["--workspace", "--all-targets"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "check",
                &["-p", "app", "--lib"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "build",
                &["--bin=app", "--example", "demo"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "build",
                &["--features", "serde,parallel", "-F", "app/extra"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "check",
                &["--no-default-features", "--features=extra"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "test",
                &["--no-run", "--all-features"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "test",
                &["--no-run", "--package=app"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "test",
                &[
                    "case_name",
                    "--no-fail-fast",
                    "--",
                    "--exact",
                    "--test-threads=1",
                ][..],
                CargoArtifactMode::TestExecution,
            ),
            (
                "run",
                &[
                    "--package=app",
                    "--bin=app",
                    "--",
                    "--no-run",
                    "--profile=release",
                ][..],
                CargoArtifactMode::RunExecution,
            ),
            (
                "bench",
                &["--profile=dev", "--bench=measured", "--", "--exact"][..],
                CargoArtifactMode::BenchExecution,
            ),
        ] {
            assert_eq!(
                compatible_arguments(cargo, &invocation(command, tail), mode),
                Some(expected.clone())
            );
        }
        for tail in [
            &["--target=x86_64-unknown-linux-gnu"][..],
            &["--profile=release"][..],
            &["--jobs=2"][..],
            &["--manifest-path=/__rabs/workspace/other/Cargo.toml"][..],
        ] {
            assert_ne!(
                compatible_arguments(
                    cargo,
                    &invocation("build", tail),
                    CargoArtifactMode::Compilation
                ),
                Some(expected.clone())
            );
        }
        for (command, tail, mode) in [
            (
                "build",
                &["--future-option"][..],
                CargoArtifactMode::Compilation,
            ),
            ("build", &["--features"][..], CargoArtifactMode::Compilation),
            ("build", &["-F"][..], CargoArtifactMode::Compilation),
            (
                "build",
                &["--features="][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "build",
                &["--features", "--all-features"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "build",
                &["--all-features=yes"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "build",
                &["--no-default-features=1"][..],
                CargoArtifactMode::Compilation,
            ),
            ("check", &["--no-run"][..], CargoArtifactMode::Compilation),
            (
                "test",
                &["--no-run", "case"][..],
                CargoArtifactMode::Compilation,
            ),
            (
                "test",
                &["--no-run", "--", "--exact"][..],
                CargoArtifactMode::Compilation,
            ),
            ("build", &[][..], CargoArtifactMode::TestExecution),
            ("test", &[][..], CargoArtifactMode::Compilation),
            ("run", &[][..], CargoArtifactMode::Compilation),
            ("run", &["--no-run"][..], CargoArtifactMode::RunExecution),
            ("bench", &[][..], CargoArtifactMode::Compilation),
            (
                "bench",
                &["--no-run"][..],
                CargoArtifactMode::BenchExecution,
            ),
            (
                "bench",
                &["--release"][..],
                CargoArtifactMode::BenchExecution,
            ),
            ("bench", &["-r"][..], CargoArtifactMode::BenchExecution),
            (
                "bench",
                &["--no-run", "--", "--exact"][..],
                CargoArtifactMode::Compilation,
            ),
        ] {
            assert_eq!(
                compatible_arguments(cargo, &invocation(command, tail), mode),
                None
            );
        }
        assert_eq!(
            compatible_arguments(
                "/usr/bin/cargo",
                &invocation("build", &[]),
                CargoArtifactMode::Compilation
            ),
            None
        );
    }

    #[test]
    fn benchmark_default_profile_shares_only_the_release_compilation_family() {
        let cargo = "/__rabs/toolchain/bin/cargo";
        let release = compatible_arguments(
            cargo,
            &invocation("build", &["--release"]),
            CargoArtifactMode::Compilation,
        )
        .unwrap();
        for (command, tail, mode) in [
            ("build", vec!["-r"], CargoArtifactMode::Compilation),
            (
                "build",
                vec!["--profile", "release"],
                CargoArtifactMode::Compilation,
            ),
            (
                "run",
                vec!["--release", "--example=demo", "--", "--profile=dev"],
                CargoArtifactMode::RunExecution,
            ),
            (
                "test",
                vec!["--profile=bench", "filter", "--", "--nocapture"],
                CargoArtifactMode::TestExecution,
            ),
            (
                "bench",
                vec!["--bench=measured", "filter", "--", "--no-run"],
                CargoArtifactMode::BenchExecution,
            ),
            ("bench", vec!["--no-run"], CargoArtifactMode::Compilation),
            (
                "bench",
                vec!["--profile=release"],
                CargoArtifactMode::BenchExecution,
            ),
        ] {
            let args = invocation(command, &tail);
            assert_eq!(
                compatible_arguments(cargo, &args, mode),
                Some(release.clone()),
                "{args:?}"
            );
        }
        for (command, tail, mode) in [
            ("build", vec![], CargoArtifactMode::Compilation),
            (
                "run",
                vec!["--", "--release"],
                CargoArtifactMode::RunExecution,
            ),
            (
                "bench",
                vec!["--profile=dev"],
                CargoArtifactMode::BenchExecution,
            ),
            (
                "bench",
                vec!["--profile=ci"],
                CargoArtifactMode::BenchExecution,
            ),
            (
                "bench",
                vec!["--target=x86_64-unknown-linux-gnu"],
                CargoArtifactMode::BenchExecution,
            ),
        ] {
            let actual = compatible_arguments(cargo, &invocation(command, &tail), mode);
            assert!(actual.is_some());
            assert_ne!(actual, Some(release.clone()));
        }
        for tail in [
            vec!["--profile=release", "--profile=dev"],
            vec!["--release", "--profile=dev"],
            vec!["--profile=dev", "-r"],
            vec!["--profile"],
        ] {
            assert!(
                compatible_arguments(
                    cargo,
                    &invocation("run", &tail),
                    CargoArtifactMode::RunExecution
                )
                .is_none()
            );
        }
    }

    #[test]
    fn clippy_preserves_selections_and_lint_order_in_a_separate_family() {
        let clippy = "/__rabs/toolchain/bin/cargo-clippy";
        let mode = CargoArtifactMode::Compilation;
        let expected = compatible_arguments(clippy, &invocation("clippy", &[]), mode).unwrap();
        assert_ne!(
            compatible_arguments(
                "/__rabs/toolchain/bin/cargo",
                &invocation("check", &[]),
                mode
            ),
            Some(expected.clone())
        );
        for tail in [
            &["--workspace"][..],
            &["--lib"][..],
            &["--package=app"][..],
            &["--features=extra"][..],
            &["-F", "extra"][..],
            &["--all-features"][..],
            &["--no-default-features"][..],
            &["--no-deps"][..],
            &["--", "-D", "warnings"][..],
        ] {
            assert_ne!(
                compatible_arguments(clippy, &invocation("clippy", tail), mode),
                Some(expected.clone())
            );
        }
        let deny_then_allow = compatible_arguments(
            clippy,
            &invocation("clippy", &["--", "-D", "warnings", "-A", "dead_code"]),
            mode,
        );
        let allow_then_deny = compatible_arguments(
            clippy,
            &invocation("clippy", &["--", "-A", "dead_code", "-D", "warnings"]),
            mode,
        );
        assert_ne!(deny_then_allow, allow_then_deny);
        assert!(deny_then_allow.is_some());
        assert!(allow_then_deny.is_some());
        assert_eq!(
            compatible_arguments(
                clippy,
                &invocation("clippy", &[]),
                CargoArtifactMode::TestExecution
            ),
            None
        );
    }
}
