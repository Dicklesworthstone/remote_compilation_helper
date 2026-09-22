//! Checked Cargo directory-source inputs for automatic source preparation.
//!
//! This is opt-in, offline input selection, not package authenticity or action
//! authority. Cargo owns resolution. We validate the already-captured vendor
//! tree, its checksum files, the selected workspace lock, and the resolved paths.
//! The source-replacement configuration is preserved, never generated or rewritten.

use super::{MAX_PACKAGES, OUTPUT_LIMIT, contained_relative, invalid, is_cargo_config, require};
use rabs_sandbox::snapshot_capture::{MemberKind, SealedSourceSnapshot};
use rabs_sandbox::source_transfer::MAX_SOURCE_FILES;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const CHECKSUM_FILE: &str = ".cargo-checksum.json";

pub(super) fn validate_directory(directory: &str) -> io::Result<()> {
    require(safe_relative(directory) && directory.split('/').count() <= 16,
        "cargo_source vendor must be a bounded relative directory inside the approved anchor")
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty() && path.len() <= 1024 && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control) && path.split('/').count() <= 32
        && path.split('/').all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

fn canonical_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn toml_input(image: &SealedSourceSnapshot, path: &str) -> io::Result<toml::Value> {
    let bytes = image.file_bytes("workspace", path)
        .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
        .ok_or_else(|| invalid("missing or oversized captured vendor input"))?;
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("vendor TOML input is not UTF-8"))?;
    // Do not echo arbitrary source/config values into operator diagnostics.
    toml::from_str(text).map_err(|_| invalid("malformed captured vendor TOML input"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checksums {
    package: String,
    #[serde(deserialize_with = "unique_hashes")]
    files: BTreeMap<String, String>,
}

// serde's ordinary map visitor replaces duplicate keys. Checksum evidence must
// instead describe exactly one value for each member, regardless of JSON order.
fn unique_hashes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded, unique file checksum map")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut files = BTreeMap::new();
            while let Some((path, checksum)) = map.next_entry::<String, String>()? {
                if files.len() >= MAX_SOURCE_FILES || files.insert(path, checksum).is_some() {
                    return Err(serde::de::Error::custom("duplicate or excessive vendor checksum members"));
                }
            }
            Ok(files)
        }
    }
    deserializer.deserialize_map(Visitor)
}

#[derive(Debug)]
struct Package {
    name: String,
    version: String,
    checksum: String,
}

/// Constructed only from one retained image. It does not outlive or authorize
/// another snapshot. Directory/package names are not inferred from name-version
/// strings; Cargo vendor allows arbitrary unambiguous package directory names.
#[derive(Debug)]
pub(super) struct VendoredSources {
    directory: String,
    config: String,
    packages: BTreeMap<String, Package>,
}

impl VendoredSources {
    pub(super) fn verify(image: &SealedSourceSnapshot, manifest: &str, directory: &str) -> io::Result<Self> {
        validate_directory(directory)?;
        require(!Path::new(manifest).starts_with(directory), "selected Cargo manifest is inside its vendor source")?;
        let captured = image.manifest("workspace").ok_or_else(|| invalid("missing captured Cargo anchor"))?;
        let mut configs = Vec::new();
        let mut file_count = 0_usize;
        let mut members: BTreeMap<String, BTreeMap<String, &str>> = BTreeMap::new();
        let prefix = format!("{directory}/");
        for (path, kind) in &captured.members {
            require(!matches!(kind, MemberKind::Symlink { .. }), "vendored source capture contains a symlink")?;
            if !matches!(kind, MemberKind::Regular { .. }) { continue; }
            file_count += 1;
            require(file_count <= MAX_SOURCE_FILES, "captured anchor exceeds the source file-count bound")?;
            if let Some(relative) = path.strip_prefix(&prefix) {
                let (package, member) = relative.split_once('/')
                    .ok_or_else(|| invalid("vendor source contains a file outside a package directory"))?;
                require(!package.starts_with('.') && safe_relative(member), "unsafe or hidden vendor package member")?;
                let package_root = format!("{directory}/{package}");
                members.entry(package_root).or_default().insert(member.to_owned(), path);
                require(members.len() <= MAX_PACKAGES, "vendor package count exceeds its bound")?;
            } else if is_cargo_config(Path::new(path)) {
                configs.push(path.clone());
            }
        }
        require(!members.is_empty(), "explicit vendor directory contains no captured packages")?;
        require(configs.len() == 1, "vendor preparation requires one captured source-replacement config and no other Cargo config layers")?;
        let config = configs.pop().ok_or_else(|| invalid("missing vendor configuration"))?;
        let config_base = Path::new(&config).parent().and_then(Path::parent)
            .ok_or_else(|| invalid("invalid vendor configuration path"))?;
        require(Path::new(manifest).parent().is_some_and(|parent| parent.starts_with(config_base)),
            "vendor source configuration is not an ancestor of the selected manifest")?;
        validate_config(&toml_input(image, &config)?, config_base, directory)?;

        let mut packages = BTreeMap::new();
        let mut identities = BTreeSet::new();
        let mut count = 0_usize;
        for (root, files) in members {
            count = count.checked_add(files.len()).filter(|count| *count <= MAX_SOURCE_FILES)
                .ok_or_else(|| invalid("vendor file count exceeds the source bound"))?;
            let checksum_path = files.get(CHECKSUM_FILE).ok_or_else(|| invalid("vendor package lacks .cargo-checksum.json"))?;
            let bytes = image.file_bytes("workspace", checksum_path)
                .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
                .ok_or_else(|| invalid("vendor checksum file unavailable or oversized"))?;
            let checksums: Checksums = serde_json::from_slice(bytes)
                .map_err(|_| invalid("malformed or duplicate vendor checksum metadata"))?;
            require(canonical_hash(&checksums.package), "registry vendor package requires a canonical package checksum")?;
            require(checksums.files.len() + 1 == files.len() && checksums.files.contains_key("Cargo.toml"),
                "vendor checksums do not cover the exact captured package file set")?;
            for (name, expected) in &checksums.files {
                require(safe_relative(name) && name != CHECKSUM_FILE && canonical_hash(expected),
                    "invalid vendor checksum path or SHA-256")?;
                let captured_path = files.get(name).ok_or_else(|| invalid("checksummed vendor member missing from capture"))?;
                let bytes = image.file_bytes("workspace", captured_path)
                    .ok_or_else(|| invalid("checksummed vendor bytes unavailable"))?;
                require(hash(bytes) == *expected, "vendored file checksum differs from captured bytes")?;
            }
            let package_manifest = files.get("Cargo.toml").ok_or_else(|| invalid("vendor package manifest missing"))?;
            let value = toml_input(image, package_manifest)?;
            // Published package manifests must not escape their own package via
            // readme, build-script, target or path-dependency declarations.
            super::validate_manifest_paths(Path::new(""), &value)?;
            let package = value.get("package").and_then(toml::Value::as_table)
                .ok_or_else(|| invalid("vendor manifest does not describe a package"))?;
            let name = package.get("name").and_then(toml::Value::as_str)
                .filter(|name| !name.is_empty()).ok_or_else(|| invalid("vendor package name missing"))?;
            let version = package.get("version").and_then(toml::Value::as_str)
                .filter(|version| !version.is_empty()).ok_or_else(|| invalid("vendor package version must be explicit"))?;
            require(identities.insert((name.to_owned(), version.to_owned())), "duplicate vendor package name and version")?;
            packages.insert(root, Package { name:name.to_owned(), version:version.to_owned(), checksum:checksums.package });
        }
        Ok(Self { directory:directory.to_owned(), config, packages })
    }

    pub(super) fn contains(&self, path: &str) -> bool {
        Path::new(path).starts_with(&self.directory)
    }

    pub(super) fn allows_config(&self, path: &str) -> bool {
        path == self.config || self.contains(path)
    }

    /// Check the actual metadata workspace's lockfile, not the first similarly
    /// named file under the approved anchor. Every locked registry package must
    /// have a byte-verified directory and the same package checksum.
    pub(super) fn bind_lock(&self, image: &SealedSourceSnapshot, lock: &Path) -> io::Result<BTreeSet<(String, String)>> {
        let lock = lock.to_str().ok_or_else(|| invalid("non-UTF-8 vendor lockfile path"))?;
        let value = toml_input(image, lock)?;
        validate_lock_sources(&value)?;
        let packages = value.get("package").and_then(toml::Value::as_array)
            .ok_or_else(|| invalid("vendor preparation requires a package lockfile"))?;
        let mut seen = BTreeSet::new();
        for package in packages {
            if package.get("source").is_none() { continue; }
            let name = package.get("name").and_then(toml::Value::as_str).ok_or_else(|| invalid("locked registry package name missing"))?;
            let version = package.get("version").and_then(toml::Value::as_str).ok_or_else(|| invalid("locked registry package version missing"))?;
            require(seen.insert((name.to_owned(), version.to_owned())), "duplicate locked registry package")?;
            let found = self.packages.values().find(|candidate| candidate.name == name && candidate.version == version)
                .ok_or_else(|| invalid("locked registry package is absent from the verified vendor source"))?;
            require(package.get("checksum").and_then(toml::Value::as_str) == Some(found.checksum.as_str()),
                "vendor package checksum differs from the workspace lockfile")?;
        }
        Ok(seen)
    }

    pub(super) fn check_package(
        &self, root: &Path, package: &Value, locked: &BTreeSet<(String, String)>,
    ) -> io::Result<()> {
        let path = package["manifest_path"].as_str().map(Path::new)
            .ok_or_else(|| invalid("resolved vendor package manifest missing"))?;
        let relative = path.strip_prefix(root).map_err(|_| invalid("resolved package escaped the captured anchor"))?;
        let parent = relative.parent().and_then(Path::to_str).ok_or_else(|| invalid("resolved package parent missing"))?;
        if package.get("source").is_some_and(Value::is_null) {
            return require(!self.contains(parent), "vendor directory cannot be reclassified as a local path package");
        }
        require(package["source"].as_str() == Some(CRATES_IO), "only crates.io directory-source replacement is supported")?;
        let expected = self.packages.get(parent).ok_or_else(|| invalid("Cargo resolved registry package outside the verified vendor source"))?;
        require(relative.file_name().is_some_and(|name| name == "Cargo.toml")
            && package["name"].as_str() == Some(expected.name.as_str())
            && package["version"].as_str() == Some(expected.version.as_str()),
            "resolved vendor package identity differs from its captured manifest")?;
        require(locked.contains(&(expected.name.clone(), expected.version.clone())),
            "Cargo resolved a vendor package absent from the workspace lockfile")?;
        let package_root = path.parent().ok_or_else(|| invalid("resolved package has no parent"))?;
        for target in package["targets"].as_array().ok_or_else(|| invalid("resolved vendor targets missing"))? {
            require(target["src_path"].as_str().is_some_and(|path| Path::new(path).starts_with(package_root)),
                "resolved vendor target is outside its package")?;
        }
        Ok(())
    }
}

fn validate_config(value: &toml::Value, base: &Path, directory: &str) -> io::Result<()> {
    let top = value.as_table().filter(|top| top.len() == 1).ok_or_else(|| invalid("vendor config may contain only source replacement"))?;
    let sources = top.get("source").and_then(toml::Value::as_table).filter(|sources| sources.len() == 2)
        .ok_or_else(|| invalid("vendor config requires exactly crates-io and one directory source"))?;
    let original = sources.get("crates-io").and_then(toml::Value::as_table).filter(|source| source.len() == 1)
        .ok_or_else(|| invalid("invalid crates.io vendor replacement"))?;
    let name = original.get("replace-with").and_then(toml::Value::as_str)
        .filter(|name| !name.is_empty() && *name != "crates-io")
        .ok_or_else(|| invalid("vendor replacement source missing"))?;
    let replacement = sources.get(name).and_then(toml::Value::as_table).filter(|source| source.len() == 1)
        .ok_or_else(|| invalid("vendor replacement must be one directory source without aliases"))?;
    let configured = replacement.get("directory").and_then(toml::Value::as_str)
        .ok_or_else(|| invalid("vendor replacement directory missing"))?;
    // Cargo resolves file-config paths relative to the parent of .cargo, not
    // relative to cwd or the .cargo directory itself (Cargo config reference).
    require(contained_relative(base, configured)? == PathBuf::from(directory),
        "Cargo config directory differs from the explicitly approved vendor directory")
}

pub(super) fn validate_lock_sources(lock: &toml::Value) -> io::Result<()> {
    let packages = lock.get("package").and_then(toml::Value::as_array)
        .filter(|packages| !packages.is_empty() && packages.len() <= MAX_PACKAGES)
        .ok_or_else(|| invalid("Cargo vendor lockfile package set is missing or excessive"))?;
    for package in packages {
        if let Some(source) = package.get("source") {
            require(source.as_str() == Some(CRATES_IO), "vendor preparation does not import Git or alternate registries")?;
            require(package.get("checksum").and_then(toml::Value::as_str).is_some_and(canonical_hash),
                "locked registry package checksum missing or noncanonical")?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
